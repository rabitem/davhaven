//! Calendar objects over DAV: verbatim storage, preconditions, permissions, MOVE and COPY, multiget, queries, sync
//! tokens, retries of lost transactions and the scheduling seam of the write path.

use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::services::{
    CalendarDataSpec, CopyRequest, DeleteOutcome, DeleteRequest, IfMatch, MoveRequest, MultigetEntry,
    ObjectFilter, ObjectService, ObjectView, Projection, PutOutcome, PutRequest, ScheduleReply, ScheduleStatus,
    TimeRange, WritePrecondition,
};
use davhaven_testkit::davhaven_app::services::{Conditions, GrantSpec};
use davhaven_testkit::davhaven_domain::events::ObjectChangeKind;
use davhaven_testkit::davhaven_domain::{
    CalendarKind, ComponentKind, ETag, ErrorKind, GrantAccess, ObjectUri, Precondition, Privilege, RequestContext,
    ResourcePath, ScheduleTag, SyncToken, Uid,
};
use davhaven_testkit::davhaven_fixtures::event::{Attendee, EventBuilder, Organizer, When};
use davhaven_testkit::davhaven_wire::ChangeKind;
use davhaven_testkit::davhaven_wire::GrantWrite;
use chrono::{TimeZone, Utc};

use super::scheduler::{Recording, service_with};
use super::support::{Fixture, Person, World, event, fixture, ics, locked};

const ICS: &str = "text/calendar; charset=utf-8";

fn put_request(path: &ResourcePath, body: &str, preconditions: WritePrecondition) -> PutRequest {
    PutRequest {
        path: path.clone(),
        body: body.to_owned(),
        content_type: Some(ICS.to_owned()),
        preconditions,
        schedule_reply: ScheduleReply::Send,
    }
}

fn delete_request(path: &ResourcePath, preconditions: WritePrecondition) -> DeleteRequest {
    DeleteRequest {
        path: path.clone(),
        preconditions,
        schedule_reply: ScheduleReply::Send,
    }
}

fn invitation(uid: &str, organizer: &str, attendees: &[&str]) -> String {
    let mut builder = event(uid, "Planning").organizer(Organizer::new(organizer));
    for attendee in attendees {
        builder = builder.attendee(Attendee::new(attendee));
    }
    builder.build()
}

/// The sequence number of the change log of a collection (what the `CTag` says).
async fn seq(world: &World, ctx: &RequestContext, collection: &ResourcePath) -> u64 {
    world
        .services
        .calendars
        .get_collection(ctx, collection)
        .await
        .unwrap()
        .sync_token
        .unwrap()
        .seq
}

async fn get(world: &World, ctx: &RequestContext, path: &ResourcePath) -> Result<ObjectView, AppError> {
    world.services.objects.get(ctx, path).await
}

fn precondition_code(error: &AppError) -> Option<&'static str> {
    error.precondition().map(Precondition::code)
}

async fn share(f: &Fixture, calendar: &str, with: &Person, access: GrantAccess) {
    f.world
        .services
        .sharing
        .put_grant(
            &f.world.admin(&f.acme),
            GrantSpec {
                calendar: f.world.key(&f.anna, calendar),
                grantee: with.name.clone(),
                body: GrantWrite {
                    access,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    f.world
        .services
        .calendars
        .list_home(&f.world.dav(&f.acme, with), &with.name)
        .await
        .unwrap();
}

#[tokio::test]
async fn puts_store_the_clients_bytes_and_every_mutation_advances_the_sync_token_exactly_once() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    let path = world.object(&acme, &anna, "personal", "standup.ics");
    let start = seq(&world, &dav, &collection).await;

    let body = ics("standup-1", "Standup");
    let etag = ETag::from_bytes(body.as_bytes());
    let created = world
        .services
        .objects
        .put(&dav, put_request(&path, &body, WritePrecondition::create_only()))
        .await
        .unwrap();
    assert!(created.created);
    assert_eq!(
        created.etag,
        Some(etag.clone()),
        "the ETag is the hash of the stored bytes"
    );
    assert_eq!(created.schedule_tag, None, "not a scheduling object resource");
    assert!(!created.schedule.is_scheduled());
    assert_eq!(seq(&world, &dav, &collection).await, start + 1);

    let read = get(&world, &dav, &path).await.unwrap();
    assert_eq!(
        read.data.as_deref(),
        Some(body.as_str()),
        "the client's bytes, verbatim"
    );
    assert_eq!(read.etag, etag);
    assert_eq!(read.size, u64::try_from(body.len()).unwrap());
    assert_eq!(read.uid.as_str(), "standup-1");
    assert_eq!(read.component, ComponentKind::Event);
    assert!(read.privileges.contains(Privilege::WriteContent));
    assert_eq!(read.path, path);

    // Replacing: the new bytes, a new ETag, one more step of the token.
    let replacement = ics("standup-1", "Standup moved");
    let replaced = world
        .services
        .objects
        .put(
            &dav,
            put_request(&path, &replacement, WritePrecondition::if_match(etag.clone())),
        )
        .await
        .unwrap();
    assert!(!replaced.created);
    assert_eq!(replaced.etag, Some(ETag::from_bytes(replacement.as_bytes())));
    assert_eq!(seq(&world, &dav, &collection).await, start + 2);

    // Failed requests change nothing and do not move the token.
    for conditions in [
        WritePrecondition::if_match(etag.clone()),
        WritePrecondition::create_only(),
    ] {
        let error = world
            .services
            .objects
            .put(&dav, put_request(&path, &body, conditions))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
    }
    let error = world
        .services
        .objects
        .delete(&dav, delete_request(&path, WritePrecondition::if_match(etag.clone())))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
    assert_eq!(seq(&world, &dav, &collection).await, start + 2);
    assert_eq!(
        get(&world, &dav, &path).await.unwrap().data.as_deref(),
        Some(replacement.as_str())
    );

    // If-Match: * needs an existing resource.
    let any = WritePrecondition {
        if_match: Some(IfMatch::Any),
        ..WritePrecondition::none()
    };
    let missing = world.object(&acme, &anna, "personal", "other.ics");
    assert_eq!(
        world
            .services
            .objects
            .put(&dav, put_request(&missing, &ics("other", "Other"), any))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );

    // Deleting.
    let new_etag = ETag::from_bytes(replacement.as_bytes());
    world
        .services
        .objects
        .delete(&dav, delete_request(&path, WritePrecondition::if_match(new_etag)))
        .await
        .unwrap();
    assert_eq!(seq(&world, &dav, &collection).await, start + 3);
    assert_eq!(get(&world, &dav, &path).await.unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(
        world
            .services
            .objects
            .delete(&dav, delete_request(&path, WritePrecondition::none()))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    // One event per mutation, in order, with the token that each of them left behind.
    let events = world
        .events_of(
            &acme,
            davhaven_testkit::davhaven_domain::EventType::CalendarObjectsChanged,
        )
        .await;
    assert_eq!(events.len(), 3);
    let kinds: Vec<ObjectChangeKind> = events
        .iter()
        .map(|envelope| World::objects_changed(envelope).changes[0].kind)
        .collect();
    assert_eq!(
        kinds,
        vec![
            ObjectChangeKind::Created,
            ObjectChangeKind::Updated,
            ObjectChangeKind::Deleted
        ]
    );
    for (index, envelope) in events.iter().enumerate() {
        let payload = World::objects_changed(envelope);
        assert_eq!(payload.sync_token.seq, start + 1 + u64::try_from(index).unwrap());
        assert!(!payload.truncated);
        let change = &payload.changes[0];
        assert_eq!(change.uid.as_str(), "standup-1");
        assert_eq!(change.uri.as_str(), "standup.ics");
        assert_eq!(change.etag.is_some(), change.kind != ObjectChangeKind::Deleted);
    }
}

#[tokio::test]
async fn invalid_data_is_rejected_with_the_matching_caldav_precondition() {
    let world = World::with(|deps| {
        deps.limits.ical.max_resource_size = 1500;
        deps.limits.ical.max_attendees_per_instance = 2;
    });
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let dav = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "personal", "x.ics");

    let two_uids = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTAMP:20270101T000000Z\r\n\
DTSTART:20270301T090000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:b\r\nDTSTAMP:20270101T000000Z\r\n\
DTSTART:20270301T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let long = event("big", "Big").description(&"x".repeat(2000)).build();
    let crowded = event("crowded", "Crowded")
        .organizer(Organizer::new("mailto:anna@acme.example"))
        .attendee(Attendee::new("mailto:a@example.org"))
        .attendee(Attendee::new("mailto:b@example.org"))
        .attendee(Attendee::new("mailto:c@example.org"))
        .build();
    let cases: Vec<(&str, String, Option<&str>, ErrorKind, &str)> = vec![
        (
            "garbage",
            "this is not a calendar".to_owned(),
            Some(ICS),
            ErrorKind::Invalid,
            "valid-calendar-data",
        ),
        (
            "media type",
            ics("m", "M"),
            Some("text/plain"),
            ErrorKind::Invalid,
            "supported-calendar-data",
        ),
        (
            "two uids",
            two_uids.to_owned(),
            Some(ICS),
            ErrorKind::Invalid,
            "valid-calendar-object-resource",
        ),
        ("too large", long, Some(ICS), ErrorKind::TooLarge, "max-resource-size"),
        (
            "too many attendees",
            crowded,
            Some(ICS),
            ErrorKind::Invalid,
            "max-attendees-per-instance",
        ),
    ];
    for (name, body, content_type, kind, code) in cases {
        let mut request = put_request(&path, &body, WritePrecondition::none());
        request.content_type = content_type.map(str::to_owned);
        let error = world.services.objects.put(&dav, request).await.unwrap_err();
        assert_eq!(error.kind(), kind, "{name}");
        assert_eq!(precondition_code(&error), Some(code), "{name}");
    }
    assert_eq!(
        get(&world, &dav, &path).await.unwrap_err().kind(),
        ErrorKind::NotFound,
        "nothing was stored"
    );
    let collection = world.collection(&acme, &anna, "personal");
    assert_eq!(seq(&world, &dav, &collection).await, 0, "and the log did not move");
}

#[tokio::test]
async fn a_calendar_accepts_only_the_components_it_was_made_for() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let body = davhaven_testkit::davhaven_wire::CalendarWrite {
        kind: None,
        display_name: "Events only".to_owned(),
        description: None,
        color: None,
        sort_order: None,
        components: Some(vec![ComponentKind::Event]),
    };
    world
        .services
        .calendars
        .upsert(
            &world.admin(&acme),
            davhaven_testkit::davhaven_app::services::CalendarSpec {
                owner: anna.name.clone(),
                slug: davhaven_testkit::davhaven_domain::CalendarSlug::parse("events").unwrap(),
                body,
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    let dav = world.dav(&acme, &anna);
    let todo = EventBuilder::todo("t-1").summary("Buy milk").build();
    let path = world.object(&acme, &anna, "events", "t.ics");
    let error = world
        .services
        .objects
        .put(&dav, put_request(&path, &todo, WritePrecondition::none()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(precondition_code(&error), Some("supported-calendar-component"));
    // The personal calendar takes both.
    let personal = world.object(&acme, &anna, "personal", "t.ics");
    world
        .services
        .objects
        .put(&dav, put_request(&personal, &todo, WritePrecondition::none()))
        .await
        .unwrap();
    assert_eq!(
        get(&world, &dav, &personal).await.unwrap().component,
        ComponentKind::Todo
    );
}

#[tokio::test]
async fn uids_are_unique_per_calendar_and_scheduling_objects_per_owner() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world
        .calendar(
            &acme,
            &anna,
            "work",
            davhaven_testkit::davhaven_domain::CalendarKind::User,
        )
        .await;
    let dav = world.dav(&acme, &anna);
    let put = |slug: &str, uri: &str, body: String| {
        let path = world.object(&acme, &anna, slug, uri);
        let dav = dav.clone();
        let world = &world;
        async move {
            world
                .services
                .objects
                .put(&dav, put_request(&path, &body, WritePrecondition::none()))
                .await
        }
    };

    put("personal", "a.ics", ics("shared-uid", "First")).await.unwrap();
    let error = put("personal", "b.ics", ics("shared-uid", "Second")).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    match error.precondition() {
        Some(Precondition::NoUidConflict(href)) => {
            assert_eq!(
                href.as_str(),
                "/dav/calendars/acme/anna/personal/a.ics",
                "the href of the resource in the way"
            );
        }
        other => panic!("{other:?}"),
    }
    // The same name with another UID replaces; other calendars may reuse a plain UID.
    put("personal", "a.ics", ics("other-uid", "Replaced")).await.unwrap();
    put("work", "a.ics", ics("shared-uid", "Elsewhere")).await.unwrap();

    // A scheduling object resource has one resource per owner, across calendars.
    let plan = invitation("plan-1", "mailto:anna@acme.example", &["mailto:ben@acme.example"]);
    put("personal", "plan.ics", plan.clone()).await.unwrap();
    let error = put("work", "plan.ics", plan).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    match error.precondition() {
        Some(Precondition::UniqueSchedulingObjectResource(href)) => {
            assert!(
                href.as_str().ends_with("/personal/plan.ics"),
                "the href names the resource in the other calendar: {}",
                href.as_str()
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn schedule_tags_are_conditions_of_their_own_and_checked_before_the_etag() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "personal", "plan.ics");
    let first = invitation("plan-1", "mailto:anna@acme.example", &["mailto:ben@acme.example"]);
    let created = world
        .services
        .objects
        .put(&dav, put_request(&path, &first, WritePrecondition::none()))
        .await
        .unwrap();
    let tag = created
        .schedule_tag
        .clone()
        .expect("scheduling objects have a Schedule-Tag");
    let read = get(&world, &dav, &path).await.unwrap();
    assert_eq!(read.schedule_tag, Some(tag.clone()));

    let second = invitation(
        "plan-1",
        "mailto:anna@acme.example",
        &["mailto:ben@acme.example", "mailto:carla@acme.example"],
    );
    // The stored bytes are not the request body (the server added `SCHEDULE-STATUS`), so the `ETag` is read back.
    let etag = read.etag.clone();
    let stale_tag = ScheduleTag::parse("\"stale\"").unwrap();
    // A stale tag fails, whatever the ETag says.
    let error = world
        .services
        .objects
        .put(
            &dav,
            put_request(
                &path,
                &second,
                WritePrecondition {
                    if_match: Some(IfMatch::Tags(vec![etag.clone()])),
                    if_schedule_tag_match: Some(stale_tag),
                    ..WritePrecondition::none()
                },
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
    // A current tag with a stale ETag is the signature of a server merge (an answer that arrived after the client read
    // the object): the scheduler excuses the ETag and keeps the answers it holds (PLAN 2.7).
    let merged = world
        .services
        .objects
        .put(
            &dav,
            put_request(
                &path,
                &second,
                WritePrecondition {
                    if_match: Some(IfMatch::Tags(vec![ETag::from_bytes(b"old")])),
                    if_schedule_tag_match: Some(tag.clone()),
                    ..WritePrecondition::none()
                },
            ),
        )
        .await
        .unwrap();
    assert_ne!(
        merged.schedule_tag,
        Some(tag.clone()),
        "the tag changes with every client write"
    );

    // Both conditions current: the write goes through, and the tag moves again.
    let current = get(&world, &dav, &path).await.unwrap();
    let ok = world
        .services
        .objects
        .put(
            &dav,
            put_request(
                &path,
                &second,
                WritePrecondition {
                    if_match: Some(IfMatch::Tags(vec![current.etag.clone()])),
                    if_schedule_tag_match: current.schedule_tag.clone(),
                    ..WritePrecondition::none()
                },
            ),
        )
        .await
        .unwrap();
    assert_ne!(
        ok.schedule_tag, current.schedule_tag,
        "the tag changes with every client write"
    );
}

#[tokio::test]
async fn permissions_follow_the_access_of_the_caller() {
    let f = fixture().await;
    let Fixture { world, acme, anna, ben } = &f;
    let carla = world.user(acme, "carla").await;
    let svc = world
        .principal(acme, "svc", davhaven_testkit::davhaven_domain::PrincipalKind::Service)
        .await;
    let annas = world.dav(acme, anna);
    let path = world.object(acme, anna, "personal", "x.ics");
    let body = ics("x-1", "X");
    world
        .services
        .objects
        .put(&annas, put_request(&path, &body, WritePrecondition::none()))
        .await
        .unwrap();
    share(&f, "personal", ben, GrantAccess::Read).await;
    let bens_path = world.object(acme, ben, "personal", "x.ics");
    let bens = world.dav(acme, ben);
    let bens_home = world.services.calendars.list_home(&bens, &ben.name).await.unwrap();
    let shared_slug = bens_home
        .iter()
        .find(|view| view.owner.name == anna.name)
        .map(|view| view.path.clone())
        .expect("the shared calendar is bound in ben's home");
    let ResourcePath::Collection { binding, .. } = &shared_slug else {
        panic!("{shared_slug:?}")
    };
    let shared_object = ResourcePath::Object {
        tenant: acme.slug.clone(),
        principal: ben.name.clone(),
        binding: binding.clone(),
        object: ObjectUri::parse("x.ics").unwrap(),
    };
    let _ = bens_path;

    // A read-only sharee reads and is told which privilege is missing for everything else.
    assert_eq!(
        get(world, &bens, &shared_object).await.unwrap().data.as_deref(),
        Some(body.as_str())
    );
    let created = world
        .services
        .objects
        .put(
            &bens,
            put_request(
                &ResourcePath::Object {
                    tenant: acme.slug.clone(),
                    principal: ben.name.clone(),
                    binding: binding.clone(),
                    object: ObjectUri::parse("new.ics").unwrap(),
                },
                &ics("new", "New"),
                WritePrecondition::none(),
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(created.kind(), ErrorKind::Forbidden);
    assert!(
        matches!(created.precondition(), Some(Precondition::NeedPrivileges(missing)) if missing.iter().any(|(_, privilege)| *privilege == Privilege::Bind)),
        "{:?}",
        created.precondition()
    );
    let replaced = world
        .services
        .objects
        .put(
            &bens,
            put_request(&shared_object, &ics("x-1", "Hijacked"), WritePrecondition::none()),
        )
        .await
        .unwrap_err();
    assert_eq!(replaced.kind(), ErrorKind::Forbidden);
    assert!(
        matches!(replaced.precondition(), Some(Precondition::NeedPrivileges(missing)) if missing.iter().any(|(_, privilege)| *privilege == Privilege::WriteContent)),
        "{:?}",
        replaced.precondition()
    );
    let deleted = world
        .services
        .objects
        .delete(&bens, delete_request(&shared_object, WritePrecondition::none()))
        .await
        .unwrap_err();
    assert_eq!(deleted.kind(), ErrorKind::Forbidden);
    assert_eq!(
        get(world, &annas, &path).await.unwrap().data.as_deref(),
        Some(body.as_str()),
        "untouched"
    );

    // With read-write access the sharee writes and deletes.
    share(&f, "personal", ben, GrantAccess::ReadWrite).await;
    world
        .services
        .objects
        .put(
            &bens,
            put_request(&shared_object, &ics("x-1", "Edited by Ben"), WritePrecondition::none()),
        )
        .await
        .unwrap();
    assert!(
        get(world, &annas, &path)
            .await
            .unwrap()
            .data
            .unwrap()
            .contains("Edited by Ben")
    );
    world
        .services
        .objects
        .delete(&bens, delete_request(&shared_object, WritePrecondition::none()))
        .await
        .unwrap();
    assert_eq!(get(world, &annas, &path).await.unwrap_err().kind(), ErrorKind::NotFound);

    // Someone without any access finds nothing, whatever they try.
    world
        .services
        .objects
        .put(&annas, put_request(&path, &body, WritePrecondition::none()))
        .await
        .unwrap();
    let carlas = world.dav(acme, &carla);
    let as_carla = ResourcePath::Object {
        tenant: acme.slug.clone(),
        principal: anna.name.clone(),
        binding: davhaven_testkit::davhaven_domain::CalendarSlug::parse("personal").unwrap(),
        object: ObjectUri::parse("x.ics").unwrap(),
    };
    assert_eq!(
        get(world, &carlas, &as_carla).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .objects
            .put(&carlas, put_request(&as_carla, &body, WritePrecondition::none()))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .objects
            .delete(&carlas, delete_request(&as_carla, WritePrecondition::none()))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    // Feed readers and the like have no business with DAV paths.
    let feed = world.feed(acme, anna, world.token_id());
    assert_eq!(get(world, &feed, &path).await.unwrap_err().kind(), ErrorKind::NotFound);

    // Managed calendars are read-only for DAV, even for their owner.
    world.calendar(acme, &svc, "holidays", CalendarKind::Managed).await;
    let svcs = world.dav(acme, &svc);
    let managed = world.object(acme, &svc, "holidays", "h.ics");
    let error = world
        .services
        .objects
        .put(
            &svcs,
            put_request(&managed, &ics("h-1", "Holiday"), WritePrecondition::none()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);

    // Paths of other tenants do not resolve for the caller of this tenant.
    let other = world.org("other").await;
    let olga = world.user(&other, "olga").await;
    let olgas = world.dav(&other, &olga);
    assert_eq!(get(world, &olgas, &path).await.unwrap_err().kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn move_relocates_an_object_without_changing_it() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let dav = world.dav(&acme, &anna);
    let personal = world.collection(&acme, &anna, "personal");
    let work = world.collection(&acme, &anna, "work");
    let from = world.object(&acme, &anna, "personal", "a.ics");
    let to = world.object(&acme, &anna, "work", "moved.ics");
    let body = invitation("plan-1", "mailto:anna@acme.example", &["mailto:ben@acme.example"]);
    world
        .services
        .objects
        .put(&dav, put_request(&from, &body, WritePrecondition::none()))
        .await
        .unwrap();
    // The server writes the delivery state of the attendee into the organizer's copy, so the `PUT` has no `ETag`
    // (RFC 4791 section 5.3.4): the condition is the `ETag` of the object as it is stored.
    let before = get(&world, &dav, &from).await.unwrap();
    let (personal_seq, work_seq) = (seq(&world, &dav, &personal).await, seq(&world, &dav, &work).await);

    let moved = world
        .services
        .objects
        .move_to(
            &dav,
            MoveRequest {
                from: from.clone(),
                to: to.clone(),
                overwrite: false,
                preconditions: WritePrecondition::if_match(before.etag.clone()),
            },
        )
        .await
        .unwrap();
    assert!(moved.created);
    assert_eq!(moved.etag, before.etag);
    let after = get(&world, &dav, &to).await.unwrap();
    assert_eq!(after.id, before.id, "a relocation: same object");
    assert_eq!(after.etag, before.etag);
    assert_eq!(after.schedule_tag, before.schedule_tag, "the Schedule-Tag stays");
    assert_eq!(after.data, before.data);
    assert_eq!(get(&world, &dav, &from).await.unwrap_err().kind(), ErrorKind::NotFound);
    assert!(
        seq(&world, &dav, &personal).await > personal_seq,
        "logged in the source calendar"
    );
    assert!(seq(&world, &dav, &work).await > work_seq, "and in the target calendar");

    // Moving onto an existing resource needs Overwrite, and then replaces it.
    let occupant = world.object(&acme, &anna, "work", "occupied.ics");
    world
        .services
        .objects
        .put(
            &dav,
            put_request(&occupant, &ics("occupant", "Occupant"), WritePrecondition::none()),
        )
        .await
        .unwrap();
    let again = world.object(&acme, &anna, "personal", "b.ics");
    world
        .services
        .objects
        .put(&dav, put_request(&again, &ics("b-1", "B"), WritePrecondition::none()))
        .await
        .unwrap();
    let request = |overwrite| MoveRequest {
        from: again.clone(),
        to: occupant.clone(),
        overwrite,
        preconditions: WritePrecondition::none(),
    };
    assert_eq!(
        world
            .services
            .objects
            .move_to(&dav, request(false))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    let overwritten = world.services.objects.move_to(&dav, request(true)).await.unwrap();
    assert!(!overwritten.created);
    assert_eq!(get(&world, &dav, &occupant).await.unwrap().uid.as_str(), "b-1");

    // A stale source precondition and moving a resource onto itself.
    let stale = world
        .services
        .objects
        .move_to(
            &dav,
            MoveRequest {
                from: to.clone(),
                to: world.object(&acme, &anna, "work", "again.ics"),
                overwrite: false,
                preconditions: WritePrecondition::if_match(ETag::from_bytes(b"old")),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(stale.kind(), ErrorKind::PreconditionFailed);
    let onto_itself = world
        .services
        .objects
        .move_to(
            &dav,
            MoveRequest {
                from: to.clone(),
                to: to.clone(),
                overwrite: true,
                preconditions: WritePrecondition::none(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(onto_itself.kind(), ErrorKind::Forbidden, "RFC 4918 section 9.9.4");
}

#[tokio::test]
async fn a_scheduling_object_cannot_move_into_another_owners_calendar() {
    let f = fixture().await;
    let Fixture { world, acme, anna, ben } = &f;
    share(&f, "personal", ben, GrantAccess::ReadWrite).await;
    let annas = world.dav(acme, anna);
    let bens = world.dav(acme, ben);
    let from = world.object(acme, anna, "personal", "plan.ics");
    world
        .services
        .objects
        .put(
            &annas,
            put_request(
                &from,
                &invitation("plan-1", "mailto:anna@acme.example", &["mailto:ben@acme.example"]),
                WritePrecondition::none(),
            ),
        )
        .await
        .unwrap();
    let to = world.object(acme, ben, "personal", "plan.ics");
    // Anna has no access to ben's calendar through her own context; she may only move within what she can write.
    let error = world
        .services
        .objects
        .move_to(
            &annas,
            MoveRequest {
                from,
                to,
                overwrite: false,
                preconditions: WritePrecondition::none(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::NotFound,
        "a calendar she cannot see does not exist for her: {error:?}"
    );
    let _ = bens;
}

#[tokio::test]
async fn copy_stores_a_new_object_that_keeps_the_uid_of_the_source() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let dav = world.dav(&acme, &anna);
    let source = world.object(&acme, &anna, "personal", "a.ics");
    let body = ics("copy-me", "Copy me");
    world
        .services
        .objects
        .put(&dav, put_request(&source, &body, WritePrecondition::none()))
        .await
        .unwrap();

    // Inside one calendar the copy would repeat the UID.
    let same = world
        .services
        .objects
        .copy_to(
            &dav,
            CopyRequest {
                from: source.clone(),
                to: world.object(&acme, &anna, "personal", "copy.ics"),
                overwrite: false,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(same.kind(), ErrorKind::Conflict);
    assert_eq!(precondition_code(&same), Some("no-uid-conflict"));

    let target = world.object(&acme, &anna, "work", "copy.ics");
    let copied = world
        .services
        .objects
        .copy_to(
            &dav,
            CopyRequest {
                from: source.clone(),
                to: target.clone(),
                overwrite: false,
            },
        )
        .await
        .unwrap();
    assert!(copied.created);
    let copy = get(&world, &dav, &target).await.unwrap();
    assert_eq!(copy.data.as_deref(), Some(body.as_str()));
    assert_eq!(copy.uid.as_str(), "copy-me");
    let original = get(&world, &dav, &source).await.unwrap();
    assert_ne!(copy.id, original.id, "a new object");
    // Overwrite decides about an existing target.
    let blocked = world
        .services
        .objects
        .copy_to(
            &dav,
            CopyRequest {
                from: source.clone(),
                to: target.clone(),
                overwrite: false,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(blocked.kind(), ErrorKind::PreconditionFailed);
    let overwritten = world
        .services
        .objects
        .copy_to(
            &dav,
            CopyRequest {
                from: source,
                to: target,
                overwrite: true,
            },
        )
        .await
        .unwrap();
    assert!(!overwritten.created);
}

#[tokio::test]
async fn multiget_answers_every_requested_resource_in_request_order() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    let a = world.object(&acme, &anna, "personal", "a.ics");
    let b = world.object(&acme, &anna, "personal", "b.ics");
    let gone = world.object(&acme, &anna, "personal", "gone.ics");
    let elsewhere = world.object(&acme, &anna, "work", "c.ics");
    for (path, uid) in [(&a, "a"), (&b, "b"), (&elsewhere, "c")] {
        world
            .services
            .objects
            .put(&dav, put_request(path, &ics(uid, uid), WritePrecondition::none()))
            .await
            .unwrap();
    }
    let entries = world
        .services
        .objects
        .multiget(
            &dav,
            &collection,
            vec![b.clone(), gone.clone(), a.clone(), elsewhere.clone(), b.clone()],
            CalendarDataSpec::default(),
        )
        .await
        .unwrap();
    assert_eq!(entries.len(), 5);
    let describe = |entry: &MultigetEntry| match entry {
        MultigetEntry::Found(view) => format!("found {}", view.path.format()),
        MultigetEntry::Missing(path) => format!("missing {}", path.format()),
    };
    assert_eq!(
        entries.iter().map(describe).collect::<Vec<_>>(),
        vec![
            "found /dav/calendars/acme/anna/personal/b.ics",
            "missing /dav/calendars/acme/anna/personal/gone.ics",
            "found /dav/calendars/acme/anna/personal/a.ics",
            "missing /dav/calendars/acme/anna/work/c.ics",
            "found /dav/calendars/acme/anna/personal/b.ics",
        ],
        "resources of other collections are not answered"
    );
    let MultigetEntry::Found(view) = &entries[0] else {
        panic!()
    };
    assert!(view.data.as_deref().unwrap().contains("UID:b"));
    // Without data only the metadata comes back.
    let bare = world
        .services
        .objects
        .multiget(&dav, &collection, vec![a], CalendarDataSpec::metadata_only())
        .await
        .unwrap();
    let MultigetEntry::Found(view) = &bare[0] else { panic!() };
    assert!(view.data.is_none());
    // The number of hrefs is limited.
    let many: Vec<ResourcePath> = (0..1001)
        .map(|index| world.object(&acme, &anna, "personal", &format!("m{index}.ics")))
        .collect();
    let error = world
        .services
        .objects
        .multiget(&dav, &collection, many, CalendarDataSpec::default())
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::Forbidden,
        "PLAN 2.15: more hrefs than the limit is 403"
    );
}

#[tokio::test]
async fn queries_filter_by_time_uid_and_component_and_can_leave_out_the_data() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    let at = |day: u32, hour: u32| When::utc(2027, 3, day, hour, 0);
    let items = [
        (
            "standup.ics",
            EventBuilder::event("standup")
                .summary("Standup")
                .starts(at(1, 9))
                .ends(at(1, 10))
                .build(),
        ),
        (
            "lunch.ics",
            EventBuilder::event("lunch")
                .summary("Team lunch")
                .starts(at(2, 12))
                .ends(at(2, 13))
                .build(),
        ),
        (
            "review.ics",
            EventBuilder::event("review")
                .summary("Quarterly review")
                .starts(at(20, 15))
                .ends(at(20, 16))
                .build(),
        ),
        (
            "todo.ics",
            EventBuilder::todo("todo").summary("Stand up straight").build(),
        ),
    ];
    for (uri, body) in &items {
        world
            .services
            .objects
            .put(
                &dav,
                put_request(
                    &world.object(&acme, &anna, "personal", uri),
                    body,
                    WritePrecondition::none(),
                ),
            )
            .await
            .unwrap();
    }
    let query = |filter: ObjectFilter| {
        let world = &world;
        let dav = &dav;
        let collection = &collection;
        async move {
            world
                .services
                .objects
                .query(dav, collection, filter, CalendarDataSpec::default())
                .await
                .unwrap()
                .iter()
                .map(|hit| hit.path.format().rsplit('/').next().unwrap().to_owned())
                .collect::<Vec<_>>()
        }
    };

    // Everything, ordered by resource name.
    assert_eq!(
        query(ObjectFilter::default()).await,
        vec!["lunch.ics", "review.ics", "standup.ics", "todo.ics"]
    );
    // A time range keeps the events that overlap it (a to-do without dates would match every range).
    let early = TimeRange::new(
        Some(Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap()),
        Some(Utc.with_ymd_and_hms(2027, 3, 3, 0, 0, 0).unwrap()),
    );
    assert_eq!(
        query(ObjectFilter {
            range: Some(early),
            component: Some(ComponentKind::Event),
            ..ObjectFilter::default()
        })
        .await,
        vec!["lunch.ics", "standup.ics"]
    );
    assert_eq!(
        query(ObjectFilter {
            component: Some(ComponentKind::Todo),
            ..ObjectFilter::default()
        })
        .await,
        vec!["todo.ics"]
    );
    assert_eq!(
        query(ObjectFilter {
            uid: Some(Uid::parse("review").unwrap()),
            ..ObjectFilter::default()
        })
        .await,
        vec!["review.ics"]
    );
    // Without data only the metadata comes back, including the ETags.
    let bare = world
        .services
        .objects
        .query(
            &dav,
            &collection,
            ObjectFilter::default(),
            CalendarDataSpec::metadata_only(),
        )
        .await
        .unwrap();
    assert_eq!(bare.len(), 4);
    assert!(bare.iter().all(|hit| hit.data.is_none()));
    let standup = bare.iter().find(|hit| hit.uid.as_str() == "standup").unwrap();
    assert_eq!(standup.etag, ETag::from_bytes(items[0].1.as_bytes()));

    // Dates outside the supported years are refused, and in a query every limit is a bad filter.
    let beyond = TimeRange::new(None, Some(Utc.with_ymd_and_hms(2200, 1, 1, 0, 0, 0).unwrap()));
    let error = world
        .services
        .objects
        .query(
            &dav,
            &collection,
            ObjectFilter {
                range: Some(beyond),
                ..ObjectFilter::default()
            },
            CalendarDataSpec::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        precondition_code(&error),
        Some("valid-filter"),
        "in a query every limit is a bad filter"
    );
}

#[tokio::test]
async fn a_recurring_event_is_expanded_into_the_instances_inside_the_range() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    let body = event("daily", "Daily").rrule("FREQ=DAILY;COUNT=5").build();
    world
        .services
        .objects
        .put(
            &dav,
            put_request(
                &world.object(&acme, &anna, "personal", "daily.ics"),
                &body,
                WritePrecondition::none(),
            ),
        )
        .await
        .unwrap();
    let range = TimeRange::new(
        Some(Utc.with_ymd_and_hms(2027, 3, 2, 0, 0, 0).unwrap()),
        Some(Utc.with_ymd_and_hms(2027, 3, 4, 0, 0, 0).unwrap()),
    );
    let hits = world
        .services
        .objects
        .query(
            &dav,
            &collection,
            ObjectFilter {
                range: Some(range),
                ..ObjectFilter::default()
            },
            CalendarDataSpec {
                include_data: true,
                projection: Projection {
                    expand: Some(range),
                    ..Projection::default()
                },
            },
        )
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    let data = hits[0].data.as_deref().unwrap();
    assert_eq!(data.matches("BEGIN:VEVENT").count(), 2, "March 2nd and 3rd: {data}");
    assert!(data.contains("RECURRENCE-ID"), "{data}");
    assert!(!data.contains("RRULE"), "expanded instances carry no rule: {data}");
    // The stored bytes are not touched by a projection.
    assert_eq!(
        get(&world, &dav, &world.object(&acme, &anna, "personal", "daily.ics"))
            .await
            .unwrap()
            .data
            .as_deref(),
        Some(body.as_str())
    );
}

#[tokio::test]
async fn sync_collection_reports_changes_and_deletions_and_refuses_unusable_tokens() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    let path = |name: &str| world.object(&acme, &anna, "personal", name);
    let put = |name: &'static str, uid: &'static str, summary: &'static str| {
        let world = &world;
        let dav = &dav;
        let path = path(name);
        async move {
            world
                .services
                .objects
                .put(dav, put_request(&path, &ics(uid, summary), WritePrecondition::none()))
                .await
                .unwrap()
        }
    };
    put("a.ics", "a", "A").await;
    put("b.ics", "b", "B").await;

    // An initial sync lists every member, and its token is the CTag.
    let initial = world
        .services
        .objects
        .sync(&dav, &collection, None, None)
        .await
        .unwrap();
    assert_eq!(initial.changes.len(), 2);
    assert!(
        initial
            .changes
            .iter()
            .all(|change| change.kind == ChangeKind::Upsert && change.etag.is_some())
    );
    assert!(!initial.truncated);
    let ctag = world
        .services
        .calendars
        .get_collection(&dav, &collection)
        .await
        .unwrap()
        .sync_token
        .unwrap();
    assert_eq!(initial.sync_token, ctag, "the sync token and the CTag are one string");
    let quiet = world
        .services
        .objects
        .sync(&dav, &collection, Some(initial.sync_token), None)
        .await
        .unwrap();
    assert!(quiet.changes.is_empty());
    assert_eq!(quiet.sync_token, initial.sync_token);

    // Changes since the token: new, changed and deleted members, one entry each.
    put("c.ics", "c", "C").await;
    world
        .services
        .objects
        .put(
            &dav,
            put_request(&path("a.ics"), &ics("a", "A changed"), WritePrecondition::none()),
        )
        .await
        .unwrap();
    world
        .services
        .objects
        .delete(&dav, delete_request(&path("b.ics"), WritePrecondition::none()))
        .await
        .unwrap();
    let incremental = world
        .services
        .objects
        .sync(&dav, &collection, Some(initial.sync_token), None)
        .await
        .unwrap();
    let describe: Vec<(String, ChangeKind)> = incremental
        .changes
        .iter()
        .map(|change| (change.path.format().rsplit('/').next().unwrap().to_owned(), change.kind))
        .collect();
    assert_eq!(
        describe,
        vec![
            ("c.ics".to_owned(), ChangeKind::Upsert),
            ("a.ics".to_owned(), ChangeKind::Upsert),
            ("b.ics".to_owned(), ChangeKind::Delete),
        ],
        "in the order of the log"
    );
    assert!(incremental.changes[2].etag.is_none(), "deletions carry no ETag");
    assert!(incremental.sync_token.seq > initial.sync_token.seq);

    // A cut answer carries a token to continue from.
    let first = world
        .services
        .objects
        .sync(&dav, &collection, Some(initial.sync_token), Some(1))
        .await
        .unwrap();
    assert!(first.truncated);
    assert_eq!(first.changes.len(), 1);
    let rest = world
        .services
        .objects
        .sync(&dav, &collection, Some(first.sync_token), None)
        .await
        .unwrap();
    assert!(!rest.truncated);
    assert_eq!(first.changes.len() + rest.changes.len(), incremental.changes.len());

    // Foreign, wrong-epoch, future and garbled tokens are refused with valid-sync-token.
    let work = world
        .services
        .calendars
        .get_collection(&dav, &world.collection(&acme, &anna, "work"))
        .await
        .unwrap()
        .sync_token
        .unwrap();
    let foreign = work;
    let wrong_epoch = SyncToken::new(
        initial.sync_token.collection,
        uuid::Uuid::from_u128(77),
        initial.sync_token.seq,
    );
    let future = SyncToken::new(
        initial.sync_token.collection,
        initial.sync_token.epoch,
        incremental.sync_token.seq + 100,
    );
    for (name, token) in [("foreign", foreign), ("wrong epoch", wrong_epoch), ("future", future)] {
        let error = world
            .services
            .objects
            .sync(&dav, &collection, Some(token), None)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{name}");
        assert_eq!(precondition_code(&error), Some("valid-sync-token"), "{name}");
    }
}

#[tokio::test]
async fn a_lost_transaction_is_repeated_up_to_three_times() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    let path = world.object(&acme, &anna, "personal", "a.ics");
    let start = seq(&world, &dav, &collection).await;

    // Two lost commits: the third attempt wins, and the write happened exactly once.
    world.faults.fail_next_commits(2);
    let commits = world.faults.commits();
    let outcome = world
        .services
        .objects
        .put(&dav, put_request(&path, &ics("a", "A"), WritePrecondition::none()))
        .await
        .unwrap();
    assert!(outcome.created);
    assert_eq!(world.faults.commits() - commits, 3);
    assert_eq!(seq(&world, &dav, &collection).await, start + 1);
    assert_eq!(
        world
            .events_of(
                &acme,
                davhaven_testkit::davhaven_domain::EventType::CalendarObjectsChanged
            )
            .await
            .len(),
        1,
        "the lost attempts left no event behind"
    );

    // Three lost commits: the request fails as unavailable and nothing was stored.
    let other = world.object(&acme, &anna, "personal", "b.ics");
    world.faults.fail_next_commits(3);
    let error = world
        .services
        .objects
        .put(&dav, put_request(&other, &ics("b", "B"), WritePrecondition::none()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert_eq!(get(&world, &dav, &other).await.unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(seq(&world, &dav, &collection).await, start + 1);

    // A store that is down is unavailable at once and the message does not leak the cause.
    world.faults.fail_next_begins(1);
    let error = get(&world, &dav, &path).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert!(!error.to_string().to_lowercase().contains("store"), "{error}");
}

#[tokio::test]
async fn concurrent_writes_to_one_calendar_each_move_the_token_once_and_none_is_lost() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    let start = seq(&world, &dav, &collection).await;
    let puts = (0..8).map(|index| {
        let path = world.object(&acme, &anna, "personal", &format!("c{index}.ics"));
        let body = ics(&format!("c{index}"), "Concurrent");
        let request = put_request(&path, &body, WritePrecondition::none());
        let objects = &world.services.objects;
        let dav = &dav;
        async move { objects.put(dav, request).await }
    });
    let results = futures::future::join_all(puts).await;
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert_eq!(seq(&world, &dav, &collection).await, start + 8, "one step per write");
    let listed = world
        .services
        .objects
        .sync(&dav, &collection, None, None)
        .await
        .unwrap();
    assert_eq!(listed.changes.len(), 8, "every object is there");
    // Eight events with eight different positions of the log.
    let events = world
        .events_of(
            &acme,
            davhaven_testkit::davhaven_domain::EventType::CalendarObjectsChanged,
        )
        .await;
    let mut positions: Vec<u64> = events
        .iter()
        .map(|event| World::objects_changed(event).sync_token.seq)
        .collect();
    positions.sort_unstable();
    assert_eq!(positions, (start + 1..=start + 8).collect::<Vec<u64>>());
}

// ---------------------------------------------------------------------------------------------------------------
// The scheduling seam
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_scheduler_acts_inside_the_write_transaction_and_its_failure_aborts_the_write() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let scheduler = Recording::default();
    let objects = service_with(&world, &scheduler);
    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    let path = world.object(&acme, &anna, "personal", "a.ics");
    let start = seq(&world, &dav, &collection).await;

    let created: PutOutcome = objects
        .put(&dav, put_request(&path, &ics("a", "A"), WritePrecondition::none()))
        .await
        .unwrap();
    assert_eq!(
        scheduler.calls(),
        vec![
            "before_write a.ics existing=false notify=true".to_owned(),
            format!("after_write a.ics seq={}", start + 1),
        ],
        "DAV writes always count as asking for attendees to be told"
    );
    assert!(
        created.schedule.is_scheduled(),
        "what the scheduler reports is the outcome of the PUT"
    );
    assert_eq!(created.schedule.recipients[0].status, ScheduleStatus::Delivered);

    // A scheduler that refuses after the store wrote aborts everything: no object, no log entry, no event.
    *locked(&scheduler.fail_after) = true;
    let other = world.object(&acme, &anna, "personal", "b.ics");
    let error = objects
        .put(&dav, put_request(&other, &ics("b", "B"), WritePrecondition::none()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(get(&world, &dav, &other).await.unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(seq(&world, &dav, &collection).await, start + 1);
    assert_eq!(
        world
            .events_of(
                &acme,
                davhaven_testkit::davhaven_domain::EventType::CalendarObjectsChanged
            )
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn bytes_changed_by_the_scheduler_are_stored_and_answered_without_an_etag() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let scheduler = Recording::default();
    let objects = service_with(&world, &scheduler);
    let dav = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "personal", "plan.ics");
    let body = invitation("plan-1", "mailto:anna@acme.example", &["mailto:ben@acme.example"]);
    let rewritten = body.replace("SUMMARY:Planning", "SUMMARY:Planning\r\nX-SERVER-NOTE:rewritten");
    *locked(&scheduler.rewrite) = Some(rewritten.clone());

    let outcome = objects
        .put(&dav, put_request(&path, &body, WritePrecondition::none()))
        .await
        .unwrap();
    assert_eq!(
        outcome.etag, None,
        "RFC 4791 5.3.4: no ETag when the stored bytes differ from the request body"
    );
    let stored = get(&world, &dav, &path).await.unwrap();
    assert_eq!(stored.data.as_deref(), Some(rewritten.as_str()));
    assert_eq!(
        stored.etag,
        ETag::from_bytes(rewritten.as_bytes()),
        "the ETag is that of the stored bytes"
    );
    assert!(outcome.schedule_tag.is_some(), "a fresh Schedule-Tag by default");

    // A server merge keeps the tag the object had.
    *locked(&scheduler.keep_tag) = true;
    let tag = stored.schedule_tag.clone();
    *locked(&scheduler.rewrite) = Some(rewritten.replace("rewritten", "rewritten again"));
    let again = objects
        .put(&dav, put_request(&path, &body, WritePrecondition::none()))
        .await
        .unwrap();
    assert_eq!(again.schedule_tag, tag);
}

#[tokio::test]
async fn a_scheduler_that_merges_excuses_a_stale_etag_when_the_schedule_tag_matches() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let path = world.object(&acme, &anna, "personal", "plan.ics");
    let dav = world.dav(&acme, &anna);
    let body = invitation("plan-1", "mailto:anna@acme.example", &["mailto:ben@acme.example"]);
    let plain = world
        .services
        .objects
        .put(&dav, put_request(&path, &body, WritePrecondition::none()))
        .await
        .unwrap();
    let tag = plain.schedule_tag.unwrap();
    let stale = WritePrecondition {
        if_match: Some(IfMatch::Tags(vec![ETag::from_bytes(b"old")])),
        if_schedule_tag_match: Some(tag),
        ..WritePrecondition::none()
    };
    let merging = service_with(&world, &Recording::merging());
    let changed = body.replace("Planning", "Planning v2");
    assert!(
        merging
            .put(&dav, put_request(&path, &changed, stale.clone()))
            .await
            .is_ok()
    );
    let not_merging = service_with(&world, &Recording::default());
    let error = not_merging
        .put(&dav, put_request(&path, &body, stale))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
}

#[tokio::test]
async fn deletions_offer_the_object_to_the_scheduler_unless_the_calendar_never_schedules() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let svc = world
        .principal(
            &acme,
            "svc",
            davhaven_testkit::davhaven_domain::PrincipalKind::Service,
        )
        .await;
    world.calendar(&acme, &svc, "holidays", CalendarKind::Managed).await;
    let scheduler = Recording::default();
    let objects = service_with(&world, &scheduler);
    let dav = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "personal", "a.ics");
    objects
        .put(&dav, put_request(&path, &ics("a", "A"), WritePrecondition::none()))
        .await
        .unwrap();
    let outcome: DeleteOutcome = objects
        .delete(&dav, delete_request(&path, WritePrecondition::none()))
        .await
        .unwrap();
    assert!(!outcome.schedule.is_scheduled());
    assert!(
        scheduler
            .calls()
            .contains(&"before_delete a.ics notify=true".to_owned()),
        "{:?}",
        scheduler.calls()
    );

    // Writes to managed calendars come through the API and never reach the scheduler, whatever is asked.
    let before = scheduler.calls().len();
    let api = world.admin(&acme);
    objects
        .put_event(
            &api,
            &world.key(&svc, "holidays"),
            davhaven_testkit::davhaven_app::services::EventWrite {
                target: Some(davhaven_testkit::davhaven_app::services::ObjectSelector::Key(
                    davhaven_testkit::davhaven_domain::ExternalKey::parse("h-1").unwrap(),
                )),
                event: davhaven_testkit::davhaven_wire::EventView::from_data(
                    davhaven_testkit::davhaven_domain::EventData {
                        summary: Some("Holiday".to_owned()),
                        start: Some(serde_json::from_value(serde_json::json!({"date": "2027-05-01"})).unwrap()),
                        ..davhaven_testkit::davhaven_domain::EventData::default()
                    },
                ),
                notify_attendees: true,
                if_match: None,
                scope: davhaven_testkit::davhaven_wire::mcp::ChangeScope::All,
            },
        )
        .await
        .unwrap();
    assert_eq!(scheduler.calls().len(), before, "managed calendars never schedule");
}

#[tokio::test]
async fn a_conflict_names_only_resources_the_caller_can_see() {
    let f = fixture().await;
    let Fixture { world, acme, anna, ben } = &f;
    world.calendar(acme, anna, "team", CalendarKind::User).await;
    share(&f, "team", ben, GrantAccess::ReadWrite).await;
    // Anna keeps a scheduling object in her own, unshared calendar.
    let plan = invitation("plan-1", "mailto:anna@acme.example", &["mailto:ben@acme.example"]);
    world
        .services
        .objects
        .put(
            &world.dav(acme, anna),
            put_request(
                &world.object(acme, anna, "personal", "private-plan.ics"),
                &plan,
                WritePrecondition::none(),
            ),
        )
        .await
        .unwrap();

    // Ben may write to `team` and reuses the UID there. The error must not tell him that Anna has a calendar
    // `personal` with a resource `private-plan.ics`: he cannot see them.
    let bens = world.dav(acme, ben);
    let clash = put_request(
        &world.object(acme, ben, "team", "mine.ics"),
        &plan,
        WritePrecondition::none(),
    );
    let error = world.services.objects.put(&bens, clash.clone()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    match error.precondition() {
        Some(Precondition::UniqueSchedulingObjectResource(href)) => {
            assert!(
                href.as_str().starts_with("/dav/calendars/acme/ben/"),
                "a path in Ben's own home: {}",
                href.as_str()
            );
            assert!(
                !href.as_str().contains("private-plan") && !href.as_str().contains("anna"),
                "nothing of Anna's: {}",
                href.as_str()
            );
        }
        other => panic!("{other:?}"),
    }

    // Once he can read the other calendar through a binding of his own, the href names it.
    share(&f, "personal", ben, GrantAccess::Read).await;
    let error = world.services.objects.put(&bens, clash).await.unwrap_err();
    match error.precondition() {
        Some(Precondition::UniqueSchedulingObjectResource(href)) => {
            assert!(
                href.as_str().starts_with("/dav/calendars/acme/ben/") && href.as_str().ends_with("/private-plan.ics"),
                "{}",
                href.as_str()
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_copy_answers_the_entity_tag_of_what_is_stored_not_the_one_of_its_source() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let scheduler = Recording::default();
    let objects = service_with(&world, &scheduler);
    let dav = world.dav(&acme, &anna);
    let source = world.object(&acme, &anna, "personal", "a.ics");
    let target = world.object(&acme, &anna, "work", "b.ics");
    objects
        .put(&dav, put_request(&source, &ics("a", "A"), WritePrecondition::none()))
        .await
        .unwrap();
    // From now on the scheduler stores more than the client sent, as scheduling does when it writes SCHEDULE-STATUS.
    let rewritten = ics("a", "A").replace("SUMMARY:A", "SUMMARY:A\r\nX-SERVER-NOTE:written by the server");
    *locked(&scheduler.rewrite) = Some(rewritten.clone());

    let copied: davhaven_testkit::davhaven_app::services::MoveOutcome = objects
        .copy_to(
            &dav,
            CopyRequest {
                from: source.clone(),
                to: target.clone(),
                overwrite: false,
            },
        )
        .await
        .unwrap();
    let stored = get(&world, &dav, &target).await.unwrap();
    assert_eq!(stored.data.as_deref(), Some(rewritten.as_str()));
    assert_eq!(
        copied.etag, stored.etag,
        "the tag of the copy is the one of the stored bytes"
    );
    assert_ne!(copied.etag, get(&world, &dav, &source).await.unwrap().etag);
}

#[tokio::test]
async fn what_the_scheduler_stores_is_what_is_indexed_and_the_attendee_rows_follow_it() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let scheduler = Recording::default();
    let objects = service_with(&world, &scheduler);
    let dav = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "personal", "plan.ics");
    // The client sends a plain event; the scheduler turns it into a meeting with an organizer and an attendee.
    let rewritten = invitation("plan-1", "mailto:anna@acme.example", &["mailto:ben@acme.example"]);
    *locked(&scheduler.rewrite) = Some(rewritten.clone());
    objects
        .put(
            &dav,
            put_request(&path, &ics("plan-1", "Planning"), WritePrecondition::none()),
        )
        .await
        .unwrap();

    let calendar = world
        .services
        .calendars
        .get(&world.admin(&acme), &world.key(&anna, "personal"))
        .await
        .unwrap();
    let mut read = world.read(&acme).await;
    let object = read
        .objects()
        .get(calendar.id, &ObjectUri::parse("plan.ics").unwrap())
        .await
        .unwrap();
    assert_eq!(object.data, rewritten);
    assert!(object.is_scheduling, "the index is that of the stored bytes");
    assert_eq!(
        object
            .organizer_address
            .as_ref()
            .map(|address| address.as_str().to_owned()),
        Some("mailto:anna@acme.example".to_owned())
    );
    let attendees = read.objects().attendees(object.id).await.unwrap();
    assert_eq!(attendees.len(), 1);
    assert_eq!(attendees[0].address.as_str(), "mailto:ben@acme.example");
    assert_eq!(
        attendees[0].principal_id,
        Some(ben.id),
        "resolved from the stored attendees"
    );
}

#[tokio::test]
async fn a_reader_acknowledging_or_snoozing_a_reminder_is_answered_without_a_write() {
    let f = fixture().await;
    let Fixture { world, acme, anna, ben } = &f;
    let with_alarm = ics("meeting", "Meeting").replace(
        "END:VEVENT",
        "BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Reminder\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT",
    );
    let annas = world.dav(acme, anna);
    let anna_path = world.object(acme, anna, "personal", "meeting.ics");
    world
        .services
        .objects
        .put(&annas, put_request(&anna_path, &with_alarm, WritePrecondition::none()))
        .await
        .unwrap();
    share(&f, "personal", ben, GrantAccess::Read).await;
    // Ben's own collection `personal` is another calendar: the share is bound under the next free name.
    let bens = world.dav(acme, ben);
    let home = world.services.calendars.list_home(&bens, &ben.name).await.unwrap();
    let shared = home.iter().find(|view| view.owner.name == anna.name).unwrap();
    let path = shared.path.child(ObjectUri::parse("meeting.ics").unwrap()).unwrap();
    let original = get(world, &bens, &path).await.unwrap();
    let collection = world.collection(acme, anna, "personal");
    let start = seq(world, &annas, &collection).await;

    // Thunderbird and Apple write the acknowledgement and the snooze back, also from a binding that is read-only.
    let acknowledged = with_alarm
        .replace("TRIGGER:-PT15M", "TRIGGER:-PT15M\r\nACKNOWLEDGED:20270301T084500Z")
        .replace(
            "END:VEVENT",
            "X-MOZ-LASTACK:20270301T084500Z\r\nX-MOZ-SNOOZE-TIME-20270301T090000:20270301T091500Z\r\nEND:VEVENT",
        );
    let outcome = world
        .services
        .objects
        .put(&bens, put_request(&path, &acknowledged, WritePrecondition::none()))
        .await
        .unwrap();
    assert!(!outcome.created);
    assert_eq!(outcome.etag, None, "ADR 0004: no ETag, nothing was stored");
    assert!(!outcome.schedule.is_scheduled());
    let after = get(world, &bens, &path).await.unwrap();
    assert_eq!(after.etag, original.etag);
    assert_eq!(after.data, original.data);
    assert_eq!(seq(world, &annas, &collection).await, start, "no change was logged");

    // Anything else from a reader is still refused, and so is the creation of a resource.
    let edited = with_alarm.replace("SUMMARY:Meeting", "SUMMARY:Edited");
    let error = world
        .services
        .objects
        .put(&bens, put_request(&path, &edited, WritePrecondition::none()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    let other = shared.path.child(ObjectUri::parse("new.ics").unwrap()).unwrap();
    let error = world
        .services
        .objects
        .put(&bens, put_request(&other, &acknowledged, WritePrecondition::none()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(seq(world, &annas, &collection).await, start);
}

#[tokio::test]
async fn the_home_lists_and_syncs_only_the_calendars_the_caller_still_has_access_to() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let team = world.group(&acme, "team", &[&anna, &ben]).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    let admin = world.admin(&acme);
    let dav = world.dav(&acme, &anna);
    let home = world.home(&acme, &anna);
    let group_path = world
        .services
        .calendars
        .list_home(&dav, &anna.name)
        .await
        .unwrap()
        .into_iter()
        .find(|view| view.kind == CalendarKind::Group)
        .map(|view| view.path)
        .expect("the group calendar is in the home of its members");

    let initial = world.services.objects.sync(&dav, &home, None, None).await.unwrap();
    assert!(initial.changes.iter().any(|change| change.path == group_path));

    // Anna leaves the group: the binding stays, the access is gone, so the listing and a fresh sync do not show it.
    world
        .services
        .principals
        .set_members(&admin, &team.name, vec![ben.name.clone()])
        .await
        .unwrap();
    let fresh = world.services.objects.sync(&dav, &home, None, None).await.unwrap();
    assert!(
        fresh.changes.iter().all(|change| change.path != group_path),
        "a calendar the caller cannot read is not a member of the home"
    );
    assert!(
        world
            .services
            .calendars
            .list_home(&dav, &anna.name)
            .await
            .unwrap()
            .iter()
            .all(|view| view.kind != CalendarKind::Group)
    );

    // She comes back, syncs, and the group is deleted: the next answer names the binding as deleted.
    world
        .services
        .principals
        .set_members(&admin, &team.name, vec![anna.name.clone(), ben.name.clone()])
        .await
        .unwrap();
    let rejoined = world.services.objects.sync(&dav, &home, None, None).await.unwrap();
    assert!(rejoined.changes.iter().any(|change| change.path == group_path));
    let version = world.services.principals.get(&admin, &team.name).await.unwrap().version;
    world
        .services
        .principals
        .delete(
            &admin,
            &team.name,
            davhaven_testkit::davhaven_app::services::DeleteOptions {
                conditions: Conditions::if_match(version),
                ..davhaven_testkit::davhaven_app::services::DeleteOptions::default()
            },
        )
        .await
        .unwrap();
    let after = world
        .services
        .objects
        .sync(&dav, &home, Some(rejoined.sync_token), None)
        .await
        .unwrap();
    let entry = after
        .changes
        .iter()
        .find(|change| change.path == group_path)
        .expect("the removal of the binding is in the change log of the home");
    assert_eq!(entry.kind, ChangeKind::Delete);
    assert!(entry.etag.is_none());
}
