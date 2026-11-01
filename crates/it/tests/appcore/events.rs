//! The JSON event interface of the management API and MCP, and its equivalence with DAV: the same stored content,
//! the same change log, the same events, the same permissions.

use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::services::{
    Conditions, DeleteEventOptions, DeleteRequest, EventSearch, EventWrite, GrantSpec, ObjectFilter, ObjectSelector,
    PageRequest, PutRequest, ScheduleReply, TimeRange, WritePrecondition,
};
use davhaven_testkit::davhaven_domain::events::ObjectChangeKind;
use davhaven_testkit::davhaven_domain::{
    CalendarKind, ComponentKind, ETag, ErrorKind, EventData, EventTime, EventType, ExternalKey, GrantAccess, ObjectUri,
    Precondition, PrincipalKind, RequestContext, ResourcePath, Scope, SyncToken, Uid,
};
use davhaven_testkit::davhaven_fixtures::event::{EventBuilder, When};
use davhaven_testkit::davhaven_wire::mcp::ChangeScope;
use davhaven_testkit::davhaven_wire::{ChangeKind, EventView, GrantWrite};
use chrono::{TimeZone, Utc};

use super::support::{Fixture, Org, Person, World, fixture, ics};

fn utc(day: u32, hour: u32) -> EventTime {
    EventTime::Utc(Utc.with_ymd_and_hms(2027, 3, day, hour, 0, 0).unwrap())
}

fn data(summary: &str, day: u32, hour: u32) -> EventData {
    EventData {
        summary: Some(summary.to_owned()),
        start: Some(utc(day, hour)),
        end: Some(utc(day, hour + 1)),
        ..EventData::default()
    }
}

fn key(text: &str) -> ExternalKey {
    ExternalKey::parse(text).unwrap()
}

fn write_by_key(text: &str, event: EventData) -> EventWrite {
    EventWrite {
        target: Some(ObjectSelector::Key(key(text))),
        event: EventView::from_data(event),
        notify_attendees: false,
        if_match: None,
        scope: ChangeScope::All,
    }
}

fn create(event: EventData) -> EventWrite {
    EventWrite {
        target: None,
        event: EventView::from_data(event),
        notify_attendees: false,
        if_match: None,
        scope: ChangeScope::All,
    }
}

fn update(selector: ObjectSelector, event: EventData) -> EventWrite {
    EventWrite {
        target: Some(selector),
        event: EventView::from_data(event),
        notify_attendees: false,
        if_match: None,
        scope: ChangeScope::All,
    }
}

fn api(world: &World, org: &Org, person: &Person) -> RequestContext {
    world.api(
        org,
        person,
        &[Scope::CalendarsRead, Scope::EventsRead, Scope::EventsWrite],
    )
}

fn dav_put(path: &ResourcePath, body: &str, preconditions: WritePrecondition) -> PutRequest {
    PutRequest {
        path: path.clone(),
        body: body.to_owned(),
        content_type: Some("text/calendar".to_owned()),
        preconditions,
        schedule_reply: ScheduleReply::Send,
    }
}

async fn seq(world: &World, org: &Org, person: &Person, slug: &str) -> u64 {
    world
        .services
        .calendars
        .get_collection(&world.dav(org, person), &world.collection(org, person, slug))
        .await
        .unwrap()
        .sync_token
        .unwrap()
        .seq
}

async fn calendar_id(
    world: &World,
    org: &Org,
    owner: &Person,
    slug: &str,
) -> davhaven_testkit::davhaven_domain::CalendarId {
    world
        .services
        .calendars
        .get(&world.admin(org), &world.key(owner, slug))
        .await
        .unwrap()
        .id
}

async fn stored(
    world: &World,
    org: &Org,
    calendar: davhaven_testkit::davhaven_domain::CalendarId,
    uid: &str,
) -> davhaven_testkit::davhaven_domain::StoredObject {
    world
        .read(org)
        .await
        .objects()
        .get_by_uid(calendar, &Uid::parse(uid).unwrap())
        .await
        .unwrap()
}

fn changed_events(
    events: &[davhaven_testkit::davhaven_domain::Envelope],
) -> Vec<&Vec<davhaven_testkit::davhaven_domain::events::ObjectChange>> {
    events
        .iter()
        .map(|envelope| &World::objects_changed(envelope).changes)
        .collect()
}

#[tokio::test]
async fn a_write_by_key_creates_the_event_with_a_deterministic_uid_and_a_repeat_changes_nothing() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    let id = calendar_id(&world, &acme, &anna, "personal").await;
    let start = seq(&world, &acme, &anna, "personal").await;

    let first = world
        .services
        .objects
        .put_event(&ctx, &calendar, write_by_key("crm-17", data("Kickoff", 1, 9)))
        .await
        .unwrap();
    assert!(first.created);
    assert!(!first.schedule.is_scheduled(), "the API never schedules unless asked");
    assert_eq!(first.event.data.uid, Some(Uid::deterministic(id, &key("crm-17"))));
    assert_eq!(first.event.external_key, Some(key("crm-17")));
    assert_eq!(first.event.calendar_id, Some(id));
    assert!(first.event.etag.is_some() && first.event.id.is_some());
    assert!(
        first.event.dav_url.as_ref().is_some_and(|url| url
            .as_str()
            .starts_with("https://cal.example.org/dav/calendars/acme/anna/personal/")),
        "{:?}",
        first.event.dav_url
    );
    assert_eq!(first.event.data.summary.as_deref(), Some("Kickoff"));
    assert_eq!(seq(&world, &acme, &anna, "personal").await, start + 1);

    // The same content again: no write, no new ETag, no new event.
    let events = world.events_of(&acme, EventType::CalendarObjectsChanged).await.len();
    let again = world
        .services
        .objects
        .put_event(&ctx, &calendar, write_by_key("crm-17", data("Kickoff", 1, 9)))
        .await
        .unwrap();
    assert!(!again.created);
    assert_eq!(again.event.etag, first.event.etag);
    assert_eq!(again.event.id, first.event.id);
    assert_eq!(
        seq(&world, &acme, &anna, "personal").await,
        start + 1,
        "the sync token stays"
    );
    assert_eq!(
        world.events_of(&acme, EventType::CalendarObjectsChanged).await.len(),
        events
    );

    // A change is an update with a new ETag.
    let changed = world
        .services
        .objects
        .put_event(&ctx, &calendar, write_by_key("crm-17", data("Kickoff moved", 2, 10)))
        .await
        .unwrap();
    assert!(!changed.created);
    assert_ne!(changed.event.etag, first.event.etag);
    assert_eq!(changed.event.data.summary.as_deref(), Some("Kickoff moved"));
    assert_eq!(seq(&world, &acme, &anna, "personal").await, start + 2);

    // Reading by every selector yields the same event.
    let from_key = world
        .services
        .objects
        .get_by_key(&ctx, &calendar, &key("crm-17"))
        .await
        .unwrap();
    let uid = changed.event.data.uid.clone().unwrap();
    let from_uid = world
        .services
        .objects
        .get_event(&ctx, &calendar, &ObjectSelector::Uid(uid), None)
        .await
        .unwrap();
    let from_resource_name = world
        .services
        .objects
        .get_event(
            &ctx,
            &calendar,
            &ObjectSelector::Uri(changed.event.uri.clone().unwrap()),
            None,
        )
        .await
        .unwrap();
    let from_object_id = world
        .services
        .objects
        .get_event(&ctx, &calendar, &ObjectSelector::Id(changed.event.id.unwrap()), None)
        .await
        .unwrap();
    assert_eq!(from_key, changed.event);
    assert_eq!(from_uid, from_key);
    assert_eq!(from_resource_name, from_key);
    assert_eq!(from_object_id, from_key);
    assert_eq!(
        world
            .services
            .objects
            .get_by_key(&ctx, &calendar, &key("unknown"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    // Deleting needs a matching ETag when one is given.
    let stale = DeleteEventOptions {
        if_match: Some(first.event.etag.clone().unwrap()),
        ..DeleteEventOptions::default()
    };
    assert_eq!(
        world
            .services
            .objects
            .delete_by_key(&ctx, &calendar, &key("crm-17"), stale)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    world
        .services
        .objects
        .delete_by_key(&ctx, &calendar, &key("crm-17"), DeleteEventOptions::default())
        .await
        .unwrap();
    assert_eq!(
        world
            .services
            .objects
            .get_by_key(&ctx, &calendar, &key("crm-17"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(seq(&world, &acme, &anna, "personal").await, start + 3);
    let events = world.events_of(&acme, EventType::CalendarObjectsChanged).await;
    let kinds: Vec<ObjectChangeKind> = changed_events(&events).iter().map(|changes| changes[0].kind).collect();
    assert_eq!(
        kinds,
        vec![
            ObjectChangeKind::Created,
            ObjectChangeKind::Updated,
            ObjectChangeKind::Deleted
        ]
    );
    assert!(
        changed_events(&events)
            .iter()
            .all(|changes| changes[0].external_key == Some(key("crm-17")))
    );
}

/// The text a DAV client reads of an event of Anna's `personal` calendar.
async fn text_of(world: &World, org: &Org, owner: &Person, event: &EventView) -> String {
    let path = world.object(org, owner, "personal", event.uri.as_ref().unwrap().as_str());
    let view = world.services.objects.get(&world.dav(org, owner), &path).await.unwrap();
    view.data.unwrap_or_default()
}

/// An event as a client sends it in JSON.
fn json_event(value: serde_json::Value) -> EventData {
    serde_json::from_value::<EventView>(value).unwrap().data
}

#[tokio::test]
async fn null_in_a_json_write_removes_the_field_and_absent_keeps_it() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    let slot = |hour: u32| serde_json::json!({"date_time": format!("2027-03-01T{hour:02}:00:00Z")});
    let full = |location: serde_json::Value, description: serde_json::Value| {
        json_event(serde_json::json!({
            "summary": "Course",
            "start": slot(9),
            "end": slot(10),
            "location": location,
            "description": description,
            "url": "https://example.org/course",
            "categories": ["course"],
            "status": "confirmed",
        }))
    };
    let created = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write_by_key(
                "course-1",
                full(serde_json::json!("Room 1"), serde_json::json!("Agenda")),
            ),
        )
        .await
        .unwrap();
    let text = text_of(&world, &acme, &anna, &created.event).await;
    assert!(
        text.contains("LOCATION:Room 1") && text.contains("DESCRIPTION:Agenda"),
        "{text}"
    );
    assert_eq!(created.event.data.location.as_deref(), Some("Room 1"));

    // The reconcile of an integration sends the location as null: it is removed, everything else stays.
    let start = seq(&world, &acme, &anna, "personal").await;
    let events = world.events_of(&acme, EventType::CalendarObjectsChanged).await.len();
    let cleared = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write_by_key("course-1", full(serde_json::Value::Null, serde_json::json!("Agenda"))),
        )
        .await
        .unwrap();
    assert!(!cleared.created);
    assert_ne!(cleared.event.etag, created.event.etag);
    assert_eq!(cleared.event.data.location, None, "the view has no location any more");
    assert_eq!(cleared.event.data.description.as_deref(), Some("Agenda"));
    assert_eq!(
        cleared.event.data.url.as_ref().map(url::Url::as_str),
        Some("https://example.org/course")
    );
    let text = text_of(&world, &acme, &anna, &cleared.event).await;
    assert!(!text.contains("LOCATION"), "{text}");
    assert!(
        text.contains("DESCRIPTION:Agenda") && text.contains("CATEGORIES:course"),
        "{text}"
    );
    assert_eq!(seq(&world, &acme, &anna, "personal").await, start + 1);
    assert_eq!(
        world.events_of(&acme, EventType::CalendarObjectsChanged).await.len(),
        events + 1
    );

    // The same write again changes nothing at all: that is what keeps a daily reconcile quiet.
    let quiet = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write_by_key("course-1", full(serde_json::Value::Null, serde_json::json!("Agenda"))),
        )
        .await
        .unwrap();
    assert_eq!(quiet.event.etag, cleared.event.etag);
    assert_eq!(seq(&world, &acme, &anna, "personal").await, start + 1);
    assert_eq!(
        world.events_of(&acme, EventType::CalendarObjectsChanged).await.len(),
        events + 1
    );

    // A write that does not mention a field keeps it; one that names it with null removes it, whatever the field.
    let renamed = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write_by_key("course-1", json_event(serde_json::json!({"summary": "Course (2)"}))),
        )
        .await
        .unwrap();
    assert_eq!(renamed.event.data.summary.as_deref(), Some("Course (2)"));
    assert_eq!(
        renamed.event.data.description.as_deref(),
        Some("Agenda"),
        "absent keeps"
    );
    assert_eq!(renamed.event.data.categories, Some(vec!["course".to_owned()]));
    let stripped = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write_by_key(
                "course-1",
                json_event(serde_json::json!({
                    "description": null, "url": null, "categories": null, "status": null, "end": null
                })),
            ),
        )
        .await
        .unwrap();
    let data = &stripped.event.data;
    assert_eq!(
        (&data.description, &data.url, &data.categories, &data.status, &data.end),
        (&None, &None, &None, &None, &None)
    );
    assert_eq!(data.summary.as_deref(), Some("Course (2)"));
    assert_eq!(data.start, Some(utc(1, 9)));
    let text = text_of(&world, &acme, &anna, &stripped.event).await;
    for gone in ["DESCRIPTION", "URL:", "CATEGORIES", "STATUS", "DTEND"] {
        assert!(!text.contains(gone), "{gone} is removed: {text}");
    }
}

#[tokio::test]
async fn an_api_write_and_a_dav_put_of_the_same_event_store_the_same_content_and_leave_the_same_trace() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "dav-side", CalendarKind::User).await;
    world.calendar(&acme, &anna, "api-side", CalendarKind::User).await;
    let dav = world.dav(&acme, &anna);
    let ctx = api(&world, &acme, &anna);
    let dav_calendar = calendar_id(&world, &acme, &anna, "dav-side").await;
    let api_calendar = calendar_id(&world, &acme, &anna, "api-side").await;

    // The same event, once as iCalendar text over DAV and once as JSON over the API.
    let text = EventBuilder::event("eq-1")
        .summary("Planning")
        .description("Agenda")
        .location("Room 1")
        .starts(When::utc(2027, 3, 1, 9, 0))
        .ends(When::utc(2027, 3, 1, 10, 0))
        // The API stamps a new event with the time of its creation; the client says the same thing here.
        .property("CREATED", "20270101T000000Z")
        .build();
    world
        .services
        .objects
        .put(
            &dav,
            dav_put(
                &world.object(&acme, &anna, "dav-side", "eq.ics"),
                &text,
                WritePrecondition::create_only(),
            ),
        )
        .await
        .unwrap();
    let event = EventData {
        uid: Some(Uid::parse("eq-1").unwrap()),
        description: Some("Agenda".to_owned()),
        location: Some("Room 1".to_owned()),
        ..data("Planning", 1, 9)
    };
    world
        .services
        .objects
        .put_event(&ctx, &world.key(&anna, "api-side"), create(event))
        .await
        .unwrap();

    // The stored objects are the same event: the content hash ignores only what iCalendar says is volatile.
    let via_dav = stored(&world, &acme, dav_calendar, "eq-1").await;
    let via_api = stored(&world, &acme, api_calendar, "eq-1").await;
    assert_eq!(
        via_dav.content_hash, via_api.content_hash,
        "{}
---
{}",
        via_dav.data, via_api.data
    );
    assert_eq!(via_dav.component, via_api.component);
    assert_eq!(via_dav.first_start, via_api.first_start);
    assert_eq!(via_dav.last_end, via_api.last_end);
    assert_eq!(via_dav.is_recurring, via_api.is_recurring);
    assert_eq!(via_dav.is_scheduling, via_api.is_scheduling);
    assert_eq!(via_dav.class, via_api.class);

    // Both writes left one `created` change at the first position of their calendar's log.
    let events = world.events_of(&acme, EventType::CalendarObjectsChanged).await;
    assert_eq!(events.len(), 2);
    for (envelope, calendar) in events.iter().zip([dav_calendar, api_calendar]) {
        let payload = World::objects_changed(envelope);
        assert_eq!(payload.calendar, calendar);
        assert_eq!(payload.sync_token.seq, 1);
        assert_eq!(payload.changes.len(), 1);
        assert_eq!(payload.changes[0].kind, ObjectChangeKind::Created);
        assert_eq!(payload.changes[0].uid.as_str(), "eq-1");
    }
    for slug in ["dav-side", "api-side"] {
        let changes = world
            .services
            .objects
            .changes(&ctx, &world.key(&anna, slug), None, None)
            .await
            .unwrap();
        assert_eq!(changes.changes.len(), 1, "{slug}");
        assert_eq!(changes.changes[0].kind, ChangeKind::Upsert);
        assert_eq!(changes.changes[0].uid.as_ref().map(Uid::as_str), Some("eq-1"));
    }

    // Read back through the other interface: the fields agree.
    let uid = ObjectSelector::Uid(Uid::parse("eq-1").unwrap());
    let from_dav = world
        .services
        .objects
        .get_event(&ctx, &world.key(&anna, "dav-side"), &uid, None)
        .await
        .unwrap();
    let from_api = world
        .services
        .objects
        .get_event(&ctx, &world.key(&anna, "api-side"), &uid, None)
        .await
        .unwrap();
    for view in [&from_dav, &from_api] {
        assert_eq!(view.data.summary.as_deref(), Some("Planning"));
        assert_eq!(view.data.description.as_deref(), Some("Agenda"));
        assert_eq!(view.data.location.as_deref(), Some("Room 1"));
        assert_eq!(view.data.start, Some(utc(1, 9)));
        assert_eq!(view.data.end, Some(utc(1, 10)));
    }
    let as_ics = world
        .services
        .objects
        .get(
            &dav,
            &world.object(&acme, &anna, "api-side", from_api.uri.clone().unwrap().as_str()),
        )
        .await
        .unwrap();
    let text = as_ics.data.unwrap();
    assert!(
        text.contains("SUMMARY:Planning") && text.contains("LOCATION:Room 1"),
        "{text}"
    );

    // Deleting leaves the same trace, too.
    world
        .services
        .objects
        .delete(
            &dav,
            DeleteRequest {
                path: world.object(&acme, &anna, "dav-side", "eq.ics"),
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await
        .unwrap();
    world
        .services
        .objects
        .delete_event(&ctx, &world.key(&anna, "api-side"), &uid, DeleteEventOptions::default())
        .await
        .unwrap();
    let events = world.events_of(&acme, EventType::CalendarObjectsChanged).await;
    assert_eq!(events.len(), 4);
    for envelope in &events[2..] {
        let payload = World::objects_changed(envelope);
        assert_eq!(payload.sync_token.seq, 2);
        assert_eq!(payload.changes[0].kind, ObjectChangeKind::Deleted);
        assert_eq!(payload.changes[0].uid.as_str(), "eq-1");
        assert!(payload.changes[0].etag.is_none() && payload.changes[0].object.is_none());
    }
    for slug in ["dav-side", "api-side"] {
        let changes = world
            .services
            .objects
            .changes(&ctx, &world.key(&anna, slug), None, None)
            .await
            .unwrap();
        assert!(changes.changes.is_empty(), "{slug}: nothing is left to list");
        assert_eq!(seq(&world, &acme, &anna, slug).await, 2, "{slug}");
    }
}

#[tokio::test]
async fn json_writes_merge_into_the_stored_component_and_keep_what_the_event_model_does_not_know() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    let rich = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nBEGIN:VEVENT\r\nUID:rich-1\r\nDTSTAMP:20270101T000000Z\r\n\
DTSTART:20270301T090000Z\r\nDTEND:20270301T100000Z\r\nSUMMARY:Planning\r\nDESCRIPTION:Agenda\r\nX-CUSTOM-FLAG:keep-me\r\n\
BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Reminder\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let path = world.object(&acme, &anna, "personal", "rich.ics");
    world
        .services
        .objects
        .put(&dav, dav_put(&path, rich, WritePrecondition::create_only()))
        .await
        .unwrap();
    let before = world.services.objects.get(&dav, &path).await.unwrap();

    // Only the summary is in the request: everything else of the stored event stays, including what JSON cannot say.
    let selector = ObjectSelector::Uid(Uid::parse("rich-1").unwrap());
    let changed = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            update(
                selector.clone(),
                EventData {
                    summary: Some("Planning (moved)".to_owned()),
                    ..EventData::default()
                },
            ),
        )
        .await
        .unwrap();
    assert!(!changed.created);
    assert_eq!(changed.event.data.description.as_deref(), Some("Agenda"));
    assert_eq!(changed.event.data.start, Some(utc(1, 9)));
    let after = world.services.objects.get(&dav, &path).await.unwrap();
    let text = after.data.clone().unwrap();
    assert!(text.contains("SUMMARY:Planning (moved)"), "{text}");
    assert!(
        text.contains("X-CUSTOM-FLAG:keep-me"),
        "unknown properties survive: {text}"
    );
    assert!(
        text.contains("BEGIN:VALARM") && text.contains("TRIGGER:-PT15M"),
        "alarms survive: {text}"
    );
    assert!(text.contains("DESCRIPTION:Agenda"), "{text}");
    assert_ne!(after.etag, before.etag);

    // The ETag of a JSON write is a condition: stale values are refused, current ones accepted.
    let mut stale = update(
        selector.clone(),
        EventData {
            summary: Some("Late".to_owned()),
            ..EventData::default()
        },
    );
    stale.if_match = Some(before.etag.clone());
    assert_eq!(
        world
            .services
            .objects
            .put_event(&ctx, &calendar, stale)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    let mut current = update(
        selector.clone(),
        EventData {
            summary: Some("Timely".to_owned()),
            ..EventData::default()
        },
    );
    current.if_match = Some(after.etag.clone());
    assert!(world.services.objects.put_event(&ctx, &calendar, current).await.is_ok());

    // An If-Match for an object that does not exist is a failed precondition, and unknown selectors are not found.
    let mut missing = write_by_key("fresh", data("Fresh", 3, 9));
    missing.if_match = Some(ETag::from_bytes(b"whatever"));
    assert_eq!(
        world
            .services
            .objects
            .put_event(&ctx, &calendar, missing)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    let unknown = update(ObjectSelector::Uid(Uid::parse("nope").unwrap()), data("x", 1, 1));
    assert_eq!(
        world
            .services
            .objects
            .put_event(&ctx, &calendar, unknown)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    // A DAV PUT over the object shows through the JSON interface at once.
    let replaced = ics("rich-1", "Replaced by the client");
    world
        .services
        .objects
        .put(&dav, dav_put(&path, &replaced, WritePrecondition::none()))
        .await
        .unwrap();
    let view = world
        .services
        .objects
        .get_event(&ctx, &calendar, &selector, None)
        .await
        .unwrap();
    assert_eq!(view.data.summary.as_deref(), Some("Replaced by the client"));
}

#[tokio::test]
async fn dav_and_the_api_agree_on_who_may_do_what() {
    let f = fixture().await;
    let Fixture { world, acme, anna, ben } = &f;
    let carla = world.user(acme, "carla").await;
    let svc = world.principal(acme, "svc", PrincipalKind::Service).await;
    world.calendar(acme, anna, "work", CalendarKind::User).await;
    let grant = |access: GrantAccess, who: Person| {
        let world = &world;
        let acme = &acme;
        let anna = &anna;
        async move {
            world
                .services
                .sharing
                .put_grant(
                    &world.admin(acme),
                    GrantSpec {
                        calendar: world.key(anna, "work"),
                        grantee: who.name.clone(),
                        body: GrantWrite {
                            access,
                            required: false,
                        },
                    },
                    Conditions::none(),
                )
                .await
                .unwrap();
            world
                .services
                .calendars
                .list_home(&world.dav(acme, &who), &who.name)
                .await
                .unwrap();
        }
    };

    // (who, creates over DAV, creates over the API): the outcome of the same write on both interfaces.
    let attempt = |who: &Person, home: &Person, slug: &str, tag: &str| {
        let who = who.clone();
        let home = home.clone();
        let slug = slug.to_owned();
        let tag = tag.to_owned();
        let world = &world;
        let acme = &acme;
        let anna = &anna;
        async move {
            let over_dav = world
                .services
                .objects
                .put(
                    &world.dav(acme, &who),
                    dav_put(
                        &world.object(acme, &home, &slug, &format!("{tag}-dav.ics")),
                        &ics(&format!("{tag}-dav"), "Same write"),
                        WritePrecondition::none(),
                    ),
                )
                .await
                .map(|_| ())
                .map_err(|error: AppError| error.kind());
            let over_api = world
                .services
                .objects
                .put_event(
                    &world.api(
                        acme,
                        &who,
                        &[Scope::CalendarsRead, Scope::EventsRead, Scope::EventsWrite],
                    ),
                    &world.key(anna, "work"),
                    create(EventData {
                        uid: Some(Uid::parse(&format!("{tag}-api")).unwrap()),
                        ..data("Same write", 1, 9)
                    }),
                )
                .await
                .map(|_| ())
                .map_err(|error| error.kind());
            (over_dav, over_api)
        }
    };

    // The owner writes on both, a stranger finds nothing on both.
    assert_eq!(attempt(anna, anna, "work", "owner").await, (Ok(()), Ok(())));
    assert_eq!(
        attempt(&carla, anna, "work", "stranger").await,
        (Err(ErrorKind::NotFound), Err(ErrorKind::NotFound)),
        "a calendar nobody shared is invisible on both"
    );
    // A read-only sharee is forbidden on both; read-write may write on both.
    grant(GrantAccess::Read, ben.clone()).await;
    let bens_slug = "work";
    assert_eq!(
        attempt(ben, ben, bens_slug, "reader").await,
        (Err(ErrorKind::Forbidden), Err(ErrorKind::Forbidden))
    );
    grant(GrantAccess::ReadWrite, ben.clone()).await;
    assert_eq!(attempt(ben, ben, bens_slug, "writer").await, (Ok(()), Ok(())));

    // A token without the scope reaches nothing on the API, whatever the principal may do.
    let reader_token = world.api(acme, anna, &[Scope::CalendarsRead, Scope::EventsRead]);
    assert_eq!(
        world
            .services
            .objects
            .put_event(&reader_token, &world.key(anna, "work"), create(data("x", 1, 1)))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    let blind = world.api(acme, anna, &[Scope::EventsWrite]);
    assert_eq!(
        world
            .services
            .objects
            .get_by_key(&blind, &world.key(anna, "work"), &key("k"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );

    // Managed calendars: read-only on DAV, writable through the API by the owner and by tenant tokens.
    world.calendar(acme, &svc, "holidays", CalendarKind::Managed).await;
    let managed = world.key(&svc, "holidays");
    let over_dav = world
        .services
        .objects
        .put(
            &world.dav(acme, &svc),
            dav_put(
                &world.object(acme, &svc, "holidays", "h.ics"),
                &ics("h-1", "H"),
                WritePrecondition::none(),
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(over_dav.kind(), ErrorKind::Forbidden);
    let owners_token = world.api(
        acme,
        &svc,
        &[Scope::CalendarsRead, Scope::EventsRead, Scope::EventsWrite],
    );
    assert!(
        world
            .services
            .objects
            .put_event(&owners_token, &managed, write_by_key("h-1", data("H", 1, 9)))
            .await
            .is_ok()
    );
    assert!(
        world
            .services
            .objects
            .put_event(&world.admin(acme), &managed, write_by_key("h-2", data("H2", 2, 9)))
            .await
            .is_ok()
    );
    // ... but tenant tokens never reach the events of personal and user calendars.
    assert_eq!(
        world
            .services
            .objects
            .put_event(
                &world.admin(acme),
                &world.key(anna, "work"),
                write_by_key("t", data("T", 1, 9))
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        world
            .services
            .objects
            .get_by_key(&world.admin(acme), &world.key(anna, "work"), &key("t"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
}

#[tokio::test]
async fn recurring_events_are_changed_for_one_instance_this_and_following_or_all() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    let path = world.object(&acme, &anna, "personal", "daily.ics");
    let body = EventBuilder::event("daily")
        .summary("Daily")
        .starts(When::utc(2027, 3, 1, 9, 0))
        .ends(When::utc(2027, 3, 1, 10, 0))
        .rrule("FREQ=DAILY;COUNT=5")
        .build();
    world
        .services
        .objects
        .put(&dav, dav_put(&path, &body, WritePrecondition::none()))
        .await
        .unwrap();
    let selector = ObjectSelector::Uri(ObjectUri::parse("daily.ics").unwrap());

    // One instance can be read; instances the series does not have do not exist.
    let third = world
        .services
        .objects
        .get_event(&ctx, &calendar, &selector, Some(utc(3, 9)))
        .await
        .unwrap();
    assert_eq!(third.data.start, Some(utc(3, 9)));
    assert_eq!(third.data.recurrence_id, Some(utc(3, 9)));
    assert!(third.data.recurrence.is_none(), "an instance is not a series");
    assert_eq!(
        world
            .services
            .objects
            .get_event(&ctx, &calendar, &selector, Some(utc(9, 9)))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    // Changing one instance adds an override and leaves the master alone.
    let mut one = update(
        selector.clone(),
        EventData {
            summary: Some("Moved to noon".to_owned()),
            recurrence_id: Some(utc(3, 9)),
            start: Some(utc(3, 12)),
            end: Some(utc(3, 13)),
            ..EventData::default()
        },
    );
    one.scope = ChangeScope::This;
    world.services.objects.put_event(&ctx, &calendar, one).await.unwrap();
    let text = world.services.objects.get(&dav, &path).await.unwrap().data.unwrap();
    assert_eq!(text.matches("BEGIN:VEVENT").count(), 2, "{text}");
    assert!(text.contains("RECURRENCE-ID:20270303T090000Z"), "{text}");
    assert!(
        text.contains("SUMMARY:Moved to noon") && text.contains("SUMMARY:Daily"),
        "{text}"
    );
    assert!(
        text.contains("RRULE:") && text.contains("COUNT=5"),
        "the master keeps its rule: {text}"
    );

    // Removing one instance adds an exception date; the object stays.
    let before = world.events_of(&acme, EventType::CalendarObjectsChanged).await.len();
    world
        .services
        .objects
        .delete_event(
            &ctx,
            &calendar,
            &selector,
            DeleteEventOptions {
                scope: ChangeScope::This,
                recurrence_id: Some(utc(2, 9)),
                ..DeleteEventOptions::default()
            },
        )
        .await
        .unwrap();
    let text = world.services.objects.get(&dav, &path).await.unwrap().data.unwrap();
    assert!(text.contains("EXDATE"), "{text}");
    let events = world.events_of(&acme, EventType::CalendarObjectsChanged).await;
    assert_eq!(events.len(), before + 1);
    assert_eq!(
        World::objects_changed(events.last().unwrap()).changes[0].kind,
        ObjectChangeKind::Updated
    );

    // Changing "this and the following" cuts the series: the earlier part stays, the rest is a new object.
    let mut following = update(
        selector.clone(),
        EventData {
            summary: Some("Later".to_owned()),
            recurrence_id: Some(utc(4, 9)),
            ..EventData::default()
        },
    );
    following.scope = ChangeScope::ThisAndFuture;
    let outcome = world
        .services
        .objects
        .put_event(&ctx, &calendar, following)
        .await
        .unwrap();
    assert!(outcome.created, "the continuation is a new object");
    assert_eq!(outcome.event.data.summary.as_deref(), Some("Later"));
    let continued_uid = outcome.event.data.uid.clone().unwrap();
    assert_ne!(continued_uid.as_str(), "daily", "under its own UID");
    let original = world.services.objects.get(&dav, &path).await.unwrap().data.unwrap();
    assert!(original.contains("SUMMARY:Daily"), "{original}");
    let events = world.events_of(&acme, EventType::CalendarObjectsChanged).await;
    let last = World::objects_changed(events.last().unwrap());
    let kinds: Vec<ObjectChangeKind> = last.changes.iter().map(|change| change.kind).collect();
    assert_eq!(
        kinds,
        vec![ObjectChangeKind::Updated, ObjectChangeKind::Created],
        "one event for both parts"
    );
    let listed = world
        .services
        .objects
        .list(&ctx, &calendar, ObjectFilter::default(), PageRequest::first())
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 2);

    // Without a scope the whole event goes.
    world
        .services
        .objects
        .delete_event(
            &ctx,
            &calendar,
            &ObjectSelector::Uid(continued_uid),
            DeleteEventOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        world
            .services
            .objects
            .list(&ctx, &calendar, ObjectFilter::default(), PageRequest::first())
            .await
            .unwrap()
            .items
            .len(),
        1
    );
}

#[tokio::test]
async fn events_are_listed_by_range_and_key_in_pages_with_cursors_that_belong_to_their_calendar() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "other", CalendarKind::User).await;
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    for index in 1..=5_u32 {
        world
            .services
            .objects
            .put_event(
                &ctx,
                &calendar,
                write_by_key(&format!("key-{index}"), data(&format!("Event {index}"), index, 9)),
            )
            .await
            .unwrap();
    }
    world
        .services
        .objects
        .put_event(
            &ctx,
            &world.key(&anna, "other"),
            write_by_key("elsewhere", data("Elsewhere", 1, 9)),
        )
        .await
        .unwrap();

    // Pages of two, in creation order, with a cursor that only works for this listing.
    let mut summaries = Vec::new();
    let mut page = PageRequest::with_limit(2);
    let mut cursors = Vec::new();
    loop {
        let batch = world
            .services
            .objects
            .list(&ctx, &calendar, ObjectFilter::default(), page.clone())
            .await
            .unwrap();
        assert!(batch.items.len() <= 2);
        summaries.extend(batch.items.iter().map(|view| view.data.summary.clone().unwrap()));
        match batch.next_cursor {
            Some(cursor) => {
                cursors.push(cursor.clone());
                page = PageRequest::with_limit(2).after(cursor);
            }
            None => break,
        }
    }
    assert_eq!(summaries, vec!["Event 1", "Event 2", "Event 3", "Event 4", "Event 5"]);
    let foreign = world
        .services
        .objects
        .list(
            &ctx,
            &world.key(&anna, "other"),
            ObjectFilter::default(),
            PageRequest::with_limit(2).after(cursors[0].clone()),
        )
        .await
        .unwrap_err();
    assert_eq!(
        foreign.kind(),
        ErrorKind::Invalid,
        "a cursor of another calendar's listing is refused"
    );

    // Filters: a time range, an external key.
    let range = TimeRange::new(
        Some(Utc.with_ymd_and_hms(2027, 3, 2, 0, 0, 0).unwrap()),
        Some(Utc.with_ymd_and_hms(2027, 3, 4, 0, 0, 0).unwrap()),
    );
    let ranged = world
        .services
        .objects
        .list(
            &ctx,
            &calendar,
            ObjectFilter {
                range: Some(range),
                ..ObjectFilter::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(
        ranged
            .items
            .iter()
            .map(|view| view.data.summary.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["Event 2", "Event 3"]
    );
    let keyed = world
        .services
        .objects
        .list(
            &ctx,
            &calendar,
            ObjectFilter {
                external_key: Some(key("key-4")),
                ..ObjectFilter::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(keyed.items.len(), 1);
    assert_eq!(keyed.items[0].data.summary.as_deref(), Some("Event 4"));
    let components = world
        .services
        .objects
        .list(
            &ctx,
            &calendar,
            ObjectFilter {
                component: Some(ComponentKind::Todo),
                ..ObjectFilter::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert!(components.items.is_empty());

    // The scope of a list is events:read.
    let blind = world.api(&acme, &anna, &[Scope::CalendarsRead]);
    assert_eq!(
        world
            .services
            .objects
            .list(&blind, &calendar, ObjectFilter::default(), PageRequest::first())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
}

#[tokio::test]
async fn event_search_spans_the_calendars_the_caller_can_read_ordered_by_start() {
    let f = fixture().await;
    let Fixture { world, acme, anna, ben } = &f;
    world.calendar(acme, anna, "work", CalendarKind::User).await;
    let ctx = api(world, acme, anna);
    let put = |slug: &'static str, key: &'static str, summary: &'static str, day: u32| {
        let world = &world;
        let ctx = &ctx;
        let anna = &anna;
        async move {
            world
                .services
                .objects
                .put_event(ctx, &world.key(anna, slug), write_by_key(key, data(summary, day, 9)))
                .await
                .unwrap();
        }
    };
    put("personal", "p1", "Team lunch", 5).await;
    put("work", "w1", "Lunch with the board", 2).await;
    put("work", "w2", "Standup", 3).await;
    // Ben's calendars are none of anna's business.
    world
        .services
        .objects
        .put_event(
            &api(world, acme, ben),
            &world.key(ben, "personal"),
            write_by_key("b1", data("Ben's lunch", 1, 9)),
        )
        .await
        .unwrap();

    let mcp = world.mcp(acme, anna, &[Scope::McpRead]);
    let found = world
        .services
        .objects
        .search_events(
            &mcp,
            EventSearch {
                text: Some("LUNCH".to_owned()),
                ..EventSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(
        found
            .items
            .iter()
            .map(|view| view.data.summary.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["Lunch with the board", "Team lunch"],
        "across calendars, by start, only anna's"
    );

    // Calendars can be named; pages continue where the last one ended.
    let all = world
        .services
        .objects
        .search_events(
            &mcp,
            EventSearch {
                calendars: vec![world.key(anna, "work"), world.key(anna, "personal")],
                ..EventSearch::default()
            },
            PageRequest::with_limit(2),
        )
        .await
        .unwrap();
    assert_eq!(all.items.len(), 2);
    let rest = world
        .services
        .objects
        .search_events(
            &mcp,
            EventSearch {
                calendars: vec![world.key(anna, "work"), world.key(anna, "personal")],
                ..EventSearch::default()
            },
            PageRequest::with_limit(2).after(all.next_cursor.clone().unwrap()),
        )
        .await
        .unwrap();
    let summaries: Vec<String> = all
        .items
        .iter()
        .chain(rest.items.iter())
        .map(|view| view.data.summary.clone().unwrap())
        .collect();
    assert_eq!(summaries, vec!["Lunch with the board", "Standup", "Team lunch"]);
    assert!(rest.next_cursor.is_none());

    // Text needs two characters, expansion needs a range, and the MCP read scope is required.
    let short = world
        .services
        .objects
        .search_events(
            &mcp,
            EventSearch {
                text: Some("a".to_owned()),
                ..EventSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap_err();
    assert_eq!(short.field_errors().first().map(|field| field.code), Some("too-short"));
    let open = world
        .services
        .objects
        .search_events(
            &mcp,
            EventSearch {
                expand: true,
                ..EventSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap_err();
    assert_eq!(open.field_errors().first().map(|field| field.pointer), Some("/range"));
    let unscoped = world.mcp(acme, anna, &[Scope::McpWrite]);
    assert_eq!(
        world
            .services
            .objects
            .search_events(&unscoped, EventSearch::default(), PageRequest::first())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
}

#[tokio::test]
async fn search_expands_recurring_events_into_instances_inside_the_range() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let body = EventBuilder::event("daily")
        .summary("Daily")
        .starts(When::utc(2027, 3, 1, 9, 0))
        .ends(When::utc(2027, 3, 1, 10, 0))
        .rrule("FREQ=DAILY;COUNT=5")
        .build();
    world
        .services
        .objects
        .put(
            &dav,
            dav_put(
                &world.object(&acme, &anna, "personal", "daily.ics"),
                &body,
                WritePrecondition::none(),
            ),
        )
        .await
        .unwrap();
    let mcp = world.mcp(&acme, &anna, &[Scope::McpRead]);
    let range = TimeRange::new(
        Some(Utc.with_ymd_and_hms(2027, 3, 2, 0, 0, 0).unwrap()),
        Some(Utc.with_ymd_and_hms(2027, 3, 4, 12, 0, 0).unwrap()),
    );
    let found = world
        .services
        .objects
        .search_events(
            &mcp,
            EventSearch {
                range: Some(range),
                expand: true,
                ..EventSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    let starts: Vec<Option<EventTime>> = found.items.iter().map(|view| view.data.start.clone()).collect();
    assert_eq!(starts, vec![Some(utc(2, 9)), Some(utc(3, 9)), Some(utc(4, 9))]);
    assert!(
        found
            .items
            .iter()
            .all(|view| view.data.recurrence_id.is_some() && view.data.recurrence.is_none())
    );
    // Without expansion the event is one result.
    let single = world
        .services
        .objects
        .search_events(
            &mcp,
            EventSearch {
                range: Some(range),
                ..EventSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(single.items.len(), 1);
}

#[tokio::test]
async fn the_changes_feed_follows_the_sync_token_of_the_calendar() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "work");
    for name in ["a", "b"] {
        world
            .services
            .objects
            .put_event(&ctx, &calendar, write_by_key(name, data(name, 1, 9)))
            .await
            .unwrap();
    }
    let initial = world
        .services
        .objects
        .changes(&ctx, &calendar, None, None)
        .await
        .unwrap();
    assert_eq!(initial.changes.len(), 2);
    let keys: Vec<Option<ExternalKey>> = initial
        .changes
        .iter()
        .map(|change| change.external_key.clone())
        .collect();
    assert!(keys.contains(&Some(key("a"))) && keys.contains(&Some(key("b"))));
    assert!(!initial.truncated);
    assert_eq!(
        initial.sync_token,
        world
            .services
            .calendars
            .get(&world.admin(&acme), &calendar)
            .await
            .unwrap()
            .sync_token,
        "the feed's token is the calendar's token"
    );

    world
        .services
        .objects
        .put_event(&ctx, &calendar, write_by_key("a", data("a changed", 1, 9)))
        .await
        .unwrap();
    world
        .services
        .objects
        .delete_by_key(&ctx, &calendar, &key("b"), DeleteEventOptions::default())
        .await
        .unwrap();
    let since = world
        .services
        .objects
        .changes(&ctx, &calendar, Some(initial.sync_token), None)
        .await
        .unwrap();
    let describe: Vec<(ChangeKind, Option<ExternalKey>)> = since
        .changes
        .iter()
        .map(|change| (change.kind, change.external_key.clone()))
        .collect();
    assert_eq!(
        describe,
        vec![(ChangeKind::Upsert, Some(key("a"))), (ChangeKind::Delete, None)],
        "a deleted object is known by its resource name only"
    );
    assert!(since.changes[1].etag.is_none());

    // Tokens of other calendars and from the future are refused.
    let other_token = world
        .services
        .calendars
        .get(&world.admin(&acme), &world.key(&anna, "personal"))
        .await
        .unwrap()
        .sync_token;
    let future = SyncToken::new(
        initial.sync_token.collection,
        initial.sync_token.epoch,
        since.sync_token.seq + 50,
    );
    for token in [other_token, future] {
        let error = world
            .services
            .objects
            .changes(&ctx, &calendar, Some(token), None)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid);
        assert_eq!(error.precondition().map(Precondition::code), Some("valid-sync-token"));
    }
}

#[tokio::test]
async fn mcp_writes_are_audited_in_the_transaction_of_the_write() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let mcp = world.mcp(&acme, &anna, &[Scope::McpRead, Scope::McpWrite]);
    let calendar = world.key(&anna, "personal");
    let before = world.audit_actions(&acme).await.len();

    let created = world
        .services
        .objects
        .put_event(&mcp, &calendar, create(data("From an assistant", 1, 9)))
        .await
        .unwrap();
    let uid = created.event.data.uid.clone().unwrap();
    world
        .services
        .objects
        .put_event(
            &mcp,
            &calendar,
            update(
                ObjectSelector::Uid(uid.clone()),
                EventData {
                    summary: Some("Renamed".to_owned()),
                    ..EventData::default()
                },
            ),
        )
        .await
        .unwrap();
    world
        .services
        .objects
        .delete_event(
            &mcp,
            &calendar,
            &ObjectSelector::Uid(uid.clone()),
            DeleteEventOptions::default(),
        )
        .await
        .unwrap();
    let audit = world.audit(&acme).await;
    let writes: Vec<&davhaven_testkit::davhaven_ports::AuditRow> = audit
        .iter()
        .skip(before)
        .filter(|row| row.action == "mcp.write")
        .collect();
    assert_eq!(writes.len(), 3);
    let tools: Vec<String> = writes
        .iter()
        .map(|row| row.details["tool"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(tools, vec!["create_event", "update_event", "delete_event"]);
    assert!(writes.iter().all(|row| row.actor.principal_id == Some(anna.id)));
    let text = format!("{writes:?}");
    assert!(
        !text.contains("From an assistant") && !text.contains("Renamed"),
        "no event content in the audit"
    );

    // A refused write leaves no record; neither do reads and API writes.
    let refused = world
        .services
        .objects
        .put_event(
            &mcp,
            &calendar,
            EventWrite {
                if_match: Some(ETag::from_bytes(b"stale")),
                ..create(data("x", 1, 9))
            },
        )
        .await;
    assert_eq!(refused.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    world
        .services
        .objects
        .put_event(
            &api(&world, &acme, &anna),
            &calendar,
            create(data("From the API", 2, 9)),
        )
        .await
        .unwrap();
    world
        .services
        .objects
        .get_event(&mcp, &calendar, &ObjectSelector::Uid(Uid::parse("none").unwrap()), None)
        .await
        .ok();
    assert_eq!(
        world
            .audit(&acme)
            .await
            .iter()
            .filter(|row| row.action == "mcp.write")
            .count(),
        3
    );
}

/// A recurring event `daily` (five days from 2027-03-01 09:00 UTC) in the personal calendar of `owner`.
async fn daily_series(world: &World, org: &Org, owner: &Person) {
    let body = EventBuilder::event("daily")
        .summary("Daily")
        .starts(When::utc(2027, 3, 1, 9, 0))
        .ends(When::utc(2027, 3, 1, 10, 0))
        .rrule("FREQ=DAILY;COUNT=5")
        .build();
    world
        .services
        .objects
        .put(
            &world.dav(org, owner),
            dav_put(
                &world.object(org, owner, "personal", "daily.ics"),
                &body,
                WritePrecondition::none(),
            ),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn deleting_or_changing_this_instance_needs_its_recurrence_id_and_never_touches_the_series_without_it() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    daily_series(&world, &acme, &anna).await;
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    let selector = ObjectSelector::Uid(Uid::parse("daily").unwrap());
    let id = calendar_id(&world, &acme, &anna, "personal").await;
    let before = stored(&world, &acme, id, "daily").await;
    let start = seq(&world, &acme, &anna, "personal").await;
    let objects = &world.services.objects;

    for scope in [ChangeScope::This, ChangeScope::ThisAndFuture] {
        let error = objects
            .delete_event(
                &ctx,
                &calendar,
                &selector,
                DeleteEventOptions {
                    scope,
                    ..DeleteEventOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "delete {scope:?}");
        assert_eq!(
            error.field_errors().first().map(|field| field.pointer),
            Some("/recurrence_id")
        );
        let mut write = update(selector.clone(), data("Changed", 1, 9));
        write.scope = scope;
        let error = objects.put_event(&ctx, &calendar, write).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "write {scope:?}");
        assert_eq!(
            error.field_errors().first().map(|field| field.pointer),
            Some("/recurrence_id")
        );
    }
    assert_eq!(
        stored(&world, &acme, id, "daily").await.etag,
        before.etag,
        "the series is intact"
    );
    assert_eq!(seq(&world, &acme, &anna, "personal").await, start);

    // With the instance named, the same request is accepted and reaches that instance only.
    objects
        .delete_event(
            &ctx,
            &calendar,
            &selector,
            DeleteEventOptions {
                scope: ChangeScope::This,
                recurrence_id: Some(utc(2, 9)),
                ..DeleteEventOptions::default()
            },
        )
        .await
        .unwrap();
    assert_ne!(stored(&world, &acme, id, "daily").await.etag, before.etag);
}

#[tokio::test]
async fn a_stranger_learns_nothing_about_events_from_preconditions_instances_or_selectors() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    daily_series(&world, &acme, &anna).await;
    let bens = api(&world, &acme, &ben);
    let calendar = world.key(&anna, "personal");
    let objects = &world.services.objects;
    let state = || async {
        (
            seq(&world, &acme, &anna, "personal").await,
            world.audit(&acme).await.len(),
            world.events(&acme).await.len(),
        )
    };
    let before = state().await;

    let selectors = [
        ObjectSelector::Uid(Uid::parse("daily").unwrap()),
        ObjectSelector::Uid(Uid::parse("missing").unwrap()),
        ObjectSelector::Key(key("no-such-key")),
        ObjectSelector::Id(davhaven_testkit::davhaven_domain::ObjectId::from_uuid(
            uuid::Uuid::from_u128(5),
        )),
    ];
    for selector in &selectors {
        let plain = DeleteEventOptions::default();
        let outdated = DeleteEventOptions {
            if_match: Some(ETag::from_bytes(b"stale")),
            ..DeleteEventOptions::default()
        };
        // Names no instance of the series: a caller who may see the series is told so, nobody else.
        let instance = DeleteEventOptions {
            scope: ChangeScope::This,
            recurrence_id: Some(utc(9, 9)),
            ..DeleteEventOptions::default()
        };
        for options in [plain, outdated, instance] {
            let error = objects
                .delete_event(&bens, &calendar, selector, options)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound, "delete {selector:?}");
        }
        let mut conditional = update(selector.clone(), data("X", 1, 9));
        conditional.if_match = Some(ETag::from_bytes(b"stale"));
        for write in [conditional, update(selector.clone(), data("X", 1, 9))] {
            let error = objects.put_event(&bens, &calendar, write).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound, "write {selector:?}");
        }
    }
    assert_eq!(state().await, before, "no sequence, audit or event changed");

    // A caller who sees the calendar but may not write to it is forbidden, whether the object exists or not.
    let admin = world.admin(&acme);
    for selector in [&selectors[0], &selectors[1]] {
        for options in [
            DeleteEventOptions::default(),
            DeleteEventOptions {
                if_match: Some(ETag::from_bytes(b"stale")),
                ..DeleteEventOptions::default()
            },
        ] {
            let error = objects
                .delete_event(&admin, &calendar, selector, options)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Forbidden, "delete {selector:?}");
        }
        let error = objects
            .put_event(&admin, &calendar, update(selector.clone(), data("X", 1, 9)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Forbidden, "write {selector:?}");
    }
    assert_eq!(state().await, before);
}

#[tokio::test]
async fn concurrent_writes_of_one_event_both_succeed_and_none_is_lost() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    let objects = &world.services.objects;
    objects
        .put_event(&ctx, &calendar, write_by_key("k-1", data("First", 1, 9)))
        .await
        .unwrap();
    let start = seq(&world, &acme, &anna, "personal").await;
    // Both read the same version before either locks the calendar: the second one starts over from the first.
    let (a, b) = tokio::join!(
        objects.put_event(&ctx, &calendar, write_by_key("k-1", data("From A", 1, 9))),
        objects.put_event(&ctx, &calendar, write_by_key("k-1", data("From B", 1, 9))),
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(seq(&world, &acme, &anna, "personal").await, start + 2);
}

/// Follows the cursors of a search to its end and returns the summaries of every page, in the order they came, and the
/// number of pages.
async fn every_page(world: &World, ctx: &RequestContext, search: EventSearch, limit: u32) -> (Vec<String>, usize) {
    let mut summaries = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let mut page = PageRequest::with_limit(limit);
        if let Some(next) = cursor.take() {
            page = page.after(next);
        }
        let result = world
            .services
            .objects
            .search_events(ctx, search.clone(), page)
            .await
            .unwrap();
        summaries.extend(result.items.iter().map(|view| view.data.summary.clone().unwrap()));
        pages += 1;
        assert!(pages < 200, "the cursors must lead to an end");
        match result.next_cursor {
            Some(next) => cursor = Some(next),
            None => return (summaries, pages),
        }
    }
}

#[tokio::test]
async fn a_search_that_is_too_large_to_order_is_paged_in_scan_order_and_loses_nothing() {
    // The whole search cannot be examined in one request (3 objects), so no chronological order exists.
    let world = World::with(|deps| deps.limits.api.max_scanned_objects = 3);
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    for n in 0..8 {
        world
            .services
            .objects
            .put_event(
                &ctx,
                &calendar,
                write_by_key(&format!("k-{n}"), data(&format!("Event {n}"), 1 + n, 9)),
            )
            .await
            .unwrap();
    }
    let mcp = world.mcp(&acme, &anna, &[Scope::McpRead]);
    let (mut seen, pages) = every_page(&world, &mcp, EventSearch::default(), 2).await;
    assert!(pages >= 4, "{pages} pages of two for eight events");
    seen.sort();
    assert_eq!(
        seen,
        (0..8).map(|n| format!("Event {n}")).collect::<Vec<_>>(),
        "every event exactly once"
    );
}

#[tokio::test]
async fn a_search_bound_that_ends_a_request_early_answers_with_a_cursor_never_with_silence() {
    // 450 events, ten of them match; a request reads 200 objects at most.
    let world = World::with(|deps| deps.limits.api.max_scanned_objects = 200);
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ctx = api(&world, &acme, &anna);
    let items = (0..450)
        .map(|n| davhaven_testkit::davhaven_wire::BatchItem {
            external_key: key(&format!("e-{n:03}")),
            event: Some(EventView::from_data(data(
                if n >= 440 { "Needle in a haystack" } else { "Hay" },
                1,
                9,
            ))),
            ical: None,
        })
        .collect();
    let batch = world
        .services
        .objects
        .batch(
            &ctx,
            &world.key(&anna, "personal"),
            davhaven_testkit::davhaven_wire::BatchRequest {
                items,
                ..davhaven_testkit::davhaven_wire::BatchRequest::default()
            },
        )
        .await
        .unwrap();
    assert!(!batch.has_failures());

    let mcp = world.mcp(&acme, &anna, &[Scope::McpRead]);
    let first = world
        .services
        .objects
        .search_events(
            &mcp,
            EventSearch {
                text: Some("needle".to_owned()),
                ..EventSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert!(
        first.items.is_empty() && first.next_cursor.is_some(),
        "the first 200 objects hold no match, and the answer says there is more to look at"
    );
    let (seen, pages) = every_page(
        &world,
        &mcp,
        EventSearch {
            text: Some("needle".to_owned()),
            ..EventSearch::default()
        },
        50,
    )
    .await;
    assert!(pages >= 2, "{pages}");
    assert_eq!(seen.len(), 10, "every match, found behind the bound: {seen:?}");
}

#[tokio::test]
async fn expanded_instances_are_paged_in_start_order_and_across_the_cut_of_a_series() {
    for max_scanned in [5000, 1] {
        // With 5000 the search is ordered by start; with 1 the scan order applies and a page can be cut inside the
        // series, which the cursor then names by the start of the last instance it delivered.
        let world = World::with(|deps| deps.limits.api.max_scanned_objects = max_scanned);
        let acme = world.org("acme").await;
        let anna = world.user(&acme, "anna").await;
        daily_series(&world, &acme, &anna).await;
        world
            .services
            .objects
            .put_event(
                &api(&world, &acme, &anna),
                &world.key(&anna, "personal"),
                write_by_key("single", data("Single", 3, 10)),
            )
            .await
            .unwrap();
        let mcp = world.mcp(&acme, &anna, &[Scope::McpRead]);
        let search = EventSearch {
            range: Some(TimeRange::new(
                Some(Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap()),
                Some(Utc.with_ymd_and_hms(2027, 3, 10, 0, 0, 0).unwrap()),
            )),
            expand: true,
            ..EventSearch::default()
        };
        let (seen, pages) = every_page(&world, &mcp, search, 2).await;
        assert!(pages >= 3, "{pages}");
        let mut counted = seen.clone();
        counted.sort();
        assert_eq!(
            counted,
            vec!["Daily", "Daily", "Daily", "Daily", "Daily", "Single"],
            "five instances and one event, each once (max_scanned_objects = {max_scanned})"
        );
        if max_scanned == 5000 {
            assert_eq!(
                seen,
                vec!["Daily", "Daily", "Daily", "Single", "Daily", "Daily"],
                "ordered by start across the pages"
            );
        }
    }
}

/// The denial matrix of the JSON event writes: whoever may not write is told so before anything else about the
/// request is looked at (the conditions, the scope, the recurrence id), and nothing changes.
#[tokio::test]
async fn a_denied_event_write_is_denied_before_its_conditions_and_changes_nothing() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let calendar = world.key(&anna, "personal");
    let admin = world.admin(&acme);
    world
        .services
        .objects
        .put_event(
            &api(&world, &acme, &anna),
            &calendar,
            write_by_key("k", data("Existing", 1, 9)),
        )
        .await
        .unwrap();
    let state = || async {
        let view = world.services.calendars.get(&admin, &calendar).await.unwrap();
        (
            view.sync_token.seq,
            world.audit(&acme).await.len(),
            world.events(&acme).await.len(),
        )
    };
    let before = state().await;

    let selector = ObjectSelector::Key(key("k"));
    let writes = || {
        let mut with_stale_tag = update(selector.clone(), data("Changed", 1, 9));
        with_stale_tag.if_match = Some(ETag::from_bytes(b"stale"));
        let mut without_instance = update(selector.clone(), data("Changed", 1, 9));
        without_instance.scope = ChangeScope::This;
        let mut missing = update(ObjectSelector::Key(key("ghost")), data("Ghost", 1, 9));
        missing.if_match = Some(ETag::from_bytes(b"stale"));
        [
            ("create", create(data("New", 2, 9))),
            ("key create", write_by_key("fresh", data("Fresh", 2, 9))),
            ("stale if-match", with_stale_tag),
            ("instance without recurrence id", without_instance),
            ("stale if-match on a missing key", missing),
        ]
    };
    let deletions = || {
        [
            (
                "stale if-match",
                DeleteEventOptions {
                    if_match: Some(ETag::from_bytes(b"stale")),
                    ..DeleteEventOptions::default()
                },
            ),
            (
                "instance without recurrence id",
                DeleteEventOptions {
                    scope: ChangeScope::ThisAndFuture,
                    ..DeleteEventOptions::default()
                },
            ),
        ]
    };

    // Ben sees nothing of Anna's calendar.
    let subjects = [("stranger", api(&world, &acme, &ben), ErrorKind::NotFound)];
    for (who, context, expected) in &subjects {
        for (what, write) in writes() {
            let error = world
                .services
                .objects
                .put_event(context, &calendar, write)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), *expected, "{who}: {what}");
        }
        for (what, options) in deletions() {
            let error = world
                .services
                .objects
                .delete_event(context, &calendar, &selector, options)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), *expected, "{who}: delete, {what}");
        }
    }
    assert_eq!(state().await, before, "the stranger changed nothing");

    // Ben may read the calendar now: he is told he may not write, whatever else is wrong with the request.
    world
        .services
        .sharing
        .put_grant(
            &admin,
            GrantSpec {
                calendar: calendar.clone(),
                grantee: ben.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    let before = state().await;
    let readers = [
        ("reader", api(&world, &acme, &ben)),
        // A tenant token administers managed and group calendars, never the personal calendar of a user.
        ("tenant token", admin.clone()),
    ];
    for (who, context) in &readers {
        for (what, write) in writes() {
            let error = world
                .services
                .objects
                .put_event(context, &calendar, write)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Forbidden, "{who}: {what}");
        }
        for (what, options) in deletions() {
            let error = world
                .services
                .objects
                .delete_event(context, &calendar, &selector, options)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Forbidden, "{who}: delete, {what}");
        }
    }
    assert_eq!(
        state().await,
        (before.0, before.1, before.2),
        "nothing was written, recorded or announced"
    );
}

#[tokio::test]
async fn a_value_that_grows_when_the_server_writes_it_is_refused_up_front_and_what_fits_can_be_merged() {
    // Commas that a client sends without a backslash are written with one: 40,000 bytes as sent are 80,000 as the
    // server writes them, above the limit of 64 KiB for a value. The server must be able to store and read its own
    // text, so such data is refused when it comes in (not when the server first rewrites it, which it then could
    // not do for anything but a refusal): see `parse::accept`.
    let Fixture { world, acme, anna, .. } = fixture().await;
    let dav = world.dav(&acme, &anna);
    let put = |uri: &str, uid: &str, commas: usize| {
        let body = format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
             DTSTAMP:20270101T000000Z\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nSUMMARY:Long\r\n\
             DESCRIPTION:{}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            ",".repeat(commas)
        );
        let request = dav_put(
            &world.object(&acme, &anna, "personal", uri),
            &body,
            WritePrecondition::none(),
        );
        let (services, dav) = (&world.services, &dav);
        async move { services.objects.put(dav, request).await }
    };
    let refused = put("big.ics", "big", 40_000).await.unwrap_err();
    assert!(
        matches!(refused.precondition(), Some(Precondition::ValidCalendarData(_))),
        "{refused:?}"
    );
    put("fits.ics", "fits", 30_000).await.unwrap();

    // What was accepted can be changed through JSON: the server writes the object again and reads it back under the
    // limits.
    let ctx = api(&world, &acme, &anna);
    let calendar = world.key(&anna, "personal");
    let changed = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            update(
                ObjectSelector::Uid(Uid::parse("fits").unwrap()),
                EventData {
                    summary: Some("Changed".to_owned()),
                    ..EventData::default()
                }
                .without(davhaven_testkit::davhaven_domain::EventField::Location),
            ),
        )
        .await
        .expect("an object that the gate accepted can be rewritten");
    assert_eq!(changed.event.data.summary.as_deref(), Some("Changed"));
    let calendar_id = calendar_id(&world, &acme, &anna, "personal").await;
    let text = stored(&world, &acme, calendar_id, "fits").await.data;
    assert!(text.contains("SUMMARY:Changed"), "{text}");
}
