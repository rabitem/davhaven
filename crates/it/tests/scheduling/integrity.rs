//! What somebody who writes a calendar cannot do to the objects of other people (PLAN 2.8): reuse the `UID` of an
//! event they know to overwrite or delete it, turn an event into a meeting of a colleague, change a meeting in a group
//! calendar that is not theirs, lean on a stale `If-Match`, or use what two requests happen to share.
//!
//! Each case asserts that what belongs to somebody else is **unchanged**: the bytes, the `ETag`, the answers of the
//! attendees and the inbox of the person who owns it.

use davhaven_testkit::davhaven_app::services::{
    IfMatch, RecipientStatus, ScheduleReply, ScheduleStatus, WritePrecondition,
};
use davhaven_testkit::davhaven_domain::{
    CalendarKind, ETag, ErrorKind, EventStatus, GrantAccess, ItipMethod, OutboxId, PartStat, Precondition,
    RequestContext, RequestId,
};
use davhaven_testkit::davhaven_fixtures::event::{Attendee, EventBuilder, Organizer, When};
use davhaven_testkit::davhaven_ports::{
    Database as _, DeliveryJob, IdGenerator as _, NewOutbox, OutboxMessage, TxMode,
};
use uuid::Uuid;

use super::support::{Org, Person, World, answered, in_collection, meeting, partstat_in, property_in, status_in};

/// What a person holds under a `UID`: the object as stored, the answers of its attendees and the size of the inbox.
#[derive(Debug, PartialEq)]
struct Held {
    etag: ETag,
    data: String,
    answers: Vec<(String, PartStat)>,
    inbox: usize,
}

async fn held(world: &World, org: &Org, person: &Person, uid: &str) -> Held {
    let object = world
        .copy_of(org, person, uid)
        .await
        .unwrap_or_else(|| panic!("{} has no object under {uid}", person.name));
    let rows = world.read(org).await.objects().attendees(object.id).await.unwrap();
    Held {
        etag: object.etag,
        data: object.data,
        answers: rows
            .iter()
            .map(|row| (row.address.as_str().to_owned(), row.partstat))
            .collect(),
        inbox: world.inbox(org, person).await.len(),
    }
}

fn moved(builder: EventBuilder) -> EventBuilder {
    builder
        .starts(When::utc(2027, 3, 11, 9, 0))
        .ends(When::utc(2027, 3, 11, 10, 0))
}

/// An event of somebody outside the tenant that somebody wrote into their own calendar (an import).
fn imported(uid: &str, organizer: &str) -> EventBuilder {
    EventBuilder::event(uid)
        .summary("Imported")
        .starts(When::utc(2027, 3, 10, 9, 0))
        .ends(When::utc(2027, 3, 10, 10, 0))
        .organizer(Organizer::new(organizer))
        .attendee(Attendee::new("mailto:guest@example.net"))
}

/// Ben writes, changes, cancels and deletes events whose `UID` is `uid`, the one of an object of `victim`, and names
/// the victim as the attendee: he is not the organizer of what the victim holds, so nothing of it may be touched, and
/// the organizer's copy says that nothing was delivered.
async fn reuse_the_uid(world: &World, acme: &Org, ben: &Person, victim: &Person, uid: &str) {
    let ctx = world.dav(acme, ben);
    let guest = victim.mailto();
    let path = world.object(acme, ben, "plant.ics");
    let failed = vec![RecipientStatus {
        address: victim.address(),
        status: ScheduleStatus::Failed,
    }];

    let outcome = world
        .put(&ctx, &path, &meeting(uid, ben, &[&guest]).build())
        .await
        .unwrap();
    assert_eq!(outcome.schedule.recipients, failed, "{uid}: a new event");
    let stored = world.text(&ctx, &path).await;
    assert_eq!(status_in(&stored, &guest).as_deref(), Some("5.1"), "{uid}: {stored}");

    let outcome = world
        .put(&ctx, &path, &moved(meeting(uid, ben, &[&guest])).build())
        .await
        .unwrap();
    assert_eq!(outcome.schedule.recipients, failed, "{uid}: a significant change");

    let outcome = world
        .put(
            &ctx,
            &path,
            &moved(meeting(uid, ben, &[&guest]))
                .status(EventStatus::Cancelled)
                .build(),
        )
        .await
        .unwrap();
    assert_eq!(outcome.schedule.recipients, failed, "{uid}: a cancellation");

    world.delete(&ctx, &path).await.unwrap();

    // An event that is created cancelled invites nobody, so it cancels nothing either.
    let second = world.object(acme, ben, "plant-2.ics");
    let outcome = world
        .put(
            &ctx,
            &second,
            &moved(meeting(uid, ben, &[&guest]))
                .status(EventStatus::Cancelled)
                .build(),
        )
        .await
        .unwrap();
    assert!(outcome.schedule.recipients.is_empty(), "{uid}: created cancelled");
    world.delete(&ctx, &second).await.unwrap();
}

#[tokio::test]
async fn reusing_the_uid_of_a_meeting_somebody_organizes_cannot_replace_or_delete_it() {
    let world = World::new();
    let acme = world.org("acme").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let dave = world.user(&acme, "dave").await;
    world
        .put(
            &world.dav(&acme, &cara),
            &world.object(&acme, &cara, "own.ics"),
            &meeting("own-1", &cara, &[&dave.mailto()]).build(),
        )
        .await
        .unwrap();
    let before = held(&world, &acme, &cara, "own-1").await;

    reuse_the_uid(&world, &acme, &ben, &cara, "own-1").await;

    assert_eq!(
        held(&world, &acme, &cara, "own-1").await,
        before,
        "Cara's own meeting, her own organizer copy, is untouched"
    );
    assert!(world.mail_jobs(&acme).await.is_empty(), "no mail");
}

#[tokio::test]
async fn reusing_the_uid_of_a_meeting_somebody_attends_cannot_replace_or_delete_their_copy() {
    let world = World::new();
    let acme = world.org("acme").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let dave = world.user(&acme, "dave").await;
    world
        .put(
            &world.dav(&acme, &dave),
            &world.object(&acme, &dave, "theirs.ics"),
            &meeting("theirs-1", &dave, &[&cara.mailto()]).build(),
        )
        .await
        .unwrap();
    let before = held(&world, &acme, &cara, "theirs-1").await;
    assert_eq!(before.inbox, 1, "Dave's invitation is in her inbox");

    reuse_the_uid(&world, &acme, &ben, &cara, "theirs-1").await;

    assert_eq!(
        held(&world, &acme, &cara, "theirs-1").await,
        before,
        "Cara's copy of Dave's meeting, and her inbox, are untouched"
    );
}

#[tokio::test]
async fn reusing_the_uid_of_a_booking_cannot_replace_it_or_get_the_room_to_decline_it() {
    let world = World::new();
    let acme = world.org("acme").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let room = world.resource(&acme, "room1").await;
    world
        .put(
            &world.dav(&acme, &cara),
            &world.object(&acme, &cara, "booking.ics"),
            &meeting("book-1", &cara, &[&room.mailto()]).build(),
        )
        .await
        .unwrap();
    let before = held(&world, &acme, &room, "book-1").await;
    let booked = world
        .text(&world.dav(&acme, &cara), &world.object(&acme, &cara, "booking.ics"))
        .await;
    assert_eq!(
        partstat_in(&booked, &room.mailto()),
        Some(PartStat::Accepted),
        "the room accepted: {booked}"
    );

    reuse_the_uid(&world, &acme, &ben, &room, "book-1").await;

    assert_eq!(
        held(&world, &acme, &room, "book-1").await,
        before,
        "the booking of Cara is still the room's, accepted, as it was"
    );
}

#[tokio::test]
async fn a_queued_delivery_of_another_organizer_is_skipped_by_the_handler_too() {
    let world = World::new();
    let acme = world.org("acme").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let dave = world.user(&acme, "dave").await;
    world
        .put(
            &world.dav(&acme, &cara),
            &world.object(&acme, &cara, "own.ics"),
            &meeting("own-1", &cara, &[&dave.mailto()]).build(),
        )
        .await
        .unwrap();
    let before = held(&world, &acme, &cara, "own-1").await;

    // Ben's event with the UID of Cara's meeting (nothing is queued for her: the write refuses to deliver).
    let text = meeting("own-1", &ben, &[&cara.mailto()]).build();
    world
        .put(&world.dav(&acme, &ben), &world.object(&acme, &ben, "plant.ics"), &text)
        .await
        .unwrap();
    assert!(
        world
            .outbox_records(&acme)
            .await
            .iter()
            .all(|record| record.kind != "internal_delivery")
    );
    let planted = world.copy_of(&acme, &ben, "own-1").await.unwrap();

    // Records as the write of an organizer above the cap would have made them, naming Cara and the UID of her meeting:
    // the handler must not believe that they are about her object.
    for (method, copy_only) in [
        (ItipMethod::Cancel, false),
        (ItipMethod::Request, false),
        (ItipMethod::Request, true),
    ] {
        let mut tx = world.db.begin(acme.id, TxMode::ReadWrite).await.unwrap();
        tx.outbox()
            .enqueue(NewOutbox::now(
                OutboxId::from_uuid(world.ids.new_id()),
                OutboxMessage::InternalDelivery(DeliveryJob {
                    calendar: planted.calendar_id,
                    object: planted.id,
                    method,
                    recipients: vec![cara.id],
                    snapshot: Some(moved(meeting("own-1", &ben, &[&cara.mailto()])).build()),
                    copy_only,
                }),
            ))
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    world.run_outbox().await;

    assert_eq!(held(&world, &acme, &cara, "own-1").await, before);
}

#[tokio::test]
async fn an_event_cannot_become_a_meeting_of_a_colleague_by_being_written_twice() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let ctx = world.dav(&acme, &ben);
    let path = world.object(&acme, &ben, "p.ics");
    let plain = EventBuilder::event("p-1")
        .summary("Plain")
        .starts(When::utc(2027, 3, 10, 9, 0))
        .ends(When::utc(2027, 3, 10, 10, 0))
        .build();
    world.put(&ctx, &path, &plain).await.unwrap();

    // The second write names Anna as the organizer and Cara as an attendee (C:organizer-allowed, as for a new object).
    let error = world
        .put(&ctx, &path, &meeting("p-1", &anna, &[&cara.mailto()]).build())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(error.precondition(), Some(&Precondition::OrganizerAllowed));
    assert_eq!(world.text(&ctx, &path).await, plain, "nothing was stored");
    assert!(world.inbox(&acme, &cara).await.is_empty(), "Cara is told nothing");
    assert!(world.inbox(&acme, &anna).await.is_empty(), "Anna is told nothing");

    // The organizer of an existing meeting does not change either, whoever the new one is.
    let imported_path = world.object(&acme, &ben, "i.ics");
    let original = imported("i-1", "mailto:olga@example.net").build();
    world.put(&ctx, &imported_path, &original).await.unwrap();
    for organizer in [anna.mailto(), "mailto:mallory@example.org".to_owned()] {
        let error = world
            .put(&ctx, &imported_path, &imported("i-1", &organizer).build())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Forbidden, "{organizer}");
        assert_eq!(
            error.precondition(),
            Some(&Precondition::AllowedOrganizerSchedulingObjectChange),
            "{organizer}"
        );
    }
    assert_eq!(world.text(&ctx, &imported_path).await, original, "nothing was stored");
    // Their own imported event is theirs to edit.
    let retitled = imported("i-1", "mailto:olga@example.net").summary("Mine now").build();
    world.put(&ctx, &imported_path, &retitled).await.unwrap();
    assert!(world.text(&ctx, &imported_path).await.contains("SUMMARY:Mine now"));
}

#[tokio::test]
async fn in_a_group_calendar_only_the_organizer_changes_or_deletes_a_meeting() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let dan = world.user(&acme, "dan").await;
    let team = world.group(&acme, "team", &[&anna, &ben, &cara]).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    let anna_shared = world.collection_of(&acme, &anna, &team).await;
    let cara_shared = world.collection_of(&acme, &cara, &team).await;
    let (anna_ctx, cara_ctx) = (world.dav(&acme, &anna), world.dav(&acme, &cara));
    let anna_path = in_collection(&anna_shared, "g-1.ics");
    let cara_path = in_collection(&cara_shared, "g-1.ics");
    world
        .put(&anna_ctx, &anna_path, &meeting("g-1", &anna, &[&dan.mailto()]).build())
        .await
        .unwrap();
    let original = world.text(&anna_ctx, &anna_path).await;
    let dan_before = world.inbox(&acme, &dan).await.len();

    // Cara is a member of the group and may write its calendar, but the meeting is Anna's.
    let retitled = original.replace("SUMMARY:Planning", "SUMMARY:Cara's meeting");
    let hijacked = original.replace(&anna.mailto(), &cara.mailto());
    for (what, body) in [("a new title", &retitled), ("a new organizer", &hijacked)] {
        let error = world.put(&cara_ctx, &cara_path, body).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Forbidden, "{what}");
        assert_eq!(
            error.precondition(),
            Some(&Precondition::AllowedOrganizerSchedulingObjectChange),
            "{what}"
        );
    }
    let error = world.delete(&cara_ctx, &cara_path).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden, "a deletion");
    assert_eq!(
        world.text(&anna_ctx, &anna_path).await,
        original,
        "the meeting is as Anna wrote it"
    );
    assert_eq!(world.inbox(&acme, &dan).await.len(), dan_before, "Dan is told nothing");
    assert!(world.copy_of(&acme, &dan, "g-1").await.is_some(), "and keeps his copy");

    // Anna changes it, and the attendee follows.
    world.put(&anna_ctx, &anna_path, &retitled).await.unwrap();
    assert!(
        world
            .copy_of(&acme, &dan, "g-1")
            .await
            .unwrap()
            .data
            .contains("SUMMARY:Cara's meeting")
    );

    // An event without attendees is nobody's meeting: every member may edit it.
    let note = EventBuilder::event("n-1")
        .summary("Note")
        .starts(When::utc(2027, 3, 10, 9, 0))
        .ends(When::utc(2027, 3, 10, 10, 0))
        .build();
    world
        .put(&cara_ctx, &in_collection(&cara_shared, "n-1.ics"), &note)
        .await
        .unwrap();
    let ben_shared = world.collection_of(&acme, &ben, &team).await;
    world
        .put(
            &world.dav(&acme, &ben),
            &in_collection(&ben_shared, "n-1.ics"),
            &note.replace("Note", "Edited note"),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn somebody_who_writes_the_calendar_of_an_attendee_answers_for_them() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let pat = world.user(&acme, "pat").await;
    let dave = world.user(&acme, "dave").await;
    world
        .grant(&acme, &anna, "personal", &pat, GrantAccess::ReadWrite)
        .await;
    world
        .put(
            &world.dav(&acme, &dave),
            &world.object(&acme, &dave, "d.ics"),
            &meeting("d-1", &dave, &[&anna.mailto()]).build(),
        )
        .await
        .unwrap();
    let copy = world.copy_of(&acme, &anna, "d-1").await.unwrap();
    let pat_ctx = world.dav(&acme, &pat);
    let shared = world.collection_of(&acme, &pat, &anna).await;
    let path = in_collection(&shared, copy.uri.as_str());

    // Pat writes Anna's calendar, so he may answer in her name; he may not change Dave's event.
    let error = world
        .put(
            &pat_ctx,
            &path,
            &copy.data.replace("SUMMARY:Planning", "SUMMARY:Pat's party"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(
        error.precondition(),
        Some(&Precondition::AllowedAttendeeSchedulingObjectChange)
    );
    assert_eq!(world.copy_of(&acme, &anna, "d-1").await.unwrap().data, copy.data);

    world
        .put(
            &pat_ctx,
            &path,
            &answered(&copy.data, &anna.mailto(), PartStat::Accepted),
        )
        .await
        .unwrap();
    let organizer_copy = world
        .text(&world.dav(&acme, &dave), &world.object(&acme, &dave, "d.ics"))
        .await;
    assert_eq!(
        partstat_in(&organizer_copy, &anna.mailto()),
        Some(PartStat::Accepted),
        "{organizer_copy}"
    );
    let inbox = world.inbox(&acme, &dave).await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(property_in(&inbox[0].data, "METHOD").as_deref(), Some("REPLY"));
    assert!(
        inbox[0].data.contains("anna@acme.example") && !inbox[0].data.contains("pat@acme.example"),
        "the answer is Anna's: {}",
        inbox[0].data
    );

    // Deleting her copy declines in her name.
    world.delete(&pat_ctx, &path).await.unwrap();
    let organizer_copy = world
        .text(&world.dav(&acme, &dave), &world.object(&acme, &dave, "d.ics"))
        .await;
    assert_eq!(
        partstat_in(&organizer_copy, &anna.mailto()),
        Some(PartStat::Declined),
        "{organizer_copy}"
    );
}

#[tokio::test]
async fn a_stale_etag_is_excused_by_a_current_schedule_tag_only_for_the_organizer_and_the_attendees() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let pat = world.user(&acme, "pat").await;
    world
        .grant(&acme, &anna, "personal", &pat, GrantAccess::ReadWrite)
        .await;
    let (anna_ctx, ben_ctx, pat_ctx) = (world.dav(&acme, &anna), world.dav(&acme, &ben), world.dav(&acme, &pat));
    let stale = || IfMatch::Tags(vec![ETag::from_bytes(b"not what is stored")]);

    // A meeting of somebody outside the tenant that Anna keeps in her calendar: neither she nor Pat is part of it.
    let imported_path = world.object(&acme, &anna, "i.ics");
    world
        .put(
            &anna_ctx,
            &imported_path,
            &imported("i-1", "mailto:olga@example.net").build(),
        )
        .await
        .unwrap();
    let stored = world.services.objects.get(&anna_ctx, &imported_path).await.unwrap();
    let tag = stored
        .schedule_tag
        .clone()
        .expect("a scheduling object has a Schedule-Tag");
    let shared = world.collection_of(&acme, &pat, &anna).await;
    for (who, ctx, path) in [
        ("the owner", &anna_ctx, imported_path.clone()),
        (
            "a colleague who writes the calendar",
            &pat_ctx,
            in_collection(&shared, "i.ics"),
        ),
    ] {
        let error = world
            .put_with(
                ctx,
                &path,
                &imported("i-1", "mailto:olga@example.net").summary("Edited").build(),
                WritePrecondition {
                    if_match: Some(stale()),
                    if_schedule_tag_match: Some(tag.clone()),
                    ..WritePrecondition::default()
                },
                ScheduleReply::Send,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ErrorKind::PreconditionFailed,
            "{who}: the write is based on a version that nobody can say was merged"
        );
    }
    assert_eq!(
        world.text(&anna_ctx, &imported_path).await,
        stored.data.expect("the text is there"),
        "nothing was stored"
    );

    // The organizer of a meeting is merged: an answer arrived since her client read the meeting, and her write keeps it.
    let meeting_path = world.object(&acme, &anna, "m-1.ics");
    let first = meeting("m-1", &anna, &[&ben.mailto()]).build();
    world.put(&anna_ctx, &meeting_path, &first).await.unwrap();
    let read = world.services.objects.get(&anna_ctx, &meeting_path).await.unwrap();
    let tag = read.schedule_tag.clone().unwrap();
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    world
        .put(
            &ben_ctx,
            &world.object(&acme, &ben, copy.uri.as_str()),
            &answered(&copy.data, &ben.mailto(), PartStat::Accepted),
        )
        .await
        .unwrap();
    world
        .put_with(
            &anna_ctx,
            &meeting_path,
            &meeting("m-1", &anna, &[&ben.mailto()])
                .description("Bring the plan")
                .build(),
            WritePrecondition {
                if_match: Some(IfMatch::Tags(vec![read.etag])),
                if_schedule_tag_match: Some(tag),
                ..WritePrecondition::default()
            },
            ScheduleReply::Send,
        )
        .await
        .unwrap();
    let stored = world.text(&anna_ctx, &meeting_path).await;
    assert_eq!(
        partstat_in(&stored, &ben.mailto()),
        Some(PartStat::Accepted),
        "Ben's answer survived the write of a client that had not seen it: {stored}"
    );
    assert!(stored.contains("Bring the plan"));
}

#[tokio::test]
async fn a_write_that_fails_after_it_was_planned_leaves_nothing_for_the_next_one_with_the_same_request_id() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    // The id of a request is the client's (`X-Request-Id`): two requests can have the same.
    let request_id = RequestId::from_uuid(Uuid::from_u128(0x1234));
    let ctx = || RequestContext {
        request_id,
        ..world.dav(&acme, &anna)
    };
    let plain = |uid: &str| {
        EventBuilder::event(uid)
            .summary("Plain")
            .starts(When::utc(2027, 3, 10, 9, 0))
            .ends(When::utc(2027, 3, 10, 10, 0))
            .build()
    };
    world
        .put(&ctx(), &world.object(&acme, &anna, "first.ics"), &plain("dup-1"))
        .await
        .unwrap();

    // This write invites Ben, is planned, and fails: the UID is taken in this calendar.
    let error = world
        .put(
            &ctx(),
            &world.object(&acme, &anna, "second.ics"),
            &meeting("dup-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error.precondition(), Some(Precondition::NoUidConflict(_))),
        "{error:?}"
    );

    // The next write with the same id to the same name schedules nothing, and must not carry out that plan.
    world
        .put(&ctx(), &world.object(&acme, &anna, "second.ics"), &plain("other-1"))
        .await
        .unwrap();
    assert!(world.inbox(&acme, &ben).await.is_empty(), "Ben was not invited");
    assert!(world.copy_of(&acme, &ben, "dup-1").await.is_none());
    assert!(world.mail_jobs(&acme).await.is_empty(), "no mail");
}

#[tokio::test]
async fn two_writes_with_the_same_request_id_keep_their_own_plans() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let cara = world.user(&acme, "cara").await;
    let ben = world.user(&acme, "ben").await;
    let dan = world.user(&acme, "dan").await;
    let request_id = RequestId::from_uuid(Uuid::from_u128(7));
    let as_anna = RequestContext {
        request_id,
        ..world.dav(&acme, &anna)
    };
    let as_cara = RequestContext {
        request_id,
        ..world.dav(&acme, &cara)
    };

    // The same name in two calendars, the same request id.
    world
        .put(
            &as_anna,
            &world.object(&acme, &anna, "m.ics"),
            &meeting("m-a", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    world
        .put(
            &as_cara,
            &world.object(&acme, &cara, "m.ics"),
            &meeting("m-c", &cara, &[&dan.mailto()]).build(),
        )
        .await
        .unwrap();

    let ben_inbox = world.inbox(&acme, &ben).await;
    let dan_inbox = world.inbox(&acme, &dan).await;
    assert_eq!((ben_inbox.len(), dan_inbox.len()), (1, 1));
    assert!(ben_inbox[0].data.contains("UID:m-a") && ben_inbox[0].data.contains("anna@acme.example"));
    assert!(dan_inbox[0].data.contains("UID:m-c") && dan_inbox[0].data.contains("cara@acme.example"));
    assert!(world.copy_of(&acme, &ben, "m-c").await.is_none());
    assert!(world.copy_of(&acme, &dan, "m-a").await.is_none());
}

#[tokio::test]
async fn the_copy_of_the_organizer_is_the_one_in_their_own_calendar_and_two_candidates_are_ambiguous() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let one = world.group(&acme, "one", &[&anna]).await;
    let two = world.group(&acme, "two", &[&anna]).await;
    world.calendar(&acme, &one, "cal", CalendarKind::Group).await;
    world.calendar(&acme, &two, "cal", CalendarKind::Group).await;
    let anna_ctx = world.dav(&acme, &anna);
    let in_one = in_collection(&world.collection_of(&acme, &anna, &one).await, "x.ics");
    let in_two = in_collection(&world.collection_of(&acme, &anna, &two).await, "x.ics");

    // Anna keeps the same meeting in the calendars of two groups.
    let invitation = meeting("x-1", &anna, &[&ben.mailto()]).build();
    world.put(&anna_ctx, &in_one, &invitation).await.unwrap();
    world.put(&anna_ctx, &in_two, &invitation).await.unwrap();
    let copy = world.copy_of(&acme, &ben, "x-1").await.expect("Ben has a copy");
    let ben_path = world.object(&acme, &ben, copy.uri.as_str());
    let ben_ctx = world.dav(&acme, &ben);

    // Ben accepts: which of the two is the organizer's copy? Neither: the answer stays in his own copy.
    world
        .put(
            &ben_ctx,
            &ben_path,
            &answered(&copy.data, &ben.mailto(), PartStat::Accepted),
        )
        .await
        .unwrap();
    assert!(world.inbox(&acme, &anna).await.is_empty(), "nobody is told on a guess");
    for (collection, name) in [(&in_one, "one"), (&in_two, "two")] {
        let text = world.text(&anna_ctx, collection).await;
        assert_eq!(
            partstat_in(&text, &ben.mailto()),
            Some(PartStat::NeedsAction),
            "{name}: {text}"
        );
    }

    // The same meeting in a calendar Anna owns is the organizer's copy, and the answer goes there.
    let own = world.object(&acme, &anna, "x.ics");
    world.put(&anna_ctx, &own, &invitation).await.unwrap();
    let copy = world.copy_of(&acme, &ben, "x-1").await.unwrap();
    world
        .put(
            &ben_ctx,
            &ben_path,
            &answered(&copy.data, &ben.mailto(), PartStat::Tentative),
        )
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &anna).await.len(), 1);
    let text = world.text(&anna_ctx, &own).await;
    assert_eq!(partstat_in(&text, &ben.mailto()), Some(PartStat::Tentative), "{text}");
}
