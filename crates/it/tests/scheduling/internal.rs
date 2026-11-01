//! Scheduling between principals of one tenant over DAV: the organizer's writes, the attendees' copies and the
//! answers that flow back (PLAN 2.8).

use davhaven_testkit::davhaven_app::services::{RecipientStatus, ScheduleReply, ScheduleStatus, WritePrecondition};
use davhaven_testkit::davhaven_domain::{
    ErrorKind, EventType, PartStat, Precondition, RequestContext, ResourcePath, ScheduleTag,
};

use super::support::{World, answered, meeting, partstat_in, property_in, status_in};

#[tokio::test]
async fn an_invitation_reaches_the_inbox_and_the_calendar_of_an_internal_attendee() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let path = world.object(&acme, &anna, "m-1.ics");
    let ctx = world.dav(&acme, &anna);

    let outcome = world
        .put(&ctx, &path, &meeting("m-1", &anna, &[&ben.mailto()]).build())
        .await
        .unwrap();

    assert!(outcome.created);
    assert_eq!(
        outcome.schedule.recipients,
        vec![RecipientStatus {
            address: ben.address(),
            status: ScheduleStatus::Delivered
        }]
    );
    assert!(
        outcome.etag.is_none(),
        "the server wrote SCHEDULE-STATUS: no ETag (RFC 4791 5.3.4)"
    );
    assert!(outcome.schedule_tag.is_some());

    // The organizer's copy carries the delivery status and the answer of nobody yet.
    let stored = world.text(&ctx, &path).await;
    assert_eq!(status_in(&stored, &ben.mailto()).as_deref(), Some("1.2"), "{stored}");
    assert_eq!(partstat_in(&stored, &ben.mailto()), Some(PartStat::NeedsAction));

    // Ben has the invitation in his inbox and a copy in his default calendar.
    let inbox = world.inbox(&acme, &ben).await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(property_in(&inbox[0].data, "METHOD").as_deref(), Some("REQUEST"));
    let copy = world
        .copy_of(&acme, &ben, "m-1")
        .await
        .expect("a copy in Ben's calendar");
    assert!(
        !copy.data.contains("METHOD:"),
        "a calendar object has no METHOD: {}",
        copy.data
    );
    assert!(copy.data.contains("SUMMARY:Planning"));
    assert!(world.inbox(&acme, &anna).await.is_empty(), "the organizer gets nothing");
}

#[tokio::test]
async fn an_answer_in_a_calendar_client_reaches_the_organizer_and_keeps_the_schedule_tag() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let organizer_path = world.object(&acme, &anna, "m-1.ics");
    let anna_ctx = world.dav(&acme, &anna);
    let ben_ctx = world.dav(&acme, &ben);
    world
        .put(
            &anna_ctx,
            &organizer_path,
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let tag_before = world
        .services
        .objects
        .get(&anna_ctx, &organizer_path)
        .await
        .unwrap()
        .schedule_tag;
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let copy_path = world.object(&acme, &ben, copy.uri.as_str());

    // Ben accepts: his client writes his copy with PARTSTAT=ACCEPTED.
    let accepted = answered(&copy.data, &ben.mailto(), PartStat::Accepted);
    let outcome = world.put(&ben_ctx, &copy_path, &accepted).await.unwrap();
    assert!(!outcome.created);

    let organizer_copy = world.text(&anna_ctx, &organizer_path).await;
    assert_eq!(
        partstat_in(&organizer_copy, &ben.mailto()),
        Some(PartStat::Accepted),
        "{organizer_copy}"
    );
    let tag_after = world
        .services
        .objects
        .get(&anna_ctx, &organizer_path)
        .await
        .unwrap()
        .schedule_tag;
    assert_eq!(
        tag_before, tag_after,
        "a server merge does not change the Schedule-Tag (PLAN 2.7)"
    );
    let inbox = world.inbox(&acme, &anna).await;
    assert_eq!(inbox.len(), 1, "Anna is told");
    assert_eq!(property_in(&inbox[0].data, "METHOD").as_deref(), Some("REPLY"));
    let replies = world.events_of(&acme, EventType::SchedulingReplyReceived).await;
    assert_eq!(replies.len(), 1);
}

#[tokio::test]
async fn a_significant_change_asks_everybody_again_and_an_insignificant_one_is_silent() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let path = world.object(&acme, &anna, "m-1.ics");
    let ctx = world.dav(&acme, &anna);
    world
        .put(&ctx, &path, &meeting("m-1", &anna, &[&ben.mailto()]).build())
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &ben).await.len(), 1);

    // A new time is significant: the answers reset, SEQUENCE rises, Ben is asked again.
    let moved = meeting("m-1", &anna, &[&ben.mailto()])
        .starts(davhaven_testkit::davhaven_fixtures::event::When::utc(
            2027, 3, 10, 11, 0,
        ))
        .ends(davhaven_testkit::davhaven_fixtures::event::When::utc(
            2027, 3, 10, 12, 0,
        ))
        .build();
    world.put(&ctx, &path, &moved).await.unwrap();
    let stored = world.text(&ctx, &path).await;
    assert_eq!(property_in(&stored, "SEQUENCE").as_deref(), Some("1"), "{stored}");
    assert_eq!(world.inbox(&acme, &ben).await.len(), 2);
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    assert!(
        copy.data.contains("DTSTART:20270310T110000Z"),
        "Ben's copy follows: {}",
        copy.data
    );

    // A new description is not: the copy follows silently, nothing is sent.
    let described = meeting("m-1", &anna, &[&ben.mailto()])
        .starts(davhaven_testkit::davhaven_fixtures::event::When::utc(
            2027, 3, 10, 11, 0,
        ))
        .ends(davhaven_testkit::davhaven_fixtures::event::When::utc(
            2027, 3, 10, 12, 0,
        ))
        .description("Bring the plan")
        .sequence(1)
        .build();
    world.put(&ctx, &path, &described).await.unwrap();
    assert_eq!(world.inbox(&acme, &ben).await.len(), 2, "no new message");
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    assert!(
        copy.data.contains("Bring the plan"),
        "the copy follows silently: {}",
        copy.data
    );
}

#[tokio::test]
async fn removing_an_attendee_cancels_for_them_and_deleting_cancels_for_the_rest() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let path = world.object(&acme, &anna, "m-1.ics");
    let ctx = world.dav(&acme, &anna);
    world
        .put(
            &ctx,
            &path,
            &meeting("m-1", &anna, &[&ben.mailto(), &cara.mailto()]).build(),
        )
        .await
        .unwrap();
    assert!(world.copy_of(&acme, &ben, "m-1").await.is_some());
    assert!(world.copy_of(&acme, &cara, "m-1").await.is_some());

    // Cara is no longer invited: she gets a CANCEL and her copy goes.
    world
        .put(&ctx, &path, &meeting("m-1", &anna, &[&ben.mailto()]).build())
        .await
        .unwrap();
    let cara_inbox = world.inbox(&acme, &cara).await;
    assert_eq!(
        property_in(&cara_inbox.last().unwrap().data, "METHOD").as_deref(),
        Some("CANCEL")
    );
    assert!(world.copy_of(&acme, &cara, "m-1").await.is_none());
    assert!(
        world.copy_of(&acme, &ben, "m-1").await.is_some(),
        "Ben is still invited"
    );

    // Anna deletes the event: Ben is told, his copy goes.
    let outcome = world.delete(&ctx, &path).await.unwrap();
    assert_eq!(outcome.schedule.recipients.len(), 1);
    let ben_inbox = world.inbox(&acme, &ben).await;
    assert_eq!(
        property_in(&ben_inbox.last().unwrap().data, "METHOD").as_deref(),
        Some("CANCEL")
    );
    assert!(world.copy_of(&acme, &ben, "m-1").await.is_none());
}

#[tokio::test]
async fn an_attendee_who_deletes_the_copy_declines_unless_told_not_to() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let anna_ctx = world.dav(&acme, &anna);
    let organizer_path = world.object(&acme, &anna, "m-1.ics");
    world
        .put(
            &anna_ctx,
            &organizer_path,
            &meeting("m-1", &anna, &[&ben.mailto(), &cara.mailto()]).build(),
        )
        .await
        .unwrap();

    let ben_copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    world
        .delete(
            &world.dav(&acme, &ben),
            &world.object(&acme, &ben, ben_copy.uri.as_str()),
        )
        .await
        .unwrap();
    let cara_copy = world.copy_of(&acme, &cara, "m-1").await.unwrap();
    world
        .delete_with(
            &world.dav(&acme, &cara),
            &world.object(&acme, &cara, cara_copy.uri.as_str()),
            ScheduleReply::Suppress,
        )
        .await
        .unwrap();

    let organizer_copy = world.text(&anna_ctx, &organizer_path).await;
    assert_eq!(
        partstat_in(&organizer_copy, &ben.mailto()),
        Some(PartStat::Declined),
        "{organizer_copy}"
    );
    assert_eq!(
        partstat_in(&organizer_copy, &cara.mailto()),
        Some(PartStat::NeedsAction),
        "Schedule-Reply: F sends nothing"
    );
    assert_eq!(world.inbox(&acme, &anna).await.len(), 1);
}

#[tokio::test]
async fn the_rules_of_who_may_organize_and_who_may_change_what_are_enforced() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let anna_ctx = world.dav(&acme, &anna);
    let ben_ctx = world.dav(&acme, &ben);

    // Ben cannot create an event that Anna organizes (C:organizer-allowed).
    let error = world
        .put(
            &ben_ctx,
            &world.object(&acme, &ben, "x.ics"),
            &meeting("x", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(error.precondition(), Some(&Precondition::OrganizerAllowed));

    // An attendee may change their answer, not the event (C:allowed-attendee-scheduling-object-change).
    world
        .put(
            &anna_ctx,
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let copy_path = world.object(&acme, &ben, copy.uri.as_str());
    let retitled = copy.data.replace("SUMMARY:Planning", "SUMMARY:Ben's party");
    let error = world.put(&ben_ctx, &copy_path, &retitled).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(
        error.precondition(),
        Some(&Precondition::AllowedAttendeeSchedulingObjectChange)
    );
    assert_eq!(
        world.copy_of(&acme, &ben, "m-1").await.unwrap().data,
        copy.data,
        "nothing was stored"
    );
}

#[tokio::test]
async fn an_attendee_with_a_current_schedule_tag_is_merged_instead_of_refused() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let anna_ctx = world.dav(&acme, &anna);
    let ben_ctx = world.dav(&acme, &ben);
    world
        .put(
            &anna_ctx,
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let path = world.object(&acme, &ben, copy.uri.as_str());
    let stale_etag = davhaven_testkit::davhaven_domain::ETag::from_bytes(b"not what is stored");

    // The write is stale by ETag but current by Schedule-Tag: the attendee's change is merged (PLAN 2.7).
    let accepted = answered(&copy.data, &ben.mailto(), PartStat::Accepted);
    let preconditions = WritePrecondition {
        if_match: Some(davhaven_testkit::davhaven_app::services::IfMatch::Tags(vec![
            stale_etag,
        ])),
        if_schedule_tag_match: copy.schedule_tag.clone(),
        ..WritePrecondition::default()
    };
    world
        .put_with(&ben_ctx, &path, &accepted, preconditions, ScheduleReply::Send)
        .await
        .unwrap();
    let organizer_copy = world.text(&anna_ctx, &world.object(&acme, &anna, "m-1.ics")).await;
    assert_eq!(partstat_in(&organizer_copy, &ben.mailto()), Some(PartStat::Accepted));

    // A stale Schedule-Tag is a 412.
    let other_tag = davhaven_testkit::davhaven_domain::ScheduleTag::parse("\"other\"").unwrap();
    let error = world
        .put_with(
            &ben_ctx,
            &path,
            &accepted,
            WritePrecondition {
                if_schedule_tag_match: Some(other_tag),
                ..WritePrecondition::default()
            },
            ScheduleReply::Send,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
}

#[tokio::test]
async fn an_attendee_answers_one_instance_of_a_series_and_the_organizer_hears_which() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let anna_ctx = world.dav(&acme, &anna);
    let organizer_path = world.object(&acme, &anna, "r-1.ics");
    world
        .put(
            &anna_ctx,
            &organizer_path,
            &meeting("r-1", &anna, &[&ben.mailto()])
                .rrule("FREQ=DAILY;COUNT=3")
                .build(),
        )
        .await
        .unwrap();
    let copy = world.copy_of(&acme, &ben, "r-1").await.unwrap();

    // Ben cannot come on the second day: his client adds an override of that instance with his answer.
    let unfolded = copy.data.replace("\r\n ", "");
    let start = unfolded.find("BEGIN:VEVENT").unwrap();
    let end = unfolded.find("END:VEVENT").unwrap() + "END:VEVENT\r\n".len();
    let master = unfolded.get(start..end).unwrap();
    let instance = master
        .replace("UID:r-1\r\n", "UID:r-1\r\nRECURRENCE-ID:20270311T090000Z\r\n")
        .replace("DTSTART:20270310T090000Z", "DTSTART:20270311T090000Z")
        .replace("DTEND:20270310T100000Z", "DTEND:20270311T100000Z")
        .replace("RRULE:FREQ=DAILY;COUNT=3\r\n", "")
        .replace("PARTSTAT=NEEDS-ACTION", "PARTSTAT=DECLINED");
    assert!(
        instance.contains("RECURRENCE-ID") && instance.contains("PARTSTAT=DECLINED"),
        "{instance}"
    );
    let declined = unfolded.replace("END:VCALENDAR", &format!("{instance}END:VCALENDAR"));
    world
        .put(
            &world.dav(&acme, &ben),
            &world.object(&acme, &ben, copy.uri.as_str()),
            &declined,
        )
        .await
        .unwrap();

    // The organizer's copy says so for that day and keeps the answer of the series.
    let organizer_copy = world.text(&anna_ctx, &organizer_path).await.replace("\r\n ", "");
    assert_eq!(
        partstat_in(&organizer_copy, &ben.mailto()),
        Some(PartStat::NeedsAction),
        "the series is unanswered"
    );
    assert_eq!(
        organizer_copy.matches("PARTSTAT=DECLINED").count(),
        1,
        "{organizer_copy}"
    );
    assert!(
        organizer_copy.contains("RECURRENCE-ID:20270311T090000Z"),
        "{organizer_copy}"
    );
    let inbox = world.inbox(&acme, &anna).await;
    assert_eq!(inbox.len(), 1);
    assert!(inbox[0].data.contains("RECURRENCE-ID:20270311T090000Z") && inbox[0].data.contains("PARTSTAT=DECLINED"));
    assert_eq!(
        world.events_of(&acme, EventType::SchedulingReplyReceived).await.len(),
        1
    );
}

#[tokio::test]
async fn the_schedule_tag_moves_with_the_changes_of_the_owner_of_a_copy_and_not_with_answers() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let (anna_ctx, ben_ctx) = (world.dav(&acme, &anna), world.dav(&acme, &ben));
    let organizer_path = world.object(&acme, &anna, "m-1.ics");
    world
        .put(
            &anna_ctx,
            &organizer_path,
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let copy_path = world.object(&acme, &ben, copy.uri.as_str());
    let (first_organizer, first_copy) = (
        tag_of(&world, &anna_ctx, &organizer_path).await,
        tag_of(&world, &ben_ctx, &copy_path).await,
    );
    assert!(first_organizer.is_some() && first_copy.is_some());

    // The organizer changes the event: a new tag for the organizer's copy and for the copy that follows it.
    let moved = meeting("m-1", &anna, &[&ben.mailto()])
        .starts(davhaven_testkit::davhaven_fixtures::event::When::utc(
            2027, 3, 10, 11, 0,
        ))
        .ends(davhaven_testkit::davhaven_fixtures::event::When::utc(
            2027, 3, 10, 12, 0,
        ))
        .build();
    world.put(&anna_ctx, &organizer_path, &moved).await.unwrap();
    let (second_organizer, second_copy) = (
        tag_of(&world, &anna_ctx, &organizer_path).await,
        tag_of(&world, &ben_ctx, &copy_path).await,
    );
    assert_ne!(second_organizer, first_organizer);
    assert_ne!(second_copy, first_copy);

    // Ben answers: his copy has a new tag (it is his change), the organizer's does not (a server merge).
    let current = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let accepted = answered(&current.data, &ben.mailto(), PartStat::Accepted);
    world.put(&ben_ctx, &copy_path, &accepted).await.unwrap();
    assert_eq!(tag_of(&world, &anna_ctx, &organizer_path).await, second_organizer);
    assert_ne!(tag_of(&world, &ben_ctx, &copy_path).await, second_copy);
}

#[tokio::test]
async fn an_event_that_loses_its_last_attendee_cancels_for_them_and_the_organizer_cannot_be_changed() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    world
        .put(&ctx, &path, &meeting("m-1", &anna, &[&ben.mailto()]).build())
        .await
        .unwrap();

    // Somebody else cannot be put in as the organizer of an event that Anna organizes.
    let error = world
        .put(
            &ctx,
            &path,
            &meeting("m-1", &anna, &[&ben.mailto()])
                .organizer(davhaven_testkit::davhaven_fixtures::event::Organizer::new(
                    "mailto:eve@example.net",
                ))
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(
        error.precondition(),
        Some(&Precondition::AllowedOrganizerSchedulingObjectChange)
    );

    // An event without attendees is no meeting any more: Ben is told and his copy goes.
    let outcome = world
        .put(&ctx, &path, &meeting("m-1", &anna, &[]).build())
        .await
        .unwrap();
    assert!(
        !outcome.schedule.is_scheduled(),
        "nobody is left to tell about the new state"
    );
    let inbox = world.inbox(&acme, &ben).await;
    assert_eq!(
        property_in(&inbox.last().unwrap().data, "METHOD").as_deref(),
        Some("CANCEL")
    );
    assert!(world.copy_of(&acme, &ben, "m-1").await.is_none());
}

#[tokio::test]
async fn an_organizer_who_edits_after_an_answer_arrived_does_not_take_the_answer_back() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let anna_ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    world
        .put(&anna_ctx, &path, &meeting("m-1", &anna, &[&ben.mailto()]).build())
        .await
        .unwrap();
    // The client of Anna reads the event, and then Ben answers: the object has a new ETag and the same Schedule-Tag.
    let read = world.services.objects.get(&anna_ctx, &path).await.unwrap();
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let accepted = answered(&copy.data, &ben.mailto(), PartStat::Accepted);
    world
        .put(
            &world.dav(&acme, &ben),
            &world.object(&acme, &ben, copy.uri.as_str()),
            &accepted,
        )
        .await
        .unwrap();

    // Anna's client writes what it has, with the conditions it read: stale by ETag, current by Schedule-Tag. The write
    // goes through (RFC 6638 section 3.2.10), and the answer that arrived meanwhile is kept.
    let edited = meeting("m-1", &anna, &[&ben.mailto()])
        .description("Bring the plan")
        .build();
    let preconditions = WritePrecondition {
        if_match: Some(davhaven_testkit::davhaven_app::services::IfMatch::Tags(vec![read.etag])),
        if_schedule_tag_match: read.schedule_tag,
        ..WritePrecondition::default()
    };
    world
        .put_with(&anna_ctx, &path, &edited, preconditions, ScheduleReply::Send)
        .await
        .unwrap();
    let stored = world.text(&anna_ctx, &path).await;
    assert!(stored.contains("Bring the plan"), "{stored}");
    assert_eq!(
        partstat_in(&stored, &ben.mailto()),
        Some(PartStat::Accepted),
        "{stored}"
    );
}

#[tokio::test]
async fn a_recipient_sees_only_their_own_attendee_line_and_no_scheduling_parameters() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto(), &cara.mailto()]).build(),
        )
        .await
        .unwrap();
    let message = world.inbox(&acme, &ben).await.pop().unwrap().data;
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap().data;
    for (what, text) in [("the message", message), ("the copy", copy)] {
        assert_eq!(
            super::support::count_of(&text, "ATTENDEE"),
            1,
            "{what} shows Ben only: {text}"
        );
        assert!(
            text.contains("ben@acme.example") && !text.contains("cara@acme.example"),
            "{what}: {text}"
        );
        assert!(
            !text.contains("SCHEDULE-"),
            "{what} carries no scheduling parameter: {text}"
        );
    }
}

/// The `Schedule-Tag` of the object at `path`, as `ctx` reads it.
async fn tag_of(world: &World, ctx: &RequestContext, path: &ResourcePath) -> Option<ScheduleTag> {
    world.services.objects.get(ctx, path).await.unwrap().schedule_tag
}
