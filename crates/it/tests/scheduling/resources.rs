//! Resources (rooms, equipment): the policy answers a booking by free-busy (PLAN 2.8, "Policy hook").

use std::sync::Arc;

use davhaven_testkit::davhaven_app::policy::ManualPolicy;
use davhaven_testkit::davhaven_app::services::ScheduleStatus;
use davhaven_testkit::davhaven_domain::{EventType, PartStat};
use davhaven_testkit::davhaven_fixtures::event::{EventBuilder, When};

use super::support::{Org, Person, World, meeting, partstat_in, status_in};

/// Anna, Ben and a room in the tenant `acme`.
async fn offices() -> (World, Org, Person, Person, Person) {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let room = world.resource(&acme, "room1").await;
    (world, acme, anna, ben, room)
}

/// The answer of the room as the organizer's copy of `uri` shows it.
async fn answer_of_room(world: &World, org: &Org, organizer: &Person, uri: &str, room: &Person) -> Option<PartStat> {
    let text = world
        .text(&world.dav(org, organizer), &world.object(org, organizer, uri))
        .await;
    partstat_in(&text, &room.mailto())
}

/// Puts a booked slot into the calendar of the room: an event without attendees, written by the room itself.
async fn book(
    world: &World,
    org: &Org,
    room: &Person,
    uid: &str,
    from: (u32, u32, u32, u32),
    to: (u32, u32, u32, u32),
) {
    let busy = EventBuilder::event(uid)
        .summary("Booked")
        .starts(When::utc(2027, from.0, from.1, from.2, from.3))
        .ends(When::utc(2027, to.0, to.1, to.2, to.3))
        .build();
    world
        .put(
            &world.dav(org, room),
            &world.object_in(org, room, "room", &format!("{uid}.ics")),
            &busy,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_free_room_accepts_and_a_booked_one_declines() {
    let (world, acme, anna, ben, room) = offices().await;

    let outcome = world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&room.mailto()]).build(),
        )
        .await
        .unwrap();
    assert_eq!(outcome.schedule.recipients[0].status, ScheduleStatus::Delivered);
    assert_eq!(
        answer_of_room(&world, &acme, &anna, "m-1.ics", &room).await,
        Some(PartStat::Accepted)
    );
    let stored = world
        .text(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await;
    assert_eq!(status_in(&stored, &room.mailto()).as_deref(), Some("1.2"));
    assert!(
        world.copy_of(&acme, &room, "m-1").await.is_some(),
        "an accepted booking is in the room's calendar"
    );
    let replies = world.events_of(&acme, EventType::SchedulingReplyReceived).await;
    assert_eq!(replies.len(), 1, "the answer of the room is announced like any other");
    assert_eq!(super::support::reply_partstat(&replies[0]), Some(PartStat::Accepted));

    // Ben wants the room for half an hour of the same time: the room declines, and keeps nothing of it.
    let clash = meeting("m-2", &ben, &[&room.mailto()])
        .starts(When::utc(2027, 3, 10, 9, 30))
        .ends(When::utc(2027, 3, 10, 10, 30))
        .build();
    world
        .put(&world.dav(&acme, &ben), &world.object(&acme, &ben, "m-2.ics"), &clash)
        .await
        .unwrap();
    assert_eq!(
        answer_of_room(&world, &acme, &ben, "m-2.ics", &room).await,
        Some(PartStat::Declined)
    );
    assert!(
        world.copy_of(&acme, &room, "m-2").await.is_none(),
        "a declined booking is not added to the calendar"
    );
    assert_eq!(world.inbox(&acme, &room).await.len(), 2, "the room was asked twice");

    // The end of a booking is exclusive: the next hour is free.
    let adjacent = meeting("m-3", &ben, &[&room.mailto()])
        .starts(When::utc(2027, 3, 10, 10, 0))
        .ends(When::utc(2027, 3, 10, 11, 0))
        .build();
    world
        .put(
            &world.dav(&acme, &ben),
            &world.object(&acme, &ben, "m-3.ics"),
            &adjacent,
        )
        .await
        .unwrap();
    assert_eq!(
        answer_of_room(&world, &acme, &ben, "m-3.ics", &room).await,
        Some(PartStat::Accepted)
    );
}

#[tokio::test]
async fn a_booking_is_checked_against_everything_in_the_room_calendar() {
    let (world, acme, anna, _ben, room) = offices().await;
    book(&world, &acme, &room, "cleaning", (3, 10, 9, 0), (3, 10, 10, 0)).await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&room.mailto()]).build(),
        )
        .await
        .unwrap();
    assert_eq!(
        answer_of_room(&world, &acme, &anna, "m-1.ics", &room).await,
        Some(PartStat::Declined)
    );
}

#[tokio::test]
async fn a_recurring_booking_collides_when_any_instance_does() {
    let (world, acme, anna, _ben, room) = offices().await;
    // The room is taken on the third day only (2027-03-12).
    book(&world, &acme, &room, "inspection", (3, 12, 9, 0), (3, 12, 10, 0)).await;
    let anna_ctx = world.dav(&acme, &anna);

    let long = meeting("long", &anna, &[&room.mailto()])
        .rrule("FREQ=DAILY;COUNT=5")
        .build();
    world
        .put(&anna_ctx, &world.object(&acme, &anna, "long.ics"), &long)
        .await
        .unwrap();
    assert_eq!(
        answer_of_room(&world, &acme, &anna, "long.ics", &room).await,
        Some(PartStat::Declined)
    );

    let short = meeting("short", &anna, &[&room.mailto()])
        .rrule("FREQ=DAILY;COUNT=2")
        .build();
    world
        .put(&anna_ctx, &world.object(&acme, &anna, "short.ics"), &short)
        .await
        .unwrap();
    assert_eq!(
        answer_of_room(&world, &acme, &anna, "short.ics", &room).await,
        Some(PartStat::Accepted)
    );
}

#[tokio::test]
async fn a_change_asks_the_room_again_and_the_room_does_not_collide_with_its_own_copy() {
    let (world, acme, anna, ben, room) = offices().await;
    let anna_ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    world
        .put(&anna_ctx, &path, &meeting("m-1", &anna, &[&room.mailto()]).build())
        .await
        .unwrap();

    // Half an hour later: the room's own copy of the event is in the way of nothing.
    let later = meeting("m-1", &anna, &[&room.mailto()])
        .starts(When::utc(2027, 3, 10, 9, 30))
        .ends(When::utc(2027, 3, 10, 10, 30))
        .build();
    world.put(&anna_ctx, &path, &later).await.unwrap();
    assert_eq!(
        answer_of_room(&world, &acme, &anna, "m-1.ics", &room).await,
        Some(PartStat::Accepted)
    );
    let copy = world.copy_of(&acme, &room, "m-1").await.unwrap();
    assert!(copy.data.contains("DTSTART:20270310T093000Z"), "{}", copy.data);

    // Cancelling frees the room for somebody else.
    world.delete(&anna_ctx, &path).await.unwrap();
    assert!(world.copy_of(&acme, &room, "m-1").await.is_none());
    world
        .put(
            &world.dav(&acme, &ben),
            &world.object(&acme, &ben, "m-2.ics"),
            &meeting("m-2", &ben, &[&room.mailto()]).build(),
        )
        .await
        .unwrap();
    assert_eq!(
        answer_of_room(&world, &acme, &ben, "m-2.ics", &room).await,
        Some(PartStat::Accepted)
    );
}

#[tokio::test]
async fn with_the_manual_policy_a_person_answers_for_the_room() {
    let world = World::with(|deps| deps.scheduling_policy = Arc::new(ManualPolicy));
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let room = world.resource(&acme, "room1").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&room.mailto()]).build(),
        )
        .await
        .unwrap();
    assert_eq!(
        answer_of_room(&world, &acme, &anna, "m-1.ics", &room).await,
        Some(PartStat::NeedsAction)
    );
    assert_eq!(
        world.inbox(&acme, &room).await.len(),
        1,
        "the request waits for a person"
    );
    assert_eq!(
        world.events_of(&acme, EventType::SchedulingReplyReceived).await.len(),
        0
    );
}
