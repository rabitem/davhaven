//! Delivery to internal attendees above the synchronous cap (PLAN 2.8): the first attendees are served inside the
//! transaction of the organizer's write, the rest is queued as `internal_delivery` and delivered by the dispatcher.

use davhaven_testkit::davhaven_app::outbox::handlers;
use davhaven_testkit::davhaven_app::services::ScheduleStatus;
use davhaven_testkit::davhaven_domain::{ItipMethod, PrincipalId};
use davhaven_testkit::davhaven_ports::OutboxMessage;

use super::support::{Org, Person, World, meeting, property_in, status_in};

/// A tenant with Anna and three colleagues, where only one attendee is served inside the write.
async fn capped() -> (World, Org, Person, [Person; 3]) {
    let world = World::with(|deps| deps.config.scheduling.max_sync_internal_attendees = 1);
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let dan = world.user(&acme, "dan").await;
    (world, acme, anna, [ben, cara, dan])
}

fn invitees(people: &[Person; 3]) -> Vec<String> {
    people.iter().map(Person::mailto).collect()
}

#[tokio::test]
async fn attendees_above_the_cap_are_queued_and_delivered_by_the_outbox() {
    let (world, acme, anna, [ben, cara, dan]) = capped().await;
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    let guests = invitees(&[ben.clone(), cara.clone(), dan.clone()]);
    let refs: Vec<&str> = guests.iter().map(String::as_str).collect();

    let outcome = world
        .put(&ctx, &path, &meeting("m-1", &anna, &refs).build())
        .await
        .unwrap();

    let status = |who: &Person| {
        outcome
            .schedule
            .recipients
            .iter()
            .find(|recipient| recipient.address == who.address())
            .map(|recipient| recipient.status)
    };
    assert_eq!(status(&ben), Some(ScheduleStatus::Delivered));
    assert_eq!(status(&cara), Some(ScheduleStatus::Queued));
    assert_eq!(status(&dan), Some(ScheduleStatus::Queued));
    let stored = world.text(&ctx, &path).await;
    assert_eq!(status_in(&stored, &ben.mailto()).as_deref(), Some("1.2"), "{stored}");
    assert_eq!(status_in(&stored, &cara.mailto()).as_deref(), Some("1.0"), "{stored}");
    assert_eq!(status_in(&stored, &dan.mailto()).as_deref(), Some("1.0"), "{stored}");

    // Nothing is delivered to the queued attendees yet; one record waits for both.
    assert_eq!(world.inbox(&acme, &ben).await.len(), 1);
    assert_eq!(world.inbox(&acme, &cara).await.len(), 0);
    assert!(world.copy_of(&acme, &cara, "m-1").await.is_none());
    let jobs: Vec<_> = world
        .outbox(&acme)
        .await
        .into_iter()
        .filter_map(|message| match message {
            OutboxMessage::InternalDelivery(job) => Some(job),
            _ => None,
        })
        .collect();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].method, ItipMethod::Request);
    let mut recipients: Vec<PrincipalId> = jobs[0].recipients.clone();
    recipients.sort();
    let mut expected = vec![cara.id, dan.id];
    expected.sort();
    assert_eq!(recipients, expected);

    world.run_outbox().await;
    for person in [&cara, &dan] {
        let inbox = world.inbox(&acme, person).await;
        assert_eq!(inbox.len(), 1, "{}", person.name);
        assert_eq!(property_in(&inbox[0].data, "METHOD").as_deref(), Some("REQUEST"));
        assert!(world.copy_of(&acme, person, "m-1").await.is_some(), "{}", person.name);
    }
}

#[tokio::test]
async fn a_record_that_is_handled_twice_delivers_once() {
    let (world, acme, anna, [ben, cara, dan]) = capped().await;
    let guests = invitees(&[ben, cara.clone(), dan.clone()]);
    let refs: Vec<&str> = guests.iter().map(String::as_str).collect();
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &refs).build(),
        )
        .await
        .unwrap();
    world.run_outbox().await;

    // A lease that ran out, a crash after the commit: the dispatcher hands the record over again.
    let record = world
        .outbox_records(&acme)
        .await
        .into_iter()
        .find(|record| record.kind == "internal_delivery")
        .expect("the delivery was queued");
    let handler = handlers(&world.core)
        .into_iter()
        .find(|handler| handler.kind() == "internal_delivery")
        .expect("every dispatcher has the handler of the kind");
    handler.handle(&record).await.unwrap();

    for person in [&cara, &dan] {
        assert_eq!(
            world.inbox(&acme, person).await.len(),
            1,
            "{}: the item found its earlier self",
            person.name
        );
        assert_eq!(
            world
                .objects_of(&acme, person)
                .await
                .iter()
                .filter(|object| object.uid.as_str() == "m-1")
                .count(),
            1,
            "{}: one copy",
            person.name
        );
    }
}

#[tokio::test]
async fn cancellations_and_silent_updates_are_queued_too() {
    let (world, acme, anna, [ben, cara, dan]) = capped().await;
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    let guests = invitees(&[ben.clone(), cara.clone(), dan.clone()]);
    let refs: Vec<&str> = guests.iter().map(String::as_str).collect();
    world
        .put(&ctx, &path, &meeting("m-1", &anna, &refs).build())
        .await
        .unwrap();
    world.run_outbox().await;

    // A description is not a significant change: the copies follow without a message, also the queued ones.
    let described = meeting("m-1", &anna, &refs).description("Bring the plan").build();
    world.put(&ctx, &path, &described).await.unwrap();
    world.run_outbox().await;
    for person in [&ben, &cara, &dan] {
        let copy = world.copy_of(&acme, person, "m-1").await.unwrap();
        assert!(copy.data.contains("Bring the plan"), "{}: {}", person.name, copy.data);
        assert_eq!(
            world.inbox(&acme, person).await.len(),
            1,
            "{}: no new message",
            person.name
        );
    }

    // Deleting the event cancels it for everybody, in order after the invitation.
    world.delete(&ctx, &path).await.unwrap();
    world.run_outbox().await;
    for person in [&ben, &cara, &dan] {
        let inbox = world.inbox(&acme, person).await;
        assert_eq!(inbox.len(), 2, "{}", person.name);
        assert_eq!(
            property_in(&inbox[1].data, "METHOD").as_deref(),
            Some("CANCEL"),
            "{}",
            person.name
        );
        assert!(world.copy_of(&acme, person, "m-1").await.is_none(), "{}", person.name);
    }
}

#[tokio::test]
async fn somebody_who_was_suspended_in_the_meantime_is_skipped() {
    let (world, acme, anna, [ben, cara, dan]) = capped().await;
    let guests = invitees(&[ben, cara.clone(), dan.clone()]);
    let refs: Vec<&str> = guests.iter().map(String::as_str).collect();
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &refs).build(),
        )
        .await
        .unwrap();
    world.suspend(&acme, &cara).await;

    world.run_outbox().await;

    assert_eq!(
        world.inbox(&acme, &cara).await.len(),
        0,
        "nothing is delivered to a suspended principal"
    );
    assert_eq!(world.inbox(&acme, &dan).await.len(), 1, "the others are not held up");
}

#[tokio::test]
async fn an_invitation_that_is_still_queued_is_dropped_for_somebody_who_was_removed_meanwhile() {
    let (world, acme, anna, [ben, cara, dan]) = capped().await;
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    let everybody = invitees(&[ben.clone(), cara.clone(), dan.clone()]);
    let refs: Vec<&str> = everybody.iter().map(String::as_str).collect();
    world
        .put(&ctx, &path, &meeting("m-1", &anna, &refs).build())
        .await
        .unwrap();

    // Before the dispatcher runs, Anna takes Cara off the event: Cara is told right away.
    let remaining = [ben.mailto(), dan.mailto()];
    let refs: Vec<&str> = remaining.iter().map(String::as_str).collect();
    world
        .put(&ctx, &path, &meeting("m-1", &anna, &refs).build())
        .await
        .unwrap();
    world.run_outbox().await;

    let methods = |items: Vec<davhaven_testkit::davhaven_domain::InboxItem>| -> Vec<String> {
        items
            .iter()
            .map(|item| property_in(&item.data, "METHOD").unwrap_or_default())
            .collect()
    };
    assert_eq!(
        methods(world.inbox(&acme, &cara).await),
        vec!["CANCEL"],
        "the late invitation does not undo the cancellation"
    );
    assert!(world.copy_of(&acme, &cara, "m-1").await.is_none());
    assert_eq!(methods(world.inbox(&acme, &dan).await), vec!["REQUEST"]);
    assert!(world.copy_of(&acme, &dan, "m-1").await.is_some());
}
