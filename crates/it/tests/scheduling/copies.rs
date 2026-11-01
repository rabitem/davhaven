//! What the next version of the organizer does to the copies of the attendees, and to the people who are told about it
//! (PLAN 2.8): what an attendee may change on their copy survives, a cancelled series reaches everybody who was invited,
//! and an answer that repeats itself still carries the remark to the organizer.

use davhaven_testkit::davhaven_app::services::{InvitationResponse, ObjectRef, ObjectSelector};
use davhaven_testkit::davhaven_domain::{EventStatus, PartStat, Scope, Uid};
use davhaven_testkit::davhaven_fixtures::event::When;

use super::support::{World, meeting, property_in};

const ALARM: &str = "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Mine\r\nEND:VALARM\r\n";

#[tokio::test]
async fn an_edit_of_the_organizer_keeps_the_alarms_and_the_transparency_of_the_attendee() {
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

    // Ben sets a reminder on his copy and marks the event free (PLAN 2.8: an attendee may change exactly these).
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let ben_path = world.object(&acme, &ben, copy.uri.as_str());
    let edited = copy.data.replace(
        "END:VEVENT\r\n",
        &format!("TRANSP:TRANSPARENT\r\n{ALARM}END:VEVENT\r\n"),
    );
    world.put(&world.dav(&acme, &ben), &ben_path, &edited).await.unwrap();
    let kept = |data: &str| data.contains("TRIGGER:-PT15M") && data.contains("TRANSP:TRANSPARENT");
    assert!(kept(&world.copy_of(&acme, &ben, "m-1").await.unwrap().data));

    // An edit that is not significant: the copy follows, and the reminder and the transparency stay.
    world
        .put(
            &anna_ctx,
            &path,
            &meeting("m-1", &anna, &[&ben.mailto()])
                .description("Bring the plan")
                .build(),
        )
        .await
        .unwrap();
    let after = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    assert!(
        after.data.contains("Bring the plan"),
        "the copy follows: {}",
        after.data
    );
    assert!(
        kept(&after.data),
        "the reminder and the transparency stay: {}",
        after.data
    );

    // A significant one replaces the copy as well, and still leaves what is Ben's.
    world
        .put(
            &anna_ctx,
            &path,
            &meeting("m-1", &anna, &[&ben.mailto()])
                .description("Bring the plan")
                .starts(When::utc(2027, 3, 11, 9, 0))
                .ends(When::utc(2027, 3, 11, 10, 0))
                .build(),
        )
        .await
        .unwrap();
    let after = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    assert!(after.data.contains("DTSTART:20270311T090000Z"), "{}", after.data);
    assert!(kept(&after.data), "{}", after.data);
    assert_eq!(
        after.data.matches("BEGIN:VALARM").count(),
        1,
        "the alarm is kept once, not once per edit: {}",
        after.data
    );
}

#[tokio::test]
async fn a_cancelled_series_also_reaches_the_attendees_removed_by_the_same_write_and_a_new_cancelled_event_invites_nobody()
 {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    world
        .put(
            &ctx,
            &path,
            &meeting("m-1", &anna, &[&ben.mailto(), &cara.mailto()]).build(),
        )
        .await
        .unwrap();

    // Anna cancels the event and drops Cara from it in one write.
    world
        .put(
            &ctx,
            &path,
            &meeting("m-1", &anna, &[&ben.mailto()])
                .status(EventStatus::Cancelled)
                .build(),
        )
        .await
        .unwrap();
    for person in [&ben, &cara] {
        let inbox = world.inbox(&acme, person).await;
        assert_eq!(
            property_in(&inbox.last().unwrap().data, "METHOD").as_deref(),
            Some("CANCEL"),
            "{} is told that it is over",
            person.name
        );
        assert!(
            world.copy_of(&acme, person, "m-1").await.is_none(),
            "{}: no orphaned copy",
            person.name
        );
    }

    // An event that is created cancelled (an import) invited nobody, so it cancels nothing.
    let outcome = world
        .put(
            &ctx,
            &world.object(&acme, &anna, "imp.ics"),
            &meeting("imp", &anna, &[&ben.mailto()])
                .status(EventStatus::Cancelled)
                .build(),
        )
        .await
        .unwrap();
    assert!(outcome.schedule.recipients.is_empty(), "nobody is told");
    assert_eq!(world.inbox(&acme, &ben).await.len(), 2, "only the two messages of m-1");
}

#[tokio::test]
async fn an_answer_that_repeats_itself_still_carries_a_new_remark_to_the_organizer() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let ben_ctx = world.api(&acme, &ben, &[Scope::EventsWrite]);
    let target = || ObjectRef {
        calendar: world.collection(&acme, &ben, "personal"),
        object: ObjectSelector::Uid(Uid::parse("m-1").unwrap()),
    };
    let accept = |comment: Option<&str>| InvitationResponse {
        partstat: PartStat::Accepted,
        comment: comment.map(str::to_owned),
    };

    world
        .services
        .scheduling
        .respond(&ben_ctx, target(), accept(None))
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &anna).await.len(), 1);
    world
        .services
        .scheduling
        .respond(&ben_ctx, target(), accept(None))
        .await
        .unwrap();
    assert_eq!(
        world.inbox(&acme, &anna).await.len(),
        1,
        "the same answer twice is one message"
    );

    // The same answer with something to add is news for the organizer.
    world
        .services
        .scheduling
        .respond(&ben_ctx, target(), accept(Some("I will bring the projector")))
        .await
        .unwrap();
    let inbox = world.inbox(&acme, &anna).await;
    assert_eq!(inbox.len(), 2);
    assert!(
        inbox[1].data.contains("COMMENT:I will bring the projector"),
        "{}",
        inbox[1].data
    );
}
