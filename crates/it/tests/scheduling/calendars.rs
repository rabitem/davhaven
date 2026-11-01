//! Scheduling in calendars that more than one person writes: a colleague with write access organizes in the name of
//! the owner, and in a group calendar the member is the organizer (PLAN 2.8, "Actor").

use davhaven_testkit::davhaven_app::services::{InvitationResponse, ObjectRef, ObjectSelector, ScheduleStatus};
use davhaven_testkit::davhaven_domain::{CalendarKind, ErrorKind, EventType, GrantAccess, PartStat, Scope};

use super::support::{Org, Person, World, event, partstat_in, property_in, write};

const GUEST: &str = "mailto:guest@example.net";

/// The unfolded text of the `ORGANIZER` line of an iCalendar text.
fn organizer_line(text: &str) -> String {
    text.replace("\r\n ", "")
        .lines()
        .find(|line| line.starts_with("ORGANIZER"))
        .unwrap_or_default()
        .to_owned()
}

/// A tenant with five people.
struct Staff {
    world: World,
    acme: Org,
    anna: Person,
    pat: Person,
    ben: Person,
    cara: Person,
    dan: Person,
}

async fn staff() -> Staff {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let pat = world.user(&acme, "pat").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let dan = world.user(&acme, "dan").await;
    Staff {
        world,
        acme,
        anna,
        pat,
        ben,
        cara,
        dan,
    }
}

#[tokio::test]
async fn a_colleague_with_write_access_organizes_in_the_name_of_the_owner() {
    let Staff {
        world,
        acme,
        anna,
        pat,
        ben,
        cara,
        ..
    } = staff().await;
    world
        .grant(&acme, &anna, "personal", &pat, GrantAccess::ReadWrite)
        .await;
    world.grant(&acme, &anna, "personal", &cara, GrantAccess::Read).await;
    let calendar = world.collection(&acme, &anna, "personal");

    // Pat writes into Anna's calendar an event that Anna organizes.
    let pat_ctx = world.api(&acme, &pat, &[Scope::EventsWrite, Scope::EventsRead]);
    let outcome = world
        .services
        .objects
        .put_event(
            &pat_ctx,
            &calendar,
            write("k1", &event("Planning", &anna, &[&ben.mailto(), GUEST]), true),
        )
        .await
        .unwrap();
    let statuses: Vec<ScheduleStatus> = outcome
        .schedule
        .recipients
        .iter()
        .map(|recipient| recipient.status)
        .collect();
    assert_eq!(statuses, vec![ScheduleStatus::Delivered, ScheduleStatus::ImipSent]);

    // The invitations name Pat as the sender (`SENT-BY`); the organizer is still Anna.
    let inbox = world.inbox(&acme, &ben).await;
    assert_eq!(inbox.len(), 1);
    let line = organizer_line(&inbox[0].data);
    assert!(line.contains("SENT-BY=\"mailto:pat@acme.example\""), "{line}");
    assert!(line.ends_with(":mailto:anna@acme.example"), "{line}");
    world.run_outbox().await;
    let mails = world.mails_to("guest@example.net").await;
    assert_eq!(mails.len(), 1);
    let (_, ics) = super::support::calendar_of(&mails[0].mail);
    let line = organizer_line(&ics);
    assert!(line.contains("SENT-BY=\"mailto:pat@acme.example\""), "{line}");
    assert!(line.ends_with(":mailto:anna@acme.example"), "{line}");

    // The answer of Ben goes to Anna's copy, whoever wrote it.
    let ben_copy = world
        .objects_of(&acme, &ben)
        .await
        .into_iter()
        .find(|object| object.data.contains("SUMMARY:Planning"))
        .expect("Ben's calendar has the event");
    world
        .services
        .scheduling
        .respond(
            &world.api(&acme, &ben, &[Scope::EventsWrite]),
            ObjectRef {
                calendar: world.collection(&acme, &ben, "personal"),
                object: ObjectSelector::Uid(ben_copy.uid.clone()),
            },
            InvitationResponse {
                partstat: PartStat::Accepted,
                comment: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &anna).await.len(), 1, "Anna, the organizer, is told");
    assert_eq!(
        world.inbox(&acme, &pat).await.len(),
        0,
        "the colleague who typed it is not the organizer"
    );

    // A reader cannot write at all, so nothing is scheduled for them.
    let error = world
        .services
        .objects
        .put_event(
            &world.api(&acme, &cara, &[Scope::EventsWrite]),
            &calendar,
            write("k2", &event("Sneaky", &anna, &[&ben.mailto()]), true),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(world.inbox(&acme, &ben).await.len(), 1);
}

#[tokio::test]
async fn somebody_with_write_access_cannot_organize_in_the_name_of_a_third_person() {
    let Staff {
        world,
        acme,
        anna,
        pat,
        ben,
        ..
    } = staff().await;
    world
        .grant(&acme, &anna, "personal", &pat, GrantAccess::ReadWrite)
        .await;
    // Pat may write into Anna's calendar, but Ben is neither Anna nor Pat: an event that Ben organizes is not Pat's
    // to send, and a new one of that kind is refused (C:organizer-allowed).
    let error = world
        .services
        .objects
        .put_event(
            &world.api(&acme, &pat, &[Scope::EventsWrite]),
            &world.collection(&acme, &anna, "personal"),
            write("k3", &event("Sneaky", &ben, &[&anna.mailto()]), true),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(world.inbox(&acme, &anna).await.len(), 0);
    assert_eq!(world.objects_of(&acme, &anna).await.len(), 0, "nothing was stored");
}

#[tokio::test]
async fn in_a_group_calendar_the_member_is_the_organizer_and_members_get_no_second_copy() {
    let Staff {
        world,
        acme,
        anna,
        ben,
        cara,
        dan,
        ..
    } = staff().await;
    let team = world.group(&acme, "team", &[&anna, &ben, &cara]).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    // Nobody has listed their home: whether a member gets a second copy follows from membership, not from whether
    // their client ever looked at the calendars it sees.
    let group_calendar = world.collection(&acme, &team, "shared");

    let outcome = world
        .services
        .objects
        .put_event(
            &world.api(&acme, &anna, &[Scope::EventsWrite, Scope::EventsRead]),
            &group_calendar,
            write(
                "g1",
                &event("Team meeting", &anna, &[&ben.mailto(), &cara.mailto(), &dan.mailto()]),
                true,
            ),
        )
        .await
        .unwrap();
    assert_eq!(outcome.schedule.recipients.len(), 3);

    // Everybody is told; only the one who does not see the group calendar gets a copy of their own.
    for person in [&ben, &cara, &dan] {
        assert_eq!(world.inbox(&acme, person).await.len(), 1, "{}", person.name);
    }
    for member in [&ben, &cara] {
        assert_eq!(
            world.objects_of(&acme, member).await.len(),
            0,
            "{} has the event in the group calendar already",
            member.name
        );
    }
    assert_eq!(world.objects_of(&acme, &dan).await.len(), 1);
    assert_eq!(world.inbox(&acme, &anna).await.len(), 0);
    assert_eq!(
        world.inbox(&acme, &team).await.len(),
        0,
        "nobody schedules in the name of a group"
    );

    // Ben answers on the event he sees in the group calendar: that is the organizer's own object, and Anna is told.
    let in_group = world
        .objects_of(&acme, &team)
        .await
        .pop()
        .expect("the group calendar holds the event");
    world
        .services
        .scheduling
        .respond(
            &world.api(&acme, &ben, &[Scope::EventsWrite]),
            ObjectRef {
                calendar: group_calendar,
                object: ObjectSelector::Uid(in_group.uid.clone()),
            },
            InvitationResponse {
                partstat: PartStat::Accepted,
                comment: None,
            },
        )
        .await
        .unwrap();
    let stored = world.objects_of(&acme, &team).await.pop().unwrap().data;
    assert_eq!(
        partstat_in(&stored, &ben.mailto()),
        Some(PartStat::Accepted),
        "{stored}"
    );
    let inbox = world.inbox(&acme, &anna).await;
    assert_eq!(
        inbox.len(),
        1,
        "the organizer is told although the answer was written into her own object"
    );
    assert_eq!(property_in(&inbox[0].data, "METHOD").as_deref(), Some("REPLY"));
    assert_eq!(
        world.events_of(&acme, EventType::SchedulingReplyReceived).await.len(),
        1
    );
}

#[tokio::test]
async fn a_tenant_can_ask_for_a_copy_even_where_the_event_is_visible_already() {
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| settings.scheduling.suppress_duplicate_copies = false)
        .await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let team = world.group(&acme, "team", &[&anna, &ben]).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap();

    world
        .services
        .objects
        .put_event(
            &world.api(&acme, &anna, &[Scope::EventsWrite]),
            &world.collection(&acme, &team, "shared"),
            write("g1", &event("Team meeting", &anna, &[&ben.mailto()]), true),
        )
        .await
        .unwrap();
    assert_eq!(
        world.objects_of(&acme, &ben).await.len(),
        1,
        "a copy of his own, as the setting says"
    );
}

#[tokio::test]
async fn the_writer_of_a_shared_calendar_who_organizes_sends_under_their_own_name() {
    // Pat writes an event of his own into Anna's calendar: Pat is the organizer, and nobody sends for him.
    let Staff {
        world,
        acme,
        anna,
        pat,
        ben,
        ..
    } = staff().await;
    world
        .grant(&acme, &anna, "personal", &pat, GrantAccess::ReadWrite)
        .await;
    let outcome = world
        .services
        .objects
        .put_event(
            &world.api(&acme, &pat, &[Scope::EventsWrite]),
            &world.collection(&acme, &anna, "personal"),
            write("p1", &event("Pat's idea", &pat, &[&ben.mailto()]), true),
        )
        .await
        .unwrap();
    assert_eq!(outcome.schedule.recipients.len(), 1);
    let inbox = world.inbox(&acme, &ben).await;
    let line = organizer_line(&inbox[0].data);
    assert!(line.ends_with(":mailto:pat@acme.example"), "{line}");
    assert!(
        !line.contains("SENT-BY"),
        "Pat is the organizer, nobody sends for him: {line}"
    );
}
