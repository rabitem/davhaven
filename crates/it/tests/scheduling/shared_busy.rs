//! Free-busy follows the meetings a person takes part in, wherever they are kept: in the calendar of a group they
//! belong to or in a calendar somebody shared with them (PLAN 2.8). A person who sees the organizer's calendar gets no
//! second copy of the event (PLAN 2.8, duplicate suppression), so the meeting is in a calendar that is not theirs and
//! has to count all the same, whether or not their client ever listed its home.

use chrono::{DateTime, TimeZone, Utc};
use davhaven_testkit::davhaven_app::services::{
    BusyKind, BusyPeriod, FreeBusyRequest, FreeBusyTarget, InvitationResponse, ObjectRef, ObjectSelector, TimeRange,
};
use davhaven_testkit::davhaven_domain::{CalendarKind, GrantAccess, PartStat, Scope, Uid};

use super::support::{Org, Person, World, in_collection, meeting};

fn at(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 3, 10, hour, 0, 0).unwrap()
}

fn nine_to_ten() -> Vec<BusyPeriod> {
    vec![BusyPeriod {
        start: at(9),
        end: at(10),
        kind: BusyKind::Busy,
    }]
}

/// The busy periods of `who` on the day of the meetings, as `asker` sees them.
async fn busy_of(world: &World, org: &Org, asker: &Person, who: &Person) -> Vec<BusyPeriod> {
    let result = world
        .services
        .scheduling
        .free_busy(
            &world.dav(org, asker),
            FreeBusyRequest {
                target: FreeBusyTarget::Addresses(vec![who.address()]),
                range: TimeRange::new(Some(at(0)), Some(at(0) + chrono::Duration::days(1))),
            },
        )
        .await
        .unwrap();
    result.entries.into_iter().next().unwrap().periods
}

#[tokio::test]
async fn a_meeting_in_a_group_calendar_makes_the_organizer_and_the_attendees_busy_and_nobody_else() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    let dan = world.user(&acme, "dan").await;
    let team = world.group(&acme, "team", &[&anna, &ben, &cara]).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    // Only Anna has listed her home (to write the meeting); Ben has not, and the group calendar has no binding of
    // his: the answer must not depend on that.
    let path = in_collection(&world.collection_of(&acme, &anna, &team).await, "g-1.ics");
    world
        .put(
            &world.dav(&acme, &anna),
            &path,
            &meeting("g-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    assert!(
        world.objects_of(&acme, &ben).await.is_empty(),
        "Ben sees the group calendar and gets no copy of his own"
    );

    assert_eq!(
        busy_of(&world, &acme, &dan, &anna).await,
        nine_to_ten(),
        "the organizer"
    );
    assert_eq!(busy_of(&world, &acme, &dan, &ben).await, nine_to_ten(), "the attendee");
    assert!(
        busy_of(&world, &acme, &dan, &cara).await.is_empty(),
        "a member of the group who is not in the meeting is free"
    );
    assert!(
        busy_of(&world, &acme, &anna, &dan).await.is_empty(),
        "and so is somebody who has nothing to do with the group"
    );

    // Ben declines: the time is his again.
    world
        .services
        .scheduling
        .respond(
            &world.api(&acme, &ben, &[Scope::EventsWrite]),
            ObjectRef {
                calendar: world.collection(&acme, &team, "shared"),
                object: ObjectSelector::Uid(Uid::parse("g-1").unwrap()),
            },
            InvitationResponse {
                partstat: PartStat::Declined,
                comment: None,
            },
        )
        .await
        .unwrap();
    assert!(
        busy_of(&world, &acme, &dan, &ben).await.is_empty(),
        "what a person declined is not their time"
    );
    assert_eq!(busy_of(&world, &acme, &dan, &anna).await, nine_to_ten());
}

#[tokio::test]
async fn a_meeting_in_a_calendar_that_was_shared_with_somebody_is_their_time_when_they_are_invited() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let pat = world.user(&acme, "pat").await;
    let cara = world.user(&acme, "cara").await;
    world.grant(&acme, &anna, "personal", &pat, GrantAccess::Read).await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&pat.mailto(), &cara.mailto()]).build(),
        )
        .await
        .unwrap();

    assert!(
        world.objects_of(&acme, &pat).await.is_empty(),
        "Pat sees Anna's calendar through the share and gets no copy"
    );
    assert_eq!(world.objects_of(&acme, &cara).await.len(), 1, "Cara does");
    assert_eq!(
        busy_of(&world, &acme, &anna, &pat).await,
        nine_to_ten(),
        "in the calendar of Anna"
    );
    assert_eq!(busy_of(&world, &acme, &anna, &cara).await, nine_to_ten(), "in her own");
}
