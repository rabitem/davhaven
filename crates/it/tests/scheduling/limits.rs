//! The limits on mail to people outside the tenant (PLAN 2.8, 2.12): they decide who is written to and never
//! refuse a write, cancellations are exempt, an answer to an organizer outside the tenant is mail as well, and what
//! was not stored is not counted.

use chrono::Duration;
use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::services::{
    InvitationResponse, ObjectRef, ObjectSelector, PutOutcome, RecipientStatus, ScheduleStatus,
};
use davhaven_testkit::davhaven_domain::{
    CalendarUserAddress, Email, ErrorKind, ItipMethod, PartStat, Precondition, Scope, Uid,
};
use davhaven_testkit::davhaven_wire::{AuthVerdict, InboundItipRequest};

use super::support::{Org, Person, World, answered, meeting, partstat_in, status_in};

fn guests(count: usize) -> Vec<String> {
    (1..=count).map(|n| format!("mailto:guest{n}@example.net")).collect()
}

fn status(guest: &str, status: ScheduleStatus) -> RecipientStatus {
    RecipientStatus {
        address: CalendarUserAddress::parse(guest).unwrap(),
        status,
    }
}

#[tokio::test]
async fn the_event_limit_and_the_quotas_never_refuse_a_write_and_the_status_says_who_was_not_mailed() {
    let world = World::with(|deps| {
        deps.config.scheduling.external_per_event = 2;
        deps.config.scheduling.external_per_organizer_per_hour = 3;
    });
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ctx = world.dav(&acme, &anna);
    let people = guests(3);
    let refs = |count: usize| -> Vec<&str> { people.iter().take(count).map(String::as_str).collect() };
    let path = |name: &str| world.object(&acme, &anna, name);

    // Three outside attendees, two allowed per event: the event is stored, the first two are mailed.
    let big = world
        .put(&ctx, &path("big.ics"), &meeting("big", &anna, &refs(3)).build())
        .await
        .unwrap();
    assert_eq!(
        big.schedule.recipients,
        vec![
            status(&people[0], ScheduleStatus::ImipSent),
            status(&people[1], ScheduleStatus::ImipSent),
            status(&people[2], ScheduleStatus::Failed),
        ]
    );
    let stored = world.text(&ctx, &path("big.ics")).await;
    for (guest, code) in [(&people[0], "1.1"), (&people[1], "1.1"), (&people[2], "5.1")] {
        assert_eq!(status_in(&stored, guest).as_deref(), Some(code), "{guest}: {stored}");
    }
    world.run_outbox().await;
    assert_eq!(world.mails_to("guest3@example.net").await.len(), 0);
    assert_eq!(world.mails().await.len(), 2);

    // Two more in the same hour: one fits under the hourly limit of 3, the other does not. The write is stored.
    let one = world
        .put(&ctx, &path("one.ics"), &meeting("one", &anna, &refs(2)).build())
        .await
        .unwrap();
    assert_eq!(
        one.schedule.recipients,
        vec![
            status(&people[0], ScheduleStatus::ImipSent),
            status(&people[1], ScheduleStatus::Failed)
        ]
    );
    assert!(
        world.copy_of(&acme, &anna, "one").await.is_some(),
        "a limit refuses nothing"
    );

    // Cancellations are not limited: the quota is used up, and the guests who were invited are told that it is over.
    world.delete(&ctx, &path("big.ics")).await.unwrap();
    let cancels: Vec<(String, String)> = world
        .mail_jobs(&acme)
        .await
        .into_iter()
        .filter(|(_, method)| method == "CANCEL")
        .collect();
    assert_eq!(
        cancels,
        vec![
            (people[0].clone(), "CANCEL".to_owned()),
            (people[1].clone(), "CANCEL".to_owned())
        ],
        "the two who were mailed; the third was never invited"
    );

    // An hour later the organizer may invite again.
    world.clock.advance(Duration::minutes(61));
    let two = world
        .put(&ctx, &path("two.ics"), &meeting("two", &anna, &refs(2)).build())
        .await
        .unwrap();
    assert_eq!(
        two.schedule.recipients,
        vec![
            status(&people[0], ScheduleStatus::ImipSent),
            status(&people[1], ScheduleStatus::ImipSent)
        ]
    );
}

#[tokio::test]
async fn the_quota_of_the_tenant_counts_all_its_organizers() {
    let world = World::with(|deps| deps.config.scheduling.external_per_tenant_per_day = 3);
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let people = guests(3);
    let refs = |count: usize| -> Vec<&str> { people.iter().take(count).map(String::as_str).collect() };
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "a.ics"),
            &meeting("a", &anna, &refs(2)).build(),
        )
        .await
        .unwrap();
    let outcome = world
        .put(
            &world.dav(&acme, &ben),
            &world.object(&acme, &ben, "b.ics"),
            &meeting("b", &ben, &refs(2)).build(),
        )
        .await
        .unwrap();
    assert_eq!(
        outcome.schedule.recipients,
        vec![
            status(&people[0], ScheduleStatus::ImipSent),
            status(&people[1], ScheduleStatus::Failed)
        ],
        "three for the day of the whole tenant, two used by Anna"
    );
}

#[tokio::test]
async fn a_write_that_fails_after_it_was_planned_uses_up_no_quota() {
    let world = World::with(|deps| deps.config.scheduling.external_per_organizer_per_hour = 2);
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ctx = world.dav(&acme, &anna);
    let people = guests(2);
    let refs: Vec<&str> = people.iter().map(String::as_str).collect();
    world
        .put(
            &ctx,
            &world.object(&acme, &anna, "a.ics"),
            &meeting("a", &anna, &[]).build(),
        )
        .await
        .unwrap();

    // Invites both and fails: the UID is taken in this calendar.
    let error = world
        .put(
            &ctx,
            &world.object(&acme, &anna, "b.ics"),
            &meeting("a", &anna, &refs).build(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error.precondition(), Some(Precondition::NoUidConflict(_))),
        "{error:?}"
    );

    let outcome = world
        .put(
            &ctx,
            &world.object(&acme, &anna, "c.ics"),
            &meeting("c", &anna, &refs).build(),
        )
        .await
        .unwrap();
    assert_eq!(
        outcome.schedule.recipients,
        vec![
            status(&people[0], ScheduleStatus::ImipSent),
            status(&people[1], ScheduleStatus::ImipSent)
        ],
        "the failed write did not use up the allowance"
    );
}

/// A tenant where Ben has an invitation from somebody outside, `olga`, that came in through the inbound endpoint.
async fn invited_from_outside(world: &World) -> (Org, Person) {
    let acme = world
        .org_with("acme", |settings| {
            settings.scheduling.inbound_methods = vec![ItipMethod::Reply, ItipMethod::Request];
        })
        .await;
    let ben = world.user(&acme, "ben").await;
    let request = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Other//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:ext-1\r\n\
        DTSTAMP:20270101T000000Z\r\nDTSTART:20270310T090000Z\r\nDTEND:20270310T100000Z\r\nSUMMARY:Their meeting\r\n\
        ORGANIZER:mailto:olga@example.net\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ben@acme.example\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";
    world
        .inbound(
            &acme,
            InboundItipRequest {
                message_id: "<req-1@example.net>".to_owned(),
                from: Email::parse("olga@example.net").unwrap(),
                ical: request.to_owned(),
                dmarc: AuthVerdict::Pass,
                dkim: AuthVerdict::Pass,
            },
        )
        .await
        .unwrap();
    assert!(world.copy_of(&acme, &ben, "ext-1").await.is_some());
    (acme, ben)
}

/// Ben's client writes his copy of the invitation from outside with the answer `partstat`.
async fn answer(world: &World, acme: &Org, ben: &Person, partstat: PartStat) -> Result<PutOutcome, AppError> {
    let copy = world.copy_of(acme, ben, "ext-1").await.unwrap();
    world
        .put(
            &world.dav(acme, ben),
            &world.object(acme, ben, copy.uri.as_str()),
            &answered(&copy.data, &ben.mailto(), partstat),
        )
        .await
}

#[tokio::test]
async fn answers_by_mail_to_an_organizer_outside_are_limited_like_invitations() {
    let world = World::with(|deps| {
        deps.config.scheduling.inbound_itip.enabled = true;
        deps.config.scheduling.external_per_organizer_per_hour = 2;
    });
    let (acme, ben) = invited_from_outside(&world).await;
    // Accept, then change his mind: two answers, two mails to the organizer.
    answer(&world, &acme, &ben, PartStat::Accepted).await.unwrap();
    answer(&world, &acme, &ben, PartStat::Declined).await.unwrap();
    assert_eq!(world.mail_jobs(&acme).await.len(), 2);

    // A third within the hour is refused, and so is its effect: Ben's copy still says what it said.
    let error = answer(&world, &acme, &ben, PartStat::Tentative).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RateLimited);
    assert!(error.retry_after().is_some());
    let data = world.copy_of(&acme, &ben, "ext-1").await.unwrap().data;
    assert_eq!(partstat_in(&data, &ben.mailto()), Some(PartStat::Declined), "{data}");
    assert_eq!(world.mail_jobs(&acme).await.len(), 2);

    // The hour passes.
    world.clock.advance(Duration::minutes(61));
    answer(&world, &acme, &ben, PartStat::Tentative).await.unwrap();
    assert_eq!(world.mail_jobs(&acme).await.len(), 3);
    world.run_outbox().await;
    assert_eq!(world.mails_to("olga@example.net").await.len(), 3);
}

#[tokio::test]
async fn over_mcp_an_answer_to_an_organizer_outside_needs_the_scope_for_mail_to_outside_people() {
    let world = World::with(|deps| deps.config.scheduling.inbound_itip.enabled = true);
    let (acme, ben) = invited_from_outside(&world).await;
    let target = || ObjectRef {
        calendar: world.collection(&acme, &ben, "personal"),
        object: ObjectSelector::Uid(Uid::parse("ext-1").unwrap()),
    };
    let accept = || InvitationResponse {
        partstat: PartStat::Accepted,
        comment: None,
    };

    let error = world
        .services
        .scheduling
        .respond(&world.mcp(&acme, &ben, &[Scope::McpWrite]), target(), accept())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    let data = world.copy_of(&acme, &ben, "ext-1").await.unwrap().data;
    assert_eq!(
        partstat_in(&data, &ben.mailto()),
        Some(PartStat::NeedsAction),
        "the refused answer was not stored either: {data}"
    );
    assert!(world.mail_jobs(&acme).await.is_empty(), "no mail");

    world
        .services
        .scheduling
        .respond(
            &world.mcp(&acme, &ben, &[Scope::McpWrite, Scope::McpScheduleExternal]),
            target(),
            accept(),
        )
        .await
        .unwrap();
    assert_eq!(
        world.mail_jobs(&acme).await,
        vec![("mailto:olga@example.net".to_owned(), "REPLY".to_owned())]
    );
}
