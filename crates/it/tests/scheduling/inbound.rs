//! The inbound iTIP endpoint (PLAN 2.8): what a mail gateway may forward, what is applied and what is quarantined.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use davhaven_testkit::davhaven_domain::{
    ErrorKind, EventPayload, EventType, ItipMethod, PartStat, Precondition, Scope,
};
use davhaven_testkit::davhaven_ports::{
    ContentScanner, PortError, RateDecision, RateKey, RateLimiter, ScanContext, ScanVerdict,
};
use davhaven_testkit::davhaven_wire::{AuthVerdict, InboundItipRequest, InboundOutcome};

use super::support::{
    Org, Person, World, gateway_mail, invitation_ical, meeting, partstat_in, property_in, reply_ical,
};

const GUEST: &str = "mailto:guest@example.net";

/// A world with the endpoint on, the tenant `acme` and its organizer `anna`, who invited the guest to `m-1`.
async fn invited_guest() -> (World, Org, Person) {
    let world = World::with_inbound();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[GUEST]).build(),
        )
        .await
        .unwrap();
    world.run_outbox().await;
    (world, acme, anna)
}

/// A message that must be quarantined: what is wrong with it, how the gateway forwards it, and the reason given.
type Case = (&'static str, Box<dyn Fn(&Person) -> InboundItipRequest>, &'static str);

/// The answer of the guest as a gateway forwards it.
fn guest_reply(
    anna: &Person,
    partstat: PartStat,
    message_id: &str,
) -> davhaven_testkit::davhaven_wire::InboundItipRequest {
    gateway_mail(
        "guest@example.net",
        message_id,
        &reply_ical("m-1", &anna.mailto(), GUEST, partstat, 0, None),
    )
}

async fn organizer_partstat(world: &World, acme: &Org, anna: &Person) -> Option<PartStat> {
    let text = world
        .text(&world.dav(acme, anna), &world.object(acme, anna, "m-1.ics"))
        .await;
    partstat_in(&text, GUEST)
}

#[tokio::test]
async fn the_endpoint_is_off_by_default_and_the_scope_is_checked_first() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let request = || guest_reply(&anna, PartStat::Accepted, "<one@example.net>");

    let error = world.inbound(&acme, request()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(
        error.precondition(),
        Some(&Precondition::FeatureNotEnabled),
        "feature-not-enabled"
    );

    // Without `itip:inbound` nobody learns whether the feature is on.
    for ctx in [
        world.tenant_token(&acme, &[Scope::EventsRead, Scope::EventsWrite]),
        world.api(&acme, &anna, &[Scope::ItipInbound]),
        world.dav(&acme, &anna),
    ] {
        let error = world
            .services
            .scheduling
            .inbound_itip(&ctx, request())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Forbidden);
    }
}

#[tokio::test]
async fn an_answer_is_applied_once_whatever_the_gateway_does() {
    let (world, acme, anna) = invited_guest().await;

    let response = world
        .inbound(
            &acme,
            gateway_mail(
                "guest@example.net",
                "<reply-1@example.net>",
                &reply_ical(
                    "m-1",
                    &anna.mailto(),
                    GUEST,
                    PartStat::Accepted,
                    0,
                    Some("Looking forward to it"),
                ),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.outcome, InboundOutcome::Applied);
    assert_eq!(response.reason, None);
    assert_eq!(organizer_partstat(&world, &acme, &anna).await, Some(PartStat::Accepted));
    let inbox = world.inbox(&acme, &anna).await;
    assert_eq!(
        inbox.len(),
        1,
        "the organizer is told through the same inbox as for any other answer"
    );
    assert_eq!(property_in(&inbox[0].data, "METHOD").as_deref(), Some("REPLY"));
    assert!(
        inbox[0].data.contains("COMMENT:Looking forward to it"),
        "{}",
        inbox[0].data
    );
    assert_eq!(
        world.events_of(&acme, EventType::SchedulingReplyReceived).await.len(),
        1
    );
    assert!(
        world
            .audit_actions(&acme)
            .await
            .contains(&"itip.inbound_accepted".to_owned())
    );

    // The same mail again, a gateway retry: nothing changes and the gateway is told so.
    let repeated = world
        .inbound(&acme, guest_reply(&anna, PartStat::Accepted, "<reply-1@example.net>"))
        .await
        .unwrap();
    assert_eq!(repeated.outcome, InboundOutcome::Duplicate);
    assert_eq!(world.inbox(&acme, &anna).await.len(), 1);
    assert_eq!(
        world.events_of(&acme, EventType::SchedulingReplyReceived).await.len(),
        1
    );

    // A changed mind is another mail and counts.
    let changed = world
        .inbound(&acme, guest_reply(&anna, PartStat::Declined, "<reply-2@example.net>"))
        .await
        .unwrap();
    assert_eq!(changed.outcome, InboundOutcome::Applied);
    assert_eq!(organizer_partstat(&world, &acme, &anna).await, Some(PartStat::Declined));
    assert_eq!(world.inbox(&acme, &anna).await.len(), 2);
}

#[tokio::test]
async fn a_message_that_fails_a_check_is_quarantined_and_changes_nothing() {
    // Each case: what the gateway sends, and why the message is not applied.
    let cases: Vec<Case> = vec![
        (
            "the sender is not the attendee",
            Box::new(|anna| {
                gateway_mail(
                    "mallory@example.net",
                    "<a@example.net>",
                    &reply_ical("m-1", &anna.mailto(), GUEST, PartStat::Accepted, 0, None),
                )
            }),
            "sender_mismatch",
        ),
        (
            "the gateway did not verify the sender",
            Box::new(|anna| {
                let mut request = guest_reply(anna, PartStat::Accepted, "<b@example.net>");
                request.dmarc = AuthVerdict::Fail;
                request
            }),
            "dmarc_not_passed",
        ),
        (
            "no verdict is no pass",
            Box::new(|anna| {
                let mut request = guest_reply(anna, PartStat::Accepted, "<c@example.net>");
                request.dmarc = AuthVerdict::None;
                request
            }),
            "dmarc_not_passed",
        ),
        (
            "the event is unknown",
            Box::new(|anna| {
                gateway_mail(
                    "guest@example.net",
                    "<d@example.net>",
                    &reply_ical("nothing-1", &anna.mailto(), GUEST, PartStat::Accepted, 0, None),
                )
            }),
            "unknown_event",
        ),
        (
            "the sender is not on the event",
            Box::new(|anna| {
                gateway_mail(
                    "stranger@example.net",
                    "<e@example.net>",
                    &reply_ical(
                        "m-1",
                        &anna.mailto(),
                        "mailto:stranger@example.net",
                        PartStat::Accepted,
                        0,
                        None,
                    ),
                )
            }),
            "unknown_attendee",
        ),
        (
            "the answer is about another version of the event",
            Box::new(|anna| {
                gateway_mail(
                    "guest@example.net",
                    "<f@example.net>",
                    &reply_ical("m-1", &anna.mailto(), GUEST, PartStat::Accepted, 7, None),
                )
            }),
            "sequence_mismatch",
        ),
    ];
    for (what, request, reason) in cases {
        let (world, acme, anna) = invited_guest().await;
        let request = request(&anna);
        let message_id = request.message_id.clone();
        let response = world.inbound(&acme, request).await.unwrap();
        assert_eq!(response.outcome, InboundOutcome::Quarantined, "{what}");
        assert_eq!(response.reason.as_deref(), Some(reason), "{what}");

        assert_eq!(
            organizer_partstat(&world, &acme, &anna).await,
            Some(PartStat::NeedsAction),
            "{what}"
        );
        assert!(
            world.inbox(&acme, &anna).await.is_empty(),
            "{what}: the organizer is not told"
        );
        assert_eq!(
            world.quarantined(&acme, &anna).await.len(),
            1,
            "{what}: the message is kept for inspection"
        );
        let rejected = world.events_of(&acme, EventType::SchedulingReplyRejected).await;
        assert_eq!(rejected.len(), 1, "{what}");
        match &rejected[0].data {
            EventPayload::SchedulingReply(payload) => assert_eq!(payload.reason.as_deref(), Some(reason), "{what}"),
            other => panic!("{what}: unexpected payload {other:?}"),
        }
        assert!(
            world
                .events_of(&acme, EventType::SchedulingReplyReceived)
                .await
                .is_empty(),
            "{what}"
        );
        assert!(
            world
                .audit_actions(&acme)
                .await
                .contains(&"itip.inbound_rejected".to_owned()),
            "{what}"
        );

        // A gateway that retries a quarantined message gets the same answer without another record.
        let again = world
            .inbound(
                &acme,
                gateway_mail(
                    "guest@example.net",
                    &message_id,
                    &reply_ical("m-1", &anna.mailto(), GUEST, PartStat::Accepted, 0, None),
                ),
            )
            .await
            .unwrap();
        assert_eq!(again.outcome, InboundOutcome::Duplicate, "{what}");
        assert_eq!(world.quarantined(&acme, &anna).await.len(), 1, "{what}");
    }
}

#[tokio::test]
async fn people_of_the_tenant_do_not_answer_by_mail() {
    let world = World::with_inbound();
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

    let response = world
        .inbound(
            &acme,
            gateway_mail(
                "ben@acme.example",
                "<ben-1@example.net>",
                &reply_ical("m-1", &anna.mailto(), &ben.mailto(), PartStat::Accepted, 0, None),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.outcome, InboundOutcome::Quarantined);
    assert_eq!(
        response.reason.as_deref(),
        Some("internal_attendee"),
        "a mail that says it is from Ben proves nothing"
    );
    let text = world
        .text(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await;
    assert_eq!(partstat_in(&text, &ben.mailto()), Some(PartStat::NeedsAction));
}

#[tokio::test]
async fn a_reply_for_an_event_that_is_gone_is_quarantined() {
    let (world, acme, anna) = invited_guest().await;
    world
        .delete(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await
        .unwrap();
    let response = world
        .inbound(&acme, guest_reply(&anna, PartStat::Accepted, "<late@example.net>"))
        .await
        .unwrap();
    assert_eq!(response.outcome, InboundOutcome::Quarantined);
    assert_eq!(response.reason.as_deref(), Some("unknown_event"));
}

#[tokio::test]
async fn unreadable_messages_and_unusable_message_ids_are_refused() {
    let (world, acme, anna) = invited_guest().await;
    let error = world
        .inbound(
            &acme,
            gateway_mail("guest@example.net", "<x@example.net>", "this is not iCalendar"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    for bad in ["", "   ", "<a@b>\u{0}", &"x".repeat(1000)] {
        let error = world
            .inbound(&acme, guest_reply(&anna, PartStat::Accepted, bad))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{bad:?}");
    }
    assert!(
        world.quarantined(&acme, &anna).await.is_empty(),
        "refused messages are not kept"
    );
    assert_eq!(
        organizer_partstat(&world, &acme, &anna).await,
        Some(PartStat::NeedsAction)
    );
}

/// A limiter that lets each key through a fixed number of times and then asks to wait.
struct Allowance {
    left: tokio::sync::Mutex<HashMap<String, u32>>,
    per_key: u32,
    asked: AtomicU32,
}

#[async_trait]
impl RateLimiter for Allowance {
    async fn check(&self, key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        // The budget of the gateway has a test of its own.
        if key.bucket == "itip_inbound_gateway" {
            return Ok(RateDecision::allow(u32::MAX));
        }
        let mut left = self.left.lock().await;
        let remaining = left
            .entry(format!("{}/{}", key.bucket, key.key))
            .or_insert(self.per_key);
        if *remaining == 0 {
            return Ok(RateDecision::deny(Duration::from_secs(90)));
        }
        *remaining -= 1;
        Ok(RateDecision::allow(*remaining))
    }
}

#[tokio::test]
async fn a_sender_is_rate_limited_and_the_others_are_not() {
    let limiter = Arc::new(Allowance {
        left: tokio::sync::Mutex::new(HashMap::new()),
        per_key: 2,
        asked: AtomicU32::new(0),
    });
    let world = World::with(|deps| {
        deps.config.scheduling.inbound_itip.enabled = true;
        deps.rate_limiter = Arc::<Allowance>::clone(&limiter);
    });
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    for n in 0..2 {
        let response = world
            .inbound(
                &acme,
                guest_reply(&anna, PartStat::Accepted, &format!("<n{n}@example.net>")),
            )
            .await
            .unwrap();
        assert_eq!(
            response.outcome,
            InboundOutcome::Quarantined,
            "the event does not exist, the mail is still counted"
        );
    }
    let error = world
        .inbound(&acme, guest_reply(&anna, PartStat::Accepted, "<n3@example.net>"))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RateLimited);
    assert_eq!(error.retry_after(), Some(Duration::from_secs(90)));
    // Somebody else's mail has a budget of its own.
    let other = gateway_mail(
        "other@example.net",
        "<o1@example.net>",
        &reply_ical(
            "m-1",
            &anna.mailto(),
            "mailto:other@example.net",
            PartStat::Accepted,
            0,
            None,
        ),
    );
    assert!(world.inbound(&acme, other).await.is_ok());
    assert!(limiter.asked.load(Ordering::SeqCst) >= 4);
}

#[tokio::test]
async fn invitations_and_cancellations_from_outside_need_the_tenant_to_ask_for_them() {
    let world = World::with_inbound();
    let acme = world.org("acme").await;
    let ben = world.user(&acme, "ben").await;
    let request = |sequence: u32, id: &str| {
        gateway_mail(
            "olga@example.net",
            id,
            &invitation_ical("REQUEST", "ext-1", "mailto:olga@example.net", &ben.mailto(), sequence),
        )
    };

    // Only answers are accepted unless the tenant enables more.
    let response = world.inbound(&acme, request(0, "<r0@example.net>")).await.unwrap();
    assert_eq!(response.outcome, InboundOutcome::Quarantined);
    assert_eq!(response.reason.as_deref(), Some("method_not_enabled"));
    assert!(world.copy_of(&acme, &ben, "ext-1").await.is_none());

    let globex = world
        .org_with("globex", |settings| {
            settings.scheduling.inbound_methods = vec![ItipMethod::Reply, ItipMethod::Request, ItipMethod::Cancel];
        })
        .await;
    let eva = world.user(&globex, "eva").await;
    let invitation = |method: &str, sequence: u32, from: &str, organizer: &str, id: &str| {
        gateway_mail(
            from,
            id,
            &invitation_ical(method, "ext-2", organizer, &eva.mailto(), sequence),
        )
    };
    let organizer = "mailto:olga@example.net";

    let applied = world
        .inbound(
            &globex,
            invitation("REQUEST", 0, "olga@example.net", organizer, "<g0@example.net>"),
        )
        .await
        .unwrap();
    assert_eq!(applied.outcome, InboundOutcome::Applied);
    let copy = world
        .copy_of(&globex, &eva, "ext-2")
        .await
        .expect("the invitation is added to Eva's calendar");
    assert!(
        copy.data.contains("SUMMARY:Their meeting") && !copy.data.contains("METHOD:"),
        "{}",
        copy.data
    );
    assert_eq!(world.inbox(&globex, &eva).await.len(), 1);
    assert_eq!(
        world
            .inbound(
                &globex,
                invitation("REQUEST", 0, "olga@example.net", organizer, "<g0@example.net>")
            )
            .await
            .unwrap()
            .outcome,
        InboundOutcome::Duplicate
    );

    // Nobody may claim to be the organizer of somebody else's event, or to be somebody of the tenant.
    let hijack = world
        .inbound(
            &globex,
            invitation("CANCEL", 1, "mallory@example.net", organizer, "<g1@example.net>"),
        )
        .await
        .unwrap();
    assert_eq!(hijack.reason.as_deref(), Some("sender_mismatch"));
    let internal = world
        .inbound(
            &globex,
            invitation(
                "REQUEST",
                0,
                "eva@globex.example",
                "mailto:eva@globex.example",
                "<g2@example.net>",
            ),
        )
        .await
        .unwrap();
    assert_eq!(internal.reason.as_deref(), Some("organizer_is_internal"));
    assert!(
        world.copy_of(&globex, &eva, "ext-2").await.is_some(),
        "the copy is still there"
    );

    // The organizer cancels: the copy goes, the cancellation is in the inbox.
    let cancelled = world
        .inbound(
            &globex,
            invitation("CANCEL", 1, "olga@example.net", organizer, "<g3@example.net>"),
        )
        .await
        .unwrap();
    assert_eq!(cancelled.outcome, InboundOutcome::Applied);
    assert!(world.copy_of(&globex, &eva, "ext-2").await.is_none());
    let inbox = world.inbox(&globex, &eva).await;
    assert_eq!(inbox.len(), 2);
    assert_eq!(property_in(&inbox[1].data, "METHOD").as_deref(), Some("CANCEL"));

    // Nobody else's message is applied without the verdict of the gateway.
    let mut unverified = invitation("REQUEST", 3, "olga@example.net", organizer, "<g4@example.net>");
    unverified.dmarc = AuthVerdict::Fail;
    assert_eq!(
        world.inbound(&globex, unverified).await.unwrap().reason.as_deref(),
        Some("dmarc_not_passed")
    );
}

#[tokio::test]
async fn the_dmarc_check_can_be_switched_off_for_a_gateway_that_does_not_report_it() {
    let world = World::with(|deps| {
        deps.config.scheduling.inbound_itip.enabled = true;
        deps.config.scheduling.inbound_itip.require_dmarc_pass = false;
    });
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[GUEST]).build(),
        )
        .await
        .unwrap();
    let mut request = guest_reply(&anna, PartStat::Tentative, "<t@example.net>");
    request.dmarc = AuthVerdict::None;
    assert_eq!(
        world.inbound(&acme, request).await.unwrap().outcome,
        InboundOutcome::Applied
    );
    assert_eq!(
        organizer_partstat(&world, &acme, &anna).await,
        Some(PartStat::Tentative)
    );
}

/// A limiter that cannot be reached.
struct Down;

#[async_trait]
impl RateLimiter for Down {
    async fn check(&self, _key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
        Err(PortError::unavailable("the limiter is down"))
    }
}

/// A limiter that lets the senders through and gives the gateway a budget.
struct GatewayBudget {
    left: AtomicU32,
}

#[async_trait]
impl RateLimiter for GatewayBudget {
    async fn check(&self, key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
        if key.bucket != "itip_inbound_gateway" {
            return Ok(RateDecision::allow(u32::MAX));
        }
        match self
            .left
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
        {
            Ok(before) => Ok(RateDecision::allow(before - 1)),
            Err(_) => Ok(RateDecision::deny(Duration::from_secs(30))),
        }
    }
}

#[tokio::test]
async fn a_retried_message_that_was_quarantined_with_nobody_to_keep_it_for_is_a_duplicate() {
    let world = World::with_inbound();
    let acme = world.org("acme").await;
    // The organizer is nobody of the tenant: the message is quarantined, and there is nobody whose inbox could keep it.
    let request = || {
        gateway_mail(
            "guest@example.net",
            "<nobody-1@example.net>",
            &reply_ical("m-9", "mailto:nobody@acme.example", GUEST, PartStat::Accepted, 0, None),
        )
    };
    let first = world.inbound(&acme, request()).await.unwrap();
    assert_eq!(first.outcome, InboundOutcome::Quarantined);
    assert_eq!(first.reason.as_deref(), Some("unknown_event"));

    let again = world.inbound(&acme, request()).await.unwrap();
    assert_eq!(again.outcome, InboundOutcome::Duplicate, "a retry of the gateway");
    assert_eq!(
        world.events_of(&acme, EventType::SchedulingReplyRejected).await.len(),
        1,
        "one event"
    );
    let audited = world
        .audit_actions(&acme)
        .await
        .into_iter()
        .filter(|action| action == "itip.inbound_rejected")
        .count();
    assert_eq!(audited, 1, "one audit record");
}

#[tokio::test]
async fn the_reasons_of_messages_that_have_nothing_to_keep_are_answered_and_deduplicated_too() {
    let world = World::with_inbound();
    let acme = world.org("acme").await;
    // A method the endpoint does not take, and a message that is not about an event.
    let publish = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Other//EN\r\nMETHOD:PUBLISH\r\nBEGIN:VEVENT\r\nUID:p-1\r\n\
        DTSTAMP:20270101T000000Z\r\nDTSTART:20270310T090000Z\r\nDTEND:20270310T100000Z\r\nSUMMARY:Open day\r\n\
        ORGANIZER:mailto:olga@example.net\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let free_busy = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Other//EN\r\nMETHOD:REPLY\r\nBEGIN:VFREEBUSY\r\nUID:fb\r\n\
        DTSTAMP:20270301T090000Z\r\nDTSTART:20270301T090000Z\r\nDTEND:20270301T100000Z\r\n\
        ORGANIZER:mailto:anna@acme.example\r\nATTENDEE:mailto:guest@example.net\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
    for (ical, reason) in [(publish, "method_not_supported"), (free_busy, "unsupported_component")] {
        let request = || gateway_mail("olga@example.net", &format!("<{reason}@example.net>"), ical);
        let first = world.inbound(&acme, request()).await.unwrap();
        assert_eq!(first.outcome, InboundOutcome::Quarantined, "{reason}");
        assert_eq!(first.reason.as_deref(), Some(reason));
        assert_eq!(
            world.inbound(&acme, request()).await.unwrap().outcome,
            InboundOutcome::Duplicate,
            "{reason}"
        );
    }
}

#[tokio::test]
async fn a_forged_invitation_that_names_many_people_is_kept_once() {
    let world = World::with(|deps| deps.config.scheduling.inbound_itip.enabled = true);
    let acme = world
        .org_with("acme", |settings| {
            settings.scheduling.inbound_methods = vec![ItipMethod::Reply, ItipMethod::Request];
        })
        .await;
    let mut people = Vec::new();
    for name in ["u1", "u2", "u3", "u4", "u5"] {
        people.push(world.user(&acme, name).await);
    }
    let mut ical = invitation_ical("REQUEST", "forged-1", "mailto:olga@example.net", &people[0].mailto(), 0);
    for person in &people[1..] {
        ical = ical.replace("END:VEVENT", &format!("ATTENDEE:{}\r\nEND:VEVENT", person.mailto()));
    }
    let mut request = gateway_mail("olga@example.net", "<forged-1@example.net>", &ical);
    request.dmarc = AuthVerdict::Fail;

    let response = world.inbound(&acme, request).await.unwrap();
    assert_eq!(response.reason.as_deref(), Some("dmarc_not_passed"));
    let mut kept = 0;
    for person in &people {
        kept += world.quarantined(&acme, person).await.len();
        assert!(world.inbox(&acme, person).await.is_empty(), "{}", person.name);
        assert!(
            world.copy_of(&acme, person, "forged-1").await.is_none(),
            "{}",
            person.name
        );
    }
    assert_eq!(kept, 1, "one copy of the message, not one per recipient");
}

#[tokio::test]
async fn a_limiter_that_does_not_answer_refuses_the_message() {
    let world = World::with(|deps| {
        deps.config.scheduling.inbound_itip.enabled = true;
        deps.rate_limiter = Arc::new(Down);
    });
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[GUEST]).build(),
        )
        .await
        .unwrap();
    let error = world
        .inbound(&acme, guest_reply(&anna, PartStat::Accepted, "<down-1@example.net>"))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable, "fail closed");
    assert_eq!(
        organizer_partstat(&world, &acme, &anna).await,
        Some(PartStat::NeedsAction),
        "nothing was applied"
    );
}

#[tokio::test]
async fn the_gateway_has_a_budget_of_its_own_whoever_the_senders_are() {
    let world = World::with(|deps| {
        deps.config.scheduling.inbound_itip.enabled = true;
        deps.rate_limiter = Arc::new(GatewayBudget {
            left: AtomicU32::new(2),
        });
    });
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let from = |n: u32| {
        gateway_mail(
            &format!("sender{n}@example.net"),
            &format!("<g{n}@example.net>"),
            &reply_ical(
                "m-1",
                &anna.mailto(),
                &format!("mailto:sender{n}@example.net"),
                PartStat::Accepted,
                0,
                None,
            ),
        )
    };
    for n in 1..=2 {
        assert!(world.inbound(&acme, from(n)).await.is_ok(), "{n}");
    }
    let error = world.inbound(&acme, from(3)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RateLimited, "varying From does not help");
    assert_eq!(error.retry_after(), Some(Duration::from_secs(30)));
}

/// The text of an invitation from outside with an alarm of the sender and an inline attachment.
fn invitation_with_extras(attendee: &str) -> String {
    invitation_ical("REQUEST", "ext-9", "mailto:olga@example.net", attendee, 0).replace(
        "END:VEVENT",
        "ATTACH;FMTTYPE=text/plain;ENCODING=BASE64;VALUE=BINARY:aGVsbG8=\r\n\
         BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT1H\r\nDESCRIPTION:Theirs\r\nEND:VALARM\r\nEND:VEVENT",
    )
}

/// A scanner that finds the word `hello` malicious.
struct RefusesHello;

#[async_trait]
impl ContentScanner for RefusesHello {
    fn name(&self) -> &'static str {
        "refuses-hello"
    }

    async fn scan(&self, content: &[u8], _context: &ScanContext) -> Result<ScanVerdict, PortError> {
        Ok(if content == b"hello" {
            ScanVerdict::Infected("hello".to_owned())
        } else {
            ScanVerdict::Clean
        })
    }
}

/// A scanner whose engine is not there.
struct Broken;

#[async_trait]
impl ContentScanner for Broken {
    fn name(&self) -> &'static str {
        "broken"
    }

    async fn scan(&self, _content: &[u8], _context: &ScanContext) -> Result<ScanVerdict, PortError> {
        Err(PortError::unavailable("the engine is down"))
    }
}

fn outside_tenant_may_invite(settings: &mut davhaven_testkit::davhaven_domain::TenantSettings) {
    settings.scheduling.inbound_methods = vec![ItipMethod::Reply, ItipMethod::Request];
}

#[tokio::test]
async fn the_copy_of_an_invitation_from_outside_has_no_alarms_of_the_sender() {
    let world = World::with(|deps| deps.config.scheduling.inbound_itip.enabled = true);
    let acme = world.org_with("acme", outside_tenant_may_invite).await;
    let ben = world.user(&acme, "ben").await;
    let response = world
        .inbound(
            &acme,
            gateway_mail(
                "olga@example.net",
                "<x1@example.net>",
                &invitation_with_extras(&ben.mailto()),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.outcome, InboundOutcome::Applied);
    let copy = world.copy_of(&acme, &ben, "ext-9").await.expect("a copy");
    assert!(
        !copy.data.contains("VALARM") && !copy.data.contains("Theirs"),
        "the alarm of the sender does not fire on Ben's devices: {}",
        copy.data
    );
    assert!(copy.data.contains("SUMMARY:Their meeting"));
}

#[tokio::test]
async fn a_content_scanner_can_refuse_an_invitation_and_one_that_is_down_stops_it() {
    let world = World::with(|deps| {
        deps.config.scheduling.inbound_itip.enabled = true;
        deps.content_scanners = vec![Arc::new(RefusesHello)];
    });
    let acme = world.org_with("acme", outside_tenant_may_invite).await;
    let ben = world.user(&acme, "ben").await;
    let response = world
        .inbound(
            &acme,
            gateway_mail(
                "olga@example.net",
                "<x2@example.net>",
                &invitation_with_extras(&ben.mailto()),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.outcome, InboundOutcome::Quarantined);
    assert_eq!(response.reason.as_deref(), Some("content_rejected"));
    assert!(world.copy_of(&acme, &ben, "ext-9").await.is_none());
    assert!(world.inbox(&acme, &ben).await.is_empty(), "nothing was delivered");
    assert_eq!(world.quarantined(&acme, &ben).await.len(), 1);

    // The same invitation without the attachment is fine.
    let plain = invitation_ical("REQUEST", "ext-8", "mailto:olga@example.net", &ben.mailto(), 0);
    assert_eq!(
        world
            .inbound(&acme, gateway_mail("olga@example.net", "<x3@example.net>", &plain))
            .await
            .unwrap()
            .outcome,
        InboundOutcome::Applied
    );

    let broken = World::with(|deps| {
        deps.config.scheduling.inbound_itip.enabled = true;
        deps.content_scanners = vec![Arc::new(Broken)];
    });
    let acme = broken.org_with("acme", outside_tenant_may_invite).await;
    let ben = broken.user(&acme, "ben").await;
    let error = broken
        .inbound(
            &acme,
            gateway_mail(
                "olga@example.net",
                "<x4@example.net>",
                &invitation_with_extras(&ben.mailto()),
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::Unavailable,
        "content that was not scanned is not stored"
    );
    assert!(broken.copy_of(&acme, &ben, "ext-9").await.is_none());
}

#[tokio::test]
async fn an_invitation_from_outside_cannot_replace_an_event_the_attendee_has_from_somebody_else() {
    let world = World::with(|deps| deps.config.scheduling.inbound_itip.enabled = true);
    let acme = world.org_with("acme", outside_tenant_may_invite).await;
    let eva = world.user(&acme, "eva").await;
    let fred = world.user(&acme, "fred").await;
    // Eva organizes a meeting that has the UID of the invitation that arrives.
    world
        .put(
            &world.dav(&acme, &eva),
            &world.object(&acme, &eva, "own.ics"),
            &meeting("ext-2", &eva, &[&fred.mailto()]).build(),
        )
        .await
        .unwrap();
    let before = world.copy_of(&acme, &eva, "ext-2").await.unwrap();
    let inbox_before = world.inbox(&acme, &eva).await.len();

    let response = world
        .inbound(
            &acme,
            gateway_mail(
                "olga@example.net",
                "<x5@example.net>",
                &invitation_ical("REQUEST", "ext-2", "mailto:olga@example.net", &eva.mailto(), 0),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.outcome, InboundOutcome::Quarantined);
    assert_eq!(response.reason.as_deref(), Some("unknown_event"));
    let after = world.copy_of(&acme, &eva, "ext-2").await.unwrap();
    assert_eq!(
        (after.etag, after.data),
        (before.etag, before.data),
        "Eva's meeting is hers"
    );
    assert_eq!(world.inbox(&acme, &eva).await.len(), inbox_before);
}
