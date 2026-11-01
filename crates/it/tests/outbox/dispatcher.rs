//! The outbox dispatcher over the in-memory store: leases, the deadline of a batch, backoff, dead letters, deferrals,
//! lost claims, the announcement of dead mails, metrics and shutdown.

use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use davhaven_testkit::davhaven_app::outbox::OutboxDispatcher;
use davhaven_testkit::davhaven_domain::{
    CalendarUserAddress, EventPayload, EventType, ItipMethod, Locale, ObjectId, OutboxId, TenantId,
};
use davhaven_testkit::davhaven_ports::{
    Clock, HandlerError, ImipJob, OutboxMessage, OutboxStatus, PortError, Reserved, StoreError, TemplateName,
    WorkReport, Worker,
};
use tokio::sync::Barrier;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::support::{MetricsCapture, Scripted, World};

fn dispatcher(world: &World, handlers: &[Arc<Scripted>]) -> OutboxDispatcher {
    OutboxDispatcher::new(world.core.clone(), handlers.iter().map(Scripted::as_handler))
}

fn retryable(text: &str) -> Result<(), HandlerError> {
    Err(HandlerError::retryable(text))
}

fn report(processed: u32, failed: u32, more: bool) -> WorkReport {
    WorkReport {
        processed,
        failed,
        more,
    }
}

fn imip_job() -> OutboxMessage {
    OutboxMessage::Imip(ImipJob {
        object: ObjectId::from_uuid(Uuid::from_u128(0x0b)),
        recipient: CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
        method: ItipMethod::Request,
        locale: Some(Locale::de()),
        template: TemplateName::parse("imip_request").unwrap(),
        snapshot: None,
        replying_attendee: None,
        comment: None,
    })
}

#[tokio::test]
async fn the_first_handler_of_a_kind_wins_and_the_poll_interval_is_configured() {
    let world = World::with(|deps| deps.config.outbox.poll_interval = Duration::from_secs(7));
    let first = Scripted::new("provider_push");
    let second = Scripted::new("provider_push");
    let other = Scripted::new("webhook");
    let dispatcher = dispatcher(&world, &[first, second, other]);
    assert_eq!(dispatcher.kinds(), vec!["provider_push", "webhook"]);
    assert!(format!("{dispatcher:?}").contains("provider_push"));
    assert_eq!(dispatcher.name(), "outbox");
    assert_eq!(dispatcher.interval(), Duration::from_secs(7));
}

#[tokio::test]
async fn a_handled_record_is_done() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    assert_eq!(dispatcher.tick().await, report(1, 0, false));
    let record = world.record(id).await;
    assert_eq!((record.status, record.attempts), (OutboxStatus::Done, 1));
    assert_eq!(record.last_error, None);
    assert_eq!(handler.calls(), 1);

    assert!(dispatcher.tick().await.is_idle(), "a done record is not handled again");
    assert_eq!(handler.calls(), 1);
}

#[tokio::test]
async fn a_record_that_is_not_due_yet_waits() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let due = world.clock.now() + ChronoDuration::minutes(10);
    world
        .enqueue_at(World::tenant(), OutboxMessage::ProviderPush(Reserved::default()), due)
        .await;

    assert!(dispatcher.tick().await.is_idle());
    world.clock.set(due);
    assert_eq!(dispatcher.tick().await, report(1, 0, false));
    assert_eq!(handler.calls(), 1);
}

#[tokio::test]
async fn transient_failures_back_off_exponentially_up_to_the_cap() {
    let world = World::with(|deps| deps.config.outbox.max_attempts = 50);
    let handler = Scripted::new("provider_push");
    for _ in 0..10 {
        handler.then(retryable("relay unavailable"));
    }
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    let mut delays = Vec::new();
    for attempt in 1..=10 {
        let before = world.clock.now();
        assert_eq!(dispatcher.tick().await, report(0, 1, false));
        let record = world.record(id).await;
        assert_eq!((record.status, record.attempts), (OutboxStatus::Pending, attempt));
        assert_eq!(record.last_error.as_deref(), Some("relay unavailable"));
        delays.push((record.next_attempt_at - before).num_seconds());
        world.clock.set(record.next_attempt_at - ChronoDuration::seconds(1));
        assert!(dispatcher.tick().await.is_idle(), "not due one second early");
        world.clock.set(record.next_attempt_at);
    }
    assert_eq!(delays, vec![30, 60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
}

#[tokio::test]
async fn permanent_failures_are_dead_at_once() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    handler.then(Err(HandlerError::permanent("recipient refused")));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    assert_eq!(dispatcher.tick().await, report(0, 1, false));
    let record = world.record(id).await;
    assert_eq!((record.status, record.attempts), (OutboxStatus::Dead, 1));
    assert_eq!(record.last_error.as_deref(), Some("recipient refused"));

    world.clock.advance(ChronoDuration::days(2));
    assert!(dispatcher.tick().await.is_idle(), "a dead record waits for an operator");
    assert_eq!(handler.calls(), 1);
}

#[tokio::test]
async fn the_attempt_budget_ends_in_a_dead_letter() {
    let world = World::with(|deps| deps.config.outbox.max_attempts = 3);
    let handler = Scripted::new("provider_push");
    for _ in 0..5 {
        handler.then(retryable("boom"));
    }
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    for expected in [OutboxStatus::Pending, OutboxStatus::Pending, OutboxStatus::Dead] {
        dispatcher.tick().await;
        let record = world.record(id).await;
        assert_eq!(record.status, expected);
        world.clock.advance(ChronoDuration::hours(2));
    }
    let record = world.record(id).await;
    assert_eq!(record.attempts, 3);
    assert_eq!(record.last_error.as_deref(), Some("gave up after 3 attempts: boom"));
    assert_eq!(handler.calls(), 3);
}

#[tokio::test]
async fn handlers_that_bound_their_retries_by_time_are_not_cut_off_by_the_attempt_budget() {
    let world = World::with(|deps| deps.config.outbox.max_attempts = 2);
    let handler = Scripted::unlimited("provider_push");
    for _ in 0..5 {
        handler.then(retryable("still down"));
    }
    handler.then(Err(HandlerError::permanent("window passed")));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;
    for _ in 0..5 {
        dispatcher.tick().await;
        assert_eq!(world.record(id).await.status, OutboxStatus::Pending);
        world.clock.advance(ChronoDuration::hours(2));
    }
    assert_eq!(world.record(id).await.attempts, 5);
    dispatcher.tick().await;
    assert_eq!(
        world.record(id).await.status,
        OutboxStatus::Dead,
        "the handler can still end it"
    );
}

#[tokio::test]
async fn a_kind_without_a_handler_is_retried_and_finally_dead() {
    let world = World::with(|deps| deps.config.outbox.max_attempts = 2);
    let dispatcher = dispatcher(&world, &[]);
    let id = world.enqueue_dummy().await;

    dispatcher.tick().await;
    let record = world.record(id).await;
    assert_eq!(record.status, OutboxStatus::Pending);
    assert_eq!(
        record.last_error.as_deref(),
        Some("no handler is registered for the outbox kind `provider_push`")
    );
    world.clock.advance(ChronoDuration::minutes(5));
    dispatcher.tick().await;
    let record = world.record(id).await;
    assert_eq!(record.status, OutboxStatus::Dead);
    assert!(record.last_error.unwrap().starts_with("gave up after 2 attempts"));
}

#[tokio::test(start_paused = true)]
async fn a_hanging_handler_is_cut_off_before_its_lease_expires() {
    let world = World::new();
    let handler = Scripted::hanging("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    let started = tokio::time::Instant::now();
    assert_eq!(dispatcher.tick().await, report(0, 1, false));
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(48),
        "80 % of the one minute lease, counted from the claim"
    );
    let record = world.record(id).await;
    assert_eq!(record.status, OutboxStatus::Pending);
    assert_eq!(
        record.last_error.as_deref(),
        Some("the handler did not finish within its lease")
    );
}

#[tokio::test]
async fn a_panicking_handler_is_a_transient_failure() {
    let world = World::new();
    let handler = Scripted::panicking("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    assert_eq!(dispatcher.tick().await, report(0, 1, false));
    let record = world.record(id).await;
    assert_eq!(record.status, OutboxStatus::Pending);
    assert_eq!(record.last_error.as_deref(), Some("the handler panicked"));
}

#[tokio::test(start_paused = true)]
async fn handlers_run_concurrently() {
    let world = World::new();
    let handler = Scripted::meeting("provider_push", Arc::new(Barrier::new(3)));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    for _ in 0..3 {
        world.enqueue_dummy().await;
    }
    let report = tokio::time::timeout(Duration::from_secs(5), dispatcher.tick())
        .await
        .expect("three handlers wait for each other, so they must run at the same time");
    assert_eq!(report.processed, 3);
}

#[tokio::test(start_paused = true)]
async fn the_number_of_concurrent_handlers_is_configured() {
    let world = World::with(|deps| deps.config.outbox.concurrency = 2);
    let handler = Scripted::sleeping("provider_push", Duration::from_secs(10));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    for _ in 0..4 {
        world.enqueue_dummy().await;
    }
    let started = tokio::time::Instant::now();
    assert_eq!(dispatcher.tick().await, report(4, 0, false));
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(20),
        "four handlers of ten seconds in two slots take two rounds"
    );
}

#[tokio::test]
async fn a_full_batch_asks_for_another_pass() {
    let world = World::with(|deps| deps.config.outbox.batch_size = 2);
    let handler = Scripted::new("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    for _ in 0..3 {
        world.enqueue_dummy().await;
    }
    assert_eq!(dispatcher.tick().await, report(2, 0, true));
    assert_eq!(dispatcher.tick().await, report(1, 0, false));
    assert!(dispatcher.tick().await.is_idle());
}

#[tokio::test]
async fn a_record_whose_lease_expired_is_taken_over() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    // Another instance claims the record and dies before it settles it.
    let mut tx = world.core.deps().database.begin_system().await.unwrap();
    assert_eq!(
        tx.outbox_claim()
            .claim(10, Duration::from_secs(60))
            .await
            .unwrap()
            .len(),
        1
    );
    tx.commit().await.unwrap();

    assert!(dispatcher.tick().await.is_idle(), "the lease holds the record");
    world.clock.advance(ChronoDuration::seconds(61));
    assert_eq!(dispatcher.tick().await, report(1, 0, false));
    let record = world.record(id).await;
    assert_eq!((record.status, record.attempts), (OutboxStatus::Done, 2));
}

#[tokio::test]
async fn a_store_outage_leaves_the_records_alone() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    world.db.set_outage(true);
    assert!(dispatcher.tick().await.is_idle());
    world.db.set_outage(false);
    assert_eq!(world.record(id).await.status, OutboxStatus::Pending);
    assert_eq!(dispatcher.tick().await, report(1, 0, false));
}

// ---------------------------------------------------------------------------------------------------------------
// A second dispatcher, a lost lease, a failing settlement
// ---------------------------------------------------------------------------------------------------------------

/// Another dispatcher instance takes `record` over after the lease of the first one ran out, and completes it.
async fn reclaimed_and_completed_by_another_instance(world: &World) {
    world.clock.advance(ChronoDuration::seconds(61));
    let mut tx = world.core.deps().database.begin_system().await.unwrap();
    let reclaimed = tx.outbox_claim().claim(1, Duration::from_secs(60)).await.unwrap();
    assert_eq!(
        reclaimed.len(),
        1,
        "the other instance reclaims the oldest expired claim"
    );
    tx.outbox_claim().complete(reclaimed[0].key()).await.unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn one_lost_claim_does_not_keep_the_other_outcomes_of_the_batch_from_being_stored() {
    let metrics = MetricsCapture::default();
    let _installed = metrics::set_default_local_recorder(&metrics);
    let world = Arc::new(World::new());
    let acting = {
        let world = Arc::clone(&world);
        // The first record to be handled is taken over by "another instance" while this one still works on it.
        let once = Arc::new(std::sync::atomic::AtomicBool::new(false));
        Arc::new(move || -> futures::future::BoxFuture<'static, ()> {
            let world = Arc::clone(&world);
            let once = Arc::clone(&once);
            Box::pin(async move {
                if !once.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    reclaimed_and_completed_by_another_instance(&world).await;
                }
            })
        })
    };
    let handler = Scripted::acting("provider_push", acting);
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let first = world.enqueue_dummy().await;
    let second = world.enqueue_dummy().await;
    let third = world.enqueue_dummy().await;

    let report = dispatcher.tick().await;
    assert_eq!(report.processed, 3, "all three handlers succeeded");
    assert_eq!(handler.calls(), 3);
    for id in [first, second, third] {
        let record = world.record(id).await;
        assert_eq!(
            record.status,
            OutboxStatus::Done,
            "{id}: every outcome is stored, or was stored by the other"
        );
    }
    assert_eq!(
        world.record(first).await.attempts,
        2,
        "the other instance's claim is the second attempt of the first record"
    );
    assert_eq!(world.record(second).await.attempts, 1);
    assert_eq!(world.record(third).await.attempts, 1);
    assert_eq!(
        metrics.get("davhaven_outbox_settle_lost_total"),
        Some(1.0),
        "the lost claim is counted: {:?}",
        metrics.all()
    );
    assert!(dispatcher.tick().await.is_idle(), "nothing is handled a second time");
    assert_eq!(handler.calls(), 3);
}

#[tokio::test]
async fn a_lost_claim_of_a_deferred_record_is_dropped_too() {
    let world = Arc::new(World::new());
    let acting = {
        let world = Arc::clone(&world);
        Arc::new(move || -> futures::future::BoxFuture<'static, ()> {
            let world = Arc::clone(&world);
            Box::pin(async move { reclaimed_and_completed_by_another_instance(&world).await })
        })
    };
    let handler = Scripted::acting("provider_push", acting);
    handler.then(Err(HandlerError::defer(Duration::from_secs(30), "held")));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    let report = dispatcher.tick().await;
    assert_eq!(report, report_of(0, 0), "a deferral is neither a success nor a failure");
    let record = world.record(id).await;
    assert_eq!(
        (record.status, record.attempts),
        (OutboxStatus::Done, 2),
        "the other instance's outcome stands"
    );
}

fn report_of(processed: u32, failed: u32) -> WorkReport {
    report(processed, failed, false)
}

#[tokio::test]
async fn a_failing_settlement_leaves_the_records_to_their_leases() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    world.db.fail_next_settlement(StoreError::Unavailable);
    assert_eq!(
        dispatcher.tick().await,
        report(0, 1, false),
        "the batch could not be stored"
    );
    assert_eq!(
        world.record(id).await.status,
        OutboxStatus::InFlight,
        "the lease holds it"
    );
    assert!(dispatcher.tick().await.is_idle());

    world.clock.advance(ChronoDuration::seconds(61));
    assert_eq!(
        dispatcher.tick().await,
        report(1, 0, false),
        "handled again after the lease"
    );
    let record = world.record(id).await;
    assert_eq!((record.status, record.attempts), (OutboxStatus::Done, 2));
    assert_eq!(handler.calls(), 2, "at-least-once delivery");
}

// ---------------------------------------------------------------------------------------------------------------
// Dead mails are announced
// ---------------------------------------------------------------------------------------------------------------

/// The reasons of the `mail.delivery_failed` events that wait in the outbox, by dead record.
async fn announced(world: &World) -> Vec<(OutboxId, String)> {
    let mut found: Vec<(OutboxId, String)> = world
        .queued_events()
        .await
        .into_iter()
        .filter_map(|event| match event.data {
            EventPayload::MailFailure(payload) => Some((payload.outbox, payload.reason)),
            _ => None,
        })
        .collect();
    found.sort();
    found
}

#[tokio::test]
async fn a_dead_mail_tells_the_tenant() {
    let world = World::with(|deps| deps.config.outbox.max_attempts = 2);
    let handler = Scripted::new("imip");
    handler.then(Err(HandlerError::permanent("recipient refused")));
    handler.then(retryable("relay down"));
    handler.then(retryable("relay down"));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let tenant = World::tenant();

    let refused = world.enqueue(tenant, imip_job()).await;
    dispatcher.tick().await;
    let events = world.queued_events().await;
    assert_eq!(events.len(), 1);
    let event = events.first().unwrap();
    assert_eq!(event.event_type, EventType::MailDeliveryFailed);
    assert_eq!(event.tenant, tenant);
    let EventPayload::MailFailure(payload) = &event.data else {
        panic!("a mail failure payload, got {:?}", event.data);
    };
    assert_eq!(payload.outbox, refused);
    assert_eq!(payload.object, Some(ObjectId::from_uuid(Uuid::from_u128(0x0b))));
    assert_eq!(payload.method, Some(ItipMethod::Request));
    assert_eq!(payload.reason, "rejected");
    assert_eq!(world.record(refused).await.status, OutboxStatus::Dead);

    let exhausted = world.enqueue(tenant, imip_job()).await;
    for _ in 0..2 {
        dispatcher.tick().await;
        world.clock.advance(ChronoDuration::hours(1));
    }
    assert_eq!(world.record(exhausted).await.status, OutboxStatus::Dead);
    let mut expected = vec![(refused, "rejected".to_owned()), (exhausted, "exhausted".to_owned())];
    expected.sort();
    assert_eq!(announced(&world).await, expected);
}

#[tokio::test]
async fn announcing_a_death_twice_enqueues_it_once() {
    // The pass announces the dead mail, then its settlement fails (a crash at that point looks the same): the
    // record is handled again when its lease runs out, dies again, and finds its announcement.
    let world = World::new();
    let handler = Scripted::new("imip");
    handler.then(Err(HandlerError::permanent("recipient refused")));
    handler.then(Err(HandlerError::permanent("recipient refused")));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue(World::tenant(), imip_job()).await;

    world.db.fail_next_settlement(StoreError::Unavailable);
    dispatcher.tick().await;
    assert_eq!(world.record(id).await.status, OutboxStatus::InFlight);
    assert_eq!(announced(&world).await, vec![(id, "rejected".to_owned())]);

    world.clock.advance(ChronoDuration::seconds(61));
    dispatcher.tick().await;
    assert_eq!(world.record(id).await.status, OutboxStatus::Dead);
    assert_eq!(
        announced(&world).await,
        vec![(id, "rejected".to_owned())],
        "the death was announced once"
    );
}

#[tokio::test]
async fn a_mail_is_not_declared_dead_while_its_death_cannot_be_announced() {
    let world = World::new();
    let handler = Scripted::new("imip");
    handler.then(Err(HandlerError::permanent("recipient refused")));
    handler.then(Err(HandlerError::permanent("recipient refused")));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue(World::tenant(), imip_job()).await;

    // The store of the tenant cannot be reached for the announcement (the system queue works).
    world.db.set_tenant_outage(Some(World::tenant()));
    assert_eq!(dispatcher.tick().await, report(0, 1, false));
    let record = world.record(id).await;
    assert_eq!(record.status, OutboxStatus::Pending, "no dead record without its event");
    assert_eq!(
        record.last_error.as_deref(),
        Some("the failure of this mail could not be announced yet")
    );
    assert_eq!(announced(&world).await, Vec::new());

    world.db.set_tenant_outage(None);
    world.clock.advance(ChronoDuration::hours(1));
    assert_eq!(dispatcher.tick().await, report(0, 1, false));
    assert_eq!(world.record(id).await.status, OutboxStatus::Dead);
    assert_eq!(announced(&world).await, vec![(id, "rejected".to_owned())]);
}

#[tokio::test]
async fn other_dead_records_do_not_produce_mail_events() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    handler.then(Err(HandlerError::permanent("nope")));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    world.enqueue_dummy().await;
    dispatcher.tick().await;
    assert_eq!(world.queued_events().await, Vec::new());
}

// ---------------------------------------------------------------------------------------------------------------
// Deferrals
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_deferred_record_is_put_back_without_using_an_attempt() {
    let world = World::with(|deps| deps.config.outbox.max_attempts = 3);
    let handler = Scripted::new("provider_push");
    for _ in 0..100 {
        handler.then(Err(HandlerError::defer(
            Duration::from_secs(30),
            "the relay is held back",
        )));
    }
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;

    for held in 1..=100 {
        assert_eq!(dispatcher.tick().await, report(0, 0, false), "hold {held}");
        let record = world.record(id).await;
        assert_eq!(
            (record.status, record.attempts),
            (OutboxStatus::Pending, 0),
            "hold {held} left the record alive and uncounted"
        );
        assert_eq!(record.last_error.as_deref(), Some("the relay is held back"));
        assert_eq!(record.next_attempt_at, world.clock.now() + ChronoDuration::seconds(30));
        world.clock.set(record.next_attempt_at - ChronoDuration::seconds(1));
        assert!(dispatcher.tick().await.is_idle(), "not due one second early");
        world.clock.set(record.next_attempt_at);
    }
    assert_eq!(handler.calls(), 100);
    assert!(
        world.queued_events().await.is_empty(),
        "nothing went dead, so nobody was told"
    );

    // The hold ends: the record is handled and done, and only that attempt counts.
    assert_eq!(dispatcher.tick().await, report(1, 0, false));
    let record = world.record(id).await;
    assert_eq!((record.status, record.attempts), (OutboxStatus::Done, 1));
}

#[tokio::test]
async fn a_hold_is_never_shorter_than_a_second() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    handler.then(Err(HandlerError::defer(Duration::ZERO, "now")));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let id = world.enqueue_dummy().await;
    dispatcher.tick().await;
    assert_eq!(
        world.record(id).await.next_attempt_at,
        world.clock.now() + ChronoDuration::seconds(1)
    );
}

#[tokio::test]
async fn the_error_of_a_record_never_carries_driver_text_or_addresses() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    handler.then(Err(HandlerError::from(StoreError::internal(
        "password=hunter2 host=db.internal",
    ))));
    handler.then(Err(HandlerError::from(PortError::rejected(
        "550 5.1.1 <guest@example.net> user unknown",
    ))));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let first = world.enqueue_dummy().await;
    let second = world.enqueue_dummy().await;
    dispatcher.tick().await;

    let first = world.record(first).await;
    assert_eq!(first.last_error.as_deref(), Some("the store failed"));
    let second = world.record(second).await;
    assert_eq!(
        second.last_error.as_deref(),
        Some("an outbound service refused the request")
    );
    for record in [first, second] {
        let shown = record.last_error.unwrap();
        for secret in ["hunter2", "db.internal", "guest@example.net"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The lease and the deadline of a batch
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn the_deadline_counts_from_the_claim_for_every_record_of_a_batch() {
    // Ten handlers of 30 s: eight start at once, two wait for a free slot and would run to 60 s, which is past the
    // lease of a minute. The deadline of the claim (48 s) cuts them off instead.
    let world = World::new();
    let handler = Scripted::sleeping("provider_push", Duration::from_secs(30));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    for _ in 0..10 {
        world.enqueue_dummy().await;
    }
    assert_eq!(dispatcher.tick().await, report(8, 2, false));
    let records = world.outbox().await;
    assert_eq!(
        records
            .iter()
            .filter(|record| record.status == OutboxStatus::Done)
            .count(),
        8
    );
    let cut: Vec<_> = records
        .iter()
        .filter(|record| record.status == OutboxStatus::Pending)
        .collect();
    assert_eq!(cut.len(), 2);
    for record in cut {
        assert_eq!(
            record.last_error.as_deref(),
            Some("the handler did not finish within its lease"),
            "cut off at 48 s after the claim, not 48 s after its own start"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_record_whose_turn_comes_after_the_deadline_is_deferred_without_being_handled() {
    let world = World::new();
    let handler = Scripted::sleeping("provider_push", Duration::from_secs(50));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    for _ in 0..10 {
        world.enqueue_dummy().await;
    }
    assert_eq!(
        dispatcher.tick().await,
        report(0, 8, false),
        "the first wave runs into the deadline"
    );
    assert_eq!(handler.calls(), 8, "the other two were never started");
    let records = world.outbox().await;
    let untouched: Vec<_> = records.iter().filter(|record| record.attempts == 0).collect();
    assert_eq!(
        untouched.len(),
        2,
        "the claim of a record that was never handled is not an attempt"
    );
    for record in untouched {
        assert_eq!(record.status, OutboxStatus::Pending);
        assert_eq!(
            record.last_error.as_deref(),
            Some("the batch ran out of time before this record was handled")
        );
    }
}

#[tokio::test(start_paused = true)]
async fn no_handler_starts_after_the_lease_of_its_claim_ran_out_with_a_batch_larger_than_the_concurrency() {
    // Twenty-five records (the default batch), slow handlers (20 s each), eight at a time: the first wave ends at
    // 20 s, the second at 40 s; the third would start with 8 s left of the 48 s deadline and be cut off in the
    // middle of its work, so it is put back instead.
    let world = World::new();
    let handler = Scripted::sleeping("provider_push", Duration::from_secs(20));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    for _ in 0..25 {
        world.enqueue_dummy().await;
    }
    let started = tokio::time::Instant::now();
    let report = dispatcher.tick().await;
    assert!(
        started.elapsed() <= Duration::from_secs(48),
        "the pass is over before the lease: {:?}",
        started.elapsed()
    );
    assert_eq!(report.processed, 16, "two full waves are done");
    assert_eq!(handler.calls(), 16, "no handler was started for the rest");
    let records = world.outbox().await;
    assert_eq!(records.iter().filter(|r| r.status == OutboxStatus::Done).count(), 16);
    assert!(
        records
            .iter()
            .filter(|r| r.status != OutboxStatus::Done)
            .all(|r| r.status == OutboxStatus::Pending && r.attempts == 0),
        "the rest is pending with its attempts untouched, never in flight under an expired lease"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Metrics, shutdown, tenants
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_gauges_and_counters_follow_the_queue() {
    let metrics = MetricsCapture::default();
    let _installed = metrics::set_default_local_recorder(&metrics);
    let world = World::with(|deps| deps.config.outbox.batch_size = 2);
    let handler = Scripted::new("provider_push");
    handler.then(Ok(()));
    handler.then(Err(HandlerError::permanent("nope")));
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let now = world.clock.now();
    for age in [300, 200, 100, 50] {
        world
            .enqueue_at(
                World::tenant(),
                OutboxMessage::ProviderPush(Reserved::default()),
                now - ChronoDuration::seconds(age),
            )
            .await;
    }

    dispatcher.tick().await;
    let all = metrics.all();
    assert_eq!(metrics.get("davhaven_outbox_pending"), Some(2.0), "{all:?}");
    assert_eq!(metrics.get("davhaven_outbox_in_flight"), Some(2.0), "{all:?}");
    assert_eq!(
        metrics.get("davhaven_outbox_oldest_pending_age_seconds"),
        Some(100.0),
        "the oldest record that still waits was due 100 s ago: {all:?}"
    );
    assert_eq!(
        metrics.get("davhaven_outbox_handled_total{kind=provider_push,outcome=done}"),
        Some(1.0),
        "{all:?}"
    );
    assert_eq!(
        metrics.get("davhaven_outbox_handled_total{kind=provider_push,outcome=dead}"),
        Some(1.0),
        "{all:?}"
    );
    assert_eq!(
        metrics.get("davhaven_outbox_dead_total{kind=provider_push}"),
        Some(1.0),
        "{all:?}"
    );
    assert_eq!(
        metrics.get("davhaven_outbox_handle_duration_seconds{kind=provider_push}"),
        Some(2.0),
        "one sample per handled record: {all:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn run_polls_until_cancelled_and_drains_a_short_handler() {
    let world = World::new();
    let handler = Scripted::sleeping("provider_push", Duration::from_secs(2));
    let dispatcher = Arc::new(dispatcher(&world, &[Arc::clone(&handler)]));
    let id = world.enqueue_dummy().await;
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let dispatcher = Arc::clone(&dispatcher);
        let cancel = cancel.clone();
        async move { dispatcher.run(cancel).await }
    });

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        world.record(id).await.status,
        OutboxStatus::InFlight,
        "the handler is working"
    );
    cancel.cancel();
    task.await.unwrap();
    let record = world.record(id).await;
    assert_eq!(
        (record.status, record.attempts),
        (OutboxStatus::Done, 1),
        "the pass in flight finished"
    );
    assert_eq!(dispatcher.release_held().await, 0);
}

#[tokio::test(start_paused = true)]
async fn a_shutdown_hands_unfinished_claims_back_without_using_an_attempt() {
    let world = World::new();
    let handler = Scripted::hanging("provider_push");
    let dispatcher = Arc::new(dispatcher(&world, &[Arc::clone(&handler)]));
    let id = world.enqueue_dummy().await;
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let dispatcher = Arc::clone(&dispatcher);
        let cancel = cancel.clone();
        async move { dispatcher.run(cancel).await }
    });

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(handler.calls(), 1);
    assert_eq!(world.record(id).await.status, OutboxStatus::InFlight);
    cancel.cancel();
    task.await.unwrap();

    let record = world.record(id).await;
    assert_eq!((record.status, record.attempts), (OutboxStatus::Pending, 0));
    assert_eq!(
        record.next_attempt_at,
        world.clock.now(),
        "due immediately on the next start"
    );
}

#[tokio::test(start_paused = true)]
async fn run_returns_at_once_when_cancelled_before_it_starts() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    world.enqueue_dummy().await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    dispatcher.run(cancel).await;
    assert_eq!(handler.calls(), 0);
}

#[tokio::test]
async fn records_of_every_tenant_are_dispatched() {
    let world = World::new();
    let handler = Scripted::new("provider_push");
    let dispatcher = dispatcher(&world, &[Arc::clone(&handler)]);
    let tenants: Vec<TenantId> = (1..=3_u128).map(|n| TenantId::from_uuid(Uuid::from_u128(n))).collect();
    for tenant in &tenants {
        world
            .enqueue(*tenant, OutboxMessage::ProviderPush(Reserved::default()))
            .await;
    }
    assert_eq!(dispatcher.tick().await, report(3, 0, false));
    for tenant in tenants {
        let records = world.outbox_of(tenant).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, OutboxStatus::Done, "{tenant}");
    }
}
