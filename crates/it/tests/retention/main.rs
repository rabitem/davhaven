//! The retention worker and the application's worker set on the in-memory store (PLAN 2.18).
//!
//! The tests run the real [`RetentionWorker`] over `store-memory`, the store the contract suite checks, with a manual
//! clock: data is created, time moves past the cut-offs of `[retention]`, one pass runs and the tests look at what
//! is left. The ports the worker does not touch are inert doubles.
//!
//! A [`Spy`](spy::Spy) around the store records the cut-off that each cleanup call received. That is what keeps a
//! step from receiving the period of another one (the inbox purge with the one-day period of OAuth states would
//! delete data a month early), and it plays the roles of a deployment: a connection that may not purge the audit log,
//! a store without the delivery purge, a backlog that is longer than one pass.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

mod spy;
mod support;

use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use davhaven_testkit::davhaven_app::config::RetentionConfig;
use davhaven_testkit::davhaven_app::retention::{RetentionWorker, SWEEP_INTERVAL};
use davhaven_testkit::davhaven_app::workers;
use davhaven_testkit::davhaven_domain::{CalendarKind, CollectionKey, CollectionKind, OutboxId};
use davhaven_testkit::davhaven_ports::{Clock, Database, OutboxStatus, StoreError, Worker};
use spy::{Call, Spy};
use support::{GaugeCapture, World};

/// A world whose store is watched by a [`Spy`].
fn watched(adjust: impl FnOnce(&mut davhaven_testkit::davhaven_app::AppDeps)) -> (World, Arc<Spy>) {
    let mut spy = None;
    let world = World::with(|deps| {
        adjust(deps);
        let watching = Spy::wrapping(Arc::clone(&deps.database));
        let database: Arc<dyn Database> = Arc::<Spy>::clone(&watching);
        deps.database = database;
        spy = Some(watching);
    });
    (world, spy.unwrap())
}

#[tokio::test]
async fn outbox_records_are_kept_for_their_retention_period_and_then_removed() {
    let world = World::new();
    let tenant = world.tenant().await;
    let done = world.settled(tenant, false).await;
    let dead = world.settled(tenant, true).await;
    let worker = RetentionWorker::new(world.core.clone());

    // Nothing is old enough on the first day.
    world.advance_days(1);
    assert_eq!(worker.sweep().await.total(), 0);
    assert!(world.outbox_ids(tenant, OutboxStatus::Done).await.contains(&done));

    // A done record is removed after 7 days, a dead one is kept for 30.
    world.advance_days(7);
    let sweep = worker.sweep().await;
    assert_eq!(sweep.removed.get("outbox"), Some(&1), "{sweep:?}");
    assert_eq!(sweep.failed, Vec::<&str>::new(), "{sweep:?}");
    assert_eq!(
        world.outbox_ids(tenant, OutboxStatus::Done).await,
        Vec::<OutboxId>::new()
    );
    assert_eq!(world.outbox_ids(tenant, OutboxStatus::Dead).await, vec![dead]);

    world.advance_days(21);
    assert_eq!(
        worker.sweep().await.removed.get("outbox"),
        None,
        "29 days after the failure: still there"
    );
    world.advance_days(2);
    assert_eq!(worker.sweep().await.removed.get("outbox"), Some(&1));
    assert_eq!(
        world.outbox_ids(tenant, OutboxStatus::Dead).await,
        Vec::<OutboxId>::new()
    );
}

#[tokio::test]
async fn a_pass_cleans_every_tenant() {
    let world = World::new();
    let first = world.tenant().await;
    let second = world.tenant().await;
    world.settled(first, false).await;
    world.settled(second, false).await;
    world.advance_days(8);
    let sweep = RetentionWorker::new(world.core.clone()).sweep().await;
    assert_eq!(sweep.removed.get("outbox"), Some(&2), "{sweep:?}");
    for tenant in [first, second] {
        assert_eq!(
            world.outbox_ids(tenant, OutboxStatus::Done).await,
            Vec::<OutboxId>::new()
        );
    }
}

#[tokio::test]
async fn pending_records_are_never_removed_however_old() {
    let world = World::new();
    let tenant = world.tenant().await;
    let waiting = world.enqueue(tenant).await;
    world.advance_days(400);
    let sweep = RetentionWorker::new(world.core.clone()).sweep().await;
    assert_eq!(sweep.total(), 0, "{sweep:?}");
    assert_eq!(world.outbox_ids(tenant, OutboxStatus::Pending).await, vec![waiting]);
}

#[tokio::test]
async fn deleted_calendars_and_principals_are_purged_after_their_period() {
    let world = World::new();
    let tenant = world.tenant().await;
    let owner = world.principal(tenant, "olivia").await;
    let calendar = world.calendar(tenant, owner.id, CalendarKind::User).await;
    let kept = world.calendar(tenant, owner.id, CalendarKind::User).await;
    world.delete_calendar(tenant, calendar.id).await;
    let leaving = world.principal(tenant, "leaving").await;
    let leaving_calendar = world.calendar(tenant, leaving.id, CalendarKind::Personal).await;
    world.delete_principal(tenant, leaving.id).await;
    let worker = RetentionWorker::new(world.core.clone());
    let (principals, calendars) = world.awaiting_purge().await;
    assert_eq!(principals, vec![(tenant, leaving.id)]);
    assert_eq!(calendars, vec![(tenant, calendar.id)]);

    world.advance_days(29);
    assert_eq!(
        worker.sweep().await.total(),
        0,
        "deleted 29 days ago: still recoverable"
    );
    assert_eq!(world.awaiting_purge().await.1, vec![(tenant, calendar.id)]);

    world.advance_days(2);
    let sweep = worker.sweep().await;
    assert_eq!(sweep.removed.get("calendars"), Some(&1), "{sweep:?}");
    assert_eq!(sweep.removed.get("principals"), Some(&1), "{sweep:?}");
    let (principals, calendars) = world.awaiting_purge().await;
    assert_eq!(
        (principals, calendars),
        (Vec::new(), Vec::new()),
        "everything due is gone"
    );
    assert!(world.calendar_exists(tenant, kept.id).await, "a live calendar stays");
    assert!(
        !world.calendar_exists(tenant, leaving_calendar.id).await,
        "the calendars of a purged principal go with it"
    );
    assert_eq!(
        world.audit_actions(tenant).await,
        vec!["principal.purged".to_owned()],
        "the purge of a principal is audited in its own transaction"
    );

    // Running again finds nothing and does not fail.
    let again = worker.sweep().await;
    assert_eq!(again.total(), 0, "{again:?}");
    assert_eq!(again.failed, Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_step_is_reported_and_the_next_pass_tries_again() {
    let world = World::new();
    let tenant = world.tenant().await;
    world.settled(tenant, false).await;
    world.advance_days(8);
    // The first system transaction of the pass (the outbox step) cannot begin; the later steps can.
    world.db.fail_next_system_begins(1);
    let worker = RetentionWorker::new(world.core.clone());
    let failed = worker.sweep().await;
    assert_eq!(failed.failed, vec!["outbox"], "{failed:?}");
    assert_eq!(
        world.outbox_ids(tenant, OutboxStatus::Done).await.len(),
        1,
        "nothing was removed"
    );
    let report = worker.tick().await;
    assert_eq!((report.processed, report.failed), (1, 0), "the next pass succeeds");
    assert_eq!(
        world.outbox_ids(tenant, OutboxStatus::Done).await,
        Vec::<OutboxId>::new()
    );
}

#[tokio::test]
async fn an_unavailable_store_fails_the_pass_without_panicking() {
    let world = World::new();
    let tenant = world.tenant().await;
    world.settled(tenant, false).await;
    world.advance_days(8);
    world.db.set_outage(true);
    let worker = RetentionWorker::new(world.core.clone());
    let report = worker.tick().await;
    assert!(report.failed > 0, "{report:?}");
    assert_eq!(report.processed, 0);
    world.db.set_outage(false);
    let recovered = worker.tick().await;
    assert_eq!((recovered.processed, recovered.failed), (1, 0));
}

#[tokio::test]
async fn the_periods_come_from_the_configuration() {
    let world = World::with(|deps| {
        deps.config.retention = RetentionConfig {
            outbox_done_days: 1,
            ..RetentionConfig::default()
        };
    });
    let tenant = world.tenant().await;
    world.settled(tenant, false).await;
    world.advance_days(2);
    let sweep = RetentionWorker::new(world.core.clone()).sweep().await;
    assert_eq!(sweep.removed.get("outbox"), Some(&1), "{sweep:?}");
}

#[tokio::test]
async fn the_application_registers_the_dispatcher_and_the_retention_worker() {
    let world = World::new();
    let worker = RetentionWorker::new(world.core.clone());
    assert_eq!(worker.name(), "retention");
    assert_eq!(worker.interval(), SWEEP_INTERVAL);
    assert!(
        worker.interval() >= Duration::from_mins(1),
        "cleanup is not a busy loop"
    );

    let app = workers::build(&world.core);
    let names: Vec<&str> = app.workers.iter().map(|worker| worker.name()).collect();
    assert_eq!(names, vec!["outbox", "retention"]);
    assert_eq!(app.lifecycles.len(), 1, "the outbox hands its leases back at the end");
    // An idle dispatcher holds no lease; the hook runs and finds nothing to hand back.
    app.lifecycles[0].shutdown().await;
}

#[tokio::test]
async fn every_step_receives_the_cutoff_of_its_own_period() {
    // Every period differs, so a step that is given the cut-off of another one shows.
    let (world, spy) = watched(|deps| {
        deps.config.retention = RetentionConfig {
            outbox_done_days: 2,
            outbox_dead_days: 3,
            collection_changes_days: 4,
            audit_days: 5,
            scheduling_inbox_days: 6,
            deleted_calendar_days: 7,
            principal_purge_days: 8,
            idempotency_hours: 9,
            oauth_state_days: 10,
            rsvp_token_days: 11,
            webhook_delivery_days: 12,
        };
    });
    world.advance_days(400);
    let now = world.clock.now();
    let ago = |days: i64| now - ChronoDuration::days(days);

    RetentionWorker::new(world.core.clone()).sweep().await;

    assert_eq!(
        spy.calls().await,
        vec![
            Call::Outbox {
                done_before: ago(2),
                dead_before: ago(3)
            },
            Call::Deliveries(ago(12)),
            Call::Changes(ago(4)),
            Call::Audit(ago(5)),
            Call::Inbox(ago(6)),
            Call::Idempotency,
            Call::OAuthStates(ago(10)),
            Call::RsvpTokens(ago(11)),
            Call::Principals(ago(8)),
            Call::Calendars(ago(7)),
        ],
        "one call per step, in the order of the pass, each with the cut-off of its period"
    );
}

#[tokio::test]
async fn the_defaults_are_the_retention_table_of_the_plan() {
    let (world, spy) = watched(|_| {});
    world.advance_days(1000);
    let now = world.clock.now();
    let ago = |days: i64| now - ChronoDuration::days(days);
    RetentionWorker::new(world.core.clone()).sweep().await;
    // Outbox done 7 d, dead 30 d; change log 90 d; audit 365 d; inbox 30 d; OAuth states 1 d; RSVP tokens and webhook
    // deliveries 30 d; principals and calendars 30 d (PLAN 2.18).
    assert_eq!(
        spy.calls().await,
        vec![
            Call::Outbox {
                done_before: ago(7),
                dead_before: ago(30)
            },
            Call::Deliveries(ago(30)),
            Call::Changes(ago(90)),
            Call::Audit(ago(365)),
            Call::Inbox(ago(30)),
            Call::Idempotency,
            Call::OAuthStates(ago(1)),
            Call::RsvpTokens(ago(30)),
            Call::Principals(ago(30)),
            Call::Calendars(ago(30)),
        ]
    );
}

#[tokio::test]
async fn audit_events_are_kept_for_a_year_and_then_removed() {
    let world = World::new();
    let tenant = world.tenant().await;
    world.audit(tenant).await;
    let worker = RetentionWorker::new(world.core.clone());

    world.advance_days(364);
    let sweep = worker.sweep().await;
    assert_eq!(sweep.removed.get("audit_events"), None, "{sweep:?}");
    assert_eq!(
        world.audit_actions(tenant).await.len(),
        1,
        "the day before the period ends it is kept"
    );

    world.advance_days(2);
    let sweep = worker.sweep().await;
    assert_eq!(sweep.removed.get("audit_events"), Some(&1), "{sweep:?}");
    assert_eq!(world.audit_actions(tenant).await, Vec::<String>::new());
    assert_eq!(
        sweep.skipped,
        Vec::<&str>::new(),
        "this connection may purge the audit log"
    );
}

#[tokio::test]
async fn pruning_the_change_log_raises_the_minimum_sequence_so_old_sync_tokens_are_refused() {
    let world = World::new();
    let tenant = world.tenant().await;
    let owner = world.principal(tenant, "olivia").await;
    let calendar = world.calendar(tenant, owner.id, CalendarKind::User).await;
    let key = CollectionKey {
        kind: CollectionKind::Calendar,
        id: calendar.id.as_uuid(),
    };
    let (epoch, seq) = world.put_object(tenant, calendar.id).await;
    let worker = RetentionWorker::new(world.core.clone());

    world.advance_days(89);
    assert_eq!(
        worker.sweep().await.removed.get("collection_changes"),
        None,
        "89 days: kept"
    );
    assert!(
        world.since(tenant, key, epoch, 0).await.is_ok(),
        "a client that synced before the first change may still ask for everything"
    );

    world.advance_days(2);
    let sweep = worker.sweep().await;
    assert!(
        sweep
            .removed
            .get("collection_changes")
            .is_some_and(|removed| *removed >= 1),
        "{sweep:?}"
    );
    assert!(
        matches!(
            world.since(tenant, key, epoch, 0).await,
            Err(StoreError::InvalidSyncToken)
        ),
        "the history this token needs is gone, so the token is refused"
    );
    assert!(
        world.since(tenant, key, epoch, seq).await.is_ok(),
        "a token at the current sequence needs no pruned history"
    );
}

#[tokio::test]
async fn a_connection_that_may_not_purge_the_audit_log_skips_the_step_and_stays_healthy() {
    let (world, spy) = watched(|_| {});
    let tenant = world.tenant().await;
    world.audit(tenant).await;
    world.advance_days(400);
    spy.audit_permitted(false);
    spy.deliveries_supported(false);
    let worker = RetentionWorker::new(world.core.clone());

    let sweep = worker.sweep().await;
    assert_eq!(sweep.skipped, vec!["webhook_deliveries", "audit_events"], "{sweep:?}");
    assert_eq!(
        sweep.failed,
        Vec::<&str>::new(),
        "a state of the deployment is no failure: {sweep:?}"
    );
    assert_eq!(
        world.audit_actions(tenant).await.len(),
        1,
        "nothing was removed from the audit log"
    );

    let report = worker.tick().await;
    assert_eq!(report.failed, 0, "the heartbeat of the worker stays healthy");
    assert!(!report.more);
}

#[tokio::test]
async fn a_backlog_longer_than_one_pass_reports_more_work_and_the_next_pass_finishes_it() {
    let (world, spy) = watched(|_| {});
    world.advance_days(31);
    spy.endless_inbox(true);
    let worker = RetentionWorker::new(world.core.clone());

    let first = worker.tick().await;
    assert!(first.more, "the step stopped at the round limit with rows left");
    assert_eq!(
        first.processed,
        davhaven_testkit::davhaven_app::retention::MAX_ROUNDS,
        "one row per round, up to the round limit"
    );
    let rounds = spy
        .calls()
        .await
        .iter()
        .filter(|call| matches!(call, Call::Inbox(_)))
        .count();
    assert_eq!(
        rounds,
        usize::try_from(davhaven_testkit::davhaven_app::retention::MAX_ROUNDS).unwrap(),
        "the step is repeated while it keeps removing rows, at most MAX_ROUNDS times"
    );

    spy.endless_inbox(false);
    let second = worker.tick().await;
    assert!(
        !second.more,
        "the backlog is gone: the worker waits for its interval again"
    );
    assert_eq!(second.failed, 0);
}

// ---------------------------------------------------------------------------------------------------------------
// The audit gauges: the alert that the purge job (which runs outside the server) stopped
// ---------------------------------------------------------------------------------------------------------------

/// The gauge of when the oldest audit event of all tenants occurred.
const OLDEST_AUDIT: &str = "davhaven_audit_oldest_event_timestamp_seconds";

/// The gauge of the configured audit retention in seconds.
const AUDIT_RETENTION: &str = "davhaven_audit_retention_seconds";

/// The unix seconds of `time` as the gauge states them.
fn seconds(time: chrono::DateTime<chrono::Utc>) -> f64 {
    f64::from(u32::try_from(time.timestamp()).unwrap())
}

#[tokio::test]
async fn the_audit_gauges_follow_the_log_and_say_nothing_where_there_is_no_event() {
    let gauges = GaugeCapture::default();
    let _installed = metrics::set_default_local_recorder(&gauges);
    let world = World::with(|deps| deps.config.retention.audit_days = 5);
    let tenant = world.tenant().await;
    let worker = RetentionWorker::new(world.core.clone());

    // No audit event: the retention is published and the oldest event is not. The series is absent, not zero: an alert on the
    // age of the oldest event must not read "an event from 1970".
    worker.sweep().await;
    assert_eq!(gauges.get(AUDIT_RETENTION), Some(5.0 * 86_400.0));
    assert_eq!(
        gauges.get(OLDEST_AUDIT),
        None,
        "a log without events has no oldest event"
    );

    // An event arrives. The lookup is every fifteen minutes, so the pass at once does not see it ...
    let first = world.clock.now();
    world.audit(tenant).await;
    worker.sweep().await;
    assert_eq!(
        gauges.get(OLDEST_AUDIT),
        None,
        "the last lookup is not fifteen minutes old"
    );
    // ... and the pass after them does.
    world.clock.advance(ChronoDuration::minutes(15));
    worker.sweep().await;
    assert_eq!(gauges.get(OLDEST_AUDIT), Some(seconds(first)));

    // A newer event does not move it: the oldest of all tenants and all events is what counts.
    world.advance_days(3);
    let second = world.clock.now();
    world.audit(world.tenant().await).await;
    worker.sweep().await;
    assert_eq!(gauges.get(OLDEST_AUDIT), Some(seconds(first)));

    // The purge job runs (here: the worker, because the in-memory store lets it) and the gauge moves to the next event.
    world.advance_days(3);
    let sweep = worker.sweep().await;
    assert_eq!(sweep.removed.get("audit_events"), Some(&1), "{sweep:?}");
    assert_eq!(
        gauges.get(OLDEST_AUDIT),
        Some(seconds(second)),
        "the first event is gone (it was six days old, the period is five), the second is the oldest now"
    );
    assert_eq!(gauges.get(AUDIT_RETENTION), Some(5.0 * 86_400.0));

    // The log is emptied while the server runs. A gauge cannot be taken back, and the last value would grow stale until the
    // alert fires for a log that holds nothing: it reads NaN, which no comparison matches.
    world.advance_days(10);
    worker.sweep().await;
    assert!(
        gauges.get(OLDEST_AUDIT).is_some_and(f64::is_nan),
        "{:?}",
        gauges.get(OLDEST_AUDIT)
    );
}

#[tokio::test]
async fn the_retention_gauge_follows_the_configuration() {
    let gauges = GaugeCapture::default();
    let _installed = metrics::set_default_local_recorder(&gauges);
    for (days, expected) in [(365, 31_536_000.0), (1, 86_400.0), (3650, 315_360_000.0)] {
        let world = World::with(|deps| deps.config.retention.audit_days = days);
        RetentionWorker::new(world.core.clone()).sweep().await;
        assert_eq!(gauges.get(AUDIT_RETENTION), Some(expected), "{days} days");
    }
}

#[tokio::test]
async fn the_oldest_audit_event_is_looked_up_every_fifteen_minutes_and_not_at_every_pass() {
    let (world, spy) = watched(|_| {});
    let worker = RetentionWorker::new(world.core.clone());
    let pass = ChronoDuration::from_std(SWEEP_INTERVAL).unwrap();
    // Passes at 0, 5, 10, 15, 20, 25 and 30 minutes: the lookups are those at 0, 15 and 30.
    for _ in 0..7 {
        worker.sweep().await;
        world.clock.advance(pass);
    }
    assert_eq!(spy.oldest_audit_lookups(), 3);
    assert_eq!(
        davhaven_testkit::davhaven_app::retention::AUDIT_LOOKUP_INTERVAL,
        Duration::from_mins(15)
    );
}

#[tokio::test]
async fn a_clock_that_stepped_back_a_little_does_not_put_the_lookup_off_by_a_whole_pass() {
    // The passes are five minutes apart by a clock that does not jump and the interval is measured by the wall clock, which does:
    // five seconds of tolerance keep a step of a second back from making the third pass after a lookup look a second too early.
    let (world, spy) = watched(|_| {});
    let worker = RetentionWorker::new(world.core.clone());
    worker.sweep().await;
    assert_eq!(spy.oldest_audit_lookups(), 1);
    world
        .clock
        .advance(ChronoDuration::minutes(14) + ChronoDuration::seconds(54));
    worker.sweep().await;
    assert_eq!(
        spy.oldest_audit_lookups(),
        1,
        "14 minutes and 54 seconds: more than the tolerance short of the interval"
    );
    world.clock.advance(ChronoDuration::seconds(1));
    worker.sweep().await;
    assert_eq!(
        spy.oldest_audit_lookups(),
        2,
        "14 minutes and 55 seconds: within the tolerance"
    );
}

#[tokio::test]
async fn a_store_that_cannot_tell_leaves_the_gauge_absent_and_a_failed_lookup_is_tried_at_the_next_pass() {
    let gauges = GaugeCapture::default();
    let _installed = metrics::set_default_local_recorder(&gauges);
    let (world, spy) = watched(|_| {});
    let tenant = world.tenant().await;
    let first = world.clock.now();
    world.audit(tenant).await;
    let worker = RetentionWorker::new(world.core.clone());

    // A store without the lookup: the step is skipped, nothing fails, the gauge stays absent, and the store is not asked again
    // before the next interval.
    spy.oldest_audit_supported(false);
    let sweep = worker.sweep().await;
    assert_eq!(sweep.skipped, vec!["audit_oldest_event"], "{sweep:?}");
    assert_eq!(sweep.failed, Vec::<&str>::new(), "{sweep:?}");
    assert_eq!(gauges.get(OLDEST_AUDIT), None);
    assert!(
        gauges.get(AUDIT_RETENTION).is_some(),
        "the retention is a setting and is published anyway"
    );
    worker.sweep().await;
    assert_eq!(spy.oldest_audit_lookups(), 1);

    // A lookup that fails is a failed step (the pass reports it and the counter counts it) and is tried again at the next pass,
    // not after another fifteen minutes.
    spy.oldest_audit_supported(true);
    spy.oldest_audit_fails(true);
    world.clock.advance(ChronoDuration::minutes(15));
    let sweep = worker.sweep().await;
    assert_eq!(sweep.failed, vec!["audit_oldest_event"], "{sweep:?}");
    assert_eq!(worker.tick().await.failed, 1, "the heartbeat of the pass knows it");
    assert_eq!(gauges.get(OLDEST_AUDIT), None);

    spy.oldest_audit_fails(false);
    world.clock.advance(ChronoDuration::minutes(5));
    let sweep = worker.sweep().await;
    assert_eq!(sweep.failed, Vec::<&str>::new(), "{sweep:?}");
    assert_eq!(gauges.get(OLDEST_AUDIT), Some(seconds(first)));

    // A failure after that leaves the value as it was: a little old is better than none.
    spy.oldest_audit_fails(true);
    world.clock.advance(ChronoDuration::minutes(15));
    worker.sweep().await;
    assert_eq!(gauges.get(OLDEST_AUDIT), Some(seconds(first)));
}
