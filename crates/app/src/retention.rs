//! Retention and cleanup of expired data (PLAN 2.18).
//!
//! [`RetentionWorker`] is the cleanup worker. Every pass computes the cut-offs of the `[retention]` table from the
//! clock and removes what is older, one system transaction per call so that no transaction holds locks for long:
//!
//! | What | Cut-off | Notes |
//! | --- | --- | --- |
//! | Outbox records | `outbox_done_days` (done), `outbox_dead_days` (dead) | |
//! | Webhook delivery records | `webhook_delivery_days` | the status of each attempt to deliver an event to a subscription |
//! | Change log | `collection_changes_days` | raises `sync_min_seq`; older sync tokens answer `valid-sync-token` |
//! | Audit events | `audit_days` | see below |
//! | Scheduling inbox | `scheduling_inbox_days` | |
//! | Idempotency keys | their own expiry | `idempotency_hours` is applied when a key is stored |
//! | OAuth states | `oauth_state_days` | |
//! | RSVP tokens | `rsvp_token_days` after they expired or were revoked | |
//! | Deleted principals | `principal_purge_days` | purged in the tenant's transaction, with the audit record |
//! | Deleted calendars | `deleted_calendar_days` | purged in the tenant's transaction |
//!
//! **Audit retention may be somebody else's job.** The runtime role of the PostgreSQL adapter cannot delete audit
//! records (`docs/operations/database.md`): the purge function belongs to the owner role, which runs it with
//! `davhaven admin purge-audit`. For such a role the store answers [`AuditPurge::NotPermitted`]; the worker skips
//! the step, which is a state of the deployment and not a failure, so the heartbeat stays healthy and the other
//! cleanups are unaffected.
//!
//! **Nothing else notices when that job stops**, so a pass also publishes two gauges that an alert can use:
//! [`AUDIT_OLDEST_EVENT_TIMESTAMP_SECONDS`] (when the oldest audit event of all tenants occurred, looked up every
//! [`AUDIT_LOOKUP_INTERVAL`] with one indexed query in a system transaction) and [`AUDIT_RETENTION_SECONDS`] (the configured
//! `audit_days`). An event that is older than the retention period by more than the interval of the job means that the job did not run.
//!
//! A step that fails is logged and counted in the report; the other steps still run, and the next pass tries
//! again. Every step works in batches the store chooses, so a pass repeats a step while it keeps removing rows,
//! up to [`MAX_ROUNDS`] times, and reports `more` when it stopped before the backlog was gone.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::audit::PrincipalAudit;
use davhaven_domain::{AuditActor, AuditEvent, CalendarId, PrincipalId, TenantId};
use davhaven_ports::{AuditPurge, NewAudit, StoreError, TxMode, WorkReport, Worker};
use uuid::Uuid;

use crate::config::RetentionConfig;
use crate::wiring::AppCore;

/// The time between two passes of the cleanup worker.
pub const SWEEP_INTERVAL: Duration = Duration::from_mins(5);

/// How many times a pass repeats one step while it keeps removing rows. A pass that stops here reports more work.
pub const MAX_ROUNDS: u32 = 20;

/// How many deleted principals or calendars one round purges. Each is purged in its own transaction.
pub const PURGE_BATCH: u32 = 50;

/// The counter of removed rows, labelled with the step.
pub const REMOVED_TOTAL: &str = "davhaven_retention_removed_total";

/// The counter of steps that failed, labelled with the step.
pub const FAILED_TOTAL: &str = "davhaven_retention_failed_total";

/// The gauge of when the oldest audit event of all tenants occurred, in seconds since the epoch.
///
/// The server never deletes audit events: the owner job `davhaven admin purge-audit` does, and nothing else tells an operator
/// that it stopped running. An event that is much older than the retention period says so (the alert expression is in
/// `docs/operations/runbook.md`). The gauge is absent while the log holds no event, and reads `NaN`, which no comparison
/// matches, when the log is emptied while the server runs (a gauge cannot be taken back, and its last value would be stale).
pub const AUDIT_OLDEST_EVENT_TIMESTAMP_SECONDS: &str = "davhaven_audit_oldest_event_timestamp_seconds";

/// The gauge of the configured `retention.audit_days` in seconds: what the age of the oldest audit event is compared with.
pub const AUDIT_RETENTION_SECONDS: &str = "davhaven_audit_retention_seconds";

/// How often a pass looks up the oldest audit event, by the clock of the application. The passes come every
/// [`SWEEP_INTERVAL`]; the lookup is one indexed query, but there is no reason to ask more often than an alert can use.
pub const AUDIT_LOOKUP_INTERVAL: Duration = Duration::from_mins(15);

/// How much earlier than [`AUDIT_LOOKUP_INTERVAL`] a lookup may come. The passes are [`SWEEP_INTERVAL`] apart by a clock that does
/// not jump, and the interval is measured by the wall clock, which does: a step of a second back would make the third pass
/// after a lookup look 14 minutes and 59 seconds late and put the lookup off by a whole pass. A few seconds of tolerance keep
/// that from adding five minutes to the delay.
const AUDIT_LOOKUP_TOLERANCE: Duration = Duration::from_secs(5);

/// The name of the lookup of the oldest audit event among the steps of a pass (`davhaven_retention_failed_total`, the report
/// of a pass).
const AUDIT_OLDEST_STEP: &str = "audit_oldest_event";

/// Seconds in a day, as a gauge value.
const SECONDS_PER_DAY: f64 = 86_400.0;

/// The unix seconds of `time` as a gauge value: exact for every time before the year 2106, saturating beyond (see
/// `gauge_value` of the outbox dispatcher for the same rule).
fn unix_seconds(time: DateTime<Utc>) -> f64 {
    f64::from(u32::try_from(time.timestamp().max(0)).unwrap_or(u32::MAX))
}

/// The moments before which data is removed, computed from the `[retention]` table and the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cutoffs {
    /// Done outbox records changed before this are removed.
    pub outbox_done: DateTime<Utc>,
    /// Dead outbox records changed before this are removed.
    pub outbox_dead: DateTime<Utc>,
    /// Webhook delivery records created before this are removed.
    pub deliveries: DateTime<Utc>,
    /// Change-log rows older than this are removed.
    pub changes: DateTime<Utc>,
    /// Audit events older than this are removed.
    pub audit: DateTime<Utc>,
    /// Scheduling inbox items older than this are removed.
    pub inbox: DateTime<Utc>,
    /// OAuth states that expired before this are removed.
    pub oauth_states: DateTime<Utc>,
    /// RSVP tokens that expired or were revoked before this are removed.
    pub rsvp_tokens: DateTime<Utc>,
    /// Principals deleted before this are purged.
    pub principals: DateTime<Utc>,
    /// Calendars deleted before this are purged.
    pub calendars: DateTime<Utc>,
}

/// `now` minus `delta`, saturating at the earliest representable time.
fn before(now: DateTime<Utc>, delta: TimeDelta) -> DateTime<Utc> {
    now.checked_sub_signed(delta).unwrap_or(DateTime::<Utc>::MIN_UTC)
}

impl Cutoffs {
    /// The cut-offs of `config` at `now`.
    pub fn at(now: DateTime<Utc>, config: &RetentionConfig) -> Self {
        let days = |days: u32| before(now, TimeDelta::try_days(i64::from(days)).unwrap_or(TimeDelta::MAX));
        Self {
            outbox_done: days(config.outbox_done_days),
            outbox_dead: days(config.outbox_dead_days),
            deliveries: days(config.webhook_delivery_days),
            changes: days(config.collection_changes_days),
            audit: days(config.audit_days),
            inbox: days(config.scheduling_inbox_days),
            oauth_states: days(config.oauth_state_days),
            rsvp_tokens: days(config.rsvp_token_days),
            principals: days(config.principal_purge_days),
            calendars: days(config.deleted_calendar_days),
        }
    }
}

/// Deleted data that is purged row by row, each in the transaction of its tenant (so that the audit record of the
/// purge is written with it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purge {
    Principals,
    Calendars,
}

impl Purge {
    const fn name(self) -> &'static str {
        match self {
            Self::Principals => "principals",
            Self::Calendars => "calendars",
        }
    }
}

/// A cleanup step that is one call of the retention repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Outbox,
    Deliveries,
    Changes,
    Audit,
    Inbox,
    Idempotency,
    OAuthStates,
    RsvpTokens,
}

impl Step {
    const ALL: [Self; 8] = [
        Self::Outbox,
        Self::Deliveries,
        Self::Changes,
        Self::Audit,
        Self::Inbox,
        Self::Idempotency,
        Self::OAuthStates,
        Self::RsvpTokens,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Outbox => "outbox",
            Self::Deliveries => "webhook_deliveries",
            Self::Changes => "collection_changes",
            Self::Audit => "audit_events",
            Self::Inbox => "scheduling_inbox",
            Self::Idempotency => "idempotency_keys",
            Self::OAuthStates => "oauth_states",
            Self::RsvpTokens => "rsvp_tokens",
        }
    }
}

/// What one call of a step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Called {
    /// The call removed this many rows.
    Removed(u64),
    /// The store does not offer the step (audit retention that runs elsewhere, a store without delivery purge).
    Skipped,
}

/// What one pass did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sweep {
    /// The rows removed, by step (`outbox`, `audit_events`, ...) and by kind of purge (`principals`, `calendars`).
    pub removed: BTreeMap<&'static str, u64>,
    /// The steps that failed. They are tried again by the next pass.
    pub failed: Vec<&'static str>,
    /// The steps the store does not offer to this connection (no error, nothing to retry).
    pub skipped: Vec<&'static str>,
    /// Whether a step stopped at [`MAX_ROUNDS`] with rows left, so the next pass should follow at once.
    pub more: bool,
}

impl Sweep {
    /// The number of rows removed by all steps together.
    pub fn total(&self) -> u64 {
        self.removed
            .values()
            .fold(0_u64, |sum, count| sum.saturating_add(*count))
    }

    fn add(&mut self, name: &'static str, count: u64) {
        if count > 0 {
            let slot = self.removed.entry(name).or_insert(0);
            *slot = slot.saturating_add(count);
            metrics::counter!(REMOVED_TOTAL, "step" => name).increment(count);
        }
    }

    fn fail(&mut self, name: &'static str, error: &StoreError) {
        tracing::warn!(step = name, %error, "a retention step failed; the next pass tries again");
        metrics::counter!(FAILED_TOTAL, "step" => name).increment(1);
        if !self.failed.contains(&name) {
            self.failed.push(name);
        }
    }

    fn skip(&mut self, name: &'static str) {
        if !self.skipped.contains(&name) {
            self.skipped.push(name);
        }
    }
}

/// What the worker remembers about the audit gauges between passes.
#[derive(Debug)]
struct AuditGauge {
    /// When the oldest audit event was last looked up, as milliseconds since the epoch by the clock of the application;
    /// `i64::MIN` before the first lookup.
    looked_up: AtomicI64,
    /// Whether the gauge of the oldest event has been given a value, so that a log that was emptied since can be told from
    /// one that never held an event.
    published: AtomicBool,
}

impl AuditGauge {
    fn new() -> Self {
        Self {
            looked_up: AtomicI64::new(i64::MIN),
            published: AtomicBool::new(false),
        }
    }

    /// Whether the lookup is due at `now` (milliseconds since the epoch): there was none yet, the last one is
    /// [`AUDIT_LOOKUP_INTERVAL`] ago (less [`AUDIT_LOOKUP_TOLERANCE`]), or the clock went back before it.
    fn due(&self, now: i64) -> bool {
        let last = self.looked_up.load(Ordering::Relaxed);
        let millis = |span: Duration| i64::try_from(span.as_millis()).unwrap_or(i64::MAX);
        let wait = millis(AUDIT_LOOKUP_INTERVAL).saturating_sub(millis(AUDIT_LOOKUP_TOLERANCE));
        last == i64::MIN || now < last || now.saturating_sub(last) >= wait
    }
}

/// The cleanup worker (`retention`).
#[derive(Debug, Clone)]
pub struct RetentionWorker {
    core: AppCore,
    audit_gauge: Arc<AuditGauge>,
}

impl RetentionWorker {
    /// Creates the worker on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self {
            core,
            audit_gauge: Arc::new(AuditGauge::new()),
        }
    }

    /// The cut-offs of a pass that starts now.
    pub fn cutoffs(&self) -> Cutoffs {
        let deps = self.core.deps();
        Cutoffs::at(deps.clock.now(), &deps.config.retention)
    }

    /// One call of `step` in its own system transaction.
    async fn call(&self, step: Step, cutoffs: &Cutoffs) -> Result<Called, StoreError> {
        let mut tx = self.core.deps().database.begin_system().await?;
        let called = {
            let repo = tx.retention();
            match step {
                Step::Outbox => Called::Removed(repo.purge_outbox(cutoffs.outbox_done, cutoffs.outbox_dead).await?),
                Step::Deliveries => match repo.purge_deliveries(cutoffs.deliveries).await {
                    Ok(removed) => Called::Removed(removed),
                    Err(StoreError::Unsupported) => Called::Skipped,
                    Err(error) => return Err(error),
                },
                Step::Changes => Called::Removed(repo.prune_changes(cutoffs.changes).await?),
                Step::Audit => match repo.purge_audit_checked(cutoffs.audit).await? {
                    AuditPurge::Purged(removed) => Called::Removed(removed),
                    AuditPurge::NotPermitted => Called::Skipped,
                },
                Step::Inbox => Called::Removed(repo.purge_inbox(cutoffs.inbox).await?),
                Step::Idempotency => Called::Removed(repo.purge_idempotency().await?),
                Step::OAuthStates => Called::Removed(repo.purge_oauth_states(cutoffs.oauth_states).await?),
                Step::RsvpTokens => Called::Removed(repo.purge_rsvp_tokens(cutoffs.rsvp_tokens).await?),
            }
        };
        tx.commit().await?;
        Ok(called)
    }

    /// Repeats `step` while it removes rows, at most [`MAX_ROUNDS`] times.
    async fn drain(&self, step: Step, cutoffs: &Cutoffs, sweep: &mut Sweep) {
        for round in 1..=MAX_ROUNDS {
            match self.call(step, cutoffs).await {
                Ok(Called::Removed(0)) => return,
                Ok(Called::Removed(count)) => {
                    sweep.add(step.name(), count);
                    if round == MAX_ROUNDS {
                        sweep.more = true;
                    }
                }
                Ok(Called::Skipped) => {
                    sweep.skip(step.name());
                    return;
                }
                Err(error) => {
                    sweep.fail(step.name(), &error);
                    return;
                }
            }
        }
    }

    /// The rows of `purge` that were deleted before its cut-off, as `(tenant, id)` pairs.
    async fn due(&self, purge: Purge, cutoffs: &Cutoffs) -> Result<Vec<(TenantId, Uuid)>, StoreError> {
        let mut tx = self.core.deps().database.begin_system().await?;
        let due = match purge {
            Purge::Principals => tx
                .retention()
                .due_principals(cutoffs.principals, PURGE_BATCH)
                .await?
                .into_iter()
                .map(|(tenant, id)| (tenant, id.as_uuid()))
                .collect(),
            Purge::Calendars => tx
                .retention()
                .due_calendars(cutoffs.calendars, PURGE_BATCH)
                .await?
                .into_iter()
                .map(|(tenant, id)| (tenant, id.as_uuid()))
                .collect(),
        };
        tx.commit().await?;
        Ok(due)
    }

    /// Purges one principal and writes `principal.purged` in the same transaction. `false` when it was gone
    /// already (another instance purged it, or it was purged on request).
    async fn purge_principal(&self, tenant: TenantId, principal: PrincipalId) -> Result<bool, StoreError> {
        let deps = self.core.deps();
        let mut tx = deps.database.begin(tenant, TxMode::ReadWrite).await?;
        match tx.principals().purge(principal).await {
            Ok(()) => {}
            Err(StoreError::NotFound) => {
                tx.commit().await?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        tx.audit()
            .append(NewAudit {
                id: deps.ids.new_id(),
                actor: AuditActor::system(),
                event: AuditEvent::PrincipalPurged(PrincipalAudit { principal }),
            })
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Purges one calendar. `false` when it was gone already.
    async fn purge_calendar(&self, tenant: TenantId, calendar: CalendarId) -> Result<bool, StoreError> {
        let mut tx = self.core.deps().database.begin(tenant, TxMode::ReadWrite).await?;
        match tx.calendars().purge(calendar).await {
            Ok(()) => {}
            Err(StoreError::NotFound) => {
                tx.commit().await?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Purges one row of `purge` in its tenant's transaction.
    async fn purge_one(&self, purge: Purge, tenant: TenantId, id: Uuid) -> Result<bool, StoreError> {
        match purge {
            Purge::Principals => self.purge_principal(tenant, PrincipalId::from_uuid(id)).await,
            Purge::Calendars => self.purge_calendar(tenant, CalendarId::from_uuid(id)).await,
        }
    }

    /// Purges the rows of `purge` whose deletion is older than the cut-off, a batch per round.
    async fn drain_purges(&self, purge: Purge, cutoffs: &Cutoffs, sweep: &mut Sweep) {
        let name = purge.name();
        for round in 1..=MAX_ROUNDS {
            let due = match self.due(purge, cutoffs).await {
                Ok(due) => due,
                Err(error) => {
                    sweep.fail(name, &error);
                    return;
                }
            };
            let mut purged = 0_u64;
            let mut failed = false;
            for (tenant, id) in &due {
                match self.purge_one(purge, *tenant, *id).await {
                    Ok(true) => purged += 1,
                    Ok(false) => {}
                    Err(error) => {
                        failed = true;
                        sweep.fail(name, &error);
                    }
                }
            }
            sweep.add(name, purged);
            // A row that cannot be purged would be listed again and again: leave it to the next pass.
            if failed || purged == 0 || u32::try_from(due.len()).is_ok_and(|due| due < PURGE_BATCH) {
                return;
            }
            if round == MAX_ROUNDS {
                sweep.more = true;
            }
        }
    }

    /// The time of the oldest audit event of all tenants, in a system transaction of its own.
    async fn oldest_audit_event(&self) -> Result<Option<DateTime<Utc>>, StoreError> {
        let mut tx = self.core.deps().database.begin_system().await?;
        let oldest = tx.retention().oldest_audit_at().await?;
        tx.commit().await?;
        Ok(oldest)
    }

    /// Publishes the two gauges that tell an operator whether the job that purges the audit log runs
    /// ([`AUDIT_OLDEST_EVENT_TIMESTAMP_SECONDS`] and [`AUDIT_RETENTION_SECONDS`]).
    ///
    /// The retention gauge is set by every pass (it is a setting, and a setting costs nothing). The oldest event is looked up
    /// every [`AUDIT_LOOKUP_INTERVAL`] by the clock of the application: one indexed lookup in a system transaction. A store
    /// that cannot answer it leaves the gauge absent and the step skipped; a lookup that fails is a failed step, and the next
    /// pass tries it again (the failure leaves the gauge as it was: a value that is a little old is better than none).
    async fn publish_audit_gauges(&self, sweep: &mut Sweep) {
        let deps = self.core.deps();
        metrics::gauge!(AUDIT_RETENTION_SECONDS).set(f64::from(deps.config.retention.audit_days) * SECONDS_PER_DAY);
        let now = deps.clock.now().timestamp_millis();
        if !self.audit_gauge.due(now) {
            return;
        }
        match self.oldest_audit_event().await {
            Ok(Some(oldest)) => {
                metrics::gauge!(AUDIT_OLDEST_EVENT_TIMESTAMP_SECONDS).set(unix_seconds(oldest));
                self.audit_gauge.published.store(true, Ordering::Relaxed);
            }
            Ok(None) => {
                // The log is empty. A gauge that was set cannot be taken back, and its last value would grow stale until an
                // alert on the age of the oldest event fires for a log that holds nothing: `NaN` matches no comparison.
                if self.audit_gauge.published.load(Ordering::Relaxed) {
                    metrics::gauge!(AUDIT_OLDEST_EVENT_TIMESTAMP_SECONDS).set(f64::NAN);
                }
            }
            Err(StoreError::Unsupported) => sweep.skip(AUDIT_OLDEST_STEP),
            Err(error) => {
                sweep.fail(AUDIT_OLDEST_STEP, &error);
                return;
            }
        }
        self.audit_gauge.looked_up.store(now, Ordering::Relaxed);
    }

    /// One complete pass: every step, then the purges of deleted principals and calendars, then the audit gauges.
    pub async fn sweep(&self) -> Sweep {
        let cutoffs = self.cutoffs();
        let mut sweep = Sweep::default();
        for step in Step::ALL {
            self.drain(step, &cutoffs, &mut sweep).await;
        }
        self.drain_purges(Purge::Principals, &cutoffs, &mut sweep).await;
        self.drain_purges(Purge::Calendars, &cutoffs, &mut sweep).await;
        self.publish_audit_gauges(&mut sweep).await;
        if !sweep.skipped.is_empty() {
            tracing::debug!(
                steps = ?sweep.skipped,
                "the store does not offer these cleanup steps to this connection (the audit purge belongs to the owner role)"
            );
        }
        if sweep.total() > 0 {
            tracing::info!(
                removed = sweep.total(),
                steps = ?sweep.removed,
                "retention removed expired data"
            );
        }
        sweep
    }
}

#[async_trait]
impl Worker for RetentionWorker {
    fn name(&self) -> &'static str {
        "retention"
    }

    fn interval(&self) -> Duration {
        SWEEP_INTERVAL
    }

    async fn tick(&self) -> WorkReport {
        let sweep = self.sweep().await;
        WorkReport {
            processed: u32::try_from(sweep.total()).unwrap_or(u32::MAX),
            failed: u32::try_from(sweep.failed.len()).unwrap_or(u32::MAX),
            more: sweep.more,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn cutoffs_follow_the_retention_table() {
        let now = Utc.with_ymd_and_hms(2027, 3, 31, 12, 0, 0).unwrap();
        let cutoffs = Cutoffs::at(now, &RetentionConfig::default());
        let days = |days: i64| now - TimeDelta::days(days);
        assert_eq!(cutoffs.outbox_done, days(7));
        assert_eq!(cutoffs.outbox_dead, days(30));
        assert_eq!(cutoffs.deliveries, days(30));
        assert_eq!(cutoffs.changes, days(90));
        assert_eq!(cutoffs.audit, days(365));
        assert_eq!(cutoffs.inbox, days(30));
        assert_eq!(cutoffs.oauth_states, days(1));
        assert_eq!(cutoffs.rsvp_tokens, days(30));
        assert_eq!(cutoffs.principals, days(30));
        assert_eq!(cutoffs.calendars, days(30));
    }

    #[test]
    fn huge_periods_saturate_instead_of_overflowing() {
        let now = Utc.with_ymd_and_hms(2027, 3, 31, 12, 0, 0).unwrap();
        let config = RetentionConfig {
            audit_days: u32::MAX,
            ..RetentionConfig::default()
        };
        let cutoffs = Cutoffs::at(now, &config);
        assert!(cutoffs.audit < now - TimeDelta::days(365));
        assert!(cutoffs.audit >= DateTime::<Utc>::MIN_UTC);
    }

    #[test]
    fn sweeps_add_up_and_remember_failures_once() {
        let mut sweep = Sweep::default();
        sweep.add("outbox", 3);
        sweep.add("outbox", 4);
        sweep.add("inbox", 0);
        sweep.fail("audit_events", &StoreError::Unavailable);
        sweep.fail("audit_events", &StoreError::Unavailable);
        sweep.skip("audit_events");
        sweep.skip("audit_events");
        assert_eq!(sweep.removed, BTreeMap::from([("outbox", 7)]));
        assert_eq!(sweep.total(), 7);
        assert_eq!(sweep.failed, vec!["audit_events"]);
        assert_eq!(sweep.skipped, vec!["audit_events"]);
    }

    #[test]
    fn every_step_has_its_own_name() {
        let names: std::collections::BTreeSet<&str> = Step::ALL.iter().map(|step| step.name()).collect();
        assert_eq!(names.len(), Step::ALL.len());
    }
}
