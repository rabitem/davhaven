//! The outbox dispatcher: the worker that claims ready records of all tenants, hands each to the handler of its
//! kind and settles the outcome.
//!
//! One pass ([`Worker::tick`]):
//!
//! 1. A system transaction claims up to `outbox.batch_size` ready records (`pending` and due, or `in_flight` with an
//!    expired lease) and reads the queue depth for the gauges. Claimed records are `in_flight` for `outbox.lease`.
//! 2. The handlers run concurrently (at most `outbox.concurrency` at a time), all under one deadline: 80 % of the lease,
//!    counted from the moment the batch was claimed, so that a claim never expires while its handler is still
//!    working, however late in the batch the handler started. A record whose turn comes when less than a quarter of
//!    the lease is left is deferred without being handled (a handler cut off in the middle of its work would repeat
//!    it). A handler that panics or hangs is an ordinary retryable failure.
//! 3. A dead `imip` record is announced first: a `mail.delivery_failed` domain event is enqueued for its tenant
//!    (with an id derived from the record, so announcing twice enqueues once). Only when that worked is the record
//!    settled dead; otherwise it is rescheduled like a transient failure, so the tenant is never left without the
//!    event for a record nobody will look at again.
//! 4. One system transaction settles the batch, every record with the claim it was handed out under
//!    (`complete_claimed`, `fail_claimed`, `defer_claimed`: a lease that ran out and was taken over by another
//!    dispatcher is not settled from here, `LeaseLost` means someone else decided and ends the matter). `Ok`
//!    completes the record, [`HandlerError::Retryable`] reschedules
//!    it at `base * 2^(attempts - 1)` (capped at `outbox.backoff_max`), [`HandlerError::Permanent`] and an
//!    exhausted attempt budget (`outbox.max_attempts`, unless the handler bounds its retries itself) dead-letter it,
//!    and [`HandlerError::Defer`] puts it back for the time the handler asked, **without counting an attempt**.
//!
//! Delivery is at-least-once: if the process stops between a handler's side effect and the settlement, the lease
//! expires and the record is handled again, which is why handlers are idempotent. A graceful shutdown ([`Worker::run`])
//! lets the pass in flight finish for a few seconds and then releases the leases it still holds, so the records are
//! due immediately on the next start without having used up an attempt.
//!
//! Records of a kind without a handler (a newer binary wrote them, or the adapter is not configured) are retried
//! like any transient failure and dead-letter after the attempt budget; nothing is dropped silently.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::events::MailFailurePayload;
use davhaven_domain::{AuditActor, Envelope, EventId, EventPayload, EventType, OutboxId};
use davhaven_ports::{
    HandlerError, NewOutbox, OutboxClaim, OutboxFailure, OutboxHandler, OutboxKey, OutboxMessage, OutboxRecord,
    OutboxStats, StoreError, TxMode, WorkReport, Worker, outbox::kind,
};
use futures::{FutureExt, StreamExt, stream};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::OutboxConfig;
use crate::wiring::AppCore;

/// How long a graceful shutdown lets the pass in flight finish before it releases the leases.
const DRAIN: Duration = Duration::from_secs(5);

/// The longest error text stored with a record.
const MAX_ERROR_CHARS: usize = 300;

/// The shortest deferral: a record is never due again sooner than this after it was held back.
const MIN_DEFER: Duration = Duration::from_secs(1);

/// The share of the lease that has to be left when a handler starts: records whose turn comes later are put back
/// without being handled.
const MIN_START_SHARE: f64 = 0.25;

/// The gauge of the records waiting for their next attempt.
pub const PENDING: &str = "davhaven_outbox_pending";
/// The gauge of the records currently claimed.
pub const IN_FLIGHT: &str = "davhaven_outbox_in_flight";
/// The gauge of the age of the oldest due record in seconds (zero when nothing is waiting).
pub const OLDEST_PENDING_AGE_SECONDS: &str = "davhaven_outbox_oldest_pending_age_seconds";
/// The counter of the records that went dead, labelled with the kind.
pub const DEAD_TOTAL: &str = "davhaven_outbox_dead_total";
/// The counter of handled records, labelled with the kind and the outcome (`done`, `retry`, `dead`).
pub const HANDLED_TOTAL: &str = "davhaven_outbox_handled_total";
/// The histogram of the time handlers take, labelled with the kind.
pub const HANDLE_DURATION_SECONDS: &str = "davhaven_outbox_handle_duration_seconds";
/// The counter of outcomes that could not be stored because the claim was lost first (another dispatcher settled
/// the record after the lease ran out, or the record was deleted). A rising value says that handlers are slower
/// than `outbox.lease`.
pub const SETTLE_LOST_TOTAL: &str = "davhaven_outbox_settle_lost_total";

/// The delay before the attempt after `attempts` claims: `backoff_base * 2^(attempts - 1)`, never more than
/// `backoff_max`.
pub fn backoff_delay(config: &OutboxConfig, attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(30);
    config
        .backoff_base
        .checked_mul(1_u32 << exponent)
        .map_or(config.backoff_max, |delay| delay.min(config.backoff_max))
}

/// The time `delay` after `now`, saturating at the end of time.
fn after_now(now: DateTime<Utc>, delay: Duration) -> DateTime<Utc> {
    chrono::Duration::from_std(delay)
        .ok()
        .and_then(|delay| now.checked_add_signed(delay))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// A count or an age as a gauge value (saturating far beyond anything an operator reads).
fn gauge_value(count: impl TryInto<u32>) -> f64 {
    f64::from(count.try_into().unwrap_or(u32::MAX))
}

/// Why a record was dead-lettered, for the `mail.delivery_failed` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadReason {
    /// The handler said repeating would not help.
    Rejected,
    /// The attempt budget is used up.
    Exhausted,
}

impl DeadReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Exhausted => "exhausted",
        }
    }
}

/// What happens to a record after its handler ran.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Done,
    Retry {
        error: String,
        at: DateTime<Utc>,
    },
    /// Nothing was attempted: due again at `at`, and the claim does not count.
    Defer {
        note: String,
        at: DateTime<Utc>,
    },
    Dead {
        error: String,
        reason: DeadReason,
    },
}

impl Outcome {
    const fn label(&self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Retry { .. } => "retry",
            Self::Defer { .. } => "deferred",
            Self::Dead { .. } => "dead",
        }
    }
}

/// The id of the `mail.delivery_failed` event (and of its outbox record) that announces the death of `outbox`.
///
/// The id is UUIDv7-shaped (the timestamp bytes are those of the outbox id, so listings stay chronological) and a
/// pure function of the outbox id: announcing the same death twice finds the first announcement.
fn announcement_id(outbox: OutboxId) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"davhaven/mail-failed/v1");
    hasher.update(outbox.as_uuid().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    for (slot, byte) in bytes.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    for (slot, byte) in bytes.iter_mut().zip(outbox.as_uuid().as_bytes().iter()).take(6) {
        *slot = *byte;
    }
    if let Some(version) = bytes.get_mut(6) {
        *version = 0x70 | (*version & 0x0f);
    }
    if let Some(variant) = bytes.get_mut(8) {
        *variant = 0x80 | (*variant & 0x3f);
    }
    Uuid::from_bytes(bytes)
}

/// The error text of a record: control characters become spaces and the text is shortened.
fn clean(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().take(MAX_ERROR_CHARS) {
        out.push(if c.is_control() { ' ' } else { c });
    }
    out
}

/// The outbox dispatcher worker.
pub struct OutboxDispatcher {
    core: AppCore,
    handlers: BTreeMap<&'static str, Arc<dyn OutboxHandler>>,
    /// The claims of the pass in flight, for the release on shutdown.
    held: Mutex<BTreeMap<OutboxKey, OutboxClaim>>,
}

impl core::fmt::Debug for OutboxDispatcher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutboxDispatcher")
            .field("kinds", &self.kinds())
            .finish_non_exhaustive()
    }
}

impl OutboxDispatcher {
    /// Creates the dispatcher with the handlers of the kinds it serves. When two handlers claim a kind, the first
    /// wins and the second is logged and ignored.
    pub fn new(core: AppCore, handlers: impl IntoIterator<Item = Arc<dyn OutboxHandler>>) -> Self {
        let mut by_kind: BTreeMap<&'static str, Arc<dyn OutboxHandler>> = BTreeMap::new();
        for handler in handlers {
            let kind = handler.kind();
            if by_kind.contains_key(kind) {
                tracing::warn!(kind, "two outbox handlers claim the same kind; the first one is used");
            } else {
                by_kind.insert(kind, handler);
            }
        }
        Self {
            core,
            handlers: by_kind,
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// The kinds that have a handler.
    pub fn kinds(&self) -> Vec<&'static str> {
        self.handlers.keys().copied().collect()
    }

    /// Releases the leases of the claims that were not settled (what a graceful shutdown does). Returns how many
    /// records became due again.
    pub async fn release_held(&self) -> u64 {
        let claims: Vec<OutboxClaim> = self.held.lock().await.values().copied().collect();
        if claims.is_empty() {
            return 0;
        }
        let released = async {
            let mut tx = self.core.deps().database.begin_system().await?;
            // Fenced by the claims: a lease that another dispatcher took over meanwhile is left alone.
            let released = tx.outbox_claim().release_claimed(&claims).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(released)
        }
        .await;
        match released {
            Ok(count) => {
                self.held.lock().await.clear();
                count
            }
            Err(error) => {
                tracing::warn!(%error, "could not release the outbox leases; they expire on their own");
                0
            }
        }
    }

    fn config(&self) -> &OutboxConfig {
        &self.core.deps().config.outbox
    }

    fn handler_timeout(&self) -> Duration {
        self.config().lease.mul_f64(0.8)
    }

    fn concurrency(&self) -> usize {
        usize::try_from(self.config().concurrency).unwrap_or(usize::MAX).max(1)
    }

    /// Claims a batch and reads the queue depth.
    async fn claim(&self) -> Result<(Vec<OutboxRecord>, OutboxStats), StoreError> {
        let config = self.config();
        let mut tx = self.core.deps().database.begin_system().await?;
        let queue = tx.outbox_claim();
        let records = queue.claim(config.batch_size, config.lease).await?;
        let stats = queue.stats().await?;
        tx.commit().await?;
        Ok((records, stats))
    }

    fn publish_stats(&self, stats: &OutboxStats) {
        let now = self.core.deps().clock.now();
        let age = stats
            .oldest_pending_at
            .map_or(0.0, |due| gauge_value((now - due).num_seconds().max(0)));
        metrics::gauge!(PENDING).set(gauge_value(stats.pending));
        metrics::gauge!(IN_FLIGHT).set(gauge_value(stats.in_flight));
        metrics::gauge!(OLDEST_PENDING_AGE_SECONDS).set(age);
    }

    /// Runs the handler of the record until `deadline`; panics and hangs become retryable failures, and a record
    /// whose turn comes after the deadline is deferred without being handled (its claim would expire under it).
    async fn invoke(
        &self,
        handler: &dyn OutboxHandler,
        record: &OutboxRecord,
        deadline: tokio::time::Instant,
    ) -> Result<(), HandlerError> {
        // A handler that starts with next to no time left would be cut off in the middle of its work (a mail
        // half sent), so a record whose turn comes that late waits for the next pass instead.
        let margin = self.config().lease.mul_f64(MIN_START_SHARE);
        if deadline.saturating_duration_since(tokio::time::Instant::now()) < margin {
            return Err(HandlerError::defer(
                MIN_DEFER,
                "the batch ran out of time before this record was handled",
            ));
        }
        let call = AssertUnwindSafe(handler.handle(record)).catch_unwind();
        match tokio::time::timeout_at(deadline, call).await {
            Ok(Ok(result)) => result,
            Ok(Err(_panic)) => Err(HandlerError::retryable("the handler panicked")),
            Err(_elapsed) => Err(HandlerError::retryable("the handler did not finish within its lease")),
        }
    }

    fn decide(&self, record: &OutboxRecord, limits_attempts: bool, result: Result<(), HandlerError>) -> Outcome {
        let config = self.config();
        match result {
            Ok(()) => Outcome::Done,
            Err(HandlerError::Permanent(message)) => Outcome::Dead {
                error: clean(&message),
                reason: DeadReason::Rejected,
            },
            Err(HandlerError::Defer { after, reason }) => Outcome::Defer {
                note: clean(reason),
                at: after_now(self.core.deps().clock.now(), after.max(MIN_DEFER)),
            },
            Err(HandlerError::Retryable(message)) => {
                if limits_attempts && record.attempts >= config.max_attempts {
                    Outcome::Dead {
                        error: clean(&format!("gave up after {} attempts: {message}", record.attempts)),
                        reason: DeadReason::Exhausted,
                    }
                } else {
                    let delay = backoff_delay(config, record.attempts);
                    Outcome::Retry {
                        error: clean(&message),
                        at: after_now(self.core.deps().clock.now(), delay),
                    }
                }
            }
            // A kind of failure this build does not know: retry it like a transient one.
            Err(other) => Outcome::Retry {
                error: clean(other.message()),
                at: after_now(self.core.deps().clock.now(), backoff_delay(config, record.attempts)),
            },
        }
    }

    /// Handles one record and decides its fate.
    async fn handle_one(&self, record: OutboxRecord, deadline: tokio::time::Instant) -> (OutboxRecord, Outcome) {
        let started = Instant::now();
        let handler = self.handlers.get(record.kind.as_str());
        let (result, limits_attempts, label) = match handler {
            Some(handler) => (
                self.invoke(handler.as_ref(), &record, deadline).await,
                handler.limits_attempts(),
                handler.kind(),
            ),
            None => (
                Err(HandlerError::retryable(format!(
                    "no handler is registered for the outbox kind `{}`",
                    clean(&record.kind)
                ))),
                true,
                "unknown",
            ),
        };
        let outcome = self.decide(&record, limits_attempts, result);
        metrics::histogram!(HANDLE_DURATION_SECONDS, "kind" => label).record(started.elapsed().as_secs_f64());
        metrics::counter!(HANDLED_TOTAL, "kind" => label, "outcome" => outcome.label()).increment(1);
        match &outcome {
            Outcome::Done => {
                tracing::debug!(outbox = %record.id, tenant = %record.tenant_id, kind = label, "outbox record handled");
            }
            Outcome::Retry { error, at } => {
                tracing::info!(
                    outbox = %record.id, tenant = %record.tenant_id, kind = label, attempt = record.attempts,
                    retry_at = %at, error = %error, "outbox record failed; it will be retried"
                );
            }
            Outcome::Defer { note, at } => {
                tracing::debug!(
                    outbox = %record.id, tenant = %record.tenant_id, kind = label, due = %at, note = %note,
                    "outbox record held back; the claim does not count"
                );
            }
            Outcome::Dead { error, reason } => {
                metrics::counter!(DEAD_TOTAL, "kind" => label).increment(1);
                tracing::warn!(
                    outbox = %record.id, tenant = %record.tenant_id, kind = label, attempt = record.attempts,
                    reason = reason.as_str(), error = %error, "outbox record is dead"
                );
            }
        }
        (record, outcome)
    }

    /// Writes the outcomes of the batch in one system transaction.
    ///
    /// A record whose claim was lost (the lease ran out and another dispatcher settled, released or reclaimed the
    /// record meanwhile: `LeaseLost`) or that no longer exists (`NotFound`: retention, tenant deletion) has
    /// nothing left to settle, and its outcome must not keep the outcomes of the rest of the batch from being
    /// stored: they would be handled again when their leases expire. Returns how many outcomes were dropped that
    /// way.
    async fn settle(&self, settled: &[(OutboxRecord, Outcome)]) -> Result<u64, StoreError> {
        let mut tx = self.core.deps().database.begin_system().await?;
        let mut lost = 0_u64;
        for (record, outcome) in settled {
            let queue = tx.outbox_claim();
            // Every record of a batch was handed out in flight, so it has a claim; one without has been changed
            // by someone else since and is lost like a lease that was taken over.
            let result = match record.claim() {
                None => Err(StoreError::LeaseLost),
                Some(claim) => match outcome {
                    Outcome::Done => queue.complete_claimed(claim).await,
                    Outcome::Retry { error, at } => {
                        queue
                            .fail_claimed(claim, OutboxFailure::retry(error.clone(), *at))
                            .await
                    }
                    Outcome::Defer { note, at } => queue.defer_claimed(claim, *at, note).await,
                    Outcome::Dead { error, .. } => queue.fail_claimed(claim, OutboxFailure::dead(error.clone())).await,
                },
            };
            match result {
                Ok(()) => {}
                Err(StoreError::NotFound | StoreError::LeaseLost) => {
                    lost += 1;
                    tracing::debug!(
                        outbox = %record.id, tenant = %record.tenant_id, kind = %record.kind,
                        outcome = outcome.label(),
                        "the claim of an outbox record was lost before its outcome was stored"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        tx.commit().await?;
        if lost > 0 {
            metrics::counter!(SETTLE_LOST_TOTAL).increment(lost);
        }
        Ok(lost)
    }

    /// Tells the subscribers of the tenant that a mail could not be delivered.
    ///
    /// The event and its outbox record take their id from the dead record ([`announcement_id`]); a record that
    /// has been announced is left alone, so a pass that crashed after announcing and handled the record again
    /// does not announce it twice.
    async fn announce_mail_failure(&self, record: &OutboxRecord, reason: DeadReason) -> Result<(), StoreError> {
        let deps = self.core.deps();
        let id = announcement_id(record.id);
        let mut tx = deps.database.begin(record.tenant_id, TxMode::ReadWrite).await?;
        match tx.outbox().get(OutboxId::from_uuid(id)).await {
            Ok(_announced) => return tx.commit().await,
            Err(StoreError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let (object, method) = match record.message() {
            Ok(OutboxMessage::Imip(job)) => (Some(job.object), Some(job.method)),
            _ => (None, None),
        };
        let envelope = Envelope::new(
            EventId::from_uuid(id),
            EventType::MailDeliveryFailed,
            record.tenant_id,
            deps.clock.now(),
            AuditActor::system(),
            EventPayload::MailFailure(MailFailurePayload {
                outbox: record.id,
                object,
                method,
                reason: reason.as_str().to_owned(),
            }),
        )
        .map_err(|error| StoreError::internal(error.to_string()))?;
        tx.outbox()
            .enqueue(NewOutbox::now(
                OutboxId::from_uuid(id),
                OutboxMessage::DomainEvent(envelope),
            ))
            .await?;
        tx.commit().await
    }

    /// Announces every dead mail of the batch before the batch is settled. A mail whose announcement fails is not
    /// declared dead: it is rescheduled like a transient failure and tried again, so the event is never lost.
    async fn announce_dead_mails(&self, settled: &mut [(OutboxRecord, Outcome)]) {
        for (record, outcome) in settled.iter_mut() {
            let Outcome::Dead { reason, .. } = &*outcome else {
                continue;
            };
            let reason = *reason;
            if record.kind != kind::IMIP {
                continue;
            }
            if let Err(error) = self.announce_mail_failure(record, reason).await {
                tracing::warn!(
                    outbox = %record.id, tenant = %record.tenant_id, %error,
                    "could not enqueue mail.delivery_failed; the record is tried again instead of going dead"
                );
                *outcome = Outcome::Retry {
                    error: "the failure of this mail could not be announced yet".to_owned(),
                    at: after_now(
                        self.core.deps().clock.now(),
                        backoff_delay(self.config(), record.attempts),
                    ),
                };
            }
        }
    }

    async fn hold(&self, records: &[OutboxRecord]) {
        let mut held = self.held.lock().await;
        for record in records {
            if let Some(claim) = record.claim() {
                held.insert(record.key(), claim);
            }
        }
    }

    async fn unhold(&self, records: &[(OutboxRecord, Outcome)]) {
        let mut held = self.held.lock().await;
        for (record, _) in records {
            held.remove(&record.key());
        }
    }
}

#[async_trait]
impl Worker for OutboxDispatcher {
    fn name(&self) -> &'static str {
        "outbox"
    }

    fn interval(&self) -> Duration {
        self.config().poll_interval
    }

    async fn tick(&self) -> WorkReport {
        // The claim starts the lease of every record of the batch: the deadline counts from before it.
        let claimed_at = tokio::time::Instant::now();
        let (records, stats) = match self.claim().await {
            Ok(claimed) => claimed,
            Err(error) => {
                tracing::warn!(%error, "the outbox dispatcher could not claim records");
                return WorkReport::idle();
            }
        };
        self.publish_stats(&stats);
        if records.is_empty() {
            return WorkReport::idle();
        }
        let deadline = claimed_at + self.handler_timeout();
        let full_batch = u32::try_from(records.len()).is_ok_and(|claimed| claimed >= self.config().batch_size);
        self.hold(&records).await;
        let mut settled: Vec<(OutboxRecord, Outcome)> = stream::iter(records)
            .map(|record| self.handle_one(record, deadline))
            .buffer_unordered(self.concurrency())
            .collect()
            .await;
        self.announce_dead_mails(&mut settled).await;
        let stored = self.settle(&settled).await;
        // Whatever happened, the claims are no longer this pass's business: after a failed settlement the leases
        // expire and the records are handled again.
        self.unhold(&settled).await;
        if let Err(error) = stored {
            tracing::warn!(%error, "the outbox dispatcher could not settle a batch; the leases will expire");
            return WorkReport {
                processed: 0,
                failed: u32::try_from(settled.len()).unwrap_or(u32::MAX),
                more: false,
            };
        }
        let mut report = WorkReport {
            processed: 0,
            failed: 0,
            more: full_batch,
        };
        for (_, outcome) in &settled {
            match outcome {
                Outcome::Done => report.processed += 1,
                Outcome::Retry { .. } | Outcome::Dead { .. } => report.failed += 1,
                // Nothing was attempted: neither a success nor a failure.
                Outcome::Defer { .. } => {}
            }
        }
        report
    }

    async fn run(&self, cancel: CancellationToken) {
        while !cancel.is_cancelled() {
            let tick = self.tick();
            tokio::pin!(tick);
            let report = tokio::select! {
                report = &mut tick => report,
                () = cancel.cancelled() => {
                    // Shutting down: give the handlers a moment to finish, then hand the claims back.
                    if let Ok(report) = tokio::time::timeout(DRAIN, &mut tick).await {
                        report
                    } else {
                        // The pass is dropped when the loop is left, and with it the handlers in flight.
                        break;
                    }
                }
            };
            if !report.more {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(self.config().poll_interval) => {}
                }
            }
        }
        let released = self.release_held().await;
        if released > 0 {
            tracing::info!(released, "released the outbox leases of the pass in flight");
        }
    }
}

#[cfg(test)]
mod tests;
