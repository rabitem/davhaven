//! Execution helpers shared by the use cases: bounded retry of lost transactions and blocking iCalendar work.

use core::future::Future;
use std::error::Error as _;
use std::time::{Duration, Instant};

use davhaven_domain::{ErrorKind, IcalLimits};
use davhaven_ical::{ErrorContext, IcalError, LimitKind};
use davhaven_ports::StoreError;

use crate::error::{AppError, AppResult, SafeMessage};
use crate::wiring::AppCore;

/// How often a transaction is attempted when it loses a race (PLAN 2.7: "bounded app retry (3)").
const ATTEMPTS: u32 = 3;

/// Whether the store reported contention: the database aborted the transaction (`SerializationFailure`), which
/// repeating the whole transaction cures (PLAN 2.7). A statement or lock-wait timeout is not contention in this
/// sense: it is the database struggling, and repeating it would triple the latency and the load at exactly that
/// moment, so it is answered `503` at once.
fn is_contention(error: &AppError) -> bool {
    error
        .source()
        .and_then(|source| source.downcast_ref::<StoreError>())
        .is_some_and(|error| matches!(error, StoreError::SerializationFailure))
}

/// Whether a failed version check came from the store (a concurrent change) and not from a header of the client.
fn is_stale_version(error: &AppError) -> bool {
    error.kind() == ErrorKind::PreconditionFailed
        && error
            .source()
            .and_then(|source| source.downcast_ref::<StoreError>())
            .is_some_and(|error| matches!(error, StoreError::PreconditionFailed))
}

/// Runs `attempt` (one complete transaction: begin, read, write, commit) and repeats it up to three times while
/// it fails because it lost a race against another writer.
///
/// With `retry_stale` a failed optimistic version check of the store is repeated too: it means that another
/// request changed the row between this one's read and its write, and a request that asked for no particular
/// version (a `PUT` or `PATCH` without `If-Match`) is computed again against the new state. A request that named
/// a version must fail instead: the client decides what to do about the change.
///
/// # Errors
///
/// The error of the last attempt.
pub(crate) async fn retrying<T, F, Fut>(retry_stale: bool, mut attempt: F) -> AppResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = AppResult<T>>,
{
    let mut tries = 1;
    loop {
        match attempt().await {
            Err(error) if tries < ATTEMPTS && (is_contention(&error) || (retry_stale && is_stale_version(&error))) => {
                tries += 1;
            }
            result => return result,
        }
    }
}

/// A wall-clock deadline for a blocking job that loops over many objects.
///
/// A timeout on the async side cannot stop a blocking thread: the job keeps running to its end and, repeated by
/// clients, fills the blocking pool. Jobs that loop (the evaluation of a page of candidates, the rendering of a
/// feed) therefore carry a `Deadline` into the closure and call [`check`](Self::check) between objects, so they
/// stop soon after the caller gave up.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline(Instant);

impl Deadline {
    /// The deadline of a job that [`blocking`] starts now: twice the wall-clock budget of the limits, which is
    /// the time the async side waits.
    pub(crate) fn of(core: &AppCore) -> Self {
        Self::after(Self::budget(core))
    }

    /// A deadline `wait` from now.
    pub(crate) fn after(wait: Duration) -> Self {
        Self(Instant::now() + wait)
    }

    /// How long the async side waits for a blocking job.
    pub(crate) fn budget(core: &AppCore) -> Duration {
        Duration::from_millis(core.deps().limits.ical.time_budget_ms).saturating_mul(2)
    }

    /// Fails with the transient `TimeBudget` limit once the deadline has passed.
    ///
    /// # Errors
    ///
    /// `IcalError::Limit(LimitKind::TimeBudget)`.
    pub(crate) fn check(&self) -> Result<(), IcalError> {
        if Instant::now() >= self.0 {
            Err(IcalError::Limit(LimitKind::TimeBudget))
        } else {
            Ok(())
        }
    }
}

/// Runs CPU-heavy iCalendar `work` on a blocking thread under the wall-clock budget of the limits.
///
/// The iCalendar layer enforces `time_budget_ms` itself; the timeout here waits twice as long, so that data that is
/// too expensive is reported by the parser (`context` decides how it is answered) and only a stuck worker is a
/// timeout. A timeout and a failed worker are the machine's problem and answer `Unavailable`, never a statement
/// about the data. Work that loops over many objects stops itself with a [`Deadline`].
///
/// # Errors
///
/// The mapped error of the iCalendar layer, or `Unavailable`.
pub(crate) async fn blocking<T, F>(core: &AppCore, context: ErrorContext, work: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce(&IcalLimits) -> Result<T, IcalError> + Send + 'static,
{
    let limits = core.deps().limits.ical.clone();
    let budget = Deadline::budget(core);
    let job = tokio::task::spawn_blocking(move || work(&limits));
    match tokio::time::timeout(budget, job).await {
        Ok(Ok(result)) => result.map_err(|error| AppError::from_ical(error, context)),
        Ok(Err(_)) | Err(_) => Err(AppError::unavailable().with_public_message(SafeMessage::from_static(
            "The request took too long to process; try again later.",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn lost_race() -> AppError {
        AppError::from(StoreError::SerializationFailure)
    }

    #[tokio::test]
    async fn contention_is_retried_three_times_and_then_reported() {
        let calls = AtomicU32::new(0);
        let result: AppResult<u32> = retrying(false, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(lost_race())
        })
        .await;
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Unavailable);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_transaction_that_wins_the_second_time_returns_its_value() {
        let calls = AtomicU32::new(0);
        let result = retrying(false, || async {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(lost_race())
            } else {
                Ok(7)
            }
        })
        .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn only_lost_races_are_repeated_and_never_timeouts_or_other_errors() {
        for error in [
            StoreError::Timeout,
            StoreError::NotFound,
            StoreError::Unavailable,
            StoreError::internal("x"),
        ] {
            let calls = AtomicU32::new(0);
            let _: AppResult<()> = retrying(true, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(AppError::from(error.clone()))
            })
            .await;
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{error}");
        }
    }

    #[test]
    fn a_deadline_passes_and_then_reports_the_transient_limit() {
        assert!(Deadline::after(Duration::from_hours(1)).check().is_ok());
        assert_eq!(
            Deadline::after(Duration::ZERO).check().unwrap_err(),
            IcalError::Limit(LimitKind::TimeBudget)
        );
    }

    #[tokio::test]
    async fn stale_versions_are_retried_only_when_the_client_named_none() {
        for (retry_stale, expected) in [(true, 3), (false, 1)] {
            let calls = AtomicU32::new(0);
            let result: AppResult<()> = retrying(retry_stale, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(AppError::from(StoreError::PreconditionFailed))
            })
            .await;
            assert_eq!(result.unwrap_err().kind(), ErrorKind::PreconditionFailed);
            assert_eq!(calls.load(Ordering::SeqCst), expected, "retry_stale = {retry_stale}");
        }
        let calls = AtomicU32::new(0);
        let _: AppResult<()> = retrying(true, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(AppError::precondition_failed())
        })
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a failed header of the client is final"
        );
    }
}
