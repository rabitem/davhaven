//! The worker that keeps the signer of Apple configuration profiles current with its files, and the gauge of its certificate.
//!
//! [`ReloadingProfileSigner`] does the reloading (see `davhaven_crypto_local::profile::reload`): it compares the metadata of
//! the certificate file and the key file with that of the files it was read from, and only a difference makes it read them and
//! replace the signer, never with a pair that cannot be used. What the server adds is the schedule, the rule for blocking work,
//! the log and the metric:
//!
//! * **One pass a minute** ([`CHECK_INTERVAL`]) on the supervisor like every other worker, so `/readyz` and
//!   `davhaven_worker_*` cover it. The pass takes its time from the `Clock` port and hands it to the signer, which looks at
//!   the files at most once per [`CHECK_INTERVAL`] by that time.
//! * **The file I/O runs on the blocking pool** (`spawn_blocking`, `ENGINEERING_RULES` R14) with a time budget
//!   ([`CHECK_BUDGET`]), never on an async worker thread. Signing never waits for a file: it takes the signer in use from a lock
//!   that is held for one pointer copy. A file system that hangs (a mount that went away) ends the pass at the budget and
//!   costs one blocked thread, not one per minute, because the signer starts no check while one is running.
//! * **A new pair that cannot be used** (a key that does not belong to the certificate, a half-written or damaged file, a
//!   certificate that has ended or that does not say when it ends) is a warning with the reason, which names the key and the
//!   file and never contains key material. The signer in use stays and the pass counts as failed in
//!   `davhaven_worker_passes_total{worker="profile_signing", outcome="failed"}`, at every check for as long as the files stay
//!   as they are (a pair that was refused is not read again until its files change).
//! * **A check that hangs shows**: the pass that ends at the budget is a failed pass with a warning, and so is every pass after
//!   it that finds the check still running (`Refresh::Busy`), for as long as the mount stays hung.
//! * **The gauge** [`CERTIFICATE_EXPIRY_TIMESTAMP_SECONDS`] is the end of the validity of the certificate in use, in unix
//!   seconds. It is set by every pass, so it follows a renewal within a minute, and it is never set while signing is off: no
//!   worker exists then, and the series is absent.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_crypto_local::profile::{CHECK_INTERVAL, Refresh, ReloadingProfileSigner};
use davhaven_ports::{Clock, WorkReport, Worker};

/// The gauge of the end of the validity of the certificate the profile signer uses (the `notAfter` of the first certificate of
/// the file, the one that signs), in seconds since the epoch. Absent while profile signing is off.
pub const CERTIFICATE_EXPIRY_TIMESTAMP_SECONDS: &str = "davhaven_profile_signing_certificate_expiry_timestamp_seconds";

/// How long one pass waits for the check of the files. A check reads two small files and normally takes microseconds; a pass
/// that waits this long means a file system that hangs.
pub const CHECK_BUDGET: Duration = Duration::from_secs(30);

/// The name of the worker, in the logs, in `/readyz` and as the `worker` label of the worker metrics.
pub const WORKER_NAME: &str = "profile_signing";

/// The unix seconds of `time` as a gauge value: exact for every time before the year 2106, and saturating beyond (nobody reads
/// a certificate that far out; see `gauge_value` of the outbox dispatcher for the same rule).
fn unix_seconds(time: DateTime<Utc>) -> f64 {
    f64::from(u32::try_from(time.timestamp().max(0)).unwrap_or(u32::MAX))
}

/// Keeps the profile signer current with its files (see the module documentation).
pub struct ProfileSigningWorker {
    signer: Arc<ReloadingProfileSigner>,
    clock: Arc<dyn Clock>,
    budget: Duration,
}

impl core::fmt::Debug for ProfileSigningWorker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProfileSigningWorker")
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl ProfileSigningWorker {
    /// A worker for `signer` that takes its time from `clock` and waits [`CHECK_BUDGET`] for a check.
    pub fn new(signer: Arc<ReloadingProfileSigner>, clock: Arc<dyn Clock>) -> Self {
        Self {
            signer,
            clock,
            budget: CHECK_BUDGET,
        }
    }

    /// The same worker with another budget for a check (the tests of the cut-off use a short one).
    #[must_use]
    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// Sets the gauge from the certificate in use. A certificate that does not say when it ends leaves the series as it is.
    fn publish(&self) {
        if let Some(end) = self.signer.not_after() {
            metrics::gauge!(CERTIFICATE_EXPIRY_TIMESTAMP_SECONDS).set(unix_seconds(end));
        }
    }

    /// Logs what the check did and says what the pass did.
    fn report(outcome: &Refresh) -> WorkReport {
        match outcome {
            Refresh::NotDue | Refresh::Unchanged => WorkReport::idle(),
            // A check that is still running when the next one is due (a whole interval later, far beyond its budget) hangs on the
            // file system. That must show: a failed pass, which the outcome metric counts, and a warning, for as long as it lasts.
            Refresh::Busy => {
                tracing::warn!(
                    "the previous check of the profile signing files has not ended and no other starts: is the file system of \
                     the certificate reachable? Signing goes on with the certificate in use"
                );
                WorkReport {
                    processed: 0,
                    failed: 1,
                    more: false,
                }
            }
            Refresh::Reloaded { not_after, generation } => {
                tracing::info!(
                    generation,
                    not_after = not_after.map(|end| end.to_rfc3339()),
                    "the profile signer picked up a renewed certificate"
                );
                WorkReport {
                    processed: 1,
                    failed: 0,
                    more: false,
                }
            }
            Refresh::Kept { reason } => {
                tracing::warn!(
                    reason,
                    "the profile signer keeps the certificate in use: the files of `[security.profile_signing]` cannot be used"
                );
                WorkReport {
                    processed: 0,
                    failed: 1,
                    more: false,
                }
            }
        }
    }
}

#[async_trait]
impl Worker for ProfileSigningWorker {
    fn name(&self) -> &'static str {
        WORKER_NAME
    }

    fn interval(&self) -> Duration {
        CHECK_INTERVAL
    }

    async fn tick(&self) -> WorkReport {
        let signer = Arc::clone(&self.signer);
        let now = self.clock.now();
        let check = tokio::task::spawn_blocking(move || signer.refresh(now));
        let report = match tokio::time::timeout(self.budget, check).await {
            Ok(Ok(outcome)) => Self::report(&outcome),
            Ok(Err(error)) => {
                tracing::error!(%error, "the check of the profile signing files ended abnormally");
                WorkReport {
                    processed: 0,
                    failed: 1,
                    more: false,
                }
            }
            Err(_) => {
                tracing::warn!(
                    budget_seconds = self.budget.as_secs(),
                    "the check of the profile signing files did not end in time: is the file system of the certificate \
                     reachable? Signing goes on with the certificate in use, and no other check starts before this one ends"
                );
                WorkReport {
                    processed: 0,
                    failed: 1,
                    more: false,
                }
            }
        };
        self.publish();
        report
    }
}

#[cfg(test)]
mod tests;
