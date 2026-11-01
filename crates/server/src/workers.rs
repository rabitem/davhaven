//! Spawning and supervision of background workers.
//!
//! Every worker of the process (the workers of the application, those that adapters return from their `build`, and the one
//! that keeps the profile signer current, `profile_signing`) is driven by one task of the [`Supervisor`]. The task calls
//! [`Worker::tick`], sleeps for the worker's interval
//! unless the pass says that more work is ready, and records a **heartbeat** around every pass. `/readyz` reads the
//! heartbeats: a worker is unhealthy when it
//!
//! * is idle and has not completed a pass for more than twice its interval, or
//! * has been inside one pass for longer than [`PASS_STALL_LIMIT`] (and twice its interval), which is the
//!   signature of a pass that hangs; a pass that merely takes long, like a batch of slow mail relays, is not one.
//!
//! A pass that panics is logged and counted, does not take the loop down and does not refresh the heartbeat, so a
//! worker that panics on every pass turns unhealthy after two intervals.
//!
//! The supervisor drives `tick`, not [`Worker::run`]: it needs the heartbeat after every pass, and a worker's own
//! `run` loop cannot report it. Work a custom `run` loop would do on shutdown belongs in the worker's
//! [`Lifecycle`](davhaven_ports::Lifecycle) hook, which the server runs after the workers have stopped (the outbox
//! dispatcher hands back its leases there).
//!
//! On shutdown the supervisor lets a pass that is running finish for up to the drain time and then drops it; the
//! worker does not start another pass.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use davhaven_ports::{WorkReport, Worker};
use futures::FutureExt as _;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// The longest a single pass may run before `/readyz` calls the worker stalled.
pub const PASS_STALL_LIMIT: Duration = Duration::from_mins(5);

/// The gauge of the seconds since a worker last completed a pass (a pass that panicked is no progress, and a pass that is
/// still running does not refresh it).
pub const HEARTBEAT_AGE_SECONDS: &str = "davhaven_worker_heartbeat_age_seconds";

/// The counter of passes, labelled with the worker and the outcome (`ok`, `failed`, `panicked`).
pub const PASSES_TOTAL: &str = "davhaven_worker_passes_total";

/// What `/readyz` knows about one worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerStatus {
    /// The worker's name.
    pub name: &'static str,
    /// Whether the worker is making progress.
    pub healthy: bool,
    /// What is wrong, when it is not healthy.
    pub detail: Option<String>,
}

/// The heartbeat state of one worker. Times are milliseconds since the supervisor started.
#[derive(Debug)]
struct Beat {
    name: &'static str,
    started: Instant,
    interval_ms: AtomicU64,
    last_beat_ms: AtomicU64,
    /// When the running pass began, plus one; zero while the worker is idle.
    pass_started_ms: AtomicU64,
}

impl Beat {
    fn new(name: &'static str, interval: Duration, started: Instant) -> Self {
        Self {
            name,
            started,
            interval_ms: AtomicU64::new(millis(interval)),
            last_beat_ms: AtomicU64::new(0),
            pass_started_ms: AtomicU64::new(0),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        millis(Instant::now().saturating_duration_since(self.started))
    }

    /// A pass begins. Only a pass that completes refreshes the heartbeat, so a worker whose every pass panics
    /// turns unhealthy while a long pass that is still running does not (it is judged by [`PASS_STALL_LIMIT`]).
    fn begin_pass(&self, interval: Duration) {
        let now = self.elapsed_ms();
        self.interval_ms.store(millis(interval), Ordering::Relaxed);
        self.pass_started_ms.store(now.saturating_add(1), Ordering::Relaxed);
    }

    /// The pass ended; a pass that did not panic is progress.
    fn end_pass(&self, progress: bool) {
        self.pass_started_ms.store(0, Ordering::Relaxed);
        if progress {
            self.last_beat_ms.store(self.elapsed_ms(), Ordering::Relaxed);
        }
    }

    fn age(&self) -> Duration {
        Duration::from_millis(
            self.elapsed_ms()
                .saturating_sub(self.last_beat_ms.load(Ordering::Relaxed)),
        )
    }

    fn status(&self) -> WorkerStatus {
        let interval = Duration::from_millis(self.interval_ms.load(Ordering::Relaxed));
        let limit = interval.saturating_mul(2);
        let pass_started = self.pass_started_ms.load(Ordering::Relaxed);
        let (healthy, detail) = if pass_started == 0 {
            let age = self.age();
            if age > limit {
                (
                    false,
                    Some(format!(
                        "no pass has completed for {}s (interval {}s)",
                        age.as_secs(),
                        interval.as_secs()
                    )),
                )
            } else {
                (true, None)
            }
        } else {
            let running = Duration::from_millis(self.elapsed_ms().saturating_sub(pass_started.saturating_sub(1)));
            if running > PASS_STALL_LIMIT.max(limit) {
                (
                    false,
                    Some(format!("one pass has been running for {}s", running.as_secs())),
                )
            } else {
                (true, None)
            }
        };
        WorkerStatus {
            name: self.name,
            healthy,
            detail,
        }
    }
}

/// Milliseconds of a duration, saturating.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// A shared view of the heartbeats of all workers, for `/readyz` and the metrics.
#[derive(Debug, Clone, Default)]
pub struct Heartbeats {
    beats: Arc<Vec<Arc<Beat>>>,
}

impl Heartbeats {
    /// The status of every worker.
    pub fn statuses(&self) -> Vec<WorkerStatus> {
        self.beats.iter().map(|beat| beat.status()).collect()
    }

    /// Sets the heartbeat-age gauge of every worker; called before `/metrics` is rendered.
    pub fn publish(&self) {
        for beat in self.beats.iter() {
            metrics::gauge!(HEARTBEAT_AGE_SECONDS, "worker" => beat.name).set(beat.age().as_secs_f64());
        }
    }

    /// The number of supervised workers.
    pub(crate) fn len(&self) -> usize {
        self.beats.len()
    }
}

/// Drives a set of workers.
pub struct Supervisor {
    workers: Vec<(Arc<dyn Worker>, Arc<Beat>)>,
    heartbeats: Heartbeats,
}

impl core::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: Vec<&'static str> = self.workers.iter().map(|(worker, _)| worker.name()).collect();
        f.debug_struct("Supervisor")
            .field("workers", &names)
            .finish_non_exhaustive()
    }
}

impl Supervisor {
    /// A supervisor for `workers`. Each starts with a fresh heartbeat. When two workers share a name the second is
    /// still supervised; both appear in the statuses.
    pub fn new(workers: Vec<Arc<dyn Worker>>) -> Self {
        let started = Instant::now();
        let entries: Vec<(Arc<dyn Worker>, Arc<Beat>)> = workers
            .into_iter()
            .map(|worker| {
                let beat = Arc::new(Beat::new(worker.name(), worker.interval(), started));
                (worker, beat)
            })
            .collect();
        let beats = entries.iter().map(|(_, beat)| Arc::clone(beat)).collect();
        Self {
            workers: entries,
            heartbeats: Heartbeats { beats: Arc::new(beats) },
        }
    }

    /// The heartbeats, to be read by `/readyz`.
    pub fn heartbeats(&self) -> Heartbeats {
        self.heartbeats.clone()
    }

    /// Spawns one task per worker. The tasks stop when `cancel` fires, after the pass in flight has had `drain` to
    /// finish.
    pub fn spawn(self, cancel: &CancellationToken, drain: Duration) -> RunningWorkers {
        let mut tasks = JoinSet::new();
        for (worker, beat) in self.workers {
            let cancel = cancel.clone();
            tasks.spawn(async move { drive(worker, beat, cancel, drain).await });
        }
        RunningWorkers { tasks }
    }
}

/// The tasks of the workers.
#[derive(Debug)]
pub struct RunningWorkers {
    tasks: JoinSet<()>,
}

impl RunningWorkers {
    /// Waits for every worker task to end (they end once the cancellation token fired and their pass drained).
    #[cfg(test)]
    pub(crate) async fn join(mut self) {
        self.drain_tasks().await;
    }

    /// Waits at most `limit` for the worker tasks to end and aborts the ones that are still running after it.
    /// Returns `true` when none had to be aborted.
    pub async fn stop(mut self, limit: Duration) -> bool {
        let finished = tokio::time::timeout(limit, self.drain_tasks()).await.is_ok();
        if !finished {
            tracing::warn!("workers did not stop in time and are cut off");
            self.tasks.abort_all();
            self.drain_tasks().await;
        }
        finished
    }

    async fn drain_tasks(&mut self) {
        while let Some(result) = self.tasks.join_next().await {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                tracing::error!(%error, "a worker task ended abnormally");
            }
        }
    }
}

/// One pass of `worker`, with panics turned into a failed pass.
async fn pass(worker: &dyn Worker) -> Option<WorkReport> {
    match AssertUnwindSafe(worker.tick()).catch_unwind().await {
        Ok(report) => Some(report),
        Err(_panic) => {
            tracing::error!(worker = worker.name(), "a worker pass panicked");
            None
        }
    }
}

/// The loop of one worker.
async fn drive(worker: Arc<dyn Worker>, beat: Arc<Beat>, cancel: CancellationToken, drain: Duration) {
    let name = worker.name();
    tracing::debug!(worker = name, "worker started");
    while !cancel.is_cancelled() {
        beat.begin_pass(worker.interval());
        let running = pass(worker.as_ref());
        tokio::pin!(running);
        let outcome = tokio::select! {
            outcome = &mut running => Some(outcome),
            () = cancel.cancelled() => tokio::time::timeout(drain, &mut running).await.ok(),
        };
        let Some(outcome) = outcome else {
            tracing::warn!(worker = name, "a worker pass was cut off by the shutdown");
            beat.end_pass(false);
            break;
        };
        beat.end_pass(outcome.is_some());
        let label = match &outcome {
            Some(report) if report.failed == 0 => "ok",
            Some(_) => "failed",
            None => "panicked",
        };
        metrics::counter!(PASSES_TOTAL, "worker" => name, "outcome" => label).increment(1);
        if outcome.is_some_and(|report| report.more) {
            continue;
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(worker.interval()) => {}
        }
    }
    tracing::debug!(worker = name, "worker stopped");
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use async_trait::async_trait;

    use super::*;

    #[test]
    fn the_sync_engine_is_validated_against_the_stall_limit_of_readyz() {
        assert_eq!(
            davhaven_app::sync_engine::STALL_LIMIT,
            PASS_STALL_LIMIT,
            "the application checks the passes of the sync worker against the limit that `/readyz` applies"
        );
    }

    struct Scripted {
        name: &'static str,
        interval: Duration,
        ticks: AtomicU32,
        behaviour: Behaviour,
    }

    enum Behaviour {
        Idle,
        More(u32),
        Slow(Duration),
        Panic,
        Hang,
    }

    #[async_trait]
    impl Worker for Scripted {
        fn name(&self) -> &'static str {
            self.name
        }

        fn interval(&self) -> Duration {
            self.interval
        }

        async fn tick(&self) -> WorkReport {
            let n = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
            match &self.behaviour {
                Behaviour::Idle => WorkReport::idle(),
                Behaviour::More(limit) => WorkReport {
                    processed: 1,
                    failed: 0,
                    more: n < *limit,
                },
                Behaviour::Slow(time) => {
                    tokio::time::sleep(*time).await;
                    WorkReport::idle()
                }
                Behaviour::Panic => panic!("the pass fails"),
                Behaviour::Hang => std::future::pending().await,
            }
        }
    }

    fn worker(name: &'static str, interval: Duration, behaviour: Behaviour) -> Arc<Scripted> {
        Arc::new(Scripted {
            name,
            interval,
            ticks: AtomicU32::new(0),
            behaviour,
        })
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_worker_beats_every_interval_and_stays_healthy() {
        let idle = worker("idle", Duration::from_secs(10), Behaviour::Idle);
        let supervisor = Supervisor::new(vec![Arc::<Scripted>::clone(&idle)]);
        let heartbeats = supervisor.heartbeats();
        let cancel = CancellationToken::new();
        let running = supervisor.spawn(&cancel, Duration::from_secs(1));
        for _ in 0..12 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            assert!(
                heartbeats.statuses().iter().all(|status| status.healthy),
                "{:?}",
                heartbeats.statuses()
            );
        }
        assert!(idle.ticks.load(Ordering::SeqCst) >= 12);
        cancel.cancel();
        running.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_pass_with_more_work_runs_again_at_once() {
        let busy = worker("busy", Duration::from_secs(60), Behaviour::More(4));
        let supervisor = Supervisor::new(vec![Arc::<Scripted>::clone(&busy)]);
        let cancel = CancellationToken::new();
        let running = supervisor.spawn(&cancel, Duration::from_secs(1));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            busy.ticks.load(Ordering::SeqCst),
            4,
            "four back-to-back passes, then the interval"
        );
        cancel.cancel();
        running.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_pass_is_not_a_stall_but_a_hung_one_is() {
        let slow = worker("slow", Duration::from_secs(2), Behaviour::Slow(Duration::from_secs(60)));
        let hung = worker("hung", Duration::from_secs(2), Behaviour::Hang);
        let supervisor = Supervisor::new(vec![slow, hung]);
        let heartbeats = supervisor.heartbeats();
        let cancel = CancellationToken::new();
        let running = supervisor.spawn(&cancel, Duration::from_secs(1));
        tokio::time::sleep(Duration::from_secs(30)).await;
        let statuses = heartbeats.statuses();
        assert!(
            statuses.iter().all(|status| status.healthy),
            "a pass of 30 s is no stall: {statuses:?}"
        );
        tokio::time::sleep(PASS_STALL_LIMIT).await;
        let statuses = heartbeats.statuses();
        let by_name = |name: &str| statuses.iter().find(|status| status.name == name).unwrap().clone();
        assert!(!by_name("hung").healthy, "{statuses:?}");
        assert!(by_name("hung").detail.unwrap().contains("running for"));
        cancel.cancel();
        running.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_worker_that_panics_every_pass_turns_unhealthy_but_keeps_running() {
        let panicking = worker("panicking", Duration::from_secs(10), Behaviour::Panic);
        let supervisor = Supervisor::new(vec![Arc::<Scripted>::clone(&panicking)]);
        let heartbeats = supervisor.heartbeats();
        let cancel = CancellationToken::new();
        let running = supervisor.spawn(&cancel, Duration::from_secs(1));
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(heartbeats.statuses()[0].healthy, "the initial heartbeat counts");
        tokio::time::sleep(Duration::from_secs(60)).await;
        let status = heartbeats.statuses().remove(0);
        assert!(
            !status.healthy
                && status
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("no pass has completed")),
            "{status:?}"
        );
        assert!(panicking.ticks.load(Ordering::SeqCst) >= 6, "the loop keeps trying");
        cancel.cancel();
        running.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_lets_a_pass_drain_and_cuts_off_a_hung_one() {
        let slow = worker("slow", Duration::from_secs(60), Behaviour::Slow(Duration::from_secs(3)));
        let hung = worker("hung", Duration::from_secs(60), Behaviour::Hang);
        let supervisor = Supervisor::new(vec![Arc::<Scripted>::clone(&slow), hung]);
        let cancel = CancellationToken::new();
        let running = supervisor.spawn(&cancel, Duration::from_secs(5));
        tokio::time::sleep(Duration::from_secs(1)).await;
        cancel.cancel();
        let before = Instant::now();
        running.join().await;
        let waited = before.elapsed();
        assert!(
            waited >= Duration::from_secs(5),
            "the hung pass waited for the drain: {waited:?}"
        );
        assert!(waited < Duration::from_secs(6), "and was then cut off: {waited:?}");
        assert_eq!(slow.ticks.load(Ordering::SeqCst), 1, "no new pass after the shutdown");
    }

    #[tokio::test(start_paused = true)]
    async fn stopping_aborts_the_workers_that_outlast_the_limit_and_says_so() {
        // The server stops the workers within the grace period even when the drain a worker was given is longer.
        let hung = worker("hung", Duration::from_secs(60), Behaviour::Hang);
        let cancel = CancellationToken::new();
        let running = Supervisor::new(vec![hung]).spawn(&cancel, Duration::from_secs(3600));
        tokio::time::sleep(Duration::from_secs(1)).await;
        cancel.cancel();
        let before = Instant::now();
        assert!(!running.stop(Duration::from_secs(2)).await, "a worker was cut off");
        let waited = before.elapsed();
        assert!(
            waited >= Duration::from_secs(2) && waited < Duration::from_secs(3),
            "{waited:?}"
        );

        let idle = worker("idle", Duration::from_secs(60), Behaviour::Idle);
        let cancel = CancellationToken::new();
        let running = Supervisor::new(vec![idle]).spawn(&cancel, Duration::from_secs(5));
        tokio::time::sleep(Duration::from_secs(1)).await;
        cancel.cancel();
        assert!(
            running.stop(Duration::from_secs(2)).await,
            "an idle worker stops at once"
        );
    }

    #[test]
    fn workers_with_the_same_name_are_all_supervised() {
        assert_eq!(Supervisor::new(Vec::new()).heartbeats().len(), 0);
        let twins = Supervisor::new(vec![
            worker("outbox", Duration::from_secs(10), Behaviour::Idle),
            worker("outbox", Duration::from_secs(10), Behaviour::Idle),
        ]);
        let statuses = twins.heartbeats().statuses();
        assert_eq!(statuses.len(), 2, "{statuses:?}");
        assert!(statuses.iter().all(|status| status.name == "outbox" && status.healthy));
    }
}
