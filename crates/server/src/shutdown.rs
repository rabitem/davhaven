//! Graceful shutdown: the termination signal and the budget of the shutdown sequence.
//!
//! On `SIGTERM` (the orchestrator's stop) or `SIGINT` (Ctrl-C) the server
//!
//! 1. starts to answer `/readyz` with 503 `draining`, so that load balancers stop sending new requests, and keeps
//!    accepting connections for `server.shutdown_delay` (0 by default), the time a load balancer needs to notice;
//! 2. stops accepting connections on the public and internal listeners and gives the requests in flight
//!    `server.shutdown_grace` to finish, while the workers finish the pass they are in (up to the same time); what is still
//!    running at the end of the grace period is cut off, connections included;
//! 3. runs the shutdown hooks of the workers and of the adapters (the outbox dispatcher hands back the leases it still
//!    holds, so its records are due immediately on the next start and no attempt is lost; the database closes its pool),
//!    one after the other within [`HOOK_BUDGET`] together;
//! 4. stops the ops listener and flushes the traces within [`FLUSH_BUDGET`], and exits.
//!
//! **The bound.** The process is gone at most [`bound`] after the signal: `server.shutdown_delay` plus
//! `server.shutdown_grace` plus the fixed budgets of the hooks, the flush and the runtime ([`FIXED`], ten seconds).
//! A container needs a stop timeout longer than that, and the server logs the figure when it starts.
//!
//! [`Running::shutdown`](crate::server::Running::shutdown) implements the sequence; this module has what it needs
//! from the operating system and the helpers that bound a wait.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use davhaven_ports::Lifecycle;
use tokio::time::Instant;

/// How long all shutdown hooks (an adapter closing its resources, the dispatcher releasing its leases) may take together.
/// They share the budget: a slow hook leaves the later ones less.
pub const HOOK_BUDGET: Duration = Duration::from_secs(5);

/// How long the flush of the queued traces may take.
pub const FLUSH_BUDGET: Duration = Duration::from_secs(4);

/// How long the end of the runtime may take (a thread that is still blocked is left behind, the process ends anyway).
pub const RUNTIME_BUDGET: Duration = Duration::from_secs(1);

/// The fixed part of the bound: the three budgets above.
pub const FIXED: Duration = Duration::from_secs(10);

/// The longest the shutdown takes after the signal: the delay, the grace period and the fixed budgets.
pub const fn bound(delay: Duration, grace: Duration) -> Duration {
    delay.saturating_add(grace).saturating_add(FIXED)
}

/// Waits for `future` at most `limit`. `true` when it finished in time.
pub async fn within(limit: Duration, future: impl Future<Output = ()>) -> bool {
    tokio::time::timeout(limit, future).await.is_ok()
}

/// Runs the shutdown hooks one after the other, all within `budget`. A hook that does not finish in what is left of the
/// budget is abandoned (and logged), and so are the hooks after it when nothing is left. `true` when every hook finished.
pub async fn run_hooks<I>(budget: Duration, hooks: I) -> bool
where
    I: IntoIterator<Item = (String, Arc<dyn Lifecycle>)>,
{
    let deadline = Instant::now() + budget;
    let mut clean = true;
    for (name, hook) in hooks {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !within(remaining, hook.shutdown()).await {
            tracing::warn!(hook = %name, "a shutdown hook did not finish within the budget and was abandoned");
            clean = false;
        }
    }
    clean
}

/// Waits until the process is asked to stop and returns the name of the signal.
///
/// # Errors
///
/// The error of installing the signal handlers.
pub async fn termination_signal() -> std::io::Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        Ok(tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            _ = interrupt.recv() => "SIGINT",
        })
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok("Ctrl-C")
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_ports::Health;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_wait_is_bounded() {
        assert!(within(Duration::from_secs(5), async {}).await);
        assert!(!within(Duration::from_secs(5), std::future::pending::<()>()).await);
    }

    #[test]
    fn the_bound_adds_the_delay_the_grace_and_ten_seconds() {
        assert_eq!(bound(Duration::ZERO, Duration::from_secs(20)), Duration::from_secs(30));
        assert_eq!(
            bound(Duration::from_secs(5), Duration::from_secs(20)),
            Duration::from_secs(35)
        );
        assert_eq!(
            HOOK_BUDGET + FLUSH_BUDGET + RUNTIME_BUDGET,
            FIXED,
            "the fixed part is the sum of the budgets"
        );
        assert_eq!(bound(Duration::MAX, Duration::MAX), Duration::MAX, "no overflow");
    }

    /// A hook that takes `time` to shut down.
    struct Takes(Duration, Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait]
    impl Lifecycle for Takes {
        async fn health(&self) -> Health {
            Health::Healthy
        }

        async fn shutdown(&self) {
            tokio::time::sleep(self.0).await;
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn hook(name: &str, time: Duration, done: &Arc<std::sync::atomic::AtomicUsize>) -> (String, Arc<dyn Lifecycle>) {
        (name.to_owned(), Arc::new(Takes(time, Arc::clone(done))))
    }

    #[tokio::test(start_paused = true)]
    async fn the_hooks_share_one_budget_instead_of_five_seconds_each() {
        let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let before = Instant::now();
        let clean = run_hooks(
            HOOK_BUDGET,
            vec![
                hook("fast", Duration::from_secs(1), &done),
                hook("slow", Duration::from_secs(30), &done),
                hook("late", Duration::from_secs(1), &done),
            ],
        )
        .await;
        let elapsed = before.elapsed();
        assert!(!clean);
        assert_eq!(
            done.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the first hook finished, the slow one was abandoned at the end of the budget, the last had nothing left"
        );
        assert!(
            elapsed >= HOOK_BUDGET && elapsed < HOOK_BUDGET + Duration::from_secs(1),
            "three hooks of five seconds each would have taken fifteen: {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hooks_that_fit_the_budget_all_run() {
        let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let clean = run_hooks(
            HOOK_BUDGET,
            vec![
                hook("a", Duration::from_secs(1), &done),
                hook("b", Duration::from_secs(2), &done),
            ],
        )
        .await;
        assert!(clean);
        assert_eq!(done.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
