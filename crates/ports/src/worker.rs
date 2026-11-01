//! Background `Worker`s and the optional `Lifecycle` of built adapters.
//!
//! An adapter that needs background work (the outbox dispatcher, a rate limiter that evicts buckets, the sync
//! engine) hands its workers to the server in [`Built::workers`](crate::plugin::Built::workers). The server spawns
//! `run` for each and, on shutdown, cancels the token and waits for the grace period. Every worker also exposes
//! `tick`, one pass of its work, which tests call directly instead of sleeping (`ENGINEERING_RULES` R9).

use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

/// The health of an adapter, as reported by [`Lifecycle::health`] and `Database::health`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Working normally.
    Healthy,
    /// Working with reduced capability; the text says what is wrong. `/readyz` still reports ready.
    Degraded(String),
    /// Not working; `/readyz` reports not ready.
    Unhealthy(String),
}

impl Health {
    /// Whether `/readyz` may report ready: healthy or degraded.
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded(_))
    }

    /// A stable `snake_case` name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded(_) => "degraded",
            Self::Unhealthy(_) => "unhealthy",
        }
    }
}

/// Optional lifecycle hooks of a built adapter.
#[async_trait]
pub trait Lifecycle: Send + Sync {
    /// The current health (used by `/readyz`).
    async fn health(&self) -> Health;

    /// Releases resources: closes pools, flushes buffers, releases leases. Called once on shutdown after the
    /// workers have stopped.
    async fn shutdown(&self);
}

/// What one pass of a worker did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkReport {
    /// Items handled successfully.
    pub processed: u32,
    /// Items that failed (and were rescheduled or dead-lettered).
    pub failed: u32,
    /// Whether more work is ready right now (a full batch), so the worker runs again without waiting.
    pub more: bool,
}

impl WorkReport {
    /// A pass that found nothing to do.
    pub const fn idle() -> Self {
        Self {
            processed: 0,
            failed: 0,
            more: false,
        }
    }

    /// Whether the pass did nothing and left nothing ready.
    pub const fn is_idle(&self) -> bool {
        self.processed == 0 && self.failed == 0 && !self.more
    }
}

/// A background worker.
#[async_trait]
pub trait Worker: Send + Sync {
    /// The worker's name, for logs, metrics and heartbeats.
    fn name(&self) -> &'static str;

    /// How long the worker sleeps between passes when it has nothing ready. `/readyz` requires a heartbeat
    /// younger than twice this interval.
    fn interval(&self) -> Duration;

    /// Runs one pass: claims ready work, handles it and reports what happened. Tests call this directly.
    async fn tick(&self) -> WorkReport;

    /// Runs passes until `cancel` fires: a pass, then a sleep of `interval` unless the pass reports more ready
    /// work. Implementations override this only when they need a different loop.
    async fn run(&self, cancel: CancellationToken) {
        while !cancel.is_cancelled() {
            let report = self.tick().await;
            if !report.more {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(self.interval()) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    struct Counting {
        ticks: AtomicU32,
        more_for: u32,
    }

    #[async_trait]
    impl Worker for Counting {
        fn name(&self) -> &'static str {
            "counting"
        }

        fn interval(&self) -> Duration {
            Duration::from_secs(10)
        }

        async fn tick(&self) -> WorkReport {
            let n = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
            WorkReport {
                processed: 1,
                failed: 0,
                more: n < self.more_for,
            }
        }
    }

    #[test]
    fn reports_and_health() {
        assert!(WorkReport::idle().is_idle());
        assert!(WorkReport::default().is_idle());
        assert!(
            !WorkReport {
                processed: 1,
                ..WorkReport::idle()
            }
            .is_idle()
        );
        assert!(
            !WorkReport {
                failed: 1,
                ..WorkReport::idle()
            }
            .is_idle()
        );
        assert!(
            !WorkReport {
                more: true,
                ..WorkReport::idle()
            }
            .is_idle()
        );
        assert!(Health::Healthy.is_ready());
        assert!(Health::Degraded("slow".to_owned()).is_ready());
        assert!(!Health::Unhealthy("down".to_owned()).is_ready());
        assert_eq!(Health::Healthy.as_str(), "healthy");
        assert_eq!(Health::Degraded(String::new()).as_str(), "degraded");
        assert_eq!(Health::Unhealthy("down".to_owned()).as_str(), "unhealthy");
    }

    #[tokio::test(start_paused = true)]
    async fn run_drains_ready_work_then_sleeps_for_the_interval() {
        let worker = Arc::new(Counting {
            ticks: AtomicU32::new(0),
            more_for: 3,
        });
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let worker = Arc::clone(&worker);
            let cancel = cancel.clone();
            async move { worker.run(cancel).await }
        });

        // Three back-to-back passes (the first two report more work), then the worker sleeps.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(worker.ticks.load(Ordering::SeqCst), 3);

        // One interval later it runs once more.
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(worker.ticks.load(Ordering::SeqCst), 4);

        cancel.cancel();
        task.await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(
            worker.ticks.load(Ordering::SeqCst),
            4,
            "a cancelled worker stops ticking"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn run_returns_immediately_when_already_cancelled() {
        let worker = Counting {
            ticks: AtomicU32::new(0),
            more_for: 0,
        };
        let cancel = CancellationToken::new();
        cancel.cancel();
        worker.run(cancel).await;
        assert_eq!(worker.ticks.load(Ordering::SeqCst), 0);
    }
}
