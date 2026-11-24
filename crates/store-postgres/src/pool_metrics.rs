//! Runtime pool occupancy, sampled by a managed worker, and cancellation-safe acquisition counts.

use std::time::Duration;

use async_trait::async_trait;
use davhaven_ports::{StoreError, WorkReport, Worker};
use metrics::Gauge;
use sqlx::pool::PoolConnection;
use sqlx::{PgPool, Postgres};

use crate::error::map_sqlx;

/// Metrics of the runtime pool only; migration and command-line pools are not included.
pub(crate) struct PoolMetrics {
    pool: PgPool,
    in_use: Gauge,
    waiting: Gauge,
}

impl PoolMetrics {
    pub(crate) fn new(pool: PgPool) -> Self {
        let this = Self {
            pool,
            in_use: metrics::gauge!("davhaven_db_pool_in_use"),
            waiting: metrics::gauge!("davhaven_db_pool_waiting"),
        };
        this.waiting.increment(0.0);
        this.sample();
        this
    }

    /// Counts the acquisition itself, including connection creation and validation, but not `BEGIN` or queries.
    pub(crate) async fn acquire(&self) -> Result<PoolConnection<Postgres>, StoreError> {
        self.waiting.increment(1.0);
        let _waiting = Waiting(self.waiting.clone());
        self.pool.acquire().await.map_err(map_sqlx)
    }

    fn sample(&self) {
        // SQLx returns connections asynchronously after commit or drop. Sampling its actual state avoids a
        // last-transaction snapshot staying nonzero forever. The two reads are not an atomic pool snapshot.
        let idle = u32::try_from(self.pool.num_idle()).unwrap_or(u32::MAX);
        self.in_use.set(f64::from(self.pool.size().saturating_sub(idle)));
    }
}

/// Kept across the await, so errors, timeouts and cancellation all remove the pending acquisition.
struct Waiting(Gauge);

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}

#[async_trait]
impl Worker for PoolMetrics {
    fn name(&self) -> &'static str {
        "postgres_pool_metrics"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(1)
    }

    async fn tick(&self) -> WorkReport {
        self.sample();
        WorkReport::idle()
    }
}
