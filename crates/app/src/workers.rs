//! Background workers of the application (outbox, retention, provider sync).
//!
//! [`build`] creates the workers the application itself needs, from the shared [`AppCore`]: the outbox dispatcher, the
//! retention worker and, when a calendar provider is switched on, the provider sync worker. The server adds the workers that adapters contribute through the plugin registry
//! (`Built::workers`: the credential `last_used_at` flusher, the rate limiter's eviction) and supervises all of
//! them: it drives [`Worker::tick`], records a heartbeat for `/readyz` and, on shutdown, stops the workers and then
//! runs the [`Lifecycle`] hooks returned here.
//!
//! This is the one place where the workers of the application are registered, so that a feature that
//! brings a worker (the provider sync engine) adds one line to [`build`], and one that brings an outbox handler adds it to
//! [`crate::outbox::handlers`] (the scheduling use cases did so for `internal_delivery`); nothing changes in the server.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use davhaven_ports::{Health, Lifecycle, WorkReport, Worker};

use crate::outbox::{OutboxDispatcher, new_dispatcher};
use crate::retention::RetentionWorker;
use crate::sync_engine::ProviderSyncWorker;
use crate::wiring::AppCore;

/// The workers of the application and the hooks that must run after they have stopped.
#[derive(Default)]
pub struct AppWorkers {
    /// The workers, to be supervised by the server.
    pub workers: Vec<Arc<dyn Worker>>,
    /// Shutdown hooks of the workers (the outbox dispatcher hands back the leases it still holds).
    pub lifecycles: Vec<Arc<dyn Lifecycle>>,
}

impl core::fmt::Debug for AppWorkers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: Vec<&'static str> = self.workers.iter().map(|worker| worker.name()).collect();
        f.debug_struct("AppWorkers")
            .field("workers", &names)
            .field("lifecycles", &self.lifecycles.len())
            .finish()
    }
}

/// The outbox dispatcher as a supervised worker.
///
/// The supervisor drives [`Worker::tick`] itself (it needs a heartbeat after every pass), so the lease release that
/// the dispatcher's own `run` loop does after the last pass is a [`Lifecycle`] hook of this wrapper: after the
/// workers have stopped, [`Lifecycle::shutdown`] hands back the claims of a pass that was cut off, so the records
/// are due at once on the next start without having used an attempt.
pub struct OutboxWorker {
    dispatcher: Arc<OutboxDispatcher>,
}

impl OutboxWorker {
    /// Wraps the dispatcher.
    pub const fn new(dispatcher: Arc<OutboxDispatcher>) -> Self {
        Self { dispatcher }
    }
}

impl core::fmt::Debug for OutboxWorker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutboxWorker")
            .field("kinds", &self.dispatcher.kinds())
            .finish()
    }
}

#[async_trait]
impl Worker for OutboxWorker {
    fn name(&self) -> &'static str {
        self.dispatcher.name()
    }

    fn interval(&self) -> Duration {
        self.dispatcher.interval()
    }

    async fn tick(&self) -> WorkReport {
        self.dispatcher.tick().await
    }
}

#[async_trait]
impl Lifecycle for OutboxWorker {
    async fn health(&self) -> Health {
        Health::Healthy
    }

    async fn shutdown(&self) {
        let released = self.dispatcher.release_held().await;
        if released > 0 {
            tracing::info!(released, "released the outbox leases of the pass that was cut off");
        }
    }
}

/// Creates the workers of the application on `core`.
pub fn build(core: &AppCore) -> AppWorkers {
    let dispatcher = Arc::new(new_dispatcher(core, std::iter::empty()));
    let outbox = Arc::new(OutboxWorker::new(dispatcher));
    let lifecycle: Arc<dyn Lifecycle> = Arc::<OutboxWorker>::clone(&outbox);
    let outbox_worker: Arc<dyn Worker> = outbox;
    let retention: Arc<dyn Worker> = Arc::new(RetentionWorker::new(core.clone()));
    let mut workers = vec![outbox_worker, retention];
    // A deployment without a provider that is switched on runs no sync worker (PLAN 4.2: a disabled provider has no workers).
    if core.deps().providers.iter().any(|provider| provider.enabled()) {
        workers.push(Arc::new(ProviderSyncWorker::new(core.clone())));
    }
    AppWorkers {
        workers,
        lifecycles: vec![lifecycle],
    }
}
