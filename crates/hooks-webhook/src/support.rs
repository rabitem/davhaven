//! Test doubles of this crate: a database that is never reachable and a plugin context built on it.
//!
//! The handler needs a real store for what it does (the deliveries and the subscriptions of a tenant), and the
//! tests that run it live in `davhaven-it` on the in-memory store, where the claim, the settling of outbox
//! records and the tenant rules are the store's own and not a double's. Here are the tests that need no store: the
//! classification of answers, the request that is built, the plugin registration.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::TenantId;
use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
use davhaven_ports::{
    Database, Health, HttpClient, OutboundRequest, OutboundResponse, PluginContext, PortError, RunMode, StoreError,
    SystemTx, Tx, TxMode,
};

/// A database that refuses every transaction: enough to build the plugins, which open none while they are built.
pub(crate) struct NoDatabase;

#[async_trait]
impl Database for NoDatabase {
    async fn begin(&self, _tenant: TenantId, _mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn health(&self) -> Health {
        Health::Unhealthy("no database".to_owned())
    }
}

/// An HTTP client that never sends.
pub(crate) struct NoHttp;

#[async_trait]
impl HttpClient for NoHttp {
    async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        Err(PortError::internal("the test double does not send"))
    }
}

/// The ports a handler is built from.
pub(crate) struct Ports {
    pub(crate) context: PluginContext,
    pub(crate) clock: ManualClock,
}

impl Ports {
    pub(crate) fn new() -> Self {
        let clock = ManualClock::default();
        let context = PluginContext::new(
            Arc::new(clock.clone()),
            Arc::new(SeqIds::starting_at(0x1000)),
            Arc::new(FixedKeyRing::default()),
            Arc::new(PlainSealer),
            Arc::new(FixedHasher::default()),
            RunMode::Dev,
        )
        .with_http(Arc::new(NoHttp))
        .with_database(Arc::new(NoDatabase));
        Self { context, clock }
    }
}
