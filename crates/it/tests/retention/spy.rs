//! A store that watches the cleanup worker.
//!
//! [`Spy`] wraps a database and records the cut-off every cleanup call of a pass received, in order. It can also play
//! the roles a deployment may give the worker: a connection that is not allowed to purge the audit log, a store without
//! the delivery purge, and a store that always finds one more row to remove (a backlog that never ends within a pass).
//! Everything else is the wrapped store.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_testkit::davhaven_domain::{CalendarId, PrincipalId, TenantId};
use davhaven_testkit::davhaven_ports::{
    AuditPurge, CredentialLookup, Database, Health, OutboxQueue, RetentionRepo, StoreError, SystemTenantRepo, SystemTx,
    Tx, TxMode,
};
use tokio::sync::Mutex;

/// A cleanup call and the cut-off it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call {
    /// `purge_outbox`.
    Outbox {
        done_before: DateTime<Utc>,
        dead_before: DateTime<Utc>,
    },
    /// `purge_deliveries`.
    Deliveries(DateTime<Utc>),
    /// `prune_changes`.
    Changes(DateTime<Utc>),
    /// `purge_audit_checked`.
    Audit(DateTime<Utc>),
    /// `purge_inbox`.
    Inbox(DateTime<Utc>),
    /// `purge_idempotency` (it has no cut-off: keys carry their own expiry).
    Idempotency,
    /// `purge_oauth_states`.
    OAuthStates(DateTime<Utc>),
    /// `purge_rsvp_tokens`.
    RsvpTokens(DateTime<Utc>),
    /// `due_principals`.
    Principals(DateTime<Utc>),
    /// `due_calendars`.
    Calendars(DateTime<Utc>),
}

/// What the spy plays besides the wrapped store.
#[derive(Debug)]
struct Behaviour {
    audit_permitted: AtomicBool,
    deliveries_supported: AtomicBool,
    endless_inbox: AtomicBool,
    oldest_audit_supported: AtomicBool,
    oldest_audit_fails: AtomicBool,
    oldest_audit_lookups: AtomicU32,
}

/// The wrapped store with its record of calls.
pub(crate) struct Spy {
    inner: Arc<dyn Database>,
    calls: Arc<Mutex<Vec<Call>>>,
    behaviour: Arc<Behaviour>,
}

impl Spy {
    /// Wraps `inner`: the audit purge is permitted, deliveries are supported and the inbox runs dry.
    pub(crate) fn wrapping(inner: Arc<dyn Database>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            calls: Arc::new(Mutex::new(Vec::new())),
            behaviour: Arc::new(Behaviour {
                audit_permitted: AtomicBool::new(true),
                deliveries_supported: AtomicBool::new(true),
                endless_inbox: AtomicBool::new(false),
                oldest_audit_supported: AtomicBool::new(true),
                oldest_audit_fails: AtomicBool::new(false),
                oldest_audit_lookups: AtomicU32::new(0),
            }),
        })
    }

    /// The calls so far, in order.
    pub(crate) async fn calls(&self) -> Vec<Call> {
        self.calls.lock().await.clone()
    }

    /// Whether the connection may purge the audit log; when not, the store answers `NotPermitted` like the PostgreSQL
    /// adapter does for a runtime role.
    pub(crate) fn audit_permitted(&self, permitted: bool) {
        self.behaviour.audit_permitted.store(permitted, Ordering::SeqCst);
    }

    /// Whether the store offers the delivery purge; when not, it answers `Unsupported`.
    pub(crate) fn deliveries_supported(&self, supported: bool) {
        self.behaviour.deliveries_supported.store(supported, Ordering::SeqCst);
    }

    /// While set, every call of the inbox purge reports one removed row, however many there are.
    pub(crate) fn endless_inbox(&self, endless: bool) {
        self.behaviour.endless_inbox.store(endless, Ordering::SeqCst);
    }

    /// Whether the store can tell the oldest audit event; when not, it answers `Unsupported` like a store that does not
    /// implement the lookup.
    pub(crate) fn oldest_audit_supported(&self, supported: bool) {
        self.behaviour.oldest_audit_supported.store(supported, Ordering::SeqCst);
    }

    /// While set, the lookup of the oldest audit event fails with `Unavailable`.
    pub(crate) fn oldest_audit_fails(&self, fails: bool) {
        self.behaviour.oldest_audit_fails.store(fails, Ordering::SeqCst);
    }

    /// How many times the oldest audit event was asked for. It is not among the [`Call`]s: those are the cleanup steps, in the
    /// order of a pass, and the lookup is no step.
    pub(crate) fn oldest_audit_lookups(&self) -> u32 {
        self.behaviour.oldest_audit_lookups.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Database for Spy {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        self.inner.begin(tenant, mode).await
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        Ok(Box::new(SpyTx {
            inner: self.inner.begin_system().await?,
            calls: Arc::clone(&self.calls),
            behaviour: Arc::clone(&self.behaviour),
        }))
    }

    async fn health(&self) -> Health {
        self.inner.health().await
    }
}

/// A system transaction whose cleanup repository records its calls.
struct SpyTx {
    inner: Box<dyn SystemTx>,
    calls: Arc<Mutex<Vec<Call>>>,
    behaviour: Arc<Behaviour>,
}

/// Adds a call to the record. A function of its own: a method would hold `&SpyTx` across the await, and the wrapped
/// transaction is `Send` but not `Sync`.
async fn record(calls: &Mutex<Vec<Call>>, call: Call) {
    calls.lock().await.push(call);
}

#[async_trait]
impl SystemTx for SpyTx {
    fn tenants(&mut self) -> &mut dyn SystemTenantRepo {
        self.inner.tenants()
    }

    fn credential_lookup(&mut self) -> &mut dyn CredentialLookup {
        self.inner.credential_lookup()
    }

    fn outbox_claim(&mut self) -> &mut dyn OutboxQueue {
        self.inner.outbox_claim()
    }

    fn retention(&mut self) -> &mut dyn RetentionRepo {
        self
    }

    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        self.inner.commit().await
    }
}

#[async_trait]
impl RetentionRepo for SpyTx {
    async fn purge_outbox(
        &mut self,
        done_before: DateTime<Utc>,
        dead_before: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        record(
            &self.calls,
            Call::Outbox {
                done_before,
                dead_before,
            },
        )
        .await;
        self.inner.retention().purge_outbox(done_before, dead_before).await
    }

    async fn prune_changes(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        record(&self.calls, Call::Changes(before)).await;
        self.inner.retention().prune_changes(before).await
    }

    async fn purge_audit(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        self.inner.retention().purge_audit(before).await
    }

    async fn purge_audit_checked(&mut self, before: DateTime<Utc>) -> Result<AuditPurge, StoreError> {
        record(&self.calls, Call::Audit(before)).await;
        if !self.behaviour.audit_permitted.load(Ordering::SeqCst) {
            return Ok(AuditPurge::NotPermitted);
        }
        self.inner.retention().purge_audit_checked(before).await
    }

    async fn oldest_audit_at(&mut self) -> Result<Option<DateTime<Utc>>, StoreError> {
        self.behaviour.oldest_audit_lookups.fetch_add(1, Ordering::SeqCst);
        if !self.behaviour.oldest_audit_supported.load(Ordering::SeqCst) {
            return Err(StoreError::Unsupported);
        }
        if self.behaviour.oldest_audit_fails.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.inner.retention().oldest_audit_at().await
    }

    async fn purge_deliveries(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        record(&self.calls, Call::Deliveries(before)).await;
        if !self.behaviour.deliveries_supported.load(Ordering::SeqCst) {
            return Err(StoreError::Unsupported);
        }
        self.inner.retention().purge_deliveries(before).await
    }

    async fn purge_inbox(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        record(&self.calls, Call::Inbox(before)).await;
        if self.behaviour.endless_inbox.load(Ordering::SeqCst) {
            return Ok(1);
        }
        self.inner.retention().purge_inbox(before).await
    }

    async fn purge_idempotency(&mut self) -> Result<u64, StoreError> {
        record(&self.calls, Call::Idempotency).await;
        self.inner.retention().purge_idempotency().await
    }

    async fn purge_oauth_states(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        record(&self.calls, Call::OAuthStates(before)).await;
        self.inner.retention().purge_oauth_states(before).await
    }

    async fn purge_rsvp_tokens(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        record(&self.calls, Call::RsvpTokens(before)).await;
        self.inner.retention().purge_rsvp_tokens(before).await
    }

    async fn due_principals(
        &mut self,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(TenantId, PrincipalId)>, StoreError> {
        record(&self.calls, Call::Principals(before)).await;
        self.inner.retention().due_principals(before, limit).await
    }

    async fn due_calendars(
        &mut self,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(TenantId, CalendarId)>, StoreError> {
        record(&self.calls, Call::Calendars(before)).await;
        self.inner.retention().due_calendars(before, limit).await
    }
}
