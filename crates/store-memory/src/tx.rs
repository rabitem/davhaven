//! Snapshot transactions.
//!
//! A transaction holds the one async mutex of the database for its whole life, so transactions run one after the
//! other, which is a legal behaviour of READ COMMITTED and makes every anomaly impossible. A read-write
//! transaction copies the state when it begins (the copy shares every table with the live state, and a table is
//! duplicated only when the transaction first writes to it, see [`Shared`](crate::state::Shared)); dropping it
//! without committing puts the copy back, so a rollback undoes everything, outbox messages included. Because
//! transactions are serial, a task must never hold one while it waits for another (see the module documentation of
//! the store port): `begin` reports that as an error after a bounded wait instead of hanging. A read-only
//! transaction (`ReadOnly` or `Snapshot`: transactions are serial, so every read sees one state anyway) clones
//! nothing and rejects every write with [`StoreError::Internal`], as the PostgreSQL adapter's `READ ONLY`
//! transaction does.
//!
//! [`MemTx`] hands its repositories out as itself: it implements every repository trait of the port, one trait
//! per aggregate, in the modules of [`repos`](crate::repos).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::TenantId;
use davhaven_ports::{
    AuditRepo, BindingRepo, CalendarRepo, ChangeRepo, Clock, CredentialLookup, CredentialRepo, ExternalAccountRepo,
    GrantRepo, IdGenerator, IdempotencyRepo, InboxRepo, MembershipRepo, NotificationRepo, OAuthStateRepo, ObjectRepo,
    OutboxQueue, OutboxRepo, PrincipalRepo, PropertyRepo, RetentionRepo, RsvpRepo, StoreError, SystemTenantRepo,
    SystemTx, TenantRepo, Tx, TxMode, WebhookRepo,
};
use tokio::sync::OwnedMutexGuard;

use crate::repos::{LABEL, micros};
use crate::state::{State, TenantData};

/// A transaction bound to one tenant.
pub(crate) struct MemTx {
    /// The database, locked for the life of the transaction.
    pub(crate) guard: OwnedMutexGuard<State>,
    /// The state at `begin`, restored on rollback; `None` for read-only transactions.
    snapshot: Option<State>,
    /// The tenant every method is bound to.
    pub(crate) tenant: TenantId,
    /// Whether writes are allowed.
    mode: TxMode,
    /// The time source.
    pub(crate) clock: Arc<dyn Clock>,
    /// The id source.
    pub(crate) ids: Arc<dyn IdGenerator>,
    /// What a transaction of an unknown tenant sees: nothing.
    empty: TenantData,
    /// Whether `commit` ran.
    committed: bool,
}

impl MemTx {
    /// Starts a transaction on the locked state.
    pub(crate) fn new(
        guard: OwnedMutexGuard<State>,
        tenant: TenantId,
        mode: TxMode,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        let snapshot = if mode.is_read_only() {
            None
        } else {
            Some((*guard).clone())
        };
        Self {
            guard,
            snapshot,
            tenant,
            mode,
            clock,
            ids,
            empty: TenantData::default(),
            committed: false,
        }
    }

    /// The current time, truncated to the microseconds the PostgreSQL adapter stores.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        micros(self.clock.now())
    }

    /// The tables of the transaction's tenant; empty for a tenant that does not exist.
    pub(crate) fn view(&self) -> &TenantData {
        self.guard
            .tenants
            .get(&self.tenant)
            .map_or(&self.empty, |entry| &entry.data)
    }

    /// Fails in a read-only transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::Internal`] in a read-only transaction.
    pub(crate) fn require_write_mode(&self) -> Result<(), StoreError> {
        if self.mode.is_read_only() {
            Err(StoreError::internal("write attempted in a read-only transaction"))
        } else {
            Ok(())
        }
    }

    /// The tables of the transaction's tenant for writing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Internal`] in a read-only transaction and [`StoreError::NotFound`] when the tenant does not
    /// exist (a row cannot reference a tenant that is not there).
    pub(crate) fn writable(&mut self) -> Result<&mut TenantData, StoreError> {
        if self.mode.is_read_only() {
            return Err(StoreError::internal("write attempted in a read-only transaction"));
        }
        self.guard
            .tenants
            .get_mut(&self.tenant)
            .map(|entry| &mut entry.data)
            .ok_or(StoreError::NotFound)
    }
}

impl Drop for MemTx {
    fn drop(&mut self) {
        if !self.committed
            && let Some(snapshot) = self.snapshot.take()
        {
            *self.guard = snapshot;
        }
    }
}

impl std::fmt::Debug for MemTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemTx")
            .field("tenant", &self.tenant)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Tx for MemTx {
    fn tenant_id(&self) -> TenantId {
        self.tenant
    }

    fn tenant(&mut self) -> &mut dyn TenantRepo {
        self
    }

    fn principals(&mut self) -> &mut dyn PrincipalRepo {
        self
    }

    fn memberships(&mut self) -> &mut dyn MembershipRepo {
        self
    }

    fn calendars(&mut self) -> &mut dyn CalendarRepo {
        self
    }

    fn bindings(&mut self) -> &mut dyn BindingRepo {
        self
    }

    fn properties(&mut self) -> &mut dyn PropertyRepo {
        self
    }

    fn grants(&mut self) -> &mut dyn GrantRepo {
        self
    }

    fn objects(&mut self) -> &mut dyn ObjectRepo {
        self
    }

    fn changes(&mut self) -> &mut dyn ChangeRepo {
        self
    }

    fn notifications(&mut self) -> &mut dyn NotificationRepo {
        self
    }

    fn inbox(&mut self) -> &mut dyn InboxRepo {
        self
    }

    fn credentials(&mut self) -> &mut dyn CredentialRepo {
        self
    }

    fn rsvp(&mut self) -> &mut dyn RsvpRepo {
        self
    }

    fn outbox(&mut self) -> &mut dyn OutboxRepo {
        self
    }

    fn webhooks(&mut self) -> &mut dyn WebhookRepo {
        self
    }

    fn external_accounts(&mut self) -> &mut dyn ExternalAccountRepo {
        self
    }

    fn oauth_states(&mut self) -> &mut dyn OAuthStateRepo {
        self
    }

    fn idempotency(&mut self) -> &mut dyn IdempotencyRepo {
        self
    }

    fn audit(&mut self) -> &mut dyn AuditRepo {
        self
    }

    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        davhaven_ports::observe(LABEL, "tx.commit", async move {
            let mut this = *self;
            this.committed = true;
            Ok(())
        })
        .await
    }
}

/// A transaction that is not bound to a tenant.
pub(crate) struct MemSystemTx {
    /// The database, locked for the life of the transaction.
    pub(crate) guard: OwnedMutexGuard<State>,
    /// The state at `begin`, restored on rollback.
    snapshot: Option<State>,
    /// The time source.
    pub(crate) clock: Arc<dyn Clock>,
    /// The id source.
    pub(crate) ids: Arc<dyn IdGenerator>,
    /// Whether `commit` ran.
    committed: bool,
}

impl MemSystemTx {
    /// Starts a system transaction on the locked state.
    pub(crate) fn new(guard: OwnedMutexGuard<State>, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        let snapshot = Some((*guard).clone());
        Self {
            guard,
            snapshot,
            clock,
            ids,
            committed: false,
        }
    }

    /// The current time, truncated to microseconds.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        micros(self.clock.now())
    }
}

impl Drop for MemSystemTx {
    fn drop(&mut self) {
        if !self.committed
            && let Some(snapshot) = self.snapshot.take()
        {
            *self.guard = snapshot;
        }
    }
}

impl std::fmt::Debug for MemSystemTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemSystemTx").finish_non_exhaustive()
    }
}

#[async_trait]
impl SystemTx for MemSystemTx {
    fn tenants(&mut self) -> &mut dyn SystemTenantRepo {
        self
    }

    fn credential_lookup(&mut self) -> &mut dyn CredentialLookup {
        self
    }

    fn outbox_claim(&mut self) -> &mut dyn OutboxQueue {
        self
    }

    fn retention(&mut self) -> &mut dyn RetentionRepo {
        self
    }

    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        davhaven_ports::observe(LABEL, "system_tx.commit", async move {
            let mut this = *self;
            this.committed = true;
            Ok(())
        })
        .await
    }
}
