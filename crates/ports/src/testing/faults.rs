//! A `Database` wrapper that injects failures, so the retry logic of the application can be tested.
//!
//! Neither store adapter ever answers [`StoreError::SerializationFailure`] on its own in a test (the in-memory
//! adapter runs transactions one after the other, and the PostgreSQL adapter only meets a conflict under
//! concurrent load), so the bounded retry of the application (PLAN 2.7: three attempts) has nothing to exercise.
//! [`FaultyDatabase`] wraps any [`Database`] and fails the next `n` commits or begins with a chosen error; the
//! wrapped transaction is rolled back like a real failed commit, so nothing of a failed attempt is visible to the
//! next one.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use davhaven_domain::TenantId;

use crate::error::StoreError;
use crate::store::{
    AuditRepo, BindingRepo, CalendarRepo, ChangeRepo, CredentialLookup, CredentialRepo, Database, ExternalAccountRepo,
    GrantRepo, IdempotencyRepo, InboxRepo, MembershipRepo, NotificationRepo, OAuthStateRepo, ObjectRepo, OutboxQueue,
    OutboxRepo, PrincipalRepo, PropertyRepo, RetentionRepo, RsvpRepo, SystemTenantRepo, SystemTx, TenantRepo, Tx,
    TxMode, WebhookRepo,
};
use crate::worker::Health;

/// The injected failures and the counters the wrapper keeps; shared by the database and its transactions.
#[derive(Debug, Default)]
struct Faults {
    /// How many of the next commits fail with [`StoreError::SerializationFailure`].
    commit_failures: AtomicU32,
    /// How many of the next begins fail with [`StoreError::Unavailable`].
    begin_failures: AtomicU32,
    /// Commits attempted (successful or not).
    commits: AtomicU32,
    /// Begins attempted (successful or not).
    begins: AtomicU32,
}

impl Faults {
    /// Takes one failure from `counter` if any is left.
    fn take(counter: &AtomicU32) -> bool {
        counter
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
            .is_ok()
    }
}

/// Wraps a [`Database`] and fails commits or begins on demand. Clones share the injected failures and counters.
#[derive(Clone)]
pub struct FaultyDatabase {
    inner: Arc<dyn Database>,
    faults: Arc<Faults>,
}

impl std::fmt::Debug for FaultyDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultyDatabase")
            .field("commits", &self.commits())
            .field("begins", &self.begins())
            .finish_non_exhaustive()
    }
}

impl FaultyDatabase {
    /// Wraps `inner`; nothing fails until a failure is injected.
    pub fn new(inner: Arc<dyn Database>) -> Self {
        Self {
            inner,
            faults: Arc::new(Faults::default()),
        }
    }

    /// Makes the next `count` commits (tenant and system transactions) roll back and answer
    /// [`StoreError::SerializationFailure`], as PostgreSQL does when it aborts a transaction after a conflict.
    pub fn fail_next_commits(&self, count: u32) {
        self.faults.commit_failures.store(count, Ordering::SeqCst);
    }

    /// Makes the next `count` begins answer [`StoreError::Unavailable`], as a pool that cannot get a connection.
    pub fn fail_next_begins(&self, count: u32) {
        self.faults.begin_failures.store(count, Ordering::SeqCst);
    }

    /// How many commits were attempted, injected failures included.
    pub fn commits(&self) -> u32 {
        self.faults.commits.load(Ordering::SeqCst)
    }

    /// How many transactions were begun (or attempted), injected failures included.
    pub fn begins(&self) -> u32 {
        self.faults.begins.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Database for FaultyDatabase {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        self.faults.begins.fetch_add(1, Ordering::SeqCst);
        if Faults::take(&self.faults.begin_failures) {
            return Err(StoreError::Unavailable);
        }
        let inner = self.inner.begin(tenant, mode).await?;
        Ok(Box::new(FaultyTx {
            inner,
            faults: Arc::clone(&self.faults),
        }))
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        self.faults.begins.fetch_add(1, Ordering::SeqCst);
        if Faults::take(&self.faults.begin_failures) {
            return Err(StoreError::Unavailable);
        }
        let inner = self.inner.begin_system().await?;
        Ok(Box::new(FaultySystemTx {
            inner,
            faults: Arc::clone(&self.faults),
        }))
    }

    async fn health(&self) -> Health {
        self.inner.health().await
    }
}

/// A tenant transaction whose commit can be made to fail.
struct FaultyTx {
    inner: Box<dyn Tx>,
    faults: Arc<Faults>,
}

#[async_trait]
impl Tx for FaultyTx {
    fn tenant_id(&self) -> TenantId {
        self.inner.tenant_id()
    }

    fn tenant(&mut self) -> &mut dyn TenantRepo {
        self.inner.tenant()
    }

    fn principals(&mut self) -> &mut dyn PrincipalRepo {
        self.inner.principals()
    }

    fn memberships(&mut self) -> &mut dyn MembershipRepo {
        self.inner.memberships()
    }

    fn calendars(&mut self) -> &mut dyn CalendarRepo {
        self.inner.calendars()
    }

    fn bindings(&mut self) -> &mut dyn BindingRepo {
        self.inner.bindings()
    }

    fn properties(&mut self) -> &mut dyn PropertyRepo {
        self.inner.properties()
    }

    fn grants(&mut self) -> &mut dyn GrantRepo {
        self.inner.grants()
    }

    fn objects(&mut self) -> &mut dyn ObjectRepo {
        self.inner.objects()
    }

    fn changes(&mut self) -> &mut dyn ChangeRepo {
        self.inner.changes()
    }

    fn notifications(&mut self) -> &mut dyn NotificationRepo {
        self.inner.notifications()
    }

    fn inbox(&mut self) -> &mut dyn InboxRepo {
        self.inner.inbox()
    }

    fn credentials(&mut self) -> &mut dyn CredentialRepo {
        self.inner.credentials()
    }

    fn rsvp(&mut self) -> &mut dyn RsvpRepo {
        self.inner.rsvp()
    }

    fn outbox(&mut self) -> &mut dyn OutboxRepo {
        self.inner.outbox()
    }

    fn webhooks(&mut self) -> &mut dyn WebhookRepo {
        self.inner.webhooks()
    }

    fn external_accounts(&mut self) -> &mut dyn ExternalAccountRepo {
        self.inner.external_accounts()
    }

    fn oauth_states(&mut self) -> &mut dyn OAuthStateRepo {
        self.inner.oauth_states()
    }

    fn idempotency(&mut self) -> &mut dyn IdempotencyRepo {
        self.inner.idempotency()
    }

    fn audit(&mut self) -> &mut dyn AuditRepo {
        self.inner.audit()
    }

    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        let this = *self;
        this.faults.commits.fetch_add(1, Ordering::SeqCst);
        if Faults::take(&this.faults.commit_failures) {
            // Dropping the wrapped transaction rolls it back, like the database does after a failed commit.
            drop(this.inner);
            return Err(StoreError::SerializationFailure);
        }
        this.inner.commit().await
    }
}

/// A system transaction whose commit can be made to fail.
struct FaultySystemTx {
    inner: Box<dyn SystemTx>,
    faults: Arc<Faults>,
}

#[async_trait]
impl SystemTx for FaultySystemTx {
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
        self.inner.retention()
    }

    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        let this = *self;
        this.faults.commits.fetch_add(1, Ordering::SeqCst);
        if Faults::take(&this.faults.commit_failures) {
            drop(this.inner);
            return Err(StoreError::SerializationFailure);
        }
        this.inner.commit().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database that hands out nothing: the counters and failures are what these tests look at.
    struct Refusing;

    #[async_trait]
    impl Database for Refusing {
        async fn begin(&self, _tenant: TenantId, _mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
            Err(StoreError::Timeout)
        }

        async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
            Err(StoreError::Timeout)
        }

        async fn health(&self) -> Health {
            Health::Healthy
        }
    }

    #[tokio::test]
    async fn begins_fail_on_demand_and_are_counted() {
        let database = FaultyDatabase::new(Arc::new(Refusing));
        let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(1));
        database.fail_next_begins(2);
        assert_eq!(
            database.begin(tenant, TxMode::ReadOnly).await.err(),
            Some(StoreError::Unavailable)
        );
        assert_eq!(database.begin_system().await.err(), Some(StoreError::Unavailable));
        assert_eq!(
            database.begin(tenant, TxMode::ReadOnly).await.err(),
            Some(StoreError::Timeout),
            "after the injected failures the wrapped database answers"
        );
        assert_eq!(database.begins(), 3);
        assert_eq!(database.commits(), 0);
        assert_eq!(database.health().await, Health::Healthy);
    }

    #[test]
    fn failures_are_taken_one_at_a_time() {
        let counter = AtomicU32::new(2);
        assert!(Faults::take(&counter));
        assert!(Faults::take(&counter));
        assert!(!Faults::take(&counter));
        assert!(!Faults::take(&counter), "an empty counter stays empty");
    }
}
