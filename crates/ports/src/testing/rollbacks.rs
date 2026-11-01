//! A `Database` wrapper that records every transaction that ends without a commit, so a test can hold the application
//! to the rule of the store port: a transaction whose work succeeded ends with `commit`, and only a failed or
//! abandoned one is rolled back (see the module documentation of the store port).
//!
//! PostgreSQL counts a dropped transaction as a rollback (`pg_stat_database.xact_rollback`), whether it wrote anything
//! or not, and operators alert on that counter. Neither adapter shows the difference to a test: a read that is dropped
//! answers exactly like one that is committed. [`RollbackWatch::wrap`] wraps any [`Database`]; every tenant and system
//! transaction it hands out is watched, and one that is dropped without a commit is recorded with the frames of the
//! application where it was begun, so a failing assertion names the code to fix. A commit that fails is recorded as
//! well: the database rolls such a transaction back.

use std::backtrace::Backtrace;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, PoisonError};

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

/// The record is touched for an instant, from `Drop`, which cannot await an asynchronous lock.
#[expect(
    clippy::disallowed_types,
    reason = "a test double that records from Drop and never across an await"
)]
type Mutex<T> = std::sync::Mutex<T>;

/// What the watch has seen; shared by the watch, the wrapped databases and their transactions.
#[derive(Debug, Default)]
struct Ledger {
    /// Transactions begun through a wrapped database.
    begun: AtomicU32,
    /// The transactions that ended without a successful commit, described, oldest first.
    rolled_back: Mutex<Vec<String>>,
}

/// Records the transactions of the databases it wraps that end without a commit. Clones share what was recorded.
#[derive(Debug, Clone, Default)]
pub struct RollbackWatch {
    ledger: Arc<Ledger>,
}

impl RollbackWatch {
    /// A watch that has recorded nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// `inner`, wrapped: every transaction it hands out is watched.
    pub fn wrap(&self, inner: Arc<dyn Database>) -> Arc<dyn Database> {
        Arc::new(WatchedDatabase {
            inner,
            ledger: Arc::clone(&self.ledger),
        })
    }

    /// How many transactions were begun through the wrapped databases.
    pub fn begun(&self) -> u32 {
        self.ledger.begun.load(Ordering::SeqCst)
    }

    /// The transactions that ended without a commit, oldest first: the kind of each (`system`, or the tenant and the
    /// mode) and the frames of the application where it was begun.
    pub fn rolled_back(&self) -> Vec<String> {
        self.ledger
            .rolled_back
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Forgets what was recorded so far (the transactions begun and those rolled back), for a test that only judges
    /// what comes next.
    pub fn reset(&self) {
        self.ledger.begun.store(0, Ordering::SeqCst);
        self.ledger
            .rolled_back
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// A transaction that is still open: it is recorded when it is dropped before [`Open::committed`] was called.
struct Open {
    ledger: Arc<Ledger>,
    kind: String,
    begun_at: Backtrace,
    committed: bool,
}

impl Open {
    fn new(ledger: &Arc<Ledger>, kind: String) -> Self {
        ledger.begun.fetch_add(1, Ordering::SeqCst);
        Self {
            ledger: Arc::clone(ledger),
            kind,
            begun_at: Backtrace::force_capture(),
            committed: false,
        }
    }

    /// The transaction was committed: nothing is recorded.
    fn committed(mut self) {
        self.committed = true;
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let entry = format!(
            "{}, begun at\n{}",
            self.kind,
            application_frames(self.begun_at.to_string())
        );
        self.ledger
            .rolled_back
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(entry);
    }
}

/// The frames of a printed backtrace that belong to the application: the ones whose source is in the workspace, not in
/// the standard library, a dependency or this wrapper. They are told by their location, whichever separator the paths of
/// the platform use, because the frame of an `async fn` may be named `{async_fn#0}` only. The whole backtrace when none
/// is found (a build without line tables).
fn application_frames(text: String) -> String {
    const ELSEWHERE: [&str; 4] = ["/rustc/", "/registry/", "/git/checkouts/", "testing/rollbacks.rs"];
    let mut frames = String::new();
    let mut function: Option<&str> = None;
    for line in text.lines() {
        let Some(location) = line.trim_start().strip_prefix("at ") else {
            function = Some(line);
            continue;
        };
        let location = location.replace('\\', "/");
        if let Some(name) = function.take()
            && !ELSEWHERE.iter().any(|part| location.contains(part))
        {
            // Writing into a `String` cannot fail.
            let _ = writeln!(frames, "{name}\n{line}");
        }
    }
    if frames.is_empty() { text } else { frames }
}

/// The database that hands out watched transactions.
struct WatchedDatabase {
    inner: Arc<dyn Database>,
    ledger: Arc<Ledger>,
}

#[async_trait]
impl Database for WatchedDatabase {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        let inner = self.inner.begin(tenant, mode).await?;
        Ok(Box::new(WatchedTx {
            inner,
            open: Open::new(&self.ledger, format!("a {mode:?} transaction of tenant {tenant}")),
        }))
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        let inner = self.inner.begin_system().await?;
        Ok(Box::new(WatchedSystemTx {
            inner,
            open: Open::new(&self.ledger, "a system transaction".to_owned()),
        }))
    }

    async fn health(&self) -> Health {
        self.inner.health().await
    }
}

/// A watched tenant transaction.
struct WatchedTx {
    inner: Box<dyn Tx>,
    open: Open,
}

#[async_trait]
impl Tx for WatchedTx {
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
        let Self { inner, open } = *self;
        // A commit that fails is a rollback: `open` is dropped unsettled and records it.
        inner.commit().await?;
        open.committed();
        Ok(())
    }
}

/// A watched system transaction.
struct WatchedSystemTx {
    inner: Box<dyn SystemTx>,
    open: Open,
}

#[async_trait]
impl SystemTx for WatchedSystemTx {
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
        let Self { inner, open } = *self;
        inner.commit().await?;
        open.committed();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FaultyDatabase;

    /// A database whose transactions do nothing and commit successfully.
    struct Empty;

    struct EmptyTx;

    #[async_trait]
    impl Database for Empty {
        async fn begin(&self, _tenant: TenantId, _mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
            Ok(Box::new(EmptyTx))
        }

        async fn health(&self) -> Health {
            Health::Healthy
        }
    }

    #[async_trait]
    impl SystemTx for EmptyTx {
        fn tenants(&mut self) -> &mut dyn SystemTenantRepo {
            panic!("the tests only begin and end transactions")
        }

        fn credential_lookup(&mut self) -> &mut dyn CredentialLookup {
            panic!("the tests only begin and end transactions")
        }

        fn outbox_claim(&mut self) -> &mut dyn OutboxQueue {
            panic!("the tests only begin and end transactions")
        }

        fn retention(&mut self) -> &mut dyn RetentionRepo {
            panic!("the tests only begin and end transactions")
        }

        async fn commit(self: Box<Self>) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn the_frames_of_the_application_are_found_by_their_location_on_every_platform() {
        let printed = [
            "   0: std::backtrace::Backtrace::force_capture",
            "             at /rustc/abc/library/std/src/backtrace.rs:312:9",
            "   1: {async_fn#0}",
            "             at ./crates/ports/src/testing/rollbacks.rs:160:30",
            "   2: {async_fn#0}",
            "             at /src/crates/auth-local/src/authenticator.rs:133:51",
            "   3: {async_block#0}",
            r"             at C:\work\davhaven\crates\app\src\credentials.rs:580:65",
            "   4: tokio::runtime::park::CachedParkThread::block_on",
            r"             at C:\Users\dev\.cargo\registry\src\tokio-1.54.1\src\runtime\park.rs:284:60",
            r"   5: {async_fn#0}",
            r"             at C:\work\davhaven\crates\ports\src\testing\rollbacks.rs:160:30",
            "   6: main",
        ]
        .join("\n");
        let frames = application_frames(printed);
        assert!(frames.contains("auth-local/src/authenticator.rs:133:51"), "{frames}");
        assert!(frames.contains(r"crates\app\src\credentials.rs:580:65"), "{frames}");
        for elsewhere in ["rollbacks.rs", "park.rs", "backtrace.rs"] {
            assert!(!frames.contains(elsewhere), "{elsewhere}: {frames}");
        }
        let unknown = "   0: main".to_owned();
        assert_eq!(
            application_frames(unknown.clone()),
            unknown,
            "without locations the whole backtrace is kept"
        );
    }

    #[tokio::test]
    async fn dropped_and_failed_transactions_are_recorded_and_committed_ones_are_not() {
        let watch = RollbackWatch::new();
        let faulty = FaultyDatabase::new(Arc::new(Empty));
        let database = watch.wrap(Arc::new(faulty.clone()));

        database.begin_system().await.unwrap().commit().await.unwrap();
        assert!(
            watch.rolled_back().is_empty(),
            "a committed transaction is not a rollback"
        );

        drop(database.begin_system().await.unwrap());
        let rolled_back = watch.rolled_back();
        assert_eq!(rolled_back.len(), 1);
        assert!(
            rolled_back[0].starts_with("a system transaction, begun at\n"),
            "the record says what was rolled back and where it was begun: {rolled_back:?}"
        );

        faulty.fail_next_commits(1);
        let failed = database.begin_system().await.unwrap().commit().await;
        assert_eq!(failed, Err(StoreError::SerializationFailure));
        assert_eq!(watch.rolled_back().len(), 2, "a failed commit is a rollback");

        assert!(
            database
                .begin(TenantId::from_uuid(uuid::Uuid::nil()), TxMode::ReadOnly)
                .await
                .is_err()
        );
        assert_eq!(watch.begun(), 3, "a begin that failed opened nothing");

        watch.reset();
        assert_eq!(
            watch.rolled_back(),
            Vec::<String>::new(),
            "a reset forgets what was recorded"
        );
        assert_eq!(watch.begun(), 0, "and what was begun");
        assert_eq!(database.health().await, Health::Healthy);
    }
}
