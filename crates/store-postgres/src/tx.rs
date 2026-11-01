//! Tenant-bound and system transactions.
//!
//! [`PgTx`] is one PostgreSQL transaction bound to one tenant: [`Database::begin`](davhaven_ports::Database::begin)
//! opens it and sets `davhaven.tenant_id` with `set_config(.., true)` (that is `SET LOCAL`), so the row-level
//! security policies admit exactly the rows of that tenant. Every query additionally names the tenant, so the
//! indexes serve it and a forgotten predicate would still be caught by the policies.
//! [`PgSystemTx`] is the transaction of the cross-tenant operations; it sets `davhaven.system` instead.
//!
//! Both types implement the repository traits of the port themselves, one trait per aggregate, in the modules of
//! [`repos`](crate::repos). Dropping a transaction without committing rolls it back.
//!
//! # Failed writes leave no trace
//!
//! PostgreSQL aborts a whole transaction after a failed statement. The repositories promise more: a method that
//! returns an error has changed nothing and the transaction stays usable. Every write therefore runs inside a
//! savepoint (`PgTx::guarded`), which is rolled back when the write fails.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use davhaven_domain::TenantId;
use davhaven_ports::{
    AuditRepo, BindingRepo, CalendarRepo, ChangeRepo, Clock, CredentialLookup, CredentialRepo, ExternalAccountRepo,
    GrantRepo, IdGenerator, IdempotencyRepo, InboxRepo, MembershipRepo, NotificationRepo, OAuthStateRepo, ObjectRepo,
    OutboxQueue, OutboxRepo, PrincipalRepo, PropertyRepo, RetentionRepo, RsvpRepo, StoreError, SystemTenantRepo,
    SystemTx, TenantRepo, Tx, WebhookRepo,
};
use futures::future::BoxFuture;
use sqlx::{Acquire, PgConnection, Postgres, Transaction};

use crate::error::map_sqlx;

/// A transaction bound to one tenant.
pub(crate) struct PgTx {
    /// The open transaction.
    pub(crate) conn: Transaction<'static, Postgres>,
    /// The tenant every query is bound to.
    pub(crate) tenant: TenantId,
    /// The time source of `created_at`, `updated_at`, expiry and change-log times.
    pub(crate) clock: Arc<dyn Clock>,
    /// The id source of epochs and of rows without a caller-chosen id.
    pub(crate) ids: Arc<dyn IdGenerator>,
    /// The `statement_timeout` of the maintenance operations (zero: none).
    pub(crate) maintenance_timeout: Duration,
}

impl PgTx {
    /// Wraps an open transaction whose `davhaven.tenant_id` is already set.
    pub(crate) fn new(
        conn: Transaction<'static, Postgres>,
        tenant: TenantId,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        maintenance_timeout: Duration,
    ) -> Self {
        Self {
            conn,
            tenant,
            clock,
            ids,
            maintenance_timeout,
        }
    }

    /// Runs `work` inside a savepoint: its effects are kept when it returns `Ok` and rolled back when it returns
    /// an error, so a failed repository method leaves the transaction exactly as it was.
    pub(crate) async fn guarded<T, F>(&mut self, work: F) -> Result<T, StoreError>
    where
        T: Send,
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, StoreError>> + Send,
    {
        guard(&mut self.conn, work).await
    }
}

/// Raises the `statement_timeout` for the rest of the enclosing savepoint and returns the value to restore.
///
/// Maintenance operations (deleting a tenant, purging a principal or a calendar, bumping every sync epoch) work on
/// as many rows as the installation has and may legitimately run longer than a request. `SET LOCAL` survives the
/// release of a savepoint, so the caller puts the previous value back with [`end_maintenance`] when it succeeds;
/// when it fails, the rollback of the savepoint restores it.
pub(crate) async fn begin_maintenance(conn: &mut PgConnection, timeout: Duration) -> Result<String, StoreError> {
    let previous: String = sqlx::query_scalar("SELECT current_setting('statement_timeout')")
        .fetch_one(&mut *conn)
        .await
        .map_err(map_sqlx)?;
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(timeout.as_millis().to_string())
        .execute(&mut *conn)
        .await
        .map_err(map_sqlx)?;
    Ok(previous)
}

/// Puts back the `statement_timeout` that [`begin_maintenance`] returned.
pub(crate) async fn end_maintenance(conn: &mut PgConnection, previous: &str) -> Result<(), StoreError> {
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(previous)
        .execute(&mut *conn)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

/// The savepoint wrapper shared by both transaction types.
pub(crate) async fn guard<T, F>(conn: &mut Transaction<'static, Postgres>, work: F) -> Result<T, StoreError>
where
    T: Send,
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, StoreError>> + Send,
{
    let mut savepoint = conn.begin().await.map_err(map_sqlx)?;
    match work(&mut savepoint).await {
        Ok(value) => {
            savepoint.commit().await.map_err(map_sqlx)?;
            Ok(value)
        }
        Err(error) => {
            if let Err(rollback) = savepoint.rollback().await {
                tracing::warn!(error = %rollback, "rolling back to the savepoint of a failed write failed");
            }
            Err(error)
        }
    }
}

impl std::fmt::Debug for PgTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTx")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Tx for PgTx {
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
        davhaven_ports::observe(crate::repos::LABEL, "tx.commit", async move {
            let this = *self;
            this.conn.commit().await.map_err(map_sqlx)
        })
        .await
    }
}

/// A transaction that is not bound to a tenant, for the operations that cross tenants.
pub(crate) struct PgSystemTx {
    /// The open transaction.
    pub(crate) conn: Transaction<'static, Postgres>,
    /// The time source.
    pub(crate) clock: Arc<dyn Clock>,
    /// The id source.
    pub(crate) ids: Arc<dyn IdGenerator>,
    /// The `statement_timeout` of the maintenance operations (zero: none).
    pub(crate) maintenance_timeout: Duration,
}

impl PgSystemTx {
    /// Wraps an open transaction whose `davhaven.system` is already set.
    pub(crate) fn new(
        conn: Transaction<'static, Postgres>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        maintenance_timeout: Duration,
    ) -> Self {
        Self {
            conn,
            clock,
            ids,
            maintenance_timeout,
        }
    }

    /// Runs `work` inside a savepoint; see [`PgTx::guarded`].
    pub(crate) async fn guarded<T, F>(&mut self, work: F) -> Result<T, StoreError>
    where
        T: Send,
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, StoreError>> + Send,
    {
        guard(&mut self.conn, work).await
    }
}

impl std::fmt::Debug for PgSystemTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSystemTx").finish_non_exhaustive()
    }
}

#[async_trait]
impl SystemTx for PgSystemTx {
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
        davhaven_ports::observe(crate::repos::LABEL, "system_tx.commit", async move {
            let this = *self;
            this.conn.commit().await.map_err(map_sqlx)
        })
        .await
    }
}
