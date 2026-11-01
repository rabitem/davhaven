//! The `Database` port: tenant-bound transactions, system transactions and repositories.
//!
//! Storage is one port with per-aggregate repositories (PLAN 2.4, F0.6):
//!
//! * [`Database::begin`] opens a [`Tx`] **bound to one tenant**. No repository method takes a tenant argument or can
//!   reach another tenant's rows; the Postgres adapter additionally sets `davhaven.tenant_id` so row-level security
//!   enforces the same (`ENGINEERING_RULES` R4). Resources of other tenants are indistinguishable from missing ones:
//!   they yield [`StoreError::NotFound`].
//! * [`Database::begin_system`] opens a [`SystemTx`] for the few operations that cross tenants: tenant management,
//!   credential lookup before the tenant is known, the outbox queue and retention.
//! * Dropping a transaction without [`Tx::commit`] rolls it back. **Every transaction whose work succeeded ends with
//!   `commit`**, also one that only read (read-only and snapshot transactions, system lookups) and a read-write one that
//!   found nothing to change: PostgreSQL counts every dropped transaction as a rollback
//!   (`pg_stat_database.xact_rollback`), and operators alert on that counter, so it should count only transactions that
//!   failed or were abandoned. Commit on the path that returns `Ok`, right after the last database call; an error path
//!   drops the transaction, which is right for one that may hold partial writes. `testing::RollbackWatch` finds the
//!   transactions that end without a commit.
//!
//! # Conventions shared by all repositories
//!
//! * **Reads**: `get*` methods return the row or [`StoreError::NotFound`]; `find*` methods return an `Option`.
//!   Methods that take a parent id (a calendar, a principal) answer `NotFound` when the parent does not exist in the
//!   tenant, rather than an empty result. Soft-deleted rows (`deleted_at` set) are invisible to every method except
//!   the purge paths.
//! * **Writes of entities** take the whole entity and return the stored entity. The store owns `version`,
//!   `created_at` and `updated_at`: whatever the caller put there is ignored, `create` stores version 1 and
//!   `update(entity, expected_version)` replaces the row when the stored version equals `expected_version` and
//!   bumps it ([`StoreError::PreconditionFailed`] otherwise; [`StoreError::NotFound`] when the row is gone).
//! * **Time** comes from the `Clock` the adapter was built with (`PluginContext::clock`), never from the database:
//!   `created_at`, `updated_at`, change-log times, expiry and revocation stamps. Tests inject a `ManualClock`.
//! * **Uniqueness** violations are typed: [`StoreError::UniqueViolation`] names the [`UniqueKey`](crate::error::UniqueKey).
//! * **Paging** is by cursor: [`PageReq`] carries a limit and the id after which to continue, [`StorePage`] returns
//!   the items in ascending id order (UUIDv7, so creation order) and the cursor of the next page. Paging is stable
//!   under concurrent inserts.
//! * **Concurrency**: the isolation level is READ COMMITTED; writers of one calendar are serialised by
//!   `CalendarRepo::lock` or by the write methods of `ObjectRepo` themselves. The application retries a
//!   transaction up to three times on [`StoreError::SerializationFailure`].
//! * **One transaction per task**: code never holds two transactions of a database at once (a tenant transaction
//!   and a system transaction for authentication or audit inside it, a claim while settling) and never awaits
//!   another port while it holds one. Every open transaction pins a pooled connection, so a task that holds one
//!   and waits for a second starves the pool as soon as as many requests do the same: with a pool of N
//!   connections, N such requests wait for each other until the acquire timeout. The in-memory adapter runs
//!   transactions one after the other under a single lock and **fails fast** instead: a `begin` that cannot get
//!   the lock within the adapter's wait ([`StoreError::Internal`]) is the symptom of a nested or leaked
//!   transaction, so application tests on the in-memory adapter see the mistake as an error, not as a hang.
//!   Open the transaction late, close it early.
//! * **Time limits** (PostgreSQL adapter): a statement that runs too long, a lock that cannot be taken in time
//!   and a transaction that sits idle between statements are aborted by the database and surface as
//!   [`StoreError::Timeout`]; the whole transaction is lost and the caller retries it.
//! * **Read-only transactions** ([`TxMode::ReadOnly`] and [`TxMode::Snapshot`]) reject writes, and
//!   `CalendarRepo::lock`, with [`StoreError::Internal`].
//! * **Listing with a token**: read `ChangeRepo::state` before listing members (see `ObjectRepo::list`); a
//!   full listing that must be one snapshot uses [`TxMode::Snapshot`].

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use davhaven_domain::TenantId;
use uuid::Uuid;

use crate::error::StoreError;
use crate::worker::Health;

pub mod calendars;
pub mod credentials;
pub mod delivery;
pub mod messages;
pub mod objects;
pub mod principals;
pub mod records;
pub mod sync;
pub mod system;

pub use calendars::{
    BindingRepo, BoundCalendar, CalendarFilter, CalendarRepo, CollectionProperty, GrantRepo, PropertyRepo,
    PropertyScope,
};
pub use credentials::{
    ApiTokenFilter, CredentialLookup, CredentialOwner, CredentialRecord, CredentialRepo, CredentialUse,
    LookedUpCredential, Rehash, RsvpRepo,
};
pub use delivery::{
    DeliveryRecord, DeliveryStatus, ExternalAccountFilter, ExternalAccountRepo, OAuthState, OAuthStateRepo,
    OutboxFilter, OutboxRepo, WebhookRepo,
};
pub use messages::{InboxRepo, InboxScope, NotificationRepo};
pub use objects::{Expected, IndexFilter, NewVersion, ObjectAttendee, ObjectHead, ObjectRepo, TimeRange, WriteResult};
pub use principals::{
    MembershipDiff, MembershipRepo, PrincipalAddress, PrincipalFilter, PrincipalMatch, PrincipalQuery, PrincipalRepo,
    TenantRepo,
};
pub use records::{
    AuditFilter, AuditRepo, AuditRow, DEFAULT_IN_FLIGHT_LEASE, IdempotencyClaim, IdempotencyRecord, IdempotencyRepo,
    IdempotencyStatus, LeasedClaim, NewAudit,
};
pub use sync::{Change, ChangeBatch, ChangeKind, ChangeRepo, SyncPosition};
pub use system::{AuditPurge, NewTenantAudit, OutboxQueue, RetentionRepo, SystemTenantRepo, TenantAudit};

/// The most items a page can hold, whatever limit the caller asks for.
pub const MAX_PAGE_LIMIT: u32 = 1000;

/// The access mode of a tenant transaction.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxMode {
    /// Reads only; the Postgres adapter opens a `READ ONLY` transaction (READ COMMITTED: every statement sees the
    /// data committed when it starts).
    ReadOnly,
    /// Reads and writes.
    ReadWrite,
    /// Reads only, from one snapshot: every statement of the transaction sees the data as it was when the first
    /// statement started (the Postgres adapter opens `READ ONLY ISOLATION LEVEL REPEATABLE READ`; the in-memory
    /// adapter is serial and needs no special handling). For a full sync or a paged `PROPFIND` depth 1 whose
    /// members and sync token must agree. A snapshot transaction is held open for the whole listing, so use it
    /// for reads that are short, bounded and rare enough not to pin a pooled connection for long.
    Snapshot,
}

impl TxMode {
    /// Whether the mode rejects writes.
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::ReadOnly | Self::Snapshot)
    }
}

/// Truncates a timestamp to the microseconds PostgreSQL stores. Both adapters stamp rows with the injected clock
/// through this function, so what one returns equals what the other returns and what a later read finds.
pub fn micros(time: DateTime<Utc>) -> DateTime<Utc> {
    time.duration_trunc(TimeDelta::microseconds(1)).unwrap_or(time)
}

/// The time `lease` after `now`, saturating at the largest representable time instead of overflowing.
pub fn lease_end(now: DateTime<Utc>, lease: Duration) -> DateTime<Utc> {
    TimeDelta::from_std(lease)
        .ok()
        .and_then(|delta| now.checked_add_signed(delta))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// A request for one page of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageReq {
    /// The most items to return; clamped to `1..=`[`MAX_PAGE_LIMIT`].
    pub limit: u32,
    /// Continue after the item with this id (the `next` of the previous page); `None` starts at the beginning.
    pub after: Option<Uuid>,
}

impl PageReq {
    /// The first page of up to `limit` items.
    pub const fn first(limit: u32) -> Self {
        Self { limit, after: None }
    }

    /// The page that follows the item `cursor`.
    #[must_use]
    pub const fn after(self, cursor: Uuid) -> Self {
        Self {
            limit: self.limit,
            after: Some(cursor),
        }
    }

    /// The limit adapters apply: at least 1 and at most [`MAX_PAGE_LIMIT`].
    pub fn effective_limit(&self) -> u32 {
        self.limit.clamp(1, MAX_PAGE_LIMIT)
    }
}

impl Default for PageReq {
    /// The first page of 50 items (the management API default).
    fn default() -> Self {
        Self::first(50)
    }
}

/// One page of a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePage<T> {
    /// The items in ascending id order.
    pub items: Vec<T>,
    /// The cursor for the next page: the id of the last item, set only when more items exist.
    pub next: Option<Uuid>,
}

impl<T> StorePage<T> {
    /// A page without items.
    pub const fn empty() -> Self {
        Self {
            items: Vec::new(),
            next: None,
        }
    }

    /// Converts the items, keeping the cursor.
    pub fn map<U>(self, convert: impl FnMut(T) -> U) -> StorePage<U> {
        StorePage {
            items: self.items.into_iter().map(convert).collect(),
            next: self.next,
        }
    }

    /// Builds a page from up to `limit + 1` rows fetched in ascending id order: the extra row only proves that
    /// more exist and is dropped. `id_of` extracts the cursor id. Adapters use this to share one rule.
    pub fn from_overfetched(mut rows: Vec<T>, request: &PageReq, id_of: impl Fn(&T) -> Uuid) -> Self {
        let limit = usize::try_from(request.effective_limit()).unwrap_or(usize::MAX);
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next = if more { rows.last().map(id_of) } else { None };
        Self { items: rows, next }
    }
}

/// The storage port: opens transactions.
#[async_trait]
pub trait Database: Send + Sync {
    /// Opens a transaction bound to `tenant`. The tenant is not checked for existence: for an unknown tenant every
    /// read simply finds nothing.
    ///
    /// A task must not call `begin` or [`begin_system`](Self::begin_system) while it holds another transaction of
    /// the same database (see the module documentation): it pins two connections, and the in-memory adapter
    /// answers [`StoreError::Internal`] once its wait for the lock is over.
    ///
    /// End every transaction that succeeded with [`Tx::commit`], whatever its mode: a dropped transaction is a
    /// rollback, and the rollback counter of PostgreSQL, which operators alert on, should count only failures.
    ///
    /// # Errors
    ///
    /// `Unavailable` when no connection can be obtained, `Timeout` when the pool is exhausted for too long.
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError>;

    /// Opens a system transaction for the cross-tenant operations. Like a tenant transaction, it ends with
    /// [`SystemTx::commit`] when its work succeeded, also when it only looked something up.
    ///
    /// # Errors
    ///
    /// Same as [`Database::begin`].
    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError>;

    /// The health of the store for `/readyz`: reachable and migrated to at least the required schema version.
    async fn health(&self) -> Health;
}

/// A transaction bound to one tenant. Repositories are borrowed one at a time; dropping the transaction without
/// committing rolls everything back, including outbox messages written in it.
///
/// A transaction whose work succeeded ends with [`commit`](Self::commit), also when it only read or found nothing to
/// write: PostgreSQL counts a dropped transaction as a rollback, and its rollback counter, which operators alert on,
/// should count only transactions that failed or were abandoned. Drop the transaction on the error paths only, or where
/// rolling back what it wrote is the point.
#[async_trait]
pub trait Tx: Send {
    /// The tenant this transaction is bound to.
    fn tenant_id(&self) -> TenantId;

    /// The tenant's own row.
    fn tenant(&mut self) -> &mut dyn TenantRepo;

    /// Principals and their addresses.
    fn principals(&mut self) -> &mut dyn PrincipalRepo;

    /// Group memberships.
    fn memberships(&mut self) -> &mut dyn MembershipRepo;

    /// Calendars.
    fn calendars(&mut self) -> &mut dyn CalendarRepo;

    /// Calendar bindings (a principal's view of a calendar).
    fn bindings(&mut self) -> &mut dyn BindingRepo;

    /// Collection properties (shared or per binding).
    fn properties(&mut self) -> &mut dyn PropertyRepo;

    /// Calendar grants.
    fn grants(&mut self) -> &mut dyn GrantRepo;

    /// Calendar objects (the verbatim iCalendar data plus index columns) and their attendees.
    fn objects(&mut self) -> &mut dyn ObjectRepo;

    /// The change log behind sync tokens.
    fn changes(&mut self) -> &mut dyn ChangeRepo;

    /// CalendarServer notifications.
    fn notifications(&mut self) -> &mut dyn NotificationRepo;

    /// The scheduling inbox.
    fn inbox(&mut self) -> &mut dyn InboxRepo;

    /// App passwords, API tokens and feed tokens.
    fn credentials(&mut self) -> &mut dyn CredentialRepo;

    /// RSVP tokens.
    fn rsvp(&mut self) -> &mut dyn RsvpRepo;

    /// The outbox (enqueue and inspection; claiming is a system operation).
    fn outbox(&mut self) -> &mut dyn OutboxRepo;

    /// Webhook subscriptions and deliveries.
    fn webhooks(&mut self) -> &mut dyn WebhookRepo;

    /// External provider accounts.
    fn external_accounts(&mut self) -> &mut dyn ExternalAccountRepo;

    /// OAuth authorization states.
    fn oauth_states(&mut self) -> &mut dyn OAuthStateRepo;

    /// Idempotency keys of the management API.
    fn idempotency(&mut self) -> &mut dyn IdempotencyRepo;

    /// The audit log (append and list only).
    fn audit(&mut self) -> &mut dyn AuditRepo;

    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::SerializationFailure`] when the database aborts the transaction because of a concurrent
    /// update (the caller retries the whole transaction), and the connection errors of [`Database::begin`].
    async fn commit(self: Box<Self>) -> Result<(), StoreError>;
}

/// A transaction that is not bound to a tenant, for operations that cross tenants.
///
/// As for [`Tx`], a system transaction whose work succeeded ends with [`commit`](Self::commit): the lookup of a
/// credential or a tenant and a claim that found nothing are no rollbacks.
#[async_trait]
pub trait SystemTx: Send {
    /// Tenant management (create, update, delete, lookup by slug and login domain).
    fn tenants(&mut self) -> &mut dyn SystemTenantRepo;

    /// Credential lookup by prefix, before the tenant of a request is known, and system token management.
    fn credential_lookup(&mut self) -> &mut dyn CredentialLookup;

    /// Claiming and settling outbox records of all tenants.
    fn outbox_claim(&mut self) -> &mut dyn OutboxQueue;

    /// Retention cleanup across tenants.
    fn retention(&mut self) -> &mut dyn RetentionRepo;

    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// Same as [`Tx::commit`].
    async fn commit(self: Box<Self>) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_requests_clamp_their_limit() {
        assert_eq!(PageReq::first(0).effective_limit(), 1);
        assert_eq!(PageReq::first(50).effective_limit(), 50);
        assert_eq!(PageReq::first(u32::MAX).effective_limit(), MAX_PAGE_LIMIT);
        assert_eq!(PageReq::default().limit, 50);
        let cursor = Uuid::from_u128(7);
        let next = PageReq::first(10).after(cursor);
        assert_eq!(next.after, Some(cursor));
        assert_eq!(next.limit, 10);
    }

    #[test]
    fn overfetched_rows_produce_a_cursor_only_when_more_exist() {
        let id = |n: &u32| Uuid::from_u128(u128::from(*n));
        let request = PageReq::first(3);

        let exact = StorePage::from_overfetched(vec![1_u32, 2, 3], &request, id);
        assert_eq!(exact.items, vec![1, 2, 3]);
        assert_eq!(exact.next, None, "exactly one page of items: nothing follows");

        let more = StorePage::from_overfetched(vec![1_u32, 2, 3, 4], &request, id);
        assert_eq!(more.items, vec![1, 2, 3]);
        assert_eq!(
            more.next,
            Some(Uuid::from_u128(3)),
            "the cursor is the last returned item"
        );

        let none = StorePage::<u32>::from_overfetched(Vec::new(), &request, id);
        assert!(none.items.is_empty() && none.next.is_none());
        assert_eq!(StorePage::<u32>::empty(), none);
    }

    #[test]
    fn modes_know_whether_they_write() {
        assert!(TxMode::ReadOnly.is_read_only());
        assert!(TxMode::Snapshot.is_read_only());
        assert!(!TxMode::ReadWrite.is_read_only());
    }

    #[test]
    fn microseconds_truncate_and_leases_saturate() {
        let now = DateTime::from_timestamp(1_800_000_000, 123_456_789).unwrap();
        assert_eq!(micros(now).timestamp_subsec_nanos(), 123_456_000);
        assert_eq!(micros(micros(now)), micros(now), "truncating twice changes nothing");
        assert_eq!(lease_end(now, Duration::from_secs(60)), now + TimeDelta::seconds(60));
        assert_eq!(lease_end(now, Duration::MAX), DateTime::<Utc>::MAX_UTC);
    }

    #[test]
    fn pages_map_their_items_and_keep_the_cursor() {
        let page = StorePage {
            items: vec![1_u32, 2],
            next: Some(Uuid::from_u128(2)),
        };
        let mapped = page.map(|n| n.to_string());
        assert_eq!(mapped.items, vec!["1".to_owned(), "2".to_owned()]);
        assert_eq!(mapped.next, Some(Uuid::from_u128(2)));
    }
}
