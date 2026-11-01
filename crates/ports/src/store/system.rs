//! System repositories: tenant management, the outbox queue and retention. They cross tenants and are reachable
//! only through a [`SystemTx`](super::SystemTx).

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::audit::TenantSettingsAudit;
use davhaven_domain::{AuditActor, AuditEvent, CalendarId, DomainName, PrincipalId, Tenant, TenantId, TenantSlug};
use uuid::Uuid;

use super::{PageReq, StorePage};
use crate::error::StoreError;
use crate::outbox::{OutboxClaim, OutboxFailure, OutboxKey, OutboxRecord, OutboxStats};

/// What an audit purge did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditPurge {
    /// The purge ran and removed this many records (at most one batch per call, as for every retention method).
    Purged(u64),
    /// The store keeps the audit log immutable for this connection: the runtime role may not call the purge (the
    /// default of the PostgreSQL adapter, `docs/operations/database.md`). Nothing was removed and nothing is
    /// wrong: retention of the audit log runs elsewhere, as a scheduled job with the owner credentials. A retention
    /// worker skips the step, logs that it did, and raises neither an error nor an unhealthy heartbeat.
    NotPermitted,
}

/// The audit events a system transaction may record about a tenant: the two changes of tenant management that are made
/// across tenants and so have no transaction of the tenant (ADR-0005). The set is part of the signature of
/// [`SystemTenantRepo::append_audit`], so a caller cannot ask for anything else; the PostgreSQL policy of the table
/// admits exactly these two actions as well, which keeps a compromised server in system scope from forging any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantAudit {
    /// The tenant was created (`tenant.created`).
    Created,
    /// The settings of the tenant changed (`tenant.settings_changed`).
    SettingsChanged(TenantSettingsAudit),
}

impl From<TenantAudit> for AuditEvent {
    fn from(event: TenantAudit) -> Self {
        match event {
            TenantAudit::Created => Self::TenantCreated,
            TenantAudit::SettingsChanged(changed) => Self::TenantSettingsChanged(changed),
        }
    }
}

/// An audit record about a tenant to append in a system transaction ([`SystemTenantRepo::append_audit`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTenantAudit {
    /// The row id (from the `IdGenerator`).
    pub id: Uuid,
    /// Who acted.
    pub actor: AuditActor,
    /// What happened.
    pub event: TenantAudit,
}

/// Tenants across the installation.
#[async_trait]
pub trait SystemTenantRepo: Send {
    /// The tenant with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: TenantId) -> Result<Tenant, StoreError>;

    /// The tenant with the immutable `slug`, if any.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_by_slug(&mut self, slug: &TenantSlug) -> Result<Option<Tenant>, StoreError>;

    /// The tenant whose login domain equals `domain` (case-insensitive), if any.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_by_login_domain(&mut self, domain: &DomainName) -> Result<Option<Tenant>, StoreError>;

    /// Lists tenants in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(&mut self, page: PageReq) -> Result<StorePage<Tenant>, StoreError>;

    /// Creates a tenant.
    ///
    /// # Errors
    ///
    /// `UniqueViolation` of `TenantSlug` or `LoginDomain`.
    async fn create(&mut self, tenant: Tenant) -> Result<Tenant, StoreError>;

    /// Replaces display name, login domain, status and settings if the stored version equals `expected_version`;
    /// the slug never changes.
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed` and `UniqueViolation` of `LoginDomain`.
    async fn update(&mut self, tenant: Tenant, expected_version: i64) -> Result<Tenant, StoreError>;

    /// Deletes the tenant and everything that belongs to it.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn delete(&mut self, id: TenantId) -> Result<(), StoreError>;

    /// Appends an audit record to the log of `tenant` **in this system transaction**, so that the record commits or
    /// rolls back together with the tenant change it describes (`tenant.created`, `tenant.settings_changed`). The
    /// audit repository of a tenant transaction cannot do this: a tenant is created and changed in a system
    /// transaction, and the record may not wait for a second transaction that can fail on its own.
    ///
    /// The scope is deliberately narrow (ADR-0005): only the events of [`TenantAudit`] (`tenant.created` and
    /// `tenant.settings_changed`) may be recorded from system scope, because they are the only ones that are written
    /// while the tenant is managed. The signature says so, and the PostgreSQL adapter enforces it in the policy of the
    /// table as well, so a compromised server in system scope cannot forge anything else. The record is stamped with
    /// the adapter's clock, as [`AuditRepo::append`](super::AuditRepo::append) does, and is read back through the audit
    /// repository of a transaction of the tenant.
    ///
    /// Additive method: the default reports [`StoreError::Unsupported`]; both store adapters override it.
    ///
    /// # Errors
    ///
    /// `NotFound` when the tenant does not exist, `Unsupported` from stores that do not implement it.
    async fn append_audit(&mut self, tenant: TenantId, entry: NewTenantAudit) -> Result<(), StoreError> {
        let _ = (tenant, entry);
        Err(StoreError::Unsupported)
    }

    /// Gives every collection of the tenant (or of all tenants with `None`) a new sync epoch, which invalidates
    /// all outstanding sync tokens. `admin bump-sync-epoch` runs this after a restore. Returns how many
    /// collections changed.
    ///
    /// # Errors
    ///
    /// `NotFound` when a given tenant does not exist.
    async fn bump_sync_epoch(&mut self, tenant: Option<TenantId>) -> Result<u64, StoreError>;
}

/// The outbox queue across tenants: the dispatcher claims ready records and settles them.
///
/// Claiming is safe for several instances at once (`FOR UPDATE SKIP LOCKED` in Postgres): a record is held by at
/// most one claimant until its lease expires.
#[async_trait]
pub trait OutboxQueue: Send {
    /// Claims up to `limit` ready records: `pending` records whose `next_attempt_at` has passed and `in_flight`
    /// records whose lease expired, ordered by due time and id. Claimed records become `in_flight` with
    /// `locked_until = now + lease` and `attempts` incremented; the returned records show those values.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn claim(&mut self, limit: u32, lease: Duration) -> Result<Vec<OutboxRecord>, StoreError>;

    /// Marks a claimed record `done`. Only an `in_flight` record can be settled: a claimant whose record was
    /// already completed, failed or released by someone else must not overwrite that outcome.
    ///
    /// This guard covers records that are already **settled**. A record that another dispatcher has *reclaimed*
    /// after this claimant's lease ran out is in flight again, and this method cannot tell the two holders apart;
    /// a dispatcher that wants that protection settles with [`complete_claimed`](Self::complete_claimed).
    ///
    /// # Errors
    ///
    /// `NotFound` when the record does not exist and `LeaseLost` when it is not `in_flight` (settled or
    /// released by someone else).
    async fn complete(&mut self, key: OutboxKey) -> Result<(), StoreError>;

    /// Records a failed attempt: with `retry_at` the record becomes `pending` again due at that time, without it
    /// the record becomes `dead`. `last_error` is stored either way. Like [`complete`](Self::complete) it settles
    /// only `in_flight` records and has the same limits ([`fail_claimed`](Self::fail_claimed) fences by claim).
    ///
    /// # Errors
    ///
    /// `NotFound` when the record does not exist and `LeaseLost` when it is not `in_flight`.
    async fn fail(&mut self, key: OutboxKey, failure: OutboxFailure) -> Result<(), StoreError>;

    /// [`complete`](Self::complete) fenced by the claim: acts only while the record is `in_flight` with the
    /// attempt number and lease end of `claim` (`OutboxRecord::claim`), so a dispatcher whose lease ran out
    /// cannot settle a record that another dispatcher reclaimed and still holds. Additive method: the default
    /// reports [`StoreError::Unsupported`]; both store adapters override it.
    ///
    /// # Errors
    ///
    /// `NotFound` when the record does not exist, `LeaseLost` when the claim is no longer the current one
    /// (nothing is changed), `Unsupported` from stores that do not implement it.
    async fn complete_claimed(&mut self, claim: OutboxClaim) -> Result<(), StoreError> {
        let _ = claim;
        Err(StoreError::Unsupported)
    }

    /// [`fail`](Self::fail) fenced by the claim; see [`complete_claimed`](Self::complete_claimed).
    ///
    /// # Errors
    ///
    /// As [`complete_claimed`](Self::complete_claimed).
    async fn fail_claimed(&mut self, claim: OutboxClaim, failure: OutboxFailure) -> Result<(), StoreError> {
        let _ = (claim, failure);
        Err(StoreError::Unsupported)
    }

    /// [`release_leases`](Self::release_leases) fenced by the claims: a lease that was reclaimed by another
    /// dispatcher is left alone. Returns how many leases were released. Additive method with the same default as
    /// [`complete_claimed`](Self::complete_claimed).
    ///
    /// # Errors
    ///
    /// Store failures only; `Unsupported` from stores that do not implement it.
    async fn release_claimed(&mut self, held: &[OutboxClaim]) -> Result<u64, StoreError> {
        let _ = held;
        Err(StoreError::Unsupported)
    }

    /// Puts a claimed record back without counting the claim as an attempt: it becomes `pending` again, due at
    /// `until`, `last_error` is set to `note` and `attempts` goes back to what it was before the claim. A handler
    /// that did not try anything (the mail rate limit holds the message back, the circuit breaker is open) defers
    /// instead of failing, so a long hold never uses up `outbox.max_attempts`. Fenced by the claim like
    /// [`complete_claimed`](Self::complete_claimed): a dispatcher whose lease ran out cannot defer a record that
    /// another dispatcher reclaimed.
    ///
    /// The default counts the claim like [`fail_claimed`](Self::fail_claimed) does, which is safe but lets a long
    /// hold dead-letter the record: stores override it. The contract suite of the store checks that a deferred
    /// record keeps its attempt count.
    ///
    /// # Errors
    ///
    /// As [`complete_claimed`](Self::complete_claimed).
    async fn defer_claimed(&mut self, claim: OutboxClaim, until: DateTime<Utc>, note: &str) -> Result<(), StoreError> {
        self.fail_claimed(claim, OutboxFailure::retry(note, until)).await
    }

    /// Releases the leases the caller still holds (graceful shutdown): the records become `pending` again, due now,
    /// and the attempt that never finished is not counted. Returns how many were released.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn release_leases(&mut self, held: &[OutboxKey]) -> Result<u64, StoreError>;

    /// The queue depth for metrics.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn stats(&mut self) -> Result<OutboxStats, StoreError>;
}

/// Retention cleanup across tenants (PLAN 2.18). Each method deletes what is older than its cut-off, in bounded
/// batches chosen by the adapter, and returns how many rows it removed; the cleanup worker calls them with cut-offs
/// computed from the retention settings and the clock.
#[async_trait]
pub trait RetentionRepo: Send {
    /// Removes `done` outbox records last changed before `done_before` and `dead` ones before `dead_before`.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn purge_outbox(&mut self, done_before: DateTime<Utc>, dead_before: DateTime<Utc>)
    -> Result<u64, StoreError>;

    /// Removes change-log rows older than `before` and raises each affected collection's `sync_min_seq` so tokens
    /// that need pruned history are rejected.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn prune_changes(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError>;

    /// Removes audit records older than `before`, one batch per call. This is the only path that deletes audit
    /// records, and the PostgreSQL adapter does not offer it to the runtime role (the audit log is append-only for
    /// the server; see `docs/operations/database.md`): for such a role the call removes nothing and returns `0`,
    /// exactly like a purge with nothing to do. A caller that needs to tell "nothing to purge" from "not permitted"
    /// (the retention worker, which must not report a healthy audit retention it is not running) calls
    /// [`purge_audit_checked`](Self::purge_audit_checked).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn purge_audit(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError>;

    /// [`purge_audit`](Self::purge_audit) that says whether the purge was permitted at all. Additive method: the
    /// default delegates to `purge_audit` and reports every result as [`AuditPurge::Purged`]; the PostgreSQL
    /// adapter overrides it to report [`AuditPurge::NotPermitted`] for a role without the privilege.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn purge_audit_checked(&mut self, before: DateTime<Utc>) -> Result<AuditPurge, StoreError> {
        self.purge_audit(before).await.map(AuditPurge::Purged)
    }

    /// When the oldest audit event of all tenants occurred, or `None` while the log is empty.
    ///
    /// The cleanup worker publishes it (`davhaven_audit_oldest_event_timestamp_seconds`) so that an operator can alert when the
    /// job that purges the audit log, which runs outside the server and which nothing else watches, stops: an event that is much
    /// older than the retention period means the purge did not run. It is one indexed lookup (the first row of the index on the
    /// time), not a scan, and it reads across tenants, which only a system transaction may. Additive method: the default reports
    /// [`StoreError::Unsupported`], and both store adapters override it.
    ///
    /// # Errors
    ///
    /// Store failures only; `Unsupported` from stores that do not implement it.
    async fn oldest_audit_at(&mut self) -> Result<Option<DateTime<Utc>>, StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Removes webhook delivery records created before `before` (one record exists per event and subscription, so
    /// the table grows with traffic). Additive method: the default implementation reports
    /// [`StoreError::Unsupported`]; both store adapters override it.
    ///
    /// # Errors
    ///
    /// Store failures only; `Unsupported` from stores that do not implement it.
    async fn purge_deliveries(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        let _ = before;
        Err(StoreError::Unsupported)
    }

    /// Removes scheduling inbox items created before `before`.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn purge_inbox(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError>;

    /// Removes idempotency keys that expired by the adapter's clock.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn purge_idempotency(&mut self) -> Result<u64, StoreError>;

    /// Removes OAuth states that expired before `before`.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn purge_oauth_states(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError>;

    /// Removes RSVP tokens that expired or were revoked before `before`.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn purge_rsvp_tokens(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError>;

    /// The principals deleted before `before` (at most `limit`, oldest first). The cleanup worker purges each in
    /// its tenant's transaction, so the audit record `principal.purged` is written atomically with the purge.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn due_principals(
        &mut self,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(TenantId, PrincipalId)>, StoreError>;

    /// The calendars soft-deleted before `before` (at most `limit`, oldest first), to be purged in their tenants'
    /// transactions.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn due_calendars(
        &mut self,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(TenantId, CalendarId)>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant repository that only implements what the trait requires.
    struct TenantStub;

    #[async_trait]
    impl SystemTenantRepo for TenantStub {
        async fn get(&mut self, _id: TenantId) -> Result<Tenant, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn find_by_slug(&mut self, _slug: &TenantSlug) -> Result<Option<Tenant>, StoreError> {
            Ok(None)
        }

        async fn find_by_login_domain(&mut self, _domain: &DomainName) -> Result<Option<Tenant>, StoreError> {
            Ok(None)
        }

        async fn list(&mut self, _page: PageReq) -> Result<StorePage<Tenant>, StoreError> {
            Ok(StorePage::empty())
        }

        async fn create(&mut self, tenant: Tenant) -> Result<Tenant, StoreError> {
            Ok(tenant)
        }

        async fn update(&mut self, tenant: Tenant, _expected_version: i64) -> Result<Tenant, StoreError> {
            Ok(tenant)
        }

        async fn delete(&mut self, _id: TenantId) -> Result<(), StoreError> {
            Ok(())
        }

        async fn bump_sync_epoch(&mut self, _tenant: Option<TenantId>) -> Result<u64, StoreError> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn a_store_without_tenant_audit_in_the_system_transaction_says_so() {
        let entry = NewTenantAudit {
            id: Uuid::nil(),
            actor: AuditActor::system(),
            event: TenantAudit::Created,
        };
        assert_eq!(
            TenantStub.append_audit(TenantId::from_uuid(Uuid::nil()), entry).await,
            Err(StoreError::Unsupported)
        );
    }

    #[test]
    fn the_tenant_events_are_the_two_that_the_policy_of_the_table_admits() {
        assert_eq!(AuditEvent::from(TenantAudit::Created).action(), "tenant.created");
        let changed = TenantAudit::SettingsChanged(TenantSettingsAudit {
            fields: vec!["scheduling.external".to_owned()],
        });
        assert_eq!(AuditEvent::from(changed).action(), "tenant.settings_changed");
    }

    /// A retention repository that only implements what the trait requires.
    struct Stub;

    #[async_trait]
    impl RetentionRepo for Stub {
        async fn purge_outbox(&mut self, _done: DateTime<Utc>, _dead: DateTime<Utc>) -> Result<u64, StoreError> {
            Ok(0)
        }

        async fn prune_changes(&mut self, _before: DateTime<Utc>) -> Result<u64, StoreError> {
            Ok(0)
        }

        async fn purge_audit(&mut self, _before: DateTime<Utc>) -> Result<u64, StoreError> {
            Ok(7)
        }

        async fn purge_inbox(&mut self, _before: DateTime<Utc>) -> Result<u64, StoreError> {
            Ok(0)
        }

        async fn purge_idempotency(&mut self) -> Result<u64, StoreError> {
            Ok(0)
        }

        async fn purge_oauth_states(&mut self, _before: DateTime<Utc>) -> Result<u64, StoreError> {
            Ok(0)
        }

        async fn purge_rsvp_tokens(&mut self, _before: DateTime<Utc>) -> Result<u64, StoreError> {
            Ok(0)
        }

        async fn due_principals(
            &mut self,
            _before: DateTime<Utc>,
            _limit: u32,
        ) -> Result<Vec<(TenantId, PrincipalId)>, StoreError> {
            Ok(Vec::new())
        }

        async fn due_calendars(
            &mut self,
            _before: DateTime<Utc>,
            _limit: u32,
        ) -> Result<Vec<(TenantId, CalendarId)>, StoreError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn the_checked_purge_reports_every_result_as_purged_unless_an_adapter_knows_better() {
        let mut stub = Stub;
        assert_eq!(
            stub.purge_audit_checked(DateTime::UNIX_EPOCH).await,
            Ok(AuditPurge::Purged(7))
        );
    }

    #[tokio::test]
    async fn the_oldest_audit_event_is_unsupported_by_default() {
        let mut stub = Stub;
        assert_eq!(stub.oldest_audit_at().await, Err(StoreError::Unsupported));
    }

    #[tokio::test]
    async fn the_delivery_purge_is_unsupported_by_default() {
        let mut stub = Stub;
        assert_eq!(
            stub.purge_deliveries(DateTime::UNIX_EPOCH).await,
            Err(StoreError::Unsupported)
        );
    }
}
