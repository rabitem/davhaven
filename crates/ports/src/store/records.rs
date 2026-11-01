//! Repositories for idempotency keys and the audit log.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{AuditActor, AuditEvent, PrincipalId, TenantId, TokenId};
use uuid::Uuid;

use super::{PageReq, StorePage};
use crate::error::StoreError;

/// How long a claimed key stays in flight when the caller does not say otherwise (see
/// [`IdempotencyRepo::claim_with_lease`]): ten minutes, long enough for any request the server lets run and short
/// enough that a client whose first attempt died with the process can retry within the same session.
pub const DEFAULT_IN_FLIGHT_LEASE: Duration = Duration::from_secs(600);

/// The state of an idempotency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdempotencyStatus {
    /// The first request with the key is still being processed, or died before it could finish (the lease of
    /// [`IdempotencyRepo::claim_with_lease`] decides which).
    InFlight,
    /// The first request finished; its response is stored (unless it carried a secret).
    Done,
}

impl IdempotencyStatus {
    /// The database spelling: `in_flight` or `done`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::Done => "done",
        }
    }
}

/// An idempotency key of a management API request (`idempotency_keys`), scoped to tenant, token and key.
#[derive(Debug, Clone, PartialEq)]
pub struct IdempotencyRecord {
    /// The token that sent the request.
    pub token_id: TokenId,
    /// The client's `Idempotency-Key`.
    pub key: String,
    /// The HTTP method of the first request.
    pub method: String,
    /// The route template or path of the first request.
    pub path: String,
    /// A fingerprint of the request body; a reuse with another fingerprint is a client error.
    pub fingerprint: String,
    /// In flight or done.
    pub status: IdempotencyStatus,
    /// The response status of the first request, once done.
    pub response_status: Option<u16>,
    /// The response body of the first request, once done; absent when the response carried a secret.
    pub response: Option<serde_json::Value>,
    /// When the key expires (24 hours after it was claimed).
    pub expires_at: DateTime<Utc>,
}

/// The result of claiming an idempotency key.
#[derive(Debug, Clone, PartialEq)]
pub enum IdempotencyClaim {
    /// The key was free (or expired) and is now claimed, in flight.
    Claimed,
    /// The key exists; the record says what the first request did so far.
    Existing(IdempotencyRecord),
}

/// The result of [`IdempotencyRepo::claim_leased`]: like [`IdempotencyClaim`], but a successful claim carries the
/// end of the lease it took, the proof the fenced methods ([`IdempotencyRepo::complete_leased`],
/// [`IdempotencyRepo::release_leased`]) need.
#[derive(Debug, Clone, PartialEq)]
pub enum LeasedClaim {
    /// The key was free (or expired, or its lease had run out) and is now claimed until `lease_until`.
    Claimed {
        /// The end of the lease; pass it back to settle the key.
        lease_until: DateTime<Utc>,
    },
    /// The key exists; the record says what the first request did so far.
    Existing(IdempotencyRecord),
}

/// Idempotency keys of the transaction's tenant.
///
/// Claiming must be visible to concurrent requests before the claiming request finishes, so callers claim in a
/// short transaction of their own and complete in another.
///
/// An in-flight key is protected by a **lease**: the claimant promises to complete or release the key within the
/// lease. A process that dies in between never does, so once the lease has run out the next claim takes the key
/// over (the client's retry succeeds) instead of answering "in progress" until the key expires a day later.
///
/// **What the API layer does.** It claims with [`claim_leased`](Self::claim_leased) and a lease of the request
/// timeout (60 s by default) plus a margin, so a request that dies without releasing the key locks its client out
/// for about a minute, not for the ten minutes of [`DEFAULT_IN_FLIGHT_LEASE`]; it settles with
/// [`complete_leased`](Self::complete_leased) (which answers [`StoreError::LeaseLost`] when a retry took the key
/// over, so a slow first request never overwrites the response of the request that replaced it) and calls
/// [`release_leased`](Self::release_leased) when the request is cancelled or fails without a response.
#[async_trait]
pub trait IdempotencyRepo: Send {
    /// [`claim_with_lease`](Self::claim_with_lease) with [`DEFAULT_IN_FLIGHT_LEASE`]. Callers that know their
    /// request timeout use the leased methods instead.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn claim(&mut self, record: IdempotencyRecord) -> Result<IdempotencyClaim, StoreError> {
        self.claim_with_lease(record, DEFAULT_IN_FLIGHT_LEASE).await
    }

    /// Claims `record.token_id`/`record.key` atomically with an explicit lease for the in-flight state, counted
    /// from now by the adapter's clock: inserts the record as in flight, or, when a record exists whose
    /// `expires_at` has not passed (by the adapter's clock) and, if it is in flight, whose lease has not run out,
    /// returns it. Expired records and in-flight records with an expired lease are replaced.
    /// [`complete`](Self::complete) ends the lease; the key then lives until `record.expires_at`. A lease that is
    /// too short lets a retry run while the first request is still being processed. Every adapter implements this
    /// method; [`claim`](Self::claim) is the provided convenience.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn claim_with_lease(
        &mut self,
        record: IdempotencyRecord,
        lease: Duration,
    ) -> Result<IdempotencyClaim, StoreError>;

    /// [`claim_with_lease`](Self::claim_with_lease) that also returns the end of the lease it took, the proof for
    /// [`complete_leased`](Self::complete_leased) and [`release_leased`](Self::release_leased). Additive method:
    /// the default reports [`StoreError::Unsupported`]; both store adapters override it.
    ///
    /// # Errors
    ///
    /// `Unsupported` from stores that do not implement it.
    async fn claim_leased(&mut self, record: IdempotencyRecord, lease: Duration) -> Result<LeasedClaim, StoreError> {
        let _ = (record, lease);
        Err(StoreError::Unsupported)
    }

    /// [`complete`](Self::complete) that only acts while the claim is still the caller's: the key must be in
    /// flight with exactly the `lease_until` that [`claim_leased`](Self::claim_leased) returned. Additive method
    /// with the same default as `claim_leased`.
    ///
    /// # Errors
    ///
    /// `NotFound` when the key does not exist, `LeaseLost` when it is done, was released or was taken over by
    /// another claim after the lease ran out (nothing is changed), `Unsupported` from stores that do not
    /// implement it.
    async fn complete_leased(
        &mut self,
        token: TokenId,
        key: &str,
        lease_until: DateTime<Utc>,
        response_status: u16,
        response: Option<serde_json::Value>,
    ) -> Result<(), StoreError> {
        let _ = (token, key, lease_until, response_status, response);
        Err(StoreError::Unsupported)
    }

    /// [`release`](Self::release) that only acts while the claim is still the caller's (same condition as
    /// [`complete_leased`](Self::complete_leased)); a key that was taken over or finished is left alone and is
    /// not an error. Additive method with the same default as `claim_leased`.
    ///
    /// # Errors
    ///
    /// Store failures only; `Unsupported` from stores that do not implement it.
    async fn release_leased(
        &mut self,
        token: TokenId,
        key: &str,
        lease_until: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let _ = (token, key, lease_until);
        Err(StoreError::Unsupported)
    }

    /// Marks the key done, ends its lease and stores the response (`None` for responses that carry secrets and
    /// must not be replayed).
    ///
    /// # Errors
    ///
    /// `NotFound` when the key does not exist.
    async fn complete(
        &mut self,
        token: TokenId,
        key: &str,
        response_status: u16,
        response: Option<serde_json::Value>,
    ) -> Result<(), StoreError>;

    /// Removes an in-flight key whose request failed before producing a response, so the client can retry.
    ///
    /// # Errors
    ///
    /// Store failures only; a missing or finished key is not an error.
    async fn release(&mut self, token: TokenId, key: &str) -> Result<(), StoreError>;
}

/// An audit record to append.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAudit {
    /// The row id (from the `IdGenerator`).
    pub id: Uuid,
    /// Who acted.
    pub actor: AuditActor,
    /// What happened. The store splits it into the `action`, `target` and `details` columns with
    /// `AuditEvent::record`.
    pub event: AuditEvent,
}

/// An audit record as stored. The action stays a string so that records written by a newer binary can still be
/// listed.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditRow {
    /// The row id.
    pub id: Uuid,
    /// The tenant.
    pub tenant_id: TenantId,
    /// When it happened (from the `Clock`).
    pub at: DateTime<Utc>,
    /// Who acted.
    pub actor: AuditActor,
    /// The action name, for example `credential.created`.
    pub action: String,
    /// The target as `kind:id`, when the action has one.
    pub target: Option<String>,
    /// The remaining details (ids, kinds and counters only).
    pub details: serde_json::Value,
}

/// Filter of [`AuditRepo::list`]. Every set field must match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditFilter {
    /// Only this action.
    pub action: Option<String>,
    /// Only records at or after this time.
    pub since: Option<DateTime<Utc>>,
    /// Only records before this time.
    pub until: Option<DateTime<Utc>>,
    /// Only records whose actor is this principal.
    pub principal: Option<PrincipalId>,
    /// Only records with this target (`kind:id`).
    pub target: Option<String>,
}

/// The audit log of the transaction's tenant. The runtime role may insert and select, never update or delete.
#[async_trait]
pub trait AuditRepo: Send {
    /// Appends a record stamped with the adapter's clock.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn append(&mut self, entry: NewAudit) -> Result<(), StoreError>;

    /// Lists records in id order (which is chronological, ids being UUIDv7).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(&mut self, filter: &AuditFilter, page: PageReq) -> Result<StorePage<AuditRow>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_lease_outlasts_a_request() {
        assert!(
            DEFAULT_IN_FLIGHT_LEASE >= Duration::from_secs(60),
            "the default request timeout is 60 s"
        );
    }

    /// A repository that only implements what the trait requires, and remembers the lease it was asked for.
    #[derive(Default)]
    struct Stub {
        lease: Option<Duration>,
    }

    fn record() -> IdempotencyRecord {
        IdempotencyRecord {
            token_id: TokenId::from_uuid(Uuid::from_u128(1)),
            key: "k".to_owned(),
            method: "POST".to_owned(),
            path: "/x".to_owned(),
            fingerprint: "f".to_owned(),
            status: IdempotencyStatus::InFlight,
            response_status: None,
            response: None,
            expires_at: DateTime::UNIX_EPOCH,
        }
    }

    #[async_trait]
    impl IdempotencyRepo for Stub {
        async fn claim_with_lease(
            &mut self,
            _record: IdempotencyRecord,
            lease: Duration,
        ) -> Result<IdempotencyClaim, StoreError> {
            self.lease = Some(lease);
            Ok(IdempotencyClaim::Claimed)
        }

        async fn complete(
            &mut self,
            _token: TokenId,
            _key: &str,
            _response_status: u16,
            _response: Option<serde_json::Value>,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn release(&mut self, _token: TokenId, _key: &str) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_plain_claim_takes_the_default_lease() {
        let mut stub = Stub::default();
        assert_eq!(stub.claim(record()).await, Ok(IdempotencyClaim::Claimed));
        assert_eq!(stub.lease, Some(DEFAULT_IN_FLIGHT_LEASE));
    }

    #[tokio::test]
    async fn the_fenced_methods_are_unsupported_until_an_adapter_implements_them() {
        let mut stub = Stub::default();
        let token = TokenId::from_uuid(Uuid::from_u128(1));
        let until = DateTime::UNIX_EPOCH;
        assert_eq!(
            stub.claim_leased(record(), Duration::from_secs(1)).await,
            Err(StoreError::Unsupported)
        );
        assert_eq!(
            stub.complete_leased(token, "k", until, 200, None).await,
            Err(StoreError::Unsupported)
        );
        assert_eq!(
            stub.release_leased(token, "k", until).await,
            Err(StoreError::Unsupported)
        );
    }

    #[test]
    fn statuses_use_their_database_spelling() {
        assert_eq!(IdempotencyStatus::InFlight.as_str(), "in_flight");
        assert_eq!(IdempotencyStatus::Done.as_str(), "done");
    }

    #[test]
    fn audit_filters_default_to_everything() {
        let filter = AuditFilter::default();
        assert!(filter.action.is_none() && filter.since.is_none() && filter.until.is_none());
        assert!(filter.principal.is_none() && filter.target.is_none());
    }
}
