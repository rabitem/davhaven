//! Repositories for the outbox, webhooks, external provider accounts and OAuth states.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    DeliveryId, EventId, EventType, ExternalAccount, ExternalAccountId, OutboxId, PrincipalId, TenantId, WebhookId,
    WebhookSubscription,
};
use uuid::Uuid;

use super::{PageReq, StorePage};
use crate::error::StoreError;
use crate::outbox::{NewOutbox, OutboxRecord, OutboxStatus};

/// Filter of [`OutboxRepo::list`]. Every set field must match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutboxFilter {
    /// Only records in this state (the API lists dead ones).
    pub status: Option<OutboxStatus>,
    /// Only records of this kind.
    pub kind: Option<String>,
}

/// The outbox of the transaction's tenant: writing messages and inspecting them. Claiming and settling messages
/// crosses tenants and belongs to the system transaction (`OutboxQueue`).
///
/// Messages enqueued in a transaction exist only if it commits, so a change and the messages it causes are atomic.
#[async_trait]
pub trait OutboxRepo: Send {
    /// Enqueues a message as `pending`, due at `not_before` (or at the current time).
    ///
    /// # Errors
    ///
    /// [`StoreError::Internal`] when the message cannot be serialized or the id exists already.
    async fn enqueue(&mut self, message: NewOutbox) -> Result<(), StoreError>;

    /// The record with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: OutboxId) -> Result<OutboxRecord, StoreError>;

    /// Lists records in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(&mut self, filter: &OutboxFilter, page: PageReq) -> Result<StorePage<OutboxRecord>, StoreError>;

    /// Puts a dead record back to `pending`, due now, with its attempts reset.
    ///
    /// # Errors
    ///
    /// `NotFound`, and `PreconditionFailed` when the record is not dead.
    async fn requeue(&mut self, id: OutboxId) -> Result<(), StoreError>;
}

/// The state of a webhook delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DeliveryStatus {
    /// Waiting for the first or the next attempt.
    Pending,
    /// The subscriber answered with a success status.
    Delivered,
    /// The last attempt failed; another is scheduled.
    Failed,
    /// Gave up after the retry window.
    Dead,
}

impl DeliveryStatus {
    /// Every status, in lifecycle order.
    pub const ALL: [Self; 4] = [Self::Pending, Self::Delivered, Self::Failed, Self::Dead];

    /// The database and JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Dead => "dead",
        }
    }
}

/// A webhook delivery attempt record (`webhook_deliveries`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// Delivery id.
    pub id: DeliveryId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The subscription the event goes to.
    pub subscription_id: WebhookId,
    /// The delivered event.
    pub event_id: EventId,
    /// The delivery state.
    pub status: DeliveryStatus,
    /// How many attempts were made.
    pub attempts: u32,
    /// The HTTP status of the last attempt, if the subscriber answered.
    pub response_status: Option<u16>,
    /// The error of the last attempt, for operators.
    pub last_error: Option<String>,
    /// When the last attempt happened (or when the delivery was created).
    pub at: DateTime<Utc>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// Webhook subscriptions and their deliveries.
#[async_trait]
pub trait WebhookRepo: Send {
    /// The subscription with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: WebhookId) -> Result<WebhookSubscription, StoreError>;

    /// Lists subscriptions in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(&mut self, page: PageReq) -> Result<StorePage<WebhookSubscription>, StoreError>;

    /// The active subscriptions that receive events of `event_type`, in id order (the dispatcher's fan-out).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn subscribed_to(&mut self, event_type: EventType) -> Result<Vec<WebhookSubscription>, StoreError>;

    /// Creates a subscription.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn create(&mut self, subscription: WebhookSubscription) -> Result<WebhookSubscription, StoreError>;

    /// Replaces a subscription if the stored version equals `expected_version`.
    ///
    /// `failure_count` belongs to [`record_failure`](Self::record_failure) and
    /// [`record_success`](Self::record_success), which change it without a version bump, so `update` never writes
    /// the value of the entity it is given (a stale copy would otherwise erase concurrent failures). The one
    /// exception is re-enabling: an update that turns a deactivated subscription active again resets the counter
    /// to zero.
    ///
    /// # Errors
    ///
    /// `NotFound` and `PreconditionFailed`.
    async fn update(
        &mut self,
        subscription: WebhookSubscription,
        expected_version: i64,
    ) -> Result<WebhookSubscription, StoreError>;

    /// Deletes a subscription and its deliveries.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn delete(&mut self, id: WebhookId) -> Result<(), StoreError>;

    /// Resets `failure_count` to zero after a successful delivery. Does not change `version`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn record_success(&mut self, id: WebhookId) -> Result<(), StoreError>;

    /// Increments `failure_count` atomically and returns the new value. Does not change `version`, so concurrent
    /// deliveries never conflict.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn record_failure(&mut self, id: WebhookId) -> Result<u32, StoreError>;

    /// Deactivates a subscription and records why (`disabled_reason`), for example after too many failures.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn disable(&mut self, id: WebhookId, reason: &str) -> Result<(), StoreError>;

    /// Creates a delivery record. There is at most one delivery per subscription and event: when the event was
    /// fanned out to the subscription before (the dispatcher repeats a fan-out after a crash), the existing record
    /// is returned unchanged and nothing is written.
    ///
    /// # Errors
    ///
    /// `NotFound` when the subscription does not exist.
    async fn create_delivery(&mut self, delivery: DeliveryRecord) -> Result<DeliveryRecord, StoreError>;

    /// The delivery with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_delivery(&mut self, id: DeliveryId) -> Result<DeliveryRecord, StoreError>;

    /// Lists the deliveries of a subscription in id order.
    ///
    /// # Errors
    ///
    /// `NotFound` when the subscription does not exist.
    async fn list_deliveries(
        &mut self,
        subscription: WebhookId,
        page: PageReq,
    ) -> Result<StorePage<DeliveryRecord>, StoreError>;

    /// Replaces a delivery record if the stored version equals `expected_version`.
    ///
    /// # Errors
    ///
    /// `NotFound` and `PreconditionFailed`.
    async fn update_delivery(
        &mut self,
        delivery: DeliveryRecord,
        expected_version: i64,
    ) -> Result<DeliveryRecord, StoreError>;
}

/// Filter of [`ExternalAccountRepo::list`]. Every set field must match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalAccountFilter {
    /// Only accounts of this principal.
    pub principal: Option<PrincipalId>,
    /// Only accounts at this provider.
    pub provider: Option<String>,
}

/// External provider accounts of the transaction's tenant.
#[async_trait]
pub trait ExternalAccountRepo: Send {
    /// The account with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: ExternalAccountId) -> Result<ExternalAccount, StoreError>;

    /// Lists accounts in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(
        &mut self,
        filter: &ExternalAccountFilter,
        page: PageReq,
    ) -> Result<StorePage<ExternalAccount>, StoreError>;

    /// Creates an account.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal or the mirror calendar does not exist.
    async fn create(&mut self, account: ExternalAccount) -> Result<ExternalAccount, StoreError>;

    /// Replaces an account (tokens, sync state, status) if the stored version equals `expected_version`.
    ///
    /// # Errors
    ///
    /// `NotFound` and `PreconditionFailed`.
    async fn update(&mut self, account: ExternalAccount, expected_version: i64) -> Result<ExternalAccount, StoreError>;

    /// Deletes an account.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn delete(&mut self, id: ExternalAccountId) -> Result<(), StoreError>;
}

/// The state of one OAuth authorization in progress (`oauth_states`): single use, ten minutes, bound to tenant,
/// principal and provider.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthState {
    /// Row id.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The principal who started the flow.
    pub principal_id: PrincipalId,
    /// The provider name.
    pub provider: String,
    /// The keyed hash of the `state` value sent to the provider.
    pub state_hash: Vec<u8>,
    /// The PKCE verifier, sealed with the secret sealer.
    pub pkce_verifier_sealed: Vec<u8>,
    /// When the state stops being valid.
    pub expires_at: DateTime<Utc>,
    /// When the state was consumed, if it was.
    pub used_at: Option<DateTime<Utc>>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

impl core::fmt::Debug for OAuthState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OAuthState")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("provider", &self.provider)
            .field(
                "state_hash",
                &format_args!("<{} bytes redacted>", self.state_hash.len()),
            )
            .field(
                "pkce_verifier_sealed",
                &format_args!("<{} bytes redacted>", self.pkce_verifier_sealed.len()),
            )
            .field("expires_at", &self.expires_at)
            .field("used_at", &self.used_at)
            .finish_non_exhaustive()
    }
}

/// OAuth authorization states.
#[async_trait]
pub trait OAuthStateRepo: Send {
    /// Stores a new state.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist and `UniqueViolation` of `OAuthState`.
    async fn create(&mut self, state: OAuthState) -> Result<OAuthState, StoreError>;

    /// Consumes the state with this hash: marks it used and returns it, atomically, so a state works once.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown, expired (by the adapter's clock) or already used state; callers answer all three
    /// the same way.
    async fn consume(&mut self, state_hash: &[u8]) -> Result<OAuthState, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_statuses_use_their_database_spelling() {
        let names: Vec<&str> = DeliveryStatus::ALL.iter().map(|status| status.as_str()).collect();
        assert_eq!(names, vec!["pending", "delivered", "failed", "dead"]);
    }

    #[test]
    fn oauth_states_do_not_debug_print_secrets() {
        let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let state = OAuthState {
            id: Uuid::from_u128(1),
            tenant_id: TenantId::from_uuid(Uuid::from_u128(2)),
            principal_id: PrincipalId::from_uuid(Uuid::from_u128(3)),
            provider: "google".to_owned(),
            state_hash: vec![0xde, 0xad],
            pkce_verifier_sealed: vec![0xbe, 0xef, 0x01],
            expires_at: at,
            used_at: None,
            created_at: at,
        };
        let shown = format!("{state:?}");
        assert!(
            shown.contains("<2 bytes redacted>") && shown.contains("<3 bytes redacted>"),
            "{shown}"
        );
        assert!(!shown.contains("222") && !shown.contains("190"), "{shown}");
    }

    #[test]
    fn filters_default_to_everything() {
        assert!(OutboxFilter::default().status.is_none());
        assert!(ExternalAccountFilter::default().principal.is_none());
    }
}
