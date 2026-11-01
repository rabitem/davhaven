//! Webhook subscriptions and deliveries.

use async_trait::async_trait;
use davhaven_domain::{DeliveryId, RequestContext, WebhookId};
use davhaven_wire::{DeliveryView, Page, WebhookCreate, WebhookCreated, WebhookSecretRotated, WebhookView};

use super::common::{Conditions, MergePatch, PageRequest};
use crate::error::AppResult;

/// Management of outbound webhooks (PLAN 2.11). Every method needs `webhooks:manage`.
#[async_trait]
pub trait WebhookService: Send + Sync {
    /// Creates a subscription. The URL must be https and pass the egress policy now and on every delivery. The
    /// signing secret is returned once.
    ///
    /// # Errors
    ///
    /// `Invalid` for URLs the egress policy refuses and unknown event types, `Forbidden`.
    async fn create(&self, ctx: &RequestContext, request: WebhookCreate) -> AppResult<WebhookCreated>;

    /// Lists the subscriptions ordered by id.
    ///
    /// # Errors
    ///
    /// `Forbidden`, `Invalid` for a bad cursor.
    async fn list(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<WebhookView>>;

    /// Reads a subscription.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn get(&self, ctx: &RequestContext, id: WebhookId) -> AppResult<WebhookView>;

    /// Changes a subscription with a JSON Merge Patch (URL, description, events, details, active).
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed`, `Invalid`, `Forbidden`.
    async fn patch(
        &self,
        ctx: &RequestContext,
        id: WebhookId,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<WebhookView>;

    /// Deletes a subscription; pending deliveries are dropped.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn delete(&self, ctx: &RequestContext, id: WebhookId) -> AppResult<()>;

    /// Rotates the signing secret. Deliveries are signed with both secrets until the retry window passed.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn rotate_secret(&self, ctx: &RequestContext, id: WebhookId) -> AppResult<WebhookSecretRotated>;

    /// Sends a test event to the subscription and reports the delivery. The call is audited (`webhook.pinged`).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Conflict` when the subscription is disabled.
    async fn ping(&self, ctx: &RequestContext, id: WebhookId) -> AppResult<DeliveryView>;

    /// Lists the deliveries of a subscription, ordered by id.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Invalid` for a bad cursor.
    async fn deliveries(&self, ctx: &RequestContext, id: WebhookId, page: PageRequest)
    -> AppResult<Page<DeliveryView>>;

    /// Schedules a delivery again (dead or delivered ones alike) with a fresh retry window and reports it. The
    /// call is audited (`webhook.redelivered`).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`; `Conflict` when the subscription is disabled, when the delivery is still being
    /// attempted, or when its event has been purged from the outbox and can no longer be sent.
    async fn redeliver(&self, ctx: &RequestContext, id: WebhookId, delivery: DeliveryId) -> AppResult<DeliveryView>;
}
