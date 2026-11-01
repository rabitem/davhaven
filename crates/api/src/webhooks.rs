//! Webhook subscription and delivery resources.
//!
//! Subscriptions follow the Standard Webhooks conventions (PLAN 2.11); the signing secret (`whsec_…`) is shown once,
//! when the subscription is created or its secret rotated, in `no-store` responses.

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_domain::{DeliveryId, TenantSlug, WebhookId};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{DeliveryView, Page, WebhookCreate, WebhookCreated, WebhookSecretRotated, WebhookView};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{JsonBody, Keys, PageParams, Paging, PatchBody, Preconditions};
use crate::openapi::MergePatchDocument;
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_webhooks, create_webhook))
        .routes(routes!(get_webhook, patch_webhook, delete_webhook))
        .routes(routes!(rotate_webhook_secret))
        .routes(routes!(ping_webhook))
        .routes(routes!(list_deliveries))
        .routes(routes!(redeliver_webhook))
}

/// Lists the webhook subscriptions of a tenant.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/webhooks",
    operation_id = "listWebhooks",
    tag = "webhooks",
    params(("tenant" = String, Path, description = "The tenant slug."), PageParams),
    responses((status = 200, description = "A page of subscriptions.", body = Page<WebhookView>))
)]
pub(crate) async fn list_webhooks(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let page = state.services.webhooks.list(&ctx, paging.request()).await?;
    Ok(paging.reply(&page))
}

/// Creates a webhook subscription.
///
/// The URL must be https and pass the egress policy now and on every delivery. The signing secret is in the
/// response and nowhere else.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/webhooks",
    operation_id = "createWebhook",
    tag = "webhooks",
    params(
        ("tenant" = String, Path, description = "The tenant slug.")
    ),
    request_body = WebhookCreate,
    responses((status = 201, description = "The subscription and its signing secret, shown once.",
        body = WebhookCreated,
        headers(("Location" = String), ("Cache-Control" = String, description = "`no-store`")))
    )
)]
pub(crate) async fn create_webhook(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(tenant): Keys<TenantSlug>,
    JsonBody(request): JsonBody<WebhookCreate>,
) -> Result<Reply, EdgeProblem> {
    let created = state.services.webhooks.create(&ctx, request).await?;
    let reply = Reply::json(StatusCode::CREATED, &created).no_store();
    let location = state.location(&format!("tenants/{tenant}/webhooks/{}", created.webhook.id));
    Ok(match &location {
        Some(url) => reply.with_location(url),
        None => reply,
    })
}

/// Reads a webhook subscription.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/webhooks/{id}",
    operation_id = "getWebhook",
    tag = "webhooks",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the subscription.")
    ),
    responses((status = 200, description = "The subscription.", body = WebhookView, headers(("ETag" = String))))
)]
pub(crate) async fn get_webhook(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, WebhookId)>,
) -> Result<Reply, EdgeProblem> {
    let webhook = state.services.webhooks.get(&ctx, id).await?;
    Ok(Reply::versioned(StatusCode::OK, &webhook))
}

/// Changes a webhook subscription with a JSON Merge Patch.
///
/// URL, description, events, details and the active flag can change. Re-enabling a subscription that was
/// disabled after repeated failures resets its failure count.
#[utoipa::path(
    patch,
    path = "/tenants/{tenant}/webhooks/{id}",
    operation_id = "patchWebhook",
    tag = "webhooks",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the subscription."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412.")
    ),
    request_body(content = MergePatchDocument, content_type = "application/merge-patch+json"),
    responses((status = 200, description = "The changed subscription.", body = WebhookView, headers(("ETag" = String))))
)]
pub(crate) async fn patch_webhook(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, WebhookId)>,
    Preconditions(conditions): Preconditions,
    PatchBody(patch): PatchBody,
) -> Result<Reply, EdgeProblem> {
    let webhook = state.services.webhooks.patch(&ctx, id, patch, conditions).await?;
    Ok(Reply::versioned(StatusCode::OK, &webhook))
}

/// Deletes a webhook subscription.
///
/// Pending deliveries are dropped.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}/webhooks/{id}",
    operation_id = "deleteWebhook",
    tag = "webhooks",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the subscription.")
    ),
    responses((status = 204, description = "The subscription was deleted."))
)]
pub(crate) async fn delete_webhook(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, WebhookId)>,
) -> Result<Reply, EdgeProblem> {
    state.services.webhooks.delete(&ctx, id).await?;
    Ok(Reply::no_content())
}

/// Rotates the signing secret of a subscription.
///
/// Deliveries are signed with both the new and the previous secret until the retry window has passed, so
/// consumers can switch without losing events. The new secret is shown once.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/webhooks/{id}/rotate-secret",
    operation_id = "rotateWebhookSecret",
    tag = "webhooks",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the subscription.")
    ),
    responses((status = 200, description = "The new signing secret, shown once.", body = WebhookSecretRotated,
        headers(("Cache-Control" = String, description = "`no-store`")))
    )
)]
pub(crate) async fn rotate_webhook_secret(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, WebhookId)>,
) -> Result<Reply, EdgeProblem> {
    let rotated = state.services.webhooks.rotate_secret(&ctx, id).await?;
    Ok(Reply::json(StatusCode::OK, &rotated).no_store())
}

/// Sends a test event to a subscription.
///
/// Answers 409 for a disabled subscription.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/webhooks/{id}/ping",
    operation_id = "pingWebhook",
    tag = "webhooks",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the subscription.")
    ),
    responses((status = 200, description = "The delivery of the test event.", body = DeliveryView))
)]
pub(crate) async fn ping_webhook(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, WebhookId)>,
) -> Result<Reply, EdgeProblem> {
    let delivery = state.services.webhooks.ping(&ctx, id).await?;
    Ok(Reply::json(StatusCode::OK, &delivery).replayable())
}

/// Lists the deliveries of a subscription.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/webhooks/{id}/deliveries",
    operation_id = "listDeliveries",
    tag = "webhooks",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the subscription."),
        PageParams
    ),
    responses((status = 200, description = "A page of deliveries.", body = Page<DeliveryView>))
)]
pub(crate) async fn list_deliveries(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, WebhookId)>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let page = state.services.webhooks.deliveries(&ctx, id, paging.request()).await?;
    Ok(paging.reply(&page))
}

/// Schedules a delivery again.
///
/// Works for delivered and dead deliveries alike; the delivery is retried by the outbox.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/webhooks/{id}/deliveries/{delivery}/redeliver",
    operation_id = "redeliverWebhook",
    tag = "webhooks",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the subscription."),
        ("delivery" = String, Path, description = "The id of the delivery.")
    ),
    responses((status = 202, description = "The delivery is scheduled again.", body = DeliveryView))
)]
pub(crate) async fn redeliver_webhook(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id, delivery)): Keys<(TenantSlug, WebhookId, DeliveryId)>,
) -> Result<Reply, EdgeProblem> {
    let delivery = state.services.webhooks.redeliver(&ctx, id, delivery).await?;
    Ok(Reply::json(StatusCode::ACCEPTED, &delivery).replayable())
}
