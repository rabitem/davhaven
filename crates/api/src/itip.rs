//! The inbound iTIP endpoint for mail gateways.
//!
//! A gateway that receives replies to scheduling mails posts them here (PLAN 2.8). The endpoint is disabled by
//! default and answers 409 `feature-not-enabled` until the deployment and the tenant enable it. Messages need a
//! gateway-supplied DMARC or DKIM pass; messages that do not match an existing organizer object are quarantined and
//! reported in the outcome, not rejected.

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_domain::TenantSlug;
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{InboundItipRequest, InboundItipResponse};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{JsonBody, Keys};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new().routes(routes!(inbound_itip))
}

/// Delivers an inbound iTIP message from a mail gateway.
///
/// Messages are deduplicated on `message_id` and rate-limited per sender. Needs the scope `itip:inbound`.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/itip/inbound",
    operation_id = "inboundItip",
    tag = "events",
    params(("tenant" = String, Path, description = "The tenant slug.")),
    request_body = InboundItipRequest,
    responses((status = 200, description = "What the server did with the message.", body = InboundItipResponse))
)]
pub(crate) async fn inbound_itip(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    JsonBody(request): JsonBody<InboundItipRequest>,
) -> Result<Reply, EdgeProblem> {
    let response = state.services.scheduling.inbound_itip(&ctx, request).await?;
    Ok(Reply::json(StatusCode::OK, &response).replayable())
}
