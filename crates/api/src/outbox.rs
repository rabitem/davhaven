//! Outbox inspection and retry resources.

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_app::services::OutboxFilter;
use davhaven_domain::{OutboxId, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{OutboxItemView, OutboxStatus, Page};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{Keys, PageParams, Paging, Params};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_outbox))
        .routes(routes!(retry_outbox))
}

/// The filter of the outbox listing.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct OutboxQuery {
    /// Only items in this state; `dead` lists what needs an operator.
    status: Option<OutboxStatus>,
}

/// Lists the outbox items of a tenant.
///
/// The outbox holds mails, internal deliveries, webhook deliveries and domain events that are waiting, running,
/// done or dead. Items are ordered by id.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/outbox",
    operation_id = "listOutbox",
    tag = "outbox",
    params(("tenant" = String, Path, description = "The tenant slug."), OutboxQuery, PageParams),
    responses((status = 200, description = "A page of outbox items.", body = Page<OutboxItemView>))
)]
pub(crate) async fn list_outbox(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    Params(query): Params<OutboxQuery>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let filter = OutboxFilter { status: query.status };
    let page = state.services.outbox.list(&ctx, filter, paging.request()).await?;
    Ok(paging.reply(&page))
}

/// Makes a dead outbox item due again.
///
/// Answers 409 for items that are not dead.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/outbox/{id}/retry",
    operation_id = "retryOutbox",
    tag = "outbox",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the outbox item.")
    ),
    responses((status = 200, description = "The item, due again.", body = OutboxItemView))
)]
pub(crate) async fn retry_outbox(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, OutboxId)>,
) -> Result<Reply, EdgeProblem> {
    let item = state.services.outbox.retry(&ctx, id).await?;
    Ok(Reply::json(StatusCode::OK, &item).replayable())
}
