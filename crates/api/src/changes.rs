//! The calendar changes feed.
//!
//! `GET …/changes?since=` reports what changed in a calendar since a sync token, the same tokens DAV clients use
//! (`urn:davhaven:sync:{collection}:{epoch}:{seq}`). A token that is garbled, from another calendar or epoch, from
//! the future or older than the retained history answers 410 `sync-token-expired`; the client starts over without
//! `since` (PLAN 2.7).

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_domain::{CalendarSlug, PrincipalName, SyncToken, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{ChangesResponse, ProblemCode};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::calendars::calendar_ref;
use crate::extract::{Keys, Params};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new().routes(routes!(list_changes))
}

/// The parameters of the changes feed.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ChangesQuery {
    /// The `sync_token` of the previous response; without it the feed starts at the current state.
    since: Option<String>,
    /// The most changes to return; a truncated response carries a token to continue from.
    limit: Option<u32>,
}

/// Lists the changes of a calendar since a sync token.
///
/// The response carries the token to pass as `since` next time. When `truncated` is true more changes follow:
/// call again with the new token.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/changes",
    operation_id = "listChanges",
    tag = "changes",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ChangesQuery
    ),
    responses((status = 200, description = "The changes and the token to continue from.", body = ChangesResponse))
)]
pub(crate) async fn list_changes(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
    Params(query): Params<ChangesQuery>,
) -> Result<Reply, EdgeProblem> {
    let since = query
        .since
        .map(|text| SyncToken::parse(&text))
        .transpose()
        .map_err(|_| {
            EdgeProblem::new(ProblemCode::SyncTokenExpired)
                .with_detail("The sync token is not valid; start over without `since`.")
        })?;
    let changes = state
        .services
        .objects
        .changes(&ctx, &calendar_ref(owner, slug), since, query.limit)
        .await?;
    Ok(Reply::json(StatusCode::OK, &changes))
}
