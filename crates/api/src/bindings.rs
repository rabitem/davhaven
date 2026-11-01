//! The calendars in the home of a principal: listing the bindings, hidden ones included, and restoring a hidden one.
//!
//! A principal who deletes a shared calendar (a group calendar, a managed one, a calendar somebody shared) in a calendar app
//! only hides the binding of their home: the calendar and the grant stay, and nothing in a calendar app brings it back. These
//! two operations are the way back for an operator. Calendars that must not leave a home at all are marked with the `required`
//! flag of their grant (`PUT …/grants/{grantee}`); a calendar app that deletes such a calendar is refused.

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_app::services::BindingFilter;
use davhaven_domain::{CalendarSlug, PrincipalName, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{HomeBindingView, Page};
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
        .routes(routes!(list_bindings))
        .routes(routes!(restore_binding))
}

/// The filter of the binding listing.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct BindingQuery {
    /// `true` lists only the bindings the principal removed from their home, `false` only the visible ones; without the
    /// parameter every binding is listed.
    hidden: Option<bool>,
}

/// Lists the calendars in the home of a principal.
///
/// The bindings of the principal's home that their calendar apps can list, **hidden ones included**: a principal who deletes a
/// shared calendar in a calendar app hides its binding, and `hidden` says so (`?hidden=true` lists only those). `required` says
/// that the principal cannot remove the calendar (a grant with the `required` flag reaches them). A calendar the principal can
/// no longer reach (a removed group member, a revoked grant) is not listed, and a binding exists from the principal's first
/// listing of the home on, so the list holds the bindings created so far. `slug` is the last segment of the DAV path and the
/// `{binding}` of the restore path. Bindings are ordered by id.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}/bindings",
    operation_id = "listBindings",
    tag = "calendars",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal whose home is listed."),
        BindingQuery,
        PageParams
    ),
    responses((status = 200, description = "A page of bindings.", body = Page<HomeBindingView>))
)]
pub(crate) async fn list_bindings(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, principal)): Keys<(TenantSlug, PrincipalName)>,
    Params(query): Params<BindingQuery>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let filter = BindingFilter { hidden: query.hidden };
    let page = state
        .services
        .calendars
        .list_bindings(&ctx, &principal, filter, paging.request())
        .await?;
    Ok(paging.reply(&page))
}

/// Shows a hidden binding in the home of a principal again.
///
/// The calendar is listed by the principal's calendar apps at their next sync. The calendar itself and its grants were never
/// touched, so nothing else needs repair. Restoring a binding that is visible changes nothing and answers 200 as well, so a
/// client can restore what it listed without checking. A binding of a calendar the principal can no longer reach answers 404,
/// as an unknown one does. The restoration is audited (`binding.restored`). A binding has no `ETag`: it cannot be fetched or
/// changed on its own.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/principals/{principal}/bindings/{binding}/restore",
    operation_id = "restoreBinding",
    tag = "calendars",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal whose home lists the binding."),
        ("binding" = String, Path, description = "The slug of the collection in the principal's home (`slug` of the listing).")
    ),
    responses((status = 200, description = "The binding, visible.", body = HomeBindingView))
)]
pub(crate) async fn restore_binding(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, principal, binding)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
) -> Result<Reply, EdgeProblem> {
    let view = state
        .services
        .calendars
        .restore_binding(&ctx, &principal, &binding)
        .await?;
    Ok(Reply::json(StatusCode::OK, &view).replayable())
}
