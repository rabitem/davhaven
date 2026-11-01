//! Calendar resources: the calendars of a principal and the search across the tenant.

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_app::services::{CalendarRef, CalendarSearch, CalendarSpec};
use davhaven_domain::{CalendarKind, CalendarSlug, PrincipalName, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{CalendarView, CalendarWrite, Page};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{JsonBody, Keys, PageParams, Paging, Params, PatchBody, Preconditions};
use crate::openapi::MergePatchDocument;
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_calendars))
        .routes(routes!(get_calendar, put_calendar, patch_calendar, delete_calendar))
        .routes(routes!(search_calendars))
}

/// The reference to a calendar by its natural key: the owner's name and the calendar slug.
pub(crate) fn calendar_ref(owner: PrincipalName, slug: CalendarSlug) -> CalendarRef {
    CalendarRef::Key { owner, slug }
}

/// The filters of the tenant-wide calendar search.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CalendarQuery {
    /// Text to look for in the name and description of calendars.
    #[serde(rename = "q")]
    query: Option<String>,
    /// Only calendars of this kind: `personal`, `group`, `managed`, `user` or `mirror`.
    #[param(value_type = Option<String>)]
    kind: Option<CalendarKind>,
    /// Only calendars owned by this principal.
    #[param(value_type = Option<String>)]
    owner: Option<PrincipalName>,
}

/// Lists the calendars a principal owns.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}/calendars",
    operation_id = "listCalendars",
    tag = "calendars",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        PageParams
    ),
    responses((status = 200, description = "A page of calendars.", body = Page<CalendarView>))
)]
pub(crate) async fn list_calendars(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner)): Keys<(TenantSlug, PrincipalName)>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let page = state
        .services
        .calendars
        .list_owned(&ctx, &owner, paging.request())
        .await?;
    Ok(paging.reply(&page))
}

/// Reads a calendar.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
    operation_id = "getCalendar",
    tag = "calendars",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug.")
    ),
    responses((status = 200, description = "The calendar.", body = CalendarView, headers(("ETag" = String))))
)]
pub(crate) async fn get_calendar(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
) -> Result<Reply, EdgeProblem> {
    let calendar = state.services.calendars.get(&ctx, &calendar_ref(owner, slug)).await?;
    Ok(Reply::versioned(StatusCode::OK, &calendar))
}

/// Creates or replaces a calendar.
///
/// Managed calendars are created with `kind: managed`; their objects are written through this API only.
#[utoipa::path(
    put,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
    operation_id = "putCalendar",
    tag = "calendars",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412."),
        ("If-None-Match" = Option<String>, Header, description = "`*` to create only; an existing resource answers 412.")
    ),
    request_body = CalendarWrite,
    responses(
        (status = 201, description = "The calendar was created.", body = CalendarView,
            headers(("ETag" = String), ("Location" = String))),
        (status = 200, description = "The calendar was replaced.", body = CalendarView, headers(("ETag" = String)))
    )
)]
pub(crate) async fn put_calendar(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((tenant, owner, slug)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
    Preconditions(conditions): Preconditions,
    JsonBody(body): JsonBody<CalendarWrite>,
) -> Result<Reply, EdgeProblem> {
    let location = state.location(&format!("tenants/{tenant}/principals/{owner}/calendars/{slug}"));
    let outcome = state
        .services
        .calendars
        .upsert(&ctx, CalendarSpec { owner, slug, body }, conditions)
        .await?;
    Ok(Reply::upserted(&outcome, location.as_ref()))
}

/// Changes a calendar with a JSON Merge Patch.
#[utoipa::path(
    patch,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
    operation_id = "patchCalendar",
    tag = "calendars",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412.")
    ),
    request_body(content = MergePatchDocument, content_type = "application/merge-patch+json"),
    responses((status = 200, description = "The changed calendar.", body = CalendarView, headers(("ETag" = String))))
)]
pub(crate) async fn patch_calendar(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
    Preconditions(conditions): Preconditions,
    PatchBody(patch): PatchBody,
) -> Result<Reply, EdgeProblem> {
    let calendar = state
        .services
        .calendars
        .patch(&ctx, &calendar_ref(owner, slug), patch, conditions)
        .await?;
    Ok(Reply::versioned(StatusCode::OK, &calendar))
}

/// Deletes a calendar for everyone.
///
/// The calendar is soft-deleted and purged after the retention period. Requires `If-Match`.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
    operation_id = "deleteCalendar",
    tag = "calendars",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ("If-Match" = String, Header, description = "The ETag of the version to delete; without it the request answers 428.")
    ),
    responses((status = 204, description = "The calendar was deleted."))
)]
pub(crate) async fn delete_calendar(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
    Preconditions(conditions): Preconditions,
) -> Result<Reply, EdgeProblem> {
    state
        .services
        .calendars
        .delete(&ctx, &calendar_ref(owner, slug), conditions)
        .await?;
    Ok(Reply::no_content())
}

/// Searches the calendars of a tenant.
///
/// Filter by text (`q`), `kind` or `owner`. Calendars are ordered by id.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/calendars",
    operation_id = "searchCalendars",
    tag = "calendars",
    params(("tenant" = String, Path, description = "The tenant slug."), CalendarQuery, PageParams),
    responses((status = 200, description = "A page of calendars.", body = Page<CalendarView>))
)]
pub(crate) async fn search_calendars(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    Params(query): Params<CalendarQuery>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let search = CalendarSearch {
        query: query.query,
        kind: query.kind,
        owner: query.owner,
    };
    let page = state
        .services
        .calendars
        .list_tenant(&ctx, search, paging.request())
        .await?;
    Ok(paging.reply(&page))
}
