//! Calendar grant resources: sharing a calendar with users, groups and service principals through the API.
//!
//! Grants made here are effective at once. The last write wins between the API and DAV sharing; the `source` of a
//! grant records which one made it.

use axum::extract::State;
use davhaven_app::services::GrantSpec;
use davhaven_domain::{CalendarSlug, PrincipalName, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{GrantView, GrantWrite, Page};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::calendars::calendar_ref;
use crate::extract::{JsonBody, Keys, PageParams, Paging, Preconditions};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_grants))
        .routes(routes!(put_grant, delete_grant))
}

/// Lists the grants of a calendar.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/grants",
    operation_id = "listGrants",
    tag = "grants",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        PageParams
    ),
    responses((status = 200, description = "A page of grants.", body = Page<GrantView>))
)]
pub(crate) async fn list_grants(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let page = state
        .services
        .sharing
        .list_grants(&ctx, &calendar_ref(owner, slug), paging.request())
        .await?;
    Ok(paging.reply(&page))
}

/// Grants a user, a group or a service principal access to a calendar.
///
/// Creates the grant or replaces the access level of an existing one. Groups are expanded dynamically: members
/// who join later gain access, members who leave lose it. A **service principal** (the machine identity of an assistant
/// or an integration, which holds principal tokens for the API and MCP) is granted like a user; client sharing
/// (`CS:share`) and principal search do not offer it. Resources are refused (422), and so is the owner of the calendar,
/// except a **group that owns its calendar**: it may be granted that calendar to mark it `required` for its members. That
/// grant adds no access (the members have the group's default access already), so its access is `read`, and only a tenant
/// token puts it.
///
/// **`required`.** A grant with `required: true` makes the calendar mandatory for everybody it reaches (the grantee, or the
/// members of a grantee group): a calendar app that deletes the collection is refused with 403 (`DAV:need-privileges`,
/// `DAV:unbind`) instead of hiding it for good, and bindings that were hidden before come back, including those of people
/// who join the group later. A grant without the flag is optional: deleting the collection hides it, and
/// `POST …/bindings/{binding}/restore` shows it again. `PUT` replaces the grant, so a body without `required` makes the
/// grant optional: **send the flag on every `PUT`.** Only a tenant token sets or clears it; a principal's token is refused
/// with 403 when it asks for `true`, a grant it puts keeps the flag the grant has, and it cannot remove a required grant. A
/// client's `CS:share` never sets the flag and cannot change or remove a grant that has it.
#[utoipa::path(
    put,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/grants/{grantee}",
    operation_id = "putGrant",
    tag = "grants",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ("grantee" = String, Path, description = "The name of the user, group or service principal that is granted access."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412."),
        ("If-None-Match" = Option<String>, Header, description = "`*` to create only; an existing resource answers 412.")
    ),
    request_body = GrantWrite,
    responses(
        (status = 201, description = "The grant was created.", body = GrantView,
            headers(("ETag" = String), ("Location" = String))),
        (status = 200, description = "The grant was replaced.", body = GrantView, headers(("ETag" = String)))
    )
)]
pub(crate) async fn put_grant(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((tenant, owner, slug, grantee)): Keys<(TenantSlug, PrincipalName, CalendarSlug, PrincipalName)>,
    Preconditions(conditions): Preconditions,
    JsonBody(body): JsonBody<GrantWrite>,
) -> Result<Reply, EdgeProblem> {
    let location = state.location(&format!(
        "tenants/{tenant}/principals/{owner}/calendars/{slug}/grants/{grantee}"
    ));
    let spec = GrantSpec {
        calendar: calendar_ref(owner, slug),
        grantee,
        body,
    };
    let outcome = state.services.sharing.put_grant(&ctx, spec, conditions).await?;
    Ok(Reply::upserted(&outcome, location.as_ref()))
}

/// Removes the grant of a user, a group or a service principal.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/grants/{grantee}",
    operation_id = "deleteGrant",
    tag = "grants",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ("grantee" = String, Path, description = "The name of the user, group or service principal."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412.")
    ),
    responses((status = 204, description = "The grant was removed."))
)]
pub(crate) async fn delete_grant(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug, grantee)): Keys<(TenantSlug, PrincipalName, CalendarSlug, PrincipalName)>,
    Preconditions(conditions): Preconditions,
) -> Result<Reply, EdgeProblem> {
    state
        .services
        .sharing
        .delete_grant(&ctx, &calendar_ref(owner, slug), &grantee, conditions)
        .await?;
    Ok(Reply::no_content())
}
