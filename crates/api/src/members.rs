//! Group membership resources.

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_domain::{PrincipalName, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::MembershipSet;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{JsonBody, Keys};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(get_members, set_members))
        .routes(routes!(add_member, remove_member))
}

/// Lists the members of a group.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{group}/members",
    operation_id = "getMembers",
    tag = "memberships",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("group" = String, Path, description = "The name of the group principal.")
    ),
    responses((status = 200, description = "The member set of the group.", body = MembershipSet))
)]
pub(crate) async fn get_members(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, group)): Keys<(TenantSlug, PrincipalName)>,
) -> Result<Reply, EdgeProblem> {
    let members = state.services.principals.members(&ctx, &group).await?;
    Ok(Reply::json(StatusCode::OK, &members))
}

/// Replaces the member set of a group.
///
/// The body is the complete set; members that are not listed are removed. Members are users, resources or
/// services of the same tenant; groups cannot be members.
#[utoipa::path(
    put,
    path = "/tenants/{tenant}/principals/{group}/members",
    operation_id = "setMembers",
    tag = "memberships",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("group" = String, Path, description = "The name of the group principal.")
    ),
    request_body = MembershipSet,
    responses((status = 200, description = "The new member set.", body = MembershipSet))
)]
pub(crate) async fn set_members(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, group)): Keys<(TenantSlug, PrincipalName)>,
    JsonBody(set): JsonBody<MembershipSet>,
) -> Result<Reply, EdgeProblem> {
    let members = state.services.principals.set_members(&ctx, &group, set.members).await?;
    Ok(Reply::json(StatusCode::OK, &members))
}

/// Adds one member to a group.
///
/// Adding an existing member changes nothing.
#[utoipa::path(
    put,
    path = "/tenants/{tenant}/principals/{group}/members/{member}",
    operation_id = "addMember",
    tag = "memberships",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("group" = String, Path, description = "The name of the group principal."),
        ("member" = String, Path, description = "The name of the member principal.")
    ),
    responses((status = 204, description = "The principal is a member."))
)]
pub(crate) async fn add_member(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, group, member)): Keys<(TenantSlug, PrincipalName, PrincipalName)>,
) -> Result<Reply, EdgeProblem> {
    state.services.principals.add_member(&ctx, &group, &member).await?;
    Ok(Reply::no_content())
}

/// Removes one member from a group.
///
/// Removing a principal that is not a member changes nothing.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}/principals/{group}/members/{member}",
    operation_id = "removeMember",
    tag = "memberships",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("group" = String, Path, description = "The name of the group principal."),
        ("member" = String, Path, description = "The name of the member principal.")
    ),
    responses((status = 204, description = "The principal is not a member."))
)]
pub(crate) async fn remove_member(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, group, member)): Keys<(TenantSlug, PrincipalName, PrincipalName)>,
) -> Result<Reply, EdgeProblem> {
    state.services.principals.remove_member(&ctx, &group, &member).await?;
    Ok(Reply::no_content())
}
