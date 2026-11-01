//! Principal resources: users, groups, resources and service principals.

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_app::services::{DeleteOptions, PrincipalFilter, PrincipalSpec};
use davhaven_domain::{PrincipalKind, PrincipalName, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{Page, PrincipalView, PrincipalWrite};
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
    OpenApiRouter::new().routes(routes!(list_principals)).routes(routes!(
        get_principal,
        put_principal,
        patch_principal,
        delete_principal
    ))
}

/// The filters of the principal listing.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct PrincipalQuery {
    /// Only principals of this kind: `user`, `group`, `resource` or `service`.
    #[param(value_type = Option<String>)]
    kind: Option<PrincipalKind>,
    /// Only the principal with this external reference (at most one matches).
    external_ref: Option<String>,
}

/// The options of a principal `DELETE`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct DeleteQuery {
    /// Purge the principal at once instead of after the retention period.
    #[serde(default)]
    purge: bool,
    /// Send cancellations for events the principal organizes in group calendars.
    #[serde(default)]
    notify_attendees: bool,
}

/// Lists the principals of a tenant.
///
/// Filter by `kind` or `external_ref`. Principals are ordered by id; deleted principals are not listed.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals",
    operation_id = "listPrincipals",
    tag = "principals",
    params(("tenant" = String, Path, description = "The tenant slug."), PrincipalQuery, PageParams),
    responses((status = 200, description = "A page of principals.", body = Page<PrincipalView>))
)]
pub(crate) async fn list_principals(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    Params(query): Params<PrincipalQuery>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let filter = PrincipalFilter {
        kind: query.kind,
        external_ref: query.external_ref,
    };
    let page = state.services.principals.list(&ctx, filter, paging.request()).await?;
    Ok(paging.reply(&page))
}

/// Reads a principal.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}",
    operation_id = "getPrincipal",
    tag = "principals",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner.")
    ),
    responses((status = 200, description = "The principal.", body = PrincipalView, headers(("ETag" = String))))
)]
pub(crate) async fn get_principal(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, name)): Keys<(TenantSlug, PrincipalName)>,
) -> Result<Reply, EdgeProblem> {
    let principal = state.services.principals.get(&ctx, &name).await?;
    Ok(Reply::versioned(StatusCode::OK, &principal))
}

/// Creates or replaces a principal.
///
/// Declarative provisioning: sending the same body twice changes nothing. The kind of an existing principal cannot
/// change.
///
/// **Deleted principals.** A principal that was deleted without `purge=true` is hidden (it is not listed and not found
/// by `external_ref`), but its name, its `external_ref` and its addresses stay reserved until it is purged
/// (`retention.principal_purge_days`, or `DELETE …?purge=true` before). The answers are fixed so that a client that
/// provisions principals can tell them from a conflict with a live principal: `If-None-Match: *` for the name of a
/// deleted principal answers **412** (`precondition-failed`, exactly as for a name that exists, with no hint about
/// the hidden principal); a write **without** it for that name answers **409** `name-reserved`; a create or a replace
/// whose `external_ref` collides with a deleted principal answers **409** `external-ref-reserved`, and one whose
/// address collides with it **409** `address-reserved`. Purge the hidden principal or wait for the retention period,
/// then repeat the request. A collision with a **live** principal is the plain 409 `conflict`.
#[utoipa::path(
    put,
    path = "/tenants/{tenant}/principals/{principal}",
    operation_id = "putPrincipal",
    tag = "principals",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412."),
        ("If-None-Match" = Option<String>, Header, description = "`*` to create only; an existing resource answers 412.")
    ),
    request_body = PrincipalWrite,
    responses(
        (status = 201, description = "The principal was created.", body = PrincipalView,
            headers(("ETag" = String), ("Location" = String))),
        (status = 200, description = "The principal was replaced.", body = PrincipalView, headers(("ETag" = String)))
    )
)]
pub(crate) async fn put_principal(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((tenant, name)): Keys<(TenantSlug, PrincipalName)>,
    Preconditions(conditions): Preconditions,
    JsonBody(body): JsonBody<PrincipalWrite>,
) -> Result<Reply, EdgeProblem> {
    let location = state.location(&format!("tenants/{tenant}/principals/{name}"));
    let outcome = state
        .services
        .principals
        .upsert(&ctx, PrincipalSpec { name, body }, conditions)
        .await?;
    Ok(Reply::upserted(&outcome, location.as_ref()))
}

/// Changes a principal with a JSON Merge Patch.
#[utoipa::path(
    patch,
    path = "/tenants/{tenant}/principals/{principal}",
    operation_id = "patchPrincipal",
    tag = "principals",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412.")
    ),
    request_body(content = MergePatchDocument, content_type = "application/merge-patch+json"),
    responses((status = 200, description = "The changed principal.", body = PrincipalView, headers(("ETag" = String))))
)]
pub(crate) async fn patch_principal(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, name)): Keys<(TenantSlug, PrincipalName)>,
    Preconditions(conditions): Preconditions,
    PatchBody(patch): PatchBody,
) -> Result<Reply, EdgeProblem> {
    let principal = state.services.principals.patch(&ctx, &name, patch, conditions).await?;
    Ok(Reply::versioned(StatusCode::OK, &principal))
}

/// Deletes a principal.
///
/// Credentials, RSVP tokens and shares are revoked at once and the principal disappears; it is purged after the
/// retention period, or immediately with `purge=true`. Requires `If-Match`.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}/principals/{principal}",
    operation_id = "deletePrincipal",
    tag = "principals",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("If-Match" = String, Header, description = "The ETag of the version to delete; without it the request answers 428."),
        DeleteQuery
    ),
    responses((status = 204, description = "The principal was deleted."))
)]
pub(crate) async fn delete_principal(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, name)): Keys<(TenantSlug, PrincipalName)>,
    Preconditions(conditions): Preconditions,
    Params(query): Params<DeleteQuery>,
) -> Result<Reply, EdgeProblem> {
    let options = DeleteOptions {
        purge: query.purge,
        notify_attendees: query.notify_attendees,
        conditions,
    };
    state.services.principals.delete(&ctx, &name, options).await?;
    Ok(Reply::no_content())
}
