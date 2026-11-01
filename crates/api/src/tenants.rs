//! Tenant resources: `/tenants` and `/tenants/{tenant}` (system tokens, scope `system:tenants`).

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_app::services::TenantSpec;
use davhaven_domain::TenantSlug;
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{Page, TenantView, TenantWrite};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{JsonBody, Keys, PageParams, Paging, PatchBody, Preconditions};
use crate::openapi::MergePatchDocument;
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new().routes(routes!(list_tenants)).routes(routes!(
        get_tenant,
        put_tenant,
        patch_tenant,
        delete_tenant
    ))
}

/// Lists the tenants.
///
/// Needs a system token with `system:tenants`. Tenants are ordered by id.
#[utoipa::path(
    get,
    path = "/tenants",
    operation_id = "listTenants",
    tag = "tenants",
    params(PageParams),
    responses((status = 200, description = "A page of tenants.", body = Page<TenantView>))
)]
pub(crate) async fn list_tenants(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let page = state.services.tenants.list(&ctx, paging.request()).await?;
    Ok(paging.reply(&page))
}

/// Reads a tenant.
///
/// System tokens read any tenant; tenant tokens with `principals:read` read their own.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}",
    operation_id = "getTenant",
    tag = "tenants",
    params(("tenant" = String, Path, description = "The tenant slug.")),
    responses((
        status = 200,
        description = "The tenant.",
        body = TenantView,
        headers(("ETag" = String, description = "The version of the tenant, for If-Match."))
    ))
)]
pub(crate) async fn get_tenant(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(slug): Keys<TenantSlug>,
) -> Result<Reply, EdgeProblem> {
    let tenant = state.services.tenants.get(&ctx, &slug).await?;
    Ok(Reply::versioned(StatusCode::OK, &tenant))
}

/// Creates or replaces a tenant.
///
/// A new tenant is provisioned with its default settings. Send `If-None-Match: *` to create only, `If-Match` to
/// replace only a known version.
#[utoipa::path(
    put,
    path = "/tenants/{tenant}",
    operation_id = "putTenant",
    tag = "tenants",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412."),
        ("If-None-Match" = Option<String>, Header, description = "`*` to create only; an existing resource answers 412.")
    ),
    request_body = TenantWrite,
    responses(
        (status = 201, description = "The tenant was created.", body = TenantView,
            headers(("ETag" = String), ("Location" = String))),
        (status = 200, description = "The tenant was replaced.", body = TenantView, headers(("ETag" = String)))
    )
)]
pub(crate) async fn put_tenant(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(slug): Keys<TenantSlug>,
    Preconditions(conditions): Preconditions,
    JsonBody(body): JsonBody<TenantWrite>,
) -> Result<Reply, EdgeProblem> {
    let location = state.location(&format!("tenants/{slug}"));
    let spec = TenantSpec { slug, body };
    let outcome = state.services.tenants.upsert(&ctx, spec, conditions).await?;
    Ok(Reply::upserted(&outcome, location.as_ref()))
}

/// Changes a tenant with a JSON Merge Patch.
///
/// The slug is immutable.
#[utoipa::path(
    patch,
    path = "/tenants/{tenant}",
    operation_id = "patchTenant",
    tag = "tenants",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("If-Match" = Option<String>, Header, description = "The ETag of the version the request applies to; a mismatch answers 412.")
    ),
    request_body(content = MergePatchDocument, content_type = "application/merge-patch+json"),
    responses((status = 200, description = "The changed tenant.", body = TenantView, headers(("ETag" = String))))
)]
pub(crate) async fn patch_tenant(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(slug): Keys<TenantSlug>,
    Preconditions(conditions): Preconditions,
    PatchBody(patch): PatchBody,
) -> Result<Reply, EdgeProblem> {
    let tenant = state.services.tenants.patch(&ctx, &slug, patch, conditions).await?;
    Ok(Reply::versioned(StatusCode::OK, &tenant))
}

/// Deletes a tenant and everything in it.
///
/// Requires `If-Match`.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}",
    operation_id = "deleteTenant",
    tag = "tenants",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("If-Match" = String, Header, description = "The ETag of the version to delete; without it the request answers 428.")
    ),
    responses((status = 204, description = "The tenant was deleted."))
)]
pub(crate) async fn delete_tenant(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(slug): Keys<TenantSlug>,
    Preconditions(conditions): Preconditions,
) -> Result<Reply, EdgeProblem> {
    state.services.tenants.delete(&ctx, &slug, conditions).await?;
    Ok(Reply::no_content())
}
