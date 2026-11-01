//! Calendar provider and external account resources.
//!
//! Providers (Google, Microsoft) are always listed, whether enabled or not; starting the OAuth flow of a disabled
//! provider answers 409 `feature-not-enabled`, so the document and the routes do not depend on cargo features
//! (PLAN 2.10). The OAuth callback itself is served by the web surface.

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_domain::{ExternalAccountId, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{AuthorizationUrl, ExternalAccountCreate, ExternalAccountView, Page, ProviderView};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{JsonBody, Keys, PageParams, Paging};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_providers))
        .routes(routes!(list_external_accounts, create_external_account))
        .routes(routes!(delete_external_account))
}

/// Lists the calendar providers of the deployment and whether each is enabled.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/providers",
    operation_id = "listProviders",
    tag = "providers",
    params(("tenant" = String, Path, description = "The tenant slug.")),
    responses((status = 200, description = "The providers (a single page).", body = Page<ProviderView>))
)]
pub(crate) async fn list_providers(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
) -> Result<Reply, EdgeProblem> {
    let providers = state.services.external_accounts.providers(&ctx).await?;
    Ok(Reply::json(StatusCode::OK, &Page::new(providers, None)))
}

/// Lists the connected external accounts of a tenant.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/external-accounts",
    operation_id = "listExternalAccounts",
    tag = "providers",
    params(("tenant" = String, Path, description = "The tenant slug."), PageParams),
    responses((status = 200, description = "A page of external accounts.", body = Page<ExternalAccountView>))
)]
pub(crate) async fn list_external_accounts(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let page = state.services.external_accounts.list(&ctx, paging.request()).await?;
    Ok(paging.reply(&page))
}

/// Starts connecting an external account.
///
/// Returns the consent URL of the provider. The OAuth state (single use, valid for 10 minutes) and the PKCE
/// verifier are stored by the server; the account appears in the listing once the user has consented and the
/// provider has called back. Answers 409 `feature-not-enabled` for disabled providers.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/external-accounts",
    operation_id = "createExternalAccount",
    tag = "providers",
    params(
        ("tenant" = String, Path, description = "The tenant slug.")
    ),
    request_body = ExternalAccountCreate,
    responses((status = 200, description = "The URL the user must open to consent.", body = AuthorizationUrl,
        headers(("Cache-Control" = String, description = "`no-store`")))
    )
)]
pub(crate) async fn create_external_account(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    JsonBody(request): JsonBody<ExternalAccountCreate>,
) -> Result<Reply, EdgeProblem> {
    let url = state
        .services
        .external_accounts
        .start(&ctx, &request.provider, &request.principal)
        .await?;
    Ok(Reply::json(StatusCode::OK, &url).no_store())
}

/// Disconnects an external account.
///
/// The tokens are revoked at the provider on a best-effort basis and deleted; the mirror calendar is removed.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}/external-accounts/{id}",
    operation_id = "deleteExternalAccount",
    tag = "providers",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the external account.")
    ),
    responses((status = 204, description = "The account was disconnected."))
)]
pub(crate) async fn delete_external_account(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, ExternalAccountId)>,
) -> Result<Reply, EdgeProblem> {
    state.services.external_accounts.delete(&ctx, id).await?;
    Ok(Reply::no_content())
}
