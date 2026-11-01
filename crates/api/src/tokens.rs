//! API token resources.
//!
//! A token can only mint tokens whose scopes are a subset of its own and allowed for the kind; tokens with `mcp:*`
//! scopes need an expiry within the configured maximum. The secret is shown once, in the creating response, which
//! is `no-store` (PLAN 2.6).

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_domain::{TenantSlug, TokenId};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{ApiTokenCreate, ApiTokenCreated, ApiTokenView, Page};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{JsonBody, Keys, PageParams, Paging};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_api_tokens, create_api_token))
        .routes(routes!(revoke_api_token))
}

/// Lists the API tokens of a tenant, including revoked ones.
///
/// The listing shows labels, prefixes, scopes and state, never a secret.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/api-tokens",
    operation_id = "listApiTokens",
    tag = "api-tokens",
    params(("tenant" = String, Path, description = "The tenant slug."), PageParams),
    responses((status = 200, description = "A page of API tokens.", body = Page<ApiTokenView>))
)]
pub(crate) async fn list_api_tokens(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let page = state
        .services
        .credentials
        .list_api_tokens(&ctx, paging.request())
        .await?;
    Ok(paging.reply(&page))
}

/// Creates an API token.
///
/// The token is in the response and nowhere else; store it now.
///
/// A token mints tokens whose scopes are a subset of its own, and a minted token never outlives its minter. **One
/// exception**: the `mcp:*` scopes, which a tenant token cannot hold itself. A tenant token with `credentials:write` may
/// put them on a principal token for a **service principal**, because the machine identity of an assistant needs exactly
/// these and `credentials:write` is already the power to act as any principal of the tenant that can act (it mints app
/// passwords as well). Every other scope of the token still has to be one the minter holds. The token then acts **as**
/// that principal: it sees and writes the calendars the principal owns or is granted, nothing else. For a user the subset
/// rule stays, so MCP scopes reach a user only from the operator (`davhaven admin principal-token`). Tokens with `mcp:*`
/// scopes need a tenant that switched MCP on (`409 feature-not-enabled` otherwise) and an expiry within
/// `security.max_mcp_token_days`. Every minting is audited (`token.created`).
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/api-tokens",
    operation_id = "createApiToken",
    tag = "api-tokens",
    params(
        ("tenant" = String, Path, description = "The tenant slug.")
    ),
    request_body = ApiTokenCreate,
    responses((status = 201, description = "The token and its secret, shown once.", body = ApiTokenCreated,
        headers(
            ("Location" = String, description = "The URL of the token; `DELETE` it to revoke the token."),
            ("Cache-Control" = String, description = "`no-store`")
        ))
    )
)]
pub(crate) async fn create_api_token(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(tenant): Keys<TenantSlug>,
    JsonBody(request): JsonBody<ApiTokenCreate>,
) -> Result<Reply, EdgeProblem> {
    let created = state.services.credentials.create_api_token(&ctx, request).await?;
    let location = state.location(&format!("tenants/{tenant}/api-tokens/{}", created.token.id));
    let reply = Reply::json(StatusCode::CREATED, &created).no_store();
    Ok(match &location {
        Some(url) => reply.with_location(url),
        None => reply,
    })
}

/// Revokes an API token.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}/api-tokens/{id}",
    operation_id = "revokeApiToken",
    tag = "api-tokens",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("id" = String, Path, description = "The id of the token.")
    ),
    responses((status = 204, description = "The token is revoked."))
)]
pub(crate) async fn revoke_api_token(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, id)): Keys<(TenantSlug, TokenId)>,
) -> Result<Reply, EdgeProblem> {
    state.services.credentials.revoke_api_token(&ctx, id).await?;
    Ok(Reply::no_content())
}
