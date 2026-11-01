//! Client configuration resources: the values to type into a calendar client, an Apple configuration profile and a
//! DAVx5 login.
//!
//! The generic configuration contains no secret. The profile and the DAVx5 login mint an app password for the
//! device, so their responses carry a secret and are `no-store` (PLAN 2.10).

use axum::extract::State;
use axum::http::StatusCode;
use davhaven_app::services::{ClientConfigKind, ClientConfigResponse};
use davhaven_domain::{PrincipalName, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{ClientConfigDavx5, ClientConfigGeneric, ClientConfigRequest, ProblemCode};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{JsonBody, Keys};
use crate::openapi::ConfigurationProfile;
use crate::reply::Reply;
use crate::router::ApiState;

/// The media type of Apple configuration profiles.
const MOBILECONFIG: &str = "application/x-apple-aspen-config";

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(get_client_config))
        .routes(routes!(create_apple_mobileconfig))
        .routes(routes!(create_davx5_config))
}

/// The answer of the service does not belong to the question: a bug of the service, not of the client.
fn mismatch() -> EdgeProblem {
    EdgeProblem::new(ProblemCode::Internal)
}

/// Reads the values to type into a calendar client.
///
/// No secret and no side effect: the server and principal URLs, the login and the well-known address.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}/client-config/generic",
    operation_id = "getClientConfig",
    tag = "client-config",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner.")
    ),
    responses((status = 200, description = "The generic client configuration.", body = ClientConfigGeneric))
)]
pub(crate) async fn get_client_config(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, principal)): Keys<(TenantSlug, PrincipalName)>,
) -> Result<Reply, EdgeProblem> {
    let response = state
        .services
        .credentials
        .client_config(&ctx, &principal, ClientConfigKind::Generic)
        .await?;
    match response {
        ClientConfigResponse::Generic(config) => Ok(Reply::json(StatusCode::OK, &config).no_store()),
        ClientConfigResponse::Mobileconfig(_) | ClientConfigResponse::Davx5(_) => Err(mismatch()),
    }
}

/// Creates an Apple configuration profile for a device.
///
/// Mints an app password with the given label and returns a `.mobileconfig` that configures the CalDAV account.
/// Installing the profile again replaces the account.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/principals/{principal}/client-config/apple-mobileconfig",
    operation_id = "createAppleMobileconfig",
    tag = "client-config",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner.")
    ),
    request_body = ClientConfigRequest,
    responses((
        status = 200,
        description = "The configuration profile; it contains the app password.",
        body = ConfigurationProfile,
        content_type = "application/x-apple-aspen-config",
        headers(("Content-Disposition" = String), ("Cache-Control" = String, description = "`no-store`"))
    ))
)]
pub(crate) async fn create_apple_mobileconfig(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, principal)): Keys<(TenantSlug, PrincipalName)>,
    JsonBody(request): JsonBody<ClientConfigRequest>,
) -> Result<Reply, EdgeProblem> {
    let response = state
        .services
        .credentials
        .client_config(&ctx, &principal, ClientConfigKind::AppleMobileconfig(request))
        .await?;
    match response {
        ClientConfigResponse::Mobileconfig(profile) => {
            Ok(Reply::binary(MOBILECONFIG, &profile.filename, profile.body).no_store())
        }
        ClientConfigResponse::Generic(_) | ClientConfigResponse::Davx5(_) => Err(mismatch()),
    }
}

/// Creates a DAVx5 login for a device.
///
/// Mints an app password with the given label and returns a login URI for a QR code.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/principals/{principal}/client-config/davx5",
    operation_id = "createDavx5Config",
    tag = "client-config",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner.")
    ),
    request_body = ClientConfigRequest,
    responses((
        status = 200,
        description = "The login URI; it contains the app password.",
        body = ClientConfigDavx5,
        headers(("Cache-Control" = String, description = "`no-store`"))
    ))
)]
pub(crate) async fn create_davx5_config(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, principal)): Keys<(TenantSlug, PrincipalName)>,
    JsonBody(request): JsonBody<ClientConfigRequest>,
) -> Result<Reply, EdgeProblem> {
    let response = state
        .services
        .credentials
        .client_config(&ctx, &principal, ClientConfigKind::Davx5(request))
        .await?;
    match response {
        ClientConfigResponse::Davx5(login) => Ok(Reply::json(StatusCode::OK, &login).no_store()),
        ClientConfigResponse::Generic(_) | ClientConfigResponse::Mobileconfig(_) => Err(mismatch()),
    }
}
