//! The `/api/v1` router built with `utoipa_axum::router::OpenApiRouter`.
//!
//! Every operation of PLAN F0.10 is registered here through the `OpenApiRouter` of its resource module, so the
//! routes and the OpenAPI document come from the same code. Routes exist regardless of enabled features (a
//! disabled provider answers 409 `feature-not-enabled`), which keeps the document identical for every build.
//!
//! [`router()`] returns the complete router for the server: the routes under `/api/v1`, bearer authentication
//! (`Authorization: Bearer`, never cookies or query parameters), the idempotency layer for `POST` requests with an
//! `Idempotency-Key` (module `idempotency`), the problem renderer of this crate and the shared edge layers.
//! [`crate::openapi::document`] returns the OpenAPI document of the same routes without needing any service.

mod idempotency;

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use davhaven_app::AppServices;
use davhaven_http::{Edge, HeaderAuth, authenticate_header};
use url::Url;
use utoipa_axum::router::OpenApiRouter;

use crate::{
    audit, bindings, calendars, changes, client_config, credentials, errors, grants, itip, members, objects, outbox,
    principals, providers, tenants, tokens, webhooks,
};

/// The path prefix of the management API.
pub const API_PREFIX: &str = "/api/v1";

/// The state every handler receives: the application services.
#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) services: AppServices,
}

impl ApiState {
    /// The absolute URL of an API resource, for `Location` headers: the public base URL (never the `Host`
    /// header) plus `/api/v1/` plus `relative` (a path without a leading slash).
    pub(crate) fn location(&self, relative: &str) -> Option<Url> {
        self.services.urls.api_root().join(relative).ok()
    }
}

/// The routes of every resource, with their OpenAPI operations.
pub(crate) fn api_router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .merge(tenants::router())
        .merge(principals::router())
        .merge(members::router())
        .merge(credentials::router())
        .merge(client_config::router())
        .merge(calendars::router())
        .merge(bindings::router())
        .merge(grants::router())
        .merge(objects::router())
        .merge(changes::router())
        .merge(tokens::router())
        .merge(webhooks::router())
        .merge(providers::router())
        .merge(audit::router())
        .merge(outbox::router())
        .merge(itip::router())
}

/// The management API as a router for the `internal` listener (route group `api`).
///
/// `edge` carries the shared configuration (timeouts, trusted proxies, allowed origins, request ids); this
/// function derives the API's own edge from it: the RFC 9457 renderer with the status table of
/// [`crate::errors`] and the body ceiling of `limits.api`. Unknown paths answer 404 and unauthenticated requests
/// to known paths 401, both as problem documents.
pub fn router(services: AppServices, edge: &Edge) -> Router {
    let auth = HeaderAuth::api(Arc::clone(&services.auth));
    let edge = edge
        .for_surface(davhaven_http::Surface::Api)
        .with_renderer(Arc::new(errors::renderer()))
        .with_limits(&services.limits);
    let (routes, _document) = api_router().split_for_parts();
    let state = ApiState { services };
    let idempotency = idempotency::Idempotency {
        state: state.clone(),
        request_timeout: edge.request_timeout(),
    };
    // The layer added last is the outermost: authentication runs first, so the idempotency layer sees the context.
    let routes = routes
        .with_state(state)
        .route_layer(from_fn_with_state(idempotency, idempotency::replay))
        .route_layer(from_fn_with_state(auth, authenticate_header));
    edge.apply(Router::new().nest(API_PREFIX, routes))
}
