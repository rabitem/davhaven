//! The web router and its security headers.
//!
//! The public pages of Davhaven (PLAN 2.5, 2.13):
//!
//! | Route | Purpose |
//! | --- | --- |
//! | `GET /rsvp/{token}`, `POST /rsvp/{token}` | RSVP page of an external attendee: read-only `GET`, CSRF-protected `POST` |
//! | `GET /feeds/{token}.ics` | subscription feed (registered as `/feeds/{file}`: path parameters cannot have a suffix) |
//! | `GET /oauth/{provider}/callback` | OAuth callback of a calendar provider |
//! | `GET /assets/{path}` | static theme assets |
//!
//! The credential is the token in the URL; every refusal of a token is the same 404 page. The router adds the
//! security headers to every response: a strict `Content-Security-Policy` without third-party sources,
//! `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Robots-Tag: noindex` and `no-store`
//! unless the handler chooses another cache policy (feeds do). Pages never set cookies. Route templates are the
//! metric and log labels, so tokens in paths never become labels. Failures are rendered with the theme of the
//! deployment and in the language of the visitor (`errors::themed_errors`).

use core::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::Response;
use axum::routing::get;
use davhaven_app::AppServices;
use davhaven_app::services::{AuthRequest, PresentedCredential};
use davhaven_domain::{Channel, RequestContext, RequestId, TenantId};
use davhaven_http::client_ip::client_ip_of;
use davhaven_http::problem::EdgeProblem;
use davhaven_http::request_id::request_id_of;
use davhaven_http::{Edge, Surface};
use uuid::Uuid;

use crate::errors::{WebProblems, add_security_headers, themed_errors, token_refusal};
use crate::{assets, feeds, oauth, rsvp};

/// The longest token accepted in a path, in bytes; real tokens have about 65 characters.
const MAX_TOKEN_BYTES: usize = 128;

/// The state of the handlers: the application services.
#[derive(Clone)]
pub(crate) struct WebState {
    pub(crate) services: AppServices,
}

/// What the edge layers learned about the request: its id and the client address.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Meta {
    request_id: RequestId,
    client_ip: Option<IpAddr>,
}

impl Meta {
    /// The id of the request.
    pub(crate) const fn request_id(self) -> RequestId {
        self.request_id
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Meta {
    type Rejection = Infallible;

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> {
        std::future::ready(Ok(Self {
            request_id: request_id_of(&parts.extensions).unwrap_or_else(|| RequestId::from_uuid(Uuid::nil())),
            client_ip: client_ip_of(&parts.extensions),
        }))
    }
}

impl WebState {
    /// Authenticates the token of a path as `credential` on `channel`.
    ///
    /// A token that cannot be a token (too long, not printable ASCII) never reaches the service. Every refusal of
    /// the credential is the same 404 ([`token_refusal`]).
    pub(crate) async fn authenticate(
        &self,
        channel: Channel,
        credential: PresentedCredential,
        token: &str,
        meta: Meta,
    ) -> Result<RequestContext, EdgeProblem> {
        if token.len() > MAX_TOKEN_BYTES || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(EdgeProblem::new(davhaven_http::problem::ProblemCode::NotFound));
        }
        let request = AuthRequest {
            channel,
            tenant_hint: None,
            credential,
            client_ip: meta.client_ip,
            request_id: meta.request_id,
        };
        self.services
            .auth
            .authenticate(request)
            .await
            .map_err(|error| token_refusal(&error))
    }

    /// The context of a request that carries no credential and belongs to no tenant (the OAuth callback, whose state
    /// identifies the tenant, the static assets and the pages of failures).
    pub(crate) fn anonymous(request_id: RequestId) -> RequestContext {
        RequestContext::internal(TenantId::from_uuid(Uuid::nil()), request_id)
    }
}

/// Adds the security headers of the web surface to every response.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    add_security_headers(response.headers_mut());
    response
}

/// The web router for the `web` route group.
///
/// `edge` carries the shared configuration; this function derives the web edge from it: HTML error pages, the
/// small body ceiling of form posts and the security headers.
pub fn router(services: AppServices, edge: &Edge) -> Router {
    let edge = edge
        .for_surface(Surface::Web)
        .with_renderer(Arc::new(WebProblems))
        .with_limits(&services.limits);
    let routes = Router::new()
        .route("/rsvp/{token}", get(rsvp::page).post(rsvp::answer))
        .route("/feeds/{file}", get(feeds::feed))
        .route("/oauth/{provider}/callback", get(oauth::callback))
        .route("/assets/{*path}", get(assets::asset))
        .with_state(WebState {
            services: services.clone(),
        })
        // Inside the security headers, which then also cover the themed pages.
        .layer(from_fn_with_state(services, themed_errors))
        .layer(from_fn(security_headers));
    edge.apply(routes)
}
