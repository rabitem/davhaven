//! The edge stack: every shared layer of one surface, in the one correct order.
//!
//! A protocol crate builds its routes, adds its own authentication where it needs it, and hands the router to
//! [`Edge::apply`]. From the outside in, the stack is:
//!
//! 1. **request id** ([`crate::request_id`]): accept or generate `X-Request-Id`, echo it;
//! 2. **tracing and metrics** ([`crate::trace`]): route-template labels, one log line per request;
//! 3. **CORS** (API only, [`crate::cors::cors_layer`]): preflights and headers for the configured origins;
//! 4. **problem rendering** ([`crate::problem`]): turns every [`EdgeProblem`] and bare error status into the
//!    surface's wire form, with the request id;
//! 5. **panic containment**: a panicking handler becomes a 500 problem instead of a dropped connection;
//! 6. sensitive request headers are marked so `Debug` output hides them;
//! 7. **client address** ([`crate::client_ip`]): `X-Forwarded-For` behind trusted proxies only;
//! 8. **load shedding** and 9. **request timeout** ([`crate::limits`]): 503 with `Retry-After`;
//! 10. **body ceiling** ([`crate::limits::limit_body`]): 413 for oversized bodies;
//! 11. **origin guard** ([`crate::cors::guard_origin`]): 403 for unsafe requests from foreign origins.
//!
//! Two limits of `server.http` are not here because they belong to the connection, not to a request: the header
//! read timeout and the maximum header size (431). Hyper enforces them when the server builds the listener; the
//! edge sees requests whose headers have been read within those limits.
//!
//! Authentication is not part of the stack: the surfaces differ (header credentials for DAV, API and MCP, path
//! tokens for the web pages), so each protocol crate adds [`crate::auth::authenticate_header`] or its own token
//! handling *inside* the stack, where the renderer can still format its refusals.
//!
//! The layers are applied to the routes of the router, which includes its fallback, so unknown paths and wrong
//! methods go through the same stack. Routers of different route groups can be merged afterwards: every route
//! keeps the layers of its own surface.

use core::any::Any;
use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use davhaven_domain::Limits;
use davhaven_wire::ProblemCode;
use ipnet::IpNet;
use tokio::sync::Semaphore;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;

use crate::client_ip::{TrustedProxies, resolve_client_ip};
use crate::cors::{CorsConfig, OriginPolicy, cors_layer, guard_origin};
use crate::limits::{BodyLimit, HttpConfig, concurrency_permits, enforce_timeout, limit_body, shed_load};
use crate::problem::{EdgeProblem, JsonProblems, ProblemRenderer, render_problems};
use crate::redact::sensitive_headers;
use crate::request_id::{RequestIdSource, assign_request_id};
use crate::surface::Surface;
use crate::trace::trace_requests;

/// The body ceiling of the web pages (RSVP form posts), in bytes.
const WEB_BODY_CEILING: usize = 64 * 1024;

/// The configuration the edge layers need, taken from the `[server]` and `[security]` tables.
#[derive(Debug, Clone, Default)]
pub struct EdgeSettings {
    /// `[server.http]`: timeouts, header limit and the concurrency limit.
    pub http: HttpConfig,
    /// `server.trusted_proxies`: the proxies whose `X-Forwarded-For` is believed.
    pub trusted_proxies: Vec<IpNet>,
    /// `[security.cors]`: the browser origins that may call the API.
    pub cors: CorsConfig,
}

/// The largest request body a surface accepts at all, derived from the configured limits: the batch limit for the
/// API, the larger of the resource and XML limits for DAV, the JSON limit for MCP and a fixed small ceiling for
/// the web pages. Routes enforce their own, tighter limits below this ceiling.
pub fn body_ceiling(limits: &Limits, surface: Surface) -> usize {
    let bytes = match surface {
        Surface::Api => limits.api.max_batch_body,
        Surface::Dav => limits.ical.max_resource_size.max(limits.dav.max_request_body),
        Surface::Mcp => limits.api.max_json_body,
        Surface::Web => return WEB_BODY_CEILING,
    };
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// The panic handler of the stack: log the panic and answer with the 500 problem.
fn panic_to_problem(payload: &(dyn Any + Send)) -> Response {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a panic without a message");
    tracing::error!(target: "davhaven::http", panic = message, "a request handler panicked");
    EdgeProblem::new(ProblemCode::Internal).into_response()
}

/// The shared layers of one surface; see the module documentation for the stack.
#[derive(Clone)]
pub struct Edge {
    surface: Surface,
    ids: Arc<dyn RequestIdSource>,
    renderer: Arc<dyn ProblemRenderer>,
    settings: Arc<EdgeSettings>,
    permits: Arc<Semaphore>,
    body_limit: usize,
    origin_guard: bool,
}

impl fmt::Debug for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Edge")
            .field("surface", &self.surface)
            .field("settings", &self.settings)
            .field("body_limit", &self.body_limit)
            .field("origin_guard", &self.origin_guard)
            .finish_non_exhaustive()
    }
}

impl Edge {
    /// The edge of `surface` with default settings, the RFC 9457 renderer and the body ceiling of the default
    /// limits. `ids` supplies the ids of requests that arrive without one.
    pub fn new(surface: Surface, ids: Arc<dyn RequestIdSource>) -> Self {
        let settings = EdgeSettings::default();
        Self {
            surface,
            ids,
            renderer: Arc::new(JsonProblems::catalog()),
            permits: concurrency_permits(settings.http.concurrency_limit),
            settings: Arc::new(settings),
            body_limit: body_ceiling(&Limits::default(), surface),
            origin_guard: surface != Surface::Mcp,
        }
    }

    /// Uses the configured timeouts, proxies and origins. The concurrency limit starts afresh with the new value.
    #[must_use]
    pub fn with_settings(mut self, settings: EdgeSettings) -> Self {
        self.permits = concurrency_permits(settings.http.concurrency_limit);
        self.settings = Arc::new(settings);
        self
    }

    /// Renders problems with `renderer` instead of the RFC 9457 JSON form.
    #[must_use]
    pub fn with_renderer(mut self, renderer: Arc<dyn ProblemRenderer>) -> Self {
        self.renderer = renderer;
        self
    }

    /// Sets the body ceiling in bytes.
    #[must_use]
    pub const fn with_body_limit(mut self, bytes: usize) -> Self {
        self.body_limit = bytes;
        self
    }

    /// Derives the body ceiling of this edge's surface from the configured limits ([`body_ceiling`]).
    #[must_use]
    pub fn with_limits(self, limits: &Limits) -> Self {
        let bytes = body_ceiling(limits, self.surface);
        self.with_body_limit(bytes)
    }

    /// Leaves the origin check to the surface itself (MCP validates against `mcp.allowed_origins`).
    #[must_use]
    pub const fn without_origin_guard(mut self) -> Self {
        self.origin_guard = false;
        self
    }

    /// The same edge for another surface: ids, renderer, settings and the concurrency limit are shared, so a
    /// listener that serves several route groups enforces one limit across them.
    #[must_use]
    pub fn for_surface(&self, surface: Surface) -> Self {
        Self {
            surface,
            body_limit: body_ceiling(&Limits::default(), surface),
            origin_guard: surface != Surface::Mcp,
            ..self.clone()
        }
    }

    /// The surface this edge serves.
    pub const fn surface(&self) -> Surface {
        self.surface
    }

    /// How long one request may take in total (`server.http.request_timeout`), for layers that run work outside the
    /// edge's own timeout and must bound it by the same time.
    pub fn request_timeout(&self) -> Duration {
        self.settings.http.request_timeout
    }

    /// The renderer of this edge, for protocol crates that mount further layers inside it.
    pub fn renderer(&self) -> Arc<dyn ProblemRenderer> {
        Arc::clone(&self.renderer)
    }

    /// Wraps every route of `router` (and its fallback) in the shared layers.
    pub fn apply(&self, router: Router) -> Router {
        let proxies = Arc::new(TrustedProxies::new(self.settings.trusted_proxies.clone()));
        let cors = (self.surface == Surface::Api)
            .then(|| cors_layer(&self.settings.cors))
            .flatten();
        let guard = self
            .origin_guard
            .then(|| from_fn_with_state(Arc::new(OriginPolicy::new(self.settings.cors.clone())), guard_origin));
        let stack = ServiceBuilder::new()
            .layer(from_fn_with_state(Arc::clone(&self.ids), assign_request_id))
            .layer(from_fn_with_state(self.surface, trace_requests))
            .option_layer(cors)
            .layer(from_fn_with_state(Arc::clone(&self.renderer), render_problems))
            .layer(CatchPanicLayer::custom(|payload: Box<dyn Any + Send + 'static>| {
                panic_to_problem(payload.as_ref())
            }))
            .layer(SetSensitiveRequestHeadersLayer::new(sensitive_headers()))
            .layer(from_fn_with_state(proxies, resolve_client_ip))
            .layer(from_fn_with_state(Arc::clone(&self.permits), shed_load))
            .layer(from_fn_with_state(self.settings.http.request_timeout, enforce_timeout))
            .layer(from_fn_with_state(BodyLimit(self.body_limit), limit_body))
            .option_layer(guard);
        router.layer(stack)
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::http::header::{CONTENT_TYPE, RETRY_AFTER};
    use axum::routing::{get, post};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::request_id::SequentialRequestIds;

    fn edge(surface: Surface) -> Edge {
        Edge::new(surface, Arc::new(SequentialRequestIds::new()))
    }

    async fn boom() -> &'static str {
        panic!("secret internal detail");
    }

    fn router(edge: &Edge) -> Router {
        edge.apply(
            Router::new()
                .route("/ok", get(|| async { "fine" }))
                .route("/boom", get(boom))
                .route("/echo", post(|body: String| async move { body })),
        )
    }

    async fn problem_of(response: Response) -> serde_json::Value {
        assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn successful_responses_carry_the_request_id() {
        let app = router(&edge(Surface::Api));
        let response = app
            .oneshot(Request::get("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-request-id"],
            "018f3c1e-7b2a-7c3d-9e4f-000000000001"
        );
    }

    #[tokio::test]
    async fn unknown_paths_and_methods_are_rendered_as_problems_with_the_request_id() {
        let app = router(&edge(Surface::Api));
        let missing = app
            .clone()
            .oneshot(Request::get("/nowhere").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let json = problem_of(missing).await;
        assert_eq!(json["code"], "not-found");
        assert_eq!(json["request_id"], "018f3c1e-7b2a-7c3d-9e4f-000000000001");

        let wrong = app
            .oneshot(Request::post("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(wrong.headers().contains_key("allow"));
        assert_eq!(problem_of(wrong).await["code"], "method-not-allowed");
    }

    #[tokio::test]
    async fn a_panicking_handler_becomes_a_500_problem_without_its_message() {
        let app = router(&edge(Surface::Api));
        let response = app
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().contains_key("x-request-id"));
        let json = problem_of(response).await;
        assert_eq!(json["code"], "internal");
        assert!(!json.to_string().contains("secret internal detail"));
    }

    #[tokio::test]
    async fn the_body_ceiling_and_the_origin_guard_apply() {
        let app = router(&edge(Surface::Api).with_body_limit(4));
        let big = Request::post("/echo")
            .header("content-length", "5")
            .body(Body::from("12345"))
            .unwrap();
        let response = app.clone().oneshot(big).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(problem_of(response).await["code"], "payload-too-large");

        let foreign = Request::post("/echo")
            .header("host", "cal.example.org")
            .header("origin", "https://evil.example")
            .body(Body::from("x"))
            .unwrap();
        let response = app.clone().oneshot(foreign).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let same_origin = Request::post("/echo")
            .header("host", "cal.example.org")
            .header("origin", "https://cal.example.org")
            .body(Body::from("x"))
            .unwrap();
        assert_eq!(app.oneshot(same_origin).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_mcp_edge_leaves_origins_to_the_mcp_crate() {
        let app = router(&edge(Surface::Mcp));
        let foreign = Request::post("/echo")
            .header("host", "cal.example.org")
            .header("origin", "https://evil.example")
            .body(Body::from("x"))
            .unwrap();
        assert_eq!(app.oneshot(foreign).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn only_the_api_answers_cors_preflights() {
        let settings = EdgeSettings {
            cors: CorsConfig {
                allowed_origins: vec!["https://admin.example.org".to_owned()],
            },
            ..EdgeSettings::default()
        };
        let preflight = || {
            Request::builder()
                .method("OPTIONS")
                .uri("/ok")
                .header("origin", "https://admin.example.org")
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap()
        };
        let api = router(&edge(Surface::Api).with_settings(settings.clone()));
        let response = api.oneshot(preflight()).await.unwrap();
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://admin.example.org"
        );
        let dav = router(&edge(Surface::Dav).with_settings(settings));
        let response = dav.oneshot(preflight()).await.unwrap();
        assert!(response.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn overload_and_timeouts_answer_503_with_retry_after() {
        let settings = EdgeSettings {
            http: HttpConfig {
                request_timeout: core::time::Duration::from_secs(30),
                ..HttpConfig::default()
            },
            ..EdgeSettings::default()
        };
        let app = edge(Surface::Web)
            .with_settings(settings)
            .apply(Router::new().route("/slow", get(std::future::pending::<&'static str>)));
        let response = app
            .oneshot(Request::get("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
    }

    #[tokio::test]
    async fn the_surfaces_of_one_listener_share_one_concurrency_limit() {
        let settings = EdgeSettings {
            http: HttpConfig {
                concurrency_limit: 1,
                ..HttpConfig::default()
            },
            ..EdgeSettings::default()
        };
        let gate = Arc::new(tokio::sync::Notify::new());
        let handler_gate = Arc::clone(&gate);
        let api = edge(Surface::Api).with_settings(settings);
        let busy = api.apply(Router::new().route(
            "/wait",
            get(move || {
                let gate = Arc::clone(&handler_gate);
                async move {
                    gate.notified().await;
                    "done"
                }
            }),
        ));
        let dav = router(&api.for_surface(Surface::Dav));
        let first = tokio::spawn(busy.oneshot(Request::get("/wait").body(Body::empty()).unwrap()));
        tokio::task::yield_now().await;
        // The only permit is held by a request of the API, so the DAV routes of the same listener are shed too.
        let shed = dav
            .clone()
            .oneshot(Request::get("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(shed.headers()[RETRY_AFTER], "1");
        gate.notify_one();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
        let after = dav
            .oneshot(Request::get("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            after.status(),
            StatusCode::OK,
            "the permit is given back with the response"
        );
    }

    #[test]
    fn ceilings_follow_the_limits_of_each_surface() {
        let limits = Limits::default();
        assert_eq!(body_ceiling(&limits, Surface::Api), 10 * 1024 * 1024);
        assert_eq!(body_ceiling(&limits, Surface::Mcp), 1024 * 1024);
        assert_eq!(body_ceiling(&limits, Surface::Dav), 1024 * 1024);
        assert_eq!(body_ceiling(&limits, Surface::Web), WEB_BODY_CEILING);
        let shared = edge(Surface::Api).for_surface(Surface::Mcp);
        assert_eq!(shared.surface(), Surface::Mcp);
        assert!(!shared.origin_guard);
    }
}
