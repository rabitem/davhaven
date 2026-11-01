//! Mounting of the MCP service behind the HTTP edge layers.
//!
//! `/mcp` is the single endpoint of the Model Context Protocol over stateless streamable HTTP (PLAN 2.5, 2.12). It
//! lives in the route group `mcp`, normally on the `internal` listener. Requests pass, in this order:
//!
//! 1. the shared edge (request id, tracing, limits, problems as RFC 9457 JSON);
//! 2. the **origin check** ([`crate::origin`]): browsers are refused unless their origin is in
//!    `mcp.allowed_origins`;
//! 3. **bearer authentication**: an API token in the `Authorization` header and nowhere else (401 with the
//!    challenge otherwise);
//! 4. the endpoint: `POST` carries one JSON-RPC message ([`crate::guard::checked_message`] answers the JSON-RPC faults
//!    of a body that is no message) and goes to the `rmcp` streamable HTTP service, which runs [`McpServer`]; `GET` (a
//!    server-to-client stream) and `DELETE` (ending a session) answer 405 because the server is stateless.
//!
//! What a token may do is judged per call by the handler, not here: a tool is offered and callable only with its
//! scope, and only a principal token acts as a person (any other token sees nothing: `not-found`).
//!
//! The transport runs in stateless mode with JSON responses: no sessions, no event streams, one `application/json`
//! answer per request. Its own protection against DNS rebinding looks at the `Host` header against a list of
//! loopback names; that is the wrong defense for a server that is reached by its public name (the `Origin` check
//! above is the right one and does not trust the `Host` header, which an attacker chooses), so the router gives the
//! transport a neutral `Host` and the transport's list is empty.
//!
//! With `mcp.enabled = false` the router has no route at all and every path answers 404.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::HOST;
use axum::http::{HeaderValue, Method};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use davhaven_app::AppServices;
use davhaven_http::problem::{EdgeProblem, JsonProblems, ProblemCode};
use davhaven_http::{Edge, HeaderAuth, Surface, authenticate_header};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::config::McpConfig;
use crate::guard::checked_message;
use crate::origin::{McpOrigins, validate_origin};
use crate::server::McpServer;

/// The path of the MCP endpoint.
pub const MCP_PATH: &str = "/mcp";

/// The challenge of 401 responses.
const CHALLENGE: &str = "Bearer realm=\"davhaven\"";

/// The `Host` the transport sees: its check of the header is switched off, but it insists on a well-formed one.
const NEUTRAL_HOST: &str = "mcp.invalid";

/// The `rmcp` transport with the limit of the body, shared by every request.
struct Gateway {
    service: StreamableHttpService<McpServer, NeverSessionManager>,
    body_limit: usize,
}

/// Serves the endpoint: `POST` is the protocol; every other method is not allowed on a stateless server.
async fn endpoint(State(gateway): State<Arc<Gateway>>, request: Request) -> Response {
    if request.method() != Method::POST {
        return EdgeProblem::new(ProblemCode::MethodNotAllowed)
            .with_allow("POST")
            .into_response();
    }
    let mut request = match checked_message(request, gateway.body_limit).await {
        Ok(request) => request,
        Err(response) => return *response,
    };
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_static(NEUTRAL_HOST));
    gateway.service.handle(request).await.map(Body::new)
}

/// The MCP router for the `mcp` route group.
///
/// `edge` carries the shared configuration; this function derives the MCP edge from it (RFC 9457 problems, the JSON
/// body ceiling, no generic origin guard because [`McpOrigins`] decides). Without `config.enabled` the router
/// serves nothing. The time the tools default to (`search_events` starts "now") is the clock of the application
/// (`AppServices::now`).
pub fn router(services: &AppServices, config: &McpConfig, edge: &Edge) -> Router {
    let edge = edge
        .for_surface(Surface::Mcp)
        .with_renderer(Arc::new(JsonProblems::catalog().with_challenge(CHALLENGE)))
        .with_limits(&services.limits);
    if !config.enabled {
        return edge.apply(Router::new());
    }
    let body_limit = usize::try_from(services.limits.api.max_json_body).unwrap_or(usize::MAX);
    let transport = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .disable_allowed_hosts()
        .with_max_request_body_bytes(body_limit);
    let server = McpServer::new(services.clone(), config.clone());
    let gateway = Arc::new(Gateway {
        service: StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(NeverSessionManager::default()),
            transport,
        ),
        body_limit,
    });
    let auth = HeaderAuth::mcp(Arc::clone(&services.auth));
    let origins = Arc::new(McpOrigins::new(config));
    let routes = Router::new()
        .route(MCP_PATH, any(endpoint))
        .with_state(gateway)
        .route_layer(from_fn_with_state(auth, authenticate_header))
        .route_layer(from_fn_with_state(origins, validate_origin));
    edge.apply(routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_path_is_the_one_of_the_plan() {
        assert_eq!(MCP_PATH, "/mcp");
    }
}
