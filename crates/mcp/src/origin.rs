//! `Origin` validation for MCP requests.
//!
//! The MCP specification requires servers to validate the `Origin` header of incoming connections, because a
//! malicious web page could otherwise drive a local or internal MCP server through the visitor's browser (DNS
//! rebinding). The rule here is exact and does not use the `Host` header, which is the point of the defense:
//!
//! * a request **without** an `Origin` header does not come from a browser page and is accepted (assistants,
//!   desktop clients and scripts send none);
//! * a request **with** an `Origin` header is accepted only when that origin is listed in `mcp.allowed_origins`;
//!   everything else, including `null`, a repeated header and an origin that merely equals the `Host` of the
//!   request (which is what a rebinding attack produces), answers 403.
//!
//! Credentials are the second line: tokens travel in the `Authorization` header only, never in cookies, so a
//! page that cannot read the token cannot use the endpoint either.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::ORIGIN;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::config::McpConfig;

/// The origins the MCP endpoint accepts (`mcp.allowed_origins`).
#[derive(Debug, Clone, Default)]
pub struct McpOrigins {
    allowed: Vec<String>,
}

impl McpOrigins {
    /// The origins of the configuration.
    pub fn new(config: &McpConfig) -> Self {
        Self {
            allowed: config.allowed_origins.clone(),
        }
    }

    /// Whether a request with this `Origin` header (`None` when it has none) may use the endpoint.
    pub fn permits(&self, origin: Option<&str>) -> bool {
        origin.is_none_or(|origin| self.allowed.iter().any(|allowed| allowed == origin))
    }
}

/// The layer function of the origin check; mount it with
/// `axum::middleware::from_fn_with_state(Arc::new(origins), validate_origin)` in front of authentication.
pub async fn validate_origin(State(origins): State<Arc<McpOrigins>>, request: Request, next: Next) -> Response {
    let mut values = request.headers().get_all(ORIGIN).iter();
    let permitted = match (values.next(), values.next()) {
        (None, _) => origins.permits(None),
        (Some(value), None) => value.to_str().is_ok_and(|origin| origins.permits(Some(origin))),
        (Some(_), Some(_)) => false,
    };
    if !permitted {
        return EdgeProblem::new(ProblemCode::Forbidden)
            .with_detail("The origin of the request is not allowed.")
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origins(allowed: &[&str]) -> McpOrigins {
        McpOrigins::new(&McpConfig {
            allowed_origins: allowed.iter().map(|origin| (*origin).to_owned()).collect(),
            ..McpConfig::default()
        })
    }

    #[test]
    fn requests_without_an_origin_are_not_from_browsers_and_pass() {
        assert!(origins(&[]).permits(None));
        assert!(origins(&["https://assistant.example.org"]).permits(None));
    }

    #[test]
    fn an_origin_must_be_listed_exactly() {
        let policy = origins(&["https://assistant.example.org", "http://localhost:3000"]);
        assert!(policy.permits(Some("https://assistant.example.org")));
        assert!(policy.permits(Some("http://localhost:3000")));
        for refused in [
            "https://assistant.example.org:8443",
            "http://assistant.example.org",
            "https://ASSISTANT.example.org",
            "https://assistant.example.org/",
            "https://evil.example",
            "http://localhost:3001",
            "null",
            "",
        ] {
            assert!(!policy.permits(Some(refused)), "{refused}");
        }
        assert!(!origins(&[]).permits(Some("https://assistant.example.org")));
    }

    mod layer {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{HeaderValue, StatusCode};
        use axum::routing::post;
        use tower::ServiceExt as _;

        use super::*;

        async fn answer(headers: Vec<HeaderValue>) -> Response {
            let app =
                Router::new()
                    .route("/mcp", post(|| async { "reached" }))
                    .layer(axum::middleware::from_fn_with_state(
                        Arc::new(origins(&["https://assistant.example.org"])),
                        validate_origin,
                    ));
            let mut request = Request::post("/mcp").body(Body::empty()).unwrap();
            for value in headers {
                request.headers_mut().append(ORIGIN, value);
            }
            app.oneshot(request).await.unwrap()
        }

        fn refused(response: &Response) -> bool {
            response.status() == StatusCode::FORBIDDEN
                && response
                    .extensions()
                    .get::<EdgeProblem>()
                    .is_some_and(|problem| problem.code() == ProblemCode::Forbidden)
        }

        #[tokio::test]
        async fn a_listed_origin_and_no_origin_reach_the_endpoint() {
            assert_eq!(answer(Vec::new()).await.status(), StatusCode::OK);
            let listed = HeaderValue::from_static("https://assistant.example.org");
            assert_eq!(answer(vec![listed]).await.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn repeated_and_unreadable_origins_are_forbidden() {
            let listed = HeaderValue::from_static("https://assistant.example.org");
            // Two headers, even the same listed one twice: which of them would a browser have meant?
            assert!(refused(&answer(vec![listed.clone(), listed]).await));
            // Bytes that are no text cannot be compared with the list, so they are not on it.
            let opaque = HeaderValue::from_bytes(b"https://assistant.example.org\xff").unwrap();
            assert!(refused(&answer(vec![opaque]).await));
            assert!(refused(
                &answer(vec![HeaderValue::from_static("https://evil.example")]).await
            ));
        }
    }
}
