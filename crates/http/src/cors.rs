//! CORS and `Origin` policy for unsafe methods.
//!
//! Unsafe methods that carry an `Origin` outside `security.cors.allowed_origins` are refused with 403 (PLAN 2.15);
//! the DAV surface has no CORS at all and the API never accepts cookies, so a browser cannot be tricked into
//! acting for a user. This module holds the configuration and the pure origin checks ([`CorsConfig`],
//! [`OriginPolicy`]) and the two tower layers built on them:
//!
//! * [`guard_origin`] refuses unsafe requests (every method except `GET`, `HEAD`, `OPTIONS` and `TRACE`) whose
//!   `Origin` header is neither in `allowed_origins` nor the origin of the server itself. An origin that names the
//!   `Host` of the request is the same origin by definition, so the RSVP form on the server's own pages is never
//!   locked out; requests without an `Origin` header (every non-browser client) pass.
//! * [`cors_layer`] answers preflight requests and adds the CORS response headers for the allowed origins, without
//!   credentials. Only the API mounts it.

use core::time::Duration;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{
    AUTHORIZATION, CONTENT_TYPE, ETAG, HOST, IF_MATCH, IF_NONE_MATCH, LINK, LOCATION, ORIGIN, RETRY_AFTER,
};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use davhaven_app::config::ConfigError;
use davhaven_wire::ProblemCode;
use schemars::JsonSchema;
use serde::Deserialize;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::problem::EdgeProblem;

/// The `[security.cors]` table.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CorsConfig {
    /// The origins (`https://admin.example.org`, `http://localhost:3000`) that may call the API from a browser.
    /// Empty by default: no browser origin is allowed.
    pub allowed_origins: Vec<String>,
}

/// Whether `text` is an origin: `http` or `https`, a host (a DNS name, an IPv4 address or a bracketed IPv6
/// address) and an optional port, nothing else. Wildcards, paths, credentials, queries and trailing slashes are
/// not part of an origin.
pub fn is_valid_origin(text: &str) -> bool {
    let Some((scheme, authority)) = text.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https") {
        return false;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((address, tail)) = bracketed.split_once(']') else {
            return false;
        };
        let port_ok = match tail.strip_prefix(':') {
            Some(port) => is_valid_port(port),
            None => tail.is_empty(),
        };
        let address_ok = !address.is_empty() && address.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
        return address_ok && port_ok;
    }
    match authority.split_once(':') {
        Some((host, port)) => is_valid_dns_host(host) && is_valid_port(port),
        None => is_valid_dns_host(authority),
    }
}

fn is_valid_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
}

fn is_valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|port| (1..=65_535).contains(&port))
}

impl CorsConfig {
    /// Checks every allowed origin.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] for `security.cors.allowed_origins` when an entry is not an origin.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.allowed_origins.iter().all(|origin| is_valid_origin(origin)) {
            Ok(())
        } else {
            Err(ConfigError::new(
                "security.cors",
                "allowed_origins",
                "entries must be origins such as https://admin.example.org (scheme, host, optional port; no path, no wildcard)",
            ))
        }
    }

    /// Whether an `Origin` header value is allowed.
    pub fn allows(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|allowed| allowed == origin)
    }
}

/// Whether a method changes state (everything except `GET`, `HEAD`, `OPTIONS` and `TRACE`). WebDAV methods count
/// as unsafe, so a browser page cannot trigger `PROPPATCH`, `MOVE` or `MKCALENDAR` cross-site.
pub fn is_unsafe_method(method: &Method) -> bool {
    !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

/// Whether `origin` (`scheme://authority`) names `host` (the authority of the request), which makes the request
/// same-origin.
fn names_host(origin: &str, host: &str) -> bool {
    origin
        .split_once("://")
        .is_some_and(|(_, authority)| authority.eq_ignore_ascii_case(host.trim()))
}

/// Decides which `Origin` headers unsafe requests may carry.
#[derive(Debug, Clone, Default)]
pub struct OriginPolicy {
    config: CorsConfig,
}

impl OriginPolicy {
    /// The policy of the configured allowed origins.
    pub const fn new(config: CorsConfig) -> Self {
        Self { config }
    }

    /// Whether a request with this `Origin` header and this authority (`Host`) may change state: the origin is
    /// configured or it is the origin of the server itself. The `null` origin and every malformed value are
    /// refused.
    pub fn permits(&self, origin: &str, host: Option<&str>) -> bool {
        self.config.allows(origin) || host.is_some_and(|host| names_host(origin, host))
    }
}

/// The layer function of the origin guard; mount it with
/// `axum::middleware::from_fn_with_state(Arc::new(policy), guard_origin)`.
pub async fn guard_origin(State(policy): State<Arc<OriginPolicy>>, request: Request, next: Next) -> Response {
    if is_unsafe_method(request.method())
        && let Some(origin) = request.headers().get(ORIGIN)
    {
        let host = request
            .uri()
            .authority()
            .map(axum::http::uri::Authority::as_str)
            .or_else(|| request.headers().get(HOST).and_then(|value| value.to_str().ok()));
        if !origin.to_str().is_ok_and(|origin| policy.permits(origin, host)) {
            return EdgeProblem::new(ProblemCode::Forbidden)
                .with_detail("The origin of the request is not allowed.")
                .into_response();
        }
    }
    next.run(request).await
}

/// The CORS layer of the management API for the configured origins: preflight answers and response headers for
/// those origins, no credentials (the API never accepts cookies), the headers and methods the API uses. `None`
/// when no origin is configured, in which case no CORS header is ever sent.
pub fn cors_layer(config: &CorsConfig) -> Option<CorsLayer> {
    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();
    if origins.is_empty() {
        return None;
    }
    let request_id = HeaderName::from_static("x-request-id");
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([
                Method::GET,
                Method::PUT,
                Method::POST,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                AUTHORIZATION,
                CONTENT_TYPE,
                IF_MATCH,
                IF_NONE_MATCH,
                HeaderName::from_static("idempotency-key"),
                request_id.clone(),
            ])
            .expose_headers([
                ETAG,
                LOCATION,
                LINK,
                RETRY_AFTER,
                request_id,
                HeaderName::from_static("idempotent-replayed"),
            ])
            .max_age(Duration::from_mins(10)),
    )
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::any;
    use tower::ServiceExt as _;

    use super::*;
    use crate::problem::{JsonProblems, ProblemRenderer, render_problems};

    #[test]
    fn origins_are_scheme_host_and_optional_port() {
        for good in [
            "https://admin.example.org",
            "http://localhost:3000",
            "https://a-b.c.example:8443",
            "http://127.0.0.1:8080",
            "http://[::1]:3000",
            "http://[::1]",
        ] {
            assert!(is_valid_origin(good), "{good}");
        }
        for bad in [
            "",
            "*",
            "admin.example.org",
            "https://",
            "ftp://example.org",
            "https://example.org/",
            "https://example.org/path",
            "https://user@example.org",
            "https://Example.org",
            "https://example.org:",
            "https://example.org:0",
            "https://example.org:70000",
            "https://example.org:80a",
            "https://*.example.org",
            "http://[::1]x",
            "http://[::1",
            "https://-example.org",
        ] {
            assert!(!is_valid_origin(bad), "{bad}");
        }
    }

    #[test]
    fn the_configuration_validates_and_matches_origins_exactly() {
        let config: CorsConfig = serde_json::from_str(r#"{"allowed_origins": ["https://admin.example.org"]}"#).unwrap();
        config.validate().unwrap();
        assert!(config.allows("https://admin.example.org"));
        assert!(!config.allows("https://admin.example.org:8443"));
        assert!(!config.allows("http://admin.example.org"));
        assert!(!CorsConfig::default().allows("https://admin.example.org"));
        CorsConfig::default().validate().unwrap();
        let broken = CorsConfig {
            allowed_origins: vec!["*".to_owned()],
        };
        let error = broken.validate().unwrap_err();
        assert_eq!((error.section(), error.key()), ("security.cors", "allowed_origins"));
        assert!(serde_json::from_str::<CorsConfig>(r#"{"origins": []}"#).is_err());
    }

    fn policy(origins: &[&str]) -> Arc<OriginPolicy> {
        Arc::new(OriginPolicy::new(CorsConfig {
            allowed_origins: origins.iter().map(|origin| (*origin).to_owned()).collect(),
        }))
    }

    #[test]
    fn only_state_changing_methods_are_guarded() {
        for safe in ["GET", "HEAD", "OPTIONS", "TRACE"] {
            assert!(
                !is_unsafe_method(&Method::from_bytes(safe.as_bytes()).unwrap()),
                "{safe}"
            );
        }
        for unsafe_method in [
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "PROPPATCH",
            "MKCALENDAR",
            "MOVE",
            "COPY",
            "REPORT",
        ] {
            assert!(
                is_unsafe_method(&Method::from_bytes(unsafe_method.as_bytes()).unwrap()),
                "{unsafe_method}"
            );
        }
    }

    #[test]
    fn the_server_itself_is_always_a_permitted_origin() {
        let policy = policy(&["https://admin.example.org"]);
        assert!(policy.permits("https://admin.example.org", None));
        assert!(policy.permits("https://cal.example.org", Some("cal.example.org")));
        assert!(policy.permits("http://CAL.example.org:8080", Some("cal.example.org:8080")));
        assert!(!policy.permits("https://cal.example.org", Some("other.example.org")));
        assert!(!policy.permits("https://evil.example", Some("cal.example.org")));
        assert!(!policy.permits("null", Some("null")));
        assert!(!policy.permits("https://cal.example.org", None));
        assert!(!policy.permits("cal.example.org", Some("cal.example.org")));
    }

    fn guarded(origins: &[&str]) -> Router {
        let renderer: Arc<dyn ProblemRenderer> = Arc::new(JsonProblems::catalog());
        Router::new()
            .route("/", any(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(policy(origins), guard_origin))
            .layer(axum::middleware::from_fn_with_state(renderer, render_problems))
    }

    async fn send(app: Router, method: &str, origin: Option<&str>, host: &str) -> StatusCode {
        let mut request = Request::builder().method(method).uri("/").header("host", host);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        app.oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn the_guard_refuses_unsafe_requests_from_foreign_origins_only() {
        let app = || guarded(&["https://admin.example.org"]);
        let cases = [
            ("POST", Some("https://evil.example"), StatusCode::FORBIDDEN),
            ("DELETE", Some("null"), StatusCode::FORBIDDEN),
            ("PROPPATCH", Some("https://evil.example"), StatusCode::FORBIDDEN),
            ("POST", Some("https://admin.example.org"), StatusCode::OK),
            ("PUT", Some("https://cal.example.org"), StatusCode::OK),
            ("POST", None, StatusCode::OK),
            ("GET", Some("https://evil.example"), StatusCode::OK),
            ("OPTIONS", Some("https://evil.example"), StatusCode::OK),
        ];
        for (method, origin, expected) in cases {
            assert_eq!(
                send(app(), method, origin, "cal.example.org").await,
                expected,
                "{method} {origin:?}"
            );
        }
        let refused = guarded(&["https://admin.example.org"])
            .oneshot(
                Request::post("/")
                    .header("host", "cal.example.org")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = http_body_util::BodyExt::collect(refused.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["code"], "forbidden");
        // An origin that is not text cannot be compared with anything and is refused.
        let unreadable = Request::post("/")
            .header("host", "cal.example.org")
            .header(
                "origin",
                HeaderValue::from_bytes(b"https://cal.example.org\xff").unwrap(),
            )
            .body(Body::empty())
            .unwrap();
        let response = guarded(&["https://admin.example.org"])
            .oneshot(unreadable)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // In absolute form the authority of the URI is the host of the request.
        let absolute = Request::post("http://cal.example.org/")
            .header("origin", "http://cal.example.org")
            .body(Body::empty())
            .unwrap();
        let response = guarded(&[]).oneshot(absolute).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let nothing_configured = guarded(&[]);
        let status = send(
            nothing_configured,
            "POST",
            Some("https://admin.example.org"),
            "cal.example.org",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn preflights_of_allowed_origins_are_answered_without_credentials() {
        let config = CorsConfig {
            allowed_origins: vec!["https://admin.example.org".to_owned()],
        };
        let app = Router::new()
            .route("/", any(|| async { "ok" }))
            .layer(cors_layer(&config).unwrap());
        let preflight = |origin: &'static str| {
            Request::builder()
                .method("OPTIONS")
                .uri("/")
                .header("origin", origin)
                .header("access-control-request-method", "PUT")
                .header("access-control-request-headers", "authorization, if-match")
                .body(Body::empty())
                .unwrap()
        };
        let allowed = app
            .clone()
            .oneshot(preflight("https://admin.example.org"))
            .await
            .unwrap();
        assert_eq!(
            allowed.headers()["access-control-allow-origin"],
            "https://admin.example.org"
        );
        assert!(allowed.headers().get("access-control-allow-credentials").is_none());
        let foreign = app.oneshot(preflight("https://evil.example")).await.unwrap();
        assert!(foreign.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn preflights_allow_the_methods_and_headers_of_the_api_and_responses_expose_its_headers() {
        let config = CorsConfig {
            allowed_origins: vec!["https://admin.example.org".to_owned()],
        };
        let app = Router::new()
            .route("/", any(|| async { "ok" }))
            .layer(cors_layer(&config).unwrap());
        let preflight = Request::builder()
            .method("OPTIONS")
            .uri("/")
            .header("origin", "https://admin.example.org")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "idempotency-key, x-request-id")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(preflight).await.unwrap();
        let list = |name: &str| -> Vec<String> {
            response.headers()[name]
                .to_str()
                .unwrap()
                .split(',')
                .map(|item| item.trim().to_ascii_lowercase())
                .collect()
        };
        for method in ["get", "put", "post", "patch", "delete", "options"] {
            assert!(
                list("access-control-allow-methods").contains(&method.to_owned()),
                "{method}"
            );
        }
        for header in [
            "authorization",
            "content-type",
            "if-match",
            "if-none-match",
            "idempotency-key",
            "x-request-id",
        ] {
            assert!(
                list("access-control-allow-headers").contains(&header.to_owned()),
                "{header}"
            );
        }
        assert_eq!(response.headers()["access-control-max-age"], "600");

        let actual = Request::get("/")
            .header("origin", "https://admin.example.org")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(actual).await.unwrap();
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://admin.example.org"
        );
        let exposed: Vec<String> = response.headers()["access-control-expose-headers"]
            .to_str()
            .unwrap()
            .split(',')
            .map(|item| item.trim().to_ascii_lowercase())
            .collect();
        for header in [
            "etag",
            "location",
            "link",
            "retry-after",
            "x-request-id",
            "idempotent-replayed",
        ] {
            assert!(exposed.contains(&header.to_owned()), "{header}: {exposed:?}");
        }
        assert!(response.headers().get("access-control-allow-credentials").is_none());
    }

    #[test]
    fn no_configured_origin_means_no_cors_layer() {
        assert!(cors_layer(&CorsConfig::default()).is_none());
    }
}
