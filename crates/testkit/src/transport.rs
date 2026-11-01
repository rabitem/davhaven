//! The `Transport` trait: in-process `oneshot` and HTTP base URL.
//!
//! A transport carries one request to an application and brings back the response. Everything above it (the
//! surface handles of [`TestApp`](crate::app::TestApp), the permission and scheduling matrices, the client-flow
//! runner) is written against the trait, so the same tests run in process against an axum router
//! ([`InProcess`]) and over the network against a deployed instance ([`HttpTransport`], used by the `conformance`
//! binary). [`FnTransport`] answers from a closure, for tests of the harness itself.

use core::fmt;
use std::sync::Once;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use tower::ServiceExt as _;
use url::Url;

/// The largest response body the transports read; test responses are small and a runaway body is a bug.
pub const MAX_RESPONSE_BODY: usize = 16 * 1024 * 1024;

/// How long [`HttpTransport`] waits for one response.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Failures of carrying a request, not HTTP error statuses (those are ordinary responses).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The request cannot be sent: a header name or value or the target is malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The application cannot be reached or the connection broke.
    #[error("connection failed: {0}")]
    Connection(String),
    /// The response body cannot be read or decoded.
    #[error("cannot read the response body: {0}")]
    Body(String),
}

/// One request: method, target (path and query, absolute path form), headers and body.
#[derive(Clone)]
pub struct TestRequest {
    /// The HTTP method; DAV methods such as `PROPFIND` are valid extension methods.
    pub method: Method,
    /// The request target: an absolute path with an optional query, for example `/dav/` or `/api/v1/tenants?limit=2`.
    pub target: String,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
    problems: Vec<String>,
}

impl TestRequest {
    /// A request without headers and body. A method name that is not a valid token is reported when the request is
    /// sent; the request then uses `GET` so the builder never fails halfway.
    pub fn new(method: &str, target: impl Into<String>) -> Self {
        let mut problems = Vec::new();
        let method = Method::from_bytes(method.as_bytes()).unwrap_or_else(|_| {
            problems.push(format!("`{method}` is not a valid HTTP method"));
            Method::GET
        });
        Self {
            method,
            target: target.into(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            problems,
        }
    }

    /// Sets a header, replacing earlier values of the same name. A malformed name or value is reported when the
    /// request is sent.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        match (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            (Ok(name), Ok(value)) => {
                self.headers.insert(name, value);
            }
            _ => self.problems.push(format!("`{name}` is not a valid header")),
        }
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets the body and the `Content-Type` header.
    #[must_use]
    pub fn content(self, content_type: &str, body: impl Into<Bytes>) -> Self {
        self.header("content-type", content_type).body(body)
    }

    /// The first malformed part of the request, as an error.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidRequest`] when the method, a header or the target is malformed.
    pub fn check(&self) -> Result<(), TransportError> {
        if let Some(problem) = self.problems.first() {
            return Err(TransportError::InvalidRequest(problem.clone()));
        }
        if !self.target.starts_with('/') {
            return Err(TransportError::InvalidRequest(format!(
                "the target `{}` is not an absolute path",
                self.target
            )));
        }
        // A target that starts with two slashes names another host in the form of a URL reference, and the request
        // (with its credentials) would go there.
        if self.target.starts_with("//") || self.target.contains('\\') {
            return Err(TransportError::InvalidRequest(format!(
                "the target `{}` could name another host",
                self.target
            )));
        }
        Ok(())
    }
}

impl fmt::Debug for TestRequest {
    /// Prints method, target and header names; header values (credentials) and bodies never appear.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field(
                "headers",
                &self.headers.keys().map(HeaderName::as_str).collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// One response.
#[derive(Debug, Clone)]
pub struct TestResponse {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
}

impl TestResponse {
    /// A response from parts, for [`FnTransport`] closures and tests.
    pub fn new(status: u16, body: impl Into<Bytes>) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            headers: HeaderMap::new(),
            body: body.into(),
        }
    }

    /// Adds a header (an invalid one is ignored).
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            self.headers.append(name, value);
        }
        self
    }

    /// The first value of a header, if it is present and printable ASCII.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// The body as text (invalid UTF-8 is replaced).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The start of the body on one line for a report or an error: whitespace collapsed, cut at `max` characters, and
    /// without any secret of a known format ([`crate::redact`]), because a refused request that was answered with a
    /// credential is exactly the failure that gets reported.
    pub fn excerpt(&self, max: usize) -> String {
        crate::redact::excerpt(&self.text(), max)
    }

    /// The body parsed as JSON.
    ///
    /// # Errors
    ///
    /// [`TransportError::Body`] when the body is not JSON of the expected shape.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, TransportError> {
        serde_json::from_slice(&self.body).map_err(|error| TransportError::Body(error.to_string()))
    }

    /// The `ETag` header.
    pub fn etag(&self) -> Option<&str> {
        self.header("etag")
    }

    /// The `Location` header.
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    /// Whether the status is 2xx.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }
}

/// Carries requests to an application.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends one request and returns the response, whatever its status.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when the request is malformed, the application cannot be reached or the body cannot be
    /// read.
    async fn send(&self, request: TestRequest) -> Result<TestResponse, TransportError>;
}

impl fmt::Debug for dyn Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn Transport")
    }
}

/// Runs requests against an axum router in the current task, without a network: `tower::ServiceExt::oneshot`.
#[derive(Clone)]
pub struct InProcess {
    router: Router,
    host: Option<HeaderValue>,
}

impl InProcess {
    /// Serves requests with `router`.
    pub const fn new(router: Router) -> Self {
        Self { router, host: None }
    }

    /// Adds `Host: host` to every request that has none, as a client or a reverse proxy does: a request that reaches a
    /// router without going through a network has no `Host`, and the same-origin check of state-changing requests
    /// (`Origin` against `Host`) needs one. An invalid host is ignored.
    #[must_use]
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = HeaderValue::from_str(host).ok();
        self
    }
}

impl fmt::Debug for InProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcess").finish_non_exhaustive()
    }
}

#[async_trait]
impl Transport for InProcess {
    async fn send(&self, request: TestRequest) -> Result<TestResponse, TransportError> {
        request.check()?;
        let mut builder = Request::builder().method(request.method).uri(request.target.as_str());
        if let Some(headers) = builder.headers_mut() {
            *headers = request.headers;
            if let Some(host) = &self.host
                && !headers.contains_key(http::header::HOST)
            {
                headers.insert(http::header::HOST, host.clone());
            }
        }
        let built = builder
            .body(Body::from(request.body))
            .map_err(|error| TransportError::InvalidRequest(error.to_string()))?;
        let response = match self.router.clone().oneshot(built).await {
            Ok(response) => response,
            Err(infallible) => match infallible {},
        };
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, MAX_RESPONSE_BODY)
            .await
            .map_err(|error| TransportError::Body(error.to_string()))?;
        Ok(TestResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }
}

/// Sends requests over the network to `base`, for example a staging deployment.
///
/// Redirects are not followed (the tests assert on them) and TLS uses rustls with the ring provider, which this
/// transport installs as the process default on first use.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    base: Url,
    client: reqwest::Client,
    max_body: usize,
}

static INSTALL_TLS_PROVIDER: Once = Once::new();

impl HttpTransport {
    /// A transport for the instance at `base` (scheme, host and port; a path prefix is replaced by the target).
    ///
    /// # Errors
    ///
    /// [`TransportError::Connection`] when the HTTP client cannot be built.
    pub fn new(base: Url) -> Result<Self, TransportError> {
        INSTALL_TLS_PROVIDER.call_once(|| {
            // Another component may have installed a provider already; either one is fine for tests.
            drop(rustls::crypto::ring::default_provider().install_default());
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|error| TransportError::Connection(error.without_url().to_string()))?;
        Ok(Self {
            base,
            client,
            max_body: MAX_RESPONSE_BODY,
        })
    }

    /// The same transport with another limit for the size of a response body (default [`MAX_RESPONSE_BODY`]): a deployed
    /// instance, or a proxy in front of it, that sends more is a failure of the request and not a reason to fill memory.
    #[must_use]
    pub const fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    /// The base URL.
    pub const fn base(&self) -> &Url {
        &self.base
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn send(&self, request: TestRequest) -> Result<TestResponse, TransportError> {
        request.check()?;
        let url = self
            .base
            .join(&request.target)
            .map_err(|error| TransportError::InvalidRequest(error.to_string()))?;
        // The credentials of the request go to the instance of the base URL and nowhere else.
        if url.origin() != self.base.origin() {
            return Err(TransportError::InvalidRequest(format!(
                "the target `{}` leaves the origin of the instance",
                request.target
            )));
        }
        let mut response = self
            .client
            .request(request.method, url)
            .headers(request.headers)
            .body(request.body)
            .send()
            .await
            .map_err(|error| TransportError::Connection(error.without_url().to_string()))?;
        let status = response.status();
        let headers = response.headers().clone();
        let limit = u64::try_from(self.max_body).unwrap_or(u64::MAX);
        if response.content_length().is_some_and(|length| length > limit) {
            return Err(TransportError::Body(format!(
                "the response announces more than {} bytes",
                self.max_body
            )));
        }
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| TransportError::Body(error.without_url().to_string()))?
        {
            if body.len() + chunk.len() > self.max_body {
                return Err(TransportError::Body(format!(
                    "the response is larger than {} bytes",
                    self.max_body
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(TestResponse {
            status,
            headers,
            body: Bytes::from(body),
        })
    }
}

/// A transport that answers every request with the result of a closure; for tests of the harness.
pub struct FnTransport<F> {
    answer: F,
}

impl<F> FnTransport<F>
where
    F: Fn(&TestRequest) -> Result<TestResponse, TransportError> + Send + Sync,
{
    /// Answers with `answer`.
    pub const fn new(answer: F) -> Self {
        Self { answer }
    }
}

impl<F> fmt::Debug for FnTransport<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FnTransport").finish_non_exhaustive()
    }
}

#[async_trait]
impl<F> Transport for FnTransport<F>
where
    F: Fn(&TestRequest) -> Result<TestResponse, TransportError> + Send + Sync,
{
    async fn send(&self, request: TestRequest) -> Result<TestResponse, TransportError> {
        request.check()?;
        (self.answer)(&request)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::HeaderMap as AxumHeaders;
    use axum::routing::{any, get};

    use super::*;

    fn router() -> Router {
        Router::new()
            .route(
                "/echo",
                any(|method: Method, headers: AxumHeaders, body: Bytes| async move {
                    let agent = headers
                        .get("x-test")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("none")
                        .to_owned();
                    (
                        [("x-method", method.to_string())],
                        format!("{agent}:{}", String::from_utf8_lossy(&body)),
                    )
                }),
            )
            .route("/json", get(|| async { r#"{"n": 3}"# }))
    }

    #[tokio::test]
    async fn in_process_requests_reach_the_router_with_extension_methods_headers_and_bodies() {
        let transport = InProcess::new(router());
        let request = TestRequest::new("PROPFIND", "/echo")
            .header("x-test", "yes")
            .body("<xml/>");
        let response = transport.send(request).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.header("x-method"), Some("PROPFIND"));
        assert_eq!(response.text(), "yes:<xml/>");

        let missing = transport.send(TestRequest::new("GET", "/missing")).await.unwrap();
        assert_eq!(
            missing.status,
            StatusCode::NOT_FOUND,
            "error statuses are responses, not errors"
        );
        let parsed: serde_json::Value = transport
            .send(TestRequest::new("GET", "/json"))
            .await
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(parsed["n"], 3);
    }

    #[tokio::test]
    async fn malformed_requests_are_reported_instead_of_sent() {
        let transport = InProcess::new(router());
        for request in [
            TestRequest::new("not a method", "/echo"),
            TestRequest::new("GET", "/echo").header("bad name", "x"),
            TestRequest::new("GET", "/echo").header("x-test", "line\nbreak"),
            TestRequest::new("GET", "no-leading-slash"),
            // A target that starts with two slashes names another host, and would take the credentials there.
            TestRequest::new("GET", "//other.example/x"),
            TestRequest::new("GET", "/\\other.example/x"),
        ] {
            let error = transport.send(request).await.unwrap_err();
            assert!(matches!(error, TransportError::InvalidRequest(_)), "{error}");
        }
    }

    #[test]
    fn requests_never_print_header_values_or_bodies() {
        let request = TestRequest::new("PUT", "/x")
            .header("authorization", "Basic c2VjcmV0")
            .content("text/plain", "very secret body");
        let shown = format!("{request:?}");
        assert!(shown.contains("authorization") && shown.contains("body_len"), "{shown}");
        assert!(!shown.contains("c2VjcmV0") && !shown.contains("very secret"), "{shown}");
    }

    #[tokio::test]
    async fn closure_transports_answer_from_the_closure() {
        let transport = FnTransport::new(|request: &TestRequest| {
            Ok(TestResponse::new(207, request.target.clone()).with_header("etag", "\"abc\""))
        });
        let response = transport.send(TestRequest::new("GET", "/dav/")).await.unwrap();
        assert_eq!((response.status.as_u16(), response.text().as_str()), (207, "/dav/"));
        assert_eq!(response.etag(), Some("\"abc\""));
        assert!(response.is_success() && response.location().is_none());
        assert!(transport.send(TestRequest::new("bad method", "/")).await.is_err());
    }

    #[tokio::test]
    async fn the_http_transport_talks_to_a_real_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router()).await });
        let base = Url::parse(&format!("http://{address}/")).unwrap();
        let transport: Arc<dyn Transport> = Arc::new(HttpTransport::new(base).unwrap());

        let request = TestRequest::new("REPORT", "/echo?x=1")
            .header("x-test", "net")
            .body("body");
        let response = transport.send(request).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.header("x-method"), Some("REPORT"));
        assert_eq!(response.text(), "net:body");

        // A body larger than the limit of the transport is an error of the request.
        let capped = HttpTransport::new(Url::parse(&format!("http://{address}/")).unwrap())
            .unwrap()
            .with_max_body(4);
        let error = capped.send(TestRequest::new("GET", "/json")).await.unwrap_err();
        assert!(matches!(error, TransportError::Body(_)), "{error}");
        assert!(
            capped.send(TestRequest::new("GET", "/missing")).await.is_ok(),
            "an empty body is within every limit"
        );
        server.abort();

        let unreachable = HttpTransport::new(Url::parse("http://127.0.0.1:1/").unwrap()).unwrap();
        let error = unreachable.send(TestRequest::new("GET", "/")).await.unwrap_err();
        assert!(matches!(error, TransportError::Connection(_)), "{error}");
    }
}
