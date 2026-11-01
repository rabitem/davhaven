//! The `HttpClient` port for all outbound HTTP (egress policy enforced by the adapter).
//!
//! Every outbound request of the server (webhooks, OAuth token exchange, provider APIs) goes through
//! [`HttpClient`]. The production adapter (`http-egress`) is the only crate that depends on an HTTP client
//! library and applies the egress policy inside `send` (`ENGINEERING_RULES` R6): HTTPS only, private, loopback,
//! link-local and metadata address ranges denied after DNS resolution, no redirects, timeouts and size caps. A
//! recording fake serves tests.

use core::fmt;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use url::Url;

use crate::error::{PortError, PortErrorKind};

/// Why a request is sent. Adapters use it for metric labels and per-purpose limits; it never changes which
/// policy applies.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpPurpose {
    /// A webhook delivery to a subscriber.
    Webhook,
    /// An OAuth token exchange, refresh or revocation.
    OAuth,
    /// A call to an external calendar provider API.
    ProviderApi,
}

impl HttpPurpose {
    /// A stable `snake_case` name for logs and metric labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::OAuth => "oauth",
            Self::ProviderApi => "provider_api",
        }
    }
}

/// An outbound HTTP request.
#[derive(Clone)]
pub struct OutboundRequest {
    /// The request method.
    pub method: Method,
    /// The target URL; the adapter refuses anything but `https` unless its configuration allows `http`.
    pub url: Url,
    /// The request headers.
    pub headers: HeaderMap,
    /// The request body (empty for none).
    pub body: Bytes,
    /// Why the request is sent.
    pub purpose: HttpPurpose,
}

impl OutboundRequest {
    /// A request without headers and body.
    pub fn new(method: Method, url: Url, purpose: HttpPurpose) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            purpose,
        }
    }

    /// Adds a header (replacing an existing value of the same name).
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }
}

impl fmt::Debug for OutboundRequest {
    /// Prints the method, the URL without query and credentials, the header names and the body size: header
    /// values (`Authorization`, `webhook-signature`) and URL query strings may carry secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = self.url.host_str().unwrap_or("");
        let target = format!("{}://{}{}", self.url.scheme(), host, self.url.path());
        let names: Vec<&str> = self.headers.keys().map(HeaderName::as_str).collect();
        f.debug_struct("OutboundRequest")
            .field("method", &self.method)
            .field("url", &target)
            .field("headers", &names)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .field("purpose", &self.purpose)
            .finish()
    }
}

/// An HTTP response. The adapter caps `body` at the maximum of the request's purpose and answers
/// [`PortErrorKind::Rejected`] when the remote sends more, with one
/// exception: the body of a [`HttpPurpose::Webhook`] answer is informational (the status is what matters), so
/// the adapter cuts it at the maximum and returns what it has instead of failing a delivery the receiver accepted.
#[derive(Clone)]
pub struct OutboundResponse {
    /// The status code. Redirects are not followed; a `3xx` is returned as is.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The response body.
    pub body: Bytes,
}

impl fmt::Debug for OutboundResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.len())
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .finish()
    }
}

/// Sends outbound HTTP requests under the egress policy.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Sends `request` and returns the response of the remote, whatever its status.
    ///
    /// # Errors
    ///
    /// * `Rejected`: the egress policy refuses the request (scheme, address range, redirect loop) or the response
    ///   exceeds the size cap of its purpose (never for [`HttpPurpose::Webhook`], whose body is cut instead).
    /// * `Timeout` and `Unavailable`: the remote did not answer in time or cannot be reached.
    /// * `Invalid`: the request cannot be sent (for example an unsupported method).
    async fn send(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError>;

    /// Checks whether `send` would accept `url` as a target, without sending anything: the application calls it
    /// when it stores a URL (webhook registration), so that a URL the egress policy refuses is rejected at
    /// registration and not only on every delivery.
    ///
    /// Adapters that enforce an egress policy override it with the checks of `send` (scheme, address ranges, and
    /// for host names the addresses they resolve to now). The default fails closed: a client that cannot check
    /// URLs answers `Unsupported`, which the application treats as an error, so no URL is accepted unchecked.
    ///
    /// # Errors
    ///
    /// `Rejected` when the policy refuses the URL, `Invalid` when it cannot be a target at all (no host),
    /// `Unavailable` or `Timeout` when a host name cannot be resolved right now, and `Unsupported` when the
    /// client has no way to check.
    async fn validate_url(&self, _url: &Url) -> Result<(), PortError> {
        Err(PortError::new(
            PortErrorKind::Unsupported,
            "this HTTP client cannot validate URLs",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_header_values_and_query_strings() {
        let url = Url::parse("https://hooks.example.org/in/endpoint?token=s3cret").unwrap();
        let request = OutboundRequest::new(Method::POST, url, HttpPurpose::Webhook)
            .with_header(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static("Bearer topsecret"),
            )
            .with_body(Bytes::from_static(b"{\"a\":1}"));
        let shown = format!("{request:?}");
        assert!(shown.contains("https://hooks.example.org/in/endpoint"), "{shown}");
        assert!(shown.contains("authorization"), "{shown}");
        assert!(shown.contains("<7 bytes>"), "{shown}");
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(!shown.contains("topsecret"), "{shown}");
    }

    #[test]
    fn builders_set_headers_and_body() {
        let url = Url::parse("https://example.org/").unwrap();
        let request = OutboundRequest::new(Method::GET, url, HttpPurpose::OAuth)
            .with_header(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("application/json"),
            )
            .with_header(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("text/plain"),
            );
        assert_eq!(request.headers.len(), 1);
        assert_eq!(request.headers.get("accept").unwrap(), "text/plain");
        assert!(request.body.is_empty());
        assert_eq!(request.purpose.as_str(), "oauth");
    }

    struct Unchecked;

    #[async_trait]
    impl HttpClient for Unchecked {
        async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
            Err(PortError::unavailable("no network in this test"))
        }
    }

    #[tokio::test]
    async fn clients_without_a_url_check_fail_closed() {
        let url = Url::parse("https://8.8.8.8/").unwrap();
        let error = Unchecked.validate_url(&url).await.unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unsupported);
    }

    #[test]
    fn responses_do_not_debug_print_bodies() {
        let response = OutboundResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"private body"),
        };
        let shown = format!("{response:?}");
        assert!(shown.contains("200") && shown.contains("<12 bytes>"), "{shown}");
        assert!(!shown.contains("private"), "{shown}");
    }
}
