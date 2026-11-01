//! Request tracing, route-template labels and HTTP metrics.
//!
//! One log line and two metric samples per request (PLAN 2.17, R8):
//!
//! * `davhaven_http_requests_total{surface,method,route,status}` and
//!   `davhaven_http_request_duration_seconds{surface,method,route}`;
//! * a structured `tracing` event with the request id, the W3C trace id when the client sent a `traceparent`, the
//!   tenant and principal ids once the request was authenticated, the route, the status and the latency.
//!
//! **Labels never come from the raw path.** The `route` of metrics and logs is the matched route template
//! (`/api/v1/tenants/{tenant}/principals`), so tokens in URLs (feeds, RSVP links, OAuth callbacks) and
//! user-controlled segments never reach a label, a span field or a log line; requests that match no route are
//! labelled [`UNMATCHED_ROUTE`]. Methods outside the known set are labelled `OTHER`, which bounds the label
//! cardinality. Bodies, query strings, iCalendar data and e-mail addresses are never logged.

use core::time::Duration;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, Method};
use axum::middleware::Next;
use axum::response::Response;
use davhaven_domain::{PrincipalId, TenantId};

use crate::request_id::request_id_of;
use crate::surface::Surface;

/// The route label of requests that matched no route (unknown paths).
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// Who made the request, for log lines.
///
/// The authentication layer puts it into the *response* extensions (the request has been consumed by then), and the
/// tracing layer reads it on the way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogIdentity {
    /// The tenant of the authenticated request.
    pub tenant: TenantId,
    /// The principal the request acts as, if it acts as one.
    pub principal: Option<PrincipalId>,
}

/// The metric label of an HTTP method: the standard methods and the WebDAV/CalDAV methods by name, everything
/// else as `OTHER`.
pub fn method_label(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "CONNECT" => "CONNECT",
        "PROPFIND" => "PROPFIND",
        "PROPPATCH" => "PROPPATCH",
        "MKCOL" => "MKCOL",
        "MKCALENDAR" => "MKCALENDAR",
        "COPY" => "COPY",
        "MOVE" => "MOVE",
        "REPORT" => "REPORT",
        "LOCK" => "LOCK",
        "UNLOCK" => "UNLOCK",
        _ => "OTHER",
    }
}

/// The trace id of a W3C `traceparent` header (`00-{32 hex}-{16 hex}-{2 hex}`), when the header is well formed
/// and the id is not all zeros.
pub fn trace_id_of(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("traceparent")?.to_str().ok()?;
    let mut parts = value.trim().split('-');
    let (Some(version), Some(trace_id), Some(span_id), Some(flags)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let hex =
        |text: &str, len: usize| text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let valid = hex(version, 2)
        && version != "ff"
        && hex(trace_id, 32)
        && trace_id.bytes().any(|b| b != b'0')
        && hex(span_id, 16)
        && span_id.bytes().any(|b| b != b'0')
        && hex(flags, 2);
    valid.then(|| trace_id.to_owned())
}

fn record_metrics(surface: Surface, method: &'static str, route: &str, status: u16, elapsed: Duration) {
    metrics::counter!(
        "davhaven_http_requests_total",
        "surface" => surface.as_str(),
        "method" => method,
        "route" => route.to_owned(),
        "status" => status.to_string()
    )
    .increment(1);
    metrics::histogram!(
        "davhaven_http_request_duration_seconds",
        "surface" => surface.as_str(),
        "method" => method,
        "route" => route.to_owned()
    )
    .record(elapsed.as_secs_f64());
}

/// The layer function of request tracing and metrics; mount it with
/// `axum::middleware::from_fn_with_state(surface, trace_requests)`.
///
/// It must sit inside the routing (every `Router::layer` does) so that the matched route template is known, and
/// inside the request id layer.
pub async fn trace_requests(State(surface): State<Surface>, request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = method_label(request.method());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| UNMATCHED_ROUTE.to_owned(), |matched| matched.as_str().to_owned());
    let request_id = request_id_of(request.extensions()).map(|id| id.to_string());
    let trace_id = trace_id_of(request.headers());

    let response = next.run(request).await;

    let elapsed = started.elapsed();
    let status = response.status().as_u16();
    let identity = response.extensions().get::<LogIdentity>().copied();
    record_metrics(surface, method, &route, status, elapsed);

    let tenant_id = identity.map(|identity| identity.tenant.to_string());
    let principal_id = identity
        .and_then(|identity| identity.principal)
        .map(|id| id.to_string());
    let latency_ms = elapsed.as_secs_f64() * 1000.0;
    if status >= 500 {
        tracing::error!(
            target: "davhaven::http",
            request_id = request_id.as_deref(),
            trace_id = trace_id.as_deref(),
            tenant_id = tenant_id.as_deref(),
            principal_id = principal_id.as_deref(),
            surface = surface.as_str(),
            method,
            route = %route,
            status,
            latency_ms,
            "request failed"
        );
    } else {
        tracing::info!(
            target: "davhaven::http",
            request_id = request_id.as_deref(),
            trace_id = trace_id.as_deref(),
            tenant_id = tenant_id.as_deref(),
            principal_id = principal_id.as_deref(),
            surface = surface.as_str(),
            method,
            route = %route,
            status,
            latency_ms,
            "request"
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt as _;

    use super::*;

    #[test]
    fn known_methods_keep_their_names_and_others_are_bounded() {
        for name in [
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "PROPFIND",
            "PROPPATCH",
            "MKCOL",
            "MKCALENDAR",
            "COPY",
            "MOVE",
            "REPORT",
            "LOCK",
            "UNLOCK",
        ] {
            let method = Method::from_bytes(name.as_bytes()).unwrap();
            assert_eq!(method_label(&method), name);
        }
        for name in ["BREW", "SEARCH", "x-custom"] {
            let method = Method::from_bytes(name.as_bytes()).unwrap();
            assert_eq!(method_label(&method), "OTHER", "{name}");
        }
    }

    #[test]
    fn trace_ids_come_from_well_formed_traceparent_headers_only() {
        let header = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("traceparent", value.parse().unwrap());
            headers
        };
        assert_eq!(
            trace_id_of(&header("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")).as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        for bad in [
            "",
            "garbage",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e47-00f067aa0ba902b7-01",
        ] {
            assert_eq!(trace_id_of(&header(bad)), None, "{bad}");
        }
        assert_eq!(trace_id_of(&HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn labels_are_route_templates_including_the_prefix_of_nested_routers() {
        let inner = Router::new().route(
            "/tenants/{tenant}",
            get(|matched: MatchedPath| async move { matched.as_str().to_owned() }),
        );
        let app = Router::new().nest("/api/v1", inner);
        let response = app
            .oneshot(Request::get("/api/v1/tenants/acme").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(
            &bytes[..],
            b"/api/v1/tenants/{tenant}",
            "the raw path never becomes a label"
        );
    }

    #[tokio::test]
    async fn the_layer_passes_responses_through_unchanged() {
        let app = Router::new()
            .route("/things/{id}", get(|| async { "thing" }))
            .layer(axum::middleware::from_fn_with_state(Surface::Api, trace_requests));
        let hit = app
            .clone()
            .oneshot(Request::get("/things/42").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(hit.status(), 200);
        let miss = app
            .oneshot(Request::get("/nothing/here").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(miss.status(), 404);
    }
}
