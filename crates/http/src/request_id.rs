//! Accepting or generating `X-Request-Id` and propagating it.
//!
//! Every request has a [`RequestId`] (PLAN 2.10, 2.17): the client's `X-Request-Id` when it is a UUID, a fresh id
//! otherwise. The id is stored in the request extensions (the `RequestContext` of the application, the logs, the
//! metrics exemplars and the problem documents carry it) and echoed in the `X-Request-Id` header of the response.
//! Ids that are not UUIDs are replaced rather than echoed, so the header can never carry client-chosen free text
//! into logs.
//!
//! Randomness comes only through the [`RequestIdSource`] port of this crate: the server implements it with the
//! `IdGenerator` (UUIDv7); tests use [`SequentialRequestIds`].

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{Extensions, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use davhaven_domain::RequestId;
use uuid::Uuid;

/// The request id header.
pub const X_REQUEST_ID: &str = "x-request-id";

/// Where fresh request ids come from.
pub trait RequestIdSource: Send + Sync + 'static {
    /// A new, unique request id (a UUIDv7 in production).
    fn next_id(&self) -> RequestId;
}

/// Deterministic request ids for tests and in-process use: `…0001`, `…0002`, … in UUIDv7 form.
#[derive(Debug, Default)]
pub struct SequentialRequestIds {
    counter: AtomicU64,
}

impl SequentialRequestIds {
    /// A source whose first id ends in `1`.
    pub const fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl RequestIdSource for SequentialRequestIds {
    fn next_id(&self) -> RequestId {
        const PREFIX: u128 = 0x018f_3c1e_7b2a_7c3d_9e4f_0000_0000_0000;
        let n = self.counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        RequestId::from_uuid(Uuid::from_u128(PREFIX | u128::from(n)))
    }
}

/// The request id stored in a request's extensions.
pub fn request_id_of(extensions: &Extensions) -> Option<RequestId> {
    extensions.get::<RequestId>().copied()
}

/// The client's id: the header value when it is a hyphenated UUID.
fn client_request_id(request: &Request) -> Option<RequestId> {
    let value = request.headers().get(X_REQUEST_ID)?.to_str().ok()?;
    RequestId::parse(value.trim()).ok()
}

/// The layer function of the request id; mount it with
/// `axum::middleware::from_fn_with_state(source, assign_request_id)`.
pub async fn assign_request_id(
    State(source): State<Arc<dyn RequestIdSource>>,
    mut request: Request,
    next: Next,
) -> Response {
    let id = client_request_id(&request).unwrap_or_else(|| source.next_id());
    request.extensions_mut().insert(id);
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&id.to_string()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(X_REQUEST_ID), value);
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

    async fn echo(request: Request) -> String {
        request_id_of(request.extensions())
            .map(|id| id.to_string())
            .unwrap_or_default()
    }

    fn app() -> Router {
        let source: Arc<dyn RequestIdSource> = Arc::new(SequentialRequestIds::new());
        Router::new()
            .route("/", get(echo))
            .layer(axum::middleware::from_fn_with_state(source, assign_request_id))
    }

    #[test]
    fn sequential_ids_are_deterministic_uuid_v7() {
        let source = SequentialRequestIds::new();
        let first = source.next_id();
        let second = source.next_id();
        assert_eq!(first.to_string(), "018f3c1e-7b2a-7c3d-9e4f-000000000001");
        assert_eq!(second.to_string(), "018f3c1e-7b2a-7c3d-9e4f-000000000002");
        assert_eq!(first.as_uuid().get_version_num(), 7);
    }

    #[tokio::test]
    async fn requests_without_an_id_get_a_fresh_one_that_is_echoed() {
        let response = app()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()[X_REQUEST_ID], "018f3c1e-7b2a-7c3d-9e4f-000000000001");
        assert_eq!(
            body_text(response).await,
            "018f3c1e-7b2a-7c3d-9e4f-000000000001",
            "the handler sees the id it echoes"
        );
    }

    async fn body_text(response: Response) -> String {
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn uuid_ids_of_clients_are_kept() {
        let id = "11111111-2222-7333-8444-555555555555";
        let request = Request::get("/")
            .header("x-request-id", id)
            .body(Body::empty())
            .unwrap();
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.headers()[X_REQUEST_ID], id);
        assert_eq!(body_text(response).await, id);
        let padded = Request::get("/")
            .header("x-request-id", format!(" {id} "))
            .body(Body::empty())
            .unwrap();
        let response = app().oneshot(padded).await.unwrap();
        assert_eq!(
            response.headers()[X_REQUEST_ID],
            id,
            "surrounding blanks are not part of the id"
        );
    }

    #[tokio::test]
    async fn other_values_are_replaced_so_free_text_never_reaches_the_logs() {
        let values: [&[u8]; 5] = [
            b"not-a-uuid",
            b"<script>",
            b"",
            b"caf\xe9",
            b"11111111-2222-7333-8444-555555555555x",
        ];
        for value in values {
            // Every value is a valid header value; `caf\xe9` is one that is not text.
            let header = HeaderValue::from_bytes(value).unwrap();
            let mut request = Request::get("/").body(Body::empty()).unwrap();
            request
                .headers_mut()
                .insert(HeaderName::from_static(X_REQUEST_ID), header);
            let response = app().oneshot(request).await.unwrap();
            assert_eq!(
                response.headers()[X_REQUEST_ID],
                "018f3c1e-7b2a-7c3d-9e4f-000000000001",
                "{value:?}"
            );
        }
    }
}
