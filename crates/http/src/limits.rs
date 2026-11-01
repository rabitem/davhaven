//! Request body and header limits and timeouts.
//!
//! The `[server.http]` table configures the connection-level protections of every listener: how long a client may
//! take to send its headers (slowloris), the largest header block, the total request time and the number of
//! requests handled concurrently. Body limits per surface come from the `[limits]` tables (PLAN 2.15); the layers
//! of this module enforce both.

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::header::CONTENT_LENGTH;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use davhaven_app::config::ConfigError;
use davhaven_wire::ProblemCode;
use http_body_util::{LengthLimitError, Limited};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::problem::EdgeProblem;

/// The `[server.http]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// How long a client may take to send the request headers; slower connections are closed.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub header_read_timeout: Duration,
    /// The largest header block in bytes; larger requests get 431.
    pub max_header_bytes: usize,
    /// How long one request may take in total; slower requests get 503.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub request_timeout: Duration,
    /// The most requests handled at the same time per listener; further requests wait or are shed.
    pub concurrency_limit: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(10),
            max_header_bytes: 16 * 1024,
            request_timeout: Duration::from_mins(1),
            concurrency_limit: 1024,
        }
    }
}

impl HttpConfig {
    /// Checks that every value is positive and the header limit is workable.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] for the first unusable key of `server.http`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.header_read_timeout.is_zero() {
            return Err(ConfigError::new(
                "server.http",
                "header_read_timeout",
                "must be greater than zero",
            ));
        }
        if self.max_header_bytes < 1024 {
            return Err(ConfigError::new(
                "server.http",
                "max_header_bytes",
                "must be at least 1024",
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(ConfigError::new(
                "server.http",
                "request_timeout",
                "must be greater than zero",
            ));
        }
        if self.request_timeout < self.header_read_timeout {
            return Err(ConfigError::new(
                "server.http",
                "request_timeout",
                "must not be shorter than header_read_timeout",
            ));
        }
        if self.concurrency_limit == 0 {
            return Err(ConfigError::new(
                "server.http",
                "concurrency_limit",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Why a request body could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BodyError {
    /// The body is larger than the limit (413).
    #[error("the request body is larger than the limit")]
    TooLarge,
    /// The connection failed or the body was malformed on the wire (400).
    #[error("the request body could not be read")]
    Unreadable,
}

impl From<BodyError> for EdgeProblem {
    fn from(error: BodyError) -> Self {
        match error {
            BodyError::TooLarge => {
                Self::new(ProblemCode::PayloadTooLarge).with_detail("The request body is larger than the limit.")
            }
            BodyError::Unreadable => {
                Self::new(ProblemCode::BadRequest).with_detail("The request body could not be read.")
            }
        }
    }
}

/// Whether an error, or anything in its chain of causes, is the length limit of the body wrapper.
fn exceeds_limit(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(candidate) = current {
        if candidate.is::<LengthLimitError>() {
            return true;
        }
        current = candidate.source();
    }
    false
}

/// Reads a request body completely and fails as soon as it exceeds `limit` bytes.
///
/// Handlers use this with the limit of their route (1 MiB for API JSON, 10 MiB for batch upserts, 256 KiB for DAV
/// XML, ...); the surface-wide ceiling of [`limit_body`] sits above it.
///
/// # Errors
///
/// [`BodyError::TooLarge`] when the body has more than `limit` bytes, [`BodyError::Unreadable`] when reading it
/// fails.
pub async fn read_body(body: Body, limit: usize) -> Result<Bytes, BodyError> {
    axum::body::to_bytes(body, limit).await.map_err(|error| {
        if exceeds_limit(&error) {
            BodyError::TooLarge
        } else {
            BodyError::Unreadable
        }
    })
}

/// The largest request body a surface accepts at all, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimit(pub usize);

/// The layer function of the body ceiling: a request that declares a larger `Content-Length` is refused with 413
/// before its body is read, and every other body is wrapped so that reading it fails once it grows past the limit
/// (chunked uploads cannot dodge the check). Mount it with
/// `axum::middleware::from_fn_with_state(BodyLimit(bytes), limit_body)`.
pub async fn limit_body(State(limit): State<BodyLimit>, request: Request, next: Next) -> Response {
    if let Some(declared) = request.headers().get(CONTENT_LENGTH) {
        let text = declared.to_str().unwrap_or_default().trim();
        match text.parse::<u64>() {
            Ok(length) if usize::try_from(length).is_ok_and(|length| length <= limit.0) => {}
            Ok(_) => return EdgeProblem::from(BodyError::TooLarge).into_response(),
            // Digits that overflow a u64 are larger than any limit; anything else is not a length at all.
            Err(_) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
                return EdgeProblem::from(BodyError::TooLarge).into_response();
            }
            Err(_) => return EdgeProblem::from(BodyError::Unreadable).into_response(),
        }
    }
    let (parts, body) = request.into_parts();
    next.run(Request::from_parts(parts, Body::new(Limited::new(body, limit.0))))
        .await
}

/// The layer function of the request timeout: a request that takes longer than `server.http.request_timeout`
/// answers 503 `unavailable`. Mount it with `axum::middleware::from_fn_with_state(timeout, enforce_timeout)`.
pub async fn enforce_timeout(State(timeout): State<Duration>, request: Request, next: Next) -> Response {
    tokio::time::timeout(timeout, next.run(request))
        .await
        .unwrap_or_else(|_| {
            EdgeProblem::new(ProblemCode::Unavailable)
                .with_detail("The request took too long to process.")
                .with_retry_after(Duration::from_secs(1))
                .into_response()
        })
}

/// The permits that bound how many requests one listener handles at the same time.
pub fn concurrency_permits(limit: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(limit.min(Semaphore::MAX_PERMITS)))
}

/// The permit of the concurrency limit that a request holds, kept in the extensions of the request.
///
/// A layer that hands the request over to a task that outlives the response (the idempotency layer of the API runs
/// its handler in a task of its own, so that the outcome of a keyed request is recorded even when the client
/// disconnects or the edge times out) clones this handle into the task. The permit is then released when the last
/// holder is done, not when the edge has answered, so detached work stays counted against the limit.
#[derive(Debug, Clone)]
pub struct HeldPermit(Arc<OwnedSemaphorePermit>);

impl HeldPermit {
    /// How many handles keep the permit (the edge itself and every task that cloned the extension).
    pub fn holders(&self) -> usize {
        Arc::strong_count(&self.0)
    }
}

/// The layer function of the concurrency limit: when every permit is taken the request is shed at once with 503
/// `unavailable` and `Retry-After: 1` instead of queueing without bound. The permit travels with the request as a
/// [`HeldPermit`] extension. Mount it with `axum::middleware::from_fn_with_state(concurrency_permits(n), shed_load)`.
pub async fn shed_load(State(permits): State<Arc<Semaphore>>, mut request: Request, next: Next) -> Response {
    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
        return EdgeProblem::new(ProblemCode::Unavailable)
            .with_detail("The server is busy; try again shortly.")
            .with_retry_after(Duration::from_secs(1))
            .into_response();
    };
    let held = HeldPermit(Arc::new(permit));
    request.extensions_mut().insert(held.clone());
    let response = next.run(request).await;
    drop(held);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_plan_values() {
        let config = HttpConfig::default();
        assert_eq!(config.header_read_timeout, Duration::from_secs(10));
        assert_eq!(config.max_header_bytes, 16_384);
        assert_eq!(config.request_timeout, Duration::from_mins(1));
        config.validate().unwrap();
        let parsed: HttpConfig = serde_json::from_str(r#"{"request_timeout": "2m", "concurrency_limit": 10}"#).unwrap();
        assert_eq!(parsed.request_timeout, Duration::from_mins(2));
        assert_eq!(parsed.concurrency_limit, 10);
        assert_eq!(parsed.max_header_bytes, 16_384);
        assert!(serde_json::from_str::<HttpConfig>(r#"{"timeout": "1s"}"#).is_err());
    }

    #[test]
    fn validation_names_the_key() {
        let cases = [
            (
                HttpConfig {
                    header_read_timeout: Duration::ZERO,
                    ..HttpConfig::default()
                },
                "header_read_timeout",
            ),
            (
                HttpConfig {
                    max_header_bytes: 10,
                    ..HttpConfig::default()
                },
                "max_header_bytes",
            ),
            (
                HttpConfig {
                    request_timeout: Duration::from_secs(5),
                    ..HttpConfig::default()
                },
                "request_timeout",
            ),
            (
                HttpConfig {
                    request_timeout: Duration::ZERO,
                    ..HttpConfig::default()
                },
                "request_timeout",
            ),
            (
                HttpConfig {
                    max_header_bytes: 1023,
                    ..HttpConfig::default()
                },
                "max_header_bytes",
            ),
            (
                HttpConfig {
                    concurrency_limit: 0,
                    ..HttpConfig::default()
                },
                "concurrency_limit",
            ),
        ];
        for (config, key) in cases {
            let error = config.validate().unwrap_err();
            assert_eq!(error.key(), key);
            assert_eq!(error.section(), "server.http");
        }
        // The boundaries themselves are usable.
        HttpConfig {
            max_header_bytes: 1024,
            request_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(10),
            concurrency_limit: 1,
        }
        .validate()
        .unwrap();
    }

    mod layers {
        use axum::Router;
        use axum::http::StatusCode;
        use axum::http::header::RETRY_AFTER;
        use axum::routing::{get, post};
        use http_body_util::BodyExt as _;
        use tokio::sync::Notify;
        use tower::ServiceExt as _;

        use super::*;
        use crate::problem::{JsonProblems, ProblemRenderer, render_problems};

        fn rendered(router: Router) -> Router {
            let renderer: Arc<dyn ProblemRenderer> = Arc::new(JsonProblems::catalog());
            router.layer(axum::middleware::from_fn_with_state(renderer, render_problems))
        }

        async fn code_of(response: Response) -> String {
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"]
                .as_str()
                .unwrap()
                .to_owned()
        }

        async fn read_all(body: Body) -> Result<usize, BodyError> {
            read_body(body, usize::MAX).await.map(|bytes| bytes.len())
        }

        #[tokio::test]
        async fn bodies_are_read_up_to_the_limit() {
            assert_eq!(read_body(Body::from("12345"), 5).await.unwrap().len(), 5);
            assert_eq!(
                read_body(Body::from("123456"), 5).await.unwrap_err(),
                BodyError::TooLarge
            );
            assert_eq!(read_body(Body::empty(), 0).await.unwrap().len(), 0);
            let problem = EdgeProblem::from(BodyError::TooLarge);
            assert_eq!(problem.code(), ProblemCode::PayloadTooLarge);
            assert_eq!(EdgeProblem::from(BodyError::Unreadable).code(), ProblemCode::BadRequest);
        }

        fn body_limited() -> Router {
            let router = Router::new()
                .route(
                    "/",
                    post(|body: Body| async move { format!("{:?}", read_all(body).await) }),
                )
                .layer(axum::middleware::from_fn_with_state(BodyLimit(8), limit_body));
            rendered(router)
        }

        #[tokio::test]
        async fn a_declared_length_over_the_ceiling_is_refused_before_reading() {
            let request = Request::post("/")
                .header("content-length", "9")
                .body(Body::from("123456789"))
                .unwrap();
            let response = body_limited().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(code_of(response).await, "payload-too-large");
            let overflow = Request::post("/")
                .header("content-length", "99999999999999999999999")
                .body(Body::empty())
                .unwrap();
            let response = body_limited().oneshot(overflow).await.unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            let garbage = Request::post("/")
                .header("content-length", "lots")
                .body(Body::empty())
                .unwrap();
            let response = body_limited().oneshot(garbage).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let exact = Request::post("/")
                .header("content-length", "8")
                .body(Body::from("12345678"))
                .unwrap();
            assert_eq!(body_limited().oneshot(exact).await.unwrap().status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn undeclared_bodies_fail_while_being_read_once_they_grow_past_the_ceiling() {
            let small = Request::post("/").body(Body::from("12345678")).unwrap();
            let response = body_limited().oneshot(small).await.unwrap();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&bytes[..], b"Ok(8)");
            let large = Request::post("/").body(Body::from("123456789")).unwrap();
            let response = body_limited().oneshot(large).await.unwrap();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&bytes[..], b"Err(TooLarge)");
        }

        #[tokio::test(start_paused = true)]
        async fn slow_requests_answer_503_with_a_retry_hint() {
            let router = Router::new()
                .route("/", get(std::future::pending::<&'static str>))
                .layer(axum::middleware::from_fn_with_state(
                    Duration::from_secs(60),
                    enforce_timeout,
                ));
            let response = rendered(router)
                .oneshot(Request::get("/").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[RETRY_AFTER], "1");
            assert_eq!(code_of(response).await, "unavailable");
        }

        #[tokio::test]
        async fn requests_beyond_the_concurrency_limit_are_shed() {
            let gate = Arc::new(Notify::new());
            let handler_gate = Arc::clone(&gate);
            let router = Router::new()
                .route(
                    "/",
                    get(move || {
                        let gate = Arc::clone(&handler_gate);
                        async move {
                            gate.notified().await;
                            "done"
                        }
                    }),
                )
                .layer(axum::middleware::from_fn_with_state(concurrency_permits(1), shed_load));
            let app = rendered(router);
            let first = tokio::spawn(app.clone().oneshot(Request::get("/").body(Body::empty()).unwrap()));
            tokio::task::yield_now().await;
            let shed = app
                .clone()
                .oneshot(Request::get("/").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(shed.headers()[RETRY_AFTER], "1");
            gate.notify_one();
            let done = first.await.unwrap().unwrap();
            assert_eq!(done.status(), StatusCode::OK);
            gate.notify_one();
            let again = tokio::spawn(app.oneshot(Request::get("/").body(Body::empty()).unwrap()));
            tokio::task::yield_now().await;
            gate.notify_one();
            assert_eq!(again.await.unwrap().unwrap().status(), StatusCode::OK);
        }

        #[test]
        fn huge_limits_do_not_overflow_the_semaphore() {
            assert_eq!(
                concurrency_permits(usize::MAX).available_permits(),
                Semaphore::MAX_PERMITS
            );
            assert_eq!(concurrency_permits(3).available_permits(), 3);
        }
    }
}
