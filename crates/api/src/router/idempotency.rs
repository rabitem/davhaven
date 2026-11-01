//! Idempotency of `POST` requests (PLAN 2.10).
//!
//! A client that is unsure whether a `POST` arrived repeats it with the same `Idempotency-Key`. The layer of this
//! module makes that safe. It sits inside the authentication layer (the scope of a key is the tenant, the token
//! and the key) and outside the handlers, and works for every `POST` of the API that carries the header (the
//! OpenAPI document declares the header on every `POST`):
//!
//! 1. The body is read with the limit of the route (1 MiB, 10 MiB for the batch upsert: a request that is too large
//!    is refused with 413 **before** a key is reserved) and hashed together with the method, the path, the query and
//!    the content type: the *fingerprint* of the request. Two requests with the same key must have the same
//!    fingerprint, otherwise the key was reused for another request.
//! 2. `IdempotencyService::reserve` decides what the key means: a **fresh** key is claimed for a *lease* (the request
//!    timeout of the server plus a margin) and the request proceeds; a key whose request **completed** answers with
//!    the stored response and `Idempotent-Replayed: true`; a key whose request is **in flight** answers 409
//!    `idempotency-in-progress`; a key used for **another request** answers 422 `idempotency-key-reuse`; a key whose
//!    response was **not kept** (it contained a secret, or could not be stored) answers 409 `secret-not-replayable`
//!    with the status and the `Location` of the first answer, so that the client can find what that attempt created.
//! 3. The handler runs in its own task, so that a client that disconnects does not cancel it half way: the work
//!    finishes and its outcome is recorded either way. The task is **bounded**: it gets the request timeout of the
//!    server, no more, so the work cannot outlive its claim (a retry after the lease would otherwise run the request
//!    a second time while the first is still working); when the time is up the handler is cancelled and the key
//!    released. The task also holds the concurrency permit of the edge, so detached work stays counted against the
//!    concurrency limit instead of escaping it when the edge has already answered.
//! 4. The outcome is recorded with the reservation, so a late settlement of an attempt that lost its claim cannot
//!    settle or release the claim of the attempt that replaced it (when the service is backed by the fenced
//!    operations of the store). A successful response is stored for replay (status, `Content-Type`, `Location`, `ETag`
//!    and the JSON body) **only when its handler marked it replayable**: the default is that nothing is kept, so a
//!    handler that forgot to think about it can never leave a secret in the idempotency table. A response marked
//!    `Cache-Control: no-store` is never stored either. Both cases, and a success that cannot be stored (too large,
//!    not JSON), are recorded as "used, not replayable" and the client still receives the original response. Every
//!    other outcome (an error answer, a timeout, a panic) releases the key, so a retry starts afresh and can
//!    succeed.
//!
//! `PUT`, `PATCH` and `DELETE` are idempotent by definition and ignore the header. On a `POST` a malformed header is
//! a 400. Requests without the header and requests of other methods pass through untouched. A keyed `POST` that
//! arrives without an authenticated context is a mounting bug (the layer belongs inside authentication) and is
//! refused with 500 instead of being run without protection. When the idempotency service fails, the request is
//! refused (503, or 501 for an operation that is not implemented) rather than executed without protection: silently
//! ignoring the header would duplicate side effects on the retry that the client sent the key for.
//!
//! A replay is the first response again, not a second execution: the same status, `Content-Type`, `Location`,
//! `ETag` and JSON document (equal in content; the member order of the stored document is the canonical one), marked
//! with `Idempotent-Replayed: true`.

use core::fmt::Write as _;
use std::time::Duration;

use axum::body::{Body, HttpBody as _};
use axum::extract::{MatchedPath, OriginalUri, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, LOCATION};
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use davhaven_app::AppServices;
use davhaven_app::services::{IdempotencyKey, Reservation, Reserved, ResponseNote, Settlement, StoredResponse};
use davhaven_domain::{ErrorKind, RequestContext};
use davhaven_http::EdgeProblem;
use davhaven_http::limits::{HeldPermit, read_body};
use davhaven_wire::ProblemCode;
use sha2::{Digest, Sha256};
use tracing::Instrument as _;

use crate::extract::idempotency_key_from;
use crate::reply::Replayable;
use crate::router::{API_PREFIX, ApiState};

/// The header that marks a replayed response.
pub(super) const REPLAYED: &str = "idempotent-replayed";

/// The response headers that are stored and replayed.
const REPLAYED_HEADERS: [HeaderName; 3] = [CONTENT_TYPE, LOCATION, ETAG];

/// How long a key stays claimed beyond the request timeout: the time to record the outcome of a request that used all
/// of its time, plus slack for the clocks of the servers that share a database.
pub(super) const LEASE_MARGIN: Duration = Duration::from_secs(30);

/// What the layer needs: the services and the request timeout of the edge it is mounted in.
#[derive(Clone)]
pub(super) struct Idempotency {
    pub(super) state: ApiState,
    /// `server.http.request_timeout`: how long a request may take, which is also how long its handler may work.
    pub(super) request_timeout: Duration,
}

impl Idempotency {
    /// How long a fresh key is claimed: the request timeout plus [`LEASE_MARGIN`].
    fn lease(&self) -> Duration {
        self.request_timeout.saturating_add(LEASE_MARGIN)
    }
}

/// The route template of a request, relative to the API prefix (`/tenants/{tenant}/principals`).
fn route_of(request: &Request) -> String {
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| request.uri().path(), MatchedPath::as_str);
    matched.strip_prefix(API_PREFIX).unwrap_or(matched).to_owned()
}

/// The largest body the route accepts: the batch limit for the batch upsert, the JSON limit for every other route.
/// The layer reads with the limit the handler would, so a request the handler must refuse with 413 is refused before
/// a key is reserved for it.
fn body_limit(state: &ApiState, route: &str) -> usize {
    let limits = &state.services.limits.api;
    let is_batch = crate::openapi::ROUTES
        .iter()
        .any(|spec| spec.operation_id == "batchObjects" && spec.path == route);
    let bytes = if is_batch {
        limits.max_batch_body
    } else {
        limits.max_json_body
    };
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// The fingerprint of a request: a SHA-256 over method, path, query, content type and body, as lowercase hex.
///
/// The fields are separated by zero bytes and the body is length-prefixed, so no two requests share an encoding.
fn fingerprint(parts: &Parts, body: &[u8]) -> String {
    let original = parts
        .extensions
        .get::<OriginalUri>()
        .map_or(&parts.uri, |original| &original.0);
    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    for field in [
        parts.method.as_str(),
        original.path(),
        original.query().unwrap_or_default(),
        content_type,
    ] {
        hasher.update(field.as_bytes());
        hasher.update([0]);
    }
    hasher.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(body);
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        // Writing to a `String` cannot fail.
        let _written = write!(hex, "{byte:02x}");
    }
    hex
}

/// The stored response as a response of this request, marked as a replay.
fn replayed(stored: &StoredResponse) -> Response {
    let body = if stored.body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&stored.body).unwrap_or_default()
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
    for (name, value) in &stored.headers {
        let name = HeaderName::try_from(name.as_str());
        let value = HeaderValue::from_str(value);
        if let (Ok(name), Ok(value)) = (name, value)
            && REPLAYED_HEADERS.contains(&name)
        {
            response.headers_mut().append(name, value);
        }
    }
    response
        .headers_mut()
        .insert(HeaderName::from_static(REPLAYED), HeaderValue::from_static("true"));
    response
}

/// The answer to a retry of a request whose response was not kept: 409 `secret-not-replayable`, with what the first
/// answer said that is free of secrets, so that the client can find, read or revoke what the first attempt created.
fn not_replayable(note: Option<&ResponseNote>) -> Response {
    let mut problem = EdgeProblem::new(ProblemCode::SecretNotReplayable);
    if let Some(note) = note {
        problem = problem.with_detail(format!(
            "The first request was answered {} and took effect; its response is not kept because it contains a \
             secret, which is shown once. Do not repeat the request: find the result{}.",
            note.status,
            if note.location.is_some() {
                " at the Location header"
            } else {
                " through the resource the request was about"
            }
        ));
        if let Some(location) = &note.location {
            problem = problem.with_location(location.clone());
        }
    }
    problem.into_response()
}

/// The refusal for a failure of the idempotency service: 503 for a dependency that fails, 501 for an operation that
/// is not implemented. The request is not run.
fn unavailable(error: &davhaven_app::AppError) -> Response {
    if error.kind() == ErrorKind::Unsupported {
        return EdgeProblem::from_app_error(error).into_response();
    }
    tracing::warn!(
        target: "davhaven::api",
        error = %error,
        "the idempotency bookkeeping failed; the request was refused instead of being run unprotected"
    );
    EdgeProblem::new(ProblemCode::Unavailable)
        .with_detail("The request could not be made repeatable right now; try again shortly.")
        .with_retry_after(Duration::from_secs(1))
        .into_response()
}

/// Whether a response must not be stored: it is marked `no-store`, which the API does for secrets, feed URLs and
/// client profiles.
fn carries_a_secret(parts: &axum::http::response::Parts) -> bool {
    parts
        .headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.to_ascii_lowercase().contains("no-store"))
}

/// What to remember of a response, or `None` when the response cannot be stored as JSON.
fn storable(parts: &axum::http::response::Parts, body: &[u8]) -> Option<StoredResponse> {
    let value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        let is_json = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"));
        if !is_json {
            return None;
        }
        serde_json::from_slice(body).ok()?
    };
    let headers = REPLAYED_HEADERS
        .iter()
        .filter_map(|name| {
            let value = parts.headers.get(name)?.to_str().ok()?;
            Some((name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    Some(StoredResponse {
        status: parts.status.as_u16(),
        headers,
        body: value,
    })
}

/// The non-secret facts of a response: its status and its `Location`.
fn note_of(parts: &axum::http::response::Parts) -> ResponseNote {
    ResponseNote {
        status: parts.status.as_u16(),
        location: parts
            .headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    }
}

/// Everything the task of one keyed request needs besides the request itself.
struct Job {
    services: AppServices,
    ctx: RequestContext,
    key: IdempotencyKey,
    reservation: Reservation,
    /// How long the handler may work.
    budget: Duration,
    /// The largest response that is buffered to be stored.
    store_limit: usize,
    /// The concurrency permit of the edge, kept until the work ends.
    permit: Option<HeldPermit>,
}

/// Records how a request ended. A failure to record is logged and never changes the response: the work is done and
/// the client must hear about it.
async fn settle(
    services: &AppServices,
    ctx: &RequestContext,
    key: &IdempotencyKey,
    reservation: &Reservation,
    settlement: Settlement,
) {
    if let Err(error) = services.idempotency.settle(ctx, key, reservation, settlement).await {
        tracing::warn!(
            target: "davhaven::api",
            error = %error,
            "recording the outcome of an idempotent request failed"
        );
    }
}

/// Runs the rest of the stack, bounded by the request timeout, and records the outcome; the whole function runs in
/// its own task.
async fn run_and_settle(job: Job, request: Request, next: Next) -> Response {
    let Job {
        services,
        ctx,
        key,
        reservation,
        budget,
        store_limit,
        permit,
    } = job;
    // Held until this function returns, however the edge answered the client in the meantime.
    let _permit = permit;
    let Ok(response) = tokio::time::timeout(budget, next.run(request)).await else {
        // The work took the whole time the request is allowed. It is cancelled and the key released, so that a retry
        // starts afresh and cannot run beside the first attempt.
        settle(&services, &ctx, &key, &reservation, Settlement::Abandon).await;
        return EdgeProblem::new(ProblemCode::Unavailable)
            .with_detail("The request took too long to process.")
            .with_retry_after(Duration::from_secs(1))
            .into_response();
    };
    if !response.status().is_success() {
        settle(&services, &ctx, &key, &reservation, Settlement::Abandon).await;
        return response;
    }
    let replayable = response.extensions().get::<Replayable>().is_some();
    let (parts, body) = response.into_parts();
    let note = note_of(&parts);
    if carries_a_secret(&parts) {
        settle(&services, &ctx, &key, &reservation, Settlement::Secret(note)).await;
        return Response::from_parts(parts, body);
    }
    let limit = u64::try_from(store_limit).unwrap_or(u64::MAX);
    let fits = body.size_hint().upper().is_some_and(|upper| upper <= limit);
    if !replayable || !fits {
        // Not marked replayable (the safe default), or too large or of unknown size to be buffered: the response is
        // not stored, and the client still gets exactly what the handler produced.
        settle(&services, &ctx, &key, &reservation, Settlement::Unstorable(note)).await;
        return Response::from_parts(parts, body);
    }
    let Ok(bytes) = axum::body::to_bytes(body, store_limit).await else {
        // The body failed while it was read: nothing reached the client, so the request may be repeated.
        settle(&services, &ctx, &key, &reservation, Settlement::Abandon).await;
        return EdgeProblem::new(ProblemCode::Internal).into_response();
    };
    let settlement = storable(&parts, &bytes).map_or(Settlement::Unstorable(note), Settlement::Response);
    settle(&services, &ctx, &key, &reservation, settlement).await;
    Response::from_parts(parts, Body::from(bytes))
}

/// The layer function; mount it with `from_fn_with_state(Idempotency { .. }, replay)` inside the authentication layer.
pub(super) async fn replay(State(layer): State<Idempotency>, request: Request, next: Next) -> Response {
    if request.method() != Method::POST {
        return next.run(request).await;
    }
    let key = match idempotency_key_from(request.headers()) {
        Ok(Some(key)) => key,
        Ok(None) => return next.run(request).await,
        Err(problem) => return problem.into_response(),
    };
    let Some(ctx) = request.extensions().get::<RequestContext>().cloned() else {
        tracing::error!(
            target: "davhaven::api",
            "a keyed POST reached the idempotency layer without an authenticated context: the layer is mounted outside authentication"
        );
        return EdgeProblem::new(ProblemCode::Internal).into_response();
    };
    let route = route_of(&request);
    let limit = body_limit(&layer.state, &route);
    let permit = request.extensions().get::<HeldPermit>().cloned();
    let (parts, body) = request.into_parts();
    let bytes = match read_body(body, limit).await {
        Ok(bytes) => bytes,
        Err(error) => return EdgeProblem::from(error).into_response(),
    };
    let key = IdempotencyKey {
        key,
        method: parts.method.as_str().to_owned(),
        route,
    };
    let fingerprint = fingerprint(&parts, &bytes);
    let reserved = layer
        .state
        .services
        .idempotency
        .reserve(&ctx, key.clone(), fingerprint, layer.lease())
        .await;
    let reservation = match reserved {
        Err(error) => return unavailable(&error),
        Ok(Reserved::Replay(stored)) => return replayed(&stored),
        Ok(Reserved::InProgress) => return EdgeProblem::new(ProblemCode::IdempotencyInProgress).into_response(),
        Ok(Reserved::KeyReuse) => return EdgeProblem::new(ProblemCode::IdempotencyKeyReuse).into_response(),
        Ok(Reserved::NotReplayable(note)) => return not_replayable(note.as_ref()),
        Ok(Reserved::Fresh(reservation)) => reservation,
    };
    let services = layer.state.services.clone();
    let job = Job {
        services: services.clone(),
        ctx: ctx.clone(),
        key: key.clone(),
        reservation,
        budget: layer.request_timeout,
        store_limit: limit,
        permit,
    };
    let request = Request::from_parts(parts, Body::from(bytes));
    let task = tokio::spawn(run_and_settle(job, request, next).in_current_span());
    let Ok(response) = task.await else {
        // The handler panicked or the runtime is shutting down: nothing was recorded, so release the key.
        settle(&services, &ctx, &key, &reservation, Settlement::Abandon).await;
        return EdgeProblem::new(ProblemCode::Internal).into_response();
    };
    response
}

#[cfg(test)]
mod tests;
