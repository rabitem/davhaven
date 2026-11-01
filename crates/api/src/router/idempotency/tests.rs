//! Tests of the idempotency layer on a small router with handlers that count their runs, wait on a gate, carry
//! secrets, fail, panic and never finish, in front of the in-memory service of `tests/support`. Time is paused where a
//! test needs a lease or a request timeout to run out.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::extract::State as RouterState;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, LOCATION, RETRY_AFTER};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::routing::{get, post};
use davhaven_app::services::IdempotencyService as _;
use davhaven_app_fake::AppServicesExt as _;
use davhaven_domain::{Actor, Channel, RequestId, ScopeSet, TenantId, TokenId};
use davhaven_http::limits::{concurrency_permits, enforce_timeout, shed_load};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tokio::sync::Notify;
use tower::ServiceExt as _;
use uuid::Uuid;

use super::*;
use crate::reply::Reply as ApiReply;

#[path = "../../../tests/support/mod.rs"]
mod support;

use support::MemoryIdempotency;

/// The request timeout of the harness; the lease is this plus [`LEASE_MARGIN`].
const TIMEOUT: Duration = Duration::from_secs(10);

/// The real batch route, so that the layer finds the larger limit of the batch upsert.
const BATCH_ROUTE: &str = "/api/v1/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/batch";

/// The handlers' shared state: counters and gates.
#[derive(Default)]
struct Probe {
    runs: AtomicUsize,
    active: AtomicUsize,
    most_active: AtomicUsize,
    started: Notify,
    gate: Notify,
}

type Shared = Arc<Probe>;

impl Probe {
    /// A run begins: counts it and how many run at the same time.
    fn begin(&self) -> usize {
        let n = self.runs.fetch_add(1, Ordering::SeqCst) + 1;
        let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.most_active.fetch_max(now, Ordering::SeqCst);
        n
    }
}

/// Ends a run when the handler returns or is dropped (cancelled).
struct Running(Shared);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn running(probe: &Shared) -> (usize, Running) {
    let n = probe.begin();
    (n, Running(Arc::clone(probe)))
}

/// A reply that its handler allows to be replayed.
fn replayable(status: StatusCode, body: &Value) -> ApiReply {
    ApiReply::json(status, body).replayable()
}

async fn ok(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (n, _run) = running(&probe);
    replayable(StatusCode::CREATED, &json!({"n": n}))
        .with_header(ETAG, "\"v1\"")
        .with_header(LOCATION, "https://cal.example.org/api/v1/things/1")
}

/// A secret: `no-store`, not marked replayable, with the `Location` of what it created.
async fn secret(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (n, _run) = running(&probe);
    ApiReply::json(StatusCode::CREATED, &json!({"n": n, "secret": "shown once"}))
        .no_store()
        .with_header(LOCATION, "/api/v1/things/7")
}

/// A handler that forgot to think about replay: a success that is neither marked replayable nor `no-store`.
async fn forgot(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (n, _run) = running(&probe);
    ApiReply::json(StatusCode::OK, &json!({"n": n, "secret": "would be leaked"}))
}

/// A contradiction: marked replayable and `no-store`. The secret wins.
async fn both(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (n, _run) = running(&probe);
    replayable(StatusCode::OK, &json!({"n": n, "secret": "never stored"})).no_store()
}

async fn fail(RouterState(probe): RouterState<Shared>) -> EdgeProblem {
    let (_n, _run) = running(&probe);
    EdgeProblem::new(ProblemCode::ValidationFailed)
}

async fn slow(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (n, _run) = running(&probe);
    probe.started.notify_one();
    probe.gate.notified().await;
    replayable(StatusCode::OK, &json!({"n": n}))
}

/// The first run never finishes; later runs answer at once.
async fn hangs_once(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (n, _run) = running(&probe);
    if n == 1 {
        std::future::pending::<()>().await;
    }
    replayable(StatusCode::OK, &json!({"n": n}))
}

async fn forever(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (_n, _run) = running(&probe);
    std::future::pending::<ApiReply>().await
}

async fn boom(RouterState(probe): RouterState<Shared>) -> &'static str {
    let (_n, _run) = running(&probe);
    panic!("a handler bug");
}

async fn empty(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (_n, _run) = running(&probe);
    ApiReply::no_content().replayable()
}

/// A success larger than any limit of the tests, marked replayable: it cannot be stored.
async fn big(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (n, _run) = running(&probe);
    replayable(StatusCode::OK, &json!({"n": n, "padding": "x".repeat(4096)}))
}

/// A success that is not a JSON document, marked replayable.
async fn text(RouterState(probe): RouterState<Shared>) -> impl IntoResponse {
    let (_n, _run) = running(&probe);
    let mut response = (StatusCode::OK, "plain text").into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response.extensions_mut().insert(Replayable);
    response
}

async fn read(RouterState(probe): RouterState<Shared>) -> ApiReply {
    let (n, _run) = running(&probe);
    ApiReply::json(StatusCode::OK, &json!({"n": n}))
}

/// A number from a test header, or `default`.
fn number(headers: &HeaderMap, name: &str, default: u128) -> u128 {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// What the authentication layer would have put into the request: the tenant and token named by the test headers.
async fn authenticated(mut request: Request, next: Next) -> Response {
    if request.headers().get("x-anonymous").is_none() {
        let context = RequestContext {
            tenant: TenantId::from_uuid(Uuid::from_u128(number(request.headers(), "x-tenant", 1))),
            actor: Actor::TenantToken(TokenId::from_uuid(Uuid::from_u128(number(
                request.headers(),
                "x-token",
                1,
            )))),
            scopes: ScopeSet::empty(),
            channel: Channel::Api,
            credential: None,
            request_id: RequestId::from_uuid(Uuid::nil()),
            locale: None,
            client_ip: None,
        };
        request.extensions_mut().insert(context);
    }
    next.run(request).await
}

struct Harness {
    app: Router,
    store: Arc<MemoryIdempotency>,
    probe: Shared,
}

fn routes() -> Router<Shared> {
    Router::new()
        .route("/ok", post(ok))
        .route("/secret", post(secret))
        .route("/forgot", post(forgot))
        .route("/both", post(both))
        .route("/fail", post(fail))
        .route("/slow", post(slow))
        .route("/hangs-once", post(hangs_once))
        .route("/forever", post(forever))
        .route("/boom", post(boom))
        .route("/empty", post(empty))
        .route("/big", post(big))
        .route("/text", post(text))
        .route("/read", get(read).post(read))
        .route(BATCH_ROUTE, post(ok))
}

/// A harness whose body limits are `json` and `batch` bytes (the defaults when `None`).
fn harness_with(limits: Option<(u64, u64)>, timeout: Duration) -> Harness {
    let store = Arc::new(MemoryIdempotency::default());
    let probe = Shared::default();
    let mut services = davhaven_app::AppServices::fake();
    services.idempotency = Arc::<MemoryIdempotency>::clone(&store);
    if let Some((json, batch)) = limits {
        services.limits.api.max_json_body = json;
        services.limits.api.max_batch_body = batch;
    }
    let layer = Idempotency {
        state: ApiState { services },
        request_timeout: timeout,
    };
    let app = routes()
        .route_layer(from_fn_with_state(layer, replay))
        .layer(from_fn(authenticated))
        .with_state(Arc::clone(&probe));
    Harness { app, store, probe }
}

fn harness() -> Harness {
    harness_with(None, TIMEOUT)
}

#[derive(Debug)]
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
    problem: Option<EdgeProblem>,
}

impl Answer {
    fn replayed(&self) -> bool {
        self.headers.get(REPLAYED).is_some_and(|value| value == "true")
    }

    fn code(&self) -> Option<ProblemCode> {
        self.problem.as_ref().map(EdgeProblem::code)
    }
}

async fn send(app: &Router, method: &str, uri: &str, key: Option<&str>, body: &str, extra: &[(&str, &str)]) -> Answer {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let problem = response.extensions().get::<EdgeProblem>().cloned();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        problem,
    }
}

async fn post_ok(harness: &Harness, key: Option<&str>, body: &str) -> Answer {
    send(&harness.app, "POST", "/ok", key, body, &[]).await
}

fn runs(harness: &Harness) -> usize {
    harness.probe.runs.load(Ordering::SeqCst)
}

#[tokio::test]
async fn a_repeated_request_replays_the_first_response_and_runs_once() {
    let harness = harness();
    let first = post_ok(&harness, Some("key-1"), r#"{"a":1}"#).await;
    assert_eq!(first.status, StatusCode::CREATED);
    assert_eq!(first.body, json!({"n": 1}));
    assert!(!first.replayed());

    let second = post_ok(&harness, Some("key-1"), r#"{"a":1}"#).await;
    assert_eq!(second.status, StatusCode::CREATED);
    assert_eq!(second.body, json!({"n": 1}), "the stored body, not a second run");
    assert!(second.replayed());
    assert_eq!(second.headers[ETAG], "\"v1\"");
    assert_eq!(second.headers[LOCATION], "https://cal.example.org/api/v1/things/1");
    assert_eq!(second.headers["content-type"], "application/json");
    assert_eq!(runs(&harness), 1);
    assert_eq!(harness.store.reserves.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_response_without_a_body_is_replayed_without_one() {
    let harness = harness();
    let first = send(&harness.app, "POST", "/empty", Some("k"), "{}", &[]).await;
    let second = send(&harness.app, "POST", "/empty", Some("k"), "{}", &[]).await;
    assert_eq!(
        (first.status, second.status),
        (StatusCode::NO_CONTENT, StatusCode::NO_CONTENT)
    );
    assert!(second.replayed() && second.body.is_null());
    assert_eq!(runs(&harness), 1);
}

#[tokio::test]
async fn a_key_for_another_request_is_refused_as_reuse() {
    let harness = harness();
    post_ok(&harness, Some("key-1"), r#"{"a":1}"#).await;
    for (what, reply) in [
        ("another body", post_ok(&harness, Some("key-1"), r#"{"a":2}"#).await),
        (
            "another path",
            send(&harness.app, "POST", "/secret", Some("key-1"), r#"{"a":1}"#, &[]).await,
        ),
        (
            "another query",
            send(&harness.app, "POST", "/ok?x=1", Some("key-1"), r#"{"a":1}"#, &[]).await,
        ),
    ] {
        assert_eq!(reply.code(), Some(ProblemCode::IdempotencyKeyReuse), "{what}");
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{what}");
    }
    assert_eq!(runs(&harness), 1, "nothing ran for a reused key");
}

#[tokio::test]
async fn the_service_receives_the_authenticated_context_of_the_request() {
    // The scope of a key is (tenant, token, key); the service applies it, and the layer is responsible for handing it
    // the context that authentication established, for both the reservation and the settlement.
    let harness = harness();
    let answer = send(
        &harness.app,
        "POST",
        "/ok",
        Some("shared"),
        "{}",
        &[("x-tenant", "3"), ("x-token", "7")],
    )
    .await;
    assert_eq!(answer.status, StatusCode::CREATED);
    let contexts = harness.store.contexts().await;
    assert_eq!(contexts.len(), 2, "one reservation and one settlement");
    for context in contexts {
        assert_eq!(context.tenant, TenantId::from_uuid(Uuid::from_u128(3)));
        assert_eq!(
            context.actor,
            Actor::TenantToken(TokenId::from_uuid(Uuid::from_u128(7)))
        );
    }
    // The same key under another token or tenant is another key of the double, which scopes as the service does.
    let other_token = send(&harness.app, "POST", "/ok", Some("shared"), "{}", &[("x-token", "2")]).await;
    let other_tenant = send(&harness.app, "POST", "/ok", Some("shared"), "{}", &[("x-tenant", "2")]).await;
    assert!(!other_token.replayed() && !other_tenant.replayed());
    assert_eq!(harness.store.len().await, 3);
}

#[tokio::test]
async fn responses_with_secrets_are_not_stored_and_a_retry_learns_where_the_first_one_went() {
    let harness = harness();
    let first = send(&harness.app, "POST", "/secret", Some("s"), "{}", &[]).await;
    assert_eq!(first.status, StatusCode::CREATED);
    assert_eq!(first.body["secret"], "shown once");
    assert_eq!(first.headers[CACHE_CONTROL], "no-store");

    let again = send(&harness.app, "POST", "/secret", Some("s"), "{}", &[]).await;
    assert_eq!(again.code(), Some(ProblemCode::SecretNotReplayable));
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert!(!again.body.to_string().contains("shown once"));
    let problem = again.problem.unwrap();
    assert_eq!(
        problem.location(),
        Some("/api/v1/things/7"),
        "the retry is told where the first attempt put what it created"
    );
    assert!(problem.detail().unwrap().contains("201"), "{:?}", problem.detail());
    assert_eq!(runs(&harness), 1, "the secret was not minted twice");
    assert!(!harness.store.has_stored_response("s").await);
}

#[tokio::test]
async fn a_handler_that_forgot_to_mark_its_response_replayable_cannot_leak_it() {
    // Fail closed: nothing is stored unless the handler says so, so a secret in a response that is not `no-store`
    // never reaches the idempotency table.
    let harness = harness();
    let first = send(&harness.app, "POST", "/forgot", Some("f"), "{}", &[]).await;
    assert_eq!(
        (first.status, first.body["secret"].clone()),
        (StatusCode::OK, json!("would be leaked"))
    );
    assert!(!harness.store.has_stored_response("f").await, "nothing was stored");
    let again = send(&harness.app, "POST", "/forgot", Some("f"), "{}", &[]).await;
    assert_eq!(again.code(), Some(ProblemCode::SecretNotReplayable));
    assert!(!again.body.to_string().contains("would be leaked"));
    assert_eq!(runs(&harness), 1);
}

#[tokio::test]
async fn no_store_wins_over_a_replayable_mark() {
    let harness = harness();
    let first = send(&harness.app, "POST", "/both", Some("b"), "{}", &[]).await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(!harness.store.has_stored_response("b").await);
    let again = send(&harness.app, "POST", "/both", Some("b"), "{}", &[]).await;
    assert_eq!(again.code(), Some(ProblemCode::SecretNotReplayable));
}

#[tokio::test]
async fn a_success_that_cannot_be_stored_is_still_delivered_and_the_key_is_marked_used() {
    // Too large to keep (the limits of the harness are small) or not a JSON document: the client gets the original
    // response, not a 500, and a retry is told that the response is not kept instead of running the work again.
    let harness = harness_with(Some((64, 128)), TIMEOUT);
    let large = send(&harness.app, "POST", "/big", Some("big"), "{}", &[]).await;
    assert_eq!(large.status, StatusCode::OK);
    assert_eq!(
        large.body["padding"].as_str().map(str::len),
        Some(4096),
        "the whole response"
    );
    let text_reply = send(&harness.app, "POST", "/text", Some("text"), "{}", &[]).await;
    assert_eq!(text_reply.status, StatusCode::OK);
    for key in ["big", "text"] {
        let path = format!("/{key}");
        let again = send(&harness.app, "POST", &path, Some(key), "{}", &[]).await;
        assert_eq!(again.code(), Some(ProblemCode::SecretNotReplayable), "{key}");
        assert!(!harness.store.has_stored_response(key).await, "{key}");
    }
    assert_eq!(runs(&harness), 2, "each ran once");
}

#[tokio::test]
async fn failures_release_the_key_so_that_a_retry_starts_afresh() {
    let harness = harness();
    for expected_runs in 1..=2 {
        let reply = send(&harness.app, "POST", "/fail", Some("f"), "{}", &[]).await;
        assert_eq!(reply.code(), Some(ProblemCode::ValidationFailed));
        assert_eq!(runs(&harness), expected_runs);
    }
    assert!(
        harness.store.is_empty().await,
        "the key of a failed request is free again"
    );
}

#[tokio::test]
async fn a_request_in_flight_is_refused_with_409_while_the_first_one_finishes() {
    let harness = harness();
    let first = tokio::spawn({
        let app = harness.app.clone();
        async move { send(&app, "POST", "/slow", Some("slow"), "{}", &[]).await }
    });
    harness.probe.started.notified().await;

    let second = send(&harness.app, "POST", "/slow", Some("slow"), "{}", &[]).await;
    assert_eq!(second.code(), Some(ProblemCode::IdempotencyInProgress));
    assert_eq!(second.status, StatusCode::CONFLICT);

    harness.probe.gate.notify_one();
    let first = first.await.unwrap();
    assert_eq!((first.status, first.body.clone()), (StatusCode::OK, json!({"n": 1})));
    let third = send(&harness.app, "POST", "/slow", Some("slow"), "{}", &[]).await;
    assert!(third.replayed());
    assert_eq!(third.body, json!({"n": 1}));
    assert_eq!(runs(&harness), 1);
}

#[tokio::test]
async fn a_client_that_disconnects_does_not_cancel_the_work_and_its_outcome_is_recorded() {
    let harness = harness();
    let abandoned = tokio::spawn({
        let app = harness.app.clone();
        async move { send(&app, "POST", "/slow", Some("gone"), "{}", &[]).await }
    });
    harness.probe.started.notified().await;
    // The client hangs up: the future of the request is dropped while the handler waits.
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());
    harness.probe.gate.notify_one();
    for _ in 0..1000 {
        if harness.store.settles.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        harness.store.settles.load(Ordering::SeqCst),
        1,
        "the outcome was recorded anyway"
    );

    let retry = send(&harness.app, "POST", "/slow", Some("gone"), "{}", &[]).await;
    assert!(
        retry.replayed(),
        "the retry gets the result of the work that was not cancelled"
    );
    assert_eq!(retry.body, json!({"n": 1}));
    assert_eq!(runs(&harness), 1);
}

#[tokio::test]
async fn a_panicking_handler_answers_500_and_releases_the_key() {
    let harness = harness();
    for expected_runs in 1..=2 {
        let reply = send(&harness.app, "POST", "/boom", Some("b"), "{}", &[]).await;
        assert_eq!(reply.code(), Some(ProblemCode::Internal));
        assert_eq!(runs(&harness), expected_runs);
    }
    assert!(harness.store.is_empty().await);
}

#[tokio::test]
async fn requests_that_do_not_ask_for_idempotency_pass_through() {
    let harness = harness();
    // No header: every request runs.
    assert_eq!(post_ok(&harness, None, "{}").await.body, json!({"n": 1}));
    assert_eq!(post_ok(&harness, None, "{}").await.body, json!({"n": 2}));
    // Other methods ignore the header.
    for expected in [3, 4] {
        let reply = send(&harness.app, "GET", "/read", Some("g"), "", &[]).await;
        assert_eq!(reply.body, json!({"n": expected}));
        assert!(!reply.replayed());
    }
    assert_eq!(
        harness.store.reserves.load(Ordering::SeqCst),
        0,
        "the service was never asked"
    );
}

#[tokio::test]
async fn a_keyed_post_without_a_context_is_refused_not_run_unprotected() {
    // The layer belongs inside authentication. A keyed POST that arrives without a context is a mounting bug, and
    // running its handler without protection would duplicate its effects on the retry the key was sent for.
    let harness = harness();
    let anonymous = send(&harness.app, "POST", "/ok", Some("a"), "{}", &[("x-anonymous", "1")]).await;
    assert_eq!(anonymous.code(), Some(ProblemCode::Internal));
    assert_eq!(runs(&harness), 0, "the handler did not run");
    assert_eq!(harness.store.reserves.load(Ordering::SeqCst), 0);
    // Without the header nothing is to protect, and the request goes through to the handler.
    let plain = send(&harness.app, "POST", "/ok", None, "{}", &[("x-anonymous", "1")]).await;
    assert_eq!(plain.status, StatusCode::CREATED);
}

#[tokio::test]
async fn a_malformed_key_is_a_400() {
    let harness = harness();
    for bad in ["", "has space", "tab\there"] {
        let reply = post_ok(&harness, Some(bad), "{}").await;
        assert_eq!(reply.code(), Some(ProblemCode::BadRequest), "{bad:?}");
    }
    let too_long = "k".repeat(256);
    assert_eq!(
        post_ok(&harness, Some(&too_long), "{}").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(runs(&harness), 0);
}

#[tokio::test]
async fn an_unavailable_service_refuses_the_request_with_503_instead_of_running_it_unprotected() {
    let harness = harness();
    harness.store.fail_begin.store(true, Ordering::SeqCst);
    let reply = post_ok(&harness, Some("k"), "{}").await;
    assert_eq!(reply.code(), Some(ProblemCode::Unavailable));
    assert_eq!(reply.problem.unwrap().retry_after(), Some(Duration::from_secs(1)));
    assert_eq!(runs(&harness), 0, "nothing ran without protection");

    // An operation a service does not implement is the 501 problem, not a silent bypass.
    let mut services = davhaven_app::AppServices::fake();
    services.idempotency = Arc::new(davhaven_app_fake::unsupported::Unsupported);
    let layer = Idempotency {
        state: ApiState { services },
        request_timeout: TIMEOUT,
    };
    let app = Router::new()
        .route("/ok", post(ok))
        .route_layer(from_fn_with_state(layer, replay))
        .layer(from_fn(authenticated))
        .with_state(Shared::default());
    let reply = send(&app, "POST", "/ok", Some("k"), "{}", &[]).await;
    assert_eq!(reply.code(), Some(ProblemCode::NotImplemented));
}

#[tokio::test]
async fn a_failure_to_record_the_outcome_does_not_change_the_response() {
    let harness = harness();
    harness.store.fail_complete.store(true, Ordering::SeqCst);
    let reply = post_ok(&harness, Some("k"), "{}").await;
    assert_eq!((reply.status, reply.body), (StatusCode::CREATED, json!({"n": 1})));
    assert_eq!(harness.store.settles.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bodies_are_read_with_the_limit_of_their_route_before_anything_is_reserved() {
    // 16 bytes of JSON, 1 KiB for batches.
    let harness = harness_with(Some((16, 1024)), TIMEOUT);
    let body = r#"{"a":"more than sixteen bytes"}"#;
    let too_large = post_ok(&harness, Some("k"), body).await;
    assert_eq!(too_large.code(), Some(ProblemCode::PayloadTooLarge));
    assert_eq!(
        harness.store.reserves.load(Ordering::SeqCst),
        0,
        "no key was reserved for a request that cannot succeed"
    );
    assert_eq!(runs(&harness), 0);
    // The batch route has the larger limit, as its handler does.
    let batch = "/api/v1/tenants/acme/principals/anna/calendars/work/objects/batch";
    let accepted = send(&harness.app, "POST", batch, Some("batch-1"), body, &[]).await;
    assert_eq!(accepted.status, StatusCode::CREATED, "{:?}", accepted.problem);
    // The batch limit is a limit too.
    let huge = format!(r#"{{"a":"{}"}}"#, "x".repeat(2000));
    let refused = send(&harness.app, "POST", batch, Some("batch-2"), &huge, &[]).await;
    assert_eq!(refused.code(), Some(ProblemCode::PayloadTooLarge));
}

#[tokio::test]
async fn the_service_is_asked_for_a_lease_of_the_request_timeout_plus_a_margin() {
    let harness = harness_with(None, Duration::from_secs(45));
    post_ok(&harness, Some("k"), "{}").await;
    assert_eq!(
        *harness.store.leases.lock().await,
        vec![Duration::from_secs(45) + LEASE_MARGIN],
        "a key stays claimed a little longer than the handler may work"
    );
}

#[tokio::test(start_paused = true)]
async fn a_handler_that_outlives_the_request_timeout_is_cancelled_and_its_key_released() {
    let harness = harness();
    let reply = send(&harness.app, "POST", "/forever", Some("slow"), "{}", &[]).await;
    assert_eq!(reply.code(), Some(ProblemCode::Unavailable), "the work took too long");
    assert_eq!(
        harness.store.settles.load(Ordering::SeqCst),
        1,
        "the outcome was recorded"
    );
    assert!(harness.store.is_empty().await, "and the key is free for a retry");
    assert_eq!(
        harness.probe.active.load(Ordering::SeqCst),
        0,
        "the handler was cancelled, not left running past its claim"
    );
    assert_eq!(harness.store.stale.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn after_a_timeout_the_retry_runs_once_and_executions_never_overlap() {
    let harness = harness();
    let first = send(&harness.app, "POST", "/hangs-once", Some("k"), "{}", &[]).await;
    assert_eq!(first.code(), Some(ProblemCode::Unavailable));
    let retry = send(&harness.app, "POST", "/hangs-once", Some("k"), "{}", &[]).await;
    assert_eq!((retry.status, retry.body.clone()), (StatusCode::OK, json!({"n": 2})));
    let third = send(&harness.app, "POST", "/hangs-once", Some("k"), "{}", &[]).await;
    assert!(third.replayed(), "the retry's response was stored");
    assert_eq!(third.body, json!({"n": 2}));
    assert_eq!(runs(&harness), 2);
    assert_eq!(
        harness.probe.most_active.load(Ordering::SeqCst),
        1,
        "the first attempt was gone before the retry started"
    );
    assert_eq!(
        harness.store.len().await,
        1,
        "exactly one result is recorded for the key"
    );
}

#[tokio::test(start_paused = true)]
async fn detached_work_keeps_the_concurrency_permit_until_it_ends() {
    // The edge answers 503 when the request timeout passes, and drops its own handle on the permit; the handler is
    // still running in the task of the layer. The permit must stay taken, or detached work escapes the limit.
    let store = Arc::new(MemoryIdempotency::default());
    let probe = Shared::default();
    let mut services = davhaven_app::AppServices::fake();
    services.idempotency = Arc::<MemoryIdempotency>::clone(&store);
    let layer = Idempotency {
        state: ApiState { services },
        // The handler may work longer than the edge waits for it.
        request_timeout: Duration::from_secs(120),
    };
    let app = routes()
        .route_layer(from_fn_with_state(layer, replay))
        .layer(from_fn(authenticated))
        .layer(from_fn_with_state(Duration::from_secs(5), enforce_timeout))
        .layer(from_fn_with_state(concurrency_permits(1), shed_load))
        .with_state(Arc::clone(&probe));

    let first = send(&app, "POST", "/slow", Some("k"), "{}", &[]).await;
    assert_eq!(first.code(), Some(ProblemCode::Unavailable));
    assert_eq!(
        first.problem.as_ref().and_then(EdgeProblem::detail),
        Some("The request took too long to process."),
        "the edge gave up on the client's behalf"
    );
    assert_eq!(probe.active.load(Ordering::SeqCst), 1, "the handler is still working");

    let shed = send(&app, "POST", "/ok", None, "{}", &[]).await;
    assert_eq!(shed.code(), Some(ProblemCode::Unavailable));
    assert_eq!(
        shed.problem.as_ref().and_then(EdgeProblem::detail),
        Some("The server is busy; try again shortly."),
        "the permit of the detached work is still taken"
    );

    probe.gate.notify_one();
    for _ in 0..100 {
        if probe.active.load(Ordering::SeqCst) == 0 && store.has_stored_response("k").await {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        store.has_stored_response("k").await,
        "the work finished and was recorded"
    );
    let after = send(&app, "POST", "/ok", None, "{}", &[]).await;
    assert_eq!(
        after.status,
        StatusCode::CREATED,
        "the permit is back when the work is done"
    );
}

#[tokio::test(start_paused = true)]
async fn a_settlement_that_presents_a_claim_that_was_taken_over_is_ignored() {
    // The contract of `settle` with a reservation (ADR-0006), as the double implements it and a service backed by the
    // fenced operations of the store must: the late settlement of an attempt that lost its claim cannot settle or
    // release the claim of the attempt that replaced it.
    let store = MemoryIdempotency::default();
    let context = RequestContext {
        tenant: TenantId::from_uuid(Uuid::from_u128(1)),
        actor: Actor::TenantToken(TokenId::from_uuid(Uuid::from_u128(1))),
        scopes: ScopeSet::empty(),
        channel: Channel::Api,
        credential: None,
        request_id: RequestId::from_uuid(Uuid::nil()),
        locale: None,
        client_ip: None,
    };
    let key = IdempotencyKey {
        key: "k".to_owned(),
        method: "POST".to_owned(),
        route: "/ok".to_owned(),
    };
    let lease = Duration::from_secs(40);
    let Reserved::Fresh(first) = store
        .reserve(&context, key.clone(), "f".to_owned(), lease)
        .await
        .unwrap()
    else {
        panic!("a fresh key");
    };
    assert_eq!(
        store
            .reserve(&context, key.clone(), "f".to_owned(), lease)
            .await
            .unwrap(),
        Reserved::InProgress
    );
    tokio::time::advance(Duration::from_secs(41)).await;
    let Reserved::Fresh(second) = store
        .reserve(&context, key.clone(), "f".to_owned(), lease)
        .await
        .unwrap()
    else {
        panic!("the key is taken over after its lease");
    };
    assert_ne!(first, second);

    // The first attempt finishes late and tries to release the key: nothing happens.
    store.settle(&context, &key, &first, Settlement::Abandon).await.unwrap();
    assert_eq!(store.stale.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .reserve(&context, key.clone(), "f".to_owned(), lease)
            .await
            .unwrap(),
        Reserved::InProgress,
        "the claim of the second attempt is intact"
    );
    // The second attempt settles with its own proof.
    let stored = StoredResponse {
        status: 200,
        headers: Vec::new(),
        body: json!({"n": 2}),
    };
    store
        .settle(&context, &key, &second, Settlement::Response(stored.clone()))
        .await
        .unwrap();
    assert_eq!(
        store.reserve(&context, key, "f".to_owned(), lease).await.unwrap(),
        Reserved::Replay(stored)
    );
}

#[test]
fn fingerprints_separate_every_part_of_a_request() {
    fn parts(method: &str, uri: &str, content_type: &str) -> Parts {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", content_type)
            .body(())
            .unwrap()
            .into_parts()
            .0
    }
    let base = fingerprint(&parts("POST", "/a/b", "application/json"), b"{}");
    assert_eq!(base.len(), 64);
    assert!(base.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(base, fingerprint(&parts("POST", "/a/b", "application/json"), b"{}"));
    for (what, other) in [
        (
            "the method",
            fingerprint(&parts("PUT", "/a/b", "application/json"), b"{}"),
        ),
        (
            "the path",
            fingerprint(&parts("POST", "/a/c", "application/json"), b"{}"),
        ),
        (
            "the query",
            fingerprint(&parts("POST", "/a/b?x=1", "application/json"), b"{}"),
        ),
        (
            "the content type",
            fingerprint(&parts("POST", "/a/b", "application/merge-patch+json"), b"{}"),
        ),
        (
            "the body",
            fingerprint(&parts("POST", "/a/b", "application/json"), b"{ }"),
        ),
    ] {
        assert_ne!(base, other, "{what}");
    }
    // Moving a byte between the path and the query changes the encoding.
    assert_ne!(
        fingerprint(&parts("POST", "/a/b?c", "application/json"), b""),
        fingerprint(&parts("POST", "/a/b", "c"), b"")
    );
}

#[test]
fn only_whitelisted_headers_are_replayed() {
    let stored = StoredResponse {
        status: 201,
        headers: vec![
            ("etag".to_owned(), "\"v3\"".to_owned()),
            ("set-cookie".to_owned(), "session=evil".to_owned()),
            ("location".to_owned(), "https://cal.example.org/x".to_owned()),
            ("bad name".to_owned(), "x".to_owned()),
        ],
        body: json!({"ok": true}),
    };
    let response = replayed(&stored);
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["etag"], "\"v3\"");
    assert_eq!(response.headers()["location"], "https://cal.example.org/x");
    assert!(response.headers().get("set-cookie").is_none());
    assert_eq!(response.headers()[REPLAYED], "true");
    let nonsense = replayed(&StoredResponse {
        status: 9999,
        headers: Vec::new(),
        body: Value::Null,
    });
    assert_eq!(
        nonsense.status(),
        StatusCode::OK,
        "an unusable stored status does not panic"
    );
    assert!(nonsense.headers().get(RETRY_AFTER).is_none());
}
