//! Rendering of RFC 9457 problem responses and the hook that lets every surface render failures its own way.
//!
//! Every failure a client can see is one row of the problem catalog ([`ProblemCode`]). Code that fails a request,
//! whether an edge layer, an extractor or a handler that received an `AppError`, does not build a response. It
//! returns an [`EdgeProblem`], which is an ordinary [`IntoResponse`] value: an empty response that carries the
//! problem in its extensions. The [`render_problems`] layer, mounted once per surface just inside the request id
//! and tracing layers, turns every such response into the surface's wire form through a [`ProblemRenderer`]:
//!
//! | Surface | Renderer | Form |
//! | --- | --- | --- |
//! | `api`, `mcp` | [`JsonProblems`] | `application/problem+json` (RFC 9457) with `type`, `code`, `request_id`, `errors` |
//! | `dav` | the renderer of the `dav` crate | status from the DAV column plus an XML `DAV:error` body |
//! | `web` | the renderer of the `web` crate | a small HTML page |
//!
//! The same layer renders the bare error statuses that the framework produces itself (the default 404 and 405, for
//! example), so no surface ever answers with a differently shaped error. Internal error text never reaches a
//! response: a problem carries the catalog title, a client-safe detail and per-field errors, nothing else.

use core::time::Duration;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, LOCATION, RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use davhaven_app::AppError;
use davhaven_domain::{Precondition, RequestId};
use davhaven_wire::ProblemDetails;
pub use davhaven_wire::{FieldProblem, ProblemCode};

use crate::rate_limit::retry_after_value;
use crate::request_id::request_id_of;

/// A failure, independent of the form it is rendered in.
///
/// Created by edge layers, extractors and handlers, converted into a response with [`IntoResponse`] and rendered by
/// the surface's [`ProblemRenderer`] (see the module documentation).
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeProblem(Box<Details>);

/// The members of an [`EdgeProblem`], boxed so that `Result<_, EdgeProblem>` stays small.
#[derive(Debug, Clone, PartialEq)]
struct Details {
    code: ProblemCode,
    detail: Option<String>,
    errors: Vec<FieldProblem>,
    precondition: Option<Precondition>,
    retry_after: Option<Duration>,
    challenge: Option<String>,
    allow: Option<String>,
    location: Option<String>,
}

impl EdgeProblem {
    /// A problem of a catalog row, without detail.
    pub fn new(code: ProblemCode) -> Self {
        Self(Box::new(Details {
            code,
            detail: None,
            errors: Vec::new(),
            precondition: None,
            retry_after: None,
            challenge: None,
            allow: None,
            location: None,
        }))
    }

    /// The problem an application error becomes: the catalog row comes from the error's precondition when it has
    /// one this release knows and from its kind otherwise ([`ProblemCode::from_error`]). The detail is the error's
    /// client-safe message unless that is just the generic text of the kind; the source error is never used.
    pub fn from_app_error(error: &AppError) -> Self {
        let details = error.problem_details();
        let mut problem = Self::new(details.code);
        problem.0.detail = details.detail;
        problem.0.errors = details.errors;
        problem.0.precondition = error.precondition().cloned();
        problem.0.retry_after = error.retry_after();
        problem
    }

    /// The problem of a bare error status that the framework produced without a body.
    pub fn from_status(status: StatusCode) -> Self {
        let code = match status.as_u16() {
            401 => ProblemCode::Unauthenticated,
            403 => ProblemCode::Forbidden,
            404 => ProblemCode::NotFound,
            405 => ProblemCode::MethodNotAllowed,
            409 => ProblemCode::Conflict,
            412 => ProblemCode::PreconditionFailed,
            413 => ProblemCode::PayloadTooLarge,
            415 => ProblemCode::UnsupportedMediaType,
            422 => ProblemCode::ValidationFailed,
            428 => ProblemCode::PreconditionRequired,
            429 => ProblemCode::RateLimited,
            501 => ProblemCode::NotImplemented,
            503 => ProblemCode::Unavailable,
            500..=599 => ProblemCode::Internal,
            _ => ProblemCode::BadRequest,
        };
        Self::new(code)
    }

    /// Sets the client-safe explanation of this occurrence.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.0.detail = Some(detail.into());
        self
    }

    /// Adds one invalid field (validation problems).
    #[must_use]
    pub fn with_error(mut self, error: FieldProblem) -> Self {
        self.0.errors.push(error);
        self
    }

    /// Sets how long the client should wait before repeating the request (`Retry-After`).
    #[must_use]
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.0.retry_after = Some(retry_after);
        self
    }

    /// Sets the `WWW-Authenticate` challenge of a 401, overriding the renderer's default.
    #[must_use]
    pub fn with_challenge(mut self, challenge: impl Into<String>) -> Self {
        self.0.challenge = Some(challenge.into());
        self
    }

    /// Sets the `Allow` header of a 405.
    #[must_use]
    pub fn with_allow(mut self, allow: impl Into<String>) -> Self {
        self.0.allow = Some(allow.into());
        self
    }

    /// Sets the `Location` header of a problem that tells the client where to find the resource the failed request
    /// is about (the resource that the first attempt of a repeated request created).
    #[must_use]
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.0.location = Some(location.into());
        self
    }

    /// The catalog row.
    pub const fn code(&self) -> ProblemCode {
        self.0.code
    }

    /// The client-safe explanation, if any.
    pub fn detail(&self) -> Option<&str> {
        self.0.detail.as_deref()
    }

    /// The invalid fields of a validation problem.
    pub fn errors(&self) -> &[FieldProblem] {
        &self.0.errors
    }

    /// The precondition of the application error this problem came from (DAV renders its element and hrefs).
    pub fn precondition(&self) -> Option<&Precondition> {
        self.0.precondition.as_ref()
    }

    /// How long the client should wait, for rate limits and overload.
    pub fn retry_after(&self) -> Option<Duration> {
        self.0.retry_after
    }

    /// The explicit `WWW-Authenticate` challenge.
    pub fn challenge(&self) -> Option<&str> {
        self.0.challenge.as_deref()
    }

    /// The `Allow` header value of a 405.
    pub fn allow(&self) -> Option<&str> {
        self.0.allow.as_deref()
    }

    /// The `Location` header value, if the problem has one.
    pub fn location(&self) -> Option<&str> {
        self.0.location.as_deref()
    }
}

impl IntoResponse for EdgeProblem {
    /// An empty response with the status of the catalog row and the problem in its extensions; the surface's
    /// [`render_problems`] layer replaces it with the rendered form.
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = Response::new(Body::empty());
        *response.status_mut() = status;
        response.extensions_mut().insert(self);
        response
    }
}

impl From<AppError> for EdgeProblem {
    fn from(error: AppError) -> Self {
        Self::from_app_error(&error)
    }
}

/// Renders a problem in the wire form of one surface.
pub trait ProblemRenderer: Send + Sync + 'static {
    /// The complete response for `problem`, including its status and the headers the problem asks for
    /// (see [`apply_problem_headers`]). `request_id` is the id of the failed request, when known.
    fn render(&self, problem: &EdgeProblem, request_id: Option<RequestId>) -> Response;
}

/// Sets `Retry-After`, `WWW-Authenticate`, `Allow` and `Location` as the problem asks.
///
/// A 429 always carries `Retry-After` (one second when the problem names no delay); a 401 carries the problem's own
/// challenge or else `default_challenge`.
pub fn apply_problem_headers(response: &mut Response, problem: &EdgeProblem, default_challenge: Option<&HeaderValue>) {
    let retry_after = problem
        .retry_after()
        .or_else(|| (problem.code() == ProblemCode::RateLimited).then_some(Duration::from_secs(1)));
    let challenge = problem
        .challenge()
        .and_then(|text| HeaderValue::from_str(text).ok())
        .or_else(|| {
            default_challenge
                .filter(|_| problem.code() == ProblemCode::Unauthenticated)
                .cloned()
        });
    let allow = problem.allow().and_then(|text| HeaderValue::from_str(text).ok());
    let location = problem.location().and_then(|text| HeaderValue::from_str(text).ok());
    let headers = response.headers_mut();
    if let Some(retry_after) = retry_after {
        headers.insert(RETRY_AFTER, retry_after_value(retry_after));
    }
    if let Some(challenge) = challenge {
        headers.insert(WWW_AUTHENTICATE, challenge);
    }
    if let Some(allow) = allow {
        headers.insert(ALLOW, allow);
    }
    if let Some(location) = location {
        headers.insert(LOCATION, location);
    }
}

fn catalog_status(code: ProblemCode) -> u16 {
    code.http_status()
}

/// The RFC 9457 renderer of the management API, MCP and every other JSON surface.
///
/// The body is a [`ProblemDetails`] document served as `application/problem+json` with `Cache-Control: no-store`.
/// The HTTP status comes from a table (the catalog by default); the `api` crate supplies its own exhaustively
/// tested table with [`JsonProblems::with_status_table`].
#[derive(Debug, Clone)]
pub struct JsonProblems {
    status: fn(ProblemCode) -> u16,
    challenge: Option<HeaderValue>,
}

impl JsonProblems {
    /// The renderer that takes the HTTP status from the problem catalog and sends no default challenge.
    pub const fn catalog() -> Self {
        Self {
            status: catalog_status,
            challenge: None,
        }
    }

    /// Takes the HTTP status from `status` instead of the catalog.
    #[must_use]
    pub const fn with_status_table(mut self, status: fn(ProblemCode) -> u16) -> Self {
        self.status = status;
        self
    }

    /// Sets the `WWW-Authenticate` challenge of 401 responses, for example `Bearer realm="davhaven"`.
    ///
    /// An unusable header value (control characters) leaves the challenge unset.
    #[must_use]
    pub fn with_challenge(mut self, challenge: &str) -> Self {
        self.challenge = HeaderValue::from_str(challenge).ok();
        self
    }
}

impl Default for JsonProblems {
    fn default() -> Self {
        Self::catalog()
    }
}

impl ProblemRenderer for JsonProblems {
    fn render(&self, problem: &EdgeProblem, request_id: Option<RequestId>) -> Response {
        let code = problem.code();
        let status_code = (self.status)(code);
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut details = ProblemDetails::new(code);
        details.status = status_code;
        details.detail = problem.detail().map(str::to_owned);
        details.request_id = request_id;
        details.errors = problem.errors().to_vec();
        let body = serde_json::to_vec(&details).unwrap_or_else(|_| b"{}".to_vec());
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        apply_problem_headers(&mut response, problem, self.challenge.as_ref());
        response
    }
}

/// The problem a response stands for: the [`EdgeProblem`] it carries, or for a bare 4xx or 5xx response without a content
/// type (what the framework produces for unknown paths and wrong methods) the problem of its status, keeping its `Allow`
/// header. `None` for everything else, which passes through a renderer unchanged.
pub fn problem_of(response: &Response) -> Option<EdgeProblem> {
    if let Some(problem) = response.extensions().get::<EdgeProblem>() {
        return Some(problem.clone());
    }
    let status = response.status();
    let is_error = status.is_client_error() || status.is_server_error();
    if is_error && !response.headers().contains_key(CONTENT_TYPE) {
        let mut problem = EdgeProblem::from_status(status);
        if let Some(allow) = response.headers().get(ALLOW).and_then(|value| value.to_str().ok()) {
            problem = problem.with_allow(allow);
        }
        return Some(problem);
    }
    None
}

/// Turns a response into its rendered form: a response that stands for a problem ([`problem_of`]) is rendered from it,
/// everything else passes unchanged.
pub fn finalize_response(
    renderer: &dyn ProblemRenderer,
    response: Response,
    request_id: Option<RequestId>,
) -> Response {
    match problem_of(&response) {
        Some(problem) => renderer.render(&problem, request_id),
        None => response,
    }
}

/// The layer function of the problem renderer; mount it with
/// `axum::middleware::from_fn_with_state(renderer, render_problems)`.
pub async fn render_problems(
    State(renderer): State<Arc<dyn ProblemRenderer>>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = request_id_of(request.extensions());
    let response = next.run(request).await;
    finalize_response(renderer.as_ref(), response, request_id)
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::routing::get;
    use davhaven_app::SafeMessage;
    use davhaven_domain::{ErrorKind, Href, Privilege};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    fn request_id() -> RequestId {
        RequestId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap()
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn a_location_is_sent_with_the_rendered_problem() {
        let problem = EdgeProblem::new(ProblemCode::SecretNotReplayable).with_location("/api/v1/things/1");
        assert_eq!(problem.location(), Some("/api/v1/things/1"));
        let response = JsonProblems::catalog().render(&problem, None);
        assert_eq!(response.headers()[LOCATION], "/api/v1/things/1");
        let plain = JsonProblems::catalog().render(&EdgeProblem::new(ProblemCode::NotFound), None);
        assert!(!plain.headers().contains_key(LOCATION));
    }

    #[test]
    fn a_disabled_feature_is_its_own_row_through_the_one_rule_of_the_catalog() {
        let disabled = EdgeProblem::from_app_error(&AppError::feature_not_enabled());
        assert_eq!(disabled.code(), ProblemCode::FeatureNotEnabled);
        assert_eq!(disabled.detail(), Some("This feature is not enabled."));
        let plain = EdgeProblem::from_app_error(&AppError::conflict());
        assert_eq!(plain.code(), ProblemCode::Conflict);
        assert_eq!(plain.detail(), None);
    }

    #[test]
    fn app_errors_become_catalog_rows_and_keep_only_client_safe_text() {
        let internal = AppError::internal(std::io::Error::other(
            "relation \"x\" does not exist (password=hunter2)",
        ));
        let problem = EdgeProblem::from_app_error(&internal);
        assert_eq!(problem.code(), ProblemCode::Internal);
        assert_eq!(
            problem.detail(),
            None,
            "the generic text of a kind is not repeated as a detail"
        );
        assert!(!format!("{problem:?}").contains("hunter2"));

        let href = Href::parse("/dav/calendars/acme/anna/work/x.ics").unwrap();
        let denied = AppError::need_privilege(href, Privilege::WriteContent);
        let problem = EdgeProblem::from_app_error(&denied);
        assert_eq!(problem.code(), ProblemCode::Forbidden);
        assert!(matches!(problem.precondition(), Some(Precondition::NeedPrivileges(pairs)) if pairs.len() == 1));

        let limited = AppError::rate_limited(Duration::from_secs(30));
        let problem = EdgeProblem::from(limited);
        assert_eq!(problem.code(), ProblemCode::RateLimited);
        assert_eq!(problem.retry_after(), Some(Duration::from_secs(30)));

        let invalid = AppError::new(ErrorKind::Invalid)
            .with_public_message(SafeMessage::from_static("The display name must not be empty."));
        let problem = EdgeProblem::from_app_error(&invalid);
        assert_eq!(problem.code(), ProblemCode::ValidationFailed);
        assert_eq!(problem.detail(), Some("The display name must not be empty."));
        assert_eq!(problem.errors().len(), 0);
    }

    #[test]
    fn the_invalid_fields_of_an_app_error_become_the_errors_of_the_problem() {
        let invalid = AppError::new(ErrorKind::Invalid)
            .with_field_error(
                "/url",
                "not-allowed",
                SafeMessage::from_static("The URL is not allowed as a webhook target."),
            )
            .with_field_error("/events", "empty", SafeMessage::from_static("Name at least one event."));
        let problem = EdgeProblem::from(invalid);
        assert_eq!(problem.code(), ProblemCode::ValidationFailed);
        assert_eq!(
            problem.errors(),
            [
                FieldProblem::new("/url", "not-allowed", "The URL is not allowed as a webhook target."),
                FieldProblem::new("/events", "empty", "Name at least one event."),
            ]
        );
    }

    #[test]
    fn bare_statuses_map_to_their_rows() {
        let cases = [
            (400, ProblemCode::BadRequest),
            (401, ProblemCode::Unauthenticated),
            (403, ProblemCode::Forbidden),
            (404, ProblemCode::NotFound),
            (405, ProblemCode::MethodNotAllowed),
            (409, ProblemCode::Conflict),
            (412, ProblemCode::PreconditionFailed),
            (413, ProblemCode::PayloadTooLarge),
            (415, ProblemCode::UnsupportedMediaType),
            (418, ProblemCode::BadRequest),
            (422, ProblemCode::ValidationFailed),
            (428, ProblemCode::PreconditionRequired),
            (429, ProblemCode::RateLimited),
            (500, ProblemCode::Internal),
            (501, ProblemCode::NotImplemented),
            (502, ProblemCode::Internal),
            (503, ProblemCode::Unavailable),
        ];
        for (status, code) in cases {
            let status = StatusCode::from_u16(status).unwrap();
            assert_eq!(EdgeProblem::from_status(status).code(), code, "{status}");
        }
    }

    #[test]
    fn problems_render_as_rfc_9457_documents() {
        let problem = EdgeProblem::new(ProblemCode::ValidationFailed)
            .with_detail("The body is invalid.")
            .with_error(FieldProblem::new("/display_name", "required", "must not be empty"));
        let response = JsonProblems::catalog().render(&problem, Some(request_id()));
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert!(response.headers().get(RETRY_AFTER).is_none());
    }

    #[tokio::test]
    async fn rendered_documents_carry_type_code_request_id_and_errors() {
        let problem = EdgeProblem::new(ProblemCode::ValidationFailed)
            .with_detail("The body is invalid.")
            .with_error(FieldProblem::new("/display_name", "required", "must not be empty"));
        let json = body_json(JsonProblems::catalog().render(&problem, Some(request_id()))).await;
        assert_eq!(json["type"], "urn:davhaven:problem:validation-failed");
        assert_eq!(json["code"], "validation-failed");
        assert_eq!(json["status"], 422);
        assert_eq!(json["detail"], "The body is invalid.");
        assert_eq!(json["request_id"], "018f3c1e-7b2a-7c3d-9e4f-0123456789ab");
        assert_eq!(json["errors"][0]["pointer"], "/display_name");
    }

    #[test]
    fn headers_follow_the_problem() {
        let renderer = JsonProblems::catalog().with_challenge("Bearer realm=\"davhaven\"");
        let limited = EdgeProblem::new(ProblemCode::RateLimited).with_retry_after(Duration::from_millis(1500));
        let response = renderer.render(&limited, None);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "2", "fractions of a second round up");
        let without_delay = renderer.render(&EdgeProblem::new(ProblemCode::RateLimited), None);
        assert_eq!(without_delay.headers()[RETRY_AFTER], "1");

        let unauthenticated = renderer.render(&EdgeProblem::new(ProblemCode::Unauthenticated), None);
        assert_eq!(unauthenticated.headers()[WWW_AUTHENTICATE], "Bearer realm=\"davhaven\"");
        let own = EdgeProblem::new(ProblemCode::Unauthenticated).with_challenge("Basic realm=\"acme\"");
        assert_eq!(
            renderer.render(&own, None).headers()[WWW_AUTHENTICATE],
            "Basic realm=\"acme\""
        );
        let other = renderer.render(&EdgeProblem::new(ProblemCode::NotFound), None);
        assert!(other.headers().get(WWW_AUTHENTICATE).is_none());

        let wrong_method = EdgeProblem::new(ProblemCode::MethodNotAllowed).with_allow("GET, HEAD");
        assert_eq!(renderer.render(&wrong_method, None).headers()[ALLOW], "GET, HEAD");
    }

    #[tokio::test]
    async fn every_catalog_row_renders_with_its_status_type_and_code_and_nothing_internal() {
        for code in ProblemCode::ALL {
            let response = JsonProblems::catalog().render(&EdgeProblem::new(*code), Some(request_id()));
            assert_eq!(response.status().as_u16(), code.http_status(), "{}", code.code());
            assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            let json = body_json(response).await;
            assert_eq!(
                json["status"],
                code.http_status(),
                "the body names the status of the response"
            );
            assert_eq!(json["code"], code.code());
            assert_eq!(json["type"], format!("urn:davhaven:problem:{}", code.code()));
            assert_eq!(json["request_id"], "018f3c1e-7b2a-7c3d-9e4f-0123456789ab");
            assert!(json.get("detail").is_none_or(serde_json::Value::is_null), "{json}");
        }
    }

    #[test]
    fn a_challenge_that_is_no_header_value_is_dropped() {
        let renderer = JsonProblems::catalog().with_challenge("Bearer realm=\"x\"\r\nSet-Cookie: a=b");
        let response = renderer.render(&EdgeProblem::new(ProblemCode::Unauthenticated), None);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
        assert!(response.headers().get("set-cookie").is_none());
        // A problem's own challenge that is no header value gives way to the renderer's.
        let renderer = JsonProblems::catalog().with_challenge("Bearer realm=\"davhaven\"");
        let own = EdgeProblem::new(ProblemCode::Unauthenticated).with_challenge("Basic\nrealm");
        assert_eq!(
            renderer.render(&own, None).headers()[WWW_AUTHENTICATE],
            "Bearer realm=\"davhaven\""
        );
    }

    #[test]
    fn only_problems_and_bare_error_statuses_stand_for_a_problem() {
        let mut typed = Response::new(Body::from("teapot"));
        *typed.status_mut() = StatusCode::BAD_REQUEST;
        typed
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(
            problem_of(&typed),
            None,
            "an error with a body of its own passes unchanged"
        );
        let mut empty = Response::new(Body::empty());
        *empty.status_mut() = StatusCode::NO_CONTENT;
        assert_eq!(problem_of(&empty), None);
        let mut moved = Response::new(Body::empty());
        *moved.status_mut() = StatusCode::NOT_MODIFIED;
        assert_eq!(problem_of(&moved), None);
        let mut bare = Response::new(Body::empty());
        *bare.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        bare.headers_mut().insert(ALLOW, HeaderValue::from_static("GET,HEAD"));
        let problem = problem_of(&bare).unwrap();
        assert_eq!(problem.code(), ProblemCode::MethodNotAllowed);
        assert_eq!(problem.allow(), Some("GET,HEAD"));
        // A problem keeps its own row even under a content type a handler set.
        let mut carried = EdgeProblem::new(ProblemCode::Conflict).into_response();
        carried
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(
            problem_of(&carried).map(|problem| problem.code()),
            Some(ProblemCode::Conflict)
        );
    }

    #[test]
    fn the_status_table_can_be_replaced() {
        fn teapot(_: ProblemCode) -> u16 {
            418
        }
        let response = JsonProblems::catalog()
            .with_status_table(teapot)
            .render(&EdgeProblem::new(ProblemCode::NotFound), None);
        assert_eq!(response.status().as_u16(), 418);
    }

    async fn teapot_handler() -> EdgeProblem {
        EdgeProblem::new(ProblemCode::Conflict).with_detail("taken")
    }

    fn app() -> Router {
        let renderer: Arc<dyn ProblemRenderer> = Arc::new(JsonProblems::catalog());
        Router::new()
            .route("/conflict", get(teapot_handler))
            .route("/ok", get(|| async { "fine" }))
            .layer(axum::middleware::from_fn_with_state(renderer, render_problems))
    }

    #[tokio::test]
    async fn the_layer_renders_handler_problems_and_leaves_success_alone() {
        let response = app()
            .oneshot(Request::get("/conflict").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(response).await["detail"], "taken");

        let ok = app()
            .oneshot(Request::get("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(
            ok.headers()
                .get(CONTENT_TYPE)
                .is_some_and(|value| value != "application/problem+json")
        );
    }

    #[tokio::test]
    async fn the_layer_renders_the_frameworks_bare_errors() {
        let missing = app()
            .oneshot(Request::get("/nowhere").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing.headers()[CONTENT_TYPE], "application/problem+json");
        assert_eq!(body_json(missing).await["code"], "not-found");

        let wrong_method = app()
            .oneshot(Request::post("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(wrong_method.headers()[ALLOW].to_str().unwrap().contains("GET"));
        assert_eq!(body_json(wrong_method).await["code"], "method-not-allowed");
    }
}
