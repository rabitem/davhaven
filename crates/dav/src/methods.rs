//! Method handlers: OPTIONS, GET, HEAD, PUT, DELETE, MOVE, COPY, MKCALENDAR, MKCOL, PROPFIND, PROPPATCH and the
//! routing of REPORT.
//!
//! Every URL of the DAV namespace (PLAN 2.5) is served by one dispatcher that first classifies the path with
//! `ResourcePath::parse` (the one parser of DAV URLs) and then decides by method:
//!
//! 1. a path that names no resource answers **404** (the same for unknown sections, malformed segments and other
//!    tenants' paths that parse; resource existence is the services' business);
//! 2. a method that is not defined for this kind of resource answers **405** with `Allow` ([`allowed_methods`]);
//! 3. `OPTIONS` answers **200** with `Allow` and the `DAV` capability header;
//! 4. every other defined method is answered by the handler of this crate that implements it, which calls the
//!    application services and renders their answers. Sharing invitations, the outbox, the listings of the inbox
//!    and the notification collection and principal search are reached through the hooks of `collaboration`, the
//!    items of both collections are served by [`crate::scheduling`] and [`crate::notifications`] directly. A
//!    service that is not there (`Unsupported`) answers **501 Not Implemented**: a client learns that the server
//!    does not support it rather than that the resource is wrong.
//!
//! # Handlers
//!
//! | Method | Resources | Module |
//! | --- | --- | --- |
//! | `PROPFIND` | every resource | `propfind` |
//! | `PROPPATCH` | calendar collections (binding properties), objects, the home and the inbox (always refused) | `proppatch` |
//! | `GET`, `HEAD`, `PUT`, `DELETE`, `MOVE`, `COPY` | calendar objects | `object` |
//! | `MKCALENDAR`, extended `MKCOL`, `DELETE` | calendar collections | `collection` |
//! | `REPORT` | collections and principals | [`crate::reports`] |
//! | `POST`, the members of the inbox and of the notification collection, principal search | | `collaboration` |
//! | `GET`, `HEAD`, `DELETE` of inbox items and notifications | | [`crate::scheduling`], [`crate::notifications`] |
//!
//! A handler returns `Result<Response, EdgeProblem>`: failures are never rendered where they happen, the
//! `DavProblems` renderer of the edge gives them their DAV form ([`crate::errors`]). A 405 always carries `Allow`.
//!
//! # Visibility comes first
//!
//! Resources the caller cannot see answer 404 (PLAN 2.6). A handler that refuses a request for a reason of its own
//! (a protected property, an invalid value, a body that makes no sense) asks the services whether the resource is
//! visible before it says so, so that such a refusal never tells the caller that a resource exists. Refusals that
//! look at the shape of the request alone (`Depth`, a header that cannot be read, the media type of a report, a
//! sync token that is no token) come first and are the same for every resource, visible or not.
//!
//! # Bounds
//!
//! The XML reader runs on the blocking pool with the wall-clock budget of the iCalendar layer (`time_budget_ms`,
//! `Call::parse_xml`); answers are cut off at `max_response_bytes` with a 507 entry for the request URI
//! (`Call::response_budget`).
//!
//! # Conditional headers
//!
//! Writes evaluate `If-Schedule-Tag-Match`, `If-Match` and `If-None-Match: *` in the services (PLAN 2.7), reads
//! (`GET`, `HEAD`) answer `If-None-Match` with 304 and a failed `If-Match` with 412 here. The `If` header of
//! RFC 4918 (lock tokens) and `If-None-Match` with entity tags on writes are not supported; see
//! `docs/interop.md`.

use core::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use davhaven_app::AppServices;
use davhaven_app::services::CalendarDataSpec;
use davhaven_domain::{Limits, RequestContext, ResourcePath};
use davhaven_http::limits::read_body;
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::errors::dav_status;
use crate::router::DavState;
use crate::xml::requests::{MakeKind, PropRequest};
use crate::xml::write::Multistatus;
use crate::xml::{Element, parse};
use crate::{notifications, scheduling};

pub(crate) mod collaboration;
mod collection;
mod headers;
mod object;
mod propfind;
mod proppatch;
mod representation;

pub(crate) use headers::minimal_requested;
pub(crate) use representation::{Representation, read_text_body, represent};

/// The value of the `DAV` response header: the compliance classes and the extensions Davhaven implements
/// (RFC 4918 classes 1 and 3, RFC 4791 `calendar-access`, RFC 6638 `calendar-auto-schedule`, RFC 5689
/// `extended-mkcol` and the CalendarServer sharing and principal search extensions).
///
/// The scheduling, sharing and principal search features are advertised as a whole: they are the contents of
/// [`crate::sharing`], [`crate::scheduling`], [`crate::notifications`] and [`crate::principals_search`].
pub const DAV_HEADER: &str = "1, 3, calendar-access, calendar-auto-schedule, extended-mkcol, calendarserver-sharing, \
                              calendarserver-principal-search";

/// The methods defined for a resource of this kind.
///
/// `MKCALENDAR` and `MKCOL` are defined on collection paths because they create the collection at the URL they are
/// sent to. Methods outside the list answer 405. `LOCK` and `UNLOCK` are in no list: WebDAV class 2 is a non-goal
/// (PLAN 1). `PROPPATCH` is defined on the home and the inbox because clients set properties there (default alarms,
/// the default calendar for invitations); the data model has no properties of a home, so every property is refused.
pub fn allowed_methods(resource: &ResourcePath) -> &'static [&'static str] {
    match resource {
        ResourcePath::Home { .. } => &[
            "OPTIONS",
            "PROPFIND",
            "PROPPATCH",
            "REPORT",
            "MKCALENDAR",
            "MKCOL",
            "POST",
        ],
        ResourcePath::Collection { .. } => &[
            "OPTIONS",
            "PROPFIND",
            "PROPPATCH",
            "REPORT",
            "MKCALENDAR",
            "MKCOL",
            "DELETE",
            "POST",
        ],
        ResourcePath::Object { .. } => &[
            "OPTIONS",
            "GET",
            "HEAD",
            "PUT",
            "DELETE",
            "MOVE",
            "COPY",
            "PROPFIND",
            "PROPPATCH",
        ],
        ResourcePath::Inbox { .. } => &["OPTIONS", "PROPFIND", "PROPPATCH", "REPORT"],
        ResourcePath::Root | ResourcePath::Principal { .. } | ResourcePath::Notifications { .. } => {
            &["OPTIONS", "PROPFIND", "REPORT"]
        }
        ResourcePath::Outbox { .. } => &["OPTIONS", "PROPFIND", "POST"],
        ResourcePath::InboxItem { .. } | ResourcePath::Notification { .. } => {
            &["OPTIONS", "GET", "HEAD", "PROPFIND", "DELETE"]
        }
    }
}

/// The `Allow` header value of a resource: its methods, comma separated.
pub fn allow_header(resource: &ResourcePath) -> String {
    allowed_methods(resource).join(", ")
}

/// The answer to `OPTIONS`: 200 without a body, `Allow` for the resource and the `DAV` header.
fn options(resource: &ResourcePath) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    if let Ok(allow) = HeaderValue::from_str(&allow_header(resource)) {
        headers.insert(ALLOW, allow);
    }
    headers.insert(HeaderName::from_static("dav"), HeaderValue::from_static(DAV_HEADER));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}

/// Runs CPU-bound work on the blocking pool and gives it `budget` of wall-clock time (PLAN 2.15, R14).
///
/// # Errors
///
/// 503 with `Retry-After` when the budget is spent (the work is left to finish on its thread, its result is
/// dropped), 500 when the work panicked, and whatever problem the work returns.
pub(crate) async fn run_blocking<T, F>(budget: Duration, work: F) -> Result<T, EdgeProblem>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, EdgeProblem> + Send + 'static,
{
    match tokio::time::timeout(budget, tokio::task::spawn_blocking(work)).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(EdgeProblem::new(ProblemCode::Internal)),
        Err(_) => Err(EdgeProblem::new(ProblemCode::Unavailable)
            .with_detail("The request took too long to read.")
            .with_retry_after(Duration::from_secs(1))),
    }
}

/// One request being served: the services, who asks, what was addressed and the request head.
pub(crate) struct Call<'a> {
    /// The application services.
    pub(crate) state: &'a DavState,
    /// The authenticated context.
    pub(crate) ctx: &'a RequestContext,
    /// The resource the URL names.
    pub(crate) resource: &'a ResourcePath,
    /// The request head: method, URI and headers.
    pub(crate) parts: &'a Parts,
}

impl Call<'_> {
    /// The application services.
    pub(crate) fn services(&self) -> &AppServices {
        &self.state.services
    }

    /// The configured limits.
    pub(crate) fn limits(&self) -> &Limits {
        &self.state.services.limits
    }

    /// The request headers.
    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    /// Reads an XML body, which may not be larger than `max_request_body` (413).
    pub(crate) async fn xml_body(&self, body: Body) -> Result<Bytes, EdgeProblem> {
        let limit = usize::try_from(self.limits().dav.max_request_body).unwrap_or(usize::MAX);
        Ok(read_body(body, limit).await?)
    }

    /// The wall-clock budget of work that parses what a client sent (`ical.time_budget_ms`).
    fn time_budget(&self) -> Duration {
        Duration::from_millis(self.limits().ical.time_budget_ms)
    }

    /// Reads an XML document on the blocking pool, under the limits of PLAN 2.15 and the time budget.
    ///
    /// # Errors
    ///
    /// 400 for a document that breaks a limit or is not well-formed, 503 when the budget is spent.
    pub(crate) async fn parse_xml(&self, bytes: Bytes) -> Result<Element, EdgeProblem> {
        let limits = self.limits().dav.clone();
        run_blocking(self.time_budget(), move || {
            parse(&bytes, &limits).map_err(EdgeProblem::from)
        })
        .await
    }

    /// The most bytes a `multistatus` answer may have (`max_response_bytes`).
    pub(crate) fn response_budget(&self) -> usize {
        usize::try_from(self.limits().dav.max_response_bytes).unwrap_or(usize::MAX)
    }

    /// Closes an answer that was cut off at the budget: a 507 entry for the request URI.
    pub(crate) fn truncated(&self, multistatus: &mut Multistatus) {
        multistatus.status_response(&self.resource.format(), 507, Some("number-of-matches-within-limits"));
    }
}

/// An empty response with a status.
pub(crate) fn status_only(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

/// A `207 Multi-Status` response with the XML document; `minimal` adds `Preference-Applied: return=minimal`.
pub(crate) fn multistatus_response(document: String, minimal: bool) -> Response {
    let mut response = Response::new(Body::from(document));
    *response.status_mut() = StatusCode::MULTI_STATUS;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if minimal {
        headers.insert(
            HeaderName::from_static("preference-applied"),
            HeaderValue::from_static("return=minimal"),
        );
    }
    response
}

/// Sets a header, skipping values that are not valid header text.
pub(crate) fn set_header(response: &mut Response, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().insert(name, value);
    }
}

/// The 501 of a conditional header the services cannot express (`If-None-Match` with entity tags on a write, the
/// `If` header of RFC 4918).
pub(crate) fn not_implemented(detail: &'static str) -> EdgeProblem {
    EdgeProblem::new(ProblemCode::NotImplemented).with_detail(detail)
}

/// What `calendar-data` of a request asks for: nothing unless the request names the property.
pub(crate) fn data_spec(request: &PropRequest) -> CalendarDataSpec {
    match request {
        PropRequest::Prop(list) | PropRequest::AllProp(list) => {
            list.calendar_data
                .clone()
                .map_or_else(CalendarDataSpec::metadata_only, |projection| CalendarDataSpec {
                    include_data: true,
                    projection,
                })
        }
        PropRequest::PropName => CalendarDataSpec::metadata_only(),
    }
}

/// Serves one request of the DAV namespace; see the module documentation for the order of the decisions.
pub(crate) async fn dispatch(State(state): State<DavState>, request: Request) -> Response {
    match route(&state, request).await {
        Ok(response) => response,
        Err(problem) => problem.into_response(),
    }
}

/// A 405 always carries `Allow` (RFC 9110 section 15.5.6), whichever layer answered it.
fn with_allow(problem: EdgeProblem, resource: &ResourcePath) -> EdgeProblem {
    if dav_status(problem.code()) == 405 && problem.allow().is_none() {
        problem.with_allow(allow_header(resource))
    } else {
        problem
    }
}

async fn route(state: &DavState, request: Request) -> Result<Response, EdgeProblem> {
    let (parts, body) = request.into_parts();
    let resource = ResourcePath::parse(parts.uri.path()).map_err(|_| EdgeProblem::new(ProblemCode::NotFound))?;
    let method = parts.method.as_str();
    if !allowed_methods(&resource).contains(&method) {
        return Err(EdgeProblem::new(ProblemCode::MethodNotAllowed).with_allow(allow_header(&resource)));
    }
    if method == "OPTIONS" {
        return Ok(options(&resource));
    }
    let ctx = parts
        .extensions
        .get::<RequestContext>()
        .ok_or_else(|| EdgeProblem::new(ProblemCode::Unauthenticated))?;
    let call = Call {
        state,
        ctx,
        resource: &resource,
        parts: &parts,
    };
    let served = match (method, &resource) {
        ("PROPFIND", _) => propfind::handle(&call, body).await,
        ("PROPPATCH", _) => proppatch::handle(&call, body).await,
        ("REPORT", _) => crate::reports::handle(&call, body).await,
        ("GET" | "HEAD", ResourcePath::Object { .. }) => object::get(&call, method == "HEAD").await,
        ("PUT", ResourcePath::Object { .. }) => object::put(&call, body).await,
        ("DELETE", ResourcePath::Object { .. }) => object::delete(&call).await,
        ("MOVE", ResourcePath::Object { .. }) => object::relocate(&call, object::Relocation::Move).await,
        ("COPY", ResourcePath::Object { .. }) => object::relocate(&call, object::Relocation::Copy).await,
        ("DELETE", ResourcePath::Collection { .. }) => collection::delete(&call).await,
        ("MKCALENDAR", _) => collection::make(&call, body, MakeKind::MkCalendar).await,
        ("MKCOL", _) => collection::make(&call, body, MakeKind::ExtendedMkcol).await,
        ("POST", _) => collaboration::post(&call, body).await,
        ("GET" | "HEAD", ResourcePath::Notification { .. }) => notifications::get(&call, method == "HEAD").await,
        ("DELETE", ResourcePath::Notification { .. }) => notifications::delete(&call).await,
        ("GET" | "HEAD", ResourcePath::InboxItem { .. }) => scheduling::get(&call, method == "HEAD").await,
        ("DELETE", ResourcePath::InboxItem { .. }) => scheduling::delete(&call).await,
        // The method table admits only the methods above, so this is not reached; a method added to the table
        // without a handler is a 405 and not a hang or a panic.
        _ => Err(EdgeProblem::new(ProblemCode::MethodNotAllowed)),
    };
    served.map_err(|problem| with_allow(problem, &resource))
}

#[cfg(test)]
mod tests {
    use davhaven_domain::{CalendarSlug, ObjectUri, PrincipalName, TenantSlug};

    use super::*;

    fn tenant() -> TenantSlug {
        TenantSlug::parse("acme").unwrap()
    }

    fn principal() -> PrincipalName {
        PrincipalName::parse("anna").unwrap()
    }

    fn every_resource() -> Vec<(&'static str, ResourcePath)> {
        let uri = ObjectUri::parse("a.ics").unwrap();
        vec![
            ("root", ResourcePath::Root),
            (
                "principal",
                ResourcePath::Principal {
                    tenant: tenant(),
                    principal: principal(),
                },
            ),
            (
                "home",
                ResourcePath::Home {
                    tenant: tenant(),
                    principal: principal(),
                },
            ),
            (
                "collection",
                ResourcePath::Collection {
                    tenant: tenant(),
                    principal: principal(),
                    binding: CalendarSlug::parse("work").unwrap(),
                },
            ),
            (
                "object",
                ResourcePath::Object {
                    tenant: tenant(),
                    principal: principal(),
                    binding: CalendarSlug::parse("work").unwrap(),
                    object: uri.clone(),
                },
            ),
            (
                "inbox",
                ResourcePath::Inbox {
                    tenant: tenant(),
                    principal: principal(),
                },
            ),
            (
                "outbox",
                ResourcePath::Outbox {
                    tenant: tenant(),
                    principal: principal(),
                },
            ),
            (
                "notifications",
                ResourcePath::Notifications {
                    tenant: tenant(),
                    principal: principal(),
                },
            ),
            (
                "notification",
                ResourcePath::Notification {
                    tenant: tenant(),
                    principal: principal(),
                    uri: uri.clone(),
                },
            ),
            (
                "inbox item",
                ResourcePath::InboxItem {
                    tenant: tenant(),
                    principal: principal(),
                    uri,
                },
            ),
        ]
    }

    #[test]
    fn the_method_table_of_every_resource_kind() {
        let expected: [(&str, &[&str]); 10] = [
            ("root", &["OPTIONS", "PROPFIND", "REPORT"]),
            ("principal", &["OPTIONS", "PROPFIND", "REPORT"]),
            (
                "home",
                &[
                    "OPTIONS",
                    "PROPFIND",
                    "PROPPATCH",
                    "REPORT",
                    "MKCALENDAR",
                    "MKCOL",
                    "POST",
                ],
            ),
            (
                "collection",
                &[
                    "OPTIONS",
                    "PROPFIND",
                    "PROPPATCH",
                    "REPORT",
                    "MKCALENDAR",
                    "MKCOL",
                    "DELETE",
                    "POST",
                ],
            ),
            (
                "object",
                &[
                    "OPTIONS",
                    "GET",
                    "HEAD",
                    "PUT",
                    "DELETE",
                    "MOVE",
                    "COPY",
                    "PROPFIND",
                    "PROPPATCH",
                ],
            ),
            ("inbox", &["OPTIONS", "PROPFIND", "PROPPATCH", "REPORT"]),
            ("outbox", &["OPTIONS", "PROPFIND", "POST"]),
            ("notifications", &["OPTIONS", "PROPFIND", "REPORT"]),
            ("notification", &["OPTIONS", "GET", "HEAD", "PROPFIND", "DELETE"]),
            ("inbox item", &["OPTIONS", "GET", "HEAD", "PROPFIND", "DELETE"]),
        ];
        let resources = every_resource();
        assert_eq!(resources.len(), expected.len());
        for ((name, resource), (expected_name, methods)) in resources.iter().zip(expected) {
            assert_eq!(*name, expected_name);
            assert_eq!(allowed_methods(resource), methods, "{name}");
        }
    }

    #[test]
    fn every_resource_answers_options_and_none_allows_locking() {
        for (name, resource) in every_resource() {
            let methods = allowed_methods(&resource);
            assert!(methods.contains(&"OPTIONS"), "{name}");
            assert!(methods.contains(&"PROPFIND"), "{name}");
            assert!(!methods.contains(&"LOCK") && !methods.contains(&"UNLOCK"), "{name}");
            assert!(!methods.contains(&"PATCH") && !methods.contains(&"TRACE"), "{name}");
            assert_eq!(allow_header(&resource), methods.join(", "));
        }
    }

    #[test]
    fn options_advertises_the_methods_and_the_capabilities() {
        let response = options(&ResourcePath::Root);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[ALLOW], "OPTIONS, PROPFIND, REPORT");
        let dav = response.headers()["dav"].to_str().unwrap();
        for token in ["1", "3", "calendar-access", "calendar-auto-schedule", "extended-mkcol"] {
            assert!(dav.split(", ").any(|part| part == token), "{token} in {dav}");
        }
        assert_eq!(response.headers()[CONTENT_LENGTH], "0");
    }

    #[test]
    fn multistatus_responses_carry_the_preference_that_was_applied() {
        let plain = multistatus_response("<x/>".to_owned(), false);
        assert_eq!(plain.status(), StatusCode::MULTI_STATUS);
        assert_eq!(plain.headers()[CONTENT_TYPE], "application/xml; charset=utf-8");
        assert!(plain.headers().get("preference-applied").is_none());
        let minimal = multistatus_response("<x/>".to_owned(), true);
        assert_eq!(minimal.headers()["preference-applied"], "return=minimal");
    }

    #[test]
    fn calendar_data_is_wanted_only_when_it_is_named() {
        use crate::xml::requests::PropList;
        use davhaven_app::services::PropertyName;
        let none = PropRequest::Prop(PropList {
            names: vec![PropertyName::new("DAV:", "getetag")],
            calendar_data: None,
        });
        assert!(!data_spec(&none).include_data);
        assert!(!data_spec(&PropRequest::PropName).include_data);
        let wanted = PropRequest::Prop(PropList {
            names: Vec::new(),
            calendar_data: Some(davhaven_app::services::Projection::default()),
        });
        assert!(data_spec(&wanted).include_data);
    }

    #[test]
    fn every_405_carries_the_methods_of_the_resource() {
        let collection = every_resource()
            .into_iter()
            .find(|(name, _)| *name == "collection")
            .unwrap()
            .1;
        for code in [ProblemCode::MethodNotAllowed, ProblemCode::ResourceExists] {
            let problem = with_allow(EdgeProblem::new(code), &collection);
            assert_eq!(problem.allow(), Some(allow_header(&collection).as_str()), "{code:?}");
        }
        let own = with_allow(
            EdgeProblem::new(ProblemCode::MethodNotAllowed).with_allow("OPTIONS"),
            &collection,
        );
        assert_eq!(own.allow(), Some("OPTIONS"), "an Allow that is set stays");
        assert_eq!(
            with_allow(EdgeProblem::new(ProblemCode::Forbidden), &collection).allow(),
            None
        );
    }

    #[tokio::test]
    async fn blocking_work_runs_off_the_executor_and_answers() {
        let answer = run_blocking(Duration::from_secs(5), || Ok(21 * 2)).await;
        assert_eq!(answer.unwrap(), 42);
        let refused = run_blocking(Duration::from_secs(5), || -> Result<(), EdgeProblem> {
            Err(EdgeProblem::new(ProblemCode::BadRequest))
        })
        .await;
        assert_eq!(refused.unwrap_err().code(), ProblemCode::BadRequest);
    }

    #[tokio::test(start_paused = true)]
    async fn blocking_work_that_overruns_its_budget_is_a_503_with_retry_after() {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let task = tokio::spawn(run_blocking(Duration::from_secs(2), move || {
            // A thread that is stuck: the budget decides, not the work.
            let _ = wait.recv_timeout(Duration::from_secs(10));
            Ok(())
        }));
        // The clock is paused, so the budget runs out when the test says so: first let the task start its timer.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        let problem = task.await.unwrap().unwrap_err();
        assert_eq!(problem.code(), ProblemCode::Unavailable);
        assert!(problem.retry_after().is_some());
        let _ = release.send(());
    }

    #[tokio::test]
    async fn blocking_work_that_panics_is_a_500_and_not_a_crash() {
        let work = || -> Result<(), EdgeProblem> { panic!("a bug in the work") };
        let answer = run_blocking(Duration::from_secs(5), work).await;
        assert_eq!(answer.unwrap_err().code(), ProblemCode::Internal);
    }
}
