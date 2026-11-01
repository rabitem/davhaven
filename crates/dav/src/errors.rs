//! Mapping of application errors to DAV status codes and precondition elements.
//!
//! A failure a DAV client sees is a row of the problem catalog ([`ProblemCode`]) in its DAV form (PLAN F0.4,
//! `docs/problems.md`): a status code and, for the CalDAV and WebDAV preconditions, the element that names the
//! violated condition in an RFC 4918 `DAV:error` body. The translation happens exactly once:
//!
//! 1. `EdgeProblem::from_app_error` picks the row from the error's precondition or kind and keeps the precondition
//!    with its payload (the hrefs of `DAV:need-privileges`, `CALDAV:no-uid-conflict`, ...);
//! 2. [`dav_status`] is this crate's table from row to DAV status, an exhaustive `match`; [`DavProblems`] renders the
//!    status and the `DAV:error` body.
//!
//! Internal error text never reaches a client: the body contains element names and the hrefs the application puts
//! into a precondition, nothing else. By contract those hrefs name resources the caller may read (the conflicting
//! object of `no-uid-conflict` lies in the collection the caller writes to; the application replaces the href of a
//! `unique-scheduling-object-resource` conflict in a calendar the caller cannot read, see `ObjectService::put`), so
//! the body discloses nothing the caller could not see. Statuses that need no body (401, 404, 501, ...) are sent
//! with an empty one.
//!
//! # Conditions the DAV layer finds itself
//!
//! Four answers are about the shape of the request, and the application never reports them: `unsupported-report` (403
//! `DAV:supported-report`), `too-many-hrefs` (403 `DAV:number-of-matches-within-limits`, the hrefs of a multiget and
//! the sharees of a share request), `sync-traversal-unsupported` (403 `DAV:sync-traversal-supported`) and
//! `foreign-destination` (502, a destination on another server). They are rows of the catalog like every other
//! failure, so that every protocol crate maps them in its exhaustive table and the problem catalog is complete; the
//! handlers answer them with `EdgeProblem::new(ProblemCode::...)`. The statuses follow the RFCs where an RFC gives
//! one (RFC 4918 sections 9.8.5, 9.9.4 and 16; RFC 6578 gives none for `sync-traversal-supported` and the status that
//! RFC 4918 section 16 uses with a precondition element is 403) and are documented in `docs/interop.md`: the
//! limit of `calendar-multiget` is 403 whether the DAV layer or the application finds it (the application reports
//! `number-of-matches-within-limits`, which maps to `too-many-matches` and 507 and is turned into `too-many-hrefs`
//! by the multiget handler), where a query or a synchronization that matches too much is 507.

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use core::fmt::Write as _;
use davhaven_domain::{Precondition, Privilege, RequestId};
use davhaven_http::problem::{EdgeProblem, ProblemCode, ProblemRenderer, apply_problem_headers};

use crate::xml::write::escape_text;

pub use davhaven_app::services::{NS_CALDAV, NS_CALENDARSERVER, NS_DAV};

/// The status a DAV client receives for a problem row.
pub const fn dav_status(code: ProblemCode) -> u16 {
    match code {
        ProblemCode::BadRequest
        | ProblemCode::ValidationFailed
        | ProblemCode::IdempotencyKeyReuse
        | ProblemCode::InvalidSchedulingMessage => 400,
        ProblemCode::Unauthenticated => 401,
        ProblemCode::Forbidden
        | ProblemCode::FeatureNotEnabled
        | ProblemCode::InvalidCalendarData
        | ProblemCode::InvalidCalendarObject
        | ProblemCode::UnsupportedCalendarComponent
        | ProblemCode::UnsupportedCalendarData
        | ProblemCode::UidConflict
        | ProblemCode::ResourceTooLarge
        | ProblemCode::DateTooEarly
        | ProblemCode::DateTooLate
        | ProblemCode::TooManyInstances
        | ProblemCode::TooManyAttendees
        | ProblemCode::SchedulingUidConflict
        | ProblemCode::OrganizerMismatch
        | ProblemCode::OrganizerNotAllowed
        | ProblemCode::OrganizerChangeNotAllowed
        | ProblemCode::AttendeeChangeNotAllowed
        | ProblemCode::SyncTokenExpired
        | ProblemCode::DepthInfinityRefused
        | ProblemCode::InvalidFilter
        | ProblemCode::ProtectedProperty
        | ProblemCode::SharingNotAllowed
        | ProblemCode::InvalidSharee
        | ProblemCode::UnsupportedReport
        | ProblemCode::TooManyHrefs
        | ProblemCode::SyncTraversalUnsupported => 403,
        ProblemCode::NotFound => 404,
        ProblemCode::MethodNotAllowed | ProblemCode::ResourceExists => 405,
        ProblemCode::Conflict
        | ProblemCode::IdempotencyInProgress
        | ProblemCode::SecretNotReplayable
        | ProblemCode::NameReserved
        | ProblemCode::ExternalRefReserved
        | ProblemCode::AddressReserved => 409,
        ProblemCode::PreconditionFailed => 412,
        ProblemCode::PayloadTooLarge => 413,
        ProblemCode::UnsupportedMediaType => 415,
        ProblemCode::PreconditionRequired => 428,
        ProblemCode::RateLimited => 429,
        ProblemCode::Internal => 500,
        ProblemCode::NotImplemented => 501,
        ProblemCode::ForeignDestination => 502,
        ProblemCode::Unavailable => 503,
        ProblemCode::TooManyMatches => 507,
    }
}

/// The namespace prefix of the namespace token the catalog uses in `dav_element()` (`DAV`, `CALDAV`); the root
/// element of the body declares the prefixes.
fn namespace(token: &str) -> Option<&'static str> {
    match token {
        "DAV" => Some("D"),
        "CALDAV" => Some("C"),
        _ => None,
    }
}

/// The response prefix and local name of the element of a privilege (`("D", "read")`, `("C", "read-free-busy")`).
pub const fn privilege_element(privilege: Privilege) -> (&'static str, &'static str) {
    match privilege {
        Privilege::Read => ("D", "read"),
        Privilege::ReadCurrentUserPrivilegeSet => ("D", "read-current-user-privilege-set"),
        Privilege::ReadFreeBusy => ("C", "read-free-busy"),
        Privilege::WriteContent => ("D", "write-content"),
        Privilege::WriteProperties => ("D", "write-properties"),
        Privilege::Bind => ("D", "bind"),
        Privilege::Unbind => ("D", "unbind"),
        Privilege::Share => ("CS", "share"),
        Privilege::ScheduleSend => ("C", "schedule-send"),
        Privilege::ScheduleDeliver => ("C", "schedule-deliver"),
    }
}

/// The content of the precondition element: the hrefs and privileges the condition is about.
fn element_content(precondition: &Precondition) -> String {
    match precondition {
        Precondition::NeedPrivileges(needed) => {
            let mut content = String::new();
            for (href, privilege) in needed {
                let (prefix, local) = privilege_element(*privilege);
                let _ = write!(
                    content,
                    "<D:resource><D:href>{}</D:href><D:privilege><{prefix}:{local}/></D:privilege></D:resource>",
                    escape_text(href.as_str())
                );
            }
            content
        }
        Precondition::NoUidConflict(href)
        | Precondition::UniqueSchedulingObjectResource(href)
        | Precondition::InvalidSharee(href) => format!("<D:href>{}</D:href>", escape_text(href.as_str())),
        _ => String::new(),
    }
}

/// A `DAV:error` document around `inner` (the precondition element, with the prefixes `D`, `C` and `CS` declared on
/// the root). Every error body of the DAV surface is made here.
pub fn error_document(inner: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error xmlns:D=\"{NS_DAV}\" xmlns:C=\"{NS_CALDAV}\" \
         xmlns:CS=\"{NS_CALENDARSERVER}\">{inner}</D:error>\n"
    )
}

/// The precondition element of a problem, written with the prefixes `D` and `C` that [`error_document`] and every
/// `multistatus` declare on their root, when the row of the problem names one.
///
/// The element comes from the catalog (`DAV:need-privileges`, `CALDAV:valid-calendar-data`, ...); the payload from
/// the precondition of the application error that caused the problem. It is what goes into a `DAV:error` element,
/// whether that is the body of an answer ([`error_body`]) or the error of one `response` of a `multistatus` (the
/// sharees of a `CS:share` request that were refused).
pub fn precondition_element(problem: &EdgeProblem) -> Option<PreconditionElement> {
    catalog_element(problem.code(), problem.precondition())
}

/// The element the catalog names for `code`, with the payload of `precondition` (the hrefs and privileges the
/// condition is about), written with the prefixes of the root of a document: the one place where a catalog token
/// (`DAV`, `CALDAV`) becomes a namespace prefix. `None` when the row names no element or a token that has no
/// prefix here.
pub(crate) fn catalog_element(code: ProblemCode, precondition: Option<&Precondition>) -> Option<PreconditionElement> {
    let (token, local) = code.dav_element()?.split_once(':')?;
    let prefix = namespace(token)?;
    let content = precondition.map(element_content).unwrap_or_default();
    Some(PreconditionElement(if content.is_empty() {
        format!("<{prefix}:{local}/>")
    } else {
        format!("<{prefix}:{local}>{content}</{prefix}:{local}>")
    }))
}

/// The XML of the element of a `DAV:error` that names a precondition, with its content escaped.
///
/// It is made by [`precondition_element`] (from the catalog and the precondition of an application error) and by
/// the crate's own constructor for a `DAV:` element that has no content, and by nothing else: the `multistatus`
/// builder takes no other markup for the error of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreconditionElement(String);

impl PreconditionElement {
    /// A `DAV:` element without content, such as `number-of-matches-within-limits`.
    pub(crate) fn dav(local: &'static str) -> Self {
        Self(format!("<D:{local}/>"))
    }

    /// The element as XML text, with the prefixes `D`, `C` and `CS` of the root of the document.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `DAV:error` body of a problem, when its row names a precondition element (see [`precondition_element`]).
pub fn error_body(problem: &EdgeProblem) -> Option<String> {
    precondition_element(problem).map(|element| error_document(element.as_str()))
}

/// The renderer of the DAV surface: the DAV status of the row, the `DAV:error` body when the row has a precondition
/// element, and the headers the problem asks for. 401 carries the problem's own `Basic` challenge (the tenant as
/// realm) or the server-wide one.
#[derive(Debug, Clone, Copy, Default)]
pub struct DavProblems;

impl ProblemRenderer for DavProblems {
    fn render(&self, problem: &EdgeProblem, _request_id: Option<RequestId>) -> Response {
        let status = StatusCode::from_u16(dav_status(problem.code())).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = match error_body(problem) {
            Some(body) => {
                let mut response = Response::new(Body::from(body));
                response
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
                response
            }
            None => Response::new(Body::empty()),
        };
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        let challenge = HeaderValue::from_static("Basic realm=\"davhaven\", charset=\"UTF-8\"");
        apply_problem_headers(&mut response, problem, Some(&challenge));
        response
    }
}

#[cfg(test)]
mod tests {
    use axum::http::header::{ALLOW, RETRY_AFTER, WWW_AUTHENTICATE};
    use davhaven_app::AppError;
    use davhaven_domain::{ErrorKind, Href};
    use http_body_util::BodyExt as _;

    use super::*;

    /// The DAV status of every row, written down independently of the table under test (PLAN F0.4 and the
    /// `dav` column of the catalog).
    const EXPECTED: [(&str, u16); 50] = [
        ("bad-request", 400),
        ("unauthenticated", 401),
        ("forbidden", 403),
        ("not-found", 404),
        ("method-not-allowed", 405),
        ("conflict", 409),
        ("precondition-failed", 412),
        ("precondition-required", 428),
        ("payload-too-large", 413),
        ("unsupported-media-type", 415),
        ("validation-failed", 400),
        ("rate-limited", 429),
        ("internal", 500),
        ("not-implemented", 501),
        ("unavailable", 503),
        ("idempotency-key-reuse", 400),
        ("idempotency-in-progress", 409),
        ("secret-not-replayable", 409),
        ("feature-not-enabled", 403),
        ("invalid-calendar-data", 403),
        ("invalid-calendar-object", 403),
        ("unsupported-calendar-component", 403),
        ("unsupported-calendar-data", 403),
        ("uid-conflict", 403),
        ("resource-too-large", 403),
        ("date-too-early", 403),
        ("date-too-late", 403),
        ("too-many-instances", 403),
        ("too-many-attendees", 403),
        ("scheduling-uid-conflict", 403),
        ("organizer-mismatch", 403),
        ("organizer-not-allowed", 403),
        ("organizer-change-not-allowed", 403),
        ("attendee-change-not-allowed", 403),
        ("invalid-scheduling-message", 400),
        ("sync-token-expired", 403),
        ("too-many-matches", 507),
        ("depth-infinity-refused", 403),
        ("invalid-filter", 403),
        ("resource-exists", 405),
        ("protected-property", 403),
        ("sharing-not-allowed", 403),
        ("invalid-sharee", 403),
        ("name-reserved", 409),
        ("external-ref-reserved", 409),
        ("address-reserved", 409),
        ("unsupported-report", 403),
        ("too-many-hrefs", 403),
        ("sync-traversal-unsupported", 403),
        ("foreign-destination", 502),
    ];

    #[test]
    fn the_table_covers_every_row_and_agrees_with_the_catalog() {
        assert_eq!(EXPECTED.len(), ProblemCode::ALL.len(), "a row was added to the catalog");
        for code in ProblemCode::ALL {
            let expected = EXPECTED
                .iter()
                .find(|(text, _)| *text == code.code())
                .unwrap_or_else(|| panic!("{} is missing from the expectations", code.code()));
            assert_eq!(dav_status(*code), expected.1, "{}", code.code());
            assert_eq!(
                dav_status(*code),
                code.dav_status(),
                "{} differs from the catalog",
                code.code()
            );
        }
    }

    #[test]
    fn every_catalog_element_has_a_known_namespace() {
        for code in ProblemCode::ALL {
            if let Some(element) = code.dav_element() {
                let (token, local) = element.split_once(':').unwrap();
                assert!(namespace(token).is_some(), "{element}");
                assert_ne!(local, "");
            }
        }
        assert_eq!(namespace("DAV"), Some("D"));
        assert_eq!(namespace("CALDAV"), Some("C"));
        assert_eq!(namespace("OTHER"), None);
    }

    #[test]
    fn privileges_have_their_dav_element_names() {
        for privilege in Privilege::ALL {
            let (prefix, local) = privilege_element(*privilege);
            assert_eq!(local, privilege.as_str(), "{privilege}");
            assert!(matches!(prefix, "D" | "C" | "CS"));
        }
        assert_eq!(privilege_element(Privilege::ReadFreeBusy).0, "C");
        assert_eq!(privilege_element(Privilege::Share).0, "CS");
    }

    async fn render(problem: EdgeProblem) -> (Response, String) {
        let mut response = DavProblems.render(&problem, None);
        let body = std::mem::take(response.body_mut());
        let bytes = body.collect().await.unwrap().to_bytes();
        (response, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn rows_with_an_element_get_a_dav_error_body_and_the_others_an_empty_one() {
        for code in ProblemCode::ALL {
            let (response, body) = render(EdgeProblem::new(*code)).await;
            assert_eq!(response.status().as_u16(), dav_status(*code), "{}", code.code());
            if let Some(element) = code.dav_element() {
                let (_, local) = element.split_once(':').unwrap();
                assert!(body.contains(&format!(":{local}")), "{} in {body}", code.code());
                assert!(body.contains("<D:error"), "{body}");
                assert_eq!(response.headers()[CONTENT_TYPE], "application/xml; charset=utf-8");
            } else {
                assert_eq!(body, "", "{}", code.code());
                assert!(response.headers().get(CONTENT_TYPE).is_none(), "{}", code.code());
            }
        }
    }

    #[tokio::test]
    async fn need_privileges_names_the_resource_and_the_privilege() {
        let href = Href::parse("/dav/calendars/acme/anna/work/a&b.ics").unwrap();
        let error = AppError::need_privilege(href, Privilege::WriteContent);
        let (response, body) = render(EdgeProblem::from(error)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(body.contains("<D:need-privileges>"), "{body}");
        assert!(
            body.contains("<D:resource><D:href>/dav/calendars/acme/anna/work/a&amp;b.ics</D:href>"),
            "{body}"
        );
        assert!(body.contains("<D:privilege><D:write-content/></D:privilege>"), "{body}");
    }

    #[tokio::test]
    async fn conflicts_name_the_resource_that_causes_them() {
        let href = Href::parse("/dav/calendars/acme/anna/work/existing.ics").unwrap();
        let error = AppError::conflict().with_precondition(Precondition::NoUidConflict(href));
        let (response, body) = render(EdgeProblem::from(error)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            body.contains(
                "<C:no-uid-conflict><D:href>/dav/calendars/acme/anna/work/existing.ics</D:href></C:no-uid-conflict>"
            ),
            "{body}"
        );
    }

    #[tokio::test]
    async fn internal_text_never_reaches_the_body() {
        let secret = "relation \"calendar_objects\" does not exist (password=hunter2)";
        let (response, body) = render(EdgeProblem::from(AppError::internal(std::io::Error::other(secret)))).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("hunter2"));
        let invalid = AppError::new(ErrorKind::Invalid)
            .with_precondition(Precondition::ValidCalendarData("DTEND is before DTSTART".to_owned()));
        let (_, body) = render(EdgeProblem::from(invalid)).await;
        assert!(body.contains("<C:valid-calendar-data/>"), "{body}");
        assert!(
            !body.contains("DTEND"),
            "the text of the parser stays out of the body: {body}"
        );
    }

    #[tokio::test]
    async fn headers_follow_the_problem() {
        let (unauthenticated, _) = render(EdgeProblem::new(ProblemCode::Unauthenticated)).await;
        assert_eq!(
            unauthenticated.headers()[WWW_AUTHENTICATE],
            "Basic realm=\"davhaven\", charset=\"UTF-8\""
        );
        let acme =
            EdgeProblem::new(ProblemCode::Unauthenticated).with_challenge("Basic realm=\"acme\", charset=\"UTF-8\"");
        let (own, _) = render(acme).await;
        assert_eq!(
            own.headers()[WWW_AUTHENTICATE],
            "Basic realm=\"acme\", charset=\"UTF-8\""
        );
        let (limited, _) = render(EdgeProblem::new(ProblemCode::RateLimited)).await;
        assert_eq!(limited.headers()[RETRY_AFTER], "1");
        let (wrong, _) = render(EdgeProblem::new(ProblemCode::MethodNotAllowed).with_allow("OPTIONS, PROPFIND")).await;
        assert_eq!(wrong.headers()[ALLOW], "OPTIONS, PROPFIND");
        assert!(wrong.headers().get(WWW_AUTHENTICATE).is_none());
    }

    fn href(path: &str) -> Href {
        Href::parse(path).unwrap()
    }

    /// A precondition with the DAV status and the `(prefix, element)` a client must see.
    type ExpectedPrecondition = (Precondition, u16, Option<(&'static str, &'static str)>);

    /// Every precondition of the catalog (PLAN F0.4) with the DAV status and the element a client must see,
    /// written down from RFC 4791, RFC 4918, RFC 6578 and RFC 6638 and not derived from the table under test.
    fn every_precondition() -> Vec<ExpectedPrecondition> {
        vec![
            (
                Precondition::NeedPrivileges(vec![(href("/dav/a/"), Privilege::Read)]),
                403,
                Some(("D", "need-privileges")),
            ),
            (
                Precondition::ValidCalendarData("x".to_owned()),
                403,
                Some(("C", "valid-calendar-data")),
            ),
            (
                Precondition::ValidCalendarObjectResource,
                403,
                Some(("C", "valid-calendar-object-resource")),
            ),
            (
                Precondition::SupportedCalendarComponent,
                403,
                Some(("C", "supported-calendar-component")),
            ),
            (
                Precondition::SupportedCalendarData,
                403,
                Some(("C", "supported-calendar-data")),
            ),
            (
                Precondition::NoUidConflict(href("/dav/b.ics")),
                403,
                Some(("C", "no-uid-conflict")),
            ),
            (Precondition::MaxResourceSize, 403, Some(("C", "max-resource-size"))),
            (Precondition::MinDateTime, 403, Some(("C", "min-date-time"))),
            (Precondition::MaxDateTime, 403, Some(("C", "max-date-time"))),
            (Precondition::MaxInstances, 403, Some(("C", "max-instances"))),
            (
                Precondition::MaxAttendeesPerInstance,
                403,
                Some(("C", "max-attendees-per-instance")),
            ),
            (
                Precondition::UniqueSchedulingObjectResource(href("/dav/c.ics")),
                403,
                Some(("C", "unique-scheduling-object-resource")),
            ),
            (
                Precondition::SameOrganizerInAllComponents,
                403,
                Some(("C", "same-organizer-in-all-components")),
            ),
            (Precondition::OrganizerAllowed, 403, Some(("C", "organizer-allowed"))),
            (
                Precondition::AllowedOrganizerSchedulingObjectChange,
                403,
                Some(("C", "allowed-organizer-scheduling-object-change")),
            ),
            (
                Precondition::AllowedAttendeeSchedulingObjectChange,
                403,
                Some(("C", "allowed-attendee-scheduling-object-change")),
            ),
            (
                Precondition::ValidSchedulingMessage,
                400,
                Some(("C", "valid-scheduling-message")),
            ),
            (Precondition::ValidSyncToken, 403, Some(("D", "valid-sync-token"))),
            (
                Precondition::NumberOfMatchesWithinLimits,
                507,
                Some(("D", "number-of-matches-within-limits")),
            ),
            (
                Precondition::PropfindFiniteDepth,
                403,
                Some(("D", "propfind-finite-depth")),
            ),
            (Precondition::ValidFilter, 403, Some(("C", "valid-filter"))),
            (
                Precondition::ResourceMustBeNull,
                405,
                Some(("D", "resource-must-be-null")),
            ),
            (
                Precondition::CannotModifyProtectedProperty,
                403,
                Some(("D", "cannot-modify-protected-property")),
            ),
            (Precondition::SharingNotAllowed, 403, None),
            (Precondition::InvalidSharee(href("/dav/principals/x/y/")), 403, None),
        ]
    }

    #[tokio::test]
    async fn every_precondition_has_its_status_and_element() {
        let cases = every_precondition();
        assert_eq!(cases.len(), 25, "the plan lists 25 preconditions");
        for (precondition, status, element) in cases {
            let code = precondition.code();
            let error = AppError::new(ErrorKind::Invalid).with_precondition(precondition);
            let (response, body) = render(EdgeProblem::from(error)).await;
            assert_eq!(response.status().as_u16(), status, "{code}");
            match element {
                Some((prefix, local)) => {
                    assert_eq!(local, code, "the element is named like the precondition");
                    assert!(
                        body.contains(&format!("<{prefix}:{local}")),
                        "{code}: expected <{prefix}:{local} in {body}"
                    );
                }
                None => assert_eq!(body, "", "{code} has no element"),
            }
        }
    }

    #[tokio::test]
    async fn the_hrefs_of_conflicts_are_escaped_in_the_body() {
        let error = AppError::conflict()
            .with_precondition(Precondition::UniqueSchedulingObjectResource(href("/dav/a&b<c>.ics")));
        let (_, body) = render(EdgeProblem::from(error)).await;
        assert!(body.contains("<D:href>/dav/a&amp;b&lt;c&gt;.ics</D:href>"), "{body}");
    }

    #[test]
    fn every_error_body_is_made_by_one_builder() {
        let document = error_document("<D:x/>");
        assert!(
            document.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error "),
            "{document}"
        );
        for declaration in [NS_DAV, NS_CALDAV, NS_CALENDARSERVER] {
            assert!(document.contains(declaration), "{declaration}");
        }
        assert!(document.ends_with("<D:x/></D:error>\n"), "{document}");
        let problem = EdgeProblem::new(ProblemCode::TooManyMatches);
        assert_eq!(
            error_body(&problem).unwrap(),
            error_document("<D:number-of-matches-within-limits/>")
        );
    }

    #[test]
    fn the_namespaces_are_those_of_the_application() {
        assert_eq!(NS_DAV, davhaven_app::services::NS_DAV);
        assert_eq!(NS_CALDAV, davhaven_app::services::NS_CALDAV);
        assert_eq!(NS_CALENDARSERVER, davhaven_app::services::NS_CALENDARSERVER);
    }
}
