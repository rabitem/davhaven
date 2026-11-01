//! The seam between the DAV core and the collaboration modules: sharing, scheduling, notifications and principal
//! search.
//!
//! The collaboration modules serve what the core leaves to them. Where the core needs to *choose* the module by the
//! resource, the choice is one of the hooks below; where the method or the report already names it, the dispatcher
//! calls the module directly. This module holds what the modules share: the checks of the request media type,
//! reading and parsing a body, the visibility rule of PLAN 2.6 and the documents the modules answer with. The work
//! itself is in [`crate::sharing`], [`crate::notifications`], [`crate::scheduling`] and
//! [`crate::principals_search`].
//!
//! | Entry | Called for | Served by |
//! | --- | --- | --- |
//! | [`post`] (hook) | `POST` on calendar collections, homes and the outbox | `CS:share`, `CS:invite-reply`, outbox requests |
//! | [`propfind_item`] (hook) | `PROPFIND` of one inbox item or notification | their properties |
//! | [`propfind_members`] (hook) | `PROPFIND` with `Depth: 1` of the inbox and the notification collection | the members, sorted by href |
//! | [`sync_subjects`] (hook) | `sync-collection` of the inbox and the notification collection that asks for more than the entity tag | the changed members |
//! | direct, `methods` | `GET`, `HEAD` and `DELETE` of an inbox item or a notification | [`crate::scheduling`], [`crate::notifications`] |
//! | direct, `reports` | `calendar-multiget` of the inbox; the principal search reports | [`crate::scheduling`], [`crate::principals_search`] |
//!
//! # POST needs a media type that browsers cannot send without asking
//!
//! `POST` is the one method a web page can trigger across origins with the credentials the browser remembers. A
//! form can send `application/x-www-form-urlencoded`, `multipart/form-data` and `text/plain` without any
//! preflight; it cannot send an XML or calendar media type. So every `POST` of the namespace has to name one
//! (PLAN 2.15): XML (`application/xml`, `text/xml`, or a `+xml` type such as `application/davsharing+xml`) for the
//! sharing requests, `text/calendar` for the outbox. Anything else, a missing `Content-Type` included, is 415. The
//! check looks at the request alone, so it comes first and is the same for every resource.

use std::collections::HashMap;

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use davhaven_app::services::{SyncChange, WritePrecondition};
use davhaven_domain::{ETag, PrincipalName, ResourcePath};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use super::headers::{self, text};
use super::{Call, set_header};
use crate::props::Subject;
use crate::xml::Element;
use crate::xml::requests::PropRequest;
use crate::xml::write::XmlWriter;
use crate::{notifications, scheduling, sharing};

/// `POST`: sharing invitations and replies, the scheduling outbox.
///
/// # Errors
///
/// 415 for a media type that is not the one of the resource; the problems of the module that serves it.
pub(crate) async fn post(call: &Call<'_>, body: Body) -> Result<Response, EdgeProblem> {
    match call.resource {
        ResourcePath::Collection { .. } => sharing::share(call, body).await,
        ResourcePath::Home { .. } => sharing::invite_reply(call, body).await,
        ResourcePath::Outbox { .. } => scheduling::outbox_post(call, body).await,
        // The method table gives `POST` to the three above only.
        _ => Err(EdgeProblem::new(ProblemCode::MethodNotAllowed)),
    }
}

/// The resource of a `PROPFIND` of one inbox item or notification, as `(href, subject)`.
///
/// # Errors
///
/// The problems of the services.
pub(crate) async fn propfind_item(call: &Call<'_>) -> Result<Vec<(String, Subject)>, EdgeProblem> {
    match call.resource {
        ResourcePath::Notification { .. } => notifications::propfind_item(call).await,
        ResourcePath::InboxItem { .. } => scheduling::propfind_item(call).await,
        _ => Err(EdgeProblem::new(ProblemCode::NotFound)),
    }
}

/// The members of a collection for `Depth: 1`.
pub(crate) struct Listing {
    /// The members as `(href, subject)`, sorted by href.
    pub(crate) members: Vec<(String, Subject)>,
    /// Whether the collection has more members than the list: reading them as well would have gone beyond
    /// `max_response_bytes`, so the answer ends with the 507 entry for the request URI.
    pub(crate) truncated: bool,
}

impl Listing {
    /// A list that is the whole collection.
    pub(crate) fn complete(members: Vec<(String, Subject)>) -> Self {
        Self {
            members,
            truncated: false,
        }
    }
}

/// The members of the inbox or the notification collection for `Depth: 1`.
///
/// The caller has resolved the collection with the tenant of the request before (`PROPFIND` reads it first), which
/// is what lets the modules address its members by the name of the home owner alone.
///
/// # Errors
///
/// The problems of the services.
pub(crate) async fn propfind_members(call: &Call<'_>, request: &PropRequest) -> Result<Listing, EdgeProblem> {
    match call.resource {
        ResourcePath::Notifications { .. } => notifications::propfind_members(call).await,
        ResourcePath::Inbox { .. } => scheduling::propfind_members(call, request).await,
        _ => Ok(Listing::complete(Vec::new())),
    }
}

/// The members a `sync-collection` of the inbox or the notification collection reports with more than their entity
/// tag, by href. Members that cannot be read any more are left out (the report then says they are gone).
///
/// # Errors
///
/// The problems of the services.
pub(crate) async fn sync_subjects(
    call: &Call<'_>,
    changes: &[SyncChange],
    select: &PropRequest,
) -> Result<HashMap<String, Subject>, EdgeProblem> {
    match call.resource {
        ResourcePath::Notifications { .. } => notifications::sync_subjects(call, changes).await,
        ResourcePath::Inbox { .. } => scheduling::sync_subjects(call, changes, select).await,
        _ => Ok(HashMap::new()),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// What the modules share
// ---------------------------------------------------------------------------------------------------------------

/// The media type of the request: `type/subtype` in lower case, without parameters.
fn media_type(request: &HeaderMap) -> Option<String> {
    let value = text(request, "content-type")?;
    let essence = value.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    (!essence.is_empty()).then_some(essence)
}

/// Whether a media type is XML: `application/xml`, `text/xml`, or any type with the `+xml` suffix.
fn is_xml(media_type: &str) -> bool {
    let Some((kind, subtype)) = media_type.split_once('/') else {
        return false;
    };
    if kind.is_empty() {
        return false;
    }
    (subtype == "xml" && matches!(kind, "application" | "text"))
        || subtype.strip_suffix("+xml").is_some_and(|name| !name.is_empty())
}

/// Whether a media type is iCalendar: `text/calendar` (the `Content-Type` has had its parameters, such as
/// `method=REQUEST`, cut off by [`media_type`]).
fn is_calendar(media_type: &str) -> bool {
    media_type == "text/calendar"
}

fn unsupported_media_type(detail: &'static str) -> EdgeProblem {
    EdgeProblem::new(ProblemCode::UnsupportedMediaType).with_detail(detail)
}

/// Requires the request to carry XML.
///
/// # Errors
///
/// 415 when the `Content-Type` is missing or names another media type.
pub(crate) fn require_xml(request: &HeaderMap) -> Result<(), EdgeProblem> {
    match media_type(request) {
        Some(media_type) if is_xml(&media_type) => Ok(()),
        _ => Err(unsupported_media_type(
            "The request body must be XML (application/xml).",
        )),
    }
}

/// Requires the request to carry iCalendar.
///
/// # Errors
///
/// 415 when the `Content-Type` is missing or names another media type.
pub(crate) fn require_calendar(request: &HeaderMap) -> Result<(), EdgeProblem> {
    match media_type(request) {
        Some(media_type) if is_calendar(&media_type) => Ok(()),
        _ => Err(unsupported_media_type(
            "The request body must be iCalendar (text/calendar).",
        )),
    }
}

/// Reads an XML body under the limits of PLAN 2.15 into its document.
///
/// The handlers turn the document into a typed request afterwards (`read_root(..).await.and_then(|root| parse(&root))`):
/// a reader passed in as an argument would be held across the awaits, and a function that takes a reference does not
/// make a future that rustc can prove `Send` in that position.
///
/// # Errors
///
/// 413 for a body above `max_request_body`, 400 for a document that breaks a limit or is not well-formed, 503 when
/// the time budget of the reader is spent.
pub(crate) async fn read_root(call: &Call<'_>, body: Body) -> Result<Element, EdgeProblem> {
    let bytes = call.xml_body(body).await?;
    call.parse_xml(bytes).await
}

/// Whether the caller may see the resource: the problem of the service (404 for an invisible resource) when not.
///
/// A handler that refuses a request for a reason of its own (a body that cannot be read, a request that makes no
/// sense) calls this first, so that such a refusal never tells the caller that a resource exists (PLAN 2.6). A
/// handler that hands the home owner's *name* to a service (the outbox) calls it before every request: the name
/// says nothing about the tenant of the path, which only resolving the resource checks.
///
/// # Errors
///
/// The problem of the service.
pub(crate) async fn visible(call: &Call<'_>) -> Result<(), EdgeProblem> {
    let services = call.services();
    let seen = match call.resource {
        ResourcePath::Notification { .. } => services
            .sharing
            .get_notification(call.ctx, call.resource)
            .await
            .map(|_| ()),
        ResourcePath::InboxItem { .. } => services.scheduling.inbox_get(call.ctx, call.resource).await.map(|_| ()),
        ResourcePath::Principal { .. } => services
            .principals
            .dav_properties(call.ctx, call.resource)
            .await
            .map(|_| ()),
        ResourcePath::Root => Ok(()),
        _ => services
            .calendars
            .get_collection(call.ctx, call.resource)
            .await
            .map(|_| ()),
    };
    seen.map_err(EdgeProblem::from)
}

/// The principal whose home the resource is in.
///
/// # Errors
///
/// 404 for resources that are in no home (the entry point).
pub(crate) fn home_owner(call: &Call<'_>) -> Result<PrincipalName, EdgeProblem> {
    call.resource
        .principal()
        .cloned()
        .ok_or_else(|| EdgeProblem::new(ProblemCode::NotFound))
}

/// A document of the collaboration modules: the XML declaration and a root element in `namespace` that declares the
/// prefixes `D`, `C` and `CS`, the content that `fill` writes, and the end of the root.
pub(crate) fn xml_document(namespace: &str, local: &str, fill: impl FnOnce(&mut XmlWriter)) -> String {
    let mut writer = XmlWriter::new();
    writer.declaration();
    writer.root(namespace, local, "");
    fill(&mut writer);
    writer.end(namespace, local);
    writer.raw("\n");
    writer.into_string()
}

/// A `200 OK` with an XML document.
pub(crate) fn xml_response(document: String) -> Response {
    let mut response = Response::new(Body::from(document));
    *response.status_mut() = StatusCode::OK;
    set_header(&mut response, CONTENT_TYPE, "application/xml; charset=utf-8");
    set_header(&mut response, CACHE_CONTROL, "no-cache");
    response
}

/// The conditional headers of a `DELETE`, when the request has any: `None` for a plain `DELETE`, which then costs
/// no read of the resource.
///
/// The notification service takes them and judges them in the transaction that deletes. The inbox service takes no
/// conditions, so [`require_conditions`] evaluates them against the entity tag the item has when it is read just
/// before: an inbox item is never rewritten, so the item cannot change between the comparison and the deletion (see
/// `crate::scheduling`).
///
/// # Errors
///
/// 412 for a condition that cannot be read, 501 for conditions the services cannot express (see
/// `headers::write_precondition`).
pub(crate) fn conditions_of(request: &HeaderMap) -> Result<Option<WritePrecondition>, EdgeProblem> {
    let conditions = headers::write_precondition(request)?;
    Ok((conditions != WritePrecondition::none()).then_some(conditions))
}

/// Evaluates conditional headers against the entity tag of the resource.
///
/// # Errors
///
/// 412 when a condition does not hold.
pub(crate) fn require_conditions(conditions: &WritePrecondition, etag: &ETag) -> Result<(), EdgeProblem> {
    headers::require_conditions(conditions, etag, None)
}

#[cfg(test)]
mod tests {
    use davhaven_app::services::{NS_CALDAV, NS_CALENDARSERVER, NS_DAV};

    use super::*;

    #[test]
    fn xml_media_types_are_the_plain_ones_and_the_plus_xml_family() {
        for xml in [
            "application/xml",
            "text/xml",
            "application/davsharing+xml",
            "application/vnd.example+xml",
            "text/x-thing+xml",
        ] {
            assert!(is_xml(xml), "{xml}");
        }
        for other in [
            "",
            "xml",
            "+xml",
            "application/+xml",
            "text/plain",
            "multipart/form-data",
            "application/x-www-form-urlencoded",
            "application/json",
            "text/calendar",
            "application/xmlx",
            "text/html+xhtml",
        ] {
            assert!(!is_xml(other), "{other}");
        }
    }

    #[test]
    fn only_text_calendar_is_calendar() {
        assert!(is_calendar("text/calendar"));
        assert!(!is_calendar("text/calendar+x"));
        assert!(!is_calendar("application/ics"));
        assert!(!is_calendar("text/xml"));
    }

    #[test]
    fn documents_declare_the_prefixes_of_the_protocol_once() {
        let document = xml_document(NS_CALDAV, "schedule-response", |writer| {
            writer.text_element(NS_CALDAV, "request-status", "2.0;Success");
        });
        assert!(
            document.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<C:schedule-response xmlns:D=\"DAV:\"")
        );
        assert!(document.ends_with("<C:request-status>2.0;Success</C:request-status></C:schedule-response>\n"));
        let shared = xml_document(NS_CALENDARSERVER, "shared-as", |_| {});
        assert!(shared.contains("<CS:shared-as xmlns:D=\"DAV:\""), "{shared}");
        assert!(shared.contains("</CS:shared-as>"), "{shared}");
        let other = xml_document("urn:example:thing", "thing", |writer| {
            writer.empty(NS_DAV, "inside");
        });
        assert!(
            other.contains("<thing xmlns=\"urn:example:thing\" xmlns:D=\"DAV:\""),
            "a root outside the fixed prefixes is in its own namespace: {other}"
        );
        assert!(other.contains("</thing>"), "{other}");
    }

    fn request_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn a_post_needs_a_media_type_a_web_page_cannot_send() {
        for xml in [
            "application/xml",
            "application/xml; charset=utf-8",
            "TEXT/XML;charset=UTF-8",
            " application/davsharing+xml ",
        ] {
            assert!(require_xml(&request_with(&[("content-type", xml)])).is_ok(), "{xml}");
        }
        for refused in [
            "text/plain",
            "text/plain; charset=utf-8",
            "multipart/form-data; boundary=x",
            "application/x-www-form-urlencoded",
            "text/calendar",
            "application/json",
            "application/xml-dtd",
            "",
        ] {
            let problem = require_xml(&request_with(&[("content-type", refused)])).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::UnsupportedMediaType, "{refused}");
        }
        assert_eq!(
            require_xml(&HeaderMap::new()).unwrap_err().code(),
            ProblemCode::UnsupportedMediaType,
            "a request without a media type is refused as well"
        );
        for calendar in [
            "text/calendar",
            "text/calendar; charset=utf-8; method=REQUEST",
            "Text/Calendar",
        ] {
            assert!(
                require_calendar(&request_with(&[("content-type", calendar)])).is_ok(),
                "{calendar}"
            );
        }
        for refused in ["application/xml", "text/plain", "application/ics"] {
            let problem = require_calendar(&request_with(&[("content-type", refused)])).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::UnsupportedMediaType, "{refused}");
        }
        assert!(require_calendar(&HeaderMap::new()).is_err());
    }

    #[test]
    fn a_delete_reads_the_resource_only_when_it_has_a_condition() {
        assert_eq!(
            conditions_of(&HeaderMap::new()).unwrap(),
            None,
            "a plain DELETE costs no read"
        );
        let etag = ETag::from_bytes(b"<a/>");
        let conditional = conditions_of(&request_with(&[("if-match", etag.as_str())]))
            .unwrap()
            .expect("If-Match is a condition");
        assert!(require_conditions(&conditional, &etag).is_ok());
        let other = ETag::from_bytes(b"<b/>");
        assert_eq!(
            require_conditions(&conditional, &other).unwrap_err().code(),
            ProblemCode::PreconditionFailed
        );
        let create_only = conditions_of(&request_with(&[("if-none-match", "*")]))
            .unwrap()
            .unwrap();
        assert_eq!(
            require_conditions(&create_only, &etag).unwrap_err().code(),
            ProblemCode::PreconditionFailed,
            "the resource exists"
        );
        let unreadable = axum::http::HeaderValue::from_bytes(b"\xff").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("if-match", unreadable);
        assert_eq!(
            conditions_of(&headers).unwrap_err().code(),
            ProblemCode::PreconditionFailed
        );
        assert_eq!(
            conditions_of(&request_with(&[("if-none-match", "\"x\"")]))
                .unwrap_err()
                .code(),
            ProblemCode::NotImplemented
        );
    }
}
