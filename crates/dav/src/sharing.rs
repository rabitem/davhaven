//! CalendarServer sharing: `CS:share`, `CS:invite-reply` and what clients get back.
//!
//! The flow as Apple Calendar runs it (PLAN 2.9):
//!
//! 1. The owner `POST`s a `CS:share` document to the calendar collection. `CS:set` invites a sharee (or changes their
//!    access), `CS:remove` ends a share. The application creates a pending grant and an invitation in the sharee's
//!    notification collection ([`crate::notifications`]).
//! 2. The sharee reads the invitation there and answers with a `CS:invite-reply` `POST` to their **calendar home**:
//!    `CS:invite-accepted` or `CS:invite-declined`, naming the invitation (`CS:in-reply-to`).
//! 3. Accepting is answered with a `CS:shared-as` document naming the new collection in the sharee's home;
//!    declining with an empty `200`.
//!
//! The properties that show a share (`CS:invite`, `CS:allowed-sharing-modes`, `CS:shared-url`, the resource types
//! `CS:shared-owner` and `CS:shared`) are rendered by [`crate::props`]; who may share what is the application's
//! decision (`decide`), this module only reads the request and renders the answer.
//!
//! # Requests
//!
//! ```xml
//! <CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">
//!   <CS:set>
//!     <D:href>mailto:ben@acme.example</D:href>
//!     <CS:common-name>Ben Baker</CS:common-name>
//!     <CS:summary>Team plans</CS:summary>
//!     <CS:read-write/>            <!-- or <CS:read/> -->
//!   </CS:set>
//!   <CS:remove><D:href>mailto:cara@acme.example</D:href></CS:remove>
//! </CS:share>
//! ```
//!
//! A `CS:set` names its sharee by calendar user address and exactly one access level; a body that does not is 400,
//! and so is one that names the same address twice (a `CS:set` and a `CS:remove` of one sharee, or two `CS:set`s of
//! one): the application applies every `CS:set` before every `CS:remove`, so what such a body means would depend on
//! an order the request cannot express, and a `multistatus` answers every resource once. One request names at most
//! `max_sharees_per_request` sharees (403 `DAV:number-of-matches-within-limits` above, which only a caller who can
//! see the collection is told).
//!
//! # Answers
//!
//! `200` without a body when every item was applied. Each item has its own answer, so one external address does not
//! stop the others: when some were refused the answer is a `207` with **one `response` for every item**, as
//! CalendarServer answers: `200` for an item that was applied, and for one that was not the status and the
//! precondition of its problem (403 for an external sharee, 403 `DAV:need-privileges` for a grant the API made on a
//! group or managed calendar). The responses are sorted by `href`, and the `href` is the text the client sent, not
//! the normalized address, so that a client that matches the answers to its items by `href` finds each of them
//! (`mailto:Ben@Acme.example` is answered as sent).

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use davhaven_app::services::{
    InviteReply, InviteReplyOutcome, NS_CALENDARSERVER, NS_DAV, ShareItemResult, ShareRequest, ShareeSet,
};
use davhaven_domain::{CalendarUserAddress, GrantAccess, PublicUrls, ResourcePath, Uid};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::errors::{PreconditionElement, dav_status, precondition_element};
use crate::methods::collaboration::{read_root, require_xml, visible, xml_document, xml_response};
use crate::methods::{Call, multistatus_response, status_only};
use crate::xml::Element;
use crate::xml::requests::bad_request;
use crate::xml::write::Multistatus;

/// Reads the text of the child `local` of the CalendarServer namespace, without the white space around it; an
/// element that is absent or empty counts as not given.
fn text_child(element: &Element, local: &str) -> Option<String> {
    element
        .child(NS_CALENDARSERVER, local)
        .map(|child| child.text().trim().to_owned())
        .filter(|text| !text.is_empty())
}

/// The calendar user address in the `D:href` of an item of a share request, and the text it was written as.
fn address_of(item: &Element) -> Result<(CalendarUserAddress, String), EdgeProblem> {
    let href = item
        .child(NS_DAV, "href")
        .ok_or_else(|| bad_request("A sharee is named by a D:href."))?;
    let text = href.text().trim().to_owned();
    let address = CalendarUserAddress::parse(&text)
        .map_err(|_| bad_request("A sharee must be named by a valid calendar user address, for example mailto:."))?;
    Ok((address, text))
}

fn sharee_of(set: &Element) -> Result<(ShareeSet, String), EdgeProblem> {
    let access = match (
        set.child(NS_CALENDARSERVER, "read").is_some(),
        set.child(NS_CALENDARSERVER, "read-write").is_some(),
    ) {
        (true, false) => GrantAccess::Read,
        (false, true) => GrantAccess::ReadWrite,
        _ => return Err(bad_request("A CS:set names exactly one of CS:read and CS:read-write.")),
    };
    let (address, text) = address_of(set)?;
    let sharee = ShareeSet {
        address,
        common_name: text_child(set, "common-name"),
        summary: text_child(set, "summary"),
        access,
    };
    Ok((sharee, text))
}

/// A `CS:share` document as it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareDocument {
    /// What the application is asked to do.
    pub request: ShareRequest,
    /// The `D:href` text of every sharee, by the calendar user address it was read as. The answer names a sharee as
    /// the client did.
    pub named: BTreeMap<String, String>,
}

/// Reads a `CS:share` document: the sharees to invite or change (`CS:set`) and those to remove (`CS:remove`).
/// Elements of other names are ignored.
///
/// The two lists are separate: the application applies every `CS:set` before every `CS:remove`, so the order of the
/// elements in the document does not matter and a document in which it would is refused (see below).
///
/// # Errors
///
/// 400 when the root is not `CS:share`, an item has no valid address or a `CS:set` no single access level, the same
/// address is named more than once (however it is spelled), or the document names nobody.
pub fn parse_share(root: &Element) -> Result<ShareDocument, EdgeProblem> {
    if !root.is(NS_CALENDARSERVER, "share") {
        return Err(bad_request("The body of this request must be a CS:share element."));
    }
    let mut request = ShareRequest::default();
    let mut named = BTreeMap::new();
    let mut name = |address: &CalendarUserAddress, text: String| {
        if named.insert(address.as_str().to_owned(), text).is_some() {
            Err(bad_request("A share request names every sharee once."))
        } else {
            Ok(())
        }
    };
    for item in root.elements() {
        if item.is(NS_CALENDARSERVER, "set") {
            let (sharee, text) = sharee_of(item)?;
            name(&sharee.address, text)?;
            request.set.push(sharee);
        } else if item.is(NS_CALENDARSERVER, "remove") {
            let (address, text) = address_of(item)?;
            name(&address, text)?;
            request.remove.push(address);
        }
    }
    if request.set.is_empty() && request.remove.is_empty() {
        return Err(bad_request("A share request needs at least one CS:set or CS:remove."));
    }
    Ok(ShareDocument { request, named })
}

/// A `CS:invite-reply` document as it was read: the reply for the application, and the `CS:hosturl` text that was
/// not judged yet (whether it names a resource of this server depends on the server's URLs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyDocument {
    /// What the application is asked to do; its `host_url` is not set until [`ReplyDocument::into_reply`].
    pub reply: InviteReply,
    /// The `D:href` of `CS:hosturl`, as written.
    pub host_href: Option<String>,
}

impl ReplyDocument {
    /// The reply for the application: the host URL is set when it names a resource of this server (`urls` are the
    /// URLs of the server).
    pub fn into_reply(self, urls: &PublicUrls) -> InviteReply {
        InviteReply {
            host_url: self.host_href.as_deref().and_then(|href| host_resource(href, urls)),
            ..self.reply
        }
    }
}

/// The resource of this server that a `CS:hosturl` names: a path-absolute reference, or an absolute URL whose origin
/// (scheme, host and port) is the one of the public or the DAV base URL. `ResourcePath::from_href` only reads the
/// path of an absolute URL, so the host is judged here.
fn host_resource(href: &str, urls: &PublicUrls) -> Option<ResourcePath> {
    if !href.starts_with('/') {
        let lower = href.to_ascii_lowercase();
        let ours = [urls.public_base(), urls.dav_base()].iter().any(|base| {
            let origin = base.origin().ascii_serialization();
            lower.starts_with(&format!("{origin}/"))
        });
        if !ours {
            return None;
        }
    }
    ResourcePath::from_href(href).ok()
}

/// Reads a `CS:invite-reply` document: the answer, the invitation it answers and the summary the sharee gives.
///
/// `CS:hosturl` is read when it names a resource of this server (a path-absolute reference, or an absolute URL on
/// the origin of the server) and ignored otherwise: the invitation identifies the share, the URL is the client's note
/// of where it came from. An absolute URL of another host is no resource of this server, whatever its path says.
///
/// # Errors
///
/// 400 when the root is not `CS:invite-reply`, the answer is not exactly one of `CS:invite-accepted` and
/// `CS:invite-declined`, or `CS:in-reply-to` is missing or no valid invitation id.
pub fn parse_invite_reply(root: &Element) -> Result<ReplyDocument, EdgeProblem> {
    if !root.is(NS_CALENDARSERVER, "invite-reply") {
        return Err(bad_request(
            "The body of this request must be a CS:invite-reply element.",
        ));
    }
    let accepted = root.child(NS_CALENDARSERVER, "invite-accepted").is_some();
    let declined = root.child(NS_CALENDARSERVER, "invite-declined").is_some();
    if accepted == declined {
        return Err(bad_request(
            "A CS:invite-reply names exactly one of CS:invite-accepted and CS:invite-declined.",
        ));
    }
    let in_reply_to = text_child(root, "in-reply-to")
        .ok_or_else(|| bad_request("A CS:invite-reply names the invitation it answers in CS:in-reply-to."))?;
    let in_reply_to =
        Uid::parse(&in_reply_to).map_err(|_| bad_request("CS:in-reply-to is not a valid invitation id."))?;
    let host_href = root
        .child(NS_CALENDARSERVER, "hosturl")
        .and_then(|host| host.child(NS_DAV, "href"))
        .map(|href| href.text().trim().to_owned());
    Ok(ReplyDocument {
        reply: InviteReply {
            in_reply_to,
            accepted,
            host_url: None,
            summary: text_child(root, "summary"),
        },
        host_href,
    })
}

/// The answer to a share request: `200` when every item was applied, otherwise a `207` with one `response` for each
/// item, sorted by `href` (items with the same `href` stay in the order the application answered them). `named` has
/// the text each sharee was written as in the request ([`ShareDocument::named`]); the `href` is that text, and the
/// normalized address for an address the request did not name.
pub fn share_response(results: &[ShareItemResult], named: &BTreeMap<String, String>) -> Response {
    match share_document(results, named) {
        Some(document) => multistatus_response(document, false),
        None => status_only(StatusCode::OK),
    }
}

/// The `multistatus` document of the `207` that answers a share request, `None` when every item was applied and the
/// answer is a plain `200` ([`share_response`]).
pub fn share_document(results: &[ShareItemResult], named: &BTreeMap<String, String>) -> Option<String> {
    if results.iter().all(|result| result.error.is_none()) {
        return None;
    }
    let mut answers: Vec<(String, u16, Option<PreconditionElement>)> = results
        .iter()
        .map(|result| {
            let href = named
                .get(result.address.as_str())
                .map_or_else(|| result.address.as_str().to_owned(), Clone::clone);
            match &result.error {
                None => (href, 200, None),
                Some(error) => {
                    let problem = EdgeProblem::from_app_error(error);
                    (href, dav_status(problem.code()), precondition_element(&problem))
                }
            }
        })
        .collect();
    answers.sort_by(|a, b| a.0.cmp(&b.0));
    let mut document = Multistatus::new();
    for (href, status, precondition) in &answers {
        document.status_response_with(href, *status, precondition.as_ref());
    }
    Some(document.finish())
}

/// The `CS:shared-as` document that answers an accepted invitation: the collection in the sharee's home.
pub fn shared_as_document(shared_as: &ResourcePath) -> String {
    xml_document(NS_CALENDARSERVER, "shared-as", |writer| {
        writer.text_element(NS_DAV, "href", &shared_as.format());
    })
}

/// Serves a `POST` of a `CS:share` document to a calendar collection.
pub(crate) async fn share(call: &Call<'_>, body: Body) -> Result<Response, EdgeProblem> {
    require_xml(call.headers())?;
    let ShareDocument { request, named } = match read_root(call, body).await.and_then(|root| parse_share(&root)) {
        Ok(document) => document,
        Err(problem) => {
            // A body that cannot be read says nothing about the collection, unless the caller cannot see it.
            visible(call).await?;
            return Err(problem);
        }
    };
    let most = usize::try_from(call.limits().dav.max_sharees_per_request).unwrap_or(usize::MAX);
    if request.set.len().saturating_add(request.remove.len()) > most {
        // Like every refusal of a body, it says nothing to a caller who cannot see the collection.
        visible(call).await?;
        return Err(EdgeProblem::new(ProblemCode::TooManyHrefs));
    }
    let results = call.services().sharing.share(call.ctx, call.resource, request).await?;
    Ok(share_response(&results, &named))
}

/// Serves a `POST` of a `CS:invite-reply` document to a calendar home.
pub(crate) async fn invite_reply(call: &Call<'_>, body: Body) -> Result<Response, EdgeProblem> {
    require_xml(call.headers())?;
    let reply = match read_root(call, body).await.and_then(|root| parse_invite_reply(&root)) {
        Ok(document) => document.into_reply(&call.services().urls),
        Err(problem) => {
            visible(call).await?;
            return Err(problem);
        }
    };
    let outcome = call
        .services()
        .sharing
        .reply_invite(call.ctx, call.resource, reply)
        .await?;
    Ok(match outcome {
        InviteReplyOutcome::Accepted { shared_as } => xml_response(shared_as_document(&shared_as)),
        InviteReplyOutcome::Declined => status_only(StatusCode::OK),
    })
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use davhaven_app::AppError;
    use davhaven_domain::{DavLimits, Href, Privilege};

    use super::*;
    use crate::testing::fixture;
    use crate::xml::parse;

    fn read(xml: &str) -> Element {
        parse(xml.as_bytes(), &DavLimits::default()).unwrap()
    }

    fn address(text: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(text).unwrap()
    }

    fn urls() -> PublicUrls {
        use davhaven_app::AppServices;
        use davhaven_app_fake::AppServicesExt as _;
        AppServices::fake().urls
    }

    fn reply_of(xml: &str) -> Result<InviteReply, EdgeProblem> {
        parse_invite_reply(&read(xml)).map(|document| document.into_reply(&urls()))
    }

    async fn body_of(response: Response) -> String {
        String::from_utf8(to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
    }

    #[test]
    fn a_share_request_names_sharees_to_set_and_to_remove() {
        let ShareDocument { request, named } = parse_share(&read(
            r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">
                 <CS:set>
                   <D:href>mailto:Ben@Acme.example</D:href>
                   <CS:common-name> Ben Baker </CS:common-name>
                   <CS:summary>Team plans</CS:summary>
                   <CS:read-write/>
                 </CS:set>
                 <CS:set><D:href>mailto:rita@acme.example</D:href><CS:read/></CS:set>
                 <CS:remove><D:href>mailto:cara@acme.example</D:href></CS:remove>
                 <CS:unknown/>
               </CS:share>"#,
        ))
        .unwrap();
        assert_eq!(
            request.set,
            vec![
                ShareeSet {
                    address: address("mailto:ben@acme.example"),
                    common_name: Some("Ben Baker".to_owned()),
                    summary: Some("Team plans".to_owned()),
                    access: GrantAccess::ReadWrite,
                },
                ShareeSet {
                    address: address("mailto:rita@acme.example"),
                    common_name: None,
                    summary: None,
                    access: GrantAccess::Read,
                },
            ]
        );
        assert_eq!(request.remove, vec![address("mailto:cara@acme.example")]);
        assert_eq!(
            named.get("mailto:ben@acme.example").map(String::as_str),
            Some("mailto:Ben@Acme.example"),
            "the text of the client is kept next to the normalized address"
        );
        assert_eq!(named.len(), 3);
    }

    #[test]
    fn a_sharee_is_named_once_however_the_address_is_spelled() {
        // A body that removes a sharee and invites them again would end with the sharee removed, because the
        // application applies every `CS:set` before every `CS:remove`; a `multistatus` has one response per resource.
        // Neither is a request: it is refused as a whole.
        let wrap = |inner: &str| {
            format!(r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">{inner}</CS:share>"#)
        };
        for inner in [
            "<CS:remove><D:href>mailto:ben@acme.example</D:href></CS:remove>\
             <CS:set><D:href>mailto:BEN@acme.example</D:href><CS:read/></CS:set>",
            "<CS:set><D:href>mailto:BEN@acme.example</D:href><CS:read/></CS:set>\
             <CS:remove><D:href> mailto:Ben@acme.example </D:href></CS:remove>",
            "<CS:set><D:href>mailto:ben@acme.example</D:href><CS:read/></CS:set>\
             <CS:set><D:href>mailto:ben@acme.example</D:href><CS:read-write/></CS:set>",
            "<CS:remove><D:href>mailto:ben@acme.example</D:href></CS:remove>\
             <CS:remove><D:href>mailto:Ben@Acme.Example</D:href></CS:remove>",
        ] {
            let problem = parse_share(&read(&wrap(inner))).unwrap_err();
            assert_eq!(
                problem.code(),
                davhaven_http::problem::ProblemCode::BadRequest,
                "{inner}"
            );
        }
        // Different sharees are fine in any order.
        let document = parse_share(&read(&wrap(
            "<CS:remove><D:href>mailto:cara@acme.example</D:href></CS:remove>\
             <CS:set><D:href>mailto:BEN@acme.example</D:href><CS:read/></CS:set>",
        )))
        .unwrap();
        assert_eq!(document.named.len(), 2);
        assert_eq!(
            document.named.get("mailto:ben@acme.example").map(String::as_str),
            Some("mailto:BEN@acme.example")
        );
    }

    #[test]
    fn empty_names_and_summaries_are_not_given() {
        let request = parse_share(&read(
            r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/"><CS:set>
                 <D:href>mailto:ben@acme.example</D:href><CS:common-name/><CS:summary>  </CS:summary><CS:read/>
               </CS:set></CS:share>"#,
        ))
        .unwrap()
        .request;
        assert_eq!(request.set[0].common_name, None);
        assert_eq!(request.set[0].summary, None);
    }

    #[test]
    fn share_requests_that_are_no_requests_are_refused() {
        let wrap = |inner: &str| {
            format!(r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">{inner}</CS:share>"#)
        };
        let bad = [
            // another document
            r#"<CS:invite-reply xmlns:CS="http://calendarserver.org/ns/"/>"#.to_owned(),
            r#"<share xmlns="urn:example"/>"#.to_owned(),
            // nobody named
            wrap(""),
            wrap("<CS:unknown/>"),
            // no or two access levels
            wrap("<CS:set><D:href>mailto:a@b.example</D:href></CS:set>"),
            wrap("<CS:set><D:href>mailto:a@b.example</D:href><CS:read/><CS:read-write/></CS:set>"),
            wrap("<CS:set><D:href>mailto:a@b.example</D:href><CS:read-write-schedule/></CS:set>"),
            // no or invalid sharee
            wrap("<CS:set><CS:read/></CS:set>"),
            wrap("<CS:set><D:href>ben</D:href><CS:read/></CS:set>"),
            wrap("<CS:set><D:href>mailto:not an address</D:href><CS:read/></CS:set>"),
            wrap("<CS:remove/>"),
            wrap("<CS:remove><D:href>   </D:href></CS:remove>"),
            // an address that normalization lengthens past the maximum is refused the first time, not only when it is read again
            wrap(&format!(
                "<CS:set><D:href>https://acme.example/ben#{}</D:href><CS:read/></CS:set>",
                "\"".repeat(200)
            )),
        ];
        for xml in bad {
            let problem = parse_share(&read(&xml)).unwrap_err();
            assert_eq!(problem.code(), davhaven_http::problem::ProblemCode::BadRequest, "{xml}");
        }
    }

    #[test]
    fn an_invitation_reply_answers_one_invitation() {
        let accepted = reply_of(
            r#"<CS:invite-reply xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">
                 <CS:invite-accepted/>
                 <CS:hosturl><D:href>/dav/calendars/acme/anna/work/</D:href></CS:hosturl>
                 <CS:in-reply-to> 4d6a-91 </CS:in-reply-to>
                 <CS:summary>Anna's work</CS:summary>
                 <CS:common-name>Ben</CS:common-name>
               </CS:invite-reply>"#,
        )
        .unwrap();
        assert!(accepted.accepted);
        assert_eq!(accepted.in_reply_to.as_str(), "4d6a-91");
        assert_eq!(
            accepted.host_url,
            Some(ResourcePath::parse("/dav/calendars/acme/anna/work/").unwrap())
        );
        assert_eq!(accepted.summary.as_deref(), Some("Anna's work"));

        let declined = reply_of(
            r#"<CS:invite-reply xmlns:CS="http://calendarserver.org/ns/">
                 <CS:invite-declined/><CS:in-reply-to>x</CS:in-reply-to>
                 <CS:hosturl><D:href xmlns:D="DAV:">https://elsewhere.example/other</D:href></CS:hosturl>
               </CS:invite-reply>"#,
        )
        .unwrap();
        assert!(!declined.accepted);
        assert_eq!(
            declined.host_url, None,
            "a URL that is no resource of this server is not a note we can use"
        );
        assert_eq!(declined.summary, None);
    }

    #[test]
    fn only_a_resource_of_this_server_is_a_host_url() {
        let own = Some(ResourcePath::parse("/dav/calendars/acme/anna/work/").unwrap());
        for (href, expected) in [
            ("/dav/calendars/acme/anna/work/", own.clone()),
            ("https://cal.example.test/dav/calendars/acme/anna/work/", own.clone()),
            ("HTTPS://CAL.EXAMPLE.TEST/dav/calendars/acme/anna/work/", own),
            // A foreign host with a path that names a resource here is no resource of this server.
            ("https://attacker.example/dav/calendars/acme/anna/work/", None),
            (
                "https://cal.example.test.attacker.example/dav/calendars/acme/anna/work/",
                None,
            ),
            (
                "https://cal.example.test@attacker.example/dav/calendars/acme/anna/work/",
                None,
            ),
            ("https://cal.example.test:8443/dav/calendars/acme/anna/work/", None),
            ("http://cal.example.test/dav/calendars/acme/anna/work/", None),
            ("//attacker.example/dav/calendars/acme/anna/work/", None),
            ("work/", None),
            ("", None),
        ] {
            assert_eq!(host_resource(href, &urls()), expected, "{href}");
        }
        let reply = r#"<CS:invite-reply xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/"><CS:invite-accepted/>
                 <CS:in-reply-to>x</CS:in-reply-to>
                 <CS:hosturl><D:href>https://attacker.example/dav/calendars/acme/anna/work/</D:href></CS:hosturl>
               </CS:invite-reply>"#;
        assert_eq!(reply_of(reply).unwrap().host_url, None);
    }

    #[test]
    fn replies_that_answer_nothing_are_refused() {
        let wrap = |inner: &str| {
            format!(r#"<CS:invite-reply xmlns:CS="http://calendarserver.org/ns/">{inner}</CS:invite-reply>"#)
        };
        let bad = [
            r#"<CS:share xmlns:CS="http://calendarserver.org/ns/"/>"#.to_owned(),
            wrap("<CS:in-reply-to>x</CS:in-reply-to>"),
            wrap("<CS:invite-accepted/><CS:invite-declined/><CS:in-reply-to>x</CS:in-reply-to>"),
            wrap("<CS:invite-accepted/>"),
            wrap("<CS:invite-accepted/><CS:in-reply-to>  </CS:in-reply-to>"),
            wrap(&format!(
                "<CS:invite-accepted/><CS:in-reply-to>{}</CS:in-reply-to>",
                "x".repeat(256)
            )),
        ];
        for xml in bad {
            let problem = reply_of(&xml).unwrap_err();
            assert_eq!(problem.code(), davhaven_http::problem::ProblemCode::BadRequest, "{xml}");
        }
    }

    #[tokio::test]
    async fn a_request_whose_items_all_succeeded_is_a_plain_200() {
        let response = share_response(
            &[ShareItemResult {
                address: address("mailto:ben@acme.example"),
                error: None,
            }],
            &BTreeMap::new(),
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, "");
        assert_eq!(share_response(&[], &BTreeMap::new()).status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn every_item_is_answered_with_its_status_and_precondition_sorted_by_the_href_the_client_sent() {
        let owner_href = Href::parse("/dav/calendars/acme/anna/work/").unwrap();
        let named: BTreeMap<String, String> = BTreeMap::from([
            (
                "mailto:ben@acme.example".to_owned(),
                "mailto:Ben@Acme.example".to_owned(),
            ),
            (
                "mailto:guest@elsewhere.example".to_owned(),
                "mailto:Guest@Elsewhere.example".to_owned(),
            ),
        ]);
        let response = share_response(
            &[
                ShareItemResult {
                    address: address("mailto:rita@acme.example"),
                    error: Some(AppError::need_privilege(owner_href.clone(), Privilege::Share)),
                },
                ShareItemResult {
                    address: address("mailto:guest@elsewhere.example"),
                    error: Some(
                        AppError::forbidden()
                            .with_precondition(davhaven_domain::Precondition::InvalidSharee(owner_href.clone())),
                    ),
                },
                ShareItemResult {
                    address: address("mailto:ben@acme.example"),
                    error: None,
                },
            ],
            &named,
        );
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let body = body_of(response).await;
        let root = read(&body);
        let responses: Vec<&Element> = root.children_named(NS_DAV, "response").collect();
        assert_eq!(responses.len(), 3, "the applied item is answered as well: {body}");
        let hrefs: Vec<String> = responses
            .iter()
            .map(|response| response.child(NS_DAV, "href").unwrap().text())
            .collect();
        assert_eq!(
            hrefs,
            [
                "mailto:Ben@Acme.example",
                "mailto:Guest@Elsewhere.example",
                "mailto:rita@acme.example"
            ],
            "sorted, as the client wrote the addresses it named and normalized for the one it did not"
        );
        assert_eq!(responses[0].child(NS_DAV, "status").unwrap().text(), "HTTP/1.1 200 OK");
        assert!(responses[0].child(NS_DAV, "error").is_none());
        assert_eq!(
            responses[1].child(NS_DAV, "status").unwrap().text(),
            "HTTP/1.1 403 Forbidden"
        );
        assert!(
            responses[1].child(NS_DAV, "error").is_none(),
            "the catalog has no element for it"
        );
        let need = responses[2]
            .child(NS_DAV, "error")
            .and_then(|error| error.child(NS_DAV, "need-privileges"))
            .unwrap_or_else(|| panic!("{body}"));
        let resource = need.child(NS_DAV, "resource").unwrap();
        assert_eq!(
            resource.child(NS_DAV, "href").unwrap().text(),
            "/dav/calendars/acme/anna/work/"
        );
        assert!(
            resource
                .child(NS_DAV, "privilege")
                .unwrap()
                .child(NS_CALENDARSERVER, "share")
                .is_some()
        );
    }

    #[test]
    fn the_shared_collection_is_named_in_the_answer_to_an_acceptance() {
        let document = shared_as_document(&ResourcePath::parse("/dav/calendars/acme/ben/annas-work/").unwrap());
        let root = read(&document);
        assert!(root.is(NS_CALENDARSERVER, "shared-as"));
        assert_eq!(
            root.child(NS_DAV, "href").unwrap().text(),
            "/dav/calendars/acme/ben/annas-work/"
        );
        assert!(document.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"));
    }

    #[test]
    fn apple_calendar_shares_with_one_person_at_a_time() {
        let read_write = parse_share(&read(&fixture("share-set-read-write.xml")))
            .unwrap()
            .request;
        assert_eq!(
            read_write.set,
            vec![ShareeSet {
                address: address("mailto:ben@acme.example"),
                common_name: Some("Ben Baker".to_owned()),
                summary: Some("Work".to_owned()),
                access: GrantAccess::ReadWrite,
            }]
        );
        assert_eq!(read_write.remove, Vec::<CalendarUserAddress>::new());

        let read_only = parse_share(&read(&fixture("share-set-read.xml"))).unwrap().request;
        assert_eq!(read_only.set[0].access, GrantAccess::Read);
        assert_eq!(read_only.set[0].common_name, None);
        assert_eq!(read_only.set[0].summary, None);

        let remove = parse_share(&read(&fixture("share-remove.xml"))).unwrap().request;
        assert_eq!(remove.set, Vec::<ShareeSet>::new());
        assert_eq!(remove.remove, vec![address("mailto:ben@acme.example")]);
    }

    #[test]
    fn one_request_can_invite_change_and_remove() {
        let request = parse_share(&read(&fixture("share-set-and-remove.xml")))
            .unwrap()
            .request;
        let invited: Vec<&str> = request.set.iter().map(|sharee| sharee.address.as_str()).collect();
        assert_eq!(invited, ["mailto:ben@acme.example", "mailto:guest@elsewhere.example"]);
        assert_eq!(request.remove, vec![address("mailto:cara@acme.example")]);
    }

    #[test]
    fn the_answers_of_a_sharee_are_read_with_the_invitation_they_name() {
        let accepted = reply_of(&fixture("invite-reply-accepted.xml")).unwrap();
        assert!(accepted.accepted);
        assert_eq!(accepted.in_reply_to.as_str(), "7b2c4f10-4d2e-4f55-9a3e-0d3b2a6c1e11");
        assert_eq!(
            accepted.host_url,
            Some(ResourcePath::parse("/dav/calendars/acme/anna/work/").unwrap())
        );
        assert_eq!(accepted.summary.as_deref(), Some("Work"));
        let declined = reply_of(&fixture("invite-reply-declined.xml")).unwrap();
        assert!(!declined.accepted);
        assert_eq!(declined.in_reply_to, accepted.in_reply_to);
        assert_eq!(declined.summary, None);
    }

    #[test]
    fn the_answer_to_an_acceptance_is_the_document_clients_read() {
        let shared_as = ResourcePath::parse("/dav/calendars/acme/ben/annas-work/").unwrap();
        assert_eq!(shared_as_document(&shared_as), fixture("invite-reply-response.xml"));
    }

    #[test]
    fn a_share_request_cannot_be_an_invitation_reply_and_the_other_way_round() {
        let share = read(&fixture("share-set-read.xml"));
        let reply = read(&fixture("invite-reply-accepted.xml"));
        assert!(parse_invite_reply(&share).is_err());
        assert!(parse_share(&reply).is_err());
    }
}
