//! Reading what a server answered as one of the outcomes of the status policy.
//!
//! The status policy (PLAN 2.6, the `[status.*]` tables of the expectations file) has five outcomes: allowed,
//! unauthenticated (401), hidden (404), forbidden (403) and precondition failed (412). [`classify`] maps a response to
//! one of them, or to [`Observed::Other`] when the server answered something the policy does not know (a 400 or 5xx
//! almost always means the probe or the server is broken, not that a permission was decided).
//!
//! A multistatus (207) carries its outcome inside: PROPPATCH answers 207 with a 403 for the property it refuses, and a
//! REPORT answers 207 with the status of every resource, so the classification reads the statuses of the responses and
//! of their propstats.
//!
//! Besides the status, [`detail_problems`] checks the form of a refusal on its surface (the challenge of a 401, the
//! `DAV:need-privileges` document of a 403 with its resource and privilege, the RFC 9457 problem of the API with its media
//! type and `type`), [`no_busy_time`] checks that a free-busy answer shows no busy time, and [`same_kind`] compares two
//! answers for the difference a caller could tell apart (the answer to a hidden resource and to one that does not exist).

use serde_json::Value;

use crate::handles::mcp_message;
use crate::matrix::{Expectation, StatusPolicy, Surface};
use crate::transport::TestResponse;
use crate::xml::{Document, Element};

/// What the server answered, in the vocabulary of the status policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    /// One of the outcomes of the policy.
    Is(Expectation),
    /// Something else, with a description.
    Other(String),
}

impl core::fmt::Display for Observed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Is(expectation) => write!(f, "{expectation}"),
            Self::Other(what) => write!(f, "other ({what})"),
        }
    }
}

/// How the response of a probe is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classifier {
    /// The status decides; a 207 is read through the statuses inside it.
    Http,
    /// The response is an MCP `tools/call` result: the HTTP status decides authentication, the tool result the rest.
    McpTool,
    /// The response is the result of an MCP tool that takes the addresses of people of the caller's organisation: an address
    /// of somebody who is not one (another tenant's person, nobody) is a validation failure, which is the answer to the
    /// question and does not say whether the person exists, so it counts as allowed.
    McpPeople,
    /// The response is the result of the MCP tool `list_calendars`: the calendar is allowed when it is listed and
    /// hidden when it is not (a listing never fails for a calendar that is invisible).
    McpListed {
        /// The id of the calendar that has to be listed.
        calendar_id: String,
    },
    /// The response is the result of an MCP tool that looks for events in every calendar the caller can see
    /// (`search_events`): allowed when the event is among them, hidden when it is not.
    McpFound {
        /// The id of the event that has to be found.
        event_id: String,
    },
    /// The response is a page of the calendars of a principal (`listCalendars`): allowed when the calendar is on it, hidden
    /// when it is not (the listing leaves out what the caller cannot see).
    ApiListed {
        /// The slug of the calendar that has to be listed.
        slug: String,
    },
}

/// The classification of one response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    /// The outcome.
    pub observed: Observed,
    /// The HTTP status.
    pub status: u16,
}

fn class_of_status(status: u16) -> Observed {
    match status {
        200..=299 => Observed::Is(Expectation::Allow),
        401 => Observed::Is(Expectation::Unauthenticated),
        403 => Observed::Is(Expectation::Forbidden),
        404 => Observed::Is(Expectation::Hidden),
        412 => Observed::Is(Expectation::PreconditionFailed),
        other => Observed::Other(format!("status {other}")),
    }
}

/// The statuses inside a multistatus: of the responses and of their propstats.
fn inner_statuses(response: &TestResponse) -> Option<Vec<u16>> {
    let document = Document::parse(&response.text()).ok()?;
    let entries = document.multistatus().ok()?;
    let mut statuses = Vec::new();
    for entry in entries {
        statuses.extend(entry.status);
        statuses.extend(entry.propstats.iter().map(|propstat| propstat.status));
    }
    Some(statuses)
}

/// Reads a multistatus: all inner statuses are 2xx (allowed); a 403 among them is a refusal; only 404s are an invisible
/// resource; anything else is not an outcome of the policy.
fn classify_multistatus(response: &TestResponse) -> Observed {
    let Some(statuses) = inner_statuses(response) else {
        return Observed::Other("a 207 that is no multistatus".to_owned());
    };
    if statuses.iter().all(|status| (200..300).contains(status)) {
        return Observed::Is(Expectation::Allow);
    }
    if statuses.contains(&403) {
        return Observed::Is(Expectation::Forbidden);
    }
    // Properties the server does not have answer 404 next to the ones it has: that is a successful request.
    if statuses.iter().any(|status| (200..300).contains(status)) {
        return Observed::Is(Expectation::Allow);
    }
    if statuses.iter().all(|status| *status == 404) {
        return Observed::Is(Expectation::Hidden);
    }
    Observed::Other(format!("a multistatus with the statuses {statuses:?}"))
}

/// Classifies a response.
pub fn classify(classifier: &Classifier, response: &TestResponse) -> Classified {
    let status = response.status.as_u16();
    let observed = match classifier {
        Classifier::Http => {
            if status == 207 {
                classify_multistatus(response)
            } else {
                class_of_status(status)
            }
        }
        Classifier::McpTool => crate::permissions::mcp::classify_tool_result(response),
        Classifier::McpPeople => crate::permissions::mcp::classify_people_result(response),
        Classifier::McpListed { calendar_id } => crate::permissions::mcp::classify_listing(response, calendar_id),
        Classifier::McpFound { event_id } => crate::permissions::mcp::classify_found(response, event_id),
        Classifier::ApiListed { slug } => classify_api_listing(response, slug),
    };
    Classified { observed, status }
}

/// Reads a page of calendars: allowed when `slug` is on it, hidden when it is not, the status otherwise.
fn classify_api_listing(response: &TestResponse, slug: &str) -> Observed {
    if response.status.as_u16() != 200 {
        return class_of_status(response.status.as_u16());
    }
    let Ok(page) = response.json::<Value>() else {
        return Observed::Other("a listing that is no JSON".to_owned());
    };
    let listed = page.get("items").and_then(Value::as_array).is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("slug").and_then(Value::as_str) == Some(slug))
    });
    Observed::Is(if listed {
        Expectation::Allow
    } else {
        Expectation::Hidden
    })
}

/// The checks on the details of an outcome that the status policy asks for besides the status:
///
/// * a 401 carries the challenge of its surface (`Basic` on DAV, `Bearer` on the API and MCP);
/// * a 403 on DAV is a `DAV:error` document with `DAV:need-privileges`, which names a resource (`DAV:href`, a path of the
///   DAV surface) and a privilege (RFC 3744 section 7.1.1);
/// * a 401, 403, 404 or 412 on the API is an RFC 9457 problem: `application/problem+json`, `type` the URN of the code
///   the policy names for the outcome, and that `code`.
pub fn detail_problems(
    surface: Surface,
    observed: &Observed,
    response: &TestResponse,
    policy: &StatusPolicy,
) -> Vec<String> {
    let mut problems = Vec::new();
    let Observed::Is(outcome) = observed else {
        return problems;
    };
    let wanted_code = policy.rule(*outcome).and_then(|rule| rule.problem_code.as_deref());
    match outcome {
        Expectation::Unauthenticated => {
            let wanted = match surface {
                Surface::Dav => Some("Basic"),
                Surface::Api | Surface::Mcp => Some("Bearer"),
                Surface::Feed | Surface::Rsvp => None,
            };
            if let Some(scheme) = wanted {
                match response.header("www-authenticate") {
                    Some(challenge) if challenge.starts_with(scheme) => {}
                    Some(challenge) => {
                        problems.push(format!("the challenge is `{challenge}`, not a {scheme} challenge"));
                    }
                    None => problems.push(format!("the 401 carries no {scheme} challenge")),
                }
            }
            if surface == Surface::Api {
                problems.extend(problem_document(response, wanted_code));
            }
        }
        Expectation::Forbidden if response.status.as_u16() == 403 => match surface {
            Surface::Dav => problems.extend(need_privileges(response)),
            Surface::Api => problems.extend(problem_document(response, wanted_code)),
            Surface::Mcp | Surface::Feed | Surface::Rsvp => {}
        },
        Expectation::Hidden | Expectation::PreconditionFailed if surface == Surface::Api => {
            problems.extend(problem_document(response, wanted_code));
        }
        _ => {}
    }
    problems
}

/// What is wrong with a `DAV:error` document of a 403 that is an authorization decision: it has to say which resource lacks
/// which privilege.
fn need_privileges(response: &TestResponse) -> Vec<String> {
    let mut problems = Vec::new();
    let document = match Document::parse(&response.text()) {
        Ok(document) => document,
        Err(error) => return vec![format!("the 403 does not carry a DAV:error document: {error}")],
    };
    let resource = "/{DAV:}error/{DAV:}need-privileges/{DAV:}resource";
    match document.select(&format!("{resource}/{{DAV:}}href")) {
        Ok(hrefs) if hrefs.iter().any(|href| href.trim().starts_with("/dav/")) => {}
        Ok(hrefs) => problems.push(format!(
            "DAV:need-privileges names no resource of the DAV surface (hrefs: {hrefs:?})"
        )),
        Err(error) => problems.push(error.to_string()),
    }
    match document.count(&format!("{resource}/{{DAV:}}privilege/*")) {
        Ok(count) if count > 0 => {}
        Ok(_) => problems.push("DAV:need-privileges names no privilege".to_owned()),
        Err(error) => problems.push(error.to_string()),
    }
    problems
}

/// What is wrong with an RFC 9457 problem document: the media type, the `type` and the `code`.
fn problem_document(response: &TestResponse, code: Option<&str>) -> Vec<String> {
    let mut problems = Vec::new();
    let content_type = response.header("content-type").unwrap_or_default();
    if !content_type.starts_with("application/problem+json") {
        problems.push(format!(
            "the media type is `{content_type}`, not application/problem+json"
        ));
    }
    let body = match response.json::<Value>() {
        Ok(body) => body,
        Err(error) => {
            problems.push(format!("the answer is no problem document: {error}"));
            return problems;
        }
    };
    let Some(code) = code else {
        return problems;
    };
    if body.get("code").and_then(Value::as_str) != Some(code) {
        problems.push(format!(
            "the problem code is {:?}, not `{code}`",
            body.get("code").and_then(Value::as_str)
        ));
    }
    let wanted_type = format!("urn:davhaven:problem:{code}");
    if body.get("type").and_then(Value::as_str) != Some(wanted_type.as_str()) {
        problems.push(format!(
            "the problem type is {:?}, not `{wanted_type}`",
            body.get("type").and_then(Value::as_str)
        ));
    }
    problems
}

/// What is wrong with the answer to a free-busy request of somebody who may not see busy time of the calendar's owner (a
/// user of another tenant): it must show none. On DAV the answer is a schedule response that may not carry a `FREEBUSY`
/// property; over MCP the entry of the address must be unknown and have no periods.
pub fn no_busy_time(surface: Surface, response: &TestResponse) -> Vec<String> {
    let mut problems = Vec::new();
    match surface {
        Surface::Dav => {
            let text = response.text();
            let unfolded = text.replace("\r\n ", "").replace("\n ", "");
            for line in unfolded.lines().map(str::trim) {
                let upper = line.to_ascii_uppercase();
                if upper.starts_with("FREEBUSY;") || upper.starts_with("FREEBUSY:") {
                    problems.push(format!("the answer carries busy time: `{line}`"));
                }
            }
        }
        Surface::Mcp => match mcp_message(response) {
            Ok(message) => {
                let entries = message
                    .pointer("/result/structuredContent/entries")
                    .and_then(Value::as_array);
                for entry in entries.into_iter().flatten() {
                    if entry.get("known").and_then(Value::as_bool) == Some(true) {
                        problems.push("the address of another tenant is known to free_busy".to_owned());
                    }
                    if entry
                        .get("busy")
                        .and_then(Value::as_array)
                        .is_some_and(|periods| !periods.is_empty())
                    {
                        problems.push("the answer carries busy periods of another tenant's person".to_owned());
                    }
                }
            }
            Err(error) => problems.push(format!("the answer cannot be read: {error}")),
        },
        Surface::Api | Surface::Feed | Surface::Rsvp => {}
    }
    problems
}

// ---------------------------------------------------------------------------------------------------------------
// Whether two answers can be told apart
// ---------------------------------------------------------------------------------------------------------------

/// The parts of an answer that a caller can tell apart: the status, the kind of body, and for a refusal the problem (code,
/// title and detail) or the elements of the `DAV:error`. The texts the request names (the slug of a calendar, an id) are
/// replaced, so that a refusal that repeats what it was asked for is the same as one that repeats something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    status: u16,
    content_type: String,
    code: Option<String>,
    title: Option<String>,
    detail: Option<String>,
    elements: Vec<String>,
}

/// `text` with every occurrence of every subject replaced by one marker, in a single pass (a marker is never searched
/// again, so a subject that is a part of the marker cannot change it).
fn replace_all(text: &str, subjects: &[&str]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(rest) = text.get(at..) {
        let Some(character) = rest.chars().next() else {
            break;
        };
        if let Some(subject) = subjects
            .iter()
            .find(|subject| !subject.is_empty() && rest.starts_with(**subject))
        {
            out.push_str("{subject}");
            at += subject.len();
        } else {
            out.push(character);
            at += character.len_utf8();
        }
    }
    out
}

fn element_names(element: &Element, names: &mut Vec<String>) {
    names.push(element.clark());
    for child in element.elements() {
        element_names(child, names);
    }
}

/// The shape of an answer; `subjects` are the texts of the request that the body may repeat.
pub fn shape_of(response: &TestResponse, subjects: &[&str]) -> Shape {
    let content_type = response
        .header("content-type")
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    let mut shape = Shape {
        status: response.status.as_u16(),
        content_type,
        code: None,
        title: None,
        detail: None,
        elements: Vec::new(),
    };
    let text = response.text();
    if let Ok(body) = serde_json::from_str::<Value>(&text) {
        // A problem document of the API; the instance and the request id differ between any two answers and are left out.
        let text_of = |value: Option<&Value>| value.and_then(Value::as_str).map(|text| replace_all(text, subjects));
        shape.code = text_of(body.get("code"));
        shape.title = text_of(body.get("title"));
        shape.detail = text_of(body.get("detail"));
        // An MCP answer is a JSON-RPC envelope: the problem is in the metadata of the result, the text in its content.
        if let Some(result) = body.get("result") {
            shape.code = text_of(result.pointer("/_meta/davhaven~1problem/code"));
            shape.title = text_of(result.pointer("/_meta/davhaven~1problem/title"));
            shape.detail = result
                .get("content")
                .and_then(Value::as_array)
                .map(|content| {
                    content
                        .iter()
                        .filter_map(|part| part.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .map(|text| replace_all(&text, subjects));
        }
    } else if let Ok(document) = Document::parse(&text) {
        element_names(&document.root, &mut shape.elements);
    }
    shape
}

/// Whether two answers are the same kind of answer: the status, the kind of body and the problem they carry. The texts in
/// `subjects` (the slug of the calendar, the key of an object, an id) are what the two requests differ in.
///
/// # Errors
///
/// What differs, as text.
pub fn same_kind(a: &TestResponse, b: &TestResponse, subjects: &[&str]) -> Result<(), String> {
    let (left, right) = (shape_of(a, subjects), shape_of(b, subjects));
    if left.status != right.status {
        return Err(format!(
            "the status is {} where the other gets {}",
            left.status, right.status
        ));
    }
    if left.content_type != right.content_type {
        return Err(format!(
            "the content type is `{}` where the other gets `{}`",
            left.content_type, right.content_type
        ));
    }
    for (what, one, other) in [
        ("problem code", &left.code, &right.code),
        ("problem title", &left.title, &right.title),
        ("problem detail", &left.detail, &right.detail),
    ] {
        if one != other {
            return Err(format!("the {what} is {one:?} where the other gets {other:?}"));
        }
    }
    if left.elements != right.elements {
        return Err(format!(
            "the DAV error has the elements {:?} where the other has {:?}",
            left.elements, right.elements
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::matrix::Expectations;

    fn policy() -> StatusPolicy {
        Expectations::bundled().unwrap().status().clone()
    }

    fn multistatus(statuses: &[u16]) -> TestResponse {
        let mut body = String::from(r#"<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">"#);
        for status in statuses {
            body.push_str(
                "<D:response><D:href>/x</D:href><D:propstat><D:prop><D:displayname/></D:prop><D:status>HTTP/1.1 ",
            );
            body.push_str(&status.to_string());
            body.push_str(" X</D:status></D:propstat></D:response>");
        }
        body.push_str("</D:multistatus>");
        TestResponse::new(207, body)
    }

    fn problem(status: u16, code: &str) -> TestResponse {
        TestResponse::new(
            status,
            json!({"type": format!("urn:davhaven:problem:{code}"), "code": code, "title": "T", "request_id": "r"})
                .to_string(),
        )
        .with_header("content-type", "application/problem+json")
    }

    #[test]
    fn statuses_map_to_the_outcomes_of_the_policy() {
        let class = |status| classify(&Classifier::Http, &TestResponse::new(status, "")).observed;
        assert_eq!(class(201), Observed::Is(Expectation::Allow));
        assert_eq!(class(204), Observed::Is(Expectation::Allow));
        assert_eq!(class(401), Observed::Is(Expectation::Unauthenticated));
        assert_eq!(class(403), Observed::Is(Expectation::Forbidden));
        assert_eq!(class(404), Observed::Is(Expectation::Hidden));
        assert_eq!(class(412), Observed::Is(Expectation::PreconditionFailed));
        assert!(matches!(class(409), Observed::Other(_)));
        assert!(matches!(class(500), Observed::Other(_)));
        assert!(matches!(class(501), Observed::Other(_)));
    }

    #[test]
    fn a_multistatus_is_read_through_its_statuses() {
        let class = |statuses: &[u16]| classify(&Classifier::Http, &multistatus(statuses)).observed;
        assert_eq!(class(&[200, 200]), Observed::Is(Expectation::Allow));
        assert_eq!(
            class(&[200, 404]),
            Observed::Is(Expectation::Allow),
            "unknown properties next to known ones"
        );
        assert_eq!(class(&[403]), Observed::Is(Expectation::Forbidden));
        assert_eq!(class(&[200, 403]), Observed::Is(Expectation::Forbidden));
        assert_eq!(class(&[404, 404]), Observed::Is(Expectation::Hidden));
        assert!(matches!(class(&[424]), Observed::Other(_)));
        assert!(matches!(
            classify(&Classifier::Http, &TestResponse::new(207, "not xml")).observed,
            Observed::Other(_)
        ));
    }

    #[test]
    fn a_listing_of_calendars_allows_what_it_names_and_hides_the_rest() {
        let page = TestResponse::new(
            200,
            json!({"items": [{"slug": "personal"}, {"slug": "projects"}]}).to_string(),
        );
        let on = |slug: &str| classify(&Classifier::ApiListed { slug: slug.to_owned() }, &page).observed;
        assert_eq!(on("projects"), Observed::Is(Expectation::Allow));
        assert_eq!(on("google"), Observed::Is(Expectation::Hidden));
        assert_eq!(
            classify(
                &Classifier::ApiListed {
                    slug: "personal".to_owned()
                },
                &TestResponse::new(403, "")
            )
            .observed,
            Observed::Is(Expectation::Forbidden)
        );
    }

    #[test]
    fn the_challenge_of_a_401_follows_the_surface() {
        let policy = policy();
        let unauthorized = TestResponse::new(401, "").with_header("www-authenticate", "Basic realm=\"x\"");
        let refusal = Observed::Is(Expectation::Unauthenticated);
        assert_eq!(
            detail_problems(Surface::Dav, &refusal, &unauthorized, &policy),
            Vec::<String>::new()
        );
        assert!(
            detail_problems(Surface::Api, &refusal, &unauthorized, &policy)
                .contains(&"the challenge is `Basic realm=\"x\"`, not a Bearer challenge".to_owned()),
            "a Basic challenge on the API"
        );
        assert_eq!(
            detail_problems(Surface::Mcp, &refusal, &unauthorized, &policy),
            vec!["the challenge is `Basic realm=\"x\"`, not a Bearer challenge".to_owned()],
            "MCP takes the tokens of the API and has no problem document on a 401"
        );
        assert_eq!(
            detail_problems(Surface::Dav, &refusal, &TestResponse::new(401, ""), &policy),
            vec!["the 401 carries no Basic challenge".to_owned()]
        );
        let bearer = TestResponse::new(401, "").with_header("www-authenticate", "Bearer realm=\"x\"");
        assert_eq!(
            detail_problems(Surface::Dav, &refusal, &bearer, &policy),
            vec!["the challenge is `Bearer realm=\"x\"`, not a Basic challenge".to_owned()],
            "DAV clients log in with Basic"
        );
        assert_eq!(
            detail_problems(Surface::Mcp, &refusal, &bearer, &policy),
            Vec::<String>::new()
        );
        assert_eq!(
            detail_problems(Surface::Feed, &refusal, &TestResponse::new(401, ""), &policy),
            Vec::<String>::new(),
            "the pages are reached by the token in their link and ask for no credentials"
        );
        let api = problem(401, "unauthenticated").with_header("www-authenticate", "Bearer realm=\"x\"");
        assert_eq!(
            detail_problems(Surface::Api, &refusal, &api, &policy),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_403_on_dav_must_say_which_resource_lacks_which_privilege() {
        let policy = policy();
        let forbidden = Observed::Is(Expectation::Forbidden);
        let check = |body: &str| {
            detail_problems(
                Surface::Dav,
                &forbidden,
                &TestResponse::new(403, body.to_owned()),
                &policy,
            )
        };
        let good = r#"<D:error xmlns:D="DAV:"><D:need-privileges><D:resource><D:href>/dav/calendars/acme/olivia/personal/</D:href><D:privilege><D:write-content/></D:privilege></D:resource></D:need-privileges></D:error>"#;
        assert_eq!(check(good), Vec::<String>::new());
        // The element alone is not the document RFC 3744 asks for.
        assert_ne!(
            check("<D:error xmlns:D=\"DAV:\"><D:need-privileges/></D:error>"),
            Vec::<String>::new()
        );
        assert_ne!(check("nope"), Vec::<String>::new());
        let no_privilege = good.replace("<D:privilege><D:write-content/></D:privilege>", "");
        assert!(
            check(&no_privilege)
                .iter()
                .any(|problem| problem.contains("no privilege"))
        );
        let elsewhere = good.replace("/dav/calendars", "/elsewhere/calendars");
        assert!(check(&elsewhere).iter().any(|problem| problem.contains("no resource")));
    }

    #[test]
    fn a_refusal_of_the_api_is_a_problem_of_the_code_the_policy_names() {
        let policy = policy();
        let detail = |observed: Expectation, response: &TestResponse| {
            detail_problems(Surface::Api, &Observed::Is(observed), response, &policy)
        };
        assert_eq!(
            detail(Expectation::Forbidden, &problem(403, "forbidden")),
            Vec::<String>::new()
        );
        assert_eq!(
            detail(Expectation::Hidden, &problem(404, "not-found")),
            Vec::<String>::new()
        );
        assert_eq!(
            detail(Expectation::PreconditionFailed, &problem(412, "precondition-failed")),
            Vec::<String>::new()
        );
        // The wrong code, a plain JSON body, a wrong `type` and a wrong media type are four different findings.
        assert_ne!(
            detail(Expectation::Forbidden, &problem(403, "conflict")),
            Vec::<String>::new()
        );
        assert_ne!(
            detail(
                Expectation::Forbidden,
                &TestResponse::new(403, r#"{"code":"forbidden"}"#)
            ),
            Vec::<String>::new()
        );
        let wrong_type = TestResponse::new(404, json!({"type": "about:blank", "code": "not-found"}).to_string())
            .with_header("content-type", "application/problem+json");
        assert!(
            detail(Expectation::Hidden, &wrong_type)
                .iter()
                .any(|problem| problem.contains("type"))
        );
        let plain = TestResponse::new(
            404,
            json!({"type": "urn:davhaven:problem:not-found", "code": "not-found"}).to_string(),
        )
        .with_header("content-type", "application/json");
        assert!(
            detail(Expectation::Hidden, &plain)
                .iter()
                .any(|problem| problem.contains("media type"))
        );
        assert_ne!(
            detail(Expectation::Forbidden, &TestResponse::new(403, "x")),
            Vec::<String>::new()
        );
        // DAV and the pages have no problem document to check on a 404.
        assert_eq!(
            detail_problems(
                Surface::Dav,
                &Observed::Is(Expectation::Hidden),
                &TestResponse::new(404, ""),
                &policy
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn busy_time_in_an_answer_to_somebody_who_may_not_see_it_is_found() {
        let schedule = |lines: &str| {
            TestResponse::new(
                200,
                format!(
                    "<C:schedule-response xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><C:calendar-data>BEGIN:VCALENDAR\r\nBEGIN:VFREEBUSY\r\n{lines}END:VFREEBUSY\r\nEND:VCALENDAR\r\n</C:calendar-data></C:schedule-response>"
                ),
            )
        };
        assert_eq!(
            no_busy_time(Surface::Dav, &schedule("REQUEST-STATUS:3.7;Invalid\r\n")),
            Vec::<String>::new()
        );
        let leaking = schedule("FREEBUSY;FBTYPE=BUSY:20270315T090000Z/20270315T100000Z\r\n");
        assert_eq!(no_busy_time(Surface::Dav, &leaking).len(), 1);
        // A folded property line is still a property line.
        let folded = schedule("FREEBUSY;FBTYPE=BUSY:20270315T090000Z/\r\n 20270315T100000Z\r\n");
        assert_eq!(no_busy_time(Surface::Dav, &folded).len(), 1);

        let entry = |known: bool, busy: Value| {
            TestResponse::new(
                200,
                json!({"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {"entries": [{"address": "a", "known": known, "busy": busy}]}}}).to_string(),
            )
            .with_header("content-type", "application/json")
        };
        assert_eq!(
            no_busy_time(Surface::Mcp, &entry(false, json!([]))),
            Vec::<String>::new()
        );
        assert_eq!(no_busy_time(Surface::Mcp, &entry(true, json!([]))).len(), 1);
        let periods = entry(
            false,
            json!([{"start": "2027-03-15T09:00:00Z", "end": "2027-03-15T10:00:00Z"}]),
        );
        assert_eq!(no_busy_time(Surface::Mcp, &periods).len(), 1);
        assert_ne!(
            no_busy_time(Surface::Mcp, &TestResponse::new(200, "no json")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn two_answers_are_the_same_kind_when_a_caller_cannot_tell_them_apart() {
        let missing = |slug: &str, detail: &str| {
            TestResponse::new(
                404,
                json!({"type": "urn:davhaven:problem:not-found", "code": "not-found", "title": "Resource not found",
                       "detail": detail, "instance": format!("/x/{slug}"), "request_id": slug})
                .to_string(),
            )
            .with_header("content-type", "application/problem+json")
        };
        // Texts that name the subject of the request differ by design; `instance` and `request_id` are not compared.
        assert!(same_kind(&missing("a", "no `a` here"), &missing("b", "no `b` here"), &["a", "b"]).is_ok());
        assert!(
            same_kind(
                &missing("a", "no calendar"),
                &missing("b", "there is a calendar, but you may not see it"),
                &["a", "b"]
            )
            .unwrap_err()
            .contains("problem detail")
        );
        assert!(
            same_kind(&missing("a", "x"), &TestResponse::new(403, ""), &[])
                .unwrap_err()
                .contains("status")
        );
        let xml = |inner: &str| {
            TestResponse::new(404, format!("<D:error xmlns:D=\"DAV:\">{inner}</D:error>"))
                .with_header("content-type", "application/xml")
        };
        assert!(same_kind(&xml(""), &xml(""), &[]).is_ok());
        // The parameters of the media type are no tell; another media type is.
        let charset = TestResponse::new(404, "<D:error xmlns:D=\"DAV:\"></D:error>")
            .with_header("content-type", "application/xml; charset=utf-8");
        assert!(same_kind(&xml(""), &charset, &[]).is_ok());
        let text =
            TestResponse::new(404, "<D:error xmlns:D=\"DAV:\"></D:error>").with_header("content-type", "text/xml");
        assert_eq!(
            same_kind(&xml(""), &text, &[]).unwrap_err(),
            "the content type is `application/xml` where the other gets `text/xml`"
        );
        assert!(
            same_kind(&xml("<D:need-privileges/>"), &xml(""), &[])
                .unwrap_err()
                .contains("elements")
        );
        let tool = |code: &str, text: &str| {
            TestResponse::new(
                200,
                json!({"jsonrpc": "2.0", "id": 1, "result": {"isError": true, "content": [{"type": "text", "text": text}],
                       "_meta": {"davhaven/problem": {"code": code, "title": "T"}}}})
                .to_string(),
            )
            .with_header("content-type", "application/json")
        };
        assert!(
            same_kind(
                &tool("not-found", "Resource not found"),
                &tool("not-found", "Resource not found"),
                &[]
            )
            .is_ok()
        );
        assert!(
            same_kind(
                &tool("not-found", "Resource not found"),
                &tool("forbidden", "Resource not found"),
                &[]
            )
            .unwrap_err()
            .contains("problem code")
        );
    }
}
