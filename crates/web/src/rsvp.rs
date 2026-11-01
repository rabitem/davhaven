//! RSVP pages: read-only GET and CSRF-protected POST answers.
//!
//! External attendees reach their invitation through `/rsvp/{token}` (PLAN 2.13). `GET` is read-only and works
//! without JavaScript. `POST` takes the answer as an HTML form: `partstat` (`ACCEPTED`, `DECLINED` or
//! `TENTATIVE`), an optional `comment` of at most 500 characters and the `csrf` token that the page contained;
//! it is repeatable, so an attendee can change their mind. The application renders both pages, checks the CSRF
//! token (bound to the RSVP token, valid for one hour) and enforces the rules of the invitation. The edge has
//! already refused foreign `Origin` headers, so the same-origin check of the plan holds before this handler runs.
//! Unknown, expired and revoked tokens answer the same 404 page.

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use davhaven_app::services::{CsrfToken, PresentedCredential, RenderedPage, RsvpAnswer, SecretString};
use davhaven_domain::{Channel, PartStat};
use davhaven_http::limits::read_body;
use davhaven_http::problem::{EdgeProblem, FieldProblem, ProblemCode};

use crate::router::{Meta, WebState};

/// The largest form body accepted, in bytes.
const MAX_FORM_BYTES: usize = 16 * 1024;
/// The longest comment of an answer, in characters.
const MAX_COMMENT_CHARS: usize = 500;
/// The longest CSRF token accepted, in bytes.
const MAX_CSRF_BYTES: usize = 512;

/// The fields of the answer form.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RsvpForm {
    partstat: String,
    comment: Option<String>,
    csrf: String,
}

/// A form field that is missing, repeated or invalid, as a 422 problem.
fn field_problem(pointer: &str, code: &str, message: &str) -> EdgeProblem {
    EdgeProblem::new(ProblemCode::ValidationFailed)
        .with_detail("The answer is not valid.")
        .with_error(FieldProblem::new(pointer, code, message))
}

/// Parses the `application/x-www-form-urlencoded` body of an answer.
///
/// Unknown fields are ignored; a known field that appears twice is refused, so that a field cannot be smuggled
/// past a check that looks at the first occurrence only.
pub(crate) fn parse_form(body: &[u8]) -> Result<RsvpForm, EdgeProblem> {
    let mut partstat = None;
    let mut comment = None;
    let mut csrf = None;
    for (name, value) in url::form_urlencoded::parse(body) {
        let slot = match name.as_ref() {
            "partstat" => &mut partstat,
            "comment" => &mut comment,
            "csrf" => &mut csrf,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(field_problem(&format!("/{name}"), "duplicate", "must be sent once"));
        }
    }
    let partstat = partstat.ok_or_else(|| field_problem("/partstat", "required", "an answer is required"))?;
    let csrf = csrf.ok_or_else(|| field_problem("/csrf", "required", "the form token is required"))?;
    Ok(RsvpForm {
        partstat,
        comment,
        csrf,
    })
}

impl RsvpForm {
    /// Checks the fields and builds the answer and the CSRF token for the service.
    pub(crate) fn into_answer(self) -> Result<(RsvpAnswer, CsrfToken), EdgeProblem> {
        let partstat = PartStat::from_ical(&self.partstat)
            .filter(|partstat| partstat.is_answer())
            .ok_or_else(|| field_problem("/partstat", "invalid", "must be ACCEPTED, DECLINED or TENTATIVE"))?;
        if self.csrf.is_empty() || self.csrf.len() > MAX_CSRF_BYTES {
            return Err(field_problem("/csrf", "invalid", "the form token is not valid"));
        }
        let comment = self
            .comment
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty());
        if comment
            .as_ref()
            .is_some_and(|text| text.chars().count() > MAX_COMMENT_CHARS)
        {
            return Err(field_problem(
                "/comment",
                "too-long",
                "must have at most 500 characters",
            ));
        }
        Ok((RsvpAnswer { partstat, comment }, CsrfToken::new(self.csrf)))
    }
}

/// Whether the request body is an HTML form.
fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// An HTML page as a response.
pub(crate) fn html(page: RenderedPage) -> Response {
    let mut response = Response::new(Body::from(page.html));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    response
}

/// Shows the invitation to the attendee the token belongs to.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(token): Path<String>,
    meta: Meta,
) -> Result<Response, EdgeProblem> {
    let credential = PresentedCredential::Rsvp(SecretString::from(token.as_str()));
    let ctx = state.authenticate(Channel::Rsvp, credential, &token, meta).await?;
    let page = state.services.scheduling.rsvp_page(&ctx).await?;
    Ok(html(page))
}

/// Records the answer of the attendee and shows the result page.
pub(crate) async fn answer(
    State(state): State<WebState>,
    Path(token): Path<String>,
    meta: Meta,
    request: Request,
) -> Result<Response, EdgeProblem> {
    let credential = PresentedCredential::Rsvp(SecretString::from(token.as_str()));
    let ctx = state.authenticate(Channel::Rsvp, credential, &token, meta).await?;
    if !is_form(request.headers()) {
        return Err(
            EdgeProblem::new(ProblemCode::UnsupportedMediaType).with_detail("The answer must be sent as an HTML form.")
        );
    }
    let body = read_body(request.into_body(), MAX_FORM_BYTES)
        .await
        .map_err(EdgeProblem::from)?;
    let (answer, csrf) = parse_form(&body)?.into_answer()?;
    let page = state.services.scheduling.rsvp_answer(&ctx, answer, csrf).await?;
    Ok(html(page))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(text: &str) -> Result<RsvpForm, EdgeProblem> {
        parse_form(text.as_bytes())
    }

    #[test]
    fn forms_are_parsed_with_percent_decoding_and_unknown_fields_ignored() {
        let parsed = form("partstat=ACCEPTED&comment=See+you%21&csrf=v1.abc&submit=Send").unwrap();
        assert_eq!(parsed.partstat, "ACCEPTED");
        assert_eq!(parsed.comment.as_deref(), Some("See you!"));
        assert_eq!(parsed.csrf, "v1.abc");
        let minimal = form("csrf=t&partstat=DECLINED").unwrap();
        assert_eq!(minimal.comment, None);
    }

    #[test]
    fn missing_and_repeated_fields_are_422_with_a_pointer() {
        for (body, pointer) in [
            ("csrf=t", "/partstat"),
            ("partstat=ACCEPTED", "/csrf"),
            ("partstat=ACCEPTED&partstat=DECLINED&csrf=t", "/partstat"),
            ("partstat=ACCEPTED&csrf=a&csrf=b", "/csrf"),
            ("partstat=ACCEPTED&csrf=t&comment=a&comment=b", "/comment"),
        ] {
            let problem = form(body).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::ValidationFailed, "{body}");
            assert_eq!(problem.errors()[0].pointer, pointer, "{body}");
        }
    }

    #[test]
    fn only_the_three_answers_of_an_attendee_are_accepted() {
        for good in ["ACCEPTED", "DECLINED", "TENTATIVE", "accepted"] {
            let (answer, _) = form(&format!("partstat={good}&csrf=t")).unwrap().into_answer().unwrap();
            assert_eq!(answer.partstat.as_ical(), good.to_ascii_uppercase());
        }
        for bad in ["NEEDS-ACTION", "DELEGATED", "COMPLETED", "", "YES"] {
            let problem = form(&format!("partstat={bad}&csrf=t"))
                .unwrap()
                .into_answer()
                .unwrap_err();
            assert_eq!(problem.errors()[0].pointer, "/partstat", "{bad}");
        }
    }

    #[test]
    fn comments_are_trimmed_and_limited_to_500_characters() {
        let (answer, csrf) = form("partstat=ACCEPTED&csrf=token&comment=++hello++")
            .unwrap()
            .into_answer()
            .unwrap();
        assert_eq!(answer.comment.as_deref(), Some("hello"));
        assert_eq!(csrf.as_str(), "token");
        let (empty, _) = form("partstat=ACCEPTED&csrf=t&comment=+++")
            .unwrap()
            .into_answer()
            .unwrap();
        assert_eq!(empty.comment, None);
        let exactly = "ä".repeat(500);
        assert!(
            form(&format!("partstat=ACCEPTED&csrf=t&comment={exactly}"))
                .unwrap()
                .into_answer()
                .is_ok()
        );
        let too_long = "ä".repeat(501);
        let problem = form(&format!("partstat=ACCEPTED&csrf=t&comment={too_long}"))
            .unwrap()
            .into_answer()
            .unwrap_err();
        assert_eq!(problem.errors()[0].pointer, "/comment");
    }

    #[test]
    fn csrf_tokens_must_be_present_and_short() {
        let longest = "a".repeat(512);
        let (_, csrf) = form(&format!("partstat=ACCEPTED&csrf={longest}"))
            .unwrap()
            .into_answer()
            .unwrap();
        assert_eq!(csrf.as_str(), longest);
        for bad in [String::new(), "a".repeat(513)] {
            let problem = form(&format!("partstat=ACCEPTED&csrf={bad}"))
                .unwrap()
                .into_answer()
                .unwrap_err();
            assert_eq!(problem.code(), ProblemCode::ValidationFailed, "{bad:.10}");
            assert_eq!(problem.errors()[0].pointer, "/csrf", "{bad:.10}");
        }
    }

    #[test]
    fn only_urlencoded_forms_count_as_forms() {
        let headers = |value: &str| {
            let mut map = HeaderMap::new();
            map.insert(CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
            map
        };
        assert!(is_form(&headers("application/x-www-form-urlencoded")));
        assert!(is_form(&headers("Application/X-WWW-Form-Urlencoded; charset=utf-8")));
        for bad in ["application/json", "text/plain", "multipart/form-data; boundary=x"] {
            assert!(!is_form(&headers(bad)), "{bad}");
        }
        assert!(!is_form(&HeaderMap::new()));
    }
}
