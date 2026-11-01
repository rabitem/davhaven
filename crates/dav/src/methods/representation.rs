//! Bodies of text and the representation of single resources.
//!
//! Two things every module that handles one resource at a time needs, in one place so that calendar objects,
//! notifications and inbox items behave alike:
//!
//! * [`read_text_body`] reads the body of a request that carries calendar data or an iTIP message (`PUT` of an
//!   object, `POST` to the outbox): at most `max_resource_size` bytes, and UTF-8;
//! * [`represent`] serves a resource the way `GET` and `HEAD` do (RFC 9110): the body with its validators, or the
//!   status that the conditional headers of the request ask for instead.

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, LAST_MODIFIED};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, Utc};
use davhaven_domain::ETag;
use davhaven_http::limits::{BodyError, read_body};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use super::{Call, headers, set_header, status_only};
use crate::props::http_date;
use crate::xml::requests::bad_request;

/// The `Content-Length` the client declared, when it is a number.
fn declared_length(request: &HeaderMap) -> Option<u64> {
    headers::text(request, "content-length")?.trim().parse().ok()
}

fn resource_too_large() -> EdgeProblem {
    EdgeProblem::new(ProblemCode::ResourceTooLarge)
}

/// Reads the body of a request that carries calendar data or an iTIP message: at most `max_resource_size` bytes of
/// UTF-8. A declared length above the limit is refused before the body is read.
///
/// # Errors
///
/// 403 `CALDAV:max-resource-size` for a body above the limit, 400 for a body that cannot be read, and the problem
/// `not_text` with `detail` for a body that is not UTF-8.
pub(crate) async fn read_text_body(
    call: &Call<'_>,
    body: Body,
    not_text: ProblemCode,
    detail: &'static str,
) -> Result<String, EdgeProblem> {
    let max = call.limits().ical.max_resource_size;
    if declared_length(call.headers()).is_some_and(|length| length > max) {
        return Err(resource_too_large());
    }
    let limit = usize::try_from(max).unwrap_or(usize::MAX);
    let bytes = read_body(body, limit).await.map_err(|error| match error {
        BodyError::TooLarge => resource_too_large(),
        BodyError::Unreadable => bad_request("The request body could not be read."),
    })?;
    String::from_utf8(Vec::from(bytes)).map_err(|_| EdgeProblem::new(not_text).with_detail(detail))
}

/// One resource as `GET` and `HEAD` serve it.
pub(crate) struct Representation<'a> {
    /// The media type of the body.
    pub(crate) content_type: &'a str,
    /// The strong entity tag of the body.
    pub(crate) etag: &'a ETag,
    /// When the resource was last changed.
    pub(crate) last_modified: DateTime<Utc>,
    /// The body.
    pub(crate) body: String,
}

/// Serves a resource the way `GET` and `HEAD` of calendar objects do (RFC 9110): conditional requests are answered
/// with 304 or 412 without the body, `HEAD` has the length and no body.
///
/// # Errors
///
/// 412 when `If-Match` fails or cannot be read.
pub(crate) fn represent(
    request: &HeaderMap,
    head: bool,
    representation: Representation<'_>,
) -> Result<Response, EdgeProblem> {
    if let Some(status) = headers::read_condition(request, representation.etag) {
        if status == StatusCode::PRECONDITION_FAILED {
            return Err(EdgeProblem::new(ProblemCode::PreconditionFailed));
        }
        let mut response = status_only(status);
        set_header(&mut response, ETAG, representation.etag.as_str());
        return Ok(response);
    }
    let length = representation.body.len();
    let mut response = Response::new(if head {
        Body::empty()
    } else {
        Body::from(representation.body)
    });
    set_header(&mut response, CONTENT_TYPE, representation.content_type);
    set_header(&mut response, ETAG, representation.etag.as_str());
    set_header(&mut response, LAST_MODIFIED, &http_date(representation.last_modified));
    set_header(&mut response, CACHE_CONTROL, "private, no-cache");
    if head {
        set_header(&mut response, CONTENT_LENGTH, &length.to_string());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn document(etag: &ETag) -> Representation<'_> {
        Representation {
            content_type: "text/xml; charset=utf-8",
            etag,
            last_modified: chrono::TimeZone::with_ymd_and_hms(&Utc, 2027, 1, 2, 3, 4, 5).unwrap(),
            body: "<a/>".to_owned(),
        }
    }

    async fn text_of(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn the_declared_length_is_a_number_or_nothing() {
        assert_eq!(declared_length(&request_with(&[("content-length", " 42 ")])), Some(42));
        assert_eq!(declared_length(&request_with(&[("content-length", "many")])), None);
        assert_eq!(declared_length(&request_with(&[("content-length", "-1")])), None);
        assert_eq!(declared_length(&HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn a_resource_is_served_with_its_validators_and_without_caching() {
        let etag = ETag::from_bytes(b"<a/>");
        let response = represent(&HeaderMap::new(), false, document(&etag)).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/xml; charset=utf-8");
        assert_eq!(response.headers()[ETAG], etag.as_str());
        assert_eq!(response.headers()[LAST_MODIFIED], "Sat, 02 Jan 2027 03:04:05 GMT");
        assert_eq!(response.headers()[CACHE_CONTROL], "private, no-cache");
        assert!(response.headers().get(CONTENT_LENGTH).is_none());
        assert_eq!(text_of(response).await, "<a/>");

        let head = represent(&HeaderMap::new(), true, document(&etag)).unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers()[CONTENT_LENGTH],
            "4",
            "HEAD has the length of the body it does not send"
        );
        assert_eq!(text_of(head).await, "");
    }

    #[tokio::test]
    async fn conditional_reads_are_answered_without_the_body() {
        let etag = ETag::from_bytes(b"<a/>");
        let same = request_with(&[("if-none-match", etag.as_str())]);
        let response = represent(&same, false, document(&etag)).unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(response.headers()[ETAG], etag.as_str());
        assert_eq!(text_of(response).await, "");

        let other = request_with(&[("if-none-match", "\"another\"")]);
        assert_eq!(
            represent(&other, false, document(&etag)).unwrap().status(),
            StatusCode::OK
        );

        let stale = request_with(&[("if-match", "\"another\"")]);
        let problem = represent(&stale, false, document(&etag)).unwrap_err();
        assert_eq!(problem.code(), ProblemCode::PreconditionFailed);
        let current = request_with(&[("if-match", etag.as_str())]);
        assert_eq!(
            represent(&current, false, document(&etag)).unwrap().status(),
            StatusCode::OK
        );
    }
}
