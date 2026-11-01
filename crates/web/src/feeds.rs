//! iCalendar subscription feeds with conditional requests.
//!
//! `GET /feeds/{token}.ics` serves the feed of a feed token (PLAN 2.13): `text/calendar; charset=utf-8`, a strong
//! `ETag` with `304` for clients that already have the current content, `Cache-Control: private, max-age=300`.
//! The route is `/feeds/{file}` because path parameters cannot be followed by a suffix; the handler requires the
//! `.ics` suffix. Calendar access is re-checked on every request by the application, so a revoked token or a
//! calendar the principal can no longer read answers 404, like every other bad token.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, LAST_MODIFIED};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use chrono::{DateTime, Utc};
use davhaven_app::services::{Conditional, FeedResponse, PresentedCredential, SecretString};
use davhaven_domain::{Channel, ETag};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::router::{Meta, WebState};

/// The cache policy of feeds: private, revalidated by the client after five minutes.
const FEED_CACHE_CONTROL: &str = "private, max-age=300";

/// The token of a feed file name: the name without `.ics`; a name without the suffix names no feed.
pub(crate) fn token_of(file: &str) -> Option<&str> {
    file.strip_suffix(".ics").filter(|token| !token.is_empty())
}

/// The conditional headers of the request: the entity tag of `If-None-Match`, when it is one strong tag.
fn conditional(headers: &HeaderMap) -> Conditional {
    let if_none_match = headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| ETag::parse(text.trim()).ok());
    Conditional { if_none_match }
}

/// An HTTP date (`Sun, 06 Nov 1994 08:49:37 GMT`).
pub(crate) fn http_date(time: DateTime<Utc>) -> String {
    time.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// The response for a feed: 304 for a current client copy, the document otherwise.
fn respond(feed: FeedResponse) -> Response {
    let (status, etag, body, modified) = match feed {
        FeedResponse::NotModified { etag } => (StatusCode::NOT_MODIFIED, etag, None, None),
        FeedResponse::Body(feed) => (StatusCode::OK, feed.etag, Some(feed.body), feed.last_modified),
    };
    let mut response = Response::new(body.map_or_else(Body::empty, Body::from));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(etag.as_str()) {
        headers.insert(ETAG, value);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(FEED_CACHE_CONTROL));
    if status == StatusCode::OK {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/calendar; charset=utf-8"));
    }
    if let Some(time) = modified
        && let Ok(value) = HeaderValue::from_str(&http_date(time))
    {
        headers.insert(LAST_MODIFIED, value);
    }
    response
}

/// Serves the feed of the token in the file name.
pub(crate) async fn feed(
    State(state): State<WebState>,
    Path(file): Path<String>,
    meta: Meta,
    headers: HeaderMap,
) -> Result<Response, EdgeProblem> {
    let Some(token) = token_of(&file) else {
        return Err(EdgeProblem::new(ProblemCode::NotFound));
    };
    let credential = PresentedCredential::Feed(SecretString::from(token));
    let ctx = state.authenticate(Channel::Feed, credential, token, meta).await?;
    let feed = state.services.feeds.render(&ctx, conditional(&headers)).await?;
    Ok(respond(feed))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use davhaven_app::services::FeedBody;
    use davhaven_domain::EventDuration;

    use super::*;

    #[test]
    fn the_token_is_the_file_name_without_the_suffix() {
        assert_eq!(token_of("dvh_feed_abc_secret.ics"), Some("dvh_feed_abc_secret"));
        for bad in ["dvh_feed_abc_secret", ".ics", "x.ICS", "x.ics.txt", ""] {
            assert_eq!(token_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn http_dates_follow_rfc_9110() {
        let time = Utc.with_ymd_and_hms(1994, 11, 6, 8, 49, 37).unwrap();
        assert_eq!(http_date(time), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn if_none_match_must_be_one_strong_tag() {
        let tag = ETag::from_bytes(b"feed");
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, HeaderValue::from_str(tag.as_str()).unwrap());
        assert_eq!(conditional(&headers).if_none_match, Some(tag));
        for bad in ["*", "W/\"abc\"", "abc", "\"a\", \"b\""] {
            headers.insert(IF_NONE_MATCH, HeaderValue::from_str(bad).unwrap());
            assert_eq!(conditional(&headers).if_none_match, None, "{bad}");
        }
        assert_eq!(conditional(&HeaderMap::new()).if_none_match, None);
    }

    fn body(text: &str) -> FeedBody {
        FeedBody {
            etag: ETag::from_bytes(text.as_bytes()),
            body: text.to_owned(),
            calendar_name: "Work".to_owned(),
            last_modified: Some(Utc.with_ymd_and_hms(2027, 3, 1, 10, 0, 0).unwrap()),
            refresh_interval: EventDuration::parse("PT15M").unwrap(),
        }
    }

    #[test]
    fn a_feed_is_text_calendar_with_validators_and_a_private_cache_policy() {
        let feed = body("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n");
        let etag = feed.etag.clone();
        let response = respond(FeedResponse::Body(feed));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/calendar; charset=utf-8");
        assert_eq!(response.headers()[ETAG], etag.as_str());
        assert_eq!(response.headers()[CACHE_CONTROL], "private, max-age=300");
        assert_eq!(response.headers()[LAST_MODIFIED], "Mon, 01 Mar 2027 10:00:00 GMT");
    }

    #[test]
    fn a_current_client_copy_gets_304_without_a_body_or_content_type() {
        let etag = ETag::from_bytes(b"x");
        let response = respond(FeedResponse::NotModified { etag: etag.clone() });
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(response.headers()[ETAG], etag.as_str());
        assert_eq!(response.headers()[CACHE_CONTROL], "private, max-age=300");
        assert!(response.headers().get(CONTENT_TYPE).is_none());
    }
}
