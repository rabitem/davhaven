//! Responses of the management API: JSON documents with their `ETag`, `Location`, `Link` and `Cache-Control`.
//!
//! Handlers build a `Reply` and return it; errors are returned as `EdgeProblem` and rendered by the edge.
//! Versioned resources (tenants, principals, calendars, grants, webhooks) answer with the `ETag` derived from their
//! `version` (the `Versioned` trait); responses that carry a secret, a feed URL or a client profile are marked `no-store`
//! (PLAN 2.10).
//!
//! # What may be replayed
//!
//! The idempotency layer stores the response of a keyed `POST` so that a retry gets it again. A response is stored
//! **only when its handler says so** with `Reply::replayable`: the default is that nothing is kept, so a handler
//! that forgets to think about it can never leave a secret in the idempotency table (a plaintext app password, a feed
//! URL, a webhook secret would be replayed to anyone who repeats the request). The handlers whose responses carry
//! no secret (batch upserts, pings, redeliveries, retries, inbound iTIP) mark theirs; the handlers that mint a secret
//! do not, and are also `no-store`, which the layer checks as a second guard.

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, ETAG, LINK, LOCATION};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use davhaven_app::services::Upserted;
use davhaven_http::EdgeProblem;
use davhaven_wire::{CalendarView, GrantView, PrincipalView, ProblemCode, TenantView, WebhookView, etag_for_version};
use serde::Serialize;
use url::Url;

/// A resource with an optimistic concurrency counter; the counter is the `ETag`.
pub(crate) trait Versioned {
    /// The version of the resource.
    fn version(&self) -> i64;
}

macro_rules! versioned {
    ($($view:ty),+ $(,)?) => {
        $(
            impl Versioned for $view {
                fn version(&self) -> i64 {
                    self.version
                }
            }
        )+
    };
}

versioned!(TenantView, PrincipalView, CalendarView, GrantView, WebhookView);

/// The body of a reply.
#[derive(Debug)]
enum Payload {
    /// No body.
    Empty,
    /// A JSON document.
    Json(Vec<u8>),
    /// A file with its own media type.
    Binary { content_type: &'static str, data: Vec<u8> },
    /// The reply could not be built; the edge renders the problem instead.
    Failed(EdgeProblem),
}

/// The marker, in the extensions of a response, that its handler allows the idempotency layer to store and replay
/// it ([`Reply::replayable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Replayable;

/// A successful response under construction.
#[derive(Debug)]
pub(crate) struct Reply {
    status: StatusCode,
    payload: Payload,
    headers: Vec<(HeaderName, HeaderValue)>,
    replayable: bool,
}

impl Reply {
    const fn new(status: StatusCode, payload: Payload) -> Self {
        Self {
            status,
            payload,
            headers: Vec::new(),
            replayable: false,
        }
    }

    /// A JSON document with the given status.
    pub(crate) fn json<T: Serialize>(status: StatusCode, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(bytes) => Self::new(status, Payload::Json(bytes)),
            Err(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                Payload::Failed(EdgeProblem::new(ProblemCode::Internal)),
            ),
        }
    }

    /// A JSON document of a versioned resource, with its `ETag`.
    pub(crate) fn versioned<T: Serialize + Versioned>(status: StatusCode, value: &T) -> Self {
        Self::json(status, value).with_header(ETAG, &etag_for_version(value.version()))
    }

    /// The answer of a create-or-replace: 201 with the `Location` of the new resource, or 200.
    pub(crate) fn upserted<T: Serialize + Versioned>(outcome: &Upserted<T>, location: Option<&Url>) -> Self {
        if outcome.created {
            let reply = Self::versioned(StatusCode::CREATED, &outcome.value);
            match location {
                Some(url) => reply.with_location(url),
                None => reply,
            }
        } else {
            Self::versioned(StatusCode::OK, &outcome.value)
        }
    }

    /// 204 without a body.
    pub(crate) const fn no_content() -> Self {
        Self::new(StatusCode::NO_CONTENT, Payload::Empty)
    }

    /// A file download. The file name is reduced to letters, digits, dots, hyphens and underscores.
    pub(crate) fn binary(content_type: &'static str, filename: &str, data: Vec<u8>) -> Self {
        let safe: String = filename
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Self::new(StatusCode::OK, Payload::Binary { content_type, data })
            .with_header(CONTENT_DISPOSITION, &format!("attachment; filename=\"{safe}\""))
    }

    /// Adds a header; a value that is not a valid header value is dropped.
    #[must_use]
    pub(crate) fn with_header(mut self, name: HeaderName, value: &str) -> Self {
        if let Ok(value) = HeaderValue::from_str(value) {
            self.headers.push((name, value));
        }
        self
    }

    /// Adds `Location`.
    #[must_use]
    pub(crate) fn with_location(self, url: &Url) -> Self {
        self.with_header(LOCATION, url.as_str())
    }

    /// Adds `Link: <reference>; rel="next"` (RFC 8288). The reference is relative (`/api/v1/...?cursor=...`): it names
    /// the next page on the origin the client already reached the API on, which the server cannot know (the API
    /// is served on the internal listener, behind whatever proxy or private name the client used).
    #[must_use]
    pub(crate) fn link_next(self, reference: &str) -> Self {
        self.with_header(LINK, &format!("<{reference}>; rel=\"next\""))
    }

    /// Allows the idempotency layer to store this response and replay it to a retry of the request. Only for
    /// responses that contain no secret: see the module documentation.
    #[must_use]
    pub(crate) const fn replayable(mut self) -> Self {
        self.replayable = true;
        self
    }

    /// Marks the response as not cacheable anywhere: it carries a secret, a feed URL or a client profile.
    #[must_use]
    pub(crate) fn no_store(self) -> Self {
        self.with_header(CACHE_CONTROL, "no-store")
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let (content_type, body) = match self.payload {
            Payload::Failed(problem) => return problem.into_response(),
            Payload::Empty => (None, Body::empty()),
            Payload::Json(bytes) => (Some("application/json"), Body::from(bytes)),
            Payload::Binary { content_type, data } => (Some(content_type), Body::from(data)),
        };
        let mut response = Response::new(body);
        *response.status_mut() = self.status;
        let headers = response.headers_mut();
        if let Some(content_type) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        for (name, value) in self.headers {
            headers.append(name, value);
        }
        if self.replayable {
            response.extensions_mut().insert(Replayable);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt as _;

    use super::*;

    async fn read(reply: Reply) -> (Response, String) {
        let mut response = reply.into_response();
        let body = std::mem::take(response.body_mut());
        let bytes = body.collect().await.unwrap().to_bytes();
        (response, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[derive(Serialize)]
    struct Thing {
        name: &'static str,
        version: i64,
    }

    impl Versioned for Thing {
        fn version(&self) -> i64 {
            self.version
        }
    }

    #[tokio::test]
    async fn versioned_replies_carry_the_etag_of_their_version() {
        let (response, body) = read(Reply::versioned(StatusCode::OK, &Thing { name: "a", version: 7 })).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[ETAG], "\"v7\"");
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(body, r#"{"name":"a","version":7}"#);
    }

    #[tokio::test]
    async fn creations_point_at_the_new_resource_and_replacements_do_not() {
        let url = Url::parse("https://cal.example.org/api/v1/things/a").unwrap();
        let created = Upserted::created(Thing { name: "a", version: 1 });
        let (response, _) = read(Reply::upserted(&created, Some(&url))).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[LOCATION], "https://cal.example.org/api/v1/things/a");
        let replaced = Upserted::replaced(Thing { name: "a", version: 2 });
        let (response, _) = read(Reply::upserted(&replaced, Some(&url))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(LOCATION).is_none());
    }

    #[tokio::test]
    async fn empty_binary_and_marked_replies() {
        let (response, body) = read(Reply::no_content()).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(body.is_empty() && response.headers().get(CONTENT_TYPE).is_none());

        let file = Reply::binary(
            "application/x-apple-aspen-config",
            "my calendar/../x.mobileconfig",
            b"<plist/>".to_vec(),
        );
        let (response, body) = read(file.no_store()).await;
        assert_eq!(response.headers()[CONTENT_TYPE], "application/x-apple-aspen-config");
        assert_eq!(
            response.headers()[CONTENT_DISPOSITION],
            "attachment; filename=\"my_calendar_.._x.mobileconfig\""
        );
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(body, "<plist/>");
    }

    #[tokio::test]
    async fn links_to_the_next_page_use_the_link_header_with_a_relative_reference() {
        let (response, _) =
            read(Reply::json(StatusCode::OK, &Vec::<u8>::new()).link_next("/api/v1/things?cursor=abc")).await;
        assert_eq!(response.headers()[LINK], "</api/v1/things?cursor=abc>; rel=\"next\"");
    }

    #[tokio::test]
    async fn only_replies_that_say_so_may_be_replayed() {
        let (plain, _) = read(Reply::json(StatusCode::OK, &Vec::<u8>::new())).await;
        assert!(
            plain.extensions().get::<Replayable>().is_none(),
            "nothing is replayable by default"
        );
        let (marked, _) = read(Reply::json(StatusCode::OK, &Vec::<u8>::new()).replayable()).await;
        assert_eq!(marked.extensions().get::<Replayable>(), Some(&Replayable));
    }

    #[test]
    fn invalid_header_values_are_dropped_instead_of_failing_the_reply() {
        let reply = Reply::no_content().with_header(ETAG, "bad\nvalue");
        assert_eq!(reply.headers.len(), 0);
    }
}
