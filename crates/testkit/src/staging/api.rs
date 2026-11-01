//! A small client of the management API for the preparation of a run.

use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::StagingError;
use crate::handles::Actor;
use crate::transport::{TestRequest, TestResponse, Transport};

/// The prefix of every path of the management API.
pub const V1: &str = "/api/v1";

/// The statuses of a request that created or replaced something.
pub const WRITTEN: &[u16] = &[200, 201, 204];

/// The statuses of a read.
pub const READ: &[u16] = &[200];

/// The statuses of a deletion.
pub const DELETED: &[u16] = &[200, 204];

/// The management API as one credential sees it.
#[derive(Clone)]
pub struct Api {
    transport: Arc<dyn Transport>,
    actor: Actor,
}

impl core::fmt::Debug for Api {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Api").finish_non_exhaustive()
    }
}

/// The longest listing [`Api::all`] follows: a server that never ends a listing is a failure, not a reason to ask for ever.
pub const MAX_PAGES: usize = 1000;

/// The start of a body on one line, for messages, without secrets.
pub fn excerpt(response: &TestResponse) -> String {
    response.excerpt(240)
}

impl Api {
    /// The API as the holder of `actor`.
    pub fn new(transport: Arc<dyn Transport>, actor: Actor) -> Self {
        Self { transport, actor }
    }

    /// The transport the requests go through.
    pub fn transport(&self) -> Arc<dyn Transport> {
        Arc::clone(&self.transport)
    }

    /// Sends a request with a JSON body (or none) and returns the answer, whatever its status.
    ///
    /// # Errors
    ///
    /// [`StagingError::Transport`] when the request cannot be carried.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        headers: &[(&str, &str)],
    ) -> Result<TestResponse, StagingError> {
        let mut request = TestRequest::new(method, path).header("accept", "application/json");
        if let Some(authorization) = self.actor.authorization() {
            request = request.header("authorization", &authorization);
        }
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            let content_type = if method.eq_ignore_ascii_case("PATCH") {
                "application/merge-patch+json"
            } else {
                "application/json"
            };
            let bytes = serde_json::to_vec(body)
                .map_err(|error| StagingError::setup(format!("a request body cannot be written: {error}")))?;
            request = request.content(content_type, bytes);
        }
        Ok(self.transport.send(request).await?)
    }

    /// Sends a request and requires one of the `accepted` statuses.
    ///
    /// # Errors
    ///
    /// [`StagingError::Unexpected`] for any other status, naming `what`.
    pub async fn call(
        &self,
        what: &str,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        accepted: &[u16],
    ) -> Result<TestResponse, StagingError> {
        self.call_with(what, method, path, body, &[], accepted).await
    }

    /// [`Api::call`] with extra headers.
    ///
    /// # Errors
    ///
    /// As [`Api::call`].
    pub async fn call_with(
        &self,
        what: &str,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        headers: &[(&str, &str)],
        accepted: &[u16],
    ) -> Result<TestResponse, StagingError> {
        let response = self.send(method, path, body, headers).await?;
        if accepted.contains(&response.status.as_u16()) {
            Ok(response)
        } else {
            Err(StagingError::Unexpected {
                what: what.to_owned(),
                status: response.status.as_u16(),
                excerpt: excerpt(&response),
            })
        }
    }

    /// Sends a request and reads the answer as `T`.
    ///
    /// # Errors
    ///
    /// As [`Api::call`], and [`StagingError::Setup`] when the answer is not a `T`.
    pub async fn json<T: DeserializeOwned>(
        &self,
        what: &str,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        accepted: &[u16],
    ) -> Result<T, StagingError> {
        let response = self.call(what, method, path, body, accepted).await?;
        response
            .json()
            .map_err(|error| StagingError::setup(format!("{what}: the answer cannot be read: {error}")))
    }

    /// `GET` of a path, read as `T`.
    ///
    /// # Errors
    ///
    /// As [`Api::json`].
    pub async fn get<T: DeserializeOwned>(&self, what: &str, path: &str) -> Result<T, StagingError> {
        self.json(what, "GET", path, None::<&()>, READ).await
    }

    /// Every item of a cursor-paged listing at `path` (which may already have a query).
    ///
    /// The listing ends when a page has no `next_cursor`. A cursor that comes back (a server that answers the same page
    /// again), more than [`MAX_PAGES`] pages, and a `Link: rel="next"` header that does not agree with `next_cursor` (PLAN
    /// 2.10 has both) are errors.
    ///
    /// # Errors
    ///
    /// As [`Api::json`], and [`StagingError::Setup`] for a listing that does not end or whose two ways of saying "more"
    /// disagree.
    pub async fn all<T: DeserializeOwned>(&self, what: &str, path: &str) -> Result<Vec<T>, StagingError> {
        use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
        let separator = if path.contains('?') { '&' } else { '?' };
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..MAX_PAGES {
            let target = match &cursor {
                None => format!("{path}{separator}limit=200"),
                Some(cursor) => format!(
                    "{path}{separator}limit=200&cursor={}",
                    utf8_percent_encode(cursor, NON_ALPHANUMERIC)
                ),
            };
            let response = self.call(what, "GET", &target, None::<&()>, READ).await?;
            let page: davhaven_wire::Page<T> = response
                .json()
                .map_err(|error| StagingError::setup(format!("{what}: the answer cannot be read: {error}")))?;
            let announced = response
                .header("link")
                .is_some_and(|link| link.contains("rel=\"next\"") || link.contains("rel=next"));
            if announced != page.next_cursor.is_some() {
                return Err(StagingError::setup(format!(
                    "{what}: `next_cursor` and `Link: rel=\"next\"` disagree (cursor {}, link {})",
                    if page.next_cursor.is_some() {
                        "present"
                    } else {
                        "absent"
                    },
                    if announced { "present" } else { "absent" }
                )));
            }
            items.extend(page.items);
            let Some(next) = page.next_cursor else {
                return Ok(items);
            };
            let next = next.as_str().to_owned();
            if seen.contains(&next) {
                return Err(StagingError::setup(format!(
                    "{what}: the listing answers with a cursor it has given before, and would never end"
                )));
            }
            seen.push(next.clone());
            cursor = Some(next);
        }
        Err(StagingError::setup(format!(
            "{what}: the listing has more than {MAX_PAGES} pages"
        )))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::transport::{FnTransport, TransportError};

    fn api(answer: impl Fn(&TestRequest) -> Result<TestResponse, TransportError> + Send + Sync + 'static) -> Api {
        Api::new(Arc::new(FnTransport::new(answer)), Actor::bearer("secret"))
    }

    #[tokio::test]
    async fn requests_carry_the_credential_the_content_type_of_their_method_and_their_body() {
        let api = api(|request| {
            let authorization = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok());
            let content_type = request
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok());
            Ok(TestResponse::new(
                200,
                format!(
                    "{} {} {} {}",
                    request.method,
                    authorization.unwrap_or("-"),
                    content_type.unwrap_or("-"),
                    String::from_utf8_lossy(&request.body)
                ),
            ))
        });
        let put = api.send("PUT", "/x", Some(&json!({"a": 1})), &[]).await.unwrap();
        assert_eq!(put.text(), "PUT Bearer secret application/json {\"a\":1}");
        let patch = api.send("PATCH", "/x", Some(&json!({"a": null})), &[]).await.unwrap();
        assert!(
            patch.text().contains("application/merge-patch+json"),
            "{}",
            patch.text()
        );
        let get = api.send("GET", "/x", None::<&()>, &[("x-test", "1")]).await.unwrap();
        assert_eq!(get.text(), "GET Bearer secret - ");
    }

    #[tokio::test]
    async fn an_unexpected_status_names_the_request_and_shows_the_answer() {
        let api = api(|_| {
            Ok(TestResponse::new(
                409,
                "{\"code\":\"conflict\",\n \"detail\":\"taken\"}",
            ))
        });
        let error = api
            .call("making the tenant", "PUT", "/x", None::<&()>, WRITTEN)
            .await
            .unwrap_err();
        let text = error.to_string();
        assert!(
            text.starts_with("making the tenant: the instance answered 409"),
            "{text}"
        );
        assert!(text.contains("\"code\":\"conflict\", \"detail\":\"taken\""), "{text}");
        let value: Result<serde_json::Value, _> = api.get("reading", "/x").await;
        assert!(matches!(value, Err(StagingError::Unexpected { status: 409, .. })));
    }

    #[tokio::test]
    async fn listings_are_read_page_by_page_with_the_cursor_of_the_previous_page() {
        let api = api(|request| {
            Ok(if request.target.contains("cursor=") {
                assert!(
                    request.target.contains("cursor=c%2B1"),
                    "the cursor is encoded: {}",
                    request.target
                );
                TestResponse::new(200, json!({"items": [3]}).to_string())
            } else {
                TestResponse::new(200, json!({"items": [1, 2], "next_cursor": "c+1"}).to_string())
                    .with_header("link", "</things?cursor=c%2B1>; rel=\"next\"")
            })
        });
        let items: Vec<u32> = api.all("listing", "/things").await.unwrap();
        assert_eq!(items, vec![1, 2, 3]);
        let queried: Vec<u32> = api.all("listing", "/things?kind=a").await.unwrap();
        assert_eq!(queried, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn a_listing_that_never_ends_or_contradicts_itself_is_an_error() {
        // The same cursor again: the server answers the same page for ever.
        let looping = api(|_| {
            Ok(
                TestResponse::new(200, json!({"items": [1], "next_cursor": "same"}).to_string())
                    .with_header("link", "</x?cursor=same>; rel=\"next\""),
            )
        });
        let error = looping.all::<u32>("listing", "/things").await.unwrap_err();
        assert!(error.to_string().contains("never end"), "{error}");

        // A cursor without the `Link` header (and the other way round): the two ways of saying "more" must agree.
        let cursor_only = api(|_| {
            Ok(TestResponse::new(
                200,
                json!({"items": [1], "next_cursor": "c"}).to_string(),
            ))
        });
        let error = cursor_only.all::<u32>("listing", "/things").await.unwrap_err();
        assert!(error.to_string().contains("disagree"), "{error}");
        let link_only = api(|_| {
            Ok(TestResponse::new(200, json!({"items": [1]}).to_string()).with_header("link", "</x>; rel=\"next\""))
        });
        let error = link_only.all::<u32>("listing", "/things").await.unwrap_err();
        assert!(error.to_string().contains("disagree"), "{error}");

        // Pages without end that never repeat a cursor stop at the page limit.
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let endless = api(move |_| {
            let number = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(TestResponse::new(
                200,
                json!({"items": [1], "next_cursor": format!("c{number}")}).to_string(),
            )
            .with_header("link", "</x>; rel=\"next\""))
        });
        let error = endless.all::<u32>("listing", "/things").await.unwrap_err();
        assert!(error.to_string().contains("more than 1000 pages"), "{error}");
    }
}
