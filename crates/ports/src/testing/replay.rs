//! [`ReplayHttp`]: an `HttpClient` that answers from recorded exchanges.
//!
//! The tests of the provider adapters (and of the sync engine on top of them) must not reach a real provider, and no real
//! client id exists for them anyway. They replay what the providers answered when somebody recorded it: a **rule** names a
//! request (method, URL without query, the query pairs and body fragments that matter, a header) and carries the recorded
//! response; the first rule that matches a request answers it, and a request that no rule matches is an error that the test
//! sees twice (the call fails, and [`ReplayHttp::unmatched`] lists it).
//!
//! Every request is remembered, so a test can assert what was sent: the form of a token request, the header of an API call, the
//! query of a page. The double applies no egress policy; the real one is the business of `davhaven-http-egress`.

use std::sync::{Arc, PoisonError};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use url::Url;

use crate::error::PortError;
use crate::http_client::{HttpClient, HttpPurpose, OutboundRequest, OutboundResponse};

/// The double locks for an instant and never across an await.
#[expect(clippy::disallowed_types, reason = "a test double with synchronous accessors")]
type Mutex<T> = std::sync::Mutex<T>;

/// What a rule answers.
#[derive(Clone)]
enum Answer {
    Response {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    },
    Failure(PortError),
}

/// One recorded exchange: the request it matches and the answer.
///
/// Build it with [`ReplayRule::get`] or [`ReplayRule::post`], narrow it with `query`, `body_contains` and `header`, and
/// finish it with [`answers`](ReplayRule::answers) or [`fails`](ReplayRule::fails). A rule that is not finished answers
/// `200` with an empty body.
#[derive(Clone)]
pub struct ReplayRule {
    method: Method,
    url: Url,
    query: Vec<(String, String)>,
    absent: Vec<String>,
    body_parts: Vec<String>,
    headers: Vec<(HeaderName, String)>,
    answer: Answer,
    uses_left: Option<u32>,
}

impl ReplayRule {
    /// A rule for `method` and `url`. The query string of `url` is ignored: name the pairs that matter with
    /// [`query`](Self::query).
    ///
    /// # Panics
    ///
    /// When `url` is not an absolute URL (a bug of the test).
    #[must_use]
    #[expect(clippy::panic, reason = "a malformed rule is a bug of the test that wrote it")]
    pub fn new(method: Method, url: &str) -> Self {
        let mut url = Url::parse(url).unwrap_or_else(|error| panic!("the URL of a replay rule `{url}`: {error}"));
        url.set_query(None);
        url.set_fragment(None);
        Self {
            method,
            url,
            query: Vec::new(),
            absent: Vec::new(),
            body_parts: Vec::new(),
            headers: Vec::new(),
            answer: Answer::Response {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::new(),
            },
            uses_left: None,
        }
    }

    /// A rule for a `GET`.
    #[must_use]
    pub fn get(url: &str) -> Self {
        Self::new(Method::GET, url)
    }

    /// A rule for a `POST`.
    #[must_use]
    pub fn post(url: &str) -> Self {
        Self::new(Method::POST, url)
    }

    /// The request must carry this query pair (decoded).
    #[must_use]
    pub fn query(mut self, name: &str, value: &str) -> Self {
        self.query.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The request must not carry this query parameter at all.
    #[must_use]
    pub fn without_query(mut self, name: &str) -> Self {
        self.absent.push(name.to_owned());
        self
    }

    /// The body of the request, read as text, must contain `fragment` (a form pair such as `code=abc`, a JSON member).
    #[must_use]
    pub fn body_contains(mut self, fragment: &str) -> Self {
        self.body_parts.push(fragment.to_owned());
        self
    }

    /// The request must carry the header `name` with exactly this `value`.
    ///
    /// # Panics
    ///
    /// When `name` is not a header name (a bug of the test).
    #[must_use]
    #[expect(clippy::panic, reason = "a malformed rule is a bug of the test that wrote it")]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        let name =
            HeaderName::from_bytes(name.as_bytes()).unwrap_or_else(|error| panic!("header name `{name}`: {error}"));
        self.headers.push((name, value.to_owned()));
        self
    }

    /// The rule answers with `status` and `body`.
    ///
    /// # Panics
    ///
    /// When `status` is not an HTTP status (a bug of the test).
    #[must_use]
    #[expect(clippy::panic, reason = "a malformed rule is a bug of the test that wrote it")]
    pub fn answers(mut self, status: u16, body: impl Into<Bytes>) -> Self {
        let status = StatusCode::from_u16(status).unwrap_or_else(|error| panic!("status {status}: {error}"));
        self.answer = Answer::Response {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
        };
        self
    }

    /// The answer carries the header `name: value` as well.
    ///
    /// # Panics
    ///
    /// When the name or the value is not valid (a bug of the test), or when the rule does not answer with a response.
    #[must_use]
    #[expect(clippy::panic, reason = "a malformed rule is a bug of the test that wrote it")]
    pub fn answer_header(mut self, name: &str, value: &str) -> Self {
        let Answer::Response { headers, .. } = &mut self.answer else {
            panic!("a rule that fails has no response headers");
        };
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap_or_else(|error| panic!("header name `{name}`: {error}")),
            HeaderValue::from_str(value).unwrap_or_else(|error| panic!("header value of `{name}`: {error}")),
        );
        self
    }

    /// The rule fails like a transport that is down.
    #[must_use]
    pub fn fails(mut self, error: PortError) -> Self {
        self.answer = Answer::Failure(error);
        self
    }

    /// The rule answers once; after that the later rules (or none) answer.
    #[must_use]
    pub const fn once(mut self) -> Self {
        self.uses_left = Some(1);
        self
    }

    /// The rule answers `times` times.
    #[must_use]
    pub const fn times(mut self, times: u32) -> Self {
        self.uses_left = Some(times);
        self
    }

    fn matches(&self, request: &OutboundRequest) -> bool {
        if self.uses_left == Some(0) || request.method != self.method {
            return false;
        }
        let same_target = request.url.scheme() == self.url.scheme()
            && request.url.host_str() == self.url.host_str()
            && request.url.port_or_known_default() == self.url.port_or_known_default()
            && request.url.path() == self.url.path();
        if !same_target {
            return false;
        }
        let pairs: Vec<(String, String)> = request
            .url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        if !self.query.iter().all(|wanted| pairs.contains(wanted)) {
            return false;
        }
        if self
            .absent
            .iter()
            .any(|name| pairs.iter().any(|(present, _)| present == name))
        {
            return false;
        }
        let body = String::from_utf8_lossy(&request.body);
        if !self.body_parts.iter().all(|part| body.contains(part.as_str())) {
            return false;
        }
        self.headers.iter().all(|(name, value)| {
            request
                .headers
                .get(name)
                .and_then(|present| present.to_str().ok())
                .is_some_and(|present| present == value)
        })
    }
}

/// A request that [`ReplayHttp`] received.
#[derive(Clone)]
pub struct RecordedRequest {
    /// The method.
    pub method: Method,
    /// The URL with its query.
    pub url: Url,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
    /// Why the request was sent.
    pub purpose: HttpPurpose,
}

impl RecordedRequest {
    /// The decoded value of the query parameter `name`.
    pub fn query_value(&self, name: &str) -> Option<String> {
        self.url
            .query_pairs()
            .find(|(present, _)| present == name)
            .map(|(_, value)| value.into_owned())
    }

    /// The decoded value of the field `name` of a form body (`application/x-www-form-urlencoded`).
    pub fn form_value(&self, name: &str) -> Option<String> {
        url::form_urlencoded::parse(&self.body)
            .find(|(present, _)| present == name)
            .map(|(_, value)| value.into_owned())
    }

    /// The value of the header `name`, when it is text.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// The body as text.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl core::fmt::Debug for RecordedRequest {
    /// The method and the URL without its query; headers and body carry secrets.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {}://{}{}",
            self.method,
            self.url.scheme(),
            self.url.host_str().unwrap_or_default(),
            self.url.path()
        )
    }
}

#[derive(Default)]
struct State {
    rules: Vec<ReplayRule>,
    seen: Vec<RecordedRequest>,
    unmatched: Vec<String>,
}

/// An `HttpClient` that replays recorded answers. Clones share their rules and their record.
#[derive(Clone, Default)]
pub struct ReplayHttp {
    state: Arc<Mutex<State>>,
}

impl core::fmt::Debug for ReplayHttp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("ReplayHttp")
            .field("rules", &state.rules.len())
            .field("requests", &state.seen.len())
            .finish()
    }
}

impl ReplayHttp {
    /// A client without rules: every request is unmatched.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a rule. Rules are tried in the order they were added.
    #[must_use]
    pub fn with(self, rule: ReplayRule) -> Self {
        self.add(rule);
        self
    }

    /// Adds a rule to a client that is in use already.
    pub fn add(&self, rule: ReplayRule) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .rules
            .push(rule);
    }

    /// Removes every rule (the record stays), for a test that changes what the remote says in the middle.
    pub fn clear_rules(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).rules.clear();
    }

    /// The requests received so far, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).seen.clone()
    }

    /// The requests received so far that went to `host`.
    pub fn requests_to(&self, host: &str) -> Vec<RecordedRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.url.host_str() == Some(host))
            .collect()
    }

    /// A line (`GET https://host/path`) for every request that no rule matched. Empty in a test that scripted everything.
    pub fn unmatched(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unmatched
            .clone()
    }

    /// Forgets the record of requests (the rules stay).
    pub fn forget(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.seen.clear();
        state.unmatched.clear();
    }
}

#[async_trait]
impl HttpClient for ReplayHttp {
    async fn send(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.seen.push(RecordedRequest {
            method: request.method.clone(),
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
            purpose: request.purpose,
        });
        let Some(rule) = state.rules.iter_mut().find(|rule| rule.matches(&request)) else {
            let line = format!(
                "{} {}://{}{}",
                request.method,
                request.url.scheme(),
                request.url.host_str().unwrap_or_default(),
                request.url.path()
            );
            state.unmatched.push(line.clone());
            return Err(PortError::internal(format!("no replay rule matches {line}")));
        };
        if let Some(left) = &mut rule.uses_left {
            *left = left.saturating_sub(1);
        }
        match &rule.answer {
            Answer::Response { status, headers, body } => Ok(OutboundResponse {
                status: *status,
                headers: headers.clone(),
                body: body.clone(),
            }),
            Answer::Failure(error) => Err(error.clone()),
        }
    }

    async fn validate_url(&self, url: &Url) -> Result<(), PortError> {
        if url.scheme() == "https" && url.host_str().is_some() {
            Ok(())
        } else {
            Err(PortError::rejected("the replay client accepts https URLs only"))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::PortErrorKind;

    use super::*;

    fn get(url: &str) -> OutboundRequest {
        OutboundRequest::new(Method::GET, Url::parse(url).unwrap(), HttpPurpose::ProviderApi)
    }

    fn post(url: &str, body: &'static str) -> OutboundRequest {
        OutboundRequest::new(Method::POST, Url::parse(url).unwrap(), HttpPurpose::OAuth)
            .with_body(Bytes::from_static(body.as_bytes()))
    }

    #[tokio::test]
    async fn the_first_matching_rule_answers_and_the_request_is_recorded() {
        let client = ReplayHttp::new()
            .with(
                ReplayRule::get("https://api.example.org/events")
                    .query("pageToken", "p2")
                    .answers(200, "second page"),
            )
            .with(ReplayRule::get("https://api.example.org/events").answers(200, "first page"));
        let first = client
            .send(get("https://api.example.org/events?maxResults=10"))
            .await
            .unwrap();
        assert_eq!(first.body.as_ref(), b"first page");
        let second = client
            .send(get("https://api.example.org/events?maxResults=10&pageToken=p2"))
            .await
            .unwrap();
        assert_eq!(second.body.as_ref(), b"second page");
        let seen = client.requests();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].query_value("pageToken").as_deref(), Some("p2"));
        assert_eq!(client.unmatched(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn bodies_headers_and_absent_query_parameters_narrow_a_rule() {
        let client = ReplayHttp::new()
            .with(
                ReplayRule::post("https://auth.example.org/token")
                    .body_contains("code=good")
                    .answers(200, "{}"),
            )
            .with(ReplayRule::post("https://auth.example.org/token").answers(400, "{\"error\":\"invalid_grant\"}"))
            .with(
                ReplayRule::get("https://api.example.org/me")
                    .header("authorization", "Bearer t1")
                    .without_query("fields")
                    .answers(200, "me"),
            );
        assert_eq!(
            client
                .send(post("https://auth.example.org/token", "code=good&x=1"))
                .await
                .unwrap()
                .status,
            StatusCode::OK
        );
        assert_eq!(
            client
                .send(post("https://auth.example.org/token", "code=bad"))
                .await
                .unwrap()
                .status,
            StatusCode::BAD_REQUEST
        );
        let authorized = get("https://api.example.org/me").with_header(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer t1"),
        );
        assert_eq!(client.send(authorized.clone()).await.unwrap().body.as_ref(), b"me");
        let with_fields = OutboundRequest {
            url: Url::parse("https://api.example.org/me?fields=x").unwrap(),
            ..authorized
        };
        assert!(client.send(with_fields).await.is_err());
        let recorded = &client.requests()[0];
        assert_eq!(recorded.form_value("code").as_deref(), Some("good"));
        assert_eq!(client.requests()[2].header("authorization"), Some("Bearer t1"));
    }

    #[tokio::test]
    async fn rules_can_be_used_up_and_can_fail() {
        let client = ReplayHttp::new()
            .with(
                ReplayRule::get("https://api.example.org/x")
                    .answers(401, "stale")
                    .once(),
            )
            .with(ReplayRule::get("https://api.example.org/x").answers(200, "fresh"))
            .with(ReplayRule::get("https://api.example.org/down").fails(PortError::timeout("slow")));
        assert_eq!(
            client.send(get("https://api.example.org/x")).await.unwrap().status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client.send(get("https://api.example.org/x")).await.unwrap().status,
            StatusCode::OK
        );
        assert_eq!(
            client.send(get("https://api.example.org/down")).await.unwrap_err().kind,
            PortErrorKind::Timeout
        );
    }

    #[tokio::test]
    async fn a_rule_answers_as_often_as_it_is_told_and_rules_can_be_cleared_without_losing_the_record() {
        let client = ReplayHttp::new()
            .with(
                ReplayRule::get("https://api.example.org/x")
                    .answers(503, "busy")
                    .times(2),
            )
            .with(ReplayRule::get("https://api.example.org/x").answers(200, "fresh"));
        let statuses = [
            client.send(get("https://api.example.org/x")).await.unwrap().status,
            client.send(get("https://api.example.org/x")).await.unwrap().status,
            client.send(get("https://api.example.org/x")).await.unwrap().status,
        ];
        assert_eq!(
            statuses,
            [
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::OK
            ]
        );
        client.add(ReplayRule::get("https://other.example.org/y").answers(204, ""));
        client.send(get("https://other.example.org/y?token=t")).await.unwrap();
        assert_eq!(client.requests_to("api.example.org").len(), 3);
        assert_eq!(client.requests_to("other.example.org").len(), 1);
        assert!(client.requests_to("example.org").is_empty(), "the host matches exactly");

        client.clear_rules();
        assert!(
            client.send(get("https://api.example.org/x")).await.is_err(),
            "without rules nothing answers"
        );
        assert_eq!(client.requests().len(), 5, "the record stays");
        assert_eq!(client.unmatched(), vec!["GET https://api.example.org/x".to_owned()]);
    }

    #[tokio::test]
    async fn a_request_without_a_rule_fails_and_is_listed() {
        let client = ReplayHttp::new();
        let error = client
            .send(get("https://api.example.org/nothing?secret=1"))
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Internal);
        assert_eq!(
            client.unmatched(),
            vec!["GET https://api.example.org/nothing".to_owned()]
        );
        let shown = format!("{:?}", client.requests()[0]);
        assert!(!shown.contains("secret"), "{shown}");
        client.forget();
        assert!(client.requests().is_empty() && client.unmatched().is_empty());
    }

    #[tokio::test]
    async fn only_https_urls_are_valid_targets() {
        let client = ReplayHttp::new();
        assert!(
            client
                .validate_url(&Url::parse("https://api.example.org/").unwrap())
                .await
                .is_ok()
        );
        assert!(
            client
                .validate_url(&Url::parse("http://api.example.org/").unwrap())
                .await
                .is_err()
        );
    }
}
