//! Surface handles: how a test talks to the DAV, API, MCP, feed and RSVP surfaces of an application.
//!
//! A handle owns a [`Transport`] and the credentials of one actor and offers the requests of its surface. It
//! builds requests only; what the server answers is checked by the test. The handles are the same whether the
//! transport runs in process or over the network, so a test written for `TestApp` also runs from the
//! `conformance` binary.

use core::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;

use crate::transport::{TestRequest, TestResponse, Transport, TransportError};

/// How a request presents itself: no credential, HTTP Basic (an app password on DAV) or a bearer token.
#[derive(Clone, PartialEq, Eq)]
pub enum Actor {
    /// No `Authorization` header.
    Anonymous,
    /// HTTP Basic with a login (`olivia@acme.example`) and an app password.
    Basic {
        /// The login name.
        login: String,
        /// The app password.
        password: String,
    },
    /// A bearer token (an API token on the API and MCP surfaces).
    Bearer(String),
}

impl Actor {
    /// No credential.
    pub const fn anonymous() -> Self {
        Self::Anonymous
    }

    /// HTTP Basic credentials.
    pub fn basic(login: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic {
            login: login.into(),
            password: password.into(),
        }
    }

    /// A bearer token.
    pub fn bearer(secret: impl Into<String>) -> Self {
        Self::Bearer(secret.into())
    }

    /// The value of the `Authorization` header, if the actor presents a credential.
    pub fn authorization(&self) -> Option<String> {
        match self {
            Self::Anonymous => None,
            Self::Basic { login, password } => {
                Some(format!("Basic {}", STANDARD.encode(format!("{login}:{password}"))))
            }
            Self::Bearer(secret) => Some(format!("Bearer {secret}")),
        }
    }
}

impl fmt::Debug for Actor {
    /// Secrets never appear: a Basic login shows its login name only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Actor::Anonymous"),
            Self::Basic { login, .. } => write!(f, "Actor::Basic({login}, <redacted>)"),
            Self::Bearer(_) => f.write_str("Actor::Bearer(<redacted>)"),
        }
    }
}

/// An API token for the API and MCP surfaces.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Wraps the secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The secret.
    pub fn secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

impl From<&Token> for Actor {
    fn from(token: &Token) -> Self {
        Self::Bearer(token.0.clone())
    }
}

/// A request on its way: add headers and a body, then [`send`](Pending::send) it.
#[derive(Debug)]
pub struct Pending {
    transport: Arc<dyn Transport>,
    request: TestRequest,
}

impl Pending {
    fn new(transport: Arc<dyn Transport>, actor: &Actor, method: &str, target: &str) -> Self {
        let mut request = TestRequest::new(method, target);
        if let Some(authorization) = actor.authorization() {
            request = request.header("authorization", &authorization);
        }
        Self { transport, request }
    }

    /// Sets a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.request = self.request.header(name, value);
        self
    }

    /// Sets the body without a content type.
    #[must_use]
    pub fn body(mut self, body: impl Into<bytes::Bytes>) -> Self {
        self.request = self.request.body(body);
        self
    }

    /// Sets the body and the content type.
    #[must_use]
    pub fn content(mut self, content_type: &str, body: impl Into<bytes::Bytes>) -> Self {
        self.request = self.request.content(content_type, body);
        self
    }

    /// Sets the body to the JSON form of `value` with the given content type.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidRequest`] when `value` cannot be serialized.
    pub fn json(self, content_type: &str, value: &impl Serialize) -> Result<Self, TransportError> {
        let body = serde_json::to_vec(value).map_err(|error| TransportError::InvalidRequest(error.to_string()))?;
        Ok(self.content(content_type, body))
    }

    /// The request as it would be sent.
    pub const fn request(&self) -> &TestRequest {
        &self.request
    }

    /// Sends the request.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when the request is malformed or cannot be carried; HTTP error statuses are ordinary
    /// responses.
    pub async fn send(self) -> Result<TestResponse, TransportError> {
        self.transport.send(self.request).await
    }
}

/// The DAV surface (`/.well-known/caldav`, `/dav/...`) as one actor.
#[derive(Clone, Debug)]
pub struct DavHandle {
    transport: Arc<dyn Transport>,
    actor: Actor,
}

impl DavHandle {
    /// A handle that sends through `transport` as `actor`.
    pub const fn new(transport: Arc<dyn Transport>, actor: Actor) -> Self {
        Self { transport, actor }
    }

    /// The actor.
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Any request, for methods without a helper.
    pub fn request(&self, method: &str, target: &str) -> Pending {
        Pending::new(Arc::clone(&self.transport), &self.actor, method, target)
    }

    /// `OPTIONS`.
    pub fn options(&self, target: &str) -> Pending {
        self.request("OPTIONS", target)
    }

    /// `PROPFIND` with a `Depth` header and an XML body.
    pub fn propfind(&self, target: &str, depth: &str, xml: &str) -> Pending {
        self.request("PROPFIND", target)
            .header("depth", depth)
            .content("application/xml; charset=utf-8", xml.to_owned())
    }

    /// `PROPPATCH` with an XML body.
    pub fn proppatch(&self, target: &str, xml: &str) -> Pending {
        self.request("PROPPATCH", target)
            .content("application/xml; charset=utf-8", xml.to_owned())
    }

    /// `REPORT` with a `Depth` header and an XML body.
    pub fn report(&self, target: &str, depth: &str, xml: &str) -> Pending {
        self.request("REPORT", target)
            .header("depth", depth)
            .content("application/xml; charset=utf-8", xml.to_owned())
    }

    /// `GET`.
    pub fn get(&self, target: &str) -> Pending {
        self.request("GET", target)
    }

    /// `PUT` of an iCalendar body.
    pub fn put(&self, target: &str, ics: &str) -> Pending {
        self.request("PUT", target)
            .content("text/calendar; charset=utf-8", ics.to_owned())
    }

    /// `DELETE`.
    pub fn delete(&self, target: &str) -> Pending {
        self.request("DELETE", target)
    }

    /// `MKCALENDAR`, with an optional XML body.
    pub fn mkcalendar(&self, target: &str, xml: Option<&str>) -> Pending {
        let pending = self.request("MKCALENDAR", target);
        match xml {
            Some(xml) => pending.content("application/xml; charset=utf-8", xml.to_owned()),
            None => pending,
        }
    }

    /// `MOVE` to the `Destination` header value `destination`.
    pub fn move_to(&self, target: &str, destination: &str) -> Pending {
        self.request("MOVE", target).header("destination", destination)
    }

    /// `COPY` to the `Destination` header value `destination`.
    pub fn copy_to(&self, target: &str, destination: &str) -> Pending {
        self.request("COPY", target).header("destination", destination)
    }

    /// `POST` with the given content type (sharing, scheduling outbox).
    pub fn post(&self, target: &str, content_type: &str, body: &str) -> Pending {
        self.request("POST", target).content(content_type, body.to_owned())
    }
}

/// The management API (`/api/v1/...`) as one token.
#[derive(Clone, Debug)]
pub struct ApiHandle {
    transport: Arc<dyn Transport>,
    actor: Actor,
}

impl ApiHandle {
    /// A handle that sends through `transport` as `actor` (normally a bearer token).
    pub const fn new(transport: Arc<dyn Transport>, actor: Actor) -> Self {
        Self { transport, actor }
    }

    /// The actor.
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The request target of an API path: `v1("/tenants")` is `/api/v1/tenants`.
    pub fn v1(rest: &str) -> String {
        format!("/api/v1{rest}")
    }

    /// Any request.
    pub fn request(&self, method: &str, target: &str) -> Pending {
        Pending::new(Arc::clone(&self.transport), &self.actor, method, target).header("accept", "application/json")
    }

    /// `GET`.
    pub fn get(&self, target: &str) -> Pending {
        self.request("GET", target)
    }

    /// `DELETE`, with the `If-Match` header when `if_match` is given.
    pub fn delete(&self, target: &str, if_match: Option<&str>) -> Pending {
        let pending = self.request("DELETE", target);
        match if_match {
            Some(etag) => pending.header("if-match", etag),
            None => pending,
        }
    }

    /// `PUT` of a JSON body.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidRequest`] when `body` cannot be serialized.
    pub fn put_json(&self, target: &str, body: &impl Serialize) -> Result<Pending, TransportError> {
        self.request("PUT", target).json("application/json", body)
    }

    /// `POST` of a JSON body.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidRequest`] when `body` cannot be serialized.
    pub fn post_json(&self, target: &str, body: &impl Serialize) -> Result<Pending, TransportError> {
        self.request("POST", target).json("application/json", body)
    }

    /// `PATCH` with a JSON Merge Patch body.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidRequest`] when `body` cannot be serialized.
    pub fn patch_json(&self, target: &str, body: &impl Serialize) -> Result<Pending, TransportError> {
        self.request("PATCH", target).json("application/merge-patch+json", body)
    }
}

/// The MCP surface (`/mcp`, stateless streamable HTTP) as one token.
#[derive(Clone, Debug)]
pub struct McpHandle {
    transport: Arc<dyn Transport>,
    actor: Actor,
    ids: Arc<AtomicU64>,
    origin: Option<String>,
}

/// The path of the MCP endpoint.
pub const MCP_PATH: &str = "/mcp";

impl McpHandle {
    /// A handle that sends through `transport` as `actor` (normally a bearer token).
    pub fn new(transport: Arc<dyn Transport>, actor: Actor) -> Self {
        Self {
            transport,
            actor,
            ids: Arc::new(AtomicU64::new(1)),
            origin: None,
        }
    }

    /// Sends `Origin: origin` with every request (the endpoint validates it against `mcp.allowed_origins`).
    #[must_use]
    pub fn with_origin(mut self, origin: &str) -> Self {
        self.origin = Some(origin.to_owned());
        self
    }

    /// The actor.
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// A JSON-RPC request `method` with `params`.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidRequest`] when the envelope cannot be serialized.
    pub fn rpc(&self, method: &str, params: &serde_json::Value) -> Result<Pending, TransportError> {
        let id = self.ids.fetch_add(1, Ordering::SeqCst);
        let envelope = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut pending = Pending::new(Arc::clone(&self.transport), &self.actor, "POST", MCP_PATH)
            .header("accept", "application/json, text/event-stream");
        if let Some(origin) = &self.origin {
            pending = pending.header("origin", origin);
        }
        pending.json("application/json", &envelope)
    }

    /// `tools/list`.
    ///
    /// # Errors
    ///
    /// See [`McpHandle::rpc`].
    pub fn list_tools(&self) -> Result<Pending, TransportError> {
        self.rpc("tools/list", &serde_json::json!({}))
    }

    /// `tools/call` of the tool `name` with `arguments`.
    ///
    /// # Errors
    ///
    /// See [`McpHandle::rpc`].
    pub fn call_tool(&self, name: &str, arguments: &serde_json::Value) -> Result<Pending, TransportError> {
        self.rpc("tools/call", &serde_json::json!({"name": name, "arguments": arguments}))
    }
}

/// The JSON-RPC message of an MCP response: the body itself, or the last `data:` line of an event stream.
///
/// # Errors
///
/// [`TransportError::Body`] when the response holds no JSON message.
pub fn mcp_message(response: &TestResponse) -> Result<serde_json::Value, TransportError> {
    let is_stream = response
        .header("content-type")
        .is_some_and(|content_type| content_type.starts_with("text/event-stream"));
    if !is_stream {
        return response.json();
    }
    let text = response.text();
    let data = text
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("data:"))
        .ok_or_else(|| TransportError::Body("the event stream holds no data line".to_owned()))?;
    serde_json::from_str(data.trim()).map_err(|error| TransportError::Body(error.to_string()))
}

/// The subscription feed surface (`/feeds/{token}.ics`).
#[derive(Clone, Debug)]
pub struct FeedHandle {
    transport: Arc<dyn Transport>,
    token: String,
}

impl FeedHandle {
    /// A handle for the feed token `token`.
    pub fn new(transport: Arc<dyn Transport>, token: &str) -> Self {
        Self {
            transport,
            token: token.to_owned(),
        }
    }

    /// The request target of the feed.
    pub fn target(&self) -> String {
        format!("/feeds/{}.ics", self.token)
    }

    /// `GET` of the feed.
    pub fn get(&self) -> Pending {
        Pending::new(Arc::clone(&self.transport), &Actor::Anonymous, "GET", &self.target())
    }

    /// `GET` of the feed with `If-None-Match`.
    pub fn get_if_none_match(&self, etag: &str) -> Pending {
        self.get().header("if-none-match", etag)
    }
}

/// The RSVP surface (`/rsvp/{token}`).
#[derive(Clone, Debug)]
pub struct RsvpHandle {
    transport: Arc<dyn Transport>,
}

impl RsvpHandle {
    /// A handle that sends through `transport`.
    pub const fn new(transport: Arc<dyn Transport>) -> Self {
        Self { transport }
    }

    /// The request target of the page of `token`.
    pub fn target(token: &str) -> String {
        format!("/rsvp/{token}")
    }

    /// `GET` of the RSVP page (read-only).
    pub fn view(&self, token: &str) -> Pending {
        Pending::new(
            Arc::clone(&self.transport),
            &Actor::Anonymous,
            "GET",
            &Self::target(token),
        )
    }

    /// `POST` of the answer form with the given fields, for example `partstat`, `comment` and `csrf`, and the
    /// `Origin` header of the page.
    pub fn answer(&self, token: &str, origin: &str, fields: &[(&str, &str)]) -> Pending {
        let body = fields
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    utf8_percent_encode(name, NON_ALPHANUMERIC),
                    utf8_percent_encode(value, NON_ALPHANUMERIC)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        Pending::new(
            Arc::clone(&self.transport),
            &Actor::Anonymous,
            "POST",
            &Self::target(token),
        )
        .header("origin", origin)
        .content("application/x-www-form-urlencoded", body)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Receiver, channel};

    use super::*;
    use crate::transport::FnTransport;

    /// A transport that records the requests it receives.
    fn recording() -> (Arc<dyn Transport>, Receiver<TestRequest>) {
        let (sender, seen) = channel();
        let transport = FnTransport::new(move |request: &TestRequest| {
            drop(sender.send(request.clone()));
            Ok(TestResponse::new(204, ""))
        });
        (Arc::new(transport), seen)
    }

    /// The most recent request that has not been taken yet.
    fn last(seen: &Receiver<TestRequest>) -> TestRequest {
        seen.try_iter().last().unwrap()
    }

    #[test]
    fn credentials_become_authorization_headers_and_never_print() {
        assert_eq!(Actor::anonymous().authorization(), None);
        assert_eq!(
            Actor::basic("olivia@acme.example", "secret").authorization().unwrap(),
            "Basic b2xpdmlhQGFjbWUuZXhhbXBsZTpzZWNyZXQ="
        );
        assert_eq!(Actor::bearer("dvh_pat_x").authorization().unwrap(), "Bearer dvh_pat_x");
        assert_eq!(Actor::from(&Token::new("t")).authorization().unwrap(), "Bearer t");
        for shown in [
            format!("{:?}", Actor::basic("olivia", "hunter2")),
            format!("{:?}", Actor::bearer("hunter2")),
            format!("{:?}", Token::new("hunter2")),
        ] {
            assert!(!shown.contains("hunter2"), "{shown}");
        }
        assert!(format!("{:?}", Actor::basic("olivia", "x")).contains("olivia"));
        assert_eq!(Token::new("t").secret(), "t");
    }

    #[tokio::test]
    async fn dav_requests_carry_method_depth_credentials_and_bodies() {
        let (transport, seen) = recording();
        let dav = DavHandle::new(transport, Actor::basic("olivia@acme.example", "pw"));
        dav.propfind("/dav/", "0", "<propfind/>").send().await.unwrap();
        let request = last(&seen);
        assert_eq!(request.method.as_str(), "PROPFIND");
        assert_eq!(request.headers["depth"], "0");
        assert!(request.headers["authorization"].to_str().unwrap().starts_with("Basic "));
        assert!(
            request.headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("application/xml")
        );
        assert_eq!(request.body, "<propfind/>");

        dav.put("/dav/calendars/acme/olivia/personal/a.ics", "BEGIN:VCALENDAR")
            .send()
            .await
            .unwrap();
        assert_eq!(last(&seen).headers["content-type"], "text/calendar; charset=utf-8");
        dav.move_to("/a", "https://cal.example/b").send().await.unwrap();
        assert_eq!(last(&seen).headers["destination"], "https://cal.example/b");
        for (pending, method) in [
            (dav.options("/dav/"), "OPTIONS"),
            (dav.get("/x"), "GET"),
            (dav.delete("/x"), "DELETE"),
            (dav.proppatch("/x", "<a/>"), "PROPPATCH"),
            (dav.report("/x", "1", "<a/>"), "REPORT"),
            (dav.mkcalendar("/x", None), "MKCALENDAR"),
            (dav.mkcalendar("/x", Some("<a/>")), "MKCALENDAR"),
            (dav.copy_to("/x", "/y"), "COPY"),
            (dav.post("/x", "application/xml", "<a/>"), "POST"),
        ] {
            assert_eq!(pending.request().method.as_str(), method);
        }
        let anonymous = DavHandle::new(recording().0, Actor::anonymous());
        assert!(anonymous.get("/dav/").request().headers.get("authorization").is_none());
        assert_eq!(anonymous.actor(), &Actor::Anonymous);
    }

    #[tokio::test]
    async fn api_requests_are_json_with_merge_patch_and_if_match() {
        let (transport, seen) = recording();
        let api = ApiHandle::new(transport, Actor::bearer("tok"));
        let target = ApiHandle::v1("/tenants/acme/principals/olivia");
        assert_eq!(target, "/api/v1/tenants/acme/principals/olivia");
        api.put_json(&target, &serde_json::json!({"kind": "user"}))
            .unwrap()
            .send()
            .await
            .unwrap();
        let request = last(&seen);
        assert_eq!(request.headers["content-type"], "application/json");
        assert_eq!(request.headers["accept"], "application/json");
        assert_eq!(request.headers["authorization"], "Bearer tok");
        assert_eq!(request.body, "{\"kind\":\"user\"}");
        api.patch_json(&target, &serde_json::json!({"display_name": null}))
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(last(&seen).headers["content-type"], "application/merge-patch+json");
        api.delete(&target, Some("\"v3\"")).send().await.unwrap();
        assert_eq!(last(&seen).headers["if-match"], "\"v3\"");
        assert!(api.delete(&target, None).request().headers.get("if-match").is_none());
        assert_eq!(api.post_json("/x", &1).unwrap().request().method.as_str(), "POST");
        assert_eq!(api.get("/x").request().method.as_str(), "GET");
        assert_eq!(api.actor(), &Actor::bearer("tok"));
    }

    #[tokio::test]
    async fn mcp_requests_are_json_rpc_with_increasing_ids_and_an_origin() {
        let (transport, seen) = recording();
        let mcp = McpHandle::new(transport, Actor::bearer("tok")).with_origin("https://assistant.example");
        mcp.call_tool("list_events", &serde_json::json!({"limit": 5}))
            .unwrap()
            .send()
            .await
            .unwrap();
        let request = last(&seen);
        assert_eq!(request.target, MCP_PATH);
        assert_eq!(request.headers["origin"], "https://assistant.example");
        assert_eq!(request.headers["accept"], "application/json, text/event-stream");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["name"], "list_events");
        assert_eq!(body["params"]["arguments"]["limit"], 5);
        let first = body["id"].as_u64().unwrap();
        mcp.list_tools().unwrap().send().await.unwrap();
        let second: serde_json::Value = serde_json::from_slice(&last(&seen).body).unwrap();
        assert_eq!(second["id"].as_u64().unwrap(), first + 1);
        assert_eq!(mcp.actor(), &Actor::bearer("tok"));
    }

    #[test]
    fn mcp_messages_are_read_from_json_bodies_and_event_streams() {
        let plain = TestResponse::new(200, r#"{"result": 1}"#).with_header("content-type", "application/json");
        assert_eq!(mcp_message(&plain).unwrap()["result"], 1);
        let stream = TestResponse::new(200, "event: message\ndata: {\"result\": 2}\n\n")
            .with_header("content-type", "text/event-stream");
        assert_eq!(mcp_message(&stream).unwrap()["result"], 2);
        let empty = TestResponse::new(200, "event: ping\n\n").with_header("content-type", "text/event-stream");
        assert!(mcp_message(&empty).is_err());
    }

    #[tokio::test]
    async fn feed_and_rsvp_requests_use_their_paths_without_credentials() {
        let (transport, seen) = recording();
        let feed = FeedHandle::new(Arc::clone(&transport), "dvh_feed_abc");
        assert_eq!(feed.target(), "/feeds/dvh_feed_abc.ics");
        feed.get_if_none_match("\"e\"").send().await.unwrap();
        let request = last(&seen);
        assert_eq!(request.headers["if-none-match"], "\"e\"");
        assert!(request.headers.get("authorization").is_none());

        let rsvp = RsvpHandle::new(transport);
        rsvp.view("dvh_rsvp_x").send().await.unwrap();
        assert_eq!(last(&seen).target, "/rsvp/dvh_rsvp_x");
        rsvp.answer(
            "dvh_rsvp_x",
            "https://cal.example",
            &[("partstat", "ACCEPTED"), ("comment", "a b&c")],
        )
        .send()
        .await
        .unwrap();
        let request = last(&seen);
        assert_eq!(request.method.as_str(), "POST");
        assert_eq!(request.headers["origin"], "https://cal.example");
        assert_eq!(request.body, "partstat=ACCEPTED&comment=a%20b%26c");
    }
}
