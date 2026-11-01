//! Shared helpers of the MCP protocol tests: the router under test over the fake application services, doubles that
//! record what the tools hand to the services and a JSON-RPC client that speaks the protocol by hand.
//!
//! The client is deliberately independent of the server's implementation: it knows the MCP specification (revision
//! `2025-06-18`, streamable HTTP, JSON-RPC 2.0) and builds every request as plain JSON, so a server that satisfies it
//! satisfies any other client of the specification.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use chrono::{DateTime, Utc};
use davhaven_app::AppServices;
use davhaven_app::error::{AppError, AppResult};
use davhaven_app::services::{
    AppClock, CalendarDataSpec, CalendarRef, CopyRequest, CsrfToken, DeleteEventOptions, DeleteOutcome, DeleteRequest,
    EventCreate, EventSearch, EventWrite, EventWriteOutcome, FindSlotsRequest, FindSlotsResult, FreeBusyRequest,
    FreeBusyResult, InboxEntry, InboxItemView, InvitationResponse, MoveOutcome, MoveRequest, MultigetEntry,
    ObjectFilter, ObjectHit, ObjectRef, ObjectSelector, ObjectService, ObjectView, PageRequest, PutOutcome, PutRequest,
    RenderedPage, RsvpAnswer, ScheduleResponse, SchedulingService, SyncResult,
};
use davhaven_app_fake::seed::{self, ANNA_TOKEN};
use davhaven_app_fake::{FakeApp, FakeWorld};
use davhaven_domain::{
    CalendarId, EventTime, PrincipalName, RequestContext, ResourcePath, Scope, ScopeSet, SyncToken, TenantSlug,
    TokenKind,
};
use davhaven_http::{Edge, SequentialRequestIds, Surface};
use davhaven_mcp::config::McpConfig;
use davhaven_wire::mcp::{ChangeScope, PROBLEM_META_KEY};
use davhaven_wire::{
    BatchRequest, BatchResult, ChangesResponse, Cursor, EventView, InboundItipRequest, InboundItipResponse, Page,
};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// The moment the server believes it is: tools that default to "now" start here.
pub(crate) const NOW: &str = "2027-03-01T08:00:00Z";

/// A token of `anna` with `mcp:read` only.
pub(crate) const READ_TOKEN: &str = "dvh_pat_readonly00_secret";

/// A token of `anna` with `mcp:write` only.
pub(crate) const WRITE_TOKEN: &str = "dvh_pat_writeonly0_secret";

/// A token of `anna` that has the event scopes of the management API but no MCP scope.
pub(crate) const EVENTS_ONLY_TOKEN: &str = "dvh_pat_eventsonly_secret";

/// A token of `ben` with every MCP scope, for tests of isolation between people.
pub(crate) const BEN_TOKEN: &str = "dvh_pat_fakeben0000_secret";

/// The time `NOW` as a value.
pub(crate) fn now() -> DateTime<Utc> {
    at(NOW)
}

/// A time from RFC 3339 text.
pub(crate) fn at(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text).unwrap().with_timezone(&Utc)
}

/// The standard fake world with the extra tokens of these tests.
fn world() -> FakeWorld {
    let mut world = seed::standard_world();
    let acme = TenantSlug::parse("acme").unwrap();
    let tenant = world.tenant_by_slug(&acme).unwrap().id;
    let anna = world
        .principal_id(&acme, &PrincipalName::parse("anna").unwrap())
        .unwrap();
    let ben = world
        .principal_id(&acme, &PrincipalName::parse("ben").unwrap())
        .unwrap();
    let principal = |world: &mut FakeWorld, who, scopes: &[Scope], secret: &str| {
        world.add_api_token(
            Some(tenant),
            TokenKind::Principal,
            Some(who),
            ScopeSet::of(scopes),
            secret,
        );
    };
    principal(&mut world, anna, &[Scope::McpRead], READ_TOKEN);
    principal(&mut world, anna, &[Scope::McpWrite], WRITE_TOKEN);
    principal(
        &mut world,
        anna,
        &[Scope::EventsRead, Scope::EventsWrite],
        EVENTS_ONLY_TOKEN,
    );
    principal(&mut world, ben, &[Scope::McpRead, Scope::McpWrite], BEN_TOKEN);
    world
}

/// What the tools handed to the object service.
#[derive(Default)]
pub(crate) struct SpyLog {
    /// `search_events` calls.
    pub(crate) searches: Vec<(EventSearch, PageRequest)>,
    /// `get_event` calls.
    pub(crate) reads: Vec<(CalendarRef, ObjectSelector, Option<EventTime>)>,
    /// `put_event` calls.
    pub(crate) writes: Vec<(CalendarRef, EventWrite)>,
    /// `delete_event` calls.
    pub(crate) deletes: Vec<(CalendarRef, ObjectSelector, DeleteEventOptions)>,
}

/// The object service of the tests: the fake, with a record of the calls the tools make and, on request, events it
/// answers with instead of the fake's own (to give the tools events with attendees and classes, which the fake
/// cannot store).
pub(crate) struct Spy {
    inner: Arc<dyn ObjectService>,
    log: Mutex<SpyLog>,
    scripted: Mutex<Option<Page<EventView>>>,
}

impl Spy {
    /// The calls so far.
    pub(crate) async fn log<R>(&self, read: impl FnOnce(&SpyLog) -> R) -> R {
        read(&*self.log.lock().await)
    }

    /// From now on `search_events` returns this page, and `get_event`, `put_event` and `respond` its first event.
    pub(crate) async fn script(&self, page: Page<EventView>) {
        *self.scripted.lock().await = Some(page);
    }

    async fn first_scripted(&self) -> Option<EventView> {
        self.scripted
            .lock()
            .await
            .as_ref()
            .and_then(|page| page.items.first().cloned())
    }
}

#[async_trait]
impl ObjectService for Spy {
    async fn get(&self, _ctx: &RequestContext, _path: &ResourcePath) -> AppResult<ObjectView> {
        Err(AppError::unsupported())
    }

    async fn put(&self, _ctx: &RequestContext, _request: PutRequest) -> AppResult<PutOutcome> {
        Err(AppError::unsupported())
    }

    async fn delete(&self, _ctx: &RequestContext, _request: DeleteRequest) -> AppResult<DeleteOutcome> {
        Err(AppError::unsupported())
    }

    async fn move_to(&self, _ctx: &RequestContext, _request: MoveRequest) -> AppResult<MoveOutcome> {
        Err(AppError::unsupported())
    }

    async fn copy_to(&self, _ctx: &RequestContext, _request: CopyRequest) -> AppResult<MoveOutcome> {
        Err(AppError::unsupported())
    }

    async fn multiget(
        &self,
        _ctx: &RequestContext,
        _collection: &ResourcePath,
        _paths: Vec<ResourcePath>,
        _data: CalendarDataSpec,
    ) -> AppResult<Vec<MultigetEntry>> {
        Err(AppError::unsupported())
    }

    async fn query(
        &self,
        _ctx: &RequestContext,
        _collection: &ResourcePath,
        _filter: ObjectFilter,
        _data: CalendarDataSpec,
    ) -> AppResult<Vec<ObjectHit>> {
        Err(AppError::unsupported())
    }

    async fn sync(
        &self,
        _ctx: &RequestContext,
        _collection: &ResourcePath,
        _since: Option<SyncToken>,
        _limit: Option<u32>,
    ) -> AppResult<SyncResult> {
        Err(AppError::unsupported())
    }

    async fn batch(
        &self,
        _ctx: &RequestContext,
        _calendar: &CalendarRef,
        _request: BatchRequest,
    ) -> AppResult<BatchResult> {
        Err(AppError::unsupported())
    }

    async fn get_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        instance: Option<EventTime>,
    ) -> AppResult<EventView> {
        self.log
            .lock()
            .await
            .reads
            .push((calendar.clone(), selector.clone(), instance.clone()));
        if let Some(view) = self.first_scripted().await {
            return Ok(view);
        }
        self.inner.get_event(ctx, calendar, selector, instance).await
    }

    async fn put_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        write: EventWrite,
    ) -> AppResult<EventWriteOutcome> {
        self.log.lock().await.writes.push((calendar.clone(), write.clone()));
        if let Some(event) = self.first_scripted().await {
            return Ok(EventWriteOutcome {
                event,
                created: true,
                schedule: davhaven_app::services::ScheduleOutcome::none(),
            });
        }
        self.inner.put_event(ctx, calendar, write).await
    }

    async fn create_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        create: EventCreate,
    ) -> AppResult<EventWriteOutcome> {
        // A creation is logged as the write it asks for, so the tests read what each tool handed the services.
        self.log.lock().await.writes.push((
            calendar.clone(),
            EventWrite {
                target: create.key.clone().map(ObjectSelector::Key),
                event: create.event.clone(),
                notify_attendees: create.notify_attendees,
                if_match: None,
                scope: ChangeScope::All,
            },
        ));
        if let Some(event) = self.first_scripted().await {
            return Ok(EventWriteOutcome {
                event,
                created: true,
                schedule: davhaven_app::services::ScheduleOutcome::none(),
            });
        }
        self.inner.create_event(ctx, calendar, create).await
    }

    async fn delete_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<()> {
        self.log
            .lock()
            .await
            .deletes
            .push((calendar.clone(), selector.clone(), options.clone()));
        self.inner.delete_event(ctx, calendar, selector, options).await
    }

    async fn delete_event_if_present(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<bool> {
        self.log
            .lock()
            .await
            .deletes
            .push((calendar.clone(), selector.clone(), options.clone()));
        self.inner
            .delete_event_if_present(ctx, calendar, selector, options)
            .await
    }

    async fn list(
        &self,
        _ctx: &RequestContext,
        _calendar: &CalendarRef,
        _filter: ObjectFilter,
        _page: PageRequest,
    ) -> AppResult<Page<EventView>> {
        Err(AppError::unsupported())
    }

    async fn search_events(
        &self,
        ctx: &RequestContext,
        search: EventSearch,
        page: PageRequest,
    ) -> AppResult<Page<EventView>> {
        self.log.lock().await.searches.push((search.clone(), page.clone()));
        if let Some(scripted) = self.scripted.lock().await.clone() {
            return Ok(scripted);
        }
        self.inner.search_events(ctx, search, page).await
    }

    async fn changes(
        &self,
        _ctx: &RequestContext,
        _calendar: &CalendarRef,
        _since: Option<SyncToken>,
        _limit: Option<u32>,
    ) -> AppResult<ChangesResponse> {
        Err(AppError::unsupported())
    }
}

/// What the tools handed to the scheduling service.
#[derive(Default)]
pub(crate) struct SchedulingLog {
    /// `free_busy` requests.
    pub(crate) free_busy: Vec<FreeBusyRequest>,
    /// `find_free_slots` requests.
    pub(crate) slots: Vec<FindSlotsRequest>,
    /// `respond` calls.
    pub(crate) responses: Vec<(ObjectRef, InvitationResponse)>,
}

/// The scheduling service of the tests: it answers what a test scripts and records what it was asked.
#[derive(Default)]
pub(crate) struct Scripted {
    log: Mutex<SchedulingLog>,
    free_busy: Mutex<Option<FreeBusyResult>>,
    slots: Mutex<Option<FindSlotsResult>>,
    respond: Mutex<Option<EventView>>,
}

impl Scripted {
    /// The calls so far.
    pub(crate) async fn log<R>(&self, read: impl FnOnce(&SchedulingLog) -> R) -> R {
        read(&*self.log.lock().await)
    }

    /// The answer of `free_busy`.
    pub(crate) async fn answer_free_busy(&self, result: FreeBusyResult) {
        *self.free_busy.lock().await = Some(result);
    }

    /// The answer of `find_free_slots`.
    pub(crate) async fn answer_slots(&self, result: FindSlotsResult) {
        *self.slots.lock().await = Some(result);
    }

    /// The answer of `respond`.
    pub(crate) async fn answer_respond(&self, view: EventView) {
        *self.respond.lock().await = Some(view);
    }
}

#[async_trait]
impl SchedulingService for Scripted {
    async fn free_busy(&self, _ctx: &RequestContext, request: FreeBusyRequest) -> AppResult<FreeBusyResult> {
        self.log.lock().await.free_busy.push(request);
        self.free_busy.lock().await.clone().ok_or_else(AppError::unsupported)
    }

    async fn find_free_slots(&self, _ctx: &RequestContext, request: FindSlotsRequest) -> AppResult<FindSlotsResult> {
        self.log.lock().await.slots.push(request);
        self.slots.lock().await.clone().ok_or_else(AppError::unsupported)
    }

    async fn outbox_post(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _body: String,
    ) -> AppResult<ScheduleResponse> {
        Err(AppError::unsupported())
    }

    async fn inbox_list(&self, _ctx: &RequestContext, _principal: &PrincipalName) -> AppResult<Vec<InboxItemView>> {
        Err(AppError::unsupported())
    }

    async fn inbox_get(&self, _ctx: &RequestContext, _path: &ResourcePath) -> AppResult<InboxItemView> {
        Err(AppError::unsupported())
    }

    async fn inbox_get_many(
        &self,
        _ctx: &RequestContext,
        _inbox: &ResourcePath,
        _paths: Vec<ResourcePath>,
        _spec: &CalendarDataSpec,
    ) -> AppResult<Vec<InboxEntry>> {
        Err(AppError::unsupported())
    }

    async fn inbox_delete(&self, _ctx: &RequestContext, _path: &ResourcePath) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn respond(
        &self,
        _ctx: &RequestContext,
        object: ObjectRef,
        response: InvitationResponse,
    ) -> AppResult<EventView> {
        self.log.lock().await.responses.push((object, response));
        self.respond.lock().await.clone().ok_or_else(AppError::unsupported)
    }

    async fn inbound_itip(
        &self,
        _ctx: &RequestContext,
        _request: InboundItipRequest,
    ) -> AppResult<InboundItipResponse> {
        Err(AppError::unsupported())
    }

    async fn rsvp_page(&self, _ctx: &RequestContext) -> AppResult<RenderedPage> {
        Err(AppError::unsupported())
    }

    async fn rsvp_answer(
        &self,
        _ctx: &RequestContext,
        _answer: RsvpAnswer,
        _csrf: CsrfToken,
    ) -> AppResult<RenderedPage> {
        Err(AppError::unsupported())
    }
}

/// The server under test: the router, the doubles and the ids of the standard world.
pub(crate) struct Setup {
    /// The MCP router.
    pub(crate) app: Router,
    /// The object service of the tools.
    pub(crate) spy: Arc<Spy>,
    /// The scheduling service of the tools.
    pub(crate) scheduling: Arc<Scripted>,
}

impl Setup {
    /// The standard world with the default configuration and `NOW` as the time.
    pub(crate) fn standard() -> Self {
        Self::with_config(&McpConfig {
            allowed_origins: vec!["https://assistant.example.org".to_owned()],
            ..McpConfig::default()
        })
    }

    /// The standard world with this configuration.
    pub(crate) fn with_config(config: &McpConfig) -> Self {
        let mut services: AppServices = FakeApp::new(world()).services;
        // The moment the server believes it is: `search_events` starts here when the call names no start.
        services.clock = AppClock::fixed(now());
        let spy = Arc::new(Spy {
            inner: Arc::clone(&services.objects),
            log: Mutex::new(SpyLog::default()),
            scripted: Mutex::new(None),
        });
        let scheduling = Arc::new(Scripted::default());
        services.objects = Arc::<Spy>::clone(&spy);
        services.scheduling = Arc::<Scripted>::clone(&scheduling);
        let edge = Edge::new(Surface::Mcp, Arc::new(SequentialRequestIds::new()));
        let app = davhaven_mcp::router(&services, config, &edge);
        Self { app, spy, scheduling }
    }

    /// A client of the standard token of `anna` (every MCP scope but not the external one).
    pub(crate) fn anna(&self) -> Client {
        self.client(ANNA_TOKEN)
    }

    /// A client of this token.
    pub(crate) fn client(&self, token: &str) -> Client {
        Client::new(self.app.clone(), token)
    }
}

/// An answer of the server: status, headers and body.
pub(crate) struct Reply {
    /// The HTTP status.
    pub(crate) status: StatusCode,
    /// The response headers.
    pub(crate) headers: HeaderMap,
    /// The body.
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// The value of a header, empty when absent.
    pub(crate) fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    /// The body as JSON; `null` when it is none.
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The `code` of a problem document body.
    pub(crate) fn problem(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }
}

/// A JSON-RPC client over the router, as one token.
pub(crate) struct Client {
    app: Router,
    token: Option<String>,
    next_id: AtomicU64,
}

impl Client {
    /// A client that presents `token` as a bearer token.
    pub(crate) fn new(app: Router, token: &str) -> Self {
        Self {
            app,
            token: Some(token.to_owned()),
            next_id: AtomicU64::new(1),
        }
    }

    /// A client that presents no credentials at all.
    pub(crate) fn anonymous(app: Router) -> Self {
        Self {
            app,
            token: None,
            next_id: AtomicU64::new(1),
        }
    }

    /// One HTTP request with exactly the given headers and body, besides the bearer token.
    pub(crate) async fn raw(&self, method: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Reply {
        self.request("/mcp", method, headers, body).await
    }

    /// [`Client::raw`] to another path.
    pub(crate) async fn request(&self, path: &str, method: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Reply {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = &self.token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes().to_vec(),
        }
    }

    /// A POST the way a client of the specification sends a message.
    pub(crate) async fn post(&self, message: &Value) -> Reply {
        self.raw(
            "POST",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("mcp-protocol-version", "2025-06-18"),
            ],
            serde_json::to_vec(message).unwrap(),
        )
        .await
    }

    /// A JSON-RPC request; the whole response object (`result` or `error`).
    pub(crate) async fn rpc(&self, method: &str, params: Value) -> Value {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let reply = self
            .post(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{method}: {}",
            String::from_utf8_lossy(&reply.body)
        );
        let response = reply.json();
        assert_eq!(response["jsonrpc"], "2.0", "{response}");
        assert_eq!(response["id"], id, "the id of the request comes back: {response}");
        response
    }

    /// `tools/call`: the `result` of the response (which may be a failed tool result).
    pub(crate) async fn call(&self, tool: &str, arguments: Value) -> Value {
        let response = self
            .rpc("tools/call", json!({"name": tool, "arguments": arguments}))
            .await;
        assert!(
            response.get("error").is_none(),
            "{tool} failed as a protocol error: {response}"
        );
        response["result"].clone()
    }

    /// `tools/call` of a call that must succeed: its `structuredContent`.
    pub(crate) async fn ok(&self, tool: &str, arguments: Value) -> Value {
        let result = self.call(tool, arguments).await;
        assert_eq!(result["isError"], false, "{tool}: {result}");
        let structured = result["structuredContent"].clone();
        assert_eq!(
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            structured,
            "the text of the result is the structured content"
        );
        structured
    }

    /// `tools/call` of a call that must fail as a tool result: the problem document, which is in `_meta` (a failure has
    /// no `structuredContent`).
    pub(crate) async fn fails(&self, tool: &str, arguments: Value) -> Value {
        let result = self.call(tool, arguments).await;
        assert_eq!(result["isError"], true, "{tool}: {result}");
        assert!(result.get("structuredContent").is_none(), "{result}");
        let problem = result["_meta"][PROBLEM_META_KEY].clone();
        assert!(problem["code"].is_string(), "{result}");
        problem
    }
}

/// The id of the calendar named `name` in the home of the client, found with `list_calendars`.
pub(crate) async fn calendar_named(client: &Client, name: &str) -> CalendarId {
    let listing = client.ok("list_calendars", json!({})).await;
    let calendar = listing["calendars"]
        .as_array()
        .unwrap()
        .iter()
        .find(|calendar| calendar["untrusted_text"]["display_name"] == name)
        .unwrap_or_else(|| panic!("no calendar named {name}: {listing}"));
    CalendarId::parse(calendar["calendar_id"].as_str().unwrap()).unwrap()
}

/// A cursor from text.
pub(crate) fn cursor(text: &str) -> Cursor {
    Cursor::parse(text).unwrap()
}
