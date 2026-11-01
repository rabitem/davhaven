//! The world of the outbox tests: an application core on the in-memory store with a deterministic clock, ids,
//! key ring and sealer, and a scripted double for each of the ports the tests do not exercise.
//!
//! The store is the real `store-memory` adapter, wrapped by [`FlakyDatabase`], which can refuse to begin
//! transactions (an outage) and make the settling of outbox records fail. Everything else about the store, the
//! claim and its lease, the settling rules, tenant isolation, is the adapter's own.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, PoisonError};

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use davhaven_testkit::davhaven_app::{AppConfig, AppCore, AppDeps};
use davhaven_testkit::davhaven_domain::events::{CalendarPayload, PrincipalPayload, WebhookPayload};
use davhaven_testkit::davhaven_domain::{
    Actor, AuditActor, Calendar, CalendarId, CalendarKind, CalendarSlug, CalendarUserAddress, Channel, Classification,
    ComponentKind, ContentHash, DeliveryId, DomainName, ETag, Email, Envelope, EventData, EventPayload, EventType,
    Limits, Locale, ObjectId, ObjectIndex, ObjectUri, OutboxId, OutgoingMail, PartStat, Principal, PrincipalId,
    PrincipalKind, PrincipalName, PrincipalStatus, PublicUrls, RequestContext, RequestId, Scope, ScopeSet,
    StoredObject, Tenant, TenantId, TenantSettings, TenantSlug, TenantStatus, TimeZoneName, TokenId, Transparency, Uid,
    WebhookId, WebhookSubscription,
};
use davhaven_testkit::davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
use davhaven_testkit::davhaven_ports::{
    AuthHint, AuthOutcome, Authenticator, Clock, Database, DeliveryRecord, Expected, FreeBusy, HandlerError, Health,
    HttpClient, IdGenerator, Invite, MailTransport, NewOutbox, NewVersion, OutboundRequest, OutboundResponse,
    OutboxClaim, OutboxFailure, OutboxKey, OutboxMessage, OutboxQueue, OutboxRecord, OutboxStats, PageReq,
    PolicyTenant, PortError, PresentedCredential, PrincipalAddress, RateDecision, RateKey, RateLimiter, RenderRequest,
    Rendered, Reserved, ResourceRequest, SchedulingPolicy, SendReceipt, StoreError, SystemTx, TemplateName,
    TemplateRenderer, Tx, TxMode, WebhookDelivery,
};
use davhaven_testkit::davhaven_store_memory::database::MemoryDatabase;
use davhaven_testkit::http::{HeaderMap, StatusCode};
use tokio::sync::Barrier;
use url::Url;
use uuid::Uuid;

/// The doubles lock for an instant and never across an await.
#[expect(clippy::disallowed_types, reason = "test doubles with synchronous accessors")]
pub(crate) type Mutex<T> = std::sync::Mutex<T>;

/// Locks a double's state, whatever happened to the thread that held it last.
pub(crate) fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------------------------
// The store, with faults
// ---------------------------------------------------------------------------------------------------------------

/// What can go wrong with the store, switched by the test.
#[derive(Default)]
struct Switches {
    /// While set, every `begin` fails with `Unavailable`.
    outage: AtomicBool,
    /// While set, `begin` fails for transactions of this tenant (system transactions and other tenants work).
    tenant_outage: Mutex<Option<TenantId>>,
    /// The next settlement (`complete`, `fail`, `defer`) fails with this error.
    settle_failure: Mutex<Option<StoreError>>,
    /// How many of the next `begin` calls fail (a store that flaps).
    failing_begins: AtomicU32,
}

/// The in-memory store with switches for an outage and for a failing settlement.
pub(crate) struct FlakyDatabase {
    inner: MemoryDatabase,
    switches: Arc<Switches>,
}

impl FlakyDatabase {
    fn new(inner: MemoryDatabase) -> Arc<Self> {
        Arc::new(Self {
            inner,
            switches: Arc::new(Switches::default()),
        })
    }

    /// The store itself, without the switches: for setting up and inspecting data.
    pub(crate) fn store(&self) -> &MemoryDatabase {
        &self.inner
    }

    /// While set, every `begin` fails with `Unavailable`.
    pub(crate) fn set_outage(&self, on: bool) {
        self.switches.outage.store(on, Ordering::SeqCst);
    }

    /// While set, `begin` fails with `Unavailable` for transactions of `tenant` only.
    pub(crate) fn set_tenant_outage(&self, tenant: Option<TenantId>) {
        *locked(&self.switches.tenant_outage) = tenant;
    }

    /// The next `complete`, `fail` or `defer` of the outbox queue fails with `error`.
    pub(crate) fn fail_next_settlement(&self, error: StoreError) {
        *locked(&self.switches.settle_failure) = Some(error);
    }

    /// The next `count` calls to `begin` or `begin_system` fail with `Unavailable`.
    pub(crate) fn fail_next_begins(&self, count: u32) {
        self.switches.failing_begins.store(count, Ordering::SeqCst);
    }

    fn refuse(&self, tenant: Option<TenantId>) -> Result<(), StoreError> {
        if self.switches.outage.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        let flapping = self
            .switches
            .failing_begins
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1));
        if flapping.is_ok() {
            return Err(StoreError::Unavailable);
        }
        match (tenant, *locked(&self.switches.tenant_outage)) {
            (Some(tenant), Some(blocked)) if tenant == blocked => Err(StoreError::Unavailable),
            _ => Ok(()),
        }
    }
}

#[async_trait]
impl Database for FlakyDatabase {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        self.refuse(Some(tenant))?;
        self.inner.begin(tenant, mode).await
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        self.refuse(None)?;
        let inner = self.inner.begin_system().await?;
        Ok(Box::new(FlakySystemTx {
            inner,
            switches: Arc::clone(&self.switches),
        }))
    }

    async fn health(&self) -> Health {
        Database::health(&self.inner).await
    }
}

/// A system transaction whose outbox queue can fail to settle.
struct FlakySystemTx {
    inner: Box<dyn SystemTx>,
    switches: Arc<Switches>,
}

#[async_trait]
impl SystemTx for FlakySystemTx {
    fn tenants(&mut self) -> &mut dyn davhaven_testkit::davhaven_ports::SystemTenantRepo {
        self.inner.tenants()
    }

    fn credential_lookup(&mut self) -> &mut dyn davhaven_testkit::davhaven_ports::CredentialLookup {
        self.inner.credential_lookup()
    }

    fn outbox_claim(&mut self) -> &mut dyn OutboxQueue {
        self
    }

    fn retention(&mut self) -> &mut dyn davhaven_testkit::davhaven_ports::RetentionRepo {
        self.inner.retention()
    }

    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        self.inner.commit().await
    }
}

impl FlakySystemTx {
    fn settlement_failure(&self) -> Option<StoreError> {
        locked(&self.switches.settle_failure).take()
    }
}

#[async_trait]
impl OutboxQueue for FlakySystemTx {
    async fn claim(&mut self, limit: u32, lease: std::time::Duration) -> Result<Vec<OutboxRecord>, StoreError> {
        self.inner.outbox_claim().claim(limit, lease).await
    }

    async fn complete(&mut self, key: OutboxKey) -> Result<(), StoreError> {
        if let Some(error) = self.settlement_failure() {
            return Err(error);
        }
        self.inner.outbox_claim().complete(key).await
    }

    async fn fail(&mut self, key: OutboxKey, failure: OutboxFailure) -> Result<(), StoreError> {
        if let Some(error) = self.settlement_failure() {
            return Err(error);
        }
        self.inner.outbox_claim().fail(key, failure).await
    }

    async fn complete_claimed(&mut self, claim: OutboxClaim) -> Result<(), StoreError> {
        if let Some(error) = self.settlement_failure() {
            return Err(error);
        }
        self.inner.outbox_claim().complete_claimed(claim).await
    }

    async fn fail_claimed(&mut self, claim: OutboxClaim, failure: OutboxFailure) -> Result<(), StoreError> {
        if let Some(error) = self.settlement_failure() {
            return Err(error);
        }
        self.inner.outbox_claim().fail_claimed(claim, failure).await
    }

    async fn defer_claimed(&mut self, claim: OutboxClaim, until: DateTime<Utc>, note: &str) -> Result<(), StoreError> {
        if let Some(error) = self.settlement_failure() {
            return Err(error);
        }
        self.inner.outbox_claim().defer_claimed(claim, until, note).await
    }

    async fn release_leases(&mut self, held: &[OutboxKey]) -> Result<u64, StoreError> {
        self.inner.outbox_claim().release_leases(held).await
    }

    async fn release_claimed(&mut self, held: &[OutboxClaim]) -> Result<u64, StoreError> {
        self.inner.outbox_claim().release_claimed(held).await
    }

    async fn stats(&mut self) -> Result<OutboxStats, StoreError> {
        self.inner.outbox_claim().stats().await
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Handlers, sinks, transports and the other single-port doubles
// ---------------------------------------------------------------------------------------------------------------

/// An outbox handler whose behavior the test scripts.
pub(crate) struct Scripted {
    kind: &'static str,
    limits_attempts: bool,
    behavior: Behavior,
    results: Mutex<VecDeque<Result<(), HandlerError>>>,
    calls: AtomicU32,
}

enum Behavior {
    /// Answers with the queued results, then `Ok`.
    Results,
    /// Never finishes.
    Hang,
    /// Panics.
    Panic,
    /// Waits for the other handlers at the barrier.
    Barrier(Arc<Barrier>),
    /// Finishes after the given time.
    Sleep(std::time::Duration),
    /// Runs the action, then answers like [`Behavior::Results`].
    Action(Action),
}

/// Something a handler does while it is working.
pub(crate) type Action = Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

impl Scripted {
    pub(crate) fn new(kind: &'static str) -> Arc<Self> {
        Self::build(kind, Behavior::Results, true)
    }

    pub(crate) fn hanging(kind: &'static str) -> Arc<Self> {
        Self::build(kind, Behavior::Hang, true)
    }

    pub(crate) fn panicking(kind: &'static str) -> Arc<Self> {
        Self::build(kind, Behavior::Panic, true)
    }

    pub(crate) fn meeting(kind: &'static str, barrier: Arc<Barrier>) -> Arc<Self> {
        Self::build(kind, Behavior::Barrier(barrier), true)
    }

    pub(crate) fn sleeping(kind: &'static str, time: std::time::Duration) -> Arc<Self> {
        Self::build(kind, Behavior::Sleep(time), true)
    }

    /// A handler that runs `action` first and then answers from its script: the way a test makes things happen
    /// while the handler is working (another dispatcher settles the record, the clock moves).
    pub(crate) fn acting(kind: &'static str, action: Action) -> Arc<Self> {
        Self::build(kind, Behavior::Action(action), true)
    }

    /// A handler that bounds its retries by time itself (`limits_attempts` is false).
    pub(crate) fn unlimited(kind: &'static str) -> Arc<Self> {
        Self::build(kind, Behavior::Results, false)
    }

    fn build(kind: &'static str, behavior: Behavior, limits_attempts: bool) -> Arc<Self> {
        Arc::new(Self {
            kind,
            limits_attempts,
            behavior,
            results: Mutex::new(VecDeque::new()),
            calls: AtomicU32::new(0),
        })
    }

    /// The handler as the dispatcher takes it.
    pub(crate) fn as_handler(self: &Arc<Self>) -> Arc<dyn davhaven_testkit::davhaven_ports::OutboxHandler> {
        let handler: Arc<Self> = Arc::clone(self);
        handler
    }

    /// Queues the answer of one call.
    pub(crate) fn then(self: &Arc<Self>, result: Result<(), HandlerError>) -> Arc<Self> {
        locked(&self.results).push_back(result);
        Arc::clone(self)
    }

    /// How often the handler was called.
    pub(crate) fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl davhaven_testkit::davhaven_ports::OutboxHandler for Scripted {
    fn kind(&self) -> &'static str {
        self.kind
    }

    async fn handle(&self, _record: &OutboxRecord) -> Result<(), HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.behavior {
            Behavior::Results => locked(&self.results).pop_front().unwrap_or(Ok(())),
            Behavior::Hang => std::future::pending().await,
            Behavior::Panic => std::panic::panic_any("scripted panic"),
            Behavior::Barrier(barrier) => {
                barrier.wait().await;
                Ok(())
            }
            Behavior::Sleep(time) => {
                tokio::time::sleep(*time).await;
                Ok(())
            }
            Behavior::Action(action) => {
                action().await;
                locked(&self.results).pop_front().unwrap_or(Ok(()))
            }
        }
    }

    fn limits_attempts(&self) -> bool {
        self.limits_attempts
    }
}

/// A mail transport that records what it is given and fails (or hangs) on demand.
#[derive(Default)]
pub(crate) struct ScriptedMail {
    sent: Mutex<Vec<OutgoingMail>>,
    failures: Mutex<VecDeque<PortError>>,
    hang: AtomicBool,
}

impl ScriptedMail {
    /// The next `send` never finishes (a relay that accepted the connection and then went silent).
    pub(crate) fn hang_next(&self) {
        self.hang.store(true, Ordering::SeqCst);
    }

    /// The next `send` fails with `error`.
    pub(crate) fn fail_next(&self, error: PortError) {
        locked(&self.failures).push_back(error);
    }

    /// Everything accepted so far.
    pub(crate) fn sent(&self) -> Vec<OutgoingMail> {
        locked(&self.sent).clone()
    }
}

#[async_trait]
impl MailTransport for ScriptedMail {
    async fn send(&self, mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        if self.hang.swap(false, Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let failure = locked(&self.failures).pop_front();
        if let Some(error) = failure {
            return Err(error);
        }
        locked(&self.sent).push(mail.clone());
        Ok(SendReceipt {
            message_id: mail.message_id.clone(),
            transport_id: None,
        })
    }
}

/// A template renderer that prints the template, the locale, the theme and the model.
#[derive(Default)]
pub(crate) struct StubTemplates {
    requests: Mutex<Vec<RenderRequest>>,
    failure: Mutex<Option<PortError>>,
}

impl StubTemplates {
    /// Every following render fails with `error`.
    pub(crate) fn fail_with(&self, error: PortError) {
        *locked(&self.failure) = Some(error);
    }

    /// The requests so far.
    pub(crate) fn requests(&self) -> Vec<RenderRequest> {
        locked(&self.requests).clone()
    }
}

#[async_trait]
impl TemplateRenderer for StubTemplates {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError> {
        let failure = locked(&self.failure).clone();
        if let Some(error) = failure {
            return Err(error);
        }
        let model = serde_json::to_string(&request.model).unwrap_or_default();
        let rendered = Rendered {
            subject: format!("{} ({}, {})", request.template, request.locale, request.theme),
            html: format!("<p>{model}</p>"),
            text: model,
        };
        locked(&self.requests).push(request);
        Ok(rendered)
    }

    fn catalog(&self) -> Vec<TemplateName> {
        Vec::new()
    }
}

/// An HTTP client that answers from a script (200 when the script is empty), remembers the requests, and
/// refuses or cannot resolve the hosts it is told to when a URL is validated.
#[derive(Default)]
pub(crate) struct ScriptedHttp {
    answers: Mutex<VecDeque<Result<OutboundResponse, PortError>>>,
    requests: Mutex<Vec<OutboundRequest>>,
    refused_hosts: Mutex<Vec<String>>,
    unresolvable_hosts: Mutex<Vec<String>>,
}

impl ScriptedHttp {
    /// The next request is answered with `status`.
    pub(crate) fn answer(&self, status: u16) {
        self.answer_with_body(status, bytes::Bytes::new());
    }

    /// The next request is answered with `status` and `body`.
    pub(crate) fn answer_with_body(&self, status: u16, body: bytes::Bytes) {
        locked(&self.answers).push_back(Ok(OutboundResponse {
            status: StatusCode::from_u16(status).unwrap(),
            headers: HeaderMap::new(),
            body,
        }));
    }

    /// The next request fails with `error`.
    pub(crate) fn fail(&self, error: PortError) {
        locked(&self.answers).push_back(Err(error));
    }

    /// The requests sent so far.
    pub(crate) fn requests(&self) -> Vec<OutboundRequest> {
        locked(&self.requests).clone()
    }

    /// `validate_url` refuses URLs of `host` from now on.
    pub(crate) fn refuse(&self, host: &str) {
        locked(&self.refused_hosts).push(host.to_owned());
    }

    /// `validate_url` cannot resolve `host` from now on (a failed lookup, which is not a refusal of the policy).
    pub(crate) fn unresolvable(&self, host: &str) {
        locked(&self.unresolvable_hosts).push(host.to_owned());
    }
}

#[async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        locked(&self.requests).push(request);
        let scripted = locked(&self.answers).pop_front();
        scripted.unwrap_or_else(|| {
            Ok(OutboundResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: bytes::Bytes::new(),
            })
        })
    }

    async fn validate_url(&self, url: &Url) -> Result<(), PortError> {
        let host = url.host_str().unwrap_or_default();
        if locked(&self.unresolvable_hosts).iter().any(|name| name == host) {
            return Err(PortError::unavailable("the host name could not be resolved"));
        }
        if url.scheme() != "https" || locked(&self.refused_hosts).iter().any(|name| name == host) {
            return Err(PortError::rejected("the egress policy refuses this URL"));
        }
        Ok(())
    }
}

/// A rate limiter that allows everything until the test scripts a denial for a bucket, and remembers the keys.
#[derive(Default)]
pub(crate) struct ScriptedLimiter {
    denials: Mutex<VecDeque<std::time::Duration>>,
    checks: Mutex<Vec<(RateKey, u32)>>,
    broken: AtomicBool,
}

impl ScriptedLimiter {
    /// The next check is denied with `retry_after`.
    pub(crate) fn deny_next(&self, retry_after: std::time::Duration) {
        locked(&self.denials).push_back(retry_after);
    }

    /// Every check fails like a shared limiter whose backend is down.
    pub(crate) fn break_down(&self) {
        self.broken.store(true, Ordering::SeqCst);
    }

    /// The checks so far: the key and the cost.
    pub(crate) fn checks(&self) -> Vec<(RateKey, u32)> {
        locked(&self.checks).clone()
    }
}

#[async_trait]
impl RateLimiter for ScriptedLimiter {
    async fn check(&self, key: &RateKey, cost: u32) -> Result<RateDecision, PortError> {
        locked(&self.checks).push((key.clone(), cost));
        if self.broken.load(Ordering::SeqCst) {
            return Err(PortError::unavailable("the limiter is down"));
        }
        Ok(match locked(&self.denials).pop_front() {
            Some(retry_after) => RateDecision::deny(retry_after),
            None => RateDecision::allow(u32::MAX),
        })
    }
}

struct NeverAuto;

#[async_trait]
impl SchedulingPolicy for NeverAuto {
    async fn auto_add(&self, _invite: &Invite) -> bool {
        false
    }

    async fn resource_reply(&self, _request: &ResourceRequest, _free_busy: &FreeBusy) -> Option<PartStat> {
        None
    }

    async fn external_allowed(&self, _tenant: &PolicyTenant, _address: &CalendarUserAddress) -> bool {
        false
    }
}

struct NoAuthenticator;

#[async_trait]
impl Authenticator for NoAuthenticator {
    async fn authenticate(
        &self,
        _credential: &PresentedCredential,
        _hint: &AuthHint,
    ) -> Result<AuthOutcome, PortError> {
        Ok(AuthOutcome::NotApplicable)
    }
}

/// An event sink that records what it is given and fails on demand.
pub(crate) struct CapturingSink {
    name: &'static str,
    delivered: Mutex<Vec<davhaven_testkit::davhaven_domain::EventId>>,
    failures: Mutex<VecDeque<HandlerError>>,
}

impl CapturingSink {
    pub(crate) fn new(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            delivered: Mutex::new(Vec::new()),
            failures: Mutex::new(VecDeque::new()),
        })
    }

    /// The sink as the application takes it.
    pub(crate) fn as_sink(self: &Arc<Self>) -> Arc<dyn davhaven_testkit::davhaven_ports::EventSink> {
        let sink: Arc<Self> = Arc::clone(self);
        sink
    }

    /// The next delivery fails with `error`.
    pub(crate) fn fail_next(&self, error: HandlerError) {
        locked(&self.failures).push_back(error);
    }

    /// The ids of the events accepted so far.
    pub(crate) fn delivered(&self) -> Vec<davhaven_testkit::davhaven_domain::EventId> {
        locked(&self.delivered).clone()
    }
}

#[async_trait]
impl davhaven_testkit::davhaven_ports::EventSink for CapturingSink {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn deliver(&self, envelope: &Envelope) -> Result<(), HandlerError> {
        let failure = locked(&self.failures).pop_front();
        if let Some(error) = failure {
            return Err(error);
        }
        locked(&self.delivered).push(envelope.id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The calendar backend
// ---------------------------------------------------------------------------------------------------------------

/// A calendar backend that answers with a fixed event and a minimal iTIP text, and remembers its requests.
pub(crate) struct FakeBackend {
    event: Mutex<EventData>,
    failure: Mutex<Option<davhaven_testkit::davhaven_app::imip::BackendError>>,
    requests: Mutex<Vec<(String, davhaven_testkit::davhaven_app::imip::MessageRequest)>>,
}

impl FakeBackend {
    pub(crate) fn new(event: EventData) -> Arc<Self> {
        Arc::new(Self {
            event: Mutex::new(event),
            failure: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
        })
    }

    /// The backend as the handlers take it.
    pub(crate) fn as_backend(self: &Arc<Self>) -> Arc<dyn davhaven_testkit::davhaven_app::imip::CalendarBackend> {
        let backend: Arc<Self> = Arc::clone(self);
        backend
    }

    /// The event the backend describes from now on.
    pub(crate) fn set_event(&self, event: EventData) {
        *locked(&self.event) = event;
    }

    /// Every following call fails with `error`; `None` makes the backend work again.
    pub(crate) fn fail_with(&self, error: Option<davhaven_testkit::davhaven_app::imip::BackendError>) {
        *locked(&self.failure) = error;
    }

    /// The sources and requests it was given.
    pub(crate) fn requests(&self) -> Vec<(String, davhaven_testkit::davhaven_app::imip::MessageRequest)> {
        locked(&self.requests).clone()
    }
}

#[async_trait]
impl davhaven_testkit::davhaven_app::imip::CalendarBackend for FakeBackend {
    async fn describe(&self, source: &str) -> Result<EventData, davhaven_testkit::davhaven_app::imip::BackendError> {
        if let Some(error) = locked(&self.failure).clone() {
            return Err(error);
        }
        // An object whose text is `SUMMARY:{text}` is described by that text; any other source by the fixed event.
        Ok(match source.strip_prefix("SUMMARY:") {
            Some(summary) => EventData {
                summary: Some(summary.trim().to_owned()),
                ..EventData::default()
            },
            None => locked(&self.event).clone(),
        })
    }

    async fn prepare(
        &self,
        source: &str,
        request: &davhaven_testkit::davhaven_app::imip::MessageRequest,
    ) -> Result<davhaven_testkit::davhaven_app::imip::Prepared, davhaven_testkit::davhaven_app::imip::BackendError>
    {
        locked(&self.requests).push((source.to_owned(), request.clone()));
        if let Some(error) = locked(&self.failure).clone() {
            return Err(error);
        }
        Ok(davhaven_testkit::davhaven_app::imip::Prepared {
            event: locked(&self.event).clone(),
            ics: format!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:{}\r\nEND:VCALENDAR\r\n",
                request.method
            ),
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------------------------------------------

/// A metrics recorder for tests: counters add up, gauges keep the last value and histograms count their samples,
/// all under the series name `name{label=value,...}` (labels sorted).
#[derive(Default, Clone)]
pub(crate) struct MetricsCapture {
    values: Arc<Mutex<std::collections::BTreeMap<String, f64>>>,
}

struct Series {
    name: String,
    values: Arc<Mutex<std::collections::BTreeMap<String, f64>>>,
}

impl Series {
    fn update(&self, change: impl FnOnce(&mut f64)) {
        let mut values = locked(&self.values);
        change(values.entry(self.name.clone()).or_insert(0.0));
    }
}

impl metrics::CounterFn for Series {
    fn increment(&self, value: u64) {
        self.update(|slot| *slot += f64::from(u32::try_from(value).unwrap_or(u32::MAX)));
    }

    fn absolute(&self, value: u64) {
        self.update(|slot| *slot = f64::from(u32::try_from(value).unwrap_or(u32::MAX)));
    }
}

impl metrics::GaugeFn for Series {
    fn increment(&self, value: f64) {
        self.update(|slot| *slot += value);
    }

    fn decrement(&self, value: f64) {
        self.update(|slot| *slot -= value);
    }

    fn set(&self, value: f64) {
        self.update(|slot| *slot = value);
    }
}

impl metrics::HistogramFn for Series {
    fn record(&self, _value: f64) {
        self.update(|slot| *slot += 1.0);
    }
}

impl MetricsCapture {
    fn series(&self, key: &metrics::Key) -> Arc<Series> {
        let mut labels: Vec<String> = key
            .labels()
            .map(|label| format!("{}={}", label.key(), label.value()))
            .collect();
        labels.sort();
        let name = if labels.is_empty() {
            key.name().to_owned()
        } else {
            format!("{}{{{}}}", key.name(), labels.join(","))
        };
        Arc::new(Series {
            name,
            values: Arc::clone(&self.values),
        })
    }

    /// The value of a series, if anything was recorded.
    pub(crate) fn get(&self, series: &str) -> Option<f64> {
        locked(&self.values).get(series).copied()
    }

    /// Every series and value, for assertion messages.
    pub(crate) fn all(&self) -> std::collections::BTreeMap<String, f64> {
        locked(&self.values).clone()
    }
}

impl metrics::Recorder for MetricsCapture {
    fn describe_counter(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn describe_gauge(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn describe_histogram(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn register_counter(&self, key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Counter {
        metrics::Counter::from_arc(self.series(key))
    }

    fn register_gauge(&self, key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::from_arc(self.series(key))
    }

    fn register_histogram(&self, key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Histogram {
        metrics::Histogram::from_arc(self.series(key))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------------------------------------------

/// The tenant of the world's requests.
pub(crate) const TENANT: u128 = 0x7e_0001;

/// The sender domain of the world's tenant.
pub(crate) const SENDER_DOMAIN: &str = "mail.example.org";

/// The application core on the in-memory store and the doubles, with handles to the pieces the tests drive.
pub(crate) struct World {
    pub(crate) core: AppCore,
    pub(crate) db: Arc<FlakyDatabase>,
    pub(crate) clock: ManualClock,
    pub(crate) ids: SeqIds,
    pub(crate) mail: Arc<ScriptedMail>,
    pub(crate) templates: Arc<StubTemplates>,
    pub(crate) http: Arc<ScriptedHttp>,
    pub(crate) limiter: Arc<ScriptedLimiter>,
}

impl World {
    pub(crate) fn new() -> Self {
        Self::with(|_| {})
    }

    /// Builds the core after `adjust` changed the dependencies (the config, extra sinks or handlers).
    pub(crate) fn with(adjust: impl FnOnce(&mut AppDeps)) -> Self {
        let clock = ManualClock::default();
        let ids = SeqIds::starting_at(0x1000);
        let db = FlakyDatabase::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::new(ids.clone())));
        let mail = Arc::new(ScriptedMail::default());
        let templates = Arc::new(StubTemplates::default());
        let http = Arc::new(ScriptedHttp::default());
        let limiter = Arc::new(ScriptedLimiter::default());
        let database = Arc::clone(&db);
        let mail_port = Arc::clone(&mail);
        let templates_port = Arc::clone(&templates);
        let http_port = Arc::clone(&http);
        let limiter_port = Arc::clone(&limiter);
        let mut deps = AppDeps {
            clock: Arc::new(clock.clone()),
            ids: Arc::new(ids.clone()),
            keyring: Arc::new(FixedKeyRing::default()),
            sealer: Arc::new(PlainSealer),
            hasher: Arc::new(FixedHasher::default()),
            database,
            http: http_port,
            mail: mail_port,
            templates: templates_port,
            rate_limiter: limiter_port,
            scheduling_policy: Arc::new(NeverAuto),
            authenticators: vec![Arc::new(NoAuthenticator)],
            event_sinks: Vec::new(),
            outbox_handlers: Vec::new(),
            providers: Vec::new(),
            content_scanners: Vec::new(),
            profile_signer: None,
            urls: PublicUrls::new(Url::parse("https://cal.example.org").unwrap()).unwrap(),
            limits: Limits::default(),
            config: AppConfig::default(),
        };
        adjust(&mut deps);
        Self {
            core: AppCore::new(deps),
            db,
            clock,
            ids,
            mail,
            templates,
            http,
            limiter,
        }
    }

    /// A world whose tenant exists already.
    pub(crate) async fn ready() -> Self {
        let world = Self::new();
        world.add_tenant(Self::tenant()).await;
        world
    }

    /// Like [`World::with`], for a world whose tenant exists already.
    pub(crate) async fn ready_with(adjust: impl FnOnce(&mut AppDeps)) -> Self {
        let world = Self::with(adjust);
        world.add_tenant(Self::tenant()).await;
        world
    }

    pub(crate) fn tenant() -> TenantId {
        TenantId::from_uuid(Uuid::from_u128(TENANT))
    }

    /// A second tenant for isolation tests.
    pub(crate) fn other_tenant() -> TenantId {
        TenantId::from_uuid(Uuid::from_u128(TENANT + 1))
    }

    /// The context of an administrator of the tenant (the internal channel is trusted).
    pub(crate) fn ctx() -> RequestContext {
        RequestContext::internal(Self::tenant(), RequestId::from_uuid(Uuid::from_u128(0x77)))
    }

    /// The context of a tenant token of `tenant` that carries `scopes` on the management API.
    pub(crate) fn token_ctx(tenant: TenantId, scopes: &[Scope]) -> RequestContext {
        RequestContext {
            tenant,
            actor: Actor::TenantToken(TokenId::from_uuid(Uuid::from_u128(0x70))),
            scopes: ScopeSet::of(scopes),
            channel: Channel::Api,
            credential: None,
            request_id: RequestId::from_uuid(Uuid::from_u128(0x78)),
            locale: None,
            client_ip: None,
        }
    }

    /// A fresh id from the world's generator.
    pub(crate) fn id<T: From<Uuid>>(&self) -> T {
        T::from(self.ids.new_id())
    }

    /// A read-write transaction of `tenant` on the store itself (no outage switches), for setting up data.
    pub(crate) async fn write(&self, tenant: TenantId) -> Box<dyn Tx> {
        self.db.store().begin(tenant, TxMode::ReadWrite).await.unwrap()
    }

    /// A read-only transaction of `tenant` on the store itself, for inspecting data.
    pub(crate) async fn read(&self, tenant: TenantId) -> Box<dyn Tx> {
        self.db.store().begin(tenant, TxMode::ReadOnly).await.unwrap()
    }

    /// Enqueues `message` for `tenant` and returns its record id.
    pub(crate) async fn enqueue(
        &self,
        tenant: TenantId,
        message: davhaven_testkit::davhaven_ports::OutboxMessage,
    ) -> OutboxId {
        let id: OutboxId = self.id();
        self.add_tenant(tenant).await;
        let mut tx = self.write(tenant).await;
        tx.outbox().enqueue(NewOutbox::now(id, message)).await.unwrap();
        tx.commit().await.unwrap();
        id
    }

    /// Enqueues `message` for `tenant`, due at `due`.
    pub(crate) async fn enqueue_at(
        &self,
        tenant: TenantId,
        message: davhaven_testkit::davhaven_ports::OutboxMessage,
        due: DateTime<Utc>,
    ) -> OutboxId {
        let id: OutboxId = self.id();
        self.add_tenant(tenant).await;
        let mut tx = self.write(tenant).await;
        tx.outbox().enqueue(NewOutbox::at(id, message, due)).await.unwrap();
        tx.commit().await.unwrap();
        id
    }

    /// Enqueues a message of the kind `provider_push`, which nothing in the application handles: tests give it a
    /// scripted handler.
    pub(crate) async fn enqueue_dummy(&self) -> OutboxId {
        self.enqueue(
            Self::tenant(),
            davhaven_testkit::davhaven_ports::OutboxMessage::ProviderPush(Reserved::default()),
        )
        .await
    }

    /// The committed outbox records of the world's tenant, ordered by id.
    pub(crate) async fn outbox(&self) -> Vec<OutboxRecord> {
        self.outbox_of(Self::tenant()).await
    }

    /// The committed outbox records of `tenant`, ordered by id.
    pub(crate) async fn outbox_of(&self, tenant: TenantId) -> Vec<OutboxRecord> {
        let mut tx = self.read(tenant).await;
        let mut records = Vec::new();
        let mut page = davhaven_testkit::davhaven_ports::PageReq::first(1000);
        loop {
            let batch = tx
                .outbox()
                .list(&davhaven_testkit::davhaven_ports::OutboxFilter::default(), page)
                .await
                .unwrap();
            records.extend(batch.items);
            match batch.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        records
    }

    /// The committed outbox record `id` of the world's tenant.
    pub(crate) async fn record(&self, id: OutboxId) -> OutboxRecord {
        self.read(Self::tenant()).await.outbox().get(id).await.unwrap()
    }

    /// The domain events waiting in the outbox of the world's tenant.
    pub(crate) async fn queued_events(&self) -> Vec<Envelope> {
        self.outbox()
            .await
            .iter()
            .filter_map(|record| match record.message() {
                Ok(davhaven_testkit::davhaven_ports::OutboxMessage::DomainEvent(envelope)) => Some(envelope),
                _ => None,
            })
            .collect()
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Tenants, principals, calendars and objects
// ---------------------------------------------------------------------------------------------------------------

/// What [`World::seed`] stored.
pub(crate) struct Seeded {
    pub(crate) calendar: Calendar,
    pub(crate) organizer: Principal,
    pub(crate) object: StoredObject,
}

/// What an object of a test looks like.
pub(crate) struct ObjectSpec<'a> {
    /// The resource name and the UID of an object that is written again; `None` makes a new object.
    pub(crate) existing: Option<&'a StoredObject>,
    pub(crate) data: &'a str,
    pub(crate) last_end: Option<DateTime<Utc>>,
    pub(crate) sequence: i32,
    pub(crate) class: Classification,
    pub(crate) organizer: Option<&'a str>,
    pub(crate) attendees: &'a [&'a str],
}

impl<'a> ObjectSpec<'a> {
    pub(crate) fn new(data: &'a str) -> Self {
        Self {
            existing: None,
            data,
            last_end: None,
            sequence: 0,
            class: Classification::Public,
            organizer: None,
            attendees: &[],
        }
    }
}

impl World {
    /// The row of `tenant`: an English-speaking tenant in Berlin that sends from `noreply@mail.example.org`.
    pub(crate) fn tenant_row(&self, tenant: TenantId) -> Tenant {
        let mut settings = TenantSettings::default();
        settings.locale = Locale::en();
        settings.timezone = TimeZoneName::parse("Europe/Berlin").unwrap();
        settings.sender.domain = Some(DomainName::parse(SENDER_DOMAIN).unwrap());
        let now = self.clock.now();
        Tenant {
            id: tenant,
            slug: TenantSlug::parse(&format!("t{}", tenant.as_uuid().simple())).unwrap(),
            display_name: "Example Organisation".to_owned(),
            login_domain: None,
            status: TenantStatus::Active,
            settings,
            created_at: now,
            updated_at: now,
            version: 1,
        }
    }

    /// Stores the tenant row of `tenant`.
    pub(crate) async fn add_tenant(&self, tenant: TenantId) {
        let row = self.tenant_row(tenant);
        self.add_tenant_row(row).await;
    }

    /// Stores `row`, unless a tenant with its id exists already.
    pub(crate) async fn add_tenant_row(&self, row: Tenant) {
        let mut system = self.db.store().begin_system().await.unwrap();
        match system.tenants().get(row.id).await {
            Ok(_existing) => return,
            Err(StoreError::NotFound) => {}
            Err(error) => panic!("{error}"),
        }
        system.tenants().create(row).await.unwrap();
        system.commit().await.unwrap();
    }

    /// Stores a user of `tenant` with the primary address `{name}@example.org`.
    pub(crate) async fn add_principal(&self, tenant: TenantId, name: &str, display_name: &str) -> Principal {
        let now = self.clock.now();
        let email = Email::parse(&format!("{name}@example.org")).unwrap();
        let id: PrincipalId = self.id();
        let principal = Principal {
            id,
            tenant_id: tenant,
            kind: PrincipalKind::User,
            name: PrincipalName::parse(name).unwrap(),
            display_name: display_name.to_owned(),
            email: Some(email.clone()),
            locale: None,
            timezone: None,
            external_ref: None,
            status: PrincipalStatus::Active,
            deleted_at: None,
            credential_generation: 0,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        let mut tx = self.write(tenant).await;
        let stored = tx.principals().create(principal).await.unwrap();
        tx.principals()
            .set_addresses(
                id,
                vec![PrincipalAddress {
                    principal_id: id,
                    address: CalendarUserAddress::mailto(&email),
                    primary: true,
                }],
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        stored
    }

    /// Stores a calendar of `kind` owned by `owner`.
    pub(crate) async fn add_calendar(&self, tenant: TenantId, owner: PrincipalId, kind: CalendarKind) -> Calendar {
        let now = self.clock.now();
        let id: CalendarId = self.id();
        let calendar = Calendar {
            id,
            tenant_id: tenant,
            owner_id: owner,
            slug: CalendarSlug::parse(&format!("cal-{}", id.as_uuid().simple())).unwrap(),
            kind,
            display_name: "Calendar".to_owned(),
            description: None,
            color: None,
            sort_order: 0,
            components: vec![ComponentKind::Event],
            timezone_ics: None,
            sync_seq: 0,
            sync_min_seq: 0,
            sync_epoch: Uuid::from_u128(1),
            deleted_at: None,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        let mut tx = self.write(tenant).await;
        let stored = tx.calendars().create(calendar).await.unwrap();
        tx.commit().await.unwrap();
        stored
    }

    /// Stores an object in `calendar`.
    pub(crate) async fn add_object(&self, calendar: &Calendar, spec: &ObjectSpec<'_>) -> StoredObject {
        let id: ObjectId = spec.existing.map_or_else(|| self.id(), |object| object.id);
        let uid = spec.existing.map_or_else(
            || format!("uid-{}", id.as_uuid().simple()),
            |object| object.uid.to_string(),
        );
        let now = self.clock.now();
        let mut index = ObjectIndex {
            uid: Uid::parse(&uid).unwrap(),
            component: ComponentKind::Event,
            first_start: Some(now),
            last_end: spec.last_end,
            is_recurring: false,
            is_scheduling: spec.organizer.is_some(),
            organizer: spec.organizer.map(|text| CalendarUserAddress::parse(text).unwrap()),
            attendees: Vec::new(),
            sequence: spec.sequence,
            class: spec.class,
            transp: Transparency::Opaque,
        };
        for attendee in spec.attendees {
            index
                .attendees
                .push(davhaven_testkit::davhaven_domain::AttendeeRef::new(
                    CalendarUserAddress::parse(attendee).unwrap(),
                ));
        }
        let version = NewVersion {
            id,
            uri: spec.existing.map_or_else(
                || ObjectUri::parse(&format!("{}.ics", id.as_uuid().simple())).unwrap(),
                |object| object.uri.clone(),
            ),
            etag: ETag::from_bytes(spec.data.as_bytes()),
            data: spec.data.to_owned(),
            schedule_tag: None,
            content_hash: ContentHash::from_digest([0; 32]),
            index,
            attendee_principals: Vec::new(),
            external_key: None,
            origin: None,
        };
        let mut tx = self.write(calendar.tenant_id).await;
        tx.objects().put(calendar.id, version, Expected::Any).await.unwrap();
        let stored = tx.objects().get_by_id(id).await.unwrap();
        tx.commit().await.unwrap();
        stored
    }

    /// Stores the tenant, an organizer with a personal calendar and an invitation in it, and returns them.
    pub(crate) async fn seed(&self) -> Seeded {
        self.add_tenant(Self::tenant()).await;
        let organizer = self.add_principal(Self::tenant(), "anna", "Anna Example").await;
        let calendar = self
            .add_calendar(Self::tenant(), organizer.id, CalendarKind::Personal)
            .await;
        let last_end = self.clock.now() + ChronoDuration::days(30);
        let object = self
            .add_object(
                &calendar,
                &ObjectSpec {
                    last_end: Some(last_end),
                    organizer: Some("mailto:anna@example.org"),
                    attendees: &[
                        "mailto:guest@example.org",
                        "mailto:guest@example.net",
                        "mailto:bob@example.org",
                    ],
                    ..ObjectSpec::new("SOURCE")
                },
            )
            .await;
        Seeded {
            calendar,
            organizer,
            object,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Events, subscriptions and the objects they are about
// ---------------------------------------------------------------------------------------------------------------

impl World {
    /// A domain event of `event_type` for `tenant`; the payload is a `principal.*` one for principal types and a
    /// calendar one otherwise, which is enough for the types the tests use.
    pub(crate) fn envelope(&self, tenant: TenantId, event_type: EventType) -> Envelope {
        let payload = match event_type {
            EventType::PrincipalCreated | EventType::PrincipalUpdated | EventType::PrincipalDeleted => {
                EventPayload::Principal(PrincipalPayload { principal: self.id() })
            }
            EventType::WebhookPing | EventType::WebhookDisabled => EventPayload::Webhook(WebhookPayload {
                webhook: self.id(),
                reason: "test".to_owned(),
            }),
            _ => EventPayload::Calendar(CalendarPayload {
                calendar: self.id(),
                owner: self.id(),
                kind: CalendarKind::Group,
            }),
        };
        Envelope::new(
            self.id(),
            event_type,
            tenant,
            self.clock.now(),
            AuditActor::system(),
            payload,
        )
        .unwrap()
    }

    /// An active subscription of `tenant` for `events`, not yet stored.
    pub(crate) fn subscription(&self, tenant: TenantId, events: &[EventType]) -> WebhookSubscription {
        let now = self.clock.now();
        WebhookSubscription {
            id: self.id(),
            tenant_id: tenant,
            url: Url::parse("https://hooks.example.org/in").unwrap(),
            description: None,
            sealed_secret: b"sealed".to_vec(),
            sealed_secret_previous: None,
            secret_rotated_at: None,
            events: events.to_vec(),
            include_details: false,
            active: true,
            failure_count: 0,
            disabled_reason: None,
            created_at: now,
            updated_at: now,
            version: 1,
        }
    }

    /// Stores `subscription` (and the tenant, if it is not there yet) and returns what the store made of it.
    pub(crate) async fn add_subscription(&self, subscription: WebhookSubscription) -> WebhookSubscription {
        let tenant = subscription.tenant_id;
        self.add_tenant(tenant).await;
        let mut tx = self.write(tenant).await;
        let stored = tx.webhooks().create(subscription).await.unwrap();
        tx.commit().await.unwrap();
        stored
    }

    /// The subscription `id` of `tenant` as stored.
    pub(crate) async fn subscription_of(&self, tenant: TenantId, id: WebhookId) -> WebhookSubscription {
        self.read(tenant).await.webhooks().get(id).await.unwrap()
    }

    /// Every delivery of `tenant`, ordered by id.
    pub(crate) async fn deliveries(&self, tenant: TenantId) -> Vec<DeliveryRecord> {
        let mut tx = self.read(tenant).await;
        let subscriptions = tx.webhooks().list(PageReq::first(1000)).await.unwrap().items;
        let mut all = Vec::new();
        for subscription in subscriptions {
            all.extend(
                tx.webhooks()
                    .list_deliveries(subscription.id, PageReq::first(1000))
                    .await
                    .unwrap()
                    .items,
            );
        }
        all.sort_by_key(|delivery| delivery.id);
        all
    }

    /// The delivery `id` of `tenant` as stored.
    pub(crate) async fn delivery_of(&self, tenant: TenantId, id: DeliveryId) -> DeliveryRecord {
        self.read(tenant).await.webhooks().get_delivery(id).await.unwrap()
    }

    /// The webhook messages in the outbox of `tenant`.
    pub(crate) async fn webhook_messages(&self, tenant: TenantId) -> Vec<WebhookDelivery> {
        self.outbox_of(tenant)
            .await
            .iter()
            .filter_map(|record| match record.message() {
                Ok(OutboxMessage::Webhook(delivery)) => Some(delivery),
                _ => None,
            })
            .collect()
    }

    /// Stores a calendar of `kind` of a fresh owner in `tenant` and returns it.
    pub(crate) async fn calendar_of_kind(&self, tenant: TenantId, kind: CalendarKind) -> Calendar {
        self.add_tenant(tenant).await;
        let name = format!("owner{}", self.id::<Uuid>().simple());
        let owner = self.add_principal(tenant, &name, "Owner").await;
        self.add_calendar(tenant, owner.id, kind).await
    }

    /// Stores an object with the summary `summary` and the class `class` in `calendar`.
    pub(crate) async fn object_with_summary(
        &self,
        calendar: &Calendar,
        summary: &str,
        class: Classification,
    ) -> StoredObject {
        let data = format!("SUMMARY:{summary}");
        self.add_object(
            calendar,
            &ObjectSpec {
                last_end: Some(self.clock.now() + ChronoDuration::hours(2)),
                class,
                ..ObjectSpec::new(&data)
            },
        )
        .await
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Putting outbox records into a state
// ---------------------------------------------------------------------------------------------------------------

/// What a claimed record is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fate {
    /// Dead letter.
    Dead,
    /// Done.
    Done,
    /// Pending again, due now (a failed attempt).
    RetryNow,
    /// Left claimed for an hour.
    InFlight,
}

impl World {
    /// Claims every ready record and gives `id` the `fate`; the other claims are handed back (their attempts are
    /// not counted). The way tests bring a record into a state through the queue itself.
    pub(crate) async fn settle(&self, id: OutboxId, fate: Fate) {
        let mut tx = self.db.store().begin_system().await.unwrap();
        let claimed = tx
            .outbox_claim()
            .claim(1000, std::time::Duration::from_secs(3600))
            .await
            .unwrap();
        let mut others = Vec::new();
        for record in claimed {
            if record.id != id {
                others.push(record.key());
                continue;
            }
            let queue = tx.outbox_claim();
            match fate {
                Fate::Dead => queue.fail(record.key(), OutboxFailure::dead("gave up")).await.unwrap(),
                Fate::Done => queue.complete(record.key()).await.unwrap(),
                Fate::RetryNow => queue
                    .fail(record.key(), OutboxFailure::retry("again", self.clock.now()))
                    .await
                    .unwrap(),
                Fate::InFlight => {}
            }
        }
        tx.outbox_claim().release_leases(&others).await.unwrap();
        tx.commit().await.unwrap();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The audit log
// ---------------------------------------------------------------------------------------------------------------

impl World {
    /// The audit records of `tenant`: action and details, oldest first.
    pub(crate) async fn audit(&self, tenant: TenantId) -> Vec<(String, serde_json::Value)> {
        let mut tx = self.read(tenant).await;
        tx.audit()
            .list(
                &davhaven_testkit::davhaven_ports::AuditFilter::default(),
                PageReq::first(1000),
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|row| (row.action, row.details))
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Changing what is stored
// ---------------------------------------------------------------------------------------------------------------

impl World {
    /// Stores a new version of `object` with the given `SEQUENCE`.
    pub(crate) async fn bump_sequence(
        &self,
        calendar: &Calendar,
        object: &StoredObject,
        sequence: i32,
    ) -> StoredObject {
        self.add_object(
            calendar,
            &ObjectSpec {
                existing: Some(object),
                sequence,
                last_end: object.last_end,
                organizer: Some("mailto:anna@example.org"),
                attendees: &[
                    "mailto:guest@example.org",
                    "mailto:guest@example.net",
                    "mailto:bob@example.org",
                ],
                ..ObjectSpec::new(&object.data)
            },
        )
        .await
    }

    /// Stores a new version of `object` that lists exactly `attendees`.
    pub(crate) async fn set_attendees(
        &self,
        calendar: &Calendar,
        object: &StoredObject,
        attendees: &[&str],
    ) -> StoredObject {
        self.add_object(
            calendar,
            &ObjectSpec {
                existing: Some(object),
                sequence: object.sequence,
                last_end: object.last_end,
                organizer: Some("mailto:anna@example.org"),
                attendees,
                ..ObjectSpec::new(&object.data)
            },
        )
        .await
    }

    /// Deletes `object`.
    pub(crate) async fn delete_object(&self, object: &StoredObject) {
        let mut tx = self.write(object.tenant_id).await;
        tx.objects()
            .delete(object.calendar_id, &object.uri, Expected::Any)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// Changes the row of the world's tenant.
    pub(crate) async fn update_tenant(&self, change: impl FnOnce(&mut Tenant)) {
        let mut system = self.db.store().begin_system().await.unwrap();
        let mut tenant = system.tenants().get(Self::tenant()).await.unwrap();
        let version = tenant.version;
        change(&mut tenant);
        system.tenants().update(tenant, version).await.unwrap();
        system.commit().await.unwrap();
    }

    /// Deletes the world's tenant.
    pub(crate) async fn delete_tenant(&self) {
        let mut system = self.db.store().begin_system().await.unwrap();
        system.tenants().delete(Self::tenant()).await.unwrap();
        system.commit().await.unwrap();
    }

    /// Changes the display name of the principal `id`.
    pub(crate) async fn rename(&self, id: PrincipalId, display_name: &str) {
        let mut tx = self.write(Self::tenant()).await;
        let mut principal = tx.principals().get(id).await.unwrap();
        let version = principal.version;
        principal.display_name = display_name.to_owned();
        tx.principals().update(principal, version).await.unwrap();
        tx.commit().await.unwrap();
    }

    /// The RSVP tokens of `object`.
    pub(crate) async fn rsvp_tokens(&self, object: ObjectId) -> Vec<davhaven_testkit::davhaven_domain::RsvpToken> {
        self.read(Self::tenant()).await.rsvp().for_object(object).await.unwrap()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// A renderer that remembers what it was asked
// ---------------------------------------------------------------------------------------------------------------

/// A template renderer that hands every request to another renderer and remembers it.
pub(crate) struct RecordingRenderer {
    inner: Arc<dyn TemplateRenderer>,
    requests: Mutex<Vec<RenderRequest>>,
}

impl RecordingRenderer {
    pub(crate) fn new(inner: Arc<dyn TemplateRenderer>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            requests: Mutex::new(Vec::new()),
        })
    }

    /// The model of the last render.
    pub(crate) fn last_model(&self) -> serde_json::Value {
        locked(&self.requests).last().unwrap().model.clone()
    }
}

#[async_trait]
impl TemplateRenderer for RecordingRenderer {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError> {
        locked(&self.requests).push(request.clone());
        self.inner.render(request).await
    }

    fn catalog(&self) -> Vec<TemplateName> {
        self.inner.catalog()
    }
}
