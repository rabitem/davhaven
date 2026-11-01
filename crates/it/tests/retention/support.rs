//! The world of the retention tests: an application core on the in-memory store with a manual clock, and helpers that
//! create the data the worker cleans up and look at what is left.
//!
//! The store is the real `store-memory` adapter, wrapped by [`FlakyDatabase`], which can refuse to begin
//! transactions (an outage) or refuse the next few system transactions (one failing step of a pass). The ports that
//! the worker does not use are inert doubles.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Duration as ChronoDuration;
use davhaven_testkit::davhaven_app::{AppConfig, AppCore, AppDeps};
use davhaven_testkit::davhaven_domain::audit::KeyRotationAudit;
use davhaven_testkit::davhaven_domain::{
    AuditActor, AuditEvent, Calendar, CalendarId, CalendarKind, CalendarSlug, CalendarUserAddress, Classification,
    CollectionKey, CollectionKind, ComponentKind, ContentHash, ETag, Limits, ObjectId, ObjectIndex, ObjectUri,
    OutboxId, OutgoingMail, PartStat, Principal, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus,
    PublicUrls, Tenant, TenantId, TenantSettings, TenantSlug, TenantStatus, Transparency, Uid,
};
use davhaven_testkit::davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
use davhaven_testkit::davhaven_ports::{
    AuditFilter, AuthHint, AuthOutcome, Authenticator, Clock, Database, Expected, FreeBusy, Health, HttpClient,
    IdGenerator, Invite, MailTransport, NewAudit, NewOutbox, NewVersion, OutboundRequest, OutboundResponse,
    OutboxFilter, OutboxMessage, OutboxStatus, PageReq, PolicyTenant, PortError, PresentedCredential, RateDecision,
    RateKey, RateLimiter, RenderRequest, Rendered, Reserved, ResourceRequest, SchedulingPolicy, SendReceipt,
    StoreError, SystemTx, TemplateName, TemplateRenderer, Tx, TxMode,
};
use davhaven_testkit::davhaven_store_memory::database::MemoryDatabase;
use url::Url;
use uuid::Uuid;

// ---------------------------------------------------------------------------------------------------------------
// The store, with faults
// ---------------------------------------------------------------------------------------------------------------

/// The in-memory store that can be made to fail.
pub(crate) struct FlakyDatabase {
    inner: MemoryDatabase,
    outage: AtomicBool,
    failing_system_begins: AtomicU32,
}

impl FlakyDatabase {
    fn new(inner: MemoryDatabase) -> Arc<Self> {
        Arc::new(Self {
            inner,
            outage: AtomicBool::new(false),
            failing_system_begins: AtomicU32::new(0),
        })
    }

    /// The store itself, for setting up and inspecting data.
    pub(crate) fn store(&self) -> &MemoryDatabase {
        &self.inner
    }

    /// While set, every `begin` and `begin_system` fails with `Unavailable`.
    pub(crate) fn set_outage(&self, on: bool) {
        self.outage.store(on, Ordering::SeqCst);
    }

    /// The next `count` calls to `begin_system` fail with `Unavailable`.
    pub(crate) fn fail_next_system_begins(&self, count: u32) {
        self.failing_system_begins.store(count, Ordering::SeqCst);
    }
}

#[async_trait]
impl Database for FlakyDatabase {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        if self.outage.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.inner.begin(tenant, mode).await
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        if self.outage.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        let failing = self
            .failing_system_begins
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1));
        if failing.is_ok() {
            return Err(StoreError::Unavailable);
        }
        self.inner.begin_system().await
    }

    async fn health(&self) -> Health {
        Database::health(&self.inner).await
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Inert doubles for the ports the worker does not use
// ---------------------------------------------------------------------------------------------------------------

struct NoMail;

#[async_trait]
impl MailTransport for NoMail {
    async fn send(&self, _mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        Err(PortError::internal("the test double does not send"))
    }
}

struct NoHttp;

#[async_trait]
impl HttpClient for NoHttp {
    async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        Err(PortError::internal("the test double does not send"))
    }
}

struct NoTemplates;

#[async_trait]
impl TemplateRenderer for NoTemplates {
    async fn render(&self, _request: RenderRequest) -> Result<Rendered, PortError> {
        Err(PortError::internal("the test double does not render"))
    }

    fn catalog(&self) -> Vec<TemplateName> {
        Vec::new()
    }
}

struct AllowAll;

#[async_trait]
impl RateLimiter for AllowAll {
    async fn check(&self, _key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
        Ok(RateDecision::allow(u32::MAX))
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

// ---------------------------------------------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------------------------------------------

/// The application core on the in-memory store, with handles to the pieces the tests drive.
pub(crate) struct World {
    pub(crate) core: AppCore,
    pub(crate) db: Arc<FlakyDatabase>,
    pub(crate) clock: ManualClock,
    pub(crate) ids: SeqIds,
}

impl World {
    pub(crate) fn new() -> Self {
        Self::with(|_| {})
    }

    /// Builds the core after `adjust` changed the dependencies (the configuration, for example).
    pub(crate) fn with(adjust: impl FnOnce(&mut AppDeps)) -> Self {
        let clock = ManualClock::default();
        let ids = SeqIds::starting_at(0x1000);
        let db = FlakyDatabase::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::new(ids.clone())));
        let database = Arc::clone(&db);
        let mut deps = AppDeps {
            clock: Arc::new(clock.clone()),
            ids: Arc::new(ids.clone()),
            keyring: Arc::new(FixedKeyRing::default()),
            sealer: Arc::new(PlainSealer),
            hasher: Arc::new(FixedHasher::default()),
            database,
            http: Arc::new(NoHttp),
            mail: Arc::new(NoMail),
            templates: Arc::new(NoTemplates),
            rate_limiter: Arc::new(AllowAll),
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
        }
    }

    /// Moves the clock forward by whole days.
    pub(crate) fn advance_days(&self, days: i64) {
        self.clock.advance(ChronoDuration::days(days));
    }

    fn id<T: From<Uuid>>(&self) -> T {
        T::from(self.ids.new_id())
    }

    async fn write(&self, tenant: TenantId) -> Box<dyn Tx> {
        self.db.store().begin(tenant, TxMode::ReadWrite).await.unwrap()
    }

    async fn read(&self, tenant: TenantId) -> Box<dyn Tx> {
        self.db.store().begin(tenant, TxMode::ReadOnly).await.unwrap()
    }

    /// Creates a tenant.
    pub(crate) async fn tenant(&self) -> TenantId {
        let id: TenantId = self.id();
        let now = self.clock.now();
        let row = Tenant {
            id,
            slug: TenantSlug::parse(&format!("t{}", id.as_uuid().simple())).unwrap(),
            display_name: "Example Organisation".to_owned(),
            login_domain: None,
            status: TenantStatus::Active,
            settings: TenantSettings::default(),
            created_at: now,
            updated_at: now,
            version: 1,
        };
        let mut system = self.db.store().begin_system().await.unwrap();
        system.tenants().create(row).await.unwrap();
        system.commit().await.unwrap();
        id
    }

    /// Enqueues a message that nothing handles, as pending.
    pub(crate) async fn enqueue(&self, tenant: TenantId) -> OutboxId {
        let id: OutboxId = self.id();
        let mut tx = self.write(tenant).await;
        tx.outbox()
            .enqueue(NewOutbox::now(id, OutboxMessage::ProviderPush(Reserved::default())))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        id
    }

    /// Enqueues a message and settles it at the current time: `done`, or `dead` when `dead` is set.
    pub(crate) async fn settled(&self, tenant: TenantId, dead: bool) -> OutboxId {
        let id = self.enqueue(tenant).await;
        let mut system = self.db.store().begin_system().await.unwrap();
        let claimed = system.outbox_claim().claim(100, Duration::from_secs(60)).await.unwrap();
        for record in claimed.iter().filter(|record| record.id == id) {
            if dead {
                system
                    .outbox_claim()
                    .fail(
                        record.key(),
                        davhaven_testkit::davhaven_ports::OutboxFailure::dead("gave up"),
                    )
                    .await
                    .unwrap();
            } else {
                system.outbox_claim().complete(record.key()).await.unwrap();
            }
        }
        system.commit().await.unwrap();
        id
    }

    /// The ids of the tenant's outbox records in `status`.
    pub(crate) async fn outbox_ids(&self, tenant: TenantId, status: OutboxStatus) -> Vec<OutboxId> {
        let mut tx = self.read(tenant).await;
        let filter = OutboxFilter {
            status: Some(status),
            kind: None,
        };
        tx.outbox()
            .list(&filter, PageReq::first(100))
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|record| record.id)
            .collect()
    }

    /// Creates a user.
    pub(crate) async fn principal(&self, tenant: TenantId, name: &str) -> Principal {
        let now = self.clock.now();
        let principal = Principal {
            id: self.id(),
            tenant_id: tenant,
            kind: PrincipalKind::User,
            name: PrincipalName::parse(name).unwrap(),
            display_name: name.to_owned(),
            email: None,
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
        tx.commit().await.unwrap();
        stored
    }

    /// Creates a calendar.
    pub(crate) async fn calendar(&self, tenant: TenantId, owner: PrincipalId, kind: CalendarKind) -> Calendar {
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

    /// Deletes a calendar the way the application does: it is hidden and purged later.
    pub(crate) async fn delete_calendar(&self, tenant: TenantId, calendar: CalendarId) {
        let mut tx = self.write(tenant).await;
        let version = tx.calendars().get(calendar).await.unwrap().version;
        tx.calendars().soft_delete(calendar, version).await.unwrap();
        tx.commit().await.unwrap();
    }

    /// Deletes a principal the way the application does: it is marked deleted and purged later.
    pub(crate) async fn delete_principal(&self, tenant: TenantId, principal: PrincipalId) {
        let mut tx = self.write(tenant).await;
        let mut row = tx.principals().get(principal).await.unwrap();
        let version = row.version;
        row.status = PrincipalStatus::Deleted;
        row.deleted_at = Some(self.clock.now());
        tx.principals().update(row, version).await.unwrap();
        tx.commit().await.unwrap();
    }

    /// The calendars and principals that are deleted and still waiting for their purge, whatever their age.
    pub(crate) async fn awaiting_purge(&self) -> (Vec<(TenantId, PrincipalId)>, Vec<(TenantId, CalendarId)>) {
        let later = self.clock.now() + ChronoDuration::days(36_500);
        let mut system = self.db.store().begin_system().await.unwrap();
        let principals = system.retention().due_principals(later, 100).await.unwrap();
        let calendars = system.retention().due_calendars(later, 100).await.unwrap();
        (principals, calendars)
    }

    /// Whether a live calendar of the tenant exists.
    pub(crate) async fn calendar_exists(&self, tenant: TenantId, calendar: CalendarId) -> bool {
        self.read(tenant).await.calendars().get(calendar).await.is_ok()
    }

    /// The names of the audit actions of the tenant, in order.
    pub(crate) async fn audit_actions(&self, tenant: TenantId) -> Vec<String> {
        let mut tx = self.read(tenant).await;
        tx.audit()
            .list(&AuditFilter::default(), PageReq::first(1000))
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|row| row.action)
            .collect()
    }

    /// Appends an audit record to the tenant's log; the store stamps it with the current time.
    pub(crate) async fn audit(&self, tenant: TenantId) {
        let mut tx = self.write(tenant).await;
        tx.audit()
            .append(NewAudit {
                id: self.ids.new_id(),
                actor: AuditActor::system(),
                event: AuditEvent::KeysRotated(KeyRotationAudit {
                    active_kid: "k1".to_owned(),
                }),
            })
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// Stores an object in the calendar, which writes one row of the change log, and returns the epoch of the collection and
    /// the sequence of the change.
    pub(crate) async fn put_object(&self, tenant: TenantId, calendar: CalendarId) -> (Uuid, u64) {
        let id: ObjectId = self.id();
        let now = self.clock.now();
        let data = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned();
        let index = ObjectIndex {
            uid: Uid::parse("retention-test").unwrap(),
            component: ComponentKind::Event,
            first_start: Some(now),
            last_end: Some(now + ChronoDuration::hours(1)),
            is_recurring: false,
            is_scheduling: false,
            organizer: None,
            attendees: Vec::new(),
            sequence: 0,
            class: Classification::Public,
            transp: Transparency::Opaque,
        };
        let version = NewVersion {
            id,
            uri: ObjectUri::parse("retention-test.ics").unwrap(),
            etag: ETag::from_bytes(data.as_bytes()),
            data,
            schedule_tag: None,
            content_hash: ContentHash::from_digest([0; 32]),
            index,
            attendee_principals: Vec::new(),
            external_key: None,
            origin: None,
        };
        let mut tx = self.write(tenant).await;
        let written = tx.objects().put(calendar, version, Expected::Any).await.unwrap();
        let key = CollectionKey {
            kind: CollectionKind::Calendar,
            id: calendar.as_uuid(),
        };
        let epoch = tx.changes().state(key).await.unwrap().epoch;
        tx.commit().await.unwrap();
        (epoch, written.seq)
    }

    /// What a client with the sync token `(epoch, seq)` of the collection gets.
    pub(crate) async fn since(
        &self,
        tenant: TenantId,
        key: CollectionKey,
        epoch: Uuid,
        seq: u64,
    ) -> Result<(), StoreError> {
        let mut tx = self.read(tenant).await;
        tx.changes().since(key, epoch, seq, 100).await.map(|_changes| ())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Gauges
// ---------------------------------------------------------------------------------------------------------------

/// A metrics recorder for tests that keeps the gauges: the last value of every gauge under the series name
/// `name{label=value,...}` (labels sorted). A gauge that was never set is not there, which is how a test tells a gauge that
/// is absent from one that is zero. Counters and histograms are not kept.
#[derive(Default, Clone)]
pub(crate) struct GaugeCapture {
    values: Arc<RwLock<BTreeMap<String, f64>>>,
}

struct GaugeSeries {
    name: String,
    values: Arc<RwLock<BTreeMap<String, f64>>>,
}

impl GaugeSeries {
    fn update(&self, change: impl FnOnce(&mut f64)) {
        let mut values = self.values.write().unwrap();
        change(values.entry(self.name.clone()).or_insert(0.0));
    }
}

impl metrics::GaugeFn for GaugeSeries {
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

impl GaugeCapture {
    /// The value of a gauge, if it was ever set.
    pub(crate) fn get(&self, series: &str) -> Option<f64> {
        self.values.read().unwrap().get(series).copied()
    }
}

impl metrics::Recorder for GaugeCapture {
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

    fn register_counter(&self, _key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Counter {
        metrics::Counter::noop()
    }

    fn register_gauge(&self, key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Gauge {
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
        metrics::Gauge::from_arc(Arc::new(GaugeSeries {
            name,
            values: Arc::clone(&self.values),
        }))
    }

    fn register_histogram(&self, _key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}
