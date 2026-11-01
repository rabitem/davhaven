//! The world of the application-core tests: the real services of `davhaven-app` on a real store (the in-memory
//! adapter or PostgreSQL, whichever copy of the suite the world is built for, `STORE`), with a deterministic clock,
//! ids, key ring, sealer and hasher.
//!
//! The store is the real adapter (the one the store contract suite checks), wrapped twice: by
//! [`CountingDatabase`], which counts how often authorization facts are loaded, and by `FaultyDatabase` of the ports
//! test doubles, which can fail commits and begins. Every other port that the services need but the tests do not
//! exercise is a double of one port: an authenticator that knows the secrets the test teaches it, a rate limiter that
//! counts failures, and "unsupported" doubles for mail, templates and HTTP.
//!
//! Tenants, principals and calendars are provisioned through the services themselves (`TenantService`,
//! `PrincipalService`, `CalendarService`), so a test starts from state that the application created.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, PoisonError};

use async_trait::async_trait;
use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::services::{CalendarRef, CalendarSpec, Conditions, PrincipalSpec, TenantSpec};
use davhaven_testkit::davhaven_app::{AppConfig, AppCore, AppDeps, AppServices, build};
use davhaven_testkit::davhaven_domain::{
    Actor, ApiToken, CalendarId, CalendarKind, CalendarSlug, CalendarUserAddress, Channel, CredentialKind, DomainName,
    Email, Envelope, EventPayload, EventType, Limits, ObjectUri, OutgoingMail, PartStat, PrincipalId, PrincipalKind,
    PrincipalName, PublicUrls, RequestContext, RequestId, ResourcePath, Scope, ScopeSet, TenantId, TenantSettings,
    TenantSlug, TokenId, TokenKind,
};
use davhaven_testkit::davhaven_fixtures::event::{EventBuilder, When};
use davhaven_testkit::davhaven_ports::testing::{
    FaultyDatabase, FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds,
};
use davhaven_testkit::davhaven_ports::{
    AuditFilter, AuditRow, AuthHint, AuthOutcome, Authenticated, Authenticator, BindingRepo, CalendarRepo, ChangeRepo,
    Clock, CredentialRepo, Database, ExternalAccountRepo, FreeBusy, GrantRepo, HttpClient, IdGenerator,
    IdempotencyRepo, InboxRepo, Invite, MailTransport, MembershipRepo, NotificationRepo, OAuthStateRepo, ObjectRepo,
    OutboundRequest, OutboundResponse, OutboxFilter, OutboxRepo, PageReq, PolicyTenant, PortError, PresentedCredential,
    PrincipalRepo, PropertyRepo, RateDecision, RateKey, RateLimiter, RenderRequest, Rendered, ResourceRequest,
    RsvpRepo, SchedulingPolicy, SendReceipt, StoreError, SystemTx, TemplateName, TemplateRenderer, TenantRepo, Tx,
    TxMode, WebhookRepo,
};
use davhaven_testkit::davhaven_store_memory::database::MemoryDatabase;
use davhaven_testkit::davhaven_wire::{
    CalendarView, CalendarWrite, PrincipalView, PrincipalWrite, TenantView, TenantWrite,
};
use davhaven_testkit::postgres::ClonedDatabase;
use chrono::{DateTime, Utc};
use url::Url;
use uuid::Uuid;

use crate::Store;

/// Whether this copy of the suite runs on PostgreSQL: it is the PostgreSQL copy and there is a database for it. Without
/// `DATABASE_URL` that fails (`ENGINEERING_RULES` R9: a run without a database must not look green), except outside CI
/// with `DAVHAVEN_ALLOW_NO_DB=1`: the copy then says that it was skipped and builds its worlds on the memory store, so a
/// local run of the whole workspace without a database stays green and still says what it did not test.
pub(crate) fn runs_on_postgres() -> bool {
    super::STORE == Store::Postgres && davhaven_testkit::postgres::require_database()
}

/// The counters and answers of the doubles are touched for an instant and never across an await.
#[expect(clippy::disallowed_types, reason = "test doubles with synchronous accessors")]
pub(crate) type Mutex<T> = std::sync::Mutex<T>;

/// Locks a double's state, whatever happened to the thread that held it last.
pub(crate) fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------------------------
// The store, counting how often authorization facts are loaded
// ---------------------------------------------------------------------------------------------------------------

/// The store that counts loads of authorization facts (`CalendarRepo::access_facts` and
/// `access_facts_many`): the application promises one load per calendar per request.
pub(crate) struct CountingDatabase {
    inner: Arc<dyn Database>,
    fact_loads: Arc<AtomicU32>,
    begins: AtomicU32,
}

impl CountingDatabase {
    fn new(inner: Arc<dyn Database>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fact_loads: Arc::new(AtomicU32::new(0)),
            begins: AtomicU32::new(0),
        })
    }

    /// How many tenant transactions were begun through the counting wrapper (the store itself, [`Self::store`], is
    /// not counted).
    pub(crate) fn begins(&self) -> u32 {
        self.begins.load(Ordering::SeqCst)
    }

    /// The store itself, without the counters: for setting up and inspecting data.
    pub(crate) fn store(&self) -> &dyn Database {
        self.inner.as_ref()
    }
}

#[async_trait]
impl Database for CountingDatabase {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        let inner = self.inner.begin(tenant, mode).await?;
        Ok(Box::new(CountingTx {
            inner,
            fact_loads: Arc::clone(&self.fact_loads),
        }))
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        self.inner.begin_system().await
    }

    async fn health(&self) -> davhaven_testkit::davhaven_ports::Health {
        self.inner.health().await
    }
}

/// A transaction that is its own calendar repository, to count the fact loads, and delegates everything else.
struct CountingTx {
    inner: Box<dyn Tx>,
    fact_loads: Arc<AtomicU32>,
}

#[async_trait]
impl Tx for CountingTx {
    fn tenant_id(&self) -> TenantId {
        self.inner.tenant_id()
    }

    fn tenant(&mut self) -> &mut dyn TenantRepo {
        self.inner.tenant()
    }

    fn principals(&mut self) -> &mut dyn PrincipalRepo {
        self.inner.principals()
    }

    fn memberships(&mut self) -> &mut dyn MembershipRepo {
        self.inner.memberships()
    }

    fn calendars(&mut self) -> &mut dyn CalendarRepo {
        self
    }

    fn bindings(&mut self) -> &mut dyn BindingRepo {
        self.inner.bindings()
    }

    fn properties(&mut self) -> &mut dyn PropertyRepo {
        self.inner.properties()
    }

    fn grants(&mut self) -> &mut dyn GrantRepo {
        self.inner.grants()
    }

    fn objects(&mut self) -> &mut dyn ObjectRepo {
        self.inner.objects()
    }

    fn changes(&mut self) -> &mut dyn ChangeRepo {
        self.inner.changes()
    }

    fn notifications(&mut self) -> &mut dyn NotificationRepo {
        self.inner.notifications()
    }

    fn inbox(&mut self) -> &mut dyn InboxRepo {
        self.inner.inbox()
    }

    fn credentials(&mut self) -> &mut dyn CredentialRepo {
        self.inner.credentials()
    }

    fn rsvp(&mut self) -> &mut dyn RsvpRepo {
        self.inner.rsvp()
    }

    fn outbox(&mut self) -> &mut dyn OutboxRepo {
        self.inner.outbox()
    }

    fn webhooks(&mut self) -> &mut dyn WebhookRepo {
        self.inner.webhooks()
    }

    fn external_accounts(&mut self) -> &mut dyn ExternalAccountRepo {
        self.inner.external_accounts()
    }

    fn oauth_states(&mut self) -> &mut dyn OAuthStateRepo {
        self.inner.oauth_states()
    }

    fn idempotency(&mut self) -> &mut dyn IdempotencyRepo {
        self.inner.idempotency()
    }

    fn audit(&mut self) -> &mut dyn davhaven_testkit::davhaven_ports::AuditRepo {
        self.inner.audit()
    }

    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        self.inner.commit().await
    }
}

#[async_trait]
impl CalendarRepo for CountingTx {
    async fn get(&mut self, id: CalendarId) -> Result<davhaven_testkit::davhaven_domain::Calendar, StoreError> {
        self.inner.calendars().get(id).await
    }

    async fn get_many(
        &mut self,
        ids: &[CalendarId],
    ) -> Result<Vec<davhaven_testkit::davhaven_domain::Calendar>, StoreError> {
        self.inner.calendars().get_many(ids).await
    }

    async fn get_by_slug(
        &mut self,
        owner: PrincipalId,
        slug: &CalendarSlug,
    ) -> Result<davhaven_testkit::davhaven_domain::Calendar, StoreError> {
        self.inner.calendars().get_by_slug(owner, slug).await
    }

    async fn list_owned(
        &mut self,
        owner: PrincipalId,
    ) -> Result<Vec<davhaven_testkit::davhaven_domain::Calendar>, StoreError> {
        self.inner.calendars().list_owned(owner).await
    }

    async fn list(
        &mut self,
        filter: &davhaven_testkit::davhaven_ports::CalendarFilter,
        page: PageReq,
    ) -> Result<davhaven_testkit::davhaven_ports::StorePage<davhaven_testkit::davhaven_domain::Calendar>, StoreError>
    {
        self.inner.calendars().list(filter, page).await
    }

    async fn visible_without_binding(
        &mut self,
        principal: PrincipalId,
    ) -> Result<Vec<davhaven_testkit::davhaven_domain::Calendar>, StoreError> {
        self.inner.calendars().visible_without_binding(principal).await
    }

    async fn access_facts(
        &mut self,
        calendar: CalendarId,
        principal: Option<PrincipalId>,
    ) -> Result<davhaven_testkit::davhaven_domain::AccessFacts, StoreError> {
        self.fact_loads.fetch_add(1, Ordering::SeqCst);
        self.inner.calendars().access_facts(calendar, principal).await
    }

    async fn access_facts_many(
        &mut self,
        calendars: &[CalendarId],
        principal: Option<PrincipalId>,
    ) -> Result<Vec<(CalendarId, davhaven_testkit::davhaven_domain::AccessFacts)>, StoreError> {
        self.fact_loads.fetch_add(1, Ordering::SeqCst);
        self.inner.calendars().access_facts_many(calendars, principal).await
    }

    async fn create(
        &mut self,
        calendar: davhaven_testkit::davhaven_domain::Calendar,
    ) -> Result<davhaven_testkit::davhaven_domain::Calendar, StoreError> {
        self.inner.calendars().create(calendar).await
    }

    async fn update(
        &mut self,
        calendar: davhaven_testkit::davhaven_domain::Calendar,
        expected_version: i64,
    ) -> Result<davhaven_testkit::davhaven_domain::Calendar, StoreError> {
        self.inner.calendars().update(calendar, expected_version).await
    }

    async fn soft_delete(&mut self, id: CalendarId, expected_version: i64) -> Result<(), StoreError> {
        self.inner.calendars().soft_delete(id, expected_version).await
    }

    async fn lock(
        &mut self,
        ids: &[CalendarId],
    ) -> Result<Vec<davhaven_testkit::davhaven_domain::Calendar>, StoreError> {
        self.inner.calendars().lock(ids).await
    }

    async fn touch(&mut self, id: CalendarId) -> Result<u64, StoreError> {
        self.inner.calendars().touch(id).await
    }

    async fn purge(&mut self, id: CalendarId) -> Result<(), StoreError> {
        self.inner.calendars().purge(id).await
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Doubles of single ports
// ---------------------------------------------------------------------------------------------------------------

/// An authenticator that accepts the secrets the test teaches it and answers `UnknownCredential` for the rest.
#[derive(Default)]
pub(crate) struct ScriptedAuth {
    known: Mutex<HashMap<String, AuthOutcome>>,
    seen: Mutex<Vec<AuthHint>>,
    failure: Mutex<Option<PortError>>,
}

impl ScriptedAuth {
    /// The secret `secret` authenticates as `authenticated`.
    pub(crate) fn accept(&self, secret: &str, authenticated: Authenticated) {
        locked(&self.known).insert(secret.to_owned(), AuthOutcome::Accepted(authenticated));
    }

    /// The secret `secret` is answered with `outcome`.
    pub(crate) fn answer(&self, secret: &str, outcome: AuthOutcome) {
        locked(&self.known).insert(secret.to_owned(), outcome);
    }

    /// Every following request fails with `error` (an authenticator whose backend is down).
    pub(crate) fn fail_with(&self, error: PortError) {
        *locked(&self.failure) = Some(error);
    }

    /// The hints of the requests the authenticator has seen.
    pub(crate) fn hints(&self) -> Vec<AuthHint> {
        locked(&self.seen).clone()
    }
}

#[async_trait]
impl Authenticator for ScriptedAuth {
    async fn authenticate(&self, credential: &PresentedCredential, hint: &AuthHint) -> Result<AuthOutcome, PortError> {
        use secrecy::ExposeSecret as _;
        locked(&self.seen).push(hint.clone());
        if let Some(error) = locked(&self.failure).clone() {
            return Err(error);
        }
        let secret = match credential {
            PresentedCredential::Basic { password, .. } => password.expose_secret(),
            PresentedCredential::Bearer(secret)
            | PresentedCredential::Feed(secret)
            | PresentedCredential::Rsvp(secret) => secret.expose_secret(),
        };
        Ok(locked(&self.known)
            .get(secret)
            .cloned()
            .unwrap_or(AuthOutcome::Rejected(
                davhaven_testkit::davhaven_ports::RejectReason::UnknownCredential,
            )))
    }
}

/// A rate limiter that counts per key and denies once the count has reached the limit, like a failure bucket.
pub(crate) struct CountingLimiter {
    limit: u32,
    counts: Mutex<HashMap<RateKey, u32>>,
    broken: Mutex<bool>,
}

impl CountingLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            counts: Mutex::new(HashMap::new()),
            broken: Mutex::new(false),
        }
    }

    /// How many units the bucket of `key` holds.
    pub(crate) fn count(&self, bucket: &'static str, key: &str) -> u32 {
        locked(&self.counts)
            .iter()
            .filter(|(candidate, _)| candidate.bucket == bucket && candidate.key.contains(key))
            .map(|(_, count)| *count)
            .sum()
    }

    /// The buckets that hold any unit, by name.
    pub(crate) fn buckets(&self) -> Vec<&'static str> {
        let mut buckets: Vec<&'static str> = locked(&self.counts)
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(key, _)| key.bucket)
            .collect();
        buckets.sort_unstable();
        buckets.dedup();
        buckets
    }

    /// Every following check fails like a limiter whose backend is down.
    pub(crate) fn break_down(&self) {
        *locked(&self.broken) = true;
    }

    /// Forgets every count (time passed).
    pub(crate) fn reset(&self) {
        locked(&self.counts).clear();
    }
}

#[async_trait]
impl RateLimiter for CountingLimiter {
    async fn check(&self, key: &RateKey, cost: u32) -> Result<RateDecision, PortError> {
        if *locked(&self.broken) {
            return Err(PortError::unavailable("the limiter is down"));
        }
        let mut counts = locked(&self.counts);
        let count = counts.entry(key.clone()).or_insert(0);
        if *count >= self.limit {
            return Ok(RateDecision::deny(std::time::Duration::from_secs(30)));
        }
        *count += cost;
        Ok(RateDecision::allow(self.limit.saturating_sub(*count)))
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

struct NoMail;

#[async_trait]
impl MailTransport for NoMail {
    async fn send(&self, _mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        Err(PortError::unsupported())
    }
}

struct NoTemplates;

#[async_trait]
impl TemplateRenderer for NoTemplates {
    async fn render(&self, _request: RenderRequest) -> Result<Rendered, PortError> {
        Err(PortError::unsupported())
    }

    fn catalog(&self) -> Vec<TemplateName> {
        Vec::new()
    }
}

struct NoHttp;

#[async_trait]
impl HttpClient for NoHttp {
    async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        Err(PortError::unsupported())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------------------------------------------

/// A tenant of the world: its id and slug.
#[derive(Debug, Clone)]
pub(crate) struct Org {
    pub(crate) id: TenantId,
    pub(crate) slug: TenantSlug,
}

/// A principal of the world: its id and immutable name.
#[derive(Debug, Clone)]
pub(crate) struct Person {
    pub(crate) id: PrincipalId,
    pub(crate) name: PrincipalName,
}

/// The services of the application on the in-memory store, with handles to the pieces the tests drive.
pub(crate) struct World {
    pub(crate) services: AppServices,
    pub(crate) core: AppCore,
    pub(crate) clock: ManualClock,
    pub(crate) ids: SeqIds,
    pub(crate) db: Arc<CountingDatabase>,
    pub(crate) faults: FaultyDatabase,
    pub(crate) auth: Arc<ScriptedAuth>,
    pub(crate) limiter: Arc<CountingLimiter>,
}

impl World {
    pub(crate) fn new() -> Self {
        Self::with(|_| {})
    }

    /// Builds the services after `adjust` changed the dependencies (the configuration, the limits).
    pub(crate) fn with(adjust: impl FnOnce(&mut AppDeps)) -> Self {
        let clock = ManualClock::default();
        let ids = SeqIds::starting_at(0x1000);
        let store: Arc<dyn Database> = if runs_on_postgres() {
            ClonedDatabase::create_blocking()
                .and_then(|clone| clone.into_database(Arc::new(clock.clone()), Arc::new(ids.clone())))
                .unwrap_or_else(|error| panic!("the PostgreSQL store of the world cannot be made: {error}"))
        } else {
            Arc::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::new(ids.clone())))
        };
        let db = CountingDatabase::new(store);
        let inner: Arc<dyn Database> = Arc::<CountingDatabase>::clone(&db);
        let faults = FaultyDatabase::new(inner);
        let auth = Arc::new(ScriptedAuth::default());
        let limiter = Arc::new(CountingLimiter::new(3));
        let limiter_port: Arc<dyn RateLimiter> = Arc::<CountingLimiter>::clone(&limiter);
        let auth_port: Arc<dyn Authenticator> = Arc::<ScriptedAuth>::clone(&auth);
        let mut deps = AppDeps {
            clock: Arc::new(clock.clone()),
            ids: Arc::new(ids.clone()),
            keyring: Arc::new(FixedKeyRing::default()),
            sealer: Arc::new(PlainSealer),
            hasher: Arc::new(FixedHasher::default()),
            database: Arc::new(faults.clone()),
            http: Arc::new(NoHttp),
            mail: Arc::new(NoMail),
            templates: Arc::new(NoTemplates),
            rate_limiter: limiter_port,
            scheduling_policy: Arc::new(NeverAuto),
            authenticators: vec![auth_port],
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
            services: build(deps.clone()),
            core: AppCore::new(deps),
            clock,
            ids,
            db,
            faults,
            auth,
            limiter,
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // Request contexts
    // -----------------------------------------------------------------------------------------------------------

    /// A fresh request id from the world's generator.
    fn request_id(&self) -> RequestId {
        RequestId::from_uuid(self.ids.new_id())
    }

    /// A fresh token id from the world's generator.
    pub(crate) fn token_id(&self) -> TokenId {
        TokenId::from_uuid(self.ids.new_id())
    }

    /// The context of a system token: not bound to a tenant, `system:tenants` only.
    pub(crate) fn system(&self) -> RequestContext {
        RequestContext {
            tenant: TenantId::from_uuid(Uuid::nil()),
            actor: Actor::SystemToken(self.token_id()),
            scopes: ScopeSet::of(&[Scope::SystemTenants]),
            channel: Channel::Api,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    /// The context of a tenant token with every scope a tenant token can have.
    pub(crate) fn admin(&self, org: &Org) -> RequestContext {
        let scopes: ScopeSet = Scope::ALL
            .iter()
            .copied()
            .filter(|scope| scope.allowed_for(TokenKind::Tenant))
            .collect();
        self.tenant_token(org, scopes)
    }

    /// The context of a tenant token with exactly `scopes`.
    pub(crate) fn tenant_token(&self, org: &Org, scopes: ScopeSet) -> RequestContext {
        RequestContext {
            tenant: org.id,
            actor: Actor::TenantToken(self.token_id()),
            scopes,
            channel: Channel::Api,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    /// A tenant token with `scopes` that exists in the store, as every authenticated token does: tokens it mints
    /// refer to it by `created_by`.
    pub(crate) async fn stored_token(&self, org: &Org, scopes: ScopeSet) -> RequestContext {
        let id = self.token_id();
        let now = self.now();
        let hashed = self.core.deps().hasher.hash(
            CredentialKind::ApiToken,
            &secrecy::SecretString::from(format!("seed-{id}")),
        );
        let mut tx = self.db.store().begin(org.id, TxMode::ReadWrite).await.unwrap();
        tx.credentials()
            .create_api_token(ApiToken {
                id,
                tenant_id: Some(org.id),
                kind: TokenKind::Tenant,
                principal_id: None,
                label: "seeded".to_owned(),
                scopes,
                prefix: id.as_uuid().simple().to_string().chars().rev().take(12).collect(),
                hash: hashed.hash,
                pepper_kid: hashed.pepper_kid,
                expires_at: None,
                created_by: None,
                allowed_origins: Vec::new(),
                last_used_at: None,
                revoked_at: None,
                created_at: now,
                updated_at: now,
                version: 1,
            })
            .await
            .unwrap();
        tx.commit().await.unwrap();
        RequestContext {
            actor: Actor::TenantToken(id),
            ..self.tenant_token(org, scopes)
        }
    }

    /// A stored tenant token with every scope a tenant token can have.
    pub(crate) async fn stored_admin(&self, org: &Org) -> RequestContext {
        let scopes: ScopeSet = Scope::ALL
            .iter()
            .copied()
            .filter(|scope| scope.allowed_for(TokenKind::Tenant))
            .collect();
        self.stored_token(org, scopes).await
    }

    /// The context of `person` on DAV (an app password): not scoped.
    pub(crate) fn dav(&self, org: &Org, person: &Person) -> RequestContext {
        RequestContext {
            tenant: org.id,
            actor: Actor::Principal(person.id),
            scopes: ScopeSet::empty(),
            channel: Channel::Dav,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    /// The context of `person` through a principal token with `scopes` on the management API.
    pub(crate) fn api(&self, org: &Org, person: &Person, scopes: &[Scope]) -> RequestContext {
        RequestContext {
            tenant: org.id,
            actor: Actor::PrincipalToken {
                principal: person.id,
                token: self.token_id(),
            },
            scopes: ScopeSet::of(scopes),
            channel: Channel::Api,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    /// The context of `person` through a principal token with MCP scopes.
    pub(crate) fn mcp(&self, org: &Org, person: &Person, scopes: &[Scope]) -> RequestContext {
        RequestContext {
            channel: Channel::Mcp,
            ..self.api(org, person, scopes)
        }
    }

    /// The context of a feed reader.
    pub(crate) fn feed(&self, org: &Org, person: &Person, token: TokenId) -> RequestContext {
        RequestContext {
            tenant: org.id,
            actor: Actor::FeedReader {
                principal: person.id,
                token,
            },
            scopes: ScopeSet::empty(),
            channel: Channel::Feed,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // Provisioning through the services
    // -----------------------------------------------------------------------------------------------------------

    /// A tenant `slug` with the default settings and the login domain `{slug}.example`.
    pub(crate) async fn org(&self, slug: &str) -> Org {
        self.org_with(slug, |_| {}).await
    }

    /// A tenant `slug` whose settings `edit` changed.
    pub(crate) async fn org_with(&self, slug: &str, edit: impl FnOnce(&mut TenantSettings)) -> Org {
        let mut settings = TenantSettings::default();
        edit(&mut settings);
        let view = self
            .tenant_write(slug, settings)
            .await
            .unwrap_or_else(|error| panic!("the tenant `{slug}` could not be created: {error:?}"));
        Org {
            id: view.id,
            slug: view.slug,
        }
    }

    /// Creates or replaces the tenant `slug` with `settings`.
    pub(crate) async fn tenant_write(&self, slug: &str, settings: TenantSettings) -> Result<TenantView, AppError> {
        let spec = TenantSpec {
            slug: TenantSlug::parse(slug).unwrap(),
            body: TenantWrite {
                display_name: format!("{slug} organisation"),
                login_domain: Some(DomainName::parse(&format!("{slug}.example")).unwrap()),
                status: None,
                settings: Some(settings),
            },
        };
        self.services
            .tenants
            .upsert(&self.system(), spec, Conditions::none())
            .await
            .map(|upserted| upserted.value)
    }

    /// A user `name` with the address `{name}@{tenant}.example`.
    pub(crate) async fn user(&self, org: &Org, name: &str) -> Person {
        self.principal(org, name, PrincipalKind::User).await
    }

    /// A principal of `kind` named `name`.
    pub(crate) async fn principal(&self, org: &Org, name: &str, kind: PrincipalKind) -> Person {
        let view = self
            .principal_write(org, name, principal_body(org, name, kind))
            .await
            .unwrap_or_else(|error| panic!("the principal `{name}` could not be created: {error:?}"));
        Person {
            id: view.id,
            name: view.name,
        }
    }

    /// Creates or replaces a principal with `body`.
    pub(crate) async fn principal_write(
        &self,
        org: &Org,
        name: &str,
        body: PrincipalWrite,
    ) -> Result<PrincipalView, AppError> {
        let spec = PrincipalSpec {
            name: PrincipalName::parse(name).unwrap(),
            body,
        };
        self.services
            .principals
            .upsert(&self.admin(org), spec, Conditions::none())
            .await
            .map(|upserted| upserted.value)
    }

    /// A group `name` with `members`.
    pub(crate) async fn group(&self, org: &Org, name: &str, members: &[&Person]) -> Person {
        let group = self.principal(org, name, PrincipalKind::Group).await;
        let names = members.iter().map(|member| member.name.clone()).collect();
        self.services
            .principals
            .set_members(&self.admin(org), &group.name, names)
            .await
            .unwrap();
        group
    }

    /// Creates a calendar of `kind` owned by `owner` through the management API.
    pub(crate) async fn calendar(&self, org: &Org, owner: &Person, slug: &str, kind: CalendarKind) -> CalendarView {
        self.services
            .calendars
            .upsert(
                &self.admin(org),
                CalendarSpec {
                    owner: owner.name.clone(),
                    slug: CalendarSlug::parse(slug).unwrap(),
                    body: CalendarWrite {
                        kind: Some(kind),
                        display_name: format!("{slug} calendar"),
                        description: None,
                        color: None,
                        sort_order: None,
                        components: None,
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the calendar `{slug}` could not be created: {error:?}"))
            .value
    }

    // -----------------------------------------------------------------------------------------------------------
    // Paths and references
    // -----------------------------------------------------------------------------------------------------------

    /// The collection `slug` in the home of `person`.
    #[expect(
        clippy::unused_self,
        reason = "the helpers of the world read as one vocabulary: `world.object(..)`"
    )]
    pub(crate) fn collection(&self, org: &Org, person: &Person, slug: &str) -> ResourcePath {
        ResourcePath::Collection {
            tenant: org.slug.clone(),
            principal: person.name.clone(),
            binding: CalendarSlug::parse(slug).unwrap(),
        }
    }

    /// The object `uri` of the collection `slug` in the home of `person`.
    #[expect(
        clippy::unused_self,
        reason = "the helpers of the world read as one vocabulary: `world.object(..)`"
    )]
    pub(crate) fn object(&self, org: &Org, person: &Person, slug: &str, uri: &str) -> ResourcePath {
        ResourcePath::Object {
            tenant: org.slug.clone(),
            principal: person.name.clone(),
            binding: CalendarSlug::parse(slug).unwrap(),
            object: ObjectUri::parse(uri).unwrap(),
        }
    }

    /// The home of `person`.
    #[expect(
        clippy::unused_self,
        reason = "the helpers of the world read as one vocabulary: `world.object(..)`"
    )]
    pub(crate) fn home(&self, org: &Org, person: &Person) -> ResourcePath {
        ResourcePath::Home {
            tenant: org.slug.clone(),
            principal: person.name.clone(),
        }
    }

    /// The management API reference of the calendar `slug` of `owner`.
    #[expect(
        clippy::unused_self,
        reason = "the helpers of the world read as one vocabulary: `world.object(..)`"
    )]
    pub(crate) fn key(&self, owner: &Person, slug: &str) -> CalendarRef {
        CalendarRef::Key {
            owner: owner.name.clone(),
            slug: CalendarSlug::parse(slug).unwrap(),
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // Inspection
    // -----------------------------------------------------------------------------------------------------------

    /// A read-only transaction on the store itself (no counters, no faults), for inspecting data.
    pub(crate) async fn read(&self, org: &Org) -> Box<dyn Tx> {
        self.db.store().begin(org.id, TxMode::ReadOnly).await.unwrap()
    }

    /// How often authorization facts were loaded since the last reset.
    pub(crate) fn fact_loads(&self) -> u32 {
        self.db.fact_loads.load(Ordering::SeqCst)
    }

    /// Starts counting fact loads from zero.
    pub(crate) fn reset_fact_loads(&self) {
        self.db.fact_loads.store(0, Ordering::SeqCst);
    }

    /// The domain events waiting in the outbox of `org`, in the order they were written.
    pub(crate) async fn events(&self, org: &Org) -> Vec<Envelope> {
        let mut tx = self.read(org).await;
        let mut records = Vec::new();
        let mut page = PageReq::first(1000);
        loop {
            let batch = tx.outbox().list(&OutboxFilter::default(), page).await.unwrap();
            records.extend(batch.items);
            match batch.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        records
            .iter()
            .filter_map(|record| match record.message() {
                Ok(davhaven_testkit::davhaven_ports::OutboxMessage::DomainEvent(envelope)) => Some(envelope),
                _ => None,
            })
            .collect()
    }

    /// The domain events of `org` of the type `kind`.
    pub(crate) async fn events_of(&self, org: &Org, kind: EventType) -> Vec<Envelope> {
        self.events(org)
            .await
            .into_iter()
            .filter(|envelope| envelope.event_type == kind)
            .collect()
    }

    /// The audit records of `org`, in the order they were written.
    pub(crate) async fn audit(&self, org: &Org) -> Vec<AuditRow> {
        let mut tx = self.read(org).await;
        let mut rows = Vec::new();
        let mut page = PageReq::first(1000);
        loop {
            let batch = tx.audit().list(&AuditFilter::default(), page).await.unwrap();
            rows.extend(batch.items);
            match batch.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        rows
    }

    /// The names of the audit actions of `org`, in order.
    pub(crate) async fn audit_actions(&self, org: &Org) -> Vec<String> {
        self.audit(org).await.into_iter().map(|row| row.action).collect()
    }

    /// The payload of a `calendar.objects_changed` event.
    pub(crate) fn objects_changed(
        envelope: &Envelope,
    ) -> &davhaven_testkit::davhaven_domain::events::ObjectsChangedPayload {
        match &envelope.data {
            EventPayload::ObjectsChanged(payload) => payload,
            other => panic!("not an objects_changed payload: {other:?}"),
        }
    }

    /// The current time of the world's clock.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

/// The body of a principal `name` of `kind` in `org`: users, resources and services get an address in the tenant's
/// domain, groups none.
pub(crate) fn principal_body(org: &Org, name: &str, kind: PrincipalKind) -> PrincipalWrite {
    PrincipalWrite {
        kind,
        display_name: name.to_owned(),
        email: (kind != PrincipalKind::Group).then(|| Email::parse(&format!("{name}@{}.example", org.slug)).unwrap()),
        addresses: Vec::new(),
        locale: None,
        timezone: None,
        external_ref: None,
        status: None,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// iCalendar text
// ---------------------------------------------------------------------------------------------------------------

/// An event `uid` titled `summary` on 2027-03-01 from 09:00 to 10:00 UTC.
pub(crate) fn event(uid: &str, summary: &str) -> EventBuilder {
    EventBuilder::event(uid)
        .summary(summary)
        .starts(When::utc(2027, 3, 1, 9, 0))
        .ends(When::utc(2027, 3, 1, 10, 0))
}

/// The text of [`event`].
pub(crate) fn ics(uid: &str, summary: &str) -> String {
    event(uid, summary).build()
}

// ---------------------------------------------------------------------------------------------------------------
// The common fixture
// ---------------------------------------------------------------------------------------------------------------

/// A world with the tenant `acme` and the users `anna` and `ben`.
pub(crate) struct Fixture {
    pub(crate) world: World,
    pub(crate) acme: Org,
    pub(crate) anna: Person,
    pub(crate) ben: Person,
}

/// Builds the common fixture.
pub(crate) async fn fixture() -> Fixture {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    Fixture { world, acme, anna, ben }
}

// ---------------------------------------------------------------------------------------------------------------
// How much work something costs
// ---------------------------------------------------------------------------------------------------------------

/// Counts the calls of the ports by operation (the `op` label of `davhaven_port_calls_total`, for example
/// `objects.query`), so that a test can say how much work a request costs (`ENGINEERING_RULES` R14). Install it with
/// `metrics::set_default_local_recorder(&calls)` for the life of a test: the recorder is local to the thread, which is
/// the only thread of a `#[tokio::test]`.
#[derive(Default, Clone)]
pub(crate) struct PortCalls {
    counts: Arc<Mutex<std::collections::BTreeMap<String, u64>>>,
    adapters: Arc<Mutex<std::collections::BTreeSet<String>>>,
}

/// One series of [`PortCalls`]: the calls of one operation.
struct CallSeries {
    op: String,
    counts: Arc<Mutex<std::collections::BTreeMap<String, u64>>>,
}

impl metrics::CounterFn for CallSeries {
    fn increment(&self, value: u64) {
        *locked(&self.counts).entry(self.op.clone()).or_insert(0) += value;
    }

    fn absolute(&self, value: u64) {
        locked(&self.counts).insert(self.op.clone(), value);
    }
}

impl PortCalls {
    /// How often the operation `op` was called since the start or the last [`reset`](Self::reset).
    pub(crate) fn count(&self, op: &str) -> u64 {
        locked(&self.counts).get(op).copied().unwrap_or(0)
    }

    /// Every operation that was called, with its count, for assertion messages.
    pub(crate) fn all(&self) -> std::collections::BTreeMap<String, u64> {
        locked(&self.counts).clone()
    }

    /// The adapters that answered a call (the `adapter` label: `memory`, `postgres`), whatever came before a reset.
    pub(crate) fn adapters(&self) -> Vec<String> {
        locked(&self.adapters).iter().cloned().collect()
    }

    /// Starts counting from zero.
    pub(crate) fn reset(&self) {
        locked(&self.counts).clear();
    }
}

impl metrics::Recorder for PortCalls {
    fn describe_counter(&self, _: metrics::KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}

    fn describe_gauge(&self, _: metrics::KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}

    fn describe_histogram(&self, _: metrics::KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}

    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        let op = key
            .labels()
            .find(|label| label.key() == "op")
            .map(|label| label.value().to_owned());
        if key.name() == davhaven_testkit::davhaven_ports::observe::CALLS_TOTAL
            && let Some(adapter) = key.labels().find(|label| label.key() == "adapter")
        {
            locked(&self.adapters).insert(adapter.value().to_owned());
        }
        match op {
            Some(op) if key.name() == davhaven_testkit::davhaven_ports::observe::CALLS_TOTAL => {
                metrics::Counter::from_arc(Arc::new(CallSeries {
                    op,
                    counts: Arc::clone(&self.counts),
                }))
            }
            _ => metrics::Counter::noop(),
        }
    }

    fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }

    fn register_histogram(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}
