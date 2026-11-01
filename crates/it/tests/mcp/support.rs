//! The world of the MCP tests: the router of `davhaven-mcp` over the real services of `davhaven-app`.
//!
//! Everything the server decides is the real thing: the store is `store-memory` (the one the store contract suite checks),
//! the cryptography is `crypto-local`, tokens are minted by the credential service and verified by `auth-local`, the
//! budgets are the memory rate limiter's, and the clock and the ids are deterministic (`ManualClock`, `SeqIds`). The few
//! doubles stand in for one port each and are never reached by an MCP call: mail, templates and outbound HTTP (an invitation
//! to an external address is enqueued in the outbox, which a test reads, and never sent).
//!
//! Tenants, principals, calendars, grants and events are provisioned through the services themselves, as the person
//! or the operator would; the assistant's side is a [`Mcp`] over the in-process transport of `davhaven-testkit`, a
//! JSON-RPC client written independently of the server.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_testkit::axum::Router;

use chrono::{DateTime, Duration, Utc};
use davhaven_testkit::Actor as WireActor;
use davhaven_testkit::davhaven_app::policy::DefaultPolicy;
use davhaven_testkit::davhaven_app::services::{
    CalendarRef, CalendarSpec, Conditions, EventWrite, GrantSpec, ObjectSelector, PrincipalSpec, PutRequest,
    ScheduleReply, TenantSpec, WritePrecondition,
};
use davhaven_testkit::davhaven_app::{AppConfig, AppDeps, AppServices, build};
use davhaven_testkit::davhaven_auth_local::authenticator::{DatabaseSource, LocalAuthenticator, LocalDeps};
use davhaven_testkit::davhaven_auth_local::config::AuthConfig;
use davhaven_testkit::davhaven_crypto_local::hasher::LocalHasher;
use davhaven_testkit::davhaven_crypto_local::keyring::{KeyMaterial, LocalCrypto, LocalKeyRing};
use davhaven_testkit::davhaven_domain::{
    Actor, CalendarId, CalendarKind, CalendarSlug, Channel, DomainName, Email, EventData, GrantAccess, Limits,
    ObjectId, ObjectUri, OutgoingMail, PrincipalId, PrincipalKind, PrincipalName, PublicUrls, RequestContext,
    RequestId, ResourcePath, Scope, ScopeSet, TenantId, TenantSettings, TenantSlug, TokenId, TokenKind,
};
use davhaven_testkit::davhaven_http::{Edge, SequentialRequestIds, Surface};
use davhaven_testkit::davhaven_mcp::config::McpConfig;
use davhaven_testkit::davhaven_ports::testing::{ManualClock, SeqIds};
use davhaven_testkit::davhaven_ports::{
    AuditFilter, AuditRow, Clock as _, Database, HttpClient, IdGenerator, MailTransport, OutboundRequest,
    OutboundResponse, OutboxFilter, PageReq, PortError, RenderRequest, Rendered, SendReceipt, TemplateName,
    TemplateRenderer, TxMode,
};
use davhaven_testkit::davhaven_ratelimit_memory::config::MemoryRateLimitConfig;
use davhaven_testkit::davhaven_ratelimit_memory::memory::MemoryRateLimiter;
use davhaven_testkit::davhaven_store_memory::database::MemoryDatabase;
use davhaven_testkit::davhaven_wire::ProblemCode;
use davhaven_testkit::davhaven_wire::mcp::PROBLEM_META_KEY;
use davhaven_testkit::davhaven_wire::{
    ApiTokenCreate, ApiTokenCreated, CalendarView, CalendarWrite, EventView, GrantWrite, PrincipalView, PrincipalWrite,
    TenantView, TenantWrite,
};
use davhaven_testkit::handles::{McpHandle, mcp_message};
use davhaven_testkit::transport::{InProcess, TestResponse, Transport};
use secrecy::SecretString;
use serde_json::{Value, json};
use url::Url;

// ---------------------------------------------------------------------------------------------------------------
// Doubles of ports that no MCP call reaches
// ---------------------------------------------------------------------------------------------------------------

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

/// A tenant of the world.
#[derive(Debug, Clone)]
pub(crate) struct Org {
    pub(crate) id: TenantId,
    pub(crate) slug: TenantSlug,
}

/// A principal of the world.
#[derive(Debug, Clone)]
pub(crate) struct Person {
    pub(crate) id: PrincipalId,
    pub(crate) name: PrincipalName,
    /// The primary calendar user address, as it appears in iCalendar text.
    pub(crate) mailto: String,
}

/// The services of the application, the router of the MCP server in front of them and the handles to the pieces a test
/// drives.
pub(crate) struct World {
    pub(crate) services: AppServices,
    pub(crate) clock: ManualClock,
    pub(crate) db: Arc<MemoryDatabase>,
    pub(crate) router: Router,
    ids: SeqIds,
}

/// The default tenant settings with the MCP switch set (the settings are `non_exhaustive`: fields are assigned).
fn settings_with_mcp(on: bool) -> TenantSettings {
    let mut settings = TenantSettings::default();
    enable_mcp(&mut settings, on);
    settings
}

fn enable_mcp(settings: &mut TenantSettings, on: bool) {
    settings.mcp_enabled = on;
}

/// The key material of the tests (one key, which signs).
fn key_material() -> KeyMaterial {
    KeyMaterial::new(
        "2027-01",
        vec![(
            "2027-01".to_owned(),
            SecretString::from("0123456789abcdef0123456789abcdef-mcp-tests"),
        )],
    )
    .unwrap()
}

impl World {
    /// The application with the default limiter allowances and the default `[mcp]` configuration.
    pub(crate) fn new() -> Self {
        Self::with(MemoryRateLimitConfig::default(), &McpConfig::default())
    }

    /// The application with these limiter allowances and this `[mcp]` configuration.
    pub(crate) fn with(rates: MemoryRateLimitConfig, mcp: &McpConfig) -> Self {
        let clock = ManualClock::default();
        let ids = SeqIds::starting_at(0x1000);
        let ids_port: Arc<dyn IdGenerator> = Arc::new(ids.clone());
        let db = Arc::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::clone(&ids_port)));
        let database: Arc<dyn Database> = Arc::<MemoryDatabase>::clone(&db);
        let crypto = LocalCrypto::new(&key_material(), Arc::clone(&ids_port));
        let authenticator = LocalAuthenticator::new(
            LocalDeps {
                source: Arc::new(DatabaseSource::new(Arc::clone(&database))),
                hasher: Arc::<LocalHasher>::clone(&crypto.hasher),
                keyring: Arc::<LocalKeyRing>::clone(&crypto.keyring),
                clock: Arc::new(clock.clone()),
                ids: Arc::clone(&ids_port),
            },
            &AuthConfig::default(),
        );
        let deps = AppDeps {
            clock: Arc::new(clock.clone()),
            ids: Arc::clone(&ids_port),
            keyring: crypto.keyring,
            sealer: crypto.sealer,
            hasher: crypto.hasher,
            database,
            http: Arc::new(NoHttp),
            mail: Arc::new(NoMail),
            templates: Arc::new(NoTemplates),
            rate_limiter: Arc::new(MemoryRateLimiter::new(Arc::new(clock.clone()), rates)),
            scheduling_policy: Arc::new(DefaultPolicy),
            authenticators: vec![Arc::new(authenticator)],
            event_sinks: Vec::new(),
            outbox_handlers: Vec::new(),
            providers: Vec::new(),
            content_scanners: Vec::new(),
            profile_signer: None,
            urls: PublicUrls::new(Url::parse("https://cal.example.org").unwrap()).unwrap(),
            limits: Limits::default(),
            config: AppConfig::default(),
        };
        let services = build(deps);
        let edge = Edge::new(Surface::Mcp, Arc::new(SequentialRequestIds::new()));
        let router = davhaven_testkit::davhaven_mcp::router(&services, mcp, &edge);
        Self {
            services,
            clock,
            db,
            router,
            ids,
        }
    }

    /// The present of the world's clock.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    // -----------------------------------------------------------------------------------------------------------
    // Request contexts of the people who provision the world (not of the assistant)
    // -----------------------------------------------------------------------------------------------------------

    fn request_id(&self) -> RequestId {
        RequestId::from_uuid(self.ids.new_id())
    }

    fn context(&self, tenant: TenantId, actor: Actor, scopes: ScopeSet, channel: Channel) -> RequestContext {
        RequestContext {
            tenant,
            actor,
            scopes,
            channel,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    /// The operator of the server: it may do what the application does for itself (mint tokens).
    fn internal(&self, org: &Org) -> RequestContext {
        RequestContext::internal(org.id, self.request_id())
    }

    /// A system token: it creates tenants.
    fn system(&self) -> RequestContext {
        self.context(
            TenantId::from_uuid(uuid::Uuid::nil()),
            Actor::SystemToken(TokenId::from_uuid(self.ids.new_id())),
            ScopeSet::of(&[Scope::SystemTenants]),
            Channel::Api,
        )
    }

    /// A tenant administrator with every scope a tenant token can have.
    fn admin(&self, org: &Org) -> RequestContext {
        let scopes: ScopeSet = Scope::ALL
            .iter()
            .copied()
            .filter(|scope| scope.allowed_for(TokenKind::Tenant))
            .collect();
        self.context(
            org.id,
            Actor::TenantToken(TokenId::from_uuid(self.ids.new_id())),
            scopes,
            Channel::Api,
        )
    }

    /// A tenant token with exactly `scopes`, stored like the one a deployment holds: a token that mints is the creator of
    /// what it mints, and the store keeps that reference. It acts through the services; it does not authenticate over HTTP.
    pub(crate) async fn admin_with(&self, org: &Org, scopes: &[Scope]) -> RequestContext {
        self.admin_until(org, scopes, None).await
    }

    /// [`World::admin_with`] for a token that expires at `expires_at` (a minted token never outlives its minter).
    pub(crate) async fn admin_until(
        &self,
        org: &Org,
        scopes: &[Scope],
        expires_at: Option<DateTime<Utc>>,
    ) -> RequestContext {
        let created = self
            .services
            .credentials
            .create_api_token(
                &self.internal(org),
                ApiTokenCreate {
                    kind: TokenKind::Tenant,
                    principal: None,
                    label: "provisioning".to_owned(),
                    scopes: ScopeSet::of(scopes),
                    expires_at,
                    allowed_origins: Vec::new(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("a tenant token could not be minted: {error:?}"));
        self.context(
            org.id,
            Actor::TenantToken(created.token.id),
            ScopeSet::of(scopes),
            Channel::Api,
        )
    }

    /// `person` on the management API with `scopes`: it writes the events a test starts from.
    pub(crate) fn api(&self, org: &Org, person: &Person, scopes: &[Scope]) -> RequestContext {
        self.context(
            org.id,
            Actor::PrincipalToken {
                principal: person.id,
                token: TokenId::from_uuid(self.ids.new_id()),
            },
            ScopeSet::of(scopes),
            Channel::Api,
        )
    }

    /// `person` on DAV: the calendar client that creates meetings and invitations.
    pub(crate) fn dav(&self, org: &Org, person: &Person) -> RequestContext {
        self.context(org.id, Actor::Principal(person.id), ScopeSet::empty(), Channel::Dav)
    }

    // -----------------------------------------------------------------------------------------------------------
    // Provisioning through the services
    // -----------------------------------------------------------------------------------------------------------

    /// A tenant `slug`, with MCP switched on or off (it is off by default).
    pub(crate) async fn org(&self, slug: &str, mcp_enabled: bool) -> Org {
        let view = self.tenant_write(slug, mcp_enabled).await;
        Org {
            id: view.id,
            slug: view.slug,
        }
    }

    /// Creates or replaces the tenant `slug` with MCP switched on or off.
    pub(crate) async fn tenant_write(&self, slug: &str, mcp_enabled: bool) -> TenantView {
        let settings = settings_with_mcp(mcp_enabled);
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
            .unwrap_or_else(|error| panic!("the tenant `{slug}` could not be written: {error:?}"))
            .value
    }

    /// A user `name` with the address `{name}@{tenant}.example` and a personal calendar.
    pub(crate) async fn user(&self, org: &Org, name: &str) -> Person {
        let email = format!("{name}@{}.example", org.slug);
        let body = PrincipalWrite {
            kind: PrincipalKind::User,
            display_name: name.to_owned(),
            email: Some(Email::parse(&email).unwrap()),
            addresses: Vec::new(),
            locale: None,
            timezone: None,
            external_ref: None,
            status: None,
        };
        let view: PrincipalView = self
            .services
            .principals
            .upsert(
                &self.admin(org),
                PrincipalSpec {
                    name: PrincipalName::parse(name).unwrap(),
                    body,
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the principal `{name}` could not be created: {error:?}"))
            .value;
        Person {
            id: view.id,
            name: view.name,
            mailto: format!("mailto:{email}"),
        }
    }

    /// A service principal `name` (the machine identity of an assistant or an integration) with the address
    /// `{name}@{tenant}.example`.
    pub(crate) async fn service(&self, org: &Org, name: &str) -> Person {
        self.principal(org, name, PrincipalKind::Service).await
    }

    /// A resource `name` (a room or a piece of equipment) with the address `{name}@{tenant}.example`.
    pub(crate) async fn resource(&self, org: &Org, name: &str) -> Person {
        self.principal(org, name, PrincipalKind::Resource).await
    }

    /// A group `name` with `members`: the owner of group calendars. A group has no address.
    pub(crate) async fn group(&self, org: &Org, name: &str, members: &[&Person]) -> Person {
        let body = PrincipalWrite {
            kind: PrincipalKind::Group,
            display_name: name.to_owned(),
            email: None,
            addresses: Vec::new(),
            locale: None,
            timezone: None,
            external_ref: None,
            status: None,
        };
        let view: PrincipalView = self
            .services
            .principals
            .upsert(
                &self.admin(org),
                PrincipalSpec {
                    name: PrincipalName::parse(name).unwrap(),
                    body,
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the group `{name}` could not be created: {error:?}"))
            .value;
        let names = members.iter().map(|member| member.name.clone()).collect();
        self.services
            .principals
            .set_members(&self.admin(org), &view.name, names)
            .await
            .unwrap_or_else(|error| panic!("the members of `{name}` could not be set: {error:?}"));
        Person {
            id: view.id,
            name: view.name,
            mailto: String::new(),
        }
    }

    /// A principal of `kind` named `name` with the address `{name}@{tenant}.example`.
    async fn principal(&self, org: &Org, name: &str, kind: PrincipalKind) -> Person {
        let email = format!("{name}@{}.example", org.slug);
        let body = PrincipalWrite {
            kind,
            display_name: name.to_owned(),
            email: Some(Email::parse(&email).unwrap()),
            addresses: Vec::new(),
            locale: None,
            timezone: None,
            external_ref: None,
            status: None,
        };
        let view: PrincipalView = self
            .services
            .principals
            .upsert(
                &self.admin(org),
                PrincipalSpec {
                    name: PrincipalName::parse(name).unwrap(),
                    body,
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the principal `{name}` could not be created: {error:?}"))
            .value;
        Person {
            id: view.id,
            name: view.name,
            mailto: format!("mailto:{email}"),
        }
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
                        display_name: slug.to_owned(),
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

    /// Shares the calendar `slug` of `owner` with `grantee` at `access`.
    pub(crate) async fn grant(&self, org: &Org, owner: &Person, slug: &str, grantee: &Person, access: GrantAccess) {
        self.services
            .sharing
            .put_grant(
                &self.admin(org),
                GrantSpec {
                    calendar: self.key(owner, slug),
                    grantee: grantee.name.clone(),
                    body: GrantWrite {
                        access,
                        required: false,
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the calendar `{slug}` could not be shared: {error:?}"));
    }

    /// The management API reference of the calendar `slug` of `owner`.
    #[expect(
        clippy::unused_self,
        reason = "the helpers of the world read as one vocabulary: `world.key(..)`"
    )]
    pub(crate) fn key(&self, owner: &Person, slug: &str) -> CalendarRef {
        CalendarRef::Key {
            owner: owner.name.clone(),
            slug: CalendarSlug::parse(slug).unwrap(),
        }
    }

    /// Writes an event to the calendar `slug` of `owner` as the owner, through the management API, under the key
    /// `key` (an integration's upsert by key).
    pub(crate) async fn event(
        &self,
        org: &Org,
        owner: &Person,
        slug: &str,
        key: &str,
        data: EventData,
    ) -> (EventView, CalendarId) {
        let ctx = self.api(org, owner, &[Scope::EventsWrite, Scope::EventsRead]);
        let outcome = self
            .services
            .objects
            .put_event(
                &ctx,
                &self.key(owner, slug),
                EventWrite {
                    target: Some(ObjectSelector::Key(
                        davhaven_testkit::davhaven_domain::ExternalKey::parse(key).unwrap(),
                    )),
                    event: EventView::from_data(data),
                    notify_attendees: false,
                    if_match: None,
                    scope: davhaven_testkit::davhaven_wire::mcp::ChangeScope::All,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("the event `{key}` could not be written: {error:?}"));
        let calendar = outcome.event.calendar_id.unwrap();
        (outcome.event, calendar)
    }

    /// A DAV `PUT` of iCalendar text into the personal calendar of `person`, as `as_person` (a meeting with
    /// attendees schedules: the invitation reaches the attendees' calendars).
    pub(crate) async fn put_ics(&self, org: &Org, as_person: &Person, owner: &Person, uri: &str, text: &str) {
        let path = ResourcePath::Object {
            tenant: org.slug.clone(),
            principal: owner.name.clone(),
            binding: CalendarSlug::parse("personal").unwrap(),
            object: ObjectUri::parse(uri).unwrap(),
        };
        self.services
            .objects
            .put(
                &self.dav(org, as_person),
                PutRequest {
                    path,
                    body: text.to_owned(),
                    content_type: Some("text/calendar".to_owned()),
                    preconditions: WritePrecondition::none(),
                    schedule_reply: ScheduleReply::Send,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("`{uri}` could not be written: {error:?}"));
    }

    /// A token of `person` with `scopes` and an expiry in 30 days, minted by the credential service: the secret the
    /// assistant presents.
    pub(crate) async fn token(&self, org: &Org, person: &Person, scopes: &[Scope]) -> String {
        self.mint(org, person, scopes, self.clock.now() + Duration::days(30))
            .await
            .secret
    }

    /// A token of `person` with `scopes` and an expiry of the test's choosing; the secret and the id of the token.
    pub(crate) async fn mint(
        &self,
        org: &Org,
        person: &Person,
        scopes: &[Scope],
        expires_at: DateTime<Utc>,
    ) -> ApiTokenCreated {
        self.services
            .credentials
            .create_api_token(
                &self.internal(org),
                ApiTokenCreate {
                    kind: TokenKind::Principal,
                    principal: Some(person.name.clone()),
                    label: "assistant".to_owned(),
                    scopes: ScopeSet::of(scopes),
                    expires_at: Some(expires_at),
                    allowed_origins: Vec::new(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("a token of `{}` could not be minted: {error:?}", person.name))
    }

    /// A token of `person` with `scopes`, minted the way a deployment does it **through the management API**: by a
    /// tenant token (every scope a tenant token can hold, which includes `credentials:write` and none of the `mcp:*`
    /// scopes), not by the operator. The result is the answer of the credential service, which may refuse.
    pub(crate) async fn mint_with_a_tenant_token(
        &self,
        org: &Org,
        person: &Person,
        scopes: &[Scope],
    ) -> Result<ApiTokenCreated, davhaven_testkit::davhaven_app::AppError> {
        let every_scope: Vec<Scope> = Scope::ALL
            .into_iter()
            .filter(|scope| scope.allowed_for(TokenKind::Tenant))
            .collect();
        let minter = self.admin_with(org, &every_scope).await;
        self.services
            .credentials
            .create_api_token(
                &minter,
                ApiTokenCreate {
                    kind: TokenKind::Principal,
                    principal: Some(person.name.clone()),
                    label: "assistant".to_owned(),
                    scopes: ScopeSet::of(scopes),
                    expires_at: Some(self.now() + Duration::days(30)),
                    allowed_origins: Vec::new(),
                },
            )
            .await
    }

    /// Whether minting a token of `person` with MCP scopes is refused because the tenant has not switched MCP on
    /// (`feature-not-enabled`).
    pub(crate) async fn token_refused(&self, org: &Org, person: &Person) -> bool {
        let attempt = self
            .services
            .credentials
            .create_api_token(
                &self.internal(org),
                ApiTokenCreate {
                    kind: TokenKind::Principal,
                    principal: Some(person.name.clone()),
                    label: "assistant".to_owned(),
                    scopes: ScopeSet::of(&[Scope::McpRead]),
                    expires_at: Some(self.now() + Duration::days(30)),
                    allowed_origins: Vec::new(),
                },
            )
            .await;
        match attempt {
            Err(error) => ProblemCode::from_error(error.kind(), error.precondition()).code() == "feature-not-enabled",
            Ok(_) => false,
        }
    }

    /// A tenant token (it administers the tenant and acts as nobody) with `scopes`.
    pub(crate) async fn tenant_token(&self, org: &Org, scopes: &[Scope]) -> String {
        self.services
            .credentials
            .create_api_token(
                &self.internal(org),
                ApiTokenCreate {
                    kind: TokenKind::Tenant,
                    principal: None,
                    label: "operator".to_owned(),
                    scopes: ScopeSet::of(scopes),
                    expires_at: None,
                    allowed_origins: Vec::new(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("a tenant token could not be minted: {error:?}"))
            .secret
    }

    /// Revokes the token with this id.
    pub(crate) async fn revoke(&self, org: &Org, token: TokenId) {
        self.services
            .credentials
            .revoke_api_token(&self.admin(org), token)
            .await
            .unwrap_or_else(|error| panic!("the token could not be revoked: {error:?}"));
    }

    // -----------------------------------------------------------------------------------------------------------
    // Inspection
    // -----------------------------------------------------------------------------------------------------------

    /// The audit records of `org`, in the order they were written.
    pub(crate) async fn audit(&self, org: &Org) -> Vec<AuditRow> {
        let mut tx = self.db.begin(org.id, TxMode::ReadOnly).await.unwrap();
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

    /// How many outbox records of `kind` (`imip`, `domain_event`, ...) `org` has.
    pub(crate) async fn outbox_count(&self, org: &Org, kind: &str) -> usize {
        let mut tx = self.db.begin(org.id, TxMode::ReadOnly).await.unwrap();
        let mut count = 0;
        let mut page = PageReq::first(1000);
        loop {
            let batch = tx
                .outbox()
                .list(
                    &OutboxFilter {
                        kind: Some(kind.to_owned()),
                        ..OutboxFilter::default()
                    },
                    page,
                )
                .await
                .unwrap();
            count += batch.items.len();
            match batch.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        count
    }

    /// The id of the event the owner wrote under `key` into the calendar `slug` (the one `get_event` and `update_event` take).
    pub(crate) async fn event_id_of(&self, org: &Org, owner: &Person, slug: &str, key: &str) -> ObjectId {
        let ctx = self.api(org, owner, &[Scope::EventsRead]);
        self.services
            .objects
            .get_by_key(
                &ctx,
                &self.key(owner, slug),
                &davhaven_testkit::davhaven_domain::ExternalKey::parse(key).unwrap(),
            )
            .await
            .unwrap()
            .id
            .unwrap()
    }

    // -----------------------------------------------------------------------------------------------------------
    // The assistant
    // -----------------------------------------------------------------------------------------------------------

    /// A client of the MCP endpoint that presents `secret` as a bearer token.
    pub(crate) fn mcp(&self, secret: &str) -> Mcp {
        self.mcp_as(WireActor::bearer(secret))
    }

    /// A client of the MCP endpoint that presents whatever `actor` presents (nothing, for an anonymous one).
    pub(crate) fn mcp_as(&self, actor: WireActor) -> Mcp {
        let transport: Arc<dyn Transport> = Arc::new(InProcess::new(self.router.clone()));
        Mcp {
            handle: McpHandle::new(transport, actor),
        }
    }
}

/// An MCP client over the in-process transport, as one token.
pub(crate) struct Mcp {
    handle: McpHandle,
}

impl Mcp {
    /// The HTTP response to a JSON-RPC request.
    pub(crate) async fn post(&self, method: &str, params: &Value) -> TestResponse {
        self.handle.rpc(method, params).unwrap().send().await.unwrap()
    }

    /// The JSON-RPC response object to a request that the server answered with 200.
    pub(crate) async fn rpc(&self, method: &str, params: &Value) -> Value {
        let response = self.post(method, params).await;
        assert_eq!(response.status, 200, "{method}: {}", response.text());
        mcp_message(&response).unwrap()
    }

    /// The `result` of `tools/call`, which may be a failed tool result.
    pub(crate) async fn call(&self, tool: &str, arguments: Value) -> Value {
        let response = self
            .rpc("tools/call", &json!({"name": tool, "arguments": arguments}))
            .await;
        assert!(
            response.get("error").is_none(),
            "{tool} failed as a protocol error: {response}"
        );
        response["result"].clone()
    }

    /// The structured content of a call that must succeed.
    pub(crate) async fn ok(&self, tool: &str, arguments: Value) -> Value {
        let result = self.call(tool, arguments).await;
        assert_eq!(result["isError"], false, "{tool}: {result}");
        result["structuredContent"].clone()
    }

    /// The problem document of a call that must fail as a tool result.
    pub(crate) async fn fails(&self, tool: &str, arguments: Value) -> Value {
        let result = self.call(tool, arguments).await;
        assert_eq!(result["isError"], true, "{tool}: {result}");
        assert!(result.get("structuredContent").is_none(), "{tool}: {result}");
        let problem = result["_meta"][PROBLEM_META_KEY].clone();
        assert!(problem["code"].is_string(), "{tool}: {result}");
        problem
    }

    /// The `result` of a failed call as a whole (text and `_meta`).
    pub(crate) async fn failed_result(&self, tool: &str, arguments: Value) -> Value {
        let result = self.call(tool, arguments).await;
        assert_eq!(result["isError"], true, "{tool}: {result}");
        result
    }
}

/// An event of `summary` on 2027-03-02 from 09:00 to 10:00 UTC.
pub(crate) fn data(summary: &str) -> EventData {
    EventData {
        summary: Some(summary.to_owned()),
        start: Some(serde_json::from_value(json!({"date_time": "2027-03-02T09:00:00Z"})).unwrap()),
        end: Some(serde_json::from_value(json!({"date_time": "2027-03-02T10:00:00Z"})).unwrap()),
        ..EventData::default()
    }
}

/// The range of the tests' events as the arguments of `list_events`.
pub(crate) fn march() -> Value {
    json!({"start": "2027-03-01T00:00:00Z", "end": "2027-03-08T00:00:00Z"})
}
