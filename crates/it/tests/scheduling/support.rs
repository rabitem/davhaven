//! The world of the scheduling tests: the real application on the in-memory store, with the real template renderer
//! and the capturing mail transport, a deterministic clock and ids, and the default scheduling policy.
//!
//! The services are built with `davhaven_app::build`, the way the server builds them, so the tests exercise the
//! wiring of the scheduler too. The outbox dispatcher is built with the handlers of the application (`imip`,
//! `domain_event` and `internal_delivery`) and runs when a test calls
//! [`World::run_outbox`]; the mail it sends is captured by the transport of the memory adapter. Tenants,
//! principals and calendars are provisioned through the services themselves.

use std::fmt::Write as _;
use std::sync::Arc;

use async_trait::async_trait;
use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::outbox::{OutboxDispatcher, new_dispatcher};
use davhaven_testkit::davhaven_app::policy::DefaultPolicy;
use davhaven_testkit::davhaven_app::services::{
    AppServices, CalendarRef, CalendarSpec, Conditions, DeleteOutcome, DeleteRequest, EventWrite, GrantSpec,
    ObjectSelector, PrincipalSpec, PutOutcome, PutRequest, ScheduleReply, TenantSpec, WritePrecondition,
};
use davhaven_testkit::davhaven_app::{AppConfig, AppCore, AppDeps, build};
use davhaven_testkit::davhaven_domain::{
    Actor, CalendarKind, CalendarSlug, CalendarUserAddress, Channel, CredentialRef, DomainName, Email, Envelope,
    EventPayload, EventType, ExternalKey, GrantAccess, InboxItem, Limits, ObjectId, ObjectUri, OutgoingMail, PartStat,
    PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus, PublicUrls, RequestContext, RequestId, ResourcePath,
    RsvpToken, Scope, ScopeSet, StoredObject, TenantId, TenantSettings, TenantSlug, TokenId,
};
use davhaven_testkit::davhaven_fixtures::event::{Attendee, EventBuilder, Organizer, When};
use davhaven_testkit::davhaven_mail_memory::config::MemoryMailConfig;
use davhaven_testkit::davhaven_mail_memory::transport::{CapturedMail, MemoryMailTransport};
use davhaven_testkit::davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
use davhaven_testkit::davhaven_ports::{
    AuthHint, AuthOutcome, Authenticator, Database, HttpClient, IdGenerator as _, OutboundRequest, OutboundResponse,
    OutboxFilter, OutboxMessage, OutboxRecord, PageReq, PortError, PresentedCredential, RateDecision, RateKey,
    RateLimiter, Tx, TxMode, WorkReport, Worker,
};
use davhaven_testkit::davhaven_store_memory::database::MemoryDatabase;
use davhaven_testkit::davhaven_templates::config::{MiniJinjaConfig, TemplatesConfig};
use davhaven_testkit::davhaven_templates::renderer::MiniJinjaRenderer;
use davhaven_testkit::davhaven_wire::mcp::ChangeScope;
use davhaven_testkit::davhaven_wire::{
    AuthVerdict, CalendarWrite, EventView, GrantWrite, InboundItipRequest, InboundItipResponse, PrincipalWrite,
    TenantWrite,
};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

/// The domain mail of the tenants is sent from.
pub(crate) const SENDER_DOMAIN: &str = "mail.example.org";

struct AllowAll;

#[async_trait]
impl RateLimiter for AllowAll {
    async fn check(&self, _key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
        Ok(RateDecision::allow(u32::MAX))
    }
}

struct NoHttp;

#[async_trait]
impl HttpClient for NoHttp {
    async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        Err(PortError::unsupported())
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
    /// The primary mail address (empty for groups).
    pub(crate) email: String,
}

impl Person {
    /// The primary calendar user address, as it appears in iCalendar text.
    pub(crate) fn mailto(&self) -> String {
        format!("mailto:{}", self.email)
    }

    /// The primary calendar user address as a value.
    pub(crate) fn address(&self) -> CalendarUserAddress {
        CalendarUserAddress::parse(&self.mailto()).unwrap()
    }
}

/// The application and everything around it.
pub(crate) struct World {
    pub(crate) services: AppServices,
    pub(crate) core: AppCore,
    pub(crate) clock: ManualClock,
    pub(crate) ids: SeqIds,
    pub(crate) db: Arc<MemoryDatabase>,
    pub(crate) mail: Arc<MemoryMailTransport>,
    dispatcher: OutboxDispatcher,
}

impl World {
    pub(crate) fn new() -> Self {
        Self::with(|_| {})
    }

    /// The application with the inbound iTIP endpoint switched on (it is off by default).
    pub(crate) fn with_inbound() -> Self {
        Self::with(|deps| deps.config.scheduling.inbound_itip.enabled = true)
    }

    /// Builds the application after `adjust` changed the dependencies (the configuration, the policy).
    pub(crate) fn with(adjust: impl FnOnce(&mut AppDeps)) -> Self {
        let clock = ManualClock::default();
        let ids = SeqIds::starting_at(0x1000);
        let db = Arc::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::new(ids.clone())));
        let mail = Arc::new(MemoryMailTransport::new(
            Arc::new(clock.clone()),
            &MemoryMailConfig::default(),
        ));
        // The year and the date of the themes follow the clock of the world, not the day the test runs.
        let renderer = MiniJinjaRenderer::new(
            &TemplatesConfig::default(),
            &MiniJinjaConfig::default(),
            Arc::new(clock.clone()),
        )
        .unwrap();
        let database: Arc<dyn Database> = Arc::<MemoryDatabase>::clone(&db);
        let mut deps = AppDeps {
            clock: Arc::new(clock.clone()),
            ids: Arc::new(ids.clone()),
            keyring: Arc::new(FixedKeyRing::default()),
            sealer: Arc::new(PlainSealer),
            hasher: Arc::new(FixedHasher::default()),
            database,
            http: Arc::new(NoHttp),
            mail: Arc::<MemoryMailTransport>::clone(&mail),
            templates: Arc::new(renderer),
            rate_limiter: Arc::new(AllowAll),
            scheduling_policy: Arc::new(DefaultPolicy),
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
        let core = AppCore::new(deps.clone());
        let dispatcher = new_dispatcher(&core, Vec::new());
        Self {
            services: build(deps),
            core,
            clock,
            ids,
            db,
            mail,
            dispatcher,
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // Request contexts
    // -----------------------------------------------------------------------------------------------------------

    fn request_id(&self) -> RequestId {
        RequestId::from_uuid(self.ids.new_id())
    }

    fn token_id(&self) -> TokenId {
        TokenId::from_uuid(self.ids.new_id())
    }

    /// The context of a system token (tenant provisioning).
    fn system(&self) -> RequestContext {
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

    /// The context of a tenant administrator: the trusted internal channel.
    pub(crate) fn admin(&self, org: &Org) -> RequestContext {
        RequestContext::internal(org.id, self.request_id())
    }

    /// A tenant token with `scopes` on the management API.
    pub(crate) fn tenant_token(&self, org: &Org, scopes: &[Scope]) -> RequestContext {
        RequestContext {
            tenant: org.id,
            actor: Actor::TenantToken(self.token_id()),
            scopes: ScopeSet::of(scopes),
            channel: Channel::Api,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    /// `person` in a CalDAV client (an app password): not scoped.
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

    /// `person` through a principal token with `scopes` on the management API.
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

    /// `person` through a principal token with `scopes` on MCP.
    pub(crate) fn mcp(&self, org: &Org, person: &Person, scopes: &[Scope]) -> RequestContext {
        RequestContext {
            channel: Channel::Mcp,
            ..self.api(org, person, scopes)
        }
    }

    /// A caller of the inbound iTIP endpoint (a tenant token with `itip:inbound`). The gateway is one token that
    /// forwards all of its mail, so every call of this method is the same token.
    pub(crate) fn gateway(&self, org: &Org) -> RequestContext {
        RequestContext {
            actor: Actor::TenantToken(TokenId::from_uuid(Uuid::from_u128(0x6a7e_0001))),
            ..self.tenant_token(org, &[Scope::ItipInbound])
        }
    }

    /// The context an RSVP link produces: the invitation, the attendee and the id of the token row.
    pub(crate) fn rsvp(&self, org: &Org, token: &RsvpToken) -> RequestContext {
        RequestContext {
            tenant: org.id,
            actor: Actor::RsvpAttendee {
                object: token.object_id,
                address: token.attendee_address.clone(),
            },
            scopes: ScopeSet::empty(),
            channel: Channel::Rsvp,
            credential: Some(CredentialRef::rsvp_token(token.id)),
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // Provisioning
    // -----------------------------------------------------------------------------------------------------------

    /// A tenant `slug` with the default settings, sending mail from [`SENDER_DOMAIN`].
    pub(crate) async fn org(&self, slug: &str) -> Org {
        self.org_with(slug, |_| {}).await
    }

    /// A tenant `slug` whose settings `edit` changed.
    pub(crate) async fn org_with(&self, slug: &str, edit: impl FnOnce(&mut TenantSettings)) -> Org {
        let mut settings = TenantSettings::default();
        settings.sender.domain = Some(DomainName::parse(SENDER_DOMAIN).unwrap());
        edit(&mut settings);
        let view = self
            .services
            .tenants
            .upsert(
                &self.system(),
                TenantSpec {
                    slug: TenantSlug::parse(slug).unwrap(),
                    body: TenantWrite {
                        display_name: format!("{slug} organisation"),
                        login_domain: Some(DomainName::parse(&format!("{slug}.example")).unwrap()),
                        status: None,
                        settings: Some(settings),
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the tenant `{slug}` could not be created: {error:?}"))
            .value;
        Org {
            id: view.id,
            slug: view.slug,
        }
    }

    /// A user `name` with the address `{name}@{tenant}.example` and a personal calendar.
    pub(crate) async fn user(&self, org: &Org, name: &str) -> Person {
        self.principal(org, name, PrincipalKind::User).await
    }

    /// A resource `name` (a room) with a calendar of its own, `room`.
    pub(crate) async fn resource(&self, org: &Org, name: &str) -> Person {
        let room = self.principal(org, name, PrincipalKind::Resource).await;
        self.calendar(org, &room, "room", CalendarKind::User).await;
        room
    }

    /// A principal of `kind` named `name`; groups have no address.
    pub(crate) async fn principal(&self, org: &Org, name: &str, kind: PrincipalKind) -> Person {
        let email = (kind != PrincipalKind::Group).then(|| format!("{name}@{}.example", org.slug));
        let view = self
            .services
            .principals
            .upsert(
                &self.admin(org),
                PrincipalSpec {
                    name: PrincipalName::parse(name).unwrap(),
                    body: PrincipalWrite {
                        kind,
                        display_name: name.to_owned(),
                        email: email.as_deref().map(|email| Email::parse(email).unwrap()),
                        addresses: Vec::new(),
                        locale: None,
                        timezone: None,
                        external_ref: None,
                        status: None,
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the principal `{name}` could not be created: {error:?}"))
            .value;
        Person {
            id: view.id,
            name: view.name,
            email: email.unwrap_or_default(),
        }
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

    /// Suspends the user `person`: the principal stays, it can no longer act.
    pub(crate) async fn suspend(&self, org: &Org, person: &Person) {
        self.services
            .principals
            .upsert(
                &self.admin(org),
                PrincipalSpec {
                    name: person.name.clone(),
                    body: PrincipalWrite {
                        kind: PrincipalKind::User,
                        display_name: person.name.to_string(),
                        email: Some(Email::parse(&person.email).unwrap()),
                        addresses: Vec::new(),
                        locale: None,
                        timezone: None,
                        external_ref: None,
                        status: Some(PrincipalStatus::Suspended),
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the principal `{}` could not be suspended: {error:?}", person.name));
    }

    /// Gives `grantee` `access` to the calendar `slug` of `owner` through the management API.
    pub(crate) async fn grant(&self, org: &Org, owner: &Person, slug: &str, grantee: &Person, access: GrantAccess) {
        self.services
            .sharing
            .put_grant(
                &self.admin(org),
                GrantSpec {
                    calendar: self.collection(org, owner, slug),
                    grantee: grantee.name.clone(),
                    body: GrantWrite {
                        access,
                        required: false,
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("the grant to `{}` could not be made: {error:?}", grantee.name));
    }

    /// A calendar of `kind` owned by `owner`.
    pub(crate) async fn calendar(&self, org: &Org, owner: &Person, slug: &str, kind: CalendarKind) {
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
            .unwrap_or_else(|error| panic!("the calendar `{slug}` could not be created: {error:?}"));
    }

    // -----------------------------------------------------------------------------------------------------------
    // Paths and writes
    // -----------------------------------------------------------------------------------------------------------

    /// The collection `slug` in the home of `person`.
    #[expect(clippy::unused_self, reason = "the helpers of the world read as one vocabulary")]
    pub(crate) fn collection(&self, org: &Org, person: &Person, slug: &str) -> CalendarRef {
        let _ = org;
        CalendarRef::Key {
            owner: person.name.clone(),
            slug: CalendarSlug::parse(slug).unwrap(),
        }
    }

    /// The object `uri` in the personal calendar of `person`.
    pub(crate) fn object(&self, org: &Org, person: &Person, uri: &str) -> ResourcePath {
        self.object_in(org, person, "personal", uri)
    }

    /// The object `uri` of the collection `slug` of `person`.
    #[expect(clippy::unused_self, reason = "the helpers of the world read as one vocabulary")]
    pub(crate) fn object_in(&self, org: &Org, person: &Person, slug: &str, uri: &str) -> ResourcePath {
        ResourcePath::Object {
            tenant: org.slug.clone(),
            principal: person.name.clone(),
            binding: CalendarSlug::parse(slug).unwrap(),
            object: ObjectUri::parse(uri).unwrap(),
        }
    }

    /// A DAV `PUT` without conditions.
    pub(crate) async fn put(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        body: &str,
    ) -> Result<PutOutcome, AppError> {
        self.put_with(ctx, path, body, WritePrecondition::none(), ScheduleReply::Send)
            .await
    }

    /// A DAV `PUT` with conditions and a `Schedule-Reply`.
    pub(crate) async fn put_with(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        body: &str,
        preconditions: WritePrecondition,
        schedule_reply: ScheduleReply,
    ) -> Result<PutOutcome, AppError> {
        self.services
            .objects
            .put(
                ctx,
                PutRequest {
                    path: path.clone(),
                    body: body.to_owned(),
                    content_type: Some("text/calendar".to_owned()),
                    preconditions,
                    schedule_reply,
                },
            )
            .await
    }

    /// A DAV `DELETE` without conditions.
    pub(crate) async fn delete(&self, ctx: &RequestContext, path: &ResourcePath) -> Result<DeleteOutcome, AppError> {
        self.delete_with(ctx, path, ScheduleReply::Send).await
    }

    /// A DAV `DELETE` with a `Schedule-Reply`.
    pub(crate) async fn delete_with(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        schedule_reply: ScheduleReply,
    ) -> Result<DeleteOutcome, AppError> {
        self.services
            .objects
            .delete(
                ctx,
                DeleteRequest {
                    path: path.clone(),
                    preconditions: WritePrecondition::none(),
                    schedule_reply,
                },
            )
            .await
    }

    /// The text of the object at `path`.
    pub(crate) async fn text(&self, ctx: &RequestContext, path: &ResourcePath) -> String {
        self.services.objects.get(ctx, path).await.unwrap().data.unwrap()
    }

    // -----------------------------------------------------------------------------------------------------------
    // Inspection
    // -----------------------------------------------------------------------------------------------------------

    /// A read-only transaction on the store itself, for inspecting data.
    pub(crate) async fn read(&self, org: &Org) -> Box<dyn Tx> {
        self.db.begin(org.id, TxMode::ReadOnly).await.unwrap()
    }

    /// The collection of a calendar of `owner` (a group, or a person who shared it) as `viewer`'s client addresses it:
    /// through the binding in the viewer's home. Listing the home creates the bindings that are created lazily.
    pub(crate) async fn collection_of(&self, org: &Org, viewer: &Person, owner: &Person) -> ResourcePath {
        self.services
            .calendars
            .list_home(&self.dav(org, viewer), &viewer.name)
            .await
            .unwrap()
            .into_iter()
            .find(|view| view.owner.id == owner.id)
            .unwrap_or_else(|| panic!("{} sees no calendar of {}", viewer.name, owner.name))
            .path
    }

    /// The DAV path of `object` through the binding its owner has to the calendar it is in.
    pub(crate) async fn path_of(&self, org: &Org, object: &StoredObject) -> ResourcePath {
        let mut tx = self.read(org).await;
        let calendar = tx.calendars().get(object.calendar_id).await.unwrap();
        let owner = tx.principals().get(calendar.owner_id).await.unwrap();
        ResourcePath::Object {
            tenant: org.slug.clone(),
            principal: owner.name,
            binding: calendar.slug,
            object: object.uri.clone(),
        }
    }

    /// The scheduling object `uid` of `person`, wherever they keep it.
    pub(crate) async fn copy_of(&self, org: &Org, person: &Person, uid: &str) -> Option<StoredObject> {
        let uid = davhaven_testkit::davhaven_domain::Uid::parse(uid).unwrap();
        self.read(org)
            .await
            .objects()
            .find_scheduling_uid(person.id, &uid)
            .await
            .unwrap()
    }

    /// Every object of every calendar `person` owns.
    pub(crate) async fn objects_of(&self, org: &Org, person: &Person) -> Vec<StoredObject> {
        let mut tx = self.read(org).await;
        let mut found = Vec::new();
        for calendar in tx.calendars().list_owned(person.id).await.unwrap() {
            let mut page = PageReq::first(1000);
            loop {
                let batch = tx.objects().list(calendar.id, page).await.unwrap();
                found.extend(batch.items);
                match batch.next {
                    Some(after) => page = page.after(after),
                    None => break,
                }
            }
        }
        found
    }

    /// The delivered items of the scheduling inbox of `person`.
    pub(crate) async fn inbox(&self, org: &Org, person: &Person) -> Vec<InboxItem> {
        self.read(org)
            .await
            .inbox()
            .list(person.id, davhaven_testkit::davhaven_ports::InboxScope::Delivered)
            .await
            .unwrap()
    }

    /// The quarantined items of the scheduling inbox of `person`.
    pub(crate) async fn quarantined(&self, org: &Org, person: &Person) -> Vec<InboxItem> {
        self.read(org)
            .await
            .inbox()
            .list(person.id, davhaven_testkit::davhaven_ports::InboxScope::Quarantined)
            .await
            .unwrap()
    }

    /// The RSVP tokens of the invitation `object`.
    pub(crate) async fn rsvp_tokens(&self, org: &Org, object: ObjectId) -> Vec<RsvpToken> {
        self.read(org).await.rsvp().for_object(object).await.unwrap()
    }

    /// Every message in the outbox of `org`, in the order it was written.
    pub(crate) async fn outbox(&self, org: &Org) -> Vec<OutboxMessage> {
        let mut tx = self.read(org).await;
        let mut messages = Vec::new();
        let mut page = PageReq::first(1000);
        loop {
            let batch = tx.outbox().list(&OutboxFilter::default(), page).await.unwrap();
            messages.extend(batch.items.iter().map(|record| record.message().unwrap()));
            match batch.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        messages
    }

    /// Every record in the outbox of `org`, in the order it was written, with its state.
    pub(crate) async fn outbox_records(&self, org: &Org) -> Vec<OutboxRecord> {
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
    }

    /// The domain events of `org`, in the order they were written.
    pub(crate) async fn events(&self, org: &Org) -> Vec<Envelope> {
        self.outbox(org)
            .await
            .into_iter()
            .filter_map(|message| match message {
                OutboxMessage::DomainEvent(envelope) => Some(envelope),
                _ => None,
            })
            .collect()
    }

    /// The types of the domain events of `org`, in order.
    pub(crate) async fn event_types(&self, org: &Org) -> Vec<EventType> {
        self.events(org)
            .await
            .into_iter()
            .map(|envelope| envelope.event_type)
            .collect()
    }

    /// The domain events of the type `kind`.
    pub(crate) async fn events_of(&self, org: &Org, kind: EventType) -> Vec<Envelope> {
        self.events(org)
            .await
            .into_iter()
            .filter(|envelope| envelope.event_type == kind)
            .collect()
    }

    /// The mail jobs of the outbox: the recipient and the method, in order.
    pub(crate) async fn mail_jobs(&self, org: &Org) -> Vec<(String, String)> {
        self.outbox(org)
            .await
            .into_iter()
            .filter_map(|message| match message {
                OutboxMessage::Imip(job) => Some((job.recipient.as_str().to_owned(), job.method.as_ical().to_owned())),
                _ => None,
            })
            .collect()
    }

    /// The audit actions of `org`, in order.
    pub(crate) async fn audit_actions(&self, org: &Org) -> Vec<String> {
        let mut tx = self.read(org).await;
        let mut actions = Vec::new();
        let mut page = PageReq::first(1000);
        loop {
            let batch = tx
                .audit()
                .list(&davhaven_testkit::davhaven_ports::AuditFilter::default(), page)
                .await
                .unwrap();
            actions.extend(batch.items.into_iter().map(|row| row.action));
            match batch.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        actions
    }

    /// Posts a message to the inbound iTIP endpoint as the gateway of `org`.
    pub(crate) async fn inbound(
        &self,
        org: &Org,
        request: InboundItipRequest,
    ) -> Result<InboundItipResponse, AppError> {
        self.services.scheduling.inbound_itip(&self.gateway(org), request).await
    }

    /// Runs the outbox dispatcher until nothing is ready: mails are composed and sent, queued deliveries are made.
    pub(crate) async fn run_outbox(&self) {
        for _ in 0..20 {
            let report: WorkReport = self.dispatcher.tick().await;
            if report.is_idle() {
                return;
            }
        }
        panic!("the outbox did not settle");
    }

    /// The mails the transport has captured, oldest first.
    pub(crate) async fn mails(&self) -> Vec<CapturedMail> {
        self.mail.sent().await
    }

    /// The mails sent to `address`.
    pub(crate) async fn mails_to(&self, address: &str) -> Vec<CapturedMail> {
        self.mail.to(address).await
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// iCalendar text
// ---------------------------------------------------------------------------------------------------------------

/// The object `uri` of the collection `collection`.
pub(crate) fn in_collection(collection: &ResourcePath, uri: &str) -> ResourcePath {
    match collection {
        ResourcePath::Collection {
            tenant,
            principal,
            binding,
        } => ResourcePath::Object {
            tenant: tenant.clone(),
            principal: principal.clone(),
            binding: binding.clone(),
            object: ObjectUri::parse(uri).unwrap(),
        },
        other => panic!("not a collection: {other:?}"),
    }
}

/// A meeting `uid` of the organizer with the given attendees (addresses as `mailto:` text), on 2027-03-10 from
/// 09:00 to 10:00 UTC.
pub(crate) fn meeting(uid: &str, organizer: &Person, attendees: &[&str]) -> EventBuilder {
    let mut builder = EventBuilder::event(uid)
        .summary("Planning")
        .starts(When::utc(2027, 3, 10, 9, 0))
        .ends(When::utc(2027, 3, 10, 10, 0))
        .organizer(Organizer::new(&organizer.mailto()));
    for attendee in attendees {
        builder = builder.attendee(Attendee::new(attendee));
    }
    builder
}

/// The `PARTSTAT` of `attendee` (a `mailto:` address) in iCalendar text, if the text lists them.
pub(crate) fn partstat_in(text: &str, attendee: &str) -> Option<PartStat> {
    let unfolded = text.replace("\r\n ", "");
    unfolded
        .lines()
        .find(|line| {
            line.starts_with("ATTENDEE") && line.to_ascii_lowercase().ends_with(&attendee.to_ascii_lowercase())
        })
        .map(|line| {
            let params = line.split(':').next().unwrap_or_default();
            params
                .split(';')
                .find_map(|param| param.strip_prefix("PARTSTAT="))
                .and_then(PartStat::from_ical)
                .unwrap_or_default()
        })
}

/// The value of `SCHEDULE-STATUS` of `attendee` in iCalendar text.
pub(crate) fn status_in(text: &str, attendee: &str) -> Option<String> {
    let unfolded = text.replace("\r\n ", "");
    unfolded
        .lines()
        .find(|line| {
            line.starts_with("ATTENDEE") && line.to_ascii_lowercase().ends_with(&attendee.to_ascii_lowercase())
        })
        .and_then(|line| {
            line.split(':')
                .next()
                .unwrap_or_default()
                .split(';')
                .find_map(|param| param.strip_prefix("SCHEDULE-STATUS="))
                .map(|value| value.trim_matches('"').to_owned())
        })
}

/// The first value of the property `name` of the text (`SEQUENCE`, `METHOD`, `STATUS`), parameters ignored.
pub(crate) fn property_in(text: &str, name: &str) -> Option<String> {
    let unfolded = text.replace("\r\n ", "");
    unfolded.lines().find_map(|line| {
        let (head, value) = line.split_once(':')?;
        (head.split(';').next()? == name).then(|| value.to_owned())
    })
}

/// How often the property `name` occurs in the text.
pub(crate) fn count_of(text: &str, name: &str) -> usize {
    text.replace("\r\n ", "")
        .lines()
        .filter(|line| line.split([':', ';']).next() == Some(name))
        .count()
}

/// The `METHOD` and the iCalendar text of the calendar alternative of a mail.
pub(crate) fn calendar_of(mail: &OutgoingMail) -> (String, String) {
    let part = mail.calendar.as_ref().expect("a scheduling mail has a calendar part");
    (part.method.as_ical().to_owned(), part.ics.clone())
}

/// Reads the answer an RSVP link shows or the organizer's copy has: the payload of a `scheduling.reply_received`.
pub(crate) fn reply_partstat(envelope: &Envelope) -> Option<PartStat> {
    match &envelope.data {
        EventPayload::SchedulingReply(payload) => payload.partstat,
        _ => None,
    }
}

/// The text with `attendee` (a `mailto:` address) answering `partstat`: what a calendar client writes when its
/// user presses a button. The text is unfolded first, because a folded line can split the parameter.
pub(crate) fn answered(text: &str, attendee: &str, partstat: PartStat) -> String {
    let unfolded = text.replace("\r\n ", "");
    let mut out = String::new();
    for line in unfolded.split_inclusive("\r\n") {
        let is_line = line.starts_with("ATTENDEE")
            && line
                .trim_end()
                .to_ascii_lowercase()
                .ends_with(&attendee.to_ascii_lowercase());
        if is_line {
            let (params, value) = line.split_once(':').unwrap();
            let mut kept: Vec<String> = params
                .split(';')
                .filter(|param| !param.starts_with("PARTSTAT="))
                .map(str::to_owned)
                .collect();
            kept.push(format!("PARTSTAT={}", partstat.as_ical()));
            let _ = write!(out, "{}:{value}", kept.join(";"));
        } else {
            out.push_str(line);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------
// Mail that a gateway forwards
// ---------------------------------------------------------------------------------------------------------------

/// A message of the gateway: the `text/calendar` part of the mail `message_id` from `from`, with the DMARC verdict
/// `pass`.
pub(crate) fn gateway_mail(from: &str, message_id: &str, ical: &str) -> InboundItipRequest {
    InboundItipRequest {
        message_id: message_id.to_owned(),
        from: Email::parse(from).unwrap(),
        ical: ical.to_owned(),
        dmarc: AuthVerdict::Pass,
        dkim: AuthVerdict::Pass,
    }
}

/// A `REPLY` as a mail client sends it: `attendee` (a `mailto:` address) answers the event `uid` of `organizer`.
pub(crate) fn reply_ical(
    uid: &str,
    organizer: &str,
    attendee: &str,
    partstat: PartStat,
    sequence: u32,
    comment: Option<&str>,
) -> String {
    let comment = comment.map(|text| format!("COMMENT:{text}\r\n")).unwrap_or_default();
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail Client//EN\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
         DTSTAMP:20270301T090000Z\r\nSEQUENCE:{sequence}\r\nORGANIZER:{organizer}\r\n\
         ATTENDEE;PARTSTAT={}:{attendee}\r\n{comment}END:VEVENT\r\nEND:VCALENDAR\r\n",
        partstat.as_ical()
    )
}

/// A `REQUEST` or `CANCEL` of an event that somebody outside the tenant organizes, for `attendee`.
pub(crate) fn invitation_ical(method: &str, uid: &str, organizer: &str, attendee: &str, sequence: u32) -> String {
    let status = if method == "CANCEL" { "STATUS:CANCELLED\r\n" } else { "" };
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Other//EN\r\nMETHOD:{method}\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
         DTSTAMP:20270101T000000Z\r\nSEQUENCE:{sequence}\r\nDTSTART:20270310T090000Z\r\nDTEND:20270310T100000Z\r\n\
         SUMMARY:Their meeting\r\n{status}ORGANIZER:{organizer}\r\n\
         ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:{attendee}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

// ---------------------------------------------------------------------------------------------------------------
// JSON events (management API and MCP)
// ---------------------------------------------------------------------------------------------------------------

/// A JSON event of `organizer` with the given attendees (addresses as text), on 2027-03-10 from 09:00 to 10:00 UTC.
pub(crate) fn event(summary: &str, organizer: &Person, attendees: &[&str]) -> Value {
    json!({
        "summary": summary,
        "start": {"date_time": "2027-03-10T09:00:00Z"},
        "end": {"date_time": "2027-03-10T10:00:00Z"},
        "organizer": {"address": organizer.mailto()},
        "attendees": attendees.iter().map(|address| json!({"address": address})).collect::<Vec<_>>()
    })
}

/// The write of the event `event` under the external key `key`; `notify` is `notify_attendees`.
pub(crate) fn write(key: &str, event: &Value, notify: bool) -> EventWrite {
    EventWrite {
        target: Some(ObjectSelector::Key(ExternalKey::parse(key).unwrap())),
        event: EventView::from_data(serde_json::from_value(event.clone()).unwrap()),
        notify_attendees: notify,
        if_match: None,
        scope: ChangeScope::All,
    }
}

/// The CSRF token of a rendered RSVP page.
pub(crate) fn csrf_of(html: &str) -> String {
    let (_, rest) = html
        .split_once("name=\"csrf\" value=\"")
        .expect("the form has a CSRF field");
    rest.split_once('"').unwrap().0.to_owned()
}
