//! Shared in-memory state of the fake services.
//!
//! [`FakeWorld`] is plain data with synchronous helpers: tenants, principals, memberships, calendars, bindings,
//! objects, change logs and credentials. [`FakeState`] wraps it in an async mutex so the service implementations
//! (`principals`, `calendars`, `objects`, `auth`) and tests share one world. Identifiers and timestamps are
//! deterministic: ids count up from one and the clock starts at 2027-01-01 00:00 UTC and only moves when a test
//! calls [`FakeState::advance`] or a write ticks it by one second.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use davhaven_app::error::{AppError, AppResult, SafeMessage};
use davhaven_domain::{
    AccessFacts, Actor, Binding, BindingFact, BindingId, Calendar, CalendarId, CalendarKind, CalendarSlug,
    CalendarUserAddress, Channel, ComponentKind, ContentHash, CredentialId, Decision, DomainName, ETag, Email,
    ExternalKey, Grant, GrantAccess, GrantFact, GrantId, GrantSource, GrantStatus, Href, Limits, Locale, ObjectId,
    ObjectUri, Operation, Principal, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus, PublicUrls,
    RequestContext, RequestId, ResourcePath, ScopeSet, StoredObject, Subject, TenantId, TenantSettings, TenantSlug,
    TimeZoneName, TokenId, TokenKind, Uid, decide,
};
use davhaven_wire::Cursor;
use tokio::sync::Mutex;
use uuid::Uuid;

/// A tenant of the fake world.
#[derive(Debug, Clone)]
pub struct FakeTenant {
    /// The tenant id.
    pub id: TenantId,
    /// The slug used in paths.
    pub slug: TenantSlug,
    /// The display name.
    pub display_name: String,
    /// The domain of `name@login_domain` logins.
    pub login_domain: Option<DomainName>,
    /// The settings (defaults unless a test changes them).
    pub settings: Arc<TenantSettings>,
}

/// An app password of the fake world (stored in plain text: this is a fake).
#[derive(Debug, Clone)]
pub struct FakeAppPassword {
    /// The credential id.
    pub id: CredentialId,
    /// The principal it authenticates.
    pub principal: PrincipalId,
    /// The plaintext password.
    pub password: String,
    /// Whether the password is revoked.
    pub revoked: bool,
}

/// An API token of the fake world.
#[derive(Debug, Clone)]
pub struct FakeApiToken {
    /// The token id.
    pub id: TokenId,
    /// The tenant of tenant and principal tokens; `None` for system tokens.
    pub tenant: Option<TenantId>,
    /// The kind of token.
    pub kind: TokenKind,
    /// The principal a principal token acts as.
    pub principal: Option<PrincipalId>,
    /// The scopes.
    pub scopes: ScopeSet,
    /// The plaintext secret presented as a `Bearer` token.
    pub secret: String,
    /// Whether the token is revoked.
    pub revoked: bool,
}

/// A feed token of the fake world.
#[derive(Debug, Clone)]
pub struct FakeFeedToken {
    /// The token id.
    pub id: TokenId,
    /// The tenant.
    pub tenant: TenantId,
    /// The principal whose access the feed is rendered with.
    pub principal: PrincipalId,
    /// The plaintext secret.
    pub secret: String,
}

/// An RSVP token of the fake world.
#[derive(Debug, Clone)]
pub struct FakeRsvpToken {
    /// The token id.
    pub id: TokenId,
    /// The tenant.
    pub tenant: TenantId,
    /// The invitation the link answers.
    pub object: ObjectId,
    /// The attendee the link was issued to.
    pub address: CalendarUserAddress,
    /// The plaintext secret.
    pub secret: String,
}

/// One entry of a calendar's change log.
#[derive(Debug, Clone)]
pub struct FakeChange {
    /// The sequence number of the change.
    pub seq: i64,
    /// The resource name.
    pub uri: ObjectUri,
    /// Whether the object exists after the change.
    pub deleted: bool,
}

/// The whole fake world.
#[derive(Debug, Clone)]
pub struct FakeWorld {
    pub(crate) urls: PublicUrls,
    pub(crate) now: DateTime<Utc>,
    next: u128,
    pub(crate) tenants: BTreeMap<TenantId, FakeTenant>,
    pub(crate) principals: BTreeMap<PrincipalId, Principal>,
    pub(crate) extra_addresses: BTreeMap<PrincipalId, Vec<CalendarUserAddress>>,
    pub(crate) members: BTreeSet<(PrincipalId, PrincipalId)>,
    pub(crate) calendars: BTreeMap<CalendarId, Calendar>,
    pub(crate) bindings: BTreeMap<BindingId, Binding>,
    pub(crate) grants: BTreeMap<GrantId, Grant>,
    /// The dead properties of the bindings: (binding, namespace, local name) to the XML of the value. Properties belong to
    /// the binding of a principal, not to the calendar (PLAN 2.4, `collection_properties.binding_id`): two sharees of one
    /// calendar keep their own.
    pub(crate) dead_properties: BTreeMap<(BindingId, String, String), String>,
    pub(crate) limits: Limits,
    pub(crate) objects: BTreeMap<ObjectId, StoredObject>,
    pub(crate) changes: BTreeMap<CalendarId, Vec<FakeChange>>,
    pub(crate) app_passwords: Vec<FakeAppPassword>,
    pub(crate) api_tokens: Vec<FakeApiToken>,
    pub(crate) feed_tokens: Vec<FakeFeedToken>,
    pub(crate) rsvp_tokens: Vec<FakeRsvpToken>,
}

impl Default for FakeWorld {
    fn default() -> Self {
        Self::new()
    }
}

/// The public base URL of the fake world.
pub const BASE_URL: &str = "https://cal.example.test";

/// The URL builder of the fake world.
#[expect(
    clippy::expect_used,
    reason = "BASE_URL is a valid base URL literal; the unit tests build every world"
)]
fn base_urls() -> PublicUrls {
    let url = BASE_URL.parse().expect("BASE_URL is a valid URL");
    PublicUrls::new(url).expect("BASE_URL is a valid bare origin")
}

impl FakeWorld {
    /// An empty world: no tenants, no principals. The clock starts at 2027-01-01 00:00 UTC.
    pub fn new() -> Self {
        Self {
            urls: base_urls(),
            now: Utc
                .with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or(DateTime::UNIX_EPOCH),
            next: 0,
            tenants: BTreeMap::new(),
            principals: BTreeMap::new(),
            extra_addresses: BTreeMap::new(),
            members: BTreeSet::new(),
            calendars: BTreeMap::new(),
            bindings: BTreeMap::new(),
            grants: BTreeMap::new(),
            dead_properties: BTreeMap::new(),
            limits: Limits::default(),
            objects: BTreeMap::new(),
            changes: BTreeMap::new(),
            app_passwords: Vec::new(),
            api_tokens: Vec::new(),
            feed_tokens: Vec::new(),
            rsvp_tokens: Vec::new(),
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Ids and time
    // ---------------------------------------------------------------------------------------------------------

    /// The next deterministic UUID (1, 2, 3, ...).
    pub(crate) fn next_uuid(&mut self) -> Uuid {
        self.next += 1;
        Uuid::from_u128(self.next)
    }

    /// The current time of the fake clock.
    pub fn now(&self) -> DateTime<Utc> {
        self.now
    }

    /// Moves the clock forward.
    pub fn advance(&mut self, by: Duration) {
        let step = chrono::Duration::from_std(by).unwrap_or_else(|_| chrono::Duration::seconds(1));
        self.now += step;
    }

    /// Writes tick the clock by one second so `updated_at` and ETags of successive writes differ.
    pub(crate) fn tick(&mut self) -> DateTime<Utc> {
        self.now += chrono::Duration::seconds(1);
        self.now
    }

    /// The URLs the fake builds links with.
    pub fn urls(&self) -> &PublicUrls {
        &self.urls
    }

    /// The limits the fake enforces: the number and the size of dead properties (`limits.dav`), the size of an object
    /// (`limits.ical`). The defaults of PLAN 2.15 unless a test sets others.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Sets the limits the fake enforces. They are also the `limits` of the services of [`FakeApp::new`](crate::FakeApp::new),
    /// which is why they are set before the services are built: a protocol layer reads them from the services and the fake
    /// applies them from its world, and the two must say the same.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// The most dead properties of one binding and the largest one in bytes, which `limits.dav` says: as the real application
    /// counts them, with the largest numbers for a limit that does not fit.
    pub(crate) fn dead_property_limits(&self) -> (usize, usize) {
        (
            usize::try_from(self.limits.dav.max_dead_properties).unwrap_or(usize::MAX),
            usize::try_from(self.limits.dav.max_dead_property_size).unwrap_or(usize::MAX),
        )
    }

    // ---------------------------------------------------------------------------------------------------------
    // Lookups
    // ---------------------------------------------------------------------------------------------------------

    /// The tenant with the id.
    pub fn tenant(&self, id: TenantId) -> Option<&FakeTenant> {
        self.tenants.get(&id)
    }

    /// The tenant with the slug.
    pub fn tenant_by_slug(&self, slug: &TenantSlug) -> Option<&FakeTenant> {
        self.tenants.values().find(|tenant| &tenant.slug == slug)
    }

    /// The tenant of a request, or `NotFound`.
    pub(crate) fn tenant_of(&self, ctx: &RequestContext) -> AppResult<&FakeTenant> {
        self.tenants.get(&ctx.tenant).ok_or_else(AppError::not_found)
    }

    /// The tenant of a request when the path names the tenant too: both must agree.
    pub(crate) fn tenant_for_path(&self, ctx: &RequestContext, slug: &TenantSlug) -> AppResult<&FakeTenant> {
        let tenant = self.tenant_of(ctx)?;
        if &tenant.slug == slug {
            Ok(tenant)
        } else {
            Err(AppError::not_found())
        }
    }

    /// A live (not deleted) principal of the tenant by name.
    pub fn principal_by_name(&self, tenant: TenantId, name: &PrincipalName) -> Option<&Principal> {
        self.principals.values().find(|principal| {
            principal.tenant_id == tenant && &principal.name == name && principal.status != PrincipalStatus::Deleted
        })
    }

    /// A live principal of the tenant by name, or `NotFound`.
    pub(crate) fn require_principal(&self, tenant: TenantId, name: &PrincipalName) -> AppResult<&Principal> {
        self.principal_by_name(tenant, name).ok_or_else(AppError::not_found)
    }

    /// A live principal of the tenant by id.
    pub(crate) fn principal_by_id(&self, tenant: TenantId, id: PrincipalId) -> Option<&Principal> {
        self.principals
            .get(&id)
            .filter(|principal| principal.tenant_id == tenant && principal.status != PrincipalStatus::Deleted)
    }

    /// The id of a principal of the tenant with the slug, for tests.
    pub fn principal_id(&self, tenant_slug: &TenantSlug, name: &PrincipalName) -> Option<PrincipalId> {
        let tenant = self.tenant_by_slug(tenant_slug)?;
        self.principal_by_name(tenant.id, name).map(|principal| principal.id)
    }

    /// The id of the live calendar of `owner` with the slug, for tests.
    pub fn find_calendar(&self, owner: PrincipalId, slug: &CalendarSlug) -> Option<CalendarId> {
        let tenant = self.principals.get(&owner)?.tenant_id;
        self.calendar_by_key(tenant, owner, slug).map(|calendar| calendar.id)
    }

    /// The groups a principal currently belongs to.
    pub(crate) fn groups_of(&self, principal: PrincipalId) -> Vec<PrincipalId> {
        self.members
            .iter()
            .filter(|(_, member)| *member == principal)
            .map(|(group, _)| *group)
            .collect()
    }

    /// The members of a group.
    pub(crate) fn members_of(&self, group: PrincipalId) -> Vec<PrincipalId> {
        self.members
            .iter()
            .filter(|(candidate, _)| *candidate == group)
            .map(|(_, member)| *member)
            .collect()
    }

    /// A live calendar of the tenant by id.
    pub(crate) fn calendar(&self, tenant: TenantId, id: CalendarId) -> Option<&Calendar> {
        self.calendars
            .get(&id)
            .filter(|calendar| calendar.tenant_id == tenant && calendar.deleted_at.is_none())
    }

    /// A live calendar of the tenant by owner and slug.
    pub(crate) fn calendar_by_key(
        &self,
        tenant: TenantId,
        owner: PrincipalId,
        slug: &CalendarSlug,
    ) -> Option<&Calendar> {
        self.calendars.values().find(|calendar| {
            calendar.tenant_id == tenant
                && calendar.owner_id == owner
                && &calendar.slug == slug
                && calendar.deleted_at.is_none()
        })
    }

    /// The binding of a principal at a slug.
    pub(crate) fn binding_by_slug(&self, principal: PrincipalId, slug: &CalendarSlug) -> Option<&Binding> {
        self.bindings
            .values()
            .find(|binding| binding.principal_id == principal && &binding.slug == slug)
    }

    /// The binding of a principal for a calendar.
    pub(crate) fn binding_for(&self, principal: PrincipalId, calendar: CalendarId) -> Option<&Binding> {
        self.bindings
            .values()
            .find(|binding| binding.principal_id == principal && binding.calendar_id == calendar)
    }

    /// The dead properties of a binding, ordered by namespace and name.
    pub(crate) fn dead_properties_of(&self, binding: BindingId) -> Vec<(&str, &str, &str)> {
        self.dead_properties
            .iter()
            .filter(|((owner, _, _), _)| *owner == binding)
            .map(|((_, namespace, local), value)| (namespace.as_str(), local.as_str(), value.as_str()))
            .collect()
    }

    /// Removes the bindings that `remove` selects, with the dead properties kept on them.
    pub(crate) fn remove_bindings(&mut self, remove: impl Fn(&Binding) -> bool) {
        let gone: BTreeSet<BindingId> = self
            .bindings
            .values()
            .filter(|binding| remove(binding))
            .map(|binding| binding.id)
            .collect();
        self.bindings.retain(|id, _| !gone.contains(id));
        self.dead_properties
            .retain(|(binding, _, _), _| !gone.contains(binding));
    }

    /// The objects of a calendar ordered by resource name.
    pub(crate) fn objects_of(&self, calendar: CalendarId) -> Vec<&StoredObject> {
        let mut objects: Vec<&StoredObject> = self
            .objects
            .values()
            .filter(|object| object.calendar_id == calendar)
            .collect();
        objects.sort_by(|a, b| a.uri.cmp(&b.uri));
        objects
    }

    /// The object of a calendar at a resource name.
    pub(crate) fn object_by_uri(&self, calendar: CalendarId, uri: &ObjectUri) -> Option<&StoredObject> {
        self.objects
            .values()
            .find(|object| object.calendar_id == calendar && &object.uri == uri)
    }

    // ---------------------------------------------------------------------------------------------------------
    // Authorization
    // ---------------------------------------------------------------------------------------------------------

    /// The facts `decide` needs about a calendar for the request's caller.
    pub(crate) fn access_facts(&self, ctx: &RequestContext, calendar: &Calendar) -> AccessFacts {
        self.access_facts_for(ctx.principal(), calendar)
    }

    /// The facts `decide` needs about a calendar for a viewer (a principal, or nobody for tokens that are
    /// not bound to a principal).
    pub(crate) fn access_facts_for(&self, viewer: Option<PrincipalId>, calendar: &Calendar) -> AccessFacts {
        let owner_kind = self
            .principals
            .get(&calendar.owner_id)
            .map_or(PrincipalKind::User, |owner| owner.kind);
        let settings = self.tenants.get(&calendar.tenant_id).map_or_else(
            || Arc::new(TenantSettings::default()),
            |tenant| Arc::clone(&tenant.settings),
        );
        AccessFacts {
            calendar_kind: calendar.kind,
            owner: calendar.owner_id,
            owner_kind,
            memberships: viewer.map(|principal| self.groups_of(principal)).unwrap_or_default(),
            grants: self
                .grants
                .values()
                .filter(|grant| grant.calendar_id == calendar.id)
                .map(GrantFact::from)
                .collect(),
            binding: viewer
                .and_then(|principal| self.binding_for(principal, calendar.id))
                .map(|binding| BindingFact {
                    id: binding.id,
                    hidden: binding.hidden,
                }),
            tenant_settings: settings,
        }
    }

    /// Decides an operation on a calendar for the request's caller.
    pub(crate) fn decision(&self, ctx: &RequestContext, calendar: &Calendar, operation: Operation) -> Decision {
        decide(
            &Subject::from(ctx),
            ctx.channel,
            &self.access_facts(ctx, calendar),
            operation,
        )
    }

    /// Enforces an operation on a calendar: `NotFound` for hidden, `Forbidden` with `need-privileges` otherwise.
    pub(crate) fn enforce(
        &self,
        ctx: &RequestContext,
        calendar: &Calendar,
        operation: Operation,
        href: impl FnOnce() -> Href,
    ) -> AppResult<()> {
        match self.decision(ctx, calendar, operation) {
            Decision::Allow => Ok(()),
            Decision::Hidden => Err(AppError::not_found()),
            Decision::Forbidden(privilege) => Err(AppError::need_privilege(href(), privilege)),
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Seeding
    // ---------------------------------------------------------------------------------------------------------

    /// Adds a tenant with the default settings.
    pub fn add_tenant(&mut self, slug: TenantSlug, display_name: &str, login_domain: Option<DomainName>) -> TenantId {
        let id = TenantId::from_uuid(self.next_uuid());
        self.tenants.insert(
            id,
            FakeTenant {
                id,
                slug,
                display_name: display_name.to_owned(),
                login_domain,
                settings: Arc::new(TenantSettings::default()),
            },
        );
        id
    }

    /// Replaces the settings of a tenant.
    pub fn set_tenant_settings(&mut self, tenant: TenantId, settings: TenantSettings) {
        if let Some(entry) = self.tenants.get_mut(&tenant) {
            entry.settings = Arc::new(settings);
        }
    }

    /// Adds a principal. Users get a personal calendar when the tenant settings ask for one.
    pub fn add_principal(
        &mut self,
        tenant: TenantId,
        kind: PrincipalKind,
        name: PrincipalName,
        display_name: &str,
        email: Option<Email>,
    ) -> PrincipalId {
        let id = PrincipalId::from_uuid(self.next_uuid());
        let now = self.tick();
        self.principals.insert(
            id,
            Principal {
                id,
                tenant_id: tenant,
                kind,
                name,
                display_name: display_name.to_owned(),
                email,
                locale: Some(Locale::en()),
                timezone: Some(TimeZoneName::utc()),
                external_ref: None,
                status: PrincipalStatus::Active,
                deleted_at: None,
                credential_generation: 0,
                created_at: now,
                updated_at: now,
                version: 1,
            },
        );
        let wants_personal = kind == PrincipalKind::User
            && self
                .tenants
                .get(&tenant)
                .is_some_and(|tenant| tenant.settings.auto_create_personal_calendar);
        if wants_personal && let Ok(slug) = CalendarSlug::parse("personal") {
            self.add_calendar(id, slug, CalendarKind::Personal, "Personal");
        }
        id
    }

    /// Changes the status of a principal (for example to `Suspended`, which makes logins fail).
    pub fn set_principal_status(&mut self, principal: PrincipalId, status: PrincipalStatus) {
        if let Some(entry) = self.principals.get_mut(&principal) {
            entry.status = status;
        }
    }

    /// Adds a member to a group.
    pub fn add_member(&mut self, group: PrincipalId, member: PrincipalId) {
        self.members.insert((group, member));
    }

    /// Adds a further calendar user address to a principal.
    pub fn add_address(&mut self, principal: PrincipalId, address: CalendarUserAddress) {
        self.extra_addresses.entry(principal).or_default().push(address);
    }

    /// Adds an app password; the principal logs in with it on the DAV channel.
    pub fn add_app_password(&mut self, principal: PrincipalId, password: &str) -> CredentialId {
        let id = CredentialId::from_uuid(self.next_uuid());
        self.app_passwords.push(FakeAppPassword {
            id,
            principal,
            password: password.to_owned(),
            revoked: false,
        });
        id
    }

    /// Adds an API token; clients present `secret` as a `Bearer` token.
    pub fn add_api_token(
        &mut self,
        tenant: Option<TenantId>,
        kind: TokenKind,
        principal: Option<PrincipalId>,
        scopes: ScopeSet,
        secret: &str,
    ) -> TokenId {
        let id = TokenId::from_uuid(self.next_uuid());
        self.api_tokens.push(FakeApiToken {
            id,
            tenant,
            kind,
            principal,
            scopes,
            secret: secret.to_owned(),
            revoked: false,
        });
        id
    }

    /// Adds a feed token.
    pub fn add_feed_token(&mut self, tenant: TenantId, principal: PrincipalId, secret: &str) -> TokenId {
        let id = TokenId::from_uuid(self.next_uuid());
        self.feed_tokens.push(FakeFeedToken {
            id,
            tenant,
            principal,
            secret: secret.to_owned(),
        });
        id
    }

    /// Adds an RSVP token for an attendee of an object.
    pub fn add_rsvp_token(
        &mut self,
        tenant: TenantId,
        object: ObjectId,
        address: CalendarUserAddress,
        secret: &str,
    ) -> TokenId {
        let id = TokenId::from_uuid(self.next_uuid());
        self.rsvp_tokens.push(FakeRsvpToken {
            id,
            tenant,
            object,
            address,
            secret: secret.to_owned(),
        });
        id
    }

    /// Adds a calendar with the owner's binding (the binding has the slug of the calendar).
    pub fn add_calendar(
        &mut self,
        owner: PrincipalId,
        slug: CalendarSlug,
        kind: CalendarKind,
        display_name: &str,
    ) -> CalendarId {
        let tenant = self
            .principals
            .get(&owner)
            .map_or(TenantId::from_uuid(Uuid::nil()), |p| p.tenant_id);
        let id = CalendarId::from_uuid(self.next_uuid());
        let epoch = self.next_uuid();
        let now = self.tick();
        self.calendars.insert(
            id,
            Calendar {
                id,
                tenant_id: tenant,
                owner_id: owner,
                slug: slug.clone(),
                kind,
                display_name: display_name.to_owned(),
                description: None,
                color: None,
                sort_order: 0,
                components: ComponentKind::ALL.to_vec(),
                timezone_ics: None,
                sync_seq: 0,
                sync_min_seq: 0,
                sync_epoch: epoch,
                deleted_at: None,
                created_at: now,
                updated_at: now,
                version: 1,
            },
        );
        self.add_binding(tenant, owner, id, slug);
        id
    }

    /// Adds a grant of access to a calendar for a user, a group or a service principal. Only accepted grants confer access. The
    /// grant does not create a binding: use [`FakeWorld::add_binding`] for the sharee's home. There is no grant of free-busy only (a
    /// principal of the tenant may always ask for free-busy): a viewer of that kind is a principal that is not granted.
    pub fn add_grant(
        &mut self,
        calendar: CalendarId,
        grantee: PrincipalId,
        access: GrantAccess,
        status: GrantStatus,
    ) -> GrantId {
        let tenant = self
            .calendars
            .get(&calendar)
            .map_or(TenantId::from_uuid(Uuid::nil()), |entry| entry.tenant_id);
        let id = GrantId::from_uuid(self.next_uuid());
        let now = self.tick();
        self.grants.insert(
            id,
            Grant {
                id,
                tenant_id: tenant,
                calendar_id: calendar,
                grantee_id: grantee,
                access,
                status,
                source: GrantSource::Api,
                required: false,
                invite_uid: None,
                summary: None,
                common_name: None,
                created_at: now,
                updated_at: now,
                version: 1,
            },
        );
        id
    }

    /// Adds a binding of a calendar to a principal's home.
    pub fn add_binding(
        &mut self,
        tenant: TenantId,
        principal: PrincipalId,
        calendar: CalendarId,
        slug: CalendarSlug,
    ) -> BindingId {
        let id = BindingId::from_uuid(self.next_uuid());
        let now = self.tick();
        self.bindings.insert(
            id,
            Binding {
                id,
                tenant_id: tenant,
                principal_id: principal,
                calendar_id: calendar,
                slug,
                display_name: None,
                color: None,
                sort_order: None,
                schedule_transp: None,
                hidden: false,
                created_at: now,
                updated_at: now,
                version: 1,
            },
        );
        id
    }

    /// Stores an iCalendar text in a calendar at a resource name, bypassing authorization and validation of
    /// the services (seeding). The text must contain a `UID:` line.
    pub fn add_object(&mut self, calendar: CalendarId, uri: ObjectUri, ical: &str) -> Option<ObjectId> {
        let uid = crate::icaltext::uid_of(ical)?;
        let component = crate::icaltext::component_of(ical).unwrap_or(ComponentKind::Event);
        self.store_object(calendar, uri, uid, component, ical.to_owned(), None)
            .ok()
            .map(|stored| stored.id)
    }

    /// The core of every object write: creates or replaces the object, bumps the calendar's sequence and logs the
    /// change. Returns the stored object and whether it was created.
    pub(crate) fn store_object(
        &mut self,
        calendar_id: CalendarId,
        uri: ObjectUri,
        uid: Uid,
        component: ComponentKind,
        data: String,
        external_key: Option<ExternalKey>,
    ) -> AppResult<StoredObject> {
        let now = self.tick();
        let existing = self.object_by_uri(calendar_id, &uri).cloned();
        let id = existing
            .as_ref()
            .map_or_else(|| ObjectId::from_uuid(self.next_uuid()), |object| object.id);
        let calendar = self.calendars.get_mut(&calendar_id).ok_or_else(AppError::not_found)?;
        calendar.sync_seq += 1;
        calendar.updated_at = now;
        let seq = calendar.sync_seq;
        let owner = calendar.owner_id;
        let tenant = calendar.tenant_id;
        let etag = ETag::from_bytes(data.as_bytes());
        let stored = StoredObject {
            id,
            tenant_id: tenant,
            calendar_id,
            owner_id: owner,
            uri: uri.clone(),
            uid,
            etag: etag.clone(),
            schedule_tag: None,
            content_hash: content_hash_of(&etag),
            component,
            size: u64::try_from(data.len()).unwrap_or(u64::MAX),
            data,
            first_start: None,
            last_end: None,
            is_recurring: false,
            is_scheduling: false,
            organizer_address: None,
            sequence: 0,
            class: davhaven_domain::Classification::Public,
            external_key: external_key.or_else(|| existing.as_ref().and_then(|object| object.external_key.clone())),
            origin: None,
            created_at: existing.as_ref().map_or(now, |object| object.created_at),
            updated_at: now,
            version: existing.as_ref().map_or(1, |object| object.version + 1),
        };
        self.objects.insert(id, stored.clone());
        self.changes.entry(calendar_id).or_default().push(FakeChange {
            seq,
            uri,
            deleted: false,
        });
        Ok(stored)
    }

    /// Removes an object and logs the deletion.
    pub(crate) fn remove_object(&mut self, id: ObjectId) -> AppResult<()> {
        let now = self.tick();
        let object = self.objects.remove(&id).ok_or_else(AppError::not_found)?;
        let calendar = self
            .calendars
            .get_mut(&object.calendar_id)
            .ok_or_else(AppError::not_found)?;
        calendar.sync_seq += 1;
        calendar.updated_at = now;
        let seq = calendar.sync_seq;
        self.changes.entry(object.calendar_id).or_default().push(FakeChange {
            seq,
            uri: object.uri,
            deleted: true,
        });
        Ok(())
    }

    /// The `ResourcePath` of a calendar's object in the viewer's home, for a binding.
    pub(crate) fn object_path(
        tenant: &TenantSlug,
        principal: &PrincipalName,
        binding: &CalendarSlug,
        uri: &ObjectUri,
    ) -> ResourcePath {
        ResourcePath::Object {
            tenant: tenant.clone(),
            principal: principal.clone(),
            binding: binding.clone(),
            object: uri.clone(),
        }
    }

    /// A request context for a principal logged in over DAV, for tests that bypass authentication.
    pub fn dav_context(&self, tenant: TenantId, principal: PrincipalId) -> RequestContext {
        RequestContext {
            tenant,
            actor: Actor::Principal(principal),
            scopes: ScopeSet::empty(),
            channel: Channel::Dav,
            credential: None,
            request_id: RequestId::from_uuid(Uuid::nil()),
            locale: None,
            client_ip: None,
        }
    }
}

/// The content hash of the fake: derived from the ETag, since the fake never compares hashes.
fn content_hash_of(etag: &ETag) -> ContentHash {
    let mut digest = [0_u8; 32];
    for (slot, byte) in digest.iter_mut().zip(etag.opaque().bytes()) {
        *slot = byte;
    }
    ContentHash::from_digest(digest)
}

/// The shared handle of the fake world.
#[derive(Debug, Clone)]
pub struct FakeState {
    world: Arc<Mutex<FakeWorld>>,
}

impl FakeState {
    /// Wraps a world.
    pub fn new(world: FakeWorld) -> Self {
        Self {
            world: Arc::new(Mutex::new(world)),
        }
    }

    /// Reads the world.
    pub async fn read<R>(&self, f: impl FnOnce(&FakeWorld) -> R) -> R {
        let world = self.world.lock().await;
        f(&world)
    }

    /// Changes the world.
    pub async fn write<R>(&self, f: impl FnOnce(&mut FakeWorld) -> R) -> R {
        let mut world = self.world.lock().await;
        f(&mut world)
    }

    /// Moves the fake clock forward.
    pub async fn advance(&self, by: Duration) {
        self.write(|world| world.advance(by)).await;
    }

    /// The time of the fake clock without waiting for the world: `None` while a service call of another task holds
    /// it. The protocol layer reads the time between its own calls, so a test that makes its calls one after the
    /// other always gets it.
    pub fn try_now(&self) -> Option<DateTime<Utc>> {
        self.world.try_lock().ok().map(|world| world.now())
    }
}

// -------------------------------------------------------------------------------------------------------------
// Paging
// -------------------------------------------------------------------------------------------------------------

/// The default and maximum page size of the fake (the API limits of the plan).
const DEFAULT_PAGE: u32 = 50;
const MAX_PAGE: u32 = 200;

/// Cuts a page out of items sorted by id: the cursor of the fake is the id of the last item of the previous page
/// (the fake does not sign cursors).
pub(crate) fn paginate<T>(
    items: Vec<(Uuid, T)>,
    limit: Option<u32>,
    cursor: Option<&Cursor>,
) -> AppResult<davhaven_wire::Page<T>> {
    let after = match cursor {
        None => None,
        Some(cursor) => Some(
            Uuid::parse_str(cursor.as_str())
                .map_err(|_| AppError::invalid(SafeMessage::from_static("The cursor is not valid.")))?,
        ),
    };
    let size = usize::try_from(limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)).unwrap_or(usize::MAX);
    let mut remaining: Vec<(Uuid, T)> = items
        .into_iter()
        .filter(|(id, _)| after.is_none_or(|after| *id > after))
        .collect();
    let more = remaining.len() > size;
    remaining.truncate(size);
    let next = if more {
        remaining
            .last()
            .and_then(|(id, _)| Cursor::parse(&id.hyphenated().to_string()).ok())
    } else {
        None
    };
    Ok(davhaven_wire::Page::new(
        remaining.into_iter().map(|(_, item)| item).collect(),
        next,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_follow_ids_and_cursors() {
        let items: Vec<(Uuid, u32)> = (1..=5).map(|n| (Uuid::from_u128(u128::from(n)), n)).collect();
        let first = paginate(items.clone(), Some(2), None).unwrap();
        assert_eq!(first.items, vec![1, 2]);
        let second = paginate(items.clone(), Some(2), first.next_cursor.as_ref()).unwrap();
        assert_eq!(second.items, vec![3, 4]);
        let third = paginate(items.clone(), Some(2), second.next_cursor.as_ref()).unwrap();
        assert_eq!(third.items, vec![5]);
        assert!(third.next_cursor.is_none());
        let bad = Cursor::parse("not-a-uuid").unwrap();
        assert!(paginate(items, Some(2), Some(&bad)).is_err());
    }

    #[test]
    fn the_world_is_deterministic() {
        let mut world = FakeWorld::new();
        let tenant = world.add_tenant(TenantSlug::parse("acme").unwrap(), "Acme", None);
        let anna = world.add_principal(
            tenant,
            PrincipalKind::User,
            PrincipalName::parse("anna").unwrap(),
            "Anna",
            None,
        );
        assert_eq!(tenant.as_uuid(), Uuid::from_u128(1));
        assert_eq!(anna.as_uuid(), Uuid::from_u128(2));
        assert_eq!(world.now().to_rfc3339(), "2027-01-01T00:00:03+00:00");
        assert_eq!(world.calendars.len(), 1, "users get a personal calendar");
        assert_eq!(world.bindings.len(), 1);
        world.advance(Duration::from_mins(1));
        assert_eq!(world.now().to_rfc3339(), "2027-01-01T00:01:03+00:00");
    }

    #[test]
    fn a_principal_without_a_grant_is_the_free_busy_only_viewer_of_the_tenant() {
        // PLAN 2.6 lists a level of free-busy, but nothing grants it: `GrantAccess` is read, read-write or admin, and free-busy is
        // open to every principal of the tenant. The free-busy-only viewer of a calendar is therefore a principal without a grant,
        // which the world seeds by not granting.
        let mut world = FakeWorld::new();
        let tenant = world.add_tenant(TenantSlug::parse("acme").unwrap(), "Acme", None);
        let mut user = |name: &str| {
            world.add_principal(
                tenant,
                PrincipalKind::User,
                PrincipalName::parse(name).unwrap(),
                name,
                None,
            )
        };
        let (anna, ben) = (user("anna"), user("ben"));
        let calendar = world.add_calendar(anna, CalendarSlug::parse("work").unwrap(), CalendarKind::User, "Work");
        let work = &world.calendars[&calendar];
        let context = |principal| RequestContext {
            tenant,
            actor: Actor::Principal(principal),
            scopes: ScopeSet::empty(),
            channel: Channel::Dav,
            credential: None,
            request_id: RequestId::from_uuid(Uuid::nil()),
            locale: None,
            client_ip: None,
        };

        assert_eq!(
            world.decision(&context(ben), work, Operation::FreeBusyQuery),
            Decision::Allow
        );
        for operation in [Operation::ReadCollection, Operation::ListObjects, Operation::ReadObject] {
            assert_eq!(
                world.decision(&context(ben), work, operation),
                Decision::Hidden,
                "{operation}: free-busy is all that a principal without a grant may ask for"
            );
        }
        assert_eq!(
            world.decision(&context(anna), work, Operation::ReadObject),
            Decision::Allow
        );
    }

    #[test]
    fn grants_statuses_and_calendar_lookups_can_be_seeded() {
        let mut world = FakeWorld::new();
        let tenant = world.add_tenant(TenantSlug::parse("acme").unwrap(), "Acme", None);
        let user = |world: &mut FakeWorld, name: &str| {
            world.add_principal(
                tenant,
                PrincipalKind::User,
                PrincipalName::parse(name).unwrap(),
                name,
                None,
            )
        };
        let anna = user(&mut world, "anna");
        let ben = user(&mut world, "ben");
        let slug = CalendarSlug::parse("shared").unwrap();
        let calendar = world.add_calendar(anna, slug.clone(), CalendarKind::User, "Shared");
        assert_eq!(world.find_calendar(anna, &slug), Some(calendar));
        assert_eq!(
            world.find_calendar(ben, &slug),
            None,
            "calendars are found by owner and slug"
        );

        let facts = |world: &FakeWorld, viewer| world.access_facts_for(Some(viewer), &world.calendars[&calendar]);
        assert_eq!(facts(&world, ben).grants, Vec::new());
        world.add_grant(calendar, ben, GrantAccess::ReadWrite, GrantStatus::Accepted);
        world.add_grant(calendar, anna, GrantAccess::Read, GrantStatus::Pending);
        let granted = facts(&world, ben).grants;
        assert_eq!(granted.len(), 2, "the facts carry every grant of the calendar");
        assert!(
            granted
                .iter()
                .any(|grant| grant.grantee == ben && grant.status == GrantStatus::Accepted)
        );

        assert_eq!(world.principals[&ben].status, PrincipalStatus::Active);
        world.set_principal_status(ben, PrincipalStatus::Suspended);
        assert_eq!(world.principals[&ben].status, PrincipalStatus::Suspended);
        let binding = world.add_binding(tenant, ben, calendar, slug.clone());
        assert_eq!(world.bindings[&binding].slug, slug, "bindings can be added for sharees");
    }
}
