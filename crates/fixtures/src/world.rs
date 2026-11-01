//! The `FixtureWorld` specification with constant names.
//!
//! The world is plain data: two tenants, an owner, a group member, sharees in every state, an unrelated user, a
//! suspended user, three service principals (the owner of the managed calendar and two that are granted calendars), a
//! resource and a user of the other tenant; a personal, a group, a managed, a shared and a mirror calendar, one event in
//! each of them, and a credential for every actor. Names are
//! constants in [`names`], so tests refer to `names::OWNER` instead of repeating literals, and the permission
//! matrix addresses actors and calendars through the [`ActorRole`] and [`CalendarRole`] dimensions.
//!
//! ```text
//! tenant acme (login domain acme.example)
//!   olivia    owner               personal, projects (shared user calendar), google (mirror)
//!   mia       group member        member of team: team-calendar (group), holidays (managed, via grant to team)
//!   rita      sharee, read        projects
//!   wanda     sharee, read-write  projects
//!   gary      grantee via group   projects (grant to the group viewers, gary is its member)
//!   paul      pending sharee      invited to projects, has not answered
//!   dora      declined sharee     declined the invitation to projects
//!   otto      other user          no access to anything
//!   sven      suspended user      owns nothing, cannot log in
//!   robot     service principal   owns holidays (managed)
//!   assistant service principal   granted team-calendar (read_write) and holidays (read), through the management API
//!   importer  service principal   granted holidays (read_write): DAV caps a managed calendar at read, the API and MCP do not
//!   room1     resource
//!   team      group (members: mia), owns team-calendar
//!   viewers   group (members: gary)
//! tenant globex (login domain globex.example)
//!   gina      user of the other tenant
//! ```
//!
//! Every user owns a `personal` calendar that is created together with the user (tenant setting
//! `auto_create_personal_calendar`, default on); the specification marks those calendars `implicit`, so a backend
//! that creates calendars together with users skips them.

use davhaven_domain::{
    AppPasswordText, CalendarKind, CalendarSlug, CalendarUserAddress, CredentialKind, DomainName, Email, ExternalKey,
    GrantAccess, GrantStatus, ObjectUri, PrincipalKind, PrincipalName, PrincipalStatus, ResourcePath, Scope, ScopeSet,
    TenantSlug, TokenKind, TokenText, Uid,
};

use crate::event::{EventBuilder, Organizer, When};

/// The constant names of the fixture world.
pub mod names {
    /// The slug of the main tenant.
    pub const TENANT: &str = "acme";
    /// The display name of the main tenant.
    pub const TENANT_DISPLAY: &str = "Acme";
    /// The login domain of the main tenant: users log in as `olivia@acme.example`.
    pub const LOGIN_DOMAIN: &str = "acme.example";
    /// The slug of the second tenant.
    pub const OTHER_TENANT: &str = "globex";
    /// The display name of the second tenant.
    pub const OTHER_TENANT_DISPLAY: &str = "Globex";
    /// The login domain of the second tenant.
    pub const OTHER_LOGIN_DOMAIN: &str = "globex.example";

    /// The owner of the personal, shared and mirror calendars.
    pub const OWNER: &str = "olivia";
    /// A member of the group `team`.
    pub const GROUP_MEMBER: &str = "mia";
    /// A sharee with read access to the shared calendar.
    pub const SHAREE_READ: &str = "rita";
    /// A sharee with read-write access to the shared calendar.
    pub const SHAREE_READ_WRITE: &str = "wanda";
    /// A user who reaches the shared calendar through the group `viewers`.
    pub const GRANTEE_VIA_GROUP: &str = "gary";
    /// A user invited to the shared calendar who has not answered.
    pub const PENDING_SHAREE: &str = "paul";
    /// A user who declined the invitation to the shared calendar.
    pub const DECLINED_SHAREE: &str = "dora";
    /// A user without access to any calendar of the owner, the group or the service principal.
    pub const OTHER_USER: &str = "otto";
    /// A suspended user: every login is refused.
    pub const SUSPENDED_USER: &str = "sven";
    /// A service principal; it owns the managed calendar.
    pub const SERVICE_PRINCIPAL: &str = "robot";
    /// A service principal that is granted the group calendar (`read_write`) and the managed calendar (`read`): the assistant
    /// of a deployment, which works through the API and MCP.
    pub const SERVICE_GRANTEE: &str = "assistant";
    /// A service principal that is granted the managed calendar for reading and writing: an integration that keeps the
    /// calendar up to date. DAV caps a managed calendar at read for everybody; the API and MCP do not.
    pub const SERVICE_WRITER: &str = "importer";
    /// A bookable resource.
    pub const RESOURCE: &str = "room1";
    /// The group that owns the group calendar (member: [`GROUP_MEMBER`]).
    pub const TEAM: &str = "team";
    /// The group that is granted read access to the shared calendar (member: [`GRANTEE_VIA_GROUP`]).
    pub const VIEWERS: &str = "viewers";
    /// A user of the other tenant.
    pub const OTHER_TENANT_USER: &str = "gina";

    /// The slug of every user's personal calendar.
    pub const PERSONAL_CALENDAR: &str = "personal";
    /// The slug of the group calendar (owner: [`TEAM`]).
    pub const GROUP_CALENDAR: &str = "team-calendar";
    /// The slug of the managed calendar (owner: [`SERVICE_PRINCIPAL`]).
    pub const MANAGED_CALENDAR: &str = "holidays";
    /// The slug of the shared user calendar (owner: [`OWNER`]).
    pub const SHARED_CALENDAR: &str = "projects";
    /// The slug of the mirror calendar (owner: [`OWNER`]).
    pub const MIRROR_CALENDAR: &str = "google";

    /// The resource name of the event in the personal calendar of the owner.
    pub const PERSONAL_EVENT_URI: &str = "personal-event@acme.example.ics";
    /// The external key of the event in the personal calendar (the key the management API addresses it by).
    pub const PERSONAL_EVENT_KEY: &str = "personal-event";
    /// The `UID` of the event in the personal calendar of the owner.
    pub const PERSONAL_EVENT_UID: &str = "personal-event@acme.example";
    /// The resource name of the event in the group calendar.
    pub const GROUP_EVENT_URI: &str = "group-event@acme.example.ics";
    /// The external key of the event in the group calendar (the key the management API addresses it by).
    pub const GROUP_EVENT_KEY: &str = "group-event";
    /// The `UID` of the event in the group calendar.
    pub const GROUP_EVENT_UID: &str = "group-event@acme.example";
    /// The resource name of the event in the managed calendar.
    pub const MANAGED_EVENT_URI: &str = "managed-event@acme.example.ics";
    /// The external key of the event in the managed calendar (the key the management API addresses it by).
    pub const MANAGED_EVENT_KEY: &str = "managed-event";
    /// The `UID` of the event in the managed calendar.
    pub const MANAGED_EVENT_UID: &str = "managed-event@acme.example";
    /// The resource name of the event in the shared calendar.
    pub const SHARED_EVENT_URI: &str = "shared-event@acme.example.ics";
    /// The external key of the event in the shared calendar (the key the management API addresses it by).
    pub const SHARED_EVENT_KEY: &str = "shared-event";
    /// The `UID` of the event in the shared calendar.
    pub const SHARED_EVENT_UID: &str = "shared-event@acme.example";
    /// The resource name of the event in the mirror calendar.
    pub const MIRROR_EVENT_URI: &str = "mirror-event@acme.example.ics";
    /// The external key of the event in the mirror calendar (the key the management API addresses it by).
    pub const MIRROR_EVENT_KEY: &str = "mirror-event";
    /// The `UID` of the event in the mirror calendar.
    pub const MIRROR_EVENT_UID: &str = "mirror-event@acme.example";
    /// The resource name of the event in the personal calendar of the user of the other tenant.
    pub const OTHER_TENANT_EVENT_URI: &str = "globex-event@globex.example.ics";
    /// The external key of the event in the personal calendar of the user of the other tenant.
    pub const OTHER_TENANT_EVENT_KEY: &str = "globex-event";
    /// The `UID` of the event in the personal calendar of the user of the other tenant.
    pub const OTHER_TENANT_EVENT_UID: &str = "globex-event@globex.example";
}

named_enum! {
    /// The actors of the permission matrix (PLAN 3.2).
    ///
    /// Each value is a way of presenting oneself to the server; most of them are one principal of the fixture
    /// world, the last three are credentials without a principal.
    pub enum ActorRole {
        /// The owner of the personal, shared and mirror calendars.
        Owner => "owner",
        /// A member of the group that owns the group calendar.
        GroupMember => "group_member",
        /// A sharee with read access to the shared calendar.
        ShareeRead => "sharee_read",
        /// A sharee with read-write access to the shared calendar.
        ShareeReadWrite => "sharee_read_write",
        /// A user who reaches the shared calendar through a group grant.
        GranteeViaGroup => "grantee_via_group",
        /// A user whose invitation to the shared calendar is pending.
        PendingSharee => "pending_sharee",
        /// A user who declined the invitation to the shared calendar.
        DeclinedSharee => "declined_sharee",
        /// A user of the same tenant without any access.
        OtherUser => "other_user",
        /// A user of the other tenant.
        OtherTenantUser => "other_tenant_user",
        /// A suspended user.
        SuspendedUser => "suspended_user",
        /// A service principal (owner of the managed calendar).
        ServicePrincipal => "service_principal",
        /// A service principal that is granted the group calendar (read-write) and the managed calendar (read).
        ServiceGrantee => "service_grantee",
        /// A service principal that is granted the managed calendar for reading and writing.
        ServiceWriter => "service_writer",
        /// A tenant administrator token of the main tenant.
        TenantToken => "tenant_token",
        /// A tenant administrator token of the other tenant.
        OtherTenantToken => "other_tenant_token",
        /// A system token.
        SystemToken => "system_token",
        /// No credential at all.
        Anonymous => "anonymous",
    }
}

impl ActorRole {
    /// The slug of the tenant the actor belongs to, for the roles that belong to one.
    pub const fn tenant(self) -> Option<&'static str> {
        match self {
            Self::Owner
            | Self::GroupMember
            | Self::ShareeRead
            | Self::ShareeReadWrite
            | Self::GranteeViaGroup
            | Self::PendingSharee
            | Self::DeclinedSharee
            | Self::OtherUser
            | Self::SuspendedUser
            | Self::ServicePrincipal
            | Self::ServiceGrantee
            | Self::ServiceWriter
            | Self::TenantToken => Some(names::TENANT),
            Self::OtherTenantUser | Self::OtherTenantToken => Some(names::OTHER_TENANT),
            Self::SystemToken | Self::Anonymous => None,
        }
    }

    /// The login name of the principal behind the role; `None` for the roles that are only a credential.
    pub const fn principal_name(self) -> Option<&'static str> {
        match self {
            Self::Owner => Some(names::OWNER),
            Self::GroupMember => Some(names::GROUP_MEMBER),
            Self::ShareeRead => Some(names::SHAREE_READ),
            Self::ShareeReadWrite => Some(names::SHAREE_READ_WRITE),
            Self::GranteeViaGroup => Some(names::GRANTEE_VIA_GROUP),
            Self::PendingSharee => Some(names::PENDING_SHAREE),
            Self::DeclinedSharee => Some(names::DECLINED_SHAREE),
            Self::OtherUser => Some(names::OTHER_USER),
            Self::OtherTenantUser => Some(names::OTHER_TENANT_USER),
            Self::SuspendedUser => Some(names::SUSPENDED_USER),
            Self::ServicePrincipal => Some(names::SERVICE_PRINCIPAL),
            Self::ServiceGrantee => Some(names::SERVICE_GRANTEE),
            Self::ServiceWriter => Some(names::SERVICE_WRITER),
            Self::TenantToken | Self::OtherTenantToken | Self::SystemToken | Self::Anonymous => None,
        }
    }
}

named_enum! {
    /// The calendars of the permission matrix (PLAN 3.2): one of each kind.
    pub enum CalendarRole {
        /// The personal calendar of the owner.
        Personal => "personal",
        /// The calendar of the group `team`.
        Group => "group",
        /// The managed calendar of the service principal.
        Managed => "managed",
        /// The user calendar of the owner that is shared with several sharees.
        Shared => "shared",
        /// The mirror calendar of the owner.
        Mirror => "mirror",
    }
}

impl CalendarRole {
    /// The slug of the calendar.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Personal => names::PERSONAL_CALENDAR,
            Self::Group => names::GROUP_CALENDAR,
            Self::Managed => names::MANAGED_CALENDAR,
            Self::Shared => names::SHARED_CALENDAR,
            Self::Mirror => names::MIRROR_CALENDAR,
        }
    }

    /// The login name of the principal that owns the calendar.
    pub const fn owner(self) -> &'static str {
        match self {
            Self::Personal | Self::Shared | Self::Mirror => names::OWNER,
            Self::Group => names::TEAM,
            Self::Managed => names::SERVICE_PRINCIPAL,
        }
    }

    /// The kind of the calendar.
    pub const fn kind(self) -> CalendarKind {
        match self {
            Self::Personal => CalendarKind::Personal,
            Self::Group => CalendarKind::Group,
            Self::Managed => CalendarKind::Managed,
            Self::Shared => CalendarKind::User,
            Self::Mirror => CalendarKind::Mirror,
        }
    }
}

/// Failures of looking things up in a [`FixtureWorld`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FixtureError {
    /// The world has no such entry; the text says what was looked for.
    #[error("the fixture world has no {0}")]
    Missing(String),
    /// The role is a credential without a principal, so it has no login, home or personal paths.
    #[error("the role `{0}` has no principal")]
    NoPrincipal(ActorRole),
    /// A name the world is built from is not valid.
    #[error("{0}")]
    Invalid(String),
}

/// A tenant of the fixture world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureTenant {
    /// The slug used in paths.
    pub slug: TenantSlug,
    /// The display name.
    pub display_name: String,
    /// The domain of `name@login_domain` logins.
    pub login_domain: DomainName,
}

/// A principal of the fixture world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixturePrincipal {
    /// The tenant the principal belongs to.
    pub tenant: TenantSlug,
    /// The immutable login name.
    pub name: PrincipalName,
    /// What the principal is.
    pub kind: PrincipalKind,
    /// The display name.
    pub display_name: String,
    /// The primary e-mail address, for principals that have one.
    pub email: Option<Email>,
    /// `Active`, or `Suspended` for the suspended user.
    pub status: PrincipalStatus,
    /// The matrix role of the principal, if it plays one.
    pub role: Option<ActorRole>,
}

impl FixturePrincipal {
    /// The login `name@login_domain` of a user in `world`.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn login(&self, world: &FixtureWorld) -> Result<String, FixtureError> {
        let tenant = world.tenant(self.tenant.as_str())?;
        Ok(format!("{}@{}", self.name, tenant.login_domain))
    }

    /// The `mailto:` calendar user address of the principal, if it has an e-mail address.
    pub fn address(&self) -> Option<CalendarUserAddress> {
        self.email.as_ref().map(CalendarUserAddress::mailto)
    }
}

/// A membership of a user in a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureMembership {
    /// The tenant of both principals.
    pub tenant: TenantSlug,
    /// The group.
    pub group: PrincipalName,
    /// The member.
    pub member: PrincipalName,
}

/// A reference to a calendar by its natural key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CalendarRef {
    /// The tenant.
    pub tenant: TenantSlug,
    /// The owning principal.
    pub owner: PrincipalName,
    /// The calendar slug.
    pub slug: CalendarSlug,
}

/// A calendar of the fixture world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureCalendar {
    /// The matrix role of the calendar, if it plays one.
    pub role: Option<CalendarRole>,
    /// The natural key.
    pub key: CalendarRef,
    /// The kind of calendar.
    pub kind: CalendarKind,
    /// The display name.
    pub display_name: String,
    /// Whether the calendar is created together with its owner (the personal calendar of every user).
    pub implicit: bool,
    /// The principals, besides the owner, that hold a binding with the calendar's slug in their home: accepted
    /// sharees, members of the owning group, grantees of a managed calendar, and the service principals that are granted a
    /// calendar (their home is listed through MCP, which a service principal has instead of a calendar client).
    pub bound: Vec<PrincipalName>,
}

/// A grant of access to a calendar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureGrant {
    /// The calendar.
    pub calendar: CalendarRef,
    /// The user or group that is granted access.
    pub grantee: PrincipalName,
    /// The access level.
    pub access: GrantAccess,
    /// Pending, accepted or declined.
    pub status: GrantStatus,
    /// Whether the calendar is required for the people the grant reaches: they cannot remove it from their home.
    pub required: bool,
}

/// An event stored in a calendar of the fixture world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureEvent {
    /// The calendar that holds the event.
    pub calendar: CalendarRef,
    /// The resource name.
    pub uri: ObjectUri,
    /// The `UID`.
    pub uid: Uid,
    /// The key the management API addresses the event by.
    pub external_key: ExternalKey,
    /// The summary.
    pub summary: String,
    /// The iCalendar text, exactly as stored.
    pub ics: String,
}

/// The start of the label of a tenant token that carries exactly one scope: `tenant-token:scope:{scope}`.
pub const TENANT_TOKEN_SCOPE_LABEL: &str = "tenant-token:scope:";

/// The start of the label of a principal token that carries exactly one scope: `principal-token-scope:{tenant}:{name}:{scope}`.
/// Only the owner of the world holds such tokens: the scope of a token is checked before anything about the principal.
pub const PRINCIPAL_TOKEN_SCOPE_LABEL: &str = "principal-token-scope:";

/// A credential of the fixture world. The secret is a constant derived from the label, so it is the same in every
/// run and in every backend.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureCredential {
    /// A unique, human readable label.
    pub label: String,
    /// App password or API token.
    pub kind: CredentialKind,
    /// The tenant of the credential; `None` for the system token.
    pub tenant: Option<TenantSlug>,
    /// The kind of API token (`None` for app passwords).
    pub token_kind: Option<TokenKind>,
    /// The principal the credential acts as (app passwords and principal tokens).
    pub principal: Option<PrincipalName>,
    /// The scopes of an API token.
    pub scopes: ScopeSet,
    /// Tokens with `mcp:*` scopes must expire; the lifetime in days.
    pub expires_in_days: Option<u32>,
    /// The plaintext secret a client presents.
    pub secret: String,
}

impl core::fmt::Debug for FixtureCredential {
    /// The secret never appears: the credentials of a world are what a deployed instance is addressed with.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FixtureCredential")
            .field("label", &self.label)
            .field("kind", &self.kind)
            .field("tenant", &self.tenant)
            .field("token_kind", &self.token_kind)
            .field("principal", &self.principal)
            .field("scopes", &self.scopes)
            .field("expires_in_days", &self.expires_in_days)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The names of the two tenants of a [`FixtureWorld`]: the slugs and login domains that have to be unique on a
/// server shared by several runs (a staging instance gets a world of its own per run).
///
/// Everything else of the world (principals, calendars, event names) is the same in every run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldNames {
    /// The slug of the main tenant.
    pub tenant: String,
    /// The display name of the main tenant.
    pub tenant_display: String,
    /// The login domain of the main tenant.
    pub login_domain: String,
    /// The slug of the other tenant.
    pub other_tenant: String,
    /// The display name of the other tenant.
    pub other_tenant_display: String,
    /// The login domain of the other tenant.
    pub other_login_domain: String,
}

impl WorldNames {
    /// The names of the standard world: `acme` and `globex`.
    pub fn standard() -> Self {
        Self {
            tenant: names::TENANT.to_owned(),
            tenant_display: names::TENANT_DISPLAY.to_owned(),
            login_domain: names::LOGIN_DOMAIN.to_owned(),
            other_tenant: names::OTHER_TENANT.to_owned(),
            other_tenant_display: names::OTHER_TENANT_DISPLAY.to_owned(),
            other_login_domain: names::OTHER_LOGIN_DOMAIN.to_owned(),
        }
    }

    /// The names of a world for one run: the tenants `{prefix}-a` and `{prefix}-b` with the login domains
    /// `{prefix}-a.example` and `{prefix}-b.example`.
    ///
    /// The prefix must make valid slugs and domain names ([`WorldNames::try_for_run`] checks); [`FixtureWorld::with_names`]
    /// panics on names that are not.
    pub fn for_run(prefix: &str) -> Self {
        Self {
            tenant: format!("{prefix}-a"),
            tenant_display: format!("Conformance {prefix} A"),
            login_domain: format!("{prefix}-a.example"),
            other_tenant: format!("{prefix}-b"),
            other_tenant_display: format!("Conformance {prefix} B"),
            other_login_domain: format!("{prefix}-b.example"),
        }
    }

    /// [`WorldNames::for_run`] for a prefix that is checked: the slugs and the login domains of both tenants must be valid.
    ///
    /// # Errors
    ///
    /// [`FixtureError::Invalid`] naming the name that is not valid (a prefix with an uppercase letter or an underscore, for
    /// example).
    pub fn try_for_run(prefix: &str) -> Result<Self, FixtureError> {
        let names = Self::for_run(prefix);
        for slug in [&names.tenant, &names.other_tenant] {
            TenantSlug::parse(slug)
                .map_err(|error| FixtureError::Invalid(format!("the tenant slug `{slug}`: {error}")))?;
        }
        for domain in [&names.login_domain, &names.other_login_domain] {
            DomainName::parse(domain)
                .map_err(|error| FixtureError::Invalid(format!("the login domain `{domain}`: {error}")))?;
        }
        Ok(names)
    }
}

/// The whole fixture world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureWorld {
    /// The names of the two tenants.
    pub names: WorldNames,
    /// The tenants, main tenant first.
    pub tenants: Vec<FixtureTenant>,
    /// All principals.
    pub principals: Vec<FixturePrincipal>,
    /// Group memberships.
    pub memberships: Vec<FixtureMembership>,
    /// All calendars, including the implicit personal calendars.
    pub calendars: Vec<FixtureCalendar>,
    /// Grants of access to calendars.
    pub grants: Vec<FixtureGrant>,
    /// One event per calendar of the matrix and one in the other tenant.
    pub events: Vec<FixtureEvent>,
    /// App passwords and API tokens.
    pub credentials: Vec<FixtureCredential>,
}

// ---------------------------------------------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------------------------------------------

#[expect(
    clippy::expect_used,
    reason = "the constants of `names` are valid by construction; the unit tests build the world"
)]
fn tenant_slug(text: &str) -> TenantSlug {
    TenantSlug::parse(text).expect("a valid tenant slug")
}

#[expect(
    clippy::expect_used,
    reason = "the constants of `names` are valid by construction; the unit tests build the world"
)]
fn principal_name(text: &str) -> PrincipalName {
    PrincipalName::parse(text).expect("a valid principal name")
}

#[expect(
    clippy::expect_used,
    reason = "the constants of `names` are valid by construction; the unit tests build the world"
)]
fn calendar_slug(text: &str) -> CalendarSlug {
    CalendarSlug::parse(text).expect("a valid calendar slug")
}

#[expect(
    clippy::expect_used,
    reason = "the constants of `names` are valid by construction; the unit tests build the world"
)]
fn object_uri(text: &str) -> ObjectUri {
    ObjectUri::parse(text).expect("a valid object name")
}

#[expect(
    clippy::expect_used,
    reason = "the constants of `names` are valid by construction; the unit tests build the world"
)]
fn uid(text: &str) -> Uid {
    Uid::parse(text).expect("a valid uid")
}

#[expect(
    clippy::expect_used,
    reason = "the constants of `names` are valid by construction; the unit tests build the world"
)]
fn email(text: &str) -> Email {
    Email::parse(text).expect("a valid e-mail address")
}

#[expect(
    clippy::expect_used,
    reason = "the constants of `names` are valid by construction; the unit tests build the world"
)]
fn domain(text: &str) -> DomainName {
    DomainName::parse(text).expect("a valid domain name")
}

#[expect(
    clippy::expect_used,
    reason = "the constants of `names` are valid by construction; the unit tests build the world"
)]
fn event_key(event_uid: &str) -> ExternalKey {
    let stem = event_uid.split('@').next().unwrap_or(event_uid);
    ExternalKey::parse(stem).expect("a valid external key")
}

fn calendar_ref(tenant: &str, owner: &str, slug: &str) -> CalendarRef {
    CalendarRef {
        tenant: tenant_slug(tenant),
        owner: principal_name(owner),
        slug: calendar_slug(slug),
    }
}

/// The scopes a token of `kind` may carry, as a set.
fn scopes_for(kind: TokenKind) -> ScopeSet {
    Scope::ALL
        .iter()
        .copied()
        .filter(|scope| scope.allowed_for(kind))
        .collect()
}

impl FixtureWorld {
    /// The standard world described in the module documentation.
    ///
    /// # Panics
    ///
    /// Never in practice: the world is built from the constants of [`names`], which are valid by construction.
    pub fn standard() -> Self {
        Self::with_names(WorldNames::standard())
    }

    /// The standard world with other tenant slugs and login domains.
    ///
    /// # Panics
    ///
    /// When the names are not valid slugs and domain names; callers build them with [`WorldNames::for_run`] or
    /// from validated input.
    pub fn with_names(world_names: WorldNames) -> Self {
        let tenants = vec![
            FixtureTenant {
                slug: tenant_slug(&world_names.tenant),
                display_name: world_names.tenant_display.clone(),
                login_domain: domain(&world_names.login_domain),
            },
            FixtureTenant {
                slug: tenant_slug(&world_names.other_tenant),
                display_name: world_names.other_tenant_display.clone(),
                login_domain: domain(&world_names.other_login_domain),
            },
        ];
        let mut world = Self {
            names: world_names,
            tenants,
            principals: Vec::new(),
            memberships: Vec::new(),
            calendars: Vec::new(),
            grants: Vec::new(),
            events: Vec::new(),
            credentials: Vec::new(),
        };
        world.add_principals();
        world.add_calendars();
        world.add_grants();
        world.add_events();
        world.add_credentials();
        world
    }

    fn push_principal(
        &mut self,
        tenant: &str,
        name: &str,
        kind: PrincipalKind,
        display_name: &str,
        status: PrincipalStatus,
        role: Option<ActorRole>,
    ) {
        let domain_name = if tenant == self.names.tenant {
            self.names.login_domain.clone()
        } else {
            self.names.other_login_domain.clone()
        };
        let has_email = matches!(kind, PrincipalKind::User | PrincipalKind::Resource);
        self.principals.push(FixturePrincipal {
            tenant: tenant_slug(tenant),
            name: principal_name(name),
            kind,
            display_name: display_name.to_owned(),
            email: has_email.then(|| email(&format!("{name}@{domain_name}"))),
            status,
            role,
        });
    }

    fn add_principals(&mut self) {
        use PrincipalKind::{Group, Resource, Service, User};
        use PrincipalStatus::{Active, Suspended};
        let acme_name = self.names.tenant.clone();
        let acme = acme_name.as_str();
        // The people and the service principals of the main tenant, each with its kind, its status and the role it plays.
        let principals = [
            (names::OWNER, "Olivia Owner", User, Active, ActorRole::Owner),
            (names::GROUP_MEMBER, "Mia Member", User, Active, ActorRole::GroupMember),
            (names::SHAREE_READ, "Rita Reader", User, Active, ActorRole::ShareeRead),
            (
                names::SHAREE_READ_WRITE,
                "Wanda Writer",
                User,
                Active,
                ActorRole::ShareeReadWrite,
            ),
            (
                names::GRANTEE_VIA_GROUP,
                "Gary Grantee",
                User,
                Active,
                ActorRole::GranteeViaGroup,
            ),
            (
                names::PENDING_SHAREE,
                "Paul Pending",
                User,
                Active,
                ActorRole::PendingSharee,
            ),
            (
                names::DECLINED_SHAREE,
                "Dora Declined",
                User,
                Active,
                ActorRole::DeclinedSharee,
            ),
            (names::OTHER_USER, "Otto Other", User, Active, ActorRole::OtherUser),
            (
                names::SUSPENDED_USER,
                "Sven Suspended",
                User,
                Suspended,
                ActorRole::SuspendedUser,
            ),
            (
                names::SERVICE_PRINCIPAL,
                "Robot",
                Service,
                Active,
                ActorRole::ServicePrincipal,
            ),
            (
                names::SERVICE_GRANTEE,
                "Assistant",
                Service,
                Active,
                ActorRole::ServiceGrantee,
            ),
            (
                names::SERVICE_WRITER,
                "Importer",
                Service,
                Active,
                ActorRole::ServiceWriter,
            ),
        ];
        for (name, display_name, kind, status, role) in principals {
            self.push_principal(acme, name, kind, display_name, status, Some(role));
        }
        self.push_principal(acme, names::RESOURCE, Resource, "Meeting room 1", Active, None);
        self.push_principal(acme, names::TEAM, Group, "The Team", Active, None);
        self.push_principal(acme, names::VIEWERS, Group, "Viewers", Active, None);
        let globex_name = self.names.other_tenant.clone();
        self.push_principal(
            &globex_name,
            names::OTHER_TENANT_USER,
            User,
            "Gina Globex",
            Active,
            Some(ActorRole::OtherTenantUser),
        );
        for (group, member) in [
            (names::TEAM, names::GROUP_MEMBER),
            (names::VIEWERS, names::GRANTEE_VIA_GROUP),
        ] {
            self.memberships.push(FixtureMembership {
                tenant: tenant_slug(&acme_name),
                group: principal_name(group),
                member: principal_name(member),
            });
        }
    }

    fn add_calendars(&mut self) {
        let acme_name = self.names.tenant.clone();
        let acme = acme_name.as_str();
        let rows: [(CalendarRole, &str, bool, &[&str]); 5] = [
            (CalendarRole::Personal, "Personal", true, &[]),
            (
                CalendarRole::Group,
                "Team calendar",
                false,
                &[names::GROUP_MEMBER, names::SERVICE_GRANTEE],
            ),
            (
                CalendarRole::Managed,
                "Holidays",
                false,
                &[names::GROUP_MEMBER, names::SERVICE_GRANTEE, names::SERVICE_WRITER],
            ),
            (
                CalendarRole::Shared,
                "Projects",
                false,
                &[names::SHAREE_READ, names::SHAREE_READ_WRITE, names::GRANTEE_VIA_GROUP],
            ),
            (CalendarRole::Mirror, "Google (mirror)", false, &[]),
        ];
        for (role, display_name, implicit, bound) in rows {
            self.calendars.push(FixtureCalendar {
                role: Some(role),
                key: calendar_ref(acme, role.owner(), role.slug()),
                kind: role.kind(),
                display_name: display_name.to_owned(),
                implicit,
                bound: bound.iter().map(|name| principal_name(name)).collect(),
            });
        }
        self.calendars.push(FixtureCalendar {
            role: None,
            key: calendar_ref(
                &self.names.other_tenant,
                names::OTHER_TENANT_USER,
                names::PERSONAL_CALENDAR,
            ),
            kind: CalendarKind::Personal,
            display_name: "Personal".to_owned(),
            implicit: true,
            bound: Vec::new(),
        });
    }

    fn add_grants(&mut self) {
        let rows = [
            (
                CalendarRole::Managed,
                names::TEAM,
                GrantAccess::Read,
                GrantStatus::Accepted,
            ),
            // The group's own calendar is marked required for its members the way the operator does it: with a grant to the group
            // that owns the calendar (the members have the group's default access without one, so the grant is `read`: it adds none).
            (
                CalendarRole::Group,
                names::TEAM,
                GrantAccess::Read,
                GrantStatus::Accepted,
            ),
            // The service principals are granted through the management API (client sharing does not offer them): the
            // assistant works in the group's calendar and reads the managed one, the importer writes the managed one.
            (
                CalendarRole::Group,
                names::SERVICE_GRANTEE,
                GrantAccess::ReadWrite,
                GrantStatus::Accepted,
            ),
            (
                CalendarRole::Managed,
                names::SERVICE_GRANTEE,
                GrantAccess::Read,
                GrantStatus::Accepted,
            ),
            (
                CalendarRole::Managed,
                names::SERVICE_WRITER,
                GrantAccess::ReadWrite,
                GrantStatus::Accepted,
            ),
            (
                CalendarRole::Shared,
                names::SHAREE_READ,
                GrantAccess::Read,
                GrantStatus::Accepted,
            ),
            (
                CalendarRole::Shared,
                names::SHAREE_READ_WRITE,
                GrantAccess::ReadWrite,
                GrantStatus::Accepted,
            ),
            (
                CalendarRole::Shared,
                names::VIEWERS,
                GrantAccess::Read,
                GrantStatus::Accepted,
            ),
            (
                CalendarRole::Shared,
                names::PENDING_SHAREE,
                GrantAccess::ReadWrite,
                GrantStatus::Pending,
            ),
            (
                CalendarRole::Shared,
                names::DECLINED_SHAREE,
                GrantAccess::Read,
                GrantStatus::Declined,
            ),
        ];
        for (role, grantee, access, status) in rows {
            self.grants.push(FixtureGrant {
                calendar: calendar_ref(&self.names.tenant, role.owner(), role.slug()),
                grantee: principal_name(grantee),
                access,
                status,
                // What the group `team` is granted is required: the managed calendar (a catalogue that every member must have)
                // and the group's own calendar. What the sharees and the group `viewers` are granted is optional.
                required: grantee == names::TEAM,
            });
        }
    }

    fn add_events(&mut self) {
        let personal_owner = format!("mailto:{}@{}", names::OWNER, self.names.login_domain);
        let acme = self.names.tenant.clone();
        let globex = self.names.other_tenant.clone();
        let rows = [
            (
                calendar_ref(&acme, names::OWNER, names::PERSONAL_CALENDAR),
                names::PERSONAL_EVENT_URI,
                names::PERSONAL_EVENT_UID,
                "Personal event",
                1,
            ),
            (
                calendar_ref(&acme, names::TEAM, names::GROUP_CALENDAR),
                names::GROUP_EVENT_URI,
                names::GROUP_EVENT_UID,
                "Group event",
                2,
            ),
            (
                calendar_ref(&acme, names::SERVICE_PRINCIPAL, names::MANAGED_CALENDAR),
                names::MANAGED_EVENT_URI,
                names::MANAGED_EVENT_UID,
                "Managed event",
                3,
            ),
            (
                calendar_ref(&acme, names::OWNER, names::SHARED_CALENDAR),
                names::SHARED_EVENT_URI,
                names::SHARED_EVENT_UID,
                "Shared event",
                4,
            ),
            (
                calendar_ref(&acme, names::OWNER, names::MIRROR_CALENDAR),
                names::MIRROR_EVENT_URI,
                names::MIRROR_EVENT_UID,
                "Mirror event",
                5,
            ),
            (
                calendar_ref(&globex, names::OTHER_TENANT_USER, names::PERSONAL_CALENDAR),
                names::OTHER_TENANT_EVENT_URI,
                names::OTHER_TENANT_EVENT_UID,
                "Globex event",
                1,
            ),
        ];
        for (calendar, uri, event_uid, summary, day) in rows {
            let mut builder = EventBuilder::event(event_uid)
                .summary(summary)
                .starts(When::zoned("Europe/Berlin", 2027, 3, day, 10, 0))
                .ends(When::zoned("Europe/Berlin", 2027, 3, day, 11, 0));
            if calendar.slug.as_str() == names::PERSONAL_CALENDAR && calendar.tenant.as_str() == acme {
                builder = builder.organizer(Organizer::new(&personal_owner));
            }
            self.events.push(FixtureEvent {
                calendar,
                uri: object_uri(uri),
                uid: uid(event_uid),
                external_key: event_key(event_uid),
                summary: summary.to_owned(),
                ics: builder.build(),
            });
        }
    }

    fn add_credentials(&mut self) {
        let acme = tenant_slug(&self.names.tenant);
        let globex = tenant_slug(&self.names.other_tenant);
        let principal_scopes = scopes_for(TokenKind::Principal);

        let users = [
            (&acme, names::OWNER),
            (&acme, names::GROUP_MEMBER),
            (&acme, names::SHAREE_READ),
            (&acme, names::SHAREE_READ_WRITE),
            (&acme, names::GRANTEE_VIA_GROUP),
            (&acme, names::PENDING_SHAREE),
            (&acme, names::DECLINED_SHAREE),
            (&acme, names::OTHER_USER),
            (&acme, names::SUSPENDED_USER),
            (&globex, names::OTHER_TENANT_USER),
        ];
        for (tenant, name) in users {
            let label = format!("app-password:{}:{name}", tenant.as_str());
            self.credentials.push(FixtureCredential {
                secret: app_password_secret(&label),
                label,
                kind: CredentialKind::AppPassword,
                tenant: Some(tenant.clone()),
                token_kind: None,
                principal: Some(principal_name(name)),
                scopes: ScopeSet::empty(),
                expires_in_days: None,
            });
        }
        let token_holders = users.into_iter().chain([
            (&acme, names::SERVICE_PRINCIPAL),
            (&acme, names::SERVICE_GRANTEE),
            (&acme, names::SERVICE_WRITER),
        ]);
        for (tenant, name) in token_holders {
            let label = format!("principal-token:{}:{name}", tenant.as_str());
            self.credentials.push(FixtureCredential {
                secret: api_token_secret(&label),
                label,
                kind: CredentialKind::ApiToken,
                tenant: Some(tenant.clone()),
                token_kind: Some(TokenKind::Principal),
                principal: Some(principal_name(name)),
                scopes: principal_scopes,
                expires_in_days: Some(30),
            });
        }

        // The owner also holds a token for each scope a principal token may carry, alone: the scope of a token is checked
        // before anything about the principal, so one principal stands for all.
        for scope in Scope::ALL
            .iter()
            .copied()
            .filter(|scope| scope.allowed_for(TokenKind::Principal))
        {
            let label = format!(
                "{PRINCIPAL_TOKEN_SCOPE_LABEL}{}:{}:{scope}",
                acme.as_str(),
                names::OWNER
            );
            self.credentials.push(FixtureCredential {
                secret: api_token_secret(&label),
                label,
                kind: CredentialKind::ApiToken,
                tenant: Some(acme.clone()),
                token_kind: Some(TokenKind::Principal),
                principal: Some(principal_name(names::OWNER)),
                scopes: ScopeSet::of(&[scope]),
                expires_in_days: Some(30),
            });
        }

        self.add_administration_tokens(&acme, &globex);
    }

    /// The tokens that act as nobody: the administrator of each tenant with every tenant scope, one for each scope alone in the
    /// main tenant, and the system token.
    fn add_administration_tokens(&mut self, acme: &TenantSlug, globex: &TenantSlug) {
        let tenant_scopes = scopes_for(TokenKind::Tenant);
        let mut tenant_tokens = vec![("admin".to_owned(), acme.clone(), tenant_scopes)];
        tenant_tokens.push(("globex-admin".to_owned(), globex.clone(), tenant_scopes));
        for scope in Scope::ALL
            .iter()
            .copied()
            .filter(|scope| scope.allowed_for(TokenKind::Tenant))
        {
            tenant_tokens.push((format!("scope:{scope}"), acme.clone(), ScopeSet::of(&[scope])));
        }
        for (name, tenant, scopes) in tenant_tokens {
            let label = format!("tenant-token:{name}");
            self.credentials.push(FixtureCredential {
                secret: api_token_secret(&label),
                label,
                kind: CredentialKind::ApiToken,
                tenant: Some(tenant),
                token_kind: Some(TokenKind::Tenant),
                principal: None,
                scopes,
                expires_in_days: None,
            });
        }

        let label = "system-token".to_owned();
        self.credentials.push(FixtureCredential {
            secret: api_token_secret(&label),
            label,
            kind: CredentialKind::ApiToken,
            tenant: None,
            token_kind: Some(TokenKind::System),
            principal: None,
            scopes: ScopeSet::of(&[Scope::SystemTenants]),
            expires_in_days: None,
        });
    }

    // -----------------------------------------------------------------------------------------------------------
    // Lookups
    // -----------------------------------------------------------------------------------------------------------

    /// The tenant with the slug.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn tenant(&self, slug: &str) -> Result<&FixtureTenant, FixtureError> {
        self.tenants
            .iter()
            .find(|tenant| tenant.slug.as_str() == slug)
            .ok_or_else(|| FixtureError::Missing(format!("tenant `{slug}`")))
    }

    /// The slug of the tenant a role belongs to in this world, for the roles that belong to one.
    pub fn tenant_slug_of(&self, role: ActorRole) -> Option<&str> {
        match role.tenant()? {
            names::OTHER_TENANT => Some(self.names.other_tenant.as_str()),
            _ => Some(self.names.tenant.as_str()),
        }
    }

    /// The principal behind a role.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn principal(&self, role: ActorRole) -> Result<&FixturePrincipal, FixtureError> {
        let name = role.principal_name().ok_or(FixtureError::NoPrincipal(role))?;
        self.principal_named(self.tenant_slug_of(role).unwrap_or(&self.names.tenant), name)
    }

    /// The principal `name` of the tenant `tenant`.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn principal_named(&self, tenant: &str, name: &str) -> Result<&FixturePrincipal, FixtureError> {
        self.principals
            .iter()
            .find(|principal| principal.tenant.as_str() == tenant && principal.name.as_str() == name)
            .ok_or_else(|| FixtureError::Missing(format!("principal `{name}` in tenant `{tenant}`")))
    }

    /// The calendar behind a role.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn calendar(&self, role: CalendarRole) -> Result<&FixtureCalendar, FixtureError> {
        self.calendars
            .iter()
            .find(|calendar| calendar.role == Some(role))
            .ok_or_else(|| FixtureError::Missing(format!("calendar `{role}`")))
    }

    /// The event in the calendar behind a role.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn event(&self, role: CalendarRole) -> Result<&FixtureEvent, FixtureError> {
        let calendar = &self.calendar(role)?.key;
        self.events
            .iter()
            .find(|event| &event.calendar == calendar)
            .ok_or_else(|| FixtureError::Missing(format!("event in calendar `{role}`")))
    }

    /// The login of a user (`olivia@acme.example`).
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn login(&self, role: ActorRole) -> Result<String, FixtureError> {
        self.principal(role)?.login(self)
    }

    /// The app password of a user.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn app_password(&self, role: ActorRole) -> Result<&FixtureCredential, FixtureError> {
        let principal = self.principal(role)?;
        self.credentials
            .iter()
            .find(|credential| {
                credential.kind == CredentialKind::AppPassword
                    && credential.principal.as_ref() == Some(&principal.name)
                    && credential.tenant.as_ref() == Some(&principal.tenant)
            })
            .ok_or_else(|| FixtureError::Missing(format!("app password of `{role}`")))
    }

    /// The principal API token of a principal (with every scope a principal token may carry).
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn principal_token(&self, role: ActorRole) -> Result<&FixtureCredential, FixtureError> {
        let principal = self.principal(role)?;
        self.credentials
            .iter()
            .find(|credential| {
                credential.token_kind == Some(TokenKind::Principal)
                    && credential.principal.as_ref() == Some(&principal.name)
                    && credential.tenant.as_ref() == Some(&principal.tenant)
                    && !credential.label.starts_with(PRINCIPAL_TOKEN_SCOPE_LABEL)
            })
            .ok_or_else(|| FixtureError::Missing(format!("principal token of `{role}`")))
    }

    /// The principal token of a principal that carries exactly one scope (only the owner of the world holds such tokens).
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn principal_token_with(&self, role: ActorRole, scope: Scope) -> Result<&FixtureCredential, FixtureError> {
        let principal = self.principal(role)?;
        self.credential_labelled(&format!(
            "{PRINCIPAL_TOKEN_SCOPE_LABEL}{}:{}:{scope}",
            principal.tenant.as_str(),
            principal.name.as_str()
        ))
    }

    /// The tenant token of the main tenant with every tenant scope.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn admin_token(&self) -> Result<&FixtureCredential, FixtureError> {
        self.credential_labelled("tenant-token:admin")
    }

    /// The tenant token of the other tenant with every tenant scope.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn other_tenant_admin_token(&self) -> Result<&FixtureCredential, FixtureError> {
        self.credential_labelled("tenant-token:globex-admin")
    }

    /// The tenant token of the main tenant that carries exactly one scope.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn tenant_token(&self, scope: Scope) -> Result<&FixtureCredential, FixtureError> {
        self.credential_labelled(&format!("{TENANT_TOKEN_SCOPE_LABEL}{scope}"))
    }

    /// The system token.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn system_token(&self) -> Result<&FixtureCredential, FixtureError> {
        self.credential_labelled("system-token")
    }

    fn credential_labelled(&self, label: &str) -> Result<&FixtureCredential, FixtureError> {
        self.credentials
            .iter()
            .find(|credential| credential.label == label)
            .ok_or_else(|| FixtureError::Missing(format!("credential `{label}`")))
    }

    /// The DAV path of the calendar's collection as `viewer` addresses it.
    ///
    /// The owner uses the calendar in the own home. A principal with a binding (an accepted sharee, a member of the
    /// owning group, a grantee of a managed calendar) uses the binding in the own home. Everybody else probes the
    /// owner's home, where the calendar must stay invisible. The tenant of the path is the tenant of the calendar,
    /// also for a viewer of another tenant.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn collection_path(&self, viewer: ActorRole, calendar: CalendarRole) -> Result<ResourcePath, FixtureError> {
        let viewer = self.principal(viewer)?;
        let calendar = self.calendar(calendar)?;
        let home = if viewer.tenant == calendar.key.tenant && calendar.bound.contains(&viewer.name) {
            viewer.name.clone()
        } else {
            calendar.key.owner.clone()
        };
        Ok(ResourcePath::Collection {
            tenant: calendar.key.tenant.clone(),
            principal: home,
            binding: calendar.key.slug.clone(),
        })
    }

    /// The DAV path of the calendar's event as `viewer` addresses it (see [`Self::collection_path`]).
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn object_path(&self, viewer: ActorRole, calendar: CalendarRole) -> Result<ResourcePath, FixtureError> {
        let event = self.event(calendar)?;
        match self.collection_path(viewer, calendar)? {
            ResourcePath::Collection {
                tenant,
                principal,
                binding,
            } => Ok(ResourcePath::Object {
                tenant,
                principal,
                binding,
                object: event.uri.clone(),
            }),
            other => Err(FixtureError::Missing(format!("object path below {}", other.format()))),
        }
    }

    /// The DAV path of an object with the resource name `name` in the same collection as the event.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] when the world has no such entry, or the role is a credential without a principal.
    pub fn new_object_path(
        &self,
        viewer: ActorRole,
        calendar: CalendarRole,
        name: &ObjectUri,
    ) -> Result<ResourcePath, FixtureError> {
        match self.collection_path(viewer, calendar)? {
            ResourcePath::Collection {
                tenant,
                principal,
                binding,
            } => Ok(ResourcePath::Object {
                tenant,
                principal,
                binding,
                object: name.clone(),
            }),
            other => Err(FixtureError::Missing(format!("object path below {}", other.format()))),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Constant secrets
// ---------------------------------------------------------------------------------------------------------------

const BASE32_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const BASE64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A deterministic character stream: FNV-1a of the label seeds a `SplitMix64` generator.
struct CharStream(u64);

impl CharStream {
    fn seeded(label: &str) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in label.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Self(hash)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn take(&mut self, alphabet: &[u8], count: usize) -> String {
        let size = u64::try_from(alphabet.len()).unwrap_or(1).max(1);
        (0..count)
            .map(|_| {
                let index = usize::try_from(self.next_u64() % size).unwrap_or(0);
                alphabet.get(index).copied().map_or('a', char::from)
            })
            .collect()
    }
}

/// The constant app password for `label`: nine groups of four lowercase base32 characters (PLAN 2.6).
///
/// The text goes through `davhaven_domain::credential_format`, the one definition of the formats, so a change of the
/// format cannot leave the fixtures behind unnoticed (the tests of this module parse every secret with it).
pub fn app_password_secret(label: &str) -> String {
    let mut stream = CharStream::seeded(label);
    let text = (0..9)
        .map(|_| stream.take(BASE32_LOWER, 4))
        .collect::<Vec<_>>()
        .join("-");
    AppPasswordText::parse(&text).map_or(text, |password| password.expose().to_owned())
}

fn token_secret(kind: CredentialKind, label: &str) -> String {
    let marker = TokenText::marker(kind).unwrap_or("pat");
    let mut stream = CharStream::seeded(&format!("{marker}:{label}"));
    let prefix = stream.take(BASE32_LOWER, 12);
    let secret = stream.take(BASE64_URL, 43);
    TokenText::from_parts(kind, &prefix, &secret).map_or_else(
        || format!("dvh_{marker}_{prefix}_{secret}"),
        |token| token.expose().as_str().to_owned(),
    )
}

/// The constant API token for `label`: `dvh_pat_{prefix12}_{secret43}` (PLAN 2.6).
pub fn api_token_secret(label: &str) -> String {
    token_secret(CredentialKind::ApiToken, label)
}

/// The constant feed token for `label`: `dvh_feed_{prefix12}_{secret43}`.
pub fn feed_token_secret(label: &str) -> String {
    token_secret(CredentialKind::FeedToken, label)
}

/// The constant RSVP token for `label`: `dvh_rsvp_{prefix12}_{secret43}`.
pub fn rsvp_token_secret(label: &str) -> String {
    token_secret(CredentialKind::RsvpToken, label)
}

/// The constant external key for the `n`th object a test creates through the API.
///
/// # Errors
///
/// [`davhaven_domain::KeyError`] cannot happen for the numbers of `u32`; the signature follows `ExternalKey::parse`.
pub fn external_key(n: u32) -> Result<ExternalKey, davhaven_domain::KeyError> {
    ExternalKey::parse(&format!("fixture:{n}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn named_enums_round_trip_through_their_text() {
        for role in ActorRole::ALL {
            assert_eq!(role.as_str().parse::<ActorRole>(), Ok(*role));
            assert_eq!(role.to_string(), role.as_str());
        }
        for role in CalendarRole::ALL {
            assert_eq!(role.as_str().parse::<CalendarRole>(), Ok(*role));
        }
        let error = "nobody".parse::<ActorRole>().unwrap_err();
        assert_eq!((error.kind(), error.input()), ("ActorRole", "nobody"));
        assert_eq!(
            serde_json::to_string(&ActorRole::GranteeViaGroup).unwrap(),
            "\"grantee_via_group\""
        );
        assert_eq!(ActorRole::ALL.len(), 17);
        assert_eq!(CalendarRole::ALL.len(), 5);
    }

    #[test]
    fn every_role_resolves_in_the_standard_world() {
        let world = FixtureWorld::standard();
        for role in ActorRole::ALL {
            match role.principal_name() {
                Some(_) => {
                    let principal = world.principal(*role).unwrap();
                    assert_eq!(principal.role, Some(*role));
                    assert_eq!(Some(principal.tenant.as_str()), role.tenant());
                }
                None => assert_eq!(world.principal(*role), Err(FixtureError::NoPrincipal(*role))),
            }
        }
        for role in CalendarRole::ALL {
            let calendar = world.calendar(*role).unwrap();
            assert_eq!(calendar.key.slug.as_str(), role.slug());
            assert_eq!(calendar.key.owner.as_str(), role.owner());
            assert_eq!(calendar.kind, role.kind());
            let event = world.event(*role).unwrap();
            assert!(event.ics.contains(&format!("UID:{}\r\n", event.uid)));
            assert_eq!(event.calendar, calendar.key);
        }
    }

    #[test]
    fn principals_calendars_and_events_are_unique() {
        let world = FixtureWorld::standard();
        let principals: BTreeSet<_> = world
            .principals
            .iter()
            .map(|p| (p.tenant.clone(), p.name.clone()))
            .collect();
        assert_eq!(principals.len(), world.principals.len());
        let calendars: BTreeSet<_> = world.calendars.iter().map(|c| c.key.clone()).collect();
        assert_eq!(calendars.len(), world.calendars.len());
        let objects: BTreeSet<_> = world
            .events
            .iter()
            .map(|e| (e.calendar.clone(), e.uri.clone()))
            .collect();
        assert_eq!(objects.len(), world.events.len());
        let uids: BTreeSet<_> = world.events.iter().map(|e| e.uid.clone()).collect();
        assert_eq!(uids.len(), world.events.len());
        // Every calendar owner, member, grantee and bound principal exists in the calendar's tenant.
        for calendar in &world.calendars {
            let tenant = calendar.key.tenant.as_str();
            assert!(world.principal_named(tenant, calendar.key.owner.as_str()).is_ok());
            for name in &calendar.bound {
                assert!(world.principal_named(tenant, name.as_str()).is_ok(), "{name}");
            }
        }
        for grant in &world.grants {
            assert!(
                world
                    .principal_named(grant.calendar.tenant.as_str(), grant.grantee.as_str())
                    .is_ok()
            );
        }
        for membership in &world.memberships {
            let group = world
                .principal_named(membership.tenant.as_str(), membership.group.as_str())
                .unwrap();
            assert_eq!(group.kind, PrincipalKind::Group);
            assert!(
                world
                    .principal_named(membership.tenant.as_str(), membership.member.as_str())
                    .is_ok()
            );
        }
    }

    #[test]
    fn bindings_follow_the_accepted_grants_and_memberships() {
        let world = FixtureWorld::standard();
        let shared = world.calendar(CalendarRole::Shared).unwrap();
        let bound: Vec<&str> = shared.bound.iter().map(PrincipalName::as_str).collect();
        assert_eq!(bound, vec!["rita", "wanda", "gary"]);
        for name in [names::PENDING_SHAREE, names::DECLINED_SHAREE, names::OTHER_USER] {
            assert!(!bound.contains(&name), "{name} has no binding");
        }
        assert_eq!(world.calendar(CalendarRole::Mirror).unwrap().bound.len(), 0);
        assert!(world.calendar(CalendarRole::Personal).unwrap().implicit);
        assert!(!world.calendar(CalendarRole::Shared).unwrap().implicit);
    }

    #[test]
    fn paths_address_the_own_home_the_binding_or_the_owners_home() {
        let world = FixtureWorld::standard();
        let path = |viewer, calendar| world.collection_path(viewer, calendar).unwrap().format();
        assert_eq!(
            path(ActorRole::Owner, CalendarRole::Personal),
            "/dav/calendars/acme/olivia/personal/"
        );
        assert_eq!(
            path(ActorRole::Owner, CalendarRole::Shared),
            "/dav/calendars/acme/olivia/projects/"
        );
        assert_eq!(
            path(ActorRole::ShareeRead, CalendarRole::Shared),
            "/dav/calendars/acme/rita/projects/"
        );
        assert_eq!(
            path(ActorRole::GranteeViaGroup, CalendarRole::Shared),
            "/dav/calendars/acme/gary/projects/"
        );
        assert_eq!(
            path(ActorRole::GroupMember, CalendarRole::Group),
            "/dav/calendars/acme/mia/team-calendar/"
        );
        assert_eq!(
            path(ActorRole::GroupMember, CalendarRole::Managed),
            "/dav/calendars/acme/mia/holidays/"
        );
        // Probing: the owner's home of the calendar.
        assert_eq!(
            path(ActorRole::OtherUser, CalendarRole::Personal),
            "/dav/calendars/acme/olivia/personal/"
        );
        assert_eq!(
            path(ActorRole::PendingSharee, CalendarRole::Shared),
            "/dav/calendars/acme/olivia/projects/"
        );
        assert_eq!(
            path(ActorRole::Owner, CalendarRole::Group),
            "/dav/calendars/acme/team/team-calendar/"
        );
        assert_eq!(
            path(ActorRole::OtherTenantUser, CalendarRole::Shared),
            "/dav/calendars/acme/olivia/projects/"
        );
        assert_eq!(
            world
                .object_path(ActorRole::ShareeRead, CalendarRole::Shared)
                .unwrap()
                .format(),
            "/dav/calendars/acme/rita/projects/shared-event@acme.example.ics"
        );
        let name = ObjectUri::parse("new.ics").unwrap();
        assert_eq!(
            world
                .new_object_path(ActorRole::Owner, CalendarRole::Mirror, &name)
                .unwrap()
                .format(),
            "/dav/calendars/acme/olivia/google/new.ics"
        );
        assert_eq!(
            world.collection_path(ActorRole::Anonymous, CalendarRole::Personal),
            Err(FixtureError::NoPrincipal(ActorRole::Anonymous))
        );
    }

    #[test]
    fn logins_and_credentials_resolve() {
        let world = FixtureWorld::standard();
        assert_eq!(world.login(ActorRole::Owner).unwrap(), "olivia@acme.example");
        assert_eq!(world.login(ActorRole::OtherTenantUser).unwrap(), "gina@globex.example");
        assert!(world.login(ActorRole::SystemToken).is_err());
        for role in ActorRole::ALL.iter().filter(|role| role.principal_name().is_some()) {
            let principal = world.principal(*role).unwrap();
            if principal.kind == PrincipalKind::User {
                assert_eq!(world.app_password(*role).unwrap().kind, CredentialKind::AppPassword);
            }
            let token = world.principal_token(*role).unwrap();
            assert_eq!(token.token_kind, Some(TokenKind::Principal));
            assert!(
                token.expires_in_days.is_some(),
                "principal tokens carry mcp scopes and expire"
            );
        }
        for role in [
            ActorRole::ServicePrincipal,
            ActorRole::ServiceGrantee,
            ActorRole::ServiceWriter,
        ] {
            assert!(
                world.app_password(role).is_err(),
                "{role}: a service principal has no password"
            );
        }
        assert_eq!(world.admin_token().unwrap().scopes, scopes_for(TokenKind::Tenant));
        assert_eq!(
            world.system_token().unwrap().scopes,
            ScopeSet::of(&[Scope::SystemTenants])
        );
        assert!(world.system_token().unwrap().tenant.is_none());
        assert_eq!(
            world
                .other_tenant_admin_token()
                .unwrap()
                .tenant
                .as_ref()
                .map(TenantSlug::as_str),
            Some("globex")
        );
        for scope in Scope::ALL.iter().filter(|scope| scope.allowed_for(TokenKind::Tenant)) {
            assert_eq!(world.tenant_token(*scope).unwrap().scopes, ScopeSet::of(&[*scope]));
        }
        assert!(world.tenant_token(Scope::McpRead).is_err());
    }

    #[test]
    fn the_owner_holds_one_principal_token_for_each_scope_a_principal_token_may_carry() {
        let world = FixtureWorld::standard();
        let general = world.principal_token(ActorRole::Owner).unwrap();
        let mut allowed = 0;
        for scope in Scope::ALL.iter().copied() {
            let token = world.principal_token_with(ActorRole::Owner, scope);
            if !scope.allowed_for(TokenKind::Principal) {
                assert!(token.is_err(), "{scope}: no principal token may carry it");
                continue;
            }
            allowed += 1;
            let token = token.unwrap();
            assert_eq!(token.scopes, ScopeSet::of(&[scope]), "{scope}: that scope alone");
            assert_eq!(token.token_kind, Some(TokenKind::Principal), "{scope}");
            assert_eq!(token.principal.as_ref().map(PrincipalName::as_str), Some("olivia"));
            assert_eq!(token.tenant.as_ref().map(TenantSlug::as_str), Some("acme"));
            assert_ne!(
                token.secret, general.secret,
                "{scope}: not the general token of the owner"
            );
        }
        assert!(allowed > 0, "some scope is allowed for principal tokens");
        assert!(
            world
                .principal_token_with(ActorRole::GroupMember, Scope::McpRead)
                .is_err(),
            "only the owner holds tokens of one scope"
        );
        assert!(matches!(
            world.principal_token_with(ActorRole::Anonymous, Scope::McpRead),
            Err(FixtureError::NoPrincipal(ActorRole::Anonymous))
        ));
    }

    #[test]
    fn secrets_have_the_documented_formats_and_are_unique() {
        let world = FixtureWorld::standard();
        let mut secrets = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        for credential in &world.credentials {
            assert!(secrets.insert(credential.secret.clone()), "{}", credential.label);
            match credential.kind {
                CredentialKind::AppPassword => {
                    let groups: Vec<&str> = credential.secret.split('-').collect();
                    assert_eq!(groups.len(), 9, "{}", credential.secret);
                    assert!(
                        groups
                            .iter()
                            .all(|g| g.len() == 4 && g.bytes().all(|b| BASE32_LOWER.contains(&b)))
                    );
                    assert!(
                        prefixes.insert(groups[..2].join("-")),
                        "app password prefixes are unique"
                    );
                }
                CredentialKind::ApiToken => {
                    let parts: Vec<&str> = credential.secret.split('_').collect();
                    // `dvh`, `pat`, prefix, secret: the base64url alphabet contains `_`, so rejoin the tail.
                    assert_eq!(&parts[..2], &["dvh", "pat"]);
                    let rest = credential.secret.strip_prefix("dvh_pat_").unwrap();
                    let (prefix, secret) = rest.split_at(12);
                    assert!(prefix.bytes().all(|b| BASE32_LOWER.contains(&b)), "{prefix}");
                    let secret = secret.strip_prefix('_').unwrap();
                    assert_eq!(secret.len(), 43);
                    assert!(secret.bytes().all(|b| BASE64_URL.contains(&b)));
                    assert!(prefixes.insert(prefix.to_owned()), "token prefixes are unique");
                }
                CredentialKind::FeedToken | CredentialKind::RsvpToken => unreachable!("not in the world"),
            }
        }
        assert_eq!(app_password_secret("x"), app_password_secret("x"));
        assert_ne!(app_password_secret("x"), app_password_secret("y"));
        assert!(feed_token_secret("x").starts_with("dvh_feed_"));
        assert!(rsvp_token_secret("x").starts_with("dvh_rsvp_"));
        assert_ne!(api_token_secret("x"), feed_token_secret("x"));
    }

    #[test]
    fn every_constant_secret_is_a_credential_in_the_format_of_the_domain() {
        for label in ["a", "anna", "mia-iphone", "acme-admin"] {
            assert!(AppPasswordText::parse(&app_password_secret(label)).is_some(), "{label}");
            for (text, kind) in [
                (api_token_secret(label), CredentialKind::ApiToken),
                (feed_token_secret(label), CredentialKind::FeedToken),
                (rsvp_token_secret(label), CredentialKind::RsvpToken),
            ] {
                let token = TokenText::parse(kind, &text).unwrap_or_else(|| panic!("{text} is a {kind}"));
                assert_eq!(token.expose().as_str(), text, "the canonical text is the text");
            }
        }
    }

    #[test]
    fn only_the_grants_of_the_group_team_are_required() {
        let world = FixtureWorld::standard();
        let required: Vec<(&str, bool)> = world
            .grants
            .iter()
            .map(|grant| (grant.grantee.as_str(), grant.required))
            .collect();
        assert!(required.contains(&(names::TEAM, true)), "{required:?}");
        for (grantee, required) in required {
            assert_eq!(required, grantee == names::TEAM, "{grantee}");
        }
        let calendars: Vec<CalendarRole> = world
            .grants
            .iter()
            .filter(|grant| grant.required)
            .filter_map(|grant| {
                world
                    .calendars
                    .iter()
                    .find(|calendar| calendar.key == grant.calendar)
                    .and_then(|calendar| calendar.role)
            })
            .collect();
        assert_eq!(calendars, vec![CalendarRole::Managed, CalendarRole::Group]);
    }

    #[test]
    fn the_service_principals_that_are_granted_calendars_hold_grants_and_their_bindings() {
        let world = FixtureWorld::standard();
        let granted = |role: ActorRole| -> Vec<(CalendarRole, GrantAccess, GrantStatus)> {
            let name = world.principal(role).unwrap().name.clone();
            world
                .grants
                .iter()
                .filter(|grant| grant.grantee == name)
                .map(|grant| {
                    let calendar = world
                        .calendars
                        .iter()
                        .find(|calendar| calendar.key == grant.calendar)
                        .and_then(|calendar| calendar.role)
                        .unwrap();
                    (calendar, grant.access, grant.status)
                })
                .collect()
        };
        assert_eq!(
            granted(ActorRole::ServiceGrantee),
            vec![
                (CalendarRole::Group, GrantAccess::ReadWrite, GrantStatus::Accepted),
                (CalendarRole::Managed, GrantAccess::Read, GrantStatus::Accepted),
            ],
            "the group's calendar for reading and writing, the managed one for reading"
        );
        assert_eq!(
            granted(ActorRole::ServiceWriter),
            vec![(CalendarRole::Managed, GrantAccess::ReadWrite, GrantStatus::Accepted)]
        );
        assert!(
            granted(ActorRole::ServicePrincipal).is_empty(),
            "the owner of the managed calendar needs no grant"
        );
        // A grant gives a binding in the home of the grantee when that home is listed for the first time, which a service
        // principal does through MCP: the world lists it once, so the first listing of a case changes nothing.
        let bound = |calendar: CalendarRole, role: ActorRole| {
            let name = &world.principal(role).unwrap().name;
            world.calendar(calendar).unwrap().bound.contains(name)
        };
        assert!(bound(CalendarRole::Group, ActorRole::ServiceGrantee));
        assert!(bound(CalendarRole::Managed, ActorRole::ServiceGrantee));
        assert!(bound(CalendarRole::Managed, ActorRole::ServiceWriter));
        assert!(!bound(CalendarRole::Group, ActorRole::ServiceWriter));
        assert!(
            !bound(CalendarRole::Managed, ActorRole::ServicePrincipal),
            "the owner has the calendar in its own home"
        );
    }

    #[test]
    fn the_suspended_user_and_the_service_principal_are_marked() {
        let world = FixtureWorld::standard();
        assert_eq!(
            world.principal(ActorRole::SuspendedUser).unwrap().status,
            PrincipalStatus::Suspended
        );
        assert_eq!(
            world.principal(ActorRole::ServicePrincipal).unwrap().kind,
            PrincipalKind::Service
        );
        assert!(world.principal(ActorRole::ServicePrincipal).unwrap().email.is_none());
        for role in [ActorRole::ServiceGrantee, ActorRole::ServiceWriter] {
            let principal = world.principal(role).unwrap();
            assert_eq!(principal.kind, PrincipalKind::Service, "{role}");
            assert!(principal.email.is_none(), "{role}: a service principal has no address");
        }
        assert_eq!(
            world
                .principal_named("acme", names::RESOURCE)
                .unwrap()
                .address()
                .unwrap()
                .as_str(),
            "mailto:room1@acme.example"
        );
        assert!(external_key(7).is_ok());
    }
}
