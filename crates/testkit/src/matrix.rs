//! The permission matrix harness and the expectations file format.
//!
//! The permission matrix (PLAN 3.2) crosses every [`ActorRole`] with every [`CalendarRole`], [`Surface`] and
//! [`Operation`] and asserts the status of each [`Case`]. The expected results are **not** computed from the code
//! under test: they come from the hand-reviewed file `matrix/expectations.toml`, parsed by [`Expectations`]. This
//! module never imports `davhaven_domain::authz`; the operations, actors and calendars are the vocabulary of the
//! plan, written down once more on purpose.
//!
//! # The expectations file
//!
//! ```text
//! schema_version = 1
//!
//! [status.<expectation>]      the status policy: HTTP status (`401`, `2xx`), DAV precondition, problem code
//! [[access]]                  default rules: the effective access of an actor on a calendar (absent: none)
//! [[cap]]                     default rules: caps on the access a surface may exercise on a calendar
//! [[needs]]                   default rules: the access an operation needs, per operation
//! [[available]]               default rules: the operations that exist on each surface
//! [[scope]]                   default rules: the token scope an operation needs on API and MCP
//! [[exception]]               explicit exception rows; the first matching row wins over every default rule
//! [[admin]]                   the scopes of the administration operations of the API (the operations that are not about one calendar)
//! ```
//!
//! Rows select dimensions with a name, a list of names or `"*"`; an omitted selector means `"*"`. The resolution
//! order of [`Expectations::resolve`] is: exception rows; availability of the operation on the surface; the token
//! scope of a tenant token; the effective access (with caps) compared with what the operation needs. Mismatches
//! between this file and the server are triaged by people: either the server or the file is wrong, and the file
//! is the one reviewed against the plan.

use core::fmt;
use core::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};

use davhaven_fixtures::{ActorRole, CalendarRole, named_enum};
use serde::Deserialize;
use serde::de::{self, Deserializer};

/// The expectations file that ships with the harness (`crates/testkit/matrix/expectations.toml`).
pub const BUNDLED: &str = include_str!("../matrix/expectations.toml");

/// The only schema version this parser reads.
pub const SCHEMA_VERSION: u32 = 1;

named_enum! {
    /// A surface of the server: how a request arrives (the channel of PLAN 2.5).
    pub enum Surface {
        /// WebDAV and CalDAV.
        Dav => "dav",
        /// The management API.
        Api => "api",
        /// The MCP server.
        Mcp => "mcp",
        /// Subscription feeds.
        Feed => "feed",
        /// RSVP pages.
        Rsvp => "rsvp",
    }
}

named_enum! {
    /// How much a principal may do with a calendar, in increasing order (PLAN 2.6).
    pub enum Level {
        /// No access: the calendar is invisible.
        Nothing => "none",
        /// Free-busy queries only.
        FreeBusy => "free_busy",
        /// Read events.
        Read => "read",
        /// Read and write events.
        ReadWrite => "read_write",
        /// Read, write, share and rename.
        Admin => "admin",
        /// The owner of the calendar.
        Owner => "owner",
    }
}

named_enum! {
    /// A kind of credential a client presents (PLAN 2.6).
    pub enum CredentialType {
        /// A per-device DAV app password.
        AppPassword => "app_password",
        /// An API token that acts as one principal.
        PrincipalToken => "principal_token",
        /// An API token that administers a tenant.
        TenantToken => "tenant_token",
        /// An API token that administers the installation.
        SystemToken => "system_token",
        /// A token in the URL of a subscription feed.
        FeedToken => "feed_token",
        /// A token in the URL of an RSVP page.
        RsvpToken => "rsvp_token",
    }
}

named_enum! {
    /// The state a credential is in when it is presented.
    pub enum CredentialState {
        /// Issued, not revoked, not expired, its principal and tenant active.
        Valid => "valid",
        /// Right prefix, wrong secret.
        WrongSecret => "wrong_secret",
        /// A well-formed credential whose prefix no credential has.
        UnknownPrefix => "unknown_prefix",
        /// Not in the format of the kind at all.
        Malformed => "malformed",
        /// Revoked through the management API (or by the event it belongs to).
        Revoked => "revoked",
        /// Past its expiry.
        Expired => "expired",
        /// Its principal is suspended.
        PrincipalSuspended => "principal_suspended",
        /// Its tenant is suspended.
        TenantSuspended => "tenant_suspended",
        /// An app password presented with the login of another user.
        CrossLogin => "cross_login",
        /// Its principal was deleted.
        DeletedPrincipal => "deleted_principal",
        /// An API token presented in another way than as a `Bearer` header.
        NotBearer => "not_bearer",
    }
}

named_enum! {
    /// What a surface does with a credential in a state.
    pub enum CredentialExpectation {
        /// The credential authenticates (what the request then gets is the business of the permission matrix).
        Accepted => "accepted",
        /// The credential is refused at the door: 401 on DAV, API and MCP, the 404 of an unknown token on the pages.
        Refused => "refused",
        /// The state does not exist for the kind of credential, or the harness cannot produce it: the reason is in the file.
        NotApplicable => "n/a",
    }
}

named_enum! {
    /// A kind of API token, for the scopes it may carry.
    pub enum TokenClass {
        /// Administers one tenant.
        Tenant => "tenant",
        /// Administers the installation.
        System => "system",
        /// Acts as one principal.
        Principal => "principal",
    }
}

named_enum! {
    /// How an actor is treated by the administration operations of the management API.
    pub enum AdminRule {
        /// Refused at the door: 401.
        Unauthenticated => "unauthenticated",
        /// Authenticated and refused whatever it carries: 403.
        Refused => "refused",
        /// Another tenant's: 404 where the path names a tenant, 403 where it does not.
        OtherTenant => "other_tenant",
        /// Decided by the scopes of the token: allowed with one of the scopes of the operation, 403 without.
        ByScope => "by_scope",
    }
}

named_enum! {
    /// How an operation that a service does not offer yet answers.
    pub enum PendingState {
        /// The service is not implemented: every caller that reaches it is answered 501.
        NotImplemented => "not_implemented",
    }
}

named_enum! {
    /// What the operation is addressed to.
    pub enum Target {
        /// A calendar (the actor's access to the calendar decides).
        Calendar => "calendar",
        /// The home of the calendar's owner (inbox, outbox, notifications, creating calendars).
        Home => "home",
    }
}

named_enum! {
    /// The outcome a case expects (the status policy of PLAN 2.6).
    pub enum Expectation {
        /// The operation succeeds (a 2xx status).
        Allow => "allow",
        /// No or invalid credentials, a suspended principal, a credential on the wrong surface: 401.
        Unauthenticated => "unauthenticated",
        /// No read visibility, including other tenants and unknown ids: 404.
        Hidden => "hidden",
        /// Visible but not permitted: 403.
        Forbidden => "forbidden",
        /// A stale precondition: 412.
        PreconditionFailed => "precondition_failed",
    }
}

named_enum! {
    /// One row of the permission matrix (PLAN 3.2): what a caller does, independent of the surface it uses.
    ///
    /// A share by the owner and a re-share by somebody else are the same operation; the actor tells them apart.
    pub enum Operation {
        /// Read a calendar's properties (PROPFIND on the collection, API get of a calendar, MCP `list_calendars`).
        ReadCollection => "read_collection",
        /// List or query objects (calendar-query, multiget, sync-collection, API list, MCP `list_events`).
        ListObjects => "list_objects",
        /// Read one object (GET, API get by key, MCP `get_event`).
        ReadObject => "read_object",
        /// Free-busy queries (REPORT, outbox POST, MCP `free_busy`).
        FreeBusyQuery => "free_busy_query",
        /// Create an object (PUT of a new resource, API and MCP create).
        CreateObject => "create_object",
        /// Replace or change an object.
        UpdateObject => "update_object",
        /// Delete an object.
        DeleteObject => "delete_object",
        /// Batch upsert through the API.
        BatchUpsert => "batch_upsert",
        /// The source side of MOVE.
        MoveObjectFrom => "move_object_from",
        /// The target side of MOVE.
        MoveObjectTo => "move_object_to",
        /// The source side of COPY.
        CopyObjectFrom => "copy_object_from",
        /// The target side of COPY.
        CopyObjectTo => "copy_object_to",
        /// Answer an invitation on behalf of the caller (API and MCP).
        RespondToInvitation => "respond_to_invitation",
        /// PROPPATCH of per-binding properties.
        PropPatchBinding => "prop_patch_binding",
        /// PROPPATCH of shared calendar properties, API update of calendar settings.
        UpdateCalendar => "update_calendar",
        /// Rename the calendar itself.
        RenameCalendar => "rename_calendar",
        /// MKCALENDAR, extended MKCOL or API creation of a calendar.
        CreateCalendar => "create_calendar",
        /// Delete the calendar for everyone.
        DeleteCalendar => "delete_calendar",
        /// DELETE of a bound collection by somebody who is not the owner: the binding disappears.
        RemoveBinding => "remove_binding",
        /// CalendarServer sharing (`CS:share`): sharing by the owner, or re-sharing by an administrator.
        ShareCalendar => "share_calendar",
        /// `CS:invite-reply`: accept or decline a pending invitation.
        ReplyInvite => "reply_invite",
        /// List the grants of a calendar (API).
        ListGrants => "list_grants",
        /// Create or replace a grant (API).
        PutGrant => "put_grant",
        /// Remove a grant (API).
        DeleteGrant => "delete_grant",
        /// Read the scheduling inbox.
        ReadInbox => "read_inbox",
        /// Delete a scheduling inbox item.
        DeleteInboxItem => "delete_inbox_item",
        /// POST to the scheduling outbox.
        PostOutbox => "post_outbox",
        /// Read the notification collection.
        ReadNotifications => "read_notifications",
        /// Delete a notification.
        DeleteNotification => "delete_notification",
        /// List the home of a principal: PROPFIND of the home (what the caller's bindings are) and the synchronization of it.
        ReadHome => "read_home",
        /// Read the principal resource of a principal: its addresses, the URL of its home (DAV PROPFIND).
        ReadPrincipal => "read_principal",
        /// Render a subscription feed.
        ReadFeed => "read_feed",
        /// Open an RSVP page.
        RsvpView => "rsvp_view",
        /// Answer on an RSVP page.
        RsvpAnswer => "rsvp_answer",
    }
}

impl Operation {
    /// Whether the operation changes state when it is allowed (the matrix runs such a case on an application of its
    /// own, so that the changes of one case cannot be seen by another). A COPY changes the destination, which is why
    /// [`Operation::CopyObjectFrom`] is among them although the source is only read: the copy of the owner lands in a calendar
    /// that is shared with others, and what it brings there is read by the cases that follow.
    pub const fn mutates(self) -> bool {
        matches!(
            self,
            Self::CreateObject
                | Self::UpdateObject
                | Self::DeleteObject
                | Self::BatchUpsert
                | Self::MoveObjectFrom
                | Self::MoveObjectTo
                | Self::CopyObjectFrom
                | Self::CopyObjectTo
                | Self::RespondToInvitation
                | Self::PropPatchBinding
                | Self::UpdateCalendar
                | Self::RenameCalendar
                | Self::CreateCalendar
                | Self::DeleteCalendar
                | Self::RemoveBinding
                | Self::ShareCalendar
                | Self::ReplyInvite
                | Self::PutGrant
                | Self::DeleteGrant
                | Self::DeleteInboxItem
                | Self::DeleteNotification
        )
    }
}

/// One cell of the matrix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Case {
    /// Who acts.
    pub actor: ActorRole,
    /// For tenant tokens: the one scope the token carries; `None` means a token with every tenant scope.
    pub token_scope: Option<String>,
    /// The calendar (or the home of its owner) the operation addresses.
    pub calendar: CalendarRole,
    /// The surface the request arrives on.
    pub surface: Surface,
    /// What is done.
    pub operation: Operation,
}

impl Case {
    /// A case without a token scope.
    pub const fn new(actor: ActorRole, calendar: CalendarRole, surface: Surface, operation: Operation) -> Self {
        Self {
            actor,
            token_scope: None,
            calendar,
            surface,
            operation,
        }
    }

    /// The same case for a tenant token that carries only `scope` (for example `events:read`).
    #[must_use]
    pub fn with_scope(mut self, scope: &str) -> Self {
        self.token_scope = Some(scope.to_owned());
        self
    }

    /// Every combination of actor, calendar, surface and operation, in a stable order. Tenant tokens appear once,
    /// with every tenant scope; add [`Case::with_scope`] variants for the per-scope dimension.
    pub fn cartesian() -> Vec<Self> {
        let mut cases = Vec::with_capacity(
            ActorRole::ALL.len() * CalendarRole::ALL.len() * Surface::ALL.len() * Operation::ALL.len(),
        );
        for actor in ActorRole::ALL {
            for calendar in CalendarRole::ALL {
                for surface in Surface::ALL {
                    for operation in Operation::ALL {
                        cases.push(Self::new(*actor, *calendar, *surface, *operation));
                    }
                }
            }
        }
        cases
    }
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.actor)?;
        if let Some(scope) = &self.token_scope {
            write!(f, "[{scope}]")?;
        }
        write!(f, " {} on {} via {}", self.operation, self.calendar, self.surface)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------------------------

/// Problems with the expectations file or with resolving a case.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MatrixError {
    /// The file is not valid TOML of the documented shape.
    #[error("the expectations file cannot be read: {0}")]
    Parse(String),
    /// The file has another schema version than this parser reads.
    #[error("the expectations file has schema_version {found}, this harness reads {SCHEMA_VERSION}")]
    SchemaVersion {
        /// The version in the file.
        found: u32,
    },
    /// The file is well-formed but inconsistent (a missing or duplicated row, an unknown status).
    #[error("the expectations file is inconsistent: {0}")]
    Invalid(String),
    /// No rule covers the case (the file lacks a row the resolution needs).
    #[error("no rule covers the case `{0}`")]
    NoRule(String),
}

// ---------------------------------------------------------------------------------------------------------------
// Selectors and rows
// ---------------------------------------------------------------------------------------------------------------

/// A selector of one dimension in a rule row: every value (`"*"`) or a list of values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Selector<T> {
    /// Every value.
    #[default]
    Any,
    /// Exactly these values.
    Only(Vec<T>),
}

impl<T: PartialEq + Copy> Selector<T> {
    /// Whether the selector selects `value`.
    pub fn matches(&self, value: T) -> bool {
        match self {
            Self::Any => true,
            Self::Only(values) => values.contains(&value),
        }
    }

    /// The selected values out of `all`.
    pub fn expand(&self, all: &[T]) -> Vec<T> {
        all.iter().copied().filter(|value| self.matches(*value)).collect()
    }
}

impl<'de, T> Deserialize<'de> for Selector<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            One(String),
            Many(Vec<String>),
        }
        let names = match Raw::deserialize(deserializer)? {
            Raw::One(name) => vec![name],
            Raw::Many(names) => names,
        };
        if names.iter().any(|name| name == "*") {
            return if names.len() == 1 {
                Ok(Self::Any)
            } else {
                Err(de::Error::custom("`*` cannot be combined with other names"))
            };
        }
        names
            .iter()
            .map(|name| name.parse::<T>().map_err(de::Error::custom))
            .collect::<Result<Vec<_>, _>>()
            .map(Self::Only)
    }
}

/// One status of the status policy as written in the file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRow {
    http: String,
    #[serde(default)]
    challenge: bool,
    #[serde(default)]
    dav_precondition: Option<String>,
    #[serde(default)]
    problem_code: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusTable {
    allow: StatusRow,
    unauthenticated: StatusRow,
    hidden: StatusRow,
    forbidden: StatusRow,
    precondition_failed: StatusRow,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessRow {
    #[serde(default)]
    actor: Selector<ActorRole>,
    #[serde(default)]
    calendar: Selector<CalendarRole>,
    level: Level,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapRow {
    #[serde(default)]
    actor: Selector<ActorRole>,
    #[serde(default)]
    calendar: Selector<CalendarRole>,
    #[serde(default)]
    surface: Selector<Surface>,
    max: Level,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NeedRow {
    operation: Selector<Operation>,
    level: Level,
    #[serde(default = "default_target")]
    target: Target,
}

const fn default_target() -> Target {
    Target::Calendar
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AvailableRow {
    surface: Surface,
    operations: Selector<Operation>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeRow {
    surface: Surface,
    operation: Selector<Operation>,
    scope: String,
}

/// A name or a list of names in a row of the file.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Names {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminRow {
    operation: Names,
    scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminActorRow {
    actor: Selector<ActorRole>,
    rule: AdminRule,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenScopesRow {
    kind: TokenClass,
    scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRow {
    operation: Names,
    observed: PendingState,
    reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialSurfaceRow {
    surface: Surface,
    accepts: Vec<CredentialType>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialStateRow {
    state: Selector<CredentialState>,
    kind: Selector<CredentialType>,
    result: CredentialExpectation,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionRow {
    #[serde(default)]
    actor: Selector<ActorRole>,
    #[serde(default)]
    calendar: Selector<CalendarRole>,
    #[serde(default)]
    surface: Selector<Surface>,
    #[serde(default)]
    operation: Selector<Operation>,
    expect: Expectation,
    /// A reason why the details of the refusal (the precondition element of a 403, the challenge of a 401) are not
    /// checked for the cases the row covers: the refusal is not an authorization decision that has a privilege to name.
    #[serde(default)]
    waive_details: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownIssueRow {
    #[serde(default)]
    actor: Selector<ActorRole>,
    #[serde(default)]
    calendar: Selector<CalendarRole>,
    #[serde(default)]
    surface: Selector<Surface>,
    #[serde(default)]
    operation: Selector<Operation>,
    observed: Expectation,
    reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileModel {
    schema_version: u32,
    status: StatusTable,
    #[serde(default)]
    access: Vec<AccessRow>,
    #[serde(default)]
    cap: Vec<CapRow>,
    #[serde(default)]
    needs: Vec<NeedRow>,
    #[serde(default)]
    available: Vec<AvailableRow>,
    #[serde(default)]
    scope: Vec<ScopeRow>,
    #[serde(default)]
    exception: Vec<ExceptionRow>,
    #[serde(default)]
    known_issue: Vec<KnownIssueRow>,
    #[serde(default)]
    admin: Vec<AdminRow>,
    #[serde(default)]
    admin_actor: Vec<AdminActorRow>,
    #[serde(default)]
    token_scopes: Vec<TokenScopesRow>,
    #[serde(default)]
    pending: Vec<PendingRow>,
    #[serde(default)]
    credential_surface: Vec<CredentialSurfaceRow>,
    #[serde(default)]
    credential_state: Vec<CredentialStateRow>,
}

// ---------------------------------------------------------------------------------------------------------------
// Status policy
// ---------------------------------------------------------------------------------------------------------------

/// The HTTP status an expectation stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStatus {
    /// Exactly this status.
    Exact(u16),
    /// Any status of the class: `Class(2)` is 2xx.
    Class(u16),
}

impl HttpStatus {
    /// Parses `401` or `2xx`.
    fn parse(text: &str) -> Option<Self> {
        if let Some(class) = text.strip_suffix("xx") {
            let class: u16 = class.parse().ok()?;
            return (1..=5).contains(&class).then_some(Self::Class(class));
        }
        let status: u16 = text.parse().ok()?;
        (100..=599).contains(&status).then_some(Self::Exact(status))
    }

    /// Whether `status` is covered.
    pub const fn accepts(self, status: u16) -> bool {
        match self {
            Self::Exact(exact) => exact == status,
            Self::Class(class) => status / 100 == class,
        }
    }
}

impl fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(status) => write!(f, "{status}"),
            Self::Class(class) => write!(f, "{class}xx"),
        }
    }
}

/// What the status policy says about one expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRule {
    /// The HTTP status.
    pub http: HttpStatus,
    /// Whether the response carries a `WWW-Authenticate` challenge.
    pub challenge: bool,
    /// The DAV precondition element a DAV response names, for example `DAV:need-privileges`.
    pub dav_precondition: Option<String>,
    /// The problem code of an API or MCP response.
    pub problem_code: Option<String>,
    /// The reason, for reports.
    pub note: Option<String>,
}

impl StatusRule {
    fn from_row(name: &str, row: &StatusRow) -> Result<Self, MatrixError> {
        let http = HttpStatus::parse(&row.http)
            .ok_or_else(|| MatrixError::Invalid(format!("status.{name}.http `{}` is not `NNN` or `Nxx`", row.http)))?;
        Ok(Self {
            http,
            challenge: row.challenge,
            dav_precondition: row.dav_precondition.clone(),
            problem_code: row.problem_code.clone(),
            note: row.note.clone(),
        })
    }
}

/// The status policy of the file (PLAN 2.6): one rule per expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPolicy {
    rules: BTreeMap<Expectation, StatusRule>,
}

impl StatusPolicy {
    fn from_table(table: &StatusTable) -> Result<Self, MatrixError> {
        Ok(Self {
            rules: BTreeMap::from([
                (Expectation::Allow, StatusRule::from_row("allow", &table.allow)?),
                (
                    Expectation::Unauthenticated,
                    StatusRule::from_row("unauthenticated", &table.unauthenticated)?,
                ),
                (Expectation::Hidden, StatusRule::from_row("hidden", &table.hidden)?),
                (
                    Expectation::Forbidden,
                    StatusRule::from_row("forbidden", &table.forbidden)?,
                ),
                (
                    Expectation::PreconditionFailed,
                    StatusRule::from_row("precondition_failed", &table.precondition_failed)?,
                ),
            ]),
        })
    }

    /// The rule of an expectation.
    pub fn rule(&self, expectation: Expectation) -> Option<&StatusRule> {
        self.rules.get(&expectation)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------------------------------------------

/// Why a case has its expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The exception row with this index (counting from zero in file order) matched.
    Exception(usize),
    /// The operation does not exist on the surface.
    Unavailable,
    /// A tenant token lacks the scope the operation needs.
    MissingScope {
        /// The scope the operation needs.
        required: String,
    },
    /// The operation is open to every authenticated principal of the tenant (free-busy).
    Open,
    /// The actor has no access to the calendar.
    NoAccess,
    /// The access is lower than what the operation needs.
    TooLow {
        /// The effective access after caps.
        access: Level,
        /// The access the operation needs.
        needs: Level,
    },
    /// The access suffices.
    Sufficient {
        /// The effective access after caps.
        access: Level,
        /// The access the operation needs.
        needs: Level,
    },
}

/// The expectation of a case and the rule that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// What the case expects.
    pub expectation: Expectation,
    /// Why.
    pub source: Source,
}

/// An exception row of the expectations file as the report shows it: the cases it decides and the answer it gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionRule {
    /// The actors the row covers.
    pub actors: Vec<ActorRole>,
    /// The calendars the row covers.
    pub calendars: Vec<CalendarRole>,
    /// The surfaces the row covers.
    pub surfaces: Vec<Surface>,
    /// The operations the row covers.
    pub operations: Vec<Operation>,
    /// The expectation the row gives.
    pub expect: Expectation,
    /// Why the details of a refusal are not checked for these cases, when the row says so.
    pub waive_details: Option<String>,
}

/// The parsed expectations file.
#[derive(Debug, Clone)]
pub struct Expectations {
    status: StatusPolicy,
    access: Vec<AccessRow>,
    cap: Vec<CapRow>,
    needs: BTreeMap<Operation, (Level, Target)>,
    available: BTreeMap<Surface, BTreeSet<Operation>>,
    scope: BTreeMap<(Surface, Operation), String>,
    exception: Vec<ExceptionRow>,
    known_issue: Vec<KnownIssueRow>,
    admin: BTreeMap<String, Vec<String>>,
    admin_actor: BTreeMap<ActorRole, (AdminRule, Option<String>)>,
    token_scopes: BTreeMap<TokenClass, Vec<String>>,
    pending: BTreeMap<String, Pending>,
    credential_surface: BTreeMap<Surface, BTreeSet<CredentialType>>,
    credential_state: BTreeMap<(CredentialState, CredentialType), (CredentialExpectation, Option<String>)>,
}

/// An operation that a service does not offer yet, and what it answers meanwhile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// What the operation does today.
    pub state: PendingState,
    /// Why, and where it is tracked.
    pub reason: String,
}

/// A deviation of the server from the oracle that is known and documented: the server answers `observed` where the
/// oracle says otherwise, for the reason given. The matrix runs such a case against `observed`, so a deviation cannot
/// grow unnoticed, and fails when the server stops deviating, so a fixed deviation is removed from the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownIssue {
    /// The actors the deviation covers.
    pub actors: Vec<ActorRole>,
    /// The calendars the deviation covers.
    pub calendars: Vec<CalendarRole>,
    /// The surfaces the deviation covers.
    pub surfaces: Vec<Surface>,
    /// The operations the deviation covers.
    pub operations: Vec<Operation>,
    /// What the server does today.
    pub observed: Expectation,
    /// Why the server deviates and where it is tracked.
    pub reason: String,
}

impl From<&KnownIssueRow> for KnownIssue {
    fn from(row: &KnownIssueRow) -> Self {
        Self {
            actors: row.actor.expand(ActorRole::ALL),
            calendars: row.calendar.expand(CalendarRole::ALL),
            surfaces: row.surface.expand(Surface::ALL),
            operations: row.operation.expand(Operation::ALL),
            observed: row.observed,
            reason: row.reason.clone(),
        }
    }
}

impl Expectations {
    /// Parses and validates an expectations file.
    ///
    /// # Errors
    ///
    /// [`MatrixError`] when the text is not TOML of the documented shape, has another schema version, lacks a
    /// status of the policy, an operation or a surface, or contains a duplicated or conflicting default row.
    #[expect(
        clippy::too_many_lines,
        reason = "one pass over the tables of the file, each checked and indexed where it is read"
    )]
    pub fn parse(text: &str) -> Result<Self, MatrixError> {
        let model: FileModel = toml::from_str(text).map_err(|error| MatrixError::Parse(error.to_string()))?;
        if model.schema_version != SCHEMA_VERSION {
            return Err(MatrixError::SchemaVersion {
                found: model.schema_version,
            });
        }
        let status = StatusPolicy::from_table(&model.status)?;

        let mut seen_access = BTreeSet::new();
        for row in &model.access {
            for actor in row.actor.expand(ActorRole::ALL) {
                for calendar in row.calendar.expand(CalendarRole::ALL) {
                    if !seen_access.insert((actor, calendar)) {
                        return Err(MatrixError::Invalid(format!(
                            "two [[access]] rows cover `{actor}` on `{calendar}`"
                        )));
                    }
                }
            }
        }

        let mut needs = BTreeMap::new();
        for row in &model.needs {
            for operation in row.operation.expand(Operation::ALL) {
                if needs.insert(operation, (row.level, row.target)).is_some() {
                    return Err(MatrixError::Invalid(format!("two [[needs]] rows cover `{operation}`")));
                }
            }
        }
        if let Some(missing) = Operation::ALL.iter().find(|operation| !needs.contains_key(*operation)) {
            return Err(MatrixError::Invalid(format!("no [[needs]] row covers `{missing}`")));
        }

        let mut available: BTreeMap<Surface, BTreeSet<Operation>> = BTreeMap::new();
        for row in &model.available {
            if available.contains_key(&row.surface) {
                return Err(MatrixError::Invalid(format!(
                    "two [[available]] rows cover the surface `{}`",
                    row.surface
                )));
            }
            available.insert(row.surface, row.operations.expand(Operation::ALL).into_iter().collect());
        }
        if let Some(missing) = Surface::ALL.iter().find(|surface| !available.contains_key(*surface)) {
            return Err(MatrixError::Invalid(format!(
                "no [[available]] row covers the surface `{missing}`"
            )));
        }

        let mut scope = BTreeMap::new();
        for row in &model.scope {
            for operation in row.operation.expand(Operation::ALL) {
                if scope.insert((row.surface, operation), row.scope.clone()).is_some() {
                    return Err(MatrixError::Invalid(format!(
                        "two [[scope]] rows cover `{operation}` on `{}`",
                        row.surface
                    )));
                }
            }
        }

        let mut admin: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for row in &model.admin {
            if row.scopes.is_empty() {
                return Err(MatrixError::Invalid(
                    "an [[admin]] row lists no scope: an operation that needs no scope has no row".to_owned(),
                ));
            }
            let operations = match &row.operation {
                Names::One(name) => vec![name.clone()],
                Names::Many(names) => names.clone(),
            };
            for operation in operations {
                if admin.insert(operation.clone(), row.scopes.clone()).is_some() {
                    return Err(MatrixError::Invalid(format!("two [[admin]] rows cover `{operation}`")));
                }
            }
        }

        let mut admin_actor = BTreeMap::new();
        for row in &model.admin_actor {
            for actor in row.actor.expand(ActorRole::ALL) {
                if admin_actor.insert(actor, (row.rule, row.note.clone())).is_some() {
                    return Err(MatrixError::Invalid(format!(
                        "two [[admin_actor]] rows cover `{actor}`"
                    )));
                }
            }
        }
        if !admin_actor.is_empty()
            && let Some(missing) = ActorRole::ALL.iter().find(|actor| !admin_actor.contains_key(*actor))
        {
            return Err(MatrixError::Invalid(format!(
                "no [[admin_actor]] row covers `{missing}`"
            )));
        }

        let mut token_scopes: BTreeMap<TokenClass, Vec<String>> = BTreeMap::new();
        for row in &model.token_scopes {
            if row.scopes.is_empty() {
                return Err(MatrixError::Invalid(format!(
                    "the [[token_scopes]] row of `{}` lists no scope",
                    row.kind
                )));
            }
            if token_scopes.insert(row.kind, row.scopes.clone()).is_some() {
                return Err(MatrixError::Invalid(format!(
                    "two [[token_scopes]] rows cover `{}` tokens",
                    row.kind
                )));
            }
        }

        let mut pending = BTreeMap::new();
        for row in &model.pending {
            let operations = match &row.operation {
                Names::One(name) => vec![name.clone()],
                Names::Many(names) => names.clone(),
            };
            for operation in operations {
                let entry = Pending {
                    state: row.observed,
                    reason: row.reason.clone(),
                };
                if pending.insert(operation.clone(), entry).is_some() {
                    return Err(MatrixError::Invalid(format!(
                        "two [[pending]] rows cover `{operation}`"
                    )));
                }
            }
        }

        let mut credential_surface: BTreeMap<Surface, BTreeSet<CredentialType>> = BTreeMap::new();
        for row in &model.credential_surface {
            if credential_surface
                .insert(row.surface, row.accepts.iter().copied().collect())
                .is_some()
            {
                return Err(MatrixError::Invalid(format!(
                    "two [[credential_surface]] rows cover the surface `{}`",
                    row.surface
                )));
            }
        }
        if !credential_surface.is_empty()
            && let Some(missing) = Surface::ALL
                .iter()
                .find(|surface| !credential_surface.contains_key(*surface))
        {
            return Err(MatrixError::Invalid(format!(
                "no [[credential_surface]] row covers the surface `{missing}`"
            )));
        }

        let mut credential_state = BTreeMap::new();
        for row in &model.credential_state {
            for state in row.state.expand(CredentialState::ALL) {
                for kind in row.kind.expand(CredentialType::ALL) {
                    if credential_state
                        .insert((state, kind), (row.result, row.note.clone()))
                        .is_some()
                    {
                        return Err(MatrixError::Invalid(format!(
                            "two [[credential_state]] rows cover `{kind}` in the state `{state}`"
                        )));
                    }
                }
            }
        }
        if !credential_state.is_empty() {
            for state in CredentialState::ALL {
                for kind in CredentialType::ALL {
                    if !credential_state.contains_key(&(*state, *kind)) {
                        return Err(MatrixError::Invalid(format!(
                            "no [[credential_state]] row covers `{kind}` in the state `{state}`"
                        )));
                    }
                }
            }
        }

        Ok(Self {
            status,
            access: model.access,
            cap: model.cap,
            needs,
            available,
            scope,
            exception: model.exception,
            known_issue: model.known_issue,
            admin,
            admin_actor,
            token_scopes,
            pending,
            credential_surface,
            credential_state,
        })
    }

    /// The scopes a token of a kind may carry, as the file lists them (PLAN 2.6).
    pub fn token_scopes(&self, class: TokenClass) -> &[String] {
        self.token_scopes.get(&class).map_or(&[], Vec::as_slice)
    }

    /// How the administration operations treat an actor; `None` for a file without `[[admin_actor]]` rows.
    pub fn admin_rule(&self, actor: ActorRole) -> Option<(AdminRule, Option<&str>)> {
        self.admin_actor
            .get(&actor)
            .map(|(rule, note)| (*rule, note.as_deref()))
    }

    /// The administration operations that a service does not offer yet, with what they answer meanwhile.
    pub fn pending(&self, operation: &str) -> Option<&Pending> {
        self.pending.get(operation)
    }

    /// The operations listed as pending, by `operationId`, in alphabetical order.
    pub fn pending_operations(&self) -> Vec<&str> {
        self.pending.keys().map(String::as_str).collect()
    }

    /// Whether a surface takes credentials of a kind at all (a credential is bound to its surface, PLAN 2.6).
    pub fn surface_takes(&self, surface: Surface, kind: CredentialType) -> bool {
        self.credential_surface
            .get(&surface)
            .is_some_and(|kinds| kinds.contains(&kind))
    }

    /// What a surface does with a credential of a kind in a state: a credential that its surface does not take is refused
    /// whatever its state; otherwise the `[[credential_state]]` row decides. `None` when the file has no such row.
    pub fn credential_expectation(
        &self,
        surface: Surface,
        kind: CredentialType,
        state: CredentialState,
    ) -> Option<CredentialExpectation> {
        if self.credential_surface.contains_key(&surface) && !self.surface_takes(surface, kind) {
            return Some(CredentialExpectation::Refused);
        }
        self.credential_state.get(&(state, kind)).map(|(result, _)| *result)
    }

    /// What the file says about a kind of credential in a state on the surface that takes it (without the rule that a
    /// surface refuses what it does not take), and why when it says "not applicable".
    pub fn credential_state_rule(
        &self,
        kind: CredentialType,
        state: CredentialState,
    ) -> Option<(CredentialExpectation, Option<&str>)> {
        self.credential_state
            .get(&(state, kind))
            .map(|(result, note)| (*result, note.as_deref()))
    }

    /// The kinds of credential a surface takes.
    pub fn credentials_taken_by(&self, surface: Surface) -> Vec<CredentialType> {
        self.credential_surface
            .get(&surface)
            .map(|kinds| kinds.iter().copied().collect())
            .unwrap_or_default()
    }

    /// The scopes of which a token needs at least one for an administration operation of the management API (the operation
    /// is named by its `operationId`), if the file lists the operation.
    pub fn admin_scopes(&self, operation: &str) -> Option<&[String]> {
        self.admin.get(operation).map(Vec::as_slice)
    }

    /// The administration operations the file lists, by `operationId`, in alphabetical order.
    pub fn admin_operations(&self) -> Vec<&str> {
        self.admin.keys().map(String::as_str).collect()
    }

    /// The file that ships with the harness.
    ///
    /// # Errors
    ///
    /// [`MatrixError`] when the bundled file is invalid; the unit tests make sure it is not.
    pub fn bundled() -> Result<Self, MatrixError> {
        Self::parse(BUNDLED)
    }

    /// The status policy.
    pub const fn status(&self) -> &StatusPolicy {
        &self.status
    }

    /// The number of exception rows.
    pub const fn exception_count(&self) -> usize {
        self.exception.len()
    }

    /// The reason why the details of a refusal are not checked for a case, when the exception row that decided it says so.
    pub fn waiver(&self, resolution: &Resolution) -> Option<&str> {
        match resolution.source {
            Source::Exception(index) => self.exception.get(index).and_then(|row| row.waive_details.as_deref()),
            _ => None,
        }
    }

    /// The exception rows, in file order (the first matching row decides a case).
    pub fn exceptions(&self) -> Vec<ExceptionRule> {
        self.exception
            .iter()
            .map(|row| ExceptionRule {
                actors: row.actor.expand(ActorRole::ALL),
                calendars: row.calendar.expand(CalendarRole::ALL),
                surfaces: row.surface.expand(Surface::ALL),
                operations: row.operation.expand(Operation::ALL),
                expect: row.expect,
                waive_details: row.waive_details.clone(),
            })
            .collect()
    }

    /// The known deviations of the server, in file order.
    pub fn known_issues(&self) -> Vec<KnownIssue> {
        self.known_issue.iter().map(KnownIssue::from).collect()
    }

    /// The known deviation that covers a case, if any (the first row in file order).
    pub fn known_issue(&self, case: &Case) -> Option<KnownIssue> {
        self.known_issue
            .iter()
            .find(|row| {
                row.actor.matches(case.actor)
                    && row.calendar.matches(case.calendar)
                    && row.surface.matches(case.surface)
                    && row.operation.matches(case.operation)
            })
            .map(KnownIssue::from)
    }

    /// The access the default rules give an actor on a calendar on a surface, after the caps. Exception rows are not
    /// consulted: this is the level of the "effective access" of PLAN 2.6.
    pub fn level_of(&self, actor: ActorRole, calendar: CalendarRole, surface: Surface) -> Level {
        let mut access = self.access_of(actor, calendar);
        for row in &self.cap {
            if row.actor.matches(actor) && row.calendar.matches(calendar) && row.surface.matches(surface) {
                access = access.min(row.max);
            }
        }
        access
    }

    /// The token scope an operation needs on a surface, if the file names one.
    pub fn scope_of(&self, surface: Surface, operation: Operation) -> Option<&str> {
        self.scope.get(&(surface, operation)).map(String::as_str)
    }

    /// The operations that exist on a surface.
    pub fn operations_on(&self, surface: Surface) -> Vec<Operation> {
        self.available
            .get(&surface)
            .map(|operations| {
                Operation::ALL
                    .iter()
                    .copied()
                    .filter(|op| operations.contains(op))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What an operation needs: the level and whether it addresses a calendar or the home of its owner.
    pub fn need_of(&self, operation: Operation) -> Option<(Level, Target)> {
        self.needs.get(&operation).copied()
    }

    /// The access a default row grants `actor` on `calendar`.
    fn access_of(&self, actor: ActorRole, calendar: CalendarRole) -> Level {
        self.access
            .iter()
            .find(|row| row.actor.matches(actor) && row.calendar.matches(calendar))
            .map_or(Level::Nothing, |row| row.level)
    }

    /// The expectation of a case.
    ///
    /// # Errors
    ///
    /// [`MatrixError::NoRule`] when the file lacks a row the resolution needs (cannot happen for a file that
    /// passed [`Expectations::parse`], which checks every operation and surface).
    pub fn expected(&self, case: &Case) -> Result<Expectation, MatrixError> {
        self.resolve(case).map(|resolution| resolution.expectation)
    }

    /// The expectation of a case together with the rule that produced it.
    ///
    /// # Errors
    ///
    /// See [`Expectations::expected`].
    pub fn resolve(&self, case: &Case) -> Result<Resolution, MatrixError> {
        if let Some((index, row)) = self.exception.iter().enumerate().find(|(_, row)| {
            row.actor.matches(case.actor)
                && row.calendar.matches(case.calendar)
                && row.surface.matches(case.surface)
                && row.operation.matches(case.operation)
        }) {
            return Ok(Resolution {
                expectation: row.expect,
                source: Source::Exception(index),
            });
        }
        let derived = |expectation, source| Ok(Resolution { expectation, source });

        let available = self
            .available
            .get(&case.surface)
            .ok_or_else(|| MatrixError::NoRule(case.to_string()))?;
        if !available.contains(&case.operation) {
            return derived(Expectation::Hidden, Source::Unavailable);
        }

        // A token that carries one scope lacks the scope of every operation that needs another one: tenant tokens and the
        // principal tokens that hold single-scope variants. The scope is checked before anything about the caller or the
        // calendar (PLAN 2.6), so the answer is a refusal even where the calendar is invisible.
        if (case.actor == ActorRole::TenantToken || case.actor.principal_name().is_some())
            && let (Some(carried), Some(required)) =
                (&case.token_scope, self.scope.get(&(case.surface, case.operation)))
            && carried != required
        {
            return derived(
                Expectation::Forbidden,
                Source::MissingScope {
                    required: required.clone(),
                },
            );
        }

        let (needs, target) = *self
            .needs
            .get(&case.operation)
            .ok_or_else(|| MatrixError::NoRule(case.to_string()))?;
        if needs == Level::Nothing {
            return derived(Expectation::Allow, Source::Open);
        }
        let mut access = self.access_of(case.actor, case.calendar);
        if target == Target::Calendar {
            for row in &self.cap {
                if row.actor.matches(case.actor)
                    && row.calendar.matches(case.calendar)
                    && row.surface.matches(case.surface)
                {
                    access = access.min(row.max);
                }
            }
        }
        if access == Level::Nothing {
            derived(Expectation::Hidden, Source::NoAccess)
        } else if access < needs {
            derived(Expectation::Forbidden, Source::TooLow { access, needs })
        } else {
            derived(Expectation::Allow, Source::Sufficient { access, needs })
        }
    }

    /// The exception rows that no case of [`Case::cartesian`] reaches because earlier rows shadow them. A row
    /// that is listed here is dead weight and should be removed or moved up.
    pub fn shadowed_exceptions(&self) -> Vec<usize> {
        let mut used = BTreeSet::new();
        for case in Case::cartesian() {
            if let Ok(Resolution {
                source: Source::Exception(index),
                ..
            }) = self.resolve(&case)
            {
                used.insert(index);
            }
        }
        (0..self.exception.len())
            .filter(|index| !used.contains(index))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ActorRole::{
        Anonymous, DeclinedSharee, GranteeViaGroup, GroupMember, OtherTenantUser, OtherUser, Owner, PendingSharee,
        ServiceGrantee, ServicePrincipal, ServiceWriter, ShareeRead, ShareeReadWrite, SuspendedUser, SystemToken,
        TenantToken,
    };
    use CalendarRole::{Group, Managed, Mirror, Personal, Shared};
    use Expectation::{Allow, Forbidden, Hidden, Unauthenticated};
    use Operation::{
        CreateCalendar, CreateObject, DeleteCalendar, DeleteObject, FreeBusyQuery, ListGrants, ListObjects,
        PropPatchBinding, PutGrant, ReadCollection, ReadFeed, ReadInbox, ReadObject, RenameCalendar, ReplyInvite,
        ShareCalendar, UpdateCalendar, UpdateObject,
    };
    use Surface::{Api, Dav, Feed, Mcp};

    fn bundled() -> Expectations {
        Expectations::bundled().unwrap()
    }

    fn expect(actor: ActorRole, calendar: CalendarRole, surface: Surface, operation: Operation) -> Expectation {
        bundled()
            .expected(&Case::new(actor, calendar, surface, operation))
            .unwrap()
    }

    #[test]
    fn the_bundled_file_parses_and_carries_the_status_policy() {
        let expectations = bundled();
        let policy = expectations.status();
        let status = |expectation| policy.rule(expectation).unwrap().http;
        assert_eq!(status(Allow), HttpStatus::Class(2));
        assert_eq!(status(Unauthenticated), HttpStatus::Exact(401));
        assert_eq!(status(Hidden), HttpStatus::Exact(404));
        assert_eq!(status(Forbidden), HttpStatus::Exact(403));
        assert_eq!(status(Expectation::PreconditionFailed), HttpStatus::Exact(412));
        assert!(policy.rule(Unauthenticated).unwrap().challenge);
        let forbidden = policy.rule(Forbidden).unwrap();
        assert_eq!(forbidden.dav_precondition.as_deref(), Some("DAV:need-privileges"));
        assert_eq!(forbidden.problem_code.as_deref(), Some("forbidden"));
        assert!(status(Allow).accepts(201) && status(Allow).accepts(207) && !status(Allow).accepts(404));
        assert!(status(Hidden).accepts(404) && !status(Hidden).accepts(403));
        assert_eq!(status(Allow).to_string(), "2xx");
        assert!(expectations.exception_count() > 0);
    }

    #[test]
    fn every_case_of_the_cartesian_product_resolves() {
        let expectations = bundled();
        let cases = Case::cartesian();
        assert_eq!(
            cases.len(),
            ActorRole::ALL.len() * CalendarRole::ALL.len() * Surface::ALL.len() * Operation::ALL.len()
        );
        for case in &cases {
            expectations
                .expected(case)
                .unwrap_or_else(|error| panic!("{case}: {error}"));
        }
    }

    #[test]
    fn no_exception_row_is_dead_weight() {
        assert_eq!(bundled().shadowed_exceptions(), Vec::<usize>::new());
    }

    #[test]
    fn owners_and_sharees_get_what_the_plan_gives_them() {
        assert_eq!(expect(Owner, Personal, Dav, ReadObject), Allow);
        assert_eq!(expect(Owner, Personal, Dav, DeleteCalendar), Allow);
        assert_eq!(expect(Owner, Shared, Dav, ShareCalendar), Allow);
        assert_eq!(expect(Owner, Mirror, Dav, ReadObject), Allow);
        assert_eq!(
            expect(Owner, Mirror, Dav, CreateObject),
            Forbidden,
            "mirrors are read-only for principals"
        );
        assert_eq!(expect(Owner, Mirror, Api, CreateObject), Forbidden);
        assert_eq!(
            expect(Owner, Mirror, Dav, ShareCalendar),
            Forbidden,
            "mirrors cannot be shared"
        );
        assert_eq!(expect(Owner, Mirror, Api, PutGrant), Forbidden);
        assert_eq!(
            expect(Owner, Group, Dav, ReadObject),
            Hidden,
            "the owner is not a member of the group"
        );

        assert_eq!(expect(ShareeRead, Shared, Dav, ReadObject), Allow);
        assert_eq!(expect(ShareeRead, Shared, Dav, CreateObject), Forbidden);
        assert_eq!(
            expect(ShareeRead, Shared, Dav, PropPatchBinding),
            Allow,
            "per-binding properties"
        );
        assert_eq!(
            expect(ShareeRead, Shared, Dav, UpdateCalendar),
            Forbidden,
            "shared properties need write access"
        );
        assert_eq!(expect(ShareeReadWrite, Shared, Dav, CreateObject), Allow);
        assert_eq!(expect(ShareeReadWrite, Shared, Dav, DeleteObject), Allow);
        assert_eq!(
            expect(ShareeReadWrite, Shared, Dav, RenameCalendar),
            Hidden,
            "renaming the calendar itself is an API operation: PROPPATCH of the display name is the binding's"
        );
        assert_eq!(expect(ShareeReadWrite, Shared, Api, RenameCalendar), Forbidden);
        assert_eq!(
            expect(ShareeReadWrite, Shared, Dav, ShareCalendar),
            Forbidden,
            "re-sharing needs admin"
        );
        assert_eq!(expect(ShareeReadWrite, Shared, Dav, DeleteCalendar), Forbidden);
        assert_eq!(expect(GranteeViaGroup, Shared, Dav, ReadObject), Allow);
        assert_eq!(expect(GranteeViaGroup, Shared, Dav, UpdateObject), Forbidden);
        assert_eq!(expect(ShareeRead, Personal, Dav, ReadObject), Hidden);
    }

    #[test]
    fn service_principals_that_are_granted_calendars_work_through_the_api_and_mcp() {
        // The assistant: read_write on the calendar of the group, read on the managed one.
        for surface in [Api, Mcp] {
            assert_eq!(expect(ServiceGrantee, Group, surface, ReadObject), Allow, "{surface}");
            assert_eq!(expect(ServiceGrantee, Group, surface, CreateObject), Allow, "{surface}");
            assert_eq!(expect(ServiceGrantee, Group, surface, UpdateObject), Allow, "{surface}");
            assert_eq!(expect(ServiceGrantee, Group, surface, DeleteObject), Allow, "{surface}");
            assert_eq!(expect(ServiceGrantee, Managed, surface, ReadObject), Allow, "{surface}");
            assert_eq!(
                expect(ServiceGrantee, Managed, surface, CreateObject),
                Forbidden,
                "{surface}: a grant of read gives no write, whatever the surface"
            );
            assert_eq!(
                expect(ServiceGrantee, Managed, surface, DeleteObject),
                Forbidden,
                "{surface}"
            );
            assert_eq!(
                expect(ServiceGrantee, Personal, surface, ReadObject),
                Hidden,
                "{surface}: what nobody granted is not there"
            );
            assert_eq!(expect(ServiceGrantee, Shared, surface, ReadObject), Hidden, "{surface}");
        }
        assert_eq!(expect(ServiceGrantee, Group, Api, UpdateCalendar), Allow);
        assert_eq!(
            expect(ServiceGrantee, Group, Api, RenameCalendar),
            Forbidden,
            "renaming and sharing need admin, which a grant of read_write is not"
        );
        assert_eq!(expect(ServiceGrantee, Group, Api, PutGrant), Forbidden);
        assert_eq!(expect(ServiceGrantee, Group, Api, DeleteCalendar), Forbidden);
        assert_eq!(
            expect(ServiceGrantee, Group, Api, CreateCalendar),
            Hidden,
            "the grant is on the calendar, the home of the group is not theirs"
        );
        assert_eq!(expect(ServiceGrantee, Group, Feed, ReadFeed), Allow);
        assert_eq!(expect(ServiceGrantee, Personal, Feed, ReadFeed), Hidden);

        // The importer writes the managed calendar on the API and on MCP, where DAV would cap it at read.
        for surface in [Api, Mcp] {
            assert_eq!(expect(ServiceWriter, Managed, surface, ReadObject), Allow, "{surface}");
            assert_eq!(
                expect(ServiceWriter, Managed, surface, CreateObject),
                Allow,
                "{surface}"
            );
            assert_eq!(
                expect(ServiceWriter, Managed, surface, UpdateObject),
                Allow,
                "{surface}"
            );
            assert_eq!(
                expect(ServiceWriter, Managed, surface, DeleteObject),
                Allow,
                "{surface}"
            );
            assert_eq!(expect(ServiceWriter, Group, surface, ReadObject), Hidden, "{surface}");
        }
        assert_eq!(
            expect(ServiceWriter, Managed, Api, DeleteCalendar),
            Forbidden,
            "only the owner deletes a calendar"
        );

        // Neither has an app password, so DAV does not let them in: a grant is for the surfaces that take tokens.
        for actor in [ServiceGrantee, ServiceWriter] {
            for calendar in [Group, Managed] {
                assert_eq!(
                    expect(actor, calendar, Dav, ReadObject),
                    Unauthenticated,
                    "{actor} on {calendar}"
                );
                assert_eq!(
                    expect(actor, calendar, Dav, CreateObject),
                    Unauthenticated,
                    "{actor} on {calendar}"
                );
            }
        }
    }

    #[test]
    fn a_copy_changes_the_destination_and_so_needs_a_world_of_its_own() {
        // The copy of the owner lands in a calendar that others read (`projects`): left in a world that the next cases share, it
        // is found by a search of a sharee, which then looks like a leak of the event of another calendar.
        for operation in [
            Operation::CopyObjectFrom,
            Operation::CopyObjectTo,
            Operation::MoveObjectFrom,
            Operation::MoveObjectTo,
        ] {
            assert!(operation.mutates(), "{operation}");
        }
        for operation in [
            ReadCollection,
            ListObjects,
            ReadObject,
            FreeBusyQuery,
            ReadFeed,
            ReadInbox,
        ] {
            assert!(!operation.mutates(), "{operation}");
        }
    }

    #[test]
    fn group_members_and_managed_calendars_follow_the_caps() {
        assert_eq!(
            expect(GroupMember, Group, Dav, CreateObject),
            Allow,
            "group default access is read-write"
        );
        assert_eq!(expect(GroupMember, Group, Dav, DeleteCalendar), Forbidden);
        assert_eq!(expect(GroupMember, Managed, Dav, ReadObject), Allow);
        assert_eq!(
            expect(GroupMember, Managed, Dav, CreateObject),
            Forbidden,
            "managed calendars cap DAV at read"
        );
        assert_eq!(
            expect(GroupMember, Managed, Api, CreateObject),
            Forbidden,
            "the grant gives read only"
        );
        assert_eq!(expect(GroupMember, Personal, Dav, ReadObject), Hidden);
        assert_eq!(expect(ServicePrincipal, Managed, Api, DeleteCalendar), Allow);
        assert_eq!(
            expect(ServicePrincipal, Managed, Api, CreateObject),
            Allow,
            "managed calendars are written by API"
        );
        assert_eq!(
            expect(ServicePrincipal, Managed, Dav, ReadObject),
            Unauthenticated,
            "no app password"
        );
    }

    #[test]
    fn invitations_free_busy_and_homes() {
        assert_eq!(
            expect(PendingSharee, Shared, Dav, ReadObject),
            Hidden,
            "a pending invitation confers nothing"
        );
        assert_eq!(expect(PendingSharee, Shared, Dav, ReplyInvite), Allow);
        assert_eq!(expect(DeclinedSharee, Shared, Dav, ReplyInvite), Hidden);
        assert_eq!(expect(Owner, Shared, Dav, ReplyInvite), Hidden);
        assert_eq!(expect(OtherUser, Personal, Dav, ReadObject), Hidden);
        assert_eq!(
            expect(OtherUser, Personal, Dav, FreeBusyQuery),
            Allow,
            "free-busy is open within the tenant"
        );
        assert_eq!(
            expect(OtherTenantUser, Personal, Dav, FreeBusyQuery),
            Allow,
            "the request goes to the user's own outbox and is answered; the busy time of this tenant is not in the answer"
        );
        assert_eq!(
            expect(OtherTenantUser, Personal, Dav, ReadCollection),
            Hidden,
            "nothing else of another tenant is visible"
        );
        assert_eq!(expect(Owner, Personal, Dav, ReadInbox), Allow);
        assert_eq!(
            expect(GroupMember, Group, Dav, ReadInbox),
            Hidden,
            "another principal's home"
        );
        assert_eq!(expect(ShareeRead, Shared, Dav, ReadInbox), Hidden);
        assert_eq!(expect(Owner, Personal, Dav, CreateCalendar), Allow);
        assert_eq!(
            expect(Owner, Mirror, Dav, CreateCalendar),
            Allow,
            "caps do not apply to the home"
        );
    }

    #[test]
    fn credentials_tenants_and_surfaces_decide_before_permissions() {
        assert_eq!(expect(Anonymous, Personal, Dav, ReadObject), Unauthenticated);
        assert_eq!(expect(Anonymous, Personal, Api, ReadCollection), Unauthenticated);
        assert_eq!(
            expect(Anonymous, Personal, Feed, ReadFeed),
            Hidden,
            "unknown feed tokens answer 404"
        );
        assert_eq!(expect(SuspendedUser, Personal, Dav, ReadObject), Unauthenticated);
        assert_eq!(expect(SuspendedUser, Personal, Api, ReadCollection), Unauthenticated);
        assert_eq!(expect(OtherTenantUser, Personal, Dav, ReadObject), Hidden);
        assert_eq!(expect(OtherTenantUser, Personal, Api, ReadCollection), Hidden);
        assert_eq!(
            expect(SystemToken, Personal, Api, ReadCollection),
            Forbidden,
            "system tokens never read calendars: authenticated, but without the scope"
        );
        assert_eq!(
            expect(SystemToken, Personal, Mcp, ReadCollection),
            Hidden,
            "MCP is for principals: a token that acts as nobody is offered no tools"
        );
        assert_eq!(expect(SystemToken, Personal, Dav, ReadObject), Unauthenticated);
        assert_eq!(
            expect(TenantToken, Personal, Dav, ReadObject),
            Unauthenticated,
            "tokens do not work on DAV"
        );
        assert_eq!(
            expect(Owner, Personal, Dav, ListGrants),
            Hidden,
            "list_grants exists on the API only"
        );
        assert_eq!(expect(Owner, Personal, Mcp, ReadCollection), Allow);
        assert_eq!(expect(Owner, Personal, Mcp, DeleteCalendar), Hidden);
    }

    #[test]
    fn tenant_tokens_administer_calendars_but_reach_events_of_group_and_managed_calendars_only() {
        let case = |calendar, operation| Case::new(TenantToken, calendar, Api, operation);
        let scoped = |calendar, operation, scope: &str| case(calendar, operation).with_scope(scope);
        let expectations = bundled();
        let expected = |case: Case| expectations.expected(&case).unwrap();
        assert_eq!(expected(case(Personal, ReadCollection)), Allow);
        assert_eq!(expected(case(Personal, ListObjects)), Forbidden);
        assert_eq!(expected(case(Shared, CreateObject)), Forbidden);
        assert_eq!(expected(case(Group, ListObjects)), Allow);
        assert_eq!(expected(case(Managed, CreateObject)), Allow);
        assert_eq!(expected(case(Mirror, PutGrant)), Forbidden);
        assert_eq!(expected(case(Shared, PutGrant)), Allow);
        assert_eq!(expected(scoped(Personal, ReadCollection, "calendars:read")), Allow);
        assert_eq!(expected(scoped(Personal, ReadCollection, "events:read")), Forbidden);
        assert_eq!(expected(scoped(Group, ListObjects, "events:read")), Allow);
        assert_eq!(expected(scoped(Group, ListObjects, "calendars:read")), Forbidden);
        assert_eq!(expected(scoped(Managed, CreateObject, "events:read")), Forbidden);
        assert_eq!(expected(scoped(Managed, CreateObject, "events:write")), Allow);
        assert_eq!(expected(scoped(Shared, ListGrants, "calendars:write")), Allow);
        assert_eq!(expected(Case::new(TenantToken, Group, Mcp, ReadCollection)), Hidden);
        let missing = expectations
            .resolve(&scoped(Group, ListObjects, "calendars:read"))
            .unwrap();
        assert_eq!(
            missing.source,
            Source::MissingScope {
                required: "events:read".to_owned()
            }
        );
    }

    #[test]
    fn resolutions_explain_themselves() {
        let expectations = bundled();
        let resolve = |case: Case| expectations.resolve(&case).unwrap();
        let sufficient = resolve(Case::new(ShareeReadWrite, Shared, Dav, CreateObject));
        assert_eq!(
            sufficient.source,
            Source::Sufficient {
                access: Level::ReadWrite,
                needs: Level::ReadWrite
            }
        );
        let too_low = resolve(Case::new(ShareeRead, Shared, Dav, CreateObject));
        assert_eq!(
            too_low.source,
            Source::TooLow {
                access: Level::Read,
                needs: Level::ReadWrite
            }
        );
        assert_eq!(
            resolve(Case::new(OtherUser, Personal, Dav, ReadObject)).source,
            Source::NoAccess
        );
        assert_eq!(
            resolve(Case::new(Owner, Personal, Dav, ListGrants)).source,
            Source::Unavailable
        );
        assert_eq!(
            resolve(Case::new(OtherUser, Personal, Dav, FreeBusyQuery)).source,
            Source::Open
        );
        assert!(matches!(
            resolve(Case::new(Anonymous, Personal, Dav, ReadObject)).source,
            Source::Exception(_)
        ));
        assert_eq!(
            Case::new(TenantToken, Personal, Api, ReadObject)
                .with_scope("events:read")
                .to_string(),
            "tenant_token[events:read] read_object on personal via api"
        );
    }

    /// A file with the minimal valid content, to which tests add or remove rows.
    fn minimal() -> String {
        let mut file = String::from(
            "schema_version = 1\n\
             [status.allow]\nhttp = \"2xx\"\n\
             [status.unauthenticated]\nhttp = \"401\"\nchallenge = true\n\
             [status.hidden]\nhttp = \"404\"\n\
             [status.forbidden]\nhttp = \"403\"\n\
             [status.precondition_failed]\nhttp = \"412\"\n\
             [[needs]]\noperation = \"*\"\nlevel = \"read\"\n",
        );
        file.extend(
            Surface::ALL
                .iter()
                .map(|surface| format!("[[available]]\nsurface = \"{surface}\"\noperations = \"*\"\n")),
        );
        file
    }

    #[test]
    fn a_minimal_file_is_valid_and_defaults_to_hidden() {
        let expectations = Expectations::parse(&minimal()).unwrap();
        let case = Case::new(Owner, Personal, Dav, ReadObject);
        assert_eq!(
            expectations.expected(&case).unwrap(),
            Hidden,
            "no access row: no access"
        );
        let with_access = format!("{}[[access]]\nactor = \"owner\"\nlevel = \"owner\"\n", minimal());
        let expectations = Expectations::parse(&with_access).unwrap();
        assert_eq!(expectations.expected(&case).unwrap(), Allow);
    }

    /// The reason of a file that is well-formed but inconsistent; any other outcome fails, so that a file rejected for another
    /// reason than the one a test means does not pass for it.
    fn inconsistency(text: &str) -> String {
        match Expectations::parse(text) {
            Err(MatrixError::Invalid(reason)) => reason,
            other => panic!("expected an inconsistent file, got {other:?}"),
        }
    }

    #[test]
    fn broken_files_are_rejected_with_a_reason() {
        let parse = |text: &str| Expectations::parse(text).unwrap_err();
        assert!(matches!(parse("this is not toml ["), MatrixError::Parse(_)));
        assert_eq!(
            parse(&minimal().replace("schema_version = 1", "schema_version = 2")),
            MatrixError::SchemaVersion { found: 2 }
        );
        assert_eq!(
            inconsistency(&minimal().replace("\"2xx\"", "\"two\"")),
            "status.allow.http `two` is not `NNN` or `Nxx`"
        );
        assert_eq!(
            inconsistency(&minimal().replace("\"2xx\"", "\"7xx\"")),
            "status.allow.http `7xx` is not `NNN` or `Nxx`"
        );
        let unknown_field = format!(
            "{}[[access]]\nactor = \"owner\"\nlevel = \"owner\"\nfoo = 1\n",
            minimal()
        );
        assert!(matches!(parse(&unknown_field), MatrixError::Parse(_)));
        let unknown_actor = format!("{}[[access]]\nactor = \"nobody\"\nlevel = \"owner\"\n", minimal());
        assert!(matches!(parse(&unknown_actor), MatrixError::Parse(_)));
        let star_and_name = format!(
            "{}[[access]]\nactor = [\"*\", \"owner\"]\nlevel = \"owner\"\n",
            minimal()
        );
        assert!(matches!(parse(&star_and_name), MatrixError::Parse(_)));
        let duplicate_access = format!(
            "{}[[access]]\nactor = \"owner\"\nlevel = \"owner\"\n[[access]]\ncalendar = \"personal\"\nlevel = \"read\"\n",
            minimal()
        );
        assert_eq!(
            inconsistency(&duplicate_access),
            "two [[access]] rows cover `owner` on `personal`",
            "the second row covers every actor, the owner among them"
        );
        let duplicate_needs = format!(
            "{}[[needs]]\noperation = \"read_object\"\nlevel = \"owner\"\n",
            minimal()
        );
        assert_eq!(
            inconsistency(&duplicate_needs),
            "two [[needs]] rows cover `read_object`"
        );
        let without_needs = minimal().replace(
            "[[needs]]\noperation = \"*\"\nlevel = \"read\"\n",
            "[[needs]]\noperation = \"read_object\"\nlevel = \"read\"\n",
        );
        let reason = inconsistency(&without_needs);
        assert!(reason.starts_with("no [[needs]] row covers `"), "{reason}");
        let without_surface = minimal().replace("[[available]]\nsurface = \"rsvp\"\noperations = \"*\"\n", "");
        assert_eq!(
            inconsistency(&without_surface),
            "no [[available]] row covers the surface `rsvp`"
        );
        let duplicate_surface = format!("{}[[available]]\nsurface = \"dav\"\noperations = []\n", minimal());
        assert_eq!(
            inconsistency(&duplicate_surface),
            "two [[available]] rows cover the surface `dav`"
        );
        let duplicate_scope = format!(
            "{}[[scope]]\nsurface = \"api\"\noperation = \"read_object\"\nscope = \"a\"\n[[scope]]\nsurface = \"api\"\noperation = \"*\"\nscope = \"b\"\n",
            minimal()
        );
        assert_eq!(
            inconsistency(&duplicate_scope),
            "two [[scope]] rows cover `read_object` on `api`"
        );
        // The same operation on two surfaces is two rows, not a duplicate.
        let two_surfaces = format!(
            "{}[[scope]]\nsurface = \"api\"\noperation = \"read_object\"\nscope = \"a\"\n[[scope]]\nsurface = \"mcp\"\noperation = \"read_object\"\nscope = \"b\"\n",
            minimal()
        );
        let expectations = Expectations::parse(&two_surfaces).unwrap();
        assert_eq!(expectations.scope_of(Api, ReadObject), Some("a"));
        assert_eq!(expectations.scope_of(Mcp, ReadObject), Some("b"));
        let without_status = minimal().replace("[status.hidden]\nhttp = \"404\"\n", "");
        assert!(matches!(parse(&without_status), MatrixError::Parse(_)));
    }

    #[test]
    fn the_tables_of_actors_tokens_pending_operations_and_credentials_are_complete_and_unique() {
        let with = |rows: &str| format!("{}{rows}", minimal());
        // Each of these tables may be left out, but a file that has one has a row for every actor, surface or state of it, and
        // never two.
        let admin_actor = "[[admin_actor]]\nactor = \"*\"\nrule = \"refused\"\n";
        assert!(Expectations::parse(&with(admin_actor)).is_ok());
        let reason = inconsistency(&with("[[admin_actor]]\nactor = \"owner\"\nrule = \"refused\"\n"));
        assert!(reason.starts_with("no [[admin_actor]] row covers `"), "{reason}");
        assert_eq!(
            inconsistency(&with(&format!(
                "{admin_actor}[[admin_actor]]\nactor = \"owner\"\nrule = \"by_scope\"\n"
            ))),
            "two [[admin_actor]] rows cover `owner`"
        );

        let token = |kind: &str, scopes: &str| format!("[[token_scopes]]\nkind = \"{kind}\"\nscopes = {scopes}\n");
        assert!(Expectations::parse(&with(&token("tenant", "[\"a\"]"))).is_ok());
        assert_eq!(
            inconsistency(&with(&token("tenant", "[]"))),
            "the [[token_scopes]] row of `tenant` lists no scope"
        );
        assert_eq!(
            inconsistency(&with(&format!(
                "{}{}",
                token("tenant", "[\"a\"]"),
                token("tenant", "[\"b\"]")
            ))),
            "two [[token_scopes]] rows cover `tenant` tokens"
        );

        let pending = "[[pending]]\noperation = \"listProviders\"\nobserved = \"not_implemented\"\nreason = \"r\"\n";
        assert!(Expectations::parse(&with(pending)).is_ok());
        assert_eq!(
            inconsistency(&with(&format!(
                "{pending}[[pending]]\noperation = [\"getProvider\", \"listProviders\"]\nobserved = \"not_implemented\"\nreason = \"r\"\n"
            ))),
            "two [[pending]] rows cover `listProviders`"
        );

        let surface_row =
            |surface: &str| format!("[[credential_surface]]\nsurface = \"{surface}\"\naccepts = [\"app_password\"]\n");
        let surfaces: String = Surface::ALL
            .iter()
            .map(|surface| surface_row(surface.as_str()))
            .collect();
        assert!(Expectations::parse(&with(&surfaces)).is_ok());
        assert_eq!(
            inconsistency(&with(&surfaces.replace(&surface_row("feed"), ""))),
            "no [[credential_surface]] row covers the surface `feed`"
        );
        assert_eq!(
            inconsistency(&with(&format!("{surfaces}{}", surface_row("dav")))),
            "two [[credential_surface]] rows cover the surface `dav`"
        );

        let states = "[[credential_state]]\nstate = \"*\"\nkind = \"*\"\nresult = \"refused\"\n";
        assert!(Expectations::parse(&with(states)).is_ok());
        let reason = inconsistency(&with(
            "[[credential_state]]\nstate = \"valid\"\nkind = \"*\"\nresult = \"accepted\"\n",
        ));
        assert!(reason.starts_with("no [[credential_state]] row covers `"), "{reason}");
        assert_eq!(
            inconsistency(&with(&format!(
                "{states}[[credential_state]]\nstate = \"valid\"\nkind = \"app_password\"\nresult = \"accepted\"\n"
            ))),
            "two [[credential_state]] rows cover `app_password` in the state `valid`"
        );
    }

    #[test]
    fn administration_operations_are_listed_with_the_scopes_they_accept() {
        let expectations = bundled();
        assert_eq!(
            expectations.admin_scopes("getTenant"),
            Some(&["system:tenants".to_owned(), "principals:read".to_owned()][..])
        );
        assert_eq!(
            expectations.admin_scopes("listWebhooks"),
            Some(&["webhooks:manage".to_owned()][..])
        );
        assert_eq!(
            expectations.admin_scopes("getCalendar"),
            None,
            "calendar operations are rows of the matrix, not of this table"
        );
        assert_eq!(expectations.admin_operations().len(), 47);
        let sorted = {
            let mut names = expectations.admin_operations();
            names.sort_unstable();
            names
        };
        assert_eq!(sorted, expectations.admin_operations());
    }

    #[test]
    fn an_administration_operation_is_listed_once_and_with_a_scope() {
        let parse = |rows: &str| Expectations::parse(&format!("{}{rows}", minimal())).unwrap_err();
        assert!(matches!(
            parse(
                "[[admin]]\noperation = \"a\"\nscopes = [\"x\"]\n[[admin]]\noperation = [\"a\", \"b\"]\nscopes = [\"y\"]\n"
            ),
            MatrixError::Invalid(_)
        ));
        assert!(matches!(
            parse("[[admin]]\noperation = \"a\"\nscopes = []\n"),
            MatrixError::Invalid(_)
        ));
        assert!(matches!(parse("[[admin]]\noperation = \"a\"\n"), MatrixError::Parse(_)));
        let ok = Expectations::parse(&format!(
            "{}[[admin]]\noperation = [\"a\", \"b\"]\nscopes = [\"x\"]\n",
            minimal()
        ))
        .unwrap();
        assert_eq!(ok.admin_operations(), vec!["a", "b"]);
    }

    #[test]
    fn selectors_select_expand_and_default_to_everything() {
        let any: Selector<Surface> = Selector::default();
        assert!(any.matches(Surface::Mcp));
        assert_eq!(any.expand(Surface::ALL).len(), Surface::ALL.len());
        let some = Selector::Only(vec![Surface::Dav, Surface::Api]);
        assert!(some.matches(Surface::Dav) && !some.matches(Surface::Feed));
        assert_eq!(some.expand(Surface::ALL), vec![Surface::Dav, Surface::Api]);
        assert_eq!(HttpStatus::parse("204"), Some(HttpStatus::Exact(204)));
        assert_eq!(HttpStatus::parse("5xx"), Some(HttpStatus::Class(5)));
        assert_eq!(HttpStatus::parse("99"), None);
        assert_eq!(HttpStatus::parse("xx"), None);
    }

    /// The oracle must not be computed by the code it judges: this module never uses the authorization functions
    /// of `davhaven_domain` (PLAN 3.2, `ENGINEERING_RULES` R9). The needles are split so that this test does not
    /// match itself.
    #[test]
    fn the_oracle_never_uses_the_authorization_code_under_test() {
        let needles = [
            concat!("davhaven_domain::", "authz"),
            concat!("authz", "::decide"),
            concat!("effective_", "access("),
            concat!("privileges", "("),
        ];
        for (number, line) in include_str!("matrix.rs").lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for needle in needles {
                assert!(
                    !line.contains(needle),
                    "matrix.rs line {} uses `{needle}`: {line}",
                    number + 1
                );
            }
        }
    }
}
