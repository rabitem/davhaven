//! The single authorization decision point: access levels, privileges, operations and `decide`.
//!
//! Every protocol surface answers "may this caller do this to that calendar?" through [`decide`], a pure function
//! of the caller ([`Subject`]), the surface ([`Channel`]), facts about the calendar ([`AccessFacts`]) and the
//! [`Operation`]. The application layer loads `AccessFacts` once per request; DAV derives
//! `current-user-privilege-set` from [`privileges`]; protocol crates never decide on their own. Operations of the
//! tenant administration API that are not bound to a calendar go through [`decide_admin`].
//!
//! # Status policy (PLAN 2.6)
//!
//! * unauthenticated callers never reach this module (401);
//! * no read visibility, including other tenants' and unknown resources: [`Decision::Hidden`] (404);
//! * visible but not permitted: [`Decision::Forbidden`] with the missing privilege (403);
//! * a stale precondition (412) is not an authorization concern.
//!
//! # Order of checks
//!
//! 1. Is this actor allowed to use this channel, and does the operation exist on it? If not: `Hidden`.
//! 2. Does the token carry the scope the operation needs (API and MCP)? If not: `Forbidden`. The scope check
//!    comes first and ignores the facts, so a missing scope never reveals whether a calendar exists.
//! 3. Does the caller see the calendar at all (read access, or a pending invitation for `ReplyInvite`)? If not:
//!    `Hidden`.
//! 4. Is the access level high enough, and do calendar kind and tenant settings allow the operation? If not:
//!    `Forbidden`.

use core::fmt;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::context::{Actor, Channel, RequestContext};
use crate::entities::{CalendarKind, Grant, GrantAccess, GrantStatus, PrincipalKind};
use crate::ids::{BindingId, PrincipalId};
use crate::scope::{Scope, ScopeSet};
use crate::settings::TenantSettings;

text_enum!(
    /// How much a principal may do with a calendar, in increasing order.
    Access [] {
        /// Free-busy queries only; nothing else about the calendar is visible.
        FreeBusy => "free_busy",
        /// Read events.
        Read => "read",
        /// Read and write events.
        ReadWrite => "read_write",
        /// Read, write, share and rename.
        Admin => "admin",
        /// The owner of the calendar: everything, including deleting the calendar.
        Owner => "owner",
    }
);

impl From<GrantAccess> for Access {
    fn from(access: GrantAccess) -> Self {
        match access {
            GrantAccess::Read => Self::Read,
            GrantAccess::ReadWrite => Self::ReadWrite,
            GrantAccess::Admin => Self::Admin,
        }
    }
}

text_enum!(
    /// A WebDAV/CalDAV privilege as reported in `current-user-privilege-set`, plus the CalendarServer and
    /// scheduling privileges Davhaven uses.
    Privilege [] {
        /// `DAV:read`.
        Read => "read",
        /// `DAV:read-current-user-privilege-set`.
        ReadCurrentUserPrivilegeSet => "read-current-user-privilege-set",
        /// `CALDAV:read-free-busy`.
        ReadFreeBusy => "read-free-busy",
        /// `DAV:write-content`.
        WriteContent => "write-content",
        /// `DAV:write-properties`.
        WriteProperties => "write-properties",
        /// `DAV:bind`: add members to a collection.
        Bind => "bind",
        /// `DAV:unbind`: remove members from a collection.
        Unbind => "unbind",
        /// `CS:share`: share the calendar with others.
        Share => "share",
        /// `CALDAV:schedule-send`: send scheduling messages from the outbox.
        ScheduleSend => "schedule-send",
        /// `CALDAV:schedule-deliver`: deliver scheduling messages into the inbox.
        ScheduleDeliver => "schedule-deliver",
    }
);

impl Privilege {
    const fn bit(self) -> u16 {
        let index: u16 = match self {
            Self::Read => 0,
            Self::ReadCurrentUserPrivilegeSet => 1,
            Self::ReadFreeBusy => 2,
            Self::WriteContent => 3,
            Self::WriteProperties => 4,
            Self::Bind => 5,
            Self::Unbind => 6,
            Self::Share => 7,
            Self::ScheduleSend => 8,
            Self::ScheduleDeliver => 9,
        };
        1 << index
    }
}

/// A set of privileges. Serialized as an array of privilege names in declaration order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(from = "Vec<Privilege>", into = "Vec<Privilege>")]
#[schemars(with = "Vec<Privilege>")]
pub struct PrivilegeSet(u16);

impl PrivilegeSet {
    /// The empty set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Builds a set from a slice of privileges.
    pub fn of(privileges: &[Privilege]) -> Self {
        privileges.iter().copied().collect()
    }

    /// Whether the set contains `privilege`.
    pub const fn contains(self, privilege: Privilege) -> bool {
        self.0 & privilege.bit() != 0
    }

    /// Adds `privilege`.
    pub fn insert(&mut self, privilege: Privilege) {
        self.0 |= privilege.bit();
    }

    /// Whether every privilege of `self` is also in `other`.
    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The number of privileges in the set.
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// The privileges in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Privilege> {
        Privilege::ALL
            .iter()
            .copied()
            .filter(move |privilege| self.contains(*privilege))
    }
}

impl fmt::Debug for PrivilegeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter().map(Privilege::as_str)).finish()
    }
}

impl FromIterator<Privilege> for PrivilegeSet {
    fn from_iter<T: IntoIterator<Item = Privilege>>(iter: T) -> Self {
        let mut set = Self::empty();
        for privilege in iter {
            set.insert(privilege);
        }
        set
    }
}

impl From<Vec<Privilege>> for PrivilegeSet {
    fn from(privileges: Vec<Privilege>) -> Self {
        privileges.into_iter().collect()
    }
}

impl From<PrivilegeSet> for Vec<Privilege> {
    fn from(set: PrivilegeSet) -> Self {
        set.iter().collect()
    }
}

impl<const N: usize> From<[Privilege; N]> for PrivilegeSet {
    fn from(privileges: [Privilege; N]) -> Self {
        privileges.into_iter().collect()
    }
}

text_enum!(
    /// The kind of DAV resource whose privileges are asked for. New kinds are added without a new major version, so
    /// callers outside this crate match with a catch-all arm.
    #[non_exhaustive]
    ResourceKind [] {
        /// A principal resource.
        Principal => "principal",
        /// A calendar home.
        Home => "home",
        /// A calendar collection.
        Collection => "collection",
        /// A calendar object resource.
        Object => "object",
        /// The scheduling inbox.
        Inbox => "inbox",
        /// The scheduling outbox.
        Outbox => "outbox",
        /// The notification collection.
        Notifications => "notifications",
        /// One item of the scheduling inbox.
        InboxItem => "inbox_item",
        /// One notification of the notification collection.
        Notification => "notification",
    }
);

text_enum!(
    /// An operation on a calendar or on a principal's scheduling collections: one variant per row of the
    /// permission matrix (PLAN 3.2). Tenant administration lives in [`AdminOperation`].
    Operation [] {
        /// Read a calendar's properties (PROPFIND on the collection, API get/list of calendars, MCP `list_calendars`).
        ReadCollection => "read_collection",
        /// List or query objects (calendar-query, multiget, sync-collection, API list and changes, MCP
        /// `list_events` and `search_events`).
        ListObjects => "list_objects",
        /// Read one object (GET, PROPFIND, API get by key, MCP `get_event`).
        ReadObject => "read_object",
        /// Free-busy queries (REPORT, outbox POST, MCP `free_busy` and `find_free_slots`): any principal of the
        /// tenant may ask, whatever access they have.
        FreeBusyQuery => "free_busy_query",
        /// Create an object (PUT of a new resource, API/MCP create).
        CreateObject => "create_object",
        /// Replace or change an object (PUT over an existing resource, API/MCP update).
        UpdateObject => "update_object",
        /// Delete an object (DELETE, API/MCP delete).
        DeleteObject => "delete_object",
        /// Batch upsert through the API.
        BatchUpsert => "batch_upsert",
        /// The source side of MOVE: the object leaves its calendar.
        MoveObjectFrom => "move_object_from",
        /// The target side of MOVE: the object arrives in the calendar.
        MoveObjectTo => "move_object_to",
        /// The source side of COPY: the object is read.
        CopyObjectFrom => "copy_object_from",
        /// The target side of COPY: a new object is created.
        CopyObjectTo => "copy_object_to",
        /// Answer an invitation on behalf of the caller (API and MCP `respond_to_invitation`).
        RespondToInvitation => "respond_to_invitation",
        /// PROPPATCH of per-binding properties (display name, color, order, transparency, default alarms, dead
        /// properties): always allowed for the binding's principal.
        PropPatchBinding => "prop_patch_binding",
        /// PROPPATCH of shared calendar properties and API updates of calendar settings.
        UpdateCalendar => "update_calendar",
        /// Change the display name of the calendar itself (not the per-binding one).
        RenameCalendar => "rename_calendar",
        /// MKCALENDAR, extended MKCOL or API creation of a calendar in a home.
        CreateCalendar => "create_calendar",
        /// Delete the calendar for everyone (DAV DELETE by the owner, API delete).
        DeleteCalendar => "delete_calendar",
        /// DELETE of a bound collection by someone who is not the owner: the binding disappears for them only, unless
        /// the calendar is required for them (an accepted grant with the `required` flag reaches them): then it is
        /// refused.
        RemoveBinding => "remove_binding",
        /// CalendarServer sharing: `CS:share` set and remove.
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
        /// Render a subscription feed.
        ReadFeed => "read_feed",
        /// Open an RSVP page.
        RsvpView => "rsvp_view",
        /// Answer on an RSVP page.
        RsvpAnswer => "rsvp_answer",
    }
);

/// What an operation needs on a given channel in terms of token scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRule {
    /// The operation does not exist on this channel.
    Unavailable,
    /// The channel's credential kind already binds the caller; scopes are not checked.
    Unscoped,
    /// The token must carry this scope.
    Required(Scope),
}

/// The access level and privilege an operation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    /// The minimum effective access.
    pub access: Access,
    /// The privilege reported as missing when the access is too low.
    pub privilege: Privilege,
}

impl Operation {
    /// The access level and privilege the operation needs, or `None` for operations that are granted
    /// independently of calendar access (per-binding properties, removing one's own binding, answering an
    /// invitation, RSVP).
    pub const fn requirement(self) -> Option<Requirement> {
        const fn need(access: Access, privilege: Privilege) -> Requirement {
            Requirement { access, privilege }
        }
        match self {
            Self::ReadCollection | Self::ListObjects | Self::ReadObject | Self::CopyObjectFrom | Self::ReadFeed => {
                Some(need(Access::Read, Privilege::Read))
            }
            Self::FreeBusyQuery => Some(need(Access::FreeBusy, Privilege::ReadFreeBusy)),
            Self::CreateObject | Self::MoveObjectTo | Self::CopyObjectTo => {
                Some(need(Access::ReadWrite, Privilege::Bind))
            }
            Self::UpdateObject | Self::BatchUpsert | Self::RespondToInvitation => {
                Some(need(Access::ReadWrite, Privilege::WriteContent))
            }
            Self::DeleteObject | Self::MoveObjectFrom => Some(need(Access::ReadWrite, Privilege::Unbind)),
            Self::UpdateCalendar => Some(need(Access::ReadWrite, Privilege::WriteProperties)),
            Self::RenameCalendar => Some(need(Access::Admin, Privilege::WriteProperties)),
            Self::CreateCalendar => Some(need(Access::Owner, Privilege::Bind)),
            Self::DeleteCalendar | Self::DeleteInboxItem | Self::DeleteNotification => {
                Some(need(Access::Owner, Privilege::Unbind))
            }
            Self::ShareCalendar | Self::ListGrants | Self::PutGrant | Self::DeleteGrant => {
                Some(need(Access::Admin, Privilege::Share))
            }
            Self::ReadInbox | Self::ReadNotifications => Some(need(Access::Owner, Privilege::Read)),
            Self::PostOutbox => Some(need(Access::Owner, Privilege::ScheduleSend)),
            Self::PropPatchBinding | Self::RemoveBinding | Self::ReplyInvite | Self::RsvpView | Self::RsvpAnswer => {
                None
            }
        }
    }

    /// The kind of DAV resource the operation's privilege is checked on; used to relate `decide` to
    /// [`privileges`].
    pub const fn resource_kind(self) -> ResourceKind {
        match self {
            Self::ReadObject | Self::UpdateObject | Self::DeleteObject | Self::MoveObjectFrom => ResourceKind::Object,
            Self::CreateCalendar | Self::ReplyInvite => ResourceKind::Home,
            Self::ReadInbox | Self::DeleteInboxItem => ResourceKind::Inbox,
            Self::PostOutbox => ResourceKind::Outbox,
            Self::ReadNotifications | Self::DeleteNotification => ResourceKind::Notifications,
            Self::RsvpView | Self::RsvpAnswer => ResourceKind::Principal,
            Self::ReadCollection
            | Self::ListObjects
            | Self::FreeBusyQuery
            | Self::CreateObject
            | Self::BatchUpsert
            | Self::MoveObjectTo
            | Self::CopyObjectFrom
            | Self::CopyObjectTo
            | Self::RespondToInvitation
            | Self::PropPatchBinding
            | Self::UpdateCalendar
            | Self::RenameCalendar
            | Self::DeleteCalendar
            | Self::RemoveBinding
            | Self::ShareCalendar
            | Self::ListGrants
            | Self::PutGrant
            | Self::DeleteGrant
            | Self::ReadFeed => ResourceKind::Collection,
        }
    }

    /// Whether the operation is a DAV method or report.
    const fn on_dav(self) -> bool {
        !matches!(
            self,
            Self::BatchUpsert
                | Self::RespondToInvitation
                | Self::ListGrants
                | Self::PutGrant
                | Self::DeleteGrant
                | Self::ReadFeed
                | Self::RsvpView
                | Self::RsvpAnswer
        )
    }

    /// What the operation needs on `channel`: whether it exists there and which scope a token must carry.
    pub const fn scope_rule(self, channel: Channel) -> ScopeRule {
        match channel {
            Channel::Dav => {
                if self.on_dav() {
                    ScopeRule::Unscoped
                } else {
                    ScopeRule::Unavailable
                }
            }
            Channel::Api => match self {
                Self::ReadCollection => ScopeRule::Required(Scope::CalendarsRead),
                Self::ListObjects | Self::ReadObject | Self::FreeBusyQuery => ScopeRule::Required(Scope::EventsRead),
                Self::CreateObject
                | Self::UpdateObject
                | Self::DeleteObject
                | Self::BatchUpsert
                | Self::RespondToInvitation => ScopeRule::Required(Scope::EventsWrite),
                Self::UpdateCalendar
                | Self::RenameCalendar
                | Self::CreateCalendar
                | Self::DeleteCalendar
                | Self::ListGrants
                | Self::PutGrant
                | Self::DeleteGrant => ScopeRule::Required(Scope::CalendarsWrite),
                _ => ScopeRule::Unavailable,
            },
            Channel::Mcp => match self {
                Self::ReadCollection | Self::ListObjects | Self::ReadObject | Self::FreeBusyQuery => {
                    ScopeRule::Required(Scope::McpRead)
                }
                Self::CreateObject | Self::UpdateObject | Self::DeleteObject | Self::RespondToInvitation => {
                    ScopeRule::Required(Scope::McpWrite)
                }
                _ => ScopeRule::Unavailable,
            },
            Channel::Feed => {
                if matches!(self, Self::ReadFeed) {
                    ScopeRule::Unscoped
                } else {
                    ScopeRule::Unavailable
                }
            }
            Channel::Rsvp => {
                if matches!(self, Self::RsvpView | Self::RsvpAnswer) {
                    ScopeRule::Unscoped
                } else {
                    ScopeRule::Unavailable
                }
            }
            Channel::Internal => ScopeRule::Unscoped,
        }
    }
}

/// One grant of the calendar as far as authorization is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantFact {
    /// The user, group or service principal that is granted access.
    pub grantee: PrincipalId,
    /// The access the grant confers once accepted.
    pub access: GrantAccess,
    /// Only accepted grants confer access.
    pub status: GrantStatus,
    /// Whether the calendar is required for the people the grant reaches: they cannot remove its binding
    /// ([`binding_required`]).
    pub required: bool,
}

impl From<&Grant> for GrantFact {
    fn from(grant: &Grant) -> Self {
        Self {
            grantee: grant.grantee_id,
            access: grant.access,
            status: grant.status,
            required: grant.required,
        }
    }
}

/// The caller's binding of the calendar, if it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingFact {
    /// The binding.
    pub id: BindingId,
    /// Hidden bindings are not listed; on DAV they no longer resolve.
    pub hidden: bool,
}

/// Everything `decide` needs to know about a calendar and the caller's relation to it, loaded by the application
/// layer in one query per request.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessFacts {
    /// The kind of calendar. For [`Operation::CreateCalendar`] this is the kind being created.
    pub calendar_kind: CalendarKind,
    /// The owning principal. For home-level operations (inbox, outbox, notifications, calendar creation) this is
    /// the principal whose home is addressed.
    pub owner: PrincipalId,
    /// What the owner is (a group's calendars give members the group default access).
    pub owner_kind: PrincipalKind,
    /// The groups the caller currently belongs to.
    pub memberships: Vec<PrincipalId>,
    /// All grants of the calendar (pending and declined ones confer nothing).
    pub grants: Vec<GrantFact>,
    /// The caller's binding of the calendar.
    pub binding: Option<BindingFact>,
    /// The settings of the tenant.
    pub tenant_settings: Arc<TenantSettings>,
}

/// The caller as far as authorization is concerned: who acts and with which token scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The authenticated actor.
    pub actor: Actor,
    /// The scopes of the credential (checked on the API and MCP channels only).
    pub scopes: ScopeSet,
}

impl Subject {
    /// Creates a subject.
    pub const fn new(actor: Actor, scopes: ScopeSet) -> Self {
        Self { actor, scopes }
    }

    /// The principal the subject acts as, if any.
    pub const fn principal(&self) -> Option<PrincipalId> {
        self.actor.principal()
    }
}

impl From<&RequestContext> for Subject {
    fn from(ctx: &RequestContext) -> Self {
        Self {
            actor: ctx.actor.clone(),
            scopes: ctx.scopes,
        }
    }
}

/// The outcome of [`decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The operation is permitted.
    Allow,
    /// The caller has no visibility of the resource: answer as if it did not exist (404).
    Hidden,
    /// The caller sees the resource but lacks this privilege (403, `DAV:need-privileges` for DAV).
    Forbidden(Privilege),
}

impl Decision {
    /// Whether the operation is permitted.
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Computes the effective access of `principal` to the calendar described by `facts`: the maximum of
///
/// * `Owner`, when the principal owns the calendar;
/// * the tenant's `group_default_access`, when a group owns the calendar and the principal is a current member;
/// * the access of every accepted grant to the principal or to a group the principal currently belongs to.
///
/// Pending and declined grants confer nothing. `None` means no access at all. The result is not capped by the
/// calendar kind or the channel; [`decide`] and [`privileges`] apply the caps.
pub fn effective_access(principal: PrincipalId, facts: &AccessFacts) -> Option<Access> {
    let mut best: Option<Access> = None;
    let mut raise = |access: Access| {
        if best.is_none_or(|current| access > current) {
            best = Some(access);
        }
    };
    if facts.owner == principal {
        raise(Access::Owner);
    }
    if facts.owner_kind == PrincipalKind::Group && facts.memberships.contains(&facts.owner) {
        raise(facts.tenant_settings.group_default_access.into());
    }
    for grant in &facts.grants {
        let applies = grant.grantee == principal || facts.memberships.contains(&grant.grantee);
        if applies && grant.status == GrantStatus::Accepted {
            raise(grant.access.into());
        }
    }
    best
}

/// Whether the calendar is **required** for `principal`: an accepted grant with the `required` flag reaches them, either
/// as its grantee or through a group they are currently a member of.
///
/// A principal cannot remove the binding of a required calendar from their home ([`Operation::RemoveBinding`] is
/// forbidden); every other calendar they see can be hidden or left. The flag is the operator's: only the management API
/// sets it, and a client's `CS:share` never does.
pub fn binding_required(principal: PrincipalId, facts: &AccessFacts) -> bool {
    facts.grants.iter().any(|grant| {
        grant.required
            && grant.status == GrantStatus::Accepted
            && (grant.grantee == principal || facts.memberships.contains(&grant.grantee))
    })
}

/// Caps the access that DAV (and for mirrors every principal surface) may exercise: managed and mirror calendars
/// are read-only for users; writes go through the API (`events:write`) or the sync engine.
fn cap_access(access: Access, kind: CalendarKind, channel: Channel) -> Access {
    let read_only = matches!(
        (kind, channel),
        (CalendarKind::Managed | CalendarKind::Mirror, Channel::Dav)
            | (CalendarKind::Mirror, Channel::Api | Channel::Mcp)
    );
    if read_only { access.min(Access::Read) } else { access }
}

/// Whether `access` to a calendar of `kind` lets a principal create, change and delete events through `channel`:
/// the access the channel may exercise on that kind of calendar (managed calendars are capped for DAV, mirror
/// calendars for DAV, the API and MCP) reaches `ReadWrite`.
///
/// This is the rule [`decide`] applies, exposed so that a protocol layer can tell a client which calendars it may
/// write to without keeping a copy of the rule. It decides nothing: the operations themselves are still decided
/// by [`decide`] on every request.
pub fn can_write_events(access: Access, kind: CalendarKind, channel: Channel) -> bool {
    cap_access(access, kind, channel) >= Access::ReadWrite
}

/// The DAV privileges of `access` on a resource of `resource` kind in a calendar of `calendar_kind`, as reported
/// in `current-user-privilege-set`.
///
/// Managed and mirror calendars are capped at `Read`. For the home, the scheduling collections and notifications
/// only the owner has privileges (pass `Access::Owner` for the principal's own resources); everyone may deliver
/// into an inbox. `Owner` and `Admin` have the same collection privileges: deleting a calendar is the separate
/// [`Operation::DeleteCalendar`].
pub fn privileges(access: Access, calendar_kind: CalendarKind, resource: ResourceKind) -> PrivilegeSet {
    use Privilege::{
        Bind, Read, ReadCurrentUserPrivilegeSet, ReadFreeBusy, ScheduleDeliver, ScheduleSend, Share, Unbind,
        WriteContent, WriteProperties,
    };
    let owner = access == Access::Owner;
    match resource {
        ResourceKind::Principal => PrivilegeSet::of(&[Read, ReadCurrentUserPrivilegeSet]),
        ResourceKind::Home => {
            if owner {
                PrivilegeSet::of(&[Read, ReadCurrentUserPrivilegeSet, WriteProperties, Bind, Unbind])
            } else {
                PrivilegeSet::empty()
            }
        }
        ResourceKind::Inbox => {
            if owner {
                PrivilegeSet::of(&[Read, ReadCurrentUserPrivilegeSet, Unbind, ScheduleDeliver])
            } else {
                PrivilegeSet::of(&[ScheduleDeliver])
            }
        }
        ResourceKind::Outbox => {
            if owner {
                PrivilegeSet::of(&[Read, ReadCurrentUserPrivilegeSet, ScheduleSend])
            } else {
                PrivilegeSet::empty()
            }
        }
        ResourceKind::Notifications => {
            if owner {
                PrivilegeSet::of(&[Read, ReadCurrentUserPrivilegeSet, Unbind])
            } else {
                PrivilegeSet::empty()
            }
        }
        // What a principal may do with one message: read it. Removing it is the `unbind` of the collection.
        ResourceKind::InboxItem | ResourceKind::Notification => {
            if owner {
                PrivilegeSet::of(&[Read, ReadCurrentUserPrivilegeSet])
            } else {
                PrivilegeSet::empty()
            }
        }
        ResourceKind::Collection => {
            let mut set = PrivilegeSet::empty();
            match cap_access(access, calendar_kind, Channel::Dav) {
                Access::FreeBusy => set.insert(ReadFreeBusy),
                Access::Read => set.extend_with(&[Read, ReadCurrentUserPrivilegeSet, ReadFreeBusy]),
                Access::ReadWrite => set.extend_with(&[
                    Read,
                    ReadCurrentUserPrivilegeSet,
                    ReadFreeBusy,
                    WriteContent,
                    WriteProperties,
                    Bind,
                    Unbind,
                ]),
                Access::Admin | Access::Owner => set.extend_with(&[
                    Read,
                    ReadCurrentUserPrivilegeSet,
                    ReadFreeBusy,
                    WriteContent,
                    WriteProperties,
                    Bind,
                    Unbind,
                    Share,
                ]),
            }
            set
        }
        ResourceKind::Object => match cap_access(access, calendar_kind, Channel::Dav) {
            Access::FreeBusy => PrivilegeSet::empty(),
            Access::Read => PrivilegeSet::of(&[Read, ReadCurrentUserPrivilegeSet]),
            Access::ReadWrite | Access::Admin | Access::Owner => {
                PrivilegeSet::of(&[Read, ReadCurrentUserPrivilegeSet, WriteContent, WriteProperties, Unbind])
            }
        },
    }
}

impl PrivilegeSet {
    fn extend_with(&mut self, privileges: &[Privilege]) {
        for privilege in privileges {
            self.insert(*privilege);
        }
    }
}

/// Whether `actor` may use `channel` at all.
const fn actor_uses_channel(actor: &Actor, channel: Channel) -> bool {
    matches!(
        (actor, channel),
        (Actor::Principal(_), Channel::Dav)
            | (Actor::PrincipalToken { .. }, Channel::Api | Channel::Mcp)
            | (Actor::TenantToken(_), Channel::Api)
            | (Actor::FeedReader { .. }, Channel::Feed)
            | (Actor::RsvpAttendee { .. }, Channel::Rsvp)
    )
}

/// Decides whether `subject` may perform `operation` on the calendar described by `facts` through `channel`.
///
/// This is the single authorization decision of the system; see the module documentation for the order of the
/// checks. `Channel::Internal` is never produced by authentication: it marks server-originated work (workers,
/// internal delivery, the sync engine), which is trusted and always allowed.
///
/// * Principals (DAV app passwords, principal tokens, feed readers) act through their [`effective_access`],
///   capped for managed and mirror calendars, with the operation's [`Requirement`].
/// * Tenant tokens administer calendars of any kind within their scopes, but reach events of group and managed
///   calendars only.
/// * System tokens, anonymous callers and mismatched actor/channel pairs see nothing.
pub fn decide(subject: &Subject, channel: Channel, facts: &AccessFacts, operation: Operation) -> Decision {
    if channel == Channel::Internal {
        return Decision::Allow;
    }
    if !actor_uses_channel(&subject.actor, channel) {
        return Decision::Hidden;
    }
    let forbidden = Decision::Forbidden(operation.requirement().map_or(Privilege::Read, |r| r.privilege));
    match operation.scope_rule(channel) {
        ScopeRule::Unavailable => return Decision::Hidden,
        ScopeRule::Required(scope) if !subject.scopes.contains(scope) => return forbidden,
        ScopeRule::Required(_) | ScopeRule::Unscoped => {}
    }
    match &subject.actor {
        Actor::RsvpAttendee { .. } => Decision::Allow,
        Actor::TenantToken(_) => decide_tenant_token(facts, operation, forbidden),
        Actor::Principal(principal) | Actor::PrincipalToken { principal, .. } | Actor::FeedReader { principal, .. } => {
            decide_principal(*principal, channel, facts, operation)
        }
        Actor::SystemToken(_) | Actor::Anonymous => Decision::Hidden,
    }
}

fn decide_principal(principal: PrincipalId, channel: Channel, facts: &AccessFacts, operation: Operation) -> Decision {
    if operation == Operation::ReplyInvite {
        let pending = facts
            .grants
            .iter()
            .any(|grant| grant.grantee == principal && grant.status == GrantStatus::Pending);
        return if pending { Decision::Allow } else { Decision::Hidden };
    }
    if operation == Operation::FreeBusyQuery {
        // Free-busy is open to every principal of the tenant; the facts are already bound to the tenant.
        return Decision::Allow;
    }
    if channel == Channel::Dav && facts.binding.is_some_and(|binding| binding.hidden) {
        return Decision::Hidden;
    }
    let Some(access) = effective_access(principal, facts) else {
        return Decision::Hidden;
    };
    let access = cap_access(access, facts.calendar_kind, channel);
    if access < Access::Read {
        return Decision::Hidden;
    }
    if matches!(operation, Operation::PropPatchBinding | Operation::RemoveBinding) {
        // Per-binding operations address the caller's own binding, which must exist.
        if facts.binding.is_none() {
            return Decision::Hidden;
        }
        // A required calendar stays in the home: leaving it is refused, whoever the caller is.
        if operation == Operation::RemoveBinding && binding_required(principal, facts) {
            return Decision::Forbidden(Privilege::Unbind);
        }
        return Decision::Allow;
    }
    let Some(requirement) = operation.requirement() else {
        return Decision::Hidden;
    };
    let forbidden = Decision::Forbidden(requirement.privilege);
    if access < requirement.access {
        return forbidden;
    }
    match operation {
        Operation::ShareCalendar => {
            let shareable = !matches!(facts.calendar_kind, CalendarKind::Managed | CalendarKind::Mirror);
            if shareable && facts.tenant_settings.sharing.enabled {
                Decision::Allow
            } else {
                forbidden
            }
        }
        Operation::PutGrant | Operation::DeleteGrant if facts.calendar_kind == CalendarKind::Mirror => forbidden,
        _ => Decision::Allow,
    }
}

fn decide_tenant_token(facts: &AccessFacts, operation: Operation, forbidden: Decision) -> Decision {
    match operation {
        // A mirror calendar goes with its account (`DELETE /external-accounts/{id}` deletes it): deleted on its own it would leave the
        // account with nothing to pull into, and the sync engine would fail with `mirror_missing` until the account is disconnected.
        Operation::DeleteCalendar if facts.calendar_kind == CalendarKind::Mirror => forbidden,
        Operation::ReadCollection
        | Operation::UpdateCalendar
        | Operation::RenameCalendar
        | Operation::CreateCalendar
        | Operation::DeleteCalendar
        | Operation::ListGrants => Decision::Allow,
        Operation::PutGrant | Operation::DeleteGrant => {
            if facts.calendar_kind == CalendarKind::Mirror {
                forbidden
            } else {
                Decision::Allow
            }
        }
        Operation::ListObjects
        | Operation::ReadObject
        | Operation::FreeBusyQuery
        | Operation::CreateObject
        | Operation::UpdateObject
        | Operation::DeleteObject
        | Operation::BatchUpsert => {
            if matches!(facts.calendar_kind, CalendarKind::Group | CalendarKind::Managed) {
                Decision::Allow
            } else {
                forbidden
            }
        }
        Operation::RespondToInvitation => forbidden,
        _ => Decision::Hidden,
    }
}

text_enum!(
    /// A tenant administration operation of the management API that is not bound to a calendar: one variant per
    /// row of PLAN F0.10 that is not covered by [`Operation`].
    AdminOperation [] {
        /// `GET /tenants`.
        ListTenants => "list_tenants",
        /// `GET /tenants/{tenant}`.
        GetTenant => "get_tenant",
        /// `PUT /tenants/{tenant}`.
        PutTenant => "put_tenant",
        /// `PATCH /tenants/{tenant}`.
        PatchTenant => "patch_tenant",
        /// `DELETE /tenants/{tenant}`.
        DeleteTenant => "delete_tenant",
        /// `GET …/principals`.
        ListPrincipals => "list_principals",
        /// `GET …/principals/{principal}`.
        GetPrincipal => "get_principal",
        /// `PUT …/principals/{principal}`.
        PutPrincipal => "put_principal",
        /// `PATCH …/principals/{principal}`.
        PatchPrincipal => "patch_principal",
        /// `DELETE …/principals/{principal}`.
        DeletePrincipal => "delete_principal",
        /// `GET …/principals/{group}/members`.
        GetMembers => "get_members",
        /// `PUT …/principals/{group}/members` (replace the full set).
        SetMembers => "set_members",
        /// `PUT …/members/{member}`.
        AddMember => "add_member",
        /// `DELETE …/members/{member}`.
        RemoveMember => "remove_member",
        /// `GET …/app-passwords`.
        ListAppPasswords => "list_app_passwords",
        /// `POST …/app-passwords`.
        CreateAppPassword => "create_app_password",
        /// `DELETE …/app-passwords/{id}`.
        RevokeAppPassword => "revoke_app_password",
        /// `GET …/feed-tokens`.
        ListFeedTokens => "list_feed_tokens",
        /// `POST …/feed-tokens`.
        CreateFeedToken => "create_feed_token",
        /// `DELETE …/feed-tokens/{id}`.
        RevokeFeedToken => "revoke_feed_token",
        /// `POST …/feed-tokens/{id}/rotate`.
        RotateFeedToken => "rotate_feed_token",
        /// `GET …/client-config/generic`.
        GetClientConfig => "get_client_config",
        /// `POST …/client-config/{apple-mobileconfig,davx5}` (mints an app password).
        CreateClientConfig => "create_client_config",
        /// `GET …/api-tokens`.
        ListApiTokens => "list_api_tokens",
        /// `POST …/api-tokens`.
        CreateApiToken => "create_api_token",
        /// `DELETE …/api-tokens/{id}`.
        RevokeApiToken => "revoke_api_token",
        /// `GET …/webhooks`.
        ListWebhooks => "list_webhooks",
        /// `POST …/webhooks`.
        CreateWebhook => "create_webhook",
        /// `GET …/webhooks/{id}`.
        GetWebhook => "get_webhook",
        /// `PATCH …/webhooks/{id}`.
        PatchWebhook => "patch_webhook",
        /// `DELETE …/webhooks/{id}`.
        DeleteWebhook => "delete_webhook",
        /// `POST …/webhooks/{id}/rotate-secret`.
        RotateWebhookSecret => "rotate_webhook_secret",
        /// `POST …/webhooks/{id}/ping`.
        PingWebhook => "ping_webhook",
        /// `GET …/webhooks/{id}/deliveries`.
        ListDeliveries => "list_deliveries",
        /// `POST …/deliveries/{delivery}/redeliver`.
        RedeliverWebhook => "redeliver_webhook",
        /// `GET …/providers`.
        ListProviders => "list_providers",
        /// `GET …/external-accounts`.
        ListExternalAccounts => "list_external_accounts",
        /// `POST …/external-accounts`.
        CreateExternalAccount => "create_external_account",
        /// `DELETE …/external-accounts/{id}`.
        DeleteExternalAccount => "delete_external_account",
        /// `GET …/audit-events`.
        ListAuditEvents => "list_audit_events",
        /// `GET …/outbox`.
        ListOutbox => "list_outbox",
        /// `POST …/outbox/{id}/retry`.
        RetryOutbox => "retry_outbox",
        /// `POST …/itip/inbound`.
        InboundItip => "inbound_itip",
        /// `GET /tenants/{tenant}/calendars` (search across the tenant).
        SearchCalendars => "search_calendars",
        /// `GET …/principals/{principal}/bindings`: the calendars in the home of a principal, hidden ones included.
        ListBindings => "list_bindings",
        /// `POST …/principals/{principal}/bindings/{binding}/restore`: shows a hidden binding in the home again.
        RestoreBinding => "restore_binding",
    }
);

impl AdminOperation {
    /// The scopes of which a token needs at least one (`x-required-scope`). `GET /tenants/{tenant}` accepts
    /// `principals:read` as well as `system:tenants`.
    pub const fn accepted_scopes(self) -> &'static [Scope] {
        match self {
            Self::ListTenants | Self::PutTenant | Self::PatchTenant | Self::DeleteTenant => &[Scope::SystemTenants],
            Self::GetTenant => &[Scope::SystemTenants, Scope::PrincipalsRead],
            Self::ListPrincipals | Self::GetPrincipal | Self::GetMembers | Self::GetClientConfig => {
                &[Scope::PrincipalsRead]
            }
            Self::PutPrincipal
            | Self::PatchPrincipal
            | Self::DeletePrincipal
            | Self::SetMembers
            | Self::AddMember
            | Self::RemoveMember => &[Scope::PrincipalsWrite],
            Self::ListAppPasswords
            | Self::CreateAppPassword
            | Self::RevokeAppPassword
            | Self::ListFeedTokens
            | Self::CreateFeedToken
            | Self::RevokeFeedToken
            | Self::RotateFeedToken
            | Self::CreateClientConfig
            | Self::ListApiTokens
            | Self::CreateApiToken
            | Self::RevokeApiToken => &[Scope::CredentialsWrite],
            Self::ListWebhooks
            | Self::CreateWebhook
            | Self::GetWebhook
            | Self::PatchWebhook
            | Self::DeleteWebhook
            | Self::RotateWebhookSecret
            | Self::PingWebhook
            | Self::ListDeliveries
            | Self::RedeliverWebhook => &[Scope::WebhooksManage],
            Self::ListProviders
            | Self::ListExternalAccounts
            | Self::CreateExternalAccount
            | Self::DeleteExternalAccount => &[Scope::ProvidersManage],
            Self::ListAuditEvents => &[Scope::AuditRead],
            Self::ListOutbox | Self::RetryOutbox => &[Scope::OutboxManage],
            Self::InboundItip => &[Scope::ItipInbound],
            Self::SearchCalendars | Self::ListBindings => &[Scope::CalendarsRead],
            Self::RestoreBinding => &[Scope::CalendarsWrite],
        }
    }
}

/// The outcome of [`decide_admin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminDecision {
    /// The operation is permitted.
    Allow,
    /// The caller is authenticated but not permitted (403 `forbidden`).
    Forbidden,
}

/// Decides whether `subject` may perform a tenant administration operation.
///
/// Only the API channel has administration operations. System tokens may use the tenant operations with
/// `system:tenants`; tenant tokens may use every operation whose accepted scope they carry. Principal tokens, DAV
/// sessions, feeds and RSVP links never administer anything. `Channel::Internal` is trusted. Whether the path's
/// tenant matches the token's tenant is resolved before this call: a mismatch answers 404 there.
pub fn decide_admin(subject: &Subject, channel: Channel, operation: AdminOperation) -> AdminDecision {
    if channel == Channel::Internal {
        return AdminDecision::Allow;
    }
    if channel != Channel::Api {
        return AdminDecision::Forbidden;
    }
    let kind = match subject.actor {
        Actor::SystemToken(_) => crate::scope::TokenKind::System,
        Actor::TenantToken(_) => crate::scope::TokenKind::Tenant,
        _ => return AdminDecision::Forbidden,
    };
    let permitted = operation
        .accepted_scopes()
        .iter()
        .any(|scope| scope.allowed_for(kind) && subject.scopes.contains(*scope));
    if permitted {
        AdminDecision::Allow
    } else {
        AdminDecision::Forbidden
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{CalendarId, TokenId};
    use crate::keys::CalendarUserAddress;

    const ME: PrincipalId = PrincipalId::from_uuid(uuid::Uuid::from_u128(0x1000));
    const OTHER: PrincipalId = PrincipalId::from_uuid(uuid::Uuid::from_u128(0x2000));
    const GROUP: PrincipalId = PrincipalId::from_uuid(uuid::Uuid::from_u128(0x3000));
    const TOKEN: TokenId = TokenId::from_uuid(uuid::Uuid::from_u128(0x4000));

    fn settings() -> Arc<TenantSettings> {
        Arc::new(TenantSettings::default())
    }

    fn facts(kind: CalendarKind) -> AccessFacts {
        AccessFacts {
            calendar_kind: kind,
            owner: OTHER,
            owner_kind: PrincipalKind::User,
            memberships: Vec::new(),
            grants: Vec::new(),
            binding: Some(BindingFact {
                id: BindingId::from_uuid(uuid::Uuid::from_u128(0x5000)),
                hidden: false,
            }),
            tenant_settings: settings(),
        }
    }

    fn grant(grantee: PrincipalId, access: GrantAccess, status: GrantStatus) -> GrantFact {
        GrantFact {
            grantee,
            access,
            status,
            required: false,
        }
    }

    /// Facts in which `ME` has exactly the given effective access to a calendar of `kind`.
    fn facts_with_access(kind: CalendarKind, access: Option<Access>) -> AccessFacts {
        let mut facts = facts(kind);
        match access {
            None | Some(Access::FreeBusy) => {}
            Some(Access::Read) => facts.grants.push(grant(ME, GrantAccess::Read, GrantStatus::Accepted)),
            Some(Access::ReadWrite) => facts
                .grants
                .push(grant(ME, GrantAccess::ReadWrite, GrantStatus::Accepted)),
            Some(Access::Admin) => facts.grants.push(grant(ME, GrantAccess::Admin, GrantStatus::Accepted)),
            Some(Access::Owner) => facts.owner = ME,
        }
        assert_eq!(effective_access(ME, &facts), access.filter(|a| *a != Access::FreeBusy));
        facts
    }

    fn dav_user() -> Subject {
        Subject::new(Actor::Principal(ME), ScopeSet::empty())
    }

    fn token(scopes: &[Scope]) -> Subject {
        Subject::new(
            Actor::PrincipalToken {
                principal: ME,
                token: TOKEN,
            },
            ScopeSet::of(scopes),
        )
    }

    fn tenant_token(scopes: &[Scope]) -> Subject {
        Subject::new(Actor::TenantToken(TOKEN), ScopeSet::of(scopes))
    }

    const A: Decision = Decision::Allow;
    const H: Decision = Decision::Hidden;
    const fn f(privilege: Privilege) -> Decision {
        Decision::Forbidden(privilege)
    }

    // ---------------------------------------------------------------------------------------------------------
    // effective_access
    // ---------------------------------------------------------------------------------------------------------

    #[test]
    fn owner_has_owner_access() {
        let mut facts = facts(CalendarKind::Personal);
        facts.owner = ME;
        assert_eq!(effective_access(ME, &facts), Some(Access::Owner));
        assert_eq!(effective_access(OTHER, &facts), None);
    }

    #[test]
    fn strangers_have_no_access() {
        assert_eq!(effective_access(ME, &facts(CalendarKind::Personal)), None);
    }

    #[test]
    fn group_members_get_the_tenant_default() {
        let mut facts = facts(CalendarKind::Group);
        facts.owner = GROUP;
        facts.owner_kind = PrincipalKind::Group;
        assert_eq!(effective_access(ME, &facts), None, "non-members get nothing");
        facts.memberships = vec![GROUP];
        assert_eq!(
            effective_access(ME, &facts),
            Some(Access::ReadWrite),
            "default group access is read_write"
        );
        for (setting, expected) in [
            (GrantAccess::Read, Access::Read),
            (GrantAccess::ReadWrite, Access::ReadWrite),
            (GrantAccess::Admin, Access::Admin),
        ] {
            facts.tenant_settings = Arc::new(TenantSettings::default().modified(|s| s.group_default_access = setting));
            assert_eq!(effective_access(ME, &facts), Some(expected));
        }
    }

    #[test]
    fn group_default_only_applies_to_calendars_owned_by_a_group() {
        let mut facts = facts(CalendarKind::User);
        facts.owner = GROUP;
        facts.owner_kind = PrincipalKind::User;
        facts.memberships = vec![GROUP];
        assert_eq!(effective_access(ME, &facts), None);
        facts.owner_kind = PrincipalKind::Resource;
        assert_eq!(effective_access(ME, &facts), None);
    }

    #[test]
    fn only_accepted_grants_confer_access() {
        let mut facts = facts(CalendarKind::User);
        for status in [GrantStatus::Pending, GrantStatus::Declined] {
            facts.grants = vec![grant(ME, GrantAccess::Admin, status)];
            assert_eq!(effective_access(ME, &facts), None, "{status}");
        }
        facts.grants = vec![grant(ME, GrantAccess::Read, GrantStatus::Accepted)];
        assert_eq!(effective_access(ME, &facts), Some(Access::Read));
    }

    #[test]
    fn grants_to_groups_apply_to_current_members_only() {
        let mut facts = facts(CalendarKind::User);
        facts.grants = vec![grant(GROUP, GrantAccess::ReadWrite, GrantStatus::Accepted)];
        assert_eq!(effective_access(ME, &facts), None, "not a member");
        facts.memberships = vec![GROUP];
        assert_eq!(effective_access(ME, &facts), Some(Access::ReadWrite));
        facts.grants = vec![grant(GROUP, GrantAccess::ReadWrite, GrantStatus::Pending)];
        assert_eq!(
            effective_access(ME, &facts),
            None,
            "pending group grants confer nothing"
        );
    }

    #[test]
    fn the_maximum_of_all_sources_wins() {
        let mut facts = facts(CalendarKind::Group);
        facts.owner = GROUP;
        facts.owner_kind = PrincipalKind::Group;
        facts.memberships = vec![GROUP];
        facts.grants = vec![
            grant(ME, GrantAccess::Admin, GrantStatus::Accepted),
            grant(GROUP, GrantAccess::Read, GrantStatus::Accepted),
            grant(OTHER, GrantAccess::Admin, GrantStatus::Accepted),
        ];
        assert_eq!(effective_access(ME, &facts), Some(Access::Admin));
        facts.owner = ME;
        assert_eq!(effective_access(ME, &facts), Some(Access::Owner));
    }

    #[test]
    fn grants_of_other_principals_do_not_leak() {
        let mut facts = facts(CalendarKind::User);
        facts.grants = vec![grant(OTHER, GrantAccess::Admin, GrantStatus::Accepted)];
        assert_eq!(effective_access(ME, &facts), None);
    }

    #[test]
    fn access_levels_are_ordered() {
        assert!(Access::FreeBusy < Access::Read);
        assert!(Access::Read < Access::ReadWrite);
        assert!(Access::ReadWrite < Access::Admin);
        assert!(Access::Admin < Access::Owner);
        assert_eq!(Access::from(GrantAccess::Admin), Access::Admin);
        assert_eq!(Access::ALL.len(), 5);
    }

    // ---------------------------------------------------------------------------------------------------------
    // privileges (hand-written expectations)
    // ---------------------------------------------------------------------------------------------------------

    use Privilege::{
        Bind, Read, ReadCurrentUserPrivilegeSet as Rcups, ReadFreeBusy, ScheduleDeliver, ScheduleSend, Share, Unbind,
        WriteContent, WriteProperties,
    };

    #[test]
    fn collection_privileges_follow_the_plan_table() {
        let p = |access| privileges(access, CalendarKind::User, ResourceKind::Collection);
        assert_eq!(p(Access::FreeBusy), PrivilegeSet::of(&[ReadFreeBusy]));
        assert_eq!(p(Access::Read), PrivilegeSet::of(&[Read, Rcups, ReadFreeBusy]));
        assert_eq!(
            p(Access::ReadWrite),
            PrivilegeSet::of(&[Read, Rcups, ReadFreeBusy, WriteContent, Bind, Unbind, WriteProperties])
        );
        let admin = PrivilegeSet::of(&[
            Read,
            Rcups,
            ReadFreeBusy,
            WriteContent,
            Bind,
            Unbind,
            WriteProperties,
            Share,
        ]);
        assert_eq!(p(Access::Admin), admin);
        assert_eq!(p(Access::Owner), admin);
    }

    #[test]
    fn managed_and_mirror_collections_are_capped_at_read_on_dav() {
        for kind in [CalendarKind::Managed, CalendarKind::Mirror] {
            for access in [Access::Read, Access::ReadWrite, Access::Admin, Access::Owner] {
                assert_eq!(
                    privileges(access, kind, ResourceKind::Collection),
                    PrivilegeSet::of(&[Read, Rcups, ReadFreeBusy]),
                    "{kind} {access}"
                );
                assert_eq!(
                    privileges(access, kind, ResourceKind::Object),
                    PrivilegeSet::of(&[Read, Rcups]),
                    "{kind} {access}"
                );
            }
            assert_eq!(
                privileges(Access::FreeBusy, kind, ResourceKind::Collection),
                PrivilegeSet::of(&[ReadFreeBusy])
            );
        }
    }

    #[test]
    fn can_write_events_is_the_rule_decide_applies_to_event_writes() {
        let kinds = [
            CalendarKind::Personal,
            CalendarKind::Group,
            CalendarKind::Managed,
            CalendarKind::User,
            CalendarKind::Mirror,
        ];
        let accesses = [Access::Read, Access::ReadWrite, Access::Admin, Access::Owner];
        for kind in kinds {
            for access in accesses {
                let facts = facts_with_access(kind, Some(access));
                for (channel, scope) in [(Channel::Api, Scope::EventsWrite), (Channel::Mcp, Scope::McpWrite)] {
                    let decided = decide(&token(&[scope]), channel, &facts, Operation::UpdateObject) == A;
                    assert_eq!(
                        can_write_events(access, kind, channel),
                        decided,
                        "{kind} {access} {channel}"
                    );
                }
                let decided = decide(&dav_user(), Channel::Dav, &facts, Operation::UpdateObject) == A;
                assert_eq!(
                    can_write_events(access, kind, Channel::Dav),
                    decided,
                    "{kind} {access} dav"
                );
            }
        }
        assert!(!can_write_events(Access::Owner, CalendarKind::Mirror, Channel::Mcp));
        assert!(can_write_events(Access::ReadWrite, CalendarKind::Managed, Channel::Mcp));
        assert!(!can_write_events(Access::Read, CalendarKind::User, Channel::Mcp));
    }

    #[test]
    fn group_calendars_are_not_capped() {
        assert!(privileges(Access::ReadWrite, CalendarKind::Group, ResourceKind::Collection).contains(WriteContent));
        assert!(privileges(Access::Owner, CalendarKind::Personal, ResourceKind::Collection).contains(Share));
    }

    #[test]
    fn object_privileges() {
        let p = |access| privileges(access, CalendarKind::User, ResourceKind::Object);
        assert_eq!(p(Access::FreeBusy), PrivilegeSet::empty());
        assert_eq!(p(Access::Read), PrivilegeSet::of(&[Read, Rcups]));
        for access in [Access::ReadWrite, Access::Admin, Access::Owner] {
            assert_eq!(
                p(access),
                PrivilegeSet::of(&[Read, Rcups, WriteContent, WriteProperties, Unbind]),
                "{access}"
            );
        }
    }

    #[test]
    fn home_and_scheduling_collections_belong_to_the_owner() {
        let kind = CalendarKind::Personal;
        assert_eq!(
            privileges(Access::Owner, kind, ResourceKind::Home),
            PrivilegeSet::of(&[Read, Rcups, WriteProperties, Bind, Unbind])
        );
        assert_eq!(
            privileges(Access::Owner, kind, ResourceKind::Inbox),
            PrivilegeSet::of(&[Read, Rcups, Unbind, ScheduleDeliver])
        );
        assert_eq!(
            privileges(Access::Owner, kind, ResourceKind::Outbox),
            PrivilegeSet::of(&[Read, Rcups, ScheduleSend])
        );
        assert_eq!(
            privileges(Access::Owner, kind, ResourceKind::Notifications),
            PrivilegeSet::of(&[Read, Rcups, Unbind])
        );
        for access in [Access::FreeBusy, Access::Read, Access::ReadWrite, Access::Admin] {
            assert_eq!(privileges(access, kind, ResourceKind::Home), PrivilegeSet::empty());
            assert_eq!(
                privileges(access, kind, ResourceKind::Inbox),
                PrivilegeSet::of(&[ScheduleDeliver]),
                "everyone may deliver"
            );
            assert_eq!(privileges(access, kind, ResourceKind::Outbox), PrivilegeSet::empty());
            assert_eq!(
                privileges(access, kind, ResourceKind::Notifications),
                PrivilegeSet::empty()
            );
        }
    }

    #[test]
    fn the_messages_of_the_scheduling_collections_belong_to_the_owner_and_can_be_read() {
        let kind = CalendarKind::Personal;
        for resource in [ResourceKind::InboxItem, ResourceKind::Notification] {
            assert_eq!(
                privileges(Access::Owner, kind, resource),
                PrivilegeSet::of(&[Read, Rcups]),
                "{resource}: removing a message is the `unbind` of its collection"
            );
            for access in [Access::FreeBusy, Access::Read, Access::ReadWrite, Access::Admin] {
                assert_eq!(
                    privileges(access, kind, resource),
                    PrivilegeSet::empty(),
                    "{resource} {access}"
                );
            }
        }
    }

    #[test]
    fn principal_resources_are_readable() {
        for access in Access::ALL {
            assert_eq!(
                privileges(*access, CalendarKind::Personal, ResourceKind::Principal),
                PrivilegeSet::of(&[Read, Rcups])
            );
        }
    }

    #[test]
    fn privilege_sets_behave_like_sets() {
        let rw = PrivilegeSet::of(&[Read, WriteContent]);
        assert!(rw.contains(Read));
        assert!(!rw.contains(Bind));
        assert!(PrivilegeSet::of(&[Read]).is_subset_of(rw));
        assert!(!rw.is_subset_of(PrivilegeSet::of(&[Read])));
        assert!(PrivilegeSet::empty().is_empty());
        assert_eq!(rw.len(), 2);
        assert_eq!(rw.iter().collect::<Vec<_>>(), vec![Read, WriteContent]);
        assert_eq!(serde_json::to_string(&rw).unwrap(), r#"["read","write-content"]"#);
        let back: PrivilegeSet = serde_json::from_str(r#"["write-content","read","read"]"#).unwrap();
        assert_eq!(back, rw);
        assert_eq!(format!("{rw:?}"), r#"{"read", "write-content"}"#);
        assert_eq!(PrivilegeSet::from([Read, WriteContent]), rw);
        assert_eq!(Privilege::ALL.len(), 10);
    }

    // ---------------------------------------------------------------------------------------------------------
    // decide: DAV, principal subject, hand-written expectation tables
    // ---------------------------------------------------------------------------------------------------------

    /// Expected decisions for effective access [none, read, `read_write`, admin, owner].
    type Row = [Decision; 5];

    const ACCESS_COLUMNS: [Option<Access>; 5] = [
        None,
        Some(Access::Read),
        Some(Access::ReadWrite),
        Some(Access::Admin),
        Some(Access::Owner),
    ];

    fn dav_expectations() -> Vec<(Operation, Row)> {
        use Operation::*;
        vec![
            (ReadCollection, [H, A, A, A, A]),
            (ListObjects, [H, A, A, A, A]),
            (ReadObject, [H, A, A, A, A]),
            (FreeBusyQuery, [A, A, A, A, A]),
            (CreateObject, [H, f(Bind), A, A, A]),
            (UpdateObject, [H, f(WriteContent), A, A, A]),
            (DeleteObject, [H, f(Unbind), A, A, A]),
            (BatchUpsert, [H, H, H, H, H]),
            (MoveObjectFrom, [H, f(Unbind), A, A, A]),
            (MoveObjectTo, [H, f(Bind), A, A, A]),
            (CopyObjectFrom, [H, A, A, A, A]),
            (CopyObjectTo, [H, f(Bind), A, A, A]),
            (RespondToInvitation, [H, H, H, H, H]),
            (PropPatchBinding, [H, A, A, A, A]),
            (UpdateCalendar, [H, f(WriteProperties), A, A, A]),
            (RenameCalendar, [H, f(WriteProperties), f(WriteProperties), A, A]),
            (CreateCalendar, [H, f(Bind), f(Bind), f(Bind), A]),
            (DeleteCalendar, [H, f(Unbind), f(Unbind), f(Unbind), A]),
            (RemoveBinding, [H, A, A, A, A]),
            (ShareCalendar, [H, f(Share), f(Share), A, A]),
            (ReplyInvite, [H, H, H, H, H]),
            (ListGrants, [H, H, H, H, H]),
            (PutGrant, [H, H, H, H, H]),
            (DeleteGrant, [H, H, H, H, H]),
            (ReadInbox, [H, f(Read), f(Read), f(Read), A]),
            (DeleteInboxItem, [H, f(Unbind), f(Unbind), f(Unbind), A]),
            (PostOutbox, [H, f(ScheduleSend), f(ScheduleSend), f(ScheduleSend), A]),
            (ReadNotifications, [H, f(Read), f(Read), f(Read), A]),
            (DeleteNotification, [H, f(Unbind), f(Unbind), f(Unbind), A]),
            (ReadFeed, [H, H, H, H, H]),
            (RsvpView, [H, H, H, H, H]),
            (RsvpAnswer, [H, H, H, H, H]),
        ]
    }

    #[test]
    fn the_expectation_table_covers_every_operation_once() {
        let table = dav_expectations();
        assert_eq!(table.len(), Operation::ALL.len());
        for operation in Operation::ALL {
            assert_eq!(table.iter().filter(|(op, _)| op == operation).count(), 1, "{operation}");
        }
    }

    #[test]
    fn dav_decisions_on_personal_calendars() {
        for kind in [CalendarKind::Personal, CalendarKind::User, CalendarKind::Group] {
            for (operation, row) in dav_expectations() {
                for (access, expected) in ACCESS_COLUMNS.iter().zip(row) {
                    let facts = facts_with_access(kind, *access);
                    let actual = decide(&dav_user(), Channel::Dav, &facts, operation);
                    assert_eq!(actual, expected, "{kind} {operation} with {access:?}");
                }
            }
        }
    }

    #[test]
    fn dav_decisions_on_managed_and_mirror_calendars_are_capped_at_read() {
        for kind in [CalendarKind::Managed, CalendarKind::Mirror] {
            for (operation, row) in dav_expectations() {
                let read_row = row[1];
                for (access, expected) in ACCESS_COLUMNS.iter().zip(row) {
                    let facts = facts_with_access(kind, *access);
                    let capped = if access.is_none() { expected } else { read_row };
                    let actual = decide(&dav_user(), Channel::Dav, &facts, operation);
                    // Sharing a read-only calendar is refused with the share privilege like any other write.
                    assert_eq!(actual, capped, "{kind} {operation} with {access:?}");
                }
            }
        }
    }

    #[test]
    fn dav_writes_to_managed_calendars_are_forbidden_even_for_the_owner() {
        let facts = facts_with_access(CalendarKind::Managed, Some(Access::Owner));
        for operation in [
            Operation::CreateObject,
            Operation::UpdateObject,
            Operation::DeleteObject,
        ] {
            assert!(
                matches!(
                    decide(&dav_user(), Channel::Dav, &facts, operation),
                    Decision::Forbidden(_)
                ),
                "{operation}"
            );
        }
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::ReadObject), A);
    }

    #[test]
    fn hidden_bindings_do_not_resolve_on_dav_but_still_do_through_the_api() {
        let mut facts = facts_with_access(CalendarKind::Group, Some(Access::ReadWrite));
        facts.binding = facts.binding.map(|b| BindingFact { hidden: true, ..b });
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::ReadObject), H);
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::PropPatchBinding),
            H
        );
        assert_eq!(
            decide(
                &token(&[Scope::EventsRead]),
                Channel::Api,
                &facts,
                Operation::ReadObject
            ),
            A
        );
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::FreeBusyQuery),
            A,
            "free-busy ignores bindings"
        );
    }

    #[test]
    fn binding_operations_need_a_binding() {
        let mut facts = facts_with_access(CalendarKind::Group, Some(Access::Read));
        facts.binding = None;
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::PropPatchBinding),
            H
        );
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::RemoveBinding), H);
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::ReadObject),
            A,
            "other operations do not"
        );
    }

    #[test]
    fn invite_replies_need_a_pending_grant_of_the_caller() {
        let mut facts = facts(CalendarKind::User);
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::ReplyInvite), H);
        facts.grants = vec![grant(OTHER, GrantAccess::Read, GrantStatus::Pending)];
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::ReplyInvite),
            H,
            "someone else's invitation"
        );
        facts.grants = vec![grant(ME, GrantAccess::Read, GrantStatus::Accepted)];
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::ReplyInvite),
            H,
            "already accepted"
        );
        facts.grants = vec![grant(ME, GrantAccess::Read, GrantStatus::Declined)];
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::ReplyInvite),
            H,
            "already declined"
        );
        facts.grants = vec![grant(ME, GrantAccess::ReadWrite, GrantStatus::Pending)];
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::ReplyInvite), A);
        // A pending invitation grants nothing else.
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::ReadObject), H);
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::ReadCollection), H);
    }

    #[test]
    fn sharing_can_be_disabled_per_tenant() {
        let mut facts = facts_with_access(CalendarKind::Personal, Some(Access::Owner));
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::ShareCalendar), A);
        facts.tenant_settings = Arc::new(TenantSettings::default().modified(|s| s.sharing.enabled = false));
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::ShareCalendar),
            f(Share)
        );
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::ReadObject),
            A,
            "reading is unaffected"
        );
    }

    #[test]
    fn group_members_write_group_calendars_through_the_default_access() {
        let mut facts = facts(CalendarKind::Group);
        facts.owner = GROUP;
        facts.owner_kind = PrincipalKind::Group;
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::ReadObject), H);
        facts.memberships = vec![GROUP];
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::UpdateObject), A);
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::ShareCalendar),
            f(Share)
        );
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::DeleteCalendar),
            f(Unbind)
        );
        facts.tenant_settings =
            Arc::new(TenantSettings::default().modified(|s| s.group_default_access = GrantAccess::Read));
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::UpdateObject),
            f(WriteContent)
        );
    }

    #[test]
    fn dav_decisions_never_exceed_the_reported_privileges() {
        // Soundness: whatever `decide` allows on DAV for a privileged operation, `current-user-privilege-set`
        // (derived from `privileges`) lists the privilege that operation needs.
        for kind in CalendarKind::ALL {
            for access in ACCESS_COLUMNS {
                let facts = facts_with_access(*kind, access);
                let Some(effective) = effective_access(ME, &facts) else {
                    continue;
                };
                for operation in Operation::ALL {
                    let Some(requirement) = operation.requirement() else {
                        continue;
                    };
                    if matches!(operation, Operation::FreeBusyQuery) {
                        continue;
                    }
                    if decide(&dav_user(), Channel::Dav, &facts, *operation).is_allowed() {
                        let granted = privileges(effective, *kind, operation.resource_kind());
                        assert!(
                            granted.contains(requirement.privilege),
                            "{kind} {operation} allowed with {effective} but {} is not in {granted:?}",
                            requirement.privilege
                        );
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // decide: channels, actors, scopes
    // ---------------------------------------------------------------------------------------------------------

    #[test]
    fn the_internal_channel_is_trusted() {
        let facts = facts(CalendarKind::Personal);
        for actor in [Actor::Anonymous, Actor::Principal(ME), Actor::SystemToken(TOKEN)] {
            let subject = Subject::new(actor, ScopeSet::empty());
            for operation in Operation::ALL {
                assert_eq!(
                    decide(&subject, Channel::Internal, &facts, *operation),
                    A,
                    "{operation}"
                );
            }
        }
    }

    #[test]
    fn anonymous_and_system_tokens_see_nothing_on_any_channel() {
        let facts = facts_with_access(CalendarKind::Personal, Some(Access::Owner));
        for actor in [Actor::Anonymous, Actor::SystemToken(TOKEN)] {
            let subject = Subject::new(actor, ScopeSet::all());
            for channel in [Channel::Dav, Channel::Api, Channel::Mcp, Channel::Feed, Channel::Rsvp] {
                for operation in Operation::ALL {
                    assert_eq!(
                        decide(&subject, channel, &facts, *operation),
                        H,
                        "{channel} {operation}"
                    );
                }
            }
        }
    }

    #[test]
    fn actors_are_bound_to_their_channels() {
        let facts = facts_with_access(CalendarKind::Personal, Some(Access::Owner));
        let all_scopes = ScopeSet::all();
        let cases = [
            (Actor::Principal(ME), vec![Channel::Dav]),
            (
                Actor::PrincipalToken {
                    principal: ME,
                    token: TOKEN,
                },
                vec![Channel::Api, Channel::Mcp],
            ),
            (Actor::TenantToken(TOKEN), vec![Channel::Api]),
            (
                Actor::FeedReader {
                    principal: ME,
                    token: TOKEN,
                },
                vec![Channel::Feed],
            ),
        ];
        for (actor, allowed) in cases {
            let subject = Subject::new(actor.clone(), all_scopes);
            for channel in [Channel::Dav, Channel::Api, Channel::Mcp, Channel::Feed, Channel::Rsvp] {
                let any_visible = Operation::ALL
                    .iter()
                    .any(|op| decide(&subject, channel, &facts, *op) != H);
                assert_eq!(any_visible, allowed.contains(&channel), "{actor:?} on {channel}");
            }
        }
    }

    #[test]
    fn rsvp_attendees_may_only_use_the_rsvp_operations() {
        let facts = facts(CalendarKind::Personal);
        let attendee = Subject::new(
            Actor::RsvpAttendee {
                object: crate::ids::ObjectId::from_uuid(uuid::Uuid::from_u128(9)),
                address: CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
            },
            ScopeSet::empty(),
        );
        for operation in Operation::ALL {
            let expected = if matches!(operation, Operation::RsvpView | Operation::RsvpAnswer) {
                A
            } else {
                H
            };
            assert_eq!(
                decide(&attendee, Channel::Rsvp, &facts, *operation),
                expected,
                "{operation}"
            );
            for channel in [Channel::Dav, Channel::Api, Channel::Mcp, Channel::Feed] {
                assert_eq!(
                    decide(&attendee, channel, &facts, *operation),
                    H,
                    "{channel} {operation}"
                );
            }
        }
    }

    #[test]
    fn feed_readers_read_feeds_with_the_access_of_their_principal() {
        let reader = Subject::new(
            Actor::FeedReader {
                principal: ME,
                token: TOKEN,
            },
            ScopeSet::empty(),
        );
        for operation in Operation::ALL {
            let facts = facts_with_access(CalendarKind::User, Some(Access::Read));
            let expected = if *operation == Operation::ReadFeed { A } else { H };
            assert_eq!(
                decide(&reader, Channel::Feed, &facts, *operation),
                expected,
                "{operation}"
            );
        }
        let none = facts_with_access(CalendarKind::User, None);
        assert_eq!(
            decide(&reader, Channel::Feed, &none, Operation::ReadFeed),
            H,
            "revoked access answers 404"
        );
        let mut pending = facts(CalendarKind::User);
        pending.grants = vec![grant(ME, GrantAccess::Read, GrantStatus::Pending)];
        assert_eq!(decide(&reader, Channel::Feed, &pending, Operation::ReadFeed), H);
        let owner = facts_with_access(CalendarKind::Managed, Some(Access::Owner));
        assert_eq!(decide(&reader, Channel::Feed, &owner, Operation::ReadFeed), A);
    }

    fn api_read_scopes() -> Vec<(Operation, Scope)> {
        vec![
            (Operation::ReadCollection, Scope::CalendarsRead),
            (Operation::ListObjects, Scope::EventsRead),
            (Operation::ReadObject, Scope::EventsRead),
            (Operation::FreeBusyQuery, Scope::EventsRead),
        ]
    }

    fn api_write_scopes() -> Vec<(Operation, Scope)> {
        vec![
            (Operation::CreateObject, Scope::EventsWrite),
            (Operation::UpdateObject, Scope::EventsWrite),
            (Operation::DeleteObject, Scope::EventsWrite),
            (Operation::BatchUpsert, Scope::EventsWrite),
            (Operation::RespondToInvitation, Scope::EventsWrite),
            (Operation::UpdateCalendar, Scope::CalendarsWrite),
            (Operation::RenameCalendar, Scope::CalendarsWrite),
            (Operation::CreateCalendar, Scope::CalendarsWrite),
            (Operation::DeleteCalendar, Scope::CalendarsWrite),
            (Operation::ListGrants, Scope::CalendarsWrite),
            (Operation::PutGrant, Scope::CalendarsWrite),
            (Operation::DeleteGrant, Scope::CalendarsWrite),
        ]
    }

    #[test]
    fn api_operations_need_their_scope_before_anything_else() {
        let owned = facts_with_access(CalendarKind::Personal, Some(Access::Owner));
        let nothing = facts_with_access(CalendarKind::Personal, None);
        for (operation, scope) in api_read_scopes().into_iter().chain(api_write_scopes()) {
            let privilege = operation.requirement().unwrap().privilege;
            // Without the scope the answer is 403 whether the caller owns the calendar or has no access at all,
            // so a missing scope never reveals whether a calendar exists.
            let without = token(&[]);
            assert_eq!(
                decide(&without, Channel::Api, &owned, operation),
                f(privilege),
                "{operation}"
            );
            assert_eq!(
                decide(&without, Channel::Api, &nothing, operation),
                f(privilege),
                "{operation}"
            );
            let wrong: Vec<Scope> = Scope::ALL.into_iter().filter(|s| *s != scope).collect();
            assert_eq!(
                decide(&token(&wrong), Channel::Api, &owned, operation),
                f(privilege),
                "{operation}"
            );
            // With the scope the normal rules apply.
            let with = token(&[scope]);
            assert_eq!(decide(&with, Channel::Api, &owned, operation), A, "{operation}");
            let expected_without_access = if operation == Operation::FreeBusyQuery { A } else { H };
            assert_eq!(
                decide(&with, Channel::Api, &nothing, operation),
                expected_without_access,
                "{operation}"
            );
        }
    }

    #[test]
    fn api_operations_without_an_api_route_are_hidden() {
        let owned = facts_with_access(CalendarKind::Personal, Some(Access::Owner));
        let subject = token(&Scope::ALL);
        let routed: Vec<Operation> = api_read_scopes()
            .into_iter()
            .chain(api_write_scopes())
            .map(|(op, _)| op)
            .collect();
        for operation in Operation::ALL {
            if routed.contains(operation) {
                continue;
            }
            assert_eq!(decide(&subject, Channel::Api, &owned, *operation), H, "{operation}");
        }
    }

    /// Expected API decisions for a principal token carrying every scope: the DAV rows of the operations that
    /// exist on both surfaces, plus the rows of the API-only operations.
    fn api_expectations() -> Vec<(Operation, Row)> {
        use Operation::*;
        let on_both = |op: &Operation| {
            op.scope_rule(Channel::Api) != ScopeRule::Unavailable
                && op.scope_rule(Channel::Dav) != ScopeRule::Unavailable
        };
        let mut rows: Vec<(Operation, Row)> = dav_expectations().into_iter().filter(|(op, _)| on_both(op)).collect();
        rows.extend([
            (BatchUpsert, [H, f(WriteContent), A, A, A]),
            (RespondToInvitation, [H, f(WriteContent), A, A, A]),
            (ListGrants, [H, f(Share), f(Share), A, A]),
            (PutGrant, [H, f(Share), f(Share), A, A]),
            (DeleteGrant, [H, f(Share), f(Share), A, A]),
        ]);
        rows
    }

    #[test]
    fn principal_tokens_follow_effective_access_on_the_api() {
        let all = token(&Scope::ALL);
        let rows = api_expectations();
        let routed = api_read_scopes().len() + api_write_scopes().len();
        assert_eq!(rows.len(), routed, "every routed operation has an expectation row");
        // The API applies the same access rules as DAV. Only DAV caps managed calendars at read: a service
        // principal that owns a managed calendar writes it through the API.
        for kind in [
            CalendarKind::Personal,
            CalendarKind::User,
            CalendarKind::Group,
            CalendarKind::Managed,
        ] {
            for (operation, row) in &rows {
                for (access, expected) in ACCESS_COLUMNS.iter().zip(*row) {
                    let facts = facts_with_access(kind, *access);
                    let actual = decide(&all, Channel::Api, &facts, *operation);
                    assert_eq!(actual, expected, "{kind} {operation} with {access:?}");
                }
            }
        }
    }

    #[test]
    fn mirror_calendars_stay_read_only_on_every_principal_surface() {
        let owned = facts_with_access(CalendarKind::Mirror, Some(Access::Owner));
        let api = token(&Scope::ALL);
        assert_eq!(decide(&api, Channel::Api, &owned, Operation::ReadObject), A);
        assert_eq!(decide(&api, Channel::Api, &owned, Operation::CreateObject), f(Bind));
        assert_eq!(
            decide(&api, Channel::Api, &owned, Operation::UpdateObject),
            f(WriteContent)
        );
        assert_eq!(decide(&api, Channel::Api, &owned, Operation::PutGrant), f(Share));
        let mcp = token(&[Scope::McpRead, Scope::McpWrite]);
        assert_eq!(decide(&mcp, Channel::Mcp, &owned, Operation::CreateObject), f(Bind));
        assert_eq!(decide(&mcp, Channel::Mcp, &owned, Operation::ReadObject), A);
    }

    #[test]
    fn mcp_tools_need_mcp_scopes_and_nothing_else_helps() {
        let owned = facts_with_access(CalendarKind::Personal, Some(Access::Owner));
        let read_ops = [
            Operation::ReadCollection,
            Operation::ListObjects,
            Operation::ReadObject,
            Operation::FreeBusyQuery,
        ];
        let write_ops = [
            Operation::CreateObject,
            Operation::UpdateObject,
            Operation::DeleteObject,
            Operation::RespondToInvitation,
        ];
        let non_mcp: Vec<Scope> = Scope::ALL
            .into_iter()
            .filter(|s| !s.as_str().starts_with("mcp:"))
            .collect();
        for operation in read_ops.into_iter().chain(write_ops) {
            let privilege = operation.requirement().unwrap().privilege;
            assert_eq!(
                decide(&token(&non_mcp), Channel::Mcp, &owned, operation),
                f(privilege),
                "{operation}"
            );
        }
        let reader = token(&[Scope::McpRead]);
        let writer = token(&[Scope::McpWrite]);
        for operation in read_ops {
            assert_eq!(decide(&reader, Channel::Mcp, &owned, operation), A, "{operation}");
            assert!(
                matches!(decide(&writer, Channel::Mcp, &owned, operation), Decision::Forbidden(_)),
                "{operation}"
            );
        }
        for operation in write_ops {
            assert_eq!(decide(&writer, Channel::Mcp, &owned, operation), A, "{operation}");
            assert!(
                matches!(decide(&reader, Channel::Mcp, &owned, operation), Decision::Forbidden(_)),
                "{operation}"
            );
        }
        // Tools that do not exist on MCP.
        for operation in [
            Operation::BatchUpsert,
            Operation::ShareCalendar,
            Operation::DeleteCalendar,
            Operation::PutGrant,
        ] {
            assert_eq!(
                decide(&token(&Scope::ALL), Channel::Mcp, &owned, operation),
                H,
                "{operation}"
            );
        }
    }

    #[test]
    fn mcp_respects_read_only_sharees() {
        let mcp = token(&[Scope::McpRead, Scope::McpWrite]);
        let sharee = facts_with_access(CalendarKind::User, Some(Access::Read));
        assert_eq!(decide(&mcp, Channel::Mcp, &sharee, Operation::ListObjects), A);
        assert_eq!(
            decide(&mcp, Channel::Mcp, &sharee, Operation::UpdateObject),
            f(WriteContent)
        );
        let stranger = facts_with_access(CalendarKind::User, None);
        assert_eq!(decide(&mcp, Channel::Mcp, &stranger, Operation::ListObjects), H);
    }

    #[test]
    fn tenant_tokens_reach_events_of_group_and_managed_calendars_only() {
        let scopes = [Scope::EventsRead, Scope::EventsWrite];
        let subject = tenant_token(&scopes);
        let event_ops = [
            (Operation::ListObjects, Privilege::Read),
            (Operation::ReadObject, Privilege::Read),
            (Operation::FreeBusyQuery, Privilege::ReadFreeBusy),
            (Operation::CreateObject, Bind),
            (Operation::UpdateObject, WriteContent),
            (Operation::DeleteObject, Unbind),
            (Operation::BatchUpsert, WriteContent),
        ];
        for kind in CalendarKind::ALL {
            for (operation, privilege) in event_ops {
                let facts = facts(*kind);
                let expected = if matches!(kind, CalendarKind::Group | CalendarKind::Managed) {
                    A
                } else {
                    f(privilege)
                };
                assert_eq!(
                    decide(&subject, Channel::Api, &facts, operation),
                    expected,
                    "{kind} {operation}"
                );
            }
        }
    }

    #[test]
    fn tenant_tokens_administer_calendars_of_every_kind_within_their_scopes() {
        let read = tenant_token(&[Scope::CalendarsRead]);
        let write = tenant_token(&[Scope::CalendarsWrite]);
        for kind in CalendarKind::ALL {
            let facts = facts(*kind);
            assert_eq!(
                decide(&read, Channel::Api, &facts, Operation::ReadCollection),
                A,
                "{kind}"
            );
            for operation in [
                Operation::UpdateCalendar,
                Operation::RenameCalendar,
                Operation::CreateCalendar,
                Operation::ListGrants,
            ] {
                assert_eq!(decide(&write, Channel::Api, &facts, operation), A, "{kind} {operation}");
                assert!(
                    matches!(decide(&read, Channel::Api, &facts, operation), Decision::Forbidden(_)),
                    "{kind} {operation}"
                );
            }
            let grants = if *kind == CalendarKind::Mirror { f(Share) } else { A };
            let delete = if *kind == CalendarKind::Mirror { f(Unbind) } else { A };
            assert_eq!(
                decide(&write, Channel::Api, &facts, Operation::DeleteCalendar),
                delete,
                "{kind}: a mirror is deleted with its account"
            );
            assert!(
                matches!(
                    decide(&read, Channel::Api, &facts, Operation::DeleteCalendar),
                    Decision::Forbidden(_)
                ),
                "{kind}: `calendars:read` does not delete"
            );
            assert_eq!(
                decide(&write, Channel::Api, &facts, Operation::PutGrant),
                grants,
                "{kind}"
            );
            assert_eq!(
                decide(&write, Channel::Api, &facts, Operation::DeleteGrant),
                grants,
                "{kind}"
            );
        }
    }

    #[test]
    fn tenant_tokens_never_impersonate_or_use_other_surfaces() {
        let facts = facts(CalendarKind::Managed);
        let all = tenant_token(&Scope::ALL);
        assert_eq!(
            decide(&all, Channel::Api, &facts, Operation::RespondToInvitation),
            f(WriteContent)
        );
        for operation in Operation::ALL {
            for channel in [Channel::Dav, Channel::Mcp, Channel::Feed, Channel::Rsvp] {
                assert_eq!(decide(&all, channel, &facts, *operation), H, "{channel} {operation}");
            }
        }
        // DAV-only operations do not exist on the API.
        for operation in [
            Operation::ShareCalendar,
            Operation::PropPatchBinding,
            Operation::ReadInbox,
            Operation::MoveObjectTo,
        ] {
            assert_eq!(decide(&all, Channel::Api, &facts, operation), H, "{operation}");
        }
    }

    #[test]
    fn a_tenant_token_without_the_scope_is_forbidden_not_hidden() {
        let facts = facts(CalendarKind::Managed);
        let subject = tenant_token(&[Scope::EventsRead]);
        assert_eq!(decide(&subject, Channel::Api, &facts, Operation::CreateObject), f(Bind));
        assert_eq!(decide(&subject, Channel::Api, &facts, Operation::ReadObject), A);
    }

    // ---------------------------------------------------------------------------------------------------------
    // decide_admin
    // ---------------------------------------------------------------------------------------------------------

    #[test]
    fn every_admin_operation_names_a_scope_and_the_catalog_is_complete() {
        assert_eq!(AdminOperation::ALL.len(), 46);
        for operation in AdminOperation::ALL {
            assert!(!operation.accepted_scopes().is_empty(), "{operation}");
        }
        // Spot checks against the table of PLAN F0.10.
        assert_eq!(AdminOperation::ListTenants.accepted_scopes(), &[Scope::SystemTenants]);
        assert_eq!(
            AdminOperation::GetTenant.accepted_scopes(),
            &[Scope::SystemTenants, Scope::PrincipalsRead]
        );
        assert_eq!(
            AdminOperation::PutPrincipal.accepted_scopes(),
            &[Scope::PrincipalsWrite]
        );
        assert_eq!(
            AdminOperation::GetClientConfig.accepted_scopes(),
            &[Scope::PrincipalsRead]
        );
        assert_eq!(
            AdminOperation::CreateClientConfig.accepted_scopes(),
            &[Scope::CredentialsWrite]
        );
        assert_eq!(
            AdminOperation::RotateFeedToken.accepted_scopes(),
            &[Scope::CredentialsWrite]
        );
        assert_eq!(
            AdminOperation::RedeliverWebhook.accepted_scopes(),
            &[Scope::WebhooksManage]
        );
        assert_eq!(
            AdminOperation::ListProviders.accepted_scopes(),
            &[Scope::ProvidersManage]
        );
        assert_eq!(AdminOperation::ListAuditEvents.accepted_scopes(), &[Scope::AuditRead]);
        assert_eq!(AdminOperation::RetryOutbox.accepted_scopes(), &[Scope::OutboxManage]);
        assert_eq!(AdminOperation::InboundItip.accepted_scopes(), &[Scope::ItipInbound]);
        assert_eq!(
            AdminOperation::SearchCalendars.accepted_scopes(),
            &[Scope::CalendarsRead]
        );
        assert_eq!(AdminOperation::ListBindings.accepted_scopes(), &[Scope::CalendarsRead]);
        assert_eq!(
            AdminOperation::RestoreBinding.accepted_scopes(),
            &[Scope::CalendarsWrite]
        );
    }

    #[test]
    fn system_tokens_manage_tenants_and_nothing_else() {
        let system = Subject::new(Actor::SystemToken(TOKEN), ScopeSet::of(&[Scope::SystemTenants]));
        for operation in AdminOperation::ALL {
            let tenant_op = matches!(
                operation,
                AdminOperation::ListTenants
                    | AdminOperation::GetTenant
                    | AdminOperation::PutTenant
                    | AdminOperation::PatchTenant
                    | AdminOperation::DeleteTenant
            );
            let expected = if tenant_op {
                AdminDecision::Allow
            } else {
                AdminDecision::Forbidden
            };
            assert_eq!(decide_admin(&system, Channel::Api, *operation), expected, "{operation}");
        }
        let empty = Subject::new(Actor::SystemToken(TOKEN), ScopeSet::empty());
        assert_eq!(
            decide_admin(&empty, Channel::Api, AdminOperation::ListTenants),
            AdminDecision::Forbidden
        );
    }

    #[test]
    fn tenant_tokens_use_the_operations_of_their_scopes() {
        for operation in AdminOperation::ALL {
            for scope in Scope::ALL {
                let subject = tenant_token(&[scope]);
                let usable =
                    scope.allowed_for(crate::scope::TokenKind::Tenant) && operation.accepted_scopes().contains(&scope);
                let expected = if usable {
                    AdminDecision::Allow
                } else {
                    AdminDecision::Forbidden
                };
                assert_eq!(
                    decide_admin(&subject, Channel::Api, *operation),
                    expected,
                    "{operation} with {scope}"
                );
            }
        }
        // `system:tenants` on a tenant token is meaningless: tenant tokens cannot manage tenants.
        let bogus = tenant_token(&[Scope::SystemTenants]);
        assert_eq!(
            decide_admin(&bogus, Channel::Api, AdminOperation::PutTenant),
            AdminDecision::Forbidden
        );
        // GET of the own tenant is allowed with principals:read.
        let reader = tenant_token(&[Scope::PrincipalsRead]);
        assert_eq!(
            decide_admin(&reader, Channel::Api, AdminOperation::GetTenant),
            AdminDecision::Allow
        );
        assert_eq!(
            decide_admin(&reader, Channel::Api, AdminOperation::PatchTenant),
            AdminDecision::Forbidden
        );
        let all = tenant_token(&Scope::ALL);
        for operation in [
            AdminOperation::ListTenants,
            AdminOperation::PutTenant,
            AdminOperation::DeleteTenant,
        ] {
            assert_eq!(
                decide_admin(&all, Channel::Api, operation),
                AdminDecision::Forbidden,
                "{operation}"
            );
        }
    }

    #[test]
    fn nobody_else_administers_anything() {
        let others = [
            Subject::new(Actor::Principal(ME), ScopeSet::all()),
            Subject::new(
                Actor::PrincipalToken {
                    principal: ME,
                    token: TOKEN,
                },
                ScopeSet::all(),
            ),
            Subject::new(
                Actor::FeedReader {
                    principal: ME,
                    token: TOKEN,
                },
                ScopeSet::all(),
            ),
            Subject::new(Actor::Anonymous, ScopeSet::all()),
        ];
        for subject in &others {
            for operation in AdminOperation::ALL {
                assert_eq!(
                    decide_admin(subject, Channel::Api, *operation),
                    AdminDecision::Forbidden,
                    "{operation}"
                );
            }
        }
        let tenant = tenant_token(&Scope::ALL);
        for channel in [Channel::Dav, Channel::Mcp, Channel::Feed, Channel::Rsvp] {
            assert_eq!(
                decide_admin(&tenant, channel, AdminOperation::ListPrincipals),
                AdminDecision::Forbidden
            );
        }
        assert_eq!(
            decide_admin(&others[3], Channel::Internal, AdminOperation::ListPrincipals),
            AdminDecision::Allow
        );
    }

    // ---------------------------------------------------------------------------------------------------------
    // Operation catalog
    // ---------------------------------------------------------------------------------------------------------

    #[test]
    fn operation_names_are_unique_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for operation in Operation::ALL {
            let name = operation.as_str();
            assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{name}");
            assert!(seen.insert(name), "{name}");
            assert_eq!(name.parse::<Operation>().unwrap(), *operation);
        }
        assert_eq!(Operation::ALL.len(), 32);
        for operation in AdminOperation::ALL {
            assert!(
                seen.insert(operation.as_str()),
                "{operation} collides with an operation name"
            );
        }
    }

    #[test]
    fn requirements_are_consistent_with_the_privilege_tables() {
        for operation in Operation::ALL {
            match operation.requirement() {
                None => assert!(
                    matches!(
                        operation,
                        Operation::PropPatchBinding
                            | Operation::RemoveBinding
                            | Operation::ReplyInvite
                            | Operation::RsvpView
                            | Operation::RsvpAnswer
                    ),
                    "{operation}"
                ),
                Some(requirement) => {
                    // The privilege must be among those the required access has on the operation's resource kind.
                    if *operation != Operation::FreeBusyQuery {
                        let granted = privileges(requirement.access, CalendarKind::User, operation.resource_kind());
                        assert!(granted.contains(requirement.privilege), "{operation}: {granted:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn subject_follows_the_request_context() {
        let ctx = RequestContext::internal(
            crate::ids::TenantId::from_uuid(uuid::Uuid::from_u128(1)),
            crate::ids::RequestId::from_uuid(uuid::Uuid::from_u128(2)),
        );
        let subject = Subject::from(&ctx);
        assert_eq!(subject.actor, Actor::Anonymous);
        assert_eq!(subject.principal(), None);
        assert_eq!(
            Subject::new(Actor::Principal(ME), ScopeSet::empty()).principal(),
            Some(ME)
        );
    }

    #[test]
    fn grant_facts_copy_the_relevant_columns() {
        use chrono::DateTime;
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let entity = Grant {
            id: crate::ids::GrantId::from_uuid(uuid::Uuid::from_u128(1)),
            tenant_id: crate::ids::TenantId::from_uuid(uuid::Uuid::from_u128(2)),
            calendar_id: CalendarId::from_uuid(uuid::Uuid::from_u128(3)),
            grantee_id: ME,
            access: GrantAccess::Admin,
            status: GrantStatus::Accepted,
            source: crate::entities::GrantSource::Api,
            required: false,
            invite_uid: None,
            summary: None,
            common_name: None,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        assert_eq!(
            GrantFact::from(&entity),
            grant(ME, GrantAccess::Admin, GrantStatus::Accepted)
        );
        let required = Grant {
            required: true,
            ..entity
        };
        assert!(GrantFact::from(&required).required);
    }

    fn required_grant(grantee: PrincipalId, status: GrantStatus) -> GrantFact {
        GrantFact {
            required: true,
            ..grant(grantee, GrantAccess::Read, status)
        }
    }

    #[test]
    fn a_required_grant_forbids_removing_the_binding_for_the_grantee_and_for_group_members() {
        let team = PrincipalId::from_uuid(uuid::Uuid::from_u128(0x7001));
        let forbidden = Decision::Forbidden(Privilege::Unbind);
        // Directly granted to the caller.
        let mut facts = facts(CalendarKind::Managed);
        facts.grants = vec![required_grant(ME, GrantStatus::Accepted)];
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::RemoveBinding),
            forbidden
        );
        // Through a group the caller belongs to.
        facts.grants = vec![required_grant(team, GrantStatus::Accepted)];
        facts.memberships = vec![team];
        assert_eq!(
            decide(&dav_user(), Channel::Dav, &facts, Operation::RemoveBinding),
            forbidden
        );
        assert!(binding_required(ME, &facts));
        // The flag restricts leaving and nothing else.
        for operation in [
            Operation::ReadCollection,
            Operation::PropPatchBinding,
            Operation::ReadObject,
        ] {
            assert_eq!(decide(&dav_user(), Channel::Dav, &facts, operation), A, "{operation}");
        }
    }

    #[test]
    fn an_optional_pending_declined_or_foreign_grant_does_not_hold_the_binding() {
        let team = PrincipalId::from_uuid(uuid::Uuid::from_u128(0x7001));
        let mut facts = facts(CalendarKind::Group);
        facts.memberships = vec![team];
        // Not required: the member may hide the calendar.
        facts.grants = vec![grant(team, GrantAccess::Read, GrantStatus::Accepted)];
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::RemoveBinding), A);
        // Required, but it confers nothing (yet or any more), or it is another group's.
        for held in [
            required_grant(team, GrantStatus::Pending),
            required_grant(team, GrantStatus::Declined),
            required_grant(OTHER, GrantStatus::Accepted),
        ] {
            facts.grants = vec![held, grant(ME, GrantAccess::Read, GrantStatus::Accepted)];
            assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::RemoveBinding), A);
            assert!(!binding_required(ME, &facts));
        }
        // Without a binding there is nothing to remove, required or not.
        facts.grants = vec![required_grant(ME, GrantStatus::Accepted)];
        facts.binding = None;
        assert_eq!(decide(&dav_user(), Channel::Dav, &facts, Operation::RemoveBinding), H);
    }
}
