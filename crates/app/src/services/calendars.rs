//! Calendars: homes, bindings, collections, collection properties and the management API's calendar resources.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    Access, BindingId, CalendarId, CalendarKind, CalendarSlug, CalendarUserAddress, ComponentKind, ErrorKind,
    GrantAccess, GrantStatus, Precondition, PrincipalId, PrincipalKind, PrincipalName, PrivilegeSet, RequestContext,
    ResourcePath, SyncToken, Transparency,
};
use davhaven_wire::{CalendarView, CalendarWrite, HomeBindingView, Page};
use futures::future::join_all;

use super::common::{Conditions, MergePatch, PageRequest, Upserted};
use crate::error::{AppError, AppResult};

/// The XML namespace of WebDAV (`DAV:`).
pub const NS_DAV: &str = "DAV:";
/// The XML namespace of CalDAV.
pub const NS_CALDAV: &str = "urn:ietf:params:xml:ns:caldav";
/// The XML namespace of Apple's calendar extensions (`calendar-color`, `calendar-order`).
pub const NS_APPLE_ICAL: &str = "http://apple.com/ns/ical/";
/// The XML namespace of CalendarServer extensions (sharing, notifications).
pub const NS_CALENDARSERVER: &str = "http://calendarserver.org/ns/";

/// Addresses a calendar: by id (MCP, webhooks) or by its natural key (management API paths).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CalendarRef {
    /// The calendar id.
    Id(CalendarId),
    /// The owner's principal name and the calendar slug.
    Key {
        /// The owning principal.
        owner: PrincipalName,
        /// The calendar slug.
        slug: CalendarSlug,
    },
}

/// The natural key and the body of a calendar `PUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarSpec {
    /// The owning principal from the path.
    pub owner: PrincipalName,
    /// The calendar slug from the path.
    pub slug: CalendarSlug,
    /// The request body.
    pub body: CalendarWrite,
}

/// A principal as other principals' resources refer to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalSummary {
    /// The principal id.
    pub id: PrincipalId,
    /// The immutable name.
    pub name: PrincipalName,
    /// The display name.
    pub display_name: String,
    /// What the principal represents.
    pub kind: PrincipalKind,
}

/// How a principal relates to a calendar's sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingRole {
    /// The calendar is not shared and the viewer owns it (or sees it through group membership).
    Unshared,
    /// The viewer owns a calendar that has invitations or grants (`CS:shared-owner`).
    Owner,
    /// The viewer sees someone else's calendar through an accepted share (`CS:shared`).
    Sharee,
}

/// The filter of [`CalendarService::list_bindings`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BindingFilter {
    /// `Some(true)` lists only the bindings the principal removed from their home, `Some(false)` only the visible ones,
    /// `None` all of them.
    pub hidden: Option<bool>,
}

/// A calendar in a principal's home: the calendar with the principal's binding overrides applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingView {
    /// The binding.
    pub binding_id: BindingId,
    /// The calendar behind it.
    pub calendar_id: CalendarId,
    /// The collection in the viewer's home.
    pub path: ResourcePath,
    /// The owner of the calendar.
    pub owner: PrincipalSummary,
    /// The kind of calendar.
    pub kind: CalendarKind,
    /// The display name (the binding's override or the calendar's).
    pub display_name: String,
    /// The description.
    pub description: Option<String>,
    /// The color as `#RRGGBB` or `#RRGGBBAA`.
    pub color: Option<String>,
    /// The sort order hint.
    pub sort_order: i32,
    /// The component types the calendar accepts.
    pub components: Vec<ComponentKind>,
    /// The `VTIMEZONE` text of the default time zone (`calendar-timezone`).
    pub timezone_ics: Option<String>,
    /// `schedule-calendar-transp` for the viewer.
    pub schedule_transp: Transparency,
    /// The viewer's effective access.
    pub access: Access,
    /// The DAV privileges the access confers on this kind of calendar (`current-user-privilege-set`).
    pub privileges: PrivilegeSet,
    /// How the viewer relates to the calendar's sharing.
    pub sharing: SharingRole,
    /// For sharees: the owner's collection (`CS:shared-url`).
    pub shared_url: Option<ResourcePath>,
    /// The current sync token, which is also the `getctag`.
    pub sync_token: SyncToken,
    /// When the calendar was created.
    pub created_at: DateTime<Utc>,
    /// When the calendar was last changed.
    pub updated_at: DateTime<Utc>,
}

/// A qualified XML name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PropertyName {
    /// The namespace URI, for example [`NS_DAV`].
    pub namespace: String,
    /// The local name, for example `displayname`.
    pub local: String,
}

impl PropertyName {
    /// A name in `namespace`.
    pub fn new(namespace: &str, local: &str) -> Self {
        Self {
            namespace: namespace.to_owned(),
            local: local.to_owned(),
        }
    }
}

/// A property the server does not interpret (dead property), stored as XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadProperty {
    /// The property name.
    pub name: PropertyName,
    /// The value as the XML of the property element's content.
    pub value_xml: String,
}

impl DeadProperty {
    /// What the property counts against `limits.dav.max_dead_property_size`: its namespace, its local name and its
    /// value, in bytes. A name is data the client chooses, so it is as much a way to fill the store as the value.
    pub fn size(&self) -> usize {
        self.name
            .namespace
            .len()
            .saturating_add(self.name.local.len())
            .saturating_add(self.value_xml.len())
    }
}

/// An invitation or grant as `CS:invite` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteView {
    /// The sharee's address (`mailto:` for people).
    pub address: CalendarUserAddress,
    /// The sharee's display name.
    pub common_name: Option<String>,
    /// The access the sharee gets.
    pub access: GrantAccess,
    /// Pending, accepted or declined.
    pub status: GrantStatus,
    /// The summary shown in the invitation.
    pub summary: Option<String>,
}

/// A collection resource with everything PROPFIND may ask for.
///
/// Used for calendar collections and for the special collections of a home (inbox, outbox, notifications) and
/// the home itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionView {
    /// The collection.
    pub path: ResourcePath,
    /// The display name.
    pub display_name: String,
    /// The viewer's privileges on the collection (`current-user-privilege-set`).
    pub privileges: PrivilegeSet,
    /// The sync token (and `getctag`) of collections with a change log; `None` for the home and the outbox.
    pub sync_token: Option<SyncToken>,
    /// For calendar collections: the calendar properties; `None` for the other collections.
    pub calendar: Option<BindingView>,
    /// The dead properties of the collection.
    pub dead_properties: Vec<DeadProperty>,
    /// For calendars the viewer may share: the invitations (`CS:invite`).
    pub invites: Vec<InviteView>,
}

impl CollectionView {
    /// The collection a listing of a home shows for one binding: everything the binding carries, and no dead
    /// properties or invitations (they need [`HomeDetail`] when a listing is read in one go).
    pub fn from_binding(binding: &BindingView) -> Self {
        Self {
            path: binding.path.clone(),
            display_name: binding.display_name.clone(),
            privileges: binding.privileges,
            sync_token: Some(binding.sync_token),
            calendar: Some(binding.clone()),
            dead_properties: Vec::new(),
            invites: Vec::new(),
        }
    }
}

/// What a listing of a calendar home needs besides the bindings themselves (see
/// [`CalendarService::list_home_collections`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HomeDetail {
    /// The dead properties of every calendar.
    pub dead_properties: bool,
    /// The invitations of every calendar the viewer may share (`CS:invite`).
    pub invites: bool,
    /// The inbox, the outbox and the notification collection of the home.
    pub special: bool,
}

/// The request of MKCALENDAR and extended MKCOL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MkCalendar {
    /// The collection to create: `ResourcePath::Collection`, so the home owner and the slug are known.
    pub path: ResourcePath,
    /// The display name.
    pub display_name: Option<String>,
    /// The description.
    pub description: Option<String>,
    /// The color.
    pub color: Option<String>,
    /// The sort order hint.
    pub sort_order: Option<i32>,
    /// The component types to accept (`supported-calendar-component-set`); the tenant default when absent.
    pub components: Option<Vec<ComponentKind>>,
    /// The `VTIMEZONE` text of the default time zone.
    pub timezone_ics: Option<String>,
    /// `schedule-calendar-transp`.
    pub schedule_transp: Option<Transparency>,
    /// Dead properties to set.
    pub dead_properties: Vec<DeadProperty>,
}

/// One change of a PROPPATCH. `None` removes the property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyChange {
    /// `DAV:displayname`.
    DisplayName(Option<String>),
    /// `CALDAV:calendar-description`.
    Description(Option<String>),
    /// `apple-ical:calendar-color`.
    Color(Option<String>),
    /// `apple-ical:calendar-order`.
    Order(Option<i32>),
    /// `CALDAV:calendar-timezone`.
    Timezone(Option<String>),
    /// `CALDAV:schedule-calendar-transp`.
    ScheduleTransparency(Option<Transparency>),
    /// Any other property, stored as XML.
    Dead {
        /// The property name.
        name: PropertyName,
        /// The new value; `None` removes the property.
        value_xml: Option<String>,
    },
}

impl PropertyChange {
    /// The qualified name of the property the change affects.
    pub fn name(&self) -> PropertyName {
        match self {
            Self::DisplayName(_) => PropertyName::new(NS_DAV, "displayname"),
            Self::Description(_) => PropertyName::new(NS_CALDAV, "calendar-description"),
            Self::Color(_) => PropertyName::new(NS_APPLE_ICAL, "calendar-color"),
            Self::Order(_) => PropertyName::new(NS_APPLE_ICAL, "calendar-order"),
            Self::Timezone(_) => PropertyName::new(NS_CALDAV, "calendar-timezone"),
            Self::ScheduleTransparency(_) => PropertyName::new(NS_CALDAV, "schedule-calendar-transp"),
            Self::Dead { name, .. } => name.clone(),
        }
    }
}

/// The changes of one PROPPATCH, applied atomically (all or none).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PropPatch {
    /// The changes in document order.
    pub changes: Vec<PropertyChange>,
}

/// The status of one property of a PROPPATCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyStatus {
    /// The change was applied (200).
    Applied,
    /// The caller may not change the property (403); the protected-property precondition applies to live
    /// properties that cannot be set by clients.
    Forbidden,
    /// The value is not acceptable (409).
    Conflict,
    /// Another property of the request failed, so this one was not applied (424).
    FailedDependency,
    /// A property limit was exceeded (507).
    InsufficientStorage,
}

/// The status of one property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyOutcome {
    /// The property.
    pub name: PropertyName,
    /// What happened to it.
    pub status: PropertyStatus,
    /// The precondition the value of the property violates, when the status alone does not say which: a
    /// `calendar-timezone` that is no iCalendar object with one `VTIMEZONE` is a `Conflict` with
    /// `valid-calendar-data` (RFC 4791 section 5.2.2). `None` for the properties that were fine, for those that
    /// depend on a failure and for refusals that need no precondition.
    pub precondition: Option<Precondition>,
}

/// The result of a PROPPATCH: one entry per requested change, in request order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropPatchOutcome {
    /// The per-property statuses; either all `Applied` or at least one failure with the rest
    /// `FailedDependency`.
    pub results: Vec<PropertyOutcome>,
}

impl PropPatchOutcome {
    /// Whether every change was applied.
    pub fn is_applied(&self) -> bool {
        self.results
            .iter()
            .all(|result| result.status == PropertyStatus::Applied)
    }
}

/// The filters of `GET /tenants/{tenant}/calendars`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CalendarSearch {
    /// Only calendars whose display name contains this text (case-insensitive).
    pub query: Option<String>,
    /// Only calendars of this kind.
    pub kind: Option<CalendarKind>,
    /// Only calendars of this owner.
    pub owner: Option<PrincipalName>,
}

/// Calendar collections and their properties.
#[async_trait]
pub trait CalendarService: Send + Sync {
    /// The calendars of a principal's home: owned calendars plus every calendar the principal can see. Group,
    /// managed and share bindings are created lazily on the first listing (PLAN 2.9).
    ///
    /// # Errors
    ///
    /// `NotFound` when the home is not visible to the caller (other principals' homes are, except for tenant
    /// administrators on the API).
    async fn list_home(&self, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Vec<BindingView>>;

    /// The collections of a home in one go, for `PROPFIND` with `Depth: 1`: the calendars (as
    /// [`list_home`](Self::list_home) lists them, with the dead properties and invitations `detail` asks for) and,
    /// when `detail.special` is set, the inbox, the outbox and the notification collection. A collection that
    /// disappears while the listing is made, or that the viewer may not see, is left out instead of failing the
    /// listing.
    ///
    /// Implementations load the authorization facts once and read all collections with one query (R14). The
    /// default answers from [`list_home`](Self::list_home) and reads the collections that need more with
    /// [`get_collection`](Self::get_collection), concurrently: correct, but one read per calendar.
    ///
    /// # Errors
    ///
    /// `NotFound` when the home is not visible to the caller or `home` is not a calendar home.
    async fn list_home_collections(
        &self,
        ctx: &RequestContext,
        home: &ResourcePath,
        detail: HomeDetail,
    ) -> AppResult<Vec<CollectionView>> {
        let ResourcePath::Home { tenant, principal } = home else {
            return Err(AppError::not_found());
        };
        let bindings = self.list_home(ctx, principal).await?;
        let mut collections = Vec::with_capacity(bindings.len().saturating_add(3));
        let mut reads = Vec::new();
        for binding in &bindings {
            if detail.dead_properties || detail.invites {
                reads.push(binding.path.clone());
            } else {
                collections.push(CollectionView::from_binding(binding));
            }
        }
        for read in join_all(reads.iter().map(|path| self.get_collection(ctx, path))).await {
            match read {
                Ok(view) => collections.push(view),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if detail.special {
            let special = [
                ResourcePath::Inbox {
                    tenant: tenant.clone(),
                    principal: principal.clone(),
                },
                ResourcePath::Outbox {
                    tenant: tenant.clone(),
                    principal: principal.clone(),
                },
                ResourcePath::Notifications {
                    tenant: tenant.clone(),
                    principal: principal.clone(),
                },
            ];
            for read in join_all(special.iter().map(|path| self.get_collection(ctx, path))).await {
                match read {
                    Ok(view) => collections.push(view),
                    Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::Forbidden) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(collections)
    }

    /// Reads one collection of a home: a calendar, the inbox, the outbox, the notification collection or the home.
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown and invisible collections.
    async fn get_collection(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<CollectionView>;

    /// Creates a calendar (MKCALENDAR, extended MKCOL).
    ///
    /// # Errors
    ///
    /// `Conflict` with `DAV:resource-must-be-null` when the slug is taken, `Forbidden` for homes of other
    /// principals and for tenants that do not allow user calendars, `Invalid` for bad properties.
    async fn mkcalendar(&self, ctx: &RequestContext, request: MkCalendar) -> AppResult<BindingView>;

    /// Applies a PROPPATCH. Per-binding properties (display name, color, order, transparency, default alarms,
    /// dead properties) are always allowed for the binding's principal; shared properties need write access.
    ///
    /// # Errors
    ///
    /// `NotFound` for invisible collections. Rejected properties are reported in the outcome, not as errors.
    async fn proppatch(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        patch: PropPatch,
    ) -> AppResult<PropPatchOutcome>;

    /// Deletes a collection: for owners the calendar is soft-deleted for everyone, for sharees the binding is
    /// removed and the grant declined, for group and managed calendars the binding is hidden (PLAN 2.9).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `PreconditionFailed`.
    async fn delete_collection(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        conditions: Conditions,
    ) -> AppResult<()>;

    /// Reads a calendar by natural key or id (management API).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn get(&self, ctx: &RequestContext, calendar: &CalendarRef) -> AppResult<CalendarView>;

    /// Lists the calendars a principal owns, ordered by id (management API).
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown principals, `Forbidden`, `Invalid` for a bad cursor.
    async fn list_owned(
        &self,
        ctx: &RequestContext,
        owner: &PrincipalName,
        page: PageRequest,
    ) -> AppResult<Page<CalendarView>>;

    /// Creates or replaces a calendar (management API `PUT`).
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown owners, `PreconditionFailed`, `Conflict`, `Invalid`, `Forbidden`.
    async fn upsert(
        &self,
        ctx: &RequestContext,
        spec: CalendarSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<CalendarView>>;

    /// Changes a calendar with a JSON Merge Patch.
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed`, `Invalid`, `Forbidden`.
    async fn patch(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<CalendarView>;

    /// Deletes a calendar for everyone (management API). Requires `If-Match`.
    ///
    /// # Errors
    ///
    /// `PreconditionRequired`, `PreconditionFailed`, `NotFound`, `Forbidden`.
    async fn delete(&self, ctx: &RequestContext, calendar: &CalendarRef, conditions: Conditions) -> AppResult<()>;

    /// Searches the calendars of the tenant (management API).
    ///
    /// # Errors
    ///
    /// `Forbidden` without `calendars:read`, `Invalid` for a bad cursor.
    async fn list_tenant(
        &self,
        ctx: &RequestContext,
        search: CalendarSearch,
        page: PageRequest,
    ) -> AppResult<Page<CalendarView>>;

    /// Lists the calendars in the home of a principal as the management API shows them: the bindings their calendar apps can
    /// list, **hidden ones included** (a principal who deletes a shared calendar in a calendar app hides its binding), with
    /// whether the calendar is required for the principal. A calendar the principal can no longer reach is not listed, and a
    /// binding is created at the principal's first listing of the home, so the list holds the bindings created so far.
    /// Ordered by binding id. `calendars:read` of a tenant token.
    ///
    /// # Errors
    ///
    /// `Forbidden` without `calendars:read` (and for every caller that is not a tenant administrator), `NotFound` for an
    /// unknown principal, `Invalid` for a bad cursor.
    async fn list_bindings(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        filter: BindingFilter,
        page: PageRequest,
    ) -> AppResult<Page<HomeBindingView>>;

    /// Shows a hidden binding in the home of the principal again; the calendar is listed by their calendar apps at the next
    /// sync. Restoring a binding that is visible changes nothing; one of a calendar the principal can no longer reach is as
    /// good as gone. The restoration is audited. `calendars:write` of a tenant token.
    ///
    /// # Errors
    ///
    /// `Forbidden` without `calendars:write` (and for every caller that is not a tenant administrator), `NotFound` for an
    /// unknown principal, binding or one that is out of reach.
    async fn restore_binding(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        binding: &CalendarSlug,
    ) -> AppResult<HomeBindingView>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_properties_have_their_dav_names() {
        let cases = [
            (PropertyChange::DisplayName(None), NS_DAV, "displayname"),
            (PropertyChange::Description(None), NS_CALDAV, "calendar-description"),
            (PropertyChange::Color(None), NS_APPLE_ICAL, "calendar-color"),
            (PropertyChange::Order(Some(1)), NS_APPLE_ICAL, "calendar-order"),
            (PropertyChange::Timezone(None), NS_CALDAV, "calendar-timezone"),
            (
                PropertyChange::ScheduleTransparency(Some(Transparency::Transparent)),
                NS_CALDAV,
                "schedule-calendar-transp",
            ),
        ];
        for (change, namespace, local) in cases {
            assert_eq!(change.name(), PropertyName::new(namespace, local));
        }
        let dead = PropertyChange::Dead {
            name: PropertyName::new("urn:example", "note"),
            value_xml: Some("<x/>".to_owned()),
        };
        assert_eq!(dead.name().local, "note");
    }

    #[test]
    fn a_patch_is_applied_only_when_every_property_is() {
        let ok = PropertyOutcome {
            name: PropertyName::new(NS_DAV, "displayname"),
            status: PropertyStatus::Applied,
            precondition: None,
        };
        let failed = PropertyOutcome {
            name: PropertyName::new(NS_DAV, "getetag"),
            status: PropertyStatus::Forbidden,
            precondition: None,
        };
        assert!(
            PropPatchOutcome {
                results: vec![ok.clone()]
            }
            .is_applied()
        );
        assert!(
            !PropPatchOutcome {
                results: vec![ok, failed]
            }
            .is_applied()
        );
        assert!(PropPatchOutcome { results: Vec::new() }.is_applied());
    }
}
