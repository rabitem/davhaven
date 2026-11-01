//! DAV, CalDAV, CalendarServer and Apple properties.
//!
//! This module is the catalog of the properties the server computes (`live` properties) and the one place that
//! knows what each of them looks like on each kind of resource ([`Subject`]):
//!
//! | Subject | Properties |
//! | --- | --- |
//! | the entry point `/dav/` | `resourcetype`, `current-user-principal`, `principal-collection-set` |
//! | a principal | identity (`displayname`, `principal-URL`, addresses, `group-membership`), the URLs of home, inbox, outbox and notifications, `CS:email-address-set`, proxy properties (empty) |
//! | a calendar home | `resourcetype`, `displayname`, `owner`, privileges |
//! | a calendar collection | everything of RFC 4791 section 5.2, `getctag`, `sync-token`, `CS:invite`, `CS:allowed-sharing-modes`, `calendar-color`, `calendar-order` |
//! | the inbox, outbox and notifications | `resourcetype`, `displayname`, `owner`, privileges, token |
//! | a calendar object | `getetag`, `getcontenttype`, `getcontentlength`, `getlastmodified`, `calendar-data`, `schedule-tag` |
//! | a notification | the entity tag, content type, size and date of the XML document, `CS:notificationtype` |
//! | a scheduling inbox item | the entity tag, content type, size and date of the iTIP message, `calendar-data` |
//! | a principal a search found | display name, addresses and user type only ([`Subject::SearchHit`]) |
//!
//! [`render`] returns the inner XML of one property or `None` when the resource does not have it, which the
//! multistatus turns into a 404 `propstat`. `propname` and `allprop` are derived from the same function
//! ([`property_names`]), so what a resource lists is exactly what it can answer. Properties a client stores
//! (dead properties, PLAN 2.4 `collection_properties`) come with the collection and are rendered as they were
//! written ([`crate::xml::write::serialize_content`]).
//!
//! The second half of the module reads the values of PROPPATCH and MKCALENDAR ([`interpret_set`]): the six
//! properties clients may set map to [`PropertyChange`]s, other live properties are protected, and anything else is
//! a dead property within the size limit.

use core::fmt::Write as _;

use chrono::{DateTime, Utc};
use davhaven_app::AppServices;
use davhaven_app::services::{
    BindingView, CollectionView, HomeDetail, InboxItemView, NS_APPLE_ICAL, NS_CALDAV, NS_CALENDARSERVER, NS_DAV,
    NotificationView, ObjectView, PrincipalHit, PrincipalProps, PropertyChange, PropertyName, SharingRole,
};
use davhaven_domain::{
    Access, CalendarKind, CalendarUserAddress, ComponentKind, ETag, GrantAccess, GrantStatus, Limits, NotificationKind,
    PrincipalKind, PrincipalName, Privilege, PrivilegeSet, ResourceKind, ResourcePath, TenantSlug, Transparency,
    privileges,
};

use crate::errors::privilege_element;
use crate::xml::Element;
use crate::xml::requests::{PropRequest, Update, format_utc};
use crate::xml::write::{Prefixes, Propstat, XmlWriter, escape_text, serialize_content_within};

/// A resource a property is asked of.
#[derive(Debug, Clone)]
pub enum Subject {
    /// The entry point `/dav/`.
    Root,
    /// A principal.
    Principal(PrincipalProps),
    /// A calendar home, a calendar collection, or the inbox, outbox or notification collection.
    Collection(CollectionView),
    /// A calendar object resource.
    Object(ObjectView),
    /// A member that `sync-collection` reports by name and entity tag only.
    Member {
        /// The member resource.
        path: ResourcePath,
        /// Its entity tag.
        etag: ETag,
    },
    /// A resource of the notification collection: an invitation or the answer to one.
    Notification(NotificationView),
    /// An item of the scheduling inbox: an iTIP message that was delivered to the principal.
    InboxItem(InboxItemView),
    /// A principal a search found. A search tells the display name and the addresses of a principal and nothing
    /// else (PLAN 2.9): the URLs of home, inbox and outbox are not part of it.
    SearchHit(PrincipalHit),
}

impl Subject {
    /// The resource.
    pub fn path(&self) -> ResourcePath {
        match self {
            Self::Root => ResourcePath::Root,
            Self::Principal(principal) => principal.path.clone(),
            Self::Collection(collection) => collection.path.clone(),
            Self::Object(object) => object.path.clone(),
            Self::Member { path, .. } => path.clone(),
            Self::Notification(notification) => notification.path.clone(),
            Self::InboxItem(item) => item.path.clone(),
            Self::SearchHit(hit) => hit.path.clone(),
        }
    }

    /// The collection a listing of a calendar home shows for one binding.
    pub fn from_binding(binding: &BindingView) -> Self {
        Self::Collection(CollectionView::from_binding(binding))
    }
}

/// What rendering needs besides the subject.
#[derive(Debug, Clone, Copy)]
pub struct Env<'a> {
    /// The application services: limits for the CalDAV limit properties.
    pub services: &'a AppServices,
    /// The principal the request is authenticated as, for `current-user-principal`.
    pub current: Option<&'a PrincipalProps>,
    /// The prefixes of the namespaces of the request, which the document declares once on its root.
    pub prefixes: &'a Prefixes,
}

type Names = &'static [(&'static str, &'static str)];

const ROOT_PROPS: Names = &[
    (NS_DAV, "resourcetype"),
    (NS_DAV, "current-user-principal"),
    (NS_DAV, "principal-collection-set"),
    (NS_DAV, "current-user-privilege-set"),
    (NS_DAV, "supported-report-set"),
    (NS_DAV, "supportedlock"),
    (NS_DAV, "lockdiscovery"),
];

const PRINCIPAL_PROPS: Names = &[
    (NS_DAV, "resourcetype"),
    (NS_DAV, "displayname"),
    (NS_DAV, "principal-URL"),
    (NS_DAV, "alternate-URI-set"),
    (NS_DAV, "group-membership"),
    (NS_DAV, "group-member-set"),
    (NS_DAV, "owner"),
    (NS_DAV, "current-user-principal"),
    (NS_DAV, "principal-collection-set"),
    (NS_DAV, "current-user-privilege-set"),
    (NS_DAV, "supported-report-set"),
    (NS_DAV, "supportedlock"),
    (NS_DAV, "lockdiscovery"),
    (NS_CALDAV, "calendar-home-set"),
    (NS_CALDAV, "calendar-user-address-set"),
    (NS_CALDAV, "calendar-user-type"),
    (NS_CALDAV, "schedule-inbox-URL"),
    (NS_CALDAV, "schedule-outbox-URL"),
    (NS_CALENDARSERVER, "notification-URL"),
    (NS_CALENDARSERVER, "email-address-set"),
    (NS_CALENDARSERVER, "calendar-proxy-read-for"),
    (NS_CALENDARSERVER, "calendar-proxy-write-for"),
];

const COLLECTION_PROPS: Names = &[
    (NS_DAV, "resourcetype"),
    (NS_DAV, "displayname"),
    (NS_DAV, "creationdate"),
    (NS_DAV, "getlastmodified"),
    (NS_DAV, "owner"),
    (NS_DAV, "current-user-principal"),
    (NS_DAV, "current-user-privilege-set"),
    (NS_DAV, "supported-privilege-set"),
    (NS_DAV, "supported-report-set"),
    (NS_DAV, "sync-token"),
    (NS_DAV, "supportedlock"),
    (NS_DAV, "lockdiscovery"),
    (NS_CALDAV, "calendar-description"),
    (NS_CALDAV, "calendar-timezone"),
    (NS_CALDAV, "supported-calendar-component-set"),
    (NS_CALDAV, "supported-calendar-data"),
    (NS_CALDAV, "supported-collation-set"),
    (NS_CALDAV, "max-resource-size"),
    (NS_CALDAV, "min-date-time"),
    (NS_CALDAV, "max-date-time"),
    (NS_CALDAV, "max-instances"),
    (NS_CALDAV, "max-attendees-per-instance"),
    (NS_CALDAV, "schedule-calendar-transp"),
    (NS_CALENDARSERVER, "getctag"),
    (NS_CALENDARSERVER, "allowed-sharing-modes"),
    (NS_CALENDARSERVER, "invite"),
    (NS_CALENDARSERVER, "shared-url"),
    (NS_APPLE_ICAL, "calendar-color"),
    (NS_APPLE_ICAL, "calendar-order"),
];

const OBJECT_PROPS: Names = &[
    (NS_DAV, "resourcetype"),
    (NS_DAV, "getetag"),
    (NS_DAV, "getcontenttype"),
    (NS_DAV, "getcontentlength"),
    (NS_DAV, "getlastmodified"),
    (NS_DAV, "current-user-principal"),
    (NS_DAV, "current-user-privilege-set"),
    (NS_DAV, "supported-report-set"),
    (NS_DAV, "supportedlock"),
    (NS_DAV, "lockdiscovery"),
    (NS_CALDAV, "calendar-data"),
    (NS_CALDAV, "schedule-tag"),
];

const MEMBER_PROPS: Names = &[(NS_DAV, "getetag")];

const NOTIFICATION_PROPS: Names = &[
    (NS_DAV, "resourcetype"),
    (NS_DAV, "getetag"),
    (NS_DAV, "getcontenttype"),
    (NS_DAV, "getcontentlength"),
    (NS_DAV, "getlastmodified"),
    (NS_DAV, "creationdate"),
    (NS_DAV, "current-user-privilege-set"),
    (NS_DAV, "supported-report-set"),
    (NS_DAV, "supportedlock"),
    (NS_DAV, "lockdiscovery"),
    (NS_CALENDARSERVER, "notificationtype"),
];

const INBOX_ITEM_PROPS: Names = &[
    (NS_DAV, "resourcetype"),
    (NS_DAV, "getetag"),
    (NS_DAV, "getcontenttype"),
    (NS_DAV, "getcontentlength"),
    (NS_DAV, "getlastmodified"),
    (NS_DAV, "creationdate"),
    (NS_DAV, "current-user-privilege-set"),
    (NS_DAV, "supported-report-set"),
    (NS_DAV, "supportedlock"),
    (NS_DAV, "lockdiscovery"),
    (NS_CALDAV, "calendar-data"),
];

/// What a principal search discloses of the principals it finds: names and addresses.
const SEARCH_HIT_PROPS: Names = &[
    (NS_DAV, "resourcetype"),
    (NS_DAV, "displayname"),
    (NS_DAV, "principal-URL"),
    (NS_CALDAV, "calendar-user-address-set"),
    (NS_CALDAV, "calendar-user-type"),
    (NS_CALENDARSERVER, "email-address-set"),
];

/// Live properties that no subject lists but that the server owns: a client may not store them as dead
/// properties (they are answered 404 or are protected).
const OTHER_LIVE_PROPS: Names = &[
    (NS_DAV, "getcontentlanguage"),
    (NS_DAV, "acl"),
    (NS_DAV, "acl-restrictions"),
    (NS_DAV, "inherited-acl-set"),
    (NS_DAV, "quota-available-bytes"),
    (NS_DAV, "quota-used-bytes"),
    (NS_CALDAV, "schedule-default-calendar-URL"),
    (NS_CALDAV, "calendar-free-busy-set"),
];

fn is_listed(names: Names, name: &PropertyName) -> bool {
    names
        .iter()
        .any(|(namespace, local)| name.namespace == *namespace && name.local == *local)
}

/// Whether the server owns the property: clients cannot change it with PROPPATCH (except the six settable ones).
pub fn is_live(name: &PropertyName) -> bool {
    [
        ROOT_PROPS,
        PRINCIPAL_PROPS,
        COLLECTION_PROPS,
        OBJECT_PROPS,
        MEMBER_PROPS,
        NOTIFICATION_PROPS,
        INBOX_ITEM_PROPS,
        OTHER_LIVE_PROPS,
    ]
    .iter()
    .any(|names| is_listed(names, name))
}

/// Whether `DAV:allprop` includes the property: the live properties of RFC 4918 section 15.
pub fn is_allprop(name: &PropertyName) -> bool {
    name.namespace == NS_DAV
        && matches!(
            name.local.as_str(),
            "creationdate"
                | "displayname"
                | "getcontentlanguage"
                | "getcontentlength"
                | "getcontenttype"
                | "getetag"
                | "getlastmodified"
                | "lockdiscovery"
                | "resourcetype"
                | "supportedlock"
        )
}

fn candidates(subject: &Subject) -> Names {
    match subject {
        Subject::Root => ROOT_PROPS,
        Subject::Principal(_) => PRINCIPAL_PROPS,
        Subject::Collection(_) => COLLECTION_PROPS,
        Subject::Object(_) => OBJECT_PROPS,
        Subject::Member { .. } => MEMBER_PROPS,
        Subject::Notification(_) => NOTIFICATION_PROPS,
        Subject::InboxItem(_) => INBOX_ITEM_PROPS,
        Subject::SearchHit(_) => SEARCH_HIT_PROPS,
    }
}

/// The names of the properties the subject has, for `propname`, in catalog order and followed by the dead
/// properties of the collection.
pub fn property_names(env: &Env<'_>, subject: &Subject) -> Vec<PropertyName> {
    let mut names: Vec<PropertyName> = candidates(subject)
        .iter()
        .map(|(namespace, local)| PropertyName::new(namespace, local))
        .filter(|name| has_property(env, subject, name))
        .collect();
    if let Subject::Collection(collection) = subject {
        names.extend(collection.dead_properties.iter().map(|dead| dead.name.clone()));
    }
    names
}

/// Whether the subject has the property, for `propname`. An inbox item always has its message, even where the
/// listing it comes from carries none: naming the property reads nothing and renders nothing.
fn has_property(env: &Env<'_>, subject: &Subject, name: &PropertyName) -> bool {
    if matches!(subject, Subject::InboxItem(_)) && name.namespace == NS_CALDAV && name.local == "calendar-data" {
        return true;
    }
    render(env, subject, name).is_some()
}

/// The names `DAV:allprop` returns: the live properties of RFC 4918 the subject has, followed by its dead
/// properties. Only the candidates `allprop` includes are looked at, not the whole catalog.
pub fn allprop_names(env: &Env<'_>, subject: &Subject) -> Vec<PropertyName> {
    let mut names: Vec<PropertyName> = candidates(subject)
        .iter()
        .map(|(namespace, local)| PropertyName::new(namespace, local))
        .filter(|name| is_allprop(name) && render(env, subject, name).is_some())
        .collect();
    if let Subject::Collection(collection) = subject {
        names.extend(collection.dead_properties.iter().map(|dead| dead.name.clone()));
    }
    names
}

/// The inner XML of the property, or `None` when the subject does not have it.
pub fn render(env: &Env<'_>, subject: &Subject, name: &PropertyName) -> Option<String> {
    // A principal a search found tells what the search discloses and nothing else, whatever the request names.
    if matches!(subject, Subject::SearchHit(_)) && !is_listed(SEARCH_HIT_PROPS, name) {
        return None;
    }
    match name.namespace.as_str() {
        NS_DAV => dav_property(env, subject, &name.local),
        NS_CALDAV => caldav_property(env, subject, &name.local),
        NS_CALENDARSERVER => calendarserver_property(subject, &name.local),
        NS_APPLE_ICAL => apple_property(subject, &name.local),
        _ => None,
    }
    .or_else(|| dead_property(subject, name))
}

fn dead_property(subject: &Subject, name: &PropertyName) -> Option<String> {
    match subject {
        Subject::Collection(collection) => collection
            .dead_properties
            .iter()
            .find(|dead| &dead.name == name)
            .map(|dead| dead.value_xml.clone()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Small XML helpers
// ---------------------------------------------------------------------------------------------------------------

fn text_of(prefix: &str, local: &str, text: &str) -> String {
    format!("<{prefix}:{local}>{}</{prefix}:{local}>", escape_text(text))
}

fn href_of(path: &ResourcePath) -> String {
    text_of("D", "href", &path.format())
}

fn principal_path(tenant: &TenantSlug, principal: &PrincipalName) -> ResourcePath {
    ResourcePath::Principal {
        tenant: tenant.clone(),
        principal: principal.clone(),
    }
}

/// The `Last-Modified` and `getlastmodified` form of an instant: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn http_date(instant: DateTime<Utc>) -> String {
    instant.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// The `Content-Type` and `getcontenttype` of a calendar object.
pub fn object_content_type(component: ComponentKind) -> String {
    format!(
        "text/calendar; charset=utf-8; component={}",
        component.as_ical().to_ascii_lowercase()
    )
}

// ---------------------------------------------------------------------------------------------------------------
// DAV: properties
// ---------------------------------------------------------------------------------------------------------------

fn dav_property(env: &Env<'_>, subject: &Subject, local: &str) -> Option<String> {
    match local {
        "resourcetype" => Some(resource_type(subject)),
        "displayname" => display_name(subject),
        "getetag" => get_etag(subject),
        "getcontenttype" => match subject {
            Subject::Object(object) => Some(object_content_type(object.component)),
            Subject::Notification(_) => Some(escape_text(crate::notifications::CONTENT_TYPE)),
            Subject::InboxItem(_) => Some(escape_text(crate::scheduling::ITEM_CONTENT_TYPE)),
            _ => None,
        },
        "getcontentlength" => match subject {
            Subject::Object(object) => Some(object.size.to_string()),
            Subject::Notification(notification) => Some(notification.size.to_string()),
            Subject::InboxItem(item) => Some(item.size.to_string()),
            _ => None,
        },
        "getlastmodified" => get_last_modified(subject),
        "creationdate" => creation_date(subject),
        "current-user-principal" => env.current.map(|principal| href_of(&principal.path)),
        "principal-URL" => principal_url(env, subject),
        "principal-collection-set" => match subject {
            Subject::Root | Subject::Principal(_) => Some(href_of(&ResourcePath::Root)),
            Subject::Collection(collection) if matches!(collection.path, ResourcePath::Home { .. }) => {
                Some(href_of(&ResourcePath::Root))
            }
            _ => None,
        },
        "owner" => owner(subject),
        "current-user-privilege-set" => current_privileges(subject),
        "supported-privilege-set" => Some(SUPPORTED_PRIVILEGE_SET.to_owned()),
        "supported-report-set" => Some(supported_reports(subject)),
        "group-membership" | "group-member-set" | "alternate-URI-set" => group_property(subject, local),
        "sync-token" => sync_token(subject),
        "supportedlock" | "lockdiscovery" => Some(String::new()),
        _ => None,
    }
}

fn resource_type(subject: &Subject) -> String {
    match subject {
        Subject::Root => "<D:collection/>".to_owned(),
        Subject::Principal(_) | Subject::SearchHit(_) => "<D:collection/><D:principal/>".to_owned(),
        Subject::Object(_) | Subject::Member { .. } | Subject::Notification(_) | Subject::InboxItem(_) => String::new(),
        Subject::Collection(collection) => match collection.path {
            ResourcePath::Collection { .. } => {
                let mut out = String::from("<D:collection/><C:calendar/>");
                match collection.calendar.as_ref().map(|calendar| calendar.sharing) {
                    Some(SharingRole::Owner) => out.push_str("<CS:shared-owner/>"),
                    Some(SharingRole::Sharee) => out.push_str("<CS:shared/>"),
                    Some(SharingRole::Unshared) | None => {}
                }
                out
            }
            ResourcePath::Inbox { .. } => "<D:collection/><C:schedule-inbox/>".to_owned(),
            ResourcePath::Outbox { .. } => "<D:collection/><C:schedule-outbox/>".to_owned(),
            ResourcePath::Notifications { .. } => "<D:collection/><CS:notification/>".to_owned(),
            _ => "<D:collection/>".to_owned(),
        },
    }
}

fn display_name(subject: &Subject) -> Option<String> {
    match subject {
        Subject::Principal(principal) => Some(escape_text(&principal.display_name)),
        Subject::SearchHit(hit) => Some(escape_text(&hit.display_name)),
        Subject::Collection(collection) => Some(escape_text(&collection.display_name)),
        _ => None,
    }
}

fn get_etag(subject: &Subject) -> Option<String> {
    match subject {
        Subject::Object(object) => Some(escape_text(object.etag.as_str())),
        Subject::Member { etag, .. } => Some(escape_text(etag.as_str())),
        Subject::Notification(notification) => Some(escape_text(notification.etag.as_str())),
        Subject::InboxItem(item) => Some(escape_text(item.etag.as_str())),
        _ => None,
    }
}

fn get_last_modified(subject: &Subject) -> Option<String> {
    match subject {
        Subject::Object(object) => Some(http_date(object.last_modified)),
        Subject::Collection(collection) => collection
            .calendar
            .as_ref()
            .map(|calendar| http_date(calendar.updated_at)),
        Subject::Notification(notification) => Some(http_date(notification.updated_at)),
        Subject::InboxItem(item) => Some(http_date(item.created_at)),
        _ => None,
    }
}

fn creation_date(subject: &Subject) -> Option<String> {
    let format = |instant: DateTime<Utc>| instant.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    match subject {
        Subject::Collection(collection) => collection.calendar.as_ref().map(|calendar| format(calendar.created_at)),
        Subject::Notification(notification) => Some(format(notification.created_at)),
        Subject::InboxItem(item) => Some(format(item.created_at)),
        _ => None,
    }
}

fn principal_url(env: &Env<'_>, subject: &Subject) -> Option<String> {
    match subject {
        Subject::Principal(principal) => Some(href_of(&principal.path)),
        Subject::SearchHit(hit) => Some(href_of(&hit.path)),
        Subject::Root => env.current.map(|principal| href_of(&principal.path)),
        _ => None,
    }
}

fn owner(subject: &Subject) -> Option<String> {
    match subject {
        Subject::Principal(principal) => Some(href_of(&principal.path)),
        Subject::Collection(collection) => {
            let tenant = collection.path.tenant()?;
            let name = match &collection.calendar {
                Some(calendar) => &calendar.owner.name,
                None => collection.path.principal()?,
            };
            Some(href_of(&principal_path(tenant, name)))
        }
        _ => None,
    }
}

fn group_property(subject: &Subject, local: &str) -> Option<String> {
    let Subject::Principal(principal) = subject else {
        return None;
    };
    let hrefs = |paths: &[ResourcePath]| paths.iter().map(href_of).collect::<String>();
    match local {
        "group-membership" => Some(hrefs(&principal.group_membership)),
        "group-member-set" if principal.kind == PrincipalKind::Group => Some(hrefs(&principal.group_members)),
        "alternate-URI-set" => Some(String::new()),
        _ => None,
    }
}

fn sync_token(subject: &Subject) -> Option<String> {
    match subject {
        Subject::Collection(collection) => collection.sync_token.map(|token| escape_text(&token.to_string())),
        _ => None,
    }
}

/// The `D:privilege` elements of a set, followed by the aggregate `D:write` (RFC 3744 section 3.4) when the set has
/// what it stands for: `write-content` and `write-properties`, and for a collection also `bind` and `unbind`.
fn privilege_set(set: PrivilegeSet, collection: bool) -> String {
    let mut out = String::new();
    let mut push = |prefix: &str, local: &str| {
        let _ = write!(out, "<D:privilege><{prefix}:{local}/></D:privilege>");
    };
    for privilege in set.iter() {
        let (prefix, local) = privilege_element(privilege);
        push(prefix, local);
    }
    let content = set.contains(Privilege::WriteContent) && set.contains(Privilege::WriteProperties);
    let members = set.contains(Privilege::Bind) && set.contains(Privilege::Unbind);
    if content && (members || !collection) {
        push("D", "write");
    }
    out
}

fn current_privileges(subject: &Subject) -> Option<String> {
    match subject {
        Subject::Collection(collection) => Some(privilege_set(collection.privileges, true)),
        Subject::Object(object) => Some(privilege_set(object.privileges, false)),
        // The entry point is the root of the principal collection: it has the privileges of a principal.
        Subject::Root | Subject::Principal(_) => Some(privilege_set(
            privileges(Access::Owner, CalendarKind::Personal, ResourceKind::Principal),
            true,
        )),
        // What the application says the caller may do with the message: it decides, this layer only renders.
        Subject::Notification(notification) => Some(privilege_set(notification.privileges, false)),
        Subject::InboxItem(item) => Some(privilege_set(item.privileges, false)),
        Subject::Member { .. } | Subject::SearchHit(_) => None,
    }
}

/// The `DAV:supported-privilege-set` of every resource: every privilege `current-user-privilege-set` can report
/// (RFC 3744 asks for the current set to be a subset of the supported one), in their aggregation (`all` >
/// `read`, `write`, the sharing and scheduling privileges).
const SUPPORTED_PRIVILEGE_SET: &str = "<D:supported-privilege><D:privilege><D:all/></D:privilege><D:abstract/>\
<D:description xml:lang=\"en\">Any operation</D:description>\
<D:supported-privilege><D:privilege><D:read/></D:privilege><D:description xml:lang=\"en\">Read</D:description>\
<D:supported-privilege><D:privilege><D:read-current-user-privilege-set/></D:privilege><D:abstract/>\
<D:description xml:lang=\"en\">Read the privileges of the current user</D:description></D:supported-privilege>\
<D:supported-privilege><D:privilege><C:read-free-busy/></D:privilege>\
<D:description xml:lang=\"en\">Read free and busy time</D:description></D:supported-privilege>\
</D:supported-privilege>\
<D:supported-privilege><D:privilege><D:write/></D:privilege><D:description xml:lang=\"en\">Write</D:description>\
<D:supported-privilege><D:privilege><D:write-content/></D:privilege>\
<D:description xml:lang=\"en\">Write the content of resources</D:description></D:supported-privilege>\
<D:supported-privilege><D:privilege><D:write-properties/></D:privilege>\
<D:description xml:lang=\"en\">Write properties</D:description></D:supported-privilege>\
<D:supported-privilege><D:privilege><D:bind/></D:privilege>\
<D:description xml:lang=\"en\">Add members to a collection</D:description></D:supported-privilege>\
<D:supported-privilege><D:privilege><D:unbind/></D:privilege>\
<D:description xml:lang=\"en\">Remove members from a collection</D:description></D:supported-privilege>\
</D:supported-privilege>\
<D:supported-privilege><D:privilege><CS:share/></D:privilege>\
<D:description xml:lang=\"en\">Share a calendar</D:description></D:supported-privilege>\
<D:supported-privilege><D:privilege><C:schedule-send/></D:privilege>\
<D:description xml:lang=\"en\">Send scheduling messages from the outbox</D:description></D:supported-privilege>\
<D:supported-privilege><D:privilege><C:schedule-deliver/></D:privilege>\
<D:description xml:lang=\"en\">Deliver scheduling messages to the inbox</D:description></D:supported-privilege>\
</D:supported-privilege>";

/// The reports a resource supports, as the `(prefix, local name)` of their elements.
///
/// The entry point is the principal collection (`principal-collection-set` of every resource), which is where
/// clients send the principal searches; a principal answers them as well (the search covers the whole tenant either
/// way, see `docs/interop.md`) and `expand-property`; the scheduling inbox answers `calendar-multiget` for its
/// items.
pub fn supported_report_names(subject: &Subject) -> &'static [(&'static str, &'static str)] {
    match subject {
        Subject::Principal(_) => &[
            ("D", "expand-property"),
            ("D", "principal-property-search"),
            ("D", "principal-search-property-set"),
            ("CS", "calendarserver-principal-search"),
        ],
        Subject::Root => &[
            ("D", "principal-property-search"),
            ("D", "principal-search-property-set"),
            ("CS", "calendarserver-principal-search"),
        ],
        Subject::Collection(collection) => match collection.path {
            ResourcePath::Collection { .. } => &[
                ("D", "sync-collection"),
                ("C", "calendar-query"),
                ("C", "calendar-multiget"),
                ("C", "free-busy-query"),
            ],
            ResourcePath::Inbox { .. } => &[("D", "sync-collection"), ("C", "calendar-multiget")],
            ResourcePath::Notifications { .. } => &[("D", "sync-collection")],
            _ => &[],
        },
        Subject::Object(_)
        | Subject::Member { .. }
        | Subject::Notification(_)
        | Subject::InboxItem(_)
        | Subject::SearchHit(_) => &[],
    }
}

fn supported_reports(subject: &Subject) -> String {
    let mut out = String::new();
    for (prefix, local) in supported_report_names(subject) {
        let _ = write!(
            out,
            "<D:supported-report><D:report><{prefix}:{local}/></D:report></D:supported-report>"
        );
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------
// CalDAV properties
// ---------------------------------------------------------------------------------------------------------------

fn caldav_property(env: &Env<'_>, subject: &Subject, local: &str) -> Option<String> {
    match subject {
        Subject::Principal(principal) => principal_caldav(principal, local),
        Subject::Collection(collection) => collection_caldav(env, collection, local),
        Subject::Object(object) => match local {
            "calendar-data" => object.data.as_deref().map(escape_text),
            "schedule-tag" => object.schedule_tag.as_ref().map(|tag| escape_text(tag.as_str())),
            _ => None,
        },
        Subject::InboxItem(item) => match local {
            "calendar-data" => item.data.as_deref().map(escape_text),
            _ => None,
        },
        Subject::SearchHit(hit) => match local {
            "calendar-user-address-set" => Some(address_set(&hit.addresses)),
            "calendar-user-type" => Some(user_type(hit.kind).to_owned()),
            _ => None,
        },
        Subject::Root | Subject::Member { .. } | Subject::Notification(_) => None,
    }
}

/// The `D:href` elements of `calendar-user-address-set`.
fn address_set(addresses: &[CalendarUserAddress]) -> String {
    addresses
        .iter()
        .map(|address| text_of("D", "href", address.as_str()))
        .collect()
}

/// The `CS:email-address` elements of `CS:email-address-set`: the `mailto:` addresses without their scheme.
fn email_address_set(addresses: &[CalendarUserAddress]) -> String {
    addresses
        .iter()
        .filter_map(CalendarUserAddress::email)
        .map(|email| text_of("CS", "email-address", email.as_str()))
        .collect()
}

/// The `CALDAV:calendar-user-type` of a principal (RFC 6638 section 9.2).
const fn user_type(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::User | PrincipalKind::Service => "INDIVIDUAL",
        PrincipalKind::Group => "GROUP",
        PrincipalKind::Resource => "RESOURCE",
    }
}

fn principal_caldav(principal: &PrincipalProps, local: &str) -> Option<String> {
    match local {
        "calendar-home-set" => Some(href_of(&principal.home)),
        "schedule-inbox-URL" => Some(href_of(&principal.inbox)),
        "schedule-outbox-URL" => Some(href_of(&principal.outbox)),
        "calendar-user-address-set" => Some(address_set(&principal.addresses)),
        "calendar-user-type" => Some(user_type(principal.kind).to_owned()),
        _ => None,
    }
}

fn collection_caldav(env: &Env<'_>, collection: &CollectionView, local: &str) -> Option<String> {
    let calendar = collection.calendar.as_ref()?;
    let limits = &env.services.limits.ical;
    match local {
        "calendar-description" => calendar.description.as_deref().map(escape_text),
        "calendar-timezone" => calendar.timezone_ics.as_deref().map(escape_text),
        "supported-calendar-component-set" => {
            let mut out = String::new();
            for component in &calendar.components {
                let _ = write!(out, "<C:comp name=\"{}\"/>", component.as_ical());
            }
            Some(out)
        }
        "supported-calendar-data" => {
            Some("<C:calendar-data content-type=\"text/calendar\" version=\"2.0\"/>".to_owned())
        }
        "supported-collation-set" => Some(
            ["i;ascii-casemap", "i;octet", "i;unicode-casemap"]
                .iter()
                .map(|collation| text_of("C", "supported-collation", collation))
                .collect(),
        ),
        "max-resource-size" => Some(limits.max_resource_size.to_string()),
        "min-date-time" => limits.min_date_time().map(format_utc),
        "max-date-time" => limits.max_date_time().map(format_utc),
        "max-instances" => Some(limits.max_instances.to_string()),
        "max-attendees-per-instance" => Some(limits.max_attendees_per_instance.to_string()),
        "schedule-calendar-transp" => Some(
            match calendar.schedule_transp {
                Transparency::Opaque => "<C:opaque/>",
                Transparency::Transparent => "<C:transparent/>",
            }
            .to_owned(),
        ),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// CalendarServer and Apple properties
// ---------------------------------------------------------------------------------------------------------------

fn calendarserver_property(subject: &Subject, local: &str) -> Option<String> {
    match subject {
        Subject::Principal(principal) => match local {
            "notification-URL" => Some(href_of(&principal.notifications)),
            "email-address-set" => Some(email_address_set(&principal.addresses)),
            "calendar-proxy-read-for" | "calendar-proxy-write-for" => Some(String::new()),
            _ => None,
        },
        Subject::SearchHit(hit) => match local {
            "email-address-set" => Some(email_address_set(&hit.addresses)),
            _ => None,
        },
        Subject::Notification(notification) => match local {
            "notificationtype" => Some(notification_type(notification.kind).to_owned()),
            _ => None,
        },
        Subject::Collection(collection) => match local {
            "getctag" => sync_token(subject),
            "allowed-sharing-modes" => collection.calendar.as_ref().map(|_| allowed_sharing_modes(collection)),
            "invite" => collection
                .calendar
                .as_ref()
                .map(|calendar| invite(collection, calendar)),
            "shared-url" => collection
                .calendar
                .as_ref()
                .and_then(|calendar| calendar.shared_url.as_ref())
                .map(href_of),
            _ => None,
        },
        Subject::Root | Subject::Object(_) | Subject::Member { .. } | Subject::InboxItem(_) => None,
    }
}

/// The value of `CS:notificationtype`: what the notification is, as the element a client dispatches on. Both kinds
/// concern a calendar (`shared-type="calendar"`; address books are not part of Davhaven).
const fn notification_type(kind: NotificationKind) -> &'static str {
    match kind {
        NotificationKind::Invite => "<CS:invite-notification shared-type=\"calendar\"/>",
        NotificationKind::InviteReply => "<CS:invite-reply shared-type=\"calendar\"/>",
    }
}

/// `CS:allowed-sharing-modes`: `can-be-shared` when the viewer holds the `CS:share` privilege on the collection. Who
/// may share which calendar (owners and admins of calendars that are not managed or mirrored, where sharing is
/// enabled) is the application's decision (PLAN 2.6); it says so in the privileges and this module shows it.
fn allowed_sharing_modes(collection: &CollectionView) -> String {
    if collection.privileges.contains(Privilege::Share) {
        "<CS:can-be-shared/>".to_owned()
    } else {
        String::new()
    }
}

fn invite(collection: &CollectionView, calendar: &BindingView) -> String {
    let mut out = String::new();
    if collection.invites.is_empty() {
        return out;
    }
    if let Some(tenant) = collection.path.tenant() {
        out.push_str("<CS:organizer>");
        out.push_str(&href_of(&principal_path(tenant, &calendar.owner.name)));
        out.push_str(&text_of("CS", "common-name", &calendar.owner.display_name));
        out.push_str("</CS:organizer>");
    }
    for invite in &collection.invites {
        out.push_str("<CS:user>");
        out.push_str(&text_of("D", "href", invite.address.as_str()));
        if let Some(name) = &invite.common_name {
            out.push_str(&text_of("CS", "common-name", name));
        }
        out.push_str(match invite.status {
            GrantStatus::Pending => "<CS:invite-noresponse/>",
            GrantStatus::Accepted => "<CS:invite-accepted/>",
            GrantStatus::Declined => "<CS:invite-declined/>",
        });
        out.push_str(match invite.access {
            GrantAccess::Read => "<CS:access><CS:read/></CS:access>",
            GrantAccess::ReadWrite | GrantAccess::Admin => "<CS:access><CS:read-write/></CS:access>",
        });
        if let Some(summary) = &invite.summary {
            out.push_str(&text_of("CS", "summary", summary));
        }
        out.push_str("</CS:user>");
    }
    out
}

fn apple_property(subject: &Subject, local: &str) -> Option<String> {
    let Subject::Collection(collection) = subject else {
        return None;
    };
    let calendar = collection.calendar.as_ref()?;
    match local {
        "calendar-color" => calendar.color.as_deref().map(escape_text),
        "calendar-order" => Some(calendar.sort_order.to_string()),
        _ => None,
    }
}

/// The principals a property of a principal points to, for `expand-property`: the groups of
/// `group-membership`, the members of `group-member-set`, and the proxy relations of CalendarServer, which are
/// always empty (delegation is not part of 1.0). `None` for every property that is no list of principals.
pub fn linked_principals(subject: &Subject, name: &PropertyName) -> Option<Vec<ResourcePath>> {
    let Subject::Principal(principal) = subject else {
        return None;
    };
    match (name.namespace.as_str(), name.local.as_str()) {
        (NS_DAV, "group-membership") => Some(principal.group_membership.clone()),
        (NS_DAV, "group-member-set") if principal.kind == PrincipalKind::Group => Some(principal.group_members.clone()),
        (NS_CALENDARSERVER, "calendar-proxy-read-for" | "calendar-proxy-write-for") => Some(Vec::new()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Property statuses of one resource
// ---------------------------------------------------------------------------------------------------------------

/// Whether the request needs the principal the request is authenticated as, before the resources are collected.
///
/// That is the case when it names `current-user-principal`, or `principal-URL` of the entry point (the principal
/// URL of a principal comes from the principal itself), and for `propname`, which lists the properties the
/// resources have, `current-user-principal` among them. `allprop` does not include `current-user-principal`.
pub fn needs_current_principal(request: &PropRequest, resource: &ResourcePath) -> bool {
    if matches!(request, PropRequest::PropName) {
        return true;
    }
    request.names().iter().any(|name| {
        name.namespace == NS_DAV
            && match name.local.as_str() {
                "current-user-principal" => true,
                "principal-URL" => matches!(resource, ResourcePath::Root),
                _ => false,
            }
    })
}

/// What a listing of a calendar home must read besides the bindings: the dead properties and the invitations of the
/// calendars, when the request can ask for them, and always the scheduling and notification collections.
pub fn home_detail(request: &PropRequest) -> HomeDetail {
    let (dead_properties, invites) = match request {
        PropRequest::Prop(list) => (
            list.names.iter().any(|name| !is_live(name)),
            list.names
                .iter()
                .any(|name| name.namespace == NS_CALENDARSERVER && name.local == "invite"),
        ),
        PropRequest::AllProp(_) | PropRequest::PropName => (true, true),
    };
    HomeDetail {
        dead_properties,
        invites,
        special: true,
    }
}

/// One property as an element: `<D:name>inner</D:name>`, or an empty element without a value.
pub fn property_element(prefixes: &Prefixes, name: &PropertyName, inner: Option<&str>) -> String {
    let mut writer = XmlWriter::with_prefixes(prefixes);
    match inner {
        Some(inner) if !inner.is_empty() => {
            writer.start(&name.namespace, &name.local);
            writer.raw(inner);
            writer.end(&name.namespace, &name.local);
        }
        _ => {
            writer.empty(&name.namespace, &name.local);
        }
    }
    writer.into_string()
}

/// The `propstat` elements of one resource for a request: the properties found (200) and, unless `minimal`, the
/// ones the resource does not have (404). A resource without any property to report still gets an empty 200
/// `propstat`, because a `response` needs one.
pub fn propstats(env: &Env<'_>, subject: &Subject, request: &PropRequest, minimal: bool) -> Vec<Propstat> {
    let mut found = String::new();
    let mut missing = String::new();
    if matches!(request, PropRequest::PropName) {
        for name in property_names(env, subject) {
            found.push_str(&property_element(env.prefixes, &name, None));
        }
    } else {
        let mut names = Vec::new();
        match request {
            PropRequest::AllProp(include) => {
                names = allprop_names(env, subject);
                // The included properties are distinct (the request reader drops repeats); only those that
                // `allprop` lists anyway are not added twice.
                let listed = names.len();
                for name in &include.names {
                    if !names.iter().take(listed).any(|known| known == name) {
                        names.push(name.clone());
                    }
                }
            }
            PropRequest::Prop(list) => names.extend(list.names.iter().cloned()),
            PropRequest::PropName => {}
        }
        for name in names {
            match render(env, subject, &name) {
                Some(inner) => found.push_str(&property_element(env.prefixes, &name, Some(&inner))),
                None => missing.push_str(&property_element(env.prefixes, &name, None)),
            }
        }
    }
    let mut propstats = Vec::new();
    if !found.is_empty() || missing.is_empty() || minimal {
        propstats.push(Propstat::found(found));
    }
    if !missing.is_empty() && !minimal {
        propstats.push(Propstat {
            status: 404,
            props: missing,
            error: None,
        });
    }
    propstats
}

// ---------------------------------------------------------------------------------------------------------------
// PROPPATCH and MKCALENDAR values
// ---------------------------------------------------------------------------------------------------------------

/// What one instruction of a PROPPATCH or MKCALENDAR comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Interpreted {
    /// A change the application applies.
    Change(PropertyChange),
    /// `supported-calendar-component-set`: settable only when the collection is created.
    Components(Vec<ComponentKind>),
    /// `resourcetype` of an extended MKCOL: the names of its children.
    ResourceType(Vec<PropertyName>),
    /// A live property that clients cannot change (403 `cannot-modify-protected-property`).
    Protected,
    /// The value is not acceptable for the property (409).
    Invalid,
    /// A value larger than the server stores: a text property or a dead property over `max_dead_property_size`, a
    /// time zone over `max_resource_size`, a dead property beyond `max_dead_properties` (403).
    TooLarge,
}

fn transparency(element: &Element) -> Interpreted {
    if element.child(NS_CALDAV, "opaque").is_some() {
        Interpreted::Change(PropertyChange::ScheduleTransparency(Some(Transparency::Opaque)))
    } else if element.child(NS_CALDAV, "transparent").is_some() {
        Interpreted::Change(PropertyChange::ScheduleTransparency(Some(Transparency::Transparent)))
    } else {
        Interpreted::Invalid
    }
}

fn components(element: &Element) -> Interpreted {
    let mut kinds = Vec::new();
    for comp in element.children_named(NS_CALDAV, "comp") {
        let Some(kind) = comp
            .attribute("name")
            .and_then(|name| ComponentKind::from_ical(name.trim()))
        else {
            return Interpreted::Invalid;
        };
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    if kinds.is_empty() {
        Interpreted::Invalid
    } else {
        Interpreted::Components(kinds)
    }
}

/// Reads the value of a `DAV:set` of a property.
///
/// The text of `displayname`, `calendar-description` and `calendar-color` and the size of a dead property may not
/// be longer than `max_dead_property_size`, a `calendar-timezone` not longer than `max_resource_size` (it is a
/// small iCalendar object the application validates): without caps one request could store megabytes in a
/// property that every listing of the home then repeats.
pub fn interpret_set(name: &PropertyName, element: &Element, limits: &Limits) -> Interpreted {
    let text = element.text();
    let text_cap = usize::try_from(limits.dav.max_dead_property_size).unwrap_or(usize::MAX);
    let timezone_cap = usize::try_from(limits.ical.max_resource_size).unwrap_or(usize::MAX);
    match (name.namespace.as_str(), name.local.as_str()) {
        (NS_DAV, "displayname") | (NS_CALDAV, "calendar-description") | (NS_APPLE_ICAL, "calendar-color")
            if text.len() > text_cap =>
        {
            Interpreted::TooLarge
        }
        (NS_CALDAV, "calendar-timezone") if text.len() > timezone_cap => Interpreted::TooLarge,
        (NS_DAV, "displayname") => Interpreted::Change(PropertyChange::DisplayName(Some(text))),
        (NS_CALDAV, "calendar-description") => Interpreted::Change(PropertyChange::Description(Some(text))),
        (NS_CALDAV, "calendar-timezone") => Interpreted::Change(PropertyChange::Timezone(Some(text))),
        (NS_APPLE_ICAL, "calendar-color") => Interpreted::Change(PropertyChange::Color(Some(text.trim().to_owned()))),
        (NS_APPLE_ICAL, "calendar-order") => text.trim().parse::<i32>().map_or(Interpreted::Invalid, |order| {
            Interpreted::Change(PropertyChange::Order(Some(order)))
        }),
        (NS_CALDAV, "schedule-calendar-transp") => transparency(element),
        (NS_CALDAV, "supported-calendar-component-set") => components(element),
        (NS_DAV, "resourcetype") => Interpreted::ResourceType(
            element
                .elements()
                .map(|child| PropertyName::new(&child.namespace, &child.local))
                .collect(),
        ),
        _ if is_live(name) => Interpreted::Protected,
        _ => serialize_content_within(element, text_cap).map_or(Interpreted::TooLarge, |value| {
            Interpreted::Change(PropertyChange::Dead {
                name: name.clone(),
                value_xml: Some(value),
            })
        }),
    }
}

/// Refuses the dead properties a request sets beyond `max` (PLAN 2.15: 403): the `max + 1`th and every later one
/// becomes [`Interpreted::TooLarge`]. The application enforces the limit for the properties a binding already has.
pub fn limit_dead_properties(interpreted: &mut [Interpreted], max: u32) {
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    let mut count = 0usize;
    for instruction in interpreted {
        if matches!(
            instruction,
            Interpreted::Change(PropertyChange::Dead { value_xml: Some(_), .. })
        ) {
            count += 1;
            if count > max {
                *instruction = Interpreted::TooLarge;
            }
        }
    }
}

/// Reads a `DAV:remove` of a property.
pub fn interpret_remove(name: &PropertyName) -> Interpreted {
    match (name.namespace.as_str(), name.local.as_str()) {
        (NS_DAV, "displayname") => Interpreted::Change(PropertyChange::DisplayName(None)),
        (NS_CALDAV, "calendar-description") => Interpreted::Change(PropertyChange::Description(None)),
        (NS_CALDAV, "calendar-timezone") => Interpreted::Change(PropertyChange::Timezone(None)),
        (NS_APPLE_ICAL, "calendar-color") => Interpreted::Change(PropertyChange::Color(None)),
        (NS_APPLE_ICAL, "calendar-order") => Interpreted::Change(PropertyChange::Order(None)),
        (NS_CALDAV, "schedule-calendar-transp") => Interpreted::Change(PropertyChange::ScheduleTransparency(None)),
        _ if is_live(name) => Interpreted::Protected,
        _ => Interpreted::Change(PropertyChange::Dead {
            name: name.clone(),
            value_xml: None,
        }),
    }
}

/// Reads one instruction of a PROPPATCH.
pub fn interpret(update: &Update, limits: &Limits) -> Interpreted {
    match update {
        Update::Set(name, element) => interpret_set(name, element, limits),
        Update::Remove(name) => interpret_remove(name),
    }
}

#[cfg(test)]
mod tests;
