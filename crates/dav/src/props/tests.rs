//! Tests of the property catalog: what every kind of resource lists and how each property is written, the
//! statuses of a request, and the reading of PROPPATCH values.

use chrono::TimeZone;
use davhaven_app::AppServices;
use davhaven_app::services::{DeadProperty, InviteView, PrincipalSummary};
use davhaven_app_fake::AppServicesExt as _;
use davhaven_domain::{
    BindingId, CalendarId, CalendarUserAddress, InboxItemId, NotificationId, ObjectId, PrincipalId, ScheduleTag,
    SyncToken, Uid,
};
use uuid::Uuid;

use super::*;
use crate::xml::parse;
use crate::xml::requests::PropList;

fn name(text: &str) -> PrincipalName {
    PrincipalName::parse(text).unwrap()
}

fn prop(namespace: &str, local: &str) -> PropertyName {
    PropertyName::new(namespace, local)
}

fn instant(day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, day, 10, 15, 30).unwrap()
}

fn path(text: &str) -> ResourcePath {
    ResourcePath::parse(text).unwrap()
}

fn principal() -> PrincipalProps {
    PrincipalProps {
        path: path("/dav/principals/acme/anna/"),
        id: PrincipalId::from_uuid(Uuid::from_u128(1)),
        name: name("anna"),
        display_name: "Anna <Acme>".to_owned(),
        kind: PrincipalKind::User,
        addresses: vec![
            CalendarUserAddress::parse("mailto:anna@acme.example").unwrap(),
            CalendarUserAddress::parse("/dav/principals/acme/anna/").unwrap(),
            CalendarUserAddress::parse("urn:uuid:00000000-0000-0000-0000-000000000001").unwrap(),
        ],
        home: path("/dav/calendars/acme/anna/"),
        inbox: path("/dav/calendars/acme/anna/inbox/"),
        outbox: path("/dav/calendars/acme/anna/outbox/"),
        notifications: path("/dav/calendars/acme/anna/notifications/"),
        group_members: vec![path("/dav/principals/acme/ben/")],
        group_membership: vec![path("/dav/principals/acme/team/")],
    }
}

fn binding(sharing: SharingRole, access: Access, kind: CalendarKind) -> BindingView {
    BindingView {
        binding_id: BindingId::from_uuid(Uuid::from_u128(2)),
        calendar_id: CalendarId::from_uuid(Uuid::from_u128(3)),
        path: path("/dav/calendars/acme/anna/work/"),
        owner: PrincipalSummary {
            id: PrincipalId::from_uuid(Uuid::from_u128(1)),
            name: name("anna"),
            display_name: "Anna".to_owned(),
            kind: PrincipalKind::User,
        },
        kind,
        display_name: "Work & Play".to_owned(),
        description: Some("All the work".to_owned()),
        color: Some("#FF2D55FF".to_owned()),
        sort_order: 7,
        components: vec![ComponentKind::Event, ComponentKind::Todo],
        timezone_ics: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned()),
        schedule_transp: Transparency::Transparent,
        access,
        privileges: privileges(access, kind, ResourceKind::Collection),
        sharing,
        shared_url: (sharing == SharingRole::Sharee).then(|| path("/dav/calendars/acme/ben/work/")),
        sync_token: SyncToken::new(Uuid::from_u128(3), Uuid::from_u128(4), 9),
        created_at: instant(1),
        updated_at: instant(2),
    }
}

fn calendar() -> CollectionView {
    let binding = binding(SharingRole::Unshared, Access::Owner, CalendarKind::User);
    CollectionView {
        path: binding.path.clone(),
        display_name: binding.display_name.clone(),
        privileges: binding.privileges,
        sync_token: Some(binding.sync_token),
        calendar: Some(binding),
        dead_properties: vec![DeadProperty {
            name: prop("urn:example:x", "note"),
            value_xml: "<inner xmlns=\"urn:example:x\">v</inner>".to_owned(),
        }],
        invites: Vec::new(),
    }
}

fn special(path_text: &str, token: bool) -> CollectionView {
    CollectionView {
        path: path(path_text),
        display_name: "Anna Inbox".to_owned(),
        privileges: PrivilegeSet::of(&[Privilege::Read, Privilege::Unbind]),
        sync_token: token.then(|| SyncToken::new(Uuid::from_u128(1), Uuid::from_u128(4), 0)),
        calendar: None,
        dead_properties: Vec::new(),
        invites: Vec::new(),
    }
}

fn object() -> ObjectView {
    ObjectView {
        path: path("/dav/calendars/acme/anna/work/a%26b.ics"),
        id: ObjectId::from_uuid(Uuid::from_u128(5)),
        calendar_id: CalendarId::from_uuid(Uuid::from_u128(3)),
        uid: Uid::parse("a-1@acme.example").unwrap(),
        component: ComponentKind::Todo,
        etag: ETag::from_bytes(b"x"),
        schedule_tag: Some(ScheduleTag::parse("\"tag-1\"").unwrap()),
        size: 321,
        last_modified: instant(3),
        data: Some("BEGIN:VCALENDAR\r\nSUMMARY:R&D\r\nEND:VCALENDAR\r\n".to_owned()),
        privileges: PrivilegeSet::of(&[Privilege::Read]),
    }
}

fn render_in(services: &AppServices, subject: &Subject, namespace: &str, local: &str) -> Option<String> {
    let current = principal();
    let env = Env {
        services,
        current: Some(&current),
        prefixes: &Prefixes::default(),
    };
    render(&env, subject, &prop(namespace, local))
}

fn value(subject: &Subject, namespace: &str, local: &str) -> Option<String> {
    render_in(&AppServices::fake(), subject, namespace, local)
}

fn names_of(subject: &Subject) -> Vec<String> {
    let services = AppServices::fake();
    let current = principal();
    let env = Env {
        services: &services,
        current: Some(&current),
        prefixes: &Prefixes::default(),
    };
    property_names(&env, subject)
        .into_iter()
        .map(|name| format!("{}{}", prefix(&name.namespace), name.local))
        .collect()
}

fn prefix(namespace: &str) -> &'static str {
    match namespace {
        NS_DAV => "D:",
        NS_CALDAV => "C:",
        NS_CALENDARSERVER => "CS:",
        NS_APPLE_ICAL => "ICAL:",
        _ => "?:",
    }
}

#[test]
fn the_entry_point_names_the_current_user() {
    let root = Subject::Root;
    assert_eq!(
        names_of(&root),
        [
            "D:resourcetype",
            "D:current-user-principal",
            "D:principal-collection-set",
            "D:current-user-privilege-set",
            "D:supported-report-set",
            "D:supportedlock",
            "D:lockdiscovery"
        ]
    );
    assert_eq!(value(&root, NS_DAV, "resourcetype").unwrap(), "<D:collection/>");
    assert_eq!(
        value(&root, NS_DAV, "current-user-principal").unwrap(),
        "<D:href>/dav/principals/acme/anna/</D:href>"
    );
    assert_eq!(
        value(&root, NS_DAV, "principal-collection-set").unwrap(),
        "<D:href>/dav/</D:href>"
    );
    assert_eq!(
        value(&root, NS_DAV, "supported-report-set").unwrap(),
        "<D:supported-report><D:report><D:principal-property-search/></D:report></D:supported-report>\
         <D:supported-report><D:report><D:principal-search-property-set/></D:report></D:supported-report>\
         <D:supported-report><D:report><CS:calendarserver-principal-search/></D:report></D:supported-report>",
        "the entry point is the principal collection: it is where clients send their searches"
    );
    let services = AppServices::fake();
    let anonymous = Env {
        services: &services,
        current: None,
        prefixes: &Prefixes::default(),
    };
    assert_eq!(render(&anonymous, &root, &prop(NS_DAV, "current-user-principal")), None);
}

#[test]
fn a_principal_describes_itself_and_where_its_calendars_are() {
    let subject = Subject::Principal(principal());
    let read = |namespace: &str, local: &str| value(&subject, namespace, local).unwrap();
    assert_eq!(read(NS_DAV, "resourcetype"), "<D:collection/><D:principal/>");
    assert_eq!(read(NS_DAV, "displayname"), "Anna &lt;Acme&gt;");
    assert_eq!(
        read(NS_DAV, "principal-URL"),
        "<D:href>/dav/principals/acme/anna/</D:href>"
    );
    assert_eq!(read(NS_DAV, "owner"), "<D:href>/dav/principals/acme/anna/</D:href>");
    assert_eq!(
        read(NS_CALDAV, "calendar-home-set"),
        "<D:href>/dav/calendars/acme/anna/</D:href>"
    );
    assert_eq!(
        read(NS_CALDAV, "schedule-inbox-URL"),
        "<D:href>/dav/calendars/acme/anna/inbox/</D:href>"
    );
    assert_eq!(
        read(NS_CALDAV, "schedule-outbox-URL"),
        "<D:href>/dav/calendars/acme/anna/outbox/</D:href>"
    );
    assert_eq!(
        read(NS_CALENDARSERVER, "notification-URL"),
        "<D:href>/dav/calendars/acme/anna/notifications/</D:href>"
    );
    assert_eq!(
        read(NS_CALDAV, "calendar-user-address-set"),
        "<D:href>mailto:anna@acme.example</D:href><D:href>/dav/principals/acme/anna/</D:href>\
         <D:href>urn:uuid:00000000-0000-0000-0000-000000000001</D:href>"
    );
    assert_eq!(
        read(NS_CALENDARSERVER, "email-address-set"),
        "<CS:email-address>anna@acme.example</CS:email-address>"
    );
    assert_eq!(read(NS_CALDAV, "calendar-user-type"), "INDIVIDUAL");
    assert_eq!(
        read(NS_DAV, "group-membership"),
        "<D:href>/dav/principals/acme/team/</D:href>"
    );
    assert_eq!(read(NS_DAV, "alternate-URI-set"), "");
    assert_eq!(
        read(NS_CALENDARSERVER, "calendar-proxy-read-for"),
        "",
        "proxy properties are empty"
    );
    assert_eq!(read(NS_CALENDARSERVER, "calendar-proxy-write-for"), "");
    assert_eq!(
        read(NS_DAV, "supported-report-set"),
        "<D:supported-report><D:report><D:expand-property/></D:report></D:supported-report>\
         <D:supported-report><D:report><D:principal-property-search/></D:report></D:supported-report>\
         <D:supported-report><D:report><D:principal-search-property-set/></D:report></D:supported-report>\
         <D:supported-report><D:report><CS:calendarserver-principal-search/></D:report></D:supported-report>"
    );
    assert_eq!(
        value(&subject, NS_DAV, "group-member-set"),
        None,
        "only groups have members"
    );
}

#[test]
fn principals_of_other_kinds_have_their_calendar_user_type() {
    for (kind, expected) in [
        (PrincipalKind::Group, "GROUP"),
        (PrincipalKind::Resource, "RESOURCE"),
        (PrincipalKind::Service, "INDIVIDUAL"),
    ] {
        let mut props = principal();
        props.kind = kind;
        let subject = Subject::Principal(props);
        assert_eq!(value(&subject, NS_CALDAV, "calendar-user-type").unwrap(), expected);
        let members = value(&subject, NS_DAV, "group-member-set");
        assert_eq!(members.is_some(), kind == PrincipalKind::Group);
    }
}

#[test]
fn a_calendar_collection_has_the_properties_of_rfc_4791() {
    let subject = Subject::Collection(calendar());
    let read = |namespace: &str, local: &str| value(&subject, namespace, local).unwrap();
    assert_eq!(read(NS_DAV, "resourcetype"), "<D:collection/><C:calendar/>");
    assert_eq!(read(NS_DAV, "displayname"), "Work &amp; Play");
    assert_eq!(read(NS_DAV, "owner"), "<D:href>/dav/principals/acme/anna/</D:href>");
    assert_eq!(read(NS_CALDAV, "calendar-description"), "All the work");
    assert_eq!(
        read(NS_CALDAV, "calendar-timezone"),
        "BEGIN:VCALENDAR&#13;\nEND:VCALENDAR&#13;\n"
    );
    assert_eq!(
        read(NS_CALDAV, "supported-calendar-component-set"),
        "<C:comp name=\"VEVENT\"/><C:comp name=\"VTODO\"/>"
    );
    assert_eq!(
        read(NS_CALDAV, "supported-calendar-data"),
        "<C:calendar-data content-type=\"text/calendar\" version=\"2.0\"/>"
    );
    assert_eq!(read(NS_CALDAV, "max-resource-size"), "1048576");
    assert_eq!(read(NS_CALDAV, "min-date-time"), "19000101T000000Z");
    assert_eq!(read(NS_CALDAV, "max-date-time"), "21000101T000000Z");
    assert_eq!(read(NS_CALDAV, "max-instances"), "3000");
    assert_eq!(read(NS_CALDAV, "max-attendees-per-instance"), "200");
    assert_eq!(read(NS_CALDAV, "schedule-calendar-transp"), "<C:transparent/>");
    assert!(
        read(NS_CALDAV, "supported-collation-set").contains("<C:supported-collation>i;octet</C:supported-collation>")
    );
    assert_eq!(read(NS_APPLE_ICAL, "calendar-color"), "#FF2D55FF");
    assert_eq!(read(NS_APPLE_ICAL, "calendar-order"), "7");
    let token = "urn:davhaven:sync:00000000-0000-0000-0000-000000000003:00000000-0000-0000-0000-000000000004:9";
    assert_eq!(read(NS_DAV, "sync-token"), token);
    assert_eq!(
        read(NS_CALENDARSERVER, "getctag"),
        token,
        "the ctag is the sync token (PLAN 2.7)"
    );
    assert_eq!(read(NS_DAV, "getlastmodified"), "Mon, 02 Mar 2026 10:15:30 GMT");
    assert_eq!(read(NS_DAV, "creationdate"), "2026-03-01T10:15:30Z");
    assert_eq!(read(NS_CALENDARSERVER, "allowed-sharing-modes"), "<CS:can-be-shared/>");
    assert_eq!(read(NS_CALENDARSERVER, "invite"), "");
    assert_eq!(value(&subject, NS_CALENDARSERVER, "shared-url"), None);
    assert_eq!(
        read(NS_DAV, "supported-report-set"),
        "<D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report>\
         <D:supported-report><D:report><C:calendar-query/></D:report></D:supported-report>\
         <D:supported-report><D:report><C:calendar-multiget/></D:report></D:supported-report>\
         <D:supported-report><D:report><C:free-busy-query/></D:report></D:supported-report>"
    );
}

#[test]
fn absent_values_are_absent_properties() {
    let mut view = calendar();
    if let Some(calendar) = view.calendar.as_mut() {
        calendar.description = None;
        calendar.color = None;
        calendar.timezone_ics = None;
    }
    let subject = Subject::Collection(view);
    for local in ["calendar-description", "calendar-timezone"] {
        assert_eq!(value(&subject, NS_CALDAV, local), None, "{local}");
    }
    assert_eq!(value(&subject, NS_APPLE_ICAL, "calendar-color"), None);
    let names = names_of(&subject);
    assert!(!names.contains(&"ICAL:calendar-color".to_owned()), "{names:?}");
    assert!(names.contains(&"ICAL:calendar-order".to_owned()));
}

#[test]
fn sharing_shows_in_the_resource_type_and_the_sharing_properties() {
    let mut owner = calendar();
    let mut sharee = calendar();
    if let Some(calendar) = owner.calendar.as_mut() {
        calendar.sharing = SharingRole::Owner;
    }
    owner.invites = vec![
        InviteView {
            address: CalendarUserAddress::parse("mailto:ben@acme.example").unwrap(),
            common_name: Some("Ben".to_owned()),
            access: GrantAccess::ReadWrite,
            status: GrantStatus::Accepted,
            summary: Some("Join <us>".to_owned()),
        },
        InviteView {
            address: CalendarUserAddress::parse("mailto:cara@acme.example").unwrap(),
            common_name: None,
            access: GrantAccess::Read,
            status: GrantStatus::Pending,
            summary: None,
        },
        InviteView {
            address: CalendarUserAddress::parse("mailto:dora@acme.example").unwrap(),
            common_name: None,
            access: GrantAccess::Admin,
            status: GrantStatus::Declined,
            summary: None,
        },
    ];
    if let Some(calendar) = sharee.calendar.as_mut() {
        calendar.sharing = SharingRole::Sharee;
        calendar.access = Access::ReadWrite;
        calendar.shared_url = Some(path("/dav/calendars/acme/ben/work/"));
        calendar.privileges = privileges(Access::ReadWrite, CalendarKind::User, ResourceKind::Collection);
    }
    sharee.privileges = privileges(Access::ReadWrite, CalendarKind::User, ResourceKind::Collection);
    let owner = Subject::Collection(owner);
    let sharee = Subject::Collection(sharee);
    assert_eq!(
        value(&owner, NS_DAV, "resourcetype").unwrap(),
        "<D:collection/><C:calendar/><CS:shared-owner/>"
    );
    assert_eq!(
        value(&sharee, NS_DAV, "resourcetype").unwrap(),
        "<D:collection/><C:calendar/><CS:shared/>"
    );
    assert_eq!(
        value(&sharee, NS_CALENDARSERVER, "shared-url").unwrap(),
        "<D:href>/dav/calendars/acme/ben/work/</D:href>"
    );
    assert_eq!(
        value(&sharee, NS_CALENDARSERVER, "allowed-sharing-modes").unwrap(),
        "",
        "a sharee with read-write access cannot share on"
    );
    let invite = value(&owner, NS_CALENDARSERVER, "invite").unwrap();
    assert!(invite.starts_with(
        "<CS:organizer><D:href>/dav/principals/acme/anna/</D:href><CS:common-name>Anna</CS:common-name></CS:organizer>"
    ));
    assert!(invite.contains(
        "<CS:user><D:href>mailto:ben@acme.example</D:href><CS:common-name>Ben</CS:common-name><CS:invite-accepted/>\
         <CS:access><CS:read-write/></CS:access><CS:summary>Join &lt;us&gt;</CS:summary></CS:user>"
    ));
    assert!(invite.contains("<CS:invite-noresponse/><CS:access><CS:read/></CS:access>"));
    assert!(invite.contains("<CS:invite-declined/><CS:access><CS:read-write/></CS:access>"));
}

/// The collection of a binding, with the privileges the application computed for it.
fn collection_of(binding: &BindingView) -> CollectionView {
    CollectionView {
        privileges: binding.privileges,
        ..CollectionView::from_binding(binding)
    }
}

#[test]
fn a_calendar_can_be_shared_when_the_application_says_the_viewer_may_share_it() {
    let modes = |access: Access, kind: CalendarKind| {
        let view = collection_of(&binding(SharingRole::Unshared, access, kind));
        value(&Subject::Collection(view), NS_CALENDARSERVER, "allowed-sharing-modes").unwrap()
    };
    for kind in [CalendarKind::Managed, CalendarKind::Mirror] {
        assert_eq!(
            modes(Access::Owner, kind),
            "",
            "{kind}: capped at read, no share privilege"
        );
    }
    for access in [Access::FreeBusy, Access::Read, Access::ReadWrite] {
        assert_eq!(modes(access, CalendarKind::User), "", "{access:?}");
    }
    for access in [Access::Admin, Access::Owner] {
        assert_eq!(modes(access, CalendarKind::User), "<CS:can-be-shared/>", "{access:?}");
    }
    // The decision is the privilege: whatever the access says, a collection without it cannot be shared (sharing
    // switched off for the tenant, for example) and one with it can.
    let mut switched_off = collection_of(&binding(SharingRole::Unshared, Access::Owner, CalendarKind::User));
    switched_off.privileges = PrivilegeSet::of(&[Privilege::Read]);
    assert_eq!(
        value(
            &Subject::Collection(switched_off),
            NS_CALENDARSERVER,
            "allowed-sharing-modes"
        )
        .unwrap(),
        ""
    );
}

#[test]
fn the_special_collections_of_a_home_have_their_resource_types() {
    for (location, expected, token) in [
        ("/dav/calendars/acme/anna/", "<D:collection/>", false),
        (
            "/dav/calendars/acme/anna/inbox/",
            "<D:collection/><C:schedule-inbox/>",
            true,
        ),
        (
            "/dav/calendars/acme/anna/outbox/",
            "<D:collection/><C:schedule-outbox/>",
            false,
        ),
        (
            "/dav/calendars/acme/anna/notifications/",
            "<D:collection/><CS:notification/>",
            true,
        ),
    ] {
        let subject = Subject::Collection(special(location, token));
        assert_eq!(value(&subject, NS_DAV, "resourcetype").unwrap(), expected, "{location}");
        assert_eq!(
            value(&subject, NS_DAV, "owner").unwrap(),
            "<D:href>/dav/principals/acme/anna/</D:href>",
            "{location}"
        );
        assert_eq!(value(&subject, NS_DAV, "sync-token").is_some(), token, "{location}");
        assert_eq!(
            value(&subject, NS_CALENDARSERVER, "getctag").is_some(),
            token,
            "{location}"
        );
        assert_eq!(
            value(&subject, NS_CALDAV, "supported-calendar-data"),
            None,
            "{location}"
        );
    }
    let home = Subject::Collection(special("/dav/calendars/acme/anna/", false));
    assert_eq!(
        value(&home, NS_DAV, "principal-collection-set").unwrap(),
        "<D:href>/dav/</D:href>"
    );
    let inbox = Subject::Collection(special("/dav/calendars/acme/anna/inbox/", true));
    assert_eq!(
        value(&inbox, NS_DAV, "supported-report-set").unwrap(),
        "<D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report>\
         <D:supported-report><D:report><C:calendar-multiget/></D:report></D:supported-report>",
        "the inbox answers a multiget for its items"
    );
    let notifications = Subject::Collection(special("/dav/calendars/acme/anna/notifications/", true));
    assert_eq!(
        value(&notifications, NS_DAV, "supported-report-set").unwrap(),
        "<D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report>"
    );
    assert_eq!(value(&inbox, NS_DAV, "principal-collection-set"), None);
}

#[test]
fn privileges_are_listed_with_their_aggregate() {
    let subject = Subject::Collection(calendar());
    let privileges = value(&subject, NS_DAV, "current-user-privilege-set").unwrap();
    for element in [
        "<D:privilege><D:read/></D:privilege>",
        "<D:privilege><D:read-current-user-privilege-set/></D:privilege>",
        "<D:privilege><C:read-free-busy/></D:privilege>",
        "<D:privilege><D:write-content/></D:privilege>",
        "<D:privilege><D:write-properties/></D:privilege>",
        "<D:privilege><D:bind/></D:privilege>",
        "<D:privilege><D:unbind/></D:privilege>",
        "<D:privilege><D:write/></D:privilege>",
    ] {
        assert!(privileges.contains(element), "{element} in {privileges}");
    }
    let reader = Subject::Object(object());
    assert_eq!(
        value(&reader, NS_DAV, "current-user-privilege-set").unwrap(),
        "<D:privilege><D:read/></D:privilege>",
        "no aggregate without the four write privileges"
    );
    let mut writable = object();
    writable.privileges = PrivilegeSet::of(&[
        Privilege::Read,
        Privilege::ReadCurrentUserPrivilegeSet,
        Privilege::WriteContent,
        Privilege::WriteProperties,
        Privilege::Unbind,
    ]);
    let listed = value(&Subject::Object(writable), NS_DAV, "current-user-privilege-set").unwrap();
    assert!(
        listed.contains("<D:privilege><D:write/></D:privilege>"),
        "an object needs no bind privilege for the aggregate: {listed}"
    );
    let inbox = Subject::Collection(special("/dav/calendars/acme/anna/inbox/", true));
    let listed = value(&inbox, NS_DAV, "current-user-privilege-set").unwrap();
    assert!(
        listed.contains("<D:unbind/>") && !listed.contains("<D:write/>"),
        "{listed}"
    );
    let supported = value(&subject, NS_DAV, "supported-privilege-set").unwrap();
    assert!(supported.starts_with("<D:supported-privilege><D:privilege><D:all/></D:privilege><D:abstract/>"));
    parse(
        format!(
            "<D:x xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:CS=\"http://calendarserver.org/ns/\">{supported}</D:x>"
        )
        .as_bytes(),
        &davhaven_domain::DavLimits::default(),
    )
    .expect("the supported privilege set is well-formed XML");
}

#[test]
fn an_object_has_its_validators_and_its_data() {
    let subject = Subject::Object(object());
    let read = |namespace: &str, local: &str| value(&subject, namespace, local).unwrap();
    assert_eq!(read(NS_DAV, "resourcetype"), "");
    assert_eq!(read(NS_DAV, "getetag"), ETag::from_bytes(b"x").as_str());
    assert_eq!(
        read(NS_DAV, "getcontenttype"),
        "text/calendar; charset=utf-8; component=vtodo"
    );
    assert_eq!(read(NS_DAV, "getcontentlength"), "321");
    assert_eq!(read(NS_DAV, "getlastmodified"), "Tue, 03 Mar 2026 10:15:30 GMT");
    assert_eq!(read(NS_CALDAV, "schedule-tag"), "\"tag-1\"");
    assert_eq!(
        read(NS_CALDAV, "calendar-data"),
        "BEGIN:VCALENDAR&#13;\nSUMMARY:R&amp;D&#13;\nEND:VCALENDAR&#13;\n"
    );
    assert_eq!(value(&subject, NS_DAV, "displayname"), None);
    assert_eq!(value(&subject, NS_CALDAV, "calendar-description"), None);
}

#[test]
fn calendar_data_is_absent_when_it_was_not_asked_for() {
    let mut view = object();
    view.data = None;
    view.schedule_tag = None;
    let subject = Subject::Object(view);
    assert_eq!(value(&subject, NS_CALDAV, "calendar-data"), None);
    assert_eq!(value(&subject, NS_CALDAV, "schedule-tag"), None);
    let names = names_of(&subject);
    assert_eq!(
        names,
        [
            "D:resourcetype",
            "D:getetag",
            "D:getcontenttype",
            "D:getcontentlength",
            "D:getlastmodified",
            "D:current-user-principal",
            "D:current-user-privilege-set",
            "D:supported-report-set",
            "D:supportedlock",
            "D:lockdiscovery"
        ]
    );
}

#[test]
fn a_sync_member_knows_its_etag_only() {
    let etag = ETag::from_bytes(b"member");
    let subject = Subject::Member {
        path: path("/dav/calendars/acme/anna/work/a.ics"),
        etag: etag.clone(),
    };
    assert_eq!(names_of(&subject), ["D:getetag"]);
    assert_eq!(value(&subject, NS_DAV, "getetag").unwrap(), etag.as_str());
    assert_eq!(subject.path(), path("/dav/calendars/acme/anna/work/a.ics"));
}

#[test]
fn dead_properties_are_listed_found_and_part_of_allprop() {
    let subject = Subject::Collection(calendar());
    assert_eq!(
        value(&subject, "urn:example:x", "note").unwrap(),
        "<inner xmlns=\"urn:example:x\">v</inner>"
    );
    assert_eq!(value(&subject, "urn:example:x", "other"), None);
    assert!(names_of(&subject).contains(&"?:note".to_owned()));
    let services = AppServices::fake();
    let current = principal();
    let env = Env {
        services: &services,
        current: Some(&current),
        prefixes: &Prefixes::default(),
    };
    let allprop: Vec<String> = allprop_names(&env, &subject)
        .into_iter()
        .map(|name| name.local)
        .collect();
    assert_eq!(
        allprop,
        [
            "resourcetype",
            "displayname",
            "creationdate",
            "getlastmodified",
            "supportedlock",
            "lockdiscovery",
            "note"
        ]
    );
}

#[test]
fn every_listed_property_is_a_known_live_property_and_every_candidate_renders_somewhere() {
    let services = AppServices::fake();
    let current = principal();
    let env = Env {
        services: &services,
        current: Some(&current),
        prefixes: &Prefixes::default(),
    };
    let sharee = binding(SharingRole::Sharee, Access::ReadWrite, CalendarKind::User);
    let mut group = principal();
    group.kind = PrincipalKind::Group;
    let subjects = [
        Subject::Root,
        Subject::Principal(principal()),
        Subject::Principal(group),
        Subject::Collection(calendar()),
        Subject::from_binding(&sharee),
        Subject::Collection(special("/dav/calendars/acme/anna/", false)),
        Subject::Collection(special("/dav/calendars/acme/anna/inbox/", true)),
        Subject::Object(object()),
        Subject::Member {
            path: path("/dav/calendars/acme/anna/work/a.ics"),
            etag: ETag::from_bytes(b"m"),
        },
    ];
    let mut rendered: Vec<PropertyName> = Vec::new();
    for subject in &subjects {
        for name in property_names(&env, subject) {
            if name.namespace != "urn:example:x" {
                assert!(is_live(&name), "{name:?} is listed but not live");
            }
            assert!(render(&env, subject, &name).is_some(), "{name:?}");
            rendered.push(name);
        }
    }
    for candidates in [
        ROOT_PROPS,
        PRINCIPAL_PROPS,
        COLLECTION_PROPS,
        OBJECT_PROPS,
        MEMBER_PROPS,
    ] {
        for (namespace, local) in candidates {
            assert!(
                rendered
                    .iter()
                    .any(|name| name.namespace == *namespace && name.local == *local),
                "no subject renders {namespace}{local}"
            );
        }
    }
}

#[test]
fn allprop_is_the_set_of_rfc_4918() {
    for local in [
        "creationdate",
        "displayname",
        "getcontentlanguage",
        "getcontentlength",
        "getcontenttype",
        "getetag",
        "getlastmodified",
        "lockdiscovery",
        "resourcetype",
        "supportedlock",
    ] {
        assert!(is_allprop(&prop(NS_DAV, local)), "{local}");
    }
    assert!(!is_allprop(&prop(NS_DAV, "sync-token")));
    assert!(!is_allprop(&prop(NS_CALDAV, "calendar-data")));
    assert!(!is_allprop(&prop(NS_CALENDARSERVER, "getctag")));
}

#[test]
fn statuses_split_found_and_missing_properties() {
    let services = AppServices::fake();
    let env = Env {
        services: &services,
        current: None,
        prefixes: &Prefixes::default(),
    };
    let subject = Subject::Object(object());
    let request = PropRequest::Prop(PropList {
        names: vec![
            prop(NS_DAV, "getetag"),
            prop(NS_DAV, "displayname"),
            prop("urn:example:x", "unknown"),
        ],
        calendar_data: None,
    });
    let statuses = propstats(&env, &subject, &request, false);
    assert_eq!(statuses.len(), 2);
    assert_eq!((statuses[0].status, statuses[1].status), (200, 404));
    assert_eq!(
        statuses[0].props,
        format!("<D:getetag>{}</D:getetag>", ETag::from_bytes(b"x").as_str())
    );
    assert_eq!(
        statuses[1].props, "<D:displayname/><unknown xmlns=\"urn:example:x\"/>",
        "missing properties are named with empty elements"
    );
    let minimal = propstats(&env, &subject, &request, true);
    assert_eq!(minimal.len(), 1, "return=minimal drops the 404 propstat");
    assert_eq!(minimal[0].status, 200);
}

#[test]
fn a_resource_without_any_property_still_gets_a_propstat() {
    let services = AppServices::fake();
    let env = Env {
        services: &services,
        current: None,
        prefixes: &Prefixes::default(),
    };
    let subject = Subject::Object(object());
    let only_missing = PropRequest::Prop(PropList {
        names: vec![prop(NS_DAV, "displayname")],
        calendar_data: None,
    });
    let minimal = propstats(&env, &subject, &only_missing, true);
    assert_eq!(minimal, [Propstat::found(String::new())]);
    let empty = PropRequest::Prop(PropList::default());
    assert_eq!(
        propstats(&env, &subject, &empty, false),
        [Propstat::found(String::new())]
    );
}

#[test]
fn propname_lists_empty_elements_and_allprop_adds_the_includes() {
    let services = AppServices::fake();
    let current = principal();
    let env = Env {
        services: &services,
        current: Some(&current),
        prefixes: &Prefixes::default(),
    };
    let subject = Subject::Collection(calendar());
    let propname = propstats(&env, &subject, &PropRequest::PropName, false);
    assert_eq!(propname.len(), 1);
    assert!(propname[0].props.contains("<D:displayname/>"));
    assert!(propname[0].props.contains("<C:calendar-description/>"));
    assert!(propname[0].props.contains("<note xmlns=\"urn:example:x\"/>"));
    assert!(!propname[0].props.contains("Work"), "no values in propname");

    let include = PropList {
        names: vec![prop(NS_CALDAV, "calendar-description"), prop(NS_DAV, "displayname")],
        calendar_data: None,
    };
    let allprop = propstats(&env, &subject, &PropRequest::AllProp(include), false);
    assert_eq!(allprop.len(), 1);
    assert!(
        allprop[0]
            .props
            .contains("<C:calendar-description>All the work</C:calendar-description>")
    );
    assert_eq!(
        allprop[0].props.matches("<D:displayname>").count(),
        1,
        "an included property that allprop has is not repeated"
    );
    assert!(!allprop[0].props.contains("getctag"));
}

#[test]
fn what_a_request_needs_before_the_resources_are_read() {
    let by_name = |local: &str| {
        PropRequest::Prop(PropList {
            names: vec![prop(NS_DAV, local)],
            calendar_data: None,
        })
    };
    let root = ResourcePath::Root;
    let principal_path = path("/dav/principals/acme/anna/");
    assert!(needs_current_principal(&by_name("current-user-principal"), &root));
    assert!(needs_current_principal(
        &by_name("current-user-principal"),
        &principal_path
    ));
    assert!(
        needs_current_principal(&by_name("principal-URL"), &root),
        "the principal URL of the entry point is the one of the user"
    );
    assert!(
        !needs_current_principal(&by_name("principal-URL"), &principal_path),
        "a principal knows its own URL"
    );
    assert!(!needs_current_principal(&by_name("displayname"), &root));
    assert!(needs_current_principal(&PropRequest::PropName, &principal_path));
    assert!(
        !needs_current_principal(&PropRequest::AllProp(PropList::default()), &root),
        "allprop does not include the current user principal"
    );
    assert!(needs_current_principal(
        &PropRequest::AllProp(PropList {
            names: vec![prop(NS_DAV, "current-user-principal")],
            calendar_data: None,
        }),
        &root
    ));

    let detail = |names: &[PropertyName]| {
        home_detail(&PropRequest::Prop(PropList {
            names: names.to_vec(),
            calendar_data: None,
        }))
    };
    let plain = detail(&[prop(NS_DAV, "displayname"), prop(NS_CALENDARSERVER, "getctag")]);
    assert!(
        !plain.dead_properties && !plain.invites,
        "known live properties come from the bindings"
    );
    assert!(plain.special, "the scheduling collections are always listed");
    let dead = detail(&[prop("urn:example:x", "note")]);
    assert!(dead.dead_properties && !dead.invites);
    let invites = detail(&[prop(NS_CALENDARSERVER, "invite")]);
    assert!(!invites.dead_properties && invites.invites);
    for everything in [PropRequest::PropName, PropRequest::AllProp(PropList::default())] {
        let detail = home_detail(&everything);
        assert!(detail.dead_properties && detail.invites && detail.special);
    }
}

fn element(xml: &str) -> Element {
    parse(xml.as_bytes(), &davhaven_domain::DavLimits::default()).unwrap()
}

fn set(namespace: &str, local: &str, xml: &str) -> Interpreted {
    interpret_set(&prop(namespace, local), &element(xml), &Limits::default())
}

#[test]
fn the_settable_properties_become_changes() {
    assert_eq!(
        set(
            NS_DAV,
            "displayname",
            r#"<displayname xmlns="DAV:"> Work </displayname>"#
        ),
        Interpreted::Change(PropertyChange::DisplayName(Some(" Work ".to_owned())))
    );
    assert_eq!(
        set(
            NS_CALDAV,
            "calendar-description",
            r#"<d xmlns="urn:ietf:params:xml:ns:caldav">About</d>"#
        ),
        Interpreted::Change(PropertyChange::Description(Some("About".to_owned())))
    );
    assert_eq!(
        set(
            NS_APPLE_ICAL,
            "calendar-color",
            r#"<c xmlns="http://apple.com/ns/ical/"> #FF2D55FF
</c>"#
        ),
        Interpreted::Change(PropertyChange::Color(Some("#FF2D55FF".to_owned())))
    );
    assert_eq!(
        set(
            NS_APPLE_ICAL,
            "calendar-order",
            r#"<o xmlns="http://apple.com/ns/ical/">12</o>"#
        ),
        Interpreted::Change(PropertyChange::Order(Some(12)))
    );
    assert_eq!(
        set(
            NS_CALDAV,
            "calendar-timezone",
            r#"<t xmlns="urn:ietf:params:xml:ns:caldav"><![CDATA[BEGIN:VCALENDAR
END:VCALENDAR]]></t>"#
        ),
        Interpreted::Change(PropertyChange::Timezone(Some(
            "BEGIN:VCALENDAR\nEND:VCALENDAR".to_owned()
        )))
    );
    assert_eq!(
        set(
            NS_CALDAV,
            "schedule-calendar-transp",
            r#"<t xmlns="urn:ietf:params:xml:ns:caldav"><transparent/></t>"#
        ),
        Interpreted::Change(PropertyChange::ScheduleTransparency(Some(Transparency::Transparent)))
    );
    assert_eq!(
        set(
            NS_CALDAV,
            "schedule-calendar-transp",
            r#"<t xmlns="urn:ietf:params:xml:ns:caldav"><opaque/></t>"#
        ),
        Interpreted::Change(PropertyChange::ScheduleTransparency(Some(Transparency::Opaque)))
    );
}

#[test]
fn values_that_do_not_fit_the_property_are_invalid() {
    assert_eq!(
        set(
            NS_APPLE_ICAL,
            "calendar-order",
            r#"<o xmlns="http://apple.com/ns/ical/">first</o>"#
        ),
        Interpreted::Invalid
    );
    assert_eq!(
        set(
            NS_APPLE_ICAL,
            "calendar-order",
            r#"<o xmlns="http://apple.com/ns/ical/">99999999999</o>"#
        ),
        Interpreted::Invalid
    );
    assert_eq!(
        set(
            NS_CALDAV,
            "schedule-calendar-transp",
            r#"<t xmlns="urn:ietf:params:xml:ns:caldav"/>"#
        ),
        Interpreted::Invalid
    );
}

#[test]
fn live_properties_are_protected() {
    for (namespace, local) in [
        (NS_DAV, "getetag"),
        (NS_DAV, "getcontenttype"),
        (NS_DAV, "sync-token"),
        (NS_DAV, "current-user-privilege-set"),
        (NS_DAV, "owner"),
        (NS_DAV, "acl"),
        (NS_CALDAV, "calendar-data"),
        (NS_CALDAV, "max-resource-size"),
        (NS_CALDAV, "calendar-home-set"),
        (NS_CALENDARSERVER, "getctag"),
        (NS_CALENDARSERVER, "invite"),
    ] {
        let xml = format!("<p xmlns=\"{namespace}\">x</p>");
        assert_eq!(
            set(namespace, local, &xml),
            Interpreted::Protected,
            "{namespace}{local}"
        );
        assert_eq!(
            interpret_remove(&prop(namespace, local)),
            Interpreted::Protected,
            "{namespace}{local}"
        );
    }
}

#[test]
fn the_component_set_is_settable_only_at_creation() {
    let calendar = r#"<s xmlns="urn:ietf:params:xml:ns:caldav"><comp name="VEVENT"/><comp name="vtodo"/><comp name="VEVENT"/></s>"#;
    assert_eq!(
        set(NS_CALDAV, "supported-calendar-component-set", calendar),
        Interpreted::Components(vec![ComponentKind::Event, ComponentKind::Todo])
    );
    for bad in [
        r#"<s xmlns="urn:ietf:params:xml:ns:caldav"/>"#,
        r#"<s xmlns="urn:ietf:params:xml:ns:caldav"><comp name="VFREEBUSY"/></s>"#,
        r#"<s xmlns="urn:ietf:params:xml:ns:caldav"><comp/></s>"#,
    ] {
        assert_eq!(
            set(NS_CALDAV, "supported-calendar-component-set", bad),
            Interpreted::Invalid,
            "{bad}"
        );
    }
    assert_eq!(
        interpret_remove(&prop(NS_CALDAV, "supported-calendar-component-set")),
        Interpreted::Protected
    );
}

#[test]
fn the_resource_type_of_a_mkcol_names_its_children() {
    assert_eq!(
        set(
            NS_DAV,
            "resourcetype",
            r#"<r xmlns="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><collection/><c:calendar/></r>"#
        ),
        Interpreted::ResourceType(vec![prop(NS_DAV, "collection"), prop(NS_CALDAV, "calendar")])
    );
}

#[test]
fn other_properties_are_stored_as_dead_properties_within_the_size_limit() {
    let outcome = set(
        "urn:example:x",
        "note",
        r#"<note xmlns="urn:example:x">a &amp; b<b xmlns="urn:y"/></note>"#,
    );
    assert_eq!(
        outcome,
        Interpreted::Change(PropertyChange::Dead {
            name: prop("urn:example:x", "note"),
            value_xml: Some("a &amp; b<b xmlns=\"urn:y\"/>".to_owned()),
        })
    );
    // A property in a namespace of the protocol that the server does not own is a dead property too.
    assert!(matches!(
        set(NS_DAV, "some-other-property", r#"<p xmlns="DAV:"/>"#),
        Interpreted::Change(PropertyChange::Dead { .. })
    ));
    let limits = Limits {
        dav: davhaven_domain::DavLimits {
            max_dead_property_size: 10,
            ..davhaven_domain::DavLimits::default()
        },
        ..Limits::default()
    };
    let big = element(r#"<note xmlns="urn:example:x">0123456789ABCDEF</note>"#);
    assert_eq!(
        interpret_set(&prop("urn:example:x", "note"), &big, &limits),
        Interpreted::TooLarge
    );
    assert_eq!(
        interpret_remove(&prop("urn:example:x", "note")),
        Interpreted::Change(PropertyChange::Dead {
            name: prop("urn:example:x", "note"),
            value_xml: None,
        })
    );
}

#[test]
fn the_text_of_the_properties_clients_set_has_a_size_limit_too() {
    let limits = Limits {
        dav: davhaven_domain::DavLimits {
            max_dead_property_size: 8,
            ..davhaven_domain::DavLimits::default()
        },
        ical: davhaven_domain::IcalLimits {
            max_resource_size: 20,
            ..davhaven_domain::IcalLimits::default()
        },
        ..Limits::default()
    };
    let with = |namespace: &str, local: &str, text: &str| {
        interpret_set(
            &prop(namespace, local),
            &element(&format!("<p xmlns=\"{namespace}\">{text}</p>")),
            &limits,
        )
    };
    for (namespace, local) in [
        (NS_DAV, "displayname"),
        (NS_CALDAV, "calendar-description"),
        (NS_APPLE_ICAL, "calendar-color"),
    ] {
        assert!(
            matches!(with(namespace, local, "12345678"), Interpreted::Change(_)),
            "{local} at the limit"
        );
        assert_eq!(with(namespace, local, "123456789"), Interpreted::TooLarge, "{local}");
    }
    assert!(matches!(
        with(NS_CALDAV, "calendar-timezone", "12345678901234567890"),
        Interpreted::Change(_)
    ));
    assert_eq!(
        with(NS_CALDAV, "calendar-timezone", "123456789012345678901"),
        Interpreted::TooLarge,
        "a time zone may be as large as a resource, not larger"
    );
}

#[test]
fn a_request_cannot_set_more_dead_properties_than_a_binding_may_have() {
    let dead = |local: &str| {
        Interpreted::Change(PropertyChange::Dead {
            name: prop("urn:example:x", local),
            value_xml: Some("v".to_owned()),
        })
    };
    let removal = Interpreted::Change(PropertyChange::Dead {
        name: prop("urn:example:x", "gone"),
        value_xml: None,
    });
    let mut instructions = vec![
        dead("a"),
        Interpreted::Change(PropertyChange::DisplayName(None)),
        dead("b"),
        removal.clone(),
        dead("c"),
        dead("d"),
    ];
    limit_dead_properties(&mut instructions, 2);
    assert_eq!(
        instructions,
        [
            dead("a"),
            Interpreted::Change(PropertyChange::DisplayName(None)),
            dead("b"),
            removal,
            Interpreted::TooLarge,
            Interpreted::TooLarge,
        ],
        "only the sets count, and the third and later are refused"
    );
    let mut none = vec![dead("a")];
    limit_dead_properties(&mut none, 0);
    assert_eq!(none, [Interpreted::TooLarge]);
}

#[test]
fn every_privilege_a_user_can_have_is_a_supported_privilege() {
    // RFC 3744 asks for current-user-privilege-set to be a subset of supported-privilege-set.
    let supported = value(&Subject::Root, NS_DAV, "supported-privilege-set").unwrap();
    for privilege in Privilege::ALL {
        let (prefix, local) = privilege_element(*privilege);
        assert!(
            supported.contains(&format!("<D:privilege><{prefix}:{local}/></D:privilege>")),
            "{privilege} is missing from {supported}"
        );
    }
    assert!(supported.contains("<D:privilege><D:write/></D:privilege>"));
}

#[test]
fn the_entry_point_and_principals_have_the_privileges_of_the_domain_table() {
    let expected = privilege_set(
        privileges(Access::Owner, CalendarKind::Personal, ResourceKind::Principal),
        true,
    );
    for subject in [Subject::Root, Subject::Principal(principal())] {
        assert_eq!(value(&subject, NS_DAV, "current-user-privilege-set").unwrap(), expected);
    }
}

#[test]
fn properties_in_other_namespaces_use_the_prefixes_of_the_document() {
    let prefixes = Prefixes::of(["urn:example:x"], 4);
    let name = prop("urn:example:x", "note");
    assert_eq!(property_element(&prefixes, &name, Some("v")), "<n0:note>v</n0:note>");
    assert_eq!(property_element(&prefixes, &name, None), "<n0:note/>");
    assert_eq!(
        property_element(&Prefixes::default(), &name, None),
        "<note xmlns=\"urn:example:x\"/>",
        "without a prefix the element declares its namespace"
    );
}

#[test]
fn removals_of_the_settable_properties_clear_them() {
    for (namespace, local, change) in [
        (NS_DAV, "displayname", PropertyChange::DisplayName(None)),
        (NS_CALDAV, "calendar-description", PropertyChange::Description(None)),
        (NS_CALDAV, "calendar-timezone", PropertyChange::Timezone(None)),
        (NS_APPLE_ICAL, "calendar-color", PropertyChange::Color(None)),
        (NS_APPLE_ICAL, "calendar-order", PropertyChange::Order(None)),
        (
            NS_CALDAV,
            "schedule-calendar-transp",
            PropertyChange::ScheduleTransparency(None),
        ),
    ] {
        assert_eq!(
            interpret_remove(&prop(namespace, local)),
            Interpreted::Change(change),
            "{local}"
        );
    }
}

#[test]
fn times_and_content_types_use_the_http_forms() {
    assert_eq!(http_date(instant(6)), "Fri, 06 Mar 2026 10:15:30 GMT");
    assert_eq!(
        object_content_type(ComponentKind::Event),
        "text/calendar; charset=utf-8; component=vevent"
    );
    assert_eq!(
        object_content_type(ComponentKind::Journal),
        "text/calendar; charset=utf-8; component=vjournal"
    );
}

fn notification(kind: NotificationKind) -> NotificationView {
    let body =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CS:notification xmlns:CS=\"http://calendarserver.org/ns/\"/>\n";
    NotificationView {
        path: path("/dav/calendars/acme/anna/notifications/invite-1.xml"),
        id: NotificationId::from_uuid(Uuid::from_u128(8)),
        uid: Uid::parse("invite-1").unwrap(),
        etag: ETag::from_bytes(body.as_bytes()),
        kind,
        body_xml: body.to_owned(),
        size: u64::try_from(body.len()).unwrap(),
        privileges: privileges(Access::Owner, CalendarKind::Personal, ResourceKind::Notification),
        created_at: instant(5),
        updated_at: instant(7),
    }
}

fn inbox_item(data: Option<&str>) -> InboxItemView {
    InboxItemView {
        path: path("/dav/calendars/acme/anna/inbox/request-1.ics"),
        id: InboxItemId::from_uuid(Uuid::from_u128(9)),
        etag: ETag::from_bytes(b"itip"),
        size: u64::try_from(data.map_or(40, str::len)).unwrap(),
        data: data.map(str::to_owned),
        privileges: privileges(Access::Owner, CalendarKind::Personal, ResourceKind::InboxItem),
        created_at: instant(6),
    }
}

fn found() -> PrincipalHit {
    PrincipalHit {
        path: path("/dav/principals/acme/ben/"),
        id: PrincipalId::from_uuid(Uuid::from_u128(10)),
        name: name("ben"),
        display_name: "Ben <Baker>".to_owned(),
        kind: PrincipalKind::User,
        addresses: vec![
            CalendarUserAddress::parse("mailto:ben@acme.example").unwrap(),
            CalendarUserAddress::parse("urn:uuid:00000000-0000-0000-0000-00000000000a").unwrap(),
        ],
    }
}

#[test]
fn a_notification_is_a_small_xml_resource_that_says_what_it_is() {
    let invite = Subject::Notification(notification(NotificationKind::Invite));
    assert_eq!(
        names_of(&invite),
        [
            "D:resourcetype",
            "D:getetag",
            "D:getcontenttype",
            "D:getcontentlength",
            "D:getlastmodified",
            "D:creationdate",
            "D:current-user-privilege-set",
            "D:supported-report-set",
            "D:supportedlock",
            "D:lockdiscovery",
            "CS:notificationtype"
        ]
    );
    assert_eq!(
        invite.path(),
        path("/dav/calendars/acme/anna/notifications/invite-1.xml")
    );
    assert_eq!(value(&invite, NS_DAV, "resourcetype").unwrap(), "");
    assert_eq!(
        value(&invite, NS_DAV, "getcontenttype").unwrap(),
        "text/xml; charset=utf-8"
    );
    assert_eq!(
        value(&invite, NS_DAV, "getcontentlength").unwrap(),
        notification(NotificationKind::Invite).body_xml.len().to_string()
    );
    assert!(value(&invite, NS_DAV, "getetag").unwrap().starts_with('"'));
    assert_eq!(
        value(&invite, NS_DAV, "getlastmodified").unwrap(),
        "Sat, 07 Mar 2026 10:15:30 GMT",
        "the date of the last write goes with the entity tag, not the date of creation"
    );
    assert_eq!(value(&invite, NS_DAV, "creationdate").unwrap(), "2026-03-05T10:15:30Z");
    assert_eq!(
        value(&invite, NS_CALENDARSERVER, "notificationtype").unwrap(),
        "<CS:invite-notification shared-type=\"calendar\"/>"
    );
    let reply = Subject::Notification(notification(NotificationKind::InviteReply));
    assert_eq!(
        value(&reply, NS_CALENDARSERVER, "notificationtype").unwrap(),
        "<CS:invite-reply shared-type=\"calendar\"/>"
    );
    // Read, never write: a notification is removed by unbinding it from its collection.
    let privileges = value(&invite, NS_DAV, "current-user-privilege-set").unwrap();
    assert!(privileges.contains("<D:read/>") && privileges.contains("<D:read-current-user-privilege-set/>"));
    assert!(
        !privileges.contains("write") && !privileges.contains("unbind"),
        "{privileges}"
    );
    assert_eq!(value(&invite, NS_DAV, "supported-report-set").unwrap(), "");
    assert!(is_live(&prop(NS_CALENDARSERVER, "notificationtype")));
}

#[test]
fn an_inbox_item_knows_its_size_and_message_only_when_it_was_read() {
    let message = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nSUMMARY:R&D\r\nEND:VCALENDAR\r\n";
    let read = Subject::InboxItem(inbox_item(Some(message)));
    assert_eq!(
        names_of(&read),
        [
            "D:resourcetype",
            "D:getetag",
            "D:getcontenttype",
            "D:getcontentlength",
            "D:getlastmodified",
            "D:creationdate",
            "D:current-user-privilege-set",
            "D:supported-report-set",
            "D:supportedlock",
            "D:lockdiscovery",
            "C:calendar-data"
        ]
    );
    assert_eq!(read.path(), path("/dav/calendars/acme/anna/inbox/request-1.ics"));
    assert_eq!(
        value(&read, NS_DAV, "getcontenttype").unwrap(),
        "text/calendar; charset=utf-8"
    );
    assert_eq!(
        value(&read, NS_DAV, "getcontentlength").unwrap(),
        message.len().to_string()
    );
    // Carriage returns are character references in element text, or an XML reader would normalize them away.
    assert_eq!(
        value(&read, NS_CALDAV, "calendar-data").unwrap(),
        "BEGIN:VCALENDAR&#13;\nMETHOD:REQUEST&#13;\nSUMMARY:R&amp;D&#13;\nEND:VCALENDAR&#13;\n"
    );
    assert_eq!(
        value(&read, NS_DAV, "getlastmodified").unwrap(),
        "Fri, 06 Mar 2026 10:15:30 GMT"
    );

    let listed = Subject::InboxItem(inbox_item(None));
    assert_eq!(
        value(&listed, NS_DAV, "getcontentlength").as_deref(),
        Some("40"),
        "the size is the application's, so a listing answers it without the message"
    );
    assert_eq!(value(&listed, NS_CALDAV, "calendar-data"), None);
    assert!(value(&listed, NS_DAV, "getetag").is_some());
    assert!(
        names_of(&listed).contains(&"C:calendar-data".to_owned()),
        "an inbox item has its message, whether or not it was read: propname names it without a read"
    );
}

#[test]
fn the_privileges_of_inbox_items_and_notifications_are_the_ones_the_application_says() {
    let mut item = inbox_item(None);
    item.privileges = privileges(Access::Owner, CalendarKind::Personal, ResourceKind::Principal);
    let mut note = notification(NotificationKind::Invite);
    note.privileges = PrivilegeSet::empty();
    let shown = value(&Subject::InboxItem(item), NS_DAV, "current-user-privilege-set").unwrap();
    assert!(shown.contains("<D:read/>"), "{shown}");
    assert_eq!(
        value(&Subject::Notification(note), NS_DAV, "current-user-privilege-set").unwrap(),
        "",
        "nothing is assumed here: a view without privileges shows none"
    );
}

#[test]
fn a_principal_a_search_found_shows_a_name_and_addresses_and_nothing_else() {
    let subject = Subject::SearchHit(found());
    assert_eq!(
        names_of(&subject),
        [
            "D:resourcetype",
            "D:displayname",
            "D:principal-URL",
            "C:calendar-user-address-set",
            "C:calendar-user-type",
            "CS:email-address-set"
        ]
    );
    assert_eq!(subject.path(), path("/dav/principals/acme/ben/"));
    assert_eq!(
        value(&subject, NS_DAV, "resourcetype").unwrap(),
        "<D:collection/><D:principal/>"
    );
    assert_eq!(value(&subject, NS_DAV, "displayname").unwrap(), "Ben &lt;Baker&gt;");
    assert_eq!(
        value(&subject, NS_DAV, "principal-URL").unwrap(),
        "<D:href>/dav/principals/acme/ben/</D:href>"
    );
    assert_eq!(
        value(&subject, NS_CALDAV, "calendar-user-address-set").unwrap(),
        "<D:href>mailto:ben@acme.example</D:href><D:href>urn:uuid:00000000-0000-0000-0000-00000000000a</D:href>"
    );
    assert_eq!(
        value(&subject, NS_CALENDARSERVER, "email-address-set").unwrap(),
        "<CS:email-address>ben@acme.example</CS:email-address>"
    );
    assert_eq!(value(&subject, NS_CALDAV, "calendar-user-type").unwrap(), "INDIVIDUAL");
    for (namespace, local) in [
        (NS_CALDAV, "calendar-home-set"),
        (NS_CALDAV, "schedule-inbox-URL"),
        (NS_CALDAV, "schedule-outbox-URL"),
        (NS_CALENDARSERVER, "notification-URL"),
        (NS_DAV, "group-membership"),
        (NS_DAV, "group-member-set"),
        (NS_DAV, "current-user-privilege-set"),
        (NS_DAV, "owner"),
        // What no property of a principal that a search found may answer, even though the property exists:
        (NS_DAV, "supported-report-set"),
        (NS_DAV, "supported-privilege-set"),
        (NS_DAV, "supportedlock"),
        (NS_DAV, "lockdiscovery"),
        (NS_DAV, "current-user-principal"),
        (NS_DAV, "principal-collection-set"),
    ] {
        assert_eq!(
            value(&subject, namespace, local),
            None,
            "{local} is not part of a search answer"
        );
    }
}

#[test]
fn the_user_type_of_a_found_principal_follows_its_kind() {
    for (kind, expected) in [
        (PrincipalKind::User, "INDIVIDUAL"),
        (PrincipalKind::Service, "INDIVIDUAL"),
        (PrincipalKind::Group, "GROUP"),
        (PrincipalKind::Resource, "RESOURCE"),
    ] {
        let subject = Subject::SearchHit(PrincipalHit { kind, ..found() });
        assert_eq!(
            value(&subject, NS_CALDAV, "calendar-user-type").unwrap(),
            expected,
            "{kind}"
        );
    }
}
