//! Discovery: the chain of PROPFINDs every client runs, from the entry point to the calendars of a home.

use axum::http::StatusCode;

use crate::support::{Dav, HOME, NS_APPLE_ICAL, NS_CALDAV, NS_CALENDARSERVER, NS_DAV, Req, User, WORK, propfind};

#[tokio::test]
async fn the_entry_point_names_the_principal_of_the_login() {
    let dav = Dav::new();
    let request = propfind(&["D:current-user-principal", "D:principal-URL", "D:resourcetype"]);
    let answer = dav.send(Req::anna("PROPFIND", "/dav/").depth("0").xml(&request)).await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), ["/dav/"]);
    let root = &multi.responses[0];
    assert_eq!(
        root.hrefs_of(NS_DAV, "current-user-principal"),
        ["/dav/principals/acme/anna/"]
    );
    assert_eq!(root.hrefs_of(NS_DAV, "principal-URL"), ["/dav/principals/acme/anna/"]);
    assert_eq!(root.children(NS_DAV, "resourcetype"), ["collection"]);

    let gina = dav
        .send(Req::new("PROPFIND", "/dav/").by(User::Gina).depth("0").xml(&request))
        .await;
    assert_eq!(
        gina.multistatus().responses[0].hrefs_of(NS_DAV, "current-user-principal"),
        ["/dav/principals/globex/gina/"],
        "a login of another tenant finds its own principal"
    );
}

#[tokio::test]
async fn the_entry_point_lists_nothing_below_it() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("PROPFIND", "/dav/")
                .depth("1")
                .xml(&propfind(&["D:resourcetype"])),
        )
        .await;
    assert_eq!(answer.multistatus().hrefs(), ["/dav/"]);
}

#[tokio::test]
async fn the_principal_points_to_home_inbox_outbox_and_notifications() {
    let dav = Dav::new();
    let request = propfind(&[
        "D:displayname",
        "D:resourcetype",
        "C:calendar-home-set",
        "C:schedule-inbox-URL",
        "C:schedule-outbox-URL",
        "CS:notification-URL",
        "C:calendar-user-address-set",
        "CS:email-address-set",
        "D:group-membership",
        "C:calendar-user-type",
        "D:supported-report-set",
    ]);
    let answer = dav
        .send(
            Req::anna("PROPFIND", "/dav/principals/acme/anna/")
                .depth("0")
                .xml(&request),
        )
        .await;
    let multi = answer.multistatus();
    let principal = multi.response("/dav/principals/acme/anna/");
    assert_eq!(principal.text(NS_DAV, "displayname"), "Anna Acme");
    assert_eq!(principal.children(NS_DAV, "resourcetype"), ["collection", "principal"]);
    assert_eq!(principal.hrefs_of(NS_CALDAV, "calendar-home-set"), [HOME]);
    assert_eq!(
        principal.hrefs_of(NS_CALDAV, "schedule-inbox-URL"),
        ["/dav/calendars/acme/anna/inbox/"]
    );
    assert_eq!(
        principal.hrefs_of(NS_CALDAV, "schedule-outbox-URL"),
        ["/dav/calendars/acme/anna/outbox/"]
    );
    assert_eq!(
        principal.hrefs_of(NS_CALENDARSERVER, "notification-URL"),
        ["/dav/calendars/acme/anna/notifications/"]
    );
    let addresses = principal.hrefs_of(NS_CALDAV, "calendar-user-address-set");
    assert_eq!(addresses[0], "mailto:anna@acme.example");
    assert!(
        addresses.contains(&"/dav/principals/acme/anna/".to_owned()),
        "{addresses:?}"
    );
    assert!(
        addresses.iter().any(|address| address.starts_with("urn:uuid:")),
        "{addresses:?}"
    );
    let email = principal.prop(NS_CALENDARSERVER, "email-address-set").unwrap();
    assert_eq!(
        email.child(NS_CALENDARSERVER, "email-address").unwrap().text(),
        "anna@acme.example"
    );
    assert_eq!(
        principal.hrefs_of(NS_DAV, "group-membership"),
        ["/dav/principals/acme/team/"]
    );
    assert_eq!(principal.text(NS_CALDAV, "calendar-user-type"), "INDIVIDUAL");
    assert_eq!(
        principal.reports(),
        [
            (NS_DAV.to_owned(), "expand-property".to_owned()),
            (NS_DAV.to_owned(), "principal-property-search".to_owned()),
            (NS_DAV.to_owned(), "principal-search-property-set".to_owned()),
            (
                NS_CALENDARSERVER.to_owned(),
                "calendarserver-principal-search".to_owned()
            ),
        ],
        "expand-property and the three principal searches"
    );
}

#[tokio::test]
async fn principals_of_the_own_tenant_can_be_looked_up_and_other_tenants_do_not_exist() {
    let dav = Dav::new();
    let request = propfind(&["D:displayname"]);
    let ben = dav
        .send(
            Req::anna("PROPFIND", "/dav/principals/acme/ben/")
                .depth("0")
                .xml(&request),
        )
        .await;
    assert_eq!(ben.multistatus().responses[0].text(NS_DAV, "displayname"), "Ben Baker");
    let gina = dav
        .send(
            Req::anna("PROPFIND", "/dav/principals/globex/gina/")
                .depth("0")
                .xml(&request),
        )
        .await;
    assert_eq!(
        gina.status,
        StatusCode::NOT_FOUND,
        "the path names another tenant: its principals are invisible, not a failed login (R4)"
    );
    let nobody = dav
        .send(
            Req::anna("PROPFIND", "/dav/principals/acme/nobody/")
                .depth("0")
                .xml(&request),
        )
        .await;
    assert_eq!(nobody.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_home_lists_every_calendar_and_the_scheduling_collections() {
    let dav = Dav::new();
    let request = propfind(&["D:displayname", "D:resourcetype", "D:current-user-privilege-set"]);
    let answer = dav.send(Req::anna("PROPFIND", HOME).depth("1").xml(&request)).await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.hrefs(),
        [
            "/dav/calendars/acme/anna/",
            "/dav/calendars/acme/anna/inbox/",
            "/dav/calendars/acme/anna/notifications/",
            "/dav/calendars/acme/anna/outbox/",
            "/dav/calendars/acme/anna/personal/",
            "/dav/calendars/acme/anna/team-calendar/",
            "/dav/calendars/acme/anna/work/",
        ],
        "the home first, then its members sorted by href"
    );
    assert_eq!(multi.response(WORK).text(NS_DAV, "displayname"), "Work");
    assert_eq!(
        multi.response(WORK).children(NS_DAV, "resourcetype"),
        ["collection", "calendar"]
    );
    assert_eq!(
        multi
            .response("/dav/calendars/acme/anna/inbox/")
            .children(NS_DAV, "resourcetype"),
        ["collection", "schedule-inbox"]
    );
    assert_eq!(
        multi
            .response("/dav/calendars/acme/anna/outbox/")
            .children(NS_DAV, "resourcetype"),
        ["collection", "schedule-outbox"]
    );
    assert_eq!(
        multi
            .response("/dav/calendars/acme/anna/notifications/")
            .children(NS_DAV, "resourcetype"),
        ["collection", "notification"]
    );
    assert_eq!(multi.response(HOME).children(NS_DAV, "resourcetype"), ["collection"]);
    assert_eq!(
        multi.response(HOME).privileges(),
        [
            "bind",
            "read",
            "read-current-user-privilege-set",
            "unbind",
            "write-properties"
        ],
        "the owner of a home reads it, sets its properties and binds and unbinds calendars"
    );
    assert_eq!(
        multi.response(WORK).privileges(),
        [
            "bind",
            "read",
            "read-current-user-privilege-set",
            "read-free-busy",
            "share",
            "unbind",
            "write",
            "write-content",
            "write-properties"
        ],
        "the owner of a calendar can do everything with it, including sharing it"
    );
}

#[tokio::test]
async fn the_home_at_depth_zero_is_the_home_alone() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("PROPFIND", HOME)
                .depth("0")
                .xml(&propfind(&["D:displayname", "D:owner"])),
        )
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), [HOME]);
    assert_eq!(
        multi.responses[0].hrefs_of(NS_DAV, "owner"),
        ["/dav/principals/acme/anna/"]
    );
}

#[tokio::test]
async fn the_homes_of_others_are_invisible() {
    let dav = Dav::new();
    let request = propfind(&["D:resourcetype"]);
    for (user, path) in [
        (User::Ben, HOME),
        (User::Ben, WORK),
        (User::Anna, "/dav/calendars/acme/ben/"),
        (User::Anna, "/dav/calendars/acme/ben/personal/"),
    ] {
        let answer = dav
            .send(Req::new("PROPFIND", path).by(user).depth("0").xml(&request))
            .await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{user:?} {path}");
        assert_eq!(answer.body, "", "nothing about the resource leaks");
    }
}

#[tokio::test]
async fn a_calendar_collection_has_the_properties_clients_read_at_setup() {
    let dav = Dav::new();
    let request = propfind(&[
        "D:displayname",
        "D:resourcetype",
        "D:owner",
        "C:supported-calendar-component-set",
        "C:supported-calendar-data",
        "C:max-resource-size",
        "C:min-date-time",
        "C:max-date-time",
        "C:max-instances",
        "C:max-attendees-per-instance",
        "C:schedule-calendar-transp",
        "CS:getctag",
        "D:sync-token",
        "D:supported-report-set",
        "D:current-user-privilege-set",
        "CS:allowed-sharing-modes",
        "A:calendar-order",
    ]);
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(&request)).await;
    let multi = answer.multistatus();
    let work = multi.response(WORK);
    assert_eq!(work.hrefs_of(NS_DAV, "owner"), ["/dav/principals/acme/anna/"]);
    assert_eq!(work.components(), ["VEVENT", "VTODO", "VJOURNAL"]);
    assert_eq!(work.text(NS_CALDAV, "max-resource-size"), "1048576");
    assert_eq!(work.text(NS_CALDAV, "min-date-time"), "19000101T000000Z");
    assert_eq!(work.text(NS_CALDAV, "max-date-time"), "21000101T000000Z");
    assert_eq!(work.text(NS_CALDAV, "max-instances"), "3000");
    assert_eq!(work.text(NS_CALDAV, "max-attendees-per-instance"), "200");
    assert_eq!(work.children(NS_CALDAV, "schedule-calendar-transp"), ["opaque"]);
    let token = work.text(NS_DAV, "sync-token");
    assert!(token.starts_with("urn:davhaven:sync:"), "{token}");
    assert_eq!(
        work.text(NS_CALENDARSERVER, "getctag"),
        token,
        "the ctag is the sync token"
    );
    assert_eq!(
        work.reports(),
        [
            (NS_DAV.to_owned(), "sync-collection".to_owned()),
            (NS_CALDAV.to_owned(), "calendar-query".to_owned()),
            (NS_CALDAV.to_owned(), "calendar-multiget".to_owned()),
            (NS_CALDAV.to_owned(), "free-busy-query".to_owned()),
        ],
        "sync-collection, calendar-query, calendar-multiget and free-busy-query"
    );
    assert_eq!(
        work.privileges(),
        [
            "bind",
            "read",
            "read-current-user-privilege-set",
            "read-free-busy",
            "share",
            "unbind",
            "write",
            "write-content",
            "write-properties"
        ]
    );
    assert_eq!(
        work.children(NS_CALENDARSERVER, "allowed-sharing-modes"),
        ["can-be-shared"]
    );
    assert_eq!(work.text(NS_APPLE_ICAL, "calendar-order"), "0");
}

#[tokio::test]
async fn the_sync_token_moves_with_every_change() {
    let dav = Dav::new();
    let read = || async {
        let answer = dav
            .send(Req::anna("PROPFIND", WORK).depth("0").xml(&propfind(&["CS:getctag"])))
            .await;
        answer.multistatus().responses[0].text(NS_CALENDARSERVER, "getctag")
    };
    let before = read().await;
    dav.put_event(&format!("{WORK}new.ics"), "new-1@acme.example", "New")
        .await;
    let after = read().await;
    assert_ne!(before, after);
    assert_eq!(read().await, after, "reading changes nothing");
}
