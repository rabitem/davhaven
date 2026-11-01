//! PROPPATCH: the properties of a binding, shared properties, dead properties, atomicity and what the server
//! refuses itself.

use axum::http::StatusCode;

use crate::support::{Dav, HOME, NS, NS_APPLE_ICAL, NS_CALDAV, NS_DAV, Req, STANDUP, User, WORK, propfind, repeat};

fn patch(inner: &str) -> String {
    format!("<D:propertyupdate {NS}>{inner}</D:propertyupdate>")
}

fn set(props: &str) -> String {
    patch(&format!("<D:set><D:prop>{props}</D:prop></D:set>"))
}

#[tokio::test]
async fn the_properties_clients_set_are_stored_and_read_back() {
    let dav = Dav::new();
    let body = set("<D:displayname>Renamed &amp; Better</D:displayname>\
         <A:calendar-color>#112233FF</A:calendar-color>\
         <A:calendar-order>5</A:calendar-order>\
         <C:calendar-description>All the work</C:calendar-description>\
         <C:schedule-calendar-transp><C:transparent/></C:schedule-calendar-transp>");
    let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), [WORK]);
    assert_eq!(multi.responses[0].stats.len(), 1, "every property was applied");
    assert_eq!(multi.responses[0].stats[0].status, 200);
    assert_eq!(multi.responses[0].stats[0].props.len(), 5);

    let read = propfind(&[
        "D:displayname",
        "A:calendar-color",
        "A:calendar-order",
        "C:calendar-description",
        "C:schedule-calendar-transp",
    ]);
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(&read)).await;
    let multi = answer.multistatus();
    let work = &multi.responses[0];
    assert_eq!(work.text(NS_DAV, "displayname"), "Renamed & Better");
    assert_eq!(work.text(NS_APPLE_ICAL, "calendar-color"), "#112233FF");
    assert_eq!(work.text(NS_APPLE_ICAL, "calendar-order"), "5");
    assert_eq!(work.text(NS_CALDAV, "calendar-description"), "All the work");
    assert_eq!(work.children(NS_CALDAV, "schedule-calendar-transp"), ["transparent"]);
}

#[tokio::test]
async fn removing_a_property_clears_it() {
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("PROPPATCH", WORK).xml(&set("<A:calendar-color>#FF0000FF</A:calendar-color>")))
        .await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS);
    let removal = patch("<D:remove><D:prop><A:calendar-color/></D:prop></D:remove>");
    let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&removal)).await;
    assert_eq!(answer.multistatus().responses[0].stats[0].status, 200);
    let read = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&propfind(&["A:calendar-color"])),
        )
        .await;
    assert_eq!(
        read.multistatus().responses[0].status_of(NS_APPLE_ICAL, "calendar-color"),
        Some(404)
    );
}

#[tokio::test]
async fn the_request_is_atomic_and_every_property_says_why() {
    let dav = Dav::new();
    let body = set("<D:displayname>Never</D:displayname>\
         <D:getetag>\"forged\"</D:getetag>\
         <A:calendar-order>first</A:calendar-order>");
    let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&body)).await;
    let multi = answer.multistatus();
    let work = &multi.responses[0];
    assert_eq!(work.status_of(NS_DAV, "getetag"), Some(403));
    let protected = work.stats.iter().find(|stat| stat.status == 403).unwrap();
    assert_eq!(protected.error.as_deref(), Some("cannot-modify-protected-property"));
    assert_eq!(
        work.status_of(NS_APPLE_ICAL, "calendar-order"),
        Some(409),
        "the value is no number"
    );
    assert_eq!(
        work.status_of(NS_DAV, "displayname"),
        Some(424),
        "a property that was fine depends on the failures"
    );

    let read = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(
        read.multistatus().responses[0].text(NS_DAV, "displayname"),
        "Work",
        "nothing was applied"
    );
}

#[tokio::test]
async fn live_properties_of_the_server_are_protected() {
    let dav = Dav::new();
    for props in [
        "<D:getetag>\"x\"</D:getetag>",
        "<D:resourcetype><D:collection/></D:resourcetype>",
        "<D:sync-token>urn:davhaven:sync:x</D:sync-token>",
        "<C:supported-calendar-component-set><C:comp name=\"VEVENT\"/></C:supported-calendar-component-set>",
        "<CS:getctag>x</CS:getctag>",
        "<D:current-user-privilege-set/>",
        "<C:max-resource-size>5</C:max-resource-size>",
    ] {
        let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&set(props))).await;
        let multi = answer.multistatus();
        let stat = &multi.responses[0].stats[0];
        assert_eq!(stat.status, 403, "{props}");
        assert_eq!(
            stat.error.as_deref(),
            Some("cannot-modify-protected-property"),
            "{props}"
        );
    }
}

#[tokio::test]
async fn dead_properties_are_kept_as_written_and_listed() {
    let dav = Dav::new();
    let value = "<x:note xmlns:x=\"urn:example:x\">plain &amp; <x:b y=\"1\">nested</x:b> text</x:note>";
    let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&set(value))).await;
    assert_eq!(answer.multistatus().responses[0].stats[0].status, 200);

    let read = dav
        .send(Req::anna("PROPFIND", WORK).depth("0").xml(&format!(
            "<D:propfind {NS} xmlns:x=\"urn:example:x\"><D:prop><x:note/></D:prop></D:propfind>"
        )))
        .await;
    let multi = read.multistatus();
    let note = multi.responses[0]
        .prop("urn:example:x", "note")
        .expect("the dead property");
    assert_eq!(note.text(), "plain &  text");
    let nested = note.child("urn:example:x", "b").unwrap();
    assert_eq!(nested.text(), "nested");
    assert_eq!(nested.attribute("y"), Some("1"));

    let all = dav.send(Req::anna("PROPFIND", WORK).depth("0")).await;
    let all = all.multistatus();
    assert!(
        all.responses[0].prop("urn:example:x", "note").is_some(),
        "allprop includes dead properties"
    );
    let names = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&format!("<D:propfind {NS}><D:propname/></D:propfind>")),
        )
        .await;
    assert!(names.multistatus().responses[0].prop("urn:example:x", "note").is_some());

    let removal = patch("<D:remove><D:prop><x:note xmlns:x=\"urn:example:x\"/></D:prop></D:remove>");
    let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&removal)).await;
    assert_eq!(answer.multistatus().responses[0].stats[0].status, 200);
    let gone = dav.send(Req::anna("PROPFIND", WORK).depth("0")).await;
    assert!(gone.multistatus().responses[0].prop("urn:example:x", "note").is_none());
}

#[tokio::test]
async fn a_listing_of_the_home_includes_the_dead_properties_of_its_calendars() {
    let dav = Dav::new();
    let value = "<x:note xmlns:x=\"urn:example:x\">kept</x:note>";
    dav.send(Req::anna("PROPPATCH", WORK).xml(&set(value))).await;
    let body =
        format!("<D:propfind {NS} xmlns:x=\"urn:example:x\"><D:prop><D:displayname/><x:note/></D:prop></D:propfind>");
    let answer = dav
        .send(Req::anna("PROPFIND", "/dav/calendars/acme/anna/").depth("1").xml(&body))
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.response(WORK).text("urn:example:x", "note"), "kept");
    assert_eq!(
        multi
            .response("/dav/calendars/acme/anna/personal/")
            .status_of("urn:example:x", "note"),
        Some(404)
    );
}

#[tokio::test]
async fn dead_properties_have_a_size_limit_and_a_count_limit() {
    let dav = Dav::new();
    let big = "x".repeat(5000);
    let answer = dav
        .send(Req::anna("PROPPATCH", WORK).xml(&set(&format!("<x:big xmlns:x=\"urn:example:x\">{big}</x:big>"))))
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.responses[0].stats[0].status, 403, "a value over 4 KiB");

    let many = repeat(51, |n| format!("<x:p{n} xmlns:x=\"urn:example:x\">v</x:p{n}>"));
    let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&set(&many))).await;
    let multi = answer.multistatus();
    let statuses: Vec<u16> = multi.responses[0].stats.iter().map(|stat| stat.status).collect();
    assert!(
        statuses.contains(&403),
        "the 51st property does not fit, and a limit is 403 whoever finds it (PLAN 2.15): {statuses:?}"
    );
    assert!(statuses.contains(&424), "the others depend on it: {statuses:?}");
    assert!(!statuses.contains(&200));
}

#[tokio::test]
async fn objects_have_no_properties_a_client_may_change() {
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("PROPPATCH", STANDUP).xml(&set("<D:displayname>x</D:displayname><x:note xmlns:x=\"urn:x\"/>")))
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), [STANDUP]);
    assert_eq!(multi.responses[0].stats.len(), 1);
    assert_eq!(multi.responses[0].stats[0].status, 403);
    assert_eq!(multi.responses[0].stats[0].props.len(), 2);
}

#[tokio::test]
async fn calendars_of_others_cannot_be_patched() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("PROPPATCH", WORK)
                .by(User::Ben)
                .xml(&set("<D:displayname>Mine</D:displayname>")),
        )
        .await;
    assert_eq!(
        answer.status,
        StatusCode::NOT_FOUND,
        "the calendar of another user does not exist for Ben"
    );
    let foreign = dav
        .send(
            Req::anna("PROPPATCH", WORK)
                .by(User::Gina)
                .xml(&set("<D:displayname>Mine</D:displayname>")),
        )
        .await;
    assert_eq!(
        foreign.status,
        StatusCode::NOT_FOUND,
        "the calendar of another tenant is invisible, not a failed login (R4)"
    );
    let read = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(read.multistatus().responses[0].text(NS_DAV, "displayname"), "Work");
}

#[tokio::test]
async fn updates_that_say_nothing_are_400() {
    let dav = Dav::new();
    for body in [
        patch(""),
        patch("<D:set/>"),
        patch("<D:set><D:prop/></D:set>"),
        "<D:propfind xmlns:D=\"DAV:\"/>".to_owned(),
        "<D:propertyupdate".to_owned(),
    ] {
        let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}");
    }
}

#[tokio::test]
async fn objects_that_are_not_visible_are_not_found_rather_than_refused() {
    let dav = Dav::new();
    let body = set("<D:displayname>x</D:displayname>");
    for (user, path) in [
        (User::Ben, STANDUP),
        (User::Anna, "/dav/calendars/acme/anna/work/missing.ics"),
        (User::Anna, "/dav/calendars/acme/ben/personal/standup.ics"),
    ] {
        let answer = dav.send(Req::new("PROPPATCH", path).by(user).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{user:?} {path}");
        assert_eq!(answer.body, "", "nothing leaks");
    }
}

#[tokio::test]
async fn nothing_is_judged_before_the_calendar_is_visible() {
    let dav = Dav::new();
    let big = format!("<x:big xmlns:x=\"urn:example:x\">{}</x:big>", "x".repeat(5000));
    let many = repeat(51, |n| format!("<x:p{n} xmlns:x=\"urn:example:x\">v</x:p{n}>"));
    let refusals: Vec<(&str, String)> = vec![
        ("a protected property", set("<D:getetag>\"x\"</D:getetag>")),
        (
            "an order that is no number",
            set("<A:calendar-order>soon</A:calendar-order>"),
        ),
        (
            "a protected property next to a settable one",
            set("<D:displayname>x</D:displayname><D:getetag/>"),
        ),
        ("an oversized dead property", set(&big)),
        ("too many dead properties", set(&many)),
        ("a body that is no update", "<D:propfind xmlns:D=\"DAV:\"/>".to_owned()),
        ("a body that is not XML", "<broken".to_owned()),
        ("a body that is too large", "x".repeat(300_000)),
    ];
    for (what, body) in &refusals {
        for (user, path) in [
            (User::Ben, WORK),
            (User::Anna, "/dav/calendars/acme/anna/nope/"),
            (User::Anna, "/dav/calendars/acme/ben/personal/"),
        ] {
            let answer = dav.send(Req::new("PROPPATCH", path).by(user).xml(body)).await;
            assert_eq!(
                answer.status,
                StatusCode::NOT_FOUND,
                "{what}: {user:?} {path} is not a calendar they can see"
            );
            assert_eq!(answer.body, "", "{what}: {user:?} {path}");
        }
    }
    // The owner gets the answer the body deserves.
    for (what, body) in &refusals[..5] {
        let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(body)).await;
        assert_eq!(answer.status, StatusCode::MULTI_STATUS, "{what}");
    }
    let unreadable = dav.send(Req::anna("PROPPATCH", WORK).xml("<broken")).await;
    assert_eq!(unreadable.status, StatusCode::BAD_REQUEST);
    let too_large = dav.send(Req::anna("PROPPATCH", WORK).xml(&"x".repeat(300_000))).await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn the_home_and_the_inbox_store_no_properties() {
    let dav = Dav::new();
    let body = set(
        "<C:schedule-default-calendar-URL><D:href>/dav/calendars/acme/anna/work/</D:href></C:schedule-default-calendar-URL>\
         <x:note xmlns:x=\"urn:example:x\">v</x:note>",
    );
    for path in [HOME, "/dav/calendars/acme/anna/inbox/"] {
        let answer = dav.send(Req::anna("PROPPATCH", path).xml(&body)).await;
        let multi = answer.multistatus();
        assert_eq!(multi.hrefs(), [path]);
        let stat = &multi.responses[0].stats[0];
        assert_eq!(stat.status, 403, "{path}");
        assert_eq!(
            stat.error.as_deref(),
            Some("cannot-modify-protected-property"),
            "{path}"
        );
        assert_eq!(stat.props.len(), 2, "{path}");
        let others = dav.send(Req::anna("PROPPATCH", path).by(User::Ben).xml(&body)).await;
        assert_eq!(others.status, StatusCode::NOT_FOUND, "{path} of another user");
    }
    for path in [
        "/dav/calendars/acme/anna/outbox/",
        "/dav/calendars/acme/anna/notifications/",
    ] {
        let answer = dav.send(Req::anna("PROPPATCH", path).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }
}

#[tokio::test]
async fn names_in_other_namespaces_are_declared_once_on_the_root() {
    let dav = Dav::new();
    let body = set(
        "<x:one xmlns:x=\"urn:example:x\">1</x:one><y:two xmlns:y=\"urn:example:x\">2</y:two>\
         <z:three xmlns:z=\"urn:example:z\">3</z:three>",
    );
    let answer = dav.send(Req::anna("PROPPATCH", WORK).xml(&body)).await;
    assert_eq!(
        answer.body.matches("urn:example:x").count(),
        1,
        "the namespace is written once: {}",
        answer.body
    );
    assert!(answer.body.contains("<n0:one/><n0:two/>"), "{}", answer.body);
    assert!(answer.body.contains("<n1:three/>"), "{}", answer.body);
    let multi = answer.multistatus();
    let props = &multi.responses[0].stats[0].props;
    let names: Vec<(&str, &str)> = props.iter().map(|p| (&*p.namespace, p.local.as_str())).collect();
    assert_eq!(
        names,
        [
            ("urn:example:x", "one"),
            ("urn:example:x", "two"),
            ("urn:example:z", "three")
        ]
    );
}

#[tokio::test]
async fn the_text_of_a_property_has_a_size_limit() {
    let dav = Dav::new();
    let text = "t".repeat(5000);
    for (property, name, namespace) in [
        (format!("<D:displayname>{text}</D:displayname>"), "displayname", NS_DAV),
        (
            format!("<C:calendar-description>{text}</C:calendar-description>"),
            "calendar-description",
            NS_CALDAV,
        ),
        (
            format!("<A:calendar-color>{text}</A:calendar-color>"),
            "calendar-color",
            NS_APPLE_ICAL,
        ),
    ] {
        let answer = dav
            .send(Req::anna("PROPPATCH", WORK).xml(&set(&format!("{property}<A:calendar-order>3</A:calendar-order>"))))
            .await;
        let multi = answer.multistatus();
        let response = &multi.responses[0];
        assert_eq!(response.status_of(namespace, name), Some(403), "{name}");
        assert_eq!(response.status_of(NS_APPLE_ICAL, "calendar-order"), Some(424), "{name}");
    }
    let read = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&propfind(&["D:displayname", "A:calendar-order"])),
        )
        .await;
    let multi = read.multistatus();
    assert_eq!(
        multi.responses[0].text(NS_DAV, "displayname"),
        "Work",
        "nothing was applied"
    );
    assert_eq!(multi.responses[0].text(NS_APPLE_ICAL, "calendar-order"), "0");
}
