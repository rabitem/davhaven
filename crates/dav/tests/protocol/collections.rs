//! MKCALENDAR, extended MKCOL and DELETE of calendar collections.

use axum::http::StatusCode;
use davhaven_app::AppServices;
use davhaven_app_fake::AppServicesExt as _;

use crate::support::{Dav, HOME, NS, NS_APPLE_ICAL, NS_CALDAV, NS_DAV, Req, User, WORK, propfind, repeat};

const HOLIDAYS: &str = "/dav/calendars/acme/anna/holidays/";

fn mkcalendar(props: &str) -> String {
    format!("<C:mkcalendar {NS}><D:set><D:prop>{props}</D:prop></D:set></C:mkcalendar>")
}

fn mkcol(props: &str) -> String {
    format!("<D:mkcol {NS}><D:set><D:prop>{props}</D:prop></D:set></D:mkcol>")
}

#[tokio::test]
async fn mkcalendar_creates_a_calendar_with_the_properties_of_the_body() {
    let dav = Dav::new();
    let body = mkcalendar(
        "<D:displayname>Holidays</D:displayname>\
         <C:calendar-description>Days off</C:calendar-description>\
         <A:calendar-color>#00FF00FF</A:calendar-color>\
         <A:calendar-order>9</A:calendar-order>\
         <C:supported-calendar-component-set><C:comp name=\"VEVENT\"/></C:supported-calendar-component-set>\
         <C:schedule-calendar-transp><C:transparent/></C:schedule-calendar-transp>\
         <x:note xmlns:x=\"urn:example:x\">kept</x:note>",
    );
    let created = dav.send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&body)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body, "");

    let read = dav
        .send(Req::anna("PROPFIND", HOLIDAYS).depth("0").xml(&format!(
            "<D:propfind {NS} xmlns:x=\"urn:example:x\"><D:prop><D:displayname/><C:calendar-description/>\
             <A:calendar-color/><A:calendar-order/><C:supported-calendar-component-set/>\
             <C:schedule-calendar-transp/><x:note/><D:resourcetype/></D:prop></D:propfind>"
        )))
        .await;
    let multi = read.multistatus();
    let calendar = &multi.responses[0];
    assert_eq!(calendar.text(NS_DAV, "displayname"), "Holidays");
    assert_eq!(calendar.text(NS_CALDAV, "calendar-description"), "Days off");
    assert_eq!(calendar.text(NS_APPLE_ICAL, "calendar-color"), "#00FF00FF");
    assert_eq!(calendar.text(NS_APPLE_ICAL, "calendar-order"), "9");
    assert_eq!(calendar.components(), ["VEVENT"], "the component set of the body");
    assert_eq!(
        calendar.children(NS_CALDAV, "schedule-calendar-transp"),
        ["transparent"]
    );
    assert_eq!(calendar.text("urn:example:x", "note"), "kept");
    assert_eq!(calendar.children(NS_DAV, "resourcetype"), ["collection", "calendar"]);

    let home = dav
        .send(
            Req::anna("PROPFIND", HOME)
                .depth("1")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert!(
        home.multistatus().hrefs().contains(&HOLIDAYS),
        "the new calendar is in the home"
    );
}

#[tokio::test]
async fn mkcalendar_without_a_body_uses_the_defaults() {
    let dav = Dav::new();
    let created = dav.send(Req::anna("MKCALENDAR", HOLIDAYS)).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let read = dav
        .send(
            Req::anna("PROPFIND", HOLIDAYS)
                .depth("0")
                .xml(&propfind(&["D:displayname", "C:supported-calendar-component-set"])),
        )
        .await;
    let multi = read.multistatus();
    assert_eq!(
        multi.responses[0].text(NS_DAV, "displayname"),
        "holidays",
        "the slug names an unnamed calendar"
    );
    assert_eq!(
        multi.responses[0].components(),
        ["VEVENT", "VTODO", "VJOURNAL"],
        "a calendar without a component set takes every component the server stores"
    );
}

#[tokio::test]
async fn an_existing_resource_cannot_be_created_again() {
    let dav = Dav::new();
    for path in [WORK, HOME, "/dav/calendars/acme/anna/personal/"] {
        let answer = dav.send(Req::anna("MKCALENDAR", path)).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
        assert_eq!(
            answer.precondition().as_deref(),
            Some("resource-must-be-null"),
            "{path}"
        );
    }
    let mkcol = dav
        .send(Req::anna("MKCOL", WORK).xml(&mkcol("<D:resourcetype><D:collection/><C:calendar/></D:resourcetype>")))
        .await;
    assert_eq!(mkcol.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(mkcol.precondition().as_deref(), Some("resource-must-be-null"));
}

#[tokio::test]
async fn extended_mkcol_creates_calendars_and_nothing_else() {
    let dav = Dav::new();
    let created = dav
        .send(Req::anna("MKCOL", HOLIDAYS).xml(&mkcol(
            "<D:resourcetype><D:collection/><C:calendar/></D:resourcetype><D:displayname>Holidays</D:displayname>",
        )))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let read = dav
        .send(
            Req::anna("PROPFIND", HOLIDAYS)
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(read.multistatus().responses[0].text(NS_DAV, "displayname"), "Holidays");

    // RFC 5689: the failure names every property with its status, and the type the server will not make is the
    // one that is refused with `valid-resourcetype`; what was fine depends on it.
    for (body, expected) in [
        (
            mkcol("<D:resourcetype><D:collection/></D:resourcetype>"),
            vec![("resourcetype", 403, Some("valid-resourcetype"))],
        ),
        (
            mkcol("<D:displayname>Not a calendar</D:displayname>"),
            vec![
                ("displayname", 424, None),
                ("resourcetype", 403, Some("valid-resourcetype")),
            ],
        ),
        (String::new(), vec![("resourcetype", 403, Some("valid-resourcetype"))]),
    ] {
        let answer = dav
            .send(Req::anna("MKCOL", "/dav/calendars/acme/anna/plain/").xml(&body))
            .await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(answer.header("content-type"), "application/xml; charset=utf-8");
        let shape: Vec<(String, u16, Option<String>)> = answer
            .failures()
            .into_iter()
            .map(|failure| (failure.name, failure.status, failure.error))
            .collect();
        let expected: Vec<(String, u16, Option<String>)> = expected
            .into_iter()
            .map(|(name, status, error)| (name.to_owned(), status, error.map(str::to_owned)))
            .collect();
        assert_eq!(shape, expected, "{body}");
    }
    let missing = dav
        .send(
            Req::anna("PROPFIND", "/dav/calendars/acme/anna/plain/")
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND, "nothing was created");
}

#[tokio::test]
async fn creation_bodies_with_bad_properties_are_refused_and_create_nothing() {
    let dav = Dav::new();
    // A property the server refuses answers 403 with the status of each property (as in a PROPPATCH); a body that
    // is no creation request at all is 400.
    for (body, failures) in [
        (
            mkcalendar("<D:getetag>\"x\"</D:getetag>"),
            Some(vec![("getetag", 403, Some("cannot-modify-protected-property"))]),
        ),
        (
            mkcalendar("<A:calendar-order>soon</A:calendar-order><D:displayname>Fine</D:displayname>"),
            Some(vec![("calendar-order", 409, None), ("displayname", 424, None)]),
        ),
        (
            mkcalendar(
                "<C:supported-calendar-component-set><C:comp name=\"VFREEBUSY\"/></C:supported-calendar-component-set>",
            ),
            Some(vec![("supported-calendar-component-set", 409, None)]),
        ),
        (mkcol("<D:displayname/>"), None),
        (
            format!("<C:mkcalendar {NS}><D:remove><D:prop><D:displayname/></D:prop></D:remove></C:mkcalendar>"),
            None,
        ),
        ("<broken".to_owned(), None),
    ] {
        let answer = dav.send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&body)).await;
        match failures {
            Some(expected) => {
                assert_eq!(answer.status, StatusCode::FORBIDDEN, "{body}");
                let shape: Vec<(String, u16, Option<String>)> = answer
                    .failures()
                    .into_iter()
                    .map(|failure| (failure.name, failure.status, failure.error))
                    .collect();
                let expected: Vec<(String, u16, Option<String>)> = expected
                    .into_iter()
                    .map(|(name, status, error)| (name.to_owned(), status, error.map(str::to_owned)))
                    .collect();
                assert_eq!(shape, expected, "{body}");
            }
            None => assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}"),
        }
    }
    let missing = dav
        .send(
            Req::anna("PROPFIND", HOLIDAYS)
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn calendars_cannot_be_created_in_the_home_of_another_user() {
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("MKCALENDAR", "/dav/calendars/acme/anna/intruder/").by(User::Ben))
        .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    let read = dav
        .send(
            Req::anna("PROPFIND", "/dav/calendars/acme/anna/intruder/")
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(read.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deleting_a_calendar_removes_it_for_good() {
    let dav = Dav::new();
    assert_eq!(
        dav.send(Req::anna("MKCALENDAR", HOLIDAYS)).await.status,
        StatusCode::CREATED
    );
    dav.put_event(&format!("{HOLIDAYS}new-year.ics"), "ny-1@acme.example", "New year")
        .await;
    let deleted = dav.send(Req::anna("DELETE", HOLIDAYS)).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(deleted.body, "");
    for path in [HOLIDAYS, &format!("{HOLIDAYS}new-year.ics")] {
        let answer = dav
            .send(Req::anna("PROPFIND", path).depth("0").xml(&propfind(&["D:getetag"])))
            .await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(
        dav.send(Req::anna("DELETE", HOLIDAYS)).await.status,
        StatusCode::NOT_FOUND
    );
    let home = dav
        .send(
            Req::anna("PROPFIND", HOME)
                .depth("1")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert!(!home.multistatus().hrefs().contains(&HOLIDAYS));
}

#[tokio::test]
async fn collections_have_no_entity_tag_to_match() {
    let dav = Dav::new();
    assert_eq!(
        dav.send(Req::anna("MKCALENDAR", HOLIDAYS)).await.status,
        StatusCode::CREATED
    );
    let tagged = dav
        .send(Req::anna("DELETE", HOLIDAYS).header("if-match", "\"abcdefghijklmnopqrstuv\""))
        .await;
    assert_eq!(tagged.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        dav.send(
            Req::anna("PROPFIND", HOLIDAYS)
                .depth("0")
                .xml(&propfind(&["D:displayname"]))
        )
        .await
        .status,
        StatusCode::MULTI_STATUS,
        "nothing was deleted"
    );
    let any = dav.send(Req::anna("DELETE", HOLIDAYS).header("if-match", "*")).await;
    assert_eq!(any.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn calendars_of_others_cannot_be_deleted() {
    let dav = Dav::new();
    let answer = dav.send(Req::anna("DELETE", WORK).by(User::Ben)).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(
        dav.send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&propfind(&["D:displayname"]))
        )
        .await
        .status,
        StatusCode::MULTI_STATUS
    );
}

#[tokio::test]
async fn a_home_that_exists_cannot_be_created_and_one_that_is_invisible_is_not_found() {
    let dav = Dav::new();
    for method in ["MKCALENDAR", "MKCOL"] {
        let own = dav.send(Req::anna(method, HOME)).await;
        assert_eq!(own.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(own.precondition().as_deref(), Some("resource-must-be-null"), "{method}");
        for path in ["/dav/calendars/acme/ben/", "/dav/calendars/acme/nobody/"] {
            let other = dav.send(Req::anna(method, path)).await;
            assert_eq!(other.status, StatusCode::NOT_FOUND, "{method} {path}");
            assert_eq!(other.body, "", "{method} {path}");
        }
    }
    let inbox = dav
        .send(Req::anna("MKCALENDAR", "/dav/calendars/acme/anna/inbox/"))
        .await;
    assert_eq!(
        inbox.status,
        StatusCode::METHOD_NOT_ALLOWED,
        "the inbox does not define the method"
    );
}

#[tokio::test]
async fn nothing_is_judged_before_the_home_is_visible() {
    let dav = Dav::new();
    let big = format!("<x:big xmlns:x=\"urn:example:x\">{}</x:big>", "x".repeat(5000));
    let many = repeat(51, |n| format!("<x:p{n} xmlns:x=\"urn:example:x\">v</x:p{n}>"));
    let requests: Vec<(&str, String)> = vec![
        ("MKCALENDAR", mkcalendar("<D:getetag>\"x\"</D:getetag>")),
        ("MKCALENDAR", mkcalendar("<A:calendar-order>soon</A:calendar-order>")),
        ("MKCALENDAR", mkcalendar(&big)),
        ("MKCALENDAR", mkcalendar(&many)),
        ("MKCALENDAR", "<broken".to_owned()),
        ("MKCALENDAR", "x".repeat(300_000)),
        ("MKCOL", mkcol("<D:displayname>Not a calendar</D:displayname>")),
        ("MKCOL", mkcol("<D:resourcetype><D:collection/></D:resourcetype>")),
        ("MKCOL", String::new()),
    ];
    for (method, body) in &requests {
        for (user, path) in [
            (User::Ben, "/dav/calendars/acme/anna/intruder/"),
            (User::Anna, "/dav/calendars/acme/ben/intruder/"),
            (User::Anna, "/dav/calendars/acme/nobody/intruder/"),
        ] {
            let answer = dav.send(Req::new(method, path).by(user).xml(body)).await;
            assert_eq!(
                answer.status,
                StatusCode::NOT_FOUND,
                "{user:?} {method} {path}: the home is not theirs, whatever the body says"
            );
            assert_eq!(answer.body, "", "{user:?} {method} {path}");
        }
    }
    let intruder = dav
        .send(
            Req::anna("PROPFIND", "/dav/calendars/acme/anna/intruder/")
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(intruder.status, StatusCode::NOT_FOUND, "nothing was created");
    // In the home of the caller the same bodies are refused for their own reasons.
    let own = dav
        .send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&mkcalendar("<D:getetag>\"x\"</D:getetag>")))
        .await;
    assert_eq!(own.status, StatusCode::FORBIDDEN);
    let too_large = dav
        .send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&"x".repeat(300_000)))
        .await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_creation_cannot_store_more_dead_properties_than_a_binding_may_have() {
    let dav = Dav::new();
    let dead = |count: usize| repeat(count, |n| format!("<x:p{n} xmlns:x=\"urn:example:x\">v</x:p{n}>"));
    let refused = dav
        .send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&mkcalendar(&dead(51))))
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "a limit of PLAN 2.15 is 403");
    let failures = refused.failures();
    assert_eq!(failures.len(), 51);
    assert_eq!(
        failures.iter().filter(|failure| failure.status == 424).count(),
        50,
        "the properties that were fine depend on the one that was not"
    );
    let over = failures.iter().find(|failure| failure.status == 403).expect("the 51st");
    assert_eq!((over.name.as_str(), over.error.as_deref()), ("p50", None));
    let missing = dav
        .send(
            Req::anna("PROPFIND", HOLIDAYS)
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND, "nothing was created");

    let fits = dav
        .send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&mkcalendar(&dead(50))))
        .await;
    assert_eq!(fits.status, StatusCode::CREATED, "{}", fits.body);
}

#[tokio::test]
async fn the_limits_of_properties_are_configurable() {
    let mut services = AppServices::fake();
    services.limits.dav.max_dead_properties = 2;
    services.limits.dav.max_dead_property_size = 40;
    services.limits.ical.max_resource_size = 1000;
    let dav = Dav::with(services);
    let dead = |count: usize| repeat(count, |n| format!("<x:p{n} xmlns:x=\"urn:example:x\">v</x:p{n}>"));
    let three = dav
        .send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&mkcalendar(&dead(3))))
        .await;
    assert_eq!(three.status, StatusCode::FORBIDDEN);
    let two = dav
        .send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&mkcalendar(&dead(2))))
        .await;
    assert_eq!(two.status, StatusCode::CREATED, "{}", two.body);

    let text = "t".repeat(41);
    for (property, name) in [
        (format!("<D:displayname>{text}</D:displayname>"), "displayname"),
        (
            format!("<C:calendar-description>{text}</C:calendar-description>"),
            "calendar-description",
        ),
        (format!("<A:calendar-color>{text}</A:calendar-color>"), "calendar-color"),
        (
            format!("<C:calendar-timezone>{}</C:calendar-timezone>", "z".repeat(1001)),
            "calendar-timezone",
        ),
    ] {
        let answer = dav
            .send(Req::anna("MKCALENDAR", "/dav/calendars/acme/anna/texty/").xml(&mkcalendar(&property)))
            .await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{name}");
        let failures = answer.failures();
        assert_eq!(
            (
                failures[0].name.as_str(),
                failures[0].status,
                failures[0].error.as_deref()
            ),
            (name, 403, None),
            "{name}"
        );
    }
    let timezone_at_the_limit = dav
        .send(
            Req::anna("MKCALENDAR", "/dav/calendars/acme/anna/zone/").xml(&mkcalendar(&format!(
                "<C:calendar-timezone>{}</C:calendar-timezone>",
                "z".repeat(1000)
            ))),
        )
        .await;
    assert_eq!(
        timezone_at_the_limit.status,
        StatusCode::CREATED,
        "{}",
        timezone_at_the_limit.body
    );
}

#[tokio::test]
async fn a_property_that_is_set_twice_has_the_last_value() {
    let dav = Dav::new();
    let body = mkcalendar(
        "<x:note xmlns:x=\"urn:example:x\">first</x:note><D:displayname>Once</D:displayname>\
         <x:note xmlns:x=\"urn:example:x\">second</x:note>",
    );
    assert_eq!(
        dav.send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&body)).await.status,
        StatusCode::CREATED
    );
    let read = dav
        .send(Req::anna("PROPFIND", HOLIDAYS).depth("0").xml(&format!(
            "<D:propfind {NS} xmlns:x=\"urn:example:x\"><D:prop><x:note/></D:prop></D:propfind>"
        )))
        .await;
    assert_eq!(read.multistatus().responses[0].text("urn:example:x", "note"), "second");
}

#[tokio::test]
async fn a_405_for_an_existing_collection_says_what_the_resource_allows() {
    let dav = Dav::new();
    for path in [WORK, HOME] {
        let answer = dav.send(Req::anna("MKCALENDAR", path)).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
        let resource = davhaven_domain::ResourcePath::parse(path).unwrap();
        assert_eq!(
            answer.header("allow"),
            davhaven_dav::methods::allow_header(&resource),
            "{path}"
        );
    }
}

#[tokio::test]
async fn deleting_a_collection_evaluates_every_condition_it_is_sent() {
    let dav = Dav::new();
    assert_eq!(
        dav.send(Req::anna("MKCALENDAR", HOLIDAYS)).await.status,
        StatusCode::CREATED
    );
    let exists = || async {
        dav.send(
            Req::anna("PROPFIND", HOLIDAYS)
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
        )
        .await
        .status
    };
    // The collection exists, so a request that wants to create it fails.
    let none_match = dav
        .send(Req::anna("DELETE", HOLIDAYS).header("if-none-match", "*"))
        .await;
    assert_eq!(none_match.status, StatusCode::PRECONDITION_FAILED);
    // A header that cannot be read is a condition that fails, not one that is skipped.
    let mut unreadable = Req::anna("DELETE", HOLIDAYS);
    unreadable = unreadable.raw_header("if-match", b"\"caf\xe9\"");
    assert_eq!(dav.send(unreadable).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(exists().await, StatusCode::MULTI_STATUS, "nothing was deleted");
    // Every occurrence counts: a tag in the first header does not hide the star in the second.
    let two = dav
        .send(
            Req::anna("DELETE", HOLIDAYS)
                .header("if-match", "\"abcdefghijklmnopqrstuv\"")
                .header("if-match", "*"),
        )
        .await;
    assert_eq!(two.status, StatusCode::NO_CONTENT);
}
