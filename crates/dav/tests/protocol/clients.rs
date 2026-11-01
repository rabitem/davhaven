//! The request bodies of the clients of PLAN G1 (`testdata/dav`): every file is sent to the router the way its
//! client sends it, and the answers are read the way that client reads them.
//!
//! The bodies are reconstructions (see the README of the directory): what matters here is their shape, with
//! prefixes of every style, namespaces declared on every element, attributes the server ignores, properties it
//! does not have and carriage returns written as references.

use axum::http::StatusCode;
use davhaven_dav::xml::parse;
use davhaven_domain::DavLimits;

use crate::support::{Dav, NS_APPLE_ICAL, NS_CALDAV, NS_CALENDARSERVER, NS_DAV, Req, STANDUP, STANDUP_ICS, WORK, todo};

const HOLIDAYS: &str = "/dav/calendars/acme/anna/holidays/";

/// Every body of the corpus; the test below keeps this list and the directory the same.
const BODIES: [&str; 13] = [
    "macos-propfind-entry.xml",
    "macos-propfind-principal.xml",
    "macos-propfind-home.xml",
    "macos-propfind-members.xml",
    "macos-mkcalendar.xml",
    "macos-proppatch-color.xml",
    "davx5-propfind-home-set.xml",
    "davx5-sync-collection.xml",
    "davx5-multiget.xml",
    "thunderbird-calendar-query-events.xml",
    "thunderbird-calendar-query-todos.xml",
    "evolution-propfind-calendar.xml",
    "ios-calendar-query-expand.xml",
];

fn directory() -> String {
    format!("{}/../../testdata/dav", env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> String {
    let path = format!("{}/{name}", directory());
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn the_corpus_and_the_list_of_bodies_agree() {
    let mut files: Vec<String> = std::fs::read_dir(directory())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
        })
        .collect();
    files.sort();
    let mut listed: Vec<String> = BODIES.iter().map(|name| (*name).to_owned()).collect();
    listed.sort();
    assert_eq!(
        files, listed,
        "a body of the corpus is not tested, or a tested body is missing"
    );
}

#[test]
fn every_body_is_well_formed_under_the_default_limits() {
    for name in BODIES {
        let body = fixture(name);
        parse(body.as_bytes(), &DavLimits::default()).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[tokio::test]
async fn macos_discovery_leads_from_the_entry_point_to_the_calendars() {
    let dav = Dav::new();
    let entry = dav
        .send(
            Req::anna("PROPFIND", "/dav/")
                .depth("0")
                .xml(&fixture("macos-propfind-entry.xml")),
        )
        .await;
    let multi = entry.multistatus();
    let principal = multi.responses[0].hrefs_of(NS_DAV, "current-user-principal");
    assert_eq!(principal, ["/dav/principals/acme/anna/"]);

    let answer = dav
        .send(
            Req::anna("PROPFIND", &principal[0])
                .depth("0")
                .xml(&fixture("macos-propfind-principal.xml")),
        )
        .await;
    let multi = answer.multistatus();
    let anna = &multi.responses[0];
    assert_eq!(anna.text(NS_DAV, "displayname"), "Anna Acme");
    assert_eq!(
        anna.hrefs_of(NS_CALDAV, "calendar-home-set"),
        ["/dav/calendars/acme/anna/"]
    );
    assert_eq!(
        anna.hrefs_of(NS_CALDAV, "schedule-inbox-URL"),
        ["/dav/calendars/acme/anna/inbox/"]
    );
    assert_eq!(
        anna.hrefs_of(NS_CALENDARSERVER, "notification-URL"),
        ["/dav/calendars/acme/anna/notifications/"]
    );
    assert_eq!(anna.hrefs_of(NS_DAV, "principal-collection-set"), ["/dav/"]);
    for unknown in [
        (NS_CALENDARSERVER, "dropbox-home-URL"),
        (NS_DAV, "resource-id"),
        (NS_CALENDARSERVER, "xmpp-server"),
    ] {
        assert_eq!(anna.status_of(unknown.0, unknown.1), Some(404), "{unknown:?}");
    }
}

#[tokio::test]
async fn macos_lists_the_calendars_of_a_home_with_forty_properties_it_may_or_may_not_have() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("PROPFIND", "/dav/calendars/acme/anna/")
                .depth("1")
                .xml(&fixture("macos-propfind-home.xml")),
        )
        .await;
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
        ]
    );
    let work = multi.response(WORK);
    assert_eq!(work.text(NS_DAV, "displayname"), "Work");
    assert_eq!(work.children(NS_DAV, "resourcetype"), ["collection", "calendar"]);
    assert_eq!(
        work.text(NS_CALENDARSERVER, "getctag"),
        work.text(NS_DAV, "sync-token"),
        "the ctag and the sync token are one value"
    );
    assert_eq!(
        work.children(NS_CALENDARSERVER, "allowed-sharing-modes"),
        ["can-be-shared"]
    );
    assert_eq!(
        work.children(NS_CALENDARSERVER, "invite").len(),
        0,
        "an unshared calendar has no invitations"
    );
    assert_eq!(work.status_of(NS_CALENDARSERVER, "invite"), Some(200));
    let privileges: Vec<String> = work
        .prop(NS_DAV, "current-user-privilege-set")
        .unwrap()
        .elements()
        .filter_map(|privilege| privilege.elements().next())
        .map(|name| name.local.clone())
        .collect();
    assert!(privileges.contains(&"read".to_owned()), "{privileges:?}");
    assert_eq!(work.children(NS_DAV, "supported-report-set").len(), 4);
    for (namespace, local) in [
        ("http://me.com/_namespace/", "bulk-requests"),
        (NS_APPLE_ICAL, "calendar-enabled"),
        (NS_APPLE_ICAL, "autoprovisioned"),
        (NS_CALENDARSERVER, "pushkey"),
        (NS_CALENDARSERVER, "source"),
        (NS_DAV, "quota-used-bytes"),
        (NS_CALDAV, "default-alarm-vevent-datetime"),
        (NS_CALDAV, "supported-calendar-component-sets"),
    ] {
        assert_eq!(work.status_of(namespace, local), Some(404), "{local}");
    }
    let found = work.stats.iter().find(|stat| stat.status == 200).unwrap().props.len();
    let missing = work.stats.iter().find(|stat| stat.status == 404).unwrap().props.len();
    assert_eq!(found + missing, 38, "every requested property is answered exactly once");
}

#[tokio::test]
async fn macos_lists_the_members_of_a_calendar() {
    let dav = Dav::new();
    dav.put_event(&format!("{WORK}second.ics"), "second-1@acme.example", "Second")
        .await;
    let answer = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("1")
                .xml(&fixture("macos-propfind-members.xml")),
        )
        .await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.hrefs(),
        [WORK, "/dav/calendars/acme/anna/work/second.ics", STANDUP]
    );
    let standup = multi.response(STANDUP);
    assert_eq!(
        standup.text(NS_DAV, "getcontenttype"),
        "text/calendar; charset=utf-8; component=vevent"
    );
    assert_eq!(
        standup.text(NS_DAV, "getetag"),
        davhaven_domain::ETag::from_bytes(STANDUP_ICS.as_bytes()).as_str()
    );
    assert_eq!(
        standup.children(NS_DAV, "resourcetype").len(),
        0,
        "an object is no collection"
    );
}

#[tokio::test]
async fn a_calendar_made_by_macos_keeps_everything_the_client_asked_for() {
    let dav = Dav::new();
    let created = dav
        .send(Req::anna("MKCALENDAR", HOLIDAYS).xml(&fixture("macos-mkcalendar.xml")))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);

    let answer = dav
        .send(
            Req::anna("PROPFIND", HOLIDAYS)
                .depth("0")
                .xml(&fixture("macos-propfind-home.xml")),
        )
        .await;
    let multi = answer.multistatus();
    let holidays = &multi.responses[0];
    assert_eq!(holidays.text(NS_DAV, "displayname"), "Holidays");
    assert_eq!(holidays.text(NS_APPLE_ICAL, "calendar-color"), "#1BADF8FF");
    assert_eq!(holidays.text(NS_APPLE_ICAL, "calendar-order"), "4");
    assert_eq!(
        holidays.text(NS_APPLE_ICAL, "calendar-enabled"),
        "1",
        "stored as a dead property"
    );
    assert_eq!(
        holidays.children(NS_CALDAV, "supported-calendar-component-set"),
        ["comp"]
    );
    assert_eq!(holidays.children(NS_CALDAV, "schedule-calendar-transp"), ["opaque"]);
    let timezone = holidays.text(NS_CALDAV, "calendar-timezone");
    assert!(
        timezone.starts_with("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"),
        "{timezone:?}"
    );
    assert!(timezone.contains("TZID:Europe/Berlin\r\n"));
    assert!(
        timezone.ends_with("END:VCALENDAR\r\n"),
        "line breaks survive the round trip: {timezone:?}"
    );
}

#[tokio::test]
async fn macos_changes_a_calendar_in_one_request() {
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("PROPPATCH", WORK).xml(&fixture("macos-proppatch-color.xml")))
        .await;
    let multi = answer.multistatus();
    let response = multi.response(WORK);
    assert_eq!(response.stats.len(), 1, "everything was applied: {multi:?}");
    assert_eq!(response.stats[0].status, 200);
    let names: Vec<&str> = response.stats[0].props.iter().map(|prop| prop.local.as_str()).collect();
    assert_eq!(
        names,
        ["calendar-color", "displayname", "calendar-enabled", "calendar-order"]
    );

    let read = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&fixture("macos-propfind-home.xml")),
        )
        .await;
    let multi = read.multistatus();
    let work = &multi.responses[0];
    assert_eq!(work.text(NS_APPLE_ICAL, "calendar-color"), "#44A703FF");
    assert_eq!(work.text(NS_DAV, "displayname"), "Team work");
    assert_eq!(work.text(NS_APPLE_ICAL, "calendar-enabled"), "0");
}

#[tokio::test]
async fn davx5_finds_its_calendars_with_default_namespaces() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("PROPFIND", "/dav/principals/acme/anna/")
                .depth("0")
                .xml(&fixture("davx5-propfind-home-set.xml")),
        )
        .await;
    let multi = answer.multistatus();
    let anna = &multi.responses[0];
    assert_eq!(
        anna.hrefs_of(NS_DAV, "current-user-principal"),
        ["/dav/principals/acme/anna/"]
    );
    assert_eq!(
        anna.hrefs_of(NS_CALDAV, "calendar-home-set"),
        ["/dav/calendars/acme/anna/"]
    );
    assert_eq!(
        anna.hrefs_of(NS_DAV, "group-membership"),
        ["/dav/principals/acme/team/"]
    );
    assert!(
        anna.hrefs_of(NS_CALDAV, "calendar-user-address-set")
            .contains(&"mailto:anna@acme.example".to_owned())
    );
}

#[tokio::test]
async fn davx5_synchronizes_with_the_content_type_and_the_tag() {
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("REPORT", WORK).xml(&fixture("davx5-sync-collection.xml")))
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), [STANDUP]);
    let standup = &multi.responses[0];
    assert_eq!(
        standup.text(NS_DAV, "getcontenttype"),
        "text/calendar; charset=utf-8; component=vevent"
    );
    assert_eq!(
        standup.text(NS_DAV, "getetag"),
        davhaven_domain::ETag::from_bytes(STANDUP_ICS.as_bytes()).as_str()
    );
    assert!(multi.sync_token.unwrap().starts_with("urn:davhaven:sync:"));
}

#[tokio::test]
async fn davx5_fetches_what_changed_and_learns_what_is_gone() {
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("REPORT", WORK).xml(&fixture("davx5-multiget.xml")))
        .await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.response(STANDUP).text(NS_CALDAV, "calendar-data"),
        STANDUP_ICS,
        "the data is what the client wrote"
    );
    let gone = multi.response("/dav/calendars/acme/anna/work/deleted-meanwhile.ics");
    assert_eq!(gone.status, Some(404));
    assert_eq!(multi.responses.len(), 2);
}

#[tokio::test]
async fn thunderbird_queries_events_and_tasks_apart() {
    let dav = Dav::new();
    dav.put_event(&format!("{WORK}another.ics"), "another-1@acme.example", "Another")
        .await;
    let tasks = dav
        .send(Req::anna("PUT", &format!("{WORK}task.ics")).ics(&todo("task-1@acme.example", "Task")))
        .await;
    assert_eq!(tasks.status, StatusCode::CREATED, "{}", tasks.body);

    let events = dav
        .send(Req::anna("REPORT", WORK).xml(&fixture("thunderbird-calendar-query-events.xml")))
        .await;
    let multi = events.multistatus();
    assert_eq!(
        multi.hrefs(),
        ["/dav/calendars/acme/anna/work/another.ics", STANDUP],
        "events only, sorted by href"
    );
    assert_eq!(
        multi.response(STANDUP).text(NS_DAV, "getcontenttype"),
        "text/calendar; charset=utf-8; component=vevent"
    );

    let open_tasks = dav
        .send(Req::anna("REPORT", WORK).xml(&fixture("thunderbird-calendar-query-todos.xml")))
        .await;
    let multi = open_tasks.multistatus();
    assert_eq!(multi.hrefs(), ["/dav/calendars/acme/anna/work/task.ics"]);
    assert_eq!(
        multi.responses[0].text(NS_DAV, "getcontenttype"),
        "text/calendar; charset=utf-8; component=vtodo"
    );
}

#[tokio::test]
async fn evolution_reads_a_calendar_with_namespaces_declared_on_the_root() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&fixture("evolution-propfind-calendar.xml")),
        )
        .await;
    let multi = answer.multistatus();
    let work = &multi.responses[0];
    assert_eq!(work.text(NS_DAV, "displayname"), "Work");
    assert_eq!(work.children(NS_DAV, "resourcetype"), ["collection", "calendar"]);
    assert_eq!(work.hrefs_of(NS_DAV, "owner"), ["/dav/principals/acme/anna/"]);
    assert!(work.prop(NS_CALENDARSERVER, "getctag").is_some());
    assert_eq!(
        work.status_of(NS_DAV, "getcontenttype"),
        Some(404),
        "a collection has no content type"
    );
    assert_eq!(
        work.status_of(NS_APPLE_ICAL, "calendar-color"),
        Some(404),
        "no color was ever set"
    );
}

#[tokio::test]
async fn ios_asks_for_expanded_instances_and_gets_an_answer() {
    let dav = Dav::new();
    dav.put_event(&format!("{WORK}other.ics"), "other-1@acme.example", "Other")
        .await;
    let answer = dav
        .send(Req::anna("REPORT", WORK).xml(&fixture("ios-calendar-query-expand.xml")))
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.responses.len(), 2);
    let standup = multi.response(STANDUP);
    assert!(standup.text(NS_CALDAV, "calendar-data").contains("BEGIN:VEVENT"));
    assert_eq!(standup.status_of(NS_DAV, "getetag"), Some(200));
}
