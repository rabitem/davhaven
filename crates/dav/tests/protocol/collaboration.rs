//! The collaboration modules end to end (PLAN 2.9, 2.8): principal search, the media types and visibility rules of
//! `POST`, the limits of share and outbox requests, and `calendar-multiget` of the scheduling inbox.
//!
//! The fake application implements principals and calendars. It has no sharing and no scheduling
//! (`SharingService`, `SchedulingService`): where a test wants to know what the layer under test hands to them, it
//! swaps them for the recording double of `davhaven_app_fake::recorder`, which answers like a service with nothing
//! in it and keeps every call with its arguments. A test then says exactly what was read from the body and passed
//! on (the request, the owner of an outbox, the paths of a bulk read, the conditions of a deletion), and that a
//! request which must not get that far never did. What the real services answer is rendered by the unit tests of the
//! modules (the documents, the statuses of the items, the fixtures of the clients) and exercised against the real
//! application by `crates/it/tests/appcore/dav_collaboration.rs` (the flows of sharing and notifications, the inbox,
//! principal search over real data).

use axum::http::StatusCode;
use davhaven_dav::xml::Element;
use davhaven_domain::DavLimits;

use crate::support::{Dav, Multi, NS, NS_CALDAV, NS_CALENDARSERVER, NS_DAV, Req, User, WORK, propfind, repeat};

const ENTRY: &str = "/dav/";
const INBOX: &str = "/dav/calendars/acme/anna/inbox/";
const OUTBOX: &str = "/dav/calendars/acme/anna/outbox/";
const NOTIFICATIONS: &str = "/dav/calendars/acme/anna/notifications/";
const HOME: &str = "/dav/calendars/acme/anna/";

fn fixture(name: &str) -> String {
    davhaven_fixtures::dav::sharing(name).unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// The properties Apple Calendar asks for when it looks up attendees, plus one the server must not disclose.
const SEARCH_PROPS: [&str; 6] = [
    "D:displayname",
    "C:calendar-user-address-set",
    "C:calendar-user-type",
    "CS:email-address-set",
    "C:calendar-home-set",
    "CS:first-name",
];

fn selection(props: &[&str]) -> String {
    let elements = repeat(props.len(), |n| {
        format!("<{}/>", props.get(n).copied().unwrap_or_default())
    });
    format!("<D:prop>{elements}</D:prop>")
}

/// A `CS:calendarserver-principal-search` document.
fn token_search(attributes: &str, tokens: &[&str], limit: Option<u32>) -> String {
    let tokens = repeat(tokens.len(), |n| {
        format!(
            "<CS:search-token>{}</CS:search-token>",
            tokens.get(n).copied().unwrap_or_default()
        )
    });
    let limit = limit
        .map(|count| format!("<CS:limit><CS:nresults>{count}</CS:nresults></CS:limit>"))
        .unwrap_or_default();
    let select = selection(&SEARCH_PROPS);
    format!(
        "<CS:calendarserver-principal-search {NS} {attributes}>{tokens}{limit}{select}</CS:calendarserver-principal-search>"
    )
}

/// A `DAV:principal-property-search` document with one `property-search` per `(properties, match)` pair.
fn property_search(mode: &str, searches: &[(&[&str], &str)], match_type: &str) -> String {
    let searches = repeat(searches.len(), |n| {
        let (props, text) = searches.get(n).copied().unwrap_or_default();
        let select = selection(props);
        format!("<D:property-search>{select}<D:match match-type=\"{match_type}\">{text}</D:match></D:property-search>")
    });
    let select = selection(&["D:displayname", "C:calendar-user-address-set"]);
    format!("<D:principal-property-search {NS} test=\"{mode}\">{searches}{select}</D:principal-property-search>")
}

/// No principal at all.
fn nobody() -> Vec<String> {
    Vec::new()
}

async fn found(dav: &Dav, user: User, path: &str, body: &str) -> Vec<String> {
    let answer = dav.send(Req::new("REPORT", path).by(user).depth("0").xml(body)).await;
    let multi: Multi = answer.multistatus();
    multi.hrefs().into_iter().map(str::to_owned).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Principal search
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn apple_calendar_looks_up_attendees_while_the_user_types() {
    let dav = Dav::new();
    let body = token_search("context=\"attendee\"", &["baker"], Some(20));
    let answer = dav.send(Req::anna("REPORT", ENTRY).depth("0").xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), ["/dav/principals/acme/ben/"]);
    let ben = &multi.responses[0];
    assert_eq!(ben.text(NS_DAV, "displayname"), "Ben Baker");
    let addresses = ben.hrefs_of(NS_CALDAV, "calendar-user-address-set");
    assert!(
        addresses.contains(&"mailto:ben@acme.example".to_owned()),
        "{addresses:?}"
    );
    assert_eq!(ben.text(NS_CALDAV, "calendar-user-type"), "INDIVIDUAL");
    let emails: Vec<String> = ben
        .prop(NS_CALENDARSERVER, "email-address-set")
        .unwrap()
        .children_named(NS_CALENDARSERVER, "email-address")
        .map(Element::text)
        .collect();
    assert_eq!(emails, ["ben@acme.example"]);
    // A search tells the name and the addresses of a person and nothing about where their calendars are.
    assert_eq!(ben.status_of(NS_CALDAV, "calendar-home-set"), Some(404));
    assert_eq!(ben.status_of(NS_CALENDARSERVER, "first-name"), Some(404));
}

#[tokio::test]
async fn the_attendee_search_that_the_fixture_of_apple_calendar_sends_finds_the_person() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("REPORT", ENTRY)
                .depth("0")
                .xml(&fixture("principal-search-attendee.xml")),
        )
        .await;
    assert_eq!(answer.multistatus().hrefs(), ["/dav/principals/acme/ben/"]);
}

#[tokio::test]
async fn the_property_search_that_the_fixture_of_other_clients_sends_finds_the_people() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("REPORT", ENTRY)
                .depth("0")
                .xml(&fixture("principal-property-search-anyof.xml")),
        )
        .await;
    // `baker` is in a display name; `cara@` starts the e-mail address of a suspended user, and a search finds active
    // principals only (like the store the real application searches).
    assert_eq!(answer.multistatus().hrefs(), ["/dav/principals/acme/ben/"]);
}

#[tokio::test]
async fn a_search_text_of_one_character_finds_nothing_and_is_no_error() {
    let dav = Dav::new();
    for body in [
        token_search("", &["b"], None),
        token_search("", &[" a "], None),
        property_search("allof", &[(&["D:displayname"], "b")], "contains"),
    ] {
        let answer = dav.send(Req::anna("REPORT", ENTRY).depth("0").xml(&body)).await;
        assert!(answer.multistatus().responses.is_empty(), "{body}: {}", answer.body);
    }
}

#[tokio::test]
async fn a_search_text_that_no_name_or_address_can_contain_finds_nothing() {
    let dav = Dav::new();
    let long = "x".repeat(600);
    for body in [
        token_search("", &[&long], None),
        token_search("", &["ben", &long], None),
        property_search("anyof", &[(&["D:displayname"], &long)], "contains"),
    ] {
        let answer = dav.send(Req::anna("REPORT", ENTRY).depth("0").xml(&body)).await;
        assert!(answer.multistatus().responses.is_empty(), "{}", answer.body);
    }
}

#[tokio::test]
async fn a_search_sent_to_a_principal_may_ask_for_every_principal_collection() {
    let dav = Dav::new();
    let body = format!(
        "<D:principal-property-search {NS}><D:apply-to-principal-collection-set/>\
         <D:property-search><D:prop><D:displayname/></D:prop><D:match>baker</D:match></D:property-search>\
         <D:prop><D:displayname/></D:prop></D:principal-property-search>"
    );
    for path in [ENTRY, "/dav/principals/acme/anna/", "/dav/principals/acme/ben/"] {
        assert_eq!(
            found(&dav, User::Anna, path, &body).await,
            ["/dav/principals/acme/ben/"],
            "{path}"
        );
    }
}

#[tokio::test]
async fn a_search_sees_the_tenant_of_the_caller_and_no_other() {
    let dav = Dav::new();
    let globex = token_search("", &["globex"], None);
    assert_eq!(found(&dav, User::Anna, ENTRY, &globex).await, nobody());
    assert_eq!(
        found(&dav, User::Gina, ENTRY, &globex).await,
        ["/dav/principals/globex/gina/"]
    );
    let acme = token_search("", &["anna"], None);
    assert_eq!(found(&dav, User::Gina, ENTRY, &acme).await, nobody());
    assert_eq!(
        found(&dav, User::Ben, ENTRY, &acme).await,
        ["/dav/principals/acme/anna/"]
    );
}

#[tokio::test]
async fn context_and_type_say_which_kinds_of_principal_are_wanted() {
    let dav = Dav::new();
    for (attributes, token, expected) in [
        ("context=\"user\"", "team", Vec::<&str>::new()),
        ("context=\"group\"", "team", vec!["/dav/principals/acme/team/"]),
        ("context=\"resource\"", "room", vec!["/dav/principals/acme/room1/"]),
        ("context=\"location\"", "room", vec!["/dav/principals/acme/room1/"]),
        ("context=\"attendee\"", "room", vec!["/dav/principals/acme/room1/"]),
        (
            "context=\"attendee\" type=\"GROUP\"",
            "team",
            vec!["/dav/principals/acme/team/"],
        ),
        ("context=\"attendee\" type=\"INDIVIDUAL\"", "team", vec![]),
        ("context=\"nonsense\"", "team", vec![]),
    ] {
        let body = token_search(attributes, &[token], None);
        assert_eq!(
            found(&dav, User::Anna, ENTRY, &body).await,
            expected,
            "{attributes} {token}"
        );
    }
}

#[tokio::test]
async fn service_principals_are_nobody_to_invite_and_are_never_found() {
    let dav = Dav::new();
    for body in [
        token_search("context=\"attendee\"", &["robot"], None),
        property_search("allof", &[(&["D:displayname"], "robot")], "contains"),
    ] {
        assert!(found(&dav, User::Anna, ENTRY, &body).await.is_empty(), "{body}");
    }
}

#[tokio::test]
async fn every_token_has_to_match_and_the_limit_is_kept() {
    let dav = Dav::new();
    let both = token_search("", &["ben", "baker"], None);
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &both).await,
        ["/dav/principals/acme/ben/"]
    );
    let one_of_them_misses = token_search("", &["ben", "clark"], None);
    assert_eq!(found(&dav, User::Anna, ENTRY, &one_of_them_misses).await, nobody());

    // `acme` is in the address of everybody of the tenant; the answer is cut at the number asked for, in the order
    // of the hrefs, and says that it was cut: a 507 entry for the request URI.
    let everybody = token_search("", &["acme"], None);
    let all = found(&dav, User::Anna, ENTRY, &everybody).await;
    assert!(all.len() > 2, "{all:?}");
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(all, sorted, "the answer is ordered by href");
    let cut = |count: usize| {
        let mut hrefs = all.get(..count).unwrap().to_vec();
        hrefs.push(ENTRY.to_owned());
        hrefs
    };
    let two = token_search("", &["acme"], Some(2));
    assert_eq!(found(&dav, User::Anna, ENTRY, &two).await, cut(2));
    let zero = token_search("", &["acme"], Some(0));
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &zero).await,
        cut(1),
        "a limit of nothing is at least one"
    );
    let many = token_search("", &["acme"], Some(5000));
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &many).await,
        all,
        "nothing was cut, so nothing is said"
    );
}

#[tokio::test]
async fn a_token_that_is_too_short_to_look_up_still_has_to_match() {
    let dav = Dav::new();
    // A client that splits what the user types at the blanks sends "Anna B" as two tokens.
    let cases: [(&[&str], Vec<&str>); 6] = [
        (&["baker", "b"], vec!["/dav/principals/acme/ben/"]),
        (&["b", "baker"], vec!["/dav/principals/acme/ben/"]),
        (&["anna", "a"], vec!["/dav/principals/acme/anna/"]),
        (&["baker", "z"], vec![]),
        (&["b", "z"], vec![]),
        (&["b"], vec![]),
    ];
    for (tokens, expected) in cases {
        let body = token_search("", tokens, None);
        assert_eq!(found(&dav, User::Anna, ENTRY, &body).await, expected, "{tokens:?}");
    }
}

#[tokio::test]
async fn a_search_for_rooms_finds_them_in_a_tenant_where_more_than_fifty_people_match_the_text() {
    let dav = Dav::crowded();
    // The location picker of Apple Calendar: the kinds are applied by the application before it cuts its answer at
    // 50 hits, which here are all people.
    for attributes in [
        "context=\"location\"",
        "context=\"resource\"",
        "context=\"attendee\" type=\"ROOM\"",
        "context=\"attendee\" type=\"RESOURCE\"",
    ] {
        let body = token_search(attributes, &["ro"], None);
        assert_eq!(
            found(&dav, User::Anna, ENTRY, &body).await,
            ["/dav/principals/acme/room1/"],
            "{attributes}"
        );
    }
    let answer = found(
        &dav,
        User::Anna,
        ENTRY,
        &token_search("context=\"user\"", &["ro"], None),
    )
    .await;
    let (entry, people) = answer.split_last().unwrap();
    assert_eq!(
        entry, ENTRY,
        "the answer that was cut says so with an entry for the request URI"
    );
    assert_eq!(people.len(), 50, "the answer is cut at 50");
    assert!(people.iter().all(|href| href.contains("/rosa")), "{people:?}");
}

#[tokio::test]
async fn an_answer_that_was_cut_says_so_and_one_that_was_not_does_not() {
    let dav = Dav::crowded();
    let answer = dav
        .send(
            Req::anna("REPORT", ENTRY)
                .depth("0")
                .xml(&token_search("context=\"user\"", &["rosa"], None)),
        )
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.responses.len(), 51, "50 principals and the entry");
    let last = multi.responses.last().unwrap();
    assert_eq!((last.href.as_str(), last.status), (ENTRY, Some(507)));
    assert!(
        answer.body.contains("number-of-matches-within-limits"),
        "the precondition says why: {}",
        answer.body
    );
    // Sixty match, the client asked for twenty: cut as well, at the number it asked for.
    let twenty = dav
        .send(
            Req::anna("REPORT", ENTRY)
                .depth("0")
                .xml(&token_search("context=\"user\"", &["rosa"], Some(20))),
        )
        .await;
    assert_eq!(twenty.multistatus().responses.len(), 21);
    // A search that fits (or that finds exactly as many as it may return) is not cut.
    let exact = dav
        .send(
            Req::anna("REPORT", ENTRY)
                .depth("0")
                .xml(&token_search("context=\"user\"", &["abauer"], Some(1))),
        )
        .await;
    let multi = exact.multistatus();
    assert_eq!(multi.hrefs(), ["/dav/principals/acme/abauer/"]);
    assert!(multi.responses.iter().all(|response| response.status.is_none()));
}

#[tokio::test]
async fn every_token_has_to_match_whatever_the_application_cut_off_for_the_other_tokens() {
    let dav = Dav::crowded();
    // Sixty people are called Anna and one of them Anna Bauer: whatever the longest token finds is cut at 50 and
    // sorts Anna Bauer behind the crowd. Every token is a condition of the one search, applied before the cut, so
    // what Apple Calendar sends while the user types "Anna B", "Anna Bau" and "Anna Baue" finds her (the first
    // three lines are the cases an application that looked up one token and checked the others would miss).
    let cases: [&[&str]; 9] = [
        &["anna", "b"],
        &["anna", "bau"],
        &["anna", "baue"],
        &["anna", "bauer"],
        &["bauer", "anna"],
        &["Anna", "BAUER"],
        &["anna", "abauer@"],
        &["anna", "bauer", "a"],
        &["a", "bauer"],
    ];
    for tokens in cases {
        let body = token_search("", tokens, None);
        assert_eq!(
            found(&dav, User::Anna, ENTRY, &body).await,
            ["/dav/principals/acme/abauer/"],
            "{tokens:?}"
        );
    }
    let nobody_is_both = token_search("", &["anna", "clark"], None);
    assert_eq!(found(&dav, User::Anna, ENTRY, &nobody_is_both).await, nobody());
}

#[tokio::test]
async fn a_property_search_finds_its_principal_among_a_crowd_whatever_else_matches_the_first_text() {
    let dav = Dav::crowded();
    let both = property_search(
        "allof",
        &[
            (&["D:displayname"], "anna"),
            (&["CS:email-address-set"], "abauer@acme.example"),
        ],
        "contains",
    );
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &both).await,
        ["/dav/principals/acme/abauer/"]
    );
    // The text that is a prefix of the display name of everybody in the crowd does not cut the one who is wanted.
    let by_start = property_search(
        "allof",
        &[(&["D:displayname"], "anna b"), (&["D:displayname"], "bauer")],
        "starts-with",
    );
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &by_start).await,
        nobody(),
        "no name starts with `bauer`"
    );
    let by_both = property_search(
        "allof",
        &[(&["D:displayname"], "anna b"), (&["D:displayname"], "bauer")],
        "contains",
    );
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &by_both).await,
        ["/dav/principals/acme/abauer/"]
    );
    let either = property_search(
        "anyof",
        &[(&["D:displayname"], "bauer"), (&["CS:email-address-set"], "rosa59@")],
        "contains",
    );
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &either).await,
        ["/dav/principals/acme/abauer/", "/dav/principals/acme/rosa59/"]
    );
    // With every element required, a text that is too short to be looked up on its own is one more condition next to
    // a text that is long enough; an element that names nothing searchable can never be satisfied. In a union what
    // cannot match adds nothing.
    let short = property_search(
        "allof",
        &[(&["D:displayname"], "bauer"), (&["D:displayname"], "b")],
        "contains",
    );
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &short).await,
        ["/dav/principals/acme/abauer/"]
    );
    let all_short = property_search(
        "allof",
        &[(&["D:displayname"], "b"), (&["CS:email-address-set"], "a")],
        "contains",
    );
    assert_eq!(found(&dav, User::Anna, ENTRY, &all_short).await, nobody());
    let nothing_searchable = property_search(
        "allof",
        &[(&["D:displayname"], "bauer"), (&["CS:first-name"], "anna")],
        "contains",
    );
    assert_eq!(found(&dav, User::Anna, ENTRY, &nothing_searchable).await, nobody());
    let ignored = property_search(
        "anyof",
        &[
            (&["D:displayname"], "bauer"),
            (&["D:displayname"], "b"),
            (&["CS:first-name"], "anna"),
        ],
        "contains",
    );
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &ignored).await,
        ["/dav/principals/acme/abauer/"]
    );
}

#[tokio::test]
async fn the_derived_addresses_of_a_principal_are_not_searched() {
    // The principal URL and the `urn:uuid:` address are part of the address set a client is shown, but they are not
    // stored: no search finds a principal by them, however the text is compared.
    let dav = Dav::new();
    for (text, matching) in [
        ("principals", "contains"),
        ("urn:uuid:", "starts-with"),
        ("/dav/principals/acme/ben/", "equals"),
    ] {
        let body = property_search("allof", &[(&["C:calendar-user-address-set"], text)], matching);
        assert_eq!(found(&dav, User::Anna, ENTRY, &body).await, nobody(), "{text}");
        let token = token_search("", &[text], None);
        assert_eq!(found(&dav, User::Anna, ENTRY, &token).await, nobody(), "{text}");
    }
}

#[tokio::test]
async fn the_terms_of_a_search_are_limited_by_the_configuration() {
    let dav = Dav::configured(|limits| limits.dav.max_search_terms = 2);
    let ok = token_search("", &["ben", "baker"], None);
    assert_eq!(found(&dav, User::Anna, ENTRY, &ok).await, ["/dav/principals/acme/ben/"]);
    let too_many = token_search("", &["ben", "baker", "acme"], None);
    let answer = dav.send(Req::anna("REPORT", ENTRY).xml(&too_many)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    let property = property_search(
        "anyof",
        &[
            (&["D:displayname"], "ben"),
            (&["D:displayname"], "anna"),
            (&["D:displayname"], "cara"),
        ],
        "contains",
    );
    let answer = dav.send(Req::anna("REPORT", ENTRY).xml(&property)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_property_search_looks_into_the_properties_it_names() {
    let dav = Dav::new();
    let by_name = property_search("allof", &[(&["D:displayname"], "baker")], "contains");
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &by_name).await,
        ["/dav/principals/acme/ben/"]
    );
    // The name of a person is not one of their addresses.
    let name_in_addresses = property_search("allof", &[(&["C:calendar-user-address-set"], "baker")], "contains");
    assert_eq!(found(&dav, User::Anna, ENTRY, &name_in_addresses).await, nobody());
    let by_address = property_search(
        "allof",
        &[(&["C:calendar-user-address-set"], "mailto:ben@")],
        "starts-with",
    );
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &by_address).await,
        ["/dav/principals/acme/ben/"]
    );
    let by_email = property_search("allof", &[(&["CS:email-address-set"], "ben@acme.example")], "equals");
    assert_eq!(
        found(&dav, User::Anna, ENTRY, &by_email).await,
        ["/dav/principals/acme/ben/"]
    );
    // `equals` is the whole value.
    let partial = property_search("allof", &[(&["D:displayname"], "baker")], "equals");
    assert_eq!(found(&dav, User::Anna, ENTRY, &partial).await, nobody());
    // Properties nobody can search in match nothing.
    let unsearchable = property_search("allof", &[(&["CS:first-name"], "ben")], "contains");
    assert_eq!(found(&dav, User::Anna, ENTRY, &unsearchable).await, nobody());
}

#[tokio::test]
async fn allof_and_anyof_combine_the_property_searches() {
    let dav = Dav::new();
    let searches: [(&[&str], &str); 2] = [(&["D:displayname"], "ben"), (&["C:calendar-user-address-set"], "ben@")];
    assert_eq!(
        found(
            &dav,
            User::Anna,
            ENTRY,
            &property_search("allof", &searches, "contains")
        )
        .await,
        ["/dav/principals/acme/ben/"]
    );
    let disjoint: [(&[&str], &str); 2] = [(&["D:displayname"], "ben"), (&["D:displayname"], "anna")];
    assert_eq!(
        found(
            &dav,
            User::Anna,
            ENTRY,
            &property_search("allof", &disjoint, "contains")
        )
        .await,
        nobody()
    );
    assert_eq!(
        found(
            &dav,
            User::Anna,
            ENTRY,
            &property_search("anyof", &disjoint, "contains")
        )
        .await,
        ["/dav/principals/acme/anna/", "/dav/principals/acme/ben/"]
    );
}

#[tokio::test]
async fn the_searchable_properties_are_listed_for_clients() {
    let dav = Dav::new();
    let body = format!("<D:principal-search-property-set {NS}/>");
    for path in [ENTRY, "/dav/principals/acme/anna/"] {
        let answer = dav.send(Req::anna("REPORT", path).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::OK, "{path}: {}", answer.body);
        assert!(answer.header("content-type").starts_with("application/xml"));
        for name in ["displayname", "calendar-user-address-set", "email-address-set"] {
            assert!(answer.body.contains(name), "{name}: {}", answer.body);
        }
    }
}

#[tokio::test]
async fn searches_that_search_for_nothing_are_400_and_a_stranger_gets_no_hint() {
    let dav = Dav::new();
    let nothing = format!(
        "<CS:calendarserver-principal-search {NS}><D:prop><D:displayname/></D:prop></CS:calendarserver-principal-search>"
    );
    let not_a_number = token_search("", &["ben"], None).replace(
        "</CS:search-token>",
        "</CS:search-token><CS:limit><CS:nresults>many</CS:nresults></CS:limit>",
    );
    let no_text = format!(
        "<D:principal-property-search {NS}><D:property-search><D:prop><D:displayname/></D:prop></D:property-search></D:principal-property-search>"
    );
    for body in [nothing, not_a_number, no_text] {
        let answer = dav.send(Req::anna("REPORT", ENTRY).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(answer.body, "", "a 400 has no element");
    }
    // The principal of another tenant is not there, whatever the body says.
    let broken = format!("<CS:calendarserver-principal-search {NS}/>");
    let answer = dav
        .send(Req::anna("REPORT", "/dav/principals/globex/gina/").xml(&broken))
        .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    let anonymous = dav
        .send(Req::new("REPORT", ENTRY).xml(&token_search("", &["ben"], None)))
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn only_the_entry_point_and_principals_answer_searches() {
    let dav = Dav::new();
    let body = token_search("", &["ben"], None);
    for path in [WORK, HOME, INBOX, NOTIFICATIONS] {
        let answer = dav.send(Req::anna("REPORT", path).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(answer.precondition().as_deref(), Some("supported-report"), "{path}");
    }
}

#[tokio::test]
async fn the_entry_point_and_the_principals_advertise_the_search_reports_they_answer() {
    let dav = Dav::new();
    for (path, expected) in [
        (
            ENTRY,
            vec![
                "principal-property-search",
                "principal-search-property-set",
                "calendarserver-principal-search",
            ],
        ),
        (
            "/dav/principals/acme/anna/",
            vec![
                "expand-property",
                "principal-property-search",
                "principal-search-property-set",
                "calendarserver-principal-search",
            ],
        ),
    ] {
        let answer = dav
            .send(
                Req::anna("PROPFIND", path)
                    .depth("0")
                    .xml(&propfind(&["D:supported-report-set"])),
            )
            .await;
        let multi = answer.multistatus();
        let reports: Vec<String> = multi.responses[0]
            .prop(NS_DAV, "supported-report-set")
            .unwrap()
            .children_named(NS_DAV, "supported-report")
            .filter_map(|entry| entry.child(NS_DAV, "report"))
            .filter_map(|report| report.elements().next())
            .map(|element| element.local.clone())
            .collect();
        assert_eq!(reports, expected, "{path}");
    }
}

#[tokio::test]
async fn a_search_answers_for_every_depth_like_for_depth_zero() {
    // RFC 3744 defines the search reports for `Depth: 0` only; Davhaven answers every depth the same.
    let dav = Dav::new();
    let body = token_search("", &["baker"], None);
    for depth in [None, Some("0"), Some("1"), Some("infinity")] {
        let mut request = Req::anna("REPORT", ENTRY).xml(&body);
        if let Some(depth) = depth {
            request = request.depth(depth);
        }
        let answer = dav.send(request).await;
        assert_eq!(answer.multistatus().hrefs(), ["/dav/principals/acme/ben/"], "{depth:?}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// POST
// ---------------------------------------------------------------------------------------------------------------

const SHARE: &str = r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/"><CS:set><D:href>mailto:ben@acme.example</D:href><CS:read-write/></CS:set></CS:share>"#;
const REPLY: &str = r#"<CS:invite-reply xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/"><CS:invite-accepted/><CS:in-reply-to>7b2c4f10</CS:in-reply-to></CS:invite-reply>"#;

fn request_with_type(path: &str, user: User, media_type: Option<&str>, body: &str) -> Req {
    let request = Req::new("POST", path).by(user).bytes(body.as_bytes().to_vec());
    match media_type {
        Some(media_type) => request.header("content-type", media_type),
        None => request,
    }
}

#[tokio::test]
async fn a_post_that_a_web_page_could_have_sent_is_refused_for_every_resource() {
    let (dav, recorder) = Dav::recording();
    let simple = [
        None,
        Some("text/plain"),
        Some("text/plain; charset=utf-8"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=x"),
        Some("application/json"),
    ];
    // The collections and the home take XML, the outbox takes iCalendar; a media type of the other kind is no
    // better than a form. The refusal looks at the request alone, so a stranger gets the same answer.
    for user in [User::Anna, User::Ben] {
        for media_type in simple {
            for (path, body) in [
                (WORK, SHARE),
                (HOME, REPLY),
                (OUTBOX, "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"),
            ] {
                let answer = dav.send(request_with_type(path, user, media_type, body)).await;
                assert_eq!(
                    answer.status,
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "{user:?} {media_type:?} {path}"
                );
            }
        }
        for (path, wrong) in [
            (WORK, "text/calendar"),
            (HOME, "text/calendar"),
            (OUTBOX, "application/xml"),
            (OUTBOX, "text/xml"),
        ] {
            let answer = dav.send(request_with_type(path, user, Some(wrong), "x")).await;
            assert_eq!(
                answer.status,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{user:?} {wrong} {path}"
            );
        }
    }
    let answer = dav
        .send(request_with_type(WORK, User::Anna, Some("text/plain"), SHARE))
        .await;
    assert_eq!(answer.body, "", "a 415 has no element");
    assert!(
        recorder.calls().is_empty(),
        "no request of a web page reached the service: {:?}",
        recorder.calls()
    );
    for (count, xml) in [
        "application/xml",
        "text/xml; charset=utf-8",
        "application/davsharing+xml",
    ]
    .into_iter()
    .enumerate()
    {
        let answer = dav.send(request_with_type(WORK, User::Anna, Some(xml), SHARE)).await;
        assert_eq!(answer.status, StatusCode::OK, "{xml}: {}", answer.body);
        assert_eq!(recorder.calls().len(), count + 1, "{xml}");
    }
}

#[tokio::test]
async fn a_post_of_an_anonymous_caller_is_a_401_before_anything_else() {
    let dav = Dav::new();
    let answer = dav.send(Req::new("POST", WORK).xml(SHARE)).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert!(answer.header("www-authenticate").starts_with("Basic realm="));
}

#[tokio::test]
async fn a_request_that_cannot_be_read_is_a_400_for_the_owner_and_a_404_for_a_stranger() {
    let (dav, recorder) = Dav::recording();
    let wrap = |inner: &str| {
        format!(r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">{inner}</CS:share>"#)
    };
    let laughs = r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><CS:share xmlns:CS="http://calendarserver.org/ns/">&lol;</CS:share>"#;
    let bodies = [
        "<CS:share".to_owned(),
        laughs.to_owned(),
        wrap(""),
        wrap("<CS:set><D:href>mailto:ben@acme.example</D:href></CS:set>"),
        wrap("<CS:set><D:href>mailto:ben@acme.example</D:href><CS:read/><CS:read-write/></CS:set>"),
        wrap("<CS:set><D:href>not an address</D:href><CS:read/></CS:set>"),
        wrap("<CS:remove/>"),
        // The same sharee twice: what such a body means would depend on the order of its parts.
        wrap(
            "<CS:remove><D:href>mailto:ben@acme.example</D:href></CS:remove>\
             <CS:set><D:href>mailto:Ben@Acme.example</D:href><CS:read/></CS:set>",
        ),
        REPLY.to_owned(),
    ];
    for body in &bodies {
        let owner = dav.send(Req::anna("POST", WORK).xml(body)).await;
        assert_eq!(owner.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(owner.body, "", "a 400 has no element");
        let stranger = dav.send(Req::new("POST", WORK).by(User::Ben).xml(body)).await;
        assert_eq!(
            stranger.status,
            StatusCode::NOT_FOUND,
            "{body}: a refusal must not say that the calendar exists"
        );
        let other_tenant = dav.send(Req::new("POST", WORK).by(User::Gina).xml(body)).await;
        assert_eq!(other_tenant.status, StatusCode::NOT_FOUND, "{body}");
    }
    let replies = [
        "<CS:invite-reply".to_owned(),
        r#"<CS:invite-reply xmlns:CS="http://calendarserver.org/ns/"><CS:invite-accepted/><CS:invite-declined/><CS:in-reply-to>x</CS:in-reply-to></CS:invite-reply>"#.to_owned(),
        r#"<CS:invite-reply xmlns:CS="http://calendarserver.org/ns/"><CS:invite-accepted/></CS:invite-reply>"#.to_owned(),
        SHARE.to_owned(),
    ];
    for body in &replies {
        let owner = dav.send(Req::anna("POST", HOME).xml(body)).await;
        assert_eq!(owner.status, StatusCode::BAD_REQUEST, "{body}");
        let stranger = dav.send(Req::new("POST", HOME).by(User::Ben).xml(body)).await;
        assert_eq!(stranger.status, StatusCode::NOT_FOUND, "{body}");
    }
    assert!(
        recorder.calls().is_empty(),
        "what cannot be read is never handed on: {:?}",
        recorder.calls()
    );
}

#[tokio::test]
async fn what_is_well_formed_is_handed_to_the_services() {
    use davhaven_app::services::{InviteReply, ShareRequest, ShareeSet};
    use davhaven_app_fake::recorder::Handed;
    use davhaven_domain::{CalendarUserAddress, GrantAccess, PrincipalName, ResourcePath, Uid};

    let (dav, recorder) = Dav::recording();
    let address = |text: &str| CalendarUserAddress::parse(text).unwrap();
    let work = ResourcePath::parse(WORK).unwrap();
    let home = ResourcePath::parse(HOME).unwrap();
    let sharee = |text: &str, name: Option<&str>, summary: Option<&str>, access| ShareeSet {
        address: address(text),
        common_name: name.map(str::to_owned),
        summary: summary.map(str::to_owned),
        access,
    };
    let share_of = |set: Vec<ShareeSet>, remove: Vec<&str>| ShareRequest {
        set,
        remove: remove.into_iter().map(address).collect(),
    };
    let ben = "mailto:ben@acme.example";
    for (document, expected) in [
        (
            SHARE.to_owned(),
            share_of(vec![sharee(ben, None, None, GrantAccess::ReadWrite)], vec![]),
        ),
        (
            fixture("share-set-read-write.xml"),
            share_of(
                vec![sharee(ben, Some("Ben Baker"), Some("Work"), GrantAccess::ReadWrite)],
                vec![],
            ),
        ),
        (
            fixture("share-set-read.xml"),
            share_of(vec![sharee(ben, None, None, GrantAccess::Read)], vec![]),
        ),
        (fixture("share-remove.xml"), share_of(vec![], vec![ben])),
        (
            fixture("share-set-and-remove.xml"),
            share_of(
                vec![
                    sharee(ben, None, Some("Work"), GrantAccess::ReadWrite),
                    sharee("mailto:guest@elsewhere.example", None, None, GrantAccess::Read),
                ],
                vec!["mailto:cara@acme.example"],
            ),
        ),
    ] {
        recorder.clear();
        let answer = dav.send(Req::anna("POST", WORK).xml(&document)).await;
        assert_eq!(answer.status, StatusCode::OK, "{document}: {}", answer.body);
        assert_eq!(
            recorder.calls(),
            [Handed::Share {
                collection: work.clone(),
                request: expected
            }],
            "{document}"
        );
    }

    let uid = |text: &str| Uid::parse(text).unwrap();
    let reply_of = |in_reply_to: &str, accepted, host: Option<&str>, summary: Option<&str>| InviteReply {
        in_reply_to: uid(in_reply_to),
        accepted,
        host_url: host.map(|path| ResourcePath::parse(path).unwrap()),
        summary: summary.map(str::to_owned),
    };
    for (document, expected) in [
        (REPLY.to_owned(), reply_of("7b2c4f10", true, None, None)),
        (
            fixture("invite-reply-accepted.xml"),
            reply_of("7b2c4f10-4d2e-4f55-9a3e-0d3b2a6c1e11", true, Some(WORK), Some("Work")),
        ),
        (
            fixture("invite-reply-declined.xml"),
            reply_of("7b2c4f10-4d2e-4f55-9a3e-0d3b2a6c1e11", false, Some(WORK), None),
        ),
    ] {
        recorder.clear();
        let answer = dav.send(Req::anna("POST", HOME).xml(&document)).await;
        assert_eq!(answer.status, StatusCode::OK, "{document}: {}", answer.body);
        assert_eq!(
            recorder.calls(),
            [Handed::ReplyInvite {
                home: home.clone(),
                reply: expected
            }],
            "{document}"
        );
    }

    recorder.clear();
    let message = fixture("outbox-freebusy-request.ics");
    let outbox = dav.send(Req::anna("POST", OUTBOX).ics(&message)).await;
    assert_eq!(outbox.status, StatusCode::OK, "{}", outbox.body);
    assert_eq!(
        recorder.calls(),
        [Handed::OutboxPost {
            owner: PrincipalName::parse("anna").unwrap(),
            body: message
        }],
        "the owner and the message byte for byte"
    );
}

#[tokio::test]
async fn the_host_of_an_invitation_is_a_note_of_this_server_or_nothing() {
    use davhaven_app_fake::recorder::Handed;

    let (dav, recorder) = Dav::recording();
    // The path names a resource here, the host is somebody else's: not a resource of this server.
    let foreign = fixture("invite-reply-accepted.xml").replace(
        "<D:href xmlns:D=\"DAV:\">/dav/calendars/acme/anna/work/</D:href>",
        "<D:href xmlns:D=\"DAV:\">https://attacker.example/dav/calendars/acme/anna/work/</D:href>",
    );
    assert!(foreign.contains("attacker.example"));
    let answer = dav.send(Req::anna("POST", HOME).xml(&foreign)).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let Some(Handed::ReplyInvite { reply, .. }) = recorder.calls().pop() else {
        panic!("{:?}", recorder.calls());
    };
    assert_eq!(reply.host_url, None);
    // The origin of this server is.
    recorder.clear();
    let own = foreign.replace("https://attacker.example", "https://cal.example.test");
    let answer = dav.send(Req::anna("POST", HOME).xml(&own)).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let Some(Handed::ReplyInvite { reply, .. }) = recorder.calls().pop() else {
        panic!("{:?}", recorder.calls());
    };
    assert_eq!(
        reply.host_url.map(|path| path.format()).as_deref(),
        Some("/dav/calendars/acme/anna/work/")
    );
}

#[tokio::test]
async fn the_outbox_of_somebody_else_is_not_there_whatever_the_message_and_whoever_asks() {
    use davhaven_app_fake::recorder::Handed;

    let (dav, recorder) = Dav::recording();
    let message = fixture("outbox-freebusy-request.ics");
    let own = dav.send(Req::anna("POST", OUTBOX).ics(&message)).await;
    assert_eq!(
        own.status,
        StatusCode::OK,
        "the owner's request is handed on: {}",
        own.body
    );
    assert_eq!(recorder.calls().len(), 1);
    recorder.clear();
    // The service is handed the name of the owner, which says nothing about the tenant of the path: the tenant, the
    // owner and the existence of the outbox are judged before it is asked. Every answer is the same 404.
    for (user, path) in [
        (User::Anna, "/dav/calendars/globex/anna/outbox/"),
        (User::Ben, OUTBOX),
        (User::Gina, OUTBOX),
        (User::Gina, "/dav/calendars/globex/anna/outbox/"),
        (User::Gina, "/dav/calendars/acme/gina/outbox/"),
        (User::Ben, "/dav/calendars/acme/nobody/outbox/"),
    ] {
        let answer = dav.send(Req::new("POST", path).by(user).ics(&message)).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{user:?} {path}");
        assert_eq!(answer.body, "", "{user:?} {path}");
    }
    assert!(
        recorder
            .calls()
            .iter()
            .all(|call| !matches!(call, Handed::OutboxPost { .. })),
        "no stranger's message reached the service: {:?}",
        recorder.calls()
    );
}

#[tokio::test]
async fn one_share_request_names_at_most_as_many_sharees_as_the_limit_for_sharees_allows() {
    use davhaven_app_fake::recorder::Handed;

    let (dav, recorder) = Dav::recording();
    let most = usize::try_from(DavLimits::default().max_sharees_per_request).unwrap();
    assert!(
        most < usize::try_from(DavLimits::default().max_multiget_hrefs).unwrap(),
        "the limit of its own is not the one of a multiget"
    );
    let request = |count: usize| {
        let sharees = repeat(count, |n| {
            format!("<CS:set><D:href>mailto:user{n}@acme.example</D:href><CS:read/></CS:set>")
        });
        format!(r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">{sharees}</CS:share>"#)
    };
    let answer = dav.send(Req::anna("POST", WORK).xml(&request(most))).await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "the limit itself is allowed: {}",
        answer.body
    );
    assert_eq!(recorder.calls().len(), 1);
    recorder.clear();
    let answer = dav.send(Req::anna("POST", WORK).xml(&request(most + 1))).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(
        answer.precondition().as_deref(),
        Some("number-of-matches-within-limits")
    );
    // The refusal is judged after the visibility of the collection: a stranger is told nothing.
    for stranger in [User::Ben, User::Gina] {
        let answer = dav
            .send(Req::new("POST", WORK).by(stranger).xml(&request(most + 1)))
            .await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{stranger:?}");
    }
    // Sharees to set and to remove count together.
    let mixed = format!(
        r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">{}{}</CS:share>"#,
        repeat(most, |n| format!(
            "<CS:set><D:href>mailto:set{n}@acme.example</D:href><CS:read/></CS:set>"
        )),
        "<CS:remove><D:href>mailto:gone@acme.example</D:href></CS:remove>"
    );
    let answer = dav.send(Req::anna("POST", WORK).xml(&mixed)).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert!(
        recorder
            .calls()
            .iter()
            .all(|call| !matches!(call, Handed::Share { .. })),
        "a request over the limit never reached the service"
    );
}

#[tokio::test]
async fn the_limit_for_sharees_is_the_configured_one() {
    let (dav, recorder) = Dav::recording_configured(|limits| {
        limits.dav.max_sharees_per_request = 2;
        limits.dav.max_multiget_hrefs = 1_000;
    });
    let request = |count: usize| {
        let sharees = repeat(count, |n| {
            format!("<CS:set><D:href>mailto:user{n}@acme.example</D:href><CS:read/></CS:set>")
        });
        format!(r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">{sharees}</CS:share>"#)
    };
    assert_eq!(
        dav.send(Req::anna("POST", WORK).xml(&request(2))).await.status,
        StatusCode::OK
    );
    assert_eq!(
        dav.send(Req::anna("POST", WORK).xml(&request(3))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(recorder.calls().len(), 1);
}

#[tokio::test]
async fn a_scheduling_message_is_bounded_and_must_be_text() {
    use davhaven_app_fake::recorder::Handed;

    let (dav, recorder) = Dav::recording();
    let max = usize::try_from(davhaven_domain::IcalLimits::default().max_resource_size).unwrap();
    let message = |size: usize| {
        let head = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\nCOMMENT:";
        let tail = "\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
        let filler = size.saturating_sub(head.len() + tail.len());
        format!("{head}{}{tail}", "x".repeat(filler))
    };
    let at_the_limit = message(max);
    assert_eq!(at_the_limit.len(), max);
    let answer = dav.send(Req::anna("POST", OUTBOX).ics(&at_the_limit)).await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "a message of the largest size is read and handed on: {}",
        answer.body
    );
    assert!(
        matches!(recorder.calls().as_slice(), [Handed::OutboxPost { body, .. }] if *body == at_the_limit),
        "the service got the whole message"
    );
    recorder.clear();

    let too_large = message(max + 1);
    let answer = dav.send(Req::anna("POST", OUTBOX).ics(&too_large)).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.precondition().as_deref(), Some("max-resource-size"));
    let stranger = dav.send(Req::new("POST", OUTBOX).by(User::Ben).ics(&too_large)).await;
    assert_eq!(
        stranger.status,
        StatusCode::NOT_FOUND,
        "the outbox of somebody else is not there"
    );

    let not_text = Req::anna("POST", OUTBOX)
        .header("content-type", "text/calendar; charset=utf-8")
        .bytes(vec![0xff, 0xfe, b'B', b'E', b'G', b'I', b'N']);
    let answer = dav.send(not_text).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.precondition().as_deref(), Some("valid-scheduling-message"));
    assert!(recorder.calls().is_empty(), "none of the three reached the service");
}

#[tokio::test]
async fn bodies_of_a_post_that_are_hostile_xml_are_refused_before_anything_is_expanded() {
    let dav = Dav::new();
    let deep = format!(
        "{}{}",
        "<CS:a xmlns:CS=\"http://calendarserver.org/ns/\">".repeat(33),
        "</CS:a>".repeat(33)
    );
    let many_namespaces = {
        let namespaces = repeat(65, |n| format!(" xmlns:n{n}=\"urn:{n}\""));
        format!("<CS:share xmlns:CS=\"http://calendarserver.org/ns/\"{namespaces}/>")
    };
    let too_large = format!(
        "<CS:share xmlns:CS=\"http://calendarserver.org/ns/\"><!--{}--></CS:share>",
        "x".repeat(300 * 1024)
    );
    for (what, body, status) in [
        ("deep", deep, StatusCode::BAD_REQUEST),
        ("namespaces", many_namespaces, StatusCode::BAD_REQUEST),
        ("large", too_large, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        for path in [WORK, HOME] {
            let answer = dav.send(Req::anna("POST", path).xml(&body)).await;
            assert_eq!(answer.status, status, "{what} {path}");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The notification collection
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn apple_calendar_asks_the_notification_collection_what_it_holds() {
    use davhaven_app_fake::recorder::Handed;
    use davhaven_domain::PrincipalName;

    let (dav, recorder) = Dav::recording();
    let body = fixture("propfind-notifications.xml");
    let answer = dav
        .send(Req::anna("PROPFIND", NOTIFICATIONS).depth("0").xml(&body))
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), [NOTIFICATIONS]);
    let collection = &multi.responses[0];
    assert_eq!(
        collection.children(NS_DAV, "resourcetype"),
        ["collection", "notification"]
    );
    // The collection itself has no entity tag, no media type and no notification type: those are the members'.
    for (namespace, local) in [
        (NS_DAV, "getetag"),
        (NS_DAV, "getcontenttype"),
        (NS_CALENDARSERVER, "notificationtype"),
    ] {
        assert_eq!(collection.status_of(namespace, local), Some(404), "{local}");
    }
    assert!(
        recorder.calls().is_empty(),
        "the collection alone asks nothing of the service"
    );
    // Its members belong to the sharing service, asked with the name of the owner once the collection is resolved.
    let members = dav
        .send(Req::anna("PROPFIND", NOTIFICATIONS).depth("1").xml(&body))
        .await;
    assert_eq!(members.multistatus().hrefs(), [NOTIFICATIONS]);
    assert_eq!(
        recorder.calls(),
        [Handed::ListNotifications(PrincipalName::parse("anna").unwrap())]
    );
    recorder.clear();
    for stranger in [User::Ben, User::Gina] {
        let answer = dav
            .send(Req::new("PROPFIND", NOTIFICATIONS).by(stranger).depth("1").xml(&body))
            .await;
        assert_eq!(
            answer.status,
            StatusCode::NOT_FOUND,
            "{stranger:?} does not see the notifications of Anna"
        );
    }
    assert!(
        recorder.calls().is_empty(),
        "a stranger's request never reached the service"
    );
}

#[tokio::test]
async fn the_collections_of_anna_are_not_there_for_anna_under_the_slug_of_another_tenant() {
    // Anna is a principal of `acme`. The services that take the name of the home owner alone (the notifications, the
    // inbox, the outbox) would find her for the path of `globex` as well; the tenant of the path is judged before.
    let (dav, recorder) = Dav::recording();
    let notifications = "/dav/calendars/globex/anna/notifications/";
    let inbox = "/dav/calendars/globex/anna/inbox/";
    let body = fixture("propfind-notifications.xml");
    let multiget = fixture("inbox-multiget.xml").replace("/acme/", "/globex/");
    for (method, path, depth, xml) in [
        ("PROPFIND", notifications, "1", body.clone()),
        ("PROPFIND", notifications, "0", body.clone()),
        ("REPORT", notifications, "0", fixture("sync-notifications.xml")),
        ("PROPFIND", inbox, "1", body.clone()),
        ("PROPFIND", inbox, "0", body.clone()),
        ("REPORT", inbox, "0", fixture("sync-notifications.xml")),
        ("REPORT", inbox, "1", multiget.clone()),
    ] {
        let answer = dav.send(Req::anna(method, path).depth(depth).xml(&xml)).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{method} {path} {depth}");
    }
    assert!(
        recorder.calls().is_empty(),
        "nothing reached the service: {:?}",
        recorder.calls()
    );
}

#[tokio::test]
async fn a_delete_of_a_notification_hands_its_conditions_to_the_service() {
    use davhaven_app::services::{IfMatch, WritePrecondition};
    use davhaven_app_fake::recorder::Handed;
    use davhaven_domain::{ETag, ResourcePath};

    let (dav, recorder) = Dav::recording();
    let path = "/dav/calendars/acme/anna/notifications/n1.xml";
    let target = ResourcePath::parse(path).unwrap();
    let etag = ETag::from_bytes(b"<notification/>");
    let answer = dav.send(Req::anna("DELETE", path)).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    let answer = dav
        .send(Req::anna("DELETE", path).header("if-match", etag.as_str()))
        .await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    let answer = dav.send(Req::anna("DELETE", path).header("if-match", "*")).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    assert_eq!(
        recorder.calls(),
        [
            Handed::DeleteNotification {
                path: target.clone(),
                conditions: WritePrecondition::none()
            },
            Handed::DeleteNotification {
                path: target.clone(),
                conditions: WritePrecondition::if_match(etag)
            },
            Handed::DeleteNotification {
                path: target,
                conditions: WritePrecondition {
                    if_match: Some(IfMatch::Any),
                    ..WritePrecondition::none()
                }
            },
        ],
        "the conditions are the service's to judge, in the transaction that deletes: no read comes first"
    );
}

#[tokio::test]
async fn the_synchronization_of_apple_calendar_reads_only_what_changed_and_for_the_owner_only() {
    let (dav, recorder) = Dav::recording();
    let body = fixture("sync-notifications.xml");
    let owner = dav.send(Req::anna("REPORT", NOTIFICATIONS).xml(&body)).await;
    assert_eq!(owner.status, StatusCode::MULTI_STATUS, "{}", owner.body);
    assert!(
        recorder.calls().is_empty(),
        "nothing changed, so nothing is read: {:?}",
        recorder.calls()
    );
    let stranger = dav
        .send(Req::new("REPORT", NOTIFICATIONS).by(User::Ben).xml(&body))
        .await;
    assert_eq!(stranger.status, StatusCode::NOT_FOUND);
    assert!(
        recorder.calls().is_empty(),
        "a stranger's request never reached the service"
    );
}

#[tokio::test]
async fn the_items_of_the_notification_collection_and_of_the_inbox_take_no_writes() {
    let dav = Dav::new();
    for path in [
        "/dav/calendars/acme/anna/notifications/n1.xml",
        "/dav/calendars/acme/anna/inbox/request-1.ics",
    ] {
        for method in [
            "PUT",
            "POST",
            "MOVE",
            "COPY",
            "PROPPATCH",
            "MKCOL",
            "MKCALENDAR",
            "REPORT",
        ] {
            let answer = dav
                .send(Req::anna(method, path).header("destination", "/dav/calendars/acme/anna/work/x.ics"))
                .await;
            assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
            assert_eq!(
                answer.header("allow"),
                "OPTIONS, GET, HEAD, PROPFIND, DELETE",
                "{method} {path}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The scheduling inbox
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_multiget_of_the_inbox_answers_404_for_what_is_no_item_of_it() {
    let dav = Dav::new();
    // The multiget of the fixture without the item of Anna's own inbox, which would be handed to the services.
    let body =
        fixture("inbox-multiget.xml").replace("  <A:href>/dav/calendars/acme/anna/inbox/request-1.ics</A:href>\n", "");
    let answer = dav.send(Req::anna("REPORT", INBOX).depth("1").xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.hrefs(),
        [
            "/dav/calendars/acme/anna/work/standup.ics",
            "/dav/calendars/acme/ben/inbox/request-1.ics",
            "/somewhere/else.ics"
        ],
        "sorted like every multistatus"
    );
    for response in &multi.responses {
        assert_eq!(response.status, Some(404), "{}", response.href);
    }
}

#[tokio::test]
async fn the_multiget_of_the_inbox_hands_its_own_items_to_the_services() {
    use davhaven_app::services::CalendarDataSpec;
    use davhaven_app_fake::recorder::Handed;
    use davhaven_domain::ResourcePath;

    let (dav, recorder) = Dav::recording();
    let item = ResourcePath::parse("/dav/calendars/acme/anna/inbox/request-1.ics").unwrap();
    let inbox = ResourcePath::parse(INBOX).unwrap();
    let body = format!(
        "<C:calendar-multiget {NS}><D:prop><D:getetag/><C:calendar-data/></D:prop><D:href>{}</D:href></C:calendar-multiget>",
        item.format()
    );
    let answer = dav.send(Req::anna("REPORT", INBOX).depth("1").xml(&body)).await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS, "{}", answer.body);
    assert_eq!(
        recorder.calls(),
        [Handed::InboxGetMany {
            inbox: inbox.clone(),
            paths: vec![item.clone()],
            spec: CalendarDataSpec::default()
        }],
        "one bulk read of the item, with the data the request asks for"
    );
    recorder.clear();
    // The fixture names an item of the inbox as well, and three things that are none of its items: only the item is
    // read.
    let answer = dav
        .send(
            Req::anna("REPORT", INBOX)
                .depth("1")
                .xml(&fixture("inbox-multiget.xml")),
        )
        .await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS, "{}", answer.body);
    assert_eq!(
        recorder.calls(),
        [Handed::InboxGetMany {
            inbox,
            paths: vec![item],
            spec: CalendarDataSpec::default()
        }]
    );
    // A multiget that asks for the entity tags alone reads no message.
    recorder.clear();
    let etags = "<C:calendar-multiget ".to_owned()
        + NS
        + "><D:prop><D:getetag/></D:prop><D:href>/dav/calendars/acme/anna/inbox/request-1.ics</D:href></C:calendar-multiget>";
    let answer = dav.send(Req::anna("REPORT", INBOX).depth("1").xml(&etags)).await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS, "{}", answer.body);
    assert!(
        matches!(recorder.calls().as_slice(), [Handed::InboxGetMany { spec, .. }] if *spec == CalendarDataSpec::metadata_only()),
        "{:?}",
        recorder.calls()
    );
}

#[tokio::test]
async fn the_listing_of_the_inbox_reads_no_message_for_the_size_or_for_propname() {
    use davhaven_app_fake::recorder::Handed;
    use davhaven_domain::PrincipalName;

    let (dav, recorder) = Dav::recording();
    for body in [
        propfind(&["D:getetag", "D:getcontentlength"]),
        propfind(&["D:getcontentlength", "D:current-user-privilege-set"]),
        format!("<D:propfind {NS}><D:propname/></D:propfind>"),
        String::new(),
    ] {
        recorder.clear();
        let answer = dav.send(Req::anna("PROPFIND", INBOX).depth("1").xml(&body)).await;
        assert_eq!(answer.status, StatusCode::MULTI_STATUS, "{body}: {}", answer.body);
        assert_eq!(
            recorder.calls(),
            [Handed::InboxList(PrincipalName::parse("anna").unwrap())],
            "the listing has everything these ask for: {body}"
        );
    }
}

#[tokio::test]
async fn the_inbox_of_somebody_else_is_not_there_for_a_multiget() {
    let dav = Dav::new();
    for user in [User::Ben, User::Gina] {
        let answer = dav
            .send(
                Req::new("REPORT", INBOX)
                    .by(user)
                    .depth("1")
                    .xml(&fixture("inbox-multiget.xml")),
            )
            .await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{user:?}");
    }
}

#[tokio::test]
async fn a_multiget_names_at_most_as_many_hrefs_as_the_limit_allows() {
    let dav = Dav::new();
    let most = usize::try_from(DavLimits::default().max_multiget_hrefs).unwrap();
    let request = |count: usize| {
        let hrefs = repeat(count, |n| {
            format!("<D:href>/dav/calendars/acme/anna/inbox/item-{n}.ics</D:href>")
        });
        format!("<C:calendar-multiget {NS}><D:prop><D:getetag/></D:prop>{hrefs}</C:calendar-multiget>")
    };
    let answer = dav
        .send(Req::anna("REPORT", INBOX).depth("1").xml(&request(most + 1)))
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(
        answer.precondition().as_deref(),
        Some("number-of-matches-within-limits")
    );
    // Like every refusal of a body, the refusal says nothing to a caller who cannot see the inbox: the visibility
    // of the inbox comes before the body is judged.
    let malformed =
        format!("<C:calendar-multiget {NS}><D:prop><D:getetag/></D:prop><D:propname/></C:calendar-multiget>");
    let owner = dav.send(Req::anna("REPORT", INBOX).depth("1").xml(&malformed)).await;
    assert_eq!(owner.status, StatusCode::BAD_REQUEST);
    for stranger in [User::Ben, User::Gina] {
        for body in [request(most + 1), malformed.clone()] {
            let answer = dav
                .send(Req::new("REPORT", INBOX).by(stranger).depth("1").xml(&body))
                .await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{stranger:?}");
        }
    }
}

#[tokio::test]
async fn the_inbox_supports_multiget_and_sync_the_notifications_only_sync() {
    let dav = Dav::new();
    let report_names = |path: &'static str| {
        let dav = &dav;
        async move {
            let answer = dav
                .send(
                    Req::anna("PROPFIND", path)
                        .depth("0")
                        .xml(&propfind(&["D:supported-report-set"])),
                )
                .await;
            let multi = answer.multistatus();
            multi.responses[0]
                .prop(NS_DAV, "supported-report-set")
                .unwrap()
                .children_named(NS_DAV, "supported-report")
                .filter_map(|entry| entry.child(NS_DAV, "report"))
                .filter_map(|report| report.elements().next())
                .map(|element| element.local.clone())
                .collect::<Vec<String>>()
        }
    };
    assert_eq!(report_names(INBOX).await, ["sync-collection", "calendar-multiget"]);
    assert_eq!(report_names(NOTIFICATIONS).await, ["sync-collection"]);
    assert_eq!(report_names(OUTBOX).await, nobody());
    let body = format!("<C:calendar-multiget {NS}><D:prop><D:getetag/></D:prop></C:calendar-multiget>");
    let answer = dav.send(Req::anna("REPORT", NOTIFICATIONS).depth("1").xml(&body)).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.precondition().as_deref(), Some("supported-report"));
}

// ---------------------------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------------------------

mod model {
    //! Arbitrary requests: whatever a client sends is read or refused, never a panic, and what is valid reads back as
    //! it was written.

    use axum::http::StatusCode;
    use davhaven_dav::principals_search::{parse_property_search, parse_token_search};
    use std::collections::BTreeMap;

    use davhaven_dav::sharing::{parse_invite_reply, parse_share, share_document, share_response};
    use davhaven_dav::xml::parse;
    use davhaven_domain::{CalendarUserAddress, DavLimits, GrantAccess};
    use proptest::prelude::*;

    fn markup_piece() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("<CS:share xmlns:CS=\"http://calendarserver.org/ns/\" xmlns:D=\"DAV:\">".to_owned()),
            Just("</CS:share>".to_owned()),
            Just("<CS:set>".to_owned()),
            Just("</CS:set>".to_owned()),
            Just("<CS:remove>".to_owned()),
            Just("</CS:remove>".to_owned()),
            Just("<CS:read/>".to_owned()),
            Just("<CS:read-write/>".to_owned()),
            Just("<CS:invite-reply xmlns:CS=\"http://calendarserver.org/ns/\">".to_owned()),
            Just("<CS:invite-accepted/>".to_owned()),
            Just("<CS:in-reply-to>x</CS:in-reply-to>".to_owned()),
            Just("<D:principal-property-search xmlns:D=\"DAV:\" test=\"anyof\">".to_owned()),
            Just("<D:property-search>".to_owned()),
            Just("<D:prop><D:displayname/></D:prop>".to_owned()),
            Just("<D:match match-type=\"starts-with\">ben</D:match>".to_owned()),
            Just(
                "<CS:calendarserver-principal-search xmlns:CS=\"http://calendarserver.org/ns/\" context=\"user\">"
                    .to_owned()
            ),
            Just("<CS:search-token>ben</CS:search-token>".to_owned()),
            Just("<CS:nresults>3</CS:nresults>".to_owned()),
            Just("<D:href>mailto:ben@acme.example</D:href>".to_owned()),
            "[ -~]{0,12}".prop_map(|text| text.replace(['<', '&'], "")),
        ]
    }

    proptest! {
        #[test]
        fn requests_of_any_shape_are_read_or_refused_and_never_panic(pieces in proptest::collection::vec(markup_piece(), 0..30)) {
            let document = pieces.concat();
            if let Ok(root) = parse(document.as_bytes(), &DavLimits::default()) {
                let _ = parse_share(&root);
                let _ = parse_invite_reply(&root);
                let _ = parse_property_search(&root, &DavLimits::default());
                let _ = parse_token_search(&root, &DavLimits::default());
            }
        }

        #[test]
        fn the_sharees_of_a_valid_request_come_back_as_written(
            sets in proptest::collection::vec(("[a-z][a-z0-9]{0,8}", any::<bool>(), proptest::option::of("[A-Za-z ]{1,12}")), 0..6),
            removes in proptest::collection::vec("[a-z][a-z0-9]{0,8}", 0..4),
        ) {
            // A request names every sharee once: a body that names one twice is refused (see `sharing`).
            let mut seen = std::collections::HashSet::new();
            let sets: Vec<_> = sets.into_iter().filter(|(name, _, _)| seen.insert(name.clone())).collect();
            let removes: Vec<_> = removes.into_iter().filter(|name| seen.insert(name.clone())).collect();
            prop_assume!(!sets.is_empty() || !removes.is_empty());
            let mut parts = vec!["<CS:share xmlns:D=\"DAV:\" xmlns:CS=\"http://calendarserver.org/ns/\">".to_owned()];
            for (name, write, summary) in &sets {
                parts.push(format!("<CS:set><D:href>mailto:{name}@acme.example</D:href>"));
                if let Some(summary) = summary {
                    parts.push(format!("<CS:summary>{summary}</CS:summary>"));
                }
                parts.push(if *write { "<CS:read-write/>" } else { "<CS:read/>" }.to_owned());
                parts.push("</CS:set>".to_owned());
            }
            for name in &removes {
                parts.push(format!("<CS:remove><D:href>mailto:{name}@acme.example</D:href></CS:remove>"));
            }
            parts.push("</CS:share>".to_owned());
            let body = parts.concat();
            let root = parse(body.as_bytes(), &DavLimits::default()).unwrap();
            let request = parse_share(&root).unwrap().request;
            prop_assert_eq!(request.set.len(), sets.len());
            for (read, (name, write, summary)) in request.set.iter().zip(&sets) {
                prop_assert_eq!(read.address.as_str(), format!("mailto:{name}@acme.example"));
                prop_assert_eq!(read.access, if *write { GrantAccess::ReadWrite } else { GrantAccess::Read });
                prop_assert_eq!(read.summary.as_deref(), summary.as_deref().map(str::trim).filter(|text| !text.is_empty()));
            }
            let removed: Vec<&str> = request.remove.iter().map(CalendarUserAddress::as_str).collect();
            let expected: Vec<String> = removes.iter().map(|name| format!("mailto:{name}@acme.example")).collect();
            prop_assert_eq!(removed, expected.iter().map(String::as_str).collect::<Vec<&str>>());
        }

        #[test]
        fn a_share_answer_names_every_item_once_by_the_text_of_the_client_in_the_order_of_the_hrefs(
            refused in proptest::collection::vec(any::<bool>(), 0..8),
        ) {
            use davhaven_app::AppError;
            use davhaven_app::services::ShareItemResult;
            let results: Vec<ShareItemResult> = refused
                .iter()
                .enumerate()
                .map(|(n, refused)| ShareItemResult {
                    address: CalendarUserAddress::parse(&format!("mailto:user{n}@acme.example")).unwrap(),
                    error: refused.then(AppError::forbidden),
                })
                .collect();
            // The client wrote the addresses with capitals, which the application normalizes.
            let named: BTreeMap<String, String> = results
                .iter()
                .map(|result| (result.address.as_str().to_owned(), result.address.as_str().replace("user", "USER")))
                .collect();
            let response = share_response(&results, &named);
            let document = share_document(&results, &named);
            if refused.iter().any(|refused| *refused) {
                prop_assert_eq!(response.status(), StatusCode::MULTI_STATUS);
                let document = document.expect("a refused item makes a 207");
                let root = parse(document.as_bytes(), &DavLimits::default()).unwrap();
                let answers: Vec<(String, String)> = root
                    .children_named("DAV:", "response")
                    .map(|answer| {
                        (
                            answer.child("DAV:", "href").unwrap().text(),
                            answer.child("DAV:", "status").unwrap().text(),
                        )
                    })
                    .collect();
                let mut expected: Vec<(String, String)> = results
                    .iter()
                    .map(|result| {
                        (
                            named[result.address.as_str()].clone(),
                            if result.error.is_some() { "HTTP/1.1 403 Forbidden" } else { "HTTP/1.1 200 OK" }.to_owned(),
                        )
                    })
                    .collect();
                expected.sort();
                prop_assert_eq!(answers, expected, "every item once, sorted by the text of the client");
            } else {
                prop_assert_eq!(response.status(), StatusCode::OK);
                prop_assert!(document.is_none());
            }
        }
    }
}
