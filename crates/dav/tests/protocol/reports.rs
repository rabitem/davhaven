//! REPORT: calendar-multiget, calendar-query, free-busy-query, expand-property and the reports a resource does
//! not support.

use axum::http::StatusCode;
use davhaven_app::AppServices;
use davhaven_app_fake::AppServicesExt as _;

use crate::support::{
    Dav, NS, NS_CALDAV, NS_CALENDARSERVER, NS_DAV, PERSONAL, Req, STANDUP, STANDUP_ICS, WORK, event, repeat, todo,
};

fn multiget(hrefs: &[&str]) -> String {
    let hrefs = repeat(hrefs.len(), |index| {
        format!("<D:href>{}</D:href>", hrefs.get(index).copied().unwrap_or_default())
    });
    format!("<C:calendar-multiget {NS}><D:prop><D:getetag/><C:calendar-data/></D:prop>{hrefs}</C:calendar-multiget>")
}

fn query(component: &str) -> String {
    format!(
        "<C:calendar-query {NS}><D:prop><D:getetag/><C:calendar-data/></D:prop><C:filter>\
         <C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"{component}\"/></C:comp-filter></C:filter></C:calendar-query>"
    )
}

#[tokio::test]
async fn a_multiget_answers_every_href_it_was_given() {
    let dav = Dav::new();
    let body = multiget(&[
        STANDUP,
        "/dav/calendars/acme/anna/work/missing.ics",
        "/dav/calendars/acme/anna/personal/standup.ics",
        "not a path at all",
        STANDUP,
    ]);
    let answer = dav.send(Req::anna("REPORT", WORK).depth("1").xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.hrefs(),
        [
            "/dav/calendars/acme/anna/personal/standup.ics",
            "/dav/calendars/acme/anna/work/missing.ics",
            STANDUP,
            "not a path at all",
        ],
        "sorted by href, each href once"
    );
    let found = multi.response(STANDUP);
    assert_eq!(
        found.text(NS_DAV, "getetag"),
        davhaven_domain::ETag::from_bytes(STANDUP_ICS.as_bytes()).as_str()
    );
    assert_eq!(
        found.text(NS_CALDAV, "calendar-data"),
        STANDUP_ICS,
        "CRLF survives the XML"
    );
    for missing in [
        "/dav/calendars/acme/anna/work/missing.ics",
        "/dav/calendars/acme/anna/personal/standup.ics",
        "not a path at all",
    ] {
        let response = multi.response(missing);
        assert_eq!(response.status, Some(404), "{missing}");
        assert!(response.stats.is_empty());
    }
}

#[tokio::test]
async fn a_multiget_only_reaches_the_collection_it_was_sent_to() {
    let dav = Dav::new();
    dav.put_event(&format!("{PERSONAL}own.ics"), "own-1@acme.example", "Own")
        .await;
    let answer = dav
        .send(
            Req::anna("REPORT", WORK)
                .depth("1")
                .xml(&multiget(&[&format!("{PERSONAL}own.ics")])),
        )
        .await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.responses[0].status,
        Some(404),
        "an object of another collection is not found here"
    );
}

#[tokio::test]
async fn the_number_of_hrefs_is_limited() {
    let mut services = AppServices::fake();
    services.limits.dav.max_multiget_hrefs = 2;
    let dav = Dav::with(services);
    let two = dav
        .send(Req::anna("REPORT", WORK).xml(&multiget(&[STANDUP, "/a"])))
        .await;
    assert_eq!(two.status, StatusCode::MULTI_STATUS);
    let three = dav
        .send(Req::anna("REPORT", WORK).xml(&multiget(&[STANDUP, "/a", "/b"])))
        .await;
    assert_eq!(three.status, StatusCode::FORBIDDEN);
    assert_eq!(three.precondition().as_deref(), Some("number-of-matches-within-limits"));
    let repeated = dav
        .send(Req::anna("REPORT", WORK).xml(&multiget(&[STANDUP, STANDUP, STANDUP])))
        .await;
    assert_eq!(
        repeated.status,
        StatusCode::FORBIDDEN,
        "the limit counts what the client sent"
    );
}

#[tokio::test]
async fn a_multiget_of_a_calendar_that_is_not_yours_is_404() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("REPORT", WORK)
                .by(crate::support::User::Ben)
                .xml(&multiget(&[STANDUP])),
        )
        .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_calendar_query_returns_the_matching_objects_with_their_data() {
    let dav = Dav::new();
    dav.send(Req::anna("PUT", &format!("{WORK}task.ics")).ics(&todo("task-1@acme.example", "Task")))
        .await;
    let events = dav
        .send(Req::anna("REPORT", WORK).depth("1").xml(&query("VEVENT")))
        .await;
    let multi = events.multistatus();
    assert_eq!(multi.hrefs(), [STANDUP]);
    assert_eq!(multi.responses[0].text(NS_CALDAV, "calendar-data"), STANDUP_ICS);

    let todos = dav
        .send(Req::anna("REPORT", WORK).depth("1").xml(&query("VTODO")))
        .await;
    assert_eq!(todos.multistatus().hrefs(), ["/dav/calendars/acme/anna/work/task.ics"]);

    let journals = dav.send(Req::anna("REPORT", WORK).xml(&query("VJOURNAL"))).await;
    assert!(
        journals.multistatus().responses.is_empty(),
        "no match is an empty multistatus"
    );
}

#[tokio::test]
async fn a_query_can_ask_for_part_of_the_data_and_a_time_range() {
    let dav = Dav::new();
    let body = format!(
        "<C:calendar-query {NS}><D:prop><D:getetag/><C:calendar-data>\
         <C:comp name=\"VCALENDAR\"><C:prop name=\"VERSION\"/><C:comp name=\"VEVENT\"><C:prop name=\"SUMMARY\"/></C:comp></C:comp>\
         </C:calendar-data></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\">\
         <C:time-range start=\"20270101T000000Z\" end=\"20270401T000000Z\"/></C:comp-filter></C:comp-filter></C:filter>\
         </C:calendar-query>"
    );
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
    assert_eq!(answer.multistatus().hrefs(), [STANDUP]);
}

#[tokio::test]
async fn queries_the_server_cannot_evaluate_are_valid_filter_failures() {
    let dav = Dav::new();
    for filter in [
        "<C:filter/>",
        "<C:filter><C:comp-filter name=\"VCALENDAR\"><C:time-range start=\"yesterday\"/></C:comp-filter></C:filter>",
        "<C:filter><C:comp-filter name=\"VCALENDAR\"><C:prop-filter name=\"SUMMARY\"><C:text-match collation=\"i;klingon\">x</C:text-match></C:prop-filter></C:comp-filter></C:filter>",
    ] {
        let body = format!("<C:calendar-query {NS}><D:prop><D:getetag/></D:prop>{filter}</C:calendar-query>");
        let answer = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{filter}");
        assert_eq!(answer.precondition().as_deref(), Some("valid-filter"), "{filter}");
    }
    let no_filter = format!("<C:calendar-query {NS}><D:prop><D:getetag/></D:prop></C:calendar-query>");
    assert_eq!(
        dav.send(Req::anna("REPORT", WORK).xml(&no_filter)).await.status,
        StatusCode::BAD_REQUEST
    );
    let other_format = format!(
        "<C:calendar-query {NS}><D:prop><C:calendar-data content-type=\"application/json\"/></D:prop>\
         <C:filter><C:comp-filter name=\"VCALENDAR\"/></C:filter></C:calendar-query>"
    );
    let unsupported = dav.send(Req::anna("REPORT", WORK).xml(&other_format)).await;
    assert_eq!(unsupported.status, StatusCode::FORBIDDEN);
    assert_eq!(unsupported.precondition().as_deref(), Some("supported-calendar-data"));
}

#[tokio::test]
async fn the_minimal_preference_applies_to_reports_too() {
    let dav = Dav::new();
    let body = format!(
        "<C:calendar-multiget {NS}><D:prop><D:getetag/><D:displayname/></D:prop><D:href>{STANDUP}</D:href></C:calendar-multiget>"
    );
    let answer = dav
        .send(Req::anna("REPORT", WORK).header("prefer", "return=minimal").xml(&body))
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.responses[0].stats.len(), 1, "the 404 for displayname is left out");
    assert_eq!(answer.header("preference-applied"), "return=minimal");
}

#[tokio::test]
async fn free_busy_needs_a_bounded_range_and_the_scheduling_service() {
    let dav = Dav::new();
    let unbounded = format!("<C:free-busy-query {NS}><C:time-range start=\"20270101T000000Z\"/></C:free-busy-query>");
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&unbounded)).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.precondition().as_deref(), Some("valid-filter"));
    let missing = format!("<C:free-busy-query {NS}/>");
    assert_eq!(
        dav.send(Req::anna("REPORT", WORK).xml(&missing)).await.status,
        StatusCode::BAD_REQUEST
    );

    // The fake has no scheduling service: the request reaches it and its answer is passed on (501). The renderer
    // of the answer is tested in the module of the reports.
    let bounded = format!(
        "<C:free-busy-query {NS}><C:time-range start=\"20270101T000000Z\" end=\"20270201T000000Z\"/></C:free-busy-query>"
    );
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&bounded)).await;
    assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn expand_property_follows_group_membership_and_has_empty_proxy_properties() {
    let dav = Dav::new();
    let body = format!(
        "<D:expand-property {NS}>\
         <D:property name=\"group-membership\" namespace=\"DAV:\"><D:property name=\"displayname\" namespace=\"DAV:\"/></D:property>\
         <D:property name=\"calendar-proxy-read-for\" namespace=\"http://calendarserver.org/ns/\"><D:property name=\"displayname\"/></D:property>\
         <D:property name=\"calendar-proxy-write-for\" namespace=\"http://calendarserver.org/ns/\"/>\
         <D:property name=\"displayname\"/>\
         <D:property name=\"nonsense\" namespace=\"urn:example:x\"/>\
         </D:expand-property>"
    );
    let answer = dav
        .send(Req::anna("REPORT", "/dav/principals/acme/anna/").depth("0").xml(&body))
        .await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), ["/dav/principals/acme/anna/"]);
    let principal = &multi.responses[0];

    let membership = principal.prop(NS_DAV, "group-membership").unwrap();
    let team = membership.child(NS_DAV, "response").expect("the group is expanded");
    assert_eq!(team.child(NS_DAV, "href").unwrap().text(), "/dav/principals/acme/team/");
    let prop = team.child(NS_DAV, "propstat").unwrap().child(NS_DAV, "prop").unwrap();
    assert_eq!(prop.child(NS_DAV, "displayname").unwrap().text(), "The Team");

    for local in ["calendar-proxy-read-for", "calendar-proxy-write-for"] {
        let proxy = principal.prop(NS_CALENDARSERVER, local).unwrap();
        assert_eq!(proxy.elements().count(), 0, "{local}: nobody is a proxy");
    }
    assert_eq!(principal.text(NS_DAV, "displayname"), "Anna Acme");
    assert_eq!(principal.status_of("urn:example:x", "nonsense"), Some(404));
}

#[tokio::test]
async fn reports_a_resource_does_not_support_are_refused_with_the_element_of_rfc_3253() {
    let dav = Dav::new();
    let version_tree = format!("<D:version-tree {NS}/>");
    for (path, body) in [
        (WORK, version_tree.clone()),
        ("/dav/principals/acme/anna/", version_tree),
        (
            "/dav/principals/acme/anna/",
            format!(
                "<C:calendar-query {NS}><C:filter><C:comp-filter name=\"VCALENDAR\"/></C:filter></C:calendar-query>"
            ),
        ),
        (
            "/dav/calendars/acme/anna/",
            format!(
                "<D:sync-collection {NS}><D:sync-token/><D:sync-level>1</D:sync-level><D:prop/></D:sync-collection>"
            ),
        ),
        (WORK, format!("<D:expand-property {NS}/>")),
    ] {
        let answer = dav.send(Req::anna("REPORT", path).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{path} {body}");
        assert_eq!(
            answer.precondition().as_deref(),
            Some("supported-report"),
            "{path} {body}"
        );
    }
}

#[tokio::test]
async fn principal_search_reports_that_search_for_nothing_are_400_and_the_property_set_answers() {
    let dav = Dav::new();
    for body in [
        format!("<D:principal-property-search {NS}/>"),
        format!("<CS:calendarserver-principal-search {NS}/>"),
    ] {
        let answer = dav
            .send(Req::anna("REPORT", "/dav/principals/acme/anna/").xml(&body))
            .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}");
    }
    let property_set = format!("<D:principal-search-property-set {NS}/>");
    let answer = dav
        .send(Req::anna("REPORT", "/dav/principals/acme/anna/").xml(&property_set))
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
}

#[tokio::test]
async fn report_bodies_that_are_not_xml_are_400_and_report_urls_must_name_a_resource() {
    let dav = Dav::new();
    assert_eq!(
        dav.send(Req::anna("REPORT", WORK).xml("not xml")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        dav.send(Req::anna("REPORT", WORK)).await.status,
        StatusCode::BAD_REQUEST,
        "an empty body names no report"
    );
    assert_eq!(
        dav.send(Req::anna("REPORT", STANDUP).xml(&multiget(&[STANDUP])))
            .await
            .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn data_written_by_one_client_is_what_another_report_returns() {
    let dav = Dav::new();
    let body = event("fresh-1@acme.example", "Fresh");
    dav.send(Req::anna("PUT", &format!("{WORK}fresh.ics")).ics(&body)).await;
    let answer = dav
        .send(Req::anna("REPORT", WORK).xml(&multiget(&[&format!("{WORK}fresh.ics")])))
        .await;
    assert_eq!(answer.multistatus().responses[0].text(NS_CALDAV, "calendar-data"), body);
}

#[tokio::test]
async fn the_entry_point_takes_reports_because_principal_search_is_sent_there() {
    let dav = Dav::new();
    let search = format!("<D:principal-search-property-set {NS}/>");
    let answer = dav.send(Req::anna("REPORT", "/dav/").xml(&search)).await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "the principal search is sent to the entry point: {}",
        answer.body
    );
    let other = format!("<D:version-tree {NS}/>");
    let answer = dav.send(Req::anna("REPORT", "/dav/").xml(&other)).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.precondition().as_deref(), Some("supported-report"));
}

#[tokio::test]
async fn two_spellings_of_one_href_are_answered_once_with_the_canonical_path() {
    let dav = Dav::new();
    let body = multiget(&[
        "/dav/calendars/acme/anna/work/%73tandup.ics",
        STANDUP,
        "https://cal.example.test/dav/calendars/acme/anna/work/standup.ics",
        "/dav/calendars/acme/anna/work/missing%2Eics",
        "/dav/calendars/acme/anna/work/missing.ics",
    ]);
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.hrefs(),
        ["/dav/calendars/acme/anna/work/missing.ics", STANDUP],
        "one answer per resource, each with the canonical href, found or not"
    );
    assert_eq!(multi.response(STANDUP).text(NS_CALDAV, "calendar-data"), STANDUP_ICS);
    assert_eq!(
        multi.response("/dav/calendars/acme/anna/work/missing.ics").status,
        Some(404)
    );
}

#[tokio::test]
async fn hrefs_of_calendars_the_caller_cannot_see_are_answered_like_hrefs_that_name_nothing() {
    let dav = Dav::new();
    let body = multiget(&[
        "/dav/calendars/acme/ben/personal/standup.ics",
        "/dav/calendars/globex/gina/personal/standup.ics",
        "https://cal.example.test/dav/calendars/globex/gina/personal/standup.ics",
        "/dav/calendars/acme/anna/work/nothing.ics",
        "/dav/calendars/acme/anna/nope/standup.ics",
    ]);
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.responses.len(),
        4,
        "the two spellings of Gina's href are one: {:?}",
        multi.hrefs()
    );
    for response in &multi.responses {
        assert_eq!(response.status, Some(404), "{}", response.href);
        assert!(response.stats.is_empty(), "{}", response.href);
        assert_eq!(response.error, None, "{}: nothing says why", response.href);
    }
}

#[tokio::test]
async fn a_multiget_that_names_nothing_still_needs_a_visible_calendar() {
    let dav = Dav::new();
    for body in [
        multiget(&[]),
        multiget(&["not a path", "/elsewhere/x.ics"]),
        multiget(&["/dav/calendars/acme/anna/personal/standup.ics"]),
    ] {
        let invisible = dav
            .send(Req::anna("REPORT", WORK).by(crate::support::User::Ben).xml(&body))
            .await;
        assert_eq!(invisible.status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(invisible.body, "", "{body}");
        let missing = dav
            .send(Req::anna("REPORT", "/dav/calendars/acme/anna/nope/").xml(&body))
            .await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND, "{body}");
        let own = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
        assert_eq!(own.status, StatusCode::MULTI_STATUS, "{body}");
    }
    let empty = dav.send(Req::anna("REPORT", WORK).xml(&multiget(&[]))).await;
    assert!(empty.multistatus().responses.is_empty());
}

fn expand(properties: &str) -> String {
    format!("<D:expand-property {NS}>{properties}</D:expand-property>")
}

const TEAM: &str = "/dav/principals/acme/team/";

#[tokio::test]
async fn the_members_of_a_group_are_expanded_and_their_number_is_bounded() {
    let members = r#"<D:property name="group-member-set"><D:property name="displayname"/></D:property>"#;
    let dav = Dav::new();
    let answer = dav.send(Req::anna("REPORT", TEAM).xml(&expand(members))).await;
    let multi = answer.multistatus();
    let set = multi.responses[0].prop(NS_DAV, "group-member-set").unwrap();
    let mut names: Vec<String> = set
        .children_named(NS_DAV, "response")
        .map(|response| {
            response
                .child(NS_DAV, "propstat")
                .and_then(|stat| stat.child(NS_DAV, "prop"))
                .and_then(|prop| prop.child(NS_DAV, "displayname"))
                .map(davhaven_dav::xml::Element::text)
                .unwrap()
        })
        .collect();
    names.sort();
    assert_eq!(names, ["Anna Acme", "Ben Baker"]);

    // The group has two members: a request that would expand more than a multiget may name is refused.
    let mut services = AppServices::fake();
    services.limits.dav.max_multiget_hrefs = 1;
    let strict = Dav::with(services);
    let answer = strict.send(Req::anna("REPORT", TEAM).xml(&expand(members))).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(
        answer.precondition().as_deref(),
        Some("number-of-matches-within-limits")
    );
}

#[tokio::test]
async fn an_expand_property_request_cannot_ask_for_the_same_expansion_again_and_again() {
    let entry = r#"<D:property name="group-member-set"><D:property name="displayname"/></D:property>"#;
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("REPORT", TEAM).xml(&expand(&entry.repeat(3_000))))
        .await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS);
    let multi = answer.multistatus();
    let property = &multi.responses[0];
    assert_eq!(property.stats.len(), 1);
    assert_eq!(
        property.stats[0].props.len(),
        1,
        "3000 identical entries are one property"
    );
    let set = property.prop(NS_DAV, "group-member-set").unwrap();
    assert_eq!(set.children_named(NS_DAV, "response").count(), 2, "and two members");
    assert!(answer.body.len() < 4_000, "{} bytes", answer.body.len());
}

#[tokio::test]
async fn names_that_would_be_written_into_the_answer_must_be_xml_names() {
    let dav = Dav::new();
    for name in [
        "x&gt;&lt;D:href&gt;/evil&lt;/D:href&gt;&lt;y",
        "a b",
        "a&quot;b",
        "&lt;",
    ] {
        let body = expand(&format!(r#"<D:property name="{name}"/>"#));
        let answer = dav.send(Req::anna("REPORT", TEAM).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{name}");
        assert!(!answer.body.contains("evil"), "{name}: {}", answer.body);
    }
    // A name in a foreign namespace is fine, and what comes back is well-formed.
    let body = expand(r#"<D:property name="note" namespace="urn:example:x"/><D:property name="displayname"/>"#);
    let answer = dav.send(Req::anna("REPORT", TEAM).xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(multi.responses[0].status_of("urn:example:x", "note"), Some(404));
    assert_eq!(multi.responses[0].text(NS_DAV, "displayname"), "The Team");
}
