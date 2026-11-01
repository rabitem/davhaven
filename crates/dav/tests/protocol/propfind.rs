//! PROPFIND: depth rules, the three kinds of property selection, statuses per property, `Prefer: return=minimal`,
//! members of calendars and the special collections of a home.

use axum::http::StatusCode;

use crate::support::{Dav, HOME, NS, NS_CALDAV, NS_DAV, Req, STANDUP, STANDUP_ICS, WORK, event, propfind, todo};

fn names(response: &crate::support::Resp) -> Vec<String> {
    response
        .stats
        .iter()
        .flat_map(|stat| stat.props.iter().map(|prop| prop.local.clone()))
        .collect()
}

#[tokio::test]
async fn infinite_depth_is_refused_and_so_is_a_missing_depth_header() {
    let dav = Dav::new();
    for depth in [Some("infinity"), Some("Infinity"), None] {
        let mut request = Req::anna("PROPFIND", HOME).xml(&propfind(&["D:displayname"]));
        if let Some(depth) = depth {
            request = request.depth(depth);
        }
        let answer = dav.send(request).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{depth:?}");
        assert_eq!(
            answer.precondition().as_deref(),
            Some("propfind-finite-depth"),
            "{depth:?}"
        );
    }
    let answer = dav
        .send(
            Req::anna("PROPFIND", HOME)
                .depth("2")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_empty_body_is_allprop() {
    let dav = Dav::new();
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0")).await;
    let multi = answer.multistatus();
    assert_eq!(
        names(&multi.responses[0]),
        [
            "resourcetype",
            "displayname",
            "creationdate",
            "getlastmodified",
            "supportedlock",
            "lockdiscovery"
        ],
        "allprop is the set of RFC 4918, no CalDAV properties"
    );
    assert_eq!(multi.responses[0].text(NS_DAV, "displayname"), "Work");
}

#[tokio::test]
async fn allprop_can_include_further_properties() {
    let dav = Dav::new();
    let body = format!(
        "<D:propfind {NS}><D:allprop/><D:include><C:supported-calendar-component-set/><CS:getctag/></D:include></D:propfind>"
    );
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(
        names(&multi.responses[0]),
        [
            "resourcetype",
            "displayname",
            "creationdate",
            "getlastmodified",
            "supportedlock",
            "lockdiscovery",
            "supported-calendar-component-set",
            "getctag"
        ],
        "the set of allprop, then the included properties, each once"
    );
    assert_eq!(multi.responses[0].stats.len(), 1, "every property was found");
}

#[tokio::test]
async fn propname_lists_the_names_without_values() {
    let dav = Dav::new();
    let body = format!("<D:propfind {NS}><D:propname/></D:propfind>");
    let answer = dav.send(Req::anna("PROPFIND", STANDUP).depth("0").xml(&body)).await;
    let multi = answer.multistatus();
    let object = &multi.responses[0];
    let listed = names(object);
    for expected in [
        "getetag",
        "getcontenttype",
        "getcontentlength",
        "getlastmodified",
        "calendar-data",
    ] {
        assert!(listed.contains(&expected.to_owned()), "{expected} in {listed:?}");
    }
    assert!(
        object
            .stats
            .iter()
            .all(|stat| stat.props.iter().all(|prop| prop.children.is_empty())),
        "propname has no values"
    );
    assert_eq!(object.stats.len(), 1);
}

#[tokio::test]
async fn properties_the_resource_does_not_have_answer_404_in_their_own_propstat() {
    let dav = Dav::new();
    let body = format!(
        "<D:propfind {NS}><D:prop><D:getetag/><D:displayname/><x:unknown xmlns:x=\"urn:example:x\"/></D:prop></D:propfind>"
    );
    let answer = dav.send(Req::anna("PROPFIND", STANDUP).depth("0").xml(&body)).await;
    let multi = answer.multistatus();
    let object = &multi.responses[0];
    assert_eq!(object.stats.len(), 2);
    assert_eq!(object.status_of(NS_DAV, "getetag"), Some(200));
    assert_eq!(object.status_of(NS_DAV, "displayname"), Some(404));
    assert_eq!(object.status_of("urn:example:x", "unknown"), Some(404));
}

#[tokio::test]
async fn prefer_minimal_and_brief_leave_out_the_404_propstats() {
    let dav = Dav::new();
    let body = propfind(&["D:getetag", "D:displayname"]);
    let plain = dav.send(Req::anna("PROPFIND", STANDUP).depth("0").xml(&body)).await;
    assert_eq!(plain.multistatus().responses[0].stats.len(), 2);
    assert_eq!(plain.header("preference-applied"), "");

    for header in [("prefer", "return=minimal"), ("brief", "t")] {
        let answer = dav
            .send(
                Req::anna("PROPFIND", STANDUP)
                    .depth("0")
                    .header(header.0, header.1)
                    .xml(&body),
            )
            .await;
        let multi = answer.multistatus();
        assert_eq!(multi.responses[0].stats.len(), 1, "{header:?}");
        assert_eq!(multi.responses[0].stats[0].status, 200);
        assert_eq!(answer.header("preference-applied"), "return=minimal", "{header:?}");
    }
    let nothing_found = dav
        .send(
            Req::anna("PROPFIND", STANDUP)
                .depth("0")
                .header("prefer", "return=minimal")
                .xml(&propfind(&["D:displayname"])),
        )
        .await;
    let multi = nothing_found.multistatus();
    assert_eq!(multi.responses[0].stats.len(), 1, "a response keeps one propstat");
    assert_eq!(multi.responses[0].stats[0].status, 200);
    assert_eq!(multi.responses[0].stats[0].props.len(), 0, "nothing is listed");
}

#[tokio::test]
async fn a_calendar_lists_its_objects_at_depth_one() {
    let dav = Dav::new();
    let first = dav
        .put_event(&format!("{WORK}z-event.ics"), "z-1@acme.example", "Last")
        .await;
    let second = dav
        .put_event(&format!("{WORK}a-event.ics"), "a-1@acme.example", "First")
        .await;
    let body = propfind(&[
        "D:getetag",
        "D:getcontenttype",
        "D:getcontentlength",
        "D:getlastmodified",
        "D:resourcetype",
    ]);
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("1").xml(&body)).await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.hrefs(),
        [
            WORK,
            "/dav/calendars/acme/anna/work/a-event.ics",
            STANDUP,
            "/dav/calendars/acme/anna/work/z-event.ics"
        ]
    );
    let a = multi.response("/dav/calendars/acme/anna/work/a-event.ics");
    assert_eq!(a.text(NS_DAV, "getetag"), second);
    assert_eq!(
        a.text(NS_DAV, "getcontenttype"),
        "text/calendar; charset=utf-8; component=vevent"
    );
    assert_eq!(
        a.text(NS_DAV, "getcontentlength"),
        event("a-1@acme.example", "First").len().to_string()
    );
    assert!(a.text(NS_DAV, "getlastmodified").ends_with(" GMT"));
    assert!(
        a.children(NS_DAV, "resourcetype").is_empty(),
        "objects are no collections"
    );
    assert_eq!(
        multi
            .response("/dav/calendars/acme/anna/work/z-event.ics")
            .text(NS_DAV, "getetag"),
        first
    );
    assert_eq!(
        multi.response(STANDUP).text(NS_DAV, "getcontentlength"),
        STANDUP_ICS.len().to_string()
    );
    assert!(
        multi.response(WORK).prop(NS_DAV, "getetag").is_none(),
        "a collection has no entity tag"
    );
}

#[tokio::test]
async fn calendar_data_comes_only_when_asked_for() {
    let dav = Dav::new();
    let without = dav
        .send(Req::anna("PROPFIND", WORK).depth("1").xml(&propfind(&["D:getetag"])))
        .await;
    assert!(
        without
            .multistatus()
            .response(STANDUP)
            .prop(NS_CALDAV, "calendar-data")
            .is_none()
    );
    let with = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("1")
                .xml(&propfind(&["D:getetag", "C:calendar-data"])),
        )
        .await;
    let multi = with.multistatus();
    assert_eq!(multi.response(STANDUP).text(NS_CALDAV, "calendar-data"), STANDUP_ICS);
    assert_eq!(
        multi.response(WORK).status_of(NS_CALDAV, "calendar-data"),
        Some(404),
        "the collection has no calendar data"
    );
}

#[tokio::test]
async fn an_object_answers_for_itself_with_or_without_a_data_selection() {
    let dav = Dav::new();
    let plain = dav
        .send(
            Req::anna("PROPFIND", STANDUP)
                .depth("0")
                .xml(&propfind(&["C:calendar-data", "D:current-user-privilege-set"])),
        )
        .await;
    let multi = plain.multistatus();
    assert_eq!(multi.hrefs(), [STANDUP]);
    assert_eq!(multi.responses[0].text(NS_CALDAV, "calendar-data"), STANDUP_ICS);
    assert_eq!(
        multi.responses[0].privileges(),
        [
            "read",
            "read-current-user-privilege-set",
            "unbind",
            "write",
            "write-content",
            "write-properties"
        ]
    );

    let selection = format!(
        "<D:propfind {NS}><D:prop><C:calendar-data><C:comp name=\"VCALENDAR\"><C:allprop/><C:allcomp/></C:comp></C:calendar-data></D:prop></D:propfind>"
    );
    let selected = dav
        .send(Req::anna("PROPFIND", STANDUP).depth("0").xml(&selection))
        .await;
    assert_eq!(
        selected.multistatus().responses[0].text(NS_CALDAV, "calendar-data"),
        STANDUP_ICS
    );
}

#[tokio::test]
async fn unknown_resources_are_404() {
    let dav = Dav::new();
    let body = propfind(&["D:getetag"]);
    for path in [
        "/dav/calendars/acme/anna/work/missing.ics",
        "/dav/calendars/acme/anna/nope/",
        "/dav/principals/acme/nobody/",
    ] {
        let answer = dav.send(Req::anna("PROPFIND", path).depth("0").xml(&body)).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn bodies_that_are_no_propfind_are_400() {
    let dav = Dav::new();
    for body in [
        "<D:other xmlns:D=\"DAV:\"/>".to_owned(),
        "<D:propfind xmlns:D=\"DAV:\"><D:prop/><D:propname/></D:propfind>".to_owned(),
        "<broken".to_owned(),
    ] {
        let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(&body)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(answer.body, "", "a 400 has no element");
    }
}

#[tokio::test]
async fn the_prefix_of_a_name_does_not_matter() {
    let dav = Dav::new();
    let body = r#"<propfind xmlns="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav"><prop><displayname/><cal:max-instances/></prop></propfind>"#;
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(body)).await;
    let multi = answer.multistatus();
    assert_eq!(multi.responses[0].text(NS_DAV, "displayname"), "Work");
    assert_eq!(multi.responses[0].text(NS_CALDAV, "max-instances"), "3000");
}

#[tokio::test]
async fn the_special_collections_answer_for_themselves_and_their_items_need_the_services_of_the_application() {
    let dav = Dav::new();
    let body = propfind(&["D:displayname", "D:resourcetype"]);
    for (path, display) in [
        ("/dav/calendars/acme/anna/inbox/", "Anna Acme Inbox"),
        ("/dav/calendars/acme/anna/outbox/", "Anna Acme Outbox"),
        ("/dav/calendars/acme/anna/notifications/", "Anna Acme Notifications"),
    ] {
        let answer = dav.send(Req::anna("PROPFIND", path).depth("0").xml(&body)).await;
        let multi = answer.multistatus();
        assert_eq!(multi.hrefs(), [path]);
        assert_eq!(multi.responses[0].text(NS_DAV, "displayname"), display);
    }
    let outbox = dav
        .send(
            Req::anna("PROPFIND", "/dav/calendars/acme/anna/outbox/")
                .depth("1")
                .xml(&body),
        )
        .await;
    assert_eq!(
        outbox.multistatus().hrefs(),
        ["/dav/calendars/acme/anna/outbox/"],
        "an outbox has no members"
    );
    for path in [
        "/dav/calendars/acme/anna/inbox/",
        "/dav/calendars/acme/anna/notifications/",
    ] {
        let answer = dav.send(Req::anna("PROPFIND", path).depth("1").xml(&body)).await;
        assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED, "{path}");
    }
    let item = dav
        .send(
            Req::anna("PROPFIND", "/dav/calendars/acme/anna/inbox/invite.ics")
                .depth("0")
                .xml(&body),
        )
        .await;
    assert_eq!(item.status, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn todos_are_listed_with_their_own_component_type() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("PUT", &format!("{WORK}task.ics"))
                .ics(&todo("task-1@acme.example", "Write"))
                .header("if-none-match", "*"),
        )
        .await;
    assert_eq!(answer.status, StatusCode::CREATED);
    let listing = dav
        .send(
            Req::anna("PROPFIND", &format!("{WORK}task.ics"))
                .depth("0")
                .xml(&propfind(&["D:getcontenttype"])),
        )
        .await;
    assert_eq!(
        listing.multistatus().responses[0].text(NS_DAV, "getcontenttype"),
        "text/calendar; charset=utf-8; component=vtodo"
    );
}
