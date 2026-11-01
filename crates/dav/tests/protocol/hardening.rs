//! Hostile and oversized request bodies: the XML limits of PLAN 2.15 enforced end to end, on every method that
//! reads XML.

use axum::http::StatusCode;
use davhaven_app::AppServices;
use davhaven_app_fake::AppServicesExt as _;

use crate::support::{Dav, NS, Req, WORK, propfind, repeat};

/// The requests that carry an XML body: the same body is sent with each of them.
fn xml_requests(body: &str) -> Vec<Req> {
    vec![
        Req::anna("PROPFIND", WORK).depth("0").xml(body),
        Req::anna("PROPPATCH", WORK).xml(body),
        Req::anna("REPORT", WORK).xml(body),
        Req::anna("MKCALENDAR", "/dav/calendars/acme/anna/new/").xml(body),
    ]
}

async fn assert_every_method_refuses(dav: &Dav, body: &str, status: StatusCode, what: &str) {
    for request in xml_requests(body) {
        let label = format!("{what}: {} bytes to {request:?}", body.len());
        let answer = dav.send(request).await;
        assert_eq!(answer.status, status, "{label}");
    }
}

#[tokio::test]
async fn entities_and_document_types_are_refused_before_anything_expands() {
    let dav = Dav::new();
    let laughs = r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">]><D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&lol2;</D:displayname></D:prop></D:propfind>"#;
    assert_every_method_refuses(&dav, laughs, StatusCode::BAD_REQUEST, "billion laughs").await;
    let external = r#"<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&x;</D:displayname></D:prop></D:propfind>"#;
    assert_every_method_refuses(&dav, external, StatusCode::BAD_REQUEST, "external entity").await;
    let custom = r#"<D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&custom;</D:displayname></D:prop></D:propfind>"#;
    assert_every_method_refuses(&dav, custom, StatusCode::BAD_REQUEST, "undeclared entity").await;
}

#[tokio::test]
async fn the_structure_of_a_body_is_limited() {
    let dav = Dav::new();
    let deep = format!("{}{}", "<D:a xmlns:D=\"DAV:\">".repeat(33), "</D:a>".repeat(33));
    assert_every_method_refuses(&dav, &deep, StatusCode::BAD_REQUEST, "33 levels").await;

    let elements = format!(
        "<D:propfind xmlns:D=\"DAV:\"><D:prop>{}</D:prop></D:propfind>",
        "<D:x/>".repeat(9_999)
    );
    assert_every_method_refuses(&dav, &elements, StatusCode::BAD_REQUEST, "10 001 elements").await;

    let attributes = repeat(33, |n| format!(" a{n}=\"1\""));
    let many_attributes = format!("<D:propfind xmlns:D=\"DAV:\"><D:prop{attributes}/></D:propfind>");
    assert_every_method_refuses(&dav, &many_attributes, StatusCode::BAD_REQUEST, "33 attributes").await;

    let namespaces = repeat(65, |n| format!(" xmlns:n{n}=\"urn:{n}\""));
    let many_namespaces = format!("<D:propfind xmlns:D=\"DAV:\"{namespaces}><D:prop/></D:propfind>");
    assert_every_method_refuses(&dav, &many_namespaces, StatusCode::BAD_REQUEST, "66 namespaces").await;
}

#[tokio::test]
async fn bodies_exactly_at_the_limits_are_accepted() {
    let dav = Dav::new();
    let at_depth = format!(
        "<D:propfind xmlns:D=\"DAV:\"><D:prop>{}{}</D:prop></D:propfind>",
        "<D:a>".repeat(30),
        "</D:a>".repeat(30)
    );
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(&at_depth)).await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS, "32 levels deep");

    let elements = format!(
        "<D:propfind xmlns:D=\"DAV:\"><D:prop>{}</D:prop></D:propfind>",
        "<D:x/>".repeat(9_998)
    );
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(&elements)).await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS, "10 000 elements");
}

#[tokio::test]
async fn text_that_is_not_xml_is_refused() {
    let dav = Dav::new();
    for (body, what) in [
        (
            b"<D:propfind xmlns:D=\"DAV:\"><D:prop><D:displayname>\xff\xfe</D:displayname></D:prop></D:propfind>"
                .to_vec(),
            "invalid UTF-8",
        ),
        (
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><D:propfind xmlns:D=\"DAV:\"/>".to_vec(),
            "another encoding",
        ),
        (
            b"<D:propfind xmlns:D=\"DAV:\"><D:prop><D:displayname>\x01</D:displayname></D:prop></D:propfind>".to_vec(),
            "a control character",
        ),
        (b"\x00\x01\x02".to_vec(), "binary data"),
        (
            b"<D:propfind xmlns:D=\"DAV:\"/><D:propfind xmlns:D=\"DAV:\"/>".to_vec(),
            "two documents",
        ),
    ] {
        for method in ["PROPFIND", "PROPPATCH", "REPORT"] {
            let mut request = Req::anna(method, WORK).bytes(body.clone());
            if method == "PROPFIND" {
                request = request.depth("0");
            }
            let answer = dav.send(request).await;
            assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{what} to {method}");
        }
    }
}

#[tokio::test]
async fn xml_bodies_have_a_size_limit_that_answers_413() {
    let dav = Dav::new();
    let just_fits = format!(
        "<D:propfind xmlns:D=\"DAV:\"><D:prop>{}</D:prop></D:propfind>",
        "<D:x/>".repeat(40_000)
    );
    assert!(just_fits.len() < 262_144);
    // The element limit is hit first, which is a 400: the size limit is not the reason.
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(&just_fits)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);

    let too_big = format!(
        "<D:propfind xmlns:D=\"DAV:\"><D:prop>{}</D:prop></D:propfind>",
        "<D:x/>".repeat(50_000)
    );
    assert!(too_big.len() > 262_144);
    for method in ["PROPFIND", "PROPPATCH", "REPORT", "MKCALENDAR"] {
        let path = if method == "MKCALENDAR" {
            "/dav/calendars/acme/anna/new/"
        } else {
            WORK
        };
        let mut request = Req::anna(method, path).xml(&too_big);
        if method == "PROPFIND" {
            request = request.depth("0");
        }
        let answer = dav.send(request).await;
        assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE, "{method}");
    }
}

#[tokio::test]
async fn nothing_is_created_by_a_refused_body() {
    let dav = Dav::new();
    let bomb = r#"<!DOCTYPE a [<!ENTITY b "c">]><C:mkcalendar xmlns:C="urn:ietf:params:xml:ns:caldav"/>"#;
    let answer = dav
        .send(Req::anna("MKCALENDAR", "/dav/calendars/acme/anna/new/").xml(bomb))
        .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    let missing = dav
        .send(Req::anna("PROPFIND", "/dav/calendars/acme/anna/new/").depth("0"))
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

// -------------------------------------------------------------------------------------------------------------
// Amplification: what a small body must not be able to make the server hold, copy or write
// -------------------------------------------------------------------------------------------------------------

/// The body of the audit: a namespace of `namespace_bytes` declared once and used by thousands of children. Held
/// per element and written per property, 230 KB of it made gigabytes.
fn namespace_bomb(namespace_bytes: usize) -> String {
    let namespace = "a".repeat(namespace_bytes);
    let children = repeat(9_990, |n| format!("<p{n}/>"));
    format!("<D:propfind xmlns:D=\"DAV:\"><D:prop xmlns=\"urn:{namespace}\">{children}</D:prop></D:propfind>")
}

#[tokio::test]
async fn a_long_namespace_used_by_thousands_of_elements_is_refused_by_every_method() {
    let dav = Dav::new();
    let body = namespace_bomb(150_000);
    assert!(body.len() < 262_144, "{} bytes pass every other limit", body.len());
    assert_every_method_refuses(&dav, &body, StatusCode::BAD_REQUEST, "a 150 KB namespace").await;

    // The same bomb with the namespace on every element, and on the attributes of one element.
    let on_each = repeat(200, |n| format!("<p{n} xmlns=\"urn:{}\"/>", "b".repeat(1_100)));
    let spread = format!("<D:propfind xmlns:D=\"DAV:\"><D:prop>{on_each}</D:prop></D:propfind>");
    assert_every_method_refuses(&dav, &spread, StatusCode::BAD_REQUEST, "1.1 KB namespaces").await;
    let long = "c".repeat(1_100);
    let attributes = repeat(16, |n| format!(" x{n}:a=\"1\" xmlns:x{n}=\"urn:{long}{n}\""));
    let on_attributes = format!("<D:propfind xmlns:D=\"DAV:\"><D:prop{attributes}/></D:propfind>");
    assert_every_method_refuses(
        &dav,
        &on_attributes,
        StatusCode::BAD_REQUEST,
        "long namespaces of attributes",
    )
    .await;
}

#[tokio::test]
async fn names_and_namespaces_up_to_the_caps_are_accepted() {
    let dav = Dav::new();
    let namespace = format!("urn:{}", "n".repeat(1_020));
    let name = "e".repeat(256);
    let body = format!("<D:propfind xmlns:D=\"DAV:\"><D:prop><{name} xmlns=\"{namespace}\"/></D:prop></D:propfind>");
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("0").xml(&body)).await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS);
    let multi = answer.multistatus();
    assert_eq!(multi.responses[0].status_of(&namespace, &name), Some(404));
    assert_eq!(
        answer.body.matches(&namespace).count(),
        1,
        "the namespace is declared once in the answer, not once per property"
    );
}

#[tokio::test]
async fn a_request_names_a_bounded_number_of_properties() {
    let dav = Dav::new();
    let properties = |count: usize| {
        let names = repeat(count, |n| format!("<x:p{n} xmlns:x=\"urn:example:x\"/>"));
        format!("<D:propfind xmlns:D=\"DAV:\"><D:prop>{names}</D:prop></D:propfind>")
    };
    let answer = dav
        .send(Req::anna("PROPFIND", WORK).depth("1").xml(&properties(1_000)))
        .await;
    assert_eq!(answer.status, StatusCode::MULTI_STATUS, "1000 properties are fine");
    assert_eq!(
        answer.body.matches("urn:example:x").count(),
        1,
        "and their namespace is written once, not once per property and resource"
    );
    let answer = dav
        .send(Req::anna("PROPFIND", WORK).depth("0").xml(&properties(1_001)))
        .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "1001 properties are too many");
}

/// A calendar with `count` more events than the seed.
async fn crowded(count: usize, limits: impl FnOnce(&mut davhaven_domain::Limits)) -> Dav {
    let mut services = AppServices::fake();
    limits(&mut services.limits);
    let dav = Dav::with(services);
    for n in 0..count {
        dav.put_event(
            &format!("{WORK}e{n:03}.ics"),
            &format!("e{n}@acme.example"),
            &format!("Event {n}"),
        )
        .await;
    }
    dav
}

#[tokio::test]
async fn an_answer_that_grows_beyond_the_limit_is_cut_off_with_a_507_for_the_request_uri() {
    let dav = crowded(30, |limits| limits.dav.max_response_bytes = 4_000).await;
    let body = propfind(&["D:getetag", "D:getcontenttype", "D:getlastmodified"]);
    let answer = dav.send(Req::anna("PROPFIND", WORK).depth("1").xml(&body)).await;
    let multi = answer.multistatus();
    let cut: Vec<_> = multi
        .responses
        .iter()
        .filter(|response| response.status == Some(507))
        .collect();
    assert_eq!(cut.len(), 1, "{:?}", multi.hrefs());
    assert_eq!(cut[0].href, WORK, "the 507 is for the request URI");
    assert_eq!(cut[0].error.as_deref(), Some("number-of-matches-within-limits"));
    assert_eq!(multi.hrefs()[0], WORK, "the collection itself comes first");
    assert!(multi.responses.len() < 31, "{} responses", multi.responses.len());
    assert!(answer.body.len() < 4_000 + 1_500, "{} bytes", answer.body.len());

    let report = dav
        .send(Req::anna("REPORT", WORK).xml(&format!(
            "<C:calendar-query {NS}><D:prop><D:getetag/><C:calendar-data/></D:prop><C:filter>\
             <C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\"/></C:comp-filter></C:filter></C:calendar-query>"
        )))
        .await;
    let multi = report.multistatus();
    assert_eq!(multi.responses.last().unwrap().status, Some(507));
    assert!(multi.responses.len() < 31);
    let hrefs: Vec<&str> = multi.hrefs().into_iter().filter(|href| *href != WORK).collect();
    let mut sorted = hrefs.clone();
    sorted.sort_unstable();
    assert_eq!(hrefs, sorted, "what is answered is the start of the sorted list");

    let roomy = crowded(30, |_| ()).await;
    let all = roomy.send(Req::anna("PROPFIND", WORK).depth("1").xml(&body)).await;
    let all = all.multistatus();
    assert_eq!(all.responses.len(), 32, "the collection, the seed and thirty events");
    assert!(all.responses.iter().all(|response| response.status != Some(507)));
}

#[tokio::test]
async fn a_multiget_reads_its_objects_in_steps_and_stops_at_the_limit() {
    let dav = crowded(250, |limits| limits.dav.max_response_bytes = 40_000).await;
    let hrefs: Vec<String> = (0..250).map(|n| format!("{WORK}e{n:03}.ics")).collect();
    let refs: Vec<&str> = hrefs.iter().map(String::as_str).collect();
    let body = format!(
        "<C:calendar-multiget {NS}><D:prop><D:getetag/><C:calendar-data/></D:prop>{}</C:calendar-multiget>",
        repeat(refs.len(), |n| format!(
            "<D:href>{}</D:href>",
            refs.get(n).copied().unwrap_or_default()
        ))
    );
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
    let multi = answer.multistatus();
    let last = multi.responses.last().unwrap();
    assert_eq!((last.href.as_str(), last.status), (WORK, Some(507)));
    let answered: Vec<&str> = multi.hrefs().into_iter().filter(|href| *href != WORK).collect();
    assert!(
        !answered.is_empty() && answered.len() < 250,
        "{} answered",
        answered.len()
    );
    assert_eq!(
        answered,
        &refs[..answered.len()],
        "the first hrefs in order, none skipped"
    );
    assert!(
        answer.body.len() < 40_000 + 100 * 700,
        "at most the limit and one step of data: {} bytes",
        answer.body.len()
    );
}
