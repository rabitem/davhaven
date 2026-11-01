//! Protocol tests of the DAV routing: the URL layout, authentication, `OPTIONS`, the method table, the statuses of
//! paths and methods that name no resource, and the edge limits, over the in-memory fake of the application services
//! (PLAN 3.1, L4). The behavior of the methods and reports is tested in `protocol/`.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use davhaven_app::AppServices;
use davhaven_app_fake::AppServicesExt as _;
use davhaven_app_fake::seed::{ADMIN_TOKEN, ANNA_PASSWORD, GINA_PASSWORD};
use davhaven_http::{Edge, SequentialRequestIds, Surface};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

const HOME: &str = "/dav/calendars/acme/anna";
const COLLECTION: &str = "/dav/calendars/acme/anna/work";
const OBJECT: &str = "/dav/calendars/acme/anna/work/standup.ics";
const HOME_SLASH: &str = "/dav/calendars/acme/anna/";
const COLLECTION_SLASH: &str = "/dav/calendars/acme/anna/work/";
const OBJECT_SLASH: &str = "/dav/calendars/acme/anna/work/standup.ics/";
const INBOX: &str = "/dav/calendars/acme/anna/inbox";
const INBOX_SLASH: &str = "/dav/calendars/acme/anna/inbox/";
const INBOX_ITEM: &str = "/dav/calendars/acme/anna/inbox/invite.ics";
const OUTBOX_SLASH: &str = "/dav/calendars/acme/anna/outbox/";
const NOTIFICATION: &str = "/dav/calendars/acme/anna/notifications/n1.xml";
const OUTBOX_ITEM: &str = "/dav/calendars/acme/anna/outbox/x";
const TOO_DEEP: &str = "/dav/calendars/acme/anna/work/a/b";

fn services() -> AppServices {
    AppServices::fake()
}

fn edge() -> Edge {
    Edge::new(Surface::Dav, Arc::new(SequentialRequestIds::new()))
}

fn dav() -> Router {
    davhaven_dav::router(services(), &edge())
}

fn wellknown() -> Router {
    davhaven_dav::wellknown_router(services(), &edge())
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }
}

fn basic(login: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{login}:{password}"))
    )
}

async fn send(app: &Router, method: &str, path: &str, authorization: Option<&str>) -> Answer {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    let response = app.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
    let (parts, body) = response.into_parts();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned(),
    }
}

async fn as_anna(method: &str, path: &str) -> Answer {
    send(&dav(), method, path, Some(&basic("anna@acme.example", ANNA_PASSWORD))).await
}

#[tokio::test]
async fn the_well_known_address_redirects_every_method_to_the_dav_entry_point() {
    let app = wellknown();
    for method in ["GET", "HEAD", "POST", "PUT", "DELETE", "PROPFIND", "OPTIONS", "REPORT"] {
        let answer = send(&app, method, "/.well-known/caldav", None).await;
        assert_eq!(answer.status, StatusCode::MOVED_PERMANENTLY, "{method}");
        assert_eq!(
            answer.header("location"),
            "https://cal.example.test/dav/",
            "{method}: the DAV entry point under the public base URL of the fake"
        );
        assert_eq!(answer.body, "", "{method}");
    }
    let elsewhere = send(&app, "GET", "/dav/", None).await;
    assert_eq!(
        elsewhere.status,
        StatusCode::NOT_FOUND,
        "the well-known group serves nothing else"
    );
}

#[tokio::test]
async fn the_well_known_redirect_ignores_the_host_the_request_names() {
    // A redirect built from `Host` or the forwarding headers would send a client that a proxy or an attacker
    // misdirected to a server of their choosing with the credentials it is about to present.
    for (name, value) in [
        ("host", "evil.example"),
        ("x-forwarded-host", "evil.example"),
        ("forwarded", "host=evil.example;proto=http"),
    ] {
        let request = Request::builder()
            .method("PROPFIND")
            .uri("/.well-known/caldav")
            .header(name, value)
            .body(Body::empty())
            .unwrap();
        let response = wellknown().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY, "{name}");
        assert_eq!(
            response.headers()["location"],
            "https://cal.example.test/dav/",
            "{name}: {value}"
        );
    }
}

#[tokio::test]
async fn unauthenticated_requests_are_challenged_with_the_tenant_as_realm() {
    let app = dav();
    let entry = send(&app, "PROPFIND", "/dav/", None).await;
    assert_eq!(entry.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        entry.header("www-authenticate"),
        "Basic realm=\"davhaven\", charset=\"UTF-8\""
    );
    assert_ne!(entry.header("x-request-id"), "");

    let home = send(&app, "PROPFIND", HOME_SLASH, None).await;
    assert_eq!(home.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        home.header("www-authenticate"),
        "Basic realm=\"acme\", charset=\"UTF-8\""
    );

    let wrong = send(&app, "GET", OBJECT, Some(&basic("anna@acme.example", "wrong"))).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let bearer = send(&app, "GET", OBJECT, Some(&format!("Bearer {ADMIN_TOKEN}"))).await;
    assert_eq!(
        bearer.status,
        StatusCode::UNAUTHORIZED,
        "API tokens are not accepted on DAV"
    );
}

#[tokio::test]
async fn logins_of_other_tenants_do_not_reach_a_tenants_paths() {
    let gina = basic("gina@globex.example", GINA_PASSWORD);
    let answer = send(&dav(), "PROPFIND", HOME_SLASH, Some(&gina)).await;
    // The login is valid, so it is no failed authentication; the resources of another tenant are invisible to it (R4).
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn options_is_open_and_lists_the_methods_of_the_resource() {
    let app = dav();
    // Anonymous: a client asks before it knows the realm, and the answer says nothing about the resource itself.
    let cases = [
        (
            OBJECT,
            "OPTIONS, GET, HEAD, PUT, DELETE, MOVE, COPY, PROPFIND, PROPPATCH",
        ),
        (
            COLLECTION_SLASH,
            "OPTIONS, PROPFIND, PROPPATCH, REPORT, MKCALENDAR, MKCOL, DELETE, POST",
        ),
        (
            HOME_SLASH,
            "OPTIONS, PROPFIND, PROPPATCH, REPORT, MKCALENDAR, MKCOL, POST",
        ),
        ("/dav/", "OPTIONS, PROPFIND, REPORT"),
        ("/dav/principals/acme/anna/", "OPTIONS, PROPFIND, REPORT"),
        (INBOX_SLASH, "OPTIONS, PROPFIND, PROPPATCH, REPORT"),
        (OUTBOX_SLASH, "OPTIONS, PROPFIND, POST"),
        (INBOX_ITEM, "OPTIONS, GET, HEAD, PROPFIND, DELETE"),
        (NOTIFICATION, "OPTIONS, GET, HEAD, PROPFIND, DELETE"),
    ];
    for (path, allow) in cases {
        let answer = send(&app, "OPTIONS", path, None).await;
        assert_eq!(answer.status, StatusCode::OK, "{path}");
        assert_eq!(answer.header("allow"), allow, "{path}");
        assert!(
            answer.header("dav").split(", ").any(|token| token == "calendar-access"),
            "{path}: {}",
            answer.header("dav")
        );
        assert_eq!(answer.body, "", "{path}");
    }
}

#[tokio::test]
async fn options_says_nothing_about_whether_a_resource_exists() {
    // OPTIONS is answered from the method table of the path alone: the answer for a resource that exists, one that
    // does not and one of another tenant is the same, with or without credentials (PLAN 2.6).
    let app = dav();
    let anna = basic("anna@acme.example", ANNA_PASSWORD);
    let existing = send(&app, "OPTIONS", OBJECT, None).await;
    for (path, authorization) in [
        ("/dav/calendars/acme/anna/work/missing.ics", None),
        ("/dav/calendars/acme/anna/nope/missing.ics", None),
        ("/dav/calendars/globex/gina/personal/standup.ics", None),
        ("/dav/calendars/globex/gina/personal/standup.ics", Some(anna.as_str())),
        ("/dav/calendars/acme/ben/personal/missing.ics", Some(anna.as_str())),
    ] {
        let answer = send(&app, "OPTIONS", path, authorization).await;
        assert_eq!(answer.status, existing.status, "{path}");
        assert_eq!(answer.header("allow"), existing.header("allow"), "{path}");
        assert_eq!(answer.header("dav"), existing.header("dav"), "{path}");
        assert_eq!(answer.body, "", "{path}");
    }
}

#[tokio::test]
async fn the_items_of_the_collections_of_sharing_and_scheduling_are_handed_to_their_services() {
    // The behavior of the collaboration modules over services that exist is in `protocol/` and in
    // `crates/it/tests/appcore/dav_collaboration.rs`; here the services are a double that records what the router
    // handed them.
    use davhaven_app::services::WritePrecondition;
    use davhaven_app_fake::recorder::{Handed, Recorder};
    use davhaven_domain::ResourcePath;

    let mut services = services();
    let recorder = Recorder::install(&mut services);
    let app = davhaven_dav::router(services, &edge());
    let item = ResourcePath::parse(INBOX_ITEM).unwrap();
    let notification = ResourcePath::parse(NOTIFICATION).unwrap();
    let cases = [
        ("GET", INBOX_ITEM, StatusCode::NOT_FOUND, Handed::InboxGet(item.clone())),
        (
            "HEAD",
            INBOX_ITEM,
            StatusCode::NOT_FOUND,
            Handed::InboxGet(item.clone()),
        ),
        ("DELETE", INBOX_ITEM, StatusCode::NO_CONTENT, Handed::InboxDelete(item)),
        (
            "GET",
            NOTIFICATION,
            StatusCode::NOT_FOUND,
            Handed::GetNotification(notification.clone()),
        ),
        (
            "HEAD",
            NOTIFICATION,
            StatusCode::NOT_FOUND,
            Handed::GetNotification(notification.clone()),
        ),
        (
            "DELETE",
            NOTIFICATION,
            StatusCode::NO_CONTENT,
            Handed::DeleteNotification {
                path: notification,
                conditions: WritePrecondition::none(),
            },
        ),
    ];
    for (method, path, status, handed) in cases {
        recorder.clear();
        let answer = send(&app, method, path, Some(&basic("anna@acme.example", ANNA_PASSWORD))).await;
        assert_eq!(answer.status, status, "{method} {path}");
        assert_eq!(recorder.calls(), [handed], "{method} {path}");
    }
}

#[tokio::test]
async fn a_post_names_its_media_type_before_anything_else_is_judged() {
    // A form on a web page can send `text/plain`, `multipart/form-data` and the URL-encoded form without asking the
    // server first, and a browser sends the credentials it remembers (PLAN 2.15): every POST has to name a media type
    // that a page cannot send. The refusal looks at the request alone, so it is the same for every resource.
    for path in [COLLECTION, HOME, OUTBOX_SLASH] {
        let answer = as_anna("POST", path).await;
        assert_eq!(answer.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{path}");
    }
}

#[tokio::test]
async fn methods_a_resource_does_not_define_answer_405_with_allow() {
    let cases = [
        ("MKCALENDAR", OBJECT),
        ("POST", OBJECT),
        ("PUT", COLLECTION),
        ("GET", COLLECTION),
        ("PUT", "/dav/"),
        ("DELETE", "/dav/principals/acme/anna/"),
        ("PUT", INBOX_SLASH),
        ("GET", OUTBOX_SLASH),
        ("LOCK", OBJECT),
        ("UNLOCK", OBJECT),
        ("PATCH", OBJECT),
        ("TRACE", OBJECT),
    ];
    for (method, path) in cases {
        let answer = as_anna(method, path).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        let allow: Vec<&str> = answer.header("allow").split(", ").collect();
        assert!(allow.contains(&"PROPFIND"), "{method} {path}: {allow:?}");
        assert!(
            !allow.contains(&method),
            "{method} {path}: the method that was refused is not offered: {allow:?}"
        );
        assert!(
            !allow.contains(&"LOCK") && !allow.contains(&"UNLOCK"),
            "{method} {path}: {allow:?}"
        );
    }
}

#[tokio::test]
async fn paths_that_name_no_resource_answer_404() {
    for path in [
        "/dav/nothing/here",
        "/dav/calendars/ACME/anna/",
        "/dav/calendars/acme/Anna/",
        OUTBOX_ITEM,
        TOO_DEEP,
    ] {
        let answer = as_anna("PROPFIND", path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn trailing_slashes_name_the_same_resources() {
    for path in [HOME, HOME_SLASH, COLLECTION, COLLECTION_SLASH, OBJECT, OBJECT_SLASH] {
        let answer = as_anna("OPTIONS", path).await;
        assert_eq!(answer.status, StatusCode::OK, "{path}");
    }
    let static_wins = send(&dav(), "OPTIONS", INBOX, None).await;
    assert!(
        static_wins.header("allow").contains("REPORT"),
        "the inbox is not a calendar called inbox"
    );
    assert!(!static_wins.header("allow").contains("PUT"));
}

#[tokio::test]
async fn oversized_bodies_are_refused_before_they_are_read() {
    let request = Request::builder()
        .method("PUT")
        .uri(OBJECT)
        .header("authorization", basic("anna@acme.example", ANNA_PASSWORD))
        .header("content-length", (2 * 1024 * 1024).to_string())
        .body(Body::empty())
        .unwrap();
    let response = dav().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn foreign_origins_cannot_change_state_through_a_browser() {
    let request = Request::builder()
        .method("PUT")
        .uri(OBJECT)
        .header("authorization", basic("anna@acme.example", ANNA_PASSWORD))
        .header("host", "cal.example.org")
        .header("origin", "https://evil.example")
        .body(Body::empty())
        .unwrap();
    let response = dav().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn request_ids_are_echoed() {
    let answer = as_anna("OPTIONS", OBJECT).await;
    assert_eq!(answer.header("x-request-id"), "018f3c1e-7b2a-7c3d-9e4f-000000000001");
}
