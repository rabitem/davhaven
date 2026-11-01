//! Protocol tests of the management API: the complete router (edge layers, bearer authentication, handlers and
//! problem rendering) over the in-memory fake of the application services (PLAN 3.1, L4).
//!
//! The fake implements principals, calendars and objects; every other service answers `unsupported`, which is the
//! `not-implemented` problem (501) at the API. The tests therefore cover both the happy paths of the wired
//! operations and the mapping of failures.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use davhaven_app::AppServices;
use davhaven_app::error::{AppError, AppResult};
use davhaven_app::services::{
    CallbackParams, ClientConfigKind, ClientConfigResponse, CredentialService, ExternalAccountService, MobileConfig,
    PageRequest, RenderedPage, WebhookService,
};
use davhaven_app_fake::AppServicesExt as _;
use davhaven_app_fake::seed::{ADMIN_TOKEN, ANNA_TOKEN, SYSTEM_TOKEN};
use davhaven_domain::{CredentialId, DeliveryId, ExternalAccountId, PrincipalName, RequestContext, TokenId, WebhookId};
use davhaven_http::{Edge, SequentialRequestIds, Surface};
use davhaven_wire::{
    ApiTokenCreate, ApiTokenCreated, ApiTokenView, AppPasswordCreate, AppPasswordCreated, AppPasswordView,
    AuthorizationUrl, DeliveryView, ExternalAccountView, FeedTokenCreate, FeedTokenCreated, FeedTokenView, Page,
    ProviderView, WebhookCreate, WebhookCreated, WebhookSecretRotated, WebhookView,
};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

#[allow(
    dead_code,
    reason = "the support module is shared with the unit tests of the idempotency layer, which use all of it"
)]
mod support;

const PRINCIPALS: &str = "/api/v1/tenants/acme/principals";
const TEAM_CALENDAR: &str = "/api/v1/tenants/acme/principals/team/calendars/team-calendar";

fn app() -> Router {
    app_with(|_| {})
}

/// The router over the fake application, after `configure` replaced the services a test cares about.
fn app_with(configure: impl FnOnce(&mut AppServices)) -> Router {
    let edge = Edge::new(Surface::Api, Arc::new(SequentialRequestIds::new()));
    let mut services = AppServices::fake();
    // The fake application leaves idempotency unsupported; the batch tests send a key.
    services.idempotency = Arc::new(support::MemoryIdempotency::default());
    configure(&mut services);
    davhaven_api::router(services, &edge)
}

/// What the tests look at in a response.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }
}

/// A request under construction.
struct Call<'a> {
    method: &'a str,
    path: String,
    token: Option<&'a str>,
    headers: Vec<(&'a str, String)>,
    body: Option<(&'a str, Vec<u8>)>,
}

fn call(method: &str, path: impl Into<String>) -> Call<'_> {
    Call {
        method,
        path: path.into(),
        token: Some(ADMIN_TOKEN),
        headers: Vec::new(),
        body: None,
    }
}

impl<'a> Call<'a> {
    fn token(mut self, token: Option<&'a str>) -> Self {
        self.token = token;
        self
    }

    fn header(mut self, name: &'a str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn json(mut self, body: &Value) -> Self {
        self.body = Some(("application/json", body.to_string().into_bytes()));
        self
    }

    fn body(mut self, content_type: &'a str, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some((content_type, body.into()));
        self
    }

    async fn send(self, app: &Router) -> Answer {
        let mut request = Request::builder().method(self.method).uri(self.path);
        if let Some(token) = self.token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in self.headers {
            request = request.header(name, value);
        }
        let body = match self.body {
            Some((content_type, bytes)) => {
                request = request.header("content-type", content_type);
                Body::from(bytes)
            }
            None => Body::empty(),
        };
        let response = app.clone().oneshot(request.body(body).unwrap()).await.unwrap();
        let (parts, body) = response.into_parts();
        Answer {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes().to_vec(),
        }
    }
}

#[tokio::test]
async fn requests_without_a_token_are_401_problems_with_a_challenge() {
    let app = app();
    let answer = call("GET", PRINCIPALS).token(None).send(&app).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.header("www-authenticate"), "Bearer realm=\"davhaven\"");
    assert_eq!(answer.header("content-type"), "application/problem+json");
    assert_eq!(answer.code(), "unauthenticated");
    assert_eq!(answer.json()["type"], "urn:davhaven:problem:unauthenticated");
    let id = answer.header("x-request-id").to_owned();
    assert_eq!(answer.json()["request_id"], id.as_str());

    let wrong = call("GET", PRINCIPALS)
        .token(Some("dvh_pat_nobody_nothing"))
        .send(&app)
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_client_request_id_is_echoed_in_header_and_problem() {
    let id = "11111111-2222-7333-8444-555555555555";
    let answer = call("GET", "/api/v1/nope")
        .header("x-request-id", id)
        .send(&app())
        .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.header("x-request-id"), id);
    assert_eq!(answer.json()["request_id"], id);
}

#[tokio::test]
async fn unknown_paths_are_404_and_wrong_methods_405_problems() {
    let app = app();
    let missing = call("GET", "/api/v1/not-a-resource").send(&app).await;
    assert_eq!(
        (missing.status, missing.code().as_str()),
        (StatusCode::NOT_FOUND, "not-found")
    );
    let outside = call("GET", "/elsewhere").send(&app).await;
    assert_eq!(outside.status, StatusCode::NOT_FOUND);

    let wrong = call("POST", "/api/v1/tenants/acme/principals/anna").send(&app).await;
    assert_eq!(wrong.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(wrong.code(), "method-not-allowed");
    for method in ["GET", "PUT", "PATCH", "DELETE"] {
        assert!(
            wrong.header("allow").contains(method),
            "{method} in {}",
            wrong.header("allow")
        );
    }
}

#[tokio::test]
async fn malformed_keys_in_the_path_name_no_resource() {
    let app = app();
    for (method, path) in [
        ("GET", "/api/v1/tenants/acme/principals/Not%20Valid"),
        ("GET", "/api/v1/tenants/acme/principals/UPPER"),
        (
            "DELETE",
            "/api/v1/tenants/acme/principals/anna/app-passwords/not-a-uuid",
        ),
    ] {
        let answer = call(method, path).send(&app).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert!(
            !answer.json().to_string().contains("Valid"),
            "the segment is not echoed: {path}"
        );
    }
}

#[tokio::test]
async fn tokens_of_another_tenant_or_without_the_scope_are_refused() {
    let app = app();
    let other_tenant = call("GET", "/api/v1/tenants/globex/principals").send(&app).await;
    assert_eq!(
        (other_tenant.status, other_tenant.code().as_str()),
        (StatusCode::NOT_FOUND, "not-found"),
        "a valid token on the path of another tenant: its resources are invisible to the token (R4), not a reason \
         to doubt the token"
    );
    assert_eq!(
        other_tenant.header("www-authenticate"),
        "",
        "it is not a failed authentication, so no challenge"
    );
    let principal_token = call("GET", PRINCIPALS).token(Some(ANNA_TOKEN)).send(&app).await;
    assert_eq!(principal_token.status, StatusCode::FORBIDDEN);
    assert_eq!(principal_token.code(), "forbidden");
    let system_token = call("GET", PRINCIPALS).token(Some(SYSTEM_TOKEN)).send(&app).await;
    assert_eq!(
        system_token.status,
        StatusCode::FORBIDDEN,
        "system tokens only manage tenants"
    );
}

#[tokio::test]
async fn services_that_have_not_landed_answer_501_not_implemented() {
    let app = app();
    let unsupported = [
        ("GET", "/api/v1/tenants", Some(SYSTEM_TOKEN)),
        ("GET", "/api/v1/tenants/acme/webhooks", None),
        ("GET", "/api/v1/tenants/acme/api-tokens", None),
        ("GET", "/api/v1/tenants/acme/audit-events", None),
        ("GET", "/api/v1/tenants/acme/outbox", None),
        ("GET", "/api/v1/tenants/acme/providers", None),
        ("GET", "/api/v1/tenants/acme/principals/anna/app-passwords", None),
        (
            "GET",
            "/api/v1/tenants/acme/principals/anna/client-config/generic",
            None,
        ),
        (
            "GET",
            "/api/v1/tenants/acme/principals/anna/calendars/work/grants",
            None,
        ),
    ];
    for (method, path, token) in unsupported {
        let answer = call(method, path).token(token.or(Some(ADMIN_TOKEN))).send(&app).await;
        assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED, "{path}");
        assert_eq!(answer.code(), "not-implemented", "{path}");
        assert_eq!(answer.json()["status"], 501);
    }
}

#[tokio::test]
async fn the_bindings_of_a_home_are_listed_and_restoring_a_visible_one_changes_nothing() {
    let app = app();
    let listed = call("GET", format!("{PRINCIPALS}/anna/bindings")).send(&app).await;
    assert_eq!(listed.status, StatusCode::OK);
    let page = listed.json();
    let items = page["items"].as_array().unwrap();
    let slugs: Vec<&str> = items.iter().map(|item| item["slug"].as_str().unwrap()).collect();
    assert!(slugs.contains(&"personal") && slugs.contains(&"work"), "{slugs:?}");
    let work = items.iter().find(|item| item["slug"] == "work").unwrap();
    assert_eq!(work["principal"], "anna");
    assert_eq!(work["owner"], "anna");
    assert_eq!(work["calendar"], "work");
    assert_eq!(work["hidden"], false);
    assert_eq!(work["required"], false);
    assert!(
        work["dav_url"]
            .as_str()
            .unwrap()
            .ends_with("/dav/calendars/acme/anna/work/"),
        "{work}"
    );
    let hidden = call("GET", format!("{PRINCIPALS}/anna/bindings?hidden=true"))
        .send(&app)
        .await;
    assert_eq!(hidden.status, StatusCode::OK);
    assert!(
        hidden.json()["items"].as_array().unwrap().is_empty(),
        "nothing is hidden"
    );

    let restored = call("POST", format!("{PRINCIPALS}/anna/bindings/work/restore"))
        .send(&app)
        .await;
    assert_eq!(restored.status, StatusCode::OK);
    assert!(
        restored.header("etag").is_empty(),
        "a binding cannot be fetched or conditionally changed on its own, so it has no ETag"
    );
    assert_eq!(restored.json()["hidden"], false);
    let missing = call("POST", format!("{PRINCIPALS}/anna/bindings/no-such/restore"))
        .send(&app)
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.code(), "not-found");
    // A person's own token does not administer a home, not even their own.
    let own = call("GET", format!("{PRINCIPALS}/anna/bindings"))
        .token(Some(ANNA_TOKEN))
        .send(&app)
        .await;
    assert_eq!(own.status, StatusCode::FORBIDDEN);
    assert_eq!(own.code(), "forbidden");
}

#[tokio::test]
async fn listings_are_cursor_pages_with_a_link_to_the_next_one() {
    let app = app();
    let first = call("GET", format!("{PRINCIPALS}?limit=2&kind=user")).send(&app).await;
    assert_eq!(first.status, StatusCode::OK);
    let page = first.json();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    let cursor = page["next_cursor"].as_str().unwrap().to_owned();
    let link = first.header("link").to_owned();
    assert!(
        link.starts_with("</api/v1/tenants/acme/principals?") && link.ends_with("; rel=\"next\""),
        "a relative reference, which names the next page on the origin the client reached the API on: {link}"
    );
    assert!(
        link.contains("limit=2") && link.contains("kind=user") && link.contains("cursor="),
        "{link}"
    );

    let second = call("GET", format!("{PRINCIPALS}?limit=2&kind=user&cursor={cursor}"))
        .send(&app)
        .await;
    assert_eq!(second.status, StatusCode::OK);
    let names: Vec<String> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second.json()["items"].as_array().unwrap())
        .map(|item| item["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        names.len(),
        3,
        "anna, ben and cara are the users of the standard world: {names:?}"
    );
}

#[tokio::test]
async fn bad_query_parameters_are_400() {
    let app = app();
    for query in [
        "limit=abc",
        "limit=-1",
        "limit=0",
        "limit=4294967296",
        "cursor=has%20space",
        "kind=wizard",
    ] {
        let answer = call("GET", format!("{PRINCIPALS}?{query}")).send(&app).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(answer.code(), "bad-request", "{query}");
    }
}

#[tokio::test]
async fn principals_are_created_replaced_patched_and_deleted_with_etags() {
    let app = app();
    let body = json!({"kind": "user", "display_name": "Dora", "email": "dora@acme.example"});
    let created = call("PUT", format!("{PRINCIPALS}/dora")).json(&body).send(&app).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert!(
        created
            .header("location")
            .ends_with("/api/v1/tenants/acme/principals/dora")
    );
    let etag = created.header("etag").to_owned();
    assert!(etag.starts_with("\"v"), "{etag}");
    assert_eq!(created.json()["name"], "dora");

    let again = call("PUT", format!("{PRINCIPALS}/dora")).json(&body).send(&app).await;
    assert_eq!(again.status, StatusCode::OK);
    assert!(again.headers.get("location").is_none());

    let patch = json!({"display_name": "Dora D."});
    let patched = call("PATCH", format!("{PRINCIPALS}/dora"))
        .body("application/merge-patch+json", patch.to_string())
        .header("if-match", etag.clone())
        .send(&app)
        .await;
    assert_eq!(patched.status, StatusCode::OK);
    assert_eq!(patched.json()["display_name"], "Dora D.");
    assert_ne!(patched.header("etag"), etag);

    let stale = call("PATCH", format!("{PRINCIPALS}/dora"))
        .json(&patch)
        .header("if-match", etag.clone())
        .send(&app)
        .await;
    assert_eq!(
        (stale.status, stale.code().as_str()),
        (StatusCode::PRECONDITION_FAILED, "precondition-failed")
    );
}

#[tokio::test]
async fn deleting_a_principal_needs_if_match_and_hides_it_afterwards() {
    let app = app();
    let body = json!({"kind": "user", "display_name": "Eli"});
    let created = call("PUT", format!("{PRINCIPALS}/eli")).json(&body).send(&app).await;
    let etag = created.header("etag").to_owned();

    let blind = call("DELETE", format!("{PRINCIPALS}/eli")).send(&app).await;
    assert_eq!(
        (blind.status, blind.code().as_str()),
        (StatusCode::PRECONDITION_REQUIRED, "precondition-required")
    );
    let star = call("DELETE", format!("{PRINCIPALS}/eli"))
        .header("if-match", "*")
        .send(&app)
        .await;
    assert_eq!(star.status, StatusCode::PRECONDITION_FAILED);
    let deleted = call("DELETE", format!("{PRINCIPALS}/eli"))
        .header("if-match", etag)
        .send(&app)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(deleted.body.len(), 0);
    let gone = call("GET", format!("{PRINCIPALS}/eli")).send(&app).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn memberships_are_read_replaced_and_changed() {
    let app = app();
    let members = call("GET", format!("{PRINCIPALS}/team/members")).send(&app).await;
    assert_eq!(members.json()["members"], json!(["anna", "ben"]));
    let replaced = call("PUT", format!("{PRINCIPALS}/team/members"))
        .json(&json!({"members": ["anna"]}))
        .send(&app)
        .await;
    assert_eq!(replaced.status, StatusCode::OK);
    assert_eq!(replaced.json()["members"], json!(["anna"]));
    let added = call("PUT", format!("{PRINCIPALS}/team/members/ben")).send(&app).await;
    assert_eq!(added.status, StatusCode::NO_CONTENT);
    let removed = call("DELETE", format!("{PRINCIPALS}/team/members/anna"))
        .send(&app)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let now = call("GET", format!("{PRINCIPALS}/team/members")).send(&app).await;
    assert_eq!(now.json()["members"], json!(["ben"]));
}

#[tokio::test]
async fn bodies_are_checked_before_the_service_sees_them() {
    let app = app();
    let path = format!("{PRINCIPALS}/fay");
    let not_json = call("PUT", path.clone())
        .body("application/json", "{not json")
        .send(&app)
        .await;
    assert_eq!(
        (not_json.status, not_json.code().as_str()),
        (StatusCode::BAD_REQUEST, "bad-request")
    );
    let empty = call("PUT", path.clone()).body("application/json", "").send(&app).await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST);
    let wrong_type = call("PUT", path.clone()).body("text/plain", "{}").send(&app).await;
    assert_eq!(
        (wrong_type.status, wrong_type.code().as_str()),
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported-media-type")
    );
    let missing = call("PUT", path.clone())
        .json(&json!({"display_name": "Fay"}))
        .send(&app)
        .await;
    assert_eq!(
        (missing.status, missing.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "validation-failed")
    );
    assert_eq!(missing.json()["errors"][0]["code"], "invalid-body");
    let unknown = call("PUT", path.clone())
        .json(&json!({"kind": "user", "display_name": "Fay", "nickname": "f"}))
        .send(&app)
        .await;
    assert_eq!(unknown.status, StatusCode::UNPROCESSABLE_ENTITY);
    let not_an_object = call("PATCH", path)
        .body("application/merge-patch+json", "[1]")
        .send(&app)
        .await;
    assert_eq!(not_an_object.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn oversized_bodies_are_413() {
    let app = app();
    let filler = "x".repeat(1024 * 1024 + 1);
    let body = json!({"kind": "user", "display_name": filler});
    let answer = call("PUT", format!("{PRINCIPALS}/big")).json(&body).send(&app).await;
    assert_eq!(
        (answer.status, answer.code().as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, "payload-too-large")
    );
    let patch = call("PATCH", format!("{PRINCIPALS}/anna"))
        .body(
            "application/merge-patch+json",
            json!({"display_name": "x".repeat(1024 * 1024 + 1)}).to_string(),
        )
        .send(&app)
        .await;
    assert_eq!(
        (patch.status, patch.code().as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, "payload-too-large"),
        "a merge patch is read with the limit of JSON bodies"
    );
}

#[tokio::test]
async fn batches_are_read_with_the_batch_limit_and_not_the_json_limit() {
    let app = app();
    let path = format!("{TEAM_CALENDAR}/objects/batch");
    let start = json!({"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"});
    // Over the 1 MiB of a JSON body and under the 10 MiB of a batch: the body is read and the batch is judged.
    let description = "x".repeat(2 * 1024 * 1024);
    let large = json!({"items": [
        {"external_key": "big", "event": {"summary": "Big", "description": description, "start": start}}
    ]});
    let read = call("POST", path.clone())
        .header("idempotency-key", "large-batch")
        .json(&large)
        .send(&app)
        .await;
    assert_eq!(
        read.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&read.body[..read.body.len().min(500)])
    );
    assert_eq!(read.json()["results"][0]["outcome"], "created");
    let filler = "x".repeat(10 * 1024 * 1024 + 1);
    let too_large = json!({"items": [
        {"external_key": "huge", "event": {"summary": "Huge", "description": filler, "start": start}}
    ]});
    let refused = call("POST", path)
        .header("idempotency-key", "huge-batch")
        .json(&too_large)
        .send(&app)
        .await;
    assert_eq!(
        (refused.status, refused.code().as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, "payload-too-large")
    );
    let absent = call("GET", format!("{TEAM_CALENDAR}/objects/by-key/huge"))
        .send(&app)
        .await;
    assert_eq!(absent.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn calendars_are_listed_read_and_created() {
    let app = app();
    let listed = call("GET", "/api/v1/tenants/acme/principals/anna/calendars")
        .send(&app)
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    let listed_json = listed.json();
    let slugs: Vec<&str> = listed_json["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["slug"].as_str())
        .collect();
    assert!(slugs.contains(&"work"), "{slugs:?}");

    let work = call("GET", "/api/v1/tenants/acme/principals/anna/calendars/work")
        .send(&app)
        .await;
    assert_eq!(work.status, StatusCode::OK);
    assert!(work.header("etag").starts_with("\"v"));
    assert_eq!(work.json()["kind"], "user");

    let created = call("PUT", "/api/v1/tenants/acme/principals/anna/calendars/holidays")
        .json(&json!({"display_name": "Holidays"}))
        .send(&app)
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert!(
        created
            .header("location")
            .ends_with("/principals/anna/calendars/holidays")
    );
}

#[tokio::test]
async fn events_are_written_read_listed_and_deleted_by_external_key() {
    let app = app();
    let key = format!("{TEAM_CALENDAR}/objects/by-key/standup-1");
    let event =
        json!({"summary": "Standup", "start": {"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"}});
    let created = call("PUT", key.clone()).json(&event).send(&app).await;
    assert_eq!(
        created.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    let etag = created.header("etag").to_owned();
    assert!(
        etag.starts_with('"') && !etag.starts_with("\"v"),
        "events carry content ETags: {etag}"
    );
    assert_eq!(created.json()["external_key"], "standup-1");
    assert!(created.header("location").ends_with("/objects/by-key/standup-1"));

    let read = call("GET", key.clone()).send(&app).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.header("etag"), etag);
    assert_eq!(read.json()["summary"], "Standup");

    let mismatch = call("PUT", key.clone())
        .json(&json!({"external_key": "other", "summary": "x"}))
        .send(&app)
        .await;
    assert_eq!(
        (mismatch.status, mismatch.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "validation-failed")
    );
    assert_eq!(mismatch.json()["errors"][0]["pointer"], "/external_key");

    let stale = call("PUT", key.clone())
        .header("if-match", "\"nope\"")
        .json(&event)
        .send(&app)
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);

    let listed = call("GET", format!("{TEAM_CALENDAR}/objects?external_key=standup-1"))
        .send(&app)
        .await;
    assert_eq!(listed.json()["items"].as_array().unwrap().len(), 1);

    let deleted = call("DELETE", key.clone()).header("if-match", etag).send(&app).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(call("GET", key).send(&app).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_event_write_removes_a_field_sent_as_null_and_refuses_null_for_the_start() {
    let app = app();
    let key = format!("{TEAM_CALENDAR}/objects/by-key/standup-2");
    let start = json!({"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"});
    let created = call("PUT", key.clone())
        .json(&json!({"summary": "Standup", "location": "Room 1", "description": "Daily", "start": start}))
        .send(&app)
        .await;
    assert_eq!(
        created.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    assert_eq!(created.json()["location"], "Room 1");

    // RFC 7396: null removes the field, a member that is not sent keeps its value.
    let cleared = call("PUT", key.clone())
        .json(&json!({"location": null}))
        .send(&app)
        .await;
    assert_eq!(
        cleared.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&cleared.body)
    );
    assert!(cleared.json().get("location").is_none(), "{}", cleared.json());
    assert_eq!(cleared.json()["description"], "Daily");
    assert_eq!(cleared.json()["summary"], "Standup");
    let read = call("GET", key.clone()).send(&app).await;
    assert!(read.json().get("location").is_none(), "{}", read.json());
    let kept = call("PUT", key.clone())
        .json(&json!({"summary": "Standup!"}))
        .send(&app)
        .await;
    assert_eq!(kept.json()["description"], "Daily");

    // The fields that cannot be removed refuse null with a 422 that names the field by its pointer.
    for member in ["uid", "start"] {
        let refused = call("PUT", key.clone()).json(&json!({ member: null })).send(&app).await;
        assert_eq!(
            (refused.status, refused.code().as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, "validation-failed"),
            "{member}"
        );
        let error = refused.json()["errors"][0].clone();
        assert_eq!(error["pointer"], format!("/{member}"));
        assert_eq!(error["code"], "not-nullable");
        let message = error["message"].as_str().unwrap().to_owned();
        assert!(message.contains(&format!("`{member}` cannot be null")), "{message}");
    }
    // The instance selector and the sequence are no fields a write removes: null is the same as leaving them out.
    for member in ["recurrence_id", "sequence"] {
        let same = call("PUT", key.clone())
            .json(&json!({"summary": "Standup!", member: null}))
            .send(&app)
            .await;
        assert_eq!(
            same.status,
            StatusCode::OK,
            "{member}: {}",
            String::from_utf8_lossy(&same.body)
        );
        assert_eq!(same.json()["summary"], "Standup!");
    }
    assert_eq!(
        call("GET", key).send(&app).await.json()["summary"],
        "Standup!",
        "a refused write changes nothing"
    );
}

#[tokio::test]
async fn tenant_tokens_reach_group_calendars_but_not_personal_ones() {
    let app = app();
    let personal = call("GET", "/api/v1/tenants/acme/principals/anna/calendars/work/objects")
        .send(&app)
        .await;
    assert_eq!(
        (personal.status, personal.code().as_str()),
        (StatusCode::FORBIDDEN, "forbidden")
    );
    let group = call("GET", format!("{TEAM_CALENDAR}/objects")).send(&app).await;
    assert_eq!(group.status, StatusCode::OK, "{}", String::from_utf8_lossy(&group.body));
    assert!(group.json()["items"].is_array());
}

#[tokio::test]
async fn batches_need_an_idempotency_key_and_apply_all_or_nothing() {
    let app = app();
    let path = format!("{TEAM_CALENDAR}/objects/batch");
    let start = json!({"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"});
    let good = json!({"items": [
        {"external_key": "a", "event": {"summary": "A", "start": start}},
        {"external_key": "b", "event": {"summary": "B", "start": start}}
    ]});
    let no_key = call("POST", path.clone()).json(&good).send(&app).await;
    assert_eq!(
        (no_key.status, no_key.code().as_str()),
        (StatusCode::BAD_REQUEST, "bad-request")
    );
    let bad_key = call("POST", path.clone())
        .header("idempotency-key", "has space")
        .json(&good)
        .send(&app)
        .await;
    assert_eq!(bad_key.status, StatusCode::BAD_REQUEST);

    let applied = call("POST", path.clone())
        .header("idempotency-key", "batch-1")
        .json(&good)
        .send(&app)
        .await;
    assert_eq!(
        applied.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&applied.body)
    );
    let applied_json = applied.json();
    let outcomes: Vec<&str> = applied_json["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["outcome"].as_str())
        .collect();
    assert_eq!(outcomes, vec!["created", "created"]);

    let broken = json!({"items": [
        {"external_key": "c", "event": {"summary": "C", "start": start}},
        {"external_key": "d", "event": {"summary": "D"}}
    ]});
    let rejected = call("POST", path)
        .header("idempotency-key", "batch-2")
        .json(&broken)
        .send(&app)
        .await;
    assert_eq!(
        (rejected.status, rejected.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "validation-failed")
    );
    assert_eq!(rejected.json()["errors"][0]["pointer"], "/items/1");
    let nothing = call("GET", format!("{TEAM_CALENDAR}/objects/by-key/c"))
        .send(&app)
        .await;
    assert_eq!(
        nothing.status,
        StatusCode::NOT_FOUND,
        "the good entry of a rejected batch is not stored"
    );
}

#[tokio::test]
async fn a_batch_item_that_removes_the_start_rejects_the_batch_at_that_item() {
    let app = app();
    let path = format!("{TEAM_CALENDAR}/objects/batch");
    let start = json!({"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"});
    let body = json!({"items": [
        {"external_key": "n1", "event": {"summary": "N1", "start": start}},
        {"external_key": "n2", "event": {"summary": "N2", "location": null, "start": start}},
        {"external_key": "n3", "event": {"summary": "N3", "start": null}}
    ]});
    let rejected = call("POST", path)
        .header("idempotency-key", "batch-null")
        .json(&body)
        .send(&app)
        .await;
    assert_eq!(
        (rejected.status, rejected.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "validation-failed")
    );
    let errors = rejected.json()["errors"].clone();
    assert_eq!(errors.as_array().unwrap().len(), 1, "{errors}");
    assert_eq!(
        errors[0]["pointer"], "/items/2/event/start",
        "the item that carries the null, not the whole body"
    );
    assert_eq!(errors[0]["code"], "not-nullable");
    for key in ["n1", "n2", "n3"] {
        let stored = call("GET", format!("{TEAM_CALENDAR}/objects/by-key/{key}"))
            .send(&app)
            .await;
        assert_eq!(
            stored.status,
            StatusCode::NOT_FOUND,
            "{key}: nothing of a rejected batch is stored"
        );
    }
}

#[tokio::test]
async fn a_repeated_batch_is_replayed_and_a_changed_one_is_refused() {
    let app = app();
    let path = format!("{TEAM_CALENDAR}/objects/batch");
    let start = json!({"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"});
    let body = json!({"items": [{"external_key": "r1", "event": {"summary": "R", "start": start}}]});
    let send = |body: &Value| {
        call("POST", path.clone())
            .header("idempotency-key", "replay-1")
            .json(body)
            .send(&app)
    };

    let first = send(&body).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json()["results"][0]["outcome"], "created");
    assert_eq!(first.header("idempotent-replayed"), "");

    let second = send(&body).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(second.header("idempotent-replayed"), "true");
    assert_eq!(
        second.json(),
        first.json(),
        "the first answer again; running the batch a second time would report the entry as unchanged"
    );

    let other = json!({"items": [{"external_key": "r2", "event": {"summary": "R2", "start": start}}]});
    let reused = send(&other).await;
    assert_eq!(
        (reused.status, reused.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "idempotency-key-reuse")
    );
    let absent = call("GET", format!("{TEAM_CALENDAR}/objects/by-key/r2"))
        .send(&app)
        .await;
    assert_eq!(
        absent.status,
        StatusCode::NOT_FOUND,
        "the refused request wrote nothing"
    );
}

#[tokio::test]
async fn a_failed_batch_does_not_hold_its_key() {
    let app = app();
    let path = format!("{TEAM_CALENDAR}/objects/batch");
    let start = json!({"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"});
    let broken = json!({"items": [{"external_key": "f1", "event": {"summary": "F"}}]});
    let fixed = json!({"items": [{"external_key": "f1", "event": {"summary": "F", "start": start}}]});
    let send = |body: &Value| {
        call("POST", path.clone())
            .header("idempotency-key", "retry-1")
            .json(body)
            .send(&app)
    };

    let refused = send(&broken).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "validation-failed");
    // The key is free again, so the corrected batch is not a reuse of it.
    let applied = send(&fixed).await;
    assert_eq!(
        applied.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&applied.body)
    );
    assert_eq!(applied.header("idempotent-replayed"), "");
}

/// Provider accounts whose provider is switched off: `google` answers `feature-not-enabled`, every other name is an
/// ordinary conflict.
struct DisabledProviders;

#[async_trait]
impl ExternalAccountService for DisabledProviders {
    async fn providers(&self, _ctx: &RequestContext) -> AppResult<Vec<ProviderView>> {
        Ok(Vec::new())
    }

    async fn start(
        &self,
        _ctx: &RequestContext,
        provider: &str,
        _principal: &PrincipalName,
    ) -> AppResult<AuthorizationUrl> {
        Err(if provider == "google" {
            AppError::feature_not_enabled()
        } else {
            AppError::conflict()
        })
    }

    async fn complete(
        &self,
        _ctx: &RequestContext,
        _provider: &str,
        _params: CallbackParams,
    ) -> AppResult<RenderedPage> {
        Err(AppError::feature_not_enabled())
    }

    async fn list(&self, _ctx: &RequestContext, _page: PageRequest) -> AppResult<Page<ExternalAccountView>> {
        Ok(Page::empty())
    }

    async fn delete(&self, _ctx: &RequestContext, _id: ExternalAccountId) -> AppResult<()> {
        Err(AppError::not_found())
    }
}

#[tokio::test]
async fn a_disabled_feature_is_a_409_problem_with_its_own_code() {
    let app = app_with(|services| services.external_accounts = Arc::new(DisabledProviders));
    let connect = |provider: &str| {
        call("POST", "/api/v1/tenants/acme/external-accounts")
            .json(&json!({"provider": provider, "principal": "anna"}))
            .send(&app)
    };
    let disabled = connect("google").await;
    assert_eq!(disabled.status, StatusCode::CONFLICT);
    assert_eq!(disabled.code(), "feature-not-enabled");
    assert_eq!(disabled.json()["type"], "urn:davhaven:problem:feature-not-enabled");
    assert_eq!(disabled.header("content-type"), "application/problem+json");
    assert_eq!(disabled.json()["detail"], "This feature is not enabled.");

    let ordinary = connect("other").await;
    assert_eq!(ordinary.status, StatusCode::CONFLICT);
    assert_eq!(
        ordinary.code(),
        "conflict",
        "an ordinary conflict keeps the generic row"
    );
}

#[tokio::test]
async fn invalid_batches_are_rejected_with_a_pointer() {
    let app = app();
    let both = json!({"items": [{"external_key": "a", "ical": "x", "event": {}}]});
    let answer = call("POST", format!("{TEAM_CALENDAR}/objects/batch"))
        .header("idempotency-key", "k")
        .json(&both)
        .send(&app)
        .await;
    assert_eq!(
        (answer.status, answer.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "validation-failed")
    );
    assert_eq!(answer.json()["errors"][0]["pointer"], "/items/0");
    assert_eq!(answer.json()["errors"][0]["code"], "invalid-batch");
}

#[tokio::test]
async fn the_changes_feed_reports_a_token_and_refuses_garbled_ones() {
    let app = app();
    let feed = call("GET", format!("{TEAM_CALENDAR}/changes")).send(&app).await;
    assert_eq!(feed.status, StatusCode::OK);
    let token = feed.json()["sync_token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("urn:davhaven:sync:"));
    let again = call("GET", format!("{TEAM_CALENDAR}/changes?since={token}"))
        .send(&app)
        .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json()["changes"], json!([]));

    let garbled = call("GET", format!("{TEAM_CALENDAR}/changes?since=nonsense"))
        .send(&app)
        .await;
    assert_eq!(
        (garbled.status, garbled.code().as_str()),
        (StatusCode::GONE, "sync-token-expired")
    );
}

#[tokio::test]
async fn unauthenticated_and_bad_requests_never_reach_the_services() {
    let app = app();
    let body = json!({"kind": "user", "display_name": "Zed"});
    let denied = call("PUT", format!("{PRINCIPALS}/zed"))
        .token(None)
        .json(&body)
        .send(&app)
        .await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    let wrong_token = call("PUT", format!("{PRINCIPALS}/zed"))
        .token(Some("dvh_pat_nobody_nothing"))
        .json(&body)
        .send(&app)
        .await;
    assert_eq!(wrong_token.status, StatusCode::UNAUTHORIZED);
    let not_json = call("PUT", format!("{PRINCIPALS}/zed"))
        .body("text/plain", body.to_string())
        .send(&app)
        .await;
    assert_eq!(not_json.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let wrong_shape = call("PUT", format!("{PRINCIPALS}/zed"))
        .json(&json!({"kind": "user", "display_name": "Zed", "unknown": true}))
        .send(&app)
        .await;
    assert_eq!(wrong_shape.status, StatusCode::UNPROCESSABLE_ENTITY);
    let listed = call("GET", format!("{PRINCIPALS}?limit=100")).send(&app).await;
    let listed_json = listed.json();
    let names: Vec<&str> = listed_json["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert!(!names.contains(&"zed"), "the refused writes left no trace");
    assert_eq!(
        call("GET", format!("{PRINCIPALS}/zed")).send(&app).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_resources_of_another_tenant_answer_the_same_404_whether_they_exist_or_not() {
    let app = app();
    let globex = "/api/v1/tenants/globex/principals";
    let body = json!({"kind": "user", "display_name": "Mallory"});
    let start = json!({"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"});
    for name in ["gina", "nobody"] {
        let requests = [
            call("GET", format!("{globex}/{name}")),
            call("PUT", format!("{globex}/{name}")).json(&body),
            call("PATCH", format!("{globex}/{name}"))
                .body("application/merge-patch+json", json!({"display_name": "x"}).to_string()),
            call("DELETE", format!("{globex}/{name}")).header("if-match", "\"v1\""),
            call("GET", format!("{globex}/{name}/calendars")),
            call("POST", format!("{globex}/{name}/calendars/personal/objects/batch"))
                .header("idempotency-key", "foreign")
                .json(&json!({"items": [{"external_key": "a", "event": {"summary": "A", "start": start}}]})),
        ];
        for request in requests {
            let label = format!("{} {}", request.method, request.path);
            let answer = request.send(&app).await;
            assert_eq!(
                (answer.status, answer.code().as_str()),
                (StatusCode::NOT_FOUND, "not-found"),
                "{label}: {}",
                String::from_utf8_lossy(&answer.body)
            );
            assert_eq!(answer.header("www-authenticate"), "", "{label}");
            let mut json = answer.json();
            json.as_object_mut().unwrap().remove("request_id");
            assert_eq!(
                json,
                json!({"type": "urn:davhaven:problem:not-found", "title": "Resource not found", "status": 404,
                       "code": "not-found"}),
                "{label}: nothing tells an existing resource of another tenant from a missing one"
            );
        }
    }
}

/// The path of a route with valid keys for every parameter.
fn concrete(template: &str) -> String {
    let id = "018f3c1e-7b2a-7c3d-9e4f-0123456789ab";
    let path = template
        .replace("{tenant}", "acme")
        .replace("{principal}", "anna")
        .replace("{group}", "team")
        .replace("{member}", "ben")
        .replace("{calendar}", "work")
        .replace("{grantee}", "ben")
        .replace("{binding}", "work")
        .replace("{external_key}", "ext-1")
        .replace("{delivery}", id)
        .replace("{id}", id);
    format!("/api/v1{path}")
}

#[tokio::test]
async fn every_operation_is_wired_and_answers_only_what_the_contract_documents() {
    let app = app();
    let document = serde_json::to_value(davhaven_api::document()).unwrap();
    for route in davhaven_api::openapi::ROUTES {
        let answer = call(route.method, concrete(route.path))
            .json(&json!({}))
            .send(&app)
            .await;
        let name = route.operation_id;
        assert_ne!(
            answer.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{name}: the method is registered"
        );
        assert_ne!(
            answer.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{name}: {}",
            String::from_utf8_lossy(&answer.body)
        );
        let key_problem = answer.status == StatusCode::NOT_FOUND
            && answer.json()["detail"] == "A segment of the path is not a valid key.";
        assert!(
            !key_problem,
            "{name}: the path parameters of the route and of the handler differ"
        );
        if answer.status.is_client_error() || answer.status.is_server_error() {
            assert_eq!(answer.header("content-type"), "application/problem+json", "{name}");
        }
        if answer.status == StatusCode::NOT_IMPLEMENTED {
            continue;
        }
        let documented = &document["paths"][route.path][route.method.to_ascii_lowercase()]["responses"];
        let status = answer.status.as_u16().to_string();
        assert!(
            documented.get(&status).is_some(),
            "{name} answered {status}, which its documentation does not list: {}",
            String::from_utf8_lossy(&answer.body)
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Secrets never reach the idempotency table
// ---------------------------------------------------------------------------------------------------------------

/// What the services that mint secrets answer, so that every secret-bearing operation can run through the real
/// router, handlers and idempotency layer. Everything else is unsupported.
struct Minting;

/// A wire value built from its JSON form, so that the test does not depend on the field order of the types.
fn wire<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

const SOME_ID: &str = "018f3c1e-7b2a-7c3d-9e4f-0123456789ab";

fn token_view() -> Value {
    json!({"id": SOME_ID, "kind": "tenant", "label": "ci", "scopes": ["principals:read"],
           "prefix": "abcdefghijkl", "created_at": "2027-01-01T00:00:00Z"})
}

fn feed_created() -> FeedTokenCreated {
    wire(json!({
        "token": {"id": SOME_ID, "mode": "busy", "calendar_ids": [], "prefix": "abcdefghijkl",
                  "created_at": "2027-01-01T00:00:00Z"},
        "feed_url": "https://cal.example.org/feeds/dvh_feed_abcdefghijkl_secret.ics",
    }))
}

#[async_trait]
impl CredentialService for Minting {
    async fn list_app_passwords(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: PageRequest,
    ) -> AppResult<Page<AppPasswordView>> {
        Err(AppError::unsupported())
    }

    async fn create_app_password(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: AppPasswordCreate,
    ) -> AppResult<AppPasswordCreated> {
        Ok(wire(json!({"id": SOME_ID, "label": "iPhone", "prefix": "abcd-efgh",
                       "password": "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh", "created_at": "2027-01-01T00:00:00Z"})))
    }

    async fn revoke_app_password(&self, _: &RequestContext, _: &PrincipalName, _: CredentialId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn list_api_tokens(&self, _: &RequestContext, _: PageRequest) -> AppResult<Page<ApiTokenView>> {
        Err(AppError::unsupported())
    }

    async fn create_api_token(&self, _: &RequestContext, _: ApiTokenCreate) -> AppResult<ApiTokenCreated> {
        Ok(wire(
            json!({"token": token_view(), "secret": "dvh_pat_abcdefghijkl_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_abcde"}),
        ))
    }

    async fn revoke_api_token(&self, _: &RequestContext, _: TokenId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn list_feed_tokens(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: PageRequest,
    ) -> AppResult<Page<FeedTokenView>> {
        Err(AppError::unsupported())
    }

    async fn create_feed_token(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: FeedTokenCreate,
    ) -> AppResult<FeedTokenCreated> {
        Ok(feed_created())
    }

    async fn revoke_feed_token(&self, _: &RequestContext, _: &PrincipalName, _: TokenId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn rotate_feed_token(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: TokenId,
    ) -> AppResult<FeedTokenCreated> {
        Ok(feed_created())
    }

    async fn client_config(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        kind: ClientConfigKind,
    ) -> AppResult<ClientConfigResponse> {
        match kind {
            ClientConfigKind::AppleMobileconfig(_) => Ok(ClientConfigResponse::Mobileconfig(MobileConfig {
                filename: "calendar.mobileconfig".to_owned(),
                body: b"<plist>with an app password</plist>".to_vec(),
            })),
            ClientConfigKind::Davx5(_) => Ok(ClientConfigResponse::Davx5(wire(
                json!({"app_password_id": SOME_ID, "login_uri": "davx5://anna:abcd-efgh@cal.example.org/dav"}),
            ))),
            ClientConfigKind::Generic => Err(AppError::unsupported()),
        }
    }
}

fn webhook_view() -> Value {
    json!({"id": SOME_ID, "url": "https://hooks.example.org/in", "events": [], "include_details": false,
           "active": true, "failure_count": 0, "created_at": "2027-01-01T00:00:00Z",
           "updated_at": "2027-01-01T00:00:00Z", "version": 1})
}

#[async_trait]
impl WebhookService for Minting {
    async fn create(&self, _: &RequestContext, _: WebhookCreate) -> AppResult<WebhookCreated> {
        Ok(wire(json!({"webhook": webhook_view(), "secret": "whsec_c2VjcmV0"})))
    }

    async fn list(&self, _: &RequestContext, _: PageRequest) -> AppResult<Page<WebhookView>> {
        Err(AppError::unsupported())
    }

    async fn get(&self, _: &RequestContext, _: WebhookId) -> AppResult<WebhookView> {
        Err(AppError::unsupported())
    }

    async fn patch(
        &self,
        _: &RequestContext,
        _: WebhookId,
        _: davhaven_app::services::MergePatch,
        _: davhaven_app::services::Conditions,
    ) -> AppResult<WebhookView> {
        Err(AppError::unsupported())
    }

    async fn delete(&self, _: &RequestContext, _: WebhookId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn rotate_secret(&self, _: &RequestContext, _: WebhookId) -> AppResult<WebhookSecretRotated> {
        Ok(wire(
            json!({"secret": "whsec_bmV3", "rotated_at": "2027-01-01T00:00:00Z"}),
        ))
    }

    async fn ping(&self, _: &RequestContext, _: WebhookId) -> AppResult<DeliveryView> {
        Err(AppError::unsupported())
    }

    async fn deliveries(&self, _: &RequestContext, _: WebhookId, _: PageRequest) -> AppResult<Page<DeliveryView>> {
        Err(AppError::unsupported())
    }

    async fn redeliver(&self, _: &RequestContext, _: WebhookId, _: DeliveryId) -> AppResult<DeliveryView> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl ExternalAccountService for Minting {
    async fn providers(&self, _: &RequestContext) -> AppResult<Vec<ProviderView>> {
        Err(AppError::unsupported())
    }

    async fn start(&self, _: &RequestContext, _: &str, _: &PrincipalName) -> AppResult<AuthorizationUrl> {
        Ok(wire(
            json!({"authorization_url": "https://accounts.example/consent?state=abc"}),
        ))
    }

    async fn complete(&self, _: &RequestContext, _: &str, _: CallbackParams) -> AppResult<RenderedPage> {
        Err(AppError::unsupported())
    }

    async fn list(&self, _: &RequestContext, _: PageRequest) -> AppResult<Page<ExternalAccountView>> {
        Err(AppError::unsupported())
    }

    async fn delete(&self, _: &RequestContext, _: ExternalAccountId) -> AppResult<()> {
        Err(AppError::unsupported())
    }
}

/// The request body each secret-minting operation takes (none for the rotations).
fn secret_request_body(operation: &str) -> Option<Value> {
    match operation {
        "createAppPassword" => Some(json!({"label": "iPhone"})),
        "createApiToken" => Some(json!({"kind": "tenant", "label": "ci", "scopes": ["principals:read"]})),
        "createFeedToken" => Some(json!({"mode": "busy", "calendar_ids": []})),
        "createAppleMobileconfig" | "createDavx5Config" => {
            Some(json!({"app_password_label": "iPhone", "include_feed": false}))
        }
        "createWebhook" => Some(json!({"url": "https://hooks.example.org/in", "events": []})),
        "createExternalAccount" => Some(json!({"provider": "google", "principal": "anna"})),
        _ => None,
    }
}

#[tokio::test]
async fn every_operation_that_returns_a_secret_is_no_store_and_never_reaches_the_idempotency_table() {
    // The operations come from the document itself: every POST whose success response declares `Cache-Control`.
    let document = serde_json::to_value(davhaven_api::document()).unwrap();
    let mut secret_operations: Vec<(String, String)> = Vec::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        let Some(operation) = item.get("post") else { continue };
        let declares_cache_control = operation["responses"]
            .as_object()
            .unwrap()
            .iter()
            .any(|(status, response)| {
                status.starts_with('2')
                    && response["headers"]
                        .as_object()
                        .is_some_and(|headers| headers.keys().any(|name| name.eq_ignore_ascii_case("cache-control")))
            });
        if declares_cache_control {
            secret_operations.push((operation["operationId"].as_str().unwrap().to_owned(), path.clone()));
        }
    }
    secret_operations.sort();
    let names: Vec<&str> = secret_operations.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "createApiToken",
            "createAppPassword",
            "createAppleMobileconfig",
            "createDavx5Config",
            "createExternalAccount",
            "createFeedToken",
            "createWebhook",
            "rotateFeedToken",
            "rotateWebhookSecret",
        ],
        "a new operation that returns a secret must be covered here (and be `no-store`)"
    );

    let store = Arc::new(support::MemoryIdempotency::default());
    let minting = Arc::new(Minting);
    let edge = Edge::new(Surface::Api, Arc::new(SequentialRequestIds::new()));
    let mut services = AppServices::fake();
    services.credentials = Arc::<Minting>::clone(&minting);
    services.webhooks = Arc::<Minting>::clone(&minting);
    services.external_accounts = Arc::<Minting>::clone(&minting);
    services.idempotency = Arc::<support::MemoryIdempotency>::clone(&store);
    let app = davhaven_api::router(services, &edge);

    for (operation, template) in &secret_operations {
        let key = format!("key-{operation}");
        let path = concrete(template);
        let send = || {
            let mut request = call("POST", path.clone()).header("idempotency-key", key.clone());
            if let Some(body) = secret_request_body(operation) {
                request = request.json(&body);
            }
            request.send(&app)
        };
        let first = send().await;
        assert!(
            first.status.is_success(),
            "{operation}: {} {}",
            first.status,
            String::from_utf8_lossy(&first.body)
        );
        assert_eq!(
            first.header("cache-control"),
            "no-store",
            "{operation}: a secret is never cached"
        );
        assert!(
            !store.has_stored_response(&key).await,
            "{operation}: the response with the secret must not be stored"
        );

        let again = send().await;
        assert_eq!(
            (again.status, again.code().as_str()),
            (StatusCode::CONFLICT, "secret-not-replayable"),
            "{operation}: a retry is refused, not replayed"
        );
        assert!(
            !String::from_utf8_lossy(&again.body).contains("whsec_")
                && !String::from_utf8_lossy(&again.body).contains("dvh_pat_")
                && !String::from_utf8_lossy(&again.body).contains("abcd-efgh-ijkl"),
            "{operation}: the refusal contains no secret"
        );
        assert!(
            !store.has_stored_response(&key).await,
            "{operation}: nothing was stored by the retry either"
        );
    }
}

#[tokio::test]
async fn the_refusal_of_a_retried_credential_creation_says_where_the_first_attempt_put_it() {
    let store = Arc::new(support::MemoryIdempotency::default());
    let edge = Edge::new(Surface::Api, Arc::new(SequentialRequestIds::new()));
    let mut services = AppServices::fake();
    services.credentials = Arc::new(Minting);
    services.idempotency = Arc::<support::MemoryIdempotency>::clone(&store);
    let app = davhaven_api::router(services, &edge);
    for (path, body, tail) in [
        (
            "/api/v1/tenants/acme/principals/anna/app-passwords",
            json!({"label": "iPhone"}),
            format!("/principals/anna/app-passwords/{SOME_ID}"),
        ),
        (
            "/api/v1/tenants/acme/api-tokens",
            json!({"kind": "tenant", "label": "ci", "scopes": ["principals:read"]}),
            format!("/api-tokens/{SOME_ID}"),
        ),
        (
            "/api/v1/tenants/acme/principals/anna/feed-tokens",
            json!({"mode": "busy", "calendar_ids": []}),
            format!("/principals/anna/feed-tokens/{SOME_ID}"),
        ),
    ] {
        let key = format!("lost{tail}");
        let send = || {
            call("POST", path)
                .header("idempotency-key", key.clone())
                .json(&body)
                .send(&app)
        };
        let first = send().await;
        assert_eq!(first.status, StatusCode::CREATED, "{path}");
        let location = first.header("location").to_owned();
        assert!(location.ends_with(&tail), "{path}: {location}");
        // The first response was lost on its way; the retry is told where the credential is.
        let again = send().await;
        assert_eq!(again.code(), "secret-not-replayable", "{path}");
        assert_eq!(
            again.header("location"),
            location,
            "{path}: the retry can find and revoke it"
        );
        assert!(again.json()["detail"].as_str().unwrap().contains("201"), "{path}");
    }
}

/// A credential service whose client configurations are of the wrong kind for every question: a bug of the service.
struct Crossed;

#[async_trait]
impl CredentialService for Crossed {
    async fn list_app_passwords(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: PageRequest,
    ) -> AppResult<Page<AppPasswordView>> {
        Err(AppError::unsupported())
    }

    async fn create_app_password(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: AppPasswordCreate,
    ) -> AppResult<AppPasswordCreated> {
        Err(AppError::unsupported())
    }

    async fn revoke_app_password(&self, _: &RequestContext, _: &PrincipalName, _: CredentialId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn list_api_tokens(&self, _: &RequestContext, _: PageRequest) -> AppResult<Page<ApiTokenView>> {
        Err(AppError::unsupported())
    }

    async fn create_api_token(&self, _: &RequestContext, _: ApiTokenCreate) -> AppResult<ApiTokenCreated> {
        Err(AppError::unsupported())
    }

    async fn revoke_api_token(&self, _: &RequestContext, _: TokenId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn list_feed_tokens(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: PageRequest,
    ) -> AppResult<Page<FeedTokenView>> {
        Err(AppError::unsupported())
    }

    async fn create_feed_token(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: FeedTokenCreate,
    ) -> AppResult<FeedTokenCreated> {
        Err(AppError::unsupported())
    }

    async fn revoke_feed_token(&self, _: &RequestContext, _: &PrincipalName, _: TokenId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn rotate_feed_token(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        _: TokenId,
    ) -> AppResult<FeedTokenCreated> {
        Err(AppError::unsupported())
    }

    async fn client_config(
        &self,
        _: &RequestContext,
        _: &PrincipalName,
        kind: ClientConfigKind,
    ) -> AppResult<ClientConfigResponse> {
        let profile = || {
            ClientConfigResponse::Mobileconfig(MobileConfig {
                filename: "calendar.mobileconfig".to_owned(),
                body: b"<plist>abcd-efgh-ijkl-mnop</plist>".to_vec(),
            })
        };
        Ok(match kind {
            ClientConfigKind::Generic | ClientConfigKind::Davx5(_) => profile(),
            ClientConfigKind::AppleMobileconfig(_) => ClientConfigResponse::Davx5(wire(
                json!({"app_password_id": SOME_ID, "login_uri": "davx5://anna:abcd-efgh-ijkl-mnop@cal.example.org/dav"}),
            )),
        })
    }
}

#[tokio::test]
async fn client_configurations_are_served_in_their_own_form_and_a_crossed_answer_is_an_internal_error() {
    let base = "/api/v1/tenants/acme/principals/anna/client-config";
    let request = json!({"app_password_label": "iPhone", "include_feed": false});

    let app = app_with(|services| services.credentials = Arc::new(Minting));
    let profile = call("POST", format!("{base}/apple-mobileconfig"))
        .json(&request)
        .send(&app)
        .await;
    assert_eq!(profile.status, StatusCode::OK);
    assert_eq!(profile.header("content-type"), "application/x-apple-aspen-config");
    assert_eq!(
        profile.header("content-disposition"),
        "attachment; filename=\"calendar.mobileconfig\""
    );
    assert_eq!(profile.header("cache-control"), "no-store");
    assert_eq!(profile.body, b"<plist>with an app password</plist>");
    let login = call("POST", format!("{base}/davx5")).json(&request).send(&app).await;
    assert_eq!(login.status, StatusCode::OK);
    assert_eq!(login.header("content-type"), "application/json");
    assert_eq!(login.json()["app_password_id"], SOME_ID);

    // The answer of the service does not belong to the question: the client did nothing wrong, and nothing of the
    // answer (which carries a password) reaches it.
    let app = app_with(|services| services.credentials = Arc::new(Crossed));
    for (method, path) in [
        ("GET", format!("{base}/generic")),
        ("POST", format!("{base}/apple-mobileconfig")),
        ("POST", format!("{base}/davx5")),
    ] {
        let answer = call(method, path.clone()).json(&request).send(&app).await;
        assert_eq!(
            (answer.status, answer.code().as_str()),
            (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            "{path}"
        );
        assert!(
            !String::from_utf8_lossy(&answer.body).contains("abcd-efgh"),
            "{path}: {}",
            String::from_utf8_lossy(&answer.body)
        );
    }
}
