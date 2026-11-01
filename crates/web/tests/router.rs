//! Protocol tests of the web surface: RSVP pages, subscription feeds, the OAuth callback and assets, with the
//! edge layers, over the in-memory fake of the application services and small stubs of the three services that
//! the fake does not implement (PLAN 3.1, L4).

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use davhaven_app::AppServices;
use davhaven_app::error::{AppError, AppResult};
use davhaven_app::services::{
    AssetService, AuthRequest, AuthService, CallbackParams, Conditional, CsrfToken, ExposeSecret,
    ExternalAccountService, FeedBody, FeedResponse, FeedService, FindSlotsRequest, FindSlotsResult, FreeBusyRequest,
    FreeBusyResult, InboxItemView, InvitationResponse, ObjectRef, PageRequest, RenderedPage, RsvpAnswer,
    ScheduleResponse, SchedulingService, StaticAsset,
};
use davhaven_app_fake::FakeApp;
use davhaven_app_fake::unsupported::Unsupported;
use davhaven_domain::{
    Actor, CalendarUserAddress, ETag, EventDuration, ExternalAccountId, Locale, ObjectId, PrincipalName,
    RequestContext, ResourcePath, TenantSlug,
};
use davhaven_http::{Edge, SequentialRequestIds, Surface};
use davhaven_wire::{
    AuthorizationUrl, ExternalAccountView, InboundItipRequest, InboundItipResponse, Page, ProviderView,
};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use uuid::Uuid;

const FEED_TOKEN: &str = "dvh_feed_abcdefghijkl_FEEDSECRETFEEDSECRETFEEDSECRETFEEDSECRET1";
const RSVP_TOKEN: &str = "dvh_rsvp_abcdefghijkl_RSVPSECRETRSVPSECRETRSVPSECRETRSVPSECRET1";

/// A feed service that serves one document and honours `If-None-Match`.
struct Feeds;

#[async_trait]
impl FeedService for Feeds {
    async fn render(&self, _ctx: &RequestContext, conditional: Conditional) -> AppResult<FeedResponse> {
        let body = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n";
        let etag = ETag::from_bytes(body.as_bytes());
        if conditional.if_none_match.as_ref() == Some(&etag) {
            return Ok(FeedResponse::NotModified { etag });
        }
        Ok(FeedResponse::Body(FeedBody {
            etag,
            body: body.to_owned(),
            calendar_name: "Work".to_owned(),
            last_modified: None,
            refresh_interval: EventDuration::parse("PT15M").unwrap(),
        }))
    }
}

/// A scheduling service that answers the two RSVP calls with what it received and nothing else.
struct Pages;

#[async_trait]
impl SchedulingService for Pages {
    async fn free_busy(&self, ctx: &RequestContext, request: FreeBusyRequest) -> AppResult<FreeBusyResult> {
        Unsupported.free_busy(ctx, request).await
    }

    async fn find_free_slots(&self, ctx: &RequestContext, request: FindSlotsRequest) -> AppResult<FindSlotsResult> {
        Unsupported.find_free_slots(ctx, request).await
    }

    async fn outbox_post(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        body: String,
    ) -> AppResult<ScheduleResponse> {
        Unsupported.outbox_post(ctx, principal, body).await
    }

    async fn inbox_list(&self, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Vec<InboxItemView>> {
        Unsupported.inbox_list(ctx, principal).await
    }

    async fn inbox_get(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<InboxItemView> {
        Unsupported.inbox_get(ctx, path).await
    }

    async fn inbox_delete(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<()> {
        Unsupported.inbox_delete(ctx, path).await
    }

    async fn respond(
        &self,
        ctx: &RequestContext,
        object: ObjectRef,
        response: InvitationResponse,
    ) -> AppResult<davhaven_wire::EventView> {
        Unsupported.respond(ctx, object, response).await
    }

    async fn inbound_itip(&self, ctx: &RequestContext, request: InboundItipRequest) -> AppResult<InboundItipResponse> {
        Unsupported.inbound_itip(ctx, request).await
    }

    async fn rsvp_page(&self, ctx: &RequestContext) -> AppResult<RenderedPage> {
        let Actor::RsvpAttendee { address, .. } = &ctx.actor else {
            return Err(AppError::forbidden());
        };
        Ok(RenderedPage {
            html: format!("<p>page for {address}</p>"),
        })
    }

    async fn rsvp_answer(&self, ctx: &RequestContext, answer: RsvpAnswer, csrf: CsrfToken) -> AppResult<RenderedPage> {
        let Actor::RsvpAttendee { address, .. } = &ctx.actor else {
            return Err(AppError::forbidden());
        };
        Ok(RenderedPage {
            html: format!(
                "<p>{address} answered {} with {:?} and {}</p>",
                answer.partstat.as_ical(),
                answer.comment,
                csrf.as_str()
            ),
        })
    }
}

/// An asset service with one file: the style sheet of the default theme.
struct Assets;

const STYLE_SHEET: &[u8] = b"body{margin:0}";

#[async_trait]
impl AssetService for Assets {
    async fn get(&self, _ctx: &RequestContext, theme: &str, file: &str) -> AppResult<StaticAsset> {
        match (theme, file) {
            ("default", "page.css") => Ok(StaticAsset {
                content_type: "text/css; charset=utf-8",
                body: bytes::Bytes::from_static(STYLE_SHEET),
                etag: ETag::from_bytes(STYLE_SHEET),
            }),
            _ => Err(AppError::not_found()),
        }
    }
}

/// An account service that reports what the callback carried.
struct Accounts;

#[async_trait]
impl ExternalAccountService for Accounts {
    async fn providers(&self, ctx: &RequestContext) -> AppResult<Vec<ProviderView>> {
        Unsupported.providers(ctx).await
    }

    async fn start(
        &self,
        ctx: &RequestContext,
        provider: &str,
        principal: &PrincipalName,
    ) -> AppResult<AuthorizationUrl> {
        Unsupported.start(ctx, provider, principal).await
    }

    async fn complete(&self, ctx: &RequestContext, provider: &str, params: CallbackParams) -> AppResult<RenderedPage> {
        Ok(RenderedPage {
            html: format!(
                "<p>{provider} state={:?} code={:?} error={:?} channel={}</p>",
                params.state,
                params.code.as_ref().map(ExposeSecret::expose_secret),
                params.error,
                ctx.channel
            ),
        })
    }

    async fn list(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<ExternalAccountView>> {
        Unsupported.list(ctx, page).await
    }

    async fn delete(&self, ctx: &RequestContext, id: ExternalAccountId) -> AppResult<()> {
        Unsupported.delete(ctx, id).await
    }
}

/// An asset service that also renders the page of a link that cannot be served: it names the status and the language.
struct ThemedAssets;

#[async_trait]
impl AssetService for ThemedAssets {
    async fn get(&self, ctx: &RequestContext, theme: &str, file: &str) -> AppResult<StaticAsset> {
        Assets.get(ctx, theme, file).await
    }

    async fn unavailable_page(
        &self,
        _ctx: &RequestContext,
        status: u16,
        languages: &[Locale],
    ) -> AppResult<RenderedPage> {
        let languages: Vec<&str> = languages.iter().map(Locale::as_str).collect();
        let languages = if languages.is_empty() {
            "none".to_owned()
        } else {
            languages.join(",")
        };
        Ok(RenderedPage {
            html: format!("<h1>themed {status} in {languages}</h1>"),
        })
    }
}

/// The router over the fake world with a feed token and an RSVP token; `stubs` replaces the three services.
async fn app(stubs: bool) -> Router {
    app_with(stubs, Arc::new(Assets)).await
}

/// [`app`] with the asset service that renders the pages of failures.
async fn app_with(stubs: bool, assets: Arc<dyn AssetService>) -> Router {
    let fake = FakeApp::standard();
    fake.state
        .write(|world| {
            let slug = TenantSlug::parse("acme").unwrap();
            let tenant = world.tenant_by_slug(&slug).unwrap().id;
            let anna = world
                .principal_id(&slug, &PrincipalName::parse("anna").unwrap())
                .unwrap();
            world.add_feed_token(tenant, anna, FEED_TOKEN);
            world.add_rsvp_token(
                tenant,
                ObjectId::from_uuid(Uuid::from_u128(7)),
                CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
                RSVP_TOKEN,
            );
        })
        .await;
    let mut services: AppServices = fake.services.clone();
    if stubs {
        services.feeds = Arc::new(Feeds);
        services.scheduling = Arc::new(Pages);
        services.external_accounts = Arc::new(Accounts);
        services.assets = assets;
    }
    let edge = Edge::new(Surface::Web, Arc::new(SequentialRequestIds::new()));
    davhaven_web::router(services, &edge)
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

async fn get(app: &Router, path: &str) -> Answer {
    send(app, Request::get(path).body(Body::empty()).unwrap()).await
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned(),
    }
}

fn post_form(path: &str, content_type: &str, body: String) -> Request<Body> {
    Request::post(path)
        .header("content-type", content_type)
        .header("host", "cal.example.org")
        .body(Body::from(body))
        .unwrap()
}

fn assert_secure(answer: &Answer) {
    assert_eq!(
        answer.header("content-security-policy"),
        "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    assert_eq!(answer.header("referrer-policy"), "no-referrer");
    assert_eq!(answer.header("x-content-type-options"), "nosniff");
    assert_eq!(answer.header("x-robots-tag"), "noindex, nofollow");
    assert!(answer.headers.get("set-cookie").is_none());
}

#[tokio::test]
async fn the_rsvp_page_is_shown_to_the_attendee_of_the_token() {
    let answer = get(&app(true).await, &format!("/rsvp/{RSVP_TOKEN}")).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(answer.header("cache-control"), "no-store");
    assert_eq!(answer.body, "<p>page for mailto:guest@example.org</p>");
    assert_secure(&answer);
}

#[tokio::test]
async fn every_bad_rsvp_token_is_the_same_404_page() {
    let app = app(true).await;
    let long = "x".repeat(300);
    let paths = [
        "/rsvp/dvh_rsvp_abcdefghijkl_unknownunknownunknown".to_owned(),
        format!("/rsvp/{FEED_TOKEN}"),
        "/rsvp/has%20space".to_owned(),
        format!("/rsvp/{long}"),
    ];
    let mut bodies = Vec::new();
    for path in &paths {
        let answer = get(&app, path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path:.40}");
        assert_eq!(answer.header("content-type"), "text/html; charset=utf-8");
        assert_secure(&answer);
        bodies.push(answer.body);
    }
    assert!(
        bodies.iter().all(|body| body == &bodies[0]),
        "the pages differ: {bodies:?}"
    );
    assert!(
        !bodies[0].contains("rsvp"),
        "the page does not repeat the token or its kind"
    );
}

#[tokio::test]
async fn an_answer_is_parsed_checked_and_handed_to_the_service() {
    let app = app(true).await;
    let path = format!("/rsvp/{RSVP_TOKEN}");
    let form = "application/x-www-form-urlencoded";
    let ok = send(
        &app,
        post_form(&path, form, "partstat=ACCEPTED&comment=See+you&csrf=v1.tok".to_owned()),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(
        ok.body,
        "<p>mailto:guest@example.org answered ACCEPTED with Some(\"See you\") and v1.tok</p>"
    );
    assert_secure(&ok);

    let cases = [
        (
            form,
            "partstat=MAYBE&csrf=t".to_owned(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (form, "partstat=ACCEPTED".to_owned(), StatusCode::UNPROCESSABLE_ENTITY),
        (
            form,
            "partstat=ACCEPTED&partstat=DECLINED&csrf=t".to_owned(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "application/json",
            "{\"partstat\":\"ACCEPTED\"}".to_owned(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            form,
            format!("partstat=ACCEPTED&csrf=t&comment={}", "x".repeat(20_000)),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ];
    for (content_type, body, status) in cases {
        let answer = send(&app, post_form(&path, content_type, body.clone())).await;
        assert_eq!(answer.status, status, "{content_type} {body:.40}");
        assert_eq!(
            answer.header("content-type"),
            "text/html; charset=utf-8",
            "errors are pages, not JSON"
        );
        assert_secure(&answer);
    }
}

#[tokio::test]
async fn an_answer_to_a_bad_token_is_the_404_page_whatever_the_form_says() {
    // The token is checked before the form, so the answer to a guessed link never tells a valid form from an invalid one.
    let app = app(true).await;
    let path = "/rsvp/dvh_rsvp_abcdefghijkl_unknownunknownunknown";
    let form = "application/x-www-form-urlencoded";
    let reference = get(&app, path).await;
    assert_eq!(reference.status, StatusCode::NOT_FOUND);
    for (content_type, body) in [
        (form, "partstat=ACCEPTED&csrf=t".to_owned()),
        (form, "partstat=MAYBE".to_owned()),
        ("application/json", "{}".to_owned()),
        (form, format!("partstat=ACCEPTED&csrf=t&comment={}", "x".repeat(20_000))),
    ] {
        let answer = send(&app, post_form(path, content_type, body.clone())).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{content_type} {body:.40}");
        assert_eq!(answer.body, reference.body, "{content_type} {body:.40}");
        assert_secure(&answer);
    }
}

#[tokio::test]
async fn answers_from_foreign_origins_are_refused_and_same_origin_posts_pass() {
    let app = app(true).await;
    let path = format!("/rsvp/{RSVP_TOKEN}");
    let body = "partstat=DECLINED&csrf=t".to_owned();
    let form = "application/x-www-form-urlencoded";
    let foreign = Request::post(&path)
        .header("content-type", form)
        .header("host", "cal.example.org")
        .header("origin", "https://evil.example")
        .body(Body::from(body.clone()))
        .unwrap();
    assert_eq!(send(&app, foreign).await.status, StatusCode::FORBIDDEN);
    let same = Request::post(&path)
        .header("content-type", form)
        .header("host", "cal.example.org")
        .header("origin", "https://cal.example.org")
        .body(Body::from(body))
        .unwrap();
    assert_eq!(send(&app, same).await.status, StatusCode::OK);
}

#[tokio::test]
async fn services_that_have_not_landed_answer_a_501_page() {
    let app = app(false).await;
    for path in [
        format!("/rsvp/{RSVP_TOKEN}"),
        format!("/feeds/{FEED_TOKEN}.ics"),
        "/oauth/google/callback".to_owned(),
    ] {
        let answer = get(&app, &path).await;
        assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED, "{path:.30}");
        assert_eq!(answer.header("content-type"), "text/html; charset=utf-8");
        assert!(answer.body.contains("not available"), "{}", answer.body);
        assert_secure(&answer);
    }
}

#[tokio::test]
async fn feeds_are_text_calendar_with_validators_and_answer_304_to_current_copies() {
    let app = app(true).await;
    let path = format!("/feeds/{FEED_TOKEN}.ics");
    let first = get(&app, &path).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.header("content-type"), "text/calendar; charset=utf-8");
    assert_eq!(first.header("cache-control"), "private, max-age=300");
    assert!(first.body.starts_with("BEGIN:VCALENDAR"));
    assert_secure(&first);
    let etag = first.header("etag").to_owned();
    assert!(etag.starts_with('"'));

    let conditional = Request::get(&path)
        .header("if-none-match", etag.clone())
        .body(Body::empty())
        .unwrap();
    let second = send(&app, conditional).await;
    assert_eq!(second.status, StatusCode::NOT_MODIFIED);
    assert_eq!(second.body, "");
    assert_eq!(second.header("etag"), etag);
    assert_eq!(second.header("cache-control"), "private, max-age=300");

    let stale = Request::get(&path)
        .header("if-none-match", "\"other\"")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, stale).await.status, StatusCode::OK);
}

#[tokio::test]
async fn bad_feed_addresses_are_all_the_same_404_page() {
    let app = app(true).await;
    let mut bodies = Vec::new();
    for path in [
        "/feeds/dvh_feed_abcdefghijkl_unknown.ics".to_owned(),
        format!("/feeds/{FEED_TOKEN}"),
        format!("/feeds/{FEED_TOKEN}.txt"),
        format!("/feeds/{RSVP_TOKEN}.ics"),
        "/feeds/.ics".to_owned(),
        format!("/feeds/{}.ics", "x".repeat(300)),
    ] {
        let answer = get(&app, &path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path:.50}");
        assert_eq!(answer.header("content-type"), "text/html; charset=utf-8");
        assert_secure(&answer);
        bodies.push(answer.body);
    }
    assert!(
        bodies.iter().all(|body| body == &bodies[0]),
        "the pages differ: {bodies:?}"
    );
}

#[tokio::test]
async fn the_oauth_callback_hands_the_parameters_to_the_service_without_a_credential() {
    let app = app(true).await;
    let answer = get(&app, "/oauth/google/callback?code=4%2F0AbC&state=s-1").await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        answer.body,
        "<p>google state=Some(\"s-1\") code=Some(\"4/0AbC\") error=None channel=internal</p>"
    );
    assert_secure(&answer);
    let refused = get(&app, "/oauth/google/callback?error=access_denied&state=s-1").await;
    assert!(
        refused.body.contains("error=Some(\"access_denied\")"),
        "{}",
        refused.body
    );
    assert!(refused.body.contains("code=None"));
}

#[tokio::test]
async fn the_oauth_callback_refuses_bad_providers_and_parameters() {
    let app = app(true).await;
    assert_eq!(
        get(&app, "/oauth/Not%20A%20Provider/callback").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, "/oauth/google/callback?state=a&state=b").await.status,
        StatusCode::BAD_REQUEST
    );
    let huge = format!("/oauth/google/callback?code={}", "a".repeat(5000));
    assert_eq!(get(&app, &huge).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn assets_are_served_from_the_application_with_a_validator_and_the_security_headers() {
    let app = app(true).await;
    let sheet = get(&app, "/assets/default/page.css").await;
    assert_eq!(sheet.status, StatusCode::OK);
    assert_eq!(sheet.body.as_bytes(), STYLE_SHEET);
    assert_eq!(sheet.header("content-type"), "text/css; charset=utf-8");
    assert_eq!(sheet.header("cache-control"), "public, max-age=3600");
    assert_eq!(sheet.header("etag"), ETag::from_bytes(STYLE_SHEET).as_str());
    assert_secure(&sheet);

    let again = send(
        &app,
        Request::get("/assets/default/page.css")
            .header("if-none-match", sheet.header("etag"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_MODIFIED);
    assert_eq!(again.body, "");
    assert_eq!(again.header("cache-control"), "public, max-age=3600");
    assert_secure(&again);
}

#[tokio::test]
async fn unknown_assets_and_paths_that_are_no_asset_names_are_the_404_page() {
    let web = app(true).await;
    for path in [
        "/assets/theme/logo.svg",
        "/assets/default/other.css",
        "/assets/default/",
        "/assets/default",
        "/assets/",
        "/assets/default/sub/page.css",
        "/assets/default/%2e%2e%2fpage.css",
        "/assets/%2e%2e/page.css",
        "/assets/default/.hidden",
    ] {
        let answer = get(&web, path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert_secure(&answer);
    }
    let unsupported = get(&app(false).await, "/assets/default/page.css").await;
    assert_eq!(
        unsupported.status,
        StatusCode::NOT_IMPLEMENTED,
        "the fake has no assets"
    );
}

#[tokio::test]
async fn other_paths_are_pages_too_and_methods_are_checked() {
    let app = app(true).await;
    let unknown = get(&app, "/nothing").await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.header("content-type"), "text/html; charset=utf-8");
    let wrong_method = send(&app, Request::delete("/feeds/x.ics").body(Body::empty()).unwrap()).await;
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        wrong_method.header("allow").contains("GET"),
        "{}",
        wrong_method.header("allow")
    );
}

#[tokio::test]
async fn request_ids_are_echoed_on_pages_and_errors() {
    let app = app(true).await;
    let ok = get(&app, &format!("/rsvp/{RSVP_TOKEN}")).await;
    assert_eq!(ok.header("x-request-id"), "018f3c1e-7b2a-7c3d-9e4f-000000000001");
    let missing = get(&app, "/nothing").await;
    assert_eq!(missing.header("x-request-id"), "018f3c1e-7b2a-7c3d-9e4f-000000000002");
    // The id a client sends is the id of its request, on the error page as well.
    let own = "11111111-2222-7333-8444-555555555555";
    let refused = send(
        &app,
        Request::get("/rsvp/dvh_rsvp_abcdefghijkl_unknownunknownunknown")
            .header("x-request-id", own)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);
    assert_eq!(refused.header("x-request-id"), own);
}

fn get_with_language(path: &str, language: &str) -> Request<Body> {
    Request::get(path)
        .header("accept-language", language)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn failures_are_rendered_by_the_application_in_the_language_of_the_visitor() {
    let app = app_with(true, Arc::new(ThemedAssets)).await;
    // Every cause of a 404 is the same themed page: unknown, revoked or foreign tokens and unknown paths.
    for path in [
        "/rsvp/dvh_rsvp_abcdefghijkl_unknownunknownunknown".to_owned(),
        format!("/rsvp/{FEED_TOKEN}"),
        "/feeds/dvh_feed_abcdefghijkl_unknownunknownunknown.ics".to_owned(),
        "/nothing".to_owned(),
    ] {
        let german = send(&app, get_with_language(&path, "de-AT,de;q=0.9,en;q=0.5")).await;
        assert_eq!(german.status, StatusCode::NOT_FOUND, "{path:.40}");
        // The application is handed the visitor's languages as they were ranked; which of them the theme ships is its business.
        assert_eq!(german.body, "<h1>themed 404 in de-AT,de,en</h1>", "{path:.40}");
        assert_eq!(german.header("content-type"), "text/html; charset=utf-8");
        assert_eq!(german.header("cache-control"), "no-store");
        assert_eq!(german.header("vary"), "Accept-Language");
        assert_secure(&german);
        let english = send(&app, get_with_language(&path, "fr;q=1, en;q=0.4")).await;
        assert_eq!(english.body, "<h1>themed 404 in fr,en</h1>", "{path:.40}");
        // No language named: the application is told none, and the deployment's default applies.
        let default = get(&app, &path).await;
        assert_eq!(default.body, "<h1>themed 404 in none</h1>", "{path:.40}");
    }
    // The headers of the problem survive: a method that is not allowed says which ones are.
    let wrong_method = send(&app, Request::delete("/feeds/x.ics").body(Body::empty()).unwrap()).await;
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(wrong_method.body, "<h1>themed 405 in none</h1>");
    assert!(
        wrong_method.header("allow").contains("GET"),
        "{}",
        wrong_method.header("allow")
    );
    // A page that works is left alone.
    let page = get(&app, &format!("/rsvp/{RSVP_TOKEN}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.body, "<p>page for mailto:guest@example.org</p>");
}

#[tokio::test]
async fn a_page_that_cannot_be_rendered_falls_back_to_the_static_page_with_the_same_status() {
    // The asset service of the other tests renders no page of failures.
    let answer = get(&app(true).await, "/rsvp/dvh_rsvp_abcdefghijkl_unknownunknownunknown").await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert!(answer.body.starts_with("<!doctype html>"), "{}", answer.body);
    assert!(answer.body.contains("no longer valid"), "{}", answer.body);
    assert_secure(&answer);
}

/// An authentication service that counts the calls and answers every one with the failure backoff.
#[derive(Default)]
struct Backoff {
    calls: AtomicUsize,
}

#[async_trait]
impl AuthService for Backoff {
    async fn authenticate(&self, _request: AuthRequest) -> AppResult<RequestContext> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(AppError::rate_limited(core::time::Duration::from_secs(30)))
    }
}

#[tokio::test]
async fn the_failure_backoff_shows_as_429_and_what_cannot_be_a_token_never_reaches_the_service() {
    let backoff = Arc::new(Backoff::default());
    let mut services: AppServices = FakeApp::standard().services.clone();
    services.auth = Arc::<Backoff>::clone(&backoff);
    let edge = Edge::new(Surface::Web, Arc::new(SequentialRequestIds::new()));
    let app = davhaven_web::router(services, &edge);

    // Hiding the backoff behind the 404 would make it useless against guessing: it shows, with the time to wait.
    let longest = "a".repeat(128);
    for path in [
        format!("/rsvp/{RSVP_TOKEN}"),
        format!("/feeds/{FEED_TOKEN}.ics"),
        format!("/rsvp/{longest}"),
    ] {
        let answer = get(&app, &path).await;
        assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "{path:.40}");
        assert_eq!(answer.header("retry-after"), "30", "{path:.40}");
        assert_secure(&answer);
    }
    assert_eq!(backoff.calls.load(Ordering::SeqCst), 3);

    // Too long, not printable or not ASCII: the 404 page without asking the service, so such guesses cost it nothing.
    let too_long = "a".repeat(129);
    for path in [
        format!("/rsvp/{too_long}"),
        format!("/feeds/{too_long}.ics"),
        "/rsvp/has%20space".to_owned(),
        "/rsvp/tab%09tab".to_owned(),
        "/rsvp/caf%C3%A9".to_owned(),
        "/feeds/caf%C3%A9.ics".to_owned(),
    ] {
        let answer = get(&app, &path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path:.40}");
        assert!(answer.headers.get("retry-after").is_none(), "{path:.40}");
    }
    assert_eq!(
        backoff.calls.load(Ordering::SeqCst),
        3,
        "a token that cannot be a token is not presented"
    );
}
