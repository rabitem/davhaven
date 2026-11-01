//! Authentication layer: credential extraction and challenges per surface.
//!
//! The edge extracts what the client presented and hands it to the application's `AuthService`; it never judges a
//! credential itself (PLAN 2.6). What differs per surface is only where the credential travels and how a refusal
//! is announced:
//!
//! | Surface | Credential | Challenge |
//! | --- | --- | --- |
//! | `dav` | `Authorization: Basic` (login and app password) | `Basic realm="{tenant}", charset="UTF-8"` |
//! | `api`, `mcp` | `Authorization: Bearer` (API token; never a query parameter) | `Bearer realm="davhaven"` |
//! | `web` | the token in the path of feeds and RSVP links | none: unknown tokens answer 404 |
//!
//! [`authenticate_header`] is the layer for the header-based surfaces. It resolves the tenant hint from the path
//! ([`crate::tenant::tenant_hint`]), calls the service, stores the resulting `RequestContext` in the request
//! extensions (handlers take it with the [`Authenticated`] extractor) and leaves the identity for the log line in
//! the response extensions. Refusals become [`EdgeProblem`]s: 401 with the challenge, 429 with `Retry-After`, the
//! mapped problem otherwise. The path-token surface calls [`auth_request`] itself, because its refusals are 404s.

use std::sync::Arc;

use axum::extract::{FromRequestParts, OriginalUri, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use davhaven_app::AppError;
use davhaven_app::services::{AuthRequest, AuthService, PresentedCredential};
use davhaven_domain::{Channel, RequestContext, RequestId, TenantSlug};
use davhaven_wire::ProblemCode;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::client_ip::client_ip_of;
use crate::problem::EdgeProblem;
use crate::request_id::request_id_of;
use crate::surface::Surface;
use crate::tenant::tenant_hint;
use crate::trace::LogIdentity;

/// The longest credential accepted in an `Authorization` header, in bytes. Real credentials are a few dozen bytes.
const MAX_CREDENTIAL_BYTES: usize = 1024;

/// The realm announced when the path names no tenant.
const SERVER_REALM: &str = "davhaven";

/// Reads the credentials of an HTTP Basic `Authorization` header value: the login and the password.
///
/// The scheme is case-insensitive; the decoded text must be UTF-8 (the challenge asks for it with
/// `charset="UTF-8"`) and contain a colon; the login must not be empty. The password may contain colons.
pub fn parse_basic(header: &str) -> Option<(String, SecretString)> {
    let (scheme, encoded) = header.split_once(' ')?;
    let encoded = encoded.trim();
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() || encoded.len() > MAX_CREDENTIAL_BYTES {
        return None;
    }
    let decoded = SecretString::from(String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?);
    let (username, password) = decoded.expose_secret().split_once(':')?;
    if username.is_empty() {
        return None;
    }
    Some((username.to_owned(), SecretString::from(password)))
}

/// Reads the token of an HTTP Bearer `Authorization` header value (RFC 6750 `b64token` characters only).
pub fn parse_bearer(header: &str) -> Option<SecretString> {
    let (scheme, token) = header.split_once(' ')?;
    let token = token.trim();
    let well_formed = !token.is_empty()
        && token.len() <= MAX_CREDENTIAL_BYTES
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'='));
    (scheme.eq_ignore_ascii_case("bearer") && well_formed).then(|| SecretString::from(token))
}

/// The credential a request presents in its `Authorization` header, as the surface expects it.
pub fn credential_from_headers(surface: Surface, headers: &HeaderMap) -> Option<PresentedCredential> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    match surface {
        Surface::Dav => {
            parse_basic(value).map(|(username, password)| PresentedCredential::Basic { username, password })
        }
        Surface::Api | Surface::Mcp => parse_bearer(value).map(PresentedCredential::Bearer),
        Surface::Web => None,
    }
}

/// The `WWW-Authenticate` challenge of a surface; DAV names the tenant of the path as its realm.
pub fn challenge(surface: Surface, tenant: Option<&TenantSlug>) -> String {
    match surface {
        Surface::Dav => format!(
            "Basic realm=\"{}\", charset=\"UTF-8\"",
            tenant.map_or(SERVER_REALM, TenantSlug::as_str)
        ),
        Surface::Api | Surface::Mcp | Surface::Web => format!("Bearer realm=\"{SERVER_REALM}\""),
    }
}

/// The authentication request of a presented credential: the request id and the client address come from what the
/// edge layers stored in the request `extensions` (a missing request id becomes the nil id).
pub fn auth_request(
    channel: Channel,
    credential: PresentedCredential,
    extensions: &Extensions,
    tenant_hint: Option<TenantSlug>,
) -> AuthRequest {
    AuthRequest {
        channel,
        tenant_hint,
        credential,
        client_ip: client_ip_of(extensions),
        request_id: request_id_of(extensions).unwrap_or_else(|| RequestId::from_uuid(Uuid::nil())),
    }
}

/// The problem of a refused authentication: an `Unauthenticated` refusal carries the surface's challenge, every
/// other error (rate limit, unavailable service) its own mapping.
pub fn refusal(surface: Surface, tenant: Option<&TenantSlug>, error: &AppError) -> EdgeProblem {
    let problem = EdgeProblem::from_app_error(error);
    if problem.code() == ProblemCode::Unauthenticated {
        problem.with_challenge(challenge(surface, tenant))
    } else {
        problem
    }
}

/// The configuration of [`authenticate_header`].
#[derive(Clone)]
pub struct HeaderAuth {
    service: Arc<dyn AuthService>,
    surface: Surface,
    channel: Channel,
    anonymous_methods: &'static [&'static str],
}

impl HeaderAuth {
    /// Basic authentication of the DAV surface.
    pub fn dav(service: Arc<dyn AuthService>) -> Self {
        Self::new(service, Surface::Dav, Channel::Dav)
    }

    /// Bearer authentication of the management API.
    pub fn api(service: Arc<dyn AuthService>) -> Self {
        Self::new(service, Surface::Api, Channel::Api)
    }

    /// Bearer authentication of the MCP endpoint.
    pub fn mcp(service: Arc<dyn AuthService>) -> Self {
        Self::new(service, Surface::Mcp, Channel::Mcp)
    }

    fn new(service: Arc<dyn AuthService>, surface: Surface, channel: Channel) -> Self {
        Self {
            service,
            surface,
            channel,
            anonymous_methods: &[],
        }
    }

    /// Lets requests with these methods through without authentication (DAV `OPTIONS` capability discovery). The
    /// handlers of such requests get no `RequestContext`.
    #[must_use]
    pub const fn with_anonymous_methods(mut self, methods: &'static [&'static str]) -> Self {
        self.anonymous_methods = methods;
        self
    }
}

/// The layer function of header authentication; mount it with
/// `axum::middleware::from_fn_with_state(header_auth, authenticate_header)` inside the problem renderer.
pub async fn authenticate_header(State(auth): State<HeaderAuth>, mut request: Request, next: Next) -> Response {
    if auth.anonymous_methods.contains(&request.method().as_str()) {
        return next.run(request).await;
    }
    // Inside a nested router the URI has lost its prefix; the tenant is named by the path the client sent.
    let path = request
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| request.uri().path(), |original| original.0.path());
    let hint = tenant_hint(auth.surface, path);
    let Some(credential) = credential_from_headers(auth.surface, request.headers()) else {
        let challenge = challenge(auth.surface, hint.as_ref());
        return EdgeProblem::new(ProblemCode::Unauthenticated)
            .with_challenge(challenge)
            .into_response();
    };
    let authentication = auth_request(auth.channel, credential, request.extensions(), hint.clone());
    match auth.service.authenticate(authentication).await {
        Ok(context) => {
            let identity = LogIdentity {
                tenant: context.tenant,
                principal: context.principal(),
            };
            request.extensions_mut().insert(context);
            let mut response = next.run(request).await;
            response.extensions_mut().insert(identity);
            response
        }
        Err(error) => refusal(auth.surface, hint.as_ref(), &error).into_response(),
    }
}

/// The authenticated context of the request, for handlers behind [`authenticate_header`].
///
/// Rejects with an `Unauthenticated` problem when no context is present, which happens only when a route was
/// mounted without the authentication layer.
#[derive(Debug, Clone)]
pub struct Authenticated(pub RequestContext);

impl<S: Send + Sync> FromRequestParts<S> for Authenticated {
    type Rejection = EdgeProblem;

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> {
        std::future::ready(
            parts
                .extensions
                .get::<RequestContext>()
                .cloned()
                .map(Self)
                .ok_or_else(|| EdgeProblem::new(ProblemCode::Unauthenticated)),
        )
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::http::header::WWW_AUTHENTICATE;
    use axum::routing::{any, get};
    use davhaven_app::AppServices;
    use davhaven_app_fake::AppServicesExt as _;
    use davhaven_app_fake::seed::{ADMIN_TOKEN, ANNA_PASSWORD, CARA_PASSWORD, GINA_PASSWORD};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::problem::{JsonProblems, ProblemRenderer, render_problems};

    fn basic(login: &str, password: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{login}:{password}")))
    }

    #[test]
    fn basic_credentials_are_decoded_strictly() {
        let (user, password) = parse_basic(&basic("anna@acme.example", "pa:ss wörd")).unwrap();
        assert_eq!(user, "anna@acme.example");
        assert_eq!(password.expose_secret(), "pa:ss wörd");
        let (_, upper) = parse_basic(&format!("BASIC {}", STANDARD.encode("a:b"))).unwrap();
        assert_eq!(upper.expose_secret(), "b");
        let (_, empty_password) = parse_basic(&basic("a", "")).unwrap();
        assert_eq!(empty_password.expose_secret(), "");
        // 1024 bytes of base64 are the longest credential: 768 bytes of login, colon and password.
        let longest = format!("{}:{}", "a".repeat(383), "b".repeat(384));
        let encoded = STANDARD.encode(&longest);
        assert_eq!(encoded.len(), 1024);
        let (login, password) = parse_basic(&format!("Basic {encoded}")).unwrap();
        assert_eq!((login.len(), password.expose_secret().len()), (383, 384));

        let bad = [
            String::new(),
            "Basic".to_owned(),
            "Basic ".to_owned(),
            "Bearer abc".to_owned(),
            "Basic !!!not-base64!!!".to_owned(),
            format!("Basic {}", STANDARD.encode("no-colon")),
            format!("Basic {}", STANDARD.encode(":only-password")),
            format!("Basic {}", STANDARD.encode([0xff_u8, b':', b'x'])),
            format!("Basic {}", "A".repeat(2000)),
            // One byte over the longest credential (1024 bytes of base64) is refused before it is decoded.
            format!("Basic {}", "A".repeat(1025)),
        ];
        for header in bad {
            assert!(parse_basic(&header).is_none(), "{header:.30}");
        }
    }

    #[test]
    fn bearer_tokens_are_taken_as_presented_and_checked_for_shape() {
        let token = parse_bearer("Bearer dvh_pat_abcdefghijkl_secret").unwrap();
        assert_eq!(token.expose_secret(), "dvh_pat_abcdefghijkl_secret");
        assert_eq!(parse_bearer("bearer   token ").unwrap().expose_secret(), "token");
        let longest = "a".repeat(1024);
        assert_eq!(
            parse_bearer(&format!("Bearer {longest}")).unwrap().expose_secret(),
            longest
        );
        assert_eq!(
            parse_bearer("Bearer AZaz09-._~+/=").unwrap().expose_secret(),
            "AZaz09-._~+/=",
            "every character class of an RFC 6750 b64token"
        );
        let too_long = format!("Bearer {}", "a".repeat(1025));
        for bad in [
            "",
            "Bearer",
            "Bearer ",
            "Basic abc",
            "Bearer a b",
            "Bearer a\"b",
            "Bearer ä",
            too_long.as_str(),
        ] {
            assert!(parse_bearer(bad).is_none(), "{bad:.30}");
        }
    }

    #[test]
    fn credentials_are_read_per_surface() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, basic("anna", "pw").parse().unwrap());
        assert!(matches!(
            credential_from_headers(Surface::Dav, &headers),
            Some(PresentedCredential::Basic { .. })
        ));
        assert!(credential_from_headers(Surface::Api, &headers).is_none());
        headers.insert(AUTHORIZATION, "Bearer tok".parse().unwrap());
        assert!(matches!(
            credential_from_headers(Surface::Api, &headers),
            Some(PresentedCredential::Bearer(_))
        ));
        assert!(matches!(
            credential_from_headers(Surface::Mcp, &headers),
            Some(PresentedCredential::Bearer(_))
        ));
        assert!(credential_from_headers(Surface::Dav, &headers).is_none());
        assert!(credential_from_headers(Surface::Web, &headers).is_none());
        assert!(credential_from_headers(Surface::Api, &HeaderMap::new()).is_none());
    }

    #[test]
    fn challenges_name_the_tenant_on_dav_only() {
        let acme = TenantSlug::parse("acme").unwrap();
        assert_eq!(
            challenge(Surface::Dav, Some(&acme)),
            "Basic realm=\"acme\", charset=\"UTF-8\""
        );
        assert_eq!(
            challenge(Surface::Dav, None),
            "Basic realm=\"davhaven\", charset=\"UTF-8\""
        );
        assert_eq!(challenge(Surface::Api, Some(&acme)), "Bearer realm=\"davhaven\"");
        assert_eq!(challenge(Surface::Mcp, None), "Bearer realm=\"davhaven\"");
    }

    async fn who(Authenticated(context): Authenticated) -> String {
        context.actor.kind_name().to_owned()
    }

    fn app(auth: HeaderAuth, surface_challenge_renderer: JsonProblems) -> Router {
        let renderer: Arc<dyn ProblemRenderer> = Arc::new(surface_challenge_renderer);
        Router::new()
            .route("/api/v1/tenants/{tenant}", get(who))
            .route("/dav/calendars/{tenant}/{principal}", any(who))
            .layer(axum::middleware::from_fn_with_state(auth, authenticate_header))
            .layer(axum::middleware::from_fn_with_state(renderer, render_problems))
    }

    fn api_app() -> Router {
        app(HeaderAuth::api(AppServices::fake().auth), JsonProblems::catalog())
    }

    fn dav_app() -> Router {
        let auth = HeaderAuth::dav(AppServices::fake().auth).with_anonymous_methods(&["OPTIONS"]);
        app(auth, JsonProblems::catalog())
    }

    async fn get_with(app: Router, path: &str, authorization: Option<&str>) -> Response {
        let mut request = Request::get(path);
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        app.oneshot(request.body(Body::empty()).unwrap()).await.unwrap()
    }

    async fn text(response: Response) -> String {
        String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn bearer_tokens_authenticate_api_requests_and_leave_a_log_identity() {
        let response = get_with(
            api_app(),
            "/api/v1/tenants/acme",
            Some(&format!("Bearer {ADMIN_TOKEN}")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let identity = response.extensions().get::<LogIdentity>().copied().unwrap();
        assert_eq!(identity.principal, None, "a tenant token acts as no principal");
        assert_eq!(text(response).await, "tenant_token");
    }

    #[tokio::test]
    async fn refusals_are_401_with_the_challenge_and_say_nothing_else() {
        let wrong_token = get_with(api_app(), "/api/v1/tenants/acme", Some("Bearer dvh_pat_wrong_wrong")).await;
        let no_header = get_with(api_app(), "/api/v1/tenants/acme", None).await;
        let wrong_scheme = get_with(api_app(), "/api/v1/tenants/acme", Some(&basic("a", "b"))).await;
        let mut bodies = Vec::new();
        for response in [wrong_token, no_header, wrong_scheme] {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[WWW_AUTHENTICATE], "Bearer realm=\"davhaven\"");
            bodies.push(text(response).await);
        }
        assert!(
            bodies.iter().all(|body| body == &bodies[0]),
            "every refusal looks the same: {bodies:?}"
        );
        // A valid token on the path of another tenant is not a refusal of the token: the resources there are invisible
        // to it, like every resource it may not see (404, R4), and there is no challenge.
        let other_tenant = get_with(
            api_app(),
            "/api/v1/tenants/globex",
            Some(&format!("Bearer {ADMIN_TOKEN}")),
        )
        .await;
        assert_eq!(other_tenant.status(), StatusCode::NOT_FOUND);
        assert!(other_tenant.headers().get(WWW_AUTHENTICATE).is_none());
    }

    #[tokio::test]
    async fn dav_logins_authenticate_with_basic_and_challenge_with_the_tenant_realm() {
        let ok = get_with(
            dav_app(),
            "/dav/calendars/acme/anna",
            Some(&basic("anna@acme.example", ANNA_PASSWORD)),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(text(ok).await, "principal");
        let wrong = get_with(
            dav_app(),
            "/dav/calendars/acme/anna",
            Some(&basic("anna@acme.example", "nope")),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            wrong.headers()[WWW_AUTHENTICATE],
            "Basic realm=\"acme\", charset=\"UTF-8\""
        );
        let suspended = get_with(
            dav_app(),
            "/dav/calendars/acme/cara",
            Some(&basic("cara@acme.example", CARA_PASSWORD)),
        )
        .await;
        assert_eq!(suspended.status(), StatusCode::UNAUTHORIZED);
        let foreign = get_with(
            dav_app(),
            "/dav/calendars/acme/gina",
            Some(&basic("gina@globex.example", GINA_PASSWORD)),
        )
        .await;
        assert_eq!(
            foreign.status(),
            StatusCode::NOT_FOUND,
            "a login of another tenant is authenticated, and the path of this tenant is invisible to it (R4)"
        );
    }

    #[tokio::test]
    async fn the_tenant_hint_survives_nesting_under_a_prefix() {
        let renderer: Arc<dyn ProblemRenderer> = Arc::new(JsonProblems::catalog());
        let inner =
            Router::new()
                .route("/tenants/{tenant}", get(who))
                .route_layer(axum::middleware::from_fn_with_state(
                    HeaderAuth::api(AppServices::fake().auth),
                    authenticate_header,
                ));
        let nested = Router::new()
            .nest("/api/v1", inner)
            .layer(axum::middleware::from_fn_with_state(renderer, render_problems));
        let own = get_with(
            nested.clone(),
            "/api/v1/tenants/acme",
            Some(&format!("Bearer {ADMIN_TOKEN}")),
        )
        .await;
        assert_eq!(own.status(), StatusCode::OK);
        let foreign = get_with(nested, "/api/v1/tenants/globex", Some(&format!("Bearer {ADMIN_TOKEN}"))).await;
        assert_eq!(
            foreign.status(),
            StatusCode::NOT_FOUND,
            "a token of another tenant must not reach the tenant because the router stripped the prefix"
        );
    }

    #[tokio::test]
    async fn api_tokens_do_not_work_on_dav_and_app_passwords_not_on_the_api() {
        let token_on_dav = get_with(
            dav_app(),
            "/dav/calendars/acme/anna",
            Some(&format!("Bearer {ADMIN_TOKEN}")),
        )
        .await;
        assert_eq!(token_on_dav.status(), StatusCode::UNAUTHORIZED);
        let password_on_api = get_with(
            api_app(),
            "/api/v1/tenants/acme",
            Some(&basic("anna@acme.example", ANNA_PASSWORD)),
        )
        .await;
        assert_eq!(password_on_api.status(), StatusCode::UNAUTHORIZED);
    }

    /// What the recording service was asked.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Asked {
        channel: Channel,
        tenant_hint: Option<String>,
        bearer: Option<String>,
        client_ip: Option<std::net::IpAddr>,
        request_id: RequestId,
    }

    /// An authentication service that records what it is asked and refuses every request with one error.
    struct Refusing {
        error: fn() -> AppError,
        asked: tokio::sync::Mutex<Vec<Asked>>,
    }

    impl Refusing {
        fn new(error: fn() -> AppError) -> Arc<Self> {
            Arc::new(Self {
                error,
                asked: tokio::sync::Mutex::new(Vec::new()),
            })
        }

        async fn asked(&self) -> Vec<Asked> {
            self.asked.lock().await.clone()
        }
    }

    // The form `#[async_trait]` expands to; the crate does not depend on the macro.
    impl AuthService for Refusing {
        fn authenticate<'life0, 'async_trait>(
            &'life0 self,
            request: AuthRequest,
        ) -> core::pin::Pin<Box<dyn Future<Output = davhaven_app::AppResult<RequestContext>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            let bearer = match &request.credential {
                PresentedCredential::Bearer(token) => Some(token.expose_secret().to_owned()),
                _ => None,
            };
            let asked = Asked {
                channel: request.channel,
                tenant_hint: request.tenant_hint.map(|slug| slug.as_str().to_owned()),
                bearer,
                client_ip: request.client_ip,
                request_id: request.request_id,
            };
            Box::pin(async move {
                self.asked.lock().await.push(asked);
                Err((self.error)())
            })
        }
    }

    #[tokio::test]
    async fn the_service_is_handed_the_channel_the_tenant_of_the_path_the_client_and_the_request_id() {
        let service = Refusing::new(AppError::unauthenticated);
        let mcp = app(
            HeaderAuth::mcp(Arc::<Refusing>::clone(&service)),
            JsonProblems::catalog(),
        );
        let id = RequestId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap();
        let address: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        let mut request = Request::get("/api/v1/tenants/acme")
            .header("authorization", "Bearer dvh_pat_abc_secret")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(id);
        request
            .extensions_mut()
            .insert(crate::client_ip::ClientIp(Some(address)));
        let response = mcp.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // Without the edge layers in front, the request id is the nil id and the client is unknown.
        let bare = get_with(mcp, "/api/v1/tenants/acme", Some("Bearer t")).await;
        assert_eq!(bare.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            service.asked().await,
            [
                Asked {
                    channel: Channel::Mcp,
                    tenant_hint: None,
                    bearer: Some("dvh_pat_abc_secret".to_owned()),
                    client_ip: Some(address),
                    request_id: id,
                },
                Asked {
                    channel: Channel::Mcp,
                    tenant_hint: None,
                    bearer: Some("t".to_owned()),
                    client_ip: None,
                    request_id: RequestId::from_uuid(Uuid::nil()),
                },
            ],
            "MCP names no tenant in its path, even on a path that looks like one of the API"
        );

        let service = Refusing::new(AppError::unauthenticated);
        let api = app(
            HeaderAuth::api(Arc::<Refusing>::clone(&service)),
            JsonProblems::catalog(),
        );
        get_with(api, "/api/v1/tenants/acme", Some("Bearer t")).await;
        let asked = service.asked().await;
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].channel, Channel::Api);
        assert_eq!(asked[0].tenant_hint.as_deref(), Some("acme"));
    }

    #[tokio::test]
    async fn requests_without_a_usable_credential_are_refused_without_asking_the_service() {
        let service = Refusing::new(AppError::unauthenticated);
        let api = app(
            HeaderAuth::api(Arc::<Refusing>::clone(&service)),
            JsonProblems::catalog(),
        );
        for authorization in [None, Some("Bearer"), Some("Bearer a b"), Some("Basic YTpi")] {
            let response = get_with(api.clone(), "/api/v1/tenants/acme", authorization).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{authorization:?}");
            assert_eq!(response.headers()[WWW_AUTHENTICATE], "Bearer realm=\"davhaven\"");
        }
        assert_eq!(service.asked().await, []);
    }

    #[tokio::test]
    async fn the_failure_backoff_and_outages_are_not_challenges() {
        fn limited() -> AppError {
            AppError::rate_limited(core::time::Duration::from_secs(42))
        }
        type Case = (fn() -> AppError, StatusCode, &'static str);
        let cases: [Case; 2] = [
            (limited, StatusCode::TOO_MANY_REQUESTS, "rate-limited"),
            (AppError::unavailable, StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        ];
        for (error, status, code) in cases {
            let dav = HeaderAuth::dav(Refusing::new(error));
            let response = get_with(
                app(dav, JsonProblems::catalog()),
                "/dav/calendars/acme/anna",
                Some(&basic("anna@acme.example", "pw")),
            )
            .await;
            assert_eq!(response.status(), status);
            assert!(
                response.headers().get(WWW_AUTHENTICATE).is_none(),
                "a client that is told to wait is not asked for other credentials"
            );
            if status == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "42");
            }
            let json: serde_json::Value = serde_json::from_str(&text(response).await).unwrap();
            assert_eq!(json["code"], code);
        }
    }

    #[tokio::test]
    async fn listed_methods_skip_authentication() {
        let request = Request::builder()
            .method("OPTIONS")
            .uri("/dav/calendars/acme/anna")
            .body(Body::empty())
            .unwrap();
        let response = dav_app().oneshot(request).await.unwrap();
        // The handler needs a context, so it refuses; what matters is that the layer did not demand credentials.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }
}
