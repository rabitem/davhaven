//! The opt-in DAV capture (`observability.dav_capture`, PLAN 2.17).
//!
//! With `observability.dav_capture.enabled = true` the server records the DAV exchanges of the tenants in the
//! allowlist, one JSON file per request in `observability.dav_capture.dir`. The files are the raw material of the
//! client-flow suite: real clients talk to a staging instance, and a capture converter turns what they said into
//! scenario fixtures (`docs/testing.md`, client flows).
//!
//! * **Which requests.** Those below `/dav/principals/{tenant}/` and `/dav/calendars/{tenant}/` of a tenant in
//!   `tenants`, **that were authenticated as a user of that tenant**. The tenant that is in the path is only the
//!   candidate: the edge says who the request was authenticated as (the identity that it leaves in the response), and
//!   the exchange is recorded only when that is the listed tenant. Unauthenticated requests (the 401 of a client that has
//!   not logged in yet) and the probes of a user of another tenant, who may not have agreed to a capture, are never
//!   written, whatever the path says. The discovery requests at `/dav/` and `/.well-known/caldav` name no tenant and are
//!   not captured.
//! * **What is recorded.** Method, path and query, the headers of the request and the response, both bodies and the
//!   status. Credentials are redacted before anything is written: the values of `Authorization`,
//!   `Proxy-Authorization`, `Cookie` and `Set-Cookie` become `<redacted>`. The bodies are calendar data of the
//!   captured tenants: that is the purpose, so capture only tenants whose users agreed, and treat the directory
//!   like the database.
//! * **Limits.** The capture sits outside the edge layers of the DAV surface, so it brings limits of its own and never
//!   makes a request more expensive than the edge would. A request body is read only when its `Content-Length` is within
//!   the DAV limits (`limits.dav.max_request_body` and `limits.ical.max_resource_size`, whichever is larger) and a
//!   request that is chunked or larger passes through unrecorded. Reading the body is bounded by the request timeout
//!   (`server.http.request_timeout`: a body that never arrives is answered 503 like the edge answers it) and the capture
//!   handles at most `server.http.concurrency_limit` exchanges at the same time; when it is at that limit the request
//!   passes through unrecorded. A response is recorded only when its size is known and at most
//!   [`MAX_RESPONSE_BYTES`]; any other passes through unrecorded. Write failures are logged and never fail the request.
//! * **Files.** `{time}-{sequence}-{METHOD}-{status}.json`, created with mode 0600 in a directory that is created with
//!   mode 0700, never overwritten. The time is the clock's (UTC, millisecond precision), so a directory sorts in the
//!   order of the exchanges.
//!
//! The format of a file:
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "captured_at": "2027-03-01T10:15:30.123Z",
//!   "tenant": "acme",
//!   "request": {"method": "PROPFIND", "path": "/dav/calendars/acme/olivia/", "query": null,
//!               "headers": [["depth", "1"], ["authorization", "<redacted>"]], "body": "<?xml ..."},
//!   "response": {"status": 207, "headers": [["content-type", "application/xml"]], "body": "<?xml ..."}
//! }
//! ```
//!
//! A body that is not UTF-8 is written as `body_base64` instead of `body`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_LENGTH, RETRY_AFTER, TRANSFER_ENCODING};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use davhaven_domain::{TenantId, TenantSlug};
use davhaven_http::trace::LogIdentity;
use davhaven_ports::{Clock, Database};
use hyper::body::Body as _;
use serde_json::{Value, json};
use tokio::sync::{RwLock, Semaphore};

use crate::config::Config;
use crate::error::ServerError;
use crate::telemetry::DavCaptureConfig;

/// The largest response that is recorded, in bytes. DAV answers (a multistatus of a large calendar) can be larger than a
/// request body ever is.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// What replaces the value of a credential header in a capture.
pub const REDACTED: &str = "<redacted>";

/// The version of the capture file format.
pub const SCHEMA_VERSION: u32 = 1;

/// The headers whose values are credentials.
const CREDENTIAL_HEADERS: [&str; 4] = ["authorization", "proxy-authorization", "cookie", "set-cookie"];

/// What bounds the work of the capture, taken from the configuration of the DAV surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureLimits {
    /// The largest request body that is read, in bytes: the DAV limits.
    pub max_request_bytes: usize,
    /// The largest response that is recorded, in bytes.
    pub max_response_bytes: usize,
    /// How long reading a request body may take.
    pub request_timeout: Duration,
    /// How many exchanges the capture handles at the same time.
    pub concurrency: usize,
}

impl CaptureLimits {
    /// The limits of a configuration: the larger of the DAV body limit and the resource limit, the request timeout and the
    /// concurrency limit of `[server.http]`.
    pub fn of(config: &Config) -> Self {
        let limits = config.limits();
        Self {
            max_request_bytes: usize::try_from(limits.dav.max_request_body.max(limits.ical.max_resource_size))
                .unwrap_or(usize::MAX),
            max_response_bytes: MAX_RESPONSE_BYTES,
            request_timeout: config.server.http.request_timeout,
            concurrency: config.server.http.concurrency_limit,
        }
    }
}

/// The ids of the tenants of the allowlist, found by slug.
#[async_trait]
pub trait TenantIds: Send + Sync {
    /// The id of the tenant with this slug, if it exists.
    async fn id_of(&self, slug: &TenantSlug) -> Option<TenantId>;
}

/// Tenant ids from the store.
struct StoreTenantIds(Arc<dyn Database>);

#[async_trait]
impl TenantIds for StoreTenantIds {
    async fn id_of(&self, slug: &TenantSlug) -> Option<TenantId> {
        let mut tx = self.0.begin_system().await.ok()?;
        let found = tx.tenants().find_by_slug(slug).await.ok()?;
        tx.commit().await.ok()?;
        found.map(|tenant| tenant.id)
    }
}

/// The capture of one server.
pub struct Capture {
    dir: PathBuf,
    tenants: BTreeSet<String>,
    known: RwLock<BTreeMap<String, TenantId>>,
    ids: Arc<dyn TenantIds>,
    clock: Arc<dyn Clock>,
    sequence: AtomicU64,
    limits: CaptureLimits,
    permits: Arc<Semaphore>,
}

impl core::fmt::Debug for Capture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Capture")
            .field("dir", &self.dir)
            .field("tenants", &self.tenants)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// The tenant slug of a DAV path below `/dav/principals/` or `/dav/calendars/`, if it names one.
pub fn tenant_of(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/dav/")?;
    let (collection, rest) = rest.split_once('/')?;
    if collection != "principals" && collection != "calendars" {
        return None;
    }
    let tenant = rest.split('/').next()?;
    (!tenant.is_empty()).then_some(tenant)
}

impl Capture {
    /// Prepares the capture of `config` with the tenants looked up in `database`: `None` when it is disabled; otherwise the
    /// directory is created (with mode 0700).
    ///
    /// # Errors
    ///
    /// [`ServerError::Io`] when the directory cannot be created, and [`ServerError::Command`] when the
    /// configuration lacks the allowlist or the directory (the configuration check refuses that already).
    pub async fn start(
        config: &DavCaptureConfig,
        clock: Arc<dyn Clock>,
        database: Arc<dyn Database>,
        limits: CaptureLimits,
    ) -> Result<Option<Arc<Self>>, ServerError> {
        Self::start_with(config, clock, Arc::new(StoreTenantIds(database)), limits).await
    }

    /// [`start`](Self::start) with another source of tenant ids.
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start).
    pub async fn start_with(
        config: &DavCaptureConfig,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn TenantIds>,
        limits: CaptureLimits,
    ) -> Result<Option<Arc<Self>>, ServerError> {
        if !config.enabled {
            return Ok(None);
        }
        let dir = config.dir.clone().ok_or_else(|| {
            ServerError::Command("observability.dav_capture.dir is required when the capture is enabled".to_owned())
        })?;
        if config.tenants.is_empty() {
            return Err(ServerError::Command(
                "observability.dav_capture.tenants must list the captured tenants".to_owned(),
            ));
        }
        let mut builder = tokio::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&dir).await.map_err(|error| {
            ServerError::io(format!("cannot create the capture directory {}", dir.display()), error)
        })?;
        Ok(Some(Arc::new(Self {
            dir,
            tenants: config.tenants.iter().map(ToString::to_string).collect(),
            known: RwLock::new(BTreeMap::new()),
            ids,
            clock,
            sequence: AtomicU64::new(0),
            limits,
            permits: Arc::new(Semaphore::new(limits.concurrency)),
        })))
    }

    /// Wraps `router` so that the exchanges of the captured tenants are recorded. Apply it outside the edge layers of
    /// the DAV router: it then sees the request as the client sent it and the response as the client gets it, with the
    /// identity the edge authenticated.
    pub fn layer(self: &Arc<Self>, router: Router) -> Router {
        router.layer(from_fn_with_state(Arc::clone(self), record))
    }

    /// Whether the exchanges below `path` are candidates for capture: the tenant of the path is in the allowlist.
    fn candidate<'a>(&self, path: &'a str) -> Option<&'a str> {
        tenant_of(path).filter(|tenant| self.tenants.contains(*tenant))
    }

    /// The id of the listed tenant `slug`, from the memory of this capture or, when it is not known yet (or the tenant
    /// was created again since), from the store.
    async fn lookup(&self, slug: &str) -> Option<TenantId> {
        let parsed = TenantSlug::parse(slug).ok()?;
        let id = self.ids.id_of(&parsed).await?;
        self.known.write().await.insert(slug.to_owned(), id);
        Some(id)
    }

    /// Whether `authenticated`, the tenant the edge authenticated the request as, is the listed tenant `slug`.
    async fn is_listed_tenant(&self, slug: &str, authenticated: TenantId) -> bool {
        let remembered = self.known.read().await.get(slug).copied();
        if remembered == Some(authenticated) {
            return true;
        }
        // Not the tenant we know (or none known yet): look again once, the tenant may have been created after the start.
        self.lookup(slug).await == Some(authenticated)
    }

    async fn write(&self, tenant: &str, status: StatusCode, method: &str, document: &Value) {
        let now = self.clock.now();
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "{}-{sequence:06}-{method}-{}.json",
            now.format("%Y%m%dT%H%M%S%3fZ"),
            status.as_u16()
        );
        let path = self.dir.join(name);
        let bytes = match serde_json::to_vec_pretty(document) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, tenant, "cannot render a DAV capture");
                return;
            }
        };
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let outcome = async {
            use tokio::io::AsyncWriteExt as _;
            let mut file = options.open(&path).await?;
            file.write_all(&bytes).await?;
            file.flush().await
        }
        .await;
        if let Err(error) = outcome {
            tracing::warn!(%error, path = %path.display(), "cannot write a DAV capture");
        }
    }
}

/// The headers as a list of `[name, value]` pairs with the credentials redacted.
fn header_list(headers: &HeaderMap) -> Vec<[String; 2]> {
    headers
        .iter()
        .map(|(name, value)| {
            let shown = if CREDENTIAL_HEADERS.contains(&name.as_str()) {
                REDACTED.to_owned()
            } else {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            };
            [name.as_str().to_owned(), shown]
        })
        .collect()
}

/// Puts a body into a document: as text when it is UTF-8, as base64 otherwise.
fn put_body(target: &mut Value, bytes: &[u8]) {
    let Some(object) = target.as_object_mut() else {
        return;
    };
    match std::str::from_utf8(bytes) {
        Ok(text) => object.insert("body".to_owned(), Value::String(text.to_owned())),
        Err(_) => object.insert("body_base64".to_owned(), Value::String(STANDARD.encode(bytes))),
    };
}

/// Whether a request body can be recorded: it is not chunked and its declared length (none means no body) is within
/// `limit`.
fn body_fits(headers: &HeaderMap, limit: usize) -> bool {
    if headers.contains_key(TRANSFER_ENCODING) {
        return false;
    }
    headers.get(CONTENT_LENGTH).is_none_or(|value| {
        value
            .to_str()
            .ok()
            .and_then(|text| text.trim().parse::<usize>().ok())
            .is_some_and(|length| length <= limit)
    })
}

/// The answer to a request whose body did not arrive in time, as the edge answers it.
fn timed_out() -> Response {
    let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

async fn record(State(capture): State<Arc<Capture>>, request: Request, next: Next) -> Response {
    let Some(slug) = capture.candidate(request.uri().path()).map(str::to_owned) else {
        return next.run(request).await;
    };
    // At the limit of the capture's own concurrency the exchange passes through unrecorded: it never makes a request wait.
    let Ok(_permit) = Arc::clone(&capture.permits).try_acquire_owned() else {
        return next.run(request).await;
    };
    let (parts, body) = request.into_parts();
    if !body_fits(&parts.headers, capture.limits.max_request_bytes) {
        // Chunked, or larger than the DAV limits: the request passes through unrecorded (and unbuffered).
        return next.run(Request::from_parts(parts, body)).await;
    }
    let request_bytes = match tokio::time::timeout(
        capture.limits.request_timeout,
        to_bytes(body, capture.limits.max_request_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            tracing::warn!(%error, "cannot read a request body for the DAV capture");
            return StatusCode::BAD_REQUEST.into_response();
        }
        Err(_elapsed) => return timed_out(),
    };
    let body = Body::from(request_bytes.clone());
    let method = parts.method.as_str().to_owned();
    let mut request_part = json!({
        "method": method,
        "path": parts.uri.path(),
        "query": parts.uri.query(),
        "headers": header_list(&parts.headers),
    });
    put_body(&mut request_part, &request_bytes);

    let response = next.run(Request::from_parts(parts, body)).await;
    // Recorded only when the edge authenticated the request as a user of the listed tenant.
    let authenticated = response
        .extensions()
        .get::<LogIdentity>()
        .map(|identity| identity.tenant);
    let Some(authenticated) = authenticated else {
        return response;
    };
    if !capture.is_listed_tenant(&slug, authenticated).await {
        return response;
    }
    // Only a response of a known size within the limit is read: anything else passes through untouched.
    let size_fits = response
        .body()
        .size_hint()
        .upper()
        .is_some_and(|size| usize::try_from(size).is_ok_and(|size| size <= capture.limits.max_response_bytes));
    if !size_fits {
        tracing::debug!(tenant = %slug, "a response of unknown or large size is not captured");
        return response;
    }
    let (response_parts, response_body) = response.into_parts();
    let response_bytes = match to_bytes(response_body, capture.limits.max_response_bytes).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "cannot read a response body for the DAV capture");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut response_part = json!({
        "status": response_parts.status.as_u16(),
        "headers": header_list(&response_parts.headers),
    });
    put_body(&mut response_part, &response_bytes);
    let document = json!({
        "schema_version": SCHEMA_VERSION,
        "captured_at": capture.clock.now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "tenant": slug,
        "request": request_part,
        "response": response_part,
    });
    capture.write(&slug, response_parts.status, &method, &document).await;
    Response::from_parts(response_parts, Body::from(response_bytes))
}

#[cfg(test)]
mod tests {
    use axum::routing::any;
    use davhaven_ports::testing::ManualClock;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use super::*;

    /// The tenant the test world authenticates its requests as.
    fn acme() -> TenantId {
        TenantId::from_uuid(Uuid::from_u128(0xAC))
    }

    fn other() -> TenantId {
        TenantId::from_uuid(Uuid::from_u128(0x07))
    }

    /// Tenant ids by slug.
    struct Ids(BTreeMap<String, TenantId>);

    #[async_trait]
    impl TenantIds for Ids {
        async fn id_of(&self, slug: &TenantSlug) -> Option<TenantId> {
            self.0.get(slug.as_str()).copied()
        }
    }

    /// The edge as the capture sees it: an exchange that was authenticated as `identity` carries that identity in its
    /// response, an exchange without one (a 401) does not.
    #[derive(Clone)]
    struct Authenticated(Option<TenantId>);

    async fn echo(State(authenticated): State<Authenticated>, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() = if authenticated.0.is_some() {
            StatusCode::MULTI_STATUS
        } else {
            StatusCode::UNAUTHORIZED
        };
        response
            .headers_mut()
            .insert("set-cookie", HeaderValue::from_static("session=secret"));
        response
            .headers_mut()
            .insert("x-method", HeaderValue::from_str(parts.method.as_str()).unwrap());
        if let Some(tenant) = authenticated.0 {
            response.extensions_mut().insert(LogIdentity {
                tenant,
                principal: None,
            });
        }
        response
    }

    fn config(directory: &std::path::Path, tenants: &[&str]) -> DavCaptureConfig {
        DavCaptureConfig {
            enabled: true,
            tenants: tenants
                .iter()
                .map(|slug| davhaven_domain::TenantSlug::parse(slug).unwrap())
                .collect(),
            dir: Some(directory.to_path_buf()),
            ..DavCaptureConfig::default()
        }
    }

    fn limits() -> CaptureLimits {
        CaptureLimits {
            max_request_bytes: 1024,
            max_response_bytes: 1024,
            request_timeout: Duration::from_secs(60),
            concurrency: 8,
        }
    }

    async fn capture(directory: &std::path::Path, tenants: &[&str], limits: CaptureLimits) -> Arc<Capture> {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::default());
        let ids = Ids(BTreeMap::from([
            ("acme".to_owned(), acme()),
            ("other".to_owned(), other()),
        ]));
        Capture::start_with(&config(directory, tenants), clock, Arc::new(ids), limits)
            .await
            .unwrap()
            .unwrap()
    }

    /// A DAV router whose exchanges are authenticated as `authenticated`.
    async fn app_as(
        directory: &std::path::Path,
        tenants: &[&str],
        limits: CaptureLimits,
        authenticated: Option<TenantId>,
    ) -> Router {
        capture(directory, tenants, limits).await.layer(
            Router::new()
                .fallback(any(echo))
                .with_state(Authenticated(authenticated)),
        )
    }

    async fn app(directory: &std::path::Path, tenants: &[&str]) -> Router {
        app_as(directory, tenants, limits(), Some(acme())).await
    }

    fn files(directory: &std::path::Path) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        found.sort();
        found
    }

    fn propfind(path: &str, body: &'static [u8]) -> Request {
        Request::builder()
            .method("PROPFIND")
            .uri(path)
            .header("authorization", "Basic b2xpdmlhOnNlY3JldA==")
            .header("depth", "1")
            .header("content-length", body.len())
            .body(Body::from(body))
            .unwrap()
    }

    #[test]
    fn the_tenant_is_the_segment_after_principals_or_calendars() {
        assert_eq!(tenant_of("/dav/calendars/acme/olivia/work/"), Some("acme"));
        assert_eq!(tenant_of("/dav/principals/acme/olivia/"), Some("acme"));
        assert_eq!(tenant_of("/dav/calendars/acme"), Some("acme"));
        for none in [
            "/dav/",
            "/dav/calendars/",
            "/dav/other/acme/",
            "/api/v1/tenants",
            "/.well-known/caldav",
            "/dav",
        ] {
            assert_eq!(tenant_of(none), None, "{none}");
        }
    }

    #[tokio::test]
    async fn an_exchange_of_a_listed_tenant_is_recorded_without_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let app = app(directory.path(), &["acme"]).await;
        let response = app
            .oneshot(propfind("/dav/calendars/acme/olivia/?x=1", b"<propfind/>"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"<propfind/>", "the exchange itself is untouched");

        let written = files(directory.path());
        assert_eq!(written.len(), 1);
        let name = written[0].file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with("-000000-PROPFIND-207.json"), "{name}");
        let text = std::fs::read_to_string(&written[0]).unwrap();
        assert!(
            !text.contains("b2xpdmlhOnNlY3JldA") && !text.contains("session=secret"),
            "{text}"
        );
        let document: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["tenant"], "acme");
        assert_eq!(document["request"]["method"], "PROPFIND");
        assert_eq!(document["request"]["path"], "/dav/calendars/acme/olivia/");
        assert_eq!(document["request"]["query"], "x=1");
        assert_eq!(document["request"]["body"], "<propfind/>");
        assert_eq!(document["response"]["status"], 207);
        assert_eq!(document["response"]["body"], "<propfind/>");
        let headers = document["request"]["headers"].as_array().unwrap();
        assert!(
            headers
                .iter()
                .any(|pair| pair[0] == "authorization" && pair[1] == REDACTED)
        );
        assert!(headers.iter().any(|pair| pair[0] == "depth" && pair[1] == "1"));
        let answered = document["response"]["headers"].as_array().unwrap();
        assert!(
            answered
                .iter()
                .any(|pair| pair[0] == "set-cookie" && pair[1] == REDACTED)
        );
        assert!(
            answered
                .iter()
                .any(|pair| pair[0] == "x-method" && pair[1] == "PROPFIND")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&written[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn other_tenants_and_other_paths_are_not_recorded() {
        let directory = tempfile::tempdir().unwrap();
        let app = app(directory.path(), &["acme"]).await;
        for path in [
            "/dav/calendars/other/olivia/",
            "/dav/",
            "/.well-known/caldav",
            "/api/v1/tenants",
        ] {
            let response = app.clone().oneshot(propfind(path, b"x")).await.unwrap();
            assert_eq!(response.status(), StatusCode::MULTI_STATUS, "{path}");
        }
        assert_eq!(files(directory.path()), Vec::<PathBuf>::new());
    }

    #[tokio::test]
    async fn an_exchange_that_was_not_authenticated_is_not_written() {
        let directory = tempfile::tempdir().unwrap();
        // The client has not logged in yet: the edge answers 401 and leaves no identity.
        let app = app_as(directory.path(), &["acme"], limits(), None).await;
        let response = app
            .oneshot(propfind("/dav/calendars/acme/olivia/", b"<propfind/>"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "the client still gets its answer"
        );
        assert_eq!(
            files(directory.path()),
            Vec::<PathBuf>::new(),
            "but a 401 exchange is no capture"
        );
    }

    #[tokio::test]
    async fn the_probe_of_a_user_of_another_tenant_is_not_written() {
        let directory = tempfile::tempdir().unwrap();
        // A user of `other`, who may not have agreed to a capture, asks for a path of `acme`.
        let app = app_as(directory.path(), &["acme"], limits(), Some(other())).await;
        let response = app
            .clone()
            .oneshot(propfind("/dav/calendars/acme/olivia/", b"<propfind/>"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        assert_eq!(files(directory.path()), Vec::<PathBuf>::new());
        // The same path asked for by a user of `acme` is written.
        let own = app_as(directory.path(), &["acme"], limits(), Some(acme())).await;
        own.oneshot(propfind("/dav/calendars/acme/olivia/", b"<propfind/>"))
            .await
            .unwrap();
        assert_eq!(files(directory.path()).len(), 1);
    }

    #[tokio::test]
    async fn binary_bodies_are_written_as_base64_and_sequences_never_collide() {
        let directory = tempfile::tempdir().unwrap();
        let app = app(directory.path(), &["acme"]).await;
        for _ in 0..2 {
            let request = Request::builder()
                .method("PUT")
                .uri("/dav/calendars/acme/olivia/work/a.ics")
                .header("content-length", 3)
                .body(Body::from(vec![0xff_u8, 0xfe, 0x00]))
                .unwrap();
            app.clone().oneshot(request).await.unwrap();
        }
        let written = files(directory.path());
        assert_eq!(written.len(), 2, "the manual clock does not move, the sequence does");
        let document: Value = serde_json::from_str(&std::fs::read_to_string(&written[1]).unwrap()).unwrap();
        assert_eq!(
            document["request"]["body_base64"],
            STANDARD.encode([0xff_u8, 0xfe, 0x00])
        );
        assert!(document["request"].get("body").is_none());
    }

    #[tokio::test]
    async fn a_body_over_the_dav_limit_or_without_a_declared_length_passes_through_unrecorded() {
        let directory = tempfile::tempdir().unwrap();
        let app = app(directory.path(), &["acme"]).await;
        let chunked = Request::builder()
            .method("PUT")
            .uri("/dav/calendars/acme/olivia/work/a.ics")
            .header("transfer-encoding", "chunked")
            .body(Body::from("chunked"))
            .unwrap();
        let response = app.clone().oneshot(chunked).await.unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        // The limit is that of the DAV surface (1 KiB here), not 32 MiB: a body over it is never buffered by the capture.
        let huge = Request::builder()
            .method("PUT")
            .uri("/dav/calendars/acme/olivia/work/a.ics")
            .header("content-length", 1025)
            .body(Body::from("small"))
            .unwrap();
        let response = app.oneshot(huge).await.unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        assert_eq!(files(directory.path()), Vec::<PathBuf>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_never_arrives_ends_with_the_request_timeout() {
        let directory = tempfile::tempdir().unwrap();
        let mut bounded = limits();
        bounded.request_timeout = Duration::from_secs(5);
        let app = app_as(directory.path(), &["acme"], bounded, Some(acme())).await;
        // The client announces ten bytes and sends none.
        let stalled = Request::builder()
            .method("PUT")
            .uri("/dav/calendars/acme/olivia/work/a.ics")
            .header("content-length", 10)
            .body(Body::from_stream(futures::stream::pending::<
                Result<Vec<u8>, std::io::Error>,
            >()))
            .unwrap();
        let response = app.oneshot(stalled).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
        assert_eq!(files(directory.path()), Vec::<PathBuf>::new());
    }

    #[tokio::test]
    async fn at_its_concurrency_limit_the_capture_lets_requests_through_unrecorded() {
        let directory = tempfile::tempdir().unwrap();
        let mut none_left = limits();
        none_left.concurrency = 0;
        let app = app_as(directory.path(), &["acme"], none_left, Some(acme())).await;
        let response = app
            .oneshot(propfind("/dav/calendars/acme/olivia/", b"<propfind/>"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS, "the request is served");
        assert_eq!(files(directory.path()), Vec::<PathBuf>::new());
    }

    #[tokio::test]
    async fn a_response_that_is_too_large_passes_through_untouched_and_unrecorded() {
        let directory = tempfile::tempdir().unwrap();
        let mut small = limits();
        small.max_response_bytes = 4;
        let app = app_as(directory.path(), &["acme"], small, Some(acme())).await;
        let response = app
            .oneshot(propfind("/dav/calendars/acme/olivia/", b"<propfind/>"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::MULTI_STATUS,
            "no 500 for a response the capture cannot hold"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"<propfind/>");
        assert_eq!(files(directory.path()), Vec::<PathBuf>::new());
    }

    #[tokio::test]
    async fn a_disabled_capture_does_nothing_and_a_broken_one_is_refused() {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::default());
        let ids: Arc<dyn TenantIds> = Arc::new(Ids(BTreeMap::new()));
        let disabled = DavCaptureConfig::default();
        assert!(
            Capture::start_with(&disabled, Arc::clone(&clock), Arc::clone(&ids), limits())
                .await
                .unwrap()
                .is_none()
        );
        let no_dir = DavCaptureConfig {
            enabled: true,
            tenants: vec![davhaven_domain::TenantSlug::parse("acme").unwrap()],
            dir: None,
            ..DavCaptureConfig::default()
        };
        assert!(
            Capture::start_with(&no_dir, Arc::clone(&clock), Arc::clone(&ids), limits())
                .await
                .is_err()
        );
        let directory = tempfile::tempdir().unwrap();
        let no_tenants = config(directory.path(), &[]);
        assert!(Capture::start_with(&no_tenants, clock, ids, limits()).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_capture_directory_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("captures").join("staging");
        capture(&directory, &["acme"], limits()).await;
        let mode = std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "the exchanges of tenants are not for other users of the host"
        );
    }

    #[test]
    fn the_limits_come_from_the_configuration_of_the_dav_surface() {
        let config = Config::from_toml(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[server.http]\nrequest_timeout = \"45s\"\n\
             concurrency_limit = 7\n",
        )
        .unwrap();
        let limits = CaptureLimits::of(&config);
        assert_eq!(limits.request_timeout, Duration::from_secs(45));
        assert_eq!(limits.concurrency, 7);
        assert_eq!(limits.max_response_bytes, MAX_RESPONSE_BYTES);
        let dav = config.limits();
        assert_eq!(
            limits.max_request_bytes,
            usize::try_from(dav.dav.max_request_body.max(dav.ical.max_resource_size)).unwrap()
        );
        assert!(limits.max_request_bytes < 32 * 1024 * 1024, "far below the old 32 MiB");
    }
}
