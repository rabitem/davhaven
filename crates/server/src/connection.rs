//! Serving HTTP connections with the limits of `[server.http]`.
//!
//! [`serve`] is the accept loop of one listener: it hands every connection to hyper's auto-detecting builder
//! (HTTP/1.1, and HTTP/2 with prior knowledge for proxies that speak it) configured with the connection-level
//! protections of PLAN 2.15 that a tower layer cannot enforce because they act before a request exists:
//!
//! * **`header_read_timeout`**: a client that does not finish its request headers in time is disconnected (slowloris).
//!   hyper's own timer starts only when it reads the head of an HTTP/1 request, *after* it has detected which protocol the
//!   client speaks, and detection waits for the first bytes with no timer at all. So the timer is not enough: a client
//!   that connects and sends nothing, or a part of the HTTP/2 preface, or the whole preface and then nothing, would hold
//!   its socket for ever. Every connection therefore also has an **idle watchdog** ([`Activity`]): a connection with no
//!   request in flight for `header_read_timeout` is closed, whatever protocol it speaks, whether it never sent a request
//!   or finished its last one. A request that is being handled (or whose response body is still being sent) is not idle,
//!   so a slow handler is never cut off by it; the request timeout of the edge bounds those.
//! * **HTTP/2 keep-alive**: the server pings an HTTP/2 connection every `header_read_timeout` and closes it when the
//!   peer does not answer within the same time, so a peer that has vanished does not hold the connection either.
//! * **`max_connections`**: a counter of open connections per listener. When it is reached the accept loop waits for a
//!   connection to close; further clients wait in the accept queue of the operating system. `concurrency_limit` counts
//!   requests, not sockets, so without this an unauthenticated client could exhaust the file descriptors of the process
//!   with idle connections.
//! * **`max_header_bytes`**: hyper answers 431 when the request head does not fit its read buffer, and refuses HTTP/2
//!   header lists above the limit. hyper cannot make the buffer smaller than 8 KiB, so [`header_guard`] enforces the
//!   exact limit on the parsed request when the configured limit is smaller than that. The answer of the guard has the
//!   form of the surface that the path belongs to (a problem document for the API and MCP, the `DAV:` error form for
//!   DAV, a small page for the web pages) and carries the request id. The 431 that hyper itself sends when the head does
//!   not fit its buffer has no body: the request never reached the application, and hyper has no way to render one.
//!   **A trade-off of this design:** hyper's read buffer is capped at the header limit (at least 8 KiB), and the same buffer
//!   is what request bodies are read through, so a body arrives in reads of at most that size (16 KiB by default) instead of
//!   the several hundred kilobytes hyper allows when nothing caps it. The calendar traffic of this server is made of small
//!   requests (a resource is at most 1 MiB, PLAN 2.15), where the extra reads and wake-ups are not measurable; a deployment
//!   whose clients upload batches of ten megabytes at the API raises `server.http.max_header_bytes` to buy larger reads, at
//!   the cost of a looser header limit.
//!
//! The peer address goes into the request as `ConnectInfo<SocketAddr>`, which the edge's client address layer
//! reads (`X-Forwarded-For` counts only behind a trusted proxy).
//!
//! When the cancellation token fires the loop stops accepting and gives the connections that are open `grace` to
//! finish their requests; idle ones are closed at once, and the connections that are still open when the grace period is
//! over are aborted, so none outlives the shutdown and holds a database connection.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CONTENT_TYPE, HeaderName};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use davhaven_dav::errors::DavProblems;
use davhaven_http::limits::HttpConfig;
use davhaven_http::problem::{EdgeProblem, JsonProblems, ProblemCode, ProblemRenderer as _};
use davhaven_http::request_id::{RequestIdSource, X_REQUEST_ID};
use davhaven_web::errors::WebProblems;
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::{GracefulConnection, GracefulShutdown};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

/// The smallest read buffer hyper allows, and so the smallest header limit hyper itself can enforce.
pub const MIN_HEADER_BUFFER: usize = 8 * 1024;

/// How long the accept loop waits after a failed `accept` (out of file descriptors, a reset connection in the
/// queue) before it tries again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The connection-level limits of `[server.http]` and `[server]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// How long a client may take to send the request headers, and how long a connection may stay without a request.
    pub header_read_timeout: Duration,
    /// The largest header block in bytes.
    pub max_header_bytes: usize,
    /// The most connections one listener keeps open at the same time.
    pub max_connections: usize,
}

impl ConnectionLimits {
    /// The limits of `[server.http]` with the connection cap of `[server]`.
    pub const fn new(http: &HttpConfig, max_connections: usize) -> Self {
        Self {
            header_read_timeout: http.header_read_timeout,
            max_header_bytes: http.max_header_bytes,
            max_connections,
        }
    }
}

/// The hyper builder with the limits applied.
pub fn connection_builder(limits: &ConnectionLimits) -> Builder<TokioExecutor> {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .max_buf_size(limits.max_header_bytes.max(MIN_HEADER_BUFFER));
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_header_list_size(u32::try_from(limits.max_header_bytes).unwrap_or(u32::MAX))
        .keep_alive_interval(limits.header_read_timeout)
        .keep_alive_timeout(limits.header_read_timeout);
    builder
}

/// What a connection has been doing: how many requests are in flight and when it last did anything. The idle watchdog
/// reads it.
#[derive(Debug)]
pub struct Activity {
    started: Instant,
    last_ms: AtomicU64,
    in_flight: AtomicUsize,
}

impl Activity {
    /// A connection that was just accepted: idle since now.
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            last_ms: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(Instant::now().saturating_duration_since(self.started).as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last_ms.store(self.elapsed_ms(), Ordering::Relaxed);
    }

    /// A request begins; it is in flight until the returned guard is dropped (with its response body).
    fn begin(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.touch();
        InFlight(Arc::clone(self))
    }

    /// How long the connection has had no request in flight; zero while one is.
    fn idle(&self) -> Duration {
        if self.in_flight.load(Ordering::Relaxed) > 0 {
            return Duration::ZERO;
        }
        let since = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        Instant::now()
            .saturating_duration_since(self.started)
            .saturating_sub(since)
    }

    /// Completes when the connection has been idle for `limit`.
    pub async fn idle_for(&self, limit: Duration) {
        loop {
            let idle = self.idle();
            if idle >= limit {
                return;
            }
            tokio::time::sleep(limit.saturating_sub(idle)).await;
        }
    }
}

impl Default for Activity {
    fn default() -> Self {
        Self::new()
    }
}

/// A request in flight on a connection.
#[derive(Debug)]
struct InFlight(Arc<Activity>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.0.touch();
    }
}

/// A response body that keeps its request in flight until the body is dropped, so the idle watchdog does not close a
/// connection whose response is still being sent.
struct Tracked {
    inner: Body,
    _in_flight: InFlight,
}

impl HttpBody for Tracked {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The surface a request path belongs to, for the form of an answer that the edge layers never get to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `/api/…` and `/mcp`: an RFC 9457 problem document.
    Problem,
    /// `/dav/…` and `/.well-known/…`: the DAV form.
    Dav,
    /// `/rsvp/…`, `/feeds/…`, `/oauth/…` and `/assets/…`: a small page.
    Page,
    /// The operations endpoints and everything else: plain text.
    Plain,
}

fn form_of(path: &str) -> Form {
    let under = |prefix: &str| path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'));
    if under("/api") || under("/mcp") {
        Form::Problem
    } else if under("/dav") || under("/.well-known") {
        Form::Dav
    } else if under("/rsvp") || under("/feeds") || under("/oauth") || under("/assets") {
        Form::Page
    } else {
        Form::Plain
    }
}

/// The answer to a request whose head is larger than the limit: status 431 in the form of the surface, with the id of the
/// request in `X-Request-Id` (and in the problem document).
fn head_too_large(form: Form, ids: &dyn RequestIdSource) -> Response {
    let request_id = ids.next_id();
    let problem = EdgeProblem::new(ProblemCode::BadRequest)
        .with_detail("The headers of the request are larger than the server accepts.");
    let mut response = match form {
        Form::Problem => JsonProblems::catalog()
            .with_status_table(|_| StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE.as_u16())
            .render(&problem, Some(request_id)),
        Form::Dav => DavProblems.render(&problem, Some(request_id)),
        Form::Page => WebProblems.render(&problem, Some(request_id)),
        Form::Plain => {
            let mut response = Response::new(Body::from("request header fields too large\n"));
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
            response
        }
    };
    *response.status_mut() = StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE;
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(X_REQUEST_ID), value);
    }
    response
}

/// The size of the request head as it was on the wire, closely enough to hold it against a limit: the request line
/// and every header line.
fn head_size(request: &Request) -> usize {
    let line = request
        .method()
        .as_str()
        .len()
        .saturating_add(request.uri().path_and_query().map_or(1, |target| target.as_str().len()))
        // The space after the method, then the version and the line break.
        .saturating_add(1)
        .saturating_add(" HTTP/1.1\r\n".len());
    request.headers().iter().fold(line, |size, (name, value)| {
        size.saturating_add(name.as_str().len())
            .saturating_add(value.len())
            .saturating_add(": \r\n".len())
    })
}

/// What the guard needs: the limit and where request ids come from.
#[derive(Clone)]
struct GuardState {
    limit: usize,
    ids: Arc<dyn RequestIdSource>,
}

async fn guard_header_size(State(state): State<GuardState>, request: Request, next: Next) -> Response {
    if head_size(&request) > state.limit {
        return head_too_large(form_of(request.uri().path()), state.ids.as_ref());
    }
    next.run(request).await
}

/// Refuses requests whose head is larger than `max_header_bytes` with 431. hyper enforces its own buffer size
/// before the request reaches the router; this layer makes the limit exact when it is below hyper's minimum.
pub fn header_guard(router: Router, max_header_bytes: usize, ids: Arc<dyn RequestIdSource>) -> Router {
    router.layer(from_fn_with_state(
        GuardState {
            limit: max_header_bytes,
            ids,
        },
        guard_header_size,
    ))
}

/// The future of one request: the router's answer.
type ServiceFuture = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

/// The hyper service of one connection: the router, with the peer address in every request. A request is in flight for
/// `activity` from the moment its head is parsed until its response body is dropped.
fn connection_service(
    app: Router,
    peer: SocketAddr,
    activity: Arc<Activity>,
) -> impl Fn(hyper::Request<Incoming>) -> ServiceFuture {
    move |request: hyper::Request<Incoming>| {
        let app = app.clone();
        let in_flight = activity.begin();
        Box::pin(async move {
            let mut request = request.map(Body::new);
            request.extensions_mut().insert(ConnectInfo(peer));
            let Ok(response) = app.oneshot(request).await;
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(
                parts,
                Body::new(Tracked {
                    inner: body,
                    _in_flight: in_flight,
                }),
            ))
        })
    }
}

/// The error of a connection of the auto-detecting builder.
type ConnectionError = Box<dyn std::error::Error + Send + Sync>;

/// Prepares the service of one connection on `io`: the hyper connection (not yet polled) and the activity its watchdog
/// reads. The connection can be watched by a [`GracefulShutdown`].
pub fn prepare<I>(
    builder: &Builder<TokioExecutor>,
    io: I,
    app: Router,
    peer: SocketAddr,
) -> (
    impl GracefulConnection<Error = ConnectionError> + Send + 'static,
    Arc<Activity>,
)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let activity = Arc::new(Activity::new());
    let service = service_fn(connection_service(app, peer, Arc::clone(&activity)));
    let connection = builder.serve_connection_with_upgrades(io, service).into_owned();
    (connection, activity)
}

/// Runs a connection until it ends or stays idle for `idle_limit` (see the module documentation).
pub async fn drive<C, E>(connection: C, activity: Arc<Activity>, idle_limit: Duration, peer: SocketAddr)
where
    C: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    tokio::select! {
        result = connection => {
            if let Err(error) = result {
                tracing::debug!(%error, %peer, "a connection ended with an error");
            }
        }
        () = activity.idle_for(idle_limit) => {
            tracing::debug!(%peer, "closed a connection that stayed idle");
        }
    }
}

/// Serves `app` on `listener` until `cancel` fires, then drains for at most `grace`. The caller has put the limits that
/// belong to the edge (`header_guard`) into `app` already.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: ConnectionLimits,
    cancel: CancellationToken,
    grace: Duration,
) {
    let builder = connection_builder(&limits);
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let graceful = GracefulShutdown::new();
    // The connections are owned by the set: the ones that are still open when the grace period is over are aborted with it.
    let mut connections = JoinSet::new();
    loop {
        // A permit first: while the cap is reached the clients wait in the accept queue of the operating system.
        let permit = tokio::select! {
            () = cancel.cancelled() => break,
            permit = Arc::clone(&permits).acquire_owned() => permit,
        };
        let Ok(permit) = permit else {
            break;
        };
        let accepted = tokio::select! {
            () = cancel.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(%error, "cannot accept a connection");
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(ACCEPT_BACKOFF) => continue,
                }
            }
        };
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%error, "cannot set TCP_NODELAY");
        }
        // Finished connections are collected as the loop goes, so the set does not grow with the traffic.
        while connections.try_join_next().is_some() {}
        let (connection, activity) = prepare(&builder, TokioIo::new(stream), app.clone(), peer);
        let watched = graceful.watch(connection);
        let idle_limit = limits.header_read_timeout;
        connections.spawn(async move {
            // The permit is the connection's place in the cap; it goes back when the connection ends.
            let _permit = permit;
            drive(watched, activity, idle_limit, peer).await;
        });
    }
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(grace) => {
            tracing::warn!("some connections did not finish within the shutdown grace period and are closed");
        }
    }
    connections.abort_all();
}

#[cfg(test)]
mod tests {
    use axum::routing::get;
    use davhaven_http::request_id::SequentialRequestIds;
    use http_body_util::BodyExt as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    use super::*;

    async fn who(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
        peer.ip().to_string()
    }

    fn app() -> Router {
        Router::new()
            .route("/who", get(who))
            .route("/ok", get(|| async { "fine" }))
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    "finally"
                }),
            )
    }

    fn ids() -> Arc<dyn RequestIdSource> {
        Arc::new(SequentialRequestIds::default())
    }

    fn guarded(max_header_bytes: usize) -> Router {
        header_guard(app(), max_header_bytes, ids())
    }

    async fn start(
        limits: ConnectionLimits,
        grace: Duration,
    ) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve(
            listener,
            guarded(limits.max_header_bytes),
            limits,
            cancel.clone(),
            grace,
        ));
        (address, cancel, task)
    }

    async fn exchange(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// The first characters of a response, for a failure message.
    fn head(response: &str) -> String {
        response.chars().take(80).collect()
    }

    fn limits(max_header_bytes: usize) -> ConnectionLimits {
        ConnectionLimits {
            header_read_timeout: Duration::from_secs(10),
            max_header_bytes,
            max_connections: 64,
        }
    }

    const GRACE: Duration = Duration::from_secs(2);

    #[tokio::test]
    async fn requests_are_served_and_carry_the_peer_address() {
        let (address, cancel, task) = start(limits(16 * 1024), GRACE).await;
        let response = exchange(address, "GET /who HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("127.0.0.1"), "{response}");
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_headers_get_431_from_hyper_and_from_the_guard() {
        // A limit at hyper's minimum: hyper itself refuses the head.
        let (address, cancel, task) = start(limits(MIN_HEADER_BUFFER), GRACE).await;
        let big = "a".repeat(MIN_HEADER_BUFFER + 512);
        let request = format!("GET /ok HTTP/1.1\r\nHost: x\r\nX-Big: {big}\r\nConnection: close\r\n\r\n");
        let response = exchange(address, &request).await;
        assert!(response.starts_with("HTTP/1.1 431"), "{}", head(&response));
        cancel.cancel();
        task.await.unwrap();

        // A limit below hyper's minimum: the guard enforces it on the parsed request.
        let (address, cancel, task) = start(limits(2048), GRACE).await;
        let medium = "a".repeat(3000);
        let request = format!("GET /ok HTTP/1.1\r\nHost: x\r\nX-Medium: {medium}\r\nConnection: close\r\n\r\n");
        let response = exchange(address, &request).await;
        assert!(response.starts_with("HTTP/1.1 431"), "{}", head(&response));
        let small = exchange(address, "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        assert!(small.starts_with("HTTP/1.1 200"), "{small}");
        cancel.cancel();
        task.await.unwrap();
    }

    /// What the guard answers to a request for `path` whose head is over the limit.
    async fn refused(path: &str) -> (Response, String) {
        let big = "a".repeat(4000);
        let request = Request::builder()
            .uri(path)
            .header("x-big", big)
            .body(Body::empty())
            .unwrap();
        let response = guarded(2048).oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (
            Response::from_parts(parts, Body::empty()),
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    #[tokio::test]
    async fn the_guard_answers_in_the_form_of_the_surface_and_names_the_request() {
        let (api, body) = refused("/api/v1/tenants").await;
        assert_eq!(api.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        assert_eq!(api.headers()[CONTENT_TYPE], "application/problem+json");
        let problem: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(problem["status"], 431, "{body}");
        let request_id = problem["request_id"].as_str().unwrap().to_owned();
        assert_eq!(
            api.headers()[X_REQUEST_ID],
            request_id.as_str(),
            "the document and the header agree"
        );
        assert!(body.contains("larger than the server accepts"), "{body}");
        assert!(!body.contains("aaaa"), "nothing of the request is echoed: {body}");

        let (mcp, _) = refused("/mcp").await;
        assert_eq!(mcp.headers()[CONTENT_TYPE], "application/problem+json");

        let (dav, _) = refused("/dav/calendars/acme/olivia/").await;
        assert_eq!(dav.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        assert!(dav.headers().contains_key(X_REQUEST_ID));
        assert_ne!(
            dav.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/problem+json"))
        );
        let (wellknown, _) = refused("/.well-known/caldav").await;
        assert_eq!(wellknown.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);

        let (page, html) = refused("/rsvp/dvh_rsvp_x").await;
        assert_eq!(page.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        assert!(
            page.headers()[CONTENT_TYPE].to_str().unwrap().starts_with("text/html"),
            "{html}"
        );
        assert!(page.headers().contains_key(X_REQUEST_ID));

        let (plain, text) = refused("/readyz").await;
        assert_eq!(plain.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        assert!(
            plain.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/plain")
        );
        assert!(plain.headers().contains_key(X_REQUEST_ID));
        assert!(text.contains("too large"), "{text}");
    }

    #[test]
    fn paths_belong_to_a_surface_by_their_first_segment() {
        for (path, form) in [
            ("/api/v1/tenants", Form::Problem),
            ("/api", Form::Problem),
            ("/mcp", Form::Problem),
            ("/mcp/x", Form::Problem),
            ("/dav/", Form::Dav),
            ("/.well-known/caldav", Form::Dav),
            ("/rsvp/abc", Form::Page),
            ("/feeds/abc.ics", Form::Page),
            ("/oauth/google/callback", Form::Page),
            ("/assets/a.css", Form::Page),
            ("/healthz", Form::Plain),
            ("/apix", Form::Plain),
            ("/", Form::Plain),
        ] {
            assert_eq!(form_of(path), form, "{path}");
        }
    }

    /// An in-memory connection served the way the accept loop serves a socket; the task ends when the connection does.
    fn in_memory(limits: ConnectionLimits) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(8192);
        let builder = connection_builder(&limits);
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let (connection, activity) = prepare(&builder, TokioIo::new(server), app(), peer);
        let task = tokio::spawn(drive(connection, activity, limits.header_read_timeout, peer));
        (client, task)
    }

    /// Lets `task` finish within `within` of virtual time; `true` when it did.
    async fn finishes(task: &mut tokio::task::JoinHandle<()>, within: Duration) -> bool {
        tokio::time::timeout(within, task).await.is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_finishes_its_headers_is_disconnected() {
        let (mut client, mut task) = in_memory(limits(16 * 1024));
        client.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        assert!(
            !finishes(&mut task, Duration::from_secs(9)).await,
            "the header timeout is 10 s"
        );
        assert!(
            finishes(&mut task, Duration::from_secs(2)).await,
            "the connection was not closed after the header read timeout"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_sends_nothing_is_disconnected() {
        let (_client, mut task) = in_memory(limits(16 * 1024));
        assert!(!finishes(&mut task, Duration::from_secs(9)).await);
        assert!(
            finishes(&mut task, Duration::from_secs(2)).await,
            "protocol detection waits for the first bytes with no timer of its own: the watchdog must end the connection"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_sends_a_part_of_the_http2_preface_is_disconnected() {
        let (mut client, mut task) = in_memory(limits(16 * 1024));
        client.write_all(b"PRI * HTTP/2.0\r\n").await.unwrap();
        assert!(!finishes(&mut task, Duration::from_secs(9)).await);
        assert!(finishes(&mut task, Duration::from_secs(2)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_sends_the_whole_http2_preface_and_then_nothing_is_disconnected() {
        let (mut client, mut task) = in_memory(limits(16 * 1024));
        client.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        assert!(!finishes(&mut task, Duration::from_secs(9)).await);
        assert!(
            finishes(&mut task, Duration::from_secs(2)).await,
            "an HTTP/2 connection without a request has no timer of its own either"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_keep_alive_connection_is_closed_after_its_last_response() {
        let (mut client, mut task) = in_memory(limits(16 * 1024));
        client.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut buffer = [0_u8; 512];
        let read = client.read(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("HTTP/1.1 200"));
        assert!(
            !finishes(&mut task, Duration::from_secs(9)).await,
            "the connection stays for reuse"
        );
        assert!(
            finishes(&mut task, Duration::from_secs(2)).await,
            "and goes after the idle limit"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_request_is_not_idle() {
        let (mut client, mut task) = in_memory(limits(16 * 1024));
        client
            .write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        // The handler takes 30 s, three times the idle limit: the connection must survive and deliver.
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200") && text.ends_with("finally"), "{text}");
        assert!(finishes(&mut task, Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn the_connection_cap_holds_further_clients_until_a_connection_closes() {
        let limits = ConnectionLimits {
            header_read_timeout: Duration::from_secs(60),
            max_header_bytes: 16 * 1024,
            max_connections: 2,
        };
        let (address, cancel, task) = start(limits, GRACE).await;
        // Two clients hold the two places; each has proved that it is served.
        let mut first = TcpStream::connect(address).await.unwrap();
        let mut second = TcpStream::connect(address).await.unwrap();
        for stream in [&mut first, &mut second] {
            stream.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
            let mut buffer = [0_u8; 256];
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("HTTP/1.1 200"));
        }
        // The third client connects (the operating system queues it) and sends its request: nobody answers it.
        let mut third = TcpStream::connect(address).await.unwrap();
        third
            .write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buffer = Vec::new();
        let early = tokio::time::timeout(Duration::from_millis(300), third.read_to_end(&mut buffer)).await;
        assert!(
            early.is_err() && buffer.is_empty(),
            "the third connection was served beyond the cap"
        );
        // A place becomes free: the waiting client is served at once.
        drop(first);
        let answered = tokio::time::timeout(Duration::from_secs(10), third.read_to_end(&mut buffer)).await;
        assert!(answered.is_ok(), "the waiting client was never served");
        assert!(
            String::from_utf8_lossy(&buffer).starts_with("HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&buffer)
        );
        drop(second);
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn the_loop_stops_when_cancelled_and_refuses_new_connections() {
        let (address, cancel, task) = start(limits(16 * 1024), GRACE).await;
        cancel.cancel();
        task.await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn connections_still_open_after_the_grace_period_are_closed() {
        // A handler that announces that it has started and then never finishes within the test.
        let started = Arc::new(tokio::sync::Notify::new());
        let announce = Arc::clone(&started);
        let router = Router::new().route(
            "/stuck",
            get(move || {
                let announce = Arc::clone(&announce);
                async move {
                    announce.notify_one();
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    "finally"
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve(
            listener,
            router,
            limits(16 * 1024),
            cancel.clone(),
            Duration::from_millis(200),
        ));
        let mut stuck = TcpStream::connect(address).await.unwrap();
        stuck
            .write_all(b"GET /stuck HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        started.notified().await;
        cancel.cancel();
        task.await.unwrap();
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(5), stuck.read_to_end(&mut rest)).await;
        assert!(closed.is_ok(), "the connection outlived the shutdown");
        assert!(!String::from_utf8_lossy(&rest).contains("finally"));
    }

    #[test]
    fn the_head_size_counts_the_request_line_and_the_headers() {
        let request = Request::builder()
            .method("GET")
            .uri("/a?b=c")
            .header("host", "x")
            .body(Body::empty())
            .unwrap();
        // "GET /a?b=c HTTP/1.1\r\n" is 21 bytes, "host: x\r\n" is 9.
        assert_eq!(head_size(&request), 30);
    }

    #[test]
    fn the_activity_of_a_connection_is_idle_until_a_request_begins() {
        let activity = Arc::new(Activity::new());
        let guard = activity.begin();
        assert_eq!(activity.idle(), Duration::ZERO, "a request in flight is not idle");
        drop(guard);
        assert_eq!(activity.in_flight.load(Ordering::Relaxed), 0);
    }
}
