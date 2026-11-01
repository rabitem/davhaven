//! The operations endpoints of the `ops` route group: `/healthz`, `/readyz` and `/metrics` (PLAN 2.5, 2.17).
//!
//! * `/healthz` says that the process is alive; it checks nothing else, so an orchestrator restarts the process only
//!   when it is wedged and not when the database is away.
//! * `/readyz` says that the instance should receive traffic: the database answers and its schema is at least the
//!   required version (the database adapter's health), the lifecycle hooks of the other adapters are healthy, and
//!   every background worker made progress within twice its interval ([`crate::workers`]). A degraded component
//!   (for example a database whose role is not row-level bound, reported with the reason) still counts as ready.
//!   From the moment the server is asked to stop, `/readyz` answers 503 `draining`: a load balancer that polls it takes the
//!   instance out of rotation. The listeners keep accepting for `server.shutdown_delay` (zero by default, so the
//!   instance stops accepting at once; set it to the time the load balancer needs to notice) and then give the requests
//!   in flight `server.shutdown_grace` to finish. The body is JSON with the status of each component; the reasons come from the
//!   adapters and never contain secrets. `davhaven healthcheck` calls this endpoint, so does the image's
//!   `HEALTHCHECK`.
//! * `/metrics` renders the Prometheus recorder.
//!
//! The endpoints belong on a listener that only operators and monitoring reach (`server.listeners.ops`, loopback
//! by default). They need no authentication and are never mounted on the public listener unless the deployment
//! merges the listeners on purpose, which `davhaven config check` reports. They do not go through the edge layers of
//! the API, but they are bounded all the same: at most [`MAX_CONCURRENT`] requests are served at a time (the others
//! get 503 at once, nothing queues) and none takes longer than [`REQUEST_TIMEOUT`], so a client that hammers `/readyz`
//! cannot turn the health checks of the database into a load of their own.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use davhaven_ports::{Database, Health, Lifecycle};
use futures::future::join_all;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::workers::Heartbeats;

/// How long `/readyz` waits for one component before it reports it unhealthy. It stays clearly below the timeout of the
/// probe that asks (`davhaven healthcheck` and the image's `HEALTHCHECK` give up after
/// [`DEFAULT_TIMEOUT`](crate::healthcheck::DEFAULT_TIMEOUT), 5 s), so a slow component is named in the 503 body and not
/// reported by the probe's own timeout. The components are asked concurrently, so this is also about how long `/readyz`
/// takes at most.
pub const COMPONENT_TIMEOUT: Duration = Duration::from_secs(2);

/// How many requests the operations endpoints serve at the same time. Monitoring asks every few seconds; more than this is
/// a mistake or an attack, and the surplus is refused with 503 instead of queued.
pub const MAX_CONCURRENT: usize = 16;

/// The longest one request to the operations endpoints may take: the components are asked concurrently within
/// [`COMPONENT_TIMEOUT`], so this is a ceiling that only a wedged handler reaches.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The content type of the Prometheus text format.
const PROMETHEUS_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// How well one component of the instance works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    /// It works.
    Healthy,
    /// It works with a restriction that the reason names; the instance still takes traffic.
    Degraded,
    /// It does not work; the instance is not ready.
    Unhealthy,
}

impl From<&Health> for ComponentStatus {
    fn from(health: &Health) -> Self {
        match health {
            Health::Healthy => Self::Healthy,
            Health::Degraded(_) => Self::Degraded,
            Health::Unhealthy(_) => Self::Unhealthy,
        }
    }
}

/// The status of one component of the instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Component {
    /// What it is: `database`, a lifecycle name or `worker:<name>`.
    pub name: String,
    /// How well it works.
    pub status: ComponentStatus,
    /// What is wrong, for a component that is not healthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Component {
    fn of(name: impl Into<String>, health: &Health) -> Self {
        let reason = match health {
            Health::Healthy => None,
            Health::Degraded(reason) | Health::Unhealthy(reason) => Some(reason.clone()),
        };
        Self {
            name: name.into(),
            status: ComponentStatus::from(health),
            reason,
        }
    }
}

/// Whether the instance should receive traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    /// Every component works.
    Ready,
    /// A component does not work.
    NotReady,
    /// The server was asked to stop and takes no new traffic.
    Draining,
}

/// The answer of `/readyz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Readiness {
    /// The verdict.
    pub status: ReadinessStatus,
    /// Every component and its status.
    pub components: Vec<Component>,
}

impl Readiness {
    /// Whether the instance should receive traffic.
    pub const fn is_ready(&self) -> bool {
        matches!(self.status, ReadinessStatus::Ready)
    }
}

/// What the operations endpoints report on.
#[derive(Clone)]
pub struct OpsState {
    database: Arc<dyn Database>,
    lifecycles: Vec<(String, Arc<dyn Lifecycle>)>,
    heartbeats: Heartbeats,
    metrics: Option<PrometheusHandle>,
    draining: Arc<AtomicBool>,
}

impl core::fmt::Debug for OpsState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpsState")
            .field("lifecycles", &self.lifecycles.len())
            .field("workers", &self.heartbeats.len())
            .field("metrics", &self.metrics.is_some())
            .field("draining", &self.draining.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Asks a component for its health, giving up after [`COMPONENT_TIMEOUT`].
async fn ask(name: String, health: impl core::future::Future<Output = Health>) -> Component {
    match tokio::time::timeout(COMPONENT_TIMEOUT, health).await {
        Ok(health) => Component::of(name, &health),
        Err(_elapsed) => Component::of(name, &Health::Unhealthy("did not answer in time".to_owned())),
    }
}

impl OpsState {
    /// The state for a server with this database, these lifecycle hooks (name and hook), these worker heartbeats
    /// and, when a Prometheus recorder is installed, its handle.
    pub fn new(
        database: Arc<dyn Database>,
        lifecycles: Vec<(String, Arc<dyn Lifecycle>)>,
        heartbeats: Heartbeats,
        metrics: Option<PrometheusHandle>,
    ) -> Self {
        Self {
            database,
            lifecycles,
            heartbeats,
            metrics,
            draining: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The flag the server raises when it starts to shut down.
    pub fn draining_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.draining)
    }

    /// Checks every component.
    pub async fn readiness(&self) -> Readiness {
        let database = ask("database".to_owned(), self.database.health());
        let hooks = join_all(
            self.lifecycles
                .iter()
                .map(|(name, lifecycle)| ask(name.clone(), lifecycle.health())),
        );
        let (database, hooks) = tokio::join!(database, hooks);
        let mut components = vec![database];
        components.extend(hooks);
        for worker in self.heartbeats.statuses() {
            let health = if worker.healthy {
                Health::Healthy
            } else {
                Health::Unhealthy(worker.detail.unwrap_or_default())
            };
            components.push(Component::of(format!("worker:{}", worker.name), &health));
        }
        let ready = components
            .iter()
            .all(|component| component.status != ComponentStatus::Unhealthy);
        let status = if self.draining.load(Ordering::Relaxed) {
            ReadinessStatus::Draining
        } else if ready {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::NotReady
        };
        Readiness { status, components }
    }
}

/// The router of the `ops` route group, with its own small limits (see the module documentation).
pub fn router(state: OpsState) -> Router {
    router_with_limits(state, MAX_CONCURRENT, REQUEST_TIMEOUT)
}

fn router_with_limits(state: OpsState, concurrent: usize, timeout: Duration) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
        .layer(from_fn_with_state(
            Bounds {
                permits: Arc::new(Semaphore::new(concurrent)),
                timeout,
            },
            bounded,
        ))
}

/// What bounds the requests of the operations endpoints.
#[derive(Clone)]
struct Bounds {
    permits: Arc<Semaphore>,
    timeout: Duration,
}

/// The answer of an operations request that was refused or cut off: 503, asking the client to come back in a second.
fn unavailable(why: &'static str) -> Response {
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, why).into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn bounded(State(bounds): State<Bounds>, request: Request, next: Next) -> Response {
    let Ok(_permit) = Arc::clone(&bounds.permits).try_acquire_owned() else {
        return unavailable("too many requests to the operations endpoints\n");
    };
    match tokio::time::timeout(bounds.timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_elapsed) => unavailable("the operations endpoint did not answer in time\n"),
    }
}

async fn healthz() -> Response {
    let mut response = "ok\n".into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn readyz(State(state): State<OpsState>) -> Response {
    let report = state.readiness().await;
    let status = if report.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let mut response = (status, axum::Json(report)).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn metrics(State(state): State<OpsState>) -> Response {
    let Some(handle) = &state.metrics else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics are not enabled in this process\n",
        )
            .into_response();
    };
    state.heartbeats.publish();
    let mut response = handle.render().into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(PROMETHEUS_TYPE));
    response
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::extract::Request;
    use davhaven_ports::{StoreError, SystemTx, Tx, TxMode};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::workers::Supervisor;

    /// A database whose health the test sets.
    struct Switchable(tokio::sync::Mutex<Health>);

    #[async_trait]
    impl Database for Switchable {
        async fn begin(&self, _tenant: davhaven_domain::TenantId, _mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn health(&self) -> Health {
            self.0.lock().await.clone()
        }
    }

    struct Hook(Health);

    #[async_trait]
    impl Lifecycle for Hook {
        async fn health(&self) -> Health {
            self.0.clone()
        }

        async fn shutdown(&self) {}
    }

    struct Hangs;

    #[async_trait]
    impl Lifecycle for Hangs {
        async fn health(&self) -> Health {
            std::future::pending().await
        }

        async fn shutdown(&self) {}
    }

    fn state(health: Health, hooks: Vec<(String, Arc<dyn Lifecycle>)>) -> (OpsState, Arc<Switchable>) {
        let database = Arc::new(Switchable(tokio::sync::Mutex::new(health)));
        let shared: Arc<dyn Database> = Arc::<Switchable>::clone(&database);
        (
            OpsState::new(shared, hooks, Supervisor::new(Vec::new()).heartbeats(), None),
            database,
        )
    }

    async fn get_path(state: &OpsState, path: &str) -> (StatusCode, String, axum::http::HeaderMap) {
        let response = router(state.clone())
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (parts.status, String::from_utf8(bytes.to_vec()).unwrap(), parts.headers)
    }

    #[tokio::test]
    async fn healthz_only_says_the_process_is_alive() {
        let (state, _) = state(Health::Unhealthy("the database is away".to_owned()), Vec::new());
        let (status, body, headers) = get_path(&state, "/healthz").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "ok\n"));
        assert_eq!(headers[CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn readyz_follows_the_database() {
        let (state, database) = state(Health::Healthy, Vec::new());
        let (status, body, _) = get_path(&state, "/readyz").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ready");
        assert_eq!(json["components"][0]["name"], "database");
        assert_eq!(json["components"][0]["status"], "healthy");
        assert_eq!(
            json["components"][0].get("reason"),
            None,
            "a healthy component has no reason"
        );

        *database.0.lock().await = Health::Degraded("role is not bound".to_owned());
        let (status, body, _) = get_path(&state, "/readyz").await;
        assert_eq!(status, StatusCode::OK, "degraded is still ready");
        assert!(
            body.contains("role is not bound") && body.contains("degraded"),
            "{body}"
        );

        *database.0.lock().await = Health::Unhealthy("the schema is too old".to_owned());
        let (status, body, _) = get_path(&state, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            body.contains("not_ready") && body.contains("the schema is too old"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn an_unhealthy_hook_makes_the_instance_not_ready() {
        let hooks: Vec<(String, Arc<dyn Lifecycle>)> = vec![
            ("outbox".to_owned(), Arc::new(Hook(Health::Healthy))),
            (
                "limiter".to_owned(),
                Arc::new(Hook(Health::Unhealthy("full".to_owned()))),
            ),
        ];
        let (state, _) = state(Health::Healthy, hooks);
        let report = state.readiness().await;
        assert!(!report.is_ready());
        let names: Vec<&str> = report
            .components
            .iter()
            .map(|component| component.name.as_str())
            .collect();
        assert_eq!(names, vec!["database", "outbox", "limiter"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_component_that_does_not_answer_is_unhealthy() {
        let hooks: Vec<(String, Arc<dyn Lifecycle>)> = vec![("stuck".to_owned(), Arc::new(Hangs))];
        let (state, _) = state(Health::Healthy, hooks);
        let report = state.readiness().await;
        assert!(!report.is_ready());
        assert_eq!(report.components[1].reason.as_deref(), Some("did not answer in time"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_component_is_named_in_a_503_before_the_probe_gives_up() {
        let hooks: Vec<(String, Arc<dyn Lifecycle>)> = vec![("stuck".to_owned(), Arc::new(Hangs))];
        let (state, _) = state(Health::Healthy, hooks);
        // The probe of the image waits `DEFAULT_TIMEOUT` for the whole answer; the answer must be there before that.
        let answered = tokio::time::timeout(crate::healthcheck::DEFAULT_TIMEOUT, get_path(&state, "/readyz")).await;
        let (status, body, _) = answered.expect("/readyz answered only after the probe had given up");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            body.contains("stuck") && body.contains("did not answer in time") && body.contains("unhealthy"),
            "{body}"
        );
        assert!(
            COMPONENT_TIMEOUT < crate::healthcheck::DEFAULT_TIMEOUT,
            "each layer answers before the next one gives up"
        );
    }

    #[test]
    fn the_statuses_are_typed_and_serialize_as_the_names_of_the_contract() {
        for (status, name) in [
            (ReadinessStatus::Ready, "ready"),
            (ReadinessStatus::NotReady, "not_ready"),
            (ReadinessStatus::Draining, "draining"),
        ] {
            assert_eq!(serde_json::to_value(status).unwrap(), name);
        }
        for (health, name) in [
            (Health::Healthy, "healthy"),
            (Health::Degraded("x".to_owned()), "degraded"),
            (Health::Unhealthy("x".to_owned()), "unhealthy"),
        ] {
            assert_eq!(serde_json::to_value(ComponentStatus::from(&health)).unwrap(), name);
        }
        let ready = Readiness {
            status: ReadinessStatus::Ready,
            components: Vec::new(),
        };
        assert!(ready.is_ready());
        assert!(
            !Readiness {
                status: ReadinessStatus::Draining,
                ..ready
            }
            .is_ready()
        );
    }

    #[tokio::test]
    async fn requests_beyond_the_concurrency_limit_are_refused_at_once() {
        let hooks: Vec<(String, Arc<dyn Lifecycle>)> = vec![("stuck".to_owned(), Arc::new(Hangs))];
        let (state, _) = state(Health::Healthy, hooks);
        let app = router_with_limits(state, 1, Duration::from_secs(60));
        // The first request holds the only place: its component never answers within the test.
        let first = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/readyz").body(Body::empty()).unwrap()),
        );
        tokio::task::yield_now().await;
        // So the second is refused without waiting.
        let second = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(second.headers()[RETRY_AFTER], "1");
        first.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_takes_longer_than_the_ceiling_is_cut_off() {
        let hooks: Vec<(String, Arc<dyn Lifecycle>)> = vec![("stuck".to_owned(), Arc::new(Hangs))];
        let (state, _) = state(Health::Healthy, hooks);
        // A ceiling below the time the hanging component takes to be given up on.
        let app = router_with_limits(state, 4, Duration::from_millis(500));
        let response = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
    }

    /// A worker whose pass never ends.
    struct Stuck;

    #[async_trait]
    impl davhaven_ports::Worker for Stuck {
        fn name(&self) -> &'static str {
            "stuck"
        }

        fn interval(&self) -> std::time::Duration {
            std::time::Duration::from_secs(1)
        }

        async fn tick(&self) -> davhaven_ports::WorkReport {
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_worker_whose_pass_hangs_makes_the_instance_not_ready_and_is_named() {
        let supervisor = Supervisor::new(vec![Arc::new(Stuck)]);
        let state = OpsState::new(
            Arc::new(Switchable(tokio::sync::Mutex::new(Health::Healthy))),
            Vec::new(),
            supervisor.heartbeats(),
            None,
        );
        let cancel = tokio_util::sync::CancellationToken::new();
        let running = supervisor.spawn(&cancel, std::time::Duration::from_secs(1));
        let (status, body, _) = get_path(&state, "/readyz").await;
        assert_eq!(status, StatusCode::OK, "a pass that just began is no stall: {body}");

        tokio::time::sleep(crate::workers::PASS_STALL_LIMIT + std::time::Duration::from_secs(1)).await;
        let (status, body, _) = get_path(&state, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let worker = json["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "worker:stuck")
            .unwrap_or_else(|| panic!("the worker is a component: {body}"));
        assert_eq!(worker["status"], "unhealthy");
        assert!(
            worker["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("running for")),
            "{body}"
        );
        cancel.cancel();
        running.join().await;
    }

    #[tokio::test]
    async fn draining_answers_503_even_when_everything_is_healthy() {
        let (state, _) = state(Health::Healthy, Vec::new());
        state.draining_flag().store(true, Ordering::Relaxed);
        let (status, body, _) = get_path(&state, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("draining"), "{body}");
    }

    #[tokio::test]
    async fn metrics_need_a_recorder_and_other_paths_do_not_exist() {
        let (state, _) = state(Health::Healthy, Vec::new());
        let (status, _, _) = get_path(&state, "/metrics").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, _, _) = get_path(&state, "/api/v1/tenants").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("davhaven_ops_test_total").increment(3);
        });
        let with_metrics = OpsState::new(
            Arc::new(Switchable(tokio::sync::Mutex::new(Health::Healthy))),
            Vec::new(),
            Supervisor::new(Vec::new()).heartbeats(),
            Some(handle),
        );
        let (status, body, headers) = get_path(&with_metrics, "/metrics").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("davhaven_ops_test_total 3"), "{body}");
        assert!(
            headers[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/plain; version=0.0.4")
        );
    }

    #[test]
    fn the_draining_flag_is_shared() {
        let (state, _) = state(Health::Healthy, Vec::new());
        let flag: Arc<AtomicBool> = state.draining_flag();
        flag.store(true, Ordering::Relaxed);
        assert!(state.draining.load(Ordering::Relaxed));
    }
}
