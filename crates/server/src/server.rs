//! Running the server: the listeners with their route groups, the workers and the shutdown sequence.
//!
//! [`start`] takes an [`Assembly`], binds every enabled listener (all of them, before any serves: a port that is taken
//! fails the start cleanly), builds the router of each listener from its route groups behind the shared edge layers
//! and spawns the accept loops, the supervised workers and the upkeep of the metrics recorder. The returned
//! [`Running`] knows the addresses and stops everything in the order described in [`crate::shutdown`].
//!
//! Which routes a listener serves comes from `server.listeners.<name>.routes` (PLAN 2.5): the default `public`
//! listener serves `wellknown`, `dav` and `web`, `internal` serves `api` and `mcp`, `ops` serves `ops`; a deployment
//! may merge them. Every route keeps the edge layers of its own surface (request id, problem rendering,
//! limits, origin guard, tracing), and one concurrency limit is shared by the groups of a listener.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use davhaven_app::{AppDeps, AppServices};
use davhaven_domain::RequestId;
use davhaven_http::request_id::RequestIdSource;
use davhaven_http::{Edge, EdgeSettings, Surface};
use davhaven_ports::{IdGenerator, Lifecycle};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::assembly::{Assembly, Hook};
use crate::capture::{Capture, CaptureLimits};
use crate::config::Config;
use crate::connection::{ConnectionLimits, header_guard, serve};
use crate::error::ServerError;
use crate::listeners::{ListenerName, ResolvedListener, RouteGroup};
use crate::ops::{self, OpsState};
use crate::shutdown::{self, HOOK_BUDGET, run_hooks};
use crate::telemetry::request_spans;
use crate::workers::{RunningWorkers, Supervisor};

/// How often the Prometheus recorder is asked to do its housekeeping (drain histograms, expire idle metrics).
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Request ids from the id generator (UUIDv7).
struct GeneratedRequestIds(Arc<dyn IdGenerator>);

impl RequestIdSource for GeneratedRequestIds {
    fn next_id(&self) -> RequestId {
        RequestId::from_uuid(self.0.new_id())
    }
}

/// The edge layers shared by the surfaces of one listener: one stack, one concurrency limit.
fn edge_of(config: &Config, ids: &Arc<dyn IdGenerator>) -> Edge {
    Edge::new(Surface::Dav, Arc::new(GeneratedRequestIds(Arc::clone(ids)))).with_settings(EdgeSettings {
        http: config.server.http.clone(),
        trusted_proxies: config.server.trusted_proxies.clone(),
        cors: config.security.cors.clone(),
    })
}

/// The router of one route group.
fn group_router(
    group: RouteGroup,
    services: &AppServices,
    edge: &Edge,
    config: &Config,
    ops: &OpsState,
    capture: Option<&Arc<Capture>>,
) -> Router {
    match group {
        RouteGroup::Wellknown => davhaven_dav::wellknown_router(services.clone(), edge),
        RouteGroup::Dav => {
            let router = davhaven_dav::router(services.clone(), edge);
            match capture {
                Some(capture) => capture.layer(router),
                None => router,
            }
        }
        RouteGroup::Web => davhaven_web::router(services.clone(), edge),
        RouteGroup::Api => davhaven_api::router(services.clone(), edge),
        RouteGroup::Mcp => davhaven_mcp::router(services, &config.mcp, edge),
        RouteGroup::Ops => ops::router(ops.clone()),
    }
}

/// The router of one listener: its route groups merged.
pub fn listener_router(
    listener: &ResolvedListener,
    services: &AppServices,
    config: &Config,
    ids: &Arc<dyn IdGenerator>,
    ops: &OpsState,
    capture: Option<&Arc<Capture>>,
) -> Router {
    let edge = edge_of(config, ids);
    let router = listener.routes.iter().fold(Router::new(), |router, group| {
        router.merge(group_router(*group, services, &edge, config, ops, capture))
    });
    // The exact header limit, below hyper's minimum buffer, answers in the form of the surface the path belongs to.
    let guarded = header_guard(
        router,
        config.server.http.max_header_bytes,
        Arc::new(GeneratedRequestIds(Arc::clone(ids))),
    );
    // The outermost layer: every request runs inside its server span, a child of the caller's span when it sent a W3C
    // `traceparent`, so the edge layers and the port calls of the request nest under it.
    request_spans(guarded)
}

/// A listener that is bound and serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundListener {
    /// Which listener it is.
    pub name: ListenerName,
    /// The address it is bound to (the real port when the configuration asked for port 0).
    pub address: SocketAddr,
    /// The route groups it serves.
    pub routes: Vec<RouteGroup>,
}

/// The running server.
pub struct Running {
    bound: Vec<BoundListener>,
    traffic: Vec<JoinHandle<()>>,
    traffic_cancel: CancellationToken,
    ops: Vec<JoinHandle<()>>,
    ops_cancel: CancellationToken,
    workers: RunningWorkers,
    workers_cancel: CancellationToken,
    upkeep: JoinHandle<()>,
    draining: Arc<AtomicBool>,
    worker_hooks: Vec<Arc<dyn Lifecycle>>,
    hooks: Vec<Hook>,
    delay: Duration,
    grace: Duration,
}

impl core::fmt::Debug for Running {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Running")
            .field("listeners", &self.bound)
            .field("delay", &self.delay)
            .field("grace", &self.grace)
            .finish_non_exhaustive()
    }
}

/// Binds a listener.
async fn bind(listener: &ResolvedListener) -> Result<TcpListener, ServerError> {
    TcpListener::bind(listener.bind)
        .await
        .map_err(|source| ServerError::Bind {
            listener: listener.name.as_str(),
            address: listener.bind,
            source,
        })
}

/// Prepares the opt-in DAV capture of the configuration, and says so in the log when it is on.
async fn start_capture(config: &Config, deps: &AppDeps) -> Result<Option<Arc<Capture>>, ServerError> {
    let capture = Capture::start(
        &config.observability.dav_capture,
        Arc::clone(&deps.clock),
        Arc::clone(&deps.database),
        CaptureLimits::of(config),
    )
    .await?;
    if let Some(capture) = &capture {
        tracing::warn!(
            capture = ?capture,
            "the DAV capture is on: exchanges of the listed tenants are recorded, credentials redacted"
        );
    }
    Ok(capture)
}

/// Starts the server: binds the listeners, spawns the accept loops, the workers and the metrics upkeep.
///
/// `metrics` is the handle of the installed Prometheus recorder; without it `/metrics` answers 503.
///
/// # Errors
///
/// [`ServerError::Bind`] when an address cannot be bound; nothing is left running then.
pub async fn start(assembly: Assembly, metrics: Option<PrometheusHandle>) -> Result<Running, ServerError> {
    let Assembly {
        config,
        core: _,
        deps,
        services,
        workers,
        worker_hooks,
        hooks,
        report: _,
    } = assembly;
    let grace = config.server.shutdown_grace;
    let delay = config.server.shutdown_delay;
    let supervisor = Supervisor::new(workers);
    let health_hooks: Vec<(String, Arc<dyn Lifecycle>)> = hooks
        .iter()
        .filter(|hook| hook.check_health)
        .map(|hook| (hook.name.clone(), Arc::clone(&hook.lifecycle)))
        .collect();
    let ops_state = OpsState::new(
        Arc::clone(&deps.database),
        health_hooks,
        supervisor.heartbeats(),
        metrics.clone(),
    );

    let capture = start_capture(&config, &deps).await?;

    // Bind everything first: a taken port must not leave half a server running.
    let resolved = config.server.listeners.resolved();
    let mut sockets = Vec::with_capacity(resolved.len());
    for listener in &resolved {
        sockets.push(bind(listener).await?);
    }

    let limits = ConnectionLimits::new(&config.server.http, config.server.max_connections);
    let traffic_cancel = CancellationToken::new();
    let ops_cancel = CancellationToken::new();
    let workers_cancel = CancellationToken::new();
    let mut bound = Vec::new();
    let mut traffic = Vec::new();
    let mut ops_tasks = Vec::new();
    for (listener, socket) in resolved.iter().zip(sockets) {
        let address = socket.local_addr().map_err(|source| ServerError::Bind {
            listener: listener.name.as_str(),
            address: listener.bind,
            source,
        })?;
        let router = listener_router(listener, &services, &config, &deps.ids, &ops_state, capture.as_ref());
        // A listener that serves only the ops group stops last, so that `/readyz` reports the draining.
        let only_ops = listener.routes.iter().all(|group| *group == RouteGroup::Ops);
        let (cancel, tasks) = if only_ops {
            (ops_cancel.clone(), &mut ops_tasks)
        } else {
            (traffic_cancel.clone(), &mut traffic)
        };
        tasks.push(tokio::spawn(serve(socket, router, limits, cancel, grace)));
        tracing::info!(
            listener = listener.name.as_str(),
            %address,
            routes = %listener.routes.iter().map(|group| group.as_str()).collect::<Vec<_>>().join(","),
            "listening"
        );
        bound.push(BoundListener {
            name: listener.name,
            address,
            routes: listener.routes.clone(),
        });
    }

    let draining = ops_state.draining_flag();
    let running_workers = supervisor.spawn(&workers_cancel, grace);
    let upkeep = tokio::spawn(upkeep(metrics, workers_cancel.clone()));
    tracing::info!(
        shutdown_delay = ?delay,
        shutdown_grace = ?grace,
        shutdown_bound = ?shutdown::bound(delay, grace),
        "a stop signal is answered within the bound; give the container a stop timeout that is longer"
    );
    Ok(Running {
        bound,
        traffic,
        traffic_cancel,
        ops: ops_tasks,
        ops_cancel,
        workers: running_workers,
        workers_cancel,
        upkeep,
        draining,
        worker_hooks,
        hooks,
        delay,
        grace,
    })
}

/// Runs the housekeeping of the metrics recorder until `cancel` fires.
async fn upkeep(handle: Option<PrometheusHandle>, cancel: CancellationToken) {
    let Some(handle) = handle else {
        return;
    };
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(UPKEEP_INTERVAL) => handle.run_upkeep(),
        }
    }
}

impl Running {
    /// The listeners that are bound.
    pub fn listeners(&self) -> &[BoundListener] {
        &self.bound
    }

    /// The address of a listener, if it is enabled.
    pub fn address(&self, name: ListenerName) -> Option<SocketAddr> {
        self.bound
            .iter()
            .find(|listener| listener.name == name)
            .map(|listener| listener.address)
    }

    /// The addresses by listener name, for logs.
    pub fn addresses(&self) -> BTreeMap<&'static str, SocketAddr> {
        self.bound
            .iter()
            .map(|listener| (listener.name.as_str(), listener.address))
            .collect()
    }

    /// Stops the server in the order of [`crate::shutdown`], within its bound ([`shutdown::bound`], not counting the flush
    /// of the traces and the runtime, which the caller bounds). Returns `true` when everything finished within the grace
    /// period and `false` when workers or hooks had to be cut off.
    pub async fn shutdown(self) -> bool {
        let Self {
            traffic,
            traffic_cancel,
            ops,
            ops_cancel,
            workers,
            workers_cancel,
            upkeep,
            draining,
            worker_hooks,
            hooks,
            delay,
            grace,
            ..
        } = self;
        draining.store(true, Ordering::Relaxed);
        tracing::info!(delay = ?delay, grace = ?grace, "shutting down: /readyz says draining");
        // The load balancer needs a moment to notice: the listeners go on accepting for the delay.
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        tracing::info!(grace = ?grace, "draining requests and workers");
        traffic_cancel.cancel();
        workers_cancel.cancel();
        let listeners = async {
            for task in traffic {
                if let Err(error) = task.await {
                    tracing::error!(%error, "a listener task ended abnormally");
                }
            }
        };
        // Both are bounded by the grace period: the listeners cut off the connections that are still open, the workers the
        // passes that are still running.
        let ((), workers_finished) = tokio::join!(listeners, workers.stop(grace));
        // The hooks share one budget: the leases of the dispatcher first, then the adapters in reverse order of construction.
        let hooks_clean = run_hooks(
            HOOK_BUDGET,
            worker_hooks
                .into_iter()
                .map(|hook| ("worker".to_owned(), hook))
                .chain(hooks.into_iter().rev().map(|hook| (hook.name, hook.lifecycle))),
        )
        .await;
        ops_cancel.cancel();
        for task in ops {
            if let Err(error) = task.await {
                tracing::error!(%error, "the ops listener task ended abnormally");
            }
        }
        drop(upkeep.await);
        tracing::info!("stopped");
        workers_finished && hooks_clean
    }
}
