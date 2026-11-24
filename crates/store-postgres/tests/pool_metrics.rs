//! Real PostgreSQL pool saturation, acquisition cancellation and sampled occupancy, without sleeps.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test environment that misbehaves fails the test loudly"
)]

mod support;

use std::time::Duration;

use davhaven_domain::TenantId;
use davhaven_ports::{
    Built, ConfigTree, Database, Health, PluginContext, PluginRegistry, PortKind, StoreError, TxMode, Worker,
};
use davhaven_store_postgres::config::PLUGIN;
use davhaven_store_postgres::plugin;
use futures::poll;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use support::TestDatabase;
use tokio::time::timeout;
use uuid::Uuid;

const PROMPT: Duration = Duration::from_secs(20);
const TENANT: TenantId = TenantId::from_uuid(Uuid::from_u128(1));

/// A real plugin build proves that the server receives the sampler, with a one-connection runtime pool.
async fn build(cluster: &support::Cluster) -> (TestDatabase, Built<dyn Database>) {
    let db = TestDatabase::create(cluster).await;
    let mut registry = PluginRegistry::new();
    plugin::register(&mut registry).unwrap();
    let tree = ConfigTree::new().with(
        PLUGIN,
        serde_json::json!({
            "url": cluster.url_for(support::APP, db.name()),
            "migrate_on_start": false,
            "allow_insecure_transport": true,
            "max_connections": 1,
            "acquire_timeout": "60s",
        }),
    );
    let built = registry
        .build_single(PortKind::DATABASE, PLUGIN, &PluginContext::for_tests(), &tree)
        .await
        .unwrap();
    (db, built)
}

/// Exact, unlabelled Prometheus samples also protect the public metric names and label cardinality.
fn gauge(handle: &PrometheusHandle, name: &str) -> f64 {
    let rendered = handle.render();
    let prefix = format!("davhaven_db_pool_{name} ");
    let sample = rendered.lines().find_map(|line| line.strip_prefix(&prefix));
    assert!(sample.is_some(), "missing unlabelled gauge {prefix} in {rendered}");
    sample.unwrap().parse().unwrap()
}

/// The driver releases connections asynchronously; wait for the observable idle state, yielding without sleeping.
async fn idle(worker: &dyn Worker, handle: &PrometheusHandle) {
    timeout(PROMPT, async {
        loop {
            assert!(worker.tick().await.is_idle());
            if gauge(handle, "in_use") == 0.0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the pool returns to idle");
}

#[tokio::test]
async fn the_plugin_samples_tenant_and_system_transactions_after_commit_and_drop() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _recorder = metrics::set_default_local_recorder(&recorder);
    let (_db, built) = build(&cluster).await;
    assert_eq!(built.workers.len(), 1);
    let worker = built.workers.first().unwrap();
    assert_eq!(worker.name(), "postgres_pool_metrics");
    assert_eq!(worker.interval(), Duration::from_secs(1));
    assert_eq!(timeout(PROMPT, built.port.health()).await.unwrap(), Health::Healthy);
    idle(worker.as_ref(), &handle).await;
    assert_eq!(gauge(&handle, "waiting"), 0.0);

    for mode in [TxMode::ReadOnly, TxMode::Snapshot, TxMode::ReadWrite] {
        let tx = built.port.begin(TENANT, mode).await.unwrap();
        worker.tick().await;
        assert_eq!(gauge(&handle, "in_use"), 1.0, "{mode:?}");
        assert_eq!(gauge(&handle, "waiting"), 0.0, "BEGIN is not an acquisition wait");
        tx.commit().await.unwrap();
        idle(worker.as_ref(), &handle).await;
    }
    let tx = built.port.begin(TENANT, TxMode::ReadWrite).await.unwrap();
    worker.tick().await;
    assert_eq!(gauge(&handle, "in_use"), 1.0);
    drop(tx);
    idle(worker.as_ref(), &handle).await;

    for commit in [true, false] {
        let tx = built.port.begin_system().await.unwrap();
        worker.tick().await;
        assert_eq!(gauge(&handle, "in_use"), 1.0);
        assert_eq!(gauge(&handle, "waiting"), 0.0);
        if commit {
            tx.commit().await.unwrap();
        } else {
            drop(tx);
        }
        idle(worker.as_ref(), &handle).await;
    }
    built.lifecycle.unwrap().shutdown().await;
    worker.tick().await;
    assert_eq!(gauge(&handle, "in_use"), 0.0);
    assert_eq!(gauge(&handle, "waiting"), 0.0);
}

#[tokio::test]
async fn concurrent_acquisitions_and_cancelled_readiness_restore_the_waiter_gauge() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _recorder = metrics::set_default_local_recorder(&recorder);
    let (_db, built) = build(&cluster).await;
    let worker = built.workers.first().unwrap();
    let held = built.port.begin_system().await.unwrap();
    let mut tenant = built.port.begin(TENANT, TxMode::ReadOnly);
    let mut system = built.port.begin_system();
    let mut health = Box::pin(built.port.health());
    assert!(poll!(&mut tenant).is_pending());
    assert!(poll!(&mut system).is_pending());
    assert!(poll!(&mut health).is_pending());
    assert_eq!(gauge(&handle, "waiting"), 3.0);
    // Sampling never acquires, even when every connection is held and requests are queued.
    assert!(worker.tick().await.is_idle());
    assert_eq!(gauge(&handle, "in_use"), 1.0);
    drop(tenant);
    assert_eq!(gauge(&handle, "waiting"), 2.0);
    drop(health);
    assert_eq!(gauge(&handle, "waiting"), 1.0);
    held.commit().await.unwrap();
    let tx = timeout(PROMPT, system).await.unwrap().unwrap();
    assert_eq!(gauge(&handle, "waiting"), 0.0);
    worker.tick().await;
    assert_eq!(gauge(&handle, "in_use"), 1.0);
    drop(tx);
    idle(worker.as_ref(), &handle).await;
    built.lifecycle.unwrap().shutdown().await;
}

#[tokio::test]
async fn acquisition_timeout_and_closed_pool_leave_no_phantom_waiters() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _recorder = metrics::set_default_local_recorder(&recorder);
    let (_db, built) = build(&cluster).await;
    let held = built.port.begin_system().await.unwrap();
    tokio::time::pause();
    let mut waiting = built.port.begin(TENANT, TxMode::ReadWrite);
    assert!(poll!(&mut waiting).is_pending());
    assert_eq!(gauge(&handle, "waiting"), 1.0);
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(matches!(waiting.await, Err(StoreError::Timeout)));
    assert_eq!(gauge(&handle, "waiting"), 0.0);
    tokio::time::resume();
    held.commit().await.unwrap();
    built.lifecycle.unwrap().shutdown().await;
    assert!(built.port.begin_system().await.is_err());
    assert_eq!(gauge(&handle, "waiting"), 0.0);
    built.workers.first().unwrap().tick().await;
    assert_eq!(gauge(&handle, "in_use"), 0.0);
}
