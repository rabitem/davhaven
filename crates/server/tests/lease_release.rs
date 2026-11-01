//! A graceful stop hands the outbox claims of a pass that was cut off back to the queue (PLAN 2.17).
//!
//! `davhaven serve` drives the workers with the supervisor. When the grace period is over the pass that is still
//! running is dropped, and the worker's shutdown hook (`OutboxWorker::shutdown`, which calls the dispatcher's
//! `release_held`) must make the records of that pass due again at once, with the unfinished attempt not counted, so
//! that no delivery waits for the lease to expire and no attempt is lost. The dispatcher's own tests cover its `run`
//! loop; the server drives `tick` instead, so this composition is tested here, with a handler that never finishes.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use davhaven_app::AppCore;
use davhaven_domain::{OutboxId, TenantId, TenantSlug};
use davhaven_ports::testing::{ManualClock, SeqIds};
use davhaven_ports::{
    Clock, HandlerError, IdGenerator, NewOutbox, OutboxFilter, OutboxHandler, OutboxMessage, OutboxRecord,
    OutboxStatus, PageReq, Reserved, TxMode,
};
use davhaven_server::admin::{self, BootstrapRequest, SettingsFlags, TokenSink};
use davhaven_server::assembly::{Assembly, assemble_with_ports};
use davhaven_server::config::Config;
use davhaven_server::registry::registry;
use davhaven_server::workers::Supervisor;
use tokio_util::sync::CancellationToken;

const DEV: &str = r#"
    [server]
    mode = "dev"
    public_base_url = "http://localhost:8080"
    [plugins]
    store = "memory"
    mail_transport = "memory"
    rate_limiter = "memory"
    http_client = "recording"
"#;

/// A handler of the reserved push kind that never finishes: the pass that runs it is the one the shutdown cuts off.
struct Hangs;

#[async_trait]
impl OutboxHandler for Hangs {
    fn kind(&self) -> &'static str {
        "provider_push"
    }

    async fn handle(&self, _record: &OutboxRecord) -> Result<(), HandlerError> {
        std::future::pending().await
    }
}

/// The record as the store has it.
async fn record(assembly: &Assembly, tenant: TenantId, id: OutboxId) -> OutboxRecord {
    let mut tx = assembly.deps.database.begin(tenant, TxMode::ReadOnly).await.unwrap();
    let filter = OutboxFilter {
        status: None,
        kind: None,
    };
    let page = tx.outbox().list(&filter, PageReq::first(100)).await.unwrap();
    page.items.into_iter().find(|record| record.id == id).unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_pass_that_is_cut_off_at_shutdown_hands_its_claim_back_with_the_attempt_uncounted() {
    let clock = Arc::new(ManualClock::default());
    let ids: Arc<dyn IdGenerator> = Arc::new(SeqIds::new());
    let config = Arc::new(Config::from_toml(DEV).unwrap());
    let assembly = assemble_with_ports(
        config,
        &Arc::new(registry().unwrap()),
        Arc::<ManualClock>::clone(&clock),
        Arc::clone(&ids),
    )
    .await
    .unwrap();

    // A tenant and one message for the handler that hangs.
    let mut secret = Vec::new();
    let tenant = admin::bootstrap(
        &assembly.deps,
        &assembly.services,
        &BootstrapRequest {
            tenant: TenantSlug::parse("acme").unwrap(),
            display_name: None,
            login_domain: None,
            settings: SettingsFlags::default(),
            label: "test".to_owned(),
            scopes: admin::default_scopes(),
            expires_at: None,
        },
        &TokenSink::Stdout,
        &mut secret,
    )
    .await
    .unwrap()
    .tenant
    .id;
    let message = OutboxId::from_uuid(ids.new_id());
    let mut tx = assembly.deps.database.begin(tenant, TxMode::ReadWrite).await.unwrap();
    tx.outbox()
        .enqueue(NewOutbox::now(
            message,
            OutboxMessage::ProviderPush(Reserved::default()),
        ))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // The workers of the application, with the handler that hangs next to the ones of the adapters, driven the way
    // `davhaven serve` drives them.
    let mut deps = assembly.deps.clone();
    deps.outbox_handlers.push(Arc::new(Hangs));
    let app = davhaven_app::workers::build(&AppCore::new(deps));
    assert_eq!(app.lifecycles.len(), 1, "the outbox worker has a shutdown hook");
    let cancel = CancellationToken::new();
    let running = Supervisor::new(app.workers).spawn(&cancel, Duration::from_secs(2));

    // A pass claims the record and gets stuck in the handler.
    let mut claimed = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stored = record(&assembly, tenant, message).await;
        if stored.status == OutboxStatus::InFlight {
            assert_eq!(stored.attempts, 1, "the claim counts as an attempt while it runs");
            assert!(stored.locked_until.is_some());
            claimed = true;
            break;
        }
    }
    assert!(claimed, "no pass claimed the record");

    // The stop signal: the pass gets the grace period, then it is dropped, then the hook runs.
    cancel.cancel();
    assert!(
        running.stop(Duration::from_secs(10)).await,
        "the supervisor ends its tasks once the pass has been cut off"
    );
    let stuck = record(&assembly, tenant, message).await;
    assert_eq!(
        stuck.status,
        OutboxStatus::InFlight,
        "the claim is still held when the pass is dropped: only the hook gives it back"
    );
    app.lifecycles[0].shutdown().await;

    let released = record(&assembly, tenant, message).await;
    assert_eq!(released.status, OutboxStatus::Pending, "the record is claimable again");
    assert_eq!(released.attempts, 0, "the attempt that never finished is not counted");
    assert_eq!(released.locked_until, None);
    assert!(
        released.next_attempt_at <= clock.now(),
        "due at once, not when the lease would have expired: {:?} against {:?}",
        released.next_attempt_at,
        clock.now()
    );
}
