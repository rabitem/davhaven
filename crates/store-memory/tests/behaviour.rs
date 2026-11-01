//! Behaviour of the in-memory adapter that the contract suite cannot see: the clock, the snapshot rollback, the
//! sharing of data between clones, the fast failure of a nested transaction and the fault-injecting wrapper that
//! gives the application's retry something to retry.

use std::sync::Arc;

use chrono::{Duration, TimeZone, Utc};
use davhaven_domain::{PrincipalKind, TenantId};
use davhaven_ports::testing::{FaultyDatabase, ManualClock, SeqIds};
use davhaven_ports::{Database, StoreError, TxMode};
use davhaven_store_memory::database::MemoryDatabase;
use std::time::Duration as StdDuration;

fn tenant_id(n: u128) -> TenantId {
    TenantId::from_uuid(uuid::Uuid::from_u128(n))
}

#[expect(
    clippy::unwrap_used,
    reason = "fixture of a test: an invalid literal is a bug of the test"
)]
fn tenant(n: u128, slug: &str) -> davhaven_domain::Tenant {
    davhaven_domain::Tenant {
        id: tenant_id(n),
        slug: davhaven_domain::TenantSlug::parse(slug).unwrap(),
        display_name: slug.to_owned(),
        login_domain: None,
        status: davhaven_domain::TenantStatus::Active,
        settings: davhaven_domain::TenantSettings::default(),
        created_at: chrono::DateTime::UNIX_EPOCH,
        updated_at: chrono::DateTime::UNIX_EPOCH,
        version: 1,
    }
}

#[expect(
    clippy::unwrap_used,
    reason = "fixture of a test: an invalid literal is a bug of the test"
)]
fn principal(n: u128, name: &str, tenant: TenantId) -> davhaven_domain::Principal {
    davhaven_domain::Principal {
        id: davhaven_domain::PrincipalId::from_uuid(uuid::Uuid::from_u128(n)),
        tenant_id: tenant,
        kind: PrincipalKind::User,
        name: davhaven_domain::PrincipalName::parse(name).unwrap(),
        display_name: name.to_owned(),
        email: None,
        locale: None,
        timezone: None,
        external_ref: None,
        status: davhaven_domain::PrincipalStatus::Active,
        deleted_at: None,
        credential_generation: 0,
        created_at: chrono::DateTime::UNIX_EPOCH,
        updated_at: chrono::DateTime::UNIX_EPOCH,
        version: 1,
    }
}

#[tokio::test]
async fn stamps_come_from_the_injected_clock() {
    let start = Utc.with_ymd_and_hms(2031, 5, 6, 7, 8, 9).unwrap();
    let clock = ManualClock::new(start);
    let db = MemoryDatabase::new(Arc::new(clock.clone()), Arc::new(SeqIds::new()));
    let mut system = db.begin_system().await.unwrap();
    let created = system.tenants().create(tenant(1, "acme")).await.unwrap();
    system.commit().await.unwrap();
    assert_eq!(created.created_at, start);
    assert_eq!(created.updated_at, start);

    clock.advance(Duration::hours(3));
    let mut system = db.begin_system().await.unwrap();
    let updated = system.tenants().update(created.clone(), created.version).await.unwrap();
    assert_eq!(updated.created_at, start);
    assert_eq!(updated.updated_at, start + Duration::hours(3));
}

#[tokio::test]
async fn nanoseconds_of_the_clock_are_truncated_to_microseconds() {
    let start = Utc.with_ymd_and_hms(2031, 5, 6, 7, 8, 9).unwrap() + Duration::nanoseconds(123_456_789);
    let db = MemoryDatabase::new(Arc::new(ManualClock::new(start)), Arc::new(SeqIds::new()));
    let mut system = db.begin_system().await.unwrap();
    let created = system.tenants().create(tenant(1, "acme")).await.unwrap();
    assert_eq!(created.created_at.timestamp_subsec_nanos(), 123_456_000);
}

#[tokio::test]
async fn a_dropped_transaction_restores_the_state_and_a_committed_one_keeps_it() {
    let db = MemoryDatabase::new(Arc::new(ManualClock::default()), Arc::new(SeqIds::new()));
    let mut system = db.begin_system().await.unwrap();
    system.tenants().create(tenant(1, "acme")).await.unwrap();
    system.commit().await.unwrap();

    let mut tx = db.begin(tenant_id(1), TxMode::ReadWrite).await.unwrap();
    tx.principals()
        .create(principal(10, "ann", tenant_id(1)))
        .await
        .unwrap();
    drop(tx);
    let mut tx = db.begin(tenant_id(1), TxMode::ReadOnly).await.unwrap();
    assert_eq!(
        tx.principals().get(principal(10, "ann", tenant_id(1)).id).await,
        Err(StoreError::NotFound)
    );
    drop(tx);

    let mut tx = db.begin(tenant_id(1), TxMode::ReadWrite).await.unwrap();
    tx.principals()
        .create(principal(10, "ann", tenant_id(1)))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = db.begin(tenant_id(1), TxMode::ReadOnly).await.unwrap();
    assert!(tx.principals().get(principal(10, "ann", tenant_id(1)).id).await.is_ok());
}

#[tokio::test]
async fn clones_share_their_data() {
    let db = MemoryDatabase::new(Arc::new(ManualClock::default()), Arc::new(SeqIds::new()));
    let twin = db.clone();
    let mut system = db.begin_system().await.unwrap();
    system.tenants().create(tenant(1, "acme")).await.unwrap();
    system.commit().await.unwrap();
    let mut system = twin.begin_system().await.unwrap();
    assert!(system.tenants().get(tenant_id(1)).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_nested_transaction_fails_fast_instead_of_hanging() {
    let db = MemoryDatabase::new(Arc::new(ManualClock::default()), Arc::new(SeqIds::new()));
    // A task that holds a transaction and begins another waits for itself. The adapter reports it once its wait is
    // over (the clock is paused, so the wait ends at once), naming the likely cause.
    let held = db.begin_system().await.unwrap();
    let nested = db.begin(tenant_id(1), TxMode::ReadOnly).await.err();
    let Some(StoreError::Internal(message)) = nested else {
        panic!("a nested begin must fail, got {nested:?}");
    };
    assert!(
        message.contains("nested transaction") && message.contains("one transaction per task"),
        "{message}"
    );
    let nested_system = db.begin_system().await;
    assert!(matches!(nested_system, Err(StoreError::Internal(_))));

    // The held transaction is unaffected, and once it ends the slot is free again.
    drop(held);
    assert!(db.begin(tenant_id(1), TxMode::ReadOnly).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_transaction_of_another_task_is_waited_for_not_reported() {
    let db = MemoryDatabase::new(Arc::new(ManualClock::default()), Arc::new(SeqIds::new()));
    let held = db.begin_system().await.unwrap();
    let other = db.clone();
    let waiter = tokio::spawn(async move { other.begin(tenant_id(1), TxMode::ReadOnly).await.map(|_| ()) });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished(), "the second task waits for the first");
    drop(held);
    assert_eq!(waiter.await.unwrap(), Ok(()), "and proceeds when the slot is free");
}

#[tokio::test(start_paused = true)]
async fn the_wait_for_the_slot_is_configurable() {
    let db = MemoryDatabase::new(Arc::new(ManualClock::default()), Arc::new(SeqIds::new()))
        .with_lock_wait(StdDuration::from_millis(5));
    let _held = db.begin_system().await.unwrap();
    let started = tokio::time::Instant::now();
    assert!(db.begin(tenant_id(1), TxMode::ReadOnly).await.is_err());
    // The clock is paused, so the elapsed time is the wait: the configured one, not the default of ten seconds, and not a
    // refusal that did not wait at all.
    let waited = started.elapsed();
    assert!(
        waited >= StdDuration::from_millis(5) && waited < StdDuration::from_secs(1),
        "the configured wait applies: {waited:?}"
    );
}

#[tokio::test]
async fn injected_commit_failures_roll_back_and_the_retry_succeeds() {
    let inner = Arc::new(MemoryDatabase::new(
        Arc::new(ManualClock::default()),
        Arc::new(SeqIds::new()),
    ));
    let db = FaultyDatabase::new(inner);
    let mut system = db.begin_system().await.unwrap();
    system.tenants().create(tenant(1, "acme")).await.unwrap();
    system.commit().await.unwrap();

    // The commit fails like PostgreSQL's after a conflict, and nothing of the attempt is visible.
    db.fail_next_commits(1);
    let mut tx = db.begin(tenant_id(1), TxMode::ReadWrite).await.unwrap();
    tx.principals()
        .create(principal(10, "ann", tenant_id(1)))
        .await
        .unwrap();
    assert_eq!(tx.commit().await, Err(StoreError::SerializationFailure));
    let mut tx = db.begin(tenant_id(1), TxMode::ReadOnly).await.unwrap();
    assert_eq!(
        tx.principals().get(principal(10, "ann", tenant_id(1)).id).await,
        Err(StoreError::NotFound),
        "the failed attempt was rolled back"
    );
    drop(tx);

    // The application's retry runs the same work again and succeeds.
    let mut tx = db.begin(tenant_id(1), TxMode::ReadWrite).await.unwrap();
    tx.principals()
        .create(principal(10, "ann", tenant_id(1)))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(db.commits(), 3, "the tenant, the failed attempt and the retry");

    // Begins can fail too (an exhausted pool).
    db.fail_next_begins(2);
    assert_eq!(db.begin_system().await.err(), Some(StoreError::Unavailable));
    assert_eq!(
        db.begin(tenant_id(1), TxMode::ReadOnly).await.err(),
        Some(StoreError::Unavailable)
    );
    assert!(db.begin_system().await.is_ok());
}
