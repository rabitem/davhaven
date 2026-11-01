//! What only a database with real concurrency can show: the write invariant's calendar lock, the order in which
//! two calendars are locked, `FOR UPDATE SKIP LOCKED` on the outbox queue and the rollback of claims. The contract
//! suite covers the observable results (distinct sequence numbers, one winner, disjoint claims); these tests pin the
//! mechanism, so a change that serialises everything or deadlocks fails here.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test environment that misbehaves fails the test loudly"
)]

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use davhaven_domain::{Binding, BindingId, CalendarId, CalendarSlug, ObjectUri, OutboxId, PrincipalId};
use davhaven_port_tests::store::fixtures::{World, seed, version};
use davhaven_ports::{Database, Expected, NewOutbox, OutboxMessage, PageReq, Reserved, StoreError, TxMode};
use sqlx::PgConnection;
use support::TestDatabase;
use tokio::time::timeout;
use uuid::Uuid;

/// How long a step that must not wait may take.
const PROMPT: Duration = Duration::from_secs(20);
/// How many pairs of crossing moves race.
const ROUNDS: u128 = 8;

/// A database with the seeded world and the name of the database, for a connection of the test's own.
async fn seeded(cluster: &support::Cluster) -> (Arc<dyn Database>, World, String) {
    let db = TestDatabase::create(cluster).await;
    let name = db.name().to_owned();
    let db: Arc<dyn Database> = Arc::new(db);
    let world = seed(&db).await.unwrap();
    (db, world, name)
}

/// Whether another session could lock the row now: `FOR NO KEY UPDATE NOWAIT` on a connection of the test's own
/// fails at once with `lock_not_available` while a transaction holds a conflicting lock, so the lock is proven
/// without waiting for anything.
async fn lock_is_free(connection: &mut PgConnection, table: &str, tenant: Uuid, id: Uuid) -> bool {
    let statement = format!("SELECT 1 FROM {table} WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE NOWAIT");
    match sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *connection)
        .await
    {
        Ok(_) => true,
        Err(error) => {
            assert_eq!(
                error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .as_deref(),
                Some("55P03"),
                "the probe failed for another reason: {error}"
            );
            false
        }
    }
}

/// Polls until some backend of the database waits for a lock, yielding between the polls (no sleeping).
async fn wait_for_a_blocked_backend(connection: &mut PgConnection, database: &str) {
    timeout(PROMPT, async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE datname = $1 AND wait_event_type = 'Lock'",
            )
            .bind(database)
            .fetch_one(&mut *connection)
            .await
            .unwrap();
            if waiting > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("no backend ever waited for the lock");
}

/// Polls until no transaction of the database is open any more: a dropped sqlx transaction only queues its
/// `ROLLBACK`, which the pool sends a moment later.
async fn wait_until_no_transaction_is_open(connection: &mut PgConnection, database: &str) {
    timeout(PROMPT, async {
        loop {
            let open: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE datname = $1 AND pid <> pg_backend_pid() \
                   AND state IN ('idle in transaction', 'idle in transaction (aborted)', 'active')",
            )
            .bind(database)
            .fetch_one(&mut *connection)
            .await
            .unwrap();
            if open == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a dropped transaction was never rolled back");
}

/// A binding of `principal` to `calendar`.
fn a_binding(n: u128, principal: PrincipalId, calendar: CalendarId, slug: &str) -> Binding {
    Binding {
        id: BindingId::from_uuid(Uuid::from_u128(0x0190_0000_0001_7000_8000_0000_0000_0000 | n)),
        tenant_id: davhaven_domain::TenantId::from_uuid(Uuid::nil()),
        principal_id: principal,
        calendar_id: calendar,
        slug: CalendarSlug::parse(slug).unwrap(),
        display_name: None,
        color: None,
        sort_order: None,
        schedule_transp: None,
        hidden: false,
        created_at: chrono::DateTime::UNIX_EPOCH,
        updated_at: chrono::DateTime::UNIX_EPOCH,
        version: 99,
    }
}

fn uri(text: &str) -> ObjectUri {
    ObjectUri::parse(text).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writers_wait_for_the_calendar_they_write_and_for_nothing_else() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (db, world, name) = seeded(&cluster).await;
    let mut probe = cluster.owner_connection(&name).await;
    // Only a superuser sees what the sessions of other roles wait for.
    let mut admin = cluster.admin().await;

    // The first writer holds the lock of `personal` until it commits.
    let mut holder = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    let first = holder
        .objects()
        .put(
            world.personal,
            version(0x1001, "one.ics", "one").unwrap(),
            Expected::Absent,
        )
        .await
        .unwrap();
    assert_eq!(first.seq, 1);
    assert!(
        !lock_is_free(&mut probe, "calendars", world.a.as_uuid(), world.personal.as_uuid()).await,
        "the writer holds the lock of the calendar it writes"
    );
    assert!(
        lock_is_free(&mut probe, "calendars", world.a.as_uuid(), world.shared.as_uuid()).await,
        "and of no other calendar"
    );

    // A writer of another calendar of the same tenant is not held up.
    let mut other = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    let elsewhere = timeout(
        PROMPT,
        other.objects().put(
            world.shared,
            version(0x1002, "elsewhere.ics", "elsewhere").unwrap(),
            Expected::Absent,
        ),
    )
    .await
    .expect("a write to another calendar waited for the holder")
    .unwrap();
    assert_eq!(elsewhere.seq, 1, "every calendar counts its own changes");
    other.commit().await.unwrap();

    // A reader is not held up either: readers never take the calendar lock.
    let mut reader = db.begin(world.a, TxMode::ReadOnly).await.unwrap();
    let listed = timeout(PROMPT, reader.objects().list(world.personal, PageReq::default()))
        .await
        .expect("a read waited for the writer")
        .unwrap();
    assert!(
        listed.items.is_empty(),
        "the holder's write is not visible before it commits"
    );
    drop(reader);

    // A binding or a grant of the calendar is not a writer of it: the foreign key check of the insert takes only a
    // `KEY SHARE` lock, which the writer's `NO KEY UPDATE` lock does not conflict with.
    let mut sharee = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    timeout(
        PROMPT,
        sharee
            .bindings()
            .create(a_binding(0x1010, world.mia, world.personal, "olivia-personal")),
    )
    .await
    .expect("a binding insert waited for an object writer of the calendar")
    .unwrap();
    sharee.commit().await.unwrap();

    // A second writer of the same calendar waits for the holder, then takes the next sequence number: it is
    // observed waiting in the lock table, and proceeds only once the holder commits.
    let waiting_db = Arc::clone(&db);
    let waiting = tokio::spawn(async move {
        let mut tx = waiting_db.begin(world.a, TxMode::ReadWrite).await?;
        let written = tx
            .objects()
            .put(world.personal, version(0x1003, "two.ics", "two")?, Expected::Absent)
            .await?;
        tx.commit().await?;
        Ok::<u64, StoreError>(written.seq)
    });
    wait_for_a_blocked_backend(&mut admin, &name).await;
    assert!(
        !waiting.is_finished(),
        "the second writer did not wait for the calendar lock"
    );
    holder.commit().await.unwrap();
    let second = timeout(PROMPT, waiting)
        .await
        .expect("the second writer never got the lock")
        .unwrap()
        .unwrap();
    assert_eq!(
        second, 2,
        "the waiting writer took the sequence number after the holder's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rolled_back_writer_releases_the_lock_and_its_sequence_number() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (db, world, _name) = seeded(&cluster).await;
    let mut holder = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    holder
        .objects()
        .put(
            world.personal,
            version(0x1101, "gone.ics", "gone").unwrap(),
            Expected::Absent,
        )
        .await
        .unwrap();
    let waiting_db = Arc::clone(&db);
    let waiting = tokio::spawn(async move {
        let mut tx = waiting_db.begin(world.a, TxMode::ReadWrite).await?;
        let written = tx
            .objects()
            .put(world.personal, version(0x1102, "kept.ics", "kept")?, Expected::Absent)
            .await?;
        tx.commit().await?;
        Ok::<u64, StoreError>(written.seq)
    });
    drop(holder);
    let seq = timeout(PROMPT, waiting)
        .await
        .expect("the lock was not released")
        .unwrap()
        .unwrap();
    assert_eq!(seq, 1, "the rolled-back change gave its sequence number back");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moves_in_opposite_directions_do_not_deadlock() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (db, world, _name) = seeded(&cluster).await;
    let mut tx = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    for round in 0..ROUNDS {
        let (x, y) = (format!("x{round}"), format!("y{round}"));
        tx.objects()
            .put(
                world.personal,
                version(0x1200 + round, &format!("{x}.ics"), &x).unwrap(),
                Expected::Absent,
            )
            .await
            .unwrap();
        tx.objects()
            .put(
                world.shared,
                version(0x1300 + round, &format!("{y}.ics"), &y).unwrap(),
                Expected::Absent,
            )
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();

    // Both calendars of every move are locked in ascending id order, so crossing moves queue instead of
    // deadlocking (a deadlock would surface as a serialization failure).
    let mut tasks = Vec::new();
    for round in 0..ROUNDS {
        for (from, to, name) in [
            (world.personal, world.shared, format!("x{round}")),
            (world.shared, world.personal, format!("y{round}")),
        ] {
            let db = Arc::clone(&db);
            tasks.push(tokio::spawn(async move {
                let mut tx = db.begin(world.a, TxMode::ReadWrite).await?;
                let moved = tx
                    .objects()
                    .move_to(
                        from,
                        &uri(&format!("{name}.ics")),
                        to,
                        &uri(&format!("{name}-moved.ics")),
                    )
                    .await?;
                tx.commit().await?;
                Ok::<(u64, u64), StoreError>(moved)
            }));
        }
    }
    for task in tasks {
        let (source, target) = timeout(PROMPT, task)
            .await
            .expect("crossing moves deadlocked")
            .unwrap()
            .expect("a crossing move failed");
        assert!(source >= 1 && target >= 1);
    }

    let mut tx = db.begin(world.a, TxMode::ReadOnly).await.unwrap();
    for calendar in [world.personal, world.shared] {
        let page = tx.objects().list(calendar, PageReq::first(100)).await.unwrap();
        assert_eq!(
            page.items.len(),
            usize::try_from(ROUNDS).unwrap(),
            "every object ended up in one calendar"
        );
        assert!(
            page.items
                .iter()
                .all(|object| object.uri.as_str().ends_with("-moved.ics"))
        );
        let sequence = tx.calendars().get(calendar).await.unwrap().sync_seq;
        // Initial put, and per round one move out (delete) and one move in (upsert) of this calendar.
        assert_eq!(
            sequence,
            i64::try_from(ROUNDS).unwrap() * 3,
            "every change of the calendar took its own sequence number"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_claims_skip_what_another_transaction_holds() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (db, world, name) = seeded(&cluster).await;
    // Only a superuser sees what the sessions of other roles wait for.
    let mut admin = cluster.admin().await;
    let mut tx = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    for n in 1..=4_u128 {
        tx.outbox()
            .enqueue(NewOutbox::now(
                OutboxId::from(Uuid::from_u128(0x2000 + n)),
                OutboxMessage::ProviderPush(Reserved {}),
            ))
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let lease = Duration::from_secs(600);

    // The first dispatcher claims two records and keeps its transaction open.
    let mut first = db.begin_system().await.unwrap();
    let held = first.outbox_claim().claim(2, lease).await.unwrap();
    assert_eq!(held.len(), 2);

    // The second one does not wait for it: it gets the other two.
    let mut second = db.begin_system().await.unwrap();
    let others = timeout(PROMPT, second.outbox_claim().claim(10, lease))
        .await
        .expect("a claimant waited for the rows another claimant holds")
        .unwrap();
    assert_eq!(others.len(), 2);
    let held_ids: BTreeSet<_> = held.iter().map(|record| record.id).collect();
    assert!(
        others.iter().all(|record| !held_ids.contains(&record.id)),
        "a record was handed out twice"
    );
    second.commit().await.unwrap();

    // The first dispatcher crashes: its claims are undone and the records are claimable again. Dropping the
    // transaction only queues the rollback, so wait until it has happened before claiming.
    drop(first);
    wait_until_no_transaction_is_open(&mut admin, &name).await;
    let mut third = db.begin_system().await.unwrap();
    let again = timeout(PROMPT, third.outbox_claim().claim(10, lease))
        .await
        .expect("the claims of a rolled-back transaction are still locked")
        .unwrap();
    let again_ids: BTreeSet<_> = again.iter().map(|record| record.id).collect();
    assert_eq!(
        again_ids, held_ids,
        "exactly the records of the crashed claimant come back"
    );
    assert!(
        again.iter().all(|record| record.attempts == 1),
        "a rolled-back claim does not count as an attempt"
    );
    third.commit().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provisioning_calls_queue_on_the_row_of_the_group_or_principal_they_write() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (db, world, name) = seeded(&cluster).await;
    let mut probe = cluster.owner_connection(&name).await;
    let (tenant, group, member, other) = (
        world.a.as_uuid(),
        world.team.as_uuid(),
        world.mia.as_uuid(),
        world.olivia.as_uuid(),
    );

    let mut first = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    first
        .memberships()
        .set_members(world.team, &[world.mia, world.olivia])
        .await
        .unwrap();
    assert!(
        !lock_is_free(&mut probe, "principals", tenant, group).await,
        "a writer of the members holds the group's row, so concurrent writers of the same group queue instead of \
         inserting the same rows"
    );
    assert!(
        lock_is_free(&mut probe, "principals", tenant, member).await,
        "the members themselves are not locked"
    );
    first
        .principals()
        .set_addresses(world.olivia, Vec::new())
        .await
        .unwrap();
    assert!(
        !lock_is_free(&mut probe, "principals", tenant, other).await,
        "a writer of a principal's addresses holds the principal's row"
    );
    first.commit().await.unwrap();
    assert!(
        lock_is_free(&mut probe, "principals", tenant, group).await
            && lock_is_free(&mut probe, "principals", tenant, other).await,
        "and lets go at commit"
    );
}

/// Commits one object written by its own transaction, as a concurrent writer would.
async fn commit_object(db: &Arc<dyn Database>, world: &World, n: u128, name: &str) {
    let mut tx = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    tx.objects()
        .put(
            world.personal,
            version(n, &format!("{name}.ics"), name).unwrap(),
            Expected::Absent,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// The names of the objects a listing returned.
fn names(page: &davhaven_ports::StorePage<davhaven_domain::StoredObject>) -> Vec<String> {
    page.items.iter().map(|object| object.uri.to_string()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_sync_reads_the_state_before_the_listing_or_loses_the_write_in_between() {
    use davhaven_domain::{CollectionKey, CollectionKind};

    let Some(cluster) = support::cluster() else {
        return;
    };
    let (db, world, _name) = seeded(&cluster).await;
    let log = CollectionKey {
        kind: CollectionKind::Calendar,
        id: world.personal.as_uuid(),
    };
    commit_object(&db, &world, 0x1201, "a").await;

    // The required order (documented on `ChangeRepo::state` and `ObjectRepo::list`): the state first, then the
    // members. READ COMMITTED gives every statement a fresh snapshot, so a write that commits in between is in the
    // listing and after the token: the client sees it once more on its next sync, and never loses it.
    let mut reader = db.begin(world.a, TxMode::ReadOnly).await.unwrap();
    let token = reader.changes().state(log).await.unwrap();
    commit_object(&db, &world, 0x1202, "b").await;
    let listing = reader.objects().list(world.personal, PageReq::default()).await.unwrap();
    assert_eq!(
        names(&listing),
        ["a.ics", "b.ics"],
        "the listing shows what committed in between"
    );
    let next = reader.changes().since(log, token.epoch, token.seq, 10).await.unwrap();
    assert_eq!(
        next.changes
            .iter()
            .map(|change| change.uri.to_string())
            .collect::<Vec<_>>(),
        ["b.ics"],
        "and the next sync reports it again (a harmless repeat)"
    );
    drop(reader);

    // The wrong order loses the write for good: it is in the token, not in the listing.
    let mut reader = db.begin(world.a, TxMode::ReadOnly).await.unwrap();
    let listing = reader.objects().list(world.personal, PageReq::default()).await.unwrap();
    commit_object(&db, &world, 0x1203, "c").await;
    let token = reader.changes().state(log).await.unwrap();
    assert_eq!(names(&listing), ["a.ics", "b.ics"]);
    assert_eq!(token.seq, 3, "the token already counts the write the listing missed");
    let next = reader.changes().since(log, token.epoch, token.seq, 10).await.unwrap();
    assert!(
        next.changes.is_empty(),
        "so a client that listed first and read the state second never learns about c.ics"
    );
    drop(reader);

    // A snapshot transaction removes the question: the listing and the state are one snapshot, in either order.
    let mut snapshot = db.begin(world.a, TxMode::Snapshot).await.unwrap();
    let before = snapshot.changes().state(log).await.unwrap();
    commit_object(&db, &world, 0x1204, "d").await;
    let listing = snapshot
        .objects()
        .list(world.personal, PageReq::default())
        .await
        .unwrap();
    let after = snapshot.changes().state(log).await.unwrap();
    assert_eq!(
        names(&listing),
        ["a.ics", "b.ics", "c.ics"],
        "the snapshot does not see d.ics, which committed after it started"
    );
    assert_eq!(before.seq, after.seq, "and its state does not move either");
    assert_eq!(before.seq, 3);
    let next = snapshot
        .changes()
        .since(log, before.epoch, before.seq, 10)
        .await
        .unwrap();
    assert!(next.changes.is_empty(), "the snapshot's token and listing agree");
    assert!(
        snapshot
            .objects()
            .put(world.personal, version(0x1205, "e.ics", "e").unwrap(), Expected::Any)
            .await
            .is_err(),
        "a snapshot transaction is read-only"
    );
    drop(snapshot);

    // The next transaction sees everything.
    let mut tx = db.begin(world.a, TxMode::ReadOnly).await.unwrap();
    assert_eq!(
        names(&tx.objects().list(world.personal, PageReq::default()).await.unwrap()).len(),
        4
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_binding_created_under_the_calendar_lock_does_not_outlive_the_soft_delete() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (db, world, name) = seeded(&cluster).await;
    let mut admin = cluster.admin().await;
    let version = {
        let mut tx = db.begin(world.a, TxMode::ReadOnly).await.unwrap();
        tx.calendars().get(world.shared).await.unwrap().version
    };

    // The documented protocol: lock the calendar first, then create the binding (the lock of the soft delete does
    // not conflict with the foreign key's `KEY SHARE` of the insert, so the lock is what orders the two).
    let mut sharee = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    sharee.calendars().lock(&[world.shared]).await.unwrap();

    let deleting_db = Arc::clone(&db);
    let deleting = tokio::spawn(async move {
        let mut tx = deleting_db.begin(world.a, TxMode::ReadWrite).await?;
        tx.calendars().soft_delete(world.shared, version).await?;
        tx.commit().await
    });
    wait_for_a_blocked_backend(&mut admin, &name).await;
    assert!(!deleting.is_finished(), "the soft delete waited for the calendar lock");

    sharee
        .bindings()
        .create(a_binding(0x1301, world.mia, world.shared, "olivia-projects"))
        .await
        .unwrap();
    sharee.commit().await.unwrap();
    timeout(PROMPT, deleting)
        .await
        .expect("the soft delete never got the lock")
        .unwrap()
        .unwrap();

    // The binding the sharee created while it held the lock is gone with the calendar, and its slug is free.
    let mut tx = db.begin(world.a, TxMode::ReadWrite).await.unwrap();
    assert_eq!(
        tx.bindings().list_for(world.mia).await.unwrap().len(),
        0,
        "no binding survives on the deleted calendar"
    );
    tx.bindings()
        .create(a_binding(0x1302, world.mia, world.personal, "olivia-projects"))
        .await
        .expect("the slug of the deleted binding is free");
}
