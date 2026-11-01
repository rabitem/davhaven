//! Cases that run transactions concurrently. Adapters that serialise transactions (the memory store) pass them
//! trivially; the PostgreSQL adapter passes them through row locks, `SKIP LOCKED` and the unique indexes.
//!
//! Every task opens, uses and ends its own transaction; no case holds a transaction open while it waits for
//! another, so an adapter with one global lock cannot deadlock.

use std::collections::BTreeSet;
use std::time::Duration;

use davhaven_domain::{CollectionKey, CollectionKind, OutboxId};
use davhaven_ports::{Expected, IndexFilter, NewOutbox, OutboxMessage, PageReq, Reserved, StoreError};
use futures::future::join_all;

use super::Outcome;
use super::world::{Db, World, address, begin, id, key, seed, system, version};
use crate::suite::Checks;

/// How many tasks race.
const TASKS: u128 = 8;

/// Joins the tasks, turning a panicked task into an error.
async fn join<T>(handles: Vec<tokio::task::JoinHandle<T>>) -> Result<Vec<T>, StoreError> {
    let mut results = Vec::with_capacity(handles.len());
    for outcome in join_all(handles).await {
        results.push(outcome.map_err(|error| StoreError::internal(format!("a task of the suite failed: {error}")))?);
    }
    Ok(results)
}

/// Concurrent writers of one calendar each get their own sequence number, and the log holds every change once.
pub(super) async fn concurrent_writers_get_distinct_sequence_numbers(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let handles: Vec<_> = (0..TASKS)
        .map(|n| {
            let db = std::sync::Arc::clone(db);
            tokio::spawn(async move {
                let mut tx = begin(&db, world.a).await?;
                let name = format!("event-{n}");
                let written = tx
                    .objects()
                    .put(
                        world.personal,
                        version(0x500 + n, &format!("{name}.ics"), &name)?,
                        Expected::Absent,
                    )
                    .await?;
                tx.commit().await?;
                Ok::<u64, StoreError>(written.seq)
            })
        })
        .collect();
    let mut seqs = Vec::new();
    for outcome in join(handles).await? {
        match outcome {
            Ok(seq) => seqs.push(seq),
            Err(error) => checks.fail(format!("a concurrent writer failed: {error}")),
        }
    }
    seqs.sort_unstable();
    checks.equal(
        &seqs,
        &(1..=8).collect::<Vec<u64>>(),
        "every writer got its own sequence number, without gaps",
    );
    let mut tx = begin(db, world.a).await?;
    let log = CollectionKey {
        kind: CollectionKind::Calendar,
        id: world.personal.as_uuid(),
    };
    let state = tx.changes().state(log).await?;
    checks.equal(&state.seq, &8, "the calendar counted them all");
    let batch = tx.changes().since(log, state.epoch, 0, 100).await?;
    checks.equal(
        &batch.changes.iter().map(|change| change.seq).collect::<Vec<_>>(),
        &(1..=8).collect::<Vec<u64>>(),
        "and the log holds each change once, at its own sequence number",
    );
    Ok(())
}

/// Several transactions create the same resource: exactly one wins, the others see its precondition fail.
pub(super) async fn racing_creators_have_one_winner(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let handles: Vec<_> = (0..TASKS)
        .map(|n| {
            let db = std::sync::Arc::clone(db);
            tokio::spawn(async move {
                let mut tx = begin(&db, world.a).await?;
                let attempt = tx
                    .objects()
                    .put(
                        world.personal,
                        version(0x600 + n, "same.ics", "same")?,
                        Expected::Absent,
                    )
                    .await;
                match attempt {
                    Ok(_) => {
                        tx.commit().await?;
                        Ok::<bool, StoreError>(true)
                    }
                    Err(StoreError::PreconditionFailed) => Ok(false),
                    Err(error) => Err(error),
                }
            })
        })
        .collect();
    let mut winners = 0;
    for outcome in join(handles).await? {
        match outcome {
            Ok(true) => winners += 1,
            Ok(false) => {}
            Err(error) => checks.fail(format!(
                "a racing creator failed with something else than a precondition: {error}"
            )),
        }
    }
    checks.equal(&winners, &1, "exactly one creator wins");
    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.calendars().get(world.personal).await?.sync_seq,
        &1,
        "and the sequence moved once",
    );
    checks.equal(
        &tx.objects().list(world.personal, PageReq::default()).await?.items.len(),
        &1,
        "and one object exists",
    );
    Ok(())
}

/// Claimants of the outbox queue never get the same record.
pub(super) async fn claims_never_overlap(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    for n in 0..10_u128 {
        tx.outbox()
            .enqueue(NewOutbox::now(id(0xA00 + n), OutboxMessage::ProviderPush(Reserved {})))
            .await?;
    }
    tx.commit().await?;
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let db = std::sync::Arc::clone(db);
            tokio::spawn(async move {
                let mut sys = system(&db).await?;
                let claimed: Vec<OutboxId> = sys
                    .outbox_claim()
                    .claim(5, Duration::from_secs(600))
                    .await?
                    .iter()
                    .map(|record| record.id)
                    .collect();
                sys.commit().await?;
                Ok::<Vec<OutboxId>, StoreError>(claimed)
            })
        })
        .collect();
    let mut seen = BTreeSet::new();
    let mut total = 0;
    for outcome in join(handles).await? {
        match outcome {
            Ok(claimed) => {
                total += claimed.len();
                seen.extend(claimed);
            }
            Err(error) => checks.fail(format!("a claimant failed: {error}")),
        }
    }
    checks.equal(&seen.len(), &total, "no record was claimed twice");
    let mut sys = system(db).await?;
    let rest = sys.outbox_claim().claim(100, Duration::from_secs(600)).await?;
    checks.that(
        rest.iter().all(|record| !seen.contains(&record.id)),
        "the rest holds none of the claimed records",
    );
    checks.equal(
        &(total + rest.len()),
        &10,
        "every record was claimed exactly once in the end",
    );
    Ok(())
}

/// A committed write is visible to every transaction that begins afterwards.
pub(super) async fn writes_are_visible_after_commit(db: &Db, checks: &mut Checks) -> Outcome {
    let world: World = seed(db).await?;
    let handles: Vec<_> = (0..6_u128)
        .map(|n| {
            let db = std::sync::Arc::clone(db);
            tokio::spawn(async move {
                let name = format!("visible-{n}");
                let mut writer = begin(&db, world.a).await?;
                let written = writer
                    .objects()
                    .put(
                        world.personal,
                        version(0x700 + n, &format!("{name}.ics"), &name)?,
                        Expected::Absent,
                    )
                    .await?;
                writer.commit().await?;
                let mut reader = begin(&db, world.a).await?;
                let seen = reader.objects().get_by_id(written.object_id).await.is_ok();
                let log = CollectionKey {
                    kind: CollectionKind::Calendar,
                    id: world.personal.as_uuid(),
                };
                let state = reader.changes().state(log).await?;
                Ok::<bool, StoreError>(seen && state.seq >= written.seq)
            })
        })
        .collect();
    for outcome in join(handles).await? {
        match outcome {
            Ok(visible) => checks.that(
                visible,
                "a writer's transaction sees its own committed write and a sequence at least as high",
            ),
            Err(error) => checks.fail(format!("a writer failed: {error}")),
        }
    }
    Ok(())
}

/// Paging with a cursor neither repeats nor skips rows while rows are inserted and deleted between pages.
pub(super) async fn cursors_are_stable(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    for n in 1..=6_u128 {
        let name = format!("o{n}");
        tx.objects()
            .put(
                world.personal,
                version(0x800 + n, &format!("{name}.ics"), &name)?,
                Expected::Absent,
            )
            .await?;
    }
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    let first = tx
        .objects()
        .query(world.personal, &IndexFilter::all(), PageReq::first(2))
        .await?;
    let mut collected: Vec<String> = first.items.iter().map(|object| object.uri.to_string()).collect();
    let mut cursor = first.next;
    drop(tx);

    let mut writer = begin(db, world.a).await?;
    writer
        .objects()
        .put(world.personal, version(0x890, "o7.ics", "o7")?, Expected::Absent)
        .await?;
    writer
        .objects()
        .delete(
            world.personal,
            &key(davhaven_domain::ObjectUri::parse("o3.ics"))?,
            Expected::Any,
        )
        .await?;
    writer.commit().await?;

    let mut rounds = 0;
    while let Some(after) = cursor {
        let mut tx = begin(db, world.a).await?;
        let page = tx
            .objects()
            .query(world.personal, &IndexFilter::all(), PageReq::first(2).after(after))
            .await?;
        collected.extend(page.items.iter().map(|object| object.uri.to_string()));
        cursor = page.next;
        drop(tx);
        rounds += 1;
        if rounds == 1 {
            let mut writer = begin(db, world.a).await?;
            writer
                .objects()
                .put(world.personal, version(0x891, "o8.ics", "o8")?, Expected::Absent)
                .await?;
            writer.commit().await?;
        }
        if rounds > 10 {
            checks.fail("paging does not end");
            break;
        }
    }
    let unique: BTreeSet<&String> = collected.iter().collect();
    checks.equal(&unique.len(), &collected.len(), "no row is returned twice");
    for survivor in ["o1.ics", "o2.ics", "o4.ics", "o5.ics", "o6.ics", "o7.ics"] {
        checks.that(
            collected.iter().any(|uri| uri == survivor),
            &format!("{survivor} is returned"),
        );
    }
    checks.that(
        !collected.iter().any(|uri| uri == "o3.ics"),
        "a row deleted between pages is not returned",
    );
    checks.equal(
        &collected.iter().take(2).cloned().collect::<Vec<_>>(),
        &vec!["o1.ics".to_owned(), "o2.ics".to_owned()],
        "the first page is the first two rows",
    );
    let mut sorted = collected.clone();
    sorted.sort();
    checks.equal(
        &collected,
        &sorted,
        "pages come in id order (ids ascend with the names)",
    );
    Ok(())
}

/// Reconcile jobs that provision the same group and principal at once all succeed (no unique violation of an unnamed
/// key surfaces as an internal error) and leave the requested state.
pub(super) async fn racing_provisioning_calls_serialise(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let handles: Vec<_> = (0..TASKS)
        .map(|_| {
            let db = std::sync::Arc::clone(db);
            tokio::spawn(async move {
                let mut tx = begin(&db, world.a).await?;
                tx.memberships()
                    .set_members(world.team, &[world.mia, world.olivia])
                    .await?;
                tx.memberships().add_member(world.team, world.mia).await?;
                tx.principals()
                    .set_addresses(
                        world.olivia,
                        vec![address(world.olivia, "mailto:olivia@example.org", true)?],
                    )
                    .await?;
                tx.commit().await?;
                Ok::<(), StoreError>(())
            })
        })
        .collect();
    for outcome in join(handles).await? {
        if let Err(error) = outcome {
            checks.fail(format!("a racing provisioning call failed: {error}"));
        }
    }
    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.memberships().members(world.team).await?,
        &vec![world.olivia, world.mia],
        "the group has the requested members, each once",
    );
    checks.equal(
        &tx.principals().addresses(world.olivia).await?.len(),
        &1,
        "and the principal has its one address",
    );
    Ok(())
}
