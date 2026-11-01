//! The sync state machine against a model (PLAN 3.1, L1: "sync state machine vs model").
//!
//! The change log is the most intricate logic of the store: per-member collapsing, the windows `since` serves, the
//! continuation of a truncated batch, the minimum sequence a prune raises, `touch` advancing the sequence without a
//! log row, and the epoch bump that invalidates every token. Example scripts cover each piece; this case drives them
//! together. A random script of writes (`put`, `delete`, `move_to`, `touch`) interleaved with prunes and epoch bumps
//! runs against the store and against a reference model that is a few lines long. After every step the store's
//! position must equal the model's, and at the end `since` from **every** token the client could hold must
//!
//! * answer `InvalidSyncToken` exactly when the model says the token is unusable (another epoch, below the minimum
//!   sequence, from the future), and
//! * otherwise return changes that, applied to the member set the client had at that token (in batches of any size,
//!   continuing from the last sequence number of a truncated batch), reconstruct the current member set, with the
//!   latest change of every member and no member twice.
//!
//! The scripts are drawn from a `proptest` strategy with the deterministic runner of the crate (the suite never
//! reads randomness: the same scripts run every time, so a failure reproduces anywhere) in as many cases as
//! `PROPTEST_CASES` says (256 by default, 20 000 in the nightly run). A failing script is added to
//! [`REGRESSIONS`], which run first on every run: this is the suite's committed regression file, because the runs
//! of an adapter's tests cannot write one next to the test.

use std::collections::{BTreeMap, BTreeSet};

use davhaven_domain::{CalendarKind, CollectionKey, CollectionKind};
use davhaven_ports::{ChangeKind, Expected};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};
use uuid::Uuid;

use super::Outcome;
use super::world::{Db, StoreChecks, World, begin, calendar, far_future, id, key, seed, system, version};
use crate::suite::Checks;

/// One step of a script. The numbers name one of four resources (`u0.ics` to `u3.ics`) of the calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// Create or replace a resource.
    Put(u8),
    /// Delete a resource (a missing one answers `NotFound` and changes nothing).
    Delete(u8),
    /// Rename a resource within the calendar (two consecutive sequence numbers).
    Move(u8, u8),
    /// Advance the sequence without a change-log row.
    Touch,
    /// Prune the whole change log (retention with a cut-off in the far future).
    Prune,
    /// Give every collection a new epoch (after a restore).
    BumpEpoch,
}

use Op::{BumpEpoch, Delete, Move, Prune, Put, Touch};

/// Scripts that once mattered, or that pin an edge of the state machine; they run before the generated ones.
const REGRESSIONS: &[&[Op]] = &[
    // Collapsing: only the latest change of a member is reported, a delete after a put is a delete.
    &[Put(0), Put(0), Delete(0), Put(1)],
    // A touch moves the sequence without a log row; a prune then raises the minimum to the last *logged* sequence.
    &[Put(0), Touch, Prune, Put(1)],
    &[Put(0), Prune, Touch, Touch, Put(2)],
    // The epoch bump invalidates every token, and the sequence continues.
    &[Put(0), Prune, BumpEpoch, Put(0)],
    &[Put(0), BumpEpoch, Delete(0), BumpEpoch, Prune],
    // Moves: a missing source, an occupied target, a rename and a delete of the renamed member.
    &[Move(0, 1), Put(0), Put(1), Move(0, 1), Move(0, 2), Delete(2), Delete(0)],
    // Nothing but touches and prunes.
    &[Touch, Prune, Touch, Prune],
];

/// The model: what the store must report, in the plainest possible terms.
#[derive(Debug, Clone, Default)]
struct Model {
    /// The current sequence number.
    seq: u64,
    /// The minimum sequence a token can resume from.
    min_seq: u64,
    /// The members that exist.
    members: BTreeSet<String>,
    /// The retained log: `(seq, member, kind)`.
    log: Vec<(u64, String, ChangeKind)>,
}

impl Model {
    fn upsert(&mut self, member: &str) {
        self.seq += 1;
        self.log.push((self.seq, member.to_owned(), ChangeKind::Upsert));
        self.members.insert(member.to_owned());
    }

    fn remove(&mut self, member: &str) {
        self.seq += 1;
        self.log.push((self.seq, member.to_owned(), ChangeKind::Delete));
        self.members.remove(member);
    }

    /// Retention with a cut-off after every entry: the log is emptied and the minimum is the last logged sequence.
    fn prune(&mut self) {
        if let Some(last) = self.log.iter().map(|entry| entry.0).max() {
            self.min_seq = self.min_seq.max(last);
        }
        self.log.clear();
    }

    /// Whether a token can be resumed.
    fn usable(&self, epoch_matches: bool, seq: u64) -> bool {
        epoch_matches && seq >= self.min_seq && seq <= self.seq
    }

    /// The latest change of every member after `seq`, ordered by sequence number.
    fn changes_after(&self, seq: u64) -> Vec<(u64, String, ChangeKind)> {
        let mut latest: BTreeMap<&str, (u64, ChangeKind)> = BTreeMap::new();
        for (at, member, kind) in self.log.iter().filter(|entry| entry.0 > seq) {
            latest.insert(member, (*at, *kind));
        }
        let mut changes: Vec<(u64, String, ChangeKind)> = latest
            .into_iter()
            .map(|(member, (at, kind))| (at, member.to_owned(), kind))
            .collect();
        changes.sort_by_key(|change| change.0);
        changes
    }
}

/// A token the client could hold: the position after a step and the members it knew then.
#[derive(Debug, Clone)]
struct Token {
    epoch: Uuid,
    seq: u64,
    members: BTreeSet<String>,
}

/// The strategy of a script: one to twenty-four steps, mostly writes.
fn script() -> impl Strategy<Value = Vec<Op>> {
    let resource = 0_u8..4;
    let step = prop_oneof![
        4 => resource.clone().prop_map(Put),
        3 => resource.clone().prop_map(Delete),
        2 => (resource.clone(), resource).prop_map(|(from, to)| Move(from, to)),
        1 => Just(Touch),
        1 => Just(Prune),
        1 => Just(BumpEpoch),
    ];
    vec(step, 1..24)
}

/// The name of a resource.
fn name(n: u8) -> String {
    format!("u{n}.ics")
}

/// Runs one script against the store and the model; failures are recorded in `checks` (the first one ends the
/// script, so a broken adapter reports one clear line per script instead of a cascade).
#[expect(clippy::too_many_lines, reason = "one linear script with its checks")]
async fn run_script(db: &Db, checks: &mut Checks, world: World, index: u128, steps: &[Op]) -> Outcome {
    create_calendar(db, world, index).await?;
    let cal = id::<davhaven_domain::CalendarId>(0x5000 + index);
    let log = CollectionKey {
        kind: CollectionKind::Calendar,
        id: cal.as_uuid(),
    };
    let label = format!("script {index} {steps:?}");

    let mut tx = begin(db, world.a).await?;
    let start = tx.changes().state(log).await?;
    tx.commit().await?;
    let mut model = Model {
        seq: start.seq,
        min_seq: start.min_seq,
        ..Model::default()
    };
    let mut epoch = start.epoch;
    let mut tokens = vec![Token {
        epoch,
        seq: model.seq,
        members: BTreeSet::new(),
    }];
    let mut counter = 0_u128;

    for (step, op) in steps.iter().enumerate() {
        let mut tx = begin(db, world.a).await?;
        match *op {
            Put(n) => {
                counter += 1;
                // A new uid for every write: a renamed member keeps its uid, so a fixed uid per name would clash.
                let object = version(0x6000 + index * 100 + counter, &name(n), &format!("uid-{counter}"))?;
                tx.objects().put(cal, object, Expected::Any).await?;
                model.upsert(&name(n));
            }
            Delete(n) => {
                let uri = key(davhaven_domain::ObjectUri::parse(&name(n)))?;
                if model.members.contains(&name(n)) {
                    tx.objects().delete(cal, &uri, Expected::Any).await?;
                    model.remove(&name(n));
                } else {
                    checks.not_found(
                        tx.objects().delete(cal, &uri, Expected::Any).await,
                        &format!("{label}, step {step}: deleting a missing member"),
                    );
                }
            }
            Move(from, to) => {
                let (source, target) = (name(from), name(to));
                let from_uri = key(davhaven_domain::ObjectUri::parse(&source))?;
                let to_uri = key(davhaven_domain::ObjectUri::parse(&target))?;
                if from == to {
                    // Moving onto itself is a conflict with itself; nothing to model.
                } else if !model.members.contains(&source) {
                    checks.not_found(
                        tx.objects().move_to(cal, &from_uri, cal, &to_uri).await,
                        &format!("{label}, step {step}: moving a missing member"),
                    );
                } else if model.members.contains(&target) {
                    checks.unique(
                        tx.objects().move_to(cal, &from_uri, cal, &to_uri).await,
                        davhaven_ports::UniqueKey::ObjectUri,
                        &format!("{label}, step {step}: moving onto an existing member"),
                    );
                } else {
                    tx.objects().move_to(cal, &from_uri, cal, &to_uri).await?;
                    model.remove(&source);
                    model.upsert(&target);
                }
            }
            Touch => {
                tx.calendars().touch(cal).await?;
                model.seq += 1;
            }
            Prune => {
                tx.commit().await?;
                let mut sys = system(db).await?;
                // A call prunes at most a batch, oldest first, and earlier scripts left rows behind.
                while sys.retention().prune_changes(far_future()).await? > 0 {}
                sys.commit().await?;
                model.prune();
                tx = begin(db, world.a).await?;
            }
            BumpEpoch => {
                tx.commit().await?;
                let mut sys = system(db).await?;
                sys.tenants().bump_sync_epoch(Some(world.a)).await?;
                sys.commit().await?;
                tx = begin(db, world.a).await?;
            }
        }
        let position = tx.changes().state(log).await?;
        tx.commit().await?;
        if *op == BumpEpoch {
            checks.differ(&position.epoch, &epoch, &format!("{label}, step {step}: a new epoch"));
            epoch = position.epoch;
        }
        if (position.seq, position.min_seq, position.epoch) != (model.seq, model.min_seq, epoch) {
            checks.fail(format!(
                "{label}, step {step} ({op:?}): the store is at seq {} / min {} / epoch {}, the model at seq {} / \
                 min {} / epoch {epoch}",
                position.seq, position.min_seq, position.epoch, model.seq, model.min_seq
            ));
            return Ok(());
        }
        tokens.push(Token {
            epoch,
            seq: model.seq,
            members: model.members.clone(),
        });
    }

    // Every token the client could hold, with a window of every size.
    let mut tx = begin(db, world.a).await?;
    for (n, token) in tokens.iter().enumerate() {
        let usable = model.usable(token.epoch == epoch, token.seq);
        for limit in [1_u32, 2, 1000] {
            let first = tx.changes().since(log, token.epoch, token.seq, limit).await;
            if !usable {
                checks.invalid_sync_token(first, &format!("{label}: token {n} ({token:?}) is unusable"));
                continue;
            }
            let Some(mut batch) = checks.ok(first, &format!("{label}: token {n} ({token:?}) is usable")) else {
                return Ok(());
            };
            let expected = model.changes_after(token.seq);
            let mut client = token.members.clone();
            let mut received: Vec<(u64, String, ChangeKind)> = Vec::new();
            loop {
                for change in &batch.changes {
                    received.push((change.seq, change.uri.to_string(), change.kind));
                    match change.kind {
                        ChangeKind::Upsert => client.insert(change.uri.to_string()),
                        ChangeKind::Delete => client.remove(&change.uri.to_string()),
                    };
                }
                let Some(last) = batch.changes.last().map(|change| change.seq) else {
                    break;
                };
                if !batch.truncated {
                    break;
                }
                let next = tx.changes().since(log, epoch, last, limit).await;
                let Some(next) = checks.ok(next, &format!("{label}: continuing token {n} from {last}")) else {
                    return Ok(());
                };
                batch = next;
            }
            checks.equal(
                &client,
                &model.members,
                &format!(
                    "{label}: the client of token {n} ({token:?}) with limit {limit} ends with the current members"
                ),
            );
            if limit >= 1000 {
                checks.equal(
                    &received,
                    &expected,
                    &format!("{label}: the changes after token {n}, latest per member, ordered by sequence"),
                );
            }
        }
    }
    Ok(())
}

/// Creates the calendar of one script, so every script starts from an empty log.
async fn create_calendar(db: &Db, world: World, index: u128) -> Result<(), davhaven_ports::StoreError> {
    let mut tx = begin(db, world.a).await?;
    tx.calendars()
        .create(calendar(
            0x5000 + index,
            world.olivia,
            &format!("model{index}"),
            CalendarKind::User,
        )?)
        .await?;
    tx.commit().await
}

/// The scripts of a run: the committed regressions first, then a deterministic sample of generated ones. Generated
/// here, in synchronous code, because the strategy and the runner of `proptest` are not `Send`.
fn scripts() -> Vec<Vec<Op>> {
    let mut scripts: Vec<Vec<Op>> = REGRESSIONS.iter().map(|steps| steps.to_vec()).collect();
    let config = Config::default();
    let mut runner = TestRunner::deterministic();
    let strategy = script();
    for _ in 0..config.cases {
        match strategy.new_tree(&mut runner) {
            Ok(tree) => scripts.push(tree.current()),
            Err(_) => break,
        }
    }
    scripts
}

/// The change log behaves like its model for the committed regression scripts and for a deterministic sample of
/// generated ones.
pub(super) async fn changes_match_a_model(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    for (index, steps) in (0_u128..).zip(scripts()) {
        run_script(db, checks, world, index, &steps).await?;
        if !checks.is_clean() {
            // The first failing script is the report; the next ones would only repeat the symptom.
            break;
        }
    }
    Ok(())
}
