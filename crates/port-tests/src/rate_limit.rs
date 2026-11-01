//! Contract suites of the `RateLimiter` port.
//!
//! [`run`] holds what every limiter promises, the noop limiter included: asking with a cost of zero never
//! consumes, allowed decisions never carry a wait time, denied decisions carry a positive one and nothing remains,
//! `remaining` never grows while the clock stands still, and a denied key does not affect other keys.
//! [`run_limited`] adds the case that the bucket `contract` runs dry after a bounded number of checks, which a
//! limiter that really limits must pass; the factory configures the limiter so that this bucket has a finite rate.
//!
//! [`run_backoff`] adds the failure backoff that R6 and PLAN 2.6 require of every limiter that serves
//! authentication, on the two buckets of the port ([`RateKey::AUTH_LOGIN_IP`], [`RateKey::AUTH_IP`]): failures end
//! in a block with a wait, the block ends when its wait is over, further failures lengthen it up to a maximum, a
//! blocked key gains nothing by hammering, keys and buckets are independent, and failures are forgotten after a long
//! quiet time. The suite does not know the numbers of the policy (they come from `[security.auth]`); it checks the
//! shape. The factory hands over the limiter and the `ManualClock` that moves it.
//!
//! The suites never sleep: a limiter that refills over time is built with the `ManualClock`, which stands still
//! unless the suite moves it.

use std::sync::Arc;
use std::time::Duration;

use davhaven_ports::testing::ManualClock;
use davhaven_ports::{RateDecision, RateKey, RateLimiter};

use crate::suite::{Checks, ContractReport, Suite};

/// The bucket the suites use.
pub const BUCKET: &str = "contract";

/// The most single-unit checks the exhaustion probe makes.
const MAX_PROBES: u32 = 20_000;

/// What the probe of one key found out.
#[derive(Debug)]
struct Probe {
    /// The first denied decision, if the bucket ran dry within the bound.
    denied: Option<RateDecision>,
    /// How many checks were allowed before the first denial (or all of them).
    allowed: u32,
}

/// Consumes single units until the first denial, recording violations of the decision invariants.
async fn probe(limiter: &dyn RateLimiter, key: &RateKey, checks: &mut Checks) -> Probe {
    let mut previous_remaining: Option<u32> = None;
    let mut allowed = 0;
    for attempt in 0..MAX_PROBES {
        let decision = match limiter.check(key, 1).await {
            Ok(decision) => decision,
            Err(error) => {
                checks.fail(format!("check {attempt} failed: {error}"));
                return Probe { denied: None, allowed };
            }
        };
        if decision.allowed {
            allowed += 1;
            if decision.retry_after.is_some() {
                checks.fail(format!("allowed check {attempt} carries a wait time"));
            }
            if let Some(before) = previous_remaining
                && decision.remaining > before
            {
                checks.fail(format!(
                    "remaining grew from {before} to {} at check {attempt} although time stood still",
                    decision.remaining
                ));
            }
            previous_remaining = Some(decision.remaining);
        } else {
            return Probe {
                denied: Some(decision),
                allowed,
            };
        }
    }
    Probe { denied: None, allowed }
}

/// Runs the suite every limiter must pass against limiters built by `factory` and returns the report.
pub async fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn RateLimiter>,
{
    let mut suite = Suite::new("rate_limit");
    let limiter = factory();

    let mut checks = Checks::new("a cost of zero consumes nothing");
    let key = RateKey::new(BUCKET, "zero-cost");
    let first = checks.ok(limiter.check(&key, 0).await, "the first zero-cost check");
    let second = checks.ok(limiter.check(&key, 0).await, "the second zero-cost check");
    if let (Some(first), Some(second)) = (first, second) {
        checks.equal(&first, &second, "two zero-cost checks in a row");
    }
    suite.record(checks);

    let mut checks = Checks::new("decisions are consistent until the bucket runs dry");
    let key = RateKey::new(BUCKET, "probe");
    let outcome = probe(limiter.as_ref(), &key, &mut checks).await;
    if let Some(denied) = outcome.denied {
        match denied.retry_after {
            Some(wait) if wait > Duration::ZERO => {}
            other => checks.fail(format!("a denial must carry a positive wait time, got {other:?}")),
        }
        checks.equal(&denied.remaining, &0, "remaining after a denial");
        match checks.ok(limiter.check(&key, 0).await, "a zero-cost check after the denial") {
            Some(after) => checks.that(!after.allowed, "a zero-cost check on a dry bucket reports no room"),
            None => checks.fail("the dry bucket cannot be asked again"),
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("a denied key does not affect other keys");
    let dry = RateKey::new(BUCKET, "isolation-dry");
    let outcome = probe(limiter.as_ref(), &dry, &mut checks).await;
    if outcome.denied.is_some() {
        let other = RateKey::new(BUCKET, "isolation-other");
        if let Some(decision) = checks.ok(limiter.check(&other, 1).await, "a check of another key") {
            checks.that(decision.allowed, "another key still has room");
        }
    }
    suite.record(checks);

    suite.finish()
}

/// Runs [`run`] and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn RateLimiter>,
{
    run(factory).await.assert_ok();
}

/// Runs the cases only a limiter that really limits passes, and returns the report.
pub async fn run_limited<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn RateLimiter>,
{
    let mut suite = Suite::new("rate_limit (limited)");
    let limiter = factory();

    let mut checks = Checks::new("the bucket runs dry after a bounded number of checks");
    let key = RateKey::new(BUCKET, "exhaustion");
    let outcome = probe(limiter.as_ref(), &key, &mut checks).await;
    checks.that(outcome.denied.is_some(), "a denial occurs within the probe bound");
    checks.that(outcome.allowed > 0, "the first check is allowed");
    suite.record(checks);

    suite.finish()
}

/// Runs the limiting cases and fails the running test when any of them fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_limited_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn RateLimiter>,
{
    run_limited(factory).await.assert_ok();
}

/// What a factory of the backoff suite builds: the limiter and the clock that moves it.
pub struct BackoffRig {
    /// The limiter under test, with its failure buckets at the policy it was given (the default, in general).
    pub limiter: Arc<dyn RateLimiter>,
    /// The clock of the limiter; the suite advances it to let blocks end.
    pub clock: ManualClock,
}

/// The most failures the backoff suite records before it decides that a bucket never blocks.
const MAX_FAILURES: u32 = 500;

/// The failure buckets of the port.
const FAILURE_BUCKETS: [&str; 2] = [RateKey::AUTH_LOGIN_IP, RateKey::AUTH_IP];

fn advance(clock: &ManualClock, by: Duration) {
    clock.advance(chrono::Duration::from_std(by).unwrap_or(chrono::Duration::MAX));
}

/// Records failures of `key` until the key is blocked and returns the wait of the first block.
async fn first_block(limiter: &dyn RateLimiter, key: &RateKey, checks: &mut Checks) -> Option<Duration> {
    for failure in 1..=MAX_FAILURES {
        let before = checks.ok(limiter.check(key, 0).await, "asking whether the key is blocked")?;
        let recorded = checks.ok(limiter.check(key, 1).await, "recording a failure")?;
        if before.allowed && !recorded.allowed {
            checks.fail(format!(
                "failure {failure} was refused although the key had room: a failure is admitted"
            ));
        }
        let after = checks.ok(limiter.check(key, 0).await, "asking again")?;
        if !after.allowed {
            return match after.retry_after {
                Some(wait) if wait > Duration::ZERO => Some(wait),
                other => {
                    checks.fail(format!("a block must carry a positive wait, got {other:?}"));
                    None
                }
            };
        }
    }
    checks.fail(format!(
        "{MAX_FAILURES} failures did not block the key: there is no backoff"
    ));
    None
}

/// Whether a sequence never shrinks.
fn never_shrinks(waits: &[Duration]) -> bool {
    waits
        .windows(2)
        .all(|pair| matches!(pair, [earlier, later] if earlier <= later))
}

/// Whether the last three waits are the same: the growth has reached its maximum.
fn stopped_growing(waits: &[Duration]) -> bool {
    let tail = waits.len().saturating_sub(3);
    waits.get(tail..).is_some_and(|tail| {
        tail.windows(2)
            .all(|pair| matches!(pair, [earlier, later] if earlier == later))
    })
}

async fn failures_end_in_a_block<F: Fn() -> BackoffRig>(factory: &F, checks: &mut Checks) {
    for bucket in FAILURE_BUCKETS {
        let rig = factory();
        first_block(rig.limiter.as_ref(), &RateKey::new(bucket, "k"), checks).await;
    }
}

async fn a_block_ends_when_its_wait_is_over<F: Fn() -> BackoffRig>(factory: &F, checks: &mut Checks) {
    for bucket in FAILURE_BUCKETS {
        let rig = factory();
        let key = RateKey::new(bucket, "k");
        let Some(wait) = first_block(rig.limiter.as_ref(), &key, checks).await else {
            continue;
        };
        let almost = wait.saturating_sub(Duration::from_millis(1));
        advance(&rig.clock, almost);
        if let Some(still) = checks.ok(rig.limiter.check(&key, 0).await, "asking just before the end") {
            checks.that(
                !still.allowed,
                "the key is still blocked a millisecond before its wait is over",
            );
        }
        advance(&rig.clock, wait.saturating_sub(almost));
        if let Some(over) = checks.ok(rig.limiter.check(&key, 0).await, "asking at the end") {
            checks.that(over.allowed, "the key has room again when its wait is over");
        }
    }
}

async fn failures_lengthen_the_block<F: Fn() -> BackoffRig>(factory: &F, checks: &mut Checks) {
    let rig = factory();
    let key = RateKey::new(RateKey::AUTH_LOGIN_IP, "growth");
    let Some(first) = first_block(rig.limiter.as_ref(), &key, checks).await else {
        return;
    };
    let mut waits = vec![first];
    for _ in 0..64 {
        let Some(last) = waits.last().copied() else {
            break;
        };
        advance(&rig.clock, last);
        if checks
            .ok(rig.limiter.check(&key, 1).await, "a failure after a block")
            .is_none()
        {
            break;
        }
        match checks.ok(rig.limiter.check(&key, 0).await, "asking after the failure") {
            Some(RateDecision {
                allowed: false,
                retry_after: Some(wait),
                ..
            }) => waits.push(wait),
            Some(other) => {
                checks.fail(format!("a failure right after a block must block again, got {other:?}"));
                break;
            }
            None => break,
        }
    }
    checks.that(
        never_shrinks(&waits),
        "the waits never shrink while failures keep coming",
    );
    checks.that(
        waits.last().is_some_and(|last| *last > first),
        "the wait grows beyond the first one",
    );
    checks.that(stopped_growing(&waits), "the wait stops growing at a maximum");
}

async fn hammering_does_not_extend_a_block<F: Fn() -> BackoffRig>(factory: &F, checks: &mut Checks) {
    let rig = factory();
    let key = RateKey::new(RateKey::AUTH_IP, "hammer");
    let Some(wait) = first_block(rig.limiter.as_ref(), &key, checks).await else {
        return;
    };
    for _ in 0..50 {
        if let Some(decision) = checks.ok(rig.limiter.check(&key, 1).await, "a failure of a blocked key") {
            checks.that(!decision.allowed, "a blocked key is denied");
        }
    }
    if let Some(after) = checks.ok(rig.limiter.check(&key, 0).await, "asking after the hammering") {
        checks.that(
            after.retry_after.is_some_and(|left| left <= wait),
            "hammering does not lengthen the block",
        );
    }
}

async fn keys_and_buckets_are_independent<F: Fn() -> BackoffRig>(factory: &F, checks: &mut Checks) {
    let rig = factory();
    let blocked = RateKey::new(RateKey::AUTH_LOGIN_IP, "a");
    if first_block(rig.limiter.as_ref(), &blocked, checks).await.is_none() {
        return;
    }
    for other in [
        RateKey::new(RateKey::AUTH_LOGIN_IP, "b"),
        RateKey::new(RateKey::AUTH_IP, "a"),
    ] {
        if let Some(decision) = checks.ok(rig.limiter.check(&other, 0).await, "asking about another key") {
            checks.that(decision.allowed, "another key or bucket is not blocked");
        }
    }
}

async fn failures_are_forgotten_when_quiet<F: Fn() -> BackoffRig>(factory: &F, checks: &mut Checks) {
    let rig = factory();
    let key = RateKey::new(RateKey::AUTH_LOGIN_IP, "quiet");
    let Some(first) = first_block(rig.limiter.as_ref(), &key, checks).await else {
        return;
    };
    advance(&rig.clock, first);
    checks.ok(rig.limiter.check(&key, 1).await, "a second block");
    advance(&rig.clock, Duration::from_hours(24 * 30));
    if let Some(rested) = checks.ok(rig.limiter.check(&key, 0).await, "asking after a month") {
        checks.that(rested.allowed, "the key has room after a month of quiet");
    }
    if let Some(again) = first_block(rig.limiter.as_ref(), &key, checks).await {
        checks.equal(
            &again,
            &first,
            "the schedule starts over: the first block is as short as before",
        );
    }
}

/// Runs the failure backoff cases against rigs built by `factory` and returns the report.
///
/// Every case gets a fresh rig. A limiter that does not back off (the `noop` limiter) fails them by design.
pub async fn run_backoff<F>(factory: F) -> ContractReport
where
    F: Fn() -> BackoffRig,
{
    let mut suite = Suite::new("rate_limit (backoff)");
    let mut checks = Checks::new("failures end in a block with a positive wait");
    failures_end_in_a_block(&factory, &mut checks).await;
    suite.record(checks);
    let mut checks = Checks::new("a block ends exactly when its wait is over");
    a_block_ends_when_its_wait_is_over(&factory, &mut checks).await;
    suite.record(checks);
    let mut checks = Checks::new("further failures lengthen the block up to a maximum");
    failures_lengthen_the_block(&factory, &mut checks).await;
    suite.record(checks);
    let mut checks = Checks::new("failures of a blocked key do not extend its block");
    hammering_does_not_extend_a_block(&factory, &mut checks).await;
    suite.record(checks);
    let mut checks = Checks::new("keys and the two failure buckets are independent");
    keys_and_buckets_are_independent(&factory, &mut checks).await;
    suite.record(checks);
    let mut checks = Checks::new("failures are forgotten after a long quiet time");
    failures_are_forgotten_when_quiet(&factory, &mut checks).await;
    suite.record(checks);
    suite.finish()
}

/// Runs the backoff cases and fails the running test when any of them fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_backoff_all<F>(factory: F)
where
    F: Fn() -> BackoffRig,
{
    run_backoff(factory).await.assert_ok();
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_ports::PortError;
    use tokio::sync::Mutex;

    use super::*;

    /// A limiter that never denies.
    struct Unlimited;

    #[async_trait]
    impl RateLimiter for Unlimited {
        async fn check(&self, _key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
            Ok(RateDecision::allow(u32::MAX))
        }
    }

    /// A bucket of `capacity` units per key without refill.
    struct Bucket {
        capacity: u32,
        used: Mutex<Vec<(RateKey, u32)>>,
    }

    #[async_trait]
    impl RateLimiter for Bucket {
        async fn check(&self, key: &RateKey, cost: u32) -> Result<RateDecision, PortError> {
            let mut used = self.used.lock().await;
            let position = if let Some(position) = used.iter().position(|(candidate, _)| candidate == key) {
                position
            } else {
                used.push((key.clone(), 0));
                used.len() - 1
            };
            let Some((_, spent)) = used.get_mut(position) else {
                return Err(PortError::internal("lost bucket"));
            };
            let fits = if cost == 0 {
                *spent < self.capacity
            } else {
                spent.saturating_add(cost) <= self.capacity
            };
            if fits {
                *spent += cost;
                Ok(RateDecision::allow(self.capacity - *spent))
            } else {
                Ok(RateDecision::deny(Duration::from_secs(30)))
            }
        }
    }

    fn bucket(capacity: u32) -> Arc<dyn RateLimiter> {
        Arc::new(Bucket {
            capacity,
            used: Mutex::new(Vec::new()),
        })
    }

    #[tokio::test]
    async fn the_noop_and_the_bucket_satisfy_the_common_contract() {
        run_all(|| Arc::new(Unlimited)).await;
        run_all(|| bucket(5)).await;
        assert_eq!(run(|| bucket(5)).await.case_count(), 3);
    }

    #[tokio::test]
    async fn only_a_real_limiter_passes_the_limiting_cases() {
        run_limited_all(|| bucket(5)).await;
        let report = run_limited(|| Arc::new(Unlimited)).await;
        assert_eq!(
            report.failed_cases(),
            vec!["the bucket runs dry after a bounded number of checks"],
            "{report}"
        );
    }

    /// A reference implementation of the failure backoff: three free failures, then blocks of 1 s, 2 s, 4 s, ...
    /// up to 64 s, forgotten after ten quiet minutes.
    struct Model {
        clock: ManualClock,
        keys: Mutex<Vec<(RateKey, ModelKey)>>,
    }

    #[derive(Clone, Copy)]
    struct ModelKey {
        failures: u32,
        blocked_until: i64,
        last: i64,
    }

    fn seconds(clock: &ManualClock) -> i64 {
        use davhaven_ports::Clock as _;
        clock.now().timestamp()
    }

    #[async_trait]
    impl RateLimiter for Model {
        async fn check(&self, key: &RateKey, cost: u32) -> Result<RateDecision, PortError> {
            let now = seconds(&self.clock);
            let mut keys = self.keys.lock().await;
            let position = keys.iter().position(|(candidate, _)| candidate == key);
            let mut state = position
                .and_then(|index| keys.get(index).map(|(_, state)| *state))
                .unwrap_or(ModelKey {
                    failures: 0,
                    blocked_until: 0,
                    last: now,
                });
            if state.failures > 0 && now - state.last.max(state.blocked_until) >= 600 {
                state.failures = 0;
            }
            let decision = if now < state.blocked_until {
                RateDecision::deny(Duration::from_secs(
                    u64::try_from(state.blocked_until - now).unwrap_or(1),
                ))
            } else {
                if cost > 0 {
                    state.failures += cost;
                    state.last = now;
                    if state.failures > 3 {
                        let doublings = (state.failures - 4).min(6);
                        state.blocked_until = now + (1_i64 << doublings);
                    }
                }
                RateDecision::allow(3_u32.saturating_sub(state.failures))
            };
            match position {
                Some(index) => {
                    if let Some(slot) = keys.get_mut(index) {
                        slot.1 = state;
                    }
                }
                None => keys.push((key.clone(), state)),
            }
            Ok(decision)
        }
    }

    fn model() -> BackoffRig {
        let clock = ManualClock::default();
        BackoffRig {
            limiter: Arc::new(Model {
                clock: clock.clone(),
                keys: Mutex::new(Vec::new()),
            }),
            clock,
        }
    }

    #[tokio::test]
    async fn a_correct_backoff_passes_the_backoff_suite() {
        run_backoff_all(model).await;
        assert_eq!(run_backoff(model).await.case_count(), 6);
    }

    #[tokio::test]
    async fn a_limiter_that_never_blocks_fails_the_backoff_suite() {
        let report = run_backoff(|| BackoffRig {
            limiter: Arc::new(Unlimited),
            clock: ManualClock::default(),
        })
        .await;
        let failed = report.failed_cases();
        assert!(
            failed.contains(&"failures end in a block with a positive wait"),
            "{report}"
        );
        assert!(
            failed.contains(&"further failures lengthen the block up to a maximum"),
            "{report}"
        );
    }

    /// A limiter that denies without a wait time, shares its buckets between keys and refills on its own.
    struct Broken(Mutex<u32>);

    #[async_trait]
    impl RateLimiter for Broken {
        async fn check(&self, _key: &RateKey, cost: u32) -> Result<RateDecision, PortError> {
            let mut used = self.0.lock().await;
            *used += cost;
            if *used <= 3 {
                Ok(RateDecision {
                    allowed: true,
                    retry_after: Some(Duration::from_secs(1)),
                    remaining: 10 - *used,
                })
            } else {
                Ok(RateDecision {
                    allowed: false,
                    retry_after: None,
                    remaining: 2,
                })
            }
        }
    }

    #[tokio::test]
    async fn a_limiter_with_inconsistent_decisions_is_caught() {
        let report = run(|| Arc::new(Broken(Mutex::new(0)))).await;
        assert!(
            report
                .failed_cases()
                .contains(&"decisions are consistent until the bucket runs dry"),
            "{report}"
        );
    }
}
