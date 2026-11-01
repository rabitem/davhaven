//! The `memory` rate limiter: keyed buckets in the memory of one process.
//!
//! A caller names a bucket (`RateKey::bucket`) and a key inside it; the configuration says what the bucket allows
//! (see [`crate::config`]). Two kinds of bucket exist and both keep a few numbers per key:
//!
//! * **Rate buckets** use the generic cell rate algorithm, the exact, integer form of a token bucket: one
//!   "theoretical arrival time" per key, where a unit costs `window / limit` and the bucket holds `limit` units.
//!   A check is allowed when taking its cost keeps the arrival time within one window of now; otherwise the answer
//!   says how long until it would fit. There is no rounding drift, no background refill and no clock but the
//!   injected [`Clock`].
//! * **Backoff buckets** count failures. The first `limit` failures within the window are free; every further one
//!   blocks the key for `base`, `2 × base`, `4 × base`, … up to `max`. A key that is blocked is denied with the
//!   time left and its failure count does not grow, so a client that keeps hammering gains nothing and a client
//!   that waits is not punished twice. Failures are forgotten once `window` has passed without a new one; the
//!   quiet time is counted from the end of the last block, so a block that is as long as the window (or longer) does
//!   not wipe out the failures it was caused by and the next block still doubles.
//!
//! Keys are opaque strings that callers derive (a keyed hash of login and client address, a token id); the limiter
//! never sees an address or a login. The table is capped at `max_keys`. When it is full, idle entries (full rate
//! buckets, expired failure counts) are dropped first; if that does not leave about a tenth of the table free, the
//! least recently used entries go too, **keys that are blocked last**, so a flood of fresh keys cannot lift the block
//! of a key that is still being punished. Making room frees a tenth at once, so the sweep is not repeated for every
//! new key. A sender who can mint more distinct keys than `max_keys` can still make the limiter forget keys that are
//! not blocked; the callers keep the authentication buckets per client address as well (and aggregate IPv6
//! addresses to a /64, `davhaven_ports::bucket_address`), which bounds the sender.
//!
//! The limiter is per process: a deployment with several instances needs a shared limiter (PLAN 1.1).

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_ports::{Clock, PortError, PortLabel, RateDecision, RateKey, RateLimiter, observe};
use tokio::sync::Mutex;

use crate::config::{BackoffConfig, BucketConfig, MemoryRateLimitConfig};

/// The label of the limiter in metrics and spans.
const LABEL: PortLabel = PortLabel::new("rate_limiter", crate::config::PLUGIN);

/// Nanoseconds since the Unix epoch.
type Nanos = i128;

const NANOS_PER_SECOND: Nanos = 1_000_000_000;

/// The nanoseconds since the epoch of an instant.
fn nanos_of(time: DateTime<Utc>) -> Nanos {
    Nanos::from(time.timestamp()) * NANOS_PER_SECOND + Nanos::from(time.timestamp_subsec_nanos())
}

/// The nanoseconds of a duration, saturating.
fn span_of(duration: Duration) -> Nanos {
    Nanos::try_from(duration.as_nanos()).unwrap_or(Nanos::MAX)
}

/// A duration of `nanos` nanoseconds: at least one, at most what a `Duration` of `u64` nanoseconds holds.
fn duration_of(nanos: Nanos) -> Duration {
    Duration::from_nanos(u64::try_from(nanos.max(1)).unwrap_or(u64::MAX))
}

/// What one key of a bucket remembers.
#[derive(Debug, Clone, Copy)]
enum Slot {
    /// A rate bucket: the theoretical arrival time of the next unit.
    Rate { tat: Nanos },
    /// A backoff bucket: the failures counted, when the last one happened and until when the key is blocked.
    Backoff {
        failures: u32,
        last_failure: Nanos,
        blocked_until: Nanos,
    },
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    slot: Slot,
    /// When the key was last checked, for eviction.
    touched: Nanos,
}

/// The answer of a check and the state to keep.
#[derive(Debug, Clone, Copy)]
struct Verdict {
    decision: RateDecision,
    slot: Slot,
}

/// The units of a rate bucket that are left at `start` (the arrival time of the next unit, not before now).
fn units_left(start: Nanos, now: Nanos, interval: Nanos, tolerance: Nanos) -> u32 {
    let free = tolerance - (start - now);
    if free <= 0 {
        return 0;
    }
    u32::try_from(free / interval).unwrap_or(u32::MAX)
}

/// One check of a rate bucket (the generic cell rate algorithm).
fn check_rate(config: &BucketConfig, previous: Option<Slot>, now: Nanos, cost: u32) -> Verdict {
    let window = span_of(config.window);
    let interval = (window / Nanos::from(config.limit.max(1))).max(1);
    let tolerance = interval.saturating_mul(Nanos::from(config.limit.max(1)));
    let tat = match previous {
        Some(Slot::Rate { tat }) => tat,
        _ => now,
    };
    let start = tat.max(now);
    if cost == 0 {
        // A probe: is there room for one unit? Nothing is consumed.
        let left = units_left(start, now, interval, tolerance);
        let decision = if left >= 1 {
            RateDecision::allow(left)
        } else {
            RateDecision::deny(duration_of((start + interval - tolerance - now).min(window)))
        };
        return Verdict {
            decision,
            slot: Slot::Rate { tat },
        };
    }
    let cost_ns = interval.saturating_mul(Nanos::from(cost));
    if cost_ns > tolerance {
        // More than the bucket can ever hold never fits; say "come back after one window".
        return Verdict {
            decision: RateDecision::deny(duration_of(window)),
            slot: Slot::Rate { tat },
        };
    }
    let new_tat = start.saturating_add(cost_ns);
    let wait = new_tat - tolerance - now;
    if wait <= 0 {
        Verdict {
            decision: RateDecision::allow(units_left(new_tat, now, interval, tolerance)),
            slot: Slot::Rate { tat: new_tat },
        }
    } else {
        Verdict {
            decision: RateDecision::deny(duration_of(wait.min(window))),
            slot: Slot::Rate { tat },
        }
    }
}

/// The block that the `failures`-th failure causes: `base` for the first one beyond the free ones, doubling.
fn block_for(backoff: &BackoffConfig, free: u32, failures: u32) -> Nanos {
    let beyond = failures.saturating_sub(free);
    let doublings = beyond.saturating_sub(1).min(62);
    let base = span_of(backoff.base);
    let max = span_of(backoff.max);
    base.saturating_mul(1_i128 << doublings).min(max)
}

/// When the quiet time of a failure key began: after its last failure or after its block ended, whichever is later.
fn quiet_since(last_failure: Nanos, blocked_until: Nanos) -> Nanos {
    last_failure.max(blocked_until)
}

/// One check of a backoff bucket.
fn check_backoff(
    config: &BucketConfig,
    backoff: &BackoffConfig,
    previous: Option<Slot>,
    now: Nanos,
    cost: u32,
) -> Verdict {
    let (mut failures, last_failure, blocked_until) = match previous {
        Some(Slot::Backoff {
            failures,
            last_failure,
            blocked_until,
        }) => (failures, last_failure, blocked_until),
        _ => (0, now, now),
    };
    // Failures are forgotten after a quiet window, counted from the end of the last block: while a key is
    // blocked it is quiet by force, and a block as long as the window must not wipe out the failures behind it.
    if failures > 0 && now - quiet_since(last_failure, blocked_until) >= span_of(config.window) {
        failures = 0;
    }
    let slot = Slot::Backoff {
        failures,
        last_failure,
        blocked_until,
    };
    if now < blocked_until {
        return Verdict {
            decision: RateDecision::deny(duration_of(blocked_until - now)),
            slot,
        };
    }
    if cost == 0 {
        return Verdict {
            decision: RateDecision::allow(config.limit.saturating_sub(failures)),
            slot,
        };
    }
    failures = failures.saturating_add(cost);
    let blocked_until = if failures > config.limit {
        now.saturating_add(block_for(backoff, config.limit, failures))
    } else {
        blocked_until
    };
    Verdict {
        decision: RateDecision::allow(config.limit.saturating_sub(failures)),
        slot: Slot::Backoff {
            failures,
            last_failure: now,
            blocked_until,
        },
    }
}

/// Whether a key has returned to the state of a key never seen, so that dropping it changes no answer.
fn is_idle(config: &BucketConfig, slot: Slot, now: Nanos) -> bool {
    match slot {
        Slot::Rate { tat } => tat <= now,
        Slot::Backoff {
            failures,
            last_failure,
            blocked_until,
        } => {
            now >= blocked_until
                && (failures == 0 || now - quiet_since(last_failure, blocked_until) >= span_of(config.window))
        }
    }
}

/// Whether a key is being punished right now: a backoff key whose block has not ended. Dropping it would lift the
/// block, so it is the last to go when the table is full.
fn is_blocked(slot: Slot, now: Nanos) -> bool {
    matches!(slot, Slot::Backoff { blocked_until, .. } if blocked_until > now)
}

/// The in-memory rate limiter.
pub struct MemoryRateLimiter {
    clock: Arc<dyn Clock>,
    config: MemoryRateLimitConfig,
    entries: Mutex<HashMap<RateKey, Entry>>,
}

impl core::fmt::Debug for MemoryRateLimiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryRateLimiter")
            .field("max_keys", &self.config.max_keys)
            .finish_non_exhaustive()
    }
}

impl MemoryRateLimiter {
    /// A limiter with the allowances of `config`, reading time from `clock`.
    pub fn new(clock: Arc<dyn Clock>, config: MemoryRateLimitConfig) -> Self {
        Self {
            clock,
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// How many keys the limiter tracks at the moment.
    pub async fn tracked_keys(&self) -> usize {
        self.entries.lock().await.len()
    }

    /// Makes room for one more key.
    ///
    /// Drops the idle entries; when that leaves the table fuller than about nine tenths of its cap, the least
    /// recently used entries are dropped as well, those whose key is blocked last. The table then has headroom, so
    /// the next new keys do not sweep it again.
    fn make_room(&self, entries: &mut HashMap<RateKey, Entry>, now: Nanos) {
        entries.retain(|key, entry| !is_idle(&self.config.bucket(key.bucket), entry.slot, now));
        let max = self.config.max_keys;
        let target = max.saturating_sub((max / 10).max(1));
        if entries.len() <= target {
            return;
        }
        let mut order: Vec<(bool, Nanos, RateKey)> = entries
            .iter()
            .map(|(key, entry)| (is_blocked(entry.slot, now), entry.touched, key.clone()))
            .collect();
        order.sort_unstable_by_key(|(blocked, touched, _)| (*blocked, *touched));
        let evict = entries.len() - target;
        for (_, _, key) in order.into_iter().take(evict) {
            entries.remove(&key);
        }
    }

    async fn decide(&self, key: &RateKey, cost: u32) -> RateDecision {
        let now = nanos_of(self.clock.now());
        let config = self.config.bucket(key.bucket);
        let mut entries = self.entries.lock().await;
        if !entries.contains_key(key) && entries.len() >= self.config.max_keys {
            self.make_room(&mut entries, now);
        }
        let previous = entries.get(key).map(|entry| entry.slot);
        let verdict = match &config.backoff {
            Some(backoff) => check_backoff(&config, backoff, previous, now, cost),
            None => check_rate(&config, previous, now, cost),
        };
        if previous.is_some() || cost > 0 || !is_idle(&config, verdict.slot, now) {
            entries.insert(
                key.clone(),
                Entry {
                    slot: verdict.slot,
                    touched: now,
                },
            );
        }
        verdict.decision
    }
}

#[async_trait]
impl RateLimiter for MemoryRateLimiter {
    async fn check(&self, key: &RateKey, cost: u32) -> Result<RateDecision, PortError> {
        observe(LABEL, "check", async { Ok(self.decide(key, cost).await) }).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Duration as Chrono;
    use davhaven_port_tests::rate_limit::{
        BUCKET, BackoffRig, run, run_all, run_backoff, run_backoff_all, run_limited, run_limited_all,
    };
    use davhaven_ports::testing::ManualClock;

    use super::*;

    fn rate(limit: u32, window: Duration) -> BucketConfig {
        BucketConfig {
            limit,
            window,
            backoff: None,
        }
    }

    fn backoff(limit: u32, window: Duration, base: Duration, max: Duration) -> BucketConfig {
        BucketConfig {
            limit,
            window,
            backoff: Some(BackoffConfig { base, max }),
        }
    }

    fn limiter_with(buckets: &[(&str, BucketConfig)], max_keys: usize) -> (MemoryRateLimiter, ManualClock) {
        let clock = ManualClock::default();
        let config = MemoryRateLimitConfig {
            default: rate(5, Duration::from_mins(1)),
            buckets: buckets
                .iter()
                .map(|(name, bucket)| ((*name).to_owned(), *bucket))
                .collect::<BTreeMap<_, _>>(),
            max_keys,
            ..MemoryRateLimitConfig::default()
        };
        (MemoryRateLimiter::new(Arc::new(clock.clone()), config), clock)
    }

    fn limiter() -> (MemoryRateLimiter, ManualClock) {
        limiter_with(&[], 1000)
    }

    #[tokio::test]
    async fn the_memory_limiter_satisfies_the_contract() {
        run_all(|| Arc::new(limiter().0)).await;
        run_limited_all(|| Arc::new(limiter().0)).await;
        assert_eq!(run(|| Arc::new(limiter().0)).await.case_count(), 3);
        assert_eq!(run_limited(|| Arc::new(limiter().0)).await.case_count(), 1);
        // The default of 600 per minute, as a deployment gets it without configuration.
        let defaults = || {
            let limiter: Arc<dyn RateLimiter> = Arc::new(MemoryRateLimiter::new(
                Arc::new(ManualClock::default()),
                MemoryRateLimitConfig::default(),
            ));
            limiter
        };
        run_all(defaults).await;
        run_limited_all(defaults).await;
    }

    /// A limiter with the failure backoff a deployment gets without configuration.
    fn default_backoff_rig() -> BackoffRig {
        let clock = ManualClock::default();
        BackoffRig {
            limiter: Arc::new(MemoryRateLimiter::new(
                Arc::new(clock.clone()),
                MemoryRateLimitConfig::default(),
            )),
            clock,
        }
    }

    #[tokio::test]
    async fn the_authentication_buckets_satisfy_the_backoff_contract_out_of_the_box() {
        run_backoff_all(default_backoff_rig).await;
        assert_eq!(run_backoff(default_backoff_rig).await.case_count(), 6);
    }

    #[tokio::test]
    async fn the_failure_policy_of_the_deployment_is_what_the_buckets_follow() {
        use davhaven_ports::FailureBackoff;

        let clock = ManualClock::default();
        let config = MemoryRateLimitConfig {
            failure_backoff: FailureBackoff {
                free: 1,
                window: Duration::from_mins(10),
                base: Duration::from_secs(7),
                max: Duration::from_secs(20),
            },
            ..MemoryRateLimitConfig::default()
        };
        let limiter = MemoryRateLimiter::new(Arc::new(clock.clone()), config);
        let key = RateKey::auth_login_ip("anna|203.0.113.7");
        assert!(limiter.check(&key, 0).await.unwrap().allowed);
        limiter.check(&key, 1).await.unwrap();
        assert!(limiter.check(&key, 0).await.unwrap().allowed, "one free failure");
        limiter.check(&key, 1).await.unwrap();
        assert_eq!(
            limiter.check(&key, 0).await.unwrap().retry_after,
            Some(Duration::from_secs(7)),
            "the base of the deployment"
        );
        clock.advance(Chrono::seconds(7));
        limiter.check(&key, 1).await.unwrap();
        assert_eq!(
            limiter.check(&key, 0).await.unwrap().retry_after,
            Some(Duration::from_secs(14))
        );
        clock.advance(Chrono::seconds(14));
        limiter.check(&key, 1).await.unwrap();
        assert_eq!(
            limiter.check(&key, 0).await.unwrap().retry_after,
            Some(Duration::from_secs(20)),
            "bounded by the maximum of the deployment"
        );
        // The per-address bucket allows four times as many free failures.
        let address = RateKey::auth_ip("203.0.113.7");
        for _ in 0..4 {
            limiter.check(&address, 1).await.unwrap();
        }
        assert!(limiter.check(&address, 0).await.unwrap().allowed);
        limiter.check(&address, 1).await.unwrap();
        assert!(!limiter.check(&address, 0).await.unwrap().allowed);
    }

    #[tokio::test]
    async fn a_rate_bucket_allows_its_limit_then_refills_continuously() {
        let (limiter, clock) = limiter();
        let key = RateKey::new("api", "token-1");
        for left in (0..5).rev() {
            let decision = limiter.check(&key, 1).await.unwrap();
            assert!(decision.allowed && decision.retry_after.is_none(), "{decision:?}");
            assert_eq!(decision.remaining, left);
        }
        let denied = limiter.check(&key, 1).await.unwrap();
        assert!(!denied.allowed);
        assert_eq!(denied.remaining, 0);
        // One unit costs 12 s (5 per minute): that is how long the client is asked to wait.
        assert_eq!(denied.retry_after, Some(Duration::from_secs(12)));

        clock.advance(Chrono::seconds(11));
        assert!(!limiter.check(&key, 1).await.unwrap().allowed, "not yet");
        clock.advance(Chrono::seconds(1));
        assert!(limiter.check(&key, 1).await.unwrap().allowed, "one unit is back");
        assert!(!limiter.check(&key, 1).await.unwrap().allowed);

        clock.advance(Chrono::hours(1));
        let full = limiter.check(&key, 0).await.unwrap();
        assert_eq!(
            (full.allowed, full.remaining),
            (true, 5),
            "an idle bucket is full again, not fuller"
        );
    }

    #[tokio::test]
    async fn no_schedule_of_requests_gets_more_than_the_burst_plus_the_refill() {
        // The guarantee a client can rely on and an attacker cannot beat: over any stretch of time, a key is admitted
        // at most `limit` units plus one unit per `window / limit` that passed. An irregular schedule (a fixed
        // linear congruential sequence, so the run is the same every time) of gaps and costs probes it.
        let (limiter, clock) = limiter();
        let key = RateKey::new("api", "token-1");
        let interval_ms: i64 = 12_000;
        let mut state: u64 = 0x5eed;
        let mut next = |modulus: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % modulus
        };
        let (mut elapsed_ms, mut admitted, mut refused) = (0_i64, 0_i64, 0);
        for _ in 0..2000 {
            let gap = i64::try_from(next(4000)).unwrap();
            let cost = u32::try_from(next(3)).unwrap() + 1;
            clock.advance(Chrono::milliseconds(gap));
            elapsed_ms += gap;
            let decision = limiter.check(&key, cost).await.unwrap();
            if decision.allowed {
                admitted += i64::from(cost);
            } else {
                refused += 1;
                assert!(decision.retry_after.is_some_and(|wait| wait <= Duration::from_mins(1)));
            }
            assert!(
                admitted <= 5 + elapsed_ms / interval_ms,
                "{admitted} units admitted after {elapsed_ms} ms"
            );
        }
        assert!(refused > 0, "the schedule is fast enough to hit the limit");
        assert!(
            admitted >= elapsed_ms / interval_ms - 5,
            "and the limiter does not starve the key: {admitted} units in {elapsed_ms} ms"
        );
    }

    #[tokio::test]
    async fn costs_larger_than_one_are_consumed_together_or_not_at_all() {
        let (limiter, _clock) = limiter();
        let key = RateKey::new("mail", "tenant");
        let first = limiter.check(&key, 3).await.unwrap();
        assert_eq!((first.allowed, first.remaining), (true, 2));
        let too_much = limiter.check(&key, 3).await.unwrap();
        assert!(!too_much.allowed, "three units do not fit into two");
        assert_eq!(
            limiter.check(&key, 0).await.unwrap().remaining,
            2,
            "a refusal consumes nothing"
        );
        assert!(limiter.check(&key, 2).await.unwrap().allowed);
        // More than the bucket can ever hold: refused with one window as the hint.
        let never = limiter.check(&RateKey::new("mail", "other"), 6).await.unwrap();
        assert!(!never.allowed);
        assert_eq!(never.retry_after, Some(Duration::from_mins(1)));
    }

    #[tokio::test]
    async fn asking_with_a_cost_of_zero_never_consumes_and_reports_room() {
        let (limiter, _clock) = limiter();
        let key = RateKey::new("api", "k");
        for _ in 0..20 {
            assert!(limiter.check(&key, 0).await.unwrap().allowed);
        }
        for _ in 0..5 {
            limiter.check(&key, 1).await.unwrap();
        }
        let blocked = limiter.check(&key, 0).await.unwrap();
        assert!(!blocked.allowed);
        assert_eq!(blocked.retry_after, Some(Duration::from_secs(12)));
        assert_eq!(limiter.tracked_keys().await, 1);
        let fresh = RateKey::new("api", "never-used");
        limiter.check(&fresh, 0).await.unwrap();
        assert_eq!(
            limiter.tracked_keys().await,
            1,
            "a probe of an unknown key stores nothing"
        );
    }

    #[tokio::test]
    async fn buckets_and_keys_are_independent_and_configured_by_name() {
        let (limiter, _clock) = limiter_with(&[("tight", rate(1, Duration::from_mins(1)))], 1000);
        assert!(limiter.check(&RateKey::new("tight", "a"), 1).await.unwrap().allowed);
        assert!(!limiter.check(&RateKey::new("tight", "a"), 1).await.unwrap().allowed);
        assert!(
            limiter.check(&RateKey::new("tight", "b"), 1).await.unwrap().allowed,
            "other key"
        );
        assert!(
            limiter.check(&RateKey::new("loose", "a"), 1).await.unwrap().allowed,
            "other bucket"
        );
        assert_eq!(
            limiter.check(&RateKey::new("loose", "a"), 0).await.unwrap().remaining,
            4,
            "default limit"
        );
    }

    #[tokio::test]
    async fn failures_beyond_the_free_ones_block_for_twice_as_long_each_time() {
        let bucket = backoff(
            2,
            Duration::from_mins(15),
            Duration::from_secs(1),
            Duration::from_secs(8),
        );
        let (limiter, clock) = limiter_with(&[("auth", bucket)], 1000);
        let key = RateKey::new("auth", "anna|203.0.113.7");

        // Two free failures; nothing blocks.
        for left in [1, 0] {
            let decision = limiter.check(&key, 1).await.unwrap();
            assert_eq!((decision.allowed, decision.remaining), (true, left));
            assert!(limiter.check(&key, 0).await.unwrap().allowed, "still free");
        }
        // The third failure is admitted and starts a block of one second, then 2, 4, 8, 8 ...
        for block in [1_u64, 2, 4, 8, 8, 8] {
            let admitted = limiter.check(&key, 1).await.unwrap();
            assert!(admitted.allowed, "the failing attempt itself was admitted");
            let blocked = limiter.check(&key, 0).await.unwrap();
            assert!(!blocked.allowed);
            assert_eq!(blocked.retry_after, Some(Duration::from_secs(block)), "block {block}");
            clock.advance(Chrono::seconds(i64::try_from(block).unwrap()));
        }
    }

    #[tokio::test]
    async fn a_blocked_key_gains_nothing_by_hammering_and_is_not_punished_twice() {
        let bucket = backoff(
            0,
            Duration::from_mins(15),
            Duration::from_secs(10),
            Duration::from_mins(5),
        );
        let (limiter, clock) = limiter_with(&[("auth", bucket)], 1000);
        let key = RateKey::new("auth", "k");
        assert!(limiter.check(&key, 1).await.unwrap().allowed);
        for _ in 0..50 {
            let denied = limiter.check(&key, 1).await.unwrap();
            assert!(!denied.allowed);
            assert_eq!(
                denied.retry_after,
                Some(Duration::from_secs(10)),
                "the block does not grow while blocked"
            );
        }
        clock.advance(Chrono::seconds(4));
        assert_eq!(
            limiter.check(&key, 1).await.unwrap().retry_after,
            Some(Duration::from_secs(6)),
            "the hint counts down"
        );
        clock.advance(Chrono::seconds(6));
        assert!(
            limiter.check(&key, 1).await.unwrap().allowed,
            "second failure after the wait: admitted, blocked 20 s"
        );
        assert_eq!(
            limiter.check(&key, 0).await.unwrap().retry_after,
            Some(Duration::from_secs(20))
        );
    }

    #[tokio::test]
    async fn failures_are_forgotten_after_a_quiet_window() {
        let bucket = backoff(
            1,
            Duration::from_mins(15),
            Duration::from_secs(30),
            Duration::from_mins(5),
        );
        let (limiter, clock) = limiter_with(&[("auth", bucket)], 1000);
        let key = RateKey::new("auth", "k");
        limiter.check(&key, 1).await.unwrap();
        limiter.check(&key, 1).await.unwrap();
        assert!(!limiter.check(&key, 0).await.unwrap().allowed);
        clock.advance(Chrono::minutes(16));
        let fresh = limiter.check(&key, 0).await.unwrap();
        assert_eq!(
            (fresh.allowed, fresh.remaining),
            (true, 1),
            "forgotten: one free failure again"
        );
        assert!(limiter.check(&key, 1).await.unwrap().allowed);
        assert!(
            limiter.check(&key, 0).await.unwrap().allowed,
            "the first failure after the window is free"
        );
    }

    #[tokio::test]
    async fn an_absurd_number_of_failures_saturates_instead_of_overflowing() {
        let bucket = backoff(
            0,
            Duration::from_hours(24),
            Duration::from_secs(1),
            Duration::from_mins(5),
        );
        let (limiter, clock) = limiter_with(&[("auth", bucket)], 1000);
        let key = RateKey::new("auth", "k");
        for _ in 0..200 {
            limiter.check(&key, u32::MAX).await.unwrap();
            let blocked = limiter.check(&key, 0).await.unwrap();
            assert_eq!(blocked.retry_after, Some(Duration::from_mins(5)));
            clock.advance(Chrono::minutes(5));
        }
    }

    #[tokio::test]
    async fn a_block_as_long_as_the_window_keeps_doubling() {
        // Without free failures, a window of 10 s and a base block of 20 s: the block outlasts the quiet window of
        // the key, which used to wipe its failures and start the schedule over with every block.
        let bucket = backoff(
            0,
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_mins(10),
        );
        let (limiter, clock) = limiter_with(&[("auth", bucket)], 1000);
        let key = RateKey::new("auth", "k");
        for block in [20_u64, 40, 80, 160, 320, 600, 600] {
            assert!(limiter.check(&key, 1).await.unwrap().allowed);
            assert_eq!(
                limiter.check(&key, 0).await.unwrap().retry_after,
                Some(Duration::from_secs(block)),
                "the {block} s block"
            );
            clock.advance(Chrono::seconds(i64::try_from(block).unwrap()));
        }
        // A quiet window after the last block, and the key starts over.
        clock.advance(Chrono::seconds(10));
        assert!(limiter.check(&key, 1).await.unwrap().allowed);
        assert_eq!(
            limiter.check(&key, 0).await.unwrap().retry_after,
            Some(Duration::from_secs(20))
        );
    }

    #[tokio::test]
    async fn a_long_window_with_a_long_maximum_reaches_the_maximum() {
        // Three free failures per quarter of an hour and blocks up to an hour: the attacker no longer gets a fresh
        // ramp every quarter of an hour.
        let bucket = backoff(
            3,
            Duration::from_mins(15),
            Duration::from_secs(60),
            Duration::from_hours(1),
        );
        let (limiter, clock) = limiter_with(&[("auth", bucket)], 1000);
        let key = RateKey::new("auth", "k");
        for _ in 0..3 {
            limiter.check(&key, 1).await.unwrap();
        }
        let mut waits = Vec::new();
        for _ in 0..8 {
            limiter.check(&key, 1).await.unwrap();
            let wait = limiter.check(&key, 0).await.unwrap().retry_after.unwrap();
            waits.push(wait.as_secs());
            clock.advance(Chrono::seconds(i64::try_from(wait.as_secs()).unwrap()));
        }
        assert_eq!(waits, vec![60, 120, 240, 480, 960, 1920, 3600, 3600]);
    }

    #[tokio::test]
    async fn a_key_that_is_blocked_survives_a_flood_of_new_keys() {
        let bucket = backoff(
            0,
            Duration::from_mins(15),
            Duration::from_mins(5),
            Duration::from_mins(5),
        );
        let (limiter, clock) = limiter_with(&[("auth", bucket)], 20);
        let blocked = RateKey::new("auth", "attacker");
        limiter.check(&blocked, 1).await.unwrap();
        assert!(!limiter.check(&blocked, 0).await.unwrap().allowed);
        for n in 0..200 {
            clock.advance(Chrono::milliseconds(10));
            limiter
                .check(&RateKey::new("api", format!("flood-{n}")), 1)
                .await
                .unwrap();
            assert!(limiter.tracked_keys().await <= 20);
        }
        assert!(
            !limiter.check(&blocked, 0).await.unwrap().allowed,
            "the block of a key that is still punished is not lifted by eviction"
        );
    }

    #[tokio::test]
    async fn making_room_leaves_headroom_so_that_the_sweep_is_not_repeated_for_every_key() {
        let (limiter, clock) = limiter_with(&[], 100);
        for n in 0..100 {
            clock.advance(Chrono::milliseconds(1));
            limiter
                .check(&RateKey::new("api", format!("busy-{n}")), 1)
                .await
                .unwrap();
        }
        clock.advance(Chrono::milliseconds(1));
        assert_eq!(limiter.tracked_keys().await, 100);
        limiter.check(&RateKey::new("api", "one-more"), 1).await.unwrap();
        assert_eq!(
            limiter.tracked_keys().await,
            91,
            "a tenth was freed at once (90 kept) before the new key went in"
        );
        for n in 0..9 {
            clock.advance(Chrono::milliseconds(1));
            limiter
                .check(&RateKey::new("api", format!("more-{n}")), 1)
                .await
                .unwrap();
        }
        assert_eq!(limiter.tracked_keys().await, 100, "the next nine keys needed no sweep");
        let oldest = limiter.check(&RateKey::new("api", "busy-0"), 0).await.unwrap();
        assert_eq!(
            oldest.remaining, 5,
            "the least recently used keys were the ones dropped"
        );
    }

    #[tokio::test]
    async fn the_table_is_capped_and_forgets_idle_keys_first() {
        let (limiter, clock) = limiter_with(&[], 10);
        for n in 0..10 {
            limiter
                .check(&RateKey::new("api", format!("key-{n}")), 1)
                .await
                .unwrap();
        }
        assert_eq!(limiter.tracked_keys().await, 10);
        // Everything is idle after an hour: a new key sweeps them away.
        clock.advance(Chrono::hours(1));
        limiter.check(&RateKey::new("api", "fresh"), 1).await.unwrap();
        assert_eq!(limiter.tracked_keys().await, 1);

        // Without idle keys the least recently used tenth makes room, and the table never exceeds its cap.
        for n in 0..50 {
            limiter
                .check(&RateKey::new("api", format!("busy-{n}")), 1)
                .await
                .unwrap();
            assert!(limiter.tracked_keys().await <= 10);
        }
        let recent = limiter.check(&RateKey::new("api", "busy-49"), 0).await.unwrap();
        assert_eq!(recent.remaining, 4, "the most recent key was kept with its state");
    }

    #[tokio::test]
    async fn contract_bucket_name_is_the_default_bucket() {
        let (limiter, _clock) = limiter();
        let key = RateKey::new(BUCKET, "x");
        assert_eq!(limiter.check(&key, 0).await.unwrap().remaining, 5);
    }
}
