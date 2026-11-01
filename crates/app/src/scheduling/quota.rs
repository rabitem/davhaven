//! Quotas of external recipients: per organizer per hour and per tenant per day (PLAN 2.8).
//!
//! A quota limits the *invitations* that leave the tenant as mail: a `REQUEST` to somebody outside it. Cancellations
//! are never limited (the recipient was counted when they were invited, and refusing the cancellation of a meeting
//! would be worse than the mail), and nothing here ever refuses a write: a recipient beyond the allowance is not
//! mailed and the organizer's copy says so (`SCHEDULE-STATUS` 5.1), like a recipient the external policy refuses.
//!
//! The scheduler asks for the allowance while it plans a write ([`Quotas::allowance`]) and records what it really
//! enqueued once the object is stored ([`Quotas::record`]), so a write that fails, rolls back or is retried uses up
//! nothing. Two writes that plan at the same moment may both see the same allowance; the limit is a guard against
//! abuse, not an exact meter.
//!
//! The counters live in the memory of the process, like the limiter of the single-instance deployment (PLAN 1.1).
//! They are not behind the [`RateLimiter`](davhaven_ports::RateLimiter) port because that port owns its rates in
//! the configuration of the adapter, and these limits are the `[scheduling]` settings of the tenant's deployment; a
//! deployment with several instances needs a shared counter, which is recorded with the shared limiter in
//! `docs/ROADMAP.md`.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::{PrincipalId, TenantId};
use tokio::sync::Mutex;

use crate::config::SchedulingConfig;

/// The window of the per-organizer quota.
const HOUR: TimeDelta = TimeDelta::hours(1);

/// The window of the per-tenant quota.
const DAY: TimeDelta = TimeDelta::days(1);

/// A table with this many keys is cleaned of expired entries before a new key is added, at most once a minute. The
/// number of keys that are alive is bounded by the organizers who sent mail within the last day, not by this
/// constant.
const CLEAN_AT: usize = 10_000;

/// How often a full table is cleaned.
const CLEAN_EVERY: TimeDelta = TimeDelta::minutes(1);

/// What a counter counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Organizer(TenantId, PrincipalId),
    Tenant(TenantId),
}

/// Recipients charged at a time: `(when, how many)`.
type Entries = Vec<(DateTime<Utc>, u32)>;

/// The counters and when they were cleaned last.
#[derive(Debug, Default)]
struct Counters {
    entries: HashMap<Key, Entries>,
    cleaned_at: Option<DateTime<Utc>>,
}

/// The counters of external recipients.
#[derive(Debug, Default)]
pub(crate) struct Quotas {
    counters: Mutex<Counters>,
}

/// How many more recipients may be mailed an invitation, and how long to wait for the next one when none may.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Allowance {
    /// The recipients that fit now.
    pub(crate) remaining: u32,
    /// Until the oldest counted recipients fall out of the window of the limit that is used up; zero while
    /// `remaining` is above `0`.
    pub(crate) wait: Duration,
}

/// The sum of the entries that are still inside `window` at `now`, and when the oldest of them leaves it.
fn inside(entries: &Entries, now: DateTime<Utc>, window: TimeDelta) -> (u64, Option<DateTime<Utc>>) {
    let from = now - window;
    let live = entries.iter().filter(|(at, _)| *at > from);
    let used = live.clone().map(|(_, count)| u64::from(*count)).sum();
    (used, live.map(|(at, _)| *at + window).min())
}

impl Quotas {
    /// How many external recipients `organizer` of `tenant` may still be mailed an invitation at `now`: the smaller
    /// of what the hourly limit of the organizer and the daily limit of the tenant leave.
    pub(crate) async fn allowance(
        &self,
        now: DateTime<Utc>,
        tenant: TenantId,
        organizer: PrincipalId,
        config: &SchedulingConfig,
    ) -> Allowance {
        let counters = self.counters.lock().await;
        let mut remaining = u64::MAX;
        let mut wait = Duration::ZERO;
        for (key, window, limit) in [
            (
                Key::Organizer(tenant, organizer),
                HOUR,
                config.external_per_organizer_per_hour,
            ),
            (Key::Tenant(tenant), DAY, config.external_per_tenant_per_day),
        ] {
            let empty = Entries::new();
            let (used, frees) = inside(counters.entries.get(&key).unwrap_or(&empty), now, window);
            let left = u64::from(limit).saturating_sub(used);
            remaining = remaining.min(left);
            if left == 0 {
                let until = frees.map_or(Duration::from_secs(1), |at| {
                    (at - now).to_std().unwrap_or(Duration::from_secs(1))
                });
                wait = wait.max(until);
            }
        }
        Allowance {
            remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
            wait,
        }
    }

    /// Records that `recipients` external recipients of `organizer` of `tenant` were mailed an invitation at `now`.
    pub(crate) async fn record(&self, now: DateTime<Utc>, tenant: TenantId, organizer: PrincipalId, recipients: u32) {
        if recipients == 0 {
            return;
        }
        let mut counters = self.counters.lock().await;
        if counters.entries.len() >= CLEAN_AT && counters.cleaned_at.is_none_or(|at| now - at >= CLEAN_EVERY) {
            counters
                .entries
                .retain(|_, entries| entries.iter().any(|(at, _)| *at > now - DAY));
            counters.cleaned_at = Some(now);
        }
        for (key, window) in [(Key::Organizer(tenant, organizer), HOUR), (Key::Tenant(tenant), DAY)] {
            let entries = counters.entries.entry(key).or_default();
            entries.retain(|(at, _)| *at > now - window);
            entries.push((now, recipients));
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use uuid::Uuid;

    use super::*;

    fn at(minutes: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 3, 1, 9, 0, 0).unwrap() + TimeDelta::minutes(minutes)
    }

    fn config(per_hour: u32, per_day: u32) -> SchedulingConfig {
        SchedulingConfig {
            external_per_organizer_per_hour: per_hour,
            external_per_tenant_per_day: per_day,
            ..SchedulingConfig::default()
        }
    }

    fn tenant(n: u128) -> TenantId {
        TenantId::from_uuid(Uuid::from_u128(n))
    }

    fn organizer(n: u128) -> PrincipalId {
        PrincipalId::from_uuid(Uuid::from_u128(n))
    }

    #[tokio::test]
    async fn an_organizer_may_invite_up_to_the_hourly_limit_and_then_waits_for_the_oldest() {
        let quotas = Quotas::default();
        let config = config(10, 1000);
        quotas.record(at(0), tenant(1), organizer(1), 6).await;
        quotas.record(at(20), tenant(1), organizer(1), 4).await;
        let left = quotas.allowance(at(30), tenant(1), organizer(1), &config).await;
        assert_eq!(left.remaining, 0);
        assert_eq!(
            left.wait,
            Duration::from_mins(30),
            "the first six leave the window at minute 60"
        );
        // Another organizer of the same tenant is not affected.
        let other = quotas.allowance(at(30), tenant(1), organizer(2), &config).await;
        assert_eq!(other.remaining, 10);
        let later = quotas.allowance(at(61), tenant(1), organizer(1), &config).await;
        assert_eq!(later.remaining, 6, "six left the window, four are still in it");
    }

    #[tokio::test]
    async fn a_tenant_has_a_daily_limit_across_its_organizers() {
        let quotas = Quotas::default();
        let config = config(100, 12);
        quotas.record(at(0), tenant(1), organizer(1), 8).await;
        quotas.record(at(10), tenant(1), organizer(2), 3).await;
        let left = quotas.allowance(at(20), tenant(1), organizer(3), &config).await;
        assert_eq!(left.remaining, 1, "the day holds twelve and eleven are used");
        quotas.record(at(20), tenant(1), organizer(3), 1).await;
        let none = quotas.allowance(at(20), tenant(1), organizer(3), &config).await;
        assert_eq!((none.remaining, none.wait), (0, Duration::from_mins(24 * 60 - 20)));
        let other_tenant = quotas.allowance(at(20), tenant(2), organizer(3), &config).await;
        assert_eq!(other_tenant.remaining, 12);
        let next_day = quotas
            .allowance(at(24 * 60 + 1), tenant(1), organizer(3), &config)
            .await;
        assert_eq!(next_day.remaining, 8);
    }

    #[tokio::test]
    async fn recording_nobody_records_nothing_and_the_allowance_never_goes_below_zero() {
        let quotas = Quotas::default();
        let config = config(5, 5);
        quotas.record(at(0), tenant(1), organizer(1), 0).await;
        assert_eq!(
            quotas
                .allowance(at(0), tenant(1), organizer(1), &config)
                .await
                .remaining,
            5
        );
        // Two writes that planned at the same moment may both record: the allowance is then used up, not negative.
        quotas.record(at(0), tenant(1), organizer(1), 4).await;
        quotas.record(at(0), tenant(1), organizer(1), 4).await;
        assert_eq!(
            quotas
                .allowance(at(1), tenant(1), organizer(1), &config)
                .await
                .remaining,
            0
        );
    }
}
