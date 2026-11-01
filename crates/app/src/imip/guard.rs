//! The safety rails around outgoing mail: the server-wide rate limit, the circuit breaker in front of the relay
//! and the staging rules (`mail.rate_limit_per_minute`, `mail.max_consecutive_failures`,
//! `mail.allowed_recipient_domains`, `mail.redirect_all_to`).
//!
//! * **Rate limit.** Two limits apply, in this order. A token bucket that holds `rate_limit_per_minute` tokens and
//!   refills at that rate per minute, shared by all tenants of **this process** (what `mail.rate_limit_per_minute`
//!   says: no instance sends faster). Then the `mail` bucket of the `RateLimiter` port, which is shared between
//!   instances when the deployment configures a shared limiter and allows everything with the `noop` one. A mail
//!   that finds either empty is held back: the handler defers it for the time the next token takes (the
//!   `retry_after` of the limiter), without using up an attempt of the outbox. A limiter that cannot answer does
//!   not stop the mail: the local bucket still applies.
//! * **Circuit breaker.** After `max_consecutive_failures` failed sends in a row the breaker opens and mail waits in
//!   the outbox instead of hammering a relay that is down. The cooldown starts at the outbox backoff base and
//!   doubles every time the relay fails again, up to the outbox backoff maximum. When it has passed one mail is
//!   let through as a probe; success closes the breaker, failure opens it again for twice as long. An answer of
//!   the relay (even a refusal of a recipient) shows that the relay works and counts as success. The state is
//!   local to the process. Mail that finds the breaker open is deferred until the cooldown has passed, without
//!   using up an attempt.
//! * **Staging rules.** Recipients outside the allowed domains are dropped (and counted), and a redirect address
//!   replaces every recipient.

use std::time::Duration as Wait;

use chrono::{DateTime, Duration, Utc};
use davhaven_domain::Email;
use davhaven_ports::{RateKey, RateLimiter};
use tokio::sync::Mutex;

use crate::config::{MailConfig, OutboxConfig};

/// The gauge that is 1 while the breaker is open or half open.
pub const CIRCUIT_OPEN: &str = "davhaven_mail_circuit_open";

/// The bucket of the `RateLimiter` port that limits outgoing mail (one key for the whole server).
pub const RATE_BUCKET: &str = "mail";

/// The key inside [`RATE_BUCKET`].
const RATE_KEY: &str = "relay";

/// A probe that never reports back (its handler was dropped) is considered lost after this long.
const PROBE_TIMEOUT: Duration = Duration::minutes(2);

/// The shortest hold: handlers never ask the dispatcher to come back sooner than this.
const MIN_HOLD: Wait = Wait::from_secs(1);

/// How long a mail waits while another mail probes the relay.
const PROBE_HOLD: Wait = Wait::from_secs(5);

/// Whether a mail may be sent now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Send it.
    Go,
    /// The rate limit is reached; the next token takes `retry_after`.
    RateLimited {
        /// How long until a token is available.
        retry_after: Wait,
    },
    /// The breaker is open; the cooldown ends in `retry_after`.
    BreakerOpen {
        /// How long until a probe is let through.
        retry_after: Wait,
    },
}

/// The kind of a [`Gate`] without its payload.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateKind {
    /// See [`Gate::Go`].
    Go,
    /// See [`Gate::RateLimited`].
    RateLimited,
    /// See [`Gate::BreakerOpen`].
    BreakerOpen,
}

#[cfg(test)]
impl Gate {
    /// The kind of the gate.
    pub(crate) const fn kind(self) -> GateKind {
        match self {
            Self::Go => GateKind::Go,
            Self::RateLimited { .. } => GateKind::RateLimited,
            Self::BreakerOpen { .. } => GateKind::BreakerOpen,
        }
    }
}

/// `span` as a wait of at least [`MIN_HOLD`].
fn hold(span: Duration) -> Wait {
    span.to_std().unwrap_or(MIN_HOLD).max(MIN_HOLD)
}

#[derive(Debug, Default)]
struct State {
    tokens: f64,
    refilled_at: Option<DateTime<Utc>>,
    failures: u32,
    trips: u32,
    open_until: Option<DateTime<Utc>>,
    probing_since: Option<DateTime<Utc>>,
}

/// The rate limit and the circuit breaker of outgoing mail.
#[derive(Debug, Default)]
pub(crate) struct MailGuard {
    state: Mutex<State>,
}

/// The cooldown after the `trips`th opening: base, doubled for every earlier opening, at most the maximum.
fn cooldown(config: &OutboxConfig, trips: u32) -> Duration {
    let delay = config
        .backoff_base
        .checked_mul(1_u32 << trips.min(20))
        .map_or(config.backoff_max, |delay| delay.min(config.backoff_max));
    Duration::from_std(delay).unwrap_or(Duration::hours(1))
}

/// `window` in seconds, with millisecond precision: a token bucket that credits whole seconds only would never
/// refill under dense traffic.
fn seconds(window: Duration) -> f64 {
    f64::from(u32::try_from(window.num_milliseconds().max(0)).unwrap_or(u32::MAX)) / 1000.0
}

/// What the local checks decided, and whether the mail took the probe slot of a half open breaker (which has to be
/// given back when the shared limiter then refuses it).
struct Admission {
    gate: Gate,
    took_probe: bool,
}

impl MailGuard {
    /// Decides whether a mail may go out at `now`; a `Go` consumes a token (and takes the probe slot of a half
    /// open breaker). The shared limiter is asked last, so that a refusal by it costs nothing locally.
    pub(crate) async fn admit(&self, now: DateTime<Utc>, mail: &MailConfig, limiter: &dyn RateLimiter) -> Gate {
        let admission = self.admit_local(now, mail).await;
        if admission.gate != Gate::Go {
            return admission.gate;
        }
        match limiter.check(&RateKey::new(RATE_BUCKET, RATE_KEY), 1).await {
            Ok(decision) if !decision.allowed => {
                self.refund(mail, admission.took_probe).await;
                Gate::RateLimited {
                    retry_after: decision.retry_after.unwrap_or(Wait::from_secs(60)).max(MIN_HOLD),
                }
            }
            Ok(_) => Gate::Go,
            Err(error) => {
                // A shared limiter that is down must not stop the mail: the local bucket still limits it.
                tracing::debug!(
                    kind = error.kind.as_str(),
                    "the shared mail limiter did not answer; the mail goes on"
                );
                Gate::Go
            }
        }
    }

    /// The local part: the token bucket of this process and the circuit breaker.
    async fn admit_local(&self, now: DateTime<Utc>, mail: &MailConfig) -> Admission {
        let held = |gate| Admission {
            gate,
            took_probe: false,
        };
        let mut state = self.state.lock().await;
        let capacity = f64::from(mail.rate_limit_per_minute);
        let tokens = match state.refilled_at {
            None => capacity,
            Some(at) => (state.tokens + seconds(now - at) * capacity / 60.0).min(capacity),
        };
        state.tokens = tokens;
        state.refilled_at = Some(now);
        if tokens < 1.0 {
            // The time the missing part of a token takes to refill, rounded up to whole seconds.
            let missing = ((1.0 - tokens) * 60.0 / capacity).ceil();
            return held(Gate::RateLimited {
                retry_after: Wait::try_from_secs_f64(missing)
                    .unwrap_or(Wait::from_secs(60))
                    .max(MIN_HOLD),
            });
        }
        let mut took_probe = false;
        if let Some(until) = state.open_until {
            let probe_lost = state.probing_since.is_some_and(|since| now - since >= PROBE_TIMEOUT);
            if now < until {
                return held(Gate::BreakerOpen {
                    retry_after: hold(until - now),
                });
            }
            if state.probing_since.is_some() && !probe_lost {
                return held(Gate::BreakerOpen {
                    retry_after: PROBE_HOLD,
                });
            }
            state.probing_since = Some(now);
            took_probe = true;
        }
        state.tokens -= 1.0;
        Admission {
            gate: Gate::Go,
            took_probe,
        }
    }

    /// Gives back what `admit_local` took for a mail that the shared limiter then refused.
    async fn refund(&self, mail: &MailConfig, took_probe: bool) {
        let mut state = self.state.lock().await;
        state.tokens = (state.tokens + 1.0).min(f64::from(mail.rate_limit_per_minute));
        if took_probe {
            state.probing_since = None;
        }
    }

    /// The local checks only, for the tests of the bucket and the breaker.
    #[cfg(test)]
    pub(crate) async fn admit_without_shared_limit(&self, now: DateTime<Utc>, mail: &MailConfig) -> Gate {
        self.admit_local(now, mail).await.gate
    }

    /// The relay answered (accepted the mail, or refused it for a reason of the mail): it works.
    pub(crate) async fn reachable(&self) {
        let mut state = self.state.lock().await;
        state.failures = 0;
        state.trips = 0;
        state.open_until = None;
        state.probing_since = None;
        metrics::gauge!(CIRCUIT_OPEN).set(0.0);
    }

    /// A send failed for a reason of the relay or the network.
    pub(crate) async fn failed(&self, now: DateTime<Utc>, mail: &MailConfig, outbox: &OutboxConfig) {
        let mut state = self.state.lock().await;
        let probe_failed = state.probing_since.take().is_some();
        state.failures = state.failures.saturating_add(1);
        // A failure that was already under way when the breaker opened does not open it again.
        let opens = probe_failed || (state.open_until.is_none() && state.failures >= mail.max_consecutive_failures);
        if opens {
            let wait = cooldown(outbox, state.trips);
            state.trips = state.trips.saturating_add(1);
            state.open_until = Some(now + wait);
            metrics::gauge!(CIRCUIT_OPEN).set(1.0);
            tracing::warn!(
                failures = state.failures,
                cooldown_seconds = wait.num_seconds(),
                "the mail circuit breaker is open"
            );
        }
    }

    /// Whether the breaker is open (or half open), for tests and diagnostics.
    #[cfg(test)]
    pub(crate) async fn is_open(&self) -> bool {
        self.state.lock().await.open_until.is_some()
    }
}

/// Whether the staging rule `allowed_recipient_domains` lets mail to `recipient` through: always when the list is
/// empty, otherwise when the recipient's domain is listed or a subdomain of a listed one.
pub(crate) fn recipient_allowed(config: &MailConfig, recipient: &Email) -> bool {
    config.allowed_recipient_domains.is_empty()
        || config.allowed_recipient_domains.iter().any(|allowed| {
            let allowed = allowed.as_str();
            let domain = recipient.domain();
            domain == allowed || domain.strip_suffix(allowed).is_some_and(|rest| rest.ends_with('.'))
        })
}

#[cfg(test)]
mod tests;
