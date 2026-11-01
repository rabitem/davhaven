//! The `RateLimiter` port.
//!
//! One limiter serves authentication backoff (failure buckets per login and IP and per IP), API and MCP request
//! budgets and mail rate limits. The caller names a bucket and a key; the adapter owns the rates (its
//! configuration) and answers whether the cost fits. `ratelimit-memory` serves a single instance; a shared limiter
//! for multi-instance deployments is a documented backlog item.
//!
//! # Failure buckets: the authentication backoff
//!
//! Two buckets have a fixed meaning that every limiter implements, because R6 and PLAN 2.6 require them: the failed
//! authentications per (login, client address) and per client address back off exponentially, with no hard
//! lockout. They are [`RateKey::AUTH_LOGIN_IP`] and [`RateKey::AUTH_IP`]; the application names them (the
//! constants are the one spelling), the limiter owns the policy ([`FailureBackoff`]), and the contract suite
//! (`davhaven_port_tests::rate_limit::run_backoff`) checks it. A failure bucket works like this:
//!
//! * `check(key, 0)` asks whether the key is blocked and consumes nothing;
//! * `check(key, 1)` records one failed authentication and is admitted (the attempt that failed has happened);
//! * the first `free` failures within a window are free, every further one blocks the key for `base`, `2 × base`,
//!   `4 × base`, … up to `max` (the next failure can only be recorded once the previous block has ended);
//! * a blocked key is denied with the time left; failures that arrive while it is blocked do not lengthen the block;
//! * failures are forgotten after `window` without a new one (counted from the end of the last block).
//!
//! A limiter that cannot do this (the `noop` limiter) fails the backoff cases by design and is refused in
//! production.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use async_trait::async_trait;

use crate::error::PortError;

/// The bits of an IPv6 client address that identify one client for the failure buckets: a /64, the smallest network
/// an ISP hands to a subscriber.
pub const IPV6_CLIENT_PREFIX_BITS: u32 = 64;

/// The address the authentication failure buckets are keyed by ([`RateKey::AUTH_IP`], and the address part of the
/// [`RateKey::AUTH_LOGIN_IP`] key).
///
/// An IPv4 address stands for itself. An IPv6 address stands for its /64: a client with a /64 owns 2^64 addresses,
/// so keying the buckets by the full address would hand it a fresh failure budget per address, which defeats the
/// backoff and lets it fill the limiter's table. An IPv4-mapped IPv6 address (`::ffff:203.0.113.7`) is the IPv4
/// address it maps. The application derives its keys from this, never from the raw address.
pub fn bucket_address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(address) => address.to_ipv4_mapped().map_or_else(
            || {
                IpAddr::V6(Ipv6Addr::from(
                    u128::from(address) & (u128::MAX << (128 - IPV6_CLIENT_PREFIX_BITS)),
                ))
            },
            IpAddr::V4,
        ),
    }
}

/// What is being limited: a bucket kind and an opaque key inside it.
///
/// Keys are derived by the caller (for example a keyed hash of login and client IP), so the limiter never stores
/// raw addresses or logins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RateKey {
    /// The kind of bucket, for example [`RateKey::AUTH_IP`], `api` or `mail`. The adapter maps it to a rate.
    pub bucket: &'static str,
    /// The identity inside the bucket.
    pub key: String,
}

impl RateKey {
    /// The failure bucket of authentications per login and client address (see the module documentation).
    pub const AUTH_LOGIN_IP: &'static str = "auth_failure_login";

    /// The failure bucket of authentications per client address (see the module documentation).
    pub const AUTH_IP: &'static str = "auth_failure_ip";

    /// The rate bucket of the tool calls of an MCP token that only read (PLAN 2.12). The key is a keyed hash of the
    /// token.
    pub const MCP_READ: &'static str = "mcp_read";

    /// The rate bucket of the tool calls of an MCP token that change calendars (PLAN 2.12: a separate budget for
    /// writes). The key is a keyed hash of the token.
    pub const MCP_WRITE: &'static str = "mcp_write";

    /// The key of a (login, client address) pair in [`RateKey::AUTH_LOGIN_IP`]; `key` is a keyed hash, never the
    /// login or the address.
    pub fn auth_login_ip(key: impl Into<String>) -> Self {
        Self::new(Self::AUTH_LOGIN_IP, key)
    }

    /// The key of a client address in [`RateKey::AUTH_IP`]; `key` is a keyed hash, never the address.
    pub fn auth_ip(key: impl Into<String>) -> Self {
        Self::new(Self::AUTH_IP, key)
    }

    /// Creates a key.
    pub fn new(bucket: &'static str, key: impl Into<String>) -> Self {
        Self {
            bucket,
            key: key.into(),
        }
    }
}

/// The policy of the failure buckets [`RateKey::AUTH_LOGIN_IP`] and [`RateKey::AUTH_IP`] (see the module documentation).
///
/// The deployment states it once, in `[security.auth]` (`backoff_free`, `backoff_window`, `backoff_base`,
/// `backoff_max`); the server hands it to the limiter through [`PluginContext::failure_backoff`], and every limiter
/// builds its failure buckets from it, so there is one source of the numbers. Without configuration the
/// [default](FailureBackoff::default) applies, which means the backoff is on out of the box.
///
/// [`PluginContext::failure_backoff`]: crate::PluginContext::failure_backoff
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureBackoff {
    /// How many failures of one (login, address) pair within `window` are free; a person mistypes a password.
    /// The per-address bucket allows [`FailureBackoff::ADDRESS_FACTOR`] times as many (an office shares an address).
    pub free: u32,
    /// The quiet time after which the failures of a key are forgotten.
    pub window: Duration,
    /// How long the first failure beyond the free ones blocks the key; every further one doubles it.
    pub base: Duration,
    /// The longest block: the largest `Retry-After` a failing client is asked to wait.
    pub max: Duration,
}

impl Default for FailureBackoff {
    fn default() -> Self {
        Self {
            free: 5,
            window: Duration::from_mins(15),
            base: Duration::from_secs(1),
            max: Duration::from_mins(5),
        }
    }
}

impl FailureBackoff {
    /// The per-address bucket allows this many times the free failures of a (login, address) pair.
    pub const ADDRESS_FACTOR: u32 = 4;

    /// The policy of the per-address bucket: as many times the free failures as [`FailureBackoff::ADDRESS_FACTOR`]
    /// says, the same timing.
    #[must_use]
    pub const fn per_address(self) -> Self {
        Self {
            free: self.free.saturating_mul(Self::ADDRESS_FACTOR),
            ..self
        }
    }

    /// Checks that the timing is usable.
    ///
    /// # Errors
    ///
    /// The name of the first unusable key of `[security.auth]` and why.
    pub fn validate(&self) -> Result<(), String> {
        if self.window.is_zero() {
            return Err("`backoff_window` must be greater than zero".to_owned());
        }
        if self.base.is_zero() {
            return Err("`backoff_base` must be greater than zero".to_owned());
        }
        if self.base > self.max {
            return Err("`backoff_base` must not exceed `backoff_max`".to_owned());
        }
        Ok(())
    }
}

/// The answer of a rate check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateDecision {
    /// Whether the cost fit into the bucket and was consumed.
    pub allowed: bool,
    /// When `allowed` is false: how long until the same cost would fit (sent as `Retry-After`).
    pub retry_after: Option<Duration>,
    /// What is left in the bucket after this check.
    pub remaining: u32,
}

impl RateDecision {
    /// An allowed decision with `remaining` units left.
    pub const fn allow(remaining: u32) -> Self {
        Self {
            allowed: true,
            retry_after: None,
            remaining,
        }
    }

    /// A denied decision; the same cost fits again after `retry_after`.
    pub const fn deny(retry_after: Duration) -> Self {
        Self {
            allowed: false,
            retry_after: Some(retry_after),
            remaining: 0,
        }
    }
}

/// Limits request rates and failure rates.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Consumes `cost` units of the bucket if they fit. A `cost` of zero consumes nothing and reports whether the
    /// bucket currently has room, which lets callers ask "am I blocked" without counting an attempt.
    ///
    /// # Errors
    ///
    /// Only infrastructure failures of shared limiters are errors; callers decide whether to fail open or closed.
    async fn check(&self, key: &RateKey, cost: u32) -> Result<RateDecision, PortError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_constructors() {
        let allowed = RateDecision::allow(7);
        assert!(allowed.allowed && allowed.retry_after.is_none() && allowed.remaining == 7);
        let denied = RateDecision::deny(Duration::from_secs(30));
        assert!(!denied.allowed);
        assert_eq!(denied.retry_after, Some(Duration::from_secs(30)));
        assert_eq!(denied.remaining, 0);
    }

    #[test]
    fn clients_are_keyed_by_ipv4_address_or_ipv6_prefix() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(bucket_address(ip("203.0.113.7")), ip("203.0.113.7"));
        assert_eq!(
            bucket_address(ip("::ffff:203.0.113.7")),
            ip("203.0.113.7"),
            "an IPv4-mapped address is IPv4"
        );
        // Every address of one /64 is one client.
        let first = bucket_address(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
        let second = bucket_address(ip("2001:db8:1:2:1:2:3:4"));
        assert_eq!(first, second);
        assert_eq!(first, ip("2001:db8:1:2::"));
        assert_ne!(
            first,
            bucket_address(ip("2001:db8:1:3::1")),
            "another /64 is another client"
        );
        assert_eq!(bucket_address(ip("::1")), ip("::"));
    }

    #[test]
    fn the_failure_buckets_have_one_spelling() {
        assert_eq!(RateKey::auth_login_ip("k").bucket, RateKey::AUTH_LOGIN_IP);
        assert_eq!(RateKey::auth_ip("k").bucket, RateKey::AUTH_IP);
        assert_ne!(RateKey::AUTH_LOGIN_IP, RateKey::AUTH_IP);
        assert_eq!(RateKey::auth_ip("k"), RateKey::new("auth_failure_ip", "k"));
    }

    #[test]
    fn the_default_backoff_is_on_and_the_address_bucket_is_wider() {
        let policy = FailureBackoff::default();
        assert_eq!(policy.validate(), Ok(()));
        assert!(policy.free > 0 && policy.base < policy.max);
        let address = policy.per_address();
        assert_eq!(address.free, policy.free * FailureBackoff::ADDRESS_FACTOR);
        assert_eq!(
            (address.window, address.base, address.max),
            (policy.window, policy.base, policy.max)
        );
        let huge = FailureBackoff {
            free: u32::MAX,
            ..policy
        };
        assert_eq!(huge.per_address().free, u32::MAX, "no overflow");
    }

    #[test]
    fn an_unusable_backoff_names_its_key() {
        let policy = FailureBackoff::default();
        for (broken, key) in [
            (
                FailureBackoff {
                    window: Duration::ZERO,
                    ..policy
                },
                "backoff_window",
            ),
            (
                FailureBackoff {
                    base: Duration::ZERO,
                    ..policy
                },
                "backoff_base",
            ),
            (
                FailureBackoff {
                    base: Duration::from_mins(10),
                    ..policy
                },
                "backoff_base",
            ),
        ] {
            assert!(broken.validate().unwrap_err().contains(key), "{key}");
        }
        assert_eq!(
            FailureBackoff {
                base: policy.max,
                ..policy
            }
            .validate(),
            Ok(()),
            "a base equal to the maximum is a constant block"
        );
    }

    #[test]
    fn keys_compare_by_bucket_and_key() {
        assert_eq!(RateKey::new("api", "t1"), RateKey::new("api", String::from("t1")));
        assert_ne!(RateKey::new("api", "t1"), RateKey::new("mail", "t1"));
    }
}
