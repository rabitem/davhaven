//! Configuration of the limiter.
//!
//! The `[plugin.memory]` table of the rate limiter. Callers name a bucket (`RateKey::bucket`, for example
//! `api`, `mcp_write`, `mail`) and a key inside it. Every bucket is one of two kinds:
//!
//! * a **rate bucket** (the default) allows `limit` units per `window`, refilled continuously (a token bucket in
//!   its exact form, the generic cell rate algorithm): request budgets of API and MCP tokens, mail rates;
//! * a **backoff bucket** (a bucket with a `backoff` table) counts failures: the first `limit` failures within
//!   `window` are free, every further one blocks the key for twice as long as the one before, from `backoff.base`
//!   up to `backoff.max`. Failures are forgotten after `window` without a new one, counted from the end of the
//!   last block. This is what authentication failures use: no hard lockout, but guessing becomes impractical.
//!
//! # The authentication failure buckets
//!
//! The two buckets of the port contract, `RateKey::AUTH_LOGIN_IP` and `RateKey::AUTH_IP`, are backoff buckets
//! **without any configuration here**: their policy is the `FailureBackoff` of the plugin context, which the server
//! fills from `[security.auth]` (`backoff_free`, `backoff_window`, `backoff_base`, `backoff_max`), and which is on
//! by default. That is the one source of the numbers. An entry for one of these two names under `buckets` overrides
//! the policy for that bucket (a deployment that wants different numbers for the per-address bucket than the
//! multiple of the per-login one says so there); the table is not needed otherwise.
//!
//! # The MCP budgets
//!
//! The tool calls of an MCP token are charged to two rate buckets, `mcp_read` for the tools that only read and
//! `mcp_write` for those that change calendars (`RateKey::MCP_READ`, `RateKey::MCP_WRITE`; PLAN 2.12), keyed per
//! token. Without an entry under `buckets` they allow [`MCP_READS_PER_MINUTE`] and [`MCP_WRITES_PER_MINUTE`] calls
//! per minute: a model in a loop must not flood a calendar, and reads must not starve writes. An entry for either
//! name tunes it.
//!
//! Buckets that need other numbers are listed under `buckets`; all others use `default`. The in-memory limiter is
//! per process: a deployment with several instances needs a shared limiter. The `noop` limiter takes no
//! configuration.

use std::collections::BTreeMap;
use std::time::Duration;

use davhaven_ports::{FailureBackoff, PluginError, RateKey};
use schemars::JsonSchema;
use serde::Deserialize;

/// The name of the plugin.
pub const PLUGIN: &str = "memory";

/// The tool calls per minute and token of the bucket `mcp_read` when the configuration names none.
pub const MCP_READS_PER_MINUTE: u32 = 120;

/// The tool calls per minute and token of the bucket `mcp_write` when the configuration names none.
pub const MCP_WRITES_PER_MINUTE: u32 = 30;

/// The exponential backoff of a failure bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackoffConfig {
    /// How long the first failure beyond the free ones blocks the key; every further failure doubles it.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub base: Duration,
    /// The longest block (the `Retry-After` a failing client is asked to wait).
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub max: Duration,
}

/// The allowance of one bucket: `limit` units per `window`, or, with `backoff`, `limit` free failures per
/// `window` and exponentially growing blocks after them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BucketConfig {
    /// The units allowed per window (rate bucket) or the failures that are free (backoff bucket).
    pub limit: u32,
    /// The length of the window (rate bucket) or the quiet time after which failures are forgotten (backoff
    /// bucket).
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub window: Duration,
    /// Makes this a backoff bucket.
    #[serde(default)]
    pub backoff: Option<BackoffConfig>,
}

/// A rate bucket of `limit` units per minute.
const fn per_minute(limit: u32) -> BucketConfig {
    BucketConfig {
        limit,
        window: Duration::from_mins(1),
        backoff: None,
    }
}

impl BucketConfig {
    /// The failure bucket of a [`FailureBackoff`] policy: `free` free failures per `window`, then blocks from
    /// `base` up to `max`.
    pub const fn failures(policy: &FailureBackoff) -> Self {
        Self {
            limit: policy.free,
            window: policy.window,
            backoff: Some(BackoffConfig {
                base: policy.base,
                max: policy.max,
            }),
        }
    }

    fn validate(&self, name: &str) -> Result<(), PluginError> {
        // A backoff bucket may have no free failures; a rate bucket that allows nothing is a mistake.
        if self.limit == 0 && self.backoff.is_none() {
            return Err(PluginError::invalid_config(
                PLUGIN,
                format!("the `limit` of {name} must be greater than zero"),
            ));
        }
        if self.window.is_zero() {
            return Err(PluginError::invalid_config(
                PLUGIN,
                format!("the `window` of {name} must be greater than zero"),
            ));
        }
        if let Some(backoff) = &self.backoff {
            if backoff.base.is_zero() {
                return Err(PluginError::invalid_config(
                    PLUGIN,
                    format!("the `backoff.base` of {name} must be greater than zero"),
                ));
            }
            if backoff.base > backoff.max {
                return Err(PluginError::invalid_config(
                    PLUGIN,
                    format!("the `backoff.base` of {name} must not exceed `backoff.max`"),
                ));
            }
        }
        Ok(())
    }
}

/// The `[plugin.memory]` table of the rate limiter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryRateLimitConfig {
    /// The allowance of buckets that are not listed in `buckets`.
    pub default: BucketConfig,
    /// Allowances of named buckets. The tool calls of MCP tokens are charged per token to `mcp_read` (default 120 per
    /// minute) and `mcp_write` (default 30 per minute); an entry with these names tunes them.
    pub buckets: BTreeMap<String, BucketConfig>,
    /// The most keys the limiter tracks; the least recently used are evicted first.
    pub max_keys: usize,
    /// The policy of the two authentication failure buckets. Not a key of the table: the plugin takes it from the
    /// plugin context (`[security.auth]`), see the module documentation.
    #[serde(skip)]
    #[schemars(skip)]
    pub failure_backoff: FailureBackoff,
}

impl Default for MemoryRateLimitConfig {
    fn default() -> Self {
        Self {
            default: BucketConfig {
                limit: 600,
                window: Duration::from_mins(1),
                backoff: None,
            },
            buckets: BTreeMap::new(),
            max_keys: 100_000,
            failure_backoff: FailureBackoff::default(),
        }
    }
}

impl MemoryRateLimitConfig {
    /// Checks every allowance and the key cap.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the offending bucket or key.
    pub fn validate(&self) -> Result<(), PluginError> {
        self.default.validate("`default`")?;
        for (name, bucket) in &self.buckets {
            bucket.validate(&format!("bucket `{name}`"))?;
        }
        self.failure_backoff
            .validate()
            .map_err(|message| PluginError::invalid_config(PLUGIN, message))?;
        if self.max_keys == 0 {
            return Err(PluginError::invalid_config(
                PLUGIN,
                "`max_keys` must be greater than zero",
            ));
        }
        Ok(())
    }

    /// The allowance of a bucket: the entry of `buckets` if there is one, else, for the two authentication
    /// failure buckets, the failure backoff of the deployment (per address with
    /// [`FailureBackoff::ADDRESS_FACTOR`] times the free failures), for the two MCP budgets
    /// [`MCP_READS_PER_MINUTE`] and [`MCP_WRITES_PER_MINUTE`], else `default`.
    pub fn bucket(&self, name: &str) -> BucketConfig {
        if let Some(configured) = self.buckets.get(name) {
            return *configured;
        }
        match name {
            RateKey::AUTH_LOGIN_IP => BucketConfig::failures(&self.failure_backoff),
            RateKey::AUTH_IP => BucketConfig::failures(&self.failure_backoff.per_address()),
            RateKey::MCP_READ => per_minute(MCP_READS_PER_MINUTE),
            RateKey::MCP_WRITE => per_minute(MCP_WRITES_PER_MINUTE),
            _ => self.default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: serde_json::Value) -> MemoryRateLimitConfig {
        davhaven_ports::parse_config(PLUGIN, value).unwrap()
    }

    #[test]
    fn defaults_apply_to_unlisted_buckets() {
        let config = parse(serde_json::json!({}));
        config.validate().unwrap();
        assert_eq!(config.bucket("anything").limit, 600);
        assert_eq!(config.bucket("anything").window, Duration::from_mins(1));
        let tuned = parse(serde_json::json!({
            "buckets": {"auth_ip": {"limit": 20, "window": "1m"}},
            "max_keys": 1000,
        }));
        tuned.validate().unwrap();
        assert_eq!(tuned.bucket("auth_ip").limit, 20);
        assert_eq!(tuned.bucket("api").limit, 600);
        assert_eq!(tuned.max_keys, 1000);
    }

    #[test]
    fn the_mcp_budgets_have_their_own_defaults_and_can_be_tuned() {
        let config = parse(serde_json::json!({}));
        config.validate().unwrap();
        let read = config.bucket(RateKey::MCP_READ);
        let write = config.bucket(RateKey::MCP_WRITE);
        assert_eq!((read.limit, read.window), (120, Duration::from_mins(1)));
        assert_eq!((write.limit, write.window), (30, Duration::from_mins(1)));
        assert!(read.backoff.is_none() && write.backoff.is_none(), "rate buckets");
        let tuned = parse(serde_json::json!({
            "default": {"limit": 5, "window": "1m"},
            "buckets": {"mcp_write": {"limit": 2, "window": "30s"}},
        }));
        assert_eq!(tuned.bucket(RateKey::MCP_WRITE).limit, 2);
        assert_eq!(
            tuned.bucket(RateKey::MCP_READ).limit,
            120,
            "the other budget keeps its default"
        );
        assert_eq!(tuned.bucket("api").limit, 5);
    }

    #[test]
    fn backoff_buckets_are_declared_with_a_backoff_table() {
        let config = parse(serde_json::json!({
            "buckets": {"auth_failure": {"limit": 3, "window": "15m", "backoff": {"base": "1s", "max": "5m"}}},
        }));
        config.validate().unwrap();
        let bucket = config.bucket("auth_failure");
        assert_eq!(bucket.limit, 3);
        assert_eq!(
            bucket.backoff,
            Some(BackoffConfig {
                base: Duration::from_secs(1),
                max: Duration::from_mins(5)
            })
        );
        assert_eq!(config.bucket("api").backoff, None);
        for (value, expected) in [
            (
                serde_json::json!({"buckets": {"x": {"limit": 1, "window": "1m", "backoff": {"base": "0s", "max": "1m"}}}}),
                "backoff.base",
            ),
            (
                serde_json::json!({"buckets": {"x": {"limit": 1, "window": "1m", "backoff": {"base": "2m", "max": "1m"}}}}),
                "must not exceed",
            ),
        ] {
            let error = parse(value).validate().unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
        assert!(
            davhaven_ports::parse_config::<MemoryRateLimitConfig>(
                PLUGIN,
                serde_json::json!({"buckets": {"x": {"limit": 1, "window": "1m", "backoff": {"base": "1s"}}}})
            )
            .is_err(),
            "a backoff needs base and max"
        );
    }

    #[test]
    fn the_authentication_buckets_back_off_without_any_configuration() {
        let config = parse(serde_json::json!({}));
        config.validate().unwrap();
        let policy = FailureBackoff::default();
        let login = config.bucket(RateKey::AUTH_LOGIN_IP);
        assert_eq!(login, BucketConfig::failures(&policy));
        assert_eq!(login.limit, policy.free);
        assert_eq!(
            login.backoff,
            Some(BackoffConfig {
                base: policy.base,
                max: policy.max
            })
        );
        let address = config.bucket(RateKey::AUTH_IP);
        assert_eq!(address.limit, policy.free * FailureBackoff::ADDRESS_FACTOR);
        assert_eq!(address.window, policy.window);
        assert!(address.backoff.is_some());
        assert_eq!(config.bucket("api").backoff, None, "other buckets are rate buckets");
    }

    #[test]
    fn tuning_another_bucket_does_not_remove_the_authentication_backoff() {
        let config = parse(serde_json::json!({
            "buckets": {"api": {"limit": 10, "window": "1m"}},
            "default": {"limit": 5, "window": "1m"},
        }));
        assert!(config.bucket(RateKey::AUTH_LOGIN_IP).backoff.is_some());
        assert!(config.bucket(RateKey::AUTH_IP).backoff.is_some());
        assert_eq!(config.bucket("api").limit, 10);
    }

    #[test]
    fn the_policy_of_the_deployment_sets_the_numbers_and_an_entry_overrides_one_bucket() {
        let mut config = parse(serde_json::json!({
            "buckets": {"auth_failure_ip": {"limit": 99, "window": "1h", "backoff": {"base": "2s", "max": "10m"}}},
        }));
        config.failure_backoff = FailureBackoff {
            free: 2,
            window: Duration::from_mins(10),
            base: Duration::from_secs(3),
            max: Duration::from_mins(2),
        };
        config.validate().unwrap();
        let login = config.bucket(RateKey::AUTH_LOGIN_IP);
        assert_eq!((login.limit, login.window), (2, Duration::from_mins(10)));
        assert_eq!(
            login.backoff,
            Some(BackoffConfig {
                base: Duration::from_secs(3),
                max: Duration::from_mins(2)
            })
        );
        let address = config.bucket(RateKey::AUTH_IP);
        assert_eq!(address.limit, 99, "the entry wins");
        assert_eq!(address.window, Duration::from_hours(1));
        config.failure_backoff.base = Duration::ZERO;
        assert!(config.validate().unwrap_err().to_string().contains("backoff_base"));
    }

    #[test]
    fn a_backoff_bucket_may_have_no_free_failures_but_a_rate_bucket_must_allow_something() {
        let strict = parse(serde_json::json!({
            "buckets": {"x": {"limit": 0, "window": "1m", "backoff": {"base": "1s", "max": "1m"}}},
        }));
        strict.validate().unwrap();
        let broken = parse(serde_json::json!({"buckets": {"x": {"limit": 0, "window": "1m"}}}));
        assert!(broken.validate().unwrap_err().to_string().contains("limit"));
    }

    #[test]
    fn typos_and_bad_values_are_refused() {
        assert!(
            davhaven_ports::parse_config::<MemoryRateLimitConfig>(PLUGIN, serde_json::json!({"maxkeys": 1})).is_err()
        );
        assert!(
            davhaven_ports::parse_config::<MemoryRateLimitConfig>(
                PLUGIN,
                serde_json::json!({"buckets": {"x": {"limit": 1}}})
            )
            .is_err(),
            "a bucket needs both limit and window"
        );
        for (value, expected) in [
            (serde_json::json!({"default": {"limit": 0, "window": "1m"}}), "default"),
            (
                serde_json::json!({"buckets": {"api": {"limit": 5, "window": "0s"}}}),
                "bucket `api`",
            ),
            (serde_json::json!({"max_keys": 0}), "max_keys"),
        ] {
            let error = parse(value).validate().unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }
}
