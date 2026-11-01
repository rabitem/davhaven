//! Configuration of the authenticator, its cache and the authentication backoff.
//!
//! The `[security.auth]` table (PLAN 2.6). Verified credentials are remembered for `cache_ttl` keyed by an HMAC of
//! the presented secret (see [`crate::cache`]); `last_used_at` is flushed at most every `last_used_flush`.
//!
//! # The backoff
//!
//! There is no hard lockout: failed authentications per (login, client address) and per client address back off
//! exponentially. The four `backoff_*` keys are the **one place** where a deployment states that policy. The
//! authenticator does not count failures (the application's `AuthService` does, in the rate limiter, buckets
//! `RateKey::AUTH_LOGIN_IP` and `RateKey::AUTH_IP`); [`AuthConfig::failure_backoff`] turns the keys into the
//! `FailureBackoff` of the port, which the server puts into the `PluginContext` before it builds the rate limiter,
//! and the limiter builds its two failure buckets from it. So `Retry-After` of a 429 for failed logins is bounded by
//! `backoff_max`, the first `backoff_free` failures of a (login, address) pair cost nothing (the per-address bucket
//! allows four times as many), and without any configuration the backoff is on with the defaults below.

use std::time::Duration;

use davhaven_ports::{FailureBackoff, PluginError};
use schemars::JsonSchema;
use serde::Deserialize;

/// The name of the plugin.
pub const PLUGIN: &str = "local";

/// The `[security.auth]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// How long a successful verification of a secret is remembered; the state of the credential (revoked,
    /// expired, suspended) is read on every use regardless.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub cache_ttl: Duration,
    /// The shortest interval between two writes of `last_used_at` of one credential.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub last_used_flush: Duration,
    /// How many failed authentications of one (login, client address) pair within `backoff_window` are free; the
    /// per-address bucket allows four times as many.
    pub backoff_free: u32,
    /// The quiet time after which the failures of a key are forgotten.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub backoff_window: Duration,
    /// The block after the first failure beyond the free ones; it doubles with every further failure of the same
    /// key.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub backoff_base: Duration,
    /// The longest block (`Retry-After`) a failing client is asked to wait.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub backoff_max: Duration,
    /// The most verified credentials the cache holds; when it is full, expired entries and then the least recently
    /// used ones (down to about nine tenths of this number) are dropped.
    pub cache_max_entries: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        let backoff = FailureBackoff::default();
        Self {
            cache_ttl: Duration::from_mins(5),
            last_used_flush: Duration::from_mins(15),
            backoff_free: backoff.free,
            backoff_window: backoff.window,
            backoff_base: backoff.base,
            backoff_max: backoff.max,
            cache_max_entries: 10_000,
        }
    }
}

impl AuthConfig {
    /// Checks that every interval is positive and the backoff is ordered.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the offending key.
    pub fn validate(&self) -> Result<(), PluginError> {
        let invalid = |message: &str| PluginError::invalid_config(PLUGIN, message);
        if self.cache_ttl.is_zero() {
            return Err(invalid("`cache_ttl` must be greater than zero"));
        }
        if self.last_used_flush.is_zero() {
            return Err(invalid("`last_used_flush` must be greater than zero"));
        }
        self.failure_backoff()
            .validate()
            .map_err(|message| PluginError::invalid_config(PLUGIN, message))?;
        if self.cache_max_entries == 0 {
            return Err(invalid("`cache_max_entries` must be greater than zero"));
        }
        Ok(())
    }

    /// The failure backoff of the deployment, as the rate limiter takes it (`PluginContext::with_failure_backoff`).
    pub const fn failure_backoff(&self) -> FailureBackoff {
        FailureBackoff {
            free: self.backoff_free,
            window: self.backoff_window,
            base: self.backoff_base,
            max: self.backoff_max,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: serde_json::Value) -> AuthConfig {
        davhaven_ports::parse_config(PLUGIN, value).unwrap()
    }

    #[test]
    fn defaults_are_the_plan_values() {
        let config = parse(serde_json::json!({}));
        assert_eq!(config.cache_ttl, Duration::from_mins(5));
        assert_eq!(config.last_used_flush, Duration::from_mins(15));
        assert_eq!(config, AuthConfig::default());
        config.validate().unwrap();
    }

    #[test]
    fn durations_parse_in_human_form_and_typos_fail() {
        let config = parse(serde_json::json!({"cache_ttl": "30s", "backoff_base": "500ms", "backoff_max": "2m"}));
        assert_eq!(config.cache_ttl, Duration::from_secs(30));
        assert_eq!(config.backoff_base, Duration::from_millis(500));
        assert_eq!(config.backoff_max, Duration::from_mins(2));
        assert!(davhaven_ports::parse_config::<AuthConfig>(PLUGIN, serde_json::json!({"cache_ttl": "soon"})).is_err());
        assert!(davhaven_ports::parse_config::<AuthConfig>(PLUGIN, serde_json::json!({"cachettl": "1s"})).is_err());
    }

    #[test]
    fn the_backoff_keys_are_what_the_rate_limiter_is_given() {
        let defaults = AuthConfig::default();
        assert_eq!(
            defaults.failure_backoff(),
            FailureBackoff::default(),
            "the documented defaults are the defaults of the port: one source of the numbers"
        );
        let config = parse(serde_json::json!({
            "backoff_free": 2,
            "backoff_window": "10m",
            "backoff_base": "3s",
            "backoff_max": "2m",
        }));
        config.validate().unwrap();
        assert_eq!(
            config.failure_backoff(),
            FailureBackoff {
                free: 2,
                window: Duration::from_mins(10),
                base: Duration::from_secs(3),
                max: Duration::from_mins(2),
            }
        );
    }

    #[test]
    fn validation_names_the_key() {
        for (value, key) in [
            (serde_json::json!({"cache_ttl": "0s"}), "cache_ttl"),
            (serde_json::json!({"last_used_flush": "0s"}), "last_used_flush"),
            (serde_json::json!({"backoff_base": "0s"}), "backoff_base"),
            (serde_json::json!({"backoff_base": "10m"}), "backoff_base"),
            (serde_json::json!({"backoff_window": "0s"}), "backoff_window"),
            (serde_json::json!({"cache_max_entries": 0}), "cache_max_entries"),
        ] {
            let error = parse(value).validate().unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }
}
