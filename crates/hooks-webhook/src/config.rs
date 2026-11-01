//! Configuration of webhook delivery.
//!
//! The `[webhooks]` table (PLAN 2.11). Delivery is at-least-once with exponential backoff until `retry_window`
//! has passed, after which the delivery is dead (an operator can redeliver it). A subscription whose deliveries
//! fail `max_consecutive_failures` times in a row is disabled automatically and a `webhook.disabled` event is
//! emitted.

use std::time::Duration;

use davhaven_ports::PluginError;
use schemars::JsonSchema;
use serde::Deserialize;

/// The name of the plugin.
pub const PLUGIN: &str = "webhook";

/// The `[webhooks]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhooksConfig {
    /// After this many failed deliveries in a row the subscription is disabled.
    pub max_consecutive_failures: u32,
    /// How long a delivery is retried before it goes dead.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub retry_window: Duration,
}

impl Default for WebhooksConfig {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 20,
            retry_window: Duration::from_hours(24),
        }
    }
}

impl WebhooksConfig {
    /// Checks that both values are positive.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the offending key.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.max_consecutive_failures == 0 {
            return Err(PluginError::invalid_config(
                PLUGIN,
                "`max_consecutive_failures` must be greater than zero",
            ));
        }
        if self.retry_window.is_zero() {
            return Err(PluginError::invalid_config(
                PLUGIN,
                "`retry_window` must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_plan_values() {
        let config: WebhooksConfig = davhaven_ports::parse_config(PLUGIN, serde_json::json!({})).unwrap();
        assert_eq!(config.retry_window, Duration::from_hours(24));
        assert_eq!(config.max_consecutive_failures, 20);
        config.validate().unwrap();
        let tuned: WebhooksConfig = davhaven_ports::parse_config(
            PLUGIN,
            serde_json::json!({"retry_window": "6h", "max_consecutive_failures": 5}),
        )
        .unwrap();
        assert_eq!(tuned.retry_window, Duration::from_hours(6));
        assert!(davhaven_ports::parse_config::<WebhooksConfig>(PLUGIN, serde_json::json!({"retry": "1h"})).is_err());
    }

    #[test]
    fn validation_names_the_key() {
        let none = WebhooksConfig {
            max_consecutive_failures: 0,
            ..WebhooksConfig::default()
        };
        assert!(
            none.validate()
                .unwrap_err()
                .to_string()
                .contains("max_consecutive_failures")
        );
        let instant = WebhooksConfig {
            retry_window: Duration::ZERO,
            ..WebhooksConfig::default()
        };
        assert!(instant.validate().unwrap_err().to_string().contains("retry_window"));
    }
}
