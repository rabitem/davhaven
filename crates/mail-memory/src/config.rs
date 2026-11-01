//! Configuration of the capturing mail transport.

use davhaven_ports::PluginError;
use schemars::JsonSchema;
use serde::Deserialize;

/// The name of the plugin.
pub const PLUGIN: &str = "memory";

/// The `[plugin.memory]` table of the mail transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryMailConfig {
    /// The most mails the transport keeps; the oldest are dropped first (the capture is bounded, like every queue
    /// of the server).
    pub max_messages: usize,
}

impl Default for MemoryMailConfig {
    fn default() -> Self {
        Self { max_messages: 10_000 }
    }
}

impl MemoryMailConfig {
    /// Checks that the capture can hold at least one mail.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for `max_messages = 0`.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.max_messages == 0 {
            return Err(PluginError::invalid_config(
                PLUGIN,
                "`max_messages` must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_validation() {
        let config: MemoryMailConfig = davhaven_ports::parse_config(PLUGIN, serde_json::json!({})).unwrap();
        assert_eq!(config.max_messages, 10_000);
        config.validate().unwrap();
        let empty = MemoryMailConfig { max_messages: 0 };
        assert!(empty.validate().unwrap_err().to_string().contains("max_messages"));
        assert!(davhaven_ports::parse_config::<MemoryMailConfig>(PLUGIN, serde_json::json!({"max": 1})).is_err());
    }
}
