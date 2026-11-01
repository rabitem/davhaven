//! Configuration of the in-memory adapter.
//!
//! The adapter has nothing to configure: it holds the data of one process and forgets it on exit. The empty
//! struct exists so the plugin has a schema like every other adapter and so misspelled keys under
//! `[plugin.memory]` still fail at startup. Production mode refuses the adapter altogether.

use schemars::JsonSchema;
use serde::Deserialize;

/// The name of the plugin.
pub const PLUGIN: &str = "memory";

/// The `[plugin.memory]` table of the store: no keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryStoreConfig {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_an_empty_table_and_refuses_keys() {
        let config: MemoryStoreConfig = davhaven_ports::parse_config(PLUGIN, serde_json::json!({})).unwrap();
        assert_eq!(config, MemoryStoreConfig::default());
        let null: MemoryStoreConfig = davhaven_ports::parse_config(PLUGIN, serde_json::Value::Null).unwrap();
        assert_eq!(null, config);
        let error =
            davhaven_ports::parse_config::<MemoryStoreConfig>(PLUGIN, serde_json::json!({"size": 1})).unwrap_err();
        assert!(error.to_string().contains("size"), "{error}");
    }
}
