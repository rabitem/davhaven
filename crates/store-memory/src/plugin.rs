//! Registration of the adapter in the plugin registry.
//!
//! The adapter registers as the `memory` plugin of the `database` kind. Production mode refuses it: the data of a
//! process that forgets everything on exit is for development, tests and consumer test images only.

use std::sync::Arc;

use davhaven_ports::{
    Built, Database, Lifecycle, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind,
    parse_config,
};
use futures::future::BoxFuture;

use crate::config::{MemoryStoreConfig, PLUGIN};
use crate::database::MemoryDatabase;

/// The descriptor of the plugin.
pub const DESCRIPTOR: PluginDescriptor<dyn Database> = PluginDescriptor::new(
    PLUGIN,
    "In-memory storage with real transactions, for development and tests (refused in production mode).",
    config_schema,
    build,
)
// The data of a process that forgets everything on exit would be lost at the next restart.
.with_refused_in_production()
.with_check(check_config);

/// The table of the store as a configuration: the one reading that `build` and the check of `davhaven config check`
/// share, so that the check says what `serve` will say.
fn config(table: serde_json::Value) -> Result<MemoryStoreConfig, PluginError> {
    parse_config(PLUGIN, table)
}

/// The check of `davhaven config check`: the table parses as `build` would have it.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] for a key the plugin does not know.
fn check_config(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    config(check.table.clone())?;
    Ok(Vec::new())
}

fn config_schema() -> schemars::Schema {
    schemars::schema_for!(MemoryStoreConfig)
}

/// Registers the adapter under `database`.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the adapter was registered before.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(PortKind::DATABASE, DESCRIPTOR)
}

fn build(ctx: PluginContext, table: serde_json::Value) -> BoxFuture<'static, Result<Built<dyn Database>, PluginError>> {
    Box::pin(async move {
        let MemoryStoreConfig {} = config(table)?;
        let database = Arc::new(MemoryDatabase::new(Arc::clone(&ctx.clock), Arc::clone(&ctx.ids)));
        let shared = Arc::clone(&database);
        let lifecycle: Arc<dyn Lifecycle> = shared;
        let port: Arc<dyn Database> = database;
        Ok(Built::new(port).with_lifecycle(lifecycle))
    })
}

#[cfg(test)]
mod tests {
    use davhaven_ports::{ConfigTree, RunMode};

    use super::*;

    #[test]
    fn the_plugin_registers_once_under_the_database_kind() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.names(PortKind::DATABASE), vec!["memory"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
    }

    #[tokio::test]
    async fn the_plugin_builds_in_dev_mode_and_is_refused_in_production() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        let dev = PluginContext::for_tests();
        let built = registry
            .build_single(PortKind::DATABASE, PLUGIN, &dev, &ConfigTree::new())
            .await
            .unwrap();
        assert!(built.lifecycle.is_some());

        let mut production = PluginContext::for_tests();
        production.mode = RunMode::Production;
        let error = registry
            .build_single(PortKind::DATABASE, PLUGIN, &production, &ConfigTree::new())
            .await
            .unwrap_err();
        assert!(matches!(error, PluginError::RefusedInProduction { .. }), "{error}");
        assert!(registry.refused_in_production("database", PLUGIN));
    }

    #[test]
    fn the_check_accepts_the_defaults_and_names_a_typo() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        for table in [serde_json::Value::Null, serde_json::json!({})] {
            let verdict = registry
                .check_table("database", PLUGIN, &table, RunMode::Dev)
                .expect("the store has a check of its own")
                .unwrap();
            assert!(verdict.is_empty(), "{verdict:?}");
        }
        let error = registry
            .check_table("database", PLUGIN, &serde_json::json!({"size": 1}), RunMode::Dev)
            .expect("the store has a check of its own")
            .unwrap_err()
            .to_string();
        assert!(error.contains("size"), "{error}");
    }

    #[tokio::test]
    async fn unknown_keys_are_refused() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        let tree = ConfigTree::new().with(PLUGIN, serde_json::json!({"size": 1}));
        let error = registry
            .build_single(PortKind::DATABASE, PLUGIN, &PluginContext::for_tests(), &tree)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("size"), "{error}");
    }
}
