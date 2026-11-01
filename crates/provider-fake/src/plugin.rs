//! Registration of the provider in the plugin registry.
//!
//! One plugin of the `provider` kind: `fake`. It is configured by `[plugin.provider.fake]`, which has no keys, and
//! production mode refuses it: a deployment that selected it would offer people a provider that connects to nothing.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use davhaven_ports::{
    Built, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind, Provider, parse_config,
};
use schemars::Schema;

use crate::config::FakeConfig;
use crate::provider::{FakeProvider, NAME};

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn Provider>, PluginError>> + Send>>;

/// Registers the `fake` provider.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has it already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::PROVIDER,
        PluginDescriptor::new(
            NAME,
            "A scriptable calendar provider with its own remote world: OAuth with PKCE, expiring tokens, calendars and \
             events. For tests of the sync engine; production mode refuses it.",
            schema,
            build,
        )
        .with_refused_in_production()
        .with_check(check_config),
    )
}

fn schema() -> Schema {
    schemars::schema_for!(FakeConfig)
}

/// The one reading of the table that `build` and the check of `davhaven config check` share.
fn config(table: serde_json::Value) -> Result<FakeConfig, PluginError> {
    parse_config(NAME, table)
}

/// The check of `davhaven config check`: the table has no keys, and a typo in it names the key.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_config(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    config(check.table.clone())?;
    Ok(Vec::new())
}

fn build(context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let FakeConfig {} = config(table)?;
        let provider: Arc<dyn Provider> = Arc::new(FakeProvider::new(Arc::clone(&context.clock)));
        Ok(Built::new(provider))
    })
}

#[cfg(test)]
mod tests {
    use davhaven_ports::{ConfigTree, RunMode};

    use super::*;

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        registry
    }

    #[test]
    fn the_plugin_registers_once_under_the_provider_kind() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::PROVIDER), vec!["fake"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        assert!(registry.refused_in_production("provider", "fake"));
        let schemas = registry.schemas();
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0].kind, "provider");
        assert_eq!(
            schemas[0].dedicated_table, None,
            "it is configured by [plugin.provider.fake] alone"
        );
    }

    #[tokio::test]
    async fn the_plugin_builds_in_development_and_refuses_unknown_keys() {
        let registry = registry();
        let context = PluginContext::for_tests();
        let built = registry
            .build_set(PortKind::PROVIDER, &["fake"], &context, &ConfigTree::new())
            .await
            .unwrap();
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].port.name(), "fake");
        assert!(built[0].port.enabled());
        let typo = ConfigTree::new().with("fake", serde_json::json!({"enabled": true}));
        let error = registry
            .build_set(PortKind::PROVIDER, &["fake"], &context, &typo)
            .await
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("enabled"), "{error}");
    }

    #[tokio::test]
    async fn production_refuses_the_fake() {
        let registry = registry();
        let mut context = PluginContext::for_tests();
        context.mode = RunMode::Production;
        let error = registry
            .build_set(PortKind::PROVIDER, &["fake"], &context, &ConfigTree::new())
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(error, PluginError::RefusedInProduction { .. }), "{error}");
    }
}
