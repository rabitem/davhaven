//! Registration of the adapter in the plugin registry.
//!
//! One plugin of the `mail_transport` kind: `memory`, the capturing transport for development and tests. It is
//! refused in production mode (`ENGINEERING_RULES` R3, PLAN 2.3).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use davhaven_ports::{
    Built, MailTransport, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind,
    parse_config,
};
use schemars::Schema;

use crate::config::{MemoryMailConfig, PLUGIN};
use crate::transport::MemoryMailTransport;

/// Registers the `memory` mail transport.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has it already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::MAIL_TRANSPORT,
        PluginDescriptor::new(
            PLUGIN,
            "Delivers nothing: keeps every mail with its RFC 5322 bytes in memory. For development and tests; refused \
             in production mode.",
            schema,
            build,
        )
        // It delivers nothing: the mails would be lost at the next restart.
        .with_refused_in_production()
        .with_check(check_config),
    )
}

/// The table of the transport as a validated configuration: the one reading that `build` and the check of
/// `davhaven config check` share, so that the check says what `serve` will say.
fn config(table: serde_json::Value) -> Result<MemoryMailConfig, PluginError> {
    let config: MemoryMailConfig = parse_config(PLUGIN, table)?;
    config.validate()?;
    Ok(config)
}

/// The check of `davhaven config check`: the table parses and validates as `build` would have it.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_config(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    config(check.table.clone())?;
    Ok(Vec::new())
}

fn schema() -> Schema {
    schemars::schema_for!(MemoryMailConfig)
}

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn MailTransport>, PluginError>> + Send>>;

fn build(context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let config = config(table)?;
        let transport: Arc<dyn MailTransport> = Arc::new(MemoryMailTransport::new(Arc::clone(&context.clock), &config));
        Ok(Built::new(transport))
    })
}

#[cfg(test)]
mod tests {
    use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
    use davhaven_ports::{ConfigTree, RunMode};
    use serde_json::json;

    use super::*;

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        registry
    }

    fn production() -> PluginContext {
        PluginContext::new(
            Arc::new(ManualClock::default()),
            Arc::new(SeqIds::new()),
            Arc::new(FixedKeyRing::default()),
            Arc::new(PlainSealer),
            Arc::new(FixedHasher::default()),
            RunMode::Production,
        )
    }

    #[test]
    fn the_plugin_is_registered_once_with_a_schema() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::MAIL_TRANSPORT), vec!["memory"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        let schemas = registry.schemas();
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0].kind, "mail_transport");
        assert_eq!(
            schemas[0].schema.as_value()["properties"]["max_messages"]["type"],
            "integer"
        );
    }

    #[tokio::test]
    async fn the_transport_builds_in_dev_mode_and_is_refused_in_production() {
        let registry = registry();
        let built = registry
            .build_single(
                PortKind::MAIL_TRANSPORT,
                "memory",
                &PluginContext::for_tests(),
                &ConfigTree::new(),
            )
            .await
            .unwrap();
        assert!(built.workers.is_empty() && built.lifecycle.is_none());
        let refused = registry
            .build_single(PortKind::MAIL_TRANSPORT, "memory", &production(), &ConfigTree::new())
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(refused, PluginError::RefusedInProduction { .. }), "{refused}");
        assert!(registry.refused_in_production("mail_transport", "memory"));
    }

    #[tokio::test]
    async fn invalid_configuration_names_the_key_and_the_check_says_the_same() {
        let registry = registry();
        for (config, key) in [(json!({"max_messages": 0}), "max_messages"), (json!({"max": 5}), "max")] {
            let tree = ConfigTree::new().with("memory", config.clone());
            let error = registry
                .build_single(PortKind::MAIL_TRANSPORT, "memory", &PluginContext::for_tests(), &tree)
                .await
                .map(|_| ())
                .unwrap_err()
                .to_string();
            assert!(error.contains(key), "{key}: {error}");
            let checked = registry
                .check_table("mail_transport", "memory", &config, RunMode::Dev)
                .expect("the transport has a check of its own")
                .unwrap_err()
                .to_string();
            assert_eq!(checked, error, "{key}");
        }
    }

    #[test]
    fn the_check_accepts_the_defaults() {
        for table in [serde_json::Value::Null, json!({}), json!({"max_messages": 5})] {
            let verdict = registry()
                .check_table("mail_transport", "memory", &table, RunMode::Dev)
                .expect("the transport has a check of its own")
                .unwrap();
            assert!(verdict.is_empty(), "{table}: {verdict:?}");
        }
    }
}
