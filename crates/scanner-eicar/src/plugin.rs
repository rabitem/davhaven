//! Registration of the scanner in the plugin registry.
//!
//! One plugin of the `content_scanner` kind: `eicar`, which production mode refuses because it would make uploads look
//! scanned (see the crate documentation).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use davhaven_ports::{
    Built, ContentScanner, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind,
    parse_config,
};
use schemars::Schema;

use crate::config::{EicarConfig, PLUGIN};
use crate::scanner::EicarScanner;

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn ContentScanner>, PluginError>> + Send>>;

/// Registers the `eicar` scanner.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has it already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::CONTENT_SCANNER,
        PluginDescriptor::new(
            PLUGIN,
            "Reports the EICAR anti-virus test string as infected and everything else as clean. A fake for tests of \
             the scanning path; it is never selected by default and production mode refuses it.",
            schema,
            build,
        )
        // A fake that reports everything but a test string as clean: a production deployment that selected it would
        // believe its uploads are scanned.
        .with_refused_in_production()
        .with_check(check_config),
    )
}

fn schema() -> Schema {
    schemars::schema_for!(EicarConfig)
}

/// The one reading of the table that `build` and the check of `davhaven config check` share.
fn config(table: serde_json::Value) -> Result<EicarConfig, PluginError> {
    parse_config(PLUGIN, table)
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

fn build(_context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let EicarConfig {} = config(table)?;
        let scanner: Arc<dyn ContentScanner> = Arc::new(EicarScanner);
        Ok(Built::new(scanner))
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
    fn the_plugin_registers_once_under_the_content_scanner_kind() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::CONTENT_SCANNER), vec!["eicar"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        let schemas = registry.schemas();
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0].kind, "content_scanner");
        assert_eq!(
            schemas[0].dedicated_table, None,
            "it is configured by [plugin.content_scanner.eicar] alone"
        );
    }

    #[tokio::test]
    async fn the_plugin_builds_and_refuses_unknown_keys() {
        let registry = registry();
        let context = PluginContext::for_tests();
        let built = registry
            .build_set(PortKind::CONTENT_SCANNER, &["eicar"], &context, &ConfigTree::new())
            .await
            .unwrap();
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].port.name(), "eicar");
        let typo = ConfigTree::new().with("eicar", serde_json::json!({"strict": true}));
        let error = registry
            .build_set(PortKind::CONTENT_SCANNER, &["eicar"], &context, &typo)
            .await
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("strict"), "{error}");
    }

    #[tokio::test]
    async fn the_scanner_is_refused_in_production() {
        let production = PluginContext {
            mode: RunMode::Production,
            ..PluginContext::for_tests()
        };
        let error = registry()
            .build_set(PortKind::CONTENT_SCANNER, &["eicar"], &production, &ConfigTree::new())
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(error, PluginError::RefusedInProduction { .. }), "{error}");
        // The descriptor is the one place that says so: `config check` reads the flag, and nothing else lists the plugin.
        assert!(registry().refused_in_production("content_scanner", "eicar"));
    }

    #[test]
    fn the_check_accepts_the_defaults_and_names_a_typo() {
        let registry = registry();
        for table in [serde_json::Value::Null, serde_json::json!({})] {
            let verdict = registry
                .check_table("content_scanner", "eicar", &table, RunMode::Dev)
                .expect("the plugin has a check")
                .unwrap();
            assert!(verdict.is_empty(), "{verdict:?}");
        }
        let error = registry
            .check_table(
                "content_scanner",
                "eicar",
                &serde_json::json!({"strict": true}),
                RunMode::Dev,
            )
            .expect("the plugin has a check")
            .unwrap_err()
            .to_string();
        assert!(error.contains("strict") && error.contains("eicar"), "{error}");
    }
}
