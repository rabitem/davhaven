//! Registration of the provider in the plugin registry.
//!
//! One plugin of the `provider` kind: `google`, configured by `[providers.google]` (or `[plugin.provider.google]`), which is
//! the table the plan gives it. It is built when `plugins.providers` selects it, and it is **off unless the table says
//! `enabled = true`**: a provider that is selected and off answers 409 `feature-not-enabled` and runs no sync. The client
//! secret is read from `client_secret_file` when the provider is enabled, by the check of `davhaven config check` as well as
//! by the build, so a missing file is found before the first request.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use davhaven_ports::{
    Built, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind, Provider, parse_config,
};
use schemars::Schema;

use crate::config::{GoogleConfig, PLUGIN};
use crate::provider::GoogleProvider;

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn Provider>, PluginError>> + Send>>;

/// Registers the `google` provider.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has it already, and [`PluginError::DuplicateTable`] when another plugin
/// names `providers.google`.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::PROVIDER,
        PluginDescriptor::new(
            PLUGIN,
            "Google Calendar: OAuth with PKCE and a pull-only import of the primary calendar into a mirror calendar. Off \
             unless `enabled = true`; needs the OAuth client of a Google Cloud project.",
            schema,
            build,
        )
        .with_dedicated_table("providers.google")
        .with_check(check_config),
    )
}

fn schema() -> Schema {
    schemars::schema_for!(GoogleConfig)
}

/// The one reading of the table that `build` and the check of `davhaven config check` share.
fn config(table: serde_json::Value) -> Result<GoogleConfig, PluginError> {
    let config: GoogleConfig = parse_config(PLUGIN, table)?;
    config.validate()?;
    Ok(config)
}

/// The check of `davhaven config check`: the table parses, is complete when the provider is on, and the file with the
/// client secret can be read. A provider that is selected but off, or on but not selected, is said.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_config(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    let config = config(check.table.clone())?;
    let mut warnings = Vec::new();
    if config.enabled {
        config.client_secret()?;
    } else {
        warnings.push(
            "`google` is selected and `[providers.google] enabled` is false: the provider is off and offers nothing until it \
             is enabled"
                .to_owned(),
        );
    }
    Ok(warnings)
}

fn build(context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let config = config(table)?;
        let http = context.require_http(PLUGIN)?;
        let provider: Arc<dyn Provider> = Arc::new(GoogleProvider::new(&config, http, Arc::clone(&context.clock))?);
        Ok(Built::new(provider))
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use davhaven_ports::testing::ReplayHttp;
    use davhaven_ports::{ConfigTree, RunMode};

    use super::*;

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        registry
    }

    fn context() -> PluginContext {
        PluginContext::for_tests().with_http(Arc::new(ReplayHttp::new()))
    }

    #[test]
    fn the_plugin_registers_once_with_the_table_of_the_plan() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::PROVIDER), vec!["google"]);
        assert_eq!(registry.dedicated_table("provider", "google"), Some("providers.google"));
        assert!(
            !registry.refused_in_production("provider", "google"),
            "a real provider is allowed in production"
        );
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        let schemas = registry.schemas();
        assert_eq!(schemas.len(), 1);
        assert!(schemas[0].schema.as_value().to_string().contains("client_secret_file"));
    }

    #[tokio::test]
    async fn a_provider_without_a_table_builds_and_is_off() {
        let registry = registry();
        let built = registry
            .build_set(PortKind::PROVIDER, &["google"], &context(), &ConfigTree::new())
            .await
            .unwrap();
        assert_eq!(built.len(), 1);
        assert!(!built[0].port.enabled());
        assert_eq!(built[0].port.name(), "google");
    }

    #[tokio::test]
    async fn production_builds_it_and_a_missing_http_client_is_named() {
        let registry = registry();
        let mut production = context();
        production.mode = RunMode::Production;
        assert!(
            registry
                .build_set(PortKind::PROVIDER, &["google"], &production, &ConfigTree::new())
                .await
                .is_ok()
        );
        let error = registry
            .build_set(
                PortKind::PROVIDER,
                &["google"],
                &PluginContext::for_tests(),
                &ConfigTree::new(),
            )
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(error, PluginError::MissingDependency { .. }), "{error}");
    }

    #[tokio::test]
    async fn an_enabled_table_is_complete_or_the_build_fails() {
        let registry = registry();
        let incomplete = ConfigTree::new().with("google", serde_json::json!({"enabled": true, "client_id": "x"}));
        let error = registry
            .build_set(PortKind::PROVIDER, &["google"], &context(), &incomplete)
            .await
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("client_secret_file"), "{error}");
        let typo = ConfigTree::new().with("google", serde_json::json!({"enabeld": true}));
        assert!(
            registry
                .build_set(PortKind::PROVIDER, &["google"], &context(), &typo)
                .await
                .map(|_| ())
                .unwrap_err()
                .to_string()
                .contains("enabeld")
        );
    }

    #[test]
    fn the_check_reads_the_secret_file_and_says_what_an_off_provider_means() {
        let off = serde_json::json!({});
        let warnings = check_config(&PluginCheck::new(&off, RunMode::Production)).unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("off"), "{warnings:?}");

        let path = std::env::temp_dir().join(format!("davhaven-google-check-{}", std::process::id()));
        std::fs::File::create(&path).unwrap().write_all(b"s3cret\n").unwrap();
        let on = serde_json::json!({
            "enabled": true,
            "client_id": "x",
            "client_secret_file": path,
            "redirect_uri": "https://cal.example.org/oauth/google/callback",
        });
        assert_eq!(
            check_config(&PluginCheck::new(&on, RunMode::Production)).unwrap(),
            Vec::<String>::new()
        );
        std::fs::remove_file(&path).unwrap();
        let error = check_config(&PluginCheck::new(&on, RunMode::Production))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("client_secret_file") && !error.contains("s3cret"),
            "{error}"
        );
    }
}
