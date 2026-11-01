//! Registration of the adapter in the plugin registry.
//!
//! Two plugins of the `authenticator` kind: `local`, which verifies app passwords and API, feed and RSVP tokens
//! against the store, and `noop`, which recognises nothing (the safe second implementation: a chain made of it
//! alone authenticates nobody). The `local` plugin is configured by the `[security.auth]` table of the
//! configuration; the server hands that table to the plugin named `local`. It returns the worker that flushes
//! `last_used_at`, which the server spawns and stops.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use davhaven_ports::{
    Authenticator, Built, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind, Worker,
    parse_config,
};
use schemars::Schema;

use crate::authenticator::{DatabaseSource, LocalAuthenticator, LocalDeps, NoopAuthenticator};
use crate::config::{AuthConfig, PLUGIN};

/// The name of the `noop` plugin.
pub const NOOP: &str = "noop";

/// Registers the `local` and `noop` authenticators.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has one of them already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::AUTHENTICATOR,
        PluginDescriptor::new(
            PLUGIN,
            "Verifies app passwords (DAV), API tokens (API, MCP), feed tokens and RSVP tokens against the store with \
             keyed hashes, caches verifications and records their use. Configured by `[security.auth]`.",
            local_schema,
            build_local,
        )
        .with_dedicated_table(TABLE)
        .with_check(check_local),
    )?;
    registry.register(
        PortKind::AUTHENTICATOR,
        PluginDescriptor::new(
            NOOP,
            "Recognises no credential: every answer is not-applicable. For chains that are completed elsewhere and for \
             tests.",
            noop_schema,
            build_noop,
        ),
    )
}

/// The dedicated table of the `local` authenticator besides `[plugin.authenticator.local]` (PLAN F0.9).
pub const TABLE: &str = "security.auth";

/// The table of the `local` authenticator as a validated configuration: the one reading that `build` and the check of
/// `davhaven config check` share, so that the check says what `serve` will say.
fn config(table: serde_json::Value) -> Result<AuthConfig, PluginError> {
    let config: AuthConfig = parse_config(PLUGIN, table)?;
    config.validate()?;
    Ok(config)
}

/// The check of `davhaven config check`: the table parses and validates as `build` would have it.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_local(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    config(check.table.clone())?;
    Ok(Vec::new())
}

fn local_schema() -> Schema {
    schemars::schema_for!(AuthConfig)
}

/// The `noop` authenticator takes no configuration: its schema is an empty object that allows no key.
fn noop_schema() -> Schema {
    schemars::json_schema!({"type": "object", "additionalProperties": false})
}

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn Authenticator>, PluginError>> + Send>>;

fn build_local(context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let config = config(table)?;
        let database = context.require_database(PLUGIN)?;
        let authenticator = LocalAuthenticator::new(
            LocalDeps {
                source: Arc::new(DatabaseSource::new(database)),
                hasher: Arc::clone(&context.hasher),
                keyring: Arc::clone(&context.keyring),
                clock: Arc::clone(&context.clock),
                ids: Arc::clone(&context.ids),
            },
            &config,
        );
        let flusher: Arc<dyn Worker> = authenticator.flusher();
        let port: Arc<dyn Authenticator> = Arc::new(authenticator);
        Ok(Built::new(port).with_workers(vec![flusher]))
    })
}

fn build_noop(_context: PluginContext, config: serde_json::Value) -> Building {
    Box::pin(async move {
        match config {
            serde_json::Value::Null => {}
            serde_json::Value::Object(members) if members.is_empty() => {}
            _ => {
                return Err(PluginError::invalid_config(
                    NOOP,
                    "the noop authenticator takes no configuration",
                ));
            }
        }
        let port: Arc<dyn Authenticator> = Arc::new(NoopAuthenticator);
        Ok(Built::new(port))
    })
}

#[cfg(test)]
mod tests {
    use davhaven_domain::{Channel, RequestId};
    use davhaven_ports::{AuthHint, AuthOutcome, ConfigTree, PresentedCredential, RunMode};
    use secrecy::SecretString;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        registry
    }

    #[test]
    fn both_authenticators_are_registered_once_with_their_schemas() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::AUTHENTICATOR), vec!["local", "noop"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        let schemas = registry.schemas();
        assert_eq!(
            schemas[0].schema.as_value()["properties"]["cache_ttl"]["type"],
            "string"
        );
        assert_eq!(schemas[1].schema.as_value()["additionalProperties"], false);
        assert!(
            registry
                .report()
                .iter()
                .any(|kind| kind.kind.name == "authenticator" && kind.is_sufficient())
        );
    }

    #[tokio::test]
    async fn the_local_authenticator_needs_the_database_and_a_valid_configuration() {
        let registry = registry();
        let context = PluginContext::for_tests();
        let error = registry
            .build_chain(PortKind::AUTHENTICATOR, &["local"], &context, &ConfigTree::new())
            .await
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("database"), "{error}");
        for (config, key) in [
            (json!({"cache_ttl": "0s"}), "cache_ttl"),
            (json!({"backoff_base": "10m"}), "backoff_base"),
            (json!({"cachettl": "1s"}), "cachettl"),
        ] {
            let tree = ConfigTree::new().with("local", config.clone());
            let error = registry
                .build_chain(PortKind::AUTHENTICATOR, &["local"], &context, &tree)
                .await
                .map(|_| ())
                .unwrap_err()
                .to_string();
            assert!(error.contains(key), "{key}: {error}");
            // `config check` says the same thing as `build`, in the same words.
            let checked = registry
                .check_table("authenticator", "local", &config, RunMode::Production)
                .expect("the authenticator has a check of its own")
                .unwrap_err()
                .to_string();
            assert_eq!(checked, error, "{key}");
        }
    }

    #[test]
    fn the_check_names_its_dedicated_table_and_accepts_the_defaults() {
        let registry = registry();
        assert_eq!(registry.dedicated_table("authenticator", "local"), Some(TABLE));
        assert_eq!(registry.dedicated_table("authenticator", "noop"), None);
        for table in [serde_json::Value::Null, json!({}), json!({"cache_ttl": "1m"})] {
            let verdict = registry
                .check_table("authenticator", "local", &table, RunMode::Production)
                .expect("the authenticator has a check of its own")
                .unwrap();
            assert!(verdict.is_empty(), "{table}: {verdict:?}");
        }
    }

    #[tokio::test]
    async fn the_noop_authenticator_passes_every_credential_on() {
        let registry = registry();
        let built = registry
            .build_chain(
                PortKind::AUTHENTICATOR,
                &["noop"],
                &PluginContext::for_tests(),
                &ConfigTree::new(),
            )
            .await
            .unwrap();
        let hint = AuthHint {
            channel: Channel::Api,
            tenant_hint: None,
            client_ip: None,
            request_id: RequestId::from_uuid(Uuid::nil()),
        };
        let credential = PresentedCredential::Bearer(SecretString::from("dvh_pat_anything"));
        let first = built.first().unwrap();
        assert_eq!(
            first.port.authenticate(&credential, &hint).await.unwrap(),
            AuthOutcome::NotApplicable
        );
        let tree = ConfigTree::new().with("noop", json!({"x": 1}));
        assert!(
            registry
                .build_chain(PortKind::AUTHENTICATOR, &["noop"], &PluginContext::for_tests(), &tree)
                .await
                .is_err()
        );
    }
}
