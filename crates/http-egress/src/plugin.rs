//! Registration of the adapter in the plugin registry.
//!
//! Two plugins of the `http_client` kind: `egress` (the production client, configured by `[security.egress]`,
//! which the server passes as the `egress` table of the plugin tree) and `recording` (a fake that sends nothing).

use std::sync::Arc;

use davhaven_ports::{
    Built, HttpClient, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind,
    parse_config,
};
use futures::future::BoxFuture;
use schemars::Schema;

use crate::client::EgressHttpClient;
use crate::config::{EgressConfig, PLUGIN};
use crate::recording::{self, RecordingConfig, RecordingHttpClient};

/// Registers the `egress` and `recording` plugins.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has them already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::HTTP_CLIENT,
        PluginDescriptor::new(
            PLUGIN,
            "Outbound HTTP over rustls with the egress policy: https only, private, loopback, link-local and metadata \
             addresses denied after DNS resolution, no redirects, timeouts and size caps.",
            egress_schema,
            build_egress,
        )
        .with_dedicated_table(TABLE)
        .with_check(check_egress),
    )?;
    registry.register(
        PortKind::HTTP_CLIENT,
        PluginDescriptor::new(
            recording::PLUGIN,
            "Sends nothing: records every request and answers with a fixed status. For tests and for copies of a \
             deployment that must not call out. Not allowed in production.",
            recording_schema,
            build_recording,
        )
        // It sends nothing: a deployment that selected it would believe its webhooks and providers work.
        .with_refused_in_production()
        .with_check(check_recording),
    )
}

/// The dedicated table of the `egress` client besides `[plugin.http_client.egress]` (PLAN F0.9).
pub const TABLE: &str = "security.egress";

/// The table of the `egress` client as a validated configuration: the one reading that `build` and the check of
/// `davhaven config check` share, so that the check says what `serve` will say.
fn egress_config(table: serde_json::Value) -> Result<EgressConfig, PluginError> {
    let config: EgressConfig = parse_config(PLUGIN, table)?;
    config.validate()?;
    Ok(config)
}

/// The table of the `recording` client as a validated configuration, shared by `build` and the check.
fn recording_config(table: serde_json::Value) -> Result<RecordingConfig, PluginError> {
    let config: RecordingConfig = parse_config(recording::PLUGIN, table)?;
    config.validate()?;
    Ok(config)
}

/// The check of `davhaven config check` for `egress`: the table parses and validates as `build` would have it.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_egress(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    egress_config(check.table.clone())?;
    Ok(Vec::new())
}

/// The check of `davhaven config check` for `recording`.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_recording(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    recording_config(check.table.clone())?;
    Ok(Vec::new())
}

fn egress_schema() -> Schema {
    schemars::schema_for!(EgressConfig)
}

fn recording_schema() -> Schema {
    schemars::schema_for!(RecordingConfig)
}

fn build_egress(
    _context: PluginContext,
    table: serde_json::Value,
) -> BoxFuture<'static, Result<Built<dyn HttpClient>, PluginError>> {
    Box::pin(async move {
        let config = egress_config(table)?;
        let client: Arc<dyn HttpClient> = Arc::new(EgressHttpClient::new(&config)?);
        Ok(Built::new(client))
    })
}

fn build_recording(
    _context: PluginContext,
    table: serde_json::Value,
) -> BoxFuture<'static, Result<Built<dyn HttpClient>, PluginError>> {
    Box::pin(async move {
        let config = recording_config(table)?;
        let status = http::StatusCode::from_u16(config.status)
            .map_err(|_| PluginError::invalid_config(recording::PLUGIN, "`status` is not an HTTP status"))?;
        let client: Arc<dyn HttpClient> = Arc::new(
            RecordingHttpClient::with_config(&EgressConfig::default(), status).with_max_requests(config.max_requests),
        );
        Ok(Built::new(client))
    })
}

#[cfg(test)]
mod tests {
    use davhaven_ports::{ConfigTree, RunMode};
    use serde_json::json;

    use super::*;

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        registry
    }

    #[test]
    fn both_plugins_are_registered_once() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::HTTP_CLIENT), vec!["egress", "recording"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        let schemas = registry.schemas();
        assert_eq!(schemas.len(), 2);
        assert!(
            schemas
                .iter()
                .all(|schema| schema.kind == "http_client" && !schema.description.is_empty())
        );
    }

    #[tokio::test]
    async fn the_default_configuration_builds_both_clients() {
        let registry = registry();
        let context = PluginContext::for_tests();
        for name in ["egress", "recording"] {
            let built = registry
                .build_single(PortKind::HTTP_CLIENT, name, &context, &ConfigTree::new())
                .await
                .unwrap();
            assert!(built.workers.is_empty() && built.lifecycle.is_none(), "{name}");
        }
    }

    #[tokio::test]
    async fn the_egress_table_is_validated_and_typos_fail() {
        let registry = registry();
        let context = PluginContext::for_tests();
        for (config, key) in [
            (json!({"connect_timeout": "0s"}), "connect_timeout"),
            (json!({"allow_htp": true}), "allow_htp"),
            (json!({"allow_cidrs": ["10.0.0.0/40"]}), "IP address"),
        ] {
            let tree = ConfigTree::new().with("egress", config);
            let error = registry
                .build_single(PortKind::HTTP_CLIENT, "egress", &context, &tree)
                .await
                .map(|_| ())
                .unwrap_err()
                .to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    /// What `davhaven config check` says about a table, from the check the descriptor carries.
    fn checked(name: &str, table: &serde_json::Value) -> Result<Vec<String>, PluginError> {
        registry()
            .check_table("http_client", name, table, RunMode::Production)
            .expect("both clients have a check of their own")
    }

    #[test]
    fn the_check_of_the_egress_client_refuses_what_the_build_refuses_and_accepts_the_defaults() {
        assert_eq!(registry().dedicated_table("http_client", "egress"), Some(TABLE));
        assert_eq!(registry().dedicated_table("http_client", "recording"), None);
        for table in [
            serde_json::Value::Null,
            json!({}),
            json!({"allow_hosts": ["hooks.example.org"], "allowed_ports": [443, 8443]}),
        ] {
            assert_eq!(checked("egress", &table).unwrap(), Vec::<String>::new(), "{table}");
        }
        // Tables that parse and that the client would refuse: the check names the key, as `build` does.
        for (table, key) in [
            (json!({"connect_timeout": "0s"}), "connect_timeout"),
            (json!({"allowed_ports": [0]}), "allowed_ports"),
            (json!({"max_response_bytes": 0}), "max_response_bytes"),
            (json!({"total_timeout": "1s", "connect_timeout": "5s"}), "total_timeout"),
            (json!({"allow_hosts": ["Hooks.Example.org"]}), "allow_hosts"),
            (json!({"allow_htp": true}), "allow_htp"),
        ] {
            let error = checked("egress", &table).unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    #[test]
    fn the_check_of_the_recording_client_refuses_what_the_build_refuses_and_accepts_the_defaults() {
        for table in [
            serde_json::Value::Null,
            json!({}),
            json!({"status": 204, "max_requests": 5}),
        ] {
            assert_eq!(checked("recording", &table).unwrap(), Vec::<String>::new(), "{table}");
        }
        for (table, key) in [
            (json!({"status": 42}), "status"),
            (json!({"status": 600}), "status"),
            (json!({"max_requests": 0}), "max_requests"),
            (json!({"statuz": 200}), "statuz"),
        ] {
            let error = checked("recording", &table).unwrap_err().to_string();
            assert!(error.contains(key) && error.contains("recording"), "{key}: {error}");
        }
    }

    #[tokio::test]
    async fn the_recording_client_is_refused_in_production() {
        let registry = registry();
        let production = PluginContext::new(
            Arc::new(davhaven_ports::testing::ManualClock::default()),
            Arc::new(davhaven_ports::testing::SeqIds::new()),
            Arc::new(davhaven_ports::testing::FixedKeyRing::default()),
            Arc::new(davhaven_ports::testing::PlainSealer),
            Arc::new(davhaven_ports::testing::FixedHasher::default()),
            RunMode::Production,
        );
        let error = registry
            .build_single(PortKind::HTTP_CLIENT, "recording", &production, &ConfigTree::new())
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(error, PluginError::RefusedInProduction { .. }), "{error}");
        assert!(registry.refused_in_production("http_client", "recording"));
        assert!(!registry.refused_in_production("http_client", "egress"));
        assert!(
            registry
                .build_single(PortKind::HTTP_CLIENT, "egress", &production, &ConfigTree::new())
                .await
                .is_ok()
        );
    }
}
