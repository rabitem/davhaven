use std::sync::Arc;

use davhaven_ports::{ConfigTree, EventSink, OutboxHandler, RunMode};
use serde_json::json;

use super::*;
use crate::support::Ports;

fn registry() -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    register(&mut registry).unwrap();
    registry
}

async fn handler(
    registry: &PluginRegistry,
    name: &str,
    context: &PluginContext,
    config: &ConfigTree,
) -> Result<Built<dyn OutboxHandler>, PluginError> {
    let mut built = registry
        .build_set(PortKind::OUTBOX_HANDLER, &[name], context, config)
        .await?;
    Ok(built.remove(0))
}

async fn sink(
    registry: &PluginRegistry,
    context: &PluginContext,
    config: &ConfigTree,
) -> Result<Built<dyn EventSink>, PluginError> {
    let mut built = registry
        .build_set(PortKind::EVENT_SINK, &["log"], context, config)
        .await?;
    Ok(built.remove(0))
}

#[test]
fn the_plugins_are_registered_once_with_schemas_and_descriptions() {
    let mut registry = registry();
    assert_eq!(registry.names(PortKind::OUTBOX_HANDLER), vec!["noop", "webhook"]);
    assert_eq!(registry.names(PortKind::EVENT_SINK), vec!["log"]);
    assert!(matches!(
        register(&mut registry),
        Err(PluginError::DuplicateName { .. })
    ));
    let schemas = registry.schemas();
    assert_eq!(schemas.len(), 3);
    assert!(schemas.iter().all(|schema| !schema.description.is_empty()));
    let webhook = schemas.iter().find(|schema| schema.name == "webhook").unwrap();
    assert_eq!(webhook.kind, "outbox_handler");
}

#[tokio::test]
async fn the_defaults_build_every_plugin() {
    let registry = registry();
    let ports = Ports::new();
    for name in ["webhook", "noop"] {
        let built = handler(&registry, name, &ports.context, &ConfigTree::new())
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(built.port.kind(), "webhook", "{name}");
        assert!(built.workers.is_empty() && built.lifecycle.is_none(), "{name}");
    }
    let built = sink(&registry, &ports.context, &ConfigTree::new()).await.unwrap();
    assert_eq!(built.port.name(), "log");
}

#[tokio::test]
async fn the_handlers_wait_for_the_database_and_the_webhook_handler_for_the_http_client_too() {
    let registry = registry();
    let tier_zero = PluginContext::for_tests();
    let error = handler(&registry, "webhook", &tier_zero, &ConfigTree::new())
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, PluginError::MissingDependency { .. }), "{error}");

    // The noop handler marks deliveries, so it needs the database; the log sink needs nothing.
    let error = handler(&registry, "noop", &tier_zero, &ConfigTree::new())
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, PluginError::MissingDependency { .. }), "{error}");
    sink(&registry, &tier_zero, &ConfigTree::new()).await.unwrap();
}

#[tokio::test]
async fn the_configuration_is_validated_and_typos_fail() {
    let registry = registry();
    let ports = Ports::new();
    for (name, config, key) in [
        ("webhook", json!({"retry": "1h"}), "retry"),
        ("webhook", json!({"retry_window": "0s"}), "retry_window"),
        (
            "webhook",
            json!({"max_consecutive_failures": 0}),
            "max_consecutive_failures",
        ),
        ("noop", json!({"x": 1}), "x"),
    ] {
        let tree = ConfigTree::new().with(name, config);
        let message = handler(&registry, name, &ports.context, &tree)
            .await
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(message.contains(key), "{key}: {message}");
    }
    let tree = ConfigTree::new().with("log", json!({"level": "debug"}));
    let message = sink(&registry, &ports.context, &tree)
        .await
        .map(|_| ())
        .unwrap_err()
        .to_string();
    assert!(message.contains("level"), "{message}");

    let tuned = ConfigTree::new().with("webhook", json!({"retry_window": "6h", "max_consecutive_failures": 5}));
    handler(&registry, "webhook", &ports.context, &tuned).await.unwrap();
}

#[test]
fn the_check_of_the_webhook_handler_judges_the_table_as_the_build_does() {
    let registry = registry();
    assert_eq!(registry.dedicated_table("outbox_handler", "webhook"), Some(TABLE));
    assert_eq!(registry.dedicated_table("outbox_handler", "noop"), None);
    let check = |table: &serde_json::Value| {
        registry
            .check_table("outbox_handler", "webhook", table, RunMode::Production)
            .expect("the webhook handler has a check of its own")
    };
    // The defaults, and a tuned table, pass.
    for table in [
        serde_json::Value::Null,
        json!({}),
        json!({"retry_window": "6h", "max_consecutive_failures": 5}),
    ] {
        assert_eq!(check(&table).unwrap(), Vec::<String>::new(), "{table}");
    }
    // A table that parses but that the handler would refuse names the key.
    for (table, key) in [
        (json!({"retry_window": "0s"}), "retry_window"),
        (json!({"max_consecutive_failures": 0}), "max_consecutive_failures"),
        (json!({"retry": "1h"}), "retry"),
    ] {
        let error = check(&table).unwrap_err().to_string();
        assert!(error.contains(key) && error.contains("webhook"), "{key}: {error}");
    }
}

#[tokio::test]
async fn production_runs_these_plugins_too() {
    let registry = registry();
    let mut context = Ports::new().context;
    context.mode = RunMode::Production;
    for name in ["webhook", "noop"] {
        handler(&registry, name, &context, &ConfigTree::new())
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    sink(&registry, &context, &ConfigTree::new()).await.unwrap();
}

#[tokio::test]
async fn the_plugins_keep_the_port_contracts() {
    let registry = registry();
    let ports = Ports::new();
    for name in ["webhook", "noop"] {
        let built = handler(&registry, name, &ports.context, &ConfigTree::new())
            .await
            .unwrap();
        let port: Arc<dyn OutboxHandler> = built.port;
        davhaven_port_tests::outbox::run_all(move || Arc::clone(&port));
    }
    let built = sink(&registry, &ports.context, &ConfigTree::new()).await.unwrap();
    let port: Arc<dyn EventSink> = built.port;
    davhaven_port_tests::event_sink::run_all(move || Arc::clone(&port)).await;
}
