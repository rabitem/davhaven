//! Registration of the adapters in the plugin registry.
//!
//! Two plugins of the `rate_limiter` kind: `memory`, the limiter of a single instance (the production limiter of
//! 1.0, PLAN 1.1), and `noop`, which allows everything and is refused in production mode.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use davhaven_ports::{
    Built, FailureBackoff, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind,
    RateLimiter, parse_config,
};
use schemars::Schema;

use crate::config::{MemoryRateLimitConfig, PLUGIN};
use crate::memory::MemoryRateLimiter;
use crate::noop::NoopRateLimiter;

/// The name of the `noop` plugin.
pub const NOOP: &str = "noop";

/// Registers the `memory` and `noop` rate limiters.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has one of them already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::RATE_LIMITER,
        PluginDescriptor::new(
            PLUGIN,
            "Keyed token buckets and failure backoff in the memory of one process. Right for a single instance; \
             several instances need a shared limiter.",
            memory_schema,
            build_memory,
        )
        .with_check(check_memory),
    )?;
    registry.register(
        PortKind::RATE_LIMITER,
        PluginDescriptor::new(
            NOOP,
            "Allows every request. For tests and for deployments that limit in front of Davhaven; refused in \
             production mode.",
            noop_schema,
            build_noop,
        )
        // It allows every request: a deployment that selected it would believe it is protected.
        .with_refused_in_production(),
    )
}

/// The table of the memory limiter as a validated configuration: the one reading that `build` and the check of
/// `davhaven config check` share, so that the check says what `serve` will say. The authentication failure buckets
/// follow `[security.auth]` (`failure_backoff`), which the server puts into the plugin context; the check does not know
/// it and passes the default, and `[security.auth]` is checked by the authenticator that owns it.
fn memory_config(
    table: serde_json::Value,
    failure_backoff: FailureBackoff,
) -> Result<MemoryRateLimitConfig, PluginError> {
    let mut config: MemoryRateLimitConfig = parse_config(PLUGIN, table)?;
    config.failure_backoff = failure_backoff;
    config.validate()?;
    Ok(config)
}

/// The check of `davhaven config check`: the table parses and validates as `build` would have it.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_memory(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    memory_config(check.table.clone(), FailureBackoff::default())?;
    Ok(Vec::new())
}

fn memory_schema() -> Schema {
    schemars::schema_for!(MemoryRateLimitConfig)
}

/// The `noop` limiter takes no configuration: its schema is an empty object that allows no key.
fn noop_schema() -> Schema {
    schemars::json_schema!({"type": "object", "additionalProperties": false})
}

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn RateLimiter>, PluginError>> + Send>>;

fn build_memory(context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let config = memory_config(table, context.failure_backoff)?;
        let limiter: Arc<dyn RateLimiter> = Arc::new(MemoryRateLimiter::new(Arc::clone(&context.clock), config));
        Ok(Built::new(limiter))
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
                    "the noop rate limiter takes no configuration",
                ));
            }
        }
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
        Ok(Built::new(limiter))
    })
}

#[cfg(test)]
mod tests {
    use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
    use std::time::Duration;

    use davhaven_ports::{ConfigTree, FailureBackoff, RateKey, RunMode};
    use serde_json::json;

    use super::*;

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        registry
    }

    fn context(mode: RunMode) -> PluginContext {
        PluginContext::new(
            Arc::new(ManualClock::default()),
            Arc::new(SeqIds::new()),
            Arc::new(FixedKeyRing::default()),
            Arc::new(PlainSealer),
            Arc::new(FixedHasher::default()),
            mode,
        )
    }

    #[test]
    fn both_limiters_are_registered_once_with_their_schemas() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::RATE_LIMITER), vec!["memory", "noop"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        let schemas = registry.schemas();
        assert_eq!(schemas.len(), 2);
        assert_eq!(schemas[0].name, "memory");
        assert_eq!(
            schemas[0].schema.as_value()["properties"]["max_keys"]["type"],
            "integer"
        );
        assert_eq!(schemas[1].schema.as_value()["additionalProperties"], false);
        assert!(
            registry
                .report()
                .iter()
                .any(|kind| kind.kind.name == "rate_limiter" && kind.is_sufficient())
        );
    }

    #[tokio::test]
    async fn the_memory_limiter_builds_with_defaults_and_in_production() {
        let registry = registry();
        for mode in [RunMode::Dev, RunMode::Production] {
            let built = registry
                .build_single(PortKind::RATE_LIMITER, "memory", &context(mode), &ConfigTree::new())
                .await
                .unwrap();
            assert!(built.workers.is_empty() && built.lifecycle.is_none());
            assert!(built.port.check(&RateKey::new("api", "k"), 1).await.unwrap().allowed);
        }
    }

    #[tokio::test]
    async fn the_memory_limiter_uses_its_configuration() {
        let registry = registry();
        let tree = ConfigTree::new().with("memory", json!({"default": {"limit": 1, "window": "1m"}}));
        let built = registry
            .build_single(PortKind::RATE_LIMITER, "memory", &context(RunMode::Dev), &tree)
            .await
            .unwrap();
        assert!(built.port.check(&RateKey::new("api", "k"), 1).await.unwrap().allowed);
        assert!(!built.port.check(&RateKey::new("api", "k"), 1).await.unwrap().allowed);
    }

    #[tokio::test]
    async fn the_authentication_buckets_follow_the_failure_backoff_of_the_context() {
        let registry = registry();
        // Without anything configured the backoff is on.
        let built = registry
            .build_single(
                PortKind::RATE_LIMITER,
                "memory",
                &context(RunMode::Production),
                &ConfigTree::new(),
            )
            .await
            .unwrap();
        let key = RateKey::auth_login_ip("anna|203.0.113.7");
        for _ in 0..FailureBackoff::default().free {
            built.port.check(&key, 1).await.unwrap();
        }
        assert!(built.port.check(&key, 0).await.unwrap().allowed, "the free failures");
        built.port.check(&key, 1).await.unwrap();
        let blocked = built.port.check(&key, 0).await.unwrap();
        assert!(!blocked.allowed);
        assert_eq!(blocked.retry_after, Some(FailureBackoff::default().base));

        // The policy of `[security.auth]` is the one the server hands over.
        let strict = context(RunMode::Production).with_failure_backoff(FailureBackoff {
            free: 0,
            base: Duration::from_secs(30),
            ..FailureBackoff::default()
        });
        let built = registry
            .build_single(PortKind::RATE_LIMITER, "memory", &strict, &ConfigTree::new())
            .await
            .unwrap();
        built.port.check(&key, 1).await.unwrap();
        assert_eq!(
            built.port.check(&key, 0).await.unwrap().retry_after,
            Some(Duration::from_secs(30))
        );

        // An unusable policy is refused at startup and names the key.
        let broken = context(RunMode::Dev).with_failure_backoff(FailureBackoff {
            base: Duration::ZERO,
            ..FailureBackoff::default()
        });
        let error = registry
            .build_single(PortKind::RATE_LIMITER, "memory", &broken, &ConfigTree::new())
            .await
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("backoff_base"), "{error}");
    }

    #[tokio::test]
    async fn invalid_configuration_names_the_key_and_the_check_says_the_same() {
        let registry = registry();
        for (config, key) in [
            (json!({"max_keys": 0}), "max_keys"),
            (json!({"max": 5}), "max"),
            (json!({"default": {"limit": 0, "window": "1m"}}), "default"),
            (
                json!({"buckets": {"api": {"limit": 5, "window": "0s"}}}),
                "bucket `api`",
            ),
        ] {
            let tree = ConfigTree::new().with("memory", config.clone());
            let error = registry
                .build_single(PortKind::RATE_LIMITER, "memory", &context(RunMode::Dev), &tree)
                .await
                .map(|_| ())
                .unwrap_err()
                .to_string();
            assert!(error.contains(key), "{key}: {error}");
            let checked = registry
                .check_table("rate_limiter", "memory", &config, RunMode::Production)
                .expect("the memory limiter has a check of its own")
                .unwrap_err()
                .to_string();
            assert_eq!(checked, error, "{key}");
        }
    }

    #[test]
    fn the_check_accepts_the_defaults_and_a_tuned_table() {
        for table in [
            serde_json::Value::Null,
            json!({}),
            json!({"max_keys": 10, "buckets": {"api": {"limit": 5, "window": "1m"}}}),
        ] {
            let verdict = registry()
                .check_table("rate_limiter", "memory", &table, RunMode::Production)
                .expect("the memory limiter has a check of its own")
                .unwrap();
            assert!(verdict.is_empty(), "{table}: {verdict:?}");
        }
        assert!(
            registry().refused_in_production("rate_limiter", "noop")
                && !registry().refused_in_production("rate_limiter", "memory"),
            "the in-process limiter is the production limiter of one instance (PLAN 1.1)"
        );
    }

    #[tokio::test]
    async fn the_noop_limiter_is_refused_in_production_and_takes_no_configuration() {
        let registry = registry();
        let refused = registry
            .build_single(
                PortKind::RATE_LIMITER,
                "noop",
                &context(RunMode::Production),
                &ConfigTree::new(),
            )
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(refused, PluginError::RefusedInProduction { .. }), "{refused}");
        let built = registry
            .build_single(
                PortKind::RATE_LIMITER,
                "noop",
                &context(RunMode::Dev),
                &ConfigTree::new(),
            )
            .await
            .unwrap();
        assert!(built.port.check(&RateKey::new("api", "k"), 99).await.unwrap().allowed);
        let tree = ConfigTree::new().with("noop", json!({"limit": 1}));
        assert!(
            registry
                .build_single(PortKind::RATE_LIMITER, "noop", &context(RunMode::Dev), &tree)
                .await
                .is_err()
        );
    }
}
