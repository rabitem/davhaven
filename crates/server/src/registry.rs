//! Registration of adapters in the plugin registry.
//!
//! [`registry`] is the one place that knows which adapters exist: it calls the `register` function of every adapter
//! crate behind its cargo feature (PLAN 2.3, no `inventory` or `linkme`) and the scheduling policies of the application
//! (`davhaven_app::policy`). The server hosts no plugin of its own: every plugin is an adapter crate or the
//! application's. A build without a feature simply has no plugin of that name, and selecting it fails at startup with the
//! list of the plugins that are available.
//!
//! Wiring is additive: a new adapter adds one `#[cfg(feature = "...")]` line to [`register_adapters`].
//! Everything else the server needs to know about it comes from its descriptor: the table of its own, when the plan gives
//! it one (`[security.auth]` for the local authenticator), and its own check of the table (see [`crate::plugins`]). Its
//! configuration is found by its kind and its name (`[plugin.<kind>.<name>]`), so a name that another kind uses as well is
//! no obstacle.
//!
//! The name of a plugin must not be the name of a kind (`database`, `mail_transport`, ...): `[plugin.<kind>.<name>]`
//! would then be ambiguous with `[plugin.<name>]`. [`registry`] refuses such a registry.
//!
//! # The registry introspection test
//!
//! The tests of this module assert the rule of `ENGINEERING_RULES` R2 for the registry of the default build: every
//! kind a deployment chooses has at least two implementations (or one plus the documented empty set), and the
//! default `[plugins]` selection resolves. The provider kind has the adapters of Google and Microsoft in the default build:
//! both are default features, so that a deployment switches one on with its client credentials and needs no build of its
//! own, and both stay off until `[providers.<name>] enabled` says otherwise. `provider-fake` is the double of the harness
//! and not a default feature.
//!
//! # What production refuses
//!
//! `ENGINEERING_RULES` R3 says "production mode refuses memory adapters" and PLAN 2.3 names "the memory adapters for
//! store, mail and rate limiting". Production refuses the plugins that **drop or fake work**: the memory store and the
//! memory mail transport (data and mails would be lost at the next restart), the echo renderer, the `noop` rate limiter,
//! the recording HTTP client and the `eicar` scanner (a test fake that would make uploads look scanned). The in-process
//! rate limiter is **allowed**: PLAN 1.1 makes it the limiter of a 1.0 instance, and it loses nothing a restart would not
//! reset anyway. ADR-0013 records the decision.
//!
//! The server holds no list of them. A plugin says so in its descriptor
//! (`PluginDescriptor::with_refused_in_production`): the registry refuses to build it in production, and `davhaven
//! config check` asks the registry (`PluginRegistry::refused_in_production`), so the two answer from the one flag and a
//! new fake needs no edit here.

use davhaven_ports::{PluginError, PluginRegistry};

/// The registry with every adapter that is compiled in and the scheduling policies of the application.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when two adapters register the same name for a kind, and
/// [`PluginError::InvalidName`] when a plugin is called like a kind of plugins (programming errors that the tests of
/// this crate would have caught).
pub fn registry() -> Result<PluginRegistry, PluginError> {
    let mut registry = PluginRegistry::new();
    register_adapters(&mut registry)?;
    for report in registry.report() {
        for name in report.plugins {
            if davhaven_ports::plugin::KINDS.iter().any(|kind| kind.name == name) {
                return Err(PluginError::InvalidName { name: name.to_owned() });
            }
        }
    }
    Ok(registry)
}

/// Registers the scheduling policies of the application (`davhaven_app::policy`: `default` and `manual`) and the adapters of
/// the cargo features that are enabled.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when a name is registered twice.
pub fn register_adapters(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    // The scheduling policies belong to the application (PLAN 2.8), not to an adapter and not to a feature.
    davhaven_app::policy::register(registry)?;
    #[cfg(feature = "store-postgres")]
    davhaven_store_postgres::plugin::register(registry)?;
    #[cfg(feature = "store-memory")]
    davhaven_store_memory::plugin::register(registry)?;
    #[cfg(feature = "mail-smtp")]
    davhaven_mail_smtp::plugin::register(registry)?;
    #[cfg(feature = "mail-memory")]
    davhaven_mail_memory::plugin::register(registry)?;
    #[cfg(feature = "templates")]
    davhaven_templates::plugin::register(registry)?;
    #[cfg(feature = "auth-local")]
    davhaven_auth_local::plugin::register(registry)?;
    #[cfg(feature = "http-egress")]
    davhaven_http_egress::plugin::register(registry)?;
    #[cfg(feature = "hooks-webhook")]
    davhaven_hooks_webhook::plugin::register(registry)?;
    #[cfg(feature = "ratelimit-memory")]
    davhaven_ratelimit_memory::plugin::register(registry)?;
    #[cfg(feature = "scanner-eicar")]
    davhaven_scanner_eicar::plugin::register(registry)?;
    #[cfg(feature = "provider-google")]
    davhaven_provider_google::plugin::register(registry)?;
    #[cfg(feature = "provider-microsoft")]
    davhaven_provider_microsoft::plugin::register(registry)?;
    #[cfg(feature = "provider-fake")]
    davhaven_provider_fake::plugin::register(registry)?;
    Ok(())
}

#[cfg(all(
    test,
    feature = "store-postgres",
    feature = "store-memory",
    feature = "mail-smtp",
    feature = "mail-memory",
    feature = "templates",
    feature = "auth-local",
    feature = "http-egress",
    feature = "hooks-webhook",
    feature = "ratelimit-memory",
    feature = "scanner-eicar",
    feature = "provider-google",
    feature = "provider-microsoft"
))]
mod tests {
    use davhaven_ports::plugin::KINDS;
    use davhaven_ports::{ConfigTree, PluginContext, PortKind, RunMode};

    use super::*;
    use crate::config::PluginsConfig;

    fn production_context() -> PluginContext {
        PluginContext::new(
            std::sync::Arc::new(davhaven_ports::testing::ManualClock::default()),
            std::sync::Arc::new(davhaven_ports::testing::SeqIds::new()),
            std::sync::Arc::new(davhaven_ports::testing::FixedKeyRing::default()),
            std::sync::Arc::new(davhaven_ports::testing::PlainSealer),
            std::sync::Arc::new(davhaven_ports::testing::FixedHasher::default()),
            RunMode::Production,
        )
    }

    #[test]
    fn every_selectable_kind_has_enough_implementations() {
        let registry = registry().unwrap();
        for report in registry.report() {
            assert!(
                report.is_sufficient(),
                "kind `{}` has {:?}: it needs two implementations (or one plus the documented empty set)",
                report.kind.name,
                report.plugins
            );
        }
        assert_eq!(registry.report().len(), KINDS.len());
    }

    #[test]
    fn the_default_selection_resolves() {
        let registry = registry().unwrap();
        let plugins = PluginsConfig::default();
        let report = registry.report();
        for kind in KINDS {
            let registered = &report
                .iter()
                .find(|entry| entry.kind.name == kind.name)
                .unwrap()
                .plugins;
            for name in plugins.names(&kind).unwrap() {
                assert!(
                    registered.contains(&name.as_str()),
                    "{}: `{name}` is not registered",
                    kind.name
                );
            }
        }
        assert!(
            !plugins.authenticators.is_empty(),
            "the authenticator chain needs a member"
        );
    }

    #[test]
    fn no_plugin_is_called_like_a_kind() {
        let registry = registry().unwrap();
        for report in registry.report() {
            for name in report.plugins {
                assert!(
                    KINDS.iter().all(|kind| kind.name != name),
                    "the plugin `{name}` has the name of a kind of plugins"
                );
            }
        }
    }

    #[test]
    fn registering_twice_is_refused() {
        let mut registry = registry().unwrap();
        assert!(matches!(
            register_adapters(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
    }

    /// What the registry says production refuses, as `(kind, name)`.
    fn flagged(registry: &PluginRegistry) -> Vec<(&'static str, &'static str)> {
        let mut flagged: Vec<(&str, &str)> = registry
            .report()
            .into_iter()
            .flat_map(|report| {
                report
                    .plugins
                    .into_iter()
                    .map(move |name| (report.kind.name, name))
                    .collect::<Vec<_>>()
            })
            .filter(|(kind, name)| registry.refused_in_production(kind, name))
            .collect();
        flagged.sort_unstable();
        flagged
    }

    #[tokio::test]
    async fn production_refuses_the_plugins_whose_descriptor_says_so_and_builds_every_other_one() {
        let registry = registry().unwrap();
        let context = production_context();
        let tree = ConfigTree::new();
        let mut refused: Vec<(&str, &str)> = Vec::new();
        // Every kind is probed the way its cardinality builds it: a single plugin, a member of a chain or of a set.
        macro_rules! probe {
            ($kind:expr, $constant:expr) => {
                for name in registry.names($constant) {
                    let built = registry
                        .build_single($constant, name, &context, &tree)
                        .await
                        .map(|_built| ());
                    if matches!(built, Err(PluginError::RefusedInProduction { .. })) {
                        refused.push(($kind, name));
                    }
                }
            };
        }
        probe!("database", PortKind::DATABASE);
        probe!("mail_transport", PortKind::MAIL_TRANSPORT);
        probe!("templates", PortKind::TEMPLATES);
        probe!("rate_limiter", PortKind::RATE_LIMITER);
        probe!("http_client", PortKind::HTTP_CLIENT);
        probe!("scheduling_policy", PortKind::SCHEDULING_POLICY);
        for kind_name in registry.names(PortKind::AUTHENTICATOR) {
            let built = registry
                .build_chain(PortKind::AUTHENTICATOR, &[kind_name], &context, &tree)
                .await
                .map(|_built| ());
            if matches!(built, Err(PluginError::RefusedInProduction { .. })) {
                refused.push(("authenticator", kind_name));
            }
        }
        macro_rules! probe_set {
            ($kind:expr, $constant:expr) => {
                for name in registry.names($constant) {
                    let built = registry
                        .build_set($constant, &[name], &context, &tree)
                        .await
                        .map(|_built| ());
                    if matches!(built, Err(PluginError::RefusedInProduction { .. })) {
                        refused.push(($kind, name));
                    }
                }
            };
        }
        probe_set!("event_sink", PortKind::EVENT_SINK);
        probe_set!("outbox_handler", PortKind::OUTBOX_HANDLER);
        probe_set!("provider", PortKind::PROVIDER);
        probe_set!("content_scanner", PortKind::CONTENT_SCANNER);
        // A plugin that is refused in production without its descriptor saying so (it still refuses itself in `build`) would
        // make `config check` accept what `serve` refuses; a flagged one that built would be a flag that means nothing.
        let flagged = flagged(&registry);
        refused.sort_unstable();
        assert_eq!(
            refused, flagged,
            "the plugins that refuse production are the ones whose descriptor is flagged"
        );
        // The one rule of R3 that must never be lost by a forgotten flag.
        assert!(flagged.contains(&("database", "memory")) && flagged.contains(&("mail_transport", "memory")));
        assert!(
            !flagged.contains(&("rate_limiter", "memory")),
            "the in-process limiter is the production limiter of one instance (PLAN 1.1)"
        );
    }
}
