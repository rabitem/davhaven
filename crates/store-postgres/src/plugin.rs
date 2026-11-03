//! Registration of the adapter in the plugin registry.
//!
//! The adapter registers as the `postgres` plugin of the `database` kind. Its configuration is the `[database]`
//! table ([`DatabaseConfig`]). Building it connects the runtime role, applies pending migrations first when
//! `migrate_on_start` is set (with the owner role of `migration_url`) and then refuses to start on a schema older
//! than [`REQUIRED_SCHEMA_VERSION`](crate::migrate::REQUIRED_SCHEMA_VERSION), so a release never serves requests
//! against a schema it cannot use. Before it connects at all it applies the transport rule of production mode
//! ([`check_transport`]), which `config check` applies as well.

use std::sync::Arc;

use davhaven_ports::{
    Built, Database, Health, Lifecycle, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry,
    PortError, PortKind, RunMode, parse_config,
};
use futures::future::BoxFuture;
use secrecy::ExposeSecret;

use crate::config::{DatabaseConfig, PLUGIN};
use crate::database::{PgDatabase, Posture, transport_warning};
use crate::migrate;

/// The dedicated table of the store besides `[plugin.database.postgres]` (PLAN F0.9).
pub const TABLE: &str = "database";

/// The descriptor of the plugin: configured by the `[database]` table, checked by `check_config`.
pub const DESCRIPTOR: PluginDescriptor<dyn Database> = PluginDescriptor::new(
    PLUGIN,
    "PostgreSQL storage with row-level tenant isolation, forward-only migrations and the outbox queue.",
    config_schema,
    build,
)
.with_dedicated_table(TABLE)
.with_check(check_config);

/// The table of the store as a validated configuration: the one reading that `build` and the check of
/// `davhaven config check` share, so that the check says what `serve` will say.
fn config(table: serde_json::Value) -> Result<DatabaseConfig, PluginError> {
    let config: DatabaseConfig = parse_config(PLUGIN, table)?;
    config.validate()?;
    Ok(config)
}

/// The check of `davhaven config check`: the table parses and validates as `build` would have it, the URL files it
/// names are read, and the transport rule of production ([`check_transport`]) is applied. Nothing connects.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] for what `build` would refuse before it connects.
fn check_config(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    let config = config(check.table.clone())?;
    check_transport(&config, check.mode)
}

fn config_schema() -> schemars::Schema {
    schemars::schema_for!(DatabaseConfig)
}

/// Registers the adapter under `database`.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the adapter was registered before.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(PortKind::DATABASE, DESCRIPTOR)
}

/// Production refuses a runtime role that row-level security does not bind (or that holds more privileges than the
/// role model allows) unless `database.allow_unbound_role` says so: tenant isolation (R4) would rest on the
/// application alone, and the zero-configuration setup (one owner URL for migrations and serving) is exactly
/// that case. In `dev` mode the findings are only logged.
fn refuse_unsafe_role(posture: &Posture, mode: RunMode, allowed: bool) -> Result<(), PluginError> {
    let findings = posture.security_findings();
    if findings.is_empty() {
        return Ok(());
    }
    let text = findings.join("; ");
    if mode.is_production() && !allowed {
        return Err(PluginError::build(
            PLUGIN,
            PortError::rejected(format!(
                "{text}. Connect the runtime role of docs/operations/database.md (NOSUPERUSER NOBYPASSRLS, not the \
                 owner of the tables) in `database.url` and keep the owner in `database.migration_url`; \
                 `database.allow_unbound_role = true` accepts the risk explicitly"
            )),
        ));
    }
    tracing::warn!(
        plugin = PLUGIN,
        mode = %mode,
        allowed,
        "{text}; see docs/operations/database.md"
    );
    Ok(())
}

/// What the operator is told when `database.allow_insecure_transport` is set and no connection URL needs it.
const STALE_OPT_IN: &str = "`database.allow_insecure_transport` is set but has no effect: every connection URL \
     requires TLS or reaches a database on this host. Remove it, so that a later change of a URL is not accepted \
     silently";

/// The transport rule of production mode, without connecting: `build` applies it before it connects, and
/// `config check` applies it so that the check says what `serve` will say.
///
/// Production refuses a connection URL that may send credentials and calendar data unencrypted to a remote host
/// unless `database.allow_insecure_transport` says so, for the same reason it refuses an unbound role: a warning in a
/// log nobody reads is how the protection disappears (R6). It looks at the runtime URL and, when the server migrates
/// at startup or a migration URL is set, at the migration URL, whose owner credentials are the most powerful ones.
///
/// The warnings are what the operator should be told where the rule does not refuse: one text per URL that has the
/// problem (in `dev` mode, or accepted by the opt-in), or that the opt-in has no effect because every URL requires
/// TLS or is local, which would accept a later change of a URL without a word.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] where production would refuse to start, and when a connection URL cannot be read.
pub fn check_transport(config: &DatabaseConfig, mode: RunMode) -> Result<Vec<String>, PluginError> {
    let warnings = transport_warnings(config)?;
    if warnings.is_empty() && config.allow_insecure_transport {
        return Ok(vec![STALE_OPT_IN.to_owned()]);
    }
    refuse_insecure_transport(warnings, mode, config.allow_insecure_transport)
}

/// The transport rule for the one connection of `davhaven migrate` and `admin purge-audit`: the owner URL
/// (`migration_url`, falling back to `url`), which these commands open without the plugin build. It needs no runtime
/// URL, so a job that holds only the owner credentials passes. The warnings are those of [`check_transport`] for this
/// URL; whether the opt-in is stale is for [`check_transport`] to say, because only it sees every URL.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] where production refuses the owner URL, and when the URL cannot be read.
pub fn check_migration_transport(config: &DatabaseConfig, mode: RunMode) -> Result<Vec<String>, PluginError> {
    let warnings: Vec<String> = migration_transport_warning(config)?.into_iter().collect();
    refuse_insecure_transport(warnings, mode, config.allow_insecure_transport)
}

/// Refuses `warnings` (the findings about the connection URLs) in production unless `allowed`; in `dev` mode, and with
/// the opt-in, they are what the operator is told.
fn refuse_insecure_transport(warnings: Vec<String>, mode: RunMode, allowed: bool) -> Result<Vec<String>, PluginError> {
    if mode.is_production() && !allowed && !warnings.is_empty() {
        return Err(PluginError::invalid_config(
            PLUGIN,
            format!(
                "{}. Put sslmode=verify-full (and sslrootcert=) into the connection URL; \
                 `database.allow_insecure_transport = true` accepts the risk explicitly",
                warnings.join("; ")
            ),
        ));
    }
    Ok(warnings)
}

/// The transport warning of the URL of the migration role.
fn migration_transport_warning(config: &DatabaseConfig) -> Result<Option<String>, PluginError> {
    Ok(transport_warning(config.migration_connection_url()?.expose_secret()))
}

/// The transport warnings of the URLs the plugin will connect to.
fn transport_warnings(config: &DatabaseConfig) -> Result<Vec<String>, PluginError> {
    let mut warnings = Vec::new();
    if let Some(warning) = transport_warning(config.runtime_url()?.expose_secret()) {
        warnings.push(warning);
    }
    if (config.migrate_on_start || config.migration_url.is_some() || config.migration_url_file.is_some())
        && let Some(warning) = migration_transport_warning(config)?
        && !warnings.contains(&warning)
    {
        warnings.push(warning);
    }
    Ok(warnings)
}

fn build(ctx: PluginContext, table: serde_json::Value) -> BoxFuture<'static, Result<Built<dyn Database>, PluginError>> {
    Box::pin(async move {
        let config = config(table)?;
        for warning in check_transport(&config, ctx.mode)? {
            tracing::warn!(
                plugin = PLUGIN,
                mode = %ctx.mode,
                allowed = config.allow_insecure_transport,
                "{warning}"
            );
        }
        if ctx.mode.is_production() && config.serves_with_migration_credentials() {
            tracing::warn!(
                plugin = PLUGIN,
                "the server migrates at startup with the owner credentials of `migration_url`, so the serving \
                 process holds them; set `database.migrate_on_start = false` and run `davhaven migrate` as a \
                 separate job (docs/operations/database.md)"
            );
        }
        if config.migrate_on_start {
            migrate::run(&config).await?;
        }
        let database = Arc::new(PgDatabase::connect(&config, Arc::clone(&ctx.clock), Arc::clone(&ctx.ids)).await?);
        let posture = database.posture().await;
        if let Err(error) = refuse_unsafe_role(&posture, ctx.mode, config.allow_unbound_role) {
            database.pool().close().await;
            return Err(error);
        }
        match Lifecycle::health(database.as_ref()).await {
            Health::Unhealthy(reason) => {
                database.pool().close().await;
                return Err(PluginError::build(PLUGIN, PortError::unavailable(reason)));
            }
            Health::Degraded(reason) => tracing::warn!(plugin = PLUGIN, %reason, "the database is degraded"),
            Health::Healthy => {}
        }
        let shared = Arc::clone(&database);
        let lifecycle: Arc<dyn Lifecycle> = shared;
        let worker = Arc::clone(&database.pool_metrics);
        let port: Arc<dyn Database> = database;
        Ok(Built::new(port).with_lifecycle(lifecycle).with_workers(vec![worker]))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plugin_registers_once_under_the_database_kind() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.names(PortKind::DATABASE), vec!["postgres"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
    }

    fn unbound() -> Posture {
        Posture {
            unbound_role: Some("davhaven_owner".to_owned()),
            ..Posture::default()
        }
    }

    #[test]
    fn production_refuses_a_role_that_row_level_security_does_not_bind() {
        let error = refuse_unsafe_role(&unbound(), RunMode::Production, false).unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("davhaven_owner") && text.contains("docs/operations/database.md"),
            "{text}"
        );
        assert!(
            text.contains("allow_unbound_role"),
            "the error names the opt-out: {text}"
        );
    }

    #[test]
    fn production_refuses_excess_privileges_and_unanswered_checks_too() {
        let privileges = Posture {
            excess_privileges: vec!["TRUNCATE on principals".to_owned()],
            ..Posture::default()
        };
        assert!(refuse_unsafe_role(&privileges, RunMode::Production, false).is_err());
        let unknown = Posture {
            unknown: Some("the role query failed".to_owned()),
            ..Posture::default()
        };
        assert!(
            refuse_unsafe_role(&unknown, RunMode::Production, false).is_err(),
            "a posture that cannot be checked is not a safe one"
        );
    }

    #[test]
    fn the_opt_out_and_dev_mode_only_warn() {
        assert!(refuse_unsafe_role(&unbound(), RunMode::Production, true).is_ok());
        assert!(refuse_unsafe_role(&unbound(), RunMode::Dev, false).is_ok());
    }

    #[test]
    fn a_bound_role_passes_in_production() {
        assert!(refuse_unsafe_role(&Posture::default(), RunMode::Production, false).is_ok());
        for notice in [
            Posture {
                ascii_only_case_folding: true,
                ..Posture::default()
            },
            Posture {
                locale_unknown: Some("the locale query failed".to_owned()),
                ..Posture::default()
            },
        ] {
            assert!(
                refuse_unsafe_role(&notice, RunMode::Production, false).is_ok(),
                "notices are reported through readiness, not refused: {notice:?}"
            );
        }
    }

    fn config_of(value: serde_json::Value) -> DatabaseConfig {
        davhaven_ports::parse_config(PLUGIN, value).unwrap()
    }

    fn config_with(url: &str) -> DatabaseConfig {
        config_of(serde_json::json!({ "url": url, "migrate_on_start": false }))
    }

    /// The text of the refusal, after the check that it is one of an invalid configuration of this plugin: nothing was
    /// tried, so the start did not fail.
    fn refusal(result: Result<Vec<String>, PluginError>) -> String {
        match result.unwrap_err() {
            PluginError::InvalidConfig { plugin, message } => {
                assert_eq!(plugin, PLUGIN);
                message
            }
            other => panic!("an invalid configuration was expected, not {other}"),
        }
    }

    #[test]
    fn production_refuses_a_remote_database_without_tls() {
        for url in [
            "postgres://app:pw@db.internal/davhaven",
            "postgres://app:pw@db.internal/davhaven?sslmode=prefer",
            "postgres://app:pw@db.internal/davhaven?ssl-mode=disable",
            "postgres://app:pw@127.example.net/davhaven?sslmode=allow",
        ] {
            let config = config_with(url);
            let text = refusal(check_transport(&config, RunMode::Production));
            assert!(
                text.contains("sslmode=verify-full") && text.contains("`database.allow_insecure_transport = true`"),
                "{url}: {text}"
            );
            assert!(!text.contains("pw"), "the error never repeats the password: {text}");
            let message = check_transport(&config, RunMode::Dev).unwrap();
            assert_eq!(message.len(), 1, "dev mode only warns: {url}");
            assert!(message[0].contains("sslmode=verify-full"), "{url}: {message:?}");

            let accepted = DatabaseConfig {
                allow_insecure_transport: true,
                ..config
            };
            let warnings = check_transport(&accepted, RunMode::Production).unwrap();
            assert_eq!(warnings.len(), 1, "the explicit opt-in starts it: {url}");
            assert!(
                warnings[0].contains("sslmode=verify-full") && !warnings[0].contains("no effect"),
                "{url}: {warnings:?}"
            );
        }
    }

    #[test]
    fn encrypted_and_local_databases_pass_in_production() {
        for url in [
            "postgres://app:pw@db.internal/davhaven?sslmode=verify-full",
            "postgres://app:pw@db.internal/davhaven?ssl-mode=require",
            "postgres://app:pw@localhost/davhaven",
            "postgres://app:pw@127.0.0.1/davhaven",
            "postgres:///davhaven?host=/var/run/postgresql&user=app",
        ] {
            let config = config_with(url);
            for mode in [RunMode::Production, RunMode::Dev] {
                assert_eq!(check_transport(&config, mode).unwrap(), Vec::<String>::new(), "{url}");
            }
        }
    }

    #[test]
    fn an_opt_in_that_changes_nothing_is_reported_as_stale() {
        for url in [
            "postgres://app:pw@db.internal/davhaven?sslmode=verify-full",
            "postgres://app:pw@localhost/davhaven",
        ] {
            let config = DatabaseConfig {
                allow_insecure_transport: true,
                ..config_with(url)
            };
            for mode in [RunMode::Production, RunMode::Dev] {
                let warnings = check_transport(&config, mode).unwrap();
                assert_eq!(warnings.len(), 1, "{url}: {warnings:?}");
                assert!(
                    warnings[0].contains("`database.allow_insecure_transport`") && warnings[0].contains("no effect"),
                    "{warnings:?}"
                );
            }
        }
    }

    #[test]
    fn the_migration_url_is_checked_too() {
        let encrypted = "postgres://app:pw@db.internal/davhaven?sslmode=verify-full";
        let plain = "postgres://owner:pw@db.internal/davhaven";
        let config =
            config_of(serde_json::json!({ "url": encrypted, "migration_url": plain, "migrate_on_start": false }));
        let text = refusal(check_transport(&config, RunMode::Production));
        assert!(
            text.contains("sslmode") && text.contains("allow_insecure_transport") && !text.contains("pw"),
            "the owner URL carries the most powerful credentials: {text}"
        );
        // The same URL is one finding, whether the migration role falls back to it or names it again.
        let both = config_of(serde_json::json!({ "url": plain, "migration_url": plain, "migrate_on_start": true }));
        assert_eq!(transport_warnings(&both).unwrap().len(), 1);
        // A migration URL that is not used (no `migrate_on_start`, none set) is not judged.
        let unused = config_of(serde_json::json!({ "url": encrypted, "migrate_on_start": false }));
        assert_eq!(
            check_transport(&unused, RunMode::Production).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_commands_that_connect_with_the_owner_apply_the_rule_to_the_owner_url_alone() {
        let encrypted = "postgres://app:pw@db.internal/davhaven?sslmode=verify-full";
        let plain = "postgres://owner:pw@db.internal/davhaven";
        // A plain owner URL is refused, with the same text and the same opt-in as the server's.
        let owner = config_of(serde_json::json!({ "url": encrypted, "migration_url": plain }));
        let text = refusal(check_migration_transport(&owner, RunMode::Production));
        assert!(
            text.contains("sslmode=verify-full") && text.contains("`database.allow_insecure_transport = true`"),
            "{text}"
        );
        assert_eq!(check_migration_transport(&owner, RunMode::Dev).unwrap().len(), 1);
        let accepted = DatabaseConfig {
            allow_insecure_transport: true,
            ..owner
        };
        assert_eq!(
            check_migration_transport(&accepted, RunMode::Production).unwrap().len(),
            1
        );
        // The owner URL falls back to the runtime URL.
        let fallback = config_with("postgres://app:pw@db.internal/davhaven");
        assert!(check_migration_transport(&fallback, RunMode::Production).is_err());
        // A job that holds only the owner credentials has no runtime URL to judge, and a plain runtime URL it never
        // opens is not its concern.
        let only_owner = config_of(serde_json::json!({ "migration_url": encrypted }));
        assert_eq!(
            check_migration_transport(&only_owner, RunMode::Production).unwrap(),
            Vec::<String>::new()
        );
        let owner_is_fine = config_of(serde_json::json!({ "url": plain, "migration_url": encrypted }));
        assert_eq!(
            check_migration_transport(&owner_is_fine, RunMode::Production).unwrap(),
            Vec::<String>::new()
        );
        assert!(check_transport(&owner_is_fine, RunMode::Production).is_err());
    }

    #[tokio::test]
    async fn building_refuses_an_unencrypted_remote_database_before_it_connects() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        let mut context = PluginContext::for_tests();
        context.mode = RunMode::Production;
        let tree = davhaven_ports::ConfigTree::new().with(
            PLUGIN,
            serde_json::json!({ "url": "postgres://app:pw@db.internal/davhaven", "migrate_on_start": false }),
        );
        let error = registry
            .build_single(PortKind::DATABASE, PLUGIN, &context, &tree)
            .await
            .unwrap_err();
        let PluginError::InvalidConfig { plugin, message } = &error else {
            panic!("an invalid configuration was expected, not {error}");
        };
        assert_eq!(plugin, PLUGIN);
        assert!(message.contains("sslmode=verify-full"), "{message}");
        assert!(!error.to_string().contains("failed to start"), "{error}");
    }

    #[test]
    fn the_schema_is_the_database_table() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        let schemas = registry.schemas();
        let schema = schemas.first().unwrap();
        assert_eq!((schema.kind, schema.name), ("database", "postgres"));
        assert!(schema.schema.as_value()["properties"]["url"].is_object());
    }

    #[test]
    fn the_descriptor_names_the_database_table_and_its_check_judges_it_as_the_build_does() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.dedicated_table("database", PLUGIN), Some(TABLE));
        assert!(!registry.refused_in_production("database", PLUGIN));
        let secure = "postgres://app@db.internal/davhaven?sslmode=verify-full";
        let check = |table: serde_json::Value, mode: RunMode| {
            registry
                .check_table("database", PLUGIN, &table, mode)
                .expect("the store has a check of its own")
        };
        assert_eq!(
            check(serde_json::json!({"url": secure}), RunMode::Production).unwrap(),
            Vec::<String>::new()
        );
        for (table, key) in [
            (serde_json::json!({}), "url"),
            (
                serde_json::json!({"url": secure, "max_connections": 0}),
                "max_connections",
            ),
            (serde_json::json!({"url": secure, "lock_timeout": "0s"}), "lock_timeout"),
            (
                serde_json::json!({"url": secure, "url_file": "/run/secrets/url"}),
                "either `url` or `url_file`",
            ),
            (
                serde_json::json!({"url": secure, "max_conections": 5}),
                "max_conections",
            ),
        ] {
            let error = check(table, RunMode::Production).unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    #[tokio::test]
    async fn building_without_a_url_fails_with_the_key_name() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        let tree = davhaven_ports::ConfigTree::new().with(PLUGIN, serde_json::json!({}));
        let error = registry
            .build_single(PortKind::DATABASE, PLUGIN, &PluginContext::for_tests(), &tree)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("url"), "{error}");
    }
}
