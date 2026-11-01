//! Configuration of the PostgreSQL adapter.
//!
//! The `[database]` table of the configuration file is the configuration of the `postgres` plugin. The
//! connection URLs are secrets: they come inline (`url`) or from a file (`url_file`), never both. The runtime
//! role connects with `url`; migrations run with `migration_url` (the owner role) and fall back to `url`.

use core::fmt;
use std::path::PathBuf;
use std::time::Duration;

use davhaven_ports::{PluginError, resolve_secret};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::Deserialize;

/// The name of the plugin; the `[database]` table configures it.
pub const PLUGIN: &str = "postgres";

/// The `[database]` table.
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// The connection URL of the runtime role (`postgres://user:password@host/db`). Secret; use `url_file` to
    /// keep it out of the configuration file.
    #[schemars(with = "Option<String>")]
    pub url: Option<SecretString>,
    /// A file that contains the connection URL of the runtime role.
    pub url_file: Option<PathBuf>,
    /// The connection URL of the owner role that runs migrations; defaults to `url`.
    #[schemars(with = "Option<String>")]
    pub migration_url: Option<SecretString>,
    /// A file that contains the migration URL.
    pub migration_url_file: Option<PathBuf>,
    /// The most connections the pool opens.
    pub max_connections: u32,
    /// How long a request waits for a free connection before it fails as unavailable.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub acquire_timeout: Duration,
    /// The `statement_timeout` of every connection: no statement of a request runs longer.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub statement_timeout: Duration,
    /// The `lock_timeout` of every connection: how long a statement waits for a row lock (for example the lock of a
    /// busy calendar) before it fails as a timeout. Writers queue behind a hot calendar while they hold a pooled
    /// connection, so this bounds how long a queue can starve the pool.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub lock_timeout: Duration,
    /// The `idle_in_transaction_session_timeout` of every connection: a transaction that sits idle between two
    /// statements for this long is terminated by the database (a request task that stalled would otherwise pin a
    /// pooled connection and its locks indefinitely).
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub idle_in_transaction_timeout: Duration,
    /// The `statement_timeout` of the maintenance operations that legitimately run long (deleting a tenant, purging
    /// a principal, bumping the sync epoch of every collection after a restore). `0s` removes the limit.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub maintenance_timeout: Duration,
    /// Whether `serve` applies pending migrations at startup (needs a working migration role). Production
    /// deployments set this to `false` and run `davhaven migrate` as a separate job with the owner credentials,
    /// so the serving process never holds them.
    pub migrate_on_start: bool,
    /// Production only: start although the runtime role is not bound by row-level security (a superuser, a role
    /// with `BYPASSRLS` or the owner of the tables) or holds privileges that the role model of
    /// `docs/operations/database.md` withholds (`TRUNCATE`, writes to the audit log or the migration history,
    /// `EXECUTE` on the audit purge function). Tenant isolation and the append-only audit log then rest on the
    /// application alone, and this switch accepts every such finding at once, so it is the setting for a deployment
    /// that cannot have the two roles, not a way to change one thing about them. In `dev` mode the finding is only
    /// logged.
    pub allow_unbound_role: bool,
    /// Production only: start although a connection URL reaches a remote host without requiring TLS
    /// (`sslmode` other than `require`, `verify-ca` or `verify-full`). Credential hashes, sealed secrets and
    /// calendar data cross this connection, so production refuses it unless this accepts the risk. The owner URL
    /// that `davhaven migrate` and `davhaven admin purge-audit` connect with is judged the same way. Local
    /// hosts (loopback, a socket) are never flagged; in `dev` mode the finding is only logged.
    pub allow_insecure_transport: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            url_file: None,
            migration_url: None,
            migration_url_file: None,
            max_connections: 10,
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(15),
            lock_timeout: Duration::from_secs(3),
            idle_in_transaction_timeout: Duration::from_secs(30),
            maintenance_timeout: Duration::from_mins(10),
            migrate_on_start: true,
            allow_unbound_role: false,
            allow_insecure_transport: false,
        }
    }
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = |secret: &Option<SecretString>| secret.as_ref().map(|_| "<redacted>");
        f.debug_struct("DatabaseConfig")
            .field("url", &redacted(&self.url))
            .field("url_file", &self.url_file)
            .field("migration_url", &redacted(&self.migration_url))
            .field("migration_url_file", &self.migration_url_file)
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field("lock_timeout", &self.lock_timeout)
            .field("idle_in_transaction_timeout", &self.idle_in_transaction_timeout)
            .field("maintenance_timeout", &self.maintenance_timeout)
            .field("migrate_on_start", &self.migrate_on_start)
            .field("allow_unbound_role", &self.allow_unbound_role)
            .field("allow_insecure_transport", &self.allow_insecure_transport)
            .finish()
    }
}

impl DatabaseConfig {
    /// Checks the values that do not need the files: the pool and timeout settings and that no URL is given
    /// twice. Whether a URL is present at all is checked when it is resolved.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the offending key.
    pub fn validate(&self) -> Result<(), PluginError> {
        let invalid = |message: &str| PluginError::invalid_config(PLUGIN, message);
        if self.max_connections == 0 {
            return Err(invalid("`max_connections` must be greater than zero"));
        }
        if self.acquire_timeout.is_zero() {
            return Err(invalid("`acquire_timeout` must be greater than zero"));
        }
        if self.statement_timeout.is_zero() {
            return Err(invalid("`statement_timeout` must be greater than zero"));
        }
        if self.lock_timeout.is_zero() {
            return Err(invalid("`lock_timeout` must be greater than zero"));
        }
        if self.idle_in_transaction_timeout.is_zero() {
            return Err(invalid("`idle_in_transaction_timeout` must be greater than zero"));
        }
        if self.url.is_some() && self.url_file.is_some() {
            return Err(invalid("set either `url` or `url_file`, not both"));
        }
        if self.migration_url.is_some() && self.migration_url_file.is_some() {
            return Err(invalid("set either `migration_url` or `migration_url_file`, not both"));
        }
        Ok(())
    }

    /// Whether the configuration gives the serving process the migration (owner) credentials: a `migration_url`
    /// or `migration_url_file` is set while `migrate_on_start` makes the server use it. Production deployments
    /// run `davhaven migrate` as a separate job instead.
    pub fn serves_with_migration_credentials(&self) -> bool {
        self.migrate_on_start && (self.migration_url.is_some() || self.migration_url_file.is_some())
    }

    /// The connection URL of the runtime role.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] when neither `url` nor `url_file` is set, both are, or the file cannot be
    /// read.
    pub fn runtime_url(&self) -> Result<SecretString, PluginError> {
        resolve_secret(PLUGIN, "url", self.url.as_ref(), "url_file", self.url_file.as_deref())
    }

    /// The connection URL of the migration role: `migration_url`, `migration_url_file` or else the runtime URL.
    ///
    /// # Errors
    ///
    /// As [`runtime_url`](Self::runtime_url).
    pub fn migration_connection_url(&self) -> Result<SecretString, PluginError> {
        if self.migration_url.is_some() || self.migration_url_file.is_some() {
            resolve_secret(
                PLUGIN,
                "migration_url",
                self.migration_url.as_ref(),
                "migration_url_file",
                self.migration_url_file.as_deref(),
            )
        } else {
            self.runtime_url()
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn parse(text: &str) -> Result<DatabaseConfig, PluginError> {
        davhaven_ports::parse_config(PLUGIN, serde_json::from_str(text).unwrap())
    }

    #[test]
    fn defaults_are_the_plan_values() {
        let config = parse("{}").unwrap();
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.acquire_timeout, Duration::from_secs(5));
        assert_eq!(config.statement_timeout, Duration::from_secs(15));
        assert_eq!(config.lock_timeout, Duration::from_secs(3));
        assert_eq!(config.idle_in_transaction_timeout, Duration::from_secs(30));
        assert_eq!(config.maintenance_timeout, Duration::from_mins(10));
        assert!(config.migrate_on_start);
        assert!(
            !config.allow_unbound_role,
            "production refuses an unbound role by default"
        );
        assert!(
            !config.allow_insecure_transport,
            "production refuses a remote database without TLS by default"
        );
        assert!(config.url.is_none() && config.url_file.is_none());
        config.validate().unwrap();
    }

    #[test]
    fn the_server_holds_owner_credentials_only_when_it_migrates_with_them() {
        let both = parse(r#"{"url": "postgres://app@db/c", "migration_url": "postgres://owner@db/c"}"#).unwrap();
        assert!(both.serves_with_migration_credentials());
        let separate_job = parse(
            r#"{"url": "postgres://app@db/c", "migration_url": "postgres://owner@db/c", "migrate_on_start": false}"#,
        )
        .unwrap();
        assert!(!separate_job.serves_with_migration_credentials());
        let single = parse(r#"{"url": "postgres://app@db/c"}"#).unwrap();
        assert!(!single.serves_with_migration_credentials());
    }

    #[test]
    fn keys_parse_and_unknown_keys_are_refused() {
        let config = parse(
            r#"{"url": "postgres://app:pw@db/davhaven", "max_connections": 20, "acquire_timeout": "2s",
                "statement_timeout": "1m", "lock_timeout": "500ms", "idle_in_transaction_timeout": "10s",
                "maintenance_timeout": "0s", "migrate_on_start": false, "allow_unbound_role": true,
                "allow_insecure_transport": true}"#,
        )
        .unwrap();
        assert!(config.allow_insecure_transport);
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.acquire_timeout, Duration::from_secs(2));
        assert_eq!(config.statement_timeout, Duration::from_mins(1));
        assert_eq!(config.lock_timeout, Duration::from_millis(500));
        assert_eq!(config.idle_in_transaction_timeout, Duration::from_secs(10));
        assert!(
            config.maintenance_timeout.is_zero(),
            "`0s` removes the maintenance limit"
        );
        assert!(!config.migrate_on_start);
        assert!(config.allow_unbound_role);
        assert_eq!(
            config.runtime_url().unwrap().expose_secret(),
            "postgres://app:pw@db/davhaven"
        );
        let error = parse(r#"{"max_connection": 5}"#).unwrap_err();
        assert!(error.to_string().contains("max_connection"), "{error}");
        // The server never purges the audit log, so there is nothing to say about where retention runs.
        let error = parse(r#"{"audit_retention": "external"}"#).unwrap_err();
        assert!(error.to_string().contains("audit_retention"), "{error}");
    }

    #[test]
    fn validation_names_the_key() {
        for (text, key) in [
            (r#"{"max_connections": 0}"#, "max_connections"),
            (r#"{"acquire_timeout": "0s"}"#, "acquire_timeout"),
            (r#"{"statement_timeout": "0s"}"#, "statement_timeout"),
            (r#"{"lock_timeout": "0s"}"#, "lock_timeout"),
            (
                r#"{"idle_in_transaction_timeout": "0s"}"#,
                "idle_in_transaction_timeout",
            ),
            (r#"{"url": "postgres://x", "url_file": "/run/secrets/db"}"#, "url"),
            (
                r#"{"migration_url": "postgres://x", "migration_url_file": "/run/secrets/m"}"#,
                "migration_url",
            ),
        ] {
            let error = parse(text).unwrap().validate().unwrap_err().to_string();
            assert!(error.contains(key), "{text}: {error}");
        }
    }

    #[test]
    fn the_migration_url_falls_back_to_the_runtime_url() {
        let only_runtime = parse(r#"{"url": "postgres://runtime@db/c"}"#).unwrap();
        assert_eq!(
            only_runtime.migration_connection_url().unwrap().expose_secret(),
            "postgres://runtime@db/c"
        );
        let both = parse(r#"{"url": "postgres://runtime@db/c", "migration_url": "postgres://owner@db/c"}"#).unwrap();
        assert_eq!(
            both.migration_connection_url().unwrap().expose_secret(),
            "postgres://owner@db/c"
        );
        assert!(
            parse("{}").unwrap().runtime_url().is_err(),
            "a URL is required to connect"
        );
    }

    #[test]
    fn debug_output_hides_the_urls() {
        let config = parse(r#"{"url": "postgres://app:hunter2@db/davhaven"}"#).unwrap();
        let shown = format!("{config:?}");
        assert!(shown.contains("redacted") && !shown.contains("hunter2"), "{shown}");
    }

    #[test]
    fn the_schema_documents_every_key() {
        let schema = schemars::schema_for!(DatabaseConfig);
        let properties = schema.as_value()["properties"].as_object().unwrap();
        for key in [
            "url",
            "url_file",
            "migration_url",
            "migration_url_file",
            "max_connections",
            "acquire_timeout",
            "statement_timeout",
            "lock_timeout",
            "idle_in_transaction_timeout",
            "maintenance_timeout",
            "migrate_on_start",
            "allow_unbound_role",
            "allow_insecure_transport",
        ] {
            assert!(properties.contains_key(key), "{key}");
        }
        assert_eq!(schema.as_value()["additionalProperties"], false);
    }
}
