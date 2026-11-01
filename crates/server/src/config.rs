//! Layered configuration (TOML and `DAVHAVEN_*` environment variables) and its validation.
//!
//! The configuration is one typed [`Config`] (`deny_unknown_fields` everywhere, so a misspelled key fails
//! startup with its name) built from, in increasing precedence, the defaults, a TOML file and `DAVHAVEN_*`
//! environment variables (`DAVHAVEN_SERVER__MODE=dev` sets `server.mode`; `__` separates the levels). An unknown
//! variable is an unknown key and fails like any typo. Secrets are never inline-only: they come from files named
//! by `*_file` keys.
//!
//! # Where the sections live
//!
//! Each crate owns the struct of its table (`ENGINEERING_RULES` R3):
//!
//! | Table | Owner |
//! | --- | --- |
//! | `[server]`, `[plugins]`, `[observability]` | this crate |
//! | `[server.http]`, `[security.cors]` | `davhaven-http` |
//! | `[mcp]` | `davhaven-mcp` |
//! | `[mail]`, `[scheduling]`, `[sharing]`, `[retention]`, `[outbox]`, `[feeds]` | `davhaven-app` |
//! | `[limits.ical]`, `[limits.dav]`, `[limits.api]` | `davhaven-domain` |
//! | `[security]` keys | `davhaven-crypto-local` |
//! | `[database]` | `davhaven-store-postgres` |
//! | `[templates]` | `davhaven-templates` |
//! | `[webhooks]` | `davhaven-hooks-webhook` |
//! | `[security.auth]` | `davhaven-auth-local` |
//! | `[security.egress]` | `davhaven-http-egress` |
//! | `[providers.google]`, `[providers.microsoft]` | the provider crates |
//! | `[plugin.<name>]` | the adapter named `<name>` |
//!
//! Adapter crates are optional cargo features of this crate, so the tables they own are carried as raw values
//! here and parsed (and validated) by the adapter when the registry builds it. The tables owned by the crates this
//! crate always depends on are typed.

use core::fmt;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use davhaven_app::AppConfig;
use davhaven_app::config::{
    ConfigError as SectionError, FeedsConfig, MailConfig, OutboxConfig, ProviderSyncConfig, RetentionConfig,
    SchedulingConfig, SharingConfig,
};
use davhaven_crypto_local::config::{KeyConfig, KeysConfig, ProfileSigningConfig};
use davhaven_domain::{ApiLimits, DavLimits, IcalLimits, Limits, LimitsError, PublicUrls};
use davhaven_http::cors::CorsConfig;
use davhaven_http::limits::HttpConfig;
use davhaven_mcp::config::McpConfig;
use davhaven_ports::{KindInfo, PluginError, PluginRegistry, RunMode};
use figment::Figment;
use figment::providers::{Env, Format as _, Toml};
use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::listeners::ListenersConfig;
use crate::telemetry::ObservabilityConfig;

/// The prefix of the environment variables.
pub const ENV_PREFIX: &str = "DAVHAVEN_";

/// Environment variables with the prefix that are not configuration keys: the path of the configuration file
/// (`DAVHAVEN_CONFIG`) is read by the command line.
const NON_CONFIG_VARIABLES: &[&str] = &["config"];

/// Why the configuration cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A file or the environment cannot be read, a key is unknown, or a value has the wrong type. The message
    /// names the key.
    #[error("cannot load the configuration: {0}")]
    Load(Box<figment::Error>),
    /// A table of the application, the HTTP edge or the MCP server is invalid.
    #[error(transparent)]
    Section(#[from] SectionError),
    /// A limit is unusable.
    #[error(transparent)]
    Limits(#[from] LimitsError),
    /// An adapter's table is invalid.
    #[error(transparent)]
    Plugin(#[from] PluginError),
    /// A key of this crate is missing or invalid.
    #[error("invalid configuration `{key}`: {reason}")]
    Invalid {
        /// The dotted key.
        key: &'static str,
        /// The rule that was violated.
        reason: String,
    },
}

impl From<figment::Error> for ConfigError {
    fn from(error: figment::Error) -> Self {
        Self::Load(Box::new(error))
    }
}

/// The `[server]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// `production` (the default, so a forgotten setting is the safe one) or `dev`. Production requires signing keys and
    /// refuses the plugins that drop or fake work: the memory store and mail transport, the echo renderer, the `noop`
    /// rate limiter, the recording HTTP client and the `eicar` scanner (each of these plugins says so in its descriptor, and
    /// `config check` and the plugin registry both read that one flag). The in-process rate limiter is the 1.0 limiter of a
    /// single instance (PLAN 1.1) and stays allowed.
    pub mode: RunMode,
    /// The public base URL of this deployment (`https://calendar.example.org`): the origin that mails, feeds,
    /// client configuration and OAuth redirects use. Required; there is no default because it is
    /// deployment-specific. Links never come from the `Host` header.
    pub public_base_url: Option<Url>,
    /// The reverse proxies whose `X-Forwarded-For` is trusted (CIDR ranges). The client address is the rightmost
    /// entry that is not a trusted proxy; without trusted proxies the header is ignored.
    #[schemars(with = "Vec<String>")]
    pub trusted_proxies: Vec<IpNet>,
    /// How long shutdown waits for in-flight requests and workers before it stops them: what is still running at the
    /// end (connections included) is cut off. The process is gone at most `shutdown_delay + shutdown_grace + 10s` after the
    /// stop signal, so give the container a stop timeout that is longer.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub shutdown_grace: Duration,
    /// How long the server keeps accepting connections after it was asked to stop, while `/readyz` already answers
    /// 503 `draining`: the time a load balancer needs to notice and to stop sending new requests. Zero (the default)
    /// stops accepting at once. The delay comes before the grace period.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub shutdown_delay: Duration,
    /// The HTTP listeners.
    pub listeners: ListenersConfig,
    /// Connection limits and timeouts.
    pub http: HttpConfig,
    /// The most connections one listener keeps open at the same time (`server.http.concurrency_limit` counts
    /// requests, not sockets). Further clients wait in the accept queue of the operating system until a connection
    /// closes, so a flood of idle connections cannot exhaust the file descriptors of the process.
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mode: RunMode::Production,
            public_base_url: None,
            trusted_proxies: Vec::new(),
            shutdown_grace: Duration::from_secs(20),
            shutdown_delay: Duration::ZERO,
            listeners: ListenersConfig::default(),
            http: HttpConfig::default(),
            max_connections: 4096,
        }
    }
}

/// The `[plugins]` table: which adapter implements each port a deployment chooses (PLAN 2.3). The values are the
/// names adapters register under; an unknown name fails startup with the list of available ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PluginsConfig {
    /// The database: `postgres` or `memory` (development and tests only).
    pub store: String,
    /// The mail transport: `smtp` or `memory`.
    pub mail_transport: String,
    /// The template renderer.
    pub templates: String,
    /// The outbound HTTP client.
    pub http_client: String,
    /// The rate limiter: `memory` (the in-process limiter of a single instance) or `noop`.
    pub rate_limiter: String,
    /// The scheduling policy.
    pub scheduling_policy: String,
    /// The authenticator chain, in order.
    pub authenticators: Vec<String>,
    /// The event sinks every domain event is delivered to.
    pub event_sinks: Vec<String>,
    /// The outbox handlers contributed by adapters.
    pub outbox_handlers: Vec<String>,
    /// The calendar providers that are compiled in and selected.
    pub providers: Vec<String>,
    /// The content scanners applied to inline binary attachments.
    pub content_scanners: Vec<String>,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            store: "postgres".to_owned(),
            mail_transport: "smtp".to_owned(),
            templates: "minijinja".to_owned(),
            http_client: "egress".to_owned(),
            rate_limiter: "memory".to_owned(),
            scheduling_policy: "default".to_owned(),
            authenticators: vec!["local".to_owned()],
            event_sinks: vec!["log".to_owned()],
            outbox_handlers: vec!["webhook".to_owned()],
            providers: Vec::new(),
            content_scanners: Vec::new(),
        }
    }
}

impl PluginsConfig {
    /// The plugin names selected for `kind`: the value of its `[plugins]` key (one name for a single kind, the list
    /// for the others), found by [`KindInfo::config_key`].
    ///
    /// Reading the table by the key the kind declares (and not by a `match` on the kind's name) means a kind that is
    /// added to [`KINDS`](davhaven_ports::plugin::KINDS) cannot be silently ignored: it either has its key here or
    /// this function says so.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when this table has no key for the kind, which is a build whose server does not know
    /// a kind of the registry yet.
    pub fn names(&self, kind: &KindInfo) -> Result<Vec<String>, ConfigError> {
        let document = serde_json::to_value(self).map_err(|error| ConfigError::Invalid {
            key: "plugins",
            reason: error.to_string(),
        })?;
        let unknown = || ConfigError::Invalid {
            key: "plugins",
            reason: format!(
                "the server has no `{}` key for the plugin kind `{}`: the plugin registry has a kind this server does not know yet",
                kind.config_key, kind.name
            ),
        };
        match document.get(kind.config_key) {
            Some(Value::String(name)) => Ok(vec![name.clone()]),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(str::to_owned).ok_or_else(unknown))
                .collect(),
            _ => Err(unknown()),
        }
    }
}

/// The `[limits]` table (PLAN 2.15).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// iCalendar limits.
    pub ical: IcalLimits,
    /// WebDAV limits.
    pub dav: DavLimits,
    /// Management API limits.
    pub api: ApiLimits,
}

impl LimitsConfig {
    /// The limits as the application layer receives them.
    pub fn limits(&self) -> Limits {
        Limits {
            ical: self.ical.clone(),
            dav: self.dav.clone(),
            api: self.api.clone(),
        }
    }
}

/// The `[security]` table (PLAN 2.6, 2.15).
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// The keys of the key ring: `[{id = "2027-01", secret_file = "/run/secrets/key-2027-01"}]`.
    pub keys: Vec<KeyConfig>,
    /// The id of the key that signs and hashes new data; the first key when absent.
    pub active_key_id: Option<String>,
    /// `[security.auth]`: the cache and backoff of the local authenticator (parsed by `davhaven-auth-local`).
    pub auth: Value,
    /// `[security.egress]`: the outbound HTTP policy (parsed by `davhaven-http-egress`).
    pub egress: Value,
    /// The longest lifetime of a token with `mcp:*` scopes, in days.
    pub max_mcp_token_days: u32,
    /// Browser origins that may call the API.
    pub cors: CorsConfig,
    /// `[security.profile_signing]`: the certificate that signs the Apple configuration profiles. Off by default.
    pub profile_signing: ProfileSigningConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            active_key_id: None,
            auth: Value::Null,
            egress: Value::Null,
            max_mcp_token_days: 90,
            cors: CorsConfig::default(),
            profile_signing: ProfileSigningConfig::default(),
        }
    }
}

impl SecurityConfig {
    /// The key section for the key ring.
    pub fn key_ring_config(&self) -> KeysConfig {
        KeysConfig {
            keys: self.keys.clone(),
            active_key_id: self.active_key_id.clone(),
        }
    }
}

/// The `[providers]` table: one table per provider, parsed by the provider crate, and the table of the sync engine that is
/// the same for every provider.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ProvidersConfig {
    /// `[providers.google]` (parsed by `davhaven-provider-google`).
    pub google: Value,
    /// `[providers.microsoft]` (parsed by `davhaven-provider-microsoft`).
    pub microsoft: Value,
    /// `[providers.sync]`: how often and how the connected accounts are pulled.
    pub sync: ProviderSyncConfig,
}

/// The whole configuration.
#[derive(Clone, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The server, its listeners and HTTP limits.
    pub server: ServerConfig,
    /// `[database]`: the table of the `postgres` plugin (parsed by `davhaven-store-postgres`).
    pub database: Value,
    /// The adapter selection.
    pub plugins: PluginsConfig,
    /// `[plugin.<name>]` and `[plugin.<kind>.<name>]`: the tables of the adapters, passed through to the adapter of that
    /// name (and kind).
    pub plugin: BTreeMap<String, Value>,
    /// Outgoing mail policy.
    pub mail: MailConfig,
    /// `[templates]`: theme and locale defaults (parsed by `davhaven-templates`).
    pub templates: Value,
    /// Scheduling ceilings.
    pub scheduling: SchedulingConfig,
    /// Calendar sharing.
    pub sharing: SharingConfig,
    /// Request, XML and iCalendar limits.
    pub limits: LimitsConfig,
    /// Keys, authentication, egress, CORS and token policy.
    pub security: SecurityConfig,
    /// Retention periods of the cleanup worker.
    pub retention: RetentionConfig,
    /// `[webhooks]`: delivery policy (parsed by `davhaven-hooks-webhook`).
    pub webhooks: Value,
    /// The outbox dispatcher.
    pub outbox: OutboxConfig,
    /// Subscription feeds.
    pub feeds: FeedsConfig,
    /// The MCP server.
    pub mcp: McpConfig,
    /// Calendar providers.
    pub providers: ProvidersConfig,
    /// Logs, metrics and traces.
    pub observability: ObservabilityConfig,
}

impl fmt::Debug for Config {
    /// Prints the typed tables and the names of the passthrough tables only: the raw values can carry inline
    /// secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("server", &self.server)
            .field("plugins", &self.plugins)
            .field("plugin", &self.plugin.keys().collect::<Vec<_>>())
            .field("mail", &self.mail)
            .field("scheduling", &self.scheduling)
            .field("sharing", &self.sharing)
            .field("limits", &self.limits)
            .field("retention", &self.retention)
            .field("outbox", &self.outbox)
            .field("feeds", &self.feeds)
            .field("mcp", &self.mcp)
            .field("observability", &self.observability)
            .finish_non_exhaustive()
    }
}

/// A dedicated table of F0.9 that this crate carries as a raw value, because the adapter that parses it is an optional
/// cargo feature, and the kind of plugin it belongs to.
#[derive(Clone, Copy)]
pub struct DedicatedTable {
    /// The dotted key of the table in the configuration file (`security.auth`).
    pub key: &'static str,
    /// The kind of plugin the table belongs to: only a descriptor of this kind may name it
    /// ([`PluginDescriptor::dedicated_table`](davhaven_ports::PluginDescriptor::dedicated_table)), so that the table
    /// of the database, with its URLs and credentials, never reaches a plugin of another kind.
    pub kind: &'static str,
    /// Reads the table from the configuration.
    read: fn(&Config) -> &Value,
}

impl DedicatedTable {
    /// The table in `config`: the raw value, empty or null when the deployment wrote none.
    pub fn value<'a>(&self, config: &'a Config) -> &'a Value {
        (self.read)(config)
    }
}

impl fmt::Debug for DedicatedTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DedicatedTable")
            .field("key", &self.key)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// The dedicated tables that an adapter may name as its own besides `[plugin.<kind>.<name>]`, each bound to the kind of
/// plugin it configures. This is the one list: [`Config::dedicated_table`] reads the tables by it, and the plugins that
/// name one are checked against it (a descriptor of another kind, or a table that is not in it, is refused). A new
/// adapter with a table of the plan that is not here needs a typed field of this crate, one row here and nothing else.
pub const DEDICATED_TABLES: [DedicatedTable; 7] = [
    DedicatedTable {
        key: "database",
        kind: "database",
        read: |config| &config.database,
    },
    DedicatedTable {
        key: "templates",
        kind: "templates",
        read: |config| &config.templates,
    },
    DedicatedTable {
        key: "webhooks",
        kind: "outbox_handler",
        read: |config| &config.webhooks,
    },
    DedicatedTable {
        key: "security.auth",
        kind: "authenticator",
        read: |config| &config.security.auth,
    },
    DedicatedTable {
        key: "security.egress",
        kind: "http_client",
        read: |config| &config.security.egress,
    },
    DedicatedTable {
        key: "providers.google",
        kind: "provider",
        read: |config| &config.providers.google,
    },
    DedicatedTable {
        key: "providers.microsoft",
        kind: "provider",
        read: |config| &config.providers.microsoft,
    },
];

/// An error for a key of this crate.
fn invalid(key: &'static str, reason: &str) -> ConfigError {
    ConfigError::Invalid {
        key,
        reason: reason.to_owned(),
    }
}

impl Config {
    /// The layered sources: the TOML file (when given; a named file must exist) and then the `DAVHAVEN_*`
    /// environment variables.
    pub fn figment(path: Option<&Path>) -> Figment {
        let figment = match path {
            Some(path) => Figment::new().merge(Toml::file_exact(path)),
            None => Figment::new(),
        };
        figment.merge(Env::prefixed(ENV_PREFIX).ignore(NON_CONFIG_VARIABLES).split("__"))
    }

    /// Loads the configuration from `path` and the environment. The result is not validated; call
    /// [`validate`](Self::validate).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Load`] for unreadable files, unknown keys and values of the wrong type.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        Self::from_figment(&Self::figment(path))
    }

    /// Extracts the configuration from prepared sources.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Load`].
    pub fn from_figment(figment: &Figment) -> Result<Self, ConfigError> {
        Ok(figment.extract()?)
    }

    /// Reads a TOML document (tests, `config check` of a candidate file). The environment is not consulted.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Load`].
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        Self::from_figment(&Figment::new().merge(Toml::string(text)))
    }

    /// Checks the whole configuration: every typed table, the public base URL, the listeners and the production rule that
    /// needs no registry (signing keys are required). The plugins that production refuses are checked against the selection
    /// by [`plugins::check`](crate::plugins::check), from the flag of their descriptors.
    ///
    /// # Errors
    ///
    /// The first problem found, as a [`ConfigError`] naming the key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let Some(base) = &self.server.public_base_url else {
            return Err(invalid(
                "server.public_base_url",
                "is required: the public URL of this deployment, for example https://calendar.example.org",
            ));
        };
        PublicUrls::new(base.clone()).map_err(|error| invalid("server.public_base_url", error.reason()))?;
        self.server.http.validate()?;
        if self.server.max_connections == 0 {
            return Err(invalid("server.max_connections", "must be greater than zero"));
        }
        self.server.listeners.validate()?;
        self.app_config().validate()?;
        self.limits().validate()?;
        self.mcp.validate()?;
        self.mcp.validate_against(&self.limits().api)?;
        self.security.cors.validate()?;
        self.observability.validate()?;
        let capture = &self.observability.dav_capture;
        if self.server.mode.is_production() && capture.enabled && !capture.allow_in_production {
            return Err(invalid(
                "observability.dav_capture.enabled",
                "is refused when server.mode is \"production\": the capture writes the calendar data of tenants to files. Run \
                 it on a development or staging instance, or set observability.dav_capture.allow_in_production = true on a \
                 staging instance that captures on purpose",
            ));
        }
        if self.server.mode.is_production() || !self.security.keys.is_empty() {
            self.security.key_ring_config().validate()?;
        }
        Ok(())
    }

    /// The configuration of the application layer.
    pub fn app_config(&self) -> AppConfig {
        AppConfig {
            mail: self.mail.clone(),
            scheduling: self.scheduling.clone(),
            sharing: self.sharing,
            retention: self.retention.clone(),
            outbox: self.outbox.clone(),
            feeds: self.feeds.clone(),
            provider_sync: self.providers.sync.clone(),
            max_mcp_token_days: self.security.max_mcp_token_days,
        }
    }

    /// The limits as the application layer receives them.
    pub fn limits(&self) -> Limits {
        self.limits.limits()
    }

    /// The raw dedicated table a plugin descriptor names, by its dotted key (`security.auth`); `None` for a key that is none
    /// of [`DEDICATED_TABLES`].
    pub fn dedicated_table(&self, key: &str) -> Option<&Value> {
        DEDICATED_TABLES
            .iter()
            .find(|table| table.key == key)
            .map(|table| table.value(self))
    }

    /// The configuration table of every selected plugin, by kind and name: `[plugin.<name>]` (when the name is
    /// selected for one kind only) or `[plugin.<kind>.<name>]`, joined with the dedicated table that the descriptor of the
    /// adapter names (`[database]`, `[security.auth]`, ...), see [`crate::plugins`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when a table is not a table, a key is set twice for one plugin, a `[plugin.<name>]`
    /// table is ambiguous because the name is selected for more than one kind, or a descriptor names a table that is none
    /// of [`DEDICATED_TABLES`] or that belongs to another kind of plugin.
    pub fn plugin_tables(&self, registry: &PluginRegistry) -> Result<crate::plugins::PluginTables, ConfigError> {
        let selections = crate::plugins::selections(&self.plugins)?;
        crate::plugins::plugin_tables(self, registry, &selections)
    }

    /// The settings that the file and the environment give, as one document with the secrets redacted: what
    /// `davhaven config check` prints. Keys that are not set (they have their defaults) are not in it.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Load`] when the sources cannot be read.
    pub fn explicit_settings(path: Option<&Path>) -> Result<Value, ConfigError> {
        let mut settings: Value = Self::figment(path).extract()?;
        redact(&mut settings);
        Ok(settings)
    }

    /// The effective settings, with the secrets redacted: what `davhaven config check` prints. The defaults of this build
    /// (read from the JSON Schema of every table) are laid under what the file and the environment say, and the table of
    /// every selected plugin, with the defaults of its own schema, is added under `plugin_settings`, by kind and name.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Load`] when the sources cannot be read and [`ConfigError::Invalid`] for a plugin table that cannot be
    /// resolved.
    pub fn effective_settings(&self, path: Option<&Path>, registry: &PluginRegistry) -> Result<Value, ConfigError> {
        let schema = schemars::schema_for!(Config);
        let mut effective = crate::schema::defaults_tree(schema.as_value());
        let explicit: Value = Self::figment(path).extract()?;
        crate::schema::merge(&mut effective, &explicit);
        if let Value::Object(members) = &mut effective {
            members.insert(
                "plugin_settings".to_owned(),
                crate::plugins::effective_plugin_settings(self, registry)?,
            );
        }
        redact(&mut effective);
        Ok(effective)
    }
}

/// What replaces a secret in the output of `config check`.
pub const REDACTED: &str = "<redacted>";

/// The words that mark a key as a secret when they are a whole part of its name (`api_key`, `db_pass`, `dsn`).
const SECRET_PARTS: [&str; 8] = ["key", "pass", "passwd", "pwd", "apikey", "dsn", "auth", "bearer"];

/// The words that mark a key as a secret wherever they appear in its name (`client_secret`, `auth_token_value`).
const SECRET_WORDS: [&str; 7] = [
    "password",
    "passphrase",
    "secret",
    "token",
    "credential",
    "private",
    "authorization",
];

/// Whether a key holds a secret by its name: passwords, passphrases, secrets, tokens, keys and DSNs. A key that names a
/// file (`password_file`) or an identifier (`active_key_id`) holds neither.
fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    if key.ends_with("_file") || key == "id" || key.ends_with("_id") {
        return false;
    }
    key.split(['_', '-', '.']).any(|part| SECRET_PARTS.contains(&part))
        || SECRET_WORDS.iter().any(|word| key.contains(word))
}

/// The user information and secret query values of a URL are hidden: `postgres://app:hunter2@db/davhaven?password=x`
/// keeps the user and the host. `None` when the text is not a URL or has nothing to hide.
fn redact_embedded_credentials(text: &str) -> Option<String> {
    let mut url = Url::parse(text).ok()?;
    let has_password = url.password().is_some();
    let has_secret_query = url.query_pairs().any(|(key, _)| is_secret_key(&key));
    if !(has_password || has_secret_query) {
        return None;
    }
    if has_password && url.set_password(Some("redacted")).is_err() {
        return Some(REDACTED.to_owned());
    }
    if url.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, value)| {
                let value = if is_secret_key(&key) {
                    "redacted".to_owned()
                } else {
                    value.into_owned()
                };
                (key.into_owned(), value)
            })
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    Some(url.to_string())
}

/// A URL without its secrets. A text that is not a URL but looks like it carries credentials is replaced entirely
/// (the value of a key that is named like a URL, `database.url`).
fn redact_url(text: &str) -> String {
    if Url::parse(text).is_err() {
        return if text.contains('@') || text.contains("password") {
            REDACTED.to_owned()
        } else {
            text.to_owned()
        };
    }
    // Nothing to hide: the text stays as it was written (no normalisation such as a trailing slash).
    redact_embedded_credentials(text).unwrap_or_else(|| text.to_owned())
}

fn redact_member(value: &mut Value, key: &str) {
    match value {
        Value::Object(members) => {
            for (name, member) in members.iter_mut() {
                redact_member(member, name);
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_member(item, key);
            }
        }
        Value::String(text) => {
            let lowered = key.to_ascii_lowercase();
            if is_secret_key(key) {
                REDACTED.clone_into(text);
            } else if lowered == "url" || lowered.ends_with("_url") || lowered.ends_with("uri") {
                *text = redact_url(text);
            } else if let Some(redacted) = redact_embedded_credentials(text) {
                // Whatever the key is called: a collector endpoint, a relay address or a DSN carries its password in
                // the URL.
                *text = redacted;
            }
        }
        _ => {}
    }
}

/// Replaces the secrets in a settings document: values under keys that are named like secrets, and the passwords
/// in URLs, whatever their key. Secrets are supposed to live in files (`*_file`), so this is the belt to those braces:
/// an inline `database.url` with a password never reaches the output of `config check`.
pub fn redact(settings: &mut Value) {
    redact_member(settings, "");
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [server]
        public_base_url = "https://cal.example.org"

        [[security.keys]]
        id = "2027-01"
        secret_file = "/run/secrets/key"
    "#;

    #[test]
    fn a_minimal_file_is_valid_and_everything_else_is_the_plan_default() {
        let config = Config::from_toml(MINIMAL).unwrap();
        config.validate().unwrap();
        assert_eq!(config.server.mode, RunMode::Production);
        assert_eq!(config.server.shutdown_grace, Duration::from_secs(20));
        assert_eq!(config.server.http.max_header_bytes, 16_384);
        assert_eq!(config.plugins.store, "postgres");
        assert_eq!(config.plugins.authenticators, vec!["local".to_owned()]);
        assert_eq!(config.scheduling.max_sync_internal_attendees, 50);
        assert_eq!(config.outbox.lease, Duration::from_mins(1));
        assert_eq!(config.feeds.refresh_interval.as_str(), "PT15M");
        assert_eq!(config.limits().ical.max_resource_size, 1_048_576);
        assert_eq!(config.security.max_mcp_token_days, 90);
        assert_eq!(config.mcp.max_range_days, 92);
        assert_eq!(config.app_config().max_mcp_token_days, 90);
        assert_eq!(config.security.key_ring_config().active_key().unwrap().id, "2027-01");
    }

    #[test]
    fn the_defaults_alone_fail_with_the_missing_url() {
        let error = Config::default().validate().unwrap_err().to_string();
        assert!(error.contains("server.public_base_url"), "{error}");
    }

    #[test]
    fn unknown_keys_fail_with_their_name_everywhere() {
        for text in [
            "[server]\npublic_base_ur = \"https://x.example\"",
            "[server.http]\nrequest_timeouts = \"1s\"",
            "[limits.ical]\nmax_resource_sizes = 1",
            "[outbox]\nbatchsize = 5",
            "[plugins]\nstorage = \"postgres\"",
            "[security.cors]\norigins = []",
            "[observability.otlp]\nsample = 1",
            "[typo]\nx = 1",
        ] {
            let error = Config::from_toml(text).unwrap_err().to_string();
            assert!(
                error.contains("unknown field") || error.contains("unknown"),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn production_requires_keys_and_the_plugin_refusals_are_one_rule_in_the_registry() {
        let without_keys = Config::from_toml("[server]\npublic_base_url = \"https://cal.example.org\"").unwrap();
        assert!(
            without_keys
                .validate()
                .unwrap_err()
                .to_string()
                .contains("at least one key")
        );
        // What production refuses among the plugins is decided in one place, the flag of the descriptors, by
        // `plugins::check` and by the plugin registry; `validate` does not repeat it, so the two cannot disagree.
        let registry = crate::registry::registry().unwrap();
        for (key, name) in [
            ("store", "memory"),
            ("mail_transport", "memory"),
            ("rate_limiter", "noop"),
        ] {
            let text = format!("{MINIMAL}\n[plugins]\n{key} = \"{name}\"");
            let config = Config::from_toml(&text).unwrap();
            config.validate().unwrap();
            let error = crate::plugins::check(&config, &registry).unwrap_err().to_string();
            assert!(error.contains(&format!("plugins.{key}")), "{error}");
        }
        let dev = "[server]\nmode = \"dev\"\npublic_base_url = \"http://localhost:8080\"\n\
                   [plugins]\nstore = \"memory\"\nmail_transport = \"memory\"\nrate_limiter = \"noop\"";
        Config::from_toml(dev).unwrap().validate().unwrap();
        let memory_limiter = format!("{MINIMAL}\n[plugins]\nrate_limiter = \"memory\"");
        Config::from_toml(&memory_limiter).unwrap().validate().unwrap();
    }

    #[test]
    fn the_dav_capture_is_refused_in_production_unless_it_is_allowed_on_purpose() {
        let on = format!(
            "{MINIMAL}\n[observability.dav_capture]\nenabled = true\ntenants = [\"acme\"]\ndir = \"/var/capture\"\n"
        );
        let error = Config::from_toml(&on).unwrap().validate().unwrap_err().to_string();
        assert!(
            error.contains("dav_capture") && error.contains("allow_in_production"),
            "{error}"
        );
        Config::from_toml(&format!("{on}allow_in_production = true\n"))
            .unwrap()
            .validate()
            .unwrap();
        let dev = "[server]\nmode = \"dev\"\npublic_base_url = \"http://localhost:8080\"\n\
                   [observability.dav_capture]\nenabled = true\ntenants = [\"acme\"]\ndir = \"/var/capture\"\n";
        Config::from_toml(dev).unwrap().validate().unwrap();
    }

    #[test]
    fn nested_tables_are_validated() {
        for (extra, key) in [
            ("[server.http]\nmax_header_bytes = 10", "max_header_bytes"),
            ("[outbox]\nbatch_size = 0", "batch_size"),
            ("[mcp]\nmax_range_days = 0", "max_range_days"),
            ("[mcp]\nmax_results = 201", "max_results"),
            ("[limits.ical]\nmax_resource_size = 0", "max_resource_size"),
            ("[security.cors]\nallowed_origins = [\"*\"]", "allowed_origins"),
            ("[server.listeners.ops]\nroutes = [\"ops\", \"api\"]", "ops"),
        ] {
            let text = format!("{MINIMAL}\n{extra}");
            let error = Config::from_toml(&text).unwrap().validate().unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
        let bad_url = Config::from_toml("[server]\npublic_base_url = \"https://cal.example.org/prefix\"\n").unwrap();
        assert!(
            bad_url
                .validate()
                .unwrap_err()
                .to_string()
                .contains("server.public_base_url")
        );
    }

    #[test]
    fn plugin_tables_are_passed_through_by_kind_and_name() {
        let text = format!("{MINIMAL}\n[plugin.smtp]\nhost = \"smtp.example.org\"\n[plugin.memory]\n");
        let config = Config::from_toml(&text).unwrap();
        let tables = config.plugin_tables(&crate::registry::registry().unwrap()).unwrap();
        assert_eq!(
            tables.get("mail_transport", "smtp").unwrap()["host"],
            "smtp.example.org"
        );
        assert!(
            tables.get("rate_limiter", "memory").is_none(),
            "an empty table is left out"
        );
        let not_a_table = Config::from_toml(&format!("{MINIMAL}\n[plugin]\nsmtp = \"host=x\"")).unwrap();
        assert!(
            not_a_table
                .plugin_tables(&crate::registry::registry().unwrap())
                .is_err()
        );
    }

    #[test]
    fn the_request_timeout_has_no_rule_with_the_idempotency_lease() {
        // The API layer leases every key for the request timeout plus a margin (ADR-0012), computed from the timeout itself,
        // so there is no second value to keep in step with it: every timeout is a valid one.
        Config::from_toml(MINIMAL).unwrap().validate().unwrap();
        for timeout in ["15s", "60s", "90s", "2m", "10m"] {
            Config::from_toml(&format!("{MINIMAL}\n[server.http]\nrequest_timeout = \"{timeout}\""))
                .unwrap()
                .validate()
                .unwrap_or_else(|error| panic!("{timeout}: {error}"));
        }
        // The setting that the lease no longer follows is gone: an operator who still sets it is told that it does nothing.
        let error = Config::from_toml(&format!("{MINIMAL}\n[limits.api]\nidempotency_lease_seconds = 150"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("idempotency_lease_seconds"), "{error}");
    }

    #[test]
    fn the_connection_cap_must_be_positive() {
        let zero = Config::from_toml("[server]\npublic_base_url = \"https://cal.example.org\"\nmax_connections = 0\n")
            .unwrap();
        assert!(zero.validate().unwrap_err().to_string().contains("max_connections"));
        assert_eq!(Config::default().server.max_connections, 4096);
    }

    #[test]
    fn every_kind_has_its_key_in_the_plugins_table() {
        let plugins = PluginsConfig::default();
        for kind in davhaven_ports::plugin::KINDS {
            let names = plugins.names(&kind).unwrap();
            if kind.cardinality == davhaven_ports::Cardinality::Single {
                assert_eq!(names.len(), 1, "{}", kind.name);
            }
        }
        let unknown = KindInfo {
            name: "future",
            cardinality: davhaven_ports::Cardinality::Set,
            config_key: "futures",
            may_be_empty: true,
        };
        let error = plugins.names(&unknown).unwrap_err().to_string();
        assert!(error.contains("futures") && error.contains("future"), "{error}");
    }

    #[test]
    fn debug_output_hides_passthrough_values() {
        let text = format!("{MINIMAL}\n[database]\nurl = \"postgres://app:hunter2@db/c\"\n[plugin.smtp]\nhost = \"x\"");
        let shown = format!("{:?}", Config::from_toml(&text).unwrap());
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("smtp"));
    }

    #[test]
    fn secrets_are_redacted_by_key_name_and_in_urls() {
        let mut settings = serde_json::json!({
            "database": {
                "url": "postgres://app:hunter2@db.example.org/davhaven?sslmode=verify-full&password=also-secret",
                "migration_url_file": "/run/secrets/owner-url",
                "max_connections": 10
            },
            "plugin": {"smtp": {"host": "smtp.example.org", "password": "p4ss", "username": "mailer"}},
            "security": {"keys": [{"id": "2027-01", "secret_file": "/run/secrets/key"}], "active_key_id": "2027-01"},
            "providers": {"google": {"client_secret": "inline", "client_id": "abc"}},
            "server": {"public_base_url": "https://cal.example.org/"}
        });
        redact(&mut settings);
        let text = settings.to_string();
        for secret in ["hunter2", "also-secret", "p4ss", "inline"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert_eq!(settings["database"]["migration_url_file"], "/run/secrets/owner-url");
        assert_eq!(settings["security"]["keys"][0]["secret_file"], "/run/secrets/key");
        assert_eq!(settings["security"]["active_key_id"], "2027-01");
        assert_eq!(settings["plugin"]["smtp"]["host"], "smtp.example.org");
        assert_eq!(settings["plugin"]["smtp"]["password"], REDACTED);
        assert_eq!(settings["server"]["public_base_url"], "https://cal.example.org/");
        let url = settings["database"]["url"].as_str().unwrap();
        assert!(
            url.starts_with("postgres://app:redacted@db.example.org/davhaven?"),
            "{url}"
        );
        assert!(url.contains("sslmode=verify-full"), "{url}");
        assert_eq!(redact_url("not a url with user:secret@host"), REDACTED);
        assert_eq!(redact_url("relative/path"), "relative/path");
    }

    #[test]
    fn credentials_are_redacted_whatever_the_key_is_called() {
        let mut settings = serde_json::json!({
            "observability": {"otlp": {"endpoint": "http://collector-user:token9@collector:4317"}},
            "plugin": {
                "x": {
                    "dsn": "postgres://u:pw1@h/d",
                    "server": "smtp://relay:pw2@mail.example.org:587",
                    "apikey": "k1",
                    "api_key": "k2",
                    "passphrase": "k3",
                    "pass": "k4",
                    "db_pwd": "k5",
                    "callback": "https://example.org/hook?token=k6&mode=full",
                    "contact": "ops@example.org",
                    "relay": "mailto:ops@example.org",
                    "bypass": "allowed",
                    "plain_url": "https://example.org/path"
                }
            }
        });
        redact(&mut settings);
        let text = settings.to_string();
        for secret in ["token9", "pw1", "pw2", "k1", "k2", "k3", "k4", "k5", "k6"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert_eq!(
            settings["observability"]["otlp"]["endpoint"],
            "http://collector-user:redacted@collector:4317/"
        );
        let x = &settings["plugin"]["x"];
        assert_eq!(x["server"], "smtp://relay:redacted@mail.example.org:587");
        assert!(x["callback"].as_str().unwrap().contains("mode=full"), "{x}");
        for kept in ["contact", "relay", "bypass", "plain_url"] {
            assert_ne!(x[kept], REDACTED, "{kept} holds no secret");
        }
        assert_eq!(x["contact"], "ops@example.org", "an e-mail address is not a credential");
        assert_eq!(x["plain_url"], "https://example.org/path");
    }

    #[test]
    #[expect(
        clippy::result_large_err,
        reason = "figment's Jail API fixes the error type of the closure"
    )]
    fn the_explicit_settings_show_file_and_environment_without_secrets() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "davhaven.toml",
                &format!("{MINIMAL}\n[database]\nurl = \"postgres://a:pw@h/d\""),
            )?;
            jail.set_env("DAVHAVEN_OUTBOX__BATCH_SIZE", "7");
            let settings = Config::explicit_settings(Some(Path::new("davhaven.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(settings["outbox"]["batch_size"], 7);
            assert_eq!(settings["server"]["public_base_url"], "https://cal.example.org");
            assert!(!settings.to_string().contains("pw@"), "{settings}");
            Ok(())
        });
    }

    #[test]
    #[expect(
        clippy::result_large_err,
        reason = "figment's Jail API fixes the error type of the closure"
    )]
    fn environment_variables_override_the_file_and_unknown_ones_fail() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("davhaven.toml", MINIMAL)?;
            jail.set_env("DAVHAVEN_SERVER__MODE", "dev");
            jail.set_env("DAVHAVEN_SERVER__HTTP__REQUEST_TIMEOUT", "90s");
            jail.set_env("DAVHAVEN_OUTBOX__BATCH_SIZE", "7");
            jail.set_env("DAVHAVEN_CONFIG", "/etc/davhaven/davhaven.toml");
            let config = Config::load(Some(Path::new("davhaven.toml"))).map_err(|error| error.to_string())?;
            assert_eq!(config.server.mode, RunMode::Dev);
            assert_eq!(config.server.http.request_timeout, Duration::from_secs(90));
            assert_eq!(config.outbox.batch_size, 7);
            assert_eq!(
                config.server.public_base_url.as_ref().unwrap().as_str(),
                "https://cal.example.org/"
            );
            jail.set_env("DAVHAVEN_SERVER__HTTP__REQUEST_TIMEOUTS", "1s");
            let error = Config::load(Some(Path::new("davhaven.toml"))).unwrap_err().to_string();
            assert!(error.contains("request_timeouts"), "{error}");
            Ok(())
        });
    }

    #[test]
    #[expect(
        clippy::result_large_err,
        reason = "figment's Jail API fixes the error type of the closure"
    )]
    fn a_named_file_must_exist() {
        figment::Jail::expect_with(|_jail| {
            let error = Config::load(Some(Path::new("missing.toml"))).unwrap_err();
            assert!(matches!(error, ConfigError::Load(_)));
            Ok(())
        });
    }

    #[test]
    fn the_schema_documents_every_table() {
        let schema = schemars::schema_for!(Config);
        let properties = schema.as_value()["properties"].as_object().unwrap();
        for table in [
            "server",
            "database",
            "plugins",
            "plugin",
            "mail",
            "templates",
            "scheduling",
            "sharing",
            "limits",
            "security",
            "retention",
            "webhooks",
            "outbox",
            "feeds",
            "mcp",
            "providers",
            "observability",
        ] {
            assert!(properties.contains_key(table), "{table}");
        }
        assert_eq!(schema.as_value()["additionalProperties"], false);
    }
}
