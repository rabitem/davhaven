//! The plugin registry: port kinds, plugin descriptors, plugin context and built ports.
//!
//! Adapters for the ports a deployment chooses are selected by name at startup (PLAN 2.3). Each adapter crate
//! exports `pub fn register(reg: &mut PluginRegistry)` that registers one [`PluginDescriptor`] per adapter; the
//! `server` crate calls them (behind cargo features) and then builds the selected plugins in three tiers:
//!
//! 1. tier 0: clock, id generator, key ring, secret sealer, credential hasher (injected directly, not selected by
//!    name) and the `http_client` plugin;
//! 2. tier 1: the `database` plugin;
//! 3. tier 2: every other kind.
//!
//! The [`PluginContext`] handed to `build` exposes the tiers that exist already: `http` is `None` while the HTTP
//! client itself is built, `database` is `None` until tier 1 is done.
//!
//! A [`PortKind`] ties a kind name to the port trait it produces, so registering and building are type-checked:
//! `PortKind::DATABASE` is a `PortKind<dyn Database>` and only accepts descriptors that build a `dyn Database`.
//! Kinds have a [`Cardinality`]: *single* kinds select exactly one plugin, *chain* kinds select an ordered list
//! (authenticators) and *set* kinds select any number (event sinks, outbox handlers, providers, content scanners).
//!
//! Each plugin's configuration is its own `Deserialize + JsonSchema` struct under `[plugin.<kind>.<name>]` (names
//! repeat across kinds, so the table is found by both); the registry passes the raw value to `build`, and
//! [`parse_config`] turns it into the struct with actionable errors. [`PluginRegistry::schemas`] feeds the generated
//! `docs/configuration.md`.
//!
//! A descriptor also says what only the plugin knows about itself, so that the server needs no list of adapters: the
//! dedicated table that the plan gives it besides `[plugin.<kind>.<name>]` (`security.auth` for the local authenticator,
//! [`PluginDescriptor::dedicated_table`]), its own check of the table, which `davhaven config check` runs without
//! building anything ([`PluginDescriptor::check`], [`PluginRegistry::check_table`]), and whether production mode refuses it
//! ([`PluginDescriptor::refused_in_production`]). A dedicated table has one owner: the registry refuses a descriptor that
//! names the table of another, and the tables of `[plugin]` and `[plugins]`.
//!
//! The descriptor and its companions ([`PluginDescriptor`], [`PluginCheck`], [`PluginSchema`]) are `#[non_exhaustive]`:
//! they are built with [`PluginDescriptor::new`] and the `with_*` builders, so that a member added later is additive.

use core::fmt;
use std::any::Any;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use futures::future::BoxFuture;
use schemars::{JsonSchema, Schema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::auth::Authenticator;
use crate::clock::Clock;
use crate::crypto::{CredentialHasher, KeyRing, SecretSealer};
use crate::error::PluginError;
use crate::event_sink::EventSink;
use crate::http_client::HttpClient;
use crate::ids::IdGenerator;
use crate::mail::MailTransport;
use crate::outbox::OutboxHandler;
use crate::policy::SchedulingPolicy;
use crate::provider::Provider;
use crate::rate_limit::{FailureBackoff, RateLimiter};
use crate::scanner::ContentScanner;
use crate::store::Database;
use crate::templates::TemplateRenderer;
use crate::worker::{Lifecycle, Worker};

/// The operating mode of the server (`server.mode`).
///
/// In [`RunMode::Production`] the plugins that drop or fake work (the memory adapters for store and mail, test fakes) are
/// refused: a descriptor says so with [`PluginDescriptor::with_refused_in_production`], and the registry refuses to build
/// it. [`RunMode::Dev`] allows them and is what the in-memory image for consumers runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
pub enum RunMode {
    /// A real deployment. The default, so a forgotten setting is the safe one.
    #[default]
    #[serde(rename = "production")]
    Production,
    /// Development and consumer test images.
    #[serde(rename = "dev")]
    Dev,
}

impl RunMode {
    /// The configuration spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Dev => "dev",
        }
    }

    /// Whether this is [`RunMode::Production`].
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

impl fmt::Display for RunMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// How many plugins of a kind a deployment selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cardinality {
    /// Exactly one plugin (`build_single`).
    Single,
    /// An ordered, non-empty list; the first applicable plugin wins (`build_chain`).
    Chain,
    /// Any number of plugins, possibly none (`build_set`).
    Set,
}

impl Cardinality {
    /// `single`, `chain` or `set`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Chain => "chain",
            Self::Set => "set",
        }
    }
}

/// A kind of plugin: a name, a cardinality and the port trait `P` that its plugins produce.
pub struct PortKind<P: ?Sized + 'static> {
    name: &'static str,
    cardinality: Cardinality,
    marker: PhantomData<fn() -> Arc<P>>,
}

impl<P: ?Sized + 'static> PortKind<P> {
    /// Defines a kind. The built-in kinds are the associated constants below; adapters never define their own.
    pub const fn new(name: &'static str, cardinality: Cardinality) -> Self {
        Self {
            name,
            cardinality,
            marker: PhantomData,
        }
    }

    /// The kind's name as used in configuration (`database`, `mail_transport`, ...).
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// How many plugins the kind selects.
    pub const fn cardinality(&self) -> Cardinality {
        self.cardinality
    }
}

impl<P: ?Sized + 'static> Clone for PortKind<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: ?Sized + 'static> Copy for PortKind<P> {}

impl<P: ?Sized + 'static> fmt::Debug for PortKind<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortKind")
            .field("name", &self.name)
            .field("cardinality", &self.cardinality)
            .finish()
    }
}

impl PortKind<dyn Database> {
    /// The store (`plugins.store`). Single.
    pub const DATABASE: Self = Self::new("database", Cardinality::Single);
}

impl PortKind<dyn MailTransport> {
    /// The mail transport (`plugins.mail_transport`). Single.
    pub const MAIL_TRANSPORT: Self = Self::new("mail_transport", Cardinality::Single);
}

impl PortKind<dyn TemplateRenderer> {
    /// The template renderer (`plugins.templates`). Single.
    pub const TEMPLATES: Self = Self::new("templates", Cardinality::Single);
}

impl PortKind<dyn HttpClient> {
    /// The outbound HTTP client (`plugins.http_client`). Single.
    pub const HTTP_CLIENT: Self = Self::new("http_client", Cardinality::Single);
}

impl PortKind<dyn RateLimiter> {
    /// The rate limiter (`plugins.rate_limiter`). Single.
    pub const RATE_LIMITER: Self = Self::new("rate_limiter", Cardinality::Single);
}

impl PortKind<dyn SchedulingPolicy> {
    /// The scheduling policy (`plugins.scheduling_policy`). Single.
    pub const SCHEDULING_POLICY: Self = Self::new("scheduling_policy", Cardinality::Single);
}

impl PortKind<dyn Authenticator> {
    /// The authenticators (`plugins.authenticators`). An ordered chain.
    pub const AUTHENTICATOR: Self = Self::new("authenticator", Cardinality::Chain);
}

impl PortKind<dyn EventSink> {
    /// The event sinks (`plugins.event_sinks`). A set.
    pub const EVENT_SINK: Self = Self::new("event_sink", Cardinality::Set);
}

impl PortKind<dyn OutboxHandler> {
    /// The outbox handlers (`plugins.outbox_handlers`). A set.
    pub const OUTBOX_HANDLER: Self = Self::new("outbox_handler", Cardinality::Set);
}

impl PortKind<dyn Provider> {
    /// The calendar providers (`plugins.providers`). A set.
    pub const PROVIDER: Self = Self::new("provider", Cardinality::Set);
}

impl PortKind<dyn ContentScanner> {
    /// The content scanners (`plugins.content_scanners`). A set, empty by default.
    pub const CONTENT_SCANNER: Self = Self::new("content_scanner", Cardinality::Set);
}

/// Static facts about a built-in kind, for introspection and documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindInfo {
    /// The kind's name.
    pub name: &'static str,
    /// How many plugins the kind selects.
    pub cardinality: Cardinality,
    /// The `[plugins]` configuration key that selects plugins of this kind.
    pub config_key: &'static str,
    /// Whether an empty selection is a valid default (the documented empty set), so that one registered plugin
    /// is enough for the introspection test.
    pub may_be_empty: bool,
}

const fn info<P: ?Sized + 'static>(kind: PortKind<P>, config_key: &'static str, may_be_empty: bool) -> KindInfo {
    KindInfo {
        name: kind.name(),
        cardinality: kind.cardinality(),
        config_key,
        may_be_empty,
    }
}

/// Every built-in kind, in tier order (tier 0 first).
pub const KINDS: [KindInfo; 11] = [
    info(PortKind::HTTP_CLIENT, "http_client", false),
    info(PortKind::DATABASE, "store", false),
    info(PortKind::MAIL_TRANSPORT, "mail_transport", false),
    info(PortKind::TEMPLATES, "templates", false),
    info(PortKind::RATE_LIMITER, "rate_limiter", false),
    info(PortKind::SCHEDULING_POLICY, "scheduling_policy", false),
    info(PortKind::AUTHENTICATOR, "authenticators", false),
    info(PortKind::EVENT_SINK, "event_sinks", true),
    info(PortKind::OUTBOX_HANDLER, "outbox_handlers", false),
    info(PortKind::PROVIDER, "providers", true),
    info(PortKind::CONTENT_SCANNER, "content_scanners", true),
];

/// What the plugins of one kind need to be built: the already built lower tiers and the run mode.
///
/// The pure ports are shared handles; cloning the context clones the handles.
#[derive(Clone)]
pub struct PluginContext {
    /// The time source (every adapter that stamps or compares times uses it).
    pub clock: Arc<dyn Clock>,
    /// The id and randomness source.
    pub ids: Arc<dyn IdGenerator>,
    /// The key ring.
    pub keyring: Arc<dyn KeyRing>,
    /// The secret sealer.
    pub sealer: Arc<dyn SecretSealer>,
    /// The credential hasher.
    pub hasher: Arc<dyn CredentialHasher>,
    /// The outbound HTTP client, once tier 0 has built it.
    pub http: Option<Arc<dyn HttpClient>>,
    /// The database, once tier 1 has built it.
    pub database: Option<Arc<dyn Database>>,
    /// The operating mode.
    pub mode: RunMode,
    /// The policy of the authentication failure buckets ([`FailureBackoff`]); the server sets it from
    /// `[security.auth]`, and the default is on, so a limiter built without configuration still backs off.
    pub failure_backoff: FailureBackoff,
}

impl PluginContext {
    /// A tier-0 context without HTTP client and database.
    pub fn new(
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        keyring: Arc<dyn KeyRing>,
        sealer: Arc<dyn SecretSealer>,
        hasher: Arc<dyn CredentialHasher>,
        mode: RunMode,
    ) -> Self {
        Self {
            clock,
            ids,
            keyring,
            sealer,
            hasher,
            http: None,
            database: None,
            mode,
            failure_backoff: FailureBackoff::default(),
        }
    }

    /// The context with the failure backoff of `[security.auth]`, for the rate limiter to build its authentication
    /// buckets from.
    #[must_use]
    pub const fn with_failure_backoff(mut self, failure_backoff: FailureBackoff) -> Self {
        self.failure_backoff = failure_backoff;
        self
    }

    /// The context for plugins of the next tier: with the built HTTP client.
    #[must_use]
    pub fn with_http(mut self, http: Arc<dyn HttpClient>) -> Self {
        self.http = Some(http);
        self
    }

    /// The context for plugins of the last tier: with the built database.
    #[must_use]
    pub fn with_database(mut self, database: Arc<dyn Database>) -> Self {
        self.database = Some(database);
        self
    }

    /// The database, or a [`PluginError::MissingDependency`] naming `plugin` when tier 1 is not built yet.
    ///
    /// # Errors
    ///
    /// [`PluginError::MissingDependency`].
    pub fn require_database(&self, plugin: &str) -> Result<Arc<dyn Database>, PluginError> {
        self.database
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| PluginError::MissingDependency {
                plugin: plugin.to_owned(),
                dependency: "database",
            })
    }

    /// The HTTP client, or a [`PluginError::MissingDependency`] naming `plugin` when tier 0 has none.
    ///
    /// # Errors
    ///
    /// [`PluginError::MissingDependency`].
    pub fn require_http(&self, plugin: &str) -> Result<Arc<dyn HttpClient>, PluginError> {
        self.http
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| PluginError::MissingDependency {
                plugin: plugin.to_owned(),
                dependency: "http client",
            })
    }

    /// Fails with [`PluginError::RefusedInProduction`] in [`RunMode::Production`]. A plugin that production refuses as a
    /// whole says so in its descriptor ([`PluginDescriptor::with_refused_in_production`]) and needs no call; this is for
    /// a plugin that refuses only some of its configurations.
    ///
    /// # Errors
    ///
    /// [`PluginError::RefusedInProduction`] when the mode is production.
    pub fn refuse_in_production(&self, plugin: &str) -> Result<(), PluginError> {
        if self.mode.is_production() {
            Err(PluginError::RefusedInProduction {
                plugin: plugin.to_owned(),
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for PluginContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginContext")
            .field("http", &self.http.is_some())
            .field("database", &self.database.is_some())
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// A built plugin: the port, its optional lifecycle hooks and the background workers it needs.
pub struct Built<P: ?Sized> {
    /// The port implementation.
    pub port: Arc<P>,
    /// Health and shutdown hooks, when the adapter has resources to manage.
    pub lifecycle: Option<Arc<dyn Lifecycle>>,
    /// Background workers the server spawns and stops.
    pub workers: Vec<Arc<dyn Worker>>,
}

impl<P: ?Sized> Built<P> {
    /// A built port without lifecycle and workers.
    pub fn new(port: Arc<P>) -> Self {
        Self {
            port,
            lifecycle: None,
            workers: Vec::new(),
        }
    }

    /// Adds lifecycle hooks.
    #[must_use]
    pub fn with_lifecycle(mut self, lifecycle: Arc<dyn Lifecycle>) -> Self {
        self.lifecycle = Some(lifecycle);
        self
    }

    /// Adds background workers.
    #[must_use]
    pub fn with_workers(mut self, workers: Vec<Arc<dyn Worker>>) -> Self {
        self.workers = workers;
        self
    }
}

impl<P: ?Sized> fmt::Debug for Built<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let workers: Vec<&'static str> = self.workers.iter().map(|worker| worker.name()).collect();
        f.debug_struct("Built")
            .field("lifecycle", &self.lifecycle.is_some())
            .field("workers", &workers)
            .finish_non_exhaustive()
    }
}

/// The builder function of a plugin: it receives the context and the plugin's configuration value and returns the
/// built port.
pub type BuildFn<P> = fn(PluginContext, serde_json::Value) -> BoxFuture<'static, Result<Built<P>, PluginError>>;

/// What a plugin is asked about its configuration table when the configuration is checked without building anything
/// (`davhaven config check`).
///
/// The table can carry inline secrets (a password, a database URL with credentials), so `Debug` prints the mode and the
/// keys of the table and never a value.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct PluginCheck<'a> {
    /// The table of the plugin, all the places it can be written in joined into one (`null` when the deployment wrote
    /// none, which is the plugin's defaults).
    pub table: &'a serde_json::Value,
    /// The operating mode, because the rules of production (an unencrypted transport, a fake that drops work) are part of
    /// what a plugin judges.
    pub mode: RunMode,
}

impl<'a> PluginCheck<'a> {
    /// The question for `table` in `mode`.
    pub const fn new(table: &'a serde_json::Value, mode: RunMode) -> Self {
        Self { table, mode }
    }
}

impl fmt::Debug for PluginCheck<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys: Vec<&str> = self
            .table
            .as_object()
            .map(|members| members.keys().map(String::as_str).collect())
            .unwrap_or_default();
        f.debug_struct("PluginCheck")
            .field("mode", &self.mode)
            .field("keys", &keys)
            .finish_non_exhaustive()
    }
}

/// A plugin's own judgement of its table: parses it into its configuration struct, applies the validation that `build`
/// applies, reads the files the table names, and says what is allowed but probably not intended.
///
/// It returns the warnings (the operator accepted an unencrypted transport, an opt-in that no longer has an effect) and
/// fails with the reason `build` would fail with, without connecting to anything. A plugin that registers none is checked
/// by the keys its JSON Schema knows, which finds typos and nothing else.
pub type CheckFn = fn(&PluginCheck<'_>) -> Result<Vec<String>, PluginError>;

/// Describes one adapter: its name, what it is, its configuration schema and how to build it.
///
/// Build one with [`PluginDescriptor::new`] and add what the plugin brings beyond that with
/// [`with_dedicated_table`](Self::with_dedicated_table), [`with_check`](Self::with_check) and
/// [`with_refused_in_production`](Self::with_refused_in_production). The struct is `#[non_exhaustive]`: the members are
/// public to read, and a member that is added later does not break a plugin crate.
#[non_exhaustive]
pub struct PluginDescriptor<P: ?Sized + 'static> {
    /// The name selected in configuration (`smtp`, `memory`, ...): 1 to 64 lowercase letters, digits, `-` or `_`,
    /// starting with a letter. Unique within the kind.
    pub name: &'static str,
    /// One sentence for the generated configuration documentation.
    pub description: &'static str,
    /// The JSON Schema of the plugin's configuration struct (`schemars::schema_for!`).
    pub config_schema: fn() -> Schema,
    /// Builds the plugin from its context and configuration.
    pub build: BuildFn<P>,
    /// The dedicated table that the plan gives the plugin besides `[plugin.<kind>.<name>]`, as the dotted key of the
    /// table in the configuration file (`security.auth` for the local authenticator, `database` for the PostgreSQL
    /// store). The server reads that table as part of the plugin's configuration; a key that is set in both places is an
    /// error. `None` for a plugin that is configured by `[plugin.<kind>.<name>]` alone. A dedicated table has one owner:
    /// [`PluginRegistry::register`] refuses a table that another descriptor names, and `plugin` and `plugins`.
    pub dedicated_table: Option<&'static str>,
    /// Checks the plugin's table without building the plugin; see [`CheckFn`]. `None` checks it against its JSON Schema.
    pub check: Option<CheckFn>,
    /// Whether production mode refuses the plugin: it drops or fakes work (the memory store and mail transport, a test
    /// fake), so a deployment that selected it would believe it works. [`PluginRegistry`] refuses to build it with
    /// [`RunMode::Production`], and `davhaven config check` reads the same flag
    /// ([`PluginRegistry::refused_in_production`]), so the two cannot differ.
    pub refused_in_production: bool,
}

impl<P: ?Sized + 'static> PluginDescriptor<P> {
    /// A descriptor that is configured by `[plugin.<kind>.<name>]`, checked against its JSON Schema and allowed in
    /// production.
    pub const fn new(
        name: &'static str,
        description: &'static str,
        config_schema: fn() -> Schema,
        build: BuildFn<P>,
    ) -> Self {
        Self {
            name,
            description,
            config_schema,
            build,
            dedicated_table: None,
            check: None,
            refused_in_production: false,
        }
    }

    /// Records the dedicated table that the plugin is configured by (see [`dedicated_table`](Self::dedicated_table)).
    #[must_use]
    pub const fn with_dedicated_table(mut self, table: &'static str) -> Self {
        self.dedicated_table = Some(table);
        self
    }

    /// Gives the plugin its own check of its table (see [`CheckFn`]).
    #[must_use]
    pub const fn with_check(mut self, check: CheckFn) -> Self {
        self.check = Some(check);
        self
    }

    /// Marks the plugin as one that production mode refuses (see [`refused_in_production`](Self::refused_in_production)).
    #[must_use]
    pub const fn with_refused_in_production(mut self) -> Self {
        self.refused_in_production = true;
        self
    }
}

impl<P: ?Sized + 'static> Clone for PluginDescriptor<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: ?Sized + 'static> Copy for PluginDescriptor<P> {}

impl<P: ?Sized + 'static> fmt::Debug for PluginDescriptor<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginDescriptor")
            .field("name", &self.name)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

/// The `[plugin.<name>]` tables of the configuration, as raw JSON values keyed by plugin name.
///
/// The `server` crate fills it from its `[plugin.*]` passthrough. `Debug` prints plugin names only, because the
/// values can contain inline secrets.
#[derive(Clone, Default)]
pub struct ConfigTree {
    plugins: BTreeMap<String, serde_json::Value>,
}

impl ConfigTree {
    /// An empty tree: every plugin builds with its defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the configuration of one plugin.
    #[must_use]
    pub fn with(mut self, plugin: impl Into<String>, config: serde_json::Value) -> Self {
        self.plugins.insert(plugin.into(), config);
        self
    }

    /// Reads a tree from a JSON object whose members are the plugin tables.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] when `value` is not an object or a member is not a table (an object or
    /// null).
    pub fn from_json(value: serde_json::Value) -> Result<Self, PluginError> {
        let serde_json::Value::Object(members) = value else {
            return Err(PluginError::invalid_config(
                "plugin",
                "the [plugin] section must be a table",
            ));
        };
        let mut tree = Self::new();
        for (name, config) in members {
            if !(config.is_object() || config.is_null()) {
                return Err(PluginError::invalid_config(
                    name,
                    "the plugin's section must be a table",
                ));
            }
            tree.plugins.insert(name, config);
        }
        Ok(tree)
    }

    /// The configuration of `plugin`, if the deployment gave any.
    pub fn get(&self, plugin: &str) -> Option<&serde_json::Value> {
        self.plugins.get(plugin)
    }

    /// The names of the plugins that have a section, sorted.
    pub fn plugin_names(&self) -> impl Iterator<Item = &str> {
        self.plugins.keys().map(String::as_str)
    }
}

impl fmt::Debug for ConfigTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigTree")
            .field("plugins", &self.plugins.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Deserializes a plugin's configuration value into its typed struct.
///
/// A missing section arrives as an empty object (or null) and deserializes to the struct's defaults when the
/// struct has `#[serde(default)]`. Configuration structs use `#[serde(deny_unknown_fields)]`, so typos fail with the
/// field name.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming `plugin` and the serde message.
pub fn parse_config<C: DeserializeOwned>(plugin: &str, value: serde_json::Value) -> Result<C, PluginError> {
    let value = if value.is_null() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        value
    };
    serde_json::from_value(value).map_err(|error| PluginError::invalid_config(plugin, error.to_string()))
}

/// The configuration schema of one registered plugin, for the generated configuration documentation.
///
/// `#[non_exhaustive]`: only the registry builds it, so that a member added later is additive.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PluginSchema {
    /// The kind of the plugin.
    pub kind: &'static str,
    /// The plugin's name (the `[plugin.<name>]` table).
    pub name: &'static str,
    /// The plugin's description.
    pub description: &'static str,
    /// The JSON Schema of its configuration.
    pub schema: Schema,
    /// The dedicated table besides `[plugin.<kind>.<name>]`, if it has one (see [`PluginDescriptor::dedicated_table`]).
    pub dedicated_table: Option<&'static str>,
}

/// The plugins registered for one built-in kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindReport {
    /// Static facts about the kind.
    pub kind: KindInfo,
    /// The registered plugin names, sorted.
    pub plugins: Vec<&'static str>,
}

impl KindReport {
    /// Whether the kind has enough implementations: at least two (a production adapter plus a second selectable
    /// one), or one when the kind documents that an empty selection is valid.
    pub fn is_sufficient(&self) -> bool {
        self.plugins.len() >= 2 || (self.kind.may_be_empty && !self.plugins.is_empty())
    }
}

struct Registered {
    description: &'static str,
    config_schema: fn() -> Schema,
    dedicated_table: Option<&'static str>,
    check: Option<CheckFn>,
    refused_in_production: bool,
    descriptor: Box<dyn Any + Send + Sync>,
}

struct KindEntry {
    cardinality: Cardinality,
    plugins: BTreeMap<&'static str, Registered>,
}

/// The registry of adapters, filled at startup and then used to build the selected ones.
#[derive(Default)]
pub struct PluginRegistry {
    kinds: BTreeMap<&'static str, KindEntry>,
}

impl fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (kind, entry) in &self.kinds {
            map.entry(kind, &entry.plugins.keys().collect::<Vec<_>>());
        }
        map.finish()
    }
}

fn valid_plugin_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && name.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// Whether `table` is a usable dedicated table: a dotted key of lowercase words (`security.auth`) that is not one of the
/// tables of the plugin configuration itself.
fn validate_table(table: &str) -> Result<(), PluginError> {
    let invalid = |reason: &'static str| PluginError::InvalidTable {
        table: table.to_owned(),
        reason,
    };
    let words_ok = !table.is_empty()
        && table.split('.').all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
        });
    if !words_ok {
        return Err(invalid(
            "a dotted key of lowercase letters, digits, `-` and `_` (`security.auth`)",
        ));
    }
    if matches!(table.split('.').next(), Some("plugin" | "plugins")) {
        return Err(invalid(
            "`[plugin]` and `[plugins]` are the plugin configuration itself, not a table of one plugin",
        ));
    }
    Ok(())
}

impl PluginRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an adapter under `kind`.
    ///
    /// # Errors
    ///
    /// * [`PluginError::InvalidName`] when the descriptor's name is not a valid plugin name.
    /// * [`PluginError::DuplicateName`] when the kind already has a plugin of that name.
    /// * [`PluginError::InvalidTable`] when the dedicated table is not a dotted key of lowercase words, or is `plugin`,
    ///   `plugins` or a table under them.
    /// * [`PluginError::DuplicateTable`] when another registered plugin, of this kind or of another, names the same
    ///   dedicated table: a table has one owner, so that a plugin never receives the keys that are written for another.
    ///
    /// A refused descriptor changes nothing.
    pub fn register<P: ?Sized + 'static>(
        &mut self,
        kind: PortKind<P>,
        descriptor: PluginDescriptor<P>,
    ) -> Result<(), PluginError> {
        if !valid_plugin_name(descriptor.name) {
            return Err(PluginError::InvalidName {
                name: descriptor.name.to_owned(),
            });
        }
        if self.registered(kind.name(), descriptor.name).is_some() {
            return Err(PluginError::DuplicateName {
                kind: kind.name(),
                name: descriptor.name.to_owned(),
            });
        }
        if let Some(table) = descriptor.dedicated_table {
            validate_table(table)?;
            if let Some((owner_kind, owner)) = self
                .dedicated_tables()
                .into_iter()
                .find_map(|(owner_kind, owner, owned)| (owned == table).then_some((owner_kind, owner)))
            {
                return Err(PluginError::DuplicateTable {
                    table: table.to_owned(),
                    kind: owner_kind,
                    name: owner.to_owned(),
                });
            }
        }
        let entry = self.kinds.entry(kind.name()).or_insert_with(|| KindEntry {
            cardinality: kind.cardinality(),
            plugins: BTreeMap::new(),
        });
        entry.plugins.insert(
            descriptor.name,
            Registered {
                description: descriptor.description,
                config_schema: descriptor.config_schema,
                dedicated_table: descriptor.dedicated_table,
                check: descriptor.check,
                refused_in_production: descriptor.refused_in_production,
                descriptor: Box::new(descriptor),
            },
        );
        Ok(())
    }

    /// The names registered for `kind`, sorted.
    pub fn names<P: ?Sized + 'static>(&self, kind: PortKind<P>) -> Vec<&'static str> {
        self.kinds
            .get(kind.name())
            .map(|entry| entry.plugins.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The configuration schemas of every registered plugin, ordered by kind and name.
    pub fn schemas(&self) -> Vec<PluginSchema> {
        let mut schemas = Vec::new();
        for (kind, entry) in &self.kinds {
            for (name, registered) in &entry.plugins {
                schemas.push(PluginSchema {
                    kind,
                    name,
                    description: registered.description,
                    schema: (registered.config_schema)(),
                    dedicated_table: registered.dedicated_table,
                });
            }
        }
        schemas
    }

    /// The dedicated table that the plugin `name` of `kind` is configured by besides `[plugin.<kind>.<name>]`
    /// ([`PluginDescriptor::dedicated_table`]); `None` when the plugin is not registered or has none.
    pub fn dedicated_table(&self, kind: &str, name: &str) -> Option<&'static str> {
        self.registered(kind, name)
            .and_then(|registered| registered.dedicated_table)
    }

    /// Whether production mode refuses the plugin `name` of `kind` ([`PluginDescriptor::refused_in_production`]); `false`
    /// when the plugin is not registered. This is the one answer: [`build_single`](Self::build_single) and its siblings
    /// refuse with it, and `davhaven config check` reports with it.
    pub fn refused_in_production(&self, kind: &str, name: &str) -> bool {
        self.registered(kind, name)
            .is_some_and(|registered| registered.refused_in_production)
    }

    /// Every plugin that has a dedicated table besides `[plugin.<kind>.<name>]`, as `(kind, name, table)` ordered by kind
    /// and name ([`PluginDescriptor::dedicated_table`]).
    pub fn dedicated_tables(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        let mut found = Vec::new();
        for (kind, entry) in &self.kinds {
            for (name, registered) in &entry.plugins {
                if let Some(table) = registered.dedicated_table {
                    found.push((*kind, *name, table));
                }
            }
        }
        found
    }

    /// Asks the plugin `name` of `kind` to judge its configuration `table` without building it ([`CheckFn`]): the warnings
    /// it has, or the reason `build` would refuse the table. `None` when the plugin is not registered or has no check of its
    /// own, so that the caller can fall back to the plugin's JSON Schema.
    pub fn check_table(
        &self,
        kind: &str,
        name: &str,
        table: &serde_json::Value,
        mode: RunMode,
    ) -> Option<Result<Vec<String>, PluginError>> {
        let check = self.registered(kind, name)?.check?;
        Some(check(&PluginCheck::new(table, mode)))
    }

    fn registered(&self, kind: &str, name: &str) -> Option<&Registered> {
        self.kinds.get(kind).and_then(|entry| entry.plugins.get(name))
    }

    /// What is registered for every built-in kind, in [`KINDS`] order (kinds without plugins have an empty list).
    /// The registry introspection test asserts [`KindReport::is_sufficient`] for each.
    pub fn report(&self) -> Vec<KindReport> {
        KINDS
            .iter()
            .map(|info| KindReport {
                kind: *info,
                plugins: self
                    .kinds
                    .get(info.name)
                    .map(|entry| entry.plugins.keys().copied().collect())
                    .unwrap_or_default(),
            })
            .collect()
    }

    /// Builds the one plugin named `name` of a single kind.
    ///
    /// # Errors
    ///
    /// * [`PluginError::WrongCardinality`] when `kind` is not a single kind.
    /// * [`PluginError::Unknown`] when no plugin has that name.
    /// * Whatever the plugin's `build` returns (invalid configuration, missing dependency, startup failure).
    pub async fn build_single<P: ?Sized + 'static>(
        &self,
        kind: PortKind<P>,
        name: &str,
        ctx: &PluginContext,
        config: &ConfigTree,
    ) -> Result<Built<P>, PluginError> {
        require_cardinality(kind, Cardinality::Single)?;
        self.build_one(kind, name, ctx, config).await
    }

    /// Builds the plugins of a chain kind, in the order of `names`.
    ///
    /// # Errors
    ///
    /// * [`PluginError::WrongCardinality`] when `kind` is not a chain kind.
    /// * [`PluginError::EmptySelection`] when `names` is empty.
    /// * [`PluginError::DuplicateSelection`] when a name appears twice.
    /// * [`PluginError::Unknown`] and the plugins' own errors; the first failure stops the build.
    pub async fn build_chain<P: ?Sized + 'static, S: AsRef<str>>(
        &self,
        kind: PortKind<P>,
        names: &[S],
        ctx: &PluginContext,
        config: &ConfigTree,
    ) -> Result<Vec<Built<P>>, PluginError> {
        require_cardinality(kind, Cardinality::Chain)?;
        if names.is_empty() {
            return Err(PluginError::EmptySelection { kind: kind.name() });
        }
        self.build_many(kind, names, ctx, config).await
    }

    /// Builds the plugins of a set kind, in the order of `names`. An empty selection builds nothing.
    ///
    /// # Errors
    ///
    /// * [`PluginError::WrongCardinality`] when `kind` is not a set kind.
    /// * [`PluginError::DuplicateSelection`] when a name appears twice.
    /// * [`PluginError::Unknown`] and the plugins' own errors; the first failure stops the build.
    pub async fn build_set<P: ?Sized + 'static, S: AsRef<str>>(
        &self,
        kind: PortKind<P>,
        names: &[S],
        ctx: &PluginContext,
        config: &ConfigTree,
    ) -> Result<Vec<Built<P>>, PluginError> {
        require_cardinality(kind, Cardinality::Set)?;
        self.build_many(kind, names, ctx, config).await
    }

    async fn build_many<P: ?Sized + 'static, S: AsRef<str>>(
        &self,
        kind: PortKind<P>,
        names: &[S],
        ctx: &PluginContext,
        config: &ConfigTree,
    ) -> Result<Vec<Built<P>>, PluginError> {
        for (index, name) in names.iter().enumerate() {
            if names
                .iter()
                .take(index)
                .any(|earlier| earlier.as_ref() == name.as_ref())
            {
                return Err(PluginError::DuplicateSelection {
                    kind: kind.name(),
                    name: name.as_ref().to_owned(),
                });
            }
        }
        let mut built = Vec::with_capacity(names.len());
        for name in names {
            built.push(self.build_one(kind, name.as_ref(), ctx, config).await?);
        }
        Ok(built)
    }

    async fn build_one<P: ?Sized + 'static>(
        &self,
        kind: PortKind<P>,
        name: &str,
        ctx: &PluginContext,
        config: &ConfigTree,
    ) -> Result<Built<P>, PluginError> {
        let registered = self.kinds.get(kind.name()).and_then(|entry| entry.plugins.get(name));
        let Some(registered) = registered else {
            return Err(PluginError::Unknown {
                kind: kind.name(),
                name: name.to_owned(),
                available: self.names(kind),
            });
        };
        let Some(descriptor) = registered.descriptor.downcast_ref::<PluginDescriptor<P>>() else {
            return Err(PluginError::TypeMismatch {
                kind: kind.name(),
                name: name.to_owned(),
            });
        };
        // The descriptor says what production refuses; the plugin's own `build` is not asked.
        if descriptor.refused_in_production && ctx.mode.is_production() {
            return Err(PluginError::RefusedInProduction {
                plugin: name.to_owned(),
            });
        }
        let value = config
            .get(name)
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        (descriptor.build)(ctx.clone(), value).await
    }

    /// The cardinality a kind was registered with, if any plugin of the kind is registered.
    pub fn cardinality_of(&self, kind: &str) -> Option<Cardinality> {
        self.kinds.get(kind).map(|entry| entry.cardinality)
    }
}

fn require_cardinality<P: ?Sized + 'static>(kind: PortKind<P>, expected: Cardinality) -> Result<(), PluginError> {
    if kind.cardinality() == expected {
        Ok(())
    } else {
        Err(PluginError::WrongCardinality {
            kind: kind.name(),
            expected: kind.cardinality().as_str(),
        })
    }
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use davhaven_domain::{Envelope, OutgoingMail};
    use serde::Deserialize;

    use super::*;
    use crate::error::{HandlerError, PortError};
    use crate::mail::SendReceipt;
    use crate::worker::{Health, WorkReport};

    // --- test plugins ---------------------------------------------------------------------------------------

    struct NullMail;

    #[async_trait]
    impl MailTransport for NullMail {
        async fn send(&self, _mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
            Err(PortError::rejected("null transport"))
        }
    }

    struct NamedSink(&'static str);

    #[async_trait]
    impl EventSink for NamedSink {
        fn name(&self) -> &'static str {
            self.0
        }

        async fn deliver(&self, _envelope: &Envelope) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    struct IdleWorker(&'static str);

    #[async_trait]
    impl Worker for IdleWorker {
        fn name(&self) -> &'static str {
            self.0
        }

        fn interval(&self) -> Duration {
            Duration::from_secs(1)
        }

        async fn tick(&self) -> WorkReport {
            WorkReport::idle()
        }
    }

    struct CountingLifecycle(AtomicU32);

    #[async_trait]
    impl Lifecycle for CountingLifecycle {
        async fn health(&self) -> Health {
            Health::Healthy
        }

        async fn shutdown(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug, Default, Deserialize, JsonSchema)]
    #[serde(default, deny_unknown_fields)]
    struct MailConfig {
        /// How many workers the plugin starts.
        workers: usize,
        /// Whether the plugin refuses to start.
        fail: bool,
    }

    fn mail_schema() -> Schema {
        schemars::schema_for!(MailConfig)
    }

    fn empty_schema() -> Schema {
        schemars::json_schema!({"type": "object"})
    }

    fn build_mail(
        ctx: PluginContext,
        config: serde_json::Value,
    ) -> BoxFuture<'static, Result<Built<dyn MailTransport>, PluginError>> {
        Box::pin(async move {
            let config: MailConfig = parse_config("smtp", config)?;
            if config.fail {
                return Err(PluginError::build("smtp", PortError::unavailable("relay unreachable")));
            }
            ctx.refuse_in_production("smtp-dev")?;
            let workers: Vec<Arc<dyn Worker>> = (0..config.workers)
                .map(|_| -> Arc<dyn Worker> { Arc::new(IdleWorker("mail-worker")) })
                .collect();
            let port: Arc<dyn MailTransport> = Arc::new(NullMail);
            Ok(Built::new(port)
                .with_lifecycle(Arc::new(CountingLifecycle(AtomicU32::new(0))))
                .with_workers(workers))
        })
    }

    fn mail_descriptor(name: &'static str) -> PluginDescriptor<dyn MailTransport> {
        PluginDescriptor::new(name, "A test mail transport.", mail_schema, build_mail)
    }

    macro_rules! sink_descriptor {
        ($name:literal) => {
            PluginDescriptor::<dyn EventSink>::new($name, "A test sink.", empty_schema, |_ctx, _config| {
                Box::pin(async {
                    let sink: Arc<dyn EventSink> = Arc::new(NamedSink($name));
                    Ok(Built::new(sink))
                })
            })
        };
    }

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        registry
            .register(PortKind::MAIL_TRANSPORT, mail_descriptor("smtp"))
            .unwrap();
        registry
            .register(PortKind::MAIL_TRANSPORT, mail_descriptor("memory"))
            .unwrap();
        registry
            .register(PortKind::EVENT_SINK, sink_descriptor!("log"))
            .unwrap();
        registry
            .register(PortKind::EVENT_SINK, sink_descriptor!("audit"))
            .unwrap();
        registry
            .register(PortKind::EVENT_SINK, sink_descriptor!("noop"))
            .unwrap();
        registry
    }

    fn ctx() -> PluginContext {
        PluginContext::for_tests()
    }

    // --- registration and introspection ---------------------------------------------------------------------

    #[test]
    fn names_are_sorted_per_kind() {
        let registry = registry();
        assert_eq!(registry.names(PortKind::MAIL_TRANSPORT), vec!["memory", "smtp"]);
        assert_eq!(registry.names(PortKind::EVENT_SINK), vec!["audit", "log", "noop"]);
        assert_eq!(registry.names(PortKind::DATABASE), Vec::<&str>::new());
        assert_eq!(registry.cardinality_of("event_sink"), Some(Cardinality::Set));
        assert_eq!(registry.cardinality_of("database"), None);
    }

    #[test]
    fn duplicate_and_invalid_names_are_rejected() {
        let mut registry = registry();
        assert_eq!(
            registry.register(PortKind::MAIL_TRANSPORT, mail_descriptor("smtp")),
            Err(PluginError::DuplicateName {
                kind: "mail_transport",
                name: "smtp".to_owned()
            })
        );
        // The same name under another kind is fine.
        assert!(
            registry
                .register(PortKind::EVENT_SINK, sink_descriptor!("smtp"))
                .is_ok()
        );
        let too_long = "a".repeat(65);
        for bad in [
            "",
            "SMTP",
            "1smtp",
            "smtp server",
            "smtp.v2",
            "-smtp",
            too_long.as_str(),
        ] {
            let bad: &'static str = Box::leak(bad.to_owned().into_boxed_str());
            assert_eq!(
                registry.register(PortKind::MAIL_TRANSPORT, mail_descriptor(bad)),
                Err(PluginError::InvalidName { name: bad.to_owned() }),
                "{bad:?}"
            );
        }
        assert!(
            registry
                .register(PortKind::MAIL_TRANSPORT, mail_descriptor("smtp-2_b"))
                .is_ok()
        );
    }

    #[test]
    fn schemas_list_every_plugin_with_its_configuration_schema() {
        let schemas = registry().schemas();
        let keys: Vec<(&str, &str)> = schemas.iter().map(|schema| (schema.kind, schema.name)).collect();
        assert_eq!(
            keys,
            vec![
                ("event_sink", "audit"),
                ("event_sink", "log"),
                ("event_sink", "noop"),
                ("mail_transport", "memory"),
                ("mail_transport", "smtp"),
            ]
        );
        let smtp = schemas.iter().find(|schema| schema.name == "smtp").unwrap();
        assert_eq!(smtp.description, "A test mail transport.");
        let json = serde_json::to_value(&smtp.schema).unwrap();
        assert!(json["properties"]["workers"].is_object(), "{json}");
        assert!(json["properties"]["fail"].is_object(), "{json}");
        assert_eq!(json["additionalProperties"], false, "{json}");
    }

    #[test]
    fn built_in_kinds_are_consistent() {
        let expected = [
            (PortKind::HTTP_CLIENT.name(), Cardinality::Single),
            (PortKind::DATABASE.name(), Cardinality::Single),
            (PortKind::MAIL_TRANSPORT.name(), Cardinality::Single),
            (PortKind::TEMPLATES.name(), Cardinality::Single),
            (PortKind::RATE_LIMITER.name(), Cardinality::Single),
            (PortKind::SCHEDULING_POLICY.name(), Cardinality::Single),
            (PortKind::AUTHENTICATOR.name(), Cardinality::Chain),
            (PortKind::EVENT_SINK.name(), Cardinality::Set),
            (PortKind::OUTBOX_HANDLER.name(), Cardinality::Set),
            (PortKind::PROVIDER.name(), Cardinality::Set),
            (PortKind::CONTENT_SCANNER.name(), Cardinality::Set),
        ];
        let listed: Vec<(&str, Cardinality)> = KINDS.iter().map(|info| (info.name, info.cardinality)).collect();
        assert_eq!(listed, expected);
        let mut names: Vec<&str> = KINDS.iter().map(|info| info.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), KINDS.len(), "kind names are unique");
        let mut keys: Vec<&str> = KINDS.iter().map(|info| info.config_key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), KINDS.len(), "configuration keys are unique");
    }

    #[test]
    fn report_covers_every_kind_and_judges_sufficiency() {
        let report = registry().report();
        assert_eq!(report.len(), KINDS.len());
        let find = |name: &str| report.iter().find(|entry| entry.kind.name == name).unwrap();
        assert_eq!(find("mail_transport").plugins, vec!["memory", "smtp"]);
        assert!(find("mail_transport").is_sufficient());
        assert!(find("event_sink").is_sufficient());
        assert_eq!(find("database").plugins, Vec::<&str>::new());
        assert!(
            !find("database").is_sufficient(),
            "a kind without plugins is never sufficient"
        );

        let one = |info: KindInfo| KindReport {
            kind: info,
            plugins: vec!["only"],
        };
        let content_scanner = KINDS
            .iter()
            .find(|info| info.name == "content_scanner")
            .copied()
            .unwrap();
        let templates = KINDS.iter().find(|info| info.name == "templates").copied().unwrap();
        assert!(
            one(content_scanner).is_sufficient(),
            "an empty set is a documented default"
        );
        assert!(
            !one(templates).is_sufficient(),
            "a single kind needs a second implementation"
        );
    }

    // --- dedicated tables and checks -------------------------------------------------------------------------

    fn strict_check(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
        let config: MailConfig = parse_config("smtp", check.table.clone())?;
        if config.fail && check.mode.is_production() {
            return Err(PluginError::invalid_config("smtp", "`fail` is refused in production"));
        }
        Ok(if config.workers > 1 {
            vec!["more than one worker".to_owned()]
        } else {
            Vec::new()
        })
    }

    /// The builders are `const`, so a descriptor can stay a constant of its crate.
    const CONSTANT: PluginDescriptor<dyn MailTransport> =
        PluginDescriptor::new("constant", "A constant descriptor.", empty_schema, build_mail)
            .with_dedicated_table("security.relay");

    #[test]
    fn a_descriptor_records_its_own_table_and_check() {
        let plain = mail_descriptor("smtp");
        assert_eq!((plain.dedicated_table, plain.check.is_some()), (None, false));
        let described = mail_descriptor("smtp-2")
            .with_dedicated_table("mail.relay")
            .with_check(strict_check);
        assert_eq!(described.dedicated_table, Some("mail.relay"));
        assert!(described.check.is_some());
        assert_eq!(CONSTANT.dedicated_table, Some("security.relay"));
    }

    #[test]
    fn the_registry_reports_the_table_and_runs_the_check_of_a_plugin() {
        let mut registry = PluginRegistry::new();
        registry
            .register(
                PortKind::MAIL_TRANSPORT,
                mail_descriptor("smtp")
                    .with_dedicated_table("mail.relay")
                    .with_check(strict_check),
            )
            .unwrap();
        registry
            .register(PortKind::MAIL_TRANSPORT, mail_descriptor("memory"))
            .unwrap();

        assert_eq!(registry.dedicated_table("mail_transport", "smtp"), Some("mail.relay"));
        assert_eq!(registry.dedicated_table("mail_transport", "memory"), None);
        assert_eq!(registry.dedicated_table("mail_transport", "absent"), None);
        assert_eq!(
            registry.dedicated_table("database", "smtp"),
            None,
            "the kind is part of the key"
        );
        assert_eq!(
            registry.dedicated_tables(),
            vec![("mail_transport", "smtp", "mail.relay")],
            "only the plugins that have a table of their own are listed"
        );
        let tables: Vec<(&str, Option<&str>)> = registry
            .schemas()
            .iter()
            .map(|schema| (schema.name, schema.dedicated_table))
            .collect();
        assert_eq!(tables, vec![("memory", None), ("smtp", Some("mail.relay"))]);

        let warnings = registry
            .check_table(
                "mail_transport",
                "smtp",
                &serde_json::json!({"workers": 2}),
                RunMode::Dev,
            )
            .unwrap()
            .unwrap();
        assert_eq!(warnings, vec!["more than one worker".to_owned()]);
        let refused = registry
            .check_table(
                "mail_transport",
                "smtp",
                &serde_json::json!({"fail": true}),
                RunMode::Production,
            )
            .unwrap()
            .unwrap_err();
        assert!(refused.to_string().contains("production"), "{refused}");
        assert!(
            registry
                .check_table("mail_transport", "smtp", &serde_json::Value::Null, RunMode::Dev)
                .unwrap()
                .unwrap()
                .is_empty(),
            "a missing table is the defaults"
        );
        // No check of its own, or no such plugin: the caller falls back to the schema.
        assert!(
            registry
                .check_table("mail_transport", "memory", &serde_json::Value::Null, RunMode::Dev)
                .is_none()
        );
        assert!(
            registry
                .check_table("database", "smtp", &serde_json::Value::Null, RunMode::Dev)
                .is_none()
        );
    }

    #[test]
    fn a_dedicated_table_has_one_owner() {
        let mut registry = PluginRegistry::new();
        registry
            .register(
                PortKind::MAIL_TRANSPORT,
                mail_descriptor("smtp").with_dedicated_table("mail.relay"),
            )
            .unwrap();
        let owned = PluginError::DuplicateTable {
            table: "mail.relay".to_owned(),
            kind: "mail_transport",
            name: "smtp".to_owned(),
        };
        // Another plugin of the same kind, and a plugin of another kind: both would receive the keys written for `smtp`.
        assert_eq!(
            registry.register(
                PortKind::MAIL_TRANSPORT,
                mail_descriptor("smtp-2").with_dedicated_table("mail.relay")
            ),
            Err(owned.clone())
        );
        assert_eq!(
            registry.register(
                PortKind::EVENT_SINK,
                sink_descriptor!("relay-log").with_dedicated_table("mail.relay")
            ),
            Err(owned)
        );
        let shown = registry
            .register(
                PortKind::EVENT_SINK,
                sink_descriptor!("relay-log").with_dedicated_table("mail.relay"),
            )
            .unwrap_err()
            .to_string();
        assert!(
            shown.contains("[mail.relay]") && shown.contains("mail_transport plugin `smtp`"),
            "{shown}"
        );
        // A refused descriptor changes nothing, and a table that nobody owns is free.
        assert_eq!(registry.names(PortKind::EVENT_SINK), Vec::<&str>::new());
        assert_eq!(registry.names(PortKind::MAIL_TRANSPORT), vec!["smtp"]);
        assert_eq!(registry.cardinality_of("event_sink"), None);
        registry
            .register(
                PortKind::EVENT_SINK,
                sink_descriptor!("relay-log").with_dedicated_table("mail.relay-log"),
            )
            .unwrap();
        // The same plugin twice is still reported as a duplicate name, whatever table it names.
        assert!(matches!(
            registry.register(
                PortKind::MAIL_TRANSPORT,
                mail_descriptor("smtp").with_dedicated_table("mail.relay")
            ),
            Err(PluginError::DuplicateName { .. })
        ));
    }

    #[test]
    fn the_tables_of_the_plugin_configuration_and_malformed_tables_are_refused() {
        let mut registry = PluginRegistry::new();
        for table in [
            "plugin",
            "plugins",
            "plugin.mail_transport",
            "plugin.smtp.extra",
            "plugins.store",
        ] {
            let error = registry
                .register(
                    PortKind::MAIL_TRANSPORT,
                    mail_descriptor("smtp").with_dedicated_table(table),
                )
                .unwrap_err();
            assert!(
                matches!(&error, PluginError::InvalidTable { table: refused, .. } if refused == table),
                "{table}: {error}"
            );
            assert!(error.to_string().contains("plugin configuration"), "{error}");
        }
        for table in [
            "",
            ".",
            "a..b",
            "security.",
            "Security.Auth",
            "mail relay",
            "mail.re/lay",
        ] {
            let error = registry
                .register(
                    PortKind::MAIL_TRANSPORT,
                    mail_descriptor("smtp").with_dedicated_table(table),
                )
                .unwrap_err();
            assert!(matches!(error, PluginError::InvalidTable { .. }), "{table:?}: {error}");
        }
        assert_eq!(registry.names(PortKind::MAIL_TRANSPORT), Vec::<&str>::new());
        // Words that merely start like the reserved ones are fine.
        for (name, table) in [("a", "plugin-x"), ("b", "plugins_x"), ("c", "security.auth-2")] {
            registry
                .register(
                    PortKind::MAIL_TRANSPORT,
                    mail_descriptor(name).with_dedicated_table(table),
                )
                .unwrap();
        }
    }

    #[test]
    fn a_check_prints_its_mode_and_the_keys_of_its_table_and_never_a_value() {
        let table = serde_json::json!({"url": "postgres://app:hunter2@db/davhaven", "password": "hunter2"});
        let check = PluginCheck::new(&table, RunMode::Production);
        assert_eq!((check.table, check.mode), (&table, RunMode::Production));
        let shown = format!("{check:?}");
        assert!(
            shown.contains("Production") && shown.contains("url") && shown.contains("password"),
            "{shown}"
        );
        assert!(!shown.contains("hunter2") && !shown.contains("postgres://"), "{shown}");
        let none = serde_json::Value::Null;
        let shown = format!("{:?}", PluginCheck::new(&none, RunMode::Dev));
        assert!(shown.contains("Dev") && shown.contains("[]"), "{shown}");
    }

    #[tokio::test]
    async fn a_descriptor_that_production_refuses_is_refused_by_the_registry_in_production_only() {
        let mut registry = PluginRegistry::new();
        registry
            .register(
                PortKind::EVENT_SINK,
                sink_descriptor!("fake").with_refused_in_production(),
            )
            .unwrap();
        registry
            .register(PortKind::EVENT_SINK, sink_descriptor!("real"))
            .unwrap();
        assert!(registry.refused_in_production("event_sink", "fake"));
        assert!(!registry.refused_in_production("event_sink", "real"));
        assert!(
            !registry.refused_in_production("event_sink", "absent")
                && !registry.refused_in_production("database", "fake"),
            "an unknown plugin is not refused: the kind is part of the key"
        );
        let production = PluginContext {
            mode: RunMode::Production,
            ..ctx()
        };
        let tree = ConfigTree::new();
        assert_eq!(
            registry
                .build_set(PortKind::EVENT_SINK, &["fake"], &production, &tree)
                .await
                .map(|_| ())
                .unwrap_err(),
            PluginError::RefusedInProduction {
                plugin: "fake".to_owned()
            }
        );
        assert_eq!(
            registry
                .build_set(PortKind::EVENT_SINK, &["real", "fake"], &production, &tree)
                .await
                .map(|_| ())
                .unwrap_err(),
            PluginError::RefusedInProduction {
                plugin: "fake".to_owned()
            },
            "one refused member refuses the set"
        );
        assert_eq!(
            registry
                .build_set(PortKind::EVENT_SINK, &["real"], &production, &tree)
                .await
                .unwrap()
                .len(),
            1
        );
        let dev = PluginContext {
            mode: RunMode::Dev,
            ..ctx()
        };
        assert_eq!(
            registry
                .build_set(PortKind::EVENT_SINK, &["fake", "real"], &dev, &tree)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    // --- building -------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn build_single_passes_the_plugins_own_configuration() {
        let registry = registry();
        let config = ConfigTree::new().with("smtp", serde_json::json!({"workers": 2}));
        let built = registry
            .build_single(PortKind::MAIL_TRANSPORT, "smtp", &ctx(), &config)
            .await
            .unwrap();
        assert_eq!(built.workers.len(), 2);
        assert!(built.lifecycle.is_some());
        assert_eq!(built.workers[0].name(), "mail-worker");
        let shown = format!("{built:?}");
        assert!(shown.contains("mail-worker"), "{shown}");

        // Without a section the plugin builds with its defaults.
        let defaults = registry
            .build_single(PortKind::MAIL_TRANSPORT, "memory", &ctx(), &ConfigTree::new())
            .await
            .unwrap();
        assert!(defaults.workers.is_empty());
    }

    #[tokio::test]
    async fn build_single_reports_unknown_plugins_with_the_available_names() {
        let error = registry()
            .build_single(PortKind::MAIL_TRANSPORT, "smtpp", &ctx(), &ConfigTree::new())
            .await
            .unwrap_err();
        assert_eq!(
            error,
            PluginError::Unknown {
                kind: "mail_transport",
                name: "smtpp".to_owned(),
                available: vec!["memory", "smtp"]
            }
        );
        let none = PluginRegistry::new()
            .build_single(PortKind::DATABASE, "postgres", &ctx(), &ConfigTree::new())
            .await
            .unwrap_err();
        assert!(
            matches!(none, PluginError::Unknown { ref available, .. } if available.is_empty()),
            "{none}"
        );
    }

    #[tokio::test]
    async fn build_errors_surface_unchanged() {
        let registry = registry();
        let invalid = ConfigTree::new().with("smtp", serde_json::json!({"wrkers": 1}));
        let error = registry
            .build_single(PortKind::MAIL_TRANSPORT, "smtp", &ctx(), &invalid)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, PluginError::InvalidConfig { plugin, message } if plugin == "smtp" && message.contains("wrkers")),
            "{error}"
        );

        let failing = ConfigTree::new().with("smtp", serde_json::json!({"fail": true}));
        let error = registry
            .build_single(PortKind::MAIL_TRANSPORT, "smtp", &ctx(), &failing)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            PluginError::build("smtp", PortError::unavailable("relay unreachable"))
        );
    }

    #[tokio::test]
    async fn cardinality_is_enforced() {
        let registry = registry();
        let config = ConfigTree::new();
        let names = ["log"];
        assert_eq!(
            registry
                .build_single(PortKind::EVENT_SINK, "log", &ctx(), &config)
                .await
                .unwrap_err(),
            PluginError::WrongCardinality {
                kind: "event_sink",
                expected: "set"
            }
        );
        assert_eq!(
            registry
                .build_chain(PortKind::EVENT_SINK, &names, &ctx(), &config)
                .await
                .unwrap_err(),
            PluginError::WrongCardinality {
                kind: "event_sink",
                expected: "set"
            }
        );
        assert_eq!(
            registry
                .build_set(PortKind::MAIL_TRANSPORT, &names, &ctx(), &config)
                .await
                .unwrap_err(),
            PluginError::WrongCardinality {
                kind: "mail_transport",
                expected: "single"
            }
        );
    }

    #[tokio::test]
    async fn sets_build_in_the_order_given_and_may_be_empty() {
        let registry = registry();
        let config = ConfigTree::new();
        let built = registry
            .build_set(PortKind::EVENT_SINK, &["noop", "log"], &ctx(), &config)
            .await
            .unwrap();
        let names: Vec<&str> = built.iter().map(|built| built.port.name()).collect();
        assert_eq!(names, vec!["noop", "log"]);

        let empty: [&str; 0] = [];
        assert!(
            registry
                .build_set(PortKind::EVENT_SINK, &empty, &ctx(), &config)
                .await
                .unwrap()
                .is_empty()
        );

        let owned = vec!["audit".to_owned()];
        assert_eq!(
            registry
                .build_set(PortKind::EVENT_SINK, &owned, &ctx(), &config)
                .await
                .unwrap()
                .len(),
            1
        );

        assert_eq!(
            registry
                .build_set(PortKind::EVENT_SINK, &["log", "audit", "log"], &ctx(), &config)
                .await
                .unwrap_err(),
            PluginError::DuplicateSelection {
                kind: "event_sink",
                name: "log".to_owned()
            }
        );
        assert!(matches!(
            registry
                .build_set(PortKind::EVENT_SINK, &["log", "missing"], &ctx(), &config)
                .await
                .unwrap_err(),
            PluginError::Unknown { name, .. } if name == "missing"
        ));
    }

    #[tokio::test]
    async fn chains_need_at_least_one_plugin() {
        let registry = PluginRegistry::new();
        let empty: [&str; 0] = [];
        assert_eq!(
            registry
                .build_chain(PortKind::AUTHENTICATOR, &empty, &ctx(), &ConfigTree::new())
                .await
                .unwrap_err(),
            PluginError::EmptySelection { kind: "authenticator" }
        );
        assert!(matches!(
            registry
                .build_chain(PortKind::AUTHENTICATOR, &["local"], &ctx(), &ConfigTree::new())
                .await
                .unwrap_err(),
            PluginError::Unknown { .. }
        ));
    }

    #[tokio::test]
    async fn a_descriptor_registered_for_another_port_type_is_a_type_mismatch() {
        let mut registry = PluginRegistry::new();
        // A rogue kind that reuses the name of the database kind but produces mail transports.
        let rogue = PortKind::<dyn MailTransport>::new("database", Cardinality::Single);
        registry.register(rogue, mail_descriptor("sneaky")).unwrap();
        let error = registry
            .build_single(PortKind::DATABASE, "sneaky", &ctx(), &ConfigTree::new())
            .await
            .unwrap_err();
        assert_eq!(
            error,
            PluginError::TypeMismatch {
                kind: "database",
                name: "sneaky".to_owned()
            }
        );
    }

    // --- context, config tree and run mode ------------------------------------------------------------------

    #[tokio::test]
    async fn production_mode_is_visible_to_plugins() {
        let mut registry = PluginRegistry::new();
        registry
            .register(PortKind::MAIL_TRANSPORT, mail_descriptor("smtp"))
            .unwrap();
        let production = PluginContext {
            mode: RunMode::Production,
            ..ctx()
        };
        // `build_mail` refuses the "smtp-dev" guard in production.
        let error = registry
            .build_single(PortKind::MAIL_TRANSPORT, "smtp", &production, &ConfigTree::new())
            .await
            .unwrap_err();
        assert_eq!(
            error,
            PluginError::RefusedInProduction {
                plugin: "smtp-dev".to_owned()
            }
        );
        let dev = PluginContext {
            mode: RunMode::Dev,
            ..ctx()
        };
        assert!(
            registry
                .build_single(PortKind::MAIL_TRANSPORT, "smtp", &dev, &ConfigTree::new())
                .await
                .is_ok()
        );
    }

    #[test]
    fn context_requires_lower_tiers() {
        let ctx = ctx();
        assert!(ctx.database.is_none() && ctx.http.is_none());
        assert_eq!(
            ctx.require_database("outbox").err(),
            Some(PluginError::MissingDependency {
                plugin: "outbox".to_owned(),
                dependency: "database"
            })
        );
        assert_eq!(
            ctx.require_http("webhook").err(),
            Some(PluginError::MissingDependency {
                plugin: "webhook".to_owned(),
                dependency: "http client"
            })
        );
        let shown = format!("{ctx:?}");
        assert!(shown.contains("database: false"), "{shown}");
        assert_eq!(
            ctx.failure_backoff,
            FailureBackoff::default(),
            "the backoff is on without configuration"
        );
        let tuned = FailureBackoff {
            base: std::time::Duration::from_secs(7),
            ..FailureBackoff::default()
        };
        assert_eq!(ctx.with_failure_backoff(tuned).failure_backoff, tuned);
        assert_eq!(RunMode::default(), RunMode::Production);
        assert!(RunMode::Production.is_production() && !RunMode::Dev.is_production());
        assert_eq!(RunMode::Dev.to_string(), "dev");
        assert_eq!(serde_json::to_string(&RunMode::Production).unwrap(), "\"production\"");
        assert_eq!(serde_json::from_str::<RunMode>("\"dev\"").unwrap(), RunMode::Dev);
    }

    #[test]
    fn config_trees_validate_their_shape_and_hide_values() {
        let tree = ConfigTree::from_json(serde_json::json!({
            "smtp": {"host": "mail.example.org", "password": "hunter2"},
            "log": null,
        }))
        .unwrap();
        assert_eq!(tree.plugin_names().collect::<Vec<_>>(), vec!["log", "smtp"]);
        assert!(tree.get("smtp").unwrap().is_object());
        assert!(tree.get("absent").is_none());
        let shown = format!("{tree:?}");
        assert!(shown.contains("smtp"), "{shown}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("mail.example.org"),
            "{shown}"
        );

        assert!(ConfigTree::from_json(serde_json::json!([1])).is_err());
        let error = ConfigTree::from_json(serde_json::json!({"smtp": "host=x"})).unwrap_err();
        assert!(
            matches!(error, PluginError::InvalidConfig { ref plugin, .. } if plugin == "smtp"),
            "{error}"
        );
    }

    #[test]
    fn parse_config_applies_defaults_and_rejects_unknown_keys() {
        let defaults: MailConfig = parse_config("smtp", serde_json::Value::Null).unwrap();
        assert_eq!(defaults.workers, 0);
        let empty: MailConfig = parse_config("smtp", serde_json::json!({})).unwrap();
        assert!(!empty.fail);
        let set: MailConfig = parse_config("smtp", serde_json::json!({"workers": 3})).unwrap();
        assert_eq!(set.workers, 3);
        let error = parse_config::<MailConfig>("smtp", serde_json::json!({"workers": "many"})).unwrap_err();
        assert!(
            matches!(error, PluginError::InvalidConfig { ref plugin, .. } if plugin == "smtp"),
            "{error}"
        );
    }

    #[test]
    fn registries_debug_print_names_only() {
        let shown = format!("{:?}", registry());
        assert!(shown.contains("mail_transport") && shown.contains("smtp"), "{shown}");
        assert!(
            !shown.contains("A test mail transport.") && !shown.contains("workers"),
            "neither descriptions nor configuration schemas: {shown}"
        );
    }
}
