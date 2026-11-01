//! The configuration of plugins: which table belongs to which adapter, and the checks of `davhaven config check`.
//!
//! A plugin is configured by one table, found by the **kind** and the name of the plugin, because names repeat across
//! kinds (`memory` is the store, the mail transport and the rate limiter; `noop` is an authenticator, an outbox handler
//! and a rate limiter):
//!
//! | Written as | Applies to |
//! | --- | --- |
//! | `[plugin.<kind>.<name>]` (`[plugin.mail_transport.memory]`) | the plugin `<name>` of that kind, always |
//! | `[plugin.<name>]` (`[plugin.smtp]`) | the plugin `<name>`, **when it is selected for one kind only**; a name that is selected for several kinds makes the table ambiguous, which is an error that names the qualified spellings |
//! | the dedicated table of the plan (`[database]` for `postgres`, `[security.auth]` for `local`, `[security.egress]` for `egress`, `[webhooks]` for `webhook`, `[templates]` for `minijinja`) | the plugin whose descriptor names it ([`PluginDescriptor::dedicated_table`](davhaven_ports::PluginDescriptor::dedicated_table)); the server reads the table by that key ([`Config::dedicated_table`](crate::config::Config::dedicated_table)). A dedicated table has one owner (the registry refuses a second descriptor that names it) and belongs to one kind of plugin ([`DEDICATED_TABLES`]): a descriptor of another kind that names it is refused |
//!
//! The server resolves them per selected plugin ([`plugin_tables`]) and hands the registry one tree per kind
//! ([`PluginTables::tree`]), so an adapter parses and validates exactly its own table whichever way it was written down
//! and never sees the table of another kind. A key written in two places of one plugin is an error.
//!
//! [`check`] is what `davhaven config check` runs, and what `serve` runs before it builds anything: the typed
//! sections, the plugin selection, every selected plugin's table, the key ring, and the rules that connect sections (the
//! SMTP send timeout against the outbox lease). It needs no database and opens no connection. **Every plugin judges its
//! own table**: its descriptor carries a check ([`PluginDescriptor::check`](davhaven_ports::PluginDescriptor::check))
//! that parses the table into the configuration struct of the adapter, applies the validation that `build` applies, reads
//! the files the table names and says what is allowed but probably not intended; the server knows no adapter by name for
//! this. A plugin that has no check of its own is checked against the JSON Schema it published, so a typo in its table
//! fails with the key's name as well, and the full validation happens when it is built. A table for an adapter that does
//! not exist is an error with the list of the adapters that do; a table for an adapter that is not selected is a warning,
//! and so is a dedicated table that is set while the build has no adapter that reads it (`[database]` in a build without the
//! PostgreSQL store): the table would be ignored, and a security setting in it would do nothing without a word.
//!
//! The adapters that refuse an unencrypted transport in production (the SMTP relay, the database connection) are asked
//! their own rule, which they apply in `build` as well, so that the check says what `serve` will say. What they accept
//! anyway (traffic that travels unencrypted because the operator allowed it, an opt-in that no longer has an effect)
//! comes back as warnings; the template renderer loads its themes, so that a theme that does not exist or a broken
//! template fails here and not at the first mail.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use davhaven_crypto_local::keyring::KeyMaterial;
use davhaven_crypto_local::profile::ReloadingProfileSigner;
use davhaven_domain::PublicUrls;
#[cfg(feature = "mail-smtp")]
use davhaven_ports::parse_config;
use davhaven_ports::plugin::KINDS;
use davhaven_ports::{
    Clock, ConfigTree, KindInfo, PluginError, PluginRegistry, PluginSchema, ProfileSigner, RunMode, SystemClock, Worker,
};
use ipnet::IpNet;
use serde_json::{Map, Value};
use url::Url;

use crate::config::{Config, ConfigError, DEDICATED_TABLES, DedicatedTable, PluginsConfig};
use crate::error::ServerError;
use crate::listeners::{ResolvedListener, RouteGroup};
use crate::profile_signing::ProfileSigningWorker;
use crate::schema::{defaults_tree, merge, unknown_keys};

/// The plugins chosen for one kind, from `[plugins]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The facts about the kind.
    pub kind: KindInfo,
    /// The selected plugin names, in order (one for single kinds).
    pub names: Vec<String>,
}

/// The selection of every kind, in the order of [`KINDS`], read from `[plugins]` by the key each kind declares.
///
/// # Errors
///
/// [`ConfigError::Invalid`] for a kind of the registry that `[plugins]` has no key for.
pub fn selections(plugins: &PluginsConfig) -> Result<Vec<Selection>, ConfigError> {
    KINDS
        .iter()
        .map(|kind| {
            Ok(Selection {
                kind: *kind,
                names: plugins.names(kind)?,
            })
        })
        .collect()
}

/// An error for a plugin table.
fn invalid(reason: String) -> ConfigError {
    ConfigError::Invalid { key: "plugin", reason }
}

/// Whether a table has no keys (absent, null or an empty table).
pub fn is_empty_table(value: &Value) -> bool {
    value.is_null() || value.as_object().is_some_and(Map::is_empty)
}

/// Joins two tables of one plugin; a key in both is an error because the operator would not know which one wins.
fn join(first: Option<Value>, first_place: &str, second: &Value, second_place: &str) -> Result<Value, ConfigError> {
    let Some(second) = second.as_object() else {
        return Err(invalid(format!("{second_place} must be a table")));
    };
    let mut merged = match first {
        Some(Value::Object(members)) => members,
        _ => Map::new(),
    };
    for (key, value) in second {
        if merged.contains_key(key) {
            return Err(invalid(format!(
                "`{key}` is set in both {first_place} and {second_place}; set it in one place"
            )));
        }
        merged.insert(key.clone(), value.clone());
    }
    Ok(Value::Object(merged))
}

/// A table that belongs to no selected plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnselectedTable {
    /// The kind, when the table was written for one (`[plugin.<kind>.<name>]`, or a dedicated table).
    pub kind: Option<&'static str>,
    /// The plugin name.
    pub name: String,
}

/// The configuration table of every selected plugin that has one, by kind and name.
#[derive(Clone, Default)]
pub struct PluginTables {
    tables: BTreeMap<(&'static str, String), Value>,
    unselected: Vec<UnselectedTable>,
}

impl core::fmt::Debug for PluginTables {
    /// Prints the names only: the values can carry inline secrets.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: Vec<String> = self
            .tables
            .keys()
            .map(|(kind, name)| format!("{kind}:{name}"))
            .collect();
        f.debug_struct("PluginTables")
            .field("tables", &names)
            .field("unselected", &self.unselected)
            .finish()
    }
}

impl PluginTables {
    /// The table of the plugin `name` of `kind`, when the deployment wrote one.
    pub fn get(&self, kind: &str, name: &str) -> Option<&Value> {
        self.tables
            .iter()
            .find(|((table_kind, table_name), _)| *table_kind == kind && table_name == name)
            .map(|(_, value)| value)
    }

    /// The tables of the plugins of `kind` as the registry's configuration tree: it holds only this kind's tables, so
    /// a plugin of another kind with the same name cannot receive them.
    pub fn tree(&self, kind: &str) -> ConfigTree {
        self.tables
            .iter()
            .filter(|((table_kind, _), _)| *table_kind == kind)
            .fold(ConfigTree::new(), |tree, ((_, name), value)| {
                tree.with(name.clone(), value.clone())
            })
    }

    /// Every table with its kind and plugin name.
    pub fn entries(&self) -> impl Iterator<Item = (&'static str, &str, &Value)> {
        self.tables
            .iter()
            .map(|((kind, name), value)| (*kind, name.as_str(), value))
    }

    /// The tables that belong to no selected plugin.
    pub fn unselected(&self) -> &[UnselectedTable] {
        &self.unselected
    }
}

/// The kinds a plugin name is selected for.
fn kinds_selecting<'a>(selections: &'a [Selection], name: &str) -> Vec<&'a str> {
    selections
        .iter()
        .filter(|selection| selection.names.iter().any(|selected| selected == name))
        .map(|selection| selection.kind.name)
        .collect()
}

/// The `[plugin]` tables of the deployment, set apart by how they are written.
struct Written<'a> {
    /// `[plugin.<name>]`, by plugin name.
    unqualified: BTreeMap<&'a str, &'a Value>,
    /// `[plugin.<kind>.<name>]`, by kind and plugin name.
    qualified: BTreeMap<(&'static str, &'a str), &'a Value>,
}

/// Sorts the members of `[plugin]` into the table of a kind (`[plugin.mail_transport]`, whose members are the plugins of
/// that kind) and the table of a plugin (`[plugin.smtp]`). Empty tables are left out.
fn written(config: &Config) -> Result<Written<'_>, ConfigError> {
    let mut found = Written {
        unqualified: BTreeMap::new(),
        qualified: BTreeMap::new(),
    };
    for (key, value) in &config.plugin {
        if let Some(kind) = KINDS.iter().find(|kind| kind.name == key) {
            if value.is_null() {
                continue;
            }
            let Some(members) = value.as_object() else {
                return Err(invalid(format!(
                    "[plugin.{key}] must be a table of the plugins of the kind `{key}`"
                )));
            };
            for (name, table) in members {
                if !(table.is_object() || table.is_null()) {
                    return Err(invalid(format!("[plugin.{key}.{name}] must be a table")));
                }
                if !is_empty_table(table) {
                    found.qualified.insert((kind.name, name), table);
                }
            }
        } else {
            if !(value.is_object() || value.is_null()) {
                return Err(invalid(format!("[plugin.{key}] must be a table")));
            }
            if !is_empty_table(value) {
                found.unqualified.insert(key, value);
            }
        }
    }
    Ok(found)
}

/// The dedicated table that the descriptor of the plugin `name` of `kind` names (`security.auth` for the local
/// authenticator), as this server knows it. `None` when the plugin names none.
///
/// A table is the table of one kind of plugin ([`DEDICATED_TABLES`]): a descriptor that names a table this server does not
/// read, or the table of another kind, is an error, because the table of the database, with its URLs and credentials, must
/// never reach a content scanner. That the table has one owner among the registered plugins is the registry's rule
/// (`PluginRegistry::register`).
fn dedicated_entry(
    registry: &PluginRegistry,
    kind: &str,
    name: &str,
) -> Result<Option<&'static DedicatedTable>, ConfigError> {
    let Some(table) = registry.dedicated_table(kind, name) else {
        return Ok(None);
    };
    let Some(entry) = DEDICATED_TABLES.iter().find(|entry| entry.key == table) else {
        return Err(invalid(format!(
            "the plugin `{name}` of the kind `{kind}` is configured by the table `[{table}]`, but this server reads no \
             table of that name (a descriptor may only name one of {})",
            DEDICATED_TABLES
                .iter()
                .map(|entry| entry.key)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    };
    if entry.kind != kind {
        return Err(invalid(format!(
            "the plugin `{name}` of the kind `{kind}` names the table `[{table}]`, which is the table of the kind `{}`: a \
             plugin may only be configured by the dedicated table of its own kind",
            entry.kind
        )));
    }
    Ok(Some(entry))
}

/// The dedicated table of the plugin `name` of `kind` and its place for messages. `None` when the plugin has none or the
/// deployment wrote none.
fn dedicated_of<'a>(
    config: &'a Config,
    registry: &PluginRegistry,
    kind: &str,
    name: &str,
) -> Result<Option<(&'a Value, &'static str)>, ConfigError> {
    let Some(entry) = dedicated_entry(registry, kind, name)? else {
        return Ok(None);
    };
    let value = entry.value(config);
    if is_empty_table(value) {
        return Ok(None);
    }
    if !value.is_object() {
        return Err(invalid(format!("[{}] must be a table", entry.key)));
    }
    Ok(Some((value, entry.key)))
}

/// The tables of one selected plugin joined into one: the dedicated table, `[plugin.<kind>.<name>]` and `[plugin.<name>]`.
/// `None` when the deployment wrote none. Records which written tables were used.
fn table_of(
    config: &Config,
    registry: &PluginRegistry,
    selections: &[Selection],
    written: &Written<'_>,
    kind: &'static str,
    name: &str,
    used: &mut Used,
) -> Result<Option<Value>, ConfigError> {
    let mut merged: Option<Value> = None;
    let mut place = String::new();
    if let Some((value, table)) = dedicated_of(config, registry, kind, name)? {
        merged = Some(value.clone());
        place = format!("[{table}]");
    }
    if let Some(table) = written.qualified.get(&(kind, name)) {
        used.qualified.insert((kind, name.to_owned()));
        let here = format!("[plugin.{kind}.{name}]");
        merged = Some(join(merged, &place, table, &here)?);
        place = here;
    }
    if let Some(table) = written.unqualified.get(name) {
        let kinds = kinds_selecting(selections, name);
        if kinds.len() > 1 {
            let spellings: Vec<String> = kinds.iter().map(|kind| format!("[plugin.{kind}.{name}]")).collect();
            return Err(invalid(format!(
                "[plugin.{name}] is ambiguous: `{name}` is selected for {} kinds of plugins ({}), and each takes its own \
                 table; write {} instead",
                kinds.len(),
                kinds.join(", "),
                spellings.join(" or ")
            )));
        }
        used.unqualified.insert(name.to_owned());
        merged = Some(join(merged, &place, table, &format!("[plugin.{name}]"))?);
    }
    Ok(merged)
}

/// Which written tables belong to a selected plugin.
#[derive(Default)]
struct Used {
    unqualified: BTreeSet<String>,
    qualified: BTreeSet<(&'static str, String)>,
}

/// The configuration table of every selected plugin: see the module documentation for where a table can be written.
///
/// # Errors
///
/// An error when a table is not a table, a key is set in two places of one plugin, or `[plugin.<name>]` is ambiguous
/// because the name is selected for more than one kind.
pub fn plugin_tables(
    config: &Config,
    registry: &PluginRegistry,
    selections: &[Selection],
) -> Result<PluginTables, ConfigError> {
    let written = written(config)?;
    let mut tables: BTreeMap<(&'static str, String), Value> = BTreeMap::new();
    let mut used = Used::default();
    for selection in selections {
        for name in &selection.names {
            if let Some(table) = table_of(
                config,
                registry,
                selections,
                &written,
                selection.kind.name,
                name,
                &mut used,
            )? {
                tables.insert((selection.kind.name, name.clone()), table);
            }
        }
    }

    let mut unselected = Vec::new();
    for name in written.unqualified.keys() {
        if !used.unqualified.contains(*name) {
            unselected.push(UnselectedTable {
                kind: None,
                name: (*name).to_owned(),
            });
        }
    }
    for (kind, name) in written.qualified.keys() {
        if !used.qualified.contains(&(*kind, (*name).to_owned())) {
            unselected.push(UnselectedTable {
                kind: Some(*kind),
                name: (*name).to_owned(),
            });
        }
    }
    for (kind, name, _table) in registry.dedicated_tables() {
        let selected = selections
            .iter()
            .any(|selection| selection.kind.name == kind && selection.names.iter().any(|selected| selected == name));
        if selected {
            continue;
        }
        if let Some(entry) = dedicated_entry(registry, kind, name)?
            && !is_empty_table(entry.value(config))
        {
            unselected.push(UnselectedTable {
                kind: Some(kind),
                name: name.to_owned(),
            });
        }
    }
    Ok(PluginTables { tables, unselected })
}

/// The dedicated tables that the deployment wrote and that no plugin of this build reads: written for an adapter that is not
/// compiled in (`[database]` in a build without the PostgreSQL store, `[security.auth]` without the local authenticator).
/// Without this the table would be ignored without a word, and with it a typo or a security setting (the auth backoff, the
/// egress policy, the provider tables) that does nothing would go unnoticed.
fn unread_tables(config: &Config, registry: &PluginRegistry) -> Vec<String> {
    let read: BTreeSet<&str> = registry
        .dedicated_tables()
        .into_iter()
        .map(|(_kind, _name, table)| table)
        .collect();
    DEDICATED_TABLES
        .iter()
        .filter(|entry| !read.contains(entry.key) && !is_empty_table(entry.value(config)))
        .map(|entry| {
            format!(
                "[{}] is set, but no adapter of this build reads it: the build has no {} plugin that is configured by it",
                entry.key, entry.kind
            )
        })
        .collect()
}

/// The profile signer that the check built: the start takes this one, so the key that passed the check (it belongs to the
/// certificate) is the one that signs, and the files are read and parsed once. It is the signer that follows its files
/// ([`ReloadingProfileSigner`]): the start adds the worker that looks at them ([`CheckedProfileSigner::worker`]).
#[derive(Debug, Clone, Default)]
pub struct CheckedProfileSigner(Option<Arc<ReloadingProfileSigner>>);

impl CheckedProfileSigner {
    /// The signer as the port the application injects, or `None` when profile signing is off.
    pub fn port(&self) -> Option<Arc<dyn ProfileSigner>> {
        self.0.clone().map(|signer| -> Arc<dyn ProfileSigner> { signer })
    }

    /// The worker that keeps the signer current with its files and publishes the expiry of its certificate, or `None` when
    /// profile signing is off. It takes its time from `clock`.
    pub fn worker(&self, clock: Arc<dyn Clock>) -> Option<Arc<dyn Worker>> {
        self.0
            .as_ref()
            .map(|signer| -> Arc<dyn Worker> { Arc::new(ProfileSigningWorker::new(Arc::clone(signer), clock)) })
    }

    /// Whether profile signing is on.
    pub const fn is_on(&self) -> bool {
        self.0.is_some()
    }
}

impl PartialEq for CheckedProfileSigner {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for CheckedProfileSigner {}

/// What a check found besides errors.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CheckReport {
    /// Things that are allowed but probably not intended (a table for an adapter that is not selected, mail or database
    /// traffic that travels unencrypted because the operator accepted it, an opt-in that no longer has an effect).
    pub warnings: Vec<String>,
    /// The plugins chosen for every kind.
    pub selections: Vec<Selection>,
    /// The plugins that have a configuration table, as `kind:name`.
    pub tables: Vec<String>,
    /// The enabled listeners with their defaults applied.
    pub listeners: Vec<ResolvedListener>,
    /// The ids of the keys of the key ring and which one is active.
    pub keys: Vec<String>,
    /// The id of the active key, when the key ring is configured.
    pub active_key: Option<String>,
    /// The signer of Apple configuration profiles that `[security.profile_signing]` names, built by the check (off when it
    /// names no files).
    pub profile_signer: CheckedProfileSigner,
}

/// The names registered for `kind`.
fn available(registry: &PluginRegistry, kind: &str) -> Vec<&'static str> {
    registry
        .report()
        .into_iter()
        .find(|entry| entry.kind.name == kind)
        .map(|entry| entry.plugins)
        .unwrap_or_default()
}

/// Checks that no kind selects a plugin twice or nothing where something is needed, and that every selected plugin
/// exists in `registry`.
fn check_selection(registry: &PluginRegistry, selections: &[Selection], mode: RunMode) -> Result<(), ConfigError> {
    for selection in selections {
        let available = available(registry, selection.kind.name);
        if selection.kind.cardinality == davhaven_ports::Cardinality::Chain && selection.names.is_empty() {
            return Err(PluginError::EmptySelection {
                kind: selection.kind.name,
            }
            .into());
        }
        for (index, name) in selection.names.iter().enumerate() {
            if selection.names.iter().take(index).any(|earlier| earlier == name) {
                return Err(PluginError::DuplicateSelection {
                    kind: selection.kind.name,
                    name: name.clone(),
                }
                .into());
            }
            if !available.contains(&name.as_str()) {
                return Err(PluginError::Unknown {
                    kind: selection.kind.name,
                    name: name.clone(),
                    available,
                }
                .into());
            }
            // What production refuses is the flag of the descriptor: the registry refuses to build the plugin in production
            // with the same flag, so `config check` and `serve` cannot differ.
            if mode.is_production() && registry.refused_in_production(selection.kind.name, name) {
                return Err(invalid(format!(
                    "plugins.{} selects `{name}`, which is refused when server.mode is \"production\": it drops or fakes \
                     work (the memory adapters lose their data at a restart, the test fakes only pretend); choose a \
                     production adapter, or set server.mode = \"dev\" for development",
                    selection.kind.config_key
                )));
            }
        }
    }
    Ok(())
}

/// Sorts the tables that belong to no selected plugin into errors (they name no adapter of this build) and warnings.
fn check_unselected(
    registry: &PluginRegistry,
    unselected: &[UnselectedTable],
    warnings: &mut Vec<String>,
) -> Result<(), ConfigError> {
    let report = registry.report();
    let known: BTreeSet<&str> = report.iter().flat_map(|entry| entry.plugins.iter().copied()).collect();
    for table in unselected {
        match table.kind {
            None => {
                if !known.contains(table.name.as_str()) {
                    return Err(invalid(format!(
                        "[plugin.{}] names no adapter of this build (adapters: {})",
                        table.name,
                        known.iter().copied().collect::<Vec<_>>().join(", ")
                    )));
                }
                warnings.push(format!(
                    "the configuration of the adapter `{}` is set, but `[plugins]` does not select it",
                    table.name
                ));
            }
            Some(kind) => {
                let registered = available(registry, kind);
                if !registered.contains(&table.name.as_str()) {
                    return Err(invalid(format!(
                        "[plugin.{kind}.{}] names no adapter of the kind `{kind}` in this build (adapters: {})",
                        table.name,
                        registered.join(", ")
                    )));
                }
                warnings.push(format!(
                    "the configuration of the {kind} adapter `{}` is set, but `[plugins]` does not select it",
                    table.name
                ));
            }
        }
    }
    Ok(())
}

/// Checks the whole configuration without a database: see the module documentation.
///
/// # Errors
///
/// The first problem found, naming the key.
pub fn check(config: &Config, registry: &PluginRegistry) -> Result<CheckReport, ConfigError> {
    config.validate()?;
    let selections = selections(&config.plugins)?;
    check_selection(registry, &selections, config.server.mode)?;

    let tables = plugin_tables(config, registry, &selections)?;
    let mut warnings = Vec::new();
    check_unselected(registry, tables.unselected(), &mut warnings)?;
    warnings.extend(unread_tables(config, registry));

    let schemas = registry.schemas();
    let none = Value::Null;
    for selection in &selections {
        for name in &selection.names {
            let table = tables.get(selection.kind.name, name).unwrap_or(&none);
            validate_plugin(
                registry,
                &schemas,
                selection.kind.name,
                name,
                table,
                config.server.mode,
                &mut warnings,
            )?;
        }
    }
    warnings.extend(observability_warnings(config));
    warnings.extend(exposure_warnings(config, &tables));
    cross_checks(config, &tables)?;

    let key_config = config.security.key_ring_config();
    let (keys, active_key) = if config.security.keys.is_empty() {
        (Vec::new(), None)
    } else {
        // Reads every secret file: an unreadable or short secret fails here and not at the first request.
        let material = KeyMaterial::from_config(&key_config)?;
        (
            material.kids().map(str::to_owned).collect(),
            Some(material.active_kid().to_owned()),
        )
    };
    if config.security.keys.is_empty() {
        warnings.push(EPHEMERAL_KEYS_WARNING.to_owned());
    }
    // Reads the certificate and the key of the profile signer: a pair that does not fit fails here and not at the start, and
    // the signer that passes is the one the start uses. A certificate that has run out, or is about to, is worth a word; a
    // running server picks up a renewal by itself, so the word is to renew it, not to restart.
    let profile_signer =
        CheckedProfileSigner(ReloadingProfileSigner::from_config(&config.security.profile_signing)?.map(Arc::new));
    if let Some(signer) = &profile_signer.0
        && let Some(warning) = signer.expiry_warning(SystemClock.now())
    {
        warnings.push(warning);
    }
    Ok(CheckReport {
        warnings,
        tables: tables
            .entries()
            .map(|(kind, name, _)| format!("{kind}:{name}"))
            .collect(),
        listeners: config.server.listeners.resolved(),
        selections,
        keys,
        active_key,
        profile_signer,
    })
}

/// [`check`] on the blocking pool of the runtime.
///
/// The check reads the key and certificate files and loads and renders every theme (the template renderer judges its own
/// table by doing what its build does), which is blocking work: it must not run on a thread of the runtime that is about
/// to serve requests (`ENGINEERING_RULES` R14). Every entry that checks the configuration from async code goes through this
/// function: `davhaven serve`, `config check` and the administrative commands (`cli::load_checked`), and the entries
/// of the assembly ([`assemble`](crate::assembly::assemble), [`assemble_with_ports`](crate::assembly::assemble_with_ports)).
///
/// # Errors
///
/// As [`check`]; [`ServerError::Task`] when the task that runs it did not finish.
pub async fn check_on_blocking_pool(
    config: &Arc<Config>,
    registry: &Arc<PluginRegistry>,
) -> Result<CheckReport, ServerError> {
    let (config, registry) = (Arc::clone(config), Arc::clone(registry));
    let report = tokio::task::spawn_blocking(move || check(&config, &registry))
        .await
        .map_err(|source| ServerError::Task {
            task: "the check of the configuration",
            source,
        })??;
    Ok(report)
}

/// What a start without `security.keys` costs. The credential pepper derives from the key ring, so a restart makes every
/// stored credential unverifiable.
pub const EPHEMERAL_KEYS_WARNING: &str = "no signing keys are configured: a development key ring is generated at every \
     start, so credentials (app passwords, API, feed and RSVP tokens), cursors, CSRF tokens and sealed data do not \
     survive a restart";

/// What the observability settings ask for that should not happen silently.
fn observability_warnings(config: &Config) -> Vec<String> {
    let mut warnings = Vec::new();
    if config.observability.dav_capture.enabled {
        warnings.push(
            "the DAV capture is on: the exchanges of the listed tenants, calendar data included, are written to observability.dav_capture.dir (credentials are redacted)"
                .to_owned(),
        );
    }
    warnings
}

/// The ranges that outbound requests must never reach (PLAN 2.11, `ENGINEERING_RULES` R6): loopback, private, link-local and
/// unique-local addresses of both families.
const DENIED_RANGES: [&str; 8] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// The settings that take a protection away: an operations listener on an address that is not loopback (`/metrics` and
/// the reasons of `/readyz` need no credentials), and, in production, an egress policy that allows plain HTTP or the
/// ranges that the policy denies.
fn exposure_warnings(config: &Config, tables: &PluginTables) -> Vec<String> {
    let mut warnings = Vec::new();
    for listener in config.server.listeners.resolved() {
        if listener.routes.contains(&RouteGroup::Ops) && !listener.bind.ip().is_loopback() {
            warnings.push(format!(
                "the `{}` listener serves /metrics and /readyz without authentication on {}, which is not a loopback address: keep it \
                 on a network that only operators and monitoring reach",
                listener.name.as_str(),
                listener.bind
            ));
        }
    }
    if config.server.mode.is_production()
        && let Some(egress) = tables.get("http_client", "egress")
    {
        if egress.get("allow_http").and_then(Value::as_bool) == Some(true) {
            warnings.push(
                "security.egress.allow_http is on: outbound requests (webhooks, providers) may use plain HTTP, which the egress \
                 policy refuses by default (PLAN 2.11)"
                    .to_owned(),
            );
        }
        let denied: Vec<IpNet> = DENIED_RANGES.iter().filter_map(|range| range.parse().ok()).collect();
        for cidr in egress
            .get("allow_cidrs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let Ok(allowed) = cidr.parse::<IpNet>() else {
                continue;
            };
            if denied
                .iter()
                .any(|range| range.contains(&allowed) || allowed.contains(range))
            {
                warnings.push(format!(
                    "security.egress.allow_cidrs allows {cidr}, which overlaps a loopback, private or link-local range that the \
                     egress policy denies: a webhook URL could reach services of this host or network"
                ));
            }
        }
    }
    warnings
}

/// The rules that connect two sections.
fn cross_checks(config: &Config, tables: &PluginTables) -> Result<(), ConfigError> {
    #[cfg(feature = "mail-smtp")]
    if config.plugins.mail_transport == "smtp" {
        let smtp: davhaven_mail_smtp::config::SmtpConfig = parse_config(
            "smtp",
            tables.get("mail_transport", "smtp").cloned().unwrap_or(Value::Null),
        )?;
        // ADR-0008: a send that is still running when 60 % of the lease has passed is cut off by the handler.
        let limit = config.outbox.lease.mul_f64(0.6);
        if smtp.total_timeout >= limit {
            return Err(invalid(format!(
                "plugin.smtp.total_timeout ({}) must stay below 60 % of outbox.lease ({}); raise the lease or lower the timeout",
                humantime_text(smtp.total_timeout),
                humantime_text(config.outbox.lease)
            )));
        }
    }
    provider_redirects(config, tables)
}

/// The redirect URI of a provider that is switched on is the callback this server serves, `{server.public_base_url}/oauth/{name}/callback`.
///
/// The application sends that URL to the provider with every authorization, and the provider compares it with the one that is
/// registered for the OAuth client: a client registered with another URL makes every connection fail at the consent screen,
/// which is found here instead of by the first person who tries. The key is read from the table as it is, so the rule holds for
/// every provider that has one, whatever its adapter calls the rest of its table.
fn provider_redirects(config: &Config, tables: &PluginTables) -> Result<(), ConfigError> {
    let Some(base) = &config.server.public_base_url else {
        return Ok(());
    };
    let Ok(urls) = PublicUrls::new(base.clone()) else {
        return Ok(());
    };
    for name in &config.plugins.providers {
        let Some(table) = tables.get("provider", name) else {
            continue;
        };
        if table.get("enabled").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(configured) = table.get("redirect_uri").and_then(Value::as_str) else {
            continue;
        };
        let expected = urls.oauth_callback_url(name);
        if configured.parse::<Url>().ok().as_ref() != Some(&expected) {
            return Err(invalid(format!(
                "providers.{name}.redirect_uri is `{configured}`, but the callback this server serves is `{expected}` \
                 (server.public_base_url and the path /oauth/{name}/callback): register that URL with the OAuth client of the \
                 provider and write it here"
            )));
        }
    }
    Ok(())
}

/// A duration in the form of the configuration files.
#[cfg(feature = "mail-smtp")]
fn humantime_text(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();
    if seconds != 0 && seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else if duration.subsec_millis() == 0 {
        format!("{seconds}s")
    } else {
        format!("{}ms", duration.as_millis())
    }
}

/// Parses the table of one selected plugin and validates it.
///
/// The plugin judges its own table ([`PluginDescriptor::check`](davhaven_ports::PluginDescriptor::check), reached through
/// [`PluginRegistry::check_table`]): it is parsed into the adapter's configuration struct, validated, and the files it names
/// are read. A plugin without a check of its own is checked against the JSON Schema it published: a key that its schema does
/// not know is an error. What only the adapter can judge is left to its `build`, which `serve` runs right after.
///
/// What the plugin says without refusing (an unencrypted transport that the operator accepted) is added to `warnings`.
fn validate_plugin(
    registry: &PluginRegistry,
    schemas: &[PluginSchema],
    kind: &str,
    name: &str,
    table: &Value,
    mode: RunMode,
    warnings: &mut Vec<String>,
) -> Result<(), PluginError> {
    if let Some(verdict) = registry.check_table(kind, name, table, mode) {
        warnings.extend(verdict?);
        return Ok(());
    }
    let own = schemas.iter().find(|schema| schema.kind == kind && schema.name == name);
    if let Some(schema) = own
        && let Some((unknown, known)) = unknown_keys(schema.schema.as_value(), table)
        && let Some(key) = unknown.first()
    {
        return Err(PluginError::invalid_config(
            name,
            format!(
                "unknown field `{key}`, {}",
                if known.is_empty() {
                    "the plugin takes no configuration".to_owned()
                } else {
                    format!("expected one of {}", known.join(", "))
                }
            ),
        ));
    }
    Ok(())
}

/// The effective settings of every selected plugin, by kind and name: what its schema says by default with the table of
/// the deployment laid over it. The values are not redacted.
///
/// # Errors
///
/// As [`plugin_tables`].
pub fn effective_plugin_settings(config: &Config, registry: &PluginRegistry) -> Result<Value, ConfigError> {
    let selections = selections(&config.plugins)?;
    let tables = plugin_tables(config, registry, &selections)?;
    let schemas = registry.schemas();
    let mut by_kind = Map::new();
    for selection in &selections {
        let mut plugins = Map::new();
        for name in &selection.names {
            let mut effective = schemas
                .iter()
                .find(|schema| schema.kind == selection.kind.name && schema.name == name.as_str())
                .map_or_else(
                    || Value::Object(Map::new()),
                    |schema| defaults_tree(schema.schema.as_value()),
                );
            if let Some(table) = tables.get(selection.kind.name, name) {
                merge(&mut effective, table);
            }
            plugins.insert(name.clone(), effective);
        }
        by_kind.insert(selection.kind.name.to_owned(), Value::Object(plugins));
    }
    Ok(Value::Object(by_kind))
}

#[cfg(test)]
mod tests {
    use davhaven_ports::PortKind;

    use super::*;
    use crate::registry::registry;

    const SERVER: &str = r#"
        [server]
        mode = "dev"
        public_base_url = "http://localhost:8080"
    "#;

    const MEMORY_PLUGINS: &str = "store = \"memory\"\nmail_transport = \"memory\"\nrate_limiter = \"memory\"";

    /// A development configuration with the memory adapters and `extra` tables.
    fn config(extra: &str) -> Config {
        with_plugins(MEMORY_PLUGINS, extra)
    }

    /// A development configuration with the given body of `[plugins]` and `extra` tables.
    fn with_plugins(plugins: &str, extra: &str) -> Config {
        Config::from_toml(&format!("{SERVER}\n[plugins]\n{plugins}\n{extra}")).unwrap()
    }

    fn production(plugins: &str, keys: &str) -> Config {
        let text = format!("[server]\npublic_base_url = \"https://cal.example.org\"\n[plugins]\n{plugins}\n{keys}\n");
        Config::from_toml(&text).unwrap()
    }

    fn tables_of(config: &Config) -> PluginTables {
        config.plugin_tables(&registry().unwrap()).unwrap()
    }

    /// A scanner that finds nothing: the plugin of a hypothetical adapter crate.
    struct NullScanner;

    #[async_trait::async_trait]
    impl davhaven_ports::ContentScanner for NullScanner {
        fn name(&self) -> &'static str {
            "clamav"
        }

        async fn scan(
            &self,
            _content: &[u8],
            _context: &davhaven_ports::ScanContext,
        ) -> Result<davhaven_ports::ScanVerdict, davhaven_ports::PortError> {
            Ok(davhaven_ports::ScanVerdict::Clean)
        }
    }

    #[test]
    fn dedicated_tables_and_plugin_tables_are_joined_per_kind_and_name() {
        let config = with_plugins(
            "store = \"postgres\"\nmail_transport = \"smtp\"",
            r#"
            [database]
            url = "postgres://app@db/davhaven"
            [plugin.postgres]
            max_connections = 3
            [templates]
            default_theme = "corporate"
            [plugin.minijinja]
            theme_dirs = ["/etc/davhaven/themes"]
            [security.auth]
            cache_ttl = "1m"
            [webhooks]
            retry_window = "6h"
            [plugin.smtp]
            host = "smtp.example.org"
            tls = "implicit"
            "#,
        );
        let tables = tables_of(&config);
        let names: Vec<(&str, &str)> = tables.entries().map(|(kind, name, _)| (kind, name)).collect();
        assert_eq!(
            names,
            vec![
                ("authenticator", "local"),
                ("database", "postgres"),
                ("mail_transport", "smtp"),
                ("outbox_handler", "webhook"),
                ("templates", "minijinja"),
            ]
        );
        let postgres = tables.get("database", "postgres").unwrap();
        assert_eq!(postgres["url"], "postgres://app@db/davhaven");
        assert_eq!(postgres["max_connections"], 3);
        let templates = tables.get("templates", "minijinja").unwrap();
        assert_eq!(templates["default_theme"], "corporate");
        assert_eq!(templates["theme_dirs"][0], "/etc/davhaven/themes");
        assert_eq!(tables.get("authenticator", "local").unwrap()["cache_ttl"], "1m");
        assert_eq!(tables.get("mail_transport", "smtp").unwrap()["tls"], "implicit");
        assert_eq!(tables.get("outbox_handler", "webhook").unwrap()["retry_window"], "6h");
    }

    #[test]
    fn a_key_in_both_places_of_one_plugin_is_refused() {
        let config = with_plugins(
            "store = \"postgres\"",
            "[database]\nurl = \"postgres://a@h/d\"\n[plugin.postgres]\nurl = \"postgres://b@h/d\"",
        );
        let error = config.plugin_tables(&registry().unwrap()).unwrap_err().to_string();
        assert!(
            error.contains("`url`") && error.contains("[database]") && error.contains("[plugin.postgres]"),
            "{error}"
        );
    }

    #[test]
    fn tables_that_are_not_tables_are_refused() {
        let mut broken = with_plugins("store = \"postgres\"", "");
        broken.database = Value::String("postgres://x".to_owned());
        assert!(
            broken
                .plugin_tables(&registry().unwrap())
                .unwrap_err()
                .to_string()
                .contains("[database] must be a table")
        );
        let scalar = config("[plugin]\nsmtp = 3");
        assert!(
            scalar
                .plugin_tables(&registry().unwrap())
                .unwrap_err()
                .to_string()
                .contains("[plugin.smtp]")
        );
        let kind = config("[plugin]\nmail_transport = 3");
        assert!(
            kind.plugin_tables(&registry().unwrap())
                .unwrap_err()
                .to_string()
                .contains("[plugin.mail_transport]")
        );
        let member = config("[plugin.mail_transport]\nmemory = 3");
        assert!(
            member
                .plugin_tables(&registry().unwrap())
                .unwrap_err()
                .to_string()
                .contains("[plugin.mail_transport.memory]")
        );
    }

    #[test]
    fn empty_tables_are_left_out() {
        let tables = tables_of(&config("[plugin.memory]\n[plugin.mail_transport.memory]\n[database]"));
        assert_eq!(tables.entries().count(), 0, "{tables:?}");
        assert_eq!(tables.unselected(), []);
    }

    #[test]
    fn a_name_that_serves_several_kinds_needs_the_kind_in_the_table() {
        // The regression of the shared `[plugin.memory]`: store, mail and limiter are all `memory`.
        let ambiguous = config("[plugin.memory]\nmax_messages = 100");
        let error = ambiguous.plugin_tables(&registry().unwrap()).unwrap_err().to_string();
        assert!(
            error.contains("[plugin.memory] is ambiguous")
                && error.contains("database")
                && error.contains("mail_transport")
                && error.contains("rate_limiter")
                && error.contains("[plugin.mail_transport.memory]"),
            "{error}"
        );

        // Written with its kind, the same key reaches the mail transport and nothing else.
        let qualified = config("[plugin.mail_transport.memory]\nmax_messages = 100");
        let tables = tables_of(&qualified);
        assert_eq!(tables.get("mail_transport", "memory").unwrap()["max_messages"], 100);
        assert!(tables.get("database", "memory").is_none());
        assert!(tables.get("rate_limiter", "memory").is_none());
        let mail = tables.tree("mail_transport");
        assert_eq!(mail.get("memory").unwrap()["max_messages"], 100);
        for other in ["database", "rate_limiter"] {
            assert!(
                tables.tree(other).get("memory").is_none(),
                "the {other} plugin must not receive the table of the mail transport"
            );
        }
    }

    #[test]
    fn an_unqualified_table_still_works_for_a_name_that_is_selected_once() {
        let only_mail = with_plugins(
            "store = \"memory\"\nmail_transport = \"memory\"\nrate_limiter = \"noop\"",
            "[plugin.memory]\nmax_messages = 5",
        );
        // `memory` is selected for the store and the mail transport: ambiguous.
        assert!(only_mail.plugin_tables(&registry().unwrap()).is_err());
        let smtp = with_plugins(
            "mail_transport = \"smtp\"",
            "[plugin.smtp]\nhost = \"smtp.example.org\"",
        );
        assert_eq!(
            tables_of(&smtp).get("mail_transport", "smtp").unwrap()["host"],
            "smtp.example.org"
        );
    }

    #[test]
    fn both_spellings_of_one_plugin_may_not_set_the_same_key() {
        let config = with_plugins(
            "mail_transport = \"smtp\"",
            "[plugin.smtp]\nhost = \"a.example.org\"\n[plugin.mail_transport.smtp]\nhost = \"b.example.org\"",
        );
        let error = config.plugin_tables(&registry().unwrap()).unwrap_err().to_string();
        assert!(error.contains("`host`") && error.contains("[plugin.smtp]"), "{error}");
        let different = with_plugins(
            "mail_transport = \"smtp\"",
            "[plugin.smtp]\nhost = \"a.example.org\"\n[plugin.mail_transport.smtp]\nport = 25",
        );
        let tables = tables_of(&different);
        let table = tables.get("mail_transport", "smtp").unwrap();
        assert_eq!(
            (table["host"].as_str(), table["port"].as_i64()),
            (Some("a.example.org"), Some(25))
        );
    }

    #[test]
    fn a_dedicated_table_belongs_to_the_plugin_that_names_it_in_its_descriptor_and_to_its_kind_only() {
        let registry = registry().unwrap();
        let config = with_plugins("authenticators = [\"local\"]", "[security.auth]\ncache_ttl = \"1m\"");
        let tables = config.plugin_tables(&registry).unwrap();
        assert_eq!(tables.get("authenticator", "local").unwrap()["cache_ttl"], "1m");
        // A plugin called `local` of another kind would not receive `[security.auth]`.
        assert!(tables.get("rate_limiter", "local").is_none());

        // The mapping of the plan is recorded in the descriptors, not in a list of this crate.
        assert_eq!(
            registry.dedicated_tables(),
            vec![
                ("authenticator", "local", "security.auth"),
                ("database", "postgres", "database"),
                ("http_client", "egress", "security.egress"),
                ("outbox_handler", "webhook", "webhooks"),
                ("provider", "google", "providers.google"),
                ("provider", "microsoft", "providers.microsoft"),
                ("templates", "minijinja", "templates"),
            ]
        );
        // A table that a descriptor names is a dedicated table of the configuration this crate reads, and of the kind of the
        // plugin that names it.
        for (kind, name, table) in registry.dedicated_tables() {
            assert!(KINDS.iter().any(|known| known.name == kind), "{kind}");
            let entry = DEDICATED_TABLES
                .iter()
                .find(|entry| entry.key == table)
                .unwrap_or_else(|| {
                    panic!("the descriptor of `{name}` ({kind}) names `[{table}]`, which this server reads no table of")
                });
            assert_eq!(
                entry.kind, kind,
                "the descriptor of `{name}` names `[{table}]`, a table of the kind `{}`",
                entry.kind
            );
            assert!(config.dedicated_table(table).is_some(), "{table}");
        }
        // The list itself: unique keys, real kinds, readable by key; `[plugin]` is not one of them.
        let mut keys: Vec<&str> = DEDICATED_TABLES.iter().map(|entry| entry.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), DEDICATED_TABLES.len(), "a table is listed once");
        for entry in DEDICATED_TABLES {
            assert!(
                KINDS.iter().any(|known| known.name == entry.kind),
                "`[{}]` names the unknown kind `{}`",
                entry.key,
                entry.kind
            );
            assert!(config.dedicated_table(entry.key).is_some(), "{}", entry.key);
        }
        assert!(config.dedicated_table("plugin").is_none());
    }

    /// A content scanner that names the dedicated table `table`, registered in `registry`.
    fn register_scanner_with_dedicated_table(registry: &mut PluginRegistry, name: &'static str, table: &'static str) {
        use davhaven_ports::{Built, ContentScanner, PluginContext, PluginDescriptor};
        registry
            .register(
                PortKind::CONTENT_SCANNER,
                PluginDescriptor::new(
                    name,
                    "A scanner of another crate.",
                    || schemars::json_schema!({"type": "object"}),
                    |_context: PluginContext, _config: Value| {
                        Box::pin(async {
                            let scanner: std::sync::Arc<dyn ContentScanner> = std::sync::Arc::new(NullScanner);
                            Ok(Built::new(scanner))
                        })
                    },
                )
                .with_dedicated_table(table),
            )
            .unwrap();
    }

    #[test]
    fn a_plugin_of_another_kind_cannot_take_the_table_of_the_database() {
        // The registry has no store here, so the table is free to name; the server still binds it to the kind that it
        // configures. Otherwise a scanner would receive the database URL, its files and its credentials.
        let mut registry = PluginRegistry::new();
        register_scanner_with_dedicated_table(&mut registry, "clamav", "database");
        let config = with_plugins(
            "content_scanners = [\"clamav\"]",
            "[database]\nurl = \"postgres://app:secret@db/davhaven\"",
        );
        let selections = vec![Selection {
            kind: *KINDS.iter().find(|kind| kind.name == "content_scanner").unwrap(),
            names: vec!["clamav".to_owned()],
        }];
        let error = plugin_tables(&config, &registry, &selections).unwrap_err().to_string();
        assert!(
            error.contains("clamav")
                && error.contains("[database]")
                && error.contains("kind `database`")
                && error.contains("its own kind"),
            "{error}"
        );
        assert!(!error.contains("secret"), "{error}");
        // The same refusal when the scanner is not selected: the table does not reach it that way either.
        let unselected = vec![Selection {
            kind: *KINDS.iter().find(|kind| kind.name == "content_scanner").unwrap(),
            names: Vec::new(),
        }];
        assert!(plugin_tables(&config, &registry, &unselected).is_err());
        // A table of the scanner's own kind would be fine; none exists, so the scanner stays with `[plugin.*]` alone.
        let mut free = PluginRegistry::new();
        register_scanner_with_dedicated_table(&mut free, "clamav", "scanners.clamav");
        let error = plugin_tables(&config, &free, &selections).unwrap_err().to_string();
        assert!(
            error.contains("[scanners.clamav]") && error.contains("reads no table"),
            "{error}"
        );
    }

    #[test]
    fn a_second_plugin_cannot_take_a_table_that_another_one_owns() {
        // The registry of the build refuses it at registration: two authenticators would both receive `[security.auth]`.
        let mut registry = registry().unwrap();
        let (owner_kind, owner) = ("authenticator", "local");
        assert_eq!(registry.dedicated_table(owner_kind, owner), Some("security.auth"));
        let error = {
            use davhaven_ports::{Authenticator, Built, PluginContext, PluginDescriptor};
            registry
                .register(
                    PortKind::AUTHENTICATOR,
                    PluginDescriptor::<dyn Authenticator>::new(
                        "ldap",
                        "An authenticator of another crate.",
                        || schemars::json_schema!({"type": "object"}),
                        |_context: PluginContext, _config: Value| {
                            Box::pin(async {
                                Err::<Built<dyn Authenticator>, _>(PluginError::invalid_config("ldap", "x"))
                            })
                        },
                    )
                    .with_dedicated_table("security.auth"),
                )
                .unwrap_err()
        };
        assert_eq!(
            error,
            PluginError::DuplicateTable {
                table: "security.auth".to_owned(),
                kind: "authenticator",
                name: "local".to_owned(),
            }
        );
        assert!(
            registry
                .names(PortKind::AUTHENTICATOR)
                .iter()
                .all(|name| *name != "ldap")
        );
        // Two plugins of one kind are refused the same way, and the first one keeps the table.
        let mut second = PluginRegistry::new();
        second
            .register(PortKind::CONTENT_SCANNER, other_scanner("a", "scanners.x"))
            .unwrap();
        assert!(matches!(
            second.register(PortKind::CONTENT_SCANNER, other_scanner("b", "scanners.x")),
            Err(PluginError::DuplicateTable { .. })
        ));
        assert_eq!(second.dedicated_tables(), vec![("content_scanner", "a", "scanners.x")]);
    }

    /// A descriptor of a content scanner with a dedicated table, for the tests of the registry.
    fn other_scanner(
        name: &'static str,
        table: &'static str,
    ) -> davhaven_ports::PluginDescriptor<dyn davhaven_ports::ContentScanner> {
        use davhaven_ports::{Built, ContentScanner, PluginContext, PluginDescriptor};
        PluginDescriptor::new(
            name,
            "A scanner of another crate.",
            || schemars::json_schema!({"type": "object"}),
            |_context: PluginContext, _config: Value| {
                Box::pin(async {
                    let scanner: std::sync::Arc<dyn ContentScanner> = std::sync::Arc::new(NullScanner);
                    Ok(Built::new(scanner))
                })
            },
        )
        .with_dedicated_table(table)
    }

    #[test]
    fn a_table_that_no_plugin_of_the_build_reads_is_reported_and_one_that_is_read_is_not() {
        // A build without the adapters that the tables are written for: the registry holds the scheduling policies only,
        // so this runs in every feature set.
        let mut bare = PluginRegistry::new();
        davhaven_app::policy::register(&mut bare).unwrap();
        let config = with_plugins(
            MEMORY_PLUGINS,
            "[database]\nurl = \"postgres://app:secret@db/davhaven\"\n[security.auth]\ncache_ttl = \"1m\"\n\
             [security.egress]\nallow_http = true\n[webhooks]\nretry_window = \"6h\"\n[templates]\ndefault_theme = \"corporate\"",
        );
        let said = unread_tables(&config, &bare);
        assert_eq!(said.len(), 5, "{said:?}");
        for (table, kind) in [
            ("database", "database"),
            ("security.auth", "authenticator"),
            ("security.egress", "http_client"),
            ("webhooks", "outbox_handler"),
            ("templates", "templates"),
        ] {
            let expected = format!(
                "[{table}] is set, but no adapter of this build reads it: the build has no {kind} plugin that is configured by it"
            );
            assert!(said.contains(&expected), "{expected}: {said:?}");
        }
        assert!(
            said.iter().all(|warning| !warning.contains("secret")),
            "a warning never shows a value: {said:?}"
        );
        // Nothing is said about empty tables.
        let quiet = with_plugins(
            MEMORY_PLUGINS,
            "[database]\n[security.auth]\n[providers.google]\n[providers.microsoft]",
        );
        assert_eq!(unread_tables(&quiet, &bare), Vec::<String>::new());
        // A provider table is a table like any other: written for a provider that this build does not have, it is said.
        let provider = with_plugins(MEMORY_PLUGINS, "[providers.google]\nenabled = false");
        assert_eq!(
            unread_tables(&provider, &bare),
            vec![
                "[providers.google] is set, but no adapter of this build reads it: the build has no provider plugin that is configured by it"
                    .to_owned()
            ]
        );
        // A table that a plugin of the build reads is not reported.
        let mut with_policy_and_scanner = PluginRegistry::new();
        register_scanner_with_dedicated_table(&mut with_policy_and_scanner, "clamav", "scanners.clamav");
        assert_eq!(unread_tables(&quiet, &with_policy_and_scanner), Vec::<String>::new());
    }

    #[test]
    fn the_tables_of_the_adapters_of_the_build_are_read_and_not_reported_as_unread() {
        let registry = registry().unwrap();
        let config = config("[database]\nurl = \"postgres://app@db/davhaven\"\n[security.auth]\ncache_ttl = \"1m\"");
        assert_eq!(
            unread_tables(&config, &registry),
            Vec::<String>::new(),
            "every adapter that these tables are written for is compiled into this build"
        );
        // The store of this configuration is the memory one: the table of the PostgreSQL store is set and not selected.
        let report = check(&config, &registry).unwrap();
        assert!(
            report.warnings.iter().any(
                |warning| warning.contains("database adapter `postgres`") && warning.contains("does not select it")
            ),
            "{:?}",
            report.warnings
        );
        assert!(
            report
                .warnings
                .iter()
                .all(|warning| !warning.contains("no adapter of this build reads it")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn a_descriptor_that_names_a_table_the_server_does_not_read_is_refused_with_the_sections_it_reads() {
        use davhaven_ports::{Built, ContentScanner, PluginContext, PluginDescriptor, PortKind};
        let mut registry = registry().unwrap();
        registry
            .register(
                PortKind::CONTENT_SCANNER,
                PluginDescriptor::new(
                    "clamav",
                    "A scanner of another crate.",
                    || schemars::json_schema!({"type": "object"}),
                    |_context: PluginContext, _config: Value| {
                        Box::pin(async {
                            let scanner: std::sync::Arc<dyn ContentScanner> = std::sync::Arc::new(NullScanner);
                            Ok(Built::new(scanner))
                        })
                    },
                )
                .with_dedicated_table("scanners.clamav"),
            )
            .unwrap();
        let config = with_plugins(&format!("{MEMORY_PLUGINS}\ncontent_scanners = [\"clamav\"]"), "");
        let error = check(&config, &registry).unwrap_err().to_string();
        assert!(
            error.contains("clamav") && error.contains("[scanners.clamav]") && error.contains("security.auth"),
            "{error}"
        );
    }

    #[test]
    fn a_valid_development_configuration_passes_with_a_warning_about_keys() {
        let registry = registry().unwrap();
        let report = check(&config(""), &registry).unwrap();
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("signing keys") && warning.contains("credentials")),
            "{:?}",
            report.warnings
        );
        assert_eq!(report.listeners.len(), 3);
        let store = report.selections.iter().find(|s| s.kind.name == "database").unwrap();
        assert_eq!(store.names, vec!["memory".to_owned()]);
    }

    #[test]
    fn unknown_plugins_are_refused_with_the_list_of_available_ones() {
        let registry = registry().unwrap();
        let bad = with_plugins(&format!("{MEMORY_PLUGINS}\nauthenticators = [\"ldap\"]"), "");
        let error = check(&bad, &registry).unwrap_err().to_string();
        assert!(error.contains("ldap") && error.contains("local"), "{error}");
        let table = config("[plugin.ldap]\nhost = \"x\"");
        let error = check(&table, &registry).unwrap_err().to_string();
        assert!(error.contains("[plugin.ldap]") && error.contains("smtp"), "{error}");
        let qualified = config("[plugin.mail_transport.ldap]\nhost = \"x\"");
        let error = check(&qualified, &registry).unwrap_err().to_string();
        assert!(
            error.contains("[plugin.mail_transport.ldap]") && error.contains("smtp") && error.contains("memory"),
            "{error}"
        );
    }

    #[test]
    fn an_adapter_table_for_a_plugin_that_is_not_selected_is_a_warning() {
        let registry = registry().unwrap();
        let report = check(&config("[plugin.smtp]\nhost = \"smtp.example.org\""), &registry).unwrap();
        assert!(
            report.warnings.iter().any(|warning| warning.contains("`smtp`")),
            "{:?}",
            report.warnings
        );
        let qualified = check(
            &config("[plugin.mail_transport.smtp]\nhost = \"smtp.example.org\""),
            &registry,
        )
        .unwrap();
        assert!(
            qualified
                .warnings
                .iter()
                .any(|warning| warning.contains("mail_transport adapter `smtp`")),
            "{:?}",
            qualified.warnings
        );
    }

    #[test]
    fn typos_in_adapter_tables_fail_with_the_key() {
        let registry = registry().unwrap();
        for (extra, key) in [
            // The mail transport's own validation, not another adapter's complaint about a key it does not know.
            ("[plugin.mail_transport.memory]\nmax_messages = 0", "max_messages"),
            ("[plugin.mail_transport.memory]\nmax_mesages = 5", "max_mesages"),
            ("[plugin.rate_limiter.memory]\nbucketz = {}", "bucketz"),
            ("[plugin.database.memory]\nmax_messages = 5", "max_messages"),
            ("[security.auth]\ncache_ttl = \"0s\"", "cache_ttl"),
            ("[webhooks]\nretry_window = \"0s\"", "retry_window"),
            ("[security.egress]\nallow_htp = true", "allow_htp"),
            ("[templates]\ndefault_locale = \"not a locale\"", "invalid locale"),
        ] {
            let error = check(&config(extra), &registry).unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    /// A directory of themes: each `(theme, file, text)` is one file.
    fn themes_in(files: &[(&str, &str, &str)]) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        for (theme, file, text) in files {
            let folder = directory.path().join(theme);
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join(file), text).unwrap();
        }
        directory
    }

    fn with_theme_dir(directory: &tempfile::TempDir, templates: &str) -> Config {
        config(&format!(
            "[templates]\n{templates}\n[plugin.templates.minijinja]\ntheme_dirs = [{:?}]",
            directory.path().display().to_string()
        ))
    }

    #[test]
    fn config_check_loads_the_themes_so_that_a_missing_theme_or_a_broken_template_fails_before_serve() {
        let registry = registry().unwrap();

        // A default theme that no directory provides.
        let error = check(&config("[templates]\ndefault_theme = \"corporate\""), &registry)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("default_theme") && error.contains("corporate"),
            "{error}"
        );

        // A theme directory that does not exist, and one that holds no theme (an unmounted volume looks like that).
        let error = check(
            &config("[plugin.templates.minijinja]\ntheme_dirs = [\"/does/not/exist\"]"),
            &registry,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("/does/not/exist"), "{error}");
        let empty = tempfile::tempdir().unwrap();
        let report = check(&with_theme_dir(&empty, ""), &registry).unwrap();
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("holds no theme") && warning.contains("theme_dirs")),
            "{:?}",
            report.warnings
        );

        // A template that does not compile names the theme and the file; so does one that needs what the application
        // does not provide.
        let broken = themes_in(&[("corporate", "feed_busy.en.subject", "Busy {% if %}")]);
        let error = check(&with_theme_dir(&broken, "default_theme = \"corporate\""), &registry)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("corporate") && error.contains("feed_busy.en.subject") && error.contains("does not compile"),
            "{error}"
        );
        let unknown_field = themes_in(&[("corporate", "feed_busy.en.subject", "{{ tenant.name }}")]);
        let error = check(&with_theme_dir(&unknown_field, ""), &registry)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("corporate") && error.contains("does not render"),
            "{error}"
        );

        // A theme that brings only its layout is complete: the content comes from the default theme.
        let layout = themes_in(&[
            (
                "corporate",
                "_mail.html",
                "<body>{% block content %}{% endblock %}</body>",
            ),
            (
                "corporate",
                "_page.html",
                "<html><body>{% block content %}{% endblock %}<footer>{{ year }}</footer></body></html>",
            ),
        ]);
        let report = check(&with_theme_dir(&layout, "default_theme = \"corporate\""), &registry).unwrap();
        assert!(
            report.tables.contains(&"templates:minijinja".to_owned()),
            "{:?}",
            report.tables
        );
    }

    #[test]
    fn a_valid_key_of_one_memory_adapter_is_accepted_and_the_others_are_not_asked() {
        let registry = registry().unwrap();
        // Store, mail transport and rate limiter are all `memory`; `max_messages` belongs to the mail transport.
        let report = check(
            &config("[plugin.mail_transport.memory]\nmax_messages = 5\n[plugin.rate_limiter.memory]\nmax_keys = 100"),
            &registry,
        )
        .unwrap();
        assert!(
            report.tables.contains(&"mail_transport:memory".to_owned()),
            "{:?}",
            report.tables
        );
        assert!(report.tables.contains(&"rate_limiter:memory".to_owned()));
        assert!(!report.tables.contains(&"database:memory".to_owned()));
        // Only one adapter selected: the short spelling is unambiguous.
        let short = with_plugins(
            "store = \"memory\"\nmail_transport = \"memory\"\nrate_limiter = \"noop\"",
            "[plugin.database.memory]\n[plugin.mail_transport.memory]\nmax_messages = 7",
        );
        check(&short, &registry).unwrap();
    }

    #[test]
    fn production_refuses_the_plugins_that_refuse_themselves() {
        let registry = registry().unwrap();
        let keys = "[[security.keys]]\nid = \"k1\"\nsecret_file = \"/x\"";
        for (selection, name) in [
            ("store = \"memory\"", "memory"),
            ("mail_transport = \"memory\"", "memory"),
            ("rate_limiter = \"noop\"", "noop"),
            ("http_client = \"recording\"", "recording"),
            ("templates = \"echo\"", "echo"),
            ("content_scanners = [\"eicar\"]", "eicar"),
        ] {
            let error = check(&production(selection, keys), &registry).unwrap_err().to_string();
            assert!(error.contains(name), "{selection}: {error}");
        }
    }

    /// The transport rules of production, which `config check` and the `build` of the plugins both apply (the SMTP relay
    /// and the database connection).
    #[cfg(all(feature = "store-postgres", feature = "mail-smtp"))]
    mod transport {
        use std::io;
        use std::path::Path;
        use std::sync::{Arc, PoisonError};

        use davhaven_ports::{PluginContext, PortKind};
        use tracing_subscriber::fmt::MakeWriter;

        use super::*;

        const SAFE_DATABASE: &str = r#"url = "postgres://app@db.internal/c?sslmode=verify-full""#;
        const PLAIN_DATABASE: &str = r#"url = "postgres://app@db.internal/c""#;
        const SAFE_RELAY: &str = r#"host = "smtp.example.org""#;
        const CAPTURE_RELAY: &str = "host = \"mail-catcher\"\ntls = \"none\"";

        /// A production configuration whose `[database]` and `[plugin.smtp]` tables are `database` and `smtp`.
        fn transports(key: &Path, database: &str, smtp: &str) -> Config {
            let text = format!(
                r#"
                [server]
                public_base_url = "https://cal.example.org"
                [plugins]
                store = "postgres"
                mail_transport = "smtp"
                [[security.keys]]
                id = "k1"
                secret_file = {key:?}
                [database]
                migrate_on_start = false
                {database}
                [plugin.smtp]
                {smtp}
                "#,
                key = key.display().to_string(),
            );
            Config::from_toml(&text).unwrap()
        }

        /// A transport table and the words that the refusal of production must contain, none when it is accepted.
        struct Case {
            name: &'static str,
            table: String,
            refusal: &'static [&'static str],
        }

        fn case(name: &'static str, table: impl Into<String>, refusal: &'static [&'static str]) -> Case {
            Case {
                name,
                table: table.into(),
                refusal,
            }
        }

        /// The files a configuration of production needs: the signing key and the password of a relay with a login.
        struct Files {
            _directory: tempfile::TempDir,
            key: std::path::PathBuf,
            login: String,
        }

        fn files() -> Files {
            let directory = tempfile::tempdir().unwrap();
            let key = directory.path().join("key");
            std::fs::write(&key, "0123456789abcdef0123456789abcdef0123456789\n").unwrap();
            let password = directory.path().join("password");
            std::fs::write(&password, "s3cret\n").unwrap();
            let login = format!("username = \"u\"\npassword_file = {:?}", password.display().to_string());
            Files {
                _directory: directory,
                key,
                login,
            }
        }

        fn production_context() -> PluginContext {
            let mut context = PluginContext::for_tests();
            context.mode = RunMode::Production;
            context
        }

        /// What `config check` and the plugin build said to one table: the same verdict in the same words, and a refusal
        /// names the plugin and the way out. `built` is `None` where a build would go on to connect.
        fn assert_verdicts_agree(case: &Case, checked: Result<(), String>, built: Option<Result<(), String>>) {
            let Case { name, refusal, .. } = case;
            if let Some(built) = built {
                assert_eq!(checked, built, "{name}: `config check` and the plugin build disagree");
            }
            if refusal.is_empty() {
                assert_eq!(checked, Ok(()), "{name}");
            } else {
                let error = checked.expect_err(name);
                for words in *refusal {
                    assert!(error.contains(words), "{name}: `{words}` is not in `{error}`");
                }
            }
        }

        #[tokio::test]
        async fn config_check_and_the_relay_build_judge_the_transport_the_same_way_in_production() {
            let registry = registry().unwrap();
            let files = files();
            let login = &files.login;
            for case in [
                case(
                    "a relay on another host without TLS",
                    CAPTURE_RELAY,
                    &["plugin `smtp`", "plugin.smtp.allow_insecure_transport = true"],
                ),
                case(
                    "a relay on another host without TLS, accepted",
                    format!("{CAPTURE_RELAY}\nallow_insecure_transport = true"),
                    &[],
                ),
                case(
                    "a login to a relay without TLS",
                    format!("{CAPTURE_RELAY}\n{login}"),
                    &["plugin `smtp`", "login", "plugin.smtp.username"],
                ),
                case(
                    "a login to a relay without TLS, accepted",
                    format!("{CAPTURE_RELAY}\nallow_insecure_transport = true\n{login}"),
                    &["plugin `smtp`", "login", "plugin.smtp.username"],
                ),
                case(
                    "a relay on this host without TLS",
                    "host = \"localhost\"\ntls = \"none\"",
                    &[],
                ),
                case(
                    "a login to a relay on this host without TLS",
                    format!("host = \"127.0.0.1\"\ntls = \"none\"\n{login}"),
                    &[],
                ),
                case("a relay with STARTTLS", SAFE_RELAY, &[]),
                case(
                    "a relay with TLS",
                    "host = \"smtp.example.org\"\ntls = \"implicit\"",
                    &[],
                ),
            ] {
                let config = transports(&files.key, SAFE_DATABASE, &case.table);
                let checked = check(&config, &registry).map(|_| ()).map_err(|error| error.to_string());
                let tree = config.plugin_tables(&registry).unwrap().tree("mail_transport");
                let built = registry
                    .build_single(PortKind::MAIL_TRANSPORT, "smtp", &production_context(), &tree)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string());
                assert_verdicts_agree(&case, checked, Some(built));
            }
        }

        #[tokio::test]
        async fn config_check_and_the_database_build_judge_the_transport_the_same_way_in_production() {
            let registry = registry().unwrap();
            let files = files();
            for case in [
                case(
                    "a plain runtime URL",
                    PLAIN_DATABASE,
                    &[
                        "plugin `postgres`",
                        "sslmode=verify-full",
                        "database.allow_insecure_transport = true",
                    ],
                ),
                case(
                    "a plain migration URL with verify-full at runtime",
                    format!("{SAFE_DATABASE}\nmigration_url = \"postgres://owner@db.internal/c\""),
                    &["plugin `postgres`", "sslmode=verify-full"],
                ),
                case(
                    "a plain runtime URL, accepted",
                    format!("{PLAIN_DATABASE}\nallow_insecure_transport = true"),
                    &[],
                ),
                case("verify-full", SAFE_DATABASE, &[]),
                case("a database on this host", "url = \"postgres://app@localhost/c\"", &[]),
            ] {
                let config = transports(&files.key, &case.table, SAFE_RELAY);
                let checked = check(&config, &registry).map(|_| ()).map_err(|error| error.to_string());
                // The build of an accepted URL would go on to connect, and needs a database: only the refusals are asked.
                let built = if checked.is_err() {
                    let tree = config.plugin_tables(&registry).unwrap().tree("database");
                    let built = registry
                        .build_single(PortKind::DATABASE, "postgres", &production_context(), &tree)
                        .await
                        .map(|_| ())
                        .map_err(|error| error.to_string());
                    Some(built)
                } else {
                    None
                };
                assert_verdicts_agree(&case, checked, built);
            }
        }

        #[test]
        fn config_check_does_not_say_that_a_refused_database_failed_to_start() {
            let files = files();
            let error = check(
                &transports(&files.key, PLAIN_DATABASE, SAFE_RELAY),
                &registry().unwrap(),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.starts_with("invalid configuration for plugin `postgres`") && !error.contains("failed to start"),
                "{error}"
            );
        }

        #[test]
        fn config_check_passes_the_insecure_choices_in_dev_mode_and_says_so() {
            let registry = registry().unwrap();
            let dev = with_plugins(
                "store = \"postgres\"\nmail_transport = \"smtp\"",
                &format!("[database]\n{PLAIN_DATABASE}\nmigrate_on_start = false\n[plugin.smtp]\n{CAPTURE_RELAY}"),
            );
            let warnings = check(&dev, &registry).unwrap().warnings;
            for expected in ["sslmode", "mail-catcher"] {
                assert!(
                    warnings
                        .iter()
                        .any(|warning| warning.contains(expected) && warning.contains("unencrypted")),
                    "{expected}: {warnings:?}"
                );
            }
        }

        #[test]
        fn config_check_warns_that_accepted_traffic_travels_unencrypted_and_that_an_opt_in_does_nothing() {
            let registry = registry().unwrap();
            let files = files();
            let warnings = |database: &str, smtp: &str| {
                check(&transports(&files.key, database, smtp), &registry)
                    .unwrap()
                    .warnings
            };
            let mentions = |warnings: &[String], words: &[&str]| {
                warnings
                    .iter()
                    .any(|warning| words.iter().all(|word| warning.contains(word)))
            };

            // The accepted risk: the opt-in is in effect.
            let accepted = warnings(
                SAFE_DATABASE,
                &format!("{CAPTURE_RELAY}\nallow_insecure_transport = true"),
            );
            assert!(mentions(&accepted, &["mail-catcher", "unencrypted"]), "{accepted:?}");
            assert!(!mentions(&accepted, &["no effect"]), "{accepted:?}");
            let accepted = warnings(
                &format!("{PLAIN_DATABASE}\nallow_insecure_transport = true"),
                SAFE_RELAY,
            );
            assert!(mentions(&accepted, &["sslmode", "unencrypted"]), "{accepted:?}");
            assert!(!mentions(&accepted, &["no effect"]), "{accepted:?}");

            // The opt-in that has no effect: TLS is on, or the host is this one.
            for relay in [
                "host = \"smtp.example.org\"\nallow_insecure_transport = true",
                "host = \"localhost\"\ntls = \"none\"\nallow_insecure_transport = true",
            ] {
                let stale = warnings(SAFE_DATABASE, relay);
                assert!(
                    mentions(&stale, &["plugin.smtp.allow_insecure_transport", "no effect"]),
                    "{relay}: {stale:?}"
                );
            }
            let stale = warnings(&format!("{SAFE_DATABASE}\nallow_insecure_transport = true"), SAFE_RELAY);
            assert!(
                mentions(&stale, &["database.allow_insecure_transport", "no effect"]),
                "{stale:?}"
            );

            // Neither is said where nothing is amiss.
            let quiet = warnings(SAFE_DATABASE, SAFE_RELAY);
            assert!(
                !mentions(&quiet, &["unencrypted"]) && !mentions(&quiet, &["no effect"]),
                "{quiet:?}"
            );
        }

        #[expect(clippy::disallowed_types, reason = "a test writer that locks for an instant")]
        type Buffer = std::sync::Mutex<Vec<u8>>;

        /// What the subscriber of a test writes.
        #[derive(Clone, Default)]
        struct Capture(Arc<Buffer>);

        impl Capture {
            fn text(&self) -> String {
                String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
            }
        }

        impl io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for Capture {
            type Writer = Self;

            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        #[tokio::test]
        async fn the_plugins_log_the_unencrypted_transport_they_start_with_after_the_operator_accepted_it() {
            let capture = Capture::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(capture.clone())
                .with_ansi(false)
                .finish();
            let _installed = tracing::subscriber::set_default(subscriber);
            let registry = registry().unwrap();
            let context = production_context();

            let relay = ConfigTree::new().with(
                "smtp",
                serde_json::json!({"host": "mail-catcher", "tls": "none", "allow_insecure_transport": true}),
            );
            registry
                .build_single(PortKind::MAIL_TRANSPORT, "smtp", &context, &relay)
                .await
                .unwrap();
            let text = capture.text();
            for expected in [
                "WARN",
                "plugin=\"smtp\"",
                "mode=production",
                "allowed=true",
                "mail-catcher",
                "unencrypted",
            ] {
                assert!(text.contains(expected), "{expected}: {text}");
            }

            // The database build goes on to connect after it has said so, which fails: nothing listens at the name.
            let database = ConfigTree::new().with(
                "postgres",
                serde_json::json!({"url": "postgres://app@db.invalid/c", "migrate_on_start": false,
                                   "acquire_timeout": "1s", "allow_insecure_transport": true}),
            );
            assert!(
                registry
                    .build_single(PortKind::DATABASE, "postgres", &context, &database)
                    .await
                    .is_err()
            );
            let text = capture.text();
            for expected in [
                "plugin=\"postgres\"",
                "allowed=true",
                "db.invalid",
                "sslmode",
                "unencrypted",
            ] {
                assert!(text.contains(expected), "{expected}: {text}");
            }
        }
    }

    #[test]
    fn secret_files_are_read_by_the_check() {
        let registry = registry().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        let keyed = |secret_file: &std::path::Path| {
            config(&format!(
                "[[security.keys]]\nid = \"2027-01\"\nsecret_file = {:?}\n",
                secret_file.display().to_string()
            ))
        };
        let error = check(&keyed(&path), &registry).unwrap_err().to_string();
        assert!(
            error.contains("secret_file") && error.contains("cannot read"),
            "{error}"
        );
        std::fs::write(&path, "tooshort\n").unwrap();
        let error = check(&keyed(&path), &registry).unwrap_err().to_string();
        assert!(
            error.contains("at least 32 characters") && !error.contains("tooshort"),
            "{error}"
        );
        std::fs::write(&path, "0123456789abcdef0123456789abcdef0123456789\n").unwrap();
        let report = check(&keyed(&path), &registry).unwrap();
        assert_eq!(report.keys, vec!["2027-01".to_owned()]);
        assert_eq!(report.active_key.as_deref(), Some("2027-01"));
        assert!(report.warnings.iter().all(|warning| !warning.contains("signing keys")));
    }

    #[test]
    fn the_smtp_timeout_must_stay_below_the_outbox_lease() {
        let registry = registry().unwrap();
        let smtp = "store = \"memory\"\nmail_transport = \"smtp\"\nrate_limiter = \"memory\"";
        let ok = with_plugins(smtp, "[plugin.smtp]\ntotal_timeout = \"30s\"");
        check(&ok, &registry).unwrap();
        let too_long = with_plugins(smtp, "[plugin.smtp]\ntotal_timeout = \"45s\"");
        let error = check(&too_long, &registry).unwrap_err().to_string();
        assert!(
            error.contains("total_timeout") && error.contains("outbox.lease"),
            "{error}"
        );
        let longer_lease = with_plugins(smtp, "[plugin.smtp]\ntotal_timeout = \"45s\"\n[outbox]\nlease = \"2m\"");
        check(&longer_lease, &registry).unwrap();
    }

    #[test]
    fn a_capture_that_records_data_is_reported_and_a_reserved_setting_is_refused() {
        let registry = registry().unwrap();
        let quiet = check(&config(""), &registry).unwrap();
        assert!(!quiet.warnings.iter().any(|warning| warning.contains("capture")));
        let loud = check(
            &config("[observability.dav_capture]\nenabled = true\ntenants = [\"acme\"]\ndir = \"/var/capture\""),
            &registry,
        )
        .unwrap();
        assert!(
            loud.warnings.iter().any(|warning| warning.contains("DAV capture")),
            "{:?}",
            loud.warnings
        );
        // A setting that promises what this build does not do is an error and not a warning.
        let error = check(&config("[observability.metrics]\ntenant_label = true"), &registry)
            .unwrap_err()
            .to_string();
        assert!(error.contains("tenant_label") && error.contains("reserved"), "{error}");
    }

    #[test]
    fn an_operations_listener_on_a_public_address_and_a_loose_egress_policy_are_reported() {
        let registry = registry().unwrap();
        let loopback = check(&config(""), &registry).unwrap();
        assert!(
            !loopback
                .warnings
                .iter()
                .any(|warning| warning.contains("without authentication")),
            "{:?}",
            loopback.warnings
        );
        let exposed = check(&config("[server.listeners.ops]\nbind = \"0.0.0.0:9090\"\n"), &registry).unwrap();
        assert!(
            exposed
                .warnings
                .iter()
                .any(|warning| warning.contains("`ops` listener") && warning.contains("0.0.0.0:9090")),
            "{:?}",
            exposed.warnings
        );
        // Merged onto the public listener, the ops group is exposed there.
        let merged = check(
            &config(
                "[server.listeners.public]\nroutes = [\"wellknown\", \"dav\", \"web\", \"ops\"]\n\
                 [server.listeners.ops]\nenabled = false\n",
            ),
            &registry,
        )
        .unwrap();
        assert!(
            merged
                .warnings
                .iter()
                .any(|warning| warning.contains("`public` listener")),
            "{:?}",
            merged.warnings
        );

        // The egress rules are about production.
        let keys = "[[security.keys]]\nid = \"k1\"\nsecret_file = \"/x\"";
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("key");
        std::fs::write(&key, "0123456789abcdef0123456789abcdef0123456789\n").unwrap();
        let keys = keys.replace("/x", &key.display().to_string().replace('\\', "/"));
        let strict = production("store = \"postgres\"\nmail_transport = \"smtp\"", &keys);
        let strict_report = check_ignoring_database(&strict, &registry);
        assert!(
            !strict_report.iter().any(|warning| warning.contains("egress")),
            "{strict_report:?}"
        );
        let loose = Config::from_toml(&format!(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[plugins]\nstore = \"postgres\"\n{keys}\n\
             [security.egress]\nallow_http = true\nallow_cidrs = [\"10.1.0.0/16\", \"192.0.2.0/24\", \"127.0.0.1/32\"]\n"
        ))
        .unwrap();
        let loose_report = check_ignoring_database(&loose, &registry);
        assert!(
            loose_report.iter().any(|warning| warning.contains("allow_http")),
            "{loose_report:?}"
        );
        assert!(
            loose_report.iter().any(|warning| warning.contains("10.1.0.0/16")),
            "{loose_report:?}"
        );
        assert!(
            loose_report.iter().any(|warning| warning.contains("127.0.0.1/32")),
            "{loose_report:?}"
        );
        assert!(
            !loose_report.iter().any(|warning| warning.contains("192.0.2.0/24")),
            "a public range is fine: {loose_report:?}"
        );
    }

    /// The exposure warnings of a configuration whose database table is not needed for the question.
    fn check_ignoring_database(config: &Config, registry: &PluginRegistry) -> Vec<String> {
        let selections = selections(&config.plugins).unwrap();
        check_selection(registry, &selections, config.server.mode).unwrap();
        let tables = plugin_tables(config, registry, &selections).unwrap();
        exposure_warnings(config, &tables)
    }

    #[test]
    fn selections_follow_the_kinds() {
        let defaults = selections(&PluginsConfig::default()).unwrap();
        assert_eq!(defaults.len(), KINDS.len());
        let by_kind = |kind: &str| defaults.iter().find(|s| s.kind.name == kind).unwrap().names.clone();
        assert_eq!(by_kind("database"), vec!["postgres".to_owned()]);
        assert_eq!(by_kind("authenticator"), vec!["local".to_owned()]);
        assert_eq!(by_kind("provider"), Vec::<String>::new());
    }

    #[test]
    fn an_empty_authenticator_chain_and_repeated_names_are_refused() {
        let registry = registry().unwrap();
        let none = with_plugins(&format!("{MEMORY_PLUGINS}\nauthenticators = []"), "");
        assert!(
            check(&none, &registry)
                .unwrap_err()
                .to_string()
                .contains("needs at least one")
        );
        let twice = with_plugins(&format!("{MEMORY_PLUGINS}\nevent_sinks = [\"log\", \"log\"]"), "");
        assert!(
            check(&twice, &registry)
                .unwrap_err()
                .to_string()
                .contains("more than once")
        );
    }

    /// The tables a plugin needs to be valid on its own, where an empty table is not enough.
    fn example_table(kind: &str, name: &str) -> &'static str {
        match (kind, name) {
            ("database", "postgres") => "[database]\nurl = \"postgres://app@db.example.org/davhaven\"\n",
            _ => "",
        }
    }

    #[test]
    fn every_registered_plugin_of_every_kind_passes_the_check_when_it_is_selected() {
        let registry = registry().unwrap();
        for report in registry.report() {
            for name in &report.plugins {
                let kind = report.kind;
                let selected = match kind.cardinality {
                    davhaven_ports::Cardinality::Single => format!("{} = \"{name}\"", kind.config_key),
                    _ => format!("{} = [\"{name}\"]", kind.config_key),
                };
                // The other kinds keep working defaults of a development configuration.
                let rest: Vec<&str> = MEMORY_PLUGINS
                    .lines()
                    .filter(|line| !line.starts_with(&format!("{} =", kind.config_key)))
                    .collect();
                let plugins = format!("{selected}\n{}", rest.join("\n"));
                let config = with_plugins(&plugins, example_table(kind.name, name));
                if let Err(error) = check(&config, &registry) {
                    panic!(
                        "selecting the {} plugin `{name}` fails `config check`: {error}. The check must work from the \
                         registry for every adapter: give its descriptor a check (`with_check`) or make its schema \
                         say what its table holds",
                        kind.name
                    );
                }
            }
        }
    }

    /// A content scanner of a hypothetical adapter crate that brings a table of its own (`ClamAV` in the roadmap).
    #[derive(serde::Deserialize, schemars::JsonSchema)]
    #[serde(deny_unknown_fields)]
    #[expect(dead_code, reason = "the fields exist for the schema and for the parser")]
    struct ClamConfig {
        host: String,
        port: u16,
    }

    /// The check of that adapter, which this crate does not know: the rules only the adapter can judge.
    fn check_clam(check: &davhaven_ports::PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
        let table = check.table.as_object().cloned().unwrap_or_default();
        if table.get("port").and_then(Value::as_u64) == Some(0) {
            return Err(PluginError::invalid_config("clamav", "`port` must not be 0"));
        }
        Ok(if table.get("host").and_then(Value::as_str) == Some("localhost") {
            vec!["the scanner `clamav` runs on this host".to_owned()]
        } else {
            Vec::new()
        })
    }

    fn registry_with_a_new_scanner(checked: bool) -> PluginRegistry {
        use davhaven_ports::{Built, ContentScanner, PluginContext, PluginDescriptor, PortKind};
        let mut registry = registry().unwrap();
        let descriptor = PluginDescriptor::new(
            "clamav",
            "A scanner of another crate.",
            || schemars::schema_for!(ClamConfig),
            |_context: PluginContext, _config: Value| {
                Box::pin(async {
                    let scanner: std::sync::Arc<dyn ContentScanner> = std::sync::Arc::new(NullScanner);
                    Ok(Built::new(scanner))
                })
            },
        );
        registry
            .register(
                PortKind::CONTENT_SCANNER,
                if checked {
                    descriptor.with_check(check_clam)
                } else {
                    descriptor
                },
            )
            .unwrap();
        registry
    }

    #[test]
    fn a_plugin_that_this_crate_does_not_know_is_checked_against_its_own_schema() {
        let registry = registry_with_a_new_scanner(false);
        let selected = format!("{MEMORY_PLUGINS}\ncontent_scanners = [\"clamav\"]");
        let valid = with_plugins(&selected, "[plugin.clamav]\nhost = \"scan.example.org\"\nport = 3310");
        check(&valid, &registry).unwrap();
        let qualified = with_plugins(
            &selected,
            "[plugin.content_scanner.clamav]\nhost = \"scan.example.org\"\nport = 3310",
        );
        check(&qualified, &registry).unwrap();
        let typo = with_plugins(&selected, "[plugin.clamav]\nhots = \"scan.example.org\"");
        let error = check(&typo, &registry).unwrap_err().to_string();
        assert!(
            error.contains("hots") && error.contains("host") && error.contains("clamav"),
            "{error}"
        );
    }

    #[test]
    fn a_plugin_judges_its_own_table_without_this_crate_knowing_it() {
        let registry = registry_with_a_new_scanner(true);
        let selected = format!("{MEMORY_PLUGINS}\ncontent_scanners = [\"clamav\"]");
        // What only the adapter can judge: the schema accepts port 0, the plugin does not.
        let refused = with_plugins(&selected, "[plugin.clamav]\nhost = \"scan.example.org\"\nport = 0");
        let error = check(&refused, &registry).unwrap_err().to_string();
        assert!(
            error.contains("clamav") && error.contains("`port` must not be 0"),
            "{error}"
        );
        // What it says without refusing is the report's, once.
        let table = "[plugin.clamav]\nhost = \"localhost\"\nport = 3310";
        let report = check(&with_plugins(&selected, table), &registry).unwrap();
        assert_eq!(
            report
                .warnings
                .iter()
                .filter(|warning| warning.contains("`clamav` runs on this host"))
                .count(),
            1,
            "{:?}",
            report.warnings
        );
    }

    #[cfg(feature = "provider-google")]
    #[test]
    fn a_provider_with_a_dedicated_table_passes_when_it_is_registered_and_selected() {
        let registry = registry().unwrap();
        // `google` registers with the table of the plan, `[providers.google]`, and the adapter checks it.
        assert_eq!(registry.dedicated_table("provider", "google"), Some("providers.google"));
        let selected = format!("{MEMORY_PLUGINS}\nproviders = [\"google\"]");
        let valid = with_plugins(&selected, "[providers.google]\nenabled = false\nclient_id = \"abc\"");
        let tables = valid.plugin_tables(&registry).unwrap();
        assert_eq!(tables.get("provider", "google").unwrap()["client_id"], "abc");
        let report = check(&valid, &registry).unwrap();
        let off: Vec<&String> = report
            .warnings
            .iter()
            .filter(|warning| warning.contains("`google` is selected"))
            .collect();
        assert_eq!(
            off.len(),
            1,
            "a provider that is selected and off is said once: {:?}",
            report.warnings
        );
        let typo = with_plugins(&selected, "[providers.google]\nenabld = false");
        assert!(check(&typo, &registry).unwrap_err().to_string().contains("enabld"));
        let incomplete = with_plugins(&selected, "[providers.google]\nenabled = true\nclient_id = \"abc\"");
        assert!(
            check(&incomplete, &registry)
                .unwrap_err()
                .to_string()
                .contains("client_secret_file")
        );
    }

    #[test]
    fn a_provider_table_that_is_set_is_reported_once() {
        // The regression of backlog item 34: a `[providers.*]` table was said twice. A table for a provider that this build has
        // is a table that no `[plugins]` selection reads; one for a provider that it has not is a table that nothing reads.
        // Either way it is one line, and a second rule that finds the same table fails here.
        let registry = registry().unwrap();
        let report = check(
            &config("[providers.google]\nenabled = false\n[providers.microsoft]\nenabled = false"),
            &registry,
        )
        .unwrap();
        for (provider, compiled) in [
            ("google", cfg!(feature = "provider-google")),
            ("microsoft", cfg!(feature = "provider-microsoft")),
        ] {
            let said: Vec<&String> = report
                .warnings
                .iter()
                .filter(|warning| warning.contains(provider))
                .collect();
            assert_eq!(said.len(), 1, "{provider}: {:?}", report.warnings);
            if compiled {
                assert!(
                    said[0].contains(&format!("provider adapter `{provider}`"))
                        && said[0].contains("does not select it"),
                    "{provider}: {said:?}"
                );
            } else {
                assert!(
                    said[0].contains(&format!(
                        "[providers.{provider}] is set, but no adapter of this build reads it"
                    )),
                    "{provider}: {said:?}"
                );
            }
        }
    }

    #[cfg(feature = "provider-google")]
    #[test]
    fn the_redirect_uri_of_a_provider_that_is_on_is_the_callback_of_this_server() {
        let registry = registry().unwrap();
        let secret = std::env::temp_dir().join(format!("davhaven-redirect-check-{}", std::process::id()));
        std::fs::write(&secret, "client-secret\n").unwrap();
        let selected = format!("{MEMORY_PLUGINS}\nproviders = [\"google\"]");
        let table = |redirect: &str, enabled: bool| {
            format!(
                "[providers.google]\nenabled = {enabled}\nclient_id = \"abc\"\nclient_secret_file = {:?}\nredirect_uri = \"{redirect}\"",
                secret.display().to_string()
            )
        };
        // `SERVER` says that this server is at http://localhost:8080.
        let with = |redirect: &str, enabled: bool| with_plugins(&selected, &table(redirect, enabled));
        check(&with("http://localhost:8080/oauth/google/callback", true), &registry).unwrap();
        for wrong in [
            "https://other.example.org/oauth/google/callback",
            "http://localhost:8080/oauth/microsoft/callback",
            "http://localhost:8080/callback",
        ] {
            let error = check(&with(wrong, true), &registry).unwrap_err().to_string();
            assert!(
                error.contains("providers.google.redirect_uri")
                    && error.contains("http://localhost:8080/oauth/google/callback"),
                "{wrong}: {error}"
            );
        }
        // A provider that is off never sends its redirect URI to anyone.
        check(&with("https://other.example.org/x", false), &registry).unwrap();
        std::fs::remove_file(&secret).unwrap();
    }

    #[test]
    fn the_effective_settings_of_a_plugin_are_its_defaults_with_the_table_laid_over_them() {
        let registry = registry().unwrap();
        let config = config("[plugin.mail_transport.memory]\nmax_messages = 5");
        let effective = effective_plugin_settings(&config, &registry).unwrap();
        assert_eq!(effective["mail_transport"]["memory"]["max_messages"], 5);
        assert_eq!(
            effective["database"]["memory"],
            serde_json::json!({}),
            "no keys, no defaults"
        );
        let limiter = &effective["rate_limiter"]["memory"];
        assert!(limiter.is_object(), "{limiter}");
    }
}
