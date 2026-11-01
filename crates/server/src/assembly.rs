//! Building the application from the configuration.
//!
//! [`Foundation`] is the first stage: the pure ports (clock, ids, key ring, sealer, hasher), injected directly
//! because they are not selected by name (PLAN 2.3), and the plugin context with the failure backoff of
//! `[security.auth]`. Commands that need only the store (`admin bump-sync-epoch`) stop here and build the database; they
//! use [`Foundation::for_store`], which reads no key file (the store does not use the keys), so such a job holds none of the
//! secrets of the deployment. The clock and the id generator are parameters ([`Foundation::with_ports`]), so a test of the
//! assembled server can use the manual clock and sequential ids (`ENGINEERING_RULES` R9).
//!
//! [`Foundation::assemble`] builds everything in the three tiers of the plugin registry:
//!
//! 1. tier 0: the `http_client` plugin (the pure ports exist already);
//! 2. tier 1: the `database` plugin (it applies migrations first when `database.migrate_on_start` is on);
//! 3. tier 2: mail transport, templates, rate limiter, scheduling policy, the authenticator chain, event sinks,
//!    outbox handlers, providers and content scanners.
//!
//! The results go into [`AppDeps`], `davhaven_app::build_from_core` creates the services that the protocol routers receive, and
//! `davhaven_app::workers::build` creates the workers of the application from the same `AppCore`. The workers and shutdown hooks that
//! adapters return from their `build` are collected on the way. Nothing is spawned here: [`Assembly`] is a value that
//! the server (or an administrative command) puts to use.

use core::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

use davhaven_app::{AppCore, AppDeps, AppServices};
use davhaven_crypto_local::keyring::{KeyMaterial, LocalCrypto};
use davhaven_domain::PublicUrls;
use davhaven_ports::{
    Authenticator, Built, Clock, ContentScanner, CredentialHasher, Database, EventSink, FailureBackoff, HttpClient,
    IdGenerator, KeyRing, Lifecycle, MailTransport, OutboxHandler, PluginContext, PluginRegistry, PortKind, Provider,
    RateLimiter, SchedulingPolicy, SecretSealer, SystemClock, TemplateRenderer, UuidV7, Worker,
};
use secrecy::SecretString;

use crate::config::Config;
use crate::error::ServerError;
use crate::plugins::{self, CheckReport, PluginTables};

/// The id of the key ring that development mode generates when no key is configured.
const EPHEMERAL_KEY_ID: &str = "ephemeral";

/// A shutdown hook of an adapter.
#[derive(Clone)]
pub struct Hook {
    /// `kind:name` of the adapter, for logs and `/readyz`.
    pub name: String,
    /// The hook.
    pub lifecycle: Arc<dyn Lifecycle>,
    /// Whether `/readyz` asks the hook for its health. The database is asked directly through `Database::health`,
    /// so its hook is only run at shutdown.
    pub check_health: bool,
}

impl fmt::Debug for Hook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hook")
            .field("name", &self.name)
            .field("check_health", &self.check_health)
            .finish_non_exhaustive()
    }
}

/// Everything built from the configuration, ready to be served.
pub struct Assembly {
    /// The configuration it was built from.
    pub config: Arc<Config>,
    /// The shared state of the application layer: the services and the workers were built from it.
    pub core: AppCore,
    /// The ports and settings of the application layer.
    pub deps: AppDeps,
    /// The services the protocol routers receive.
    pub services: AppServices,
    /// The workers of the application and of the adapters, not yet running.
    pub workers: Vec<Arc<dyn Worker>>,
    /// The shutdown hooks of the workers of the application (run first).
    pub worker_hooks: Vec<Arc<dyn Lifecycle>>,
    /// The hooks of the adapters, in the order they were built (run in reverse).
    pub hooks: Vec<Hook>,
    /// What the configuration check found that is allowed but probably not intended.
    pub report: CheckReport,
}

impl fmt::Debug for Assembly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let workers: Vec<&'static str> = self.workers.iter().map(|worker| worker.name()).collect();
        f.debug_struct("Assembly")
            .field("workers", &workers)
            .field("hooks", &self.hooks)
            .finish_non_exhaustive()
    }
}

/// The key ring, sealer and hasher: from the configured key files, or in development mode without keys from a
/// key that is generated for this process (credentials, cursors, CSRF tokens and sealed data do not survive a restart:
/// the credential pepper derives from the key ring, so every stored app password and token stops verifying).
fn crypto(config: &Config, ids: &Arc<dyn IdGenerator>) -> Result<LocalCrypto, ServerError> {
    if config.security.keys.is_empty() {
        return ephemeral_crypto(ids);
    }
    Ok(LocalCrypto::from_config(
        &config.security.key_ring_config(),
        Arc::clone(ids),
    )?)
}

/// A key ring that exists only in this process.
fn ephemeral_crypto(ids: &Arc<dyn IdGenerator>) -> Result<LocalCrypto, ServerError> {
    let mut secret = String::with_capacity(64);
    for byte in ids.random_bytes(32) {
        // Writing into a `String` cannot fail.
        let _ = write!(secret, "{byte:02x}");
    }
    let material = KeyMaterial::new(
        EPHEMERAL_KEY_ID,
        vec![(EPHEMERAL_KEY_ID.to_owned(), SecretString::from(secret))],
    )?;
    Ok(LocalCrypto::new(&material, Arc::clone(ids)))
}

/// The failure backoff of `[security.auth]`, which the rate limiter builds its authentication buckets from.
#[cfg(feature = "auth-local")]
fn failure_backoff(tables: &PluginTables) -> Result<FailureBackoff, ServerError> {
    let table = tables
        .get("authenticator", "local")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let config: davhaven_auth_local::config::AuthConfig = davhaven_ports::parse_config("local", table)?;
    Ok(config.failure_backoff())
}

/// Without the local authenticator there is no `[security.auth]`: the default backoff applies.
#[cfg(not(feature = "auth-local"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature is that of the build with the local authenticator"
)]
fn failure_backoff(_tables: &PluginTables) -> Result<FailureBackoff, ServerError> {
    Ok(FailureBackoff::default())
}

/// Collects what the adapters return besides their port.
#[derive(Default)]
struct Parts {
    workers: Vec<Arc<dyn Worker>>,
    hooks: Vec<Hook>,
}

impl Parts {
    /// Takes the workers and the hook of `built` and returns its port.
    fn take<P: ?Sized>(&mut self, name: String, built: Built<P>, check_health: bool) -> Arc<P> {
        if let Some(lifecycle) = built.lifecycle {
            self.hooks.push(Hook {
                name,
                lifecycle,
                check_health,
            });
        }
        self.workers.extend(built.workers);
        built.port
    }

    /// Takes the parts of several built plugins of one kind, named `kind:name`, and returns their ports.
    fn take_all<P: ?Sized>(&mut self, kind: &str, names: &[String], built: Vec<Built<P>>) -> Vec<Arc<P>> {
        built
            .into_iter()
            .zip(names)
            .map(|(built, name)| self.take(format!("{kind}:{name}"), built, true))
            .collect()
    }
}

/// The registry and the context of one build, and what the plugins hand back besides their ports.
struct Build<'a> {
    registry: &'a PluginRegistry,
    tables: &'a PluginTables,
    context: PluginContext,
    parts: Parts,
}

impl Build<'_> {
    /// Builds the plugin `name` of a single kind; its hook is asked for health by `/readyz`.
    async fn single<P: ?Sized + 'static>(&mut self, kind: PortKind<P>, name: &str) -> Result<Arc<P>, ServerError> {
        let built = self
            .registry
            .build_single(kind, name, &self.context, &self.tables.tree(kind.name()))
            .await?;
        Ok(self.parts.take(format!("{}:{name}", kind.name()), built, true))
    }

    /// Like [`single`](Self::single), for a plugin whose health `/readyz` asks through another path (the database).
    async fn single_quiet<P: ?Sized + 'static>(
        &mut self,
        kind: PortKind<P>,
        name: &str,
    ) -> Result<Arc<P>, ServerError> {
        let built = self
            .registry
            .build_single(kind, name, &self.context, &self.tables.tree(kind.name()))
            .await?;
        Ok(self.parts.take(format!("{}:{name}", kind.name()), built, false))
    }

    /// Builds the plugins of a chain kind, in order.
    async fn chain<P: ?Sized + 'static>(
        &mut self,
        kind: PortKind<P>,
        names: &[String],
    ) -> Result<Vec<Arc<P>>, ServerError> {
        let built = self
            .registry
            .build_chain(kind, names, &self.context, &self.tables.tree(kind.name()))
            .await?;
        Ok(self.parts.take_all(kind.name(), names, built))
    }

    /// Builds the plugins of a set kind, in order.
    async fn set<P: ?Sized + 'static>(
        &mut self,
        kind: PortKind<P>,
        names: &[String],
    ) -> Result<Vec<Arc<P>>, ServerError> {
        let built = self
            .registry
            .build_set(kind, names, &self.context, &self.tables.tree(kind.name()))
            .await?;
        Ok(self.parts.take_all(kind.name(), names, built))
    }
}

/// A wrapper around the database that tier 1 builds; see [`Foundation::with_database_layer`].
type DatabaseLayer = Box<dyn FnOnce(Arc<dyn Database>) -> Arc<dyn Database> + Send>;

/// The first stage of the build: the pure ports and the plugin context.
pub struct Foundation {
    /// The configuration.
    pub config: Arc<Config>,
    /// The time source.
    pub clock: Arc<dyn Clock>,
    /// The id and randomness source.
    pub ids: Arc<dyn IdGenerator>,
    /// The key ring.
    pub keyring: Arc<dyn KeyRing>,
    /// The secret sealer.
    pub sealer: Arc<dyn SecretSealer>,
    /// The credential hasher.
    pub hasher: Arc<dyn CredentialHasher>,
    tables: PluginTables,
    context: PluginContext,
    database_layer: Option<DatabaseLayer>,
}

impl fmt::Debug for Foundation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Foundation")
            .field("tables", &self.tables)
            .field("context", &self.context)
            .field("database_layer", &self.database_layer.is_some())
            .finish_non_exhaustive()
    }
}

impl Foundation {
    /// Builds the pure ports (reading the key files) and the plugin context. The registry tells which table each plugin is
    /// configured by (`[security.auth]` for the local authenticator): see [`crate::plugins`].
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] or [`ServerError::Plugin`] for unusable keys and plugin tables.
    pub fn new(config: Arc<Config>, registry: &PluginRegistry) -> Result<Self, ServerError> {
        Self::with_ports(config, registry, Arc::new(SystemClock), Arc::new(UuidV7))
    }

    /// [`new`](Self::new) with another clock and id generator: the tests of the assembled server run on the manual clock
    /// and sequential ids.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn with_ports(
        config: Arc<Config>,
        registry: &PluginRegistry,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Result<Self, ServerError> {
        let crypto = crypto(&config, &ids)?;
        Self::from_crypto(config, registry, clock, ids, crypto)
    }

    /// The foundation of a command that needs only the store: **no key file is read**, and the key ring is one that exists
    /// only in this process. The store does not seal or sign anything, so a job like `admin bump-sync-epoch` needs none of
    /// the secrets of the deployment.
    ///
    /// # Errors
    ///
    /// [`ServerError::Plugin`] for unusable plugin tables.
    pub fn for_store(config: Arc<Config>, registry: &PluginRegistry) -> Result<Self, ServerError> {
        let ids: Arc<dyn IdGenerator> = Arc::new(UuidV7);
        let crypto = ephemeral_crypto(&ids)?;
        Self::from_crypto(config, registry, Arc::new(SystemClock), ids, crypto)
    }

    fn from_crypto(
        config: Arc<Config>,
        registry: &PluginRegistry,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        crypto: LocalCrypto,
    ) -> Result<Self, ServerError> {
        let keyring: Arc<dyn KeyRing> = crypto.keyring;
        let sealer: Arc<dyn SecretSealer> = crypto.sealer;
        let hasher: Arc<dyn CredentialHasher> = crypto.hasher;
        let tables = config.plugin_tables(registry)?;
        let context = PluginContext::new(
            Arc::clone(&clock),
            Arc::clone(&ids),
            Arc::clone(&keyring),
            Arc::clone(&sealer),
            Arc::clone(&hasher),
            config.server.mode,
        )
        .with_failure_backoff(failure_backoff(&tables)?);
        Ok(Self {
            config,
            clock,
            ids,
            keyring,
            sealer,
            hasher,
            tables,
            context,
            database_layer: None,
        })
    }

    /// Wraps the database that tier 1 builds in what `layer` returns, before anything else receives it: the plugins of
    /// tier 2 (the authenticators, the outbox handlers), the services and the workers all use the wrapper. For the tests
    /// of the assembled application that watch the transactions of the store; [`database`](Self::database) does not
    /// apply it.
    #[must_use]
    pub fn with_database_layer(
        mut self,
        layer: impl FnOnce(Arc<dyn Database>) -> Arc<dyn Database> + Send + 'static,
    ) -> Self {
        self.database_layer = Some(Box::new(layer));
        self
    }

    /// Builds the selected database plugin (tier 1) without the HTTP client, which the store does not need.
    ///
    /// # Errors
    ///
    /// [`ServerError::Plugin`] when the plugin does not exist, its table is invalid or it cannot start.
    pub async fn database(&self, registry: &PluginRegistry) -> Result<Built<dyn Database>, ServerError> {
        Ok(registry
            .build_single(
                PortKind::DATABASE,
                &self.config.plugins.store,
                &self.context,
                &self.tables.tree(PortKind::DATABASE.name()),
            )
            .await?)
    }

    /// Builds everything: see the module documentation.
    ///
    /// # Errors
    ///
    /// [`ServerError`] for the first plugin that cannot be built.
    pub async fn assemble(self, registry: &PluginRegistry, report: CheckReport) -> Result<Assembly, ServerError> {
        let Self {
            config,
            clock,
            ids,
            keyring,
            sealer,
            hasher,
            tables,
            context,
            database_layer,
        } = self;
        let selected = &config.plugins;
        let mut build = Build {
            registry,
            tables: &tables,
            context,
            parts: Parts::default(),
        };

        // Tier 0: the outbound HTTP client; the pure ports exist already.
        let http: Arc<dyn HttpClient> = build.single(PortKind::HTTP_CLIENT, &selected.http_client).await?;
        build.context = build.context.clone().with_http(Arc::clone(&http));

        // Tier 1: the database.
        let mut database: Arc<dyn Database> = build.single_quiet(PortKind::DATABASE, &selected.store).await?;
        if let Some(layer) = database_layer {
            database = layer(database);
        }
        build.context = build.context.clone().with_database(Arc::clone(&database));

        // Tier 2: everything else.
        let mail: Arc<dyn MailTransport> = build.single(PortKind::MAIL_TRANSPORT, &selected.mail_transport).await?;
        let templates: Arc<dyn TemplateRenderer> = build.single(PortKind::TEMPLATES, &selected.templates).await?;
        let rate_limiter: Arc<dyn RateLimiter> = build.single(PortKind::RATE_LIMITER, &selected.rate_limiter).await?;
        let scheduling_policy: Arc<dyn SchedulingPolicy> = build
            .single(PortKind::SCHEDULING_POLICY, &selected.scheduling_policy)
            .await?;
        let authenticators: Vec<Arc<dyn Authenticator>> =
            build.chain(PortKind::AUTHENTICATOR, &selected.authenticators).await?;
        let event_sinks: Vec<Arc<dyn EventSink>> = build.set(PortKind::EVENT_SINK, &selected.event_sinks).await?;
        let outbox_handlers: Vec<Arc<dyn OutboxHandler>> =
            build.set(PortKind::OUTBOX_HANDLER, &selected.outbox_handlers).await?;
        let providers: Vec<Arc<dyn Provider>> = build.set(PortKind::PROVIDER, &selected.providers).await?;
        let content_scanners: Vec<Arc<dyn ContentScanner>> =
            build.set(PortKind::CONTENT_SCANNER, &selected.content_scanners).await?;
        let parts = build.parts;

        let base = config
            .server
            .public_base_url
            .clone()
            .ok_or_else(|| ServerError::PublicUrl("is required".to_owned()))?;
        // The certificate that signs Apple profiles, when the deployment has one: the signer the check built, whose key was
        // checked against the certificate, so that a pair that does not fit stopped the start and the files are read once.
        let profile_signer = report.profile_signer.port();
        let deps = AppDeps {
            clock,
            ids,
            keyring,
            sealer,
            hasher,
            database,
            http,
            mail,
            templates,
            rate_limiter,
            scheduling_policy,
            authenticators,
            event_sinks,
            outbox_handlers,
            providers,
            content_scanners,
            profile_signer,
            urls: PublicUrls::new(base)?,
            limits: config.limits(),
            config: config.app_config(),
        };
        // One core for the services and the workers: what the core holds (the memory of tenant status that
        // authentication consults and provisioning invalidates) is shared, so the two cannot drift apart.
        let core = AppCore::new(deps.clone());
        let services = davhaven_app::build_from_core(&core);
        let app = davhaven_app::workers::build(&core);
        let mut workers = parts.workers;
        workers.extend(app.workers);
        // The worker that keeps the profile signer current with its files, when the deployment has one.
        workers.extend(report.profile_signer.worker(Arc::clone(&deps.clock)));
        Ok(Assembly {
            core,
            config,
            deps,
            services,
            workers,
            worker_hooks: app.lifecycles,
            hooks: parts.hooks,
            report,
        })
    }
}

/// Checks the configuration (no database needed) and builds everything.
///
/// The check runs on the blocking pool ([`plugins::check_on_blocking_pool`]), as it does in every command of the binary
/// (`cli::load_checked`): it reads files and loads and renders the themes. A caller that has checked the configuration
/// already builds from that report with [`Foundation::assemble`], as `davhaven serve` does.
///
/// # Errors
///
/// [`ServerError`] for the first problem: an invalid configuration, a missing file, a plugin that cannot start.
pub async fn assemble(config: Arc<Config>, registry: &Arc<PluginRegistry>) -> Result<Assembly, ServerError> {
    let report = plugins::check_on_blocking_pool(&config, registry).await?;
    let foundation = Foundation::new(config, registry)?;
    foundation.assemble(registry, report).await
}

/// [`assemble`] with another clock and id generator, for tests of the assembled server.
///
/// # Errors
///
/// As [`assemble`].
pub async fn assemble_with_ports(
    config: Arc<Config>,
    registry: &Arc<PluginRegistry>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
) -> Result<Assembly, ServerError> {
    let report = plugins::check_on_blocking_pool(&config, registry).await?;
    let foundation = Foundation::with_ports(config, registry, clock, ids)?;
    foundation.assemble(registry, report).await
}

#[cfg(test)]
mod tests {
    use davhaven_ports::KeyPurpose;

    use super::*;
    use crate::registry::registry;

    const DEV: &str = r#"
        [server]
        mode = "dev"
        public_base_url = "http://localhost:8080"
        [plugins]
        store = "memory"
        mail_transport = "memory"
        templates = "minijinja"
        rate_limiter = "memory"
        http_client = "recording"
    "#;

    fn config(extra: &str) -> Arc<Config> {
        Arc::new(Config::from_toml(&format!("{DEV}\n{extra}")).unwrap())
    }

    #[tokio::test]
    async fn a_development_configuration_assembles_with_workers_and_services() {
        let registry = Arc::new(registry().unwrap());
        let assembly = assemble(config(""), &registry).await.unwrap();
        let names: Vec<&str> = assembly.workers.iter().map(|worker| worker.name()).collect();
        for expected in ["outbox", "retention"] {
            assert!(names.contains(&expected), "{names:?}");
        }
        assert_eq!(assembly.deps.authenticators.len(), 1);
        assert_eq!(assembly.deps.event_sinks.len(), 1, "the log sink");
        assert_eq!(assembly.services.urls.public_base().as_str(), "http://localhost:8080/");
        assert!(
            assembly
                .report
                .warnings
                .iter()
                .any(|warning| warning.contains("signing keys"))
        );
        assert!(
            !assembly.worker_hooks.is_empty(),
            "the outbox worker releases its leases at shutdown"
        );
        assert!(
            assembly
                .hooks
                .iter()
                .any(|hook| hook.name.starts_with("database:") && !hook.check_health)
        );
        assert_eq!(assembly.deps.database.health().await, davhaven_ports::Health::Healthy);
        assert!(format!("{assembly:?}").contains("outbox"));
    }

    #[tokio::test]
    async fn production_mode_refuses_what_the_checks_refuse_before_anything_is_built() {
        let registry = Arc::new(registry().unwrap());
        let production = Config::from_toml(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[plugins]\nstore = \"memory\"\n\
             [[security.keys]]\nid = \"k1\"\nsecret_file = \"/x\"",
        )
        .unwrap();
        let error = assemble(Arc::new(production), &registry).await.map(|_| ()).unwrap_err();
        assert!(error.to_string().contains("plugins.store"), "{error}");
    }

    #[tokio::test]
    async fn plugin_failures_name_the_plugin() {
        let registry = Arc::new(registry().unwrap());
        let broken = config("[plugin.minijinja]\ntheme_dirs = [\"/does/not/exist\"]");
        let error = assemble(broken, &registry).await.map(|_| ()).unwrap_err();
        assert!(
            error.to_string().contains("minijinja") || error.to_string().contains("theme"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn the_key_ring_comes_from_the_files_or_is_generated_for_development() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, "0123456789abcdef0123456789abcdef0123456789\n").unwrap();
        let keyed = config(&format!(
            "[[security.keys]]\nid = \"2027-01\"\nsecret_file = {:?}",
            path.display().to_string()
        ));
        let registry = registry().unwrap();
        let foundation = Foundation::new(keyed, &registry).unwrap();
        let active = |foundation: &Foundation| foundation.keyring.active_kid(KeyPurpose::CredentialPepper);
        assert_eq!(active(&foundation), "2027-01");
        let generated = Foundation::new(config(""), &registry).unwrap();
        assert_eq!(active(&generated), EPHEMERAL_KEY_ID);
        let again = Foundation::new(config(""), &registry).unwrap();
        let signature = generated.keyring.sign(KeyPurpose::Cursor, b"cursor");
        assert!(
            !again.keyring.verify(KeyPurpose::Cursor, b"cursor", &signature),
            "every process generates its own development key"
        );
        assert!(generated.keyring.verify(KeyPurpose::Cursor, b"cursor", &signature));
    }

    #[tokio::test]
    async fn the_database_alone_can_be_built_for_administrative_commands() {
        let registry = registry().unwrap();
        let foundation = Foundation::new(config(""), &registry).unwrap();
        let built = foundation.database(&registry).await.unwrap();
        assert_eq!(built.port.health().await, davhaven_ports::Health::Healthy);
        assert!(built.lifecycle.is_some());
    }

    #[tokio::test]
    async fn a_store_only_command_reads_no_key_file() {
        let registry = registry().unwrap();
        // The key file named here does not exist: `new` reads it and fails, `for_store` never looks at it.
        let keyed = config("[[security.keys]]\nid = \"2027-01\"\nsecret_file = \"/does/not/exist\"");
        assert!(
            Foundation::new(Arc::clone(&keyed), &registry).is_err(),
            "the key file is read"
        );
        let foundation = Foundation::for_store(keyed, &registry).unwrap();
        assert_eq!(
            foundation.keyring.active_kid(KeyPurpose::CredentialPepper),
            EPHEMERAL_KEY_ID
        );
        let built = foundation.database(&registry).await.unwrap();
        assert_eq!(built.port.health().await, davhaven_ports::Health::Healthy);
    }

    #[tokio::test]
    async fn the_assembly_runs_on_the_clock_and_ids_it_is_given() {
        use davhaven_ports::testing::{ManualClock, SeqIds};
        let clock = Arc::new(ManualClock::default());
        let ids: Arc<dyn IdGenerator> = Arc::new(SeqIds::new());
        let assembly = assemble_with_ports(
            config(""),
            &Arc::new(registry().unwrap()),
            Arc::<ManualClock>::clone(&clock),
            Arc::clone(&ids),
        )
        .await
        .unwrap();
        let before = assembly.deps.clock.now();
        clock.advance(chrono::TimeDelta::hours(1));
        assert_eq!(assembly.deps.clock.now() - before, chrono::TimeDelta::hours(1));
    }

    /// What the check of the plugin `probe` saw: the thread of the test, and whether a check ran on it.
    static CALLER: std::sync::OnceLock<std::thread::ThreadId> = std::sync::OnceLock::new();
    static CHECKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static CHECKED_ON_THE_CALLER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// The check of the plugin `probe`: records the thread it runs on.
    #[expect(clippy::unnecessary_wraps, reason = "the signature of `CheckFn`")]
    fn probe_check(_check: &davhaven_ports::PluginCheck<'_>) -> Result<Vec<String>, davhaven_ports::PluginError> {
        use std::sync::atomic::Ordering;
        CHECKS.fetch_add(1, Ordering::SeqCst);
        if CALLER.get() == Some(&std::thread::current().id()) {
            CHECKED_ON_THE_CALLER.store(true, Ordering::SeqCst);
        }
        Ok(Vec::new())
    }

    /// A scanner that finds nothing, built by the plugin `probe`.
    struct ProbeScanner;

    #[async_trait::async_trait]
    impl davhaven_ports::ContentScanner for ProbeScanner {
        fn name(&self) -> &'static str {
            "probe"
        }

        async fn scan(
            &self,
            _content: &[u8],
            _context: &davhaven_ports::ScanContext,
        ) -> Result<davhaven_ports::ScanVerdict, davhaven_ports::PortError> {
            Ok(davhaven_ports::ScanVerdict::Clean)
        }
    }

    /// The registry of the server with a content scanner called `probe` whose check is `check`.
    fn registry_with_probe(check: davhaven_ports::CheckFn) -> Arc<PluginRegistry> {
        use davhaven_ports::{Built, ContentScanner, PluginContext, PluginDescriptor};

        let mut plugins = registry().unwrap();
        plugins
            .register(
                davhaven_ports::PortKind::CONTENT_SCANNER,
                PluginDescriptor::new(
                    "probe",
                    "A scanner whose check the test chooses.",
                    || schemars::json_schema!({"type": "object"}),
                    |_context: PluginContext, _config: serde_json::Value| {
                        Box::pin(async {
                            let scanner: Arc<dyn ContentScanner> = Arc::new(ProbeScanner);
                            Ok(Built::new(scanner))
                        })
                    },
                )
                .with_check(check),
            )
            .unwrap();
        Arc::new(plugins)
    }

    #[tokio::test]
    async fn the_entries_of_the_assembly_check_the_configuration_on_the_blocking_pool() {
        use std::sync::atomic::Ordering;

        use davhaven_ports::testing::{ManualClock, SeqIds};

        // The check reads files and loads the themes: blocking work that `davhaven serve` keeps off the runtime (R14), and
        // the entries of the assembly used to run it on the calling thread. A plugin whose check records its thread shows
        // where it ran; the test runs on a runtime of one thread, so the thread of the test is the calling thread.
        let plugins = registry_with_probe(probe_check);
        // `DEV` ends inside `[plugins]`, so the key joins that table.
        let configuration = config("content_scanners = [\"probe\"]");
        let _ = CALLER.set(std::thread::current().id());

        assemble(Arc::clone(&configuration), &plugins).await.unwrap();
        assert_eq!(CHECKS.load(Ordering::SeqCst), 1, "assemble checks the plugin once");
        assemble_with_ports(
            configuration,
            &plugins,
            Arc::new(ManualClock::default()),
            Arc::new(SeqIds::new()),
        )
        .await
        .unwrap();
        assert_eq!(CHECKS.load(Ordering::SeqCst), 2, "and so does assemble_with_ports");
        assert!(
            !CHECKED_ON_THE_CALLER.load(Ordering::SeqCst),
            "a check ran on the calling thread instead of the blocking pool"
        );
    }

    /// The check of a plugin that panics.
    fn panicking_check(_check: &davhaven_ports::PluginCheck<'_>) -> Result<Vec<String>, davhaven_ports::PluginError> {
        let refused: Result<Vec<String>, davhaven_ports::PluginError> =
            Err(davhaven_ports::PluginError::invalid_config("probe", "refused"));
        assert!(refused.is_ok(), "the check of this plugin panics");
        refused
    }

    #[tokio::test]
    async fn a_check_that_does_not_finish_is_a_task_that_did_not_finish_and_no_command() {
        let plugins = registry_with_probe(panicking_check);
        let error = assemble(config("content_scanners = [\"probe\"]"), &plugins)
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(&error, ServerError::Task { task, .. } if *task == "the check of the configuration"),
            "{error:?}"
        );
        assert!(error.to_string().contains("did not finish"), "{error}");
    }
}
