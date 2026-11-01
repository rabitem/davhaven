//! `TestApp` and its builder.
//!
//! `TestApp::builder().store(StoreKind::Memory).clock(clock).ids(ids).config(config).build().await` builds the
//! **real application** the way `davhaven serve` builds it, on a seeded [`FixtureWorld`], and hands out the handles
//! a test talks to it with: [`TestApp::dav`], [`TestApp::api`], [`TestApp::mcp`], [`TestApp::feed`] and
//! [`TestApp::rsvp`] send requests through the in-process [`Transport`]; [`TestApp::mails`] and [`TestApp::events`]
//! show the side effects; [`TestApp::clock`] moves time and [`TestApp::run_workers_until_idle`] runs the background
//! workers without sleeping.
//!
//! # What runs behind the handles
//!
//! * The ports are built through the plugin registry of the server (`davhaven_server::registry`) from a development
//!   configuration: the memory or the PostgreSQL store, the local authenticator, the template renderer, the default
//!   scheduling policy, the recording HTTP client and the `noop` rate limiter (the matrix profile of PLAN 3.2). The
//!   clock and the id generator are the manual clock and the sequential ids of the builder.
//! * The mail transport and one event sink are the captures of the harness ([`MailCapture`], [`EventCapture`]): they
//!   are part of the `AppDeps` the services and the workers are built from, so every mail the application composes and
//!   every domain event it delivers is observable.
//! * The routers are those of `davhaven serve`: [`listener_router`] with
//!   every route group on one listener (wellknown, dav, web, api, mcp and ops), behind the shared edge layers. Requests
//!   reach them through [`InProcess`], without a network.
//! * The world is seeded through the services (see [`crate::seed`]); credentials are the constant secrets of the world.
//!
//! The PostgreSQL store runs the same application on a database cloned from the migrated template, connected as the
//! `NOBYPASSRLS` runtime role (see [`crate::postgres`]).
//!
//! Time moves only through the [`ManualClock`]: [`TestApp::advance`] advances it and everything built on it (the
//! services, the workers, the credential cache) follows.

use core::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use chrono::Duration;
use davhaven_app::AppConfig;
use davhaven_app::AppServices;
use davhaven_app::error::AppError;
use davhaven_app::services::{AuthRequest, PresentedCredential, SecretString};
use davhaven_app::sync_engine::ProviderSyncWorker;
use davhaven_app::{AppCore, AppDeps, build_from_core};
use davhaven_domain::{Channel, Limits, RequestContext, RequestId, Scope, TenantId, TenantSettings};
use davhaven_fixtures::{ActorRole, FixtureError, FixtureWorld, named_enum};
use davhaven_ports::testing::{ManualClock, SeqIds};
use davhaven_ports::{Clock, Database, IdGenerator, Lifecycle, Provider, StoreError, Worker};
use davhaven_server::assembly::Foundation;
use davhaven_server::capture::{Capture, CaptureLimits};
use davhaven_server::config::Config;
use davhaven_server::listeners::{ListenerName, ResolvedListener, RouteGroup};
use davhaven_server::ops::OpsState;
use davhaven_server::plugins::check_on_blocking_pool;
use davhaven_server::registry::registry;
use davhaven_server::server::listener_router;
use davhaven_server::workers::Supervisor;
use url::Url;

use crate::busy::Watched;
use crate::capture::{EventCapture, MailCapture, Snapshot};
use crate::credentials::CredentialBook;
use crate::flow::ScenarioEnv;
use crate::handles::{Actor, ApiHandle, DavHandle, FeedHandle, McpHandle, RsvpHandle, Token};
use crate::matrix::Surface;
use crate::postgres::ClonedDatabase;
use crate::seed::{SeedIndex, seed_world};
use crate::transport::{InProcess, Transport, TransportError};

/// How many passes over the workers [`TestApp::run_workers_until_idle`] makes before it gives up.
pub const MAX_WORKER_PASSES: u32 = 1000;

/// The host of [`PUBLIC_BASE_URL`]: in-process requests carry it as their `Host`, as the requests of a browser do.
pub const PUBLIC_HOST: &str = "cal.example.org";

/// The public base URL of the application under test: absolute URLs in mails, feeds and API views are built from it.
pub const PUBLIC_BASE_URL: &str = "https://cal.example.org";

named_enum! {
    /// Which store backs the application.
    pub enum StoreKind {
        /// The in-memory store.
        Memory => "memory",
        /// PostgreSQL, reached through `DATABASE_URL`.
        Postgres => "postgres",
    }
}

/// Failures of building or using a [`TestApp`].
#[derive(Debug, thiserror::Error)]
pub enum TestAppError {
    /// A lookup in the fixture world failed.
    #[error(transparent)]
    Fixture(#[from] FixtureError),
    /// The requested store cannot be used.
    #[error("the {store} store is not available: {reason}")]
    StoreUnavailable {
        /// The requested store.
        store: StoreKind,
        /// Why not.
        reason: String,
    },
    /// The configuration is invalid.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// The application cannot be assembled from its configuration.
    #[error("cannot assemble the application: {0}")]
    Assembly(String),
    /// The fixture world cannot be seeded into the application.
    #[error("cannot seed the fixture world: {0}")]
    Seed(String),
    /// The role has no credential on the surface.
    #[error("the role `{0}` has no credential here")]
    NoCredential(ActorRole),
    /// A service of the application failed.
    #[error("application error: {0}")]
    App(#[from] AppError),
    /// A request could not be carried.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The workers still had work after the maximum number of passes.
    #[error("the workers still had work after {passes} passes")]
    WorkersBusy {
        /// The number of passes made.
        passes: u32,
    },
    /// The store could not be read for an observation.
    #[error("cannot observe the application: {0}")]
    Observe(String),
    /// The store refused a request of the harness.
    #[error("the store refused it: {0}")]
    Store(StoreError),
    /// The application cannot be served on a socket.
    #[error("cannot serve the application: {0}")]
    Serve(String),
}

/// The texts by which a failure of the store that repeating may cure (`StoreError::is_retryable`) shows in the error of an
/// assembly (the message of the port error: `timed out`, `unavailable`) and of a seeding (the debug form of the store error:
/// `Timeout`, `Unavailable`), and the end of a connection that the server closed.
const TRANSIENT_TEXTS: [&str; 5] = ["timed out", "Timeout", "unavailable", "Unavailable", "EOF"];

/// Whether a failure to build an application is one that a second attempt may not repeat: the store was not reachable, or too slow.
fn is_transient(error: &TestAppError) -> bool {
    match error {
        TestAppError::StoreUnavailable { store, .. } => *store == StoreKind::Postgres,
        TestAppError::Assembly(reason) | TestAppError::Seed(reason) => {
            TRANSIENT_TEXTS.iter().any(|text| reason.contains(text))
        }
        _ => false,
    }
}

/// What [`TestApp::run_workers_until_idle`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkSummary {
    /// How many passes over all workers were made (the last one found nothing to do).
    pub passes: u32,
    /// Items handled successfully.
    pub processed: u32,
    /// Items that failed.
    pub failed: u32,
}

named_enum! {
    /// The rate limiter of the application under test.
    pub enum LimiterProfile {
        /// The matrix profile: nothing is limited and failed logins never back off (PLAN 3.2).
        Noop => "noop",
        /// The in-process limiter of a single instance, as configured by default.
        Memory => "memory",
    }
}

type RouterFactory = Box<dyn FnOnce(&AppServices) -> Router + Send>;
type Configure = Box<dyn FnOnce(&mut AppConfig) + Send>;
type DatabaseLayer = Box<dyn FnOnce(Arc<dyn Database>) -> Arc<dyn Database> + Send>;

/// Builds a [`TestApp`].
#[must_use]
pub struct TestAppBuilder {
    store: StoreKind,
    clock: Option<ManualClock>,
    ids: Option<SeqIds>,
    config: Option<AppConfig>,
    configure: Vec<Configure>,
    limits: Option<Limits>,
    world: Option<FixtureWorld>,
    seeded: bool,
    tenant_settings: Vec<(String, TenantSettings)>,
    router: Option<RouterFactory>,
    workers: Vec<Arc<dyn Worker>>,
    limiter: LimiterProfile,
    server_toml: Vec<String>,
    providers: Option<Vec<Arc<dyn Provider>>>,
    database_layer: Option<DatabaseLayer>,
}

impl fmt::Debug for TestAppBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestAppBuilder")
            .field("store", &self.store)
            .field("seeded", &self.seeded)
            .finish_non_exhaustive()
    }
}

impl TestAppBuilder {
    /// Selects the store (default: memory).
    pub fn store(mut self, store: StoreKind) -> Self {
        self.store = store;
        self
    }

    /// Uses this clock; keep a clone to move time from the test (default: a fresh `ManualClock`, which starts at
    /// 2027-01-01T00:00:00Z).
    pub fn clock(mut self, clock: ManualClock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Uses this id generator (default: a fresh `SeqIds`).
    pub fn ids(mut self, ids: SeqIds) -> Self {
        self.ids = Some(ids);
        self
    }

    /// Uses this application configuration (default: the one of a development server). It is validated by `build`.
    pub fn config(mut self, config: AppConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Changes the application configuration after the defaults (or [`TestAppBuilder::config`]) were applied; for
    /// example `.configure(|config| config.scheduling.inbound_itip.enabled = true)`.
    pub fn configure(mut self, change: impl FnOnce(&mut AppConfig) + Send + 'static) -> Self {
        self.configure.push(Box::new(change));
        self
    }

    /// Uses these limits (default: `Limits::default()`).
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Seeds this world instead of [`FixtureWorld::standard`].
    pub fn world(mut self, world: FixtureWorld) -> Self {
        self.world = Some(world);
        self
    }

    /// Starts without any tenant, principal or calendar.
    pub fn empty(mut self) -> Self {
        self.seeded = false;
        self
    }

    /// Replaces the settings of the tenant with the slug `tenant` before the world is seeded.
    pub fn tenant_settings(mut self, tenant: &str, settings: TenantSettings) -> Self {
        self.tenant_settings.push((tenant.to_owned(), settings));
        self
    }

    /// Serves in-process requests with the router that `build_router` builds from the application services instead
    /// of the routers of the server.
    pub fn router(mut self, build_router: impl FnOnce(&AppServices) -> Router + Send + 'static) -> Self {
        self.router = Some(Box::new(build_router));
        self
    }

    /// Adds a background worker that [`TestApp::run_workers_until_idle`] ticks.
    pub fn worker(mut self, worker: Arc<dyn Worker>) -> Self {
        self.workers.push(worker);
        self
    }

    /// Replaces the calendar providers of the application with `providers`, for a test that writes the remote world of a
    /// provider (the `Script` of a `FakeProvider`). Without it the application has the providers that the configuration of the
    /// harness selects: a fake of its own, whose remote world nobody reaches. An empty list switches every provider off.
    pub fn providers(mut self, providers: Vec<Arc<dyn Provider>>) -> Self {
        self.providers = Some(providers);
        self
    }

    /// Wraps the store in what `layer` returns before anything of the application receives it: the transactions of the
    /// services, the workers and the adapters (the authenticator, the webhook handler), of the seeding of the world and of
    /// the observations of the harness all go through the wrapper (for example `davhaven_ports::testing::RollbackWatch`).
    pub fn database_layer(
        mut self,
        layer: impl FnOnce(Arc<dyn Database>) -> Arc<dyn Database> + Send + 'static,
    ) -> Self {
        self.database_layer = Some(Box::new(layer));
        self
    }

    /// Selects the rate limiter (default: [`LimiterProfile::Noop`], the matrix profile).
    pub fn limiter(mut self, limiter: LimiterProfile) -> Self {
        self.limiter = limiter;
        self
    }

    /// Adds TOML to the configuration of the server (a development configuration with the plugins of the harness), for
    /// the settings that are not part of the application configuration, for example `[mcp]`. The TOML is merged into the
    /// configuration table by table: a key that the harness sets too (`[mcp] enabled`) takes the value given here, and the
    /// other keys of its table stay. Text that is not a TOML document is reported by `build` as [`TestAppError::Config`].
    pub fn server_config(mut self, toml: &str) -> Self {
        self.server_toml.push(toml.to_owned());
        self
    }

    /// Builds the application.
    ///
    /// # Errors
    ///
    /// [`TestAppError::StoreUnavailable`] for the PostgreSQL store when no database is configured (with `CI=true` the
    /// message says that a test needing PostgreSQL fails instead of skipping), [`TestAppError::Config`] for an invalid
    /// configuration or limits, [`TestAppError::Assembly`] when the application cannot be assembled and
    /// [`TestAppError::Seed`] when the fixture world cannot be seeded.
    pub async fn build(self) -> Result<TestApp, TestAppError> {
        let Self {
            store,
            clock,
            ids,
            config,
            configure,
            limits,
            world,
            seeded,
            tenant_settings,
            router,
            workers,
            limiter,
            server_toml,
            providers,
            database_layer,
        } = self;
        let clock = clock.unwrap_or_default();
        let ids = ids.unwrap_or_default();
        let database = match store {
            StoreKind::Memory => None,
            StoreKind::Postgres => Some(ClonedDatabase::create().await?),
        };
        let toml = server_configuration(store, database.as_ref(), limiter, &server_toml)?;
        let server_config =
            Arc::new(Config::from_toml(&toml).map_err(|error| TestAppError::Config(error.to_string()))?);
        let plugins = Arc::new(registry().map_err(|error| TestAppError::Assembly(error.to_string()))?);
        let system_clock: Arc<dyn Clock> = Arc::new(clock.clone());
        let system_ids: Arc<dyn IdGenerator> = Arc::new(ids.clone());
        let report = check_on_blocking_pool(&server_config, &plugins)
            .await
            .map_err(|error| TestAppError::Assembly(error.to_string()))?;
        let mut foundation = Foundation::with_ports(Arc::clone(&server_config), &plugins, system_clock, system_ids)
            .map_err(|error| TestAppError::Assembly(error.to_string()))?;
        if let Some(layer) = database_layer {
            foundation = foundation.with_database_layer(layer);
        }
        let assembly = foundation
            .assemble(&plugins, report)
            .await
            .map_err(|error| TestAppError::Assembly(error.to_string()))?;

        // The captures replace the mail transport and join the event sinks: the services and the workers of the
        // application are built again from the changed dependencies.
        let mails = MailCapture::new(Arc::new(clock.clone()));
        let events = EventCapture::new();
        let mut deps: AppDeps = assembly.deps.clone();
        deps.mail = Arc::new(mails.clone());
        deps.event_sinks.push(Arc::new(events.clone()));
        if let Some(providers) = providers {
            deps.providers = providers;
        }
        configure_deps(&mut deps, config, configure, limits)?;
        let core = AppCore::new(deps.clone());
        let services = build_from_core(&core);
        let app_workers = davhaven_app::workers::build(&core);
        let lifecycles = app_workers.lifecycles.clone();
        let all_workers = merge_workers(&assembly.workers, app_workers.workers, workers)?;
        let mut hooks: Vec<Arc<dyn Lifecycle>> = lifecycles;
        hooks.extend(assembly.hooks.iter().rev().map(|hook| Arc::clone(&hook.lifecycle)));

        let world = world.unwrap_or_else(FixtureWorld::standard);
        let index = if seeded {
            seed_world(&deps, &services, &world, &tenant_settings).await?
        } else {
            SeedIndex::default()
        };
        // The capture of DAV exchanges (`[observability.dav_capture]` of the server configuration of the builder) is part of
        // the routers of the server like it is in `davhaven serve`.
        let capture = Capture::start(
            &server_config.observability.dav_capture,
            Arc::new(clock.clone()),
            Arc::clone(&deps.database),
            CaptureLimits::of(&server_config),
        )
        .await
        .map_err(|error| TestAppError::Config(error.to_string()))?;
        let router = match router {
            Some(build_router) => build_router(&services),
            None => production_router(&server_config, &services, &deps, capture.as_ref()),
        };
        let book = CredentialBook::from_world(&world);
        Ok(TestApp {
            services,
            deps,
            world: Arc::new(world),
            book: Arc::new(book),
            index,
            clock,
            ids,
            store,
            transport: carrier(&router),
            router,
            mails,
            events,
            workers: all_workers,
            hooks,
            _database: database,
        })
    }
}

/// The workers the harness ticks: the ones of the assembly that the harness did not build again, the ones it built again on its own
/// dependencies and the ones of the builder.
///
/// The assembly built the workers of the application on a core of its own, with the mail transport of the configuration. The
/// harness builds them again on the dependencies with the captures, so the assembly's copies of exactly those workers (the ones
/// `davhaven_app::workers::build` returns, whatever they are called) are left out. A worker that is added there later is left out
/// of the assembly's list too, and one that would be ticked twice is an error.
fn merge_workers(
    assembled: &[Arc<dyn Worker>],
    rebuilt: Vec<Arc<dyn Worker>>,
    extra: Vec<Arc<dyn Worker>>,
) -> Result<Vec<Arc<dyn Worker>>, TestAppError> {
    let mut replaced: std::collections::BTreeSet<&str> = rebuilt.iter().map(|worker| worker.name()).collect();
    // The sync worker of the assembly pulls the accounts of the providers that the assembly built. When the builder replaced the
    // providers there are none of those, and a worker that stays would pull the accounts of a provider nobody can reach.
    replaced.insert(ProviderSyncWorker::NAME);
    let mut all: Vec<Arc<dyn Worker>> = assembled
        .iter()
        .filter(|worker| !replaced.contains(worker.name()))
        .cloned()
        .collect();
    all.extend(rebuilt);
    all.extend(extra);
    let mut seen = std::collections::BTreeSet::new();
    if let Some(twice) = all.iter().map(|worker| worker.name()).find(|name| !seen.insert(*name)) {
        return Err(TestAppError::Assembly(format!(
            "the worker `{twice}` would be ticked twice: the harness and the server both build it"
        )));
    }
    Ok(all)
}

/// Applies the application configuration and the limits of the builder to the dependencies and validates them.
fn configure_deps(
    deps: &mut AppDeps,
    config: Option<AppConfig>,
    configure: Vec<Configure>,
    limits: Option<Limits>,
) -> Result<(), TestAppError> {
    if let Some(config) = config {
        deps.config = config;
    }
    for change in configure {
        change(&mut deps.config);
    }
    deps.config
        .validate()
        .map_err(|error| TestAppError::Config(error.to_string()))?;
    if let Some(limits) = limits {
        limits
            .validate()
            .map_err(|error| TestAppError::Config(error.to_string()))?;
        deps.limits = limits;
    }
    Ok(())
}

/// Merges `extra` into `base`: tables are merged key by key, any other value replaces the one of the base.
fn merge_tables(base: &mut toml::Table, extra: toml::Table) {
    for (key, value) in extra {
        match value {
            toml::Value::Table(more) => match base.get_mut(&key) {
                Some(toml::Value::Table(existing)) => merge_tables(existing, more),
                _ => {
                    base.insert(key, toml::Value::Table(more));
                }
            },
            other => {
                base.insert(key, other);
            }
        }
    }
}

/// The TOML of the development configuration the harness assembles the application from, with the extra settings of the
/// builder merged in.
fn server_configuration(
    store: StoreKind,
    database: Option<&ClonedDatabase>,
    limiter: LimiterProfile,
    extras: &[String],
) -> Result<String, TestAppError> {
    let database_table = database.map_or_else(String::new, |database| {
        format!(
            "[database]\nurl = \"{}\"\nmigrate_on_start = false\nmax_connections = 4\nacquire_timeout = \"30s\"\n",
            database.runtime_url()
        )
    });
    let base = format!(
        "[server]\nmode = \"dev\"\npublic_base_url = \"{PUBLIC_BASE_URL}\"\n\n\
         [plugins]\nstore = \"{store}\"\nmail_transport = \"memory\"\ntemplates = \"minijinja\"\n\
         http_client = \"recording\"\nrate_limiter = \"{limiter}\"\nproviders = [\"fake\"]\n\n\
         [mcp]\nenabled = true\n\n{database_table}\n"
    );
    if extras.is_empty() {
        return Ok(base);
    }
    let mut table: toml::Table = base
        .parse()
        .map_err(|error: toml::de::Error| TestAppError::Config(error.to_string()))?;
    for extra in extras {
        let more: toml::Table = extra.parse().map_err(|error: toml::de::Error| {
            TestAppError::Config(format!("the extra server configuration: {error}"))
        })?;
        merge_tables(&mut table, more);
    }
    toml::to_string(&table).map_err(|error| TestAppError::Config(error.to_string()))
}

/// The routers of the server with every route group on one listener.
fn production_router(
    config: &Arc<Config>,
    services: &AppServices,
    deps: &AppDeps,
    capture: Option<&Arc<Capture>>,
) -> Router {
    let listener = ResolvedListener {
        name: ListenerName::Public,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        routes: RouteGroup::ALL.to_vec(),
    };
    let ops = OpsState::new(
        Arc::clone(&deps.database),
        Vec::new(),
        Supervisor::new(Vec::new()).heartbeats(),
        None,
    );
    listener_router(&listener, services, config, &deps.ids, &ops, capture)
}

/// The in-process transport of `router`, which counts the busy answers it carries ([`TestApp::busy_answers`]).
fn carrier(router: &Router) -> Arc<Watched> {
    Arc::new(Watched::new(Arc::new(
        InProcess::new(router.clone()).with_host(PUBLIC_HOST),
    )))
}

/// An application that listens on a socket (see [`TestApp::serve`]).
#[derive(Debug)]
pub struct Served {
    /// The base URL of the server: `http://127.0.0.1:{port}/`.
    pub base_url: Url,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A complete application with handles for every surface.
pub struct TestApp {
    services: AppServices,
    deps: AppDeps,
    world: Arc<FixtureWorld>,
    book: Arc<CredentialBook>,
    index: SeedIndex,
    clock: ManualClock,
    ids: SeqIds,
    store: StoreKind,
    transport: Arc<Watched>,
    router: Router,
    mails: MailCapture,
    events: EventCapture,
    workers: Vec<Arc<dyn Worker>>,
    hooks: Vec<Arc<dyn Lifecycle>>,
    /// Kept so that the cloned database is dropped with the application.
    _database: Option<ClonedDatabase>,
}

impl fmt::Debug for TestApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestApp")
            .field("store", &self.store)
            .field("workers", &self.workers.len())
            .finish_non_exhaustive()
    }
}

impl TestApp {
    /// Builds the application that `factory` describes, and makes it again (three attempts in all, with a pause that grows) when
    /// the store was not there for a moment: a PostgreSQL server that is shared with other test processes drops a connection or
    /// is slow to accept one now and then. Any other failure is returned at once.
    ///
    /// # Errors
    ///
    /// The error of the last attempt.
    pub async fn build_with_retries(factory: impl Fn() -> TestAppBuilder) -> Result<Self, TestAppError> {
        let mut attempt = 1_u32;
        loop {
            match factory().build().await {
                Ok(app) => return Ok(app),
                Err(error) if attempt < 3 && is_transient(&error) => {
                    tokio::time::sleep(core::time::Duration::from_secs(u64::from(attempt))).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Starts building an application: memory store, the standard fixture world, a fresh manual clock and id
    /// generator, the default configuration.
    pub fn builder() -> TestAppBuilder {
        TestAppBuilder {
            store: StoreKind::Memory,
            clock: None,
            ids: None,
            config: None,
            configure: Vec::new(),
            limits: None,
            world: None,
            seeded: true,
            tenant_settings: Vec::new(),
            router: None,
            workers: Vec::new(),
            limiter: LimiterProfile::Noop,
            server_toml: Vec::new(),
            providers: None,
            database_layer: None,
        }
    }

    /// The application services: what protocol routers receive.
    pub const fn services(&self) -> &AppServices {
        &self.services
    }

    /// The dependencies the services were built from: the ports (the database among them), the captures and the
    /// configuration.
    pub const fn deps(&self) -> &AppDeps {
        &self.deps
    }

    /// The fixture world the application was seeded with.
    pub fn world(&self) -> &FixtureWorld {
        &self.world
    }

    /// The credentials of the roles.
    pub fn book(&self) -> &CredentialBook {
        &self.book
    }

    /// The ids of what was seeded.
    pub const fn index(&self) -> &SeedIndex {
        &self.index
    }

    /// The manual clock; advance it with [`TestApp::advance`].
    pub const fn clock(&self) -> &ManualClock {
        &self.clock
    }

    /// The deterministic id generator.
    pub const fn ids(&self) -> &SeqIds {
        &self.ids
    }

    /// The application configuration.
    pub const fn config(&self) -> &AppConfig {
        &self.deps.config
    }

    /// The store the application runs on.
    pub const fn store(&self) -> StoreKind {
        self.store
    }

    /// The mails captured so far.
    pub const fn mails(&self) -> &MailCapture {
        &self.mails
    }

    /// The domain events captured so far.
    pub const fn events(&self) -> &EventCapture {
        &self.events
    }

    /// The id of a tenant of the world, by slug.
    pub fn tenant_id(&self, slug: &str) -> Option<TenantId> {
        self.index.tenant(slug)
    }

    /// Serves the routers of the application on a socket of the loopback interface, for the code that talks to a deployed
    /// instance over HTTP (the staging runner): the same application, reached the way a client reaches a server. The
    /// server stops when the returned [`Served`] is dropped.
    ///
    /// # Errors
    ///
    /// [`TestAppError::Serve`] when no socket can be bound.
    pub async fn serve(&self) -> Result<Served, TestAppError> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|error| TestAppError::Serve(format!("cannot bind a socket: {error}")))?;
        let address = listener
            .local_addr()
            .map_err(|error| TestAppError::Serve(format!("cannot read the address of the socket: {error}")))?;
        let service = self.router.clone().into_make_service_with_connect_info::<SocketAddr>();
        let task = tokio::spawn(async move {
            drop(axum::serve(listener, service).await);
        });
        let base_url = Url::parse(&format!("http://{address}/"))
            .map_err(|error| TestAppError::Serve(format!("the address of the socket is not a URL: {error}")))?;
        Ok(Served { base_url, task })
    }

    /// The in-process transport, for handles and the scenario runner. It counts the busy answers it carries
    /// ([`TestApp::busy_answers`]).
    pub fn transport(&self) -> Arc<dyn Transport> {
        Arc::<Watched>::clone(&self.transport)
    }

    /// How many answers of the application so far said that it was too busy to answer ([`crate::busy::is_busy`]: a 503, or an MCP
    /// tool that failed as unavailable). A case that ran on an application of its own and failed with nothing but such answers
    /// in the count may be run again on a new one ([`crate::busy::repeat_while_busy`]).
    pub fn busy_answers(&self) -> u32 {
        self.transport.busy_answers()
    }

    /// The DAV surface as `actor`.
    pub fn dav(&self, actor: &Actor) -> DavHandle {
        DavHandle::new(self.transport(), actor.clone())
    }

    /// The management API as the holder of `token`.
    pub fn api(&self, token: &Token) -> ApiHandle {
        ApiHandle::new(self.transport(), Actor::from(token))
    }

    /// The management API with any credential (for credential-versus-surface cases).
    pub fn api_as(&self, actor: &Actor) -> ApiHandle {
        ApiHandle::new(self.transport(), actor.clone())
    }

    /// The MCP surface as the holder of `token`.
    pub fn mcp(&self, token: &Token) -> McpHandle {
        McpHandle::new(self.transport(), Actor::from(token))
    }

    /// The MCP surface with any credential.
    pub fn mcp_as(&self, actor: &Actor) -> McpHandle {
        McpHandle::new(self.transport(), actor.clone())
    }

    /// The subscription feed of `token`.
    pub fn feed(&self, token: &str) -> FeedHandle {
        FeedHandle::new(self.transport(), token)
    }

    /// The RSVP pages.
    pub fn rsvp(&self) -> RsvpHandle {
        RsvpHandle::new(self.transport())
    }

    /// The credentials of `role` on DAV: its app password, or for the roles that have none the credential they do
    /// have.
    ///
    /// # Errors
    ///
    /// [`TestAppError::NoCredential`] when the role has no credential at all.
    pub fn actor(&self, role: ActorRole) -> Result<Actor, TestAppError> {
        self.book
            .actor(role, Surface::Dav, None)
            .ok_or(TestAppError::NoCredential(role))
    }

    /// The API token of `role`: the principal token of a principal, the all-scopes tenant token or the system token.
    ///
    /// # Errors
    ///
    /// [`TestAppError::NoCredential`] for the anonymous role.
    pub fn token(&self, role: ActorRole) -> Result<Token, TestAppError> {
        match self.book.actor(role, Surface::Api, None) {
            Some(Actor::Bearer(secret)) => Ok(Token::new(secret)),
            _ => Err(TestAppError::NoCredential(role)),
        }
    }

    /// The tenant token that carries exactly `scope`.
    ///
    /// # Errors
    ///
    /// [`TestAppError::Fixture`] when no tenant token carries that scope (system and `mcp:*` scopes have none).
    pub fn tenant_token(&self, scope: Scope) -> Result<Token, TestAppError> {
        Ok(Token::new(&self.world.tenant_token(scope)?.secret))
    }

    /// Authenticates `actor` through the authentication service on `channel` and returns the request context the
    /// services receive, for tests that call the services directly.
    ///
    /// # Errors
    ///
    /// [`TestAppError::App`] with the kind `Unauthenticated` when the actor is anonymous, the credentials are
    /// wrong, the principal is suspended, or the credentials are not valid on the channel.
    pub async fn authenticate(&self, channel: Channel, actor: &Actor) -> Result<RequestContext, TestAppError> {
        let credential = match actor {
            Actor::Anonymous => return Err(TestAppError::App(AppError::unauthenticated())),
            Actor::Basic { login, password } => PresentedCredential::Basic {
                username: login.clone(),
                password: SecretString::from(password.as_str()),
            },
            Actor::Bearer(secret) => PresentedCredential::Bearer(SecretString::from(secret.as_str())),
        };
        let request = AuthRequest {
            channel,
            tenant_hint: None,
            credential,
            client_ip: None,
            request_id: RequestId::from_uuid(self.ids.new_id()),
        };
        Ok(self.services.auth.authenticate(request).await?)
    }

    /// Authenticates `role` the way its credentials work: principals with an app password over DAV, the others as
    /// bearer tokens on the API.
    ///
    /// # Errors
    ///
    /// [`TestAppError::NoCredential`] for the anonymous role, [`TestAppError::App`] when authentication fails (a
    /// suspended principal, for example).
    pub async fn login(&self, role: ActorRole) -> Result<RequestContext, TestAppError> {
        let on_dav = self.book.actor(role, Surface::Dav, None);
        if let Some(actor @ Actor::Basic { .. }) = on_dav {
            return self.authenticate(Channel::Dav, &actor).await;
        }
        match self.book.actor(role, Surface::Api, None) {
            Some(actor @ Actor::Bearer(_)) => self.authenticate(Channel::Api, &actor).await,
            _ => Err(TestAppError::NoCredential(role)),
        }
    }

    /// Moves time forward (a negative duration moves it back): the manual clock the application is built on.
    pub fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// The side effects observed so far; compare two snapshots to assert that a request changed nothing.
    pub async fn snapshot(&self) -> Snapshot {
        Snapshot::take(&self.mails, &self.events).await
    }

    /// Ticks every worker (the outbox dispatcher, the retention worker, the adapters' workers) until a whole pass finds
    /// nothing to do. It never sleeps: workers expose `tick`, and time moves only through [`TestApp::clock`].
    ///
    /// # Errors
    ///
    /// [`TestAppError::WorkersBusy`] when the workers still have work after [`MAX_WORKER_PASSES`] passes (a worker
    /// that keeps producing work for itself).
    pub async fn run_workers_until_idle(&self) -> Result<WorkSummary, TestAppError> {
        let mut summary = WorkSummary::default();
        for pass in 1..=MAX_WORKER_PASSES {
            let mut busy = false;
            for worker in &self.workers {
                let report = worker.tick().await;
                summary.processed += report.processed;
                summary.failed += report.failed;
                busy |= !report.is_idle();
            }
            summary.passes = pass;
            if !busy {
                return Ok(summary);
            }
        }
        Err(TestAppError::WorkersBusy {
            passes: MAX_WORKER_PASSES,
        })
    }

    /// Runs the shutdown hooks of the application (the workers hand back what they hold, the store closes its pool).
    pub async fn shutdown(&self) {
        for hook in &self.hooks {
            hook.shutdown().await;
        }
    }

    /// An environment for the client-flow runner that sends through `transport` (to a socket of [`TestApp::serve`], for example)
    /// with the credentials and the variables of this application; `base_url` is the one the scenarios see as `{{base_url}}`.
    pub fn scenario_env_over(&self, transport: Arc<dyn Transport>, base_url: &str) -> ScenarioEnv {
        ScenarioEnv::for_world(transport, Arc::clone(&self.book), self.world(), base_url, None)
    }

    /// An environment for the client-flow runner: the in-process transport, the credentials of every role and the
    /// variables `tenant`, `login_domain` and `other_tenant`.
    pub fn scenario_env(&self) -> ScenarioEnv {
        ScenarioEnv::for_world(
            self.transport(),
            Arc::clone(&self.book),
            self.world(),
            PUBLIC_BASE_URL,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_domain::{CalendarKind, ErrorKind, PrincipalName};
    use davhaven_fixtures::names;
    use davhaven_ports::WorkReport;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    async fn app() -> TestApp {
        TestApp::builder().build().await.unwrap()
    }

    #[tokio::test]
    async fn the_standard_world_is_seeded_with_every_kind_of_principal_and_credential() {
        let app = app().await;
        for role in ActorRole::ALL {
            match role {
                ActorRole::Anonymous => {
                    assert!(matches!(app.login(*role).await, Err(TestAppError::NoCredential(_))));
                }
                ActorRole::SuspendedUser => {
                    let error = app.login(*role).await.unwrap_err();
                    assert!(
                        matches!(&error, TestAppError::App(app_error) if app_error.kind() == ErrorKind::Unauthenticated)
                    );
                }
                _ => {
                    let ctx = app.login(*role).await.unwrap();
                    assert_eq!(ctx.principal().is_some(), role.principal_name().is_some(), "{role}");
                }
            }
        }
        let owner = app.login(ActorRole::Owner).await.unwrap();
        assert_eq!(owner.channel, Channel::Dav);
        let admin = app.login(ActorRole::TenantToken).await.unwrap();
        assert_eq!(admin.channel, Channel::Api);
    }

    #[tokio::test]
    async fn calendars_grants_bindings_and_events_follow_the_world() {
        let app = app().await;
        let world = app.world().clone();
        let rita = app.login(ActorRole::ShareeRead).await.unwrap();
        let home = app
            .services()
            .calendars
            .list_home(&rita, &PrincipalName::parse("rita").unwrap())
            .await
            .unwrap();
        let slugs: Vec<String> = home.iter().map(|binding| binding.path.format()).collect();
        assert!(
            slugs.contains(&"/dav/calendars/acme/rita/projects/".to_owned()),
            "{slugs:?}"
        );
        let path = world
            .object_path(ActorRole::ShareeRead, davhaven_fixtures::CalendarRole::Shared)
            .unwrap();
        let object = app.services().objects.get(&rita, &path).await.unwrap();
        assert_eq!(object.uid.as_str(), names::SHARED_EVENT_UID);
        assert!(
            object
                .data
                .as_deref()
                .is_some_and(|data| data.contains("SUMMARY:Shared event")),
            "{:?}",
            object.data
        );

        let owner = app.login(ActorRole::Owner).await.unwrap();
        let bindings = app
            .services()
            .calendars
            .list_home(&owner, &PrincipalName::parse("olivia").unwrap())
            .await
            .unwrap();
        let kinds: Vec<CalendarKind> = bindings.iter().map(|binding| binding.kind).collect();
        assert!(kinds.contains(&CalendarKind::Personal));
        assert!(kinds.contains(&CalendarKind::User));
        assert!(kinds.contains(&CalendarKind::Mirror));
        assert_eq!(bindings.len(), 3, "personal, projects and google: {kinds:?}");
    }

    #[tokio::test]
    async fn the_routers_of_the_server_answer_through_the_in_process_transport() {
        let app = app().await;
        let owner = app.actor(ActorRole::Owner).unwrap();
        let response = app
            .dav(&owner)
            .propfind(
                "/dav/principals/acme/olivia/",
                "0",
                "<propfind xmlns=\"DAV:\"><prop><displayname/></prop></propfind>",
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status.as_u16(), 207, "{}", response.text());
        assert!(response.text().contains("Olivia Owner"), "{}", response.text());
        let health = app.dav(&Actor::Anonymous).get("/healthz").send().await.unwrap();
        assert_eq!(health.status.as_u16(), 200);
        let unauthenticated = app
            .dav(&Actor::Anonymous)
            .propfind("/dav/calendars/acme/olivia/", "0", "")
            .send()
            .await
            .unwrap();
        assert_eq!(unauthenticated.status.as_u16(), 401);
    }

    #[tokio::test]
    async fn an_empty_app_has_no_tenants_and_a_custom_world_is_seeded() {
        let empty = TestApp::builder().empty().build().await.unwrap();
        assert!(matches!(empty.login(ActorRole::Owner).await, Err(TestAppError::App(_))));

        let mut world = FixtureWorld::standard();
        world
            .credentials
            .retain(|credential| credential.label != "system-token");
        let app = TestApp::builder().world(world).build().await.unwrap();
        assert!(app.login(ActorRole::SystemToken).await.is_err());
        assert!(app.login(ActorRole::Owner).await.is_ok());
    }

    #[tokio::test]
    async fn a_world_with_other_names_is_seeded_under_them() {
        let world = FixtureWorld::with_names(davhaven_fixtures::WorldNames::for_run("run7"));
        let app = TestApp::builder().world(world).build().await.unwrap();
        let owner = app.login(ActorRole::Owner).await.unwrap();
        assert_eq!(Some(owner.tenant), app.tenant_id("run7-a"));
        assert!(app.tenant_id("acme").is_none());
        let actor = app.actor(ActorRole::Owner).unwrap();
        assert!(matches!(&actor, Actor::Basic { login, .. } if login == "olivia@run7-a.example"));
        let response = app
            .dav(&actor)
            .propfind("/dav/calendars/run7-a/olivia/personal/", "0", "")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status.as_u16(), 207, "{}", response.text());
    }

    #[tokio::test]
    async fn tenant_settings_apply_to_the_tenant_that_is_named() {
        let settings: TenantSettings = serde_json::from_value(serde_json::json!({"feeds_enabled": false})).unwrap();
        let app = TestApp::builder()
            .tenant_settings("acme", settings)
            .build()
            .await
            .unwrap();
        assert!(app.login(ActorRole::Owner).await.is_ok());
        let stored = app
            .services()
            .tenants
            .get(
                &app.login(ActorRole::TenantToken).await.unwrap(),
                &davhaven_domain::TenantSlug::parse("acme").unwrap(),
            )
            .await
            .unwrap();
        assert!(
            !stored.settings.feeds_enabled,
            "the settings of the builder were applied"
        );
        let error = TestApp::builder()
            .tenant_settings("nowhere", TenantSettings::default())
            .build()
            .await
            .unwrap_err();
        assert!(matches!(error, TestAppError::Seed(_)), "{error}");
    }

    #[test]
    fn a_store_that_is_busy_is_tried_again_and_a_mistake_is_not() {
        // The texts a PostgreSQL server that has no connection left gives, as the assembly and the seeding report them.
        for reason in [
            "plugin `postgres` failed to start: timeout: store operation timed out",
            "plugin `postgres` failed to start: unavailable: the database cannot be reached",
        ] {
            assert!(is_transient(&TestAppError::Assembly(reason.to_owned())), "{reason}");
        }
        for reason in ["create the tenant: Timeout", "create the principal: Unavailable"] {
            assert!(is_transient(&TestAppError::Seed(reason.to_owned())), "{reason}");
        }
        let unreachable = TestAppError::StoreUnavailable {
            store: StoreKind::Postgres,
            reason: "the superuser cannot connect".to_owned(),
        };
        assert!(is_transient(&unreachable));
        // A store that is not there at all, a configuration that is wrong and a world that is wrong stay what they are.
        let memory = TestAppError::StoreUnavailable {
            store: StoreKind::Memory,
            reason: "no such store".to_owned(),
        };
        assert!(!is_transient(&memory));
        assert!(!is_transient(&TestAppError::Config(
            "max_mcp_token_days must be positive".to_owned()
        )));
        for reason in [
            "plugin `postgres` failed to start: invalid configuration: `url` is not a PostgreSQL connection URL",
            "the tenant `acme` was not created",
        ] {
            assert!(!is_transient(&TestAppError::Assembly(reason.to_owned())), "{reason}");
            assert!(!is_transient(&TestAppError::Seed(reason.to_owned())), "{reason}");
        }
    }

    #[tokio::test]
    async fn invalid_configuration_is_reported_and_the_default_store_is_memory() {
        let error = TestApp::builder()
            .configure(|config| config.max_mcp_token_days = 0)
            .build()
            .await
            .unwrap_err();
        assert!(matches!(error, TestAppError::Config(_)), "{error}");
        assert_eq!(TestApp::builder().build().await.unwrap().store(), StoreKind::Memory);
    }

    #[tokio::test]
    async fn a_custom_router_replaces_the_routers_of_the_server() {
        let custom = TestApp::builder()
            .router(|_services| Router::new().route("/ping", axum::routing::get(|| async { "pong" })))
            .build()
            .await
            .unwrap();
        let response = custom.dav(&Actor::Anonymous).get("/ping").send().await.unwrap();
        assert_eq!(response.text(), "pong");
    }

    #[tokio::test]
    async fn the_busy_answers_of_the_application_are_counted() {
        let app = TestApp::builder()
            .router(|_services| {
                Router::new()
                    .route("/fine", axum::routing::get(|| async { "fine" }))
                    .route(
                        "/busy",
                        axum::routing::get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
                    )
            })
            .build()
            .await
            .unwrap();
        assert_eq!(app.busy_answers(), 0);
        for target in ["/fine", "/busy", "/busy"] {
            app.dav(&Actor::Anonymous).get(target).send().await.unwrap();
        }
        assert_eq!(app.busy_answers(), 2, "the answers that said busy, and no others");
    }

    #[tokio::test]
    async fn credentials_and_tokens_resolve_per_role_and_surface() {
        let app = app().await;
        assert!(
            matches!(app.actor(ActorRole::Owner).unwrap(), Actor::Basic { ref login, .. } if login == "olivia@acme.example")
        );
        assert!(matches!(app.actor(ActorRole::TenantToken).unwrap(), Actor::Bearer(_)));
        assert!(
            matches!(app.actor(ActorRole::ServicePrincipal).unwrap(), Actor::Bearer(_)),
            "no app password"
        );
        assert_eq!(app.actor(ActorRole::Anonymous).unwrap(), Actor::Anonymous);
        assert!(app.token(ActorRole::Owner).is_ok() && app.token(ActorRole::SystemToken).is_ok());
        assert!(app.token(ActorRole::Anonymous).is_err());
        assert!(app.tenant_token(Scope::EventsRead).is_ok());
        assert!(app.tenant_token(Scope::McpRead).is_err());
        assert!(matches!(
            app.authenticate(Channel::Dav, &Actor::Anonymous).await,
            Err(TestAppError::App(_))
        ));
        let wrong_surface = app
            .authenticate(Channel::Api, &app.actor(ActorRole::Owner).unwrap())
            .await;
        assert!(wrong_surface.is_err(), "app passwords do not work on the API");
    }

    /// A worker with a fixed amount of work.
    struct Backlog {
        remaining: AtomicU32,
    }

    #[async_trait]
    impl Worker for Backlog {
        fn name(&self) -> &'static str {
            "backlog"
        }

        fn interval(&self) -> std::time::Duration {
            std::time::Duration::from_secs(1)
        }

        async fn tick(&self) -> WorkReport {
            let left = self.remaining.load(Ordering::SeqCst);
            if left == 0 {
                return WorkReport::idle();
            }
            self.remaining.fetch_sub(1, Ordering::SeqCst);
            WorkReport {
                processed: 1,
                failed: 0,
                more: left > 1,
            }
        }
    }

    /// A worker that never runs out of work.
    struct Endless;

    #[async_trait]
    impl Worker for Endless {
        fn name(&self) -> &'static str {
            "endless"
        }

        fn interval(&self) -> std::time::Duration {
            std::time::Duration::from_secs(1)
        }

        async fn tick(&self) -> WorkReport {
            WorkReport {
                processed: 1,
                failed: 0,
                more: true,
            }
        }
    }

    #[tokio::test]
    async fn workers_run_until_a_pass_finds_nothing_and_a_runaway_worker_is_reported() {
        let idle = app().await;
        let summary = idle.run_workers_until_idle().await.unwrap();
        assert_eq!(summary.failed, 0);
        assert!(summary.passes >= 1);
        let app = TestApp::builder()
            .worker(Arc::new(Backlog {
                remaining: AtomicU32::new(3),
            }))
            .build()
            .await
            .unwrap();
        let summary = app.run_workers_until_idle().await.unwrap();
        assert!(summary.processed >= 3, "{summary:?}");
        assert_eq!(
            app.run_workers_until_idle().await.unwrap().processed,
            0,
            "idle stays idle"
        );

        let runaway = TestApp::builder().worker(Arc::new(Endless)).build().await.unwrap();
        assert!(matches!(
            runaway.run_workers_until_idle().await,
            Err(TestAppError::WorkersBusy {
                passes: MAX_WORKER_PASSES
            })
        ));
        assert_eq!(Endless.name(), "endless");
    }

    #[tokio::test]
    async fn time_moves_the_manual_clock_the_application_runs_on() {
        let clock = ManualClock::default();
        let app = TestApp::builder().clock(clock.clone()).build().await.unwrap();
        let before = clock.now();
        app.advance(Duration::hours(2));
        assert_eq!(clock.now(), before + Duration::hours(2));
        assert_eq!(app.deps().clock.now(), before + Duration::hours(2));
        app.advance(Duration::minutes(-30));
        assert_eq!(clock.now(), before + Duration::minutes(90));
        assert_eq!(app.snapshot().await, Snapshot { mails: 0, events: 0 });
    }

    #[tokio::test]
    async fn extra_server_configuration_is_merged_into_the_tables_of_the_harness() {
        // `[mcp]` is a table the harness sets itself: the keys given here join it, and what the harness set stays.
        let app = TestApp::builder()
            .server_config("[mcp]\nmax_range_days = 31\n")
            .build()
            .await
            .unwrap();
        let owner = app.token(ActorRole::Owner).unwrap();
        let listed = app.mcp(&owner).list_tools().unwrap().send().await.unwrap();
        assert_eq!(
            listed.status.as_u16(),
            200,
            "the endpoint is still enabled: {}",
            listed.text()
        );
        // Text that is no TOML is a configuration error, not a panic.
        let error = TestApp::builder()
            .server_config("not = [toml")
            .build()
            .await
            .unwrap_err();
        assert!(matches!(error, TestAppError::Config(_)), "{error}");
    }

    #[tokio::test]
    async fn every_worker_is_ticked_once() {
        let app = app().await;
        let names: Vec<&str> = app.workers.iter().map(|worker| worker.name()).collect();
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "{names:?}");
        assert!(
            names.contains(&"outbox"),
            "the outbox worker of the application is there once: {names:?}"
        );
    }

    #[tokio::test]
    async fn the_captures_are_wired_into_the_application() {
        let app = app().await;
        // Seeding writes through the real services, so domain events were produced; delivering them needs the workers.
        app.run_workers_until_idle().await.unwrap();
        assert!(
            app.events().count().await > 0,
            "the event sink of the harness is part of the deps"
        );
        assert_eq!(app.mails().count().await, 0, "no invitation was sent while seeding");
    }
}
