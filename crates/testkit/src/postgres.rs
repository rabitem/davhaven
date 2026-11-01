//! Databases for the PostgreSQL store of [`TestApp`](crate::app::TestApp).
//!
//! The harness needs a PostgreSQL server on which `DATABASE_URL` is a superuser (CI starts one, the build host has
//! one). The roles of production are reproduced: an *owner* role that owns the schema and runs the migrations, and a
//! *runtime* role that is `NOBYPASSRLS` and owns nothing, so row-level security binds everything the application does
//! (PLAN 2.4). The migrated schema is built once per set of migrations into a template database (under a cluster-wide
//! lock, so parallel test processes of every database agree); every application then clones the template, which takes
//! milliseconds, and the clone is dropped when the application is.
//!
//! A test that needs PostgreSQL and finds no `DATABASE_URL` is an error, never a skip, when `CI` is set (PLAN 3.6,
//! `ENGINEERING_RULES` R9); outside CI the error says what to set. The roles and databases are created on whatever
//! cluster `DATABASE_URL` names, so point it only at a throw-away server: a remote cluster that is not declared
//! throw-away (`DAVHAVEN_TEST_DB_THROWAWAY=1`, `CI`, or a database called `davhaven_*`) is refused.
//!
//! The roles, the provisioning statements and the locks are those of the tests of `davhaven-store-postgres` (a test below
//! compares them with that copy). Roles and the names of databases belong to the cluster, so test runs that use databases of
//! their own on one cluster (the workspaces of a shared build host) change the same two roles, want the same template and
//! could drop each other's databases. An advisory lock belongs to the database it is taken in, so every lock of the
//! provisioning is taken in the maintenance database, where every run meets. Roles that are in order are never written; setting
//! them up takes a lock, and a run that still meets another one that writes them (a copy of this code that does not know the
//! lock) tries again. The names of the databases carry a random text of the run and no process id, which repeats between the
//! containers of a host. The template of this harness and the one of the store tests have different names (the store tests
//! fingerprint the role model as well), so the two suites do not share one.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use davhaven_domain::TenantId;
use davhaven_ports::{Clock, Database, Health, IdGenerator, StoreError, SystemTx, Tx, TxMode};
use davhaven_store_postgres::database::PgDatabase;
use davhaven_store_postgres::migrate;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection};

use crate::app::{StoreKind, TestAppError};

/// The owner role of the test databases.
const OWNER: &str = "davhaven_owner";
/// The runtime role of the test databases.
const APP: &str = "davhaven_app";
/// The advisory lock that serialises the provisioning of templates and databases across the whole cluster (see
/// `Cluster::lock_cluster`).
const LOCK: i64 = 7_424_001;
/// The advisory lock that serialises changes to the test roles across the whole cluster.
const ROLE_LOCK: i64 = 7_424_002;
/// The database that every cluster has and that holds the locks of the provisioning.
const MAINTENANCE_DATABASE: &str = "postgres";
/// How often the setup of the roles is tried when another process changes them at the same time.
const ROLE_ATTEMPTS: u32 = 5;

/// A text that names this process among the processes of every run that shares the cluster. Process ids repeat between the
/// containers of a build host, so a name made of the process id could belong to a database of another run, which the
/// `DROP DATABASE IF EXISTS` before its creation would then end. `RandomState` is seeded by the operating system.
fn run_id() -> &'static str {
    static RUN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    RUN.get_or_init(|| {
        use std::hash::BuildHasher as _;
        format!("{:016x}", std::hash::RandomState::new().hash_one(std::process::id()))
    })
}

/// The query that counts the test roles that are in order: they can log in, hold no privilege a role model withholds and carry
/// the comment that marks them as the tests' own. The tests of `davhaven-store-postgres` have the same query (a test below
/// compares the copy).
const ROLES_READY: &str = "SELECT count(*) FROM pg_roles r WHERE r.rolname IN ('davhaven_owner', 'davhaven_app') \
               AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole \
               AND NOT r.rolreplication AND NOT r.rolbypassrls \
               AND coalesce(shobj_description(r.oid, 'pg_authid'), '') = 'davhaven-test-role' \
               AND (r.rolname <> 'davhaven_app' OR NOT r.rolinherit)";

/// The statements that create the two roles and assert their attributes.
const ROLE_STATEMENTS: [&str; 3] = [
    // A role that was not made by the tests and owns a real database is not ours to reconfigure.
    "DO $$ BEGIN \
       IF EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = 'davhaven_owner' \
                    AND coalesce(shobj_description(r.oid, 'pg_authid'), '') <> 'davhaven-test-role' \
                    AND EXISTS (SELECT 1 FROM pg_database d WHERE d.datdba = r.oid \
                                  AND d.datname !~ '^davhaven_(t|e|tpl)_')) THEN \
         RAISE EXCEPTION 'the role davhaven_owner exists, was not created by the Davhaven tests and \
                          owns a database: refusing to change its password and attributes'; END IF; \
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'davhaven_owner') THEN \
         CREATE ROLE davhaven_owner LOGIN PASSWORD 'davhaven_owner'; END IF; \
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'davhaven_app') THEN \
         CREATE ROLE davhaven_app LOGIN PASSWORD 'davhaven_app'; END IF; \
       COMMENT ON ROLE davhaven_owner IS 'davhaven-test-role'; \
       COMMENT ON ROLE davhaven_app IS 'davhaven-test-role'; \
     END $$",
    "ALTER ROLE davhaven_owner WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
    "ALTER ROLE davhaven_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
];

/// The statements that give a new database the privilege setup of production.
const PROVISIONING: &[&str] = &[
    "REVOKE ALL ON SCHEMA public FROM PUBLIC",
    "ALTER SCHEMA public OWNER TO davhaven_owner",
    "GRANT USAGE ON SCHEMA public TO davhaven_app",
    "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO davhaven_app",
    "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO davhaven_app",
];

/// A statement the harness assembles from names it generates itself (never from outside input).
fn raw(statement: String) -> sqlx::RawSql {
    sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
}

fn unavailable(reason: impl Into<String>) -> TestAppError {
    TestAppError::StoreUnavailable {
        store: StoreKind::Postgres,
        reason: reason.into(),
    }
}

fn database_error(what: &str, error: &sqlx::Error) -> TestAppError {
    unavailable(format!("{what}: {error}"))
}

/// Whether an environment value says "yes": anything but unset, empty, `0` and `false`.
fn truthy(value: Option<&str>) -> bool {
    value.is_some_and(|value| !matches!(value.trim().to_ascii_lowercase().as_str(), "" | "0" | "false"))
}

/// Whether the cluster in `url` may be used: local, or declared throw-away.
fn is_throwaway(url: &str, flag: bool, in_ci: bool) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let host = parsed
        .query_pairs()
        .find(|(key, _)| key == "host")
        .map(|(_, value)| value.into_owned())
        .or_else(|| parsed.host_str().map(str::to_owned))
        .unwrap_or_default();
    let database = parsed.path().trim_start_matches('/');
    davhaven_store_postgres::database::is_local_host(&host) || flag || in_ci || database.starts_with("davhaven_")
}

/// The cluster of the tests.
#[derive(Clone)]
struct Cluster {
    url: String,
    admin: PgConnectOptions,
}

/// Connects, and tries again a few times when the connection is dropped or refused: the server is shared with every other test
/// process that runs at the same time, and one that is busy closes a connection now and then.
///
/// This pauses between the attempts, which R9 ("tests never sleep") allows here: the rule keeps a test from waiting for time
/// that a manual clock could supply, and there is no clock to move for a server that is busy, nothing to await but its
/// recovery. Retries that follow an event the harness can see take no pause (`ensure_roles`: the other run has finished when
/// its error arrives).
async fn connect_again_if_dropped(options: &PgConnectOptions) -> Result<PgConnection, sqlx::Error> {
    let mut attempt = 1_u32;
    loop {
        match PgConnection::connect_with(options).await {
            Ok(connection) => return Ok(connection),
            Err(error) if attempt >= 4 => return Err(error),
            Err(_) => {
                tokio::time::sleep(core::time::Duration::from_millis(250 * u64::from(attempt))).await;
                attempt += 1;
            }
        }
    }
}

impl Cluster {
    /// The cluster named by `DATABASE_URL`.
    fn from_environment() -> Result<Self, TestAppError> {
        let url = std::env::var("DATABASE_URL").unwrap_or_default();
        let in_ci = truthy(std::env::var("CI").ok().as_deref());
        if url.is_empty() {
            return Err(unavailable(if in_ci {
                "DATABASE_URL is not set but CI is: a test that needs PostgreSQL fails instead of skipping"
            } else {
                "DATABASE_URL is not set (outside CI, DAVHAVEN_ALLOW_NO_DB=1 makes the tests that need PostgreSQL skip)"
            }));
        }
        let admin = PgConnectOptions::from_str(&url)
            .map_err(|_| unavailable("DATABASE_URL is not a PostgreSQL connection URL"))?;
        let flag = truthy(std::env::var("DAVHAVEN_TEST_DB_THROWAWAY").ok().as_deref());
        if !is_throwaway(&url, flag, in_ci) {
            return Err(unavailable(
                "DATABASE_URL names a remote server that is not declared throw-away: the harness creates login roles \
                 with weak passwords and databases on it. Point it at a local or disposable server, or set \
                 DAVHAVEN_TEST_DB_THROWAWAY=1",
            ));
        }
        Ok(Self { url, admin })
    }

    fn owner_options(&self, database: &str) -> PgConnectOptions {
        self.admin.clone().username(OWNER).password(OWNER).database(database)
    }

    /// The connection URL of the runtime role on `database`.
    fn runtime_url(&self, database: &str) -> Result<String, TestAppError> {
        let mut url = url::Url::parse(&self.url).map_err(|_| unavailable("DATABASE_URL is not a URL"))?;
        url.set_username(APP)
            .map_err(|()| unavailable("DATABASE_URL has no host"))?;
        url.set_password(Some(APP))
            .map_err(|()| unavailable("DATABASE_URL has no host"))?;
        url.set_path(&format!("/{database}"));
        Ok(url.to_string())
    }

    async fn admin(&self) -> Result<PgConnection, TestAppError> {
        connect_again_if_dropped(&self.admin)
            .await
            .map_err(|error| database_error("the superuser cannot connect", &error))
    }

    async fn admin_to(&self, database: &str) -> Result<PgConnection, TestAppError> {
        connect_again_if_dropped(&self.admin.clone().database(database))
            .await
            .map_err(|error| database_error("the superuser cannot connect to the database", &error))
    }

    /// Whether both roles exist with the attributes they are given (and the comment that marks them as the tests' own).
    async fn roles_are_ready(connection: &mut PgConnection) -> Result<bool, TestAppError> {
        let ready = sqlx::query_scalar::<_, i64>(ROLES_READY)
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| database_error("the roles are not readable", &error))?;
        Ok(ready == 2)
    }

    /// Creates the two roles and asserts their attributes (idempotent).
    async fn apply_roles(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
        for statement in ROLE_STATEMENTS {
            sqlx::raw_sql(statement).execute(&mut *connection).await?;
        }
        Ok(())
    }

    /// Whether `error` is one of the ways in which two processes that change the same role at the same time can fail:
    /// both update the same catalog row (`tuple concurrently updated`), or both find the role missing and both create it.
    fn is_role_race(error: &sqlx::Error) -> bool {
        matches!(error, sqlx::Error::Database(failure)
            if failure.message().contains("tuple concurrently updated")
                || matches!(failure.code().as_deref(), Some("23505" | "42710")))
    }

    /// Takes the advisory lock `key` for the whole cluster and returns the connection that holds it (closing the connection
    /// releases it).
    ///
    /// An advisory lock belongs to the **database** it is taken in, while roles and the names of databases belong to the
    /// **cluster**. Test runs that use databases of their own (the workspaces of a shared build host) would not meet at a lock
    /// taken in their own database, and would change the same two roles and drop each other's staging databases. Every lock of
    /// the provisioning is therefore taken in the maintenance database that every cluster has, where they meet. A cluster
    /// without it (SQLSTATE `3D000`) holds the lock in the database of `DATABASE_URL`, which is enough for the runs of that
    /// one database; any other failure to connect is a failure of the test environment.
    async fn lock_cluster(&self, key: i64) -> Result<PgConnection, TestAppError> {
        let maintenance = connect_again_if_dropped(&self.admin.clone().database(MAINTENANCE_DATABASE)).await;
        let mut connection = match maintenance {
            Err(sqlx::Error::Database(ref failure)) if failure.code().as_deref() == Some("3D000") => {
                self.admin().await?
            }
            other => other.map_err(|error| {
                database_error(
                    "the maintenance database, which holds the locks of the provisioning, cannot be reached",
                    &error,
                )
            })?,
        };
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&mut connection)
            .await
            .map_err(|error| database_error("the provisioning lock", &error))?;
        Ok(connection)
    }

    /// Creates the two roles and asserts their attributes, once for the cluster.
    ///
    /// Roles that are in order are left alone: every update of a role is an update of a catalog row, and processes that
    /// update the same row at the same time fail with `tuple concurrently updated`. Setting them up is serialised across the
    /// cluster ([`lock_cluster`](Self::lock_cluster)) and, because a process that does not know this lock may still be writing
    /// them, tried again when it meets such a failure. The run that wrote at the same time has finished when its error
    /// arrives, so trying again needs no pause. `davhaven-store-postgres` has the same rule in its own tests.
    async fn ensure_roles(&self, connection: &mut PgConnection) -> Result<(), TestAppError> {
        if Self::roles_are_ready(connection).await? {
            return Ok(());
        }
        let lock = self.lock_cluster(ROLE_LOCK).await?;
        let mut attempt = 1_u32;
        // The roles may have been made while this run waited for the lock.
        let outcome = loop {
            if Self::roles_are_ready(connection).await? {
                break Ok(());
            }
            match Self::apply_roles(connection).await {
                Err(error) if attempt < ROLE_ATTEMPTS && Self::is_role_race(&error) => attempt += 1,
                outcome => break outcome,
            }
        };
        // Closing the session releases its advisory lock.
        drop(lock.close().await);
        outcome.map_err(|error| database_error("a role statement failed", &error))
    }

    /// The name of the template database for the embedded migrations, created and migrated when missing.
    async fn template(&self) -> Result<String, TestAppError> {
        // The template depends on the migrations and on the provisioning statements it was prepared with.
        let mut fingerprint: u64 = 0xcbf2_9ce4_8422_2325;
        for migration in migrate::migrator().iter() {
            for byte in migration.version.to_be_bytes().iter().chain(migration.checksum.iter()) {
                fingerprint = (fingerprint ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
            }
        }
        for byte in PROVISIONING.iter().flat_map(|statement| statement.bytes()) {
            fingerprint = (fingerprint ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
        let name = format!("davhaven_tpl_{fingerprint:016x}");
        // One run at a time builds a template for the whole cluster: the name of the staging database is the same for every
        // run that wants this template, and the `DROP DATABASE .. WITH (FORCE)` of a stale one ends the migration of a run
        // that is not stale. Closing the connection of the lock releases it, also when the build failed.
        let lock = self.lock_cluster(LOCK).await?;
        let mut admin = self.admin().await?;
        let built = self.build_template(&mut admin, &name).await;
        drop(lock.close().await);
        built?;
        Ok(name)
    }

    async fn build_template(&self, admin: &mut PgConnection, name: &str) -> Result<(), TestAppError> {
        self.ensure_roles(admin).await?;
        let exists = sqlx::query_scalar::<_, i32>("SELECT 1 FROM pg_database WHERE datname = $1")
            .bind(name)
            .fetch_optional(&mut *admin)
            .await
            .map_err(|error| database_error("the catalog is not readable", &error))?
            .is_some();
        if exists {
            return Ok(());
        }
        let staging = format!("{name}_building");
        let step = |what: &'static str| move |error: sqlx::Error| database_error(what, &error);
        raw(format!("DROP DATABASE IF EXISTS {staging} WITH (FORCE)"))
            .execute(&mut *admin)
            .await
            .map_err(step("a stale staging database cannot be dropped"))?;
        raw(format!("CREATE DATABASE {staging} OWNER {OWNER}"))
            .execute(&mut *admin)
            .await
            .map_err(step("the staging database cannot be created"))?;
        let mut prepare = self.admin_to(&staging).await?;
        for statement in PROVISIONING {
            sqlx::raw_sql(*statement)
                .execute(&mut prepare)
                .await
                .map_err(step("a privilege statement failed"))?;
        }
        drop(prepare.close().await);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(self.owner_options(&staging))
            .await
            .map_err(step("the owner role cannot connect"))?;
        let migrated = migrate::run_on(&pool).await;
        pool.close().await;
        migrated.map_err(|error| unavailable(format!("the migrations failed: {error}")))?;
        raw(format!("ALTER DATABASE {staging} RENAME TO {name}"))
            .execute(&mut *admin)
            .await
            .map_err(step("the template cannot be published"))?;
        Ok(())
    }

    /// Clones the template into a new database and returns its name.
    async fn clone_database(&self) -> Result<String, TestAppError> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let template = self.template().await?;
        let name = format!("davhaven_t_h{}_{}", run_id(), COUNTER.fetch_add(1, Ordering::SeqCst));
        let lock = self.lock_cluster(LOCK).await?;
        let mut admin = self.admin().await?;
        let created = async {
            raw(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                .execute(&mut admin)
                .await?;
            raw(format!("CREATE DATABASE {name} TEMPLATE {template} OWNER {OWNER}"))
                .execute(&mut admin)
                .await
        }
        .await;
        drop(lock.close().await);
        created.map_err(|error| database_error("the template cannot be cloned", &error))?;
        Ok(name)
    }
}

/// A database cloned from the migrated template; dropped with the value.
#[derive(Debug)]
pub struct ClonedDatabase {
    cluster_url: String,
    name: String,
    runtime_url: String,
}

impl ClonedDatabase {
    /// Clones the template (creating it first when the migrations are new to the cluster).
    ///
    /// # Errors
    ///
    /// [`TestAppError::StoreUnavailable`] when `DATABASE_URL` is missing, names a server the harness may not use or
    /// the database cannot be prepared.
    pub async fn create() -> Result<Self, TestAppError> {
        let cluster = Cluster::from_environment()?;
        let name = cluster.clone_database().await?;
        let runtime_url = cluster.runtime_url(&name)?;
        Ok(Self {
            cluster_url: cluster.url,
            name,
            runtime_url,
        })
    }

    /// As [`create`](Self::create) for code that is not async: the world of a test that builds its services in a
    /// synchronous constructor. The database is made on a thread of its own with a runtime of its own, and the call
    /// returns when it exists; the calling thread is blocked meanwhile, which is harmless because nothing it runs
    /// needs the database yet.
    ///
    /// # Errors
    ///
    /// As [`create`](Self::create).
    pub fn create_blocking() -> Result<Self, TestAppError> {
        let made = std::thread::spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| unavailable(format!("the runtime for the database cannot be built: {error}")))?
                .block_on(Self::create())
        })
        .join();
        made.unwrap_or_else(|_| Err(unavailable("the thread that makes the database panicked")))
    }

    /// The connection URL of the runtime role (`NOBYPASSRLS`) on the cloned database.
    pub fn runtime_url(&self) -> &str {
        &self.runtime_url
    }

    /// The store of this database as the application uses it: the PostgreSQL adapter on the runtime role, stamping
    /// with `clock` and numbering with `ids`, so that a test that drives the clock and the ids sees what it sees on the
    /// in-memory store. The returned database **owns the clone**: it is dropped when the last handle goes.
    ///
    /// The pool connects lazily, so this works in a synchronous constructor as long as a Tokio runtime is entered.
    /// Statement and lock waits are bounded (two minutes and half a minute), so a deadlock fails a test instead of
    /// hanging it.
    ///
    /// # Errors
    ///
    /// [`TestAppError::StoreUnavailable`] when the connection URL cannot be used.
    pub fn into_database(
        self,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Result<Arc<dyn Database>, TestAppError> {
        let options = PgConnectOptions::from_str(&self.runtime_url)
            .map_err(|_| unavailable("the runtime URL of the clone is not a PostgreSQL URL"))?
            .application_name("davhaven-test")
            .options([("statement_timeout", "120000"), ("lock_timeout", "30000")]);
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(60))
            .connect_lazy_with(options);
        Ok(Arc::new(OwnedDatabase {
            inner: PgDatabase::from_pool(pool, clock, ids),
            _clone: self,
        }))
    }

    /// The name of the cloned database.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for ClonedDatabase {
    /// Drops the database, terminating the connections that are still open. The drop runs on a thread of its own with
    /// a runtime of its own, so it works whatever runtime (if any) the value is dropped on, and it is waited for before the
    /// runtime that the value was dropped on ends: a test binary that ends right after its last test would otherwise exit before a
    /// detached thread ran, and the last clones of every binary would stay on the cluster. A failure leaves the database
    /// behind, which only wastes disk of a throw-away server.
    ///
    /// The drop takes a few hundred milliseconds on an idle cluster and up to a minute on one that is busy (`DROP DATABASE`
    /// waits for the backends of the cluster), and the code that drops a world is usually the code that runs the other worlds of
    /// the matrix too: the cases of a matrix are futures of one task, so a drop that kept the thread would keep every one of them
    /// from running for that long. Transactions of the others would sit idle past the `idle_in_transaction_timeout` of the store,
    /// their pools would run out of their `acquire_timeout`, and the application would answer 503. `release` does not wait for
    /// the drop in async code.
    fn drop(&mut self) {
        let url = self.cluster_url.clone();
        let name = self.name.clone();
        release(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                return;
            };
            runtime.block_on(async move {
                let Ok(options) = PgConnectOptions::from_str(&url) else {
                    return;
                };
                if let Ok(mut admin) = PgConnection::connect_with(&options).await {
                    drop(
                        raw(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                            .execute(&mut admin)
                            .await,
                    );
                }
            });
        });
    }
}

/// Runs a clean-up without keeping the caller from running its other futures. In async code it goes to the blocking pool of the
/// runtime, which the runtime waits for when it ends (a test that is over has cleaned up); without a runtime it runs at once and
/// is waited for.
fn release(cleanup: impl FnOnce() + Send + 'static) {
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => drop(runtime.spawn_blocking(move || on_a_thread(cleanup))),
        Err(_) => on_a_thread(cleanup),
    }
}

/// Runs a clean-up on a thread of its own and waits for it: it builds a runtime of its own, which a thread that is in a runtime
/// (a blocking thread of one is) is not to start. A clean-up that panicked has nothing left to report: the database stays, like
/// after any other failure.
fn on_a_thread(cleanup: impl FnOnce() + Send + 'static) {
    drop(std::thread::spawn(cleanup).join());
}

/// The PostgreSQL adapter together with the database it runs on, so that the database lives as long as the store.
struct OwnedDatabase {
    inner: PgDatabase,
    _clone: ClonedDatabase,
}

#[async_trait]
impl Database for OwnedDatabase {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        self.inner.begin(tenant, mode).await
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        self.inner.begin_system().await
    }

    async fn health(&self) -> Health {
        Database::health(&self.inner).await
    }
}

/// Whether a test that needs PostgreSQL should run: `true` when `DATABASE_URL` is set.
///
/// Without it the test fails (`ENGINEERING_RULES` R9: a run without a database must not look green), except outside CI
/// when `DAVHAVEN_ALLOW_NO_DB` says that skipping is intended; the test then says so on the error stream and the
/// function returns `false`.
///
/// # Panics
///
/// Without `DATABASE_URL`, unless the skip is explicitly allowed and the run is not CI.
pub fn require_database() -> bool {
    use std::io::Write as _;

    if std::env::var("DATABASE_URL").is_ok_and(|url| !url.is_empty()) {
        return true;
    }
    let in_ci = truthy(std::env::var("CI").ok().as_deref());
    let allowed = truthy(std::env::var("DAVHAVEN_ALLOW_NO_DB").ok().as_deref());
    assert!(
        allowed && !in_ci,
        "DATABASE_URL is not set: the tests that need PostgreSQL cannot run. Set it, or (outside CI) set \
         DAVHAVEN_ALLOW_NO_DB=1 to skip them explicitly"
    );
    drop(writeln!(
        std::io::stderr(),
        "SKIPPED (DAVHAVEN_ALLOW_NO_DB): DATABASE_URL is not set, nothing was tested against PostgreSQL"
    ));
    false
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use super::{
        LOCK, MAINTENANCE_DATABASE, PROVISIONING, ROLE_ATTEMPTS, ROLE_LOCK, ROLE_STATEMENTS, ROLES_READY, release,
        run_id,
    };

    /// A clean-up that is started from async code must not keep the thread that polls the futures of the other worlds: the cases of
    /// a matrix are futures of one task. The test has one thread, which sends the signal that the clean-up waits for after
    /// `release` returned: a `release` that waited for the clean-up would have kept the thread for the five seconds that the
    /// clean-up waits at most, and the clean-up would say that nobody came.
    #[tokio::test]
    async fn a_cleanup_started_from_async_code_does_not_keep_the_thread_that_polls() {
        let (signal, signalled) = mpsc::channel::<()>();
        let (outcome, outcomes) = mpsc::channel::<bool>();
        release(move || {
            // `recv_timeout` is the bound of the failure, not a pause: it returns when the signal comes.
            outcome
                .send(signalled.recv_timeout(Duration::from_secs(5)).is_ok())
                .unwrap();
        });
        signal.send(()).unwrap();
        assert!(
            outcomes.recv_timeout(Duration::from_secs(30)).unwrap(),
            "the thread was free to send the signal while the clean-up ran"
        );
    }

    #[test]
    fn a_cleanup_without_a_runtime_has_run_when_release_returns() {
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        release(move || flag.store(true, Ordering::SeqCst));
        assert!(done.load(Ordering::SeqCst));
    }

    #[test]
    fn a_cleanup_that_panics_is_left_behind_quietly() {
        release(|| panic!("the cluster is gone"));
    }

    /// The source of the copy of this setup in the tests of `davhaven-store-postgres`.
    const STORE_COPY: &str = include_str!("../../store-postgres/tests/support/mod.rs");

    /// A text without the white space and the line continuations that separate the pieces of a long string literal, so that a
    /// statement can be looked for in the source that spells it across lines.
    fn compact(text: &str) -> String {
        text.chars()
            .filter(|character| !character.is_whitespace() && *character != '\\')
            .collect()
    }

    /// `7424001` as `7_424_001`, the way the constants are written.
    fn grouped(number: i64) -> String {
        let digits = number.to_string();
        let mut grouped = String::new();
        for (index, digit) in digits.chars().enumerate() {
            if index > 0 && (digits.len() - index).is_multiple_of(3) {
                grouped.push('_');
            }
            grouped.push(digit);
        }
        grouped
    }

    #[test]
    fn the_setup_of_the_roles_is_the_one_of_the_store_tests() {
        // Two copies of one rule: the harness cannot use the support code of another crate's tests, and a copy that
        // drifted would write the roles another way, or take another lock, than the tests that run beside it.
        let store = compact(STORE_COPY);
        let mut statements = vec![ROLES_READY];
        statements.extend(ROLE_STATEMENTS);
        statements.extend(PROVISIONING);
        for statement in statements {
            assert!(
                store.contains(&compact(statement)),
                "the store tests do not have the statement:\n{statement}"
            );
        }
        for (name, key) in [("LOCK", LOCK), ("ROLE_LOCK", ROLE_LOCK)] {
            assert!(
                store.contains(&compact(&format!("const {name}: i64 = {};", grouped(key)))),
                "the store tests do not hold {name} = {key}"
            );
        }
        assert!(
            store.contains(&compact(&format!(
                "const MAINTENANCE_DATABASE: &str = \"{MAINTENANCE_DATABASE}\";"
            ))),
            "the store tests lock in another database"
        );
        assert!(
            store.contains(&compact(&format!("const ROLE_ATTEMPTS: u32 = {ROLE_ATTEMPTS};"))),
            "the store tests try the roles another number of times"
        );
    }

    #[test]
    fn the_names_of_the_databases_carry_the_random_text_of_the_run() {
        assert_eq!(run_id().len(), 16);
        assert!(run_id().chars().all(|character| character.is_ascii_hexdigit()));
        assert_eq!(run_id(), run_id(), "one text for the whole process");
    }
}
