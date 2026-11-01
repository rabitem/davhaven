//! Provisioning of PostgreSQL databases for the integration tests.
//!
//! The tests need a PostgreSQL server on which `DATABASE_URL` is a superuser (CI starts one; the build host has
//! one). A test that finds no `DATABASE_URL` fails, in CI (`CI` set to anything but empty, `0` or `false`) as
//! everywhere else (`ENGINEERING_RULES` R9): a run without a database must not look green. Setting
//! `DAVHAVEN_ALLOW_NO_DB=1` outside CI skips the tests explicitly and says so.
//!
//! The support code reproduces the role model of production (docs/operations/database.md): an *owner* role that
//! owns the schema and runs migrations, and a *runtime* role that is `NOBYPASSRLS`, owns nothing and gets its
//! privileges through default privileges. Tests always connect as the runtime role, so row-level security applies
//! to everything they do. The provisioning statements are [`PROVISIONING`], which a test compares with the
//! statements printed in the documentation.
//!
//! The test roles are created on whatever cluster `DATABASE_URL` names, with their name as the password and
//! `LOGIN`; point `DATABASE_URL` only at a throw-away server. Two guards keep a stray `DATABASE_URL` in a
//! developer's shell from doing damage. The cluster must be local (loopback or a socket), or the run must say it is a
//! throw-away one: `DAVHAVEN_TEST_DB_THROWAWAY=1`, `CI`, or a database named `davhaven_*` (the name the shared
//! build hosts give to the one database of a workspace). And an existing role with the name of a test role is only
//! taken over when the tests made it (it carries the comment `davhaven-test-role`) or when it owns nothing but
//! test databases; a real `davhaven_owner` that owns a real database makes the tests refuse to run.
//!
//! Roles and the names of databases belong to the cluster, so test runs that use databases of their own on one cluster
//! (the workspaces of a shared build host) change the same two roles, want the same template and could drop each other's
//! databases. An advisory lock belongs to the database it is taken in, so every lock of the provisioning is taken in the
//! maintenance database, where every run meets. Roles that are in order are never written; setting them up takes a lock, and
//! a run that still meets another one that writes them (a copy of this code that does not know the lock) tries again. The
//! names of the databases a run makes carry a random text and no process id, which repeats between the containers of a host.
//! Both copies of this setup (here and in `davhaven-testkit`) follow the same rules, and a test there compares the copy.
//!
//! The migrated schema is built once per migration set into a template database (under the cluster-wide lock, so parallel
//! test processes of every database agree); every test then clones the template, which takes milliseconds, and the clone
//! is dropped when the test ends.

#![allow(dead_code, reason = "every test binary uses a different part of the support code")]
#![expect(
    clippy::expect_used,
    reason = "a test environment that cannot be provisioned fails the test loudly"
)]

use std::io::Write as _;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use davhaven_domain::TenantId;
use davhaven_ports::testing::{ManualClock, SeqIds};
use davhaven_ports::{Database, Health, StoreError, SystemTx, Tx, TxMode};
use davhaven_store_postgres::database::PgDatabase;
use davhaven_store_postgres::migrate;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool};

/// The owner role of the test databases.
pub(crate) const OWNER: &str = "davhaven_owner";
/// The runtime role of the test databases.
pub(crate) const APP: &str = "davhaven_app";
/// The advisory lock that serialises the provisioning of templates and databases across the whole cluster (see
/// `Cluster::lock_cluster`).
pub(crate) const LOCK: i64 = 7_424_001;
/// The advisory lock that serialises changes to the test roles across the whole cluster.
pub(crate) const ROLE_LOCK: i64 = 7_424_002;
/// The database that every cluster has and that holds the locks of the provisioning.
const MAINTENANCE_DATABASE: &str = "postgres";
/// How often the setup of the roles is tried when another process changes them at the same time.
const ROLE_ATTEMPTS: u32 = 5;

/// A text that names this process among the processes of every run that shares the cluster. Process ids repeat between the
/// containers of a build host, so a name made of the process id could belong to a database of another run, which the
/// `DROP DATABASE IF EXISTS` before its creation would then end. `RandomState` is seeded by the operating system.
pub(crate) fn run_id() -> &'static str {
    static RUN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    RUN.get_or_init(|| {
        use std::hash::BuildHasher as _;
        format!("{:016x}", std::hash::RandomState::new().hash_one(std::process::id()))
    })
}

/// The query that counts the test roles that are in order: they can log in, hold no privilege a role model withholds and carry
/// the comment that marks them as the tests' own.
pub(crate) const ROLES_READY: &str = "SELECT count(*) FROM pg_roles r WHERE r.rolname IN ('davhaven_owner', 'davhaven_app') \
               AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole \
               AND NOT r.rolreplication AND NOT r.rolbypassrls \
               AND coalesce(shobj_description(r.oid, 'pg_authid'), '') = 'davhaven-test-role' \
               AND (r.rolname <> 'davhaven_app' OR NOT r.rolinherit)";

/// The statements that create the two roles and assert their attributes. `davhaven-testkit` has the same three (a test there
/// compares its copy with this file).
pub(crate) const ROLE_STATEMENTS: [&str; 3] = [
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

/// A statement the tests assemble from names they generate themselves (never from outside input).
fn raw(statement: String) -> sqlx::RawSql {
    sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
}

/// The connection to the server of the tests.
#[derive(Clone)]
pub(crate) struct Cluster {
    url: String,
    admin: PgConnectOptions,
}

/// Whether an environment value says "yes": anything but unset, empty, `0` and `false`.
fn truthy(value: Option<&str>) -> bool {
    value.is_some_and(|value| !matches!(value.trim().to_ascii_lowercase().as_str(), "" | "0" | "false"))
}

/// The cluster of the tests, or `None` when the tests were told explicitly to skip.
///
/// # Panics
///
/// Without `DATABASE_URL`, unless `DAVHAVEN_ALLOW_NO_DB` is set and the run is not CI: a test that needs
/// PostgreSQL fails rather than report green having tested nothing.
pub(crate) fn cluster() -> Option<Cluster> {
    if let Ok(url) = std::env::var("DATABASE_URL")
        && !url.is_empty()
    {
        let admin = PgConnectOptions::from_str(&url).expect("DATABASE_URL is not a PostgreSQL URL");
        refuse_shared_servers(&url);
        return Some(Cluster { url, admin });
    }
    let in_ci = truthy(std::env::var("CI").ok().as_deref());
    let allowed = truthy(std::env::var("DAVHAVEN_ALLOW_NO_DB").ok().as_deref());
    assert!(
        allowed && !in_ci,
        "DATABASE_URL is not set: the PostgreSQL tests cannot run. Set it, or (outside CI) set \
         DAVHAVEN_ALLOW_NO_DB=1 to skip them explicitly"
    );
    let _ = writeln!(
        std::io::stderr(),
        "SKIPPED (DAVHAVEN_ALLOW_NO_DB): DATABASE_URL is not set, nothing was tested against PostgreSQL"
    );
    None
}

/// Whether the cluster in `url` may be used for the tests: local, or declared throw-away. See the module
/// documentation.
fn is_throwaway(url: &str, throwaway_flag: bool, in_ci: bool) -> bool {
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
    davhaven_store_postgres::database::is_local_host(&host)
        || throwaway_flag
        || in_ci
        || database.starts_with("davhaven_")
}

/// Panics when `DATABASE_URL` points at a server the tests must not create roles and databases on.
///
/// # Panics
///
/// For a remote server that is not declared throw-away.
fn refuse_shared_servers(url: &str) {
    let flag = truthy(std::env::var("DAVHAVEN_TEST_DB_THROWAWAY").ok().as_deref());
    let in_ci = truthy(std::env::var("CI").ok().as_deref());
    assert!(
        is_throwaway(url, flag, in_ci),
        "DATABASE_URL names a remote server that is not declared throw-away: the store tests create login roles \
         with weak passwords and databases on it. Point it at a local or disposable server, or set \
         DAVHAVEN_TEST_DB_THROWAWAY=1 to say that this one is disposable"
    );
}

/// The statements that give a new database the privilege setup of production, as docs/operations/database.md
/// prints them (the roles and the database are created by the support code itself).
pub(crate) const PROVISIONING: &[&str] = &[
    "REVOKE ALL ON SCHEMA public FROM PUBLIC",
    "ALTER SCHEMA public OWNER TO davhaven_owner",
    "GRANT USAGE ON SCHEMA public TO davhaven_app",
    "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO davhaven_app",
    "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO davhaven_app",
];

/// The same privileges through the default privileges of the owner in every schema (no `IN SCHEMA`), the other
/// spelling an operator may use; the migration's role block finds both.
pub(crate) const PROVISIONING_GLOBAL: &[&str] = &[
    "REVOKE ALL ON SCHEMA public FROM PUBLIC",
    "ALTER SCHEMA public OWNER TO davhaven_owner",
    "GRANT USAGE ON SCHEMA public TO davhaven_app",
    "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO davhaven_app",
    "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner GRANT USAGE, SELECT ON SEQUENCES TO davhaven_app",
];

/// The grant that lets the runtime role purge the audit log. It is **not** a setup (the role model withholds it and the
/// posture check reports it as a security finding): the contract suite exercises the retention methods of the store through
/// the server's own role, so its databases have it, and the tests of the finding grant it to see the finding.
pub(crate) const GRANT_AUDIT_PURGE: &str =
    "GRANT EXECUTE ON FUNCTION davhaven_purge_audit(timestamptz, integer) TO davhaven_app";

/// What a dedicated role needs to run the audit purge instead of the owner (docs/operations/database.md, "Audit log
/// retention"): the schema to find the function in, and the function.
pub(crate) const RETENTION_ROLE_GRANTS: &[&str] = &[
    "GRANT USAGE ON SCHEMA public TO davhaven_retention",
    "GRANT EXECUTE ON FUNCTION davhaven_purge_audit(timestamptz, integer) TO davhaven_retention",
];

impl Cluster {
    /// Options that connect as the owner role to `database`.
    pub(crate) fn owner_options(&self, database: &str) -> PgConnectOptions {
        self.admin.clone().username(OWNER).password(OWNER).database(database)
    }

    /// Options that connect as the runtime role to `database`.
    pub(crate) fn app_options(&self, database: &str) -> PgConnectOptions {
        self.admin.clone().username(APP).password(APP).database(database)
    }

    /// A connection URL for `role` and `database`, derived from `DATABASE_URL`.
    pub(crate) fn url_for(&self, role: &str, database: &str) -> String {
        let mut url = url::Url::parse(&self.url).expect("DATABASE_URL is a URL");
        url.set_username(role).expect("the URL has a host");
        url.set_password(Some(role)).expect("the URL has a host");
        url.set_path(&format!("/{database}"));
        url.to_string()
    }

    /// A superuser connection to the maintenance database of the URL.
    pub(crate) async fn admin(&self) -> PgConnection {
        PgConnection::connect_with(&self.admin)
            .await
            .expect("the superuser connects")
    }

    /// A pool of the superuser on `database`.
    pub(crate) async fn admin_pool(&self, database: &str) -> PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            .connect_with(self.admin.clone().database(database))
            .await
            .expect("the superuser connects to the database")
    }

    /// A superuser connection to `database`.
    pub(crate) async fn admin_to(&self, database: &str) -> PgConnection {
        PgConnection::connect_with(&self.admin.clone().database(database))
            .await
            .expect("the superuser connects to the database")
    }

    /// Whether both roles exist with the attributes the tests give them and the comment that marks them as the tests'
    /// own. Reading the catalog is all it does.
    pub(crate) async fn roles_are_ready(connection: &mut PgConnection) -> bool {
        let ready = sqlx::query_scalar::<_, i64>(ROLES_READY)
            .fetch_one(&mut *connection)
            .await
            .expect("the roles are readable");
        ready == 2
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
    pub(crate) fn is_role_race(error: &sqlx::Error) -> bool {
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
    pub(crate) async fn lock_cluster(&self, key: i64) -> PgConnection {
        let maintenance = PgConnection::connect_with(&self.admin.clone().database(MAINTENANCE_DATABASE)).await;
        let mut connection = match maintenance {
            Err(sqlx::Error::Database(ref failure)) if failure.code().as_deref() == Some("3D000") => self.admin().await,
            other => other.expect("the maintenance database connects: it holds the locks of the provisioning"),
        };
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&mut connection)
            .await
            .expect("the provisioning lock");
        connection
    }

    /// Creates the two roles and asserts their attributes, once for the cluster.
    ///
    /// Roles that are in order are left alone: every update of a role is an update of a catalog row, and processes that
    /// update the same row at the same time fail with `tuple concurrently updated`. Setting them up is serialised across the
    /// cluster ([`lock_cluster`](Self::lock_cluster)) and, because a process that does not know this lock may still be writing
    /// them, tried again when it meets such a failure. The run that wrote at the same time has finished when its error
    /// arrives, so trying again needs no pause.
    pub(crate) async fn ensure_roles(&self, connection: &mut PgConnection) {
        if Self::roles_are_ready(connection).await {
            return;
        }
        let lock = self.lock_cluster(ROLE_LOCK).await;
        let mut attempt = 1_u32;
        // The roles may have been made while this run waited for the lock.
        while !Self::roles_are_ready(connection).await {
            match Self::apply_roles(connection).await {
                Err(error) if attempt < ROLE_ATTEMPTS && Self::is_role_race(&error) => attempt += 1,
                outcome => {
                    outcome.expect("a role statement runs");
                    break;
                }
            }
        }
        // Closing the session releases its advisory lock.
        let _ = lock.close().await;
    }

    /// Gives a new database the privilege setup of production: the owner owns the schema, the runtime role gets
    /// data access through the owner's default privileges.
    async fn prepare(&self, database: &str, statements: &[&'static str]) {
        let mut connection = self.admin_to(database).await;
        for statement in statements.iter().copied() {
            sqlx::raw_sql(statement)
                .execute(&mut connection)
                .await
                .expect("a privilege statement runs");
        }
    }

    /// The name of the template database for the embedded migrations, created and migrated when missing.
    pub(crate) async fn template(&self) -> String {
        // The template depends on the migrations and on the provisioning statements it was prepared with.
        let mut fingerprint: u64 = 0xcbf2_9ce4_8422_2325;
        for migration in migrate::migrator().iter() {
            for byte in migration.version.to_be_bytes().iter().chain(migration.checksum.iter()) {
                fingerprint = (fingerprint ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
            }
        }
        // The role model runs after the migrations (`migrate::run_on`), so the template depends on its text as well.
        let role_model = include_str!("../../src/role_model.sql");
        for byte in role_model
            .bytes()
            .chain(PROVISIONING.iter().flat_map(|statement| statement.bytes()))
        {
            fingerprint = (fingerprint ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
        let name = format!("davhaven_tpl_{fingerprint:016x}");
        // One run at a time builds a template for the whole cluster: the name of the staging database is the same for every
        // run that wants this template, and the `DROP DATABASE .. WITH (FORCE)` of a stale one ends the migration of a run
        // that is not stale.
        let lock = self.lock_cluster(LOCK).await;
        let mut admin = self.admin().await;
        self.ensure_roles(&mut admin).await;
        let exists = sqlx::query_scalar::<_, i32>("SELECT 1 FROM pg_database WHERE datname = $1")
            .bind(&name)
            .fetch_optional(&mut admin)
            .await
            .expect("the catalog is readable")
            .is_some();
        if !exists {
            let staging = format!("{name}_building");
            raw(format!("DROP DATABASE IF EXISTS {staging} WITH (FORCE)"))
                .execute(&mut admin)
                .await
                .expect("a stale staging database is dropped");
            raw(format!("CREATE DATABASE {staging} OWNER {OWNER}"))
                .execute(&mut admin)
                .await
                .expect("the staging database is created");
            self.prepare(&staging, PROVISIONING).await;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect_with(self.owner_options(&staging))
                .await
                .expect("the owner connects");
            migrate::run_on(&pool).await.expect("the migrations apply");
            pool.close().await;
            raw(format!("ALTER DATABASE {staging} RENAME TO {name}"))
                .execute(&mut admin)
                .await
                .expect("the template is published");
        }
        let _ = lock.close().await;
        name
    }

    /// Clones the template into a new database and returns its name.
    pub(crate) async fn clone_database(&self) -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let template = self.template().await;
        let name = format!("davhaven_t_{}_{}", run_id(), COUNTER.fetch_add(1, Ordering::SeqCst));
        let lock = self.lock_cluster(LOCK).await;
        let mut admin = self.admin().await;
        raw(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .expect("a stale test database is dropped");
        raw(format!("CREATE DATABASE {name} TEMPLATE {template} OWNER {OWNER}"))
            .execute(&mut admin)
            .await
            .expect("the template is cloned");
        let _ = lock.close().await;
        name
    }

    /// Creates a database with the production privilege setup and no schema.
    pub(crate) async fn empty_database(&self) -> Scratch {
        self.empty_database_with(PROVISIONING).await
    }

    /// Creates a database provisioned with `statements` and no schema.
    pub(crate) async fn empty_database_with(&self, statements: &[&'static str]) -> Scratch {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let name = format!("davhaven_e_{}_{}", run_id(), COUNTER.fetch_add(1, Ordering::SeqCst));
        let lock = self.lock_cluster(LOCK).await;
        let mut admin = self.admin().await;
        self.ensure_roles(&mut admin).await;
        raw(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .expect("a stale database is dropped");
        raw(format!("CREATE DATABASE {name} OWNER {OWNER}"))
            .execute(&mut admin)
            .await
            .expect("the database is created");
        let _ = lock.close().await;
        self.prepare(&name, statements).await;
        Scratch {
            cluster: self.clone(),
            name,
        }
    }

    /// Drops a database, terminating its connections.
    pub(crate) async fn drop_database(&self, name: &str) {
        let mut admin = self.admin().await;
        let _ = raw(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await;
    }

    /// A connection of the owner role to `database`.
    pub(crate) async fn owner_connection(&self, database: &str) -> PgConnection {
        PgConnection::connect_with(&self.owner_options(database))
            .await
            .expect("the owner role connects")
    }

    /// A connection of the runtime role to `database`.
    pub(crate) async fn app_connection(&self, database: &str) -> PgConnection {
        PgConnection::connect_with(&self.app_options(database))
            .await
            .expect("the runtime role connects")
    }

    /// A pool of the owner role (what migrations run with) on `database`.
    pub(crate) async fn owner_pool(&self, database: &str) -> PgPool {
        PgPoolOptions::new()
            .max_connections(2)
            .connect_with(self.owner_options(database))
            .await
            .expect("the owner role connects")
    }

    /// A pool of the runtime role on `database`.
    pub(crate) async fn app_pool(&self, database: &str, max_connections: u32) -> PgPool {
        PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect_with(self.app_options(database))
            .await
            .expect("the runtime role connects")
    }

    /// Runs a script as the owner role (simple protocol, so it may contain several statements).
    pub(crate) async fn run_script(&self, database: &str, script: &'static str) {
        let mut connection = self.owner_connection(database).await;
        sqlx::raw_sql(script)
            .execute(&mut connection)
            .await
            .expect("the script runs");
    }

    /// Fills the tables of `database` with the rows of `seed.sql`.
    pub(crate) async fn seed(&self, database: &str) {
        self.run_script(database, include_str!("seed.sql")).await;
    }
}

/// A cloned database that is dropped with the value.
pub(crate) struct TestDatabase {
    inner: PgDatabase,
    cluster: Cluster,
    name: String,
    /// The clock the store stamps with.
    pub(crate) clock: ManualClock,
}

impl TestDatabase {
    /// Clones the template and connects the runtime role with a manual clock and sequential ids.
    pub(crate) async fn create(cluster: &Cluster) -> Self {
        Self::with_pool_size(cluster, 10).await
    }

    /// As [`create`](Self::create), with the opt-in grant that lets the runtime role purge the audit log
    /// ([`GRANT_AUDIT_PURGE`]): what the server needs to run retention itself.
    pub(crate) async fn create_with_audit_purge(cluster: &Cluster) -> Self {
        let db = Self::create(cluster).await;
        cluster.run_script(db.name(), GRANT_AUDIT_PURGE).await;
        db
    }

    /// As [`create`](Self::create) with a pool of `max_connections` connections.
    pub(crate) async fn with_pool_size(cluster: &Cluster, max_connections: u32) -> Self {
        let name = cluster.clone_database().await;
        let options = cluster.app_options(&name);
        Self::connect(cluster, name, options, max_connections).await
    }

    /// Clones the template and connects the *owner* role, which row-level security does not bind: what the
    /// repositories do then rests on the explicit tenant predicates of their statements alone.
    pub(crate) async fn create_as_owner(cluster: &Cluster) -> Self {
        let name = cluster.clone_database().await;
        let options = cluster.owner_options(&name);
        Self::connect(cluster, name, options, 10).await
    }

    /// Opens the pool of a cloned database with the given role.
    async fn connect(cluster: &Cluster, name: String, options: PgConnectOptions, max_connections: u32) -> Self {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(std::time::Duration::from_secs(60))
            .connect_with(options)
            .await
            .expect("the role connects");
        let clock = ManualClock::default();
        let inner = PgDatabase::from_pool(pool, Arc::new(clock.clone()), Arc::new(SeqIds::new()));
        Self {
            inner,
            cluster: cluster.clone(),
            name,
            clock,
        }
    }

    /// The name of the database.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The cluster the database lives in.
    pub(crate) fn cluster(&self) -> &Cluster {
        &self.cluster
    }

    /// The pool of the runtime role.
    pub(crate) fn pool(&self) -> &PgPool {
        self.inner.pool()
    }
}

#[async_trait]
impl Database for TestDatabase {
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

impl Drop for TestDatabase {
    fn drop(&mut self) {
        drop_in_thread(self.cluster.clone(), self.name.clone());
    }
}

/// A database without a schema (but with the privilege setup of production), dropped with the value.
pub(crate) struct Scratch {
    cluster: Cluster,
    name: String,
}

impl Scratch {
    /// The name of the database.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The cluster the database lives in.
    pub(crate) fn cluster(&self) -> &Cluster {
        &self.cluster
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop_in_thread(self.cluster.clone(), self.name.clone());
    }
}

/// Drops a database from a thread of its own: the server terminates the connections itself (`WITH (FORCE)`), and
/// the runtime of the test, which may be the very thread that waits here, is not involved.
fn drop_in_thread(cluster: Cluster, name: String) {
    let cleanup = std::thread::spawn(move || {
        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
            runtime.block_on(cluster.drop_database(&name));
        }
    });
    let _ = cleanup.join();
}

#[cfg(test)]
mod guards {
    use super::is_throwaway;

    #[test]
    fn local_and_declared_servers_are_accepted_and_others_refused() {
        for url in [
            "postgres://u:p@localhost:5432/postgres",
            "postgres://u:p@127.0.0.1/davhaven",
            "postgres://u:p@[::1]/x",
            "postgres:///x?host=/var/run/postgresql&user=u",
            "postgres://u:p@db.internal/davhaven_ws_1",
        ] {
            assert!(is_throwaway(url, false, false), "{url}");
        }
        assert!(is_throwaway("postgres://u:p@db.internal/postgres", true, false));
        assert!(is_throwaway("postgres://u:p@db.internal/postgres", false, true));
        for url in [
            "postgres://u:p@db.internal/postgres",
            "postgres://u:p@db.internal/davhaven",
            "postgres://u:p@127.example.net/prod",
            "not a url",
        ] {
            assert!(!is_throwaway(url, false, false), "{url}");
        }
    }
}
