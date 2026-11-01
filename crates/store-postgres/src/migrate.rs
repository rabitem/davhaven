//! Embedded migrations and schema version checks.
//!
//! Migrations are forward-only and follow expand/contract (`ENGINEERING_RULES` R16): a release can run on the schema
//! of the release after it, drops and renames ship one release after the code stopped using the old shape, and
//! only this crate writes them. They live in `migrations/` as `<timestamp>_<description>.sql`, are embedded at
//! compile time and are applied with the owner role (`davhaven migrate`, or at startup when
//! `database.migrate_on_start` is set).
//!
//! The runtime ignores migrations that are newer than the binary (a rolling deployment starts the new schema
//! before the old instances stop) and refuses to become ready on a schema older than
//! [`REQUIRED_SCHEMA_VERSION`].

use std::time::Duration;

use davhaven_ports::{PortError, StoreError};
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::config::{DatabaseConfig, PLUGIN};
use crate::error::map_sqlx;

/// The oldest PostgreSQL server this schema works on, as `server_version_num` (15.0): the migration uses
/// `ON DELETE SET NULL (column)`, which PostgreSQL 14 rejects with a syntax error nobody can act on.
pub const MIN_SERVER_VERSION_NUM: i32 = 150_000;

/// The oldest schema version this binary works on: the version of the newest migration it needs. `/readyz`
/// reports not ready while the highest applied migration is older. Raise it only in the release that first
/// needs a migration, never in the release that merely ships one for the next. This release needs
/// `20261101120000_initial_schema`.
pub const REQUIRED_SCHEMA_VERSION: i64 = 20_261_101_120_000;

/// The role model of the database as SQL (`role_model.sql`): what the runtime roles of the migrating role may and may
/// not do. It is applied after every migration run; see [`enforce_role_model`].
const ROLE_MODEL: &str = include_str!("role_model.sql");

/// The advisory lock (of this database) that serialises applications of the role model: the ASCII bytes of `davhave`.
const ROLE_MODEL_LOCK: i64 = 0x0064_6176_6861_7665;

/// The embedded migrations. The migrator ignores applied migrations it does not know, so an older binary keeps
/// working on a newer schema.
pub fn migrator() -> Migrator {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.set_ignore_missing(true);
    migrator
}

/// One embedded migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationInfo {
    /// The version: the timestamp in the file name.
    pub version: i64,
    /// The description: the rest of the file name.
    pub description: String,
}

/// The embedded migrations in the order they are applied.
pub fn embedded() -> Vec<MigrationInfo> {
    migrator()
        .iter()
        .map(|migration| MigrationInfo {
            version: migration.version,
            description: migration.description.to_string(),
        })
        .collect()
}

/// The version of the newest embedded migration.
pub fn latest_version() -> i64 {
    migrator().iter().map(|migration| migration.version).max().unwrap_or(0)
}

/// What a migration run did about the role model of the database ([`enforce_role_model`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleModel {
    /// The role model was applied to this many runtime roles: the roles that hold default privileges of the owner of the
    /// tables. None means that the owner granted no default privileges (a setup where the operator grants by hand), so
    /// there was nothing to take away; the posture check still judges the role that serves requests.
    Applied {
        /// How many runtime roles were found.
        runtime_roles: u32,
    },
    /// The role model was **not** applied: the connected role does not own the tables, so it may not change what any
    /// role holds. This is what a runtime role gets when it migrates with its own credentials, and what a database
    /// that was restored without `--role=<owner>` gets (docs/operations/backup.md).
    NotOwner,
}

impl core::fmt::Display for RoleModel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Applied { runtime_roles: 0 } => f.write_str(
                "applied; the owner of the tables has no default privileges for another role, so there was no runtime \
                 role to restrict",
            ),
            Self::Applied { runtime_roles: 1 } => f.write_str("applied to 1 runtime role"),
            Self::Applied { runtime_roles } => write!(f, "applied to {runtime_roles} runtime roles"),
            Self::NotOwner => f.write_str("not applied: the connected role does not own the tables"),
        }
    }
}

/// What a migration run found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// The highest applied version before the run (`None` for an empty database).
    pub before: Option<i64>,
    /// The highest applied version after the run.
    pub after: Option<i64>,
    /// What the run did about the role model of the database.
    pub role_model: RoleModel,
}

impl MigrationReport {
    /// Whether the run applied at least one migration.
    pub fn changed(&self) -> bool {
        self.before != self.after
    }
}

/// The highest successfully applied migration version, or `None` when the database has no migration history.
///
/// # Errors
///
/// Connection failures and, for a database where the history table does not exist, `None` is returned instead.
pub async fn applied_version(pool: &PgPool) -> Result<Option<i64>, StoreError> {
    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations')::text")
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)?;
    if table.is_none() {
        return Ok(None);
    }
    sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
}

/// Checks a `server_version_num` against [`MIN_SERVER_VERSION_NUM`].
///
/// # Errors
///
/// The message names the server's version and the minimum, for operators.
pub fn check_server_version(version_num: i32) -> Result<(), String> {
    if version_num >= MIN_SERVER_VERSION_NUM {
        return Ok(());
    }
    Err(format!(
        "PostgreSQL {} is not supported: Davhaven needs PostgreSQL {} or newer (server_version_num {version_num})",
        version_num / 10_000,
        MIN_SERVER_VERSION_NUM / 10_000
    ))
}

/// Refuses a server older than PostgreSQL 15 with a message that names the minimum version, before a migration
/// fails on it or a query misbehaves.
///
/// # Errors
///
/// [`StoreError::Internal`] with the message of [`check_server_version`]; connection failures as `map_sqlx`.
pub async fn require_supported_server(pool: &PgPool) -> Result<(), StoreError> {
    let text: String = sqlx::query_scalar("SHOW server_version_num")
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)?;
    let number = text
        .trim()
        .parse::<i32>()
        .map_err(|_| StoreError::internal(format!("the server reports an unreadable version number `{text}`")))?;
    check_server_version(number).map_err(StoreError::internal)
}

/// Whether a failed migration was refused by the database with the SQLSTATE `code`, looking through the layers of the error.
fn has_sqlstate(error: &(dyn std::error::Error + 'static), code: &str) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(sqlx::Error::Database(database)) = error.downcast_ref::<sqlx::Error>()
            && database.code().as_deref() == Some(code)
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// Whether a failed migration was refused by the database for lack of privilege (SQLSTATE 42501), which is what the
/// runtime role gets when `migrate_on_start` makes the server migrate with its own credentials.
fn permission_denied(error: &(dyn std::error::Error + 'static)) -> bool {
    has_sqlstate(error, "42501")
}

/// Whether a failed migration gave up waiting for a lock (SQLSTATE 55P03, `lock_not_available`): the `lock_timeout` of the
/// migration connection ([`MIGRATION_LOCK_TIMEOUT`]) ran out.
fn lock_timed_out(error: &(dyn std::error::Error + 'static)) -> bool {
    has_sqlstate(error, "55P03")
}

/// The hint that goes with a migration that gave up waiting for a lock.
const LOCK_HINT: &str = "it waited for a lock that something else holds (a long transaction, or another run of \
     `davhaven migrate`) and gave up instead of making every write of the application queue behind it; nothing of it was \
     applied (every migration is one transaction), so run `davhaven migrate` again once the transaction has ended";

/// The hint that goes with a migration the connected role was not allowed to run.
const OWNER_HINT: &str = "the connected role may not change the schema: run `davhaven migrate` with the owner role \
     (`database.migration_url`), or set `database.migrate_on_start = false` when the schema is already migrated";

/// Whether the connected role owns the tables (or is a member of the role that does), which is the only role that may
/// change what the runtime roles hold.
async fn owns_the_tables(pool: &PgPool) -> Result<bool, StoreError> {
    sqlx::query_scalar(
        "SELECT COALESCE((SELECT pg_has_role(current_user, c.relowner, 'USAGE') FROM pg_class c \
         WHERE c.oid = to_regclass('public.principals')), false)",
    )
    .fetch_one(pool)
    .await
    .map_err(map_sqlx)
}

/// Applies the role model of the database (`role_model.sql`) to the runtime roles of the owner of the tables: the
/// roles that hold the owner's default privileges lose `TRUNCATE`, `REFERENCES` and `TRIGGER`, the right to change or
/// delete audit records, the right to write the migration history, the right to purge the audit log and the default
/// right to call the functions that a later migration creates, and keep the right to call the functions of the
/// row-level security policies. A role that holds no default privileges of the owner (a dedicated role that runs the
/// audit purge) is left alone. Idempotent. Answers [`RoleModel::NotOwner`] without a change when the connected role does
/// not own the tables (or is not a member of their owner): a runtime role that migrates with its own credentials may not
/// change privileges and leaves them as they are.
///
/// [`run_on`] calls it after every migration run. It matters when **no migration is pending**: a database restored
/// from a dump (`pg_restore --no-owner --role=<owner>`) gets its tables from the default privileges of the owner
/// before the dump's own `GRANT` statements add to them, so the restored runtime role holds more than the role model
/// allows until this runs (docs/operations/backup.md).
///
/// # Errors
///
/// [`StoreError::Internal`] when a statement fails (with the owner role this means a damaged catalog).
pub async fn enforce_role_model(pool: &PgPool) -> Result<RoleModel, StoreError> {
    if !owns_the_tables(pool).await? {
        return Ok(RoleModel::NotOwner);
    }
    // Several instances may start at once with `migrate_on_start`: the migrator serialises the migrations, and this
    // serialises the privilege changes that follow (two concurrent updates of the same catalog row fail with "tuple
    // concurrently updated").
    let mut tx = pool.begin().await.map_err(map_sqlx)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ROLE_MODEL_LOCK)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    sqlx::raw_sql(ROLE_MODEL)
        .execute(&mut *tx)
        .await
        .map_err(|error| StoreError::internal(format!("the role model could not be applied: {}", map_sqlx(error))))?;
    // The statement counts the runtime roles it found and leaves the number in a setting of this transaction.
    let found: Option<String> = sqlx::query_scalar("SELECT current_setting('davhaven.role_model_roles', true)")
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    tx.commit().await.map_err(map_sqlx)?;
    let runtime_roles = found
        .and_then(|text| text.parse::<u32>().ok())
        .ok_or_else(|| StoreError::internal("the role model did not report how many runtime roles it found"))?;
    if runtime_roles == 0 {
        tracing::warn!(
            plugin = PLUGIN,
            "the owner of the tables has no default privileges for another role, so the role model found no runtime \
             role to restrict; the privileges of the role that serves requests are whatever the operator granted \
             (docs/operations/database.md)"
        );
    }
    Ok(RoleModel::Applied { runtime_roles })
}

/// Applies the pending migrations through `pool`, whose role must be the owner of the schema, and then the role
/// model of the database ([`enforce_role_model`]).
///
/// # Errors
///
/// [`StoreError::Unavailable`] when the database cannot be reached and [`StoreError::Internal`] when the server
/// is older than PostgreSQL 15, a migration fails (with a hint when the role lacked the privilege) or an applied
/// migration was changed after it ran (checksum mismatch).
pub async fn run_on(pool: &PgPool) -> Result<MigrationReport, StoreError> {
    require_supported_server(pool).await?;
    let schema: Option<String> = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)?;
    if schema.as_deref() != Some("public") {
        return Err(StoreError::internal(format!(
            "the connection's current schema is `{}`, but Davhaven migrates and uses schema `public` only; set the \
             role's `search_path` to `public`",
            schema.as_deref().unwrap_or("(none)")
        )));
    }
    let before = applied_version(pool).await?;
    migrator().run(pool).await.map_err(|error| {
        let hint = if permission_denied(&error) {
            format!(" ({OWNER_HINT})")
        } else if lock_timed_out(&error) {
            format!(" ({LOCK_HINT})")
        } else {
            String::new()
        };
        StoreError::internal(format!("migration failed: {error}{hint}"))
    })?;
    let role_model = enforce_role_model(pool).await?;
    let after = applied_version(pool).await?;
    Ok(MigrationReport {
        before,
        after,
        role_model,
    })
}

/// How many audit records one call of the purge function removes at most.
const AUDIT_PURGE_BATCH: i32 = 5000;

/// Purges the audit records older than `cutoff` with the credentials of `config`'s migration role (`migration_url`,
/// falling back to `url`): the way to run audit retention, which the runtime role may not do. The role is the owner or a
/// role of its own that may execute the purge function and nothing else (docs/operations/database.md). It calls
/// `davhaven_purge_audit` repeatedly until a call removes less than a batch and returns the total. The server's
/// `davhaven admin purge-audit` runs this; it takes the cut-off from the retention settings and the clock. As for
/// [`run`], the caller applies the transport rule of the owner URL first.
///
/// # Errors
///
/// [`davhaven_ports::PluginError`] when the URL cannot be resolved, the database cannot be reached, the role may
/// not execute the function (it is not the owner) or the server is not supported.
pub async fn purge_audit(
    config: &DatabaseConfig,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Result<u64, davhaven_ports::PluginError> {
    use secrecy::ExposeSecret;

    config.validate()?;
    let url = config.migration_connection_url()?;
    let options: PgConnectOptions = url.expose_secret().parse().map_err(|_| {
        davhaven_ports::PluginError::invalid_config(PLUGIN, "the migration URL is not a PostgreSQL URL")
    })?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(config.acquire_timeout.max(Duration::from_secs(10)))
        .connect_with(options.application_name("davhaven-purge-audit"))
        .await
        .map_err(|error| davhaven_ports::PluginError::build(PLUGIN, PortError::from(map_sqlx(error))))?;
    let mut total = 0_u64;
    let outcome = async {
        require_supported_server(&pool).await?;
        loop {
            let removed: i64 = sqlx::query_scalar("SELECT davhaven_purge_audit($1, $2)")
                .bind(cutoff)
                .bind(AUDIT_PURGE_BATCH)
                .fetch_one(&pool)
                .await
                .map_err(map_sqlx)?;
            let removed = u64::try_from(removed).unwrap_or(0);
            total = total.saturating_add(removed);
            if removed < u64::try_from(AUDIT_PURGE_BATCH).unwrap_or(u64::MAX) {
                return Ok::<u64, StoreError>(total);
            }
        }
    }
    .await
    .map_err(|error| davhaven_ports::PluginError::build(PLUGIN, PortError::from(error)));
    pool.close().await;
    outcome
}

/// How long a migration waits for a lock before it gives up: the `lock_timeout` of the connection that migrates.
///
/// A statement that needs a lock that is not free (an `ALTER TABLE` on a table that a long transaction
/// has read) waits for it, and while it waits **every statement that comes after it queues behind it**: the application stops
/// answering on that table until the first transaction ends. A migration that cannot get its lock in this time fails, rolls
/// back (each migration is one transaction) and leaves the schema as it was; the operator runs `davhaven migrate` again.
/// The same limit applies to a second run of `davhaven migrate` (or an instance that starts with `migrate_on_start`) that waits
/// for the advisory lock of the run that is applying the migrations: when those take longer, it fails and is run again.
pub const MIGRATION_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Connects with the migration role of `config` (`migration_url`, falling back to `url`) and applies the pending
/// migrations. This is what `davhaven migrate` and `database.migrate_on_start` run. A migration gives up when it has waited
/// [`MIGRATION_LOCK_TIMEOUT`] for a lock.
///
/// The transport rule of production mode is the caller's, because only the caller knows the mode: it applies
/// [`check_migration_transport`](crate::plugin::check_migration_transport) before it calls this (the plugin build
/// applies [`check_transport`](crate::plugin::check_transport), which covers this URL, and so does `davhaven migrate`).
///
/// # Errors
///
/// [`davhaven_ports::PluginError`] when the URL cannot be resolved or the database cannot be reached or migrated.
pub async fn run(config: &DatabaseConfig) -> Result<MigrationReport, davhaven_ports::PluginError> {
    run_with_lock_timeout(config, MIGRATION_LOCK_TIMEOUT).await
}

/// [`run`] with another `lock_timeout` for the connection that migrates (the tests of the give-up use a short one).
///
/// # Errors
///
/// As [`run`].
pub async fn run_with_lock_timeout(
    config: &DatabaseConfig,
    lock_timeout: Duration,
) -> Result<MigrationReport, davhaven_ports::PluginError> {
    use secrecy::ExposeSecret;

    config.validate()?;
    let url = config.migration_connection_url()?;
    let options: PgConnectOptions = url.expose_secret().parse().map_err(|_| {
        davhaven_ports::PluginError::invalid_config(PLUGIN, "the migration URL is not a PostgreSQL URL")
    })?;
    let lock_ms = lock_timeout.as_millis().to_string();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(config.acquire_timeout.max(Duration::from_secs(10)))
        .connect_with(
            options
                .application_name("davhaven-migrate")
                .options([("lock_timeout", lock_ms.as_str())]),
        )
        .await
        .map_err(|error| davhaven_ports::PluginError::build(PLUGIN, PortError::from(map_sqlx(error))))?;
    let report = run_on(&pool)
        .await
        .map_err(|error| davhaven_ports::PluginError::build(PLUGIN, PortError::from(error)));
    pool.close().await;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_embedded_in_ascending_order() {
        let migrations = embedded();
        assert_ne!(migrations.len(), 0);
        let mut sorted = migrations.clone();
        sorted.sort_by_key(|migration| migration.version);
        assert_eq!(migrations, sorted, "migrations are applied in version order");
        let mut versions: Vec<i64> = migrations.iter().map(|migration| migration.version).collect();
        versions.dedup();
        assert_eq!(versions.len(), migrations.len(), "versions are unique");
    }

    #[test]
    fn migrations_are_forward_only() {
        for migration in migrator().iter() {
            assert!(
                !migration.migration_type.is_down_migration(),
                "{} is a down migration; migrations are forward-only (R16)",
                migration.version
            );
        }
    }

    #[test]
    fn migration_versions_are_timestamps() {
        for migration in embedded() {
            let digits = migration.version.to_string();
            assert_eq!(digits.len(), 14, "{digits} is not a YYYYMMDDHHMMSS timestamp");
            assert_ne!(migration.description.len(), 0);
        }
    }

    #[test]
    fn the_required_version_is_an_embedded_migration() {
        assert!(migrator().version_exists(REQUIRED_SCHEMA_VERSION));
        assert!(REQUIRED_SCHEMA_VERSION <= latest_version());
    }

    #[test]
    fn old_servers_are_refused_with_the_minimum_named() {
        assert!(check_server_version(150_000).is_ok());
        assert!(check_server_version(150_013).is_ok());
        assert!(check_server_version(170_004).is_ok());
        assert!(check_server_version(180_000).is_ok());
        for old in [140_012, 90_624, 0] {
            let message = check_server_version(old).unwrap_err();
            assert!(message.contains("15 or newer"), "{message}");
            assert!(message.contains(&old.to_string()), "{message}");
        }
        assert!(check_server_version(140_012).unwrap_err().contains("PostgreSQL 14"));
    }

    #[test]
    fn a_permission_error_is_found_in_the_source_chain() {
        let plain = std::io::Error::other("nothing to see");
        assert!(!permission_denied(&plain));
    }

    #[test]
    fn the_role_model_outcome_tells_the_operator_what_happened() {
        // `davhaven migrate` prints it: a run that restricted nobody must not read like one that restricted the runtime role.
        assert_eq!(
            RoleModel::Applied { runtime_roles: 1 }.to_string(),
            "applied to 1 runtime role"
        );
        assert_eq!(
            RoleModel::Applied { runtime_roles: 2 }.to_string(),
            "applied to 2 runtime roles"
        );
        let nobody = RoleModel::Applied { runtime_roles: 0 }.to_string();
        assert!(
            nobody.contains("no default privileges") && nobody.contains("no runtime role"),
            "{nobody}"
        );
        let not_owner = RoleModel::NotOwner.to_string();
        assert!(
            not_owner.starts_with("not applied") && not_owner.contains("does not own the tables"),
            "{not_owner}"
        );
    }

    #[test]
    fn reports_know_whether_anything_changed() {
        let unchanged = MigrationReport {
            before: Some(1),
            after: Some(1),
            role_model: RoleModel::NotOwner,
        };
        assert!(!unchanged.changed());
        let changed = MigrationReport {
            before: None,
            after: Some(1),
            role_model: RoleModel::Applied { runtime_roles: 1 },
        };
        assert!(changed.changed());
    }
}
