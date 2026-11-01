//! Migrations, schema versions, readiness, the plugin and the invariants of the schema that the adapter relies on
//! (constraint names, no database clock).

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test environment that misbehaves fails the test loudly"
)]

mod support;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;

use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
use davhaven_ports::{
    ConfigTree, Database, Health, PageReq, PluginContext, PluginRegistry, PortKind, RunMode, StoreError, TxMode,
};
use davhaven_store_postgres::config::{DatabaseConfig, PLUGIN};
use davhaven_store_postgres::database::PgDatabase;
use davhaven_store_postgres::error::{UNIQUE_CONSTRAINTS, map_sqlx};
use davhaven_store_postgres::migrate::{self, REQUIRED_SCHEMA_VERSION, RoleModel};
use davhaven_store_postgres::plugin;
use secrecy::SecretString;
use sqlx::PgPool;
use support::{Cluster, Scratch, TestDatabase};

/// A database on the runtime pool of `pool`, with the clock and ids of the tests.
fn database(pool: PgPool) -> PgDatabase {
    PgDatabase::from_pool(pool, Arc::new(ManualClock::default()), Arc::new(SeqIds::new()))
}

/// The configuration that connects the roles of the tests to `database`.
fn config(cluster: &Cluster, database: &str) -> DatabaseConfig {
    DatabaseConfig {
        url: Some(SecretString::from(cluster.url_for(support::APP, database))),
        migration_url: Some(SecretString::from(cluster.url_for(support::OWNER, database))),
        ..DatabaseConfig::default()
    }
}

/// An empty database and an owner pool on it.
async fn empty(cluster: &Cluster) -> (Scratch, PgPool) {
    let scratch = cluster.empty_database().await;
    let owner = cluster.owner_pool(scratch.name()).await;
    (scratch, owner)
}

#[tokio::test]
async fn migrations_apply_to_an_empty_database_and_are_idempotent() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (_scratch, owner) = empty(&cluster).await;
    assert_eq!(migrate::applied_version(&owner).await.unwrap(), None);

    let first = migrate::run_on(&owner).await.unwrap();
    assert_eq!(first.before, None);
    assert_eq!(first.after, Some(migrate::latest_version()));
    assert!(first.changed());

    let second = migrate::run_on(&owner).await.unwrap();
    assert!(!second.changed(), "a second run applies nothing");
    assert_eq!(second.after, Some(migrate::latest_version()));

    let history: Vec<(i64, bool)> = sqlx::query_as("SELECT version, success FROM _sqlx_migrations ORDER BY version")
        .fetch_all(&owner)
        .await
        .unwrap();
    let embedded: Vec<i64> = migrate::embedded().iter().map(|migration| migration.version).collect();
    assert_eq!(
        history.iter().map(|(version, _)| *version).collect::<Vec<_>>(),
        embedded
    );
    assert!(history.iter().all(|(_, success)| *success));
}

#[tokio::test]
async fn concurrent_migrations_serialise() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let scratch = cluster.empty_database().await;
    let name = scratch.name().to_owned();
    let runs: Vec<_> = (0..3)
        .map(|_| {
            let cluster = cluster.clone();
            let name = name.clone();
            tokio::spawn(async move {
                let owner = cluster.owner_pool(&name).await;
                migrate::run_on(&owner).await
            })
        })
        .collect();
    for run in runs {
        let report = run.await.unwrap().expect("a concurrent migration run succeeds");
        assert_eq!(report.after, Some(migrate::latest_version()));
    }
    let owner = cluster.owner_pool(&name).await;
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&owner)
        .await
        .unwrap();
    assert_eq!(
        usize::try_from(applied).unwrap(),
        migrate::embedded().len(),
        "each migration ran once"
    );
}

#[tokio::test]
async fn the_runtime_role_cannot_migrate() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let scratch = cluster.empty_database().await;
    let app = cluster.app_pool(scratch.name(), 1).await;
    let error = migrate::run_on(&app)
        .await
        .expect_err("the runtime role has no right to create the schema");
    assert!(matches!(error, StoreError::Internal(_)), "{error:?}");
    assert_eq!(migrate::applied_version(&app).await.unwrap(), None);
}

#[tokio::test]
async fn a_changed_migration_is_refused() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (_scratch, owner) = empty(&cluster).await;
    migrate::run_on(&owner).await.unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = '\\x00'")
        .execute(&owner)
        .await
        .unwrap();
    let error = migrate::run_on(&owner)
        .await
        .expect_err("a migration that changed after it ran is refused");
    assert!(
        error
            .to_string()
            .contains("was previously applied but has been modified"),
        "the refusal names the checksum mismatch, not just any failure: {error}"
    );
}

#[test]
fn released_migrations_never_change() {
    // R16: a released migration is never edited. `tests/released_migrations.txt` lists `version sha384` of every
    // migration of a release; a migration that is listed must still exist with the same checksum. A migration
    // that is not listed yet is unreleased and may still change (the list gets its line when the release is cut).
    let released: Vec<(i64, String)> = include_str!("released_migrations.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (version, checksum) = line.split_once(' ').expect("`<version> <sha384>` per line");
            (version.parse().expect("a numeric version"), checksum.trim().to_owned())
        })
        .collect();
    let migrator = migrate::migrator();
    for (version, checksum) in released {
        let migration = migrator
            .iter()
            .find(|migration| migration.version == version)
            .unwrap_or_else(|| panic!("the released migration {version} was removed or renamed"));
        let actual = migration.checksum.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        assert_eq!(
            actual, checksum,
            "the released migration {version} was edited; add a new migration instead"
        );
    }
}

#[tokio::test]
async fn a_newer_schema_is_tolerated() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (scratch, owner) = empty(&cluster).await;
    migrate::run_on(&owner).await.unwrap();
    // The next release already migrated the database; this (older) binary keeps running on it.
    let future = migrate::latest_version() + 1;
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES ($1, 'from the next release', true, '\\x00', 0)",
    )
    .bind(future)
    .execute(&owner)
    .await
    .unwrap();

    let report = migrate::run_on(&owner)
        .await
        .expect("unknown newer migrations are ignored");
    assert!(!report.changed());
    assert_eq!(report.after, Some(future));

    let runtime = database(cluster.app_pool(scratch.name(), 2).await);
    assert_eq!(Database::health(&runtime).await, Health::Healthy);
    let mut tx = runtime.begin_system().await.unwrap();
    assert_eq!(tx.tenants().list(PageReq::default()).await.unwrap().items.len(), 0);
}

#[tokio::test]
async fn health_follows_the_schema_version() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (scratch, owner) = empty(&cluster).await;
    let runtime = database(cluster.app_pool(scratch.name(), 2).await);

    // No migration history at all.
    let Health::Unhealthy(reason) = Database::health(&runtime).await else {
        panic!("an unmigrated database is ready");
    };
    assert!(reason.contains("migrate"), "{reason}");

    migrate::run_on(&owner).await.unwrap();
    assert_eq!(Database::health(&runtime).await, Health::Healthy);

    // A failed migration does not count as applied: the newest one that did (none, while the required migration is the
    // first) is older than the release needs.
    sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version >= $1")
        .bind(REQUIRED_SCHEMA_VERSION)
        .execute(&owner)
        .await
        .unwrap();
    assert_eq!(
        migrate::applied_version(&owner).await.unwrap(),
        migrate::embedded()
            .iter()
            .map(|migration| migration.version)
            .filter(|version| *version < REQUIRED_SCHEMA_VERSION)
            .max(),
        "the failed migrations are not the applied version"
    );
    let Health::Unhealthy(reason) = Database::health(&runtime).await else {
        panic!("a database whose required migration failed is ready");
    };
    assert!(reason.contains("davhaven migrate"), "{reason}");

    sqlx::query("UPDATE _sqlx_migrations SET success = true")
        .execute(&owner)
        .await
        .unwrap();
    assert_eq!(Database::health(&runtime).await, Health::Healthy);

    // A schema older than the release needs: the newest applied migration is one before the required one.
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version > $1")
        .bind(REQUIRED_SCHEMA_VERSION)
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET version = $1 - 1 WHERE version = $1")
        .bind(REQUIRED_SCHEMA_VERSION)
        .execute(&owner)
        .await
        .unwrap();
    let Health::Unhealthy(reason) = Database::health(&runtime).await else {
        panic!("a schema that is too old is ready");
    };
    assert!(reason.contains(&REQUIRED_SCHEMA_VERSION.to_string()), "{reason}");

    // The database going away is reported, not raised.
    drop(owner);
    cluster.drop_database(scratch.name()).await;
    assert!(matches!(Database::health(&runtime).await, Health::Unhealthy(_)));
}

#[tokio::test]
async fn migrate_and_connect_work_from_the_configuration() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let scratch = cluster.empty_database().await;
    let config = config(&cluster, scratch.name());

    let report = migrate::run(&config).await.expect("the migration role migrates");
    assert!(report.changed());
    assert!(!migrate::run(&config).await.unwrap().changed());

    let database = PgDatabase::connect(&config, Arc::new(ManualClock::default()), Arc::new(SeqIds::new()))
        .await
        .expect("the runtime role connects");
    assert_eq!(Database::health(&database).await, Health::Healthy);

    // Without a migration URL the runtime URL migrates, and the runtime role cannot.
    let runtime_only = DatabaseConfig {
        migration_url: None,
        ..config.clone()
    };
    assert!(migrate::run(&runtime_only).await.is_err());

    // A wrong password is a startup failure with a name, not a hang.
    let wrong = DatabaseConfig {
        url: Some(SecretString::from(cluster.url_for("davhaven_nobody", scratch.name()))),
        ..config
    };
    let error = PgDatabase::connect(&wrong, Arc::new(ManualClock::default()), Arc::new(SeqIds::new()))
        .await
        .expect_err("an unknown role cannot connect");
    assert!(
        !error.to_string().contains("davhaven_nobody:"),
        "the error leaks the URL: {error}"
    );
}

/// The key of the advisory lock sqlx takes around a migration run: `0x3d32ad9e * crc32(database name)` (CRC-32/ISO-HDLC),
/// as `sqlx-postgres` computes it. If sqlx changes it, the migration below no longer waits and the test fails.
fn sqlx_migration_lock_id(database: &str) -> i64 {
    let mut crc = 0xffff_ffff_u32;
    for byte in database.bytes() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    0x3d32_ad9e * i64::from(!crc)
}

#[tokio::test]
async fn a_migration_that_waits_for_a_lock_gives_up_and_runs_again_when_the_lock_is_free() {
    use sqlx::Connection as _;

    let Some(cluster) = support::cluster() else {
        return;
    };
    let scratch = cluster.empty_database().await;
    let config = config(&cluster, scratch.name());
    let mut owner = cluster.owner_connection(scratch.name()).await;

    // Another session holds the lock that serialises migrations of this database (the advisory lock sqlx takes, keyed
    // by the database name). A migration that waited for it forever would hang a deployment; it gives up after the lock
    // timeout of its connection instead, and leaves the schema as it was.
    let mut holder = cluster.owner_connection(scratch.name()).await;
    let mut transaction = holder.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(sqlx_migration_lock_id(scratch.name()))
        .execute(&mut *transaction)
        .await
        .unwrap();
    let error = migrate::run_with_lock_timeout(&config, std::time::Duration::from_millis(300))
        .await
        .expect_err("a migration cannot get its lock");
    let shown = error.to_string();
    assert!(
        shown.contains("lock timeout") && shown.contains("run `davhaven migrate` again"),
        "the error says why and what to do: {shown}"
    );
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_sqlx_migrations'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(tables, 0, "nothing of the migration was applied");
    let pool = cluster.owner_pool(scratch.name()).await;
    assert_eq!(
        migrate::applied_version(&pool).await.unwrap(),
        None,
        "and the history says so"
    );

    // The lock is free: running it again applies it.
    transaction.rollback().await.unwrap();
    let report = migrate::run(&config).await.unwrap();
    assert!(report.changed(), "{report:?}");
    assert_eq!(report.after, Some(migrate::latest_version()));
    assert_eq!(migrate::MIGRATION_LOCK_TIMEOUT, std::time::Duration::from_secs(10));
}

#[tokio::test]
async fn connection_limits_apply_and_map_to_timeouts() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let scratch = cluster.empty_database().await;
    let mut config = config(&cluster, scratch.name());
    migrate::run(&config).await.unwrap();
    config.statement_timeout = std::time::Duration::from_millis(200);
    config.lock_timeout = std::time::Duration::from_millis(150);
    config.idle_in_transaction_timeout = std::time::Duration::from_secs(45);
    let database = Arc::new(
        PgDatabase::connect(&config, Arc::new(ManualClock::default()), Arc::new(SeqIds::new()))
            .await
            .unwrap(),
    );
    for (setting, expected) in [
        ("statement_timeout", "200ms"),
        ("lock_timeout", "150ms"),
        ("idle_in_transaction_session_timeout", "45s"),
    ] {
        let shown: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SHOW {setting}")))
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(shown, expected, "{setting} of every connection");
    }
    let error = sqlx::query("SELECT pg_sleep(5)")
        .execute(database.pool())
        .await
        .expect_err("the statement is cancelled");
    assert!(matches!(map_sqlx(error), StoreError::Timeout));

    // A writer queued behind a held calendar lock gives up after the lock timeout instead of holding a pooled
    // connection for the whole statement timeout.
    let shared: Arc<dyn Database> = Arc::<PgDatabase>::clone(&database);
    let world = davhaven_port_tests::store::fixtures::seed(&shared).await.unwrap();
    let mut holder = shared.begin(world.a, TxMode::ReadWrite).await.unwrap();
    holder
        .objects()
        .put(
            world.personal,
            davhaven_port_tests::store::fixtures::version(0x1001, "one.ics", "one").unwrap(),
            davhaven_ports::Expected::Absent,
        )
        .await
        .unwrap();
    let mut waiting = shared.begin(world.a, TxMode::ReadWrite).await.unwrap();
    let blocked = waiting
        .objects()
        .put(
            world.personal,
            davhaven_port_tests::store::fixtures::version(0x1002, "two.ics", "two").unwrap(),
            davhaven_ports::Expected::Absent,
        )
        .await;
    assert_eq!(
        blocked.map(|_| ()),
        Err(StoreError::Timeout),
        "a writer behind a held lock times out"
    );
    drop(waiting);
    holder.commit().await.unwrap();
    // The pool keeps working afterwards.
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn the_plugin_migrates_on_start_and_refuses_an_unmigrated_database() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let mut registry = PluginRegistry::new();
    plugin::register(&mut registry).unwrap();
    let context = PluginContext::for_tests();
    let scratch = cluster.empty_database().await;

    // Without `migrate_on_start` an unmigrated database is refused at startup, with a hint.
    let mut table = serde_json::json!({
        "url": cluster.url_for(support::APP, scratch.name()),
        "migration_url": cluster.url_for(support::OWNER, scratch.name()),
        "migrate_on_start": false,
        "allow_insecure_transport": true,
    });
    let tree = ConfigTree::new().with(PLUGIN, table.clone());
    let error = registry
        .build_single(PortKind::DATABASE, PLUGIN, &context, &tree)
        .await
        .map(|_| ())
        .expect_err("an unmigrated database is refused");
    assert!(error.to_string().contains("migrate"), "{error}");

    // With it, the plugin migrates and then serves.
    table["migrate_on_start"] = serde_json::json!(true);
    let tree = ConfigTree::new().with(PLUGIN, table);
    let built = registry
        .build_single(PortKind::DATABASE, PLUGIN, &context, &tree)
        .await
        .expect("the plugin migrates and builds");
    assert_eq!(built.port.health().await, Health::Healthy);
    let lifecycle = built.lifecycle.expect("the adapter has a lifecycle");
    assert_eq!(lifecycle.health().await, Health::Healthy);
    let mut tx = built.port.begin_system().await.unwrap();
    assert_eq!(tx.tenants().list(PageReq::default()).await.unwrap().items.len(), 0);
    drop(tx);
    lifecycle.shutdown().await;
}

#[tokio::test]
async fn every_unique_index_has_a_key_and_every_key_an_index() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    // Unique constraints and unique indexes that are not primary keys: the ones a violation can name.
    let unique: BTreeSet<String> = sqlx::query_scalar(
        "SELECT i.relname::text FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid \
         JOIN pg_class t ON t.oid = x.indrelid \
         WHERE t.relnamespace = 'public'::regnamespace AND x.indisunique AND NOT x.indisprimary \
           AND t.relname <> '_sqlx_migrations'",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let mapped: BTreeSet<String> = UNIQUE_CONSTRAINTS.iter().map(|(name, _)| (*name).to_owned()).collect();
    // Unique indexes whose violation the adapter never lets happen, so no `UniqueKey` names them:
    // targets of composite foreign keys (supersets of a primary key) and guards the adapter checks first
    // (properties are written by upsert; `set_addresses` rejects two primary addresses before it writes).
    let key_targets: BTreeSet<String> = [
        "calendar_bindings_calendar_id_key",
        "api_tokens_tenant_id_key",
        "collection_properties_binding_key",
        "collection_properties_shared_key",
        "principal_addresses_primary_key",
        // `create_delivery` answers the existing record for a repeated event (`ON CONFLICT DO NOTHING`).
        "webhook_deliveries_event_key",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    let missing: Vec<&String> = mapped.difference(&unique).collect();
    assert!(
        missing.is_empty(),
        "UNIQUE_CONSTRAINTS names constraints the schema does not have: {missing:?}"
    );
    let unmapped: Vec<&String> = unique
        .difference(&mapped)
        .filter(|name| !key_targets.contains(*name))
        .collect();
    assert!(
        unmapped.is_empty(),
        "unique indexes without a UniqueKey (a violation would be reported as an internal error): {unmapped:?}"
    );
}

#[tokio::test]
async fn nothing_depends_on_the_database_clock() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    // R16: logic-relevant timestamps come from `Clock`; no column fills itself in.
    let defaults: Vec<String> = sqlx::query_scalar(
        "SELECT table_name || '.' || column_name || ' = ' || column_default FROM information_schema.columns \
         WHERE table_schema = 'public' AND column_default IS NOT NULL AND table_name <> '_sqlx_migrations' \
           AND (column_default ILIKE '%now()%' OR column_default ILIKE '%current_timestamp%' \
                OR column_default ILIKE '%clock_timestamp%' OR column_default ILIKE '%statement_timestamp%' \
                OR column_default ILIKE '%current_date%' OR column_default ILIKE '%transaction_timestamp%')",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert!(
        defaults.is_empty(),
        "columns default to the database clock: {defaults:?}"
    );
    // Nor do generated or identity columns.
    let computed: Vec<String> = sqlx::query_scalar(
        "SELECT table_name || '.' || column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations' \
           AND (is_generated <> 'NEVER' OR is_identity = 'YES')",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert!(
        computed.is_empty(),
        "the schema has generated or identity columns: {computed:?}"
    );
    // Nor do triggers.
    let triggers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN \
         (SELECT oid FROM pg_class WHERE relnamespace = 'public'::regnamespace)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        triggers, 0,
        "the schema has triggers; the adapter's writes would not be the whole story"
    );
}

#[tokio::test]
async fn timestamps_come_from_the_injected_clock() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let instant: chrono::DateTime<chrono::Utc> = "2031-02-03T04:05:06.123456789Z".parse().unwrap();
    db.clock.set(instant);
    let name = db.name().to_owned();
    let shared: Arc<dyn Database> = Arc::new(db);
    let world = davhaven_port_tests::store::fixtures::seed(&shared).await.unwrap();
    // The stored value is the clock's, truncated to the microseconds the column keeps.
    let mut owner = cluster.owner_connection(&name).await;
    let stored: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT created_at FROM tenants WHERE id = $1")
        .bind(world.a.as_uuid())
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(
        stored,
        "2031-02-03T04:05:06.123456Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
    );
}

#[tokio::test]
async fn health_warns_when_row_level_security_does_not_bind_the_role() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    // The runtime role is bound: healthy.
    assert_eq!(Database::health(&database(db.pool().clone())).await, Health::Healthy);
    // The owner of the tables and a superuser are not bound: the database works, and says so.
    for pool in [cluster.owner_pool(db.name()).await, cluster.admin_pool(db.name()).await] {
        let health = Database::health(&database(pool)).await;
        let Health::Degraded(reason) = &health else {
            panic!("a role that bypasses row-level security is reported healthy: {health:?}");
        };
        assert!(reason.contains("row-level security"), "{reason}");
        assert!(health.is_ready(), "the database stays usable");
    }
}

#[tokio::test]
async fn health_reports_privileges_the_runtime_role_must_not_have() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let runtime = database(db.pool().clone());
    let clean = runtime.posture().await;
    assert!(clean.security_findings().is_empty(), "{clean:?}");
    assert!(
        !clean.ascii_only_case_folding && clean.locale_unknown.is_none(),
        "the test cluster needs a Unicode-aware LC_CTYPE"
    );

    let mut owner = cluster.owner_connection(db.name()).await;
    for (statement, finding) in [
        ("GRANT TRUNCATE ON principals TO davhaven_app", "TRUNCATE on principals"),
        ("GRANT UPDATE ON audit_events TO davhaven_app", "UPDATE on audit_events"),
        (
            "GRANT INSERT ON _sqlx_migrations TO davhaven_app",
            "INSERT on _sqlx_migrations",
        ),
        (
            "GRANT CREATE ON SCHEMA public TO davhaven_app",
            "CREATE on schema public",
        ),
        (
            "GRANT EXECUTE ON FUNCTION davhaven_purge_audit(timestamptz, integer) TO davhaven_app",
            PURGE_FINDING,
        ),
    ] {
        sqlx::query(statement).execute(&mut owner).await.unwrap();
        let posture = runtime.posture().await;
        assert_eq!(posture.excess_privileges, vec![finding.to_owned()], "{statement}");
        let Health::Degraded(reason) = Database::health(&runtime).await else {
            panic!("`{statement}` is not reported");
        };
        assert!(reason.contains(finding), "{reason}");
        let revoke = statement.replacen("GRANT", "REVOKE", 1).replacen(" TO ", " FROM ", 1);
        sqlx::query(sqlx::AssertSqlSafe(revoke))
            .execute(&mut owner)
            .await
            .unwrap();
    }
    assert_eq!(Database::health(&runtime).await, Health::Healthy);

    // A posture query that fails is a finding, never a clean bill of health.
    let closed = database(db.pool().clone());
    closed.pool().close().await;
    let posture = closed.posture().await;
    assert!(posture.unknown.is_some(), "{posture:?}");
    assert_ne!(
        posture.security_findings().len(),
        0,
        "an unanswered posture query is a finding"
    );
}

/// A production context: the plugin applies the rules of `RunMode::Production`.
fn production() -> PluginContext {
    PluginContext::new(
        Arc::new(ManualClock::default()),
        Arc::new(SeqIds::new()),
        Arc::new(FixedKeyRing::default()),
        Arc::new(PlainSealer),
        Arc::new(FixedHasher::default()),
        RunMode::Production,
    )
}

#[tokio::test]
async fn production_refuses_a_role_that_row_level_security_does_not_bind() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let mut registry = PluginRegistry::new();
    plugin::register(&mut registry).unwrap();
    let scratch = cluster.empty_database().await;

    // The zero-configuration setup: one URL, the owner's, which migrates and serves. Row-level security does not
    // bind the owner of the tables, so production refuses it with a message that says what to do.
    let table = serde_json::json!({
        "url": cluster.url_for(support::OWNER, scratch.name()),
        "allow_insecure_transport": true,
    });
    let tree = ConfigTree::new().with(PLUGIN, table);
    let error = registry
        .build_single(PortKind::DATABASE, PLUGIN, &production(), &tree)
        .await
        .map(|_| ())
        .expect_err("production serves with the owner role");
    let text = error.to_string();
    assert!(
        text.contains("row-level security") && text.contains("allow_unbound_role") && text.contains("database.md"),
        "{text}"
    );
    assert!(
        !text.contains("postgres://"),
        "the error must not leak the connection URL: {text}"
    );

    // The explicit opt-out starts it, and readiness keeps saying so.
    let table = serde_json::json!({
        "url": cluster.url_for(support::OWNER, scratch.name()),
        "allow_unbound_role": true,
        "allow_insecure_transport": true,
    });
    let tree = ConfigTree::new().with(PLUGIN, table);
    let built = registry
        .build_single(PortKind::DATABASE, PLUGIN, &production(), &tree)
        .await
        .expect("the opt-out starts the server");
    let Health::Degraded(reason) = built.port.health().await else {
        panic!("an unbound role must stay visible in readiness");
    };
    assert!(reason.contains("row-level security"), "{reason}");
    built.lifecycle.expect("a lifecycle").shutdown().await;

    // Development only warns.
    let table =
        serde_json::json!({ "url": cluster.url_for(support::OWNER, scratch.name()), "migrate_on_start": false });
    let tree = ConfigTree::new().with(PLUGIN, table);
    registry
        .build_single(PortKind::DATABASE, PLUGIN, &PluginContext::for_tests(), &tree)
        .await
        .expect("dev mode accepts a single role");

    // The proper runtime role, with the owner only for migrations, starts without any opt-out.
    let table = serde_json::json!({
        "url": cluster.url_for(support::APP, scratch.name()),
        "migration_url": cluster.url_for(support::OWNER, scratch.name()),
        "migrate_on_start": false,
        "allow_insecure_transport": true,
    });
    let tree = ConfigTree::new().with(PLUGIN, table);
    let built = registry
        .build_single(PortKind::DATABASE, PLUGIN, &production(), &tree)
        .await
        .expect("the runtime role is accepted in production");
    assert_eq!(built.port.health().await, Health::Healthy);
    built.lifecycle.expect("a lifecycle").shutdown().await;
}

/// What the posture check says about a runtime role that can execute the audit purge.
const PURGE_FINDING: &str = "EXECUTE on davhaven_purge_audit(timestamp with time zone,integer)";

#[tokio::test]
async fn a_runtime_role_that_can_purge_the_audit_log_is_a_security_finding() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    // The role model: the runtime role may not execute the purge function, and there is nothing to report. Audit
    // retention runs as the owner (`davhaven admin purge-audit`); the server has nothing to say about it.
    let runtime = database(db.pool().clone());
    let posture = runtime.posture().await;
    assert!(posture.security_findings().is_empty(), "{posture:?}");
    assert_eq!(Database::health(&runtime).await, Health::Healthy);

    // With the grant that an earlier release documented the server could purge, but a role that can purge can erase the
    // audit trail of every tenant: it is a security finding, whatever else the configuration says.
    cluster.run_script(db.name(), support::GRANT_AUDIT_PURGE).await;
    let mut registry = PluginRegistry::new();
    plugin::register(&mut registry).unwrap();
    let table = serde_json::json!({
        "url": cluster.url_for(support::APP, db.name()),
        "migrate_on_start": false,
        "allow_insecure_transport": true,
    });
    let tree = ConfigTree::new().with(PLUGIN, table);
    let posture = runtime.posture().await;
    assert_eq!(posture.excess_privileges, vec![PURGE_FINDING.to_owned()]);
    assert_eq!(posture.security_findings().len(), 1, "{posture:?}");
    let Health::Degraded(reason) = Database::health(&runtime).await else {
        panic!("a role that can purge the audit log is reported healthy");
    };
    assert!(
        reason.contains("davhaven_purge_audit") && reason.contains("erase the audit trail"),
        "{reason}"
    );
    let error = registry
        .build_single(PortKind::DATABASE, PLUGIN, &production(), &tree)
        .await
        .map(|_| ())
        .expect_err("production starts with a runtime role that can purge the audit log");
    let text = error.to_string();
    assert!(
        text.contains("davhaven_purge_audit") && text.contains("allow_unbound_role"),
        "{text}"
    );
    // `allow_unbound_role` accepts every security finding at once, this one too, and readiness keeps saying so.
    let accepted = ConfigTree::new().with(
        PLUGIN,
        serde_json::json!({
            "url": cluster.url_for(support::APP, db.name()),
            "migrate_on_start": false,
            "allow_insecure_transport": true,
            "allow_unbound_role": true,
        }),
    );
    let built = registry
        .build_single(PortKind::DATABASE, PLUGIN, &production(), &accepted)
        .await
        .expect("the opt-out starts the server");
    assert!(matches!(built.port.health().await, Health::Degraded(_)));
    built.lifecycle.expect("a lifecycle").shutdown().await;

    // The next run of the role model takes the grant back, and production starts without any opt-out.
    let owner = cluster.owner_pool(db.name()).await;
    let report = migrate::run_on(&owner).await.unwrap();
    assert_eq!(report.role_model, RoleModel::Applied { runtime_roles: 1 });
    let posture = runtime.posture().await;
    assert!(posture.excess_privileges.is_empty(), "{posture:?}");
    let built = registry
        .build_single(PortKind::DATABASE, PLUGIN, &production(), &tree)
        .await
        .expect("production starts without the audit purge grant");
    assert_eq!(built.port.health().await, Health::Healthy);
    built.lifecycle.expect("a lifecycle").shutdown().await;
}

#[tokio::test]
async fn a_function_that_runs_with_the_owners_rights_is_not_executable_by_the_runtime_role_by_default() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // An operator may have granted the runtime role the functions of the owner by default privileges (so that every
    // function a migration creates later is executable without a grant of its own).
    let mut statements = support::PROVISIONING.to_vec();
    statements.push(
        "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO davhaven_app",
    );
    statements.push("ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner GRANT EXECUTE ON FUNCTIONS TO davhaven_app");
    let scratch = cluster.empty_database_with(&statements).await;
    let owner = cluster.owner_pool(scratch.name()).await;
    migrate::run_on(&owner).await.expect("the migrations apply");
    let runtime = database(cluster.app_pool(scratch.name(), 2).await);

    // A function that a later migration creates is not executable by the runtime role: the role model took the
    // default privileges on functions away, so a new function that runs with the owner's rights is no way past the
    // privileges of the runtime role. (The helpers of the policies are granted by name.)
    sqlx::raw_sql(
        "CREATE FUNCTION davhaven_probe_definer() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'; \
         CREATE FUNCTION davhaven_probe_plain() RETURNS integer LANGUAGE sql AS 'SELECT 2'",
    )
    .execute(&owner)
    .await
    .unwrap();
    // PUBLIC may execute a new function unless the owner says otherwise; the test is about the runtime role's own
    // grant, so it takes PUBLIC's away first.
    sqlx::raw_sql(
        "REVOKE ALL ON FUNCTION davhaven_probe_definer() FROM PUBLIC; \
         REVOKE ALL ON FUNCTION davhaven_probe_plain() FROM PUBLIC",
    )
    .execute(&owner)
    .await
    .unwrap();
    for (function, expected) in [
        ("davhaven_probe_definer()", false),
        ("davhaven_probe_plain()", false),
        ("davhaven_current_tenant()", true),
        ("davhaven_is_system()", true),
    ] {
        let may: bool =
            sqlx::query_scalar("SELECT has_function_privilege('davhaven_app', $1::regprocedure, 'EXECUTE')")
                .bind(function)
                .fetch_one(&owner)
                .await
                .unwrap();
        assert_eq!(may, expected, "{function}");
    }
    let posture = runtime.posture().await;
    assert!(posture.excess_privileges.is_empty(), "{posture:?}");

    // Whatever function that runs with the owner's rights the runtime role may execute is a finding, not only the
    // purge: a grant by hand, or a function created while the default privileges were still there.
    sqlx::query("GRANT EXECUTE ON FUNCTION davhaven_probe_definer() TO davhaven_app")
        .execute(&owner)
        .await
        .unwrap();
    let posture = runtime.posture().await;
    assert_eq!(
        posture.excess_privileges,
        vec!["EXECUTE on davhaven_probe_definer()".to_owned()]
    );
    assert_eq!(posture.security_findings().len(), 1, "{posture:?}");
    // A function that does not run with the owner's rights is no finding: it holds nothing the role lacks.
    sqlx::query("GRANT EXECUTE ON FUNCTION davhaven_probe_plain() TO davhaven_app")
        .execute(&owner)
        .await
        .unwrap();
    assert_eq!(runtime.posture().await.excess_privileges.len(), 1);
}

#[tokio::test]
async fn a_dedicated_retention_role_keeps_the_purge_when_the_role_model_runs() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // The alternative to the owner's credentials for `davhaven admin purge-audit`: a role that may execute the purge
    // and nothing else (docs/operations/database.md, "Audit log retention"). It holds no default privileges of the
    // owner, so the role model does not count it among the runtime roles and leaves its grant alone.
    let retention = ProbeRole::create(&cluster, "davhaven_retention", "NOSUPERUSER NOBYPASSRLS", &[]).await;
    let db = TestDatabase::create(&cluster).await;
    let owner = cluster.owner_pool(db.name()).await;
    for grant in support::RETENTION_ROLE_GRANTS {
        sqlx::query(sqlx::AssertSqlSafe(grant.to_string()))
            .execute(&owner)
            .await
            .unwrap();
    }

    let report = migrate::run_on(&owner).await.unwrap();
    assert_eq!(report.role_model, RoleModel::Applied { runtime_roles: 1 });
    for (role, expected) in [(retention.name, true), (support::APP, false), (support::OWNER, true)] {
        let may: bool = sqlx::query_scalar(EXECUTES_PURGE)
            .bind(role)
            .fetch_one(&owner)
            .await
            .unwrap();
        assert_eq!(may, expected, "{role}");
    }

    // The role purges the audit log, with the URL of its own in the place of the owner's.
    let config = DatabaseConfig {
        url: Some(SecretString::from(cluster.url_for(support::APP, db.name()))),
        migration_url: Some(SecretString::from(cluster.url_for(retention.name, db.name()))),
        ..DatabaseConfig::default()
    };
    let removed = migrate::purge_audit(&config, chrono::DateTime::UNIX_EPOCH)
        .await
        .expect("the retention role purges");
    assert_eq!(removed, 0, "there is nothing that old");
    // And it can do nothing else with the database: it reads no audit record.
    let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(&cluster.url_for(retention.name, db.name()))
        .await
        .unwrap();
    let refused = sqlx::query("SELECT count(*) FROM audit_events")
        .fetch_one(&mut connection)
        .await
        .expect_err("the retention role reads no audit record");
    assert!(
        matches!(&refused, sqlx::Error::Database(error) if error.code().as_deref() == Some("42501")),
        "{refused}"
    );
}

/// Creates a login role (password equal to its name) for the duration of a test, as the superuser of the cluster.
struct ProbeRole {
    cluster: Cluster,
    name: &'static str,
}

impl ProbeRole {
    async fn create(cluster: &Cluster, name: &'static str, attributes: &str, member_of: &[&str]) -> Self {
        let mut admin = cluster.admin().await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS {name}")))
            .execute(&mut admin)
            .await
            .unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {name} LOGIN PASSWORD '{name}' {attributes}"
        )))
        .execute(&mut admin)
        .await
        .unwrap();
        for parent in member_of {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT {parent} TO {name}")))
                .execute(&mut admin)
                .await
                .unwrap();
        }
        Self {
            cluster: cluster.clone(),
            name,
        }
    }

    /// The database as this role sees it.
    async fn database(&self, database_name: &str) -> PgDatabase {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.cluster.url_for(self.name, database_name))
            .await
            .expect("the probe role connects");
        database(pool)
    }
}

impl Drop for ProbeRole {
    fn drop(&mut self) {
        let cluster = self.cluster.clone();
        let name = self.name;
        let cleanup = std::thread::spawn(move || {
            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                runtime.block_on(async {
                    let mut admin = cluster.admin().await;
                    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS {name}")))
                        .execute(&mut admin)
                        .await;
                });
            }
        });
        let _ = cleanup.join();
    }
}

#[tokio::test]
async fn roles_that_can_bypass_row_level_security_are_unbound_even_when_they_own_nothing() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;

    // Not the owner of anything, but with BYPASSRLS (the rolbypassrls arm of the check).
    let bypass = ProbeRole::create(&cluster, "davhaven_probe_bypass", "NOSUPERUSER BYPASSRLS", &[]).await;
    let posture = bypass.database(db.name()).await.posture().await;
    assert_eq!(
        posture.unbound_role.as_deref(),
        Some("davhaven_probe_bypass"),
        "{posture:?}"
    );

    // A member of the owner role can become the owner (SET ROLE), which row-level security does not bind (the
    // `pg_has_role ... MEMBER` arm, which ADR-0005 names).
    let member = ProbeRole::create(
        &cluster,
        "davhaven_probe_member",
        "NOSUPERUSER NOBYPASSRLS",
        &[support::OWNER],
    )
    .await;
    let posture = member.database(db.name()).await.posture().await;
    assert_eq!(
        posture.unbound_role.as_deref(),
        Some("davhaven_probe_member"),
        "{posture:?}"
    );

    // A member of a role that bypasses row-level security can become it (the recursive membership arm).
    let inheriting = ProbeRole::create(
        &cluster,
        "davhaven_probe_inheriting",
        "NOSUPERUSER NOBYPASSRLS",
        &["davhaven_probe_bypass"],
    )
    .await;
    let posture = inheriting.database(db.name()).await.posture().await;
    assert_eq!(
        posture.unbound_role.as_deref(),
        Some("davhaven_probe_inheriting"),
        "{posture:?}"
    );

    // The proper runtime role is still bound.
    let runtime = database(db.pool().clone()).posture().await;
    assert_eq!(runtime.unbound_role, None, "{runtime:?}");

    // And production refuses each of them at startup, with the role named.
    let mut registry = PluginRegistry::new();
    plugin::register(&mut registry).unwrap();
    for role in [
        "davhaven_probe_bypass",
        "davhaven_probe_member",
        "davhaven_probe_inheriting",
    ] {
        let table = serde_json::json!({
            "url": cluster.url_for(role, db.name()),
            "migrate_on_start": false,
            "allow_insecure_transport": true,
        });
        let tree = ConfigTree::new().with(PLUGIN, table);
        let error = registry
            .build_single(PortKind::DATABASE, PLUGIN, &production(), &tree)
            .await
            .map(|_| ())
            .expect_err("production refuses a role that row-level security does not bind");
        let text = error.to_string();
        assert!(text.contains(role) && text.contains("row-level security"), "{text}");
    }
}

#[tokio::test]
async fn the_posture_does_not_fail_open_when_the_schema_is_not_where_it_looks() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    // The same runtime role, but a connection whose current schema is not `public`: the checks cannot see the
    // tables where they look, which must be a finding, not a clean bill of health.
    let options = cluster.app_options(db.name()).options([("search_path", "pg_catalog")]);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let posture = database(pool).posture().await;
    let unknown = posture.unknown.clone().unwrap_or_default();
    assert!(unknown.contains("public"), "{posture:?}");
    assert_ne!(posture.security_findings().len(), 0);
}

#[tokio::test]
async fn migrations_refuse_a_connection_that_is_not_in_schema_public() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let scratch = cluster.empty_database().await;
    let options = cluster
        .owner_options(scratch.name())
        .options([("search_path", "pg_catalog")]);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let error = migrate::run_on(&pool).await.expect_err("the schema is not public");
    let StoreError::Internal(message) = error else {
        panic!("{error:?}");
    };
    assert!(
        message.contains("schema `public`") && message.contains("search_path"),
        "{message}"
    );
}

#[tokio::test]
async fn migrating_with_the_runtime_role_says_how_to_do_it_right() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let scratch = cluster.empty_database().await;
    // The documented production setup has the runtime role in `url` and no `migration_url`; `migrate_on_start`
    // defaults to true, so the first start meets "permission denied for schema public". The error must say what to do.
    let mut registry = PluginRegistry::new();
    plugin::register(&mut registry).unwrap();
    let table = serde_json::json!({ "url": cluster.url_for(support::APP, scratch.name()) });
    let tree = ConfigTree::new().with(PLUGIN, table);
    let error = registry
        .build_single(PortKind::DATABASE, PLUGIN, &PluginContext::for_tests(), &tree)
        .await
        .map(|_| ())
        .expect_err("the runtime role cannot migrate");
    let text = error.to_string();
    assert!(
        text.contains("migration_url") && text.contains("migrate_on_start"),
        "the error names the owner URL and the switch: {text}"
    );
    assert!(!text.contains("postgres://"), "{text}");
}

#[tokio::test]
async fn soft_deleting_a_large_calendar_runs_under_the_maintenance_timeout() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let name = db.name().to_owned();
    let shared: Arc<dyn Database> = Arc::new(db);
    let world = davhaven_port_tests::store::fixtures::seed(&shared).await.unwrap();

    // A calendar with many objects (written in bulk by the owner, as an import would).
    let mut owner = cluster.owner_connection(&name).await;
    sqlx::query(
        "INSERT INTO calendar_objects (tenant_id, id, calendar_id, owner_id, uri, uid, etag, content_hash, component, \
                                       data, size, first_start, last_end, is_recurring, is_scheduling, sequence, \
                                       class, live, created_at, updated_at, version) \
         SELECT $1, ('00000000-0000-7000-8000-' || lpad(n::text, 12, '0'))::uuid, $2, $3, 'o' || n || '.ics', \
                'uid-' || n, '\"etag\"', 'hash', 'VEVENT', 'BEGIN:VCALENDAR' || repeat('x', 200), 215, \
                now(), now(), false, false, 0, 'PUBLIC', true, now(), now(), 1 \
         FROM generate_series(1, 20000) AS n",
    )
    .bind(world.a.as_uuid())
    .bind(world.shared.as_uuid())
    .bind(world.olivia.as_uuid())
    .execute(&mut owner)
    .await
    .unwrap();
    let version = {
        let mut tx = shared.begin(world.a, TxMode::ReadOnly).await.unwrap();
        tx.calendars().get(world.shared).await.unwrap().version
    };

    // The update of every object row is as large as the calendar: it runs under `maintenance_timeout`, not under
    // the request's `statement_timeout`. With a maintenance limit of one millisecond it cannot finish, which proves
    // which limit applies (and the failed attempt leaves the calendar alone).
    let strict = PgDatabase::from_pool(
        cluster.app_pool(&name, 2).await,
        Arc::new(ManualClock::default()),
        Arc::new(SeqIds::new()),
    )
    .with_maintenance_timeout(std::time::Duration::from_millis(1));
    let mut tx = strict.begin(world.a, TxMode::ReadWrite).await.unwrap();
    assert_eq!(
        tx.calendars().soft_delete(world.shared, version).await,
        Err(StoreError::Timeout),
        "the soft delete of a large calendar runs under the maintenance timeout"
    );
    drop(tx);
    let mut tx = shared.begin(world.a, TxMode::ReadOnly).await.unwrap();
    assert!(
        tx.calendars().get(world.shared).await.is_ok(),
        "the timed-out soft delete changed nothing"
    );
    drop(tx);

    // With the default maintenance timeout (ten minutes) the same soft delete completes.
    let mut tx = shared.begin(world.a, TxMode::ReadWrite).await.unwrap();
    tx.calendars().soft_delete(world.shared, version).await.unwrap();
    tx.commit().await.unwrap();
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM calendar_objects WHERE calendar_id = $1 AND live")
        .bind(world.shared.as_uuid())
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(live, 0, "every object of the deleted calendar stopped being live");
}

#[tokio::test]
async fn an_rsvp_purge_removes_one_batch_and_takes_the_expired_tokens_first() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    cluster.seed(db.name()).await;
    // A batch of expired tokens and three revoked ones, copies of the token of the seed (which expires in 2027 and stays).
    let mut owner = cluster.owner_connection(db.name()).await;
    sqlx::query(
        "INSERT INTO rsvp_tokens (tenant_id, id, object_id, attendee_address, prefix, hash, pepper_kid, expires_at, \
                                  revoked_at, last_used_at, last_response, created_at, updated_at, version) \
         SELECT tenant_id, ('00000000-0000-7000-8000-' || lpad(n::text, 12, '0'))::uuid, object_id, attendee_address, \
                'bulk-' || n, hash, pepper_kid, \
                CASE WHEN n <= 5000 THEN timestamptz '2026-01-01T00:00:00Z' ELSE timestamptz '2030-01-01T00:00:00Z' END, \
                CASE WHEN n <= 5000 THEN NULL ELSE timestamptz '2026-01-01T00:00:00Z' END, \
                NULL, NULL, created_at, updated_at, 1 \
         FROM rsvp_tokens CROSS JOIN generate_series(1, 5003) AS n \
         WHERE id = 'a0000000-0000-7000-8000-000000000014'",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    let cutoff: chrono::DateTime<chrono::Utc> = "2026-06-01T00:00:00Z".parse().unwrap();
    let left = |what: &'static str| format!("SELECT count(*) FROM rsvp_tokens WHERE {what}");

    // One call removes at most one batch (5000 rows), so a retention tick has bounded work: the expired tokens fill it
    // and the revoked ones wait for the next call.
    let shared: Arc<dyn Database> = Arc::new(db);
    for (expected, what) in [(5000, "the expired tokens"), (3, "the revoked tokens"), (0, "nothing")] {
        let mut system = shared.begin_system().await.unwrap();
        let removed = system.retention().purge_rsvp_tokens(cutoff).await.unwrap();
        system.commit().await.unwrap();
        assert_eq!(removed, expected, "a call removes {what}");
        if expected == 5000 {
            let revoked: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(left("revoked_at IS NOT NULL")))
                .fetch_one(&mut owner)
                .await
                .unwrap();
            assert_eq!(revoked, 3, "the revoked tokens are left for the next call");
        }
    }
    let kept: Vec<String> = sqlx::query_scalar("SELECT prefix FROM rsvp_tokens ORDER BY prefix")
        .fetch_all(&mut owner)
        .await
        .unwrap();
    assert_eq!(kept, ["rt-a", "rt-b"], "the tokens of the seed are not due");
}

#[tokio::test]
async fn the_owner_job_purges_the_audit_log_in_batches_until_nothing_old_is_left() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    // More records than one call of the purge function removes (5000), and one that is not old enough.
    sqlx::query(
        "INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at) \
         SELECT 'a0000000-0000-7000-8000-000000000000', ('00000000-0000-7000-8000-' || lpad(n::text, 12, '0'))::uuid, \
                '{\"kind\": \"system\"}', 'tenant.updated', NULL, '{}', \
                CASE WHEN n <= 10007 THEN timestamptz '2026-01-01T00:00:00Z' ELSE timestamptz '2028-01-01T00:00:00Z' END \
         FROM generate_series(1, 10008) AS n",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    let config = config(&cluster, db.name());
    let cutoff: chrono::DateTime<chrono::Utc> = "2027-01-01T00:00:00Z".parse().unwrap();
    assert_eq!(
        migrate::purge_audit(&config, cutoff).await.unwrap(),
        10_007,
        "the job calls the function until a call removes less than a batch"
    );
    let left: Vec<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT at FROM audit_events")
        .fetch_all(&mut owner)
        .await
        .unwrap();
    assert_eq!(
        left,
        ["2028-01-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>().unwrap()]
    );
}

#[tokio::test]
async fn a_connection_that_the_server_ends_is_unavailable() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    // What an administrator's `pg_terminate_backend` and a shutdown of the server look like to the driver: the backend ends
    // with `admin_shutdown`. The application may try again on another connection, so it is no internal error.
    let mut app = cluster.app_connection(db.name()).await;
    let ended = sqlx::query("SELECT pg_terminate_backend(pg_backend_pid())")
        .execute(&mut app)
        .await
        .expect_err("the backend ends");
    assert_eq!(
        ended
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("57P01"),
        "{ended}"
    );
    assert_eq!(map_sqlx(ended), StoreError::Unavailable);
}

#[tokio::test]
async fn an_old_binary_keeps_the_event_types_a_newer_one_wrote() {
    use davhaven_domain::{EventType, TenantId, WebhookId, WebhookSubscription};
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let name = db.name().to_owned();
    let shared: Arc<dyn Database> = Arc::new(db);
    let world = davhaven_port_tests::store::fixtures::seed(&shared).await.unwrap();
    let id = WebhookId::from_uuid(uuid::Uuid::from_u128(0x0190_0000_0001_7000_8000_0000_0000_0777));
    let mut tx = shared.begin(world.a, TxMode::ReadWrite).await.unwrap();
    tx.webhooks()
        .create(WebhookSubscription {
            id,
            tenant_id: TenantId::from_uuid(uuid::Uuid::nil()),
            url: url::Url::parse("https://hooks.example.org/in").unwrap(),
            description: None,
            sealed_secret: vec![1, 2, 3],
            sealed_secret_previous: None,
            secret_rotated_at: None,
            events: vec![EventType::CalendarCreated],
            include_details: false,
            active: true,
            failure_count: 0,
            disabled_reason: None,
            created_at: chrono::DateTime::UNIX_EPOCH,
            updated_at: chrono::DateTime::UNIX_EPOCH,
            version: 1,
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // A newer release subscribed the same webhook to an event type this binary does not know (R16: every released
    // binary runs on the data of the next release).
    let mut owner = cluster.owner_connection(&name).await;
    sqlx::query("UPDATE webhook_subscriptions SET events = events || ARRAY['calendar.future_event']::text[]")
        .execute(&mut owner)
        .await
        .unwrap();

    // This binary reads what it knows, and patching the subscription (a new description) does not remove what it
    // does not know.
    let mut tx = shared.begin(world.a, TxMode::ReadWrite).await.unwrap();
    let mut current = tx.webhooks().get(id).await.unwrap();
    assert_eq!(
        current.events,
        vec![EventType::CalendarCreated],
        "unknown names are not shown"
    );
    current.description = Some("patched by the old binary".to_owned());
    current.events.push(EventType::PrincipalCreated);
    let version = current.version;
    tx.webhooks().update(current, version).await.unwrap();
    tx.commit().await.unwrap();

    let stored: Vec<String> = sqlx::query_scalar("SELECT unnest(events) FROM webhook_subscriptions ORDER BY 1")
        .fetch_all(&mut owner)
        .await
        .unwrap();
    assert_eq!(
        stored,
        ["calendar.created", "calendar.future_event", "principal.created"],
        "the event type of the newer release survived the update, and the new subscription was added"
    );
}

/// The migrations of the initial release only, as a migrator of their own: sqlx applies them without the role model that
/// `migrate::run_on` applies after every run.
fn initial_release() -> sqlx::migrate::Migrator {
    let migrations = migrate::migrator()
        .iter()
        .filter(|migration| migration.version <= INITIAL_SCHEMA)
        .cloned()
        .collect();
    sqlx::migrate::Migrator::with_migrations(migrations)
}

/// The version of the initial schema; the audit purge was granted to nobody but the owner and revoked from PUBLIC.
const INITIAL_SCHEMA: i64 = 20_261_101_120_000;

const EXECUTES_PURGE: &str =
    "SELECT has_function_privilege($1::name, 'davhaven_purge_audit(timestamptz, integer)', 'EXECUTE')";

#[tokio::test]
async fn the_runtime_role_loses_the_audit_purge_however_it_came_by_it() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // What an operator may have set up before the migration: default privileges on functions of the owner (a function
    // that is created afterwards is executable by the runtime role without any grant of its own).
    let mut statements = support::PROVISIONING.to_vec();
    statements.push(
        "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO davhaven_app",
    );
    let scratch = cluster.empty_database_with(&statements).await;
    let owner = cluster.owner_pool(scratch.name()).await;
    initial_release()
        .run(&owner)
        .await
        .expect("the initial release applies");
    assert_eq!(migrate::applied_version(&owner).await.unwrap(), Some(INITIAL_SCHEMA));
    // The migration takes the purge from PUBLIC only, so the default privileges alone already gave it to the runtime role.
    let by_default: bool = sqlx::query_scalar(EXECUTES_PURGE)
        .bind(support::APP)
        .fetch_one(&owner)
        .await
        .unwrap();
    assert!(
        by_default,
        "the default privileges on functions give the runtime role the purge"
    );
    // And the explicit grant of the opt-in (docs/operations/database.md) on top.
    sqlx::query("GRANT EXECUTE ON FUNCTION davhaven_purge_audit(timestamptz, integer) TO davhaven_app")
        .execute(&owner)
        .await
        .unwrap();
    let before: bool = sqlx::query_scalar(EXECUTES_PURGE)
        .bind(support::APP)
        .fetch_one(&owner)
        .await
        .unwrap();
    assert!(before, "the runtime role holds the purge before the role model runs");
    let owner_may: bool = sqlx::query_scalar(EXECUTES_PURGE)
        .bind(support::OWNER)
        .fetch_one(&owner)
        .await
        .unwrap();
    assert!(owner_may, "the owner always may");

    // `davhaven migrate`: the migrations that came after the initial release (none yet), then the role model.
    let report = migrate::run_on(&owner).await.unwrap();
    assert_eq!(report.after, Some(migrate::latest_version()));
    assert_eq!(report.role_model, RoleModel::Applied { runtime_roles: 1 });
    for (role, expected) in [(support::APP, false), (support::OWNER, true)] {
        let may: bool = sqlx::query_scalar(EXECUTES_PURGE)
            .bind(role)
            .fetch_one(&owner)
            .await
            .unwrap();
        assert_eq!(may, expected, "{role} after `davhaven migrate`");
    }
    let public: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a \
                         WHERE p.oid = 'davhaven_purge_audit(timestamptz, integer)'::regprocedure AND a.grantee = 0)",
    )
    .fetch_one(&owner)
    .await
    .unwrap();
    assert!(!public, "nor does PUBLIC");

    // The server stays up on it, and the owner can purge: audit retention runs with the owner credentials.
    let runtime = database(cluster.app_pool(scratch.name(), 2).await);
    let posture = runtime.posture().await;
    assert!(posture.excess_privileges.is_empty(), "{posture:?}");
    let purged: i64 = sqlx::query_scalar("SELECT davhaven_purge_audit(now(), 10)")
        .fetch_one(&owner)
        .await
        .unwrap();
    assert_eq!(purged, 0, "the owner executes the function");
}

#[tokio::test]
async fn the_role_model_is_applied_after_every_migration_run_and_not_only_by_the_first() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let owner = cluster.owner_pool(db.name()).await;
    let runtime = database(db.pool().clone());
    let posture = runtime.posture().await;
    assert!(posture.excess_privileges.is_empty(), "{posture:?}");

    // What the restore of a dump leaves (docs/operations/backup.md): the tables got the default privileges of the
    // owner when they were created, which include writes to the audit log and the migration history, and the grants
    // that the dump itself carries add to them. The functions of the policies may be missing from the grants too.
    for statement in [
        "GRANT UPDATE, DELETE ON audit_events TO davhaven_app",
        "GRANT INSERT, UPDATE, DELETE ON _sqlx_migrations TO davhaven_app",
        "GRANT TRUNCATE, REFERENCES, TRIGGER ON principals TO davhaven_app",
        "REVOKE EXECUTE ON FUNCTION davhaven_current_tenant() FROM davhaven_app",
        // A function is executable by PUBLIC unless its owner says otherwise.
        "REVOKE EXECUTE ON FUNCTION davhaven_current_tenant() FROM PUBLIC",
    ] {
        sqlx::query(statement).execute(&owner).await.unwrap();
    }
    let helper = "SELECT has_function_privilege('davhaven_app', 'davhaven_current_tenant()', 'EXECUTE')";
    let lacks: bool = sqlx::query_scalar(helper).fetch_one(&owner).await.unwrap();
    assert!(!lacks, "the runtime role lacks a helper of the policies before the run");
    let drifted = runtime.posture().await;
    let mut seen = drifted.excess_privileges.clone();
    seen.sort();
    assert_eq!(
        seen,
        [
            "DELETE on _sqlx_migrations",
            "DELETE on audit_events",
            "INSERT on _sqlx_migrations",
            "REFERENCES on principals",
            "TRIGGER on principals",
            "TRUNCATE on principals",
            "UPDATE on _sqlx_migrations",
            "UPDATE on audit_events",
        ],
        "the drift is seen by the posture check, all of it and nothing else"
    );

    // No migration is pending, and the run still puts the privileges right.
    let report = migrate::run_on(&owner).await.unwrap();
    assert!(!report.changed(), "nothing was pending");
    assert_eq!(report.role_model, RoleModel::Applied { runtime_roles: 1 });
    let restored = runtime.posture().await;
    assert!(restored.excess_privileges.is_empty(), "{restored:?}");
    assert!(restored.security_findings().is_empty(), "{restored:?}");
    let helper: bool = sqlx::query_scalar(helper).fetch_one(&owner).await.unwrap();
    assert!(helper, "and the functions the policies call are granted again");
    assert_eq!(Database::health(&runtime).await, Health::Healthy);

    // Applying it again changes nothing.
    assert_eq!(
        migrate::enforce_role_model(&owner).await.unwrap(),
        RoleModel::Applied { runtime_roles: 1 }
    );
    let posture = runtime.posture().await;
    assert!(posture.excess_privileges.is_empty(), "{posture:?}");
}

#[tokio::test]
async fn the_role_model_is_the_business_of_the_owner_only() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    // A role that does not own the tables may not change privileges, and does not try (a server that migrates on
    // start with its own credentials must not fail on it when nothing is pending); the report says that it did not.
    assert_eq!(
        migrate::enforce_role_model(db.pool()).await.unwrap(),
        RoleModel::NotOwner
    );
    let owner = cluster.owner_pool(db.name()).await;
    assert_eq!(
        migrate::enforce_role_model(&owner).await.unwrap(),
        RoleModel::Applied { runtime_roles: 1 }
    );
}

#[tokio::test]
async fn a_migration_role_that_acts_for_the_owner_applies_the_role_model_to_the_runtime_roles_of_the_owner() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // A managed PostgreSQL service often has the migration job log in as a role that is a member of the NOLOGIN role that
    // owns the tables. The default privileges that name the runtime role belong to the owner, not to the member, so the
    // runtime roles are the ones of the owner of the tables and not of the role that runs the statements.
    let migrator = ProbeRole::create(
        &cluster,
        "davhaven_migrator",
        "NOSUPERUSER NOBYPASSRLS",
        &[support::OWNER],
    )
    .await;
    let db = TestDatabase::create(&cluster).await;
    let owner = cluster.owner_pool(db.name()).await;
    sqlx::query("GRANT UPDATE, DELETE ON audit_events TO davhaven_app")
        .execute(&owner)
        .await
        .unwrap();
    let runtime = database(db.pool().clone());
    assert_eq!(runtime.posture().await.excess_privileges.len(), 2);

    let as_member = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&cluster.url_for(migrator.name, db.name()))
        .await
        .expect("the member of the owner role connects");
    assert_eq!(
        migrate::enforce_role_model(&as_member).await.unwrap(),
        RoleModel::Applied { runtime_roles: 1 },
        "the runtime role of the owner is found through the owner's default privileges"
    );
    let posture = runtime.posture().await;
    assert!(
        posture.excess_privileges.is_empty(),
        "and the privileges it holds beyond the role model are taken away: {posture:?}"
    );
}

#[tokio::test]
async fn the_property_batch_read_is_driven_by_the_listed_calendars_and_uses_the_index_of_each_kind() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    cluster.seed(db.name()).await;
    let owner = cluster.owner_pool(db.name()).await;
    // A tenant with many calendars, bindings and properties of both kinds that the read is not asked about: a read that is
    // not driven by the calendars it is asked about reads all of them (`ENGINEERING_RULES` R14).
    sqlx::query(
        "WITH calendar AS ( \
           INSERT INTO calendars (tenant_id, id, owner_id, slug, kind, display_name, description, color, sort_order, \
                                  components, timezone_ics, sync_seq, sync_min_seq, sync_epoch, deleted_at, \
                                  created_at, updated_at, version) \
           SELECT 'a0000000-0000-7000-8000-000000000000', gen_random_uuid(), 'a0000000-0000-7000-8000-000000000001', \
                  'bulk-' || n, 'user', 'Bulk ' || n, NULL, NULL, 0, ARRAY['VEVENT'], NULL, 0, 0, gen_random_uuid(), \
                  NULL, '2026-10-01T12:00:00Z', '2026-10-01T12:00:00Z', 1 \
           FROM generate_series(1, 300) AS n RETURNING id, slug), \
         binding AS ( \
           INSERT INTO calendar_bindings (tenant_id, id, principal_id, calendar_id, slug, display_name, color, \
                                          sort_order, schedule_transp, hidden, created_at, updated_at, version) \
           SELECT 'a0000000-0000-7000-8000-000000000000', gen_random_uuid(), 'a0000000-0000-7000-8000-000000000001', \
                  c.id, c.slug, NULL, NULL, NULL, NULL, false, '2026-10-01T12:00:00Z', '2026-10-01T12:00:00Z', 1 \
           FROM calendar c RETURNING id, calendar_id) \
         INSERT INTO collection_properties (tenant_id, id, calendar_id, binding_id, ns, name, value_xml) \
         SELECT 'a0000000-0000-7000-8000-000000000000', gen_random_uuid(), b.calendar_id, \
                CASE WHEN k % 2 = 0 THEN b.id END, 'urn:test', 'property-' || k, '<x/>' \
         FROM binding b CROSS JOIN generate_series(1, 20) AS k",
    )
    .execute(&owner)
    .await
    .unwrap();
    sqlx::query("ANALYZE collection_properties")
        .execute(&owner)
        .await
        .unwrap();

    // The statement of the repository, as it is sent. A sequential scan is switched off so that the plan shows what the
    // statement is able to use: the index that serves each kind of property, on the calendars that were asked for.
    let statement = include_str!("../src/repos/list_many_properties.sql");
    let mut connection = cluster.owner_connection(db.name()).await;
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "PREPARE list_many(uuid, uuid[], uuid[]) AS {statement}"
    )))
    .execute(&mut connection)
    .await
    .unwrap();
    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (COSTS OFF) EXECUTE list_many('a0000000-0000-7000-8000-000000000000', \
         ARRAY['a0000000-0000-7000-8000-000000000003']::uuid[], ARRAY['a0000000-0000-7000-8000-000000000005']::uuid[])",
    )
    .fetch_all(&mut connection)
    .await
    .unwrap();
    let plan = plan.join("\n");
    for index in ["collection_properties_shared_key", "collection_properties_binding_key"] {
        assert!(plan.contains(index), "the read does not use {index}:\n{plan}");
    }
    assert!(
        !plan.contains("SubPlan"),
        "the read filters the properties of the tenant through a sub-select:\n{plan}"
    );
    // The index condition of every scan of the properties names the calendar: one that names the tenant only reads every
    // property of the tenant, whatever calendars were asked for.
    let lines: Vec<&str> = plan.lines().collect();
    let scans: Vec<usize> = (0..lines.len())
        .filter(|at| {
            lines
                .get(*at)
                .is_some_and(|line| line.contains(" on collection_properties "))
        })
        .collect();
    assert_eq!(scans.len(), 2, "one scan for each kind of property:\n{plan}");
    for scan in scans {
        let condition = lines
            .iter()
            .skip(scan + 1)
            .find(|line| line.contains("Index Cond"))
            .copied()
            .unwrap_or_default();
        assert!(
            condition.contains("calendar_id"),
            "the scan names no calendar in its index condition ({condition}):\n{plan}"
        );
    }
}
