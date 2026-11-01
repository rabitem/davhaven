//! Tenant isolation as the database enforces it: row-level security on every tenant table, the privileges of the
//! runtime role, composite foreign keys and the lifetime of the tenant context. These tests talk SQL to the
//! migrated schema as the runtime role (and as the owner where they probe what only the owner may do); they do not
//! go through the adapter, so they hold for every future code path.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test environment that misbehaves fails the test loudly"
)]

mod support;

use davhaven_domain::TenantId;
use davhaven_ports::{AuditPurge, Database, TxMode};
use davhaven_store_postgres::database::PgDatabase;
use davhaven_store_postgres::migrate;
use sqlx::{Connection, PgConnection, Postgres, Transaction};
use support::{APP, Cluster, TestDatabase};
use uuid::Uuid;

/// The id `<prefix>0000000-0000-7000-8000-0000000000NN` of the seed.
fn sid(prefix: char, n: u8) -> Uuid {
    Uuid::parse_str(&format!("{prefix}0000000-0000-7000-8000-0000000000{n:02}")).expect("a valid uuid")
}

/// A migrated database with the rows of `seed.sql`.
async fn seeded(cluster: &Cluster) -> TestDatabase {
    let db = TestDatabase::create(cluster).await;
    cluster.seed(db.name()).await;
    db
}

/// A transaction of the runtime role; bound to `tenant` when one is given.
async fn as_tenant(db: &TestDatabase, tenant: Option<Uuid>) -> Transaction<'static, Postgres> {
    let mut tx = db.pool().begin().await.expect("a transaction begins");
    if let Some(tenant) = tenant {
        sqlx::query("SELECT set_config('davhaven.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .expect("the tenant is set");
    }
    tx
}

/// A transaction of the runtime role in system scope.
async fn as_system(db: &TestDatabase) -> Transaction<'static, Postgres> {
    let mut tx = db.pool().begin().await.expect("a transaction begins");
    sqlx::query("SELECT set_config('davhaven.system', 'on', true)")
        .execute(&mut *tx)
        .await
        .expect("the system scope is set");
    tx
}

/// The SQLSTATE of a database error (empty for other errors).
fn sqlstate(error: &sqlx::Error) -> String {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

/// The name of the constraint a database error names (empty when it names none).
fn constraint(error: &sqlx::Error) -> String {
    error
        .as_database_error()
        .and_then(|error| error.constraint())
        .map(str::to_owned)
        .unwrap_or_default()
}

/// Every table of the schema that holds tenant data: all of `public` except the migration history.
async fn tenant_tables(connection: &mut PgConnection) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT relname::text FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' \
         AND relname <> '_sqlx_migrations' ORDER BY relname",
    )
    .fetch_all(connection)
    .await
    .expect("the catalog is readable")
}

/// The column that holds the tenant of a row.
fn tenant_column(table: &str) -> &'static str {
    if table == "tenants" { "id" } else { "tenant_id" }
}

/// Counts the rows of `table` that satisfy `condition`, on `connection`.
async fn count(connection: &mut PgConnection, table: &str, condition: &str) -> i64 {
    let counted = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM {table} WHERE {condition}"
    )))
    .fetch_one(connection)
    .await;
    assert!(counted.is_ok(), "counting {table} where {condition}: {counted:?}");
    counted.unwrap()
}

#[tokio::test]
async fn every_tenant_table_has_row_level_security_and_a_policy() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    let tables = tenant_tables(&mut owner).await;
    assert!(tables.len() >= 25, "the schema has {} tenant tables", tables.len());
    for table in &tables {
        let (enabled, policies): (bool, i64) = sqlx::query_as(
            "SELECT c.relrowsecurity, (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) \
             FROM pg_class c WHERE c.oid = ('public.' || quote_ident($1))::regclass",
        )
        .bind(table)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert!(enabled, "row-level security is not enabled on {table}");
        assert!(
            policies >= 1,
            "{table} has no policy, so the runtime role could read nothing from it"
        );
    }
}

#[tokio::test]
async fn the_runtime_role_is_unprivileged() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let mut app = cluster.app_connection(db.name()).await;
    let (superuser, bypass, create_role, create_db, replication): (bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication FROM pg_roles \
         WHERE rolname = current_user",
    )
    .fetch_one(&mut app)
    .await
    .unwrap();
    assert!(
        !superuser && !bypass && !create_role && !create_db && !replication,
        "the runtime role has a privilege it must not have"
    );
    let owned: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM pg_class WHERE relowner = r.oid) \
              + (SELECT count(*) FROM pg_proc WHERE proowner = r.oid) \
              + (SELECT count(*) FROM pg_namespace WHERE nspowner = r.oid) \
         FROM pg_roles r WHERE r.rolname = current_user",
    )
    .fetch_one(&mut app)
    .await
    .unwrap();
    assert_eq!(
        owned, 0,
        "the runtime role owns schema objects, so row-level security would not bind it"
    );
    let may_create: bool = sqlx::query_scalar("SELECT has_schema_privilege(current_user, 'public', 'CREATE')")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert!(!may_create, "the runtime role may create objects in the schema");
    let current: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(current, APP);
}

#[tokio::test]
async fn a_tenant_sees_only_its_own_rows_in_every_table() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    let (a, b) = (sid('a', 0), sid('b', 0));
    for table in tenant_tables(&mut owner).await {
        let column = tenant_column(&table);
        let of_a = count(&mut owner, &table, &format!("{column} = '{a}'")).await;
        let of_b = count(&mut owner, &table, &format!("{column} = '{b}'")).await;
        assert!(
            of_a >= 1 && of_b >= 1,
            "seed.sql has no rows of both tenants in {table}; add them, the isolation test is vacuous without"
        );

        let mut tx = as_tenant(&db, Some(a)).await;
        assert_eq!(
            count(&mut tx, &table, "true").await,
            of_a,
            "tenant a sees {table} of other tenants or misses its own"
        );
        assert_eq!(
            count(&mut tx, &table, &format!("{column} <> '{a}'")).await,
            0,
            "{table} leaks foreign rows"
        );
        drop(tx);

        let mut tx = as_tenant(&db, Some(b)).await;
        assert_eq!(
            count(&mut tx, &table, "true").await,
            of_b,
            "tenant b sees {table} of other tenants or misses its own"
        );
        drop(tx);

        let mut tx = as_tenant(&db, None).await;
        assert_eq!(
            count(&mut tx, &table, "true").await,
            0,
            "{table} is readable without a tenant"
        );
        drop(tx);

        let mut tx = as_tenant(&db, Some(Uuid::nil())).await;
        assert_eq!(
            count(&mut tx, &table, "true").await,
            0,
            "{table} is readable for an unknown tenant"
        );
    }
}

#[tokio::test]
async fn a_malformed_tenant_context_fails_closed() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    for setting in ["", "not-a-uuid", "a0000000-0000-7000-8000-000000000000 OR true"] {
        let mut tx = db.pool().begin().await.unwrap();
        sqlx::query("SELECT set_config('davhaven.tenant_id', $1, true)")
            .bind(setting)
            .execute(&mut *tx)
            .await
            .unwrap();
        let outcome = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM principals")
            .fetch_one(&mut *tx)
            .await;
        match outcome {
            Ok(rows) => assert_eq!(rows, 0, "`{setting}` as tenant shows rows"),
            Err(error) => assert_eq!(
                sqlstate(&error),
                "22P02",
                "`{setting}` fails for another reason: {error}"
            ),
        }
    }
    let mut tx = db.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL row_security = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let refused = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM principals")
        .fetch_one(&mut *tx)
        .await
        .expect_err("switching row security off must not bypass it");
    assert_eq!(sqlstate(&refused), "42501", "{refused}");
}

#[tokio::test]
async fn foreign_rows_cannot_be_written() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    let (a, b) = (sid('a', 0), sid('b', 0));

    // Inserting a row for another tenant violates the policy.
    let mut tx = as_tenant(&db, Some(a)).await;
    let refused = sqlx::query(
        "INSERT INTO principals (tenant_id, id, kind, name, display_name, email, locale, timezone, external_ref, \
                                 status, deleted_at, credential_generation, created_at, updated_at, version) \
         SELECT $1, $2, kind, 'planted', display_name, email, locale, timezone, NULL, status, deleted_at, \
                credential_generation, created_at, updated_at, version \
         FROM principals WHERE id = $3",
    )
    .bind(b)
    .bind(sid('b', 77))
    .bind(sid('a', 1))
    .execute(&mut *tx)
    .await
    .expect_err("a foreign row is refused");
    assert_eq!(sqlstate(&refused), "42501", "{refused}");
    drop(tx);

    // Moving an own row to another tenant violates the policy too.
    let mut tx = as_tenant(&db, Some(a)).await;
    let refused = sqlx::query("UPDATE principals SET tenant_id = $1 WHERE id = $2")
        .bind(b)
        .bind(sid('a', 1))
        .execute(&mut *tx)
        .await
        .expect_err("handing a row to another tenant is refused");
    assert_eq!(sqlstate(&refused), "42501", "{refused}");
    drop(tx);

    // Updating and deleting foreign rows touches nothing.
    let mut tx = as_tenant(&db, Some(a)).await;
    let updated = sqlx::query("UPDATE principals SET display_name = 'hijacked' WHERE tenant_id = $1")
        .bind(b)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 0);
    let deleted = sqlx::query("DELETE FROM principals WHERE tenant_id = $1")
        .bind(b)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(deleted.rows_affected(), 0);
    let deleted = sqlx::query("DELETE FROM calendar_objects WHERE tenant_id = $1")
        .bind(b)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(deleted.rows_affected(), 0);
    tx.commit().await.unwrap();

    let mut owner = cluster.owner_connection(db.name()).await;
    assert_eq!(count(&mut owner, "principals", &format!("tenant_id = '{b}'")).await, 2);
    assert_eq!(
        count(
            &mut owner,
            "principals",
            &format!("tenant_id = '{b}' AND display_name = 'hijacked'")
        )
        .await,
        0
    );
    assert_eq!(
        count(&mut owner, "calendar_objects", &format!("tenant_id = '{b}'")).await,
        1
    );
}

#[tokio::test]
async fn no_tenant_table_takes_a_row_for_another_tenant() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    let (a, b) = (sid('a', 0), sid('b', 0));
    // `foreign_rows_cannot_be_written` shows it for principals; this holds it for every table, so that a table a migration
    // adds without the check of its policy is caught. The planted row is a copy of a row of the tenant with only the tenant
    // changed, and PostgreSQL checks the policy before constraints and keys, so the policy is the only thing that refuses it.
    let before: Vec<i64> = {
        let mut counts = Vec::new();
        for table in tenant_tables(&mut owner).await {
            let column = tenant_column(&table);
            counts.push(count(&mut owner, &table, &format!("{column} = '{b}'")).await);
        }
        counts
    };
    for table in tenant_tables(&mut owner).await {
        if table == "tenants" {
            // A tenant transaction may not write the tenant row at all (`the_tenant_row_is_read_only_for_tenants`).
            continue;
        }
        let column = tenant_column(&table);
        let mut tx = as_tenant(&db, Some(a)).await;
        let planted = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO {table} SELECT (jsonb_populate_record(NULL::{table}, \
             to_jsonb(own) || jsonb_build_object('{column}', $1::uuid))).* FROM {table} own LIMIT 1"
        )))
        .bind(b)
        .execute(&mut *tx)
        .await
        .map(|done| done.rows_affected());
        let refused = planted.expect_err(&format!(
            "a tenant transaction planted a row for another tenant in {table} (or seed.sql has no row of the tenant there)"
        ));
        assert_eq!(sqlstate(&refused), "42501", "{table}: {refused}");
        drop(tx);

        let mut tx = as_tenant(&db, Some(a)).await;
        let handed = sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE {table} SET {column} = $1")))
            .bind(b)
            .execute(&mut *tx)
            .await
            .map(|done| done.rows_affected());
        let refused = handed.expect_err(&format!(
            "a tenant transaction handed its rows of {table} to another tenant"
        ));
        assert_eq!(sqlstate(&refused), "42501", "{table}: {refused}");
    }
    let mut after = Vec::new();
    for table in tenant_tables(&mut owner).await {
        let column = tenant_column(&table);
        after.push(count(&mut owner, &table, &format!("{column} = '{b}'")).await);
    }
    assert_eq!(after, before, "the other tenant's rows are what they were");
}

#[tokio::test]
async fn the_tenant_row_is_read_only_for_tenants() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    let a = sid('a', 0);
    let mut tx = as_tenant(&db, Some(a)).await;
    assert_eq!(count(&mut tx, "tenants", "true").await, 1);
    let updated = sqlx::query("UPDATE tenants SET display_name = 'renamed'")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 0, "a tenant transaction renamed a tenant");
    let deleted = sqlx::query("DELETE FROM tenants").execute(&mut *tx).await.unwrap();
    assert_eq!(deleted.rows_affected(), 0, "a tenant transaction deleted a tenant");
    drop(tx);

    let mut tx = as_tenant(&db, Some(a)).await;
    let refused = sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, login_domain, status, settings, created_at, updated_at, version) \
         VALUES ($1, 'planted', 'Planted', NULL, 'active', '{}', now(), now(), 1)",
    )
    .bind(a)
    .execute(&mut *tx)
    .await
    .expect_err("a tenant transaction creates a tenant");
    assert_eq!(sqlstate(&refused), "42501", "{refused}");
}

/// What the cross-tenant operations of the server may do in system scope, table by table: `*` for every command,
/// otherwise the letters of the commands PostgreSQL records in `pg_policy.polcmd` (`r` SELECT, `a` INSERT, `w` UPDATE,
/// `d` DELETE), in alphabetical order. These are exactly the commands `repos/system.rs` runs; adding a table or a
/// command here is a security decision, so review it. The test below compares the catalog with this list and proves
/// that every other command is refused.
const SYSTEM_SCOPE: &[(&str, &str)] = &[
    // Lookup reads every kind; only system tokens can be created or changed.
    ("api_tokens", "arw"),
    ("app_passwords", "r"),
    // The two audit events of tenant management are appended in the system transaction of the change (and nothing
    // else: the policy names the actions); system scope reads the log (the oldest record of all tenants, for the monitoring
    // of the purge job) but changes and deletes no record.
    ("audit_events", "ar"),
    ("calendars", "rw"),
    ("collection_changes", "adr"),
    ("feed_tokens", "r"),
    ("idempotency_keys", "dr"),
    ("oauth_states", "dr"),
    ("outbox", "drw"),
    ("principals", "r"),
    ("principals_sync", "rw"),
    ("rsvp_tokens", "dr"),
    ("scheduling_inbox", "dr"),
    ("tenants", "*"),
    ("webhook_deliveries", "dr"),
];

/// A command the policies do not allow changed no row: it either found none it may touch, or (for the audit log, whose
/// `UPDATE` and `DELETE` privileges the runtime role does not even have) was refused outright.
fn assert_nothing_changed(table: &str, what: &str, result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>) {
    match result {
        Ok(done) => assert_eq!(done.rows_affected(), 0, "system scope {what} rows of {table}"),
        Err(error) => assert_eq!(sqlstate(&error), "42501", "{table}: {error}"),
    }
}

/// The first column of a table, which an `UPDATE ... SET c = c` can name.
async fn first_column(connection: &mut PgConnection, table: &str) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position LIMIT 1",
    )
    .bind(table)
    .fetch_one(connection)
    .await
    .unwrap()
}

#[expect(clippy::too_many_lines, reason = "one linear script of checks over the pinned list")]
#[tokio::test]
async fn system_scope_reaches_exactly_the_tables_and_commands_the_operations_use() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    let policies: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.relname::text, p.polname::text, p.polcmd::text FROM pg_policy p \
         JOIN pg_class c ON c.oid = p.polrelid WHERE p.polname LIKE 'system_scope%' ORDER BY 1, 2",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    // One policy per command: the name says which, and the catalog agrees.
    let mut by_table: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (table, name, command) in &policies {
        let expected_command = match name.as_str() {
            "system_scope" => "*",
            "system_scope_select" => "r",
            "system_scope_insert" => "a",
            "system_scope_update" => "w",
            "system_scope_delete" => "d",
            other => panic!("{table}: unexpected system policy `{other}`"),
        };
        assert_eq!(command, expected_command, "{table}.{name}");
        by_table.entry(table.clone()).or_default().push_str(command);
    }
    let found: Vec<(String, String)> = by_table
        .into_iter()
        .map(|(table, commands)| {
            let mut letters: Vec<char> = commands.chars().collect();
            letters.sort_unstable();
            (table, letters.into_iter().collect())
        })
        .collect();
    let expected: Vec<(String, String)> = SYSTEM_SCOPE
        .iter()
        .map(|(table, commands)| {
            let mut letters: Vec<char> = commands.chars().collect();
            letters.sort_unstable();
            ((*table).to_owned(), letters.into_iter().collect())
        })
        .collect();
    assert_eq!(found, expected);

    // Reads: system scope sees every row of the tables with a SELECT (or all) policy and nothing of the others.
    let allows = |table: &str, command: char| {
        SYSTEM_SCOPE
            .iter()
            .any(|(name, commands)| *name == table && (commands.contains('*') || commands.contains(command)))
    };
    let mut tx = as_system(&db).await;
    for table in tenant_tables(&mut owner).await {
        let all = count(&mut owner, &table, "true").await;
        let seen = count(&mut tx, &table, "true").await;
        if allows(&table, 'r') {
            assert_eq!(seen, all, "system scope does not see all of {table}");
        } else {
            assert_eq!(seen, 0, "system scope sees {table}, which has no system policy");
        }
    }
    drop(tx);

    // Every table times every command that is not on the list is refused: an UPDATE or DELETE finds no row it may
    // touch, and an INSERT (of a copy of an existing row, so that the only thing that can stop it is the policy)
    // is refused by row-level security (`42501`) wherever the rows can be read at all.
    for table in tenant_tables(&mut owner).await {
        let column = first_column(&mut owner, &table).await;
        if !allows(&table, 'w') {
            let mut tx = as_system(&db).await;
            let result = sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE {table} SET {column} = {column}")))
                .execute(&mut *tx)
                .await;
            assert_nothing_changed(&table, "updated", result);
        }
        if !allows(&table, 'd') {
            let mut tx = as_system(&db).await;
            let result = sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table}")))
                .execute(&mut *tx)
                .await;
            assert_nothing_changed(&table, "deleted", result);
        }
        if !allows(&table, 'a') {
            let mut tx = as_system(&db).await;
            let copied = sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO {table} SELECT * FROM {table}"
            )))
            .execute(&mut *tx)
            .await;
            if allows(&table, 'r') {
                let refused = copied.expect_err(&format!("system scope inserted into {table}"));
                assert_eq!(sqlstate(&refused), "42501", "{table}: {refused}");
            } else {
                assert_eq!(
                    copied.unwrap().rows_affected(),
                    0,
                    "system scope cannot even read {table}, so nothing was copied"
                );
            }
        }
    }

    // The tokens that system scope may create or change are system tokens only (`tenant_id` NULL, kind `system`):
    // it cannot mint or alter a tenant's or a principal's token.
    let mut tx = as_system(&db).await;
    let minted = sqlx::query(
        "INSERT INTO api_tokens (tenant_id, id, kind, principal_id, label, scopes, prefix, hash, pepper_kid, \
                                 allowed_origins, created_at, updated_at, version) \
         SELECT tenant_id, $1, kind, principal_id, label, scopes, 'minted-prefix', hash, pepper_kid, \
                allowed_origins, created_at, updated_at, version FROM api_tokens WHERE tenant_id IS NOT NULL LIMIT 1",
    )
    .bind(sid('a', 79))
    .execute(&mut *tx)
    .await
    .expect_err("system scope mints a tenant token");
    assert_eq!(sqlstate(&minted), "42501", "{minted}");
    drop(tx);
    let mut tx = as_system(&db).await;
    let changed = sqlx::query("UPDATE api_tokens SET label = 'overwritten' WHERE kind <> 'system'")
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(changed, 0, "system scope changed a tenant or principal token");
    drop(tx);
    let mut tx = as_system(&db).await;
    let created = sqlx::query(
        "INSERT INTO api_tokens (tenant_id, id, kind, principal_id, label, scopes, prefix, hash, pepper_kid, \
                                 allowed_origins, created_at, updated_at, version) \
         VALUES (NULL, $1, 'system', NULL, 'system token', '{system:tenants}', 'sys-prefix', '\\x00', 'kid', \
                 '{}', now(), now(), 1)",
    )
    .bind(sid('a', 80))
    .execute(&mut *tx)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(created, 1, "system scope creates system tokens");
    let revoked = sqlx::query("UPDATE api_tokens SET revoked_at = now() WHERE kind = 'system'")
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert!(revoked >= 1, "system scope revokes system tokens");
    drop(tx);

    // The audit log: system scope appends the two events of tenant management for an existing tenant, and cannot
    // append anything else or change or delete a record. It reads the log of every tenant (the monitoring of the purge job
    // asks for the oldest record). The tenant sees its record.
    let existing = count(&mut owner, "audit_events", "true").await;
    assert!(existing >= 2, "the seed has an audit record per tenant ({existing})");
    let mut tx = as_system(&db).await;
    let record_for = |tenant: Uuid, id: Uuid, action: &'static str| {
        sqlx::query(
            "INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at) \
             VALUES ($1, $2, '{\"kind\": \"system\"}', $3, NULL, '{}', '2026-10-02T12:00:00Z')",
        )
        .bind(tenant)
        .bind(id)
        .bind(action)
    };
    let record = |id: Uuid, action: &'static str| record_for(sid('a', 0), id, action);
    for (n, action) in [(60, "tenant.created"), (61, "tenant.settings_changed")] {
        let appended = record(sid('a', n), action)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|error| panic!("system scope appends {action}: {error}"));
        assert_eq!(appended.rows_affected(), 1, "{action}");
    }
    assert_eq!(
        count(&mut tx, "audit_events", "true").await,
        existing + 2,
        "system scope reads every audit record, of every tenant, and the two it appended"
    );
    tx.commit().await.unwrap();
    for (n, action) in [
        (62, "tenant.deleted"),
        (63, "principal.deleted"),
        (64, "credential.created"),
        (65, "keys.rotated"),
        (66, ""),
    ] {
        let mut tx = as_system(&db).await;
        let refused = record(sid('a', n), action)
            .execute(&mut *tx)
            .await
            .expect_err(&format!("system scope appends the action `{action}`"));
        assert_eq!(sqlstate(&refused), "42501", "{action}: {refused}");
    }
    for statement in [
        "UPDATE audit_events SET action = 'tenant.created'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ] {
        let mut tx = as_system(&db).await;
        let refused = sqlx::query(statement).execute(&mut *tx).await;
        assert!(
            refused.is_err_and(|error| sqlstate(&error) == "42501"),
            "system scope may not run `{statement}` on the audit log"
        );
    }
    let mut tx = as_tenant(&db, Some(sid('a', 0))).await;
    let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_events WHERE id = ANY($1) ORDER BY id")
        .bind(vec![sid('a', 60), sid('a', 61)])
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        actions,
        ["tenant.created", "tenant.settings_changed"],
        "the tenant sees what system scope appended"
    );
    drop(tx);
    // The log of a tenant that does not exist gets no record either, whatever the action: the audit log has no foreign
    // key to the tenants, so the policy is what keeps a forged record under an unknown tenant's name out.
    for (n, action) in [(68, "tenant.created"), (69, "tenant.settings_changed")] {
        let mut tx = as_system(&db).await;
        let refused = record_for(sid('f', 0), sid('a', n), action)
            .execute(&mut *tx)
            .await
            .expect_err(&format!(
                "system scope appends {action} to the log of a tenant that does not exist"
            ));
        assert_eq!(sqlstate(&refused), "42501", "{action}: {refused}");
    }
    // Neither does a transaction that is no system scope at all.
    let mut tx = as_tenant(&db, None).await;
    let refused = record(sid('a', 67), "tenant.created")
        .execute(&mut *tx)
        .await
        .expect_err("a transaction without a scope appends an audit record");
    assert_eq!(sqlstate(&refused), "42501", "{refused}");
    drop(tx);

    // Retention may delete old webhook deliveries across tenants, and nothing else about them.
    let mut tx = as_system(&db).await;
    let removed = sqlx::query("DELETE FROM webhook_deliveries")
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert!(removed >= 2, "system scope cannot purge deliveries ({removed} removed)");
    drop(tx);

    // Without the setting, even the tables with a system policy are empty.
    let mut tx = as_tenant(&db, None).await;
    assert_eq!(count(&mut tx, "tenants", "true").await, 0);
    // The setting is a plain string: anything but `on` is no system scope.
    sqlx::query("SELECT set_config('davhaven.system', 'yes', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(count(&mut tx, "tenants", "true").await, 0);
}

#[tokio::test]
async fn the_tenant_context_does_not_outlive_its_transaction() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // One connection: every transaction below runs on the connection the previous one used.
    let db = TestDatabase::with_pool_size(&cluster, 1).await;
    cluster.seed(db.name()).await;
    let a = TenantId::from_uuid(sid('a', 0));

    let mut committed = db.begin(a, TxMode::ReadWrite).await.unwrap();
    assert_eq!(
        committed
            .principals()
            .get(sid('a', 1).into())
            .await
            .unwrap()
            .name
            .as_str(),
        "alice"
    );
    committed.commit().await.unwrap();
    assert_nothing_is_visible(&db, "after a commit").await;

    let rolled_back = db.begin(a, TxMode::ReadOnly).await.unwrap();
    drop(rolled_back);
    assert_nothing_is_visible(&db, "after a rollback").await;

    let mut system = db.begin_system().await.unwrap();
    assert_eq!(
        system
            .tenants()
            .list(davhaven_ports::PageReq::default())
            .await
            .unwrap()
            .items
            .len(),
        2
    );
    system.commit().await.unwrap();
    assert_nothing_is_visible(&db, "after a system transaction").await;
}

/// On the (only) connection of the pool, neither tenant data nor the system tables are visible, and no setting
/// is left over.
async fn assert_nothing_is_visible(db: &TestDatabase, when: &str) {
    let tenants: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let principals: i64 = sqlx::query_scalar("SELECT count(*) FROM principals")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!((tenants, principals), (0, 0), "rows are visible {when}");
    let leftover: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT unnest(ARRAY[current_setting('davhaven.tenant_id', true), current_setting('davhaven.system', true)])",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    for setting in leftover {
        assert!(
            setting.is_none_or(|value| value.is_empty()),
            "a setting is left over {when}"
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one table of statements, one entry per foreign key"
)]
#[tokio::test]
async fn composite_foreign_keys_keep_references_inside_the_tenant() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    // The owner is not subject to row-level security, so only the keys can refuse these statements.
    let mut owner = cluster.owner_connection(db.name()).await;
    let a = sid('a', 0);

    let cases: Vec<(&str, String, &str)> = vec![
        (
            "an object in a calendar of another tenant",
            format!(
                "INSERT INTO calendar_objects (tenant_id, id, calendar_id, owner_id, uri, uid, etag, schedule_tag, \
                   content_hash, component, data, size, first_start, last_end, is_recurring, is_scheduling, \
                   organizer_address, sequence, class, external_key, origin, live, created_at, updated_at, version) \
                 SELECT tenant_id, '{}', '{}', owner_id, 'cross.ics', 'cross', etag, schedule_tag, content_hash, \
                   component, data, size, first_start, last_end, is_recurring, false, organizer_address, sequence, \
                   class, NULL, origin, live, created_at, updated_at, version \
                 FROM calendar_objects WHERE tenant_id = '{a}' AND id = '{}'",
                sid('a', 50),
                sid('b', 3),
                sid('a', 4)
            ),
            "calendar_objects_calendar_fkey",
        ),
        (
            "a calendar owned by a principal of another tenant",
            format!(
                "UPDATE calendars SET owner_id = '{}' WHERE tenant_id = '{a}' AND id = '{}'",
                sid('b', 1),
                sid('a', 3)
            ),
            "calendars_owner_fkey",
        ),
        (
            "a binding of a principal of another tenant",
            format!(
                "UPDATE calendar_bindings SET principal_id = '{}' WHERE tenant_id = '{a}' AND id = '{}'",
                sid('b', 1),
                sid('a', 5)
            ),
            "calendar_bindings_principal_fkey",
        ),
        (
            "a binding of a calendar of another tenant",
            format!(
                "UPDATE calendar_bindings SET calendar_id = '{}' WHERE tenant_id = '{a}' AND id = '{}'",
                sid('b', 3),
                sid('a', 5)
            ),
            "calendar_bindings_calendar_fkey",
        ),
        (
            "a property of a binding that belongs to another calendar",
            format!(
                "UPDATE collection_properties SET binding_id = '{}', calendar_id = '{}' \
                 WHERE tenant_id = '{a}' AND id = '{}'",
                sid('a', 5),
                sid('a', 21),
                sid('a', 6)
            ),
            "collection_properties_binding_fkey",
        ),
        (
            "an attendee who resolves to a principal of another tenant",
            format!(
                "UPDATE object_attendees SET principal_id = '{}' WHERE tenant_id = '{a}' AND object_id = '{}'",
                sid('b', 1),
                sid('a', 4)
            ),
            "object_attendees_principal_fkey",
        ),
        (
            "a member of another tenant",
            format!(
                "INSERT INTO memberships (tenant_id, group_id, member_id) VALUES ('{a}', '{}', '{}')",
                sid('a', 2),
                sid('b', 1)
            ),
            "memberships_member_fkey",
        ),
        (
            "a grant to a principal of another tenant",
            format!(
                "UPDATE calendar_grants SET grantee_id = '{}' WHERE tenant_id = '{a}' AND id = '{}'",
                sid('b', 1),
                sid('a', 7)
            ),
            "calendar_grants_grantee_fkey",
        ),
        (
            "a mirror calendar of another tenant",
            format!(
                "UPDATE external_accounts SET mirror_calendar_id = '{}' WHERE tenant_id = '{a}' AND id = '{}'",
                sid('b', 3),
                sid('a', 15)
            ),
            "external_accounts_calendar_fkey",
        ),
        (
            "a delivery of a subscription of another tenant",
            format!(
                "UPDATE webhook_deliveries SET subscription_id = '{}' WHERE tenant_id = '{a}' AND id = '{}'",
                sid('b', 17),
                sid('a', 18)
            ),
            "webhook_deliveries_subscription_fkey",
        ),
        (
            "an RSVP token of an object of another tenant",
            format!(
                "UPDATE rsvp_tokens SET object_id = '{}' WHERE tenant_id = '{a}' AND id = '{}'",
                sid('b', 4),
                sid('a', 14)
            ),
            "rsvp_tokens_object_fkey",
        ),
        (
            "an outbox message of a tenant that does not exist",
            format!(
                "INSERT INTO outbox (tenant_id, id, kind, payload, schema_version, status, attempts, \
                   next_attempt_at, created_at, updated_at) \
                 VALUES ('{}', '{}', 'x', '{{}}', 1, 'pending', 0, now(), now(), now())",
                Uuid::nil(),
                sid('b', 60)
            ),
            "outbox_tenant_id_fkey",
        ),
    ];
    for (what, statement, expected) in cases {
        let refused = sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut owner)
            .await
            .expect_err(what);
        assert_eq!(sqlstate(&refused), "23503", "{what}: {refused}");
        assert_eq!(constraint(&refused), expected, "{what}");
    }
}

#[tokio::test]
async fn every_foreign_key_between_tenant_tables_includes_the_tenant() {
    /// A foreign key: its name, its table, the table it references and the columns of both sides in key order.
    type ForeignKey = (String, String, String, Vec<String>, Vec<String>);
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    // The table above refuses one statement per key it knows; this reads every foreign key of the schema, so that a key a
    // migration adds is held to the same rule (R4): a key to a tenant table pairs the tenant column of both sides, so a row
    // can only ever reference a row of its own tenant. A key to `tenants` is the tenant column itself.
    let keys: Vec<ForeignKey> = sqlx::query_as(
        "SELECT c.conname::text, c.conrelid::regclass::text, c.confrelid::regclass::text, \
                ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(n, o) \
                      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n ORDER BY k.o), \
                ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(n, o) \
                      JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n ORDER BY k.o) \
         FROM pg_constraint c WHERE c.contype = 'f' AND c.connamespace = 'public'::regnamespace ORDER BY 1",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert!(keys.len() >= 25, "the schema has {} foreign keys", keys.len());
    let mut violations = Vec::new();
    for (name, table, target, columns, referenced) in &keys {
        // The token that minted an API token may be a system token, which has no tenant (the comment on the table).
        if name == "api_tokens_created_by_fkey" {
            assert_eq!(
                (
                    table.as_str(),
                    target.as_str(),
                    columns.as_slice(),
                    referenced.as_slice()
                ),
                (
                    "api_tokens",
                    "api_tokens",
                    ["created_by".to_owned()].as_slice(),
                    ["id".to_owned()].as_slice()
                )
            );
            continue;
        }
        let paired = if target == "tenants" {
            columns.as_slice() == [tenant_column(table)] && referenced.as_slice() == ["id"]
        } else {
            columns.first().map(String::as_str) == Some(tenant_column(table))
                && referenced.first().map(String::as_str) == Some(tenant_column(target))
        };
        if !paired {
            violations.push(format!("{name}: {table} {columns:?} -> {target} {referenced:?}"));
        }
    }
    assert!(
        violations.is_empty(),
        "foreign keys that can reference a row of another tenant: {violations:?}"
    );
}

#[tokio::test]
async fn deleting_a_tenant_removes_everything_it_owns_but_its_audit_trail() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    let (a, b) = (sid('a', 0), sid('b', 0));
    // Calendars, objects, bindings, credentials and the rest hang off the tenant through cascading keys; the change
    // log has no key on its collection and relies on the tenant key; the audit log has none on purpose.
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(a)
        .execute(&mut owner)
        .await
        .unwrap();
    for table in tenant_tables(&mut owner).await {
        let column = tenant_column(&table);
        let left = count(&mut owner, &table, &format!("{column} = '{a}'")).await;
        if table == "audit_events" {
            assert_eq!(
                left, 1,
                "the audit trail of a deleted tenant is kept for retention to remove"
            );
        } else {
            assert_eq!(left, 0, "{table} keeps rows of a deleted tenant");
        }
        assert!(
            count(&mut owner, &table, &format!("{column} = '{b}'")).await >= 1,
            "{table} lost rows of another tenant"
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear script of statements and their refusals"
)]
#[tokio::test]
async fn the_audit_log_is_append_only_and_the_runtime_role_cannot_purge_it() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    let a = sid('a', 0);

    // Privileges as the catalog states them.
    let mut owner = cluster.owner_connection(db.name()).await;
    for (privilege, expected) in [
        ("SELECT", true),
        ("INSERT", true),
        ("UPDATE", false),
        ("DELETE", false),
        ("TRUNCATE", false),
        ("REFERENCES", false),
        ("TRIGGER", false),
    ] {
        let granted: bool = sqlx::query_scalar("SELECT has_table_privilege($1::name, 'audit_events', $2)")
            .bind(APP)
            .bind(privilege)
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert_eq!(granted, expected, "{privilege} on audit_events for the runtime role");
    }

    // A tenant transaction appends and reads its own records.
    let mut tx = as_tenant(&db, Some(a)).await;
    sqlx::query(
        "INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at) \
         VALUES ($1, $2, '{\"kind\": \"system\"}', 'tenant.updated', NULL, '{}', '2026-10-02T12:00:00Z')",
    )
    .bind(a)
    .bind(sid('a', 50))
    .execute(&mut *tx)
    .await
    .unwrap();
    assert_eq!(count(&mut tx, "audit_events", "true").await, 2);
    tx.commit().await.unwrap();

    // It cannot append for another tenant, and cannot change or remove what exists.
    let mut tx = as_tenant(&db, Some(a)).await;
    let refused = sqlx::query(
        "INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at) \
         VALUES ($1, $2, '{}', 'tenant.updated', NULL, '{}', now())",
    )
    .bind(sid('b', 0))
    .bind(sid('b', 51))
    .execute(&mut *tx)
    .await
    .expect_err("an audit record for another tenant is refused");
    assert_eq!(sqlstate(&refused), "42501", "{refused}");
    drop(tx);
    for statement in [
        "UPDATE audit_events SET action = 'tenant.deleted'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ] {
        let mut tx = as_tenant(&db, Some(a)).await;
        let refused = sqlx::query(statement).execute(&mut *tx).await.expect_err(statement);
        assert_eq!(sqlstate(&refused), "42501", "{statement}: {refused}");
    }

    // The purge function is not granted to the runtime role: a compromised server cannot wipe the trail of every
    // tenant with one call, whatever the cut-off.
    let executable: bool = sqlx::query_scalar(
        "SELECT has_function_privilege($1::name, 'davhaven_purge_audit(timestamptz, integer)', 'EXECUTE')",
    )
    .bind(APP)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(!executable, "the runtime role may execute davhaven_purge_audit");
    let refused = sqlx::query_scalar::<_, i64>("SELECT davhaven_purge_audit('infinity', 2147483647)")
        .fetch_one(db.pool())
        .await
        .expect_err("the runtime role purges the audit log");
    assert_eq!(sqlstate(&refused), "42501", "{refused}");
    let cutoff: chrono::DateTime<chrono::Utc> = "2027-01-01T00:00:00Z".parse().unwrap();
    // Through the adapter, the missing grant is a state of the deployment, not an error: the plain purge removes
    // nothing, and the checked one says that it was not permitted (the retention worker skips the step instead of
    // reporting an internal error every tick; readiness reports it, see `migrations.rs`).
    let (plain, checked) = {
        let mut system = db.begin_system().await.unwrap();
        let plain = system.retention().purge_audit(cutoff).await;
        let checked = system.retention().purge_audit_checked(cutoff).await;
        (plain, checked)
    };
    assert_eq!(
        plain,
        Ok(0),
        "the adapter's audit purge removes nothing without the grant"
    );
    assert_eq!(checked, Ok(AuditPurge::NotPermitted));
    assert_eq!(
        count(&mut owner, "audit_events", &format!("at < '{cutoff}'")).await,
        3,
        "nothing was deleted"
    );

    // The owner can: retention as a scheduled job with the migration credentials.
    let removed: i64 = sqlx::query_scalar("SELECT davhaven_purge_audit($1, 2)")
        .bind(cutoff)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(removed, 2, "the function takes at most the batch size");
    let removed: i64 = sqlx::query_scalar("SELECT davhaven_purge_audit($1, 100)")
        .bind(cutoff)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(removed, 1);
    assert_eq!(count(&mut owner, "audit_events", "true").await, 0);

    // Nobody else may call it.
    let public: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a \
         WHERE p.proname = 'davhaven_purge_audit' AND a.grantee = 0",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(public, 0, "PUBLIC may execute the audit retention function");
}

#[tokio::test]
async fn system_scope_reads_the_oldest_audit_event_of_all_tenants_and_the_index_can_answer_it() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = seeded(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    let parse = |text: &str| -> chrono::DateTime<chrono::Utc> { text.parse().unwrap() };
    let (a, b) = (sid('a', 0), sid('b', 0));
    // The oldest record is in the log of the second tenant and has microseconds, the next one in the first tenant's.
    let (oldest, older, newer) = (
        parse("2020-02-29T00:00:00.000001Z"),
        parse("2024-12-31T23:59:59.123456Z"),
        parse("2027-01-01T00:00:00Z"),
    );
    for (tenant, n, at) in [(a, 70, older), (b, 71, oldest), (a, 72, newer)] {
        sqlx::query(
            "INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at) \
             VALUES ($1, $2, '{\"kind\": \"system\"}', 'tenant.created', NULL, '{}', $3)",
        )
        .bind(tenant)
        .bind(sid('a', n))
        .bind(at)
        .execute(&mut owner)
        .await
        .unwrap();
    }

    // Through the adapter, as the runtime role: the oldest record of all tenants, at the precision of the column.
    let mut system = db.begin_system().await.unwrap();
    assert_eq!(system.retention().oldest_audit_at().await, Ok(Some(oldest)));
    drop(system);

    // Only system scope reads across tenants: a tenant transaction sees the oldest record of its own log, and a
    // transaction without a scope sees none.
    let mut tx = as_tenant(&db, Some(a)).await;
    let own: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT at FROM audit_events ORDER BY at LIMIT 1")
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
    assert_ne!(own, Some(oldest), "a tenant reads the log of another tenant");
    assert!(own.is_some_and(|at| at <= older), "the tenant reads its own log");
    drop(tx);
    let mut tx = as_tenant(&db, None).await;
    assert_eq!(count(&mut tx, "audit_events", "true").await, 0);
    drop(tx);

    // The index can answer the statement of the adapter: with sequential scans turned off (a log of a handful of rows would be read
    // by a scan otherwise; on a large log the planner prefers the index for an ordered read of one row), the plan is a scan of
    // `audit_events_at_idx`. This pins that the index serves the query, not what the planner picks on every size of table.
    let mut tx = as_system(&db).await;
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar("EXPLAIN (COSTS OFF) SELECT at FROM audit_events ORDER BY at LIMIT 1")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("Index Scan") && line.contains("audit_events_at_idx")),
        "{plan:?}"
    );
    drop(tx);

    // An empty log has no oldest record.
    sqlx::query("DELETE FROM audit_events")
        .execute(&mut owner)
        .await
        .unwrap();
    let mut system = db.begin_system().await.unwrap();
    assert_eq!(system.retention().oldest_audit_at().await, Ok(None));
}

#[tokio::test]
async fn an_operator_can_let_the_server_purge_the_audit_log_explicitly() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // The documented opt-in: `GRANT EXECUTE` on the function, for operators who run retention from the server.
    let db = TestDatabase::create_with_audit_purge(&cluster).await;
    cluster.seed(db.name()).await;
    let cutoff: chrono::DateTime<chrono::Utc> = "2027-01-01T00:00:00Z".parse().unwrap();
    let mut system = db.begin_system().await.unwrap();
    assert_eq!(
        system.retention().purge_audit_checked(cutoff).await.unwrap(),
        AuditPurge::Purged(2),
        "the seed has one audit record per tenant"
    );
    system.commit().await.unwrap();
    let mut owner = cluster.owner_connection(db.name()).await;
    assert_eq!(count(&mut owner, "audit_events", "true").await, 0);

    // And the grant can be taken back at any time.
    sqlx::query("REVOKE EXECUTE ON FUNCTION davhaven_purge_audit(timestamptz, integer) FROM davhaven_app")
        .execute(&mut owner)
        .await
        .unwrap();
    let refused = sqlx::query_scalar::<_, i64>("SELECT davhaven_purge_audit($1, 1)")
        .bind(cutoff)
        .fetch_one(db.pool())
        .await
        .expect_err("a revoked grant is gone");
    assert_eq!(sqlstate(&refused), "42501", "{refused}");
}

#[tokio::test]
async fn the_owner_job_purges_the_audit_log_for_a_server_that_may_not() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // The recommended setup: no grant for the runtime role. `davhaven admin purge-audit` runs
    // `migrate::purge_audit` with the owner credentials (`migration_url`) on a schedule.
    let db = seeded(&cluster).await;
    let config = davhaven_store_postgres::config::DatabaseConfig {
        url: Some(secrecy::SecretString::from(cluster.url_for(support::APP, db.name()))),
        migration_url: Some(secrecy::SecretString::from(cluster.url_for(support::OWNER, db.name()))),
        ..davhaven_store_postgres::config::DatabaseConfig::default()
    };
    let mut owner = cluster.owner_connection(db.name()).await;
    let before = count(&mut owner, "audit_events", "true").await;
    assert!(before >= 2, "the seed has an audit record per tenant ({before})");

    let nothing_old_enough: chrono::DateTime<chrono::Utc> = "2000-01-01T00:00:00Z".parse().unwrap();
    assert_eq!(migrate::purge_audit(&config, nothing_old_enough).await.unwrap(), 0);
    assert_eq!(count(&mut owner, "audit_events", "true").await, before);

    let cutoff: chrono::DateTime<chrono::Utc> = "2027-01-01T00:00:00Z".parse().unwrap();
    assert_eq!(
        migrate::purge_audit(&config, cutoff).await.unwrap(),
        u64::try_from(before).unwrap(),
        "the job removes everything older than the cut-off"
    );
    assert_eq!(count(&mut owner, "audit_events", "true").await, 0);

    // With the runtime role's credentials the job is refused: the function is the owner's.
    let runtime_only = davhaven_store_postgres::config::DatabaseConfig {
        url: Some(secrecy::SecretString::from(cluster.url_for(support::APP, db.name()))),
        ..davhaven_store_postgres::config::DatabaseConfig::default()
    };
    let refused = migrate::purge_audit(&runtime_only, cutoff)
        .await
        .expect_err("the runtime role may not purge");
    assert!(!refused.to_string().contains("postgres://"), "{refused}");
}

#[tokio::test]
async fn the_runtime_role_cannot_change_the_schema_or_its_history() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let mut app = cluster.app_connection(db.name()).await;

    // The migration history is readable (readiness) and nothing else.
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert!(applied >= 1);
    for statement in [
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (1, 'forged', true, '\\x00', 0)",
        "UPDATE _sqlx_migrations SET success = false",
        "DELETE FROM _sqlx_migrations",
        "TRUNCATE _sqlx_migrations",
        "CREATE TABLE intruder (id integer)",
        "ALTER TABLE principals DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE principals NO FORCE ROW LEVEL SECURITY",
        "DROP POLICY tenant_isolation ON principals",
        "CREATE POLICY open ON principals USING (true)",
        "DROP TABLE principals",
        "ALTER TABLE principals ADD COLUMN extra integer",
        "CREATE OR REPLACE FUNCTION davhaven_current_tenant() RETURNS uuid LANGUAGE sql AS 'SELECT NULL::uuid'",
        "ALTER ROLE davhaven_app BYPASSRLS",
        "SET ROLE davhaven_owner",
    ] {
        let refused = sqlx::query(statement).execute(&mut app).await.expect_err(statement);
        assert_eq!(sqlstate(&refused), "42501", "{statement}: {refused}");
        // A failed statement outside a transaction leaves the connection usable.
        let healthy: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&mut app).await.unwrap();
        assert_eq!(healthy, 1);
    }
    app.close().await.unwrap();
}

#[tokio::test]
async fn the_runtime_role_has_data_access_to_every_tenant_table_through_default_privileges() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let db = TestDatabase::create(&cluster).await;
    let mut owner = cluster.owner_connection(db.name()).await;
    let mut missing = Vec::new();
    let mut excess = Vec::new();
    for table in tenant_tables(&mut owner).await {
        // TRUNCATE bypasses row-level security, REFERENCES and TRIGGER have no use at runtime.
        for privilege in ["TRUNCATE", "REFERENCES", "TRIGGER"] {
            let granted: bool = sqlx::query_scalar("SELECT has_table_privilege($1::name, $2::text, $3::text)")
                .bind(APP)
                .bind(format!("public.{table}"))
                .bind(privilege)
                .fetch_one(&mut owner)
                .await
                .unwrap();
            if granted {
                excess.push(format!("{privilege} on {table}"));
            }
        }
        for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
            if table == "audit_events" && (privilege == "UPDATE" || privilege == "DELETE") {
                continue;
            }
            let granted: bool = sqlx::query_scalar("SELECT has_table_privilege($1::name, $2::text, $3::text)")
                .bind(APP)
                .bind(format!("public.{table}"))
                .bind(privilege)
                .fetch_one(&mut owner)
                .await
                .unwrap();
            if !granted {
                missing.push(format!("{privilege} on {table}"));
            }
        }
    }
    assert!(missing.is_empty(), "the runtime role lacks: {missing:?}");
    assert!(
        excess.is_empty(),
        "the runtime role holds privileges it must not have: {excess:?}"
    );
}

/// The provisioning of a careless operator: every privilege on every future table for the runtime role.
const GRANT_ALL: &[&str] = &[
    "REVOKE ALL ON SCHEMA public FROM PUBLIC",
    "ALTER SCHEMA public OWNER TO davhaven_owner",
    "GRANT USAGE ON SCHEMA public TO davhaven_app",
    "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT ALL ON TABLES TO davhaven_app",
    "ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO davhaven_app",
];

/// The privileges the role model withholds, as `privilege on object` texts, for the runtime role of `database`.
async fn withheld_privileges(cluster: &Cluster, database: &str) -> Vec<String> {
    let mut owner = cluster.owner_connection(database).await;
    let mut held = Vec::new();
    for (table, privilege) in [
        ("audit_events", "UPDATE"),
        ("audit_events", "DELETE"),
        ("audit_events", "TRUNCATE"),
        ("_sqlx_migrations", "INSERT"),
        ("_sqlx_migrations", "UPDATE"),
        ("_sqlx_migrations", "DELETE"),
        ("_sqlx_migrations", "TRUNCATE"),
        ("principals", "TRUNCATE"),
        ("calendar_objects", "TRUNCATE"),
        ("principals", "REFERENCES"),
        ("principals", "TRIGGER"),
    ] {
        let granted: bool = sqlx::query_scalar("SELECT has_table_privilege($1::name, $2::text, $3::text)")
            .bind(APP)
            .bind(format!("public.{table}"))
            .bind(privilege)
            .fetch_one(&mut owner)
            .await
            .unwrap();
        if granted {
            held.push(format!("{privilege} on {table}"));
        }
    }
    held
}

/// The runtime pool of a migrated scratch database, as the server would connect.
async fn migrated(cluster: &Cluster, statements: &[&'static str]) -> (support::Scratch, PgDatabase) {
    let scratch = cluster.empty_database_with(statements).await;
    let owner = cluster.owner_pool(scratch.name()).await;
    migrate::run_on(&owner).await.expect("the owner migrates");
    let runtime = cluster.app_pool(scratch.name(), 2).await;
    let database = PgDatabase::from_pool(
        runtime,
        std::sync::Arc::new(davhaven_ports::testing::ManualClock::default()),
        std::sync::Arc::new(davhaven_ports::testing::SeqIds::new()),
    );
    (scratch, database)
}

#[tokio::test]
async fn the_migration_takes_back_what_a_blanket_grant_gave_the_runtime_role() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (scratch, database) = migrated(&cluster, GRANT_ALL).await;
    assert_eq!(
        withheld_privileges(&cluster, scratch.name()).await,
        Vec::<String>::new(),
        "default privileges that grant everything leave the runtime role with more than the role model allows"
    );
    let posture = database.posture().await;
    assert!(posture.security_findings().is_empty(), "{posture:?}");
}

#[tokio::test]
async fn default_privileges_in_every_schema_give_the_same_role_model() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // The other spelling of the provisioning (no `IN SCHEMA`): the migration's role block finds it as well.
    let (scratch, database) = migrated(&cluster, support::PROVISIONING_GLOBAL).await;
    assert_eq!(
        withheld_privileges(&cluster, scratch.name()).await,
        Vec::<String>::new()
    );
    let mut owner = cluster.owner_connection(scratch.name()).await;
    for function in ["davhaven_current_tenant()", "davhaven_is_system()"] {
        let granted: bool = sqlx::query_scalar("SELECT has_function_privilege($1::name, $2::text, 'EXECUTE')")
            .bind(APP)
            .bind(function)
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert!(granted, "the runtime role cannot execute {function}");
    }
    let posture = database.posture().await;
    assert!(posture.security_findings().is_empty(), "{posture:?}");
}

#[test]
fn the_documented_provisioning_is_what_the_tests_run() {
    /// Collapses whitespace so that a statement printed over several lines compares equal.
    fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    let documentation = flat(include_str!("../../../docs/operations/database.md"));
    for statement in support::PROVISIONING.iter().chain(support::RETENTION_ROLE_GRANTS) {
        assert!(
            documentation.contains(&format!("{};", flat(statement))),
            "docs/operations/database.md does not print the statement the tests run: {statement}"
        );
    }
}
