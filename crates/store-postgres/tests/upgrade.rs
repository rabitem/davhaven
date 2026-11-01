//! The upgrade test (PLAN 3.6, `ENGINEERING_RULES` R16): the schema of a previous release, filled with fixture rows,
//! is migrated to the current schema and then read - and written - through the adapter.
//!
//! Every file `tests/upgrade/<version>.sql` holds the standard dataset (see the file header) in the schema of the
//! release whose newest migration is `<version>`. For every fixture the test
//!
//! 1. creates a database with the privilege setup of production,
//! 2. applies the migrations up to `<version>` as the owner,
//! 3. runs the fixture as the owner,
//! 4. applies all later migrations,
//! 5. reads the dataset back as the runtime role through the repositories and checks every fact of it, and
//! 6. writes to it, continuing the sequence numbers and the sync tokens of the old data.
//!
//! A migration PR therefore proves that data written by the previous release is still read correctly. Fixtures are
//! never edited; when a release changes the shape of the data it adds a fixture for its own schema.
//!
//! The same file proves the restore of docs/operations/backup.md: every `tests/restore/<version>.sql` is a plain
//! `pg_dump` of the database of that release (with the dataset in it). The test creates a database with the privilege
//! setup of production, restores the dump into it **as the owner role** (`SET ROLE`, which is what `pg_restore --no-owner
//! --role=<owner>` does), migrates, starts the server on it in production mode and reads the dataset back. A dump
//! is never edited either; a release that changes the schema adds a dump of its own.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test environment that misbehaves fails the test loudly"
)]

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use davhaven_domain::{
    CalendarId, CalendarSlug, CalendarUserAddress, CollectionKey, CollectionKind, CredentialKind, DomainName,
    GrantAccess, GrantSource, GrantStatus, ObjectUri, PrincipalId, PrincipalName, TenantId, TenantSlug, TenantStatus,
};
use davhaven_port_tests::store::fixtures::version;
use davhaven_ports::outbox::OutboxStatus;
use davhaven_ports::testing::{FixedHasher, FixedKeyRing, PlainSealer};
use davhaven_ports::testing::{ManualClock, SeqIds};
use davhaven_ports::{AuditFilter, ChangeKind, Database, Expected, Health, InboxScope, PageReq, PropertyScope, TxMode};
use davhaven_ports::{ConfigTree, PluginContext, PluginRegistry, PortKind, RunMode};
use davhaven_store_postgres::config::PLUGIN;
use davhaven_store_postgres::database::PgDatabase;
use davhaven_store_postgres::migrate;
use davhaven_store_postgres::migrate::RoleModel;
use davhaven_store_postgres::plugin;
use sqlx::SqlSafeStr as _;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use uuid::Uuid;

/// The id `01900000-0000-7000-8000-0000000000NN` of the fixtures (two hexadecimal digits in `NN`).
fn fixture_id(n: u8) -> Uuid {
    Uuid::parse_str(&format!("01900000-0000-7000-8000-0000000000{n:02x}")).unwrap()
}

/// The fixtures, in ascending order of the schema version they are written for.
fn fixtures() -> Vec<(i64, PathBuf)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("upgrade");
    let mut found: Vec<(i64, PathBuf)> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .map(|path| {
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            let version = stem.split('_').next().and_then(|digits| digits.parse::<i64>().ok());
            assert!(
                version.is_some(),
                "{stem}.sql must start with the schema version it is written for"
            );
            (version.unwrap(), path)
        })
        .collect();
    found.sort();
    found
}

#[test]
fn every_fixture_names_a_migration_of_this_crate() {
    let found = fixtures();
    assert!(!found.is_empty(), "there is no upgrade fixture");
    for (version, path) in found {
        assert!(
            migrate::migrator().version_exists(version),
            "{} is written for schema version {version}, which no migration produces",
            path.display()
        );
    }
}

/// The migrations up to and including `version`, as a migrator of their own.
fn migrator_until(version: i64) -> Migrator {
    let migrations = migrate::migrator()
        .iter()
        .filter(|migration| migration.version <= version)
        .cloned()
        .collect();
    Migrator::with_migrations(migrations)
}

/// A database with the previous release's schema (`version`) and the previous release's data.
async fn old_release(cluster: &support::Cluster, version: i64, path: &Path) -> (support::Scratch, sqlx::PgPool) {
    let scratch = cluster.empty_database().await;
    let owner = cluster.owner_pool(scratch.name()).await;
    migrator_until(version)
        .run(&owner)
        .await
        .expect("the old migrations apply");
    assert_eq!(migrate::applied_version(&owner).await.unwrap(), Some(version));
    let fixture = std::fs::read_to_string(path).unwrap();
    let loaded = sqlx::raw_sql(sqlx::AssertSqlSafe(fixture)).execute(&owner).await;
    assert!(loaded.is_ok(), "{} does not load: {loaded:?}", path.display());
    (scratch, owner)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn later_migrations_are_applied_over_the_old_data_and_the_adapter_still_works() {
    // The central path of the harness (old schema, old data, the migrations that came later, read, write) applies
    // no later migration until the first release is followed by another. This test makes one up, the way a real
    // migration PR would add one, and proves that the mechanism works before it is needed.
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (version, path) = fixtures().pop().expect("there is a fixture");
    let (scratch, owner) = old_release(&cluster, version, &path).await;

    let synthetic = Migration::new(
        migrate::latest_version() + 1,
        "synthetic".into(),
        MigrationType::Simple,
        "ALTER TABLE calendars ADD COLUMN synthetic_note text".into_sql_str(),
        false,
    );
    let mut migrations: Vec<Migration> = migrate::migrator().iter().cloned().collect();
    migrations.push(synthetic);
    let mut extended = Migrator::with_migrations(migrations);
    extended.set_ignore_missing(true);
    extended
        .run(&owner)
        .await
        .expect("the later migrations apply on top of the old data");
    assert_eq!(
        migrate::applied_version(&owner).await.unwrap(),
        Some(migrate::latest_version() + 1),
        "the extra migration is recorded"
    );
    let untouched: i64 = sqlx::query_scalar("SELECT count(*) FROM calendars WHERE synthetic_note IS NULL")
        .fetch_one(&owner)
        .await
        .unwrap();
    assert!(untouched >= 1, "the old rows have the new column, empty");

    // This binary does not know the extra migration and must keep working on the migrated data.
    let runtime = PgDatabase::from_pool(
        cluster.app_pool(scratch.name(), 4).await,
        Arc::new(ManualClock::default()),
        Arc::new(SeqIds::new()),
    );
    read_dataset(&runtime).await;
    write_on_top(&runtime).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_release_schema_upgrades_and_reads_back() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    for (version, path) in fixtures() {
        // The previous release's schema, with the previous release's data.
        let (scratch, owner) = old_release(&cluster, version, &path).await;

        // The new release's migrations. The fixture of the newest release has none to apply (the dataset is read back
        // from the schema it was written for); `later_migrations_are_applied_over_the_old_data_and_the_adapter_still_works`
        // proves the path for a later migration until a real one exists.
        let report = migrate::run_on(&owner)
            .await
            .expect("the new migrations apply on top of the old data");
        assert_eq!(
            (report.before, report.after),
            (Some(version), Some(migrate::latest_version())),
            "fixture {version}"
        );
        assert_eq!(
            report.changed(),
            version < migrate::latest_version(),
            "exactly the migrations after the fixture's release ran (fixture {version})"
        );
        assert_eq!(
            migrate::applied_version(&owner).await.unwrap(),
            Some(migrate::latest_version())
        );

        // The new release's code on the migrated data, as the runtime role.
        let clock = ManualClock::default();
        let runtime = PgDatabase::from_pool(
            cluster.app_pool(scratch.name(), 4).await,
            Arc::new(clock),
            Arc::new(SeqIds::new()),
        );
        assert_eq!(Database::health(&runtime).await, Health::Healthy, "fixture {version}");
        read_dataset(&runtime).await;
        write_on_top(&runtime).await;
    }
}

/// Every fact of the standard dataset, read through the repositories.
#[expect(clippy::too_many_lines, reason = "one linear script of expectations")]
async fn read_dataset(db: &PgDatabase) {
    let acme = TenantId::from_uuid(fixture_id(0x0a));
    let olivia = PrincipalId::from_uuid(fixture_id(0x01));
    let team = PrincipalId::from_uuid(fixture_id(0x02));
    let personal = CalendarId::from_uuid(fixture_id(0x03));
    let projects = CalendarId::from_uuid(fixture_id(0x04));

    let mut tx = db.begin(acme, TxMode::ReadOnly).await.unwrap();

    let tenant = tx.tenant().get().await.unwrap();
    assert_eq!(tenant.slug.as_str(), "acme");
    assert_eq!(tenant.display_name, "Acme GmbH");
    assert_eq!(
        tenant.login_domain.as_ref().map(DomainName::as_str),
        Some("acme.example")
    );
    assert_eq!(tenant.status, TenantStatus::Active);
    assert_eq!(tenant.version, 1);
    assert_eq!(tenant.created_at.to_rfc3339(), "2026-10-01T08:00:00+00:00");

    let found = tx
        .principals()
        .get_by_name(&PrincipalName::parse("olivia").unwrap())
        .await
        .unwrap();
    assert_eq!(found.id, olivia);
    assert_eq!(found.display_name, "Olivia Ostermann");
    assert_eq!(
        found.email.as_ref().map(davhaven_domain::Email::as_str),
        Some("olivia@acme.example")
    );
    assert_eq!(found.external_ref.as_deref(), Some("ldap:olivia"));
    assert_eq!((found.credential_generation, found.version), (2, 3));
    let addresses = tx.principals().addresses(olivia).await.unwrap();
    assert_eq!(addresses.len(), 2);
    assert_eq!(
        addresses
            .iter()
            .filter(|address| address.primary)
            .map(|address| address.address.as_str())
            .collect::<Vec<_>>(),
        ["mailto:olivia@acme.example"]
    );
    let by_address = tx
        .principals()
        .find_by_address(&CalendarUserAddress::parse("mailto:o.ostermann@acme.example").unwrap())
        .await
        .unwrap();
    assert_eq!(by_address.map(|principal| principal.id), Some(olivia));
    assert_eq!(
        tx.principals()
            .find_by_external_ref("ldap:olivia")
            .await
            .unwrap()
            .map(|p| p.id),
        Some(olivia)
    );
    assert_eq!(tx.memberships().members(team).await.unwrap(), [olivia]);
    assert_eq!(tx.memberships().groups_of(olivia).await.unwrap(), [team]);

    let calendar = tx
        .calendars()
        .get_by_slug(olivia, &CalendarSlug::parse("personal").unwrap())
        .await
        .unwrap();
    assert_eq!(calendar.id, personal);
    assert_eq!((calendar.sync_seq, calendar.sync_min_seq), (4, 0));
    assert_eq!(calendar.sync_epoch, fixture_id(0xe1));
    assert_eq!(calendar.display_name, "Olivia");
    assert_eq!(calendar.color.as_deref(), Some("#336699"));
    assert_eq!(calendar.components.len(), 2);
    assert_eq!(calendar.version, 5);
    let owned: Vec<_> = tx
        .calendars()
        .list_owned(olivia)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(owned, [personal, projects]);

    let binding = tx
        .bindings()
        .get_by_slug(olivia, &CalendarSlug::parse("personal").unwrap())
        .await
        .unwrap();
    assert_eq!((binding.calendar_id, binding.hidden), (personal, false));
    let grant = tx
        .grants()
        .find(personal, team)
        .await
        .unwrap()
        .expect("the grant to the team");
    assert_eq!(
        (grant.access, grant.status, grant.source),
        (GrantAccess::ReadWrite, GrantStatus::Accepted, GrantSource::Api)
    );
    let properties = tx.properties().list(personal, PropertyScope::Shared).await.unwrap();
    assert_eq!(properties.len(), 1);

    let a = tx
        .objects()
        .get(personal, &ObjectUri::parse("a.ics").unwrap())
        .await
        .unwrap();
    assert_eq!(a.id.as_uuid(), fixture_id(0x11));
    assert_eq!(a.uid.as_str(), "uid-a");
    assert_eq!(a.etag.as_str(), "\"aaaaaaaaaaaaaaaaaaaaaa\"");
    assert!(a.data.starts_with("BEGIN:VCALENDAR\r\n") && a.data.contains("UID:uid-a"));
    assert_eq!(a.size, 84);
    assert_eq!(
        a.last_end.map(|end| end.to_rfc3339()).as_deref(),
        Some("2027-03-01T11:00:00+00:00")
    );
    assert_eq!(
        a.external_key.as_ref().map(davhaven_domain::ExternalKey::as_str),
        Some("ext-a")
    );
    let b = tx
        .objects()
        .get(personal, &ObjectUri::parse("b.ics").unwrap())
        .await
        .unwrap();
    assert!(b.last_end.is_none(), "an unbounded event keeps its infinite end");
    assert!(b.is_recurring && b.is_scheduling);
    assert_eq!(b.sequence, 2);
    assert_eq!(
        b.schedule_tag.as_ref().map(davhaven_domain::ScheduleTag::as_str),
        Some("\"sched-b\"")
    );
    assert_eq!(
        b.organizer_address.as_ref().map(CalendarUserAddress::as_str),
        Some("mailto:olivia@acme.example")
    );
    assert_eq!(
        tx.objects()
            .get_by_uid(personal, &davhaven_domain::Uid::parse("uid-a").unwrap())
            .await
            .unwrap()
            .id,
        a.id
    );
    let listed: Vec<_> = tx
        .objects()
        .list(personal, PageReq::default())
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|o| o.id)
        .collect();
    assert_eq!(listed, [a.id, b.id], "objects list in id order");
    assert!(
        tx.objects()
            .get(personal, &ObjectUri::parse("c.ics").unwrap())
            .await
            .is_err(),
        "c.ics was deleted"
    );
    let attendees = tx.objects().attendees(b.id).await.unwrap();
    assert_eq!(attendees.len(), 2);
    assert_eq!(
        attendees
            .iter()
            .filter(|attendee| attendee.principal_id.is_some())
            .count(),
        1
    );
    let scheduling = tx
        .objects()
        .find_scheduling_uid(olivia, &davhaven_domain::Uid::parse("uid-b").unwrap())
        .await
        .unwrap();
    assert_eq!(scheduling.map(|object| object.id), Some(b.id));

    let log = CollectionKey {
        kind: CollectionKind::Calendar,
        id: personal.as_uuid(),
    };
    let state = tx.changes().state(log).await.unwrap();
    assert_eq!((state.epoch, state.seq, state.min_seq), (fixture_id(0xe1), 4, 0));
    let everything = tx.changes().since(log, state.epoch, 0, 100).await.unwrap();
    let described: Vec<_> = everything
        .changes
        .iter()
        .map(|change| (change.seq, change.uri.as_str().to_owned(), change.kind))
        .collect();
    assert_eq!(
        described,
        [
            (1, "a.ics".to_owned(), ChangeKind::Upsert),
            (2, "b.ics".to_owned(), ChangeKind::Upsert),
            (4, "c.ics".to_owned(), ChangeKind::Delete),
        ],
        "the log collapses to the latest change per resource"
    );
    let later = tx.changes().since(log, state.epoch, 2, 100).await.unwrap();
    assert_eq!(later.changes.len(), 1);
    assert_eq!(
        tx.changes()
            .since(log, state.epoch, 4, 100)
            .await
            .unwrap()
            .changes
            .len(),
        0
    );
    let home = CollectionKey {
        kind: CollectionKind::Home,
        id: olivia.as_uuid(),
    };
    let home_state = tx.changes().state(home).await.unwrap();
    assert_eq!((home_state.epoch, home_state.seq), (fixture_id(0xe2), 1));
    assert_eq!(
        tx.changes()
            .since(home, home_state.epoch, 0, 10)
            .await
            .unwrap()
            .changes
            .len(),
        1
    );
    let inbox_state = tx
        .changes()
        .state(CollectionKey {
            kind: CollectionKind::Inbox,
            id: olivia.as_uuid(),
        })
        .await
        .unwrap();
    assert_eq!((inbox_state.epoch, inbox_state.seq), (fixture_id(0xe3), 1));
    let notification_state = tx
        .changes()
        .state(CollectionKey {
            kind: CollectionKind::Notifications,
            id: olivia.as_uuid(),
        })
        .await
        .unwrap();
    assert_eq!(
        (notification_state.epoch, notification_state.seq),
        (fixture_id(0xe4), 1)
    );

    let notification = tx
        .notifications()
        .get_by_uri(olivia, &ObjectUri::parse("invite.xml").unwrap())
        .await
        .unwrap();
    assert_eq!(notification.uid.as_str(), "invite-1");
    assert_eq!(tx.inbox().list(olivia, InboxScope::Delivered).await.unwrap().len(), 1);
    assert_eq!(tx.inbox().list(olivia, InboxScope::Quarantined).await.unwrap().len(), 0);

    let passwords = tx.credentials().list_app_passwords(olivia).await.unwrap();
    assert_eq!(passwords.len(), 1);
    let app_password = passwords.first().unwrap();
    assert_eq!(
        (app_password.label.as_str(), app_password.prefix.as_str()),
        ("iPhone", "ap_fixture_olivia")
    );
    assert_eq!(app_password.hash, [1, 2, 3, 4, 5]);

    let message = tx
        .outbox()
        .get(davhaven_domain::OutboxId::from_uuid(fixture_id(0x41)))
        .await
        .unwrap();
    assert_eq!(
        (message.kind.as_str(), message.status, message.attempts),
        ("provider_push", OutboxStatus::Pending, 0)
    );

    let audit = tx
        .audit()
        .list(&AuditFilter::default(), PageReq::default())
        .await
        .unwrap();
    assert_eq!(audit.items.len(), 1);
    assert_eq!(audit.items.first().unwrap().action, "tenant.created");
    drop(tx);

    // Isolation survives the upgrade: another tenant sees nothing of it.
    let mut stranger = db
        .begin(TenantId::from_uuid(fixture_id(0x99)), TxMode::ReadOnly)
        .await
        .unwrap();
    assert!(stranger.calendars().get(personal).await.is_err());
    assert!(stranger.principals().get(olivia).await.is_err());
    drop(stranger);

    let mut system = db.begin_system().await.unwrap();
    let by_domain = system
        .tenants()
        .find_by_login_domain(&DomainName::parse("ACME.example").unwrap())
        .await
        .unwrap();
    assert_eq!(by_domain.map(|tenant| tenant.id), Some(acme));
    assert!(
        system
            .tenants()
            .find_by_slug(&TenantSlug::parse("acme").unwrap())
            .await
            .unwrap()
            .is_some()
    );
    let password = system
        .credential_lookup()
        .find_by_prefix(CredentialKind::AppPassword, "ap_fixture_olivia")
        .await
        .unwrap()
        .expect("the app password is found by its prefix");
    assert_eq!(password.tenant_status, Some(TenantStatus::Active));
    assert_eq!(password.credential_generation, Some(2));
    let tenant_token = system
        .credential_lookup()
        .find_by_prefix(CredentialKind::ApiToken, "at_fixture_acme")
        .await
        .unwrap()
        .expect("the tenant token is found by its prefix");
    assert_eq!(tenant_token.tenant_status, Some(TenantStatus::Active));
    let system_tokens = system.credential_lookup().list_system_tokens().await.unwrap();
    assert_eq!(system_tokens.len(), 1);
    assert_eq!(system_tokens.first().unwrap().label, "operator");
    let due = system
        .outbox_claim()
        .claim(10, std::time::Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(due.len(), 1, "the fixture's pending message is due");
    drop(system);
}

/// Writes on top of the migrated data: the sequence numbers and sync tokens continue where the old release left
/// them.
async fn write_on_top(db: &PgDatabase) {
    let acme = TenantId::from_uuid(fixture_id(0x0a));
    let personal = CalendarId::from_uuid(fixture_id(0x03));
    let log = CollectionKey {
        kind: CollectionKind::Calendar,
        id: fixture_id(0x03),
    };
    let mut tx = db.begin(acme, TxMode::ReadWrite).await.unwrap();
    let written = tx
        .objects()
        .put(personal, version(0x7001, "d.ics", "uid-d").unwrap(), Expected::Absent)
        .await
        .unwrap();
    assert_eq!(written.seq, 5, "the new write continues the old sequence");
    let replaced = tx
        .objects()
        .put(personal, version(0x7002, "a.ics", "uid-a").unwrap(), Expected::Any)
        .await
        .unwrap();
    assert_eq!((replaced.seq, replaced.created), (6, false));
    let batch = tx.changes().since(log, fixture_id(0xe1), 4, 100).await.unwrap();
    assert_eq!(
        batch.changes.iter().map(|change| change.seq).collect::<Vec<_>>(),
        [5, 6]
    );
    assert_eq!(batch.current.seq, 6);
    tx.commit().await.unwrap();

    let mut tx = db.begin(acme, TxMode::ReadOnly).await.unwrap();
    assert_eq!(tx.calendars().get(personal).await.unwrap().sync_seq, 6);
    assert_eq!(
        tx.objects()
            .list(personal, PageReq::default())
            .await
            .unwrap()
            .items
            .len(),
        3
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Restoring a dump (docs/operations/backup.md)
// ---------------------------------------------------------------------------------------------------------------

/// The dumps, in ascending order of the schema version of the release they were taken from.
fn dumps() -> Vec<(i64, PathBuf)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("restore");
    let mut found: Vec<(i64, PathBuf)> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .map(|path| {
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            let version = stem
                .parse::<i64>()
                .expect("a dump is named after the schema version of its release");
            (version, path)
        })
        .collect();
    found.sort();
    found
}

#[test]
fn every_dump_is_of_a_release_that_has_an_upgrade_fixture() {
    let fixtures: Vec<i64> = fixtures().into_iter().map(|(version, _)| version).collect();
    let dumps = dumps();
    assert!(!dumps.is_empty(), "there is no restore dump");
    for (version, path) in dumps {
        assert!(
            migrate::migrator().version_exists(version) && fixtures.contains(&version),
            "{} is a dump of schema version {version}, which no migration produces or no upgrade fixture holds the dataset of",
            path.display()
        );
    }
}

/// The schema of a database as the catalog describes it, one line per object: relations, columns, constraints, indexes,
/// row-level security, policies and functions. Privileges are left out: a restore leaves others than a migration does,
/// and the role model is what puts them right (`a_dump_restored_with_the_owner_role_starts_in_production_mode_after_the_migration`).
async fn schema_of(pool: &sqlx::PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT line FROM ( \
           SELECT 'relation ' || relname || ' ' || relkind::text AS line FROM pg_class \
             WHERE relnamespace = 'public'::regnamespace \
           UNION ALL \
           SELECT 'column ' || c.relname || '.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) \
                  || CASE WHEN a.attnotnull THEN ' not null' ELSE '' END \
                  || coalesce(' default ' || pg_get_expr(d.adbin, d.adrelid), '') \
             FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid \
             LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
             WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p') AND a.attnum > 0 \
               AND NOT a.attisdropped \
           UNION ALL \
           SELECT 'constraint ' || conrelid::regclass::text || '.' || conname || ' ' || pg_get_constraintdef(oid) \
             FROM pg_constraint WHERE connamespace = 'public'::regnamespace \
           UNION ALL \
           SELECT 'index ' || indexdef FROM pg_indexes WHERE schemaname = 'public' \
           UNION ALL \
           SELECT 'row security ' || relname || ' ' || relrowsecurity::text || ' ' || relforcerowsecurity::text FROM pg_class \
             WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p') \
           UNION ALL \
           SELECT 'policy ' || tablename || '.' || policyname || ' ' || permissive || ' ' || cmd || ' ' || roles::text \
                  || ' using ' || coalesce(qual, '-') || ' check ' || coalesce(with_check, '-') \
             FROM pg_policies WHERE schemaname = 'public' \
           UNION ALL \
           SELECT 'function ' || pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace = 'public'::regnamespace \
         ) described ORDER BY line",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The rows of every table of the dataset, as JSON in a fixed order, by table. The migration history is left out (it holds
/// when and how fast the migrations ran); its versions and checksums are compared on their own.
async fn rows_of(pool: &sqlx::PgPool) -> Vec<(String, String)> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT relname::text FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' \
         AND relname <> '_sqlx_migrations' ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut rows = Vec::new();
    for table in tables {
        let content: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text), '[]'::jsonb)::text FROM {table} t"
        )))
        .fetch_one(pool)
        .await
        .unwrap();
        rows.push((table, content));
    }
    rows
}

/// The migration history without its timings: version, description, success and checksum.
async fn history_of(pool: &sqlx::PgPool) -> Vec<(i64, String, bool, Vec<u8>)> {
    sqlx::query_as("SELECT version, description, success, checksum FROM _sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_dump_holds_the_schema_of_its_release_and_the_rows_of_its_upgrade_fixture() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // A dump is never edited, so it must be what its release really wrote: the schema that the migrations up to its version
    // make and the dataset of the upgrade fixture of that release. A dump that was edited by hand, or not taken again when
    // its release's schema still changed, differs from the database that the migrations and the fixture make.
    let fixtures = fixtures();
    for (version, path) in dumps() {
        let (_, fixture) = fixtures
            .iter()
            .find(|(fixture_version, _)| *fixture_version == version)
            .expect("every dump has an upgrade fixture");
        let (_made, made) = old_release(&cluster, version, fixture).await;
        let restored_database = cluster.empty_database().await;
        restore(&cluster, restored_database.name(), &path, Some(support::OWNER)).await;
        let restored = cluster.owner_pool(restored_database.name()).await;

        let (expected, found) = (schema_of(&made).await, schema_of(&restored).await);
        assert!(
            expected.len() > 100,
            "the catalog query describes the schema: {expected:#?}"
        );
        let missing: Vec<&String> = expected.iter().filter(|line| !found.contains(line)).collect();
        let extra: Vec<&String> = found.iter().filter(|line| !expected.contains(line)).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "the dump of {version} has another schema than its migrations make; missing: {missing:#?}, extra: {extra:#?}"
        );
        assert_eq!(found, expected, "the dump of {version} repeats an object");
        assert_eq!(
            history_of(&restored).await,
            history_of(&made).await,
            "the migration history of the dump of {version}"
        );
        let (expected, found) = (rows_of(&made).await, rows_of(&restored).await);
        assert!(
            expected.iter().filter(|(_, rows)| rows != "[]").count() >= 10,
            "the upgrade fixture of {version} fills the tables of the dataset: {expected:?}"
        );
        assert_eq!(
            found.iter().map(|(table, _)| table).collect::<Vec<_>>(),
            expected.iter().map(|(table, _)| table).collect::<Vec<_>>()
        );
        for ((table, want), (_, got)) in expected.iter().zip(&found) {
            assert_eq!(
                got, want,
                "the rows of {table} in the dump of {version} are not those of its upgrade fixture"
            );
        }
    }
}

/// Restores a dump into `database` the way the documentation says: as the superuser of the cluster, with `SET ROLE`
/// when a role is given (what `pg_restore --no-owner --role=<role>` does), in one transaction.
async fn restore(cluster: &support::Cluster, database: &str, path: &Path, role: Option<&str>) {
    let dump = std::fs::read_to_string(path).unwrap();
    let script = match role {
        Some(role) => format!("SET ROLE {role};\n{dump}"),
        None => dump,
    };
    let pool = cluster.admin_pool(database).await;
    let restored = sqlx::raw_sql(sqlx::AssertSqlSafe(script)).execute(&pool).await;
    pool.close().await;
    assert!(restored.is_ok(), "{} does not restore: {restored:?}", path.display());
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

/// Starts the database plugin on `database` as production does, with the runtime role, and returns what readiness says.
async fn start_in_production(cluster: &support::Cluster, database: &str) -> Health {
    let mut registry = PluginRegistry::new();
    plugin::register(&mut registry).unwrap();
    let table = serde_json::json!({
        "url": cluster.url_for(support::APP, database),
        "migrate_on_start": false,
        "allow_insecure_transport": true,
    });
    let tree = ConfigTree::new().with(PLUGIN, table);
    let built = registry
        .build_single(PortKind::DATABASE, PLUGIN, &production(), &tree)
        .await
        .expect("production starts on the restored database");
    let health = built.port.health().await;
    built.lifecycle.expect("a lifecycle").shutdown().await;
    health
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dump_restored_with_the_owner_role_starts_in_production_mode_after_the_migration() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    for (version, path) in dumps() {
        // A new database with the roles and the default privileges of the production recipe, and the dump restored
        // into it as the owner (backup.md, steps 1 and 2).
        let scratch = cluster.empty_database().await;
        restore(&cluster, scratch.name(), &path, Some(support::OWNER)).await;
        let owner = cluster.owner_pool(scratch.name()).await;
        assert_eq!(
            migrate::applied_version(&owner).await.unwrap(),
            Some(version),
            "the migration history came with the dump"
        );
        let tables_owned_by_others: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p') \
             AND pg_get_userbyid(c.relowner) <> 'davhaven_owner'",
        )
        .fetch_one(&owner)
        .await
        .unwrap();
        assert_eq!(tables_owned_by_others, 0, "the owner role owns every restored table");

        // What the restore leaves: the tables were created with the default privileges of the owner (which write to the
        // audit log and the migration history) and the grants of the dump only add to them.
        let runtime = PgDatabase::from_pool(
            cluster.app_pool(scratch.name(), 4).await,
            Arc::new(ManualClock::default()),
            Arc::new(SeqIds::new()),
        );
        let restored = runtime.posture().await;
        for finding in [
            "UPDATE on audit_events",
            "DELETE on audit_events",
            "INSERT on _sqlx_migrations",
        ] {
            assert!(
                restored.excess_privileges.iter().any(|privilege| privilege == finding),
                "a database restored over default privileges holds {finding}: {restored:?}"
            );
        }

        // Step 3: `davhaven migrate` with the owner credentials. It brings the schema to the release that is about to
        // run, and puts the role model back whether or not a migration was pending.
        let report = migrate::run_on(&owner)
            .await
            .expect("the migrations apply to the restored database");
        assert_eq!(report.before, Some(version));
        assert_eq!(report.after, Some(migrate::latest_version()));
        assert_eq!(
            report.role_model,
            RoleModel::Applied { runtime_roles: 1 },
            "the role model was applied to the runtime role"
        );
        let after = runtime.posture().await;
        assert!(after.security_findings().is_empty(), "{after:?}");
        assert_eq!(Database::health(&runtime).await, Health::Healthy);

        // The server starts in production mode, and the data of the dump is there.
        assert_eq!(
            start_in_production(&cluster, scratch.name()).await,
            Health::Healthy,
            "dump of {version}"
        );
        read_dataset(&runtime).await;
        write_on_top(&runtime).await;

        // The migration step alone is what restored the role model: a second run changes nothing.
        let again = migrate::run_on(&owner).await.unwrap();
        assert!(!again.changed());
        assert_eq!(again.role_model, RoleModel::Applied { runtime_roles: 1 });
        let posture = runtime.posture().await;
        assert!(posture.security_findings().is_empty(), "{posture:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dump_restored_without_the_owner_role_cannot_be_migrated() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let (version, path) = dumps().pop().expect("there is a dump");
    // Restoring as the superuser (no `--role`) makes the superuser the owner of every table. The owner role of the
    // deployment then cannot change them, so `davhaven migrate` fails instead of leaving a half-owned schema.
    let scratch = cluster.empty_database().await;
    restore(&cluster, scratch.name(), &path, None).await;
    let owner = cluster.owner_pool(scratch.name()).await;
    // Whatever is pending, the role model step is the owner's business only, and it says that it did not run: a newer dump of a
    // release with nothing left to migrate must still be refused (with a migration pending the owner fails to alter a table
    // that it does not own, which is an error of its own).
    assert_eq!(
        migrate::enforce_role_model(&owner).await.unwrap(),
        RoleModel::NotOwner,
        "the owner role does not own the restored tables (dump of {version})"
    );
    let outcome = migrate::run_on(&owner).await;
    assert!(
        outcome.is_err()
            || outcome
                .as_ref()
                .is_ok_and(|report| report.role_model == RoleModel::NotOwner),
        "the owner role migrated tables that it does not own, or claimed to have applied the role model to them (dump of {version}): {outcome:?}"
    );
    // And the second run, which has nothing left to migrate whatever the first did, reports the same.
    let again = migrate::run_on(&owner).await;
    assert!(
        again.is_err()
            || again
                .as_ref()
                .is_ok_and(|report| report.role_model == RoleModel::NotOwner),
        "{again:?}"
    );
    let owners: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT pg_get_userbyid(c.relowner)::text FROM pg_class c \
         WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p') ORDER BY 1",
    )
    .fetch_all(&owner)
    .await
    .unwrap();
    assert!(!owners.iter().any(|name| name == "davhaven_owner"), "{owners:?}");
}
