//! The setup of the roles of the test databases. Roles belong to the cluster, and test runs that use databases of their
//! own on one cluster (the workspaces of a shared build host) change the same two, which used to fail with `tuple
//! concurrently updated`. These tests pin the parts of the rule in `support`: the failure itself and that the setup
//! recognises it, roles that are in order are not written, and the locks that serialise the provisioning are taken where
//! every run meets.

#![expect(
    clippy::unwrap_used,
    reason = "a test environment that misbehaves fails the test loudly"
)]

mod support;

use std::time::Duration;

use sqlx::{Connection, PgConnection};
use support::Cluster;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// How long a step that must not wait may take.
const PROMPT: Duration = Duration::from_secs(20);

/// What the catalog says about the version of the rows that hold the two roles and their comments: `xmin` is the transaction
/// that wrote a row, so a row that nobody wrote has the same one before and after.
async fn versions_of_the_roles(connection: &mut PgConnection) -> (String, String) {
    let roles: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(rolname || ':' || xmin::text, ',' ORDER BY rolname), '') FROM pg_authid \
         WHERE rolname IN ('davhaven_owner', 'davhaven_app')",
    )
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    let comments: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(d.objoid::text || ':' || d.xmin::text, ',' ORDER BY d.objoid), '') \
           FROM pg_shdescription d JOIN pg_authid r ON r.oid = d.objoid \
          WHERE d.classoid = 'pg_authid'::regclass AND r.rolname IN ('davhaven_owner', 'davhaven_app')",
    )
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    (roles, comments)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roles_that_are_in_order_are_not_written() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // The roles exist and are in order once a template has been made.
    cluster.template().await;
    let mut watch = cluster.admin().await;
    let before = versions_of_the_roles(&mut watch).await;
    assert!(
        !before.0.is_empty() && !before.1.is_empty(),
        "the roles and their comments exist: {before:?}"
    );

    let mut runs = JoinSet::new();
    for _ in 0..8 {
        let cluster = cluster.clone();
        runs.spawn(async move {
            let mut admin = cluster.admin().await;
            cluster.ensure_roles(&mut admin).await;
        });
    }
    while let Some(run) = runs.join_next().await {
        run.unwrap();
    }
    // Every update of a role writes a new version of its catalog row; the rows are the ones they were.
    assert_eq!(
        versions_of_the_roles(&mut watch).await,
        before,
        "a run that finds the roles in order wrote them: every update of a role is an update of a catalog row that another \
         run may be updating at the same time"
    );
}

/// Whether the lock `key` is free, asked from `probe`, a session of the maintenance database. Taking it holds it, so the
/// caller lets go of it.
async fn lock_is_free(probe: &mut PgConnection, key: i64) -> bool {
    let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *probe)
        .await
        .unwrap();
    if free {
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *probe)
            .await
            .unwrap();
    }
    free
}

#[tokio::test]
async fn the_locks_of_the_provisioning_are_taken_in_the_maintenance_database_and_end_with_their_session() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // An advisory lock belongs to the database it is taken in. Runs that work in databases of their own meet at a lock only if
    // they all take it in the same one, so a session of the maintenance database sees whether it is held.
    let mut probe = cluster.admin_to("postgres").await;
    for key in [support::LOCK, support::ROLE_LOCK] {
        let held = cluster.lock_cluster(key).await;
        assert!(
            !lock_is_free(&mut probe, key).await,
            "the lock {key} is not taken in the maintenance database, so runs in other databases do not wait for it"
        );
        held.close().await.unwrap();
        timeout(PROMPT, async {
            while !lock_is_free(&mut probe, key).await {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("closing the session did not release the lock {key}"));
    }
}

#[tokio::test]
async fn two_updates_of_one_role_fail_in_the_way_that_the_setup_tries_again() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // The failure that the setup is written against, made on a role of this run alone: two sessions update the same row of
    // the catalog, the second waits for the first, and when the first commits the second fails.
    let role = format!("davhaven_race_{}", support::run_id());
    let mut first = cluster.admin().await;
    let mut second = cluster.admin().await;
    let mut watch = cluster.admin().await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} NOLOGIN")))
        .execute(&mut first)
        .await
        .unwrap();
    sqlx::raw_sql("BEGIN").execute(&mut first).await.unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER ROLE {role} CONNECTION LIMIT 5")))
        .execute(&mut first)
        .await
        .unwrap();

    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut second)
        .await
        .unwrap();
    let statement = format!("ALTER ROLE {role} CONNECTION LIMIT 6");
    let waiting = tokio::spawn(async move {
        let outcome = sqlx::raw_sql(sqlx::AssertSqlSafe(statement)).execute(&mut second).await;
        (second, outcome)
    });
    // Until the second session waits on a lock (the transaction of the first), committing would prove nothing.
    timeout(PROMPT, async {
        loop {
            let waits: Option<String> =
                sqlx::query_scalar::<_, Option<String>>("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1")
                    .bind(pid)
                    .fetch_optional(&mut watch)
                    .await
                    .unwrap()
                    .flatten();
            if waits.as_deref() == Some("Lock") {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the second update never waited for the first");
    sqlx::raw_sql("COMMIT").execute(&mut first).await.unwrap();

    let (second, outcome) = waiting.await.unwrap();
    let error = outcome.expect_err("the second update fails when the first commits");
    assert!(
        error.to_string().contains("tuple concurrently updated"),
        "another failure than the one the setup is written against: {error}"
    );
    assert!(
        Cluster::is_role_race(&error),
        "the setup does not recognise it: {error}"
    );

    drop(second);
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE {role}")))
        .execute(&mut first)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_other_failures_of_a_race_between_two_setups_are_recognised_and_nothing_else_is() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    let mut admin = cluster.admin().await;
    sqlx::raw_sql("CREATE TEMP TABLE role_race_probe (id integer PRIMARY KEY); INSERT INTO role_race_probe VALUES (1)")
        .execute(&mut admin)
        .await
        .unwrap();

    // Two runs that both found the role missing: the second creation meets the first (a duplicate key on the catalog's
    // index, or the check of the statement itself).
    let duplicate = sqlx::raw_sql("INSERT INTO role_race_probe VALUES (1)")
        .execute(&mut admin)
        .await
        .unwrap_err();
    assert!(Cluster::is_role_race(&duplicate), "{duplicate}");
    let current: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    let existing = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE \"{current}\"")))
        .execute(&mut admin)
        .await
        .unwrap_err();
    assert!(Cluster::is_role_race(&existing), "{existing}");

    // Anything else is a failure of the setup and ends the test.
    let broken = sqlx::raw_sql("SELEC 1").execute(&mut admin).await.unwrap_err();
    assert!(!Cluster::is_role_race(&broken), "{broken}");
    assert!(!Cluster::is_role_race(&sqlx::Error::PoolTimedOut));
}

#[tokio::test]
async fn the_names_of_the_databases_of_a_run_do_not_repeat_between_processes() {
    let Some(cluster) = support::cluster() else {
        return;
    };
    // The process id repeats between the containers of a build host, so a name made of it could be the database of another
    // run. The databases of this run carry the random text of the run.
    let name = cluster.clone_database().await;
    assert!(
        name.starts_with(&format!("davhaven_t_{}_", support::run_id())),
        "{name} does not carry the text of the run"
    );
    assert_eq!(support::run_id().len(), 16, "a 64-bit text in hexadecimal");
    cluster.drop_database(&name).await;
}
