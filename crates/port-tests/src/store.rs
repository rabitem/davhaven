//! Contract suite of the `Database` port.
//!
//! Both store adapters (memory and PostgreSQL) run this suite, so they behave identically. A case builds a fresh
//! database with the factory, seeds what it needs through the port, and checks one aspect of the contract:
//!
//! * **tenants and principals**: the system tenant repository, principals with their addresses and groups, search,
//!   credential generations, purge;
//! * **calendars**: calendars, soft deletion, locking, authorization facts, bindings, collection properties and
//!   grants;
//! * **objects and the write invariant** (PLAN 2.7): `put`, `delete` and `move_to` advance the calendar's
//!   sequence exactly once per mutation and log the change at that sequence number, failed writes change
//!   nothing, expected states are honoured, unique keys are typed, queries return supersets in id order and pages
//!   are stable, unbounded events use an infinite end;
//! * **change logs**: sync positions, collapsing, truncation, token checks, home, inbox and notification logs;
//! * **credentials, outbox, webhooks, provider accounts, OAuth states, idempotency keys and the audit log**;
//! * **retention**: the cleanup methods and what they leave behind;
//! * **tenant isolation** (R4): every repository method called with a foreign tenant answers `NotFound`, `None`
//!   or an empty list and changes nothing;
//! * **transactions**: rollback (outbox messages included), failed writes leave no trace, read-only transactions,
//!   one clock for every stamp;
//! * **concurrency**: distinct sequence numbers for concurrent writers, one winner for racing creators, claims
//!   that never overlap, visibility after commit, stable cursors.
//!
//! The suite never reads the system clock and never sleeps. Time-dependent behaviour (lease expiry, expiring
//! keys, retention cut-offs) is probed with instants far in the past and the future relative to any clock a test
//! uses, and with a lease of zero, which is already over when the claim returns.

use std::future::Future;
use std::sync::Arc;

use davhaven_ports::testing::ManualClock;
use davhaven_ports::{Database, StoreError};
use futures::future::BoxFuture;

use crate::suite::{Checks, ContractReport, Suite};

mod calendars;
mod changes;
mod concurrency;
mod credentials;
mod defaults;
mod delivery;
mod isolation;
mod objects;
mod principals;
mod records;
mod retention;
mod sync_model;
mod tenants;
mod transactions;
mod world;

/// The seeded world of the suite and the builder of object versions, for the tests of a store adapter that
/// need the same data as the contract cases (PostgreSQL-specific locking and privilege tests).
pub mod fixtures {
    pub use super::world::{World, seed, version};
}

pub use defaults::required_methods_only;
pub use isolation::{TENANT_OPERATIONS, assert_isolation_covers};
use world::Db;

/// A case: it gets a fresh database and records its findings in the checks.
type Case = for<'a> fn(Db, &'a mut Checks) -> BoxFuture<'a, ()>;

/// The one list of the suite's cases, and every use of it.
///
/// Each entry is `module::function` where the function is `async fn(&Db, &mut Checks) -> Result<(), StoreError>`; an
/// unexpected error fails the case. A new case is added **here and nowhere else**: the table [`run`] walks, the
/// names [`case_names`] returns and the tests every adapter generates all come from this list.
///
/// Uses (the first token selects one):
///
/// * `table`: the table of [`Case`] entries, for `CASES`;
/// * `tests <runner>`: one `#[tokio::test]` per case in a module `cases`, each calling the async function `runner`
///   (defined next to the macro call) with the name of the case; `runner` returns `Option<ContractReport>`, where
///   `None` means "skipped" (no database to test against) and `Some` is asserted clean;
/// * `isolation_tests <runner>`: the same for the cases of the `isolation` module only, in a module
///   `isolation_cases` (PostgreSQL runs them once more as the unbound owner role).
///
/// Adapters call `store_contract_tests!` instead of this macro.
#[doc(hidden)]
#[macro_export]
macro_rules! store_cases {
    (table) => {
        $crate::store_cases! { @list table }
    };
    (tests $runner:ident) => {
        $crate::store_cases! { @list tests $runner }
    };
    (isolation_tests $runner:ident) => {
        $crate::store_cases! { @list isolation_tests $runner }
    };

    (@list $($mode:tt)*) => {
        $crate::store_cases! { @ $($mode)* ;
            tenants::tenants_create_get_find_list,
            tenants::tenants_update_and_delete,
            tenants::tenants_unique_keys,
            tenants::tenants_delete_keeps_the_audit_log,
            tenants::tenants_audit_in_the_system_transaction,
            tenants::tenants_bump_the_sync_epoch,
            principals::principals_crud,
            principals::principals_filters_and_pages,
            principals::principals_unique_keys,
            principals::principals_addresses,
            principals::principals_batch_reads,
            principals::principals_search,
            principals::principals_search_criteria,
            principals::principals_unicode_text,
            principals::principals_credential_generation,
            principals::memberships,
            principals::principals_purge_removes_everything,
            calendars::calendars_crud,
            calendars::calendars_soft_delete_lock_touch_purge,
            calendars::calendars_soft_delete_removes_bindings,
            calendars::calendars_unique_slugs,
            calendars::calendars_visibility_and_facts,
            calendars::bindings,
            calendars::collection_properties,
            calendars::grants,
            calendars::calendars_batch_reads,
            objects::objects_put_and_read,
            objects::objects_attendees,
            objects::objects_write_invariant,
            objects::objects_expected_states,
            objects::objects_unique_keys,
            objects::objects_uid_conflicts_name_the_resource,
            objects::objects_move,
            objects::objects_query,
            objects::objects_query_instants,
            objects::objects_time_range_vectors,
            objects::objects_index_listings,
            objects::objects_unicode_data,
            objects::objects_of_deleted_calendars,
            changes::changes_since,
            changes::changes_token_checks,
            changes::changes_of_principal_collections,
            changes::notifications_and_inbox,
            sync_model::changes_match_a_model,
            credentials::app_passwords_and_api_tokens,
            credentials::feed_tokens_and_usage,
            credentials::credential_lookup,
            credentials::credential_rehash,
            credentials::rsvp_tokens,
            delivery::outbox_inspection,
            delivery::outbox_claims,
            delivery::outbox_settling,
            delivery::outbox_fenced_settling,
            delivery::webhooks_and_deliveries,
            delivery::webhook_counters_and_duplicate_deliveries,
            delivery::external_accounts_and_oauth_states,
            records::idempotency_keys,
            records::idempotency_leases,
            records::idempotency_fenced_settling,
            records::audit_log,
            retention::retention_purges,
            retention::retention_prunes_change_logs,
            retention::retention_due_rows,
            isolation::foreign_tenant_reads,
            isolation::foreign_tenant_writes,
            isolation::entities_cannot_choose_their_tenant,
            isolation::unknown_tenants,
            isolation::isolation_covers_every_operation,
            transactions::rollback_discards_everything,
            transactions::failed_writes_leave_no_trace,
            transactions::read_only_transactions,
            transactions::snapshot_transactions,
            transactions::text_with_nul_is_refused,
            transactions::timestamps_are_consistent_and_microsecond_precise,
            transactions::health_is_ready,
            concurrency::concurrent_writers_get_distinct_sequence_numbers,
            concurrency::racing_creators_have_one_winner,
            concurrency::claims_never_overlap,
            concurrency::writes_are_visible_after_commit,
            concurrency::cursors_are_stable,
            concurrency::racing_provisioning_calls_serialise,
        }
    };

    (@ table ; $($module:ident :: $name:ident),+ $(,)?) => {
        &[$((
            stringify!($name),
            |database, checks| {
                ::std::boxed::Box::pin(async move {
                    if let ::std::result::Result::Err(error) = $module::$name(&database, checks).await {
                        checks.fail(format!("unexpected store error: {error}"));
                    }
                })
            },
        )),+]
    };

    (@ tests $runner:ident ; $($module:ident :: $name:ident),+ $(,)?) => {
        mod cases {
            $(
                #[::tokio::test(flavor = "multi_thread", worker_threads = 4)]
                async fn $name() {
                    if let ::std::option::Option::Some(report) = super::$runner(stringify!($name)).await {
                        report.assert_ok();
                    }
                }
            )+
        }
    };

    (@ isolation_tests $runner:ident ; $($module:ident :: $name:ident),+ $(,)?) => {
        mod isolation_cases {
            $( $crate::store_cases! { @isolation_one $runner $module :: $name } )+
        }
    };
    (@isolation_one $runner:ident isolation :: $name:ident) => {
        #[::tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            if let ::std::option::Option::Some(report) = super::$runner(stringify!($name)).await {
                report.assert_ok();
            }
        }
    };
    (@isolation_one $runner:ident $other:ident :: $name:ident) => {};
}

/// Generates one `#[tokio::test]` per case of the store contract suite, so a failure names its case and the test
/// runner can parallelise and retry. An adapter's test file needs three lines of its own:
///
/// ```ignore
/// async fn run(name: &'static str) -> Option<davhaven_port_tests::ContractReport> {
///     davhaven_port_tests::store::run_case(name, fresh_database).await
/// }
/// davhaven_port_tests::store_contract_tests!(run);
/// ```
///
/// The runner returns `None` to skip the case (an adapter without a database to test against); the cases come
/// from the suite's own list, so a case added to the suite has a test in every adapter without any edit there.
/// An adapter whose isolation must also hold without row-level security calls `store_isolation_tests!` with a
/// runner of its own.
#[macro_export]
macro_rules! store_contract_tests {
    ($runner:ident) => {
        $crate::store_cases! { tests $runner }
    };
}

/// Generates one test per case of the suite's `isolation` module only, in a module `isolation_cases` (see
/// `store_contract_tests!`).
#[macro_export]
macro_rules! store_isolation_tests {
    ($runner:ident) => {
        $crate::store_cases! { isolation_tests $runner }
    };
}

/// Every case of the suite.
const CASES: &[(&str, Case)] = crate::store_cases!(table);

/// Runs the suite against databases built by `factory` and returns the report.
///
/// Every call of `factory` must return a database that no other test uses (an empty memory store, or a schema
/// cloned from the migrated template database); the cases write freely.
pub async fn run<F, Fut>(factory: F) -> ContractReport
where
    F: Fn() -> Fut,
    Fut: Future<Output = Arc<dyn Database>>,
{
    let mut suite = Suite::new("store");
    for (name, case) in CASES {
        let mut checks = Checks::new(name);
        case(factory().await, &mut checks).await;
        suite.record(checks);
    }
    suite.finish()
}

/// The names of the cases, in the order [`run`] runs them. Adapters generate one test per name, so a failure is
/// attributed to its case and the test runner can retry and parallelise them.
pub fn case_names() -> Vec<&'static str> {
    CASES.iter().map(|(name, _)| *name).collect()
}

/// Runs the case `name` against a database built by `factory` and returns its report (one case), or `None` when
/// the suite has no case of that name.
pub async fn run_case<F, Fut>(name: &str, factory: F) -> Option<ContractReport>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Arc<dyn Database>>,
{
    let (name, case) = CASES.iter().find(|(candidate, _)| *candidate == name)?;
    let mut suite = Suite::new("store");
    let mut checks = Checks::new(name);
    case(factory().await, &mut checks).await;
    suite.record(checks);
    Some(suite.finish())
}

/// A case that moves the clock of its database: the cases whose answer depends on **when** things happened (the oldest audit
/// record of all tenants) need records with distinct times, and the clock of a database belongs to the code that builds it.
/// The case gets the manual clock the database was built with, and moves it (forwards or back) between its writes.
type ClockedCase = for<'a> fn(Db, ManualClock, &'a mut Checks) -> BoxFuture<'a, ()>;

/// The one list of the cases that move the clock, and every use of it (the same layout as [`store_cases!`]).
#[doc(hidden)]
#[macro_export]
macro_rules! store_clocked_cases {
    (table) => {
        $crate::store_clocked_cases! { @ table ; retention::retention_oldest_audit_event }
    };
    (tests $runner:ident) => {
        $crate::store_clocked_cases! { @ tests $runner ; retention::retention_oldest_audit_event }
    };

    (@ table ; $($module:ident :: $name:ident),+ $(,)?) => {
        &[$((
            stringify!($name),
            |database, clock, checks| {
                ::std::boxed::Box::pin(async move {
                    if let ::std::result::Result::Err(error) = $module::$name(&database, &clock, checks).await {
                        checks.fail(format!("unexpected store error: {error}"));
                    }
                })
            },
        )),+]
    };

    (@ tests $runner:ident ; $($module:ident :: $name:ident),+ $(,)?) => {
        mod clocked_cases {
            $(
                #[::tokio::test(flavor = "multi_thread", worker_threads = 4)]
                async fn $name() {
                    if let ::std::option::Option::Some(report) = super::$runner(stringify!($name)).await {
                        report.assert_ok();
                    }
                }
            )+
        }
    };
}

/// Generates one `#[tokio::test]` per case that moves the clock, in a module `clocked_cases` (see `store_contract_tests!`).
/// The adapter's runner builds the database **and** the manual clock it was built with:
///
/// ```ignore
/// async fn run_clocked(name: &'static str) -> Option<davhaven_port_tests::ContractReport> {
///     davhaven_port_tests::store::run_clocked_case(name, fresh_database_and_clock).await
/// }
/// davhaven_port_tests::store_clocked_contract_tests!(run_clocked);
/// ```
#[macro_export]
macro_rules! store_clocked_contract_tests {
    ($runner:ident) => {
        $crate::store_clocked_cases! { tests $runner }
    };
}

/// Every case that moves the clock.
const CLOCKED_CASES: &[(&str, ClockedCase)] = crate::store_clocked_cases!(table);

/// The names of the cases that move the clock, in the order of their list.
pub fn clocked_case_names() -> Vec<&'static str> {
    CLOCKED_CASES.iter().map(|(name, _)| *name).collect()
}

/// Runs the case `name` that moves the clock against a database and the manual clock it was built with, both from
/// `factory` (the clock must be the one of the database, or the case checks nothing), and returns its report, or `None` when the
/// suite has no such case.
pub async fn run_clocked_case<F, Fut>(name: &str, factory: F) -> Option<ContractReport>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = (Arc<dyn Database>, ManualClock)>,
{
    let (name, case) = CLOCKED_CASES.iter().find(|(candidate, _)| *candidate == name)?;
    let mut suite = Suite::new("store");
    let mut checks = Checks::new(name);
    let (database, clock) = factory().await;
    case(database, clock, &mut checks).await;
    suite.record(checks);
    Some(suite.finish())
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_all<F, Fut>(factory: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = Arc<dyn Database>>,
{
    run(factory).await.assert_ok();
}

/// The number of cases, so adapters can assert that the suite is not empty.
pub const fn case_count() -> usize {
    CASES.len()
}

/// The error type every case returns.
type Outcome = Result<(), StoreError>;
