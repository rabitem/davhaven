//! The application core, on both stores.
//!
//! These are the application-level tests (PLAN 3.1, L3) of the use cases in `davhaven-app`: tenants and
//! principals, calendars and bindings, calendar objects, the JSON event interface and its equivalence with DAV,
//! batch upserts, sharing, credentials and authentication, feeds, idempotency keys, the audit log and tenant
//! isolation. They run the real services over the real stores, the ones the store contract suite checks, so the
//! behavior they rely on (the write invariant, rollback including the outbox, tenant isolation) is the store's and
//! not a test double's. The few doubles are small and each stands in for one port: the authenticator chain, the
//! rate limiter, mail, templates and HTTP.
//!
//! **The whole suite runs twice**: once on `store-memory` (module `on_memory`) and once on PostgreSQL as the bound
//! runtime role, so that row-level security, the composite keys, the system scope and the real transactions are
//! part of what the application is tested against (`on_postgres`, backlog item 20). Each module holds its own copy
//! of the files below, compiled with the store it is named after (`STORE`), and the world of the tests
//! (`support::World`) builds the store from it, so the tests themselves do not know which store they run on. The
//! PostgreSQL copy needs `DATABASE_URL` (a throw-away server: CI has one, the build host too) and fails without one;
//! outside CI, `DAVHAVEN_ALLOW_NO_DB=1` builds its worlds on the memory store and says so (`support::runs_on_postgres`).

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]
#![expect(
    clippy::too_many_lines,
    reason = "a scenario reads best from top to bottom; its steps share the state that the test builds up"
)]
#![expect(
    clippy::duplicate_mod,
    reason = "the suite is compiled once per store on purpose: the files are the same, the world they run on is not"
)]
#![expect(
    clippy::assert_is_empty,
    reason = "the assertion message names the case; the contents of a list that should be empty add nothing"
)]

/// The store a copy of the suite runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Store {
    /// `davhaven-store-memory`.
    Memory,
    /// `davhaven-store-postgres` on a database cloned from the migrated template, as the bound runtime role.
    Postgres,
}

/// One copy of the suite: the world and the test modules, declared in the module that invokes it (`on_memory.rs`,
/// `on_postgres.rs`), each of which defines `STORE` first. The paths are relative to the directory of that file,
/// which is why the copies are file modules and not inline ones.
macro_rules! suite {
    () => {
        #[path = "support.rs"]
        mod support;

        #[path = "scheduler.rs"]
        mod scheduler;

        #[path = "audit.rs"]
        mod audit;
        #[path = "batch.rs"]
        mod batch;
        #[path = "batch_reads.rs"]
        mod batch_reads;
        #[path = "bindings.rs"]
        mod bindings;
        #[path = "calendars.rs"]
        mod calendars;
        #[path = "credentials.rs"]
        mod credentials;
        #[path = "dav_collaboration.rs"]
        mod dav_collaboration;
        #[path = "events.rs"]
        mod events;
        #[path = "facts.rs"]
        mod facts;
        #[path = "feeds.rs"]
        mod feeds;
        #[path = "idempotency.rs"]
        mod idempotency;
        #[path = "isolation.rs"]
        mod isolation;
        #[path = "objects.rs"]
        mod objects;
        #[path = "principals.rs"]
        mod principals;
        #[path = "sharing.rs"]
        mod sharing;
        #[path = "stores.rs"]
        mod stores;
        #[path = "tenants.rs"]
        mod tenants;
    };
}

mod on_memory;
mod on_postgres;
