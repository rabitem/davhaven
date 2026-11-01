//! The suite on PostgreSQL (`davhaven-store-postgres`) as the bound runtime role, on a database cloned from the migrated
//! template for every world (backlog item 20): row-level security, the composite keys, the system scope and real
//! transactions are part of what the application is tested against.

/// The store of this copy of the suite.
pub(crate) const STORE: crate::Store = crate::Store::Postgres;

suite!();
