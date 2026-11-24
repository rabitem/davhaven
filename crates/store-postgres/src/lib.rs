//! PostgreSQL implementation of the `Database` port.
//!
//! Owns the schema migrations (forward-only, expand/contract), row-level security on every tenant table and the
//! tenant-bound transactions. Queries are runtime-checked `sqlx` queries (`query_as` with `FromRow`).

#![forbid(unsafe_code)]

pub mod config;
pub mod database;
pub mod error;
pub mod migrate;
pub mod plugin;
mod pool_metrics;
mod repos;
mod tx;
