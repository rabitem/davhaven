//! In-memory implementation of the `Database` port.
//!
//! Transactions work on a copy-on-write snapshot under one async mutex, so commit and rollback behave like the
//! PostgreSQL adapter. Intended for development and tests; production mode refuses it.

#![forbid(unsafe_code)]

pub mod config;
pub mod database;
pub mod plugin;
mod repos;
mod state;
mod tx;
