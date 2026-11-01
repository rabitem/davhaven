//! Integration tests of Davhaven.
//!
//! This crate contains only tests (in `tests/`); they use `davhaven-testkit` to run the application in process
//! against the memory and PostgreSQL stores. It is, besides `davhaven-conformance`, the only consumer of the
//! test harness.

#![forbid(unsafe_code)]
