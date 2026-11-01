//! Contract test suites for every Davhaven port.
//!
//! Every adapter runs the suite of its port, for example `port_tests::store::run_all(factory)`, so all
//! implementations of a port behave identically (`ENGINEERING_RULES` R2). The entry points follow one pattern:
//!
//! * `run(factory)` runs the suite and returns the [`ContractReport`]; this is how the suites test themselves
//!   against deliberately broken doubles;
//! * `run_all(factory)` runs it and fails the running test when a case fails, listing every violated expectation;
//! * the factory builds a fresh implementation (or, for pure ports with keys, one built from a spec), so the cases
//!   never depend on each other.
//!
//! The suites for the pure ports (`clock`, `ids`, `keyring`, `sealer`, `hasher`, `profile_signer`) and for `event_sink`, `mail`,
//! `scanner`, `outbox` and `rate_limit` already hold cases that the test doubles of `davhaven-ports` and the
//! capture doubles of the test harness pass. The other entry points (`store`, `auth`, `http_client`, `policy`,
//! `provider`, `templates`) are in place with their final factory signature and have no cases yet; the crate that
//! implements the port adds them (PLAN 4.2); [`ContractReport::pending`] marks a suite without cases.
//!
//! The suites never sleep and never read the system clock: time-dependent adapters are built with the
//! `ManualClock` of `davhaven-ports`.

#![forbid(unsafe_code)]

pub mod auth;
pub mod clock;
pub mod event_sink;
pub mod hasher;
pub mod http_client;
pub mod ids;
pub mod keyring;
pub mod mail;
pub mod outbox;
pub mod policy;
pub mod profile_signer;
pub mod provider;
pub mod rate_limit;
pub mod scanner;
pub mod sealer;
pub mod store;
pub mod suite;
pub mod templates;

pub use suite::{CaseResult, Checks, ContractReport, Suite};
