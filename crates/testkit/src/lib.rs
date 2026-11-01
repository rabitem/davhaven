//! The Davhaven test harness.
//!
//! `TestApp` builds a complete application (memory or PostgreSQL store, manual clock, sequential ids) with
//! handles for every surface; transports run requests in process or against a base URL; the permission and
//! scheduling matrix harnesses and the client-flow runner execute the hand-reviewed expectations and scenario
//! files. Only the `it` and `conformance` crates use it.
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | An application to test against, with clock, ids, mails, events and workers | [`app`] |
//! | Requests to the DAV, API, MCP, feed and RSVP surfaces | [`handles`] |
//! | Carrying a request: in process or over HTTP | [`transport`] |
//! | Answers of a host that is too busy, and sending the request again | [`busy`] |
//! | The captured side effects (mails, domain events) | [`capture`] |
//! | What every role presents on every surface | [`credentials`] |
//! | Seeding the fixture world into the application | [`seed`] |
//! | The PostgreSQL databases of the harness | [`postgres`] |
//! | The state a test compares before and after a request | [`observe`] |
//! | The permission matrix and its expectations file | [`matrix`], [`permissions`] |
//! | The permission matrix as a document | [`report`] |
//! | Keeping secrets out of reports and errors | [`redact`] |
//! | What the matrix covers of the server's routes, methods and tools | [`coverage`] |
//! | The scheduling matrix | [`scheduling`] |
//! | Client-flow scenarios (YAML) and their runner | [`flow`] |
//! | Recorded DAV exchanges as scenarios | [`convert`] |
//! | The harness against a deployed instance | [`staging`] |
//! | XML trees and paths for assertions | [`xml`] |
//!
//! The fixture world (constant names, actors, calendars, credentials) is in `davhaven_fixtures`. The crates a test
//! needs are re-exported below, so `davhaven-it` depends on this crate alone.
//!
//! The documentation of the whole harness, including the expectations file format and the scenario schema, is in
//! `docs/testing.md`.

#![forbid(unsafe_code)]

pub mod app;
pub mod busy;
pub mod capture;
pub mod convert;
pub mod coverage;
pub mod credentials;
pub mod flow;
pub mod handles;
pub mod matrix;
pub mod observe;
pub mod permissions;
pub mod postgres;
pub mod redact;
pub mod report;
mod sample;
pub mod scheduling;
pub mod seed;
pub mod staging;
pub mod transport;
pub mod xml;

pub use app::{LimiterProfile, Served, StoreKind, TestApp, TestAppBuilder, TestAppError, WorkSummary};
pub use capture::{CapturedMail, EventCapture, MailCapture, Snapshot};
pub use credentials::{CredentialBook, credentials_of};
pub use flow::{Scenario, ScenarioEnv, ScenarioReport, load_scenarios, run_scenario};
pub use handles::{Actor, ApiHandle, DavHandle, FeedHandle, McpHandle, RsvpHandle, Token};
pub use matrix::{Case, Expectation, Expectations, Operation, Surface};
pub use observe::Observation;
pub use transport::{FnTransport, HttpTransport, InProcess, TestRequest, TestResponse, Transport, TransportError};

pub use axum;
pub use davhaven_app;
pub use davhaven_auth_local;
pub use davhaven_crypto_local;
pub use davhaven_dav;
pub use davhaven_domain;
pub use davhaven_fixtures;
pub use davhaven_hooks_webhook;
pub use davhaven_http;
pub use davhaven_http_egress;
pub use davhaven_mail_memory;
pub use davhaven_mcp;
pub use davhaven_port_tests;
pub use davhaven_ports;
pub use davhaven_provider_fake;
pub use davhaven_ratelimit_memory;
pub use davhaven_server;
pub use davhaven_store_memory;
pub use davhaven_templates;
pub use davhaven_wire;
pub use http;
