//! The application layer of Davhaven.
//!
//! [`services`] defines the inbound application API (one trait per service, all taking a `RequestContext` and
//! returning [`AppError`]); the other modules implement the use cases on top of the ports: authorization fact
//! loading, calendars, objects, sharing, principals, provisioning, managed calendars, feeds, credentials,
//! idempotency, audit, scheduling and iTIP, RSVP, inbound iTIP, the outbox dispatcher and iMIP composer, the
//! provider sync engine, retention, background workers and the operator tasks of the administrative commands
//! (system tokens, the resealing of stored secrets).
//!
//! Protocol crates receive only [`AppServices`]; they never see ports or adapters. The server builds the ports,
//! collects them in [`AppDeps`] and calls [`build`].
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | The service traits and their DTOs | [`services`] |
//! | The error type of every service method | [`error`] |
//! | Configuration owned by the application | [`config`] |
//! | Dependencies and construction | [`wiring`] |
//! | Retention and the workers the server supervises | [`retention`], [`workers`] |
//! | System tokens and key rotation (`davhaven admin ...`) | [`maintenance`] |
//!
//! Until a service implements a method, it answers `AppError::unsupported()` (`ENGINEERING_RULES` R5).

#![forbid(unsafe_code)]

pub mod addresses;
pub mod assets;
pub mod audit;
pub mod authz;
pub mod calendars;
pub mod config;
pub mod credentials;
pub mod error;
pub mod feeds;
pub mod idempotency;
pub mod imip;
pub mod inbound;
pub mod itip;
pub mod maintenance;
pub mod managed;
pub mod oauth;
pub mod objects;
pub mod outbox;
pub(crate) mod paging;
pub mod policy;
pub mod principals;
pub mod provisioning;
pub mod retention;
pub mod rsvp;
pub mod scheduling;
pub mod services;
pub mod sharing;
pub mod sync_engine;
pub(crate) mod texts;
pub mod wiring;
pub mod workers;

pub use config::AppConfig;
pub use error::{AppError, AppResult, FieldError, SafeMessage};
pub use services::AppServices;
pub use wiring::{AppCore, AppDeps, build, build_from_core};
