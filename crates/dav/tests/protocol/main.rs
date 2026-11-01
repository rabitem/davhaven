//! Protocol tests of the DAV core over the fake of the application services (PLAN 3.1, L4): discovery, PROPFIND,
//! PROPPATCH, the object methods with their preconditions, MKCALENDAR and extended MKCOL, the reports, the limits,
//! the properties of the sync state machine, and the parts of the collaboration modules (principal search, the
//! rules of `POST`, the scheduling inbox) that the fake's principals and calendars are enough for.
//!
//! Every test sends HTTP requests through the router of the crate and reads the answers the way a client does. The
//! fake enforces the real permission rules (`domain::authz::decide`), keeps objects verbatim with strong ETags and
//! keeps a change log per calendar, so the status policy of PLAN 2.6 and the consistency contract of PLAN 2.7 are
//! exercised end to end. What the fake does not implement (sharing, scheduling, free-busy, filter evaluation) is
//! tested at the unit level of this crate and in the integration matrices on the real application.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

mod clients;
mod collaboration;
mod collections;
mod discovery;
mod hardening;
mod model;
mod objects;
mod permissions;
mod propfind;
mod proppatch;
mod reports;
mod support;
mod sync;
