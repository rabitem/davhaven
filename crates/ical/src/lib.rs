//! iCalendar processing for Davhaven.
//!
//! Wraps the `calcard` parser entirely (no `calcard` type appears in any public API) and provides validation with
//! limits, serialization, object indexing, content hashing, timezone resolution (including Windows zone names),
//! recurrence expansion, CalDAV filters, free-busy computation, calendar-data projection, iTIP diff/build/apply,
//! busy stripping and merging of `EventData` into stored components.
//!
//! It performs no I/O; CPU-heavy entry points are called by the application inside `spawn_blocking`. Every
//! entry point enforces the limits of [`IcalLimits`], never loops without bound and never panics on any input.
//! The deterministic bound is the step budget (`max_iterator_steps`, counted per generated recurrence date) and
//! the structural limits; the wall-clock budget `time_budget_ms` is a second line of defence that is checked
//! between series, after every rule and every few hundred instances, and by the parser after it has read the
//! document. Exceeding it is a transient failure ([`LimitKind::TimeBudget`]), not invalid data.
//!
//! # Model
//!
//! [`ParsedCalendar`] is an opaque, immutable calendar object resource. The stored bytes of an object are
//! the client's bytes; the functions here only re-serialize what the server changes itself. Time zones resolve
//! IANA names, Windows names (the embedded CLDR table) and the observances of a `VTIMEZONE`; floating times and
//! all-day dates are read in UTC unless an `_in_zone` variant is used.

#![forbid(unsafe_code)]

pub mod busy;
pub mod error;
pub mod expand;
pub mod filter;
pub mod freebusy;
pub mod hash;
pub mod index;
pub mod itip;
pub mod merge;
pub mod parse;
pub mod projection;
pub mod serialize;
pub mod tz;
pub mod validate;

mod calendar;
mod matcher;
mod occurrence;
mod recur;
mod windows;
mod zones;

pub use calendar::contained_panics;
pub use davhaven_domain::IcalLimits;
pub use error::{ErrorContext, IcalError, LimitKind};
pub use parse::ParsedCalendar;
pub use validate::ValidatedObject;

/// The `PRODID` of everything this crate generates.
pub(crate) const PRODID: &str = "-//Davhaven//iCalendar//EN";
