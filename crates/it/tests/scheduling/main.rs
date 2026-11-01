//! Server-side scheduling (PLAN 2.8, 2.13, 3.3) on the real application over the in-memory store.
//!
//! These are the application-level tests (PLAN 3.1, L3) of server-side scheduling: the organizer's and the attendee's
//! writes through DAV, the management API and MCP, delivery to internal attendees and iMIP mail to external ones,
//! the answers through the three channels (a calendar client, the RSVP page, the inbound iTIP endpoint), the
//! policy, free-busy and the scheduling collections. The expected results are written down from the rules of the
//! plan, not computed from the code under test. The scheduling matrix (`matrix`) runs the cases of
//! `davhaven_testkit::scheduling` against the decision table in `table`.
//!
//! One test binary holds all of it, so that the shared world in [`support`] is compiled once.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]
#![expect(
    clippy::too_many_lines,
    reason = "a scenario reads best from top to bottom; its steps share the state that the test builds up"
)]

mod support;

mod calendars;
mod copies;
mod external;
mod freebusy;
mod inbound;
mod integrity;
mod internal;
mod limits;
mod matrix;
mod policy;
mod queue;
mod resources;
mod shared_busy;
mod surfaces;
mod table;
mod tenants;
mod unscheduled;
