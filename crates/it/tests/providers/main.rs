//! Calendar providers on the real application: the OAuth flow over HTTP, the mirror calendar, the sync worker, the
//! disconnection of an account and who may do what.
//!
//! The application is the one `davhaven serve` builds (`TestApp`), on the in-memory store and on PostgreSQL, with a **fake
//! provider** whose remote world the tests write (`Script`): the calendars and events it holds, the tokens it has issued and
//! the calls it was told to fail. The management API starts a flow, the callback of the web surface ends it, the sync worker
//! pulls, and the API and DAV show what the mirror holds. The adapters of Google and Microsoft are tested against recorded
//! HTTP in their own crates; what they have in common with the fake is the contract suite of `davhaven-port-tests`.
//!
//! One test binary holds all of it, so that the shared world in [`support`] is compiled once.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    reason = "the helpers and scenarios of an integration test crate are not covered by the allowances for tests"
)]

mod support;

mod accounts;
mod connect;
mod sync;
