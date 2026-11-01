//! The outbox, the webhook service, the iMIP composer and the webhook adapter on the in-memory store.
//!
//! These are the application-level tests of the outbox (PLAN 3.1, L3). They run the real dispatcher, services and
//! handlers over `store-memory`, the same store the contract suite checks, so the behavior they rely on (the
//! claim and its lease, `PreconditionFailed` for a settled record, one delivery per subscription and event, tenant
//! isolation, the one-transaction-per-task rule that shows up here as a hang) is the store's and not a test
//! double's. The ports that are not under test are small scripted doubles of one port each: the mail transport,
//! the HTTP client, the template renderer, the calendar backend, the rate limiter, an event sink.
//!
//! One test binary holds all of it, so that the shared world in [`support`] is compiled once.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

mod support;

mod dispatcher;
mod fan_out;
mod imip_mail;
mod imip_templates;
mod operators;
mod rsvp_links;
mod webhook_delivery;
mod webhook_service;
