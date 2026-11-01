//! Outbound webhooks and event sinks.
//!
//! The `webhook` outbox handler delivers domain events following the Standard Webhooks specification (signed with
//! HMAC-SHA256, multiple signatures during secret rotation) with retries bounded by `webhooks.retry_window` and the
//! automatic disabling of subscriptions that keep failing; the `log` event sink writes domain events to the
//! structured log. [`signing::Verifier`] is the reference implementation of the receiving side.
//!
//! `docs/webhooks.md` describes the events, the request, the signature, the retries and how receivers verify.

#![forbid(unsafe_code)]

pub mod config;
pub mod log_sink;
pub mod plugin;
pub mod signing;
pub mod webhook;

#[cfg(test)]
mod support;
