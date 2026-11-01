//! Local implementation of the `Authenticator` port.
//!
//! Verifies server-generated credentials (app passwords, API tokens, feed tokens, RSVP tokens) with keyed HMAC
//! hashes in constant time, runs equal-cost dummy verifications for unknown prefixes and remembers successful
//! verifications under an HMAC of the presented secret. The formats of the credentials are not defined here but in
//! `davhaven_domain::credential_format`, which the application mints them with.

#![forbid(unsafe_code)]

pub mod authenticator;
pub mod cache;
pub mod config;
pub mod format;
pub mod plugin;

#[cfg(test)]
mod testing;
