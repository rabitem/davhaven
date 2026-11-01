//! In-memory implementation of the `MailTransport` port.
//!
//! Captures every mail as structured data and as MIME bytes for tests and development.

#![forbid(unsafe_code)]

pub mod config;
pub mod plugin;
pub mod transport;
