//! SMTP implementation of the `MailTransport` port based on `lettre` with rustls (ring provider).

#![forbid(unsafe_code)]

pub mod config;
pub mod plugin;
pub mod transport;
