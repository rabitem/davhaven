//! Implementation of the `HttpClient` port: the only place in Davhaven that talks HTTP to the outside.
//!
//! The egress policy allows https only, denies private, loopback, link-local and metadata address ranges after DNS
//! resolution, follows no redirects and enforces timeouts and response size caps. A recording fake supports
//! tests.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod plugin;
pub mod policy;
pub mod recording;
pub mod resolver;
