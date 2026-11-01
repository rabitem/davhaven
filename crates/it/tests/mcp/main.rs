//! The MCP server over the **real** application services on the in-memory store (PLAN 3.1, L4/L6).
//!
//! `crates/mcp/tests/mcp` tests the protocol layer over the fake application, whose services are doubles that answer
//! what a test scripts. What a double cannot honestly answer is tested here: every call goes through `davhaven_mcp::router`
//! over `davhaven_app::build`, with the production cryptography, the local authenticator that verifies the tokens the
//! credential service minted, the memory rate limiter and the memory store. The permissions are the services' (`decide`),
//! the visibility, the budgets, the tenant switch, the busy-only form of what is private to others and the idempotent
//! creation are the application's, and these tests are what keeps them so.
//!
//! | Module | What it checks |
//! | --- | --- |
//! | [`tools`] | every tool against the real services, a write-only token, creation that is made once, deletion of what is not there, cursors that belong to their search |
//! | [`privacy`] | private events of others as busy time (reads, searches, writes), what a text search cannot be used to read |
//! | [`isolation`] | other tenants and strangers see nothing (404, no detail, no side effect), foreign cursors, credential states |
//! | [`service`] | a service principal as the assistant: the token a tenant token mints through the management API (the exception for service principals), the calendars it is granted, and where the exception stops |
//! | [`budgets`] | the per-token budgets of the rate limiter port, their audit records, the tenant switch |
//! | [`client`] | an independent MCP client (the `rmcp` client) over a socket |
//!
//! The world and the JSON-RPC handle are in [`support`].

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "the helpers of an integration test crate are not covered by the allow-*-in-tests settings of clippy.toml"
)]
#![expect(
    clippy::too_many_lines,
    reason = "a scenario reads best from top to bottom; its steps share the state that the test builds up"
)]

mod budgets;
mod client;
mod isolation;
mod privacy;
mod service;
mod support;
mod tools;
