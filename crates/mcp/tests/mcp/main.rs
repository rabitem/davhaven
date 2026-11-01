//! Protocol tests of the MCP server over the in-memory fake of the application services (PLAN 3.1, L4).
//!
//! | Module | What it checks |
//! | --- | --- |
//! | [`router`] | the mounting: bearer authentication, the person-token check, the exact `Origin` check, the methods of a stateless endpoint, the faults of a body that is no JSON-RPC message |
//! | [`protocol`] | the protocol: `initialize` and version negotiation, `ping`, notifications, `tools/list` per scope, protocol errors |
//! | [`tools`] | each tool: what it hands to the services, what it returns, the safety conventions, scopes and budgets |
//! | [`conformance`] | an independent client of the specification: the handshake, the committed tool catalog, every result against its announced schema |
//!
//! The doubles and the JSON-RPC client are in [`support`]; the validator the conformance tests use is in [`schema`].

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by the allow-*-in-tests settings of clippy.toml"
)]

mod conformance;
mod protocol;
mod router;
mod schema;
mod support;
mod tools;
