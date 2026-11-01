//! The Model Context Protocol (MCP) server of Davhaven.
//!
//! Exposes calendar tools to Model Context Protocol clients over stateless streamable HTTP, authenticated with
//! principal-bound, scoped API tokens (PLAN 2.12). The tools and their input and output schemas come from
//! `davhaven-wire` and are stable (names never change, changes are additive); every tool acts as the person the token
//! belongs to through the application services, so permissions, scheduling, auditing, events, the safe form of what an
//! assistant may read and the per-token budgets are the services' and the same as over DAV and the management API.
//! What this crate adds is the protocol and the shape of a call and of its answer: a protocol crate decides nothing
//! (PLAN 2.6).
//!
//! # How a request flows
//!
//! ```text
//! POST /mcp ─ edge ─ origin check ─ bearer authentication ─ JSON-RPC check ─ rmcp transport
//!                                                                                │
//!                         McpServer: initialize · tools/list · tools/call ◄──────┘
//!                                                │ actor, scope, budget, arguments
//!                                                ▼
//!                             tools ──► application services ──► render (field mapping)
//! ```
//!
//! Failures are tool results with `isError: true` and the problem document in `_meta["davhaven/problem"]`; JSON-RPC
//! errors are for protocol faults only. The deployment-facing behaviour (static bearer tokens instead of MCP OAuth,
//! limits, budgets, what an assistant is shown) is documented in `docs/interop.md`.
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | The router of the `mcp` route group | [`mod@router`] |
//! | The `[mcp]` configuration | [`config`] |
//! | `Origin` validation | [`origin`] |
//! | The JSON-RPC check of a body | [`guard`] |
//! | The protocol handler and the server information | [`server`] |
//! | The tool catalog, scopes and implementations | [`tools`] |
//! | Reading the arguments of a call and their limits | [`input`] |
//! | The mapping of service views to the wire form of the tools | [`render`] |
//! | The person behind the token | [`caller`] |
//! | Failures as tool results | [`errors`] |

#![forbid(unsafe_code)]

pub mod caller;
pub mod config;
pub mod errors;
pub mod guard;
pub mod input;
pub mod origin;
pub mod render;
pub mod router;
pub mod server;
pub mod tools;

pub use router::router;
