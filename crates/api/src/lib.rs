//! The management REST API of Davhaven (`/api/v1`).
//!
//! Provisioning of tenants, principals and memberships, credentials and client configuration, calendars, grants,
//! managed calendar objects (including batch upsert), changes feeds, webhooks, providers, audit events, outbox
//! inspection and the inbound iTIP endpoint. Every route is registered regardless of enabled features, so the
//! generated OpenAPI 3.1 document is identical for every build.
//!
//! # Structure
//!
//! Handlers are thin adapters: they extract typed keys, query parameters, conditional headers and bodies
//! ([`extract`]), call exactly one method of the application services, and build the response ([`reply`]).
//! Authentication is the bearer layer of `davhaven-http`, authorization is the application's (the services call
//! `domain::authz`), and every failure is an `EdgeProblem` rendered as RFC 9457 JSON ([`errors`]). Operations whose
//! service does not implement yet answer 501 `not-implemented` through that same path.
//!
//! The OpenAPI document ([`openapi::document`]) is generated from the registered routes; the route table
//! ([`openapi::ROUTES`]) gives every operation its scopes from the domain's decision point (`x-required-scope`).
//! `xtask contracts` writes the document to `docs/openapi.json`.
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | The router for the server | [`mod@router`] |
//! | The OpenAPI document and the route table | [`openapi`] |
//! | Mapping of application errors to problems | [`errors`] |
//! | Request extractors | [`extract`] |
//! | Tenants, principals, members | [`tenants`], [`principals`], [`members`] |
//! | App passwords, feed tokens, API tokens, client configuration | [`credentials`], [`tokens`], [`client_config`] |
//! | Calendars, bindings, grants, objects, changes | [`calendars`], [`bindings`], [`grants`], [`objects`], [`changes`] |
//! | Webhooks, providers, audit, outbox, inbound iTIP | [`webhooks`], [`providers`], [`audit`], [`outbox`], [`itip`] |

#![forbid(unsafe_code)]

pub mod audit;
pub mod bindings;
pub mod calendars;
pub mod changes;
pub mod client_config;
pub mod credentials;
pub mod errors;
pub mod extract;
pub mod grants;
pub mod itip;
pub mod members;
pub mod objects;
pub mod openapi;
pub mod outbox;
pub mod principals;
pub mod providers;
pub mod reply;
pub mod router;
pub mod tenants;
pub mod tokens;
pub mod webhooks;

pub use openapi::document;
pub use router::router;
