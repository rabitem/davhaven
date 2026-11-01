//! Shared HTTP edge layers for the Davhaven protocol routers.
//!
//! Request ids, client IP resolution behind trusted proxies, tenant resolution, authentication, rate limiting,
//! body and header limits, tracing with token redaction, RFC 9457 problem rendering and the CORS policy. Every
//! protocol router (`dav`, `api`, `web`, `mcp`) is mounted behind these layers.
//!
//! # Using the edge
//!
//! A protocol crate builds its router, adds its authentication inside it and wraps it once:
//!
//! ```text
//! let routes = Router::new().route(...).layer(from_fn_with_state(HeaderAuth::api(auth), authenticate_header));
//! let router = edge.apply(routes);            // request id, tracing, problems, limits, origin guard, ...
//! ```
//!
//! [`edge::Edge`] holds the shared stack, configured once by the server from `[server]` and `[security]` and
//! cloned per route group. Failures are never rendered where they happen: edge layers, extractors and handlers
//! return a [`problem::EdgeProblem`], and the surface's [`problem::ProblemRenderer`] gives it its wire form (RFC 9457
//! JSON, DAV XML, an HTML page), so that every error of a surface looks the same and carries the request id.
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | The whole stack for a surface | [`edge`] |
//! | Errors as responses, renderers, the hook of a surface | [`problem`] |
//! | `X-Request-Id` | [`request_id`] |
//! | Route-template labels, metrics, the request log line | [`trace`] |
//! | Trusted proxies and the client address | [`client_ip`] |
//! | Header credentials, the `RequestContext` extractor, challenges | [`auth`] |
//! | The tenant named by a path | [`tenant`] |
//! | Body ceilings, timeouts, load shedding | [`limits`] |
//! | `Origin` guard and CORS | [`cors`] |
//! | `Retry-After` | [`rate_limit`] |
//! | Token redaction | [`redact`] |

#![forbid(unsafe_code)]

pub mod auth;
pub mod client_ip;
pub mod cors;
pub mod edge;
pub mod limits;
pub mod problem;
pub mod rate_limit;
pub mod redact;
pub mod request_id;
pub mod surface;
pub mod tenant;
pub mod trace;

pub use auth::{Authenticated, HeaderAuth, authenticate_header};
pub use edge::{Edge, EdgeSettings};
pub use problem::{EdgeProblem, JsonProblems, ProblemRenderer};
pub use request_id::{RequestIdSource, SequentialRequestIds};
pub use surface::Surface;
