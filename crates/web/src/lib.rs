//! Public web endpoints of Davhaven.
//!
//! RSVP pages for external attendees (work without JavaScript, strict CSP), iCalendar subscription feeds, the
//! OAuth callback for calendar providers and static theme assets.
//!
//! # Structure
//!
//! The credential of every page is the token in its URL (RSVP and feed tokens), so the surface is built around
//! three rules: every refusal of a token is the same 404 page ([`errors::token_refusal`]), tokens never reach logs
//! or metric labels (the edge labels with route templates), and every response carries the security headers of
//! [`errors::add_security_headers`]. Handlers call exactly one method of the application services
//! (`rsvp_page`, `rsvp_answer`, `render`, `complete`); operations that are not implemented yet answer 501.
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | The router of the `web` route group | [`mod@router`] |
//! | RSVP page and answers | [`rsvp`] |
//! | Subscription feeds | [`feeds`] |
//! | OAuth callback | [`oauth`] |
//! | Theme assets | [`assets`] |
//! | Error pages, token refusals, security headers | [`errors`] |

#![forbid(unsafe_code)]

pub mod assets;
pub mod errors;
pub mod feeds;
pub mod oauth;
pub mod router;
pub mod rsvp;

pub use router::router;
