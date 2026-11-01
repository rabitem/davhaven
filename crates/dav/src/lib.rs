//! The WebDAV/CalDAV router of Davhaven.
//!
//! Implements RFC 4918, 4791, 6578, 6638 and the CalendarServer extensions used by Apple Calendar on top of the
//! application services: discovery, PROPFIND/PROPPATCH, object methods with preconditions, MKCALENDAR and extended
//! MKCOL, reports (calendar-query, multiget, sync-collection, free-busy, expand-property), sharing,
//! notifications, scheduling inbox/outbox and principal search. DAV XML is parsed with a hardened `quick-xml`
//! reader into typed requests and written with a hand-written escaping writer.
//!
//! # State of the crate
//!
//! The DAV core is implemented: discovery, `PROPFIND`, `PROPPATCH` of binding properties, `GET`, `HEAD`, `PUT`,
//! `DELETE`, `MOVE` and `COPY` of calendar objects with the conditional headers of PLAN 2.7, `MKCALENDAR` and
//! extended `MKCOL`, and the reports `calendar-query`, `calendar-multiget`, `sync-collection`, `free-busy-query` and
//! `expand-property`, with `Prefer: return=minimal`, the limits of PLAN 2.15 and the mapping of every application
//! error to its DAV status and precondition element ([`errors`]). The collaboration modules are implemented too:
//! CalendarServer sharing ([`sharing`]), the notification collection ([`notifications`]), the scheduling inbox and
//! outbox with `Schedule-Tag` ([`scheduling`]) and principal search ([`principals_search`]); the hooks of
//! `methods::collaboration` route requests to them. Methods a resource does not define answer 405, paths that name
//! no resource and resources the caller cannot see answer 404.
//!
//! # Bounds
//!
//! Requests are bounded the way PLAN 2.15 and R6 ask: XML bodies are read on the blocking pool under a time budget
//! with limits on size, structure, names and namespaces ([`xml`]); answers stop at `max_response_bytes` with a 507
//! entry for the request URI; dead properties and the properties a request names are counted.
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | The routers of the `dav` and `wellknown` route groups | [`mod@router`] |
//! | Method dispatch, the method table and the handlers | [`methods`] |
//! | The well-known redirect and principal discovery | [`discovery`] |
//! | The properties of every resource and the values of PROPPATCH | [`props`] |
//! | `calendar-query`, `calendar-multiget`, `free-busy-query`, `expand-property` | [`reports`] |
//! | `sync-collection` | [`sync`] |
//! | `CS:share`, `CS:invite-reply`, `CS:shared-as` | [`sharing`] |
//! | The notification collection and its resources | [`notifications`] |
//! | The scheduling inbox and outbox | [`scheduling`] |
//! | `Schedule-Tag`, `If-Schedule-Tag-Match`, `Schedule-Reply` | the object methods and headers of [`methods`], the property in [`props`] |
//! | `DAV:principal-property-search`, `CS:calendarserver-principal-search` | [`principals_search`] |
//! | Hardened XML parsing, typed requests and the writer | [`xml`] |
//! | DAV status codes and `DAV:error` bodies | [`errors`] |

#![forbid(unsafe_code)]

pub mod discovery;
pub mod errors;
pub mod methods;
pub mod notifications;
pub mod principals_search;
pub mod props;
pub mod reports;
pub mod router;
pub mod scheduling;
pub mod sharing;
pub mod sync;
#[cfg(test)]
mod testing;
pub mod xml;

pub use router::{router, wellknown_router};
