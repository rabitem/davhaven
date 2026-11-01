//! The DAV router: method dispatch on `axum::routing::any` routes.
//!
//! WebDAV defines methods axum has no names for (`PROPFIND`, `REPORT`, `MKCALENDAR`, ...), so every URL of the
//! namespace is an `any` route and the handler dispatches on `req.method()` (ADR-0001). The routes are the URL
//! layout of PLAN 2.5, each registered with and without the trailing slash:
//!
//! | Route | Resource |
//! | --- | --- |
//! | `/dav/` | entry point |
//! | `/dav/principals/{tenant}/{principal}/` | principal |
//! | `/dav/calendars/{tenant}/{principal}/` | calendar home |
//! | `/dav/calendars/{tenant}/{principal}/{binding}/` | calendar collection (a binding) |
//! | `/dav/calendars/{tenant}/{principal}/{binding}/{object}` | calendar object |
//! | `/dav/calendars/{tenant}/{principal}/inbox/`, `outbox/`, `notifications/` | scheduling and notification collections |
//! | `/dav/calendars/{tenant}/{principal}/inbox/{item}`, `notifications/{item}` | their members |
//!
//! Static segments (`inbox`, `outbox`, `notifications`) win over the `{binding}` parameter, which is also why
//! those names are reserved calendar slugs. Route templates are the metric and log labels, so the raw path, which
//! contains tenant and principal names, never becomes a label.
//!
//! Two routers serve the two route groups: [`router()`] (`dav`, behind Basic authentication, `OPTIONS` open) and
//! [`wellknown_router`] (`wellknown`, no authentication).

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::any;
use davhaven_app::AppServices;
use davhaven_http::{Edge, HeaderAuth, Surface, authenticate_header};

use crate::discovery::{WELL_KNOWN_PATH, well_known};
use crate::errors::DavProblems;
use crate::methods::dispatch;

/// The state of the handlers: the application services.
#[derive(Clone)]
pub(crate) struct DavState {
    pub(crate) services: AppServices,
}

/// The URL templates of the DAV namespace (without the trailing-slash variants).
pub const DAV_ROUTES: [&str; 10] = [
    "/dav",
    "/dav/principals/{tenant}/{principal}",
    "/dav/calendars/{tenant}/{principal}",
    "/dav/calendars/{tenant}/{principal}/inbox",
    "/dav/calendars/{tenant}/{principal}/outbox",
    "/dav/calendars/{tenant}/{principal}/notifications",
    "/dav/calendars/{tenant}/{principal}/inbox/{item}",
    "/dav/calendars/{tenant}/{principal}/notifications/{item}",
    "/dav/calendars/{tenant}/{principal}/{binding}",
    "/dav/calendars/{tenant}/{principal}/{binding}/{object}",
];

/// The DAV edge: the shared layers of `edge` for the DAV surface, with DAV error bodies and a body ceiling that
/// leaves room above `max_resource_size`: a `PUT` slightly over the limit reaches its handler, which answers 403
/// `CALDAV:max-resource-size` as RFC 4791 asks, while anything beyond the ceiling is refused with 413 before it is
/// read. The XML methods enforce `max_request_body` themselves.
///
/// `davhaven_http::body_ceiling` answers the larger of the two limits for the DAV surface, which would refuse that
/// `PUT` with 413 before its handler could answer 403; until the shared function says the sum, the ceiling is set
/// here (a point for the owner of `http`, noted in `docs/interop.md`).
fn dav_edge(edge: &Edge, services: &AppServices) -> Edge {
    let ceiling = services
        .limits
        .ical
        .max_resource_size
        .saturating_add(services.limits.dav.max_request_body);
    edge.for_surface(Surface::Dav)
        .with_renderer(Arc::new(DavProblems))
        .with_body_limit(usize::try_from(ceiling).unwrap_or(usize::MAX))
}

/// The DAV router for the `dav` route group.
///
/// Requests need HTTP Basic credentials (an app password) except `OPTIONS`, which clients send before they log in.
/// Unauthenticated requests answer 401 with `WWW-Authenticate: Basic realm="{tenant}", charset="UTF-8"`. `POST`
/// (sharing, the outbox), the items of the inbox and of the notification collection and the principal search
/// reports are served by the collaboration modules (see [`crate::methods`]).
pub fn router(services: AppServices, edge: &Edge) -> Router {
    let edge = dav_edge(edge, &services);
    let auth = HeaderAuth::dav(Arc::clone(&services.auth)).with_anonymous_methods(&["OPTIONS"]);
    let mut routes = Router::new();
    for template in DAV_ROUTES {
        routes = routes
            .route(template, any(dispatch))
            .route(&format!("{template}/"), any(dispatch));
    }
    let routes = routes
        .with_state(DavState { services })
        .route_layer(from_fn_with_state(auth, authenticate_header));
    edge.apply(routes)
}

/// The router of the `wellknown` route group: `/.well-known/caldav` redirects every method to `/dav/`, without
/// authentication.
pub fn wellknown_router(services: AppServices, edge: &Edge) -> Router {
    let edge = dav_edge(edge, &services);
    edge.apply(
        Router::new()
            .route(WELL_KNOWN_PATH, any(well_known))
            .with_state(DavState { services }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_templates_are_the_url_layout_of_the_plan() {
        assert_eq!(DAV_ROUTES.len(), 10);
        for template in DAV_ROUTES {
            assert!(template.starts_with("/dav"), "{template}");
            assert!(
                !template.ends_with('/'),
                "{template}: the slash variants are added by the router"
            );
        }
        assert!(DAV_ROUTES.contains(&"/dav/calendars/{tenant}/{principal}/{binding}/{object}"));
    }
}
