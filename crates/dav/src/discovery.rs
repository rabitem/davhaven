//! Well-known redirect, principal discovery and current-user-principal.
//!
//! `/.well-known/caldav` (RFC 6764) answers **301** to the DAV entry point `/dav/` for every method, without
//! authentication: clients follow the redirect with the method they started with and authenticate at the target.
//! The target is built from `PublicUrls` (`server.public_base_url`, or the DAV base URL when DAV lives on another
//! origin), never from the `Host` header. The route group `wellknown` is separate from `dav` so that a deployment can
//! serve the redirect on a different listener (PLAN 2.5).
//!
//! The discovery that follows is a chain of PROPFINDs that every client runs the same way:
//!
//! 1. `PROPFIND /dav/` asks for `DAV:current-user-principal` (`current_principal` finds the principal the request
//!    is authenticated as);
//! 2. `PROPFIND` of that principal asks for `C:calendar-home-set`, `C:calendar-user-address-set` and the URLs of
//!    the scheduling inbox and outbox;
//! 3. `PROPFIND` of the home with `Depth: 1` lists the calendars with their names, colors and `supported-calendar-component-set`.
//!
//! The properties are rendered by [`crate::props`], the PROPFIND handler is in [`crate::methods`].

use axum::body::Body;
use axum::extract::State;
use axum::http::header::LOCATION;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use davhaven_app::services::PrincipalProps;
use davhaven_domain::ErrorKind;
use davhaven_http::problem::EdgeProblem;

use crate::methods::Call;
use crate::router::DavState;
use crate::xml::requests::PropRequest;

/// The path of the well-known resource.
pub const WELL_KNOWN_PATH: &str = "/.well-known/caldav";

/// Answers every method with a permanent redirect to the DAV entry point.
pub(crate) async fn well_known(State(state): State<DavState>) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
    if let Ok(location) = HeaderValue::from_str(state.services.urls.dav_root().as_str()) {
        response.headers_mut().insert(LOCATION, location);
    }
    response
}

/// The principal the request is authenticated as, when the request needs it (`current-user-principal` asked for by
/// name, `principal-URL` of the entry point, or `propname`; see `needs_current_principal`).
///
/// Contexts that act as no principal have none, and the property is then simply absent. So is the property when
/// the service cannot tell (`Unsupported`): the one property answers 404 in its `propstat`, where failing the whole
/// multistatus would make a client give up at the first step of its discovery.
///
/// # Errors
///
/// The problem of the service when it fails for any other reason.
pub(crate) async fn current_principal(
    call: &Call<'_>,
    request: &PropRequest,
) -> Result<Option<PrincipalProps>, EdgeProblem> {
    if !crate::props::needs_current_principal(request, call.resource) {
        return Ok(None);
    }
    match call.services().principals.current(call.ctx).await {
        Ok(principal) => Ok(Some(principal)),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::Unauthenticated | ErrorKind::NotFound | ErrorKind::Unsupported
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(EdgeProblem::from(error)),
    }
}
