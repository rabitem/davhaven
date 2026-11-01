//! The caller of a tool: the authenticated context and what the tools need to know about the person behind it.
//!
//! Every tool acts as the principal of the token, through the same services and the same decision as DAV and the
//! management API (PLAN 2.6). A few results are described from the person's point of view: whether the person organizes
//! an event and which answer they gave (that needs the person's calendar user addresses), and `list_calendars` needs
//! the name of the person's home. The person is read with `PrincipalService::current` when the first of those needs
//! it, once per call, and never otherwise: most events carry no people, a write-only token's tools need nothing but the
//! write, and `free_busy` needs nobody. The request context carries ids only, so nothing here is derivable from it, and
//! nothing is guessed in its place: a service that does not implement `current` (it answers `Unsupported`) makes the tools
//! that describe people fail with the problem `not-implemented`, because a wrong `organizer_is_me` is worse than an
//! error.
//!
//! What an assistant may see is the application's to say, not this layer's: the views it hands back are the safe ones
//! (`davhaven-app` `objects::sight`), and `current` reads no calendar, so it needs no scope.

use davhaven_app::services::PrincipalProps;
use davhaven_app::{AppResult, AppServices};
use davhaven_domain::{CalendarUserAddress, RequestContext};
use davhaven_wire::EventView;
use davhaven_wire::mcp::McpEvent;
use tokio::sync::OnceCell;

use crate::render;

/// The caller of one tool call.
pub struct Caller<'a> {
    /// The authenticated context of the request; every service call is made with it.
    pub ctx: RequestContext,
    /// The application services, shared by every call.
    pub services: &'a AppServices,
    me: OnceCell<PrincipalProps>,
}

impl<'a> Caller<'a> {
    /// The caller of a request.
    pub fn new(ctx: RequestContext, services: &'a AppServices) -> Self {
        Self {
            ctx,
            services,
            me: OnceCell::new(),
        }
    }

    /// The person behind the token, read on first use.
    ///
    /// # Errors
    ///
    /// The error of the principal service, for example `Unauthenticated` for a context that acts as no principal and
    /// `Unsupported` for a service that does not implement `current`.
    pub async fn me(&self) -> AppResult<&PrincipalProps> {
        self.me
            .get_or_try_init(|| self.services.principals.current(&self.ctx))
            .await
    }

    /// The events in the wire form of the tools. The person is read only when an event says something about people.
    ///
    /// # Errors
    ///
    /// The errors of [`Caller::me`] and of [`render::event`].
    pub async fn events(&self, views: Vec<EventView>, include_attendees: bool) -> AppResult<Vec<McpEvent>> {
        let me: &[CalendarUserAddress] = if views.iter().any(render::needs_viewer) {
            &self.me().await?.addresses
        } else {
            &[]
        };
        views
            .into_iter()
            .map(|view| render::event(view, me, include_attendees))
            .collect()
    }

    /// One event in the wire form of the tools (see [`Caller::events`]).
    ///
    /// # Errors
    ///
    /// The errors of [`Caller::events`].
    pub async fn event(&self, view: EventView, include_attendees: bool) -> AppResult<McpEvent> {
        let me: &[CalendarUserAddress] = if render::needs_viewer(&view) {
            &self.me().await?.addresses
        } else {
            &[]
        };
        render::event(view, me, include_attendees)
    }
}
