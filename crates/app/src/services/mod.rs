//! Service traits, their DTOs and the `AppServices` bundle handed to protocol routers.
//!
//! This is the inbound API of the application (PLAN F0.5). One trait per area; every method is `async`, takes the
//! `RequestContext` of the caller first and returns [`AppResult`](crate::error::AppResult). Protocol crates
//! (`dav`, `api`, `web`, `mcp`) receive an [`AppServices`] and nothing else: they never see ports or adapters.
//!
//! | Trait | Area | Main callers |
//! | --- | --- | --- |
//! | [`AuthService`] | credentials to `RequestContext` | `http` |
//! | [`TenantService`] | tenant provisioning | `api` |
//! | [`PrincipalService`] | principals, groups, search, DAV principal properties | `dav`, `api` |
//! | [`CalendarService`] | homes, bindings, collections, PROPPATCH, calendar resources | `dav`, `api`, `mcp` |
//! | [`ObjectService`] | objects, queries, sync, JSON events, batch | `dav`, `api`, `mcp` |
//! | [`SharingService`] | CalendarServer sharing, grants, notifications | `dav`, `api` |
//! | [`SchedulingService`] | free-busy, outbox, inbox, respond, RSVP, inbound iTIP | `dav`, `api`, `mcp`, `web` |
//! | [`CredentialService`] | app passwords, API tokens, feed tokens, client config | `api` |
//! | [`FeedService`] | subscription feeds | `web` |
//! | [`WebhookService`] | outbound webhook subscriptions | `api` |
//! | [`ExternalAccountService`] | provider accounts and OAuth | `api`, `web` |
//! | [`AuditService`] | audit log | `api` |
//! | [`OutboxService`] | dead outbox items | `api` |
//! | [`AssetService`] | static theme assets (style sheet, logo) | `web` |
//! | [`IdempotencyService`] | `Idempotency-Key` bookkeeping | `api` |
//!
//! The DTOs live next to their trait. Management API bodies and views are the types of `davhaven-wire`; DAV
//! resources use the DTOs of this module (`BindingView`, `CollectionView`, `ObjectView`, ...).
//!
//! # Conventions
//!
//! * Resources that are invisible to the caller, including other tenants', answer `NotFound`; visible but not
//!   permitted is `Forbidden` (PLAN 2.6). The services decide through `domain::authz::decide`; protocol crates
//!   never decide.
//! * Writes of mutable API resources take [`Conditions`] (`If-Match`, `If-None-Match: *`) and return the new
//!   `version` in the view; `PATCH` takes a [`MergePatch`].
//! * Listings take a [`PageRequest`] and return `davhaven_wire::Page`.
//! * New methods are added with a default body that returns `Unsupported` (PLAN 4.4); changing an existing
//!   signature affects every implementation.

pub mod assets;
pub mod audit;
pub mod auth;
pub mod calendars;
pub mod common;
pub mod credentials;
pub mod external_accounts;
pub mod feeds;
pub mod idempotency;
pub mod objects;
pub mod outbox;
pub mod principals;
pub mod scheduling;
pub mod sharing;
pub mod tenants;
pub mod time;
pub mod webhooks;

use core::fmt;
use std::sync::Arc;

use davhaven_domain::{Limits, PublicUrls};

pub use assets::*;
pub use audit::*;
pub use auth::*;
pub use calendars::*;
pub use common::*;
pub use credentials::*;
pub use davhaven_ical::filter::{CalendarFilter, TimeRange};
pub use davhaven_ical::freebusy::{BusyKind, BusyPeriod};
pub use davhaven_ical::projection::Projection;
pub use davhaven_wire::ChangeKind;
pub use external_accounts::*;
pub use feeds::*;
pub use idempotency::*;
pub use objects::*;
pub use outbox::*;
pub use principals::*;
pub use scheduling::*;
pub use secrecy::{ExposeSecret, SecretString};
pub use sharing::*;
pub use tenants::*;
pub use time::*;
pub use webhooks::*;

/// Every service of the application plus the values protocol routers need to build links and enforce limits.
///
/// This is the only state a protocol router receives. It is cheap to clone (reference counts). `app::build`
/// creates it from the ports; `davhaven-app-fake` creates one with in-memory semantics for protocol tests.
#[derive(Clone)]
pub struct AppServices {
    /// Authentication.
    pub auth: Arc<dyn AuthService>,
    /// Tenant provisioning.
    pub tenants: Arc<dyn TenantService>,
    /// Principals and memberships.
    pub principals: Arc<dyn PrincipalService>,
    /// Calendars and collections.
    pub calendars: Arc<dyn CalendarService>,
    /// Calendar objects.
    pub objects: Arc<dyn ObjectService>,
    /// Sharing, grants and notifications.
    pub sharing: Arc<dyn SharingService>,
    /// Scheduling, RSVP and inbound iTIP.
    pub scheduling: Arc<dyn SchedulingService>,
    /// Credentials and client configuration.
    pub credentials: Arc<dyn CredentialService>,
    /// Subscription feeds.
    pub feeds: Arc<dyn FeedService>,
    /// Webhook subscriptions.
    pub webhooks: Arc<dyn WebhookService>,
    /// Provider accounts and OAuth.
    pub external_accounts: Arc<dyn ExternalAccountService>,
    /// The audit log.
    pub audit: Arc<dyn AuditService>,
    /// The outbox.
    pub outbox: Arc<dyn OutboxService>,
    /// Static theme assets.
    pub assets: Arc<dyn AssetService>,
    /// Idempotency keys.
    pub idempotency: Arc<dyn IdempotencyService>,
    /// Absolute URLs for mails, feeds and client configuration; never derived from the `Host` header.
    pub urls: PublicUrls,
    /// The configured limits (iCalendar, DAV, API).
    pub limits: Limits,
    /// The clock of the application, read-only: the present for the defaults of a call (MCP `search_events`
    /// starts now). Protocol crates cannot reach the `Clock` port, and read the time here.
    pub clock: AppClock,
}

impl AppServices {
    /// The present, as the application's clock tells it.
    pub fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.clock.now()
    }
}

impl fmt::Debug for AppServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppServices")
            .field("urls", &self.urls)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_sync_clone<T: Send + Sync + Clone + 'static>() {}

    #[test]
    fn the_bundle_can_be_shared_between_tasks() {
        send_sync_clone::<AppServices>();
    }

    #[test]
    fn service_traits_are_object_safe_and_thread_safe() {
        fn object_safe<T: ?Sized + Send + Sync>() {}
        object_safe::<dyn AuthService>();
        object_safe::<dyn TenantService>();
        object_safe::<dyn PrincipalService>();
        object_safe::<dyn CalendarService>();
        object_safe::<dyn ObjectService>();
        object_safe::<dyn SharingService>();
        object_safe::<dyn SchedulingService>();
        object_safe::<dyn CredentialService>();
        object_safe::<dyn FeedService>();
        object_safe::<dyn WebhookService>();
        object_safe::<dyn ExternalAccountService>();
        object_safe::<dyn AuditService>();
        object_safe::<dyn OutboxService>();
        object_safe::<dyn IdempotencyService>();
    }
}
