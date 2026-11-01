//! A minimal in-memory implementation of the Davhaven service traits.
//!
//! Protocol crates (`dav`, `api`, `web`, `mcp`) use it in their tests before the real application is wired, so
//! they can be developed and tested independently. It covers principals, calendars, objects and authentication
//! with simple semantics; everything else answers `unsupported`.
//!
//! ```
//! use davhaven_app::services::{AuthRequest, AuthService, PresentedCredential, SecretString};
//! use davhaven_app::AppServices;
//! use davhaven_app_fake::AppServicesExt as _;
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! let services = AppServices::fake();
//! let request = AuthRequest {
//!     channel: davhaven_domain::Channel::Dav,
//!     tenant_hint: None,
//!     credential: PresentedCredential::Basic {
//!         username: "anna@acme.example".to_owned(),
//!         password: SecretString::from(davhaven_app_fake::seed::ANNA_PASSWORD),
//!     },
//!     client_ip: None,
//!     request_id: davhaven_domain::RequestId::from_uuid(uuid::Uuid::nil()),
//! };
//! let ctx = services.auth.authenticate(request).await.unwrap();
//! assert!(ctx.actor.is_authenticated());
//! # });
//! ```
//!
//! # What it implements
//!
//! * authentication of app passwords, API tokens, feed tokens and RSVP tokens ([`auth`]);
//! * principals with create-or-replace, merge patches, memberships, search and DAV properties ([`principals`]);
//! * calendar homes, collections, PROPPATCH and the management API's calendar resources ([`calendars`]);
//! * objects with verbatim bytes, ETags, preconditions, UID rules, a change log with sync tokens, the JSON event
//!   interface and batch upsert ([`objects`]).
//!
//! The sharing and scheduling services are not implemented. A test that wants to know what a protocol layer hands to
//! them swaps them for the recording double of [`recorder`].
//!
//! Permissions are the real ones: the fake asks `davhaven_domain::authz::decide` with facts computed from its
//! world. The [`seed`] module builds a standard world with constant names so tests need no setup;
//! [`FakeApp`] gives access to the world for assertions and for changing it between calls.
//!
//! The fake deliberately does not validate iCalendar beyond a minimal envelope, evaluate `calendar-query`
//! filters, expand recurrences, schedule or share. Everything it does not implement answers
//! `AppError::unsupported()`.

#![forbid(unsafe_code)]

use std::sync::Arc;

use chrono::DateTime;
use davhaven_app::AppServices;
use davhaven_app::services::AppClock;

pub mod auth;
pub mod calendars;
mod icaltext;
pub mod objects;
pub mod principals;
pub mod recorder;
pub mod seed;
pub mod state;
pub mod unsupported;

pub use state::{FakeState, FakeWorld};

use auth::FakeAuth;
use calendars::FakeCalendars;
use objects::FakeObjects;
use principals::FakePrincipals;
use unsupported::Unsupported;

/// The fake services together with the world they run on.
#[derive(Debug, Clone)]
pub struct FakeApp {
    /// The services protocol routers receive.
    pub services: AppServices,
    /// The shared world, for seeding and assertions.
    pub state: FakeState,
}

impl FakeApp {
    /// Builds the services on `world`.
    pub fn new(world: FakeWorld) -> Self {
        let urls = world.urls().clone();
        // One set of limits: the fake applies the ones of its world, and a protocol layer reads the same from the services.
        let limits = world.limits().clone();
        let state = FakeState::new(world);
        let services = AppServices {
            auth: Arc::new(FakeAuth::new(state.clone())),
            tenants: Arc::new(Unsupported),
            principals: Arc::new(FakePrincipals::new(state.clone())),
            calendars: Arc::new(FakeCalendars::new(state.clone())),
            objects: Arc::new(FakeObjects::new(state.clone())),
            sharing: Arc::new(Unsupported),
            scheduling: Arc::new(Unsupported),
            credentials: Arc::new(Unsupported),
            feeds: Arc::new(Unsupported),
            webhooks: Arc::new(Unsupported),
            external_accounts: Arc::new(Unsupported),
            audit: Arc::new(Unsupported),
            outbox: Arc::new(Unsupported),
            assets: Arc::new(Unsupported),
            idempotency: Arc::new(Unsupported),
            urls,
            limits,
            clock: AppClock::new({
                let state = state.clone();
                // The fake keeps its own deterministic clock; a test that wants another present replaces
                // `services.clock` (it is a plain field).
                move || state.try_now().unwrap_or(DateTime::UNIX_EPOCH)
            }),
        };
        Self { services, state }
    }

    /// The services on an empty world (no tenants, no principals).
    pub fn empty() -> Self {
        Self::new(FakeWorld::new())
    }

    /// The services on the standard world of [`seed`].
    pub fn standard() -> Self {
        Self::new(seed::standard_world())
    }
}

/// `AppServices::fake()`: the fake services on the standard world.
///
/// `AppServices` lives in `davhaven-app`, so the constructor is an extension trait; import it with
/// `use davhaven_app_fake::AppServicesExt as _;`.
pub trait AppServicesExt {
    /// The fake services on the standard world of [`seed`].
    fn fake() -> AppServices;

    /// The fake services on a world the caller built.
    fn fake_with(world: FakeWorld) -> AppServices;
}

impl AppServicesExt for AppServices {
    fn fake() -> AppServices {
        FakeApp::standard().services
    }

    fn fake_with(world: FakeWorld) -> AppServices {
        FakeApp::new(world).services
    }
}
