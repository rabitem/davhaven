//! The environments the permission matrix runs against.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::PrincipalName;
use davhaven_fixtures::{ActorRole, CalendarRole, FixtureWorld, feed_token_secret};
use davhaven_ports::{StoreError, TxMode};

use super::McpIds;
use crate::app::{TestApp, TestAppBuilder, TestAppError};
use crate::credentials::CredentialBook;
use crate::observe::Observation;
use crate::seed::mint_feed_token;
use crate::transport::{FnTransport, TestRequest, TestResponse, Transport};

/// Whether an environment can give every case that changes something a world of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// [`MatrixEnv::fresh`] makes a new world for every case that is allowed to change something.
    PerCase,
    /// It cannot (or must not, because it is expensive): the cases that change something are left out.
    Unavailable,
}

/// An application with its fixture world, its credentials and a way to look at its state.
#[async_trait]
pub trait MatrixEnv: Send + Sync {
    /// The world the application was seeded with.
    fn world(&self) -> &FixtureWorld;

    /// The credentials of the roles.
    fn book(&self) -> &CredentialBook;

    /// Carries the requests of the cases.
    fn transport(&self) -> Arc<dyn Transport>;

    /// The state of the application, to compare before and after a request.
    async fn observe(&self) -> Result<Observation, String>;

    /// A new environment in the state of a freshly seeded world.
    async fn fresh(&self) -> Result<Box<dyn MatrixEnv>, String>;

    /// Whether cases that change something get an environment of their own ([`MatrixEnv::fresh`]); an environment that
    /// cannot offer one has those cases left out of the run and reported as skipped.
    fn isolation(&self) -> Isolation {
        Isolation::PerCase
    }

    /// Whether several worlds made by [`MatrixEnv::fresh`] can be in use at the same time. A deployed instance has one
    /// world, which a reset replaces, so its cases run one after the other.
    fn parallel_worlds(&self) -> bool {
        true
    }

    /// The origin that browsers of this environment send with form posts (`scheme://host[:port]`): the one the instance is
    /// reached at, which the same-origin check of unsafe requests compares with the `Host` header.
    fn origin(&self) -> String {
        crate::app::PUBLIC_BASE_URL.to_owned()
    }

    /// Whether the inbound iTIP endpoint is switched on: `Some(true)` when it is (the endpoint takes a message), `Some(false)` when
    /// it is not (it answers 409 `feature-not-enabled`), `None` when the environment cannot tell (a deployed instance).
    fn inbound_itip(&self) -> Option<bool> {
        Some(true)
    }

    /// Whether a case may delete the tenant of the world. A deployed instance builds the world again inside the same two
    /// tenants, so a case that deletes one would end the run.
    fn may_delete_tenants(&self) -> bool {
        true
    }

    /// Whether the state is observed around requests that only read. Observing is cheap in process and costs requests on
    /// a deployed instance, where the matrices look at the state around the requests that can change it.
    fn observes_reads(&self) -> bool {
        true
    }

    /// Whether the environment has the calendar of the role (a deployed instance cannot make a mirror calendar).
    fn has_calendar(&self, _role: CalendarRole) -> bool {
        true
    }

    /// The ids MCP tools address the calendar and its event by.
    async fn mcp_ids(&self, calendar: CalendarRole) -> Result<McpIds, String>;

    /// A feed token of the actor for the calendar, made even when the actor has no access to it (the application checks
    /// access on every request); `None` for roles that are no principal.
    async fn feed_token(&self, actor: ActorRole, calendar: CalendarRole) -> Result<Option<String>, String>;

    /// The UID of the invitation that the pending sharee has not answered.
    async fn invitation_uid(&self) -> Result<Option<String>, String>;
}

/// The in-process application as an environment.
pub struct AppEnv {
    app: TestApp,
    factory: Arc<dyn Fn() -> TestAppBuilder + Send + Sync>,
}

impl AppEnv {
    /// Builds an application with `factory` and uses it as the environment; [`MatrixEnv::fresh`] builds another one
    /// with the same factory.
    ///
    /// # Errors
    ///
    /// The message of the error that built the application.
    pub async fn new(factory: impl Fn() -> TestAppBuilder + Send + Sync + 'static) -> Result<Self, String> {
        let factory: Arc<dyn Fn() -> TestAppBuilder + Send + Sync> = Arc::new(factory);
        let app = TestApp::build_with_retries({
            let factory = Arc::clone(&factory);
            move || factory()
        })
        .await
        .map_err(|error| error.to_string())?;
        Ok(Self { app, factory })
    }

    /// The application.
    pub const fn app(&self) -> &TestApp {
        &self.app
    }
}

#[async_trait]
impl MatrixEnv for AppEnv {
    fn world(&self) -> &FixtureWorld {
        self.app.world()
    }

    fn book(&self) -> &CredentialBook {
        self.app.book()
    }

    fn transport(&self) -> Arc<dyn Transport> {
        self.app.transport()
    }

    async fn observe(&self) -> Result<Observation, String> {
        // Reading the state is a read: a store that is slow for a moment (a PostgreSQL server shared with other test processes) is
        // asked again before the run says that the state cannot be observed.
        let mut attempt = 1_u32;
        loop {
            match self.app.observe().await {
                Ok(observation) => return Ok(observation),
                Err(error) if attempt < 3 && error.to_string().contains("Timeout") => {
                    tokio::time::sleep(core::time::Duration::from_millis(500 * u64::from(attempt))).await;
                    attempt += 1;
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    async fn fresh(&self) -> Result<Box<dyn MatrixEnv>, String> {
        // A server that is busy with other databases drops a connection or times out now and then: a world is made again before
        // the run says that it cannot be made.
        let factory = Arc::clone(&self.factory);
        let app = TestApp::build_with_retries(move || factory())
            .await
            .map_err(|error| error.to_string())?;
        Ok(Box::new(Self {
            app,
            factory: Arc::clone(&self.factory),
        }))
    }

    fn inbound_itip(&self) -> Option<bool> {
        Some(self.app.config().scheduling.inbound_itip.enabled)
    }

    async fn mcp_ids(&self, calendar: CalendarRole) -> Result<McpIds, String> {
        let world = self.app.world();
        let fixture = world.calendar(calendar).map_err(|error| error.to_string())?;
        let event = world.event(calendar).map_err(|error| error.to_string())?;
        let calendar_id = self
            .app
            .index()
            .calendars
            .get(&fixture.key)
            .copied()
            .ok_or_else(|| format!("the calendar `{}` is not seeded", fixture.key.slug))?;
        let tenant = self
            .app
            .tenant_id(fixture.key.tenant.as_str())
            .ok_or_else(|| "the tenant is not seeded".to_owned())?;
        let mut tx = self
            .app
            .deps()
            .database
            .begin(tenant, TxMode::ReadOnly)
            .await
            .map_err(|error| error.to_string())?;
        let object = tx
            .objects()
            .get(calendar_id, &event.uri)
            .await
            .map_err(|error| error.to_string())?;
        tx.commit().await.map_err(|error| error.to_string())?;
        Ok(McpIds {
            calendar_id: calendar_id.to_string(),
            event_id: object.id.to_string(),
        })
    }

    async fn feed_token(&self, actor: ActorRole, calendar: CalendarRole) -> Result<Option<String>, String> {
        let world = self.app.world();
        let Ok(principal) = world.principal(actor) else {
            return Ok(None);
        };
        let fixture = world.calendar(calendar).map_err(|error| error.to_string())?;
        let calendar_id = self
            .app
            .index()
            .calendars
            .get(&fixture.key)
            .copied()
            .ok_or_else(|| format!("the calendar `{}` is not seeded", fixture.key.slug))?;
        let tenant = self
            .app
            .tenant_id(principal.tenant.as_str())
            .ok_or_else(|| "the tenant is not seeded".to_owned())?;
        let principal_id = self
            .app
            .index()
            .principal(principal.tenant.as_str(), principal.name.as_str())
            .ok_or_else(|| "the principal is not seeded".to_owned())?;
        let secret = feed_token_secret(&format!("matrix:{actor}:{calendar}"));
        match mint_feed_token(self.app.deps(), tenant, principal_id, vec![calendar_id], &secret).await {
            Ok(()) => Ok(Some(secret)),
            // A calendar of another tenant cannot be put into a feed: there is no such feed.
            Err(TestAppError::Store(StoreError::NotFound)) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn invitation_uid(&self) -> Result<Option<String>, String> {
        let ctx = self
            .app
            .login(ActorRole::PendingSharee)
            .await
            .map_err(|error| error.to_string())?;
        let name = PrincipalName::parse(davhaven_fixtures::names::PENDING_SHAREE).map_err(|error| error.to_string())?;
        let notifications = self
            .app
            .services()
            .sharing
            .list_notifications(&ctx, &name)
            .await
            .map_err(|error| format!("{error:?}"))?;
        Ok(notifications.first().map(|notification| notification.uid.to_string()))
    }
}

/// An environment that answers from closures, for the tests of the harness itself: they feed the matrix answers that a good
/// server never gives (a refusal that changed something, a refusal that leaks, a hidden calendar that is not answered like a
/// missing one) and check that the matrix notices. It has the fixture world and its credentials, a transport that calls the
/// `answer` closure, and a state that is whatever the `state` closure says; it makes no other world (and says so, unless
/// [`ScriptedEnv::offering_worlds`] has it claim that it does).
pub struct ScriptedEnv {
    world: FixtureWorld,
    book: CredentialBook,
    transport: Arc<dyn Transport>,
    state: Arc<dyn Fn() -> Observation + Send + Sync>,
    isolation: Isolation,
}

impl ScriptedEnv {
    /// An environment whose server is `answer` and whose state is `state`.
    pub fn new(
        answer: impl Fn(&TestRequest) -> TestResponse + Send + Sync + 'static,
        state: impl Fn() -> Observation + Send + Sync + 'static,
    ) -> Self {
        let world = FixtureWorld::standard();
        let book = CredentialBook::from_world(&world);
        Self {
            world,
            book,
            transport: Arc::new(FnTransport::new(move |request: &TestRequest| Ok(answer(request)))),
            state: Arc::new(state),
            isolation: Isolation::Unavailable,
        }
    }

    /// The same environment, claiming that it gives every case that changes something a world of its own, which it cannot make
    /// ([`MatrixEnv::fresh`] fails): a database that is too busy to clone, for the tests of what a run does with such a case.
    #[must_use]
    pub const fn offering_worlds(mut self) -> Self {
        self.isolation = Isolation::PerCase;
        self
    }
}

#[async_trait]
impl MatrixEnv for ScriptedEnv {
    fn world(&self) -> &FixtureWorld {
        &self.world
    }

    fn book(&self) -> &CredentialBook {
        &self.book
    }

    fn transport(&self) -> Arc<dyn Transport> {
        Arc::clone(&self.transport)
    }

    async fn observe(&self) -> Result<Observation, String> {
        Ok((self.state)())
    }

    async fn fresh(&self) -> Result<Box<dyn MatrixEnv>, String> {
        Err("a scripted environment makes no other world".to_owned())
    }

    fn isolation(&self) -> Isolation {
        self.isolation
    }

    async fn mcp_ids(&self, _calendar: CalendarRole) -> Result<McpIds, String> {
        Ok(McpIds {
            calendar_id: "018f3c1e-7b2a-7c3d-9e4f-000000000001".to_owned(),
            event_id: "018f3c1e-7b2a-7c3d-9e4f-000000000002".to_owned(),
        })
    }

    async fn feed_token(&self, _actor: ActorRole, _calendar: CalendarRole) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn invitation_uid(&self) -> Result<Option<String>, String> {
        Ok(None)
    }
}
