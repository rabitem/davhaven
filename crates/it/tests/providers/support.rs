//! The world of the provider tests: the real application with a fake provider whose remote world the tests write, and the
//! helpers that go through the flow the way a person does (the management API to start it, the callback of the web surface to
//! end it) and look at what it left (the accounts, the mirror calendar and its events).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use async_trait::async_trait;

use davhaven_testkit::davhaven_domain::{CalendarId, EventType, Principal, PrincipalName, PrincipalStatus, Scope};
use davhaven_testkit::davhaven_fixtures::{ActorRole, names};
use davhaven_testkit::davhaven_ports::testing::ManualClock;
use davhaven_testkit::davhaven_ports::{
    OAuthProvider, PortError, Provider, RemoteCalendar, RemoteCalendarApi, RemoteChanges, TxMode,
};
use davhaven_testkit::davhaven_provider_fake::provider::FakeProvider;
use davhaven_testkit::davhaven_provider_fake::script::Script;
use davhaven_testkit::{ApiHandle, StoreKind, TestApp, TestAppBuilder, TestRequest, TestResponse, Token, WorkSummary};
use secrecy::SecretString;
use serde_json::Value;
use tokio::sync::Notify;
use url::Url;

/// The application, the remote world of its provider and the token of the administrator of the tenant.
pub(crate) struct World {
    pub(crate) app: TestApp,
    pub(crate) script: Script,
    pub(crate) admin: Token,
    codes: AtomicU32,
}

/// The builder of a world: a fake provider that is on, with the script the test keeps.
pub(crate) fn builder(store: StoreKind, clock: &ManualClock, provider: &Arc<FakeProvider>) -> TestAppBuilder {
    let shared = Arc::clone(provider);
    let provider: Arc<dyn Provider> = shared;
    TestApp::builder()
        .store(store)
        .clock(clock.clone())
        .providers(vec![provider])
}

impl World {
    /// A world on `store` whose provider is on.
    pub(crate) async fn new(store: StoreKind) -> Self {
        Self::with_provider(store, |clock| FakeProvider::new(Arc::new(clock.clone()))).await
    }

    /// A world whose provider is the one `make` builds from the clock of the application.
    pub(crate) async fn with_provider(store: StoreKind, make: impl FnOnce(&ManualClock) -> FakeProvider) -> Self {
        Self::custom(store, make, |builder| builder).await
    }

    /// A world whose builder `tweak` changes after the provider was added (the limits, for example).
    pub(crate) async fn tweaked(store: StoreKind, tweak: impl Fn(TestAppBuilder) -> TestAppBuilder) -> Self {
        Self::custom(store, |clock| FakeProvider::new(Arc::new(clock.clone())), tweak).await
    }

    async fn custom(
        store: StoreKind,
        make: impl FnOnce(&ManualClock) -> FakeProvider,
        tweak: impl Fn(TestAppBuilder) -> TestAppBuilder,
    ) -> Self {
        let clock = ManualClock::default();
        let provider = Arc::new(make(&clock));
        let script = provider.script();
        let app = TestApp::build_with_retries(|| tweak(builder(store, &clock, &provider)))
            .await
            .unwrap();
        let admin = app.token(ActorRole::TenantToken).unwrap();
        Self {
            app,
            script,
            admin,
            codes: AtomicU32::new(0),
        }
    }

    /// The path of the tenant in the management API.
    pub(crate) fn base(&self) -> String {
        format!("/api/v1/tenants/{}", self.app.world().names.tenant)
    }

    /// The administrator of the tenant.
    pub(crate) fn api(&self) -> ApiHandle {
        self.app.api(&self.admin)
    }

    /// The API with a token that carries exactly `scope`.
    pub(crate) fn api_with(&self, scope: Scope) -> ApiHandle {
        self.app.api(&self.app.tenant_token(scope).unwrap())
    }

    /// `POST …/external-accounts`.
    pub(crate) async fn start(&self, provider: &str, principal: &str) -> TestResponse {
        self.api()
            .post_json(
                &format!("{}/external-accounts", self.base()),
                &serde_json::json!({"provider": provider, "principal": principal}),
            )
            .unwrap()
            .send()
            .await
            .unwrap()
    }

    /// The state of the consent URL that `start` answered.
    pub(crate) fn state_of(started: &TestResponse) -> String {
        let body: Value = started.json().unwrap();
        let url = Url::parse(body["authorization_url"].as_str().unwrap()).unwrap();
        url.query_pairs()
            .find(|(name, _)| name == "state")
            .map(|(_, value)| value.into_owned())
            .unwrap()
    }

    /// `GET /oauth/{provider}/callback?{query}`, as the browser of a person without any credential sends it.
    pub(crate) async fn callback(&self, provider: &str, query: &str) -> TestResponse {
        let request = TestRequest::new("GET", format!("/oauth/{provider}/callback?{query}"));
        self.app.transport().send(request).await.unwrap()
    }

    /// The whole flow for `principal` with the code `code`: the administrator starts it, the person consents, the provider
    /// calls back. Returns the answer of the callback.
    pub(crate) async fn flow(&self, principal: &str, code: &str) -> TestResponse {
        let started = self.start("fake", principal).await;
        assert_eq!(started.status.as_u16(), 200, "{}", started.excerpt(300));
        let state = Self::state_of(&started);
        self.callback("fake", &format!("code={code}&state={state}")).await
    }

    /// Connects the account `{name}@fake.example` of `principal` with a code of its own (a code works once) and returns its view.
    pub(crate) async fn connect(&self, principal: &str, name: &str) -> Value {
        let account_ref = format!("{name}@fake.example");
        let code = format!("code-{}", self.codes.fetch_add(1, Ordering::SeqCst));
        self.script.accept_code(&code, &account_ref);
        let page = self.flow(principal, &code).await;
        assert_eq!(page.status.as_u16(), 200, "{}", page.excerpt(300));
        assert!(
            page.text().contains("Calendar connected") || page.text().contains("Kalender verbunden"),
            "{}",
            page.excerpt(600)
        );
        self.accounts()
            .await
            .into_iter()
            .find(|account| account["account_ref"] == account_ref && account["principal"] == principal)
            .unwrap_or_else(|| unreachable!("the account {account_ref} of {principal} is not in the list"))
    }

    /// The accounts of the tenant, in the order of the list.
    pub(crate) async fn accounts(&self) -> Vec<Value> {
        let listed = self
            .api()
            .get(&format!("{}/external-accounts?limit=200", self.base()))
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status.as_u16(), 200, "{}", listed.excerpt(300));
        let page: Value = listed.json().unwrap();
        page["items"].as_array().unwrap().clone()
    }

    /// The account with `id`.
    pub(crate) async fn account(&self, id: &str) -> Value {
        self.accounts()
            .await
            .into_iter()
            .find(|account| account["id"] == id)
            .unwrap_or_else(|| unreachable!("no account {id}"))
    }

    /// The calendars `principal` owns.
    pub(crate) async fn calendars_of(&self, principal: &str) -> Vec<Value> {
        let listed = self
            .api()
            .get(&format!("{}/principals/{principal}/calendars?limit=200", self.base()))
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status.as_u16(), 200, "{}", listed.excerpt(300));
        let page: Value = listed.json().unwrap();
        page["items"].as_array().unwrap().clone()
    }

    /// The mirror calendar of `account` (its view in the list of the calendars of the principal), if it is there.
    pub(crate) async fn mirror(&self, account: &Value) -> Option<Value> {
        let id = account["mirror_calendar_id"].as_str().unwrap().to_owned();
        let principal = account["principal"].as_str().unwrap().to_owned();
        self.calendars_of(&principal)
            .await
            .into_iter()
            .find(|calendar| calendar["id"] == id)
    }

    /// The events of the mirror calendar of `account`: `(summary, etag)` in the order of the list.
    pub(crate) async fn events(&self, account: &Value) -> Vec<(String, String)> {
        let mirror = self.mirror(account).await.expect("the mirror calendar is there");
        let principal = account["principal"].as_str().unwrap();
        let slug = mirror["slug"].as_str().unwrap();
        // The owner reads their own calendar: a tenant token reaches the events of group and managed calendars only.
        let owner = self.app.token(ActorRole::Owner).unwrap();
        let listed = self
            .app
            .api(&owner)
            .get(&format!(
                "{}/principals/{principal}/calendars/{slug}/objects?limit=200",
                self.base()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status.as_u16(), 200, "{}", listed.excerpt(300));
        let page: Value = listed.json().unwrap();
        let mut events: Vec<(String, String)> = page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| {
                (
                    event["summary"].as_str().unwrap_or_default().to_owned(),
                    event["etag"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        events.sort();
        events
    }

    /// The summaries of the events of the mirror, sorted.
    pub(crate) async fn summaries(&self, account: &Value) -> Vec<String> {
        self.events(account)
            .await
            .into_iter()
            .map(|(summary, _)| summary)
            .collect()
    }

    /// The sync token of the mirror calendar: it changes exactly when something was written to it.
    pub(crate) async fn sync_token(&self, account: &Value) -> String {
        let mirror = self.mirror(account).await.expect("the mirror calendar is there");
        mirror["sync_token"].as_str().unwrap().to_owned()
    }

    /// Runs the workers until nothing is left to do.
    pub(crate) async fn work(&self) -> WorkSummary {
        self.app.run_workers_until_idle().await.unwrap()
    }

    /// Moves the clock forward by `minutes`.
    pub(crate) fn pass(&self, minutes: i64) {
        self.app.advance(chrono::Duration::minutes(minutes));
    }

    /// How many `external_account.sync_failed` events were delivered, by reason.
    pub(crate) async fn failures_told(&self) -> Vec<String> {
        self.app
            .events()
            .of_type(EventType::ExternalAccountSyncFailed)
            .await
            .into_iter()
            .map(|envelope| {
                serde_json::to_value(&envelope.data).unwrap()["reason"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    /// The actions of the audit log of the tenant, newest first as the API lists them.
    pub(crate) async fn audit_actions(&self) -> Vec<String> {
        let listed = self
            .api()
            .get(&format!("{}/audit-events?limit=200", self.base()))
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status.as_u16(), 200, "{}", listed.excerpt(300));
        let page: Value = listed.json().unwrap();
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["action"].as_str().unwrap().to_owned())
            .collect()
    }

    /// The owner of the world (a user of the main tenant).
    pub(crate) const OWNER: &'static str = names::OWNER;

    /// A world whose provider stops once, at the call for the changes of a calendar, until the test lets it go (see [`Gate`]),
    /// to hold a pull open while something else happens to its account.
    pub(crate) async fn gated(store: StoreKind) -> (Self, Arc<Gate>) {
        let clock = ManualClock::default();
        let fake = Arc::new(FakeProvider::new(Arc::new(clock.clone())));
        let script = fake.script();
        let gate = Arc::new(Gate::new());
        let provider: Arc<dyn Provider> = Arc::new(Gated {
            inner: fake,
            gate: Arc::clone(&gate),
        });
        let app = TestApp::build_with_retries(|| {
            TestApp::builder()
                .store(store)
                .clock(clock.clone())
                .providers(vec![Arc::clone(&provider)])
        })
        .await
        .unwrap();
        let admin = app.token(ActorRole::TenantToken).unwrap();
        let world = Self {
            app,
            script,
            admin,
            codes: AtomicU32::new(0),
        };
        (world, gate)
    }

    /// Gives the principal `name` the status `status`, as a change by an administrator would leave it.
    pub(crate) async fn set_status(&self, name: &str, status: PrincipalStatus) {
        let tenant = self.app.tenant_id("acme").unwrap();
        let mut tx = self.app.deps().database.begin(tenant, TxMode::ReadWrite).await.unwrap();
        let principal = tx
            .principals()
            .get_by_name(&PrincipalName::parse(name).unwrap())
            .await
            .unwrap();
        let updated = Principal {
            status,
            ..principal.clone()
        };
        tx.principals().update(updated, principal.version).await.unwrap();
        tx.commit().await.unwrap();
    }

    /// Deletes the mirror calendar of `account` behind the back of the API, which refuses to: what a purge or an operator's
    /// statement would do.
    pub(crate) async fn delete_mirror(&self, account: &Value) {
        let tenant = self.app.tenant_id("acme").unwrap();
        let id = CalendarId::parse(account["mirror_calendar_id"].as_str().unwrap()).unwrap();
        let mut tx = self.app.deps().database.begin(tenant, TxMode::ReadWrite).await.unwrap();
        let calendar = tx.calendars().get(id).await.unwrap();
        tx.calendars().soft_delete(calendar.id, calendar.version).await.unwrap();
        tx.commit().await.unwrap();
    }
}

/// The stop of a [`Gated`] provider: the first call for the changes of a calendar says that it is there (`reached`) and waits
/// until the test lets it go (`release`).
pub(crate) struct Gate {
    armed: AtomicBool,
    pub(crate) reached: Notify,
    pub(crate) release: Notify,
}

impl Gate {
    fn new() -> Self {
        Self {
            armed: AtomicBool::new(true),
            reached: Notify::new(),
            release: Notify::new(),
        }
    }
}

/// The fake provider with a [`Gate`] in front of the calls for the changes of a calendar.
struct Gated {
    inner: Arc<FakeProvider>,
    gate: Arc<Gate>,
}

impl Provider for Gated {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn display_name(&self) -> &'static str {
        self.inner.display_name()
    }

    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn oauth(&self) -> &dyn OAuthProvider {
        self.inner.oauth()
    }

    fn calendars(&self) -> &dyn RemoteCalendarApi {
        self
    }
}

#[async_trait]
impl RemoteCalendarApi for Gated {
    async fn list_calendars(&self, token: &SecretString) -> Result<Vec<RemoteCalendar>, PortError> {
        self.inner.calendars().list_calendars(token).await
    }

    async fn changes_since(
        &self,
        token: &SecretString,
        calendar: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteChanges, PortError> {
        if self.gate.armed.swap(false, Ordering::SeqCst) {
            self.gate.reached.notify_one();
            self.gate.release.notified().await;
        }
        self.inner.calendars().changes_since(token, calendar, cursor).await
    }
}

/// Runs the scenario `$body` (an async function of the store) as a test on the in-memory store and as one on PostgreSQL. The
/// PostgreSQL test needs `DATABASE_URL` and fails without it (a skip is for `DAVHAVEN_ALLOW_NO_DB` outside CI only).
macro_rules! on_both_stores {
    ($name:ident, $body:ident) => {
        mod $name {
            use davhaven_testkit::StoreKind;

            #[tokio::test]
            async fn on_memory() {
                super::$body(StoreKind::Memory).await;
            }

            #[tokio::test]
            async fn on_postgres() {
                if !davhaven_testkit::postgres::require_database() {
                    return;
                }
                super::$body(StoreKind::Postgres).await;
            }
        }
    };
}

pub(crate) use on_both_stores;
