//! The administration operations of the management API in the permission matrix (PLAN 3.2: every API operation x scope).
//!
//! The calendar matrix covers the operations of the API that are about one calendar (reading and writing events, the
//! settings of a calendar, grants). The rest of the API, 47 operations in 15 groups (tenants, principals and members, the bindings of a home,
//! app passwords, feed tokens, API tokens, client configuration, webhooks, providers and external accounts, the audit log,
//! the outbox, the inbound iTIP endpoint and the search for calendars), administers the tenant. Its rules are rows of the
//! expectations file, short and the same for every operation (PLAN 2.6):
//!
//! * `[[admin_actor]]` says how each actor is treated: a request without credentials, or with the credentials of a suspended
//!   principal, is answered 401 (`unauthenticated`); principals never administer anything, whatever their scopes, so a
//!   principal token is refused with 403 (`refused`); an actor of another tenant sees nothing of this one (404 where the path
//!   names a tenant, 403 where it does not: `other_tenant`); a token is decided by its scopes (`by_scope`);
//! * `[[token_scopes]]` lists the scopes each kind of token may carry, and `[[admin]]` the scopes each operation accepts: a
//!   token is allowed when it carries one of them and refused (403) when it carries none, so a system token (it carries
//!   `system:tenants` only) is allowed where that scope is listed and refused everywhere else and reads no data of any tenant;
//! * `[[pending]]` lists the operations that are not implemented yet: the callers that reach the service are answered
//!   501, and the row is checked against what the server does today (a new 501 anywhere else is a failure, and an operation that
//!   stops answering 501 makes the row stale).
//!
//! [`OPERATIONS`] lists the operations with the facts that are not decisions (the method and the path, what a successful
//! answer is), and [`expected`] resolves a case from the file. Every operation is crossed with every actor, and tenant tokens
//! with every scope a tenant token can carry: the token that carries exactly the scope of the operation is allowed, the tokens
//! that carry any other scope are refused. An operation that names an id (a webhook, a token, an outbox item) is also asked
//! for by the administrator of another tenant **in its own tenant** with the ids of the first tenant: the lookup by id must
//! not find what belongs to somebody else, and the answer is the one for an id that nothing has.
//!
//! The harness compares the answer, that a refusal changes nothing (the whole state, credentials and webhooks included), that a
//! hidden answer is the answer a tenant that does not exist would get, and the details of a refusal (the challenge, the problem).
//! Everything the harness creates is labelled with [`LABEL`], so that a reset of a deployed
//! instance finds it again.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use davhaven_fixtures::{ActorRole, CalendarRole, FixtureWorld, names};
use futures::StreamExt as _;
use serde_json::{Value, json};

use super::{Verdict, detail_problems, request, same_kind};
use crate::busy::{self, Attempt, Effect, Policy};
use crate::handles::Actor;
use crate::matrix::{AdminRule, Expectation, Expectations, MatrixError, Surface, TokenClass};
use crate::observe::Observation;
use crate::permissions::{Isolation, MatrixEnv, Observed, RunOptions};
use crate::staging::provision::{HARNESS_PRINCIPAL_PREFIX, LABEL};
use crate::transport::{TestRequest, TestResponse};

/// One administration operation of the management API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminOp {
    /// The `operationId` of `docs/openapi.json`.
    pub id: &'static str,
    /// The HTTP method.
    pub method: &'static str,
    /// The path template of `docs/openapi.json`, below `/api/v1`.
    pub path: &'static str,
    /// The statuses that say that the operation was done (or was understood and refused for a reason that is not a
    /// permission: a feature that is switched off answers 409).
    pub success: &'static [u16],
    /// Whether the path names a tenant (and so has one to hide from the others): every path but the list of tenants.
    pub tenant_in_path: bool,
}

impl AdminOp {
    /// Whether the operation reads only.
    pub const fn reads(&self) -> bool {
        matches!(self.method.as_bytes(), b"GET")
    }

    /// Whether the path names something by an id that a request of another tenant could try to reach (a webhook, a token, a
    /// delivery, an outbox item, an external account).
    pub fn names_an_id(&self) -> bool {
        self.path.contains("{id}") || self.path.contains("{delivery}")
    }
}

const fn op(id: &'static str, method: &'static str, path: &'static str, success: &'static [u16]) -> AdminOp {
    AdminOp {
        id,
        method,
        path,
        success,
        tenant_in_path: true,
    }
}

const READ: &[u16] = &[200];
const WRITTEN: &[u16] = &[200, 201, 204];
const CREATED: &[u16] = &[201];
const DELETED: &[u16] = &[200, 204];

/// Every administration operation, in the order of the paths of `docs/openapi.json`.
pub const OPERATIONS: &[AdminOp] = &[
    AdminOp {
        tenant_in_path: false,
        ..op("listTenants", "GET", "/tenants", READ)
    },
    op("deleteTenant", "DELETE", "/tenants/{tenant}", DELETED),
    op("getTenant", "GET", "/tenants/{tenant}", READ),
    op("patchTenant", "PATCH", "/tenants/{tenant}", READ),
    op("putTenant", "PUT", "/tenants/{tenant}", WRITTEN),
    op("listApiTokens", "GET", "/tenants/{tenant}/api-tokens", READ),
    op("createApiToken", "POST", "/tenants/{tenant}/api-tokens", CREATED),
    op("revokeApiToken", "DELETE", "/tenants/{tenant}/api-tokens/{id}", DELETED),
    op("listAuditEvents", "GET", "/tenants/{tenant}/audit-events", READ),
    op("searchCalendars", "GET", "/tenants/{tenant}/calendars", READ),
    op(
        "listExternalAccounts",
        "GET",
        "/tenants/{tenant}/external-accounts",
        READ,
    ),
    // Starts the OAuth flow at the fake provider where the environment has one (the harness of this crate switches it on): 200 with
    // the consent URL. Where it has none the operation is understood and answers 409 `feature-not-enabled` ([`success_of`] picks
    // the statuses that the environment is in).
    op(
        "createExternalAccount",
        "POST",
        "/tenants/{tenant}/external-accounts",
        &[200, 409],
    ),
    op(
        "deleteExternalAccount",
        "DELETE",
        "/tenants/{tenant}/external-accounts/{id}",
        &[204],
    ),
    // Inbound iTIP takes a message where it is switched on and answers 409 `feature-not-enabled` where it is not
    // ([`success_of`] picks the one that the environment is in).
    op("inboundItip", "POST", "/tenants/{tenant}/itip/inbound", &[200]),
    op("listOutbox", "GET", "/tenants/{tenant}/outbox", READ),
    op(
        "retryOutbox",
        "POST",
        "/tenants/{tenant}/outbox/{id}/retry",
        &[200, 202, 204, 409],
    ),
    op("listPrincipals", "GET", "/tenants/{tenant}/principals", READ),
    op(
        "getMembers",
        "GET",
        "/tenants/{tenant}/principals/{group}/members",
        READ,
    ),
    op(
        "setMembers",
        "PUT",
        "/tenants/{tenant}/principals/{group}/members",
        WRITTEN,
    ),
    op(
        "removeMember",
        "DELETE",
        "/tenants/{tenant}/principals/{group}/members/{member}",
        DELETED,
    ),
    op(
        "addMember",
        "PUT",
        "/tenants/{tenant}/principals/{group}/members/{member}",
        WRITTEN,
    ),
    op(
        "deletePrincipal",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}",
        DELETED,
    ),
    op("getPrincipal", "GET", "/tenants/{tenant}/principals/{principal}", READ),
    op(
        "patchPrincipal",
        "PATCH",
        "/tenants/{tenant}/principals/{principal}",
        READ,
    ),
    op(
        "putPrincipal",
        "PUT",
        "/tenants/{tenant}/principals/{principal}",
        WRITTEN,
    ),
    op(
        "listAppPasswords",
        "GET",
        "/tenants/{tenant}/principals/{principal}/app-passwords",
        READ,
    ),
    op(
        "createAppPassword",
        "POST",
        "/tenants/{tenant}/principals/{principal}/app-passwords",
        CREATED,
    ),
    op(
        "revokeAppPassword",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}/app-passwords/{id}",
        DELETED,
    ),
    op(
        "listBindings",
        "GET",
        "/tenants/{tenant}/principals/{principal}/bindings",
        READ,
    ),
    op(
        "restoreBinding",
        "POST",
        "/tenants/{tenant}/principals/{principal}/bindings/{binding}/restore",
        READ,
    ),
    op(
        "createAppleMobileconfig",
        "POST",
        "/tenants/{tenant}/principals/{principal}/client-config/apple-mobileconfig",
        WRITTEN,
    ),
    op(
        "createDavx5Config",
        "POST",
        "/tenants/{tenant}/principals/{principal}/client-config/davx5",
        WRITTEN,
    ),
    op(
        "getClientConfig",
        "GET",
        "/tenants/{tenant}/principals/{principal}/client-config/generic",
        READ,
    ),
    op(
        "listFeedTokens",
        "GET",
        "/tenants/{tenant}/principals/{principal}/feed-tokens",
        READ,
    ),
    op(
        "createFeedToken",
        "POST",
        "/tenants/{tenant}/principals/{principal}/feed-tokens",
        CREATED,
    ),
    op(
        "revokeFeedToken",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}/feed-tokens/{id}",
        DELETED,
    ),
    op(
        "rotateFeedToken",
        "POST",
        "/tenants/{tenant}/principals/{principal}/feed-tokens/{id}/rotate",
        WRITTEN,
    ),
    op("listProviders", "GET", "/tenants/{tenant}/providers", READ),
    op("listWebhooks", "GET", "/tenants/{tenant}/webhooks", READ),
    op("createWebhook", "POST", "/tenants/{tenant}/webhooks", CREATED),
    op("deleteWebhook", "DELETE", "/tenants/{tenant}/webhooks/{id}", DELETED),
    op("getWebhook", "GET", "/tenants/{tenant}/webhooks/{id}", READ),
    op("patchWebhook", "PATCH", "/tenants/{tenant}/webhooks/{id}", READ),
    op(
        "listDeliveries",
        "GET",
        "/tenants/{tenant}/webhooks/{id}/deliveries",
        READ,
    ),
    op(
        "redeliverWebhook",
        "POST",
        "/tenants/{tenant}/webhooks/{id}/deliveries/{delivery}/redeliver",
        &[200, 202, 204, 409],
    ),
    op(
        "pingWebhook",
        "POST",
        "/tenants/{tenant}/webhooks/{id}/ping",
        &[200, 202, 204],
    ),
    op(
        "rotateWebhookSecret",
        "POST",
        "/tenants/{tenant}/webhooks/{id}/rotate-secret",
        WRITTEN,
    ),
];

/// The operation with an `operationId`.
pub fn operation(id: &str) -> Option<&'static AdminOp> {
    OPERATIONS.iter().find(|candidate| candidate.id == id)
}

/// The statuses that say that an operation was done in an environment: those of the table, except for the inbound iTIP
/// endpoint, which takes a message (200) where the environment has switched it on and answers 409 where it has not, and
/// either where the environment cannot tell, and for starting a flow, which gives the consent URL (200) where the environment
/// offers the fake provider (`fixtures` holds the account that was connected at it) and may answer 409 `feature-not-enabled`
/// everywhere else.
pub fn success_of(operation: &AdminOp, env: &dyn MatrixEnv, fixtures: &Fixtures) -> Vec<u16> {
    if operation.id == "createExternalAccount" {
        return if fixtures.external_account_id.is_some() {
            vec![200]
        } else {
            vec![200, 409]
        };
    }
    if operation.id == "inboundItip" {
        return match env.inbound_itip() {
            Some(true) => vec![200],
            Some(false) => vec![409],
            None => vec![200, 409],
        };
    }
    operation.success.to_vec()
}

// ---------------------------------------------------------------------------------------------------------------
// Cases and the oracle
// ---------------------------------------------------------------------------------------------------------------

/// One cell of the administration matrix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdminCase {
    /// The `operationId`.
    pub operation: &'static str,
    /// Who acts.
    pub actor: ActorRole,
    /// For tenant tokens: the one scope the token carries; `None` is the token with every tenant scope.
    pub scope: Option<String>,
    /// For the administrator of another tenant: the request goes to **its own tenant** and names the ids of the main tenant
    /// (a webhook, a token, an outbox item that exist there and not here).
    pub foreign_ids: bool,
}

impl AdminCase {
    /// A case without a scope of its own and with the ids of its tenant.
    pub const fn new(operation: &'static str, actor: ActorRole) -> Self {
        Self {
            operation,
            actor,
            scope: None,
            foreign_ids: false,
        }
    }
}

impl fmt::Display for AdminCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.actor)?;
        if let Some(scope) = &self.scope {
            write!(f, "[{scope}]")?;
        }
        write!(f, " {}", self.operation)?;
        if self.foreign_ids {
            write!(f, " (with ids of another tenant)")?;
        }
        Ok(())
    }
}

/// The scopes a tenant token can carry, from the expectations file.
pub fn tenant_scopes(expectations: &Expectations) -> Vec<String> {
    expectations.token_scopes(TokenClass::Tenant).to_vec()
}

/// The cases of the matrix: every operation with every actor, with the tenant token that carries each scope, and with the
/// administrator of the other tenant asking for the ids of the main one where the operation names an id.
pub fn cases(expectations: &Expectations) -> Vec<AdminCase> {
    let scopes = tenant_scopes(expectations);
    let mut cases = Vec::new();
    for operation in OPERATIONS {
        for actor in ActorRole::ALL {
            cases.push(AdminCase::new(operation.id, *actor));
            if *actor == ActorRole::TenantToken {
                for scope in &scopes {
                    cases.push(AdminCase {
                        scope: Some(scope.clone()),
                        ..AdminCase::new(operation.id, *actor)
                    });
                }
            }
            if *actor == ActorRole::OtherTenantToken && operation.names_an_id() {
                cases.push(AdminCase {
                    foreign_ids: true,
                    ..AdminCase::new(operation.id, *actor)
                });
            }
        }
    }
    cases
}

/// What a case expects, from the rows of the expectations file (`[[admin_actor]]`, `[[token_scopes]]`, `[[admin]]`).
///
/// # Errors
///
/// [`MatrixError::NoRule`] when the operation is unknown, the file lists no scopes for it or no rule for the actor.
pub fn expected(expectations: &Expectations, case: &AdminCase) -> Result<Expectation, MatrixError> {
    let operation = operation(case.operation).ok_or_else(|| MatrixError::NoRule(case.to_string()))?;
    let accepted = expectations
        .admin_scopes(operation.id)
        .ok_or_else(|| MatrixError::NoRule(case.to_string()))?;
    let (rule, _) = expectations
        .admin_rule(case.actor)
        .ok_or_else(|| MatrixError::NoRule(case.to_string()))?;
    Ok(match rule {
        AdminRule::Unauthenticated => Expectation::Unauthenticated,
        AdminRule::Refused => Expectation::Forbidden,
        AdminRule::OtherTenant => {
            // In its own tenant the administrator of another tenant finds nothing of what it is not told: the ids belong to
            // somebody else, so they name nothing.
            if case.foreign_ids || operation.tenant_in_path {
                Expectation::Hidden
            } else {
                Expectation::Forbidden
            }
        }
        AdminRule::ByScope => {
            let carried: Vec<String> = match (&case.scope, case.actor) {
                (Some(scope), _) => vec![scope.clone()],
                (None, ActorRole::SystemToken) => expectations.token_scopes(TokenClass::System).to_vec(),
                (None, _) => expectations.token_scopes(TokenClass::Tenant).to_vec(),
            };
            if carried
                .iter()
                .any(|scope| accepted.iter().any(|candidate| candidate == scope))
            {
                Expectation::Allow
            } else {
                Expectation::Forbidden
            }
        }
    })
}

// ---------------------------------------------------------------------------------------------------------------
// The requests
// ---------------------------------------------------------------------------------------------------------------

/// What an operation needs to exist before it can be asked for: ids and entity tags of things the administrator made.
#[derive(Debug, Clone, Default)]
pub struct Fixtures {
    app_password_id: Option<String>,
    feed_token_id: Option<String>,
    api_token_id: Option<String>,
    webhook_id: Option<String>,
    delivery_id: Option<String>,
    outbox_id: Option<String>,
    external_account_id: Option<String>,
    calendar_id: Option<String>,
    tenant_etag: Option<String>,
    principal_etag: Option<String>,
    /// What could not be prepared, by the name the operations ask for it with.
    missing: BTreeMap<&'static str, String>,
}

/// The names of what an operation needs, as [`Fixtures`] records what is missing.
mod needs {
    pub(super) const APP_PASSWORD: &str = "an app password";
    pub(super) const FEED_TOKEN: &str = "a feed token";
    pub(super) const API_TOKEN: &str = "an API token";
    pub(super) const WEBHOOK: &str = "a webhook";
    pub(super) const EXTERNAL_ACCOUNT: &str = "an external account";
    pub(super) const CALENDAR: &str = "a calendar";
    pub(super) const ADMINISTRATOR: &str = "an administration token";
}

impl Fixtures {
    fn lack(&mut self, what: &'static str, why: impl Into<String>) {
        self.missing.insert(what, why.into());
    }
}

fn text_at(value: &Value, pointer: &str) -> Option<String> {
    value.pointer(pointer).and_then(Value::as_str).map(str::to_owned)
}

/// The path of the tenant of the world.
fn tenant_path(world: &FixtureWorld) -> String {
    format!("/api/v1/tenants/{}", world.names.tenant)
}

async fn send(
    env: &dyn MatrixEnv,
    actor: &Actor,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<TestResponse, String> {
    let mut built = request(actor, method, path).header("accept", "application/json");
    if let Some(body) = body {
        let bytes = serde_json::to_vec(body).map_err(|error| error.to_string())?;
        built = built.content("application/json", bytes);
    }
    // What a fixture makes is labelled, and a second one of the kind does no harm, so a request that the host was too busy to
    // answer is sent again whatever it was.
    busy::send_repeatable(env.transport().as_ref(), &built)
        .await
        .0
        .map_err(|error| error.to_string())
}

/// Makes what the operations ask for with the administration token of the tenant. What is made is labelled with
/// [`LABEL`], so that a reset finds it again.
#[expect(
    clippy::too_many_lines,
    reason = "one request for each thing an operation can need, each recording why it is missing"
)]
pub async fn fixtures(env: &dyn MatrixEnv) -> Fixtures {
    let mut fixtures = Fixtures::default();
    let Some(admin) = env.book().actor(ActorRole::TenantToken, Surface::Api, None) else {
        fixtures.lack(needs::ADMINISTRATOR, "the environment has no administration token");
        return fixtures;
    };
    let world = env.world();
    let base = tenant_path(world);
    let owner = format!("{base}/principals/{}", names::OWNER);

    match send(env, &admin, "GET", &base, None).await {
        Ok(response) => fixtures.tenant_etag = response.header("etag").map(str::to_owned),
        Err(error) => fixtures.lack("the tenant", error),
    }
    match send(
        env,
        &admin,
        "GET",
        &format!("{base}/principals/{}", names::OTHER_USER),
        None,
    )
    .await
    {
        Ok(response) => fixtures.principal_etag = response.header("etag").map(str::to_owned),
        Err(error) => fixtures.lack("the principal", error),
    }
    if let Ok(response) = send(env, &admin, "GET", &format!("{owner}/app-passwords"), None).await
        && let Ok(page) = response.json::<Value>()
    {
        fixtures.app_password_id = text_at(&page, "/items/0/id");
    }
    if fixtures.app_password_id.is_none() {
        fixtures.lack(needs::APP_PASSWORD, "the owner has none");
    }
    if let Ok(response) = send(env, &admin, "GET", &format!("{base}/outbox"), None).await
        && let Ok(page) = response.json::<Value>()
    {
        fixtures.outbox_id = text_at(&page, "/items/0/id");
    }
    match env.mcp_ids(CalendarRole::Personal).await {
        Ok(ids) => fixtures.calendar_id = Some(ids.calendar_id),
        Err(error) => fixtures.lack(needs::CALENDAR, error),
    }
    if let Some(calendar) = &fixtures.calendar_id
        && let Ok(response) = send(
            env,
            &admin,
            "POST",
            &format!("{owner}/feed-tokens"),
            Some(&json!({"mode": "full", "calendar_ids": [calendar]})),
        )
        .await
        && let Ok(created) = response.json::<Value>()
    {
        fixtures.feed_token_id = text_at(&created, "/token/id");
    }
    if fixtures.feed_token_id.is_none() {
        fixtures.lack(needs::FEED_TOKEN, "it could not be made");
    }
    if let Ok(response) = send(
        env,
        &admin,
        "POST",
        &format!("{base}/api-tokens"),
        Some(&json!({"kind": "tenant", "label": format!("{LABEL}-matrix"), "scopes": ["events:read"]})),
    )
    .await
        && let Ok(created) = response.json::<Value>()
    {
        fixtures.api_token_id = text_at(&created, "/token/id");
    }
    if fixtures.api_token_id.is_none() {
        fixtures.lack(needs::API_TOKEN, "it could not be made");
    }
    match send(
        env,
        &admin,
        "POST",
        &format!("{base}/webhooks"),
        Some(&json!({
            "url": "https://hooks.example.net/matrix",
            "events": ["calendar.created"],
            "description": format!("{LABEL}-matrix")
        })),
    )
    .await
    {
        Ok(response) => match response.json::<Value>() {
            Ok(created) => fixtures.webhook_id = text_at(&created, "/webhook/id"),
            Err(_) => fixtures.lack(
                needs::WEBHOOK,
                format!("status {}: {}", response.status, response.excerpt(160)),
            ),
        },
        Err(error) => fixtures.lack(needs::WEBHOOK, error),
    }
    // A connected account, through the flow a person goes through. Only an environment that has a provider switched on can make
    // one (the harness of this crate switches the fake on); every other one says so, and the operations that need an account are
    // then asked for with an id that nothing has.
    match connect_account(env, &admin, &base, names::OWNER).await {
        Ok(id) => fixtures.external_account_id = Some(id),
        Err(why) => fixtures.lack(needs::EXTERNAL_ACCOUNT, why),
    }
    if let Some(webhook) = &fixtures.webhook_id {
        drop(send(env, &admin, "POST", &format!("{base}/webhooks/{webhook}/ping"), None).await);
        if let Ok(response) = send(
            env,
            &admin,
            "GET",
            &format!("{base}/webhooks/{webhook}/deliveries"),
            None,
        )
        .await
            && let Ok(page) = response.json::<Value>()
        {
            fixtures.delivery_id = text_at(&page, "/items/0/id");
        }
    }
    fixtures
}

/// The provider the harness connects an account at: the test double of the application, which a deployed instance does not have.
const PROVIDER: &str = "fake";

/// Connects an account of `principal` the way a person does: the administrator starts the flow, the provider sends the browser
/// back to the callback with a code, and the account is in the list. Returns its id, or why the environment cannot make one.
async fn connect_account(env: &dyn MatrixEnv, admin: &Actor, base: &str, principal: &str) -> Result<String, String> {
    let started = send(
        env,
        admin,
        "POST",
        &format!("{base}/external-accounts"),
        Some(&json!({"provider": PROVIDER, "principal": principal})),
    )
    .await?;
    if started.status.as_u16() != 200 {
        return Err(format!(
            "the provider `{PROVIDER}` is not offered here (status {}): {}",
            started.status,
            started.excerpt(120)
        ));
    }
    let body: Value = started.json().map_err(|error| error.to_string())?;
    let authorization = text_at(&body, "/authorization_url").ok_or("the answer names no authorization URL")?;
    let state = url::Url::parse(&authorization)
        .map_err(|error| error.to_string())?
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .ok_or("the authorization URL carries no state")?;
    let callback = request(
        &Actor::anonymous(),
        "GET",
        &format!("/oauth/{PROVIDER}/callback?code=fake-{principal}&state={state}"),
    );
    let consented = env
        .transport()
        .send(callback)
        .await
        .map_err(|error| error.to_string())?;
    if consented.status.as_u16() != 200 {
        return Err(format!("the callback answered {}", consented.status));
    }
    let listed = send(env, admin, "GET", &format!("{base}/external-accounts"), None).await?;
    let page: Value = listed.json().map_err(|error| error.to_string())?;
    text_at(&page, "/items/0/id").ok_or_else(|| "the account is not in the list".to_owned())
}

/// A request of a case.
#[derive(Debug, Clone)]
struct Prepared {
    method: &'static str,
    path: String,
    body: Option<Value>,
    headers: Vec<(&'static str, String)>,
}

impl Prepared {
    fn new(method: &'static str, path: String) -> Self {
        Self {
            method,
            path,
            body: None,
            headers: Vec::new(),
        }
    }

    fn json(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.to_owned()));
        self
    }

    fn build(&self, actor: &Actor) -> TestRequest {
        let mut built = request(actor, self.method, &self.path).header("accept", "application/json");
        for (name, value) in &self.headers {
            built = built.header(name, value);
        }
        if let Some(body) = &self.body {
            let content_type = if self.method == "PATCH" {
                "application/merge-patch+json"
            } else {
                "application/json"
            };
            built = built.content(content_type, serde_json::to_vec(body).unwrap_or_default());
        }
        built
    }
}

/// The id of something an operation needs, or the reason why it cannot be asked for.
fn needed<'a>(what: &'static str, id: Option<&'a String>, fixtures: &Fixtures) -> Result<&'a str, String> {
    id.map(String::as_str).ok_or_else(|| {
        let why = fixtures
            .missing
            .get(what)
            .map_or("it could not be made", String::as_str);
        format!("the operation needs {what}, and {why}")
    })
}

/// A REPLY of a guest to an event that nobody organizes here: the endpoint takes it and quarantines it (the answer is 200 with
/// the outcome `quarantined`).
fn inbound_reply(seq: usize) -> String {
    [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Davhaven//matrix//EN",
        "METHOD:REPLY",
        "BEGIN:VEVENT",
        &format!("UID:matrix-inbound-{seq}@guest.example"),
        "DTSTAMP:20270101T000000Z",
        "DTSTART:20270601T090000Z",
        "SEQUENCE:0",
        "ORGANIZER:mailto:olivia@acme.example",
        "ATTENDEE;PARTSTAT=ACCEPTED:mailto:guest@example.net",
        "END:VEVENT",
        "END:VCALENDAR",
        "",
    ]
    .join("\r\n")
}

/// The request of an operation on the world, with `seq` making the names of what it creates unique. With `foreign_ids` the
/// request goes to the other tenant of the world and names the ids that [`Fixtures`] holds (they belong to the main tenant).
#[expect(
    clippy::too_many_lines,
    reason = "one arm per operation of the API, each a method, a path and perhaps a body"
)]
fn prepare(
    operation: &AdminOp,
    world: &FixtureWorld,
    fixtures: &Fixtures,
    seq: usize,
    foreign_ids: bool,
) -> Result<Prepared, String> {
    let tenant_slug = if foreign_ids {
        &world.names.other_tenant
    } else {
        &world.names.tenant
    };
    let tenant = format!("/api/v1/tenants/{tenant_slug}");
    let principal = |name: &str| format!("{tenant}/principals/{name}");
    // The principal whose credentials an operation is about: the owner of the main tenant, the user of the other one.
    let person = if foreign_ids {
        names::OTHER_TENANT_USER
    } else {
        names::OWNER
    };
    let owner = principal(person);
    let group = principal(names::TEAM);
    let method = operation.method;
    let nil = "00000000-0000-7000-8000-000000000000";
    let if_match = |etag: &Option<String>| etag.clone().unwrap_or_else(|| "\"v1\"".to_owned());
    let prepared = match operation.id {
        "listTenants" => Prepared::new(method, "/api/v1/tenants".to_owned()),
        "getTenant" | "putTenant" | "patchTenant" | "deleteTenant" => {
            let base = Prepared::new(method, tenant.clone());
            match operation.id {
                "putTenant" => base.json(json!({
                    "display_name": world.names.tenant_display,
                    "login_domain": world.names.login_domain
                })),
                "patchTenant" => {
                    base.json(json!({"display_name": format!("{} (patched)", world.names.tenant_display)}))
                }
                "deleteTenant" => base.header("if-match", &if_match(&fixtures.tenant_etag)),
                _ => base,
            }
        }
        "listApiTokens" => Prepared::new(method, format!("{tenant}/api-tokens")),
        "createApiToken" => Prepared::new(method, format!("{tenant}/api-tokens"))
            // A token mints tokens with a subset of its own scopes: the one with exactly `credentials:write` hands out that.
            .json(json!({"kind": "tenant", "label": format!("{LABEL}-matrix-{seq}"), "scopes": ["credentials:write"]})),
        "revokeApiToken" => {
            let id = needed(needs::API_TOKEN, fixtures.api_token_id.as_ref(), fixtures)?;
            Prepared::new(method, format!("{tenant}/api-tokens/{id}"))
        }
        "listAuditEvents" => Prepared::new(method, format!("{tenant}/audit-events")),
        "searchCalendars" => Prepared::new(method, format!("{tenant}/calendars")),
        "listBindings" => Prepared::new(method, format!("{owner}/bindings")),
        // The owner's own, visible binding: restoring it changes nothing, so an allowed case leaves the world as it was.
        "restoreBinding" => Prepared::new(method, format!("{owner}/bindings/{}/restore", names::PERSONAL_CALENDAR)),
        "listExternalAccounts" => Prepared::new(method, format!("{tenant}/external-accounts")),
        "createExternalAccount" => {
            // The fake provider where the environment has one (an account was connected at it); `google`, which is off in a
            // deployment that did not switch it on, where it has not.
            let provider = if fixtures.external_account_id.is_some() {
                PROVIDER
            } else {
                "google"
            };
            Prepared::new(method, format!("{tenant}/external-accounts"))
                .json(json!({"provider": provider, "principal": person}))
        }
        "deleteExternalAccount" => {
            // The account of the world when the environment has one; an id that nothing has otherwise (a case that is refused
            // before the lookup does not need more).
            let id = fixtures.external_account_id.as_deref().unwrap_or(nil);
            Prepared::new(method, format!("{tenant}/external-accounts/{id}"))
        }
        "inboundItip" => Prepared::new(method, format!("{tenant}/itip/inbound")).json(json!({
            "message_id": format!("<matrix-{seq}@mail.example.net>"),
            "from": "guest@example.net",
            "ical": inbound_reply(seq),
            "dmarc": "pass"
        })),
        "listOutbox" => Prepared::new(method, format!("{tenant}/outbox")),
        "retryOutbox" => {
            let id = fixtures.outbox_id.as_deref().unwrap_or(nil);
            Prepared::new(method, format!("{tenant}/outbox/{id}/retry"))
        }
        "listPrincipals" => Prepared::new(method, format!("{tenant}/principals")),
        "getMembers" => Prepared::new(method, format!("{group}/members")),
        "setMembers" => {
            Prepared::new(method, format!("{group}/members")).json(json!({"members": [names::GROUP_MEMBER]}))
        }
        "removeMember" => Prepared::new(method, format!("{group}/members/{}", names::GROUP_MEMBER)),
        "addMember" => Prepared::new(method, format!("{group}/members/{}", names::OTHER_USER)),
        "getPrincipal" => Prepared::new(method, principal(names::OTHER_USER)),
        "patchPrincipal" => {
            Prepared::new(method, principal(names::OTHER_USER)).json(json!({"display_name": "Otto (patched)"}))
        }
        "putPrincipal" => Prepared::new(method, principal(&format!("{HARNESS_PRINCIPAL_PREFIX}mx-{seq}")))
            .json(json!({"kind": "user", "display_name": format!("Matrix {seq}")})),
        "deletePrincipal" => {
            Prepared::new(method, principal(names::OTHER_USER)).header("if-match", &if_match(&fixtures.principal_etag))
        }
        "listAppPasswords" => Prepared::new(method, format!("{owner}/app-passwords")),
        "createAppPassword" => Prepared::new(method, format!("{owner}/app-passwords"))
            .json(json!({"label": format!("{LABEL}-matrix-{seq}")})),
        "revokeAppPassword" => {
            let id = needed(needs::APP_PASSWORD, fixtures.app_password_id.as_ref(), fixtures)?;
            Prepared::new(method, format!("{owner}/app-passwords/{id}"))
        }
        "createAppleMobileconfig" => Prepared::new(method, format!("{owner}/client-config/apple-mobileconfig"))
            .json(json!({"app_password_label": format!("{LABEL}-matrix-{seq}"), "include_feed": false})),
        "createDavx5Config" => Prepared::new(method, format!("{owner}/client-config/davx5"))
            .json(json!({"app_password_label": format!("{LABEL}-matrix-{seq}")})),
        "getClientConfig" => Prepared::new(method, format!("{owner}/client-config/generic")),
        "listFeedTokens" => Prepared::new(method, format!("{owner}/feed-tokens")),
        "createFeedToken" => {
            let calendar = needed(needs::CALENDAR, fixtures.calendar_id.as_ref(), fixtures)?;
            Prepared::new(method, format!("{owner}/feed-tokens"))
                .json(json!({"mode": "full", "calendar_ids": [calendar]}))
        }
        "revokeFeedToken" => {
            let id = needed(needs::FEED_TOKEN, fixtures.feed_token_id.as_ref(), fixtures)?;
            Prepared::new(method, format!("{owner}/feed-tokens/{id}"))
        }
        "rotateFeedToken" => {
            let id = needed(needs::FEED_TOKEN, fixtures.feed_token_id.as_ref(), fixtures)?;
            Prepared::new(method, format!("{owner}/feed-tokens/{id}/rotate"))
        }
        "listProviders" => Prepared::new(method, format!("{tenant}/providers")),
        "listWebhooks" => Prepared::new(method, format!("{tenant}/webhooks")),
        "createWebhook" => Prepared::new(method, format!("{tenant}/webhooks")).json(json!({
            "url": format!("https://hooks.example.net/matrix-{seq}"),
            "events": ["calendar.created"],
            "description": format!("{LABEL}-matrix")
        })),
        "getWebhook" | "patchWebhook" | "deleteWebhook" | "listDeliveries" | "pingWebhook" | "rotateWebhookSecret" => {
            let id = needed(needs::WEBHOOK, fixtures.webhook_id.as_ref(), fixtures)?;
            let path = match operation.id {
                "listDeliveries" => format!("{tenant}/webhooks/{id}/deliveries"),
                "pingWebhook" => format!("{tenant}/webhooks/{id}/ping"),
                "rotateWebhookSecret" => format!("{tenant}/webhooks/{id}/rotate-secret"),
                _ => format!("{tenant}/webhooks/{id}"),
            };
            let base = Prepared::new(method, path);
            if operation.id == "patchWebhook" {
                base.json(json!({"description": format!("{LABEL}-matrix patched")}))
            } else {
                base
            }
        }
        "redeliverWebhook" => {
            let id = needed(needs::WEBHOOK, fixtures.webhook_id.as_ref(), fixtures)?;
            let delivery = fixtures.delivery_id.as_deref().unwrap_or(nil);
            Prepared::new(
                method,
                format!("{tenant}/webhooks/{id}/deliveries/{delivery}/redeliver"),
            )
        }
        other => return Err(format!("the operation `{other}` has no request in the harness")),
    };
    Ok(prepared)
}

// ---------------------------------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------------------------------

/// The result of one case.
#[derive(Debug, Clone)]
pub struct AdminResult {
    /// The case.
    pub case: AdminCase,
    /// What the oracle expects.
    pub expected: Expectation,
    /// The HTTP status of the answer (0 when nothing was sent).
    pub status: u16,
    /// What is wrong, empty when the answer is as expected.
    pub problems: Vec<String>,
    /// The verdict.
    pub verdict: Verdict,
    /// Why the case did not run.
    pub note: Option<String>,
    /// How often a request of the case was sent again because the host answered that it was too busy ([`crate::busy`]).
    pub repeats: u32,
}

/// The result of a run of the administration matrix.
#[derive(Debug, Clone, Default)]
pub struct AdminReport {
    /// Every case, in the order of [`cases`].
    pub results: Vec<AdminResult>,
    /// Problems with an environment itself.
    pub environment_problems: Vec<String>,
    /// The cases the sample left out ([`super::Sampling`]): of those that change something (a world of their own each, which
    /// is slow on PostgreSQL) all but the first of each operation. Not among the results.
    pub left_out: Vec<AdminCase>,
}

/// Why a case that deletes the tenant is left out of an environment that cannot do without it.
pub const ENDS_THE_RUN: &str =
    "deleting the tenant would end the run: the world of this environment is built inside it";

impl AdminReport {
    /// The results with a verdict.
    pub fn with(&self, verdict: &Verdict) -> Vec<&AdminResult> {
        self.results
            .iter()
            .filter(|result| &result.verdict == verdict)
            .collect()
    }

    /// Whether nothing failed.
    pub fn is_clean(&self) -> bool {
        self.environment_problems.is_empty() && self.with(&Verdict::Failed).is_empty()
    }

    /// The number of cases that were sent to the server.
    pub fn executed(&self) -> usize {
        self.results
            .iter()
            .filter(|result| matches!(result.verdict, Verdict::Passed | Verdict::Failed))
            .count()
    }

    /// The cases that needed a request sent again because the host answered that it was too busy ([`crate::busy`]).
    pub fn repeated(&self) -> Vec<&AdminResult> {
        self.results.iter().filter(|result| result.repeats > 0).collect()
    }

    /// Whether more cases needed a repeat than a busy host explains ([`crate::busy::excessive`]).
    pub fn too_many_repeats(&self) -> bool {
        crate::busy::excessive(self.repeated().len(), self.executed())
    }

    /// The skipped cases whose reason is not in `allowed`: a skip that nobody expected.
    pub fn unexpected_skips(&self, allowed: &[&str]) -> Vec<&AdminResult> {
        self.with(&Verdict::Skipped)
            .into_iter()
            .filter(|result| !result.note.as_deref().is_some_and(|note| allowed.contains(&note)))
            .collect()
    }

    /// The cases of `all` that the report has neither as a result nor as left out of the sample: a case that the run lost.
    pub fn missing<'a>(&self, all: &'a [AdminCase]) -> Vec<&'a AdminCase> {
        let accounted: BTreeSet<&AdminCase> = self
            .results
            .iter()
            .map(|result| &result.case)
            .chain(&self.left_out)
            .collect();
        all.iter().filter(|case| !accounted.contains(case)).collect()
    }
}

impl fmt::Display for AdminReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = |verdict| self.with(&verdict).len();
        writeln!(
            f,
            "{} administration cases: {} passed, {} failed, {} skipped",
            self.results.len(),
            count(Verdict::Passed),
            count(Verdict::Failed),
            count(Verdict::Skipped)
        )?;
        if !self.left_out.is_empty() {
            writeln!(
                f,
                "{} more cases are not in the sample of this run",
                self.left_out.len()
            )?;
        }
        for problem in &self.environment_problems {
            writeln!(f, "environment: {problem}")?;
        }
        let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
        for result in self.with(&Verdict::Skipped) {
            *skipped.entry(result.note.clone().unwrap_or_default()).or_default() += 1;
        }
        for (reason, number) in skipped {
            writeln!(f, "skipped ({number}): {reason}")?;
        }
        let repeated = self.repeated();
        if !repeated.is_empty() {
            writeln!(
                f,
                "{} of {} cases needed a request sent again ({} times in all) because the host answered that it was too busy (503):",
                repeated.len(),
                self.executed(),
                repeated.iter().map(|result| result.repeats).sum::<u32>()
            )?;
            for result in repeated.iter().take(10) {
                writeln!(f, "  {} (sent again {} times)", result.case, result.repeats)?;
            }
            if repeated.len() > 10 {
                writeln!(f, "  and {} more", repeated.len() - 10)?;
            }
        }
        // The same disagreement in many cases of one operation is shown once, with the cases it occurs in.
        let mut by_operation: BTreeMap<&str, BTreeMap<String, Vec<&AdminResult>>> = BTreeMap::new();
        for result in self.with(&Verdict::Failed) {
            let signature = format!("expected {}, answered {}", result.expected, result.status);
            by_operation
                .entry(result.case.operation)
                .or_default()
                .entry(signature)
                .or_default()
                .push(result);
        }
        for (operation, signatures) in by_operation {
            writeln!(f, "\n{operation}:")?;
            for (signature, results) in signatures {
                writeln!(f, "  x{} {signature}", results.len())?;
                for result in results.iter().take(3) {
                    writeln!(f, "      e.g. {}", result.case)?;
                    for problem in &result.problems {
                        writeln!(f, "           {problem}")?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Whether `status` is what the expectation stands for on this operation in this environment.
fn status_matches(expected: Expectation, success: &[u16], status: u16) -> bool {
    match expected {
        Expectation::Allow => success.contains(&status),
        Expectation::Unauthenticated => status == 401,
        Expectation::Hidden => status == 404,
        Expectation::Forbidden => status == 403,
        Expectation::PreconditionFailed => status == 412,
    }
}

/// What a case that reaches a service that is not offered yet is answered: 501. Only the cases that get past the door are
/// answered by the service: a request without credentials and another tenant's are judged before it (but not the ids of another
/// tenant, which only a service that looks them up can find to be missing).
fn is_answered_by_the_service(expected: Expectation) -> bool {
    matches!(expected, Expectation::Allow | Expectation::Forbidden)
}

/// Runs one case on an environment with the fixtures [`fixtures`] made; the flag says that a refused request changed the
/// state.
#[expect(
    clippy::too_many_lines,
    reason = "one pass over the checks that every case gets, in the order of the report"
)]
pub async fn run_case(
    env: &dyn MatrixEnv,
    expectations: &Expectations,
    fixtures: &Fixtures,
    case: &AdminCase,
    expected: Expectation,
    seq: usize,
) -> (AdminResult, bool) {
    let mut result = AdminResult {
        case: case.clone(),
        expected,
        status: 0,
        problems: Vec::new(),
        verdict: Verdict::Passed,
        note: None,
        repeats: 0,
    };
    let skip = |mut result: AdminResult, note: String| {
        result.verdict = Verdict::Skipped;
        result.note = Some(note);
        (result, false)
    };
    let Some(operation) = operation(case.operation) else {
        return skip(result, format!("the operation `{}` is not known", case.operation));
    };
    if operation.id == "deleteTenant" && expected == Expectation::Allow && !env.may_delete_tenants() {
        return skip(result, ENDS_THE_RUN.to_owned());
    }
    let Some(actor) = env.book().actor(case.actor, Surface::Api, case.scope.as_deref()) else {
        return skip(
            result,
            format!("the role `{}` has no credential on the API with this scope", case.actor),
        );
    };
    let prepared = match prepare(operation, env.world(), fixtures, seq, case.foreign_ids) {
        Ok(prepared) => prepared,
        Err(note) => return skip(result, note),
    };
    // A service that is not offered yet answers 501 to everybody who reaches it (`[[pending]]`).
    let pending = expectations
        .pending(operation.id)
        .filter(|_| is_answered_by_the_service(expected) || case.foreign_ids);
    let success = success_of(operation, env, fixtures);
    // The state is looked at around a request that is refused, or answered by a service that is not there: neither may change it.
    let refused = expected != Expectation::Allow || pending.is_some();
    // A request that may change something is looked at from before: the state is what a refusal must leave alone, and what a
    // request that the host answered as too busy is compared with, to know whether it did anything.
    let changes = !operation.reads();
    let observed = changes && refused;
    let before = if changes {
        env.observe().await
    } else {
        Ok(Observation::new())
    };
    let (sent, repeats) = busy::repeat_while_busy(Policy::STANDARD, || async {
        let response = env.transport().send(prepared.build(&actor)).await;
        let busy_effect = match &response {
            Ok(response) if busy::is_busy(response) => Some(if changes {
                Effect::of_request(true, before.as_ref().ok(), env.observe().await.ok().as_ref())
            } else {
                Effect::Repeatable
            }),
            _ => None,
        };
        Attempt {
            value: response,
            busy: busy_effect,
        }
    })
    .await;
    result.repeats = repeats;
    let response = match sent {
        Ok(response) => response,
        Err(error) => {
            result.problems.push(format!("the request cannot be sent: {error}"));
            result.verdict = Verdict::Failed;
            return (result, false);
        }
    };
    let after = if observed {
        env.observe().await
    } else {
        Ok(Observation::new())
    };
    let status = response.status.as_u16();
    result.status = status;
    if let Some(pending) = pending {
        if status != 501 {
            result.problems.push(format!(
                "the operation is listed as pending ({}) and is expected to answer 501, but it answered {status}: remove the \
                 [[pending]] row if the service is there now ({})",
                pending.reason,
                response.excerpt(160)
            ));
        }
    } else if !status_matches(expected, &success, status) {
        result.problems.push(format!(
            "answered {status}, expected {expected} ({}): {}",
            if expected == Expectation::Allow {
                format!("one of {success:?}")
            } else {
                "the status of the policy".to_owned()
            },
            response.excerpt(160)
        ));
    } else if expected != Expectation::Allow {
        result.problems.extend(
            detail_problems(Surface::Api, &Observed::Is(expected), &response, expectations.status())
                .into_iter()
                .map(|problem| format!("{problem} ({})", response.excerpt(160))),
        );
    }
    let mut tainted = false;
    if observed {
        match (before, after) {
            (Ok(before), Ok(after)) => {
                let differences = before.diff(&after);
                if !differences.is_empty() {
                    tainted = true;
                    result.problems.push(format!(
                        "the refused request changed the state: {}",
                        differences.iter().take(6).cloned().collect::<Vec<_>>().join("; ")
                    ));
                }
            }
            (Err(error), _) | (_, Err(error)) => {
                result.problems.push(format!("the state cannot be observed: {error}"));
            }
        }
    }
    if expected == Expectation::Hidden && (operation.tenant_in_path || case.foreign_ids) {
        // Another tenant's resource is answered like one that does not exist: a tenant that is not there, or an id that
        // nothing has.
        let mut control = prepared.clone();
        let mut subjects: Vec<String> = Vec::new();
        if case.foreign_ids {
            let nil = "00000000-0000-7000-8000-000000000000";
            for id in fixtures.ids() {
                if control.path.contains(id) {
                    control.path = control.path.replace(id, nil);
                    subjects.push(id.to_owned());
                }
            }
            subjects.push(nil.to_owned());
        } else {
            let slug = env.world().names.tenant.clone();
            control.path = control
                .path
                .replacen(&format!("/tenants/{slug}"), "/tenants/no-such-tenant-xyz", 1);
            subjects.push(slug);
            subjects.push("no-such-tenant-xyz".to_owned());
        }
        // The control asks for something that is not there: it changes nothing, so a busy answer to it is sent again too.
        let (control_sent, control_repeats) =
            busy::send_repeatable(env.transport().as_ref(), &control.build(&actor)).await;
        result.repeats += control_repeats;
        if let Ok(missing) = control_sent {
            let subjects: Vec<&str> = subjects.iter().map(String::as_str).collect();
            if let Err(difference) = same_kind(&response, &missing, &subjects) {
                result.problems.push(format!(
                    "what is hidden is distinguishable from what is not there: {difference}"
                ));
            }
        }
    }
    if !result.problems.is_empty() {
        result.verdict = Verdict::Failed;
    }
    (result, tainted)
}

impl Fixtures {
    /// The ids of what the administrator made, for the controls of the cases that name them.
    fn ids(&self) -> Vec<&str> {
        [
            &self.app_password_id,
            &self.feed_token_id,
            &self.api_token_id,
            &self.webhook_id,
            &self.delivery_id,
            &self.outbox_id,
            &self.external_account_id,
        ]
        .into_iter()
        .filter_map(|id| id.as_deref())
        .collect()
    }
}

/// Whether a case, allowed to change something, needs a world of its own.
fn needs_own_world(case: &AdminCase, expected: Expectation, pending: bool) -> bool {
    expected == Expectation::Allow && !pending && operation(case.operation).is_some_and(|operation| !operation.reads())
}

/// The result of a case that was not sent, because the environment it needs cannot be made: a failure of the run, so that the
/// case is in the report and the run is not clean, and not a case that is missing from it.
fn not_run(case: AdminCase, expected: Expectation, why: String) -> AdminResult {
    AdminResult {
        case,
        expected,
        status: 0,
        problems: vec![why],
        verdict: Verdict::Failed,
        note: None,
        repeats: 0,
    }
}

/// The result of a case that the environment cannot run, with the reason.
fn left_out(case: AdminCase, expected: Expectation, why: &str) -> AdminResult {
    AdminResult {
        case,
        expected,
        status: 0,
        problems: Vec::new(),
        verdict: Verdict::Skipped,
        note: Some(why.to_owned()),
        repeats: 0,
    }
}

/// Runs the administration matrix against an environment.
///
/// Cases that cannot change anything run in sequence on the environment itself; a case that is allowed to change something
/// runs on a world of its own ([`MatrixEnv::fresh`]), or is left out where the environment cannot make one. Every case of
/// [`cases`] is in the report, as a result or as left out of the sample, even when the world it needs cannot be made: it
/// is a failed result then (a case without an expectation in the file is the one exception, and is an environment problem).
pub async fn run(env: &dyn MatrixEnv, expectations: &Expectations, options: &RunOptions) -> AdminReport {
    let mut report = AdminReport::default();
    let can_isolate = env.isolation() == Isolation::PerCase;
    let mut shared = Vec::new();
    let mut own = Vec::new();
    // A world of their own costs seconds on PostgreSQL: a sample runs the first case of each operation in one.
    let mut worlds: BTreeSet<&str> = BTreeSet::new();
    let mut collected: Vec<(usize, AdminResult)> = Vec::new();
    for (seq, case) in cases(expectations).into_iter().enumerate() {
        let expected = match expected(expectations, &case) {
            Ok(expected) => expected,
            Err(error) => {
                report.environment_problems.push(error.to_string());
                continue;
            }
        };
        let pending = expectations.pending(case.operation).is_some();
        if needs_own_world(&case, expected, pending) {
            if options.sampling != super::Sampling::Everything && !worlds.insert(case.operation) {
                report.left_out.push(case);
                continue;
            }
            if can_isolate {
                own.push((seq, case, expected));
            } else {
                collected.push((seq, left_out(case, expected, super::NEEDS_OWN_WORLD)));
            }
        } else {
            shared.push((seq, case, expected));
        }
    }

    let mut current: Option<(Box<dyn MatrixEnv>, Fixtures)> = None;
    let mut replacement_failed: Option<String> = None;
    let shared_fixtures = fixtures(env).await;
    for (seq, case, expected) in shared {
        // The environment that a refused request changed could not be replaced: the cases that are left have none to run on.
        if let Some(why) = &replacement_failed {
            collected.push((seq, not_run(case, expected, why.clone())));
            continue;
        }
        let (result, tainted) = match &current {
            Some((owned, owned_fixtures)) => {
                run_case(owned.as_ref(), expectations, owned_fixtures, &case, expected, seq).await
            }
            None => run_case(env, expectations, &shared_fixtures, &case, expected, seq).await,
        };
        collected.push((seq, result));
        if tainted {
            match env.fresh().await {
                Ok(fresh) => {
                    let made = fixtures(fresh.as_ref()).await;
                    current = Some((fresh, made));
                }
                Err(error) => {
                    replacement_failed = Some(format!(
                        "no environment replaces the one a refused request changed: {error}"
                    ));
                }
            }
        }
    }

    let shards = if env.parallel_worlds() {
        options.concurrency.max(1)
    } else {
        1
    };
    let isolated = own.into_iter().map(|(seq, case, expected)| async move {
        let result = match env.fresh().await {
            Ok(fresh) => {
                let made = fixtures(fresh.as_ref()).await;
                run_case(fresh.as_ref(), expectations, &made, &case, expected, seq)
                    .await
                    .0
            }
            Err(error) => not_run(
                case,
                expected,
                format!("no world of its own can be made for the case: {error}"),
            ),
        };
        (seq, result)
    });
    collected.extend(
        futures::stream::iter(isolated)
            .buffer_unordered(shards)
            .collect::<Vec<_>>()
            .await,
    );
    collected.sort_by_key(|(seq, _)| *seq);
    report.results = collected.into_iter().map(|(_, result)| result).collect();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundled() -> Expectations {
        Expectations::bundled().unwrap()
    }

    fn expect(operation: &'static str, actor: ActorRole, scope: Option<&str>) -> Expectation {
        expected(
            &bundled(),
            &AdminCase {
                scope: scope.map(str::to_owned),
                ..AdminCase::new(operation, actor)
            },
        )
        .unwrap()
    }

    #[test]
    fn the_table_lists_each_operation_once_in_the_order_of_the_paths() {
        let mut ids: Vec<&str> = OPERATIONS.iter().map(|operation| operation.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), OPERATIONS.len());
        assert_eq!(OPERATIONS.len(), 47);
        let keys: Vec<(&str, &str)> = OPERATIONS
            .iter()
            .map(|operation| (operation.path, operation.method))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "the order of docs/openapi.json: paths, then methods");
        assert!(operation("listTenants").is_some_and(|operation| !operation.tenant_in_path));
        assert!(operation("getTenant").is_some_and(|operation| operation.tenant_in_path && operation.reads()));
        // Exactly the paths that name a tenant say so.
        for operation in OPERATIONS {
            assert_eq!(
                operation.tenant_in_path,
                operation.path.contains("{tenant}"),
                "{}",
                operation.id
            );
        }
    }

    #[test]
    fn every_operation_of_the_table_has_scopes_in_the_file_and_the_file_lists_nothing_else() {
        let expectations = bundled();
        let mut listed = expectations.admin_operations();
        listed.sort_unstable();
        let mut known: Vec<&str> = OPERATIONS.iter().map(|operation| operation.id).collect();
        known.sort_unstable();
        assert_eq!(listed, known);
        // The pending rows name operations of the table.
        for pending in expectations.pending_operations() {
            assert!(operation(pending).is_some(), "{pending}");
        }
    }

    #[test]
    fn the_rules_of_the_file_are_what_the_oracle_answers() {
        use ActorRole::{
            Anonymous, GroupMember, OtherTenantToken, OtherTenantUser, Owner, ServicePrincipal, SuspendedUser,
            SystemToken, TenantToken,
        };
        use Expectation::{Allow, Forbidden, Hidden, Unauthenticated};
        assert_eq!(expect("listWebhooks", Anonymous, None), Unauthenticated);
        assert_eq!(expect("listWebhooks", SuspendedUser, None), Unauthenticated);
        assert_eq!(
            expect("listWebhooks", Owner, None),
            Forbidden,
            "principals never administer"
        );
        assert_eq!(expect("listWebhooks", ServicePrincipal, None), Forbidden);
        assert_eq!(expect("listWebhooks", GroupMember, None), Forbidden);
        assert_eq!(expect("listWebhooks", OtherTenantUser, None), Hidden);
        assert_eq!(expect("listWebhooks", OtherTenantToken, None), Hidden);
        assert_eq!(expect("listWebhooks", TenantToken, None), Allow);
        assert_eq!(expect("listWebhooks", TenantToken, Some("webhooks:manage")), Allow);
        assert_eq!(expect("listWebhooks", TenantToken, Some("events:read")), Forbidden);
        assert_eq!(
            expect("listWebhooks", SystemToken, None),
            Forbidden,
            "system tokens read no tenant data"
        );
        // Operations of the installation: tenant tokens never have `system:tenants`.
        assert_eq!(expect("putTenant", TenantToken, None), Forbidden);
        assert_eq!(expect("putTenant", SystemToken, None), Allow);
        assert_eq!(
            expect("listTenants", OtherTenantToken, None),
            Forbidden,
            "no tenant in the path: nothing to hide"
        );
        assert_eq!(expect("listTenants", OtherTenantUser, None), Forbidden);
        // A tenant is also readable by its administrator, with `principals:read`.
        assert_eq!(expect("getTenant", TenantToken, Some("principals:read")), Allow);
        assert_eq!(expect("getTenant", SystemToken, None), Allow);
        assert_eq!(expect("patchTenant", TenantToken, Some("principals:read")), Forbidden);
        // The administrator of another tenant is refused in its own tenant, and finds nothing under the ids of another.
        let foreign = AdminCase {
            foreign_ids: true,
            ..AdminCase::new("getWebhook", OtherTenantToken)
        };
        assert_eq!(expected(&bundled(), &foreign).unwrap(), Hidden);
    }

    #[test]
    fn the_scopes_the_file_lists_are_the_scopes_the_domain_allows() {
        // The tokens of the world are made from the domain (`Scope::allowed_for`) and the matrix from the file: they must agree.
        use davhaven_domain::{Scope, TokenKind};
        let expectations = bundled();
        for (class, kind) in [
            (TokenClass::Tenant, TokenKind::Tenant),
            (TokenClass::System, TokenKind::System),
            (TokenClass::Principal, TokenKind::Principal),
        ] {
            let mut listed: Vec<&str> = expectations.token_scopes(class).iter().map(String::as_str).collect();
            listed.sort_unstable();
            let mut allowed: Vec<&str> = Scope::ALL
                .iter()
                .filter(|scope| scope.allowed_for(kind))
                .map(|scope| scope.as_str())
                .collect();
            allowed.sort_unstable();
            assert_eq!(listed, allowed, "{class}");
        }
    }

    #[test]
    fn the_cases_cross_every_operation_with_every_actor_and_every_scope_of_a_tenant_token() {
        let expectations = bundled();
        let all = cases(&expectations);
        let scopes = tenant_scopes(&expectations);
        assert!(
            !scopes
                .iter()
                .any(|scope| scope.starts_with("mcp:") || scope == "system:tenants")
        );
        let with_ids = OPERATIONS.iter().filter(|operation| operation.names_an_id()).count();
        assert!(with_ids > 10, "{with_ids}");
        assert_eq!(
            all.len(),
            OPERATIONS.len() * (ActorRole::ALL.len() + scopes.len()) + with_ids,
            "every actor, every scope of a tenant token, and the other tenant's administrator with the ids of the first"
        );
        for case in &all {
            expected(&expectations, case).unwrap();
        }
        let allowed: Vec<String> = all
            .iter()
            .filter(|case| {
                case.operation == "listAuditEvents" && expected(&expectations, case).unwrap() == Expectation::Allow
            })
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            allowed,
            vec![
                "tenant_token listAuditEvents",
                "tenant_token[audit:read] listAuditEvents"
            ],
            "the token with every scope and the token with the scope of the operation"
        );
        let idor: Vec<String> = all
            .iter()
            .filter(|case| case.foreign_ids && case.operation == "revokeApiToken")
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            idor,
            vec!["other_tenant_token revokeApiToken (with ids of another tenant)"]
        );
    }

    #[test]
    fn requests_are_built_for_every_operation() {
        let world = FixtureWorld::standard();
        let fixtures = Fixtures {
            app_password_id: Some("ap".to_owned()),
            feed_token_id: Some("ft".to_owned()),
            api_token_id: Some("at".to_owned()),
            webhook_id: Some("wh".to_owned()),
            delivery_id: Some("dl".to_owned()),
            outbox_id: Some("ob".to_owned()),
            external_account_id: Some("ea".to_owned()),
            calendar_id: Some("cal".to_owned()),
            tenant_etag: Some("\"v3\"".to_owned()),
            principal_etag: Some("\"v2\"".to_owned()),
            missing: BTreeMap::new(),
        };
        for operation in OPERATIONS {
            let prepared = prepare(operation, &world, &fixtures, 7, false)
                .unwrap_or_else(|error| panic!("{}: {error}", operation.id));
            assert_eq!(prepared.method, operation.method, "{}", operation.id);
            let template = operation.path.replace("{tenant}", &world.names.tenant);
            let prefix = template.split("/{").next().unwrap();
            assert!(
                prepared.path.starts_with(&format!("/api/v1{prefix}")),
                "{}: {} does not start with {prefix}",
                operation.id,
                prepared.path
            );
            let built = prepared.build(&Actor::bearer("t"));
            assert_eq!(built.method.as_str(), operation.method);
        }
        let delete = prepare(operation("deleteTenant").unwrap(), &world, &fixtures, 1, false).unwrap();
        assert_eq!(delete.headers, vec![("if-match", "\"v3\"".to_owned())]);
        let without = prepare(
            operation("revokeApiToken").unwrap(),
            &world,
            &Fixtures::default(),
            1,
            false,
        )
        .unwrap_err();
        assert!(without.contains("an API token"), "{without}");
        // What the harness makes carries the label of the run, so that a reset of a deployed instance finds it again.
        let token = prepare(operation("createApiToken").unwrap(), &world, &fixtures, 7, false).unwrap();
        assert!(token.body.unwrap().to_string().contains("conformance-matrix-7"));
        let principal = prepare(operation("putPrincipal").unwrap(), &world, &fixtures, 7, false).unwrap();
        assert!(
            principal.path.ends_with("/principals/conformance-mx-7"),
            "{}",
            principal.path
        );
        // The request with foreign ids goes to the other tenant and names the ids of the first.
        let foreign = prepare(operation("revokeAppPassword").unwrap(), &world, &fixtures, 7, true).unwrap();
        assert_eq!(
            foreign.path, "/api/v1/tenants/globex/principals/gina/app-passwords/ap",
            "the attacker's own tenant and principal, the victim's id"
        );
    }

    #[test]
    fn what_a_missing_fixture_is_called_is_what_the_operations_ask_for() {
        // The reason shown for an operation that cannot be asked for is the reason the fixtures recorded under the same name.
        let mut fixtures = Fixtures::default();
        fixtures.lack(needs::WEBHOOK, "the instance refused it");
        let world = FixtureWorld::standard();
        let error = prepare(operation("getWebhook").unwrap(), &world, &fixtures, 1, false).unwrap_err();
        assert!(
            error.contains("a webhook") && error.contains("the instance refused it"),
            "{error}"
        );
    }

    #[test]
    fn statuses_mean_what_the_policy_and_the_operation_say() {
        let create = operation("createExternalAccount").unwrap();
        assert!(
            status_matches(Expectation::Allow, create.success, 409),
            "a feature that is off is understood"
        );
        assert!(!status_matches(Expectation::Allow, create.success, 403));
        assert!(status_matches(Expectation::Hidden, create.success, 404));
        assert!(
            status_matches(Expectation::Forbidden, create.success, 403)
                && status_matches(Expectation::Unauthenticated, create.success, 401)
        );
        // Deleting an account is answered 204: a 404 is the answer for an account that is not there, not a success.
        let delete = operation("deleteExternalAccount").unwrap();
        assert!(status_matches(Expectation::Allow, delete.success, 204));
        assert!(!status_matches(Expectation::Allow, delete.success, 404));
        assert!(status_matches(Expectation::Hidden, delete.success, 404));
    }

    #[test]
    fn only_the_callers_that_reach_the_service_are_answered_by_it() {
        assert!(is_answered_by_the_service(Expectation::Allow));
        assert!(is_answered_by_the_service(Expectation::Forbidden));
        assert!(!is_answered_by_the_service(Expectation::Unauthenticated));
        assert!(!is_answered_by_the_service(Expectation::Hidden));
        let expectations = bundled();
        assert!(
            expectations.pending_operations().is_empty(),
            "every operation of the management API is offered: {:?}",
            expectations.pending_operations()
        );
        assert!(expectations.pending("listProviders").is_none());
    }
}
