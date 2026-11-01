//! The staging runner (PLAN 4.2) against an application that listens on a socket.
//!
//! The application is the one `davhaven serve` builds, started without a world. The tenants of the run are created the way
//! an operator creates them (`davhaven admin bootstrap`, which also hands out the administration tokens, and
//! `davhaven admin system-token`), and everything after that goes through `davhaven_testkit::staging` over HTTP:
//! provisioning the fixture world with the management API and DAV, the matrices, the client flows, the reset between cases
//! and the deletion of the tenants.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use davhaven_testkit::davhaven_app::{AppDeps, AppServices};
use davhaven_testkit::davhaven_domain::{DomainName, ScopeSet, TenantSlug};
use davhaven_testkit::davhaven_fixtures::{ActorRole, CalendarRole};
use davhaven_testkit::davhaven_server::admin::{
    BootstrapRequest, SettingsFlags, TokenSink, bootstrap, default_scopes, principal_token, system_token,
};
use davhaven_testkit::flow::{self, FlowVerdict};
use davhaven_testkit::permissions::{MatrixEnv as _, Sampling};
use davhaven_testkit::staging::api::Api;
use davhaven_testkit::staging::provision::{LABEL, RUN_TOKEN_DAYS};
use davhaven_testkit::staging::{
    Deployment, Options, PrincipalTokenIssuer, PrincipalTokenRequest, StagingConfig, StagingError, run,
};
use davhaven_testkit::{Expectations, McpHandle, Served, Surface, TestApp};

/// An application with the two tenants of a run and its operator tokens, listening on a socket.
struct Instance {
    app: TestApp,
    served: Served,
    config: StagingConfig,
}

/// The command of the operator, `davhaven admin principal-token create ... --print-token`, as the function it runs: the
/// token is made by the same code and its secret comes back on the standard output of the command.
struct OperatorCommand {
    deps: AppDeps,
    services: AppServices,
}

#[async_trait]
impl PrincipalTokenIssuer for OperatorCommand {
    async fn issue(&self, request: &PrincipalTokenRequest) -> Result<String, String> {
        let create = davhaven_testkit::davhaven_server::admin::PrincipalTokenRequest {
            tenant: request.tenant.clone(),
            principal: request.principal.clone(),
            label: request.label.clone(),
            scopes: request.scopes.iter().collect::<ScopeSet>(),
            expires_at: Some(self.deps.clock.now() + chrono::Duration::days(i64::from(request.expires_in_days))),
        };
        // The function takes the standard output of the command as a `&mut dyn Write`, which a future that is `Send` cannot hold
        // across an await point: it runs on a thread of its own, as the command does in its own process.
        let (deps, services, runtime) = (
            self.deps.clone(),
            self.services.clone(),
            tokio::runtime::Handle::current(),
        );
        tokio::task::spawn_blocking(move || {
            let mut printed = Vec::new();
            runtime
                .block_on(principal_token(
                    &deps,
                    &services,
                    &create,
                    &TokenSink::Stdout,
                    &mut printed,
                ))
                .map_err(|error| error.to_string())?;
            // As the real issuer does: a command that prints nothing (the token with this label exists already, and its secret
            // is shown once) has made no token that the run could use.
            printed_secret(&printed).ok_or_else(|| "it printed nothing".to_owned())
        })
        .await
        .map_err(|error| error.to_string())?
    }
}

/// The first line of what a command printed, when there is one.
fn printed_secret(output: &[u8]) -> Option<String> {
    String::from_utf8(output.to_vec())
        .unwrap()
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
}

/// The first line of what a command printed, which the commands of the tests always print.
fn secret_of(output: &[u8]) -> String {
    printed_secret(output).unwrap()
}

/// The JSON-RPC message that `list_calendars` is answered with when it is called with `actor`.
async fn list_calendars_as(deployment: &Deployment, actor: davhaven_testkit::Actor) -> serde_json::Value {
    let response = McpHandle::new(deployment.transport(), actor)
        .call_tool("list_calendars", &serde_json::json!({}))
        .unwrap()
        .send()
        .await
        .unwrap();
    davhaven_testkit::handles::mcp_message(&response).unwrap()
}

/// The calendars `list_calendars` shows the holder of the token of `role`, as (id, writable), ordered by id.
async fn listed_calendars(deployment: &Deployment, role: ActorRole) -> Vec<(String, bool)> {
    let actor = deployment.book().actor(role, Surface::Mcp, None).unwrap();
    let message = list_calendars_as(deployment, actor).await;
    assert_ne!(
        message.pointer("/result/isError"),
        Some(&serde_json::Value::Bool(true)),
        "{role}: {message}"
    );
    let calendars = message
        .pointer("/result/structuredContent/calendars")
        .and_then(serde_json::Value::as_array);
    assert!(calendars.is_some(), "{role}: {message}");
    let mut listed: Vec<(String, bool)> = calendars
        .into_iter()
        .flatten()
        .map(|calendar| {
            (
                calendar
                    .get("calendar_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap()
                    .to_owned(),
                calendar.get("writable").and_then(serde_json::Value::as_bool).unwrap(),
            )
        })
        .collect();
    listed.sort();
    listed
}

/// Creates a tenant and its administration token with the command the operator runs (`--mcp-enabled`, which a run needs for the
/// MCP column).
async fn bootstrapped(app: &TestApp, slug: &str, login_domain: &str) -> String {
    bootstrapped_with(app, slug, login_domain, true).await
}

/// [`bootstrapped`], with MCP switched on or not.
async fn bootstrapped_with(app: &TestApp, slug: &str, login_domain: &str, mcp: bool) -> String {
    let mut printed = Vec::new();
    bootstrap(
        app.deps(),
        app.services(),
        &BootstrapRequest {
            tenant: TenantSlug::parse(slug).unwrap(),
            display_name: None,
            login_domain: Some(DomainName::parse(login_domain).unwrap()),
            settings: SettingsFlags {
                mcp_enabled: Some(mcp),
                ..SettingsFlags::default()
            },
            label: "bootstrap".to_owned(),
            scopes: default_scopes(),
            expires_at: None,
        },
        &TokenSink::Stdout,
        &mut printed,
    )
    .await
    .unwrap();
    secret_of(&printed)
}

/// What the operator prepares besides the two tenants.
#[derive(Clone, Copy)]
struct Preparation {
    /// A system token: the run switches MCP on in the tenants and deletes them at the end.
    system_token: bool,
    /// The command that issues the principal tokens that open MCP.
    token_command: bool,
    /// MCP switched on in the tenants (`admin bootstrap --mcp-enabled`).
    mcp: bool,
}

impl Preparation {
    /// Everything: what a run with all its options has.
    const FULL: Self = Self {
        system_token: true,
        token_command: true,
        mcp: true,
    };
}

async fn instance(run_id: &str) -> Instance {
    instance_with(run_id, Preparation::FULL).await
}

async fn instance_with(run_id: &str, preparation: Preparation) -> Instance {
    let app = TestApp::builder().empty().build().await.unwrap();
    let tenant_token = bootstrapped_with(
        &app,
        &format!("{run_id}-a"),
        &format!("{run_id}-a.example"),
        preparation.mcp,
    )
    .await;
    let other_tenant_token = bootstrapped_with(
        &app,
        &format!("{run_id}-b"),
        &format!("{run_id}-b.example"),
        preparation.mcp,
    )
    .await;
    let system_token = if preparation.system_token {
        let mut printed = Vec::new();
        system_token(app.deps(), "conformance", None, &TokenSink::Stdout, &mut printed)
            .await
            .unwrap();
        Some(secret_of(&printed))
    } else {
        None
    };
    let served = app.serve().await.unwrap();
    let token_issuer = preparation.token_command.then(|| -> Arc<dyn PrincipalTokenIssuer> {
        Arc::new(OperatorCommand {
            deps: app.deps().clone(),
            services: app.services().clone(),
        })
    });
    let config = StagingConfig {
        base_url: served.base_url.clone(),
        run_id: run_id.to_owned(),
        tenant_token,
        other_tenant_token,
        system_token,
        clock: Arc::clone(&app.deps().clock),
        token_issuer,
    };
    Instance { app, served, config }
}

fn scenario_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/scenarios")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_world_is_built_over_http_and_every_role_can_use_what_it_was_given() {
    let instance = instance("r1").await;
    let deployment = Deployment::provision(instance.config.clone()).await.unwrap();
    assert_eq!(deployment.world().names.tenant, "r1-a");

    // Every user of the world logs in to DAV with the app password the instance issued; the suspended one cannot.
    let transport = deployment.transport();
    for role in ActorRole::ALL {
        let Some(principal) = deployment
            .world()
            .principal(*role)
            .ok()
            .filter(|p| p.role == Some(*role))
        else {
            continue;
        };
        // The service principal has no app password: its token is what the book offers on DAV, and DAV refuses it.
        let Some(actor @ davhaven_testkit::Actor::Basic { .. }) =
            deployment.book().actor(*role, davhaven_testkit::Surface::Dav, None)
        else {
            continue;
        };
        let home = format!("/dav/calendars/{}/{}/", principal.tenant, principal.name);
        let request = davhaven_testkit::permissions::request(&actor, "PROPFIND", &home).header("depth", "0");
        let status = transport.send(request).await.unwrap().status.as_u16();
        let wanted = if *role == ActorRole::SuspendedUser { 401 } else { 207 };
        assert_eq!(status, wanted, "{role} on {home}");
    }

    // Every principal of the world has a token that opens MCP: the service principals got theirs from the administration token of
    // the tenant, the users from the command of the operator.
    for role in ActorRole::ALL.iter().filter(|role| role.principal_name().is_some()) {
        assert!(
            !deployment.book().lacks_mcp_token(*role, None),
            "{role} has a token that opens MCP"
        );
    }
    let group = deployment.mcp_ids(CalendarRole::Group).await.unwrap().calendar_id;
    let managed = deployment.mcp_ids(CalendarRole::Managed).await.unwrap().calendar_id;
    let mut wanted = vec![(group.clone(), true), (managed.clone(), false)];
    wanted.sort();
    assert_eq!(
        listed_calendars(&deployment, ActorRole::ServiceGrantee).await,
        wanted,
        "the assistant works in the calendar of the group and reads the managed one"
    );
    assert_eq!(
        listed_calendars(&deployment, ActorRole::ServiceWriter).await,
        vec![(managed, true)],
        "a grant of read_write reaches the managed calendar on MCP, where DAV caps it at read"
    );
    assert!(
        listed_calendars(&deployment, ActorRole::GroupMember)
            .await
            .contains(&(group, true)),
        "the token the operator issued to a user works"
    );

    // The invitations: one is waiting for the pending sharee, none for the sharee who declined.
    assert!(
        deployment.invitation_uid().await.unwrap().is_some(),
        "the pending sharee has an invitation"
    );

    // The state the matrices compare is readable, and a write over the API changes it.
    let before = deployment.observe_http().await.unwrap();
    assert!(
        before
            .get("calendars r1-a")
            .is_some_and(|text| text.contains("olivia/personal:")),
        "{before:?}"
    );
    let ids = deployment.mcp_ids(CalendarRole::Personal).await.unwrap();
    assert!(!ids.calendar_id.is_empty() && !ids.event_id.is_empty());
    let owner = deployment.book().principal_token(ActorRole::Owner).unwrap().to_owned();
    let request = davhaven_testkit::permissions::request(
        &davhaven_testkit::Actor::bearer(owner),
        "PUT",
        "/api/v1/tenants/r1-a/principals/olivia/calendars/personal/objects/by-key/staging-1",
    )
    .header("accept", "application/json")
    .content(
        "application/json",
        r#"{"summary":"Written by the test","start":{"date_time":"2027-06-01T09:00:00Z"},"end":{"date_time":"2027-06-01T10:00:00Z"}}"#,
    );
    let written = transport.send(request).await.unwrap();
    assert!(written.status.is_success(), "{}", written.text());
    let after = deployment.observe_http().await.unwrap();
    assert!(
        !before.diff(&after).is_empty(),
        "a write moves the sync token of the calendar"
    );

    // A feed token can be made for a calendar the principal reads, and not for one it does not.
    assert!(
        deployment
            .feed_token(ActorRole::Owner, CalendarRole::Personal)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        deployment
            .feed_token(ActorRole::OtherUser, CalendarRole::Personal)
            .await
            .unwrap()
            .is_none()
    );
    drop(instance.served);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_gives_a_new_world_with_new_secrets_and_the_old_ones_stop_working() {
    let instance = instance("r2").await;
    let deployment = Deployment::provision(instance.config.clone()).await.unwrap();
    let old = deployment
        .book()
        .actor(ActorRole::Owner, davhaven_testkit::Surface::Dav, None)
        .unwrap();
    let transport = deployment.transport();
    let home = "/dav/calendars/r2-a/olivia/";
    let propfind = |actor: &davhaven_testkit::Actor| {
        davhaven_testkit::permissions::request(actor, "PROPFIND", home).header("depth", "0")
    };
    assert_eq!(transport.send(propfind(&old)).await.unwrap().status.as_u16(), 207);

    // A change that a reset takes back.
    let admin = davhaven_testkit::Actor::bearer(&instance.config.tenant_token);
    let deleted = transport
        .send(
            davhaven_testkit::permissions::request(
                &admin,
                "DELETE",
                "/api/v1/tenants/r2-a/principals/olivia?purge=true",
            )
            .header("if-match", "\"v1\""),
        )
        .await
        .unwrap();
    assert!(deleted.status.is_success(), "{}", deleted.text());

    let again = deployment.reset().await.unwrap();
    let new = again
        .book()
        .actor(ActorRole::Owner, davhaven_testkit::Surface::Dav, None)
        .unwrap();
    assert_ne!(old, new, "the secrets are new");
    assert_eq!(transport.send(propfind(&new)).await.unwrap().status.as_u16(), 207);
    assert_eq!(
        transport.send(propfind(&old)).await.unwrap().status.as_u16(),
        401,
        "the old app password was revoked with its principal"
    );
    drop(instance.app);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tenant_with_another_login_domain_is_refused_with_the_command_that_creates_the_right_one() {
    let app = TestApp::builder().empty().build().await.unwrap();
    let tenant_token = bootstrapped(&app, "r3-a", "wrong.example").await;
    let other_tenant_token = bootstrapped(&app, "r3-b", "r3-b.example").await;
    let served = app.serve().await.unwrap();
    let config = StagingConfig {
        base_url: served.base_url.clone(),
        run_id: "r3".to_owned(),
        tenant_token,
        other_tenant_token,
        system_token: None,
        clock: Arc::clone(&app.deps().clock),
        token_issuer: None,
    };
    let error = Deployment::provision(config).await.unwrap_err();
    assert!(matches!(error, StagingError::Setup(_)), "{error}");
    let text = error.to_string();
    assert!(
        text.contains("davhaven admin bootstrap --tenant r3-a --login-domain r3-a.example"),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_permission_matrix_runs_over_http_and_leaves_out_what_would_change_the_world() {
    let instance = instance("r4").await;
    // A sample on pull requests, like the other suites that are expensive (every case with `CONFORMANCE_FULL=1`): the whole matrix
    // over HTTP takes several minutes with its MCP column, which asks for one case at a time, and what it adds to the sample is
    // more of the same requests. The sample takes two and a half; `.config/nextest.toml` gives this test ten minutes, not three.
    let report = run(
        instance.config.clone(),
        &Expectations::bundled().unwrap(),
        Options {
            keep: true,
            sampling: Sampling::for_pull_requests(),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let matrix = report.matrix.as_ref().unwrap();
    let skipped = matrix.with(&davhaven_testkit::permissions::Verdict::Skipped).len();
    assert!(skipped > 30, "the cases that change something are left out: {skipped}");
    assert!(
        matrix.executed() > 800,
        "only {} cases ran:\n{matrix}",
        matrix.executed()
    );
    assert!(
        matrix.executed_on(Surface::Mcp) > 100,
        "the MCP column ran only {} cases:\n{matrix}",
        matrix.executed_on(Surface::Mcp)
    );
    // What is left out has one of the reasons of a deployed instance: a case that changes something needs a world of its own, and
    // the invitation is not performed. Every role has a token that opens MCP (the operator's command issues the users'), so the MCP
    // column runs, and nothing is left out for want of a token.
    let accepted = [
        davhaven_testkit::permissions::NEEDS_OWN_WORLD,
        davhaven_testkit::permissions::mcp::NO_INVITATION,
    ];
    let unexpected = matrix.unexpected_skips(&accepted);
    assert!(
        unexpected.is_empty(),
        "{} cases were left out for a reason nobody expected, e.g. {}: {:?}",
        unexpected.len(),
        unexpected
            .first()
            .map(|result| result.case.to_string())
            .unwrap_or_default(),
        unexpected.first().and_then(|result| result.note.clone())
    );
    let administration = report.admin.as_ref().unwrap();
    assert!(
        administration.executed() > 300,
        "only {} administration cases ran:\n{administration}",
        administration.executed()
    );
    let unexpected = administration.unexpected_skips(&[
        davhaven_testkit::permissions::NEEDS_OWN_WORLD,
        davhaven_testkit::permissions::admin::ENDS_THE_RUN,
    ]);
    assert!(
        unexpected.is_empty(),
        "{} administration cases were left out for a reason nobody expected, e.g. {}: {:?}",
        unexpected.len(),
        unexpected
            .first()
            .map(|result| result.case.to_string())
            .unwrap_or_default(),
        unexpected.first().and_then(|result| result.note.clone())
    );
    assert!(report.is_clean(), "{report}");
    drop(instance);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_flows_run_on_a_world_of_their_own_and_the_tenants_are_deleted_at_the_end() {
    let instance = instance("r5").await;
    let all = flow::load_scenarios(&scenario_dir()).unwrap();
    let chosen: Vec<_> = all
        .into_iter()
        .filter(|(_, scenario)| {
            matches!(
                scenario.name.as_str(),
                "apple-calendar-crud" | "thunderbird-accept" | "ccs-caldavtester-share"
            )
        })
        .collect();
    assert_eq!(chosen.len(), 3, "the scenarios of the test exist");
    let report = run(
        instance.config.clone(),
        &Expectations::bundled().unwrap(),
        Options {
            matrices: false,
            flows: chosen,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let flows = report.flows.as_ref().unwrap();
    assert_eq!(flows.results.len(), 3);
    assert!(
        flows
            .results
            .iter()
            .all(|(_, verdict, _)| *verdict == FlowVerdict::Passed),
        "{report}"
    );
    assert!(report.torn_down, "{report}");

    // The tenants are gone: the system token no longer finds them.
    let system = davhaven_testkit::Actor::bearer(instance.config.system_token.as_ref().unwrap());
    let transport = davhaven_testkit::HttpTransport::new(instance.served.base_url.clone()).unwrap();
    let gone = davhaven_testkit::Transport::send(
        &transport,
        davhaven_testkit::permissions::request(&system, "GET", "/api/v1/tenants/r5-a"),
    )
    .await
    .unwrap();
    assert_eq!(gone.status.as_u16(), 404, "{}", gone.text());
}

/// The request that reads `path` with the token of the operator of the tenant.
fn read(token: &str, path: &str) -> davhaven_testkit::TestRequest {
    davhaven_testkit::permissions::request(&davhaven_testkit::Actor::bearer(token), "GET", path)
        .header("accept", "application/json")
}

/// Makes a principal that no run made, as the operator of a real tenant would have.
async fn add_stranger(instance: &Instance, tenant: &str) {
    let transport = davhaven_testkit::HttpTransport::new(instance.served.base_url.clone()).unwrap();
    let made = davhaven_testkit::Transport::send(
        &transport,
        davhaven_testkit::permissions::request(
            &davhaven_testkit::Actor::bearer(&instance.config.tenant_token),
            "PUT",
            &format!("/api/v1/tenants/{tenant}/principals/stranger"),
        )
        .header("accept", "application/json")
        .content(
            "application/json",
            format!(
                r#"{{"kind":"user","display_name":"Stranger","email":"stranger@{tenant}.example","addresses":[]}}"#
            ),
        ),
    )
    .await
    .unwrap();
    assert!(made.status.is_success(), "{}", made.text());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tenant_that_holds_a_principal_that_no_run_made_is_refused_before_anything_is_written() {
    let instance = instance("r6").await;
    add_stranger(&instance, "r6-a").await;
    let error = Deployment::provision(instance.config.clone()).await.unwrap_err();
    assert!(matches!(error, StagingError::Setup(_)), "{error}");
    assert!(error.to_string().contains("stranger"), "{error}");

    // Nothing of the world was written, and the principal of the tenant is still there.
    let transport = davhaven_testkit::HttpTransport::new(instance.served.base_url.clone()).unwrap();
    let token = &instance.config.tenant_token;
    let olivia = davhaven_testkit::Transport::send(&transport, read(token, "/api/v1/tenants/r6-a/principals/olivia"))
        .await
        .unwrap();
    assert_eq!(olivia.status.as_u16(), 404, "{}", olivia.text());
    let stranger =
        davhaven_testkit::Transport::send(&transport, read(token, "/api/v1/tenants/r6-a/principals/stranger"))
            .await
            .unwrap();
    assert!(stranger.status.is_success(), "{}", stranger.text());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_does_not_delete_a_principal_that_no_run_made() {
    let instance = instance("r7").await;
    let deployment = Deployment::provision(instance.config.clone()).await.unwrap();
    add_stranger(&instance, "r7-a").await;
    let error = deployment.reset().await.unwrap_err();
    assert!(matches!(error, StagingError::Setup(_)), "{error}");

    let transport = davhaven_testkit::HttpTransport::new(instance.served.base_url.clone()).unwrap();
    let stranger = davhaven_testkit::Transport::send(
        &transport,
        read(
            &instance.config.tenant_token,
            "/api/v1/tenants/r7-a/principals/stranger",
        ),
    )
    .await
    .unwrap();
    assert!(
        stranger.status.is_success(),
        "the stranger is still there: {}",
        stranger.text()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tokens_of_the_wrong_tenant_stop_the_run_before_it_writes() {
    let instance = instance("r8").await;
    // The tokens are swapped: each one belongs to the tenant the run does not use it for.
    let swapped = StagingConfig {
        tenant_token: instance.config.other_tenant_token.clone(),
        other_tenant_token: instance.config.tenant_token.clone(),
        ..instance.config.clone()
    };
    let error = Deployment::provision(swapped).await.unwrap_err();
    assert!(
        matches!(error, StagingError::Unexpected { status: 404, .. }),
        "the token of the other tenant sees nothing of this one: {error}"
    );

    let transport = davhaven_testkit::HttpTransport::new(instance.served.base_url.clone()).unwrap();
    let olivia = davhaven_testkit::Transport::send(
        &transport,
        read(&instance.config.tenant_token, "/api/v1/tenants/r8-a/principals/olivia"),
    )
    .await
    .unwrap();
    assert_eq!(olivia.status.as_u16(), 404, "nothing was written: {}", olivia.text());
}

/// An issuer whose command always fails, as the command of an operator does when the host cannot be reached.
struct BrokenCommand;

#[async_trait]
impl PrincipalTokenIssuer for BrokenCommand {
    async fn issue(&self, _request: &PrincipalTokenRequest) -> Result<String, String> {
        Err("it failed (exit status: 255)".to_owned())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_has_a_token_that_opens_mcp_only_when_the_operator_issues_it() {
    let instance = instance_with(
        "r9",
        Preparation {
            token_command: false,
            ..Preparation::FULL
        },
    )
    .await;
    let deployment = Deployment::provision(instance.config.clone()).await.unwrap();
    let book = deployment.book();

    // The service principals got theirs from the administration token of the tenant (ADR-0015), without an operator.
    for role in [
        ActorRole::ServicePrincipal,
        ActorRole::ServiceGrantee,
        ActorRole::ServiceWriter,
    ] {
        assert!(!book.lacks_mcp_token(role, None), "{role}");
    }
    assert_eq!(listed_calendars(&deployment, ActorRole::ServiceGrantee).await.len(), 2);

    // The users have the token of the management API, which carries no scope of MCP, and the cases that need one are left out.
    for role in [ActorRole::Owner, ActorRole::GroupMember, ActorRole::SuspendedUser] {
        assert!(book.principal_token(role).is_some(), "{role} can use the API");
        assert!(book.lacks_mcp_token(role, None), "{role} has no token that opens MCP");
    }
    assert!(
        book.lacks_mcp_token(ActorRole::Owner, Some("mcp:read")),
        "no token that carries one scope of MCP either"
    );
    assert!(
        !book.lacks_mcp_token(ActorRole::Owner, Some("events:read")),
        "the tokens of one scope of the API are made as before"
    );
    assert!(!book.lacks_mcp_token(ActorRole::TenantToken, None) && !book.lacks_mcp_token(ActorRole::Anonymous, None));

    // What the book says is what the instance does: it refuses MCP to the token the management API gave the owner, for want of the
    // scope of the tool (a failed tool result that says forbidden), and answers the token of a service principal.
    let owner = book.actor(ActorRole::Owner, Surface::Mcp, None).unwrap();
    let refused = list_calendars_as(&deployment, owner).await;
    assert_eq!(
        refused.pointer("/result/isError"),
        Some(&serde_json::Value::Bool(true)),
        "{refused}"
    );
    assert_eq!(
        refused
            .pointer("/result/_meta/davhaven~1problem/code")
            .and_then(serde_json::Value::as_str),
        Some("forbidden"),
        "{refused}"
    );
    drop(instance.served);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tokens_of_a_run_expire_after_the_run_and_not_after_a_month() {
    // The principal tokens of the world carry every scope of a principal, the scopes of MCP among them: the run asks the command of
    // the operator for them with a lifetime of `RUN_TOKEN_DAYS`, and the management API too.
    #[derive(Default)]
    struct Asked(tokio::sync::Mutex<Vec<u32>>);
    struct Recording(Arc<Asked>, OperatorCommand);

    #[async_trait]
    impl PrincipalTokenIssuer for Recording {
        async fn issue(&self, request: &PrincipalTokenRequest) -> Result<String, String> {
            self.0.0.lock().await.push(request.expires_in_days);
            self.1.issue(request).await
        }
    }

    let instance = instance("r12").await;
    let asked = Arc::new(Asked::default());
    let config = StagingConfig {
        token_issuer: Some(Arc::new(Recording(
            Arc::clone(&asked),
            OperatorCommand {
                deps: instance.app.deps().clone(),
                services: instance.app.services().clone(),
            },
        ))),
        ..instance.config.clone()
    };
    let deployment = Deployment::provision(config).await.unwrap();
    let lifetimes = asked.0.lock().await.clone();
    assert!(
        !lifetimes.is_empty(),
        "the users of the world have tokens from the command"
    );
    assert!(
        lifetimes.iter().all(|days| *days == RUN_TOKEN_DAYS),
        "the command is asked for {RUN_TOKEN_DAYS} day(s) every time: {lifetimes:?}"
    );

    // The tokens the management API issued for the run expire within the same time: a token that never expires is one that the
    // world does not give an expiry (the tokens of the tenant), none of them lasts a month.
    let tokens: Vec<serde_json::Value> = Api::new(
        deployment.transport(),
        davhaven_testkit::Actor::bearer(&instance.config.tenant_token),
    )
    .all("listing the tokens", "/api/v1/tenants/r12-a/api-tokens")
    .await
    .unwrap();
    let latest = instance.app.deps().clock.now()
        + chrono::Duration::days(i64::from(RUN_TOKEN_DAYS))
        + chrono::Duration::minutes(1);
    let mut expiring = 0;
    for token in tokens
        .iter()
        .filter(|token| token["label"].as_str().is_some_and(|label| label.starts_with(LABEL)))
    {
        let Some(expires_at) = token["expires_at"].as_str() else {
            continue;
        };
        expiring += 1;
        let expires_at = expires_at.parse::<chrono::DateTime<chrono::Utc>>().unwrap();
        assert!(
            expires_at <= latest,
            "{}: expires {expires_at}, later than {latest}",
            token["label"]
        );
    }
    assert!(expiring > 10, "the principal tokens of the world expire: {expiring}");
    drop(instance.served);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tenant_without_mcp_stops_a_run_that_has_the_command_and_is_a_run_without_mcp_cases_otherwise() {
    // The command would fail for such a tenant (a token with `mcp:*` scopes is minted only where MCP is switched on), and the MCP
    // cases of every role would be left out without anybody saying why: with the command given, the run stops and names the
    // way out.
    let instance = instance_with(
        "r10",
        Preparation {
            system_token: false,
            mcp: false,
            ..Preparation::FULL
        },
    )
    .await;
    let error = Deployment::provision(instance.config.clone()).await.unwrap_err();
    assert!(matches!(error, StagingError::Setup(_)), "{error}");
    let text = error.to_string();
    assert!(
        text.contains("MCP switched off")
            && text.contains("davhaven admin bootstrap --tenant r10-a --login-domain r10-a.example --mcp-enabled"),
        "{text}"
    );
    drop(instance.served);

    // Without the command nothing is asked for: nobody has a token that opens MCP, and every role can still use the API.
    let instance = instance_with(
        "r13",
        Preparation {
            system_token: false,
            token_command: false,
            mcp: false,
        },
    )
    .await;
    let deployment = Deployment::provision(instance.config.clone()).await.unwrap();
    for role in ActorRole::ALL.iter().filter(|role| role.principal_name().is_some()) {
        assert!(
            deployment.book().principal_token(*role).is_some(),
            "{role} can use the API"
        );
        assert!(
            deployment.book().lacks_mcp_token(*role, None),
            "{role}: MCP is switched off"
        );
    }
    drop(instance.served);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_command_that_fails_stops_the_run_with_its_reason_and_takes_the_world_down_again() {
    let instance = instance("r11").await;
    let config = StagingConfig {
        token_issuer: Some(Arc::new(BrokenCommand)),
        ..instance.config.clone()
    };
    let error = Deployment::provision(config).await.unwrap_err();
    assert!(matches!(error, StagingError::Setup(_)), "{error}");
    let text = error.to_string();
    assert!(
        text.contains("could not be issued by the command of the operator") && text.contains("exit status: 255"),
        "{text}"
    );

    // What was built before the token was asked for is gone: the principals are deleted, not left in the tenant.
    let transport = davhaven_testkit::HttpTransport::new(instance.served.base_url.clone()).unwrap();
    let token = &instance.config.tenant_token;
    let olivia = davhaven_testkit::Transport::send(&transport, read(token, "/api/v1/tenants/r11-a/principals/olivia"))
        .await
        .unwrap();
    assert_eq!(olivia.status.as_u16(), 404, "{}", olivia.text());
}
