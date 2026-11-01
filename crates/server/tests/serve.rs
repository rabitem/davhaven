//! The server end to end over real sockets: the assembled application behind its three listeners.
//!
//! These tests build the application exactly like `davhaven serve` does (`assemble`, then `server::start`) from
//! a configuration, bind the listeners to free ports and talk to them with the small HTTP client of `support`. They
//! cover what only the whole wiring can show: which route group answers on which listener, the operations
//! endpoints, the connection limits of `[server.http]`, a management API write that a DAV client reads back (and the
//! other way round), the shutdown, and the same scenario on PostgreSQL, where one test runs the production setup of
//! `docs/operations/database.md`: an owner role that migrates and a runtime role that row-level security binds.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use davhaven_domain::{DomainName, PrincipalName, Scope, ScopeSet, TenantSlug};
use davhaven_ports::{Database, IdGenerator};
use davhaven_server::admin::{self, BootstrapRequest, PrincipalTokenRequest, SettingsFlags, TokenOutcome, TokenSink};
use davhaven_server::assembly::{Assembly, assemble};
use davhaven_server::config::Config;
use davhaven_server::listeners::ListenerName;
use davhaven_server::registry::registry;
use davhaven_server::server::{Running, start};
use serde_json::{Value, json};
use support::{Client, basic, database_url};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// The `[server]` part of a development configuration: ephemeral ports on the loopback interface.
const SERVER: &str = r#"
    [server]
    mode = "dev"
    public_base_url = "http://localhost:8080"
    shutdown_grace = "5s"
    [server.listeners.public]
    bind = "127.0.0.1:0"
    [server.listeners.internal]
    bind = "127.0.0.1:0"
    [server.listeners.ops]
    bind = "127.0.0.1:0"
"#;

/// A development configuration with the memory store and the memory mail transport.
fn memory(extra: &str) -> String {
    format!(
        "{SERVER}
[plugins]
store = \"memory\"
mail_transport = \"memory\"
rate_limiter = \"memory\"
http_client = \"recording\"
{extra}"
    )
}

/// A running server with a tenant and its administration token.
struct World {
    running: Running,
    database: Arc<dyn Database>,
    public: Client,
    internal: Client,
    ops: Client,
    tenant: String,
    domain: String,
    token: String,
}

/// A tenant that `admin bootstrap` made: its login domain and the administration token.
struct Bootstrapped {
    domain: String,
    token: String,
}

/// Creates the tenant `tenant` with an administration token, the way `davhaven admin bootstrap` does.
async fn bootstrap_tenant(assembly: &Assembly, tenant: &str) -> Bootstrapped {
    bootstrap_tenant_with(assembly, tenant, SettingsFlags::default()).await
}

/// [`bootstrap_tenant`] with the settings the flags of `admin bootstrap` give.
async fn bootstrap_tenant_with(assembly: &Assembly, tenant: &str, settings: SettingsFlags) -> Bootstrapped {
    let domain = format!("{tenant}.example");
    let request = BootstrapRequest {
        tenant: TenantSlug::parse(tenant).unwrap(),
        display_name: Some("End to end".to_owned()),
        login_domain: Some(DomainName::parse(&domain).unwrap()),
        settings,
        label: "e2e".to_owned(),
        scopes: admin::default_scopes(),
        expires_at: None,
    };
    let mut secret = Vec::new();
    admin::bootstrap(
        &assembly.deps,
        &assembly.services,
        &request,
        &TokenSink::Stdout,
        &mut secret,
    )
    .await
    .unwrap();
    Bootstrapped {
        domain,
        token: String::from_utf8(secret).unwrap().trim().to_owned(),
    }
}

/// Starts the assembled server; `tenant` is the one the returned world talks about.
async fn world_of(assembly: Assembly, tenant: &str, bootstrapped: Bootstrapped) -> World {
    let database = Arc::clone(&assembly.deps.database);
    let running = start(assembly, None).await.unwrap();
    let client = |name| Client::new(running.address(name).unwrap());
    World {
        public: client(ListenerName::Public),
        internal: client(ListenerName::Internal),
        ops: client(ListenerName::Ops),
        running,
        database,
        tenant: tenant.to_owned(),
        domain: bootstrapped.domain,
        token: bootstrapped.token,
    }
}

/// Builds and starts the server of `config`, after creating the tenant `tenant` with an administration token.
async fn boot(config: &str, tenant: &str) -> World {
    let config = Arc::new(Config::from_toml(config).unwrap());
    let assembly = assemble(config, &Arc::new(registry().unwrap())).await.unwrap();
    let bootstrapped = bootstrap_tenant(&assembly, tenant).await;
    world_of(assembly, tenant, bootstrapped).await
}

/// The path of a `dav_url`, which the API builds from `server.public_base_url`: a client talks to the address of the
/// listener, with the path of the resource.
fn path_of(url: &str) -> String {
    url::Url::parse(url).map_or_else(|_| url.to_owned(), |parsed| parsed.path().to_owned())
}

const CRLF_EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Davhaven//e2e//EN\r\nBEGIN:VEVENT\r\n\
    UID:e2e-kickoff@example.org\r\nDTSTAMP:20270301T100000Z\r\nDTSTART:20270302T100000Z\r\n\
    DTEND:20270302T110000Z\r\nSUMMARY:Kickoff\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// What provisioning gives the rest of the scenario: the user's credentials and her personal calendar.
struct Olivia {
    /// Her API token (management API, `events:*`).
    token: String,
    /// The slug of her personal calendar.
    slug: String,
    /// The path of that calendar on the public listener.
    collection: String,
    /// `Authorization` of her DAV login.
    authorization: String,
}

/// The path of a management API resource of the world's tenant.
fn api_path(world: &World, path: &str) -> String {
    format!("/api/v1/tenants/{}{path}", world.tenant)
}

/// The administration token provisions Olivia: a user, an app password and an API token.
async fn provision(world: &World) -> Olivia {
    provision_user(
        &world.internal,
        &world.tenant,
        &world.domain,
        &world.token,
        "olivia",
        "Olivia",
    )
    .await
}

/// The administration token of `tenant` provisions the user `name`: a user, an app password and an API token.
async fn provision_user(
    internal: &Client,
    tenant: &str,
    domain: &str,
    token: &str,
    name: &str,
    display_name: &str,
) -> Olivia {
    let base = format!("/api/v1/tenants/{tenant}");
    let user = internal
        .api(
            "PUT",
            &format!("{base}/principals/{name}"),
            token,
            &json!({"kind": "user", "display_name": display_name, "email": format!("{name}@{domain}")}),
        )
        .await;
    assert_eq!(user.status, 201, "{}", user.text());
    let password = internal
        .api(
            "POST",
            &format!("{base}/principals/{name}/app-passwords"),
            token,
            &json!({"label": "phone"}),
        )
        .await;
    assert_eq!(password.status, 201, "{}", password.text());
    assert_eq!(
        password.header("cache-control"),
        Some("no-store"),
        "a secret is never cached"
    );
    let password = password.json()["password"].as_str().unwrap().to_owned();
    let minted = internal
        .api(
            "POST",
            &format!("{base}/api-tokens"),
            token,
            &json!({
                "kind": "principal",
                "principal": name,
                "label": "e2e",
                "scopes": ["calendars:read", "events:read", "events:write"]
            }),
        )
        .await;
    assert_eq!(minted.status, 201, "{}", minted.text());
    let user_token = minted.json()["secret"].as_str().unwrap().to_owned();

    // The personal calendar exists.
    let calendars = internal
        .api(
            "GET",
            &format!("{base}/principals/{name}/calendars"),
            &user_token,
            &Value::Null,
        )
        .await;
    assert_eq!(calendars.status, 200, "{}", calendars.text());
    let calendar = calendars.json()["items"][0].clone();
    Olivia {
        authorization: basic(&format!("{name}@{domain}"), &password),
        token: user_token,
        slug: calendar["slug"].as_str().unwrap().to_owned(),
        collection: path_of(calendar["dav_url"].as_str().unwrap()),
    }
}

/// A DAV client logs in with the app password and writes an event; the API shows it.
async fn dav_writes_and_the_api_reads(world: &World, olivia: &Olivia) {
    let principal_url = format!("/dav/principals/{}/olivia/", world.tenant);
    let principal = world
        .public
        .send(
            "PROPFIND",
            &principal_url,
            &[("Authorization", olivia.authorization.as_str()), ("Depth", "0")],
            br#"<?xml version="1.0"?><propfind xmlns="DAV:"><prop><displayname/></prop></propfind>"#,
        )
        .await;
    assert_eq!(principal.status, 207, "{}", principal.text());
    assert!(principal.text().contains("Olivia"), "{}", principal.text());
    let wrong = basic(&format!("olivia@{}", world.domain), "not-the-password");
    let refused = world
        .public
        .send(
            "PROPFIND",
            &principal_url,
            &[("Authorization", wrong.as_str()), ("Depth", "0")],
            b"",
        )
        .await;
    assert_eq!(refused.status, 401);

    let put = world
        .public
        .send(
            "PUT",
            &format!("{}kickoff.ics", olivia.collection),
            &[
                ("Authorization", olivia.authorization.as_str()),
                ("Content-Type", "text/calendar; charset=utf-8"),
            ],
            CRLF_EVENT.as_bytes(),
        )
        .await;
    assert_eq!(put.status, 201, "{}", put.text());
    let listed = world
        .internal
        .api(
            "GET",
            &api_path(world, &format!("/principals/olivia/calendars/{}/objects", olivia.slug)),
            &olivia.token,
            &Value::Null,
        )
        .await;
    assert_eq!(listed.status, 200, "{}", listed.text());
    let items = listed.json()["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["summary"], "Kickoff");
    assert_eq!(items[0]["uid"], "e2e-kickoff@example.org");
}

/// The API writes another event; DAV reads it back and lists both.
async fn the_api_writes_and_dav_reads(world: &World, olivia: &Olivia) {
    let written = world
        .internal
        .api(
            "PUT",
            &api_path(
                world,
                &format!(
                    "/principals/olivia/calendars/{}/objects/by-key/from-the-api",
                    olivia.slug
                ),
            ),
            &olivia.token,
            &json!({
                "summary": "From the API",
                "start": {"date_time": "2027-03-03T10:00:00Z"},
                "end": {"date_time": "2027-03-03T11:00:00Z"}
            }),
        )
        .await;
    assert!(
        matches!(written.status, 200 | 201),
        "{} {}",
        written.status,
        written.text()
    );
    let dav_url = path_of(written.json()["dav_url"].as_str().unwrap());
    let read = world
        .public
        .send(
            "GET",
            &dav_url,
            &[("Authorization", olivia.authorization.as_str())],
            b"",
        )
        .await;
    assert_eq!(read.status, 200, "{}", read.text());
    assert!(read.text().contains("SUMMARY:From the API"), "{}", read.text());
    let etag = read.header("etag").unwrap().to_owned();
    assert!(etag.starts_with('"'), "a strong ETag: {etag}");
    let members = world
        .public
        .send(
            "PROPFIND",
            &olivia.collection,
            &[("Authorization", olivia.authorization.as_str()), ("Depth", "1")],
            br#"<?xml version="1.0"?><propfind xmlns="DAV:"><prop><getetag/></prop></propfind>"#,
        )
        .await;
    assert_eq!(members.status, 207);
    assert!(members.text().contains("kickoff.ics"), "{}", members.text());
    assert!(members.text().contains(&etag.replace('"', "&quot;")) || members.text().contains(&etag));
}

/// The scenario of the image smoke test, over real sockets: provision a user through the management API, let a DAV
/// client write an event with the app password, read it with the principal's API token, write another one through
/// the API and read it back over DAV.
async fn the_scenario(world: &World) {
    let olivia = provision(world).await;
    dav_writes_and_the_api_reads(world, &olivia).await;
    the_api_writes_and_dav_reads(world, &olivia).await;
}

#[tokio::test]
async fn every_listener_answers_and_serves_only_its_route_groups() {
    let world = boot(&memory(""), "acme").await;

    // ops: liveness, readiness, and nothing else.
    let live = world.ops.get("/healthz").await;
    assert_eq!((live.status, live.text().as_str()), (200, "ok\n"));
    let ready = world.ops.get("/readyz").await;
    assert_eq!(ready.status, 200, "{}", ready.text());
    let report = ready.json();
    assert_eq!(report["status"], "ready");
    let names: Vec<&str> = report["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| component["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"database"), "{names:?}");
    assert!(names.contains(&"worker:outbox"), "{names:?}");
    assert!(names.contains(&"worker:retention"), "{names:?}");
    assert_eq!(
        world.ops.get("/metrics").await.status,
        503,
        "no recorder in this process"
    );
    assert_eq!(world.ops.get("/dav/").await.status, 404);
    assert_eq!(world.ops.get("/api/v1/tenants").await.status, 404);

    // public: the well-known redirect, DAV discovery with its challenge, no API.
    let wellknown = world.public.get("/.well-known/caldav").await;
    assert_eq!(wellknown.status, 301);
    assert!(
        wellknown
            .header("location")
            .is_some_and(|location| location.ends_with("/dav/")),
        "the redirect target is built from server.public_base_url: {:?}",
        wellknown.header("location")
    );
    let options = world.public.send("OPTIONS", "/dav/", &[], b"").await;
    assert_eq!(options.status, 200, "{}", options.text());
    assert!(options.header("dav").is_some_and(|dav| dav.contains("calendar-access")));
    let challenge = world.public.send("PROPFIND", "/dav/", &[("Depth", "0")], b"").await;
    assert_eq!(challenge.status, 401);
    assert!(
        challenge
            .header("www-authenticate")
            .is_some_and(|value| value.starts_with("Basic "))
    );
    assert_eq!(world.public.get("/api/v1/tenants").await.status, 404);
    assert_eq!(world.public.get("/healthz").await.status, 404);

    // internal: the API with its Bearer challenge, no DAV.
    let anonymous = world.internal.get("/api/v1/tenants/acme/principals").await;
    assert_eq!(anonymous.status, 401);
    assert_eq!(anonymous.header("content-type"), Some("application/problem+json"));
    assert!(
        anonymous
            .header("www-authenticate")
            .is_some_and(|value| value.starts_with("Bearer "))
    );
    assert!(
        anonymous.header("x-request-id").is_some(),
        "the edge stamps a request id"
    );
    assert_eq!(world.internal.send("PROPFIND", "/dav/", &[], b"").await.status, 404);

    let authorised = world
        .internal
        .api("GET", "/api/v1/tenants/acme/principals", &world.token, &Value::Null)
        .await;
    assert_eq!(authorised.status, 200, "{}", authorised.text());
    assert!(
        world.running.shutdown().await,
        "everything stops within the grace period"
    );
}

#[tokio::test]
async fn listeners_can_be_merged_onto_one_address() {
    let config = r#"
        [server]
        mode = "dev"
        public_base_url = "http://localhost:8080"
        shutdown_grace = "5s"
        [server.listeners.public]
        bind = "127.0.0.1:0"
        routes = ["wellknown", "dav", "web", "api", "mcp", "ops"]
        [server.listeners.internal]
        enabled = false
        [server.listeners.ops]
        enabled = false
        [plugins]
        store = "memory"
        mail_transport = "memory"
        rate_limiter = "memory"
        http_client = "recording"
    "#;
    let config = Arc::new(Config::from_toml(config).unwrap());
    let assembly = assemble(config, &Arc::new(registry().unwrap())).await.unwrap();
    let running = start(assembly, None).await.unwrap();
    assert_eq!(running.listeners().len(), 1);
    let one = Client::new(running.address(ListenerName::Public).unwrap());
    assert_eq!(one.get("/readyz").await.status, 200);
    assert_eq!(one.get("/.well-known/caldav").await.status, 301);
    assert_eq!(one.get("/api/v1/tenants/acme/principals").await.status, 401);
    assert_eq!(one.send("PROPFIND", "/dav/", &[], b"").await.status, 401);
    assert!(running.shutdown().await);
}

#[tokio::test]
async fn a_management_api_write_is_read_over_dav_and_the_other_way_round() {
    let world = boot(&memory(""), "acme").await;
    the_scenario(&world).await;
    assert!(world.running.shutdown().await);
}

/// One MCP tool call over HTTP as the bearer of `token`: the structured content of a result that is no failure.
async fn mcp_tool(client: &Client, token: &str, tool: &str, arguments: Value) -> Value {
    let body =
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}});
    let authorization = format!("Bearer {token}");
    let reply = client
        .send(
            "POST",
            "/mcp",
            &[
                ("Authorization", authorization.as_str()),
                ("Content-Type", "application/json"),
                ("Accept", "application/json, text/event-stream"),
            ],
            &serde_json::to_vec(&body).unwrap(),
        )
        .await;
    assert_eq!(reply.status, 200, "{tool}: {}", reply.text());
    let text = reply.text();
    let message: Value = if reply
        .header("content-type")
        .is_some_and(|content_type| content_type.starts_with("text/event-stream"))
    {
        let data = text.lines().rev().find_map(|line| line.strip_prefix("data:")).unwrap();
        serde_json::from_str(data.trim()).unwrap()
    } else {
        reply.json()
    };
    assert_eq!(message["result"]["isError"], false, "{tool}: {message}");
    message["result"]["structuredContent"].clone()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario: provision, mint twice, use over MCP, revoke"
)]
async fn the_mcp_token_of_a_service_principal_comes_from_the_operator_or_from_the_api_and_works_over_mcp() {
    let config = Arc::new(Config::from_toml(&memory("")).unwrap());
    let assembly = assemble(config, &Arc::new(registry().unwrap())).await.unwrap();
    // `admin bootstrap --mcp-enabled`: the tenant has MCP on from the start, no system token and no PATCH.
    let flags = SettingsFlags {
        mcp_enabled: Some(true),
        ..SettingsFlags::default()
    };
    let bootstrapped = bootstrap_tenant_with(&assembly, "acme", flags).await;
    let services = assembly.services.clone();
    let deps = assembly.deps.clone();
    let clock = Arc::clone(&assembly.deps.clock);
    let world = world_of(assembly, "acme", bootstrapped).await;

    // The administration token provisions the service principal and a calendar it is granted: Olivia's personal one.
    let olivia = provision(&world).await;
    let robot = world
        .internal
        .api(
            "PUT",
            &api_path(&world, "/principals/robot"),
            &world.token,
            &json!({"kind": "service", "display_name": "Robot", "email": format!("robot@{}", world.domain)}),
        )
        .await;
    assert_eq!(robot.status, 201, "{}", robot.text());
    let grant = world
        .internal
        .api(
            "PUT",
            &api_path(
                &world,
                &format!("/principals/olivia/calendars/{}/grants/robot", olivia.slug),
            ),
            &world.token,
            &json!({"access": "read_write"}),
        )
        .await;
    assert_eq!(grant.status, 201, "a service principal is a grantee: {}", grant.text());

    // 1. The operator mints a token for it (`davhaven admin principal-token create`), once: a second run finds it.
    let expires_at = clock.now() + chrono::Duration::days(30);
    let request = PrincipalTokenRequest {
        tenant: TenantSlug::parse("acme").unwrap(),
        principal: PrincipalName::parse("robot").unwrap(),
        label: "robot-cli".to_owned(),
        scopes: ScopeSet::of(&[Scope::McpRead, Scope::McpWrite]),
        expires_at: Some(expires_at),
    };
    let mut secret = Vec::new();
    let created = admin::principal_token(&deps, &services, &request, &TokenSink::Stdout, &mut secret)
        .await
        .unwrap();
    assert!(matches!(created, TokenOutcome::Created(_)), "{created:?}");
    let cli_token = String::from_utf8(secret).unwrap().trim().to_owned();
    assert!(cli_token.starts_with("dvh_pat_"), "{cli_token}");
    let mut nothing = Vec::new();
    let again = admin::principal_token(&deps, &services, &request, &TokenSink::Stdout, &mut nothing)
        .await
        .unwrap();
    assert!(matches!(again, TokenOutcome::Exists { .. }), "{again:?}");
    assert!(nothing.is_empty(), "a token that exists is not shown again");

    // 2. The administration token of the tenant (it holds credentials:write and no MCP scope) mints one through the
    // management API.
    let minted = world
        .internal
        .api(
            "POST",
            &api_path(&world, "/api-tokens"),
            &world.token,
            &json!({"kind": "principal", "principal": "robot", "label": "robot-api",
                    "scopes": ["mcp:read", "mcp:write"], "expires_at": expires_at.to_rfc3339()}),
        )
        .await;
    assert_eq!(minted.status, 201, "{}", minted.text());
    assert_eq!(minted.header("cache-control"), Some("no-store"));
    let api_token = minted.json()["secret"].as_str().unwrap().to_owned();
    // It does not extend to a user: Olivia gets no MCP token from a token that holds no MCP scope.
    let refused = world
        .internal
        .api(
            "POST",
            &api_path(&world, "/api-tokens"),
            &world.token,
            &json!({"kind": "principal", "principal": "olivia", "label": "nope",
                    "scopes": ["mcp:read"], "expires_at": expires_at.to_rfc3339()}),
        )
        .await;
    assert_eq!(refused.status, 403, "{}", refused.text());

    // Both tokens are the service principal over MCP: it sees the calendar it was granted and writes to it.
    for (index, token) in [&cli_token, &api_token].into_iter().enumerate() {
        let calendars = mcp_tool(&world.internal, token, "list_calendars", json!({})).await;
        let listed = calendars["calendars"].as_array().unwrap();
        assert_eq!(listed.len(), 1, "{calendars}");
        assert_eq!(listed[0]["writable"], true, "{calendars}");
        let calendar = listed[0]["calendar_id"].clone();
        let created = mcp_tool(
            &world.internal,
            token,
            "create_event",
            json!({"calendar_id": calendar, "client_request_id": format!("kickoff-{index}"),
                   "event": {"summary": "Kickoff", "start": {"date_time": "2027-03-02T09:00:00Z"},
                             "end": {"date_time": "2027-03-02T10:00:00Z"}}}),
        )
        .await;
        assert_eq!(created["created"], true, "{created}");
    }
    // The events landed in Olivia's calendar, and the operator sees both tokens (never their secrets).
    let listed = admin::principal_tokens(
        &deps,
        &services,
        &TenantSlug::parse("acme").unwrap(),
        Some(&PrincipalName::parse("robot").unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(
        listed.iter().map(|token| token.label.as_str()).collect::<Vec<_>>(),
        vec!["robot-cli", "robot-api"]
    );
    assert!(!format!("{listed:?}").contains(&cli_token));

    // Revoked, the token stops at once; the other one is not affected.
    admin::revoke_principal_token(&deps, &services, &TenantSlug::parse("acme").unwrap(), listed[0].id)
        .await
        .unwrap();
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let call = |token: String| {
        let client = world.internal;
        let body = serde_json::to_vec(&body).unwrap();
        async move {
            client
                .send(
                    "POST",
                    "/mcp",
                    &[
                        ("Authorization", format!("Bearer {token}").as_str()),
                        ("Content-Type", "application/json"),
                        ("Accept", "application/json, text/event-stream"),
                    ],
                    &body,
                )
                .await
                .status
        }
    };
    assert_eq!(call(cli_token.clone()).await, 401);
    assert_eq!(call(api_token.clone()).await, 200);
    assert!(world.running.shutdown().await);
}

#[tokio::test]
async fn a_deleted_principal_keeps_its_values_reserved_and_the_api_says_which_problem_it_is() {
    let world = boot(&memory(""), "acme").await;
    let principals = api_path(&world, "/principals");
    let authorization = format!("Bearer {}", world.token);
    let internal = world.internal;
    // A `PUT` of a user with the given body; `create_only` adds `If-None-Match: *`.
    let put = |name: &str, body: Value, create_only: bool| {
        let path = format!("{principals}/{name}");
        let authorization = authorization.clone();
        async move {
            let mut headers = vec![
                ("Authorization", authorization.as_str()),
                ("Content-Type", "application/json"),
            ];
            if create_only {
                headers.push(("If-None-Match", "*"));
            }
            internal
                .send("PUT", &path, &headers, &serde_json::to_vec(&body).unwrap())
                .await
        }
    };
    let delete = |name: &str, etag: &str, purge: bool| {
        let path = format!("{principals}/{name}{}", if purge { "?purge=true" } else { "" });
        let (authorization, etag) = (authorization.clone(), etag.to_owned());
        async move {
            internal
                .send(
                    "DELETE",
                    &path,
                    &[("Authorization", authorization.as_str()), ("If-Match", etag.as_str())],
                    &[],
                )
                .await
        }
    };
    let user = |name: &str, extra: Value| {
        let mut body = json!({"kind": "user", "display_name": name, "email": format!("{name}@acme.example")});
        for (key, value) in extra.as_object().unwrap() {
            body[key] = value.clone();
        }
        body
    };

    // Anna has an external reference and a further address, and is deleted without a purge.
    let anna = put(
        "anna",
        user(
            "anna",
            json!({"external_ref": "hr-1", "addresses": ["mailto:anna.sales@acme.example"]}),
        ),
        true,
    )
    .await;
    assert_eq!(anna.status, 201, "{}", anna.text());
    let etag = anna.header("etag").unwrap().to_owned();
    let deleted = delete("anna", &etag, false).await;
    assert_eq!(deleted.status, 204, "{}", deleted.text());

    // The name: 412, as for every name that exists, and a problem that says nothing about the hidden principal.
    let taken = put("anna", user("anna", json!({})), true).await;
    assert_eq!(taken.status, 412, "{}", taken.text());
    assert_eq!(taken.header("content-type"), Some("application/problem+json"));
    let problem = taken.json();
    assert_eq!(problem["code"], "precondition-failed");
    assert!(
        problem.get("errors").is_none() && problem["detail"].as_str().is_none_or(|detail| !detail.contains("anna"))
    );
    // Without the condition the same name is a 409 with a code of its own, so that a client that provisions
    // declaratively can tell it from a collision with a live principal.
    let reserved = put("anna", user("anna", json!({})), false).await;
    assert_eq!(reserved.status, 409, "{}", reserved.text());
    assert_eq!(reserved.json()["code"], "name-reserved");
    assert_eq!(reserved.json()["type"], "urn:davhaven:problem:name-reserved");

    // The external reference and the addresses: 409 with their own codes, so that a client can purge or wait.
    let reference = put("ben", user("ben", json!({"external_ref": "hr-1"})), true).await;
    assert_eq!(reference.status, 409, "{}", reference.text());
    assert_eq!(reference.json()["code"], "external-ref-reserved");
    assert_eq!(reference.json()["type"], "urn:davhaven:problem:external-ref-reserved");
    let primary = put("cara", user("cara", json!({"email": "anna@acme.example"})), true).await;
    assert_eq!(primary.status, 409, "{}", primary.text());
    assert_eq!(primary.json()["code"], "address-reserved");
    let further = put(
        "dora",
        user("dora", json!({"addresses": ["mailto:anna.sales@acme.example"]})),
        false,
    )
    .await;
    assert_eq!(further.status, 409, "{}", further.text());
    assert_eq!(further.json()["code"], "address-reserved");

    // A live principal that holds a value is the plain conflict.
    let frank = put("frank", user("frank", json!({"external_ref": "hr-2"})), true).await;
    assert_eq!(frank.status, 201, "{}", frank.text());
    let grace = put("grace", user("grace", json!({"external_ref": "hr-2"})), true).await;
    assert_eq!(grace.status, 409, "{}", grace.text());
    assert_eq!(grace.json()["code"], "conflict");

    // A purge frees the values at once.
    let zed = put("zed", user("zed", json!({"external_ref": "hr-9"})), true).await;
    assert_eq!(zed.status, 201, "{}", zed.text());
    let purged = delete("zed", zed.header("etag").unwrap(), true).await;
    assert_eq!(purged.status, 204, "{}", purged.text());
    let successor = put("zed-2", user("zed-2", json!({"external_ref": "hr-9"})), true).await;
    assert_eq!(successor.status, 201, "{}", successor.text());
    let name_again = put("zed", user("zed", json!({"email": "zed.again@acme.example"})), true).await;
    assert_eq!(name_again.status, 201, "{}", name_again.text());
    assert!(world.running.shutdown().await);
}

#[tokio::test]
async fn the_connection_limits_of_the_configuration_apply_to_the_listeners() {
    let config = memory("[server.http]\nmax_header_bytes = 8192\nheader_read_timeout = \"1s\"\n");
    let world = boot(&config, "acme").await;
    let big = "a".repeat(9000);
    let too_big = world
        .public
        .send("GET", "/.well-known/caldav", &[("X-Big", big.as_str())], b"")
        .await;
    assert_eq!(too_big.status, 431, "an oversized head is refused");
    assert_eq!(
        world.public.get("/.well-known/caldav").await.status,
        301,
        "and the next request is served"
    );

    // A client that never finishes its headers is disconnected after `header_read_timeout` (1 s here), and not before.
    let address = world.running.address(ListenerName::Public).unwrap();
    let mut slow = TcpStream::connect(address).await.unwrap();
    slow.write_all(b"GET /.well-known/caldav HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    let early = tokio::time::timeout(Duration::from_millis(300), slow.read_to_end(&mut answer)).await;
    assert!(
        early.is_err(),
        "the connection was closed long before the header read timeout: {answer:?}"
    );
    let closed = tokio::time::timeout(Duration::from_secs(10), slow.read_to_end(&mut answer)).await;
    assert!(closed.is_ok(), "the connection was still open after 10 s");

    // So is a client that connects and says nothing at all: the server cannot even tell which protocol it speaks.
    let mut silent = TcpStream::connect(address).await.unwrap();
    let mut nothing = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(10), silent.read_to_end(&mut nothing)).await;
    assert!(closed.is_ok(), "a silent connection was still open after 10 s");
    assert_eq!(nothing, Vec::<u8>::new());
    assert!(world.running.shutdown().await);
}

#[tokio::test]
async fn shutdown_stops_accepting_and_finishes_within_the_grace_period() {
    let world = boot(&memory(""), "acme").await;
    let public = world.running.address(ListenerName::Public).unwrap();
    let ops = world.running.address(ListenerName::Ops).unwrap();
    assert_eq!(world.ops.get("/readyz").await.status, 200);
    assert!(world.running.shutdown().await);
    assert!(
        TcpStream::connect(public).await.is_err(),
        "the public listener is closed"
    );
    assert!(TcpStream::connect(ops).await.is_err(), "and so is the ops listener");
}

#[tokio::test]
async fn during_the_shutdown_delay_readiness_says_draining_and_the_listeners_still_serve() {
    // The load balancer polls `/readyz` and takes the instance out of rotation; until it has noticed, the requests it still
    // sends are served (`server.shutdown_delay`, docs/operations).
    let config = memory("").replace(
        "shutdown_grace = \"5s\"",
        "shutdown_grace = \"5s\"\n    shutdown_delay = \"1s\"",
    );
    let world = boot(&config, "acme").await;
    let public = world.running.address(ListenerName::Public).unwrap();
    assert_eq!(world.ops.get("/readyz").await.status, 200);
    let mut shutdown = std::pin::pin!(world.running.shutdown());
    // The first poll marks the instance as draining and waits out the delay.
    assert!(futures::poll!(shutdown.as_mut()).is_pending());

    let ready = world.ops.get("/readyz").await;
    assert_eq!(ready.status, 503, "{}", ready.text());
    assert_eq!(ready.json()["status"], "draining");
    assert_eq!(
        world.public.get("/.well-known/caldav").await.status,
        301,
        "a new connection is still served during the delay"
    );
    let authorised = world
        .internal
        .api("GET", "/api/v1/tenants/acme/principals", &world.token, &Value::Null)
        .await;
    assert_eq!(authorised.status, 200, "{}", authorised.text());

    let finished = tokio::time::timeout(Duration::from_secs(30), shutdown)
        .await
        .expect("the shutdown ends within its bound");
    assert!(finished, "everything stops within the grace period");
    assert!(
        TcpStream::connect(public).await.is_err(),
        "after the delay the listener is closed"
    );
}

#[tokio::test]
async fn the_same_scenario_runs_on_postgres() {
    let Some(url) = database_url() else {
        return;
    };
    // A tenant of its own in the shared test database: the slug is random, the tenant is removed afterwards.
    let suffix = davhaven_ports::UuidV7.new_id().simple().to_string();
    let tenant = format!("e2e-{suffix}");
    let config = format!(
        "{SERVER}\n[plugins]\nstore = \"postgres\"\nmail_transport = \"memory\"\nrate_limiter = \"memory\"\n\
         http_client = \"recording\"\n[database]\nurl = {url:?}\nmigrate_on_start = true\nmax_connections = 4\n"
    );
    let world = boot(&config, &tenant).await;
    let ready = world.ops.get("/readyz").await;
    assert_eq!(ready.status, 200, "{}", ready.text());
    the_scenario(&world).await;

    let slug = TenantSlug::parse(&tenant).unwrap();
    // The tenant goes while the database is still open (the shutdown closes the pool).
    let mut tx = world.database.begin_system().await.unwrap();
    let found = tx.tenants().find_by_slug(&slug).await.unwrap().unwrap();
    tx.tenants().delete(found.id).await.unwrap();
    tx.commit().await.unwrap();
    assert!(world.running.shutdown().await);
}

#[tokio::test]
async fn dav_exchanges_of_a_listed_tenant_are_captured_without_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let capture = format!(
        "[observability.dav_capture]\nenabled = true\ntenants = [\"acme\"]\ndir = {:?}\n",
        directory.path().display().to_string()
    );
    let world = boot(&memory(&capture), "acme").await;
    let tenant = &world.tenant;
    let user = world
        .internal
        .api(
            "PUT",
            &format!("/api/v1/tenants/{tenant}/principals/olivia"),
            &world.token,
            &json!({"kind": "user", "display_name": "Olivia", "email": format!("olivia@{}", world.domain)}),
        )
        .await;
    assert_eq!(user.status, 201, "{}", user.text());
    let password = world
        .internal
        .api(
            "POST",
            &format!("/api/v1/tenants/{tenant}/principals/olivia/app-passwords"),
            &world.token,
            &json!({"label": "phone"}),
        )
        .await;
    let password = password.json()["password"].as_str().unwrap().to_owned();

    let authorization = basic(&format!("olivia@{}", world.domain), &password);
    let answered = world
        .public
        .send(
            "PROPFIND",
            &format!("/dav/principals/{tenant}/olivia/"),
            &[("Authorization", authorization.as_str()), ("Depth", "0")],
            br#"<?xml version="1.0"?><propfind xmlns="DAV:"><prop><displayname/></prop></propfind>"#,
        )
        .await;
    assert_eq!(answered.status, 207, "{}", answered.text());
    // A tenant that is not listed is not recorded, and neither are the API and the discovery requests.
    world.public.get("/.well-known/caldav").await;
    let other = world
        .public
        .send(
            "PROPFIND",
            "/dav/principals/other/olivia/",
            &[("Authorization", authorization.as_str())],
            b"",
        )
        .await;
    assert!(
        other.status >= 400,
        "the path of another tenant is not served to Olivia: {} {}",
        other.status,
        other.text()
    );

    let mut files: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    assert_eq!(files.len(), 1, "{files:?}");
    let text = std::fs::read_to_string(&files[0]).unwrap();
    assert!(
        !text.contains(&password) && !text.contains(&authorization),
        "credentials leaked: {text}"
    );
    let document: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["tenant"], "acme");
    assert_eq!(document["request"]["method"], "PROPFIND");
    assert_eq!(document["response"]["status"], 207);
    assert!(document["response"]["body"].as_str().unwrap().contains("Olivia"));
    assert!(world.running.shutdown().await);
}

/// The files a capture directory holds.
fn captured(directory: &std::path::Path) -> usize {
    std::fs::read_dir(directory).unwrap().count()
}

#[tokio::test]
async fn the_capture_records_only_authenticated_exchanges_and_never_buffers_an_oversized_body() {
    let directory = tempfile::tempdir().unwrap();
    let capture = format!(
        "[observability.dav_capture]\nenabled = true\ntenants = [\"acme\"]\ndir = {:?}\n",
        directory.path().display().to_string()
    );
    let world = boot(&memory(&capture), "acme").await;
    let olivia = provision(&world).await;
    assert_eq!(
        captured(directory.path()),
        0,
        "provisioning goes through the API, which is not captured"
    );

    // The 401 of a client that has not logged in yet is no capture.
    let anonymous = world
        .public
        .send(
            "PROPFIND",
            &format!("/dav/principals/{}/olivia/", world.tenant),
            &[("Depth", "0")],
            b"",
        )
        .await;
    assert_eq!(anonymous.status, 401);
    assert_eq!(
        captured(directory.path()),
        0,
        "an unauthenticated exchange is not recorded"
    );

    // A body that is announced larger than the DAV limits is refused by the edge on its headers alone: the capture, which
    // sits outside it, must not read it first. The client never sends the body.
    let address = world.running.address(ListenerName::Public).unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "PUT {}huge.ics HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nContent-Type: text/calendar\r\n\
         Content-Length: 33554432\r\nConnection: close\r\n\r\n",
        olivia.collection, olivia.authorization
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
        .await
        .expect("the server answered without waiting for a body of 32 MiB")
        .unwrap();
    let reply = support::parse(&answer);
    assert_eq!(reply.status, 413, "{}", reply.text());
    assert_eq!(captured(directory.path()), 0, "a refused request is not recorded");

    // An authenticated exchange of the listed tenant is.
    let listed = world
        .public
        .send(
            "PROPFIND",
            &format!("/dav/principals/{}/olivia/", world.tenant),
            &[("Authorization", olivia.authorization.as_str()), ("Depth", "0")],
            br#"<?xml version="1.0"?><propfind xmlns="DAV:"><prop><displayname/></prop></propfind>"#,
        )
        .await;
    assert_eq!(listed.status, 207, "{}", listed.text());
    assert_eq!(captured(directory.path()), 1);
    assert!(world.running.shutdown().await);
}

/// The production setup of `docs/operations/database.md` needs the PostgreSQL store (`admin::migrate`).
#[cfg(feature = "store-postgres")]
mod production {
    use crate::support::Roles;
    use davhaven_app::AppCore;
    use davhaven_app::retention::RetentionWorker;
    use davhaven_ports::SystemClock;

    use super::*;

    /// A production configuration of the two-role setup: the server connects as `url`; `migration_url` and extra `[database]`
    /// keys are added when given. The test database may be on another host of a private build network, where production
    /// would ask for TLS to the database: `allow_insecure_transport` is set so that the posture of the role, which this test
    /// is about, is the only thing that can refuse the start.
    fn production_config(
        url: &str,
        migration_url: Option<&str>,
        key: &std::path::Path,
        database_extra: &str,
    ) -> String {
        let migration = migration_url
            .map(|migration| format!("migration_url = {migration:?}\n"))
            .unwrap_or_default();
        format!(
            "[server]\npublic_base_url = \"https://calendar.example.org\"\nshutdown_grace = \"5s\"\n\
             [server.listeners.public]\nbind = \"127.0.0.1:0\"\n[server.listeners.internal]\nbind = \"127.0.0.1:0\"\n\
             [server.listeners.ops]\nbind = \"127.0.0.1:0\"\n\
             [plugins]\nstore = \"postgres\"\nmail_transport = \"smtp\"\n\
             [plugin.smtp]\nhost = \"smtp.invalid\"\n\
             [database]\nurl = {url:?}\n{migration}migrate_on_start = false\nmax_connections = 4\n\
             allow_insecure_transport = true\n{database_extra}\
             [[security.keys]]\nid = \"k1\"\nsecret_file = {:?}\n",
            key.display().to_string()
        )
    }

    /// A second tenant on the same database. Whatever its credentials are, the resources of the first are not there: 404 over
    /// the API and over DAV, and nothing of the other tenant in the body (`ENGINEERING_RULES` R4).
    async fn other_tenants_see_nothing(world: &World, olivia: &Olivia, globex: &Bootstrapped) {
        let bob = provision_user(&world.internal, "globex", &globex.domain, &globex.token, "bob", "Bob").await;
        for (token, what) in [
            (&globex.token, "the administration token"),
            (&bob.token, "the API token of a user"),
        ] {
            let reply = world
                .internal
                .api("GET", "/api/v1/tenants/acme/principals/olivia", token, &Value::Null)
                .await;
            assert_eq!(reply.status, 404, "{what} of another tenant: {}", reply.text());
            assert!(!reply.text().contains("Olivia"), "{what}: {}", reply.text());
        }
        for path in [
            "/dav/principals/acme/olivia/".to_owned(),
            olivia.collection.clone(),
            format!("{}kickoff.ics", olivia.collection),
        ] {
            for method in ["PROPFIND", "GET"] {
                let reply = world
                    .public
                    .send(
                        method,
                        &path,
                        &[("Authorization", bob.authorization.as_str()), ("Depth", "0")],
                        b"",
                    )
                    .await;
                assert_eq!(
                    reply.status,
                    404,
                    "{method} {path} as a user of another tenant: {}",
                    reply.text()
                );
                assert!(
                    !reply.text().contains("Kickoff") && !reply.text().contains("Olivia"),
                    "{method} {path}: {}",
                    reply.text()
                );
            }
        }
        let own = world
            .internal
            .api(
                "GET",
                "/api/v1/tenants/globex/principals/bob",
                &globex.token,
                &Value::Null,
            )
            .await;
        assert_eq!(own.status, 200, "{}", own.text());
    }

    #[tokio::test]
    async fn production_mode_serves_under_the_two_role_model_and_tenants_stay_apart() {
        let Some(admin_url) = database_url() else {
            return;
        };
        let roles = Roles::create(&admin_url).await;
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("key");
        std::fs::write(&key, "0123456789abcdef0123456789abcdef0123456789\n").unwrap();
        let registry = Arc::new(registry().unwrap());

        // A deployment step with the owner's credentials migrates; the serving process never holds them.
        let owner_config =
            Config::from_toml(&production_config(&roles.runtime_url, Some(&roles.owner_url), &key, "")).unwrap();
        let migrated = admin::migrate(&owner_config).await.unwrap();
        assert!(migrated.changed(), "{migrated:?}");
        assert!(
            matches!(
                migrated.role_model,
                davhaven_store_postgres::migrate::RoleModel::Applied { runtime_roles: 1 }
            ),
            "the role model of the database was applied to the runtime role: {migrated:?}"
        );

        // The server connects as the runtime role in production mode: the posture check passes, and /readyz reports the
        // database as healthy and not as degraded.
        let serving = Config::from_toml(&production_config(&roles.runtime_url, None, &key, "")).unwrap();
        let assembly = assemble(Arc::new(serving), &registry).await.unwrap();
        let acme = bootstrap_tenant(&assembly, "acme").await;
        let globex = bootstrap_tenant(&assembly, "globex").await;
        let retention = RetentionWorker::new(AppCore::new(assembly.deps.clone()));
        let world = world_of(assembly, "acme", acme).await;
        let ready = world.ops.get("/readyz").await;
        assert_eq!(ready.status, 200, "{}", ready.text());
        assert_eq!(
            ready.json()["components"][0],
            json!({"name": "database", "status": "healthy"}),
            "the role is bound by row-level security: {}",
            ready.text()
        );

        // The scenario of the image smoke test runs under row-level security.
        let olivia = provision(&world).await;
        dav_writes_and_the_api_reads(&world, &olivia).await;
        the_api_writes_and_dav_reads(&world, &olivia).await;

        other_tenants_see_nothing(&world, &olivia, &globex).await;

        // The retention worker runs as the runtime role: it is not allowed to purge the audit log, which is a state of the
        // deployment and not a failure; the owner purges it with the command of the recipe.
        let sweep = retention.sweep().await;
        assert_eq!(sweep.failed, Vec::<&str>::new(), "{sweep:?}");
        assert_eq!(sweep.skipped, vec!["audit_events"], "{sweep:?}");
        admin::purge_audit(&owner_config, &SystemClock).await.unwrap();
        assert_eq!(world.ops.get("/readyz").await.status, 200);
        assert!(world.running.shutdown().await);

        // Production refuses a role that row-level security does not bind (here the superuser), unless the operator says
        // that tenant isolation may rest on the application alone.
        let unbound_url = roles.superuser_url.clone();
        let unbound = Config::from_toml(&production_config(&unbound_url, None, &key, "")).unwrap();
        let refused = assemble(Arc::new(unbound), &registry)
            .await
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("superuser") && refused.contains("docs/operations/database.md"),
            "{refused}"
        );
        let accepted = Config::from_toml(&production_config(
            &unbound_url,
            None,
            &key,
            "allow_unbound_role = true\n",
        ))
        .unwrap();
        let assembly = assemble(Arc::new(accepted), &registry).await.unwrap();
        for hook in assembly.hooks {
            hook.lifecycle.shutdown().await;
        }
        roles.drop_all().await;
    }
}
