//! A service principal as the assistant: the token a deployment mints through the management API, the calendars the
//! principal is granted (a group's and a managed one), and the limits of the exception that makes this possible.
//!
//! A tenant token cannot hold `mcp:*` scopes, and a token mints only tokens whose scopes are a subset of its own, so
//! without an exception no token could ever mint the token an assistant needs. The exception is for the `mcp:*` scopes
//! of **service principals**: a tenant token with `credentials:write` (which can mint an app password for them as well)
//! may put them on a principal token for such a principal, **provided it holds the API scope that reaches the same data**
//! (`events:read` for `mcp:read`, `events:write` for `mcp:write` and `mcp:schedule_external`), because MCP, unlike DAV,
//! does not cap managed calendars at read. Every other scope still follows the subset rule, and users are not covered
//! at all (`davhaven_app::credentials`, "Who may mint what").

use davhaven_testkit::davhaven_app::services::PageRequest;
use davhaven_testkit::davhaven_domain::{CalendarKind, ErrorKind, GrantAccess, Scope, ScopeSet, TokenKind};
use davhaven_testkit::davhaven_wire::{ApiTokenCreate, ProblemCode};
use serde_json::{Value, json};

use super::support::{Org, Person, World, data, march};

/// The tenant `acme` (MCP switched on) with the user anna and the group `staff` she belongs to. The service principal
/// `assistant` is granted the group's calendar `team` for reading and writing and the managed calendar `courses` of anna
/// for reading: the two kinds of calendar besides a person's own that a deployment gives an assistant.
struct Acme {
    world: World,
    org: Org,
    anna: Person,
    assistant: Person,
    team: Value,
    courses: Value,
}

async fn acme() -> Acme {
    let world = World::new();
    let org = world.org("acme", true).await;
    let anna = world.user(&org, "anna").await;
    let staff = world.group(&org, "staff", &[&anna]).await;
    let assistant = world.service(&org, "assistant").await;
    let team = world.calendar(&org, &staff, "team", CalendarKind::Group).await;
    let courses = world.calendar(&org, &anna, "courses", CalendarKind::Managed).await;
    world
        .grant(&org, &staff, "team", &assistant, GrantAccess::ReadWrite)
        .await;
    world.grant(&org, &anna, "courses", &assistant, GrantAccess::Read).await;
    Acme {
        world,
        org,
        anna,
        assistant,
        team: json!(team.id),
        courses: json!(courses.id),
    }
}

/// The request for a principal token of `person` that never expires (the rule for tokens without MCP scopes).
fn principal_token(person: &Person, scopes: &[Scope]) -> ApiTokenCreate {
    ApiTokenCreate {
        kind: TokenKind::Principal,
        principal: Some(person.name.clone()),
        label: "integration".to_owned(),
        scopes: ScopeSet::of(scopes),
        expires_at: None,
        allowed_origins: Vec::new(),
    }
}

/// The request for a principal token of `person` with `scopes` that expires in 30 days (MCP scopes need an expiry).
fn mcp_token(world: &World, person: &Person, scopes: &[Scope]) -> ApiTokenCreate {
    ApiTokenCreate {
        expires_at: Some(world.now() + chrono::Duration::days(30)),
        ..principal_token(person, scopes)
    }
}

#[tokio::test]
async fn a_tenant_token_mints_the_mcp_token_of_a_service_principal_that_works_on_its_grants() {
    let Acme {
        world,
        org,
        anna,
        assistant,
        team,
        courses,
    } = acme().await;

    // The tenant token of the deployment has credentials:write and no MCP scope, and still mints the token.
    let minted = world
        .mint_with_a_tenant_token(&org, &assistant, &[Scope::McpRead, Scope::McpWrite])
        .await
        .unwrap();
    assert_eq!(minted.token.principal, Some(assistant.name.clone()));
    assert!(minted.token.expires_at.is_some(), "an MCP token expires");
    let mcp = world.mcp(&minted.secret);

    // The home of the service principal lists what it was granted, with what it may do there.
    let calendars = mcp.ok("list_calendars", json!({})).await;
    let listed = calendars["calendars"].as_array().unwrap();
    assert_eq!(listed.len(), 2, "{calendars}");
    let find = |id: &Value| {
        listed
            .iter()
            .find(|calendar| &calendar["calendar_id"] == id)
            .unwrap_or_else(|| panic!("a granted calendar is in the home: {calendars}"))
    };
    assert_eq!(
        find(&team)["writable"],
        true,
        "the group's calendar, granted read_write"
    );
    assert_eq!(find(&courses)["writable"], false, "the managed calendar, granted read");

    // It writes where it may and reads what it wrote.
    let created = mcp
        .ok(
            "create_event",
            json!({"calendar_id": team, "client_request_id": "kickoff",
                   "event": {"summary": "Kickoff", "start": {"date_time": "2027-03-02T09:00:00Z"},
                             "end": {"date_time": "2027-03-02T10:00:00Z"}}}),
        )
        .await;
    assert_eq!(created["created"], true);
    let mut range = march();
    range["calendar_id"] = team.clone();
    let listing = mcp.ok("list_events", range).await;
    assert_eq!(listing["events"].as_array().unwrap().len(), 1);

    // It reads the managed calendar, and a write there is refused with the answer for a missing privilege: the grant is
    // read, and MCP honours what the grant says.
    let (event, _) = world.event(&org, &anna, "courses", "course-1", data("Course")).await;
    let mut range = march();
    range["calendar_id"] = courses.clone();
    let seen = mcp.ok("list_events", range).await;
    assert_eq!(seen["events"].as_array().unwrap().len(), 1);
    let refused = mcp
        .fails(
            "create_event",
            json!({"calendar_id": courses, "client_request_id": "sneaky",
                   "event": {"summary": "Not allowed", "start": {"date_time": "2027-03-03T09:00:00Z"},
                             "end": {"date_time": "2027-03-03T10:00:00Z"}}}),
        )
        .await;
    assert_eq!(refused["code"], "forbidden");
    let refused = mcp
        .fails(
            "delete_event",
            json!({"calendar_id": courses, "event_id": event.id.unwrap()}),
        )
        .await;
    assert_eq!(refused["code"], "forbidden");

    // The minting is in the audit log of the tenant.
    let actions = world.audit_actions(&org).await;
    assert!(actions.iter().any(|action| action == "token.created"), "{actions:?}");
}

#[tokio::test]
async fn the_exception_is_for_service_principals_and_for_principal_tokens_only() {
    let Acme {
        world,
        org,
        anna,
        assistant,
        ..
    } = acme().await;

    // A user cannot be given MCP scopes by a tenant token: the plain rule applies and says where MCP scopes go.
    let error = world
        .mint_with_a_tenant_token(&org, &anna, &[Scope::McpRead])
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert!(error.public_message().as_str().contains("service principal"), "{error}");

    // Neither can a resource: the exception is for service principals, not for every principal that can hold a token.
    let room = world.resource(&org, "room-1").await;
    let error = world
        .mint_with_a_tenant_token(&org, &room, &[Scope::McpRead])
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::Forbidden,
        "a resource gets no MCP scopes from a tenant token"
    );
    assert!(error.public_message().as_str().contains("service principal"), "{error}");

    // A token that lacks events:write cannot hand it to a user ...
    let weak = world
        .admin_with(&org, &[Scope::CredentialsWrite, Scope::EventsRead])
        .await;
    let refused = world
        .services
        .credentials
        .create_api_token(&weak, principal_token(&anna, &[Scope::EventsWrite]))
        .await
        .unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::Forbidden, "users get the subset rule");
    // ... and not to a service principal either: the exception is the `mcp:*` scopes, nothing else.
    let refused = world
        .services
        .credentials
        .create_api_token(&weak, principal_token(&assistant, &[Scope::EventsWrite]))
        .await
        .unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::Forbidden, "events:write is not an MCP scope");
    let mixed = mcp_token(&world, &assistant, &[Scope::McpRead, Scope::EventsWrite]);
    let refused = world
        .services
        .credentials
        .create_api_token(&weak, mixed)
        .await
        .unwrap_err();
    assert_eq!(
        refused.kind(),
        ErrorKind::Forbidden,
        "the other scopes of the token follow the rule"
    );
    assert!(
        !refused.public_message().as_str().contains("service principal"),
        "it is not the MCP scopes that are refused: {refused}"
    );
    // The MCP scopes that the API scopes of the minter reach are what a token that holds credentials:write may add for
    // a service principal, next to scopes it holds itself.
    let allowed = world
        .services
        .credentials
        .create_api_token(
            &weak,
            mcp_token(&world, &assistant, &[Scope::McpRead, Scope::EventsRead]),
        )
        .await
        .unwrap();
    assert_eq!(allowed.token.principal, Some(assistant.name.clone()));

    // Without credentials:write nothing is minted at all, for anyone.
    let reader = world.admin_with(&org, &[Scope::EventsRead]).await;
    let nothing = world
        .services
        .credentials
        .create_api_token(&reader, principal_token(&assistant, &[Scope::EventsRead]))
        .await
        .unwrap_err();
    assert_eq!(nothing.kind(), ErrorKind::Forbidden);

    // The exception is for principal tokens: a tenant token keeps to the scopes of the token that mints it.
    let more = ApiTokenCreate {
        kind: TokenKind::Tenant,
        principal: None,
        label: "more".to_owned(),
        scopes: ScopeSet::of(&[Scope::PrincipalsWrite]),
        expires_at: None,
        allowed_origins: Vec::new(),
    };
    let only_credentials = world.admin_with(&org, &[Scope::CredentialsWrite]).await;
    let refused = world
        .services
        .credentials
        .create_api_token(&only_credentials, more)
        .await
        .unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::Forbidden);
}

#[tokio::test]
async fn the_exception_stays_inside_the_tenant() {
    let Acme { world, org, .. } = acme().await;
    // A service principal of another tenant is invisible to a token of this one: 404, and nothing is minted for it there.
    let globex = world.org("globex", true).await;
    let outsider = world.service(&globex, "outsider").await;
    let acme_admin = world
        .admin_with(&org, &[Scope::CredentialsWrite, Scope::EventsRead, Scope::EventsWrite])
        .await;
    let error = world
        .services
        .credentials
        .create_api_token(&acme_admin, mcp_token(&world, &outsider, &[Scope::McpRead]))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound, "{error}");
    let globex_admin = world.admin_with(&globex, &[Scope::CredentialsWrite]).await;
    let tokens = world
        .services
        .credentials
        .list_api_tokens(&globex_admin, PageRequest::first())
        .await
        .unwrap();
    assert!(
        tokens.items.iter().all(|token| token.principal.is_none()),
        "no token acts as a principal of the other tenant: {:?}",
        tokens.items
    );
}

#[tokio::test]
async fn an_mcp_scope_needs_the_api_scope_that_reaches_the_same_data() {
    let Acme {
        world, org, assistant, ..
    } = acme().await;
    // The assistant owns a managed calendar: DAV caps it at read for everyone, MCP does not.
    world.calendar(&org, &assistant, "feed", CalendarKind::Managed).await;
    let feed = world
        .services
        .calendars
        .get(
            &world.admin_with(&org, &[Scope::CalendarsRead]).await,
            &world.key(&assistant, "feed"),
        )
        .await
        .unwrap()
        .id;

    // credentials:write alone hands out nothing, not even the read of what the assistant owns ...
    let only_credentials = world.admin_with(&org, &[Scope::CredentialsWrite]).await;
    // ... and with events:read it hands out the reading only: mcp:write and mcp:schedule_external send invitations and
    // write the managed calendars, which a token without events:write could never do itself.
    let reads = world
        .admin_with(&org, &[Scope::CredentialsWrite, Scope::EventsRead])
        .await;
    let writes_only = world
        .admin_with(&org, &[Scope::CredentialsWrite, Scope::EventsWrite])
        .await;
    for (minter, scopes, allowed) in [
        (&only_credentials, &[Scope::McpRead][..], false),
        (&reads, &[Scope::McpRead][..], true),
        (&reads, &[Scope::McpWrite][..], false),
        (&reads, &[Scope::McpScheduleExternal][..], false),
        (&reads, &[Scope::McpRead, Scope::McpWrite][..], false),
        // The scopes are independent: writing events does not read them, so `events:write` hands out the writing and the
        // invitations, and not the reading.
        (&writes_only, &[Scope::McpWrite][..], true),
        (&writes_only, &[Scope::McpScheduleExternal][..], true),
        (&writes_only, &[Scope::McpRead][..], false),
    ] {
        let result = world
            .services
            .credentials
            .create_api_token(minter, mcp_token(&world, &assistant, scopes))
            .await;
        if allowed {
            assert!(result.is_ok(), "{scopes:?}: {result:?}");
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Forbidden, "{scopes:?}");
            assert!(
                error.public_message().as_str().contains("events:"),
                "the refusal names the API scope that is missing: {error}"
            );
        }
    }

    // A token that may read and write events may hand out the reading, the writing and the invitations together ...
    let writes = world
        .admin_with(&org, &[Scope::CredentialsWrite, Scope::EventsRead, Scope::EventsWrite])
        .await;
    let minted = world
        .services
        .credentials
        .create_api_token(
            &writes,
            mcp_token(
                &world,
                &assistant,
                &[Scope::McpRead, Scope::McpWrite, Scope::McpScheduleExternal],
            ),
        )
        .await
        .unwrap();
    // ... and the token reaches the managed calendar, which is why the minter needs the scope of the same reach.
    let mcp = world.mcp(&minted.secret);
    let created = mcp
        .ok(
            "create_event",
            json!({"calendar_id": json!(feed), "client_request_id": "feed-1",
                   "event": {"summary": "Course", "start": {"date_time": "2027-03-02T09:00:00Z"},
                             "end": {"date_time": "2027-03-02T10:00:00Z"}}}),
        )
        .await;
    assert_eq!(
        created["created"], true,
        "MCP writes to a managed calendar the principal may write"
    );
}

#[tokio::test]
async fn the_minted_token_follows_the_rules_of_mcp_tokens() {
    let Acme {
        world, org, assistant, ..
    } = acme().await;

    // An expiry is required for MCP scopes, as for every MCP token.
    let admin = world
        .admin_with(&org, &[Scope::CredentialsWrite, Scope::EventsRead])
        .await;
    let no_expiry = world
        .services
        .credentials
        .create_api_token(&admin, principal_token(&assistant, &[Scope::McpRead]))
        .await
        .unwrap_err();
    assert_eq!(no_expiry.kind(), ErrorKind::Invalid);
    assert_eq!(
        no_expiry.field_errors().first().map(|field| field.code),
        Some("required")
    );

    // A token never outlives the token that minted it: the expiry of the minter caps the one that was asked for.
    let until = world.now() + chrono::Duration::days(1);
    let short_lived = world
        .admin_until(&org, &[Scope::CredentialsWrite, Scope::EventsRead], Some(until))
        .await;
    let capped = world
        .services
        .credentials
        .create_api_token(&short_lived, mcp_token(&world, &assistant, &[Scope::McpRead]))
        .await
        .unwrap();
    assert_eq!(
        capped.token.expires_at.map(|at| at.timestamp_micros()),
        Some(until.timestamp_micros()),
        "the 30 days that were asked for are cut to the day the minter has left"
    );

    // The token can be revoked, and it stops working at once.
    let minted = world
        .mint_with_a_tenant_token(&org, &assistant, &[Scope::McpRead])
        .await
        .unwrap();
    let mcp = world.mcp(&minted.secret);
    assert_eq!(
        mcp.ok("list_calendars", json!({})).await["calendars"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    world.revoke(&org, minted.token.id).await;
    let response = mcp.post("tools/list", &json!({})).await;
    assert_eq!(response.status, 401);

    // A tenant that has not switched MCP on mints no MCP token, for a service principal either.
    let off = world.org("off", false).await;
    let robot = world.service(&off, "robot").await;
    let refused = world
        .mint_with_a_tenant_token(&off, &robot, &[Scope::McpRead])
        .await
        .unwrap_err();
    assert_eq!(
        ProblemCode::from_error(refused.kind(), refused.precondition()).code(),
        "feature-not-enabled"
    );
}
