//! Who sees nothing: other tenants, strangers in the same tenant, tokens that are no good (R4, PLAN 2.6).
//!
//! What a person cannot see answers `not-found`, and the answer is the one for what does not exist: the same status, code
//! and text for a calendar of another tenant, a calendar of a stranger and an id that nobody ever made, for every tool
//! that takes an id, and asking changes nothing.

use chrono::Duration;
use davhaven_testkit::Actor;
use davhaven_testkit::davhaven_domain::{CalendarKind, Scope};
use serde_json::{Value, json};

use super::support::{World, data};

/// The calls every tool that names a calendar answers, against `calendar`.
fn calls(calendar: &Value, event: &Value) -> Vec<(&'static str, Value)> {
    vec![
        ("get_event", json!({"calendar_id": calendar, "event_id": event})),
        (
            "list_events",
            json!({"calendar_id": calendar, "start": "2027-03-01T00:00:00Z", "end": "2027-03-08T00:00:00Z"}),
        ),
        (
            "search_events",
            json!({"calendar_id": calendar, "query": "standup", "start": "2027-03-01T00:00:00Z",
                   "end": "2027-03-08T00:00:00Z"}),
        ),
        (
            "create_event",
            json!({"calendar_id": calendar,
                   "event": {"summary": "Intruder", "start": {"date_time": "2027-03-02T12:00:00Z"}}}),
        ),
        (
            "update_event",
            json!({"calendar_id": calendar, "event_id": event, "changes": {"summary": "Hijacked"}}),
        ),
        ("delete_event", json!({"calendar_id": calendar, "event_id": event})),
        (
            "respond_to_invitation",
            json!({"calendar_id": calendar, "event_id": event, "partstat": "accepted"}),
        ),
    ]
}

#[tokio::test]
async fn people_of_other_tenants_and_strangers_see_nothing_through_any_tool_and_change_nothing() {
    let world = World::new();
    let acme = world.org("acme", true).await;
    let globex = world.org("globex", true).await;
    let anna = world.user(&acme, "anna").await;
    let cara = world.user(&acme, "cara").await;
    let gina = world.user(&globex, "gina").await;
    let work = world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let (event, _) = world.event(&acme, &anna, "work", "standup", data("Standup")).await;
    let (work_id, event_id) = (json!(work.id), json!(event.id.unwrap()));
    let owner = world.mcp(&world.token(&acme, &anna, &[Scope::McpRead, Scope::McpWrite]).await);
    let stranger = world.mcp(&world.token(&acme, &cara, &[Scope::McpRead, Scope::McpWrite]).await);
    let foreigner = world.mcp(&world.token(&globex, &gina, &[Scope::McpRead, Scope::McpWrite]).await);
    let before_actions = world.audit_actions(&acme).await;
    let before_events = world.outbox_count(&acme, "domain_event").await;
    let first_etag = owner
        .ok("get_event", json!({"calendar_id": work_id, "event_id": event_id}))
        .await["event"]["etag"]
        .clone();

    let nobody = json!("018f3c1e-7b2a-7c3d-9e4f-0000000000cc");
    for (who, assistant) in [("a stranger", &stranger), ("a person of another tenant", &foreigner)] {
        for ((tool, real), (_, unknown)) in calls(&work_id, &event_id).into_iter().zip(calls(&nobody, &event_id)) {
            let seen = assistant.fails(tool, real).await;
            let missing = assistant.fails(tool, unknown).await;
            assert_eq!(seen["code"], "not-found", "{who}: {tool}");
            assert_eq!(seen["status"], 404, "{who}: {tool}");
            assert_eq!(
                seen["detail"], missing["detail"],
                "{who}: {tool}: what exists looks like what does not"
            );
            assert_eq!(seen["title"], missing["title"], "{who}: {tool}");
            assert!(!seen.to_string().contains("Standup"), "{who}: {tool}: {seen}");
        }
    }

    // Asking changed nothing: not the event, not the audit log, not the outbox.
    let still = owner
        .ok("get_event", json!({"calendar_id": work_id, "event_id": event_id}))
        .await;
    assert_eq!(still["event"]["untrusted_text"]["summary"], "Standup");
    assert_eq!(still["event"]["etag"], first_etag);
    assert_eq!(
        world.audit_actions(&acme).await,
        before_actions,
        "nobody wrote anything"
    );
    assert_eq!(world.outbox_count(&acme, "domain_event").await, before_events);

    // Their own home holds their own calendars only.
    for assistant in [&stranger, &foreigner] {
        let calendars = assistant.ok("list_calendars", json!({})).await;
        assert!(
            !calendars.to_string().contains(work_id.as_str().unwrap()),
            "the calendar of somebody else is not in the home: {calendars}"
        );
    }
    // Free-busy tells the busy times of people of the own tenant; the people of another tenant are outsiders.
    let outsider = foreigner
        .ok(
            "free_busy",
            json!({"addresses": ["anna@acme.example"], "start": "2027-03-02T00:00:00Z", "end": "2027-03-03T00:00:00Z"}),
        )
        .await;
    assert_eq!(outsider["entries"][0]["known"], false);
    assert_eq!(outsider["entries"][0]["busy"], json!([]));
}

#[tokio::test]
async fn a_cursor_of_one_person_or_tenant_gets_nobody_else_anna_results() {
    let world = World::new();
    let acme = world.org("acme", true).await;
    let globex = world.org("globex", true).await;
    let anna = world.user(&acme, "anna").await;
    let cara = world.user(&acme, "cara").await;
    let gina = world.user(&globex, "gina").await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    world.event(&acme, &anna, "work", "a", data("Alpha")).await;
    let mut later = data("Beta");
    later.start = Some(serde_json::from_value(json!({"date_time": "2027-03-03T09:00:00Z"})).unwrap());
    later.end = Some(serde_json::from_value(json!({"date_time": "2027-03-03T10:00:00Z"})).unwrap());
    world.event(&acme, &anna, "work", "b", later).await;
    let owner = world.mcp(&world.token(&acme, &anna, &[Scope::McpRead]).await);
    let stranger = world.mcp(&world.token(&acme, &cara, &[Scope::McpRead]).await);
    let foreigner = world.mcp(&world.token(&globex, &gina, &[Scope::McpRead]).await);

    let arguments = |cursor: Option<&Value>| {
        let mut arguments = json!({"start": "2027-03-01T00:00:00Z", "end": "2027-03-08T00:00:00Z", "limit": 1});
        if let Some(cursor) = cursor {
            arguments["cursor"] = cursor.clone();
        }
        arguments
    };
    let first = owner.ok("list_events", arguments(None)).await;
    assert_eq!(first["events"].as_array().unwrap().len(), 1);
    let cursor = first["next_cursor"].clone();

    // The cursor of another tenant is not valid; one signed for the tenant and presented by a stranger continues the
    // stranger's own listing, which holds nothing of Anna's.
    let other_tenant = foreigner.fails("list_events", arguments(Some(&cursor))).await;
    assert_eq!(other_tenant["code"], "validation-failed");
    let stranger_page = stranger.ok("list_events", arguments(Some(&cursor))).await;
    assert_eq!(stranger_page["events"], json!([]), "{stranger_page}");
    let anna_events = owner.ok("list_events", arguments(Some(&cursor))).await;
    assert_eq!(anna_events["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn tokens_that_are_no_good_are_refused_before_anything_is_looked_at() {
    let world = World::new();
    let acme = world.org("acme", true).await;
    let anna = world.user(&acme, "anna").await;
    let both = [Scope::McpRead, Scope::McpWrite];

    // Nothing, a made-up token and a token of the right form that nobody minted.
    for actor in [
        Actor::Anonymous,
        Actor::bearer("dvh_pat_nobody000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Actor::bearer("not-even-a-token"),
    ] {
        let response = world.mcp_as(actor).post("ping", &json!({})).await;
        assert_eq!(response.status, 401);
        assert_eq!(response.header("www-authenticate"), Some("Bearer realm=\"davhaven\""));
    }

    // A token that expired.
    let expiring = world.mint(&acme, &anna, &both, world.now() + Duration::hours(1)).await;
    let assistant = world.mcp(&expiring.secret);
    assert_eq!(assistant.post("ping", &json!({})).await.status, 200);
    world.clock.advance(Duration::hours(2));
    assert_eq!(
        assistant.post("ping", &json!({})).await.status,
        401,
        "an expired token is no token"
    );

    // A token that was revoked, at once.
    let revoked = world.mint(&acme, &anna, &both, world.now() + Duration::days(1)).await;
    let assistant = world.mcp(&revoked.secret);
    assert_eq!(assistant.post("ping", &json!({})).await.status, 200);
    world.revoke(&acme, revoked.token.id).await;
    assert_eq!(assistant.post("ping", &json!({})).await.status, 401);
}

#[tokio::test]
async fn only_a_principal_token_with_an_mcp_scope_is_offered_anything() {
    let world = World::new();
    let acme = world.org("acme", true).await;
    let anna = world.user(&acme, "anna").await;
    let calendar = world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let event = json!("018f3c1e-7b2a-7c3d-9e4f-0000000000dd");

    // A tenant administrator acts as nobody: it may shake hands, is offered no tools and finds nothing.
    let admin = world.mcp(
        &world
            .tenant_token(&acme, &[Scope::EventsRead, Scope::CalendarsRead])
            .await,
    );
    // A token of the person that was issued for something else carries no MCP scope.
    let events_only = world.mcp(
        &world
            .token(&acme, &anna, &[Scope::EventsRead, Scope::EventsWrite])
            .await,
    );
    for (what, assistant, code) in [
        ("a tenant token", &admin, "not-found"),
        ("a token without an MCP scope", &events_only, "forbidden"),
    ] {
        let listed = assistant.rpc("tools/list", &json!({})).await;
        assert_eq!(listed["result"]["tools"], json!([]), "{what}");
        for (tool, arguments) in calls(&json!(calendar.id), &event) {
            let problem = assistant.fails(tool, arguments).await;
            assert_eq!(problem["code"], code, "{what}: {tool}");
        }
        let problem = assistant.fails("list_calendars", json!({})).await;
        assert_eq!(problem["code"], code, "{what}");
    }
}
