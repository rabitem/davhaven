//! The per-token budgets of the rate limiter port, their audit records and the tenant switch.
//!
//! The budgets are the `RateLimiter` port's (R2): the application charges every tool call to the bucket of its token
//! (`mcp_read`, `mcp_write`), and the allowance is the limiter's configuration. Time is the manual clock of the world,
//! so nothing here sleeps.

use std::collections::BTreeMap;
use std::time::Duration as StdDuration;

use chrono::Duration;
use davhaven_testkit::davhaven_domain::{CalendarKind, Scope};
use davhaven_testkit::davhaven_mcp::config::McpConfig;
use davhaven_testkit::davhaven_ratelimit_memory::config::{BucketConfig, MemoryRateLimitConfig};
use serde_json::json;

use super::support::{Mcp, Org, Person, World};

/// A limiter that allows `reads` read calls and `writes` write calls per minute and token.
fn rates(reads: u32, writes: u32) -> MemoryRateLimitConfig {
    let bucket = |limit| BucketConfig {
        limit,
        window: StdDuration::from_mins(1),
        backoff: None,
    };
    MemoryRateLimitConfig {
        buckets: BTreeMap::from([
            ("mcp_read".to_owned(), bucket(reads)),
            ("mcp_write".to_owned(), bucket(writes)),
        ]),
        ..MemoryRateLimitConfig::default()
    }
}

/// A world with that limiter, the tenant acme, anna with her calendar `work` and a token of anna.
async fn limited(reads: u32, writes: u32) -> (World, Org, Person, serde_json::Value, Mcp) {
    let world = World::with(rates(reads, writes), &McpConfig::default());
    let org = world.org("acme", true).await;
    let anna = world.user(&org, "anna").await;
    let work = world.calendar(&org, &anna, "work", CalendarKind::User).await;
    let assistant = world.mcp(&world.token(&org, &anna, &[Scope::McpRead, Scope::McpWrite]).await);
    (world, org, anna, json!(work.id), assistant)
}

#[tokio::test]
async fn reads_and_writes_have_budgets_of_their_own_per_token() {
    let (world, org, _, work, assistant) = limited(3, 1).await;
    for _ in 0..3 {
        assistant.ok("list_calendars", json!({})).await;
    }
    let refused = assistant.failed_result("list_calendars", json!({})).await;
    let meta = &refused["_meta"];
    assert_eq!(meta["davhaven/problem"]["code"], "rate-limited");
    assert_eq!(meta["davhaven/problem"]["status"], 429);
    assert_eq!(meta["davhaven/retryable"], true);
    assert_eq!(
        meta["davhaven/retry_after_seconds"], 20,
        "three calls per minute is one per 20 seconds"
    );

    // The exhausted reads leave the writes alone, which have their own allowance.
    let event =
        json!({"calendar_id": work, "event": {"summary": "Lunch", "start": {"date_time": "2027-03-02T12:00:00Z"}}});
    assistant.ok("create_event", event.clone()).await;
    assert_eq!(assistant.fails("create_event", event).await["code"], "rate-limited");

    // Another token has a budget of its own, and the handshake and the tool list are free.
    let ben = world.user(&org, "ben").await;
    world
        .mcp(&world.token(&org, &ben, &[Scope::McpRead]).await)
        .ok("list_calendars", json!({}))
        .await;
    for _ in 0..10 {
        assistant.rpc("tools/list", &json!({})).await;
        assistant.rpc("ping", &json!({})).await;
    }

    // Time refills the bucket, a refused call having cost nothing.
    world.clock.advance(Duration::seconds(20));
    assistant.ok("list_calendars", json!({})).await;
    assert_eq!(
        assistant.fails("list_calendars", json!({})).await["code"],
        "rate-limited"
    );
}

#[tokio::test]
async fn a_call_with_bad_arguments_costs_budget_like_any_other() {
    let (_, _, _, _, assistant) = limited(1, 1).await;
    let invalid = assistant.fails("list_events", json!({"nonsense": true})).await;
    assert_eq!(invalid["code"], "validation-failed");
    let refused = assistant.fails("list_calendars", json!({})).await;
    assert_eq!(
        refused["code"], "rate-limited",
        "a client that loops on a mistake is slowed down"
    );
}

#[tokio::test]
async fn a_refused_call_never_reaches_the_services() {
    let (world, org, _, work, assistant) = limited(1, 1).await;
    let event =
        json!({"calendar_id": work, "event": {"summary": "Lunch", "start": {"date_time": "2027-03-02T12:00:00Z"}}});
    assistant.ok("create_event", event.clone()).await;
    let written = world
        .audit_actions(&org)
        .await
        .iter()
        .filter(|action| *action == "mcp.write")
        .count();
    for _ in 0..3 {
        assistant.fails("create_event", event.clone()).await;
    }
    let after = world
        .audit_actions(&org)
        .await
        .iter()
        .filter(|action| *action == "mcp.write")
        .count();
    assert_eq!(after, written, "nothing was written by a refused call");
}

#[tokio::test]
async fn refusals_are_audited_once_per_token_and_minute_with_the_total_of_the_minute_that_ended() {
    let (world, org, _, _, assistant) = limited(3, 30).await;
    let trips = |rows: Vec<davhaven_testkit::davhaven_ports::AuditRow>| -> Vec<(String, u64)> {
        rows.into_iter()
            .filter(|row| row.action == "rate_limit.tripped")
            .map(|row| {
                (
                    row.details["bucket"].as_str().unwrap().to_owned(),
                    row.details["count"].as_u64().unwrap(),
                )
            })
            .collect()
    };
    for _ in 0..3 {
        assistant.ok("list_calendars", json!({})).await;
    }
    for _ in 0..5 {
        assistant.fails("list_calendars", json!({})).await;
    }
    assert_eq!(
        trips(world.audit(&org).await),
        vec![("mcp_read".to_owned(), 1)],
        "a flood of refused calls is one record while the minute lasts, written when it started"
    );

    // The next minute: the refusals of the one that ended are recorded as a total, and the new one opens its own record.
    world.clock.advance(Duration::seconds(61));
    for _ in 0..3 {
        assistant.ok("list_calendars", json!({})).await;
    }
    assistant.fails("list_calendars", json!({})).await;
    assert_eq!(
        trips(world.audit(&org).await),
        vec![
            ("mcp_read".to_owned(), 1),
            ("mcp_read".to_owned(), 5),
            ("mcp_read".to_owned(), 1)
        ]
    );
    // The records name the token's label and never the content of a call.
    let rows = world.audit(&org).await;
    let row = rows.iter().find(|row| row.action == "rate_limit.tripped").unwrap();
    assert_eq!(row.actor.label.as_deref(), Some("assistant"));
}

#[tokio::test]
async fn a_tenant_that_switches_mcp_off_loses_the_endpoint_at_once_and_gets_it_back() {
    let world = World::new();
    let org = world.org("acme", true).await;
    let other = world.org("globex", true).await;
    let anna = world.user(&org, "anna").await;
    let gina = world.user(&other, "gina").await;
    let assistant = world.mcp(&world.token(&org, &anna, &[Scope::McpRead]).await);
    let neighbour = world.mcp(&world.token(&other, &gina, &[Scope::McpRead]).await);
    assistant.ok("list_calendars", json!({})).await;

    world.tenant_write("acme", false).await;
    let refused = assistant.post("ping", &json!({})).await;
    assert_eq!(
        refused.status, 404,
        "the endpoint does not exist for a tenant that has not switched it on"
    );
    assert_eq!(refused.json::<serde_json::Value>().unwrap()["code"], "not-found");
    neighbour.ok("list_calendars", json!({})).await;
    assert!(
        world.token_refused(&org, &anna).await,
        "no new token with MCP scopes is minted for the tenant either"
    );

    world.tenant_write("acme", true).await;
    assistant.ok("list_calendars", json!({})).await;
}

#[tokio::test]
async fn a_tenant_has_mcp_off_until_it_says_otherwise() {
    let world = World::new();
    let org = world.org("quiet", false).await;
    let anna = world.user(&org, "anna").await;
    assert!(world.token_refused(&org, &anna).await, "the default is fail closed");
}
