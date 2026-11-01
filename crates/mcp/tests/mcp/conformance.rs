//! Conformance with the specification, checked by a client that shares no code with the server.
//!
//! The client in [`super::support`] builds every message as plain JSON from what the MCP specification (revision
//! `2025-06-18`) and JSON-RPC 2.0 say, and the validator in [`super::schema`] reads the schemas the server announces
//! the way any client does. A server that passes is a server any client of the specification can use:
//!
//! * the lifecycle: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`;
//! * the catalog is the committed contract (`docs/contracts/mcp-tools.json`), with the annotations of the plan;
//! * every successful result carries `structuredContent` that validates against the tool's `outputSchema`, and the
//!   arguments the tests send validate against its `inputSchema`;
//! * every failure is a tool result with `isError: true`, no `structuredContent` (it would have to satisfy the output
//!   schema) and an RFC 9457 problem in `_meta`.

use davhaven_app::services::{BusyKind, BusyPeriod, FindSlotsResult, FreeBusyEntry, FreeBusyResult, Slot, TimeRange};
use davhaven_domain::{CalendarUserAddress, EventAttendee, EventData, ObjectId, PartStat};
use davhaven_wire::EventView;
use davhaven_wire::mcp::{PROBLEM_META_KEY, REQUIRED_SCOPE_META_KEY};
use serde_json::{Value, json};
use uuid::Uuid;

use super::schema::violations;
use super::support::{Client, Setup, at, calendar_named};

/// The committed catalog of the tools: the contract that `cargo xtask contracts --check` keeps current.
fn committed_catalog() -> Value {
    serde_json::from_str(include_str!("../../../../docs/contracts/mcp-tools.json")).unwrap()
}

/// The tools the server lists, by name.
async fn listed(client: &Client) -> Vec<Value> {
    client.rpc("tools/list", json!({})).await["result"]["tools"]
        .as_array()
        .unwrap()
        .clone()
}

fn tool<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap_or_else(|| panic!("no tool {name}"))
}

/// Calls a tool the way a model would: the arguments must satisfy the announced input schema, and a result of a
/// successful call must satisfy the announced output schema.
async fn call_conforming(client: &Client, tools: &[Value], name: &str, arguments: Value) -> Value {
    let announced = tool(tools, name);
    let problems = violations(&announced["inputSchema"], &arguments);
    assert_eq!(
        problems,
        Vec::<String>::new(),
        "{name}: the test sends arguments its own input schema rejects"
    );
    let result = client.call(name, arguments).await;
    assert_eq!(result["isError"], false, "{name}: {result}");
    let structured = &result["structuredContent"];
    let problems = violations(&announced["outputSchema"], structured);
    assert!(
        problems.is_empty(),
        "{name}: the result does not satisfy its output schema: {problems:?}\n{structured}"
    );
    assert_eq!(result["content"].as_array().unwrap().len(), 1, "{name}");
    assert_eq!(result["content"][0]["type"], "text");
    assert_eq!(
        &serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
        structured,
        "{name}: the text is the serialized structured content (a client that ignores structuredContent reads it)"
    );
    structured.clone()
}

fn invitation(calendar: davhaven_domain::CalendarId) -> EventView {
    let mut data = EventData {
        uid: Some(davhaven_domain::Uid::parse("invitation-1").unwrap()),
        summary: Some("Planning".to_owned()),
        start: Some(
            serde_json::from_value(json!({"date_time": "2027-03-03T10:00:00", "time_zone": "Europe/Berlin"})).unwrap(),
        ),
        end: Some(
            serde_json::from_value(json!({"date_time": "2027-03-03T11:00:00", "time_zone": "Europe/Berlin"})).unwrap(),
        ),
        ..EventData::default()
    };
    data.attendees = Some(vec![EventAttendee {
        address: CalendarUserAddress::parse("mailto:anna@acme.example").unwrap(),
        common_name: None,
        partstat: Some(PartStat::Tentative),
        role: None,
        cutype: None,
        rsvp: Some(true),
        schedule_agent: None,
    }]);
    EventView {
        id: Some(ObjectId::from_uuid(Uuid::from_u128(42))),
        calendar_id: Some(calendar),
        etag: Some(davhaven_domain::ETag::from_bytes(b"invitation")),
        data,
        ..EventView::default()
    }
}

#[tokio::test]
async fn the_lifecycle_of_a_client_runs_through() {
    let setup = Setup::standard();
    let client = setup.anna();
    // 1. initialize, and the notification that completes the handshake.
    let handshake = client
        .raw(
            "POST",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ],
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": "init-1", "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"roots": {}, "sampling": {}},
                    "clientInfo": {"name": "independent-client", "title": "Independent client", "version": "9.9"},
                },
            }))
            .unwrap(),
        )
        .await;
    assert_eq!(handshake.header("content-type"), "application/json");
    let answer = handshake.json();
    assert_eq!(answer["id"], "init-1", "a string id is echoed as a string");
    assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");
    assert!(answer["result"]["serverInfo"]["name"].is_string());
    assert!(answer["result"]["capabilities"]["tools"].is_object());
    let initialized = client
        .raw(
            "POST",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("mcp-protocol-version", "2025-06-18"),
            ],
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).unwrap(),
        )
        .await;
    assert_eq!(initialized.status, 202);
    assert_eq!(initialized.body, Vec::<u8>::new());
    // 2. ping, then the tools.
    assert_eq!(client.rpc("ping", json!({})).await["result"], json!({}));
    assert_eq!(listed(&client).await.len(), 10);
}

#[tokio::test]
async fn every_response_has_the_shape_json_rpc_prescribes() {
    let setup = Setup::standard();
    let client = setup.anna();
    for (id, method) in [
        (json!(0), "ping"),
        (json!("a-string"), "tools/list"),
        (json!(9_007_199_254_740_991_u64), "ping"),
    ] {
        let reply = client
            .post(&json!({"jsonrpc": "2.0", "id": id, "method": method}))
            .await;
        let response = reply.json();
        let mut keys: Vec<&str> = response.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["id", "jsonrpc", "result"], "{response}");
        assert_eq!(response["id"], id);
        assert_eq!(response["jsonrpc"], "2.0");
    }
    let error = client.rpc("no/such/method", json!({})).await;
    let mut keys: Vec<&str> = error.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["error", "id", "jsonrpc"], "{error}");
    assert!(error["error"]["code"].is_i64() && error["error"]["message"].is_string());
}

#[tokio::test]
async fn the_catalog_is_the_committed_contract() {
    let setup = Setup::standard();
    let served = listed(&setup.anna()).await;
    let committed = committed_catalog();
    let contract = committed["tools"].as_array().unwrap();
    assert_eq!(served.len(), contract.len());
    assert_eq!(committed["protocol_revision"], "2025-06-18");
    for (served, contract) in served.iter().zip(contract) {
        let name = contract["name"].as_str().unwrap();
        assert_eq!(served["name"], contract["name"]);
        for member in ["title", "description", "inputSchema", "outputSchema", "annotations"] {
            assert_eq!(
                served[member], contract[member],
                "{name}: {member} differs from docs/contracts/mcp-tools.json"
            );
        }
        assert_eq!(
            served["_meta"][REQUIRED_SCOPE_META_KEY], contract["x-required-scope"],
            "{name}"
        );
        assert_eq!(
            served["_meta"], contract["_meta"],
            "{name}: the vendor members of a tool are part of the committed contract"
        );
    }
}

#[tokio::test]
async fn the_vendor_members_of_the_handshake_are_the_committed_contract() {
    let setup = Setup::standard();
    let handshake = setup
        .anna()
        .rpc(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "meta", "version": "1"}}),
        )
        .await;
    assert_eq!(
        handshake["result"]["_meta"],
        committed_catalog()["initialize_meta"],
        "the `_meta` of the initialize result is in docs/contracts/mcp-tools.json"
    );
}

#[tokio::test]
async fn annotations_say_what_the_plan_says() {
    let setup = Setup::standard();
    let tools = listed(&setup.anna()).await;
    for read in [
        "list_calendars",
        "list_events",
        "get_event",
        "search_events",
        "free_busy",
        "find_free_slots",
    ] {
        let hints = &tool(&tools, read)["annotations"];
        assert_eq!(hints["readOnlyHint"], true, "{read}");
        assert_eq!(hints["idempotentHint"], true, "{read}");
        assert_eq!(hints["destructiveHint"], false, "{read}");
        assert_eq!(
            hints["openWorldHint"], false,
            "{read}: the tools only reach the calendars of the server"
        );
    }
    assert_eq!(tool(&tools, "delete_event")["annotations"]["destructiveHint"], true);
    for write in ["create_event", "update_event", "respond_to_invitation"] {
        let hints = &tool(&tools, write)["annotations"];
        assert_eq!(hints["readOnlyHint"], false, "{write}");
        assert_eq!(hints["destructiveHint"], false, "{write}");
    }
    for idempotent in ["update_event", "respond_to_invitation"] {
        assert_eq!(
            tool(&tools, idempotent)["annotations"]["idempotentHint"],
            true,
            "{idempotent}"
        );
    }
    assert_eq!(tool(&tools, "create_event")["annotations"]["idempotentHint"], false);
    assert_eq!(tool(&tools, "delete_event")["annotations"]["idempotentHint"], false);
    for tool in &tools {
        assert_eq!(tool["inputSchema"]["type"], "object", "{}", tool["name"]);
        assert_eq!(tool["outputSchema"]["type"], "object", "{}", tool["name"]);
    }
}

#[tokio::test]
async fn the_reading_tools_answer_with_structured_content_that_satisfies_their_output_schema() {
    let setup = Setup::standard();
    let client = setup.anna();
    let tools = listed(&client).await;
    let work = calendar_named(&client, "Work").await;
    let range = json!({"start": "2027-03-01T00:00:00Z", "end": "2027-03-08T00:00:00Z"});

    call_conforming(&client, &tools, "list_calendars", json!({})).await;
    let listing = call_conforming(
        &client,
        &tools,
        "list_events",
        json!({"calendar_id": work, "start": range["start"], "end": range["end"], "include_attendees": true, "limit": 10}),
    )
    .await;
    let standup = listing["events"][0]["event_id"].clone();
    call_conforming(
        &client,
        &tools,
        "get_event",
        json!({"calendar_id": work, "event_id": standup}),
    )
    .await;
    call_conforming(
        &client,
        &tools,
        "search_events",
        json!({"query": "stand", "start": range["start"], "end": range["end"]}),
    )
    .await;

    setup
        .scheduling
        .answer_free_busy(FreeBusyResult {
            range: TimeRange::new(Some(at("2027-03-01T00:00:00Z")), Some(at("2027-03-02T00:00:00Z"))),
            entries: vec![FreeBusyEntry {
                address: Some(CalendarUserAddress::parse("mailto:ben@acme.example").unwrap()),
                known: true,
                periods: vec![BusyPeriod {
                    start: at("2027-03-01T09:00:00Z"),
                    end: at("2027-03-01T10:00:00Z"),
                    kind: BusyKind::BusyUnavailable,
                }],
            }],
            generated_at: at("2027-03-01T00:00:00Z"),
        })
        .await;
    call_conforming(
        &client,
        &tools,
        "free_busy",
        json!({"addresses": ["ben@acme.example"], "start": "2027-03-01T00:00:00Z", "end": "2027-03-02T00:00:00Z"}),
    )
    .await;
    setup
        .scheduling
        .answer_slots(FindSlotsResult {
            slots: vec![Slot {
                start: at("2027-03-02T09:00:00Z"),
                end: at("2027-03-02T09:30:00Z"),
            }],
            truncated: false,
        })
        .await;
    call_conforming(
        &client,
        &tools,
        "find_free_slots",
        json!({
            "addresses": ["ben@acme.example"], "start": "2027-03-02T00:00:00Z", "end": "2027-03-03T00:00:00Z",
            "duration_minutes": 30, "working_hours": {"start": "09:00:00", "end": "17:00:00"}, "time_zone": "Europe/Berlin",
        }),
    )
    .await;
}

#[tokio::test]
async fn the_writing_tools_answer_with_structured_content_that_satisfies_their_output_schema() {
    let setup = Setup::standard();
    let client = setup.anna();
    let tools = listed(&client).await;
    let work = calendar_named(&client, "Work").await;

    let created = call_conforming(
        &client,
        &tools,
        "create_event",
        json!({
            "calendar_id": work, "client_request_id": "conformance-1", "notify_attendees": false,
            "event": {
                "summary": "Conformance lunch", "start": {"date_time": "2027-03-02T12:00:00", "time_zone": "Europe/Berlin"},
                "duration": "PT1H", "categories": ["test"],
            },
        }),
    )
    .await;
    let event_id = created["event"]["event_id"].clone();
    let updated = call_conforming(
        &client,
        &tools,
        "update_event",
        json!({"calendar_id": work, "event_id": event_id, "if_match": created["event"]["etag"], "changes": {"location": "Garden"}}),
    )
    .await;
    assert_eq!(updated["event"]["untrusted_text"]["location"], "Garden");

    setup.scheduling.answer_respond(invitation(work)).await;
    let answered = call_conforming(
        &client,
        &tools,
        "respond_to_invitation",
        json!({"calendar_id": work, "event_id": event_id, "partstat": "accepted", "comment": "See you there"}),
    )
    .await;
    assert_eq!(
        answered["event"]["my_partstat"], "tentative",
        "what the service returned is shown"
    );

    let deleted = call_conforming(
        &client,
        &tools,
        "delete_event",
        json!({"calendar_id": work, "event_id": event_id}),
    )
    .await;
    assert_eq!(deleted, json!({"deleted": true}));
}

#[tokio::test]
async fn every_failure_is_a_tool_result_with_an_rfc_9457_problem() {
    let setup = Setup::standard();
    let client = setup.anna();
    let calls = [
        (
            "get_event",
            json!({"calendar_id": "018f3c1e-7b2a-7c3d-9e4f-000000000001", "event_id": "018f3c1e-7b2a-7c3d-9e4f-000000000002"}),
            "not-found",
            404,
        ),
        (
            "list_events",
            json!({"start": "2027-03-01T00:00:00Z", "end": "2028-03-01T00:00:00Z"}),
            "validation-failed",
            422,
        ),
        (
            "create_event",
            json!({"calendar_id": "018f3c1e-7b2a-7c3d-9e4f-000000000001"}),
            "validation-failed",
            422,
        ),
        (
            "free_busy",
            json!({"addresses": ["ben@acme.example"], "start": "2027-03-01T00:00:00Z", "end": "2027-03-02T00:00:00Z"}),
            "not-implemented",
            501,
        ),
    ];
    for (name, arguments, code, status) in calls {
        let result = client.call(name, arguments).await;
        assert_eq!(result["isError"], true, "{name}: {result}");
        assert_eq!(result["content"][0]["type"], "text");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        assert!(
            result.get("structuredContent").is_none(),
            "{name}: a failure has no structured content, which would have to satisfy the output schema: {result}"
        );
        let problem = &result["_meta"][PROBLEM_META_KEY];
        assert_eq!(problem["code"], code, "{name}");
        assert_eq!(problem["type"], format!("urn:davhaven:problem:{code}"));
        assert!(problem["title"].is_string(), "{problem}");
        assert_eq!(
            problem["status"], status,
            "{name}: the status the management API would answer"
        );
        assert!(problem["request_id"].is_string());
        assert_eq!(
            result["_meta"]["davhaven/retryable"], false,
            "{name}: none of these succeeds when repeated"
        );
    }
}

#[tokio::test]
async fn the_catalog_and_the_handshake_have_snapshots() {
    let setup = Setup::standard();
    let client = setup.anna();
    let handshake = client
        .rpc(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "snapshot", "version": "1"}}),
        )
        .await;
    let mut announced = handshake["result"].clone();
    announced["serverInfo"]["version"] = json!("[version]");
    insta::assert_json_snapshot!("initialize_result", announced);

    let tools = listed(&client).await;
    let catalog: Vec<Value> = tools
        .iter()
        .map(|tool| {
            let properties = |schema: &Value| -> Value {
                let required: Vec<&str> = schema["required"]
                    .as_array()
                    .map(|names| names.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let members: serde_json::Map<String, Value> = schema["properties"]
                    .as_object()
                    .map(|members| {
                        members
                            .keys()
                            .map(|name| {
                                (
                                    name.clone(),
                                    json!(if required.contains(&name.as_str()) {
                                        "required"
                                    } else {
                                        "optional"
                                    }),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Value::Object(members)
            };
            json!({
                "name": tool["name"],
                "title": tool["title"],
                "scope": tool["_meta"][REQUIRED_SCOPE_META_KEY],
                "annotations": tool["annotations"],
                "input": properties(&tool["inputSchema"]),
                "output": properties(&tool["outputSchema"]),
            })
        })
        .collect();
    insta::assert_json_snapshot!("tool_catalog", catalog);
}
