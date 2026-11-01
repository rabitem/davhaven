//! The protocol: the handshake and version negotiation, `ping`, notifications, the tool list per token, and the
//! JSON-RPC errors that protocol faults (and only those) produce.

use axum::http::StatusCode;
use davhaven_mcp::server::INSTRUCTIONS;
use davhaven_wire::mcp::{PROBLEM_META_KEY, REQUIRED_SCOPE_META_KEY, TOOLS_VERSION, TOOLS_VERSION_META_KEY};
use serde_json::{Value, json};

use super::support::{BEN_TOKEN, READ_TOKEN, Setup, WRITE_TOKEN};

fn initialize(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}
    })
}

fn names(result: &Value) -> Vec<&str> {
    result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn the_handshake_announces_a_tool_server_and_its_catalog_version() {
    let setup = Setup::standard();
    let response = setup
        .anna()
        .rpc("initialize", initialize("2025-06-18")["params"].clone())
        .await;
    let result = &response["result"];
    assert_eq!(result["protocolVersion"], "2025-06-18");
    assert_eq!(result["serverInfo"]["name"], "davhaven");
    assert_eq!(result["serverInfo"]["title"], "Davhaven calendar server");
    assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(result["instructions"], INSTRUCTIONS);
    assert_eq!(result["_meta"][TOOLS_VERSION_META_KEY], TOOLS_VERSION);
    let capabilities = result["capabilities"].as_object().unwrap();
    assert_eq!(
        capabilities.keys().collect::<Vec<_>>(),
        vec!["tools"],
        "a tool server offers tools and nothing else"
    );
    assert_ne!(
        capabilities["tools"].get("listChanged").and_then(Value::as_bool),
        Some(true),
        "the catalog does not change while the server runs"
    );
    assert!(
        result.get("resultType").is_none(),
        "the revision of the client has no result types"
    );
}

#[tokio::test]
async fn only_the_implemented_revision_is_offered_and_every_other_request_is_answered_with_it() {
    // 2024-11-05 is the HTTP+SSE transport, which this endpoint does not serve, and 2025-03-26 asks servers to receive
    // JSON-RPC batches, which this server refuses: neither is offered. The client decides whether to continue.
    let setup = Setup::standard();
    let client = setup.anna();
    let cases = [
        ("2024-11-05", "2025-06-18"),
        ("2025-03-26", "2025-06-18"),
        ("2025-06-18", "2025-06-18"),
        ("2025-11-25", "2025-06-18"),
        ("2026-07-28", "2025-06-18"),
        ("2099-01-01", "2025-06-18"),
        ("not-a-version", "2025-06-18"),
    ];
    for (asked, answered) in cases {
        // The header is optional on the handshake; a client that sends it names the version of its own request.
        let reply = client
            .raw(
                "POST",
                &[
                    ("content-type", "application/json"),
                    ("accept", "application/json, text/event-stream"),
                ],
                serde_json::to_vec(&initialize(asked)).unwrap(),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{asked}");
        assert_eq!(reply.json()["result"]["protocolVersion"], answered, "{asked}");
    }
}

#[tokio::test]
async fn ping_is_answered_with_an_empty_result() {
    let setup = Setup::standard();
    let response = setup.anna().rpc("ping", json!({})).await;
    assert_eq!(response["result"], json!({}));
}

#[tokio::test]
async fn every_request_stands_alone() {
    // No handshake, no session: a client may start with `tools/list` (this is what the stateless transport is for).
    let setup = Setup::standard();
    let response = setup.anna().rpc("tools/list", json!({})).await;
    assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 10);
    // And the version header is optional: the transport assumes the first stateless revision without it.
    let reply = setup
        .anna()
        .raw(
            "POST",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ],
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"})).unwrap(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["id"], 5);
}

#[tokio::test]
async fn an_unknown_protocol_version_header_is_refused() {
    let setup = Setup::standard();
    let reply = setup
        .anna()
        .raw(
            "POST",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("mcp-protocol-version", "1999-01-01"),
            ],
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})).unwrap(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_tool_list_shows_the_tools_the_token_may_call() {
    let setup = Setup::standard();
    let everything = setup.anna().rpc("tools/list", json!({})).await["result"].clone();
    assert_eq!(
        names(&everything),
        vec![
            "list_calendars",
            "list_events",
            "get_event",
            "search_events",
            "free_busy",
            "find_free_slots",
            "create_event",
            "update_event",
            "delete_event",
            "respond_to_invitation",
        ]
    );
    assert!(everything.get("nextCursor").is_none(), "the catalog is one page");
    let read = setup.client(READ_TOKEN).rpc("tools/list", json!({})).await["result"].clone();
    assert_eq!(
        names(&read),
        vec![
            "list_calendars",
            "list_events",
            "get_event",
            "search_events",
            "free_busy",
            "find_free_slots"
        ]
    );
    let write = setup.client(WRITE_TOKEN).rpc("tools/list", json!({})).await["result"].clone();
    assert_eq!(
        names(&write),
        vec!["create_event", "update_event", "delete_event", "respond_to_invitation"]
    );
    for tool in everything["tools"].as_array().unwrap() {
        let scope = tool["_meta"][REQUIRED_SCOPE_META_KEY].as_str().unwrap();
        assert_eq!(
            scope,
            if tool["annotations"]["readOnlyHint"] == true {
                "mcp:read"
            } else {
                "mcp:write"
            },
            "{}",
            tool["name"]
        );
    }
}

#[tokio::test]
async fn protocol_faults_are_json_rpc_errors() {
    let setup = Setup::standard();
    let client = setup.client(BEN_TOKEN);
    let unknown_method = client.rpc("tools/run", json!({})).await;
    assert_eq!(unknown_method["error"]["code"], -32601);
    assert!(unknown_method.get("result").is_none());

    let unknown_tool = client
        .rpc("tools/call", json!({"name": "drop_database", "arguments": {}}))
        .await;
    assert_eq!(
        unknown_tool["error"]["code"], -32602,
        "an unknown tool is a fault of the request: {unknown_tool}"
    );

    for params in [
        json!({}),
        json!({"name": 7}),
        json!({"arguments": {}}),
        json!({"name": "get_event", "arguments": 5}),
    ] {
        let malformed = client.rpc("tools/call", params.clone()).await;
        assert_eq!(malformed["error"]["code"], -32602, "{params}: {malformed}");
    }
    // A method the server has, with parameters that are not the method's, is a fault of the parameters and not an
    // unknown method.
    let bad_handshake = client.rpc("initialize", json!({"protocolVersion": 7})).await;
    assert_eq!(bad_handshake["error"]["code"], -32602, "{bad_handshake}");
    // The catalog is one page: whatever cursor a client sends, it gets the whole list and no next cursor.
    let with_cursor = client.rpc("tools/list", json!({"cursor": "page-2"})).await;
    assert_eq!(with_cursor["result"]["tools"].as_array().unwrap().len(), 10);
    // Parameters that are no structured value make the message no valid request at all.
    let unstructured = client
        .post(&json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": "text"}))
        .await;
    assert_eq!(unstructured.status, StatusCode::BAD_REQUEST);
    assert_eq!(unstructured.json()["error"]["code"], -32600);
}

#[tokio::test]
async fn a_failed_call_is_a_result_and_not_a_protocol_error() {
    let setup = Setup::standard();
    let response = setup
        .anna()
        .rpc(
            "tools/call",
            json!({"name": "get_event", "arguments": {"nonsense": true}}),
        )
        .await;
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["_meta"][PROBLEM_META_KEY]["code"],
        "validation-failed"
    );
}

#[tokio::test]
async fn results_of_an_older_revision_carry_no_result_type() {
    let setup = Setup::standard();
    let result = setup.anna().call("list_calendars", json!({})).await;
    assert!(result.get("resultType").is_none(), "{result}");
    assert_eq!(result["isError"], false);
}
