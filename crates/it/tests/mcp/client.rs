//! An independent MCP client over a socket: the `rmcp` client library, written by somebody else, against the server.
//!
//! The JSON-RPC client of `crates/mcp/tests/mcp` knows the specification and shares no code with the server; this one is a
//! real client implementation: it performs the handshake the way assistants do, lists the tools, calls them with arguments
//! as JSON objects and reads the results, over a TCP connection to `axum::serve` with the router of `davhaven-mcp` over
//! the real services. A server that this client cannot use does not conform, whatever its own tests say. (`xtask arch-check`
//! keeps the `rmcp` client out of `davhaven-mcp` itself and allows it here.)

use davhaven_testkit::axum;
use davhaven_testkit::davhaven_domain::{CalendarKind, Scope};
use rmcp::ServiceExt as _;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Value, json};

use super::support::World;

/// The arguments of a call as the JSON object the protocol carries.
fn arguments(value: &Value) -> serde_json::Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[tokio::test]
async fn an_independent_client_can_use_the_server() {
    // The HTTP client library insists on a TLS provider being chosen, even for a plain connection.
    davhaven_testkit::davhaven_server::install_crypto_provider();
    let world = World::new();
    let org = world.org("acme", true).await;
    let anna = world.user(&org, "anna").await;
    let work = world.calendar(&org, &anna, "work", CalendarKind::User).await;
    let token = world.token(&org, &anna, &[Scope::McpRead, Scope::McpWrite]).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = world.router.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // The server is stateless: the client must not insist on a session.
    let mut config = StreamableHttpClientTransportConfig::with_uri(format!("http://{address}/mcp")).auth_header(token);
    config.allow_stateless = true;
    let client = ().serve(StreamableHttpClientTransport::from_config(config)).await.unwrap();

    // The handshake: who the server is and what it offers.
    let info = client
        .peer_info()
        .expect("the handshake produced the server information");
    assert_eq!(
        info.server_info.as_ref().map(|server| server.name.as_str()),
        Some("davhaven")
    );
    assert!(info.capabilities.tools.is_some(), "a tool server");
    assert_eq!(info.protocol_version.as_str(), "2025-06-18");

    // The catalog: ten tools, each with an input and an output schema, the destructive one flagged.
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(
        names,
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
    for tool in &tools {
        assert!(tool.output_schema.is_some(), "{}", tool.name);
        assert_eq!(tool.input_schema["type"], "object", "{}", tool.name);
    }
    let delete = tools.iter().find(|tool| tool.name == "delete_event").unwrap();
    assert_eq!(
        delete.annotations.as_ref().and_then(|hints| hints.destructive_hint),
        Some(true)
    );

    // A call that succeeds: structured content, and the same JSON as text for clients that read only text.
    let created = client
        .call_tool(
            CallToolRequestParams::new("create_event").with_arguments(arguments(&json!({
                "calendar_id": work.id, "client_request_id": "client-1",
                "event": {"summary": "Lunch", "start": {"date_time": "2027-03-02T12:00:00Z"}, "duration": "PT1H"},
            }))),
        )
        .await
        .unwrap();
    assert_eq!(created.is_error, Some(false));
    let structured = created.structured_content.clone().expect("structured content");
    assert_eq!(structured["created"], true);
    let block = serde_json::to_value(created.content.first().expect("a content block")).unwrap();
    assert_eq!(block["type"], "text");
    assert_eq!(
        serde_json::from_str::<Value>(block["text"].as_str().unwrap()).unwrap(),
        structured
    );

    // A call that fails: a result with `isError`, the problem in `_meta`, and no structured content to mis-validate.
    let failed = client
        .call_tool(
            CallToolRequestParams::new("get_event").with_arguments(arguments(&json!({
                "calendar_id": work.id, "event_id": "018f3c1e-7b2a-7c3d-9e4f-0000000000aa",
            }))),
        )
        .await
        .unwrap();
    assert_eq!(failed.is_error, Some(true));
    assert!(failed.structured_content.is_none());
    let problem = &failed.meta.as_ref().expect("the problem is in _meta").0["davhaven/problem"];
    assert_eq!(problem["code"], "not-found");

    client.cancel().await.unwrap();
    server.abort();
}
