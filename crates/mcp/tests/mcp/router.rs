//! The mounting of the endpoint: who gets in, which methods and bodies are accepted, and what a failure looks like.

use axum::http::StatusCode;
use davhaven_app_fake::seed::{ADMIN_TOKEN, ANNA_TOKEN, SYSTEM_TOKEN};
use davhaven_mcp::config::McpConfig;
use serde_json::{Value, json};

use super::support::{BEN_TOKEN, Client, EVENTS_ONLY_TOKEN, READ_TOKEN, Setup, WRITE_TOKEN};

/// A message every authenticated principal may send.
fn ping() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
}

#[tokio::test]
async fn requests_need_a_bearer_token_and_are_challenged_otherwise() {
    let setup = Setup::standard();
    let anonymous = Client::anonymous(setup.app.clone()).post(&ping()).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.header("www-authenticate"), "Bearer realm=\"davhaven\"");
    assert_eq!(anonymous.header("content-type"), "application/problem+json");
    assert_eq!(anonymous.problem(), "unauthenticated");
    assert_ne!(anonymous.header("x-request-id"), "");

    let wrong = setup.client("dvh_pat_nobody_nothing").post(&ping()).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let without_request_id = |reply: &super::support::Reply| {
        let mut json = reply.json();
        json.as_object_mut().unwrap().remove("request_id");
        json
    };
    assert_eq!(
        without_request_id(&wrong),
        without_request_id(&anonymous),
        "every refusal looks the same"
    );

    // A credential that is valid, but for another surface: anna's app password (`ANNA_PASSWORD` of the seed, which works
    // on DAV) as a Basic login and as a bearer token. Credentials are bound to their surface (R6).
    let valid_basic = format!(
        "Basic {}",
        // `anna@acme.example:anna-secret-pass`
        "YW5uYUBhY21lLmV4YW1wbGU6YW5uYS1zZWNyZXQtcGFzcw=="
    );
    let valid_bearer = format!("Bearer {}", davhaven_app_fake::seed::ANNA_PASSWORD);
    for (what, header) in [("as Basic", valid_basic), ("as Bearer", valid_bearer)] {
        let refused = Client::anonymous(setup.app.clone())
            .raw(
                "POST",
                &[
                    ("authorization", header.as_str()),
                    ("content-type", "application/json"),
                    ("accept", "application/json, text/event-stream"),
                ],
                serde_json::to_vec(&ping()).unwrap(),
            )
            .await;
        assert_eq!(
            refused.status,
            StatusCode::UNAUTHORIZED,
            "a valid app password {what} is not an MCP credential"
        );
        assert_eq!(
            refused.header("www-authenticate"),
            "Bearer realm=\"davhaven\"",
            "{what}"
        );
        assert_eq!(refused.problem(), "unauthenticated", "{what}");
    }
}

#[tokio::test]
async fn every_authenticated_token_may_speak_and_what_it_may_do_is_judged_per_call() {
    // The tokens of people, a tenant administrator, a system token and a token issued for something else all get
    // answers; what each of them is offered and may call is the business of the handler (see `tools.rs`).
    let setup = Setup::standard();
    for token in [
        ANNA_TOKEN,
        READ_TOKEN,
        WRITE_TOKEN,
        BEN_TOKEN,
        ADMIN_TOKEN,
        SYSTEM_TOKEN,
        EVENTS_ONLY_TOKEN,
    ] {
        let reply = setup.client(token).post(&ping()).await;
        assert_eq!(reply.status, StatusCode::OK, "{token}");
    }
}

#[tokio::test]
async fn a_stateless_server_has_no_stream_and_no_sessions() {
    let setup = Setup::standard();
    let client = setup.anna();
    for method in ["GET", "DELETE", "PUT", "PATCH"] {
        let answer = client.raw(method, &[], Vec::new()).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(answer.header("allow"), "POST", "{method}");
        assert_eq!(answer.problem(), "method-not-allowed");
    }
}

#[tokio::test]
async fn a_session_id_is_never_a_credential() {
    let setup = Setup::standard();
    let headers = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-session-id", "a-session-the-server-never-made"),
    ];
    let body = serde_json::to_vec(&ping()).unwrap();
    let without_token = Client::anonymous(setup.app.clone())
        .raw("POST", &headers, body.clone())
        .await;
    assert_eq!(without_token.status, StatusCode::UNAUTHORIZED);
    // With a token the session id changes nothing: there are no sessions to find.
    let with_token = setup.anna().raw("POST", &headers, body).await;
    assert_eq!(with_token.status, StatusCode::OK);
    assert!(
        with_token.headers.get("mcp-session-id").is_none(),
        "the server issues no sessions"
    );
}

#[tokio::test]
async fn browsers_need_their_origin_on_the_list_and_the_host_header_does_not_help() {
    let setup = Setup::standard();
    let client = setup.anna();
    let cases = [
        (Some("https://assistant.example.org"), StatusCode::OK),
        (None, StatusCode::OK),
        (Some("https://evil.example"), StatusCode::FORBIDDEN),
        (Some("null"), StatusCode::FORBIDDEN),
        (Some("https://assistant.example.org:8443"), StatusCode::FORBIDDEN),
        (Some("http://assistant.example.org"), StatusCode::FORBIDDEN),
    ];
    for (origin, expected) in cases {
        let mut headers = vec![
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("host", "cal.example.org"),
        ];
        if let Some(origin) = origin {
            headers.push(("origin", origin));
        }
        let answer = client.raw("POST", &headers, serde_json::to_vec(&ping()).unwrap()).await;
        assert_eq!(answer.status, expected, "{origin:?}");
    }
    // DNS rebinding: the attacker's page and the request both name the attacker's host.
    let rebinding = client
        .raw(
            "POST",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("host", "rebind.evil.example"),
                ("origin", "https://rebind.evil.example"),
            ],
            serde_json::to_vec(&ping()).unwrap(),
        )
        .await;
    assert_eq!(rebinding.status, StatusCode::FORBIDDEN);
    assert_eq!(rebinding.problem(), "forbidden");
}

#[tokio::test]
async fn the_host_header_is_not_a_defense_here_and_never_a_reason_to_refuse() {
    let setup = Setup::standard();
    let client = setup.anna();
    for host in [
        None,
        Some("cal.example.org"),
        Some("localhost:8080"),
        Some("[::1]:3000"),
    ] {
        let mut headers = vec![
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ];
        if let Some(host) = host {
            headers.push(("host", host));
        }
        let answer = client.raw("POST", &headers, serde_json::to_vec(&ping()).unwrap()).await;
        assert_eq!(answer.status, StatusCode::OK, "{host:?}");
    }
}

#[tokio::test]
async fn the_origin_is_checked_before_the_credentials() {
    let setup = Setup::standard();
    let answer = Client::anonymous(setup.app.clone())
        .raw(
            "POST",
            &[("origin", "https://evil.example"), ("content-type", "application/json")],
            Vec::new(),
        )
        .await;
    assert_eq!(
        answer.status,
        StatusCode::FORBIDDEN,
        "a foreign page learns nothing about the token"
    );
    assert_eq!(answer.problem(), "forbidden");
    assert_eq!(
        answer.header("www-authenticate"),
        "",
        "no challenge invites a foreign page to try credentials"
    );
}

#[tokio::test]
async fn repeated_origin_headers_are_refused() {
    let setup = Setup::standard();
    let answer = setup
        .anna()
        .raw(
            "POST",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("origin", "https://assistant.example.org"),
                ("origin", "https://assistant.example.org"),
            ],
            serde_json::to_vec(&ping()).unwrap(),
        )
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_disabled_endpoint_serves_nothing() {
    let setup = Setup::with_config(&McpConfig {
        enabled: false,
        ..McpConfig::default()
    });
    let answer = setup.anna().post(&ping()).await;
    assert_eq!(
        (answer.status, answer.problem().as_str()),
        (StatusCode::NOT_FOUND, "not-found")
    );
}

#[tokio::test]
async fn other_paths_are_404_problems() {
    let setup = Setup::standard();
    let client = setup.anna();
    for path in ["/mcp/x", "/", "/api/v1/tenants"] {
        let answer = client.request(path, "POST", &[], Vec::new()).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(answer.problem(), "not-found");
    }
}

#[tokio::test]
async fn a_body_that_is_no_json_rpc_message_gets_the_json_rpc_fault() {
    let setup = Setup::standard();
    let client = setup.anna();
    let headers = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
    ];
    let cases: [(&str, i64); 6] = [
        ("", -32700),
        ("not json", -32700),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,", -32700),
        ("[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]", -32600),
        ("{}", -32600),
        ("{\"jsonrpc\":\"2.0\",\"id\":9}", -32600),
    ];
    for (body, code) in cases {
        let answer = client.raw("POST", &headers, body.as_bytes().to_vec()).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body:?}");
        assert_eq!(answer.header("content-type"), "application/json");
        let json = answer.json();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["error"]["code"], code, "{body:?}");
    }
    let echoed = client
        .raw("POST", &headers, br#"{"jsonrpc":"2.0","id":9}"#.to_vec())
        .await
        .json();
    assert_eq!(echoed["id"], 9, "the id of the bad request is echoed");
}

#[tokio::test]
async fn bodies_above_the_ceiling_are_refused_before_they_are_read() {
    let setup = Setup::standard();
    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"pad\":\"{}\"}}}}",
        "x".repeat(1_100_000)
    );
    let answer = setup
        .anna()
        .raw(
            "POST",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ],
            huge.into_bytes(),
        )
        .await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(answer.problem(), "payload-too-large");
}

#[tokio::test]
async fn the_transport_insists_on_the_headers_of_the_specification() {
    let setup = Setup::standard();
    let client = setup.anna();
    let body = serde_json::to_vec(&ping()).unwrap();
    // A client of the specification accepts both JSON and an event stream. Which 4xx the transport answers is its own
    // choice; that the answer is a problem document of the edge, and no text of the transport, is the contract.
    for accept in [None, Some("application/json"), Some("text/event-stream")] {
        let mut headers = vec![("content-type", "application/json")];
        if let Some(accept) = accept {
            headers.push(("accept", accept));
        }
        let refused = client.raw("POST", &headers, body.clone()).await;
        assert!(
            [StatusCode::BAD_REQUEST, StatusCode::NOT_ACCEPTABLE].contains(&refused.status),
            "{accept:?}: {}",
            refused.status
        );
        assert_eq!(refused.header("content-type"), "application/problem+json", "{accept:?}");
        assert!(!refused.problem().is_empty(), "{accept:?}");
    }
    let form = client
        .raw(
            "POST",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("accept", "application/json, text/event-stream"),
            ],
            body,
        )
        .await;
    assert_eq!(form.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(form.problem(), "unsupported-media-type");
}

#[tokio::test]
async fn notifications_are_accepted_without_an_answer() {
    let setup = Setup::standard();
    let answer = setup
        .anna()
        .post(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    assert_eq!(answer.status, StatusCode::ACCEPTED);
    assert_eq!(answer.body, Vec::<u8>::new());
}
