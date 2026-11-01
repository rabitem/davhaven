//! The check in front of the protocol handler: that the body is a JSON-RPC message.
//!
//! The protocol implementation answers a body that is not valid JSON with `415` and a plain text, which says nothing
//! a JSON-RPC client can act on. [`checked_message`] reads the body (it is limited to `limits.api.max_json_body` by
//! the edge and here) and answers the faults JSON-RPC names: `-32700` for text that is not JSON and `-32600` for
//! JSON that is not a request, notification or response, in particular for batches, which MCP does not use since
//! revision `2025-06-18`.
//!
//! The body is parsed once as the message it should be; only a body that is none is parsed again, as plain JSON, to
//! tell which fault to answer and to echo its id. A body that cannot be read is `413` when it is beyond the limit and
//! `400` when the connection failed (a client that gave up is not a client that sent too much).
//!
//! Who may call which tool is not decided here: that is the handler's job per call ([`crate::server`]), where the
//! token's actor and scopes are judged the way the services judge them.

use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use davhaven_http::problem::{EdgeProblem, ProblemCode};
use http_body_util::{BodyExt as _, LengthLimitError, Limited};
use rmcp::model::ClientJsonRpcMessage;
use serde_json::{Value, json};

/// JSON-RPC: the text is not JSON.
const PARSE_ERROR: i32 = -32700;

/// JSON-RPC: the JSON is not a valid message.
const INVALID_REQUEST: i32 = -32600;

/// A JSON-RPC error response (HTTP 400 with the error object of the specification).
fn rpc_error(code: i32, message: &str, id: &Value) -> Response {
    let body = json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}});
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// Whether a body error is the one of a body longer than its limit. The limit of this function and the limit layer of
/// the edge both produce it, the second wrapped in the error type of the HTTP framework, so the chain of sources is
/// searched.
fn is_length_limit(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.is::<LengthLimitError>() {
            return true;
        }
        current = error.source();
    }
    false
}

/// Reads the body of a request and checks that it is one JSON-RPC message; hands the request back with the same
/// body for the protocol implementation, or answers the JSON-RPC fault.
///
/// # Errors
///
/// The response to send instead: `413` for a body beyond `limit` bytes, `400` for a body that could not be read, a
/// JSON-RPC error for text that is no JSON (`-32700`), for a batch and for JSON that is no message (`-32600`).
pub async fn checked_message(request: Request, limit: usize) -> Result<Request, Box<Response>> {
    let (parts, body) = request.into_parts();
    let bytes = match Limited::new(body, limit).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) if is_length_limit(&*error) => {
            return Err(Box::new(EdgeProblem::new(ProblemCode::PayloadTooLarge).into_response()));
        }
        Err(_) => return Err(Box::new(EdgeProblem::new(ProblemCode::BadRequest).into_response())),
    };
    // The common case: a message. One parse, and the bytes go on to the protocol implementation unchanged.
    if serde_json::from_slice::<ClientJsonRpcMessage>(&bytes).is_ok() {
        return Ok(Request::from_parts(parts, Body::from(bytes)));
    }
    // Not a message: which fault is it?
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return Err(Box::new(rpc_error(PARSE_ERROR, "Parse error", &Value::Null)));
    };
    if value.is_array() {
        return Err(Box::new(rpc_error(
            INVALID_REQUEST,
            "Invalid Request: batches are not supported",
            &Value::Null,
        )));
    }
    let id = value
        .get("id")
        .filter(|id| id.is_string() || id.is_number())
        .cloned()
        .unwrap_or(Value::Null);
    Err(Box::new(rpc_error(INVALID_REQUEST, "Invalid Request", &id)))
}

#[cfg(test)]
mod tests {
    use axum::http::Method;

    use super::*;

    fn post(body: &str) -> Request {
        Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("x-kept", "yes")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    async fn error_of(body: &str) -> (StatusCode, Value) {
        let response = *checked_message(post(body), 1024).await.unwrap_err();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn a_message_passes_with_its_body_and_headers_intact() {
        let text = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let request = checked_message(post(text), 1024).await.unwrap();
        assert_eq!(request.headers()["x-kept"], "yes");
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), text.as_bytes());
        for notification in [
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":"x","method":"unknown/method"}"#,
        ] {
            assert!(
                checked_message(post(notification), 1024).await.is_ok(),
                "{notification}"
            );
        }
    }

    #[tokio::test]
    async fn text_that_is_not_json_is_a_parse_error() {
        for body in ["", "not json", "{\"jsonrpc\":", "\u{feff}{}"] {
            let (status, json) = error_of(body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
            // The codes are the ones of the JSON-RPC 2.0 specification, not whatever the constants say.
            assert_eq!(json["error"]["code"], -32700);
            assert_eq!(json["id"], Value::Null);
            assert_eq!(json["jsonrpc"], "2.0");
        }
    }

    #[tokio::test]
    async fn batches_and_non_messages_are_invalid_requests() {
        let (status, json) = error_of(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], -32600);
        assert_eq!(json["id"], Value::Null, "a batch has no one id to echo");
        for body in ["1", "\"text\"", "null", "{}", r#"{"jsonrpc":"2.0"}"#] {
            let (_, json) = error_of(body).await;
            assert_eq!(json["error"]["code"], -32600, "{body}");
        }
        let (_, json) = error_of(r#"{"jsonrpc":"1.0","id":7}"#).await;
        assert_eq!(json["error"]["code"], -32600);
        assert_eq!(json["id"], 7, "the id of the bad request is echoed when there is one");
        let (_, json) = error_of(r#"{"jsonrpc":"1.0","id":"seven"}"#).await;
        assert_eq!(json["id"], "seven");
    }

    #[tokio::test]
    async fn only_a_string_or_number_is_echoed_as_the_id() {
        // JSON-RPC ids are strings, numbers or null; anything else in the member is not an id to repeat.
        for id in ["{\"a\":1}", "[1]", "true", "null"] {
            let (_, json) = error_of(&format!(r#"{{"jsonrpc":"1.0","id":{id}}}"#)).await;
            assert_eq!(json["error"]["code"], -32600, "{id}");
            assert_eq!(json["id"], Value::Null, "{id}");
        }
    }

    #[tokio::test]
    async fn a_body_of_exactly_the_limit_is_read_and_one_byte_more_is_not() {
        let message = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let limit = message.len();
        assert!(checked_message(post(message), limit).await.is_ok());
        let response = *checked_message(post(&format!("{message} ")), limit).await.unwrap_err();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_body_that_cannot_be_read_is_a_bad_request_and_not_a_payload_that_is_too_large() {
        let broken = futures::stream::once(async {
            Err::<bytes::Bytes, std::io::Error>(std::io::Error::other("connection reset"))
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::from_stream(broken))
            .unwrap();
        let response = *checked_message(request, 1024).await.unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem = response.extensions().get::<EdgeProblem>().unwrap();
        assert_eq!(problem.code(), ProblemCode::BadRequest);
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused_with_the_payload_problem() {
        let response = *checked_message(post(&format!("{{\"pad\":\"{}\"}}", "x".repeat(2000))), 1024)
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let problem = response.extensions().get::<EdgeProblem>().unwrap();
        assert_eq!(problem.code(), ProblemCode::PayloadTooLarge);
    }
}
