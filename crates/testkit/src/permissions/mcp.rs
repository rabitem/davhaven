//! The requests of the permission matrix on the MCP surface.
//!
//! MCP tools are called with JSON-RPC over `POST /mcp` with a principal token. A failed tool call is a tool result with
//! `isError: true` whose problem document (`not-found`, `forbidden`) is in `_meta["davhaven/problem"]`: a failure has no
//! `structuredContent`, because that would have to match the output schema of the tool (ADR-0014, which amends PLAN 2.12);
//! authentication failures are HTTP 401. The calendar and the event are addressed by their ids (`list_calendars` and the
//! application know them; the environment supplies them).
//!
//! The endpoint is part of the application: nothing in this module asks whether it is there. A tenant that has switched MCP
//! off, a route group that is not mounted or a lost token answer 404, and that shows as the failure of every case, which is
//! what it is. The only cases that are left out are those of a role that has no token that opens MCP: the in-process
//! application stores them, a deployed instance issues them to service principals through the management API and to users
//! only through `davhaven admin principal-token create` ([`crate::staging::PrincipalTokenIssuer`]), and a role without one is
//! reported as skipped (the cases that its credential alone decides are run anyway).

use serde_json::{Value, json};

use super::classify::Observed;
use super::{Addressing, Classifier, MatrixEnv, Plan, Probe, request};
use crate::handles::{Actor, MCP_PATH, mcp_message};
use crate::matrix::{Case, Expectation, Operation, Resolution, Surface};
use crate::transport::{TestRequest, TestResponse};

/// The window the listing and the free-busy tools look at: the month of the events of the world.
const FROM: &str = "2027-03-01T00:00:00Z";
const TO: &str = "2027-04-01T00:00:00Z";

/// Why the cases of a role that has no token that opens MCP are left out: the management API issues such a token to a service
/// principal and never to a user (a token mints tokens with a subset of its own scopes, and no tenant token carries the scopes
/// of MCP), so a deployed instance has one for a user only when the operator mints it (`davhaven admin principal-token create`),
/// and only for a tenant that has MCP switched on.
pub const NO_MCP_CREDENTIALS: &str = concat!(
    "this role has no token that opens MCP: the management API issues one to a service principal of a tenant that has MCP ",
    "switched on (`davhaven admin bootstrap --mcp-enabled`), and to a user only through `davhaven admin principal-token create` ",
    "(`--principal-token-command` of the runner)"
);

/// Why the allowed answer to an invitation is not performed: the fixture world has no event that invites somebody who may
/// write to its calendar.
pub const NO_INVITATION: &str = "the fixture world has no invitation to answer";

/// A `tools/call` request.
pub fn tool_call(actor: &Actor, id: usize, tool: &str, arguments: &Value) -> TestRequest {
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    });
    request(actor, "POST", MCP_PATH)
        .header("accept", "application/json, text/event-stream")
        .content("application/json", serde_json::to_vec(&envelope).unwrap_or_default())
}

/// The `code` of the problem of a failed tool result: the problem document is in `_meta["davhaven/problem"]`.
fn problem_code(result: &Value) -> Option<&str> {
    result
        .get("_meta")
        .and_then(|meta| meta.get("davhaven/problem"))
        .and_then(|problem| problem.get("code"))
        .and_then(Value::as_str)
}

fn problem_outcome(code: Option<&str>) -> Observed {
    match code {
        Some("not-found") => Observed::Is(Expectation::Hidden),
        Some("forbidden") => Observed::Is(Expectation::Forbidden),
        Some("unauthenticated") => Observed::Is(Expectation::Unauthenticated),
        Some("precondition-failed") => Observed::Is(Expectation::PreconditionFailed),
        Some(other) => Observed::Other(format!("the tool failed with the problem `{other}`")),
        None => Observed::Other("a failed tool result without a problem code".to_owned()),
    }
}

/// The JSON-RPC result of a `tools/call` answer, or the outcome that the HTTP status alone decides.
fn result_of(response: &TestResponse) -> Result<Value, Observed> {
    let status = response.status.as_u16();
    if status != 200 {
        return Err(match status {
            401 => Observed::Is(Expectation::Unauthenticated),
            403 => Observed::Is(Expectation::Forbidden),
            404 => Observed::Is(Expectation::Hidden),
            other => Observed::Other(format!("status {other}")),
        });
    }
    let message = mcp_message(response).map_err(|error| Observed::Other(error.to_string()))?;
    if let Some(error) = message.get("error") {
        return Err(Observed::Other(format!("a JSON-RPC error: {error}")));
    }
    message
        .get("result")
        .cloned()
        .ok_or_else(|| Observed::Other("an answer without a result".to_owned()))
}

/// What a failed tool result is: the outcome of the policy its problem code stands for. A failure that carries
/// `structuredContent` is not an outcome of the policy: the server has to leave it out (it would have to match the output
/// schema of the tool).
fn failure_of(result: &Value) -> Observed {
    if result.get("structuredContent").is_some() {
        return Observed::Other(
            "a failed tool result carries structuredContent, which it must not (it would violate the output schema of the tool)"
                .to_owned(),
        );
    }
    problem_outcome(problem_code(result))
}

fn is_failure(result: &Value) -> bool {
    result.get("isError").and_then(Value::as_bool) == Some(true)
}

/// Whether the answer is a tool that failed because the server was too busy to run it: a failed tool result whose problem is
/// `unavailable`, which is how MCP says 503 (the answer to the request is 200).
pub(crate) fn is_unavailable(response: &TestResponse) -> bool {
    const MARK: &[u8] = b"davhaven/problem";
    // Most answers are not tool results at all: look at the bytes before reading a message out of them.
    if !response.body.windows(MARK.len()).any(|window| window == MARK) {
        return false;
    }
    result_of(response).is_ok_and(|result| is_failure(&result) && problem_code(&result) == Some("unavailable"))
}

/// Reads the result of a tool call as an outcome of the policy.
pub fn classify_tool_result(response: &TestResponse) -> Observed {
    match result_of(response) {
        Err(observed) => observed,
        Ok(result) => {
            if is_failure(&result) {
                failure_of(&result)
            } else {
                Observed::Is(Expectation::Allow)
            }
        }
    }
}

/// Reads the result of a tool that takes the addresses of people of the caller's organisation: a validation failure about the
/// addresses is the answer (nothing is said about whether a person of another organisation exists).
pub fn classify_people_result(response: &TestResponse) -> Observed {
    if let Ok(result) = result_of(response)
        && is_failure(&result)
        && result.get("structuredContent").is_none()
        && problem_code(&result) == Some("validation-failed")
    {
        return Observed::Is(Expectation::Allow);
    }
    classify_tool_result(response)
}

/// Reads the result of a tool that lists something under `pointer`: allowed when an item whose `key` is `wanted` is there,
/// hidden when none is (a listing never fails for what is invisible).
fn classify_list(response: &TestResponse, pointer: &str, key: &str, wanted: &str) -> Observed {
    match result_of(response) {
        Err(observed) => observed,
        Ok(result) => {
            if is_failure(&result) {
                return failure_of(&result);
            }
            let listed = result.pointer(pointer).and_then(Value::as_array).is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.get(key).and_then(Value::as_str) == Some(wanted))
            });
            Observed::Is(if listed {
                Expectation::Allow
            } else {
                Expectation::Hidden
            })
        }
    }
}

/// Reads the result of `list_calendars`: allowed when the calendar is listed, hidden when it is not.
pub fn classify_listing(response: &TestResponse, calendar_id: &str) -> Observed {
    classify_list(response, "/structuredContent/calendars", "calendar_id", calendar_id)
}

/// Reads the result of `search_events` over every calendar: allowed when the event is among the results, hidden when it is
/// not.
pub fn classify_found(response: &TestResponse, event_id: &str) -> Observed {
    classify_list(response, "/structuredContent/events", "event_id", event_id)
}

/// An event as the tools take it.
fn event(summary: &str) -> Value {
    json!({
        "summary": summary,
        "start": {"date_time": "2027-06-01T09:00:00Z"},
        "end": {"date_time": "2027-06-01T10:00:00Z"}
    })
}

/// Plans a case on MCP.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per operation of the matrix, each a short list of requests"
)]
pub async fn plan(env: &dyn MatrixEnv, case: &Case, resolution: &Resolution, seq: usize) -> Plan {
    let at = Addressing::new(env.world());
    // What is decided before the protocol is reached (the credential) can be checked without a token that opens MCP.
    let decided_by_credential = resolution.expectation == Expectation::Unauthenticated;
    if !decided_by_credential && env.book().lacks_mcp_token(case.actor, case.token_scope.as_deref()) {
        return Plan::Skip(NO_MCP_CREDENTIALS.to_owned());
    }
    let Some(actor) = env.book().actor(case.actor, Surface::Mcp, case.token_scope.as_deref()) else {
        return Plan::Skip(format!(
            "the role `{}` has no credential on MCP{}",
            case.actor,
            case.token_scope
                .as_ref()
                .map_or_else(String::new, |scope| format!(" with the scope {scope}"))
        ));
    };
    let ids = match env.mcp_ids(case.calendar).await {
        Ok(ids) => ids,
        Err(error) => return Plan::Skip(format!("the ids of the calendar are unknown: {error}")),
    };
    let calendar = &ids.calendar_id;
    let id = &ids.event_id;
    let summary = at.event(case.calendar).summary.clone();
    let tool = |name: &str, arguments: &Value| tool_call(&actor, seq, name, arguments);
    let probes = match case.operation {
        Operation::ReadCollection => vec![
            Probe::new("list_calendars", tool("list_calendars", &json!({}))).read_as(Classifier::McpListed {
                calendar_id: calendar.clone(),
            }),
        ],
        Operation::ListObjects => vec![
            Probe::new(
                "list_events",
                tool(
                    "list_events",
                    &json!({"calendar_id": calendar, "start": FROM, "end": TO}),
                ),
            )
            .read_as(Classifier::McpTool)
            .showing(&[id.as_str()]),
            // The classic leak: a search over every calendar the caller can see finds events the caller must not see.
            Probe::new(
                "search_events over every calendar",
                tool(
                    "search_events",
                    &json!({"query": summary, "start": FROM, "end": TO, "limit": 200}),
                ),
            )
            .read_as(Classifier::McpFound { event_id: id.clone() }),
        ],
        Operation::ReadObject => vec![
            Probe::new(
                "get_event",
                tool("get_event", &json!({"calendar_id": calendar, "event_id": id})),
            )
            .read_as(Classifier::McpTool)
            .showing(&[id.as_str()]),
        ],
        Operation::FreeBusyQuery => {
            // The owner of the calendar when it is a person, otherwise (a group or a managed calendar) the person of the
            // world that owns a calendar of her own: `find_free_slots` only takes people of the organisation.
            let address = at
                .owner_address(case.calendar)
                .or_else(|| at.actor_address(davhaven_fixtures::ActorRole::Owner))
                .unwrap_or_else(|| "mailto:nobody@acme.example".to_owned());
            // Somebody of another tenant is answered, and the answer says that the address is not known here.
            let private = case.actor == davhaven_fixtures::ActorRole::OtherTenantUser;
            let free_busy = Probe::new(
                "free_busy",
                tool(
                    "free_busy",
                    &json!({"addresses": [address.clone()], "start": FROM, "end": TO}),
                ),
            )
            .read_as(Classifier::McpTool);
            let slots = Probe::new(
                "find_free_slots",
                tool(
                    "find_free_slots",
                    &json!({"addresses": [address], "start": FROM, "end": TO, "duration_minutes": 30}),
                ),
            )
            .read_as(Classifier::McpPeople);
            if private {
                vec![free_busy.without_busy_time(), slots]
            } else {
                vec![free_busy, slots]
            }
        }
        Operation::CreateObject => vec![
            Probe::new(
                "create_event",
                tool(
                    "create_event",
                    &json!({
                        "calendar_id": calendar,
                        "client_request_id": format!("mx-{seq}"),
                        "event": event("Created by the matrix"),
                        "notify_attendees": false
                    }),
                ),
            )
            .read_as(Classifier::McpTool),
        ],
        Operation::UpdateObject => vec![
            Probe::new(
                "update_event",
                tool(
                    "update_event",
                    &json!({
                        "calendar_id": calendar,
                        "event_id": id,
                        "scope": "all",
                        "changes": event("Changed by the matrix"),
                        "notify_attendees": false
                    }),
                ),
            )
            .read_as(Classifier::McpTool),
        ],
        Operation::DeleteObject => vec![
            Probe::new(
                "delete_event",
                tool(
                    "delete_event",
                    &json!({"calendar_id": calendar, "event_id": id, "scope": "all", "notify_attendees": false}),
                ),
            )
            .read_as(Classifier::McpTool),
        ],
        Operation::RespondToInvitation => {
            if resolution.expectation == Expectation::Allow {
                return Plan::Skip(NO_INVITATION.to_owned());
            }
            vec![
                Probe::new(
                    "respond_to_invitation",
                    tool(
                        "respond_to_invitation",
                        &json!({"calendar_id": calendar, "event_id": id, "partstat": "accepted"}),
                    ),
                )
                .read_as(Classifier::McpTool),
            ]
        }
        other => return Plan::NotApplicable(format!("{other} does not exist on MCP")),
    };
    Plan::Probes(probes)
}

#[cfg(test)]
mod tests {
    use davhaven_wire::mcp::{
        CreateEventInput, DeleteEventInput, FindFreeSlotsInput, FreeBusyInput, GetEventInput, ListEventsInput,
        RespondToInvitationInput, SearchEventsInput, UpdateEventInput,
    };

    use super::*;

    fn answer(result: &Value) -> TestResponse {
        TestResponse::new(
            200,
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "result": result})).unwrap(),
        )
        .with_header("content-type", "application/json")
    }

    /// A failure as the MCP server writes it: the problem document is in the metadata and there is no structured content.
    fn failure(code: &str) -> TestResponse {
        answer(&json!({
            "isError": true,
            "content": [{"type": "text", "text": "Resource not found"}],
            "_meta": {"davhaven/problem": {"code": code, "status": 404}}
        }))
    }

    #[test]
    fn the_problem_of_a_failed_result_is_read_from_the_metadata_only() {
        assert_eq!(
            classify_tool_result(&failure("not-found")),
            Observed::Is(Expectation::Hidden)
        );
        assert_eq!(
            classify_tool_result(&failure("forbidden")),
            Observed::Is(Expectation::Forbidden)
        );
        let listing = failure("not-found");
        assert_eq!(classify_listing(&listing, "c1"), Observed::Is(Expectation::Hidden));
        // The structured content of a failure would violate the output schema of the tool (ADR-0014): it is a finding, even
        // when a problem code is in it or next to it.
        let in_structured_content =
            answer(&json!({"isError": true, "structuredContent": {"code": "forbidden"}, "content": []}));
        assert!(matches!(
            classify_tool_result(&in_structured_content),
            Observed::Other(text) if text.contains("structuredContent")
        ));
        let both = answer(&json!({
            "isError": true,
            "structuredContent": {"code": "forbidden"},
            "_meta": {"davhaven/problem": {"code": "not-found"}}
        }));
        assert!(matches!(classify_tool_result(&both), Observed::Other(_)));
        assert!(matches!(
            classify_tool_result(&answer(&json!({"isError": true, "content": []}))),
            Observed::Other(text) if text.contains("without a problem code")
        ));
    }

    #[test]
    fn tool_results_map_to_the_outcomes_of_the_policy() {
        assert_eq!(
            classify_tool_result(&answer(&json!({"structuredContent": {}, "content": []}))),
            Observed::Is(Expectation::Allow)
        );
        assert_eq!(
            classify_tool_result(&failure("not-found")),
            Observed::Is(Expectation::Hidden)
        );
        assert!(matches!(classify_tool_result(&failure("conflict")), Observed::Other(_)));
        assert_eq!(
            classify_tool_result(&TestResponse::new(401, "")),
            Observed::Is(Expectation::Unauthenticated)
        );
        // A 404 and a 501 of the endpoint are what they are: the endpoint is not there. They are not "skipped".
        assert_eq!(
            classify_tool_result(&TestResponse::new(404, "")),
            Observed::Is(Expectation::Hidden)
        );
        assert!(matches!(
            classify_tool_result(&TestResponse::new(501, "")),
            Observed::Other(_)
        ));
        assert!(matches!(
            classify_tool_result(&TestResponse::new(
                200,
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"x"}}"#
            )),
            Observed::Other(_)
        ));
    }

    #[test]
    fn a_tool_for_people_of_the_organisation_answers_a_stranger_with_a_validation_failure_that_counts_as_allowed() {
        assert_eq!(
            classify_people_result(&failure("validation-failed")),
            Observed::Is(Expectation::Allow)
        );
        assert_eq!(
            classify_people_result(&answer(&json!({"structuredContent": {}, "content": []}))),
            Observed::Is(Expectation::Allow)
        );
        // Only that failure is excused: the others are what they are.
        assert_eq!(
            classify_people_result(&failure("not-found")),
            Observed::Is(Expectation::Hidden)
        );
        assert!(matches!(
            classify_people_result(&failure("conflict")),
            Observed::Other(_)
        ));
        // The same failure for the tool of somebody else's events is not an outcome of the policy.
        assert!(matches!(
            classify_tool_result(&failure("validation-failed")),
            Observed::Other(_)
        ));
    }

    #[test]
    fn a_listing_allows_the_calendars_it_names_and_hides_the_others() {
        let listing =
            answer(&json!({"structuredContent": {"calendars": [{"calendar_id": "c1"}, {"calendar_id": "c2"}]}}));
        assert_eq!(classify_listing(&listing, "c2"), Observed::Is(Expectation::Allow));
        assert_eq!(classify_listing(&listing, "c9"), Observed::Is(Expectation::Hidden));
        assert_eq!(
            classify_listing(&TestResponse::new(401, ""), "c1"),
            Observed::Is(Expectation::Unauthenticated)
        );
        let found = answer(&json!({"structuredContent": {"events": [{"event_id": "e1"}], "truncated": false}}));
        assert_eq!(classify_found(&found, "e1"), Observed::Is(Expectation::Allow));
        assert_eq!(classify_found(&found, "e2"), Observed::Is(Expectation::Hidden));
    }

    #[test]
    fn the_arguments_of_the_probes_are_the_inputs_of_the_tools() {
        let calendar = "018f3c1e-7b2a-7c3d-9e4f-000000000001";
        let object = "018f3c1e-7b2a-7c3d-9e4f-000000000002";
        serde_json::from_value::<ListEventsInput>(json!({"calendar_id": calendar, "start": FROM, "end": TO})).unwrap();
        serde_json::from_value::<SearchEventsInput>(
            json!({"query": "Personal event", "start": FROM, "end": TO, "limit": 200}),
        )
        .unwrap();
        serde_json::from_value::<GetEventInput>(json!({"calendar_id": calendar, "event_id": object})).unwrap();
        serde_json::from_value::<RespondToInvitationInput>(
            json!({"calendar_id": calendar, "event_id": object, "partstat": "accepted"}),
        )
        .unwrap();
        serde_json::from_value::<FreeBusyInput>(json!({"addresses": ["mailto:a@x.example"], "start": FROM, "end": TO}))
            .unwrap();
        serde_json::from_value::<FindFreeSlotsInput>(json!({
            "addresses": ["mailto:a@x.example"], "start": FROM, "end": TO, "duration_minutes": 30
        }))
        .unwrap();
        serde_json::from_value::<CreateEventInput>(json!({
            "calendar_id": calendar,
            "client_request_id": "mx-1",
            "event": event("A"),
            "notify_attendees": false
        }))
        .unwrap();
        serde_json::from_value::<UpdateEventInput>(json!({
            "calendar_id": calendar,
            "event_id": object,
            "scope": "all",
            "changes": event("B"),
            "notify_attendees": false
        }))
        .unwrap();
        serde_json::from_value::<DeleteEventInput>(json!({
            "calendar_id": calendar,
            "event_id": object,
            "scope": "all",
            "notify_attendees": false
        }))
        .unwrap();
    }

    #[test]
    fn a_tool_call_is_a_json_rpc_post() {
        let request = tool_call(&Actor::bearer("tok"), 7, "get_event", &json!({"a": 1}));
        assert_eq!(request.target, MCP_PATH);
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["name"], "get_event");
        assert_eq!(body["id"], 7);
        assert_eq!(request.headers["authorization"], "Bearer tok");
    }
}
