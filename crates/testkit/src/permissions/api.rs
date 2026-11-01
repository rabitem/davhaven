//! The requests of the permission matrix on the management API.
//!
//! The API addresses calendars by the natural keys of their owner and slug, and objects by their external key. The
//! credentials are API tokens: the principal token of a principal, a tenant token (with every tenant scope, or with
//! the one scope the case is about) or the system token.

use serde_json::{Value, json};

use super::{Addressing, Classifier, MatrixEnv, Plan, Probe, request};
use crate::busy;
use crate::handles::Actor;
use crate::matrix::{Case, Expectation, Operation, Resolution, Surface};
use crate::transport::TestRequest;

/// The `If-Match` of a version that nothing has.
const STALE_VERSION: &str = "\"v999999\"";
/// The `If-Match` (the content tag) of an event that nothing has: a well-formed tag (22 characters of base64url), because the
/// edge refuses a header that is no tag of the API with 412 before it asks who the caller is.
const STALE_CONTENT_TAG: &str = "\"AAAAAAAAAAAAAAAAAAAAAA\"";

const JSON: &str = "application/json";
const MERGE_PATCH: &str = "application/merge-patch+json";

fn with_json(request: TestRequest, content_type: &str, body: &Value) -> TestRequest {
    request
        .header("accept", JSON)
        .content(content_type, serde_json::to_vec(body).unwrap_or_default())
}

fn get(actor: &Actor, target: &str) -> TestRequest {
    request(actor, "GET", target).header("accept", JSON)
}

/// An event as the API takes it.
fn event(summary: &str) -> Value {
    json!({
        "summary": summary,
        "start": {"date_time": "2027-06-01T09:00:00Z"},
        "end": {"date_time": "2027-06-01T10:00:00Z"}
    })
}

/// The version of a calendar as its `ETag` shows it, read with the all-scopes tenant token. `If-Match` of a `DELETE`
/// needs the current one; the permission decision does not look at it.
async fn etag_of_calendar(env: &dyn MatrixEnv, path: &str) -> Option<String> {
    let admin = env
        .book()
        .actor(davhaven_fixtures::ActorRole::TenantToken, Surface::Api, None)?;
    let response = busy::send_repeatable(env.transport().as_ref(), &get(&admin, path))
        .await
        .0
        .ok()?;
    response.header("etag").map(str::to_owned)
}

/// The display name of a calendar as the API shows it, read with the all-scopes tenant token: a `PUT` that replaces a
/// calendar must carry the name it has to change only what it means to (renaming is another operation).
async fn display_name_of_calendar(env: &dyn MatrixEnv, path: &str, fallback: &str) -> String {
    let Some(admin) = env
        .book()
        .actor(davhaven_fixtures::ActorRole::TenantToken, Surface::Api, None)
    else {
        return fallback.to_owned();
    };
    let Ok(response) = busy::send_repeatable(env.transport().as_ref(), &get(&admin, path))
        .await
        .0
    else {
        return fallback.to_owned();
    };
    response
        .json::<Value>()
        .ok()
        .and_then(|view| view.get("display_name").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| fallback.to_owned())
}

/// Plans a case on the management API.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per operation of the matrix, each a short list of requests"
)]
pub async fn plan(env: &dyn MatrixEnv, case: &Case, resolution: &Resolution, seq: usize) -> Plan {
    let at = Addressing::new(env.world());
    let Some(actor) = env.book().actor(case.actor, Surface::Api, case.token_scope.as_deref()) else {
        return Plan::Skip(format!(
            "the role `{}` has no credential on the API{}",
            case.actor,
            case.token_scope
                .as_ref()
                .map_or_else(String::new, |scope| format!(" with the scope {scope}"))
        ));
    };
    let role = case.calendar;
    let calendar = at.api_calendar(role);
    let key = at.event(role).external_key.to_string();
    let by_key = format!("{calendar}/objects/by-key/{key}");
    let allowed = resolution.expectation == Expectation::Allow;

    let slug = at.slug(role);
    let summary = at.event(role).summary.clone();
    let probes = match case.operation {
        Operation::ReadCollection => vec![
            Probe::new("GET of the calendar", get(&actor, &calendar)).showing(&[&slug]),
            // The listing of the calendars of its owner leaves out what the caller cannot see.
            Probe::new(
                "GET of the calendars of the owner",
                get(&actor, &format!("{}/calendars", at.api_owner(role))),
            )
            .read_as(Classifier::ApiListed { slug: slug.clone() }),
        ],
        Operation::ListObjects => vec![
            Probe::new("GET of the objects", get(&actor, &format!("{calendar}/objects"))).showing(&[&summary]),
            Probe::new("GET of the changes", get(&actor, &format!("{calendar}/changes"))),
        ],
        Operation::ReadObject => vec![Probe::new("GET of the event by key", get(&actor, &by_key)).showing(&[&summary])],
        Operation::CreateObject => vec![Probe::new(
            "PUT of a new event by key",
            with_json(
                request(&actor, "PUT", &format!("{calendar}/objects/by-key/mx-{seq}")),
                JSON,
                &event("Created by the matrix"),
            ),
        )],
        Operation::UpdateObject => vec![
            // A condition that is false does not matter to somebody who may not write, and stops somebody who may.
            Probe::new(
                "PUT over the event by key with a stale If-Match",
                with_json(
                    request(&actor, "PUT", &by_key).header("if-match", STALE_CONTENT_TAG),
                    JSON,
                    &event("Changed by the matrix"),
                ),
            )
            .stale(),
            Probe::new(
                "PUT over the event by key",
                with_json(request(&actor, "PUT", &by_key), JSON, &event("Changed by the matrix")),
            ),
        ],
        Operation::DeleteObject => vec![
            Probe::new(
                "DELETE of the event by key with a stale If-Match",
                request(&actor, "DELETE", &by_key)
                    .header("accept", JSON)
                    .header("if-match", STALE_CONTENT_TAG),
            )
            .stale(),
            Probe::new(
                "DELETE of the event by key",
                request(&actor, "DELETE", &by_key).header("accept", JSON),
            ),
        ],
        Operation::BatchUpsert => vec![Probe::new(
            "POST of a batch",
            with_json(
                request(&actor, "POST", &format!("{calendar}/objects/batch"))
                    .header("idempotency-key", &format!("matrix-batch-{seq}")),
                JSON,
                &json!({"items": [{"external_key": format!("mx-batch-{seq}"), "event": event("Batch of the matrix")}]}),
            ),
        )],
        Operation::UpdateCalendar => {
            // `PUT` replaces the calendar: with the name it has, only the settings change (a new name is `rename_calendar`).
            let display_name = display_name_of_calendar(env, &calendar, &at.calendar(role).display_name).await;
            vec![
                Probe::new(
                    "PATCH of the description",
                    with_json(
                        request(&actor, "PATCH", &calendar),
                        MERGE_PATCH,
                        &json!({"description": "Changed by the matrix"}),
                    ),
                ),
                Probe::new(
                    "PUT over the calendar",
                    with_json(
                        request(&actor, "PUT", &calendar),
                        JSON,
                        &json!({"display_name": display_name, "description": "Replaced by the matrix"}),
                    ),
                ),
            ]
        }
        Operation::RenameCalendar => vec![Probe::new(
            "PATCH of the display name",
            with_json(
                request(&actor, "PATCH", &calendar),
                MERGE_PATCH,
                &json!({"display_name": "Renamed by the matrix"}),
            ),
        )],
        Operation::CreateCalendar => {
            let kind = match role {
                davhaven_fixtures::CalendarRole::Group => "group",
                davhaven_fixtures::CalendarRole::Managed => "managed",
                _ => "user",
            };
            vec![Probe::new(
                "PUT of a new calendar in the home of the owner",
                with_json(
                    request(&actor, "PUT", &format!("{}/calendars/mx-{seq}", at.api_owner(role))),
                    JSON,
                    &json!({"display_name": "Created by the matrix", "kind": kind}),
                ),
            )]
        }
        Operation::DeleteCalendar => {
            // The permission is decided before the condition: a caller who is refused is refused whatever the version, so the
            // refused ones send a version that nothing has.
            let etag = if allowed {
                etag_of_calendar(env, &calendar)
                    .await
                    .unwrap_or_else(|| "\"v1\"".to_owned())
            } else {
                STALE_VERSION.to_owned()
            };
            vec![Probe::new(
                "DELETE of the calendar",
                request(&actor, "DELETE", &calendar)
                    .header("accept", JSON)
                    .header("if-match", &etag),
            )]
        }
        Operation::ListGrants => vec![Probe::new(
            "GET of the grants",
            get(&actor, &format!("{calendar}/grants")),
        )],
        Operation::PutGrant => vec![Probe::new(
            "PUT of a grant",
            with_json(
                request(&actor, "PUT", &format!("{calendar}/grants/otto")),
                JSON,
                &json!({"access": "read"}),
            ),
        )],
        Operation::DeleteGrant => {
            let admin = env
                .book()
                .actor(davhaven_fixtures::ActorRole::TenantToken, Surface::Api, None);
            let mut probe = Probe::new(
                "DELETE of a grant",
                request(&actor, "DELETE", &format!("{calendar}/grants/otto")).header("accept", JSON),
            );
            if allowed && let Some(admin) = admin {
                // The grant that is deleted has to exist.
                probe = probe.after(with_json(
                    request(&admin, "PUT", &format!("{calendar}/grants/otto")),
                    JSON,
                    &json!({"access": "read"}),
                ));
            }
            vec![probe]
        }
        other => return Plan::NotApplicable(format!("{other} does not exist on the API")),
    };
    Plan::Probes(probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_the_json_the_api_takes() {
        let value = event("A");
        assert_eq!(value["summary"], "A");
        assert_eq!(value["start"]["date_time"], "2027-06-01T09:00:00Z");
    }

    #[test]
    fn json_requests_carry_their_content_type_and_body() {
        let request = with_json(TestRequest::new("PATCH", "/x"), MERGE_PATCH, &json!({"a": 1}));
        assert_eq!(request.headers["content-type"], MERGE_PATCH);
        assert_eq!(request.headers["accept"], JSON);
        assert_eq!(request.body, "{\"a\":1}");
    }
}
