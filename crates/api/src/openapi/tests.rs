//! Tests of the OpenAPI document: the route table, the scopes, the components and what generators need.

use std::collections::{BTreeMap, BTreeSet};

use super::components::{IDEMPOTENCY_COMPONENTS, PROBLEMS, SHARED_PARAMETER_COUNT, schema_references};
use super::*;

fn json_document() -> serde_json::Value {
    serde_json::to_value(document()).unwrap()
}

#[test]
fn external_account_sync_metadata_is_optional_and_times_are_date_time_strings() {
    let document = json_document();
    let schema = &document["components"]["schemas"]["ExternalAccountView"];
    let required = schema["required"].as_array().unwrap();
    for field in ["last_sync_at", "next_sync_at", "last_error_code"] {
        assert!(
            !required.iter().any(|name| name == field),
            "{field} must remain optional"
        );
        let property = &schema["properties"][field];
        assert_eq!(
            property["type"],
            serde_json::json!(["string", "null"]),
            "{field}: {property}"
        );
        if field != "last_error_code" {
            assert_eq!(property["format"], "date-time", "{field}: {property}");
        }
    }
}

/// Every `(method, path, operationId)` of the document.
fn registered(document: &serde_json::Value) -> BTreeSet<(String, String, String)> {
    let mut found = BTreeSet::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let id = operation["operationId"].as_str().unwrap().to_owned();
            found.insert((method.to_ascii_uppercase(), path.clone(), id));
        }
    }
    found
}

#[test]
fn the_route_table_and_the_registered_routes_are_the_same_set() {
    let from_table: BTreeSet<(String, String, String)> = ROUTES
        .iter()
        .map(|route| {
            (
                route.method.to_owned(),
                route.path.to_owned(),
                route.operation_id.to_owned(),
            )
        })
        .collect();
    assert_eq!(from_table.len(), ROUTES.len(), "duplicate rows in the route table");
    assert_eq!(from_table, registered(&json_document()));
    assert_eq!(ROUTES.len(), 61);
}

#[test]
fn operation_ids_are_unique_camel_case_verb_nouns() {
    let mut seen = BTreeSet::new();
    for route in ROUTES {
        assert!(seen.insert(route.operation_id), "{}", route.operation_id);
        let id = route.operation_id;
        assert!(id.chars().next().is_some_and(char::is_lowercase), "{id}");
        assert!(id.chars().all(char::is_alphanumeric), "{id}");
    }
}

#[test]
fn every_admin_operation_has_a_route_and_every_route_an_authority() {
    for operation in AdminOperation::ALL {
        let routes = ROUTES
            .iter()
            .filter(|route| route.authority == Authority::Admin(*operation))
            .count();
        assert!(routes >= 1, "{operation} has no route");
    }
    for route in ROUTES {
        assert!(
            !route.authority.scopes().is_empty(),
            "{} has no scope",
            route.operation_id
        );
        assert!(!route.authority.operation_names().is_empty(), "{}", route.operation_id);
    }
}

#[test]
fn calendar_routes_need_exactly_one_scope_for_all_their_operations() {
    for route in ROUTES {
        if let Authority::Calendar(operations) = route.authority {
            let scopes = route.authority.scopes();
            assert_eq!(scopes.len(), 1, "{}", route.operation_id);
            for operation in operations {
                assert_eq!(
                    operation.scope_rule(Channel::Api),
                    ScopeRule::Required(scopes[0]),
                    "{} {operation}",
                    route.operation_id
                );
            }
        }
    }
}

/// The scopes of every operation as the plan lists them, written down independently of the domain.
const PLAN_SCOPES: &[(&str, &[&str])] = &[
    ("listTenants", &["system:tenants"]),
    ("getTenant", &["system:tenants", "principals:read"]),
    ("putTenant", &["system:tenants"]),
    ("patchTenant", &["system:tenants"]),
    ("deleteTenant", &["system:tenants"]),
    ("listPrincipals", &["principals:read"]),
    ("getPrincipal", &["principals:read"]),
    ("putPrincipal", &["principals:write"]),
    ("patchPrincipal", &["principals:write"]),
    ("deletePrincipal", &["principals:write"]),
    ("getMembers", &["principals:read"]),
    ("setMembers", &["principals:write"]),
    ("addMember", &["principals:write"]),
    ("removeMember", &["principals:write"]),
    ("listAppPasswords", &["credentials:write"]),
    ("createAppPassword", &["credentials:write"]),
    ("revokeAppPassword", &["credentials:write"]),
    ("listFeedTokens", &["credentials:write"]),
    ("createFeedToken", &["credentials:write"]),
    ("revokeFeedToken", &["credentials:write"]),
    ("rotateFeedToken", &["credentials:write"]),
    ("getClientConfig", &["principals:read"]),
    ("createAppleMobileconfig", &["credentials:write"]),
    ("createDavx5Config", &["credentials:write"]),
    ("listCalendars", &["calendars:read"]),
    ("getCalendar", &["calendars:read"]),
    ("putCalendar", &["calendars:write"]),
    ("patchCalendar", &["calendars:write"]),
    ("deleteCalendar", &["calendars:write"]),
    ("listGrants", &["calendars:write"]),
    ("putGrant", &["calendars:write"]),
    ("deleteGrant", &["calendars:write"]),
    ("listObjects", &["events:read"]),
    ("batchObjects", &["events:write"]),
    ("getObjectByKey", &["events:read"]),
    ("putObjectByKey", &["events:write"]),
    ("deleteObjectByKey", &["events:write"]),
    ("listChanges", &["events:read"]),
    ("searchCalendars", &["calendars:read"]),
    ("listBindings", &["calendars:read"]),
    ("restoreBinding", &["calendars:write"]),
    ("listApiTokens", &["credentials:write"]),
    ("createApiToken", &["credentials:write"]),
    ("revokeApiToken", &["credentials:write"]),
    ("listWebhooks", &["webhooks:manage"]),
    ("createWebhook", &["webhooks:manage"]),
    ("getWebhook", &["webhooks:manage"]),
    ("patchWebhook", &["webhooks:manage"]),
    ("deleteWebhook", &["webhooks:manage"]),
    ("rotateWebhookSecret", &["webhooks:manage"]),
    ("pingWebhook", &["webhooks:manage"]),
    ("listDeliveries", &["webhooks:manage"]),
    ("redeliverWebhook", &["webhooks:manage"]),
    ("listProviders", &["providers:manage"]),
    ("listExternalAccounts", &["providers:manage"]),
    ("createExternalAccount", &["providers:manage"]),
    ("deleteExternalAccount", &["providers:manage"]),
    ("listAuditEvents", &["audit:read"]),
    ("listOutbox", &["outbox:manage"]),
    ("retryOutbox", &["outbox:manage"]),
    ("inboundItip", &["itip:inbound"]),
];

#[test]
fn every_operation_carries_the_scopes_of_the_plan() {
    let document = json_document();
    let mut checked = 0;
    for item in document["paths"].as_object().unwrap().values() {
        for operation in item.as_object().unwrap().values() {
            let id = operation["operationId"].as_str().unwrap();
            let expected = PLAN_SCOPES
                .iter()
                .find(|(name, _)| *name == id)
                .unwrap_or_else(|| panic!("{id} is not in the plan"))
                .1;
            assert_eq!(operation["x-required-scope"], json!(expected), "{id}");
            assert!(operation["x-davhaven-operation"].is_array(), "{id}");
            checked += 1;
        }
    }
    assert_eq!(checked, PLAN_SCOPES.len());
}

#[test]
fn the_document_describes_the_api() {
    let document = json_document();
    assert!(document["openapi"].as_str().unwrap().starts_with("3.1"));
    assert_eq!(document["info"]["title"], "Davhaven management API");
    assert_eq!(document["servers"][0]["url"], "/api/v1");
    assert_eq!(
        document["components"]["securitySchemes"][SECURITY_SCHEME]["scheme"],
        "bearer"
    );
    assert_eq!(document["security"][0][SECURITY_SCHEME], json!([]));
    assert!(document["components"]["schemas"]["ProblemDetails"].is_object());
    let tags: Vec<&str> = document["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tag| tag["name"].as_str().unwrap())
        .collect();
    assert_eq!(tags.len(), TAGS.len());
}

#[test]
fn every_operation_documents_its_problems() {
    let document = json_document();
    for (path, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let responses = operation["responses"].as_object().unwrap();
            for status in ["401", "403", "404", "429", "500"] {
                assert!(responses.contains_key(status), "{method} {path} lacks {status}");
            }
            assert!(
                responses.keys().any(|status| status.starts_with('2')),
                "{method} {path} has no success response"
            );
        }
    }
}

#[test]
fn problem_responses_follow_from_what_each_operation_accepts() {
    // 413, 415 and 422 only for an operation that takes a body (422 also for a POST: the same Idempotency-Key for
    // another request), 412 only for an operation that declares If-Match or If-None-Match, 409 for the writes. A
    // generator emits a branch per documented status, so a status the operation can never answer is a dead branch,
    // and the document stops saying which preconditions an operation honours.
    let document = json_document();
    for (path, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let responses = operation["responses"].as_object().unwrap();
            let has_body = operation.get("requestBody").is_some();
            let conditional = ["If-Match", "If-None-Match"]
                .iter()
                .any(|name| parameter_of(&document, operation, name).is_some());
            for status in ["413", "415"] {
                assert_eq!(responses.contains_key(status), has_body, "{method} {path} {status}");
            }
            assert_eq!(
                responses.contains_key("422"),
                has_body || method == "post",
                "{method} {path} 422"
            );
            assert_eq!(responses.contains_key("412"), conditional, "{method} {path} 412");
            assert_eq!(
                responses.contains_key("409"),
                matches!(method.as_str(), "put" | "post" | "patch" | "delete"),
                "{method} {path} 409"
            );
        }
    }
}

#[test]
fn every_post_declares_the_idempotency_key_in_the_form_that_is_true_for_it() {
    // The layer acts on every POST that carries the header, so the document declares it on every POST, and on
    // nothing else. Which form follows from the operation: required for the batch upsert, answered with 409
    // secret-not-replayable on a retry when the success response carries a secret (it declares Cache-Control), a
    // replay otherwise.
    let document = json_document();
    let no_parameters: Vec<serde_json::Value> = Vec::new();
    let mut posts = 0;
    for (path, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let id = operation["operationId"].as_str().unwrap();
            let declared: Vec<&str> = operation["parameters"]
                .as_array()
                .unwrap_or(&no_parameters)
                .iter()
                .filter_map(|parameter| parameter["$ref"].as_str())
                .filter(|target| target.contains("IdempotencyKey"))
                .map(|target| target.rsplit('/').next().unwrap())
                .collect();
            if method != "post" {
                assert!(
                    declared.is_empty(),
                    "{method} {path} ignores the header and must not declare it"
                );
                continue;
            }
            posts += 1;
            let secret = operation["responses"]
                .as_object()
                .unwrap()
                .iter()
                .any(|(status, response)| {
                    status.starts_with('2')
                        && response["headers"].as_object().is_some_and(|headers| {
                            headers.keys().any(|name| name.eq_ignore_ascii_case("cache-control"))
                        })
                });
            let expected = if id == "batchObjects" {
                "IdempotencyKeyRequiredHeader"
            } else if secret {
                "IdempotencyKeySecretHeader"
            } else {
                "IdempotencyKeyHeader"
            };
            assert_eq!(declared, vec![expected], "{id}");
        }
    }
    assert_eq!(posts, 15, "the POST operations of the API");

    let parameters = &document["components"]["parameters"];
    for name in ["IdempotencyKeyHeader", "IdempotencyKeySecretHeader"] {
        assert_eq!(parameters[name]["required"], false, "{name}");
    }
    assert_eq!(parameters["IdempotencyKeyRequiredHeader"]["required"], true);
    let replays = parameters["IdempotencyKeyHeader"]["description"].as_str().unwrap();
    assert!(replays.contains("answers the first response again"), "{replays}");
    let secret = parameters["IdempotencyKeySecretHeader"]["description"]
        .as_str()
        .unwrap();
    assert!(
        secret.contains("409") && secret.contains("secret-not-replayable") && !secret.contains("answers the first"),
        "operations that return a secret never replay: {secret}"
    );
    for name in IDEMPOTENCY_COMPONENTS {
        assert_eq!(parameters[name]["name"], "Idempotency-Key");
        assert_eq!(parameters[name]["in"], "header");
        assert_eq!(parameters[name]["schema"]["maxLength"], 255);
    }
}

#[test]
fn the_idempotency_key_of_every_secret_operation_is_the_secret_form() {
    // The nine operations of the API whose response carries a secret, a feed URL or a profile.
    let document = json_document();
    let mut secret_operations = BTreeSet::new();
    for item in document["paths"].as_object().unwrap().values() {
        let Some(operation) = item.get("post") else { continue };
        let target = operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|parameter| parameter["$ref"].as_str())
            .find(|target| target.contains("IdempotencyKey"))
            .unwrap();
        if target.ends_with("IdempotencyKeySecretHeader") {
            secret_operations.insert(operation["operationId"].as_str().unwrap().to_owned());
        }
    }
    let expected: BTreeSet<String> = [
        "createApiToken",
        "createAppPassword",
        "createAppleMobileconfig",
        "createDavx5Config",
        "createExternalAccount",
        "createFeedToken",
        "createWebhook",
        "rotateFeedToken",
        "rotateWebhookSecret",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(secret_operations, expected);
}

#[test]
fn deleting_versioned_resources_requires_if_match() {
    let document = json_document();
    for (path, method) in [
        ("/tenants/{tenant}", "delete"),
        ("/tenants/{tenant}/principals/{principal}", "delete"),
        (
            "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
            "delete",
        ),
    ] {
        let operation = &document["paths"][path][method];
        assert!(operation["responses"]["428"].is_object(), "{method} {path}");
    }
    assert!(document["paths"]["/tenants/{tenant}/webhooks/{id}"]["delete"]["responses"]["428"].is_null());
}

#[test]
fn the_document_does_not_change_between_builds() {
    // As a value: the members of the extensions of an operation are kept in a hash map, so the order of the raw
    // serialization differs between runs; `xtask contracts` writes `docs/openapi.json` with sorted keys.
    assert_eq!(json_document(), json_document());
}

/// Every `$ref` of a document with the pointer it names.
fn references(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(members) => {
            for (key, member) in members {
                match member {
                    serde_json::Value::String(target) if key == "$ref" => found.push(target.clone()),
                    _ => references(member, found),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                references(item, found);
            }
        }
        _ => {}
    }
}

#[test]
fn every_reference_of_the_document_resolves() {
    let document = json_document();
    let mut found = Vec::new();
    references(&document, &mut found);
    assert!(found.len() > 500, "{} references", found.len());
    for target in found {
        let pointer = target
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("{target} is not a local reference"));
        assert!(document.pointer(pointer).is_some(), "{target} does not resolve");
    }
}

#[test]
fn problems_are_components_that_operations_refer_to() {
    let document = json_document();
    let components = document["components"]["responses"].as_object().unwrap();
    assert_eq!(components.len(), PROBLEMS.len());
    let mut used = BTreeSet::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            for (status, response) in operation["responses"].as_object().unwrap() {
                if status.starts_with('2') {
                    continue;
                }
                let target = response["$ref"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{method} {path} {status} repeats a problem response"));
                let name = target.strip_prefix("#/components/responses/").unwrap();
                assert!(components.contains_key(name), "{target}");
                used.insert(name.to_owned());
            }
        }
    }
    assert_eq!(used.len(), components.len(), "a problem component is never used");
    for spec in &PROBLEMS {
        let component = &components[spec.name];
        assert_eq!(component["description"], spec.description, "{}", spec.name);
        assert_eq!(
            component["content"]["application/problem+json"]["schema"]["$ref"], "#/components/schemas/ProblemDetails",
            "{}",
            spec.name
        );
    }
}

#[test]
fn problem_components_announce_the_headers_their_status_carries() {
    let document = json_document();
    let components = &document["components"]["responses"];
    assert!(components["Unauthenticated"]["headers"]["WWW-Authenticate"].is_object());
    for name in ["RateLimited", "Unavailable"] {
        let header = &components[name]["headers"]["Retry-After"];
        assert_eq!(header["schema"]["type"], "integer", "{name}");
    }
    for name in ["NotFound", "Conflict", "ValidationFailed", "InternalError"] {
        assert!(components[name]["headers"].is_null(), "{name}");
    }
}

/// The parameter an operation declares under `name`, whether inline or as a reference.
fn parameter_of<'a>(
    document: &'a serde_json::Value,
    operation: &'a serde_json::Value,
    name: &str,
) -> Option<&'a serde_json::Value> {
    operation["parameters"]
        .as_array()?
        .iter()
        .map(|parameter| match parameter["$ref"].as_str() {
            Some(target) => document
                .pointer(target.strip_prefix('#').unwrap_or_default())
                .unwrap_or(parameter),
            None => parameter,
        })
        .find(|parameter| parameter["name"] == name)
}

#[test]
fn shared_parameters_are_components_and_every_path_segment_is_declared() {
    let document = json_document();
    let shared = document["components"]["parameters"].as_object().unwrap();
    for name in [
        "TenantPath",
        "PrincipalPath",
        "CalendarPath",
        "LimitQuery",
        "CursorQuery",
        "IfMatchHeader",
        "IdempotencyKeyHeader",
    ] {
        assert!(shared.contains_key(name), "{name} is not shared: {:?}", shared.keys());
    }
    let mut uses = BTreeSet::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        let segments = path
            .split('/')
            .filter_map(|segment| segment.strip_prefix('{').and_then(|rest| rest.strip_suffix('}')));
        for (method, operation) in item.as_object().unwrap() {
            for segment in segments.clone() {
                let parameter = parameter_of(&document, operation, segment)
                    .unwrap_or_else(|| panic!("{method} {path} does not declare {segment}"));
                assert_eq!(parameter["in"], "path", "{method} {path} {segment}");
                assert_eq!(parameter["required"], true, "{method} {path} {segment}");
            }
            for parameter in operation["parameters"].as_array().unwrap_or(&Vec::new()) {
                if let Some(target) = parameter["$ref"].as_str() {
                    uses.insert(target.rsplit('/').next().unwrap().to_owned());
                }
            }
        }
    }
    assert_eq!(uses.len(), shared.len(), "a shared parameter is never used");
}

/// The names of the parameter components, as the published contract has them. A generator may emit a type per
/// parameter component, so a rename is a breaking change of `v1`: change this list only on purpose.
const PARAMETER_COMPONENTS: [&str; 18] = [
    "CalendarPath",
    "CursorQuery",
    "EventIfMatchHeader",
    "ExternalKeyPath",
    "FeedTokenIdPath",
    "GroupPath",
    "IdempotencyKeyHeader",
    "IdempotencyKeyRequiredHeader",
    "IdempotencyKeySecretHeader",
    "IfMatchHeader",
    "IfMatchRequiredHeader",
    "IfNoneMatchHeader",
    "LimitQuery",
    "MemberPath",
    "NotifyAttendeesQuery",
    "PrincipalPath",
    "TenantPath",
    "WebhookIdPath",
];

#[test]
fn the_names_of_the_parameter_components_are_declared_and_pinned() {
    let document = json_document();
    let names: Vec<&str> = document["components"]["parameters"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(names, PARAMETER_COMPONENTS, "the set of parameter components changed");
    // Components that say whose id they carry: no `IdPath` and no numbered duplicates.
    assert!(
        names.iter().all(|name| !name.ends_with(|c: char| c.is_ascii_digit())),
        "{names:?}"
    );
    let parameters = &document["components"]["parameters"];
    assert!(
        parameters["WebhookIdPath"]["description"]
            .as_str()
            .unwrap()
            .contains("subscription")
    );
    assert!(
        parameters["FeedTokenIdPath"]["description"]
            .as_str()
            .unwrap()
            .contains("feed token")
    );
    assert!(
        parameters["EventIfMatchHeader"]["description"]
            .as_str()
            .unwrap()
            .contains("event")
    );
    // And every table row is used.
    assert_eq!(
        PARAMETER_COMPONENTS.len(),
        SHARED_PARAMETER_COUNT + IDEMPOTENCY_COMPONENTS.len()
    );
}

#[test]
fn no_parameter_that_several_operations_repeat_stays_inline() {
    // A parameter that appears twice or more is shared, or it has a typo that every other operation does not have.
    let document = json_document();
    let mut inline: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            for parameter in operation["parameters"].as_array().unwrap_or(&Vec::new()) {
                if parameter.get("$ref").is_none() {
                    inline
                        .entry(parameter.to_string())
                        .or_default()
                        .push(format!("{method} {path}"));
                }
            }
        }
    }
    let repeated: Vec<(&String, &Vec<String>)> = inline.iter().filter(|(_, uses)| uses.len() > 1).collect();
    assert!(repeated.is_empty(), "repeated inline parameters: {repeated:#?}");
}

#[test]
fn the_page_size_documents_its_bounds() {
    let document = json_document();
    let limit = &document["components"]["parameters"]["LimitQuery"]["schema"];
    assert_eq!(limit["minimum"], 1);
    assert_eq!(limit["maximum"], 200);
    assert_eq!(limit["default"], 50);
}

#[test]
fn the_problem_code_lists_the_codes_clients_receive() {
    // The wire value of a code is its kebab-case catalog code, not the name of the Rust variant (the derive of the
    // schema does not see the serde rename of a macro expansion, which published `BadRequest` once).
    let document = json_document();
    let listed: Vec<&str> = document["components"]["schemas"]["ProblemCode"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    let expected: Vec<&str> = davhaven_wire::ProblemCode::ALL.iter().map(|code| code.code()).collect();
    assert_eq!(listed, expected);
    assert!(listed.contains(&"validation-failed") && !listed.contains(&"ValidationFailed"));
    assert_eq!(
        document["components"]["schemas"]["ProblemDetails"]["properties"]["code"]["$ref"],
        "#/components/schemas/ProblemCode"
    );
}

#[test]
fn optional_parameters_are_not_nullable() {
    let document = json_document();
    let mut checked = 0;
    for item in document["paths"].as_object().unwrap().values() {
        for operation in item.as_object().unwrap().values() {
            for parameter in operation["parameters"].as_array().unwrap_or(&Vec::new()) {
                let parameter = match parameter["$ref"].as_str() {
                    Some(target) => document.pointer(target.strip_prefix('#').unwrap()).unwrap(),
                    None => parameter,
                };
                assert!(
                    parameter["schema"]["type"].is_string() || parameter["schema"]["$ref"].is_string(),
                    "{parameter}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 150, "{checked} parameters");
}

#[test]
fn pages_refer_to_their_items() {
    let document = json_document();
    let schemas = document["components"]["schemas"].as_object().unwrap();
    let pages: Vec<&String> = schemas.keys().filter(|name| name.starts_with("Page_")).collect();
    assert!(pages.len() >= 14, "{pages:?}");
    for name in pages {
        let item = name.strip_prefix("Page_").unwrap();
        assert!(schemas.contains_key(item), "{name} has no component for {item}");
        assert_eq!(
            schemas[name]["properties"]["items"]["items"]["$ref"],
            format!("#/components/schemas/{item}"),
            "{name}"
        );
    }
}

#[test]
fn shared_components_are_registered_once_and_never_overridden() {
    let document = json_document();
    let schemas = document["components"]["schemas"].as_object().unwrap();
    for (name, schema) in davhaven_wire::schema::shared_components() {
        if let Some(registered) = schemas.get(&name) {
            assert_eq!(
                registered,
                &serde_json::to_value(&schema).unwrap(),
                "{name} is defined twice, differently"
            );
        }
    }
    for name in [
        "CalendarKind",
        "PrincipalKind",
        "TenantStatus",
        "TenantSettings",
        "EventTime",
        "Recurrence",
        "PartStat",
        "EventAlarm",
        "AlarmAction",
        "AuditActor",
    ] {
        assert!(schemas.contains_key(name), "{name} is not a component");
    }
    assert!(
        !schemas.contains_key("EventData"),
        "a component that nothing refers to is dropped"
    );
}

#[test]
fn every_schema_component_is_reachable_from_an_operation() {
    let document = json_document();
    let schemas = document["components"]["schemas"].as_object().unwrap();
    let mut live = BTreeSet::new();
    schema_references(&document["paths"], &mut live);
    schema_references(&document["components"]["responses"], &mut live);
    let mut pending: Vec<String> = live.iter().cloned().collect();
    while let Some(name) = pending.pop() {
        let mut found = BTreeSet::new();
        schema_references(&schemas[&name], &mut found);
        for reference in found {
            assert!(
                schemas.contains_key(&reference),
                "{name} refers to the missing {reference}"
            );
            if live.insert(reference.clone()) {
                pending.push(reference);
            }
        }
    }
    let all: BTreeSet<String> = schemas.keys().cloned().collect();
    assert_eq!(all, live, "unreachable components: {:?}", all.difference(&live));
}

/// The places where alternatives are bare strings without values: an enumeration that lost its values.
fn lost_enumerations(value: &serde_json::Value, path: &str, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(members) => {
            for keyword in ["oneOf", "anyOf"] {
                let Some(alternatives) = members.get(keyword).and_then(serde_json::Value::as_array) else {
                    continue;
                };
                let bare = |alternative: &serde_json::Value| {
                    alternative.as_object().is_some_and(|object| {
                        object.get("type") == Some(&json!("string"))
                            && object.keys().all(|key| matches!(key.as_str(), "type" | "description"))
                    })
                };
                if alternatives.len() > 1 && alternatives.iter().all(bare) {
                    found.push(format!("{path}.{keyword}"));
                }
            }
            for (key, member) in members {
                lost_enumerations(member, &format!("{path}.{key}"), found);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                lost_enumerations(item, &format!("{path}[{index}]"), found);
            }
        }
        _ => {}
    }
}

#[test]
fn enumerations_keep_their_values_and_are_defined_once() {
    let document = json_document();
    let mut lost = Vec::new();
    lost_enumerations(&document, "#", &mut lost);
    assert!(lost.is_empty(), "enumerations without values: {lost:?}");

    let schemas = document["components"]["schemas"].as_object().unwrap();
    let class = &schemas["EventView"]["properties"]["class"];
    let status = &schemas["EventView"]["properties"]["status"];
    for (property, component) in [(class, "Classification"), (status, "EventStatus")] {
        assert!(
            property
                .to_string()
                .contains(&format!("#/components/schemas/{component}")),
            "{property}"
        );
        assert!(
            schemas[component]["enum"]
                .as_array()
                .is_some_and(|values| values.len() >= 2)
        );
    }
    // The same enumeration is one component however many schemas use it.
    let inline = schemas
        .values()
        .filter(|schema| schema["enum"] == schemas["PartStat"]["enum"])
        .count();
    assert_eq!(inline, 1, "PartStat is copied into other schemas");
}

#[test]
fn files_are_binary_strings_and_not_arrays_of_numbers() {
    let document = json_document();
    let profile = &document["paths"]["/tenants/{tenant}/principals/{principal}/client-config/apple-mobileconfig"]["post"]
        ["responses"]["200"]["content"]["application/x-apple-aspen-config"]["schema"];
    assert_eq!(profile["$ref"], "#/components/schemas/ConfigurationProfile");
    let schema = &document["components"]["schemas"]["ConfigurationProfile"];
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["format"], "binary");
}

#[test]
fn shared_parameters_say_whether_they_must_be_sent() {
    let document = json_document();
    let parameters = document["components"]["parameters"].as_object().unwrap();
    assert_eq!(parameters["IfMatchHeader"]["required"], false);
    assert_eq!(parameters["IfMatchRequiredHeader"]["required"], true);
}

#[test]
fn the_document_stays_small() {
    // Every operation used to repeat its problem responses, its parameters and the items of its pages; those
    // are components now. A document that grows past this size has started to repeat itself again.
    let compact = serde_json::to_string(&json_document()).unwrap();
    assert!(compact.len() < 160_000, "{} bytes", compact.len());
}

#[test]
fn the_document_tells_clients_how_the_api_evolves() {
    let description = json_document()["info"]["description"].as_str().unwrap().to_owned();
    for phrase in [
        "Idempotent-Replayed",
        "secret-not-replayable",
        "Retry-After",
        "enumeration values",
        "Sunset",
    ] {
        assert!(description.contains(phrase), "{phrase}");
    }
}
