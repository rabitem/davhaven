//! What the permission matrix covers: every route, method and tool of the server maps to an operation of the matrix.
//!
//! PLAN 3.2 asks for an exhaustiveness test: no way into the server may exist that no row of the matrix is about. [`check`]
//! compares the tables of this module, written by hand, with what the server itself says it offers:
//!
//! * **the management API**: every `operationId` of the OpenAPI document (`davhaven_api::document`). The 14 operations that
//!   are about one calendar map to the operations of the matrix ([`CALENDAR_API`]); the other 45 are the administration
//!   operations of [`permissions::admin`], whose paths, methods and scopes are compared with the
//!   document;
//! * **DAV**: every method the router offers on every kind of resource (`davhaven_dav::methods::allowed_methods`), mapped to
//!   the operations of the matrix or to the reason why the method decides nothing about calendar data ([`DAV`]);
//! * **MCP**: every tool of `davhaven_wire::mcp::TOOLS` ([`MCP`]), with the scope of the tool compared with the oracle;
//! * **the web pages**: feeds and RSVP pages map to their operations, the rest (assets, OAuth callback, operations) to the reason
//!   why they decide nothing ([`WEB`]).
//!
//! The comparison runs both ways: an operation of the server that no table knows is a problem, and so is a table entry for
//! something the server does not offer (a stale row) and an operation of the oracle that no way into the server reaches. The
//! scopes the server documents for an operation must be the scopes the oracle names. The one exception is the web pages: the
//! routes of the pages are compared with the table by hand (`davhaven-web` exports no route table yet), so a new page route
//! that nobody added to [`WEB`] goes unnoticed until it does; the pages are one-way coverage.
//!
//! A table only says what the matrix is *meant* to send. [`probes_sent`] runs the planners of the matrix for every case on an
//! environment and records which routes (API operations, DAV methods on each kind of resource, MCP tools) their probes
//! really send for which operation, and [`check_probes`] compares that with the tables: a route that a table maps to an
//! operation and that no probe of the operation sends is a problem, and so is a probe that sends a route for an operation the
//! table does not map it to.

use std::collections::{BTreeMap, BTreeSet};

use davhaven_domain::ResourcePath;
use serde_json::Value;

use crate::matrix::{Expectations, Operation, Surface};
use crate::permissions::{self, MatrixEnv, Plan, RunOptions, admin};

/// What a way into the server decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Covered {
    /// It performs these operations of the matrix (which the matrix runs for every actor and calendar).
    Matrix(&'static [Operation]),
    /// It is an administration operation of the API (the administration matrix).
    Admin,
    /// It decides nothing about calendar data, or is decided elsewhere: the reason.
    Elsewhere(&'static str),
}

/// The operations of the API that are about one calendar, by `operationId`.
pub const CALENDAR_API: &[(&str, &[Operation])] = &[
    ("listCalendars", &[Operation::ReadCollection]),
    ("getCalendar", &[Operation::ReadCollection]),
    ("putCalendar", &[Operation::CreateCalendar, Operation::UpdateCalendar]),
    ("patchCalendar", &[Operation::UpdateCalendar, Operation::RenameCalendar]),
    ("deleteCalendar", &[Operation::DeleteCalendar]),
    ("listChanges", &[Operation::ListObjects]),
    ("listObjects", &[Operation::ListObjects]),
    ("batchObjects", &[Operation::BatchUpsert]),
    ("getObjectByKey", &[Operation::ReadObject]),
    ("putObjectByKey", &[Operation::CreateObject, Operation::UpdateObject]),
    ("deleteObjectByKey", &[Operation::DeleteObject]),
    ("listGrants", &[Operation::ListGrants]),
    ("putGrant", &[Operation::PutGrant]),
    ("deleteGrant", &[Operation::DeleteGrant]),
];

/// The kinds of DAV resources, with a path of each.
pub const DAV_RESOURCES: &[(&str, &str)] = &[
    ("root", "/dav/"),
    ("principal", "/dav/principals/acme/olivia/"),
    ("home", "/dav/calendars/acme/olivia/"),
    ("collection", "/dav/calendars/acme/olivia/personal/"),
    ("object", "/dav/calendars/acme/olivia/personal/event.ics"),
    ("inbox", "/dav/calendars/acme/olivia/inbox/"),
    ("outbox", "/dav/calendars/acme/olivia/outbox/"),
    ("notifications", "/dav/calendars/acme/olivia/notifications/"),
    (
        "notification",
        "/dav/calendars/acme/olivia/notifications/invitation.xml",
    ),
    ("inbox item", "/dav/calendars/acme/olivia/inbox/message.ics"),
];

const DISCOVERY: Covered = Covered::Elsewhere("capability discovery answers every caller and shows no calendar data");

/// The methods of every kind of DAV resource and what they decide.
pub const DAV: &[(&str, &str, Covered)] = &[
    ("root", "OPTIONS", DISCOVERY),
    (
        "root",
        "PROPFIND",
        Covered::Elsewhere("the entry point names the principal of the login and nothing else"),
    ),
    (
        "root",
        "REPORT",
        Covered::Elsewhere("principal search: people of the tenant by name and address (`dav_collaboration` tests)"),
    ),
    ("principal", "OPTIONS", DISCOVERY),
    ("principal", "PROPFIND", Covered::Matrix(&[Operation::ReadPrincipal])),
    (
        "principal",
        "REPORT",
        Covered::Elsewhere("principal search: people of the tenant by name and address (`dav_collaboration` tests)"),
    ),
    ("home", "OPTIONS", DISCOVERY),
    ("home", "PROPFIND", Covered::Matrix(&[Operation::ReadHome])),
    (
        "home",
        "PROPPATCH",
        Covered::Elsewhere("a home has no properties: refused whatever the caller"),
    ),
    (
        "home",
        "REPORT",
        Covered::Elsewhere(
            "no report is defined on a home (`sync-collection` of a home is 403 `DAV:supported-report` whoever asks, `crates/it/tests/permissions.rs`)",
        ),
    ),
    (
        "home",
        "MKCALENDAR",
        Covered::Elsewhere(
            "creates the collection at the URL it is sent to, and a home that exists is refused: the creation of a collection is the `collection` row",
        ),
    ),
    (
        "home",
        "MKCOL",
        Covered::Elsewhere(
            "creates the collection at the URL it is sent to, and a home that exists is refused: the creation of a collection is the `collection` row",
        ),
    ),
    ("home", "POST", Covered::Matrix(&[Operation::ReplyInvite])),
    ("collection", "OPTIONS", DISCOVERY),
    (
        "collection",
        "PROPFIND",
        Covered::Matrix(&[Operation::ReadCollection, Operation::ListObjects]),
    ),
    (
        "collection",
        "PROPPATCH",
        Covered::Matrix(&[Operation::PropPatchBinding, Operation::UpdateCalendar]),
    ),
    ("collection", "REPORT", Covered::Matrix(&[Operation::ListObjects])),
    (
        "collection",
        "MKCALENDAR",
        Covered::Matrix(&[Operation::CreateCalendar]),
    ),
    ("collection", "MKCOL", Covered::Matrix(&[Operation::CreateCalendar])),
    (
        "collection",
        "DELETE",
        Covered::Matrix(&[Operation::DeleteCalendar, Operation::RemoveBinding]),
    ),
    ("collection", "POST", Covered::Matrix(&[Operation::ShareCalendar])),
    ("object", "OPTIONS", DISCOVERY),
    ("object", "GET", Covered::Matrix(&[Operation::ReadObject])),
    ("object", "HEAD", Covered::Matrix(&[Operation::ReadObject])),
    (
        "object",
        "PUT",
        Covered::Matrix(&[Operation::CreateObject, Operation::UpdateObject]),
    ),
    ("object", "DELETE", Covered::Matrix(&[Operation::DeleteObject])),
    (
        "object",
        "MOVE",
        Covered::Matrix(&[Operation::MoveObjectFrom, Operation::MoveObjectTo]),
    ),
    (
        "object",
        "COPY",
        Covered::Matrix(&[Operation::CopyObjectFrom, Operation::CopyObjectTo]),
    ),
    ("object", "PROPFIND", Covered::Matrix(&[Operation::ReadObject])),
    (
        "object",
        "PROPPATCH",
        Covered::Elsewhere("an object has no properties of its own: refused whatever the caller"),
    ),
    ("inbox", "OPTIONS", DISCOVERY),
    ("inbox", "PROPFIND", Covered::Matrix(&[Operation::ReadInbox])),
    (
        "inbox",
        "PROPPATCH",
        Covered::Elsewhere("the inbox has no properties to set: refused whatever the caller"),
    ),
    ("inbox", "REPORT", Covered::Matrix(&[Operation::ReadInbox])),
    ("outbox", "OPTIONS", DISCOVERY),
    (
        "outbox",
        "PROPFIND",
        Covered::Elsewhere("the outbox has no members; its properties are those of the home"),
    ),
    (
        "outbox",
        "POST",
        Covered::Matrix(&[Operation::PostOutbox, Operation::FreeBusyQuery]),
    ),
    ("notifications", "OPTIONS", DISCOVERY),
    (
        "notifications",
        "PROPFIND",
        Covered::Matrix(&[Operation::ReadNotifications]),
    ),
    (
        "notifications",
        "REPORT",
        Covered::Matrix(&[Operation::ReadNotifications]),
    ),
    ("notification", "OPTIONS", DISCOVERY),
    ("notification", "GET", Covered::Matrix(&[Operation::ReadNotifications])),
    ("notification", "HEAD", Covered::Matrix(&[Operation::ReadNotifications])),
    (
        "notification",
        "PROPFIND",
        Covered::Matrix(&[Operation::ReadNotifications]),
    ),
    (
        "notification",
        "DELETE",
        Covered::Matrix(&[Operation::DeleteNotification]),
    ),
    ("inbox item", "OPTIONS", DISCOVERY),
    ("inbox item", "GET", Covered::Matrix(&[Operation::ReadInbox])),
    ("inbox item", "HEAD", Covered::Matrix(&[Operation::ReadInbox])),
    ("inbox item", "PROPFIND", Covered::Matrix(&[Operation::ReadInbox])),
    ("inbox item", "DELETE", Covered::Matrix(&[Operation::DeleteInboxItem])),
];

/// The tools of the MCP server and the operations of the matrix they perform.
pub const MCP: &[(&str, &[Operation])] = &[
    ("list_calendars", &[Operation::ReadCollection]),
    ("list_events", &[Operation::ListObjects]),
    ("get_event", &[Operation::ReadObject]),
    ("search_events", &[Operation::ListObjects]),
    ("free_busy", &[Operation::FreeBusyQuery]),
    ("find_free_slots", &[Operation::FreeBusyQuery]),
    ("create_event", &[Operation::CreateObject]),
    ("update_event", &[Operation::UpdateObject]),
    ("delete_event", &[Operation::DeleteObject]),
    ("respond_to_invitation", &[Operation::RespondToInvitation]),
];

/// The routes of the web pages and the operations listener: method, path template, what they decide.
pub const WEB: &[(&str, &str, Covered)] = &[
    ("GET", "/feeds/{token}.ics", Covered::Matrix(&[Operation::ReadFeed])),
    ("GET", "/rsvp/{token}", Covered::Matrix(&[Operation::RsvpView])),
    ("POST", "/rsvp/{token}", Covered::Matrix(&[Operation::RsvpAnswer])),
    (
        "GET",
        "/oauth/{provider}/callback",
        Covered::Elsewhere(
            "bound to the single-use state of the OAuth flow, which names the tenant, the principal and the provider (`providers` tests of `davhaven-it`)",
        ),
    ),
    (
        "GET",
        "/assets/{*path}",
        Covered::Elsewhere("static assets of the themes: public by design"),
    ),
    (
        "ANY",
        "/.well-known/caldav",
        Covered::Elsewhere("a redirect to `/dav/` for every caller"),
    ),
    (
        "GET",
        "/healthz",
        Covered::Elsewhere("the operations listener: no tenant data"),
    ),
    (
        "GET",
        "/readyz",
        Covered::Elsewhere("the operations listener: no tenant data"),
    ),
    (
        "GET",
        "/metrics",
        Covered::Elsewhere("the operations listener: no tenant data"),
    ),
];

/// What [`check`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    /// What does not add up; empty when every way into the server is covered.
    pub problems: Vec<String>,
    /// How many operations of the API the server documents.
    pub api_operations: usize,
    /// How many (resource, method) pairs the DAV router offers.
    pub dav_methods: usize,
    /// How many tools the MCP server offers.
    pub mcp_tools: usize,
}

/// The operations of the API the document lists: `operationId` to (method, path, scopes).
fn documented_operations() -> BTreeMap<String, (String, String, Vec<String>)> {
    let document = serde_json::to_value(davhaven_api::document()).unwrap_or(Value::Null);
    let mut operations = BTreeMap::new();
    let Some(paths) = document.get("paths").and_then(Value::as_object) else {
        return operations;
    };
    for (path, item) in paths {
        for method in ["get", "put", "post", "patch", "delete"] {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let Some(id) = operation.get("operationId").and_then(Value::as_str) else {
                continue;
            };
            let scopes = operation
                .get("x-required-scope")
                .and_then(Value::as_array)
                .map(|scopes| scopes.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                .unwrap_or_default();
            operations.insert(id.to_owned(), (method.to_ascii_uppercase(), path.clone(), scopes));
        }
    }
    operations
}

fn check_api(expectations: &Expectations, problems: &mut Vec<String>) -> usize {
    let documented = documented_operations();
    let mut reached: BTreeSet<Operation> = BTreeSet::new();
    for (id, (method, path, scopes)) in &documented {
        if let Some(operation) = admin::operation(id) {
            if operation.method != method || operation.path != path {
                problems.push(format!(
                    "API {id}: the document has {method} {path}, the administration table {} {}",
                    operation.method, operation.path
                ));
            }
            match expectations.admin_scopes(id) {
                Some(oracle) => {
                    let listed: BTreeSet<&str> = scopes.iter().map(String::as_str).collect();
                    let expected: BTreeSet<&str> = oracle.iter().map(String::as_str).collect();
                    if listed != expected {
                        problems.push(format!(
                            "API {id}: the document says the scopes are {listed:?}, the expectations file {expected:?}"
                        ));
                    }
                }
                None => problems.push(format!("API {id}: the expectations file has no [[admin]] row for it")),
            }
        } else if let Some((_, operations)) = CALENDAR_API.iter().find(|(known, _)| known == id) {
            for operation in *operations {
                reached.insert(*operation);
                match expectations.scope_of(Surface::Api, *operation) {
                    Some(oracle) if scopes.iter().any(|scope| scope == oracle) => {}
                    other => problems.push(format!(
                        "API {id}: the document says the scopes are {scopes:?}, the expectations file says {other:?} for {operation}"
                    )),
                }
            }
        } else {
            problems.push(format!(
                "API {method} {path} ({id}) maps to no operation of the matrix: add it to the administration operations or to CALENDAR_API"
            ));
        }
    }
    for operation in admin::OPERATIONS {
        if !documented.contains_key(operation.id) {
            problems.push(format!(
                "API {}: the administration table lists an operation the document does not have",
                operation.id
            ));
        }
    }
    for (id, _) in CALENDAR_API {
        if !documented.contains_key(*id) {
            problems.push(format!(
                "API {id}: CALENDAR_API lists an operation the document does not have"
            ));
        }
    }
    for operation in expectations.operations_on(Surface::Api) {
        if !reached.contains(&operation) {
            problems.push(format!(
                "API: the matrix has the operation `{operation}`, which no route of the document performs"
            ));
        }
    }
    documented.len()
}

fn check_dav(expectations: &Expectations, problems: &mut Vec<String>) -> usize {
    let mut offered: BTreeSet<(&str, String)> = BTreeSet::new();
    for &(kind, path) in DAV_RESOURCES {
        match ResourcePath::parse(path) {
            Ok(resource) => {
                for method in davhaven_dav::methods::allowed_methods(&resource) {
                    offered.insert((kind, (*method).to_owned()));
                }
            }
            Err(error) => problems.push(format!(
                "DAV: the sample path of `{kind}` ({path}) is not a resource: {error}"
            )),
        }
    }
    let mut reached: BTreeSet<Operation> = BTreeSet::new();
    for (kind, method) in &offered {
        match DAV
            .iter()
            .find(|(known, name, _)| known == kind && *name == method.as_str())
        {
            Some((_, _, Covered::Matrix(operations))) => reached.extend(operations.iter().copied()),
            Some(_) => {}
            None => problems.push(format!(
                "DAV {method} on a {kind}: the router offers it and no row of DAV says what it decides"
            )),
        }
    }
    for &(kind, method, _) in DAV {
        if !offered.contains(&(kind, method.to_owned())) {
            problems.push(format!(
                "DAV {method} on a {kind}: the table lists a method the router does not offer"
            ));
        }
    }
    for operation in expectations.operations_on(Surface::Dav) {
        if !reached.contains(&operation) {
            problems.push(format!(
                "DAV: the matrix has the operation `{operation}`, which no method of the router performs"
            ));
        }
    }
    offered.len()
}

fn check_mcp(expectations: &Expectations, problems: &mut Vec<String>) -> usize {
    let mut reached: BTreeSet<Operation> = BTreeSet::new();
    for tool in &davhaven_wire::mcp::TOOLS {
        let Some((_, operations)) = MCP.iter().find(|(name, _)| *name == tool.name) else {
            problems.push(format!(
                "MCP {}: the server offers the tool and no row of MCP maps it to an operation",
                tool.name
            ));
            continue;
        };
        for operation in *operations {
            reached.insert(*operation);
            match expectations.scope_of(Surface::Mcp, *operation) {
                Some(oracle) if oracle == tool.scope.as_str() => {}
                other => problems.push(format!(
                    "MCP {}: the tool needs the scope `{}`, the expectations file says {other:?} for {operation}",
                    tool.name,
                    tool.scope.as_str()
                )),
            }
        }
    }
    for (name, _) in MCP {
        if !davhaven_wire::mcp::TOOLS.iter().any(|tool| tool.name == *name) {
            problems.push(format!("MCP {name}: the table lists a tool the server does not offer"));
        }
    }
    for operation in expectations.operations_on(Surface::Mcp) {
        if !reached.contains(&operation) {
            problems.push(format!(
                "MCP: the matrix has the operation `{operation}`, which no tool performs"
            ));
        }
    }
    davhaven_wire::mcp::TOOLS.len()
}

fn check_web(expectations: &Expectations, problems: &mut Vec<String>) {
    let mut reached: BTreeSet<Operation> = BTreeSet::new();
    for (_, _, covered) in WEB {
        if let Covered::Matrix(operations) = covered {
            reached.extend(operations.iter().copied());
        }
    }
    for surface in [Surface::Feed, Surface::Rsvp] {
        for operation in expectations.operations_on(surface) {
            if !reached.contains(&operation) {
                problems.push(format!(
                    "{surface}: the matrix has the operation `{operation}`, which no route of the web pages performs"
                ));
            }
        }
    }
}

/// Compares the tables of this module with what the server offers and with the oracle.
pub fn check(expectations: &Expectations) -> Coverage {
    let mut problems = Vec::new();
    let api_operations = check_api(expectations, &mut problems);
    let dav_methods = check_dav(expectations, &mut problems);
    let mcp_tools = check_mcp(expectations, &mut problems);
    check_web(expectations, &mut problems);
    Coverage {
        problems,
        api_operations,
        dav_methods,
        mcp_tools,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// What the probes really send
// ---------------------------------------------------------------------------------------------------------------

/// The name of a kind of DAV resource as [`DAV_RESOURCES`] and [`DAV`] call it.
const fn dav_kind(resource: &ResourcePath) -> &'static str {
    match resource {
        ResourcePath::Root => "root",
        ResourcePath::Principal { .. } => "principal",
        ResourcePath::Home { .. } => "home",
        ResourcePath::Collection { .. } => "collection",
        ResourcePath::Object { .. } => "object",
        ResourcePath::Inbox { .. } => "inbox",
        ResourcePath::Outbox { .. } => "outbox",
        ResourcePath::Notifications { .. } => "notifications",
        ResourcePath::Notification { .. } => "notification",
        ResourcePath::InboxItem { .. } => "inbox item",
    }
}

/// The `operationId` of the API operation that a request goes to: the method and the path (below `/api/v1`) matched against the
/// path templates of the document, where a `{name}` segment takes any one segment.
fn api_route(
    method: &str,
    target: &str,
    documented: &BTreeMap<String, (String, String, Vec<String>)>,
) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    let below = path.strip_prefix("/api/v1")?;
    let actual: Vec<&str> = below.split('/').collect();
    documented
        .iter()
        .find(|(_, (documented_method, template, _))| {
            let wanted: Vec<&str> = template.split('/').collect();
            documented_method.eq_ignore_ascii_case(method)
                && wanted.len() == actual.len()
                && wanted.iter().zip(&actual).all(|(want, have)| {
                    (want.starts_with('{') && want.ends_with('}') && !have.is_empty()) || want == have
                })
        })
        .map(|(id, _)| id.clone())
}

/// The route of a probe: the API operation, `{kind of resource} {METHOD}` on DAV, the name of the MCP tool.
fn route_of(
    surface: Surface,
    request: &crate::transport::TestRequest,
    documented: &BTreeMap<String, (String, String, Vec<String>)>,
) -> Option<String> {
    match surface {
        Surface::Api => api_route(request.method.as_str(), &request.target, documented),
        Surface::Dav => {
            let path = request.target.split('?').next().unwrap_or(&request.target);
            let resource = ResourcePath::parse(path).ok()?;
            Some(format!("{} {}", dav_kind(&resource), request.method))
        }
        Surface::Mcp => {
            let body: Value = serde_json::from_slice(&request.body).ok()?;
            body.pointer("/params/name").and_then(Value::as_str).map(str::to_owned)
        }
        Surface::Feed | Surface::Rsvp => None,
    }
}

/// What the probes of the matrix send: for the API, DAV and MCP surfaces, the routes (API operation, `{kind} {METHOD}`, tool)
/// that the probes of each operation really send, found by planning every case of the matrix on `env`. A planner may write to
/// `env` (a case that is allowed to deliver an invitation does), so the environment is one the caller can spare.
pub async fn probes_sent(env: &dyn MatrixEnv, expectations: &Expectations) -> BTreeSet<(Surface, String, Operation)> {
    let documented = documented_operations();
    let mut sent = BTreeSet::new();
    let options = RunOptions {
        token_scopes: false,
        ..RunOptions::default()
    };
    for (seq, case) in permissions::cases(expectations, &options).into_iter().enumerate() {
        if !matches!(case.surface, Surface::Dav | Surface::Api | Surface::Mcp) || !env.has_calendar(case.calendar) {
            continue;
        }
        let Ok(resolution) = expectations.resolve(&case) else {
            continue;
        };
        let Plan::Probes(probes) = permissions::plan(env, &case, &resolution, seq).await else {
            continue;
        };
        for probe in probes {
            if let Some(route) = route_of(case.surface, &probe.request, &documented) {
                sent.insert((case.surface, route, case.operation));
            }
        }
    }
    sent
}

/// Compares what the probes send with the tables: every route that a table maps to an operation has to be sent by a probe of that
/// operation, and a probe may send a route only for an operation the table maps it to.
pub fn check_probes(sent: &BTreeSet<(Surface, String, Operation)>) -> Vec<String> {
    let mut problems = Vec::new();
    for (id, operations) in CALENDAR_API {
        for operation in *operations {
            if !sent.contains(&(Surface::Api, (*id).to_owned(), *operation)) {
                problems.push(format!("API {id}: no probe of `{operation}` sends it"));
            }
        }
    }
    for (kind, method, covered) in DAV {
        if let Covered::Matrix(operations) = covered {
            for operation in *operations {
                if !sent.contains(&(Surface::Dav, format!("{kind} {method}"), *operation)) {
                    problems.push(format!("DAV {method} on a {kind}: no probe of `{operation}` sends it"));
                }
            }
        }
    }
    for (name, operations) in MCP {
        for operation in *operations {
            if !sent.contains(&(Surface::Mcp, (*name).to_owned(), *operation)) {
                problems.push(format!("MCP {name}: no probe of `{operation}` calls it"));
            }
        }
    }
    for (surface, route, operation) in sent {
        let mapped = match surface {
            Surface::Api => CALENDAR_API
                .iter()
                .find(|(id, _)| *id == route.as_str())
                .is_some_and(|(_, operations)| operations.contains(operation)),
            Surface::Dav => DAV.iter().any(|(kind, method, covered)| {
                format!("{kind} {method}") == *route
                    && matches!(covered, Covered::Matrix(operations) if operations.contains(operation))
            }),
            Surface::Mcp => MCP
                .iter()
                .any(|(name, operations)| *name == route.as_str() && operations.contains(operation)),
            Surface::Feed | Surface::Rsvp => true,
        };
        // The administration operations are the business of their own matrix: a request to one of them is not a probe of
        // this one.
        let admin = *surface == Surface::Api && admin::operation(route).is_some();
        if !mapped && !admin {
            problems.push(format!(
                "{surface}: a probe of `{operation}` sends `{route}`, which no table maps to that operation"
            ));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundled() -> Expectations {
        Expectations::bundled().unwrap()
    }

    #[test]
    fn a_request_is_matched_to_the_operation_of_the_document_it_goes_to() {
        let documented = documented_operations();
        let route = |method: &str, target: &str| api_route(method, target, &documented);
        assert_eq!(
            route("GET", "/api/v1/tenants/acme/principals/olivia/calendars").as_deref(),
            Some("listCalendars")
        );
        assert_eq!(
            route("GET", "/api/v1/tenants/acme/principals/olivia/calendars/personal").as_deref(),
            Some("getCalendar")
        );
        assert_eq!(
            route("PUT", "/api/v1/tenants/acme/principals/olivia/calendars/personal").as_deref(),
            Some("putCalendar")
        );
        assert_eq!(
            route("PATCH", "/api/v1/tenants/acme/principals/olivia/calendars/personal").as_deref(),
            Some("patchCalendar")
        );
        assert_eq!(
            route(
                "PUT",
                "/api/v1/tenants/acme/principals/olivia/calendars/personal/objects/by-key/k?x=1"
            )
            .as_deref(),
            Some("putObjectByKey")
        );
        assert_eq!(
            route(
                "POST",
                "/api/v1/tenants/acme/principals/olivia/calendars/personal/objects/batch"
            )
            .as_deref(),
            Some("batchObjects")
        );
        assert_eq!(
            route("GET", "/api/v1/tenants/acme/webhooks").as_deref(),
            Some("listWebhooks")
        );
        assert_eq!(route("GET", "/api/v1/nothing/here"), None);
        assert_eq!(route("GET", "/dav/"), None, "not a path of the API");
    }

    #[test]
    fn the_kind_of_a_dav_path_is_the_kind_of_its_resource() {
        let kind = |path: &str| dav_kind(&ResourcePath::parse(path).unwrap());
        for (name, path) in DAV_RESOURCES {
            assert_eq!(kind(path), *name, "{path}");
        }
        assert_eq!(kind("/dav/calendars/acme/olivia/mx-1-col/"), "collection");
        assert_eq!(kind("/dav/calendars/acme/olivia/inbox/item-1.ics"), "inbox item");
        assert_eq!(
            kind("/dav/calendars/acme/olivia/notifications/item-1.xml"),
            "notification"
        );
    }

    #[test]
    fn a_route_that_no_probe_sends_and_a_probe_that_sends_an_unmapped_route_are_reported() {
        let nothing = BTreeSet::new();
        let problems = check_probes(&nothing);
        assert!(
            problems.iter().any(|problem| problem.contains("API listCalendars")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|problem| problem.contains("MCP search_events")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("DAV MKCOL on a collection")),
            "{problems:?}"
        );
        // A probe of `delete_object` that sends the route of `get_event` is not what the table says.
        let mut wrong = BTreeSet::new();
        wrong.insert((Surface::Mcp, "get_event".to_owned(), Operation::DeleteObject));
        assert!(
            check_probes(&wrong)
                .iter()
                .any(|problem| problem.contains("sends `get_event`")),
            "{:?}",
            check_probes(&wrong)
        );
    }

    #[test]
    fn every_way_into_the_server_is_covered_and_nothing_in_the_tables_is_stale() {
        let coverage = check(&bundled());
        assert_eq!(coverage.problems, Vec::<String>::new());
        assert_eq!(
            coverage.api_operations, 61,
            "14 operations about a calendar and 47 administration operations"
        );
        assert_eq!(coverage.mcp_tools, 10);
        assert!(coverage.dav_methods > 40, "{}", coverage.dav_methods);
    }

    #[test]
    fn the_api_tables_split_the_operations_of_the_document_exactly() {
        let documented = documented_operations();
        let calendar: BTreeSet<&str> = CALENDAR_API.iter().map(|(id, _)| *id).collect();
        let administration: BTreeSet<&str> = admin::OPERATIONS.iter().map(|operation| operation.id).collect();
        assert!(calendar.is_disjoint(&administration));
        let known: BTreeSet<&str> = calendar.union(&administration).copied().collect();
        let all: BTreeSet<&str> = documented.keys().map(String::as_str).collect();
        assert_eq!(known, all);
    }

    #[test]
    fn a_route_without_a_row_is_reported() {
        // A file that does not list one administration operation: the document has it, the oracle does not.
        let without = crate::matrix::BUNDLED.replace(
            "[[admin]]\noperation = \"listAuditEvents\"\nscopes = [\"audit:read\"]\n",
            "",
        );
        assert_ne!(without, crate::matrix::BUNDLED);
        let coverage = check(&Expectations::parse(&without).unwrap());
        assert!(
            coverage
                .problems
                .iter()
                .any(|problem| problem.contains("listAuditEvents") && problem.contains("no [[admin]] row")),
            "{:?}",
            coverage.problems
        );
        // A scope that the file and the document disagree about.
        let wrong = crate::matrix::BUNDLED.replace(
            "operation = \"listAuditEvents\"\nscopes = [\"audit:read\"]",
            "operation = \"listAuditEvents\"\nscopes = [\"outbox:manage\"]",
        );
        let coverage = check(&Expectations::parse(&wrong).unwrap());
        assert!(
            coverage
                .problems
                .iter()
                .any(|problem| problem.contains("listAuditEvents") && problem.contains("scopes")),
            "{:?}",
            coverage.problems
        );
    }

    /// The problems of [`check`] for the bundled file with `from` replaced by `to`.
    fn problems_with(from: &str, to: &str) -> Vec<String> {
        let changed = crate::matrix::BUNDLED.replace(from, to);
        assert_ne!(changed, crate::matrix::BUNDLED, "`{from}` is not in the file");
        check(&Expectations::parse(&changed).unwrap()).problems
    }

    #[test]
    fn an_operation_of_the_oracle_that_nothing_performs_is_reported() {
        // The oracle claims an operation on a surface where no route, method, tool or page performs it: a row of the matrix that
        // no request can ever check. Each is the one problem of the file.
        for (surface, from, to, problem) in [
            (
                "api",
                "[[available]]\nsurface = \"api\"\noperations = [\n  \"read_collection\",",
                "[[available]]\nsurface = \"api\"\noperations = [\n  \"share_calendar\", \"read_collection\",",
                "API: the matrix has the operation `share_calendar`, which no route of the document performs",
            ),
            (
                "dav",
                "[[available]]\nsurface = \"dav\"\noperations = [\n  \"read_collection\",",
                "[[available]]\nsurface = \"dav\"\noperations = [\n  \"batch_upsert\", \"read_collection\",",
                "DAV: the matrix has the operation `batch_upsert`, which no method of the router performs",
            ),
            (
                "mcp",
                "[[available]]\nsurface = \"mcp\"\noperations = [\n  \"read_collection\",",
                "[[available]]\nsurface = \"mcp\"\noperations = [\n  \"delete_calendar\", \"read_collection\",",
                "MCP: the matrix has the operation `delete_calendar`, which no tool performs",
            ),
            (
                "feed",
                "surface = \"feed\"\noperations = [\"read_feed\"]",
                "surface = \"feed\"\noperations = [\"read_feed\", \"read_object\"]",
                "feed: the matrix has the operation `read_object`, which no route of the web pages performs",
            ),
            (
                "rsvp",
                "surface = \"rsvp\"\noperations = [\"rsvp_view\", \"rsvp_answer\"]",
                "surface = \"rsvp\"\noperations = [\"rsvp_view\", \"rsvp_answer\", \"read_inbox\"]",
                "rsvp: the matrix has the operation `read_inbox`, which no route of the web pages performs",
            ),
        ] {
            assert_eq!(problems_with(from, to), vec![problem.to_owned()], "{surface}");
        }
    }

    #[test]
    fn a_scope_that_the_oracle_and_the_server_disagree_about_is_reported_for_calendars_and_tools() {
        // The API documents `calendars:read` for the operations that read a calendar; the oracle now says `events:read`.
        let api = problems_with(
            "operation = \"read_collection\"\nscope = \"calendars:read\"",
            "operation = \"read_collection\"\nscope = \"events:read\"",
        );
        assert_ne!(api, Vec::<String>::new());
        for problem in &api {
            assert!(
                problem.starts_with("API ")
                    && problem.ends_with("the expectations file says Some(\"events:read\") for read_collection"),
                "{api:?}"
            );
        }
        // The tools that read need `mcp:read`; the oracle now says `mcp:write`.
        let mcp = problems_with(
            "operation = [\"read_collection\", \"list_objects\", \"read_object\", \"free_busy_query\"]\nscope = \"mcp:read\"",
            "operation = [\"read_collection\", \"list_objects\", \"read_object\", \"free_busy_query\"]\nscope = \"mcp:write\"",
        );
        assert_ne!(mcp, Vec::<String>::new());
        for problem in &mcp {
            assert!(
                problem.starts_with("MCP ")
                    && problem.contains(
                        "the tool needs the scope `mcp:read`, the expectations file says Some(\"mcp:write\")"
                    ),
                "{mcp:?}"
            );
        }
        // An oracle without the scope of a tool is a disagreement too, not a pass.
        let unscoped = problems_with(
            "[[scope]]\nsurface = \"mcp\"\noperation = [\"create_object\", \"update_object\", \"delete_object\", \"respond_to_invitation\"]\nscope = \"mcp:write\"\n",
            "",
        );
        assert_ne!(unscoped, Vec::<String>::new());
        assert!(
            unscoped.iter().all(
                |problem| problem.contains("the tool needs the scope `mcp:write`, the expectations file says None")
            ),
            "{unscoped:?}"
        );
    }
}
