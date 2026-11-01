//! What the document is built from besides the routes: problem responses, shared parameters, the `Idempotency-Key`
//! header, page items and the pruning of schemas that nothing reaches.
//!
//! [`super::document`] registers these after the routes are collected. Operations refer to the components instead of
//! repeating them, which keeps the document small and gives client generators one definition of each.
//!
//! The names of the shared parameters are part of the published contract (ADR-0011): a generator may emit a type per
//! parameter component. They are therefore **declared** (the table [`SHARED_PARAMETERS`]), not derived from how
//! often something is used, so adding an operation can never rename or swap an existing component.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use utoipa::openapi::header::{Header, HeaderBuilder};
use utoipa::openapi::path::{Operation as PathOperation, Parameter, ParameterBuilder, ParameterIn, PathItem};
use utoipa::openapi::schema::{ArrayItems, Components, ObjectBuilder, Schema, SchemaType, Type};
use utoipa::openapi::{ContentBuilder, OpenApi, Ref, RefOr, Required, ResponseBuilder};

/// One problem response of the document: the status it describes, its name under `components/responses` and the
/// text that says when a client sees it.
pub(super) struct ProblemSpec {
    pub(super) status: &'static str,
    pub(super) name: &'static str,
    pub(super) description: &'static str,
}

const fn problem(status: &'static str, name: &'static str, description: &'static str) -> ProblemSpec {
    ProblemSpec {
        status,
        name,
        description,
    }
}

/// The problem responses of the API, one component each. Operations refer to them (`$ref`) instead of repeating the
/// response, so the document stays small and a client generator emits one type per problem class.
pub(super) const PROBLEMS: [ProblemSpec; 14] = [
    problem(
        "400",
        "BadRequest",
        "The request is malformed: an invalid query parameter or header, or a body that is not JSON.",
    ),
    problem(
        "401",
        "Unauthenticated",
        "No valid API token was presented; `WWW-Authenticate` names the scheme.",
    ),
    problem(
        "403",
        "Forbidden",
        "The token lacks a scope or the permission for this operation.",
    ),
    problem(
        "404",
        "NotFound",
        "The resource does not exist or is not visible to the token.",
    ),
    problem(
        "409",
        "Conflict",
        "The request conflicts with the current state: a uniqueness conflict, `idempotency-in-progress`, \
         `secret-not-replayable`, `feature-not-enabled` or, for a principal, `name-reserved`, \
         `external-ref-reserved` or `address-reserved` (the value belongs to a deleted principal that is not purged \
         yet); the `code` member says which.",
    ),
    problem(
        "412",
        "PreconditionFailed",
        "`If-Match` or `If-None-Match` does not hold for the current version of the resource. `If-None-Match: *` \
         fails for every name that exists, including the name of a deleted principal that is not purged yet (a write \
         without it answers 409 `name-reserved` for that name).",
    ),
    problem(
        "410",
        "Gone",
        "The sync token is not usable any more (`sync-token-expired`); start over without `since`.",
    ),
    problem("413", "PayloadTooLarge", "The request body is larger than the limit."),
    problem("415", "UnsupportedMediaType", "The body is not sent as JSON."),
    problem(
        "422",
        "ValidationFailed",
        "The body is valid JSON but a value is invalid, or an `Idempotency-Key` was reused for another request; \
         `errors` lists the offending fields.",
    ),
    problem("428", "PreconditionRequired", "The request must carry `If-Match`."),
    problem(
        "429",
        "RateLimited",
        "Too many requests; `Retry-After` says when to try again.",
    ),
    problem("500", "InternalError", "An internal error occurred."),
    problem(
        "503",
        "Unavailable",
        "A dependency is unavailable; `Retry-After` says when to try again.",
    ),
];

/// The problem responses every operation documents.
pub(super) const COMMON_PROBLEMS: [&str; 7] = ["400", "401", "403", "404", "429", "500", "503"];

/// The problem responses of operations that take a body.
pub(super) const BODY_PROBLEMS: [&str; 3] = ["413", "415", "422"];

/// Problem responses of single operations: the changes feed answers 410 for a token that is not usable any more.
pub(super) const OPERATION_PROBLEMS: [(&str, &str); 1] = [("listChanges", "410")];

/// A response header with the given text and type.
fn response_header(description: &str, kind: Type) -> Header {
    HeaderBuilder::new()
        .schema(Some(ObjectBuilder::new().schema_type(kind).build()))
        .description(Some(description))
        .build()
}

/// The component of a problem response: the `ProblemDetails` document and the headers the status carries.
fn problem_component(spec: &ProblemSpec) -> utoipa::openapi::Response {
    let builder = ResponseBuilder::new().description(spec.description).content(
        "application/problem+json",
        ContentBuilder::new()
            .schema(Some(Ref::from_schema_name("ProblemDetails")))
            .build(),
    );
    match spec.status {
        "401" => builder.header(
            "WWW-Authenticate",
            response_header("The challenge: `Bearer realm=\"davhaven\"`.", Type::String),
        ),
        "429" | "503" => builder.header(
            "Retry-After",
            response_header("The seconds to wait before the request is repeated.", Type::Integer),
        ),
        _ => builder,
    }
    .build()
}

/// Registers the problem responses as `components/responses`.
pub(super) fn register_problems(components: &mut Components) {
    for spec in &PROBLEMS {
        components
            .responses
            .insert(spec.name.to_owned(), RefOr::T(problem_component(spec)));
    }
}

/// Documents `status` of an operation as a reference to its problem component, unless the operation declares the
/// status itself.
pub(super) fn add_problem(operation: &mut PathOperation, status: &str) {
    if let Some(spec) = PROBLEMS.iter().find(|spec| spec.status == status) {
        operation
            .responses
            .responses
            .entry(status.to_owned())
            .or_insert_with(|| RefOr::Ref(Ref::from_response_name(spec.name)));
    }
}

/// The operations of a path item with their upper-case method names.
fn operations_mut(item: &mut PathItem) -> [(&'static str, &mut Option<PathOperation>); 5] {
    [
        ("GET", &mut item.get),
        ("PUT", &mut item.put),
        ("POST", &mut item.post),
        ("DELETE", &mut item.delete),
        ("PATCH", &mut item.patch),
    ]
}

/// Calls `visit` with the method and the operation of every operation of the document.
pub(super) fn for_each_operation(openapi: &mut OpenApi, mut visit: impl FnMut(&str, &mut PathOperation)) {
    for item in openapi.paths.paths.values_mut() {
        for (method, operation) in operations_mut(item) {
            if let Some(operation) = operation {
                visit(method, operation);
            }
        }
    }
}

/// An optional parameter is simply absent, so its schema is the plain type: `["string", "null"]` becomes `string`.
/// Client generators turn the nullable form into a wrapper type that no header or query parameter needs.
fn without_null(parameter: &mut Parameter) {
    if let Some(RefOr::T(Schema::Object(object))) = &mut parameter.schema
        && let SchemaType::Array(types) = &object.schema_type
        && types.contains(&Type::Null)
    {
        let kinds: Vec<Type> = types.iter().filter(|kind| **kind != Type::Null).cloned().collect();
        if let [kind] = kinds.as_slice() {
            object.schema_type = SchemaType::Type(kind.clone());
        }
    }
}

/// A parameter that operations share, with the name of its component.
///
/// A parameter is recognised by its name, its location, whether it is required and the beginning of its description
/// (the description tells apart parameters that share a name: `id` is the id of a subscription in one place and the
/// id of a feed token in another). The component is named for what it is, not for how often it is used.
struct SharedParameter {
    /// The name under `components/parameters`.
    component: &'static str,
    name: &'static str,
    location: ParameterIn,
    required: bool,
    /// The description starts with this.
    description: &'static str,
}

const fn shared(
    component: &'static str,
    name: &'static str,
    location: ParameterIn,
    required: bool,
    description: &'static str,
) -> SharedParameter {
    SharedParameter {
        component,
        name,
        location,
        required,
        description,
    }
}

/// Every shared parameter of the API. Anything that is not listed stays where it is, in its operation.
const SHARED_PARAMETERS: [SharedParameter; 15] = [
    shared("TenantPath", "tenant", ParameterIn::Path, true, "The tenant slug"),
    shared(
        "PrincipalPath",
        "principal",
        ParameterIn::Path,
        true,
        "The immutable name of the principal",
    ),
    shared("GroupPath", "group", ParameterIn::Path, true, "The name of the group"),
    shared(
        "MemberPath",
        "member",
        ParameterIn::Path,
        true,
        "The name of the member",
    ),
    shared(
        "CalendarPath",
        "calendar",
        ParameterIn::Path,
        true,
        "The immutable calendar slug",
    ),
    shared(
        "ExternalKeyPath",
        "external_key",
        ParameterIn::Path,
        true,
        "The external key.",
    ),
    shared(
        "WebhookIdPath",
        "id",
        ParameterIn::Path,
        true,
        "The id of the subscription",
    ),
    shared(
        "FeedTokenIdPath",
        "id",
        ParameterIn::Path,
        true,
        "The id of the feed token",
    ),
    shared("CursorQuery", "cursor", ParameterIn::Query, false, "The `next_cursor`"),
    shared("LimitQuery", "limit", ParameterIn::Query, false, "The page size"),
    shared(
        "NotifyAttendeesQuery",
        "notify_attendees",
        ParameterIn::Query,
        false,
        "Send scheduling messages",
    ),
    shared(
        "IfMatchHeader",
        "If-Match",
        ParameterIn::Header,
        false,
        "The ETag of the version the request applies to",
    ),
    shared(
        "EventIfMatchHeader",
        "If-Match",
        ParameterIn::Header,
        false,
        "The content ETag of the event",
    ),
    shared(
        "IfMatchRequiredHeader",
        "If-Match",
        ParameterIn::Header,
        true,
        "The ETag of the version to delete",
    ),
    shared(
        "IfNoneMatchHeader",
        "If-None-Match",
        ParameterIn::Header,
        false,
        "`*` to create only",
    ),
];

/// How many parameters are shared, for the test that pins the set of components.
#[cfg(test)]
pub(super) const SHARED_PARAMETER_COUNT: usize = SHARED_PARAMETERS.len();

/// The components the `Idempotency-Key` header of a `POST` is registered as, besides [`SHARED_PARAMETERS`].
pub(super) const IDEMPOTENCY_COMPONENTS: [&str; 3] = [
    "IdempotencyKeyHeader",
    "IdempotencyKeyRequiredHeader",
    "IdempotencyKeySecretHeader",
];

/// The component of a parameter that operations share, if it is one.
fn shared_component(parameter: &Parameter) -> Option<&'static str> {
    let description = parameter.description.as_deref().unwrap_or_default();
    SHARED_PARAMETERS
        .iter()
        .find(|row| {
            row.name == parameter.name
                && row.location == parameter.parameter_in
                && row.required == (parameter.required == Required::True)
                && description.starts_with(row.description)
        })
        .map(|row| row.component)
}

/// Moves the parameters of [`SHARED_PARAMETERS`] into `components/parameters` and refers to them.
///
/// The path segments (`tenant`, `principal`, `calendar`), the paging parameters and the conditional headers are
/// declared by dozens of operations. They are written once and referenced, which keeps the document small and
/// gives client generators one definition to work from. The first operation that declares a shared parameter
/// provides the definition; an operation whose declaration differs from it in any way (a typo in a description
/// that every other operation repeats) keeps its own inline, so sharing never changes what an operation says, and
/// the tests find the stray copy.
pub(super) fn share_parameters(openapi: &mut OpenApi) {
    for_each_operation(openapi, |_, operation| {
        for parameter in operation.parameters.iter_mut().flatten() {
            if let RefOr::T(parameter) = parameter {
                without_null(parameter);
            }
        }
    });

    let mut definitions: BTreeMap<&'static str, (String, Parameter)> = BTreeMap::new();
    for_each_operation(openapi, |_, operation| {
        for parameter in operation.parameters.iter().flatten() {
            if let RefOr::T(parameter) = parameter
                && let Some(component) = shared_component(parameter)
                && let Ok(text) = serde_json::to_string(parameter)
            {
                definitions
                    .entry(component)
                    .or_insert_with(|| (text, parameter.clone()));
            }
        }
    });
    let components = openapi.components.get_or_insert_with(Components::new);
    for (component, (_, parameter)) in &definitions {
        components
            .parameters
            .insert((*component).to_owned(), RefOr::T(parameter.clone()));
    }

    for_each_operation(openapi, |_, operation| {
        for parameter in operation.parameters.iter_mut().flatten() {
            if let RefOr::T(inline) = parameter
                && let Some(component) = shared_component(inline)
                && let Some((text, _)) = definitions.get(component)
                && serde_json::to_string(inline).is_ok_and(|inline| &inline == text)
            {
                *parameter = RefOr::Ref(Ref::new(format!("#/components/parameters/{component}")));
            }
        }
    });
}

/// What the `Idempotency-Key` header of a `POST` means for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyKind {
    /// Optional; a retry with the same key replays the first response.
    Replays,
    /// Required (batch upserts); otherwise as `Replays`.
    Required,
    /// Optional; the response contains a secret, which is never stored, so a retry is answered 409
    /// `secret-not-replayable` and creates nothing a second time.
    Secret,
}

impl KeyKind {
    /// The component the header is registered as.
    pub(super) const fn component(self) -> &'static str {
        match self {
            Self::Replays => IDEMPOTENCY_COMPONENTS[0],
            Self::Required => IDEMPOTENCY_COMPONENTS[1],
            Self::Secret => IDEMPOTENCY_COMPONENTS[2],
        }
    }

    const fn required(self) -> bool {
        matches!(self, Self::Required)
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Replays => {
                "Makes the request safe to repeat. A retry with the same key and the same request answers the first \
                 response again, marked `Idempotent-Replayed: true`, for 24 hours; the same key with another request \
                 is 422 `idempotency-key-reuse`, and a retry while the first request is still running is 409 \
                 `idempotency-in-progress`. A first attempt that ended in an error can be repeated."
            }
            Self::Required => {
                "Required: makes the batch safe to repeat. A retry with the same key and the same request answers the \
                 first response again, marked `Idempotent-Replayed: true`, for 24 hours; the same key with another \
                 request is 422 `idempotency-key-reuse`, and a retry while the first request is still running is \
                 409 `idempotency-in-progress`. A first attempt that ended in an error can be repeated."
            }
            Self::Secret => {
                "Makes the request safe to repeat in the sense that it never takes effect twice. The response \
                 contains a secret, which is shown once and never stored, so a retry with the same key is answered \
                 409 `secret-not-replayable` (with the status and the `Location` of the first answer, so that the \
                 result can be found, read or revoked) instead of replaying it. The same key with another request is \
                 422 `idempotency-key-reuse`. A first attempt that ended in an error can be repeated."
            }
        }
    }
}

/// Registers the three forms of the `Idempotency-Key` header as `components/parameters`.
pub(super) fn register_idempotency_parameters(components: &mut Components) {
    for kind in [KeyKind::Replays, KeyKind::Required, KeyKind::Secret] {
        let parameter = ParameterBuilder::new()
            .name("Idempotency-Key")
            .parameter_in(ParameterIn::Header)
            .required(if kind.required() {
                Required::True
            } else {
                Required::False
            })
            .description(Some(kind.description()))
            .schema(Some(
                ObjectBuilder::new()
                    .schema_type(Type::String)
                    .min_length(Some(1))
                    .max_length(Some(255))
                    .build(),
            ))
            .build();
        components
            .parameters
            .insert(kind.component().to_owned(), RefOr::T(parameter));
    }
}

/// Declares the `Idempotency-Key` header on an operation, as a reference to the component of its kind.
pub(super) fn add_idempotency_key(operation: &mut PathOperation, kind: KeyKind) {
    operation
        .parameters
        .get_or_insert_with(Vec::new)
        .push(RefOr::Ref(Ref::new(format!(
            "#/components/parameters/{}",
            kind.component()
        ))));
}

/// Whether a success response of the operation declares the header `name` (compared without regard to case).
pub(super) fn success_declares_header(operation: &PathOperation, name: &str) -> bool {
    operation.responses.responses.iter().any(|(status, response)| {
        status.starts_with('2')
            && matches!(response, RefOr::T(response)
                if response.headers.keys().any(|header| header.eq_ignore_ascii_case(name)))
    })
}

/// Whether the operation declares a conditional header (`If-Match` or `If-None-Match`) of its own.
pub(super) fn declares_conditional_header(operation: &PathOperation) -> bool {
    operation.parameters.iter().flatten().any(|parameter| {
        matches!(parameter, RefOr::T(parameter)
            if parameter.parameter_in == ParameterIn::Header
                && (parameter.name.eq_ignore_ascii_case("if-match") || parameter.name.eq_ignore_ascii_case("if-none-match")))
    })
}

/// Lets the schema of every `Page_{Item}` refer to the component of its item instead of repeating it.
///
/// The generic `Page<T>` is expanded per item type by the derive, which inlines the item schema: every page carried
/// a full copy of its item, `EventView` and `TenantView` among them. The inlined schema equals the component of the
/// item, so replacing it by a reference changes nothing a client sees.
pub(super) fn reference_page_items(components: &mut Components) {
    let known = components.schemas.clone();
    for (name, schema) in &mut components.schemas {
        let Some(item) = name.strip_prefix("Page_") else {
            continue;
        };
        if let RefOr::T(Schema::Object(page)) = schema
            && let Some(RefOr::T(Schema::Array(items))) = page.properties.get_mut("items")
            && let ArrayItems::RefOrSchema(inner) = &mut items.items
            && known.get(item).is_some_and(|expected| expected == &**inner)
        {
            **inner = RefOr::Ref(Ref::from_schema_name(item));
        }
    }
}

/// The prefix of references to schema components.
const SCHEMA_REFERENCE: &str = "#/components/schemas/";

/// Adds the names of the schema components that `value` refers to.
pub(super) fn schema_references(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(members) => {
            for (key, member) in members {
                match member {
                    Value::String(target) if key == "$ref" => {
                        if let Some(name) = target.strip_prefix(SCHEMA_REFERENCE) {
                            found.insert(name.to_owned());
                        }
                    }
                    _ => schema_references(member, found),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                schema_references(item, found);
            }
        }
        _ => {}
    }
}

/// Drops the schema components that no operation, response, parameter or other component reaches.
///
/// The shared components of the wire crate are registered as a whole, so the ones this API never uses (the event
/// model of the MCP tools, say) must not end up in the document.
pub(super) fn prune_unused_schemas(openapi: &mut OpenApi) {
    let Ok(Value::Object(document)) = serde_json::to_value(&*openapi) else {
        return;
    };
    let components = document.get("components").and_then(Value::as_object);
    let schemas = components
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object);
    let mut live = BTreeSet::new();
    for (key, member) in &document {
        if key != "components" {
            schema_references(member, &mut live);
        }
    }
    for (key, member) in components.into_iter().flatten() {
        if key != "schemas" {
            schema_references(member, &mut live);
        }
    }
    let mut pending: Vec<String> = live.iter().cloned().collect();
    while let Some(name) = pending.pop() {
        let mut found = BTreeSet::new();
        if let Some(schema) = schemas.and_then(|schemas| schemas.get(&name)) {
            schema_references(schema, &mut found);
        }
        for reference in found {
            if live.insert(reference.clone()) {
                pending.push(reference);
            }
        }
    }
    if let Some(components) = openapi.components.as_mut() {
        components.schemas.retain(|name, _| live.contains(name));
    }
}
