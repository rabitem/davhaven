//! The OpenAPI document: metadata, security schemes and `x-required-scope` extensions.
//!
//! [`document`] builds the OpenAPI 3.1 document of the management API from the same routes that `crate::router`
//! serves, so the document cannot drift from the code; `xtask contracts` writes it to `docs/openapi.json` and CI
//! fails when the committed file is out of date. Paths are relative to the server URL `/api/v1`.
//!
//! # What the document adds to the routes
//!
//! * **Metadata**: title, version, license, the bearer security scheme (every operation needs an API token) and the
//!   tag descriptions.
//! * **`x-required-scope`** on every operation: the scopes of which a token needs at least one. The scopes are not
//!   written down here a second time; they come from the single decision point of the domain
//!   ([`AdminOperation::accepted_scopes`] and [`Operation::scope_rule`]), through the route table [`ROUTES`].
//!   The permission matrix generates its API cases from this extension.
//! * **`x-davhaven-operation`**: the names of the domain operations the route performs (`list_tenants`,
//!   `create_calendar`, ...), so tests can prove that every route maps to an operation of the matrix.
//! * **Problem responses**: every operation documents the RFC 9457 `ProblemDetails` responses it can produce, and
//!   the schema of the problem document is part of the components. They follow from what the operation accepts: 413,
//!   415 and 422 for a request body, 422 and 409 for the `Idempotency-Key` of a `POST`, 412 for an `If-Match` or
//!   `If-None-Match` header the operation declares, 428 where the version must be named.
//! * **The `Idempotency-Key` header**: every `POST` accepts it (the layer acts on all of them), so the document
//!   declares it on every `POST`, in the form that is true for the operation: optional and replaying, required (batch
//!   upserts), or for operations whose response carries a secret, optional and answered with 409
//!   `secret-not-replayable` on a retry. The form is derived from the operation (a success response with a
//!   `Cache-Control` header carries a secret), not written down a second time.
//! * **Components**: the problem responses, the parameters that several operations share, the items of the pages and
//!   the shared schemas of the wire crate are registered once and referred to; schemas that nothing reaches are
//!   dropped (module `components`).
//!
//! # The route table
//!
//! [`ROUTES`] lists every operation once: operation id, method, path template and the domain authority behind
//! it. Tests compare the table with the registered routes in both directions, so a route without a row or a row
//! without a route fails the build.

mod components;

use davhaven_domain::{AdminOperation, Channel, Operation, Scope, ScopeRule};
use serde_json::json;
use utoipa::openapi::path::Operation as PathOperation;
use utoipa::openapi::schema::{Components, ObjectBuilder, Schema, Type};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme};
use utoipa::openapi::tag::TagBuilder;
use utoipa::openapi::{InfoBuilder, KnownFormat, LicenseBuilder, OpenApi, RefOr, SchemaFormat, Server};
use utoipa::{PartialSchema, ToSchema};

use self::components::{
    BODY_PROBLEMS, COMMON_PROBLEMS, KeyKind, OPERATION_PROBLEMS, add_idempotency_key, add_problem,
    declares_conditional_header, for_each_operation, prune_unused_schemas, reference_page_items,
    register_idempotency_parameters, register_problems, share_parameters, success_declares_header,
};
use crate::router::api_router;

/// The name of the bearer security scheme.
const SECURITY_SCHEME: &str = "bearerAuth";

/// The schema of the body of a `PATCH`: a JSON Merge Patch document (RFC 7396), documented as a free-form object
/// because a patch may contain any member of the resource.
pub(crate) struct MergePatchDocument;

impl PartialSchema for MergePatchDocument {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::Object)
                .description(Some(
                    "A JSON Merge Patch (RFC 7396): the members to change; `null` removes a member.",
                ))
                .build(),
        ))
    }
}

impl ToSchema for MergePatchDocument {}

/// The schema of an Apple configuration profile (`.mobileconfig`): a file, not JSON. Documented as a binary string,
/// which client generators turn into a byte stream; `Vec<u8>` would read as an array of integers.
pub(crate) struct ConfigurationProfile;

impl PartialSchema for ConfigurationProfile {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::String)
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::Binary)))
                .description(Some(
                    "An Apple configuration profile (a property list in the `.mobileconfig` format).",
                ))
                .build(),
        ))
    }
}

impl ToSchema for ConfigurationProfile {}

/// What decides whether a token may use an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// A tenant administration operation (`AdminOperation`), which carries its accepted scopes.
    Admin(AdminOperation),
    /// Operations on one calendar (`Operation`); the scope of each comes from `Operation::scope_rule` for the API.
    Calendar(&'static [Operation]),
}

impl Authority {
    /// The scopes of which a token needs at least one, without duplicates, in a stable order.
    pub fn scopes(self) -> Vec<Scope> {
        match self {
            Self::Admin(operation) => operation.accepted_scopes().to_vec(),
            Self::Calendar(operations) => {
                let mut scopes = Vec::new();
                for operation in operations {
                    if let ScopeRule::Required(scope) = operation.scope_rule(Channel::Api)
                        && !scopes.contains(&scope)
                    {
                        scopes.push(scope);
                    }
                }
                scopes
            }
        }
    }

    /// The names of the domain operations behind the route (`list_tenants`, `create_calendar`, ...).
    pub fn operation_names(self) -> Vec<&'static str> {
        match self {
            Self::Admin(operation) => vec![operation.as_str()],
            Self::Calendar(operations) => operations.iter().map(|operation| operation.as_str()).collect(),
        }
    }
}

/// One operation of the management API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    /// The `operationId` of the OpenAPI document (`verbNoun`).
    pub operation_id: &'static str,
    /// The HTTP method in upper case.
    pub method: &'static str,
    /// The path template relative to `/api/v1`.
    pub path: &'static str,
    /// The domain authority that decides the scopes.
    pub authority: Authority,
}

const fn route(
    operation_id: &'static str,
    method: &'static str,
    path: &'static str,
    authority: Authority,
) -> RouteSpec {
    RouteSpec {
        operation_id,
        method,
        path,
        authority,
    }
}

const fn admin(operation: AdminOperation) -> Authority {
    Authority::Admin(operation)
}

const fn calendar(operations: &'static [Operation]) -> Authority {
    Authority::Calendar(operations)
}

/// Every operation of the management API (PLAN F0.10), in the order of the plan.
pub const ROUTES: &[RouteSpec] = &[
    route("listTenants", "GET", "/tenants", admin(AdminOperation::ListTenants)),
    route(
        "getTenant",
        "GET",
        "/tenants/{tenant}",
        admin(AdminOperation::GetTenant),
    ),
    route(
        "putTenant",
        "PUT",
        "/tenants/{tenant}",
        admin(AdminOperation::PutTenant),
    ),
    route(
        "patchTenant",
        "PATCH",
        "/tenants/{tenant}",
        admin(AdminOperation::PatchTenant),
    ),
    route(
        "deleteTenant",
        "DELETE",
        "/tenants/{tenant}",
        admin(AdminOperation::DeleteTenant),
    ),
    route(
        "listPrincipals",
        "GET",
        "/tenants/{tenant}/principals",
        admin(AdminOperation::ListPrincipals),
    ),
    route(
        "getPrincipal",
        "GET",
        "/tenants/{tenant}/principals/{principal}",
        admin(AdminOperation::GetPrincipal),
    ),
    route(
        "putPrincipal",
        "PUT",
        "/tenants/{tenant}/principals/{principal}",
        admin(AdminOperation::PutPrincipal),
    ),
    route(
        "patchPrincipal",
        "PATCH",
        "/tenants/{tenant}/principals/{principal}",
        admin(AdminOperation::PatchPrincipal),
    ),
    route(
        "deletePrincipal",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}",
        admin(AdminOperation::DeletePrincipal),
    ),
    route(
        "getMembers",
        "GET",
        "/tenants/{tenant}/principals/{group}/members",
        admin(AdminOperation::GetMembers),
    ),
    route(
        "setMembers",
        "PUT",
        "/tenants/{tenant}/principals/{group}/members",
        admin(AdminOperation::SetMembers),
    ),
    route(
        "addMember",
        "PUT",
        "/tenants/{tenant}/principals/{group}/members/{member}",
        admin(AdminOperation::AddMember),
    ),
    route(
        "removeMember",
        "DELETE",
        "/tenants/{tenant}/principals/{group}/members/{member}",
        admin(AdminOperation::RemoveMember),
    ),
    route(
        "listAppPasswords",
        "GET",
        "/tenants/{tenant}/principals/{principal}/app-passwords",
        admin(AdminOperation::ListAppPasswords),
    ),
    route(
        "createAppPassword",
        "POST",
        "/tenants/{tenant}/principals/{principal}/app-passwords",
        admin(AdminOperation::CreateAppPassword),
    ),
    route(
        "revokeAppPassword",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}/app-passwords/{id}",
        admin(AdminOperation::RevokeAppPassword),
    ),
    route(
        "listFeedTokens",
        "GET",
        "/tenants/{tenant}/principals/{principal}/feed-tokens",
        admin(AdminOperation::ListFeedTokens),
    ),
    route(
        "createFeedToken",
        "POST",
        "/tenants/{tenant}/principals/{principal}/feed-tokens",
        admin(AdminOperation::CreateFeedToken),
    ),
    route(
        "revokeFeedToken",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}/feed-tokens/{id}",
        admin(AdminOperation::RevokeFeedToken),
    ),
    route(
        "rotateFeedToken",
        "POST",
        "/tenants/{tenant}/principals/{principal}/feed-tokens/{id}/rotate",
        admin(AdminOperation::RotateFeedToken),
    ),
    route(
        "getClientConfig",
        "GET",
        "/tenants/{tenant}/principals/{principal}/client-config/generic",
        admin(AdminOperation::GetClientConfig),
    ),
    route(
        "createAppleMobileconfig",
        "POST",
        "/tenants/{tenant}/principals/{principal}/client-config/apple-mobileconfig",
        admin(AdminOperation::CreateClientConfig),
    ),
    route(
        "createDavx5Config",
        "POST",
        "/tenants/{tenant}/principals/{principal}/client-config/davx5",
        admin(AdminOperation::CreateClientConfig),
    ),
    route(
        "listCalendars",
        "GET",
        "/tenants/{tenant}/principals/{principal}/calendars",
        calendar(&[Operation::ReadCollection]),
    ),
    route(
        "getCalendar",
        "GET",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
        calendar(&[Operation::ReadCollection]),
    ),
    route(
        "putCalendar",
        "PUT",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
        calendar(&[Operation::CreateCalendar, Operation::UpdateCalendar]),
    ),
    route(
        "patchCalendar",
        "PATCH",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
        calendar(&[Operation::UpdateCalendar, Operation::RenameCalendar]),
    ),
    route(
        "deleteCalendar",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}",
        calendar(&[Operation::DeleteCalendar]),
    ),
    route(
        "listGrants",
        "GET",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/grants",
        calendar(&[Operation::ListGrants]),
    ),
    route(
        "putGrant",
        "PUT",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/grants/{grantee}",
        calendar(&[Operation::PutGrant]),
    ),
    route(
        "deleteGrant",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/grants/{grantee}",
        calendar(&[Operation::DeleteGrant]),
    ),
    route(
        "listObjects",
        "GET",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects",
        calendar(&[Operation::ListObjects]),
    ),
    route(
        "batchObjects",
        "POST",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/batch",
        calendar(&[Operation::BatchUpsert]),
    ),
    route(
        "getObjectByKey",
        "GET",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/by-key/{external_key}",
        calendar(&[Operation::ReadObject]),
    ),
    route(
        "putObjectByKey",
        "PUT",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/by-key/{external_key}",
        calendar(&[Operation::CreateObject, Operation::UpdateObject]),
    ),
    route(
        "deleteObjectByKey",
        "DELETE",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/by-key/{external_key}",
        calendar(&[Operation::DeleteObject]),
    ),
    route(
        "listChanges",
        "GET",
        "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/changes",
        calendar(&[Operation::ListObjects]),
    ),
    route(
        "searchCalendars",
        "GET",
        "/tenants/{tenant}/calendars",
        admin(AdminOperation::SearchCalendars),
    ),
    route(
        "listBindings",
        "GET",
        "/tenants/{tenant}/principals/{principal}/bindings",
        admin(AdminOperation::ListBindings),
    ),
    route(
        "restoreBinding",
        "POST",
        "/tenants/{tenant}/principals/{principal}/bindings/{binding}/restore",
        admin(AdminOperation::RestoreBinding),
    ),
    route(
        "listApiTokens",
        "GET",
        "/tenants/{tenant}/api-tokens",
        admin(AdminOperation::ListApiTokens),
    ),
    route(
        "createApiToken",
        "POST",
        "/tenants/{tenant}/api-tokens",
        admin(AdminOperation::CreateApiToken),
    ),
    route(
        "revokeApiToken",
        "DELETE",
        "/tenants/{tenant}/api-tokens/{id}",
        admin(AdminOperation::RevokeApiToken),
    ),
    route(
        "listWebhooks",
        "GET",
        "/tenants/{tenant}/webhooks",
        admin(AdminOperation::ListWebhooks),
    ),
    route(
        "createWebhook",
        "POST",
        "/tenants/{tenant}/webhooks",
        admin(AdminOperation::CreateWebhook),
    ),
    route(
        "getWebhook",
        "GET",
        "/tenants/{tenant}/webhooks/{id}",
        admin(AdminOperation::GetWebhook),
    ),
    route(
        "patchWebhook",
        "PATCH",
        "/tenants/{tenant}/webhooks/{id}",
        admin(AdminOperation::PatchWebhook),
    ),
    route(
        "deleteWebhook",
        "DELETE",
        "/tenants/{tenant}/webhooks/{id}",
        admin(AdminOperation::DeleteWebhook),
    ),
    route(
        "rotateWebhookSecret",
        "POST",
        "/tenants/{tenant}/webhooks/{id}/rotate-secret",
        admin(AdminOperation::RotateWebhookSecret),
    ),
    route(
        "pingWebhook",
        "POST",
        "/tenants/{tenant}/webhooks/{id}/ping",
        admin(AdminOperation::PingWebhook),
    ),
    route(
        "listDeliveries",
        "GET",
        "/tenants/{tenant}/webhooks/{id}/deliveries",
        admin(AdminOperation::ListDeliveries),
    ),
    route(
        "redeliverWebhook",
        "POST",
        "/tenants/{tenant}/webhooks/{id}/deliveries/{delivery}/redeliver",
        admin(AdminOperation::RedeliverWebhook),
    ),
    route(
        "listProviders",
        "GET",
        "/tenants/{tenant}/providers",
        admin(AdminOperation::ListProviders),
    ),
    route(
        "listExternalAccounts",
        "GET",
        "/tenants/{tenant}/external-accounts",
        admin(AdminOperation::ListExternalAccounts),
    ),
    route(
        "createExternalAccount",
        "POST",
        "/tenants/{tenant}/external-accounts",
        admin(AdminOperation::CreateExternalAccount),
    ),
    route(
        "deleteExternalAccount",
        "DELETE",
        "/tenants/{tenant}/external-accounts/{id}",
        admin(AdminOperation::DeleteExternalAccount),
    ),
    route(
        "listAuditEvents",
        "GET",
        "/tenants/{tenant}/audit-events",
        admin(AdminOperation::ListAuditEvents),
    ),
    route(
        "listOutbox",
        "GET",
        "/tenants/{tenant}/outbox",
        admin(AdminOperation::ListOutbox),
    ),
    route(
        "retryOutbox",
        "POST",
        "/tenants/{tenant}/outbox/{id}/retry",
        admin(AdminOperation::RetryOutbox),
    ),
    route(
        "inboundItip",
        "POST",
        "/tenants/{tenant}/itip/inbound",
        admin(AdminOperation::InboundItip),
    ),
];

/// Operations whose `DELETE` must carry `If-Match` (428 without it): calendars, principals and tenants.
const REQUIRES_IF_MATCH: [&str; 3] = ["deleteTenant", "deletePrincipal", "deleteCalendar"];

/// `POST` operations that need an `Idempotency-Key` (400 without it): the batch upsert.
const REQUIRES_IDEMPOTENCY_KEY: [&str; 1] = ["batchObjects"];

const API_DESCRIPTION: &str = "\
The management API of Davhaven: provisioning of tenants, principals and memberships, credentials and client \
configuration, calendars and grants, managed calendar objects with batch upsert, changes feeds, webhooks, provider \
accounts, audit events, outbox inspection and the inbound iTIP endpoint for mail gateways.

**Conventions.** Paths use the immutable natural keys (tenant slug, principal name, calendar slug, external key). \
JSON is snake_case, timestamps are RFC 3339 in UTC. Mutable resources return an `ETag` derived from their `version`; \
`PUT` creates or replaces, `PATCH` takes a JSON Merge Patch (RFC 7396), `If-Match` fails with 412, and deleting \
tenants, principals and calendars requires `If-Match` (428). Lists are cursor pages (`limit`, `cursor`, \
`next_cursor`, a relative `Link: rel=next`). Every `POST` accepts an `Idempotency-Key` (required for batch \
upserts); a replayed response carries `Idempotent-Replayed: true`, and a response that contains a secret is never \
stored or replayed: the retry is answered 409 `secret-not-replayable` with the status and `Location` of the first \
answer. Errors are RFC 9457 problem documents with a stable `code`; 429 and 503 carry `Retry-After`. Every \
operation lists the scopes a token needs in `x-required-scope` (any one of them suffices).

**Compatibility.** The API is versioned by its path; changes within `v1` are additive: new operations, new optional \
members and new values of enumerations, problem codes included. Clients must ignore members they do not know and \
tolerate enumeration values they do not know: the enumerations of this document list the values of this release, \
and a generated client has to be configured to keep an unknown value (see `docs/api.md`). Deprecations are \
announced with `Deprecation` and `Sunset` headers.";

/// The tags of the operations, with their descriptions.
const TAGS: [(&str, &str); 15] = [
    ("tenants", "Tenant provisioning with system tokens."),
    ("principals", "Users, groups, resources and service principals."),
    ("memberships", "The members of group principals."),
    ("app-passwords", "App passwords for DAV clients."),
    ("feed-tokens", "Tokens of subscription feeds."),
    ("client-config", "Configuration profiles for calendar clients."),
    (
        "calendars",
        "Calendars of a principal and the search across the tenant.",
    ),
    (
        "grants",
        "Sharing of calendars with users, groups and service principals.",
    ),
    ("events", "Calendar objects, written as JSON events or iCalendar."),
    ("changes", "The changes feed of a calendar."),
    ("api-tokens", "API tokens of a tenant."),
    ("webhooks", "Outbound webhook subscriptions and their deliveries."),
    ("providers", "Calendar providers and connected external accounts."),
    ("audit", "The audit log."),
    ("outbox", "Inspection and retry of outbox items."),
];

/// Adds the extensions and the problem responses of one operation.
fn annotate_operation(operation: &mut PathOperation, method: &str) {
    let Some(spec) = operation
        .operation_id
        .as_deref()
        .and_then(|id| ROUTES.iter().find(|route| route.operation_id == id))
    else {
        return;
    };
    let scopes: Vec<&str> = spec.authority.scopes().into_iter().map(Scope::as_str).collect();
    let extensions = operation.extensions.get_or_insert_with(Default::default);
    extensions.insert("x-required-scope".to_owned(), json!(scopes));
    extensions.insert(
        "x-davhaven-operation".to_owned(),
        json!(spec.authority.operation_names()),
    );

    let takes_a_body = operation.request_body.is_some();
    let conditional = declares_conditional_header(operation);
    let secret = success_declares_header(operation, "Cache-Control");

    for status in COMMON_PROBLEMS {
        add_problem(operation, status);
    }
    if takes_a_body {
        for status in BODY_PROBLEMS {
            add_problem(operation, status);
        }
    }
    if method == "POST" {
        // Every POST accepts an Idempotency-Key, and the same key for another request is 422.
        let kind = if REQUIRES_IDEMPOTENCY_KEY.contains(&spec.operation_id) {
            KeyKind::Required
        } else if secret {
            KeyKind::Secret
        } else {
            KeyKind::Replays
        };
        add_idempotency_key(operation, kind);
        add_problem(operation, "422");
    }
    if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
        add_problem(operation, "409");
    }
    if conditional {
        add_problem(operation, "412");
    }
    if REQUIRES_IF_MATCH.contains(&spec.operation_id) {
        add_problem(operation, "428");
    }
    for (operation_id, status) in OPERATION_PROBLEMS {
        if operation_id == spec.operation_id {
            add_problem(operation, status);
        }
    }
}

/// Registers a schema and everything it refers to as a component.
fn register<T: ToSchema>(components: &mut Components) {
    let mut referenced = Vec::new();
    T::schemas(&mut referenced);
    components.schemas.extend(referenced);
    components.schemas.insert(T::name().into_owned(), T::schema());
}

/// Fills in the metadata and annotates every operation of the registered routes.
fn finish(openapi: &mut OpenApi) {
    openapi.info = InfoBuilder::new()
        .title("Davhaven management API")
        .version("1.0.0")
        .description(Some(API_DESCRIPTION))
        .license(Some(
            LicenseBuilder::new()
                .name("Apache-2.0 OR MIT")
                .identifier(Some("Apache-2.0 OR MIT"))
                .build(),
        ))
        .build();
    openapi.servers = Some(vec![Server::new("/api/v1")]);
    openapi.tags = Some(
        TAGS.iter()
            .map(|(name, description)| TagBuilder::new().name(*name).description(Some(*description)).build())
            .collect(),
    );
    openapi.security = Some(vec![SecurityRequirement::new(SECURITY_SCHEME, Vec::<String>::new())]);

    let components = openapi.components.get_or_insert_with(Components::new);
    components.add_security_scheme(
        SECURITY_SCHEME,
        SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("dvh_pat_{prefix}_{secret}")
                .description(Some(
                    "An API token in the `Authorization: Bearer` header. System tokens manage tenants, \
                     tenant tokens administer one tenant within their scopes, principal tokens act as their \
                     principal. Tokens are never accepted in URLs or cookies.",
                ))
                .build(),
        ),
    );
    register::<davhaven_wire::ProblemDetails>(components);
    for (name, schema) in davhaven_wire::schema::shared_components() {
        components.schemas.entry(name).or_insert(schema);
    }
    register_problems(components);
    register_idempotency_parameters(components);
    reference_page_items(components);

    for_each_operation(openapi, |method, operation| annotate_operation(operation, method));
    share_parameters(openapi);
    prune_unused_schemas(openapi);
}

/// The OpenAPI 3.1 document of the management API.
///
/// Needs no services: it is built from the registered routes. Calling it twice yields equal documents.
pub fn document() -> OpenApi {
    let mut openapi = api_router().into_openapi();
    finish(&mut openapi);
    openapi
}

#[cfg(test)]
mod tests;
