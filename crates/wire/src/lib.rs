//! Wire types of the Davhaven management API, MCP tools and webhooks.
//!
//! These DTOs are the published contract: they derive OpenAPI (`utoipa`) and JSON Schema (`schemars`)
//! descriptions, and `xtask contracts` exports the generated documents for drift checks. The problem code
//! catalog maps every error to its HTTP status, DAV status and precondition element and MCP form.
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | Pagination | [`page`] |
//! | Errors (RFC 9457 problems and the catalog of codes) | [`problem`] |
//! | Events as JSON | [`event`] |
//! | Tenants, principals, calendars, grants | [`tenant`], [`principal`], [`calendar`], [`grant`] |
//! | Credentials and client configuration | [`credentials`], [`client_config`] |
//! | Batch upsert and the changes feed | [`batch`], [`changes`] |
//! | Webhooks, outbox, audit | [`webhook`], [`outbox`], [`audit`] |
//! | Provider accounts and inbound iTIP | [`external_account`], [`itip`] |
//! | MCP tool inputs and outputs | [`mcp`] |
//! | ETags of versioned resources | [`version`] |
//! | Generated contract documents | [`schema`], [`mcp::tools_document`] |
//!
//! Layering (`ENGINEERING_RULES` R1): this crate depends on `davhaven-domain` only. Domain types appear in
//! the DTOs wherever the JSON form is the one the domain defines (ids, natural keys, enumerations).

#![forbid(unsafe_code)]

pub mod audit;
pub mod batch;
pub mod calendar;
pub mod changes;
pub mod client_config;
pub mod credentials;
pub mod event;
pub mod external_account;
pub mod grant;
pub mod itip;
pub mod mcp;
pub mod outbox;
pub mod page;
pub mod principal;
pub mod problem;
pub mod schema;
pub mod tenant;
pub mod version;
pub mod webhook;

pub use audit::AuditEventView;
pub use batch::{BatchItem, BatchItemResult, BatchMode, BatchOutcome, BatchRequest, BatchRequestError, BatchResult};
pub use calendar::{CalendarView, CalendarWrite, HomeBindingView};
pub use changes::{ChangeKind, ChangeView, ChangesResponse};
pub use client_config::{ClientConfigDavx5, ClientConfigGeneric, ClientConfigRequest};
pub use credentials::{
    ApiTokenCreate, ApiTokenCreated, ApiTokenView, AppPasswordCreate, AppPasswordCreated, AppPasswordView,
    FeedTokenCreate, FeedTokenCreated, FeedTokenView,
};
pub use event::EventView;
pub use external_account::{AuthorizationUrl, ExternalAccountCreate, ExternalAccountView, ProviderView};
pub use grant::{GrantView, GrantWrite};
pub use itip::{AuthVerdict, InboundItipRequest, InboundItipResponse, InboundOutcome};
pub use outbox::{OutboxItemView, OutboxStatus};
pub use page::{Cursor, CursorError, Page};
pub use principal::{MembershipSet, PrincipalView, PrincipalWrite};
pub use problem::{FieldProblem, ProblemCode, ProblemDetails};
pub use tenant::{TenantView, TenantWrite};
pub use version::{etag_for_version, version_from_etag};
pub use webhook::{
    DeliveryStatus, DeliveryView, WebhookCreate, WebhookCreated, WebhookEnvelope, WebhookSecretRotated, WebhookView,
};
