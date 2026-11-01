//! Audit event resources.

use axum::extract::State;
use chrono::{DateTime, Utc};
use davhaven_app::services::AuditFilter;
use davhaven_domain::TenantSlug;
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::{AuditEventView, Page};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::extract::{Keys, PageParams, Paging, Params};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new().routes(routes!(list_audit_events))
}

/// The filters of the audit listing; every given filter must match.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AuditQuery {
    /// Only this action, for example `credential.created`.
    action: Option<String>,
    /// Only this target, written `kind:id`.
    target: Option<String>,
    /// Only events at or after this instant (RFC 3339, written with `Z`; encode `+` as `%2B`).
    #[param(value_type = Option<String>, format = DateTime)]
    since: Option<DateTime<Utc>>,
    /// Only events before this instant (RFC 3339).
    #[param(value_type = Option<String>, format = DateTime)]
    until: Option<DateTime<Utc>>,
}

/// Lists the audit events of a tenant.
///
/// Events are ordered by id. They carry the actor, the action, the target and details that never contain event
/// bodies or secrets.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/audit-events",
    operation_id = "listAuditEvents",
    tag = "audit",
    params(("tenant" = String, Path, description = "The tenant slug."), AuditQuery, PageParams),
    responses((status = 200, description = "A page of audit events.", body = Page<AuditEventView>))
)]
pub(crate) async fn list_audit_events(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys(_tenant): Keys<TenantSlug>,
    Params(query): Params<AuditQuery>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let filter = AuditFilter {
        action: query.action,
        target: query.target,
        since: query.since,
        until: query.until,
    };
    let page = state.services.audit.list(&ctx, filter, paging.request()).await?;
    Ok(paging.reply(&page))
}
