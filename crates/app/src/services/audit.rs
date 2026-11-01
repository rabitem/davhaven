//! Audit events.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::RequestContext;
use davhaven_wire::{AuditEventView, Page};

use super::common::PageRequest;
use crate::error::AppResult;

/// The filters of `GET …/audit-events`; every set field must match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditFilter {
    /// Only this action, for example `credential.created`.
    pub action: Option<String>,
    /// Only this target, as `kind:id`.
    pub target: Option<String>,
    /// Only events at or after this time.
    pub since: Option<DateTime<Utc>>,
    /// Only events before this time.
    pub until: Option<DateTime<Utc>>,
}

/// Reading the audit log. Writing happens inside the transaction of the audited change.
#[async_trait]
pub trait AuditService: Send + Sync {
    /// Lists audit events ordered by id. Needs `audit:read`.
    ///
    /// # Errors
    ///
    /// `Forbidden`, `Invalid` for a bad cursor or filter.
    async fn list(
        &self,
        ctx: &RequestContext,
        filter: AuditFilter,
        page: PageRequest,
    ) -> AppResult<Page<AuditEventView>>;
}
