//! The tenant row, as a tenant transaction sees it.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{DomainName, Tenant, TenantId, TenantSettings, TenantSlug, TenantStatus};
use davhaven_ports::{StoreError, TenantRepo};
use uuid::Uuid;

use super::{DbResult, corrupt, decode, decode_opt};
use crate::tx::PgTx;

/// A row of `tenants`.
#[derive(sqlx::FromRow)]
pub(super) struct TenantRow {
    id: Uuid,
    slug: String,
    display_name: String,
    login_domain: Option<String>,
    status: String,
    settings: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl TenantRow {
    /// Validates the row and builds the entity.
    pub(super) fn into_tenant(self) -> Result<Tenant, StoreError> {
        Ok(Tenant {
            id: TenantId::from_uuid(self.id),
            slug: decode("tenant slug", TenantSlug::parse(&self.slug))?,
            display_name: self.display_name,
            login_domain: decode_opt("login domain", self.login_domain.as_deref(), DomainName::parse)?,
            status: decode("tenant status", self.status.parse::<TenantStatus>())?,
            settings: serde_json::from_value::<TenantSettings>(self.settings)
                .map_err(|error| corrupt("tenant settings", error))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

#[async_trait]
impl TenantRepo for PgTx {
    async fn get(&mut self) -> Result<Tenant, StoreError> {
        observed!("tenant.get", {
            let row =
                sqlx::query_as::<_, TenantRow>(concat!("SELECT ", tenant_columns!(""), " FROM tenants WHERE id = $1"))
                    .bind(self.tenant.as_uuid())
                    .fetch_optional(&mut *self.conn)
                    .await
                    .db()?;
            row.ok_or(StoreError::NotFound)?.into_tenant()
        })
    }
}
