//! The tenant row, as a tenant transaction sees it.

use async_trait::async_trait;
use davhaven_domain::Tenant;
use davhaven_ports::{StoreError, TenantRepo};

use crate::tx::MemTx;

#[async_trait]
impl TenantRepo for MemTx {
    async fn get(&mut self) -> Result<Tenant, StoreError> {
        observed!(
            "tenant.get",
            self.guard
                .tenants
                .get(&self.tenant)
                .map(|entry| entry.tenant.clone())
                .ok_or(StoreError::NotFound)
        )
    }
}
