//! Tenant administration (system tokens with the `system:tenants` scope).

use async_trait::async_trait;
use davhaven_domain::{RequestContext, TenantSlug};
use davhaven_wire::{Page, TenantView, TenantWrite};

use super::common::{Conditions, MergePatch, PageRequest, Upserted};
use crate::error::AppResult;

/// The natural key and the body of a tenant `PUT`.
#[derive(Debug, Clone, PartialEq)]
pub struct TenantSpec {
    /// The slug from the path.
    pub slug: TenantSlug,
    /// The request body.
    pub body: TenantWrite,
}

/// Tenant provisioning (PLAN 2.10, F0.10 `/tenants`).
///
/// These methods work across tenants and use system transactions; `ctx.tenant` is ignored (see
/// `AuthService::authenticate`). `get` is also open to tenant tokens with `principals:read` for their own
/// tenant.
#[async_trait]
pub trait TenantService: Send + Sync {
    /// Lists tenants ordered by id.
    ///
    /// # Errors
    ///
    /// `Forbidden` without `system:tenants`; `Invalid` for a bad cursor.
    async fn list(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<TenantView>>;

    /// Reads a tenant.
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown tenants and for tenants a tenant token may not see; `Forbidden` without scope.
    async fn get(&self, ctx: &RequestContext, slug: &TenantSlug) -> AppResult<TenantView>;

    /// Creates or replaces a tenant. A new tenant is provisioned with its default settings, the bootstrap data
    /// and a `tenant.created` audit event.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` for stale conditions, `Conflict` for a taken login domain, `Invalid` for invalid
    /// settings, `Forbidden` without scope.
    async fn upsert(
        &self,
        ctx: &RequestContext,
        spec: TenantSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<TenantView>>;

    /// Changes a tenant with a JSON Merge Patch (the slug is immutable).
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed`, `Invalid`, `Forbidden`.
    async fn patch(
        &self,
        ctx: &RequestContext,
        slug: &TenantSlug,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<TenantView>;

    /// Deletes a tenant and everything in it. Requires `If-Match`.
    ///
    /// # Errors
    ///
    /// `PreconditionRequired` without `If-Match`, `PreconditionFailed`, `NotFound`, `Forbidden`.
    async fn delete(&self, ctx: &RequestContext, slug: &TenantSlug, conditions: Conditions) -> AppResult<()>;
}
