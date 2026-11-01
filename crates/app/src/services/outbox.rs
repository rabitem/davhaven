//! Outbox inspection and retry.

use async_trait::async_trait;
use davhaven_domain::{OutboxId, RequestContext};
use davhaven_wire::{OutboxItemView, OutboxStatus, Page};

use super::common::PageRequest;
use crate::error::AppResult;

/// The filter of `GET …/outbox`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutboxFilter {
    /// Only items in this state.
    pub status: Option<OutboxStatus>,
}

impl OutboxFilter {
    /// Dead items only.
    pub const fn dead() -> Self {
        Self {
            status: Some(OutboxStatus::Dead),
        }
    }
}

/// Operator access to the outbox. Every method needs `outbox:manage`.
#[async_trait]
pub trait OutboxService: Send + Sync {
    /// Lists outbox items of the tenant ordered by id.
    ///
    /// # Errors
    ///
    /// `Forbidden`, `Invalid` for a bad cursor.
    async fn list(
        &self,
        ctx: &RequestContext,
        filter: OutboxFilter,
        page: PageRequest,
    ) -> AppResult<Page<OutboxItemView>>;

    /// Lists dead items (`list` with the dead filter).
    ///
    /// # Errors
    ///
    /// As [`list`](Self::list).
    async fn list_dead(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<OutboxItemView>> {
        self.list(ctx, OutboxFilter::dead(), page).await
    }

    /// Makes a dead item due again.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Conflict` for items that are not dead, `Forbidden`.
    async fn retry(&self, ctx: &RequestContext, id: OutboxId) -> AppResult<OutboxItemView>;
}
