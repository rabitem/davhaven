//! Operator access to the outbox: listing items and making dead ones due again.
//!
//! Webhook deliveries are not retried here: the retry window of a webhook runs from the creation of its record, so a
//! dead delivery that is older than the window would get one attempt and die again. They are repeated with
//! `…/webhooks/{id}/deliveries/{delivery}/redeliver`, which starts a new record with a fresh window.

use async_trait::async_trait;
use davhaven_domain::audit::OutboxAudit;
use davhaven_domain::{AdminOperation, AuditActor, AuditEvent, OutboxId, RequestContext};
use davhaven_ports::{NewAudit, OutboxRecord, OutboxStatus as StoreStatus, StoreError, TxMode, outbox::kind};
use davhaven_wire::{OutboxItemView, OutboxStatus, Page};

use super::admin;
use crate::error::{AppError, AppResult, SafeMessage};
use crate::paging;
use crate::services::{OutboxFilter, OutboxService, PageRequest};
use crate::wiring::AppCore;

const LISTING: &str = "outbox";

/// The [`OutboxService`] of the application.
#[derive(Debug, Clone)]
pub struct OutboxServiceImpl {
    core: AppCore,
}

impl OutboxServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

const fn store_status(status: OutboxStatus) -> StoreStatus {
    match status {
        OutboxStatus::Pending => StoreStatus::Pending,
        OutboxStatus::InFlight => StoreStatus::InFlight,
        OutboxStatus::Done => StoreStatus::Done,
        OutboxStatus::Dead => StoreStatus::Dead,
    }
}

const fn wire_status(status: StoreStatus) -> OutboxStatus {
    match status {
        StoreStatus::Pending => OutboxStatus::Pending,
        StoreStatus::InFlight => OutboxStatus::InFlight,
        StoreStatus::Done => OutboxStatus::Done,
        StoreStatus::Dead => OutboxStatus::Dead,
    }
}

/// The view of a record: the payload stays inside, it can name recipients.
fn view(record: &OutboxRecord) -> OutboxItemView {
    OutboxItemView {
        id: record.id,
        kind: record.kind.clone(),
        status: wire_status(record.status),
        attempts: record.attempts,
        next_attempt_at: record.next_attempt_at,
        last_error: record.last_error.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

#[async_trait]
impl OutboxService for OutboxServiceImpl {
    async fn list(
        &self,
        ctx: &RequestContext,
        filter: OutboxFilter,
        page: PageRequest,
    ) -> AppResult<Page<OutboxItemView>> {
        admin(ctx, AdminOperation::ListOutbox)?;
        // The filter is part of what a cursor is bound to: a cursor of `?status=dead` is no cursor of another list.
        let listing = filter.status.map_or_else(
            || LISTING.to_owned(),
            |status| format!("{LISTING}?status={}", store_status(status)),
        );
        let request = paging::page_request(&self.core, ctx, &listing, &page)?;
        let store_filter = davhaven_ports::OutboxFilter {
            status: filter.status.map(store_status),
            kind: None,
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let rows = tx.outbox().list(&store_filter, request).await?;
        tx.commit().await?;
        let next = paging::next_cursor(&self.core, ctx, &listing, rows.next)?;
        Ok(Page::new(rows.items.iter().map(view).collect(), next))
    }

    async fn retry(&self, ctx: &RequestContext, id: OutboxId) -> AppResult<OutboxItemView> {
        admin(ctx, AdminOperation::RetryOutbox)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        if tx.outbox().get(id).await?.kind == kind::WEBHOOK {
            return Err(AppError::conflict().with_public_message(SafeMessage::from_static(
                "Webhook deliveries are repeated with the redeliver endpoint of their subscription.",
            )));
        }
        match tx.outbox().requeue(id).await {
            Ok(()) => {}
            Err(StoreError::PreconditionFailed) => {
                return Err(AppError::conflict()
                    .with_public_message(SafeMessage::from_static("Only dead items can be retried.")));
            }
            Err(error) => return Err(error.into()),
        }
        let record = tx.outbox().get(id).await?;
        tx.audit()
            .append(NewAudit {
                id: self.core.deps().ids.new_id(),
                actor: AuditActor::from_context(ctx, None, None),
                event: AuditEvent::OutboxRetried(OutboxAudit {
                    outbox: id,
                    kind: record.kind.clone(),
                }),
            })
            .await?;
        tx.commit().await?;
        tracing::info!(outbox = %id, tenant = %ctx.tenant, "a dead outbox item was made due again");
        Ok(view(&record))
    }
}
