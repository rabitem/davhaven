//! The `domain_event` outbox handler: the fan-out of committed domain events.
//!
//! The application writes `OutboxMessage::DomainEvent` in the transaction of the change that caused it. After
//! commit the dispatcher hands the record to [`DomainEventHandler`], which
//!
//! 1. expands one webhook delivery per active subscription of the tenant that subscribes to the event type: a
//!    `webhook_deliveries` row (`pending`) and an outbox record of the kind `webhook`, both written in one tenant
//!    transaction, and
//! 2. hands the envelope to every configured [`EventSink`](davhaven_ports::EventSink).
//!
//! The expansion is idempotent: the id of a delivery is derived from the event id and the subscription id, so a
//! record that is handled again (after a retry because a sink was unavailable, or after a lease expired) creates
//! nothing twice. The delivery id doubles as the id of its outbox record. A tenant has a bounded number of
//! subscriptions (`outbox.max_webhooks_per_tenant`), which bounds the work of one expansion.
//!
//! A subscription with `include_details` gets the details of the objects the event is about inside its delivery
//! (the `details` module): they are read here, from managed and group calendars only, and never by the
//! webhook adapter.
//!
//! Event sinks are at-least-once like everything else in the outbox: when one asks for a retry the whole record is
//! handled again, and sinks that already accepted the event see it again. They deduplicate on the envelope id.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{DeliveryId, Envelope, EventId, EventType, OutboxId, TenantId, WebhookId};
use davhaven_ports::{
    DeliveryRecord, DeliveryStatus, HandlerError, NewOutbox, OutboxHandler, OutboxMessage, OutboxRecord, StoreError,
    TxMode, WebhookDelivery, outbox::kind,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::details;
use crate::imip::{CalendarBackend, IcalBackend};
use crate::wiring::AppCore;

/// The id of the delivery of `event` to `webhook`.
///
/// The id is UUIDv7-shaped so that listings ordered by id are chronological: the timestamp bytes are those of the
/// event id, the remaining bits come from a hash of both ids. The same pair always yields the same id.
pub fn delivery_id(event: EventId, webhook: WebhookId) -> DeliveryId {
    let mut hasher = Sha256::new();
    hasher.update(b"davhaven/webhook-delivery/v1");
    hasher.update(event.as_uuid().as_bytes());
    hasher.update(webhook.as_uuid().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    for (slot, byte) in bytes.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    for (slot, byte) in bytes.iter_mut().zip(event.as_uuid().as_bytes().iter()).take(6) {
        *slot = *byte;
    }
    if let Some(version) = bytes.get_mut(6) {
        *version = 0x70 | (*version & 0x0f);
    }
    if let Some(variant) = bytes.get_mut(8) {
        *variant = 0x80 | (*variant & 0x3f);
    }
    DeliveryId::from_uuid(Uuid::from_bytes(bytes))
}

/// The handler of the `domain_event` kind.
pub struct DomainEventHandler {
    core: AppCore,
    backend: Arc<dyn CalendarBackend>,
}

impl core::fmt::Debug for DomainEventHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DomainEventHandler").finish_non_exhaustive()
    }
}

impl DomainEventHandler {
    /// Creates the handler on the shared application core, with the iCalendar layer of the application.
    pub fn new(core: AppCore) -> Self {
        let backend = IcalBackend::new(core.deps().limits.ical.clone());
        Self::with_backend(core, Arc::new(backend))
    }

    /// Creates the handler with another calendar backend (tests).
    pub fn with_backend(core: AppCore, backend: Arc<dyn CalendarBackend>) -> Self {
        Self { core, backend }
    }

    /// Whether a subscription to `event_type` asks for details.
    async fn wants_details(&self, tenant: TenantId, event_type: EventType) -> Result<bool, StoreError> {
        let mut tx = self.core.deps().database.begin(tenant, TxMode::ReadOnly).await?;
        let subscriptions = tx.webhooks().subscribed_to(event_type).await?;
        tx.commit().await?;
        Ok(subscriptions.iter().any(|subscription| subscription.include_details))
    }

    /// Creates the deliveries of `envelope` for the subscriptions of `tenant`; returns how many are new.
    async fn fan_out(&self, tenant: TenantId, envelope: &Envelope) -> Result<usize, StoreError> {
        let deps = self.core.deps();
        // The details are read (and the summaries parsed) before the transaction that writes the deliveries opens.
        let details = if self.wants_details(tenant, envelope.event_type).await? {
            details::details(&self.core, self.backend.as_ref(), tenant, envelope).await?
        } else {
            None
        };
        let mut tx = deps.database.begin(tenant, TxMode::ReadWrite).await?;
        let subscriptions = tx.webhooks().subscribed_to(envelope.event_type).await?;
        let mut created = 0;
        for subscription in subscriptions {
            let delivery = delivery_id(envelope.id, subscription.id);
            match tx.webhooks().get_delivery(delivery).await {
                Ok(_existing) => continue,
                Err(StoreError::NotFound) => {}
                Err(error) => return Err(error),
            }
            let now = deps.clock.now();
            tx.webhooks()
                .create_delivery(DeliveryRecord {
                    id: delivery,
                    tenant_id: tenant,
                    subscription_id: subscription.id,
                    event_id: envelope.id,
                    status: DeliveryStatus::Pending,
                    attempts: 0,
                    response_status: None,
                    last_error: None,
                    at: now,
                    created_at: now,
                    updated_at: now,
                    version: 1,
                })
                .await?;
            tx.outbox()
                .enqueue(NewOutbox::now(
                    OutboxId::from_uuid(delivery.as_uuid()),
                    OutboxMessage::Webhook(WebhookDelivery {
                        delivery,
                        webhook: subscription.id,
                        envelope: envelope.clone(),
                        details: if subscription.include_details {
                            details.clone()
                        } else {
                            None
                        },
                    }),
                ))
                .await?;
            created += 1;
        }
        tx.commit().await?;
        Ok(created)
    }

    /// Hands the envelope to every sink; transient failures ask for another pass of the record.
    async fn deliver_to_sinks(&self, envelope: &Envelope) -> Result<(), HandlerError> {
        let mut transient = Vec::new();
        for sink in &self.core.deps().event_sinks {
            match sink.deliver(envelope).await {
                Ok(()) => {}
                Err(error) if error.is_retryable() => {
                    tracing::warn!(sink = sink.name(), event = %envelope.id, error = %error.message(), "an event sink is unavailable");
                    transient.push(format!("the event sink `{}` is not available", sink.name()));
                }
                Err(error) => {
                    tracing::warn!(sink = sink.name(), event = %envelope.id, error = %error.message(), "an event sink refused an event; it is dropped for this sink");
                }
            }
        }
        if transient.is_empty() {
            Ok(())
        } else {
            Err(HandlerError::retryable(transient.join("; ")))
        }
    }
}

#[async_trait]
impl OutboxHandler for DomainEventHandler {
    fn kind(&self) -> &'static str {
        kind::DOMAIN_EVENT
    }

    async fn handle(&self, record: &OutboxRecord) -> Result<(), HandlerError> {
        let envelope = match record.message() {
            Ok(OutboxMessage::DomainEvent(envelope)) => envelope,
            Ok(other) => {
                return Err(HandlerError::permanent(format!(
                    "the record holds a `{}` message, not a domain event",
                    other.kind()
                )));
            }
            Err(_) => return Err(HandlerError::permanent("the payload of the record cannot be decoded")),
        };
        if envelope.tenant != record.tenant_id {
            return Err(HandlerError::permanent(
                "the tenant of the event is not the tenant of the record",
            ));
        }
        // A ping goes to the one subscription that asked for it (`WebhookService::ping`), never to subscribers.
        if envelope.event_type != EventType::WebhookPing {
            let created = self.fan_out(record.tenant_id, &envelope).await?;
            tracing::debug!(event = %envelope.id, kind = envelope.event_type.as_str(), created, "domain event fanned out");
        }
        self.deliver_to_sinks(&envelope).await
    }
}

#[cfg(test)]
mod tests;
