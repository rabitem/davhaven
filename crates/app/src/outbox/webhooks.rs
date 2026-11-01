//! Management of webhook subscriptions (PLAN 2.11): create, read, change, delete, rotate the signing secret, send a
//! test event, inspect and repeat deliveries.
//!
//! The signing secret is `whsec_{base64 of 32 random bytes}`. It is shown once (in the response that creates or
//! rotates it) and kept sealed with the secret sealer, bound to the tenant, the subscription row and the purpose
//! `webhook_secret`; the webhook handler opens it with the same associated data. A rotation keeps the previous
//! secret next to the new one, and deliveries are signed with both until the retry window has passed.
//!
//! Registration validates the URL with the egress policy (`HttpClient::validate_url`); the policy applies again on
//! every delivery. A tenant may have `outbox.max_webhooks_per_tenant` subscriptions, which bounds the work of
//! fanning one event out, and a test event can be sent to one subscription a few times a minute.
//!
//! # Rotation
//!
//! A rotation keeps the previous secret for the overlap (the retry window), so deliveries that were signed before
//! the rotation still verify at the receiver. Rotating **again** inside the overlap ends it for the secret before:
//! only the newest two secrets exist. That is also how a leaked secret is revoked at once: rotate twice. The
//! previous secret stays sealed in its row after the overlap but signs nothing any more.
//!
//! # Audit
//!
//! Creating, changing, deleting and rotating a subscription write audit records, and so do a test event and a
//! redelivery (`webhook.pinged`, `webhook.redelivered`): both make the server send a request to a host of the
//! tenant's choosing. The record of a change names the settings that changed and, when the URL changed, the host
//! (never the path or the query).

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use davhaven_domain::audit::{WebhookAudit, WebhookDeliveryAudit};
use davhaven_domain::events::WebhookPayload;
use davhaven_domain::{
    AdminOperation, AuditActor, AuditEvent, DeliveryId, Envelope, EventId, EventPayload, EventType, OutboxId,
    RequestContext, WebhookId, WebhookSubscription,
};
use davhaven_ports::{
    DeliveryRecord, DeliveryStatus as StoreDeliveryStatus, NewAudit, NewOutbox, OutboxMessage, OutboxStatus, PageReq,
    PortError, PortErrorKind, RateKey, SealAad, StoreError, Tx, TxMode, WebhookDelivery,
};
use davhaven_wire::{
    DeliveryStatus, DeliveryView, Page, WebhookCreate, WebhookCreated, WebhookSecretRotated, WebhookView,
};
use secrecy::SecretString;
use url::Url;

use super::admin;
use crate::error::{AppError, AppResult, SafeMessage};
use crate::paging;
use crate::services::{Conditions, MergePatch, PageRequest, WebhookService};
use crate::wiring::AppCore;

const LISTING_WEBHOOKS: &str = "webhooks";
const LISTING_DELIVERIES: &str = "deliveries";

/// The prefix of signing secrets.
const SECRET_PREFIX: &str = "whsec_";

/// The longest description of a subscription, in characters.
const MAX_DESCRIPTION_CHARS: usize = 500;

/// The longest URL of a subscription, in bytes (the egress policy refuses longer ones as well).
const MAX_URL_BYTES: usize = 2048;

/// How often a `patch` repeats when a concurrent change makes its update lose the race and the request did not
/// ask for a specific version.
const PATCH_ATTEMPTS: u32 = 3;

/// The bucket of the rate limiter that bounds test events per subscription.
const PING_BUCKET: &str = "webhook_ping";

/// The [`WebhookService`] of the application.
#[derive(Debug, Clone)]
pub struct WebhookServiceImpl {
    core: AppCore,
}

impl WebhookServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }

    /// Makes a signing secret and seals it for subscription `id`.
    fn new_secret(&self, tenant: davhaven_domain::TenantId, id: WebhookId) -> AppResult<(SecretString, Vec<u8>)> {
        let deps = self.core.deps();
        let key = deps.ids.random_bytes(32);
        let secret = SecretString::from(format!("{SECRET_PREFIX}{}", STANDARD.encode(key)));
        let sealed = deps
            .sealer
            .seal(secret_text(&secret).as_bytes(), &SealAad::webhook_secret(tenant, id))?
            .into_bytes();
        Ok((secret, sealed))
    }

    /// Checks the URL against the egress policy.
    ///
    /// A URL the policy refuses and a host name that does not resolve get the same answer: the difference would
    /// let a tenant administrator probe the names of the deployment's private DNS one URL at a time. The operator
    /// sees the reason in the log of the egress adapter.
    async fn check_url(&self, url: &Url) -> AppResult<()> {
        if url.as_str().len() > MAX_URL_BYTES {
            return Err(field_error(
                "/url",
                "too-long",
                "The URL is too long (at most 2048 characters).",
            ));
        }
        match self.core.deps().http.validate_url(url).await {
            Ok(()) => Ok(()),
            Err(error) => Err(match error.kind {
                PortErrorKind::Rejected
                | PortErrorKind::Invalid
                | PortErrorKind::Unavailable
                | PortErrorKind::Timeout => {
                    tracing::info!(kind = error.kind.as_str(), "a webhook URL was refused at registration");
                    field_error("/url", "not-allowed", "The URL is not allowed as a webhook target.")
                }
                PortErrorKind::Internal | PortErrorKind::Unsupported => AppError::from(error),
            }),
        }
    }

    fn audit(&self, ctx: &RequestContext, event: AuditEvent) -> NewAudit {
        NewAudit {
            id: self.core.deps().ids.new_id(),
            actor: AuditActor::from_context(ctx, None, None),
            event,
        }
    }

    /// The audit details of `webhook`: the host of its URL when events are sent there for the first time or to a
    /// new place.
    fn webhook_audit(webhook: WebhookId, url: Option<&Url>) -> WebhookAudit {
        WebhookAudit {
            host: url.and_then(Url::host_str).map(str::to_owned),
            ..WebhookAudit::new(webhook)
        }
    }
}

fn secret_text(secret: &SecretString) -> &str {
    secrecy::ExposeSecret::expose_secret(secret)
}

fn bad_input(text: &'static str) -> AppError {
    AppError::invalid(SafeMessage::from_static(text))
}

/// An invalid request that names the field (`pointer`) and the problem (`code`).
fn field_error(pointer: &'static str, code: &'static str, text: &'static str) -> AppError {
    AppError::invalid(SafeMessage::from_static(text)).with_field_error(pointer, code, SafeMessage::from_static(text))
}

/// Normalizes the writable fields: a description without control characters and within its limit, at least one
/// event type and every event type once.
fn normalize(mut body: WebhookCreate) -> AppResult<WebhookCreate> {
    if let Some(description) = &body.description {
        if description.chars().count() > MAX_DESCRIPTION_CHARS {
            return Err(field_error(
                "/description",
                "too-long",
                "The description is too long (at most 500 characters).",
            ));
        }
        if description.chars().any(char::is_control) {
            return Err(field_error(
                "/description",
                "control-characters",
                "The description must not contain control characters.",
            ));
        }
    }
    if body.events.contains(&EventType::WebhookPing) {
        // The test event goes to the one subscription that asks for it, whatever its filter says.
        return Err(field_error(
            "/events",
            "not-allowed",
            "webhook.ping is sent by the ping endpoint and cannot be subscribed to.",
        ));
    }
    if body.events.is_empty() {
        // A subscription without events would be silent; that is never what a client means.
        return Err(field_error(
            "/events",
            "empty",
            "Name at least one event type; a subscription without events receives nothing.",
        ));
    }
    if body.description.as_deref().is_some_and(|text| text.trim().is_empty()) {
        body.description = None;
    }
    let mut seen = Vec::with_capacity(body.events.len());
    body.events.retain(|event| {
        let first = !seen.contains(event);
        seen.push(*event);
        first
    });
    Ok(body)
}

fn view(subscription: &WebhookSubscription) -> WebhookView {
    WebhookView {
        id: subscription.id,
        url: subscription.url.clone(),
        description: subscription.description.clone(),
        events: subscription.events.clone(),
        include_details: subscription.include_details,
        active: subscription.active,
        failure_count: subscription.failure_count,
        disabled_reason: subscription.disabled_reason.clone(),
        secret_rotated_at: subscription.secret_rotated_at,
        created_at: subscription.created_at,
        updated_at: subscription.updated_at,
        version: subscription.version,
    }
}

/// The delivery as the API shows it.
pub(crate) fn delivery_view(record: &DeliveryRecord) -> DeliveryView {
    DeliveryView {
        id: record.id,
        webhook_id: record.subscription_id,
        event_id: record.event_id,
        status: match record.status {
            StoreDeliveryStatus::Pending => DeliveryStatus::Pending,
            StoreDeliveryStatus::Delivered => DeliveryStatus::Delivered,
            StoreDeliveryStatus::Failed => DeliveryStatus::Failed,
            StoreDeliveryStatus::Dead => DeliveryStatus::Dead,
        },
        attempts: record.attempts,
        response_status: record.response_status,
        last_error: record.last_error.clone(),
        at: record.at,
    }
}

/// The names of the writable settings that differ between `before` and `after`.
fn changed_fields(before: &WebhookSubscription, after: &WebhookSubscription) -> Vec<String> {
    [
        ("url", before.url != after.url),
        ("description", before.description != after.description),
        ("events", before.events != after.events),
        ("include_details", before.include_details != after.include_details),
        ("active", before.active != after.active),
    ]
    .into_iter()
    .filter(|(_, changed)| *changed)
    .map(|(name, _)| name.to_owned())
    .collect()
}

/// The writable form of a subscription, for merge patches.
fn writable(subscription: &WebhookSubscription) -> WebhookCreate {
    WebhookCreate {
        url: subscription.url.clone(),
        description: subscription.description.clone(),
        events: subscription.events.clone(),
        include_details: subscription.include_details,
        active: subscription.active,
    }
}

async fn load(tx: &mut dyn Tx, id: WebhookId) -> AppResult<WebhookSubscription> {
    Ok(tx.webhooks().get(id).await?)
}

#[async_trait]
impl WebhookService for WebhookServiceImpl {
    async fn create(&self, ctx: &RequestContext, request: WebhookCreate) -> AppResult<WebhookCreated> {
        admin(ctx, AdminOperation::CreateWebhook)?;
        let body = normalize(request)?;
        self.check_url(&body.url).await?;
        let deps = self.core.deps();
        let id = WebhookId::from_uuid(deps.ids.new_id());
        let (secret, sealed_secret) = self.new_secret(ctx.tenant, id)?;
        let now = deps.clock.now();
        let subscription = WebhookSubscription {
            id,
            tenant_id: ctx.tenant,
            url: body.url,
            description: body.description,
            sealed_secret,
            sealed_secret_previous: None,
            secret_rotated_at: None,
            events: body.events,
            include_details: body.include_details,
            active: body.active,
            failure_count: 0,
            disabled_reason: None,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let limit = deps.config.outbox.max_webhooks_per_tenant;
        let existing = tx.webhooks().list(PageReq::first(limit.saturating_add(1))).await?;
        if u32::try_from(existing.items.len()).is_ok_and(|count| count >= limit) {
            return Err(AppError::conflict().with_public_message(SafeMessage::from_static(
                "The tenant has reached the limit of webhook subscriptions; delete one first.",
            )));
        }
        let stored = tx.webhooks().create(subscription).await?;
        tx.audit()
            .append(self.audit(
                ctx,
                AuditEvent::WebhookCreated(Self::webhook_audit(id, Some(&stored.url))),
            ))
            .await?;
        tx.commit().await?;
        Ok(WebhookCreated {
            webhook: view(&stored),
            secret: secret_text(&secret).to_owned(),
        })
    }

    async fn list(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<WebhookView>> {
        admin(ctx, AdminOperation::ListWebhooks)?;
        let request = paging::page_request(&self.core, ctx, LISTING_WEBHOOKS, &page)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let rows = tx.webhooks().list(request).await?;
        tx.commit().await?;
        let next = paging::next_cursor(&self.core, ctx, LISTING_WEBHOOKS, rows.next)?;
        Ok(Page::new(rows.items.iter().map(view).collect(), next))
    }

    async fn get(&self, ctx: &RequestContext, id: WebhookId) -> AppResult<WebhookView> {
        admin(ctx, AdminOperation::GetWebhook)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let subscription = load(tx.as_mut(), id).await?;
        tx.commit().await?;
        Ok(view(&subscription))
    }

    async fn patch(
        &self,
        ctx: &RequestContext,
        id: WebhookId,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<WebhookView> {
        admin(ctx, AdminOperation::PatchWebhook)?;
        let deps = self.core.deps();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let current = {
                let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadOnly).await?;
                let current = load(tx.as_mut(), id).await?;
                tx.commit().await?;
                current
            };
            conditions.check(Some(current.version))?;
            let mut document = serde_json::to_value(writable(&current)).map_err(AppError::internal)?;
            patch.apply(&mut document);
            let body = normalize(
                serde_json::from_value::<WebhookCreate>(document)
                    .map_err(|_| bad_input("The patched subscription is not valid."))?,
            )?;
            if body.url != current.url {
                self.check_url(&body.url).await?;
            }
            let reactivated = body.active && !current.active;
            let updated = WebhookSubscription {
                url: body.url,
                description: body.description,
                events: body.events,
                include_details: body.include_details,
                active: body.active,
                // A subscription that is switched on again starts with a clean record.
                failure_count: if reactivated { 0 } else { current.failure_count },
                disabled_reason: if body.active {
                    None
                } else {
                    current.disabled_reason.clone()
                },
                ..current.clone()
            };
            let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
            let stored = match tx.webhooks().update(updated, current.version).await {
                Ok(stored) => stored,
                // Changed since it was read. A request that named a version fails (the client decides); one that
                // did not is computed again against the new state, a few times (PLAN 2.7).
                Err(StoreError::PreconditionFailed) if conditions.if_match.is_none() && attempt < PATCH_ATTEMPTS => {
                    continue;
                }
                Err(StoreError::PreconditionFailed) => return Err(AppError::precondition_failed()),
                Err(error) => return Err(error.into()),
            };
            let details = WebhookAudit {
                fields: changed_fields(&current, &stored),
                ..Self::webhook_audit(id, (stored.url != current.url).then_some(&stored.url))
            };
            tx.audit()
                .append(self.audit(ctx, AuditEvent::WebhookUpdated(details)))
                .await?;
            tx.commit().await?;
            return Ok(view(&stored));
        }
    }

    async fn delete(&self, ctx: &RequestContext, id: WebhookId) -> AppResult<()> {
        admin(ctx, AdminOperation::DeleteWebhook)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        tx.webhooks().delete(id).await?;
        tx.audit()
            .append(self.audit(ctx, AuditEvent::WebhookDeleted(Self::webhook_audit(id, None))))
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn rotate_secret(&self, ctx: &RequestContext, id: WebhookId) -> AppResult<WebhookSecretRotated> {
        admin(ctx, AdminOperation::RotateWebhookSecret)?;
        let deps = self.core.deps();
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let current = load(tx.as_mut(), id).await?;
        let (secret, sealed) = self.new_secret(ctx.tenant, id)?;
        let rotated_at = deps.clock.now();
        let updated = WebhookSubscription {
            sealed_secret_previous: Some(current.sealed_secret.clone()),
            sealed_secret: sealed,
            secret_rotated_at: Some(rotated_at),
            ..current.clone()
        };
        match tx.webhooks().update(updated, current.version).await {
            Ok(_) => {}
            // Another change won the race while the secret was made: nothing was rotated, the caller tries again.
            Err(StoreError::PreconditionFailed) => {
                return Err(AppError::conflict().with_public_message(SafeMessage::from_static(
                    "The subscription changed while its secret was rotated; try again.",
                )));
            }
            Err(error) => return Err(error.into()),
        }
        tx.audit()
            .append(self.audit(ctx, AuditEvent::WebhookSecretRotated(Self::webhook_audit(id, None))))
            .await?;
        tx.commit().await?;
        Ok(WebhookSecretRotated {
            secret: secret_text(&secret).to_owned(),
            rotated_at,
        })
    }

    async fn ping(&self, ctx: &RequestContext, id: WebhookId) -> AppResult<DeliveryView> {
        admin(ctx, AdminOperation::PingWebhook)?;
        let deps = self.core.deps();
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let subscription = load(tx.as_mut(), id).await?;
        if !subscription.active {
            return Err(AppError::conflict().with_public_message(SafeMessage::from_static(
                "The subscription is disabled; activate it before sending a test event.",
            )));
        }
        // A test event goes to whatever host the subscription names: keep a tenant from using it as a trigger.
        // A limiter that cannot answer does not block the operator.
        let key = RateKey::new(PING_BUCKET, id.to_string());
        if let Ok(decision) = deps.rate_limiter.check(&key, 1).await
            && !decision.allowed
        {
            return Err(AppError::rate_limited(
                decision.retry_after.unwrap_or(std::time::Duration::from_secs(60)),
            ));
        }
        let now = deps.clock.now();
        let envelope = Envelope::new(
            EventId::from_uuid(deps.ids.new_id()),
            EventType::WebhookPing,
            ctx.tenant,
            now,
            AuditActor::from_context(ctx, None, None),
            EventPayload::Webhook(WebhookPayload {
                webhook: id,
                reason: WebhookPayload::PING.to_owned(),
            }),
        )
        .map_err(AppError::internal)?;
        let delivery = DeliveryId::from_uuid(deps.ids.new_id());
        let record = tx
            .webhooks()
            .create_delivery(DeliveryRecord {
                id: delivery,
                tenant_id: ctx.tenant,
                subscription_id: id,
                event_id: envelope.id,
                status: StoreDeliveryStatus::Pending,
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
                    webhook: id,
                    envelope,
                    details: None,
                }),
            ))
            .await?;
        tx.audit()
            .append(self.audit(
                ctx,
                AuditEvent::WebhookPinged(WebhookDeliveryAudit { webhook: id, delivery }),
            ))
            .await?;
        tx.commit().await?;
        Ok(delivery_view(&record))
    }

    async fn deliveries(
        &self,
        ctx: &RequestContext,
        id: WebhookId,
        page: PageRequest,
    ) -> AppResult<Page<DeliveryView>> {
        admin(ctx, AdminOperation::ListDeliveries)?;
        // Cursors of different subscriptions must not be interchangeable.
        let listing = format!("{LISTING_DELIVERIES}/{id}");
        let request = paging::page_request(&self.core, ctx, &listing, &page)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let rows = tx.webhooks().list_deliveries(id, request).await?;
        tx.commit().await?;
        let next = paging::next_cursor(&self.core, ctx, &listing, rows.next)?;
        Ok(Page::new(rows.items.iter().map(delivery_view).collect(), next))
    }

    async fn redeliver(&self, ctx: &RequestContext, id: WebhookId, delivery: DeliveryId) -> AppResult<DeliveryView> {
        admin(ctx, AdminOperation::RedeliverWebhook)?;
        let deps = self.core.deps();
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let subscription = load(tx.as_mut(), id).await?;
        let record = tx.webhooks().get_delivery(delivery).await?;
        if record.subscription_id != id {
            return Err(AppError::not_found());
        }
        if !subscription.active {
            return Err(AppError::conflict().with_public_message(SafeMessage::from_static(
                "The subscription is disabled; activate it before sending again.",
            )));
        }
        // The event is kept in the outbox record that carried the delivery.
        let original = match tx.outbox().get(OutboxId::from_uuid(delivery.as_uuid())).await {
            Ok(original) => original,
            Err(StoreError::NotFound) => {
                return Err(AppError::conflict().with_public_message(SafeMessage::from_static(
                    "The event of this delivery has been purged and cannot be sent again.",
                )));
            }
            Err(error) => return Err(error.into()),
        };
        // A delivery that is still being attempted is left alone. One whose first record went dead without ever
        // settling it (the store was down for longer than the retry window) is not attempted any more, whatever
        // the row says; it shows in that nothing touched the row for twice the longest backoff, which an attempt
        // in progress always does.
        let now = deps.clock.now();
        let longest_pause =
            chrono::Duration::from_std(deps.config.outbox.backoff_max).unwrap_or(chrono::Duration::hours(1));
        let stalled = original.status == OutboxStatus::Dead && now - record.at > longest_pause * 2;
        let attempted = matches!(
            record.status,
            StoreDeliveryStatus::Pending | StoreDeliveryStatus::Failed
        ) && !stalled;
        if attempted {
            return Err(AppError::conflict()
                .with_public_message(SafeMessage::from_static("The delivery is still being attempted.")));
        }
        let Ok(OutboxMessage::Webhook(message)) = original.message() else {
            return Err(AppError::internal(PortError::internal(
                "the outbox record of a delivery does not hold a webhook message",
            )));
        };
        let reset = tx
            .webhooks()
            .update_delivery(
                DeliveryRecord {
                    status: StoreDeliveryStatus::Pending,
                    attempts: 0,
                    response_status: None,
                    last_error: None,
                    at: now,
                    ..record.clone()
                },
                record.version,
            )
            .await?;
        tx.outbox()
            .enqueue(NewOutbox::now(
                OutboxId::from_uuid(deps.ids.new_id()),
                OutboxMessage::Webhook(message),
            ))
            .await?;
        tx.audit()
            .append(self.audit(
                ctx,
                AuditEvent::WebhookRedelivered(WebhookDeliveryAudit { webhook: id, delivery }),
            ))
            .await?;
        tx.commit().await?;
        Ok(delivery_view(&reset))
    }
}

#[cfg(test)]
mod tests;
