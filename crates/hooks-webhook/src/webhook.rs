//! The `webhook` outbox handler: one HTTP delivery of one event to one subscription.
//!
//! The record carries a [`WebhookDelivery`] (delivery id, subscription id, the event envelope); the secrets, the URL
//! and the delivery bookkeeping live in the tenant's tables. An attempt
//!
//! 1. loads the subscription and the delivery (a deleted subscription or delivery means there is nothing left to
//!    do: the record is done) and skips deliveries that were delivered already. The details of the objects an event
//!    is about (`include_details`) arrive inside the record, written by the application when it fanned the event
//!    out from managed and group calendars; this handler reads no calendar data;
//! 2. opens the sealed secret, and the previous one during the overlap after a rotation;
//! 3. sends the envelope as JSON with the Standard Webhooks headers through the `HttpClient` port, which applies
//!    the egress policy on every send;
//! 4. settles in one tenant transaction: the delivery becomes `delivered`, `failed` (another attempt follows) or
//!    `dead`, and the failure counter of the subscription is reset by a delivery or raised by a delivery that went
//!    dead because of the receiver. A subscription whose deliveries went dead `max_consecutive_failures` times in a
//!    row is disabled, which raises `webhook.disabled` and an audit record.
//!
//! # What counts against a subscription
//!
//! The counter counts **deliveries that ended dead because of the receiver**, one per delivery, and a delivery that
//! succeeds resets it. A failed attempt that is retried counts for nothing: with the 24 hour retry window a
//! receiver that is down for an hour must not be switched off because twenty events were waiting for it, and one
//! event retried with the outbox backoff would otherwise use up the limit alone. Ending dead because of the
//! receiver means the retry window ended while the receiver still did not accept the event, or the egress policy
//! refuses the URL (a host that now resolves to a private address). A `410 Gone` disables the subscription at
//! once. Deliveries of a subscription that is switched off are skipped (see below) and count for nothing.
//!
//! Retries are bounded by time and not by the number of attempts: the dispatcher keeps rescheduling `Retryable`
//! failures with its backoff ([`OutboxHandler::limits_attempts`] is `false`), and the handler turns **every**
//! retryable failure, an unavailable store or a broken sealer included, into a permanent one when the outbox record
//! is older than `webhooks.retry_window` (24 hours by default), so no record is retried for ever. An operator can
//! send a dead delivery again (`…/redeliver`), which starts a record with a window of its own.
//!
//! What the outcome of the request means:
//!
//! | Answer | Delivery | Handler result |
//! | --- | --- | --- |
//! | 2xx | `delivered` | done |
//! | 410 | `dead`, subscription disabled (`endpoint_gone`) | permanent |
//! | other status, timeout, unreachable | `failed` | retryable (permanent after the retry window) |
//! | refused by the egress policy | `dead` (counts) | permanent |
//! | the subscription is switched off | `dead`, "the subscription is disabled" (counts for nothing) | done (the record is not a failure) |
//!
//! The client cuts the body of an answer at its size cap instead of failing (the status is all that counts), so a
//! receiver that echoes the request or answers with a page is judged by its status.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use davhaven_domain::audit::WebhookAudit;
use davhaven_domain::events::WebhookPayload;
use davhaven_domain::{
    AuditActor, AuditEvent, Envelope, EventId, EventPayload, EventType, OutboxId, TenantId, WebhookId,
};
use davhaven_ports::{
    Clock, Database, DeliveryRecord, DeliveryStatus, HandlerError, HttpClient, HttpPurpose, IdGenerator, NewAudit,
    NewOutbox, OutboundRequest, OutboxDecodeError, OutboxHandler, OutboxMessage, OutboxRecord, PluginContext,
    PluginError, PortError, PortErrorKind, PortLabel, SealAad, Sealed, SecretSealer, StoreError, TxMode,
    WebhookDelivery, observe, outbox::kind,
};
use davhaven_wire::WebhookEnvelope;
use http::{HeaderName, HeaderValue, Method};
use secrecy::ExposeSecret;

use crate::config::{PLUGIN, WebhooksConfig};
use crate::signing::{self, ID_HEADER, SIGNATURE_HEADER, SigningKey, TIMESTAMP_HEADER};

/// What `observe` labels the handler with.
const LABEL: PortLabel = PortLabel::new("outbox_handler", PLUGIN);

/// The `User-Agent` of deliveries.
const USER_AGENT: &str = concat!("Davhaven-Webhooks/", env!("CARGO_PKG_VERSION"));

/// What the delivery row says of a delivery that was not sent because its subscription is switched off.
pub const SKIPPED_ERROR: &str = "the subscription is disabled";

/// The reason recorded when a receiver answers 410 Gone.
pub const ENDPOINT_GONE: &str = WebhookPayload::ENDPOINT_GONE;

/// The reason recorded when a subscription reaches `max_consecutive_failures`.
pub const MAX_CONSECUTIVE_FAILURES: &str = WebhookPayload::MAX_CONSECUTIVE_FAILURES;

/// What one attempt came to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// The receiver accepted the event.
    Delivered { status: u16 },
    /// The attempt failed; another one is due unless the retry window ended.
    Failed { status: Option<u16>, error: String },
    /// The delivery cannot succeed any more.
    Dead {
        status: Option<u16>,
        error: String,
        /// Whether the receiver is to blame: the delivery counts against the subscription.
        counts: bool,
        /// A reason to disable the subscription right away.
        disable: Option<&'static str>,
    },
    /// The subscription is switched off: nothing is sent and nothing counts. The delivery row says why it was not
    /// sent, and the outbox record is done, because nothing failed that an operator has to look at.
    Skipped,
}

/// What settling the outcome decided.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Done,
    Retry(String),
    Dead(String),
}

/// The `webhook` handler.
pub struct WebhookHandler {
    database: Arc<dyn Database>,
    http: Arc<dyn HttpClient>,
    sealer: Arc<dyn SecretSealer>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    config: WebhooksConfig,
}

impl core::fmt::Debug for WebhookHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebhookHandler")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// What the first transaction of an attempt reads.
struct Loaded {
    subscription: davhaven_domain::WebhookSubscription,
    delivery: DeliveryRecord,
}

impl WebhookHandler {
    /// Creates the handler on the built ports of the plugin context.
    ///
    /// # Errors
    ///
    /// [`PluginError::MissingDependency`] when the context has no database or no HTTP client yet, and the
    /// validation error of the configuration.
    pub fn from_context(context: &PluginContext, config: WebhooksConfig) -> Result<Self, PluginError> {
        config.validate()?;
        Ok(Self {
            database: context.require_database(PLUGIN)?,
            http: context.require_http(PLUGIN)?,
            sealer: Arc::clone(&context.sealer),
            clock: Arc::clone(&context.clock),
            ids: Arc::clone(&context.ids),
            config,
        })
    }

    /// Reads the subscription and the delivery. `None` when either is gone.
    async fn load(&self, tenant: TenantId, delivery: &WebhookDelivery) -> Result<Option<Loaded>, StoreError> {
        let mut tx = self.database.begin(tenant, TxMode::ReadOnly).await?;
        let subscription = match tx.webhooks().get(delivery.webhook).await {
            Ok(subscription) => subscription,
            Err(StoreError::NotFound) => {
                tx.commit().await?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let record = match tx.webhooks().get_delivery(delivery.delivery).await {
            Ok(record) => record,
            Err(StoreError::NotFound) => {
                tx.commit().await?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        tx.commit().await?;
        Ok(Some(Loaded {
            subscription,
            delivery: record,
        }))
    }

    /// The keys that sign now: the current secret, and the previous one while the overlap after a rotation lasts.
    fn keys(
        &self,
        tenant: TenantId,
        subscription: &davhaven_domain::WebhookSubscription,
        now: DateTime<Utc>,
    ) -> Result<Vec<SigningKey>, &'static str> {
        let aad = SealAad::webhook_secret(tenant, subscription.id);
        let open = |sealed: &[u8]| -> Result<SigningKey, &'static str> {
            let bytes = self
                .sealer
                .open(&Sealed::from_bytes(sealed.to_vec()), &aad)
                .map_err(|_| "the signing secret cannot be opened")?;
            let text = core::str::from_utf8(bytes.expose_secret()).map_err(|_| "the signing secret is not valid")?;
            SigningKey::parse(text).map_err(|_| "the signing secret is not valid")
        };
        let mut keys = vec![open(&subscription.sealed_secret)?];
        let overlap = chrono::Duration::from_std(self.config.retry_window).unwrap_or(chrono::Duration::days(1));
        if let (Some(previous), Some(rotated_at)) =
            (&subscription.sealed_secret_previous, subscription.secret_rotated_at)
            && now < rotated_at + overlap
        {
            // A previous secret that no longer opens is not worth failing the delivery for.
            if let Ok(key) = open(previous) {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    /// The request of one attempt.
    fn request(
        subscription: &davhaven_domain::WebhookSubscription,
        delivery: &WebhookDelivery,
        details: Option<serde_json::Value>,
        keys: &[SigningKey],
        now: DateTime<Utc>,
    ) -> Result<OutboundRequest, &'static str> {
        let mut body = WebhookEnvelope::from(&delivery.envelope);
        if let (Some(details), Some(data)) = (details, body.data.as_object_mut()) {
            data.insert("details".to_owned(), details);
        }
        let bytes = serde_json::to_vec(&body).map_err(|_| "the event cannot be serialized")?;
        let id = delivery.envelope.id.as_uuid().hyphenated().to_string();
        let timestamp = now.timestamp();
        let signature = signing::signature_header(keys, &id, timestamp, &bytes);
        let value = |text: &str| HeaderValue::from_str(text).map_err(|_| "a header value is not valid");
        Ok(
            OutboundRequest::new(Method::POST, subscription.url.clone(), HttpPurpose::Webhook)
                .with_header(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_static("application/json"),
                )
                .with_header(
                    HeaderName::from_static("user-agent"),
                    HeaderValue::from_static(USER_AGENT),
                )
                .with_header(HeaderName::from_static(ID_HEADER), value(&id)?)
                .with_header(
                    HeaderName::from_static(TIMESTAMP_HEADER),
                    value(&timestamp.to_string())?,
                )
                .with_header(HeaderName::from_static(SIGNATURE_HEADER), value(&signature)?)
                .with_body(Bytes::from(bytes)),
        )
    }

    /// Turns the answer of the receiver (or the failure to get one) into an outcome.
    fn classify(
        result: Result<davhaven_ports::OutboundResponse, PortError>,
        record: &OutboxRecord,
        now: DateTime<Utc>,
        window: chrono::Duration,
    ) -> Outcome {
        let outcome = match result {
            Ok(response) => {
                let status = response.status.as_u16();
                if response.status.is_success() {
                    return Outcome::Delivered { status };
                }
                if status == 410 {
                    return Outcome::Dead {
                        status: Some(status),
                        error: "the receiver answered 410 Gone".to_owned(),
                        counts: true,
                        disable: Some(ENDPOINT_GONE),
                    };
                }
                Outcome::Failed {
                    status: Some(status),
                    error: format!("HTTP {status}"),
                }
            }
            Err(error) => match error.kind {
                PortErrorKind::Rejected => {
                    return Outcome::Dead {
                        status: None,
                        error: "the egress policy refused the request".to_owned(),
                        counts: true,
                        disable: None,
                    };
                }
                PortErrorKind::Invalid | PortErrorKind::Unsupported => {
                    return Outcome::Dead {
                        status: None,
                        error: "the request cannot be sent".to_owned(),
                        counts: false,
                        disable: None,
                    };
                }
                PortErrorKind::Unavailable | PortErrorKind::Timeout | PortErrorKind::Internal => Outcome::Failed {
                    status: None,
                    error: format!("the request failed ({})", error.kind.as_str()),
                },
            },
        };
        match outcome {
            Outcome::Failed { status, error } if now >= record.created_at + window => Outcome::Dead {
                status,
                error: format!("the retry window ended ({error})"),
                counts: true,
                disable: None,
            },
            other => other,
        }
    }

    /// Writes the outcome of an attempt and decides how the dispatcher goes on.
    async fn settle(
        &self,
        tenant: TenantId,
        delivery: &WebhookDelivery,
        outcome: &Outcome,
        now: DateTime<Utc>,
    ) -> Result<Verdict, StoreError> {
        let mut tx = self.database.begin(tenant, TxMode::ReadWrite).await?;
        let current = match tx.webhooks().get_delivery(delivery.delivery).await {
            Ok(current) => current,
            // Deleted with its subscription while the request was in flight.
            Err(StoreError::NotFound) => {
                tx.commit().await?;
                return Ok(Verdict::Done);
            }
            Err(error) => return Err(error),
        };
        let webhook = delivery.webhook;

        // The failure counter of the subscription: reset by a delivery, raised by a delivery that ended dead
        // because of the receiver. A failed attempt that is retried changes nothing.
        let bookkeeping = match outcome {
            Outcome::Delivered { .. } => tx.webhooks().record_success(webhook).await.map(|()| None),
            Outcome::Dead { counts: true, .. } => tx.webhooks().record_failure(webhook).await.map(Some),
            Outcome::Dead { counts: false, .. } | Outcome::Failed { .. } | Outcome::Skipped => Ok(None),
        };
        let failures = match bookkeeping {
            Ok(failures) => failures,
            // The subscription is gone: so is the reason for the delivery to exist.
            Err(StoreError::NotFound) => {
                tx.commit().await?;
                return Ok(Verdict::Done);
            }
            Err(error) => return Err(error),
        };
        let mut disable = match outcome {
            Outcome::Dead { disable, .. } => *disable,
            Outcome::Delivered { .. } | Outcome::Failed { .. } | Outcome::Skipped => None,
        };
        if disable.is_none() && failures.is_some_and(|count| count >= self.config.max_consecutive_failures) {
            disable = Some(MAX_CONSECUTIVE_FAILURES);
        }

        let (status, response_status, last_error, verdict) = match outcome {
            Outcome::Delivered { status } => (DeliveryStatus::Delivered, Some(*status), None, Verdict::Done),
            Outcome::Failed { status, error } => (
                DeliveryStatus::Failed,
                *status,
                Some(error.clone()),
                Verdict::Retry(error.clone()),
            ),
            Outcome::Dead { status, error, .. } => (
                DeliveryStatus::Dead,
                *status,
                Some(error.clone()),
                Verdict::Dead(error.clone()),
            ),
            Outcome::Skipped => (
                DeliveryStatus::Dead,
                None,
                Some(SKIPPED_ERROR.to_owned()),
                Verdict::Done,
            ),
        };
        tx.webhooks()
            .update_delivery(
                DeliveryRecord {
                    status,
                    attempts: current.attempts.saturating_add(1),
                    response_status,
                    last_error,
                    at: now,
                    ..current.clone()
                },
                current.version,
            )
            .await?;
        if let Some(reason) = disable {
            self.disable(tx.as_mut(), tenant, webhook, reason, now).await?;
        }
        tx.commit().await?;
        Ok(verdict)
    }

    /// Disables the subscription, raises `webhook.disabled` and audits it. Does nothing when the subscription is
    /// switched off already.
    async fn disable(
        &self,
        tx: &mut dyn davhaven_ports::Tx,
        tenant: TenantId,
        webhook: WebhookId,
        reason: &'static str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        match tx.webhooks().get(webhook).await {
            Ok(subscription) if subscription.active => {}
            Ok(_) | Err(StoreError::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        }
        tx.webhooks().disable(webhook, reason).await?;
        let envelope = Envelope::new(
            EventId::from_uuid(self.ids.new_id()),
            EventType::WebhookDisabled,
            tenant,
            now,
            AuditActor::system(),
            EventPayload::Webhook(WebhookPayload {
                webhook,
                reason: reason.to_owned(),
            }),
        )
        .map_err(|error| StoreError::internal(error.to_string()))?;
        tx.outbox()
            .enqueue(NewOutbox::now(
                OutboxId::from_uuid(self.ids.new_id()),
                OutboxMessage::DomainEvent(envelope),
            ))
            .await?;
        tx.audit()
            .append(NewAudit {
                id: self.ids.new_id(),
                actor: AuditActor::system(),
                event: AuditEvent::WebhookDisabled(WebhookAudit {
                    reason: Some(reason.to_owned()),
                    ..WebhookAudit::new(webhook)
                }),
            })
            .await?;
        tracing::warn!(tenant = %tenant, webhook = %webhook, reason, "a webhook subscription was disabled");
        Ok(())
    }

    /// Whether the retry window of the record has passed.
    fn window_ended(&self, record: &OutboxRecord) -> bool {
        let window = chrono::Duration::from_std(self.config.retry_window).unwrap_or(chrono::Duration::days(1));
        self.clock.now() >= record.created_at + window
    }

    /// Marks a delivery dead because its window ended while the attempt could not even be made or settled. Best
    /// effort: when the store is down the delivery keeps its state, and the dead record can be redelivered.
    async fn give_up(&self, tenant: TenantId, delivery: davhaven_domain::DeliveryId) {
        let marked = async {
            let mut tx = self.database.begin(tenant, TxMode::ReadWrite).await?;
            let current = match tx.webhooks().get_delivery(delivery).await {
                Ok(current) => current,
                Err(StoreError::NotFound) => return tx.commit().await,
                Err(error) => return Err(error),
            };
            if current.status == DeliveryStatus::Delivered {
                return tx.commit().await;
            }
            tx.webhooks()
                .update_delivery(
                    DeliveryRecord {
                        status: DeliveryStatus::Dead,
                        last_error: Some("the retry window ended".to_owned()),
                        at: self.clock.now(),
                        ..current.clone()
                    },
                    current.version,
                )
                .await?;
            tx.commit().await
        }
        .await;
        if let Err(error) = marked {
            tracing::warn!(%error, "could not mark a delivery dead after its retry window ended");
        }
    }

    /// One attempt to deliver.
    async fn deliver(&self, record: &OutboxRecord, delivery: WebhookDelivery) -> Result<(), HandlerError> {
        let tenant = record.tenant_id;
        let now = self.clock.now();
        let Some(loaded) = self.load(tenant, &delivery).await? else {
            tracing::debug!(outbox = %record.id, "the subscription or the delivery is gone; nothing to send");
            return Ok(());
        };
        if loaded.delivery.status == DeliveryStatus::Delivered {
            // A duplicate of a record that was handled already (a lease expired, the settlement was lost).
            return Ok(());
        }
        let window = chrono::Duration::from_std(self.config.retry_window).unwrap_or(chrono::Duration::days(1));
        let outcome = if loaded.subscription.active {
            // The details were read for the subscription as it was when the event fanned out; a subscription that
            // has switched them off since gets none.
            let details = delivery.details.clone().filter(|_| loaded.subscription.include_details);
            match self
                .keys(tenant, &loaded.subscription, now)
                .and_then(|keys| Self::request(&loaded.subscription, &delivery, details, &keys, now))
            {
                Ok(request) => Self::classify(self.http.send(request).await, record, now, window),
                Err(error) => Outcome::Dead {
                    status: None,
                    error: error.to_owned(),
                    counts: false,
                    disable: None,
                },
            }
        } else {
            Outcome::Skipped
        };
        match self.settle(tenant, &delivery, &outcome, now).await? {
            Verdict::Done => Ok(()),
            Verdict::Retry(error) => Err(HandlerError::retryable(error)),
            Verdict::Dead(error) => Err(HandlerError::permanent(error)),
        }
    }
}

#[async_trait]
impl OutboxHandler for WebhookHandler {
    fn kind(&self) -> &'static str {
        kind::WEBHOOK
    }

    async fn handle(&self, record: &OutboxRecord) -> Result<(), HandlerError> {
        observe(LABEL, "handle", async {
            let delivery = match record.message() {
                Ok(OutboxMessage::Webhook(delivery)) => delivery,
                Ok(other) => {
                    return Err(HandlerError::permanent(format!(
                        "the record holds a `{}` message, not a webhook delivery",
                        other.kind()
                    )));
                }
                Err(OutboxDecodeError::UnsupportedVersion { .. }) => {
                    return Err(HandlerError::retryable("the payload was written by a newer version"));
                }
                Err(_) => return Err(HandlerError::permanent("the payload of the record cannot be decoded")),
            };
            if delivery.envelope.tenant != record.tenant_id {
                return Err(HandlerError::permanent(
                    "the tenant of the event is not the tenant of the record",
                ));
            }
            let (tenant, webhook_delivery) = (record.tenant_id, delivery.delivery);
            match self.deliver(record, delivery).await {
                // The window bounds every way of failing, not only the answers of receivers: a store that stays
                // down or a sealer that stays broken must not keep a record alive for ever.
                Err(error) if error.is_retryable() && self.window_ended(record) => {
                    self.give_up(tenant, webhook_delivery).await;
                    Err(HandlerError::permanent("the retry window ended"))
                }
                other => other,
            }
        })
        .await
    }

    /// Webhook retries are bounded by `webhooks.retry_window`, which the handler enforces itself.
    fn limits_attempts(&self) -> bool {
        false
    }
}

/// The text of a delivery that the `noop` handler took.
pub const NOOP_ERROR: &str = "webhooks are not delivered by this deployment";

/// The `noop` handler of the kind `webhook`: completes every delivery without sending anything. For deployments
/// that do not use webhooks and for tests; subscriptions can still be managed.
///
/// A delivery the handler takes is marked `dead` with [`NOOP_ERROR`], so that the API shows what happened to it
/// (it was never sent) instead of a delivery that stays `pending` for ever. Such a delivery can be redelivered
/// once a real handler is configured.
#[derive(Clone)]
pub struct NoopWebhookHandler {
    database: Arc<dyn Database>,
    clock: Arc<dyn Clock>,
}

impl core::fmt::Debug for NoopWebhookHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoopWebhookHandler").finish_non_exhaustive()
    }
}

impl NoopWebhookHandler {
    /// Creates the handler on the built ports of the plugin context.
    ///
    /// # Errors
    ///
    /// [`PluginError::MissingDependency`] when the context has no database yet.
    pub fn from_context(context: &PluginContext) -> Result<Self, PluginError> {
        Ok(Self {
            database: context.require_database(crate::plugin::NOOP)?,
            clock: Arc::clone(&context.clock),
        })
    }

    /// Marks the delivery of the record dead; a delivery that is gone or finished is left alone.
    async fn mark(&self, tenant: TenantId, delivery: davhaven_domain::DeliveryId) -> Result<(), StoreError> {
        let mut tx = self.database.begin(tenant, TxMode::ReadWrite).await?;
        let current = match tx.webhooks().get_delivery(delivery).await {
            Ok(current) => current,
            Err(StoreError::NotFound) => return tx.commit().await,
            Err(error) => return Err(error),
        };
        if matches!(current.status, DeliveryStatus::Delivered | DeliveryStatus::Dead) {
            return tx.commit().await;
        }
        tx.webhooks()
            .update_delivery(
                DeliveryRecord {
                    status: DeliveryStatus::Dead,
                    last_error: Some(NOOP_ERROR.to_owned()),
                    at: self.clock.now(),
                    ..current.clone()
                },
                current.version,
            )
            .await?;
        tx.commit().await
    }
}

/// What `observe` labels the `noop` handler with.
const NOOP_LABEL: PortLabel = PortLabel::new("outbox_handler", crate::plugin::NOOP);

#[async_trait]
impl OutboxHandler for NoopWebhookHandler {
    fn kind(&self) -> &'static str {
        kind::WEBHOOK
    }

    async fn handle(&self, record: &OutboxRecord) -> Result<(), HandlerError> {
        observe(NOOP_LABEL, "handle", async {
            match record.message() {
                Ok(OutboxMessage::Webhook(delivery)) => Ok(self.mark(record.tenant_id, delivery.delivery).await?),
                Ok(other) => Err(HandlerError::permanent(format!(
                    "the record holds a `{}` message, not a webhook delivery",
                    other.kind()
                ))),
                Err(_) => Err(HandlerError::permanent("the payload of the record cannot be decoded")),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests;
