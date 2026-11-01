//! Webhook subscriptions, deliveries and the webhook envelope.
//!
//! Subscriptions are managed through the API; deliveries follow the Standard Webhooks conventions (`webhook-id`,
//! `webhook-timestamp`, `webhook-signature: v1,<base64 HMAC>`). The signing secret (`whsec_…`) is shown once, in
//! the response that creates it or rotates it. Delivery is at-least-once and unordered; consumers deduplicate on
//! the envelope `id`.

use core::fmt;

use chrono::{DateTime, Utc};
use davhaven_domain::{AuditActor, DeliveryId, Envelope, EventId, EventType, TenantId, WebhookId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

/// A webhook subscription as the management API shows it. The secret is never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct WebhookView {
    /// The webhook id.
    #[schema(value_type = Uuid)]
    pub id: WebhookId,
    /// The target URL (https only).
    #[schema(value_type = String)]
    pub url: Url,
    /// A free-text description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The event types the subscription receives.
    #[schema(value_type = Vec<String>)]
    pub events: Vec<EventType>,
    /// Whether payloads carry details such as summary and times.
    pub include_details: bool,
    /// Inactive subscriptions receive nothing.
    pub active: bool,
    /// How many deliveries failed in a row.
    pub failure_count: u32,
    /// Why the subscription was disabled automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// When the signing secret was last rotated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_rotated_at: Option<DateTime<Utc>>,
    /// When the subscription was created.
    pub created_at: DateTime<Utc>,
    /// When the subscription was last changed.
    pub updated_at: DateTime<Utc>,
    /// The optimistic concurrency counter; the `ETag` is derived from it.
    pub version: i64,
}

/// The body of `POST …/webhooks`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookCreate {
    /// The target URL. Must be https; the egress policy is applied at registration and on every delivery.
    #[schema(value_type = String)]
    pub url: Url,
    /// A free-text description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The event types to receive; an empty list receives nothing.
    #[schema(value_type = Vec<String>)]
    pub events: Vec<EventType>,
    /// Whether payloads carry details such as summary and times (default `false`: thin payloads).
    #[serde(default)]
    pub include_details: bool,
    /// Whether the subscription is active (default `true`).
    #[serde(default = "default_active")]
    pub active: bool,
}

const fn default_active() -> bool {
    true
}

/// A freshly created webhook. The signing secret is shown only here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct WebhookCreated {
    /// The subscription.
    pub webhook: WebhookView,
    /// The signing secret `whsec_{base64}`.
    pub secret: String,
}

impl fmt::Debug for WebhookCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookCreated")
            .field("webhook", &self.webhook)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The result of rotating a signing secret: the new secret is shown once; the previous one keeps signing
/// alongside it until the retry window of pending deliveries has passed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct WebhookSecretRotated {
    /// The new signing secret `whsec_{base64}`.
    pub secret: String,
    /// When the secret was rotated.
    pub rotated_at: DateTime<Utc>,
}

impl fmt::Debug for WebhookSecretRotated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSecretRotated")
            .field("secret", &"<redacted>")
            .field("rotated_at", &self.rotated_at)
            .finish()
    }
}

/// The state of a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Waiting for the first or the next attempt.
    Pending,
    /// The receiver answered with a success status.
    Delivered,
    /// The last attempt failed; another one is scheduled.
    Failed,
    /// Retries are exhausted; an operator can redeliver.
    Dead,
}

/// One delivery of one event to one subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct DeliveryView {
    /// The delivery id.
    #[schema(value_type = Uuid)]
    pub id: DeliveryId,
    /// The subscription.
    #[schema(value_type = Uuid)]
    pub webhook_id: WebhookId,
    /// The event that is delivered.
    #[schema(value_type = Uuid)]
    pub event_id: EventId,
    /// The state of the delivery.
    pub status: DeliveryStatus,
    /// How many attempts were made.
    pub attempts: u32,
    /// The HTTP status of the last attempt, when the receiver answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    /// The error of the last attempt, for operators (never contains payloads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the delivery was last attempted or scheduled.
    pub at: DateTime<Utc>,
}

/// The body of a webhook request: the domain event envelope with the payload as free JSON, because the payload
/// shape depends on `type` (see `events.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct WebhookEnvelope {
    /// The event id (UUIDv7); also the `webhook-id` header. Consumers deduplicate on it.
    #[schema(value_type = Uuid)]
    pub id: EventId,
    /// What happened.
    #[serde(rename = "type")]
    #[schema(schema_with = crate::schema::event_type)]
    pub event_type: EventType,
    /// The envelope format version; additive changes keep it.
    pub version: u32,
    /// The tenant the event belongs to.
    #[schema(value_type = Uuid)]
    pub tenant: TenantId,
    /// When the change was committed.
    pub occurred_at: DateTime<Utc>,
    /// Who caused the event.
    #[schema(schema_with = crate::schema::audit_actor)]
    pub actor: AuditActor,
    /// The payload: ids, natural keys and ETags; details only for subscriptions with `include_details`.
    #[schema(value_type = Object)]
    pub data: serde_json::Value,
}

impl From<&Envelope> for WebhookEnvelope {
    fn from(envelope: &Envelope) -> Self {
        Self {
            id: envelope.id,
            event_type: envelope.event_type,
            version: envelope.version,
            tenant: envelope.tenant,
            occurred_at: envelope.occurred_at,
            actor: envelope.actor.clone(),
            data: serde_json::to_value(&envelope.data).unwrap_or(serde_json::Value::Null),
        }
    }
}

#[cfg(test)]
mod tests {
    use davhaven_domain::events::PrincipalPayload;
    use davhaven_domain::{EventPayload, PrincipalId};

    use super::*;

    #[test]
    fn webhook_creation_defaults_to_active_with_thin_payloads() {
        let create: WebhookCreate = serde_json::from_str(
            r#"{"url": "https://hooks.example.org/in", "events": ["principal.created", "calendar.objects_changed"]}"#,
        )
        .unwrap();
        assert!(create.active);
        assert!(!create.include_details);
        assert_eq!(create.events.len(), 2);
        assert!(serde_json::from_str::<WebhookCreate>(r#"{"url": "https://x.example", "events": ["nope"]}"#).is_err());
    }

    #[test]
    fn secrets_are_not_debug_printed() {
        let rotated = WebhookSecretRotated {
            secret: "whsec_TOPSECRET".to_owned(),
            rotated_at: DateTime::UNIX_EPOCH,
        };
        assert!(!format!("{rotated:?}").contains("TOPSECRET"));
    }

    #[test]
    fn the_envelope_keeps_the_event_json_shape() {
        let envelope = Envelope::new(
            EventId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000001").unwrap(),
            EventType::PrincipalCreated,
            TenantId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000002").unwrap(),
            DateTime::UNIX_EPOCH,
            AuditActor::system(),
            EventPayload::Principal(PrincipalPayload {
                principal: PrincipalId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000003").unwrap(),
            }),
        )
        .unwrap();
        let wire = WebhookEnvelope::from(&envelope);
        let from_domain = serde_json::to_value(&envelope).unwrap();
        let from_wire = serde_json::to_value(&wire).unwrap();
        assert_eq!(from_domain, from_wire);
        assert_eq!(from_wire["type"], "principal.created");
        assert_eq!(
            serde_json::from_value::<WebhookEnvelope>(from_wire).unwrap().data["principal"],
            "018f3c1e-7b2a-7c3d-9e4f-000000000003"
        );
    }
}
