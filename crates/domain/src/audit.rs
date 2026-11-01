//! Audit event catalog and audit actors.
//!
//! Audit events are written inside the transaction of the change they record (`audit_events`: `actor`, `action`,
//! `target`, `details`). They carry ids, kinds and counters only: never secrets, event bodies or e-mail
//! addresses (PLAN 2.18). [`AuditEvent`] is the closed catalog; [`AuditEvent::record`] splits an event into the
//! three columns.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::context::{Actor, CredentialKind, RequestContext};
use crate::entities::GrantAccess;
use crate::ids::{
    BindingId, CalendarId, DeliveryId, ExternalAccountId, ObjectId, OutboxId, PrincipalId, TokenId, WebhookId,
};
use crate::keys::Uid;
use crate::scope::{ScopeSet, TokenKind};
use crate::vocab::{ItipMethod, PartStat};

text_enum!(
    /// What kind of actor performed an audited action.
    AuditActorKind [] {
        /// A principal with an app password.
        Principal => "principal",
        /// A principal API token.
        PrincipalToken => "principal_token",
        /// A tenant administrator token.
        TenantToken => "tenant_token",
        /// A system token.
        SystemToken => "system_token",
        /// A subscription feed reader.
        FeedReader => "feed_reader",
        /// An RSVP attendee.
        RsvpAttendee => "rsvp_attendee",
        /// An unauthenticated caller.
        Anonymous => "anonymous",
        /// The server itself (workers, retention, the sync engine).
        System => "system",
    }
);

/// The actor of an audit event (`audit_events.actor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuditActor {
    /// What kind of actor it was.
    pub kind: AuditActorKind,
    /// The principal, for actors that act as one.
    pub principal_id: Option<PrincipalId>,
    /// The token, for token-based actors.
    pub token_id: Option<TokenId>,
    /// The token's label, for operators.
    pub label: Option<String>,
    /// A keyed hash of the client IP (never the address itself).
    pub ip_hash: Option<String>,
}

impl AuditActor {
    /// The actor of server-originated work.
    pub const fn system() -> Self {
        Self {
            kind: AuditActorKind::System,
            principal_id: None,
            token_id: None,
            label: None,
            ip_hash: None,
        }
    }

    /// Describes the actor of a request. `label` is the token label if the caller looked it up; `ip_hash` is
    /// the keyed hash of the client IP.
    pub fn from_context(ctx: &RequestContext, label: Option<String>, ip_hash: Option<String>) -> Self {
        let kind = match &ctx.actor {
            Actor::Principal(_) => AuditActorKind::Principal,
            Actor::PrincipalToken { .. } => AuditActorKind::PrincipalToken,
            Actor::TenantToken(_) => AuditActorKind::TenantToken,
            Actor::SystemToken(_) => AuditActorKind::SystemToken,
            Actor::FeedReader { .. } => AuditActorKind::FeedReader,
            Actor::RsvpAttendee { .. } => AuditActorKind::RsvpAttendee,
            Actor::Anonymous => {
                if ctx.channel == crate::context::Channel::Internal {
                    AuditActorKind::System
                } else {
                    AuditActorKind::Anonymous
                }
            }
        };
        Self {
            kind,
            principal_id: ctx.actor.principal(),
            token_id: ctx.actor.token(),
            label,
            ip_hash,
        }
    }
}

/// Details of a credential event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CredentialAudit {
    /// The kind of credential.
    pub kind: CredentialKind,
    /// The credential's id (a credential id for app passwords, a token id for the token kinds).
    pub credential: Uuid,
    /// The principal the credential authenticates, if it belongs to one.
    pub principal: Option<PrincipalId>,
}

/// Details of a principal lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalAudit {
    /// The principal.
    pub principal: PrincipalId,
}

/// Details of an API token event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenAudit {
    /// The token.
    pub token: TokenId,
    /// System, tenant or principal token.
    pub kind: TokenKind,
    /// The principal a principal token acts as.
    pub principal: Option<PrincipalId>,
    /// The scopes the token carries.
    pub scopes: ScopeSet,
    /// When the token expires, if it does.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Reference to a revoked token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenRevocationAudit {
    /// The revoked token.
    pub token: TokenId,
}

/// Aggregated authentication failures (one record per window and key, never one per attempt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthFailureAudit {
    /// The credential mechanism, for example `app_password`.
    pub mechanism: String,
    /// The failure reason as used for the metric label, for example `bad_secret`.
    pub reason: String,
    /// How many failures the record aggregates.
    pub count: u32,
    /// The length of the aggregation window in seconds.
    pub window_seconds: u32,
}

/// Details of a grant or share change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantAudit {
    /// The calendar.
    pub calendar: CalendarId,
    /// The grant, when it still exists.
    pub grant: Option<crate::ids::GrantId>,
    /// The user, group or service principal that is granted access.
    pub grantee: PrincipalId,
    /// The access level involved, if the event has one.
    pub access: Option<GrantAccess>,
    /// Whether the grant marks the calendar as required for the people it reaches: a change of the flag alone is a
    /// `grant.updated`, and this is how the log shows it.
    #[serde(default)]
    pub required: bool,
}

/// Details of a binding that was shown in a home again (`binding.restored`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BindingAudit {
    /// The principal whose home lists the binding.
    pub principal: PrincipalId,
    /// The calendar behind the binding.
    pub calendar: CalendarId,
    /// The binding.
    pub binding: BindingId,
}

/// Changed tenant settings, by name only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TenantSettingsAudit {
    /// The dotted names of the settings that changed, for example `scheduling.external`.
    pub fields: Vec<String>,
}

/// Details of a webhook change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WebhookAudit {
    /// The webhook subscription.
    pub webhook: WebhookId,
    /// A machine-readable reason, for example why it was disabled.
    pub reason: Option<String>,
    /// For `webhook.updated`: the names of the settings that changed (`url`, `description`, `events`,
    /// `include_details`, `active`). Changing the URL or switching on `include_details` redirects events, so the
    /// log says so.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// For `webhook.created` and for a change of the URL: the host the events go to. Never the path or the
    /// query, which can carry a token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl WebhookAudit {
    /// The details of a change of `webhook` that says nothing more.
    pub const fn new(webhook: WebhookId) -> Self {
        Self {
            webhook,
            reason: None,
            fields: Vec::new(),
            host: None,
        }
    }
}

/// Details of a test event or a repeated delivery of a webhook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WebhookDeliveryAudit {
    /// The webhook subscription the event goes to.
    pub webhook: WebhookId,
    /// The delivery that was created (a test event) or sent again (a redelivery).
    pub delivery: DeliveryId,
}

/// Details of an operator retrying an outbox item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutboxAudit {
    /// The outbox item that was made due again.
    pub outbox: OutboxId,
    /// Its kind (`imip`, `domain_event`, ...).
    pub kind: String,
}

/// Details of an external account change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExternalAccountAudit {
    /// The external account.
    pub external_account: ExternalAccountId,
    /// The principal who owns it.
    pub principal: PrincipalId,
    /// The provider name.
    pub provider: String,
}

/// Details of an MCP write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct McpWriteAudit {
    /// The tool that was called, for example `create_event`.
    pub tool: String,
    /// The calendar the tool changed.
    pub calendar: Option<CalendarId>,
    /// The object the tool changed.
    pub object: Option<ObjectId>,
    /// The UID of the object.
    pub uid: Option<Uid>,
}

/// Details of an RSVP answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RsvpAudit {
    /// The invitation that was answered.
    pub object: ObjectId,
    /// The answer.
    pub partstat: PartStat,
}

/// Details of an inbound iTIP decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InboundItipAudit {
    /// The method of the message, if it could be read.
    pub method: Option<ItipMethod>,
    /// The organizer object the message was applied to.
    pub object: Option<ObjectId>,
    /// Why the message was rejected (machine-readable), for rejections.
    pub reason: Option<String>,
}

/// Details of a rate limit trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RateLimitAudit {
    /// The kind of bucket, for example `login` or `ip`.
    pub bucket: String,
    /// How many requests were refused in the aggregation window.
    pub count: u32,
}

/// Details of a key rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KeyRotationAudit {
    /// The key id that is active after the rotation.
    pub active_kid: String,
}

/// The audit catalog (`audit_events.action`). The serialized form is the event's `details` plus an `action`
/// member; [`AuditEvent::record`] separates them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action")]
pub enum AuditEvent {
    /// An app password, feed token or RSVP token was created.
    #[serde(rename = "credential.created")]
    CredentialCreated(CredentialAudit),
    /// A credential was revoked.
    #[serde(rename = "credential.revoked")]
    CredentialRevoked(CredentialAudit),
    /// A revoked credential was presented again.
    #[serde(rename = "credential.used_after_revoke")]
    CredentialUsedAfterRevoke(CredentialAudit),
    /// Authentication failures, aggregated per window.
    #[serde(rename = "auth.failures")]
    AuthFailures(AuthFailureAudit),
    /// An API token was created.
    #[serde(rename = "token.created")]
    TokenCreated(TokenAudit),
    /// An API token was revoked.
    #[serde(rename = "token.revoked")]
    TokenRevoked(TokenRevocationAudit),
    /// A principal was created.
    #[serde(rename = "principal.created")]
    PrincipalCreated(PrincipalAudit),
    /// A principal was changed.
    #[serde(rename = "principal.updated")]
    PrincipalUpdated(PrincipalAudit),
    /// A principal was deleted (hidden; credentials and shares revoked).
    #[serde(rename = "principal.deleted")]
    PrincipalDeleted(PrincipalAudit),
    /// A deleted principal was purged.
    #[serde(rename = "principal.purged")]
    PrincipalPurged(PrincipalAudit),
    /// A grant was created.
    #[serde(rename = "grant.created")]
    GrantCreated(GrantAudit),
    /// A grant was changed.
    #[serde(rename = "grant.updated")]
    GrantUpdated(GrantAudit),
    /// A grant was removed.
    #[serde(rename = "grant.deleted")]
    GrantDeleted(GrantAudit),
    /// A hidden binding was shown in a principal's home again (by an operator, or because the calendar became required).
    #[serde(rename = "binding.restored")]
    BindingRestored(BindingAudit),
    /// A calendar was shared with someone (invitation sent).
    #[serde(rename = "share.invited")]
    ShareInvited(GrantAudit),
    /// An invitation was accepted.
    #[serde(rename = "share.accepted")]
    ShareAccepted(GrantAudit),
    /// An invitation was declined.
    #[serde(rename = "share.declined")]
    ShareDeclined(GrantAudit),
    /// A share was removed by the owner or the sharee.
    #[serde(rename = "share.removed")]
    ShareRemoved(GrantAudit),
    /// A tenant was created.
    #[serde(rename = "tenant.created")]
    TenantCreated,
    /// Tenant settings were changed.
    #[serde(rename = "tenant.settings_changed")]
    TenantSettingsChanged(TenantSettingsAudit),
    /// A tenant was deleted.
    #[serde(rename = "tenant.deleted")]
    TenantDeleted,
    /// A webhook subscription was created.
    #[serde(rename = "webhook.created")]
    WebhookCreated(WebhookAudit),
    /// A webhook subscription was changed.
    #[serde(rename = "webhook.updated")]
    WebhookUpdated(WebhookAudit),
    /// A webhook subscription was deleted.
    #[serde(rename = "webhook.deleted")]
    WebhookDeleted(WebhookAudit),
    /// The signing secret of a webhook was rotated.
    #[serde(rename = "webhook.secret_rotated")]
    WebhookSecretRotated(WebhookAudit),
    /// A webhook was disabled after repeated failures.
    #[serde(rename = "webhook.disabled")]
    WebhookDisabled(WebhookAudit),
    /// A test event was sent to a webhook subscription.
    #[serde(rename = "webhook.pinged")]
    WebhookPinged(WebhookDeliveryAudit),
    /// A delivery of a webhook subscription was sent again by an operator.
    #[serde(rename = "webhook.redelivered")]
    WebhookRedelivered(WebhookDeliveryAudit),
    /// An operator made a dead outbox item due again.
    #[serde(rename = "outbox.retried")]
    OutboxRetried(OutboxAudit),
    /// An external provider account was connected.
    #[serde(rename = "external_account.created")]
    ExternalAccountCreated(ExternalAccountAudit),
    /// An external provider account was disconnected.
    #[serde(rename = "external_account.deleted")]
    ExternalAccountDeleted(ExternalAccountAudit),
    /// An MCP tool changed calendar data.
    #[serde(rename = "mcp.write")]
    McpWrite(McpWriteAudit),
    /// An attendee answered through an RSVP link.
    #[serde(rename = "rsvp.answered")]
    RsvpAnswered(RsvpAudit),
    /// An inbound iTIP message was applied.
    #[serde(rename = "itip.inbound_accepted")]
    InboundItipAccepted(InboundItipAudit),
    /// An inbound iTIP message was rejected or quarantined.
    #[serde(rename = "itip.inbound_rejected")]
    InboundItipRejected(InboundItipAudit),
    /// A rate limit was tripped, aggregated per window.
    #[serde(rename = "rate_limit.tripped")]
    RateLimitTripped(RateLimitAudit),
    /// The active signing key was rotated.
    #[serde(rename = "keys.rotated")]
    KeysRotated(KeyRotationAudit),
}

/// An audit event split into the columns of `audit_events`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditRecord {
    /// The action name, for example `credential.created`.
    pub action: &'static str,
    /// The principal-visible target as `kind:id`, when the event has one.
    pub target: Option<String>,
    /// The remaining details as a JSON object.
    pub details: serde_json::Value,
}

impl AuditEvent {
    /// The action name (`audit_events.action`); equals the serialized `action` tag.
    pub const fn action(&self) -> &'static str {
        match self {
            Self::CredentialCreated(_) => "credential.created",
            Self::CredentialRevoked(_) => "credential.revoked",
            Self::CredentialUsedAfterRevoke(_) => "credential.used_after_revoke",
            Self::AuthFailures(_) => "auth.failures",
            Self::TokenCreated(_) => "token.created",
            Self::TokenRevoked(_) => "token.revoked",
            Self::PrincipalCreated(_) => "principal.created",
            Self::PrincipalUpdated(_) => "principal.updated",
            Self::PrincipalDeleted(_) => "principal.deleted",
            Self::PrincipalPurged(_) => "principal.purged",
            Self::GrantCreated(_) => "grant.created",
            Self::GrantUpdated(_) => "grant.updated",
            Self::GrantDeleted(_) => "grant.deleted",
            Self::BindingRestored(_) => "binding.restored",
            Self::ShareInvited(_) => "share.invited",
            Self::ShareAccepted(_) => "share.accepted",
            Self::ShareDeclined(_) => "share.declined",
            Self::ShareRemoved(_) => "share.removed",
            Self::TenantCreated => "tenant.created",
            Self::TenantSettingsChanged(_) => "tenant.settings_changed",
            Self::TenantDeleted => "tenant.deleted",
            Self::WebhookCreated(_) => "webhook.created",
            Self::WebhookUpdated(_) => "webhook.updated",
            Self::WebhookDeleted(_) => "webhook.deleted",
            Self::WebhookSecretRotated(_) => "webhook.secret_rotated",
            Self::WebhookDisabled(_) => "webhook.disabled",
            Self::WebhookPinged(_) => "webhook.pinged",
            Self::WebhookRedelivered(_) => "webhook.redelivered",
            Self::OutboxRetried(_) => "outbox.retried",
            Self::ExternalAccountCreated(_) => "external_account.created",
            Self::ExternalAccountDeleted(_) => "external_account.deleted",
            Self::McpWrite(_) => "mcp.write",
            Self::RsvpAnswered(_) => "rsvp.answered",
            Self::InboundItipAccepted(_) => "itip.inbound_accepted",
            Self::InboundItipRejected(_) => "itip.inbound_rejected",
            Self::RateLimitTripped(_) => "rate_limit.tripped",
            Self::KeysRotated(_) => "keys.rotated",
        }
    }

    /// The target of the event as `kind:id`, when it has one (for example `principal:{id}`).
    pub fn target(&self) -> Option<String> {
        match self {
            Self::CredentialCreated(a) | Self::CredentialRevoked(a) | Self::CredentialUsedAfterRevoke(a) => {
                Some(format!("{}:{}", a.kind, a.credential.hyphenated()))
            }
            Self::TokenCreated(a) => Some(format!("token:{}", a.token)),
            Self::TokenRevoked(a) => Some(format!("token:{}", a.token)),
            Self::PrincipalCreated(a)
            | Self::PrincipalUpdated(a)
            | Self::PrincipalDeleted(a)
            | Self::PrincipalPurged(a) => Some(format!("principal:{}", a.principal)),
            Self::GrantCreated(a)
            | Self::GrantUpdated(a)
            | Self::GrantDeleted(a)
            | Self::ShareInvited(a)
            | Self::ShareAccepted(a)
            | Self::ShareDeclined(a)
            | Self::ShareRemoved(a) => Some(format!("calendar:{}", a.calendar)),
            Self::BindingRestored(a) => Some(format!("calendar:{}", a.calendar)),
            Self::WebhookCreated(a)
            | Self::WebhookUpdated(a)
            | Self::WebhookDeleted(a)
            | Self::WebhookSecretRotated(a)
            | Self::WebhookDisabled(a) => Some(format!("webhook:{}", a.webhook)),
            Self::WebhookPinged(a) | Self::WebhookRedelivered(a) => Some(format!("webhook:{}", a.webhook)),
            Self::OutboxRetried(a) => Some(format!("outbox:{}", a.outbox)),
            Self::ExternalAccountCreated(a) | Self::ExternalAccountDeleted(a) => {
                Some(format!("external_account:{}", a.external_account))
            }
            Self::McpWrite(a) => a.calendar.map(|calendar| format!("calendar:{calendar}")),
            Self::RsvpAnswered(a) => Some(format!("object:{}", a.object)),
            Self::InboundItipAccepted(a) | Self::InboundItipRejected(a) => {
                a.object.map(|object| format!("object:{object}"))
            }
            Self::AuthFailures(_)
            | Self::TenantCreated
            | Self::TenantSettingsChanged(_)
            | Self::TenantDeleted
            | Self::RateLimitTripped(_)
            | Self::KeysRotated(_) => None,
        }
    }

    /// Splits the event into the `action`, `target` and `details` columns.
    pub fn record(&self) -> AuditRecord {
        let mut details = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(object) = details.as_object_mut() {
            object.remove("action");
        } else {
            details = serde_json::Value::Object(serde_json::Map::new());
        }
        AuditRecord {
            action: self.action(),
            target: self.target(),
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Channel;
    use crate::ids::{BindingId, GrantId, RequestId, TenantId};

    fn principal(n: u128) -> PrincipalId {
        PrincipalId::from_uuid(Uuid::from_u128(n))
    }

    fn calendar(n: u128) -> CalendarId {
        CalendarId::from_uuid(Uuid::from_u128(n))
    }

    #[expect(clippy::too_many_lines, reason = "one sample per variant is a list, not logic")]
    fn one_of_each() -> Vec<AuditEvent> {
        let credential = CredentialAudit {
            kind: CredentialKind::AppPassword,
            credential: Uuid::from_u128(1),
            principal: Some(principal(2)),
        };
        let principal_audit = PrincipalAudit {
            principal: principal(2),
        };
        let grant = GrantAudit {
            calendar: calendar(3),
            grant: Some(GrantId::from_uuid(Uuid::from_u128(4))),
            grantee: principal(5),
            access: Some(GrantAccess::Read),
            required: true,
        };
        let webhook = WebhookAudit {
            fields: vec!["url".to_owned()],
            host: Some("hooks.example.org".to_owned()),
            ..WebhookAudit::new(WebhookId::from_uuid(Uuid::from_u128(6)))
        };
        let external = ExternalAccountAudit {
            external_account: ExternalAccountId::from_uuid(Uuid::from_u128(7)),
            principal: principal(2),
            provider: "google".to_owned(),
        };
        let inbound = InboundItipAudit {
            method: Some(ItipMethod::Reply),
            object: Some(ObjectId::from_uuid(Uuid::from_u128(8))),
            reason: None,
        };
        vec![
            AuditEvent::CredentialCreated(credential.clone()),
            AuditEvent::CredentialRevoked(credential.clone()),
            AuditEvent::CredentialUsedAfterRevoke(credential),
            AuditEvent::AuthFailures(AuthFailureAudit {
                mechanism: "app_password".to_owned(),
                reason: "bad_secret".to_owned(),
                count: 12,
                window_seconds: 300,
            }),
            AuditEvent::TokenCreated(TokenAudit {
                token: TokenId::from_uuid(Uuid::from_u128(9)),
                kind: TokenKind::Principal,
                principal: Some(principal(2)),
                scopes: ScopeSet::of(&[crate::scope::Scope::McpRead]),
                expires_at: DateTime::from_timestamp(1_800_000_000, 0),
            }),
            AuditEvent::TokenRevoked(TokenRevocationAudit {
                token: TokenId::from_uuid(Uuid::from_u128(9)),
            }),
            AuditEvent::PrincipalCreated(principal_audit.clone()),
            AuditEvent::PrincipalUpdated(principal_audit.clone()),
            AuditEvent::PrincipalDeleted(principal_audit.clone()),
            AuditEvent::PrincipalPurged(principal_audit),
            AuditEvent::GrantCreated(grant.clone()),
            AuditEvent::GrantUpdated(grant.clone()),
            AuditEvent::GrantDeleted(grant.clone()),
            AuditEvent::BindingRestored(BindingAudit {
                principal: principal(2),
                calendar: calendar(3),
                binding: BindingId::from_uuid(Uuid::from_u128(12)),
            }),
            AuditEvent::ShareInvited(grant.clone()),
            AuditEvent::ShareAccepted(grant.clone()),
            AuditEvent::ShareDeclined(grant.clone()),
            AuditEvent::ShareRemoved(grant),
            AuditEvent::TenantCreated,
            AuditEvent::TenantSettingsChanged(TenantSettingsAudit {
                fields: vec!["scheduling.external".to_owned()],
            }),
            AuditEvent::TenantDeleted,
            AuditEvent::WebhookCreated(webhook.clone()),
            AuditEvent::WebhookUpdated(webhook.clone()),
            AuditEvent::WebhookDeleted(webhook.clone()),
            AuditEvent::WebhookSecretRotated(webhook.clone()),
            AuditEvent::WebhookDisabled(WebhookAudit {
                reason: Some("max_consecutive_failures".to_owned()),
                ..webhook
            }),
            AuditEvent::WebhookPinged(WebhookDeliveryAudit {
                webhook: WebhookId::from_uuid(Uuid::from_u128(6)),
                delivery: DeliveryId::from_uuid(Uuid::from_u128(10)),
            }),
            AuditEvent::WebhookRedelivered(WebhookDeliveryAudit {
                webhook: WebhookId::from_uuid(Uuid::from_u128(6)),
                delivery: DeliveryId::from_uuid(Uuid::from_u128(10)),
            }),
            AuditEvent::OutboxRetried(OutboxAudit {
                outbox: OutboxId::from_uuid(Uuid::from_u128(11)),
                kind: "imip".to_owned(),
            }),
            AuditEvent::ExternalAccountCreated(external.clone()),
            AuditEvent::ExternalAccountDeleted(external),
            AuditEvent::McpWrite(McpWriteAudit {
                tool: "create_event".to_owned(),
                calendar: Some(calendar(3)),
                object: None,
                uid: Uid::parse("uid-1").ok(),
            }),
            AuditEvent::RsvpAnswered(RsvpAudit {
                object: ObjectId::from_uuid(Uuid::from_u128(8)),
                partstat: PartStat::Accepted,
            }),
            AuditEvent::InboundItipAccepted(inbound.clone()),
            AuditEvent::InboundItipRejected(InboundItipAudit {
                reason: Some("unknown_sender".to_owned()),
                ..inbound
            }),
            AuditEvent::RateLimitTripped(RateLimitAudit {
                bucket: "login".to_owned(),
                count: 30,
            }),
            AuditEvent::KeysRotated(KeyRotationAudit {
                active_kid: "k2".to_owned(),
            }),
        ]
    }

    #[test]
    fn every_action_name_is_unique_and_matches_the_serialized_tag() {
        let events = one_of_each();
        assert_eq!(events.len(), 37);
        let mut seen = std::collections::BTreeSet::new();
        for event in &events {
            let action = event.action();
            assert!(seen.insert(action), "duplicate action {action}");
            let json = serde_json::to_value(event).unwrap();
            assert_eq!(json["action"], action);
            let back: AuditEvent = serde_json::from_value(json).unwrap();
            assert_eq!(&back, event);
        }
    }

    #[test]
    fn records_split_action_target_and_details() {
        let event = AuditEvent::PrincipalDeleted(PrincipalAudit {
            principal: principal(2),
        });
        let record = event.record();
        assert_eq!(record.action, "principal.deleted");
        assert_eq!(
            record.target.as_deref(),
            Some("principal:00000000-0000-0000-0000-000000000002")
        );
        assert_eq!(
            record.details,
            serde_json::json!({"principal": "00000000-0000-0000-0000-000000000002"})
        );

        let unit = AuditEvent::TenantDeleted.record();
        assert_eq!(unit.action, "tenant.deleted");
        assert_eq!(unit.target, None);
        assert_eq!(unit.details, serde_json::json!({}));
    }

    #[test]
    fn targets_name_the_affected_resource() {
        let events = one_of_each();
        let targets: Vec<(&str, Option<String>)> = events.iter().map(|e| (e.action(), e.target())).collect();
        let find = |action: &str| targets.iter().find(|(a, _)| *a == action).unwrap().1.clone();
        assert_eq!(
            find("credential.created").unwrap(),
            "app_password:00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            find("token.created").unwrap(),
            "token:00000000-0000-0000-0000-000000000009"
        );
        assert_eq!(
            find("share.accepted").unwrap(),
            "calendar:00000000-0000-0000-0000-000000000003"
        );
        assert_eq!(
            find("webhook.disabled").unwrap(),
            "webhook:00000000-0000-0000-0000-000000000006"
        );
        assert_eq!(
            find("rsvp.answered").unwrap(),
            "object:00000000-0000-0000-0000-000000000008"
        );
        assert_eq!(find("auth.failures"), None);
        assert_eq!(find("keys.rotated"), None);
        assert_eq!(find("tenant.created"), None);
    }

    fn collect_keys(value: &serde_json::Value, keys: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, inner) in map {
                    keys.push(key.to_lowercase());
                    collect_keys(inner, keys);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|item| collect_keys(item, keys)),
            _ => {}
        }
    }

    #[test]
    fn details_hold_ids_and_counters_only() {
        // The catalog has no field that can carry a secret, an e-mail address or event content; this guards the
        // field names of every sample against someone adding such a field to a payload.
        let forbidden = [
            "secret",
            "password",
            "email",
            "mail",
            "summary",
            "description",
            "body",
            "ics",
            "address",
        ];
        for event in one_of_each() {
            let mut keys = Vec::new();
            collect_keys(&event.record().details, &mut keys);
            for key in &keys {
                for word in forbidden {
                    assert!(
                        !key.contains(word),
                        "{} has a field `{key}` containing {word}",
                        event.action()
                    );
                }
            }
        }
    }

    #[test]
    fn actors_are_derived_from_the_request_context() {
        let tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let request = RequestId::from_uuid(Uuid::from_u128(2));
        let base = RequestContext::internal(tenant, request);
        assert_eq!(AuditActor::from_context(&base, None, None), AuditActor::system());

        let anonymous = RequestContext {
            channel: Channel::Dav,
            ..base.clone()
        };
        assert_eq!(
            AuditActor::from_context(&anonymous, None, None).kind,
            AuditActorKind::Anonymous
        );

        let token = TokenId::from_uuid(Uuid::from_u128(3));
        let ctx = RequestContext {
            channel: Channel::Api,
            actor: Actor::PrincipalToken {
                principal: principal(4),
                token,
            },
            ..base
        };
        let actor = AuditActor::from_context(&ctx, Some("ci".to_owned()), Some("abc123".to_owned()));
        assert_eq!(actor.kind, AuditActorKind::PrincipalToken);
        assert_eq!(actor.principal_id, Some(principal(4)));
        assert_eq!(actor.token_id, Some(token));
        assert_eq!(actor.label.as_deref(), Some("ci"));
        assert_eq!(actor.ip_hash.as_deref(), Some("abc123"));
        let json = serde_json::to_value(&actor).unwrap();
        assert_eq!(json["kind"], "principal_token");
        assert!(json.get("ip_hash").is_some());
    }

    #[test]
    fn every_actor_kind_has_a_name() {
        assert_eq!(AuditActorKind::ALL.len(), 8);
        assert_eq!(AuditActorKind::System.as_str(), "system");
    }
}
