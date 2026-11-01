//! Audit event views.
//!
//! Audit events record security-relevant actions (credential, token, grant and principal changes, webhook and
//! account changes, MCP writes, RSVP answers, inbound iTIP decisions). They carry ids, kinds and counters, never
//! secrets, event bodies or e-mail addresses (PLAN 2.18).

use chrono::{DateTime, Utc};
use davhaven_domain::AuditActor;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// An audit event as `GET …/audit-events` lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct AuditEventView {
    /// The event id.
    pub id: Uuid,
    /// When it happened.
    pub at: DateTime<Utc>,
    /// Who acted.
    #[schema(schema_with = crate::schema::audit_actor)]
    pub actor: AuditActor,
    /// The action name, for example `credential.created`.
    pub action: String,
    /// The target as `kind:id`, when the action has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The remaining details (ids, kinds and counters only).
    #[schema(value_type = Object)]
    pub details: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_views_round_trip() {
        let view = AuditEventView {
            id: Uuid::from_u128(1),
            at: DateTime::UNIX_EPOCH,
            actor: AuditActor::system(),
            action: "credential.created".to_owned(),
            target: Some("app_password:018f3c1e-7b2a-7c3d-9e4f-000000000001".to_owned()),
            details: serde_json::json!({"kind": "app_password"}),
        };
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["actor"]["kind"], "system");
        assert_eq!(serde_json::from_value::<AuditEventView>(json).unwrap(), view);
    }
}
