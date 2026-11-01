//! The inbound iTIP endpoint for mail gateways.
//!
//! Replies sent through a mail client's buttons arrive in the organizer's mailbox, not at Davhaven. A mail
//! gateway can forward them to `POST /api/v1/tenants/{tenant}/itip/inbound` (scope `itip:inbound`, disabled by
//! default). Davhaven accepts an iTIP `REPLY` (and `REQUEST`/`CANCEL` when the tenant enables them) only with a
//! passing gateway verdict, when the sender is the replying attendee and when UID and `SEQUENCE` match an existing
//! organizer object; everything else is quarantined (PLAN 2.8).

use davhaven_domain::Email;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The result of an authentication check the gateway performed on the mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthVerdict {
    /// The check passed.
    Pass,
    /// The check failed.
    Fail,
    /// No check was made or its result is unknown.
    #[default]
    None,
}

/// The body of `POST …/itip/inbound`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundItipRequest {
    /// The `Message-ID` of the mail; messages are deduplicated on it.
    pub message_id: String,
    /// The sender address of the mail (the `From` header).
    #[schema(value_type = String)]
    pub from: Email,
    /// The `text/calendar` part of the mail.
    pub ical: String,
    /// The DMARC verdict of the gateway. With `require_dmarc_pass` (the default) anything but `pass` quarantines.
    #[serde(default)]
    pub dmarc: AuthVerdict,
    /// The DKIM verdict of the gateway, recorded for operators.
    #[serde(default)]
    pub dkim: AuthVerdict,
}

/// What Davhaven did with an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InboundOutcome {
    /// The message was applied to the organizer's object.
    Applied,
    /// A message with this `Message-ID` was already processed; nothing changed.
    Duplicate,
    /// The message was not applied; the response carries the `reason`. One copy is kept for inspection in the
    /// scheduling inbox of the person it was meant for when there is one, and `scheduling.reply_rejected` is emitted
    /// for a reply (not for an invitation or a cancellation).
    Quarantined,
}

/// The answer of `POST …/itip/inbound`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct InboundItipResponse {
    /// What happened.
    pub outcome: InboundOutcome,
    /// A machine-readable reason for a quarantine, for example `dmarc_not_passed` or `sender_mismatch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_default_to_unknown() {
        let request: InboundItipRequest = serde_json::from_str(
            r#"{"message_id": "<abc@mail.example.org>", "from": "Guest@Example.org", "ical": "BEGIN:VCALENDAR"}"#,
        )
        .unwrap();
        assert_eq!(request.dmarc, AuthVerdict::None);
        assert_eq!(request.dkim, AuthVerdict::None);
        assert_eq!(request.from.as_str(), "guest@example.org");
        assert!(serde_json::from_str::<InboundItipRequest>(r#"{"message_id": "x", "from": "g@e.org"}"#).is_err());
    }

    #[test]
    fn responses_omit_an_absent_reason() {
        let applied = InboundItipResponse {
            outcome: InboundOutcome::Applied,
            reason: None,
        };
        assert_eq!(serde_json::to_string(&applied).unwrap(), r#"{"outcome":"applied"}"#);
    }
}
