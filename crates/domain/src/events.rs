//! Domain event catalog and the event envelope delivered to sinks and webhooks.
//!
//! The application writes `OutboxMessage::DomainEvent(Envelope)` in the same transaction as the change; after
//! commit the dispatcher fans the envelope out to event sinks and webhook subscriptions. Payloads are thin: ids,
//! natural keys and ETags, never event content or e-mail addresses. Details such as summary and times are added
//! by the webhook layer only for subscriptions that ask for them.
//!
//! Event types and payload shapes are an external contract (webhook consumers, `events.schema.json`): they only
//! grow, and an event type keeps its payload shape forever.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};

use crate::audit::AuditActor;
use crate::entities::{CalendarKind, GrantAccess, GrantStatus};
use crate::ids::{
    CalendarId, EventId, ExternalAccountId, GrantId, ObjectId, OutboxId, PrincipalId, TenantId, WebhookId,
};
use crate::keys::{ETag, ExternalKey, ObjectUri, Uid};
use crate::sync::SyncToken;
use crate::vocab::{ItipMethod, PartStat};

/// The version of the envelope format. Additive changes keep the version.
pub const ENVELOPE_VERSION: u32 = 1;

/// The most object changes one `calendar.objects_changed` event lists; larger batches set `truncated` and
/// consumers fetch the rest from the changes feed.
pub const MAX_LISTED_CHANGES: usize = 100;

text_enum!(
    /// The catalog of domain events (PLAN 2.11).
    EventType [] {
        /// A principal was created.
        PrincipalCreated => "principal.created",
        /// A principal was changed.
        PrincipalUpdated => "principal.updated",
        /// A principal was deleted.
        PrincipalDeleted => "principal.deleted",
        /// The members of a group changed.
        MembershipChanged => "membership.changed",
        /// A calendar was created.
        CalendarCreated => "calendar.created",
        /// A calendar was changed.
        CalendarUpdated => "calendar.updated",
        /// A calendar was deleted.
        CalendarDeleted => "calendar.deleted",
        /// Objects of a calendar were created, changed or deleted.
        CalendarObjectsChanged => "calendar.objects_changed",
        /// A grant was created.
        GrantCreated => "grant.created",
        /// A grant was changed.
        GrantUpdated => "grant.updated",
        /// A grant was removed.
        GrantDeleted => "grant.deleted",
        /// A calendar was shared with someone.
        ShareInvited => "share.invited",
        /// A share invitation was accepted.
        ShareAccepted => "share.accepted",
        /// A share invitation was declined.
        ShareDeclined => "share.declined",
        /// An attendee's reply was applied to an organizer's object.
        SchedulingReplyReceived => "scheduling.reply_received",
        /// An inbound reply was rejected or quarantined.
        SchedulingReplyRejected => "scheduling.reply_rejected",
        /// An attendee answered through an RSVP link.
        RsvpAnswered => "rsvp.answered",
        /// A scheduling mail could not be delivered.
        MailDeliveryFailed => "mail.delivery_failed",
        /// Syncing an external account failed.
        ExternalAccountSyncFailed => "external_account.sync_failed",
        /// A webhook subscription was disabled after repeated failures.
        WebhookDisabled => "webhook.disabled",
        /// A test event an operator sent to one subscription (`POST …/webhooks/{id}/ping`); it is delivered
        /// whatever the subscription's event filter says.
        WebhookPing => "webhook.ping",
    }
);

/// Payload of `principal.*` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalPayload {
    /// The principal.
    pub principal: PrincipalId,
}

/// Payload of `membership.changed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MembershipPayload {
    /// The group.
    pub group: PrincipalId,
    /// Members that were added.
    pub added: Vec<PrincipalId>,
    /// Members that were removed.
    pub removed: Vec<PrincipalId>,
}

/// Payload of `calendar.created|updated|deleted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CalendarPayload {
    /// The calendar.
    pub calendar: CalendarId,
    /// The owning principal.
    pub owner: PrincipalId,
    /// The kind of calendar.
    pub kind: CalendarKind,
}

text_enum!(
    /// What happened to an object.
    ObjectChangeKind [] {
        /// The object was created.
        Created => "created",
        /// The object was changed.
        Updated => "updated",
        /// The object was deleted.
        Deleted => "deleted",
    }
);

/// One changed object in a `calendar.objects_changed` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObjectChange {
    /// What happened.
    pub kind: ObjectChangeKind,
    /// The object, when it still exists.
    pub object: Option<ObjectId>,
    /// The resource name.
    pub uri: ObjectUri,
    /// The iCalendar UID.
    pub uid: Uid,
    /// The caller-chosen key, if the object has one.
    pub external_key: Option<ExternalKey>,
    /// The new ETag; `None` for deletions.
    pub etag: Option<ETag>,
}

/// Payload of `calendar.objects_changed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObjectsChangedPayload {
    /// The calendar.
    pub calendar: CalendarId,
    /// The sync token after the change; the changes feed resumes from the previous one.
    pub sync_token: SyncToken,
    /// The changed objects, at most [`MAX_LISTED_CHANGES`].
    pub changes: Vec<ObjectChange>,
    /// Whether more objects changed than are listed.
    pub truncated: bool,
}

/// Payload of `grant.*` and `share.*` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantPayload {
    /// The calendar.
    pub calendar: CalendarId,
    /// The grant.
    pub grant: GrantId,
    /// The user, group or service principal that is granted access.
    pub grantee: PrincipalId,
    /// The access level.
    pub access: GrantAccess,
    /// The state of the grant after the event.
    pub status: GrantStatus,
    /// Whether the calendar is required for the people the grant reaches after the event. A change of the flag alone is a
    /// `grant.updated` too, and this field is how a consumer sees it.
    #[serde(default)]
    pub required: bool,
}

/// Payload of `scheduling.reply_received` and `scheduling.reply_rejected`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SchedulingReplyPayload {
    /// The organizer's calendar; `None` when a rejected reply matched no object.
    pub calendar: Option<CalendarId>,
    /// The organizer's object; `None` when a rejected reply matched no object.
    pub object: Option<ObjectId>,
    /// The UID of the event the reply is about.
    pub uid: Option<Uid>,
    /// The internal attendee, when the replying address resolves to a principal.
    pub attendee: Option<PrincipalId>,
    /// The answer; `None` when the message could not be read.
    pub partstat: Option<PartStat>,
    /// Why the reply was rejected (machine-readable), for rejections.
    pub reason: Option<String>,
}

/// Payload of `rsvp.answered`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RsvpPayload {
    /// The organizer's calendar.
    pub calendar: CalendarId,
    /// The organizer's object.
    pub object: ObjectId,
    /// The UID of the event.
    pub uid: Uid,
    /// The answer.
    pub partstat: PartStat,
}

/// Payload of `mail.delivery_failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MailFailurePayload {
    /// The outbox message that failed permanently.
    pub outbox: OutboxId,
    /// The object the mail was about, if any.
    pub object: Option<ObjectId>,
    /// The iTIP method of the mail, if it carried one.
    pub method: Option<ItipMethod>,
    /// A machine-readable reason, for example `rejected` or `timeout`.
    pub reason: String,
}

/// Payload of `external_account.sync_failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExternalAccountPayload {
    /// The external account.
    pub external_account: ExternalAccountId,
    /// The principal who owns it.
    pub principal: PrincipalId,
    /// The provider name.
    pub provider: String,
    /// A machine-readable reason, for example `auth_revoked`.
    pub reason: String,
}

/// Payload of `webhook.disabled` and `webhook.ping`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WebhookPayload {
    /// The webhook subscription.
    pub webhook: WebhookId,
    /// A machine-readable reason: `endpoint_gone` or `max_consecutive_failures` for `webhook.disabled`, `ping`
    /// for `webhook.ping`.
    pub reason: String,
}

impl WebhookPayload {
    /// The reason of `webhook.disabled` when the receiver answered 410 Gone.
    pub const ENDPOINT_GONE: &'static str = "endpoint_gone";
    /// The reason of `webhook.disabled` when the subscription failed `webhooks.max_consecutive_failures` times in
    /// a row.
    pub const MAX_CONSECUTIVE_FAILURES: &'static str = "max_consecutive_failures";
    /// The reason of `webhook.ping`, a test event an operator sent to one subscription.
    pub const PING: &'static str = "ping";
}

/// The payload of an event. Serialized without a tag: the envelope's `type` says which shape `data` has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum EventPayload {
    /// `principal.created|updated|deleted`.
    Principal(PrincipalPayload),
    /// `membership.changed`.
    Membership(MembershipPayload),
    /// `calendar.created|updated|deleted`.
    Calendar(CalendarPayload),
    /// `calendar.objects_changed`.
    ObjectsChanged(ObjectsChangedPayload),
    /// `grant.*` and `share.*`.
    Grant(GrantPayload),
    /// `scheduling.reply_received|reply_rejected`.
    SchedulingReply(SchedulingReplyPayload),
    /// `rsvp.answered`.
    Rsvp(RsvpPayload),
    /// `mail.delivery_failed`.
    MailFailure(MailFailurePayload),
    /// `external_account.sync_failed`.
    ExternalAccount(ExternalAccountPayload),
    /// `webhook.disabled` and `webhook.ping`.
    Webhook(WebhookPayload),
}

/// The payload shape of an event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Principal,
    Membership,
    Calendar,
    ObjectsChanged,
    Grant,
    SchedulingReply,
    Rsvp,
    MailFailure,
    ExternalAccount,
    Webhook,
}

impl EventType {
    const fn shape(self) -> Shape {
        match self {
            Self::PrincipalCreated | Self::PrincipalUpdated | Self::PrincipalDeleted => Shape::Principal,
            Self::MembershipChanged => Shape::Membership,
            Self::CalendarCreated | Self::CalendarUpdated | Self::CalendarDeleted => Shape::Calendar,
            Self::CalendarObjectsChanged => Shape::ObjectsChanged,
            Self::GrantCreated
            | Self::GrantUpdated
            | Self::GrantDeleted
            | Self::ShareInvited
            | Self::ShareAccepted
            | Self::ShareDeclined => Shape::Grant,
            Self::SchedulingReplyReceived | Self::SchedulingReplyRejected => Shape::SchedulingReply,
            Self::RsvpAnswered => Shape::Rsvp,
            Self::MailDeliveryFailed => Shape::MailFailure,
            Self::ExternalAccountSyncFailed => Shape::ExternalAccount,
            Self::WebhookDisabled | Self::WebhookPing => Shape::Webhook,
        }
    }
}

impl EventPayload {
    const fn shape(&self) -> Shape {
        match self {
            Self::Principal(_) => Shape::Principal,
            Self::Membership(_) => Shape::Membership,
            Self::Calendar(_) => Shape::Calendar,
            Self::ObjectsChanged(_) => Shape::ObjectsChanged,
            Self::Grant(_) => Shape::Grant,
            Self::SchedulingReply(_) => Shape::SchedulingReply,
            Self::Rsvp(_) => Shape::Rsvp,
            Self::MailFailure(_) => Shape::MailFailure,
            Self::ExternalAccount(_) => Shape::ExternalAccount,
            Self::Webhook(_) => Shape::Webhook,
        }
    }

    /// Whether this payload has the shape the event type promises.
    pub const fn fits(&self, event_type: EventType) -> bool {
        matches!(
            (self.shape(), event_type.shape()),
            (Shape::Principal, Shape::Principal)
                | (Shape::Membership, Shape::Membership)
                | (Shape::Calendar, Shape::Calendar)
                | (Shape::ObjectsChanged, Shape::ObjectsChanged)
                | (Shape::Grant, Shape::Grant)
                | (Shape::SchedulingReply, Shape::SchedulingReply)
                | (Shape::Rsvp, Shape::Rsvp)
                | (Shape::MailFailure, Shape::MailFailure)
                | (Shape::ExternalAccount, Shape::ExternalAccount)
                | (Shape::Webhook, Shape::Webhook)
        )
    }

    /// Reads the payload of an event of `event_type` from JSON.
    ///
    /// # Errors
    ///
    /// Returns the JSON error when `value` does not have the shape of `event_type`.
    pub fn from_json(event_type: EventType, value: serde_json::Value) -> Result<Self, serde_json::Error> {
        Ok(match event_type.shape() {
            Shape::Principal => Self::Principal(serde_json::from_value(value)?),
            Shape::Membership => Self::Membership(serde_json::from_value(value)?),
            Shape::Calendar => Self::Calendar(serde_json::from_value(value)?),
            Shape::ObjectsChanged => Self::ObjectsChanged(serde_json::from_value(value)?),
            Shape::Grant => Self::Grant(serde_json::from_value(value)?),
            Shape::SchedulingReply => Self::SchedulingReply(serde_json::from_value(value)?),
            Shape::Rsvp => Self::Rsvp(serde_json::from_value(value)?),
            Shape::MailFailure => Self::MailFailure(serde_json::from_value(value)?),
            Shape::ExternalAccount => Self::ExternalAccount(serde_json::from_value(value)?),
            Shape::Webhook => Self::Webhook(serde_json::from_value(value)?),
        })
    }
}

/// Error for an envelope whose payload does not match its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("payload does not match event type {event_type}")]
pub struct PayloadMismatch {
    /// The event type that was claimed.
    pub event_type: EventType,
}

/// A domain event as stored in the outbox and delivered to sinks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Envelope {
    /// Unique id of the event (UUIDv7); webhook consumers deduplicate on it.
    pub id: EventId,
    /// What happened.
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// The envelope format version, currently [`ENVELOPE_VERSION`].
    pub version: u32,
    /// The tenant the event belongs to.
    pub tenant: TenantId,
    /// When the change was committed (from the `Clock`).
    pub occurred_at: DateTime<Utc>,
    /// Who caused the event.
    pub actor: AuditActor,
    /// The payload; its shape is determined by `type`.
    pub data: EventPayload,
}

impl Envelope {
    /// Creates an envelope of the current version.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadMismatch`] when `data` does not have the shape of `event_type`.
    pub fn new(
        id: EventId,
        event_type: EventType,
        tenant: TenantId,
        occurred_at: DateTime<Utc>,
        actor: AuditActor,
        data: EventPayload,
    ) -> Result<Self, PayloadMismatch> {
        if !data.fits(event_type) {
            return Err(PayloadMismatch { event_type });
        }
        Ok(Self {
            id,
            event_type,
            version: ENVELOPE_VERSION,
            tenant,
            occurred_at,
            actor,
            data,
        })
    }
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            id: EventId,
            #[serde(rename = "type")]
            event_type: EventType,
            version: u32,
            tenant: TenantId,
            occurred_at: DateTime<Utc>,
            actor: AuditActor,
            data: serde_json::Value,
        }
        let raw = Raw::deserialize(deserializer)?;
        let data = EventPayload::from_json(raw.event_type, raw.data).map_err(D::Error::custom)?;
        Ok(Self {
            id: raw.id,
            event_type: raw.event_type,
            version: raw.version,
            tenant: raw.tenant,
            occurred_at: raw.occurred_at,
            actor: raw.actor,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn p(n: u128) -> PrincipalId {
        PrincipalId::from_uuid(Uuid::from_u128(n))
    }

    fn c(n: u128) -> CalendarId {
        CalendarId::from_uuid(Uuid::from_u128(n))
    }

    fn o(n: u128) -> ObjectId {
        ObjectId::from_uuid(Uuid::from_u128(n))
    }

    fn sample_payload(event_type: EventType) -> EventPayload {
        match event_type.shape() {
            Shape::Principal => EventPayload::Principal(PrincipalPayload { principal: p(1) }),
            Shape::Membership => EventPayload::Membership(MembershipPayload {
                group: p(1),
                added: vec![p(2)],
                removed: vec![p(3), p(4)],
            }),
            Shape::Calendar => EventPayload::Calendar(CalendarPayload {
                calendar: c(1),
                owner: p(2),
                kind: CalendarKind::Group,
            }),
            Shape::ObjectsChanged => EventPayload::ObjectsChanged(ObjectsChangedPayload {
                calendar: c(1),
                sync_token: SyncToken::new(Uuid::from_u128(1), Uuid::from_u128(2), 9),
                changes: vec![
                    ObjectChange {
                        kind: ObjectChangeKind::Created,
                        object: Some(o(5)),
                        uri: ObjectUri::parse("a.ics").unwrap(),
                        uid: Uid::parse("uid-a").unwrap(),
                        external_key: Some(ExternalKey::parse("booking:1").unwrap()),
                        etag: Some(ETag::from_bytes(b"a")),
                    },
                    ObjectChange {
                        kind: ObjectChangeKind::Deleted,
                        object: None,
                        uri: ObjectUri::parse("b.ics").unwrap(),
                        uid: Uid::parse("uid-b").unwrap(),
                        external_key: None,
                        etag: None,
                    },
                ],
                truncated: false,
            }),
            Shape::Grant => EventPayload::Grant(GrantPayload {
                calendar: c(1),
                grant: GrantId::from_uuid(Uuid::from_u128(6)),
                grantee: p(2),
                access: GrantAccess::ReadWrite,
                status: GrantStatus::Pending,
                required: true,
            }),
            Shape::SchedulingReply => EventPayload::SchedulingReply(SchedulingReplyPayload {
                calendar: Some(c(1)),
                object: Some(o(2)),
                uid: Some(Uid::parse("uid-r").unwrap()),
                attendee: Some(p(3)),
                partstat: Some(PartStat::Accepted),
                reason: None,
            }),
            Shape::Rsvp => EventPayload::Rsvp(RsvpPayload {
                calendar: c(1),
                object: o(2),
                uid: Uid::parse("uid-r").unwrap(),
                partstat: PartStat::Declined,
            }),
            Shape::MailFailure => EventPayload::MailFailure(MailFailurePayload {
                outbox: OutboxId::from_uuid(Uuid::from_u128(7)),
                object: Some(o(2)),
                method: Some(ItipMethod::Request),
                reason: "rejected".to_owned(),
            }),
            Shape::ExternalAccount => EventPayload::ExternalAccount(ExternalAccountPayload {
                external_account: ExternalAccountId::from_uuid(Uuid::from_u128(8)),
                principal: p(1),
                provider: "google".to_owned(),
                reason: "auth_revoked".to_owned(),
            }),
            Shape::Webhook => EventPayload::Webhook(WebhookPayload {
                webhook: WebhookId::from_uuid(Uuid::from_u128(9)),
                reason: "max_consecutive_failures".to_owned(),
            }),
        }
    }

    fn envelope(event_type: EventType) -> Envelope {
        Envelope::new(
            EventId::from_uuid(Uuid::from_u128(100)),
            event_type,
            TenantId::from_uuid(Uuid::from_u128(200)),
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            AuditActor::system(),
            sample_payload(event_type),
        )
        .unwrap()
    }

    #[test]
    fn the_catalog_matches_the_plan() {
        let names: Vec<&str> = EventType::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "principal.created",
                "principal.updated",
                "principal.deleted",
                "membership.changed",
                "calendar.created",
                "calendar.updated",
                "calendar.deleted",
                "calendar.objects_changed",
                "grant.created",
                "grant.updated",
                "grant.deleted",
                "share.invited",
                "share.accepted",
                "share.declined",
                "scheduling.reply_received",
                "scheduling.reply_rejected",
                "rsvp.answered",
                "mail.delivery_failed",
                "external_account.sync_failed",
                "webhook.disabled",
                "webhook.ping",
            ]
        );
        for event_type in EventType::ALL {
            assert_eq!(event_type.as_str().parse::<EventType>().unwrap(), *event_type);
            assert_eq!(serde_json::to_string(event_type).unwrap(), format!("\"{event_type}\""));
        }
    }

    #[test]
    fn every_event_type_round_trips_through_json() {
        for event_type in EventType::ALL {
            let original = envelope(*event_type);
            assert!(original.data.fits(*event_type));
            let json = serde_json::to_string(&original).unwrap();
            let back: Envelope = serde_json::from_str(&json).unwrap();
            assert_eq!(back, original, "{event_type}");
        }
    }

    #[test]
    fn the_envelope_has_the_documented_members() {
        let value = serde_json::to_value(envelope(EventType::RsvpAnswered)).unwrap();
        let mut keys: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["actor", "data", "id", "occurred_at", "tenant", "type", "version"]
        );
        assert_eq!(value["type"], "rsvp.answered");
        assert_eq!(value["version"], 1);
        assert_eq!(value["occurred_at"], "2027-01-15T08:00:00Z");
        assert_eq!(value["data"]["partstat"], "declined");
        assert_eq!(value["actor"]["kind"], "system");
    }

    #[test]
    fn mismatched_payloads_are_rejected() {
        let wrong = Envelope::new(
            EventId::from_uuid(Uuid::from_u128(1)),
            EventType::RsvpAnswered,
            TenantId::from_uuid(Uuid::from_u128(2)),
            DateTime::from_timestamp(0, 0).unwrap(),
            AuditActor::system(),
            sample_payload(EventType::PrincipalCreated),
        );
        assert_eq!(
            wrong.unwrap_err(),
            PayloadMismatch {
                event_type: EventType::RsvpAnswered
            }
        );

        // The same check applies when reading: a principal payload does not parse as an RSVP answer.
        let mut value = serde_json::to_value(envelope(EventType::PrincipalCreated)).unwrap();
        value["type"] = serde_json::json!("rsvp.answered");
        assert!(serde_json::from_value::<Envelope>(value).is_err());
        let mut value = serde_json::to_value(envelope(EventType::PrincipalCreated)).unwrap();
        value["type"] = serde_json::json!("principal.exploded");
        assert!(serde_json::from_value::<Envelope>(value).is_err());
    }

    #[test]
    fn every_type_accepts_exactly_the_payload_shapes_of_its_family() {
        for event_type in EventType::ALL {
            for other in EventType::ALL {
                let fits = sample_payload(*other).fits(*event_type);
                assert_eq!(
                    fits,
                    event_type.shape() == other.shape(),
                    "{event_type} vs payload of {other}"
                );
            }
        }
    }

    #[test]
    fn payloads_are_thin() {
        // No payload field carries content or addresses; every member of every sample is an id, a key, a
        // timestamp, a status or a short machine-readable reason.
        let forbidden = [
            "summary",
            "description",
            "location",
            "email",
            "address",
            "name",
            "title",
            "ics",
            "body",
        ];
        for event_type in EventType::ALL {
            let value = serde_json::to_value(sample_payload(*event_type)).unwrap();
            let mut stack = vec![&value];
            while let Some(value) = stack.pop() {
                match value {
                    serde_json::Value::Object(map) => {
                        for (key, inner) in map {
                            assert!(
                                !forbidden.iter().any(|word| key.contains(word)),
                                "{event_type}: field {key}"
                            );
                            stack.push(inner);
                        }
                    }
                    serde_json::Value::Array(items) => stack.extend(items.iter()),
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn the_listing_limit_is_documented_as_a_constant() {
        assert_eq!(MAX_LISTED_CHANGES, 100);
        assert_eq!(ENVELOPE_VERSION, 1);
    }
}
