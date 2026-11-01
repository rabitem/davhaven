//! The outbox message model and the `OutboxHandler` port.
//!
//! The application writes an [`OutboxMessage`] in the same transaction as the change that causes it (domain
//! events, scheduling mail, internal delivery above the synchronous cap, webhook deliveries). After commit the
//! dispatcher in `davhaven-app` claims ready records with `OutboxQueue::claim`, picks the [`OutboxHandler`] whose
//! `kind()` equals the record's kind and reports the outcome back: complete, retry with backoff or dead.
//!
//! Messages are versioned: the `schema_version` column lets a newer binary change a payload while an older one
//! still reads what it wrote. Payloads reference entities by id wherever possible and never carry rendered
//! content.

use core::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarId, CalendarUserAddress, DeliveryId, Envelope, ItipMethod, Locale, ObjectId, OutboxId, PrincipalId,
    TenantId, WebhookId,
};
use serde::{Deserialize, Serialize};

use crate::error::HandlerError;
use crate::templates::TemplateName;

/// The `kind` strings of outbox records; [`OutboxHandler::kind`] returns one of them.
pub mod kind {
    /// An iMIP mail to an external attendee.
    pub const IMIP: &str = "imip";
    /// Internal delivery queued because the attendee count exceeds the synchronous cap.
    pub const INTERNAL_DELIVERY: &str = "internal_delivery";
    /// One webhook delivery.
    pub const WEBHOOK: &str = "webhook";
    /// A domain event waiting to be fanned out to sinks and webhook subscriptions.
    pub const DOMAIN_EVENT: &str = "domain_event";
    /// Reserved for pushing changes to an external provider (backlog).
    pub const PROVIDER_PUSH: &str = "provider_push";
}

/// The payload schema version this build writes and reads.
pub const SCHEMA_VERSION: u32 = 1;

/// A scheduling mail to one external attendee. The handler renders `template` in `locale`, builds the iTIP part
/// and hands the mail to the `MailTransport`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImipJob {
    /// The organizer's calendar object the message is about.
    pub object: ObjectId,
    /// The external recipient.
    pub recipient: CalendarUserAddress,
    /// The iTIP method of the message.
    pub method: ItipMethod,
    /// The recipient's locale, when known; the tenant locale applies otherwise.
    pub locale: Option<Locale>,
    /// The mail template.
    pub template: TemplateName,
    /// The iCalendar text the message is built from, for messages that must survive a deletion of the object
    /// (`CANCEL`, and the `REPLY` an attendee's deletion of the own copy sends) or must carry exactly the version
    /// that triggered them. When absent the handler reads the stored object. A `REPLY` job always carries one,
    /// because the copy it is about is gone, or changes again, by the time the mail goes out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// For a `REPLY`: the attendee who answers (the address of the principal whose copy changed or was deleted).
    /// The handler names the sender of the mail after this attendee and reads the `PARTSTAT` of this attendee from
    /// the snapshot; it never looks at the stored object for it, which is gone when the answer is a deletion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replying_attendee: Option<CalendarUserAddress>,
    /// For a `REPLY`: the comment the attendee gave with the answer (at most 500 characters), shown to the
    /// organizer in the mail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl fmt::Debug for ImipJob {
    /// Redacts the recipient: e-mail addresses never appear in logs (`ENGINEERING_RULES` R8).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImipJob")
            .field("object", &self.object)
            .field("recipient", &"<redacted>")
            .field("method", &self.method)
            .field("template", &self.template)
            .finish_non_exhaustive()
    }
}

/// Internal delivery of an iTIP message to attendees in the same tenant, queued when there are more than
/// `scheduling.max_sync_internal_attendees`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryJob {
    /// The organizer's calendar.
    pub calendar: CalendarId,
    /// The organizer's calendar object the message is about.
    pub object: ObjectId,
    /// The iTIP method of the message: `REQUEST` or `CANCEL`.
    pub method: ItipMethod,
    /// The internal attendees that still have to receive it.
    pub recipients: Vec<PrincipalId>,
    /// The iCalendar text to deliver, when the stored object may have changed by dispatch time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// Whether the recipients' copies of the event are only brought up to date and no message is put into their
    /// scheduling inboxes (an edit that is not significant). Records written before the field existed deliver
    /// messages.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub copy_only: bool,
}

/// One webhook delivery: the event and the subscription it goes to.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// The delivery record that tracks attempts and outcome.
    pub delivery: DeliveryId,
    /// The subscription that receives the event.
    pub webhook: WebhookId,
    /// The event to deliver (a thin envelope).
    pub envelope: Envelope,
    /// The details of the objects the event is about (summary and times), for a subscription with
    /// `include_details`. The application writes them when it fans the event out, from objects of managed and
    /// group calendars only, and the webhook handler copies them into `data.details` of the request when the
    /// subscription still asks for them; the handler never reads calendar data itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl fmt::Debug for WebhookDelivery {
    /// Omits the details, which hold the summaries of events.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookDelivery")
            .field("delivery", &self.delivery)
            .field("webhook", &self.webhook)
            .field("envelope", &self.envelope)
            .field("details", &self.details.as_ref().map(|_| "<details>"))
            .finish()
    }
}

/// Placeholder payload of a reserved message kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Reserved {}

/// Why an outbox record could not be turned into an [`OutboxMessage`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutboxDecodeError {
    /// The kind is not known to this build (a newer binary wrote it).
    #[error("unknown outbox kind `{0}`")]
    UnknownKind(String),
    /// The payload was written with a newer schema version than this build reads.
    #[error("outbox payload of kind `{kind}` has unsupported schema version {version}")]
    UnsupportedVersion {
        /// The record's kind.
        kind: String,
        /// The record's schema version.
        version: u32,
    },
    /// The payload does not have the shape of its kind.
    #[error("outbox payload of kind `{kind}` is malformed: {message}")]
    Malformed {
        /// The record's kind.
        kind: String,
        /// What the decoder reported.
        message: String,
    },
}

/// A message in the outbox.
///
/// The serialized form is `{"kind": ..., "payload": ...}`; stores keep the two parts in separate columns, using
/// [`OutboxMessage::to_parts`] and [`OutboxMessage::from_parts`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum OutboxMessage {
    /// A scheduling mail to an external attendee.
    Imip(ImipJob),
    /// Internal delivery above the synchronous cap.
    InternalDelivery(DeliveryJob),
    /// One webhook delivery.
    Webhook(WebhookDelivery),
    /// A domain event waiting for fan-out.
    DomainEvent(Envelope),
    /// Reserved for pushing changes to a provider.
    ProviderPush(Reserved),
}

impl OutboxMessage {
    /// The `kind` string of the message (see [`kind`]).
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Imip(_) => kind::IMIP,
            Self::InternalDelivery(_) => kind::INTERNAL_DELIVERY,
            Self::Webhook(_) => kind::WEBHOOK,
            Self::DomainEvent(_) => kind::DOMAIN_EVENT,
            Self::ProviderPush(_) => kind::PROVIDER_PUSH,
        }
    }

    /// The payload schema version this build writes.
    pub const fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    /// The payload as JSON, without the kind tag (the `payload` column).
    ///
    /// # Errors
    ///
    /// Returns the serializer's error, which cannot happen for the message types of this module.
    pub fn payload(&self) -> Result<serde_json::Value, serde_json::Error> {
        match self {
            Self::Imip(job) => serde_json::to_value(job),
            Self::InternalDelivery(job) => serde_json::to_value(job),
            Self::Webhook(delivery) => serde_json::to_value(delivery),
            Self::DomainEvent(envelope) => serde_json::to_value(envelope),
            Self::ProviderPush(reserved) => serde_json::to_value(reserved),
        }
    }

    /// Splits the message into the `kind`, `schema_version` and `payload` columns.
    ///
    /// # Errors
    ///
    /// Same as [`OutboxMessage::payload`].
    pub fn to_parts(&self) -> Result<(&'static str, u32, serde_json::Value), serde_json::Error> {
        Ok((self.kind(), self.schema_version(), self.payload()?))
    }

    /// Reads a message from the columns of a record.
    ///
    /// # Errors
    ///
    /// * [`OutboxDecodeError::UnknownKind`] for a kind this build does not know.
    /// * [`OutboxDecodeError::UnsupportedVersion`] for a payload newer than [`SCHEMA_VERSION`].
    /// * [`OutboxDecodeError::Malformed`] when the payload does not fit its kind.
    pub fn from_parts(kind: &str, schema_version: u32, payload: &serde_json::Value) -> Result<Self, OutboxDecodeError> {
        let known = [
            self::kind::IMIP,
            self::kind::INTERNAL_DELIVERY,
            self::kind::WEBHOOK,
            self::kind::DOMAIN_EVENT,
            self::kind::PROVIDER_PUSH,
        ];
        if !known.contains(&kind) {
            return Err(OutboxDecodeError::UnknownKind(kind.to_owned()));
        }
        if schema_version > SCHEMA_VERSION {
            return Err(OutboxDecodeError::UnsupportedVersion {
                kind: kind.to_owned(),
                version: schema_version,
            });
        }
        let tagged = serde_json::json!({ "kind": kind, "payload": payload });
        serde_json::from_value(tagged).map_err(|error| OutboxDecodeError::Malformed {
            kind: kind.to_owned(),
            message: error.to_string(),
        })
    }
}

/// The lifecycle state of an outbox record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    /// Waiting for `next_attempt_at`.
    Pending,
    /// Claimed by a dispatcher until `locked_until`.
    InFlight,
    /// Handled successfully.
    Done,
    /// Failed permanently or exhausted its attempts; waits for an operator to retry it.
    Dead,
}

impl OutboxStatus {
    /// Every status, in lifecycle order.
    pub const ALL: [Self; 4] = [Self::Pending, Self::InFlight, Self::Done, Self::Dead];

    /// The database and JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InFlight => "in_flight",
            Self::Done => "done",
            Self::Dead => "dead",
        }
    }
}

impl fmt::Display for OutboxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Identifies one outbox record across tenants (the dispatcher works on records of all tenants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutboxKey {
    /// The tenant of the record.
    pub tenant: TenantId,
    /// The record id.
    pub id: OutboxId,
}

/// The proof that a dispatcher holds the lease of an outbox record: the key plus the attempt number and lease end
/// the claim wrote (every claim increments `attempts` and sets a new `locked_until`). The fenced settle methods
/// of [`OutboxQueue`](crate::store::OutboxQueue) only act while the stored values still equal these, so a
/// dispatcher whose lease ran out cannot settle a record that another dispatcher has since reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboxClaim {
    /// The record.
    pub key: OutboxKey,
    /// The value of `attempts` the claim produced.
    pub attempt: u32,
    /// The value of `locked_until` the claim produced.
    pub locked_until: DateTime<Utc>,
}

/// An outbox record as stored.
#[derive(Clone, PartialEq)]
pub struct OutboxRecord {
    /// Record id. Also the stable part of the `Message-ID` of mail sent for it.
    pub id: OutboxId,
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The message kind (see [`kind`]).
    pub kind: String,
    /// The payload schema version.
    pub schema_version: u32,
    /// The payload (see [`OutboxMessage`]).
    pub payload: serde_json::Value,
    /// Lifecycle state.
    pub status: OutboxStatus,
    /// How many times the record has been claimed.
    pub attempts: u32,
    /// When the record is next due.
    pub next_attempt_at: DateTime<Utc>,
    /// While `InFlight`: when the claim expires.
    pub locked_until: Option<DateTime<Utc>>,
    /// The error of the last failed attempt, for operators.
    pub last_error: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
}

impl OutboxRecord {
    /// The key of the record across tenants.
    pub const fn key(&self) -> OutboxKey {
        OutboxKey {
            tenant: self.tenant_id,
            id: self.id,
        }
    }

    /// The proof of the claim that returned this record, for the fenced settle methods of
    /// [`OutboxQueue`](crate::store::OutboxQueue); `None` for a record that is not in flight (a read through the
    /// outbox repository).
    pub fn claim(&self) -> Option<OutboxClaim> {
        let locked_until = self.locked_until?;
        (self.status == OutboxStatus::InFlight).then_some(OutboxClaim {
            key: self.key(),
            attempt: self.attempts,
            locked_until,
        })
    }

    /// Decodes the message.
    ///
    /// # Errors
    ///
    /// See [`OutboxMessage::from_parts`].
    pub fn message(&self) -> Result<OutboxMessage, OutboxDecodeError> {
        OutboxMessage::from_parts(&self.kind, self.schema_version, &self.payload)
    }
}

impl fmt::Debug for OutboxRecord {
    /// Omits the payload, which can contain recipient addresses.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboxRecord")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("kind", &self.kind)
            .field("schema_version", &self.schema_version)
            .field("status", &self.status)
            .field("attempts", &self.attempts)
            .field("next_attempt_at", &self.next_attempt_at)
            .field("locked_until", &self.locked_until)
            .finish_non_exhaustive()
    }
}

/// A message to enqueue.
#[derive(Debug, Clone, PartialEq)]
pub struct NewOutbox {
    /// The record id (from the `IdGenerator`).
    pub id: OutboxId,
    /// The message.
    pub message: OutboxMessage,
    /// Earliest delivery time; `None` means as soon as possible.
    pub not_before: Option<DateTime<Utc>>,
}

impl NewOutbox {
    /// A message that is due immediately.
    pub const fn now(id: OutboxId, message: OutboxMessage) -> Self {
        Self {
            id,
            message,
            not_before: None,
        }
    }

    /// A message that is due at `not_before`.
    pub const fn at(id: OutboxId, message: OutboxMessage, not_before: DateTime<Utc>) -> Self {
        Self {
            id,
            message,
            not_before: Some(not_before),
        }
    }
}

/// How a failed attempt is recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxFailure {
    /// The error text for operators (no secrets, no addresses).
    pub error: String,
    /// When to try again; `None` dead-letters the record.
    pub retry_at: Option<DateTime<Utc>>,
}

impl OutboxFailure {
    /// Schedules another attempt at `retry_at`.
    pub fn retry(error: impl Into<String>, retry_at: DateTime<Utc>) -> Self {
        Self {
            error: error.into(),
            retry_at: Some(retry_at),
        }
    }

    /// Dead-letters the record.
    pub fn dead(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            retry_at: None,
        }
    }
}

/// Queue depth for the `outbox_pending`, `outbox_oldest_pending_age_seconds` and `outbox_dead_total` metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutboxStats {
    /// Records waiting for their next attempt.
    pub pending: u64,
    /// Records currently claimed.
    pub in_flight: u64,
    /// Dead records.
    pub dead: u64,
    /// The due time of the oldest pending record.
    pub oldest_pending_at: Option<DateTime<Utc>>,
}

/// Handles outbox records of one kind.
#[async_trait]
pub trait OutboxHandler: Send + Sync {
    /// The record kind this handler takes (one of [`kind`]).
    fn kind(&self) -> &'static str;

    /// Handles one record. Handlers are idempotent: a record can be delivered more than once (a lease expired
    /// while the handler ran, or the process stopped after the side effect).
    ///
    /// # Errors
    ///
    /// [`HandlerError::Retryable`] reschedules the record with backoff until `outbox.max_attempts`;
    /// [`HandlerError::Permanent`] dead-letters it.
    async fn handle(&self, record: &OutboxRecord) -> Result<(), HandlerError>;

    /// Whether the dispatcher dead-letters a record of this kind once it has been claimed `outbox.max_attempts`
    /// times. This is the default.
    ///
    /// A handler that bounds its retries by time instead (webhook deliveries retry until `webhooks.retry_window`
    /// has passed, which is longer than twelve attempts at the default backoff) returns `false`: the dispatcher
    /// then keeps rescheduling `Retryable` failures with backoff, and the handler answers
    /// [`HandlerError::Permanent`] itself when its deadline has passed.
    fn limits_attempts(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use davhaven_domain::events::CalendarPayload;
    use davhaven_domain::{AuditActor, CalendarKind, EventId, EventPayload, EventType};
    use uuid::Uuid;

    use super::*;

    fn uuid<T: From<Uuid>>(n: u128) -> T {
        T::from(Uuid::from_u128(n))
    }

    fn envelope() -> Envelope {
        Envelope::new(
            uuid::<EventId>(1),
            EventType::CalendarCreated,
            uuid(2),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
            AuditActor::system(),
            EventPayload::Calendar(CalendarPayload {
                calendar: uuid(3),
                owner: uuid(4),
                kind: CalendarKind::Group,
            }),
        )
        .unwrap()
    }

    fn imip() -> ImipJob {
        ImipJob {
            object: uuid(5),
            recipient: CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
            method: ItipMethod::Request,
            locale: Some(Locale::de()),
            template: TemplateName::parse("imip_request").unwrap(),
            snapshot: None,
            replying_attendee: None,
            comment: None,
        }
    }

    fn messages() -> Vec<OutboxMessage> {
        vec![
            OutboxMessage::Imip(imip()),
            OutboxMessage::InternalDelivery(DeliveryJob {
                calendar: uuid(6),
                object: uuid(7),
                method: ItipMethod::Cancel,
                recipients: vec![uuid(8), uuid(9)],
                snapshot: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned()),
                copy_only: false,
            }),
            OutboxMessage::Webhook(WebhookDelivery {
                delivery: uuid(10),
                webhook: uuid(11),
                envelope: envelope(),
                details: None,
            }),
            OutboxMessage::DomainEvent(envelope()),
            OutboxMessage::ProviderPush(Reserved::default()),
        ]
    }

    #[test]
    fn every_message_round_trips_through_its_columns() {
        for message in messages() {
            let (kind, version, payload) = message.to_parts().unwrap();
            assert_eq!(kind, message.kind());
            assert_eq!(version, SCHEMA_VERSION);
            assert_eq!(OutboxMessage::from_parts(kind, version, &payload).unwrap(), message);
        }
    }

    #[test]
    fn serialized_form_is_kind_plus_payload() {
        let message = OutboxMessage::Imip(imip());
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["kind"], "imip");
        assert_eq!(json["payload"]["method"], "request");
        assert_eq!(serde_json::from_value::<OutboxMessage>(json).unwrap(), message);
        let kinds: Vec<&str> = messages().iter().map(OutboxMessage::kind).collect();
        assert_eq!(
            kinds,
            vec!["imip", "internal_delivery", "webhook", "domain_event", "provider_push"]
        );
    }

    #[test]
    fn snapshots_are_omitted_when_absent_and_default_when_missing() {
        let payload = OutboxMessage::Imip(imip()).payload().unwrap();
        assert!(payload.get("snapshot").is_none(), "{payload}");
        let decoded = OutboxMessage::from_parts("imip", 1, &payload).unwrap();
        assert!(matches!(decoded, OutboxMessage::Imip(job) if job.snapshot.is_none()));
    }

    #[test]
    fn reply_fields_and_details_are_optional_on_the_wire_and_survive_a_round_trip() {
        let payload = OutboxMessage::Imip(imip()).payload().unwrap();
        for key in ["replying_attendee", "comment"] {
            assert!(payload.get(key).is_none(), "{key}: {payload}");
        }
        let reply = OutboxMessage::Imip(ImipJob {
            method: ItipMethod::Reply,
            replying_attendee: Some(CalendarUserAddress::parse("mailto:ann@example.org").unwrap()),
            comment: Some("Running late".to_owned()),
            snapshot: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned()),
            ..imip()
        });
        let (kind, version, payload) = reply.to_parts().unwrap();
        assert_eq!(payload["replying_attendee"], "mailto:ann@example.org");
        assert_eq!(OutboxMessage::from_parts(kind, version, &payload).unwrap(), reply);

        let thin = serde_json::json!({
            "delivery": uuid::<DeliveryId>(10),
            "webhook": uuid::<WebhookId>(11),
            "envelope": envelope(),
        });
        let decoded: WebhookDelivery = serde_json::from_value(thin).unwrap();
        assert!(
            decoded.details.is_none(),
            "a payload written before the field existed still decodes"
        );
        let detailed = WebhookDelivery {
            details: Some(serde_json::json!({"objects": [{"summary": "Planning"}]})),
            ..decoded
        };
        let json = serde_json::to_value(&detailed).unwrap();
        assert_eq!(serde_json::from_value::<WebhookDelivery>(json).unwrap(), detailed);
        let shown = format!("{detailed:?}");
        assert!(!shown.contains("Planning"), "the debug output hides summaries: {shown}");
    }

    #[test]
    fn decoding_reports_unknown_kinds_versions_and_malformed_payloads() {
        let payload = serde_json::json!({});
        assert_eq!(
            OutboxMessage::from_parts("carrier_pigeon", 1, &payload),
            Err(OutboxDecodeError::UnknownKind("carrier_pigeon".to_owned()))
        );
        assert_eq!(
            OutboxMessage::from_parts("webhook", SCHEMA_VERSION + 1, &payload),
            Err(OutboxDecodeError::UnsupportedVersion {
                kind: "webhook".to_owned(),
                version: SCHEMA_VERSION + 1
            })
        );
        let error = OutboxMessage::from_parts("imip", 1, &payload).unwrap_err();
        assert!(
            matches!(error, OutboxDecodeError::Malformed { ref kind, .. } if kind == "imip"),
            "{error}"
        );
        assert!(OutboxMessage::from_parts("provider_push", 1, &payload).is_ok());
    }

    #[test]
    fn records_decode_and_do_not_debug_print_payloads() {
        let message = OutboxMessage::Imip(imip());
        let (kind, version, payload) = message.to_parts().unwrap();
        let record = OutboxRecord {
            id: uuid(20),
            tenant_id: uuid(21),
            kind: kind.to_owned(),
            schema_version: version,
            payload,
            status: OutboxStatus::Pending,
            attempts: 0,
            next_attempt_at: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
            locked_until: None,
            last_error: None,
            created_at: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
        };
        assert_eq!(record.message().unwrap(), message);
        assert_eq!(
            record.key(),
            OutboxKey {
                tenant: uuid(21),
                id: uuid(20)
            }
        );
        let shown = format!("{record:?}");
        assert!(!shown.contains("guest@example.org"), "{shown}");
        assert!(!shown.contains("payload"), "{shown}");
        let job = format!("{:?}", imip());
        assert!(!job.contains("guest@example.org"), "{job}");
    }

    #[test]
    fn only_a_claimed_record_has_a_claim() {
        let (kind, version, payload) = OutboxMessage::Imip(imip()).to_parts().unwrap();
        let at = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
        let mut record = OutboxRecord {
            id: uuid(20),
            tenant_id: uuid(21),
            kind: kind.to_owned(),
            schema_version: version,
            payload,
            status: OutboxStatus::Pending,
            attempts: 0,
            next_attempt_at: at,
            locked_until: None,
            last_error: None,
            created_at: at,
            updated_at: at,
        };
        assert_eq!(record.claim(), None, "a pending record is held by nobody");
        record.status = OutboxStatus::InFlight;
        record.attempts = 3;
        assert_eq!(
            record.claim(),
            None,
            "an in-flight record without a lease end has no proof to show"
        );
        let lease = at + chrono::TimeDelta::minutes(1);
        record.locked_until = Some(lease);
        assert_eq!(
            record.claim(),
            Some(OutboxClaim {
                key: record.key(),
                attempt: 3,
                locked_until: lease
            })
        );
        record.status = OutboxStatus::Done;
        assert_eq!(record.claim(), None, "a settled record is not claimed any more");
    }

    #[test]
    fn statuses_use_their_database_spelling() {
        let names: Vec<&str> = OutboxStatus::ALL.iter().map(|status| status.as_str()).collect();
        assert_eq!(names, vec!["pending", "in_flight", "done", "dead"]);
        assert_eq!(serde_json::to_string(&OutboxStatus::InFlight).unwrap(), "\"in_flight\"");
        assert_eq!(OutboxStatus::Dead.to_string(), "dead");
    }

    struct Plain;

    #[async_trait]
    impl OutboxHandler for Plain {
        fn kind(&self) -> &'static str {
            kind::IMIP
        }

        async fn handle(&self, _record: &OutboxRecord) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    #[test]
    fn handlers_limit_attempts_unless_they_say_otherwise() {
        assert!(Plain.limits_attempts());
        assert_eq!(Plain.kind(), "imip");
    }

    #[test]
    fn enqueue_and_failure_constructors() {
        let at = Utc.with_ymd_and_hms(2027, 2, 1, 0, 0, 0).unwrap();
        let now = NewOutbox::now(uuid(1), OutboxMessage::ProviderPush(Reserved::default()));
        assert!(now.not_before.is_none());
        let later = NewOutbox::at(uuid(1), OutboxMessage::ProviderPush(Reserved::default()), at);
        assert_eq!(later.not_before, Some(at));
        assert_eq!(OutboxFailure::retry("x", at).retry_at, Some(at));
        assert_eq!(OutboxFailure::dead("x").retry_at, None);
    }
}
