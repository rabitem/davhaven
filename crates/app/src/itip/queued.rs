//! The `internal_delivery` outbox handler: delivery to internal recipients above the synchronous cap.
//!
//! An organizer's write delivers to the internal attendees inside its own transaction up to
//! `scheduling.max_sync_internal_attendees` (PLAN 2.8). The attendees beyond that number are queued: the write stores
//! one `OutboxMessage::InternalDelivery` per kind of delivery with the recipients and a snapshot of the organizer's
//! copy (the version that triggered the delivery, with the addresses that may leave the server already rewritten).
//! After the commit this handler delivers them with the same [`ItipProcessor`] the synchronous path uses, in a
//! transaction of its own:
//!
//! | Record | What each recipient gets |
//! | --- | --- |
//! | `REQUEST` | the invitation in the scheduling inbox, and a copy of the event by policy |
//! | `CANCEL` | the cancellation in the scheduling inbox, and their copy removed |
//! | `REQUEST` with `copy_only` | their copy brought up to date, no message (an edit that is not significant) |
//!
//! # Idempotence
//!
//! A record can be handled more than once (a lease that ran out, a crash after the commit). The inbox items are named
//! after the record and the recipient, so a second pass finds what the first one delivered; a copy that already holds
//! the new content is left alone and a copy that is gone stays gone. A recipient who was deleted or suspended in the
//! meantime is skipped, and so is one who was removed from the event since an invitation or an update was queued for
//! them (the cancellation that removed them is a record of its own and still reaches them).
//!
//! The messages carry the `DTSTAMP` of the moment the record was queued, not of the delivery, so a `CANCEL` queued
//! after a `REQUEST` is never older than it (RFC 5546 section 2.1.5), however late the dispatcher runs.

use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    AddressKind, CalendarId, CalendarUserAddress, ErrorKind, IcalLimits, ItipMethod, ObjectUri, Principal, PrincipalId,
    PrincipalStatus, RequestContext, RequestId, Tenant, Uid,
};
use davhaven_ical::itip::{MessageSpec, build_message};
use davhaven_ical::{ErrorContext, IcalError};
use davhaven_ports::{
    DeliveryJob, HandlerError, ObjectAttendee, OutboxHandler, OutboxMessage, OutboxRecord, Tx, TxMode, outbox::kind,
};

use super::{
    CopyOp, DeliveryScope, InternalDelivery, ItipProcessor, Viewers, blocking_ical, organizer_addresses, wants_copy,
};
use crate::authz::{found, retrying};
use crate::error::{AppError, AppResult};
use crate::wiring::AppCore;

/// The handler of the `internal_delivery` kind.
pub struct InternalDeliveryHandler {
    core: AppCore,
    processor: ItipProcessor,
}

impl core::fmt::Debug for InternalDeliveryHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InternalDeliveryHandler").finish_non_exhaustive()
    }
}

impl InternalDeliveryHandler {
    /// Creates the handler on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self {
            processor: ItipProcessor::new(core.clone()),
            core,
        }
    }
}

/// A recipient the handler delivers to.
struct Recipient {
    principal: Principal,
    /// The address the recipient is known by in the snapshot.
    wire: CalendarUserAddress,
}

/// What was built for one recipient.
#[derive(Debug, Default)]
struct BuiltFor {
    /// The message for the scheduling inbox.
    message: Option<String>,
    /// The text of the recipient's copy.
    copy: Option<String>,
}

/// What building the messages of a job produced: the UID, the organizer the snapshot names and one entry per
/// recipient, in order. A recipient who is not an attendee of the snapshot has none.
struct BuiltJob {
    uid: Uid,
    organizer: Option<CalendarUserAddress>,
    per_recipient: Vec<Option<BuiltFor>>,
}

/// What a record delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Kind {
    /// The method of the message: `Request` or `Cancel`.
    method: ItipMethod,
    /// Whether only the copies follow, without a message.
    copy_only: bool,
}

/// Builds the messages of `kind` for each of `wires` from the snapshot. Runs on a blocking thread.
fn build_job(
    snapshot: &str,
    kind: Kind,
    wires: &[CalendarUserAddress],
    dtstamp: DateTime<Utc>,
    limits: &IcalLimits,
) -> Result<BuiltJob, IcalError> {
    let calendar = davhaven_ical::parse::parse(snapshot.as_bytes(), limits)?;
    let data = davhaven_ical::merge::to_event_data(&calendar, None)?;
    let uid = data.uid.ok_or_else(|| IcalError::invalid("the snapshot has no UID"))?;
    let organizer = data.organizer.map(|organizer| organizer.address);
    let mut per_recipient = Vec::with_capacity(wires.len());
    for wire in wires {
        let message =
            |method: ItipMethod| match build_message(&calendar, &MessageSpec::new(method, wire.clone(), dtstamp)) {
                Ok(message) => Ok(Some(message)),
                // The recipient is not on the event any more: there is no message for them.
                Err(IcalError::Invalid(_)) => Ok(None),
                Err(error) => Err(error),
            };
        let built = match (kind.method, kind.copy_only) {
            (ItipMethod::Cancel, _) => message(ItipMethod::Cancel)?
                .map(|message| {
                    davhaven_ical::serialize::serialize(&message.calendar).map(|text| BuiltFor {
                        message: Some(text),
                        copy: None,
                    })
                })
                .transpose()?,
            (_, copy_only) => message(ItipMethod::Request)?
                .map(|message| {
                    let copy = davhaven_ical::serialize::serialize(&message.object())?;
                    let text = if copy_only {
                        None
                    } else {
                        Some(davhaven_ical::serialize::serialize(&message.calendar)?)
                    };
                    Ok::<_, IcalError>(BuiltFor {
                        message: text,
                        copy: Some(copy),
                    })
                })
                .transpose()?,
        };
        per_recipient.push(built);
    }
    Ok(BuiltJob {
        uid,
        organizer,
        per_recipient,
    })
}

/// The address `principal` has in the copy of the event: the one of the attendee row that resolved to them,
/// otherwise their primary mail address (principal URLs and `urn:uuid` addresses never leave the server, PLAN 2.6).
fn wire_address(rows: &[ObjectAttendee], principal: &Principal) -> Option<CalendarUserAddress> {
    let row = rows.iter().find(|row| row.principal_id == Some(principal.id));
    match (row, &principal.email) {
        (Some(row), _) if row.address.kind() == AddressKind::Mailto => Some(row.address.clone()),
        (_, Some(email)) => Some(CalendarUserAddress::mailto(email)),
        (Some(row), None) => Some(row.address.clone()),
        (None, None) => None,
    }
}

/// What happens to the copy of a recipient: a cancellation removes it, a message with a copy puts it (creating it in
/// `create_in` when there is none), anything else leaves it.
fn copy_op(method: ItipMethod, copy: Option<String>, create_in: Option<CalendarId>) -> CopyOp {
    match (method, copy) {
        (ItipMethod::Cancel, _) => CopyOp::Remove,
        (_, Some(text)) => CopyOp::Put { text, create_in },
        (_, None) => CopyOp::Keep,
    }
}

impl InternalDeliveryHandler {
    /// The recipients of a record who are still to be delivered to: active principals, and, unless the record
    /// cancels, only those who are still on the event.
    async fn recipients(
        tx: &mut dyn Tx,
        job: &DeliveryJob,
        event_exists: bool,
        rows: &[ObjectAttendee],
    ) -> AppResult<Vec<Recipient>> {
        let mut seen: HashSet<PrincipalId> = HashSet::new();
        let mut recipients: Vec<Recipient> = Vec::new();
        for id in &job.recipients {
            if !seen.insert(*id) {
                continue;
            }
            let Some(principal) = found(tx.principals().get(*id).await)? else {
                continue;
            };
            if principal.status != PrincipalStatus::Active {
                continue;
            }
            // An invitation or an update for somebody who was removed from the event since is dropped: the cancellation
            // that removed them is a record of its own and still reaches them.
            let invited = rows.iter().any(|row| row.principal_id == Some(principal.id));
            if job.method != ItipMethod::Cancel && event_exists && !invited {
                continue;
            }
            if let Some(wire) = wire_address(rows, &principal) {
                recipients.push(Recipient { principal, wire });
            }
        }
        Ok(recipients)
    }

    /// Every address that names the organizer the copies of the recipients must name: those of the stored object's
    /// organizer and the one of the snapshot.
    async fn organizers(
        &self,
        tx: &mut dyn Tx,
        tenant: &Tenant,
        organizer: Option<&CalendarUserAddress>,
        snapshot: Option<&CalendarUserAddress>,
    ) -> AppResult<Vec<CalendarUserAddress>> {
        let mut organizers: Vec<CalendarUserAddress> = Vec::new();
        if let Some(address) = organizer {
            organizers = organizer_addresses(&self.core, tx, tenant, address).await?;
        }
        if let Some(address) = snapshot
            && !organizers.contains(address)
        {
            organizers.push(address.clone());
        }
        Ok(organizers)
    }

    /// One attempt: delivers the job in a transaction of the tenant.
    async fn deliver(&self, ctx: &RequestContext, record: &OutboxRecord, job: &DeliveryJob) -> AppResult<()> {
        let deps = self.core.deps();
        let mut tx = deps.database.begin(record.tenant_id, TxMode::ReadWrite).await?;
        let tenant = tx.tenant().get().await?;
        let object = found(tx.objects().get_by_id(job.object).await)?;
        let Some(source) = job
            .snapshot
            .clone()
            .or_else(|| object.as_ref().map(|object| object.data.clone()))
        else {
            tx.commit().await?;
            return Ok(());
        };
        // An invitation or an update of an event that was deleted since has nothing to deliver; a cancellation is
        // exactly what is still wanted then.
        if object.is_none() && job.method != ItipMethod::Cancel {
            tx.commit().await?;
            return Ok(());
        }
        let rows = match &object {
            Some(object) => tx.objects().attendees(object.id).await?,
            None => Vec::new(),
        };
        let recipients = Self::recipients(tx.as_mut(), job, object.is_some(), &rows).await?;
        if recipients.is_empty() {
            tx.commit().await?;
            return Ok(());
        }
        let wires: Vec<CalendarUserAddress> = recipients.iter().map(|recipient| recipient.wire.clone()).collect();
        let kind = Kind {
            method: job.method,
            copy_only: job.copy_only,
        };
        let dtstamp = record.created_at;
        let built = blocking_ical(&self.core, move |limits| {
            build_job(&source, kind, &wires, dtstamp, limits)
        })
        .await?
        .map_err(|error| AppError::from_ical(error, ErrorContext::Scheduling))?;
        // The organizer the copies of the recipients must name: the organizer of the stored object (in every form
        // that names them) and the one of the snapshot, which is what the recipients' copies were built from.
        let organizer = object
            .as_ref()
            .and_then(|object| object.organizer_address.clone())
            .or_else(|| built.organizer.clone());
        let organizers = self
            .organizers(tx.as_mut(), &tenant, organizer.as_ref(), built.organizer.as_ref())
            .await?;
        let viewers = match found(tx.calendars().get(job.calendar).await)? {
            Some(calendar) => Some(Viewers::load(tx.as_mut(), &calendar).await?),
            None => None,
        };
        let mut deliveries: Vec<InternalDelivery> = Vec::with_capacity(recipients.len());
        for (recipient, built) in recipients.into_iter().zip(built.per_recipient) {
            let Some(built) = built else {
                continue;
            };
            let create_in = match (&built.message, &organizer) {
                // Only an invitation creates a copy; an update brings an existing one up to date.
                (Some(_), Some(organizer)) if job.method != ItipMethod::Cancel => {
                    wants_copy(
                        &self.core,
                        tx.as_mut(),
                        &tenant,
                        organizer,
                        viewers.as_ref(),
                        &recipient.principal,
                    )
                    .await?
                }
                _ => None,
            };
            let name = ObjectUri::parse(&format!(
                "q-{}-{}.ics",
                record.id.as_uuid().simple(),
                recipient.principal.id.as_uuid().simple()
            ))
            .map_err(AppError::internal)?;
            deliveries.push(InternalDelivery {
                copy: copy_op(job.method, built.copy, create_in),
                messages: built.message.into_iter().collect(),
                inbox_names: Some(vec![name]),
                address: recipient.wire,
                principal: recipient.principal,
            });
        }
        if deliveries.is_empty() {
            tx.commit().await?;
            return Ok(());
        }
        self.processor
            .deliver(
                tx.as_mut(),
                &DeliveryScope {
                    ctx,
                    uid: &built.uid,
                    organizers: &organizers,
                },
                &deliveries,
            )
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// What the dispatcher is told about a failed delivery: store and machine trouble is worth another attempt, a
/// delivery that can never work (a recipient whose calendar is gone) is not.
fn handler_error(error: &AppError) -> HandlerError {
    match error.kind() {
        ErrorKind::Unavailable | ErrorKind::Conflict | ErrorKind::Internal | ErrorKind::RateLimited => {
            HandlerError::retryable("the internal delivery could not be completed yet")
        }
        _ => HandlerError::permanent("the internal delivery cannot be completed"),
    }
}

#[async_trait]
impl OutboxHandler for InternalDeliveryHandler {
    fn kind(&self) -> &'static str {
        kind::INTERNAL_DELIVERY
    }

    async fn handle(&self, record: &OutboxRecord) -> Result<(), HandlerError> {
        let job = match record.message() {
            Ok(OutboxMessage::InternalDelivery(job)) => job,
            Ok(other) => {
                return Err(HandlerError::permanent(format!(
                    "the record holds a `{}` message, not an internal delivery",
                    other.kind()
                )));
            }
            Err(_) => return Err(HandlerError::permanent("the payload of the record cannot be decoded")),
        };
        let ctx = RequestContext::internal(record.tenant_id, RequestId::from_uuid(record.id.as_uuid()));
        retrying(false, || self.deliver(&ctx, record, &job))
            .await
            .map_err(|error| handler_error(&error))
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use davhaven_domain::IcalLimits;

    use super::*;

    const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:queued-1\r\n\
        DTSTAMP:20270301T090000Z\r\nDTSTART:20270310T100000Z\r\nDTEND:20270310T110000Z\r\nSUMMARY:Meeting\r\n\
        ORGANIZER:mailto:anna@acme.example\r\nATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:ben@acme.example\r\n\
        ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:cara@acme.example\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    fn address(text: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(text).unwrap()
    }

    fn stamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 3, 1, 9, 30, 0).unwrap()
    }

    const REQUEST: Kind = Kind {
        method: ItipMethod::Request,
        copy_only: false,
    };

    #[test]
    fn a_request_gives_each_recipient_a_message_and_a_copy_without_method() {
        let wires = [address("mailto:ben@acme.example"), address("mailto:cara@acme.example")];
        let built = build_job(EVENT, REQUEST, &wires, stamp(), &IcalLimits::default()).unwrap();
        assert_eq!(built.uid.as_str(), "queued-1");
        assert_eq!(built.organizer, Some(address("mailto:anna@acme.example")));
        assert_eq!(built.per_recipient.len(), 2);
        for entry in &built.per_recipient {
            let entry = entry.as_ref().unwrap();
            let message = entry.message.as_deref().unwrap();
            assert!(message.contains("METHOD:REQUEST"), "{message}");
            assert!(
                message.contains("DTSTAMP:20270301T093000Z"),
                "the stamp is the moment of queueing: {message}"
            );
            let copy = entry.copy.as_deref().unwrap();
            assert!(!copy.contains("METHOD"), "{copy}");
            assert!(copy.contains("UID:queued-1"));
        }
        let first = built.per_recipient[0].as_ref().unwrap().message.as_deref().unwrap();
        assert!(
            first.contains("ben@acme.example") && !first.contains("cara@acme.example"),
            "only the recipient is shown: {first}"
        );
    }

    #[test]
    fn a_cancel_has_a_message_and_no_copy_and_a_copy_only_record_has_a_copy_and_no_message() {
        let wires = [address("mailto:ben@acme.example")];
        let cancel = Kind {
            method: ItipMethod::Cancel,
            copy_only: false,
        };
        let cancelled = build_job(EVENT, cancel, &wires, stamp(), &IcalLimits::default()).unwrap();
        let entry = cancelled.per_recipient[0].as_ref().unwrap();
        assert!(entry.message.as_deref().unwrap().contains("METHOD:CANCEL"));
        assert!(entry.copy.is_none());
        let only_the_copy = Kind {
            copy_only: true,
            ..REQUEST
        };
        let followed = build_job(EVENT, only_the_copy, &wires, stamp(), &IcalLimits::default()).unwrap();
        let entry = followed.per_recipient[0].as_ref().unwrap();
        assert!(entry.message.is_none());
        assert!(entry.copy.as_deref().unwrap().contains("UID:queued-1"));
    }

    #[test]
    fn somebody_who_is_not_on_the_event_gets_nothing() {
        let wires = [
            address("mailto:stranger@acme.example"),
            address("mailto:ben@acme.example"),
        ];
        let built = build_job(EVENT, REQUEST, &wires, stamp(), &IcalLimits::default()).unwrap();
        assert!(built.per_recipient[0].is_none());
        assert!(built.per_recipient[1].is_some());
    }

    #[test]
    fn a_snapshot_that_is_not_an_event_is_an_error() {
        let wires = [address("mailto:ben@acme.example")];
        assert!(build_job("garbage", REQUEST, &wires, stamp(), &IcalLimits::default()).is_err());
    }

    #[test]
    fn dispatcher_errors_follow_the_kind() {
        assert!(matches!(
            handler_error(&AppError::unavailable()),
            HandlerError::Retryable(_)
        ));
        assert!(matches!(
            handler_error(&AppError::not_found()),
            HandlerError::Permanent(_)
        ));
        assert!(matches!(
            handler_error(&AppError::forbidden()),
            HandlerError::Permanent(_)
        ));
    }
}
