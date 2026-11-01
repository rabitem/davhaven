//! Building the organizer's copy and the messages of a write: the blocking half of the plan.
//!
//! Everything here is pure iCalendar work and runs on a blocking thread. The decisions that need the store, the
//! policy or the clock were made before; this module only applies them: the answers of resources and the delivery
//! states go into the organizer's copy, the addresses that must not leave the server are rewritten, and the
//! messages are built from the result.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarUserAddress, EventTime, IcalLimits, ItipMethod, PartStat};
use davhaven_ical::IcalError;
use davhaven_ical::ParsedCalendar;
use davhaven_ical::itip::{
    ItipMessage, MessageScope, MessageSpec, ReplySpec, apply_reply_with, build_message, reply_message,
    rewrite_addresses, set_schedule_status, set_sent_by,
};

use super::execute::whole;

/// One recipient of messages.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent part of what the recipient is sent; an enum would have to list their combinations"
)]
pub(crate) struct BuildRecipient {
    /// The address on the wire.
    pub(crate) wire: CalendarUserAddress,
    /// A message of the whole event.
    pub(crate) request: bool,
    /// A cancellation of the whole event, from the new copy.
    pub(crate) cancel_new: bool,
    /// A cancellation of the whole event, from the stored copy.
    pub(crate) cancel_old: bool,
    /// Cancellations of single instances, from the stored copy.
    pub(crate) instances: Vec<EventTime>,
    /// Whether the recipient's copy follows the new organizer copy.
    pub(crate) copy: bool,
    /// Whether the recipient is in the tenant (they get inbox messages) or outside it (they get mails).
    pub(crate) internal: bool,
}

/// What to build.
#[derive(Debug)]
pub(crate) struct BuildJob {
    /// The new organizer copy after the rules of PLAN 2.8.
    pub(crate) calendar: ParsedCalendar,
    /// The stored copy.
    pub(crate) old: Option<ParsedCalendar>,
    /// The copy the client sent.
    pub(crate) incoming: ParsedCalendar,
    /// The address of the wire of every address that has another one.
    pub(crate) wire: HashMap<CalendarUserAddress, CalendarUserAddress>,
    /// Answers of resources, by the address in the copy.
    pub(crate) answers: Vec<(CalendarUserAddress, PartStat)>,
    /// `SCHEDULE-STATUS` of recipients, by the address in the copy.
    pub(crate) statuses: Vec<(CalendarUserAddress, &'static str)>,
    /// The recipients.
    pub(crate) recipients: Vec<BuildRecipient>,
    /// The `DTSTAMP` of the messages.
    pub(crate) now: DateTime<Utc>,
    /// The organizer, as the copy names them.
    pub(crate) organizer: CalendarUserAddress,
    /// The person who writes for the organizer (a colleague with write access to the organizer's calendar): the
    /// messages name them as the sender (`SENT-BY`, RFC 5545 section 3.2.18).
    pub(crate) sent_by: Option<CalendarUserAddress>,
}

/// What was built for one recipient.
#[derive(Debug, Clone, Default)]
pub(crate) struct BuiltRecipient {
    /// The message of the whole event.
    pub(crate) request: Option<String>,
    /// The cancellation of the whole event.
    pub(crate) cancel: Option<String>,
    /// The cancellations of single instances.
    pub(crate) instance_cancels: Vec<String>,
    /// The text of the recipient's copy.
    pub(crate) copy: Option<String>,
    /// The organizer's copy as the mail of a `REQUEST` is built from it, when it differs from the stored one
    /// (addresses of the wire); `None` lets the mail read the stored object.
    pub(crate) snapshot_request: Option<String>,
    /// The copy a cancellation mail is built from.
    pub(crate) snapshot_cancel: Option<String>,
}

/// What was built.
#[derive(Debug)]
pub(crate) struct Built {
    /// The copy to store instead of the client's, when it differs.
    pub(crate) organizer: Option<String>,
    /// The organizer copy with the addresses of the wire, for deliveries that are queued.
    pub(crate) wire_new: String,
    /// The stored copy with the addresses of the wire, for cancellations that are queued.
    pub(crate) wire_old: Option<String>,
    /// The messages, in the order of the recipients.
    pub(crate) recipients: Vec<BuiltRecipient>,
}

/// The calendar as it is known outside the server: principal URLs and `urn:uuid` addresses become mail addresses and
/// a colleague who writes for the organizer is named as the sender.
fn on_the_wire(
    calendar: &ParsedCalendar,
    map: &HashMap<CalendarUserAddress, CalendarUserAddress>,
    sent_by: Option<&CalendarUserAddress>,
) -> Result<ParsedCalendar, IcalError> {
    let rewritten = if map.is_empty() {
        calendar.clone()
    } else {
        rewrite_addresses(calendar, &|address| map.get(address).cloned())?
    };
    match sent_by {
        Some(by) => set_sent_by(&rewritten, by),
        None => Ok(rewritten),
    }
}

/// Builds a message, treating "the recipient is not on the event" as "there is no message".
fn optional_message(source: &ParsedCalendar, spec: &MessageSpec) -> Result<Option<ItipMessage>, IcalError> {
    match build_message(source, spec) {
        Ok(message) => Ok(Some(message)),
        Err(IcalError::Invalid(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The text of a message, with its `METHOD`.
fn text_of(message: &ItipMessage) -> Result<String, IcalError> {
    davhaven_ical::serialize::serialize(&message.calendar)
}

/// Folds the answers of resources into the copy: each is a `REPLY` of the resource, applied like any other.
fn fold_answers(
    mut calendar: ParsedCalendar,
    job: &BuildJob,
    limits: &IcalLimits,
) -> Result<ParsedCalendar, IcalError> {
    if job.answers.is_empty() {
        return Ok(calendar);
    }
    let data = davhaven_ical::merge::to_event_data(&calendar, None)?;
    let (Some(uid), sequence) = (data.uid, data.sequence.unwrap_or(0)) else {
        return Ok(calendar);
    };
    for (attendee, partstat) in &job.answers {
        let message = reply_message(&ReplySpec {
            uid: &uid,
            organizer: &job.organizer,
            attendee,
            partstat: *partstat,
            sequence,
            dtstamp: job.now,
            comment: None,
        })?;
        calendar = apply_reply_with(&calendar, &message, limits, Some(attendee))?.updated;
    }
    Ok(calendar)
}

/// Builds the new organizer copy and the messages. Runs on a blocking thread.
///
/// # Errors
///
/// The errors of the iCalendar layer.
pub(crate) fn build(job: &BuildJob, limits: &IcalLimits) -> Result<Built, IcalError> {
    let mut calendar = fold_answers(job.calendar.clone(), job, limits)?;
    for (address, code) in &job.statuses {
        // A recipient that is not on the new copy (a removed attendee) has no line to write to.
        if let Ok(updated) = set_schedule_status(&calendar, address, code) {
            calendar = updated;
        }
    }
    let organizer = if calendar == job.incoming {
        None
    } else {
        Some(davhaven_ical::serialize::serialize(&calendar)?)
    };
    let sent_by = job.sent_by.as_ref();
    let wire_new = on_the_wire(&calendar, &job.wire, sent_by)?;
    let wire_old = job
        .old
        .as_ref()
        .map(|old| on_the_wire(old, &job.wire, sent_by))
        .transpose()?;
    let wire_new_text = davhaven_ical::serialize::serialize(&wire_new)?;
    let wire_old_text = wire_old.as_ref().map(davhaven_ical::serialize::serialize).transpose()?;
    // Mails are built from the stored object unless the wire form differs from it.
    let request_snapshot = (wire_new != calendar).then(|| wire_new_text.clone());
    let mut recipients = Vec::with_capacity(job.recipients.len());
    for recipient in &job.recipients {
        let mut built = BuiltRecipient::default();
        let to = &recipient.wire;
        // The text of the invitation is the inbox message of a recipient who is told and the copy of one whose
        // copy only follows the organizer's.
        let request = if recipient.request || (recipient.copy && recipient.internal) {
            optional_message(&wire_new, &whole(ItipMethod::Request, to, job.now))?
        } else {
            None
        };
        if recipient.cancel_new {
            built.cancel = optional_message(&wire_new, &whole(ItipMethod::Cancel, to, job.now))?
                .as_ref()
                .map(text_of)
                .transpose()?;
            built.snapshot_cancel = Some(wire_new_text.clone());
        }
        if recipient.cancel_old
            && let Some(old) = &wire_old
        {
            built.cancel = optional_message(old, &whole(ItipMethod::Cancel, to, job.now))?
                .as_ref()
                .map(text_of)
                .transpose()?;
            built.snapshot_cancel.clone_from(&wire_old_text);
        }
        if recipient.internal
            && !recipient.instances.is_empty()
            && let Some(old) = &wire_old
        {
            let spec = MessageSpec {
                scope: MessageScope::Instances(recipient.instances.clone()),
                ..MessageSpec::new(ItipMethod::Cancel, to.clone(), job.now)
            };
            built
                .instance_cancels
                .extend(optional_message(old, &spec)?.as_ref().map(text_of).transpose()?);
        }
        if recipient.request || !recipient.instances.is_empty() {
            built.snapshot_request.clone_from(&request_snapshot);
        }
        if recipient.copy && recipient.internal {
            built.copy = request
                .as_ref()
                .map(|message| davhaven_ical::serialize::serialize(&message.object()))
                .transpose()?;
        }
        if recipient.request {
            built.request = request.as_ref().map(text_of).transpose()?;
        }
        recipients.push(built);
    }
    Ok(Built {
        organizer,
        wire_new: wire_new_text,
        wire_old: wire_old_text,
        recipients,
    })
}
