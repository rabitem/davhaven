//! Calendar objects from messages, messages from answers: the small constructions the application needs around
//! the iTIP messages, so that it never reads or writes iCalendar text itself.
//!
//! * [`reply_message`] builds the `REPLY` that answers a whole event when there is no copy to derive it from (an
//!   answer on the RSVP page, an answer through the management API, a decline that a deletion implies);
//! * [`ItipMessage::object`] is the calendar object resource a message describes (a stored object never carries a
//!   `METHOD`);
//! * [`set_sent_by`] names the party that acts for the organizer on every `ORGANIZER` (RFC 5545 section 3.2.18);
//! * [`strip_alarms`] removes the alarms of an object that came from outside, and [`inline_attachments`] lists the
//!   binary attachments it carries (the application passes them through its content scanners);
//! * [`carry_over_attendee_data`] keeps what an attendee may change on their own copy (alarms, `TRANSP`) when the
//!   organizer's next version replaces the copy.

use calcard::icalendar::{ICalendarEntry, ICalendarValue, Uri};
use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarUserAddress, PartStat, Uid};

use super::message::{ItipMessage, is_link_text};
use super::{utc_zones, views};
use crate::calendar::{
    Kind, Node, Param, Prop, address_value, entry_for_text, entry_from_line, entry_moment, instant_entry, param_text,
    text_entry,
};
use crate::error::IcalError;
use crate::merge::set_param;
use crate::parse::ParsedCalendar;

/// What a `REPLY` that answers a whole event says (RFC 5546 section 3.2.3): the identity of the event, the
/// organizer, the one attendee with the answer and, when there is one, the attendee's remark.
#[derive(Debug, Clone, Copy)]
pub struct ReplySpec<'a> {
    /// The UID of the event.
    pub uid: &'a Uid,
    /// The organizer the reply is for.
    pub organizer: &'a CalendarUserAddress,
    /// The attendee who answers, as the organizer's copy names them.
    pub attendee: &'a CalendarUserAddress,
    /// The answer.
    pub partstat: PartStat,
    /// The `SEQUENCE` of the copy the answer is about (a negative number counts as 0).
    pub sequence: i32,
    /// The `DTSTAMP` of the message (from the `Clock`).
    pub dtstamp: DateTime<Utc>,
    /// The attendee's remark.
    pub comment: Option<&'a str>,
}

/// Builds the `REPLY` of `spec`: one `VEVENT` without `RECURRENCE-ID`, so it answers the whole series.
///
/// The result is an ordinary message of this crate: it can be serialized, parsed with
/// [`parse_message`](super::parse_message) and applied with [`apply_reply_with`](super::apply_reply_with) like one
/// that came from a mail client.
///
/// # Errors
///
/// [`IcalError::Invalid`] when a value cannot be written (a date out of range).
pub fn reply_message(spec: &ReplySpec<'_>) -> Result<ItipMessage, IcalError> {
    let mut root = Node::new(Kind::VCalendar);
    root.entries.push(text_entry(Prop::Version, "2.0"));
    root.entries.push(text_entry(Prop::Prodid, crate::PRODID));
    root.entries.push(entry_from_line("METHOD:REPLY")?);
    let mut event = Node::new(Kind::VEvent);
    event.entries.push(entry_for_text("UID", spec.uid.as_str())?);
    event
        .entries
        .push(instant_entry(Prop::Dtstamp, spec.dtstamp).ok_or_else(|| IcalError::invalid("a date is out of range"))?);
    event
        .entries
        .push(entry_from_line(&format!("SEQUENCE:{}", spec.sequence.max(0)))?);
    event
        .entries
        .push(ICalendarEntry::new(Prop::Organizer).with_value(address_value(spec.organizer)));
    let mut attendee = ICalendarEntry::new(Prop::Attendee).with_value(address_value(spec.attendee));
    set_param(&mut attendee, &Param::Partstat, "PARTSTAT", spec.partstat.as_ical())?;
    event.entries.push(attendee);
    if let Some(comment) = spec.comment.filter(|text| !text.is_empty()) {
        event.entries.push(entry_for_text("COMMENT", comment)?);
    }
    root.children.push(event);
    Ok(ItipMessage {
        method: davhaven_domain::ItipMethod::Reply,
        calendar: ParsedCalendar::from_root(root),
    })
}

impl ItipMessage {
    /// The calendar object resource the message describes: its calendar without the `METHOD` property, which a
    /// stored object must not carry. Nothing inside a component is touched.
    pub fn object(&self) -> ParsedCalendar {
        let mut root = self.calendar.root.clone();
        root.remove(&Prop::Method);
        ParsedCalendar::from_root(root)
    }
}

/// The calendar with `SENT-BY="{acting}"` on every `ORGANIZER`: somebody who writes for the organizer (a colleague
/// with write access to their calendar) is named as the party that sends (PLAN 2.8). A `SENT-BY` the line had is
/// replaced; every other parameter stays.
///
/// # Errors
///
/// [`IcalError::Invalid`] when the address cannot be written as a parameter value.
pub fn set_sent_by(calendar: &ParsedCalendar, acting: &CalendarUserAddress) -> Result<ParsedCalendar, IcalError> {
    let mut root = calendar.root.clone();
    sent_by_in(&mut root, acting)?;
    Ok(ParsedCalendar::from_root(root))
}

fn sent_by_in(node: &mut Node, acting: &CalendarUserAddress) -> Result<(), IcalError> {
    for entry in node.entries.iter_mut().filter(|entry| entry.name == Prop::Organizer) {
        set_param(entry, &Param::SentBy, "SENT-BY", acting.as_str())?;
    }
    for child in &mut node.children {
        sent_by_in(child, acting)?;
    }
    Ok(())
}

/// The calendar without the alarms of any component. Alarms of an object that came from outside (an invitation of
/// an organizer in another organisation) are the sender's, not the recipient's, and must not fire on the
/// recipient's devices.
pub fn strip_alarms(calendar: &ParsedCalendar) -> ParsedCalendar {
    let mut root = calendar.root.clone();
    strip_alarms_in(&mut root);
    ParsedCalendar::from_root(root)
}

fn strip_alarms_in(node: &mut Node) {
    node.children.retain(|child| child.kind != Kind::VAlarm);
    for child in &mut node.children {
        strip_alarms_in(child);
    }
}

/// An inline binary attachment of an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineAttachment {
    /// The decoded content.
    pub content: Vec<u8>,
    /// The declared media type (`FMTTYPE`), when there is one.
    pub media_type: Option<String>,
}

/// The inline binary attachments of every component of the calendar, in document order; links (`ATTACH` with a
/// URL) are not content and are left out.
pub fn inline_attachments(calendar: &ParsedCalendar) -> Vec<InlineAttachment> {
    let mut found = Vec::new();
    collect_attachments(&calendar.root, &mut found);
    found
}

fn collect_attachments(node: &Node, found: &mut Vec<InlineAttachment>) {
    for entry in node.entries.iter().filter(|entry| entry.name == Prop::Attach) {
        let media_type = param_text(entry, &Param::Fmttype);
        for value in &entry.values {
            let content = match value {
                ICalendarValue::Binary(bytes) => Some(bytes.clone()),
                ICalendarValue::Uri(Uri::Data(data)) => Some(data.data.clone()),
                // Decoded binary data that happens to be valid text comes back as text.
                ICalendarValue::Uri(Uri::Location(text)) | ICalendarValue::Text(text) if !is_link_text(text) => {
                    Some(text.clone().into_bytes())
                }
                _ => None,
            };
            if let Some(content) = content {
                found.push(InlineAttachment {
                    content,
                    media_type: media_type.clone(),
                });
            }
        }
    }
    for child in &node.children {
        collect_attachments(child, found);
    }
}

/// `new` with the parts of `previous` that belong to the person whose copy it is: the alarms and `TRANSP` of every
/// component that exists in both (the master and the overrides with the same `RECURRENCE-ID`).
///
/// An attendee may change exactly these on their own copy (PLAN 2.8). The organizer's next version replaces the
/// copy, and the organizer's version knows nothing of them (alarms never leave the server in a message), so without
/// this an unrelated edit would delete the reminders of every attendee and make an event that somebody marked free
/// busy again. A component that `previous` does not have keeps what `new` says; a `previous` without `TRANSP`
/// leaves the `TRANSP` of `new` alone.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn carry_over_attendee_data(new: &ParsedCalendar, previous: &ParsedCalendar) -> Result<ParsedCalendar, IcalError> {
    let new_zones = utc_zones(&new.root);
    let old_zones = utc_zones(&previous.root);
    let before = views(&previous.root, &old_zones);
    let mut root = new.root.clone();
    for node in root.children.iter_mut().filter(|node| node.component_kind().is_some()) {
        let key = node
            .first(&Prop::RecurrenceId)
            .and_then(entry_moment)
            .and_then(|moment| new_zones.rid_key(&moment));
        let Some(old) = before.iter().find(|view| view.key == key) else {
            continue;
        };
        node.children.retain(|child| child.kind != Kind::VAlarm);
        node.children.extend(
            old.node
                .children
                .iter()
                .filter(|child| child.kind == Kind::VAlarm)
                .cloned(),
        );
        if let Some(transparency) = old.node.first(&Prop::Transp) {
            node.set(transparency.clone());
        }
    }
    Ok(ParsedCalendar::from_root(root))
}
