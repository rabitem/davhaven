//! Building the iTIP messages the server sends and checking the ones it receives.

use std::collections::BTreeSet;

use calcard::icalendar::{ICalendarEntry, ICalendarValue, Uri};
use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarUserAddress, EventTime, IcalLimits, ItipMethod};

use super::{strip_schedule_in, upper, utc_zones};
use crate::calendar::{
    Kind, Moment, Node, Param, Prop, address_of, address_value, entry_for_text, entry_from_line, entry_moment,
    instant_entry, param_text,
};
use crate::error::IcalError;
use crate::merge::{master_index, override_from_master, override_index, set_param};
use crate::parse::ParsedCalendar;
use crate::zones::Zones;

/// Which components of the organizer copy an outgoing message covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageScope {
    /// The whole object: master and overrides. Components that do not list the recipient are left out (an
    /// attendee who was invited to one instance only gets that instance).
    Whole,
    /// Only the listed instances (a `CANCEL` or `REQUEST` for single instances).
    Instances(Vec<EventTime>),
}

/// How many attendees a `REQUEST` or `CANCEL` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttendeeVisibility {
    /// The message lists only the recipient. Guests do not learn who else is invited: nothing is revealed to
    /// the recipient's mail client or to an internal attendee's copy. This is the default (`docs/interop.md`).
    #[default]
    Own,
    /// The message lists every attendee of the instance, as the mails of Google and Outlook do.
    All,
}

/// The specification of an outgoing iTIP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSpec {
    /// The method: `REQUEST` and `CANCEL` from the organizer, `REPLY` from an attendee.
    pub method: ItipMethod,
    /// The recipient of the message; `REQUEST` and `CANCEL` are for this attendee (see `attendees`), `REPLY`
    /// goes to the organizer.
    pub recipient: CalendarUserAddress,
    /// For `REPLY`: the replying attendee (taken from the request context, never from the body).
    pub replying_attendee: Option<CalendarUserAddress>,
    /// Which components the message covers.
    pub scope: MessageScope,
    /// The `DTSTAMP` of the message: the moment it is built (from the `Clock`). RFC 5546 section 2.1.5 orders
    /// messages with the same `SEQUENCE` by `DTSTAMP`, so a `CANCEL` or `REPLY` that kept the stamp of the
    /// stored copy could be taken for an older message than the `REQUEST` it follows and be ignored. It is
    /// written to every component of the message; `SEQUENCE` stays the one of the copy the message is built
    /// from, which is at least the one of every `REQUEST` sent before.
    pub dtstamp: DateTime<Utc>,
    /// How many attendees a `REQUEST` or `CANCEL` shows.
    pub attendees: AttendeeVisibility,
    /// For `REPLY`: the remark of the attendee, written as `COMMENT` (RFC 5546 section 3.2.3). Ignored for the
    /// other methods. The text is the application's to check (the RSVP page allows 500 characters).
    pub comment: Option<String>,
}

impl MessageSpec {
    /// A message of `method` for `recipient` that covers the whole object and shows only the recipient.
    pub fn new(method: ItipMethod, recipient: CalendarUserAddress, dtstamp: DateTime<Utc>) -> Self {
        Self {
            method,
            recipient,
            replying_attendee: None,
            scope: MessageScope::Whole,
            dtstamp,
            attendees: AttendeeVisibility::Own,
            comment: None,
        }
    }
}

/// An iTIP message: the method and the calendar carrying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItipMessage {
    /// The `METHOD`.
    pub method: ItipMethod,
    /// The calendar of the message (`VCALENDAR` with `METHOD`, components and the needed `VTIMEZONE`s).
    pub calendar: ParsedCalendar,
}

/// The properties a `REPLY` keeps (RFC 5546 section 3.2.3 asks for less; the time and the summary help mail
/// clients to show what is answered). The `COMMENT` of a reply is the attendee's, never one of the copy.
const REPLY_PROPERTIES: [&str; 10] = [
    "UID",
    "DTSTAMP",
    "SEQUENCE",
    "ORGANIZER",
    "ATTENDEE",
    "RECURRENCE-ID",
    "DTSTART",
    "DTEND",
    "DURATION",
    "SUMMARY",
];

/// Whether the text of an `ATTACH` value is a link (anything else is inline data that never leaves the server).
pub(super) fn is_link_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("://") || lower.starts_with("cid:") || lower.starts_with("mailto:") || lower.starts_with("urn:")
}

/// Whether an `ATTACH` value is a link (anything else is inline data that never leaves the server).
fn is_link(entry: &ICalendarEntry) -> bool {
    match entry.values.first() {
        Some(ICalendarValue::Uri(Uri::Location(text)) | ICalendarValue::Text(text)) => is_link_text(text),
        _ => false,
    }
}

/// Removes what must not leave the server: alarms, `X-APPLE-*` and `X-MOZ-*` properties, the comments the attendees gave
/// with their answers (they are the organizer's: another attendee is not told what somebody wrote to the organizer), inline
/// attachments and every `SCHEDULE-*` parameter.
fn strip_private(node: &mut Node) {
    node.children.retain(|child| child.kind != Kind::VAlarm);
    node.entries.retain(|entry| {
        let name = upper(entry.name.as_str());
        let private =
            name.starts_with("X-APPLE-") || name.starts_with("X-MOZ-") || name == super::reply::ATTENDEE_COMMENT;
        let inline = entry.name == Prop::Attach && !is_link(entry);
        !private && !inline
    });
    strip_schedule_in(node);
}

/// The components a message covers: clones of the overrides, or copies of the master for instances without one.
fn select_components(root: &Node, zones: &Zones, spec: &MessageSpec) -> Result<Vec<Node>, IcalError> {
    let stored: Vec<&Node> = root
        .children
        .iter()
        .filter(|node| node.component_kind().is_some())
        .collect();
    match &spec.scope {
        MessageScope::Whole => {
            if spec.method == ItipMethod::Cancel {
                // A cancelled series is cancelled by its master alone.
                if let Some(master) = stored.iter().copied().find(|node| !node.is_override()) {
                    return Ok(vec![master.clone()]);
                }
            }
            Ok(stored.into_iter().cloned().collect())
        }
        MessageScope::Instances(list) => {
            let mut selected = Vec::with_capacity(list.len());
            for time in list {
                let rid = Moment::from_event_time(time);
                if let Some(index) = override_index(root, zones, &rid) {
                    if let Some(node) = root.children.get(index) {
                        selected.push(node.clone());
                    }
                    continue;
                }
                let master =
                    master_index(root).ok_or_else(|| IcalError::invalid("the object has no master component"))?;
                selected.push(override_from_master(root, master, &rid, zones)?);
            }
            Ok(selected)
        }
    }
}

/// Whether the component lists the address as an attendee.
fn lists(node: &Node, address: &CalendarUserAddress) -> bool {
    node.all(&Prop::Attendee)
        .any(|entry| address_of(entry).as_ref() == Some(address))
}

/// Leaves only the `ATTENDEE` line of `address` on the component.
fn keep_attendee(node: &mut Node, address: &CalendarUserAddress) {
    node.entries
        .retain(|entry| entry.name != Prop::Attendee || address_of(entry).as_ref() == Some(address));
}

/// Builds the iTIP message for `spec` from the organizer's (or the attendee's) copy: `SCHEDULE-*` parameters,
/// alarms, `X-APPLE-*`, `X-MOZ-*` and binary attachments are stripped, a `VTIMEZONE` is added for every `TZID`
/// and every component carries `spec.dtstamp`.
///
/// For `REQUEST` and `CANCEL` a component that does not list the recipient is left out of a whole-object
/// message, so an attendee who was removed from one instance still gets the rest; the `CANCEL` of that instance
/// is a message of its own (`ItipDiff::instance_attendees` names it). Addresses are taken as they are in the
/// copy: map principal URLs and `urn:uuid` addresses to `mailto` with [`rewrite_addresses`] before building.
///
/// # Errors
///
/// [`IcalError::Invalid`] when the copy cannot produce the message (for example a `REPLY` for an attendee that
/// is not on the event); [`IcalError::Unsupported`] for methods other than `REQUEST`, `CANCEL` and `REPLY`.
pub fn build_message(source: &ParsedCalendar, spec: &MessageSpec) -> Result<ItipMessage, IcalError> {
    if !matches!(
        spec.method,
        ItipMethod::Request | ItipMethod::Cancel | ItipMethod::Reply
    ) {
        return Err(IcalError::unsupported(format!(
            "building {} messages",
            spec.method.as_ical()
        )));
    }
    let zones = utc_zones(&source.root);
    let components = select_components(&source.root, &zones, spec)?;
    if components.is_empty() {
        return Err(IcalError::invalid("the message would carry no component"));
    }
    let stamp =
        instant_entry(Prop::Dtstamp, spec.dtstamp).ok_or_else(|| IcalError::invalid("a date is out of range"))?;
    let target = if spec.method == ItipMethod::Reply {
        spec.replying_attendee
            .as_ref()
            .ok_or_else(|| IcalError::invalid("a reply needs the replying attendee"))?
    } else {
        &spec.recipient
    };
    let explicit = matches!(spec.scope, MessageScope::Instances(_));
    let mut kept: Vec<Node> = Vec::with_capacity(components.len());
    for mut node in components {
        if !node.has(&Prop::Organizer) {
            return Err(IcalError::invalid("the event has no organizer"));
        }
        if !lists(&node, target) {
            if explicit {
                return Err(IcalError::invalid("the attendee is not on the event"));
            }
            continue;
        }
        strip_private(&mut node);
        match spec.method {
            ItipMethod::Request => {
                if spec.attendees == AttendeeVisibility::Own {
                    keep_attendee(&mut node, &spec.recipient);
                }
            }
            ItipMethod::Cancel => {
                if spec.attendees == AttendeeVisibility::Own {
                    keep_attendee(&mut node, &spec.recipient);
                }
                node.set(entry_from_line("STATUS:CANCELLED")?);
            }
            _ => {
                keep_attendee(&mut node, target);
                node.entries
                    .retain(|entry| REPLY_PROPERTIES.contains(&upper(entry.name.as_str()).as_str()));
                if let Some(comment) = spec.comment.as_deref().filter(|text| !text.is_empty()) {
                    node.entries.push(entry_for_text("COMMENT", comment)?);
                }
            }
        }
        node.set(stamp.clone());
        kept.push(node);
    }
    if kept.is_empty() {
        return Err(IcalError::invalid("the attendee is not on the event"));
    }
    let mut root = Node::new(Kind::VCalendar);
    root.entries.push(entry_for_text("VERSION", "2.0")?);
    root.entries.push(entry_for_text("PRODID", crate::PRODID)?);
    root.entries
        .push(entry_from_line(&format!("METHOD:{}", spec.method.as_ical()))?);
    let used: BTreeSet<String> = kept
        .iter()
        .flat_map(|node| node.entries.iter())
        .filter_map(|entry| param_text(entry, &Param::Tzid))
        .collect();
    for zone in source.root.children.iter().filter(|node| node.kind == Kind::VTimezone) {
        if zone.text(&Prop::Tzid).is_some_and(|tzid| used.contains(&tzid)) {
            root.children.push(zone.clone());
        }
    }
    root.children.extend(kept);
    crate::tz::ensure_vtimezones(&mut root);
    Ok(ItipMessage {
        method: spec.method,
        calendar: ParsedCalendar::from_root(root),
    })
}

/// Replaces the calendar user addresses of `ORGANIZER` and `ATTENDEE` lines (and their `SENT-BY`) with the
/// ones `map` returns; an address `map` has no answer for stays. Parameters are kept.
///
/// PLAN 2.6: principal URLs and `urn:uuid` addresses are normalised to `mailto` before anything leaves the
/// server. The application maps the copy first and builds the message from the mapped copy, so that the
/// addresses of the message and the recipient agree.
///
/// # Errors
///
/// [`IcalError::Invalid`] when a replacement cannot be written back.
pub fn rewrite_addresses(
    calendar: &ParsedCalendar,
    map: &dyn Fn(&CalendarUserAddress) -> Option<CalendarUserAddress>,
) -> Result<ParsedCalendar, IcalError> {
    let mut root = calendar.root.clone();
    rewrite_in(&mut root, map)?;
    Ok(ParsedCalendar::from_root(root))
}

fn rewrite_in(
    node: &mut Node,
    map: &dyn Fn(&CalendarUserAddress) -> Option<CalendarUserAddress>,
) -> Result<(), IcalError> {
    for entry in &mut node.entries {
        if !matches!(entry.name, Prop::Organizer | Prop::Attendee) {
            continue;
        }
        if let Some(current) = address_of(entry)
            && let Some(replacement) = map(&current)
            && replacement != current
        {
            entry.values = vec![address_value(&replacement)];
        }
        // The party that acts for the organizer or attendee is an address as well.
        if let Some(acting) = param_text(entry, &Param::SentBy).and_then(|text| CalendarUserAddress::parse(&text).ok())
            && let Some(replacement) = map(&acting)
            && replacement != acting
        {
            set_param(entry, &Param::SentBy, "SENT-BY", replacement.as_str())?;
        }
    }
    for child in &mut node.children {
        rewrite_in(child, map)?;
    }
    Ok(())
}

/// Parses and checks an inbound iTIP message (a `text/calendar` part with a `METHOD`): the structure and limits
/// of every stored object (dates, recurrence rules, counts, sizes) and the gate of [`crate::parse::accept`] (the
/// message survives the writer), a known `METHOD`, one UID and only the components that method allows.
///
/// # Errors
///
/// [`IcalError::Invalid`] for data that is not a valid scheduling message, [`IcalError::Limit`] for exceeded
/// limits. Answer them with [`crate::ErrorContext::Scheduling`] (`CALDAV:valid-scheduling-message`).
pub fn parse_message(input: &[u8], limits: &IcalLimits) -> Result<ItipMessage, IcalError> {
    let calendar = crate::parse::accept(input, limits)?;
    let root = &calendar.root;
    let method = root
        .text(&Prop::Method)
        .ok_or_else(|| IcalError::invalid("the message has no METHOD"))?;
    let method =
        ItipMethod::from_ical(method.trim()).ok_or_else(|| IcalError::invalid("the METHOD is not an iTIP method"))?;
    let zones = utc_zones(root);
    zones.check_referenced()?;
    let mut uid: Option<String> = None;
    let mut components = 0usize;
    for child in &root.children {
        let kind_ok = match child.kind {
            Kind::VTimezone => continue,
            Kind::VEvent | Kind::VTodo | Kind::VJournal => true,
            Kind::VFreebusy => matches!(method, ItipMethod::Reply | ItipMethod::Request | ItipMethod::Publish),
            _ => false,
        };
        if !kind_ok {
            return Err(IcalError::invalid(
                "the message holds a component that its METHOD does not allow",
            ));
        }
        components += 1;
        let own = child
            .uid()
            .ok_or_else(|| IcalError::invalid("a component of the message has no UID"))?;
        match &uid {
            Some(existing) if existing != &own => {
                return Err(IcalError::invalid("the components of the message have different UIDs"));
            }
            _ => uid = Some(own),
        }
        check_message_component(child, method)?;
        if child.component_kind().is_some() {
            // The same rules as for a stored object: valid dates and rules, counts, sizes.
            crate::validate::check_component(child, &zones, limits)?;
        } else {
            crate::validate::check_sizes(child, limits)?;
        }
        for property in [Prop::Dtstart, Prop::Dtend, Prop::Due, Prop::RecurrenceId] {
            if let Some(entry) = child.first(&property)
                && entry_moment(entry).is_none()
            {
                return Err(IcalError::invalid(format!(
                    "{} is not a valid date or date-time",
                    property.as_str()
                )));
            }
        }
    }
    if components == 0 {
        return Err(IcalError::invalid("the message holds no component"));
    }
    Ok(ItipMessage { method, calendar })
}

fn check_message_component(node: &Node, method: ItipMethod) -> Result<(), IcalError> {
    let attendees = node.all(&Prop::Attendee).count();
    let needs_organizer = matches!(method, ItipMethod::Request | ItipMethod::Cancel | ItipMethod::Reply);
    if needs_organizer && node.kind != Kind::VFreebusy && !node.has(&Prop::Organizer) {
        return Err(IcalError::invalid("the message has no ORGANIZER"));
    }
    match method {
        ItipMethod::Request if node.kind != Kind::VFreebusy && attendees == 0 => {
            Err(IcalError::invalid("a REQUEST needs at least one ATTENDEE"))
        }
        ItipMethod::Reply if node.kind != Kind::VFreebusy && attendees != 1 => {
            Err(IcalError::invalid("a REPLY needs exactly one ATTENDEE per component"))
        }
        _ => Ok(()),
    }
}
