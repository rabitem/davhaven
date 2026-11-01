//! Merging `EventData` into stored components.

use std::fmt::Write as _;

use calcard::icalendar::ICalendarEntry;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    AlarmAction, AlarmRelated, AlarmTrigger, EventAlarm, EventAttendee, EventData, EventField, EventOrganizer,
    Recurrence,
};

use super::instances::{
    invalid, master_index, names_instance, override_from_master, override_index, set_param, shifted_end,
};
use super::{EditScope, MergeContext};
use crate::calendar::{
    Kind, Moment, Node, Param, Prop, address_of, address_value, entry_for_moment, entry_for_text, entry_from_line,
    entry_moment, escape_text, param_value,
};
use crate::error::IcalError;
use crate::parse::ParsedCalendar;
use crate::zones::{Zone, Zones};

/// Merges `patch` into `existing` (or creates a new calendar when `existing` is `None`) and returns the new
/// calendar. `patch.recurrence_id` selects an override; whether the sequence number is raised for significant
/// changes is the caller's decision through `patch.sequence`.
///
/// With [`EditScope::This`] an edit that names a recurrence id changes (or creates) the override of that
/// instance; with [`EditScope::All`] the master component is edited whatever the recurrence id says.
/// [`EditScope::ThisAndFuture`] with a recurrence id is not done here: the way clients split a series produces
/// two objects, see [`super::merge_event_split`].
///
/// The answers of the attendees are theirs: a `partstat` in the patch is ignored for every attendee but the
/// organizer's own line (a new attendee starts as `NEEDS-ACTION`, an attendee that is already listed keeps the
/// stored answer); only a `REPLY` changes one ([`crate::itip::apply_reply`]).
///
/// The result passes the gate every stored object passes: it is serialized and parsed and validated again with
/// `context.limits`, so what is returned can be stored and read back (the escaped length of a text field, the
/// size of the whole object and the number of properties are checked there, not only the raw length of the
/// fields).
///
/// # Errors
///
/// * [`IcalError::Invalid`] when the result would not be a valid event (no start on create, `end` before
///   `start`, a recurrence id that names no instance, an `EMAIL` alarm, ...),
/// * [`IcalError::Limit`] when the result exceeds a limit,
/// * [`IcalError::Unsupported`] for [`EditScope::ThisAndFuture`] with a recurrence id.
pub fn merge_event(
    existing: Option<&ParsedCalendar>,
    patch: &EventData,
    context: &MergeContext<'_>,
) -> Result<ParsedCalendar, IcalError> {
    if context.scope == EditScope::ThisAndFuture && patch.recurrence_id.is_some() {
        return Err(IcalError::unsupported(
            "this-and-future edits split the series into two objects; use merge_event_split",
        ));
    }
    check_patch(patch, context)?;
    let creating = existing.is_none();
    if creating && patch.start.is_none() {
        return Err(invalid("a new event needs a start"));
    }
    if creating && patch.recurrence_id.is_some() {
        return Err(invalid("an instance can only be edited on an existing event"));
    }
    let mut root = match existing {
        Some(calendar) => calendar.root.clone(),
        None => new_root()?,
    };
    let floating = Zone::from_tz(context.default_zone.tz());
    let zones = Zones::for_tree(&root, floating.clone());
    let index = target_component(&mut root, patch, context, &zones)?;
    {
        let node = root
            .children
            .get_mut(index)
            .ok_or_else(|| invalid("the component is missing"))?;
        apply(node, patch, context, &zones)?;
    }
    crate::tz::ensure_vtimezones(&mut root);
    finish(root, context.limits)
}

/// The checks of the patch that need no stored component.
pub(super) fn check_patch(patch: &EventData, context: &MergeContext<'_>) -> Result<(), IcalError> {
    patch
        .validate(context.limits)
        .map_err(|error| IcalError::invalid(error.to_string()))?;
    if patch.uid.as_ref().is_some_and(|uid| uid != context.uid) {
        return Err(invalid("the UID of an event cannot be changed"));
    }
    Ok(())
}

/// The gate for what the server produces: the tree is written out and read back through the validation every
/// stored object passes, so that no result can be stored that could not be parsed again.
pub(super) fn finish(root: Node, limits: &davhaven_domain::IcalLimits) -> Result<ParsedCalendar, IcalError> {
    let text = crate::serialize::serialize(&ParsedCalendar::from_root(root))?;
    Ok(crate::validate::parse_and_validate(text.as_bytes(), limits)?.calendar)
}

pub(super) fn new_root() -> Result<Node, IcalError> {
    let mut root = Node::new(Kind::VCalendar);
    root.entries.push(entry_for_text("VERSION", "2.0")?);
    root.entries.push(entry_for_text("PRODID", crate::PRODID)?);
    Ok(root)
}

pub(super) fn stamp(node: &mut Node, now: DateTime<Utc>, created: bool) -> Result<(), IcalError> {
    let value = now.naive_utc();
    node.set(entry_for_moment("DTSTAMP", &Moment::Utc(value))?);
    node.set(entry_for_moment("LAST-MODIFIED", &Moment::Utc(value))?);
    if created {
        node.set(entry_for_moment("CREATED", &Moment::Utc(value))?);
    }
    Ok(())
}

/// Finds the component the patch edits, creating the master of a new event or the override of an instance.
fn target_component(
    root: &mut Node,
    patch: &EventData,
    context: &MergeContext<'_>,
    zones: &Zones,
) -> Result<usize, IcalError> {
    let rid = patch.recurrence_id.as_ref().map(Moment::from_event_time);
    let edits_master = rid.is_none() || context.scope == EditScope::All;
    if edits_master {
        if let Some(index) = master_index(root) {
            return Ok(index);
        }
        if !root.children.iter().any(|node| node.component_kind().is_some()) {
            let mut master = Node::new(Kind::VEvent);
            master.entries.push(entry_for_text("UID", context.uid.as_str())?);
            stamp(&mut master, context.now, true)?;
            master.entries.push(entry_from_line("SEQUENCE:0")?);
            root.children.push(master);
            return Ok(root.children.len().saturating_sub(1));
        }
        return Err(invalid("the object has no component without RECURRENCE-ID"));
    }
    let rid = rid.ok_or_else(|| invalid("the recurrence id is missing"))?;
    if let Some(index) = override_index(root, zones, &rid) {
        return Ok(index);
    }
    let master = master_index(root).ok_or_else(|| invalid("the object has no master component"))?;
    if !names_instance(root, zones, context.limits, &rid)? {
        return Err(invalid("the recurrence id names no instance of the event"));
    }
    let node = override_from_master(root, master, &rid, zones)?;
    root.children.push(node);
    Ok(root.children.len().saturating_sub(1))
}

/// Applies the fields of the patch to one component: a field with a value replaces the property, a field that is
/// absent leaves it alone and a field that is `null` (`patch.removed`) removes it.
pub(super) fn apply(
    node: &mut Node,
    patch: &EventData,
    context: &MergeContext<'_>,
    zones: &Zones,
) -> Result<(), IcalError> {
    apply_times(node, patch, zones)?;
    for (field, property, value) in [
        (EventField::Summary, Prop::Summary, &patch.summary),
        (EventField::Description, Prop::Description, &patch.description),
        (EventField::Location, Prop::Location, &patch.location),
    ] {
        match value {
            Some(text) if !text.is_empty() => node.set(entry_for_text(property.as_str(), text)?),
            // An empty text removes the property, like `null` does.
            Some(_) => node.remove(&property),
            None if patch.removes(field) => node.remove(&property),
            None => {}
        }
    }
    replace(
        node,
        patch.removes(EventField::Status),
        &Prop::Status,
        patch
            .status
            .map(|status| entry_from_line(&format!("STATUS:{}", status.as_ical()))),
    )?;
    replace(
        node,
        patch.removes(EventField::Transparency),
        &Prop::Transp,
        patch
            .transparency
            .map(|transparency| entry_from_line(&format!("TRANSP:{}", transparency.as_ical()))),
    )?;
    replace(
        node,
        patch.removes(EventField::Class),
        &Prop::Class,
        patch
            .class
            .map(|class| entry_from_line(&format!("CLASS:{}", class.as_ical()))),
    )?;
    match &patch.recurrence {
        Some(recurrence) => apply_recurrence(node, recurrence)?,
        None if patch.removes(EventField::Recurrence) => apply_recurrence(node, &Recurrence::default())?,
        None => {}
    }
    replace(
        node,
        patch.removes(EventField::Organizer),
        &Prop::Organizer,
        patch.organizer.as_ref().map(organizer_entry),
    )?;
    match &patch.attendees {
        Some(attendees) => merge_attendees(node, attendees)?,
        None if patch.removes(EventField::Attendees) => merge_attendees(node, &[])?,
        None => {}
    }
    if patch.removes(EventField::Organizer) && node.first(&Prop::Attendee).is_some() {
        // RFC 5545 section 3.8.4.3: a component that is scheduled with attendees names its organizer. Clients treat
        // an object with attendees and no organizer as a meeting without an owner.
        return Err(invalid(
            "`organizer` cannot be removed while the event has attendees; remove them in the same write (`attendees`: null)",
        ));
    }
    match &patch.categories {
        Some(categories) => {
            node.remove(&Prop::Categories);
            if !categories.is_empty() {
                let values: Vec<String> = categories.iter().map(|category| escape_text(category)).collect();
                node.entries
                    .push(entry_from_line(&format!("CATEGORIES:{}", values.join(",")))?);
            }
        }
        None if patch.removes(EventField::Categories) => node.remove(&Prop::Categories),
        None => {}
    }
    replace(
        node,
        patch.removes(EventField::Url),
        &Prop::Url,
        patch
            .url
            .as_ref()
            .map(|url| entry_from_line(&format!("URL:{}", url.as_str()))),
    )?;
    if let Some(sequence) = patch.sequence {
        node.set(entry_from_line(&format!("SEQUENCE:{sequence}"))?);
    }
    match &patch.alarms {
        Some(alarms) => {
            let fallback = node
                .text(&Prop::Summary)
                .filter(|summary| !summary.is_empty())
                .unwrap_or_else(|| context.default_alarm_text.to_owned());
            node.children.retain(|child| child.kind != Kind::VAlarm);
            for alarm in alarms {
                node.children.push(alarm_node(alarm, &fallback)?);
            }
        }
        None if patch.removes(EventField::Alarms) => node.children.retain(|child| child.kind != Kind::VAlarm),
        None => {}
    }
    stamp(node, context.now, false)
}

/// One single-valued property of a JSON Merge Patch: a value replaces the property, `null` (`removed`) removes it,
/// and a field that is neither leaves it as it is.
fn replace(
    node: &mut Node,
    removed: bool,
    property: &Prop,
    value: Option<Result<ICalendarEntry, IcalError>>,
) -> Result<(), IcalError> {
    match value {
        Some(entry) => node.set(entry?),
        None if removed => node.remove(property),
        None => {}
    }
    Ok(())
}

fn apply_times(node: &mut Node, patch: &EventData, zones: &Zones) -> Result<(), IcalError> {
    let end_name = if node.kind == Kind::VTodo {
        Prop::Due
    } else {
        Prop::Dtend
    };
    let old_start = node.first(&Prop::Dtstart).and_then(entry_moment);
    let old_end = node.first(&end_name).and_then(entry_moment);
    // A write that decides the end itself (a new end, a duration, or `null` which removes the end) does not leave the
    // old end to be moved with the start.
    let decides_end = patch.end.is_some() || patch.duration.is_some() || patch.removes(EventField::End);
    if let Some(start) = &patch.start {
        let new_start = Moment::from_event_time(start);
        if !decides_end && let (Some(old_start), Some(old_end)) = (&old_start, &old_end) {
            // Moving the start keeps the length of the event.
            if old_end.is_date() == new_start.is_date() {
                let shifted = shifted_end(zones, old_start, old_end, &new_start)?;
                node.set(entry_for_moment(end_name.as_str(), &shifted)?);
            } else {
                node.remove(&end_name);
            }
        }
        node.set(entry_for_moment("DTSTART", &new_start)?);
    }
    if patch.removes(EventField::End) {
        node.remove(&end_name);
    }
    if patch.removes(EventField::Duration) {
        node.remove(&Prop::Duration);
    }
    if let Some(end) = &patch.end {
        node.remove(&Prop::Duration);
        node.set(entry_for_moment(end_name.as_str(), &Moment::from_event_time(end))?);
    }
    if let Some(duration) = &patch.duration {
        node.remove(&end_name);
        node.set(entry_from_line(&format!("DURATION:{}", duration.as_str()))?);
    }
    Ok(())
}

fn apply_recurrence(node: &mut Node, recurrence: &Recurrence) -> Result<(), IcalError> {
    node.remove(&Prop::Rrule);
    node.remove(&Prop::Rdate);
    node.remove(&Prop::Exdate);
    if let Some(rule) = &recurrence.rrule {
        node.entries.push(entry_from_line(&format!("RRULE:{}", rule.as_str()))?);
    }
    for time in &recurrence.rdates {
        node.entries
            .push(entry_for_moment("RDATE", &Moment::from_event_time(time))?);
    }
    for time in &recurrence.exdates {
        node.entries
            .push(entry_for_moment("EXDATE", &Moment::from_event_time(time))?);
    }
    Ok(())
}

fn organizer_entry(organizer: &EventOrganizer) -> Result<ICalendarEntry, IcalError> {
    let mut line = String::from("ORGANIZER");
    if let Some(name) = organizer.common_name.as_ref().filter(|name| !name.is_empty()) {
        let _ = write!(line, ";CN={}", param_value(name));
    }
    if let Some(sent_by) = &organizer.sent_by {
        let _ = write!(line, ";SENT-BY={}", param_value(sent_by.as_str()));
    }
    line.push(':');
    line.push_str(organizer.address.as_str());
    entry_from_line(&line)
}

/// Replaces the attendees of the component by the listed ones, matched by address. A listed attendee keeps the
/// parameters the caller does not state. The answer (`PARTSTAT`) is the attendee's: it is only taken from the
/// patch for the organizer's own line, every other attendee keeps the stored answer or starts as
/// `NEEDS-ACTION`.
fn merge_attendees(node: &mut Node, attendees: &[EventAttendee]) -> Result<(), IcalError> {
    let organizer = node.first(&Prop::Organizer).and_then(address_of);
    let old: Vec<ICalendarEntry> = node.all(&Prop::Attendee).cloned().collect();
    let position = node.entries.iter().position(|entry| entry.name == Prop::Attendee);
    node.remove(&Prop::Attendee);
    let mut merged: Vec<ICalendarEntry> = Vec::with_capacity(attendees.len());
    for attendee in attendees {
        let stored = old
            .iter()
            .find(|entry| address_of(entry).as_ref() == Some(&attendee.address));
        let mut entry = match stored {
            Some(entry) => entry.clone(),
            None => ICalendarEntry::new(Prop::Attendee).with_value(address_value(&attendee.address)),
        };
        if let Some(name) = &attendee.common_name {
            set_param(&mut entry, &Param::Cn, "CN", name)?;
        }
        let is_organizer = organizer.as_ref() == Some(&attendee.address);
        match (stored, attendee.partstat) {
            (_, Some(partstat)) if is_organizer => {
                set_param(&mut entry, &Param::Partstat, "PARTSTAT", partstat.as_ical())?;
            }
            (None, _) => {
                set_param(&mut entry, &Param::Partstat, "PARTSTAT", "NEEDS-ACTION")?;
                crate::calendar::remove_param(&mut entry, &Param::ScheduleStatus);
            }
            (Some(_), _) => {}
        }
        if let Some(role) = attendee.role {
            set_param(&mut entry, &Param::Role, "ROLE", role.as_ical())?;
        }
        if let Some(cutype) = attendee.cutype {
            set_param(&mut entry, &Param::Cutype, "CUTYPE", cutype.as_ical())?;
        }
        if let Some(rsvp) = attendee.rsvp {
            set_param(&mut entry, &Param::Rsvp, "RSVP", if rsvp { "TRUE" } else { "FALSE" })?;
        }
        if let Some(agent) = attendee.schedule_agent {
            set_param(&mut entry, &Param::ScheduleAgent, "SCHEDULE-AGENT", agent.as_ical())?;
        }
        merged.push(entry);
    }
    let at = position.unwrap_or(node.entries.len()).min(node.entries.len());
    for (offset, entry) in merged.into_iter().enumerate() {
        node.entries
            .insert(at.saturating_add(offset).min(node.entries.len()), entry);
    }
    Ok(())
}

/// The component of an alarm. `fallback` is the text of an alarm that has none (the title of the event, or the
/// default text of the caller).
///
/// An `EMAIL` alarm needs recipients and a subject (RFC 5545 section 3.6.6) that the event model cannot carry,
/// so the server does not write one.
fn alarm_node(alarm: &EventAlarm, fallback: &str) -> Result<Node, IcalError> {
    let mut node = Node::new(Kind::VAlarm);
    let action = match alarm.action {
        AlarmAction::Display => "DISPLAY",
        AlarmAction::Audio => "AUDIO",
        AlarmAction::Email => {
            return Err(invalid(
                "e-mail alarms cannot be written (they need recipients); use a display or audio alarm",
            ));
        }
    };
    node.entries.push(entry_from_line(&format!("ACTION:{action}"))?);
    let trigger = match &alarm.trigger {
        AlarmTrigger::Relative { offset, related } => {
            let related = match related {
                AlarmRelated::Start => "",
                AlarmRelated::End => ";RELATED=END",
            };
            format!("TRIGGER{related}:{}", offset.as_str())
        }
        AlarmTrigger::Absolute { at } => format!("TRIGGER;VALUE=DATE-TIME:{}Z", at.naive_utc().format("%Y%m%dT%H%M%S")),
    };
    node.entries.push(entry_from_line(&trigger)?);
    let description = alarm
        .description
        .as_deref()
        .filter(|text| !text.is_empty())
        .unwrap_or(fallback);
    node.entries.push(entry_for_text("DESCRIPTION", description)?);
    Ok(node)
}
