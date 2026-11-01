//! Reading stored components as `EventData`.

use calcard::icalendar::{ICalendarEntry, ICalendarValue};
use chrono::{DateTime, Utc};
use davhaven_domain::{
    AlarmAction, AlarmRelated, AlarmTrigger, CalendarUserAddress, Classification, EventAlarm, EventAttendee, EventData,
    EventDuration, EventOrganizer, EventStatus, EventTime, Recurrence, RecurrenceRule, Transparency, Uid,
};

use super::instances::{invalid, master_index, override_index};
use crate::calendar::{
    Kind, Moment, Node, Param, Prop, address_of, cutype_of, entry_duration, entry_moment, entry_moments, entry_periods,
    entry_texts, param_text, partstat_of, role_of, schedule_agent_of,
};
use crate::error::IcalError;
use crate::parse::ParsedCalendar;
use crate::zones::{Zone, Zones};

// ---------------------------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------------------------

/// Renders one component of `calendar` as `EventData`: the master component, or the override with the given
/// recurrence id.
///
/// # Errors
///
/// [`IcalError::Invalid`] when the calendar has no such component.
pub fn to_event_data(calendar: &ParsedCalendar, recurrence_id: Option<&EventTime>) -> Result<EventData, IcalError> {
    let root = &calendar.root;
    let zones = Zones::for_tree(root, Zone::utc());
    let index = match recurrence_id {
        None => master_index(root),
        Some(rid) => override_index(root, &zones, &Moment::from_event_time(rid)),
    };
    let node = index
        .and_then(|index| root.children.get(index))
        .ok_or_else(|| invalid("the object has no such component"))?;
    Ok(event_data_of(node, &zones))
}

fn event_data_of(node: &Node, zones: &Zones) -> EventData {
    let time = |name: &Prop| {
        node.first(name)
            .and_then(entry_moment)
            .map(|moment| moment.to_event_time(zones))
    };
    let end_name = if node.kind == Kind::VTodo {
        Prop::Due
    } else {
        Prop::Dtend
    };
    EventData {
        uid: node.uid().and_then(|uid| Uid::parse(&uid).ok()),
        recurrence_id: time(&Prop::RecurrenceId),
        summary: node.text(&Prop::Summary),
        description: node.text(&Prop::Description),
        location: node.text(&Prop::Location),
        start: time(&Prop::Dtstart),
        end: time(&end_name),
        duration: node
            .first(&Prop::Duration)
            .and_then(entry_duration)
            .and_then(|duration| EventDuration::parse(&duration.to_string()).ok()),
        status: node.text(&Prop::Status).and_then(|text| EventStatus::from_ical(&text)),
        transparency: node.text(&Prop::Transp).and_then(|text| Transparency::from_ical(&text)),
        class: node
            .text(&Prop::Class)
            .and_then(|text| Classification::from_ical(&text)),
        recurrence: recurrence_of(node, zones),
        organizer: node.first(&Prop::Organizer).and_then(organizer_of),
        attendees: attendees_of(node),
        categories: categories_of(node),
        url: node.text(&Prop::Url).and_then(|text| url::Url::parse(&text).ok()),
        sequence: node
            .integer(&Prop::Sequence)
            .and_then(|value| i32::try_from(value).ok()),
        alarms: alarms_of(node, zones),
        // What is stored has nothing to remove.
        removed: std::collections::BTreeSet::new(),
    }
}

fn recurrence_of(node: &Node, zones: &Zones) -> Option<Recurrence> {
    let rrule = node
        .first(&Prop::Rrule)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::RecurrenceRule(rule) => RecurrenceRule::parse(&rule.to_string()).ok(),
            _ => None,
        });
    let mut rdates: Vec<EventTime> = Vec::new();
    for entry in node.all(&Prop::Rdate) {
        rdates.extend(entry_moments(entry).0.iter().map(|moment| moment.to_event_time(zones)));
        rdates.extend(
            entry_periods(entry)
                .iter()
                .map(|period| period.start.to_event_time(zones)),
        );
    }
    let exdates: Vec<EventTime> = node
        .all(&Prop::Exdate)
        .flat_map(|entry| entry_moments(entry).0)
        .map(|moment| moment.to_event_time(zones))
        .collect();
    if rrule.is_none() && rdates.is_empty() && exdates.is_empty() {
        return None;
    }
    Some(Recurrence { rrule, rdates, exdates })
}

fn organizer_of(entry: &ICalendarEntry) -> Option<EventOrganizer> {
    Some(EventOrganizer {
        address: address_of(entry)?,
        common_name: param_text(entry, &Param::Cn),
        sent_by: param_text(entry, &Param::SentBy).and_then(|text| CalendarUserAddress::parse(&text).ok()),
    })
}

fn attendees_of(node: &Node) -> Option<Vec<EventAttendee>> {
    let list: Vec<EventAttendee> = node
        .all(&Prop::Attendee)
        .filter_map(|entry| {
            Some(EventAttendee {
                address: address_of(entry)?,
                common_name: param_text(entry, &Param::Cn),
                partstat: Some(partstat_of(entry)),
                role: crate::calendar::has_param(entry, &Param::Role).then(|| role_of(entry)),
                cutype: crate::calendar::has_param(entry, &Param::Cutype).then(|| cutype_of(entry)),
                rsvp: param_text(entry, &Param::Rsvp).map(|text| text.eq_ignore_ascii_case("TRUE")),
                schedule_agent: crate::calendar::has_param(entry, &Param::ScheduleAgent)
                    .then(|| schedule_agent_of(entry)),
            })
        })
        .collect();
    (!list.is_empty()).then_some(list)
}

fn categories_of(node: &Node) -> Option<Vec<String>> {
    let list: Vec<String> = node.all(&Prop::Categories).flat_map(entry_texts).collect();
    (!list.is_empty()).then_some(list)
}

fn alarms_of(node: &Node, zones: &Zones) -> Option<Vec<EventAlarm>> {
    let list: Vec<EventAlarm> = node
        .children
        .iter()
        .filter(|child| child.kind == Kind::VAlarm)
        .filter_map(|alarm| {
            let action = match alarm.text(&Prop::Action)?.to_ascii_uppercase().as_str() {
                "DISPLAY" => AlarmAction::Display,
                "AUDIO" => AlarmAction::Audio,
                "EMAIL" => AlarmAction::Email,
                _ => return None,
            };
            let trigger_entry = alarm.first(&Prop::Trigger)?;
            let trigger = match trigger_entry.values.first()? {
                ICalendarValue::Duration(duration) => AlarmTrigger::Relative {
                    offset: EventDuration::parse(&duration.to_string()).ok()?,
                    related: if param_text(trigger_entry, &Param::Related)
                        .is_some_and(|related| related.eq_ignore_ascii_case("END"))
                    {
                        AlarmRelated::End
                    } else {
                        AlarmRelated::Start
                    },
                },
                ICalendarValue::PartialDateTime(_) => AlarmTrigger::Absolute {
                    at: zones.to_utc(&entry_moment(trigger_entry)?)?,
                },
                _ => return None,
            };
            Some(EventAlarm {
                action,
                trigger,
                description: alarm.text(&Prop::Description),
            })
        })
        .collect();
    (!list.is_empty()).then_some(list)
}

/// The recurrence ids of the override components of `calendar`, in ascending order.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn override_ids(calendar: &ParsedCalendar) -> Result<Vec<EventTime>, IcalError> {
    let root = &calendar.root;
    let zones = Zones::for_tree(root, Zone::utc());
    let mut found: Vec<(Option<DateTime<Utc>>, EventTime)> = root
        .children
        .iter()
        .filter(|node| node.component_kind().is_some())
        .filter_map(|node| node.first(&Prop::RecurrenceId).and_then(entry_moment))
        .map(|moment| (zones.to_utc(&moment), moment.to_event_time(&zones)))
        .collect();
    found.sort_by_key(|(instant, _)| *instant);
    Ok(found.into_iter().map(|(_, time)| time).collect())
}
