//! Comparing two versions of one component: which properties changed, and which of them are significant.

use std::collections::{BTreeMap, BTreeSet};

use calcard::icalendar::ICalendarValue;
use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::CalendarUserAddress;

use super::{SERVER_OWNED, upper};
use crate::calendar::{
    Kind, Length, Moment, Node, Param, Prop, address_of, entry_duration, entry_moment, entry_moments,
};
use crate::hash::{canonical, canonical_entry};
use crate::occurrence::start_moment;
use crate::zones::{RidKey, Zones};

/// What differs between two versions of one component.
#[derive(Debug, Default)]
pub(super) struct Compared {
    pub(super) significant: Vec<String>,
    pub(super) other: Vec<String>,
}

/// How strictly versions are compared.
#[derive(Clone, Copy)]
pub(super) struct CompareOptions<'a> {
    /// The attendee whose own `ATTENDEE` lines are left out (an attendee changes their own participation).
    pub(super) own: Option<&'a CalendarUserAddress>,
    /// Also leave out what attendees may change on their copy (`TRANSP`, alarms) and client private properties.
    pub(super) attendee_mode: bool,
}

impl CompareOptions<'_> {
    /// The comparison of two versions of the organizer's copy.
    pub(super) const fn organizer() -> Self {
        Self {
            own: None,
            attendee_mode: false,
        }
    }
}

const SIGNIFICANT: [&str; 10] = [
    "DTSTART", "DTEND", "DURATION", "DUE", "RRULE", "RDATE", "EXDATE", "LOCATION", "SUMMARY", "STATUS",
];

const VOLATILE: [&str; 6] = [
    "DTSTAMP",
    "LAST-MODIFIED",
    "CREATED",
    "SEQUENCE",
    "PRODID",
    "RECURRENCE-ID",
];

fn time_equal(old_zones: &Zones, old: Option<&Moment>, new_zones: &Zones, new: Option<&Moment>) -> bool {
    match (old, new) {
        (None, None) => true,
        (Some(first), Some(second)) => {
            if first.is_date() != second.is_date() {
                false
            } else if first.is_date() {
                first.date() == second.date()
            } else {
                old_zones.to_utc(first) == new_zones.to_utc(second)
            }
        }
        _ => false,
    }
}

/// The instant an instance ends: `DTEND`/`DUE`, `DTSTART` plus `DURATION`, or the default length.
fn effective_end(node: &Node, zones: &Zones) -> Option<DateTime<Utc>> {
    let start = start_moment(node).ok().flatten()?;
    let begin = zones.to_utc(&start)?;
    let end_name = if node.kind == Kind::VTodo {
        Prop::Due
    } else {
        Prop::Dtend
    };
    if let Some(end) = node.first(&end_name).and_then(entry_moment) {
        return zones.to_utc(&end);
    }
    if let Some(duration) = node.first(&Prop::Duration).and_then(entry_duration) {
        let length = Length::from_duration(&duration);
        return begin.checked_add_signed(TimeDelta::try_seconds(length.total_seconds()?)?);
    }
    if start.is_date() {
        return begin.checked_add_signed(TimeDelta::try_days(1)?);
    }
    Some(begin)
}

fn rule_of(node: &Node) -> Option<&calcard::icalendar::ICalendarRecurrenceRule> {
    match node.first(&Prop::Rrule)?.values.first()? {
        ICalendarValue::RecurrenceRule(rule) => Some(rule),
        _ => None,
    }
}

/// The instances a date property (`RDATE`, `EXDATE`) names.
pub(super) fn date_set(node: &Node, name: &Prop, zones: &Zones) -> BTreeSet<RidKey> {
    node.all(name)
        .flat_map(|entry| entry_moments(entry).0)
        .filter_map(|moment| zones.rid_key(&moment))
        .collect()
}

fn text_of(node: &Node, name: &Prop) -> String {
    node.text(name).unwrap_or_default()
}

/// The properties of a component by name, as sorted canonical lines; alarms count as one property `VALARM`.
///
/// Comparing the organizer's copy leaves out what belongs to the server on the lines of the attendees: their
/// answer and the delivery status. A client cannot change those, so a version that only differs there is not a
/// change. The comments the attendees gave with their answers are the server's as well, and left out the same way.
fn property_map(node: &Node, options: &CompareOptions<'_>) -> BTreeMap<String, Vec<String>> {
    let organizer_mode = options.own.is_none() && !options.attendee_mode;
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &node.entries {
        let name = upper(entry.name.as_str());
        if SIGNIFICANT.contains(&name.as_str()) || VOLATILE.contains(&name.as_str()) {
            continue;
        }
        // The comments of the attendees are the server's like their answers: a client's version cannot change them.
        if organizer_mode && name == super::reply::ATTENDEE_COMMENT {
            continue;
        }
        if options.attendee_mode && (name == "TRANSP" || name.starts_with("X-APPLE-") || name.starts_with("X-MOZ-")) {
            continue;
        }
        if name == "ATTENDEE" && options.own.is_some() && address_of(entry).as_ref() == options.own {
            continue;
        }
        let ignored: &[Param] = if name == "ATTENDEE" && organizer_mode {
            &SERVER_OWNED
        } else {
            &[Param::ScheduleStatus]
        };
        map.entry(name).or_default().push(canonical_entry(entry, ignored));
    }
    if !options.attendee_mode {
        let mut alarms: Vec<String> = node
            .children
            .iter()
            .filter(|child| child.kind == Kind::VAlarm)
            .map(|child| {
                let mut text = String::new();
                canonical(child, &mut text);
                text
            })
            .collect();
        alarms.sort();
        if !alarms.is_empty() {
            map.insert("VALARM".to_owned(), alarms);
        }
    }
    for lines in map.values_mut() {
        lines.sort();
    }
    map
}

pub(super) fn compare(
    old: &Node,
    old_zones: &Zones,
    new: &Node,
    new_zones: &Zones,
    options: &CompareOptions<'_>,
) -> Compared {
    let mut result = Compared::default();
    let moment = |node: &Node, name: &Prop| node.first(name).and_then(entry_moment);
    if !time_equal(
        old_zones,
        moment(old, &Prop::Dtstart).as_ref(),
        new_zones,
        moment(new, &Prop::Dtstart).as_ref(),
    ) {
        result.significant.push("DTSTART".to_owned());
    }
    if effective_end(old, old_zones) != effective_end(new, new_zones) {
        let name = if old.has(&Prop::Duration) || new.has(&Prop::Duration) {
            "DURATION"
        } else if old.kind == Kind::VTodo {
            "DUE"
        } else {
            "DTEND"
        };
        result.significant.push(name.to_owned());
    }
    if rule_of(old) != rule_of(new) {
        result.significant.push("RRULE".to_owned());
    }
    if date_set(old, &Prop::Rdate, old_zones) != date_set(new, &Prop::Rdate, new_zones) {
        result.significant.push("RDATE".to_owned());
    }
    if date_set(old, &Prop::Exdate, old_zones) != date_set(new, &Prop::Exdate, new_zones) {
        result.significant.push("EXDATE".to_owned());
    }
    for (property, name) in [(Prop::Location, "LOCATION"), (Prop::Summary, "SUMMARY")] {
        if text_of(old, &property) != text_of(new, &property) {
            result.significant.push(name.to_owned());
        }
    }
    let status = |node: &Node| node.status().unwrap_or_else(|| "CONFIRMED".to_owned());
    if status(old) != status(new) {
        result.significant.push("STATUS".to_owned());
    }
    let before = property_map(old, options);
    let after = property_map(new, options);
    let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    for name in names {
        if before.get(name) != after.get(name) {
            result.other.push(name.clone());
        }
    }
    result
}
