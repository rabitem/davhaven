//! Evaluation of `calendar-query` filters (RFC 4791 section 9.7) against a parsed calendar.
//!
//! The structure of the filter mirrors the structure of the calendar: a `comp-filter` selects child components
//! by name and constrains them with a time range, property filters and nested component filters. A component
//! with a time range matches when one of its *instances* overlaps the range (RFC 4791 section 9.9), so
//! recurring components are expanded with the engine of [`crate::occurrence`]; an alarm matches when one of
//! its trigger times, computed from the instances of its parent, falls into the range.

use std::collections::{HashMap, HashSet};

use calcard::icalendar::{ICalendarParameterValue, ICalendarValue};
use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::{IcalLimits, TimeZoneName};

use crate::calendar::{Kind, Length, Node, PeriodEnd, Prop, entry_duration, entry_moment, entry_periods, entry_texts};
use crate::error::IcalError;
use crate::filter::{CalendarFilter, Collation, CompFilter, ParamFilter, PropFilter, TextMatch, TimeRange};
use crate::occurrence::{Budget, Engine, Flow, TodoTimes};
use crate::parse::{ParsedCalendar, split_content_line};
use crate::zones::{Zone, Zones};

/// The most `REPEAT` repetitions of an alarm that are evaluated.
const MAX_ALARM_REPEATS: i64 = 1_000;
/// How far around a time range instances are searched for alarms (alarms fire before or after their instance).
const ALARM_SLACK_DAYS: i64 = 31;

type RangeKey = (Option<i64>, Option<i64>);

/// The state of one evaluation.
struct Matcher<'a> {
    root: &'a Node,
    zones: Zones,
    limits: &'a IcalLimits,
    budget: Budget,
    /// The components that have an instance in a range, by range.
    cache: HashMap<RangeKey, HashSet<usize>>,
}

/// The place of a component in the tree, as far as time ranges need to know it.
#[derive(Clone, Copy)]
struct Place {
    /// Index among the children of the `VCALENDAR` when the component is a direct child of it.
    top_index: Option<usize>,
    /// The enclosing top-level component and its index (for alarms).
    parent: Option<usize>,
}

/// Evaluates a filter against a calendar with floating values read in `zone`.
pub(crate) fn evaluate(
    calendar: &ParsedCalendar,
    filter: &CalendarFilter,
    limits: &IcalLimits,
    zone: TimeZoneName,
) -> Result<bool, IcalError> {
    let root = &calendar.root;
    let mut matcher = Matcher {
        root,
        zones: Zones::for_tree(root, Zone::from_tz(zone.tz())),
        limits,
        budget: Budget::new(limits),
        cache: HashMap::new(),
    };
    if !filter.root.name.eq_ignore_ascii_case(root.kind.as_str()) || filter.root.is_not_defined {
        return Ok(false);
    }
    let place = Place {
        top_index: None,
        parent: None,
    };
    matcher.satisfied(&filter.root, root, place)
}

fn name_matches(kind: &Kind, name: &str) -> bool {
    kind.as_str().eq_ignore_ascii_case(name)
}

impl<'a> Matcher<'a> {
    /// Whether the component satisfies every condition of the comp-filter (except its own existence).
    fn satisfied(&mut self, filter: &CompFilter, node: &'a Node, place: Place) -> Result<bool, IcalError> {
        if let Some(range) = &filter.time_range
            && !self.in_range(node, place, range)?
        {
            return Ok(false);
        }
        for property in &filter.prop_filters {
            if !prop_matches(property, node, &self.zones) {
                return Ok(false);
            }
        }
        self.children_match(&filter.comp_filters, node, place)
    }

    fn children_match(&mut self, filters: &[CompFilter], parent: &'a Node, place: Place) -> Result<bool, IcalError> {
        for filter in filters {
            let candidates: Vec<(usize, &'a Node)> = parent
                .children
                .iter()
                .enumerate()
                .filter(|(_, child)| name_matches(&child.kind, &filter.name))
                .collect();
            if filter.is_not_defined {
                if candidates.is_empty() {
                    continue;
                }
                return Ok(false);
            }
            let mut any = false;
            for (index, child) in candidates {
                let child_place = if place.top_index.is_none() && std::ptr::eq(parent, self.root) {
                    Place {
                        top_index: Some(index),
                        parent: None,
                    }
                } else {
                    Place {
                        top_index: None,
                        parent: place.top_index,
                    }
                };
                if self.satisfied(filter, child, child_place)? {
                    any = true;
                    break;
                }
            }
            if !any {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn in_range(&mut self, node: &'a Node, place: Place, range: &TimeRange) -> Result<bool, IcalError> {
        match node.kind {
            Kind::VEvent | Kind::VTodo | Kind::VJournal => match place.top_index {
                Some(index) => self.component_in_range(index, node, range),
                None => Ok(false),
            },
            Kind::VAlarm => match place.parent {
                Some(index) => self.alarm_in_range(index, node, range),
                None => Ok(false),
            },
            Kind::VFreebusy => Ok(self.freebusy_in_range(node, range)),
            _ => Ok(false),
        }
    }

    /// The components that have an instance overlapping `range`. Matching only asks whether an instance exists,
    /// so nothing is collected and the limit on the number of instances does not apply: a series that has
    /// thousands of instances in the range matches like any other (the step and time budgets still bound the
    /// work).
    fn components_in(&mut self, range: &TimeRange) -> Result<&HashSet<usize>, IcalError> {
        let key = (range.start.map(|at| at.timestamp()), range.end.map(|at| at.timestamp()));
        if !self.cache.contains_key(&key) {
            let mut engine = Engine::new(&self.zones, self.limits, self.budget).without_instance_limit();
            let mut found = HashSet::new();
            engine.visit(self.root, range, &mut |occurrence| {
                found.insert(occurrence.component);
                Ok(Flow::Continue)
            })?;
            self.cache.insert(key, found);
        }
        self.cache
            .get(&key)
            .ok_or_else(|| IcalError::invalid("the filter cannot be evaluated"))
    }

    fn component_in_range(&mut self, index: usize, node: &Node, range: &TimeRange) -> Result<bool, IcalError> {
        if self.components_in(range)?.contains(&index) {
            return Ok(true);
        }
        // A to-do without DTSTART and DUE has no instances; the table of RFC 4791 section 9.9 still applies.
        if node.kind == Kind::VTodo && !node.has(&Prop::Dtstart) && !node.has(&Prop::Due) {
            let instant = |property: &Prop| {
                node.first(property)
                    .and_then(entry_moment)
                    .and_then(|moment| self.zones.to_utc(&moment))
            };
            let todo = TodoTimes {
                completed: instant(&Prop::Completed),
                created: instant(&Prop::Created),
                ..TodoTimes::default()
            };
            return Ok(todo_matches(&todo, range));
        }
        Ok(false)
    }

    fn freebusy_in_range(&self, node: &Node, range: &TimeRange) -> bool {
        let at = |property: &Prop| {
            node.first(property)
                .and_then(entry_moment)
                .and_then(|moment| self.zones.to_utc(&moment))
        };
        match (at(&Prop::Dtstart), at(&Prop::Dtend)) {
            (Some(start), Some(end)) => {
                range.start.is_none_or(|from| from <= end) && range.end.is_none_or(|to| to > start)
            }
            // Without its own period, RFC 4791 9.9 compares every FREEBUSY period: (start < period-end) AND
            // (end > period-start).
            _ => node.all(&Prop::Freebusy).flat_map(entry_periods).any(|period| {
                let Some(start) = self.zones.to_utc(&period.start) else {
                    return false;
                };
                let end = match period.end {
                    PeriodEnd::At(end) => self.zones.to_utc(&end),
                    PeriodEnd::Length(length) => Length::from_duration(&length)
                        .total_seconds()
                        .and_then(TimeDelta::try_seconds)
                        .and_then(|delta| start.checked_add_signed(delta)),
                };
                end.is_some_and(|end| {
                    range.start.is_none_or(|from| from < end) && range.end.is_none_or(|to| to > start)
                })
            }),
        }
    }

    fn alarm_in_range(&mut self, parent_index: usize, alarm: &Node, range: &TimeRange) -> Result<bool, IcalError> {
        let Some(trigger) = alarm.first(&Prop::Trigger) else {
            return Ok(false);
        };
        let interval = alarm
            .first(&Prop::Duration)
            .and_then(entry_duration)
            .map(|duration| Length::from_duration(&duration));
        let repeats = alarm.integer(&Prop::Repeat).unwrap_or(0).clamp(0, MAX_ALARM_REPEATS);
        let step = interval.and_then(Length::total_seconds);
        let fires = |first: DateTime<Utc>| -> bool {
            (0..=repeats).any(|k| {
                let offset = step.and_then(|step| step.checked_mul(k)).unwrap_or(0);
                TimeDelta::try_seconds(offset)
                    .and_then(|delta| first.checked_add_signed(delta))
                    .is_some_and(|at| range.contains(at))
            })
        };
        match trigger.values.first() {
            Some(ICalendarValue::PartialDateTime(value)) => {
                let moment = crate::calendar::moment_from_partial(value, false, None);
                Ok(moment.and_then(|moment| self.zones.to_utc(&moment)).is_some_and(fires))
            }
            Some(ICalendarValue::Duration(duration)) => {
                let related_end = matches!(
                    trigger.parameter(&crate::calendar::Param::Related),
                    Some(ICalendarParameterValue::Related(
                        calcard::icalendar::ICalendarRelated::End
                    ))
                );
                let length = Length::from_duration(duration);
                let offset = length.total_seconds().and_then(TimeDelta::try_seconds);
                let Some(offset) = offset else {
                    return Ok(false);
                };
                let slack = TimeDelta::try_days(ALARM_SLACK_DAYS).unwrap_or_default();
                let reach = offset.abs().checked_add(&slack).unwrap_or(slack);
                let window = TimeRange::new(
                    range.start.map(|at| at.checked_sub_signed(reach).unwrap_or(at)),
                    range.end.map(|at| at.checked_add_signed(reach).unwrap_or(at)),
                );
                let mut engine = Engine::new(&self.zones, self.limits, self.budget).without_instance_limit();
                let mut hit = false;
                engine.visit(self.root, &window, &mut |occurrence| {
                    if occurrence.component != parent_index {
                        return Ok(Flow::Continue);
                    }
                    let base = if related_end { occurrence.end } else { occurrence.start };
                    if base.checked_add_signed(offset).is_some_and(fires) {
                        hit = true;
                        return Ok(Flow::Stop);
                    }
                    Ok(Flow::Continue)
                })?;
                Ok(hit)
            }
            _ => Ok(false),
        }
    }
}

/// RFC 4791 section 9.9 for to-dos without any `DTSTART` or `DUE`.
fn todo_matches(todo: &TodoTimes, range: &TimeRange) -> bool {
    let starts_by = |at: DateTime<Utc>| range.start.is_none_or(|start| start <= at);
    let ends_after = |at: DateTime<Utc>| range.end.is_none_or(|end| end > at);
    let ends_at_or_after = |at: DateTime<Utc>| range.end.is_none_or(|end| end >= at);
    match (todo.completed, todo.created) {
        (Some(completed), Some(created)) => {
            (starts_by(created) || starts_by(completed)) && (ends_at_or_after(created) || ends_at_or_after(completed))
        }
        (Some(completed), None) => starts_by(completed) && ends_at_or_after(completed),
        (None, Some(created)) => ends_after(created),
        (None, None) => true,
    }
}

fn prop_matches(filter: &PropFilter, node: &Node, zones: &Zones) -> bool {
    let entries: Vec<&calcard::icalendar::ICalendarEntry> = node
        .entries
        .iter()
        .filter(|entry| entry.name.as_str().eq_ignore_ascii_case(&filter.name))
        .collect();
    if filter.is_not_defined {
        return entries.is_empty();
    }
    entries.into_iter().any(|entry| {
        if let Some(range) = &filter.time_range {
            let inside = entry_moment(entry)
                .and_then(|moment| zones.to_utc(&moment))
                .is_some_and(|at| range.contains(at));
            if !inside {
                return false;
            }
        }
        if let Some(text) = &filter.text_match
            && !text_matches(text, &property_texts(entry))
        {
            return false;
        }
        filter.param_filters.iter().all(|param| param_matches(param, entry))
    })
}

fn param_matches(filter: &ParamFilter, entry: &calcard::icalendar::ICalendarEntry) -> bool {
    let values: Vec<Option<String>> = entry
        .params
        .iter()
        .filter(|param| param.name.as_str().eq_ignore_ascii_case(&filter.name))
        .map(|param| param.value.clone().into_text().map(std::borrow::Cow::into_owned))
        .collect();
    if filter.is_not_defined {
        return values.is_empty();
    }
    if values.is_empty() {
        return false;
    }
    match &filter.text_match {
        Some(text) => {
            let texts: Vec<String> = values.into_iter().flatten().collect();
            text_matches(text, &texts)
        }
        None => true,
    }
}

/// The text values a text-match is compared with: the text of the property's values, or for typed values
/// (dates, numbers) their serialized form.
fn property_texts(entry: &calcard::icalendar::ICalendarEntry) -> Vec<String> {
    let texts = entry_texts(entry);
    if !texts.is_empty() && texts.len() == entry.values.len() {
        return texts;
    }
    let mut line = String::new();
    // Writing into a `String` cannot fail.
    let _ = entry.write_to(&mut line);
    let unfolded = line.replace("\r\n ", "");
    let unfolded = unfolded.trim_end_matches("\r\n");
    split_content_line(unfolded)
        .map(|(_, value)| value.split(',').map(str::to_owned).collect())
        .unwrap_or_default()
}

fn fold(text: &str, collation: Collation) -> String {
    match collation {
        Collation::AsciiCasemap => text.to_ascii_lowercase(),
        Collation::UnicodeCasemap => text.to_lowercase(),
        Collation::Octet => text.to_owned(),
    }
}

fn text_matches(filter: &TextMatch, texts: &[String]) -> bool {
    let needle = fold(&filter.value, filter.collation);
    let found = texts.iter().any(|text| fold(text, filter.collation).contains(&needle));
    found != filter.negate
}
