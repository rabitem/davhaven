//! Projection of calendar data for `calendar-data` requests (expand, limit, component selection).
//!
//! A `calendar-data` element in `calendar-query`, `calendar-multiget` and PROPFIND/REPORT may restrict the
//! returned iCalendar to selected components and properties, expand recurring events into single instances
//! (`expand`), keep only the recurrence overrides inside a range (`limit-recurrence-set`) or restrict
//! `VFREEBUSY` periods (`limit-freebusy-set`). [`project`] applies such a request to a stored calendar and
//! returns the text to send. A default [`Projection`] returns the whole calendar.
//!
//! Expansion follows RFC 4791 section 9.6.5: every instance becomes a component of its own with a
//! `RECURRENCE-ID`, the recurrence properties are gone, date-times with a time zone are written in UTC and
//! all-day dates and floating times stay as they are.

use std::collections::BTreeSet;

use calcard::icalendar::{ICalendarEntry, ICalendarValue};
use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::{IcalLimits, TimeZoneName};

use crate::calendar::{Kind, Length, Moment, Node, Param, Prop, entry_for_moment, entry_moment, param_text};
use crate::error::IcalError;
use crate::filter::TimeRange;
use crate::occurrence::{Budget, Engine, Flow, Occurrence};
use crate::parse::ParsedCalendar;
use crate::zones::{Zone, Zones};

/// A property selection inside a component selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropSelection {
    /// The property name.
    pub name: String,
    /// Return the property without its value (`novalue="yes"`).
    pub no_value: bool,
}

/// A selection of the parts of a component to return (`comp` in `calendar-data`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComponentSelection {
    /// The component name (`VCALENDAR`, `VEVENT`, ...).
    pub name: String,
    /// Return every property (`allprop`).
    pub all_props: bool,
    /// The selected properties when `all_props` is false.
    pub props: Vec<PropSelection>,
    /// Return every child component (`allcomp`).
    pub all_comps: bool,
    /// The selected child components when `all_comps` is false.
    pub comps: Vec<ComponentSelection>,
}

/// What to return of a stored calendar.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Projection {
    /// Restrict components and properties; `None` returns everything.
    pub select: Option<ComponentSelection>,
    /// Expand recurring events into single instances inside the range (`expand`).
    pub expand: Option<TimeRange>,
    /// Return only the overrides inside the range plus the master (`limit-recurrence-set`).
    pub limit_recurrence_set: Option<TimeRange>,
    /// Return only the free-busy periods inside the range (`limit-freebusy-set`).
    pub limit_freebusy_set: Option<TimeRange>,
}

impl Projection {
    /// Whether the projection returns the stored data unchanged.
    pub const fn is_identity(&self) -> bool {
        self.select.is_none()
            && self.expand.is_none()
            && self.limit_recurrence_set.is_none()
            && self.limit_freebusy_set.is_none()
    }
}

/// Applies `projection` to `calendar` and serializes the result.
///
/// Floating times and all-day dates are read as UTC; see [`project_in_zone`].
///
/// # Errors
///
/// [`IcalError::Invalid`] for a projection that cannot be applied (for example `expand` together with
/// `limit-recurrence-set`) and [`IcalError::Limit`] when expansion exceeds the limits.
pub fn project(calendar: &ParsedCalendar, projection: &Projection, limits: &IcalLimits) -> Result<String, IcalError> {
    project_in_zone(calendar, projection, limits, TimeZoneName::utc())
}

/// Like [`project`], with floating times and all-day dates read in `floating_zone` (the time zone of the
/// calendar collection).
///
/// # Errors
///
/// As [`project`].
pub fn project_in_zone(
    calendar: &ParsedCalendar,
    projection: &Projection,
    limits: &IcalLimits,
    floating_zone: TimeZoneName,
) -> Result<String, IcalError> {
    if projection.is_identity() {
        return crate::serialize::serialize(calendar);
    }
    if projection.expand.is_some() && projection.limit_recurrence_set.is_some() {
        return Err(IcalError::invalid(
            "expand cannot be combined with limit-recurrence-set",
        ));
    }
    let zones = Zones::for_tree(&calendar.root, Zone::from_tz(floating_zone.tz()));
    let mut root = calendar.root.clone();
    if let Some(range) = &projection.expand {
        range.validate_bounded(limits)?;
        root = expand_instances(&root, range, &zones, limits)?;
    } else if let Some(range) = &projection.limit_recurrence_set {
        range.validate(limits)?;
        root = limit_recurrences(&root, range, &zones, limits)?;
    }
    if let Some(range) = &projection.limit_freebusy_set {
        range.validate(limits)?;
        limit_freebusy(&mut root, range, &zones);
    }
    if let Some(selection) = &projection.select {
        if !selection.name.eq_ignore_ascii_case("VCALENDAR") {
            return Err(IcalError::invalid(
                "the calendar-data selection must start at VCALENDAR",
            ));
        }
        root = select(&root, selection);
    }
    Ok(root.to_calendar().to_string())
}

// ---------------------------------------------------------------------------------------------------------------
// Expansion
// ---------------------------------------------------------------------------------------------------------------

/// The properties that describe the recurrence set and disappear from expanded instances.
fn is_recurrence_property(name: &Prop) -> bool {
    matches!(
        name,
        Prop::Rrule | Prop::Rdate | Prop::Exdate | Prop::Exrule | Prop::RecurrenceId
    )
}

/// How a moment is written in an expanded instance: UTC for zoned values, as is for dates and floating values.
fn expanded_moment(zones: &Zones, like: &Moment, instant: DateTime<Utc>) -> Moment {
    match like {
        Moment::Date(_) => Moment::Date(zones.local_in_zone_of(like, instant).date()),
        Moment::Floating(_) => Moment::Floating(zones.local_in_zone_of(like, instant)),
        Moment::Utc(_) | Moment::Zoned { .. } => Moment::Utc(instant.naive_utc()),
    }
}

fn expand_instances(root: &Node, range: &TimeRange, zones: &Zones, limits: &IcalLimits) -> Result<Node, IcalError> {
    let mut engine = Engine::new(zones, limits, Budget::new(limits));
    let occurrences = engine.expand(root, range)?;
    let mut output = Node::new(Kind::VCalendar);
    output.entries.clone_from(&root.entries);
    let mut instances: Vec<Node> = Vec::with_capacity(occurrences.len());
    for occurrence in &occurrences {
        let Some(source) = root.children.get(occurrence.component) else {
            continue;
        };
        instances.push(instance_node(source, occurrence, zones)?);
    }
    let used: BTreeSet<String> = instances
        .iter()
        .flat_map(|node| node.entries.iter())
        .filter_map(|entry| param_text(entry, &Param::Tzid))
        .collect();
    for child in &root.children {
        let referenced =
            child.kind == Kind::VTimezone && child.text(&Prop::Tzid).is_some_and(|tzid| used.contains(&tzid));
        if referenced {
            output.children.push(child.clone());
        }
    }
    output.children.extend(instances);
    Ok(output)
}

fn instance_node(source: &Node, occurrence: &Occurrence, zones: &Zones) -> Result<Node, IcalError> {
    let mut node = Node::new(source.kind.clone());
    node.children.clone_from(&source.children);
    let start_like = source.first(&Prop::Dtstart).and_then(entry_moment);
    let end_like = source
        .first(&Prop::Dtend)
        .or_else(|| source.first(&Prop::Due))
        .and_then(entry_moment);
    for entry in &source.entries {
        if is_recurrence_property(&entry.name) {
            continue;
        }
        let replacement = match (&entry.name, &start_like, &end_like) {
            (Prop::Dtstart, Some(like), _) => Some(("DTSTART", like, occurrence.effective_start())),
            (Prop::Dtend, _, Some(like)) => Some(("DTEND", like, occurrence.effective_end())),
            (Prop::Due, _, Some(like)) => Some(("DUE", like, occurrence.effective_end())),
            _ => None,
        };
        match replacement {
            Some((name, like, instant)) => {
                node.entries
                    .push(entry_for_moment(name, &expanded_moment(zones, like, instant))?);
            }
            None => node.entries.push(entry.clone()),
        }
    }
    let rid = expanded_identity(&occurrence.recurrence_id, zones);
    node.entries.push(entry_for_moment("RECURRENCE-ID", &rid)?);
    Ok(node)
}

/// The recurrence id of an expanded instance.
fn expanded_identity(rid: &Moment, zones: &Zones) -> Moment {
    match rid {
        Moment::Date(_) | Moment::Floating(_) | Moment::Utc(_) => rid.clone(),
        Moment::Zoned { .. } => zones
            .to_utc(rid)
            .map_or_else(|| rid.clone(), |instant| Moment::Utc(instant.naive_utc())),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------------------------------------------

fn limit_recurrences(root: &Node, range: &TimeRange, zones: &Zones, limits: &IcalLimits) -> Result<Node, IcalError> {
    // The result is bounded by the number of override components, so the limit on instances does not apply.
    let mut engine = Engine::new(zones, limits, Budget::new(limits)).without_instance_limit();
    let mut inside: BTreeSet<usize> = BTreeSet::new();
    engine.visit(root, range, &mut |occurrence| {
        if occurrence.is_override {
            inside.insert(occurrence.component);
        }
        Ok(Flow::Continue)
    })?;
    let mut output = root.clone();
    output.children = root
        .children
        .iter()
        .enumerate()
        .filter(|(index, child)| !child.is_override() || inside.contains(index))
        .map(|(_, child)| child.clone())
        .collect();
    Ok(output)
}

fn limit_freebusy(root: &mut Node, range: &TimeRange, zones: &Zones) {
    for child in &mut root.children {
        if child.kind != Kind::VFreebusy {
            continue;
        }
        for entry in &mut child.entries {
            if entry.name != Prop::Freebusy {
                continue;
            }
            let tzid = param_text(entry, &Param::Tzid);
            entry.values.retain(|value| {
                let ICalendarValue::Period(period) = value else {
                    return true;
                };
                let (from, until) = match period {
                    calcard::icalendar::ICalendarPeriod::Range { start, end } => (
                        crate::calendar::moment_from_partial(start, false, tzid.as_deref())
                            .and_then(|moment| zones.to_utc(&moment)),
                        crate::calendar::moment_from_partial(end, false, tzid.as_deref())
                            .and_then(|moment| zones.to_utc(&moment)),
                    ),
                    calcard::icalendar::ICalendarPeriod::Duration { start, duration } => {
                        // A period given by its start and its length ends that long after the start.
                        let from = crate::calendar::moment_from_partial(start, false, tzid.as_deref())
                            .and_then(|moment| zones.to_utc(&moment));
                        let length = Length::from_duration(duration);
                        let until = from.and_then(|from| {
                            let days = TimeDelta::try_days(length.days)?;
                            let seconds = TimeDelta::try_seconds(length.seconds)?;
                            from.checked_add_signed(days)?.checked_add_signed(seconds)
                        });
                        (from, until)
                    }
                };
                match (from, until) {
                    (Some(from), Some(until)) => range.overlaps(from, until),
                    _ => true,
                }
            });
        }
        child
            .entries
            .retain(|entry| entry.name != Prop::Freebusy || !entry.values.is_empty());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------------------------------------------

fn select(node: &Node, selection: &ComponentSelection) -> Node {
    let mut output = Node::new(node.kind.clone());
    for entry in &node.entries {
        if selection.all_props {
            output.entries.push(entry.clone());
            continue;
        }
        if let Some(chosen) = selection
            .props
            .iter()
            .find(|prop| entry.name.as_str().eq_ignore_ascii_case(&prop.name))
        {
            let mut kept: ICalendarEntry = entry.clone();
            if chosen.no_value {
                kept.values.clear();
            }
            output.entries.push(kept);
        }
    }
    for child in &node.children {
        if selection.all_comps {
            output.children.push(child.clone());
        } else if let Some(sub) = selection
            .comps
            .iter()
            .find(|comp| child.kind.as_str().eq_ignore_ascii_case(&comp.name))
        {
            output.children.push(select(child, sub));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::parse::parse;

    fn parsed(text: &str) -> ParsedCalendar {
        parse(text.as_bytes(), &IcalLimits::default()).unwrap()
    }

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 3, day, hour, 0, 0).unwrap()
    }

    fn range(from: DateTime<Utc>, until: DateTime<Utc>) -> TimeRange {
        TimeRange::new(Some(from), Some(until))
    }

    const SERIES: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n\
        BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
        BEGIN:VEVENT\r\nUID:s\r\nDTSTAMP:20270101T000000Z\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\n\
        DTEND;TZID=Europe/Berlin:20270301T110000\r\nRRULE:FREQ=DAILY;COUNT=5\r\nEXDATE;TZID=Europe/Berlin:20270303T100000\r\n\
        SUMMARY:Daily\r\nEND:VEVENT\r\n\
        BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID;TZID=Europe/Berlin:20270304T100000\r\nDTSTART;TZID=Europe/Berlin:20270304T150000\r\n\
        DTEND;TZID=Europe/Berlin:20270304T160000\r\nSUMMARY:Moved\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn the_default_projection_is_the_identity() {
        assert!(Projection::default().is_identity());
        let narrowed = Projection {
            select: Some(ComponentSelection::default()),
            ..Projection::default()
        };
        assert!(!narrowed.is_identity());
        let expanding = Projection {
            expand: Some(TimeRange::default()),
            ..Projection::default()
        };
        assert!(!expanding.is_identity());
    }

    #[test]
    fn the_identity_returns_the_whole_calendar() {
        let calendar = parsed(SERIES);
        let text = project(&calendar, &Projection::default(), &IcalLimits::default()).unwrap();
        assert_eq!(text, crate::serialize::serialize(&calendar).unwrap());
    }

    #[test]
    fn expansion_writes_one_component_per_instance_in_utc() {
        let projection = Projection {
            expand: Some(range(at(1, 0), at(10, 0))),
            ..Projection::default()
        };
        let text = project(&parsed(SERIES), &projection, &IcalLimits::default()).unwrap();
        assert_eq!(text.matches("BEGIN:VEVENT").count(), 4, "{text}");
        assert!(
            !text.contains("RRULE") && !text.contains("EXDATE") && !text.contains("BEGIN:VTIMEZONE"),
            "{text}"
        );
        assert!(text.contains("DTSTART:20270301T090000Z\r\n"), "{text}");
        assert!(text.contains("RECURRENCE-ID:20270301T090000Z\r\n"), "{text}");
        assert!(!text.contains("20270303T"), "the excluded instance is gone:\n{text}");
        assert!(
            text.contains("DTSTART:20270304T140000Z\r\n"),
            "the override keeps its own time:\n{text}"
        );
        assert!(text.contains("SUMMARY:Moved"), "{text}");
        let again = parse(text.as_bytes(), &IcalLimits::default());
        assert!(again.is_ok());
    }

    #[test]
    fn expansion_keeps_dates_and_floating_values_and_needs_a_bounded_range() {
        let all_day = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART;VALUE=DATE:20270301\r\nRRULE:FREQ=DAILY;COUNT=2\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let projection = Projection {
            expand: Some(range(at(1, 0), at(10, 0))),
            ..Projection::default()
        };
        let text = project(&parsed(all_day), &projection, &IcalLimits::default()).unwrap();
        assert!(text.contains("DTSTART;VALUE=DATE:20270301\r\n"), "{text}");
        assert!(text.contains("RECURRENCE-ID;VALUE=DATE:20270302\r\n"), "{text}");
        let open = Projection {
            expand: Some(TimeRange::new(Some(at(1, 0)), None)),
            ..Projection::default()
        };
        assert!(project(&parsed(all_day), &open, &IcalLimits::default()).is_err());
    }

    #[test]
    fn expand_and_limit_recurrence_set_exclude_each_other() {
        let both = Projection {
            expand: Some(range(at(1, 0), at(2, 0))),
            limit_recurrence_set: Some(range(at(1, 0), at(2, 0))),
            ..Projection::default()
        };
        assert!(matches!(
            project(&parsed(SERIES), &both, &IcalLimits::default()),
            Err(IcalError::Invalid(_))
        ));
    }

    #[test]
    fn limiting_the_recurrence_set_keeps_the_master_and_overlapping_overrides() {
        let inside = Projection {
            limit_recurrence_set: Some(range(at(4, 0), at(5, 0))),
            ..Projection::default()
        };
        let text = project(&parsed(SERIES), &inside, &IcalLimits::default()).unwrap();
        assert_eq!(text.matches("BEGIN:VEVENT").count(), 2, "{text}");
        let outside = Projection {
            limit_recurrence_set: Some(range(at(1, 0), at(2, 0))),
            ..Projection::default()
        };
        let text = project(&parsed(SERIES), &outside, &IcalLimits::default()).unwrap();
        assert_eq!(text.matches("BEGIN:VEVENT").count(), 1, "{text}");
        assert!(text.contains("RRULE:FREQ=DAILY;COUNT=5"), "{text}");
    }

    #[test]
    fn selection_restricts_components_and_properties() {
        let selection = ComponentSelection {
            name: "VCALENDAR".to_owned(),
            all_props: false,
            props: vec![PropSelection {
                name: "VERSION".to_owned(),
                no_value: false,
            }],
            all_comps: false,
            comps: vec![ComponentSelection {
                name: "vevent".to_owned(),
                all_props: false,
                props: vec![
                    PropSelection {
                        name: "UID".to_owned(),
                        no_value: false,
                    },
                    PropSelection {
                        name: "SUMMARY".to_owned(),
                        no_value: true,
                    },
                ],
                all_comps: false,
                comps: Vec::new(),
            }],
        };
        let projection = Projection {
            select: Some(selection),
            ..Projection::default()
        };
        let text = project(&parsed(SERIES), &projection, &IcalLimits::default()).unwrap();
        assert!(text.contains("VERSION:2.0\r\n") && !text.contains("PRODID"), "{text}");
        assert!(text.contains("UID:s\r\n") && text.contains("SUMMARY:\r\n"), "{text}");
        assert!(!text.contains("DTSTART") && !text.contains("VTIMEZONE"), "{text}");
        let wrong_root = Projection {
            select: Some(ComponentSelection {
                name: "VEVENT".to_owned(),
                ..ComponentSelection::default()
            }),
            ..Projection::default()
        };
        assert!(project(&parsed(SERIES), &wrong_root, &IcalLimits::default()).is_err());
    }

    #[test]
    fn freebusy_periods_are_limited() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VFREEBUSY\r\nUID:f\r\nDTSTART:20270301T000000Z\r\nDTEND:20270310T000000Z\r\n\
            FREEBUSY:20270301T100000Z/20270301T110000Z,20270305T100000Z/20270305T110000Z\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
        let projection = Projection {
            limit_freebusy_set: Some(range(at(5, 0), at(6, 0))),
            ..Projection::default()
        };
        let out = project(&parsed(text), &projection, &IcalLimits::default()).unwrap();
        assert!(out.contains("FREEBUSY:20270305T100000Z/20270305T110000Z\r\n"), "{out}");
        assert!(!out.contains("20270301T100000Z/"), "{out}");
    }

    #[test]
    fn freebusy_periods_given_by_their_length_overlap_by_their_end_too() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VFREEBUSY\r\nUID:f\r\nDTSTART:20270301T000000Z\r\nDTEND:20270310T000000Z\r\n\
            FREEBUSY:20270301T093000Z/PT1H,20270301T120000Z/PT1H,20270301T080000Z/20270301T090000Z\r\n\
            END:VFREEBUSY\r\nEND:VCALENDAR\r\n";
        let projection = Projection {
            limit_freebusy_set: Some(range(at(1, 10), at(1, 11))),
            ..Projection::default()
        };
        let out = project(&parsed(text), &projection, &IcalLimits::default()).unwrap();
        // 09:30 for an hour ends at 10:30 and overlaps 10:00-11:00; the others do not.
        assert!(out.contains("FREEBUSY:20270301T093000Z/PT1H\r\n"), "{out}");
        assert!(
            !out.contains("20270301T120000Z") && !out.contains("20270301T080000Z"),
            "{out}"
        );
    }
}
