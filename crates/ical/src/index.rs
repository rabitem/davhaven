//! Extraction of the `ObjectIndex` from a calendar object.
//!
//! The index feeds the store's pre-filter, so it must be a superset filter: it may report objects that exact
//! evaluation rejects but must never miss one (PLAN 2.7). `first_start` is the start of the earliest instance
//! and `last_end` the end of the latest one (`None` for infinite recurrences and undated components).
//!
//! * Floating times are converted to UTC and padded by [`davhaven_domain::index::FLOATING_PADDING_HOURS`] on
//!   both sides because their real offset is unknown.
//! * Both bounds are widened by one second. RFC 4791 section 9.9 has inclusive comparisons (an event without an
//!   end matches a range that starts exactly at its start, a to-do with only a `DUE` matches a range that ends
//!   exactly at it, ...) while the pre-filter excludes the range end (`first_start < end`) and an implementation
//!   of it may be strict at the other side as well; one second is the smallest step the values have, so the
//!   widened interval is a superset at every boundary whichever way the pre-filter treats it.
//! * A to-do whose only date is `CREATED` matches every range that ends after it, however late: it has no
//!   `last_end`.
//! * The recurrence rules of every series are evaluated up to the latest date the server accepts, bounded or not,
//!   within the step budget. A rule that needs more steps (every hourly rule that never ends) is refused when the
//!   object is stored with [`crate::LimitKind::IteratorSteps`], so that no stored object can make a later read
//!   fail.

use std::collections::HashSet;

use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::index::FLOATING_PADDING_HOURS;
use davhaven_domain::{AttendeeRef, CalendarUserAddress, Classification, IcalLimits, ObjectIndex, Transparency};

use crate::calendar::{
    Kind, Moment, Node, Param, Prop, address_of, cutype_of, entry_moment, entry_moments, entry_periods, param_text,
    partstat_of, role_of, schedule_agent_of,
};
use crate::error::IcalError;
use crate::filter::TimeRange;
use crate::occurrence::{Budget, Engine, Flow, start_moment};
use crate::recur::is_unbounded;
use crate::validate::ValidatedObject;
use crate::zones::{Zone, Zones};

/// The first start and the last end of an object.
type Bounds = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// Extracts the index columns of a validated object.
///
/// # Errors
///
/// * [`IcalError::Limit`] with [`crate::LimitKind::IteratorSteps`] when a recurrence rule needs more than
///   `max_iterator_steps` steps to reach the latest accepted date, and with [`crate::LimitKind::TimeBudget`]
///   when the work takes longer than the time budget,
/// * [`IcalError::Invalid`] when a date of the object cannot be evaluated.
pub fn index(object: &ValidatedObject, limits: &IcalLimits) -> Result<ObjectIndex, IcalError> {
    let root = &object.calendar.root;
    let zones = Zones::for_tree(root, Zone::utc());
    let components: Vec<&Node> = root
        .children
        .iter()
        .filter(|node| node.component_kind().is_some())
        .collect();
    let master = components
        .iter()
        .find(|node| !node.is_override())
        .or_else(|| components.first())
        .copied();
    let (first_start, last_end) = bounds(root, &components, &zones, limits)?;
    let organizer = components
        .iter()
        .find_map(|node| node.first(&Prop::Organizer).and_then(address_of));
    let attendees = attendees_of(&components);
    let is_recurring = components
        .iter()
        .any(|node| node.has(&Prop::Rrule) || node.has(&Prop::Rdate));
    let sequence = master
        .and_then(|node| node.integer(&Prop::Sequence))
        .map_or(0, |value| i32::try_from(value).unwrap_or(i32::MAX).max(0));
    let class = master
        .and_then(|node| node.text(&Prop::Class))
        .and_then(|text| Classification::from_ical(&text))
        .unwrap_or_default();
    let transp = master
        .and_then(|node| node.text(&Prop::Transp))
        .and_then(|text| Transparency::from_ical(&text))
        .unwrap_or_default();
    Ok(ObjectIndex {
        uid: object.uid.clone(),
        component: object.component,
        first_start,
        last_end,
        is_recurring,
        is_scheduling: organizer.is_some() && !attendees.is_empty(),
        organizer,
        attendees,
        sequence,
        class,
        transp,
    })
}

/// The attendees of all components, one entry per address (the first occurrence wins).
fn attendees_of(components: &[&Node]) -> Vec<AttendeeRef> {
    let mut seen: HashSet<CalendarUserAddress> = HashSet::new();
    let mut found: Vec<AttendeeRef> = Vec::new();
    for node in components {
        for entry in node.all(&Prop::Attendee) {
            let Some(address) = address_of(entry) else {
                continue;
            };
            if !seen.insert(address.clone()) {
                continue;
            }
            found.push(AttendeeRef {
                address,
                common_name: param_text(entry, &Param::Cn),
                partstat: partstat_of(entry),
                cutype: cutype_of(entry),
                role: role_of(entry),
                schedule_agent: schedule_agent_of(entry),
            });
        }
    }
    found
}

/// The padded instant of a moment: floating values and dates get the zone-offset padding.
fn padded(zones: &Zones, moment: &Moment, later: bool) -> Option<DateTime<Utc>> {
    let instant = zones.to_utc(moment)?;
    let floating = matches!(moment, Moment::Date(_) | Moment::Floating(_));
    if !floating {
        return Some(instant);
    }
    let padding = TimeDelta::try_hours(FLOATING_PADDING_HOURS)?;
    if later {
        instant.checked_add_signed(padding)
    } else {
        instant.checked_sub_signed(padding)
    }
}

/// Every date the components state themselves: starts, due dates, recurrence dates and recurrence ids.
fn stated_moments(node: &Node) -> Result<Vec<Moment>, IcalError> {
    let mut moments: Vec<Moment> = Vec::new();
    moments.extend(start_moment(node)?);
    let todo = node.kind == Kind::VTodo;
    for property in [
        Prop::Dtend,
        Prop::Due,
        Prop::Completed,
        Prop::Created,
        Prop::RecurrenceId,
    ] {
        // `COMPLETED` and `CREATED` date a to-do (RFC 4791 section 9.9); on other components they are stamps.
        if matches!(property, Prop::Completed | Prop::Created) && !todo {
            continue;
        }
        if let Some(moment) = node.first(&property).and_then(entry_moment) {
            moments.push(moment);
        }
    }
    for entry in node.all(&Prop::Rdate) {
        moments.extend(entry_moments(entry).0);
        for period in entry_periods(entry) {
            moments.push(period.start);
            if let crate::calendar::PeriodEnd::At(end) = period.end {
                moments.push(end);
            }
        }
    }
    Ok(moments)
}

/// Whether the component is a to-do that only `CREATED` dates: RFC 4791 section 9.9 matches it with every range
/// that ends after `CREATED`.
fn is_created_only_todo(node: &Node) -> bool {
    node.kind == Kind::VTodo
        && node.has(&Prop::Created)
        && !node.has(&Prop::Dtstart)
        && !node.has(&Prop::Due)
        && !node.has(&Prop::Completed)
}

/// One second, the margin that makes the strict pre-filter a superset of the inclusive rows of RFC 4791 9.9.
fn one_second() -> TimeDelta {
    TimeDelta::seconds(1)
}

fn bounds(root: &Node, components: &[&Node], zones: &Zones, limits: &IcalLimits) -> Result<Bounds, IcalError> {
    let mut stated = Vec::new();
    for node in components {
        stated.extend(stated_moments(node)?);
    }
    let first = stated.iter().filter_map(|moment| padded(zones, moment, false)).min();
    if first.is_none() {
        return Ok((None, None));
    }
    let unbounded = components.iter().any(|node| {
        node.first(&Prop::Rrule)
            .and_then(|entry| entry.values.first())
            .is_some_and(
                |value| matches!(value, calcard::icalendar::ICalendarValue::RecurrenceRule(rule) if is_unbounded(rule)),
            )
    }) || components.iter().any(|node| is_created_only_todo(node));
    let mut last = stated.iter().filter_map(|moment| padded(zones, moment, true)).max();
    // Every series is evaluated up to the latest accepted date, so that a rule that cannot be evaluated within
    // the step budget is refused now; the instances of a series that ends also give the end of the object.
    let range = TimeRange::new(None, limits.max_date_time());
    let mut engine = Engine::new(zones, limits, Budget::new(limits)).without_instance_limit();
    engine.visit(root, &range, &mut |occurrence| {
        let end = if occurrence.floating {
            occurrence
                .end
                .checked_add_signed(TimeDelta::try_hours(FLOATING_PADDING_HOURS).unwrap_or_default())
                .unwrap_or(occurrence.end)
        } else {
            occurrence.end
        };
        last = Some(last.map_or(end, |current| current.max(end)));
        Ok(Flow::Continue)
    })?;
    let first = first.and_then(|at| at.checked_sub_signed(one_second()));
    let last = if unbounded {
        None
    } else {
        last.and_then(|at| at.checked_add_signed(one_second()))
    };
    Ok((first, last))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use chrono::TimeZone;
    use davhaven_domain::{CalendarUserAddress, ComponentKind};

    use super::*;
    use crate::error::LimitKind;
    use crate::validate::parse_and_validate;

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    /// The index is widened by one second on both sides (see the module documentation).
    fn lo(instant: DateTime<Utc>) -> DateTime<Utc> {
        instant - TimeDelta::seconds(1)
    }

    fn hi(instant: DateTime<Utc>) -> DateTime<Utc> {
        instant + TimeDelta::seconds(1)
    }

    fn indexed(body: &str) -> ObjectIndex {
        let text = format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:idx\r\n{body}END:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        let limits = IcalLimits::default();
        let object = parse_and_validate(text.as_bytes(), &limits).unwrap();
        index(&object, &limits).unwrap()
    }

    #[test]
    fn a_plain_event_is_bounded_by_its_own_times() {
        let found = indexed(
            "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nSEQUENCE:3\r\nCLASS:PRIVATE\r\nTRANSP:TRANSPARENT\r\n",
        );
        assert_eq!(found.uid.as_str(), "idx");
        assert_eq!(found.component, ComponentKind::Event);
        assert_eq!(found.first_start, Some(lo(at(2027, 3, 1, 10))));
        assert_eq!(found.last_end, Some(hi(at(2027, 3, 1, 11))));
        assert!(!found.is_recurring && !found.is_scheduling);
        assert_eq!(found.sequence, 3);
        assert_eq!(found.class, Classification::Private);
        assert_eq!(found.transp, Transparency::Transparent);
    }

    #[test]
    fn zoned_times_become_utc() {
        let found =
            indexed("DTSTART;TZID=America/New_York:20270301T100000\r\nDTEND;TZID=America/New_York:20270301T110000\r\n");
        assert_eq!(found.first_start, Some(lo(at(2027, 3, 1, 15))));
        assert_eq!(found.last_end, Some(hi(at(2027, 3, 1, 16))));
    }

    #[test]
    fn floating_times_and_dates_are_padded() {
        let floating = indexed("DTSTART:20270301T100000\r\nDTEND:20270301T110000\r\n");
        assert_eq!(floating.first_start, Some(lo(at(2027, 2, 28, 20))));
        assert_eq!(floating.last_end, Some(hi(at(2027, 3, 2, 1))));
        let all_day = indexed("DTSTART;VALUE=DATE:20270301\r\n");
        assert_eq!(all_day.first_start, Some(lo(at(2027, 2, 28, 10))));
        assert_eq!(all_day.last_end, Some(hi(at(2027, 3, 2, 14))));
    }

    #[test]
    fn infinite_recurrences_have_no_last_end() {
        let found = indexed("DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=WEEKLY\r\n");
        assert_eq!(found.first_start, Some(lo(at(2027, 3, 1, 10))));
        assert_eq!(found.last_end, None);
        assert!(found.is_recurring);
    }

    #[test]
    fn counted_and_bounded_recurrences_end_with_their_last_instance() {
        let counted = indexed("DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=WEEKLY;COUNT=3\r\n");
        assert_eq!(counted.last_end, Some(hi(at(2027, 3, 15, 11))));
        let until = indexed(
            "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;UNTIL=20270305T100000Z\r\n",
        );
        assert_eq!(until.last_end, Some(hi(at(2027, 3, 5, 11))));
        let long = indexed("DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT=5000\r\n");
        let last_start = chrono::NaiveDate::from_ymd_opt(2027, 3, 1).unwrap() + chrono::Days::new(4999);
        assert_eq!(
            long.last_end,
            Some(hi(last_start.and_hms_opt(11, 0, 0).unwrap().and_utc()))
        );
    }

    #[test]
    fn rdates_and_overrides_extend_the_bounds() {
        let found = indexed(
            "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRDATE:20270401T100000Z\r\nEXDATE:20270101T100000Z\r\n",
        );
        assert_eq!(found.first_start, Some(lo(at(2027, 3, 1, 10))));
        assert_eq!(found.last_end, Some(hi(at(2027, 4, 1, 11))));
    }

    #[test]
    fn undated_events_have_no_bounds() {
        let found = indexed("SUMMARY:No start\r\n");
        assert_eq!((found.first_start, found.last_end), (None, None));
    }

    #[test]
    fn scheduling_objects_list_organizer_and_attendees_once() {
        let found = indexed(
            "DTSTART:20270301T100000Z\r\nORGANIZER;CN=Anna:mailto:Anna@Example.org\r\n\
             ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;ROLE=CHAIR:mailto:bob@example.org\r\n\
             ATTENDEE;CUTYPE=ROOM:mailto:room@example.org\r\nATTENDEE:mailto:BOB@example.org\r\n",
        );
        assert!(found.is_scheduling);
        assert_eq!(
            found.organizer.as_ref().map(CalendarUserAddress::as_str),
            Some("mailto:anna@example.org")
        );
        assert_eq!(found.attendees.len(), 2);
        let bob = found.attendees.first().unwrap();
        assert_eq!(bob.common_name.as_deref(), Some("Bob"));
        assert_eq!(bob.partstat, calendar_partstat());
        assert_eq!(found.attendees.get(1).unwrap().cutype, davhaven_domain::CuType::Room);
    }

    fn calendar_partstat() -> davhaven_domain::PartStat {
        davhaven_domain::PartStat::Accepted
    }

    #[test]
    fn organizers_without_attendees_are_not_scheduling() {
        let found = indexed("DTSTART:20270301T100000Z\r\nORGANIZER:mailto:anna@example.org\r\n");
        assert!(!found.is_scheduling);
        assert!(found.organizer.is_some());
    }

    fn try_index(text: &str, limits: &IcalLimits) -> Result<ObjectIndex, IcalError> {
        let object = parse_and_validate(text.as_bytes(), limits).unwrap();
        index(&object, limits)
    }

    fn wrapped(kind: &str, body: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:{kind}\r\nUID:idx\r\n{body}END:{kind}\r\nEND:VCALENDAR\r\n")
    }

    #[test]
    fn the_bounds_include_the_inclusive_rows_of_the_rfc() {
        let start = at(2027, 3, 1, 10);
        // An event without an end matches a range that starts exactly at its start (start <= DTSTART).
        let instant = indexed("DTSTART:20270301T100000Z\r\n");
        assert!(instant.may_overlap(Some(start), Some(start + TimeDelta::hours(1))));
        // A to-do with only a DUE matches a range that ends exactly at it (end >= DUE).
        let due = try_index(&wrapped("VTODO", "DUE:20270301T100000Z\r\n"), &IcalLimits::default()).unwrap();
        assert!(due.may_overlap(Some(start - TimeDelta::hours(1)), Some(start)));
        // COMPLETED matches on both edges.
        let completed = try_index(
            &wrapped("VTODO", "COMPLETED:20270301T100000Z\r\n"),
            &IcalLimits::default(),
        )
        .unwrap();
        assert!(completed.may_overlap(Some(start), Some(start + TimeDelta::hours(1))));
        assert!(completed.may_overlap(Some(start - TimeDelta::hours(1)), Some(start)));
        // Still a filter: ranges that are clearly apart do not overlap.
        assert!(!instant.may_overlap(Some(start + TimeDelta::hours(1)), None));
        assert!(!instant.may_overlap(None, Some(start - TimeDelta::hours(1))));
    }

    #[test]
    fn a_to_do_dated_only_by_creation_matches_every_later_range() {
        let todo = try_index(
            &wrapped("VTODO", "CREATED:20270301T080000Z\r\n"),
            &IcalLimits::default(),
        )
        .unwrap();
        assert_eq!(todo.first_start, Some(lo(at(2027, 3, 1, 8))));
        assert_eq!(
            todo.last_end, None,
            "RFC 4791 section 9.9: (end > CREATED), however late the range is"
        );
        assert!(todo.may_overlap(Some(at(2035, 1, 1, 0)), Some(at(2035, 2, 1, 0))));
        // With another date the interval is bounded again.
        let due = try_index(
            &wrapped("VTODO", "CREATED:20270301T080000Z\r\nDUE:20270302T080000Z\r\n"),
            &IcalLimits::default(),
        )
        .unwrap();
        assert_eq!(due.last_end, Some(hi(at(2027, 3, 2, 8))));
    }

    #[test]
    fn rules_that_cannot_be_evaluated_within_the_step_budget_are_refused_when_stored() {
        let limits = IcalLimits::default();
        // An hourly rule that never ends needs hundreds of thousands of steps to reach the year 2100.
        for start in ["20270301T100000Z", "20100101T000000Z", "19000101T000000Z"] {
            let text = wrapped("VEVENT", &format!("DTSTART:{start}\r\nRRULE:FREQ=HOURLY\r\n"));
            assert_eq!(
                try_index(&text, &limits),
                Err(IcalError::Limit(LimitKind::IteratorSteps)),
                "{start}"
            );
        }
        // Daily rules from 1900 to 2100 fit, a bounded hourly rule fits as well.
        let daily = wrapped("VEVENT", "DTSTART:19000101T000000Z\r\nRRULE:FREQ=DAILY\r\n");
        assert_eq!(try_index(&daily, &limits).unwrap().last_end, None);
        let bounded = wrapped("VEVENT", "DTSTART:19000101T000000Z\r\nRRULE:FREQ=HOURLY;COUNT=1000\r\n");
        assert!(try_index(&bounded, &limits).unwrap().last_end.is_some());
        // The budget is the configured one.
        let tight = IcalLimits {
            max_iterator_steps: 1_000,
            ..IcalLimits::default()
        };
        let daily_open = wrapped("VEVENT", "DTSTART:20270301T100000Z\r\nRRULE:FREQ=DAILY\r\n");
        assert_eq!(
            try_index(&daily_open, &tight),
            Err(IcalError::Limit(LimitKind::IteratorSteps))
        );
    }

    #[test]
    fn running_out_of_time_is_reported_as_the_transient_limit() {
        let none = IcalLimits {
            time_budget_ms: 0,
            ..IcalLimits::default()
        };
        let text = wrapped("VEVENT", "DTSTART:20270301T100000Z\r\n");
        let object = parse_and_validate(text.as_bytes(), &IcalLimits::default()).unwrap();
        assert_eq!(index(&object, &none), Err(IcalError::Limit(LimitKind::TimeBudget)));
    }

    #[test]
    fn many_attendees_across_components_are_listed_once_each() {
        let mut body = String::from("DTSTART:20270301T100000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\n");
        for n in 0..150 {
            let _ = write!(body, "ATTENDEE:mailto:g{n}@example.org\r\n");
        }
        let mut text = wrapped("VEVENT", &body);
        let mut override_part =
            String::from("BEGIN:VEVENT\r\nUID:idx\r\nRECURRENCE-ID:20270302T100000Z\r\nDTSTART:20270302T110000Z\r\n");
        for n in 50..200 {
            let _ = write!(override_part, "ATTENDEE:mailto:g{n}@example.org\r\n");
        }
        override_part.push_str("END:VEVENT\r\n");
        text = text.replace("END:VCALENDAR\r\n", &format!("{override_part}END:VCALENDAR\r\n"));
        let found = try_index(&text, &IcalLimits::default()).unwrap();
        assert_eq!(found.attendees.len(), 200);
    }
}
