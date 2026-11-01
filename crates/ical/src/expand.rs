//! Recurrence expansion with instance and iteration limits.
//!
//! Expansion turns a recurring object (a master component plus overrides) into concrete instances inside a
//! time range. It honors `RRULE`, `RDATE`, `EXDATE`, `RECURRENCE-ID` overrides (an override replaces the
//! generated instance it names) and time zone rules including daylight saving transitions. It is bounded by
//! `max_instances` and `max_iterator_steps`; exceeding either is [`IcalError::Limit`], never an unbounded loop.
//!
//! Wall-clock values are mapped to instants as RFC 5545 section 3.3.5 says: a time that occurs twice is the
//! first occurrence, a time that does not occur uses the offset before the jump. Floating times and all-day
//! dates have no zone of their own: [`expand`] reads them as UTC, [`expand_in_zone`] in the zone you give
//! (CalDAV servers use the calendar's time zone).

use chrono::{DateTime, Utc};
use davhaven_domain::{EventTime, IcalLimits, TimeZoneName};

use crate::error::IcalError;
use crate::filter::TimeRange;
use crate::occurrence::{Budget, Engine, Occurrence};
use crate::parse::ParsedCalendar;
use crate::zones::{Zone, Zones};

/// One concrete occurrence of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// The identity of the instance: the `RECURRENCE-ID` it has or would have.
    pub recurrence_id: EventTime,
    /// The start of the instance in UTC.
    pub start: DateTime<Utc>,
    /// The end of the instance in UTC (equal to `start` for zero-length events).
    pub end: DateTime<Utc>,
    /// Whether the instance comes from an override component instead of the recurrence rule.
    pub is_override: bool,
    /// Whether the instance is an all-day instance.
    pub all_day: bool,
}

/// Expands the recurring components of `calendar` into the instances overlapping `range`, ordered by start and
/// then by recurrence id. A non-recurring object yields its single instance when it overlaps.
///
/// Floating and all-day values are read as UTC; see [`expand_in_zone`].
///
/// # Errors
///
/// * [`IcalError::Invalid`] when the range is open-ended (see [`TimeRange::validate_bounded`]) or the data
///   holds a value that cannot be expanded,
/// * [`IcalError::Limit`] for more than `max_instances` instances, more than `max_iterator_steps` steps, an
///   exceeded time budget or a sub-hourly rule.
pub fn expand(calendar: &ParsedCalendar, range: &TimeRange, limits: &IcalLimits) -> Result<Vec<Instance>, IcalError> {
    expand_in_zone(calendar, range, limits, TimeZoneName::utc())
}

/// Like [`expand`], with floating times and all-day dates read in `floating_zone` (the time zone of the
/// calendar collection).
///
/// # Errors
///
/// As [`expand`].
pub fn expand_in_zone(
    calendar: &ParsedCalendar,
    range: &TimeRange,
    limits: &IcalLimits,
    floating_zone: TimeZoneName,
) -> Result<Vec<Instance>, IcalError> {
    range.validate_bounded(limits)?;
    let zones = Zones::for_tree(&calendar.root, Zone::from_tz(floating_zone.tz()));
    let mut engine = Engine::new(&zones, limits, Budget::new(limits));
    let occurrences = engine.expand(&calendar.root, range)?;
    Ok(occurrences
        .iter()
        .filter(|occurrence| occurrence.is_dated())
        .map(|occurrence| instance_of(occurrence, &zones))
        .collect())
}

fn instance_of(occurrence: &Occurrence, zones: &Zones) -> Instance {
    Instance {
        recurrence_id: occurrence.recurrence_id.to_event_time(zones),
        start: occurrence.effective_start(),
        end: occurrence.effective_end(),
        is_override: occurrence.is_override,
        all_day: occurrence.all_day,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{NaiveDate, TimeZone};

    use super::*;
    use crate::error::LimitKind;
    use crate::parse::parse;

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    fn calendar(body: &str) -> ParsedCalendar {
        let text =
            format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:u\r\n{body}END:VEVENT\r\nEND:VCALENDAR\r\n");
        parse(text.as_bytes(), &IcalLimits::default()).unwrap()
    }

    fn range(start: DateTime<Utc>, end: DateTime<Utc>) -> TimeRange {
        TimeRange::new(Some(start), Some(end))
    }

    #[test]
    fn instances_carry_their_identity_in_the_domain_form() {
        let weekly = calendar(
            "DTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\nRRULE:FREQ=WEEKLY;COUNT=2\r\n",
        );
        let found = expand(
            &weekly,
            &range(at(2027, 1, 1, 0), at(2027, 12, 1, 0)),
            &IcalLimits::default(),
        )
        .unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].start, at(2027, 3, 1, 9));
        assert_eq!(
            found[1].recurrence_id,
            EventTime::Zoned {
                local: NaiveDate::from_ymd_opt(2027, 3, 8)
                    .unwrap()
                    .and_hms_opt(10, 0, 0)
                    .unwrap(),
                zone: TimeZoneName::parse("Europe/Berlin").unwrap(),
            }
        );
        assert!(!found[1].is_override && !found[1].all_day);
    }

    #[test]
    fn open_ended_ranges_are_refused() {
        let single = calendar("DTSTART:20270301T100000Z\r\n");
        let open = TimeRange::new(Some(at(2027, 1, 1, 0)), None);
        assert!(matches!(
            expand(&single, &open, &IcalLimits::default()),
            Err(IcalError::Invalid(_))
        ));
        let long = range(at(2027, 1, 1, 0), at(2040, 1, 1, 0));
        assert_eq!(
            expand(&single, &long, &IcalLimits::default()),
            Err(IcalError::Limit(LimitKind::TimeRange))
        );
    }

    #[test]
    fn floating_values_are_read_in_the_requested_zone() {
        let floating = calendar("DTSTART:20270301T100000\r\nDTEND:20270301T110000\r\n");
        let window = range(at(2027, 2, 28, 0), at(2027, 3, 3, 0));
        let utc = expand(&floating, &window, &IcalLimits::default()).unwrap();
        assert_eq!(utc[0].start, at(2027, 3, 1, 10));
        let berlin = expand_in_zone(
            &floating,
            &window,
            &IcalLimits::default(),
            TimeZoneName::parse("Europe/Berlin").unwrap(),
        )
        .unwrap();
        assert_eq!(berlin[0].start, at(2027, 3, 1, 9));
    }

    #[test]
    fn nothing_matches_outside_the_range() {
        let single = calendar("DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n");
        let found = expand(
            &single,
            &range(at(2027, 4, 1, 0), at(2027, 4, 2, 0)),
            &IcalLimits::default(),
        )
        .unwrap();
        assert_eq!(found.len(), 0);
    }
}
