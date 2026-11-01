//! The read paths of the crate: matching and free-busy over long series, the budgets of one call, the index as a
//! pre-filter that never misses, and the pairing of overrides with the instances they replace.
//!
//! `PROPTEST_CASES` raises the number of cases; failing cases are kept in `reads.proptest-regressions`.

#![expect(
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-panic-in-tests"
)]

use chrono::{DateTime, Duration, TimeZone, Utc};
use davhaven_domain::{IcalLimits, TimeZoneName};
use davhaven_ical::expand::{expand, expand_in_zone};
use davhaven_ical::filter::{CalendarFilter, CompFilter, TimeRange, matches};
use davhaven_ical::freebusy::busy_periods;
use davhaven_ical::index::index;
use davhaven_ical::parse::{ParsedCalendar, parse};
use davhaven_ical::projection::{Projection, project};
use davhaven_ical::validate::parse_and_validate;
use davhaven_ical::{IcalError, LimitKind};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

fn limits() -> IcalLimits {
    IcalLimits::default()
}

fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
}

fn object(kind: &str, body: &str) -> ParsedCalendar {
    let text = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:{kind}\r\nUID:reads\r\nDTSTAMP:20270101T000000Z\r\n{body}END:{kind}\r\nEND:VCALENDAR\r\n"
    );
    parse_and_validate(text.as_bytes(), &limits())
        .unwrap_or_else(|error| panic!("{kind} {body:?}: {error}"))
        .calendar
}

fn filter(component: &str, range: TimeRange) -> CalendarFilter {
    CalendarFilter {
        root: CompFilter {
            name: "VCALENDAR".to_owned(),
            is_not_defined: false,
            time_range: None,
            prop_filters: Vec::new(),
            comp_filters: vec![CompFilter {
                name: component.to_owned(),
                is_not_defined: false,
                time_range: Some(range),
                prop_filters: Vec::new(),
                comp_filters: Vec::new(),
            }],
        },
    }
}

// ---------------------------------------------------------------------------------------------------------------
// A long series is no reason to fail a query
// ---------------------------------------------------------------------------------------------------------------

const DAILY: &str = "DTSTART:20270101T100000Z\r\nDTEND:20270101T110000Z\r\nRRULE:FREQ=DAILY\r\n";

#[test]
fn matching_does_not_count_instances() {
    let calendar = object("VEVENT", DAILY);
    // Ten years of a daily series are 3 653 instances, more than `max_instances`.
    let decade = TimeRange::new(Some(at(2027, 1, 1, 0)), Some(at(2037, 1, 1, 0)));
    assert!(matches(&calendar, &filter("VEVENT", decade), &limits()).unwrap());
    // An open-ended range reaches ten years from its start.
    let open = TimeRange::new(Some(at(2027, 1, 1, 0)), None);
    assert!(matches(&calendar, &filter("VEVENT", open), &limits()).unwrap());
    let from_the_end = TimeRange::new(None, Some(at(2040, 1, 1, 0)));
    assert!(matches(&calendar, &filter("VEVENT", from_the_end), &limits()).unwrap());
    // A range without instances is still a no.
    let before = TimeRange::new(Some(at(2020, 1, 1, 0)), Some(at(2021, 1, 1, 0)));
    assert!(!matches(&calendar, &filter("VEVENT", before), &limits()).unwrap());
    // Returning the instances is another matter: that is what `max_instances` caps.
    assert_eq!(
        expand(&calendar, &decade, &limits()).unwrap_err(),
        IcalError::Limit(LimitKind::Instances)
    );
}

#[test]
fn matching_an_alarm_of_a_long_series_does_not_count_instances() {
    let calendar = object(
        "VEVENT",
        "DTSTART:20270101T100000Z\r\nDTEND:20270101T110000Z\r\nRRULE:FREQ=DAILY\r\n\
         BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\n",
    );
    let decade = TimeRange::new(Some(at(2027, 1, 1, 0)), Some(at(2037, 1, 1, 0)));
    let mut with_alarm = filter("VEVENT", decade);
    with_alarm.root.comp_filters[0].comp_filters.push(CompFilter {
        name: "VALARM".to_owned(),
        is_not_defined: false,
        time_range: Some(decade),
        prop_filters: Vec::new(),
        comp_filters: Vec::new(),
    });
    assert!(matches(&calendar, &with_alarm, &limits()).unwrap());
}

#[test]
fn free_busy_merges_a_long_series() {
    let calendar = object("VEVENT", DAILY);
    let decade = TimeRange::new(Some(at(2027, 1, 1, 0)), Some(at(2037, 1, 1, 0)));
    let busy = busy_periods(&[&calendar], &decade, &limits()).unwrap();
    assert_eq!(busy.len(), 3653);
    // A range that long still has to be a valid free-busy request.
    let too_long = TimeRange::new(Some(at(2027, 1, 1, 0)), Some(at(2040, 1, 1, 0)));
    assert_eq!(
        busy_periods(&[&calendar], &too_long, &limits()).unwrap_err(),
        IcalError::Limit(LimitKind::TimeRange)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// One budget per call
// ---------------------------------------------------------------------------------------------------------------

fn counted(days: u32) -> ParsedCalendar {
    object(
        "VEVENT",
        &format!("DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT={days}\r\n"),
    )
}

#[test]
fn free_busy_over_many_objects_shares_one_step_budget() {
    let calendars: Vec<ParsedCalendar> = (0..3).map(|_| counted(5)).collect();
    let refs: Vec<&ParsedCalendar> = calendars.iter().collect();
    let range = TimeRange::new(Some(at(2027, 3, 1, 0)), Some(at(2027, 4, 1, 0)));
    // Five steps for each object: two fit in twelve, three do not.
    let tight = IcalLimits {
        max_iterator_steps: 12,
        ..IcalLimits::default()
    };
    assert!(busy_periods(&refs[..2], &range, &tight).is_ok());
    assert_eq!(
        busy_periods(&refs, &range, &tight).unwrap_err(),
        IcalError::Limit(LimitKind::IteratorSteps)
    );
    assert_eq!(busy_periods(&refs, &range, &limits()).unwrap().len(), 5);
}

#[test]
fn every_read_path_reports_the_time_budget_as_a_transient_limit() {
    let calendar = counted(5);
    let none = IcalLimits {
        time_budget_ms: 0,
        ..IcalLimits::default()
    };
    let range = TimeRange::new(Some(at(2027, 3, 1, 0)), Some(at(2027, 4, 1, 0)));
    let transient = IcalError::Limit(LimitKind::TimeBudget);
    assert_eq!(expand(&calendar, &range, &none).unwrap_err(), transient);
    assert_eq!(busy_periods(&[&calendar], &range, &none).unwrap_err(), transient);
    assert_eq!(
        matches(&calendar, &filter("VEVENT", range), &none).unwrap_err(),
        transient
    );
    let projection = Projection {
        expand: Some(range),
        ..Projection::default()
    };
    assert_eq!(project(&calendar, &projection, &none).unwrap_err(), transient);
    let text = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    assert_eq!(parse(text.as_bytes(), &none).unwrap_err(), transient);
    // Every one of them maps to a retryable answer, never to one about the data.
    assert!(transient.is_transient());
}

// ---------------------------------------------------------------------------------------------------------------
// Overrides replace exactly the instance they name
// ---------------------------------------------------------------------------------------------------------------

fn series_with_override(rid: &str, start: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
         BEGIN:VEVENT\r\nUID:reads\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\n\
         RRULE:FREQ=DAILY;COUNT=3\r\nEND:VEVENT\r\n\
         BEGIN:VEVENT\r\nUID:reads\r\nRECURRENCE-ID{rid}\r\nDTSTART{start}\r\nDTEND{start}\r\nSUMMARY:moved\r\nEND:VEVENT\r\n\
         END:VCALENDAR\r\n"
    )
}

#[test]
fn an_override_written_in_another_zone_pairs_with_its_instance_by_instant() {
    let range = TimeRange::new(Some(at(2027, 2, 28, 0)), Some(at(2027, 3, 10, 0)));
    // The second instance is 10:00 in Berlin, 09:00 UTC and 04:00 in New York.
    for rid in [
        ":20270302T090000Z",
        ";TZID=America/New_York:20270302T040000",
        ";TZID=Europe/Berlin:20270302T100000",
    ] {
        let text =
            series_with_override(rid, ":20270302T150000Z").replace("DTEND:20270302T150000Z", "DTEND:20270302T160000Z");
        let calendar = parse_and_validate(text.as_bytes(), &limits()).unwrap().calendar;
        let found = expand(&calendar, &range, &limits()).unwrap();
        let shape: Vec<(DateTime<Utc>, bool)> = found.iter().map(|i| (i.start, i.is_override)).collect();
        assert_eq!(
            shape,
            vec![
                (at(2027, 3, 1, 9), false),
                (at(2027, 3, 2, 15), true),
                (at(2027, 3, 3, 9), false)
            ],
            "{rid}"
        );
    }
}

#[test]
fn an_override_of_an_all_day_series_pairs_by_date() {
    let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
        BEGIN:VEVENT\r\nUID:reads\r\nDTSTART;VALUE=DATE:20270301\r\nRRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:day\r\nEND:VEVENT\r\n\
        BEGIN:VEVENT\r\nUID:reads\r\nRECURRENCE-ID;VALUE=DATE:20270302\r\nDTSTART;VALUE=DATE:20270302\r\nDTEND;VALUE=DATE:20270304\r\n\
        SUMMARY:longer\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let calendar = parse_and_validate(text.as_bytes(), &limits()).unwrap().calendar;
    let range = TimeRange::new(Some(at(2027, 2, 28, 0)), Some(at(2027, 3, 10, 0)));
    let berlin = TimeZoneName::parse("Europe/Berlin").unwrap();
    let found = expand_in_zone(&calendar, &range, &limits(), berlin).unwrap();
    let shape: Vec<(bool, bool)> = found.iter().map(|i| (i.is_override, i.all_day)).collect();
    assert_eq!(shape, vec![(false, true), (true, true), (false, true)]);
    // The override lasts two days, the others one.
    assert_eq!(found[1].end - found[1].start, Duration::days(2));
    assert_eq!(found[0].end - found[0].start, Duration::days(1));
}

// ---------------------------------------------------------------------------------------------------------------
// The index never misses what a query matches
// ---------------------------------------------------------------------------------------------------------------

fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    }
}

/// An hour on the day of the tests, `0..=23`, as the iCalendar value of a UTC date-time.
fn stamp(hour: i64) -> String {
    (at(2027, 3, 1, 0) + Duration::hours(hour))
        .format("%Y%m%dT%H%M%SZ")
        .to_string()
}

/// The rows of RFC 4791 section 9.9 for events and to-dos: the kind and the body of the component.
fn shapes(a: i64, b: i64) -> Vec<(&'static str, String)> {
    let (first, second) = (a.min(b), a.max(b));
    vec![
        (
            "VEVENT",
            format!("DTSTART:{}\r\nDTEND:{}\r\n", stamp(first), stamp(second)),
        ),
        (
            "VEVENT",
            format!("DTSTART:{}\r\nDURATION:PT{}H\r\n", stamp(first), second - first),
        ),
        ("VEVENT", format!("DTSTART:{}\r\n", stamp(first))),
        ("VJOURNAL", format!("DTSTART:{}\r\n", stamp(first))),
        (
            "VTODO",
            format!("DTSTART:{}\r\nDUE:{}\r\n", stamp(first), stamp(second)),
        ),
        (
            "VTODO",
            format!("DTSTART:{}\r\nDURATION:PT{}H\r\n", stamp(first), second - first),
        ),
        ("VTODO", format!("DTSTART:{}\r\n", stamp(first))),
        ("VTODO", format!("DUE:{}\r\n", stamp(first))),
        ("VTODO", format!("COMPLETED:{}\r\n", stamp(first))),
        ("VTODO", format!("CREATED:{}\r\n", stamp(first))),
        (
            "VTODO",
            format!("CREATED:{}\r\nCOMPLETED:{}\r\n", stamp(first), stamp(second)),
        ),
        ("VEVENT", "DTSTART;VALUE=DATE:20270301\r\n".to_owned()),
    ]
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn what_time_range_matches_is_in_the_index(a in 0..8_i64, b in 0..8_i64, from in 0..10_i64, span in 1..6_i64) {
        let range = TimeRange::new(
            Some(at(2027, 3, 1, 0) + Duration::hours(from)),
            Some(at(2027, 3, 1, 0) + Duration::hours(from + span)),
        );
        for (kind, body) in shapes(a, b) {
            let validated = {
                let text = format!(
                    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:{kind}\r\nUID:reads\r\nDTSTAMP:20270101T000000Z\r\n{body}END:{kind}\r\nEND:VCALENDAR\r\n"
                );
                parse_and_validate(text.as_bytes(), &limits()).unwrap()
            };
            let exact = matches(&validated.calendar, &filter(kind, range), &limits()).unwrap();
            let indexed = index(&validated, &limits()).unwrap();
            prop_assert!(
                !exact || indexed.may_overlap(range.start, range.end),
                "{kind} {body:?} matches [{from}, {}) but the index {:?} does not",
                from + span,
                (indexed.first_start, indexed.last_end)
            );
            // The same for the open ends of a range.
            let from_here = TimeRange::new(range.start, None);
            let exact = matches(&validated.calendar, &filter(kind, from_here), &limits()).unwrap();
            prop_assert!(!exact || indexed.may_overlap(from_here.start, from_here.end), "{kind} {body:?}");
            let until_there = TimeRange::new(None, range.end);
            let exact = matches(&validated.calendar, &filter(kind, until_there), &limits()).unwrap();
            prop_assert!(!exact || indexed.may_overlap(until_there.start, until_there.end), "{kind} {body:?}");
        }
    }
}
