//! The time-range tables of RFC 4791 section 9.9 as test vectors, evaluated through `calendar-query` filters
//! (`filter::matches`), through `expand` and through the free-busy computation.
//!
//! The expectations are written out by hand from the conditions of the RFC; they do not come from the code under
//! test. All instants are on 2027-03-01 in UTC; `h(10)` is 10:00.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use chrono::{DateTime, TimeZone, Utc};
use davhaven_domain::IcalLimits;
use davhaven_ical::expand::expand;
use davhaven_ical::filter::{CalendarFilter, CompFilter, TimeRange, matches};
use davhaven_ical::parse::ParsedCalendar;
use davhaven_ical::validate::parse_and_validate;

fn h(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap() + chrono::Duration::hours(i64::from(hour))
}

fn object(kind: &str, body: &str) -> ParsedCalendar {
    let text = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:{kind}\r\nUID:vector\r\nDTSTAMP:20270101T000000Z\r\n{body}END:{kind}\r\nEND:VCALENDAR\r\n"
    );
    parse_and_validate(text.as_bytes(), &IcalLimits::default())
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

fn hit(calendar: &ParsedCalendar, component: &str, start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> bool {
    matches(
        calendar,
        &filter(component, TimeRange::new(start, end)),
        &IcalLimits::default(),
    )
    .unwrap()
}

/// A table row: the range `[start, end)` in hours and whether the object matches it.
type Vector = (u32, u32, bool);

fn check(kind: &str, body: &str, vectors: &[Vector]) {
    let calendar = object(kind, body);
    for &(start, end, expected) in vectors {
        assert_eq!(
            hit(&calendar, kind, Some(h(start)), Some(h(end))),
            expected,
            "{kind} {body:?} against [{start}:00, {end}:00)"
        );
    }
}

#[test]
fn vevent_with_dtend() {
    // (start < DTEND AND end > DTSTART): the event spans [10:00, 12:00).
    check(
        "VEVENT",
        "DTSTART:20270301T100000Z\r\nDTEND:20270301T120000Z\r\n",
        &[
            (9, 10, false),
            (9, 11, true),
            (10, 12, true),
            (11, 13, true),
            (12, 13, false),
            (8, 14, true),
            (10, 11, true),
            (11, 12, true),
            (1, 2, false),
            (23, 24, false),
        ],
    );
}

#[test]
fn vevent_with_a_positive_duration() {
    // (start < DTSTART+DURATION AND end > DTSTART).
    check(
        "VEVENT",
        "DTSTART:20270301T100000Z\r\nDURATION:PT2H\r\n",
        &[(9, 10, false), (9, 11, true), (11, 13, true), (12, 13, false)],
    );
}

#[test]
fn vevent_with_a_zero_duration_or_none_matches_its_instant() {
    // (start <= DTSTART AND end > DTSTART).
    for body in [
        "DTSTART:20270301T100000Z\r\nDURATION:PT0S\r\n",
        "DTSTART:20270301T100000Z\r\n",
    ] {
        check(
            "VEVENT",
            body,
            &[(9, 10, false), (9, 11, true), (10, 11, true), (11, 12, false)],
        );
    }
}

#[test]
fn vevent_with_a_dtend_equal_to_dtstart_follows_the_first_row_of_the_table() {
    // (start < DTEND AND end > DTSTART): the instant must lie strictly inside the range.
    check(
        "VEVENT",
        "DTSTART:20270301T100000Z\r\nDTEND:20270301T100000Z\r\n",
        &[(9, 10, false), (9, 11, true), (10, 11, false), (11, 12, false)],
    );
}

#[test]
fn all_day_events_without_end_last_one_day() {
    // (start < DTSTART+P1D AND end > DTSTART) with DTSTART a DATE: the day [00:00, 24:00).
    check(
        "VEVENT",
        "DTSTART;VALUE=DATE:20270301\r\n",
        &[(0, 1, true), (23, 24, true)],
    );
    let calendar = object("VEVENT", "DTSTART;VALUE=DATE:20270301\r\n");
    let next_day = (
        Utc.with_ymd_and_hms(2027, 3, 2, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2027, 3, 3, 0, 0, 0).unwrap(),
    );
    assert!(!hit(&calendar, "VEVENT", Some(next_day.0), Some(next_day.1)));
    let previous = (
        Utc.with_ymd_and_hms(2027, 2, 27, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap(),
    );
    assert!(!hit(&calendar, "VEVENT", Some(previous.0), Some(previous.1)));
}

#[test]
fn open_ended_ranges() {
    let calendar = object("VEVENT", "DTSTART:20270301T100000Z\r\nDTEND:20270301T120000Z\r\n");
    assert!(hit(&calendar, "VEVENT", Some(h(11)), None));
    assert!(!hit(&calendar, "VEVENT", Some(h(12)), None));
    assert!(hit(&calendar, "VEVENT", None, Some(h(11))));
    assert!(!hit(&calendar, "VEVENT", None, Some(h(10))));
}

#[test]
fn vtodo_with_dtstart_and_duration() {
    // (start <= DTSTART+DURATION) AND ((end > DTSTART) OR (end >= DTSTART+DURATION)); span [10:00, 12:00].
    check(
        "VTODO",
        "DTSTART:20270301T100000Z\r\nDURATION:PT2H\r\n",
        &[
            (9, 10, false),
            (9, 11, true),
            (12, 13, true),
            (13, 14, false),
            (13, 15, false),
        ],
    );
}

#[test]
fn vtodo_with_dtstart_and_due() {
    // ((start < DUE) OR (start <= DTSTART)) AND ((end > DTSTART) OR (end >= DUE)).
    check(
        "VTODO",
        "DTSTART:20270301T100000Z\r\nDUE:20270301T120000Z\r\n",
        &[
            (9, 10, false),
            (9, 11, true),
            (11, 13, true),
            (12, 13, false),
            (13, 14, false),
        ],
    );
}

#[test]
fn vtodo_with_dtstart_only() {
    // (start <= DTSTART) AND (end > DTSTART).
    check(
        "VTODO",
        "DTSTART:20270301T100000Z\r\n",
        &[(9, 10, false), (9, 11, true), (10, 11, true), (11, 12, false)],
    );
}

#[test]
fn vtodo_with_due_only() {
    // (start < DUE) AND (end >= DUE).
    check(
        "VTODO",
        "DUE:20270301T120000Z\r\n",
        &[
            (11, 12, true),
            (11, 13, true),
            (12, 13, false),
            (9, 11, false),
            (9, 12, true),
        ],
    );
}

#[test]
fn vtodo_with_completed_and_created() {
    // ((start <= CREATED) OR (start <= COMPLETED)) AND ((end >= CREATED) OR (end >= COMPLETED)).
    check(
        "VTODO",
        "CREATED:20270301T080000Z\r\nCOMPLETED:20270301T120000Z\r\n",
        &[
            (7, 8, true),
            (7, 9, true),
            (9, 11, true),
            (11, 13, true),
            (13, 14, false),
            (1, 7, false),
        ],
    );
}

#[test]
fn vtodo_with_completed_only() {
    // (start <= COMPLETED) AND (end >= COMPLETED).
    check(
        "VTODO",
        "COMPLETED:20270301T120000Z\r\n",
        &[(11, 12, true), (12, 13, true), (13, 14, false), (10, 11, false)],
    );
}

#[test]
fn vtodo_with_created_only() {
    // (end > CREATED).
    check(
        "VTODO",
        "CREATED:20270301T080000Z\r\n",
        &[(7, 8, false), (7, 9, true), (12, 13, true), (1, 8, false)],
    );
}

#[test]
fn vtodo_without_any_date_matches_every_range() {
    check(
        "VTODO",
        "SUMMARY:Anytime\r\n",
        &[(1, 2, true), (9, 10, true), (23, 24, true)],
    );
}

#[test]
fn vjournal() {
    // DTSTART a DATE-TIME: (start <= DTSTART) AND (end > DTSTART).
    check(
        "VJOURNAL",
        "DTSTART:20270301T100000Z\r\n",
        &[(9, 10, false), (9, 11, true), (10, 11, true), (11, 12, false)],
    );
    // DTSTART a DATE: (start < DTSTART+P1D) AND (end > DTSTART).
    check(
        "VJOURNAL",
        "DTSTART;VALUE=DATE:20270301\r\n",
        &[(0, 1, true), (12, 13, true)],
    );
    // No DTSTART: never.
    check("VJOURNAL", "SUMMARY:Undated\r\n", &[(1, 2, false), (9, 10, false)]);
}

#[test]
fn recurring_events_match_when_one_instance_does() {
    let calendar = object(
        "VEVENT",
        "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\n",
    );
    let day = |d: u32, from: u32, to: u32| {
        (
            Utc.with_ymd_and_hms(2027, 3, d, from, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2027, 3, d, to, 0, 0).unwrap(),
        )
    };
    for (range, expected) in [
        (day(1, 10, 11), true),
        (day(2, 10, 11), true),
        (day(3, 10, 11), true),
        (day(4, 10, 11), false),
        (day(2, 11, 12), false),
        (day(2, 0, 10), false),
    ] {
        assert_eq!(
            hit(&calendar, "VEVENT", Some(range.0), Some(range.1)),
            expected,
            "{range:?}"
        );
    }
}

#[test]
fn expansion_agrees_with_the_filter() {
    let limits = IcalLimits::default();
    for (kind, body) in [
        ("VEVENT", "DTSTART:20270301T100000Z\r\nDTEND:20270301T120000Z\r\n"),
        ("VEVENT", "DTSTART:20270301T100000Z\r\n"),
        ("VEVENT", "DTSTART;VALUE=DATE:20270301\r\n"),
        ("VTODO", "DTSTART:20270301T100000Z\r\nDUE:20270301T120000Z\r\n"),
        ("VJOURNAL", "DTSTART:20270301T100000Z\r\n"),
    ] {
        let calendar = object(kind, body);
        for start in 0..24 {
            let end = start + 1;
            let range = TimeRange::new(Some(h(start)), Some(h(end)));
            let by_filter = matches(&calendar, &filter(kind, range), &limits).unwrap();
            let by_expansion = !expand(&calendar, &range, &limits).unwrap().is_empty();
            assert_eq!(by_filter, by_expansion, "{kind} {body:?} [{start}:00, {end}:00)");
        }
    }
}
