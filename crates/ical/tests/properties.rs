//! Property tests (PLAN L1): expansion against an independent oracle and metamorphic relations, the round trip
//! and fixed point of the serializer, and the semantics of `time-range` against a brute force evaluation of the
//! RFC 4791 conditions.
//!
//! `PROPTEST_CASES` raises the number of cases (the nightly job uses 20 000); failing cases are kept in
//! `properties.proptest-regressions` and replayed first.

#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use davhaven_domain::IcalLimits;
use davhaven_ical::expand::{Instance, expand};
use davhaven_ical::filter::{CalendarFilter, CompFilter, TimeRange, matches};
use davhaven_ical::hash::content_hash;
use davhaven_ical::parse::{ParsedCalendar, parse};
use davhaven_ical::serialize::serialize;
use davhaven_ical::validate::parse_and_validate;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

fn limits() -> IcalLimits {
    IcalLimits::default()
}

const ZONES: [&str; 6] = [
    "UTC",
    "Europe/Berlin",
    "America/New_York",
    "Asia/Kolkata",
    "Australia/Lord_Howe",
    "Pacific/Auckland",
];

const WEEKDAYS: [(&str, Weekday); 7] = [
    ("MO", Weekday::Mon),
    ("TU", Weekday::Tue),
    ("WE", Weekday::Wed),
    ("TH", Weekday::Thu),
    ("FR", Weekday::Fri),
    ("SA", Weekday::Sat),
    ("SU", Weekday::Sun),
];

/// A daily or weekly series with an exact oracle.
#[derive(Debug, Clone)]
struct Series {
    zone: &'static str,
    start: NaiveDateTime,
    minutes: u32,
    weekly: bool,
    interval: u32,
    count: u32,
    days: Vec<usize>,
}

fn series() -> impl Strategy<Value = Series> {
    (
        prop::sample::select(ZONES.to_vec()),
        (2020..2029_i32, 1..=12_u32, 1..=28_u32),
        (8..=17_u32, prop::sample::select(vec![0_u32, 15, 30, 45])),
        1..=240_u32,
        any::<bool>(),
        1..=4_u32,
        1..=40_u32,
        prop::collection::btree_set(0..7_usize, 1..=4),
    )
        .prop_map(
            |(zone, (year, month, day), (hour, minute), minutes, weekly, interval, count, days)| {
                let start = NaiveDate::from_ymd_opt(year, month, day)
                    .unwrap()
                    .and_hms_opt(hour, minute, 0)
                    .unwrap();
                // The start belongs to the series: RFC 5545 leaves a start that does not match the rule undefined.
                let mut days = days;
                days.insert(usize::try_from(start.weekday().num_days_from_monday()).unwrap());
                Series {
                    zone,
                    start,
                    minutes,
                    weekly,
                    interval,
                    count,
                    days: days.into_iter().collect(),
                }
            },
        )
}

impl Series {
    fn text(&self, extra: &str) -> String {
        let end = self.start + Duration::minutes(i64::from(self.minutes));
        let mut rule = if self.weekly {
            format!("FREQ=WEEKLY;INTERVAL={};COUNT={}", self.interval, self.count)
        } else {
            format!("FREQ=DAILY;INTERVAL={};COUNT={}", self.interval, self.count)
        };
        if self.weekly {
            let names: Vec<&str> = self.days.iter().map(|&day| WEEKDAYS[day].0).collect();
            write!(rule, ";BYDAY={}", names.join(",")).unwrap();
        }
        let zone = if self.zone == "UTC" {
            String::new()
        } else {
            format!(";TZID={}", self.zone)
        };
        let utc = if self.zone == "UTC" { "Z" } else { "" };
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:series\r\nDTSTAMP:20270101T000000Z\r\n\
             DTSTART{zone}:{}{utc}\r\nDTEND{zone}:{}{utc}\r\nRRULE:{rule}\r\n{extra}END:VEVENT\r\nEND:VCALENDAR\r\n",
            self.start.format("%Y%m%dT%H%M%S"),
            end.format("%Y%m%dT%H%M%S"),
        )
    }

    /// The local start times of the instances, by brute force over the days.
    fn locals(&self) -> Vec<NaiveDateTime> {
        let first_day = self.start.date();
        let week_start = first_day - Duration::days(i64::from(first_day.weekday().num_days_from_monday()));
        let mut found = Vec::new();
        let mut day = first_day;
        while found.len() < usize::try_from(self.count).unwrap() {
            let included = if self.weekly {
                let weeks = (day - week_start).num_days() / 7;
                weeks % i64::from(self.interval) == 0
                    && self.days.iter().any(|&index| WEEKDAYS[index].1 == day.weekday())
            } else {
                (day - first_day).num_days() % i64::from(self.interval) == 0
            };
            if included {
                found.push(day.and_time(self.start.time()));
            }
            day += Duration::days(1);
        }
        found
    }

    fn tz(&self) -> Tz {
        self.zone.parse().unwrap()
    }

    fn instant(&self, local: NaiveDateTime) -> DateTime<Utc> {
        // Local times between 08:00 and 18:00 never fall into a gap or an overlap.
        self.tz()
            .from_local_datetime(&local)
            .single()
            .unwrap()
            .with_timezone(&Utc)
    }

    fn oracle(&self) -> Vec<DateTime<Utc>> {
        self.locals().into_iter().map(|local| self.instant(local)).collect()
    }
}

fn parsed(text: &str) -> ParsedCalendar {
    parse_and_validate(text.as_bytes(), &limits())
        .unwrap_or_else(|error| panic!("{error}\n{text}"))
        .calendar
}

/// Failing cases are written next to this file (`properties.proptest-regressions`) and replayed first.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    }
}

fn all_instances(calendar: &ParsedCalendar) -> Vec<Instance> {
    let range = TimeRange::new(
        Some(Utc.with_ymd_and_hms(2019, 12, 1, 0, 0, 0).unwrap()),
        Some(Utc.with_ymd_and_hms(2029, 11, 30, 0, 0, 0).unwrap()),
    );
    expand(calendar, &range, &limits()).unwrap()
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn expansion_matches_the_oracle(series in series()) {
        let calendar = parsed(&series.text(""));
        let found = all_instances(&calendar);
        let starts: Vec<DateTime<Utc>> = found.iter().map(|instance| instance.start).collect();
        let expected: Vec<DateTime<Utc>> = series
            .oracle()
            .into_iter()
            .filter(|start| *start < Utc.with_ymd_and_hms(2029, 11, 30, 0, 0, 0).unwrap())
            .collect();
        prop_assert_eq!(&starts, &expected);
        for instance in &found {
            prop_assert_eq!(instance.end - instance.start, Duration::minutes(i64::from(series.minutes)));
            prop_assert!(!instance.is_override && !instance.all_day);
        }
    }

    #[test]
    fn instances_keep_the_wall_clock_time_of_the_start(series in series()) {
        let calendar = parsed(&series.text(""));
        for instance in all_instances(&calendar) {
            let local = instance.start.with_timezone(&series.tz()).naive_local();
            prop_assert_eq!(local.time(), series.start.time());
        }
    }

    #[test]
    fn windows_add_up(series in series(), cuts in (0..3650_i64, 0..3650_i64, 0..3650_i64)) {
        let calendar = parsed(&series.text(""));
        let mut cuts = [cuts.0, cuts.1, cuts.2];
        cuts.sort_unstable();
        let origin = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let at = |days: i64| origin + Duration::days(days);
        let window = |from: i64, until: i64| TimeRange::new(Some(at(from)), Some(at(until)));
        let whole = expand(&calendar, &window(cuts[0], cuts[2]), &limits()).unwrap();
        let first = expand(&calendar, &window(cuts[0], cuts[1]), &limits()).unwrap();
        let second = expand(&calendar, &window(cuts[1], cuts[2]), &limits()).unwrap();
        let identity = |instances: &[Instance]| -> BTreeSet<(DateTime<Utc>, String)> {
            instances.iter().map(|i| (i.start, format!("{:?}", i.recurrence_id))).collect()
        };
        let union: BTreeSet<_> = identity(&first).union(&identity(&second)).cloned().collect();
        prop_assert_eq!(identity(&whole), union);
        // Every instance overlaps the window it was found in.
        for instance in &whole {
            prop_assert!(instance.start < at(cuts[2]) && (instance.end > at(cuts[0]) || instance.start == instance.end));
        }
    }

    #[test]
    fn an_exdate_removes_exactly_one_instance(series in series(), pick in 0..40_usize) {
        let calendar = parsed(&series.text(""));
        let before = all_instances(&calendar);
        // The start of the series lies inside the window, so there is always an instance to remove.
        prop_assert!(!before.is_empty());
        let index = pick % before.len();
        let local = series.locals()[index];
        let tzid = if series.zone == "UTC" { String::new() } else { format!(";TZID={}", series.zone) };
        let suffix = if series.zone == "UTC" { "Z" } else { "" };
        let exdate = format!("EXDATE{tzid}:{}{suffix}\r\n", local.format("%Y%m%dT%H%M%S"));
        let after = all_instances(&parsed(&series.text(&exdate)));
        let mut expected = before.clone();
        expected.remove(index);
        prop_assert_eq!(after, expected);
    }

    #[test]
    fn an_override_replaces_exactly_its_instance(series in series(), pick in 0..40_usize, minutes in 1..300_i64) {
        let calendar = parsed(&series.text(""));
        let before = all_instances(&calendar);
        prop_assert!(!before.is_empty());
        let index = pick % before.len();
        let local = series.locals()[index];
        let tzid = if series.zone == "UTC" { String::new() } else { format!(";TZID={}", series.zone) };
        let suffix = if series.zone == "UTC" { "Z" } else { "" };
        let moved_to = local + Duration::minutes(minutes);
        let override_text = format!(
            "BEGIN:VEVENT\r\nUID:series\r\nDTSTAMP:20270101T000000Z\r\nRECURRENCE-ID{tzid}:{}{suffix}\r\nDTSTART{tzid}:{}{suffix}\r\n\
             DTEND{tzid}:{}{suffix}\r\nSUMMARY:moved\r\nEND:VEVENT\r\n",
            local.format("%Y%m%dT%H%M%S"),
            moved_to.format("%Y%m%dT%H%M%S"),
            (moved_to + Duration::minutes(30)).format("%Y%m%dT%H%M%S"),
        );
        let text = series.text("").replace("END:VCALENDAR\r\n", &format!("{override_text}END:VCALENDAR\r\n"));
        // The moved instance may leave 08:00-18:00 local time, so only the zone-independent facts are checked.
        let after = all_instances(&parsed(&text));
        prop_assert_eq!(after.len(), before.len());
        prop_assert_eq!(after.iter().filter(|instance| instance.is_override).count(), 1);
        let replaced = series.instant(local);
        let moved: Vec<&Instance> = after.iter().filter(|instance| instance.is_override).collect();
        prop_assert_eq!(moved[0].end - moved[0].start, Duration::minutes(30));
        let others: Vec<DateTime<Utc>> = after.iter().filter(|i| !i.is_override).map(|i| i.start).collect();
        prop_assert!(!others.contains(&replaced) || moved[0].start == replaced);
        let kept: Vec<DateTime<Utc>> = before.iter().enumerate().filter(|(i, _)| *i != index).map(|(_, i)| i.start).collect();
        prop_assert_eq!(others, kept);
    }

    #[test]
    fn expanded_series_are_ordered_and_unique(series in series()) {
        let found = all_instances(&parsed(&series.text("")));
        let keys: Vec<(DateTime<Utc>, String)> = found
            .iter()
            .map(|instance| (instance.start, format!("{:?}", instance.recurrence_id)))
            .collect();
        prop_assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn serialization_is_a_fixed_point(series in series()) {
        let calendar = parsed(&series.text("SUMMARY:Round trip\\, with \\; separators\r\nX-NOTE:keep\r\n"));
        let text = serialize(&calendar).unwrap();
        let again = parse(text.as_bytes(), &limits()).unwrap();
        prop_assert_eq!(&again, &calendar);
        prop_assert_eq!(serialize(&again).unwrap(), text);
        prop_assert_eq!(content_hash(&again).unwrap(), content_hash(&calendar).unwrap());
    }

    #[test]
    fn the_hash_ignores_volatile_properties_only(series in series(), sequence in 0..1000_u32) {
        let base = parsed(&series.text(""));
        let bumped = parsed(&series.text(&format!("SEQUENCE:{sequence}\r\nLAST-MODIFIED:20290101T000000Z\r\n")));
        let retitled = parsed(&series.text("SUMMARY:different\r\n"));
        prop_assert_eq!(content_hash(&base).unwrap(), content_hash(&bumped).unwrap());
        prop_assert_ne!(content_hash(&base).unwrap(), content_hash(&retitled).unwrap());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// `time-range` against the conditions of RFC 4791 section 9.9
// ---------------------------------------------------------------------------------------------------------------

fn timed_event(start_minute: i64, shape: u8, length: i64) -> (String, i64, i64) {
    let base = Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap();
    let stamp = |minutes: i64| (base + Duration::minutes(minutes)).format("%Y%m%dT%H%M%SZ").to_string();
    let (extra, end) = match shape % 3 {
        0 => (
            format!("DTEND:{}\r\n", stamp(start_minute + length)),
            start_minute + length,
        ),
        1 => (format!("DURATION:PT{length}M\r\n"), start_minute + length),
        _ => (String::new(), start_minute),
    };
    let text = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:p\r\nDTSTAMP:20270101T000000Z\r\nDTSTART:{}\r\n{extra}END:VEVENT\r\nEND:VCALENDAR\r\n",
        stamp(start_minute)
    );
    let kind = i64::from(shape % 3);
    (text, end, kind)
}

fn event_filter(range: TimeRange) -> CalendarFilter {
    CalendarFilter {
        root: CompFilter {
            name: "VCALENDAR".to_owned(),
            is_not_defined: false,
            time_range: None,
            prop_filters: Vec::new(),
            comp_filters: vec![CompFilter {
                name: "VEVENT".to_owned(),
                is_not_defined: false,
                time_range: Some(range),
                prop_filters: Vec::new(),
                comp_filters: Vec::new(),
            }],
        },
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn time_range_follows_the_rfc_for_events(
        start in 60..1200_i64,
        shape in 0..3_u8,
        length in 0..300_i64,
        from in 0..1500_i64,
        span in 1..600_i64,
    ) {
        let (text, end, kind) = timed_event(start, shape, length);
        let calendar = parsed(&text);
        let base = Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap();
        let (range_start, range_end) = (from, from + span);
        // The rows of the table: DTEND present, DURATION > 0, DURATION = 0 or neither.
        let expected = match kind {
            0 => range_start < end && range_end > start,
            1 if length > 0 => range_start < end && range_end > start,
            _ => range_start <= start && range_end > start,
        };
        let range = TimeRange::new(
            Some(base + Duration::minutes(range_start)),
            Some(base + Duration::minutes(range_end)),
        );
        let actual = matches(&calendar, &event_filter(range), &limits()).unwrap();
        prop_assert_eq!(actual, expected, "{} against [{}, {})", text, range_start, range_end);
        let expanded = !expand(&calendar, &range, &limits()).unwrap().is_empty();
        prop_assert_eq!(expanded, expected);
    }
}
