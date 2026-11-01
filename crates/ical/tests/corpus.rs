//! The corpus of client bodies in `testdata/corpus`: round trips, leniency, rejection and the findings of the
//! calcard spike (ADR-0001).

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeDelta, TimeZone, Utc};
use davhaven_domain::{ComponentKind, EventTime, IcalLimits, ItipMethod};
use davhaven_ical::expand::{Instance, expand};
use davhaven_ical::filter::{CalendarFilter, CompFilter, TimeRange, matches};
use davhaven_ical::freebusy::busy_periods;
use davhaven_ical::hash::content_hash;
use davhaven_ical::index::index;
use davhaven_ical::itip::{apply_reply, parse_message};
use davhaven_ical::merge::to_event_data;
use davhaven_ical::parse::{ParsedCalendar, parse};
use davhaven_ical::serialize::serialize;
use davhaven_ical::validate::parse_and_validate;
use davhaven_ical::{IcalError, LimitKind};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus")
}

fn files(subdirectory: &str) -> Vec<(String, Vec<u8>)> {
    let directory = if subdirectory.is_empty() {
        corpus()
    } else {
        corpus().join(subdirectory)
    };
    let mut found: Vec<(String, Vec<u8>)> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|extension| extension == "ics"))
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path()).unwrap();
            (name, bytes)
        })
        .collect();
    found.sort();
    found
}

fn body(name: &str) -> Vec<u8> {
    let path = corpus().join(name);
    fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn limits() -> IcalLimits {
    IcalLimits::default()
}

fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
}

fn year(year: i32) -> TimeRange {
    TimeRange::new(Some(at(year, 1, 1, 0)), Some(at(year + 1, 1, 1, 0)))
}

fn instances(name: &str, range: &TimeRange) -> Vec<Instance> {
    let object = parse_and_validate(&body(name), &limits()).unwrap();
    expand(&object.calendar, range, &limits()).unwrap()
}

fn starts(found: &[Instance]) -> Vec<DateTime<Utc>> {
    found.iter().map(|instance| instance.start).collect()
}

#[test]
fn the_corpus_is_not_empty() {
    assert!(files("").len() >= 15);
    assert!(files("imip").len() >= 5);
    assert!(files("rejected").len() >= 8);
}

#[test]
fn every_client_body_is_accepted_and_round_trips() {
    for (name, bytes) in files("") {
        let object = parse_and_validate(&bytes, &limits()).unwrap_or_else(|error| panic!("{name}: {error}"));
        let first = serialize(&object.calendar).unwrap();
        assert!(first.ends_with("\r\n"), "{name}");
        assert!(
            first.split("\r\n").all(|line| line.len() <= 75),
            "{name}: lines are folded at 75 octets"
        );
        let second_calendar = parse(first.as_bytes(), &limits()).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(second_calendar, object.calendar, "{name}: parse(serialize(c)) == c");
        assert_eq!(
            serialize(&second_calendar).unwrap(),
            first,
            "{name}: serialization is a fixed point"
        );
        assert_eq!(
            content_hash(&second_calendar).unwrap(),
            content_hash(&object.calendar).unwrap(),
            "{name}: the content hash survives re-serialization"
        );
        let again = parse_and_validate(first.as_bytes(), &limits()).unwrap();
        assert_eq!(
            index(&again, &limits()).unwrap(),
            index(&object, &limits()).unwrap(),
            "{name}: the index survives re-serialization"
        );
    }
}

#[test]
fn every_client_body_reads_as_event_data() {
    for (name, bytes) in files("") {
        let object = parse_and_validate(&bytes, &limits()).unwrap();
        let data = to_event_data(&object.calendar, None).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(data.uid.as_ref(), Some(&object.uid), "{name}");
    }
}

#[test]
fn every_client_body_is_expandable_over_a_decade() {
    let range = TimeRange::new(Some(at(2027, 1, 1, 0)), Some(at(2037, 1, 1, 0)));
    for (name, bytes) in files("") {
        let object = parse_and_validate(&bytes, &limits()).unwrap();
        // Long running unbounded series may exceed the instance limit; everything else must expand.
        match expand(&object.calendar, &range, &limits()) {
            Ok(found) => {
                assert!(
                    found.windows(2).all(|pair| pair[0].start <= pair[1].start),
                    "{name}: ordered"
                );
            }
            Err(IcalError::Limit(LimitKind::Instances | LimitKind::IteratorSteps)) => {}
            Err(other) => panic!("{name}: {other}"),
        }
    }
}

#[test]
fn every_client_body_can_be_matched_and_summed_up_over_a_decade() {
    // Whether an instance exists and which time is busy are questions about the whole series, however long it
    // runs: only the expansion that returns the instances is capped by `max_instances`.
    let decade = TimeRange::new(Some(at(2027, 1, 1, 0)), Some(at(2037, 1, 1, 0)));
    let open = TimeRange::new(Some(at(2027, 1, 1, 0)), None);
    for (name, bytes) in files("") {
        let object = parse_and_validate(&bytes, &limits()).unwrap();
        for range in [decade, open] {
            let filter = CalendarFilter {
                root: CompFilter {
                    name: "VCALENDAR".to_owned(),
                    is_not_defined: false,
                    time_range: None,
                    prop_filters: Vec::new(),
                    comp_filters: vec![CompFilter {
                        name: object.component.as_ical().to_owned(),
                        is_not_defined: false,
                        time_range: Some(range),
                        prop_filters: Vec::new(),
                        comp_filters: Vec::new(),
                    }],
                },
            };
            matches(&object.calendar, &filter, &limits()).unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        busy_periods(&[&object.calendar], &decade, &limits()).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn rejected_bodies_are_refused() {
    for (name, bytes) in files("rejected") {
        let result = parse_and_validate(&bytes, &limits());
        assert!(result.is_err(), "{name} must be rejected, got {result:?}");
    }
}

#[test]
fn truncated_documents_are_rejected_with_an_explanation() {
    // Finding 3 of the calcard spike: a document without END:VEVENT or END:VCALENDAR parsed without an error.
    for name in [
        "truncated-before-end-vevent.ics",
        "truncated-before-end-vcalendar.ics",
        "truncated-inside-alarm.ics",
    ] {
        let bytes = body(&format!("rejected/{name}"));
        let Err(IcalError::Invalid(message)) = parse(&bytes, &limits()) else {
            panic!("{name} must be refused by the parser");
        };
        assert!(message.contains("incomplete"), "{name}: {message}");
    }
}

#[test]
fn the_reasons_for_rejection_are_specific() {
    let rejection = |name: &str| match parse_and_validate(&body(&format!("rejected/{name}")), &limits()) {
        Err(error) => error,
        Ok(object) => panic!("{name} is accepted: {object:?}"),
    };
    let reason = |name: &str| {
        rejection(name)
            .client_message()
            .expect("a message for the client")
            .to_owned()
    };
    let precondition = |name: &str| rejection(name).precondition().map(|precondition| precondition.code());
    assert!(reason("method-publish-google-export.ics").contains("METHOD"));
    assert!(reason("mixed-component-types.ics").contains("only one component type"));
    assert!(reason("different-uids.ics").contains("different UIDs"));
    // RFC 4791 section 5.3.2.1: these are `valid-calendar-object-resource`, not `valid-calendar-data`.
    for name in [
        "method-publish-google-export.ics",
        "mixed-component-types.ics",
        "different-uids.ics",
    ] {
        assert_eq!(precondition(name), Some("valid-calendar-object-resource"), "{name}");
    }
    assert_eq!(precondition("dtend-before-dtstart.ics"), Some("valid-calendar-data"));
    assert_eq!(precondition("not-icalendar-vcard.ics"), Some("valid-calendar-data"));
    assert!(reason("not-icalendar-vcard.ics").contains("BEGIN:VCALENDAR"));
    assert!(reason("two-calendars.ics").contains("more than one VCALENDAR"));
    assert_eq!(reason("dtend-before-dtstart.ics"), "DTEND is before DTSTART");
    assert_eq!(
        parse_and_validate(&body("rejected/sub-hourly-rrule.ics"), &limits()),
        Err(IcalError::Limit(LimitKind::SubDailyFrequency))
    );
    assert_eq!(
        parse_and_validate(&body("rejected/date-out-of-range.ics"), &limits()),
        Err(IcalError::Limit(LimitKind::MaxDateTime))
    );
}

#[test]
fn lf_line_endings_parse_to_the_same_calendar_as_crlf() {
    let lf = body("lenient-lf-line-endings.ics");
    assert!(!lf.contains(&b'\r'));
    let crlf = String::from_utf8(lf.clone()).unwrap().replace('\n', "\r\n");
    assert_eq!(
        parse(&lf, &limits()).unwrap(),
        parse(crlf.as_bytes(), &limits()).unwrap()
    );
    assert!(parse_and_validate(&lf, &limits()).is_ok());
}

#[test]
fn zero_length_events_are_accepted_and_match_their_instant() {
    let object = parse_and_validate(&body("lenient-zero-length-dtend.ics"), &limits()).unwrap();
    let found = index(&object, &limits()).unwrap();
    // The index is a pre-filter that never misses: both bounds are one second wider than the instant.
    assert_eq!(found.first_start, Some(at(2027, 3, 1, 10) - TimeDelta::seconds(1)));
    assert_eq!(found.last_end, Some(at(2027, 3, 1, 10) + TimeDelta::seconds(1)));
    let around = TimeRange::new(
        Some(Utc.with_ymd_and_hms(2027, 3, 1, 9, 30, 0).unwrap()),
        Some(Utc.with_ymd_and_hms(2027, 3, 1, 10, 30, 0).unwrap()),
    );
    assert_eq!(expand(&object.calendar, &around, &limits()).unwrap().len(), 1);
    let starting_at_it = TimeRange::new(Some(at(2027, 3, 1, 10)), Some(at(2027, 3, 1, 11)));
    assert_eq!(
        expand(&object.calendar, &starting_at_it, &limits()).unwrap().len(),
        0,
        "RFC 4791 section 9.9: start < DTEND is false for a range that starts at the instant"
    );
    let before = TimeRange::new(Some(at(2027, 3, 1, 9)), Some(at(2027, 3, 1, 10)));
    assert_eq!(expand(&object.calendar, &before, &limits()).unwrap().len(), 0);
    let all_day = parse_and_validate(&body("lenient-zero-length-allday.ics"), &limits()).unwrap();
    assert!(index(&all_day, &limits()).unwrap().first_start.is_some());
    // An all-day event whose `DTEND` equals `DTSTART` is that day: the query for the day, which starts at
    // midnight, finds it (it must not be an instant at midnight that the range has to contain strictly).
    let the_day = TimeRange::new(Some(at(2027, 3, 2, 0)), Some(at(2027, 3, 3, 0)));
    let found = expand(&all_day.calendar, &the_day, &limits()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].start, found[0].end), (at(2027, 3, 2, 0), at(2027, 3, 3, 0)));
    let next_day = TimeRange::new(Some(at(2027, 3, 3, 0)), Some(at(2027, 3, 4, 0)));
    assert_eq!(expand(&all_day.calendar, &next_day, &limits()).unwrap().len(), 0);
}

#[test]
fn windows_zone_names_resolve_with_and_without_a_vtimezone() {
    let with = instances("caldav-synchronizer-windows-tzid.ics", &year(2027));
    assert_eq!(starts(&with), vec![at(2027, 3, 29, 8)]);
    assert_eq!(with[0].end, Utc.with_ymd_and_hms(2027, 3, 29, 9, 30, 0).unwrap());
    let without = instances("caldav-synchronizer-windows-tzid-no-vtimezone.ics", &year(2027));
    assert_eq!(
        starts(&without),
        vec![at(2027, 9, 2, 10), at(2027, 9, 3, 10), at(2027, 9, 4, 10)],
        "Romance Standard Time is Paris, UTC+2 in September"
    );
}

#[test]
fn a_customized_time_zone_is_evaluated_from_its_observances() {
    let found = instances("outlook-customized-timezone.ics", &year(2027));
    assert_eq!(starts(&found), vec![at(2027, 6, 15, 13)], "UTC+2 in June");
    assert_eq!(found[0].end, at(2027, 6, 15, 14));
}

#[test]
fn registry_style_zone_names_resolve() {
    let found = instances("evolution-event-registry-tzid.ics", &year(2027));
    assert_eq!(starts(&found), vec![at(2027, 3, 8, 8)]);
}

#[test]
fn an_iana_zone_without_a_definition_follows_the_daylight_saving_change() {
    let found = instances("lenient-iana-tzid-without-vtimezone.ics", &year(2027));
    // 09:00 in New York: EST (14:00Z) on March 13th, EDT (13:00Z) from March 14th on.
    assert_eq!(
        starts(&found),
        vec![at(2027, 3, 13, 14), at(2027, 3, 14, 13), at(2027, 3, 15, 13)]
    );
}

#[test]
fn overrides_replace_the_instance_they_name() {
    // Finding 2 of the calcard spike: the override was reported as an additional instance while the master
    // instance it replaces was still emitted.
    let found = instances("apple-macos-weekly-override.ics", &year(2027));
    assert_eq!(
        found.len(),
        13,
        "14 Mondays, one excluded, one moved: {:?}",
        starts(&found)
    );
    let overrides: Vec<&Instance> = found.iter().filter(|instance| instance.is_override).collect();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].start, at(2027, 3, 8, 11));
    assert_eq!(overrides[0].end, at(2027, 3, 8, 12));
    let all = starts(&found);
    assert!(!all.contains(&at(2027, 3, 8, 9)), "the replaced instance is gone");
    assert!(!all.contains(&at(2027, 3, 15, 9)), "the excluded instance is gone");
    assert!(all.contains(&at(2027, 3, 22, 9)), "CET before the change");
    assert!(all.contains(&at(2027, 3, 29, 8)), "CEST after the change");
    assert_eq!(all.last(), Some(&at(2027, 5, 31, 8)), "UNTIL is inclusive");
    assert!(all.windows(2).all(|pair| pair[0] < pair[1]), "no duplicates");
    assert_eq!(
        found[2].recurrence_id,
        EventTime::Zoned {
            local: chrono::NaiveDate::from_ymd_opt(2027, 3, 22)
                .unwrap()
                .and_hms_opt(10, 0, 0)
                .unwrap(),
            zone: davhaven_domain::TimeZoneName::parse("Europe/Berlin").unwrap(),
        }
    );
}

#[test]
fn the_index_bounds_the_series() {
    let object = parse_and_validate(&body("apple-macos-weekly-override.ics"), &limits()).unwrap();
    let found = index(&object, &limits()).unwrap();
    assert_eq!(found.first_start, Some(at(2027, 3, 1, 9) - TimeDelta::seconds(1)));
    assert_eq!(found.last_end, Some(at(2027, 5, 31, 9) + TimeDelta::seconds(1)));
    assert!(found.is_recurring && !found.is_scheduling);
    let yearly = parse_and_validate(&body("apple-ios-allday-yearly.ics"), &limits()).unwrap();
    assert_eq!(index(&yearly, &limits()).unwrap().last_end, None, "infinite series");
    let monthly = parse_and_validate(&body("thunderbird-event-monthly.ics"), &limits()).unwrap();
    let bounds = index(&monthly, &limits()).unwrap();
    assert_eq!(bounds.first_start, Some(at(2027, 3, 2, 18) - TimeDelta::seconds(1)));
    assert_eq!(bounds.last_end, Some(at(2027, 5, 18, 19) + TimeDelta::seconds(1)));
    let todo = parse_and_validate(&body("thunderbird-todo.ics"), &limits()).unwrap();
    let found = index(&todo, &limits()).unwrap();
    assert_eq!(found.component, ComponentKind::Todo);
    assert_eq!(
        found.first_start,
        Some(at(2027, 1, 5, 12) - TimeDelta::seconds(1)),
        "CREATED dates a to-do"
    );
    assert_eq!(found.last_end, Some(at(2027, 3, 31, 15) + TimeDelta::seconds(1)));
}

#[test]
fn recurrence_rules_of_the_clients_expand_as_written() {
    let monthly = instances("thunderbird-event-monthly.ics", &year(2027));
    assert_eq!(
        starts(&monthly),
        vec![
            at(2027, 3, 2, 18),
            at(2027, 3, 16, 18),
            at(2027, 4, 6, 17),
            at(2027, 4, 20, 17),
            at(2027, 5, 4, 17),
            at(2027, 5, 18, 17),
        ]
    );
    let weekly = instances(
        "davx5-event-utc.ics",
        &TimeRange::new(Some(at(2027, 3, 1, 0)), Some(at(2027, 3, 15, 0))),
    );
    assert_eq!(
        starts(&weekly),
        vec![at(2027, 3, 3, 17), at(2027, 3, 10, 17), at(2027, 3, 13, 17)]
    );
    let yearly = instances(
        "apple-ios-allday-yearly.ics",
        &TimeRange::new(Some(at(2027, 1, 1, 0)), Some(at(2031, 1, 1, 0))),
    );
    assert_eq!(yearly.len(), 4);
    assert!(yearly.iter().all(|instance| instance.all_day));
}

#[test]
fn text_survives_unfolding_and_unescaping() {
    let object = parse_and_validate(&body("utf8-folded-description.ics"), &limits()).unwrap();
    let data = to_event_data(&object.calendar, None).unwrap();
    assert_eq!(data.summary.as_deref(), Some("日本語の会議 – Größe, Ärger, Æther, 😀"));
    assert_eq!(
        data.description.as_deref(),
        Some(
            "Erste Zeile\nZweite Zeile mit Umlauten äöüß und einem langen Text, der mitten in einem Wort umbrochen \
             wird und danach noch weitergeht. Dazu ein Emoji 😀 und ein Absatz; mit Semikolon, Komma."
        )
    );
    assert_eq!(data.location.as_deref(), Some("Zürich, Bahnhofstrasse 1"));
}

#[test]
fn an_invited_attendee_copy_keeps_its_scheduling_state() {
    let object = parse_and_validate(&body("apple-ios-invite-accepted.ics"), &limits()).unwrap();
    let found = index(&object, &limits()).unwrap();
    assert!(found.is_scheduling);
    assert_eq!(
        found
            .organizer
            .as_ref()
            .map(davhaven_domain::CalendarUserAddress::as_str),
        Some("mailto:anna@example.org")
    );
    assert_eq!(found.attendees.len(), 2);
    let text = serialize(&object.calendar).unwrap();
    assert!(text.contains("SCHEDULE-STATUS=2.0"), "{text}");
}

#[test]
fn imip_messages_parse_with_their_methods() {
    for (name, expected) in [
        ("google-request.ics", ItipMethod::Request),
        ("google-cancel.ics", ItipMethod::Cancel),
        ("outlook-request-windows-tzid.ics", ItipMethod::Request),
        ("outlook-reply-accepted.ics", ItipMethod::Reply),
        ("apple-reply-declined.ics", ItipMethod::Reply),
    ] {
        let bytes = body(&format!("imip/{name}"));
        let message = parse_message(&bytes, &limits()).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(message.method, expected, "{name}");
        let text = serialize(&message.calendar).unwrap();
        assert!(text.contains(&format!("METHOD:{}\r\n", expected.as_ical())), "{name}");
        assert_eq!(parse(text.as_bytes(), &limits()).unwrap(), message.calendar, "{name}");
        // Messages are not calendar object resources: the METHOD makes the storage rules refuse them.
        assert!(parse_and_validate(&bytes, &limits()).is_err(), "{name}");
    }
}

fn object_without_method(name: &str) -> ParsedCalendar {
    let text = String::from_utf8(body(name)).unwrap().replace("METHOD:REQUEST\r\n", "");
    parse_and_validate(text.as_bytes(), &limits()).unwrap().calendar
}

#[test]
fn an_outlook_reply_updates_the_organizer_copy() {
    let copy = object_without_method("imip/outlook-request-windows-tzid.ics");
    let reply = parse_message(&body("imip/outlook-reply-accepted.ics"), &limits()).unwrap();
    let applied = apply_reply(&copy, &reply).unwrap();
    assert_eq!(applied.attendee.as_str(), "mailto:bob@example.org");
    assert!(applied.sequence_matches);
    assert_eq!(
        applied.instances.len(),
        1,
        "the reply names the instance, which gets an override"
    );
    let text = serialize(&applied.updated).unwrap().replace("\r\n ", "");
    assert!(text.contains("PARTSTAT=ACCEPTED"), "{text}");
    assert!(parse_and_validate(text.as_bytes(), &limits()).is_ok());

    let google = object_without_method("imip/google-request.ics");
    let decline = parse_message(&body("imip/apple-reply-declined.ics"), &limits()).unwrap();
    assert!(apply_reply(&google, &decline).is_err(), "another UID, another attendee");
}
