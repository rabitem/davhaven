//! `calendar-query` filters (RFC 4791 section 9.7): the expectations are written out by hand from the RFC, case by
//! case; the time-range tables of section 9.9 are in `rfc4791_time_range.rs`.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use chrono::{DateTime, TimeZone, Utc};
use davhaven_domain::IcalLimits;
use davhaven_ical::filter::{
    CalendarFilter, Collation, CompFilter, ParamFilter, PropFilter, TextMatch, TimeRange, matches, validate_filter,
};
use davhaven_ical::parse::{ParsedCalendar, parse};
use davhaven_ical::validate::parse_and_validate;
use davhaven_ical::{ErrorContext, IcalError, LimitKind};

const TEAM: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:filters\r\nDTSTAMP:20270101T000000Z\r\n\
    DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nSUMMARY:Team Meeting\r\nDESCRIPTION:Quarterly planning\r\n\
    LOCATION:Room 1\r\nCATEGORIES:work,planning\r\nCATEGORIES:internal\r\n\
    ATTENDEE;PARTSTAT=ACCEPTED;CN=Bob:mailto:bob@example.org\r\nATTENDEE;PARTSTAT=DECLINED:mailto:cleo@example.org\r\n\
    BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\n\
    BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER;RELATED=END:PT30M\r\nREPEAT:2\r\nDURATION:PT1H\r\nDESCRIPTION:After\r\nEND:VALARM\r\n\
    END:VEVENT\r\nEND:VCALENDAR\r\n";

fn limits() -> IcalLimits {
    IcalLimits::default()
}

fn calendar(text: &str) -> ParsedCalendar {
    parse_and_validate(text.as_bytes(), &limits())
        .unwrap_or_else(|error| panic!("{error}\n{text}"))
        .calendar
}

fn at(hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 3, 1, hour, minute, 0).unwrap()
}

fn range(from: DateTime<Utc>, until: DateTime<Utc>) -> TimeRange {
    TimeRange::new(Some(from), Some(until))
}

fn comp(name: &str) -> CompFilter {
    CompFilter {
        name: name.to_owned(),
        is_not_defined: false,
        time_range: None,
        prop_filters: Vec::new(),
        comp_filters: Vec::new(),
    }
}

fn prop(name: &str) -> PropFilter {
    PropFilter {
        name: name.to_owned(),
        is_not_defined: false,
        time_range: None,
        text_match: None,
        param_filters: Vec::new(),
    }
}

fn text(value: &str, collation: Collation, negate: bool) -> TextMatch {
    TextMatch {
        value: value.to_owned(),
        collation,
        negate,
    }
}

fn root(children: Vec<CompFilter>) -> CalendarFilter {
    CalendarFilter {
        root: CompFilter {
            comp_filters: children,
            ..comp("VCALENDAR")
        },
    }
}

fn event_with(props: Vec<PropFilter>) -> CalendarFilter {
    root(vec![CompFilter {
        prop_filters: props,
        ..comp("VEVENT")
    }])
}

fn event_with_alarm(range: TimeRange) -> CalendarFilter {
    root(vec![CompFilter {
        comp_filters: vec![CompFilter {
            time_range: Some(range),
            ..comp("VALARM")
        }],
        ..comp("VEVENT")
    }])
}

fn hit(source: &ParsedCalendar, filter: &CalendarFilter) -> bool {
    matches(source, filter, &limits()).unwrap()
}

// ---------------------------------------------------------------------------------------------------------------
// text-match
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn text_match_follows_the_collation() {
    let team = calendar(TEAM);
    let summary = |value: &str, collation: Collation, negate: bool| {
        event_with(vec![PropFilter {
            text_match: Some(text(value, collation, negate)),
            ..prop("SUMMARY")
        }])
    };
    // i;ascii-casemap is the default: ASCII letters match in any case, it is a substring test.
    assert!(hit(&team, &summary("team", Collation::default(), false)));
    assert!(hit(&team, &summary("MEETING", Collation::AsciiCasemap, false)));
    assert!(hit(&team, &summary("m Me", Collation::AsciiCasemap, false)));
    assert!(!hit(&team, &summary("standup", Collation::AsciiCasemap, false)));
    // i;octet compares bytes.
    assert!(!hit(&team, &summary("team", Collation::Octet, false)));
    assert!(hit(&team, &summary("Team", Collation::Octet, false)));
    // i;unicode-casemap folds non-ASCII letters, i;ascii-casemap does not.
    let umlauts = calendar(&TEAM.replace("SUMMARY:Team Meeting", "SUMMARY:Ärger im Büro"));
    assert!(!hit(&umlauts, &summary("ärger", Collation::AsciiCasemap, false)));
    assert!(!hit(&umlauts, &summary("ärger", Collation::Octet, false)));
    assert!(hit(&umlauts, &summary("ärger", Collation::UnicodeCasemap, false)));
    assert!(hit(&umlauts, &summary("BÜRO", Collation::UnicodeCasemap, false)));
}

#[test]
fn negate_condition_inverts_the_match_of_the_value() {
    let team = calendar(TEAM);
    let summary = |value: &str, negate: bool| {
        event_with(vec![PropFilter {
            text_match: Some(text(value, Collation::AsciiCasemap, negate)),
            ..prop("SUMMARY")
        }])
    };
    assert!(hit(&team, &summary("standup", true)));
    assert!(!hit(&team, &summary("meeting", true)));
    // A property with several values is negated as a whole: "work" is among the values, so the negation is false.
    let category = |value: &str, negate: bool| {
        event_with(vec![PropFilter {
            text_match: Some(text(value, Collation::AsciiCasemap, negate)),
            ..prop("CATEGORIES")
        }])
    };
    assert!(hit(&team, &category("planning", false)));
    // With a single CATEGORIES line holding several values the negation applies to the whole property: one of
    // the values contains "planning", so the negated condition is false.
    let single = calendar(&TEAM.replace("CATEGORIES:internal\r\n", ""));
    assert!(!hit(&single, &category("planning", true)));
    assert!(hit(&single, &category("travel", true)));
    // With several properties of the name, one of them satisfying the condition is enough.
    assert!(
        hit(&team, &category("planning", true)),
        "the second CATEGORIES line does not contain it"
    );
    assert!(
        hit(&team, &category("internal", true)),
        "the first CATEGORIES line does not contain it"
    );
    // A property that is not there matches nothing, negated or not.
    let missing = |negate: bool| {
        event_with(vec![PropFilter {
            text_match: Some(text("x", Collation::AsciiCasemap, negate)),
            ..prop("X-NOT-THERE")
        }])
    };
    assert!(!hit(&team, &missing(false)));
    assert!(!hit(&team, &missing(true)));
}

// ---------------------------------------------------------------------------------------------------------------
// is-not-defined at the three levels, param-filter, nested components
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn is_not_defined_works_for_components_properties_and_parameters() {
    let team = calendar(TEAM);
    // Components.
    let no_alarm = root(vec![CompFilter {
        comp_filters: vec![CompFilter {
            is_not_defined: true,
            ..comp("VALARM")
        }],
        ..comp("VEVENT")
    }]);
    assert!(!hit(&team, &no_alarm));
    let no_todo = root(vec![CompFilter {
        is_not_defined: true,
        ..comp("VTODO")
    }]);
    assert!(hit(&team, &no_todo));
    let no_event = root(vec![CompFilter {
        is_not_defined: true,
        ..comp("VEVENT")
    }]);
    assert!(!hit(&team, &no_event));
    // Properties.
    let location_undefined = event_with(vec![PropFilter {
        is_not_defined: true,
        ..prop("LOCATION")
    }]);
    assert!(!hit(&team, &location_undefined));
    let nothing_undefined = event_with(vec![PropFilter {
        is_not_defined: true,
        ..prop("X-NOPE")
    }]);
    assert!(hit(&team, &nothing_undefined));
    // Parameters: one of the attendees (Cleo) has no CN.
    let without_name = event_with(vec![PropFilter {
        param_filters: vec![ParamFilter {
            name: "CN".to_owned(),
            is_not_defined: true,
            text_match: None,
        }],
        ..prop("ATTENDEE")
    }]);
    assert!(hit(&team, &without_name));
    // The conditions of one property filter hold for the same property: Bob has the name, Cleo has not.
    let bob_without_name = event_with(vec![PropFilter {
        text_match: Some(text("bob@", Collation::AsciiCasemap, false)),
        param_filters: vec![ParamFilter {
            name: "CN".to_owned(),
            is_not_defined: true,
            text_match: None,
        }],
        ..prop("ATTENDEE")
    }]);
    assert!(!hit(&team, &bob_without_name));
}

#[test]
fn param_filters_compare_the_value_of_the_parameter() {
    let team = calendar(TEAM);
    let partstat = |value: &str| {
        event_with(vec![PropFilter {
            param_filters: vec![ParamFilter {
                name: "partstat".to_owned(),
                is_not_defined: false,
                text_match: Some(text(value, Collation::AsciiCasemap, false)),
            }],
            ..prop("ATTENDEE")
        }])
    };
    assert!(hit(&team, &partstat("accepted")));
    assert!(hit(&team, &partstat("DECLINED")));
    assert!(!hit(&team, &partstat("TENTATIVE")));
    // Both conditions must hold for the same attendee.
    let bob_declined = event_with(vec![PropFilter {
        text_match: Some(text("bob@", Collation::AsciiCasemap, false)),
        param_filters: vec![ParamFilter {
            name: "PARTSTAT".to_owned(),
            is_not_defined: false,
            text_match: Some(text("DECLINED", Collation::AsciiCasemap, false)),
        }],
        ..prop("ATTENDEE")
    }]);
    assert!(!hit(&team, &bob_declined));
}

#[test]
fn a_param_filter_without_a_text_match_asks_for_the_parameter_only() {
    let team = calendar(TEAM);
    let attendee_with = |name: &str| {
        event_with(vec![PropFilter {
            param_filters: vec![ParamFilter {
                name: name.to_owned(),
                is_not_defined: false,
                text_match: None,
            }],
            ..prop("ATTENDEE")
        }])
    };
    assert!(hit(&team, &attendee_with("CN")), "Bob has a name");
    assert!(hit(&team, &attendee_with("cn")), "parameter names are case-insensitive");
    assert!(!hit(&team, &attendee_with("DELEGATED-FROM")), "nobody was delegated");
    let summary_with_language = event_with(vec![PropFilter {
        param_filters: vec![ParamFilter {
            name: "LANGUAGE".to_owned(),
            is_not_defined: false,
            text_match: None,
        }],
        ..prop("SUMMARY")
    }]);
    assert!(!hit(&team, &summary_with_language));
}

#[test]
fn a_text_match_on_a_value_that_is_not_text_compares_its_written_form() {
    let team = calendar(TEAM);
    let matching = |property: &str, value: &str| {
        event_with(vec![PropFilter {
            text_match: Some(text(value, Collation::AsciiCasemap, false)),
            ..prop(property)
        }])
    };
    assert!(hit(&team, &matching("DTSTART", "20270301T10")));
    assert!(
        hit(&team, &matching("DTSTART", "t100000z")),
        "ascii-casemap applies to dates too"
    );
    assert!(!hit(&team, &matching("DTSTART", "20270302")));
    // Each value of a list is a text of its own, and every CATEGORIES line counts.
    assert!(hit(&team, &matching("CATEGORIES", "planning")));
    assert!(hit(&team, &matching("CATEGORIES", "internal")));
    assert!(!hit(&team, &matching("CATEGORIES", "work,planning")));
    let numbered = calendar(&TEAM.replace("LOCATION:Room 1\r\n", "LOCATION:Room 1\r\nSEQUENCE:12\r\n"));
    assert!(hit(&numbered, &matching("SEQUENCE", "12")));
    assert!(!hit(&numbered, &matching("SEQUENCE", "13")));
}

#[test]
fn nested_component_filters_select_children_by_name() {
    let team = calendar(TEAM);
    let with_description = root(vec![CompFilter {
        comp_filters: vec![CompFilter {
            prop_filters: vec![PropFilter {
                text_match: Some(text("after", Collation::AsciiCasemap, false)),
                ..prop("DESCRIPTION")
            }],
            ..comp("VALARM")
        }],
        ..comp("VEVENT")
    }]);
    assert!(hit(&team, &with_description));
    let wrong_text = root(vec![CompFilter {
        comp_filters: vec![CompFilter {
            prop_filters: vec![PropFilter {
                text_match: Some(text("quarterly", Collation::AsciiCasemap, false)),
                ..prop("DESCRIPTION")
            }],
            ..comp("VALARM")
        }],
        ..comp("VEVENT")
    }]);
    assert!(!hit(&team, &wrong_text), "the alarm's description, not the event's");
    // A filter for another top-level component than the calendar's root never matches.
    let wrong_root = CalendarFilter { root: comp("VEVENT") };
    assert!(!hit(&team, &wrong_root));
}

// ---------------------------------------------------------------------------------------------------------------
// time-range on alarms, free-busy and properties
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn an_alarm_matches_when_one_of_its_trigger_times_is_in_the_range() {
    let team = calendar(TEAM);
    // The first alarm fires 15 minutes before the start: 09:45.
    assert!(hit(&team, &event_with_alarm(range(at(9, 30), at(9, 50)))));
    assert!(!hit(&team, &event_with_alarm(range(at(9, 46), at(10, 0)))));
    // The second one fires 30 minutes after the end (RELATED=END): 11:30, and twice more every hour.
    assert!(hit(&team, &event_with_alarm(range(at(11, 20), at(11, 40)))));
    assert!(hit(&team, &event_with_alarm(range(at(12, 25), at(12, 35)))));
    assert!(hit(&team, &event_with_alarm(range(at(13, 0), at(14, 0)))));
    // Nothing fires between the first and the second alarm, and the repeats stop after REPEAT times.
    assert!(!hit(&team, &event_with_alarm(range(at(10, 0), at(11, 0)))));
    assert!(!hit(&team, &event_with_alarm(range(at(14, 0), at(16, 0)))));
}

#[test]
fn an_alarm_with_an_absolute_trigger_matches_at_that_instant_and_one_without_a_trigger_never() {
    let absolute = calendar(&TEAM.replace("TRIGGER:-PT15M", "TRIGGER;VALUE=DATE-TIME:20270301T080000Z"));
    assert!(hit(&absolute, &event_with_alarm(range(at(7, 59), at(8, 1)))));
    assert!(
        !hit(&absolute, &event_with_alarm(range(at(9, 30), at(9, 50)))),
        "the absolute trigger does not follow the start"
    );
    // A VALARM without TRIGGER breaks RFC 5545; a stored one is never read as firing.
    let without = parse(
        TEAM.replace("TRIGGER:-PT15M\r\n", "")
            .replace("TRIGGER;RELATED=END:PT30M\r\n", "")
            .as_bytes(),
        &limits(),
    )
    .unwrap();
    assert!(!hit(&without, &event_with_alarm(range(at(0, 0), at(23, 0)))));
}

#[test]
fn a_free_busy_component_matches_by_its_own_period() {
    let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VFREEBUSY\r\nUID:fb\r\nDTSTAMP:20270101T000000Z\r\n\
        DTSTART:20270301T100000Z\r\nDTEND:20270301T120000Z\r\nFREEBUSY:20270301T103000Z/20270301T113000Z\r\n\
        END:VFREEBUSY\r\nEND:VCALENDAR\r\n";
    // A free-busy answer is not stored as an object, it only has to be readable.
    let free_busy = parse(text.as_bytes(), &limits()).unwrap();
    let wrapped = |range| {
        root(vec![CompFilter {
            time_range: Some(range),
            ..comp("VFREEBUSY")
        }])
    };
    // RFC 4791 section 9.9: (start <= DTEND) AND (end > DTSTART).
    assert!(hit(&free_busy, &wrapped(range(at(11, 30), at(13, 0)))));
    assert!(hit(&free_busy, &wrapped(range(at(9, 0), at(10, 30)))));
    assert!(
        hit(&free_busy, &wrapped(range(at(12, 0), at(13, 0)))),
        "start <= DTEND is inclusive"
    );
    assert!(!hit(&free_busy, &wrapped(range(at(12, 1), at(13, 0)))));
    assert!(
        !hit(&free_busy, &wrapped(range(at(8, 0), at(10, 0)))),
        "end > DTSTART is exclusive"
    );
}

#[test]
fn a_property_time_range_checks_the_instant_of_the_property() {
    let team = calendar(TEAM);
    let start_in = |from: DateTime<Utc>, until: DateTime<Utc>| {
        event_with(vec![PropFilter {
            time_range: Some(range(from, until)),
            ..prop("DTSTART")
        }])
    };
    assert!(
        hit(&team, &start_in(at(10, 0), at(10, 30))),
        "the start of the range is inclusive"
    );
    assert!(hit(&team, &start_in(at(9, 0), at(10, 1))));
    assert!(
        !hit(&team, &start_in(at(9, 0), at(10, 0))),
        "the end of the range is exclusive"
    );
    assert!(!hit(&team, &start_in(at(10, 1), at(12, 0))));
}

/// RFC 4791 section 9.9: a VFREEBUSY without DTSTART and DTEND overlaps a range when one of its FREEBUSY periods
/// does, `(start < period-end) AND (end > period-start)`.
#[test]
fn a_free_busy_component_without_its_own_period_matches_by_its_free_busy_periods() {
    let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VFREEBUSY\r\nUID:fb\r\nDTSTAMP:20270101T000000Z\r\n\
        FREEBUSY:20270301T103000Z/20270301T113000Z\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
    let free_busy = parse(text.as_bytes(), &limits()).unwrap();
    let wrapped = |range| {
        root(vec![CompFilter {
            time_range: Some(range),
            ..comp("VFREEBUSY")
        }])
    };
    assert!(hit(&free_busy, &wrapped(range(at(11, 0), at(12, 0)))));
    assert!(
        !hit(&free_busy, &wrapped(range(at(11, 30), at(12, 0)))),
        "start < period-end"
    );
    assert!(
        !hit(&free_busy, &wrapped(range(at(9, 0), at(10, 30)))),
        "end > period-start"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// validate_filter
// ---------------------------------------------------------------------------------------------------------------

fn nested(depth: usize) -> CalendarFilter {
    let mut filter = comp("VEVENT");
    for _ in 1..depth {
        filter = CompFilter {
            comp_filters: vec![filter],
            ..comp("VEVENT")
        };
    }
    root(vec![filter])
}

fn rejection(filter: &CalendarFilter) -> IcalError {
    validate_filter(filter, &limits()).unwrap_err()
}

#[test]
fn valid_filters_are_accepted() {
    assert!(validate_filter(&event_with(vec![prop("SUMMARY")]), &limits()).is_ok());
    let timed = root(vec![CompFilter {
        time_range: Some(range(at(0, 0), at(23, 0))),
        ..comp("VEVENT")
    }]);
    assert!(validate_filter(&timed, &limits()).is_ok());
    // The root is matched case-insensitively.
    let lower = CalendarFilter {
        root: comp("vcalendar"),
    };
    assert!(validate_filter(&lower, &limits()).is_ok());
    // RFC 4791 section 9.9: a time-range may be open at either end.
    for open in [
        TimeRange::new(Some(at(0, 0)), None),
        TimeRange::new(None, Some(at(0, 0))),
    ] {
        let open_ended = root(vec![CompFilter {
            time_range: Some(open),
            ..comp("VEVENT")
        }]);
        assert!(validate_filter(&open_ended, &limits()).is_ok());
    }
    // Exactly ten years, and exactly max_nesting levels (the root and three below it), are allowed.
    let ten_years = root(vec![CompFilter {
        time_range: Some(range(at(0, 0), Utc.with_ymd_and_hms(2037, 3, 1, 0, 0, 0).unwrap())),
        ..comp("VEVENT")
    }]);
    assert!(validate_filter(&ten_years, &limits()).is_ok());
    assert!(validate_filter(&nested(3), &limits()).is_ok());
    // Conditions on properties and parameters that hold together.
    let attendee = event_with(vec![PropFilter {
        time_range: Some(range(at(0, 0), at(1, 0))),
        param_filters: vec![ParamFilter {
            name: "PARTSTAT".to_owned(),
            is_not_defined: true,
            text_match: None,
        }],
        ..prop("ATTENDEE")
    }]);
    assert!(validate_filter(&attendee, &limits()).is_ok());
}

#[test]
fn filters_that_are_not_valid_are_refused_with_the_filter_precondition() {
    let rooted_wrongly = CalendarFilter { root: comp("VEVENT") };
    let too_deep = nested(5);
    let on_calendar = CalendarFilter {
        root: CompFilter {
            time_range: Some(range(at(0, 0), at(1, 0))),
            ..comp("VCALENDAR")
        },
    };
    let on_timezone = root(vec![CompFilter {
        time_range: Some(range(at(0, 0), at(1, 0))),
        ..comp("VTIMEZONE")
    }]);
    let undefined_with_conditions = root(vec![CompFilter {
        is_not_defined: true,
        prop_filters: vec![prop("SUMMARY")],
        ..comp("VEVENT")
    }]);
    let undefined_property_with_conditions = event_with(vec![PropFilter {
        is_not_defined: true,
        text_match: Some(text("x", Collation::AsciiCasemap, false)),
        ..prop("SUMMARY")
    }]);
    let nameless = root(vec![comp(" ")]);
    let too_long = root(vec![CompFilter {
        time_range: Some(range(at(0, 0), Utc.with_ymd_and_hms(2040, 1, 1, 0, 0, 0).unwrap())),
        ..comp("VEVENT")
    }]);
    let before_the_minimum = root(vec![CompFilter {
        time_range: Some(range(
            Utc.with_ymd_and_hms(1800, 1, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(1800, 1, 2, 0, 0, 0).unwrap(),
        )),
        ..comp("VEVENT")
    }]);
    let backwards = root(vec![CompFilter {
        time_range: Some(range(at(5, 0), at(4, 0))),
        ..comp("VEVENT")
    }]);
    let boundless = root(vec![CompFilter {
        time_range: Some(TimeRange::default()),
        ..comp("VEVENT")
    }]);
    let cases = [
        ("the root must be VCALENDAR", &rooted_wrongly),
        ("nesting deeper than max_nesting", &too_deep),
        ("a time-range on VCALENDAR", &on_calendar),
        ("a time-range on VTIMEZONE", &on_timezone),
        ("is-not-defined with conditions", &undefined_with_conditions),
        ("is-not-defined with a text-match", &undefined_property_with_conditions),
        ("a component without a name", &nameless),
        ("a span of more than ten years", &too_long),
        ("a range before the minimum date", &before_the_minimum),
        ("a range that ends before it starts", &backwards),
        ("a range without bounds", &boundless),
    ];
    for (why, filter) in cases {
        let error = rejection(filter);
        assert_eq!(
            error
                .precondition_in(ErrorContext::Query)
                .map(|precondition| precondition.code()),
            Some("valid-filter"),
            "{why}: {error}"
        );
    }
    // The particular limits are the ones that are documented.
    assert_eq!(rejection(&too_deep), IcalError::Limit(LimitKind::Nesting));
    assert_eq!(rejection(&too_long), IcalError::Limit(LimitKind::TimeRange));
    assert_eq!(rejection(&before_the_minimum), IcalError::Limit(LimitKind::MinDateTime));
}

#[test]
fn property_and_parameter_filters_that_are_not_valid_are_refused_with_the_filter_precondition() {
    let nameless_property = event_with(vec![prop(" ")]);
    let param = |name: &str, is_not_defined: bool, text_match: Option<TextMatch>| {
        event_with(vec![PropFilter {
            param_filters: vec![ParamFilter {
                name: name.to_owned(),
                is_not_defined,
                text_match,
            }],
            ..prop("ATTENDEE")
        }])
    };
    let nameless_parameter = param("", false, None);
    let undefined_parameter_with_text = param("CN", true, Some(text("x", Collation::AsciiCasemap, false)));
    let property_range_backwards = event_with(vec![PropFilter {
        time_range: Some(range(at(5, 0), at(4, 0))),
        ..prop("DTSTART")
    }]);
    let property_range_too_long = event_with(vec![PropFilter {
        time_range: Some(range(at(0, 0), Utc.with_ymd_and_hms(2037, 3, 1, 0, 0, 1).unwrap())),
        ..prop("DTSTART")
    }]);
    let cases = [
        ("a property without a name", &nameless_property),
        ("a parameter without a name", &nameless_parameter),
        (
            "an undefined parameter with a text-match",
            &undefined_parameter_with_text,
        ),
        ("a property range that ends before it starts", &property_range_backwards),
        ("a property range of more than ten years", &property_range_too_long),
    ];
    for (why, filter) in cases {
        let error = rejection(filter);
        assert_eq!(
            error
                .precondition_in(ErrorContext::Query)
                .map(|precondition| precondition.code()),
            Some("valid-filter"),
            "{why}: {error}"
        );
    }
    assert_eq!(
        rejection(&property_range_too_long),
        IcalError::Limit(LimitKind::TimeRange)
    );
}
