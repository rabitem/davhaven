//! The body shared by the never-panic property test and the fuzz targets: push bytes through every entry point
//! of the crate and check the invariants that hold for whatever is accepted.

use chrono::{TimeZone, Utc};
use davhaven_domain::{CalendarUserAddress, EventData, EventTime, IcalLimits, ItipMethod, PartStat, TimeZoneName, Uid};
use davhaven_ical::busy::{BusyOptions, strip_to_busy};
use davhaven_ical::contained_panics;
use davhaven_ical::expand::{expand, expand_in_zone};
use davhaven_ical::filter::{CalendarFilter, Collation, CompFilter, PropFilter, TextMatch, TimeRange, matches};
use davhaven_ical::freebusy::{Participation, busy_periods, busy_periods_for, read_request};
use davhaven_ical::hash::content_hash;
use davhaven_ical::index::index;
use davhaven_ical::itip::{
    MessageSpec, ReplySpec, apply_organizer_changes, apply_reply_with, attendee_change_violations, build_message,
    carry_over_attendee_data, diff, inline_attachments, organizer_change_violations, parse_message, reply_message,
    rewrite_addresses, set_schedule_status, set_sent_by, strip_alarms, strip_schedule_params,
};
use davhaven_ical::merge::{
    EditScope, MergeContext, merge_event, merge_event_split, override_ids, remove_instances_with_limits, to_event_data,
};
use davhaven_ical::parse::{ParsedCalendar, accept, parse};
use davhaven_ical::projection::{ComponentSelection, Projection, project};
use davhaven_ical::serialize::serialize;
use davhaven_ical::validate::{ValidatedObject, parse_and_validate, validate};

pub(crate) fn small_limits() -> IcalLimits {
    IcalLimits {
        max_instances: 200,
        max_iterator_steps: 5_000,
        time_budget_ms: 1_500,
        ..IcalLimits::default()
    }
}

pub(crate) fn wide_range() -> TimeRange {
    TimeRange::new(
        Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        Some(Utc.with_ymd_and_hms(2028, 1, 1, 0, 0, 0).unwrap()),
    )
}

pub(crate) fn some_filter() -> CalendarFilter {
    CalendarFilter {
        root: CompFilter {
            name: "VCALENDAR".to_owned(),
            is_not_defined: false,
            time_range: None,
            prop_filters: Vec::new(),
            comp_filters: vec![CompFilter {
                name: "VEVENT".to_owned(),
                is_not_defined: false,
                time_range: Some(wide_range()),
                prop_filters: vec![PropFilter {
                    name: "SUMMARY".to_owned(),
                    is_not_defined: false,
                    time_range: None,
                    text_match: Some(TextMatch {
                        value: "a".to_owned(),
                        collation: Collation::UnicodeCasemap,
                        negate: false,
                    }),
                    param_filters: Vec::new(),
                }],
                comp_filters: vec![CompFilter {
                    name: "VALARM".to_owned(),
                    is_not_defined: false,
                    time_range: Some(wide_range()),
                    prop_filters: Vec::new(),
                    comp_filters: Vec::new(),
                }],
            }],
        },
    }
}

/// Pushes the bytes through every entry point of the crate and checks that no third-party panic was contained on
/// the way: the crate turns such a panic into an error, which a property that only looks for panics cannot see.
pub(crate) fn exercise(bytes: &[u8]) {
    let before = contained_panics();
    run(bytes);
    assert_eq!(
        contained_panics(),
        before,
        "a panic of the parser or the generator was contained"
    );
}

/// The round trip of everything `accept` lets in: the text it is serialized as parses to the same calendar (and so to
/// the same content hash), and that serializes to the same text. Backlog 45 and 51: the lenient reader of the parser
/// library accepted data its writer wrote differently, or as text that no longer read.
pub(crate) fn assert_round_trip(parsed: &ParsedCalendar, limits: &IcalLimits) {
    let text = serialize(parsed).unwrap();
    let again = parse(text.as_bytes(), limits);
    assert!(
        again.is_ok(),
        "what was serialized parses: {:?}\n{text:?}",
        again.as_ref().err()
    );
    let again = again.unwrap();
    assert_eq!(&again, parsed, "the round trip changes the calendar:\n{text:?}");
    assert_eq!(serialize(&again).unwrap(), text, "serialization is a fixed point");
    assert_eq!(
        content_hash(&again).unwrap(),
        content_hash(parsed).unwrap(),
        "the content hash does not survive the round trip"
    );
}

fn run(bytes: &[u8]) {
    let limits = small_limits();
    if let Ok(message) = parse_message(bytes, &limits) {
        let _ = read_request(&message);
        let _ = message.object();
    }
    let Ok(parsed) = parse(bytes, &limits) else {
        return;
    };
    // What comes in survives the writer; what is only read (a stored object from before the gate) need not, and
    // every path below still must not panic on it.
    if let Ok(accepted) = accept(bytes, &limits) {
        assert_round_trip(&accepted, &limits);
    }
    reads(&parsed, &limits);
    scheduling(&parsed, &limits);
    if let Ok(object) = validate(parsed, &limits) {
        stored(&object, &limits);
    }
}

/// The read paths: expansion, filters, free-busy, projection and busy stripping.
fn reads(parsed: &ParsedCalendar, limits: &IcalLimits) {
    let _ = expand(parsed, &wide_range(), limits);
    let berlin = TimeZoneName::parse("Europe/Berlin").unwrap();
    let _ = expand_in_zone(parsed, &wide_range(), limits, berlin);
    let _ = matches(parsed, &some_filter(), limits);
    let _ = busy_periods(&[parsed], &wide_range(), limits);
    let guest = [CalendarUserAddress::parse("mailto:guest@example.org").unwrap()];
    for participating_only in [false, true] {
        let who = Participation {
            addresses: &guest,
            participating_only,
        };
        let _ = busy_periods_for(&[parsed], &wide_range(), limits, TimeZoneName::utc(), &who);
    }
    let projection = Projection {
        expand: Some(wide_range()),
        select: Some(ComponentSelection {
            name: "VCALENDAR".to_owned(),
            all_props: true,
            props: Vec::new(),
            all_comps: true,
            comps: Vec::new(),
        }),
        ..Projection::default()
    };
    let _ = project(parsed, &projection, limits);
    let _ = strip_to_busy(
        parsed,
        &BusyOptions {
            summary: "Busy",
            uid_salt: b"salt",
        },
    );
    let _ = to_event_data(parsed, None);
    let _ = override_ids(parsed);
}

/// The scheduling rules: diff, organizer rules, attendee checks, messages and replies.
fn scheduling(parsed: &ParsedCalendar, limits: &IcalLimits) {
    let _ = strip_schedule_params(parsed);
    let _ = strip_alarms(parsed);
    let _ = inline_attachments(parsed);
    let _ = carry_over_attendee_data(parsed, parsed);
    let _ = diff(Some(parsed), parsed, limits);
    let _ = apply_organizer_changes(Some(parsed), parsed, limits);
    let attendee = CalendarUserAddress::parse("mailto:guest@example.org").unwrap();
    let _ = set_schedule_status(parsed, &attendee, "1.2");
    let _ = set_sent_by(parsed, &attendee);
    let organizer = CalendarUserAddress::parse("mailto:org@example.org").unwrap();
    let uid = Uid::parse("answer").unwrap();
    let reply = reply_message(&ReplySpec {
        uid: &uid,
        organizer: &organizer,
        attendee: &attendee,
        partstat: PartStat::Tentative,
        sequence: 2,
        dtstamp: Utc.with_ymd_and_hms(2027, 1, 2, 0, 0, 0).unwrap(),
        comment: Some("Fine, with me;\nsee you"),
    })
    .expect("a reply can always be built");
    let text = serialize(&reply.calendar).unwrap();
    assert!(
        parse_message(text.as_bytes(), limits).is_ok(),
        "a built reply reads back as a message:\n{text}"
    );
    let _ = attendee_change_violations(parsed, parsed, &attendee);
    let _ = organizer_change_violations(parsed, parsed);
    let _ = rewrite_addresses(parsed, &|address| (address != &attendee).then(|| attendee.clone()));
    for method in [ItipMethod::Request, ItipMethod::Cancel, ItipMethod::Reply] {
        let spec = MessageSpec {
            replying_attendee: Some(attendee.clone()),
            comment: Some("Fine with me".to_owned()),
            ..MessageSpec::new(
                method,
                attendee.clone(),
                Utc.with_ymd_and_hms(2027, 1, 2, 0, 0, 0).unwrap(),
            )
        };
        if let Ok(message) = build_message(parsed, &spec) {
            let _ = apply_reply_with(parsed, &message, limits, Some(&attendee));
            let _ = serialize(&message.calendar);
        }
    }
}

/// What the server produces from a stored object can be stored and read back.
fn stores_and_reads_back(calendar: &ParsedCalendar, limits: &IcalLimits) {
    let text = serialize(calendar).unwrap();
    assert!(
        parse_and_validate(text.as_bytes(), limits).is_ok(),
        "what the server produces can be stored and read back:\n{text}"
    );
}

/// The paths that change a stored object: index, merge, split and removal.
fn stored(object: &ValidatedObject, limits: &IcalLimits) {
    let berlin = TimeZoneName::parse("Europe/Berlin").unwrap();
    if let Ok(found) = index(object, limits) {
        assert!(found.first_start.is_none() || found.last_end.is_none() || found.first_start <= found.last_end);
    }
    let uid = object.uid.clone();
    let context = MergeContext {
        uid: &uid,
        now: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
        default_zone: berlin,
        scope: EditScope::All,
        limits,
        default_alarm_text: "Reminder",
    };
    if let Ok(data) = to_event_data(&object.calendar, None) {
        if let Ok(merged) = merge_event(Some(&object.calendar), &data, &context) {
            stores_and_reads_back(&merged, limits);
        }
        let continuation = Uid::parse("continuation").unwrap();
        let rid = override_ids(&object.calendar)
            .ok()
            .and_then(|ids| ids.into_iter().next());
        let patch = EventData {
            recurrence_id: rid.or_else(|| data.start.clone()),
            summary: Some("Changed".to_owned()),
            ..data
        };
        if let Ok(split) = merge_event_split(&object.calendar, &patch, &context, &continuation) {
            stores_and_reads_back(&split.continuation, limits);
            if let Some(earlier) = &split.earlier {
                stores_and_reads_back(earlier, limits);
            }
        }
    }
    let mut instances: Vec<EventTime> = override_ids(&object.calendar).unwrap_or_default();
    instances.push(EventTime::Utc(Utc.with_ymd_and_hms(2027, 3, 1, 10, 0, 0).unwrap()));
    for rid in &instances {
        for scope in [EditScope::This, EditScope::ThisAndFuture, EditScope::All] {
            if let Ok(Some(remaining)) = remove_instances_with_limits(&object.calendar, rid, scope, limits) {
                stores_and_reads_back(&remaining, limits);
            }
        }
    }
}
