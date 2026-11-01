//! Tests of the merge: creating and editing events, reading `EventData`, removing instances and splitting a
//! series.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use davhaven_domain::{
    AlarmAction, AlarmRelated, AlarmTrigger, CalendarUserAddress, Classification, EventAlarm, EventAttendee, EventData,
    EventDuration, EventField, EventOrganizer, EventStatus, EventTime, IcalLimits, PartStat, Recurrence,
    RecurrenceRule, Role, TimeZoneName, Transparency, Uid,
};

use super::*;
use crate::error::{IcalError, LimitKind};
use crate::hash::content_hash;
use crate::parse::{ParsedCalendar, parse};
use crate::serialize::serialize;

fn limits() -> IcalLimits {
    IcalLimits::default()
}

fn uid() -> Uid {
    Uid::parse("merge-1").unwrap()
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 1, 12, 0, 0).unwrap()
}

fn context<'a>(uid: &'a Uid, limits: &'a IcalLimits, scope: EditScope) -> MergeContext<'a> {
    MergeContext {
        uid,
        now: now(),
        default_zone: TimeZoneName::parse("Europe/Berlin").unwrap(),
        scope,
        limits,
        default_alarm_text: "Reminder",
    }
}

fn berlin(day: u32, hour: u32) -> EventTime {
    EventTime::Zoned {
        local: NaiveDate::from_ymd_opt(2027, 3, day)
            .unwrap()
            .and_hms_opt(hour, 0, 0)
            .unwrap(),
        zone: TimeZoneName::parse("Europe/Berlin").unwrap(),
    }
}

fn parsed(text: &str) -> ParsedCalendar {
    parse(text.as_bytes(), &limits()).unwrap()
}

fn text_of(calendar: &ParsedCalendar) -> String {
    serialize(calendar).unwrap().replace("\r\n ", "")
}

fn create(patch: &EventData) -> ParsedCalendar {
    let limits = limits();
    let uid = uid();
    merge_event(None, patch, &context(&uid, &limits, EditScope::All)).unwrap()
}

#[test]
fn a_new_event_gets_identity_stamps_and_a_time_zone_definition() {
    let created = create(&EventData {
        summary: Some("Planning".to_owned()),
        location: Some("Room 1, 2nd floor; east".to_owned()),
        start: Some(berlin(1, 10)),
        end: Some(berlin(1, 11)),
        ..EventData::default()
    });
    let text = text_of(&created);
    assert!(text.contains("UID:merge-1\r\n"), "{text}");
    assert!(text.contains("DTSTAMP:20270101T120000Z\r\n"), "{text}");
    assert!(text.contains("CREATED:20270101T120000Z\r\n"), "{text}");
    assert!(text.contains("SEQUENCE:0\r\n"), "{text}");
    assert!(text.contains("SUMMARY:Planning\r\n"), "{text}");
    assert!(text.contains("LOCATION:Room 1\\, 2nd floor\\; east\r\n"), "{text}");
    assert!(
        text.contains("DTSTART;TZID=Europe/Berlin:20270301T100000\r\n"),
        "{text}"
    );
    assert!(text.contains("BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n"), "{text}");
    assert_eq!(
        parse(text.as_bytes(), &limits()).unwrap(),
        created,
        "the result is a fixed point"
    );
}

#[test]
fn creating_needs_a_start_and_no_recurrence_id() {
    let limits = limits();
    let uid = uid();
    let ctx = context(&uid, &limits, EditScope::All);
    assert_eq!(
        merge_event(None, &EventData::default(), &ctx).map(|_| ()),
        Err(IcalError::Invalid("a new event needs a start".to_owned()))
    );
    let with_rid = EventData {
        start: Some(berlin(1, 10)),
        recurrence_id: Some(berlin(1, 10)),
        ..EventData::default()
    };
    assert_eq!(
        merge_event(None, &with_rid, &ctx).map(|_| ()),
        Err(IcalError::Invalid(
            "an instance can only be edited on an existing event".to_owned()
        ))
    );
    let other_uid = EventData {
        uid: Some(Uid::parse("other").unwrap()),
        start: Some(berlin(1, 10)),
        ..EventData::default()
    };
    assert_eq!(
        merge_event(None, &other_uid, &ctx).map(|_| ()),
        Err(IcalError::Invalid("the UID of an event cannot be changed".to_owned()))
    );
}

#[test]
fn merging_keeps_unknown_properties_alarms_and_parameters() {
    let stored = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
         DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nSUMMARY:Old\r\nX-CUSTOM;X-PARAM=1:keep me\r\n\
         ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;X-NUM-GUESTS=2:mailto:bob@example.org\r\n\
         BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let limits = limits();
    let uid = uid();
    let patch = EventData {
        summary: Some("New".to_owned()),
        attendees: Some(vec![EventAttendee {
            address: CalendarUserAddress::parse("mailto:bob@example.org").unwrap(),
            common_name: None,
            partstat: None,
            role: Some(Role::OptParticipant),
            cutype: None,
            rsvp: None,
            schedule_agent: None,
        }]),
        ..EventData::default()
    };
    let merged = merge_event(Some(&stored), &patch, &context(&uid, &limits, EditScope::All)).unwrap();
    let text = text_of(&merged);
    assert!(text.contains("SUMMARY:New\r\n"), "{text}");
    assert!(text.contains("X-CUSTOM;X-PARAM=1:keep me\r\n"), "{text}");
    assert!(
        text.contains("PARTSTAT=ACCEPTED") && text.contains("X-NUM-GUESTS=2"),
        "{text}"
    );
    assert!(text.contains("ROLE=OPT-PARTICIPANT"), "{text}");
    assert!(
        text.contains("BEGIN:VALARM"),
        "alarms the caller did not mention survive:\n{text}"
    );
    assert!(
        text.contains("DTSTAMP:20270101T120000Z\r\n") && text.contains("LAST-MODIFIED:20270101T120000Z\r\n"),
        "{text}"
    );
    assert!(text.contains("DTSTART:20270301T100000Z\r\n"), "{text}");
}

#[test]
fn empty_strings_and_lists_clear_fields() {
    let created = create(&EventData {
        summary: Some("S".to_owned()),
        description: Some("D".to_owned()),
        categories: Some(vec!["a".to_owned(), "b".to_owned()]),
        start: Some(berlin(1, 10)),
        ..EventData::default()
    });
    assert!(text_of(&created).contains("CATEGORIES:a,b\r\n"));
    let limits = limits();
    let uid = uid();
    let cleared = merge_event(
        Some(&created),
        &EventData {
            description: Some(String::new()),
            categories: Some(Vec::new()),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::All),
    )
    .unwrap();
    let text = text_of(&cleared);
    assert!(!text.contains("DESCRIPTION") && !text.contains("CATEGORIES"), "{text}");
    assert!(text.contains("SUMMARY:S"), "{text}");
}

#[test]
fn moving_the_start_keeps_the_length() {
    let created = create(&EventData {
        start: Some(berlin(1, 10)),
        end: Some(berlin(1, 12)),
        ..EventData::default()
    });
    let limits = limits();
    let uid = uid();
    let moved = merge_event(
        Some(&created),
        &EventData {
            start: Some(berlin(5, 14)),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::All),
    )
    .unwrap();
    let data = to_event_data(&moved, None).unwrap();
    assert_eq!(data.start, Some(berlin(5, 14)));
    assert_eq!(data.end, Some(berlin(5, 16)));
}

#[test]
fn moving_a_timed_event_to_a_day_drops_the_end_instead_of_mixing_value_types() {
    let created = create(&EventData {
        start: Some(berlin(1, 10)),
        end: Some(berlin(1, 12)),
        ..EventData::default()
    });
    let limits = limits();
    let uid = uid();
    let moved = merge_event(
        Some(&created),
        &EventData {
            start: Some(EventTime::Date(NaiveDate::from_ymd_opt(2027, 3, 5).unwrap())),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::All),
    )
    .unwrap();
    // RFC 5545 section 3.8.2.2: DTEND has the value type of DTSTART; a two-hour length means nothing for a day.
    let text = text_of(&moved);
    assert!(text.contains("DTSTART;VALUE=DATE:20270305\r\n"), "{text}");
    assert!(!text.contains("DTEND"), "{text}");
}

#[test]
fn invalid_results_are_rejected() {
    let created = create(&EventData {
        start: Some(berlin(1, 10)),
        end: Some(berlin(1, 11)),
        ..EventData::default()
    });
    let limits = limits();
    let uid = uid();
    let backwards = merge_event(
        Some(&created),
        &EventData {
            end: Some(berlin(1, 9)),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::All),
    );
    assert!(matches!(backwards, Err(IcalError::Invalid(_))), "{backwards:?}");
    let bad_rule = merge_event(
        Some(&created),
        &EventData {
            recurrence: Some(Recurrence {
                rrule: Some(RecurrenceRule::parse("FREQ=WEEKLY;BYMONTHDAY=1").unwrap()),
                ..Recurrence::default()
            }),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::All),
    );
    assert!(matches!(bad_rule, Err(IcalError::Invalid(_))));
}

const SERIES: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
    DTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\nRRULE:FREQ=DAILY;COUNT=5\r\n\
    SUMMARY:Daily\r\nX-KEEP:1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

#[test]
fn editing_one_instance_creates_an_override() {
    let stored = parsed(SERIES);
    let limits = limits();
    let uid = uid();
    let patch = EventData {
        recurrence_id: Some(berlin(3, 10)),
        summary: Some("Only today".to_owned()),
        start: Some(berlin(3, 15)),
        ..EventData::default()
    };
    let merged = merge_event(Some(&stored), &patch, &context(&uid, &limits, EditScope::This)).unwrap();
    let text = text_of(&merged);
    assert!(
        text.contains("RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000\r\n"),
        "{text}"
    );
    assert!(
        text.contains("DTSTART;TZID=Europe/Berlin:20270303T150000\r\n"),
        "{text}"
    );
    assert!(
        text.contains("DTEND;TZID=Europe/Berlin:20270303T160000\r\n"),
        "the override keeps the length:\n{text}"
    );
    assert_eq!(
        text.matches("RRULE:FREQ=DAILY").count(),
        1,
        "the override has no recurrence rule:\n{text}"
    );
    assert_eq!(text.matches("X-KEEP:1").count(), 2, "{text}");
    assert_eq!(override_ids(&merged).unwrap(), vec![berlin(3, 10)]);
    let data = to_event_data(&merged, Some(&berlin(3, 10))).unwrap();
    assert_eq!(data.summary.as_deref(), Some("Only today"));
    assert_eq!(data.recurrence_id, Some(berlin(3, 10)));
    // A second edit of the same instance changes the override, it does not add another.
    let again = merge_event(
        Some(&merged),
        &EventData {
            recurrence_id: Some(berlin(3, 10)),
            summary: Some("Changed again".to_owned()),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::This),
    )
    .unwrap();
    assert_eq!(override_ids(&again).unwrap().len(), 1);
}

#[test]
fn instances_that_do_not_exist_cannot_be_edited() {
    let stored = parsed(SERIES);
    let limits = limits();
    let uid = uid();
    let patch = EventData {
        recurrence_id: Some(berlin(20, 10)),
        summary: Some("x".to_owned()),
        ..EventData::default()
    };
    assert!(matches!(
        merge_event(Some(&stored), &patch, &context(&uid, &limits, EditScope::This)),
        Err(IcalError::Invalid(_))
    ));
}

#[test]
fn this_and_future_is_not_written_as_a_range_override_and_all_edits_the_master() {
    let stored = parsed(SERIES);
    let limits = limits();
    let uid = uid();
    let patch = EventData {
        recurrence_id: Some(berlin(3, 10)),
        summary: Some("From now on".to_owned()),
        ..EventData::default()
    };
    // RANGE=THISANDFUTURE is read but never written: few clients evaluate it. The split is `merge_event_split`.
    assert!(matches!(
        merge_event(Some(&stored), &patch, &context(&uid, &limits, EditScope::ThisAndFuture)),
        Err(IcalError::Unsupported(_))
    ));
    let all = merge_event(Some(&stored), &patch, &context(&uid, &limits, EditScope::All)).unwrap();
    let data = to_event_data(&all, None).unwrap();
    assert_eq!(data.summary.as_deref(), Some("From now on"));
    assert_eq!(override_ids(&all).unwrap().len(), 0);
}

#[test]
fn event_data_reads_every_field() {
    let stored = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\n\
         DURATION:PT1H30M\r\nSUMMARY:Review\r\nDESCRIPTION:Line one\\nLine two\r\nLOCATION:Room\r\nSTATUS:TENTATIVE\r\n\
         TRANSP:TRANSPARENT\r\nCLASS:PRIVATE\r\nRRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=3\r\nEXDATE;TZID=Europe/Berlin:20270308T100000\r\n\
         RDATE;VALUE=DATE:20270320\r\nORGANIZER;CN=Anna;SENT-BY=\"mailto:pa@example.org\":mailto:anna@example.org\r\n\
         ATTENDEE;CN=Bob;PARTSTAT=TENTATIVE;ROLE=CHAIR;RSVP=TRUE:mailto:bob@example.org\r\nCATEGORIES:A,B\r\nURL:https://example.org/e\r\n\
         SEQUENCE:4\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER;RELATED=END:-PT5M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\n\
         BEGIN:VALARM\r\nACTION:AUDIO\r\nTRIGGER;VALUE=DATE-TIME:20270301T080000Z\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let data = to_event_data(&stored, None).unwrap();
    assert_eq!(data.uid.as_ref().map(Uid::as_str), Some("merge-1"));
    assert_eq!(data.summary.as_deref(), Some("Review"));
    assert_eq!(data.description.as_deref(), Some("Line one\nLine two"));
    assert_eq!(data.start, Some(berlin(1, 10)));
    assert_eq!(data.duration.as_ref().map(EventDuration::as_str), Some("PT1H30M"));
    assert_eq!(data.status, Some(EventStatus::Tentative));
    assert_eq!(data.transparency, Some(Transparency::Transparent));
    assert_eq!(data.class, Some(Classification::Private));
    let recurrence = data.recurrence.unwrap();
    assert_eq!(
        recurrence.rrule.as_ref().map(RecurrenceRule::as_str),
        Some("FREQ=WEEKLY;COUNT=3;BYDAY=MO")
    );
    assert_eq!(recurrence.exdates, vec![berlin(8, 10)]);
    assert_eq!(
        recurrence.rdates,
        vec![EventTime::Date(NaiveDate::from_ymd_opt(2027, 3, 20).unwrap())]
    );
    let organizer = data.organizer.unwrap();
    assert_eq!(organizer.common_name.as_deref(), Some("Anna"));
    assert_eq!(
        organizer.sent_by.as_ref().map(CalendarUserAddress::as_str),
        Some("mailto:pa@example.org")
    );
    let attendee = data.attendees.unwrap().remove(0);
    assert_eq!(attendee.partstat, Some(PartStat::Tentative));
    assert_eq!(attendee.role, Some(Role::Chair));
    assert_eq!(attendee.rsvp, Some(true));
    assert_eq!(data.categories, Some(vec!["A".to_owned(), "B".to_owned()]));
    assert_eq!(data.url.as_ref().map(url::Url::as_str), Some("https://example.org/e"));
    assert_eq!(data.sequence, Some(4));
    let alarms = data.alarms.unwrap();
    assert_eq!(alarms.len(), 2);
    assert!(matches!(
        alarms[0].trigger,
        AlarmTrigger::Relative {
            related: AlarmRelated::End,
            ..
        }
    ));
    assert!(matches!(alarms[1].trigger, AlarmTrigger::Absolute { .. }));
}

#[test]
fn reading_a_missing_component_fails() {
    let stored = parsed(SERIES);
    assert_eq!(
        to_event_data(&stored, Some(&berlin(3, 10))).map(|_| ()),
        Err(IcalError::Invalid("the object has no such component".to_owned()))
    );
}

#[test]
fn removing_instances() {
    let stored = parsed(SERIES);
    // One instance: an EXDATE.
    let without = remove_instances(&stored, &berlin(3, 10), EditScope::This)
        .unwrap()
        .unwrap();
    assert!(
        text_of(&without).contains("EXDATE;TZID=Europe/Berlin:20270303T100000"),
        "{}",
        text_of(&without)
    );
    // This and future: the rule ends before the instance.
    let shortened = remove_instances(&stored, &berlin(3, 10), EditScope::ThisAndFuture)
        .unwrap()
        .unwrap();
    let text = text_of(&shortened);
    assert!(text.contains("UNTIL=20270303T085959Z"), "{text}");
    assert!(!text.contains("COUNT="), "{text}");
    // Everything.
    assert!(
        remove_instances(&stored, &berlin(3, 10), EditScope::All)
            .unwrap()
            .is_none()
    );
    // Removing the first instance and everything after it leaves nothing.
    assert!(
        remove_instances(&stored, &berlin(1, 10), EditScope::ThisAndFuture)
            .unwrap()
            .is_none()
    );
    // An instance that does not exist.
    assert_eq!(
        remove_instances(&stored, &berlin(20, 10), EditScope::This).map(|_| ()),
        Err(IcalError::Invalid(
            "the recurrence id names no instance of the event".to_owned()
        ))
    );
}

#[test]
fn removing_an_instance_with_an_override_drops_the_override() {
    let limits = limits();
    let uid = uid();
    let stored = parsed(SERIES);
    let with_override = merge_event(
        Some(&stored),
        &EventData {
            recurrence_id: Some(berlin(3, 10)),
            summary: Some("Moved".to_owned()),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::This),
    )
    .unwrap();
    let removed = remove_instances(&with_override, &berlin(3, 10), EditScope::This)
        .unwrap()
        .unwrap();
    assert_eq!(override_ids(&removed).unwrap().len(), 0);
    assert!(text_of(&removed).contains("EXDATE"));
}

#[test]
fn a_single_event_vanishes_with_its_only_instance() {
    let created = create(&EventData {
        start: Some(berlin(1, 10)),
        ..EventData::default()
    });
    assert!(
        remove_instances(&created, &berlin(1, 10), EditScope::This)
            .unwrap()
            .is_none()
    );
}

fn date(day: u32) -> EventTime {
    EventTime::Date(NaiveDate::from_ymd_opt(2027, 3, day).unwrap())
}

fn floating(day: u32, hour: u32) -> EventTime {
    EventTime::Floating(
        NaiveDate::from_ymd_opt(2027, 3, day)
            .unwrap()
            .and_hms_opt(hour, 0, 0)
            .unwrap(),
    )
}

const ALL_DAY_SERIES: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\n\
    DTSTAMP:20260101T000000Z\r\nDTSTART;VALUE=DATE:20270301\r\nDTEND;VALUE=DATE:20270303\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\n\
    SUMMARY:Off-site\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const FLOATING_SERIES: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\n\
    DTSTAMP:20260101T000000Z\r\nDTSTART:20270301T100000\r\nDTEND:20270301T113000\r\nRRULE:FREQ=DAILY;COUNT=5\r\n\
    SUMMARY:Wherever I am\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

#[test]
fn editing_one_instance_of_an_all_day_series_keeps_dates_and_the_length_in_days() {
    let limits = limits();
    let uid = uid();
    let edited = merge_event(
        Some(&parsed(ALL_DAY_SERIES)),
        &EventData {
            recurrence_id: Some(date(8)),
            summary: Some("Moved off-site".to_owned()),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::This),
    )
    .unwrap();
    let text = text_of(&edited);
    assert!(text.contains("RECURRENCE-ID;VALUE=DATE:20270308\r\n"), "{text}");
    assert!(
        text.contains("DTSTART;VALUE=DATE:20270308\r\nDTEND;VALUE=DATE:20270310\r\n"),
        "the override spans two days like the series: {text}"
    );
    assert!(text.contains("SUMMARY:Moved off-site\r\n"), "{text}");
    assert_eq!(override_ids(&edited).unwrap(), vec![date(8)]);
}

#[test]
fn editing_one_instance_of_a_floating_series_stays_floating() {
    let limits = limits();
    let uid = uid();
    let edited = merge_event(
        Some(&parsed(FLOATING_SERIES)),
        &EventData {
            recurrence_id: Some(floating(3, 10)),
            location: Some("Home".to_owned()),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::This),
    )
    .unwrap();
    let text = text_of(&edited);
    assert!(
        text.contains("RECURRENCE-ID:20270303T100000\r\n"),
        "no zone and no Z: {text}"
    );
    assert!(
        text.contains("DTSTART:20270303T100000\r\nDTEND:20270303T113000\r\n"),
        "{text}"
    );
}

#[test]
fn editing_one_instance_of_a_recurring_to_do_moves_its_due_date_along() {
    let limits = limits();
    let uid = uid();
    let todo = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VTODO\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
         DTSTART:20270301T100000Z\r\nDUE:20270301T120000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:Task\r\nEND:VTODO\r\n\
         END:VCALENDAR\r\n",
    );
    let edited = merge_event(
        Some(&todo),
        &EventData {
            recurrence_id: Some(utc(2, 10)),
            summary: Some("Task, once".to_owned()),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::This),
    )
    .unwrap();
    let text = text_of(&edited);
    assert_eq!(text.matches("BEGIN:VTODO").count(), 2, "{text}");
    assert!(
        text.contains("DTSTART:20270302T100000Z\r\nDUE:20270302T120000Z\r\nRECURRENCE-ID:20270302T100000Z\r\n"),
        "{text}"
    );
    assert!(!text.contains("DTEND"), "a to-do ends with DUE: {text}");
}

#[test]
fn removing_the_future_of_an_all_day_series_ends_it_on_the_day_before() {
    let cut = remove_instances(&parsed(ALL_DAY_SERIES), &date(15), EditScope::ThisAndFuture)
        .unwrap()
        .unwrap();
    let text = text_of(&cut);
    // RFC 5545 section 3.3.10: UNTIL has the value type of DTSTART, a date for an all-day series.
    assert!(text.contains("RRULE:FREQ=WEEKLY;UNTIL=20270314\r\n"), "{text}");
    assert_eq!(
        instance_starts(&cut),
        vec![
            Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2027, 3, 8, 0, 0, 0).unwrap()
        ]
    );
}

#[test]
fn removing_the_future_of_a_floating_series_ends_it_with_a_floating_until() {
    let cut = remove_instances(&parsed(FLOATING_SERIES), &floating(4, 10), EditScope::ThisAndFuture)
        .unwrap()
        .unwrap();
    let text = text_of(&cut);
    // RFC 5545 section 3.3.10: with a floating DTSTART, UNTIL is a local time as well.
    assert!(text.contains("RRULE:FREQ=DAILY;UNTIL=20270304T095959\r\n"), "{text}");
    assert_eq!(instance_starts(&cut), vec![at(1, 10), at(2, 10), at(3, 10)]);
}

// ---------------------------------------------------------------------------------------------------------------
// The gate every result passes
// ---------------------------------------------------------------------------------------------------------------

fn utc(day: u32, hour: u32) -> EventTime {
    EventTime::Utc(Utc.with_ymd_and_hms(2027, 3, day, hour, 0, 0).unwrap())
}

#[test]
fn text_that_grows_when_it_is_escaped_cannot_be_stored() {
    let limits = limits();
    let uid = uid();
    // 40,000 commas pass the raw limit of the field (65,536) and become 80,000 characters when escaped.
    let patch = EventData {
        description: Some(",".repeat(40_000)),
        start: Some(utc(1, 10)),
        ..EventData::default()
    };
    assert_eq!(
        merge_event(None, &patch, &context(&uid, &limits, EditScope::All)),
        Err(IcalError::Limit(LimitKind::ValueLength))
    );
    // The same text that stays short is fine, and what is returned can be parsed again.
    let fine = EventData {
        description: Some(",".repeat(1_000)),
        start: Some(utc(1, 10)),
        ..EventData::default()
    };
    let merged = merge_event(None, &fine, &context(&uid, &limits, EditScope::All)).unwrap();
    assert!(parse(serialize(&merged).unwrap().as_bytes(), &limits).is_ok());
}

#[test]
fn urls_and_categories_are_bounded_too() {
    let limits = limits();
    let uid = uid();
    let ctx = context(&uid, &limits, EditScope::All);
    let long_url = EventData {
        url: Some(url::Url::parse(&format!("https://example.org/{}", "a".repeat(100_000))).unwrap()),
        start: Some(utc(1, 10)),
        ..EventData::default()
    };
    assert_eq!(
        merge_event(None, &long_url, &ctx),
        Err(IcalError::Limit(LimitKind::ValueLength))
    );
    let many_categories = EventData {
        categories: Some((0..20_000).map(|n| format!("c{n}")).collect()),
        start: Some(utc(1, 10)),
        ..EventData::default()
    };
    assert_eq!(
        merge_event(None, &many_categories, &ctx),
        Err(IcalError::Limit(LimitKind::ValueLength))
    );
}

#[test]
fn a_patch_that_pushes_the_object_past_the_size_limit_is_refused() {
    let tight = IcalLimits {
        max_resource_size: 2_000,
        ..IcalLimits::default()
    };
    let uid = uid();
    let ctx = context(&uid, &tight, EditScope::All);
    let created = merge_event(
        None,
        &EventData {
            description: Some("x".repeat(1_000)),
            start: Some(utc(1, 10)),
            ..EventData::default()
        },
        &ctx,
    )
    .unwrap();
    let grown = merge_event(
        Some(&created),
        &EventData {
            location: Some("y".repeat(1_500)),
            ..EventData::default()
        },
        &ctx,
    );
    assert_eq!(grown, Err(IcalError::Limit(LimitKind::ResourceSize)));
}

#[test]
fn running_out_of_time_is_the_transient_limit() {
    let none = IcalLimits {
        time_budget_ms: 0,
        ..IcalLimits::default()
    };
    let uid = uid();
    let patch = EventData {
        start: Some(utc(1, 10)),
        ..EventData::default()
    };
    assert_eq!(
        merge_event(None, &patch, &context(&uid, &none, EditScope::All)),
        Err(IcalError::Limit(LimitKind::TimeBudget))
    );
}

#[test]
fn alarms_take_their_text_from_the_title_or_the_caller_and_email_alarms_are_refused() {
    let limits = limits();
    let uid = uid();
    let alarm = |action| EventAlarm {
        action,
        trigger: AlarmTrigger::Relative {
            offset: EventDuration::parse("-PT15M").unwrap(),
            related: AlarmRelated::Start,
        },
        description: None,
    };
    let with_title = merge_event(
        None,
        &EventData {
            summary: Some("Planning".to_owned()),
            start: Some(utc(1, 10)),
            alarms: Some(vec![alarm(AlarmAction::Display)]),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::All),
    )
    .unwrap();
    let text = text_of(&with_title);
    assert!(
        text.contains("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Planning\r\n"),
        "{text}"
    );
    let without_title = merge_event(
        None,
        &EventData {
            start: Some(utc(1, 10)),
            alarms: Some(vec![alarm(AlarmAction::Display)]),
            ..EventData::default()
        },
        &MergeContext {
            default_alarm_text: "Erinnerung",
            ..context(&uid, &limits, EditScope::All)
        },
    )
    .unwrap();
    assert!(text_of(&without_title).contains("DESCRIPTION:Erinnerung\r\n"));
    // An e-mail alarm needs recipients that the event model cannot carry.
    let email = merge_event(
        None,
        &EventData {
            start: Some(utc(1, 10)),
            alarms: Some(vec![alarm(AlarmAction::Email)]),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::All),
    );
    assert!(matches!(email, Err(IcalError::Invalid(_))), "{email:?}");
}

#[test]
fn an_alarm_after_the_end_and_the_scheduling_agent_of_an_attendee_are_written() {
    let limits = limits();
    let uid = uid();
    let created = merge_event(
        None,
        &EventData {
            start: Some(utc(1, 10)),
            end: Some(utc(1, 11)),
            alarms: Some(vec![EventAlarm {
                action: AlarmAction::Display,
                trigger: AlarmTrigger::Relative {
                    offset: EventDuration::parse("PT5M").unwrap(),
                    related: AlarmRelated::End,
                },
                description: Some("Wrap up".to_owned()),
            }]),
            attendees: Some(vec![EventAttendee {
                schedule_agent: Some(davhaven_domain::ScheduleAgent::Client),
                ..attendee("mailto:bob@example.org", None)
            }]),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::All),
    )
    .unwrap();
    let text = text_of(&created);
    assert!(text.contains("TRIGGER;RELATED=END:PT5M\r\n"), "{text}");
    assert!(
        text.contains(";SCHEDULE-AGENT=CLIENT:mailto:bob@example.org\r\n"),
        "{text}"
    );
    let read = to_event_data(&created, None).unwrap();
    assert_eq!(
        read.attendees.unwrap()[0].schedule_agent,
        Some(davhaven_domain::ScheduleAgent::Client)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Answers belong to the attendees
// ---------------------------------------------------------------------------------------------------------------

fn attendee(address: &str, partstat: Option<PartStat>) -> EventAttendee {
    EventAttendee {
        address: CalendarUserAddress::parse(address).unwrap(),
        common_name: None,
        partstat,
        role: None,
        cutype: None,
        rsvp: None,
        schedule_agent: None,
    }
}

#[test]
fn a_patch_cannot_set_the_answer_of_an_attendee() {
    let limits = limits();
    let uid = uid();
    let stored = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
         DTSTART:20270301T100000Z\r\nORGANIZER:mailto:anna@example.org\r\n\
         ATTENDEE;PARTSTAT=TENTATIVE;SCHEDULE-STATUS=1.2:mailto:bob@example.org\r\n\
         ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:anna@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let patch = EventData {
        attendees: Some(vec![
            attendee("mailto:bob@example.org", Some(PartStat::Accepted)),
            attendee("mailto:dan@example.org", Some(PartStat::Accepted)),
            attendee("mailto:anna@example.org", Some(PartStat::Accepted)),
        ]),
        ..EventData::default()
    };
    let merged = merge_event(Some(&stored), &patch, &context(&uid, &limits, EditScope::All)).unwrap();
    let text = text_of(&merged);
    // Bob keeps what the server holds, Dan is new and starts open, the organizer's own line is hers.
    assert!(
        text.contains("PARTSTAT=TENTATIVE;SCHEDULE-STATUS=1.2:mailto:bob@example.org"),
        "{text}"
    );
    assert!(text.contains("PARTSTAT=NEEDS-ACTION:mailto:dan@example.org"), "{text}");
    assert!(text.contains("PARTSTAT=ACCEPTED:mailto:anna@example.org"), "{text}");
}

// ---------------------------------------------------------------------------------------------------------------
// Text from clients never becomes structure
// ---------------------------------------------------------------------------------------------------------------

const EVIL: &str = "x\r\nATTENDEE;ROLE=CHAIR:mailto:evil@example.org\r\nX-INJECT:1";

#[test]
fn text_fields_keep_their_value_and_add_no_properties() {
    let limits = limits();
    let uid = uid();
    let patch = EventData {
        summary: Some(EVIL.to_owned()),
        description: Some(EVIL.to_owned()),
        location: Some(EVIL.to_owned()),
        categories: Some(vec![EVIL.to_owned()]),
        start: Some(utc(1, 10)),
        alarms: Some(vec![EventAlarm {
            action: AlarmAction::Display,
            trigger: AlarmTrigger::Relative {
                offset: EventDuration::parse("-PT5M").unwrap(),
                related: AlarmRelated::Start,
            },
            description: Some(EVIL.to_owned()),
        }]),
        ..EventData::default()
    };
    let merged = merge_event(None, &patch, &context(&uid, &limits, EditScope::All)).unwrap();
    let text = text_of(&merged);
    assert!(
        !text
            .lines()
            .any(|line| line.starts_with("ATTENDEE") || line.starts_with("X-INJECT")),
        "{text}"
    );
    let read = to_event_data(&merged, None).unwrap();
    let expected = "x\nATTENDEE;ROLE=CHAIR:mailto:evil@example.org\nX-INJECT:1";
    assert_eq!(read.summary.as_deref(), Some(expected));
    assert_eq!(read.description.as_deref(), Some(expected));
    assert_eq!(read.location.as_deref(), Some(expected));
    assert_eq!(read.categories, Some(vec![expected.to_owned()]));
    assert_eq!(read.attendees, None);
    assert_eq!(read.alarms.unwrap()[0].description.as_deref(), Some(expected));
}

#[test]
fn parameter_values_cannot_leave_their_parameter() {
    let limits = limits();
    let uid = uid();
    let hostile = "Eve\";ROLE=CHAIR:mailto:evil@example.org\r\nATTENDEE:mailto:evil2@example.org";
    let patch = EventData {
        start: Some(utc(1, 10)),
        organizer: Some(EventOrganizer {
            address: CalendarUserAddress::parse("mailto:anna@example.org").unwrap(),
            common_name: Some(hostile.to_owned()),
            sent_by: Some(CalendarUserAddress::parse("mailto:pa@example.org").unwrap()),
        }),
        attendees: Some(vec![EventAttendee {
            common_name: Some(hostile.to_owned()),
            ..attendee("mailto:bob@example.org", None)
        }]),
        ..EventData::default()
    };
    let merged = merge_event(None, &patch, &context(&uid, &limits, EditScope::All)).unwrap();
    let read = to_event_data(&merged, None).unwrap();
    let cleaned = "Eve;ROLE=CHAIR:mailto:evil@example.orgATTENDEE:mailto:evil2@example.org";
    let bob = &read.attendees.unwrap()[0];
    assert_eq!(bob.common_name.as_deref(), Some(cleaned));
    assert_eq!(bob.role, None, "the injected ROLE is part of the name");
    assert_eq!(bob.address.as_str(), "mailto:bob@example.org");
    assert_eq!(read.organizer.unwrap().common_name.as_deref(), Some(cleaned));
    assert!(
        !text_of(&merged)
            .lines()
            .any(|line| line.starts_with("ATTENDEE:mailto:evil"))
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Removing instances
// ---------------------------------------------------------------------------------------------------------------

const UTC_SERIES: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
    DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\n\
    RDATE;VALUE=PERIOD:20270305T100000Z/PT2H,20270310T100000Z/PT1H\r\n\
    EXDATE:20270302T100000Z,20270312T100000Z\r\nSUMMARY:Daily\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

#[test]
fn removing_the_future_cuts_lists_of_dates_value_by_value() {
    let stored = parsed(UTC_SERIES);
    let cut = remove_instances(&stored, &utc(10, 10), EditScope::ThisAndFuture)
        .unwrap()
        .unwrap();
    let text = text_of(&cut);
    // The rule ended before the cut and stays as it is; the periods and the exclusions before the cut stay.
    assert!(text.contains("RRULE:FREQ=DAILY;COUNT=3\r\n"), "{text}");
    assert!(text.contains("RDATE;VALUE=PERIOD:20270305T100000Z/PT2H\r\n"), "{text}");
    assert!(!text.contains("20270310"), "{text}");
    assert!(
        text.contains("EXDATE:20270302T100000Z\r\n") && !text.contains("20270312"),
        "{text}"
    );
}

#[test]
fn removing_from_a_series_of_recurrence_dates_only_works() {
    let stored = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n\
         RDATE:20270305T100000Z,20270308T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let cut = remove_instances(&stored, &utc(8, 10), EditScope::ThisAndFuture)
        .unwrap()
        .unwrap();
    let text = text_of(&cut);
    assert!(
        text.contains("RDATE:20270305T100000Z\r\n") && !text.contains("20270308"),
        "{text}"
    );
}

#[test]
fn removing_instances_obeys_the_configured_limits() {
    let stored = parsed(SERIES);
    // Looking for the instance needs the steps of the series.
    let tight = IcalLimits {
        max_iterator_steps: 2,
        ..IcalLimits::default()
    };
    assert_eq!(
        remove_instances_with_limits(&stored, &berlin(3, 10), EditScope::This, &tight),
        Err(IcalError::Limit(LimitKind::IteratorSteps))
    );
    // Every removal adds an EXDATE; the result may not pass max_recurrence_dates.
    let few = IcalLimits {
        max_recurrence_dates: 2,
        ..IcalLimits::default()
    };
    let one = remove_instances_with_limits(&stored, &berlin(2, 10), EditScope::This, &few)
        .unwrap()
        .unwrap();
    let two = remove_instances_with_limits(&one, &berlin(3, 10), EditScope::This, &few)
        .unwrap()
        .unwrap();
    assert_eq!(
        remove_instances_with_limits(&two, &berlin(4, 10), EditScope::This, &few),
        Err(IcalError::Limit(LimitKind::RecurrenceDates))
    );
}

// ---------------------------------------------------------------------------------------------------------------
// `null` removes a field (RFC 7396)
// ---------------------------------------------------------------------------------------------------------------

/// An event that has a value for every field a write can remove, an unknown property and an alarm.
const FULL: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\n\
    DTSTAMP:20260101T000000Z\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\n\
    SUMMARY:Planning\r\nDESCRIPTION:Agenda\r\nLOCATION:Room 1\r\nSTATUS:CONFIRMED\r\nTRANSP:OPAQUE\r\nCLASS:PRIVATE\r\n\
    RRULE:FREQ=WEEKLY;COUNT=4\r\nRDATE;TZID=Europe/Berlin:20270303T100000\r\nEXDATE;TZID=Europe/Berlin:20270308T100000\r\n\
    ORGANIZER;CN=Anna:mailto:anna@example.org\r\nATTENDEE;CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.org\r\n\
    CATEGORIES:work,team\r\nURL:https://example.org/meeting\r\nSEQUENCE:2\r\nX-KEEP;X-P=1:kept\r\n\
    BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

fn merged_with(stored: &ParsedCalendar, patch: &EventData) -> Result<ParsedCalendar, IcalError> {
    let limits = limits();
    let uid = uid();
    merge_event(Some(stored), patch, &context(&uid, &limits, EditScope::All))
}

/// `data` without the member of `field`.
fn without_member(mut data: EventData, field: EventField) -> EventData {
    match field {
        EventField::Summary => data.summary = None,
        EventField::Description => data.description = None,
        EventField::Location => data.location = None,
        EventField::End => data.end = None,
        EventField::Duration => data.duration = None,
        EventField::Status => data.status = None,
        EventField::Transparency => data.transparency = None,
        EventField::Class => data.class = None,
        EventField::Recurrence => data.recurrence = None,
        EventField::Organizer => data.organizer = None,
        EventField::Attendees => data.attendees = None,
        EventField::Categories => data.categories = None,
        EventField::Url => data.url = None,
        EventField::Alarms => data.alarms = None,
        _ => unreachable!("a field was added to EventField: teach this helper and the merge"),
    }
    data
}

#[test]
fn null_removes_exactly_the_field_it_names() {
    let stored = parsed(FULL);
    let before = to_event_data(&stored, None).unwrap();
    for field in EventField::ALL.iter().copied() {
        if field == EventField::Duration {
            continue; // the event has an end, not a duration: see the test of the length below
        }
        // The organizer goes with the attendees: an event that is scheduled names its organizer.
        let (patch, expected) = if field == EventField::Organizer {
            (
                EventData::default().without(field).without(EventField::Attendees),
                without_member(without_member(before.clone(), field), EventField::Attendees),
            )
        } else {
            (
                EventData::default().without(field),
                without_member(before.clone(), field),
            )
        };
        let merged = merged_with(&stored, &patch).unwrap();
        let after = to_event_data(&merged, None).unwrap();
        assert_eq!(after, expected, "{field:?}: the field is gone and nothing else changed");
        let text = text_of(&merged);
        assert!(
            text.contains("X-KEEP;X-P=1:kept\r\n"),
            "{field:?}: what the model does not know stays: {text}"
        );
    }
}

#[test]
fn null_removes_the_properties_from_the_stored_text() {
    let stored = parsed(FULL);
    for (field, names) in [
        (EventField::Summary, vec!["SUMMARY"]),
        (EventField::Description, vec!["DESCRIPTION:Agenda"]),
        (EventField::Location, vec!["LOCATION"]),
        (EventField::End, vec!["DTEND"]),
        (EventField::Status, vec!["STATUS"]),
        (EventField::Transparency, vec!["TRANSP"]),
        (EventField::Class, vec!["CLASS"]),
        (EventField::Recurrence, vec!["RRULE:FREQ=WEEKLY", "RDATE", "EXDATE"]),
        (EventField::Organizer, vec!["ORGANIZER", "ATTENDEE"]),
        (EventField::Attendees, vec!["ATTENDEE"]),
        (EventField::Categories, vec!["CATEGORIES"]),
        (EventField::Url, vec!["URL"]),
        (EventField::Alarms, vec!["BEGIN:VALARM", "TRIGGER"]),
    ] {
        let patch = if field == EventField::Organizer {
            EventData::default().without(field).without(EventField::Attendees)
        } else {
            EventData::default().without(field)
        };
        let merged = merged_with(&stored, &patch).unwrap();
        let text = text_of(&merged);
        for name in names {
            assert!(!text.contains(name), "{field:?} must remove {name}: {text}");
        }
        assert!(
            text.contains("DTSTART;TZID=Europe/Berlin:20270301T100000\r\n"),
            "{field:?}: {text}"
        );
        assert!(
            text.contains("SEQUENCE:2\r\n"),
            "the write does not touch the sequence: {text}"
        );
    }
}

#[test]
fn null_for_what_is_not_there_changes_nothing() {
    // A client that sends every field, with null for the empty ones, every day must not move the content hash.
    let created = create(&EventData {
        summary: Some("Planning".to_owned()),
        start: Some(berlin(1, 10)),
        end: Some(berlin(1, 11)),
        ..EventData::default()
    });
    let mut patch = EventData::default();
    for field in EventField::ALL.iter().copied() {
        patch = patch.without(field);
    }
    patch.summary = Some("Planning".to_owned());
    patch.end = Some(berlin(1, 11));
    patch.removed.remove(&EventField::Summary);
    patch.removed.remove(&EventField::End);
    let merged = merged_with(&created, &patch).unwrap();
    assert_eq!(content_hash(&merged).unwrap(), content_hash(&created).unwrap());
    assert_eq!(
        to_event_data(&merged, None).unwrap(),
        to_event_data(&created, None).unwrap()
    );
}

#[test]
fn a_resent_event_with_null_repairs_what_drifted_and_then_stays_quiet() {
    let stored = parsed(FULL);
    let resend = EventData {
        summary: Some("Planning".to_owned()),
        ..EventData::default()
    }
    .without(EventField::Location)
    .without(EventField::Url);
    let repaired = merged_with(&stored, &resend).unwrap();
    let text = text_of(&repaired);
    assert!(!text.contains("LOCATION") && !text.contains("URL:"), "{text}");
    assert_ne!(content_hash(&repaired).unwrap(), content_hash(&stored).unwrap());
    let again = merged_with(&repaired, &resend).unwrap();
    assert_eq!(content_hash(&again).unwrap(), content_hash(&repaired).unwrap());
}

#[test]
fn the_end_and_the_duration_can_be_removed_and_replaced_by_each_other() {
    let with_end = parsed(FULL);
    // `null` for the end removes it, and the event has none.
    let open = merged_with(&with_end, &EventData::default().without(EventField::End)).unwrap();
    let data = to_event_data(&open, None).unwrap();
    assert_eq!((data.end, data.duration), (None, None));
    // The start that moves with it does not drag a removed end along.
    let moved = merged_with(
        &with_end,
        &EventData {
            start: Some(berlin(5, 14)),
            ..EventData::default()
        }
        .without(EventField::End),
    )
    .unwrap();
    let data = to_event_data(&moved, None).unwrap();
    assert_eq!((data.start, data.end, data.duration), (Some(berlin(5, 14)), None, None));
    // A duration for an event that has an end replaces the end; `null` for the duration then removes it.
    let lasting = merged_with(
        &with_end,
        &EventData {
            duration: Some(EventDuration::parse("PT2H").unwrap()),
            ..EventData::default()
        },
    )
    .unwrap();
    let data = to_event_data(&lasting, None).unwrap();
    assert_eq!(
        (data.end, data.duration.as_ref().map(EventDuration::as_str)),
        (None, Some("PT2H"))
    );
    let without = merged_with(&lasting, &EventData::default().without(EventField::Duration)).unwrap();
    assert_eq!(to_event_data(&without, None).unwrap().duration, None);
    // `null` for the duration of an event that has an end leaves the end, which the start still moves along.
    let shifted = merged_with(
        &with_end,
        &EventData {
            start: Some(berlin(5, 14)),
            ..EventData::default()
        }
        .without(EventField::Duration),
    )
    .unwrap();
    let data = to_event_data(&shifted, None).unwrap();
    assert_eq!((data.start, data.end), (Some(berlin(5, 14)), Some(berlin(5, 15))));
    // An end together with `null` for the duration is no conflict.
    let new_end = merged_with(
        &lasting,
        &EventData {
            end: Some(berlin(1, 13)),
            ..EventData::default()
        }
        .without(EventField::Duration),
    )
    .unwrap();
    let data = to_event_data(&new_end, None).unwrap();
    assert_eq!((data.end, data.duration), (Some(berlin(1, 13)), None));
}

#[test]
fn a_to_do_loses_its_due_date_with_the_end() {
    let todo = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VTODO\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
         DTSTART:20270301T100000Z\r\nDUE:20270302T100000Z\r\nSUMMARY:Task\r\nEND:VTODO\r\nEND:VCALENDAR\r\n",
    );
    let merged = merged_with(&todo, &EventData::default().without(EventField::End)).unwrap();
    let text = text_of(&merged);
    assert!(!text.contains("DUE") && text.contains("SUMMARY:Task"), "{text}");
}

#[test]
fn a_field_cannot_be_given_and_removed_in_one_write() {
    let stored = parsed(FULL);
    // `without` drops the value, so the state is built by hand, as a client that builds a request in code could.
    let mut both = EventData {
        location: Some("Room 2".to_owned()),
        ..EventData::default()
    };
    both.removed.insert(EventField::Location);
    assert!(matches!(merged_with(&stored, &both), Err(IcalError::Invalid(_))));
}

#[test]
fn the_organizer_cannot_be_removed_while_attendees_remain() {
    // RFC 5545 section 3.8.4.3: an event with attendees names its organizer. An object with attendees and no
    // organizer is a meeting without an owner for every scheduling client.
    let stored = parsed(FULL);
    let refused = merged_with(&stored, &EventData::default().without(EventField::Organizer));
    let Err(IcalError::Invalid(message)) = refused else {
        panic!("removing the organizer of an event with attendees is refused: {refused:?}");
    };
    assert!(
        message.contains("`organizer`") && message.contains("attendees"),
        "{message}"
    );
    // Attendees that the same write still sends do not help.
    let still = EventData {
        attendees: Some(vec![EventAttendee {
            address: CalendarUserAddress::parse("mailto:bob@example.org").unwrap(),
            common_name: None,
            partstat: None,
            role: None,
            cutype: None,
            rsvp: None,
            schedule_agent: None,
        }]),
        ..EventData::default()
    }
    .without(EventField::Organizer);
    assert!(matches!(merged_with(&stored, &still), Err(IcalError::Invalid(_))));
    // Removing both in one write is fine, and so is removing the organizer of an event that has no attendees.
    let both = merged_with(
        &stored,
        &EventData::default()
            .without(EventField::Organizer)
            .without(EventField::Attendees),
    )
    .unwrap();
    let text = text_of(&both);
    assert!(!text.contains("ORGANIZER") && !text.contains("ATTENDEE"), "{text}");
    let alone = merged_with(&both, &EventData::default().without(EventField::Organizer)).unwrap();
    assert_eq!(content_hash(&alone).unwrap(), content_hash(&both).unwrap());
    let organized = merged_with(
        &both,
        &EventData {
            organizer: Some(EventOrganizer {
                address: CalendarUserAddress::parse("mailto:anna@example.org").unwrap(),
                common_name: None,
                sent_by: None,
            }),
            ..EventData::default()
        },
    )
    .unwrap();
    let removed = merged_with(&organized, &EventData::default().without(EventField::Organizer)).unwrap();
    assert!(!text_of(&removed).contains("ORGANIZER"));
}

#[test]
fn a_write_that_leaves_the_organizer_alone_edits_an_object_that_has_attendees_and_none() {
    // The rule is about the write that removes the organizer, not about objects that arrived without one.
    let orphan = parsed(&FULL.replace("ORGANIZER;CN=Anna:mailto:anna@example.org\r\n", ""));
    let merged = merged_with(
        &orphan,
        &EventData {
            summary: Some("Renamed".to_owned()),
            ..EventData::default()
        },
    )
    .unwrap();
    assert!(text_of(&merged).contains("SUMMARY:Renamed"));
    let again = merged_with(&orphan, &EventData::default().without(EventField::Organizer));
    assert!(
        matches!(again, Err(IcalError::Invalid(_))),
        "removing what is not there is still refused while attendees remain"
    );
}

#[test]
fn the_organizer_of_the_master_of_a_series_with_overrides_cannot_be_removed_alone() {
    // Every component of an object names the same organizer (CalDAV `same-organizer-in-all-components`), so the
    // organizer of a series that has overrides goes with all of them or with none.
    let series = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
         DTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\nRRULE:FREQ=DAILY;COUNT=5\r\n\
         SUMMARY:Daily\r\nORGANIZER:mailto:anna@example.org\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:merge-1\r\n\
         DTSTAMP:20260101T000000Z\r\nRECURRENCE-ID;TZID=Europe/Berlin:20270302T100000\r\n\
         DTSTART;TZID=Europe/Berlin:20270302T140000\r\nDTEND;TZID=Europe/Berlin:20270302T150000\r\nSUMMARY:Moved\r\n\
         ORGANIZER:mailto:anna@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let refused = merged_with(&series, &EventData::default().without(EventField::Organizer));
    assert!(
        matches!(refused, Err(IcalError::OrganizerMismatch(_))),
        "the master alone: {refused:?}"
    );
}

#[test]
fn a_nested_value_replaces_the_stored_one_as_a_whole_and_attendees_are_matched_by_address() {
    // RFC 7396 holds for the members of the event, and no deeper: an object or a list that is sent replaces the
    // stored one. A client that adds an exclusion with `{"recurrence": {"exdates": [..]}}` loses the rule.
    let stored = parsed(FULL);
    let exdate = EventTime::Zoned {
        local: NaiveDate::from_ymd_opt(2027, 3, 15)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap(),
        zone: TimeZoneName::parse("Europe/Berlin").unwrap(),
    };
    let merged = merged_with(
        &stored,
        &EventData {
            recurrence: Some(Recurrence {
                exdates: vec![exdate],
                ..Recurrence::default()
            }),
            organizer: Some(EventOrganizer {
                address: CalendarUserAddress::parse("mailto:anna@example.org").unwrap(),
                common_name: None,
                sent_by: None,
            }),
            attendees: Some(vec![EventAttendee {
                address: CalendarUserAddress::parse("mailto:bob@example.org").unwrap(),
                common_name: None,
                partstat: None,
                role: Some(Role::OptParticipant),
                cutype: None,
                rsvp: None,
                schedule_agent: None,
            }]),
            ..EventData::default()
        },
    )
    .unwrap();
    let text = text_of(&merged);
    assert!(
        !text.contains("RRULE:FREQ=WEEKLY") && !text.contains("RDATE"),
        "the recurrence group is replaced as a whole: {text}"
    );
    assert!(text.contains("EXDATE;TZID=Europe/Berlin:20270315T100000"), "{text}");
    assert!(
        text.contains("ORGANIZER:mailto:anna@example.org") && !text.contains("CN=Anna"),
        "an organizer that is sent replaces the stored one, its name included: {text}"
    );
    assert!(
        text.contains("CN=Bob") && text.contains("PARTSTAT=ACCEPTED") && text.contains("ROLE=OPT-PARTICIPANT"),
        "an attendee is matched by address and keeps the parameters that are not sent: {text}"
    );
}

#[test]
fn null_works_on_an_instance_and_on_a_split() {
    let stored = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
         DTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\nRRULE:FREQ=DAILY;COUNT=5\r\n\
         SUMMARY:Daily\r\nLOCATION:Room 1\r\nDESCRIPTION:Agenda\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let limits = limits();
    let uid = uid();
    // One instance: the override loses the location, the series keeps it.
    let patch = EventData {
        recurrence_id: Some(berlin(2, 10)),
        ..EventData::default()
    }
    .without(EventField::Location);
    let merged = merge_event(Some(&stored), &patch, &context(&uid, &limits, EditScope::This)).unwrap();
    assert_eq!(
        to_event_data(&merged, None).unwrap().location.as_deref(),
        Some("Room 1")
    );
    let instance = to_event_data(&merged, Some(&berlin(2, 10))).unwrap();
    assert_eq!(
        (instance.location, instance.description.as_deref()),
        (None, Some("Agenda"))
    );
    // This and the following instances: the new series loses the description, the old one keeps it.
    let patch = EventData {
        recurrence_id: Some(berlin(3, 10)),
        ..EventData::default()
    }
    .without(EventField::Description);
    let split = merge_event_split(&stored, &patch, &split_context(&uid, &limits), &continuation_uid()).unwrap();
    let earlier = to_event_data(&split.earlier.unwrap(), None).unwrap();
    assert_eq!(earlier.description.as_deref(), Some("Agenda"));
    let tail = to_event_data(&split.continuation, None).unwrap();
    assert_eq!((tail.description, tail.location.as_deref()), (None, Some("Room 1")));
}

// ---------------------------------------------------------------------------------------------------------------
// Editing this and all following instances
// ---------------------------------------------------------------------------------------------------------------

fn split_context<'a>(uid: &'a Uid, limits: &'a IcalLimits) -> MergeContext<'a> {
    context(uid, limits, EditScope::ThisAndFuture)
}

fn continuation_uid() -> Uid {
    Uid::parse("merge-2").unwrap()
}

fn instance_starts(calendar: &ParsedCalendar) -> Vec<DateTime<Utc>> {
    let range = crate::filter::TimeRange::new(
        Some(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()),
        Some(Utc.with_ymd_and_hms(2027, 12, 31, 0, 0, 0).unwrap()),
    );
    crate::expand::expand(calendar, &range, &limits())
        .unwrap()
        .iter()
        .map(|instance| instance.start)
        .collect()
}

fn at(day: u32, hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 3, day, hour, 0, 0).unwrap()
}

#[test]
fn a_this_and_future_edit_cuts_the_series_and_starts_a_new_one() {
    let stored = parsed(SERIES);
    let limits = limits();
    let uid = uid();
    let patch = EventData {
        recurrence_id: Some(berlin(3, 10)),
        summary: Some("From now on".to_owned()),
        start: Some(berlin(3, 15)),
        ..EventData::default()
    };
    let split = merge_event_split(&stored, &patch, &split_context(&uid, &limits), &continuation_uid()).unwrap();
    let earlier = split.earlier.expect("the series had earlier instances");
    let earlier_text = text_of(&earlier);
    assert!(earlier_text.contains("UID:merge-1\r\n"), "{earlier_text}");
    assert!(
        earlier_text.contains("RRULE:FREQ=DAILY;UNTIL=20270303T085959Z\r\n"),
        "{earlier_text}"
    );
    assert!(!earlier_text.contains("COUNT="), "{earlier_text}");
    assert!(
        !earlier_text.contains("RECURRENCE-ID"),
        "no RANGE=THISANDFUTURE overrides: {earlier_text}"
    );
    assert_eq!(instance_starts(&earlier), vec![at(1, 9), at(2, 9)]);

    let tail = text_of(&split.continuation);
    assert!(
        tail.contains("UID:merge-2\r\n") && !tail.contains("UID:merge-1"),
        "{tail}"
    );
    assert!(
        tail.contains("DTSTART;TZID=Europe/Berlin:20270303T150000\r\n"),
        "{tail}"
    );
    assert!(tail.contains("DTEND;TZID=Europe/Berlin:20270303T160000\r\n"), "{tail}");
    assert!(
        tail.contains("RRULE:FREQ=DAILY;COUNT=3\r\n"),
        "the count is reduced by the cut: {tail}"
    );
    assert!(
        tail.contains("SUMMARY:From now on\r\n") && tail.contains("X-KEEP:1\r\n"),
        "{tail}"
    );
    assert!(tail.contains("SEQUENCE:0\r\n"), "{tail}");
    assert!(!tail.contains("RANGE=THISANDFUTURE"), "{tail}");
    assert_eq!(
        instance_starts(&split.continuation),
        vec![at(3, 14), at(4, 14), at(5, 14)]
    );
    // Together they are the old series with the new time from the cut on.
    let all: Vec<DateTime<Utc>> = instance_starts(&earlier)
        .into_iter()
        .chain(instance_starts(&split.continuation))
        .collect();
    assert_eq!(all.len(), 5);
}

#[test]
fn later_overrides_and_dates_move_to_the_new_series() {
    let limits = limits();
    let uid = uid();
    let ctx = context(&uid, &limits, EditScope::This);
    let mut stored = parsed(SERIES);
    for (day, summary) in [(2, "Two"), (4, "Four")] {
        stored = merge_event(
            Some(&stored),
            &EventData {
                recurrence_id: Some(berlin(day, 10)),
                summary: Some(summary.to_owned()),
                ..EventData::default()
            },
            &ctx,
        )
        .unwrap();
    }
    let with_dates = parsed(&text_of(&stored).replace(
        "RRULE:FREQ=DAILY;COUNT=5\r\n",
        "RRULE:FREQ=DAILY;COUNT=5\r\n\
                 EXDATE;TZID=Europe/Berlin:20270302T100000,20270304T100000\r\n\
                 RDATE;TZID=Europe/Berlin:20270310T100000\r\n",
    ));
    let patch = EventData {
        recurrence_id: Some(berlin(3, 10)),
        summary: Some("From three".to_owned()),
        ..EventData::default()
    };
    let split = merge_event_split(&with_dates, &patch, &split_context(&uid, &limits), &continuation_uid()).unwrap();
    let earlier = text_of(&split.earlier.unwrap());
    assert!(
        earlier.contains("SUMMARY:Two") && !earlier.contains("SUMMARY:Four"),
        "{earlier}"
    );
    assert!(
        earlier.contains("EXDATE;TZID=Europe/Berlin:20270302T100000\r\n"),
        "{earlier}"
    );
    assert!(
        !earlier.contains("20270304") && !earlier.contains("20270310"),
        "{earlier}"
    );
    let tail = text_of(&split.continuation);
    assert!(tail.contains("SUMMARY:Four") && !tail.contains("SUMMARY:Two"), "{tail}");
    assert_eq!(
        tail.matches("UID:merge-2").count(),
        2,
        "master and the later override: {tail}"
    );
    assert!(tail.contains("EXDATE;TZID=Europe/Berlin:20270304T100000\r\n"), "{tail}");
    assert!(tail.contains("RDATE;TZID=Europe/Berlin:20270310T100000\r\n"), "{tail}");
    assert!(!tail.contains("20270302"), "{tail}");
}

#[test]
fn the_new_series_starts_from_the_instance_as_it_is_shown() {
    let limits = limits();
    let uid = uid();
    let stored = merge_event(
        Some(&parsed(SERIES)),
        &EventData {
            recurrence_id: Some(berlin(3, 10)),
            summary: Some("Moved and renamed".to_owned()),
            start: Some(berlin(3, 12)),
            ..EventData::default()
        },
        &context(&uid, &limits, EditScope::This),
    )
    .unwrap();
    let split = merge_event_split(
        &stored,
        &EventData {
            recurrence_id: Some(berlin(3, 10)),
            location: Some("Room 7".to_owned()),
            ..EventData::default()
        },
        &split_context(&uid, &limits),
        &continuation_uid(),
    )
    .unwrap();
    let tail = text_of(&split.continuation);
    assert!(
        tail.contains("DTSTART;TZID=Europe/Berlin:20270303T120000\r\n"),
        "{tail}"
    );
    assert!(
        tail.contains("SUMMARY:Moved and renamed\r\n") && tail.contains("LOCATION:Room 7\r\n"),
        "{tail}"
    );
    assert_eq!(
        tail.matches("BEGIN:VEVENT").count(),
        1,
        "the override became the master: {tail}"
    );
    assert!(!tail.contains("RECURRENCE-ID"), "{tail}");
}

#[test]
fn splitting_at_the_first_instance_edits_the_whole_object() {
    let limits = limits();
    let uid = uid();
    let split = merge_event_split(
        &parsed(SERIES),
        &EventData {
            recurrence_id: Some(berlin(1, 10)),
            summary: Some("Renamed".to_owned()),
            ..EventData::default()
        },
        &split_context(&uid, &limits),
        &continuation_uid(),
    )
    .unwrap();
    assert!(split.earlier.is_none());
    let tail = text_of(&split.continuation);
    assert!(
        tail.contains("UID:merge-1\r\n") && tail.contains("SUMMARY:Renamed\r\n"),
        "{tail}"
    );
    assert!(tail.contains("RRULE:FREQ=DAILY;COUNT=5\r\n"), "{tail}");
}

#[test]
fn an_instance_from_a_recurrence_date_after_the_rule_starts_a_series_without_a_rule() {
    let limits = limits();
    let uid = uid();
    let stored = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n\
         RRULE:FREQ=DAILY;COUNT=2\r\nRDATE:20270305T100000Z,20270308T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let split = merge_event_split(
        &stored,
        &EventData {
            recurrence_id: Some(utc(5, 10)),
            summary: Some("Late".to_owned()),
            ..EventData::default()
        },
        &split_context(&uid, &limits),
        &continuation_uid(),
    )
    .unwrap();
    let earlier = text_of(&split.earlier.unwrap());
    assert!(
        earlier.contains("RRULE:FREQ=DAILY;COUNT=2\r\n") && !earlier.contains("RDATE"),
        "{earlier}"
    );
    let tail = text_of(&split.continuation);
    assert!(!tail.contains("RRULE"), "{tail}");
    assert!(
        tail.contains("DTSTART:20270305T100000Z\r\n") && tail.contains("RDATE:20270308T100000Z\r\n"),
        "{tail}"
    );
    assert_eq!(instance_starts(&split.continuation), vec![at(5, 10), at(8, 10)]);
}

#[test]
fn a_split_needs_an_instance_and_a_uid_of_its_own() {
    let limits = limits();
    let uid = uid();
    let stored = parsed(SERIES);
    let ctx = split_context(&uid, &limits);
    let no_instance = EventData {
        recurrence_id: Some(berlin(20, 10)),
        ..EventData::default()
    };
    assert!(matches!(
        merge_event_split(&stored, &no_instance, &ctx, &continuation_uid()),
        Err(IcalError::Invalid(_))
    ));
    let no_rid = EventData::default();
    assert!(matches!(
        merge_event_split(&stored, &no_rid, &ctx, &continuation_uid()),
        Err(IcalError::Invalid(_))
    ));
    let patch = EventData {
        recurrence_id: Some(berlin(3, 10)),
        ..EventData::default()
    };
    assert!(matches!(
        merge_event_split(&stored, &patch, &ctx, &uid),
        Err(IcalError::Invalid(_))
    ));
}

#[test]
fn splitting_an_endless_series_in_a_zone_of_its_own_keeps_the_rule_and_the_zone_definition() {
    let limits = limits();
    let uid = uid();
    let stored = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VTIMEZONE\r\nTZID:Office\r\nBEGIN:STANDARD\r\n\
         DTSTART:19700101T000000\r\nTZOFFSETFROM:+0300\r\nTZOFFSETTO:+0300\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
         BEGIN:VTIMEZONE\r\nTZID:Unused\r\nBEGIN:STANDARD\r\nDTSTART:19700101T000000\r\nTZOFFSETFROM:+0500\r\n\
         TZOFFSETTO:+0500\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
         BEGIN:VEVENT\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;TZID=Office:20270301T100000\r\n\
         DTEND;TZID=Office:20270301T110000\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Weekly\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let split = merge_event_split(
        &stored,
        &EventData {
            recurrence_id: Some(utc(15, 7)),
            summary: Some("Weekly, renamed".to_owned()),
            ..EventData::default()
        },
        &split_context(&uid, &limits),
        &continuation_uid(),
    )
    .unwrap();
    let earlier = split.earlier.unwrap();
    // 10:00 at +03:00 is 07:00Z; the last instant that stays is a second before the instance of the 15th.
    assert!(
        text_of(&earlier).contains("RRULE:FREQ=WEEKLY;UNTIL=20270315T065959Z\r\n"),
        "{}",
        text_of(&earlier)
    );
    assert_eq!(instance_starts(&earlier), vec![at(1, 7), at(8, 7)]);
    let tail = text_of(&split.continuation);
    assert!(tail.contains("RRULE:FREQ=WEEKLY\r\n"), "still endless: {tail}");
    assert!(
        tail.contains("TZID:Office\r\n") && tail.contains("TZOFFSETTO:+0300\r\n"),
        "the definition the new series uses travels with it: {tail}"
    );
    assert!(!tail.contains("TZID:Unused"), "{tail}");
    assert_eq!(
        &instance_starts(&split.continuation)[..3],
        &[at(15, 7), at(22, 7), at(29, 7)]
    );
}

#[test]
fn a_this_and_future_edit_of_an_object_made_of_overrides_only_is_refused() {
    let limits = limits();
    let uid = uid();
    let only_override = parsed(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:merge-1\r\nDTSTAMP:20260101T000000Z\r\n\
         RECURRENCE-ID:20270303T100000Z\r\nDTSTART:20270303T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    let patch = EventData {
        recurrence_id: Some(utc(3, 10)),
        summary: Some("Only mine".to_owned()),
        ..EventData::default()
    };
    // An attendee invited to one instance has no series to cut, and no master to edit as a whole.
    assert_eq!(
        merge_event_split(
            &only_override,
            &patch,
            &split_context(&uid, &limits),
            &continuation_uid()
        ),
        Err(IcalError::Invalid("the object has no master component".to_owned()))
    );
    assert_eq!(
        merge_event(
            Some(&only_override),
            &EventData::default(),
            &context(&uid, &limits, EditScope::All)
        ),
        Err(IcalError::Invalid(
            "the object has no component without RECURRENCE-ID".to_owned()
        ))
    );
    // The instance itself can still be edited.
    let edited = merge_event(Some(&only_override), &patch, &context(&uid, &limits, EditScope::This)).unwrap();
    assert!(text_of(&edited).contains("SUMMARY:Only mine\r\n"));
}
