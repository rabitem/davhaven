//! Tests of the iTIP functions: the diff, the rules for organizer copies, messages, replies and the changes an
//! attendee may make.

use davhaven_domain::{CalendarUserAddress, EventTime, IcalLimits, ItipMethod, PartStat, TimeZoneName};
use std::fmt::Write as _;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};

use super::*;
use crate::error::{IcalError, LimitKind};
use crate::parse::{ParsedCalendar, parse};
use crate::serialize::serialize;

fn limits() -> IcalLimits {
    IcalLimits::default()
}

fn parsed(text: &str) -> ParsedCalendar {
    parse(text.as_bytes(), &limits()).unwrap()
}

fn address(text: &str) -> CalendarUserAddress {
    CalendarUserAddress::parse(text).unwrap()
}

fn unfolded(calendar: &ParsedCalendar) -> String {
    serialize(calendar).unwrap().replace("\r\n ", "")
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

fn event(body: &str) -> String {
    format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\n{body}END:VCALENDAR\r\n")
}

const MASTER: &str = "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
    DTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\n\
    SUMMARY:Planning\r\nLOCATION:Room 1\r\nORGANIZER;CN=Anna:mailto:anna@example.org\r\n\
    ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;RSVP=TRUE;SCHEDULE-STATUS=1.2:mailto:bob@example.org\r\n\
    ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:mailto:cleo@example.org\r\nX-APPLE-STRUCTURED-LOCATION:geo\r\n\
    BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\nEND:VEVENT\r\n";

fn series(extra: &str) -> String {
    event(&MASTER.replace(
        "END:VEVENT\r\n",
        &format!("RRULE:FREQ=DAILY;COUNT=5\r\n{extra}END:VEVENT\r\n"),
    ))
}

#[test]
fn a_new_object_is_created() {
    let new = parsed(&event(MASTER));
    let report = diff(None, &new, &limits()).unwrap();
    assert_eq!(report.instances.len(), 1);
    assert_eq!(report.instances[0].change, ChangeClass::Created);
    assert_eq!(
        report.added_attendees,
        vec![address("mailto:bob@example.org"), address("mailto:cleo@example.org")]
    );
    assert!(report.removed_attendees.is_empty() && !report.needs_sequence_bump);
}

#[test]
fn unchanged_data_and_volatile_edits_are_unchanged() {
    let old = parsed(&event(MASTER));
    let new = parsed(&event(
        &MASTER
            .replace("DTSTAMP:20270101T000000Z", "DTSTAMP:20270202T000000Z")
            .replace("SEQUENCE:1", "SEQUENCE:7"),
    ));
    let report = diff(Some(&old), &new, &limits()).unwrap();
    assert_eq!(report.instances[0].change, ChangeClass::Unchanged);
    assert!(!report.needs_sequence_bump);
    // A different encoding of the same time is not a change either.
    let utc = parsed(&event(
        &MASTER
            .replace("DTSTART;TZID=Europe/Berlin:20270301T100000", "DTSTART:20270301T090000Z")
            .replace("DTEND;TZID=Europe/Berlin:20270301T110000", "DURATION:PT1H"),
    ));
    let same = diff(Some(&old), &utc, &limits()).unwrap();
    assert_eq!(
        same.instances[0].change,
        ChangeClass::Unchanged,
        "{:?}",
        same.instances[0]
    );
}

#[test]
fn significant_changes_are_classified_and_name_their_properties() {
    let old = parsed(&event(MASTER));
    for (from, to, property) in [
        (
            "DTSTART;TZID=Europe/Berlin:20270301T100000",
            "DTSTART;TZID=Europe/Berlin:20270301T103000",
            "DTSTART",
        ),
        (
            "DTEND;TZID=Europe/Berlin:20270301T110000",
            "DTEND;TZID=Europe/Berlin:20270301T120000",
            "DTEND",
        ),
        ("SUMMARY:Planning", "SUMMARY:Planning II", "SUMMARY"),
        ("LOCATION:Room 1", "LOCATION:Room 2", "LOCATION"),
        ("SEQUENCE:1", "SEQUENCE:1\r\nSTATUS:TENTATIVE", "STATUS"),
    ] {
        let new = parsed(&event(&MASTER.replace(from, to)));
        let report = diff(Some(&old), &new, &limits()).unwrap();
        assert_eq!(report.instances[0].change, ChangeClass::Significant, "{property}");
        assert!(
            report.instances[0].changed_properties.contains(&property.to_owned()),
            "{property}"
        );
        assert!(
            report.needs_sequence_bump,
            "the client did not raise SEQUENCE ({property})"
        );
    }
    let bumped = parsed(&event(
        &MASTER
            .replace("SEQUENCE:1", "SEQUENCE:2")
            .replace("SUMMARY:Planning", "SUMMARY:Other"),
    ));
    assert!(!diff(Some(&old), &bumped, &limits()).unwrap().needs_sequence_bump);
}

#[test]
fn insignificant_changes_do_not_resend() {
    let old = parsed(&event(MASTER));
    for (from, to, property) in [
        (
            "SUMMARY:Planning",
            "SUMMARY:Planning\r\nDESCRIPTION:Agenda attached",
            "DESCRIPTION",
        ),
        ("TRIGGER:-PT15M", "TRIGGER:-PT30M", "VALARM"),
    ] {
        let new = parsed(&event(&MASTER.replace(from, to)));
        let report = diff(Some(&old), &new, &limits()).unwrap();
        assert_eq!(report.instances[0].change, ChangeClass::Insignificant, "{property}");
        assert_eq!(report.instances[0].changed_properties, vec![property.to_owned()]);
        assert!(!report.needs_sequence_bump);
    }
}

#[test]
fn attendees_that_come_and_go_are_reported() {
    let old = parsed(&event(MASTER));
    let new = parsed(&event(&MASTER.replace(
        "ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:mailto:cleo@example.org\r\n",
        "ATTENDEE;CN=Dan:mailto:dan@example.org\r\n",
    )));
    let report = diff(Some(&old), &new, &limits()).unwrap();
    assert_eq!(report.added_attendees, vec![address("mailto:dan@example.org")]);
    assert_eq!(report.removed_attendees, vec![address("mailto:cleo@example.org")]);
}

#[test]
fn the_organizers_own_attendee_line_is_not_a_recipient() {
    let with_organizer = MASTER.replace(
        "ATTENDEE;CN=Bob",
        "ATTENDEE;CN=Anna;PARTSTAT=ACCEPTED:mailto:anna@example.org\r\nATTENDEE;CN=Bob",
    );
    let created = diff(None, &parsed(&event(&with_organizer)), &limits()).unwrap();
    assert_eq!(
        created.added_attendees,
        vec![address("mailto:bob@example.org"), address("mailto:cleo@example.org")]
    );
    let removed = diff(
        Some(&parsed(&event(&with_organizer))),
        &parsed(&event(MASTER)),
        &limits(),
    )
    .unwrap();
    assert_eq!(removed.removed_attendees, Vec::new());
}

#[test]
fn a_new_override_that_moves_its_instance_is_a_significant_change() {
    let override_text = "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
        RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000\r\nDTSTART;TZID=Europe/Berlin:20270303T140000\r\n\
        DTEND;TZID=Europe/Berlin:20270303T150000\r\nSUMMARY:Planning\r\nLOCATION:Room 1\r\n\
        ORGANIZER;CN=Anna:mailto:anna@example.org\r\n\
        ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.org\r\n\
        ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:mailto:cleo@example.org\r\nEND:VEVENT\r\n";
    let base = series("");
    let old = parsed(&base);
    let with = |text: &str| parsed(&base.replace("END:VCALENDAR\r\n", &format!("{text}END:VCALENDAR\r\n")));
    let moved = with(override_text);
    let report = diff(Some(&old), &moved, &limits()).unwrap();
    let override_diff = report
        .instances
        .iter()
        .find(|instance| instance.recurrence_id.is_some())
        .unwrap();
    assert_eq!(override_diff.change, ChangeClass::Significant);
    assert_eq!(override_diff.changed_properties, vec!["DTEND", "DTSTART"]);
    assert!(
        report.needs_sequence_bump,
        "the override has the sequence of the series"
    );
    let update = apply_organizer_changes(Some(&old), &moved, &limits()).unwrap();
    let text = unfolded(&update.calendar);
    assert!(text.contains("SEQUENCE:2"), "{text}");
    assert!(
        text.contains("ATTENDEE;CN=Bob;PARTSTAT=NEEDS-ACTION:mailto:bob@example.org"),
        "{text}"
    );
    // Changing nothing about the instance but its description leaves it created.
    let same_time = override_text
        .replace("20270303T140000", "20270303T100000")
        .replace("20270303T150000", "20270303T110000")
        .replace("SUMMARY:Planning", "SUMMARY:Planning\r\nDESCRIPTION:Notes");
    let report = diff(Some(&old), &with(&same_time), &limits()).unwrap();
    let created = report
        .instances
        .iter()
        .find(|instance| instance.recurrence_id.is_some())
        .unwrap();
    assert_eq!(created.change, ChangeClass::Created);
    assert!(!report.needs_sequence_bump);
}

#[test]
fn overrides_exdates_and_removed_overrides_are_instances_of_their_own() {
    let override_text = "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
        RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000\r\nDTSTART;TZID=Europe/Berlin:20270303T140000\r\n\
        DTEND;TZID=Europe/Berlin:20270303T150000\r\nSUMMARY:Planning\r\nORGANIZER;CN=Anna:mailto:anna@example.org\r\n\
        ATTENDEE;CN=Bob:mailto:bob@example.org\r\nEND:VEVENT\r\n";
    let base = series("");
    let old = parsed(&base.replace("END:VCALENDAR\r\n", &format!("{override_text}END:VCALENDAR\r\n")));
    // The override moves again, a second instance is excluded, nothing else changes.
    let moved = base.replace(
        "END:VCALENDAR\r\n",
        &format!(
            "{}END:VCALENDAR\r\n",
            override_text
                .replace("20270303T140000", "20270303T160000")
                .replace("20270303T150000", "20270303T170000")
        ),
    );
    let new = parsed(&moved.replace(
        "RRULE:FREQ=DAILY;COUNT=5\r\n",
        "RRULE:FREQ=DAILY;COUNT=5\r\nEXDATE;TZID=Europe/Berlin:20270304T100000\r\n",
    ));
    let report = diff(Some(&old), &new, &limits()).unwrap();
    let changes: Vec<(Option<EventTime>, ChangeClass)> = report
        .instances
        .iter()
        .map(|instance| (instance.recurrence_id.clone(), instance.change))
        .collect();
    assert_eq!(
        changes,
        vec![
            (None, ChangeClass::Significant),
            (Some(berlin(3, 10)), ChangeClass::Significant)
        ]
    );
    assert_eq!(report.cancelled_instances, vec![berlin(4, 10)]);
    // Removing the override cancels its instance.
    let without = parsed(&base);
    let removed = diff(Some(&old), &without, &limits()).unwrap();
    assert!(
        removed
            .instances
            .iter()
            .any(|instance| instance.change == ChangeClass::Removed)
    );
    assert_eq!(removed.cancelled_instances, vec![berlin(3, 10)]);
}

#[test]
fn organizer_updates_raise_the_sequence_and_reset_the_answers() {
    let old = parsed(&event(MASTER));
    let new = parsed(&event(&MASTER.replace("LOCATION:Room 1", "LOCATION:Room 2")));
    let update = apply_organizer_changes(Some(&old), &new, &limits()).unwrap();
    let text = unfolded(&update.calendar);
    assert!(text.contains("SEQUENCE:2\r\n"), "{text}");
    assert_eq!(text.matches("PARTSTAT=NEEDS-ACTION").count(), 2, "{text}");
    assert!(!text.contains("PARTSTAT=ACCEPTED"), "{text}");
    assert_eq!(update.diff.instances[0].change, ChangeClass::Significant);
    // Insignificant edits leave participation alone.
    let quiet = parsed(&event(&MASTER.replace("TRIGGER:-PT15M", "TRIGGER:-PT30M")));
    let untouched = apply_organizer_changes(Some(&old), &quiet, &limits()).unwrap();
    assert!(unfolded(&untouched.calendar).contains("PARTSTAT=ACCEPTED"));
}

/// The moment the messages of the tests are built (later than the `DTSTAMP` of the stored copies).
fn stamp() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 2, 1, 10, 0, 0).unwrap()
}

fn spec(method: ItipMethod, recipient: &str) -> MessageSpec {
    MessageSpec::new(method, address(recipient), stamp())
}

#[test]
fn a_request_carries_only_the_recipient_and_nothing_private() {
    let source = parsed(&event(MASTER));
    let message = build_message(&source, &spec(ItipMethod::Request, "mailto:bob@example.org")).unwrap();
    assert_eq!(message.method, ItipMethod::Request);
    let text = unfolded(&message.calendar);
    assert!(text.contains("METHOD:REQUEST\r\n"), "{text}");
    assert!(text.contains("PRODID:-//Davhaven//iCalendar//EN"), "{text}");
    assert!(
        text.contains("mailto:bob@example.org") && !text.contains("cleo@"),
        "{text}"
    );
    assert!(
        !text.contains("VALARM") && !text.contains("X-APPLE") && !text.contains("SCHEDULE-STATUS"),
        "{text}"
    );
    assert!(
        text.contains("BEGIN:VTIMEZONE") && text.contains("TZID:Europe/Berlin"),
        "{text}"
    );
    assert!(text.contains("ORGANIZER;CN=Anna:mailto:anna@example.org"), "{text}");
    assert_eq!(
        build_message(&source, &spec(ItipMethod::Request, "mailto:zed@example.org")).map(|_| ()),
        Err(IcalError::Invalid("the attendee is not on the event".to_owned()))
    );
}

#[test]
fn a_cancel_marks_the_event_cancelled() {
    let source = parsed(&series(""));
    let whole = build_message(&source, &spec(ItipMethod::Cancel, "mailto:cleo@example.org")).unwrap();
    let text = unfolded(&whole.calendar);
    assert!(
        text.contains("METHOD:CANCEL\r\n") && text.contains("STATUS:CANCELLED\r\n"),
        "{text}"
    );
    let one = MessageSpec {
        scope: MessageScope::Instances(vec![berlin(3, 10)]),
        ..spec(ItipMethod::Cancel, "mailto:cleo@example.org")
    };
    let instance = build_message(&source, &one).unwrap();
    let text = unfolded(&instance.calendar);
    assert!(
        text.contains("RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000"),
        "{text}"
    );
    assert!(text.contains("DTSTART;TZID=Europe/Berlin:20270303T100000"), "{text}");
    assert!(!text.contains("RRULE:FREQ=DAILY"), "{text}");
}

#[test]
fn a_reply_comes_from_the_replying_attendee_only() {
    let source = parsed(&event(MASTER));
    let reply = MessageSpec {
        replying_attendee: Some(address("mailto:bob@example.org")),
        ..spec(ItipMethod::Reply, "mailto:anna@example.org")
    };
    let message = build_message(&source, &reply).unwrap();
    let text = unfolded(&message.calendar);
    assert!(text.contains("METHOD:REPLY\r\n"), "{text}");
    assert!(
        text.contains("ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:bob@example.org"),
        "{text}"
    );
    assert!(
        !text.contains("cleo@") && !text.contains("LOCATION") && !text.contains("VALARM"),
        "{text}"
    );
    assert!(
        text.contains("SUMMARY:Planning") && text.contains("UID:itip-1"),
        "{text}"
    );
    let without = spec(ItipMethod::Reply, "mailto:anna@example.org");
    assert_eq!(
        build_message(&source, &without).map(|_| ()),
        Err(IcalError::Invalid("a reply needs the replying attendee".to_owned()))
    );
    let stranger = MessageSpec {
        replying_attendee: Some(address("mailto:zed@example.org")),
        ..spec(ItipMethod::Reply, "mailto:anna@example.org")
    };
    assert_eq!(
        build_message(&source, &stranger).map(|_| ()),
        Err(IcalError::Invalid("the attendee is not on the event".to_owned()))
    );
    assert!(matches!(
        build_message(&source, &spec(ItipMethod::Publish, "mailto:bob@example.org")),
        Err(IcalError::Unsupported(_))
    ));
}

#[test]
fn messages_parse_and_are_checked() {
    let source = parsed(&event(MASTER));
    let request = build_message(&source, &spec(ItipMethod::Request, "mailto:bob@example.org")).unwrap();
    let text = serialize(&request.calendar).unwrap();
    let again = parse_message(text.as_bytes(), &limits()).unwrap();
    assert_eq!(again.method, ItipMethod::Request);
    assert_eq!(again.calendar, request.calendar);
    let second_event = "BEGIN:VEVENT\r\nUID:itip-2\r\nDTSTAMP:20270101T000000Z\r\nDTSTART:20270302T100000Z\r\n\
        ORGANIZER:mailto:anna@example.org\r\nATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let free_busy = "BEGIN:VFREEBUSY\r\nUID:itip-1\r\nDTSTAMP:20270101T000000Z\r\nORGANIZER:mailto:anna@example.org\r\n\
        END:VFREEBUSY\r\nEND:VCALENDAR\r\n";
    let only_header = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n";
    for (broken, reason) in [
        (text.replace("METHOD:REQUEST\r\n", ""), "the message has no METHOD"),
        (
            text.replace("METHOD:REQUEST", "METHOD:SHOUT"),
            "the METHOD is not an iTIP method",
        ),
        (
            text.replace("ORGANIZER;CN=Anna:mailto:anna@example.org\r\n", ""),
            "the message has no ORGANIZER",
        ),
        (
            text.replace(
                "ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:bob@example.org\r\n",
                "",
            ),
            "a REQUEST needs at least one ATTENDEE",
        ),
        (
            text.replace("UID:itip-1\r\n", ""),
            "a component of the message has no UID",
        ),
        (
            text.replace("END:VCALENDAR\r\n", second_event),
            "the components of the message have different UIDs",
        ),
        (
            text.replace("METHOD:REQUEST", "METHOD:CANCEL")
                .replace("END:VCALENDAR\r\n", free_busy),
            "the message holds a component that its METHOD does not allow",
        ),
        (only_header.to_owned(), "the message holds no component"),
        (
            event(MASTER).replace("BEGIN:VCALENDAR\r\n", "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\n"),
            "a REPLY needs exactly one ATTENDEE per component",
        ),
    ] {
        assert_eq!(
            parse_message(broken.as_bytes(), &limits()).map(|message| message.method),
            Err(IcalError::Invalid(reason.to_owned())),
            "{broken}"
        );
    }
    let bad_date = text.replace("DTSTART;TZID=Europe/Berlin:20270301T100000", "DTSTART:garbage");
    assert!(
        matches!(parse_message(bad_date.as_bytes(), &limits()), Err(IcalError::Invalid(message)) if message.contains("DTSTART")),
        "bad date"
    );
    // A free-busy request names no attendee and is allowed with REQUEST.
    let free_busy_request = only_header.replace("END:VCALENDAR\r\n", free_busy);
    assert_eq!(
        parse_message(free_busy_request.as_bytes(), &limits()).map(|message| message.method),
        Ok(ItipMethod::Request)
    );
}

#[test]
fn replies_update_the_organizer_copy() {
    let copy = parsed(&event(MASTER));
    let reply_text = event(
        "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270102T000000Z\r\nSEQUENCE:1\r\nORGANIZER:mailto:anna@example.org\r\n\
         ATTENDEE;PARTSTAT=DECLINED:mailto:bob@example.org\r\nEND:VEVENT\r\n",
    )
    .replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:REPLY\r\n");
    let reply = parse_message(reply_text.as_bytes(), &limits()).unwrap();
    let applied = apply_reply(&copy, &reply).unwrap();
    assert_eq!(applied.attendee, address("mailto:bob@example.org"));
    assert_eq!(applied.partstat, PartStat::Declined);
    assert!(applied.sequence_matches && applied.instances.is_empty());
    let text = unfolded(&applied.updated);
    assert!(text.contains("PARTSTAT=DECLINED"), "{text}");
    assert!(
        text.contains("PARTSTAT=TENTATIVE"),
        "other attendees keep their answers:\n{text}"
    );
    let stale = parse_message(reply_text.replace("SEQUENCE:1", "SEQUENCE:0").as_bytes(), &limits()).unwrap();
    assert!(!apply_reply(&copy, &stale).unwrap().sequence_matches);
    let stranger = parse_message(reply_text.replace("bob@", "zed@").as_bytes(), &limits()).unwrap();
    assert_eq!(
        apply_reply(&copy, &stranger).map(|_| ()),
        Err(IcalError::Invalid("the attendee is not on the event".to_owned()))
    );
    let not_a_reply = parse_message(
        reply_text.replace("METHOD:REPLY", "METHOD:CANCEL").as_bytes(),
        &limits(),
    )
    .unwrap();
    assert_eq!(
        apply_reply(&copy, &not_a_reply).map(|_| ()),
        Err(IcalError::Invalid("only a REPLY can be applied".to_owned()))
    );
}

#[test]
fn a_reply_to_one_instance_creates_an_override() {
    let copy = parsed(&series(""));
    let reply_text = event(
        "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270102T000000Z\r\nSEQUENCE:1\r\nORGANIZER:mailto:anna@example.org\r\n\
         RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000\r\nATTENDEE;PARTSTAT=DECLINED:mailto:bob@example.org\r\nEND:VEVENT\r\n",
    )
    .replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:REPLY\r\n");
    let reply = parse_message(reply_text.as_bytes(), &limits()).unwrap();
    let applied = apply_reply(&copy, &reply).unwrap();
    assert_eq!(applied.instances, vec![berlin(3, 10)]);
    let text = unfolded(&applied.updated);
    assert!(
        text.contains("RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000"),
        "{text}"
    );
    assert_eq!(text.matches("PARTSTAT=DECLINED").count(), 1, "{text}");
    assert_eq!(text.matches("BEGIN:VEVENT").count(), 2, "{text}");
    let missing = reply_text.replace("20270303T100000", "20270320T100000");
    let nowhere = parse_message(missing.as_bytes(), &limits()).unwrap();
    assert_eq!(
        apply_reply(&copy, &nowhere).map(|_| ()),
        Err(IcalError::Invalid(
            "the reply names an instance the event does not have".to_owned()
        ))
    );
}

#[test]
fn schedule_status_is_written_per_attendee() {
    let copy = parsed(&event(MASTER));
    let updated = set_schedule_status(&copy, &address("mailto:cleo@example.org"), "1.1").unwrap();
    let text = unfolded(&updated);
    assert!(
        text.contains("PARTSTAT=TENTATIVE;SCHEDULE-STATUS=1.1:mailto:cleo@example.org"),
        "{text}"
    );
    assert!(
        text.contains("SCHEDULE-STATUS=1.2:mailto:bob@example.org"),
        "the other attendee is untouched:\n{text}"
    );
    let replaced = set_schedule_status(&updated, &address("mailto:bob@example.org"), "3.7").unwrap();
    assert!(unfolded(&replaced).contains("SCHEDULE-STATUS=3.7:mailto:bob@example.org"));
    for bad in ["", "12", "1.", ".2", "1.x", "1.2.3.4", "1.2;DROP"] {
        assert!(
            set_schedule_status(&copy, &address("mailto:bob@example.org"), bad).is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(
        set_schedule_status(&copy, &address("mailto:zed@example.org"), "1.2").map(|_| ()),
        Err(IcalError::Invalid("the attendee is not on the event".to_owned()))
    );
    assert!(set_schedule_status(&copy, &address("mailto:bob@example.org"), "5.1").is_ok());
}

#[test]
fn schedule_parameters_are_stripped() {
    let copy = parsed(&event(&MASTER.replace(
        "RSVP=TRUE",
        "RSVP=TRUE;SCHEDULE-AGENT=CLIENT;SCHEDULE-FORCE-SEND=REQUEST",
    )));
    let text = unfolded(&strip_schedule_params(&copy).unwrap());
    assert!(!text.contains("SCHEDULE-"), "{text}");
    assert!(
        text.contains("PARTSTAT=ACCEPTED") && text.contains("RSVP=TRUE"),
        "{text}"
    );
}

#[test]
fn attendees_may_change_only_their_own_participation() {
    let old = parsed(&event(MASTER));
    let bob = address("mailto:bob@example.org");
    let allowed = |from: &str, to: &str| {
        let new = parsed(&event(&MASTER.replace(from, to)));
        attendee_change_violations(&old, &new, &bob).unwrap()
    };
    assert_eq!(allowed("PARTSTAT=ACCEPTED", "PARTSTAT=DECLINED;X-NEW=1").len(), 0);
    assert_eq!(allowed("TRIGGER:-PT15M", "TRIGGER:-PT1H").len(), 0);
    assert_eq!(
        allowed("X-APPLE-STRUCTURED-LOCATION:geo", "X-APPLE-STRUCTURED-LOCATION:other").len(),
        0
    );
    assert_eq!(allowed("DTSTAMP:20270101T000000Z", "DTSTAMP:20270909T000000Z").len(), 0);
    assert_eq!(allowed("SEQUENCE:1", "TRANSP:TRANSPARENT\r\nSEQUENCE:1").len(), 0);
    assert_eq!(
        allowed("SUMMARY:Planning", "SUMMARY:Hijacked"),
        vec!["SUMMARY".to_owned()]
    );
    assert_eq!(
        allowed(
            "DTSTART;TZID=Europe/Berlin:20270301T100000",
            "DTSTART;TZID=Europe/Berlin:20270301T110000"
        ),
        vec!["DTSTART".to_owned()]
    );
    assert_eq!(
        allowed("PARTSTAT=TENTATIVE", "PARTSTAT=ACCEPTED"),
        vec!["ATTENDEE".to_owned()],
        "somebody else's answer"
    );
    assert_eq!(allowed("SEQUENCE:1", "SEQUENCE:5"), vec!["SEQUENCE".to_owned()]);
    assert_eq!(
        allowed("mailto:anna@example.org", "mailto:mallory@example.org"),
        vec!["ORGANIZER".to_owned()]
    );
}

#[test]
fn attendees_may_add_the_override_of_an_instance_they_answer() {
    let old = parsed(&series(""));
    let bob = address("mailto:bob@example.org");
    let copy = "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
        RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000\r\nDTSTART;TZID=Europe/Berlin:20270303T100000\r\n\
        DTEND;TZID=Europe/Berlin:20270303T110000\r\nSUMMARY:Planning\r\nLOCATION:Room 1\r\nORGANIZER;CN=Anna:mailto:anna@example.org\r\n\
        ATTENDEE;CN=Bob;PARTSTAT=DECLINED;RSVP=TRUE:mailto:bob@example.org\r\n\
        ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:mailto:cleo@example.org\r\nEND:VEVENT\r\n";
    let with_override =
        |text: &str| parsed(&series("").replace("END:VCALENDAR\r\n", &format!("{text}END:VCALENDAR\r\n")));
    assert_eq!(
        attendee_change_violations(&old, &with_override(copy), &bob)
            .unwrap()
            .len(),
        0
    );
    let moved = copy.replace(
        "DTSTART;TZID=Europe/Berlin:20270303T100000",
        "DTSTART;TZID=Europe/Berlin:20270303T120000",
    );
    assert_eq!(
        attendee_change_violations(&old, &with_override(&moved), &bob).unwrap(),
        vec!["RECURRENCE-ID".to_owned()]
    );
    let retitled = copy.replace("SUMMARY:Planning", "SUMMARY:Other");
    assert_eq!(
        attendee_change_violations(&old, &with_override(&retitled), &bob).unwrap(),
        vec!["RECURRENCE-ID".to_owned()]
    );
    // Removing an override is not allowed.
    let removed = attendee_change_violations(&with_override(copy), &old, &bob).unwrap();
    assert_eq!(removed, vec!["RECURRENCE-ID".to_owned()]);
}

// ---------------------------------------------------------------------------------------------------------------
// The answers of the attendees are the server's
// ---------------------------------------------------------------------------------------------------------------

fn answer_of(calendar: &ParsedCalendar, who: &str) -> Option<String> {
    let text = unfolded(calendar);
    let line = text
        .lines()
        .find(|line| line.starts_with("ATTENDEE") && line.ends_with(&format!("mailto:{who}@example.org")))?;
    let found = line
        .split(';')
        .find_map(|part| part.strip_prefix("PARTSTAT="))
        .map(|rest| rest.split(':').next().unwrap_or(rest).to_owned());
    Some(found.unwrap_or_else(|| "NEEDS-ACTION".to_owned()))
}

fn status_of(calendar: &ParsedCalendar, who: &str) -> Option<String> {
    let text = unfolded(calendar);
    let line = text
        .lines()
        .find(|line| line.starts_with("ATTENDEE") && line.ends_with(&format!("mailto:{who}@example.org")))?;
    line.split(';')
        .find_map(|part| part.strip_prefix("SCHEDULE-STATUS="))
        .map(|rest| rest.split(':').next().unwrap_or(rest).to_owned())
}

#[test]
fn a_client_cannot_set_the_answers_of_the_attendees() {
    let old = parsed(&event(MASTER));
    let forged = MASTER
        .replace("PARTSTAT=TENTATIVE", "PARTSTAT=ACCEPTED")
        .replace("PARTSTAT=ACCEPTED;RSVP=TRUE;SCHEDULE-STATUS=1.2", "PARTSTAT=DECLINED;RSVP=TRUE")
        .replace(
            "X-APPLE-STRUCTURED-LOCATION:geo",
            "ATTENDEE;CN=Dan;PARTSTAT=ACCEPTED;SCHEDULE-STATUS=1.2:mailto:dan@example.org\r\nX-APPLE-STRUCTURED-LOCATION:geo",
        );
    let update = apply_organizer_changes(Some(&old), &parsed(&event(&forged)), &limits()).unwrap();
    let stored = &update.calendar;
    // Cleo and Bob keep what the server holds, Dan is new and starts open, nobody has a status the server
    // did not write.
    assert_eq!(answer_of(stored, "cleo").as_deref(), Some("TENTATIVE"));
    assert_eq!(answer_of(stored, "bob").as_deref(), Some("ACCEPTED"));
    assert_eq!(status_of(stored, "bob").as_deref(), Some("1.2"));
    assert_eq!(answer_of(stored, "dan").as_deref(), Some("NEEDS-ACTION"));
    assert_eq!(status_of(stored, "dan"), None);
    // A version that only differs in the answers is no change at all.
    assert_eq!(update.diff.instances[0].change, ChangeClass::Insignificant);
    let only_answers = MASTER.replace("PARTSTAT=TENTATIVE", "PARTSTAT=ACCEPTED");
    let same = apply_organizer_changes(Some(&old), &parsed(&event(&only_answers)), &limits()).unwrap();
    assert_eq!(same.diff.instances[0].change, ChangeClass::Unchanged);
    assert_eq!(answer_of(&same.calendar, "cleo").as_deref(), Some("TENTATIVE"));
}

#[test]
fn a_new_object_starts_with_open_answers_but_the_organizer_keeps_hers() {
    let with_organizer = MASTER.replace(
        "ATTENDEE;CN=Bob",
        "ATTENDEE;CN=Anna;PARTSTAT=ACCEPTED:mailto:anna@example.org\r\nATTENDEE;CN=Bob",
    );
    let update = apply_organizer_changes(None, &parsed(&event(&with_organizer)), &limits()).unwrap();
    assert_eq!(answer_of(&update.calendar, "bob").as_deref(), Some("NEEDS-ACTION"));
    assert_eq!(answer_of(&update.calendar, "cleo").as_deref(), Some("NEEDS-ACTION"));
    assert_eq!(answer_of(&update.calendar, "anna").as_deref(), Some("ACCEPTED"));
    assert_eq!(status_of(&update.calendar, "bob"), None);
}

#[test]
fn attendees_that_the_server_does_not_schedule_keep_the_answer_their_client_wrote() {
    let client_managed = MASTER.replace(
        "X-APPLE-STRUCTURED-LOCATION:geo",
        "ATTENDEE;CN=Dan;PARTSTAT=ACCEPTED;SCHEDULE-AGENT=CLIENT:mailto:dan@example.org\r\nX-APPLE-STRUCTURED-LOCATION:geo",
    );
    let update = apply_organizer_changes(None, &parsed(&event(&client_managed)), &limits()).unwrap();
    assert_eq!(answer_of(&update.calendar, "dan").as_deref(), Some("ACCEPTED"));
    assert_eq!(answer_of(&update.calendar, "bob").as_deref(), Some("NEEDS-ACTION"));
}

#[test]
fn a_new_override_starts_from_the_answers_of_the_series() {
    let base = series("");
    let old = parsed(&base);
    let override_text = "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
        RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000\r\nDTSTART;TZID=Europe/Berlin:20270303T100000\r\n\
        DTEND;TZID=Europe/Berlin:20270303T110000\r\nSUMMARY:Planning\r\nLOCATION:Room 1\r\n\
        ORGANIZER;CN=Anna:mailto:anna@example.org\r\n\
        ATTENDEE;CN=Bob;PARTSTAT=DECLINED:mailto:bob@example.org\r\n\
        ATTENDEE;CN=Cleo;PARTSTAT=ACCEPTED:mailto:cleo@example.org\r\nEND:VEVENT\r\n";
    let new = parsed(&base.replace("END:VCALENDAR\r\n", &format!("{override_text}END:VCALENDAR\r\n")));
    let update = apply_organizer_changes(Some(&old), &new, &limits()).unwrap();
    let text = unfolded(&update.calendar);
    let override_part = text.split("RECURRENCE-ID").nth(1).unwrap();
    assert!(
        override_part.contains("CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.org"),
        "{override_part}"
    );
    assert!(
        override_part.contains("PARTSTAT=TENTATIVE:mailto:cleo@example.org"),
        "{override_part}"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn every_message_is_stamped_at_the_moment_it_is_built() {
    let source = parsed(&series(""));
    let stored_stamp = "DTSTAMP:20270101T000000Z";
    assert!(unfolded(&source).contains(stored_stamp));
    for spec in [
        spec(ItipMethod::Request, "mailto:bob@example.org"),
        spec(ItipMethod::Cancel, "mailto:bob@example.org"),
        MessageSpec {
            replying_attendee: Some(address("mailto:bob@example.org")),
            ..spec(ItipMethod::Reply, "mailto:anna@example.org")
        },
    ] {
        let text = unfolded(&build_message(&source, &spec).unwrap().calendar);
        assert!(!text.contains(stored_stamp), "{text}");
        assert!(text.contains("DTSTAMP:20270201T100000Z\r\n"), "{text}");
        // The sequence stays the one of the copy: at least that of every REQUEST sent before.
        assert!(text.contains("SEQUENCE:1\r\n"), "{text}");
    }
}

#[test]
fn a_reply_carries_the_comment_of_the_attendee_and_none_of_the_copy() {
    let source = parsed(&event(
        &MASTER.replace("SUMMARY:Planning", "SUMMARY:Planning\r\nCOMMENT:Organizer note"),
    ));
    let reply = MessageSpec {
        replying_attendee: Some(address("mailto:bob@example.org")),
        comment: Some("Sorry, a clash".to_owned()),
        ..spec(ItipMethod::Reply, "mailto:anna@example.org")
    };
    let text = unfolded(&build_message(&source, &reply).unwrap().calendar);
    assert!(text.contains("COMMENT:Sorry\\, a clash\r\n"), "{text}");
    assert!(!text.contains("Organizer note"), "{text}");
    let without = MessageSpec { comment: None, ..reply };
    assert!(!unfolded(&build_message(&source, &without).unwrap().calendar).contains("COMMENT"));
    // The reply is read back with its comment.
    let reply_text = event(
        "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270102T000000Z\r\nSEQUENCE:1\r\nORGANIZER:mailto:anna@example.org\r\n\
         ATTENDEE;PARTSTAT=DECLINED:mailto:bob@example.org\r\nCOMMENT:Sorry\\, a clash\r\nEND:VEVENT\r\n",
    )
    .replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:REPLY\r\n");
    let message = parse_message(reply_text.as_bytes(), &limits()).unwrap();
    let applied = apply_reply(&parsed(&event(MASTER)), &message).unwrap();
    assert_eq!(applied.comment.as_deref(), Some("Sorry, a clash"));
    // The organizer's copy keeps it, as CalendarServer does and Calendar on macOS shows it: bob's comment, with whose it is and
    // when it was given, and no `COMMENT` of the event itself.
    let stored = unfolded(&applied.updated);
    assert!(
        stored.contains("X-CALENDARSERVER-ATTENDEE-COMMENT;X-CALENDARSERVER-ATTENDEE-REF=\"mailto:bob@example.org\""),
        "{stored}"
    );
    assert!(
        stored.contains(";X-CALENDARSERVER-DTSTAMP=20270102T000000Z:Sorry\\, a clash\r\n"),
        "{stored}"
    );
    assert!(!stored.contains("\r\nCOMMENT:"), "{stored}");
}

fn reply_with_comment(partstat: &str, who: &str, rid: Option<&str>, comment: Option<&str>) -> ItipMessage {
    let rid = rid.map_or_else(String::new, |rid| format!("RECURRENCE-ID;TZID=Europe/Berlin:{rid}\r\n"));
    let comment = comment.map_or_else(String::new, |text| format!("COMMENT:{text}\r\n"));
    let body = format!(
        "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270102T000000Z\r\nSEQUENCE:1\r\nORGANIZER:mailto:anna@example.org\r\n\
         {rid}ATTENDEE;PARTSTAT={partstat}:mailto:{who}@example.org\r\n{comment}END:VEVENT\r\n"
    );
    let text = event(&body).replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:REPLY\r\n");
    parse_message(text.as_bytes(), &limits()).unwrap()
}

fn comments_of(calendar: &ParsedCalendar) -> Vec<String> {
    unfolded(calendar)
        .split("\r\n")
        .filter(|line| line.starts_with("X-CALENDARSERVER-ATTENDEE-COMMENT"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_comment_of_an_answer_stays_on_the_organizer_copy_until_the_attendee_answers_again() {
    let copy = parsed(&event(MASTER));
    let first = apply_reply(
        &copy,
        &reply_with_comment("DECLINED", "bob", None, Some("Sorry\\, a clash")),
    )
    .unwrap();
    assert_eq!(comments_of(&first.updated).len(), 1, "{}", unfolded(&first.updated));
    // Cleo's comment is another line; neither replaces the other.
    let both = apply_reply(
        &first.updated,
        &reply_with_comment("TENTATIVE", "cleo", None, Some("Maybe")),
    )
    .unwrap();
    let lines = comments_of(&both.updated);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|line| line.contains("bob@example.org") && line.ends_with(":Sorry\\, a clash"))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("cleo@example.org") && line.ends_with(":Maybe"))
    );
    // Bob changes his mind with a new remark: his line is replaced, Cleo's stays.
    let changed = apply_reply(
        &both.updated,
        &reply_with_comment("ACCEPTED", "bob", None, Some("Fits now")),
    )
    .unwrap();
    let lines = comments_of(&changed.updated);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|line| line.contains("bob@example.org") && line.ends_with(":Fits now"))
    );
    assert!(!lines.iter().any(|line| line.contains("Sorry")));
    // An answer without a remark takes the earlier remark away: it belonged to the earlier answer.
    let silent = apply_reply(&changed.updated, &reply_with_comment("ACCEPTED", "bob", None, None)).unwrap();
    let lines = comments_of(&silent.updated);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("cleo@example.org"));
    // What is stored parses and serializes to the same bytes again.
    let text = serialize(&both.updated).unwrap();
    assert_eq!(serialize(&parsed(&text)).unwrap(), text);
}

#[test]
fn the_comment_of_an_answer_to_one_instance_stays_with_that_instance() {
    let copy = parsed(&series(""));
    let one = apply_reply(
        &copy,
        &reply_with_comment("DECLINED", "bob", Some("20270302T100000"), Some("Not that day")),
    )
    .unwrap();
    let text = unfolded(&one.updated);
    let comment_at = text.find("X-CALENDARSERVER-ATTENDEE-COMMENT").unwrap();
    let override_at = text.find("RECURRENCE-ID;TZID=Europe/Berlin:20270302T100000").unwrap();
    assert!(
        comment_at > override_at,
        "the comment is on the override, not on the master: {text}"
    );
    assert_eq!(comments_of(&one.updated).len(), 1);
    // An answer to the series reaches the overrides that still carry the earlier answer, and takes the comment along: cleo's
    // answer to the second day made an override that follows bob's answer to the series.
    let cleo = apply_reply(
        &copy,
        &reply_with_comment("DECLINED", "cleo", Some("20270302T100000"), None),
    )
    .unwrap();
    let carried = apply_reply(
        &cleo.updated,
        &reply_with_comment("DECLINED", "bob", None, Some("Away all week")),
    )
    .unwrap();
    assert_eq!(
        comments_of(&carried.updated).len(),
        2,
        "the master and the override that followed it"
    );
}

#[test]
fn what_attendees_wrote_to_the_organizer_reaches_nobody_else() {
    let copy = parsed(&event(MASTER));
    let answered = apply_reply(
        &copy,
        &reply_with_comment("DECLINED", "bob", None, Some("Private remark")),
    )
    .unwrap();
    assert_eq!(comments_of(&answered.updated).len(), 1);
    for (method, recipient) in [
        (ItipMethod::Request, "mailto:cleo@example.org"),
        (ItipMethod::Cancel, "mailto:cleo@example.org"),
    ] {
        let text = unfolded(
            &build_message(&answered.updated, &spec(method, recipient))
                .unwrap()
                .calendar,
        );
        assert!(
            !text.contains("Private remark") && !text.contains("ATTENDEE-COMMENT"),
            "{method:?}: {text}"
        );
    }
}

fn answered_with_comment() -> ParsedCalendar {
    apply_reply(
        &parsed(&event(MASTER)),
        &reply_with_comment("DECLINED", "bob", None, Some("Sorry\\, a clash")),
    )
    .unwrap()
    .updated
}

#[test]
fn a_version_that_predates_a_reply_does_not_take_the_comment_of_the_answer_away() {
    let stored = answered_with_comment();
    // The client read the copy before the reply: its version has no comment and only adds a description.
    let stale = parsed(&event(
        &MASTER.replace("SUMMARY:Planning", "SUMMARY:Planning\r\nDESCRIPTION:Notes"),
    ));
    let update = apply_organizer_changes(Some(&stored), &stale, &limits()).unwrap();
    assert_eq!(update.diff.instances[0].change, ChangeClass::Insignificant);
    assert_eq!(update.diff.instances[0].changed_properties, vec!["DESCRIPTION"]);
    let lines = comments_of(&update.calendar);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("bob@example.org") && lines[0].ends_with(":Sorry\\, a clash"));
    // A version that is the stored one changes nothing at all.
    let same = apply_organizer_changes(Some(&stored), &stored, &limits()).unwrap();
    assert_eq!(same.diff.instances[0].change, ChangeClass::Unchanged);
    assert_eq!(comments_of(&same.calendar).len(), 1);
}

#[test]
fn a_significant_change_resets_the_answers_and_takes_their_comments_away() {
    let stored = answered_with_comment();
    let moved = parsed(&event(&MASTER.replace("SUMMARY:Planning", "SUMMARY:Moved")));
    let update = apply_organizer_changes(Some(&stored), &moved, &limits()).unwrap();
    assert_eq!(update.diff.instances[0].change, ChangeClass::Significant);
    assert_eq!(answer_of(&update.calendar, "bob").as_deref(), Some("NEEDS-ACTION"));
    assert!(
        comments_of(&update.calendar).is_empty(),
        "a remark belongs to its answer: {}",
        unfolded(&update.calendar)
    );
}

#[test]
fn a_client_cannot_write_the_comment_of_an_attendee() {
    let stored = answered_with_comment();
    let forged = parsed(&event(&MASTER.replace(
        "X-APPLE-STRUCTURED-LOCATION:geo",
        "X-CALENDARSERVER-ATTENDEE-COMMENT;X-CALENDARSERVER-ATTENDEE-REF=\"mailto:bob@example.org\":Planted\r\n\
         X-CALENDARSERVER-ATTENDEE-COMMENT;X-CALENDARSERVER-ATTENDEE-REF=\"mailto:cleo@example.org\":Also planted\r\n\
         X-APPLE-STRUCTURED-LOCATION:geo",
    )));
    let update = apply_organizer_changes(Some(&stored), &forged, &limits()).unwrap();
    let lines = comments_of(&update.calendar);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("bob@example.org") && lines[0].ends_with(":Sorry\\, a clash"));
    assert!(!unfolded(&update.calendar).contains("planted"));
    // A new object starts without any comment.
    let fresh = apply_organizer_changes(None, &forged, &limits()).unwrap();
    assert_eq!(comments_of(&fresh.calendar), Vec::<String>::new());
}

#[test]
fn the_comment_of_an_answer_is_cut_and_never_makes_the_copy_too_large() {
    let long = "x".repeat(MAX_COMMENT_CHARS + 300);
    let applied = apply_reply(
        &parsed(&event(MASTER)),
        &reply_with_comment("DECLINED", "bob", None, Some(&long)),
    )
    .unwrap();
    assert_eq!(
        applied.comment.as_deref().map(|text| text.chars().count()),
        Some(MAX_COMMENT_CHARS)
    );
    let lines = comments_of(&applied.updated);
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].ends_with(&format!(":{}", "x".repeat(MAX_COMMENT_CHARS))),
        "{}",
        lines[0]
    );
    // A copy that has room for the answer and not for the remark takes the answer without it.
    let copy = parsed(&event(MASTER));
    let size = serialize(&copy).unwrap().len();
    let tight = IcalLimits {
        max_resource_size: u64::try_from(size + 80).unwrap(),
        ..IcalLimits::default()
    };
    let message = reply_with_comment("DECLINED", "bob", None, Some(&long));
    let squeezed = apply_reply_with(&copy, &message, &tight, None).unwrap();
    assert_eq!(squeezed.partstat, PartStat::Declined);
    assert_eq!(comments_of(&squeezed.updated), Vec::<String>::new());
    assert_eq!(answer_of(&squeezed.updated, "bob").as_deref(), Some("DECLINED"));
}

#[test]
fn the_attendees_of_a_message_are_the_recipient_or_everybody() {
    let source = parsed(&event(MASTER));
    let own = unfolded(
        &build_message(&source, &spec(ItipMethod::Request, "mailto:bob@example.org"))
            .unwrap()
            .calendar,
    );
    assert!(
        own.contains("bob@example.org") && !own.contains("cleo@example.org"),
        "{own}"
    );
    let everybody = MessageSpec {
        attendees: AttendeeVisibility::All,
        ..spec(ItipMethod::Request, "mailto:bob@example.org")
    };
    let all = unfolded(&build_message(&source, &everybody).unwrap().calendar);
    assert!(
        all.contains("bob@example.org") && all.contains("cleo@example.org"),
        "{all}"
    );
    assert!(
        !all.contains("SCHEDULE-STATUS"),
        "no scheduling parameter leaves the server: {all}"
    );
    let cancel = MessageSpec {
        attendees: AttendeeVisibility::All,
        ..spec(ItipMethod::Cancel, "mailto:bob@example.org")
    };
    let text = unfolded(&build_message(&source, &cancel).unwrap().calendar);
    assert!(
        text.contains("cleo@example.org") && text.contains("STATUS:CANCELLED"),
        "{text}"
    );
}

/// A series with an override that names fewer attendees than the series (Cleo is not invited to that day).
fn series_without_cleo_on_the_third() -> String {
    let override_text = "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
        RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000\r\nDTSTART;TZID=Europe/Berlin:20270303T100000\r\n\
        DTEND;TZID=Europe/Berlin:20270303T110000\r\nSUMMARY:Planning\r\nLOCATION:Room 1\r\n\
        ORGANIZER;CN=Anna:mailto:anna@example.org\r\n\
        ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:bob@example.org\r\nEND:VEVENT\r\n";
    series("").replace("END:VCALENDAR\r\n", &format!("{override_text}END:VCALENDAR\r\n"))
}

#[test]
fn an_attendee_who_is_not_invited_to_one_instance_still_gets_the_rest() {
    let source = parsed(&series_without_cleo_on_the_third());
    let request = build_message(&source, &spec(ItipMethod::Request, "mailto:cleo@example.org")).unwrap();
    let text = unfolded(&request.calendar);
    assert_eq!(text.matches("BEGIN:VEVENT").count(), 1, "only the series: {text}");
    assert!(!text.contains("RECURRENCE-ID"), "{text}");
    let bob = unfolded(
        &build_message(&source, &spec(ItipMethod::Request, "mailto:bob@example.org"))
            .unwrap()
            .calendar,
    );
    assert_eq!(bob.matches("BEGIN:VEVENT").count(), 2, "{bob}");
    // Asking for the instance Cleo is not invited to is an error, and so is a stranger.
    let instance = MessageSpec {
        scope: MessageScope::Instances(vec![berlin(3, 10)]),
        ..spec(ItipMethod::Request, "mailto:cleo@example.org")
    };
    assert_eq!(
        build_message(&source, &instance).map(|_| ()),
        Err(IcalError::Invalid("the attendee is not on the event".to_owned()))
    );
    assert_eq!(
        build_message(&source, &spec(ItipMethod::Request, "mailto:zed@example.org")).map(|_| ()),
        Err(IcalError::Invalid("the attendee is not on the event".to_owned()))
    );
}

#[test]
fn the_diff_names_the_attendees_that_an_override_drops() {
    let old = parsed(&series(""));
    let new = parsed(&series_without_cleo_on_the_third());
    let report = diff(Some(&old), &new, &limits()).unwrap();
    assert!(report.removed_attendees.is_empty(), "Cleo is still on the series");
    assert_eq!(
        report.instance_attendees,
        vec![InstanceAttendees {
            recurrence_id: Some(berlin(3, 10)),
            added: Vec::new(),
            removed: vec![address("mailto:cleo@example.org")],
        }]
    );
    // The CANCEL for Cleo's instance is built from the stored copy, which still lists her there.
    let cancel = MessageSpec {
        scope: MessageScope::Instances(vec![berlin(3, 10)]),
        ..spec(ItipMethod::Cancel, "mailto:cleo@example.org")
    };
    let text = unfolded(&build_message(&old, &cancel).unwrap().calendar);
    assert!(
        text.contains("RECURRENCE-ID;TZID=Europe/Berlin:20270303T100000") && text.contains("STATUS:CANCELLED"),
        "{text}"
    );
    // Nothing changes for attendees when the lists of the instances agree.
    assert_eq!(
        diff(Some(&old), &old, &limits()).unwrap().instance_attendees,
        Vec::new()
    );
}

#[test]
fn addresses_are_mapped_before_they_leave_the_server() {
    let internal = event(
        &MASTER
            .replace(
                "ORGANIZER;CN=Anna:mailto:anna@example.org",
                "ORGANIZER;CN=Anna;SENT-BY=\"mailto:pa@example.org\":/dav/principals/acme/anna/",
            )
            .replace(
                "ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:mailto:cleo@example.org",
                "ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:urn:uuid:11111111-2222-3333-4444-555555555555",
            ),
    );
    let source = parsed(&internal);
    let map = |found: &CalendarUserAddress| -> Option<CalendarUserAddress> {
        match found.as_str() {
            "/dav/principals/acme/anna/" => Some(address("mailto:anna@example.org")),
            "urn:uuid:11111111-2222-3333-4444-555555555555" => Some(address("mailto:cleo@example.org")),
            _ => None,
        }
    };
    let mapped = rewrite_addresses(&source, &map).unwrap();
    let text = unfolded(&mapped);
    assert!(
        text.contains("ORGANIZER;CN=Anna;SENT-BY=\"mailto:pa@example.org\":mailto:anna@example.org"),
        "{text}"
    );
    assert!(
        text.contains("ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:mailto:cleo@example.org"),
        "{text}"
    );
    assert!(
        !text.contains("urn:uuid") && !text.contains("/dav/principals"),
        "{text}"
    );
    // The message is built from the mapped copy, so its addresses and its recipient agree.
    let message = build_message(&mapped, &spec(ItipMethod::Request, "mailto:cleo@example.org")).unwrap();
    assert!(unfolded(&message.calendar).contains("mailto:cleo@example.org"));
    // Built from the unmapped copy the recipient is not found.
    assert!(build_message(&source, &spec(ItipMethod::Request, "mailto:cleo@example.org")).is_err());
    // An address the map has no answer for stays.
    let kept = unfolded(&rewrite_addresses(&source, &|_| None).unwrap());
    assert!(kept.contains("urn:uuid:11111111"), "{kept}");
}

// ---------------------------------------------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------------------------------------------

/// A `REPLY` with one component per answer: the answer, the instance it names (if any) and the replying attendee.
fn reply_to(components: &[(&str, Option<&str>, &str)]) -> ItipMessage {
    let mut body = String::new();
    for (partstat, rid, who) in components {
        let rid = rid.map_or_else(String::new, |rid| format!("RECURRENCE-ID;TZID=Europe/Berlin:{rid}\r\n"));
        let _ = write!(
            body,
            "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270102T000000Z\r\nSEQUENCE:1\r\nORGANIZER:mailto:anna@example.org\r\n\
             {rid}ATTENDEE;PARTSTAT={partstat}:mailto:{who}@example.org\r\nEND:VEVENT\r\n"
        );
    }
    let text = event(&body).replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:REPLY\r\n");
    parse_message(text.as_bytes(), &limits()).unwrap()
}

#[test]
fn a_reply_must_come_from_the_attendee_it_names() {
    let copy = parsed(&event(MASTER));
    let reply = reply_to(&[("DECLINED", None, "bob")]);
    let bob = address("mailto:bob@example.org");
    assert!(apply_reply_with(&copy, &reply, &limits(), Some(&bob)).is_ok());
    let cleo = address("mailto:cleo@example.org");
    let spoofed = apply_reply_with(&copy, &reply, &limits(), Some(&cleo));
    assert_eq!(
        spoofed.map(|applied| applied.attendee),
        Err(IcalError::Invalid(
            "the reply answers for another attendee than the one who sent it".to_owned()
        ))
    );
    // One message cannot carry the answers of two attendees, not even one per instance.
    let two_people = reply_to(&[("DECLINED", None, "bob"), ("ACCEPTED", Some("20270301T100000"), "cleo")]);
    let copy = parsed(&series(""));
    assert_eq!(
        apply_reply_with(&copy, &two_people, &limits(), None).map(|applied| applied.attendee),
        Err(IcalError::Invalid("a REPLY must come from one attendee".to_owned()))
    );
    // Nor answer another event than the copy it is applied to.
    let other_event = reply_to(&[("DECLINED", None, "bob")]);
    let elsewhere = parsed(&series("").replace("UID:itip-1", "UID:itip-other"));
    assert_eq!(
        apply_reply_with(&elsewhere, &other_event, &limits(), None).map(|applied| applied.attendee),
        Err(IcalError::Invalid("the reply is for another event".to_owned()))
    );
}

#[test]
fn a_reply_to_the_series_also_answers_the_overrides_that_carried_the_old_answer() {
    let copy = parsed(&series_with_two_overrides());
    let reply = reply_to(&[("DECLINED", None, "bob")]);
    let applied = apply_reply_with(&copy, &reply, &limits(), None).unwrap();
    // The master and the override that still carried Bob's earlier answer (ACCEPTED) are declined; the override
    // Bob answered differently (TENTATIVE) keeps his answer.
    let text = unfolded(&applied.updated);
    let parts: Vec<&str> = text.split("BEGIN:VEVENT").skip(1).collect();
    assert_eq!(parts.len(), 3, "{text}");
    assert!(
        parts[0].contains("PARTSTAT=DECLINED") && !parts[0].contains("PARTSTAT=ACCEPTED;RSVP=TRUE;SCHEDULE"),
        "{}",
        parts[0]
    );
    assert!(
        parts[1].contains("20270303T100000") && parts[1].contains("PARTSTAT=DECLINED"),
        "{}",
        parts[1]
    );
    assert!(
        parts[2].contains("20270304T100000") && parts[2].contains("PARTSTAT=TENTATIVE"),
        "{}",
        parts[2]
    );
    // An answer to one instance only changes that instance.
    let one = reply_to(&[("TENTATIVE", Some("20270303T100000"), "bob")]);
    let applied = apply_reply_with(&copy, &one, &limits(), None).unwrap();
    let text = unfolded(&applied.updated);
    assert!(
        text.split("BEGIN:VEVENT").nth(1).unwrap().contains("PARTSTAT=ACCEPTED"),
        "{text}"
    );
}

fn series_with_two_overrides() -> String {
    let overrides = |day: u32, partstat: &str| {
        format!(
            "BEGIN:VEVENT\r\nUID:itip-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
             RECURRENCE-ID;TZID=Europe/Berlin:2027030{day}T100000\r\nDTSTART;TZID=Europe/Berlin:2027030{day}T100000\r\n\
             DTEND;TZID=Europe/Berlin:2027030{day}T110000\r\nSUMMARY:Planning\r\nORGANIZER;CN=Anna:mailto:anna@example.org\r\n\
             ATTENDEE;CN=Bob;PARTSTAT={partstat};RSVP=TRUE:mailto:bob@example.org\r\n\
             ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:mailto:cleo@example.org\r\nEND:VEVENT\r\n"
        )
    };
    series("").replace(
        "END:VCALENDAR\r\n",
        &format!(
            "{}{}END:VCALENDAR\r\n",
            overrides(3, "ACCEPTED"),
            overrides(4, "TENTATIVE")
        ),
    )
}

#[test]
fn a_reply_may_not_name_too_many_or_too_distant_instances_or_grow_the_object_too_far() {
    let copy = parsed(&series(""));
    // Four instances exist (COUNT=5 and one is the start); the cap is the configured one.
    let many = reply_to(&[
        ("DECLINED", Some("20270302T100000"), "bob"),
        ("DECLINED", Some("20270303T100000"), "bob"),
        ("DECLINED", Some("20270304T100000"), "bob"),
    ]);
    let few = IcalLimits {
        max_recurrence_dates: 2,
        ..IcalLimits::default()
    };
    assert_eq!(
        apply_reply_with(&copy, &many, &few, None).unwrap_err(),
        IcalError::Limit(LimitKind::RecurrenceDates)
    );
    let applied = apply_reply_with(&copy, &many, &limits(), None).unwrap();
    assert_eq!(applied.instances.len(), 3);
    assert_eq!(unfolded(&applied.updated).matches("BEGIN:VEVENT").count(), 4);
    // An instance that does not exist, and one that is too far from the others.
    let missing = reply_to(&[("DECLINED", Some("20270320T100000"), "bob")]);
    assert_eq!(
        apply_reply_with(&copy, &missing, &limits(), None).map(|applied| applied.attendee),
        Err(IcalError::Invalid(
            "the reply names an instance the event does not have".to_owned()
        ))
    );
    let far = reply_to(&[
        ("DECLINED", Some("20270302T100000"), "bob"),
        ("DECLINED", Some("20450302T100000"), "bob"),
    ]);
    assert_eq!(
        apply_reply_with(&copy, &far, &limits(), None).map(|applied| applied.attendee),
        Err(IcalError::Invalid("the reply names instances too far apart".to_owned()))
    );
    // The result stays an object the server stores.
    let tight = IcalLimits {
        max_components: 3,
        ..IcalLimits::default()
    };
    assert_eq!(
        apply_reply_with(&copy, &many, &tight, None).unwrap_err(),
        IcalError::Limit(LimitKind::Components)
    );
    let small = IcalLimits {
        max_resource_size: u64::try_from(serialize(&copy).unwrap().len()).unwrap() + 100,
        ..IcalLimits::default()
    };
    assert_eq!(
        apply_reply_with(&copy, &many, &small, None).unwrap_err(),
        IcalError::Limit(LimitKind::ResourceSize)
    );
}

#[test]
fn replies_to_instances_use_the_configured_step_budget() {
    let copy = parsed(&series(""));
    let reply = reply_to(&[("DECLINED", Some("20270303T100000"), "bob")]);
    let tight = IcalLimits {
        max_iterator_steps: 2,
        ..IcalLimits::default()
    };
    assert_eq!(
        apply_reply_with(&copy, &reply, &tight, None).unwrap_err(),
        IcalError::Limit(LimitKind::IteratorSteps)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Inbound messages are held to the rules of stored objects
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn inbound_messages_must_have_valid_dates_and_rules() {
    let source = parsed(&event(MASTER));
    let request = build_message(&source, &spec(ItipMethod::Request, "mailto:bob@example.org")).unwrap();
    let text = serialize(&request.calendar).unwrap();
    assert!(parse_message(text.as_bytes(), &limits()).is_ok());
    for (broken, why) in [
        (
            text.replace("SUMMARY:Planning", "SUMMARY:Planning\r\nRRULE:FREQ=WEEKLY;BYMONTHDAY=1"),
            "inconsistent rule",
        ),
        (
            text.replace("SUMMARY:Planning", "SUMMARY:Planning\r\nRRULE:FREQ=SECONDLY"),
            "sub-hourly rule",
        ),
        (text.replace("20270301T110000", "20270301T090000"), "end before start"),
        (text.replace("SEQUENCE:1", "SEQUENCE:abc"), "unreadable sequence"),
        (
            text.replace("20270301T100000", "18990301T100000"),
            "date before the minimum",
        ),
        (
            text.replace("SUMMARY:Planning", "SUMMARY:Planning\r\nDTSTART:20270301T100000Z"),
            "two starts",
        ),
    ] {
        assert!(parse_message(broken.as_bytes(), &limits()).is_err(), "{why}");
    }
    // The limits are the configured ones.
    let tight = IcalLimits {
        max_attendees_per_instance: 0,
        ..IcalLimits::default()
    };
    assert_eq!(
        parse_message(text.as_bytes(), &tight).unwrap_err(),
        IcalError::Limit(LimitKind::Attendees)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// What may change on a copy
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_organizer_and_the_uid_of_a_copy_cannot_change() {
    let old = parsed(&event(MASTER));
    let moved = parsed(&event(
        &MASTER.replace("mailto:anna@example.org", "mailto:mallory@example.org"),
    ));
    assert_eq!(
        organizer_change_violations(&old, &moved).unwrap(),
        vec!["ORGANIZER".to_owned()]
    );
    let renamed = parsed(&event(&MASTER.replace("UID:itip-1", "UID:itip-2")));
    assert_eq!(
        organizer_change_violations(&old, &renamed).unwrap(),
        vec!["UID".to_owned()]
    );
    let removed = parsed(&event(
        &MASTER.replace("ORGANIZER;CN=Anna:mailto:anna@example.org\r\n", ""),
    ));
    assert_eq!(
        organizer_change_violations(&old, &removed).unwrap(),
        vec!["ORGANIZER".to_owned()]
    );
    // A copy that had no organizer may become a meeting, and nothing changed is fine.
    assert_eq!(
        organizer_change_violations(&removed, &old).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(organizer_change_violations(&old, &old).unwrap(), Vec::<String>::new());
}

#[test]
fn attendees_may_not_rewrite_the_event_or_the_other_guests() {
    let old = parsed(&event(&MASTER.replace("RRULE", "X-RRULE")));
    let with_rule = parsed(&series(""));
    let bob = address("mailto:bob@example.org");
    let violations = |new: &ParsedCalendar| attendee_change_violations(&old, new, &bob).unwrap();
    // The recurrence, the exclusions and the classification are the organizer's.
    assert_eq!(violations(&with_rule), vec!["RRULE".to_owned()]);
    let exdate = event(&MASTER.replace(
        "SUMMARY:Planning",
        "SUMMARY:Planning\r\nEXDATE;TZID=Europe/Berlin:20270302T100000",
    ));
    assert_eq!(violations(&parsed(&exdate)), vec!["EXDATE".to_owned()]);
    let class = event(&MASTER.replace("SUMMARY:Planning", "SUMMARY:Planning\r\nCLASS:PRIVATE"));
    assert_eq!(violations(&parsed(&class)), vec!["CLASS".to_owned()]);
    let attach = event(&MASTER.replace(
        "SUMMARY:Planning",
        "SUMMARY:Planning\r\nATTACH:https://example.org/file",
    ));
    assert_eq!(violations(&parsed(&attach)), vec!["ATTACH".to_owned()]);
    // Guests cannot be added or removed.
    let added = event(&MASTER.replace("X-APPLE-STRUCTURED-LOCATION:geo", "ATTENDEE:mailto:dan@example.org"));
    assert_eq!(violations(&parsed(&added)), vec!["ATTENDEE".to_owned()]);
    let removed = event(&MASTER.replace("ATTENDEE;CN=Cleo;PARTSTAT=TENTATIVE:mailto:cleo@example.org\r\n", ""));
    assert_eq!(violations(&parsed(&removed)), vec!["ATTENDEE".to_owned()]);
    // Their own line is theirs to edit, but it cannot move to another address or disappear.
    let own_parameters = event(&MASTER.replace(
        "RSVP=TRUE;SCHEDULE-STATUS=1.2",
        "ROLE=OPT-PARTICIPANT;RSVP=FALSE;DELEGATED-TO=\"mailto:dan@example.org\"",
    ));
    assert_eq!(violations(&parsed(&own_parameters)), Vec::<String>::new());
    let another_address = event(&MASTER.replace("mailto:bob@example.org", "mailto:bobby@example.org"));
    assert_eq!(violations(&parsed(&another_address)), vec!["ATTENDEE".to_owned()]);
    let gone = event(&MASTER.replace(
        "ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;RSVP=TRUE;SCHEDULE-STATUS=1.2:mailto:bob@example.org\r\n",
        "",
    ));
    assert_eq!(violations(&parsed(&gone)), vec!["ATTENDEE".to_owned()]);
}
