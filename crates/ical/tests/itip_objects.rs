//! The constructions the application needs around iTIP messages: the `REPLY` of an answer, the object a message
//! describes, `SENT-BY`, alarms and `TRANSP` that an attendee keeps, the request of an outbox `POST` and the busy
//! time of one person. The application never reads or writes iCalendar text itself; these are the functions it uses
//! instead.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use chrono::{DateTime, TimeZone, Utc};
use davhaven_domain::{CalendarUserAddress, IcalLimits, ItipMethod, PartStat, TimeZoneName, Uid};
use davhaven_ical::filter::TimeRange;
use davhaven_ical::freebusy::{BusyKind, BusyPeriod, Participation, busy_periods_for, read_request};
use davhaven_ical::itip::{
    ReplySpec, apply_reply_with, carry_over_attendee_data, inline_attachments, parse_message, reply_message,
    set_sent_by, strip_alarms,
};
use davhaven_ical::parse::{ParsedCalendar, parse};
use davhaven_ical::serialize::serialize;

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

fn at(day: u32, hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 3, day, hour, 0, 0).unwrap()
}

fn calendar(body: &str) -> String {
    format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\n{body}END:VCALENDAR\r\n")
}

const MEETING: &str = "BEGIN:VEVENT\r\nUID:obj-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:2\r\n\
    DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nSUMMARY:Planning\r\n\
    ORGANIZER;CN=Anna:mailto:anna@example.org\r\n\
    ATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@example.org\r\n\
    ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:cleo@example.org\r\nTRANSP:TRANSPARENT\r\n\
    BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nDESCRIPTION:Mine\r\nEND:VALARM\r\nEND:VEVENT\r\n";

// ---------------------------------------------------------------------------------------------------------------
// The REPLY of an answer
// ---------------------------------------------------------------------------------------------------------------

fn spec<'a>(
    uid: &'a Uid,
    organizer: &'a CalendarUserAddress,
    attendee: &'a CalendarUserAddress,
    comment: Option<&'a str>,
) -> ReplySpec<'a> {
    ReplySpec {
        uid,
        organizer,
        attendee,
        partstat: PartStat::Tentative,
        sequence: 3,
        dtstamp: Utc.with_ymd_and_hms(2027, 3, 1, 9, 30, 5).unwrap(),
        comment,
    }
}

#[test]
fn a_reply_reads_back_as_a_reply_of_that_attendee_with_the_remark() {
    let uid = Uid::parse("event, one;two").unwrap();
    let (organizer, attendee) = (address("mailto:anna@acme.example"), address("mailto:guest@example.net"));
    let message = reply_message(&spec(&uid, &organizer, &attendee, Some("See you, maybe;\nlate"))).unwrap();
    assert_eq!(message.method, ItipMethod::Reply);
    let text = serialize(&message.calendar).unwrap();
    let again = parse_message(text.as_bytes(), &limits()).unwrap();
    assert_eq!(again.method, ItipMethod::Reply);
    let data = davhaven_ical::merge::to_event_data(&again.calendar, None).unwrap();
    assert_eq!(data.uid, Some(uid));
    assert_eq!(data.sequence, Some(3));
    assert_eq!(data.organizer.unwrap().address, organizer);
    let attendees = data.attendees.unwrap();
    assert_eq!(attendees.len(), 1);
    assert_eq!(attendees[0].address, attendee);
    assert_eq!(attendees[0].partstat, Some(PartStat::Tentative));
    let unfolded = text.replace("\r\n ", "");
    assert!(unfolded.contains("DTSTAMP:20270301T093005Z\r\n"), "{unfolded}");
    assert!(
        unfolded.contains("COMMENT:See you\\, maybe\\;\\nlate\r\n"),
        "the remark is escaped: {unfolded}"
    );
}

#[test]
fn a_reply_without_a_remark_has_no_comment_and_a_negative_sequence_counts_as_none() {
    let uid = Uid::parse("uid-1").unwrap();
    let (organizer, attendee) = (address("mailto:anna@acme.example"), address("mailto:guest@example.net"));
    for comment in [None, Some("")] {
        let message = reply_message(&ReplySpec {
            sequence: -4,
            ..spec(&uid, &organizer, &attendee, comment)
        })
        .unwrap();
        let text = unfolded(&message.calendar);
        assert!(!text.contains("COMMENT"), "{text}");
        assert!(text.contains("SEQUENCE:0\r\n"), "{text}");
    }
}

#[test]
fn a_built_reply_is_folded_into_the_organizers_copy_like_any_other() {
    let uid = Uid::parse("obj-1").unwrap();
    let (organizer, attendee) = (address("mailto:anna@example.org"), address("mailto:cleo@example.org"));
    let copy = parsed(&calendar(MEETING));
    let message = reply_message(&ReplySpec {
        sequence: 2,
        partstat: PartStat::Accepted,
        ..spec(&uid, &organizer, &attendee, Some("yes"))
    })
    .unwrap();
    let applied = apply_reply_with(&copy, &message, &limits(), Some(&attendee)).unwrap();
    assert!(applied.sequence_matches);
    assert_eq!(applied.partstat, PartStat::Accepted);
    assert_eq!(applied.comment.as_deref(), Some("yes"));
    assert!(
        unfolded(&applied.updated).contains("PARTSTAT=ACCEPTED:mailto:cleo@example.org"),
        "{}",
        unfolded(&applied.updated)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Objects from messages
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_object_of_a_message_lacks_the_method_and_nothing_else() {
    let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:m-1\r\n\
        DTSTAMP:20270101T000000Z\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n\
        DESCRIPTION:METHOD:CANCEL inside\r\nX-NOTE:METHOD:cancel\r\nORGANIZER:mailto:anna@example.org\r\n\
        ATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let message = parse_message(text.as_bytes(), &limits()).unwrap();
    let object = unfolded(&message.object());
    assert!(!object.contains("\r\nMETHOD:REQUEST"), "{object}");
    assert!(
        object.contains("DESCRIPTION:METHOD:CANCEL inside"),
        "values stay: {object}"
    );
    assert!(object.contains("X-NOTE:METHOD:cancel"), "{object}");
    assert!(object.contains("UID:m-1"), "{object}");
    assert!(
        unfolded(&message.calendar).contains("METHOD:REQUEST"),
        "the message keeps its method"
    );
}

#[test]
fn alarms_are_stripped_from_every_component() {
    let copy = parsed(&calendar(MEETING));
    assert!(unfolded(&copy).contains("BEGIN:VALARM"));
    let stripped = unfolded(&strip_alarms(&copy));
    assert!(
        !stripped.contains("VALARM") && !stripped.contains("TRIGGER"),
        "{stripped}"
    );
    assert!(
        stripped.contains("TRANSP:TRANSPARENT"),
        "everything else stays: {stripped}"
    );
}

#[test]
fn inline_attachments_are_listed_and_links_are_not() {
    let text = calendar(
        "BEGIN:VEVENT\r\nUID:att-1\r\nDTSTAMP:20270101T000000Z\r\nDTSTART:20270301T100000Z\r\n\
         ATTACH;FMTTYPE=text/plain;ENCODING=BASE64;VALUE=BINARY:aGVsbG8=\r\n\
         ATTACH;FMTTYPE=application/pdf:https://example.org/agenda.pdf\r\n\
         BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nDESCRIPTION:x\r\n\
         ATTACH;ENCODING=BASE64;VALUE=BINARY:d29ybGQ=\r\nEND:VALARM\r\nEND:VEVENT\r\n",
    );
    let found = inline_attachments(&parsed(&text));
    let contents: Vec<&[u8]> = found.iter().map(|attachment| attachment.content.as_slice()).collect();
    assert_eq!(contents, vec![b"hello".as_slice(), b"world".as_slice()], "{found:?}");
    assert_eq!(found[0].media_type.as_deref(), Some("text/plain"));
    assert_eq!(found[1].media_type, None);
    assert_eq!(inline_attachments(&parsed(&calendar(MEETING))), Vec::new());
}

// ---------------------------------------------------------------------------------------------------------------
// SENT-BY
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_sender_is_named_on_every_organizer_line_and_only_there() {
    let text = calendar(
        "BEGIN:VEVENT\r\nUID:x\r\nDTSTAMP:20270101T000000Z\r\nDTSTART:20270301T100000Z\r\n\
         ORGANIZER;CN=\"Anna: A\";SENT-BY=\"mailto:old@example.org\":mailto:anna@acme.example\r\n\
         ATTENDEE;SENT-BY=\"mailto:keep@example.org\":mailto:ben@acme.example\r\nEND:VEVENT\r\n\
         BEGIN:VEVENT\r\nUID:x\r\nRECURRENCE-ID:20270302T100000Z\r\nDTSTAMP:20270101T000000Z\r\n\
         DTSTART:20270302T100000Z\r\nORGANIZER:mailto:anna@acme.example\r\nEND:VEVENT\r\n",
    );
    let by = address("mailto:pa@acme.example");
    let edited = set_sent_by(&parsed(&text), &by).unwrap();
    let out = unfolded(&edited);
    assert_eq!(out.matches("SENT-BY=\"mailto:pa@acme.example\"").count(), 2, "{out}");
    assert!(!out.contains("old@example.org"), "an earlier sender is replaced: {out}");
    assert!(
        out.contains("SENT-BY=\"mailto:keep@example.org\""),
        "attendee lines are untouched: {out}"
    );
    assert!(out.contains("CN=\"Anna: A\""), "other parameters stay: {out}");
    assert_eq!(
        unfolded(&set_sent_by(&edited, &by).unwrap()),
        out,
        "writing it twice changes nothing"
    );
    let folded = serialize(&edited).unwrap();
    for physical in folded.split("\r\n") {
        assert!(physical.len() <= 75, "{} octets: {physical}", physical.len());
    }
    let plain = parsed(&calendar(
        "BEGIN:VEVENT\r\nUID:y\r\nDTSTAMP:20270101T000000Z\r\nEND:VEVENT\r\n",
    ));
    assert_eq!(
        set_sent_by(&plain, &by).unwrap(),
        plain,
        "a calendar without an organizer is left as it is"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// What an attendee keeps
// ---------------------------------------------------------------------------------------------------------------

const SERIES: &str = "BEGIN:VEVENT\r\nUID:ser-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
    DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:Series\r\n\
    ORGANIZER:mailto:anna@example.org\r\nATTENDEE:mailto:bob@example.org\r\n{master}END:VEVENT\r\n\
    BEGIN:VEVENT\r\nUID:ser-1\r\nRECURRENCE-ID:20270302T100000Z\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\n\
    DTSTART:20270302T120000Z\r\nDTEND:20270302T130000Z\r\nSUMMARY:Moved\r\n\
    ORGANIZER:mailto:anna@example.org\r\nATTENDEE:mailto:bob@example.org\r\n{moved}END:VEVENT\r\n";

fn series(master: &str, moved: &str) -> ParsedCalendar {
    parsed(&calendar(&SERIES.replace("{master}", master).replace("{moved}", moved)))
}

const ALARM: &str = "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Mine\r\nEND:VALARM\r\n";

#[test]
fn the_alarms_and_the_transparency_of_the_recipient_survive_the_next_version_of_the_organizer() {
    let previous = series(&format!("TRANSP:TRANSPARENT\r\n{ALARM}"), ALARM);
    let new = series("", "");
    let merged = unfolded(&carry_over_attendee_data(&new, &previous).unwrap());
    assert_eq!(
        merged.matches("BEGIN:VALARM").count(),
        2,
        "one alarm on each component: {merged}"
    );
    assert_eq!(merged.matches("TRIGGER:-PT15M").count(), 2, "{merged}");
    assert_eq!(merged.matches("TRANSP:TRANSPARENT").count(), 1, "{merged}");
    assert!(
        merged.contains("SUMMARY:Series"),
        "the organizer's content is the new one: {merged}"
    );
    assert!(merged.contains("DTSTART:20270302T120000Z"), "{merged}");
}

#[test]
fn an_alarm_the_recipient_does_not_have_is_not_added_and_a_component_without_counterpart_is_left_alone() {
    let previous = series("", "");
    let new = series(ALARM, "TRANSP:TRANSPARENT\r\n");
    let merged = unfolded(&carry_over_attendee_data(&new, &previous).unwrap());
    assert!(
        !merged.contains("BEGIN:VALARM"),
        "an alarm of the organizer never reaches a recipient: {merged}"
    );
    assert!(
        merged.contains("TRANSP:TRANSPARENT"),
        "a TRANSP the previous copy had none of stays: {merged}"
    );
    let master_only = parsed(&calendar(
        "BEGIN:VEVENT\r\nUID:ser-1\r\nDTSTAMP:20270101T000000Z\r\nSEQUENCE:1\r\nDTSTART:20270301T100000Z\r\n\
         DTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nORGANIZER:mailto:anna@example.org\r\n\
         ATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\n",
    ));
    let with_override = series("", &format!("TRANSP:TRANSPARENT\r\n{ALARM}"));
    let carried = unfolded(&carry_over_attendee_data(&with_override, &master_only).unwrap());
    assert!(
        carried.contains("RECURRENCE-ID:20270302T100000Z") && carried.matches("BEGIN:VALARM").count() == 1,
        "an override the previous copy did not have is left as it is: {carried}"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// The request of an outbox POST
// ---------------------------------------------------------------------------------------------------------------

const REQUEST: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Client//EN\r\nMETHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\n\
    UID:fb-1\r\nDTSTAMP:20270301T090000Z\r\nDTSTART:20270310T080000Z\r\nDTEND:20270310T180000Z\r\n\
    ORGANIZER;CN=\"Anna: Example\":mailto:anna@acme.example\r\n\
    ATTENDEE:mailto:ben@acme.example\r\nATTENDEE:mailto:cara@\r\n acme.example\r\nATTENDEE:mailto:ben@acme.example\r\n\
    END:VFREEBUSY\r\nEND:VCALENDAR\r\n";

fn request_of(text: &str) -> Result<davhaven_ical::freebusy::FreeBusyRequest, davhaven_ical::IcalError> {
    read_request(&parse_message(text.as_bytes(), &limits())?)
}

#[test]
fn a_free_busy_request_is_read_from_the_message() {
    let ask = request_of(REQUEST).unwrap();
    assert_eq!(ask.organizer, address("mailto:anna@acme.example"));
    assert_eq!(
        ask.attendees,
        vec![address("mailto:ben@acme.example"), address("mailto:cara@acme.example")],
        "folded lines are joined and an attendee is listed once"
    );
    assert_eq!(ask.start, Utc.with_ymd_and_hms(2027, 3, 10, 8, 0, 0).unwrap());
    assert_eq!(ask.end, Utc.with_ymd_and_hms(2027, 3, 10, 18, 0, 0).unwrap());
    let lf = REQUEST.replace("\r\n", "\n");
    assert_eq!(request_of(&lf).unwrap(), ask, "line endings do not matter");
}

#[test]
fn only_a_single_free_busy_request_is_accepted() {
    for (what, text) in [
        ("an event", REQUEST.replace("VFREEBUSY", "VEVENT")),
        ("a reply", REQUEST.replace("METHOD:REQUEST", "METHOD:REPLY")),
        (
            "a free-busy request next to an event",
            REQUEST.replace(
                "END:VFREEBUSY\r\n",
                "END:VFREEBUSY\r\nBEGIN:VEVENT\r\nUID:fb-1\r\nDTSTART:20270310T080000Z\r\nEND:VEVENT\r\n",
            ),
        ),
    ] {
        assert!(request_of(&text).is_err(), "{what}");
    }
    let zone = REQUEST.replace(
        "BEGIN:VFREEBUSY",
        "BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\n\
         TZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\nBEGIN:VFREEBUSY",
    );
    assert!(request_of(&zone).is_ok(), "a VTIMEZONE is no component of its own");
}

#[test]
fn organizer_attendees_and_a_range_in_utc_are_required() {
    for (needle, replacement) in [
        ("ORGANIZER;CN=\"Anna: Example\":mailto:anna@acme.example\r\n", ""),
        ("DTSTART:20270310T080000Z", "DTSTART:20270310T080000"),
        ("DTEND:20270310T180000Z", "DTEND;TZID=Europe/Berlin:20270310T180000"),
        ("DTEND:20270310T180000Z\r\n", ""),
    ] {
        assert!(request_of(&REQUEST.replace(needle, replacement)).is_err(), "{needle}");
    }
    let nobody = REQUEST
        .replace("ATTENDEE:mailto:ben@acme.example\r\n", "")
        .replace("ATTENDEE:mailto:cara@\r\n acme.example\r\n", "");
    assert!(request_of(&nobody).is_err());
}

// ---------------------------------------------------------------------------------------------------------------
// Busy time of one person
// ---------------------------------------------------------------------------------------------------------------

fn window() -> TimeRange {
    TimeRange::new(Some(at(1, 0)), Some(at(8, 0)))
}

fn busy(day: u32, hour: u32) -> BusyPeriod {
    BusyPeriod {
        start: at(day, hour),
        end: at(day, hour + 1),
        kind: BusyKind::Busy,
    }
}

fn event(uid: &str, day: u32, people: &str) -> String {
    format!(
        "BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20270101T000000Z\r\nDTSTART:202703{day:02}T100000Z\r\n\
         DTEND:202703{day:02}T110000Z\r\n{people}END:VEVENT\r\n"
    )
}

#[test]
fn a_person_is_busy_with_what_they_organize_attend_or_have_not_declined_and_free_where_they_declined() {
    let ben = [address("mailto:ben@acme.example")];
    let cal = parsed(&calendar(&format!(
        "{}{}{}{}{}",
        event("own", 1, ""),
        event(
            "organized",
            2,
            "ORGANIZER:mailto:ben@acme.example\r\nATTENDEE:mailto:cara@acme.example\r\n"
        ),
        event(
            "attended",
            3,
            "ORGANIZER:mailto:anna@acme.example\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:ben@acme.example\r\n"
        ),
        event(
            "declined",
            4,
            "ORGANIZER:mailto:anna@acme.example\r\nATTENDEE;PARTSTAT=DECLINED:mailto:ben@acme.example\r\n"
        ),
        event(
            "strangers",
            5,
            "ORGANIZER:mailto:anna@acme.example\r\nATTENDEE:mailto:cara@acme.example\r\n"
        ),
    )));
    let own = |only| Participation {
        addresses: &ben,
        participating_only: only,
    };
    let zone = TimeZoneName::utc();
    let everything = busy_periods_for(&[&cal], &window(), &limits(), zone, &own(false)).unwrap();
    assert_eq!(
        everything,
        vec![busy(1, 10), busy(2, 10), busy(3, 10), busy(5, 10)],
        "the person's own calendar counts as a whole, except what they declined"
    );
    let participating = busy_periods_for(&[&cal], &window(), &limits(), zone, &own(true)).unwrap();
    assert_eq!(
        participating,
        vec![busy(2, 10), busy(3, 10)],
        "in the calendar of a group only what the person takes part in counts, and not what they declined"
    );
}

#[test]
fn a_declined_instance_of_a_series_is_free_and_the_rest_is_busy() {
    let ben = [address("mailto:ben@acme.example")];
    let master = "BEGIN:VEVENT\r\nUID:s\r\nDTSTAMP:20270101T000000Z\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n\
        RRULE:FREQ=DAILY;COUNT=3\r\nORGANIZER:mailto:anna@acme.example\r\n\
        ATTENDEE;PARTSTAT=ACCEPTED:mailto:ben@acme.example\r\nEND:VEVENT\r\n\
        BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID:20270302T100000Z\r\nDTSTAMP:20270101T000000Z\r\n\
        DTSTART:20270302T100000Z\r\nDTEND:20270302T110000Z\r\nORGANIZER:mailto:anna@acme.example\r\n\
        ATTENDEE;PARTSTAT=DECLINED:mailto:ben@acme.example\r\nEND:VEVENT\r\n";
    let cal = parsed(&calendar(master));
    let who = Participation {
        addresses: &ben,
        participating_only: true,
    };
    let found = busy_periods_for(&[&cal], &window(), &limits(), TimeZoneName::utc(), &who).unwrap();
    assert_eq!(found, vec![busy(1, 10), busy(3, 10)]);
}
