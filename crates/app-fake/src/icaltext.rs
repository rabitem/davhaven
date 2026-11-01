//! A deliberately naive reader and writer of iCalendar text for the fake.
//!
//! The fake cannot use the real `davhaven-ical` crate (it is a separate crate and the fake must not depend on it),
//! so it understands just enough: it finds the `UID`, the component type and a handful of simple properties of the
//! first component, and renders a minimal `VEVENT` from JSON event fields. It does not validate, expand
//! recurrences or understand time zone definitions.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use davhaven_domain::{ComponentKind, EventData, EventDuration, EventStatus, EventTime, TimeZoneName, Uid};

const DATE_FORMAT: &str = "%Y%m%d";
const LOCAL_FORMAT: &str = "%Y%m%dT%H%M%S";

/// The logical lines of an iCalendar text: line endings removed, folded lines joined.
fn unfolded(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(continuation) = line.strip_prefix([' ', '\t'])
            && let Some(last) = lines.last_mut()
        {
            last.push_str(continuation);
            continue;
        }
        lines.push(line.to_owned());
    }
    lines
}

/// The first component after `BEGIN:VCALENDAR` that is an event, to-do or journal.
pub(crate) fn component_of(text: &str) -> Option<ComponentKind> {
    unfolded(text).iter().find_map(|line| {
        let name = line.strip_prefix("BEGIN:")?;
        ComponentKind::from_ical(name.trim())
    })
}

/// The name, parameters and value of a content line.
fn split_line(line: &str) -> Option<(&str, &str, &str)> {
    let (head, value) = line.split_once(':')?;
    let (name, params) = head.split_once(';').unwrap_or((head, ""));
    Some((name, params, value))
}

/// The value of the first property `name` inside the first event, to-do or journal.
fn first_property(text: &str, name: &str) -> Option<(String, String)> {
    let mut inside = false;
    for line in unfolded(text) {
        if let Some(begin) = line.strip_prefix("BEGIN:") {
            if ComponentKind::from_ical(begin.trim()).is_some() {
                inside = true;
            } else if inside {
                // A nested component (an alarm) ends the properties of the main component.
                return None;
            }
            continue;
        }
        if !inside {
            continue;
        }
        if let Some((property, params, value)) = split_line(&line)
            && property.eq_ignore_ascii_case(name)
        {
            return Some((params.to_owned(), value.to_owned()));
        }
    }
    None
}

/// The `UID` of the first component.
pub(crate) fn uid_of(text: &str) -> Option<Uid> {
    first_property(text, "UID").and_then(|(_, value)| Uid::parse(value.trim()).ok())
}

/// Whether the text looks like a calendar: it has the `VCALENDAR` envelope.
pub(crate) fn has_envelope(text: &str) -> bool {
    let lines = unfolded(text);
    let begins = lines
        .iter()
        .any(|line| line.trim().eq_ignore_ascii_case("BEGIN:VCALENDAR"));
    let ends = lines
        .iter()
        .any(|line| line.trim().eq_ignore_ascii_case("END:VCALENDAR"));
    begins && ends
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => out.push('\n'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// Reads a `DTSTART`/`DTEND` style value with its parameters.
fn parse_time(params: &str, value: &str) -> Option<EventTime> {
    let value = value.trim();
    let is_date =
        params.to_ascii_uppercase().contains("VALUE=DATE") && !params.to_ascii_uppercase().contains("DATE-TIME");
    if is_date || value.len() == 8 {
        return NaiveDate::parse_from_str(value, DATE_FORMAT).ok().map(EventTime::Date);
    }
    if let Some(utc) = value.strip_suffix('Z') {
        let local = NaiveDateTime::parse_from_str(utc, LOCAL_FORMAT).ok()?;
        return Some(EventTime::Utc(DateTime::from_naive_utc_and_offset(local, Utc)));
    }
    let local = NaiveDateTime::parse_from_str(value, LOCAL_FORMAT).ok()?;
    let zone = params
        .split(';')
        .find_map(|param| param.strip_prefix("TZID="))
        .and_then(|name| TimeZoneName::parse(name.trim_matches('"')).ok());
    Some(zone.map_or(EventTime::Floating(local), |zone| EventTime::Zoned { local, zone }))
}

/// Writes a time as a property line.
fn time_line(name: &str, time: &EventTime) -> String {
    match time {
        EventTime::Date(date) => format!("{name};VALUE=DATE:{}", date.format(DATE_FORMAT)),
        EventTime::Floating(local) => format!("{name}:{}", local.format(LOCAL_FORMAT)),
        EventTime::Zoned { local, zone } => format!("{name};TZID={zone}:{}", local.format(LOCAL_FORMAT)),
        EventTime::Utc(instant) => format!("{name}:{}Z", instant.format(LOCAL_FORMAT)),
    }
}

/// The event fields the fake understands, read from the first component of the text.
pub(crate) fn event_data(text: &str) -> EventData {
    let text_of = |name: &str| first_property(text, name).map(|(_, value)| unescape(&value));
    let time_of = |name: &str| first_property(text, name).and_then(|(params, value)| parse_time(&params, &value));
    EventData {
        uid: uid_of(text),
        summary: text_of("SUMMARY"),
        description: text_of("DESCRIPTION"),
        location: text_of("LOCATION"),
        start: time_of("DTSTART"),
        end: time_of("DTEND"),
        duration: first_property(text, "DURATION").and_then(|(_, value)| EventDuration::parse(value.trim()).ok()),
        status: first_property(text, "STATUS").and_then(|(_, value)| EventStatus::from_ical(value.trim())),
        ..EventData::default()
    }
}

/// Renders a minimal `VEVENT` from event fields.
pub(crate) fn render_event(data: &EventData, uid: &Uid, stamp: DateTime<Utc>) -> String {
    let mut lines: Vec<String> = vec![
        "BEGIN:VCALENDAR".to_owned(),
        "VERSION:2.0".to_owned(),
        "PRODID:-//Davhaven//app-fake//EN".to_owned(),
        "BEGIN:VEVENT".to_owned(),
        format!("UID:{uid}"),
        format!("DTSTAMP:{}Z", stamp.format(LOCAL_FORMAT)),
    ];
    if let Some(summary) = &data.summary {
        lines.push(format!("SUMMARY:{}", escape(summary)));
    }
    if let Some(description) = &data.description {
        lines.push(format!("DESCRIPTION:{}", escape(description)));
    }
    if let Some(location) = &data.location {
        lines.push(format!("LOCATION:{}", escape(location)));
    }
    if let Some(start) = &data.start {
        lines.push(time_line("DTSTART", start));
    }
    if let Some(end) = &data.end {
        lines.push(time_line("DTEND", end));
    } else if let Some(duration) = &data.duration {
        lines.push(format!("DURATION:{duration}"));
    }
    if let Some(status) = data.status {
        lines.push(format!("STATUS:{}", status.as_ical()));
    }
    lines.push("END:VEVENT".to_owned());
    lines.push("END:VCALENDAR".to_owned());
    let mut text = lines.join("\r\n");
    text.push_str("\r\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nEND:VTIMEZONE\r\n\
BEGIN:VEVENT\r\nUID:abc-123\r\nSUMMARY:Stand \r\n up\\, daily\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\n\
DTEND;TZID=Europe/Berlin:20270301T103000\r\nSTATUS:CONFIRMED\r\nBEGIN:VALARM\r\nSUMMARY:ignored\r\nEND:VALARM\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn reads_uid_component_and_simple_properties() {
        assert!(has_envelope(SAMPLE));
        assert_eq!(uid_of(SAMPLE).unwrap().as_str(), "abc-123");
        assert_eq!(component_of(SAMPLE), Some(ComponentKind::Event));
        let data = event_data(SAMPLE);
        assert_eq!(data.summary.as_deref(), Some("Stand up, daily"));
        assert_eq!(data.status, Some(EventStatus::Confirmed));
        assert!(matches!(data.start, Some(EventTime::Zoned { .. })));
        assert!(matches!(data.end, Some(EventTime::Zoned { .. })));
    }

    #[test]
    fn rejects_text_without_an_envelope_or_uid() {
        assert!(!has_envelope("hello"));
        assert!(!has_envelope("BEGIN:VCALENDAR\r\n"));
        assert!(uid_of("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n").is_none());
        assert!(component_of("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").is_none());
    }

    #[test]
    fn times_round_trip_through_the_renderer() {
        let uid = Uid::parse("uid-1").unwrap();
        let stamp = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2027, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            Utc,
        );
        let times = [
            EventTime::Date(NaiveDate::from_ymd_opt(2027, 3, 1).unwrap()),
            EventTime::Utc(DateTime::from_naive_utc_and_offset(
                NaiveDate::from_ymd_opt(2027, 3, 1)
                    .unwrap()
                    .and_hms_opt(10, 0, 0)
                    .unwrap(),
                Utc,
            )),
            EventTime::Floating(
                NaiveDate::from_ymd_opt(2027, 3, 1)
                    .unwrap()
                    .and_hms_opt(10, 0, 0)
                    .unwrap(),
            ),
            EventTime::Zoned {
                local: NaiveDate::from_ymd_opt(2027, 3, 1)
                    .unwrap()
                    .and_hms_opt(10, 0, 0)
                    .unwrap(),
                zone: TimeZoneName::parse("Europe/Berlin").unwrap(),
            },
        ];
        for start in times {
            let data = EventData {
                summary: Some("Line; one, two\nline two".to_owned()),
                start: Some(start.clone()),
                duration: Some(EventDuration::parse("PT1H").unwrap()),
                ..EventData::default()
            };
            let text = render_event(&data, &uid, stamp);
            assert!(has_envelope(&text), "{text}");
            let back = event_data(&text);
            assert_eq!(back.start, Some(start));
            assert_eq!(back.summary, data.summary);
            assert_eq!(back.duration, data.duration);
            assert_eq!(back.uid, Some(uid.clone()));
        }
    }
}
