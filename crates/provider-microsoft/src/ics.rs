//! Microsoft Graph events as iCalendar text.
//!
//! Graph speaks JSON, the server stores iCalendar. This module is the one translation, and it is written to be boring and
//! lossless where it matters:
//!
//! * **Every occurrence is an event.** The import reads the `calendarView` of a window, which Graph answers with the single
//!   events and the *occurrences and exceptions* of recurring ones, each with an id of its own. The mirror holds each as an
//!   event with no recurrence rule: what a person sees in their calendar app is what Outlook shows for the window, an
//!   exception included, and no recurrence pattern has to be translated (Graph's patterns, with their `index`, `firstDayOfWeek`
//!   and ranges, are not RFC 5545 rules). The price is that a series is not editable as a series in the mirror, which is read-only
//!   anyway. A cancelled occurrence is not in the answer, so it is not in the mirror.
//! * **Times keep their meaning.** An all-day event is a `DATE`. A timed event is written in the zone Graph names for it (a Windows
//!   zone name such as `W. Europe Standard Time`, which the server resolves, PLAN 2.15), or in UTC. A zone name that cannot be a
//!   `TZID` parameter is not passed on: the time is then floating. Graph answers in UTC unless a request says `Prefer:
//!   outlook.timezone`, and the import does not, so the events of an account arrive as instants; the converter handles a named
//!   zone all the same.
//! * **Attendees, organizers, alarms and online-meeting data are not imported**: the mirror is for seeing one's own calendar, and it
//!   never schedules.
//! * **Text is bounded** (a title and a location to 1000 characters, a description to 30000), escaped as RFC 5545 asks and folded at
//!   75 octets, so that the server's limits (PLAN 2.15) are not what decides whether an event arrives.
//!
//! The text of the description is plain: the request asks Graph for it (`Prefer: outlook.body-content-type="text"`).

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use davhaven_ports::RemoteChange;
use serde::Deserialize;

/// The longest title or location, in characters.
const MAX_LINE_TEXT: usize = 1000;
/// The longest description, in characters.
const MAX_DESCRIPTION: usize = 30_000;
/// The longest UID, in characters.
const MAX_UID: usize = 250;

/// A start or an end: a local date-time and the zone it is local in.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Zoned {
    /// `2026-10-28T09:00:00.0000000`: no offset, the zone is next to it.
    pub(crate) date_time: Option<String>,
    /// A Windows or IANA zone name, or `UTC`.
    pub(crate) time_zone: Option<String>,
}

/// The body of an event.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct Body {
    pub(crate) content: Option<String>,
}

/// The location of an event.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Location {
    pub(crate) display_name: Option<String>,
}

/// An event of Microsoft Graph, with the members the import reads.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Event {
    pub(crate) id: String,
    pub(crate) change_key: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) body: Option<Body>,
    pub(crate) start: Option<Zoned>,
    pub(crate) end: Option<Zoned>,
    pub(crate) is_all_day: bool,
    pub(crate) is_cancelled: bool,
    pub(crate) show_as: Option<String>,
    pub(crate) sensitivity: Option<String>,
    pub(crate) location: Option<Location>,
    pub(crate) created_date_time: Option<String>,
    pub(crate) last_modified_date_time: Option<String>,
}

/// A local date-time as Graph writes it (`2026-10-28T09:00:00.0000000`; a trailing `Z` or offset is ignored, the zone is the one
/// next to it).
fn local(text: &str) -> Option<NaiveDateTime> {
    let text: String = text.chars().take(27).collect();
    NaiveDateTime::parse_from_str(&text, "%Y-%m-%dT%H:%M:%S%.f")
        .or_else(|_| NaiveDateTime::parse_from_str(&text, "%Y-%m-%dT%H:%M:%S"))
        .ok()
}

fn instant(text: Option<&str>) -> Option<DateTime<Utc>> {
    text.and_then(local).map(|naive| naive.and_utc())
}

/// How a time is written.
enum Zone<'a> {
    /// An instant in UTC (`Z`).
    Utc,
    /// Local time in a zone that is a `TZID` (`TZID=W. Europe Standard Time`).
    Named(&'a str),
    /// Local time without a zone: the name cannot be a `TZID` parameter.
    Floating,
}

fn zone_of(name: Option<&str>) -> Zone<'_> {
    let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) else {
        return Zone::Utc;
    };
    if ["utc", "etc/utc", "uct", "zulu", "tzone://microsoft/utc"]
        .iter()
        .any(|alias| name.eq_ignore_ascii_case(alias))
    {
        return Zone::Utc;
    }
    let plain = name.len() <= 100
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '/' | '-' | '+' | '(' | ')'));
    if plain { Zone::Named(name) } else { Zone::Floating }
}

/// The text of a date-time property (`DTSTART`, `DTEND`) of a timed event.
fn timed(name: &str, local: NaiveDateTime, zone: &Zone<'_>) -> String {
    let text = local.format("%Y%m%dT%H%M%S");
    match zone {
        Zone::Utc => format!("{name}:{text}Z"),
        Zone::Named(zone) => format!("{name};TZID={zone}:{text}"),
        Zone::Floating => format!("{name}:{text}"),
    }
}

/// Escapes a text value (RFC 5545 section 3.3.11) and drops control characters other than the tab.
fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str("\\n");
            }
            '\n' => out.push_str("\\n"),
            '\t' => out.push('\t'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// A calendar object under construction: lines are folded at 75 octets and end in CRLF.
struct Ics {
    out: String,
}

impl Ics {
    fn line(&mut self, text: &str) {
        let mut width = 0_usize;
        for c in text.chars() {
            let size = c.len_utf8();
            if width + size > 75 {
                self.out.push_str("\r\n ");
                width = 1;
            }
            self.out.push(c);
            width += size;
        }
        self.out.push_str("\r\n");
    }

    fn text(&mut self, name: &str, value: &str, max: usize) {
        let value: String = value.chars().take(max).collect();
        if !value.trim().is_empty() {
            self.line(&format!("{name}:{}", escape_text(&value)));
        }
    }

    fn timestamp(&mut self, name: &str, instant: DateTime<Utc>) {
        self.line(&format!("{name}:{}", instant.format("%Y%m%dT%H%M%SZ")));
    }
}

/// The calendar object of an event, or nothing when it is cancelled or has no usable start.
fn object(event: &Event, now: DateTime<Utc>) -> Option<String> {
    if event.is_cancelled || event.id.is_empty() {
        return None;
    }
    let start = event.start.as_ref()?;
    let start_local = local(start.date_time.as_deref()?)?;
    let mut ics = Ics { out: String::new() };
    ics.line("BEGIN:VCALENDAR");
    ics.line("VERSION:2.0");
    ics.line("PRODID:-//Davhaven//Microsoft 365 calendar import//EN");
    ics.line("BEGIN:VEVENT");
    let uid: String = event.id.chars().take(MAX_UID).collect();
    ics.line(&format!("UID:{}", escape_text(&uid)));
    let modified = instant(event.last_modified_date_time.as_deref());
    let created = instant(event.created_date_time.as_deref());
    ics.timestamp("DTSTAMP", modified.or(created).unwrap_or(now));
    if let Some(created) = created {
        ics.timestamp("CREATED", created);
    }
    if let Some(modified) = modified {
        ics.timestamp("LAST-MODIFIED", modified);
    }
    if let Some(subject) = &event.subject {
        ics.text("SUMMARY", subject, MAX_LINE_TEXT);
    }
    if let Some(description) = event.body.as_ref().and_then(|body| body.content.as_deref()) {
        ics.text("DESCRIPTION", description, MAX_DESCRIPTION);
    }
    if let Some(place) = event
        .location
        .as_ref()
        .and_then(|location| location.display_name.as_deref())
    {
        ics.text("LOCATION", place, MAX_LINE_TEXT);
    }
    if event.show_as.as_deref() == Some("tentative") {
        ics.line("STATUS:TENTATIVE");
    }
    if event.show_as.as_deref() == Some("free") {
        ics.line("TRANSP:TRANSPARENT");
    }
    match event.sensitivity.as_deref() {
        Some("private" | "personal") => ics.line("CLASS:PRIVATE"),
        Some("confidential") => ics.line("CLASS:CONFIDENTIAL"),
        _ => {}
    }
    let end_local = event
        .end
        .as_ref()
        .and_then(|end| end.date_time.as_deref())
        .and_then(local);
    if event.is_all_day {
        let first: NaiveDate = start_local.date();
        ics.line(&format!("DTSTART;VALUE=DATE:{}", first.format("%Y%m%d")));
        let last = end_local
            .map(|end| end.date())
            .filter(|end| *end > first)
            .or_else(|| first.succ_opt());
        if let Some(last) = last {
            ics.line(&format!("DTEND;VALUE=DATE:{}", last.format("%Y%m%d")));
        }
    } else {
        ics.line(&timed("DTSTART", start_local, &zone_of(start.time_zone.as_deref())));
        if let (Some(end), Some(end_local)) = (&event.end, end_local) {
            ics.line(&timed("DTEND", end_local, &zone_of(end.time_zone.as_deref())));
        }
    }
    ics.line("END:VEVENT");
    ics.line("END:VCALENDAR");
    Some(ics.out)
}

/// The mirror's view of a listing of events: one change per event, in the order of the ids. `now` is the time stamp of an event
/// that has none. An event that is cancelled or has no start is left out.
pub(crate) fn convert(events: &[Event], now: DateTime<Utc>) -> Vec<RemoteChange> {
    let mut out: Vec<RemoteChange> = events
        .iter()
        .filter_map(|event| {
            object(event, now).map(|ics| RemoteChange {
                remote_id: event.id.clone(),
                etag: event.change_key.clone(),
                ics: Some(ics),
            })
        })
        .collect();
    out.sort_by(|a, b| a.remote_id.cmp(&b.remote_id));
    out.dedup_by(|a, b| a.remote_id == b.remote_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-28T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn only(json: &str) -> String {
        let events: Vec<Event> = serde_json::from_str(json).unwrap();
        let mut changes = convert(&events, now());
        assert_eq!(changes.len(), 1, "{changes:?}");
        changes.remove(0).ics.unwrap()
    }

    fn lines(text: &[&str]) -> String {
        let mut joined = text.join("\r\n");
        joined.push_str("\r\n");
        joined
    }

    #[test]
    fn a_timed_event_keeps_its_zone_and_its_text_is_escaped() {
        let ics = only(
            r#"[{"id":"AAMkAGI2=","changeKey":"CQAAABYAAA","subject":"Planning, Q4; \"final\"",
                "body":{"contentType":"text","content":"Line one\r\nLine two"},"location":{"displayName":"Room 4"},
                "createdDateTime":"2026-10-01T08:00:00.1234567Z","lastModifiedDateTime":"2026-10-20T09:30:00.0000000Z",
                "start":{"dateTime":"2026-11-02T10:00:00.0000000","timeZone":"W. Europe Standard Time"},
                "end":{"dateTime":"2026-11-02T11:30:00.0000000","timeZone":"W. Europe Standard Time"},
                "isAllDay":false,"isCancelled":false,"showAs":"busy","sensitivity":"normal","type":"singleInstance"}]"#,
        );
        assert_eq!(
            ics,
            lines(&[
                "BEGIN:VCALENDAR",
                "VERSION:2.0",
                "PRODID:-//Davhaven//Microsoft 365 calendar import//EN",
                "BEGIN:VEVENT",
                "UID:AAMkAGI2=",
                "DTSTAMP:20261020T093000Z",
                "CREATED:20261001T080000Z",
                "LAST-MODIFIED:20261020T093000Z",
                "SUMMARY:Planning\\, Q4\\; \"final\"",
                "DESCRIPTION:Line one\\nLine two",
                "LOCATION:Room 4",
                "DTSTART;TZID=W. Europe Standard Time:20261102T100000",
                "DTEND;TZID=W. Europe Standard Time:20261102T113000",
                "END:VEVENT",
                "END:VCALENDAR",
            ])
        );
    }

    #[test]
    fn utc_floating_and_named_zones_are_written_accordingly() {
        let utc = only(
            r#"[{"id":"u","start":{"dateTime":"2026-11-02T10:00:00.0000000","timeZone":"UTC"},
                "end":{"dateTime":"2026-11-02T11:00:00.0000000","timeZone":"tzone://Microsoft/Utc"}}]"#,
        );
        assert!(
            utc.contains("DTSTART:20261102T100000Z\r\n") && utc.contains("DTEND:20261102T110000Z\r\n"),
            "{utc}"
        );
        let iana = only(r#"[{"id":"i","start":{"dateTime":"2026-11-02T10:00:00","timeZone":"America/New_York"}}]"#);
        assert!(
            iana.contains("DTSTART;TZID=America/New_York:20261102T100000\r\n"),
            "{iana}"
        );
        assert!(!iana.contains("DTEND"), "an event without an end has none");
        for odd in [
            "tzone://Microsoft/Custom",
            "Zone;with,separators",
            "Zone\"quoted",
            "Zone\u{7}bell",
        ] {
            let json = format!(
                r#"[{{"id":"f","start":{{"dateTime":"2026-11-02T10:00:00.0000000","timeZone":{}}}}}]"#,
                serde_json::to_string(odd).unwrap()
            );
            let floating = only(&json);
            assert!(floating.contains("DTSTART:20261102T100000\r\n"), "{odd}: {floating}");
        }
    }

    #[test]
    fn an_all_day_event_is_a_date_and_sensitivity_and_availability_are_kept() {
        let ics = only(
            r#"[{"id":"d","subject":"Holiday","isAllDay":true,"showAs":"free","sensitivity":"private",
                "start":{"dateTime":"2026-12-24T00:00:00.0000000","timeZone":"W. Europe Standard Time"},
                "end":{"dateTime":"2026-12-26T00:00:00.0000000","timeZone":"W. Europe Standard Time"}}]"#,
        );
        for line in [
            "DTSTART;VALUE=DATE:20261224",
            "DTEND;VALUE=DATE:20261226",
            "TRANSP:TRANSPARENT",
            "CLASS:PRIVATE",
            "DTSTAMP:20261028T120000Z",
        ] {
            assert!(ics.contains(&format!("{line}\r\n")), "{line}\n{ics}");
        }
        let one_day =
            only(r#"[{"id":"d","isAllDay":true,"start":{"dateTime":"2026-12-31T00:00:00.0000000","timeZone":"UTC"}}]"#);
        assert!(one_day.contains("DTEND;VALUE=DATE:20270101\r\n"), "{one_day}");
        let zero = only(
            r#"[{"id":"d","isAllDay":true,"start":{"dateTime":"2026-12-31T00:00:00.0000000","timeZone":"UTC"},
                "end":{"dateTime":"2026-12-31T00:00:00.0000000","timeZone":"UTC"}}]"#,
        );
        assert!(
            zero.contains("DTEND;VALUE=DATE:20270101\r\n"),
            "an end that is not after the start is one day: {zero}"
        );
        let tentative = only(
            r#"[{"id":"t","showAs":"tentative","sensitivity":"confidential","start":{"dateTime":"2026-12-31T10:00:00","timeZone":"UTC"}}]"#,
        );
        assert!(
            tentative.contains("STATUS:TENTATIVE\r\n") && tentative.contains("CLASS:CONFIDENTIAL\r\n"),
            "{tentative}"
        );
    }

    #[test]
    fn cancelled_events_and_events_that_cannot_be_shown_are_left_out_and_the_rest_is_ordered() {
        let events: Vec<Event> = serde_json::from_str(
            r#"[{"id":"b","start":{"dateTime":"2026-12-31T10:00:00","timeZone":"UTC"}},
                {"id":"dead","isCancelled":true,"start":{"dateTime":"2026-12-31T10:00:00","timeZone":"UTC"}},
                {"id":"nostart","subject":"No time"},
                {"id":"badtime","start":{"dateTime":"not a time","timeZone":"UTC"}},
                {"id":""},
                {"id":"a","start":{"dateTime":"2026-12-30T10:00:00","timeZone":"UTC"}},
                {"id":"a","start":{"dateTime":"2026-12-30T10:00:00","timeZone":"UTC"}}]"#,
        )
        .unwrap();
        let changes = convert(&events, now());
        assert_eq!(
            changes
                .iter()
                .map(|change| change.remote_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"],
            "ordered by id, one object per id"
        );
    }

    #[test]
    fn long_lines_are_folded_and_text_is_bounded() {
        let ics = only(&format!(
            r#"[{{"id":"long","subject":"{}","body":{{"content":"{}"}},"start":{{"dateTime":"2026-12-31T10:00:00","timeZone":"UTC"}}}}]"#,
            "Überraschungsfeier ".repeat(12),
            "d".repeat(40_000)
        ));
        for line in ics.split("\r\n") {
            assert!(line.len() <= 75, "{} octets: {line}", line.len());
        }
        let unfolded = ics.replace("\r\n ", "");
        assert!(unfolded.contains("SUMMARY:Überraschungsfeier Überraschungsfeier"));
        assert!(unfolded.contains(&format!("DESCRIPTION:{}\r\n", "d".repeat(MAX_DESCRIPTION))));
    }

    #[test]
    fn control_characters_never_reach_the_calendar_object() {
        let ics = only(
            r#"[{"id":"x\r\nBEGIN:VEVENT","subject":"a\u0000b\u0007c","start":{"dateTime":"2026-12-31T10:00:00","timeZone":"UTC"}}]"#,
        );
        assert!(ics.contains("SUMMARY:abc\r\n"), "{ics}");
        assert_eq!(ics.lines().filter(|line| *line == "BEGIN:VEVENT").count(), 1, "{ics}");
        assert!(
            ics.contains("UID:x\\nBEGIN:VEVENT\r\n"),
            "a break in an id is text, not a line: {ics}"
        );
    }
}
