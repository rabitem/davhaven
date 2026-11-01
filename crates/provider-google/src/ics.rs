//! Google events as iCalendar text.
//!
//! Google's calendar API speaks JSON, the server stores iCalendar. This module is the one translation, and it is written to
//! be boring and lossless where it matters:
//!
//! * **A series is one object.** A recurring event is a master with `recurrence` lines (RRULE, EXDATE, RDATE: they already are
//!   iCalendar, and are passed through), plus separate events for the instances that were changed (`recurringEventId` names the
//!   master, `originalStartTime` the instance) or cancelled. The mirror holds one object per series: the master, an `EXDATE`
//!   for every cancelled instance and an override with `RECURRENCE-ID` for every changed one. An instance whose master is not in
//!   the listing (a series that ended before the window) becomes an event of its own.
//! * **Times keep their meaning.** An all-day event is a `DATE`. A one-off event is an instant in UTC. A series keeps the time
//!   zone Google names for it, so that "every Monday at 10:00" stays at 10:00 across a change of daylight saving time.
//! * **Attendees, organizers, alarms and conference data are not imported.** The mirror is for seeing one's own calendar next to
//!   the others, and it never schedules; the people on an event are other people's data.
//! * **Text is bounded** (a title and a location to 1000 characters, a description to 30000), escaped as RFC 5545 asks and
//!   folded at 75 octets, so that the server's limits (PLAN 2.15) are not what decides whether an event arrives.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr as _;

use chrono::{DateTime, FixedOffset, NaiveDate, Utc};
use chrono_tz::Tz;
use davhaven_ports::RemoteChange;
use serde::Deserialize;

/// The longest title or location, in characters.
const MAX_LINE_TEXT: usize = 1000;
/// The longest description, in characters.
const MAX_DESCRIPTION: usize = 30_000;

/// A start, end or original start of an event.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Moment {
    /// The date of an all-day event (`2026-10-28`).
    pub(crate) date: Option<String>,
    /// The instant of a timed event, with its offset (RFC 3339).
    pub(crate) date_time: Option<String>,
    /// The IANA zone of the event (`Europe/Berlin`).
    pub(crate) time_zone: Option<String>,
}

/// An event of the Google Calendar API, with the members the import reads.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Event {
    pub(crate) id: String,
    pub(crate) etag: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) summary: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) location: Option<String>,
    pub(crate) start: Option<Moment>,
    pub(crate) end: Option<Moment>,
    pub(crate) recurrence: Vec<String>,
    pub(crate) recurring_event_id: Option<String>,
    pub(crate) original_start_time: Option<Moment>,
    pub(crate) transparency: Option<String>,
    pub(crate) visibility: Option<String>,
    #[serde(rename = "iCalUID")]
    pub(crate) ical_uid: Option<String>,
    pub(crate) sequence: Option<i64>,
    pub(crate) created: Option<String>,
    pub(crate) updated: Option<String>,
}

impl Event {
    fn cancelled(&self) -> bool {
        self.status.as_deref() == Some("cancelled")
    }
}

/// A parsed `Moment`.
#[derive(Debug, Clone, Copy)]
enum When {
    Date(NaiveDate),
    Instant(DateTime<FixedOffset>),
}

fn when(moment: &Moment) -> Option<When> {
    if let Some(date) = moment.date.as_deref() {
        return NaiveDate::parse_from_str(date, "%Y-%m-%d").ok().map(When::Date);
    }
    moment
        .date_time
        .as_deref()
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(When::Instant)
}

/// Whether a zone is UTC under another name, which is written as `Z` instead of a `TZID`.
fn is_utc(zone: Tz) -> bool {
    matches!(
        zone.name(),
        "UTC" | "Etc/UTC" | "Etc/UCT" | "Etc/Universal" | "Etc/Zulu" | "UCT" | "Universal" | "Zulu"
    )
}

/// The text of a date or date-time property (`DTSTART`, `DTEND`, `RECURRENCE-ID`, `EXDATE`): a `DATE`, an instant in UTC, or
/// the local time in `zone` with its `TZID`.
fn date_property(name: &str, when: When, zone: Option<Tz>) -> String {
    match when {
        When::Date(date) => format!("{name};VALUE=DATE:{}", date.format("%Y%m%d")),
        When::Instant(instant) => match zone.filter(|zone| !is_utc(*zone)) {
            Some(zone) => format!(
                "{name};TZID={}:{}",
                zone.name(),
                instant.with_timezone(&zone).format("%Y%m%dT%H%M%S")
            ),
            None => format!("{name}:{}", instant.with_timezone(&Utc).format("%Y%m%dT%H%M%SZ")),
        },
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

/// The text of at most `max` characters.
fn truncated(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// A calendar object under construction: lines are folded at 75 octets and end in CRLF.
struct Ics {
    out: String,
}

impl Ics {
    fn new() -> Self {
        Self { out: String::new() }
    }

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
        let value = truncated(value, max);
        if !value.trim().is_empty() {
            self.line(&format!("{name}:{}", escape_text(&value)));
        }
    }

    fn timestamp(&mut self, name: &str, instant: DateTime<Utc>) {
        self.line(&format!("{name}:{}", instant.format("%Y%m%dT%H%M%SZ")));
    }
}

fn parse_instant(text: Option<&str>) -> Option<DateTime<Utc>> {
    text.and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|instant| instant.with_timezone(&Utc))
}

/// The properties every `VEVENT` of an event has, besides its times.
fn describe(ics: &mut Ics, event: &Event, uid: &str, now: DateTime<Utc>) {
    ics.line(&format!("UID:{}", escape_text(uid)));
    let updated = parse_instant(event.updated.as_deref());
    ics.timestamp(
        "DTSTAMP",
        updated
            .or_else(|| parse_instant(event.created.as_deref()))
            .unwrap_or(now),
    );
    if let Some(created) = parse_instant(event.created.as_deref()) {
        ics.timestamp("CREATED", created);
    }
    if let Some(updated) = updated {
        ics.timestamp("LAST-MODIFIED", updated);
    }
    if let Some(sequence) = event.sequence.filter(|sequence| *sequence > 0) {
        ics.line(&format!("SEQUENCE:{sequence}"));
    }
    if let Some(summary) = &event.summary {
        ics.text("SUMMARY", summary, MAX_LINE_TEXT);
    }
    if let Some(description) = &event.description {
        ics.text("DESCRIPTION", description, MAX_DESCRIPTION);
    }
    if let Some(location) = &event.location {
        ics.text("LOCATION", location, MAX_LINE_TEXT);
    }
    match event.status.as_deref() {
        Some("confirmed") => ics.line("STATUS:CONFIRMED"),
        Some("tentative") => ics.line("STATUS:TENTATIVE"),
        _ => {}
    }
    if event.transparency.as_deref() == Some("transparent") {
        ics.line("TRANSP:TRANSPARENT");
    }
    match event.visibility.as_deref() {
        Some("public") => ics.line("CLASS:PUBLIC"),
        Some("private") => ics.line("CLASS:PRIVATE"),
        Some("confidential") => ics.line("CLASS:CONFIDENTIAL"),
        _ => {}
    }
}

/// `DTSTART` and `DTEND` of an event in `zone`. An event without a start cannot be shown and has none of them.
fn times(ics: &mut Ics, event: &Event, zone: Option<Tz>) -> Option<()> {
    let start = event.start.as_ref().and_then(when)?;
    ics.line(&date_property("DTSTART", start, zone));
    match (event.end.as_ref().and_then(when), start) {
        (Some(end), _) => ics.line(&date_property("DTEND", end, zone)),
        (None, When::Date(date)) => {
            if let Some(next) = date.succ_opt() {
                ics.line(&date_property("DTEND", When::Date(next), zone));
            }
        }
        (None, When::Instant(_)) => {}
    }
    Some(())
}

/// The recurrence lines of a master that are iCalendar properties of the kinds that are meant (`RRULE`, `EXRULE`, `RDATE`,
/// `EXDATE`), without control characters.
fn recurrence_lines(event: &Event) -> Vec<String> {
    event
        .recurrence
        .iter()
        .map(|line| line.chars().filter(|c| !c.is_control()).collect::<String>())
        .filter(|line| {
            let upper = line.to_ascii_uppercase();
            ["RRULE", "EXRULE", "RDATE", "EXDATE"].iter().any(|name| {
                upper
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with(':') || rest.starts_with(';'))
            })
        })
        .collect()
}

/// The zone a series is expanded in: the one Google names for its start, else UTC.
fn series_zone(master: &Event) -> Tz {
    master
        .start
        .as_ref()
        .and_then(|start| start.time_zone.as_deref())
        .and_then(|name| Tz::from_str(name).ok())
        .unwrap_or(Tz::UTC)
}

/// The uid of an event: its iCalendar UID, else its id.
fn uid_of(event: &Event) -> &str {
    event
        .ical_uid
        .as_deref()
        .filter(|uid| !uid.trim().is_empty())
        .unwrap_or(&event.id)
}

/// The calendar object of an event that is not part of a series, or of a series with its changed and cancelled instances.
fn object(master: &Event, children: &[Event], now: DateTime<Utc>) -> Option<String> {
    let series = !recurrence_lines(master).is_empty();
    let zone = series.then(|| series_zone(master));
    let uid = uid_of(master);
    let mut ics = Ics::new();
    ics.line("BEGIN:VCALENDAR");
    ics.line("VERSION:2.0");
    ics.line("PRODID:-//Davhaven//Google Calendar import//EN");
    ics.line("BEGIN:VEVENT");
    describe(&mut ics, master, uid, now);
    times(&mut ics, master, zone)?;
    if series {
        for line in recurrence_lines(master) {
            ics.line(&line);
        }
        // A cancelled instance is an exception date of the series.
        for child in children.iter().filter(|child| child.cancelled()) {
            if let Some(original) = child.original_start_time.as_ref().and_then(when) {
                ics.line(&date_property("EXDATE", original, zone));
            }
        }
    }
    ics.line("END:VEVENT");
    let mut changed: Vec<&Event> = children.iter().filter(|child| !child.cancelled()).collect();
    changed.sort_by(|a, b| a.id.cmp(&b.id));
    for child in changed {
        let Some(original) = child.original_start_time.as_ref().and_then(when) else {
            continue;
        };
        let mut part = Ics::new();
        part.line("BEGIN:VEVENT");
        describe(&mut part, child, uid, now);
        part.line(&date_property("RECURRENCE-ID", original, zone));
        if times(&mut part, child, zone).is_none() {
            continue;
        }
        part.line("END:VEVENT");
        ics.out.push_str(&part.out);
    }
    ics.line("END:VCALENDAR");
    Some(ics.out)
}

/// The mirror's view of a listing of events: one change per series or event, in the order of the ids.
///
/// `now` is the time stamp of an event that has none. An event that cannot be shown (it has no start) and a cancelled one is
/// left out.
pub(crate) fn convert(events: Vec<Event>, now: DateTime<Utc>) -> Vec<RemoteChange> {
    let (children, parents): (Vec<Event>, Vec<Event>) = events
        .into_iter()
        .filter(|event| !event.id.is_empty())
        .partition(|event| event.recurring_event_id.is_some());
    let masters: BTreeSet<&str> = parents
        .iter()
        .filter(|event| !recurrence_lines(event).is_empty())
        .map(|event| event.id.as_str())
        .collect();
    let mut kids: BTreeMap<String, Vec<Event>> = BTreeMap::new();
    let mut orphans: Vec<Event> = Vec::new();
    for child in children {
        let master = child.recurring_event_id.clone().unwrap_or_default();
        if masters.contains(master.as_str()) {
            kids.entry(master).or_default().push(child);
        } else {
            orphans.push(child);
        }
    }
    let mut out: Vec<RemoteChange> = Vec::new();
    for parent in &parents {
        if parent.cancelled() {
            continue;
        }
        let own = kids.remove(&parent.id).unwrap_or_default();
        if let Some(ics) = object(parent, &own, now) {
            out.push(RemoteChange {
                remote_id: parent.id.clone(),
                etag: parent.etag.clone(),
                ics: Some(ics),
            });
        }
    }
    for orphan in &orphans {
        if orphan.cancelled() {
            continue;
        }
        // Without its series an instance stands for itself: it is not a recurrence any more. The instances of one series share the
        // iCalendar UID of the series, and a calendar holds a UID once, so each is named by its own id (a second changed instance
        // of the same series would otherwise be refused at every pull).
        let standalone = Event {
            recurrence: Vec::new(),
            ical_uid: Some(orphan.id.clone()),
            ..orphan.clone()
        };
        if let Some(ics) = object(&standalone, &[], now) {
            out.push(RemoteChange {
                remote_id: orphan.id.clone(),
                etag: orphan.etag.clone(),
                ics: Some(ics),
            });
        }
    }
    out.sort_by(|a, b| a.remote_id.cmp(&b.remote_id));
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

    fn events(json: &str) -> Vec<Event> {
        serde_json::from_str::<Vec<Event>>(json).unwrap()
    }

    fn only(json: &str) -> String {
        let mut changes = convert(events(json), now());
        assert_eq!(changes.len(), 1, "{changes:?}");
        changes.remove(0).ics.unwrap()
    }

    #[test]
    fn a_one_off_event_is_an_instant_in_utc_with_its_text_escaped() {
        let ics = only(
            r#"[{"id":"abc1","etag":"\"e1\"","status":"confirmed","iCalUID":"abc1@google.com",
                "summary":"Planning, Q4; \"final\"","description":"Line one\nLine two\\done","location":"Room 4",
                "created":"2026-10-01T08:00:00.000Z","updated":"2026-10-20T09:30:00.123Z","sequence":2,
                "start":{"dateTime":"2026-11-02T10:00:00+01:00","timeZone":"Europe/Berlin"},
                "end":{"dateTime":"2026-11-02T11:30:00+01:00","timeZone":"Europe/Berlin"}}]"#,
        );
        assert_eq!(
            ics,
            [
                "BEGIN:VCALENDAR",
                "VERSION:2.0",
                "PRODID:-//Davhaven//Google Calendar import//EN",
                "BEGIN:VEVENT",
                "UID:abc1@google.com",
                "DTSTAMP:20261020T093000Z",
                "CREATED:20261001T080000Z",
                "LAST-MODIFIED:20261020T093000Z",
                "SEQUENCE:2",
                "SUMMARY:Planning\\, Q4\\; \"final\"",
                "DESCRIPTION:Line one\\nLine two\\\\done",
                "LOCATION:Room 4",
                "STATUS:CONFIRMED",
                "DTSTART:20261102T090000Z",
                "DTEND:20261102T103000Z",
                "END:VEVENT",
                "END:VCALENDAR",
                "",
            ]
            .join("\r\n")
        );
    }

    #[test]
    fn an_all_day_event_is_a_date_and_visibility_and_transparency_are_kept() {
        let ics = only(
            r#"[{"id":"day1","summary":"Holiday","transparency":"transparent","visibility":"private","status":"tentative",
                "start":{"date":"2026-12-24"},"end":{"date":"2026-12-25"},"updated":"2026-10-20T09:30:00Z"}]"#,
        );
        for line in [
            "UID:day1",
            "STATUS:TENTATIVE",
            "TRANSP:TRANSPARENT",
            "CLASS:PRIVATE",
            "DTSTART;VALUE=DATE:20261224",
            "DTEND;VALUE=DATE:20261225",
        ] {
            assert!(ics.contains(&format!("{line}\r\n")), "{line}\n{ics}");
        }
        assert!(ics.contains("DTSTAMP:20261020T093000Z\r\n"));
        assert!(!ics.contains("SEQUENCE"), "a sequence of zero is not written");
    }

    #[test]
    fn an_all_day_event_without_an_end_lasts_one_day_and_a_timed_one_without_an_end_has_none() {
        let all_day = only(r#"[{"id":"d","start":{"date":"2026-12-31"}}]"#);
        assert!(all_day.contains("DTEND;VALUE=DATE:20270101\r\n"), "{all_day}");
        let timed = only(r#"[{"id":"t","start":{"dateTime":"2026-12-31T10:00:00Z"}}]"#);
        assert!(!timed.contains("DTEND"), "{timed}");
        assert!(
            timed.contains("DTSTAMP:20261028T120000Z\r\n"),
            "an event without a time stamp gets the time of the pull: {timed}"
        );
    }

    #[test]
    fn a_series_keeps_its_zone_its_rules_its_cancelled_instances_and_its_changed_ones() {
        let ics = only(
            r#"[
              {"id":"series1","iCalUID":"series1@google.com","summary":"Stand-up","updated":"2026-10-20T09:30:00Z",
               "start":{"dateTime":"2026-10-26T10:00:00+01:00","timeZone":"Europe/Berlin"},
               "end":{"dateTime":"2026-10-26T10:15:00+01:00","timeZone":"Europe/Berlin"},
               "recurrence":["RRULE:FREQ=WEEKLY;BYDAY=MO","EXDATE;TZID=Europe/Berlin:20261109T100000","X-EVIL:injected"]},
              {"id":"series1_20261102T090000Z","recurringEventId":"series1","status":"cancelled",
               "originalStartTime":{"dateTime":"2026-11-02T10:00:00+01:00","timeZone":"Europe/Berlin"}},
              {"id":"series1_20261116T090000Z","recurringEventId":"series1","summary":"Stand-up (long)","updated":"2026-10-21T09:30:00Z",
               "originalStartTime":{"dateTime":"2026-11-16T10:00:00+01:00","timeZone":"Europe/Berlin"},
               "start":{"dateTime":"2026-11-16T11:00:00+01:00","timeZone":"Europe/Berlin"},
               "end":{"dateTime":"2026-11-16T12:00:00+01:00","timeZone":"Europe/Berlin"}}
            ]"#,
        );
        assert_eq!(
            ics,
            [
                "BEGIN:VCALENDAR",
                "VERSION:2.0",
                "PRODID:-//Davhaven//Google Calendar import//EN",
                "BEGIN:VEVENT",
                "UID:series1@google.com",
                "DTSTAMP:20261020T093000Z",
                "LAST-MODIFIED:20261020T093000Z",
                "SUMMARY:Stand-up",
                "DTSTART;TZID=Europe/Berlin:20261026T100000",
                "DTEND;TZID=Europe/Berlin:20261026T101500",
                "RRULE:FREQ=WEEKLY;BYDAY=MO",
                "EXDATE;TZID=Europe/Berlin:20261109T100000",
                "EXDATE;TZID=Europe/Berlin:20261102T100000",
                "END:VEVENT",
                "BEGIN:VEVENT",
                "UID:series1@google.com",
                "DTSTAMP:20261021T093000Z",
                "LAST-MODIFIED:20261021T093000Z",
                "SUMMARY:Stand-up (long)",
                "RECURRENCE-ID;TZID=Europe/Berlin:20261116T100000",
                "DTSTART;TZID=Europe/Berlin:20261116T110000",
                "DTEND;TZID=Europe/Berlin:20261116T120000",
                "END:VEVENT",
                "END:VCALENDAR",
                "",
            ]
            .join("\r\n"),
            "a series is one object; lines that are no recurrence properties are dropped"
        );
    }

    #[test]
    fn an_all_day_series_is_expanded_in_dates() {
        let ics = only(
            r#"[{"id":"s","start":{"date":"2026-10-01"},"end":{"date":"2026-10-02"},"recurrence":["RRULE:FREQ=MONTHLY","exdate;value=date:20261201"]},
                {"id":"s_20261101","recurringEventId":"s","status":"cancelled","originalStartTime":{"date":"2026-11-01"}}]"#,
        );
        for line in [
            "DTSTART;VALUE=DATE:20261001",
            "RRULE:FREQ=MONTHLY",
            "exdate;value=date:20261201",
            "EXDATE;VALUE=DATE:20261101",
        ] {
            assert!(ics.contains(&format!("{line}\r\n")), "{line}\n{ics}");
        }
    }

    #[test]
    fn an_instance_without_its_series_stands_for_itself_and_cancelled_things_are_left_out() {
        let changes = convert(
            events(
                r#"[{"id":"orphan_1","recurringEventId":"gone","summary":"Moved instance","iCalUID":"gone@google.com",
                      "start":{"dateTime":"2026-11-03T08:00:00Z"},"end":{"dateTime":"2026-11-03T09:00:00Z"},
                      "originalStartTime":{"dateTime":"2026-11-02T08:00:00Z"}},
                     {"id":"orphan_2","recurringEventId":"gone","status":"cancelled","originalStartTime":{"date":"2026-11-09"}},
                     {"id":"dead","status":"cancelled","start":{"date":"2026-11-09"}},
                     {"id":"nostart","summary":"No time"},
                     {"id":""}]"#,
            ),
            now(),
        );
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0].remote_id, "orphan_1");
        let ics = changes[0].ics.as_deref().unwrap();
        assert!(
            ics.contains("UID:orphan_1\r\n") && !ics.contains("RECURRENCE-ID"),
            "{ics}"
        );
    }

    #[test]
    fn several_changed_instances_of_a_series_that_is_not_listed_have_a_uid_each() {
        let changes = convert(
            events(
                r#"[{"id":"gone_20261102T080000Z","recurringEventId":"gone","iCalUID":"gone@google.com","summary":"One",
                      "start":{"dateTime":"2026-11-03T08:00:00Z"},"end":{"dateTime":"2026-11-03T09:00:00Z"},
                      "originalStartTime":{"dateTime":"2026-11-02T08:00:00Z"}},
                     {"id":"gone_20261109T080000Z","recurringEventId":"gone","iCalUID":"gone@google.com","summary":"Two",
                      "start":{"dateTime":"2026-11-10T08:00:00Z"},"end":{"dateTime":"2026-11-10T09:00:00Z"},
                      "originalStartTime":{"dateTime":"2026-11-09T08:00:00Z"}}]"#,
            ),
            now(),
        );
        let uids: Vec<String> = changes
            .iter()
            .map(|change| {
                change
                    .ics
                    .as_deref()
                    .unwrap()
                    .lines()
                    .find(|line| line.starts_with("UID:"))
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(uids.len(), 2, "{changes:?}");
        assert_ne!(uids[0], uids[1], "a calendar holds a UID once: {uids:?}");
    }

    #[test]
    fn long_lines_are_folded_at_75_octets_without_cutting_a_character() {
        let ics = only(&format!(
            r#"[{{"id":"long","summary":"{}","start":{{"date":"2026-10-01"}}}}]"#,
            "Überraschungsfeier ".repeat(12)
        ));
        for line in ics.split("\r\n") {
            assert!(line.len() <= 75, "{} octets: {line}", line.len());
        }
        let unfolded = ics.replace("\r\n ", "");
        assert!(
            unfolded.contains("SUMMARY:Überraschungsfeier Überraschungsfeier"),
            "{unfolded}"
        );
        assert!(ics.ends_with("END:VCALENDAR\r\n"));
    }

    #[test]
    fn text_is_bounded_and_empty_text_is_left_out() {
        let ics = only(&format!(
            r#"[{{"id":"big","summary":"   ","description":"{}","location":"{}","start":{{"date":"2026-10-01"}}}}]"#,
            "d".repeat(40_000),
            "l".repeat(2_000)
        ));
        let unfolded = ics.replace("\r\n ", "");
        assert!(!unfolded.contains("SUMMARY"), "a blank title is no title");
        assert!(unfolded.contains(&format!("DESCRIPTION:{}\r\n", "d".repeat(MAX_DESCRIPTION))));
        assert!(unfolded.contains(&format!("LOCATION:{}\r\n", "l".repeat(MAX_LINE_TEXT))));
    }

    #[test]
    fn control_characters_never_reach_the_calendar_object() {
        let ics = only(
            r#"[{"id":"x","summary":"a\u0000b\u0007c\td","description":"x\r\ny\rz","start":{"date":"2026-10-01"},
                "recurrence":["RRULE:FREQ=DAILY\r\nBEGIN:VEVENT"]}]"#,
        );
        assert!(ics.contains("SUMMARY:abc\td\r\n"), "{ics}");
        assert!(ics.contains("DESCRIPTION:x\\ny\\nz\r\n"), "{ics}");
        assert!(
            ics.contains("RRULE:FREQ=DAILYBEGIN:VEVENT\r\n"),
            "the line break cannot start a new property: {ics}"
        );
        assert_eq!(
            ics.matches("BEGIN:VEVENT").count(),
            1 + 1,
            "only the text of the rule, not a second event"
        );
    }

    #[test]
    fn a_series_in_utc_is_written_in_utc() {
        let ics = only(
            r#"[{"id":"u","start":{"dateTime":"2026-10-26T10:00:00Z","timeZone":"UTC"},"end":{"dateTime":"2026-10-26T11:00:00Z","timeZone":"UTC"},
                "recurrence":["RRULE:FREQ=DAILY;COUNT=3"]}]"#,
        );
        assert!(ics.contains("DTSTART:20261026T100000Z\r\n"), "{ics}");
        let unknown = only(
            r#"[{"id":"u","start":{"dateTime":"2026-10-26T10:00:00+02:00","timeZone":"Mars/Olympus"},
                "recurrence":["RRULE:FREQ=DAILY;COUNT=3"]}]"#,
        );
        assert!(
            unknown.contains("DTSTART:20261026T080000Z\r\n"),
            "an unknown zone falls back to UTC: {unknown}"
        );
    }

    #[test]
    fn the_listing_is_ordered_by_id() {
        let changes = convert(
            events(r#"[{"id":"b","start":{"date":"2026-10-01"}},{"id":"a","start":{"date":"2026-10-02"}}]"#),
            now(),
        );
        assert_eq!(
            changes
                .iter()
                .map(|change| change.remote_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }
}
