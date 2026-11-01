//! `EventBuilder` for iCalendar events.
//!
//! Builds the text of a `VCALENDAR` with one `VEVENT`, `VTODO` or `VJOURNAL`, byte-for-byte deterministic: the
//! `DTSTAMP` is a fixed instant unless the test sets one, lines end in CRLF and are folded at 75 octets, text
//! values are escaped. The builder writes what it is told and never validates; tests that need invalid or odd
//! calendars add raw properties with [`EventBuilder::property`].

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use davhaven_domain::{Classification, ComponentKind, CuType, EventStatus, PartStat, Role, Transparency};

/// The product identifier of generated calendars.
const PRODID: &str = "-//Davhaven//fixtures//EN";

/// The longest content line in octets, without the line break (RFC 5545 section 3.1).
const FOLD_AT: usize = 75;

/// A point in time as an iCalendar property value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum When {
    /// An absolute time in UTC (`20270301T090000Z`).
    Utc(DateTime<Utc>),
    /// A local time in a named zone (`TZID=Europe/Berlin:20270301T100000`).
    Zoned {
        /// The IANA zone name written to the `TZID` parameter.
        tzid: String,
        /// The local date and time.
        local: NaiveDateTime,
    },
    /// A local time without zone (`20270301T100000`).
    Floating(NaiveDateTime),
    /// A whole day (`VALUE=DATE:20270301`).
    Date(NaiveDate),
}

impl When {
    /// A UTC time from calendar fields; the unrepresentable combination `None`.
    pub fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> Option<Self> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, 0)
            .single()
            .map(Self::Utc)
    }

    /// A zoned local time from calendar fields; the unrepresentable combination `None`.
    pub fn zoned(tzid: &str, year: i32, month: u32, day: u32, hour: u32, minute: u32) -> Option<Self> {
        let local = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, 0)?;
        Some(Self::Zoned {
            tzid: tzid.to_owned(),
            local,
        })
    }

    /// A whole day from calendar fields; the unrepresentable combination `None`.
    pub fn date(year: i32, month: u32, day: u32) -> Option<Self> {
        NaiveDate::from_ymd_opt(year, month, day).map(Self::Date)
    }

    /// The `;`-prefixed parameters and the value of a content line, as `(params, value)`.
    fn render(&self) -> (String, String) {
        const LOCAL: &str = "%Y%m%dT%H%M%S";
        match self {
            Self::Utc(time) => (String::new(), time.format("%Y%m%dT%H%M%SZ").to_string()),
            Self::Zoned { tzid, local } => (format!(";TZID={tzid}"), local.format(LOCAL).to_string()),
            Self::Floating(local) => (String::new(), local.format(LOCAL).to_string()),
            Self::Date(date) => (";VALUE=DATE".to_owned(), date.format("%Y%m%d").to_string()),
        }
    }
}

/// The organizer of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organizer {
    /// The calendar user address, for example `mailto:olivia@acme.example`.
    pub address: String,
    /// The common name, if any.
    pub name: Option<String>,
}

impl Organizer {
    /// An organizer with an address and no common name.
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_owned(),
            name: None,
        }
    }

    /// Sets the common name.
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }
}

/// An attendee of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attendee {
    /// The calendar user address, for example `mailto:mia@acme.example`.
    pub address: String,
    /// The common name, if any.
    pub name: Option<String>,
    /// The participation status.
    pub partstat: PartStat,
    /// The calendar user type.
    pub cutype: CuType,
    /// The participation role.
    pub role: Role,
    /// Whether a reply is requested (`RSVP=TRUE`).
    pub rsvp: bool,
}

impl Attendee {
    /// An individual required participant who has not answered and is asked to reply.
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_owned(),
            name: None,
            partstat: PartStat::NeedsAction,
            cutype: CuType::Individual,
            role: Role::ReqParticipant,
            rsvp: true,
        }
    }

    /// Sets the common name.
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    /// Sets the participation status.
    #[must_use]
    pub fn partstat(mut self, partstat: PartStat) -> Self {
        self.partstat = partstat;
        self
    }

    /// Sets the calendar user type.
    #[must_use]
    pub fn cutype(mut self, cutype: CuType) -> Self {
        self.cutype = cutype;
        self
    }
}

/// Builds the text of a calendar object resource.
///
/// ```
/// use davhaven_fixtures::{EventBuilder, When};
///
/// let ics = EventBuilder::event("standup@example.test")
///     .summary("Standup")
///     .starts(When::utc(2027, 3, 1, 9, 0).unwrap())
///     .ends(When::utc(2027, 3, 1, 9, 15).unwrap())
///     .build();
/// assert!(ics.starts_with("BEGIN:VCALENDAR\r\n"));
/// assert!(ics.contains("UID:standup@example.test\r\n"));
/// assert!(ics.contains("DTSTART:20270301T090000Z\r\n"));
/// ```
#[derive(Debug, Clone)]
pub struct EventBuilder {
    component: ComponentKind,
    uid: String,
    dtstamp: DateTime<Utc>,
    summary: Option<String>,
    description: Option<String>,
    location: Option<String>,
    start: Option<When>,
    end: Option<When>,
    rrule: Option<String>,
    organizer: Option<Organizer>,
    attendees: Vec<Attendee>,
    class: Option<Classification>,
    transp: Option<Transparency>,
    status: Option<EventStatus>,
    sequence: Option<u32>,
    properties: Vec<(String, String)>,
}

impl EventBuilder {
    fn new(component: ComponentKind, uid: &str) -> Self {
        Self {
            component,
            uid: uid.to_owned(),
            dtstamp: DateTime::UNIX_EPOCH,
            summary: None,
            description: None,
            location: None,
            start: None,
            end: None,
            rrule: None,
            organizer: None,
            attendees: Vec::new(),
            class: None,
            transp: None,
            status: None,
            sequence: None,
            properties: Vec::new(),
        }
    }

    /// A `VEVENT` with the given `UID`. The `DTSTAMP` is 2027-01-01T00:00:00Z unless [`Self::dtstamp`] sets one.
    pub fn event(uid: &str) -> Self {
        let mut builder = Self::new(ComponentKind::Event, uid);
        builder.dtstamp = Utc
            .with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
            .single()
            .unwrap_or(DateTime::UNIX_EPOCH);
        builder
    }

    /// A `VTODO` with the given `UID`.
    pub fn todo(uid: &str) -> Self {
        let mut builder = Self::event(uid);
        builder.component = ComponentKind::Todo;
        builder
    }

    /// A `VJOURNAL` with the given `UID`.
    pub fn journal(uid: &str) -> Self {
        let mut builder = Self::event(uid);
        builder.component = ComponentKind::Journal;
        builder
    }

    /// Sets the `DTSTAMP`.
    #[must_use]
    pub fn dtstamp(mut self, stamp: DateTime<Utc>) -> Self {
        self.dtstamp = stamp;
        self
    }

    /// Sets the `SUMMARY`.
    #[must_use]
    pub fn summary(mut self, summary: &str) -> Self {
        self.summary = Some(summary.to_owned());
        self
    }

    /// Sets the `DESCRIPTION`.
    #[must_use]
    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_owned());
        self
    }

    /// Sets the `LOCATION`.
    #[must_use]
    pub fn location(mut self, location: &str) -> Self {
        self.location = Some(location.to_owned());
        self
    }

    /// Sets the `DTSTART`; `None` leaves it out, so a failed [`When`] constructor does not need unwrapping.
    #[must_use]
    pub fn starts(mut self, start: impl Into<Option<When>>) -> Self {
        self.start = start.into();
        self
    }

    /// Sets the `DTEND` (`DUE` for a to-do); `None` leaves it out.
    #[must_use]
    pub fn ends(mut self, end: impl Into<Option<When>>) -> Self {
        self.end = end.into();
        self
    }

    /// Sets the `RRULE`, for example `FREQ=WEEKLY;COUNT=4`.
    #[must_use]
    pub fn rrule(mut self, rule: &str) -> Self {
        self.rrule = Some(rule.to_owned());
        self
    }

    /// Sets the `ORGANIZER`.
    #[must_use]
    pub fn organizer(mut self, organizer: Organizer) -> Self {
        self.organizer = Some(organizer);
        self
    }

    /// Adds an `ATTENDEE`.
    #[must_use]
    pub fn attendee(mut self, attendee: Attendee) -> Self {
        self.attendees.push(attendee);
        self
    }

    /// Sets the `CLASS`.
    #[must_use]
    pub fn class(mut self, class: Classification) -> Self {
        self.class = Some(class);
        self
    }

    /// Sets the `TRANSP`.
    #[must_use]
    pub fn transp(mut self, transp: Transparency) -> Self {
        self.transp = Some(transp);
        self
    }

    /// Sets the `STATUS`.
    #[must_use]
    pub fn status(mut self, status: EventStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets the `SEQUENCE`.
    #[must_use]
    pub fn sequence(mut self, sequence: u32) -> Self {
        self.sequence = Some(sequence);
        self
    }

    /// Adds a raw content line (`name` with optional `;params`, value) after the known properties. Nothing is
    /// escaped or validated; use it for `X-` properties, odd parameters and deliberately broken input.
    #[must_use]
    pub fn property(mut self, name: &str, value: &str) -> Self {
        self.properties.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The `UID` of the object.
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// The text of the calendar: CRLF line ends, lines folded at 75 octets, a trailing CRLF.
    pub fn build(&self) -> String {
        let name = self.component.as_ical();
        let mut lines: Vec<String> = vec![
            "BEGIN:VCALENDAR".to_owned(),
            "VERSION:2.0".to_owned(),
            format!("PRODID:{PRODID}"),
            format!("BEGIN:{name}"),
            format!("UID:{}", self.uid),
            format!("DTSTAMP:{}", self.dtstamp.format("%Y%m%dT%H%M%SZ")),
        ];
        if let Some(start) = &self.start {
            let (params, value) = start.render();
            lines.push(format!("DTSTART{params}:{value}"));
        }
        if let Some(end) = &self.end {
            let (params, value) = end.render();
            let property = if self.component == ComponentKind::Todo {
                "DUE"
            } else {
                "DTEND"
            };
            lines.push(format!("{property}{params}:{value}"));
        }
        if let Some(rule) = &self.rrule {
            lines.push(format!("RRULE:{rule}"));
        }
        for (property, value) in [
            ("SUMMARY", &self.summary),
            ("DESCRIPTION", &self.description),
            ("LOCATION", &self.location),
        ] {
            if let Some(value) = value {
                lines.push(format!("{property}:{}", escape_text(value)));
            }
        }
        if let Some(class) = self.class {
            lines.push(format!("CLASS:{class}"));
        }
        if let Some(transp) = self.transp {
            lines.push(format!("TRANSP:{transp}"));
        }
        if let Some(status) = self.status {
            lines.push(format!("STATUS:{status}"));
        }
        if let Some(sequence) = self.sequence {
            lines.push(format!("SEQUENCE:{sequence}"));
        }
        if let Some(organizer) = &self.organizer {
            let common_name = organizer
                .name
                .as_ref()
                .map_or_else(String::new, |name| format!(";CN={}", quote_param(name)));
            lines.push(format!("ORGANIZER{common_name}:{}", organizer.address));
        }
        for attendee in &self.attendees {
            let common_name = attendee
                .name
                .as_ref()
                .map_or_else(String::new, |name| format!(";CN={}", quote_param(name)));
            let rsvp = if attendee.rsvp { "TRUE" } else { "FALSE" };
            lines.push(format!(
                "ATTENDEE{common_name};CUTYPE={};ROLE={};PARTSTAT={};RSVP={rsvp}:{}",
                attendee.cutype, attendee.role, attendee.partstat, attendee.address
            ));
        }
        for (property, value) in &self.properties {
            lines.push(format!("{property}:{value}"));
        }
        lines.push(format!("END:{name}"));
        lines.push("END:VCALENDAR".to_owned());

        let mut out = String::new();
        for line in lines {
            fold_into(&mut out, &line);
        }
        out
    }
}

/// Escapes a TEXT value (RFC 5545 section 3.3.11).
fn escape_text(value: &str) -> String {
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

/// Quotes a parameter value when it contains characters that need it (RFC 5545 section 3.2).
fn quote_param(value: &str) -> String {
    let cleaned: String = value.chars().filter(|c| !matches!(c, '"' | '\r' | '\n')).collect();
    if cleaned.contains([';', ':', ',']) {
        format!("\"{cleaned}\"")
    } else {
        cleaned
    }
}

/// Appends `line` folded at [`FOLD_AT`] octets (never inside a UTF-8 sequence) with a CRLF at the end.
fn fold_into(out: &mut String, line: &str) {
    let mut width = 0;
    let mut first = true;
    for c in line.chars() {
        let size = c.len_utf8();
        // Continuation lines start with one space, which counts towards the limit.
        let limit = if first { FOLD_AT } else { FOLD_AT - 1 };
        if width + size > limit {
            out.push_str("\r\n ");
            width = 0;
            first = false;
        }
        out.push(c);
        width += size;
    }
    out.push_str("\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_event_is_deterministic() {
        let ics = EventBuilder::event("a@example.test")
            .summary("Planning")
            .starts(When::utc(2027, 3, 1, 9, 0))
            .ends(When::utc(2027, 3, 1, 10, 0))
            .build();
        assert_eq!(
            ics,
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Davhaven//fixtures//EN\r\nBEGIN:VEVENT\r\n\
             UID:a@example.test\r\nDTSTAMP:20270101T000000Z\r\nDTSTART:20270301T090000Z\r\n\
             DTEND:20270301T100000Z\r\nSUMMARY:Planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        );
    }

    #[test]
    fn times_render_with_their_parameters() {
        let ics = EventBuilder::event("t")
            .starts(When::zoned("Europe/Berlin", 2027, 3, 1, 10, 0))
            .ends(When::date(2027, 3, 2))
            .build();
        assert!(ics.contains("DTSTART;TZID=Europe/Berlin:20270301T100000\r\n"), "{ics}");
        assert!(ics.contains("DTEND;VALUE=DATE:20270302\r\n"), "{ics}");
        let floating = EventBuilder::event("f")
            .starts(Some(When::Floating(
                NaiveDate::from_ymd_opt(2027, 3, 1)
                    .unwrap()
                    .and_hms_opt(8, 30, 5)
                    .unwrap(),
            )))
            .build();
        assert!(floating.contains("DTSTART:20270301T083005\r\n"), "{floating}");
        assert!(When::utc(2027, 13, 1, 0, 0).is_none() && When::date(2027, 2, 30).is_none());
    }

    #[test]
    fn todos_and_journals_use_their_component_and_due() {
        let todo = EventBuilder::todo("t").ends(When::date(2027, 3, 2)).build();
        assert!(todo.contains("BEGIN:VTODO\r\n") && todo.contains("DUE;VALUE=DATE:20270302\r\n"));
        assert!(!todo.contains("DTEND"));
        let journal = EventBuilder::journal("j").build();
        assert!(journal.contains("BEGIN:VJOURNAL\r\n") && journal.contains("END:VJOURNAL\r\n"));
    }

    #[test]
    fn people_properties_and_raw_lines_are_written() {
        let ics = EventBuilder::event("p")
            .organizer(Organizer::new("mailto:olivia@acme.example").named("Olivia"))
            .attendee(
                Attendee::new("mailto:mia@acme.example")
                    .named("Mia, M.")
                    .partstat(PartStat::Accepted),
            )
            .class(Classification::Private)
            .transp(Transparency::Transparent)
            .status(EventStatus::Confirmed)
            .sequence(2)
            .rrule("FREQ=WEEKLY;COUNT=4")
            .property("X-TEST", "1")
            .build()
            .replace("\r\n ", "");
        assert!(
            ics.contains("ORGANIZER;CN=Olivia:mailto:olivia@acme.example\r\n"),
            "{ics}"
        );
        assert!(
            ics.contains(
                "ATTENDEE;CN=\"Mia, M.\";CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE:\
                 mailto:mia@acme.example\r\n"
            ),
            "{ics}"
        );
        for expected in [
            "CLASS:PRIVATE",
            "TRANSP:TRANSPARENT",
            "STATUS:CONFIRMED",
            "SEQUENCE:2",
            "RRULE:FREQ=WEEKLY;COUNT=4",
            "X-TEST:1",
        ] {
            assert!(ics.contains(&format!("{expected}\r\n")), "{expected} in {ics}");
        }
    }

    #[test]
    fn text_is_escaped_and_long_lines_fold_on_character_boundaries() {
        let ics = EventBuilder::event("e").summary("a;b,c\\d\ne").build();
        assert!(ics.contains("SUMMARY:a\\;b\\,c\\\\d\\ne\r\n"), "{ics}");

        let long = "ä".repeat(100);
        let folded = EventBuilder::event("e").description(&long).build();
        for line in folded.split("\r\n") {
            assert!(line.len() <= FOLD_AT, "line of {} octets: {line}", line.len());
        }
        let unfolded = folded.replace("\r\n ", "");
        assert!(unfolded.contains(&format!("DESCRIPTION:{long}\r\n")));

        let crlf = EventBuilder::event("e").summary("first\r\nsecond").build();
        assert!(
            crlf.contains("SUMMARY:first\\nsecond\r\n"),
            "a CRLF in a text value is one escaped line break, never a bare CR: {crlf}"
        );
    }

    #[test]
    fn the_dtstamp_can_be_set() {
        let stamp = Utc.with_ymd_and_hms(2030, 5, 6, 7, 8, 9).unwrap();
        assert!(
            EventBuilder::event("e")
                .dtstamp(stamp)
                .build()
                .contains("DTSTAMP:20300506T070809Z\r\n")
        );
        assert_eq!(EventBuilder::event("uid-1").uid(), "uid-1");
    }
}
