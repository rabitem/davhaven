//! `EventData`: the canonical JSON event model shared by the API, MCP and iCalendar merge.
//!
//! JSON event writes (management API, MCP) are merged into the stored component by `davhaven-ical` as a JSON Merge
//! Patch (RFC 7396): a field with a value replaces the stored value, a field that is absent leaves it alone, and a
//! field that is explicitly `null` removes it. Everything the model does not know (unknown properties, X-
//! properties, alarms the caller did not mention) is kept. The fields that cannot be removed (`uid` and `start`) refuse
//! `null`; for the instance selector `recurrence_id` and the server-managed `sequence`, `null` is the same as
//! leaving them out. The rule is that of a JSON Merge Patch for the members of the event, and no more: the value of
//! a member that is an object (`recurrence`, `organizer`, `start`, `end`) or a list replaces the stored one as a
//! whole, it is not merged member by member (attendees are matched by address). `wire::EventView` adds ids, ETags
//! and links around the same fields.
//!
//! The three states of a field are held by the fields of [`EventData`] themselves: `Some(value)` is a value,
//! `None` is "not named", and the set [`EventData::removed`] holds the fields that were named with `null`. What is
//! read from a stored event never has a removal; what is serialized names it as `null`, so a client that builds
//! an `EventData` in Rust and sends it says the same as one that writes the JSON.
//!
//! The model describes one component: the master event, or one override selected by `recurrence_id`.

use core::fmt;
use std::collections::BTreeSet;

use chrono::{DateTime, LocalResult, NaiveDate, NaiveDateTime, TimeZone, Utc};
use schemars::JsonSchema;
use serde::de::Error as _;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::keys::{CalendarUserAddress, TimeZoneName, Uid};
use crate::limits::IcalLimits;
use crate::vocab::{Classification, CuType, EventStatus, PartStat, Role, ScheduleAgent, Transparency};

const LOCAL_FORMAT: &str = "%Y-%m-%dT%H:%M:%S";
const UTC_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

/// Error for a date or time that cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid date or time: {0}")]
pub struct EventTimeError(&'static str);

impl EventTimeError {
    /// The rule that was violated.
    pub const fn reason(&self) -> &'static str {
        self.0
    }
}

/// The JSON form of an [`EventTime`]: either `{"date": "2027-03-01"}` for all-day values or
/// `{"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"}` for zoned values. A `date_time` that
/// ends in `Z` (or carries an offset) is UTC and takes no `time_zone`; one without a `time_zone` is floating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "EventTime")]
pub struct EventTimeRepr {
    /// An all-day date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<NaiveDate>,
    /// A date and time of day, local or UTC (see the type documentation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_time: Option<String>,
    /// The IANA time zone of a local `date_time`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<TimeZoneName>,
}

/// A point in an event: an all-day date, a floating local time, a local time in a zone, or a UTC instant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "EventTimeRepr", into = "EventTimeRepr")]
#[schemars(with = "EventTimeRepr")]
pub enum EventTime {
    /// A calendar date (`VALUE=DATE`): all-day events.
    Date(NaiveDate),
    /// A local time without a zone: it means the same wall-clock time wherever the viewer is.
    Floating(NaiveDateTime),
    /// A local time in an IANA zone.
    Zoned {
        /// The wall-clock time.
        local: NaiveDateTime,
        /// The zone the wall-clock time is in.
        zone: TimeZoneName,
    },
    /// An absolute instant in UTC.
    Utc(DateTime<Utc>),
}

impl From<EventTime> for EventTimeRepr {
    fn from(time: EventTime) -> Self {
        match time {
            EventTime::Date(date) => Self {
                date: Some(date),
                date_time: None,
                time_zone: None,
            },
            EventTime::Floating(local) => Self {
                date: None,
                date_time: Some(local.format(LOCAL_FORMAT).to_string()),
                time_zone: None,
            },
            EventTime::Zoned { local, zone } => Self {
                date: None,
                date_time: Some(local.format(LOCAL_FORMAT).to_string()),
                time_zone: Some(zone),
            },
            EventTime::Utc(instant) => Self {
                date: None,
                date_time: Some(instant.format(UTC_FORMAT).to_string()),
                time_zone: None,
            },
        }
    }
}

impl TryFrom<EventTimeRepr> for EventTime {
    type Error = EventTimeError;

    fn try_from(repr: EventTimeRepr) -> Result<Self, Self::Error> {
        match (repr.date, repr.date_time, repr.time_zone) {
            (Some(date), None, None) => Ok(Self::Date(date)),
            (None, Some(text), zone) => {
                if let Ok(instant) = DateTime::parse_from_rfc3339(&text) {
                    if zone.is_some() {
                        return Err(EventTimeError("time_zone cannot be combined with a UTC date_time"));
                    }
                    return Ok(Self::Utc(instant.with_timezone(&Utc)));
                }
                let local = NaiveDateTime::parse_from_str(&text, LOCAL_FORMAT)
                    .map_err(|_| EventTimeError("date_time must look like 2027-03-01T10:00:00 or end in Z"))?;
                Ok(zone.map_or(Self::Floating(local), |zone| Self::Zoned { local, zone }))
            }
            (Some(_), _, _) => Err(EventTimeError("date cannot be combined with date_time or time_zone")),
            (None, None, _) => Err(EventTimeError("either date or date_time is required")),
        }
    }
}

impl EventTime {
    /// Whether this is an all-day date.
    pub const fn is_date(&self) -> bool {
        matches!(self, Self::Date(_))
    }

    /// The instant this time denotes. Floating times and dates (as midnight) are interpreted in
    /// `floating_zone`; a wall-clock time that does not exist (spring-forward gap) yields `None`, an ambiguous
    /// one (fall-back overlap) the earlier instant.
    pub fn to_utc(&self, floating_zone: TimeZoneName) -> Option<DateTime<Utc>> {
        let resolve = |local: &NaiveDateTime, zone: TimeZoneName| match zone.tz().from_local_datetime(local) {
            LocalResult::Single(instant) => Some(instant.with_timezone(&Utc)),
            LocalResult::Ambiguous(earlier, _) => Some(earlier.with_timezone(&Utc)),
            LocalResult::None => None,
        };
        match self {
            Self::Date(date) => resolve(&date.and_hms_opt(0, 0, 0)?, floating_zone),
            Self::Floating(local) => resolve(local, floating_zone),
            Self::Zoned { local, zone } => resolve(local, *zone),
            Self::Utc(instant) => Some(*instant),
        }
    }
}

fn parse_duration(input: &str) -> Result<String, &'static str> {
    /// Consumes `\d+unit` at the start of `text` if present.
    fn consume(text: &str, unit: char) -> Result<&str, &'static str> {
        let digits = text.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Ok(text);
        }
        if digits > 9 {
            return Err("numbers must have at most 9 digits");
        }
        match text.get(digits..) {
            Some(rest) if rest.starts_with(unit) => Ok(rest.get(unit.len_utf8()..).unwrap_or_default()),
            _ => Ok(text),
        }
    }

    let upper = input.trim().to_ascii_uppercase();
    let unsigned = upper.strip_prefix(['+', '-']).unwrap_or(&upper);
    let Some(rest) = unsigned.strip_prefix('P') else {
        return Err("must start with P (for example PT30M)");
    };
    let shape_error = "must look like P1W, P2D, PT1H30M or P1DT2H";
    if rest.is_empty() {
        return Err(shape_error);
    }
    if let Some(weeks) = rest.strip_suffix('W') {
        let ok = !weeks.is_empty() && weeks.len() <= 9 && weeks.bytes().all(|b| b.is_ascii_digit());
        return if ok { Ok(upper) } else { Err(shape_error) };
    }
    let (date_part, time_part) = match rest.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (rest, None),
    };
    if !consume(date_part, 'D')?.is_empty() {
        return Err(shape_error);
    }
    if let Some(time) = time_part {
        let after = consume(consume(consume(time, 'H')?, 'M')?, 'S')?;
        if time.is_empty() || !after.is_empty() {
            return Err(shape_error);
        }
    }
    Ok(upper)
}

string_key!(
    /// An iCalendar duration (`DURATION`, RFC 5545 section 3.3.6) such as `PT30M`, `P1D`, `P1W` or `-PT15M`,
    /// normalized to upper case.
    EventDuration,
    "duration",
    parse_duration
);

impl EventDuration {
    /// The nominal length in seconds (a day counts 86 400 seconds, a week 604 800), negative for a leading `-`.
    pub fn seconds(&self) -> i64 {
        let text = self.as_str();
        let negative = text.starts_with('-');
        let body = text.trim_start_matches(['+', '-']).trim_start_matches('P');
        let mut total: i64 = 0;
        let mut number: i64 = 0;
        for c in body.chars() {
            if let Some(digit) = c.to_digit(10) {
                number = number.saturating_mul(10).saturating_add(i64::from(digit));
                continue;
            }
            let unit = match c {
                'W' => 604_800,
                'D' => 86_400,
                'H' => 3_600,
                'M' => 60,
                'S' => 1,
                _ => 0,
            };
            total = total.saturating_add(number.saturating_mul(unit));
            number = 0;
        }
        if negative { -total } else { total }
    }
}

fn parse_recurrence_rule(input: &str) -> Result<String, &'static str> {
    let upper = input.trim().to_ascii_uppercase();
    if upper.is_empty() || upper.len() > 1024 {
        return Err("must be 1 to 1024 characters");
    }
    if upper.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    let body = upper.strip_prefix("RRULE:").unwrap_or(&upper);
    if !body.split(';').any(|part| part.starts_with("FREQ=")) {
        return Err("must contain FREQ=");
    }
    if !body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b';' | b',' | b'-' | b'+' | b':'))
    {
        return Err("contains characters that are not allowed");
    }
    Ok(body.to_owned())
}

string_key!(
    /// A recurrence rule value (RFC 5545 `RECUR`) such as `FREQ=WEEKLY;BYDAY=MO,WE`, normalized to upper case
    /// without a leading `RRULE:`. The syntax and the limits (no `SECONDLY`/`MINUTELY`) are checked by
    /// `davhaven-ical`; this type only guarantees a safe, single-line text with a `FREQ`.
    RecurrenceRule,
    "recurrence rule",
    parse_recurrence_rule
);

/// The recurrence definition of an event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Recurrence {
    /// The recurrence rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrule: Option<RecurrenceRule>,
    /// Additional instances.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rdates: Vec<EventTime>,
    /// Excluded instances.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exdates: Vec<EventTime>,
}

/// The organizer of an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EventOrganizer {
    /// The organizer's calendar user address.
    pub address: CalendarUserAddress,
    /// The display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// Set when someone acts on behalf of the organizer (`SENT-BY`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_by: Option<CalendarUserAddress>,
}

/// An attendee of an event. Absent parameters mean "keep the stored value" on merge and the iCalendar default
/// on create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EventAttendee {
    /// The attendee's calendar user address.
    pub address: CalendarUserAddress,
    /// The display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// The participation status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partstat: Option<PartStat>,
    /// The participation role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// The calendar user type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutype: Option<CuType>,
    /// Whether a reply is requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsvp: Option<bool>,
    /// Who sends scheduling messages to the attendee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_agent: Option<ScheduleAgent>,
}

text_enum!(
    /// What an alarm does.
    AlarmAction [] {
        /// Show a message.
        Display => "display",
        /// Play a sound.
        Audio => "audio",
        /// Send an e-mail.
        Email => "email",
    }
);

text_enum!(
    /// The event bound a relative alarm trigger is measured from.
    AlarmRelated [Default] {
        /// The start of the event.
        #[default]
        Start => "start",
        /// The end of the event.
        End => "end",
    }
);

/// When an alarm fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlarmTrigger {
    /// An offset from the start or end of the event; negative offsets fire before it.
    Relative {
        /// The offset, for example `-PT15M`.
        offset: EventDuration,
        /// The bound the offset is measured from.
        #[serde(default)]
        related: AlarmRelated,
    },
    /// An absolute instant.
    Absolute {
        /// The instant in UTC.
        at: DateTime<Utc>,
    },
}

/// An alarm of an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EventAlarm {
    /// What the alarm does.
    pub action: AlarmAction,
    /// When it fires.
    pub trigger: AlarmTrigger,
    /// The text shown by a display alarm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Error for an `EventData` that breaks a consistency rule or a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid event field `{field}`: {reason}")]
pub struct EventDataError {
    field: &'static str,
    reason: &'static str,
}

impl EventDataError {
    const fn new(field: &'static str, reason: &'static str) -> Self {
        Self { field, reason }
    }

    /// The name of the offending field.
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// The rule that was violated.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

text_enum!(
    /// A field of [`EventData`] that an explicit JSON `null` removes from the stored event (RFC 7396). The
    /// spelling is the name of the JSON member.
    ///
    /// `uid` and `start` are not here: they identify the event and cannot be removed, and `null` for one of them
    /// is refused where the JSON is read. `recurrence_id` and `sequence` are not here either: `null` for them is
    /// the same as leaving them out (the master component, a number the server manages).
    #[non_exhaustive]
    EventField [] {
        /// `summary`.
        Summary => "summary",
        /// `description`.
        Description => "description",
        /// `location`.
        Location => "location",
        /// `end` (`DTEND`, `DUE` for a to-do).
        End => "end",
        /// `duration`.
        Duration => "duration",
        /// `status`.
        Status => "status",
        /// `transparency`.
        Transparency => "transparency",
        /// `class`.
        Class => "class",
        /// `recurrence`: the rule and the recurrence dates and exclusions with it.
        Recurrence => "recurrence",
        /// `organizer`.
        Organizer => "organizer",
        /// `attendees`: every attendee.
        Attendees => "attendees",
        /// `categories`.
        Categories => "categories",
        /// `url`.
        Url => "url",
        /// `alarms`: every alarm.
        Alarms => "alarms",
    }
);

/// The members of the JSON form that refuse `null`: the identity of the event.
const NOT_NULLABLE: [&str; 2] = ["uid", "start"];

/// The text that follows the member in the error for a `null` that cannot be a removal.
const NOT_NULLABLE_REASON: &str = "cannot be null: the field cannot be removed";

/// The member that `error`, the text of a deserialization error of [`EventData`], refuses `null` for; `None` for
/// any other error. The edge uses it to point at the member (`not-nullable`) instead of the whole body.
pub fn null_refused_member(error: &str) -> Option<&'static str> {
    NOT_NULLABLE
        .into_iter()
        .find(|member| error.contains(&format!("`{member}` {NOT_NULLABLE_REASON}")))
}

/// The canonical event model. Every field is optional: on create the application supplies the missing required
/// ones (UID, start). A write is merged into the stored event like a JSON Merge Patch (RFC 7396) for the members of
/// the event: a field with a value replaces the stored one, a field that is absent keeps it, and a field that is
/// `null` removes it. The rule goes no deeper than the members: an object or a list that is sent (`recurrence`,
/// `organizer`, `start`, `end`, `alarms`, `categories`) replaces the stored one as a whole, and only attendees are
/// matched, by address.
// In Rust the three states are `Some(value)`, `None` and a member of `removed`; see the module documentation. The
// serde implementations are written by hand for that, and the attributes below describe the JSON form to `schemars`.
#[derive(Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
pub struct EventData {
    /// The iCalendar UID; derived from the external key or generated when absent on create. It cannot be `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Uid")]
    pub uid: Option<Uid>,
    /// Selects an override instance of a recurring event; absent addresses the master component. `null` is the
    /// same as absent: the instance selector is no field that a write could remove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence_id: Option<EventTime>,
    /// The title. `null` removes it, and so does an empty text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// The description. `null` removes it, and so does an empty text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The location. `null` removes it, and so does an empty text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The start. It cannot be `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "EventTime")]
    pub start: Option<EventTime>,
    /// The end; mutually exclusive with `duration`. `null` removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<EventTime>,
    /// The length; mutually exclusive with `end`. `null` removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<EventDuration>,
    /// The status. `null` removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<EventStatus>,
    /// Whether the event blocks time. `null` removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<Transparency>,
    /// The access classification. `null` removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<Classification>,
    /// The recurrence definition; `null` or an empty `Recurrence` removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<Recurrence>,
    /// The organizer. `null` removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organizer: Option<EventOrganizer>,
    /// The attendees; the list replaces the stored attendees, `null` or an empty list removes them all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attendees: Option<Vec<EventAttendee>>,
    /// The categories; `null` or an empty list removes them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<String>>,
    /// A link related to the event. `null` removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,
    /// The revision number; the server raises it on significant changes when the client does not. `null` is the
    /// same as absent: the number belongs to the server and is no field that a write could remove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<i32>,
    /// The alarms; the list replaces the stored alarms, `null` or an empty list removes them all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alarms: Option<Vec<EventAlarm>>,
    /// The fields the write names with `null`, which removes them from the stored event. A field must not be in
    /// both this set and its own member ([`validate`](Self::validate) refuses it; [`without`](Self::without) keeps
    /// the two apart). It is no member of the JSON form: the removal is the `null` of the field.
    #[schemars(skip)]
    pub removed: BTreeSet<EventField>,
}

impl EventData {
    /// Checks the consistency rules and limits that can be decided without the stored component: `end` and
    /// `duration` exclude each other, `end` has the kind of `start` (all-day or timed) and does not precede it,
    /// a field is not both given and removed, and text, list and recurrence sizes stay within `limits`.
    ///
    /// # Errors
    ///
    /// Returns an [`EventDataError`] naming the first offending field.
    pub fn validate(&self, limits: &IcalLimits) -> Result<(), EventDataError> {
        if let Some(field) = EventField::ALL
            .iter()
            .copied()
            .find(|field| self.removes(*field) && self.is_set(*field))
        {
            return Err(EventDataError::new(
                field.as_str(),
                "cannot be given and removed (null) at once",
            ));
        }
        if self.end.is_some() && self.duration.is_some() {
            return Err(EventDataError::new("duration", "cannot be combined with end"));
        }
        if let (Some(start), Some(end)) = (&self.start, &self.end) {
            if start.is_date() != end.is_date() {
                return Err(EventDataError::new(
                    "end",
                    "must be a date exactly when start is a date",
                ));
            }
            let zone = TimeZoneName::utc();
            if let (Some(first), Some(last)) = (start.to_utc(zone), end.to_utc(zone))
                && last < first
            {
                return Err(EventDataError::new("end", "must not be before start"));
            }
        }
        let max_text = usize::try_from(limits.max_value_length).unwrap_or(usize::MAX);
        let texts = [
            ("summary", &self.summary),
            ("description", &self.description),
            ("location", &self.location),
        ];
        for (field, value) in texts {
            if value.as_ref().is_some_and(|text| text.len() > max_text) {
                return Err(EventDataError::new(field, "is too long"));
            }
        }
        let max_attendees = usize::try_from(limits.max_attendees_per_instance).unwrap_or(usize::MAX);
        if self.attendees.as_ref().is_some_and(|list| list.len() > max_attendees) {
            return Err(EventDataError::new("attendees", "has too many entries"));
        }
        let max_alarms = usize::try_from(limits.max_alarms).unwrap_or(usize::MAX);
        if self.alarms.as_ref().is_some_and(|list| list.len() > max_alarms) {
            return Err(EventDataError::new("alarms", "has too many entries"));
        }
        let max_dates = usize::try_from(limits.max_recurrence_dates).unwrap_or(usize::MAX);
        if self
            .recurrence
            .as_ref()
            .is_some_and(|r| r.rdates.len().saturating_add(r.exdates.len()) > max_dates)
        {
            return Err(EventDataError::new("recurrence", "has too many dates"));
        }
        if self.sequence.is_some_and(|sequence| sequence < 0) {
            return Err(EventDataError::new("sequence", "must not be negative"));
        }
        if self
            .categories
            .as_ref()
            .is_some_and(|list| list.iter().any(|c| c.is_empty() || c.contains(',')))
        {
            return Err(EventDataError::new(
                "categories",
                "entries must be non-empty and must not contain commas",
            ));
        }
        Ok(())
    }

    /// Whether the event is an all-day event, when the start is known.
    pub fn is_all_day(&self) -> Option<bool> {
        self.start.as_ref().map(EventTime::is_date)
    }

    /// Whether the write names `field` with `null`, which removes it from the stored event.
    pub fn removes(&self, field: EventField) -> bool {
        self.removed.contains(&field)
    }

    /// These fields with `field` removed: the write names it with `null`, and its member has no value (a field is
    /// either given or removed, see [`validate`](Self::validate)).
    #[must_use]
    pub fn without(mut self, field: EventField) -> Self {
        self.removed.insert(field);
        self.clear(field);
        self
    }

    /// Drops the value of the member of `field`.
    fn clear(&mut self, field: EventField) {
        match field {
            EventField::Summary => self.summary = None,
            EventField::Description => self.description = None,
            EventField::Location => self.location = None,
            EventField::End => self.end = None,
            EventField::Duration => self.duration = None,
            EventField::Status => self.status = None,
            EventField::Transparency => self.transparency = None,
            EventField::Class => self.class = None,
            EventField::Recurrence => self.recurrence = None,
            EventField::Organizer => self.organizer = None,
            EventField::Attendees => self.attendees = None,
            EventField::Categories => self.categories = None,
            EventField::Url => self.url = None,
            EventField::Alarms => self.alarms = None,
        }
    }

    /// Whether the member of `field` has a value.
    fn is_set(&self, field: EventField) -> bool {
        match field {
            EventField::Summary => self.summary.is_some(),
            EventField::Description => self.description.is_some(),
            EventField::Location => self.location.is_some(),
            EventField::End => self.end.is_some(),
            EventField::Duration => self.duration.is_some(),
            EventField::Status => self.status.is_some(),
            EventField::Transparency => self.transparency.is_some(),
            EventField::Class => self.class.is_some(),
            EventField::Recurrence => self.recurrence.is_some(),
            EventField::Organizer => self.organizer.is_some(),
            EventField::Attendees => self.attendees.is_some(),
            EventField::Categories => self.categories.is_some(),
            EventField::Url => self.url.is_some(),
            EventField::Alarms => self.alarms.is_some(),
        }
    }
}

impl Serialize for EventData {
    /// Writes the members that have a value and, for a removal, a `null`; a member that is neither is left out.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Every field is named, so that a field added to the struct does not compile until it is written here.
        let Self {
            uid,
            recurrence_id,
            summary,
            description,
            location,
            start,
            end,
            duration,
            status,
            transparency,
            class,
            recurrence,
            organizer,
            attendees,
            categories,
            url,
            sequence,
            alarms,
            removed,
        } = self;
        let mut map = serializer.serialize_map(None)?;
        if let Some(uid) = uid {
            map.serialize_entry("uid", uid)?;
        }
        if let Some(recurrence_id) = recurrence_id {
            map.serialize_entry("recurrence_id", recurrence_id)?;
        }
        // A field that can be removed: its value, or `null` when the write removes it.
        macro_rules! removable {
            ($field:ident, $variant:ident) => {
                match $field {
                    Some(value) => map.serialize_entry(EventField::$variant.as_str(), value)?,
                    None if removed.contains(&EventField::$variant) => {
                        map.serialize_entry(EventField::$variant.as_str(), &None::<()>)?;
                    }
                    None => {}
                }
            };
        }
        removable!(summary, Summary);
        removable!(description, Description);
        removable!(location, Location);
        if let Some(start) = start {
            map.serialize_entry("start", start)?;
        }
        removable!(end, End);
        removable!(duration, Duration);
        removable!(status, Status);
        removable!(transparency, Transparency);
        removable!(class, Class);
        removable!(recurrence, Recurrence);
        removable!(organizer, Organizer);
        removable!(attendees, Attendees);
        removable!(categories, Categories);
        removable!(url, Url);
        if let Some(sequence) = sequence {
            map.serialize_entry("sequence", sequence)?;
        }
        removable!(alarms, Alarms);
        map.end()
    }
}

impl<'de> Deserialize<'de> for EventData {
    /// Reads the members; a `null` removes the field when it can be removed and is refused otherwise. Members that
    /// are not part of the model are ignored, so that views can extend it.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        EventDataRepr::deserialize(deserializer).map(Self::from)
    }
}

/// A member of the JSON form that can be absent, `null` or have a value.
#[derive(Debug, Default)]
enum Patch<T> {
    /// The member is not in the document.
    #[default]
    Absent,
    /// The member is `null`.
    Null,
    /// The member has a value.
    Value(T),
}

impl<T> Patch<T> {
    /// The value of the member; a `null` is recorded as the removal of `field`.
    fn into_value(self, field: EventField, removed: &mut BTreeSet<EventField>) -> Option<T> {
        match self {
            Self::Absent => None,
            Self::Null => {
                removed.insert(field);
                None
            }
            Self::Value(value) => Some(value),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Patch<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Option::<T>::deserialize(deserializer)?.map_or(Self::Null, Self::Value))
    }
}

/// Reads a member that cannot be `null` (`uid`, `start`): a value, or an error that names the member, which the
/// edge turns into a problem at the pointer of the member ([`null_refused_member`]).
macro_rules! never_null {
    ($function:ident, $name:literal) => {
        fn $function<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<Option<T>, D::Error> {
            Option::<T>::deserialize(deserializer)?
                .map(Some)
                .ok_or_else(|| D::Error::custom(format!("`{}` {NOT_NULLABLE_REASON}", $name)))
        }
    };
}

never_null!(uid_not_null, "uid");
never_null!(start_not_null, "start");

/// The members of the JSON form as they are read: the shape [`EventData`] is deserialized through.
#[derive(Deserialize)]
struct EventDataRepr {
    #[serde(default, deserialize_with = "uid_not_null")]
    uid: Option<Uid>,
    #[serde(default)]
    recurrence_id: Option<EventTime>,
    #[serde(default)]
    summary: Patch<String>,
    #[serde(default)]
    description: Patch<String>,
    #[serde(default)]
    location: Patch<String>,
    #[serde(default, deserialize_with = "start_not_null")]
    start: Option<EventTime>,
    #[serde(default)]
    end: Patch<EventTime>,
    #[serde(default)]
    duration: Patch<EventDuration>,
    #[serde(default)]
    status: Patch<EventStatus>,
    #[serde(default)]
    transparency: Patch<Transparency>,
    #[serde(default)]
    class: Patch<Classification>,
    #[serde(default)]
    recurrence: Patch<Recurrence>,
    #[serde(default)]
    organizer: Patch<EventOrganizer>,
    #[serde(default)]
    attendees: Patch<Vec<EventAttendee>>,
    #[serde(default)]
    categories: Patch<Vec<String>>,
    #[serde(default)]
    url: Patch<Url>,
    #[serde(default)]
    sequence: Option<i32>,
    #[serde(default)]
    alarms: Patch<Vec<EventAlarm>>,
}

impl From<EventDataRepr> for EventData {
    fn from(repr: EventDataRepr) -> Self {
        let mut removed = BTreeSet::new();
        let summary = repr.summary.into_value(EventField::Summary, &mut removed);
        let description = repr.description.into_value(EventField::Description, &mut removed);
        let location = repr.location.into_value(EventField::Location, &mut removed);
        let end = repr.end.into_value(EventField::End, &mut removed);
        let duration = repr.duration.into_value(EventField::Duration, &mut removed);
        let status = repr.status.into_value(EventField::Status, &mut removed);
        let transparency = repr.transparency.into_value(EventField::Transparency, &mut removed);
        let class = repr.class.into_value(EventField::Class, &mut removed);
        let recurrence = repr.recurrence.into_value(EventField::Recurrence, &mut removed);
        let organizer = repr.organizer.into_value(EventField::Organizer, &mut removed);
        let attendees = repr.attendees.into_value(EventField::Attendees, &mut removed);
        let categories = repr.categories.into_value(EventField::Categories, &mut removed);
        let url = repr.url.into_value(EventField::Url, &mut removed);
        let alarms = repr.alarms.into_value(EventField::Alarms, &mut removed);
        Self {
            uid: repr.uid,
            recurrence_id: repr.recurrence_id,
            summary,
            description,
            location,
            start: repr.start,
            end,
            duration,
            status,
            transparency,
            class,
            recurrence,
            organizer,
            attendees,
            categories,
            url,
            sequence: repr.sequence,
            alarms,
            removed,
        }
    }
}

impl fmt::Display for EventTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Date(date) => write!(f, "{date}"),
            Self::Floating(local) => write!(f, "{}", local.format(LOCAL_FORMAT)),
            Self::Zoned { local, zone } => write!(f, "{} {zone}", local.format(LOCAL_FORMAT)),
            Self::Utc(instant) => write!(f, "{}", instant.format(UTC_FORMAT)),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveTime;

    use super::*;

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn local(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
        date(y, m, d).and_time(NaiveTime::from_hms_opt(h, min, 0).unwrap())
    }

    fn zone(name: &str) -> TimeZoneName {
        TimeZoneName::parse(name).unwrap()
    }

    fn time_json(json: &str) -> Result<EventTime, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn the_four_time_kinds_round_trip_through_json() {
        let cases = [
            (EventTime::Date(date(2027, 3, 1)), r#"{"date":"2027-03-01"}"#),
            (
                EventTime::Floating(local(2027, 3, 1, 10, 0)),
                r#"{"date_time":"2027-03-01T10:00:00"}"#,
            ),
            (
                EventTime::Zoned {
                    local: local(2027, 3, 1, 10, 0),
                    zone: zone("Europe/Berlin"),
                },
                r#"{"date_time":"2027-03-01T10:00:00","time_zone":"Europe/Berlin"}"#,
            ),
            (
                EventTime::Utc(Utc.with_ymd_and_hms(2027, 3, 1, 9, 0, 0).unwrap()),
                r#"{"date_time":"2027-03-01T09:00:00Z"}"#,
            ),
        ];
        for (time, json) in cases {
            assert_eq!(serde_json::to_string(&time).unwrap(), json);
            assert_eq!(time_json(json).unwrap(), time);
        }
    }

    #[test]
    fn offsets_are_converted_to_utc() {
        let parsed = time_json(r#"{"date_time":"2027-03-01T11:00:00+02:00"}"#).unwrap();
        assert_eq!(
            parsed,
            EventTime::Utc(Utc.with_ymd_and_hms(2027, 3, 1, 9, 0, 0).unwrap())
        );
    }

    #[test]
    fn invalid_times_are_rejected_with_a_reason() {
        for bad in [
            "{}",
            r#"{"time_zone":"Europe/Berlin"}"#,
            r#"{"date":"2027-03-01","date_time":"2027-03-01T10:00:00"}"#,
            r#"{"date":"2027-03-01","time_zone":"Europe/Berlin"}"#,
            r#"{"date_time":"2027-03-01T10:00:00Z","time_zone":"Europe/Berlin"}"#,
            r#"{"date_time":"2027-03-01 10:00:00"}"#,
            r#"{"date_time":"2027-03-01"}"#,
            r#"{"date_time":"2027-13-01T10:00:00"}"#,
            r#"{"date_time":"tomorrow"}"#,
            r#"{"date":"2027-02-30"}"#,
            r#"{"date":"2027-03-01","extra":1}"#,
            r#"{"date_time":"2027-03-01T10:00:00","time_zone":"Mars/Base"}"#,
            r#""2027-03-01""#,
        ] {
            assert!(time_json(bad).is_err(), "{bad}");
        }
        let err = EventTime::try_from(EventTimeRepr {
            date: None,
            date_time: None,
            time_zone: None,
        })
        .unwrap_err();
        assert_eq!(err.reason(), "either date or date_time is required");
        assert!(err.to_string().starts_with("invalid date or time"));
    }

    #[test]
    fn times_resolve_to_utc_in_the_right_zone() {
        let berlin = zone("Europe/Berlin");
        let utc = TimeZoneName::utc();
        let summer = EventTime::Zoned {
            local: local(2027, 7, 1, 10, 0),
            zone: berlin,
        };
        assert_eq!(
            summer.to_utc(utc),
            Some(Utc.with_ymd_and_hms(2027, 7, 1, 8, 0, 0).unwrap())
        );
        let winter = EventTime::Zoned {
            local: local(2027, 1, 1, 10, 0),
            zone: berlin,
        };
        assert_eq!(
            winter.to_utc(utc),
            Some(Utc.with_ymd_and_hms(2027, 1, 1, 9, 0, 0).unwrap())
        );
        let floating = EventTime::Floating(local(2027, 7, 1, 10, 0));
        assert_eq!(
            floating.to_utc(berlin),
            Some(Utc.with_ymd_and_hms(2027, 7, 1, 8, 0, 0).unwrap())
        );
        assert_eq!(
            floating.to_utc(utc),
            Some(Utc.with_ymd_and_hms(2027, 7, 1, 10, 0, 0).unwrap())
        );
        let day = EventTime::Date(date(2027, 7, 1));
        assert_eq!(
            day.to_utc(berlin),
            Some(Utc.with_ymd_and_hms(2027, 6, 30, 22, 0, 0).unwrap())
        );
        let instant = EventTime::Utc(Utc.with_ymd_and_hms(2027, 7, 1, 5, 0, 0).unwrap());
        assert_eq!(
            instant.to_utc(berlin),
            Some(Utc.with_ymd_and_hms(2027, 7, 1, 5, 0, 0).unwrap())
        );
        // 2027-03-28 02:30 does not exist in Berlin (clocks jump from 02:00 to 03:00).
        let gap = EventTime::Zoned {
            local: local(2027, 3, 28, 2, 30),
            zone: berlin,
        };
        assert_eq!(gap.to_utc(utc), None);
        // 2027-10-31 02:30 happens twice; the earlier instant (CEST) wins.
        let overlap = EventTime::Zoned {
            local: local(2027, 10, 31, 2, 30),
            zone: berlin,
        };
        assert_eq!(
            overlap.to_utc(utc),
            Some(Utc.with_ymd_and_hms(2027, 10, 31, 0, 30, 0).unwrap())
        );
        assert!(day.is_date());
        assert!(!floating.is_date());
    }

    #[test]
    fn durations_follow_rfc_5545() {
        for (text, seconds) in [
            ("PT30M", 1_800),
            ("pt1h30m", 5_400),
            ("P1D", 86_400),
            ("P1W", 604_800),
            ("P2W", 1_209_600),
            ("P1DT2H", 93_600),
            ("PT0S", 0),
            ("-PT15M", -900),
            ("+PT15M", 900),
            ("PT1H0M30S", 3_630),
            ("P15DT5H0M20S", 15 * 86_400 + 5 * 3_600 + 20),
        ] {
            let duration = EventDuration::parse(text).unwrap();
            assert_eq!(duration.seconds(), seconds, "{text}");
            assert_eq!(duration.as_str(), text.to_ascii_uppercase());
        }
        for bad in [
            "",
            "P",
            "PT",
            "T30M",
            "30M",
            "P1",
            "PT30",
            "P1H",
            "PT1D",
            "P1W2D",
            "P1.5D",
            "PT1M1H",
            "P-1D",
            "P1DT",
            "PTS",
            "PT1H30",
            "P1WT1H",
            "PT9999999999S",
            "P1D2H",
            "P 1D",
        ] {
            assert!(EventDuration::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn recurrence_rules_are_normalized_single_line_values() {
        assert_eq!(
            RecurrenceRule::parse("freq=weekly;byday=mo,we").unwrap().as_str(),
            "FREQ=WEEKLY;BYDAY=MO,WE"
        );
        assert_eq!(
            RecurrenceRule::parse("RRULE:FREQ=DAILY;COUNT=3").unwrap().as_str(),
            "FREQ=DAILY;COUNT=3"
        );
        assert_eq!(
            RecurrenceRule::parse("FREQ=YEARLY;UNTIL=20301231T000000Z")
                .unwrap()
                .as_str(),
            "FREQ=YEARLY;UNTIL=20301231T000000Z"
        );
        for bad in [
            "",
            "COUNT=3",
            "FREQ=DAILY\r\nX-EVIL:1",
            "FREQ=DAILY;BYDAY=MO MO",
            &format!("FREQ={}", "A".repeat(1025)),
        ] {
            assert!(RecurrenceRule::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sparse_json_leaves_everything_else_absent() {
        let data: EventData = serde_json::from_str(r#"{"summary":"Standup","start":{"date":"2027-03-01"}}"#).unwrap();
        assert_eq!(data.summary.as_deref(), Some("Standup"));
        assert_eq!(data.start, Some(EventTime::Date(date(2027, 3, 1))));
        assert_eq!(data.end, None);
        assert_eq!(data.attendees, None);
        assert_eq!(data.alarms, None);
        assert_eq!(
            serde_json::to_string(&data).unwrap(),
            r#"{"summary":"Standup","start":{"date":"2027-03-01"}}"#
        );
        assert_eq!(serde_json::to_string(&EventData::default()).unwrap(), "{}");
        assert_eq!(data.is_all_day(), Some(true));
        assert_eq!(EventData::default().is_all_day(), None);
    }

    #[test]
    fn unknown_members_are_ignored_so_views_can_extend_the_model() {
        let data: EventData = serde_json::from_str(r#"{"summary":"x","etag":"\"abc\"","links":[]}"#).unwrap();
        assert_eq!(data.summary.as_deref(), Some("x"));
    }

    fn data_json(json: &str) -> Result<EventData, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn null_removes_every_field_that_can_be_removed() {
        for field in EventField::ALL.iter().copied() {
            let json = format!(r#"{{"{}":null}}"#, field.as_str());
            let data = data_json(&json).unwrap();
            assert_eq!(data.removed, BTreeSet::from([field]), "{json}");
            assert!(data.removes(field));
            assert!(!data.is_set(field), "a removal is no value: {json}");
            assert_eq!(
                serde_json::to_string(&data).unwrap(),
                json,
                "the removal is written as null"
            );
            data.validate(&IcalLimits::default()).unwrap();
        }
        let both = data_json(r#"{"location":null,"description":null,"summary":"Kept"}"#).unwrap();
        assert_eq!(
            both.removed,
            BTreeSet::from([EventField::Location, EventField::Description])
        );
        assert_eq!(both.summary.as_deref(), Some("Kept"));
    }

    #[test]
    fn absent_and_null_and_a_value_are_three_different_things() {
        let absent = data_json(r#"{"location":"Raum 1"}"#).unwrap();
        assert_eq!(absent.location.as_deref(), Some("Raum 1"));
        assert!(absent.removed.is_empty());
        let nothing = data_json("{}").unwrap();
        assert_eq!(nothing, EventData::default());
        let null = data_json(r#"{"location":null}"#).unwrap();
        assert_eq!(null.location, None);
        assert!(null.removes(EventField::Location));
        assert_ne!(null, nothing, "null is not the same as absent");
        // An empty value is a value, not a removal: the merge treats it like a removal for text, that is its rule.
        let empty = data_json(r#"{"location":"","attendees":[],"categories":[]}"#).unwrap();
        assert!(empty.removed.is_empty());
        assert_eq!(empty.attendees, Some(Vec::new()));
        assert_eq!(
            serde_json::to_string(&null.clone().without(EventField::End)).unwrap(),
            r#"{"location":null,"end":null}"#
        );
    }

    #[test]
    fn the_fields_that_cannot_be_removed_refuse_null() {
        for name in ["uid", "start"] {
            let error = data_json(&format!(r#"{{"{name}":null}}"#)).unwrap_err();
            let message = error.to_string();
            assert!(message.contains(&format!("`{name}` cannot be null")), "{message}");
            assert_eq!(
                null_refused_member(&message),
                Some(name),
                "the edge finds the member in the message"
            );
        }
        assert_eq!(null_refused_member("invalid type: string \"x\", expected a map"), None);
        // A value is fine, and so is the absence of the member.
        let data = data_json(r#"{"uid":"u","sequence":3,"start":{"date":"2027-03-01"}}"#).unwrap();
        assert_eq!(data.sequence, Some(3));
        assert!(data.removed.is_empty());
    }

    #[test]
    fn null_for_the_instance_selector_and_the_sequence_is_the_same_as_leaving_them_out() {
        // Neither is a field that a write could remove: the selector says which component is meant (none: the
        // master), and the number is the server's. A client that serializes every member of its model as null
        // sends exactly this, and it worked before null removed fields.
        let data = data_json(r#"{"recurrence_id":null,"sequence":null,"summary":"x"}"#).unwrap();
        assert_eq!(data.recurrence_id, None);
        assert_eq!(data.sequence, None);
        assert!(data.removed.is_empty(), "no removal is recorded for them");
        assert_eq!(
            data,
            data_json(r#"{"summary":"x"}"#).unwrap(),
            "it is the same event data as with the members left out"
        );
    }

    #[test]
    fn without_removes_the_value_too() {
        let data = full().without(EventField::Location).without(EventField::Alarms);
        assert_eq!(data.location, None);
        assert_eq!(data.alarms, None);
        assert_eq!(data.removed, BTreeSet::from([EventField::Location, EventField::Alarms]));
        data.validate(&IcalLimits::default())
            .expect("a field removed with `without` is not also given");
        for field in EventField::ALL.iter().copied() {
            let mut one = full();
            one.duration = Some(EventDuration::parse("PT1H").unwrap());
            let one = one.without(field);
            assert!(one.removes(field) && !one.is_set(field), "{field:?}");
        }
    }

    #[test]
    fn null_works_through_a_flattened_view_too() {
        #[derive(Deserialize)]
        struct View {
            id: Option<String>,
            #[serde(flatten)]
            data: EventData,
        }
        let view: View = serde_json::from_str(r#"{"id":null,"summary":"x","location":null,"url":null}"#).unwrap();
        assert_eq!(view.id, None);
        assert_eq!(view.data.summary.as_deref(), Some("x"));
        assert_eq!(
            view.data.removed,
            BTreeSet::from([EventField::Location, EventField::Url])
        );
        let error = serde_json::from_str::<View>(r#"{"start":null}"#).err().unwrap();
        assert!(error.to_string().contains("`start` cannot be null"), "{error}");
    }

    #[test]
    fn a_field_cannot_be_given_and_removed_at_once() {
        let limits = IcalLimits::default();
        for field in EventField::ALL.iter().copied() {
            // Every removable field has a value here (`end` and `duration` together: this check comes first).
            let mut data = full();
            data.duration = Some(EventDuration::parse("PT1H").unwrap());
            data.removed.insert(field);
            let error = data.validate(&limits).unwrap_err();
            assert_eq!(error.field(), field.as_str(), "{field:?}");
            assert_eq!(error.reason(), "cannot be given and removed (null) at once");
        }
        let mut data = full();
        data.removed.insert(EventField::Url);
        data.url = None;
        data.validate(&limits).unwrap();
    }

    #[test]
    fn serialization_names_a_removal_where_its_member_would_be() {
        let mut data = full();
        data.location = None;
        data.alarms = None;
        data.removed = BTreeSet::from([EventField::Location, EventField::Alarms]);
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["location"], serde_json::Value::Null);
        assert!(json.as_object().unwrap().contains_key("location"));
        assert_eq!(json["alarms"], serde_json::Value::Null);
        assert_eq!(
            serde_json::from_value::<EventData>(json).unwrap(),
            data,
            "and it reads back"
        );
    }

    #[test]
    fn the_schema_describes_the_wire_form() {
        let schema = serde_json::to_value(schemars::schema_for!(EventData)).unwrap();
        let properties = schema["properties"].as_object().unwrap();
        assert!(
            !properties.contains_key("removed"),
            "the removal set is not a member: {schema}"
        );
        // Every member that is written is described, and nothing else is.
        let mut everything = full();
        everything.recurrence_id = Some(EventTime::Date(date(2027, 3, 8)));
        everything.duration = Some(EventDuration::parse("PT1H").unwrap());
        let written = serde_json::to_value(&everything).unwrap();
        let mut written: Vec<&String> = written.as_object().unwrap().keys().collect();
        let mut described: Vec<&String> = properties.keys().collect();
        written.sort();
        described.sort();
        assert_eq!(written, described);
        // `null` is allowed exactly where it removes something.
        let nullable = |name: &str| {
            let text = properties[name].to_string();
            text.contains(r#""null""#) || text.contains(r#""type":"null""#)
        };
        for field in EventField::ALL.iter().copied() {
            assert!(nullable(field.as_str()), "{} takes null: {schema}", field.as_str());
        }
        for name in ["uid", "start"] {
            assert!(!nullable(name), "{name} refuses null: {}", properties[name]);
        }
        for name in ["recurrence_id", "sequence"] {
            assert!(nullable(name), "{name} takes null as absent: {}", properties[name]);
        }
        assert!(
            schema
                .get("required")
                .is_none_or(|required| required.as_array().is_some_and(Vec::is_empty)),
            "every member is optional: {schema}"
        );
    }

    fn full() -> EventData {
        EventData {
            uid: Some(Uid::parse("uid-1").unwrap()),
            recurrence_id: None,
            summary: Some("Teamtreffen".to_owned()),
            description: Some("Agenda".to_owned()),
            location: Some("Raum 1".to_owned()),
            start: Some(EventTime::Zoned {
                local: local(2027, 3, 1, 10, 0),
                zone: zone("Europe/Berlin"),
            }),
            end: Some(EventTime::Zoned {
                local: local(2027, 3, 1, 11, 0),
                zone: zone("Europe/Berlin"),
            }),
            duration: None,
            status: Some(EventStatus::Confirmed),
            transparency: Some(Transparency::Opaque),
            class: Some(Classification::Private),
            recurrence: Some(Recurrence {
                rrule: Some(RecurrenceRule::parse("FREQ=WEEKLY;COUNT=4").unwrap()),
                rdates: vec![EventTime::Floating(local(2027, 3, 3, 10, 0))],
                exdates: vec![EventTime::Date(date(2027, 3, 8))],
            }),
            organizer: Some(EventOrganizer {
                address: CalendarUserAddress::parse("mailto:anna@example.org").unwrap(),
                common_name: Some("Anna".to_owned()),
                sent_by: None,
            }),
            attendees: Some(vec![EventAttendee {
                address: CalendarUserAddress::parse("mailto:guest@example.net").unwrap(),
                common_name: None,
                partstat: Some(PartStat::Accepted),
                role: Some(Role::OptParticipant),
                cutype: None,
                rsvp: Some(true),
                schedule_agent: None,
            }]),
            categories: Some(vec!["work".to_owned()]),
            url: Some(Url::parse("https://example.org/meeting").unwrap()),
            sequence: Some(2),
            alarms: Some(vec![
                EventAlarm {
                    action: AlarmAction::Display,
                    trigger: AlarmTrigger::Relative {
                        offset: EventDuration::parse("-PT15M").unwrap(),
                        related: AlarmRelated::Start,
                    },
                    description: Some("Gleich geht es los".to_owned()),
                },
                EventAlarm {
                    action: AlarmAction::Audio,
                    trigger: AlarmTrigger::Absolute {
                        at: Utc.with_ymd_and_hms(2027, 3, 1, 8, 0, 0).unwrap(),
                    },
                    description: None,
                },
            ]),
            removed: BTreeSet::new(),
        }
    }

    #[test]
    fn a_full_event_round_trips() {
        let data = full();
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(serde_json::from_str::<EventData>(&json).unwrap(), data);
        let value = serde_json::to_value(&data).unwrap();
        assert_eq!(value["alarms"][0]["trigger"]["type"], "relative");
        assert_eq!(value["alarms"][0]["trigger"]["related"], "start");
        assert_eq!(value["alarms"][1]["trigger"]["type"], "absolute");
        assert_eq!(value["class"], "private");
        assert_eq!(value["recurrence"]["rrule"], "FREQ=WEEKLY;COUNT=4");
    }

    #[test]
    fn relative_alarm_triggers_default_to_the_start() {
        let alarm: EventAlarm =
            serde_json::from_str(r#"{"action":"display","trigger":{"type":"relative","offset":"-PT5M"}}"#).unwrap();
        assert_eq!(
            alarm.trigger,
            AlarmTrigger::Relative {
                offset: EventDuration::parse("-PT5M").unwrap(),
                related: AlarmRelated::Start
            }
        );
        assert!(serde_json::from_str::<EventAlarm>(r#"{"action":"display","trigger":{"type":"sometime"}}"#).is_err());
    }

    #[test]
    fn a_full_event_is_valid_with_the_default_limits() {
        full().validate(&IcalLimits::default()).unwrap();
        EventData::default().validate(&IcalLimits::default()).unwrap();
    }

    #[test]
    fn validation_names_the_offending_field() {
        let limits = IcalLimits::default();
        let check = |edit: &dyn Fn(&mut EventData)| {
            let mut data = full();
            edit(&mut data);
            data.validate(&limits).unwrap_err().field()
        };
        assert_eq!(
            check(&|d| d.duration = Some(EventDuration::parse("PT1H").unwrap())),
            "duration"
        );
        assert_eq!(check(&|d| d.end = Some(EventTime::Date(date(2027, 3, 2)))), "end");
        assert_eq!(
            check(&|d| d.end = Some(EventTime::Zoned {
                local: local(2027, 3, 1, 9, 0),
                zone: zone("Europe/Berlin")
            })),
            "end"
        );
        assert_eq!(check(&|d| d.summary = Some("x".repeat(65_537))), "summary");
        assert_eq!(check(&|d| d.description = Some("x".repeat(65_537))), "description");
        assert_eq!(check(&|d| d.location = Some("x".repeat(65_537))), "location");
        assert_eq!(check(&|d| d.sequence = Some(-1)), "sequence");
        assert_eq!(check(&|d| d.categories = Some(vec!["a,b".to_owned()])), "categories");
        assert_eq!(check(&|d| d.categories = Some(vec![String::new()])), "categories");
        let attendee = full().attendees.unwrap().remove(0);
        assert_eq!(check(&|d| d.attendees = Some(vec![attendee.clone(); 201])), "attendees");
        let alarm = full().alarms.unwrap().remove(0);
        assert_eq!(check(&|d| d.alarms = Some(vec![alarm.clone(); 11])), "alarms");
        assert_eq!(
            check(&|d| d.recurrence = Some(Recurrence {
                rrule: None,
                rdates: vec![EventTime::Date(date(2027, 1, 1)); 1001],
                exdates: Vec::new()
            })),
            "recurrence"
        );
    }

    #[test]
    fn all_day_events_accept_an_exclusive_next_day_end() {
        let data = EventData {
            start: Some(EventTime::Date(date(2027, 3, 1))),
            end: Some(EventTime::Date(date(2027, 3, 2))),
            ..EventData::default()
        };
        data.validate(&IcalLimits::default()).unwrap();
        let backwards = EventData {
            end: Some(EventTime::Date(date(2027, 2, 28))),
            ..data
        };
        assert_eq!(backwards.validate(&IcalLimits::default()).unwrap_err().field(), "end");
    }

    #[test]
    fn display_is_human_readable() {
        assert_eq!(EventTime::Date(date(2027, 3, 1)).to_string(), "2027-03-01");
        assert_eq!(
            EventTime::Floating(local(2027, 3, 1, 10, 0)).to_string(),
            "2027-03-01T10:00:00"
        );
        assert_eq!(
            EventTime::Zoned {
                local: local(2027, 3, 1, 10, 0),
                zone: zone("Europe/Berlin")
            }
            .to_string(),
            "2027-03-01T10:00:00 Europe/Berlin"
        );
        assert_eq!(
            EventTime::Utc(Utc.with_ymd_and_hms(2027, 3, 1, 9, 0, 0).unwrap()).to_string(),
            "2027-03-01T09:00:00Z"
        );
    }
}
