//! The internal calendar model: a component tree over the `calcard` entries, plus typed access to times,
//! durations, attendees and parameters.
//!
//! Everything in this module is private to the crate. `calcard` stores components in a flat list with child
//! indices; the algorithms of this crate read and rewrite a plain tree ([`Node`]) instead, which is easier to
//! transform. The tree is converted back to the flat form only to serialize.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};

use calcard::common::PartialDateTime;
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarDuration, ICalendarEntry, ICalendarParameter,
    ICalendarParameterName, ICalendarParameterValue, ICalendarParticipationRole, ICalendarParticipationStatus,
    ICalendarPeriod, ICalendarProperty, ICalendarScheduleAgentValue, ICalendarUserTypes, ICalendarValue,
    ICalendarValueType, Uri,
};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, TimeDelta, Timelike, Utc};
use davhaven_domain::{
    CalendarUserAddress, ComponentKind, CuType, EventTime, PartStat, Role, ScheduleAgent, TimeZoneName,
};

use crate::error::IcalError;
use crate::zones::Zones;

/// The deepest component tree the model builds, whatever the configured nesting limit says. It keeps the
/// recursion in [`Node::from_calendar`] and [`Node::into_calendar`] bounded.
pub(crate) const MAX_TREE_DEPTH: usize = 32;

/// Component type alias used throughout the crate.
pub(crate) type Kind = ICalendarComponentType;
/// Property name alias used throughout the crate.
pub(crate) type Prop = ICalendarProperty;
/// Parameter name alias used throughout the crate.
pub(crate) type Param = ICalendarParameterName;

/// A component with its properties and child components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    /// The component type (`VEVENT`, `VTIMEZONE`, ...).
    pub(crate) kind: Kind,
    /// The properties in document order.
    pub(crate) entries: Vec<ICalendarEntry>,
    /// The child components in document order.
    pub(crate) children: Vec<Node>,
}

impl Node {
    /// An empty component.
    pub(crate) const fn new(kind: Kind) -> Self {
        Self {
            kind,
            entries: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Builds the tree of a parsed calendar; `None` when the component indices are not a tree of acceptable
    /// depth (never the case for parser output).
    pub(crate) fn from_calendar(calendar: &ICalendar) -> Option<Self> {
        Self::build(calendar, 0, 0)
    }

    fn build(calendar: &ICalendar, id: usize, depth: usize) -> Option<Self> {
        if depth > MAX_TREE_DEPTH {
            return None;
        }
        let component = calendar.components.get(id)?;
        let mut children = Vec::with_capacity(component.component_ids.len());
        for child in &component.component_ids {
            let child = usize::try_from(*child).ok()?;
            if child <= id {
                return None;
            }
            children.push(Self::build(calendar, child, depth.saturating_add(1))?);
        }
        Some(Self {
            kind: component.component_type.clone(),
            entries: component.entries.clone(),
            children,
        })
    }

    /// The flat `calcard` form of the tree, with component ids assigned in document order as the parser does.
    pub(crate) fn to_calendar(&self) -> ICalendar {
        let mut components = Vec::new();
        self.flatten(&mut components);
        ICalendar { components }
    }

    fn flatten(&self, out: &mut Vec<ICalendarComponent>) -> u32 {
        let id = out.len();
        out.push(ICalendarComponent {
            component_type: self.kind.clone(),
            entries: self.entries.clone(),
            component_ids: Vec::new(),
        });
        let ids: Vec<u32> = self.children.iter().map(|child| child.flatten(out)).collect();
        if let Some(slot) = out.get_mut(id) {
            slot.component_ids = ids;
        }
        u32::try_from(id).unwrap_or(u32::MAX)
    }

    /// The first property with this name.
    pub(crate) fn first(&self, name: &Prop) -> Option<&ICalendarEntry> {
        self.entries.iter().find(|entry| &entry.name == name)
    }

    /// Every property with this name, in document order.
    pub(crate) fn all<'a>(&'a self, name: &'a Prop) -> impl Iterator<Item = &'a ICalendarEntry> + 'a {
        self.entries.iter().filter(move |entry| &entry.name == name)
    }

    /// Whether the component has a property with this name.
    pub(crate) fn has(&self, name: &Prop) -> bool {
        self.entries.iter().any(|entry| &entry.name == name)
    }

    /// The text of the first value of the first property with this name.
    pub(crate) fn text(&self, name: &Prop) -> Option<String> {
        self.first(name).and_then(entry_text)
    }

    /// The integer value of the first property with this name.
    pub(crate) fn integer(&self, name: &Prop) -> Option<i64> {
        self.first(name)
            .and_then(|entry| entry.values.first())
            .and_then(ICalendarValue::as_integer)
    }

    /// Removes every property with this name.
    pub(crate) fn remove(&mut self, name: &Prop) {
        self.entries.retain(|entry| &entry.name != name);
    }

    /// Replaces every property of the entry's name by the entry, keeping the position of the first one.
    pub(crate) fn set(&mut self, entry: ICalendarEntry) {
        let position = self.entries.iter().position(|existing| existing.name == entry.name);
        self.entries.retain(|existing| existing.name != entry.name);
        match position {
            Some(position) => self.entries.insert(position.min(self.entries.len()), entry),
            None => self.entries.push(entry),
        }
    }

    /// The component's type as a stored kind (`VEVENT`, `VTODO`, `VJOURNAL`).
    pub(crate) fn component_kind(&self) -> Option<ComponentKind> {
        component_kind(&self.kind)
    }

    /// Whether this is an override component (it has a `RECURRENCE-ID`).
    pub(crate) fn is_override(&self) -> bool {
        self.has(&Prop::RecurrenceId)
    }

    /// The UID of the component.
    pub(crate) fn uid(&self) -> Option<String> {
        self.text(&Prop::Uid)
    }

    /// The `STATUS` token in upper case.
    pub(crate) fn status(&self) -> Option<String> {
        self.text(&Prop::Status).map(|status| status.to_ascii_uppercase())
    }

    /// The `TRANSP` token in upper case.
    pub(crate) fn transparency(&self) -> Option<String> {
        self.text(&Prop::Transp).map(|value| value.to_ascii_uppercase())
    }
}

/// The stored kind of a component type, `None` for everything that cannot be stored on its own.
pub(crate) fn component_kind(kind: &Kind) -> Option<ComponentKind> {
    match kind {
        Kind::VEvent => Some(ComponentKind::Event),
        Kind::VTodo => Some(ComponentKind::Todo),
        Kind::VJournal => Some(ComponentKind::Journal),
        _ => None,
    }
}

/// The text of the first value of a property, if it has one.
pub(crate) fn entry_text(entry: &ICalendarEntry) -> Option<String> {
    entry.values.first().and_then(value_text)
}

/// The text of a value; enumerations give their token, binary data and numbers give nothing.
pub(crate) fn value_text(value: &ICalendarValue) -> Option<String> {
    match value {
        ICalendarValue::Text(text) | ICalendarValue::Uri(Uri::Location(text)) => Some(text.clone()),
        ICalendarValue::Uri(Uri::Data(_))
        | ICalendarValue::Binary(_)
        | ICalendarValue::Boolean(_)
        | ICalendarValue::PartialDateTime(_)
        | ICalendarValue::Duration(_)
        | ICalendarValue::RecurrenceRule(_)
        | ICalendarValue::Period(_)
        | ICalendarValue::Float(_)
        | ICalendarValue::Integer(_) => None,
        other => other.as_text().map(str::to_owned),
    }
}

/// All text values of a property (categories and the like).
pub(crate) fn entry_texts(entry: &ICalendarEntry) -> Vec<String> {
    entry.values.iter().filter_map(value_text).collect()
}

/// The text of a parameter value.
pub(crate) fn param_text(entry: &ICalendarEntry, name: &Param) -> Option<String> {
    entry
        .parameter(name)
        .and_then(|value| value.as_text())
        .map(str::to_owned)
}

/// Whether the property has this parameter.
pub(crate) fn has_param(entry: &ICalendarEntry, name: &Param) -> bool {
    entry.params.iter().any(|param| &param.name == name)
}

/// Removes every parameter with this name.
pub(crate) fn remove_param(entry: &mut ICalendarEntry, name: &Param) {
    entry.params.retain(|param| &param.name != name);
}

/// A property with a single text value.
pub(crate) fn text_entry(name: Prop, value: &str) -> ICalendarEntry {
    ICalendarEntry::new(name).with_value(value.to_owned())
}

// ---------------------------------------------------------------------------------------------------------------
// Time values
// ---------------------------------------------------------------------------------------------------------------

/// A point in time as an iCalendar value states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Moment {
    /// A calendar date (`VALUE=DATE`).
    Date(NaiveDate),
    /// A local time without a zone.
    Floating(NaiveDateTime),
    /// An absolute instant (`Z` suffix or a numeric offset), as naive UTC.
    Utc(NaiveDateTime),
    /// A local time with a `TZID`, as written (not yet resolved).
    Zoned {
        /// The wall-clock time.
        local: NaiveDateTime,
        /// The `TZID` parameter value.
        tzid: String,
    },
}

impl Moment {
    /// Whether this is an all-day date.
    pub(crate) const fn is_date(&self) -> bool {
        matches!(self, Self::Date(_))
    }

    /// The wall-clock value: the local time, the date at midnight, or the UTC time.
    pub(crate) fn local(&self) -> NaiveDateTime {
        match self {
            Self::Date(date) => date.and_time(chrono::NaiveTime::MIN),
            Self::Floating(local) | Self::Utc(local) | Self::Zoned { local, .. } => *local,
        }
    }

    /// The calendar date of the wall-clock value.
    pub(crate) fn date(&self) -> NaiveDate {
        self.local().date()
    }

    /// A copy of this moment with another wall-clock value in the same kind and zone.
    pub(crate) fn with_local(&self, local: NaiveDateTime) -> Self {
        match self {
            Self::Date(_) => Self::Date(local.date()),
            Self::Floating(_) => Self::Floating(local),
            Self::Utc(_) => Self::Utc(local),
            Self::Zoned { tzid, .. } => Self::Zoned {
                local,
                tzid: tzid.clone(),
            },
        }
    }

    /// The domain representation of the value: zones that are not IANA zones become UTC instants.
    pub(crate) fn to_event_time(&self, zones: &Zones) -> EventTime {
        match self {
            Self::Date(date) => EventTime::Date(*date),
            Self::Floating(local) => EventTime::Floating(*local),
            Self::Utc(local) => EventTime::Utc(local.and_utc()),
            Self::Zoned { local, tzid } => match zones.iana_name(tzid) {
                Some(zone) => EventTime::Zoned { local: *local, zone },
                None => zones.to_utc(self).map_or(EventTime::Floating(*local), EventTime::Utc),
            },
        }
    }

    /// The moment a domain time denotes.
    pub(crate) fn from_event_time(time: &EventTime) -> Self {
        match time {
            EventTime::Date(date) => Self::Date(*date),
            EventTime::Floating(local) => Self::Floating(*local),
            EventTime::Zoned { local, zone } => Self::Zoned {
                local: *local,
                tzid: zone.as_str().to_owned(),
            },
            EventTime::Utc(instant) => Self::Utc(instant.naive_utc()),
        }
    }
}

/// Converts a parsed date or date-time value; `date_only` is the `VALUE=DATE` flag of the property.
pub(crate) fn moment_from_partial(value: &PartialDateTime, date_only: bool, tzid: Option<&str>) -> Option<Moment> {
    let parsed = value.to_date_time()?;
    if date_only || !value.has_time() {
        return Some(Moment::Date(parsed.date_time.date()));
    }
    match parsed.offset {
        Some(offset) => {
            let seconds = TimeDelta::try_seconds(i64::from(offset.local_minus_utc()))?;
            let utc = parsed.date_time.checked_sub_signed(seconds)?;
            Some(Moment::Utc(utc))
        }
        None => Some(match tzid {
            Some(tzid) if !tzid.is_empty() => Moment::Zoned {
                local: parsed.date_time,
                tzid: tzid.to_owned(),
            },
            _ => Moment::Floating(parsed.date_time),
        }),
    }
}

/// The first date or date-time value of a property; `None` when it is absent or unreadable.
pub(crate) fn entry_moment(entry: &ICalendarEntry) -> Option<Moment> {
    let tzid = param_text(entry, &Param::Tzid);
    let date_only = entry.is_type(&ICalendarValueType::Date);
    match entry.values.first()? {
        ICalendarValue::PartialDateTime(value) => moment_from_partial(value, date_only, tzid.as_deref()),
        _ => None,
    }
}

/// All date and date-time values of a property (`EXDATE`, `RDATE`); unreadable values are skipped and
/// reported through the second element.
pub(crate) fn entry_moments(entry: &ICalendarEntry) -> (Vec<Moment>, bool) {
    let tzid = param_text(entry, &Param::Tzid);
    let date_only = entry.is_type(&ICalendarValueType::Date);
    let mut moments = Vec::new();
    let mut all_readable = true;
    for value in &entry.values {
        match value {
            ICalendarValue::PartialDateTime(value) => match moment_from_partial(value, date_only, tzid.as_deref()) {
                Some(moment) => moments.push(moment),
                None => all_readable = false,
            },
            _ => all_readable = false,
        }
    }
    (moments, all_readable)
}

/// The end of an `RDATE` period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeriodEnd {
    /// An explicit end.
    At(Moment),
    /// A length.
    Length(ICalendarDuration),
}

/// An `RDATE;VALUE=PERIOD` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Period {
    /// The start of the period.
    pub(crate) start: Moment,
    /// The end or length.
    pub(crate) end: PeriodEnd,
}

/// The periods of an `RDATE` property.
pub(crate) fn entry_periods(entry: &ICalendarEntry) -> Vec<Period> {
    let tzid = param_text(entry, &Param::Tzid);
    let convert = |value: &PartialDateTime| moment_from_partial(value, false, tzid.as_deref());
    entry
        .values
        .iter()
        .filter_map(|value| match value {
            ICalendarValue::Period(ICalendarPeriod::Range { start, end }) => Some(Period {
                start: convert(start)?,
                end: PeriodEnd::At(convert(end)?),
            }),
            ICalendarValue::Period(ICalendarPeriod::Duration { start, duration }) => Some(Period {
                start: convert(start)?,
                end: PeriodEnd::Length(duration.clone()),
            }),
            _ => None,
        })
        .collect()
}

/// The first duration value of a property.
pub(crate) fn entry_duration(entry: &ICalendarEntry) -> Option<ICalendarDuration> {
    match entry.values.first()? {
        ICalendarValue::Duration(duration) => Some(duration.clone()),
        _ => None,
    }
}

/// A duration split into the calendar part (days, measured on the wall clock) and the exact part (seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Length {
    /// Days (weeks counted as seven days), negative for negative durations.
    pub(crate) days: i64,
    /// Hours, minutes and seconds in seconds, negative for negative durations.
    pub(crate) seconds: i64,
}

impl Length {
    /// Splits an iCalendar duration.
    pub(crate) fn from_duration(duration: &ICalendarDuration) -> Self {
        let days = i64::from(duration.weeks)
            .saturating_mul(7)
            .saturating_add(i64::from(duration.days));
        let seconds = i64::from(duration.hours)
            .saturating_mul(3600)
            .saturating_add(i64::from(duration.minutes).saturating_mul(60))
            .saturating_add(i64::from(duration.seconds));
        if duration.neg {
            Self {
                days: -days,
                seconds: -seconds,
            }
        } else {
            Self { days, seconds }
        }
    }

    /// The length in seconds when a day counts as 86 400 of them, or `None` on overflow. Exact where the time
    /// zone is not known (alarm triggers and repeats, the end of a duration in a comparison).
    pub(crate) fn total_seconds(self) -> Option<i64> {
        self.days.checked_mul(86_400)?.checked_add(self.seconds)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Writing time values
// ---------------------------------------------------------------------------------------------------------------

/// The `PartialDateTime` for a naive date-time; `None` for years outside the representable range.
pub(crate) fn partial_from_local(local: NaiveDateTime, with_time: bool, utc: bool) -> Option<PartialDateTime> {
    let mut value = PartialDateTime {
        year: Some(u16::try_from(local.year()).ok()?),
        month: Some(u8::try_from(local.month()).ok()?),
        day: Some(u8::try_from(local.day()).ok()?),
        ..PartialDateTime::default()
    };
    if with_time {
        value.hour = Some(u8::try_from(local.hour()).ok()?);
        value.minute = Some(u8::try_from(local.minute()).ok()?);
        value.second = Some(u8::try_from(local.second()).ok()?);
    }
    if utc {
        value.tz_hour = Some(0);
        value.tz_minute = Some(0);
    }
    Some(value)
}

/// A property carrying a moment (`DTSTART`, `RECURRENCE-ID`, ...): the `VALUE` and `TZID` parameters follow the
/// kind of the moment.
pub(crate) fn moment_entry(name: Prop, moment: &Moment) -> Option<ICalendarEntry> {
    let mut entry = ICalendarEntry::new(name);
    let (value, params) = moment_value(moment)?;
    entry.params = params;
    entry.values.push(value);
    Some(entry)
}

/// The value and parameters that represent a moment.
pub(crate) fn moment_value(moment: &Moment) -> Option<(ICalendarValue, Vec<ICalendarParameter>)> {
    let mut params = Vec::new();
    let value = match moment {
        Moment::Date(date) => {
            params.push(ICalendarParameter::value(ICalendarValueType::Date));
            partial_from_local(date.and_time(chrono::NaiveTime::MIN), false, false)?
        }
        Moment::Floating(local) => partial_from_local(*local, true, false)?,
        Moment::Utc(local) => partial_from_local(*local, true, true)?,
        Moment::Zoned { local, tzid } => {
            params.push(ICalendarParameter::tzid(tzid.clone()));
            partial_from_local(*local, true, false)?
        }
    };
    Some((ICalendarValue::PartialDateTime(Box::new(value)), params))
}

/// A `DTSTAMP`-style property for an instant.
pub(crate) fn instant_entry(name: Prop, instant: DateTime<Utc>) -> Option<ICalendarEntry> {
    moment_entry(name, &Moment::Utc(instant.naive_utc()))
}

// ---------------------------------------------------------------------------------------------------------------
// Building entries from text
// ---------------------------------------------------------------------------------------------------------------

/// Escapes text for use as a property value (RFC 5545 section 3.3.11): backslash, semicolon, comma and line
/// breaks; other control characters are dropped.
pub(crate) fn escape_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            ';' => escaped.push_str("\\;"),
            ',' => escaped.push_str("\\,"),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                escaped.push_str("\\n");
            }
            '\n' => escaped.push_str("\\n"),
            '\t' => escaped.push('\t'),
            other if other.is_control() => {}
            other => escaped.push(other),
        }
    }
    escaped
}

/// A parameter value for use in a content line: control characters and double quotes are dropped, and values
/// with separators are quoted.
pub(crate) fn param_value(text: &str) -> String {
    let cleaned: String = text.chars().filter(|c| !c.is_control() && *c != '"').collect();
    if cleaned.chars().any(|c| matches!(c, ',' | ';' | ':' | ' ')) {
        format!("\"{cleaned}\"")
    } else {
        cleaned
    }
}

/// The content line of a text property.
pub(crate) fn text_line(name: &str, value: &str) -> String {
    format!("{name}:{}", escape_text(value))
}

/// The content line of a date or date-time property.
pub(crate) fn moment_line(name: &str, moment: &Moment) -> String {
    match moment {
        Moment::Date(date) => format!("{name};VALUE=DATE:{}", date.format("%Y%m%d")),
        Moment::Floating(local) => format!("{name}:{}", local.format("%Y%m%dT%H%M%S")),
        Moment::Utc(utc) => format!("{name}:{}Z", utc.format("%Y%m%dT%H%M%S")),
        Moment::Zoned { local, tzid } => {
            format!("{name};TZID={}:{}", param_value(tzid), local.format("%Y%m%dT%H%M%S"))
        }
    }
}

/// The panics of third-party code this crate has contained, see [`contain`].
static CONTAINED_PANICS: AtomicU64 = AtomicU64::new(0);

/// How many panics of the parser and the recurrence generator this crate has caught and turned into errors since
/// the process started.
///
/// No input is supposed to make third-party code panic: every one of them is a bug to report and fix. The
/// application exports the count as a metric; the tests assert that it stays where it was, which a plain
/// "never panics" property cannot see because the panic is contained.
pub fn contained_panics() -> u64 {
    CONTAINED_PANICS.load(Ordering::Relaxed)
}

/// Runs third-party code that may panic. A panic never reaches the caller: it is counted ([`contained_panics`])
/// and the result is `None`.
pub(crate) fn contain<T>(work: impl FnOnce() -> T) -> Option<T> {
    if let Ok(value) = catch_unwind(AssertUnwindSafe(work)) {
        Some(value)
    } else {
        CONTAINED_PANICS.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// Parses one content line into a typed property, exactly as the parser would read it from a document (so that
/// generated and parsed data have the same representation).
pub(crate) fn entry_from_line(line: &str) -> Result<ICalendarEntry, IcalError> {
    let text = format!("BEGIN:VCALENDAR\nBEGIN:X-ENTRY\n{line}\nEND:X-ENTRY\nEND:VCALENDAR\n");
    let calendar = contain(|| match calcard::Parser::new(&text).entry() {
        calcard::Entry::ICalendar(calendar) => Some(calendar),
        _ => None,
    })
    .flatten();
    calendar
        .and_then(|calendar| calendar.components.into_iter().nth(1))
        .and_then(|component| component.entries.into_iter().next())
        .ok_or_else(|| IcalError::invalid("a property value cannot be written"))
}

/// A property of a date or date-time value, built from a moment.
pub(crate) fn entry_for_moment(name: &str, moment: &Moment) -> Result<ICalendarEntry, IcalError> {
    entry_from_line(&moment_line(name, moment))
}

/// A text property with escaping.
pub(crate) fn entry_for_text(name: &str, value: &str) -> Result<ICalendarEntry, IcalError> {
    entry_from_line(&text_line(name, value))
}

// ---------------------------------------------------------------------------------------------------------------
// Attendees and addresses
// ---------------------------------------------------------------------------------------------------------------

/// The calendar user address of an `ORGANIZER` or `ATTENDEE` property; `None` when it is not a usable address.
pub(crate) fn address_of(entry: &ICalendarEntry) -> Option<CalendarUserAddress> {
    entry_text(entry).and_then(|text| CalendarUserAddress::parse(&text).ok())
}

/// The participation status of an attendee property.
pub(crate) fn partstat_of(entry: &ICalendarEntry) -> PartStat {
    match entry.parameter(&Param::Partstat) {
        Some(ICalendarParameterValue::Partstat(value)) => match value {
            ICalendarParticipationStatus::NeedsAction | ICalendarParticipationStatus::Failed => PartStat::NeedsAction,
            ICalendarParticipationStatus::Accepted => PartStat::Accepted,
            ICalendarParticipationStatus::Declined => PartStat::Declined,
            ICalendarParticipationStatus::Tentative => PartStat::Tentative,
            ICalendarParticipationStatus::Delegated => PartStat::Delegated,
            ICalendarParticipationStatus::Completed => PartStat::Completed,
            ICalendarParticipationStatus::InProcess => PartStat::InProcess,
        },
        Some(ICalendarParameterValue::Text(text)) => PartStat::from_ical(text).unwrap_or_default(),
        _ => PartStat::default(),
    }
}

/// The participation role of an attendee property.
pub(crate) fn role_of(entry: &ICalendarEntry) -> Role {
    match entry.parameter(&Param::Role) {
        Some(ICalendarParameterValue::Role(value)) => match value {
            ICalendarParticipationRole::Chair | ICalendarParticipationRole::Owner => Role::Chair,
            ICalendarParticipationRole::ReqParticipant => Role::ReqParticipant,
            ICalendarParticipationRole::OptParticipant => Role::OptParticipant,
            ICalendarParticipationRole::NonParticipant => Role::NonParticipant,
        },
        Some(ICalendarParameterValue::Text(text)) => Role::from_ical(text).unwrap_or_default(),
        _ => Role::default(),
    }
}

/// The calendar user type of an attendee property.
pub(crate) fn cutype_of(entry: &ICalendarEntry) -> CuType {
    match entry.parameter(&Param::Cutype) {
        Some(ICalendarParameterValue::Cutype(value)) => match value {
            ICalendarUserTypes::Individual => CuType::Individual,
            ICalendarUserTypes::Group => CuType::Group,
            ICalendarUserTypes::Resource => CuType::Resource,
            ICalendarUserTypes::Room => CuType::Room,
            ICalendarUserTypes::Unknown => CuType::Unknown,
        },
        Some(ICalendarParameterValue::Text(text)) => CuType::from_ical(text).unwrap_or_default(),
        _ => CuType::default(),
    }
}

/// The scheduling agent of an attendee property.
pub(crate) fn schedule_agent_of(entry: &ICalendarEntry) -> ScheduleAgent {
    match entry.parameter(&Param::ScheduleAgent) {
        Some(ICalendarParameterValue::ScheduleAgent(value)) => match value {
            ICalendarScheduleAgentValue::Server => ScheduleAgent::Server,
            ICalendarScheduleAgentValue::Client => ScheduleAgent::Client,
            ICalendarScheduleAgentValue::None => ScheduleAgent::None,
        },
        Some(ICalendarParameterValue::Text(text)) => ScheduleAgent::from_ical(text).unwrap_or_default(),
        _ => ScheduleAgent::default(),
    }
}

/// A calendar user address as a property value.
pub(crate) fn address_value(address: &CalendarUserAddress) -> ICalendarValue {
    ICalendarValue::Uri(Uri::Location(address.as_str().to_owned()))
}

/// Whether a parameter is one of the scheduling parameters of RFC 6638 (`SCHEDULE-*`), which never leave the
/// server.
pub(crate) fn is_schedule_param(name: &Param) -> bool {
    matches!(
        name,
        Param::ScheduleAgent | Param::ScheduleForceSend | Param::ScheduleStatus
    )
}

/// The zone name of a resolved IANA zone, for `EventTime`.
pub(crate) fn zone_name(zone: chrono_tz::Tz) -> Option<TimeZoneName> {
    TimeZoneName::parse(zone.name()).ok()
}

#[cfg(test)]
mod tests {
    use calcard::Entry;
    use calcard::Parser;

    use super::*;

    fn parse(text: &str) -> Node {
        let mut parser = Parser::new(text);
        let Entry::ICalendar(calendar) = parser.entry() else {
            panic!("not a calendar");
        };
        Node::from_calendar(&calendar).unwrap()
    }

    const SAMPLE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nBEGIN:STANDARD\r\n\
        DTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
        BEGIN:VEVENT\r\nUID:one\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\n\
        BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn the_tree_follows_the_document_structure() {
        let root = parse(SAMPLE);
        assert_eq!(root.kind, Kind::VCalendar);
        let kinds: Vec<&Kind> = root.children.iter().map(|child| &child.kind).collect();
        assert_eq!(kinds, [&Kind::VTimezone, &Kind::VEvent]);
        let event = root.children.get(1).unwrap();
        assert_eq!(event.uid().as_deref(), Some("one"));
        assert_eq!(event.children.len(), 1);
    }

    #[test]
    fn flattening_assigns_the_ids_the_parser_assigns() {
        let root = parse(SAMPLE);
        let mut parser = Parser::new(SAMPLE);
        let Entry::ICalendar(calendar) = parser.entry() else {
            panic!("not a calendar");
        };
        assert_eq!(root.to_calendar(), calendar);
    }

    #[test]
    fn moments_follow_value_type_and_zone() {
        let root = parse(SAMPLE);
        let event = root.children.get(1).unwrap();
        let start = entry_moment(event.first(&Prop::Dtstart).unwrap()).unwrap();
        assert_eq!(
            start,
            Moment::Zoned {
                local: NaiveDate::from_ymd_opt(2027, 3, 1)
                    .unwrap()
                    .and_hms_opt(10, 0, 0)
                    .unwrap(),
                tzid: "Europe/Berlin".to_owned(),
            }
        );
        let cases = [
            ("DTSTART:20270301\r\n", "DTSTART;VALUE=DATE:20270301\r\n"),
            ("DTSTART:20270301T100000\r\n", "DTSTART:20270301T100000\r\n"),
            ("DTSTART:20270301T100000Z\r\n", "DTSTART:20270301T100000Z\r\n"),
        ];
        for (_, input) in cases {
            let text = format!("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n{input}END:VEVENT\r\nEND:VCALENDAR\r\n");
            let root = parse(&text);
            let event = root.children.first().unwrap();
            let moment = entry_moment(event.first(&Prop::Dtstart).unwrap()).unwrap();
            let expected_date = NaiveDate::from_ymd_opt(2027, 3, 1).unwrap();
            assert_eq!(moment.date(), expected_date, "{input}");
            let rebuilt = moment_entry(Prop::Dtstart, &moment).unwrap();
            let again = entry_moment(&rebuilt).unwrap();
            assert_eq!(again, moment, "{input}");
        }
    }

    #[test]
    fn unreadable_values_are_reported() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART:garbage\r\nEXDATE:20270301T100000Z,nonsense\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let root = parse(text);
        let event = root.children.first().unwrap();
        assert!(entry_moment(event.first(&Prop::Dtstart).unwrap()).is_none());
        let (moments, all) = entry_moments(event.first(&Prop::Exdate).unwrap());
        assert_eq!(moments.len(), 1);
        assert!(!all);
    }

    #[test]
    fn durations_split_into_days_and_seconds() {
        let duration = ICalendarDuration {
            neg: true,
            weeks: 1,
            days: 2,
            hours: 3,
            minutes: 4,
            seconds: 5,
        };
        assert_eq!(
            Length::from_duration(&duration),
            Length {
                days: -9,
                seconds: -(3 * 3600 + 4 * 60 + 5)
            }
        );
    }

    #[test]
    fn attendee_parameters_have_defaults() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
            ATTENDEE;CN=Gast;PARTSTAT=ACCEPTED;ROLE=CHAIR;CUTYPE=ROOM;SCHEDULE-AGENT=CLIENT:MAILTO:Gast@Example.org\r\n\
            ATTENDEE:mailto:plain@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let root = parse(text);
        let event = root.children.first().unwrap();
        let mut attendees = event.all(&Prop::Attendee);
        let first = attendees.next().unwrap();
        assert_eq!(address_of(first).unwrap().as_str(), "mailto:gast@example.org");
        assert_eq!(partstat_of(first), PartStat::Accepted);
        assert_eq!(role_of(first), Role::Chair);
        assert_eq!(cutype_of(first), CuType::Room);
        assert_eq!(schedule_agent_of(first), ScheduleAgent::Client);
        let second = attendees.next().unwrap();
        assert_eq!(partstat_of(second), PartStat::NeedsAction);
        assert_eq!(role_of(second), Role::ReqParticipant);
        assert_eq!(cutype_of(second), CuType::Individual);
        assert_eq!(schedule_agent_of(second), ScheduleAgent::Server);
    }

    #[test]
    fn every_attendee_parameter_value_maps_to_its_domain_value() {
        let attendee = |params: &str| {
            let text = format!(
                "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nATTENDEE{params}:mailto:a@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
            );
            parse(&text)
                .children
                .first()
                .unwrap()
                .first(&Prop::Attendee)
                .unwrap()
                .clone()
        };
        let partstats = [
            ("NEEDS-ACTION", PartStat::NeedsAction),
            ("ACCEPTED", PartStat::Accepted),
            ("DECLINED", PartStat::Declined),
            ("TENTATIVE", PartStat::Tentative),
            ("DELEGATED", PartStat::Delegated),
            ("COMPLETED", PartStat::Completed),
            ("IN-PROCESS", PartStat::InProcess),
            ("accepted", PartStat::Accepted),
            // Values the domain does not know read as the RFC 5545 default.
            ("X-MAYBE", PartStat::NeedsAction),
        ];
        for (value, expected) in partstats {
            assert_eq!(
                partstat_of(&attendee(&format!(";PARTSTAT={value}"))),
                expected,
                "{value}"
            );
        }
        let roles = [
            ("CHAIR", Role::Chair),
            ("REQ-PARTICIPANT", Role::ReqParticipant),
            ("OPT-PARTICIPANT", Role::OptParticipant),
            ("NON-PARTICIPANT", Role::NonParticipant),
            ("X-OBSERVER", Role::ReqParticipant),
        ];
        for (value, expected) in roles {
            assert_eq!(role_of(&attendee(&format!(";ROLE={value}"))), expected, "{value}");
        }
        let cutypes = [
            ("INDIVIDUAL", CuType::Individual),
            ("GROUP", CuType::Group),
            ("RESOURCE", CuType::Resource),
            ("ROOM", CuType::Room),
            ("UNKNOWN", CuType::Unknown),
            ("X-CAR", CuType::Individual),
        ];
        for (value, expected) in cutypes {
            assert_eq!(cutype_of(&attendee(&format!(";CUTYPE={value}"))), expected, "{value}");
        }
        let agents = [
            ("SERVER", ScheduleAgent::Server),
            ("CLIENT", ScheduleAgent::Client),
            ("NONE", ScheduleAgent::None),
            ("X-ROBOT", ScheduleAgent::Server),
        ];
        for (value, expected) in agents {
            assert_eq!(
                schedule_agent_of(&attendee(&format!(";SCHEDULE-AGENT={value}"))),
                expected,
                "{value}"
            );
        }
    }

    #[test]
    fn text_is_escaped_so_that_it_stays_one_value_of_one_line() {
        // RFC 5545 section 3.3.11: backslash, semicolon and comma are escaped, a line break is written as \n.
        let cases = [
            ("plain text", "plain text"),
            ("a\\b;c,d", "a\\\\b\\;c\\,d"),
            ("one\ntwo", "one\\ntwo"),
            ("one\r\ntwo", "one\\ntwo"),
            ("one\rtwo", "one\\ntwo"),
            ("one\n\ntwo", "one\\n\\ntwo"),
            ("tab\tkept", "tab\tkept"),
            ("bell\u{7}nul\u{0}del\u{7f}nel\u{85}", "bellnuldelnel"),
            ("Grüße, 日本", "Grüße\\, 日本"),
        ];
        for (input, expected) in cases {
            assert_eq!(escape_text(input), expected, "{input:?}");
            assert!(!escape_text(input).contains(['\r', '\n']), "{input:?}");
        }
    }

    #[test]
    fn parameter_values_are_quoted_when_they_hold_a_separator_and_never_hold_a_quote() {
        // RFC 5545 section 3.2: a value with ':', ';' or ',' is a quoted-string, which cannot contain DQUOTE.
        let cases = [
            ("Anna", "Anna"),
            ("Anna Smith", "\"Anna Smith\""),
            ("Smith, Anna", "\"Smith, Anna\""),
            ("a;ROLE=CHAIR", "\"a;ROLE=CHAIR\""),
            ("mailto:a@example.org", "\"mailto:a@example.org\""),
            ("say \"hi\"", "\"say hi\""),
            ("line\r\nbreak", "linebreak"),
            ("\"", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(param_value(input), expected, "{input:?}");
        }
    }

    #[test]
    fn set_keeps_the_position_of_the_replaced_property() {
        let mut root = parse(SAMPLE);
        let event = root.children.get_mut(1).unwrap();
        let before: Vec<String> = event.entries.iter().map(|e| e.name.as_str().to_owned()).collect();
        event.set(text_entry(Prop::Uid, "two"));
        let after: Vec<String> = event.entries.iter().map(|e| e.name.as_str().to_owned()).collect();
        assert_eq!(before, after);
        assert_eq!(event.uid().as_deref(), Some("two"));
        event.set(text_entry(Prop::Summary, "new"));
        assert_eq!(event.entries.last().unwrap().name, Prop::Summary);
    }
}
