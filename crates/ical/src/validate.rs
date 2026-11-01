//! Validation of calendar object resources against RFC 4791/5545 rules and configured limits.
//!
//! A calendar object resource must contain exactly one `VCALENDAR` whose components share one UID and have one
//! component type (a master plus overrides with `RECURRENCE-ID`), carry no `METHOD`, and stay within the limits
//! (attendees, alarms, recurrence dates, date range, no sub-hourly recurrence). Whether the target collection
//! accepts the component type (`CALDAV:supported-calendar-component`) is decided by the application from
//! [`ValidatedObject::component`].
//!
//! The rejections are classified the way RFC 4791 section 5.3.2.1 and RFC 6638 do: data that is not valid
//! iCalendar is [`IcalError::Invalid`] (`CALDAV:valid-calendar-data`), a violated restriction on calendar object
//! resources is [`IcalError::ObjectRule`] (`CALDAV:valid-calendar-object-resource`) and differing organizers are
//! [`IcalError::OrganizerMismatch`] (`CALDAV:same-organizer-in-all-components`).

use std::collections::HashSet;
use std::fmt;

use calcard::icalendar::{ICalendarValue, Uri};
use chrono::NaiveDateTime;
use davhaven_domain::{CalendarUserAddress, ComponentKind, IcalLimits, Uid};

use crate::calendar::{
    Kind, Moment, Node, Prop, address_of, entry_duration, entry_moment, entry_moments, entry_periods, entry_text,
};
use crate::error::{IcalError, LimitKind};
use crate::parse::ParsedCalendar;
use crate::recur::{RuleError, check_rule, is_sub_hourly};
use crate::zones::{RidKey, Zone, Zones};

/// A parsed calendar that satisfies the rules for calendar object resources.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedObject {
    /// The calendar.
    pub calendar: ParsedCalendar,
    /// The UID shared by all components.
    pub uid: Uid,
    /// The component type of the master (or only) component.
    pub component: ComponentKind,
}

impl fmt::Debug for ValidatedObject {
    /// Shows the kind and the size of the object, never its content (`ENGINEERING_RULES` R8).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedObject")
            .field("component", &self.component)
            .field("calendar", &self.calendar)
            .finish_non_exhaustive()
    }
}

/// Checks a parsed calendar against the rules for calendar object resources and the limits.
///
/// # Errors
///
/// * [`IcalError::Invalid`] with a client-safe explanation for data that is not valid iCalendar (an unreadable
///   date, a missing UID, a rule RFC 5545 forbids, ...),
/// * [`IcalError::ObjectRule`] for a violated restriction on calendar object resources (a `METHOD` property,
///   mixed component types, differing UIDs, a duplicate `RECURRENCE-ID`, more than one master component),
/// * [`IcalError::OrganizerMismatch`] for an `ORGANIZER` that differs between components,
/// * [`IcalError::Limit`] for exceeded limits.
pub fn validate(calendar: ParsedCalendar, limits: &IcalLimits) -> Result<ValidatedObject, IcalError> {
    let (uid, component) = check(&calendar.root, limits)?;
    Ok(ValidatedObject {
        calendar,
        uid,
        component,
    })
}

/// Parses and validates in one step: the gate of every object that is written (`PUT`, a batch item, the result of
/// a merge). It goes through [`crate::parse::accept`], so the object must survive the writer too; what is stored
/// is read with [`crate::parse::parse`], which does not decide acceptance again.
///
/// # Errors
///
/// The errors of [`crate::parse::accept`] and [`validate`].
pub fn parse_and_validate(input: &[u8], limits: &IcalLimits) -> Result<ValidatedObject, IcalError> {
    validate(crate::parse::accept(input, limits)?, limits)
}

fn check(root: &Node, limits: &IcalLimits) -> Result<(Uid, ComponentKind), IcalError> {
    if let Some(version) = root.text(&Prop::Version)
        && version.trim() != "2.0"
    {
        return Err(IcalError::invalid("only iCalendar version 2.0 is supported"));
    }
    if root.has(&Prop::Method) {
        return Err(IcalError::object_rule(
            "calendar object resources must not have a METHOD property",
        ));
    }
    // The limits on time zone definitions hold before anything is evaluated.
    for zone in root.children.iter().filter(|child| child.kind == Kind::VTimezone) {
        check_timezone(zone, limits)?;
    }
    let zones = Zones::for_tree(root, Zone::utc());
    zones.check_referenced()?;
    let max_attendees = usize::try_from(limits.max_attendees_per_instance).unwrap_or(usize::MAX);
    let mut attendees: HashSet<CalendarUserAddress> = HashSet::new();
    let mut uid: Option<String> = None;
    let mut kind: Option<ComponentKind> = None;
    let mut masters = 0usize;
    let mut recurrence_ids: HashSet<RidKey> = HashSet::new();
    let mut organizers: Vec<Option<String>> = Vec::new();
    for child in &root.children {
        match child.kind {
            Kind::VTimezone => {}
            Kind::VEvent | Kind::VTodo | Kind::VJournal => {
                let component = child
                    .component_kind()
                    .ok_or_else(|| IcalError::object_rule("unsupported component"))?;
                match kind {
                    Some(existing) if existing != component => {
                        return Err(IcalError::object_rule("an object may contain only one component type"));
                    }
                    _ => kind = Some(component),
                }
                let own_uid = check_component(child, &zones, limits)?;
                match &uid {
                    Some(existing) if existing != &own_uid => {
                        return Err(IcalError::object_rule("the components have different UIDs"));
                    }
                    _ => uid = Some(own_uid),
                }
                if let Some(entry) = child.first(&Prop::RecurrenceId) {
                    let moment = entry_moment(entry)
                        .ok_or_else(|| IcalError::invalid("RECURRENCE-ID is not a valid date or date-time"))?;
                    if zones.rid_key(&moment).is_some_and(|key| !recurrence_ids.insert(key)) {
                        return Err(IcalError::object_rule("two components have the same RECURRENCE-ID"));
                    }
                } else {
                    masters += 1;
                }
                organizers.push(child.first(&Prop::Organizer).map(|entry| {
                    address_of(entry)
                        .map(|address| address.as_str().to_owned())
                        .or_else(|| entry_text(entry).map(|text| text.to_ascii_lowercase()))
                        .unwrap_or_default()
                }));
                // The limit is per instance, but the index keeps the attendees of every component of the object:
                // the distinct attendees of the object as a whole may not exceed it either.
                for entry in child.all(&Prop::Attendee) {
                    if let Some(address) = address_of(entry) {
                        attendees.insert(address);
                        if attendees.len() > max_attendees {
                            return Err(IcalError::Limit(LimitKind::Attendees));
                        }
                    }
                }
            }
            _ => {
                return Err(IcalError::object_rule(
                    "only VEVENT, VTODO and VJOURNAL components can be stored (VTIMEZONE is allowed next to them)",
                ));
            }
        }
    }
    if masters > 1 {
        return Err(IcalError::object_rule(
            "an object may hold only one component without RECURRENCE-ID",
        ));
    }
    if organizers.windows(2).any(|pair| pair.first() != pair.get(1)) {
        return Err(IcalError::organizer_mismatch(
            "the ORGANIZER differs between components",
        ));
    }
    let (Some(uid), Some(kind)) = (uid, kind) else {
        return Err(IcalError::object_rule("the object has no VEVENT, VTODO or VJOURNAL"));
    };
    let uid =
        Uid::parse(&uid).map_err(|error| IcalError::invalid(format!("the UID is not valid: {}", error.reason())))?;
    Ok((uid, kind))
}

pub(crate) fn check_timezone(node: &Node, limits: &IcalLimits) -> Result<(), IcalError> {
    let observances = node
        .children
        .iter()
        .filter(|child| matches!(child.kind, Kind::Standard | Kind::Daylight))
        .count();
    if observances > usize::try_from(limits.max_observances).unwrap_or(usize::MAX) {
        return Err(IcalError::Limit(LimitKind::Observances));
    }
    Ok(())
}

fn at_most_once(node: &Node, property: &Prop) -> Result<(), IcalError> {
    if node.all(property).take(2).count() > 1 {
        return Err(IcalError::invalid(format!(
            "{} appears more than once",
            property.as_str()
        )));
    }
    Ok(())
}

/// The date bounds as wall-clock values.
fn bounds(limits: &IcalLimits) -> (Option<NaiveDateTime>, Option<NaiveDateTime>) {
    (
        limits.min_date_time().map(|at| at.naive_utc()),
        limits.max_date_time().map(|at| at.naive_utc()),
    )
}

fn check_range(moment: &Moment, limits: &IcalLimits) -> Result<(), IcalError> {
    let (min, max) = bounds(limits);
    let local = moment.local();
    if min.is_some_and(|min| local < min) {
        return Err(IcalError::Limit(LimitKind::MinDateTime));
    }
    if max.is_some_and(|max| local > max) {
        return Err(IcalError::Limit(LimitKind::MaxDateTime));
    }
    Ok(())
}

fn moment_of(node: &Node, property: &Prop, limits: &IcalLimits) -> Result<Option<Moment>, IcalError> {
    let Some(entry) = node.first(property) else {
        return Ok(None);
    };
    let moment = entry_moment(entry)
        .ok_or_else(|| IcalError::invalid(format!("{} is not a valid date or date-time", property.as_str())))?;
    check_range(&moment, limits)?;
    Ok(Some(moment))
}

/// Checks one `VEVENT`, `VTODO` or `VJOURNAL`: the properties that may appear once, the dates, the recurrence rule
/// and the per-component limits. Returns the UID. Messages (`itip::parse_message`) are held to the same rules as
/// stored objects.
pub(crate) fn check_component(node: &Node, zones: &Zones, limits: &IcalLimits) -> Result<String, IcalError> {
    for property in [
        Prop::Uid,
        Prop::Dtstart,
        Prop::Dtend,
        Prop::Due,
        Prop::Duration,
        Prop::RecurrenceId,
        Prop::Rrule,
        Prop::Organizer,
        Prop::Sequence,
    ] {
        at_most_once(node, &property)?;
    }
    let uid = node.uid().ok_or_else(|| IcalError::invalid("a component has no UID"))?;
    let start = moment_of(node, &Prop::Dtstart, limits)?;
    let end = moment_of(node, &Prop::Dtend, limits)?;
    let due = moment_of(node, &Prop::Due, limits)?;
    moment_of(node, &Prop::RecurrenceId, limits)?;
    if node.has(&Prop::Duration) {
        let duration = node
            .first(&Prop::Duration)
            .and_then(entry_duration)
            .ok_or_else(|| IcalError::invalid("DURATION is not a valid duration"))?;
        if duration.neg {
            return Err(IcalError::invalid("DURATION must not be negative"));
        }
        if end.is_some() || due.is_some() {
            return Err(IcalError::invalid("DURATION cannot be combined with DTEND or DUE"));
        }
    }
    check_order(zones, start.as_ref(), end.as_ref(), "DTEND is before DTSTART")?;
    check_order(zones, start.as_ref(), due.as_ref(), "DUE is before DTSTART")?;
    check_sequence(node)?;
    check_recurrence(node, start.as_ref().or(due.as_ref()), limits)?;
    check_sizes(node, limits)?;
    Ok(uid)
}

fn check_order(zones: &Zones, start: Option<&Moment>, end: Option<&Moment>, message: &str) -> Result<(), IcalError> {
    let (Some(start), Some(end)) = (start, end) else {
        return Ok(());
    };
    if let (Some(first), Some(last)) = (zones.to_utc(start), zones.to_utc(end))
        && last < first
    {
        return Err(IcalError::invalid(message));
    }
    Ok(())
}

fn check_sequence(node: &Node) -> Result<(), IcalError> {
    let Some(entry) = node.first(&Prop::Sequence) else {
        return Ok(());
    };
    match entry.values.first() {
        Some(ICalendarValue::Integer(value)) if *value >= 0 => Ok(()),
        _ => Err(IcalError::invalid("SEQUENCE is not a valid number")),
    }
}

fn check_recurrence(node: &Node, start: Option<&Moment>, limits: &IcalLimits) -> Result<(), IcalError> {
    let mut dates = 0usize;
    for entry in node.all(&Prop::Rdate) {
        let (moments, _) = entry_moments(entry);
        let periods = entry_periods(entry);
        if moments.len().saturating_add(periods.len()) != entry.values.len() {
            return Err(IcalError::invalid(
                "RDATE has a value that is not a date, date-time or period",
            ));
        }
        for moment in moments.iter().chain(periods.iter().map(|period| &period.start)) {
            check_range(moment, limits)?;
        }
        dates = dates.saturating_add(entry.values.len());
    }
    for entry in node.all(&Prop::Exdate) {
        let (_, all_readable) = entry_moments(entry);
        if !all_readable {
            return Err(IcalError::invalid("EXDATE has a value that is not a date or date-time"));
        }
        dates = dates.saturating_add(entry.values.len());
    }
    if dates > usize::try_from(limits.max_recurrence_dates).unwrap_or(usize::MAX) {
        return Err(IcalError::Limit(LimitKind::RecurrenceDates));
    }
    let Some(entry) = node.first(&Prop::Rrule) else {
        return Ok(());
    };
    let Some(ICalendarValue::RecurrenceRule(rule)) = entry.values.first() else {
        return Err(IcalError::invalid("RRULE is not a valid recurrence rule"));
    };
    if is_sub_hourly(rule) {
        return Err(IcalError::Limit(LimitKind::SubDailyFrequency));
    }
    let Some(start) = start else {
        return Err(IcalError::invalid("RRULE needs a DTSTART"));
    };
    check_rule(rule, start.local()).map_err(|error| {
        let RuleError::Invalid(message) = error;
        IcalError::Invalid(message)
    })
}

pub(crate) fn check_sizes(node: &Node, limits: &IcalLimits) -> Result<(), IcalError> {
    let attendees = node.all(&Prop::Attendee).count();
    if attendees > usize::try_from(limits.max_attendees_per_instance).unwrap_or(usize::MAX) {
        return Err(IcalError::Limit(LimitKind::Attendees));
    }
    let alarms = node.children.iter().filter(|child| child.kind == Kind::VAlarm).count();
    if alarms > usize::try_from(limits.max_alarms).unwrap_or(usize::MAX) {
        return Err(IcalError::Limit(LimitKind::Alarms));
    }
    let max_attachment = usize::try_from(limits.max_inline_attach_bytes).unwrap_or(usize::MAX);
    for entry in node
        .entries
        .iter()
        .chain(node.children.iter().flat_map(|child| child.entries.iter()))
        .filter(|entry| entry.name == Prop::Attach)
    {
        let too_large = entry.values.iter().any(|value| match value {
            ICalendarValue::Binary(bytes) => bytes.len() > max_attachment,
            ICalendarValue::Uri(Uri::Data(data)) => data.data.len() > max_attachment,
            // Decoded binary data that happens to be valid text comes back as text.
            ICalendarValue::Uri(Uri::Location(text)) | ICalendarValue::Text(text) => text.len() > max_attachment,
            _ => false,
        });
        if too_large {
            return Err(IcalError::Limit(LimitKind::InlineAttachment));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn limits() -> IcalLimits {
        IcalLimits::default()
    }

    fn event(body: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:u1\r\n{body}END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    fn check_text(text: &str) -> Result<ValidatedObject, IcalError> {
        parse_and_validate(text.as_bytes(), &limits())
    }

    fn rejection(text: &str) -> IcalError {
        match check_text(text) {
            Err(error) => error,
            Ok(object) => panic!("expected a rejection, got {object:?}"),
        }
    }

    fn invalid(text: &str) -> String {
        match rejection(text) {
            IcalError::Invalid(message) => message,
            other => panic!("expected an invalid error, got {other:?}"),
        }
    }

    fn object_rule(text: &str) -> String {
        match rejection(text) {
            IcalError::ObjectRule(message) => message,
            other => panic!("expected a calendar object resource rule, got {other:?}"),
        }
    }

    fn organizer_mismatch(text: &str) -> String {
        match rejection(text) {
            IcalError::OrganizerMismatch(message) => message,
            other => panic!("expected an organizer mismatch, got {other:?}"),
        }
    }

    fn limit(text: &str) -> LimitKind {
        match rejection(text) {
            IcalError::Limit(kind) => kind,
            other => panic!("expected a limit error, got {other:?}"),
        }
    }

    #[test]
    fn a_simple_event_is_valid() {
        let object = check_text(&event(
            "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nSUMMARY:x\r\n",
        ))
        .unwrap();
        assert_eq!(object.uid.as_str(), "u1");
        assert_eq!(object.component, ComponentKind::Event);
    }

    #[test]
    fn debug_output_never_contains_the_content() {
        let object = check_text(&event(
            "DTSTART:20270301T100000Z\r\nSUMMARY:Salary talk\r\nATTENDEE:mailto:guest@example.org\r\n",
        ))
        .unwrap();
        let shown = format!("{object:?} {:?}", object.calendar);
        assert!(
            !shown.contains("Salary") && !shown.contains("guest@") && !shown.contains("u1"),
            "{shown}"
        );
        assert!(shown.contains("components"), "{shown}");
    }

    #[test]
    fn zero_length_events_are_accepted_but_negative_ones_are_not() {
        assert!(check_text(&event("DTSTART:20270301T100000Z\r\nDTEND:20270301T100000Z\r\n")).is_ok());
        assert!(check_text(&event("DTSTART;VALUE=DATE:20270301\r\nDTEND;VALUE=DATE:20270301\r\n")).is_ok());
        assert_eq!(
            invalid(&event("DTSTART:20270301T100000Z\r\nDTEND:20270301T090000Z\r\n")),
            "DTEND is before DTSTART"
        );
        assert!(
            invalid(&event(
                "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nDURATION:PT1H\r\n"
            ))
            .contains("DURATION")
        );
        assert!(invalid(&event("DTSTART:20270301T100000Z\r\nDURATION:-PT1H\r\n")).contains("negative"));
    }

    #[test]
    fn leniency_rules_hold() {
        // Windows TZID without a VTIMEZONE, an IANA TZID without a VTIMEZONE and LF line endings.
        let windows = event("DTSTART;TZID=W. Europe Standard Time:20270301T100000\r\n");
        assert!(check_text(&windows).is_ok());
        let iana = event("DTSTART;TZID=Europe/Berlin:20270301T100000\r\n");
        assert!(check_text(&iana).is_ok());
        assert!(check_text(&iana.replace("\r\n", "\n")).is_ok());
        // Unknown zones are accepted and read as floating.
        assert!(check_text(&event("DTSTART;TZID=Nowhere/Atlantis:20270301T100000\r\n")).is_ok());
        // Objects without a start are stored too.
        assert!(check_text(&event("SUMMARY:undated\r\n")).is_ok());
    }

    #[test]
    fn structure_rules_are_enforced() {
        assert!(
            invalid(&event("DTSTART:20270301T100000Z\r\n").replace("VERSION:2.0", "VERSION:1.0")).contains("version")
        );
        assert!(
            object_rule(&event("DTSTART:20270301T100000Z\r\n").replace("VERSION:2.0", "VERSION:2.0\r\nMETHOD:REQUEST"))
                .contains("METHOD")
        );
        let no_uid = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20270301T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(invalid(no_uid).contains("UID"));
        let empty = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n";
        assert!(object_rule(empty).contains("no VEVENT"));
        let freebusy = "BEGIN:VCALENDAR\r\nBEGIN:VFREEBUSY\r\nUID:x\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
        assert!(object_rule(freebusy).contains("VEVENT, VTODO and VJOURNAL"));
    }

    #[test]
    fn calendar_object_resource_rules_have_their_own_error() {
        let mixed = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u\r\nEND:VEVENT\r\nBEGIN:VTODO\r\nUID:u\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        assert!(object_rule(mixed).contains("only one component type"));
        let uids = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:b\r\nRECURRENCE-ID:20270301T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(object_rule(uids).contains("different UIDs"));
        let two_masters = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:a\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(object_rule(two_masters).contains("without RECURRENCE-ID"));
        let duplicate = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID:20270301T100000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID:20270301T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(object_rule(duplicate).contains("same RECURRENCE-ID"));
        // The same instant written in two zones is the same RECURRENCE-ID.
        let zones = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID:20270301T090000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID;TZID=Europe/Berlin:20270301T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(object_rule(zones).contains("same RECURRENCE-ID"));
        // Each of them answers CALDAV:valid-calendar-object-resource when stored.
        for text in [mixed, uids, two_masters, duplicate, zones] {
            assert_eq!(
                rejection(text).precondition().map(|precondition| precondition.code()),
                Some("valid-calendar-object-resource")
            );
        }
    }

    #[test]
    fn differing_organizers_have_their_own_error() {
        let organizers = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nORGANIZER:mailto:a@example.org\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID:20270301T100000Z\r\nORGANIZER:mailto:b@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(organizer_mismatch(organizers).contains("ORGANIZER"));
        assert_eq!(
            rejection(organizers)
                .precondition()
                .map(|precondition| precondition.code()),
            Some("same-organizer-in-all-components")
        );
        // Spelling the same address differently is not a mismatch.
        let same = organizers.replace("mailto:b@example.org", "MAILTO:A@Example.org");
        assert!(check_text(&same).is_ok());
    }

    #[test]
    fn data_errors_stay_valid_calendar_data() {
        let cases = [
            event("DTSTART:garbage\r\n"),
            event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=WEEKLY;BYMONTHDAY=1\r\n"),
            event("DTSTART:20270301T100000Z\r\nDTEND:20270301T090000Z\r\n"),
        ];
        for text in cases {
            assert_eq!(
                rejection(&text).precondition().map(|precondition| precondition.code()),
                Some("valid-calendar-data"),
                "{text}"
            );
        }
    }

    #[test]
    fn an_object_with_only_an_override_is_valid() {
        let only = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID:20270301T100000Z\r\nDTSTART:20270301T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(check_text(only).is_ok());
    }

    #[test]
    fn unreadable_values_are_rejected() {
        assert!(invalid(&event("DTSTART:garbage\r\n")).contains("DTSTART"));
        assert!(invalid(&event("DTSTART:20270301T100000Z\r\nDTEND:nonsense\r\n")).contains("DTEND"));
        assert!(invalid(&event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=SOMETIMES\r\n")).contains("RRULE"));
        assert!(invalid(&event("DTSTART:20270301T100000Z\r\nSEQUENCE:abc\r\n")).contains("SEQUENCE"));
        assert!(invalid(&event("DTSTART:20270301T100000Z\r\nEXDATE:nonsense\r\n")).contains("EXDATE"));
        assert!(invalid(&event("DTSTART:20270301T100000Z\r\nRDATE:nonsense\r\n")).contains("RDATE"));
        assert!(invalid(&event("DTSTART:20270301T100000Z\r\nDTSTART:20270302T100000Z\r\n")).contains("more than once"));
        assert!(invalid(&event("RRULE:FREQ=DAILY\r\n")).contains("DTSTART"));
    }

    #[test]
    fn recurrence_rules_are_checked_against_the_rfc() {
        assert!(
            check_text(&event(
                "DTSTART:20270301T100000Z\r\nRRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=10\r\n"
            ))
            .is_ok()
        );
        assert!(
            invalid(&event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=WEEKLY;BYMONTHDAY=1\r\n")).contains("BYMONTHDAY")
        );
        assert_eq!(
            limit(&event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=SECONDLY\r\n")),
            LimitKind::SubDailyFrequency
        );
        assert_eq!(
            limit(&event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=MINUTELY;COUNT=3\r\n")),
            LimitKind::SubDailyFrequency
        );
        assert!(check_text(&event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=HOURLY;COUNT=3\r\n")).is_ok());
    }

    #[test]
    fn the_date_range_is_enforced() {
        assert_eq!(limit(&event("DTSTART:18991231T100000Z\r\n")), LimitKind::MinDateTime);
        assert_eq!(limit(&event("DTSTART:21000101T000001Z\r\n")), LimitKind::MaxDateTime);
        assert!(check_text(&event("DTSTART:19000101T000000Z\r\n")).is_ok());
        assert!(check_text(&event("DTSTART:21000101T000000Z\r\n")).is_ok());
        assert_eq!(
            limit(&event("DTSTART:20270301T100000Z\r\nRDATE:21500101T000000Z\r\n")),
            LimitKind::MaxDateTime
        );
        // Time zone definitions may start in the year 1601.
        let outlook = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Custom\r\nBEGIN:STANDARD\r\nDTSTART:16010101T000000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
            BEGIN:VEVENT\r\nUID:u\r\nDTSTART;TZID=Custom:20270301T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(check_text(outlook).is_ok());
    }

    #[test]
    fn counts_are_limited() {
        let attendees = "ATTENDEE:mailto:guest@example.org\r\n".repeat(201);
        assert_eq!(
            limit(&event(&format!("DTSTART:20270301T100000Z\r\n{attendees}"))),
            LimitKind::Attendees
        );
        let alarm = "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\n";
        assert_eq!(limit(&event(&alarm.repeat(11))), LimitKind::Alarms);
        assert!(check_text(&event(&alarm.repeat(10))).is_ok());
        let dates = (0..1001)
            .map(|n| format!("2027{:02}{:02}T100000Z", n % 12 + 1, n % 28 + 1))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            limit(&event(&format!("DTSTART:20270301T100000Z\r\nRDATE:{dates}\r\n"))),
            LimitKind::RecurrenceDates
        );
        let observance =
            "BEGIN:STANDARD\r\nDTSTART:19700101T000000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\n";
        let observances = observance.repeat(201);
        let zone = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Many\r\n{observances}END:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:u\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        assert_eq!(limit(&zone), LimitKind::Observances);
    }

    /// An object whose overrides each name `per_override` attendees; with `shared` they are the same people in
    /// every override, otherwise every override has its own.
    fn overrides_with_attendees(overrides: usize, per_override: usize, shared: bool) -> String {
        let mut text = String::from(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:many\r\nDTSTART:20270301T100000Z\r\nRRULE:FREQ=DAILY\r\nEND:VEVENT\r\n",
        );
        for n in 0..overrides {
            let _ = write!(
                text,
                "BEGIN:VEVENT\r\nUID:many\r\nRECURRENCE-ID:2027{:02}{:02}T100000Z\r\nDTSTART:2027{:02}{:02}T120000Z\r\n",
                n % 12 + 1,
                n / 12 + 1,
                n % 12 + 1,
                n / 12 + 1,
            );
            for guest in 0..per_override {
                let owner = if shared { 0 } else { n };
                let _ = write!(text, "ATTENDEE:mailto:g{owner}-{guest}@example.org\r\n");
            }
            text.push_str("END:VEVENT\r\n");
        }
        text.push_str("END:VCALENDAR\r\n");
        text
    }

    #[test]
    fn the_attendees_of_all_components_together_are_limited() {
        // Every component is within the per-instance limit, the object as a whole is not: the index would keep
        // the union.
        let different = overrides_with_attendees(20, 200, false);
        assert_eq!(limit(&different), LimitKind::Attendees);
        // The same people in every override are one set of attendees.
        let shared = overrides_with_attendees(20, 200, true);
        assert!(check_text(&shared).is_ok());
    }

    #[test]
    fn time_zone_limits_hold_before_anything_is_evaluated() {
        // The event comes first and uses the zone that has too many observances.
        let observance = "BEGIN:STANDARD\r\nDTSTART:19700101T000000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0100\r\nRRULE:FREQ=YEARLY\r\nEND:STANDARD\r\n";
        let text = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u\r\nDTSTART;TZID=Many:20270301T100000\r\nDTEND;TZID=Many:20270301T110000\r\nEND:VEVENT\r\n\
             BEGIN:VTIMEZONE\r\nTZID:Many\r\n{}END:VTIMEZONE\r\nEND:VCALENDAR\r\n",
            observance.repeat(201)
        );
        assert_eq!(limit(&text), LimitKind::Observances);
    }

    #[test]
    fn a_zone_whose_rules_run_away_is_refused_when_it_is_used() {
        let observance = "BEGIN:STANDARD\r\nDTSTART:16010101T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
            RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\n";
        let used = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Ancient\r\n{}END:VTIMEZONE\r\n\
             BEGIN:VEVENT\r\nUID:u\r\nDTSTART;TZID=Ancient:20270301T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            observance.repeat(50)
        );
        assert_eq!(limit(&used), LimitKind::Observances);
        let unused = used.replace("DTSTART;TZID=Ancient:", "DTSTART:");
        assert!(check_text(&unused).is_ok(), "an unused definition is never evaluated");
    }

    #[test]
    fn inline_attachments_are_limited() {
        let big = "A".repeat(400_000);
        let text = event(&format!(
            "DTSTART:20270301T100000Z\r\nATTACH;ENCODING=BASE64;VALUE=BINARY:{big}\r\n"
        ));
        let wide = IcalLimits {
            max_resource_size: 2_000_000,
            ..IcalLimits::default()
        };
        assert_eq!(
            parse_and_validate(text.as_bytes(), &wide),
            Err(IcalError::Limit(LimitKind::InlineAttachment))
        );
    }

    #[test]
    fn the_attachment_limit_counts_decoded_bytes_whatever_form_the_data_takes() {
        let small = IcalLimits {
            max_inline_attach_bytes: 300,
            ..IcalLimits::default()
        };
        let attached = |line: String| {
            parse_and_validate(
                event(&format!("DTSTART:20270301T100000Z\r\n{line}\r\n")).as_bytes(),
                &small,
            )
        };
        // "QUFB" is the base64 form of "AAA": binary data that decodes to text.
        let binary = |groups: usize| attached(format!("ATTACH;ENCODING=BASE64;VALUE=BINARY:{}", "QUFB".repeat(groups)));
        assert!(binary(100).is_ok(), "300 decoded bytes are within the limit");
        assert_eq!(
            binary(101).map(|_| ()),
            Err(IcalError::Limit(LimitKind::InlineAttachment))
        );
        // A data: URI (RFC 2397) is inline data too and cannot be used to get around the limit.
        let data_uri = |groups: usize| attached(format!("ATTACH:data:text/plain;base64,{}", "QUFB".repeat(groups)));
        assert!(data_uri(10).is_ok());
        assert_eq!(
            data_uri(101).map(|_| ()),
            Err(IcalError::Limit(LimitKind::InlineAttachment))
        );
    }
}
