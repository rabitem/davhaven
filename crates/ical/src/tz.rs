//! Timezone resolution: IANA names, `VTIMEZONE` matching and the embedded Windows zone table.
//!
//! Outlook and CalDAV Synchronizer send Windows zone names (`W. Europe Standard Time`) and some clients send
//! `VTIMEZONE` components with custom `TZID`s. This module maps them to IANA zones (using the CLDR Windows zone
//! table embedded in the crate) and renders `VTIMEZONE` components for iTIP messages and feeds, which must
//! carry one for every `TZID` they use.

use std::collections::BTreeSet;
use std::str::FromStr;

use calcard::common::timezone::Tz as CalendarTz;
use calcard::icalendar::{ICalendar, ICalendarComponent, ICalendarComponentType};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use davhaven_domain::{IcalLimits, TimeZoneName};

use crate::calendar::{
    Kind, Moment, Node, Param, Prop, contain, entry_moment, entry_moments, entry_periods, text_entry, zone_name,
};
use crate::error::{IcalError, LimitKind};
use crate::zones::{Zone, ZoneError};

/// The longest span a rendered `VTIMEZONE` may cover, in seconds (250 years).
const MAX_RENDER_SPAN: i64 = 250 * 366 * 86_400;

/// Maps a Windows time zone name to the IANA zone of its default territory.
///
/// Returns `Ok(None)` for names that are not in the table.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable should the table ever need to be loaded.
pub fn windows_to_iana(name: &str) -> Result<Option<TimeZoneName>, IcalError> {
    Ok(crate::windows::lookup(name).and_then(|iana| TimeZoneName::parse(iana).ok()))
}

/// Resolves a `TZID` as clients write it to an IANA zone: IANA names (also with the `/mozilla.org/` and
/// `/freeassociation.sourceforge.net/` prefixes some clients add), Windows names and common aliases.
///
/// Returns `Ok(None)` when the identifier is unknown; the caller then falls back to the `VTIMEZONE` that came
/// with the data or treats the value as floating.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn resolve_tzid(tzid: &str) -> Result<Option<TimeZoneName>, IcalError> {
    Ok(resolve(tzid))
}

fn resolve(tzid: &str) -> Option<TimeZoneName> {
    let tzid = tzid.trim();
    if tzid.is_empty() || tzid.len() > 256 {
        return None;
    }
    if let Some(zone) = iana(tzid) {
        return Some(zone);
    }
    if let Some(path) = tzid.strip_prefix('/') {
        // Registry style identifiers: /mozilla.org/20050126_1/Europe/Berlin, /softwarestudio.org/Olson_x/...
        let segments: Vec<&str> = path.split('/').collect();
        for start in 0..segments.len() {
            let candidate = segments.get(start..).map(|rest| rest.join("/"))?;
            if let Some(zone) = iana(&candidate) {
                return Some(zone);
            }
        }
    }
    if let Some(mapped) = crate::windows::lookup(tzid) {
        return TimeZoneName::parse(mapped).ok();
    }
    if !tzid.to_ascii_lowercase().ends_with("standard time")
        && let Some(mapped) = crate::windows::lookup(&format!("{tzid} Standard Time"))
    {
        return TimeZoneName::parse(mapped).ok();
    }
    // Display names such as "(UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna" and older aliases.
    match CalendarTz::from_str(tzid) {
        Ok(CalendarTz::Tz(zone)) => zone_name(zone),
        _ => None,
    }
}

/// An IANA name, matched exactly and then ignoring ASCII case.
fn iana(text: &str) -> Option<TimeZoneName> {
    if let Ok(zone) = TimeZoneName::parse(text) {
        return Some(zone);
    }
    chrono_tz::TZ_VARIANTS
        .iter()
        .find(|zone| zone.name().eq_ignore_ascii_case(text))
        .copied()
        .and_then(zone_name)
}

/// Reads the value of the `CALDAV:calendar-timezone` property (RFC 4791 section 5.2.2): an iCalendar object that
/// holds exactly one `VTIMEZONE` and nothing else, and returns the zone it stands for. Floating times and all-day
/// dates of the calendar are read in that zone (RFC 4791 section 9.9), which is what the `_in_zone` functions of
/// this crate take.
///
/// The zone is found the way [`resolve_tzid`] and the evaluation of stored objects find it: the `TZID` as an IANA
/// or Windows name, then the location hints of the definition (`X-LIC-LOCATION`, `X-MICROSOFT-CDO-TZID`). A
/// definition that is none of these (a custom zone made of observances only) cannot be named and is refused;
/// the client can send the IANA name as `TZID` instead.
///
/// The text is held to the gate of [`crate::parse::accept`]: the value is stored as the client sent it, and the
/// server may write it again.
///
/// # Errors
///
/// * [`IcalError::Invalid`] when the text is not an iCalendar object with exactly one `VTIMEZONE`, has another
///   component, has no `TZID`, or names a zone the server does not know,
/// * [`IcalError::Limit`] for exceeded limits (the size of the text, the observances of the definition).
pub fn calendar_timezone(ics: &str, limits: &IcalLimits) -> Result<TimeZoneName, IcalError> {
    let calendar = crate::parse::accept(ics.as_bytes(), limits)?;
    let root = &calendar.root;
    if root.children.iter().any(|child| child.kind != Kind::VTimezone) {
        return Err(IcalError::invalid(
            "the time zone value may hold nothing but its VTIMEZONE",
        ));
    }
    let mut definitions = root.children.iter();
    let (Some(definition), None) = (definitions.next(), definitions.next()) else {
        return Err(IcalError::invalid(
            "the time zone value must hold exactly one VTIMEZONE",
        ));
    };
    crate::validate::check_timezone(definition, limits)?;
    let tzid = definition
        .text(&Prop::Tzid)
        .ok_or_else(|| IcalError::invalid("the VTIMEZONE has no TZID"))?;
    match crate::zones::resolve_zone(&tzid, Some(definition)) {
        Ok(Some(Zone::Iana(zone))) => {
            zone_name(zone).ok_or_else(|| IcalError::invalid("the time zone is not one the server knows"))
        }
        Ok(Some(Zone::Custom(_)) | None) => Err(IcalError::invalid(
            "the time zone is not one the server knows; use the name of an IANA time zone as its TZID",
        )),
        Err(ZoneError::TooComplex) => Err(IcalError::Limit(LimitKind::Observances)),
    }
}

/// Renders a `VTIMEZONE` component for `zone` with the observances needed between `from` and `until`.
///
/// The text uses `CRLF` line endings and ends with the line break after `END:VTIMEZONE`.
///
/// # Errors
///
/// [`IcalError::Invalid`] when `until` is not after `from` or the span exceeds 250 years.
pub fn render_vtimezone(zone: TimeZoneName, from: DateTime<Utc>, until: DateTime<Utc>) -> Result<String, IcalError> {
    let node = vtimezone_node(zone.as_str(), from, until)?;
    Ok(node.to_calendar().to_string())
}

/// The `VTIMEZONE` component of `tzid` (a name this crate resolves) with observances for the given span.
pub(crate) fn vtimezone_node(tzid: &str, from: DateTime<Utc>, until: DateTime<Utc>) -> Result<Node, IcalError> {
    let span = until.timestamp().saturating_sub(from.timestamp());
    if span <= 0 {
        return Err(IcalError::invalid(
            "the end of the time zone span is not after its start",
        ));
    }
    if span > MAX_RENDER_SPAN {
        return Err(IcalError::invalid("the time zone span is too long"));
    }
    let zone = resolve(tzid).ok_or_else(|| IcalError::invalid("the time zone is unknown"))?;
    let mut calendar = ICalendar {
        components: vec![ICalendarComponent::new(ICalendarComponentType::VCalendar)],
    };
    let id = contain(|| calendar.add_timezone(zone.as_str(), from.timestamp(), until.timestamp()))
        .ok_or_else(|| IcalError::invalid("the time zone cannot be rendered"))?
        .ok_or_else(|| IcalError::invalid("the time zone cannot be rendered"))?;
    let root = Node::from_calendar(&calendar).ok_or_else(|| IcalError::invalid("the time zone cannot be rendered"))?;
    let _ = id;
    let mut vtimezone = root
        .children
        .into_iter()
        .find(|child| child.kind == Kind::VTimezone)
        .ok_or_else(|| IcalError::invalid("the time zone cannot be rendered"))?;
    if tzid != zone.as_str() {
        vtimezone.set(text_entry(Prop::Tzid, tzid));
    }
    Ok(vtimezone)
}

/// Adds a `VTIMEZONE` for every `TZID` the object uses that it does not define, so that the object is
/// self-contained (iTIP messages, feeds). Identifiers that do not resolve are left alone.
///
/// The observances cover the years of the object's values from one year before to two years after.
pub(crate) fn ensure_vtimezones(root: &mut Node) {
    let mut defined: BTreeSet<String> = root
        .children
        .iter()
        .filter(|child| child.kind == Kind::VTimezone)
        .filter_map(|child| child.text(&Prop::Tzid))
        .collect();
    let mut used = BTreeSet::new();
    let mut years: Vec<i32> = Vec::new();
    for child in root.children.iter().filter(|child| child.kind != Kind::VTimezone) {
        collect_used(child, &mut used, &mut years);
    }
    let (Some(first), Some(last)) = (years.iter().min().copied(), years.iter().max().copied()) else {
        return;
    };
    let from =
        NaiveDate::from_ymd_opt(first.saturating_sub(1).max(1900), 1, 1).and_then(|date| date.and_hms_opt(0, 0, 0));
    let until =
        NaiveDate::from_ymd_opt(last.saturating_add(2).min(2200), 1, 1).and_then(|date| date.and_hms_opt(0, 0, 0));
    let (Some(from), Some(until)) = (from, until) else {
        return;
    };
    let mut added = Vec::new();
    for tzid in used {
        if defined.contains(&tzid) {
            continue;
        }
        if let Ok(node) = vtimezone_node(&tzid, from.and_utc(), until.and_utc()) {
            defined.insert(tzid);
            added.push(node);
        }
    }
    let position = root
        .children
        .iter()
        .position(|child| child.kind != Kind::VTimezone)
        .unwrap_or(root.children.len());
    for (offset, node) in added.into_iter().enumerate() {
        root.children.insert(position.saturating_add(offset), node);
    }
}

fn collect_used(node: &Node, used: &mut BTreeSet<String>, years: &mut Vec<i32>) {
    for entry in &node.entries {
        if let Some(tzid) = crate::calendar::param_text(entry, &Param::Tzid) {
            used.insert(tzid);
        }
        let moments: Vec<Moment> = match entry.name {
            Prop::Dtstart | Prop::Dtend | Prop::Due | Prop::RecurrenceId | Prop::Completed => {
                entry_moment(entry).into_iter().collect()
            }
            Prop::Exdate => entry_moments(entry).0,
            Prop::Rdate => {
                let mut all = entry_moments(entry).0;
                all.extend(entry_periods(entry).into_iter().map(|period| period.start));
                all
            }
            _ => Vec::new(),
        };
        years.extend(moments.iter().map(|moment| moment.date().year()));
    }
    for child in &node.children {
        collect_used(child, used, years);
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::zones::{Zone, Zones};

    fn zone(name: &str) -> TimeZoneName {
        TimeZoneName::parse(name).unwrap()
    }

    fn year(year: i32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn windows_names_map_to_their_default_zone() {
        assert_eq!(
            windows_to_iana("W. Europe Standard Time").unwrap(),
            Some(zone("Europe/Berlin"))
        );
        assert_eq!(
            windows_to_iana("Eastern Standard Time").unwrap(),
            Some(zone("America/New_York"))
        );
        assert_eq!(windows_to_iana("Not A Zone").unwrap(), None);
        assert_eq!(windows_to_iana("").unwrap(), None);
    }

    #[test]
    fn tzids_resolve_the_way_clients_write_them() {
        let cases = [
            ("Europe/Berlin", Some("Europe/Berlin")),
            ("europe/berlin", Some("Europe/Berlin")),
            (" Europe/Berlin ", Some("Europe/Berlin")),
            ("/mozilla.org/20050126_1/Europe/Berlin", Some("Europe/Berlin")),
            (
                "/freeassociation.sourceforge.net/Tzfile/Europe/Berlin",
                Some("Europe/Berlin"),
            ),
            (
                "/softwarestudio.org/Olson_20011030_5/America/Chicago",
                Some("America/Chicago"),
            ),
            (
                "/softwarestudio.org/Olson_20011030_5/America/Argentina/Buenos_Aires",
                Some("America/Argentina/Buenos_Aires"),
            ),
            ("W. Europe Standard Time", Some("Europe/Berlin")),
            ("w. europe standard time", Some("Europe/Berlin")),
            ("W. Europe", Some("Europe/Berlin")),
            ("Romance Standard Time", Some("Europe/Paris")),
            ("(UTC-08:00) Pacific Time (US & Canada)", Some("America/Los_Angeles")),
            ("UTC", Some("UTC")),
            ("Customized Time Zone", None),
            ("Nowhere/Atlantis", None),
            ("", None),
        ];
        for (input, expected) in cases {
            let resolved = resolve_tzid(input).unwrap().map(|name| name.to_string());
            assert_eq!(resolved.as_deref(), expected, "{input}");
        }
        assert_eq!(resolve_tzid(&"x".repeat(1000)).unwrap(), None);
    }

    #[test]
    fn rendered_zones_carry_the_observances_of_the_span() {
        let text = render_vtimezone(zone("Europe/Berlin"), year(2027), year(2029)).unwrap();
        assert!(text.starts_with("BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n"), "{text}");
        assert!(text.ends_with("END:VTIMEZONE\r\n"), "{text}");
        assert!(text.contains("TZOFFSETFROM:+0100"), "{text}");
        assert!(text.contains("TZOFFSETTO:+0200"), "{text}");
        assert!(
            text.contains("BEGIN:DAYLIGHT") && text.contains("BEGIN:STANDARD"),
            "{text}"
        );
    }

    #[test]
    fn invalid_spans_are_rejected() {
        assert!(matches!(
            render_vtimezone(zone("Europe/Berlin"), year(2029), year(2027)),
            Err(IcalError::Invalid(_))
        ));
        assert!(matches!(
            render_vtimezone(zone("Europe/Berlin"), year(2027), year(2027)),
            Err(IcalError::Invalid(_))
        ));
        assert!(matches!(
            render_vtimezone(zone("Europe/Berlin"), year(1700), year(2100)),
            Err(IcalError::Invalid(_))
        ));
    }

    #[test]
    fn missing_definitions_are_added_for_every_zone_in_use() {
        use calcard::{Entry, Parser};
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\n\
            DTSTART;TZID=W. Europe Standard Time:20270301T100000\r\nDTEND;TZID=America/New_York:20270301T110000\r\n\
            END:VEVENT\r\nEND:VCALENDAR\r\n";
        let mut parser = Parser::new(text);
        let Entry::ICalendar(calendar) = parser.entry() else {
            panic!("not a calendar");
        };
        let mut root = Node::from_calendar(&calendar).unwrap();
        ensure_vtimezones(&mut root);
        let ids: Vec<String> = root
            .children
            .iter()
            .filter(|child| child.kind == Kind::VTimezone)
            .filter_map(|child| child.text(&Prop::Tzid))
            .collect();
        assert_eq!(ids, ["America/New_York", "W. Europe Standard Time"]);
        assert_eq!(root.children.last().unwrap().kind, Kind::VEvent);
        let before = root.clone();
        ensure_vtimezones(&mut root);
        assert_eq!(root, before, "a second run adds nothing");
        assert!(
            Zones::for_tree(&root, Zone::utc())
                .zone("W. Europe Standard Time")
                .is_some()
        );
    }

    fn zone_value(definitions: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\n{definitions}END:VCALENDAR\r\n")
    }

    const BERLIN_ISH: &str = "BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
        RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\n\
        BEGIN:DAYLIGHT\r\nDTSTART:19700329T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\n\
        RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\nEND:DAYLIGHT\r\n";

    #[test]
    fn the_calendar_time_zone_is_the_zone_of_its_definition() {
        let limits = IcalLimits::default();
        let iana = zone_value(&format!(
            "BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n{BERLIN_ISH}END:VTIMEZONE\r\n"
        ));
        assert_eq!(calendar_timezone(&iana, &limits).unwrap(), zone("Europe/Berlin"));
        // Outlook and CalDav Synchronizer send a Windows name, with or without observances.
        let windows = zone_value(&format!(
            "BEGIN:VTIMEZONE\r\nTZID:W. Europe Standard Time\r\n{BERLIN_ISH}END:VTIMEZONE\r\n"
        ));
        assert_eq!(calendar_timezone(&windows, &limits).unwrap(), zone("Europe/Berlin"));
        // A custom name is found through the location hints of the definition.
        let hinted = zone_value(&format!(
            "BEGIN:VTIMEZONE\r\nTZID:Office\r\nX-LIC-LOCATION:America/Chicago\r\n{BERLIN_ISH}END:VTIMEZONE\r\n"
        ));
        assert_eq!(calendar_timezone(&hinted, &limits).unwrap(), zone("America/Chicago"));
    }

    #[test]
    fn a_calendar_time_zone_must_be_one_definition_the_server_can_name() {
        let limits = IcalLimits::default();
        let message = |text: &str| match calendar_timezone(text, &limits) {
            Err(IcalError::Invalid(message)) => message,
            other => panic!("expected a rejection, got {other:?}"),
        };
        let one = format!("BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n{BERLIN_ISH}END:VTIMEZONE\r\n");
        let two = zone_value(&format!(
            "{one}BEGIN:VTIMEZONE\r\nTZID:Europe/Paris\r\n{BERLIN_ISH}END:VTIMEZONE\r\n"
        ));
        assert!(message(&two).contains("exactly one"));
        assert!(message(&zone_value("")).contains("exactly one"));
        let event = zone_value(&format!("{one}BEGIN:VEVENT\r\nUID:x\r\nEND:VEVENT\r\n"));
        assert!(message(&event).contains("nothing but"));
        let unnamed = zone_value(&format!("BEGIN:VTIMEZONE\r\n{BERLIN_ISH}END:VTIMEZONE\r\n"));
        assert!(message(&unnamed).contains("TZID"));
        // A definition made of observances alone cannot be named.
        let custom = zone_value(&format!(
            "BEGIN:VTIMEZONE\r\nTZID:Custom\r\n{BERLIN_ISH}END:VTIMEZONE\r\n"
        ));
        assert!(message(&custom).contains("IANA"));
        assert!(message("BEGIN:VEVENT\r\nEND:VEVENT\r\n").contains("iCalendar"));
    }

    #[test]
    fn the_limits_hold_for_a_calendar_time_zone() {
        let observance =
            "BEGIN:STANDARD\r\nDTSTART:19700101T000000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\n";
        let many = zone_value(&format!(
            "BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n{}END:VTIMEZONE\r\n",
            observance.repeat(201)
        ));
        assert_eq!(
            calendar_timezone(&many, &IcalLimits::default()),
            Err(IcalError::Limit(LimitKind::Observances))
        );
        let tight = IcalLimits {
            max_resource_size: 100,
            ..IcalLimits::default()
        };
        assert_eq!(
            calendar_timezone(&many, &tight),
            Err(IcalError::Limit(LimitKind::ResourceSize))
        );
        // Within the count of observances, but rules that would have to run for four centuries.
        let ancient = "BEGIN:STANDARD\r\nDTSTART:16010101T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
            RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\n";
        let runaway = zone_value(&format!(
            "BEGIN:VTIMEZONE\r\nTZID:Ancient\r\n{}END:VTIMEZONE\r\n",
            ancient.repeat(50)
        ));
        assert_eq!(
            calendar_timezone(&runaway, &IcalLimits::default()),
            Err(IcalError::Limit(LimitKind::Observances))
        );
    }
}
