//! Time zones for one calendar object: IANA zones, `VTIMEZONE` definitions and the mapping between wall-clock
//! time and instants.
//!
//! A `TZID` is resolved in this order (the order `CalConnect` recommends for interoperability):
//!
//! 1. the IANA name, a Windows zone name or a common alias ([`crate::tz::resolve_tzid`]),
//! 2. the location hints of a `VTIMEZONE` with that `TZID` (`X-LIC-LOCATION`, `X-MICROSOFT-CDO-TZID`),
//! 3. the observances of that `VTIMEZONE` itself,
//!
//! and values whose `TZID` stays unknown are treated as floating. Wall-clock times map to instants the way
//! RFC 5545 section 3.3.5 prescribes: a time that occurs twice (the clock goes back) is the first occurrence,
//! a time that does not occur (the clock jumps forward) is interpreted with the offset before the jump.
//!
//! Zones are resolved on first use and only for the `TZID`s the object refers to: a document may carry hundreds
//! of definitions that nothing uses, and evaluating the observance rules of a custom zone is the expensive part.
//! The work is bounded: a `VTIMEZONE` may have at most [`MAX_OBSERVANCES_EVALUATED`] observances and its rules
//! may produce at most [`MAX_ONSETS_PER_ZONE`] transitions together; a zone beyond that is [`ZoneError::TooComplex`]
//! (unusable, so its values read as floating) and the validation of stored objects refuses it.

use std::cell::OnceCell;
use std::collections::{BTreeSet, HashMap};

use calcard::common::timezone::Tz as CalendarTz;
use calcard::icalendar::{ICalendarFrequency, ICalendarProperty, ICalendarValue};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Offset, TimeDelta, TimeZone, Utc};
use chrono_tz::Tz;
use davhaven_domain::TimeZoneName;

use crate::calendar::{Kind, Moment, Node, Param, Prop, entry_moment, entry_moments};
use crate::error::{IcalError, LimitKind};
use crate::recur::{rule_locals, rule_until_local};

/// Seconds in a day, the window in which local times are searched for their offset.
const DAY: i64 = 86_400;
/// The most onsets generated for one observance rule: a yearly rule that starts in 1601 (as Outlook writes
/// them) needs 500 to reach 2101.
const MAX_ONSETS_PER_RULE: usize = 600;
/// The most onsets all observances of one `VTIMEZONE` may generate together.
pub(crate) const MAX_ONSETS_PER_ZONE: usize = 20_000;
/// The most observances of one `VTIMEZONE` that are evaluated, whatever the configured limit says.
pub(crate) const MAX_OBSERVANCES_EVALUATED: usize = 1_000;
/// The wall-clock end of generated observance rules.
const OBSERVANCE_HORIZON_YEAR: i32 = 2101;

/// Why a `VTIMEZONE` cannot be evaluated although it is well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZoneError {
    /// The definition has more observances or its rules produce more transitions than the evaluation allows.
    TooComplex,
}

/// A `VTIMEZONE` evaluated from its observances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CustomZone {
    /// The offset before the first transition, in seconds east of UTC.
    initial: i32,
    /// Transitions as (instant in UTC seconds, offset afterwards), ascending.
    transitions: Vec<(i64, i32)>,
}

/// The parts of an observance that matter: the first onset and the offsets before and after it.
fn observance_parts(observance: &Node) -> Option<(NaiveDateTime, i32, i32)> {
    let start = observance.first(&Prop::Dtstart).and_then(entry_moment)?.local();
    let from = offset_of(observance.first(&Prop::Tzoffsetfrom)?.values.first()?)?;
    let to = offset_of(observance.first(&Prop::Tzoffsetto)?.values.first()?)?;
    Some((start, from, to))
}

impl CustomZone {
    fn offset_at(&self, utc: i64) -> i32 {
        let index = self.transitions.partition_point(|(at, _)| *at <= utc);
        index
            .checked_sub(1)
            .and_then(|index| self.transitions.get(index))
            .map_or(self.initial, |(_, offset)| *offset)
    }

    /// Evaluates a `VTIMEZONE` component; `Ok(None)` when it has no usable observance.
    fn from_vtimezone(node: &Node) -> Result<Option<Self>, ZoneError> {
        let observances: Vec<&Node> = node
            .children
            .iter()
            .filter(|child| matches!(child.kind, Kind::Standard | Kind::Daylight))
            .collect();
        if observances.len() > MAX_OBSERVANCES_EVALUATED {
            return Err(ZoneError::TooComplex);
        }
        let mut onsets_left = MAX_ONSETS_PER_ZONE;
        let mut transitions: Vec<(i64, i32)> = Vec::new();
        let mut earliest: Option<(i64, i32)> = None;
        for observance in observances {
            let Some((start, from, to)) = observance_parts(observance) else {
                return Ok(None);
            };
            let mut onsets: BTreeSet<NaiveDateTime> = BTreeSet::new();
            onsets.insert(start);
            if let Some(ICalendarValue::RecurrenceRule(rule)) =
                observance.first(&Prop::Rrule).and_then(|entry| entry.values.first())
                && rule.freq == ICalendarFrequency::Yearly
            {
                let from_zone = Zone::Custom(Self {
                    initial: from,
                    transitions: Vec::new(),
                });
                let until = rule_until_local(rule, &from_zone).or_else(|| {
                    NaiveDate::from_ymd_opt(OBSERVANCE_HORIZON_YEAR, 1, 1).and_then(|date| date.and_hms_opt(0, 0, 0))
                });
                let cap = MAX_ONSETS_PER_RULE.min(onsets_left);
                if cap == 0 {
                    return Err(ZoneError::TooComplex);
                }
                if let Ok(generated) = rule_locals(rule, start, false, until, cap) {
                    if generated.truncated {
                        return Err(ZoneError::TooComplex);
                    }
                    onsets_left = onsets_left.saturating_sub(generated.dates.len());
                    onsets.extend(generated.dates);
                }
            }
            for entry in observance.all(&Prop::Rdate) {
                let moments = entry_moments(entry).0;
                if moments.len() > onsets_left {
                    return Err(ZoneError::TooComplex);
                }
                onsets_left = onsets_left.saturating_sub(moments.len());
                onsets.extend(moments.iter().map(Moment::local));
            }
            for onset in onsets {
                let Some(at) = onset.and_utc().timestamp().checked_sub(i64::from(from)) else {
                    return Ok(None);
                };
                transitions.push((at, to));
                if earliest.is_none_or(|(first, _)| at < first) {
                    earliest = Some((at, from));
                }
            }
        }
        let Some((_, initial)) = earliest else {
            return Ok(None);
        };
        transitions.sort_unstable();
        transitions.dedup();
        Ok(Some(Self { initial, transitions }))
    }
}

/// The seconds east of UTC a `TZOFFSETFROM`/`TZOFFSETTO` value states.
fn offset_of(value: &ICalendarValue) -> Option<i32> {
    let ICalendarValue::PartialDateTime(parts) = value else {
        return None;
    };
    let seconds = i32::from(parts.tz_hour?)
        .checked_mul(3600)?
        .checked_add(i32::from(parts.tz_minute.unwrap_or(0)).checked_mul(60)?)?;
    Some(if parts.tz_minus { -seconds } else { seconds })
}

/// A time zone: the rules that map instants to local time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Zone {
    /// A zone of the bundled time zone database.
    Iana(Tz),
    /// A zone evaluated from a `VTIMEZONE` of the calendar object.
    Custom(CustomZone),
}

impl Zone {
    /// Coordinated Universal Time.
    pub(crate) const fn utc() -> Self {
        Self::Iana(Tz::UTC)
    }

    /// A zone of the database.
    pub(crate) const fn from_tz(zone: Tz) -> Self {
        Self::Iana(zone)
    }

    /// The offset east of UTC, in seconds, at an instant given in Unix seconds.
    pub(crate) fn offset_at(&self, utc: i64) -> i32 {
        match self {
            Self::Iana(zone) => DateTime::from_timestamp(utc, 0).map_or(0, |instant| {
                zone.offset_from_utc_datetime(&instant.naive_utc())
                    .fix()
                    .local_minus_utc()
            }),
            Self::Custom(zone) => zone.offset_at(utc),
        }
    }

    /// The instant a wall-clock time denotes in this zone (first occurrence for repeated times, the offset
    /// before the jump for skipped times). `None` only for dates outside the representable range.
    pub(crate) fn local_to_utc(&self, local: NaiveDateTime) -> Option<DateTime<Utc>> {
        let naive_seconds = local.and_utc().timestamp();
        let before = self.offset_at(naive_seconds.checked_sub(DAY)?);
        let after = self.offset_at(naive_seconds.checked_add(DAY)?);
        let mut best: Option<i64> = None;
        for offset in [before, after] {
            let candidate = naive_seconds.checked_sub(i64::from(offset))?;
            if self.offset_at(candidate) == offset && best.is_none_or(|current| candidate < current) {
                best = Some(candidate);
            }
        }
        let seconds = match best {
            Some(seconds) => seconds,
            None => naive_seconds.checked_sub(i64::from(before))?,
        };
        DateTime::from_timestamp(seconds, 0)
    }

    /// The wall-clock time of an instant in this zone.
    pub(crate) fn utc_to_local(&self, instant: DateTime<Utc>) -> NaiveDateTime {
        let offset = self.offset_at(instant.timestamp());
        TimeDelta::try_seconds(i64::from(offset))
            .and_then(|shift| instant.naive_utc().checked_add_signed(shift))
            .unwrap_or_else(|| instant.naive_utc())
    }

    /// The IANA name of the zone, if it is one.
    pub(crate) fn iana(&self) -> Option<Tz> {
        match self {
            Self::Iana(zone) => Some(*zone),
            Self::Custom(_) => None,
        }
    }
}

/// How a moment identifies an instance of a recurrence set: all-day values by their date, everything else by
/// the instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum RidKey {
    /// An all-day instance.
    Date(NaiveDate),
    /// A timed instance.
    Instant(DateTime<Utc>),
}

/// One `TZID` of an object: the definition that came with it (if any) and the zone it resolves to, computed on
/// first use.
#[derive(Debug, Clone)]
struct Entry {
    definition: Option<Node>,
    referenced: bool,
    resolved: OnceCell<Result<Option<Zone>, ZoneError>>,
}

/// The time zones of one calendar object plus the zone floating values and dates are read in.
#[derive(Debug, Clone)]
pub(crate) struct Zones {
    floating: Zone,
    entries: HashMap<String, Entry>,
}

impl Zones {
    /// A resolver that knows no `TZID` (everything unknown is floating).
    pub(crate) fn new(floating: Zone) -> Self {
        Self {
            floating,
            entries: HashMap::new(),
        }
    }

    /// Prepares the `TZID`s the object refers to; nothing is evaluated until a zone is asked for.
    pub(crate) fn for_tree(root: &Node, floating: Zone) -> Self {
        let mut zones = Self::new(floating);
        let mut definitions: HashMap<String, &Node> = HashMap::new();
        let mut referenced: BTreeSet<String> = BTreeSet::new();
        collect_tzids(root, &mut definitions, &mut referenced);
        for tzid in referenced {
            let definition = definitions.get(&tzid).map(|node| (*node).clone());
            zones.entries.insert(
                tzid,
                Entry {
                    definition,
                    referenced: true,
                    resolved: OnceCell::new(),
                },
            );
        }
        zones
    }

    /// The zone of a `TZID`, if it resolves.
    pub(crate) fn zone(&self, tzid: &str) -> Option<&Zone> {
        let entry = self.entries.get(tzid)?;
        entry
            .resolved
            .get_or_init(|| resolve_zone(tzid, entry.definition.as_ref()))
            .as_ref()
            .ok()?
            .as_ref()
    }

    /// Evaluates every zone the object refers to, so that a definition that is too complex to evaluate is found
    /// when the object is stored and not when it is read.
    ///
    /// # Errors
    ///
    /// [`LimitKind::Observances`] for a referenced `VTIMEZONE` with too many observances or transitions.
    pub(crate) fn check_referenced(&self) -> Result<(), IcalError> {
        for (tzid, entry) in &self.entries {
            if !entry.referenced {
                continue;
            }
            let resolved = entry
                .resolved
                .get_or_init(|| resolve_zone(tzid, entry.definition.as_ref()));
            if resolved.is_err() {
                return Err(IcalError::Limit(LimitKind::Observances));
            }
        }
        Ok(())
    }

    /// The zone a moment's wall-clock value is expressed in.
    pub(crate) fn zone_of(&self, moment: &Moment) -> &Zone {
        match moment {
            Moment::Zoned { tzid, .. } => self.zone(tzid).unwrap_or(&self.floating),
            Moment::Date(_) | Moment::Floating(_) => &self.floating,
            Moment::Utc(_) => &UTC_ZONE,
        }
    }

    /// The instant of a moment: dates at midnight and floating values in the floating zone.
    pub(crate) fn to_utc(&self, moment: &Moment) -> Option<DateTime<Utc>> {
        match moment {
            Moment::Utc(utc) => Some(utc.and_utc()),
            other => self.zone_of(other).local_to_utc(other.local()),
        }
    }

    /// The key that identifies the instance a moment names.
    pub(crate) fn rid_key(&self, moment: &Moment) -> Option<RidKey> {
        match moment {
            Moment::Date(date) => Some(RidKey::Date(*date)),
            other => self.to_utc(other).map(RidKey::Instant),
        }
    }

    /// The wall-clock time of an instant in the zone of `like`.
    pub(crate) fn local_in_zone_of(&self, like: &Moment, instant: DateTime<Utc>) -> NaiveDateTime {
        self.zone_of(like).utc_to_local(instant)
    }

    /// Whether two moments name the same instance: all-day values by date, everything else by instant.
    pub(crate) fn same(&self, a: &Moment, b: &Moment) -> bool {
        if a.is_date() || b.is_date() {
            return a.date() == b.date();
        }
        match (self.to_utc(a), self.to_utc(b)) {
            (Some(first), Some(second)) => first == second,
            _ => false,
        }
    }

    /// The IANA name of a `TZID`, if it resolves to a zone of the database.
    pub(crate) fn iana_name(&self, tzid: &str) -> Option<TimeZoneName> {
        self.zone(tzid)
            .and_then(Zone::iana)
            .and_then(crate::calendar::zone_name)
    }

    /// How many zones have been resolved so far (tests assert that unused definitions are never evaluated).
    #[cfg(test)]
    fn resolved_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.resolved.get().is_some())
            .count()
    }
}

static UTC_ZONE: Zone = Zone::utc();

fn collect_tzids<'a>(node: &'a Node, definitions: &mut HashMap<String, &'a Node>, referenced: &mut BTreeSet<String>) {
    if node.kind == Kind::VTimezone {
        if let Some(tzid) = node.text(&Prop::Tzid) {
            definitions.entry(tzid).or_insert(node);
        }
        return;
    }
    for entry in &node.entries {
        if let Some(tzid) = crate::calendar::param_text(entry, &Param::Tzid) {
            referenced.insert(tzid);
        }
    }
    for child in &node.children {
        collect_tzids(child, definitions, referenced);
    }
}

pub(crate) fn resolve_zone(tzid: &str, definition: Option<&Node>) -> Result<Option<Zone>, ZoneError> {
    if let Ok(Some(name)) = crate::tz::resolve_tzid(tzid) {
        return Ok(Some(Zone::Iana(name.tz())));
    }
    let Some(definition) = definition else {
        return Ok(None);
    };
    for entry in &definition.entries {
        let ICalendarProperty::Other(name) = &entry.name else {
            continue;
        };
        let Some(text) = crate::calendar::entry_text(entry) else {
            continue;
        };
        if name.eq_ignore_ascii_case("X-LIC-LOCATION") {
            let location = text.strip_prefix("SystemV/").unwrap_or(&text);
            if let Ok(Some(zone)) = crate::tz::resolve_tzid(location) {
                return Ok(Some(Zone::Iana(zone.tz())));
            }
        } else if name.eq_ignore_ascii_case("X-MICROSOFT-CDO-TZID")
            && let Some(CalendarTz::Tz(zone)) = CalendarTz::from_ms_cdo_zone_id(&text)
        {
            return Ok(Some(Zone::Iana(zone)));
        }
    }
    CustomZone::from_vtimezone(definition).map(|zone| zone.map(Zone::Custom))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use calcard::{Entry, Parser};

    use super::*;

    fn local(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(hour, minute, 0)
            .unwrap()
    }

    fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        local(year, month, day, hour, minute).and_utc()
    }

    fn tree(text: &str) -> Node {
        let mut parser = Parser::new(text);
        let Entry::ICalendar(calendar) = parser.entry() else {
            panic!("not a calendar");
        };
        Node::from_calendar(&calendar).unwrap()
    }

    #[test]
    fn repeated_local_times_use_the_first_occurrence() {
        let berlin = Zone::from_tz(chrono_tz::Europe::Berlin);
        // The clocks go back at 03:00 CEST on 2027-10-31; 02:30 occurs twice.
        assert_eq!(
            berlin.local_to_utc(local(2027, 10, 31, 2, 30)),
            Some(utc(2027, 10, 31, 0, 30))
        );
        assert_eq!(
            berlin.local_to_utc(local(2027, 10, 31, 3, 30)),
            Some(utc(2027, 10, 31, 2, 30))
        );
    }

    #[test]
    fn skipped_local_times_use_the_offset_before_the_jump() {
        let berlin = Zone::from_tz(chrono_tz::Europe::Berlin);
        // The clocks jump from 02:00 to 03:00 on 2027-03-28; 02:30 does not occur and counts as CET.
        assert_eq!(
            berlin.local_to_utc(local(2027, 3, 28, 2, 30)),
            Some(utc(2027, 3, 28, 1, 30))
        );
        assert_eq!(
            berlin.local_to_utc(local(2027, 3, 28, 3, 30)),
            Some(utc(2027, 3, 28, 1, 30))
        );
        assert_eq!(
            berlin.local_to_utc(local(2027, 3, 27, 2, 30)),
            Some(utc(2027, 3, 27, 1, 30))
        );
    }

    #[test]
    fn ordinary_times_round_trip() {
        for zone in [
            Zone::utc(),
            Zone::from_tz(chrono_tz::America::New_York),
            Zone::from_tz(chrono_tz::Asia::Kolkata),
            Zone::from_tz(chrono_tz::Australia::Lord_Howe),
        ] {
            let instant = utc(2027, 6, 15, 12, 0);
            let wall = zone.utc_to_local(instant);
            assert_eq!(zone.local_to_utc(wall), Some(instant));
        }
        assert_eq!(
            Zone::from_tz(chrono_tz::Asia::Kolkata).utc_to_local(utc(2027, 1, 1, 0, 0)),
            local(2027, 1, 1, 5, 30)
        );
    }

    const CUSTOM: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
        BEGIN:VTIMEZONE\r\nTZID:Customized Time Zone\r\n\
        BEGIN:STANDARD\r\nDTSTART:16010101T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
        RRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\n\
        BEGIN:DAYLIGHT\r\nDTSTART:16010101T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\n\
        RRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=-1SU;BYMONTH=3\r\nEND:DAYLIGHT\r\n\
        END:VTIMEZONE\r\n\
        BEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=Customized Time Zone:20270601T100000\r\nEND:VEVENT\r\n\
        END:VCALENDAR\r\n";

    #[test]
    fn a_custom_vtimezone_is_evaluated_from_its_observances() {
        let root = tree(CUSTOM);
        let zones = Zones::for_tree(&root, Zone::utc());
        let zone = zones.zone("Customized Time Zone").expect("the zone resolves");
        assert!(zone.iana().is_none());
        // Summer: UTC+2; winter: UTC+1; the switch dates are the last Sundays of March and October.
        assert_eq!(
            zone.local_to_utc(local(2027, 7, 1, 12, 0)),
            Some(utc(2027, 7, 1, 10, 0))
        );
        assert_eq!(
            zone.local_to_utc(local(2027, 1, 15, 12, 0)),
            Some(utc(2027, 1, 15, 11, 0))
        );
        assert_eq!(
            zone.local_to_utc(local(2027, 3, 28, 1, 59)),
            Some(utc(2027, 3, 28, 0, 59))
        );
        assert_eq!(
            zone.local_to_utc(local(2027, 3, 28, 3, 0)),
            Some(utc(2027, 3, 28, 1, 0))
        );
        assert_eq!(
            zone.local_to_utc(local(2027, 10, 31, 3, 30)),
            Some(utc(2027, 10, 31, 2, 30))
        );
        let event = root.children.get(1).unwrap();
        let start = entry_moment(event.first(&Prop::Dtstart).unwrap()).unwrap();
        assert_eq!(zones.to_utc(&start), Some(utc(2027, 6, 1, 8, 0)));
    }

    #[test]
    fn known_names_win_over_embedded_definitions() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n\
            BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0000\r\nTZOFFSETTO:+0000\r\nEND:STANDARD\r\n\
            END:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=Europe/Berlin:20270601T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let root = tree(text);
        let zones = Zones::for_tree(&root, Zone::utc());
        assert_eq!(
            zones.zone("Europe/Berlin").and_then(Zone::iana),
            Some(chrono_tz::Europe::Berlin)
        );
        assert_eq!(
            zones.iana_name("Europe/Berlin").map(|name| name.to_string()).as_deref(),
            Some("Europe/Berlin")
        );
    }

    #[test]
    fn a_definition_that_names_its_iana_zone_resolves_to_that_zone() {
        // Lightning writes X-LIC-LOCATION (sometimes with the SystemV/ prefix of old libical), Exchange the number
        // of its zone in X-MICROSOFT-CDO-TZID (20 is Tokyo); the observances of the definitions here are UTC, so
        // that only the name can give the result.
        let definition = |tzid: &str, extra: &str| {
            format!(
                "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:{tzid}\r\n{extra}\
                 BEGIN:STANDARD\r\nDTSTART:19700101T000000\r\nTZOFFSETFROM:+0000\r\nTZOFFSETTO:+0000\r\nEND:STANDARD\r\n\
                 END:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID={tzid}:20270601T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
            )
        };
        for (extra, expected) in [
            ("X-LIC-LOCATION:Europe/Berlin\r\n", chrono_tz::Europe::Berlin),
            (
                "X-LIC-LOCATION:SystemV/America/New_York\r\n",
                chrono_tz::America::New_York,
            ),
            ("X-MICROSOFT-CDO-TZID:20\r\n", chrono_tz::Asia::Tokyo),
        ] {
            let root = tree(&definition("Mozilla Zone", extra));
            let zones = Zones::for_tree(&root, Zone::utc());
            assert_eq!(
                zones.zone("Mozilla Zone").and_then(Zone::iana),
                Some(expected),
                "{extra}"
            );
        }
        // A location nobody knows falls back to the observances.
        let root = tree(&definition("Mozilla Zone", "X-LIC-LOCATION:Nowhere/Atlantis\r\n"));
        let zones = Zones::for_tree(&root, Zone::utc());
        let zone = zones
            .zone("Mozilla Zone")
            .expect("the observances still define the zone");
        assert!(zone.iana().is_none());
        assert_eq!(
            zone.local_to_utc(local(2027, 6, 1, 10, 0)),
            Some(utc(2027, 6, 1, 10, 0))
        );
    }

    #[test]
    fn windows_names_resolve_without_a_definition() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=W. Europe Standard Time:20270601T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let root = tree(text);
        let zones = Zones::for_tree(&root, Zone::utc());
        assert_eq!(
            zones.zone("W. Europe Standard Time").and_then(Zone::iana),
            Some(chrono_tz::Europe::Berlin)
        );
    }

    #[test]
    fn unknown_zones_fall_back_to_the_floating_zone() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=Nowhere/Atlantis:20270601T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let root = tree(text);
        let zones_for_tree = Zones::for_tree(&root, Zone::from_tz(chrono_tz::Europe::Berlin));
        let event = root.children.first().unwrap();
        let start = entry_moment(event.first(&Prop::Dtstart).unwrap()).unwrap();
        assert!(zones_for_tree.zone("Nowhere/Atlantis").is_none());
        assert_eq!(
            zones_for_tree.to_utc(&start),
            Some(utc(2027, 6, 1, 8, 0)),
            "an unknown zone is read as floating, here in Berlin"
        );
    }

    /// A document with `count` custom zones whose yearly rules start in 1601, none of them used by the event.
    fn many_zones(count: usize, used: Option<usize>) -> String {
        let mut text = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n");
        for n in 0..count {
            let _ = write!(
                text,
                "BEGIN:VTIMEZONE\r\nTZID:Custom {n}\r\n\
                 BEGIN:STANDARD\r\nDTSTART:16010101T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
                 RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\n\
                 BEGIN:DAYLIGHT\r\nDTSTART:16010101T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\n\
                 RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\nEND:DAYLIGHT\r\nEND:VTIMEZONE\r\n"
            );
        }
        let zone = used.map_or_else(String::new, |n| format!(";TZID=Custom {n}"));
        let _ = write!(
            text,
            "BEGIN:VEVENT\r\nUID:x\r\nDTSTART{zone}:20270601T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        text
    }

    #[test]
    fn unused_definitions_are_never_evaluated() {
        let root = tree(&many_zones(300, None));
        let zones = Zones::for_tree(&root, Zone::utc());
        assert_eq!(zones.resolved_count(), 0, "nothing is evaluated up front");
        assert!(zones.check_referenced().is_ok());
        assert_eq!(zones.resolved_count(), 0, "unreferenced zones stay untouched");
        // Asking for one zone evaluates that zone and no other.
        let used = tree(&many_zones(300, Some(7)));
        let zones = Zones::for_tree(&used, Zone::utc());
        let event = used.children.last().unwrap();
        let start = entry_moment(event.first(&Prop::Dtstart).unwrap()).unwrap();
        assert_eq!(zones.to_utc(&start), Some(utc(2027, 6, 1, 8, 0)));
        assert_eq!(zones.resolved_count(), 1);
    }

    #[test]
    fn a_zone_whose_rules_run_away_is_too_complex() {
        let observance = "BEGIN:STANDARD\r\nDTSTART:16010101T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
            RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\n";
        // Fifty rules of 500 transitions each exceed what one zone may produce.
        let text = format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTIMEZONE\r\nTZID:Ancient\r\n{}END:VTIMEZONE\r\n\
             BEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=Ancient:20270601T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            observance.repeat(50)
        );
        let root = tree(&text);
        let zones = Zones::for_tree(&root, Zone::utc());
        assert_eq!(zones.check_referenced(), Err(IcalError::Limit(LimitKind::Observances)));
        assert!(zones.zone("Ancient").is_none(), "an unusable zone reads as floating");
        let unused = text.replace("DTSTART;TZID=Ancient:", "DTSTART:");
        assert!(
            Zones::for_tree(&tree(&unused), Zone::utc()).check_referenced().is_ok(),
            "only referenced zones are checked"
        );
    }

    #[test]
    fn outlook_zones_from_1601_are_within_the_bounds() {
        let root = tree(CUSTOM);
        assert!(Zones::for_tree(&root, Zone::utc()).check_referenced().is_ok());
    }

    #[test]
    fn instance_keys_identify_dates_and_instants() {
        let zones = Zones::new(Zone::from_tz(chrono_tz::Europe::Berlin));
        let date = Moment::Date(NaiveDate::from_ymd_opt(2027, 3, 1).unwrap());
        assert_eq!(
            zones.rid_key(&date),
            Some(RidKey::Date(NaiveDate::from_ymd_opt(2027, 3, 1).unwrap()))
        );
        let floating = Moment::Floating(local(2027, 3, 1, 10, 0));
        assert_eq!(zones.rid_key(&floating), Some(RidKey::Instant(utc(2027, 3, 1, 9, 0))));
        let absolute = Moment::Utc(local(2027, 3, 1, 9, 0));
        assert_eq!(zones.rid_key(&absolute), zones.rid_key(&floating));
    }

    #[test]
    fn floating_values_and_dates_use_the_floating_zone() {
        let zones = Zones::new(Zone::from_tz(chrono_tz::Asia::Kolkata));
        let floating = Moment::Floating(local(2027, 1, 1, 12, 0));
        assert_eq!(zones.to_utc(&floating), Some(utc(2027, 1, 1, 6, 30)));
        let date = Moment::Date(NaiveDate::from_ymd_opt(2027, 1, 1).unwrap());
        assert_eq!(zones.to_utc(&date), Some(utc(2026, 12, 31, 18, 30)));
        let absolute = Moment::Utc(local(2027, 1, 1, 12, 0));
        assert_eq!(zones.to_utc(&absolute), Some(utc(2027, 1, 1, 12, 0)));
    }
}
