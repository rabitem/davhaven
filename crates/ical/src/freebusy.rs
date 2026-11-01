//! Free-busy computation over calendar objects.
//!
//! Free-busy answers "when is this person busy?" without revealing why. Opaque, non-cancelled events count;
//! `TRANSPARENT` and `CANCELLED` ones do not; `CLASS:PRIVATE` and `CONFIDENTIAL` events count as busy like any
//! other (their details are never part of the result). The result is merged: periods are sorted, overlapping
//! and adjacent periods of the same kind are combined.

use calcard::common::PartialDateTime;
use calcard::icalendar::{ICalendarFreeBusyType, ICalendarParameter, ICalendarPeriod, ICalendarValue};
use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarUserAddress, IcalLimits, ItipMethod, PartStat, TimeZoneName, Uid};

use crate::calendar::{
    Kind, Moment, Node, Prop, address_of, address_value, entry_moment, instant_entry, moment_entry, partial_from_local,
    partstat_of, text_entry,
};
use crate::error::{IcalError, LimitKind};
use crate::filter::TimeRange;
use crate::itip::ItipMessage;
use crate::occurrence::{Budget, Engine, Flow};
use crate::parse::ParsedCalendar;
use crate::zones::{Zone, Zones};

/// Collected busy periods are merged once there are this many, so that a long series cannot pile up.
const COMPACT_AT: usize = 4_096;
/// The most merged busy periods one computation returns; more is [`LimitKind::Instances`].
const MAX_BUSY_PERIODS: usize = 50_000;

/// The kind of a busy period (`FBTYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BusyKind {
    /// `BUSY`: the time is taken.
    Busy,
    /// `BUSY-TENTATIVE`: the time is taken tentatively (events with `STATUS:TENTATIVE`).
    BusyTentative,
    /// `BUSY-UNAVAILABLE`: the person is unavailable.
    BusyUnavailable,
}

/// A period of busy time in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusyPeriod {
    /// The inclusive start.
    pub start: DateTime<Utc>,
    /// The exclusive end.
    pub end: DateTime<Utc>,
    /// The kind of busy time.
    pub kind: BusyKind,
}

/// Computes the merged busy periods of `calendars` inside `range`.
///
/// Floating times and all-day dates are read as UTC; see [`busy_periods_in_zone`].
///
/// # Errors
///
/// * [`IcalError::Invalid`] or [`IcalError::Limit`] for an unbounded or too long range
///   (see [`TimeRange::validate_bounded`]),
/// * [`LimitKind::IteratorSteps`] and [`LimitKind::TimeBudget`] when the objects together exceed the step or
///   time budget (one budget covers the whole call), [`LimitKind::Instances`] for more than 50 000 merged
///   busy periods. A long series is no error: the limit on instances per expansion does not apply here.
pub fn busy_periods(
    calendars: &[&ParsedCalendar],
    range: &TimeRange,
    limits: &IcalLimits,
) -> Result<Vec<BusyPeriod>, IcalError> {
    busy_periods_in_zone(calendars, range, limits, TimeZoneName::utc())
}

/// Like [`busy_periods`], with floating times and all-day dates read in `floating_zone` (the time zone of the
/// calendar collection).
///
/// # Errors
///
/// As [`busy_periods`].
pub fn busy_periods_in_zone(
    calendars: &[&ParsedCalendar],
    range: &TimeRange,
    limits: &IcalLimits,
    floating_zone: TimeZoneName,
) -> Result<Vec<BusyPeriod>, IcalError> {
    busy_periods_impl(calendars, range, limits, floating_zone, None)
}

/// Whose time a computation is about when the events it reads were not all written for that person alone: the
/// events of the calendars of a group, or of a calendar somebody shared.
#[derive(Debug, Clone, Copy)]
pub struct Participation<'a> {
    /// Every calendar user address that names the person.
    pub addresses: &'a [CalendarUserAddress],
    /// Whether events the person neither organizes nor attends are left out. The calendars a person owns count
    /// as a whole (`false`); the calendars of a group and the calendars shared with them count only for the
    /// events they take part in (`true`).
    pub participating_only: bool,
}

/// [`busy_periods_in_zone`] for one person: an event the person has **declined** (their `ATTENDEE` line says
/// `PARTSTAT=DECLINED`, on the master or on one instance) does not make them busy, and with
/// [`Participation::participating_only`] neither does an event they are not the `ORGANIZER` or an `ATTENDEE` of.
///
/// # Errors
///
/// As [`busy_periods`].
pub fn busy_periods_for(
    calendars: &[&ParsedCalendar],
    range: &TimeRange,
    limits: &IcalLimits,
    floating_zone: TimeZoneName,
    who: &Participation<'_>,
) -> Result<Vec<BusyPeriod>, IcalError> {
    busy_periods_impl(calendars, range, limits, floating_zone, Some(who))
}

fn busy_periods_impl(
    calendars: &[&ParsedCalendar],
    range: &TimeRange,
    limits: &IcalLimits,
    floating_zone: TimeZoneName,
    who: Option<&Participation<'_>>,
) -> Result<Vec<BusyPeriod>, IcalError> {
    range.validate_bounded(limits)?;
    let (Some(from), Some(until)) = (range.start, range.end) else {
        return Err(IcalError::invalid("this time-range needs both a start and an end"));
    };
    // One budget covers the whole call: the wall clock and the generator steps are shared by every object, so
    // asking about many objects cannot cost many times what one object may cost.
    let budget = Budget::new(limits);
    let mut steps = usize::try_from(limits.max_iterator_steps).unwrap_or(usize::MAX);
    let mut periods: Vec<BusyPeriod> = Vec::new();
    let mut compact_at = COMPACT_AT;
    for calendar in calendars {
        let root = &calendar.root;
        let zones = Zones::for_tree(root, Zone::from_tz(floating_zone.tz()));
        let mut engine = Engine::new(&zones, limits, budget)
            .with_steps(steps)
            .without_instance_limit();
        engine.visit(root, range, &mut |occurrence| {
            let Some(node) = root.children.get(occurrence.component) else {
                return Ok(Flow::Continue);
            };
            let Some(kind) = busy_kind(node).filter(|_| who.is_none_or(|who| counts_for(node, who))) else {
                return Ok(Flow::Continue);
            };
            let start = occurrence.start.max(from);
            let end = occurrence.end.min(until);
            if start < end {
                periods.push(BusyPeriod { start, end, kind });
                if periods.len() >= compact_at {
                    periods = merge(std::mem::take(&mut periods));
                    if periods.len() > MAX_BUSY_PERIODS {
                        return Err(IcalError::Limit(LimitKind::Instances));
                    }
                    // Merging again is only worth it once the list has doubled.
                    compact_at = periods.len().saturating_mul(2).max(COMPACT_AT);
                }
            }
            Ok(Flow::Continue)
        })?;
        steps = engine.steps_left();
        budget.check()?;
    }
    let merged = merge(periods);
    if merged.len() > MAX_BUSY_PERIODS {
        return Err(IcalError::Limit(LimitKind::Instances));
    }
    Ok(merged)
}

/// The kind of busy time a component contributes; `None` for components that do not block time.
fn busy_kind(node: &Node) -> Option<BusyKind> {
    if node.kind != Kind::VEvent || node.transparency().as_deref() == Some("TRANSPARENT") {
        return None;
    }
    match node.status().as_deref() {
        Some("CANCELLED") => None,
        Some("TENTATIVE") => Some(BusyKind::BusyTentative),
        _ => Some(BusyKind::Busy),
    }
}

/// Whether a component makes the person busy: not when they declined it, and, when only events they take part in
/// count, only when they organize it or are on its attendee list.
fn counts_for(node: &Node, who: &Participation<'_>) -> bool {
    let named = |entry: &calcard::icalendar::ICalendarEntry| {
        address_of(entry).is_some_and(|address| who.addresses.contains(&address))
    };
    if node.all(&Prop::Organizer).any(named) {
        return true;
    }
    let mut attends = false;
    for entry in node.all(&Prop::Attendee).filter(|entry| named(entry)) {
        if partstat_of(entry) == PartStat::Declined {
            return false;
        }
        attends = true;
    }
    attends || !who.participating_only
}

/// What a `VFREEBUSY` request of an outbox `POST` asks (RFC 6638 section 5.1): who asks, whose busy time, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeBusyRequest {
    /// The `ORGANIZER`: who asks.
    pub organizer: CalendarUserAddress,
    /// The `ATTENDEE`s: whose busy time is asked, each once, in order of appearance.
    pub attendees: Vec<CalendarUserAddress>,
    /// `DTSTART`.
    pub start: DateTime<Utc>,
    /// `DTEND`.
    pub end: DateTime<Utc>,
}

/// Reads the request of an iTIP message that passed [`parse_message`](crate::itip::parse_message): a `REQUEST`
/// with exactly one `VFREEBUSY` (time zone components are not components of their own), an `ORGANIZER`, at least
/// one `ATTENDEE` and a range given in UTC.
///
/// # Errors
///
/// [`IcalError::Invalid`] with a short reason when the message is anything else.
pub fn read_request(message: &ItipMessage) -> Result<FreeBusyRequest, IcalError> {
    if message.method != ItipMethod::Request {
        return Err(IcalError::invalid(
            "only a free-busy REQUEST can be posted to the outbox",
        ));
    }
    let mut components = message
        .calendar
        .root
        .children
        .iter()
        .filter(|node| node.kind != Kind::VTimezone);
    let (Some(node), None) = (components.next(), components.next()) else {
        return Err(IcalError::invalid("the outbox accepts exactly one VFREEBUSY component"));
    };
    if node.kind != Kind::VFreebusy {
        return Err(IcalError::invalid("the outbox accepts exactly one VFREEBUSY component"));
    }
    let organizer = node
        .first(&Prop::Organizer)
        .and_then(address_of)
        .ok_or_else(|| IcalError::invalid("the free-busy request has no ORGANIZER"))?;
    let mut attendees: Vec<CalendarUserAddress> = Vec::new();
    for address in node.all(&Prop::Attendee).filter_map(address_of) {
        if !attendees.contains(&address) {
            attendees.push(address);
        }
    }
    if attendees.is_empty() {
        return Err(IcalError::invalid("the free-busy request names nobody to ask"));
    }
    let utc = |name: &Prop, what: &'static str| match node.first(name).and_then(entry_moment) {
        Some(Moment::Utc(at)) => Ok(at.and_utc()),
        _ => Err(IcalError::invalid(what)),
    };
    Ok(FreeBusyRequest {
        organizer,
        attendees,
        start: utc(&Prop::Dtstart, "DTSTART must be a date-time in UTC")?,
        end: utc(&Prop::Dtend, "DTEND must be a date-time in UTC")?,
    })
}

/// Sorts the periods and combines overlapping and adjacent ones of the same kind.
fn merge(mut periods: Vec<BusyPeriod>) -> Vec<BusyPeriod> {
    periods.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.start.cmp(&b.start)).then(a.end.cmp(&b.end)));
    let mut merged: Vec<BusyPeriod> = Vec::with_capacity(periods.len());
    for period in periods {
        match merged.last_mut() {
            Some(last) if last.kind == period.kind && period.start <= last.end => {
                last.end = last.end.max(period.end);
            }
            _ => merged.push(period),
        }
    }
    merged.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)).then(a.kind.cmp(&b.kind)));
    merged
}

/// The data of a `VFREEBUSY` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeBusyReport {
    /// The requesting organizer, if the report answers a scheduling request.
    pub organizer: Option<CalendarUserAddress>,
    /// The principal whose busy time is reported.
    pub attendee: CalendarUserAddress,
    /// The queried range.
    pub range: TimeRange,
    /// The busy periods inside the range.
    pub periods: Vec<BusyPeriod>,
    /// The `DTSTAMP` of the answer (from the `Clock`).
    pub dtstamp: DateTime<Utc>,
    /// The `UID` of the answer (from the `IdGenerator`).
    pub uid: Uid,
}

fn period_value(period: &BusyPeriod) -> Option<ICalendarValue> {
    let part = |at: DateTime<Utc>| -> Option<PartialDateTime> { partial_from_local(at.naive_utc(), true, true) };
    Some(ICalendarValue::Period(ICalendarPeriod::Range {
        start: part(period.start)?,
        end: part(period.end)?,
    }))
}

/// Renders a free-busy answer as a `VCALENDAR` with a `VFREEBUSY` component (and `METHOD:REPLY` when the report
/// has an organizer).
///
/// # Errors
///
/// [`IcalError::Invalid`] when the range of the report has no start or end, or a date is out of range.
pub fn render_freebusy(report: &FreeBusyReport) -> Result<String, IcalError> {
    freebusy_calendar(
        report.organizer.as_ref(),
        Some(&report.attendee),
        &report.range,
        &report.periods,
        report.dtstamp,
        &report.uid,
    )
}

/// Renders the answer of a `free-busy-query` on a calendar collection (RFC 4791 section 7.10): a `VCALENDAR` with
/// one `VFREEBUSY` that has the range and the busy periods, and neither `METHOD`, `ORGANIZER` nor `ATTENDEE`,
/// because nobody asked on behalf of anybody.
///
/// # Errors
///
/// [`IcalError::Invalid`] when the range has no start or end, or a date is out of range.
pub fn render_collection_freebusy(
    range: &TimeRange,
    periods: &[BusyPeriod],
    dtstamp: DateTime<Utc>,
    uid: &Uid,
) -> Result<String, IcalError> {
    freebusy_calendar(None, None, range, periods, dtstamp, uid)
}

fn freebusy_calendar(
    organizer: Option<&CalendarUserAddress>,
    attendee: Option<&CalendarUserAddress>,
    range: &TimeRange,
    periods: &[BusyPeriod],
    dtstamp: DateTime<Utc>,
    uid: &Uid,
) -> Result<String, IcalError> {
    let (Some(from), Some(until)) = (range.start, range.end) else {
        return Err(IcalError::invalid("a free-busy answer needs a start and an end"));
    };
    let out_of_range = || IcalError::invalid("a date is out of range");
    let mut calendar = Node::new(Kind::VCalendar);
    calendar.entries.push(text_entry(Prop::Version, "2.0"));
    calendar.entries.push(text_entry(Prop::Prodid, crate::PRODID));
    if organizer.is_some() {
        calendar.entries.push(
            calcard::icalendar::ICalendarEntry::new(Prop::Method)
                .with_value(calcard::icalendar::ICalendarMethod::Reply),
        );
    }
    let mut freebusy = Node::new(Kind::VFreebusy);
    freebusy.entries.push(text_entry(Prop::Uid, uid.as_str()));
    freebusy
        .entries
        .push(instant_entry(Prop::Dtstamp, dtstamp).ok_or_else(out_of_range)?);
    if let Some(organizer) = organizer {
        freebusy
            .entries
            .push(calcard::icalendar::ICalendarEntry::new(Prop::Organizer).with_value(address_value(organizer)));
    }
    if let Some(attendee) = attendee {
        freebusy
            .entries
            .push(calcard::icalendar::ICalendarEntry::new(Prop::Attendee).with_value(address_value(attendee)));
    }
    freebusy
        .entries
        .push(moment_entry(Prop::Dtstart, &Moment::Utc(from.naive_utc())).ok_or_else(out_of_range)?);
    freebusy
        .entries
        .push(moment_entry(Prop::Dtend, &Moment::Utc(until.naive_utc())).ok_or_else(out_of_range)?);
    for kind in [BusyKind::Busy, BusyKind::BusyTentative, BusyKind::BusyUnavailable] {
        let values: Vec<ICalendarValue> = periods
            .iter()
            .filter(|period| period.kind == kind)
            .filter_map(period_value)
            .collect();
        if values.is_empty() {
            continue;
        }
        let mut entry = calcard::icalendar::ICalendarEntry::new(Prop::Freebusy).with_values(values);
        match kind {
            BusyKind::Busy => {}
            BusyKind::BusyTentative => entry
                .params
                .push(ICalendarParameter::fbtype(ICalendarFreeBusyType::BusyTentative)),
            BusyKind::BusyUnavailable => entry
                .params
                .push(ICalendarParameter::fbtype(ICalendarFreeBusyType::BusyUnavailable)),
        }
        freebusy.entries.push(entry);
    }
    calendar.children.push(freebusy);
    Ok(calendar.to_calendar().to_string())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::parse::parse;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 3, day, hour, 0, 0).unwrap()
    }

    fn calendar(body: &str) -> ParsedCalendar {
        let text = format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{body}END:VCALENDAR\r\n");
        parse(text.as_bytes(), &IcalLimits::default()).unwrap()
    }

    fn event(uid: &str, body: &str) -> String {
        format!("BEGIN:VEVENT\r\nUID:{uid}\r\n{body}END:VEVENT\r\n")
    }

    fn window() -> TimeRange {
        TimeRange::new(Some(at(1, 0)), Some(at(8, 0)))
    }

    #[test]
    fn transparent_and_cancelled_events_do_not_count() {
        let cal = calendar(&format!(
            "{}{}{}{}",
            event("a", "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n"),
            event(
                "b",
                "DTSTART:20270302T100000Z\r\nDTEND:20270302T110000Z\r\nTRANSP:TRANSPARENT\r\n"
            ),
            event(
                "c",
                "DTSTART:20270303T100000Z\r\nDTEND:20270303T110000Z\r\nSTATUS:CANCELLED\r\n"
            ),
            event(
                "d",
                "DTSTART:20270304T100000Z\r\nDTEND:20270304T110000Z\r\nSTATUS:TENTATIVE\r\nCLASS:PRIVATE\r\n"
            ),
        ));
        let found = busy_periods(&[&cal], &window(), &IcalLimits::default()).unwrap();
        assert_eq!(
            found,
            vec![
                BusyPeriod {
                    start: at(1, 10),
                    end: at(1, 11),
                    kind: BusyKind::Busy
                },
                BusyPeriod {
                    start: at(4, 10),
                    end: at(4, 11),
                    kind: BusyKind::BusyTentative
                },
            ]
        );
    }

    #[test]
    fn periods_merge_across_events_and_calendars() {
        let one = calendar(&format!(
            "{}{}",
            event("a", "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n"),
            event("b", "DTSTART:20270301T110000Z\r\nDTEND:20270301T120000Z\r\n"),
        ));
        let two = calendar(&event("c", "DTSTART:20270301T103000Z\r\nDTEND:20270301T133000Z\r\n"));
        let found = busy_periods(&[&one, &two], &window(), &IcalLimits::default()).unwrap();
        assert_eq!(
            found,
            vec![BusyPeriod {
                start: at(1, 10),
                end: Utc.with_ymd_and_hms(2027, 3, 1, 13, 30, 0).unwrap(),
                kind: BusyKind::Busy
            }]
        );
    }

    #[test]
    fn recurring_events_and_clipping_to_the_range() {
        let cal = calendar(&event(
            "r",
            "DTSTART:20270228T230000Z\r\nDTEND:20270301T010000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\n",
        ));
        let found = busy_periods(&[&cal], &window(), &IcalLimits::default()).unwrap();
        assert_eq!(
            found.first().unwrap().start,
            at(1, 0),
            "clipped to the start of the range"
        );
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn zero_length_events_block_nothing() {
        let cal = calendar(&event("z", "DTSTART:20270301T100000Z\r\nDTEND:20270301T100000Z\r\n"));
        assert_eq!(
            busy_periods(&[&cal], &window(), &IcalLimits::default()).unwrap().len(),
            0
        );
    }

    #[test]
    fn unbounded_ranges_are_refused() {
        let cal = calendar(&event("a", "DTSTART:20270301T100000Z\r\n"));
        let open = TimeRange::new(Some(at(1, 0)), None);
        assert!(busy_periods(&[&cal], &open, &IcalLimits::default()).is_err());
    }

    #[test]
    fn answers_render_as_vfreebusy() {
        let report = FreeBusyReport {
            organizer: Some(CalendarUserAddress::parse("mailto:anna@example.org").unwrap()),
            attendee: CalendarUserAddress::parse("mailto:bob@example.org").unwrap(),
            range: window(),
            periods: vec![
                BusyPeriod {
                    start: at(1, 10),
                    end: at(1, 11),
                    kind: BusyKind::Busy,
                },
                BusyPeriod {
                    start: at(2, 10),
                    end: at(2, 11),
                    kind: BusyKind::Busy,
                },
                BusyPeriod {
                    start: at(4, 10),
                    end: at(4, 11),
                    kind: BusyKind::BusyTentative,
                },
            ],
            dtstamp: at(1, 0),
            uid: Uid::parse("fb-1").unwrap(),
        };
        let text = render_freebusy(&report).unwrap().replace("\r\n ", "");
        assert!(text.contains("METHOD:REPLY\r\n"), "{text}");
        assert!(text.contains("BEGIN:VFREEBUSY\r\n"), "{text}");
        assert!(
            text.contains("FREEBUSY:20270301T100000Z/20270301T110000Z,20270302T100000Z/20270302T110000Z\r\n"),
            "{text}"
        );
        assert!(
            text.contains("FREEBUSY;FBTYPE=BUSY-TENTATIVE:20270304T100000Z/20270304T110000Z\r\n"),
            "{text}"
        );
        assert!(
            text.contains("DTSTART:20270301T000000Z\r\n") && text.contains("DTEND:20270308T000000Z\r\n"),
            "{text}"
        );
        assert!(text.contains("ORGANIZER:mailto:anna@example.org\r\n"), "{text}");
        assert!(text.contains("ATTENDEE:mailto:bob@example.org\r\n"), "{text}");
        let again = parse(text.as_bytes(), &IcalLimits::default());
        assert!(again.is_ok(), "{again:?}");
        let without_organizer = FreeBusyReport {
            organizer: None,
            ..report.clone()
        };
        assert!(!render_freebusy(&without_organizer).unwrap().contains("METHOD"));
        let open = FreeBusyReport {
            range: TimeRange::default(),
            ..report
        };
        assert!(render_freebusy(&open).is_err());
    }

    #[test]
    fn the_answer_for_a_collection_names_nobody() {
        let periods = [
            BusyPeriod {
                start: at(2, 9),
                end: at(2, 10),
                kind: BusyKind::Busy,
            },
            BusyPeriod {
                start: at(3, 9),
                end: at(3, 12),
                kind: BusyKind::BusyTentative,
            },
            BusyPeriod {
                start: at(4, 0),
                end: at(5, 0),
                kind: BusyKind::BusyUnavailable,
            },
        ];
        let uid = Uid::parse("fb-2").unwrap();
        let text = render_collection_freebusy(&window(), &periods, at(1, 0), &uid)
            .unwrap()
            .replace("\r\n ", "");
        for absent in ["METHOD", "ORGANIZER", "ATTENDEE"] {
            assert!(!text.contains(absent), "{absent} in {text}");
        }
        assert!(text.contains("UID:fb-2\r\n"), "{text}");
        assert!(text.contains("DTSTAMP:20270301T000000Z\r\n"), "{text}");
        assert!(
            text.contains("DTSTART:20270301T000000Z\r\n") && text.contains("DTEND:20270308T000000Z\r\n"),
            "{text}"
        );
        assert!(
            text.contains("FREEBUSY:20270302T090000Z/20270302T100000Z\r\n"),
            "{text}"
        );
        assert!(
            text.contains("FREEBUSY;FBTYPE=BUSY-TENTATIVE:20270303T090000Z/20270303T120000Z\r\n"),
            "{text}"
        );
        assert!(
            text.contains("FREEBUSY;FBTYPE=BUSY-UNAVAILABLE:20270304T000000Z/20270305T000000Z\r\n"),
            "{text}"
        );
        assert!(parse(text.as_bytes(), &IcalLimits::default()).is_ok(), "{text}");
        let empty = render_collection_freebusy(&window(), &[], at(1, 0), &uid).unwrap();
        assert!(!empty.contains("FREEBUSY:"), "{empty}");
        assert!(render_collection_freebusy(&TimeRange::default(), &periods, at(1, 0), &uid).is_err());
    }
}
