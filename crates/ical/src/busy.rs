//! Busy-only stripping of events for feeds and free-busy views.
//!
//! Busy-only views reveal that time is taken and nothing else (PLAN 2.13): the summary becomes a localized
//! "Busy", the UID is replaced by a keyed hash so that it cannot be correlated with other data, and every
//! property that could carry content (description, location, attendees, organizer, attachments, alarms, `X-`
//! properties) is removed. Timing properties (`DTSTART`, `DTEND`/`DURATION`, `RRULE`, `EXDATE`,
//! `RECURRENCE-ID`) stay so that recurrence still expands correctly; they keep only the parameters that say
//! how to read them (`VALUE`, `TZID`, `RANGE`), never a vendor parameter. The time zone definitions that stay
//! are rebuilt from their identifier and the timing of their observances, so a name, a comment or an `X-`
//! property of the definition does not reach a public feed either.

use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;

use calcard::icalendar::ICalendarEntry;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::calendar::{Kind, Moment, Node, Param, Prop, entry_for_moment, entry_for_text, entry_moment, param_text};
use crate::error::IcalError;
use crate::parse::ParsedCalendar;

/// How to strip a calendar to busy time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BusyOptions<'a> {
    /// The summary of the busy blocks, already localized ("Busy", "Beschäftigt").
    pub summary: &'a str,
    /// The secret key of the UID hash (HMAC-SHA256); the application derives it from its key ring for the feed.
    /// It must be stable per feed so that the hashed UIDs stay stable.
    pub uid_salt: &'a [u8],
}

impl fmt::Debug for BusyOptions<'_> {
    /// The key is a secret and never printed (`ENGINEERING_RULES` R6).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusyOptions")
            .field("summary", &self.summary)
            .field("uid_salt", &"<redacted>")
            .finish()
    }
}

/// The properties that stay in a busy component, in output order.
const KEPT: [Prop; 8] = [
    Prop::Dtstamp,
    Prop::Dtstart,
    Prop::Dtend,
    Prop::Duration,
    Prop::Rrule,
    Prop::Rdate,
    Prop::Exdate,
    Prop::RecurrenceId,
];

/// The parameters of a kept property that stay: the ones that say how to read the value.
fn is_kept_param(name: &Param) -> bool {
    matches!(name, Param::Value | Param::Tzid | Param::Range)
}

/// Strips `calendar` to its busy time. Returns `None` when the object contributes nothing: it is `TRANSPARENT`
/// or `CANCELLED` (skipped in busy-only views).
///
/// A cancelled or transparent override of an otherwise busy series removes its instance from the series, so
/// the time it freed does not show as busy.
///
/// # Errors
///
/// [`IcalError::Invalid`] when a value of the calendar cannot be written back.
pub fn strip_to_busy(
    calendar: &ParsedCalendar,
    options: &BusyOptions<'_>,
) -> Result<Option<ParsedCalendar>, IcalError> {
    let root = &calendar.root;
    let events: Vec<&Node> = root.children.iter().filter(|node| node.kind == Kind::VEvent).collect();
    let master = events.iter().copied().find(|node| !node.is_override());
    let master_busy = master.is_some_and(is_busy);
    let mut output: Vec<Node> = Vec::new();
    let mut freed: Vec<Moment> = Vec::new();
    if let (Some(master), true) = (master, master_busy) {
        output.push(busy_component(master, options)?);
    }
    for node in events.iter().copied().filter(|node| node.is_override()) {
        if is_busy(node) {
            output.push(busy_component(node, options)?);
        } else if master_busy && let Some(rid) = node.first(&Prop::RecurrenceId).and_then(entry_moment) {
            freed.push(rid);
        }
    }
    if output.is_empty() {
        return Ok(None);
    }
    if let Some(first) = output.first_mut()
        && master_busy
    {
        for rid in &freed {
            first.entries.push(entry_for_moment("EXDATE", rid)?);
        }
    }
    let mut result = Node::new(Kind::VCalendar);
    result.entries.push(entry_for_text("VERSION", "2.0")?);
    result.entries.push(entry_for_text("PRODID", crate::PRODID)?);
    let used = used_tzids(&output);
    for zone in root.children.iter().filter(|node| node.kind == Kind::VTimezone) {
        if zone.text(&Prop::Tzid).is_some_and(|tzid| used.contains(&tzid)) {
            result.children.push(clean_timezone(zone));
        }
    }
    result.children.extend(output);
    Ok(Some(ParsedCalendar::from_root(result)))
}

/// Whether a component blocks time: it is neither `TRANSPARENT` nor `CANCELLED`.
fn is_busy(node: &Node) -> bool {
    node.transparency().as_deref() != Some("TRANSPARENT") && node.status().as_deref() != Some("CANCELLED")
}

fn busy_component(source: &Node, options: &BusyOptions<'_>) -> Result<Node, IcalError> {
    let mut node = Node::new(Kind::VEvent);
    let uid = source.uid().unwrap_or_default();
    node.entries
        .push(entry_for_text("UID", &hashed_uid(&uid, options.uid_salt)?)?);
    for name in &KEPT {
        node.entries.extend(source.all(name).map(|entry| {
            let mut kept = entry.clone();
            kept.params.retain(|param| is_kept_param(&param.name));
            kept
        }));
    }
    node.entries.push(entry_for_text("SUMMARY", options.summary)?);
    Ok(node)
}

/// A time zone definition reduced to what evaluates it: the identifier and, per observance, the start, the
/// offsets and the recurrence of the transitions. Names, comments and every other property are dropped.
fn clean_timezone(zone: &Node) -> Node {
    let mut clean = Node::new(Kind::VTimezone);
    clean.entries.extend(zone.all(&Prop::Tzid).map(|entry| {
        let mut kept = entry.clone();
        kept.params.clear();
        kept
    }));
    for observance in zone
        .children
        .iter()
        .filter(|child| matches!(child.kind, Kind::Standard | Kind::Daylight))
    {
        let mut kept = Node::new(observance.kind.clone());
        for name in [
            Prop::Dtstart,
            Prop::Tzoffsetfrom,
            Prop::Tzoffsetto,
            Prop::Rrule,
            Prop::Rdate,
        ] {
            kept.entries.extend(observance.all(&name).map(|entry| {
                let mut simple = entry.clone();
                simple.params.retain(|param| is_kept_param(&param.name));
                simple
            }));
        }
        clean.children.push(kept);
    }
    clean
}

/// The keyed, hex encoded HMAC-SHA256 of a UID (first 128 bits).
fn hashed_uid(uid: &str, key: &[u8]) -> Result<String, IcalError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| IcalError::invalid("the busy feed key is not usable"))?;
    mac.update(uid.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        // Writing into a `String` cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

fn used_tzids(components: &[Node]) -> BTreeSet<String> {
    components
        .iter()
        .flat_map(|node| node.entries.iter())
        .filter_map(|entry: &ICalendarEntry| param_text(entry, &Param::Tzid))
        .collect()
}

#[cfg(test)]
mod tests {
    use davhaven_domain::IcalLimits;

    use super::*;
    use crate::parse::parse;
    use crate::serialize::serialize;

    fn parsed(text: &str) -> ParsedCalendar {
        parse(text.as_bytes(), &IcalLimits::default()).unwrap()
    }

    const OPTIONS: BusyOptions<'static> = BusyOptions {
        summary: "Busy",
        uid_salt: b"feed-salt",
    };

    const SECRET: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//X//EN\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n\
        BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
        BEGIN:VEVENT\r\nUID:secret-uid\r\nDTSTAMP:20270101T000000Z\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\n\
        DTEND;TZID=Europe/Berlin:20270301T110000\r\nRRULE:FREQ=WEEKLY;COUNT=3\r\nSUMMARY:Salary talk\r\nDESCRIPTION:Private\r\n\
        LOCATION:Room 7\r\nORGANIZER:mailto:boss@example.org\r\nATTENDEE:mailto:me@example.org\r\nCLASS:CONFIDENTIAL\r\n\
        X-SECRET:1\r\nATTACH:https://example.org/file\r\nSTATUS:CONFIRMED\r\n\
        BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nDESCRIPTION:alarm\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn content_is_removed_and_timing_stays() {
        let stripped = strip_to_busy(&parsed(SECRET), &OPTIONS).unwrap().unwrap();
        let text = serialize(&stripped).unwrap();
        for leaked in [
            "secret-uid",
            "Salary",
            "Private",
            "Room 7",
            "boss@",
            "me@",
            "X-SECRET",
            "ATTACH",
            "VALARM",
            "CONFIDENTIAL",
            "alarm",
        ] {
            assert!(!text.contains(leaked), "{leaked} leaked:\n{text}");
        }
        assert!(text.contains("SUMMARY:Busy\r\n"), "{text}");
        assert!(
            text.contains("DTSTART;TZID=Europe/Berlin:20270301T100000\r\n"),
            "{text}"
        );
        assert!(text.contains("DTEND;TZID=Europe/Berlin:20270301T110000\r\n"), "{text}");
        assert!(text.contains("RRULE:FREQ=WEEKLY;COUNT=3\r\n"), "{text}");
        assert!(text.contains("BEGIN:VTIMEZONE"), "the used time zone stays:\n{text}");
    }

    #[test]
    fn hashed_uids_are_stable_per_salt_and_differ_across_salts() {
        let one = serialize(&strip_to_busy(&parsed(SECRET), &OPTIONS).unwrap().unwrap()).unwrap();
        let again = serialize(&strip_to_busy(&parsed(SECRET), &OPTIONS).unwrap().unwrap()).unwrap();
        assert_eq!(one, again);
        let other = BusyOptions {
            uid_salt: b"another",
            ..OPTIONS
        };
        let different = serialize(&strip_to_busy(&parsed(SECRET), &other).unwrap().unwrap()).unwrap();
        assert_ne!(one, different);
        let uid_line = one.lines().find(|line| line.starts_with("UID:")).unwrap();
        assert_eq!(uid_line.len(), "UID:".len() + 32);
    }

    #[test]
    fn transparent_and_cancelled_objects_contribute_nothing() {
        let transparent = SECRET.replace("STATUS:CONFIRMED", "TRANSP:TRANSPARENT");
        assert!(strip_to_busy(&parsed(&transparent), &OPTIONS).unwrap().is_none());
        let cancelled = SECRET.replace("STATUS:CONFIRMED", "STATUS:CANCELLED");
        assert!(strip_to_busy(&parsed(&cancelled), &OPTIONS).unwrap().is_none());
        let todo = "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t\r\nDUE:20270301T100000Z\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        assert!(strip_to_busy(&parsed(todo), &OPTIONS).unwrap().is_none());
    }

    #[test]
    fn a_cancelled_override_frees_its_instance() {
        let text = SECRET.replace(
            "END:VEVENT\r\nEND:VCALENDAR\r\n",
            "END:VEVENT\r\nBEGIN:VEVENT\r\nUID:secret-uid\r\nRECURRENCE-ID;TZID=Europe/Berlin:20270308T100000\r\n\
             DTSTART;TZID=Europe/Berlin:20270308T100000\r\nDTEND;TZID=Europe/Berlin:20270308T110000\r\nSTATUS:CANCELLED\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let stripped = strip_to_busy(&parsed(&text), &OPTIONS).unwrap().unwrap();
        let out = serialize(&stripped).unwrap();
        assert!(out.contains("EXDATE;TZID=Europe/Berlin:20270308T100000\r\n"), "{out}");
        assert_eq!(out.matches("BEGIN:VEVENT").count(), 1, "{out}");
    }

    #[test]
    fn a_busy_override_of_a_transparent_series_stands_alone() {
        let text = SECRET.replace("STATUS:CONFIRMED", "TRANSP:TRANSPARENT").replace(
            "END:VEVENT\r\nEND:VCALENDAR\r\n",
            "END:VEVENT\r\nBEGIN:VEVENT\r\nUID:secret-uid\r\nRECURRENCE-ID;TZID=Europe/Berlin:20270308T100000\r\n\
             DTSTART;TZID=Europe/Berlin:20270308T120000\r\nDTEND;TZID=Europe/Berlin:20270308T130000\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let stripped = strip_to_busy(&parsed(&text), &OPTIONS).unwrap().unwrap();
        let out = serialize(&stripped).unwrap();
        assert_eq!(out.matches("BEGIN:VEVENT").count(), 1, "{out}");
        assert!(
            out.contains("RECURRENCE-ID;TZID=Europe/Berlin:20270308T100000"),
            "{out}"
        );
    }

    #[test]
    fn kept_properties_lose_every_vendor_parameter() {
        let text = SECRET
            .replace(
                "DTSTART;TZID=Europe/Berlin:20270301T100000",
                "DTSTART;X-SECRET=leaks;TZID=Europe/Berlin;X-APPLE-TRAVEL=1:20270301T100000",
            )
            .replace(
                "RRULE:FREQ=WEEKLY;COUNT=3",
                "RRULE;X-TOKEN=abc:FREQ=WEEKLY;COUNT=3\r\nEXDATE;X-NOTE=private;TZID=Europe/Berlin:20270308T100000",
            );
        let stripped = strip_to_busy(&parsed(&text), &OPTIONS).unwrap().unwrap();
        let out = serialize(&stripped).unwrap();
        assert!(
            !out.contains("X-SECRET") && !out.contains("X-TOKEN") && !out.contains("X-NOTE"),
            "{out}"
        );
        assert!(!out.contains("X-APPLE"), "{out}");
        assert!(out.contains("DTSTART;TZID=Europe/Berlin:20270301T100000\r\n"), "{out}");
        assert!(out.contains("EXDATE;TZID=Europe/Berlin:20270308T100000\r\n"), "{out}");
    }

    #[test]
    fn the_time_zone_that_stays_is_rebuilt_from_its_timing() {
        let text = SECRET.replace(
            "BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n",
            "BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nCOMMENT:Salary talk room\r\nX-SECRET-ZONE:1\r\nTZURL:https://example.org/secret\r\n",
        )
        .replace(
            "BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\n",
            "BEGIN:STANDARD\r\nTZNAME:Secret time\r\nCOMMENT:Hidden\r\nX-ZONE-NOTE:2\r\nDTSTART:19701025T030000\r\n",
        );
        let stripped = strip_to_busy(&parsed(&text), &OPTIONS).unwrap().unwrap();
        let out = serialize(&stripped).unwrap();
        for leaked in [
            "Salary talk room",
            "X-SECRET-ZONE",
            "TZURL",
            "Secret time",
            "Hidden",
            "X-ZONE-NOTE",
        ] {
            assert!(!out.contains(leaked), "{leaked} leaked:\n{out}");
        }
        assert!(
            out.contains("TZID:Europe/Berlin\r\n")
                && out.contains("TZOFFSETFROM:+0200\r\n")
                && out.contains("TZOFFSETTO:+0100\r\n")
                && out.contains("DTSTART:19701025T030000\r\n"),
            "the zone still evaluates:\n{out}"
        );
    }

    #[test]
    fn the_key_is_never_printed_and_the_hash_is_keyed() {
        let shown = format!("{OPTIONS:?}");
        assert!(
            !shown.contains("feed-salt") && shown.contains("Busy") && shown.contains("redacted"),
            "{shown}"
        );
        // The same UID under the same key hashes the same; another key gives another value, and the empty key is
        // still a key.
        let one = hashed_uid("uid", b"key").unwrap();
        assert_eq!(one, hashed_uid("uid", b"key").unwrap());
        assert_ne!(one, hashed_uid("uid", b"other").unwrap());
        assert_ne!(one, hashed_uid("other", b"key").unwrap());
        assert_eq!(hashed_uid("uid", b"").unwrap().len(), 32);
        assert!(one.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
