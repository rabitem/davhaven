//! Content hashes that ignore volatile properties (DTSTAMP, LAST-MODIFIED, SEQUENCE, PRODID).
//!
//! Two calendars with equal content hashes are the same event for the purpose of API and sync-engine upserts:
//! writing one over the other changes nothing (no new ETag, no sequence bump; PLAN 2.7). The hash is computed
//! over a canonical form (sorted properties and parameters, normalized values) so that formatting differences
//! do not matter.
//!
//! The ETag of stored bytes is a different thing: it is a hash of the bytes themselves and lives in
//! `davhaven_domain::ETag::from_bytes`.

use calcard::icalendar::ICalendarEntry;
use davhaven_domain::ContentHash;
use sha2::{Digest, Sha256};

use crate::calendar::{Node, Param, Prop};
use crate::error::IcalError;
use crate::parse::ParsedCalendar;

/// The properties that change on every edit without changing the content.
fn is_volatile(name: &Prop) -> bool {
    matches!(name, Prop::Dtstamp | Prop::LastModified | Prop::Sequence | Prop::Prodid)
}

/// The canonical text of a property: parameters sorted, written the way the serializer writes it. The
/// parameters named in `ignored` are left out.
pub(crate) fn canonical_entry(entry: &ICalendarEntry, ignored: &[Param]) -> String {
    let mut entry = entry.clone();
    entry.params.retain(|param| !ignored.contains(&param.name));
    entry.params.sort();
    let mut line = String::new();
    // Writing into a `String` cannot fail.
    let _ = entry.write_to(&mut line);
    line
}

/// The canonical text of a component: its properties (parameters sorted, volatile ones left out) in sorted
/// order, then its children in the order of their own canonical text.
pub(crate) fn canonical(node: &Node, out: &mut String) {
    canonical_without(node, out, &|_| false);
}

/// [`canonical`] that leaves out the properties `skip` names as well.
fn canonical_without(node: &Node, out: &mut String, skip: &dyn Fn(&ICalendarEntry) -> bool) {
    out.push_str("BEGIN:");
    out.push_str(node.kind.as_str());
    out.push('\n');
    let mut lines: Vec<String> = node
        .entries
        .iter()
        .filter(|entry| !is_volatile(&entry.name) && !skip(entry))
        .map(|entry| canonical_entry(entry, &[]))
        .collect();
    lines.sort();
    for line in lines {
        out.push_str(&line);
    }
    let mut children: Vec<String> = node
        .children
        .iter()
        .map(|child| {
            let mut text = String::new();
            canonical_without(child, &mut text, skip);
            text
        })
        .collect();
    children.sort();
    for child in children {
        out.push_str(&child);
    }
    out.push_str("END:");
    out.push_str(node.kind.as_str());
    out.push('\n');
}

/// The content hash of a calendar, ignoring `DTSTAMP`, `LAST-MODIFIED`, `SEQUENCE` and `PRODID`.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn content_hash(calendar: &ParsedCalendar) -> Result<ContentHash, IcalError> {
    digest_of(calendar, &|_| false)
}

/// Whether a property records the state of an alarm on one device: the acknowledgement of RFC 9074
/// (`ACKNOWLEDGED`) and the snooze and last-acknowledged marks of Thunderbird (`X-MOZ-LASTACK`,
/// `X-MOZ-SNOOZE-TIME` and its per-instance forms `X-MOZ-SNOOZE-TIME-{recurrence id}`).
fn is_alarm_state(entry: &ICalendarEntry) -> bool {
    let name = entry.name.as_str().to_ascii_uppercase();
    name == "ACKNOWLEDGED" || name == "X-MOZ-LASTACK" || name.starts_with("X-MOZ-SNOOZE-TIME")
}

/// [`content_hash`] that also ignores the properties that record the state of an alarm on a device
/// (`ACKNOWLEDGED`, `X-MOZ-LASTACK`, `X-MOZ-SNOOZE-TIME*`, wherever they appear).
///
/// Two calendars with equal hashes of this kind differ at most in acknowledgements and snoozes: a client that
/// only dismissed or snoozed a reminder of a calendar it may not write sends such a copy (ADR 0004, rule 2), which
/// the server answers without storing it.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn content_hash_ignoring_alarm_state(calendar: &ParsedCalendar) -> Result<ContentHash, IcalError> {
    digest_of(calendar, &is_alarm_state)
}

fn digest_of(calendar: &ParsedCalendar, skip: &dyn Fn(&ICalendarEntry) -> bool) -> Result<ContentHash, IcalError> {
    let mut text = String::new();
    canonical_without(&calendar.root, &mut text, skip);
    let digest = Sha256::digest(text.as_bytes());
    let bytes: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| IcalError::invalid("the digest has an unexpected length"))?;
    Ok(ContentHash::from_digest(bytes))
}

#[cfg(test)]
mod tests {
    use davhaven_domain::IcalLimits;

    use super::*;
    use crate::parse::parse;

    fn hash(text: &str) -> ContentHash {
        content_hash(&parse(text.as_bytes(), &IcalLimits::default()).unwrap()).unwrap()
    }

    const BASE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//A//EN\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTAMP:20270101T000000Z\r\n\
        SEQUENCE:1\r\nLAST-MODIFIED:20270101T000000Z\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\nSUMMARY:Hello\r\n\
        ATTENDEE;CN=A;PARTSTAT=ACCEPTED:mailto:a@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn volatile_properties_do_not_matter() {
        let changed = BASE
            .replace("DTSTAMP:20270101T000000Z", "DTSTAMP:20281231T235959Z")
            .replace("SEQUENCE:1", "SEQUENCE:9")
            .replace("LAST-MODIFIED:20270101T000000Z", "LAST-MODIFIED:20280101T000000Z")
            .replace("PRODID:-//A//EN", "PRODID:-//B//EN");
        assert_eq!(hash(BASE), hash(&changed));
    }

    #[test]
    fn formatting_does_not_matter() {
        let lf = BASE.replace("\r\n", "\n");
        assert_eq!(hash(BASE), hash(&lf));
        let reordered = BASE.replace(
            "SUMMARY:Hello\r\nATTENDEE;CN=A;PARTSTAT=ACCEPTED:mailto:a@example.org\r\n",
            "ATTENDEE;PARTSTAT=ACCEPTED;CN=A:mailto:a@example.org\r\nSUMMARY:Hello\r\n",
        );
        assert_eq!(hash(BASE), hash(&reordered));
        let folded = BASE.replace("SUMMARY:Hello", "SUMMARY:Hel\r\n lo");
        assert_eq!(hash(BASE), hash(&folded));
    }

    #[test]
    fn real_changes_change_the_hash() {
        assert_ne!(hash(BASE), hash(&BASE.replace("SUMMARY:Hello", "SUMMARY:Hallo")));
        assert_ne!(hash(BASE), hash(&BASE.replace("T100000", "T110000")));
        assert_ne!(
            hash(BASE),
            hash(&BASE.replace("PARTSTAT=ACCEPTED", "PARTSTAT=DECLINED"))
        );
        assert_ne!(hash(BASE), hash(&BASE.replace("UID:x", "UID:y")));
        assert_ne!(
            hash(BASE),
            hash(&BASE.replace(
                "END:VEVENT",
                "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT"
            ))
        );
    }

    #[test]
    fn the_order_of_overrides_does_not_matter() {
        let one = "BEGIN:VEVENT\r\nUID:x\r\nRECURRENCE-ID:20270302T100000Z\r\nSUMMARY:one\r\nEND:VEVENT\r\n";
        let two = "BEGIN:VEVENT\r\nUID:x\r\nRECURRENCE-ID:20270303T100000Z\r\nSUMMARY:two\r\nEND:VEVENT\r\n";
        let wrap = |a: &str, b: &str| format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{a}{b}END:VCALENDAR\r\n");
        assert_eq!(hash(&wrap(one, two)), hash(&wrap(two, one)));
    }

    #[test]
    fn alarm_state_is_ignored_by_its_own_hash_only() {
        let hash_ignoring = |text: &str| {
            content_hash_ignoring_alarm_state(&parse(text.as_bytes(), &IcalLimits::default()).unwrap()).unwrap()
        };
        let acknowledged = BASE.replace(
            "END:VEVENT",
            "X-MOZ-LASTACK:20270301T090000Z\r\nX-MOZ-SNOOZE-TIME-20270301T100000:20270301T091500Z\r\n\
             BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nACKNOWLEDGED:20270301T094000Z\r\nEND:VALARM\r\nEND:VEVENT",
        );
        let unacknowledged = BASE.replace(
            "END:VEVENT",
            "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT",
        );
        assert_ne!(
            hash(&acknowledged),
            hash(&unacknowledged),
            "the plain hash sees the state"
        );
        assert_eq!(hash_ignoring(&acknowledged), hash_ignoring(&unacknowledged));
        let lower = acknowledged.replace("X-MOZ-LASTACK", "x-moz-lastack");
        assert_eq!(
            hash_ignoring(&lower),
            hash_ignoring(&unacknowledged),
            "names are case-insensitive"
        );
        // Everything else still counts.
        let edited = acknowledged.replace("SUMMARY:Hello", "SUMMARY:Hallo");
        assert_ne!(hash_ignoring(&edited), hash_ignoring(&unacknowledged));
        let moved_trigger = acknowledged.replace("TRIGGER:-PT5M", "TRIGGER:-PT10M");
        assert_ne!(hash_ignoring(&moved_trigger), hash_ignoring(&unacknowledged));
    }

    #[test]
    fn hashes_are_64_hex_digits() {
        let value = hash(BASE);
        assert_eq!(value.as_str().len(), 64);
        assert!(value.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
