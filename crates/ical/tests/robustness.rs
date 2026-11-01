//! Robustness: no input makes any entry point panic or loop (PLAN L1 "never-panic parse", R9).
//!
//! Inputs are arbitrary bytes, mutated corpus files and random assemblies of iCalendar lines that parse often
//! enough to reach validation, expansion, filters, projection and iTIP. Whatever parses is pushed through every
//! public function; the property is that none of them panics and that whatever is accepted round-trips.
//! `PROPTEST_CASES` raises the number of cases.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use davhaven_domain::IcalLimits;
use davhaven_ical::filter::{CalendarFilter, CompFilter, validate_filter};
use davhaven_ical::tz::{render_vtimezone, resolve_tzid, windows_to_iana};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

#[path = "support/exercise.rs"]
mod support;

use support::{assert_round_trip, exercise, small_limits, wide_range};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus")
}

fn corpus_files() -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    for directory in [corpus(), corpus().join("imip"), corpus().join("rejected")] {
        for entry in fs::read_dir(directory).unwrap().filter_map(Result::ok) {
            if entry.path().extension().is_some_and(|extension| extension == "ics") {
                found.push(fs::read(entry.path()).unwrap());
            }
        }
    }
    found.sort();
    found
}

const LINES: [&str; 60] = [
    "BEGIN:VEVENT",
    "END:VEVENT",
    "BEGIN:VTODO",
    "END:VTODO",
    "BEGIN:VALARM",
    "END:VALARM",
    "BEGIN:VTIMEZONE",
    "END:VTIMEZONE",
    "BEGIN:STANDARD",
    "END:STANDARD",
    "BEGIN:DAYLIGHT",
    "END:DAYLIGHT",
    "UID:fuzz",
    "UID:other",
    "DTSTAMP:20270101T000000Z",
    "DTSTART:20270301T100000Z",
    "DTSTART;TZID=Europe/Berlin:20270301T100000",
    "DTSTART;TZID=W. Europe Standard Time:20270301T100000",
    "DTSTART;TZID=Custom:20270301T100000",
    "DTSTART;VALUE=DATE:20270301",
    "DTSTART:20270301T100000",
    "DTEND:20270301T110000Z",
    "DTEND;VALUE=DATE:20270302",
    "DUE:20270303T100000Z",
    "DURATION:PT1H",
    "DURATION:-P1D",
    "RRULE:FREQ=DAILY;COUNT=5",
    "RRULE:FREQ=WEEKLY;BYDAY=MO,WE;UNTIL=20271231T000000Z",
    "RRULE:FREQ=MONTHLY;BYDAY=-1FR",
    "RRULE:FREQ=YEARLY;BYWEEKNO=20;BYDAY=MO",
    "RRULE:FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=30",
    "RRULE:FREQ=HOURLY;COUNT=100000",
    "RRULE:FREQ=SECONDLY",
    "RRULE:FREQ=DAILY;BYSETPOS=1",
    "RRULE:FREQ=DAILY",
    "RDATE:20270305T100000Z",
    "RDATE;VALUE=PERIOD:20270305T100000Z/PT2H",
    "EXDATE:20270302T100000Z",
    "RECURRENCE-ID:20270302T100000Z",
    "RECURRENCE-ID;RANGE=THISANDFUTURE:20270303T100000Z",
    "ORGANIZER;CN=Org:mailto:org@example.org",
    "ATTENDEE;PARTSTAT=ACCEPTED:mailto:guest@example.org",
    "ATTENDEE;CN=\"Two, Three\";RSVP=TRUE:mailto:two@example.org",
    "SUMMARY:Fuzz\\, test",
    "STATUS:CANCELLED",
    "TRANSP:TRANSPARENT",
    "SEQUENCE:3",
    "SEQUENCE:x",
    "ACTION:DISPLAY",
    "TRIGGER:-PT15M",
    "TRIGGER;VALUE=DATE-TIME:20270301T080000Z",
    "REPEAT:3",
    "TZID:Custom",
    "TZOFFSETFROM:+0100",
    "TZOFFSETTO:+0200",
    "METHOD:REQUEST",
    "ATTACH;ENCODING=BASE64;VALUE=BINARY:SGVsbG8=",
    "X-CUSTOM;X-P=1:value",
    "GEO:48.1;11.5",
    "CATEGORIES:a,b",
];

fn assembled(lines: &[usize]) -> Vec<u8> {
    let mut text = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\n");
    for &line in lines {
        text.push_str(LINES[line % LINES.len()]);
        text.push_str("\r\n");
    }
    text.push_str("END:VCALENDAR\r\n");
    text.into_bytes()
}

/// A wrapper that opens one event so that most assemblies are structurally valid.
fn event_assembled(lines: &[usize]) -> Vec<u8> {
    let mut text =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:fuzz\r\nDTSTART:20270301T100000Z\r\n");
    for &line in lines {
        let chosen = LINES[line % LINES.len()];
        if chosen.starts_with("BEGIN:") || chosen.starts_with("END:") || chosen.starts_with("UID:") {
            continue;
        }
        text.push_str(chosen);
        text.push_str("\r\n");
    }
    text.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    text.into_bytes()
}

#[derive(Debug, Clone)]
enum Mutation {
    Flip(usize, u8),
    Delete(usize, usize),
    Insert(usize, Vec<u8>),
    Truncate(usize),
    Duplicate(usize, usize),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Flip(at, byte)),
        (any::<usize>(), 0..64_usize).prop_map(|(at, length)| Mutation::Delete(at, length)),
        (any::<usize>(), prop::collection::vec(any::<u8>(), 0..16)).prop_map(|(at, bytes)| Mutation::Insert(at, bytes)),
        any::<usize>().prop_map(Mutation::Truncate),
        (any::<usize>(), 0..200_usize).prop_map(|(at, length)| Mutation::Duplicate(at, length)),
    ]
}

fn mutate(mut bytes: Vec<u8>, mutations: &[Mutation]) -> Vec<u8> {
    for mutation in mutations {
        if bytes.is_empty() {
            break;
        }
        let len = bytes.len();
        match mutation {
            Mutation::Flip(at, byte) => bytes[at % len] ^= byte | 1,
            Mutation::Delete(at, length) => {
                let from = at % len;
                let to = (from + length).min(len);
                bytes.drain(from..to);
            }
            Mutation::Insert(at, inserted) => {
                let from = at % (len + 1);
                bytes.splice(from..from, inserted.iter().copied());
            }
            Mutation::Truncate(at) => bytes.truncate(at % len),
            Mutation::Duplicate(at, length) => {
                let from = at % len;
                let to = (from + length).min(len);
                let copy: Vec<u8> = bytes[from..to].to_vec();
                bytes.splice(to..to, copy);
            }
        }
    }
    bytes
}

/// Failing cases are written next to this file (`robustness.proptest-regressions`) and replayed first.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..3000)) {
        exercise(&bytes);
    }

    #[test]
    fn arbitrary_text_never_panics(text in "\\PC{0,1500}") {
        exercise(text.as_bytes());
    }

    #[test]
    fn mutated_corpus_files_never_panic(
        file in any::<usize>(),
        mutations in prop::collection::vec(mutation(), 1..8),
    ) {
        let files = corpus_files();
        let original = files[file % files.len()].clone();
        exercise(&mutate(original, &mutations));
    }

    #[test]
    fn assembled_documents_never_panic(lines in prop::collection::vec(0..LINES.len(), 0..30)) {
        exercise(&assembled(&lines));
    }

    #[test]
    fn assembled_events_never_panic(lines in prop::collection::vec(0..LINES.len(), 0..20)) {
        exercise(&event_assembled(&lines));
    }

    #[test]
    fn zone_names_never_panic(name in "\\PC{0,80}") {
        let _ = resolve_tzid(&name);
        let _ = windows_to_iana(&name);
        let from = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let until = Utc.with_ymd_and_hms(2028, 1, 1, 0, 0, 0).unwrap();
        if let Ok(Some(zone)) = resolve_tzid(&name) {
            prop_assert!(render_vtimezone(zone, from, until).is_ok());
        }
    }

    #[test]
    fn filters_are_validated_without_panicking(depth in 0..40_usize, name in "[A-Za-z]{0,10}") {
        let mut filter = CompFilter {
            name: name.clone(),
            is_not_defined: false,
            time_range: Some(wide_range()),
            prop_filters: Vec::new(),
            comp_filters: Vec::new(),
        };
        for _ in 0..depth {
            filter = CompFilter {
                name: name.clone(),
                is_not_defined: false,
                time_range: None,
                prop_filters: Vec::new(),
                comp_filters: vec![filter],
            };
        }
        let _ = validate_filter(&CalendarFilter { root: filter }, &IcalLimits::default());
    }
}

#[test]
fn the_corpus_never_panics_unmutated() {
    for bytes in corpus_files() {
        exercise(&bytes);
    }
}

/// The characters that turned out to matter: the separators of the content line, the escapes, the quote, and what the
/// parser reads differently from the scan (Unicode line separators) or that make a value nearly valid (digits and
/// signs after a date or an offset).
const EDGE_CHARACTERS: [&str; 14] = [
    ";", ",", "\\", "\"", ":", "=", "\\n", "^", "'", "2", "+", "-", "\u{85}", "\u{2028}",
];

/// Every distinct content line of the corpus, unfolded, without the lines that open and close components.
fn corpus_lines() -> std::collections::BTreeSet<String> {
    let mut lines = std::collections::BTreeSet::new();
    for bytes in corpus_files() {
        let text = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
        let mut logical = String::new();
        for raw in text.split('\n') {
            if let Some(continuation) = raw.strip_prefix([' ', '\t']) {
                logical.push_str(continuation);
                continue;
            }
            lines.insert(std::mem::take(&mut logical));
            logical.push_str(raw);
        }
        lines.insert(logical);
    }
    lines.retain(|line| {
        let upper = line.to_ascii_uppercase();
        !line.is_empty() && !upper.starts_with("BEGIN:") && !upper.starts_with("END:")
    });
    lines
}

/// Backlog 45 and 51: a parameter name with a backslash in it, a time zone offset of one digit, a date with a sign
/// after it were all accepted and then written as something else. Every content line of the corpus, with every one
/// of these characters at its start, after its first `;` and at its end, is either refused or survives the round trip.
#[test]
fn an_edge_character_in_any_corpus_line_is_refused_or_survives_the_round_trip() {
    let limits = small_limits();
    let mut accepted = 0_usize;
    for line in corpus_lines() {
        let after_first_semicolon = line.find(';').map(|at| at + 1);
        let positions = [Some(0), after_first_semicolon, Some(line.len())];
        for at in positions.into_iter().flatten() {
            for edge in EDGE_CHARACTERS {
                let mut changed = line.clone();
                changed.insert_str(at, edge);
                let text = format!(
                    "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:edge\r\n{changed}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
                );
                if let Ok(parsed) = davhaven_ical::parse::accept(text.as_bytes(), &limits) {
                    accepted += 1;
                    assert_round_trip(&parsed, &limits);
                }
            }
        }
    }
    assert!(
        accepted > 1000,
        "the sweep accepted only {accepted} documents: it no longer reaches the writer"
    );
}

/// Backlog 51: a value that is longer when the server writes it. Commas, semicolons and backslashes that a client
/// sent without a backslash are written with one, so a value of 40,000 characters is written as 80,000, above
/// the limit of 65,536. What is accepted must survive the writer under the limits of the input, so such a value is
/// refused when it comes in, and one whose written form fits is accepted and round-trips.
#[test]
fn a_value_that_grows_when_it_is_written_is_refused_or_survives_the_round_trip() {
    let limits = small_limits();
    let mut accepted = 0_usize;
    for special in [",", ";", "\\", ",;"] {
        for count in [1_usize, 10_000, 16_000, 20_000, 32_767, 32_769, 40_000, 65_000] {
            let value = special.repeat(count);
            let text = format!(
                "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:grows\r\nDESCRIPTION:{value}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
            );
            exercise(text.as_bytes());
            if let Ok(parsed) = davhaven_ical::parse::accept(text.as_bytes(), &limits) {
                accepted += 1;
                assert_round_trip(&parsed, &limits);
            }
        }
    }
    assert!(accepted >= 8, "only {accepted} of the values were accepted");
}
proptest! {
    #![proptest_config(config())]

    /// The same with several edits at places of the whole document that proptest chooses, whole corpus files.
    #[test]
    fn edge_characters_in_corpus_files_are_refused_or_survive_the_round_trip(
        file in any::<usize>(),
        edits in prop::collection::vec((any::<usize>(), 0..EDGE_CHARACTERS.len()), 1..4),
    ) {
        let files = corpus_files();
        let mut bytes = files[file % files.len()].clone();
        for (at, edge) in edits {
            let at = at % (bytes.len() + 1);
            bytes.splice(at..at, EDGE_CHARACTERS[edge].bytes());
        }
        exercise(&bytes);
    }
}
