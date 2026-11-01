//! The iTIP golden set (PLAN 4.2): every directory of `crates/fixtures/data/itip/` holds the organizer's
//! stored copy (`old.ics`, absent for a create) and the version the client sends (`new.ics`). The test runs the
//! scheduling rules of PLAN 2.8 over the pair and compares everything the application would act on, byte for
//! byte, with the files next to the inputs:
//!
//! * `diff.txt`: the classification of every instance, added and removed attendees, cancelled instances;
//! * `organizer.ics`: the organizer copy to store (`SEQUENCE` raised, answers as the server holds them);
//! * `request-<name>.ics`: the `REQUEST` for an attendee;
//! * `cancel-<name>.ics`: the `CANCEL` of the whole object for an attendee;
//! * `cancel-instance-<n>-<name>.ics`: the `CANCEL` of one instance for an attendee.
//!
//! A scenario with a `reply.ics` is one where an attendee's `REPLY` reached the organizer's copy after the client
//! read it: the reply is applied to `old.ics` first (`after-reply.ics` is the result, `reply.txt` what the
//! application learns from it) and `new.ics`, the stale version the client sends, is compared with that.
//!
//! `<name>` is the local part of the attendee's address. `UPDATE_GOLDEN=1` rewrites the files; the change is then
//! reviewed in the diff like any other. The expectations at the bottom (`the_scenarios_encode_the_rules_of_the_plan`
//! and `the_organizer_copies_follow_the_ownership_rules`) are written by hand and do not change with the files.
//! The application's scheduling matrix and the calendar API read the same directories.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use davhaven_domain::{CalendarUserAddress, EventTime, IcalLimits, ItipMethod, PartStat, ScheduleAgent};
use davhaven_ical::itip::{
    ChangeClass, ItipDiff, MessageScope, MessageSpec, apply_organizer_changes, apply_reply_with, build_message,
    parse_message, rewrite_addresses,
};
use davhaven_ical::merge::to_event_data;
use davhaven_ical::parse::ParsedCalendar;
use davhaven_ical::serialize::serialize;
use davhaven_ical::validate::parse_and_validate;

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/data/itip")
}

fn limits() -> IcalLimits {
    IcalLimits::default()
}

/// The moment the messages of the scenarios are built: later than the `DTSTAMP` of every stored copy.
fn send_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 2, 2, 9, 0, 0).unwrap()
}

fn updating() -> bool {
    std::env::var_os("UPDATE_GOLDEN").is_some()
}

fn load(path: &Path) -> ParsedCalendar {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    parse_and_validate(&bytes, &limits())
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .calendar
}

fn render_time(time: &EventTime) -> String {
    match time {
        EventTime::Date(date) => format!("date {date}"),
        EventTime::Floating(local) => format!("floating {}", local.format("%Y-%m-%dT%H:%M:%S")),
        EventTime::Zoned { local, zone } => format!("{} {}", zone.as_str(), local.format("%Y-%m-%dT%H:%M:%S")),
        EventTime::Utc(instant) => format!("utc {}", instant.format("%Y-%m-%dT%H:%M:%SZ")),
    }
}

fn render_diff(diff: &ItipDiff) -> String {
    let mut text = String::new();
    for instance in &diff.instances {
        let who = instance
            .recurrence_id
            .as_ref()
            .map_or_else(|| "master".to_owned(), |rid| format!("instance {}", render_time(rid)));
        let class = match instance.change {
            ChangeClass::Created => "created",
            ChangeClass::Significant => "significant",
            ChangeClass::Insignificant => "insignificant",
            ChangeClass::Removed => "removed",
            ChangeClass::Unchanged => "unchanged",
        };
        let names = if instance.changed_properties.is_empty() {
            "-".to_owned()
        } else {
            instance.changed_properties.join(", ")
        };
        writeln!(text, "{who}: {class} [{names}]").unwrap();
    }
    let list = |items: Vec<String>| {
        if items.is_empty() {
            "-".to_owned()
        } else {
            items.join(", ")
        }
    };
    writeln!(
        text,
        "added attendees: {}",
        list(diff.added_attendees.iter().map(ToString::to_string).collect())
    )
    .unwrap();
    writeln!(
        text,
        "removed attendees: {}",
        list(diff.removed_attendees.iter().map(ToString::to_string).collect())
    )
    .unwrap();
    writeln!(
        text,
        "cancelled instances: {}",
        list(diff.cancelled_instances.iter().map(render_time).collect())
    )
    .unwrap();
    writeln!(text, "needs sequence bump: {}", diff.needs_sequence_bump).unwrap();
    text
}

/// The name of an attendee in file names: the local part of the address.
fn local_name(address: &CalendarUserAddress) -> String {
    let text = address.as_str();
    let text = text.strip_prefix("mailto:").unwrap_or(text);
    text.split('@').next().unwrap_or(text).to_owned()
}

/// The addresses a scenario maps before anything leaves the server (`addresses.txt`, one `from => to` per line):
/// principal URLs and `urn:uuid` addresses become `mailto` addresses (PLAN 2.6).
type AddressMap = Vec<(CalendarUserAddress, CalendarUserAddress)>;

fn load_addresses(dir: &Path) -> AddressMap {
    let Ok(text) = fs::read_to_string(dir.join("addresses.txt")) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (from, to) = line
                .split_once(" => ")
                .unwrap_or_else(|| panic!("addresses.txt: `{line}` is not `from => to`"));
            (
                CalendarUserAddress::parse(from.trim()).expect("a calendar user address"),
                CalendarUserAddress::parse(to.trim()).expect("a calendar user address"),
            )
        })
        .collect()
}

/// An address as the message shows it.
fn mapped(address: &CalendarUserAddress, map: &AddressMap) -> CalendarUserAddress {
    map.iter()
        .find(|(from, _)| from == address)
        .map_or_else(|| address.clone(), |(_, to)| to.clone())
}

/// A copy with the addresses of the scenario mapped, the way the application does before it builds a message.
fn on_the_wire(calendar: &ParsedCalendar, map: &AddressMap) -> ParsedCalendar {
    if map.is_empty() {
        return calendar.clone();
    }
    rewrite_addresses(calendar, &|address| {
        map.iter().find(|(from, _)| from == address).map(|(_, to)| to.clone())
    })
    .expect("the addresses are mapped")
}

/// The attendees of the master component who get messages: not the organizer's own line, and only those the
/// server schedules (`SCHEDULE-AGENT` other than `SERVER` means their client does it, PLAN 2.8).
fn recipients(calendar: &ParsedCalendar) -> Vec<CalendarUserAddress> {
    let data = to_event_data(calendar, None).expect("master data");
    let organizer = data.organizer.map(|organizer| organizer.address);
    data.attendees
        .unwrap_or_default()
        .into_iter()
        .filter(|attendee| {
            attendee
                .schedule_agent
                .is_none_or(|agent| agent == ScheduleAgent::Server)
        })
        .map(|attendee| attendee.address)
        .filter(|address| Some(address) != organizer.as_ref())
        .collect()
}

fn is_cancelled(calendar: &ParsedCalendar) -> bool {
    to_event_data(calendar, None)
        .expect("master data")
        .status
        .is_some_and(|status| status.as_ical() == "CANCELLED")
}

fn message(
    source: &ParsedCalendar,
    method: ItipMethod,
    recipient: &CalendarUserAddress,
    scope: MessageScope,
) -> String {
    let built = build_message(
        source,
        &MessageSpec {
            scope,
            ..MessageSpec::new(method, recipient.clone(), send_time())
        },
    )
    .unwrap_or_else(|error| panic!("{} for {recipient}: {error}", method.as_ical()));
    let text = serialize(&built.calendar).expect("serializable message");
    // What leaves the server is a valid message of the right method, free of private data.
    let parsed = parse_message(text.as_bytes(), &limits()).expect("a valid message");
    assert_eq!(parsed.method, method);
    for forbidden in ["SCHEDULE-", "X-APPLE-", "X-MOZ-", "BEGIN:VALARM"] {
        assert!(!text.contains(forbidden), "{forbidden} leaks into\n{text}");
    }
    // Every component is stamped at the moment of sending, never with the stamp of the stored copy.
    let stamps: Vec<&str> = text.lines().filter(|line| line.starts_with("DTSTAMP")).collect();
    assert!(!stamps.is_empty(), "{text}");
    assert!(stamps.iter().all(|line| *line == "DTSTAMP:20270202T090000Z"), "{text}");
    text
}

/// What the application learns from applying a reply.
fn render_reply(applied: &davhaven_ical::itip::ReplyApplication) -> String {
    let mut text = String::new();
    writeln!(text, "attendee: {}", applied.attendee).unwrap();
    writeln!(text, "answer: {}", applied.partstat.as_ical()).unwrap();
    let instances: Vec<String> = applied.instances.iter().map(render_time).collect();
    writeln!(
        text,
        "instances: {}",
        if instances.is_empty() {
            "-".to_owned()
        } else {
            instances.join(", ")
        }
    )
    .unwrap();
    writeln!(text, "sequence matches: {}", applied.sequence_matches).unwrap();
    writeln!(text, "comment: {}", applied.comment.as_deref().unwrap_or("-")).unwrap();
    text
}

/// Everything the scenario produces, in file name order. `stored` is the organizer copy the client's version is
/// compared with: `old.ics`, or `old.ics` with the reply applied.
fn outputs(
    stored: Option<&ParsedCalendar>,
    new: &ParsedCalendar,
    reply_files: Vec<(String, String)>,
    map: &AddressMap,
) -> Vec<(String, String)> {
    let update = apply_organizer_changes(stored, new, &limits()).expect("organizer update");
    let mut found = vec![
        ("diff.txt".to_owned(), render_diff(&update.diff)),
        (
            "organizer.ics".to_owned(),
            serialize(&update.calendar).expect("serializable organizer copy"),
        ),
    ];
    found.extend(reply_files);
    // The stored copies keep the addresses the clients wrote; the messages carry the mapped ones.
    let organizer_copy = on_the_wire(&update.calendar, map);
    let old = stored.map(|old| on_the_wire(old, map));
    let attendees = recipients(&organizer_copy);
    let changed = update
        .diff
        .instances
        .iter()
        .any(|instance| matches!(instance.change, ChangeClass::Created | ChangeClass::Significant));
    let cancelled_series = is_cancelled(&organizer_copy) && old.as_ref().is_none_or(|old| !is_cancelled(old));
    if cancelled_series {
        for attendee in &attendees {
            found.push((
                format!("cancel-{}.ics", local_name(attendee)),
                message(&organizer_copy, ItipMethod::Cancel, attendee, MessageScope::Whole),
            ));
        }
    } else {
        let added: Vec<CalendarUserAddress> = update
            .diff
            .added_attendees
            .iter()
            .map(|address| mapped(address, map))
            .collect();
        let requested: Vec<&CalendarUserAddress> = if changed {
            attendees.iter().collect()
        } else {
            attendees.iter().filter(|attendee| added.contains(attendee)).collect()
        };
        for attendee in requested {
            found.push((
                format!("request-{}.ics", local_name(attendee)),
                message(&organizer_copy, ItipMethod::Request, attendee, MessageScope::Whole),
            ));
        }
        if let Some(old) = &old {
            for attendee in update.diff.removed_attendees.iter().map(|address| mapped(address, map)) {
                found.push((
                    format!("cancel-{}.ics", local_name(&attendee)),
                    message(old, ItipMethod::Cancel, &attendee, MessageScope::Whole),
                ));
            }
            for (number, instance) in update.diff.cancelled_instances.iter().enumerate() {
                for attendee in &attendees {
                    found.push((
                        format!("cancel-instance-{}-{}.ics", number + 1, local_name(attendee)),
                        message(
                            old,
                            ItipMethod::Cancel,
                            attendee,
                            MessageScope::Instances(vec![instance.clone()]),
                        ),
                    ));
                }
            }
        }
    }
    found.sort();
    found
}

fn scenarios() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(data_dir())
        .expect("the golden directory exists")
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.is_dir())
        .collect();
    found.sort();
    found
}

/// The files a scenario with a reply adds, and the stored copy after the reply.
fn apply_scenario_reply(dir: &Path, old: &ParsedCalendar) -> (ParsedCalendar, Vec<(String, String)>) {
    let bytes = fs::read(dir.join("reply.ics")).expect("reply.ics");
    let reply = parse_message(&bytes, &limits()).expect("a valid reply");
    let organizer = to_event_data(old, None).expect("master data").organizer;
    let attendee = to_event_data(&reply.calendar, None)
        .expect("reply data")
        .attendees
        .and_then(|list| list.into_iter().next())
        .map(|attendee| attendee.address)
        .expect("the reply names its attendee");
    assert!(organizer.is_some(), "the scenario is a scheduling object");
    let applied = apply_reply_with(old, &reply, &limits(), Some(&attendee)).expect("the reply applies");
    let files = vec![
        (
            "after-reply.ics".to_owned(),
            serialize(&applied.updated).expect("serializable copy"),
        ),
        ("reply.txt".to_owned(), render_reply(&applied)),
    ];
    (applied.updated, files)
}

fn check_scenario(dir: &Path, update: bool) -> Vec<String> {
    let old_path = dir.join("old.ics");
    let old = old_path.exists().then(|| load(&old_path));
    let new = load(&dir.join("new.ics"));
    let (stored, reply_files) = if dir.join("reply.ics").exists() {
        let (after, files) = apply_scenario_reply(dir, old.as_ref().expect("a reply needs a stored copy"));
        (Some(after), files)
    } else {
        (old, Vec::new())
    };
    let produced = outputs(stored.as_ref(), &new, reply_files, &load_addresses(dir));
    let mut problems = Vec::new();
    let names: BTreeSet<&str> = produced.iter().map(|(name, _)| name.as_str()).collect();
    for (name, content) in &produced {
        let path = dir.join(name);
        if update {
            fs::write(&path, content).expect("write golden file");
            continue;
        }
        match fs::read(&path) {
            Ok(golden) if golden == content.as_bytes() => {}
            Ok(golden) => problems.push(format!(
                "{}: differs from the golden file\n--- golden\n{}\n--- produced\n{content}",
                path.display(),
                String::from_utf8_lossy(&golden)
            )),
            Err(_) => problems.push(format!("{}: missing golden file; produced\n{content}", path.display())),
        }
    }
    // Files that the scenario no longer produces are stale.
    for entry in fs::read_dir(dir).expect("scenario directory").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if matches!(name.as_str(), "old.ics" | "new.ics" | "reply.ics" | "addresses.txt")
            || names.contains(name.as_str())
        {
            continue;
        }
        if update {
            fs::remove_file(entry.path()).expect("remove stale golden file");
        } else {
            problems.push(format!("{}: stale golden file", entry.path().display()));
        }
    }
    problems
}

#[test]
fn the_golden_set_matches() {
    let update = updating();
    let scenarios = scenarios();
    assert!(
        scenarios.len() >= 20,
        "the golden set is incomplete: {} scenarios",
        scenarios.len()
    );
    let problems: Vec<String> = scenarios
        .iter()
        .flat_map(|dir| {
            check_scenario(dir, update)
                .into_iter()
                .map(|problem| format!("[{}] {problem}", dir.file_name().unwrap_or_default().to_string_lossy()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));
}

/// The names of the messages a scenario produces.
fn messages_of(name: &str) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(data_dir().join(name))
        .expect("scenario directory")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|file| file.starts_with("request-") || file.starts_with("cancel-"))
        .collect();
    found.sort();
    found
}

/// The golden files are the contract with the application: they must encode the rules of PLAN 2.8, not merely
/// whatever the code produces. These assertions pin down the classification and the recipients of the
/// well-known scenarios independently of the generator.
#[test]
fn the_scenarios_encode_the_rules_of_the_plan() {
    if updating() {
        return;
    }
    let both = ["request-bob.ics", "request-cleo.ics"];
    let expected: [(&str, &str, &[&str]); 27] = [
        ("time-moved", "master: significant [DTEND, DTSTART]", &both),
        (
            "time-moved-sequence-bumped",
            "master: significant [DTEND, DTSTART]",
            &both,
        ),
        ("summary-changed", "master: significant [SUMMARY]", &both),
        ("location-changed", "master: significant [LOCATION]", &both),
        ("rrule-extended", "master: significant [RRULE]", &both),
        ("rdate-added", "master: significant [RDATE]", &both),
        ("duration-changed", "master: significant [DTEND]", &both),
        ("all-day-to-timed", "master: significant [DTEND, DTSTART]", &both),
        ("description-only", "master: insignificant [DESCRIPTION]", &[]),
        ("alarm-only", "master: insignificant [VALARM]", &[]),
        // The answers of the attendees are the server's: a client that flips one changes nothing.
        ("attendee-answer-only", "master: unchanged [-]", &[]),
        ("dtend-as-duration", "master: unchanged [-]", &[]),
        (
            "attendee-added",
            "master: insignificant [ATTENDEE]",
            &["request-dan.ics"],
        ),
        (
            "resource-added",
            "master: insignificant [ATTENDEE]",
            &["request-room1.ics"],
        ),
        (
            "attendee-removed",
            "master: insignificant [ATTENDEE]",
            &["cancel-cleo.ics"],
        ),
        (
            "time-moved-attendee-removed",
            "master: significant [ATTENDEE, DTEND, DTSTART]",
            &["cancel-cleo.ics", "request-bob.ics"],
        ),
        (
            "exdate-added",
            "master: significant [EXDATE]",
            &[
                "cancel-instance-1-bob.ics",
                "cancel-instance-1-cleo.ics",
                "request-bob.ics",
                "request-cleo.ics",
            ],
        ),
        (
            "status-cancelled",
            "master: significant [STATUS]",
            &["cancel-bob.ics", "cancel-cleo.ics"],
        ),
        ("create-single", "master: created [-]", &both),
        ("create-recurring-weekly", "master: created [-]", &both),
        ("create-windows-tzid", "master: created [-]", &both),
        ("create-all-day", "master: created [-]", &both),
        (
            "override-removed",
            "master: unchanged [-]\ninstance Europe/Berlin 2027-03-08T10:00:00: removed [-]",
            &["cancel-instance-1-bob.ics", "cancel-instance-1-cleo.ics"],
        ),
        // A reply arrived after the client read the copy: the stale version only adds a description. The remark of the
        // reply is on the organizer's copy as the attendee's comment, which the stale version of the client does not have and
        // which the server keeps: the comment is not part of what the client changed.
        ("reply-then-stale-edit", "master: insignificant [DESCRIPTION]", &[]),
        // A cancelled instance is a significant change of that instance; the others are sent the series.
        (
            "override-cancelled-with-status",
            "master: unchanged [-]\ninstance Europe/Berlin 2027-03-08T10:00:00: significant [STATUS]",
            &both,
        ),
        // Principal URLs and `urn:uuid` addresses are `mailto` addresses on the wire (PLAN 2.6).
        ("principal-addresses", "master: created [-]", &both),
        // An attendee whose own client schedules (`SCHEDULE-AGENT=CLIENT`) gets nothing from the server.
        ("schedule-agent-client", "master: created [-]", &["request-bob.ics"]),
    ];
    for (name, lines, messages) in expected {
        let diff = fs::read_to_string(data_dir().join(name).join("diff.txt")).expect("diff.txt");
        assert!(diff.starts_with(lines), "{name}: expected {lines:?} in\n{diff}");
        assert_eq!(messages_of(name), messages, "{name}");
    }
    // A single instance that is moved, or whose time changes again, is a significant change of that instance;
    // one that only gains a description is just new.
    for (name, line) in [
        ("override-added", "significant [DTEND, DTSTART]"),
        ("override-changed", "significant [DTEND, DTSTART]"),
        ("override-added-description", "created [-]"),
        ("this-and-future-override", "significant [DTEND, DTSTART]"),
    ] {
        let diff = fs::read_to_string(data_dir().join(name).join("diff.txt")).expect("diff.txt");
        let expected = format!("master: unchanged [-]\ninstance Europe/Berlin 2027-03-08T10:00:00: {line}\n");
        assert!(diff.starts_with(&expected), "{name}:\n{diff}");
    }
}

/// What the stored organizer copy of a scenario must hold for the master component, written out by hand from the
/// rules of PLAN 2.7 and 2.8: the `SEQUENCE`, and the answer of Bob, Cleo and any other guest (`None`: not on the
/// event). The answers of the attendees are the server's: they come from the stored copy (Bob accepted, Cleo
/// tentative), or are `NEEDS-ACTION` for attendees that are new on the instance and on every instance that
/// changed significantly. Nothing in `new.ics` can change them.
type Expectation = (&'static str, i32, &'static [(&'static str, Option<PartStat>)]);

const ACCEPTED: Option<PartStat> = Some(PartStat::Accepted);
const TENTATIVE: Option<PartStat> = Some(PartStat::Tentative);
const OPEN: Option<PartStat> = Some(PartStat::NeedsAction);

const ORGANIZER_COPIES: [Expectation; 32] = [
    ("alarm-only", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
    ("all-day-to-timed", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    (
        "attendee-added",
        0,
        &[("bob", ACCEPTED), ("cleo", TENTATIVE), ("dan", OPEN)],
    ),
    (
        "resource-added",
        0,
        &[("bob", ACCEPTED), ("cleo", TENTATIVE), ("room1", OPEN)],
    ),
    // The client sent Cleo as ACCEPTED; only a REPLY can say that.
    ("attendee-answer-only", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
    ("attendee-removed", 0, &[("bob", ACCEPTED), ("cleo", None)]),
    ("create-all-day", 0, &[("bob", OPEN), ("cleo", OPEN)]),
    ("create-recurring-weekly", 0, &[("bob", OPEN), ("cleo", OPEN)]),
    // The client sent Bob as ACCEPTED and Cleo as TENTATIVE on a new object.
    ("create-single", 0, &[("bob", OPEN), ("cleo", OPEN)]),
    ("create-windows-tzid", 0, &[("bob", OPEN), ("cleo", OPEN)]),
    ("description-only", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
    ("dtend-as-duration", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
    ("duration-changed", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    ("exdate-added", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    ("location-changed", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    ("override-added", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
    (
        "override-added-description",
        0,
        &[("bob", ACCEPTED), ("cleo", TENTATIVE)],
    ),
    (
        "override-cancelled-with-status",
        0,
        &[("bob", ACCEPTED), ("cleo", TENTATIVE)],
    ),
    ("override-changed", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
    ("override-removed", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
    ("principal-addresses", 0, &[("bob", OPEN), ("cleo", OPEN)]),
    ("rdate-added", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    // Bob declined (the reply) after the client read the copy; the stale version cannot take that back.
    (
        "reply-then-stale-edit",
        0,
        &[("bob", Some(PartStat::Declined)), ("cleo", TENTATIVE)],
    ),
    ("rrule-extended", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    // Cleo's own client schedules for her: the server neither answers nor resets for her, her answer stays as sent.
    ("schedule-agent-client", 0, &[("bob", OPEN), ("cleo", TENTATIVE)]),
    ("status-cancelled", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    ("summary-changed", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    ("this-and-future-override", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
    ("time-moved-attendee-removed", 1, &[("bob", OPEN), ("cleo", None)]),
    ("time-moved-sequence-bumped", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    ("time-moved", 1, &[("bob", OPEN), ("cleo", OPEN)]),
    ("two-overrides", 0, &[("bob", ACCEPTED), ("cleo", TENTATIVE)]),
];

#[test]
fn the_organizer_copies_follow_the_ownership_rules() {
    if updating() {
        return;
    }
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for (name, sequence, answers) in ORGANIZER_COPIES {
        covered.insert(name);
        let copy = load(&data_dir().join(name).join("organizer.ics"));
        let master = to_event_data(&copy, None).expect("master data");
        assert_eq!(master.sequence, Some(sequence), "{name}: SEQUENCE of the master");
        let attendees = master.attendees.unwrap_or_default();
        // The stored copy keeps the addresses the client wrote; the names are those of their mailboxes.
        let map = load_addresses(&data_dir().join(name));
        let who_is = |address: &CalendarUserAddress| local_name(&mapped(address, &map));
        for (who, expected) in answers {
            let found = attendees
                .iter()
                .find(|attendee| who_is(&attendee.address) == *who)
                .and_then(|attendee| attendee.partstat);
            assert_eq!(found, *expected, "{name}: the answer of {who}");
        }
        // Nobody else slipped in.
        let listed: BTreeSet<String> = attendees
            .iter()
            .map(|attendee| who_is(&attendee.address))
            .filter(|who| who != "anna")
            .collect();
        let expected_listed: BTreeSet<String> = answers
            .iter()
            .filter(|(_, answer)| answer.is_some())
            .map(|(who, _)| (*who).to_owned())
            .collect();
        assert_eq!(listed, expected_listed, "{name}: the attendees");
    }
    assert_eq!(
        covered.len(),
        scenarios().len(),
        "every scenario has an expectation for its organizer copy"
    );
    // The remark that came with Bob's answer is the server's like the answer: the stale version of the client does not have it
    // and the stored copy keeps it (the golden file of the diff says the stale version only added a description).
    let kept = serialize(&load(&data_dir().join("reply-then-stale-edit").join("organizer.ics")))
        .unwrap()
        .replace("\r\n ", "");
    assert!(
        kept.contains("X-CALENDARSERVER-DTSTAMP=20270210T080000Z:Sorry\\, a clash with the audit"),
        "{kept}"
    );
    // The significantly changed instance of an override restarts the answers, the series keeps them.
    for name in ["override-added", "override-changed"] {
        let copy = load(&data_dir().join(name).join("organizer.ics"));
        let text = serialize(&copy).unwrap().replace("\r\n ", "");
        let override_part = text.split("RECURRENCE-ID").nth(1).expect("the override");
        assert!(override_part.contains("SEQUENCE:1"), "{name}: {override_part}");
        assert_eq!(override_part.matches("PARTSTAT=NEEDS-ACTION").count(), 2, "{name}");
    }
}

/// Nobody who writes the organizer's calendar can leave a delivery status behind: a new object has had nothing
/// delivered, and a status only stays where the stored copy had it.
#[test]
fn a_client_cannot_plant_delivery_states() {
    if updating() {
        return;
    }
    for dir in scenarios() {
        let name = dir.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if dir.join("old.ics").exists() {
            continue;
        }
        let copy = serialize(&load(&dir.join("organizer.ics")))
            .unwrap()
            .replace("\r\n ", "");
        assert!(
            !copy.contains("SCHEDULE-STATUS"),
            "{name}: a new object has no delivery states\n{copy}"
        );
    }
    // A scenario with an old copy keeps the states the old copy had and no others: Cleo's `1.1` (an iMIP mail was
    // sent) stays, and `attendee-added` gives Dan none although the client wrote `ACCEPTED` and `1.2` for him.
    let copy = serialize(&load(&data_dir().join("attendee-added").join("organizer.ics")))
        .unwrap()
        .replace("\r\n ", "");
    assert!(copy.contains("SCHEDULE-STATUS=1.1:mailto:cleo@example.org"), "{copy}");
    let dan = copy
        .lines()
        .find(|line| line.contains("dan@example.org"))
        .expect("Dan is invited");
    assert!(!dan.contains("SCHEDULE-STATUS"), "{dan}");
}

/// Principal URLs and `urn:uuid` addresses never leave the server: the messages carry the mailbox addresses
/// while the stored copy keeps what the client wrote (PLAN 2.6).
#[test]
fn principal_addresses_are_mailto_addresses_on_the_wire() {
    if updating() {
        return;
    }
    let dir = data_dir().join("principal-addresses");
    let stored = fs::read_to_string(dir.join("organizer.ics"))
        .expect("organizer.ics")
        .replace("\r\n ", "");
    assert!(stored.contains("urn:uuid:5a9c1e0e") && stored.contains("/dav/principals/example/bob/"));
    for message in ["request-bob.ics", "request-cleo.ics"] {
        let text = fs::read_to_string(dir.join(message))
            .expect(message)
            .replace("\r\n ", "");
        assert!(
            !text.contains("urn:uuid") && !text.contains("/dav/principals"),
            "{message}\n{text}"
        );
        assert!(
            text.contains("ORGANIZER;CN=\"Anna Beispiel\":mailto:anna@example.org"),
            "{text}"
        );
    }
    let bob = fs::read_to_string(dir.join("request-bob.ics"))
        .expect("request-bob.ics")
        .replace("\r\n ", "");
    assert!(bob.contains(":mailto:bob@example.org"), "{bob}");
}

/// The recurrence rules of the golden files keep their meaning when the client moves several instances at once.
#[test]
fn several_overrides_are_classified_one_by_one() {
    if updating() {
        return;
    }
    let diff = fs::read_to_string(data_dir().join("two-overrides").join("diff.txt")).expect("diff.txt");
    assert!(
        diff.starts_with(
            "master: unchanged [-]\n\
             instance Europe/Berlin 2027-03-08T10:00:00: significant [DTEND, DTSTART]\n\
             instance Europe/Berlin 2027-03-15T10:00:00: created [-]\n"
        ),
        "{diff}"
    );
    assert_eq!(messages_of("two-overrides"), ["request-bob.ics", "request-cleo.ics"]);
}

#[test]
fn a_reply_that_arrived_before_the_stale_edit_is_kept_and_reported() {
    if updating() {
        return;
    }
    let reply = fs::read_to_string(data_dir().join("reply-then-stale-edit").join("reply.txt")).expect("reply.txt");
    assert_eq!(
        reply,
        "attendee: mailto:bob@example.org\nanswer: DECLINED\ninstances: -\nsequence matches: true\ncomment: Sorry, a clash with the audit\n"
    );
}
