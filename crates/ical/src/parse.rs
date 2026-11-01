//! Lenient parsing of client iCalendar data into the internal representation.
//!
//! Real clients send data that is not strictly RFC 5545: bare `LF` line endings, Windows time zone names,
//! missing `VTIMEZONE` components, zero-length `DTEND`, stray whitespace. [`parse`] accepts what the clients of
//! PLAN G1 produce, enforces the structural limits of [`IcalLimits`] while reading, and never panics on any
//! input. The result, [`ParsedCalendar`], is opaque: no parser type leaks through the public API, and the stored
//! bytes stay verbatim because the server re-serializes only what it changes.
//!
//! The parser is `calcard`. Because that parser is forgiving to the point of silently dropping what it does not
//! understand, a structural scan runs first on the same text: it enforces the size, nesting, component, property
//! and value limits before anything is allocated for them, and it rejects documents that are not one complete
//! `VCALENDAR` (a missing `END:` line means the upload was truncated, and storing it would lose data).

use std::borrow::Cow;
use std::fmt;

use calcard::icalendar::{ICalendarProperty, ICalendarValue};
use calcard::{Entry, Parser};
use davhaven_domain::IcalLimits;

use crate::calendar::{Kind, MAX_TREE_DEPTH, Node, contain};
use crate::error::{IcalError, LimitKind};
use crate::occurrence::Budget;

/// The longest piece of user text echoed in an error message.
const SNIPPET_LENGTH: usize = 40;

/// A parsed calendar object resource: one `VCALENDAR` with its components.
///
/// The type is opaque; the other modules of this crate read it. It is immutable: functions that change a
/// calendar return a new one.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedCalendar {
    pub(crate) root: Node,
}

impl ParsedCalendar {
    pub(crate) const fn from_root(root: Node) -> Self {
        Self { root }
    }
}

impl fmt::Debug for ParsedCalendar {
    /// Shows how big the calendar is and nothing it says: addresses, titles and descriptions never reach a log
    /// line through `{:?}` (`ENGINEERING_RULES` R8).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut components = 0usize;
        let mut properties = 0usize;
        let mut stack: Vec<&Node> = vec![&self.root];
        while let Some(node) = stack.pop() {
            components = components.saturating_add(1);
            properties = properties.saturating_add(node.entries.len());
            stack.extend(node.children.iter());
        }
        f.debug_struct("ParsedCalendar")
            .field("components", &components)
            .field("properties", &properties)
            .finish_non_exhaustive()
    }
}

/// Parses the bytes of a calendar object resource: the reader of everything that is stored.
///
/// The input must be UTF-8 (a leading byte order mark is ignored). Unfolding, `LF`-only line endings and
/// unknown properties are handled; structural limits (`max_resource_size`, `max_components`,
/// `max_properties_per_component`, `max_value_length`, `max_nesting`) are enforced during parsing. The
/// application runs this inside `spawn_blocking` with the wall-clock budget `time_budget_ms`.
///
/// This reads what is stored without deciding whether the server may keep it: an object that was accepted once
/// stays readable, and a read (a query, a feed, a free-busy answer) never fails because of how a client wrote
/// a value. Data that comes in is held to more: [`accept`] is the gate of every write, of every incoming
/// scheduling message and of the time zone of a calendar.
///
/// # Errors
///
/// * [`IcalError::Invalid`] when the data is not iCalendar, is not UTF-8, or is incomplete (an unterminated
///   component),
/// * [`IcalError::Limit`] when a structural limit is exceeded.
pub fn parse(input: &[u8], limits: &IcalLimits) -> Result<ParsedCalendar, IcalError> {
    let budget = Budget::new(limits);
    let text = normalized(input, limits)?;
    let root = read(&text, limits, Names::Unchecked)?;
    budget.check()?;
    Ok(ParsedCalendar { root })
}

/// The gate for data that comes in: [`parse`], and the data must survive the writer.
///
/// What is accepted here is written as text that reads back as the same calendar, within the same limits, and
/// writing that gives the same text. The reader behind the parser is lenient (a value that is nearly a
/// date-time is read as one, a parameter name is unescaped like a value), and what it reads is not always what
/// its writer writes. Data for which the two disagree is refused, rather than read in a way that the client did
/// not write (`DTSTART:20270301T100000+0100` would come back as a floating time) or kept in a form that no
/// later rewrite by the server can reproduce. The stored bytes of an accepted object stay the client's; this
/// decides only what is accepted, and it costs one more write and read of the document.
///
/// The text the server writes is held to the limits too, because the server may store it: escaping makes a text
/// value longer than the client sent it (every `,` and `;` that came without a backslash gets one), and an
/// object whose written form does not fit `max_value_length` or `max_resource_size` could never be rewritten
/// (merged, scheduled) and read again.
///
/// # Errors
///
/// As [`parse`]; [`IcalError::Invalid`] for data that cannot be written back as iCalendar text (a parameter
/// name that is not a name, a value that is read other than it is written); [`IcalError::Limit`] also when the
/// written form exceeds a limit.
pub fn accept(input: &[u8], limits: &IcalLimits) -> Result<ParsedCalendar, IcalError> {
    let budget = Budget::new(limits);
    let text = normalized(input, limits)?;
    let root = read(&text, limits, Names::Checked)?;
    budget.check()?;
    require_round_trip(&root, limits, &budget)?;
    Ok(ParsedCalendar { root })
}

/// The text of `input` as the scan and the parser see it: the size is within the limit, the bytes are UTF-8, a
/// leading byte order mark is gone and the lines end in `LF`.
fn normalized<'a>(input: &'a [u8], limits: &IcalLimits) -> Result<Cow<'a, str>, IcalError> {
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > limits.max_resource_size {
        return Err(IcalError::Limit(LimitKind::ResourceSize));
    }
    let text = std::str::from_utf8(input).map_err(|_| IcalError::invalid("the data is not valid UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    Ok(normalize_line_endings(text))
}

/// Whether the scan checks the names of the parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Names {
    /// Every name is checked: the data is being accepted ([`accept`]).
    Checked,
    /// Names are left to the parser: the data is being read ([`parse`]).
    Unchecked,
}

/// Reads normalized text (`LF` line endings, no byte order mark) into the component tree: the structural scan,
/// the parser and the checks of the tree.
fn read(text: &str, limits: &IcalLimits, names: Names) -> Result<Node, IcalError> {
    scan(text, limits, names)?;
    let calendar = contain(|| match Parser::new(text).entry() {
        Entry::ICalendar(calendar) => Some(calendar),
        _ => None,
    })
    .ok_or_else(|| IcalError::invalid("the data cannot be parsed"))?
    .ok_or_else(|| IcalError::invalid("the data is not an iCalendar object"))?;
    let root =
        Node::from_calendar(&calendar).ok_or_else(|| IcalError::invalid("the data is not an iCalendar object"))?;
    if root.kind != Kind::VCalendar {
        return Err(IcalError::invalid("the data is not an iCalendar object"));
    }
    check_structure(&root, limits)?;
    Ok(root)
}

/// Checks that `root` survives the writer: the text it is written as reads back as the same tree.
///
/// The writer of the parser library does not write what its reader read in two kinds of cases, and the reader
/// is not the one to say which: a value that the reader accepts leniently and the writer formats strictly
/// (`DTSTAMP:20270101T000000Z2`, `TZOFFSETTO:+2`), and a name or a value that the reader unescapes and the
/// writer does not escape again (a parameter name with a backslash or a quote in it). A tree that does not read
/// back as itself breaks everything that writes a stored object after changing it (merging, scheduling), and
/// makes the content hash depend on how often the data went through the writer.
///
/// The written text is read with the limits of the input, the size of the whole resource included: it is what
/// the server would store, and a stored object is read under those limits.
fn require_round_trip(root: &Node, limits: &IcalLimits, budget: &Budget) -> Result<(), IcalError> {
    // The writer is third-party code like the reader, and runs on every upload now: a panic in it is a refusal.
    let text = contain(|| root.to_calendar().to_string()).ok_or_else(not_writable)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > limits.max_resource_size {
        return Err(IcalError::Limit(LimitKind::ResourceSize));
    }
    let again = read(&normalize_line_endings(&text), limits, Names::Unchecked).map_err(|error| match error {
        IcalError::Invalid(_) => not_writable(),
        other => other,
    })?;
    budget.check()?;
    if &again == root { Ok(()) } else { Err(not_writable()) }
}

/// The refusal of data that the writer cannot reproduce.
fn not_writable() -> IcalError {
    IcalError::invalid("the data contains something that cannot be written back as iCalendar text")
}

/// Bare carriage returns and `CRLF` become `LF`; the parser and the scan then see the same lines.
fn normalize_line_endings(text: &str) -> Cow<'_, str> {
    if text.contains('\r') {
        Cow::Owned(text.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Cow::Borrowed(text)
    }
}

/// A recurrence rule the parser could not read is kept as its raw text, which the writer would escape again on
/// every round trip; such a rule cannot be expanded either, so the document is refused.
fn check_rules(node: &Node) -> Result<(), IcalError> {
    let malformed = node
        .entries
        .iter()
        .filter(|entry| matches!(entry.name, ICalendarProperty::Rrule | ICalendarProperty::Exrule))
        .any(|entry| {
            entry.values.is_empty()
                || !entry
                    .values
                    .iter()
                    .all(|value| matches!(value, ICalendarValue::RecurrenceRule(_)))
        });
    if malformed {
        return Err(IcalError::invalid("RRULE is not a valid recurrence rule"));
    }
    Ok(())
}

/// Re-checks the limits on the parsed tree, so that they hold whatever the scan and the parser disagree on.
fn check_structure(root: &Node, limits: &IcalLimits) -> Result<(), IcalError> {
    let max_components = usize::try_from(limits.max_components).unwrap_or(usize::MAX);
    let max_properties = usize::try_from(limits.max_properties_per_component).unwrap_or(usize::MAX);
    let max_depth = usize::try_from(limits.max_nesting)
        .unwrap_or(usize::MAX)
        .min(MAX_TREE_DEPTH);
    let mut components = 0usize;
    let mut stack: Vec<(&Node, usize)> = vec![(root, 1)];
    while let Some((node, depth)) = stack.pop() {
        components = components.saturating_add(1);
        if components > max_components {
            return Err(IcalError::Limit(LimitKind::Components));
        }
        if depth > max_depth {
            return Err(IcalError::Limit(LimitKind::Nesting));
        }
        if node.entries.len() > max_properties {
            return Err(IcalError::Limit(LimitKind::Properties));
        }
        check_rules(node)?;
        stack.extend(node.children.iter().map(|child| (child, depth.saturating_add(1))));
    }
    Ok(())
}

/// A short, printable piece of user supplied text for error messages.
fn snippet(text: &str) -> String {
    let mut shown: String = text.chars().filter(|c| !c.is_control()).take(SNIPPET_LENGTH).collect();
    if text.chars().count() > SNIPPET_LENGTH {
        shown.push_str("...");
    }
    shown
}

/// What the scan and the parser both treat as blank around a name: a space or a tab. `str::trim` would strip
/// every Unicode white space (`U+0085`, `U+2028`, ...), which the parser reads as part of the name: the scan
/// would then see a `BEGIN:VEVENT` that the parser does not.
const BLANK: [char; 2] = [' ', '\t'];

/// Checks the parameter names of a content line (`head`, the part before the `:` of the value): each is what
/// RFC 5545 section 3.2 allows, letters, digits and `-` (`_` is accepted like in property names).
///
/// The parser unescapes a parameter name like any other token (`\n`, `\;`, a quote) and its writer writes the
/// name as it is, so a name with such a character in it is written as something else than what was read, or as
/// a line that is no longer one content line. An empty name is ignored by the parser and allowed here.
fn check_parameter_names(head: &str) -> Result<(), IcalError> {
    let mut in_quotes = false;
    let mut from = 0usize;
    let mut first = true;
    let mut check = |segment: &str| {
        if std::mem::take(&mut first) {
            // The first segment is the property name, checked by the caller.
            return Ok(());
        }
        let name = segment
            .split_once('=')
            .map_or(segment, |(name, _)| name)
            .trim_matches(BLANK);
        if name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            Ok(())
        } else {
            Err(IcalError::invalid(format!(
                "'{}' is not a valid parameter name",
                snippet(name)
            )))
        }
    };
    for (index, byte) in head.bytes().enumerate() {
        match byte {
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => {
                check(head.get(from..index).unwrap_or_default())?;
                from = index.saturating_add(1);
            }
            _ => {}
        }
    }
    check(head.get(from..).unwrap_or_default())
}

/// Splits a content line at the first `:` outside double quotes.
pub(crate) fn split_content_line(line: &str) -> Option<(&str, &str)> {
    let mut in_quotes = false;
    for (index, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => {
                let head = line.get(..index)?;
                let value = line.get(index + 1..)?;
                return Some((head, value));
            }
            _ => {}
        }
    }
    None
}

/// The state of the structural scan.
struct Scan {
    names: Names,
    max_value: usize,
    max_depth: usize,
    max_components: usize,
    max_properties: usize,
    stack: Vec<(String, usize)>,
    components: usize,
    started: bool,
    finished: bool,
}

impl Scan {
    fn line(&mut self, line: &str) -> Result<(), IcalError> {
        let line = line.trim_end_matches(BLANK);
        if line.trim_start_matches(BLANK).is_empty() {
            return Ok(());
        }
        let Some((head, value)) = split_content_line(line) else {
            return Err(IcalError::invalid("a content line has no ':' separator"));
        };
        let name = head.split(';').next().unwrap_or_default().trim_matches(BLANK);
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(IcalError::invalid(format!(
                "'{}' is not a valid property name",
                snippet(name)
            )));
        }
        if self.names == Names::Checked {
            check_parameter_names(head)?;
        }
        // Inline binary attachments have their own, larger limit (`max_inline_attach_bytes`, checked on the
        // decoded data by the validation); the size of the whole resource bounds them here.
        if value.len() > self.max_value && !name.eq_ignore_ascii_case("ATTACH") {
            return Err(IcalError::Limit(LimitKind::ValueLength));
        }
        if name.eq_ignore_ascii_case("BEGIN") {
            self.begin(value.trim_matches(BLANK))
        } else if name.eq_ignore_ascii_case("END") {
            self.end(value.trim_matches(BLANK))
        } else {
            self.property()
        }
    }

    fn begin(&mut self, name: &str) -> Result<(), IcalError> {
        if self.finished {
            return Err(IcalError::invalid(if name.eq_ignore_ascii_case("VCALENDAR") {
                "the data contains more than one VCALENDAR"
            } else {
                "the data continues after END:VCALENDAR"
            }));
        }
        if self.stack.is_empty() && !name.eq_ignore_ascii_case("VCALENDAR") {
            return Err(IcalError::invalid(
                "the data is not an iCalendar object (BEGIN:VCALENDAR is missing)",
            ));
        }
        if name.is_empty() {
            return Err(IcalError::invalid("BEGIN has no component name"));
        }
        self.started = true;
        self.components = self.components.saturating_add(1);
        if self.components > self.max_components {
            return Err(IcalError::Limit(LimitKind::Components));
        }
        if self.stack.len().saturating_add(1) > self.max_depth {
            return Err(IcalError::Limit(LimitKind::Nesting));
        }
        self.stack.push((name.to_ascii_uppercase(), 0));
        Ok(())
    }

    fn end(&mut self, name: &str) -> Result<(), IcalError> {
        let Some((open, _)) = self.stack.pop() else {
            return Err(IcalError::invalid(format!(
                "END:{} has no matching BEGIN",
                snippet(name)
            )));
        };
        if !open.eq_ignore_ascii_case(name) {
            return Err(IcalError::invalid(format!(
                "END:{} does not match BEGIN:{}",
                snippet(name),
                snippet(&open)
            )));
        }
        if self.stack.is_empty() {
            self.finished = true;
        }
        Ok(())
    }

    fn property(&mut self) -> Result<(), IcalError> {
        let Some((_, count)) = self.stack.last_mut() else {
            return Err(if self.finished {
                IcalError::invalid("the data continues after END:VCALENDAR")
            } else {
                IcalError::invalid("the data is not an iCalendar object (BEGIN:VCALENDAR is missing)")
            });
        };
        *count = count.saturating_add(1);
        if *count > self.max_properties {
            return Err(IcalError::Limit(LimitKind::Properties));
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), IcalError> {
        if let Some((open, _)) = self.stack.last() {
            return Err(IcalError::invalid(format!(
                "the data is incomplete: BEGIN:{} has no END",
                snippet(open)
            )));
        }
        if !self.started {
            return Err(IcalError::invalid("the data is not an iCalendar object"));
        }
        Ok(())
    }
}

/// Scans the lines of `text` (already `LF` separated): unfolds them, enforces the limits that do not need a
/// parse and checks that the components nest properly and are all closed.
fn scan(text: &str, limits: &IcalLimits, names: Names) -> Result<(), IcalError> {
    let mut state = Scan {
        names,
        max_value: usize::try_from(limits.max_value_length).unwrap_or(usize::MAX),
        max_depth: usize::try_from(limits.max_nesting)
            .unwrap_or(usize::MAX)
            .min(MAX_TREE_DEPTH),
        max_components: usize::try_from(limits.max_components).unwrap_or(usize::MAX),
        max_properties: usize::try_from(limits.max_properties_per_component).unwrap_or(usize::MAX),
        stack: Vec::new(),
        components: 0,
        started: false,
        finished: false,
    };
    let mut logical = String::new();
    for raw in text.split('\n') {
        if let Some(continuation) = raw.strip_prefix([' ', '\t'])
            && !logical.is_empty()
        {
            logical.push_str(continuation);
            continue;
        }
        state.line(&logical)?;
        logical.clear();
        logical.push_str(raw);
    }
    state.line(&logical)?;
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> IcalLimits {
        IcalLimits::default()
    }

    const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:one\r\n\
        DTSTART:20270301T100000Z\r\nSUMMARY:Hello\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn a_recurrence_rule_that_cannot_be_read_is_refused() {
        for rule in [
            "RRULE:\\\\FREQ=DAILY",
            "RRULE:NONSENSE",
            "RRULE:",
            "EXRULE:FREQ=WEEKLY;COUNT=x",
        ] {
            let text = EVENT.replace("SUMMARY:Hello", rule);
            assert!(
                matches!(parse(text.as_bytes(), &limits()), Err(IcalError::Invalid(_))),
                "{rule} is accepted"
            );
        }
        let ok = EVENT.replace("SUMMARY:Hello", "RRULE:FREQ=DAILY;COUNT=2");
        assert!(parse(ok.as_bytes(), &limits()).is_ok());
    }

    #[test]
    fn a_complete_object_parses() {
        let parsed = parse(EVENT.as_bytes(), &limits()).unwrap();
        assert_eq!(parsed.root.kind, Kind::VCalendar);
        assert_eq!(parsed.root.children.len(), 1);
    }

    #[test]
    fn lf_line_endings_and_a_byte_order_mark_are_accepted() {
        let lf = EVENT.replace("\r\n", "\n");
        assert_eq!(
            parse(lf.as_bytes(), &limits()).unwrap(),
            parse(EVENT.as_bytes(), &limits()).unwrap()
        );
        let bom = format!("\u{feff}{EVENT}");
        assert_eq!(
            parse(bom.as_bytes(), &limits()).unwrap(),
            parse(EVENT.as_bytes(), &limits()).unwrap()
        );
        let cr = EVENT.replace("\r\n", "\r");
        assert_eq!(
            parse(cr.as_bytes(), &limits()).unwrap(),
            parse(EVENT.as_bytes(), &limits()).unwrap()
        );
    }

    #[test]
    fn folded_lines_are_unfolded() {
        let folded = EVENT.replace("SUMMARY:Hello", "SUMMARY:Hel\r\n lo");
        let parsed = parse(folded.as_bytes(), &limits()).unwrap();
        let event = parsed.root.children.first().unwrap();
        assert_eq!(event.text(&crate::calendar::Prop::Summary).as_deref(), Some("Hello"));
    }

    #[test]
    fn truncated_documents_are_rejected() {
        for cut in [
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:one\r\nDTSTART:20270301T100000Z\r\n",
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:one\r\nEND:VEVENT\r\n",
            "BEGIN:VCALENDAR\r\n",
        ] {
            let error = parse(cut.as_bytes(), &limits()).unwrap_err();
            let IcalError::Invalid(message) = error else {
                panic!("expected an invalid error for {cut:?}");
            };
            assert!(message.contains("incomplete"), "{message}");
        }
    }

    #[test]
    fn data_that_is_not_a_calendar_is_rejected() {
        for input in [
            "",
            "   \r\n",
            "hello world",
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:x\r\nEND:VCARD\r\n",
            "VERSION:2.0\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
        ] {
            assert!(
                matches!(parse(input.as_bytes(), &limits()), Err(IcalError::Invalid(_))),
                "{input:?}"
            );
        }
        assert!(matches!(
            parse(&[0xff, 0xfe, 0x00], &limits()),
            Err(IcalError::Invalid(_))
        ));
    }

    #[test]
    fn mismatched_and_repeated_structure_is_rejected() {
        let mismatch = EVENT.replace("END:VEVENT", "END:VTODO");
        assert!(matches!(
            parse(mismatch.as_bytes(), &limits()),
            Err(IcalError::Invalid(_))
        ));
        let twice = format!("{EVENT}{EVENT}");
        let IcalError::Invalid(message) = parse(twice.as_bytes(), &limits()).unwrap_err() else {
            panic!("expected an invalid error");
        };
        assert!(message.contains("more than one"), "{message}");
        let trailing = format!("{EVENT}SUMMARY:stray\r\n");
        assert!(matches!(
            parse(trailing.as_bytes(), &limits()),
            Err(IcalError::Invalid(_))
        ));
        let no_colon = EVENT.replace("SUMMARY:Hello", "SUMMARY Hello");
        assert!(matches!(
            parse(no_colon.as_bytes(), &limits()),
            Err(IcalError::Invalid(_))
        ));
    }

    #[test]
    fn trailing_blank_lines_are_fine() {
        let padded = format!("{EVENT}\r\n\r\n");
        assert!(parse(padded.as_bytes(), &limits()).is_ok());
    }

    #[test]
    fn the_resource_size_limit_applies() {
        let tight = IcalLimits {
            max_resource_size: 100,
            ..IcalLimits::default()
        };
        assert_eq!(
            parse(EVENT.as_bytes(), &tight),
            Err(IcalError::Limit(LimitKind::ResourceSize))
        );
        let exact = IcalLimits {
            max_resource_size: u64::try_from(EVENT.len()).unwrap(),
            ..IcalLimits::default()
        };
        assert!(parse(EVENT.as_bytes(), &exact).is_ok());
    }

    #[test]
    fn structural_limits_apply() {
        let components = IcalLimits {
            max_components: 1,
            ..IcalLimits::default()
        };
        assert_eq!(
            parse(EVENT.as_bytes(), &components),
            Err(IcalError::Limit(LimitKind::Components))
        );
        let properties = IcalLimits {
            max_properties_per_component: 2,
            ..IcalLimits::default()
        };
        assert_eq!(
            parse(EVENT.as_bytes(), &properties),
            Err(IcalError::Limit(LimitKind::Properties))
        );
        let nesting = IcalLimits {
            max_nesting: 1,
            ..IcalLimits::default()
        };
        assert_eq!(
            parse(EVENT.as_bytes(), &nesting),
            Err(IcalError::Limit(LimitKind::Nesting))
        );
        let value = IcalLimits {
            max_value_length: 4,
            ..IcalLimits::default()
        };
        assert_eq!(
            parse(EVENT.as_bytes(), &value),
            Err(IcalError::Limit(LimitKind::ValueLength))
        );
    }

    #[test]
    fn structural_limits_allow_exactly_the_configured_amount() {
        // EVENT has two components on two levels, at most three properties in one component, and its longest
        // value is the sixteen characters of the start.
        let exact = IcalLimits {
            max_components: 2,
            max_properties_per_component: 3,
            max_nesting: 2,
            max_value_length: 16,
            ..IcalLimits::default()
        };
        assert!(parse(EVENT.as_bytes(), &exact).is_ok());
        assert!(accept(EVENT.as_bytes(), &exact).is_ok());
    }

    #[test]
    fn components_that_do_not_open_or_close_properly_are_rejected_with_a_reason() {
        let message = |text: &str| match parse(text.as_bytes(), &limits()) {
            Err(IcalError::Invalid(message)) => message,
            other => panic!("{text:?} is accepted or refused for another reason: {other:?}"),
        };
        assert_eq!(message("END:VCALENDAR\r\n"), "END:VCALENDAR has no matching BEGIN");
        assert_eq!(
            message("BEGIN:VCALENDAR\r\nBEGIN:\r\nEND:\r\nEND:VCALENDAR\r\n"),
            "BEGIN has no component name"
        );
        assert_eq!(
            message(&EVENT.replace("END:VEVENT", "END:VTODO")),
            "END:VTODO does not match BEGIN:VEVENT"
        );
        assert_eq!(
            message(&format!("{EVENT}BEGIN:VEVENT\r\nEND:VEVENT\r\n")),
            "the data continues after END:VCALENDAR"
        );
        assert!(message(&EVENT.replace("SUMMARY:", "SUM MARY:")).contains("not a valid property name"));
    }

    #[test]
    fn long_values_are_limited() {
        let mut text = String::from("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDESCRIPTION:");
        for _ in 0..20_000 {
            text.push_str("0123456789\r\n ");
        }
        text.push_str("\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n");
        let wide = IcalLimits {
            max_resource_size: 10_000_000,
            ..IcalLimits::default()
        };
        assert_eq!(
            parse(text.as_bytes(), &wide),
            Err(IcalError::Limit(LimitKind::ValueLength))
        );
    }

    #[test]
    fn deep_nesting_is_limited_even_with_a_generous_setting() {
        let mut text = String::from("BEGIN:VCALENDAR\r\n");
        for _ in 0..100 {
            text.push_str("BEGIN:X-DEEP\r\n");
        }
        for _ in 0..100 {
            text.push_str("END:X-DEEP\r\n");
        }
        text.push_str("END:VCALENDAR\r\n");
        let generous = IcalLimits {
            max_nesting: 1000,
            ..IcalLimits::default()
        };
        assert_eq!(
            parse(text.as_bytes(), &generous),
            Err(IcalError::Limit(LimitKind::Nesting))
        );
    }

    #[test]
    fn error_messages_do_not_echo_long_input() {
        let name = "X".repeat(500);
        let text = format!("BEGIN:VCALENDAR\r\nBEGIN:{name}\r\nEND:Y\r\nEND:VCALENDAR\r\n");
        let IcalError::Invalid(message) = parse(text.as_bytes(), &limits()).unwrap_err() else {
            panic!("expected an invalid error");
        };
        assert!(message.len() < 200, "{message}");
    }

    // -----------------------------------------------------------------------------------------------------------
    // What the writer can reproduce (backlog 45, 51: the round trip of the robustness test and of the fuzz target)
    // -----------------------------------------------------------------------------------------------------------

    /// A calendar with one event that has `line` as a property.
    fn event_with(line: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n{line}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    }

    /// The contract of [`accept`]: what is accepted is written as text that reads back as the same calendar, and
    /// writing that gives the same text. `None` for data that is refused (always as invalid data, never a limit).
    fn parsed_and_written(text: &str) -> Option<ParsedCalendar> {
        match accept(text.as_bytes(), &limits()) {
            Ok(parsed) => {
                let written = crate::serialize::serialize(&parsed).unwrap();
                let again = parse(written.as_bytes(), &limits())
                    .unwrap_or_else(|error| panic!("{error:?}: what was written does not read back:\n{written}"));
                assert_eq!(again, parsed, "the writer changes what was read:\n{text}\n{written}");
                assert_eq!(
                    crate::serialize::serialize(&again).unwrap(),
                    written,
                    "the writer is not a fixed point"
                );
                Some(parsed)
            }
            Err(error) => {
                assert!(matches!(error, IcalError::Invalid(_)), "{error:?} for {text:?}");
                None
            }
        }
    }

    fn refusal(text: &str) -> String {
        match accept(text.as_bytes(), &limits()) {
            Err(IcalError::Invalid(message)) => message,
            other => panic!("{text:?} is accepted or refused for another reason: {other:?}"),
        }
    }

    #[test]
    fn a_parameter_name_that_the_writer_cannot_reproduce_is_refused() {
        // The parser unescapes a parameter name like a value, the writer writes it as it is: a backslash, a quote or
        // a colon in the name came back as a different name, as two parameters, or as a line without a value.
        for line in [
            r"T;\:",
            r"E;\n:",
            r"E;\N:",
            r#"R;C"l":"#,
            r#"N;n"5""":"#,
            r"ATTACH;V\\ALUE=URI:Chord",
            r"DTSTART;VA\;LUE=DATE:20270302",
            r"DTEND;TZI\,D=Europe/Berlin:20270302T150000",
            r"ATTENDEE;\\CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT:mailto:anna@example.org",
            r"ATTENDEE;CUTYPE=INDIVIDUAL;CN\=Anna Beispiel:mailto:anna@example.org",
            r"LOCATION;\nLANGUAGE=de-DE:Konferenzraum 3",
            "X-A;X\u{85}Y=1:v",
            "X-A;X\u{2028}Y=1:v",
            "X-A;X'Y=1:v",
        ] {
            let message = refusal(&event_with(line));
            assert!(message.contains("parameter name"), "{line}: {message}");
        }
    }

    #[test]
    fn the_scan_and_the_parser_agree_on_what_blank_is() {
        // `str::trim` strips U+0085 and U+2028 too, which the parser reads as part of a name: the scan then saw a
        // BEGIN or an END that the parser did not, and the two disagreed about the structure.
        for text in [
            "BEGIN:VCALENDAR\r\nBEGIN\u{2028}:VEVENT\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nEND\u{85}:VEVENT\r\nEND:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nEND:VEVENT\r\n\u{2028}END:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\n\u{85}BEGIN:VEVENT\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        ] {
            let message = refusal(text);
            assert!(message.contains("not a valid property name"), "{text:?}: {message}");
            // The reader agrees with the gate on the structure: it is not a gate-only rule.
            assert!(
                matches!(parse(text.as_bytes(), &limits()), Err(IcalError::Invalid(_))),
                "{text:?}"
            );
        }
        // A Unicode line separator inside a value is text.
        let text = event_with("SUMMARY:one\u{2028}two\u{85}three");
        let parsed = parsed_and_written(&text).expect("a Unicode line separator in a value is text");
        let event = parsed.root.children.first().unwrap();
        assert_eq!(
            event.text(&crate::calendar::Prop::Summary).as_deref(),
            Some("one\u{2028}two\u{85}three")
        );
    }

    #[test]
    fn a_value_that_the_writer_formats_differently_is_refused_rather_than_read_another_way() {
        // The reader takes these leniently and its writer writes something else (a floating time for a UTC one with
        // trailing garbage, an offset of four digits for one of one): reading them as the writer would write them
        // would give the client another time than the one it wrote.
        for line in [
            "TZOFFSETTO:+2",
            "TZOFFSETFROM:+0",
            "TZOFFSETFROM:+0I00",
            "TZOFFSETFROM:+0;100",
            "TZOFFSETTO:+0%200",
            "DTSTAMP:20270101T000000Z2",
            "LAST-MODIFIED:20270220T080000Z9",
            "DTSTART:20270303T170000-",
            "DTSTART:20270301T100000+0100",
            r#"T;D="e"P:"#,
        ] {
            let message = refusal(&event_with(line));
            assert!(message.contains("cannot be written back"), "{line}: {message}");
        }
    }

    #[test]
    fn what_clients_send_is_accepted_and_survives_the_writer() {
        // Leniency is the point of the reader: nothing a real client writes may be refused for the sake of the
        // round trip. (The corpus files are tested as whole documents in `tests/corpus.rs`.)
        for line in [
            "DESCRIPTION;ENCODING=QUOTED-PRINTABLE:abc=0D=0Adef",
            "DESCRIPTION;ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:caf=C3=A9",
            "DESCRIPTION;CHARSET=UTF-8:Caf\u{e9}",
            r#"DTSTART;TZID="Europe/Berlin":20270301T100000"#,
            r#"ATTENDEE;CN="Doe, Jane";PARTSTAT=ACCEPTED:mailto:jane@example.org"#,
            "X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=\"Stra\u{df}e 1\\n12345 Berlin\";X-APPLE-RADIUS=49.9;\
             X-TITLE=\"B\u{fc}ro\":geo:52.5,13.4",
            "DTSTART:20270301T100000Z ",
            "DTSTART:20270301",
            "DTEND;VALUE=DATE:20270302",
            "DURATION:P1DT2H",
            "GEO:48.137154;11.576124",
            "EXDATE;TZID=Europe/Berlin:20270302T100000,20270303T100000",
            "RDATE;VALUE=DATE:20270305",
            "RRULE:FREQ=MONTHLY;BYDAY=2TU;UNTIL=20271231",
            "LAST-MODIFIED:20270101T000000",
            "CATEGORIES:a,b",
            "PERCENT-COMPLETE:50",
            r#"ORGANIZER;CN=X;SENT-BY="mailto:y@example.org":mailto:x@example.org"#,
            r#"ATTENDEE;DELEGATED-FROM="mailto:a@example.org","mailto:b@example.org":mailto:c@example.org"#,
            "X-ALT-DESC;FMTTYPE=text/html:<html><body>Hi</body></html>",
            "SUMMARY:",
            r#"LOCATION;ALTREP="http://x.example":Room"#,
            "TRIGGER;RELATED=END:PT5M",
            "summary:lowercase",
            r"SUMMARY:Backslash \\ and semi \; comma \,",
            "X-FOO;X-BAR=baz:value",
            "X-FOO;X_BAR=baz:value",
            "ATTACH;FMTTYPE=application/pdf:https://example.org/a.pdf",
            "ATTACH;ENCODING=BASE64;VALUE=BINARY:SGVsbG8=",
            "REQUEST-STATUS:2.0;Success",
            "TZOFFSETFROM:-0500",
            "TZOFFSETFROM:+010000",
            "TZOFFSETTO:+0530",
            // RFC 6868: ical.js (Thunderbird) and Apple write a quote, a line break and a caret in a parameter
            // value as `^'`, `^n` and `^^`.
            "ATTENDEE;CN=^'Bob^' Smith:mailto:bob@example.org",
            "X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=Street 1^n12345 Berlin:geo:52.5,13.4",
            "ATTENDEE;CN=A^^B;PARTSTAT=ACCEPTED:mailto:ab@example.org",
        ] {
            let text = event_with(line);
            assert!(
                parsed_and_written(&text).is_some(),
                "{line} is refused: {:?}",
                accept(text.as_bytes(), &limits()).unwrap_err()
            );
        }
    }

    #[test]
    fn the_reader_leaves_to_the_gate_what_only_the_gate_refuses() {
        // Objects that were stored before the gate was this strict stay readable: a query, a feed or a free-busy
        // answer must not fail for one of them. Only what comes in is held to the writer.
        for line in [
            "DTSTART:20270301T100000+0100",
            "DTSTAMP:20270101T000000Z2",
            r"ATTENDEE;\\CUTYPE=INDIVIDUAL:mailto:anna@example.org",
            "X-A;X'Y=1:v",
            "X-A;X\u{85}Y=1:v",
        ] {
            let text = event_with(line);
            assert!(parse(text.as_bytes(), &limits()).is_ok(), "{line} is not read");
            assert!(
                matches!(accept(text.as_bytes(), &limits()), Err(IcalError::Invalid(_))),
                "{line} is accepted"
            );
        }
    }

    #[test]
    fn the_text_the_writer_writes_is_held_to_the_limits_of_the_input() {
        // Commas that a client sent without a backslash are written with one: the text is twice as long as it was
        // sent. The server may store its own text, and a stored object is read under the same limits, so data whose
        // written form does not fit is refused when it comes in, as the value that is too long that it is, and not
        // when the server first rewrites it.
        let tight = IcalLimits {
            max_value_length: 64,
            ..IcalLimits::default()
        };
        let text = event_with(&format!("DESCRIPTION:{}", ",".repeat(60)));
        assert!(
            parse(text.as_bytes(), &tight).is_ok(),
            "the reader takes what is within the limit"
        );
        assert_eq!(
            accept(text.as_bytes(), &tight),
            Err(IcalError::Limit(LimitKind::ValueLength))
        );
        // Thirty commas are written as sixty characters, which fit.
        let fits = event_with(&format!("DESCRIPTION:{}", ",".repeat(30)));
        let accepted = accept(fits.as_bytes(), &tight).expect("the written form fits the limit");
        let written = crate::serialize::serialize(&accepted).unwrap().replace("\r\n ", "");
        assert!(
            written.contains(&format!("DESCRIPTION:{}", "\\,".repeat(30))),
            "{written}"
        );
        assert!(
            parse(written.as_bytes(), &tight).is_ok(),
            "what the server writes is read under the limit"
        );
        // What is above the limit as it is sent is refused by both.
        let too_long = event_with(&format!("DESCRIPTION:{}", "x".repeat(65)));
        for result in [parse(too_long.as_bytes(), &tight), accept(too_long.as_bytes(), &tight)] {
            assert_eq!(result, Err(IcalError::Limit(LimitKind::ValueLength)));
        }
    }

    #[test]
    fn a_description_of_forty_thousand_commas_is_refused_when_it_comes_in() {
        // A counterexample of the round trip of the harnesses: a value within the limit as sent (40,000 bytes of
        // 65,536) that is written as twice as long (80,000), so that the server could not rewrite it (a JSON merge,
        // a SCHEDULE-STATUS) and the harness could not read back its own text under the limits of the input.
        let text = event_with(&format!("DESCRIPTION:{}", ",".repeat(40_000)));
        assert!(parse(text.as_bytes(), &limits()).is_ok());
        assert_eq!(
            accept(text.as_bytes(), &limits()),
            Err(IcalError::Limit(LimitKind::ValueLength))
        );
        let fits = event_with(&format!("DESCRIPTION:{}", ",".repeat(30_000)));
        assert!(accept(fits.as_bytes(), &limits()).is_ok());
    }

    #[test]
    fn the_written_form_must_fit_the_resource_size() {
        // `CRLF` after every line is longer than `LF`: data at the limit as it is sent, with bare line feeds, would
        // be longer once the server writes it.
        let lf = EVENT.replace("\r\n", "\n");
        let exact = IcalLimits {
            max_resource_size: u64::try_from(lf.len()).unwrap(),
            ..IcalLimits::default()
        };
        assert!(parse(lf.as_bytes(), &exact).is_ok());
        assert_eq!(
            accept(lf.as_bytes(), &exact),
            Err(IcalError::Limit(LimitKind::ResourceSize))
        );
        let crlf = IcalLimits {
            max_resource_size: u64::try_from(EVENT.len()).unwrap(),
            ..IcalLimits::default()
        };
        assert!(accept(EVENT.as_bytes(), &crlf).is_ok());
    }
}
