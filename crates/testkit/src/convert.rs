//! The capture converter: DAV exchanges recorded by a server into a client-flow scenario.
//!
//! With `observability.dav_capture.enabled = true` a server writes one JSON file per DAV request of the tenants in its
//! allowlist (`davhaven_server::capture`, PLAN 2.17): method, path, headers (credentials redacted), bodies and status of
//! the request and of the answer. Real clients, pointed at a staging instance that holds the world of a run
//! ([`staging`](crate::staging)), leave such files behind. [`convert`] turns the files of one client doing one thing into a
//! scenario of the client-flow suite ([`Scenario`]): the same requests, with the values that belong to the run replaced
//! by variables, the values the server made up replaced by captures, and what the client got back stated structurally, so
//! that the scenario runs against any world of the fixture, in process in CI and over HTTP against staging.
//!
//! # What becomes what
//!
//! * The tenant slug of the run in a path (`/dav/calendars/{tenant}/...`, `/dav/principals/{tenant}/...`) becomes
//!   `{{tenant}}`, the login domain `{{login_domain}}`. The names of the principals are those of the fixture world (the
//!   instance that was captured held the world of a run), and so are the slugs of its calendars.
//! * An `ETag`, a `Schedule-Tag`, a `Location` or a sync token that an answer carries and a later request repeats
//!   (`If-Match`, `If-Schedule-Tag-Match`, `Destination`, the body of a `sync-collection`) becomes a capture of the step
//!   that got it and `{{name}}` in the step that sends it again. Values that nobody repeats are not captured.
//! * Of the headers of a request only the ones that carry meaning for the server are kept (`Content-Type`, `Depth`, the
//!   conditions, `Prefer`, `Destination`, `Overwrite`, `Schedule-Reply`, `Accept`).
//! * The answer becomes a status, the presence of the entity tags it carried, the status of each resource of a
//!   multistatus, and for calendar data the `UID`, `SUMMARY`, `DTSTART`, `RRULE` and `STATUS` lines.
//! * The free text of calendar data (`SUMMARY`, `DESCRIPTION`, `LOCATION`, `COMMENT`, `CONTACT` and the `CN` of people) is
//!   replaced by neutral text unless [`Options::keep_text`] is set: a capture holds what real people wrote.
//!
//! The scenario is marked `captured` with the provenance the caller gives and the time span of the capture.

use core::fmt::{self, Write as _};
use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use davhaven_fixtures::ActorRole;
use serde::Deserialize;

use crate::flow::{FlowError, Scenario};
use crate::xml::Document;

/// The version of the capture file format this reader accepts (`davhaven_server::capture::SCHEMA_VERSION`).
pub const CAPTURE_SCHEMA_VERSION: u32 = davhaven_server::capture::SCHEMA_VERSION;

/// Why files cannot be converted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConvertError {
    /// A file or directory cannot be read.
    #[error("cannot read {path}: {reason}")]
    Io {
        /// The path.
        path: String,
        /// The operating system's message.
        reason: String,
    },
    /// A file is not a capture of the format this reader knows.
    #[error("{file} is not a capture: {reason}")]
    Format {
        /// The file.
        file: String,
        /// What is wrong.
        reason: String,
    },
    /// An exchange has a body that is not text.
    #[error("{file} has a body that is not UTF-8 text; calendar data and DAV XML are text")]
    Binary {
        /// The file.
        file: String,
    },
    /// There is nothing to convert.
    #[error("no capture files were found")]
    Empty,
    /// The captures name more than one tenant.
    #[error("the captures belong to several tenants ({0}); convert one tenant at a time")]
    SeveralTenants(String),
    /// The scenario that was written does not read back (a defect of the converter, never of the input).
    #[error("the scenario that was written is not valid: {0}")]
    Invalid(String),
}

/// What an exchange sent.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_base64: Option<String>,
}

/// What an exchange got back.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResponse {
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_base64: Option<String>,
}

/// A capture file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapture {
    schema_version: u32,
    captured_at: String,
    tenant: String,
    request: RawRequest,
    response: RawResponse,
}

/// One recorded request and its answer, bodies as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// The name of the file it was read from; files sort in the order of the exchanges.
    pub file: String,
    /// When the server recorded it (UTC, millisecond precision).
    pub captured_at: String,
    /// The tenant slug of the capture.
    pub tenant: String,
    /// The method.
    pub method: String,
    /// The path with the query, as the client sent it.
    pub target: String,
    /// The request headers (names lower case).
    pub request_headers: Vec<(String, String)>,
    /// The request body.
    pub request_body: Option<String>,
    /// The status of the answer.
    pub status: u16,
    /// The headers of the answer (names lower case).
    pub response_headers: Vec<(String, String)>,
    /// The body of the answer.
    pub response_body: Option<String>,
}

impl Exchange {
    fn request_header(&self, name: &str) -> Option<&str> {
        header(&self.request_headers, name)
    }

    fn response_header(&self, name: &str) -> Option<&str> {
        header(&self.response_headers, name)
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn text_of(file: &str, text: Option<String>, base64: Option<String>) -> Result<Option<String>, ConvertError> {
    if let Some(text) = text {
        return Ok(Some(text));
    }
    let Some(encoded) = base64 else {
        return Ok(None);
    };
    let bytes = STANDARD
        .decode(encoded.as_bytes())
        .map_err(|error| ConvertError::Format {
            file: file.to_owned(),
            reason: format!("a base64 body cannot be decoded: {error}"),
        })?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ConvertError::Binary { file: file.to_owned() })
}

/// Reads one capture file.
///
/// # Errors
///
/// [`ConvertError::Format`] for a file that is not a capture of this version, [`ConvertError::Binary`] for a body that is
/// not text.
pub fn parse_capture(file: &str, text: &str) -> Result<Exchange, ConvertError> {
    let raw: RawCapture = serde_json::from_str(text).map_err(|error| ConvertError::Format {
        file: file.to_owned(),
        reason: error.to_string(),
    })?;
    if raw.schema_version != CAPTURE_SCHEMA_VERSION {
        return Err(ConvertError::Format {
            file: file.to_owned(),
            reason: format!(
                "schema_version is {}, this reader knows {CAPTURE_SCHEMA_VERSION}",
                raw.schema_version
            ),
        });
    }
    let lower = |headers: Vec<(String, String)>| -> Vec<(String, String)> {
        headers
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect()
    };
    let target = match &raw.request.query {
        Some(query) if !query.is_empty() => format!("{}?{query}", raw.request.path),
        _ => raw.request.path.clone(),
    };
    Ok(Exchange {
        file: file.to_owned(),
        captured_at: raw.captured_at,
        tenant: raw.tenant,
        method: raw.request.method.clone(),
        target,
        request_headers: lower(raw.request.headers),
        request_body: text_of(file, raw.request.body, raw.request.body_base64)?,
        status: raw.response.status,
        response_headers: lower(raw.response.headers),
        response_body: text_of(file, raw.response.body, raw.response.body_base64)?,
    })
}

/// Reads every `*.json` file directly in `dir`, in the order of their names (which is the order of the exchanges).
///
/// # Errors
///
/// [`ConvertError::Io`] for a directory or file that cannot be read, [`ConvertError::Empty`] for a directory without
/// captures, and the errors of [`parse_capture`].
pub fn read_captures(dir: &Path) -> Result<Vec<Exchange>, ConvertError> {
    let io = |error: std::io::Error| ConvertError::Io {
        path: dir.display().to_string(),
        reason: error.to_string(),
    };
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(io)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()
        .map_err(io)?;
    files.retain(|path| path.extension().is_some_and(|extension| extension == "json"));
    files.sort();
    let mut exchanges = Vec::with_capacity(files.len());
    for path in files {
        let text = std::fs::read_to_string(&path).map_err(|error| ConvertError::Io {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        let name = path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        exchanges.push(parse_capture(&name, &text)?);
    }
    if exchanges.is_empty() {
        return Err(ConvertError::Empty);
    }
    Ok(exchanges)
}

/// What the converter is told about the captured flow.
#[derive(Debug, Clone)]
pub struct Options {
    /// The unique name of the scenario.
    pub name: String,
    /// What the scenario shows.
    pub description: Option<String>,
    /// The client of the client-by-feature grid (`apple-calendar`, `davx5`, ...).
    pub client: String,
    /// The feature of the grid (`crud`, `invite-internal`, ...).
    pub feature: String,
    /// Where the capture comes from: the client and its version, the device, the date. The span of the capture is added.
    pub provenance: String,
    /// The role of the fixture world that the captured user plays; the user is found by the name in the paths when it is
    /// `None`.
    pub actor: Option<ActorRole>,
    /// The login domain of the captured tenant, replaced by `{{login_domain}}` where it appears.
    pub login_domain: Option<String>,
    /// Keeps the free text of the calendar data instead of replacing it.
    pub keep_text: bool,
}

/// The result of a conversion.
#[derive(Debug, Clone, PartialEq)]
pub struct Converted {
    /// The scenario as YAML text.
    pub yaml: String,
    /// The scenario as the runner reads it back.
    pub scenario: Scenario,
}

// ---------------------------------------------------------------------------------------------------------------
// YAML
// ---------------------------------------------------------------------------------------------------------------

/// Appends formatted text.
fn put(out: &mut String, args: fmt::Arguments<'_>) {
    let _ = out.write_fmt(args);
}

/// A double-quoted YAML scalar.
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control.is_control() => put(&mut out, format_args!("\\u{:04X}", u32::from(control))),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Whether a multi-line text can be written as a literal block without changing it.
fn fits_a_block(text: &str) -> bool {
    !text.is_empty()
        && text.contains('\n')
        && !text.contains('\r')
        && !text.starts_with([' ', '\n', '\t'])
        && !text
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
        && !text.ends_with("\n\n")
}

/// A key and a text value at `indent` spaces: a literal block for text that fits one, a quoted scalar otherwise.
fn field(out: &mut String, indent: usize, key: &str, value: &str) {
    let pad = " ".repeat(indent);
    if fits_a_block(value) {
        let chomp = if value.ends_with('\n') { "" } else { "-" };
        put(out, format_args!("{pad}{key}: |{chomp}\n"));
        for line in value.strip_suffix('\n').unwrap_or(value).split('\n') {
            if line.is_empty() {
                out.push('\n');
            } else {
                put(out, format_args!("{pad}  {line}\n"));
            }
        }
    } else {
        put(out, format_args!("{pad}{key}: {}\n", quoted(value)));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Values that the server made up
// ---------------------------------------------------------------------------------------------------------------

/// A value that an answer carried and that a later request may repeat.
#[derive(Debug, Clone)]
struct Candidate {
    value: String,
    name: String,
    /// `header: ETag` or `xpath: ...`: how the scenario captures it.
    source: Source,
    step: usize,
    used: bool,
}

#[derive(Debug, Clone)]
enum Source {
    Header(&'static str),
    XPath(&'static str),
}

/// The headers of a request that are kept.
const KEPT_REQUEST_HEADERS: [&str; 9] = [
    "content-type",
    "depth",
    "if-match",
    "if-none-match",
    "if-schedule-tag-match",
    "prefer",
    "destination",
    "overwrite",
    "schedule-reply",
];

/// The headers of an answer whose presence is stated.
const PRESENT_RESPONSE_HEADERS: [&str; 2] = ["etag", "schedule-tag"];

/// The properties of iCalendar whose value is free text that somebody wrote.
const FREE_TEXT: [&str; 9] = [
    "SUMMARY",
    "DESCRIPTION",
    "LOCATION",
    "COMMENT",
    "CONTACT",
    "X-ALT-DESC",
    "CATEGORIES",
    "RESOURCES",
    "X-WR-CALDESC",
];

/// The parameters whose value is somebody's text: the name of a person, the title and address of a place.
const TEXT_PARAMETERS: [&str; 4] = ["CN", "X-TITLE", "X-ADDRESS", "LABEL"];

/// The parameters whose value is an address.
const ADDRESS_PARAMETERS: [&str; 2] = ["EMAIL", "SENT-BY"];

/// The elements of the DAV and CalendarServer XML of a request whose text is somebody's: the names of calendars, their
/// descriptions, the names and remarks of the people a calendar is shared with.
const XML_TEXT: [&str; 5] = [
    "displayname",
    "calendar-description",
    "calendar-name",
    "common-name",
    "summary",
];

/// The position of the first `delimiter` that is not inside a quoted string.
fn first_outside_quotes(text: &str, delimiter: char) -> Option<usize> {
    let mut quoted = false;
    for (index, character) in text.char_indices() {
        if character == '"' {
            quoted = !quoted;
        } else if character == delimiter && !quoted {
            return Some(index);
        }
    }
    None
}

/// `text` cut at every `delimiter` that is not inside a quoted string.
fn split_outside_quotes(text: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = text;
    while let Some(index) = first_outside_quotes(rest, delimiter) {
        parts.push(rest.get(..index).unwrap_or_default());
        rest = rest.get(index + delimiter.len_utf8()..).unwrap_or_default();
    }
    parts.push(rest);
    parts
}

/// A parameter value written as the format asks for it: in quotes (the text of a person has spaces and punctuation).
fn quoted_param(text: &str) -> String {
    format!("\"{text}\"")
}

/// Replaces what real people wrote in calendar data and in DAV XML by neutral text, the same text for the same original.
///
/// Calendar data is unfolded first (a property folded at 75 octets is one text, and where it was cut is a matter of the client
/// that wrote it, so the request and the answer of a server would otherwise get different texts), and written unfolded.
/// Parameters are found by name without regard to case and with respect for quoted values (a name may hold a colon or a
/// semicolon). Addresses outside the login domain of the captured tenant are somebody's too, and are replaced.
#[derive(Debug, Default)]
struct Scrubber {
    seen: BTreeMap<String, usize>,
    addresses: BTreeMap<String, usize>,
    login_domain: Option<String>,
}

impl Scrubber {
    fn new(login_domain: Option<&str>) -> Self {
        Self {
            login_domain: login_domain.map(str::to_ascii_lowercase),
            ..Self::default()
        }
    }

    fn number(&mut self, original: &str) -> usize {
        let next = self.seen.len() + 1;
        *self.seen.entry(original.to_owned()).or_insert(next)
    }

    fn replacement(&mut self, original: &str) -> String {
        format!("Text {}", self.number(original))
    }

    /// An address (`mailto:` form or bare, perhaps in quotes): unchanged inside the login domain, `guestN@example.net` outside
    /// it. Without a login domain nothing is known about whose addresses these are, and they stay.
    fn address(&mut self, original: &str) -> String {
        let Some(login_domain) = self.login_domain.clone() else {
            return original.to_owned();
        };
        let quoted = original.starts_with('"') && original.ends_with('"') && original.len() >= 2;
        let bare = original.trim_matches('"');
        let (prefix, mailbox) = match bare.get(..7) {
            Some(start) if start.eq_ignore_ascii_case("mailto:") => (start, bare.get(7..).unwrap_or_default()),
            _ => ("", bare),
        };
        let Some((_, domain)) = mailbox.rsplit_once('@') else {
            return original.to_owned();
        };
        if domain.eq_ignore_ascii_case(&login_domain) {
            return original.to_owned();
        }
        let next = self.addresses.len() + 1;
        let number = *self.addresses.entry(mailbox.to_ascii_lowercase()).or_insert(next);
        let replaced = format!("{prefix}guest{number}@example.net");
        if quoted { format!("\"{replaced}\"") } else { replaced }
    }

    /// The calendar data with its free text and the addresses outside the login domain replaced. The line endings stay as
    /// they are; folded lines come out unfolded.
    fn ical(&mut self, text: &str) -> String {
        let unfolded = unfold(text);
        let mut out = String::with_capacity(unfolded.len());
        for line in unfolded.split_inclusive('\n') {
            let (body, ending) = match line.strip_suffix("\r\n") {
                Some(body) => (body, "\r\n"),
                None => match line.strip_suffix('\n') {
                    Some(body) => (body, "\n"),
                    None => (line, ""),
                },
            };
            out.push_str(&self.line(body));
            out.push_str(ending);
        }
        out
    }

    /// One logical line of calendar data.
    fn line(&mut self, line: &str) -> String {
        let Some(colon) = first_outside_quotes(line, ':') else {
            return line.to_owned();
        };
        let head = line.get(..colon).unwrap_or_default();
        let value = line.get(colon + 1..).unwrap_or_default();
        let mut parts = split_outside_quotes(head, ';').into_iter();
        let written_name = parts.next().unwrap_or_default();
        let name = written_name.to_ascii_uppercase();
        let params: Vec<&str> = parts.collect();

        // Properties whose value is taken whole: the text goes, and so do the parameters that could carry more of it.
        if FREE_TEXT.contains(&name.as_str()) {
            let replaced = self.replacement(value);
            return self.assemble(written_name, &params, &replaced);
        }
        match name.as_str() {
            "URL" => {
                let number = self.number(value);
                return self.assemble(written_name, &params, &format!("https://example.net/url-{number}"));
            }
            "ATTACH" => {
                // An inline attachment is the content of a file: nothing of it is kept, and the parameters that describe it
                // (`ENCODING`, `VALUE`) go with it.
                let number = self.number(value);
                return format!("{written_name}:https://example.net/attachment-{number}");
            }
            "GEO" => return self.assemble(written_name, &params, "0.0;0.0"),
            "X-APPLE-STRUCTURED-LOCATION" => return self.assemble(written_name, &params, "geo:0.0,0.0"),
            _ => {}
        }
        let replaced_value = if name == "ATTENDEE" || name == "ORGANIZER" {
            // The address stays when it is one of the tenant's (it is what scheduling is about); the common name is somebody's.
            self.address(value)
        } else {
            value.to_owned()
        };
        self.assemble(written_name, &params, &replaced_value)
    }

    /// The property written out again: its name as it was written, the parameters with the text and the addresses in them
    /// replaced, and the value.
    fn assemble(&mut self, name: &str, params: &[&str], value: &str) -> String {
        let mut out = String::from(name);
        for param in params {
            out.push(';');
            let Some((key, original)) = param.split_once('=') else {
                out.push_str(param);
                continue;
            };
            let upper = key.to_ascii_uppercase();
            if TEXT_PARAMETERS.contains(&upper.as_str()) {
                let replaced = self.replacement(original.trim_matches('"'));
                put(&mut out, format_args!("{key}={}", quoted_param(&replaced)));
            } else if ADDRESS_PARAMETERS.contains(&upper.as_str()) {
                let replaced = self.address(original);
                put(&mut out, format_args!("{key}={replaced}"));
            } else {
                out.push_str(param);
            }
        }
        out.push(':');
        out.push_str(value);
        out
    }

    /// DAV XML with the text of the elements of [`XML_TEXT`] replaced; everything else stays as it is.
    fn xml(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(open) = rest.find('<') {
            let (before, from) = rest.split_at(open);
            out.push_str(before);
            let Some(close) = from.find('>') else {
                out.push_str(from);
                return out;
            };
            let tag = from.get(..=close).unwrap_or_default();
            out.push_str(tag);
            rest = from.get(close + 1..).unwrap_or_default();
            let Some(name) = start_tag_name(tag) else {
                continue;
            };
            let local = name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase();
            if !XML_TEXT.contains(&local.as_str()) {
                continue;
            }
            let end_tag = format!("</{name}>");
            if let Some(end) = rest.find(&end_tag) {
                let inner = rest.get(..end).unwrap_or_default();
                if !inner.contains('<') && !inner.trim().is_empty() {
                    out.push_str(&self.replacement(inner.trim()));
                    rest = rest.get(end..).unwrap_or_default();
                }
            }
        }
        out.push_str(rest);
        out
    }
}

/// The qualified name of an element that a start tag opens; `None` for end tags, comments, processing instructions and
/// elements that are empty.
fn start_tag_name(tag: &str) -> Option<&str> {
    let inner = tag.strip_prefix('<')?.strip_suffix('>')?;
    if inner.starts_with(['/', '?', '!']) || inner.ends_with('/') {
        return None;
    }
    inner.split(|character: char| character.is_whitespace()).next()
}

/// The calendar data with its folded lines joined.
fn unfold(text: &str) -> String {
    text.replace("\r\n ", "")
        .replace("\r\n\t", "")
        .replace("\n ", "")
        .replace("\n\t", "")
}

/// The lines of an object that a scenario asserts: its `UID`, `SUMMARY`, `DTSTART`, `RRULE` and `STATUS`.
fn asserted_lines(ical: &str) -> Vec<String> {
    let unfolded = unfold(ical);
    let mut lines = Vec::new();
    for wanted in ["UID", "SUMMARY", "DTSTART", "RRULE", "STATUS"] {
        let found = unfolded.lines().map(|line| line.trim_end_matches('\r')).find(|line| {
            line.split_once(':').is_some_and(|(head, _)| {
                let name = head.split(';').next().unwrap_or(head);
                name.eq_ignore_ascii_case(wanted)
            })
        });
        if let Some(line) = found {
            lines.push(line.to_owned());
        }
    }
    lines
}

fn is_ical(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| value.to_ascii_lowercase().starts_with("text/calendar"))
}

fn is_xml(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.starts_with("application/xml") || value.starts_with("text/xml")
    })
}

// ---------------------------------------------------------------------------------------------------------------
// The conversion
// ---------------------------------------------------------------------------------------------------------------

/// The context of one conversion: what is replaced in text, and which values were seen.
struct Conversion<'a> {
    options: &'a Options,
    tenant: &'a str,
    scrubber: Scrubber,
    candidates: Vec<Candidate>,
    counters: BTreeMap<&'static str, usize>,
}

impl Conversion<'_> {
    /// `text` with the run's names replaced by variables.
    fn generalize(&self, text: &str) -> String {
        let mut text = text
            .replace(
                &format!("/dav/calendars/{}/", self.tenant),
                "/dav/calendars/{{tenant}}/",
            )
            .replace(
                &format!("/dav/principals/{}/", self.tenant),
                "/dav/principals/{{tenant}}/",
            );
        if let Some(domain) = &self.options.login_domain {
            text = text.replace(&format!("@{domain}"), "@{{login_domain}}");
        }
        text
    }

    /// `text` with the values of earlier answers replaced by their captures; marks the ones that were used.
    fn substitute(&mut self, text: &str, before_step: usize) -> String {
        let mut text = text.to_owned();
        for candidate in &mut self.candidates {
            if candidate.step < before_step && !candidate.value.is_empty() && text.contains(&candidate.value) {
                text = text.replace(&candidate.value, &format!("{{{{{}}}}}", candidate.name));
                candidate.used = true;
            }
        }
        text
    }

    fn remember(&mut self, kind: &'static str, value: &str, source: Source, step: usize) {
        if value.is_empty() || self.candidates.iter().any(|candidate| candidate.value == value) {
            return;
        }
        let counter = self.counters.entry(kind).or_insert(0);
        *counter += 1;
        self.candidates.push(Candidate {
            value: value.to_owned(),
            name: format!("{kind}{counter}"),
            source,
            step,
            used: false,
        });
    }

    fn body(&mut self, body: &str, content_type: Option<&str>, step: usize) -> String {
        let text = if self.options.keep_text {
            body.to_owned()
        } else if is_ical(content_type) {
            self.scrubber.ical(body)
        } else if is_xml(content_type) {
            self.scrubber.xml(body)
        } else {
            body.to_owned()
        };
        let generalized = self.generalize(&text);
        self.substitute(&generalized, step)
    }
}

/// The user of a capture: the name that most paths below `/dav/calendars/{tenant}/` carry.
fn captured_user(exchanges: &[Exchange]) -> Option<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for exchange in exchanges {
        let prefix = format!("/dav/calendars/{}/", exchange.tenant);
        if let Some(rest) = exchange.target.strip_prefix(&prefix)
            && let Some(name) = rest.split('/').next().filter(|name| !name.is_empty())
        {
            *counts.entry(name.to_owned()).or_default() += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, count)| *count).map(|(name, _)| name)
}

/// The statuses of the responses of a multistatus: `href` and the status the resource has (the status of the response
/// itself, or 200 when every property is there, otherwise the status of the first property that is not).
fn multistatus_statuses(body: &str) -> Vec<(String, u16)> {
    let Ok(document) = Document::parse(body) else {
        return Vec::new();
    };
    let Ok(entries) = document.multistatus() else {
        return Vec::new();
    };
    entries
        .into_iter()
        .map(|entry| {
            let status = entry.status.unwrap_or_else(|| {
                entry
                    .propstats
                    .iter()
                    .map(|propstat| propstat.status)
                    .find(|status| !(200..300).contains(status))
                    .unwrap_or(200)
            });
            (entry.href, status)
        })
        .collect()
}

fn sync_token_of(body: &str) -> Option<String> {
    let document = Document::parse(body).ok()?;
    document
        .select("/{DAV:}multistatus/{DAV:}sync-token")
        .ok()?
        .into_iter()
        .next()
        .map(|token| token.trim().to_owned())
}

/// Converts the exchanges of one captured flow into a scenario.
///
/// # Errors
///
/// [`ConvertError::Empty`] without exchanges, [`ConvertError::SeveralTenants`] when the exchanges belong to more than one
/// tenant, [`ConvertError::Invalid`] when the scenario that was written does not read back (a defect of the converter).
pub fn convert(exchanges: &[Exchange], options: &Options) -> Result<Converted, ConvertError> {
    let (Some(first), Some(last)) = (exchanges.first(), exchanges.last()) else {
        return Err(ConvertError::Empty);
    };
    let mut tenants: Vec<&str> = exchanges.iter().map(|exchange| exchange.tenant.as_str()).collect();
    tenants.sort_unstable();
    tenants.dedup();
    if tenants.len() > 1 {
        return Err(ConvertError::SeveralTenants(tenants.join(", ")));
    }
    let user = captured_user(exchanges);
    let role = options.actor.unwrap_or_else(|| {
        user.as_deref()
            .and_then(|name| {
                ActorRole::ALL
                    .iter()
                    .copied()
                    .find(|role| role.principal_name() == Some(name))
            })
            .unwrap_or(ActorRole::Owner)
    });
    let actor = user.clone().unwrap_or_else(|| "user".to_owned());

    let mut conversion = Conversion {
        options,
        tenant: &first.tenant,
        scrubber: Scrubber::new(options.login_domain.as_deref()),
        candidates: Vec::new(),
        counters: BTreeMap::new(),
    };
    let mut steps = String::new();
    let mut step_texts: Vec<String> = Vec::with_capacity(exchanges.len());
    for (index, exchange) in exchanges.iter().enumerate() {
        step_texts.push(convert_step(&mut conversion, exchange, index, &actor));
    }
    // The captures are written into the step that got the value, now that it is known which values were repeated.
    for (index, text) in step_texts.iter().enumerate() {
        let mut captures = String::new();
        for candidate in conversion
            .candidates
            .iter()
            .filter(|candidate| candidate.step == index && candidate.used)
        {
            let source = match candidate.source {
                Source::Header(name) => format!("header: {name}"),
                Source::XPath(path) => format!("xpath: {}", quoted(path)),
            };
            put(
                &mut captures,
                format_args!("      {}: {{ {source} }}\n", candidate.name),
            );
        }
        steps.push_str(&text.replace(
            "@@captures@@",
            &if captures.is_empty() {
                String::new()
            } else {
                format!("    capture:\n{captures}")
            },
        ));
    }

    let mut yaml = String::new();
    yaml.push_str("schema_version: 1\n");
    put(&mut yaml, format_args!("name: {}\n", quoted(&options.name)));
    if let Some(description) = &options.description {
        field(&mut yaml, 0, "description", description);
    }
    put(&mut yaml, format_args!("client: {}\n", quoted(&options.client)));
    put(&mut yaml, format_args!("feature: {}\n", quoted(&options.feature)));
    yaml.push_str("origin: captured\n");
    put(
        &mut yaml,
        format_args!(
            "provenance: {}\n",
            quoted(&format!(
                "{} (captured {} to {}, {} exchanges)",
                options.provenance.trim(),
                first.captured_at,
                last.captured_at,
                exchanges.len()
            ))
        ),
    );
    yaml.push_str("actors:\n");
    put(&mut yaml, format_args!("  {actor}: {role}\n"));
    yaml.push_str("steps:\n");
    yaml.push_str(&steps);
    let scenario = Scenario::from_yaml(&yaml).map_err(|error| match error {
        FlowError::Parse(reason) | FlowError::Template(reason) => ConvertError::Invalid(reason),
        other => ConvertError::Invalid(other.to_string()),
    })?;
    Ok(Converted { yaml, scenario })
}

/// The YAML of one step; the captures are filled in later at `@@captures@@`.
fn convert_step(conversion: &mut Conversion<'_>, exchange: &Exchange, index: usize, actor: &str) -> String {
    let mut out = step_request(conversion, exchange, index, actor);
    remember_answer(conversion, exchange, index);
    out.push_str("@@captures@@");
    out.push_str(&step_expectation(conversion, exchange, index));
    out
}

/// The YAML of the request of one step.
fn step_request(conversion: &mut Conversion<'_>, exchange: &Exchange, index: usize, actor: &str) -> String {
    let mut out = String::new();
    let method = exchange.method.to_ascii_uppercase();
    let target = {
        let generalized = conversion.generalize(&exchange.target);
        conversion.substitute(&generalized, index)
    };
    let name = format!(
        "{:02} {method} {}",
        index + 1,
        short(&exchange.target, conversion.tenant)
    );
    put(&mut out, format_args!("  - name: {}\n", quoted(&name)));
    put(&mut out, format_args!("    as: {actor}\n"));
    out.push_str("    request:\n");
    put(&mut out, format_args!("      method: {method}\n"));
    put(&mut out, format_args!("      path: {}\n", quoted(&target)));
    let content_type = exchange.request_header("content-type");
    let mut headers = Vec::new();
    for kept in KEPT_REQUEST_HEADERS {
        if let Some(value) = exchange.request_header(kept) {
            let generalized = conversion.generalize(value);
            headers.push((kept, conversion.substitute(&generalized, index)));
        }
    }
    if !headers.is_empty() {
        out.push_str("      headers:\n");
        for (name, value) in &headers {
            put(
                &mut out,
                format_args!("        {}: {}\n", title_case(name), quoted(value)),
            );
        }
    }
    if let Some(body) = exchange.request_body.as_deref().filter(|body| !body.is_empty()) {
        let text = conversion.body(body, content_type, index);
        if is_ical(content_type) {
            // The runner sends calendar data with CRLF line endings; the file holds plain line breaks.
            field(&mut out, 6, "ical", &text.replace("\r\n", "\n"));
        } else {
            field(&mut out, 6, "body", &text);
        }
    }
    out
}

/// Remembers the values the server made up in the answer of a step: a later request may repeat them.
fn remember_answer(conversion: &mut Conversion<'_>, exchange: &Exchange, index: usize) {
    for header_name in PRESENT_RESPONSE_HEADERS {
        if let Some(value) = exchange.response_header(header_name) {
            let (kind, source) = if header_name == "etag" {
                ("etag", Source::Header("ETag"))
            } else {
                ("scheduletag", Source::Header("Schedule-Tag"))
            };
            conversion.remember(kind, value, source, index);
        }
    }
    if let Some(location) = exchange.response_header("location") {
        let generalized = conversion.generalize(location);
        conversion.remember("location", &generalized, Source::Header("Location"), index);
    }
    let response_type = exchange.response_header("content-type");
    if let Some(body) = exchange.response_body.as_deref()
        && is_xml(response_type)
        && let Some(token) = sync_token_of(body)
    {
        conversion.remember(
            "sync",
            &token,
            Source::XPath("/{DAV:}multistatus/{DAV:}sync-token"),
            index,
        );
    }
}

/// The YAML of what the answer of a step is expected to be.
fn step_expectation(conversion: &mut Conversion<'_>, exchange: &Exchange, index: usize) -> String {
    let mut out = String::new();
    let response_type = exchange.response_header("content-type");
    out.push_str("    expect:\n");
    put(&mut out, format_args!("      status: {}\n", exchange.status));
    let present: Vec<&str> = PRESENT_RESPONSE_HEADERS
        .into_iter()
        .filter(|name| exchange.response_header(name).is_some())
        .collect();
    if !present.is_empty() {
        out.push_str("      headers:\n");
        for name in present {
            put(&mut out, format_args!("        {name}: {{}}\n"));
        }
    }
    if exchange.status == 207
        && let Some(body) = exchange.response_body.as_deref()
    {
        let statuses = multistatus_statuses(body);
        if !statuses.is_empty() {
            out.push_str("      statuses:\n");
            let mut seen = Vec::new();
            for (href, status) in statuses {
                let href = conversion.generalize(&href);
                if !seen.contains(&href) {
                    put(&mut out, format_args!("        {}: {status}\n", quoted(&href)));
                    seen.push(href);
                }
            }
        }
    }
    if is_ical(response_type)
        && let Some(body) = exchange.response_body.as_deref()
    {
        let text = if conversion.options.keep_text {
            body.to_owned()
        } else {
            conversion.scrubber.ical(body)
        };
        let lines = asserted_lines(&text);
        if !lines.is_empty() {
            out.push_str("      ical_contains:\n");
            for line in lines {
                let generalized = conversion.generalize(&line);
                let substituted = conversion.substitute(&generalized, index + 1);
                put(&mut out, format_args!("        - {}\n", quoted(&substituted)));
            }
        }
    }
    out
}

/// The path of a step shortened for its name: the part after the home of the tenant.
fn short(target: &str, tenant: &str) -> String {
    let stripped = target
        .strip_prefix(&format!("/dav/calendars/{tenant}/"))
        .or_else(|| target.strip_prefix(&format!("/dav/principals/{tenant}/")))
        .unwrap_or(target);
    stripped.chars().take(60).collect()
}

fn title_case(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + characters.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

impl fmt::Display for Converted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.yaml)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[expect(
        clippy::too_many_arguments,
        reason = "a recorded exchange has exactly these parts, and the tests read best with them in the order of the file"
    )]
    fn capture(
        sequence: usize,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
        status: u16,
        response_headers: &[(&str, &str)],
        response_body: Option<&str>,
    ) -> Exchange {
        let value = json!({
            "schema_version": 1,
            "captured_at": format!("2027-03-01T10:15:{sequence:02}.000Z"),
            "tenant": "r42-a",
            "request": {
                "method": method,
                "path": path,
                "query": null,
                "headers": headers.iter().map(|(n, v)| json!([n, v])).collect::<Vec<_>>(),
                "body": body,
            },
            "response": {
                "status": status,
                "headers": response_headers.iter().map(|(n, v)| json!([n, v])).collect::<Vec<_>>(),
                "body": response_body,
            }
        });
        parse_capture(&format!("{sequence:04}.json"), &value.to_string()).unwrap()
    }

    fn options() -> Options {
        Options {
            name: "captured-crud".to_owned(),
            description: Some("A client stores an event and reads it back.".to_owned()),
            client: "apple-calendar".to_owned(),
            feature: "crud".to_owned(),
            provenance: "Calendar on macOS 15, staging run r42".to_owned(),
            actor: None,
            login_domain: Some("r42-a.example".to_owned()),
            keep_text: false,
        }
    }

    const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x-1@r42-a.example\r\nDTSTART:20270315T090000Z\r\nSUMMARY:Dentist with Anna\r\nDESCRIPTION:Bring the X-rays\r\nATTENDEE;CN=\"Anna Real\":mailto:anna@r42-a.example\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    fn flow() -> Vec<Exchange> {
        vec![
            capture(
                1,
                "PUT",
                "/dav/calendars/r42-a/olivia/personal/x-1.ics",
                &[
                    ("content-type", "text/calendar; charset=utf-8"),
                    ("if-none-match", "*"),
                    ("authorization", "<redacted>"),
                    ("user-agent", "macOS"),
                ],
                Some(EVENT),
                201,
                &[("etag", "\"abc123\"")],
                None,
            ),
            capture(
                2,
                "GET",
                "/dav/calendars/r42-a/olivia/personal/x-1.ics",
                &[("authorization", "<redacted>")],
                None,
                200,
                &[("etag", "\"abc123\""), ("content-type", "text/calendar; charset=utf-8")],
                Some(EVENT),
            ),
            capture(
                3,
                "PUT",
                "/dav/calendars/r42-a/olivia/personal/x-1.ics",
                &[
                    ("content-type", "text/calendar; charset=utf-8"),
                    ("if-match", "\"abc123\""),
                ],
                Some(EVENT),
                204,
                &[("etag", "\"def456\"")],
                None,
            ),
            capture(
                4,
                "PROPFIND",
                "/dav/calendars/r42-a/olivia/personal/",
                &[("depth", "1"), ("content-type", "application/xml")],
                Some("<propfind xmlns=\"DAV:\"><prop><getetag/></prop></propfind>"),
                207,
                &[("content-type", "application/xml; charset=utf-8")],
                Some(
                    "<multistatus xmlns=\"DAV:\"><response><href>/dav/calendars/r42-a/olivia/personal/x-1.ics</href><propstat><prop><getetag>\"def456\"</getetag></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>",
                ),
            ),
        ]
    }

    #[test]
    fn a_flow_becomes_a_scenario_that_reads_back_and_does_not_mention_the_run() {
        let converted = convert(&flow(), &options()).unwrap();
        let yaml = &converted.yaml;
        assert!(!yaml.contains("r42-a"), "the tenant of the run is a variable:\n{yaml}");
        assert!(
            yaml.contains("{{tenant}}") && yaml.contains("{{login_domain}}"),
            "{yaml}"
        );
        let scenario = &converted.scenario;
        assert_eq!(scenario.origin, crate::flow::Origin::Captured);
        assert_eq!(
            (scenario.client.as_str(), scenario.feature.as_str()),
            ("apple-calendar", "crud")
        );
        assert_eq!(scenario.steps.len(), 4);
        assert!(scenario.provenance.contains("Calendar on macOS 15") && scenario.provenance.contains("4 exchanges"));
        assert_eq!(
            scenario.actors.get("olivia"),
            Some(&ActorRole::Owner),
            "the user of the paths is the owner of the world"
        );
    }

    #[test]
    fn only_the_headers_that_mean_something_to_a_server_are_kept() {
        let converted = convert(&flow(), &options()).unwrap();
        let first = &converted.scenario.steps[0].request;
        assert_eq!(
            first.headers.get("Content-Type").map(String::as_str),
            Some("text/calendar; charset=utf-8")
        );
        assert_eq!(first.headers.get("If-None-Match").map(String::as_str), Some("*"));
        assert!(
            !converted.yaml.contains("redacted") && !converted.yaml.contains("macOS\n"),
            "{}",
            converted.yaml
        );
        assert_eq!(first.headers.len(), 2);
    }

    #[test]
    fn a_value_the_server_made_up_and_a_client_repeats_is_captured_and_templated() {
        let converted = convert(&flow(), &options()).unwrap();
        let steps = &converted.scenario.steps;
        assert_eq!(
            steps[0].capture.get("etag1").and_then(|c| c.header.as_deref()),
            Some("ETag")
        );
        assert_eq!(
            steps[2].request.headers.get("If-Match").map(String::as_str),
            Some("{{etag1}}")
        );
        // The second entity tag is never repeated by a request, so nothing captures it.
        assert!(steps[2].capture.is_empty(), "{:?}", steps[2].capture);
        assert!(
            !converted.yaml.contains("abc123"),
            "the entity tag is a capture:\n{}",
            converted.yaml
        );
    }

    #[test]
    fn free_text_is_replaced_by_neutral_text_unless_it_is_kept() {
        let scrubbed = convert(&flow(), &options()).unwrap();
        assert!(
            !scrubbed.yaml.contains("Dentist")
                && !scrubbed.yaml.contains("X-rays")
                && !scrubbed.yaml.contains("Anna Real"),
            "{}",
            scrubbed.yaml
        );
        assert!(scrubbed.yaml.contains("SUMMARY:Text 1"), "{}", scrubbed.yaml);
        assert!(
            scrubbed.yaml.contains("mailto:anna@{{login_domain}}"),
            "addresses stay: {}",
            scrubbed.yaml
        );
        let kept = convert(
            &flow(),
            &Options {
                keep_text: true,
                ..options()
            },
        )
        .unwrap();
        assert!(kept.yaml.contains("SUMMARY:Dentist with Anna"), "{}", kept.yaml);
    }

    #[test]
    fn answers_are_stated_structurally() {
        let converted = convert(&flow(), &options()).unwrap();
        let steps = &converted.scenario.steps;
        assert_eq!(
            steps[0].expect.status.as_ref().map(ToString::to_string).as_deref(),
            Some("201")
        );
        assert!(steps[0].expect.headers.contains_key("etag"));
        // The calendar data of the read is asserted by its identifying lines, with the free text scrubbed the same way.
        let read = &steps[1].expect;
        assert!(
            read.ical_contains.iter().any(|line| line == "UID:x-1@{{login_domain}}"),
            "{read:?}"
        );
        assert!(
            read.ical_contains.iter().any(|line| line == "SUMMARY:Text 1"),
            "{read:?}"
        );
        // The multistatus is stated by the status of every resource it names.
        let listing = &steps[3].expect;
        assert_eq!(
            listing
                .statuses
                .get("/dav/calendars/{{tenant}}/olivia/personal/x-1.ics"),
            Some(&200)
        );
    }

    /// An event whose long lines are folded the way a client folds them.
    const FOLDED: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x-2@r42-a.example\r\nDTSTART:20270315T090000Z\r\nSUMMARY:A very long summary about the dentist that goes on and on and\r\n  on until it was folded\r\nDESCRIPTION:Bring the X-rays and the long letter from the specialist who\r\n  saw me last year\r\nATTENDEE;CN=\"Anna \r\n Real, Jr.\":mailto:anna@r42-a.example\r\nATTENDEE;CN=Bob;EMAIL=bob@gmail.example:mailto:bob@gmail.example\r\nX-ALT-DESC;FMTTYPE=text/html:<html>secret plans</html>\r\nURL:https://clinic.example/secret\r\nGEO:52.5;13.4\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    /// The same event as a server writes it: the summary is folded in another place.
    const FOLDED_ELSEWHERE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x-2@r42-a.example\r\nDTSTART:20270315T090000Z\r\nSUMMARY:A very long summary about the dentist that goes on and on and on\r\n  until it was folded\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn folded_lines_are_scrubbed_whole_and_come_out_the_same_wherever_they_were_folded() {
        let request = capture(
            1,
            "PUT",
            "/dav/calendars/r42-a/olivia/personal/x-2.ics",
            &[("content-type", "text/calendar")],
            Some(FOLDED),
            201,
            &[],
            None,
        );
        let answer = capture(
            2,
            "GET",
            "/dav/calendars/r42-a/olivia/personal/x-2.ics",
            &[],
            None,
            200,
            &[("content-type", "text/calendar")],
            Some(FOLDED_ELSEWHERE),
        );
        let converted = convert(&[request, answer], &options()).unwrap();
        // Nothing of what somebody wrote is left: not the tail of a folded line, not the name in a folded parameter, not the
        // properties and parameters that only some clients write.
        for leaked in [
            "specialist",
            "dentist",
            "saw me",
            "Anna Real",
            "Jr.",
            "Bob",
            "gmail",
            "secret plans",
            "clinic",
            "52.5",
            "X-rays",
        ] {
            assert!(
                !converted.yaml.contains(leaked),
                "`{leaked}` leaked:\n{}",
                converted.yaml
            );
        }
        // An address outside the login domain is replaced, one inside it stays.
        assert!(
            converted.yaml.contains("mailto:guest1@example.net"),
            "{}",
            converted.yaml
        );
        assert!(
            converted.yaml.contains("mailto:anna@{{login_domain}}"),
            "{}",
            converted.yaml
        );
        // The request and the answer say the same about the summary, though they fold it in different places: the scenario
        // that is converted from them matches what the server returns when it is replayed.
        let sent = converted.scenario.steps[0].request.ical.as_deref().unwrap();
        let summary = sent.lines().find(|line| line.starts_with("SUMMARY:")).unwrap();
        let read = &converted.scenario.steps[1].expect;
        assert!(
            read.ical_contains.iter().any(|line| line == summary),
            "{summary} is not among {:?}",
            read.ical_contains
        );
    }

    #[test]
    fn the_text_of_dav_xml_requests_is_scrubbed_too() {
        let body = "<A:propertyupdate xmlns:A=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><A:set><A:prop><A:displayname>Anna's secret calendar</A:displayname><C:calendar-description>Private notes</C:calendar-description><A:getetag>keep</A:getetag></A:prop></A:set></A:propertyupdate>";
        let exchanges = vec![capture(
            1,
            "PROPPATCH",
            "/dav/calendars/r42-a/olivia/personal/",
            &[("content-type", "application/xml")],
            Some(body),
            207,
            &[],
            None,
        )];
        let converted = convert(&exchanges, &options()).unwrap();
        assert!(
            !converted.yaml.contains("secret calendar") && !converted.yaml.contains("Private notes"),
            "{}",
            converted.yaml
        );
        assert!(
            converted.yaml.contains("<A:displayname>Text 1</A:displayname>")
                && converted
                    .yaml
                    .contains("<C:calendar-description>Text 2</C:calendar-description>"),
            "{}",
            converted.yaml
        );
        assert!(
            converted.yaml.contains("<A:getetag>keep</A:getetag>"),
            "only the elements that hold somebody's text are replaced"
        );
        let kept = convert(
            &exchanges,
            &Options {
                keep_text: true,
                ..options()
            },
        )
        .unwrap();
        assert!(kept.yaml.contains("Private notes"), "{}", kept.yaml);
    }

    #[test]
    fn parameters_are_found_by_name_without_regard_to_case_and_with_respect_for_quotes() {
        let mut scrubber = Scrubber::new(Some("r42-a.example"));
        let line =
            scrubber.line(r#"attendee;cn="Doe; John: the Third";partstat=ACCEPTED:mailto:Doe@Elsewhere.example"#);
        assert!(
            !line.contains("Doe") && !line.contains("Elsewhere"),
            "the name and the address are replaced: {line}"
        );
        assert!(
            line.contains("PARTSTAT") || line.contains("partstat=ACCEPTED"),
            "{line}"
        );
        assert!(line.starts_with("attendee;"), "the name is written as it was: {line}");
        // The same address in another case is the same stranger.
        let again = scrubber.line("ATTENDEE:mailto:doe@elsewhere.example");
        assert_eq!(again, "ATTENDEE:mailto:guest1@example.net");
        // Without a login domain nothing is known about whose addresses these are.
        let mut unknown = Scrubber::new(None);
        assert_eq!(
            unknown.line("ATTENDEE:mailto:doe@elsewhere.example"),
            "ATTENDEE:mailto:doe@elsewhere.example"
        );
    }

    #[test]
    fn the_capture_format_is_the_one_the_server_writes() {
        assert_eq!(CAPTURE_SCHEMA_VERSION, davhaven_server::capture::SCHEMA_VERSION);
    }

    #[test]
    fn sync_tokens_are_captured_from_the_report_and_templated_into_the_next_request() {
        let exchanges = vec![
            capture(
                1,
                "REPORT",
                "/dav/calendars/r42-a/olivia/personal/",
                &[("content-type", "application/xml"), ("depth", "1")],
                Some("<sync-collection xmlns=\"DAV:\"><sync-token/><sync-level>1</sync-level></sync-collection>"),
                207,
                &[("content-type", "application/xml; charset=utf-8")],
                Some("<multistatus xmlns=\"DAV:\"><sync-token>urn:davhaven:sync:c:e:1</sync-token></multistatus>"),
            ),
            capture(
                2,
                "REPORT",
                "/dav/calendars/r42-a/olivia/personal/",
                &[("content-type", "application/xml"), ("depth", "1")],
                Some(
                    "<sync-collection xmlns=\"DAV:\"><sync-token>urn:davhaven:sync:c:e:1</sync-token><sync-level>1</sync-level></sync-collection>",
                ),
                207,
                &[("content-type", "application/xml; charset=utf-8")],
                Some("<multistatus xmlns=\"DAV:\"><sync-token>urn:davhaven:sync:c:e:1</sync-token></multistatus>"),
            ),
        ];
        let converted = convert(&exchanges, &options()).unwrap();
        let first = &converted.scenario.steps[0];
        assert_eq!(
            first.capture.get("sync1").and_then(|c| c.xpath.as_deref()),
            Some("/{DAV:}multistatus/{DAV:}sync-token")
        );
        let second = converted.scenario.steps[1].request.body.as_deref().unwrap();
        assert!(second.contains("<sync-token>{{sync1}}</sync-token>"), "{second}");
    }

    #[test]
    fn a_schedule_tag_and_a_location_that_a_later_request_repeats_are_captured_from_their_headers() {
        let exchanges = vec![
            capture(
                1,
                "PUT",
                "/dav/calendars/r42-a/olivia/personal/x-3.ics",
                &[("content-type", "text/calendar")],
                Some(EVENT),
                201,
                &[
                    ("schedule-tag", "\"st-1\""),
                    ("location", "/dav/calendars/r42-a/olivia/personal/server-3.ics"),
                ],
                None,
            ),
            capture(
                2,
                "DELETE",
                "/dav/calendars/r42-a/olivia/personal/server-3.ics",
                &[("if-schedule-tag-match", "\"st-1\"")],
                None,
                204,
                &[],
                None,
            ),
        ];
        let converted = convert(&exchanges, &options()).unwrap();
        let steps = &converted.scenario.steps;
        assert_eq!(
            steps[0].capture.get("scheduletag1").and_then(|c| c.header.as_deref()),
            Some("Schedule-Tag")
        );
        assert_eq!(
            steps[0].capture.get("location1").and_then(|c| c.header.as_deref()),
            Some("Location")
        );
        assert!(
            steps[0].expect.headers.contains_key("schedule-tag"),
            "{:?}",
            steps[0].expect
        );
        assert_eq!(
            steps[1]
                .request
                .headers
                .get("If-Schedule-Tag-Match")
                .map(String::as_str),
            Some("{{scheduletag1}}")
        );
        assert_eq!(
            steps[1].request.path, "{{location1}}",
            "the path the server chose is the one the answer named"
        );
        assert!(!converted.yaml.contains("st-1"), "{}", converted.yaml);
    }

    #[test]
    fn links_attachments_places_categories_and_the_addresses_of_strangers_are_scrubbed() {
        let mut scrubber = Scrubber::new(Some("r42-a.example"));
        assert_eq!(
            scrubber.line("URL:https://clinic.example/secret"),
            "URL:https://example.net/url-1"
        );
        // An inline attachment is the content of a file: its encoding parameters go with it.
        assert_eq!(
            scrubber.line("ATTACH;ENCODING=BASE64;VALUE=BINARY;FMTTYPE=image/png:iVBORw0KGgo="),
            "ATTACH:https://example.net/attachment-2"
        );
        assert_eq!(
            scrubber.line(
                r#"X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS="Main Street 1";X-TITLE="Dr. Who":geo:52.5,13.4"#
            ),
            r#"X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS="Text 3";X-TITLE="Text 4":geo:0.0,0.0"#
        );
        // The assistant who sends for the organizer is a stranger; the organizer is of the tenant and stays.
        assert_eq!(
            scrubber.line(r#"ORGANIZER;SENT-BY="mailto:assistant@elsewhere.example":mailto:boss@r42-a.example"#),
            r#"ORGANIZER;SENT-BY="mailto:guest1@example.net":mailto:boss@r42-a.example"#
        );
        assert_eq!(
            scrubber.line("ATTENDEE:urn:uuid:5f1e"),
            "ATTENDEE:urn:uuid:5f1e",
            "a value that is no address is nobody's"
        );
        assert_eq!(scrubber.line("CATEGORIES:Health,Private"), "CATEGORIES:Text 5");
        assert_eq!(
            scrubber.line("SUMMARY:Health,Private"),
            "SUMMARY:Text 5",
            "the same text gets the same replacement wherever it is"
        );
        assert_eq!(scrubber.line("NO COLON AT ALL"), "NO COLON AT ALL");
        // Calendar data with plain line breaks keeps them.
        assert_eq!(
            scrubber.ical("BEGIN:VEVENT\nDESCRIPTION:Call the bank\nEND:VEVENT"),
            "BEGIN:VEVENT\nDESCRIPTION:Text 6\nEND:VEVENT"
        );
    }

    #[test]
    fn the_captured_user_plays_the_role_of_the_fixture_world_that_has_the_name_unless_one_is_given() {
        let read = |path: &str| capture(1, "GET", path, &[], None, 200, &[], None);
        let exchanges = vec![
            read("/dav/calendars/r42-a/rita/projects/"),
            read("/dav/calendars/r42-a/rita/inbox/"),
            read("/dav/calendars/r42-a/olivia/projects/"),
        ];
        let converted = convert(&exchanges, &options()).unwrap();
        assert_eq!(
            converted.scenario.actors.get("rita"),
            Some(&ActorRole::ShareeRead),
            "most paths are rita's"
        );
        assert_eq!(converted.scenario.actors.len(), 1);
        let given = convert(
            &exchanges,
            &Options {
                actor: Some(ActorRole::ShareeReadWrite),
                ..options()
            },
        )
        .unwrap();
        assert_eq!(given.scenario.actors.get("rita"), Some(&ActorRole::ShareeReadWrite));
    }

    #[test]
    fn a_multistatus_states_each_resource_once_with_the_status_that_decides_it() {
        let body = "<multistatus xmlns=\"DAV:\">\
            <response><href>/dav/calendars/r42-a/olivia/personal/a.ics</href><propstat><prop><getetag/></prop><status>HTTP/1.1 200 OK</status></propstat></response>\
            <response><href>/dav/calendars/r42-a/olivia/personal/a.ics</href><status>HTTP/1.1 404 Not Found</status></response>\
            <response><href>/dav/calendars/r42-a/olivia/personal/b.ics</href><propstat><prop><getetag/></prop><status>HTTP/1.1 200 OK</status></propstat><propstat><prop><displayname/></prop><status>HTTP/1.1 403 Forbidden</status></propstat></response>\
            <response><href>/dav/calendars/r42-a/olivia/personal/c.ics</href><status>HTTP/1.1 404 Not Found</status></response>\
            </multistatus>";
        let exchanges = vec![capture(
            1,
            "PROPFIND",
            "/dav/calendars/r42-a/olivia/personal/",
            &[("depth", "1")],
            None,
            207,
            &[("content-type", "application/xml")],
            Some(body),
        )];
        let converted = convert(&exchanges, &options()).unwrap();
        let statuses = &converted.scenario.steps[0].expect.statuses;
        let at = |name: &str| {
            statuses
                .get(&format!("/dav/calendars/{{{{tenant}}}}/olivia/personal/{name}"))
                .copied()
        };
        assert_eq!(
            at("a.ics"),
            Some(200),
            "the first answer for a resource is the one stated"
        );
        assert_eq!(
            at("b.ics"),
            Some(403),
            "a property that is refused decides the resource"
        );
        assert_eq!(at("c.ics"), Some(404), "the status of the response itself");
        assert_eq!(statuses.len(), 3, "{statuses:?}");
    }

    #[test]
    fn exchanges_of_several_tenants_or_none_at_all_are_refused() {
        assert_eq!(convert(&[], &options()).unwrap_err(), ConvertError::Empty);
        let mut other = flow();
        if let Some(exchange) = other.get_mut(1) {
            exchange.tenant = "other".to_owned();
        }
        assert_eq!(
            convert(&other, &options()).unwrap_err(),
            ConvertError::SeveralTenants("other, r42-a".to_owned())
        );
    }

    #[test]
    fn capture_files_are_read_strictly_and_bodies_that_are_not_text_are_refused() {
        assert!(matches!(
            parse_capture("a.json", "{}"),
            Err(ConvertError::Format { .. })
        ));
        let wrong_version = json!({"schema_version": 2, "captured_at": "x", "tenant": "t",
            "request": {"method": "GET", "path": "/", "query": null, "headers": [], "body": null},
            "response": {"status": 200, "headers": [], "body": null}});
        assert!(matches!(
            parse_capture("a.json", &wrong_version.to_string()),
            Err(ConvertError::Format { .. })
        ));
        let binary = json!({"schema_version": 1, "captured_at": "x", "tenant": "t",
            "request": {"method": "PUT", "path": "/", "query": null, "headers": [], "body_base64": "/w=="},
            "response": {"status": 200, "headers": [], "body": null}});
        assert!(matches!(
            parse_capture("a.json", &binary.to_string()),
            Err(ConvertError::Binary { .. })
        ));
        let garbled = json!({"schema_version": 1, "captured_at": "x", "tenant": "t",
            "request": {"method": "PUT", "path": "/", "query": null, "headers": [], "body": null},
            "response": {"status": 200, "headers": [], "body_base64": "not base64!"}});
        match parse_capture("b.json", &garbled.to_string()) {
            Err(ConvertError::Format { file, reason }) => {
                assert_eq!(file, "b.json");
                assert!(reason.starts_with("a base64 body cannot be decoded"), "{reason}");
            }
            other => panic!("a body that is not base64 is a format error: {other:?}"),
        }
        let encoded = json!({"schema_version": 1, "captured_at": "x", "tenant": "t",
            "request": {"method": "PUT", "path": "/p", "query": "a=b", "headers": [["Depth", "1"]], "body_base64": "aGk="},
            "response": {"status": 200, "headers": [], "body": null}});
        let exchange = parse_capture("a.json", &encoded.to_string()).unwrap();
        assert_eq!(exchange.request_body.as_deref(), Some("hi"));
        assert_eq!(exchange.target, "/p?a=b");
        assert_eq!(exchange.request_header("DEPTH"), Some("1"));
    }

    #[test]
    fn texts_survive_the_yaml_they_are_written_into() {
        for text in [
            "plain",
            "with \"quotes\" and \\ backslash",
            "two\nlines\n",
            "two\nlines without a final break",
            "  leading space\nsecond",
            "tab\there\nsecond",
            "{{braces}}: and colons # and hashes",
            "carriage\r\nreturns\r\n",
            "trailing blank\n\n",
            "unicode ä ü 日本",
        ] {
            let mut yaml = String::from(
                "schema_version: 1\nname: t\nclient: c\nfeature: f\norigin: captured\nprovenance: p\nactors:\n  a: owner\nsteps:\n  - name: s\n    as: a\n    request:\n      method: PUT\n      path: /x\n",
            );
            field(&mut yaml, 6, "body", text);
            let scenario = Scenario::from_yaml(&yaml).unwrap_or_else(|error| panic!("{text:?}: {error}\n{yaml}"));
            assert_eq!(scenario.steps[0].request.body.as_deref(), Some(text), "{yaml}");
        }
    }

    #[test]
    fn a_directory_of_captures_is_read_in_the_order_of_its_files() {
        let dir = tempfile::tempdir().unwrap();
        for (name, sequence) in [
            ("2027-03-01T10:15:02.000Z-2-GET-200.json", 2),
            ("2027-03-01T10:15:01.000Z-1-PUT-201.json", 1),
        ] {
            let value = json!({"schema_version": 1, "captured_at": format!("t{sequence}"), "tenant": "t",
                "request": {"method": "GET", "path": "/dav/calendars/t/olivia/personal/", "query": null, "headers": [], "body": null},
                "response": {"status": 200, "headers": [], "body": null}});
            std::fs::write(dir.path().join(name), value.to_string()).unwrap();
        }
        std::fs::write(dir.path().join("notes.txt"), "not a capture").unwrap();
        let read = read_captures(dir.path()).unwrap();
        assert_eq!(
            read.iter()
                .map(|exchange| exchange.captured_at.as_str())
                .collect::<Vec<_>>(),
            ["t1", "t2"]
        );
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(read_captures(empty.path()).unwrap_err(), ConvertError::Empty);
        assert!(matches!(
            read_captures(&empty.path().join("missing")),
            Err(ConvertError::Io { .. })
        ));
    }
}
