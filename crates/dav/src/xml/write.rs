//! The hand-written XML writer, the escaping rules and the `multistatus` builder.
//!
//! Responses use four fixed prefixes, declared once on the root element of a document: `D` (`DAV:`), `C`
//! (CalDAV), `CS` (CalendarServer) and `ICAL` (Apple's calendar extensions). The other namespaces a request names
//! get a generated prefix (`n0`, `n1`, ...), declared once on the root as well ([`Prefixes`]), so that a request
//! that lists a thousand properties of a long namespace does not make every `response` of a large listing repeat
//! the namespace a thousand times. A name in a namespace without a prefix (a dead property that the request did not
//! name) declares its namespace itself as the default namespace of the element.
//!
//! Text is escaped so that it survives an XML parser unchanged: `&`, `<` and `>`, and the carriage return as
//! `&#13;`, because an XML parser folds a literal `CR LF` into `LF` and iCalendar text is `CRLF` terminated.
//! Characters XML 1.0 cannot represent are replaced by U+FFFD instead of producing a document no parser accepts.
//! A local name that is not an XML name is never written as it is: the writer is the last line of defence against
//! markup in a response, whatever reached it.

use core::fmt::Write as _;
use std::collections::HashMap;
use std::sync::Arc;

use davhaven_app::services::{NS_APPLE_ICAL, NS_CALDAV, NS_CALENDARSERVER, NS_DAV};

use super::{Element, NS_XML, Node, is_ncname, is_xml_char};
use crate::errors::PreconditionElement;

/// What the writer puts where a local name is not an XML name.
const INVALID_NAME: &str = "invalid-name";

/// The namespaces with a fixed prefix, in the order [`XmlWriter::root`] declares them: the one source of truth for the
/// prefixes a document may use and the prefixes it declares.
const FIXED_PREFIXES: [(&str, &str); 4] = [
    ("D", NS_DAV),
    ("C", NS_CALDAV),
    ("CS", NS_CALENDARSERVER),
    ("ICAL", NS_APPLE_ICAL),
];

/// The prefix the response namespaces are written with; `None` for namespaces without a fixed one.
pub fn prefix_of(namespace: &str) -> Option<&'static str> {
    FIXED_PREFIXES
        .iter()
        .find(|(_, fixed)| *fixed == namespace)
        .map(|(prefix, _)| *prefix)
}

/// The generated prefixes of the namespaces of one request: the namespace at index `i` is written `n{i}`.
#[derive(Debug, Clone, Default)]
pub struct Prefixes {
    table: Arc<PrefixTable>,
}

#[derive(Debug, Default)]
struct PrefixTable {
    index: HashMap<String, usize>,
    order: Vec<String>,
}

impl Prefixes {
    /// The prefixes for `namespaces`: every namespace that has no fixed prefix, once, in order of appearance, at
    /// most `limit` of them (the others are written with a declaration of their own).
    pub fn of<'a>(namespaces: impl IntoIterator<Item = &'a str>, limit: usize) -> Self {
        let mut table = PrefixTable::default();
        for namespace in namespaces {
            if table.order.len() >= limit {
                break;
            }
            if prefix_of(namespace).is_some() || namespace.is_empty() || table.index.contains_key(namespace) {
                continue;
            }
            table.index.insert(namespace.to_owned(), table.order.len());
            table.order.push(namespace.to_owned());
        }
        Self { table: Arc::new(table) }
    }

    /// The number of namespaces with a generated prefix.
    pub fn len(&self) -> usize {
        self.table.order.len()
    }

    /// Whether no namespace has a generated prefix.
    pub fn is_empty(&self) -> bool {
        self.table.order.is_empty()
    }

    fn index_of(&self, namespace: &str) -> Option<usize> {
        self.table.index.get(namespace).copied()
    }

    /// The attributes that declare the prefixes, each with a leading space.
    fn declarations(&self) -> String {
        let mut out = String::new();
        for (index, namespace) in self.table.order.iter().enumerate() {
            let _ = write!(out, " xmlns:n{index}=\"");
            push_escaped(&mut out, namespace, true);
            out.push('"');
        }
        out
    }
}

/// Appends `text` escaped for element content (`attribute` false) or for a double-quoted attribute value.
fn push_escaped(out: &mut String, text: &str, attribute: bool) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            '"' if attribute => out.push_str("&quot;"),
            '\n' if attribute => out.push_str("&#10;"),
            '\t' if attribute => out.push_str("&#9;"),
            c if is_xml_char(c) => out.push(c),
            _ => out.push('\u{fffd}'),
        }
    }
}

/// `text` escaped for element content.
pub fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    push_escaped(&mut out, text, false);
    out
}

/// The local name as it may be written.
fn safe_local(local: &str) -> &str {
    if is_ncname(local) { local } else { INVALID_NAME }
}

/// Builds an XML document as text.
#[derive(Debug, Default, Clone)]
pub struct XmlWriter {
    out: String,
    prefixes: Prefixes,
}

impl XmlWriter {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty writer that writes the namespaces of `prefixes` with their generated prefix.
    pub fn with_prefixes(prefixes: &Prefixes) -> Self {
        Self {
            out: String::new(),
            prefixes: prefixes.clone(),
        }
    }

    /// Writes the XML declaration.
    pub fn declaration(&mut self) -> &mut Self {
        self.out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        self
    }

    /// Writes a start tag (`<D:name>`), with the declaration of its namespace when it has no prefix.
    pub fn start(&mut self, namespace: &str, local: &str) -> &mut Self {
        self.tag(namespace, local, false)
    }

    /// Writes an end tag.
    pub fn end(&mut self, namespace: &str, local: &str) -> &mut Self {
        self.out.push_str("</");
        self.push_prefix(namespace);
        self.out.push_str(safe_local(local));
        self.out.push('>');
        self
    }

    /// Writes an empty element (`<D:name/>`).
    pub fn empty(&mut self, namespace: &str, local: &str) -> &mut Self {
        self.tag(namespace, local, true)
    }

    /// Writes an element that holds only text.
    pub fn text_element(&mut self, namespace: &str, local: &str, text: &str) -> &mut Self {
        self.start(namespace, local);
        self.text(text);
        self.end(namespace, local)
    }

    /// Writes escaped character data.
    pub fn text(&mut self, text: &str) -> &mut Self {
        push_escaped(&mut self.out, text, false);
        self
    }

    /// Writes XML that is already well-formed (the content of a property, a rendered fragment).
    pub fn raw(&mut self, xml: &str) -> &mut Self {
        self.out.push_str(xml);
        self
    }

    /// The number of bytes written so far.
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// The finished document.
    pub fn into_string(self) -> String {
        self.out
    }

    /// The prefix of a namespace with its colon, or nothing for a namespace that declares itself.
    fn push_prefix(&mut self, namespace: &str) {
        if let Some(prefix) = prefix_of(namespace) {
            self.out.push_str(prefix);
            self.out.push(':');
        } else if let Some(index) = self.prefixes.index_of(namespace) {
            let _ = write!(self.out, "n{index}:");
        }
    }

    fn tag(&mut self, namespace: &str, local: &str, empty: bool) -> &mut Self {
        self.open(namespace, local, "", empty)
    }

    /// Writes a start tag with `attributes` (each with a leading space) after the declaration of its namespace.
    fn open(&mut self, namespace: &str, local: &str, attributes: &str, empty: bool) -> &mut Self {
        self.out.push('<');
        self.push_prefix(namespace);
        self.out.push_str(safe_local(local));
        if prefix_of(namespace).is_none() && self.prefixes.index_of(namespace).is_none() {
            self.out.push_str(" xmlns=\"");
            push_escaped(&mut self.out, namespace, true);
            self.out.push('"');
        }
        self.out.push_str(attributes);
        self.out.push_str(if empty { "/>" } else { ">" });
        self
    }

    /// Writes the start tag of the root element of a document: every fixed prefix (`D`, `C`, `CS` and `ICAL`) is
    /// declared on it, so that whatever element the document writes below is namespace-well-formed, followed by
    /// `declarations` (attributes with a leading space, such as the generated prefixes of a request). A root in a
    /// namespace without a fixed prefix declares its own namespace as the default one.
    pub fn root(&mut self, namespace: &str, local: &str, declarations: &str) -> &mut Self {
        let mut attributes = String::new();
        for (prefix, fixed) in FIXED_PREFIXES {
            let _ = write!(attributes, " xmlns:{prefix}=\"{fixed}\"");
        }
        attributes.push_str(declarations);
        self.open(namespace, local, &attributes, false)
    }
}

/// The inner XML of a parsed element (its text and children), self-contained: every element declares its own
/// namespace, so the result can be stored and written back inside any other element unchanged. This is how dead
/// properties are kept.
pub fn serialize_content(element: &Element) -> String {
    serialize_content_within(element, usize::MAX).unwrap_or_default()
}

/// Like [`serialize_content`], but gives up as soon as the result would be longer than `limit` bytes, so that a
/// value that is refused for its size is not written out completely first.
pub fn serialize_content_within(element: &Element, limit: usize) -> Option<String> {
    let mut out = String::new();
    for node in &element.children {
        if !write_node(&mut out, node, limit) {
            return None;
        }
    }
    Some(out)
}

fn write_node(out: &mut String, node: &Node, limit: usize) -> bool {
    match node {
        Node::Text(text) => push_escaped(out, text, false),
        Node::Element(element) => {
            if !write_element(out, element, limit) {
                return false;
            }
        }
    }
    out.len() <= limit
}

fn write_element(out: &mut String, element: &Element, limit: usize) -> bool {
    out.push('<');
    out.push_str(&element.local);
    out.push_str(" xmlns=\"");
    push_escaped(out, &element.namespace, true);
    out.push('"');
    // Attributes in a namespace need a prefix, declared on this element: `n0`, `n1`, ...
    let mut declared: Vec<&str> = Vec::new();
    for attribute in &element.attributes {
        let namespace = attribute.namespace.as_str();
        if !namespace.is_empty() && namespace != NS_XML && !declared.contains(&namespace) {
            declared.push(namespace);
            out.push_str(" xmlns:n");
            out.push_str(&declared.len().saturating_sub(1).to_string());
            out.push_str("=\"");
            push_escaped(out, namespace, true);
            out.push('"');
        }
    }
    for attribute in &element.attributes {
        out.push(' ');
        let namespace = attribute.namespace.as_str();
        if namespace == NS_XML {
            out.push_str("xml:");
        } else if let Some(index) = declared.iter().position(|candidate| *candidate == namespace) {
            out.push('n');
            out.push_str(&index.to_string());
            out.push(':');
        }
        out.push_str(&attribute.local);
        out.push_str("=\"");
        push_escaped(out, &attribute.value, true);
        out.push('"');
    }
    if out.len() > limit {
        return false;
    }
    if element.children.is_empty() {
        out.push_str("/>");
        return true;
    }
    out.push('>');
    for child in &element.children {
        if !write_node(out, child, limit) {
            return false;
        }
    }
    out.push_str("</");
    out.push_str(&element.local);
    out.push('>');
    out.len() <= limit
}

/// The status line of a `D:status` element: `HTTP/1.1 404 Not Found`.
pub fn status_line(status: u16) -> String {
    let reason = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or("Unknown");
    format!("HTTP/1.1 {status} {reason}")
}

/// One `D:propstat`: the properties that share a status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Propstat {
    /// The HTTP status of the properties.
    pub status: u16,
    /// The rendered `D:prop` content: one element per property.
    pub props: String,
    /// The precondition element to report next to the status (`cannot-modify-protected-property`,
    /// `valid-calendar-data`). Only [`PreconditionElement`]s are accepted, which `crate::errors` makes from the
    /// catalog or for a `DAV:` element: the namespace of an element is not decided here.
    pub error: Option<PreconditionElement>,
}

impl Propstat {
    /// The properties that were found (200).
    pub const fn found(props: String) -> Self {
        Self {
            status: 200,
            props,
            error: None,
        }
    }
}

fn write_propstat(w: &mut XmlWriter, propstat: &Propstat) {
    w.start(NS_DAV, "propstat");
    w.start(NS_DAV, "prop");
    w.raw(&propstat.props);
    w.end(NS_DAV, "prop");
    w.text_element(NS_DAV, "status", &status_line(propstat.status));
    if let Some(error) = &propstat.error {
        w.start(NS_DAV, "error");
        w.raw(error.as_str());
        w.end(NS_DAV, "error");
    }
    w.end(NS_DAV, "propstat");
}

/// One `D:response` with property statuses, as XML text (also used for the expanded properties of
/// `expand-property`).
pub fn response_element(href: &str, propstats: &[Propstat]) -> String {
    let mut w = XmlWriter::new();
    w.start(NS_DAV, "response");
    w.text_element(NS_DAV, "href", href);
    for propstat in propstats {
        write_propstat(&mut w, propstat);
    }
    w.end(NS_DAV, "response");
    w.into_string()
}

/// A `D:multistatus` document under construction (also the shape of `CALDAV:mkcalendar-response` and
/// `DAV:mkcol-response`, which differ in the root element only).
#[derive(Debug, Clone)]
pub struct Multistatus {
    writer: XmlWriter,
    root: (&'static str, &'static str),
}

impl Default for Multistatus {
    fn default() -> Self {
        Self::new()
    }
}

impl Multistatus {
    /// Starts the document: declaration and root element with the four response prefixes.
    pub fn new() -> Self {
        Self::with_prefixes(&Prefixes::default())
    }

    /// Starts the document with the generated prefixes declared on the root element as well.
    pub fn with_prefixes(prefixes: &Prefixes) -> Self {
        Self::rooted(NS_DAV, "multistatus", prefixes)
    }

    /// Starts a document with another root element (`CALDAV:mkcalendar-response`, `DAV:mkcol-response`).
    pub fn rooted(namespace: &'static str, local: &'static str, prefixes: &Prefixes) -> Self {
        let mut writer = XmlWriter::with_prefixes(prefixes);
        writer.declaration();
        writer.root(namespace, local, &prefixes.declarations());
        Self {
            writer,
            root: (namespace, local),
        }
    }

    /// The number of bytes written so far: what a handler compares with `max_response_bytes`.
    pub fn len(&self) -> usize {
        self.writer.len()
    }

    /// Whether nothing has been written (never true: the root element is written at once).
    pub fn is_empty(&self) -> bool {
        self.writer.is_empty()
    }

    /// Adds a response with property statuses.
    pub fn response(&mut self, href: &str, propstats: &[Propstat]) -> &mut Self {
        self.writer.raw(&response_element(href, propstats));
        self
    }

    /// Adds one `propstat` directly below the root element (`mkcalendar-response` and `mkcol-response`).
    pub fn propstat(&mut self, propstat: &Propstat) -> &mut Self {
        write_propstat(&mut self.writer, propstat);
        self
    }

    /// Adds a response that has one status for the whole resource (a deleted member, a missing href), with an
    /// optional `DAV:error` element naming a precondition.
    pub fn status_response(&mut self, href: &str, status: u16, error: Option<&'static str>) -> &mut Self {
        self.status_response_with(href, status, error.map(PreconditionElement::dav).as_ref())
    }

    /// Adds a response that has one status for the whole resource and a `DAV:error` with the precondition element
    /// `error`. Only [`PreconditionElement`]s are accepted: markup that this crate did not write and escape cannot
    /// be put into a `multistatus` through this method.
    pub fn status_response_with(&mut self, href: &str, status: u16, error: Option<&PreconditionElement>) -> &mut Self {
        let w = &mut self.writer;
        w.start(NS_DAV, "response");
        w.text_element(NS_DAV, "href", href);
        w.text_element(NS_DAV, "status", &status_line(status));
        if let Some(error) = error {
            w.start(NS_DAV, "error");
            w.raw(error.as_str());
            w.end(NS_DAV, "error");
        }
        w.end(NS_DAV, "response");
        self
    }

    /// Adds the `D:sync-token` that ends a `sync-collection` answer.
    pub fn sync_token(&mut self, token: &str) -> &mut Self {
        self.writer.text_element(NS_DAV, "sync-token", token);
        self
    }

    /// Closes the root element and returns the document.
    pub fn finish(mut self) -> String {
        let (namespace, local) = self.root;
        self.writer.end(namespace, local);
        self.writer.raw("\n");
        self.writer.into_string()
    }
}

#[cfg(test)]
mod tests {
    use davhaven_domain::DavLimits;
    use davhaven_http::problem::ProblemCode;

    use super::*;
    use crate::errors::catalog_element;
    use crate::xml::parse;

    /// `text` escaped for a double-quoted attribute value.
    fn escape_attribute(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        push_escaped(&mut out, text, true);
        out
    }

    fn reparse(xml: &str) -> Element {
        parse(xml.as_bytes(), &DavLimits::default()).unwrap()
    }

    #[test]
    fn text_is_escaped_so_that_it_survives_a_parser() {
        let ics = "BEGIN:VCALENDAR\r\nSUMMARY:R&D <team> \"x\" 'y'\r\nEND:VCALENDAR\r\n";
        let xml = format!("<a>{}</a>", escape_text(ics));
        assert!(
            xml.contains("&#13;"),
            "the carriage return is written as a reference: {xml}"
        );
        assert!(!xml.contains('\r'));
        assert_eq!(reparse(&xml).text(), ics);
    }

    #[test]
    fn attribute_values_are_escaped_completely() {
        let value = "a\"b&c<d>\ne\tf\r";
        let xml = format!("<a b=\"{}\"/>", escape_attribute(value));
        assert_eq!(reparse(&xml).attribute("b"), Some(value), "{xml}");
    }

    proptest::proptest! {
        /// Whatever text an attribute value carries, it reads back as written (with U+FFFD for what XML cannot hold).
        #[test]
        fn any_attribute_value_the_server_writes_reads_back_as_written(text in proptest::prelude::any::<String>()) {
            let expected: String = text
                .chars()
                .map(|c| if is_xml_char(c) { c } else { '\u{fffd}' })
                .collect();
            let attribute = format!("<a b=\"{}\"/>", escape_attribute(&text));
            let parsed = parse(attribute.as_bytes(), &DavLimits::default());
            proptest::prop_assert!(parsed.is_ok(), "{attribute:?}: {parsed:?}");
            proptest::prop_assert_eq!(parsed.unwrap().attribute("b").map(str::to_owned), Some(expected));
        }
    }

    #[test]
    fn characters_xml_cannot_hold_become_replacement_characters() {
        assert_eq!(escape_text("a\u{0}b\u{8}c\u{fffe}d"), "a\u{fffd}b\u{fffd}c\u{fffd}d");
        assert_eq!(escape_text("tab\tnl\n"), "tab\tnl\n");
    }

    #[test]
    fn known_namespaces_use_their_prefix_and_others_declare_themselves() {
        let mut w = XmlWriter::new();
        w.start(NS_DAV, "prop")
            .empty(NS_CALDAV, "calendar-data")
            .start("urn:example:x", "note")
            .text("a<b")
            .end("urn:example:x", "note")
            .empty(NS_CALENDARSERVER, "getctag")
            .end(NS_DAV, "prop");
        assert_eq!(
            w.into_string(),
            "<D:prop><C:calendar-data/><note xmlns=\"urn:example:x\">a&lt;b</note><CS:getctag/></D:prop>"
        );
        assert_eq!(prefix_of(NS_APPLE_ICAL), Some("ICAL"));
        assert_eq!(prefix_of("urn:other"), None);
    }

    #[test]
    fn generated_prefixes_are_declared_once_and_used_everywhere() {
        let prefixes = Prefixes::of(
            [
                NS_DAV,
                "urn:example:x",
                "urn:example:y",
                "urn:example:x",
                "",
                "urn:example:z",
            ],
            2,
        );
        assert_eq!(
            prefixes.len(),
            2,
            "the fixed prefixes, duplicates and the limit are skipped"
        );
        assert!(!prefixes.is_empty());
        let mut w = XmlWriter::with_prefixes(&prefixes);
        w.start("urn:example:x", "a")
            .empty("urn:example:y", "b")
            .empty("urn:example:z", "c")
            .end("urn:example:x", "a");
        assert_eq!(
            w.into_string(),
            "<n0:a><n1:b/><c xmlns=\"urn:example:z\"/></n0:a>",
            "a namespace over the limit declares itself"
        );
        let mut document = Multistatus::with_prefixes(&prefixes);
        document.status_response("/x", 404, None);
        let xml = document.finish();
        assert!(
            xml.contains(" xmlns:n0=\"urn:example:x\" xmlns:n1=\"urn:example:y\""),
            "{xml}"
        );
        let root = reparse(&xml);
        assert!(root.is(NS_DAV, "multistatus"));
    }

    #[test]
    fn an_answer_that_names_many_namespaces_declares_them_on_its_root_and_reads_back_with_room_for_them() {
        // A request may name 64 namespaces, each declared on the element that uses it; the answer declares them all once on
        // its root, and a reader that counts every declaration as an attribute of that element needs room for them (the fuzz
        // target of the request reader found a request with more than 32 and the answer was refused with the default limits).
        let namespaces: Vec<String> = (0..64).map(|n| format!("urn:example:{n}")).collect();
        let prefixes = Prefixes::of(namespaces.iter().map(String::as_str), 64);
        assert_eq!(prefixes.len(), 64);
        let mut properties = XmlWriter::with_prefixes(&prefixes);
        for namespace in &namespaces {
            properties.empty(namespace, "p");
        }
        let mut document = Multistatus::with_prefixes(&prefixes);
        document.response("/x", &[Propstat::found(properties.into_string())]);
        let xml = document.finish();
        assert_eq!(
            xml.matches(" xmlns:n").count(),
            64,
            "one declaration for each, on the root: {xml}"
        );
        let roomy = DavLimits {
            max_xml_namespaces: 128,
            max_xml_attributes: 128,
            ..DavLimits::default()
        };
        let root = parse(xml.as_bytes(), &roomy).unwrap();
        let written = root
            .child(NS_DAV, "response")
            .and_then(|response| response.child(NS_DAV, "propstat"))
            .and_then(|propstat| propstat.child(NS_DAV, "prop"))
            .map(|prop| prop.elements().count());
        assert_eq!(written, Some(64));
    }

    #[test]
    fn a_name_that_is_not_an_xml_name_never_reaches_the_output() {
        for hostile in ["x><D:href>/evil</D:href><y", "a b", "a\"b", "", "1a", "a:b", "a/>"] {
            let mut w = XmlWriter::new();
            w.start(NS_DAV, hostile).text("v").end(NS_DAV, hostile);
            w.empty("urn:example:x", hostile);
            let xml = w.into_string();
            assert!(
                !xml.contains("evil") && !xml.contains("a b") && !xml.contains("a\"b"),
                "{xml}"
            );
            let wrapped = format!("<holder xmlns:D=\"DAV:\">{xml}</holder>");
            let root = reparse(&wrapped);
            assert_eq!(root.elements().count(), 2, "{xml}");
            assert!(root.elements().all(|element| element.local == INVALID_NAME), "{xml}");
        }
    }

    #[test]
    fn dead_property_content_round_trips_through_serialization() {
        let source = r#"<x:prop xmlns:x="urn:a" xmlns:y="urn:b">
            text &amp; more <y:child y:attr="1" xml:lang="de" plain="2"><x:deep/></y:child><![CDATA[<raw>]]>
        </x:prop>"#;
        let original = reparse(source);
        let stored = serialize_content(&original);
        let wrapped = format!("<holder xmlns=\"urn:h\">{stored}</holder>");
        let again = reparse(&wrapped);
        assert_eq!(again.children, original.children, "stored: {stored}");
        // The stored form is self-contained: no element depends on a declaration of an ancestor.
        assert!(stored.contains("<child xmlns=\"urn:b\""), "{stored}");
        assert!(stored.contains("xml:lang=\"de\""), "{stored}");
    }

    #[test]
    fn serialization_gives_up_when_the_value_is_too_long() {
        let element = reparse(&format!("<a>{}</a>", "x".repeat(100)));
        assert_eq!(
            serialize_content_within(&element, 100).as_deref(),
            Some("x".repeat(100).as_str())
        );
        assert_eq!(serialize_content_within(&element, 99), None);
        let nested = reparse(&format!("<a>{}</a>", "<b xmlns=\"urn:long-namespace\"/>".repeat(50)));
        assert_eq!(serialize_content_within(&nested, 500), None, "the declarations count");
        assert!(serialize_content_within(&nested, usize::MAX).is_some());
    }

    #[test]
    fn empty_content_stays_empty() {
        assert_eq!(serialize_content(&reparse("<a/>")), "");
        assert_eq!(serialize_content(&reparse("<a></a>")), "");
    }

    #[test]
    fn a_multistatus_has_the_prefixes_and_the_statuses() {
        let mut multistatus = Multistatus::new();
        multistatus.response(
            "/dav/calendars/acme/anna/a&b.ics",
            &[
                Propstat::found("<D:getetag>\"x\"</D:getetag>".to_owned()),
                Propstat {
                    status: 404,
                    props: "<C:calendar-data/>".to_owned(),
                    error: None,
                },
                Propstat {
                    status: 403,
                    props: "<D:resourcetype/>".to_owned(),
                    error: Some(PreconditionElement::dav("cannot-modify-protected-property")),
                },
            ],
        );
        multistatus.status_response("/gone.ics", 404, None);
        multistatus.status_response(
            "/dav/calendars/acme/anna/work/",
            507,
            Some("number-of-matches-within-limits"),
        );
        multistatus.sync_token("urn:davhaven:sync:x");
        assert!(!multistatus.is_empty() && multistatus.len() >= 100);
        let xml = multistatus.finish();
        let root = reparse(&xml);
        assert!(root.is(NS_DAV, "multistatus"));
        let responses: Vec<_> = root.children_named(NS_DAV, "response").collect();
        assert_eq!(responses.len(), 3);
        assert_eq!(
            responses[0].child(NS_DAV, "href").unwrap().text(),
            "/dav/calendars/acme/anna/a&b.ics"
        );
        let statuses: Vec<String> = responses[0]
            .children_named(NS_DAV, "propstat")
            .map(|propstat| propstat.child(NS_DAV, "status").unwrap().text())
            .collect();
        assert_eq!(
            statuses,
            ["HTTP/1.1 200 OK", "HTTP/1.1 404 Not Found", "HTTP/1.1 403 Forbidden"]
        );
        let forbidden = responses[0].children_named(NS_DAV, "propstat").nth(2).unwrap();
        assert!(
            forbidden
                .child(NS_DAV, "error")
                .unwrap()
                .child(NS_DAV, "cannot-modify-protected-property")
                .is_some()
        );
        assert_eq!(
            responses[2].child(NS_DAV, "status").unwrap().text(),
            "HTTP/1.1 507 Insufficient Storage"
        );
        assert_eq!(root.child(NS_DAV, "sync-token").unwrap().text(), "urn:davhaven:sync:x");
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus"));
    }

    #[test]
    fn the_precondition_of_a_property_may_be_a_caldav_element() {
        let mut multistatus = Multistatus::new();
        multistatus.response(
            "/dav/calendars/acme/anna/work/",
            &[
                Propstat {
                    status: 409,
                    props: "<C:calendar-timezone/>".to_owned(),
                    error: catalog_element(ProblemCode::InvalidCalendarData, None),
                },
                Propstat {
                    status: 403,
                    props: "<D:getetag/>".to_owned(),
                    error: catalog_element(ProblemCode::ProtectedProperty, None),
                },
            ],
        );
        let xml = multistatus.finish();
        let root = reparse(&xml);
        let response = root.child(NS_DAV, "response").unwrap();
        let errors: Vec<(String, String)> = response
            .children_named(NS_DAV, "propstat")
            .map(|propstat| {
                let element = propstat
                    .child(NS_DAV, "error")
                    .unwrap()
                    .elements()
                    .next()
                    .unwrap()
                    .clone();
                (element.namespace.to_string(), element.local.clone())
            })
            .collect();
        assert_eq!(
            errors,
            [
                (NS_CALDAV.to_owned(), "valid-calendar-data".to_owned()),
                (NS_DAV.to_owned(), "cannot-modify-protected-property".to_owned()),
            ],
            "{xml}"
        );
    }

    #[test]
    fn the_failure_of_a_creation_has_its_own_root_and_propstats_below_it() {
        let mut document = Multistatus::rooted(NS_CALDAV, "mkcalendar-response", &Prefixes::default());
        document.propstat(&Propstat {
            status: 403,
            props: "<D:displayname/>".to_owned(),
            error: Some(PreconditionElement::dav("cannot-modify-protected-property")),
        });
        let xml = document.finish();
        let root = reparse(&xml);
        assert!(root.is(NS_CALDAV, "mkcalendar-response"), "{xml}");
        let propstat = root.child(NS_DAV, "propstat").expect("a propstat below the root");
        assert_eq!(
            propstat.child(NS_DAV, "status").unwrap().text(),
            "HTTP/1.1 403 Forbidden"
        );
        assert!(xml.trim_end().ends_with("</C:mkcalendar-response>"), "{xml}");
    }

    #[test]
    fn a_root_in_a_namespace_without_a_fixed_prefix_declares_its_own_namespace() {
        let mut writer = XmlWriter::new();
        writer.declaration();
        writer.root("urn:example:document", "document", "");
        writer.empty(NS_DAV, "inner");
        writer.end("urn:example:document", "document");
        let xml = writer.into_string();
        let root = reparse(&xml);
        assert!(root.is("urn:example:document", "document"), "{xml}");
        assert!(
            root.child(NS_DAV, "inner").is_some(),
            "the fixed prefixes are declared on it: {xml}"
        );
        let mut known = XmlWriter::new();
        known.root(NS_CALDAV, "schedule-response", " xmlns:n0=\"x\"");
        assert_eq!(
            known.into_string(),
            format!(
                "<C:schedule-response xmlns:D=\"{NS_DAV}\" xmlns:C=\"{NS_CALDAV}\" xmlns:CS=\"{NS_CALENDARSERVER}\" \
                 xmlns:ICAL=\"{NS_APPLE_ICAL}\" xmlns:n0=\"x\">"
            )
        );
    }

    #[test]
    fn a_root_declares_every_prefix_the_writer_can_use() {
        for (prefix, namespace) in FIXED_PREFIXES {
            assert_eq!(prefix_of(namespace), Some(prefix));
            let mut writer = XmlWriter::new();
            writer.root(NS_DAV, "document", "");
            writer.empty(namespace, "inside");
            writer.end(NS_DAV, "document");
            let xml = writer.into_string();
            assert!(
                reparse(&xml).child(namespace, "inside").is_some(),
                "{prefix}: an element in the namespace is well-formed below the root: {xml}"
            );
        }
        assert_eq!(prefix_of("urn:example:other"), None);
    }

    #[test]
    fn a_response_with_a_status_has_the_precondition_element_it_names() {
        let mut document = Multistatus::new();
        document.status_response("/a", 404, None);
        document.status_response("/b", 507, Some("number-of-matches-within-limits"));
        document.status_response_with("/c", 403, Some(&PreconditionElement::dav("invalid-sharee")));
        let xml = document.finish();
        assert!(
            xml.contains("<D:response><D:href>/a</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>"),
            "{xml}"
        );
        assert!(
            xml.contains("<D:error><D:number-of-matches-within-limits/></D:error>"),
            "{xml}"
        );
        assert!(xml.contains("<D:error><D:invalid-sharee/></D:error>"), "{xml}");
    }

    #[test]
    fn status_lines_name_the_reason() {
        assert_eq!(status_line(200), "HTTP/1.1 200 OK");
        assert_eq!(status_line(424), "HTTP/1.1 424 Failed Dependency");
        assert_eq!(status_line(507), "HTTP/1.1 507 Insufficient Storage");
        assert_eq!(status_line(799), "HTTP/1.1 799 Unknown");
    }
}
