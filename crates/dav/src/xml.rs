//! Hardened DAV XML: parsing into typed requests and the escaping XML writer.
//!
//! Request bodies are parsed with `quick_xml::NsReader` into a small owned tree ([`Element`]) and then read into
//! typed requests ([`requests`]); responses are written by hand with [`write::XmlWriter`]. There is no serde
//! derive anywhere (ADR-0001): DAV XML is mixed content with open-ended property sets, which derives handle badly.
//!
//! # Hardening
//!
//! Bodies come from the internet, so the parser enforces the limits of PLAN 2.15 (`DavLimits`) while it reads:
//!
//! * a `DOCTYPE` is refused outright, which rules out entity expansion bombs and external entities. Only the five
//!   predefined entities and numeric character references are resolved;
//! * nesting depth, element count, attributes per element and the number of distinct namespaces are counted, and
//!   the first document that exceeds one is refused (a namespace declared again and again counts once);
//! * control characters other than tab, line feed and carriage return are refused, in text and in attribute
//!   values, so they can never reach a stored property or a response;
//! * a declared encoding other than UTF-8 is refused, and so is anything after the root element;
//! * a namespace URI longer than [`MAX_NAMESPACE_BYTES`] and a name longer than [`MAX_NAME_BYTES`] are refused
//!   before anything is copied, and every namespace URI is kept once per document (interned), so that the memory
//!   the tree holds is bounded by the size of the body plus a fixed cost per element, however the body repeats a
//!   namespace. Without the two rules a 230 KiB body that declares a 150 KB namespace on one element and uses it
//!   for 10 000 children would hold, and later copy and write, gigabytes.
//!
//! Every failure is an [`XmlError`], which the handlers answer with 400 (the size ceiling of the body itself is
//! enforced before parsing and answers 413). The handlers run the reader through `methods::Call::parse_xml`,
//! which moves it off the async executor and gives it the wall-clock budget of PLAN 2.15.
//!
//! # The tree
//!
//! Names are resolved: an [`Element`] carries its namespace URI and local name, whatever prefix the client chose.
//! Text and child elements keep their order so that the content of a dead property can be written back exactly
//! ([`write::serialize_content`]).

use core::fmt;
use core::ops::Deref;
use std::collections::HashMap;
use std::sync::Arc;

use davhaven_domain::DavLimits;
use quick_xml::XmlVersion;
use quick_xml::errors::Error as QuickXmlError;
use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{NamespaceError, ResolveResult};
use quick_xml::reader::NsReader;

pub mod reports;
pub mod requests;
pub mod write;

/// The namespace the reserved `xml:` prefix is bound to.
pub const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";

/// The namespace the reserved `xmlns` prefix is bound to.
const NS_XMLNS: &str = "http://www.w3.org/2000/xmlns/";

/// The longest namespace URI a request may use, in bytes. Real namespaces are a few dozen bytes long.
pub const MAX_NAMESPACE_BYTES: usize = 1024;

/// The longest local name of an element or attribute a request may use, in bytes.
pub const MAX_NAME_BYTES: usize = 256;

/// The most bytes a namespace URI may take as it is written in the document, before references are resolved: a URI
/// of [`MAX_NAMESPACE_BYTES`] can be written with up to six times as many bytes (`&quot;` for one character), and
/// the stored form of a dead property writes every URI that way.
const MAX_RAW_NAMESPACE_BYTES: usize = MAX_NAMESPACE_BYTES * 6;

/// A namespace URI, shared by every element and attribute of a document that uses it.
///
/// It reads like a `str` (`Deref`, comparisons with `&str`), so the code that looks at names does not care that
/// the text is held once.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Namespace(Arc<str>);

impl Namespace {
    /// The URI.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Namespace {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Namespace {
    fn from(uri: &str) -> Self {
        Self(Arc::from(uri))
    }
}

impl From<String> for Namespace {
    fn from(uri: String) -> Self {
        Self(Arc::from(uri))
    }
}

impl PartialEq<str> for Namespace {
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}

impl PartialEq<&str> for Namespace {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a request body could not be read as DAV XML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlError {
    /// The body is not valid UTF-8, or declares another encoding.
    NotUtf8,
    /// The body has no root element.
    Empty,
    /// The body is not well-formed XML, or contains characters XML does not allow.
    Malformed,
    /// The body has a `DOCTYPE`, which is refused.
    Doctype,
    /// An entity other than the five predefined ones is referenced.
    UnknownEntity,
    /// An element or attribute uses a namespace prefix that is not declared.
    UnknownPrefix,
    /// The nesting is deeper than `max_xml_depth`.
    TooDeep,
    /// The body has more elements than `max_xml_elements`.
    TooManyElements,
    /// An element has more attributes than `max_xml_attributes`.
    TooManyAttributes,
    /// The body declares more namespaces than `max_xml_namespaces`.
    TooManyNamespaces,
    /// A namespace URI is longer than [`MAX_NAMESPACE_BYTES`] or a name longer than [`MAX_NAME_BYTES`].
    NameTooLong,
    /// An element is in the namespace of the `xml` or the `xmlns` prefix, which Namespaces in XML reserves: no client sends one,
    /// and the answer could not write it back.
    ReservedNamespace,
}

impl XmlError {
    /// A short, client-safe description (it names the rule, never the content of the body).
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NotUtf8 => "The XML body must be UTF-8.",
            Self::Empty => "The XML body is empty.",
            Self::Malformed => "The XML body is not well-formed.",
            Self::Doctype => "A document type declaration is not allowed.",
            Self::UnknownEntity => "Only the predefined XML entities are allowed.",
            Self::UnknownPrefix => "The XML body uses an undeclared namespace prefix.",
            Self::TooDeep => "The XML body is nested too deeply.",
            Self::TooManyElements => "The XML body has too many elements.",
            Self::TooManyAttributes => "An XML element has too many attributes.",
            Self::TooManyNamespaces => "The XML body declares too many namespaces.",
            Self::NameTooLong => "An XML name or namespace is too long.",
            Self::ReservedNamespace => "An XML element may not be in the reserved xml or xmlns namespace.",
        }
    }
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

impl core::error::Error for XmlError {}

/// An attribute with its resolved name. Namespace declarations are not attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The namespace URI; empty for attributes without a prefix.
    pub namespace: Namespace,
    /// The local name.
    pub local: String,
    /// The value, with entities resolved and whitespace normalized as XML requires.
    pub value: String,
}

/// A child of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A child element.
    Element(Element),
    /// Character data: text, CDATA sections and resolved references, merged.
    Text(String),
}

/// An element with its resolved name, attributes and children in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// The namespace URI; empty for elements in no namespace.
    pub namespace: Namespace,
    /// The local name.
    pub local: String,
    /// The attributes, without namespace declarations.
    pub attributes: Vec<Attribute>,
    /// The children in document order.
    pub children: Vec<Node>,
}

impl Element {
    /// An empty element.
    pub fn new(namespace: &str, local: &str) -> Self {
        Self::in_namespace(Namespace::from(namespace), local)
    }

    /// An empty element in an already shared namespace.
    fn in_namespace(namespace: Namespace, local: &str) -> Self {
        Self {
            namespace,
            local: local.to_owned(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Whether the element has this name.
    pub fn is(&self, namespace: &str, local: &str) -> bool {
        self.namespace == namespace && self.local == local
    }

    /// The child elements in document order (text is skipped).
    pub fn elements(&self) -> impl Iterator<Item = &Self> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(element) => Some(element),
            Node::Text(_) => None,
        })
    }

    /// The first child element with this name.
    pub fn child(&self, namespace: &str, local: &str) -> Option<&Self> {
        self.elements().find(|element| element.is(namespace, local))
    }

    /// The child elements with this name.
    pub fn children_named<'a>(&'a self, namespace: &'a str, local: &'a str) -> impl Iterator<Item = &'a Self> {
        self.elements().filter(move |element| element.is(namespace, local))
    }

    /// The value of the attribute without a namespace.
    pub fn attribute(&self, local: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| attribute.namespace.is_empty() && attribute.local == local)
            .map(|attribute| attribute.value.as_str())
    }

    /// The text directly inside the element: the text children concatenated, child elements skipped.
    pub fn text(&self) -> String {
        let mut text = String::new();
        for node in &self.children {
            if let Node::Text(part) = node {
                text.push_str(part);
            }
        }
        text
    }
}

/// `count` pieces of text, the `n`th made by `piece`, concatenated: the large bodies of the tests.
#[cfg(test)]
pub(crate) fn repeated(count: usize, piece: impl Fn(usize) -> String) -> String {
    let mut out = String::new();
    for n in 0..count {
        out.push_str(&piece(n));
    }
    out
}

/// Whether a character may appear in an XML 1.0 document.
pub(crate) const fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | ' '..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

/// Whether a character may start an XML name that has no colon (`NameStartChar` of XML 1.0, fifth edition,
/// section 2.3).
const fn is_name_start(c: char) -> bool {
    matches!(
        c,
        'A'..='Z'
            | '_'
            | 'a'..='z'
            | '\u{c0}'..='\u{d6}'
            | '\u{d8}'..='\u{f6}'
            | '\u{f8}'..='\u{2ff}'
            | '\u{370}'..='\u{37d}'
            | '\u{37f}'..='\u{1fff}'
            | '\u{200c}'..='\u{200d}'
            | '\u{2070}'..='\u{218f}'
            | '\u{2c00}'..='\u{2fef}'
            | '\u{3001}'..='\u{d7ff}'
            | '\u{f900}'..='\u{fdcf}'
            | '\u{fdf0}'..='\u{fffd}'
            | '\u{10000}'..='\u{effff}'
    )
}

/// Whether a character may continue an XML name that has no colon (`NameChar` of XML 1.0, fifth edition).
const fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || matches!(
            c,
            '-' | '.' | '0'..='9' | '\u{b7}' | '\u{300}'..='\u{36f}' | '\u{203f}'..='\u{2040}'
        )
}

/// Whether a local name is safe to write back as it is: exactly the names of XML 1.0 without a colon, so that no
/// quote, space, markup or character that a strict parser refuses in a name ever reaches a response.
pub(crate) fn is_ncname(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(is_name_start) && chars.all(is_name_char)
}

/// Keeps one copy of every namespace URI of a document.
struct Interner {
    none: Namespace,
    known: HashMap<String, Namespace>,
}

impl Interner {
    fn new() -> Self {
        Self {
            none: Namespace::from(""),
            known: HashMap::new(),
        }
    }

    fn intern(&mut self, uri: &str) -> Namespace {
        if uri.is_empty() {
            return self.none.clone();
        }
        if let Some(known) = self.known.get(uri) {
            return known.clone();
        }
        let namespace = Namespace::from(uri);
        self.known.insert(uri.to_owned(), namespace.clone());
        namespace
    }
}

/// The counters and limits of one parse.
struct Budget {
    max_depth: usize,
    max_elements: usize,
    max_attributes: usize,
    max_namespaces: usize,
    elements: usize,
    /// The distinct namespace URIs the document has declared so far.
    namespaces: Vec<String>,
    interner: Interner,
}

impl Budget {
    fn new(limits: &DavLimits) -> Self {
        let size = |value: u32| usize::try_from(value).unwrap_or(usize::MAX);
        Self {
            max_depth: size(limits.max_xml_depth),
            max_elements: size(limits.max_xml_elements),
            max_attributes: size(limits.max_xml_attributes),
            max_namespaces: size(limits.max_xml_namespaces),
            elements: 0,
            namespaces: Vec::new(),
            interner: Interner::new(),
        }
    }

    fn open(&mut self, depth: usize) -> Result<(), XmlError> {
        if depth > self.max_depth {
            return Err(XmlError::TooDeep);
        }
        self.elements += 1;
        if self.elements > self.max_elements {
            return Err(XmlError::TooManyElements);
        }
        Ok(())
    }

    /// Records a declaration. The limit counts distinct namespaces, not declarations: a client may declare the
    /// same few namespaces on every element, as Apple Calendar does for each property of a `PROPFIND`.
    fn declare_namespace(&mut self, uri: &str) -> Result<(), XmlError> {
        if self.namespaces.iter().any(|known| known == uri) {
            return Ok(());
        }
        if self.namespaces.len() >= self.max_namespaces {
            return Err(XmlError::TooManyNamespaces);
        }
        self.namespaces.push(uri.to_owned());
        Ok(())
    }
}

fn map_error(error: &QuickXmlError) -> XmlError {
    match error {
        QuickXmlError::Namespace(NamespaceError::TooManyBindings(_)) => XmlError::TooManyNamespaces,
        QuickXmlError::Namespace(NamespaceError::TooDeeplyNested(_)) => XmlError::TooDeep,
        QuickXmlError::Namespace(NamespaceError::UnknownPrefix(_)) => XmlError::UnknownPrefix,
        _ => XmlError::Malformed,
    }
}

/// The namespace of a resolved name: empty when the name is in none, an error for undeclared prefixes.
///
/// The resolver keeps the text of a declaration as it was written, references included (`xmlns:x="a&amp;b"` binds
/// `a&amp;b`), while the namespace is the value of the attribute: the references are resolved here, and the
/// result is held to the rules of every other attribute value. The length is checked before anything is copied.
fn namespace_of(resolved: &ResolveResult<'_>, interner: &mut Interner) -> Result<Namespace, XmlError> {
    match resolved {
        ResolveResult::Bound(namespace) => {
            let raw = namespace.into_inner();
            if raw.len() > MAX_RAW_NAMESPACE_BYTES {
                return Err(XmlError::NameTooLong);
            }
            let uri = unescape(raw).map_err(|_| XmlError::UnknownEntity)?;
            if uri.len() > MAX_NAMESPACE_BYTES {
                return Err(XmlError::NameTooLong);
            }
            if uri.chars().all(is_xml_char) {
                Ok(interner.intern(&uri))
            } else {
                Err(XmlError::Malformed)
            }
        }
        ResolveResult::Unbound => Ok(interner.intern("")),
        ResolveResult::Unknown(_) => Err(XmlError::UnknownPrefix),
    }
}

/// Builds the element of a start tag; `reader` resolves the names of the element and of its attributes.
fn start_element(
    start: &BytesStart<'_>,
    namespace: Namespace,
    reader: &NsReader<&[u8]>,
    budget: &mut Budget,
) -> Result<Element, XmlError> {
    let local = start.local_name().into_inner();
    if local.len() > MAX_NAME_BYTES {
        return Err(XmlError::NameTooLong);
    }
    if !is_ncname(local) {
        return Err(XmlError::Malformed);
    }
    let mut element = Element::in_namespace(namespace, local);
    let mut count = 0usize;
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|_| XmlError::Malformed)?;
        count += 1;
        if count > budget.max_attributes {
            return Err(XmlError::TooManyAttributes);
        }
        if attribute.key.as_namespace_binding().is_some() {
            if attribute.value.len() > MAX_RAW_NAMESPACE_BYTES {
                return Err(XmlError::NameTooLong);
            }
            let uri = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|_| XmlError::Malformed)?;
            if uri.len() > MAX_NAMESPACE_BYTES {
                return Err(XmlError::NameTooLong);
            }
            if !uri.chars().all(is_xml_char) {
                return Err(XmlError::Malformed);
            }
            budget.declare_namespace(&uri)?;
            continue;
        }
        let (namespace, local) = reader.resolver().resolve_attribute(attribute.key);
        if local.into_inner().len() > MAX_NAME_BYTES {
            return Err(XmlError::NameTooLong);
        }
        if !is_ncname(local.into_inner()) {
            return Err(XmlError::Malformed);
        }
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| XmlError::Malformed)?;
        if !value.chars().all(is_xml_char) {
            return Err(XmlError::Malformed);
        }
        let namespace = namespace_of(&namespace, &mut budget.interner)?;
        let local = local.into_inner();
        // Two prefixes bound to one namespace name the same attribute (Namespaces in XML, section 6.3).
        if element
            .attributes
            .iter()
            .any(|existing| existing.namespace == namespace && existing.local == local)
        {
            return Err(XmlError::Malformed);
        }
        element.attributes.push(Attribute {
            namespace,
            local: local.to_owned(),
            value: value.into_owned(),
        });
    }
    Ok(element)
}

/// Appends character data to the open element, merging it with the text before it.
fn push_text(open: &mut [Element], text: &str) -> Result<(), XmlError> {
    if !text.chars().all(is_xml_char) {
        return Err(XmlError::Malformed);
    }
    let Some(parent) = open.last_mut() else {
        // Outside the root element only whitespace is allowed.
        return if text.chars().all(char::is_whitespace) {
            Ok(())
        } else {
            Err(XmlError::Malformed)
        };
    };
    if let Some(Node::Text(existing)) = parent.children.last_mut() {
        existing.push_str(text);
    } else {
        parent.children.push(Node::Text(text.to_owned()));
    }
    Ok(())
}

/// The namespace of an element. Namespaces in XML reserves two: the one of the `xmlns` prefix, which no element may be in, and
/// the one of the `xml` prefix, which an element may be in (`<xml:x/>`) although the prefix cannot be declared again. The answer
/// declares the namespaces it names, and neither can be declared under another prefix or as the default one, so an element in
/// either could not be written back (a property named in a `PROPFIND`, the stored form of a dead property): no client sends one,
/// and the document that carries one is refused with [`XmlError::ReservedNamespace`], a deviation that `docs/interop.md`
/// records.
fn element_namespace(namespace: Namespace) -> Result<Namespace, XmlError> {
    if matches!(namespace.as_str(), NS_XMLNS | NS_XML) {
        Err(XmlError::ReservedNamespace)
    } else {
        Ok(namespace)
    }
}

/// The character a reference (`&amp;`, `&#38;`, `&#x26;`) stands for.
fn resolve_reference(reference: &quick_xml::events::BytesRef<'_>) -> Result<char, XmlError> {
    if let Some(character) = reference.resolve_char_ref().map_err(|_| XmlError::Malformed)? {
        return Ok(character);
    }
    match &**reference {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        _ => Err(XmlError::UnknownEntity),
    }
}

/// Attaches a finished element to its parent, or makes it the root.
fn close_element(open: &mut [Element], root: &mut Option<Element>, finished: Element) -> Result<(), XmlError> {
    if let Some(parent) = open.last_mut() {
        parent.children.push(Node::Element(finished));
        Ok(())
    } else if root.is_none() {
        *root = Some(finished);
        Ok(())
    } else {
        Err(XmlError::Malformed)
    }
}

/// Parses a DAV XML document into its root element, enforcing the limits.
///
/// # Errors
///
/// An [`XmlError`] naming the first rule the document breaks.
pub fn parse(bytes: &[u8], limits: &DavLimits) -> Result<Element, XmlError> {
    let text = core::str::from_utf8(bytes).map_err(|_| XmlError::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = NsReader::from_str(text);
    reader
        .resolver_mut()
        .set_max_namespace_bindings(usize::try_from(limits.max_xml_namespaces).unwrap_or(usize::MAX));
    let mut budget = Budget::new(limits);
    let mut open: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    loop {
        // The resolved name borrows the reader, so it is turned into an owned namespace before anything else.
        let (namespace, event) = {
            let (resolved, event) = reader.read_resolved_event().map_err(|error| map_error(&error))?;
            (namespace_of(&resolved, &mut budget.interner), event)
        };
        match event {
            Event::Start(start) => {
                budget.open(open.len() + 1)?;
                if root.is_some() && open.is_empty() {
                    return Err(XmlError::Malformed);
                }
                let element = start_element(&start, element_namespace(namespace?)?, &reader, &mut budget)?;
                open.push(element);
            }
            Event::Empty(start) => {
                budget.open(open.len() + 1)?;
                let element = start_element(&start, element_namespace(namespace?)?, &reader, &mut budget)?;
                close_element(&mut open, &mut root, element)?;
            }
            Event::End(_) => {
                let finished = open.pop().ok_or(XmlError::Malformed)?;
                close_element(&mut open, &mut root, finished)?;
            }
            Event::Text(text) => push_text(&mut open, &text.xml10_content())?,
            Event::CData(data) => push_text(&mut open, &data.xml10_content())?,
            Event::GeneralRef(reference) => {
                let mut buffer = [0u8; 4];
                push_text(&mut open, resolve_reference(&reference)?.encode_utf8(&mut buffer))?;
            }
            Event::DocType(_) => return Err(XmlError::Doctype),
            Event::Decl(declaration) => {
                let utf8 = match declaration.encoding() {
                    None => true,
                    Some(Ok(encoding)) => encoding.eq_ignore_ascii_case("utf-8"),
                    Some(Err(_)) => false,
                };
                if !utf8 {
                    return Err(XmlError::NotUtf8);
                }
            }
            Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
    }
    if !open.is_empty() {
        return Err(XmlError::Malformed);
    }
    root.ok_or(XmlError::Empty)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> DavLimits {
        DavLimits::default()
    }

    fn parse_str(text: &str) -> Result<Element, XmlError> {
        parse(text.as_bytes(), &limits())
    }

    #[test]
    fn names_are_resolved_whatever_the_prefix() {
        let root = parse_str(
            r#"<?xml version="1.0" encoding="utf-8"?>
            <x:propfind xmlns:x="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
              <x:prop><c:calendar-data c:foo="bar" plain="1"/><x:displayname/></x:prop>
            </x:propfind>"#,
        )
        .unwrap();
        assert!(root.is("DAV:", "propfind"));
        let prop = root.child("DAV:", "prop").unwrap();
        let data = prop.child("urn:ietf:params:xml:ns:caldav", "calendar-data").unwrap();
        assert_eq!(data.attribute("plain"), Some("1"));
        assert_eq!(data.attributes.len(), 2);
        assert_eq!(data.attributes[0].namespace, "urn:ietf:params:xml:ns:caldav");
        assert!(prop.child("DAV:", "displayname").is_some());
        assert!(prop.child("urn:other", "displayname").is_none());
    }

    #[test]
    fn default_namespaces_apply_to_elements_but_not_to_attributes() {
        let root = parse_str(r#"<a xmlns="urn:one" b="c"><d xmlns=""/><e xmlns="urn:two"/></a>"#).unwrap();
        assert!(root.is("urn:one", "a"));
        assert_eq!(root.attributes[0].namespace, "");
        let children: Vec<_> = root.elements().collect();
        assert!(children[0].is("", "d"));
        assert!(children[1].is("urn:two", "e"));
    }

    #[test]
    fn text_is_merged_across_cdata_and_references() {
        let root = parse_str("<a>x &amp; y &lt;<![CDATA[<z>]]>&#65;&#x42;</a>").unwrap();
        assert_eq!(root.text(), "x & y <<z>AB");
        assert_eq!(root.children.len(), 1, "one merged text node");
        let mixed = parse_str("<a>one<b/>two</a>").unwrap();
        assert_eq!(mixed.children.len(), 3);
        assert_eq!(mixed.text(), "onetwo");
    }

    #[test]
    fn carriage_returns_in_character_references_survive() {
        // `&#13;` is how a server writes the CRLF of iCalendar text so that the XML parser does not fold it.
        let root = parse_str("<a>line&#13;\nnext</a>").unwrap();
        assert_eq!(root.text(), "line\r\nnext");
    }

    #[test]
    fn a_doctype_is_refused_before_any_entity_can_expand() {
        let bomb = r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>"#;
        assert_eq!(parse_str(bomb).unwrap_err(), XmlError::Doctype);
        let external = r#"<!DOCTYPE a SYSTEM "file:///etc/passwd"><a/>"#;
        assert_eq!(parse_str(external).unwrap_err(), XmlError::Doctype);
    }

    #[test]
    fn undeclared_and_custom_entities_are_refused() {
        assert_eq!(parse_str("<a>&custom;</a>").unwrap_err(), XmlError::UnknownEntity);
        assert_eq!(parse_str("<a>&#0;</a>").unwrap_err(), XmlError::Malformed);
        assert_eq!(parse_str("<a>&#1;</a>").unwrap_err(), XmlError::Malformed);
        assert_eq!(parse_str("<a>&#xD800;</a>").unwrap_err(), XmlError::Malformed);
        assert_eq!(parse_str("<x:a/>").unwrap_err(), XmlError::UnknownPrefix);
    }

    #[test]
    fn control_characters_never_get_through() {
        assert_eq!(parse_str("<a>x\u{1}y</a>").unwrap_err(), XmlError::Malformed);
        assert_eq!(parse_str("<a b=\"x\u{8}\"/>").unwrap_err(), XmlError::Malformed);
        // A namespace declaration is an attribute too: the fuzzer found a control character in one.
        assert_eq!(
            parse_str("<a xmlns:x=\"urn:\u{1}\"/>").unwrap_err(),
            XmlError::Malformed
        );
        assert_eq!(parse_str("<a xmlns=\"urn:\u{0}x\"/>").unwrap_err(), XmlError::Malformed);
        assert!(parse_str("<a>tab\tnl\nok</a>").is_ok());
    }

    #[test]
    fn one_attribute_cannot_be_written_twice_under_two_prefixes() {
        let twice = r#"<e xmlns:a="urn:u" xmlns:b="urn:u" a:x="1" b:x="2"/>"#;
        assert_eq!(parse_str(twice).unwrap_err(), XmlError::Malformed);
        let apart = r#"<e xmlns:a="urn:u" xmlns:b="urn:v" a:x="1" b:x="2" x="3"/>"#;
        assert_eq!(parse_str(apart).unwrap().attributes.len(), 3);
    }

    #[test]
    fn an_element_in_a_namespace_that_xml_reserves_is_refused() {
        // The fuzz target of the request reader found `<xmlns:x/>`, a property whose answer would declare the namespace of the
        // `xmlns` prefix as the one of another prefix, which no reader accepts.
        for bad in [
            r"<a><xmlns:x/></a>",
            r"<a><xmlns:x>text</xmlns:x></a>",
            r"<a><xml:x/></a>",
            r"<xml:a/>",
            r#"<a xmlns="http://www.w3.org/XML/1998/namespace"><b/></a>"#,
            r#"<a><b xmlns="http://www.w3.org/2000/xmlns/"/></a>"#,
        ] {
            assert!(parse_str(bad).is_err(), "{bad}");
        }
        // An element of the XML namespace is allowed by the specification and refused here, with the reason that says so (and not
        // as a document that is not well-formed).
        for refused in [r"<a><xml:x/></a>", r"<xml:a/>"] {
            assert_eq!(
                parse_str(refused).unwrap_err(),
                XmlError::ReservedNamespace,
                "{refused}"
            );
        }
        assert_eq!(
            XmlError::ReservedNamespace.describe(),
            "An XML element may not be in the reserved xml or xmlns namespace."
        );
        // The attribute `xml:lang` stays what it is, and so do declarations.
        let root = parse_str(r#"<a xml:lang="de" xmlns:x="urn:x"><x:b xml:space="preserve"/></a>"#).unwrap();
        assert!(
            root.attributes
                .iter()
                .any(|attribute| attribute.namespace == NS_XML && attribute.local == "lang" && attribute.value == "de")
        );
    }

    #[test]
    fn references_in_a_namespace_declaration_are_resolved() {
        let root = parse_str(r#"<a xmlns:x="urn:a&amp;b&#63;&gt;"><x:c x:d="1"/></a>"#).unwrap();
        let child = root.elements().next().unwrap();
        assert_eq!(child.namespace, "urn:a&b?>");
        assert_eq!(child.attributes[0].namespace, "urn:a&b?>");
        for bad in [
            r#"<a xmlns="urn:&unknown;"/>"#,
            r#"<a xmlns="urn:&#1;"/>"#,
            r#"<a xmlns:x="urn:&#xD800;"><x:b/></a>"#,
        ] {
            assert!(parse_str(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn malformed_documents_are_refused() {
        for text in [
            "",
            "   ",
            "not xml",
            "<a>",
            "<a></b>",
            "<a/><b/>",
            "<a/>trailing",
            "</a>",
            "<a b=1/>",
            "<a b='1' b='2'/>",
        ] {
            let error = parse_str(text).unwrap_err();
            assert!(
                matches!(error, XmlError::Empty | XmlError::Malformed),
                "{text:?}: {error:?}"
            );
        }
        assert_eq!(parse_str("").unwrap_err(), XmlError::Empty);
        assert!(parse_str("<a/>  \n").is_ok(), "whitespace after the root is fine");
        assert!(parse_str("<a/><!-- trailing comment -->").is_ok());
    }

    #[test]
    fn only_utf8_is_accepted() {
        assert_eq!(
            parse(&[b'<', b'a', b'>', 0xff, b'<', b'/', b'a', b'>'], &limits()).unwrap_err(),
            XmlError::NotUtf8
        );
        assert_eq!(
            parse_str(r#"<?xml version="1.0" encoding="ISO-8859-1"?><a/>"#).unwrap_err(),
            XmlError::NotUtf8
        );
        assert!(parse_str(r#"<?xml version="1.0" encoding="UTF-8"?><a/>"#).is_ok());
        assert!(
            parse("\u{feff}<a/>".as_bytes(), &limits()).is_ok(),
            "a byte order mark is ignored"
        );
    }

    #[test]
    fn nesting_is_limited() {
        let limits = DavLimits {
            max_xml_depth: 3,
            ..DavLimits::default()
        };
        assert!(parse(b"<a><b><c/></b></a>", &limits).is_ok());
        assert_eq!(
            parse(b"<a><b><c><d/></c></b></a>", &limits).unwrap_err(),
            XmlError::TooDeep
        );
        let deep = format!("{}{}", "<a>".repeat(200), "</a>".repeat(200));
        assert_eq!(parse_str(&deep).unwrap_err(), XmlError::TooDeep);
    }

    #[test]
    fn the_element_count_is_limited() {
        let limits = DavLimits {
            max_xml_elements: 5,
            ..DavLimits::default()
        };
        assert!(parse(b"<a><b/><b/><b/><b/></a>", &limits).is_ok());
        assert_eq!(
            parse(b"<a><b/><b/><b/><b/><b/></a>", &limits).unwrap_err(),
            XmlError::TooManyElements
        );
    }

    #[test]
    fn attributes_per_element_are_limited() {
        let limits = DavLimits {
            max_xml_attributes: 2,
            ..DavLimits::default()
        };
        assert!(parse(b"<a b='1' c='2'/>", &limits).is_ok());
        assert_eq!(
            parse(b"<a b='1' c='2' d='3'/>", &limits).unwrap_err(),
            XmlError::TooManyAttributes
        );
    }

    #[test]
    fn namespace_declarations_are_limited() {
        let limits = DavLimits {
            max_xml_namespaces: 2,
            ..DavLimits::default()
        };
        assert!(parse(br#"<a xmlns:x="urn:1" xmlns:y="urn:2"/>"#, &limits).is_ok());
        assert_eq!(
            parse(br#"<a xmlns:x="urn:1" xmlns:y="urn:2" xmlns:z="urn:3"/>"#, &limits).unwrap_err(),
            XmlError::TooManyNamespaces
        );
        let spread = br#"<a xmlns:x="urn:1"><b xmlns:y="urn:2"><c xmlns:z="urn:3"/></b></a>"#;
        assert_eq!(parse(spread, &limits).unwrap_err(), XmlError::TooManyNamespaces);
        let siblings = br#"<a><b xmlns:x="urn:1"/><b xmlns:y="urn:2"/><b xmlns:z="urn:3"/></a>"#;
        assert_eq!(
            parse(siblings, &limits).unwrap_err(),
            XmlError::TooManyNamespaces,
            "the limit is on distinct namespaces of the document, wherever they are declared"
        );
    }

    #[test]
    fn the_same_namespaces_may_be_declared_as_often_as_a_client_likes() {
        // Apple Calendar declares the namespace of every property on the property element itself.
        let mut properties = String::new();
        for n in 0..200 {
            let property = match n % 4 {
                0 => format!("<p{n} xmlns=\"DAV:\"/>"),
                1 => format!("<p{n} xmlns=\"urn:ietf:params:xml:ns:caldav\"/>"),
                2 => format!("<x:p{n} xmlns:x=\"http://calendarserver.org/ns/\"/>"),
                _ => format!("<y:p{n} xmlns:y=\"http://apple.com/ns/ical/\"><z:c xmlns:z=\"DAV:\"/></y:p{n}>"),
            };
            properties.push_str(&property);
        }
        let body = format!("<propfind xmlns=\"DAV:\"><prop>{properties}</prop></propfind>");
        let root = parse_str(&body).unwrap();
        assert_eq!(root.child("DAV:", "prop").unwrap().elements().count(), 200);
    }

    #[test]
    fn errors_describe_the_rule_not_the_content() {
        for error in [
            XmlError::NotUtf8,
            XmlError::Empty,
            XmlError::Malformed,
            XmlError::Doctype,
            XmlError::UnknownEntity,
            XmlError::UnknownPrefix,
            XmlError::TooDeep,
            XmlError::TooManyElements,
            XmlError::TooManyAttributes,
            XmlError::TooManyNamespaces,
            XmlError::NameTooLong,
        ] {
            assert!(error.describe().ends_with('.'), "{error:?}");
            assert_eq!(error.to_string(), error.describe());
        }
    }

    #[test]
    fn names_are_the_names_of_xml_without_a_colon() {
        for good in [
            "a",
            "_a",
            "note.v2",
            "x-y",
            "\u{e4}\u{f6}",
            "caf\u{e9}",
            "a\u{b7}b",
            "\u{65e5}\u{672c}",
        ] {
            assert!(is_ncname(good), "{good}");
        }
        for bad in [
            "",
            "1a",
            "-a",
            ".a",
            "a:b",
            ":a",
            "a b",
            "a<b",
            "a\"b",
            "a\u{aa}",
            "\u{d7}",
            "a\u{2028}",
        ] {
            assert!(!is_ncname(bad), "{bad:?}");
        }
    }

    #[test]
    fn long_namespaces_and_names_are_refused_before_they_are_copied() {
        let long_uri = "n".repeat(MAX_NAMESPACE_BYTES + 1);
        for body in [
            format!(r#"<a xmlns="urn:{long_uri}"/>"#),
            format!(r#"<a xmlns:x="urn:{long_uri}"><x:b/></a>"#),
            format!(r#"<a xmlns:x="urn:{long_uri}" x:c="1"/>"#),
            format!(r#"<a xmlns:x="urn:{long_uri}"><b x:c="1"/></a>"#),
        ] {
            assert_eq!(
                parse_str(&body).unwrap_err(),
                XmlError::NameTooLong,
                "{}",
                body.chars().take(40).collect::<String>()
            );
        }
        let uri_at_the_limit = "n".repeat(MAX_NAMESPACE_BYTES - 4);
        assert!(parse_str(&format!(r#"<a xmlns="urn:{uri_at_the_limit}"/>"#)).is_ok());

        let long_name = "e".repeat(MAX_NAME_BYTES + 1);
        assert_eq!(
            parse_str(&format!("<{long_name}/>")).unwrap_err(),
            XmlError::NameTooLong
        );
        assert_eq!(
            parse_str(&format!(r#"<a {long_name}="1"/>"#)).unwrap_err(),
            XmlError::NameTooLong
        );
        let name_at_the_limit = "e".repeat(MAX_NAME_BYTES);
        assert!(parse_str(&format!(r#"<{name_at_the_limit} {name_at_the_limit}="1"/>"#)).is_ok());
    }

    #[test]
    fn the_cap_is_on_the_namespace_not_on_the_way_it_is_written() {
        // A namespace of exactly the cap that needs escaping is written with four times as many bytes by the stored
        // form of a dead property, and must read back.
        let uri = ">".repeat(MAX_NAMESPACE_BYTES);
        let root = parse_str(&format!(r#"<a xmlns="{uri}"><b/></a>"#)).unwrap();
        let stored = write::serialize_content(&root);
        assert!(stored.len() > 4 * MAX_NAMESPACE_BYTES, "{}", stored.len());
        let again = parse_str(&format!("<holder xmlns=\"urn:h\">{stored}</holder>")).unwrap();
        assert_eq!(again.children, root.children);
        let too_long = ">".repeat(MAX_NAMESPACE_BYTES + 1);
        assert_eq!(
            parse_str(&format!(r#"<a xmlns="{too_long}"/>"#)).unwrap_err(),
            XmlError::NameTooLong
        );
        let escaped_too_long = "&gt;".repeat(MAX_NAMESPACE_BYTES + 1);
        assert_eq!(
            parse_str(&format!(r#"<a xmlns="{escaped_too_long}"/>"#)).unwrap_err(),
            XmlError::NameTooLong
        );
        let giant = "&gt;".repeat(100_000);
        assert_eq!(
            parse_str(&format!(r#"<a xmlns="{giant}"/>"#)).unwrap_err(),
            XmlError::NameTooLong,
            "refused from the written length, before it is resolved"
        );
    }

    #[test]
    fn the_amplifying_document_of_the_audit_is_refused() {
        // One 150 KB namespace declared once and used by ten thousand children: about 230 KB of text that, held
        // per element, would be 1.5 GB.
        let namespace = "a".repeat(150_000);
        let children = repeated(9_990, |n| format!("<p{n}/>"));
        let body =
            format!(r#"<D:propfind xmlns:D="DAV:"><D:prop xmlns="urn:{namespace}">{children}</D:prop></D:propfind>"#);
        assert!(body.len() < 262_144);
        assert_eq!(parse_str(&body).unwrap_err(), XmlError::NameTooLong);
    }

    #[test]
    fn a_namespace_is_held_once_however_often_it_is_used() {
        let body = format!(
            r#"<a xmlns="urn:one">{}<c xmlns="urn:one" xmlns:x="urn:one" x:y="1"/></a>"#,
            "<b/>".repeat(100)
        );
        let root = parse_str(&body).unwrap();
        for child in root.elements() {
            assert!(Arc::ptr_eq(&child.namespace.0, &root.namespace.0), "{}", child.local);
        }
        let declared_twice = root.elements().last().unwrap();
        assert!(Arc::ptr_eq(
            &declared_twice.attributes[0].namespace.0,
            &root.namespace.0
        ));
        let none = parse_str(r#"<a xmlns=""><b/></a>"#).unwrap();
        assert!(Arc::ptr_eq(
            &none.namespace.0,
            &none.elements().next().unwrap().namespace.0
        ));
    }

    #[test]
    fn namespaces_read_like_text() {
        let namespace = Namespace::from("urn:x");
        assert_eq!(namespace, "urn:x");
        assert_eq!(namespace.as_str(), "urn:x");
        assert_eq!(namespace.len(), 5, "it derefs to str");
        assert_eq!(namespace.to_string(), "urn:x");
        assert_eq!(namespace, Namespace::from(String::from("urn:x")));
        assert_ne!(namespace, "urn:y");
    }

    #[test]
    fn xml_characters_follow_the_specification() {
        for c in [
            '\t',
            '\n',
            '\r',
            ' ',
            'a',
            'ä',
            '\u{d7ff}',
            '\u{e000}',
            '\u{fffd}',
            '\u{10000}',
        ] {
            assert!(is_xml_char(c), "{c:?}");
        }
        for c in ['\0', '\u{1}', '\u{b}', '\u{1f}', '\u{fffe}', '\u{ffff}'] {
            assert!(!is_xml_char(c), "{c:?}");
        }
    }
}
