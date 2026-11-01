//! A small XML tree and a path language for the assertions of client-flow scenarios.
//!
//! Scenarios assert on DAV responses (`207 Multi-Status`, `calendar-data`, ...). They need a few things from XML:
//! the namespace of every name, the text of an element, and a way to say "this element exists exactly once". The
//! parser here builds a tree with resolved namespaces; [`Document::select`] evaluates a deliberately small subset of
//! `XPath` 1.0 on it, with names in Clark notation (`{DAV:}href`) so that scenarios need no prefix declarations (the
//! same convention as the `ccs-caldavtester` scripts the scenarios are ported from).
//!
//! # Path language
//!
//! ```text
//! path      = ( "/" | "//" ) step { ( "/" | "//" ) step } [ "/" terminal ]
//! step      = name [ predicate ]
//! name      = "{" namespace "}" local | local | "*"        (a bare name is in no namespace)
//! predicate = "[" integer "]"                              the nth match among the children of one parent
//!           | "[@" name [ "=" quoted ] "]"                 an attribute exists / has the value
//!           | "[" name [ "=" quoted ] "]"                  a child exists / has the (trimmed) text
//! terminal  = "text()" | "@" name                          the text of an element / an attribute value
//! ```
//!
//! The first step addresses the root element; `//` searches all descendants. A path without terminal selects
//! elements, and their value is the text of the element. The parser is for tests: it rejects `DOCTYPE`, limits
//! the nesting depth and keeps whitespace in text.

use std::collections::BTreeMap;

/// The deepest element nesting the parser accepts.
const MAX_DEPTH: usize = 64;

/// Failures of parsing XML or of evaluating a path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlError {
    /// The text is not well-formed XML; the message says where and why.
    #[error("malformed XML: {0}")]
    Malformed(String),
    /// The document has a `DOCTYPE`, which the harness refuses like the server does.
    #[error("DOCTYPE declarations are not accepted")]
    Doctype,
    /// The nesting is deeper than 64 elements.
    #[error("the XML nests deeper than {MAX_DEPTH} elements")]
    TooDeep,
    /// The path expression cannot be parsed.
    #[error("invalid path `{path}`: {reason}")]
    Path {
        /// The path as written.
        path: String,
        /// What is wrong with it.
        reason: String,
    },
}

/// An attribute of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The namespace, empty for unprefixed attributes.
    pub namespace: String,
    /// The local name.
    pub local: String,
    /// The decoded value.
    pub value: String,
}

/// A child of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A nested element.
    Element(Element),
    /// Decoded character data (including `CDATA` sections).
    Text(String),
}

/// An element with a resolved namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// The namespace URI, empty when the element is in no namespace.
    pub namespace: String,
    /// The local name.
    pub local: String,
    /// The attributes without namespace declarations.
    pub attributes: Vec<Attribute>,
    /// The children in document order.
    pub children: Vec<Node>,
}

impl Element {
    /// The name in Clark notation: `{DAV:}href`, or `href` without namespace.
    pub fn clark(&self) -> String {
        clark(&self.namespace, &self.local)
    }

    /// The concatenated text of the element and its descendants.
    pub fn text(&self) -> String {
        let mut out = String::new();
        self.collect_text(&mut out);
        out
    }

    fn collect_text(&self, out: &mut String) {
        for child in &self.children {
            match child {
                Node::Text(text) => out.push_str(text),
                Node::Element(element) => element.collect_text(out),
            }
        }
    }

    /// The child elements in document order.
    pub fn elements(&self) -> impl Iterator<Item = &Self> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(element) => Some(element),
            Node::Text(_) => None,
        })
    }

    /// The value of the attribute with the Clark name `name`.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| clark(&attribute.namespace, &attribute.local) == name)
            .map(|attribute| attribute.value.as_str())
    }
}

/// The Clark notation of a name.
fn clark(namespace: &str, local: &str) -> String {
    if namespace.is_empty() {
        local.to_owned()
    } else {
        format!("{{{namespace}}}{local}")
    }
}

/// A parsed XML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The root element.
    pub root: Element,
}

// ---------------------------------------------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------------------------------------------

/// A start tag: the qualified name, the raw attributes and whether the tag closes itself.
type StartTag<'a> = (&'a str, Vec<(&'a str, String)>, bool);

struct Parser<'a> {
    text: &'a str,
    pos: usize,
    scopes: Vec<BTreeMap<String, String>>,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        self.text.get(self.pos..).unwrap_or("")
    }

    fn starts_with(&self, prefix: &str) -> bool {
        self.rest().starts_with(prefix)
    }

    fn advance(&mut self, bytes: usize) {
        self.pos = (self.pos + bytes).min(self.text.len());
    }

    fn malformed(&self, reason: &str) -> XmlError {
        let line = self
            .text
            .get(..self.pos)
            .map_or(1, |head| head.matches('\n').count() + 1);
        XmlError::Malformed(format!("{reason} (line {line})"))
    }

    fn skip_whitespace(&mut self) {
        let trimmed = self.rest().trim_start_matches([' ', '\t', '\r', '\n']);
        self.pos = self.text.len() - trimmed.len();
    }

    /// Skips comments and processing instructions; rejects a DOCTYPE.
    fn skip_misc(&mut self) -> Result<(), XmlError> {
        loop {
            self.skip_whitespace();
            if self.starts_with("<?") {
                self.skip_past("?>")?;
            } else if self.starts_with("<!--") {
                self.skip_past("-->")?;
            } else if self.starts_with("<!DOCTYPE") || self.starts_with("<!doctype") {
                return Err(XmlError::Doctype);
            } else {
                return Ok(());
            }
        }
    }

    fn skip_past(&mut self, terminator: &str) -> Result<(), XmlError> {
        match self.rest().find(terminator) {
            Some(index) => {
                self.advance(index + terminator.len());
                Ok(())
            }
            None => Err(self.malformed(&format!("`{terminator}` is missing"))),
        }
    }

    fn name(&mut self) -> Result<&'a str, XmlError> {
        let rest = self.rest();
        let end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '=' | '>' | '/' | '<' | '"' | '\''))
            .unwrap_or(rest.len());
        if end == 0 {
            return Err(self.malformed("a name is expected"));
        }
        let name = rest.get(..end).unwrap_or("");
        self.advance(end);
        Ok(name)
    }

    fn lookup(&self, prefix: &str) -> Option<&str> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(prefix))
            .map(String::as_str)
    }

    /// Reads `<name attr="value" ...` up to and including `>` or `/>`; returns the name, the raw attributes and
    /// whether the tag closes itself.
    fn start_tag(&mut self) -> Result<StartTag<'a>, XmlError> {
        if !self.starts_with("<") {
            return Err(self.malformed("an element is expected"));
        }
        self.advance(1);
        let qname = self.name()?;
        let mut attributes: Vec<(&'a str, String)> = Vec::new();
        loop {
            self.skip_whitespace();
            if self.starts_with("/>") {
                self.advance(2);
                return Ok((qname, attributes, true));
            }
            if self.starts_with(">") {
                self.advance(1);
                return Ok((qname, attributes, false));
            }
            let name = self.name()?;
            self.skip_whitespace();
            if !self.starts_with("=") {
                return Err(self.malformed("an attribute needs a value"));
            }
            self.advance(1);
            self.skip_whitespace();
            let Some(quote @ ('"' | '\'')) = self.rest().chars().next() else {
                return Err(self.malformed("an attribute value must be quoted"));
            };
            self.advance(1);
            let rest = self.rest();
            let end = rest
                .find(quote)
                .ok_or_else(|| self.malformed("an attribute value is not closed"))?;
            let value = decode(rest.get(..end).unwrap_or(""), self)?;
            self.advance(end + 1);
            attributes.push((name, value));
        }
    }

    /// The namespace a prefix is bound to; the empty prefix is the default namespace, which may be unbound.
    fn namespace_of(&self, prefix: &str) -> Result<String, XmlError> {
        match self.lookup(prefix) {
            Some(namespace) => Ok(namespace.to_owned()),
            None if prefix.is_empty() => Ok(String::new()),
            None => Err(self.malformed(&format!("the prefix `{prefix}` is not declared"))),
        }
    }

    fn element(&mut self, depth: usize) -> Result<Element, XmlError> {
        if depth > MAX_DEPTH {
            return Err(XmlError::TooDeep);
        }
        let (qname, raw_attributes, self_closing) = self.start_tag()?;

        let mut scope = BTreeMap::new();
        for (name, value) in &raw_attributes {
            if *name == "xmlns" {
                scope.insert(String::new(), value.clone());
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                scope.insert(prefix.to_owned(), value.clone());
            }
        }
        self.scopes.push(scope);

        let (prefix, local) = qname.split_once(':').unwrap_or(("", qname));
        let namespace = self.namespace_of(prefix)?;
        let mut attributes = Vec::new();
        for (name, value) in raw_attributes {
            if name == "xmlns" || name.starts_with("xmlns:") {
                continue;
            }
            let (attribute_prefix, attribute_local) = name.split_once(':').unwrap_or(("", name));
            // Unprefixed attributes are in no namespace, whatever the default namespace is.
            let attribute_namespace = if attribute_prefix.is_empty() {
                String::new()
            } else {
                self.namespace_of(attribute_prefix)?
            };
            attributes.push(Attribute {
                namespace: attribute_namespace,
                local: attribute_local.to_owned(),
                value,
            });
        }

        let mut children = Vec::new();
        if !self_closing {
            self.content(depth, &mut children)?;
            if !self.starts_with("</") {
                return Err(self.malformed(&format!("`</{qname}>` is missing")));
            }
            self.advance(2);
            let closing = self.name()?;
            self.skip_whitespace();
            if closing != qname || !self.starts_with(">") {
                return Err(self.malformed(&format!("`</{closing}>` does not close `<{qname}>`")));
            }
            self.advance(1);
        }
        self.scopes.pop();
        Ok(Element {
            namespace,
            local: local.to_owned(),
            attributes,
            children,
        })
    }

    fn content(&mut self, depth: usize, children: &mut Vec<Node>) -> Result<(), XmlError> {
        loop {
            let rest = self.rest();
            if rest.is_empty() {
                return Err(self.malformed("the document ends inside an element"));
            }
            if self.starts_with("</") {
                return Ok(());
            }
            if self.starts_with("<!--") {
                self.skip_past("-->")?;
            } else if self.starts_with("<![CDATA[") {
                self.advance("<![CDATA[".len());
                let rest = self.rest();
                let end = rest
                    .find("]]>")
                    .ok_or_else(|| self.malformed("a CDATA section is not closed"))?;
                children.push(Node::Text(rest.get(..end).unwrap_or("").to_owned()));
                self.advance(end + 3);
            } else if self.starts_with("<?") {
                self.skip_past("?>")?;
            } else if self.starts_with("<!") {
                return Err(self.malformed("a declaration is not allowed inside an element"));
            } else if self.starts_with("<") {
                children.push(Node::Element(self.element(depth + 1)?));
            } else {
                let end = rest.find('<').unwrap_or(rest.len());
                let raw = rest.get(..end).unwrap_or("");
                children.push(Node::Text(decode(raw, self)?));
                self.advance(end);
            }
        }
    }
}

/// Decodes the predefined entities and character references of `raw`.
fn decode(raw: &str, parser: &Parser<'_>) -> Result<String, XmlError> {
    if !raw.contains('&') {
        return Ok(raw.to_owned());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find('&') {
        out.push_str(rest.get(..start).unwrap_or(""));
        let after = rest.get(start + 1..).unwrap_or("");
        let end = after
            .find(';')
            .ok_or_else(|| parser.malformed("an entity reference is not closed"))?;
        let entity = after.get(..end).unwrap_or("");
        let decoded = match entity {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|decimal| decimal.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => out.push(c),
            None => return Err(parser.malformed(&format!("the entity `&{entity};` is not known"))),
        }
        rest = after.get(end + 1..).unwrap_or("");
    }
    out.push_str(rest);
    Ok(out)
}

impl Document {
    /// Parses a document.
    ///
    /// # Errors
    ///
    /// [`XmlError`] when the text is not well-formed, has a `DOCTYPE`, or nests too deeply.
    pub fn parse(text: &str) -> Result<Self, XmlError> {
        let mut parser = Parser {
            text: text.strip_prefix('\u{feff}').unwrap_or(text),
            pos: 0,
            scopes: vec![BTreeMap::from([(
                "xml".to_owned(),
                "http://www.w3.org/XML/1998/namespace".to_owned(),
            )])],
        };
        parser.skip_misc()?;
        let root = parser.element(1)?;
        parser.skip_misc()?;
        if !parser.rest().is_empty() {
            return Err(parser.malformed("content after the root element"));
        }
        Ok(Self { root })
    }

    /// Evaluates a path (see the module documentation) and returns the value of every match: the text of the
    /// matched elements, or the attribute values or texts selected by a terminal.
    ///
    /// # Errors
    ///
    /// [`XmlError::Path`] when the path cannot be parsed.
    pub fn select(&self, path: &str) -> Result<Vec<String>, XmlError> {
        let compiled = Path::compile(path)?;
        Ok(compiled.evaluate(&self.root))
    }

    /// How many elements or values the path selects.
    ///
    /// # Errors
    ///
    /// [`XmlError::Path`] when the path cannot be parsed.
    pub fn count(&self, path: &str) -> Result<usize, XmlError> {
        self.select(path).map(|values| values.len())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum NameTest {
    Any,
    Name { namespace: String, local: String },
}

impl NameTest {
    fn parse(text: &str) -> Option<Self> {
        if text == "*" {
            return Some(Self::Any);
        }
        if let Some(rest) = text.strip_prefix('{') {
            let (namespace, local) = rest.split_once('}')?;
            return (!namespace.is_empty() && !local.is_empty()).then(|| Self::Name {
                namespace: namespace.to_owned(),
                local: local.to_owned(),
            });
        }
        (!text.is_empty()).then(|| Self::Name {
            namespace: String::new(),
            local: text.to_owned(),
        })
    }

    fn matches(&self, element: &Element) -> bool {
        match self {
            Self::Any => true,
            Self::Name { namespace, local } => &element.namespace == namespace && &element.local == local,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Predicate {
    Index(usize),
    Attribute { name: String, value: Option<String> },
    Child { test: NameTest, value: Option<String> },
}

impl Predicate {
    fn parse(text: &str) -> Option<Self> {
        if let Ok(index) = text.parse::<usize>() {
            return (index > 0).then_some(Self::Index(index));
        }
        let (subject, value) = match text.split_once('=') {
            Some((subject, quoted)) => {
                let quoted = quoted.trim();
                let unquoted = quoted
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .or_else(|| quoted.strip_prefix('\'').and_then(|rest| rest.strip_suffix('\'')))?;
                (subject.trim(), Some(unquoted.to_owned()))
            }
            None => (text.trim(), None),
        };
        if let Some(name) = subject.strip_prefix('@') {
            return (!name.is_empty()).then(|| Self::Attribute {
                name: name.to_owned(),
                value,
            });
        }
        NameTest::parse(subject).map(|test| Self::Child { test, value })
    }

    fn holds(&self, element: &Element) -> bool {
        match self {
            Self::Index(_) => true,
            Self::Attribute { name, value } => element
                .attribute(name)
                .is_some_and(|actual| value.as_deref().is_none_or(|expected| expected == actual)),
            Self::Child { test, value } => element.elements().any(|child| {
                test.matches(child) && value.as_deref().is_none_or(|expected| child.text().trim() == expected)
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    descendant: bool,
    test: NameTest,
    predicate: Option<Predicate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Terminal {
    Text,
    Attribute(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Path {
    steps: Vec<Step>,
    terminal: Option<Terminal>,
}

impl Path {
    fn error(path: &str, reason: &str) -> XmlError {
        XmlError::Path {
            path: path.to_owned(),
            reason: reason.to_owned(),
        }
    }

    /// Splits `path` into segments at `/` and `//`, ignoring slashes inside `{...}` and `[...]`.
    fn segments(path: &str) -> Result<Vec<(bool, String)>, XmlError> {
        let mut segments = Vec::new();
        let mut current = String::new();
        let mut descendant = false;
        let mut braces = 0_usize;
        let mut brackets = 0_usize;
        let mut quote: Option<char> = None;
        let mut chars = path.chars().peekable();
        if chars.peek() != Some(&'/') {
            return Err(Self::error(path, "a path starts with `/`"));
        }
        let mut pending = false;
        while let Some(c) = chars.next() {
            match c {
                '/' if braces == 0 && brackets == 0 && quote.is_none() => {
                    if pending {
                        if current.is_empty() {
                            return Err(Self::error(path, "an empty step"));
                        }
                        segments.push((descendant, core::mem::take(&mut current)));
                    }
                    descendant = chars.peek() == Some(&'/');
                    if descendant {
                        chars.next();
                    }
                    pending = true;
                }
                '{' if quote.is_none() => {
                    braces += 1;
                    current.push(c);
                }
                '}' if quote.is_none() => {
                    braces = braces.saturating_sub(1);
                    current.push(c);
                }
                '[' if braces == 0 && quote.is_none() => {
                    brackets += 1;
                    current.push(c);
                }
                ']' if braces == 0 && quote.is_none() => {
                    brackets = brackets.saturating_sub(1);
                    current.push(c);
                }
                '"' | '\'' if brackets > 0 => {
                    match quote {
                        Some(open) if open == c => quote = None,
                        None => quote = Some(c),
                        Some(_) => {}
                    }
                    current.push(c);
                }
                other => current.push(other),
            }
        }
        if braces != 0 || brackets != 0 || quote.is_some() {
            return Err(Self::error(path, "unbalanced `{`, `[` or quote"));
        }
        if current.is_empty() {
            return Err(Self::error(path, "the path ends with `/`"));
        }
        segments.push((descendant, current));
        Ok(segments)
    }

    fn compile(path: &str) -> Result<Self, XmlError> {
        let mut segments = Self::segments(path)?;
        let terminal = match segments.last() {
            Some((false, last)) if last == "text()" => Some(Terminal::Text),
            Some((false, last)) => last.strip_prefix('@').map(|name| Terminal::Attribute(name.to_owned())),
            _ => None,
        };
        if terminal.is_some() {
            segments.pop();
        }
        if segments.is_empty() {
            return Err(Self::error(path, "a terminal needs an element before it"));
        }
        let mut steps = Vec::new();
        for (descendant, segment) in segments {
            let (name, predicate) = match segment.find('[') {
                Some(open) => {
                    let inner = segment
                        .get(open + 1..)
                        .and_then(|rest| rest.strip_suffix(']'))
                        .ok_or_else(|| Self::error(path, "a predicate must end with `]`"))?;
                    let predicate =
                        Predicate::parse(inner).ok_or_else(|| Self::error(path, "the predicate is not understood"))?;
                    (segment.get(..open).unwrap_or(""), Some(predicate))
                }
                None => (segment.as_str(), None),
            };
            let test = NameTest::parse(name).ok_or_else(|| Self::error(path, "the name test is not understood"))?;
            steps.push(Step {
                descendant,
                test,
                predicate,
            });
        }
        Ok(Self { steps, terminal })
    }

    fn evaluate(&self, root: &Element) -> Vec<String> {
        let mut context: Vec<&Element> = Vec::new();
        for (position, step) in self.steps.iter().enumerate() {
            let mut next: Vec<&Element> = Vec::new();
            if position == 0 {
                // The virtual document node has the root as its only child.
                let mut candidates = Vec::new();
                if step.descendant {
                    descendants(root, true, &mut candidates);
                } else {
                    candidates.push(root);
                }
                next.extend(apply(step, candidates));
            } else {
                for parent in context.iter().copied() {
                    let mut candidates = Vec::new();
                    if step.descendant {
                        descendants(parent, false, &mut candidates);
                    } else {
                        candidates.extend(parent.elements());
                    }
                    next.extend(apply(step, candidates));
                }
            }
            context = next;
        }
        match &self.terminal {
            None | Some(Terminal::Text) => context.iter().map(|element| element.text()).collect(),
            Some(Terminal::Attribute(name)) => context
                .iter()
                .filter_map(|element| element.attribute(name).map(str::to_owned))
                .collect(),
        }
    }
}

/// Collects the descendants of `element` in document order (and `element` itself when `include_self`).
fn descendants<'a>(element: &'a Element, include_self: bool, out: &mut Vec<&'a Element>) {
    if include_self {
        out.push(element);
    }
    for child in element.elements() {
        descendants(child, true, out);
    }
}

/// Keeps the candidates the step's name test and predicate select.
fn apply<'a>(step: &Step, candidates: Vec<&'a Element>) -> Vec<&'a Element> {
    let named: Vec<&Element> = candidates
        .into_iter()
        .filter(|element| step.test.matches(element))
        .collect();
    match &step.predicate {
        None => named,
        Some(Predicate::Index(index)) => named.get(index.saturating_sub(1)).copied().into_iter().collect(),
        Some(predicate) => named.into_iter().filter(|element| predicate.holds(element)).collect(),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Multi-Status
// ---------------------------------------------------------------------------------------------------------------

/// One `DAV:propstat` of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Propstat {
    /// The status code of the `DAV:status` line.
    pub status: u16,
    /// The properties with their text, in Clark notation.
    pub properties: Vec<(String, String)>,
}

/// One `DAV:response` of a multistatus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultistatusEntry {
    /// The `DAV:href` (as sent, still percent-encoded).
    pub href: String,
    /// The status of the response itself (sync-collection and DELETE results), if it has one.
    pub status: Option<u16>,
    /// The property results.
    pub propstats: Vec<Propstat>,
}

impl MultistatusEntry {
    /// Whether the property is present with a 2xx status; returns its text.
    pub fn property(&self, name: &str) -> Option<&str> {
        self.propstats
            .iter()
            .filter(|propstat| (200..300).contains(&propstat.status))
            .flat_map(|propstat| propstat.properties.iter())
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    /// Whether `status` is the status of the response or of one of its propstats.
    pub fn has_status(&self, status: u16) -> bool {
        self.status == Some(status) || self.propstats.iter().any(|propstat| propstat.status == status)
    }
}

/// The code of a status line such as `HTTP/1.1 200 OK`.
fn status_code(line: &str) -> Option<u16> {
    line.split_whitespace().nth(1)?.parse().ok()
}

impl Document {
    /// The responses of a `DAV:multistatus` document.
    ///
    /// # Errors
    ///
    /// [`XmlError::Malformed`] when the root is not `{DAV:}multistatus` or a response lacks its `href` or has an
    /// unreadable status line.
    pub fn multistatus(&self) -> Result<Vec<MultistatusEntry>, XmlError> {
        const DAV: &str = "DAV:";
        let is = |element: &Element, local: &str| element.namespace == DAV && element.local == local;
        if !is(&self.root, "multistatus") {
            return Err(XmlError::Malformed(format!(
                "the root is {}, not {{DAV:}}multistatus",
                self.root.clark()
            )));
        }
        let mut entries = Vec::new();
        for response in self.root.elements().filter(|element| is(element, "response")) {
            let href = response
                .elements()
                .find(|element| is(element, "href"))
                .map(|element| element.text().trim().to_owned())
                .ok_or_else(|| XmlError::Malformed("a response has no href".to_owned()))?;
            let parse_status = |element: &Element| {
                status_code(element.text().trim())
                    .ok_or_else(|| XmlError::Malformed(format!("`{}` is not a status line", element.text().trim())))
            };
            let status = response
                .elements()
                .find(|element| is(element, "status"))
                .map(parse_status)
                .transpose()?;
            let mut propstats = Vec::new();
            for propstat in response.elements().filter(|element| is(element, "propstat")) {
                let status = propstat
                    .elements()
                    .find(|element| is(element, "status"))
                    .map(parse_status)
                    .transpose()?
                    .ok_or_else(|| XmlError::Malformed("a propstat has no status".to_owned()))?;
                let properties = propstat
                    .elements()
                    .filter(|element| is(element, "prop"))
                    .flat_map(Element::elements)
                    .map(|property| (property.clark(), property.text()))
                    .collect();
                propstats.push(Propstat { status, properties });
            }
            entries.push(MultistatusEntry {
                href,
                status,
                propstats,
            });
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTISTATUS: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<!-- a comment -->
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/">
  <D:response>
    <D:href>/dav/calendars/acme/olivia/personal/</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>Personal &amp; more</D:displayname>
        <CS:getctag>urn:davhaven:sync:1:2:3</CS:getctag>
        <D:resourcetype><D:collection/><C:calendar/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
    <D:propstat>
      <D:prop><C:calendar-description/></D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/calendars/acme/olivia/personal/gone.ics</D:href>
    <D:status>HTTP/1.1 404 Not Found</D:status>
  </D:response>
</D:multistatus>"#;

    fn document() -> Document {
        Document::parse(MULTISTATUS).unwrap()
    }

    #[test]
    fn documents_parse_with_namespaces_text_and_entities() {
        let document = document();
        assert_eq!(document.root.clark(), "{DAV:}multistatus");
        let first = document.root.elements().next().unwrap();
        assert_eq!(first.clark(), "{DAV:}response");
        assert_eq!(
            document
                .select("/{DAV:}multistatus/{DAV:}response/{DAV:}propstat/{DAV:}prop/{DAV:}displayname")
                .unwrap(),
            vec!["Personal & more".to_owned()]
        );
        let cdata = Document::parse("<a><![CDATA[<b> & ]]>x&#65;&#x42;</a>").unwrap();
        assert_eq!(cdata.root.text(), "<b> & xAB");
        let attributes = Document::parse(r#"<a xmlns:x="urn:x" b='1' x:c="2"/>"#).unwrap();
        assert_eq!(attributes.root.attribute("b"), Some("1"));
        assert_eq!(attributes.root.attribute("{urn:x}c"), Some("2"));
        let defaulted = Document::parse(r#"<a xmlns="urn:d"><b/><c xmlns=""/></a>"#).unwrap();
        let names: Vec<String> = defaulted.root.elements().map(Element::clark).collect();
        assert_eq!(names, vec!["{urn:d}b".to_owned(), "c".to_owned()]);
    }

    #[test]
    fn malformed_documents_are_rejected() {
        for broken in [
            "",
            "<a>",
            "<a></b>",
            "<a b=1/>",
            "<a b='1/>",
            "<a>&nope;</a>",
            "<a>&amp</a>",
            "<p:a/>",
            "<a/><b/>",
            "<a><!DOC></a>",
            "text",
            "<a b></a>",
        ] {
            assert!(
                matches!(Document::parse(broken), Err(XmlError::Malformed(_))),
                "{broken}"
            );
        }
        assert_eq!(Document::parse("<!DOCTYPE a><a/>"), Err(XmlError::Doctype));
        let deep = format!("{}{}", "<a>".repeat(70), "</a>".repeat(70));
        assert_eq!(Document::parse(&deep), Err(XmlError::TooDeep));
        assert!(Document::parse("\u{feff}<a/>").is_ok(), "a byte order mark is skipped");
    }

    #[test]
    fn paths_select_elements_texts_and_attributes() {
        let document = document();
        let count = |path: &str| document.count(path).unwrap();
        assert_eq!(count("/{DAV:}multistatus/{DAV:}response"), 2);
        assert_eq!(count("//{DAV:}href"), 2);
        assert_eq!(count("//{DAV:}status"), 3);
        assert_eq!(count("/{DAV:}multistatus/*/{DAV:}href"), 2);
        assert_eq!(count("/{DAV:}multistatus/{DAV:}response[1]/{DAV:}href"), 1);
        assert_eq!(count("/{DAV:}multistatus/{DAV:}response[3]"), 0);
        assert_eq!(
            count("/{DAV:}multistatus/response"),
            0,
            "a bare name is in no namespace"
        );
        assert_eq!(count("//{DAV:}resourcetype/{DAV:}collection"), 1);
        assert_eq!(
            document
                .select("/{DAV:}multistatus/{DAV:}response[2]/{DAV:}href/text()")
                .unwrap(),
            vec!["/dav/calendars/acme/olivia/personal/gone.ics".to_owned()]
        );
        assert_eq!(
            document
                .select("//{DAV:}response[{DAV:}status='HTTP/1.1 404 Not Found']/{DAV:}href")
                .unwrap(),
            vec!["/dav/calendars/acme/olivia/personal/gone.ics".to_owned()]
        );
        assert_eq!(count("//{DAV:}response[{DAV:}status]"), 1);
        assert_eq!(count("//{DAV:}response[{DAV:}href='/nowhere']"), 0);

        let attributes = Document::parse(r#"<r><i id="a" k="1"/><i id="b"/><i/></r>"#).unwrap();
        assert_eq!(
            attributes.select("/r/i/@id").unwrap(),
            vec!["a".to_owned(), "b".to_owned()]
        );
        assert_eq!(attributes.count("/r/i[@id]").unwrap(), 2);
        assert_eq!(attributes.count("/r/i[@id='b']").unwrap(), 1);
        assert_eq!(attributes.count("/r/i[@id=\"zzz\"]").unwrap(), 0);
        assert_eq!(attributes.count("/r/i[2]").unwrap(), 1);
        assert_eq!(attributes.count("//i").unwrap(), 3);
        assert_eq!(attributes.count("//r").unwrap(), 1, "// includes the root");
    }

    #[test]
    fn invalid_paths_are_rejected_with_a_reason() {
        let document = document();
        for path in [
            "",
            "{DAV:}multistatus",
            "/",
            "/{DAV:}multistatus/",
            "/{DAV:}multistatus//",
            "/a[0]",
            "/a[",
            "/a[@]",
            "/{DAV:",
            "/text()",
            "/a[@x='1]",
            "/{}a",
        ] {
            assert!(matches!(document.select(path), Err(XmlError::Path { .. })), "{path}");
        }
    }

    #[test]
    fn multistatus_responses_are_summarised() {
        let entries = document().multistatus().unwrap();
        assert_eq!(entries.len(), 2);
        let personal = &entries[0];
        assert_eq!(personal.href, "/dav/calendars/acme/olivia/personal/");
        assert_eq!(personal.status, None);
        assert_eq!(personal.property("{DAV:}displayname"), Some("Personal & more"));
        assert_eq!(
            personal.property("{http://calendarserver.org/ns/}getctag"),
            Some("urn:davhaven:sync:1:2:3")
        );
        assert_eq!(
            personal.property("{urn:ietf:params:xml:ns:caldav}calendar-description"),
            None,
            "404 propstat"
        );
        assert!(personal.has_status(404) && personal.has_status(200) && !personal.has_status(403));
        let gone = &entries[1];
        assert_eq!(gone.status, Some(404));
        assert!(gone.propstats.is_empty() && gone.has_status(404));
        assert!(Document::parse("<a/>").unwrap().multistatus().is_err());
        let no_href = Document::parse(r#"<D:multistatus xmlns:D="DAV:"><D:response/></D:multistatus>"#).unwrap();
        assert!(no_href.multistatus().is_err());
        let bad_status = Document::parse(
            r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>/x</D:href><D:status>nope</D:status></D:response></D:multistatus>"#,
        )
        .unwrap();
        assert!(bad_status.multistatus().is_err());
    }
}
