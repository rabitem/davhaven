//! Properties (PLAN 3.1, L1): the XML reader never panics, the stored form of a dead property reads back
//! unchanged, and the sync protocol keeps a replica equal to the server under any sequence of writes and
//! (possibly truncated) syncs.

use std::collections::BTreeMap;

use davhaven_dav::xml::write::{escape_text, serialize_content};
use davhaven_dav::xml::{Attribute, Element, NS_XML, Namespace, Node, parse};
use davhaven_domain::DavLimits;
use proptest::prelude::*;

use crate::support::{Dav, NS, Req, WORK, event};

// -------------------------------------------------------------------------------------------------------------
// The XML reader
// -------------------------------------------------------------------------------------------------------------

/// Pieces of markup that, put together at random, give the reader every kind of malformed document.
fn markup_piece() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("<a>"),
        Just("</a>"),
        Just("<b/>"),
        Just("<D:x xmlns:D=\"DAV:\">"),
        Just("</D:x>"),
        Just("<c d='1' e=\"2\">"),
        Just("<c d='1' d='2'/>"),
        Just("text"),
        Just("&amp;"),
        Just("&#x41;"),
        Just("&#0;"),
        Just("&bogus;"),
        Just("&"),
        Just("<![CDATA[x]]>"),
        Just("<![CDATA["),
        Just("<!--c-->"),
        Just("<!-- -- -->"),
        Just("<?pi x?>"),
        Just("<?xml version=\"1.0\" encoding=\"utf-8\"?>"),
        Just("<!DOCTYPE a>"),
        Just("<"),
        Just(">"),
        Just("\u{1}"),
        Just("\u{feff}"),
        Just("xmlns:p=\"u\""),
        Just("<p:q/>"),
    ]
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_the_xml_reader(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = parse(&bytes, &DavLimits::default());
    }

    #[test]
    fn markup_soup_never_panics_the_xml_reader(pieces in proptest::collection::vec(markup_piece(), 0..40)) {
        let text: String = pieces.concat();
        let _ = parse(text.as_bytes(), &DavLimits::default());
    }

    #[test]
    fn arbitrary_text_never_panics_the_xml_reader(text in "[<>/!?&;#a-zA-Z0-9:=\"' \\n-]{0,300}") {
        let _ = parse(text.as_bytes(), &DavLimits::default());
    }
}

// -------------------------------------------------------------------------------------------------------------
// The stored form of dead properties
// -------------------------------------------------------------------------------------------------------------

fn local_name() -> impl Strategy<Value = String> {
    prop_oneof![Just("a"), Just("b"), Just("item"), Just("x-y"), Just("note.v2")].prop_map(str::to_owned)
}

fn namespace() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(""),
        Just("urn:a"),
        Just("urn:b"),
        Just("DAV:"),
        Just("urn:a&b<c>\"d'e")
    ]
    .prop_map(str::to_owned)
}

fn attribute() -> impl Strategy<Value = Attribute> {
    (
        prop_oneof![
            Just(""),
            Just("urn:a"),
            Just("urn:b"),
            Just("urn:a&b<c>\"d'e"),
            Just(NS_XML)
        ],
        prop_oneof![Just("p"), Just("q"), Just("lang")],
        "[a-z0-9 <>&\"'\u{e4}\u{65e5}\\n\\t\\r]{0,8}",
    )
        .prop_map(|(namespace, local, value)| Attribute {
            namespace: Namespace::from(namespace),
            local: local.to_owned(),
            value,
        })
}

fn text() -> impl Strategy<Value = String> {
    "[a-z0-9 <>&\"'\u{e4}\u{f6}\u{65e5}\\n\\t\\r]{1,10}"
}

/// Random elements up to four levels deep.
fn element() -> impl Strategy<Value = Element> {
    let leaf = (namespace(), local_name(), proptest::collection::vec(attribute(), 0..3)).prop_map(
        |(namespace, local, attributes)| Element {
            namespace: Namespace::from(namespace),
            local,
            attributes: unique(attributes),
            children: Vec::new(),
        },
    );
    leaf.prop_recursive(4, 24, 4, |inner| {
        (
            namespace(),
            local_name(),
            proptest::collection::vec(attribute(), 0..3),
            proptest::collection::vec(
                prop_oneof![text().prop_map(Node::Text), inner.prop_map(Node::Element)],
                0..4,
            ),
        )
            .prop_map(|(namespace, local, attributes, children)| Element {
                namespace: Namespace::from(namespace),
                local,
                attributes: unique(attributes),
                children: merge_text(children),
            })
    })
}

/// An element has at most one attribute of a name.
fn unique(attributes: Vec<Attribute>) -> Vec<Attribute> {
    let mut kept: Vec<Attribute> = Vec::new();
    for attribute in attributes {
        if !kept
            .iter()
            .any(|other| other.namespace == attribute.namespace && other.local == attribute.local)
        {
            kept.push(attribute);
        }
    }
    kept
}

/// Adjacent text nodes are one node when read back.
fn merge_text(children: Vec<Node>) -> Vec<Node> {
    let mut merged: Vec<Node> = Vec::new();
    for child in children {
        match (merged.last_mut(), child) {
            (Some(Node::Text(existing)), Node::Text(next)) => existing.push_str(&next),
            (_, child) => merged.push(child),
        }
    }
    merged
}

proptest! {
    #[test]
    fn what_is_stored_for_a_dead_property_reads_back_unchanged(
        children in proptest::collection::vec(prop_oneof![text().prop_map(Node::Text), element().prop_map(Node::Element)], 0..4)
    ) {
        let children = merge_text(children);
        let mut holder = Element::new("urn:holder", "holder");
        holder.children = children.clone();
        let stored = serialize_content(&holder);
        let wrapped = format!("<holder xmlns=\"urn:holder\">{stored}</holder>");
        let parsed = parse(wrapped.as_bytes(), &DavLimits::default());
        prop_assert!(parsed.is_ok(), "{stored}: {parsed:?}");
        prop_assert_eq!(parsed.unwrap().children, children, "{}", stored);
    }
}

// -------------------------------------------------------------------------------------------------------------
// The sync state machine
// -------------------------------------------------------------------------------------------------------------

const NAMES: [&str; 4] = ["a", "b", "c", "d"];

#[derive(Debug, Clone)]
enum Op {
    Put(usize),
    Delete(usize),
    /// A synchronization of the replica, with an optional limit per answer.
    Sync(Option<u32>),
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    proptest::collection::vec(
        prop_oneof![
            (0..NAMES.len()).prop_map(Op::Put),
            (0..NAMES.len()).prop_map(Op::Delete),
            proptest::option::of(1u32..4).prop_map(Op::Sync),
        ],
        1..30,
    )
}

/// Runs the operations against the server and a client replica that is driven by `sync-collection` only, and
/// checks after every complete synchronization that the replica equals the server.
async fn replicate(ops: Vec<Op>) -> Result<(), String> {
    let dav = Dav::new();
    let mut server: BTreeMap<String, String> = BTreeMap::new();
    let mut replica: BTreeMap<String, String> = BTreeMap::new();
    // The seeded event is part of the server from the start.
    server.insert(
        "standup.ics".to_owned(),
        davhaven_domain::ETag::from_bytes(davhaven_app_fake::seed::STANDUP_ICS.as_bytes())
            .as_str()
            .to_owned(),
    );
    let mut token = String::new();
    let mut version = 0u32;
    let mut all = ops;
    all.push(Op::Sync(None));
    for op in all {
        match op {
            Op::Put(index) => {
                version += 1;
                let stem = NAMES.get(index).copied().unwrap();
                let name = format!("{stem}.ics");
                let uid = format!("{stem}-1@acme.example");
                let answer = dav
                    .send(Req::anna("PUT", &format!("{WORK}{name}")).ics(&event(&uid, &format!("version {version}"))))
                    .await;
                if !matches!(answer.status.as_u16(), 201 | 204) {
                    return Err(format!("PUT {name}: {} {}", answer.status, answer.body));
                }
                server.insert(name, answer.header("etag").to_owned());
            }
            Op::Delete(index) => {
                let name = format!("{}.ics", NAMES.get(index).copied().unwrap());
                let answer = dav.send(Req::anna("DELETE", &format!("{WORK}{name}"))).await;
                let expected = if server.remove(&name).is_some() { 204 } else { 404 };
                if answer.status.as_u16() != expected {
                    return Err(format!("DELETE {name}: {} instead of {expected}", answer.status));
                }
            }
            Op::Sync(limit) => loop {
                let limit = limit.map_or_else(String::new, |n| {
                    format!("<D:limit><D:nresults>{n}</D:nresults></D:limit>")
                });
                let body = format!(
                    "<D:sync-collection {NS}><D:sync-token>{token}</D:sync-token><D:sync-level>1</D:sync-level>{limit}\
                     <D:prop><D:getetag/></D:prop></D:sync-collection>"
                );
                let answer = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
                if answer.status.as_u16() != 207 {
                    return Err(format!("sync: {} {}", answer.status, answer.body));
                }
                let multi = answer.multistatus();
                let mut truncated = false;
                for response in &multi.responses {
                    if response.href == WORK {
                        truncated |= response.status == Some(507);
                        continue;
                    }
                    let name = response.href.rsplit('/').next().unwrap_or_default().to_owned();
                    match response.status {
                        Some(404) => {
                            replica.remove(&name);
                        }
                        _ => {
                            replica.insert(name, response.text(crate::support::NS_DAV, "getetag"));
                        }
                    }
                }
                token = multi.sync_token.ok_or("an answer without a token")?;
                if !truncated {
                    break;
                }
            },
        }
        if matches!(op, Op::Sync(_)) && replica != server {
            return Err(format!(
                "replica {replica:?} differs from server {server:?} (ops so far)"
            ));
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn a_replica_that_follows_the_sync_protocol_equals_the_server(ops in ops()) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let outcome = runtime.block_on(replicate(ops.clone()));
        prop_assert!(outcome.is_ok(), "{:?}: {:?}", ops, outcome);
    }
}

// -------------------------------------------------------------------------------------------------------------
// The XML writer
// -------------------------------------------------------------------------------------------------------------

/// What the writer makes of a character: itself, or U+FFFD for what XML 1.0 cannot hold.
fn representable(c: char) -> char {
    if matches!(c, '\t' | '\n' | '\r' | ' '..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}') {
        c
    } else {
        '\u{fffd}'
    }
}

proptest! {
    #[test]
    fn any_text_the_server_writes_reads_back_as_written(text in any::<String>()) {
        let expected: String = text.chars().map(representable).collect();
        let element = format!("<a>{}</a>", escape_text(&text));
        let parsed = parse(element.as_bytes(), &DavLimits::default());
        prop_assert!(parsed.is_ok(), "{element:?}: {parsed:?}");
        prop_assert_eq!(parsed.unwrap().text(), expected);
    }
}
