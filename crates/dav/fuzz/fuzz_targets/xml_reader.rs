//! The front door of every DAV request with a body: the XML reader and the typed request readers behind it.
//!
//! Whatever a client sends is read or refused, never a panic. A document that is accepted must also survive the
//! way dead properties are kept: the stored form of its content, written back inside another element, reads
//! as the same tree.

#![no_main]

use davhaven_dav::props::interpret;
use davhaven_dav::xml::reports::{
    parse_calendar_query, parse_expand_property, parse_free_busy_query, parse_multiget, parse_sync_collection,
};
use davhaven_dav::xml::requests::{
    MakeKind, parse_make_collection, parse_propertyupdate, parse_propfind, prop_request,
};
use davhaven_dav::xml::parse;
use davhaven_dav::xml::write::{Multistatus, Prefixes, Propstat, XmlWriter, serialize_content};
use davhaven_domain::{DavLimits, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = DavLimits::default();
    let everything = Limits::default();
    let _ = parse_propfind(data, &limits);
    let _ = parse_make_collection(data, &limits, MakeKind::MkCalendar);
    let _ = parse_make_collection(data, &limits, MakeKind::ExtendedMkcol);
    let Ok(root) = parse(data, &limits) else {
        return;
    };
    if let Ok(request) = prop_request(&root) {
        // What the server writes for a request it accepted is a document it can read again: the names go through
        // the writer, and the namespaces through the prefixes declared once on the root.
        let prefixes = Prefixes::of(request.names().iter().map(|name| name.namespace.as_str()), 64);
        let mut properties = XmlWriter::with_prefixes(&prefixes);
        for name in request.names() {
            properties.empty(&name.namespace, &name.local);
        }
        let mut multistatus = Multistatus::with_prefixes(&prefixes);
        multistatus.response("/x", &[Propstat::found(properties.into_string())]);
        let answer = multistatus.finish();
        // A request declares its namespaces on the elements that use them, the answer declares all of them once on its root:
        // the reader needs room for that many declarations (it counts them as attributes of the element) and for the elements
        // the answer adds to the request's.
        let wide = DavLimits {
            max_xml_namespaces: 128,
            max_xml_attributes: 128,
            max_xml_elements: limits.max_xml_elements + 16,
            ..limits.clone()
        };
        assert!(parse(answer.as_bytes(), &wide).is_ok(), "the answer to an accepted request does not parse");
    }
    let _ = parse_calendar_query(&root);
    let _ = parse_multiget(&root);
    let _ = parse_sync_collection(&root);
    let _ = parse_expand_property(&root);
    let _ = parse_free_busy_query(&root);
    if let Ok(updates) = parse_propertyupdate(&root) {
        for update in &updates {
            let _ = interpret(update, &everything);
        }
    }

    // A stored value declares the namespace of every element and of every namespaced attribute itself, and the
    // holder adds a namespace of its own: the second read has room for the difference.
    let stored = serialize_content(&root);
    let roomy = DavLimits {
        max_xml_depth: limits.max_xml_depth + 2,
        max_xml_elements: limits.max_xml_elements + 2,
        max_xml_attributes: limits.max_xml_attributes * 3,
        max_xml_namespaces: limits.max_xml_namespaces + 2,
        ..limits
    };
    let wrapped = format!("<holder xmlns=\"urn:holder\">{stored}</holder>");
    let again = parse(wrapped.as_bytes(), &roomy).expect("the stored form of a value parses");
    assert_eq!(again.children, root.children, "the stored form changes the value");
});
