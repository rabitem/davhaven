//! The readers of the collaboration modules: share requests, invitation replies and the two principal searches.
//!
//! Whatever a client sends is read or refused, never a panic. A share request that is accepted must also survive
//! being written down again: the sharees, their access, names and summaries read back as they were read.

#![no_main]

use davhaven_dav::principals_search::{parse_property_search, parse_token_search};
use davhaven_dav::sharing::{parse_invite_reply, parse_share, shared_as_document};
use davhaven_dav::xml::parse;
use davhaven_dav::xml::write::escape_text;
use davhaven_domain::{DavLimits, GrantAccess, ResourcePath};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = DavLimits::default();
    let Ok(root) = parse(data, &limits) else {
        return;
    };
    let _ = parse_invite_reply(&root);
    let _ = parse_property_search(&root, &limits);
    let _ = parse_token_search(&root, &limits);

    let Ok(document) = parse_share(&root) else {
        return;
    };
    let request = &document.request;
    let mut written = String::from("<CS:share xmlns:D=\"DAV:\" xmlns:CS=\"http://calendarserver.org/ns/\">");
    for sharee in &request.set {
        written.push_str("<CS:set><D:href>");
        written.push_str(&escape_text(sharee.address.as_str()));
        written.push_str("</D:href>");
        if let Some(name) = &sharee.common_name {
            written.push_str(&format!("<CS:common-name>{}</CS:common-name>", escape_text(name)));
        }
        if let Some(summary) = &sharee.summary {
            written.push_str(&format!("<CS:summary>{}</CS:summary>", escape_text(summary)));
        }
        written.push_str(match sharee.access {
            GrantAccess::Read => "<CS:read/>",
            _ => "<CS:read-write/>",
        });
        written.push_str("</CS:set>");
    }
    for address in &request.remove {
        written.push_str(&format!(
            "<CS:remove><D:href>{}</D:href></CS:remove>",
            escape_text(address.as_str())
        ));
    }
    written.push_str("</CS:share>");
    let again = parse(written.as_bytes(), &limits).expect("a request the server wrote parses");
    let reread = parse_share(&again).expect("a request the server wrote is a request");
    assert_eq!(reread.request, document.request, "writing a share request down changes it");

    // The answer to an acceptance names a collection and reads back as that collection.
    if let Ok(path) = ResourcePath::parse("/dav/calendars/acme/ben/shared/") {
        let document = shared_as_document(&path);
        assert!(parse(document.as_bytes(), &limits).is_ok(), "the answer to an acceptance does not parse");
    }
});
