//! The object methods: PUT, GET, HEAD, DELETE, MOVE and COPY with their preconditions, and what the services
//! report for bad data.

use axum::http::StatusCode;
use davhaven_domain::ETag;

use crate::support::{Dav, NS, PERSONAL, Req, STANDUP, STANDUP_ICS, User, WORK, event, propfind, todo};

const NEW: &str = "/dav/calendars/acme/anna/work/new.ics";

fn etag_of(text: &str) -> String {
    ETag::from_bytes(text.as_bytes()).as_str().to_owned()
}

/// An event of exactly `size` bytes.
fn padded(size: usize) -> String {
    let base = event("pad-1@acme.example", "Padded");
    let marker = "END:VEVENT\r\n";
    let (before, after) = base.split_once(marker).unwrap();
    let need = size - base.len() - "X-PAD:".len() - 2;
    format!("{before}X-PAD:{}\r\n{marker}{after}", "a".repeat(need))
}

#[tokio::test]
async fn a_new_object_is_created_and_read_back_byte_for_byte() {
    let dav = Dav::new();
    let body = event("new-1@acme.example", "New \u{e4}\u{f6}\u{fc}");
    let created = dav
        .send(Req::anna("PUT", NEW).ics(&body).header("if-none-match", "*"))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body, "");
    assert_eq!(
        created.header("etag"),
        etag_of(&body),
        "the tag of the bytes the client sent"
    );

    let read = dav.send(Req::anna("GET", NEW)).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body, body, "stored verbatim, CRLF included");
    assert_eq!(read.header("etag"), etag_of(&body));
    assert_eq!(
        read.header("content-type"),
        "text/calendar; charset=utf-8; component=vevent"
    );
    assert!(
        read.header("last-modified").ends_with(" GMT"),
        "{}",
        read.header("last-modified")
    );
    assert_eq!(read.header("cache-control"), "private, no-cache");
}

#[tokio::test]
async fn replacing_an_object_answers_204_with_the_new_tag() {
    let dav = Dav::new();
    let before = dav.put_event(NEW, "new-1@acme.example", "First").await;
    let second = event("new-1@acme.example", "Second");
    let answer = dav.send(Req::anna("PUT", NEW).ics(&second)).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    assert_eq!(answer.header("etag"), etag_of(&second));
    assert_ne!(answer.header("etag"), before);
    assert_eq!(dav.send(Req::anna("GET", NEW)).await.body, second);
}

#[tokio::test]
async fn if_none_match_star_protects_existing_objects() {
    let dav = Dav::new();
    let answer = dav
        .send(
            Req::anna("PUT", STANDUP)
                .ics(&event("other@acme.example", "Overwrite"))
                .header("if-none-match", "*"),
        )
        .await;
    assert_eq!(answer.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        dav.send(Req::anna("GET", STANDUP)).await.body,
        STANDUP_ICS,
        "nothing changed"
    );
}

#[tokio::test]
async fn if_match_guards_updates() {
    let dav = Dav::new();
    let current = etag_of(STANDUP_ICS);
    let update = event("standup-1@acme.example", "Moved");
    let stale = dav
        .send(
            Req::anna("PUT", STANDUP)
                .ics(&update)
                .header("if-match", &etag_of("stale")),
        )
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let weak = dav
        .send(
            Req::anna("PUT", STANDUP)
                .ics(&update)
                .header("if-match", &format!("W/{current}")),
        )
        .await;
    assert_eq!(
        weak.status,
        StatusCode::PRECONDITION_FAILED,
        "a weak tag never satisfies If-Match"
    );
    let foreign = dav
        .send(
            Req::anna("PUT", STANDUP)
                .ics(&update)
                .header("if-match", "\"not-ours\""),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::PRECONDITION_FAILED);
    let missing = dav
        .send(Req::anna("PUT", NEW).ics(&update).header("if-match", "*"))
        .await;
    assert_eq!(
        missing.status,
        StatusCode::PRECONDITION_FAILED,
        "If-Match: * needs an existing object"
    );

    let listed = format!("{}, {current}", etag_of("other"));
    let accepted = dav
        .send(Req::anna("PUT", STANDUP).ics(&update).header("if-match", &listed))
        .await;
    assert_eq!(accepted.status, StatusCode::NO_CONTENT, "{}", accepted.body);
    assert_eq!(accepted.header("etag"), etag_of(&update));
}

#[tokio::test]
async fn a_uid_that_is_taken_names_the_object_that_holds_it() {
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("PUT", NEW).ics(&event("standup-1@acme.example", "Same uid")))
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.precondition().as_deref(), Some("no-uid-conflict"));
    assert_eq!(answer.precondition_href().as_deref(), Some(STANDUP));
    assert_eq!(answer.header("content-type"), "application/xml; charset=utf-8");
}

#[tokio::test]
async fn bad_data_is_refused_with_the_matching_calendar_precondition() {
    let dav = Dav::new();
    let garbage = dav.send(Req::anna("PUT", NEW).ics("this is not a calendar")).await;
    assert_eq!(garbage.status, StatusCode::FORBIDDEN);
    assert_eq!(garbage.precondition().as_deref(), Some("valid-calendar-data"));

    let binary = dav
        .send(
            Req::anna("PUT", NEW)
                .header("content-type", "text/calendar")
                .bytes(vec![0xff, 0xfe, 0x00, 0x42]),
        )
        .await;
    assert_eq!(binary.status, StatusCode::FORBIDDEN);
    assert_eq!(
        binary.precondition().as_deref(),
        Some("valid-calendar-data"),
        "calendar data is UTF-8"
    );

    let empty = dav.send(Req::anna("PUT", NEW).ics("")).await;
    assert_eq!(empty.precondition().as_deref(), Some("valid-calendar-data"));
}

#[tokio::test]
async fn a_calendar_refuses_components_it_does_not_accept() {
    let dav = Dav::new();
    let mkcalendar = "<C:mkcalendar xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:set><D:prop>\
         <C:supported-calendar-component-set><C:comp name=\"VEVENT\"/></C:supported-calendar-component-set>\
         </D:prop></D:set></C:mkcalendar>";
    let created = dav
        .send(Req::anna("MKCALENDAR", "/dav/calendars/acme/anna/events-only/").xml(mkcalendar))
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let answer = dav
        .send(
            Req::anna("PUT", "/dav/calendars/acme/anna/events-only/task.ics").ics(&todo("task-1@acme.example", "Task")),
        )
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.precondition().as_deref(), Some("supported-calendar-component"));
    let accepted = dav
        .send(Req::anna("PUT", "/dav/calendars/acme/anna/events-only/e.ics").ics(&event("e-1@acme.example", "Event")))
        .await;
    assert_eq!(accepted.status, StatusCode::CREATED);
}

#[tokio::test]
async fn objects_may_be_as_large_as_the_limit_and_no_larger() {
    let dav = Dav::new();
    let limit = 1024 * 1024;
    let exact = padded(limit);
    assert_eq!(exact.len(), limit);
    let accepted = dav.send(Req::anna("PUT", NEW).ics(&exact)).await;
    assert_eq!(accepted.status, StatusCode::CREATED, "{}", accepted.body);

    let over = padded(limit + 1);
    let declared = dav
        .send(
            Req::anna("PUT", "/dav/calendars/acme/anna/work/over.ics")
                .header("content-length", &over.len().to_string())
                .ics(&over),
        )
        .await;
    assert_eq!(declared.status, StatusCode::FORBIDDEN);
    assert_eq!(declared.precondition().as_deref(), Some("max-resource-size"));

    // Without a declared length the body is cut off while it is read.
    let chunked = dav
        .send(Req::anna("PUT", "/dav/calendars/acme/anna/work/over.ics").ics(&over))
        .await;
    assert_eq!(chunked.status, StatusCode::FORBIDDEN);
    assert_eq!(chunked.precondition().as_deref(), Some("max-resource-size"));
    let listing = dav
        .send(
            Req::anna("PROPFIND", "/dav/calendars/acme/anna/work/over.ics")
                .depth("0")
                .xml(&propfind(&["D:getetag"])),
        )
        .await;
    assert_eq!(listing.status, StatusCode::NOT_FOUND, "nothing was stored");
}

#[tokio::test]
async fn reads_are_conditional_and_head_has_no_body() {
    let dav = Dav::new();
    let tag = etag_of(STANDUP_ICS);
    let not_modified = dav.send(Req::anna("GET", STANDUP).header("if-none-match", &tag)).await;
    assert_eq!(not_modified.status, StatusCode::NOT_MODIFIED);
    assert_eq!(not_modified.body, "");
    assert_eq!(not_modified.header("etag"), tag);
    let weak = dav
        .send(Req::anna("GET", STANDUP).header("if-none-match", &format!("W/{tag}")))
        .await;
    assert_eq!(weak.status, StatusCode::NOT_MODIFIED);
    let other = dav
        .send(Req::anna("GET", STANDUP).header("if-none-match", &etag_of("x")))
        .await;
    assert_eq!(other.status, StatusCode::OK);
    let failed = dav
        .send(Req::anna("GET", STANDUP).header("if-match", &etag_of("x")))
        .await;
    assert_eq!(failed.status, StatusCode::PRECONDITION_FAILED);
    let matched = dav.send(Req::anna("GET", STANDUP).header("if-match", &tag)).await;
    assert_eq!(matched.status, StatusCode::OK);

    let head = dav.send(Req::anna("HEAD", STANDUP)).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.body, "");
    assert_eq!(head.header("etag"), tag);
    assert_eq!(head.header("content-length"), STANDUP_ICS.len().to_string());
    assert_eq!(
        head.header("content-type"),
        "text/calendar; charset=utf-8; component=vevent"
    );
}

#[tokio::test]
async fn the_objects_of_other_users_do_not_exist_for_a_user_without_access() {
    let dav = Dav::new();
    for request in [
        Req::anna("GET", STANDUP).by(User::Ben),
        Req::anna("HEAD", STANDUP).by(User::Ben),
        Req::anna("PUT", NEW).by(User::Ben).ics(&event("x@acme.example", "x")),
        Req::anna("DELETE", STANDUP).by(User::Ben),
        Req::anna("MOVE", STANDUP).by(User::Ben).header("destination", NEW),
        Req::anna("COPY", STANDUP).by(User::Ben).header("destination", NEW),
    ] {
        let label = format!("{request:?}");
        let answer = dav.send(request).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{label}");
        assert_eq!(answer.body, "", "{label}");
    }
    assert_eq!(
        dav.send(Req::anna("GET", STANDUP)).await.status,
        StatusCode::OK,
        "nothing happened"
    );
}

#[tokio::test]
async fn delete_is_conditional_and_final() {
    let dav = Dav::new();
    let stale = dav
        .send(Req::anna("DELETE", STANDUP).header("if-match", &etag_of("stale")))
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(dav.send(Req::anna("GET", STANDUP)).await.status, StatusCode::OK);
    let deleted = dav
        .send(Req::anna("DELETE", STANDUP).header("if-match", &etag_of(STANDUP_ICS)))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(deleted.body, "");
    assert_eq!(dav.send(Req::anna("GET", STANDUP)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        dav.send(Req::anna("DELETE", STANDUP)).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn move_relocates_an_object_within_and_between_calendars() {
    let dav = Dav::new();
    let within = dav
        .send(Req::anna("MOVE", STANDUP).header("destination", "/dav/calendars/acme/anna/work/moved.ics"))
        .await;
    assert_eq!(within.status, StatusCode::CREATED);
    assert_eq!(dav.send(Req::anna("GET", STANDUP)).await.status, StatusCode::NOT_FOUND);
    let moved = dav
        .send(Req::anna("GET", "/dav/calendars/acme/anna/work/moved.ics"))
        .await;
    assert_eq!(moved.body, STANDUP_ICS, "the bytes and the tag do not change");
    assert_eq!(moved.header("etag"), etag_of(STANDUP_ICS));

    let across = dav
        .send(
            Req::anna("MOVE", "/dav/calendars/acme/anna/work/moved.ics")
                .header("destination", &format!("{PERSONAL}elsewhere.ics")),
        )
        .await;
    assert_eq!(across.status, StatusCode::CREATED);
    assert_eq!(
        dav.send(Req::anna("GET", &format!("{PERSONAL}elsewhere.ics")))
            .await
            .body,
        STANDUP_ICS
    );
}

#[tokio::test]
async fn destinations_may_be_absolute_urls_of_the_server() {
    let dav = Dav::new();
    let answer = dav
        .send(Req::anna("MOVE", STANDUP).header(
            "destination",
            "https://cal.example.test/dav/calendars/acme/anna/work/absolute%20name.ics",
        ))
        .await;
    assert_eq!(answer.status, StatusCode::CREATED, "{}", answer.body);
    let read = dav
        .send(Req::anna("GET", "/dav/calendars/acme/anna/work/absolute%20name.ics"))
        .await;
    assert_eq!(read.status, StatusCode::OK);
}

#[tokio::test]
async fn overwrite_decides_what_happens_to_an_existing_destination() {
    let dav = Dav::new();
    let other = dav.put_event(NEW, "new-1@acme.example", "Other").await;
    let refused = dav
        .send(
            Req::anna("MOVE", STANDUP)
                .header("destination", NEW)
                .header("overwrite", "F"),
        )
        .await;
    assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        dav.send(Req::anna("GET", NEW)).await.header("etag"),
        other,
        "the destination is untouched"
    );
    assert_eq!(
        dav.send(Req::anna("GET", STANDUP)).await.status,
        StatusCode::OK,
        "so is the source"
    );

    let replaced = dav.send(Req::anna("MOVE", STANDUP).header("destination", NEW)).await;
    assert_eq!(
        replaced.status,
        StatusCode::NO_CONTENT,
        "the default is T and an existing target is replaced"
    );
    assert_eq!(dav.send(Req::anna("GET", NEW)).await.body, STANDUP_ICS);
}

#[tokio::test]
async fn copy_keeps_the_source_and_its_uid() {
    let dav = Dav::new();
    let copied = dav
        .send(Req::anna("COPY", STANDUP).header("destination", &format!("{PERSONAL}copy.ics")))
        .await;
    assert_eq!(copied.status, StatusCode::CREATED, "{}", copied.body);
    assert_eq!(dav.send(Req::anna("GET", STANDUP)).await.status, StatusCode::OK);
    assert_eq!(
        dav.send(Req::anna("GET", &format!("{PERSONAL}copy.ics"))).await.body,
        STANDUP_ICS
    );

    let same_calendar = dav.send(Req::anna("COPY", STANDUP).header("destination", NEW)).await;
    assert_eq!(same_calendar.status, StatusCode::FORBIDDEN);
    assert_eq!(same_calendar.precondition().as_deref(), Some("no-uid-conflict"));
    assert_eq!(same_calendar.precondition_href().as_deref(), Some(STANDUP));
}

#[tokio::test]
async fn destinations_that_make_no_sense_are_refused() {
    let dav = Dav::new();
    let refuse = |destination: Option<&'static str>, overwrite: Option<&'static str>| {
        let mut request = Req::anna("MOVE", STANDUP);
        if let Some(destination) = destination {
            request = request.header("destination", destination);
        }
        if let Some(overwrite) = overwrite {
            request = request.header("overwrite", overwrite);
        }
        request
    };
    for (request, expected) in [
        (refuse(None, None), StatusCode::BAD_REQUEST),
        (
            refuse(Some("https://evil.example/dav/calendars/acme/anna/work/x.ics"), None),
            StatusCode::BAD_GATEWAY,
        ),
        (
            refuse(Some("/dav/calendars/acme/anna/work/"), None),
            StatusCode::FORBIDDEN,
        ),
        (
            refuse(Some("/dav/calendars/acme/anna/inbox/"), None),
            StatusCode::FORBIDDEN,
        ),
        (refuse(Some("/somewhere/else.ics"), None), StatusCode::BAD_REQUEST),
        (refuse(Some(STANDUP), None), StatusCode::FORBIDDEN),
        (refuse(Some(NEW), Some("maybe")), StatusCode::BAD_REQUEST),
        (
            refuse(Some("/dav/calendars/acme/anna/nope/x.ics"), None),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let label = format!("{request:?}");
        assert_eq!(dav.send(request).await.status, expected, "{label}");
    }
    assert_eq!(
        dav.send(Req::anna("GET", STANDUP)).await.status,
        StatusCode::OK,
        "nothing moved"
    );
}

#[tokio::test]
async fn conditions_the_server_cannot_evaluate_are_answered_not_ignored() {
    let dav = Dav::new();
    let tagged = dav
        .send(
            Req::anna("PUT", NEW)
                .ics(&event("n@acme.example", "n"))
                .header("if-none-match", "\"abc\""),
        )
        .await;
    assert_eq!(tagged.status, StatusCode::NOT_IMPLEMENTED);
    let junk = dav
        .send(
            Req::anna("PUT", NEW)
                .ics(&event("n@acme.example", "n"))
                .header("if-schedule-tag-match", "junk"),
        )
        .await;
    assert_eq!(
        junk.status,
        StatusCode::PRECONDITION_FAILED,
        "a schedule tag the server never issued cannot match"
    );
    assert_eq!(
        dav.send(Req::anna("GET", NEW)).await.status,
        StatusCode::NOT_FOUND,
        "neither request wrote"
    );
}

#[tokio::test]
async fn names_with_spaces_and_non_ascii_letters_are_one_resource_in_every_method() {
    let dav = Dav::new();
    // "caf\u{e9} & bar+baz.ics", percent-encoded the way a client writes it.
    let sent = format!("{WORK}caf%C3%A9%20%26%20bar%2Bbaz.ics");
    let tag = dav.put_event(&sent, "odd-name-1@acme.example", "Odd name").await;

    let listing = dav
        .send(Req::anna("PROPFIND", WORK).depth("1").xml(&propfind(&["D:getetag"])))
        .await;
    let multi = listing.multistatus();
    let href = multi
        .hrefs()
        .into_iter()
        .find(|href| href.contains("caf"))
        .expect("the object is listed")
        .to_owned();
    assert!(href.starts_with(WORK), "{href}");
    assert_eq!(
        href,
        format!("{WORK}caf%C3%A9%20&%20bar+baz.ics"),
        "the canonical form encodes what a path segment must encode and nothing else"
    );
    assert_eq!(multi.response(&href).text(crate::support::NS_DAV, "getetag"), tag);
    let by_the_other_spelling = dav.send(Req::anna("GET", &sent)).await;
    assert_eq!(
        by_the_other_spelling.status,
        StatusCode::OK,
        "both spellings name one resource"
    );

    let read = dav.send(Req::anna("GET", &href)).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.header("etag"), tag);

    let multiget = format!(
        "<C:calendar-multiget {NS}><D:prop><D:getetag/></D:prop><D:href>{}</D:href></C:calendar-multiget>",
        href.replace('&', "&amp;")
    );
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&multiget)).await;
    let multi = answer.multistatus();
    assert_eq!(
        multi.hrefs(),
        [href.as_str()],
        "the href of the answer is the href of the request"
    );

    let sync = format!(
        "<D:sync-collection {NS}><D:sync-token/><D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"
    );
    let synced = dav.send(Req::anna("REPORT", WORK).xml(&sync)).await;
    assert!(synced.multistatus().hrefs().contains(&href.as_str()));

    let moved = format!("{PERSONAL}na%C3%AFve%20name.ics");
    let answer = dav.send(Req::anna("MOVE", &href).header("destination", &moved)).await;
    assert_eq!(answer.status, StatusCode::CREATED, "{}", answer.body);
    assert_eq!(dav.send(Req::anna("GET", &href)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(dav.send(Req::anna("GET", &moved)).await.status, StatusCode::OK);
    assert_eq!(
        dav.send(Req::anna("DELETE", &moved)).await.status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn destinations_in_calendars_the_caller_cannot_see_are_not_found_and_change_nothing() {
    let dav = Dav::new();
    let ben = "/dav/calendars/acme/ben/personal/";
    let gina = "/dav/calendars/globex/gina/personal/";
    let work_ctag = dav.ctag(User::Anna, WORK).await;
    let ben_ctag = dav.ctag(User::Ben, ben).await;
    let gina_ctag = dav.ctag(User::Gina, gina).await;
    for destination in [
        "/dav/calendars/acme/ben/personal/stolen.ics",
        "/dav/calendars/globex/gina/personal/stolen.ics",
        "https://cal.example.test/dav/calendars/acme/ben/personal/stolen.ics",
        "https://cal.example.test/dav/calendars/globex/gina/personal/stolen.ics",
        "/dav/calendars/acme/nobody/personal/stolen.ics",
        "/dav/calendars/acme/anna/nope/stolen.ics",
    ] {
        for method in ["MOVE", "COPY"] {
            let answer = dav
                .send(Req::anna(method, STANDUP).header("destination", destination))
                .await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{method} to {destination}");
            assert_eq!(answer.body, "", "{method} to {destination}: nothing leaks");
        }
    }
    let source = dav.send(Req::anna("GET", STANDUP)).await;
    assert_eq!(source.status, StatusCode::OK, "the source is still there");
    assert_eq!(source.body, STANDUP_ICS);
    assert_eq!(
        dav.ctag(User::Anna, WORK).await,
        work_ctag,
        "the source calendar did not change"
    );
    assert_eq!(
        dav.ctag(User::Ben, ben).await,
        ben_ctag,
        "Ben's calendar did not change"
    );
    assert_eq!(dav.ctag(User::Gina, gina).await, gina_ctag, "neither did Gina's");
    let stolen = dav
        .send(Req::new("GET", &format!("{ben}stolen.ics")).by(User::Ben))
        .await;
    assert_eq!(stolen.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_destination_on_another_server_is_a_bad_gateway() {
    let dav = Dav::new();
    for destination in [
        "https://evil.example/dav/calendars/acme/anna/work/x.ics",
        "http://cal.example.test/dav/calendars/acme/anna/work/x.ics",
        "https://cal.example.test:8443/dav/calendars/acme/anna/work/x.ics",
        "ftp://cal.example.test/dav/calendars/acme/anna/work/x.ics",
    ] {
        for method in ["MOVE", "COPY"] {
            let answer = dav
                .send(Req::anna(method, STANDUP).header("destination", destination))
                .await;
            assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{method} to {destination}");
        }
    }
    assert_eq!(dav.send(Req::anna("GET", STANDUP)).await.status, StatusCode::OK);
    let default_port = dav
        .send(Req::anna("MOVE", STANDUP).header(
            "destination",
            "https://CAL.example.test:443/dav/calendars/acme/anna/work/ported.ics",
        ))
        .await;
    assert_eq!(
        default_port.status,
        StatusCode::CREATED,
        "the default port names the same server: {}",
        default_port.body
    );
}

#[tokio::test]
async fn copy_evaluates_its_conditions_against_the_source() {
    let dav = Dav::new();
    let copy = format!("{PERSONAL}copy.ics");
    let current = etag_of(STANDUP_ICS);
    let absent = || async { dav.send(Req::anna("GET", &copy)).await.status == StatusCode::NOT_FOUND };

    for (what, request) in [
        (
            "a stale If-Match",
            Req::anna("COPY", STANDUP).header("if-match", &etag_of("stale")),
        ),
        (
            "a weak tag in If-Match",
            Req::anna("COPY", STANDUP).header("if-match", &format!("W/{current}")),
        ),
        (
            "If-None-Match: *, because the source exists",
            Req::anna("COPY", STANDUP).header("if-none-match", "*"),
        ),
        (
            "an If-Match that cannot be read",
            Req::anna("COPY", STANDUP).raw_header("if-match", b"\"caf\xe9\""),
        ),
        (
            "an If-Schedule-Tag-Match the source does not have",
            Req::anna("COPY", STANDUP).header("if-schedule-tag-match", "\"st-1\""),
        ),
    ] {
        let answer = dav.send(request.header("destination", &copy)).await;
        assert_eq!(answer.status, StatusCode::PRECONDITION_FAILED, "{what}");
        assert!(absent().await, "{what}: nothing was copied");
    }
    let unsupported = dav
        .send(
            Req::anna("COPY", STANDUP)
                .header("if-none-match", "\"abc\"")
                .header("destination", &copy),
        )
        .await;
    assert_eq!(unsupported.status, StatusCode::NOT_IMPLEMENTED);
    assert!(absent().await);

    let matching = dav
        .send(
            Req::anna("COPY", STANDUP)
                .header("if-match", &current)
                .header("destination", &copy),
        )
        .await;
    assert_eq!(matching.status, StatusCode::CREATED, "{}", matching.body);
    // A second copy of the same event cannot go into the same calendar (the UID is taken); a calendar of its own
    // takes it.
    assert_eq!(
        dav.send(Req::anna("MKCALENDAR", "/dav/calendars/acme/anna/spare/"))
            .await
            .status,
        StatusCode::CREATED
    );
    let star = dav
        .send(
            Req::anna("COPY", STANDUP)
                .header("if-match", "*")
                .header("destination", "/dav/calendars/acme/anna/spare/second.ics"),
        )
        .await;
    assert_eq!(star.status, StatusCode::CREATED, "{}", star.body);
}

#[tokio::test]
async fn unreadable_conditions_fail_every_write_instead_of_being_ignored() {
    let dav = Dav::new();
    for (method, path) in [("PUT", NEW), ("DELETE", STANDUP), ("MOVE", STANDUP)] {
        for header in ["if-match", "if-none-match", "if-schedule-tag-match"] {
            let mut request = Req::anna(method, path).raw_header(header, b"\"caf\xe9\"");
            if method == "PUT" {
                request = request.ics(&event("n@acme.example", "n"));
            }
            if method == "MOVE" {
                request = request.header("destination", &format!("{PERSONAL}moved.ics"));
            }
            let answer = dav.send(request).await;
            assert_eq!(answer.status, StatusCode::PRECONDITION_FAILED, "{method} with {header}");
        }
    }
    assert_eq!(
        dav.send(Req::anna("GET", STANDUP)).await.body,
        STANDUP_ICS,
        "nothing ran"
    );
    assert_eq!(dav.send(Req::anna("GET", NEW)).await.status, StatusCode::NOT_FOUND);
    let list = dav
        .send(
            Req::anna("PUT", NEW)
                .ics(&event("n@acme.example", "n"))
                .header("if-schedule-tag-match", "\"a\", \"b\""),
        )
        .await;
    assert_eq!(
        list.status,
        StatusCode::NOT_IMPLEMENTED,
        "a list of schedule tags cannot be evaluated, so it is refused rather than ignored"
    );
}
