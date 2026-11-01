//! The `sync-collection` report: initial and incremental synchronization, deletions, truncation, tokens the
//! server cannot use and the levels it does not offer.

use axum::http::StatusCode;
use davhaven_app::AppServices;
use davhaven_app_fake::AppServicesExt as _;

use crate::support::{Dav, Multi, NS, NS_CALDAV, NS_DAV, PERSONAL, Req, STANDUP, STANDUP_ICS, User, WORK};

fn sync(token: &str, extra: &str) -> String {
    format!(
        "<D:sync-collection {NS}><D:sync-token>{token}</D:sync-token><D:sync-level>1</D:sync-level>{extra}\
         <D:prop><D:getetag/></D:prop></D:sync-collection>"
    )
}

async fn sync_of(dav: &Dav, path: &str, token: &str, extra: &str) -> Multi {
    let answer = dav.send(Req::anna("REPORT", path).xml(&sync(token, extra))).await;
    answer.multistatus()
}

#[tokio::test]
async fn the_initial_sync_lists_every_member_and_hands_out_a_token() {
    let dav = Dav::new();
    let multi = sync_of(&dav, WORK, "", "").await;
    assert_eq!(multi.hrefs(), [STANDUP]);
    assert_eq!(
        multi.responses[0].text(NS_DAV, "getetag"),
        davhaven_domain::ETag::from_bytes(STANDUP_ICS.as_bytes()).as_str()
    );
    let token = multi.sync_token.unwrap();
    assert!(token.starts_with("urn:davhaven:sync:"), "{token}");

    let ctag = dav
        .send(
            Req::anna("PROPFIND", WORK)
                .depth("0")
                .xml(&crate::support::propfind(&["CS:getctag"])),
        )
        .await;
    assert_eq!(
        ctag.multistatus().responses[0].text(crate::support::NS_CALENDARSERVER, "getctag"),
        token,
        "the ctag of the collection is the token of the sync"
    );
}

#[tokio::test]
async fn later_syncs_report_changes_and_deletions() {
    let dav = Dav::new();
    let first = sync_of(&dav, WORK, "", "").await.sync_token.unwrap();
    let created = dav
        .put_event(&format!("{WORK}new.ics"), "new-1@acme.example", "New")
        .await;
    assert_eq!(
        dav.send(Req::anna("DELETE", STANDUP)).await.status,
        StatusCode::NO_CONTENT
    );

    let second = sync_of(&dav, WORK, &first, "").await;
    assert_eq!(
        second.hrefs(),
        ["/dav/calendars/acme/anna/work/new.ics", STANDUP],
        "sorted by href: the changed member and the deleted one"
    );
    assert_eq!(second.responses[0].text(NS_DAV, "getetag"), created);
    assert_eq!(
        second.responses[1].status,
        Some(404),
        "a deletion is a 404 without properties"
    );
    assert!(second.responses[1].stats.is_empty());
    let token = second.sync_token.unwrap();
    assert_ne!(token, first);

    let third = sync_of(&dav, WORK, &token, "").await;
    assert!(third.responses.is_empty(), "nothing changed");
    assert_eq!(
        third.sync_token.unwrap(),
        token,
        "the token stays the same until something changes"
    );
}

#[tokio::test]
async fn a_member_that_changed_twice_is_reported_once() {
    let dav = Dav::new();
    let token = sync_of(&dav, WORK, "", "").await.sync_token.unwrap();
    dav.put_event(&format!("{WORK}busy.ics"), "busy-1@acme.example", "One")
        .await;
    let update = crate::support::event("busy-1@acme.example", "Two");
    let answer = dav
        .send(Req::anna("PUT", &format!("{WORK}busy.ics")).ics(&update))
        .await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    let multi = sync_of(&dav, WORK, &token, "").await;
    assert_eq!(multi.hrefs(), ["/dav/calendars/acme/anna/work/busy.ics"]);
    assert_eq!(
        multi.responses[0].text(NS_DAV, "getetag"),
        davhaven_domain::ETag::from_bytes(update.as_bytes()).as_str(),
        "the state after the last change"
    );
}

#[tokio::test]
async fn a_truncated_answer_says_so_and_continues_where_it_stopped() {
    let dav = Dav::new();
    let start = sync_of(&dav, WORK, "", "").await.sync_token.unwrap();
    for name in ["a", "b", "c"] {
        dav.put_event(&format!("{WORK}{name}.ics"), &format!("{name}-1@acme.example"), name)
            .await;
    }
    let limit = "<D:limit><D:nresults>2</D:nresults></D:limit>";
    let page = sync_of(&dav, WORK, &start, limit).await;
    let members: Vec<&str> = page.hrefs().into_iter().filter(|href| *href != WORK).collect();
    assert_eq!(
        members,
        [
            "/dav/calendars/acme/anna/work/a.ics",
            "/dav/calendars/acme/anna/work/b.ics"
        ],
        "the oldest changes come first"
    );
    let cut = page.response(WORK);
    assert_eq!(cut.status, Some(507), "the request URI reports that there is more");
    assert_eq!(cut.error.as_deref(), Some("number-of-matches-within-limits"));
    let middle = page.sync_token.unwrap();

    let rest = sync_of(&dav, WORK, &middle, limit).await;
    assert_eq!(rest.hrefs(), ["/dav/calendars/acme/anna/work/c.ics"]);
    assert!(rest.responses.iter().all(|response| response.status != Some(507)));
    let end = rest.sync_token.unwrap();
    assert_ne!(end, middle);
    assert!(sync_of(&dav, WORK, &end, limit).await.responses.is_empty());
}

#[tokio::test]
async fn tokens_the_server_cannot_use_answer_403_valid_sync_token() {
    let dav = Dav::new();
    let token = sync_of(&dav, WORK, "", "").await.sync_token.unwrap();
    let parts: Vec<&str> = token.split(':').collect();
    assert_eq!(parts.len(), 6, "{token}");
    let other_epoch = format!(
        "{}:{}:{}:{}:{}:{}",
        parts[0], parts[1], parts[2], parts[3], "00000000-0000-0000-0000-0000000000ff", parts[5]
    );
    let future = format!(
        "{}:{}:{}:{}:{}:{}",
        parts[0], parts[1], parts[2], parts[3], parts[4], 9999
    );
    let personal = sync_of(&dav, PERSONAL, "", "").await.sync_token.unwrap();
    for bad in [
        "garbage".to_owned(),
        "urn:davhaven:sync:x:y:z".to_owned(),
        format!("{token}0000"),
        other_epoch,
        future,
        personal,
    ] {
        let answer = dav.send(Req::anna("REPORT", WORK).xml(&sync(&bad, ""))).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{bad}");
        assert_eq!(answer.precondition().as_deref(), Some("valid-sync-token"), "{bad}");
    }
    let still = sync_of(&dav, WORK, &token, "").await;
    assert!(still.responses.is_empty(), "the refusals changed nothing");
    assert_eq!(still.sync_token, Some(token), "the real token still works");
}

#[tokio::test]
async fn only_sync_level_one_is_offered() {
    let dav = Dav::new();
    let infinite = format!(
        "<D:sync-collection {NS}><D:sync-token/><D:sync-level>infinite</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"
    );
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&infinite)).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.precondition().as_deref(), Some("sync-traversal-supported"));
}

#[tokio::test]
async fn incomplete_sync_requests_are_400() {
    let dav = Dav::new();
    for body in [
        format!("<D:sync-collection {NS}><D:sync-level>1</D:sync-level><D:prop/></D:sync-collection>"),
        format!("<D:sync-collection {NS}><D:sync-token/><D:prop/></D:sync-collection>"),
        format!("<D:sync-collection {NS}><D:sync-token/><D:sync-level>1</D:sync-level></D:sync-collection>"),
        format!("<D:sync-collection {NS}><D:sync-token/><D:sync-level>2</D:sync-level><D:prop/></D:sync-collection>"),
        sync("", "<D:limit><D:nresults>lots</D:nresults></D:limit>"),
    ] {
        let answer = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}");
    }
}

#[tokio::test]
async fn members_can_be_reported_with_more_than_their_tag() {
    let dav = Dav::new();
    let start = sync_of(&dav, WORK, "", "").await.sync_token.unwrap();
    let body = format!(
        "<D:sync-collection {NS}><D:sync-token>{start}</D:sync-token><D:sync-level>1</D:sync-level>\
         <D:prop><D:getetag/><D:getcontenttype/><C:calendar-data/></D:prop></D:sync-collection>"
    );
    dav.put_event(&format!("{WORK}new.ics"), "new-1@acme.example", "New")
        .await;
    dav.send(Req::anna("DELETE", STANDUP)).await;
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&body)).await;
    let multi = answer.multistatus();
    let new = multi.response("/dav/calendars/acme/anna/work/new.ics");
    assert_eq!(
        new.text(NS_DAV, "getcontenttype"),
        "text/calendar; charset=utf-8; component=vevent"
    );
    assert_eq!(
        new.text(NS_CALDAV, "calendar-data"),
        crate::support::event("new-1@acme.example", "New")
    );
    assert_eq!(multi.response(STANDUP).status, Some(404));

    let initial = format!(
        "<D:sync-collection {NS}><D:sync-token/><D:sync-level>1</D:sync-level><D:prop><C:calendar-data/></D:prop></D:sync-collection>"
    );
    let answer = dav.send(Req::anna("REPORT", WORK).xml(&initial)).await;
    let multi = answer.multistatus();
    assert_eq!(multi.hrefs(), ["/dav/calendars/acme/anna/work/new.ics"]);
}

#[tokio::test]
async fn the_collections_of_others_cannot_be_synchronized() {
    let dav = Dav::new();
    let token = sync_of(&dav, WORK, "", "").await.sync_token.unwrap();
    // A token Anna was handed is no key: with it or without it, the calendar does not exist for the others.
    for user in [User::Ben, User::Gina] {
        for presented in ["", token.as_str()] {
            let answer = dav
                .send(Req::anna("REPORT", WORK).by(user).xml(&sync(presented, "")))
                .await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{user:?} with {presented:?}");
            assert_eq!(answer.body, "", "{user:?} with {presented:?}: nothing leaks");
        }
    }
    for (user, path) in [
        (User::Ben, "/dav/calendars/acme/anna/inbox/"),
        (User::Ben, "/dav/calendars/acme/anna/notifications/"),
        (User::Gina, "/dav/calendars/acme/anna/inbox/"),
    ] {
        let answer = dav.send(Req::new("REPORT", path).by(user).xml(&sync("", ""))).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{user:?} {path}");
    }
}

#[tokio::test]
async fn the_inbox_and_the_notification_collection_are_synchronized_too() {
    let dav = Dav::new();
    for path in [
        "/dav/calendars/acme/anna/inbox/",
        "/dav/calendars/acme/anna/notifications/",
    ] {
        let multi = sync_of(&dav, path, "", "").await;
        assert!(multi.responses.is_empty(), "{path}");
        let token = multi.sync_token.unwrap();
        assert!(token.starts_with("urn:davhaven:sync:"), "{path}: {token}");
        let again = sync_of(&dav, path, &token, "").await;
        assert!(again.responses.is_empty(), "{path}");
        assert_eq!(
            again.sync_token,
            Some(token),
            "{path}: the token it handed out is one it takes back"
        );
    }
}

#[tokio::test]
async fn an_answer_reports_no_more_members_than_the_server_allows_and_the_client_can_continue() {
    let mut services = AppServices::fake();
    services.limits.dav.max_multiget_hrefs = 2;
    let dav = Dav::with(services);
    let mut token = sync_of(&dav, WORK, "", "").await.sync_token.unwrap();
    for n in 0..5 {
        dav.put_event(&format!("{WORK}c{n}.ics"), &format!("c{n}@acme.example"), "C")
            .await;
    }
    let mut seen: Vec<String> = Vec::new();
    // The client asks for a hundred; the server answers two at a time and says where it stopped.
    for step in 0..5 {
        let multi = sync_of(&dav, WORK, &token, "<D:limit><D:nresults>100</D:nresults></D:limit>").await;
        let members: Vec<String> = multi
            .responses
            .iter()
            .filter(|response| response.href != WORK)
            .map(|response| response.href.clone())
            .collect();
        assert!(members.len() <= 2, "step {step}: {members:?}");
        seen.extend(members);
        token = multi.sync_token.unwrap();
        let truncated = multi.responses.iter().any(|response| response.status == Some(507));
        if !truncated {
            break;
        }
    }
    seen.sort();
    let expected: Vec<String> = (0..5).map(|n| format!("{WORK}c{n}.ics")).collect();
    assert_eq!(seen, expected, "every change arrived, each once");
}
