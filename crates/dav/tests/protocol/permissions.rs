//! The actors of the permission rules (PLAN 2.6, 3.2) over HTTP: the owner, sharees with read and read-write
//! access, sharees who have not accepted, a user who is suspended, and a calendar DAV cannot write. Every denial
//! asserts the status policy (404 for what the caller cannot see, 403 with `DAV:need-privileges` naming the
//! resource and the privilege for what they can see but not do) and that nothing changed: the object, the other
//! calendars and the `getctag` of the calendar are as they were.
//!
//! The expectations are written by hand from PLAN 2.6; they do not call the code that decides.
//!
//! What the fake cannot express is not here: a grantee who may only read free and busy time, the `CS:shared`
//! resource types and the invitation flow (those are exercised against the real application by
//! `crates/it/tests/appcore/dav_collaboration.rs`).

use axum::http::StatusCode;

use crate::support::{
    Dav, MANAGED, NS, NS_APPLE_ICAL, NS_CALDAV, NS_DAV, Req, SHARE, STANDUP, STANDUP_ICS, User, WORK, event, propfind,
};

fn share_of(user: &str) -> String {
    format!("/dav/calendars/acme/{user}/{SHARE}/")
}

fn patch(props: &str) -> String {
    format!("<D:propertyupdate {NS}><D:set><D:prop>{props}</D:prop></D:set></D:propertyupdate>")
}

/// The names of the privileges `user` has on `path`, sorted.
async fn privileges(dav: &Dav, user: User, path: &str) -> Vec<String> {
    let answer = dav
        .send(
            Req::new("PROPFIND", path)
                .by(user)
                .depth("0")
                .xml(&propfind(&["D:current-user-privilege-set"])),
        )
        .await;
    answer.multistatus().responses.first().unwrap().privileges()
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

/// Asserts that a request was refused with 403 and `DAV:need-privileges` for one resource and privilege.
fn assert_needs(answer: &crate::support::Answer, href: &str, privilege: &str, what: &str) {
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{what}: {}", answer.body);
    assert_eq!(answer.precondition().as_deref(), Some("need-privileges"), "{what}");
    assert_eq!(
        answer.needed(),
        [(href.to_owned(), privilege.to_owned())],
        "{what}: the resource and the privilege that are missing"
    );
}

#[tokio::test]
async fn a_read_sharee_reads_and_nothing_else() {
    let dav = Dav::shared();
    let share = share_of("rita");
    let standup = format!("{share}standup.ics");
    let created = format!("{share}new.ics");
    let moved = format!("{share}moved.ics");
    let copy = format!("{share}copy.ics");
    let ctag = dav.ctag(User::Anna, WORK).await;

    let read = dav.send(Req::new("GET", &standup).by(User::Rita)).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body, STANDUP_ICS, "the shared object, byte for byte");
    let listing = dav
        .send(
            Req::new("PROPFIND", &share)
                .by(User::Rita)
                .depth("1")
                .xml(&propfind(&["D:getetag"])),
        )
        .await;
    assert_eq!(listing.multistatus().hrefs(), [share.as_str(), standup.as_str()]);

    let put_new = dav
        .send(
            Req::new("PUT", &created)
                .by(User::Rita)
                .ics(&event("rita-1@acme.example", "Mine"))
                .header("if-none-match", "*"),
        )
        .await;
    assert_needs(&put_new, &created, "bind", "PUT of a new object");
    let put_over = dav
        .send(
            Req::new("PUT", &standup)
                .by(User::Rita)
                .ics(&event("standup-1@acme.example", "Rewritten")),
        )
        .await;
    assert_needs(&put_over, &standup, "write-content", "PUT over an object");
    let delete = dav.send(Req::new("DELETE", &standup).by(User::Rita)).await;
    assert_needs(&delete, &standup, "unbind", "DELETE of an object");
    let moving = dav
        .send(Req::new("MOVE", &standup).by(User::Rita).header("destination", &moved))
        .await;
    assert_needs(&moving, &standup, "unbind", "MOVE out of the share");
    let copying = dav
        .send(Req::new("COPY", &standup).by(User::Rita).header("destination", &copy))
        .await;
    assert_needs(&copying, &copy, "bind", "COPY into the share");

    // Nothing happened: the calendar, the object and the names that were refused.
    assert_eq!(dav.ctag(User::Anna, WORK).await, ctag, "the calendar did not change");
    assert_eq!(
        dav.ctag(User::Rita, &share).await,
        ctag,
        "and it is the same calendar for Rita"
    );
    assert_eq!(dav.send(Req::anna("GET", STANDUP)).await.body, STANDUP_ICS);
    for name in ["new.ics", "moved.ics", "copy.ics"] {
        let absent = dav.send(Req::anna("GET", &format!("{WORK}{name}"))).await;
        assert_eq!(absent.status, StatusCode::NOT_FOUND, "{name} was not created");
    }
}

#[tokio::test]
async fn a_read_sharee_may_copy_what_she_reads_into_her_own_calendars() {
    let dav = Dav::shared();
    let standup = format!("{}standup.ics", share_of("rita"));
    let ctag = dav.ctag(User::Anna, WORK).await;
    let copied = dav
        .send(
            Req::new("COPY", &standup)
                .by(User::Rita)
                .header("destination", "/dav/calendars/acme/rita/personal/copy.ics"),
        )
        .await;
    assert_eq!(copied.status, StatusCode::CREATED, "{}", copied.body);
    let read = dav
        .send(Req::new("GET", "/dav/calendars/acme/rita/personal/copy.ics").by(User::Rita))
        .await;
    assert_eq!(read.body, STANDUP_ICS);
    assert_eq!(dav.ctag(User::Anna, WORK).await, ctag, "the source is untouched");
}

#[tokio::test]
async fn a_read_write_sharee_changes_the_shared_calendar() {
    let dav = Dav::shared();
    let share = share_of("walt");
    let created = format!("{share}walt.ics");
    let ctag = dav.ctag(User::Anna, WORK).await;
    let put = dav
        .send(
            Req::new("PUT", &created)
                .by(User::Walt)
                .ics(&event("walt-1@acme.example", "From Walt"))
                .header("if-none-match", "*"),
        )
        .await;
    assert_eq!(put.status, StatusCode::CREATED, "{}", put.body);
    let seen = dav.send(Req::anna("GET", &format!("{WORK}walt.ics"))).await;
    assert_eq!(seen.status, StatusCode::OK, "the owner sees what the sharee wrote");
    assert_ne!(dav.ctag(User::Anna, WORK).await, ctag, "and her clients synchronize it");
    let delete = dav.send(Req::new("DELETE", &created).by(User::Walt)).await;
    assert_eq!(delete.status, StatusCode::NO_CONTENT);
    assert_eq!(
        dav.send(Req::anna("GET", &format!("{WORK}walt.ics"))).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn sharees_do_not_reach_the_home_of_the_owner() {
    let dav = Dav::shared();
    for user in [User::Rita, User::Walt] {
        for (method, path) in [
            ("GET", STANDUP),
            ("PROPFIND", "/dav/calendars/acme/anna/"),
            ("PROPFIND", WORK),
            ("MKCALENDAR", "/dav/calendars/acme/anna/intruder/"),
        ] {
            let mut request = Req::new(method, path).by(user);
            if method == "PROPFIND" {
                request = request.depth("0").xml(&propfind(&["D:displayname"]));
            }
            let answer = dav.send(request).await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{user:?} {method} {path}");
            assert_eq!(answer.body, "", "{user:?} {method} {path}");
        }
    }
}

#[tokio::test]
async fn the_privileges_over_http_are_those_of_the_access_level() {
    let dav = Dav::shared();
    let reads = ["read", "read-current-user-privilege-set", "read-free-busy"];
    let writes = ["bind", "unbind", "write", "write-content", "write-properties"];
    let all_of = |extra: &[&str]| {
        let mut all: Vec<&str> = reads.iter().chain(writes.iter()).chain(extra.iter()).copied().collect();
        all.sort_unstable();
        names(&all)
    };

    assert_eq!(
        privileges(&dav, User::Rita, &share_of("rita")).await,
        names(&reads),
        "a read sharee reads"
    );
    assert_eq!(
        privileges(&dav, User::Walt, &share_of("walt")).await,
        all_of(&[]),
        "a read-write sharee reads and writes, and cannot share on"
    );
    assert_eq!(
        privileges(&dav, User::Anna, WORK).await,
        all_of(&["share"]),
        "the owner can also share"
    );
    assert_eq!(
        privileges(&dav, User::Anna, MANAGED).await,
        names(&reads),
        "a managed calendar is read-only over DAV, even for its owner"
    );

    let standup = |user: &str| format!("{}standup.ics", share_of(user));
    assert_eq!(
        privileges(&dav, User::Rita, &standup("rita")).await,
        names(&["read", "read-current-user-privilege-set"]),
        "an object of a read share"
    );
    assert_eq!(
        privileges(&dav, User::Walt, &standup("walt")).await,
        names(&[
            "read",
            "read-current-user-privilege-set",
            "unbind",
            "write",
            "write-content",
            "write-properties"
        ]),
        "an object of a read-write share"
    );
    assert_eq!(
        privileges(&dav, User::Rita, "/dav/calendars/acme/rita/").await,
        names(&[
            "bind",
            "read",
            "read-current-user-privilege-set",
            "unbind",
            "write-properties"
        ]),
        "the home belongs to its owner"
    );
    assert_eq!(
        privileges(&dav, User::Rita, "/dav/principals/acme/rita/").await,
        names(&["read", "read-current-user-privilege-set"]),
        "a principal"
    );
    assert_eq!(
        privileges(&dav, User::Anna, "/dav/").await,
        names(&["read", "read-current-user-privilege-set"]),
        "the entry point"
    );
}

#[tokio::test]
async fn a_calendar_that_dav_cannot_write_refuses_writes_with_need_privileges() {
    let dav = Dav::shared();
    let object = format!("{MANAGED}event.ics");
    let ctag = dav.ctag(User::Anna, MANAGED).await;
    let put = dav
        .send(
            Req::anna("PUT", &object)
                .ics(&event("managed-1@acme.example", "Managed"))
                .header("if-none-match", "*"),
        )
        .await;
    assert_needs(&put, &object, "bind", "PUT into a managed calendar");
    assert_eq!(dav.ctag(User::Anna, MANAGED).await, ctag, "nothing was written");
    let absent = dav.send(Req::anna("GET", &object)).await;
    assert_eq!(absent.status, StatusCode::NOT_FOUND);
    let listing = dav
        .send(Req::anna("PROPFIND", MANAGED).depth("1").xml(&propfind(&["D:getetag"])))
        .await;
    assert_eq!(
        listing.multistatus().hrefs(),
        [MANAGED],
        "the calendar is there and empty"
    );
}

#[tokio::test]
async fn properties_of_the_binding_are_the_sharees_and_shared_ones_need_write_access() {
    let dav = Dav::shared();
    let share = share_of("rita");
    let ctag = dav.ctag(User::Anna, WORK).await;
    let display_name = |user: User, path: String| {
        let dav = &dav;
        async move {
            let answer = dav
                .send(
                    Req::new("PROPFIND", &path)
                        .by(user)
                        .depth("0")
                        .xml(&propfind(&["D:displayname", "C:calendar-description"])),
                )
                .await;
            let multi = answer.multistatus();
            let response = &multi.responses[0];
            (
                response.text(NS_DAV, "displayname"),
                response.status_of(NS_CALDAV, "calendar-description"),
            )
        }
    };

    // The name and the color of a binding are the sharee's own.
    let own = dav
        .send(Req::new("PROPPATCH", &share).by(User::Rita).xml(&patch(
            "<D:displayname>Rita's view</D:displayname><A:calendar-color>#112233FF</A:calendar-color>",
        )))
        .await;
    let multi = own.multistatus();
    assert!(
        multi.responses[0].stats.iter().all(|stat| stat.status == 200),
        "{}",
        own.body
    );
    assert_eq!(display_name(User::Rita, share.clone()).await.0, "Rita's view");
    assert_eq!(
        display_name(User::Anna, WORK.to_owned()).await.0,
        "Work",
        "the owner's name is not changed"
    );
    assert_eq!(
        dav.ctag(User::Anna, WORK).await,
        ctag,
        "a per-binding property is no change of the calendar"
    );

    // A property of the calendar needs write access, and the request is atomic.
    let shared = dav
        .send(Req::new("PROPPATCH", &share).by(User::Rita).xml(&patch(
            "<D:displayname>Renamed</D:displayname><C:calendar-description>Mine now</C:calendar-description>",
        )))
        .await;
    let multi = shared.multistatus();
    let response = &multi.responses[0];
    assert_eq!(response.status_of(NS_CALDAV, "calendar-description"), Some(403));
    assert_eq!(
        response.status_of(NS_DAV, "displayname"),
        Some(424),
        "it depends on the refusal"
    );
    let (name, description) = display_name(User::Rita, share.clone()).await;
    assert_eq!(name, "Rita's view", "nothing was applied");
    assert_eq!(description, Some(404), "and the calendar has no description");
    assert_eq!(dav.ctag(User::Anna, WORK).await, ctag);

    // A sharee with write access changes the calendar for everyone.
    let walt = dav
        .send(
            Req::new("PROPPATCH", &share_of("walt"))
                .by(User::Walt)
                .xml(&patch("<C:calendar-description>By Walt</C:calendar-description>")),
        )
        .await;
    assert_eq!(walt.multistatus().responses[0].stats[0].status, 200, "{}", walt.body);
    assert_eq!(
        display_name(User::Anna, WORK.to_owned()).await.1,
        Some(200),
        "the owner sees the description"
    );
    assert_ne!(
        dav.ctag(User::Anna, WORK).await,
        ctag,
        "a shared property changes the calendar"
    );
    let color = dav
        .send(
            Req::new("PROPFIND", &share)
                .by(User::Rita)
                .depth("0")
                .xml(&propfind(&["A:calendar-color"])),
        )
        .await;
    assert_eq!(
        color.multistatus().responses[0].text(NS_APPLE_ICAL, "calendar-color"),
        "#112233FF",
        "the color the sharee chose is still hers"
    );
}

#[tokio::test]
async fn an_invitation_that_is_pending_or_declined_gives_nothing() {
    let dav = Dav::shared();
    let ctag = dav.ctag(User::Anna, WORK).await;
    for (user, name) in [(User::Pia, "pia"), (User::Dora, "dora")] {
        let share = share_of(name);
        let standup = format!("{share}standup.ics");
        for request in [
            Req::new("GET", &standup),
            Req::new("PROPFIND", &share)
                .depth("0")
                .xml(&propfind(&["D:displayname"])),
            Req::new("PUT", &format!("{share}new.ics")).ics(&event("x@acme.example", "x")),
            Req::new("DELETE", &standup),
            Req::new("MOVE", &standup).header("destination", &format!("{share}moved.ics")),
            Req::new("REPORT", &share).xml(&format!(
                "<C:calendar-multiget {NS}><D:prop><D:getetag/></D:prop><D:href>{standup}</D:href></C:calendar-multiget>"
            )),
        ] {
            let label = format!("{user:?} {request:?}");
            let answer = dav.send(request.by(user)).await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{label}");
            assert_eq!(answer.body, "", "{label}: nothing leaks");
        }
    }
    assert_eq!(dav.ctag(User::Anna, WORK).await, ctag, "nothing changed");
    assert_eq!(dav.send(Req::anna("GET", STANDUP)).await.body, STANDUP_ICS);
}

#[tokio::test]
async fn a_suspended_user_cannot_log_in() {
    let dav = Dav::shared();
    for (method, path) in [
        ("PROPFIND", "/dav/"),
        ("GET", "/dav/calendars/acme/cara/personal/x.ics"),
        ("PUT", "/dav/calendars/acme/cara/personal/x.ics"),
    ] {
        let answer = dav.send(Req::new(method, path).by(User::Cara).depth("0")).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert!(
            answer.header("www-authenticate").starts_with("Basic"),
            "{method} {path}"
        );
    }
}
