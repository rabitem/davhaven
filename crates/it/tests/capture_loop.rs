//! The capture converter closes the loop (PLAN 3.4): what a server records of a client is a scenario that passes.
//!
//! A server with `[observability.dav_capture]` records the DAV exchanges of a tenant, one file per request. A client works
//! against it (here: the requests of a calendar client that stores an event, reads it back, lists the calendar, changes the
//! event with the entity tag it holds, synchronizes twice and deletes it). `davhaven_testkit::convert` turns the files into
//! a scenario with the values of the run replaced by variables and the entity tags and the sync token replaced by captures,
//! and the scenario passes against another server that holds the same world, in process and over HTTP.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::path::PathBuf;
use std::sync::Arc;

use davhaven_testkit::convert::{Options, convert, read_captures};
use davhaven_testkit::davhaven_fixtures::{ActorRole, EventBuilder, When};
use davhaven_testkit::flow::{Origin, run_scenario};
use davhaven_testkit::xml::Document;
use davhaven_testkit::{Actor, HttpTransport, TestApp};

const HOME: &str = "/dav/calendars/acme/olivia/personal/";

const SYNC_INITIAL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<sync-collection xmlns="DAV:"><sync-token/><sync-level>1</sync-level><prop><getetag/></prop></sync-collection>"#;

fn sync_with(token: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<sync-collection xmlns="DAV:"><sync-token>{token}</sync-token><sync-level>1</sync-level><prop><getetag/></prop></sync-collection>"#
    )
}

fn event(summary: &str) -> String {
    EventBuilder::event("capture-1@acme.example")
        .summary(summary)
        .starts(When::utc(2027, 6, 1, 9, 0))
        .ends(When::utc(2027, 6, 1, 10, 0))
        .build()
}

/// Does what a calendar client does, as the owner.
async fn work_as_a_client(app: &TestApp, owner: &Actor) {
    let dav = app.dav(owner);
    let created = dav
        .put(&format!("{HOME}capture-1.ics"), &event("Dentist with Anna"))
        .header("if-none-match", "*")
        .send()
        .await
        .unwrap();
    assert_eq!(created.status.as_u16(), 201, "{}", created.text());
    let etag = created.etag().unwrap().to_owned();
    let read = dav.get(&format!("{HOME}capture-1.ics")).send().await.unwrap();
    assert_eq!(read.status.as_u16(), 200);
    let members = dav
        .propfind(
            HOME,
            "1",
            r#"<?xml version="1.0"?><propfind xmlns="DAV:"><prop><getetag/><resourcetype/></prop></propfind>"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(members.status.as_u16(), 207);
    let changed = dav
        .put(&format!("{HOME}capture-1.ics"), &event("Dentist, moved"))
        .header("if-match", &etag)
        .send()
        .await
        .unwrap();
    assert!(changed.status.is_success(), "{}", changed.text());
    let first = dav.report(HOME, "1", SYNC_INITIAL).send().await.unwrap();
    assert_eq!(first.status.as_u16(), 207, "{}", first.text());
    let token = Document::parse(&first.text())
        .unwrap()
        .select("/{DAV:}multistatus/{DAV:}sync-token")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let second = dav.report(HOME, "1", &sync_with(&token)).send().await.unwrap();
    assert_eq!(second.status.as_u16(), 207, "{}", second.text());
    let deleted = dav
        .delete(&format!("{HOME}capture-1.ics"))
        .header("if-match", changed.etag().unwrap())
        .send()
        .await
        .unwrap();
    assert!(deleted.status.is_success(), "{}", deleted.text());
}

fn options() -> Options {
    Options {
        name: "captured-store-read-change-sync-delete".to_owned(),
        description: Some(
            "A calendar client stores an event, reads it, changes it, synchronizes and deletes it.".to_owned(),
        ),
        client: "apple-calendar".to_owned(),
        feature: "crud".to_owned(),
        provenance: "recorded from the harness client of the capture test".to_owned(),
        actor: None,
        login_domain: Some("acme.example".to_owned()),
        keep_text: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_the_server_recorded_of_a_client_is_a_scenario_that_passes() {
    let dir: PathBuf = std::env::temp_dir().join(format!("davhaven-it-capture-{}", std::process::id()));
    drop(std::fs::remove_dir_all(&dir));
    let recording = TestApp::builder()
        .server_config(&format!(
            "[observability.dav_capture]\nenabled = true\ntenants = [\"acme\"]\ndir = \"{}\"\n",
            dir.display()
        ))
        .build()
        .await
        .unwrap();
    let owner = recording.actor(ActorRole::Owner).unwrap();
    work_as_a_client(&recording, &owner).await;
    // A request that is not the client's: another tenant's user is never recorded, and so is nobody who is not logged in.
    let stranger = recording.actor(ActorRole::OtherTenantUser).unwrap();
    recording.dav(&stranger).propfind(HOME, "0", "").send().await.unwrap();
    recording
        .dav(&Actor::Anonymous)
        .propfind(HOME, "0", "")
        .send()
        .await
        .unwrap();

    let exchanges = read_captures(&dir).unwrap();
    assert_eq!(
        exchanges.len(),
        7,
        "the seven requests of the client and nothing else: {exchanges:#?}"
    );

    let converted = convert(&exchanges, &options()).unwrap();
    drop(std::fs::remove_dir_all(&dir));
    let scenario = &converted.scenario;
    assert_eq!(scenario.origin, Origin::Captured);
    let yaml = &converted.yaml;
    assert!(
        !yaml.contains("acme"),
        "the tenant of the recording is a variable:\n{yaml}"
    );
    assert!(
        !yaml.contains("Dentist"),
        "the free text of the calendar data is scrubbed:\n{yaml}"
    );
    assert!(
        yaml.contains("{{etag1}}") && yaml.contains("{{sync1}}"),
        "values of the server are captures:\n{yaml}"
    );

    // Another server with the same world, in process and over a socket: the scenario passes on both.
    let fresh = TestApp::builder().build().await.unwrap();
    let report = run_scenario(&fresh.scenario_env(), scenario).await;
    assert!(report.is_success(), "in process:\n{report}\n{yaml}");

    let served = TestApp::builder().build().await.unwrap();
    let socket = served.serve().await.unwrap();
    let transport = Arc::new(HttpTransport::new(socket.base_url.clone()).unwrap());
    let env = served.scenario_env_over(transport, socket.base_url.as_str().trim_end_matches('/'));
    let report = run_scenario(&env, scenario).await;
    assert!(report.is_success(), "over a socket:\n{report}\n{yaml}");
}
