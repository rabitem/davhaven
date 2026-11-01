//! Every transaction whose work succeeded ends with a commit (the store port, `crates/ports/src/store/mod.rs`).
//!
//! PostgreSQL counts a transaction that is dropped as a rollback (`pg_stat_database.xact_rollback`), reads included, and
//! operators alert on the share of rollbacks: a read that is dropped instead of committed makes that alert fire on a healthy
//! server and hides the failures it is meant to show. Neither store lets a test see the difference in what a request answers,
//! so the application is assembled with its store wrapped in a `RollbackWatch` (the test double of the ports), which records
//! every tenant and system transaction that ends without a commit together with the frames of the application that began it.
//!
//! The test drives a representative happy path of each surface and of the workers on the real application: authentication
//! with each kind of credential, CalDAV discovery, listings, reports, reads and writes, the reads of the management API, MCP
//! tools, a feed, an RSVP page, and the outbox with and without work, an invitation that a newer one superseded among it.
//! After every step nothing may have been rolled back.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use davhaven_testkit::davhaven_domain::{CalendarUserAddress, ItipMethod, ObjectUri, OutboxId};
use davhaven_testkit::davhaven_fixtures::{ActorRole, Attendee, CalendarRole, EventBuilder, Organizer, When};
use davhaven_testkit::davhaven_ports::testing::RollbackWatch;
use davhaven_testkit::davhaven_ports::{IdGenerator as _, ImipJob, NewOutbox, OutboxMessage, TemplateName, TxMode};
use davhaven_testkit::handles::mcp_message;
use davhaven_testkit::scheduling::text::rsvp_tokens_in;
use davhaven_testkit::{Actor, TestApp, TestResponse};
use serde_json::{Value, json};

/// The calendar the steps read and write: the personal calendar of the owner of the fixture world.
const COLLECTION: &str = "/dav/calendars/acme/olivia/personal/";

/// The home of the owner.
const HOME: &str = "/dav/calendars/acme/olivia/";

/// The management API below the tenant of the fixture world.
const TENANT: &str = "/api/v1/tenants/acme";

/// Fails when a transaction ended without a commit since the last check, naming the step and where each one was begun.
fn assert_committed(watch: &RollbackWatch, step: &str) {
    let rolled_back = watch.rolled_back();
    assert!(
        rolled_back.is_empty(),
        "{step}: {} transaction(s) ended without a commit:\n\n{}",
        rolled_back.len(),
        rolled_back.join("\n")
    );
}

/// Fails when `response` is not a success: the steps are happy paths, so a refusal would test nothing.
fn assert_success(step: &str, response: &TestResponse) {
    let status = response.status.as_u16();
    assert!(
        (200..300).contains(&status) || status == 304,
        "{step}: {status} {}",
        response.excerpt(400)
    );
}

/// Sends a request, checks that it succeeded and that every transaction it ran was committed.
async fn step(watch: &RollbackWatch, name: &str, request: davhaven_testkit::handles::Pending) -> TestResponse {
    let response = request.send().await.unwrap();
    assert_success(name, &response);
    assert_committed(watch, name);
    response
}

/// An event without attendees.
fn plain_event(uid: &str) -> String {
    EventBuilder::event(uid)
        .summary("Review")
        .starts(When::utc(2027, 5, 3, 9, 0))
        .ends(When::utc(2027, 5, 3, 10, 0))
        .build()
}

/// The guest outside the tenant who is mailed an RSVP link.
const GUEST: &str = "guest@example.net";

/// The invitation of the guest.
const INVITATION: &str = "tx-invitation.ics";

/// An event that invites the guest, in its version `sequence`.
fn invitation(sequence: u32) -> String {
    EventBuilder::event("tx-invitation@acme.example")
        .summary("Planning")
        .organizer(Organizer::new("mailto:olivia@acme.example"))
        .attendee(Attendee::new(&format!("mailto:{GUEST}")))
        .starts(When::utc(2027, 6, 1, 9, 0))
        .ends(When::utc(2027, 6, 1, 10, 0))
        .sequence(sequence)
        .build()
}

async fn caldav(app: &TestApp, watch: &RollbackWatch) {
    let owner = app.actor(ActorRole::Owner).unwrap();
    let dav = app.dav(&owner);
    let props =
        r#"<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:resourcetype/><d:getetag/></d:prop></d:propfind>"#;
    step(
        watch,
        "DAV PROPFIND of the root (an app password)",
        dav.propfind("/dav/", "0", props),
    )
    .await;
    step(watch, "DAV PROPFIND of the home", dav.propfind(HOME, "1", props)).await;
    step(
        watch,
        "DAV PROPFIND of a collection",
        dav.propfind(COLLECTION, "1", props),
    )
    .await;
    let put = step(
        watch,
        "DAV PUT of a new event",
        dav.put(
            &format!("{COLLECTION}tx-plain.ics"),
            &plain_event("tx-plain@acme.example"),
        ),
    )
    .await;
    assert!(put.header("etag").is_some(), "the PUT answers an ETag");
    step(
        watch,
        "DAV GET of an event",
        dav.get(&format!("{COLLECTION}tx-plain.ics")),
    )
    .await;
    let sync = r#"<d:sync-collection xmlns:d="DAV:"><d:sync-token/><d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#;
    step(watch, "DAV REPORT sync-collection", dav.report(COLLECTION, "1", sync)).await;
    let query = r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"><c:time-range start="20270101T000000Z" end="20280101T000000Z"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>"#;
    step(watch, "DAV REPORT calendar-query", dav.report(COLLECTION, "1", query)).await;
    let multiget = format!(
        r#"<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><d:href>{COLLECTION}tx-plain.ics</d:href></c:calendar-multiget>"#
    );
    step(
        watch,
        "DAV REPORT calendar-multiget",
        dav.report(COLLECTION, "1", &multiget),
    )
    .await;

    // A client with a password that is no longer valid: the lookup of the credential succeeded, the refusal is no rollback.
    let login = app.world().login(ActorRole::Owner).unwrap();
    let refused = app
        .dav(&Actor::basic(login, "WRONG-WRONG-WRONG-WRONG"))
        .propfind("/dav/", "0", props)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status.as_u16(), 401, "{}", refused.excerpt(200));
    assert_committed(watch, "DAV with a wrong password");
}

async fn management_api(app: &TestApp, watch: &RollbackWatch) {
    let system = app.api(&app.token(ActorRole::SystemToken).unwrap());
    step(
        watch,
        "API list of tenants (a system token)",
        system.get("/api/v1/tenants"),
    )
    .await;
    step(watch, "API tenant (a system token)", system.get(TENANT)).await;

    let admin = app.api(&app.token(ActorRole::TenantToken).unwrap());
    let created = step(
        watch,
        "API create of a webhook (a tenant token)",
        admin
            .post_json(
                &format!("{TENANT}/webhooks"),
                &json!({"url": "https://hooks.example.net/transactions", "events": ["calendar.objects_changed"]}),
            )
            .unwrap(),
    )
    .await;
    let webhook = created
        .json::<Value>()
        .unwrap()
        .pointer("/webhook/id")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    for (name, path) in [
        ("API tenant (a tenant token)", String::new()),
        ("API list of principals", "/principals".to_owned()),
        ("API principal", "/principals/olivia".to_owned()),
        (
            "API generic client configuration",
            "/principals/olivia/client-config/generic".to_owned(),
        ),
        (
            "API list of app passwords",
            "/principals/olivia/app-passwords".to_owned(),
        ),
        ("API list of feed tokens", "/principals/olivia/feed-tokens".to_owned()),
        ("API list of bindings", "/principals/olivia/bindings".to_owned()),
        ("API list of API tokens", "/api-tokens".to_owned()),
        ("API search for calendars", "/calendars".to_owned()),
        ("API list of webhooks", "/webhooks".to_owned()),
        ("API webhook", format!("/webhooks/{webhook}")),
        ("API list of deliveries", format!("/webhooks/{webhook}/deliveries")),
        ("API list of providers", "/providers".to_owned()),
        ("API list of external accounts", "/external-accounts".to_owned()),
        ("API audit log", "/audit-events".to_owned()),
        ("API outbox", "/outbox".to_owned()),
    ] {
        step(watch, name, admin.get(&format!("{TENANT}{path}"))).await;
    }

    let owner = app.api(&app.token(ActorRole::Owner).unwrap());
    let calendar = format!("{TENANT}/principals/olivia/calendars/personal");
    for (name, path) in [
        (
            "API list of calendars (a principal token)",
            format!("{TENANT}/principals/olivia/calendars"),
        ),
        ("API calendar", calendar.clone()),
        ("API list of objects", format!("{calendar}/objects")),
        ("API list of changes", format!("{calendar}/changes")),
        ("API list of grants", format!("{calendar}/grants")),
    ] {
        step(watch, name, owner.get(&path)).await;
    }
}

async fn mcp(app: &TestApp, watch: &RollbackWatch) {
    let mcp = app.mcp(&app.token(ActorRole::Owner).unwrap());
    for (name, tool, arguments) in [
        ("MCP list_calendars (an MCP token)", "list_calendars", json!({})),
        (
            "MCP list_events",
            "list_events",
            json!({"start": "2027-05-01T00:00:00Z", "end": "2027-07-01T00:00:00Z", "limit": 10}),
        ),
    ] {
        let response = step(watch, name, mcp.call_tool(tool, &arguments).unwrap()).await;
        let message = mcp_message(&response).unwrap();
        assert!(message.get("error").is_none(), "{name}: {message}");
        assert_ne!(
            message.pointer("/result/isError"),
            Some(&Value::Bool(true)),
            "{name}: {message}"
        );
    }
}

async fn feed(app: &TestApp, watch: &RollbackWatch) {
    let admin = app.api(&app.token(ActorRole::TenantToken).unwrap());
    let calendar = app.world().calendar(CalendarRole::Personal).unwrap().key.clone();
    let id = app.index().calendars.get(&calendar).unwrap();
    let issued = step(
        watch,
        "API create of a feed token",
        admin
            .post_json(
                &format!("{TENANT}/principals/olivia/feed-tokens"),
                &json!({"mode": "full", "calendar_ids": [id.to_string()]}),
            )
            .unwrap(),
    )
    .await;
    let body: Value = issued.json().unwrap();
    let secret = body
        .pointer("/feed_url")
        .and_then(Value::as_str)
        .and_then(|url| url.rsplit('/').next())
        .and_then(|name| name.strip_suffix(".ics"))
        .unwrap()
        .to_owned();
    let first = step(watch, "feed (a feed token)", app.feed(&secret).get()).await;
    let etag = first.header("etag").unwrap().to_owned();
    let unchanged = step(
        watch,
        "feed that has not changed",
        app.feed(&secret).get_if_none_match(&etag),
    )
    .await;
    assert_eq!(unchanged.status.as_u16(), 304);
}

async fn invitation_and_rsvp(app: &TestApp, watch: &RollbackWatch) {
    let owner = app.actor(ActorRole::Owner).unwrap();
    let path = format!("{COLLECTION}{INVITATION}");
    step(
        watch,
        "DAV PUT of an invitation",
        app.dav(&owner).put(&path, &invitation(0)),
    )
    .await;
    let summary = app.run_workers_until_idle().await.unwrap();
    assert!(
        summary.processed > 0,
        "the invitation and the events are delivered: {summary:?}"
    );
    assert_committed(watch, "the workers with work (mail, events, webhook deliveries)");

    let token = app
        .mails()
        .to(GUEST)
        .await
        .iter()
        .rev()
        .find_map(|captured| {
            let body = format!(
                "{}\n{}",
                captured.mail.text,
                captured.mail.html.clone().unwrap_or_default()
            );
            rsvp_tokens_in(&body).pop()
        })
        .unwrap();
    step(watch, "RSVP page (an RSVP token)", app.rsvp().view(&token)).await;

    // The outbox is not ordered: an invitation can be handled after the update that replaced it. It is then dropped as done,
    // which is no failure, and what its transaction read is committed.
    step(
        watch,
        "DAV PUT of an update of the invitation",
        app.dav(&owner).put(&path, &invitation(1)),
    )
    .await;
    app.run_workers_until_idle().await.unwrap();
    assert_committed(watch, "the workers with the update");
    let mailed = app.mails().to(GUEST).await.len();
    enqueue_stale_invitation(app).await;
    let summary = app.run_workers_until_idle().await.unwrap();
    assert!(summary.processed > 0, "the stale invitation is handled: {summary:?}");
    assert_committed(watch, "the workers with an invitation that an update superseded");
    assert_eq!(
        app.mails().to(GUEST).await.len(),
        mailed,
        "the superseded invitation is not mailed"
    );
}

/// Queues the first version of the invitation once more, as a record that the dispatcher meets after the update.
async fn enqueue_stale_invitation(app: &TestApp) {
    let deps = app.deps();
    let tenant = app.tenant_id("acme").unwrap();
    let key = app.world().calendar(CalendarRole::Personal).unwrap().key.clone();
    let calendar = *app.index().calendars.get(&key).unwrap();
    let mut tx = deps.database.begin(tenant, TxMode::ReadWrite).await.unwrap();
    let object = tx
        .objects()
        .get(calendar, &ObjectUri::parse(INVITATION).unwrap())
        .await
        .unwrap();
    assert!(object.sequence >= 1, "the update is stored: {}", object.sequence);
    tx.outbox()
        .enqueue(NewOutbox::now(
            OutboxId::from_uuid(deps.ids.new_id()),
            OutboxMessage::Imip(ImipJob {
                object: object.id,
                recipient: CalendarUserAddress::parse(&format!("mailto:{GUEST}")).unwrap(),
                method: ItipMethod::Request,
                locale: None,
                template: TemplateName::parse("imip_request").unwrap(),
                snapshot: Some(invitation(0)),
                replying_attendee: None,
                comment: None,
            }),
        ))
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn every_transaction_that_succeeds_is_committed() {
    let watch = RollbackWatch::new();
    let layer = watch.clone();
    let app = TestApp::builder()
        .database_layer(move |database| layer.wrap(database))
        .build()
        .await
        .unwrap();
    assert!(watch.begun() > 0, "the world is seeded through the watched store");
    assert_committed(&watch, "seeding the world");

    let summary = app.run_workers_until_idle().await.unwrap();
    assert!(summary.processed > 0, "the seeding left events to deliver: {summary:?}");
    assert_committed(&watch, "the workers with the work of the seeding");
    let idle = app.run_workers_until_idle().await.unwrap();
    assert_eq!(idle.processed, 0, "{idle:?}");
    assert_committed(&watch, "the workers with nothing to do");

    let begun = watch.begun();
    caldav(&app, &watch).await;
    management_api(&app, &watch).await;
    mcp(&app, &watch).await;
    feed(&app, &watch).await;
    invitation_and_rsvp(&app, &watch).await;
    // The uses of the credentials of the requests are written by a worker.
    app.run_workers_until_idle().await.unwrap();
    assert_committed(&watch, "the workers after the requests");
    assert!(
        watch.begun() > begun + 40,
        "the steps ran their transactions through the watched store: {} before, {} after",
        begun,
        watch.begun()
    );
    let idle = app.run_workers_until_idle().await.unwrap();
    assert_eq!(idle.processed, 0, "{idle:?}");
    assert_committed(&watch, "the workers with nothing to do, at the end");
}
