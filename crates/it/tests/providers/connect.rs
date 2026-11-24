//! The OAuth flow: starting it, the callback, what a connection creates, and everything that must not connect.

use davhaven_testkit::StoreKind;
use davhaven_testkit::davhaven_domain::PrincipalStatus;
use davhaven_testkit::davhaven_fixtures::names;
use davhaven_testkit::davhaven_provider_fake::provider::FakeProvider;
use serde_json::Value;

use super::support::{World, on_both_stores};

fn code_of(response: &davhaven_testkit::TestResponse) -> String {
    response.json::<Value>().unwrap()["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

// ---------------------------------------------------------------------------------------------------------------
// A connection
// ---------------------------------------------------------------------------------------------------------------

/// Nobody writes to a mirror but the sync engine: not the owner with a calendar client, not a tenant token over the API.
async fn nobody_writes_to_the_mirror(world: &World, slug: &str, account: &Value) {
    let dav = world.app.dav(
        &world
            .app
            .actor(davhaven_testkit::davhaven_fixtures::ActorRole::Owner)
            .unwrap(),
    );
    let put = dav
        .put(
            &format!("/dav/calendars/acme/olivia/{slug}/mine.ics"),
            &davhaven_testkit::davhaven_provider_fake::script::simple_event(
                "mine",
                "Mine",
                "20270105T090000Z",
                "20270105T100000Z",
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.status.as_u16(), 403, "{}", put.excerpt(300));
    // The owner's own token (`events:write`) is the caller that only the rule for mirrors refuses: a tenant token is refused for the
    // events of every personal calendar, mirror or not, and would prove nothing.
    let owner = world
        .app
        .token(davhaven_testkit::davhaven_fixtures::ActorRole::Owner)
        .unwrap();
    let write = world
        .app
        .api(&owner)
        .request(
            "PUT",
            &format!(
                "{}/principals/olivia/calendars/{slug}/objects/by-key/mine",
                world.base()
            ),
        )
        .json(
            "application/json",
            &serde_json::json!({"start": {"date_time": "2027-01-05T09:00:00Z"}, "summary": "Mine"}),
        )
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(
        write.status.as_u16(),
        403,
        "the API does not write to a mirror either: {}",
        write.excerpt(300)
    );
    assert_eq!(world.summaries(account).await, Vec::<String>::new());
}

async fn a_connection_creates_the_account_and_a_read_only_mirror(store: StoreKind) {
    let world = World::new(store).await;
    let started = world.start("fake", World::OWNER).await;
    assert_eq!(started.status.as_u16(), 200, "{}", started.excerpt(300));
    assert_eq!(
        started.header("cache-control"),
        Some("no-store"),
        "the answer carries a state"
    );
    let body: Value = started.json().unwrap();
    let url = url::Url::parse(body["authorization_url"].as_str().unwrap()).unwrap();
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let value = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .unwrap()
    };
    assert_eq!(value("code_challenge_method"), "S256");
    assert_eq!(
        value("code_challenge").len(),
        43,
        "the SHA-256 of the verifier, as unpadded base64"
    );
    assert_eq!(value("redirect_uri"), "https://cal.example.org/oauth/fake/callback");
    assert!(value("state").starts_with(&format!("{}.", world.app.tenant_id("acme").unwrap().as_uuid().simple())));
    assert!(
        world.accounts().await.is_empty(),
        "nothing is connected before the person consents"
    );

    let page = world
        .callback("fake", &format!("code=fake-olivia&state={}", value("state")))
        .await;
    assert_eq!(page.status.as_u16(), 200, "{}", page.excerpt(300));
    assert!(page.text().contains("Calendar connected"), "{}", page.excerpt(600));
    assert!(
        page.header("content-type")
            .is_some_and(|value| value.starts_with("text/html")),
        "{:?}",
        page.header("content-type")
    );

    let accounts = world.accounts().await;
    assert_eq!(accounts.len(), 1);
    let account = accounts.first().unwrap();
    assert_eq!(account["provider"], "fake");
    assert_eq!(account["account_ref"], "olivia@fake.example");
    assert_eq!(account["principal"], "olivia");
    assert_eq!(account["status"], "active");
    assert!(account.get("last_error").is_none(), "{account}");
    assert!(
        !account.to_string().to_lowercase().contains("token"),
        "a view never carries tokens: {account}"
    );

    // The mirror: a calendar of the owner, of its own kind, named after the provider and the account.
    let mirror = world.mirror(account).await.expect("the owner has the mirror calendar");
    assert_eq!(mirror["kind"], "mirror");
    assert_eq!(mirror["display_name"], "Fake: olivia@fake.example");
    assert_eq!(mirror["components"], serde_json::json!(["event"]));
    let slug = mirror["slug"].as_str().unwrap().to_owned();
    assert!(slug.starts_with("fake-"), "{slug}");

    nobody_writes_to_the_mirror(&world, &slug, account).await;

    // The connection is on the audit log, and the mirror was announced like any new calendar.
    assert!(
        world
            .audit_actions()
            .await
            .contains(&"external_account.created".to_owned())
    );
}

on_both_stores!(connection, a_connection_creates_the_account_and_a_read_only_mirror);

// ---------------------------------------------------------------------------------------------------------------
// What must not connect
// ---------------------------------------------------------------------------------------------------------------

async fn a_state_works_once(store: StoreKind) {
    let world = World::new(store).await;
    let started = world.start("fake", World::OWNER).await;
    let state = World::state_of(&started);
    let first = world.callback("fake", &format!("code=fake-olivia&state={state}")).await;
    assert_eq!(first.status.as_u16(), 200);
    let again = world
        .callback("fake", &format!("code=fake-olivia2&state={state}"))
        .await;
    assert_eq!(again.status.as_u16(), 404, "{}", again.excerpt(300));
    assert_eq!(world.accounts().await.len(), 1, "the second callback connected nothing");
}

on_both_stores!(state_once, a_state_works_once);

async fn a_state_belongs_to_the_provider_it_was_made_for(store: StoreKind) {
    let world = World::new(store).await;
    let state = World::state_of(&world.start("fake", World::OWNER).await);
    let other = world
        .callback("google", &format!("code=fake-olivia&state={state}"))
        .await;
    assert_eq!(other.status.as_u16(), 404, "{}", other.excerpt(300));
    // The state was used up by the attempt: what stole it cannot use it at the right provider either.
    let right = world.callback("fake", &format!("code=fake-olivia&state={state}")).await;
    assert_eq!(right.status.as_u16(), 404);
    assert!(world.accounts().await.is_empty());
}

on_both_stores!(state_provider, a_state_belongs_to_the_provider_it_was_made_for);

async fn what_is_not_a_state_of_this_server_reveals_nothing(store: StoreKind) {
    let world = World::new(store).await;
    let genuine = World::state_of(&world.start("fake", World::OWNER).await);
    let secret = genuine.split_once('.').unwrap().1;
    let tenant = world.app.tenant_id("acme").unwrap().as_uuid().simple().to_string();
    let other_tenant = world.app.tenant_id("globex").unwrap().as_uuid().simple().to_string();
    for query in [
        String::new(),
        "code=fake-olivia".to_owned(),
        "state=garbage&code=fake-olivia".to_owned(),
        format!("state={tenant}.{}&code=fake-olivia", "a".repeat(43)),
        // The secret of one tenant under the id of the other: the state names a tenant whose transaction does not hold it.
        format!("state={other_tenant}.{secret}&code=fake-olivia"),
        format!("state={}&code=fake-olivia", "x".repeat(600)),
    ] {
        let page = world.callback("fake", &query).await;
        let status = page.status.as_u16();
        assert!(
            matches!(status, 400 | 404),
            "{query:.40}: {status} {}",
            page.excerpt(200)
        );
    }
    assert!(world.accounts().await.is_empty());
    // The genuine state is still good: none of that used it up.
    let page = world
        .callback("fake", &format!("code=fake-olivia&state={genuine}"))
        .await;
    assert_eq!(page.status.as_u16(), 200, "{}", page.excerpt(300));
    assert_eq!(world.accounts().await.len(), 1);
}

on_both_stores!(not_a_state, what_is_not_a_state_of_this_server_reveals_nothing);

async fn a_state_expires_after_ten_minutes(store: StoreKind) {
    let world = World::new(store).await;
    let state = World::state_of(&world.start("fake", World::OWNER).await);
    world.pass(11);
    let page = world.callback("fake", &format!("code=fake-olivia&state={state}")).await;
    assert_eq!(page.status.as_u16(), 404, "{}", page.excerpt(300));
    assert!(world.accounts().await.is_empty());
    // Nine minutes are within the window.
    let fresh = World::state_of(&world.start("fake", World::OWNER).await);
    world.pass(9);
    let page = world.callback("fake", &format!("code=fake-olivia&state={fresh}")).await;
    assert_eq!(page.status.as_u16(), 200, "{}", page.excerpt(300));
}

on_both_stores!(state_expiry, a_state_expires_after_ten_minutes);

#[tokio::test]
async fn a_refused_consent_and_a_rejected_code_end_on_a_page_that_says_so() {
    let world = World::new(StoreKind::Memory).await;
    for failure in ["error=access_denied", "code=fake-olivia-refused"] {
        world.script.reject_code("fake-olivia-refused");
        let state = World::state_of(&world.start("fake", World::OWNER).await);
        let page = world.callback("fake", &format!("{failure}&state={state}")).await;
        assert_eq!(page.status.as_u16(), 200, "{failure}: {}", page.excerpt(300));
        assert!(
            page.text().contains("Connection failed"),
            "{failure}: {}",
            page.excerpt(600)
        );
        assert!(
            !page.text().contains("fake-olivia") && !page.text().contains("access_denied"),
            "the page does not repeat what the provider or the browser said"
        );
        // The state is used up: the page cannot be replayed with a code that works.
        let replay = world.callback("fake", &format!("code=fake-olivia&state={state}")).await;
        assert_eq!(replay.status.as_u16(), 404, "{failure}");
    }
    assert!(world.accounts().await.is_empty(), "nothing was connected");
}

#[tokio::test]
async fn an_account_without_calendars_connects_nothing_and_gives_its_access_back() {
    let world = World::new(StoreKind::Memory).await;
    world.script.set_calendars(Vec::new());
    let page = world.flow(World::OWNER, "fake-olivia").await;
    assert_eq!(page.status.as_u16(), 200);
    assert!(page.text().contains("Connection failed"), "{}", page.excerpt(600));
    assert!(world.accounts().await.is_empty());
    assert_eq!(
        world.script.revoked_tokens().len(),
        1,
        "the tokens of the connection that came to nothing are revoked"
    );
}

#[tokio::test]
async fn a_person_who_is_suspended_at_the_consent_screen_connects_nothing_and_the_access_is_given_back() {
    let world = World::new(StoreKind::Memory).await;
    let state = World::state_of(&world.start("fake", World::OWNER).await);
    // An administrator suspends the person while they are at the provider.
    world.set_status(World::OWNER, PrincipalStatus::Suspended).await;
    let page = world.callback("fake", &format!("code=fake-olivia&state={state}")).await;
    assert_eq!(page.status.as_u16(), 200, "{}", page.excerpt(300));
    assert!(page.text().contains("Connection failed"), "{}", page.excerpt(600));
    assert!(world.accounts().await.is_empty(), "no account was written");
    assert_eq!(
        world.script.revoked_tokens().len(),
        1,
        "nobody holds the grant, so the tokens that were just issued are revoked"
    );
}

#[tokio::test]
async fn a_provider_that_is_off_or_unknown_cannot_start_a_flow() {
    let world = World::new(StoreKind::Memory).await;
    // Google is known to the project and not in this world (nothing selected it): off.
    let off = world.start("google", World::OWNER).await;
    assert_eq!(
        (off.status.as_u16(), code_of(&off).as_str()),
        (409, "feature-not-enabled"),
        "{}",
        off.excerpt(300)
    );
    let unknown = world.start("nonsense", World::OWNER).await;
    assert_eq!(unknown.status.as_u16(), 404, "{}", unknown.excerpt(300));
    // A provider that is selected and switched off is off as well.
    let disabled = World::with_provider(StoreKind::Memory, |clock| {
        FakeProvider::new(std::sync::Arc::new(clock.clone())).disabled()
    })
    .await;
    let off = disabled.start("fake", World::OWNER).await;
    assert_eq!(
        (off.status.as_u16(), code_of(&off).as_str()),
        (409, "feature-not-enabled"),
        "{}",
        off.excerpt(300)
    );
    assert!(disabled.accounts().await.is_empty());
}

#[tokio::test]
async fn only_users_connect_accounts() {
    let world = World::new(StoreKind::Memory).await;
    let missing = world.start("fake", "nobody").await;
    assert_eq!(missing.status.as_u16(), 404, "{}", missing.excerpt(300));
    for (principal, code) in [
        (names::TEAM, "not-a-user"),
        (names::RESOURCE, "not-a-user"),
        (names::SERVICE_PRINCIPAL, "not-a-user"),
        (names::SUSPENDED_USER, "suspended"),
    ] {
        let refused = world.start("fake", principal).await;
        assert_eq!(refused.status.as_u16(), 422, "{principal}: {}", refused.excerpt(300));
        let problem: Value = refused.json().unwrap();
        assert_eq!(problem["errors"][0]["pointer"], "/principal", "{principal}: {problem}");
        assert_eq!(problem["errors"][0]["code"], code, "{principal}: {problem}");
    }
    let other_tenant = world
        .api()
        .post_json(
            &format!("{}/external-accounts", world.base()),
            &serde_json::json!({"provider": "fake", "principal": names::OTHER_TENANT_USER}),
        )
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(
        other_tenant.status.as_u16(),
        404,
        "a principal of another tenant does not exist here: {}",
        other_tenant.excerpt(300)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// More than once
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn connecting_the_same_account_again_replaces_its_tokens_and_keeps_its_mirror() {
    let world = World::new(StoreKind::Memory).await;
    world.script.put_event("primary", "e1", simple("e1", "One"));
    let first = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    assert_eq!(world.summaries(&first).await, vec!["One".to_owned()]);

    // The person removed the access: the next pull finds out, and the account is off.
    world.script.revoke_access();
    world.pass(16);
    world.work().await;
    let off = world.account(first["id"].as_str().unwrap()).await;
    assert_eq!(off["status"], "disabled");
    assert!(off["last_error"].as_str().unwrap().starts_with("auth_revoked"), "{off}");

    // Connecting again is the way back: the same account and the same mirror, with working tokens.
    let again = world.connect(World::OWNER, "olivia").await;
    assert_eq!(
        again["id"], first["id"],
        "the account of the same person at the same provider is one account"
    );
    assert_eq!(again["mirror_calendar_id"], first["mirror_calendar_id"]);
    assert_eq!(again["status"], "active");
    assert!(again.get("last_error").is_none(), "{again}");
    for field in ["last_sync_at", "next_sync_at", "last_error_code"] {
        assert!(again.get(field).is_none(), "reconnection clears {field}: {again}");
    }
    assert_eq!(world.accounts().await.len(), 1);
    assert_eq!(
        world
            .calendars_of(World::OWNER)
            .await
            .iter()
            .filter(|calendar| calendar["kind"] == "mirror")
            .count(),
        // The world has a mirror of its own (`google`), and this account has one.
        2
    );
    world.script.put_event("primary", "e2", simple("e2", "Two"));
    world.pass(16);
    world.work().await;
    assert_eq!(world.summaries(&again).await, vec!["One".to_owned(), "Two".to_owned()]);
}

#[tokio::test]
async fn two_accounts_of_one_person_have_two_mirrors() {
    let world = World::new(StoreKind::Memory).await;
    let first = world.connect(World::OWNER, "olivia").await;
    let second = world.connect(World::OWNER, "olivia-work").await;
    assert_ne!(first["id"], second["id"]);
    assert_ne!(first["mirror_calendar_id"], second["mirror_calendar_id"]);
    let slugs: Vec<String> = world
        .calendars_of(World::OWNER)
        .await
        .into_iter()
        .filter(|calendar| calendar["slug"].as_str().unwrap().starts_with("fake-"))
        .map(|calendar| calendar["slug"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(slugs.len(), 2, "{slugs:?}");
    assert_eq!(world.accounts().await.len(), 2);
}

// ---------------------------------------------------------------------------------------------------------------
// The providers
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_providers_are_listed_whether_or_not_they_are_on() {
    let world = World::new(StoreKind::Memory).await;
    let listed = world
        .api()
        .get(&format!("{}/providers", world.base()))
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status.as_u16(), 200, "{}", listed.excerpt(300));
    let page: Value = listed.json().unwrap();
    assert_eq!(
        page["items"],
        serde_json::json!([
            {"name": "fake", "enabled": true},
            {"name": "google", "enabled": false},
            {"name": "microsoft", "enabled": false},
        ]),
        "the providers of the project are there even when the deployment has not got them"
    );
    assert!(
        page["next_cursor"].is_null() || page.get("next_cursor").is_none(),
        "{page}"
    );
}

/// The ICS of a one-hour event on 5 January 2027.
fn simple(uid: &str, summary: &str) -> String {
    davhaven_testkit::davhaven_provider_fake::script::simple_event(uid, summary, "20270105T090000Z", "20270105T100000Z")
}
