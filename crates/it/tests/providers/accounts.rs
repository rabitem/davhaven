//! The accounts of a tenant: the list, the disconnection and who may do either.

use davhaven_testkit::StoreKind;
use davhaven_testkit::davhaven_domain::{EventType, Scope};
use davhaven_testkit::davhaven_fixtures::{ActorRole, names};
use davhaven_testkit::davhaven_ports::PortError;
use davhaven_testkit::davhaven_provider_fake::script::Call;
use serde_json::Value;

use super::support::{World, on_both_stores};

fn id_of(account: &Value) -> String {
    account["id"].as_str().unwrap().to_owned()
}

// ---------------------------------------------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_list_is_paged_in_the_order_of_the_ids_and_shows_no_secret() {
    let world = World::new(StoreKind::Memory).await;
    let mut connected = Vec::new();
    for name in ["olivia", "olivia-two", "olivia-three"] {
        connected.push(id_of(&world.connect(World::OWNER, name).await));
    }
    let first = world
        .api()
        .get(&format!("{}/external-accounts?limit=2", world.base()))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status.as_u16(), 200);
    let page: Value = first.json().unwrap();
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let cursor = page["next_cursor"]
        .as_str()
        .expect("a third account is waiting")
        .to_owned();
    assert!(
        first.header("link").is_some_and(|link| link.contains("next")),
        "{:?}",
        first.header("link")
    );
    let second = world
        .api()
        .get(&format!("{}/external-accounts?limit=2&cursor={cursor}", world.base()))
        .send()
        .await
        .unwrap();
    let rest: Value = second.json().unwrap();
    assert_eq!(rest["items"].as_array().unwrap().len(), 1);
    assert!(rest["next_cursor"].is_null() || rest.get("next_cursor").is_none());
    let mut listed: Vec<String> = items
        .iter()
        .chain(rest["items"].as_array().unwrap())
        .map(id_of)
        .collect();
    let mut sorted = listed.clone();
    sorted.sort();
    assert_eq!(listed, sorted, "the order of the ids");
    listed.sort();
    connected.sort();
    assert_eq!(listed, connected);
    let body = format!("{page}{rest}").to_lowercase();
    for secret in ["token", "secret", "verifier", "ya29", "sealed"] {
        assert!(!body.contains(secret), "{secret} in {body}");
    }
    // A cursor of this list opens no other list.
    let other = world
        .api()
        .get(&format!("{}/webhooks?cursor={cursor}", world.base()))
        .send()
        .await
        .unwrap();
    assert!(matches!(other.status.as_u16(), 400 | 422), "{}", other.excerpt(300));
}

// ---------------------------------------------------------------------------------------------------------------
// The disconnection
// ---------------------------------------------------------------------------------------------------------------

async fn disconnecting_removes_the_account_and_the_mirror_and_gives_the_access_back(store: StoreKind) {
    let world = World::new(store).await;
    world.script.put_event(
        "primary",
        "e1",
        davhaven_testkit::davhaven_provider_fake::script::simple_event(
            "e1",
            "One",
            "20270105T090000Z",
            "20270105T100000Z",
        ),
    );
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    assert_eq!(world.summaries(&account).await, vec!["One".to_owned()]);
    let mirror = world.mirror(&account).await.unwrap();
    let id = id_of(&account);
    world.app.events().clear().await;

    let deleted = world
        .api()
        .delete(&format!("{}/external-accounts/{id}", world.base()), None)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status.as_u16(), 204, "{}", deleted.excerpt(300));
    assert!(world.accounts().await.is_empty());
    assert!(
        world.mirror(&account).await.is_none(),
        "the mirror calendar is deleted with its account: {mirror}"
    );
    assert_eq!(
        world.script.revoked_tokens().len(),
        1,
        "the provider was asked to forget the access"
    );
    let audit = world.audit_actions().await;
    assert!(audit.contains(&"external_account.deleted".to_owned()), "{audit:?}");
    world.work().await;
    assert_eq!(
        world.app.events().of_type(EventType::CalendarDeleted).await.len(),
        1,
        "the calendar went like any calendar does"
    );

    // Gone is gone: the same request again is an account that does not exist, and the pull of the worker finds nothing.
    let again = world
        .api()
        .delete(&format!("{}/external-accounts/{id}", world.base()), None)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status.as_u16(), 404, "{}", again.excerpt(300));
    let calls = world.script.calls().len();
    world.pass(60);
    world.work().await;
    assert_eq!(world.script.calls().len(), calls);
}

on_both_stores!(
    disconnection,
    disconnecting_removes_the_account_and_the_mirror_and_gives_the_access_back
);

#[tokio::test]
async fn a_provider_that_cannot_revoke_does_not_keep_the_account() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    world
        .script
        .fail_next(Call::Revoke, PortError::unavailable("the revocation endpoint is down"));
    let deleted = world
        .api()
        .delete(&format!("{}/external-accounts/{}", world.base(), id_of(&account)), None)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status.as_u16(), 204, "{}", deleted.excerpt(300));
    assert!(world.accounts().await.is_empty());
    assert_eq!(world.script.count(Call::Revoke), 1);
}

#[tokio::test]
async fn an_account_that_was_switched_off_can_be_disconnected_too() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    world.script.revoke_access();
    world.pass(16);
    world.work().await;
    assert_eq!(world.account(&id_of(&account)).await["status"], "disabled");
    let deleted = world
        .api()
        .delete(&format!("{}/external-accounts/{}", world.base(), id_of(&account)), None)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status.as_u16(), 204, "{}", deleted.excerpt(300));
    assert!(world.accounts().await.is_empty());
}

async fn a_mirror_goes_with_its_account_and_cannot_be_deleted_on_its_own(store: StoreKind) {
    let world = World::new(store).await;
    let account = world.connect(World::OWNER, "olivia").await;
    let mirror = world.mirror(&account).await.unwrap();
    let path = format!(
        "{}/principals/olivia/calendars/{}",
        world.base(),
        mirror["slug"].as_str().unwrap()
    );
    // The tenant token holds every scope, and it is the one actor that may delete the calendar of a person. The mirror is the
    // exception: deleted on its own it would leave the account with nothing to pull into.
    let refused = world.api().delete(&path, Some("\"v1\"")).send().await.unwrap();
    assert_eq!(refused.status.as_u16(), 403, "{}", refused.excerpt(300));
    assert!(world.mirror(&account).await.is_some(), "the mirror is still there");
    assert_eq!(world.account(&id_of(&account)).await["status"], "active");
    // The way to delete it is to disconnect the account, which takes the mirror with it.
    let deleted = world
        .api()
        .delete(&format!("{}/external-accounts/{}", world.base(), id_of(&account)), None)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status.as_u16(), 204, "{}", deleted.excerpt(300));
    assert!(world.mirror(&account).await.is_none());
}

on_both_stores!(
    mirror_deletion,
    a_mirror_goes_with_its_account_and_cannot_be_deleted_on_its_own
);

#[tokio::test]
async fn the_access_is_given_back_only_when_no_account_is_left_that_holds_the_grant() {
    let world = World::new(StoreKind::Memory).await;
    // The same account of the provider, connected for two people of the tenant: at some providers revoking one token of the
    // grant ends the grant for both.
    let first = world.connect(World::OWNER, "shared").await;
    let second = world.connect(names::OTHER_USER, "shared").await;
    assert_ne!(id_of(&first), id_of(&second));
    let deleted = world
        .api()
        .delete(&format!("{}/external-accounts/{}", world.base(), id_of(&first)), None)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status.as_u16(), 204, "{}", deleted.excerpt(300));
    assert_eq!(
        world.script.revoked_tokens().len(),
        0,
        "the other account still holds the grant: nothing is revoked"
    );
    let deleted = world
        .api()
        .delete(&format!("{}/external-accounts/{}", world.base(), id_of(&second)), None)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status.as_u16(), 204, "{}", deleted.excerpt(300));
    assert_eq!(
        world.script.revoked_tokens().len(),
        1,
        "the last account of the grant gives the access back"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Who may
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_scope_providers_manage_does_all_four_and_nothing_else_does_any() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    let id = id_of(&account);
    let manage = world.api_with(Scope::ProvidersManage);
    for path in ["providers", "external-accounts"] {
        let listed = manage.get(&format!("{}/{path}", world.base())).send().await.unwrap();
        assert_eq!(listed.status.as_u16(), 200, "{path}: {}", listed.excerpt(300));
    }
    for scope in [
        Scope::EventsRead,
        Scope::WebhooksManage,
        Scope::CalendarsWrite,
        Scope::AuditRead,
    ] {
        let api = world.api_with(scope);
        for (method, path) in [
            ("GET", "providers".to_owned()),
            ("GET", "external-accounts".to_owned()),
            ("DELETE", format!("external-accounts/{id}")),
        ] {
            let refused = api
                .request(method, &format!("{}/{path}", world.base()))
                .send()
                .await
                .unwrap();
            assert_eq!(
                refused.status.as_u16(),
                403,
                "{scope:?} {method} {path}: {}",
                refused.excerpt(300)
            );
        }
        let start = api
            .post_json(
                &format!("{}/external-accounts", world.base()),
                &serde_json::json!({"provider": "fake", "principal": "olivia"}),
            )
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(start.status.as_u16(), 403, "{scope:?}: {}", start.excerpt(300));
    }
    // A refusal changed nothing.
    assert_eq!(world.accounts().await.len(), 1);
    // The person themselves cannot: principals never administer.
    let owner = world.app.token(ActorRole::Owner).unwrap();
    let refused = world
        .app
        .api(&owner)
        .get(&format!("{}/external-accounts", world.base()))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status.as_u16(), 403, "{}", refused.excerpt(300));
    // The scope disconnects.
    let deleted = manage
        .delete(&format!("{}/external-accounts/{id}", world.base()), None)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status.as_u16(), 204, "{}", deleted.excerpt(300));
}

async fn another_tenant_sees_nothing_of_the_accounts_of_this_one(store: StoreKind) {
    let world = World::new(store).await;
    let account = world.connect(World::OWNER, "olivia").await;
    let id = id_of(&account);
    let other_admin = world.app.token(ActorRole::OtherTenantToken).unwrap();
    let other = world.app.api(&other_admin);
    let other_base = format!("/api/v1/tenants/{}", world.app.world().names.other_tenant);
    // At home the administrator of the other tenant sees an empty list, and the id of an account of this tenant is no account.
    let listed = other
        .get(&format!("{other_base}/external-accounts"))
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status.as_u16(), 200);
    let page: Value = listed.json().unwrap();
    assert_eq!(page["items"], serde_json::json!([]));
    let missing = other
        .delete(&format!("{other_base}/external-accounts/{id}"), None)
        .send()
        .await
        .unwrap();
    let nothing = other
        .delete(
            &format!("{other_base}/external-accounts/00000000-0000-7000-8000-000000000000"),
            None,
        )
        .send()
        .await
        .unwrap();
    assert_eq!((missing.status.as_u16(), nothing.status.as_u16()), (404, 404));
    let code = |response: &davhaven_testkit::TestResponse| response.json::<Value>().unwrap()["code"].clone();
    assert_eq!(
        code(&missing),
        code(&nothing),
        "an account of another tenant is answered like one that is not there"
    );
    // In the tenant of the accounts they are hidden altogether.
    let foreign = other
        .get(&format!(
            "/api/v1/tenants/{}/external-accounts",
            world.app.world().names.tenant
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status.as_u16(), 404);
    // A flow started in one tenant cannot be finished in another: the state names its own.
    let started = world.start("fake", World::OWNER).await;
    let state = World::state_of(&started);
    let tenant = world.app.tenant_id("acme").unwrap().as_uuid().simple().to_string();
    let globex = world.app.tenant_id("globex").unwrap().as_uuid().simple().to_string();
    let moved = state.replacen(&tenant, &globex, 1);
    assert_ne!(moved, state);
    let page = world.callback("fake", &format!("code=fake-olivia&state={moved}")).await;
    assert_eq!(page.status.as_u16(), 404);
    assert_eq!(
        world.accounts().await.len(),
        1,
        "the account of the first flow, and nothing from the forged one"
    );
}

on_both_stores!(other_tenant, another_tenant_sees_nothing_of_the_accounts_of_this_one);
