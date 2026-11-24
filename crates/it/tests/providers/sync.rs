//! The sync worker: what a pull writes into the mirror, and what it does when the provider or the account fails.

use chrono::Duration;
use davhaven_testkit::StoreKind;
use davhaven_testkit::davhaven_app::AppCore;
use davhaven_testkit::davhaven_app::sync_engine::{ProviderSyncWorker, SyncOutcome};
use davhaven_testkit::davhaven_domain::{ApiLimits, EventType, ExternalAccountId, Limits, PrincipalStatus};
use davhaven_testkit::davhaven_fixtures::{ActorRole, names};
use davhaven_testkit::davhaven_ports::{Clock, PortError, PortErrorKind, Provider, Worker};
use davhaven_testkit::davhaven_provider_fake::script::{Call, Mode, simple_event};
use serde_json::Value;

use super::support::{World, on_both_stores};

/// The ICS of a one-hour event on 5 January 2027.
fn event(uid: &str, summary: &str) -> String {
    simple_event(uid, summary, "20270105T090000Z", "20270105T100000Z")
}

fn text(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// How many requests for the changes of the calendar the provider has seen.
fn pulls(world: &World) -> usize {
    world.script.count(Call::Changes)
}

// ---------------------------------------------------------------------------------------------------------------
// What a pull writes
// ---------------------------------------------------------------------------------------------------------------

async fn a_mirror_follows_its_calendar(store: StoreKind) {
    let world = World::new(store).await;
    world.script.put_event("primary", "e1", event("e1", "One"));
    world.script.put_event("primary", "e2", event("e2", "Two"));
    let account = world.connect(World::OWNER, "olivia").await;
    for field in ["last_sync_at", "next_sync_at", "last_error_code"] {
        assert!(account.get(field).is_none(), "a new account has no {field}: {account}");
    }
    assert_eq!(
        world.summaries(&account).await,
        Vec::<String>::new(),
        "nothing is pulled before the worker runs"
    );

    // The account is due as soon as it is connected.
    let first_sync = world.app.clock().now();
    world.work().await;
    assert_eq!(world.summaries(&account).await, text(&["One", "Two"]));
    assert_eq!(pulls(&world), 1);
    let synced = world.account(account["id"].as_str().unwrap()).await;
    assert_eq!(synced["last_sync_at"], serde_json::json!(first_sync));
    assert_eq!(
        synced["next_sync_at"],
        serde_json::json!(first_sync + Duration::minutes(15))
    );
    assert!(synced.get("last_error_code").is_none(), "{synced}");
    let token = world.sync_token(&account).await;
    let etags = world.events(&account).await;

    // It is then pulled every 15 minutes, and not at every pass of the worker.
    world.pass(14);
    world.work().await;
    assert_eq!(pulls(&world), 1, "not due yet");
    world.pass(2);
    world.work().await;
    assert_eq!(pulls(&world), 2);
    assert_eq!(
        world.sync_token(&account).await,
        token,
        "a calendar that did not change is not written"
    );
    assert_eq!(
        world.events(&account).await,
        etags,
        "and its events keep their entity tags"
    );

    // One event changed, one is new and one is gone.
    world.script.put_event("primary", "e1", event("e1", "One (moved)"));
    world.script.put_event("primary", "e3", event("e3", "Three"));
    world.script.remove_event("primary", "e2");
    world.pass(16);
    world.work().await;
    assert_eq!(world.summaries(&account).await, text(&["One (moved)", "Three"]));
    assert_ne!(
        world.sync_token(&account).await,
        token,
        "the mirror changed, so its sync token did"
    );
    let view = world.account(account["id"].as_str().unwrap()).await;
    assert_eq!(view["status"], "active");
    assert!(view.get("last_error").is_none(), "{view}");
    assert_eq!(
        view["last_sync_at"],
        serde_json::json!(first_sync + Duration::minutes(32))
    );
    assert_eq!(
        view["next_sync_at"],
        serde_json::json!(first_sync + Duration::minutes(47))
    );
}

on_both_stores!(following, a_mirror_follows_its_calendar);

#[tokio::test]
async fn a_provider_without_a_change_feed_is_pulled_as_a_snapshot() {
    let world = World::new(StoreKind::Memory).await;
    world.script.set_mode(Mode::Snapshot);
    world.script.put_event("primary", "e1", event("e1", "One"));
    world.script.put_event("primary", "e2", event("e2", "Two"));
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    assert_eq!(world.summaries(&account).await, text(&["One", "Two"]));
    // What the list no longer names was deleted remotely.
    world.script.remove_event("primary", "e1");
    world.script.put_event("primary", "e3", event("e3", "Three"));
    world.pass(16);
    world.work().await;
    assert_eq!(world.summaries(&account).await, text(&["Three", "Two"]));
    // An empty calendar is an empty mirror.
    world.script.remove_event("primary", "e2");
    world.script.remove_event("primary", "e3");
    world.pass(16);
    world.work().await;
    assert_eq!(world.summaries(&account).await, Vec::<String>::new());
}

#[tokio::test]
async fn a_large_calendar_is_stored_in_chunks_and_trimmed_in_chunks() {
    let world = World::tweaked(StoreKind::Memory, |builder| {
        builder.limits(Limits {
            api: ApiLimits {
                max_batch_items: 3,
                ..ApiLimits::default()
            },
            ..Limits::default()
        })
    })
    .await;
    world.script.set_mode(Mode::Snapshot);
    for number in 0..10 {
        world.script.put_event(
            "primary",
            &format!("e{number}"),
            event(&format!("e{number}"), &format!("Event {number}")),
        );
    }
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    assert_eq!(
        world.summaries(&account).await.len(),
        10,
        "four batches of at most three"
    );
    for number in 0..8 {
        world.script.remove_event("primary", &format!("e{number}"));
    }
    world.pass(16);
    world.work().await;
    assert_eq!(world.summaries(&account).await, text(&["Event 8", "Event 9"]));
}

#[tokio::test]
async fn an_event_that_cannot_be_stored_does_not_stop_the_calendar() {
    let world = World::new(StoreKind::Memory).await;
    world.script.put_event(
        "primary",
        "bad",
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    world.script.put_event("primary", "good", event("good", "Good"));
    // Two events of the provider that share one UID: the calendar keeps the first.
    world.script.put_event("primary", "twin-a", event("twin", "Twin A"));
    world.script.put_event("primary", "twin-b", event("twin", "Twin B"));
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    let summaries = world.summaries(&account).await;
    assert!(summaries.contains(&"Good".to_owned()), "{summaries:?}");
    assert!(!summaries.iter().any(String::is_empty), "{summaries:?}");
    assert_eq!(
        summaries.iter().filter(|summary| summary.starts_with("Twin")).count(),
        1,
        "{summaries:?}"
    );
    let view = world.account(account["id"].as_str().unwrap()).await;
    assert_eq!(view["status"], "active", "{view}");
    // The cursor moved on: the next pull does not try the same events again with the same result.
    world.pass(16);
    world.work().await;
    assert_eq!(world.summaries(&account).await, summaries);
}

#[tokio::test]
async fn a_cursor_the_provider_forgot_starts_a_full_pull() {
    let world = World::new(StoreKind::Memory).await;
    world.script.put_event("primary", "e1", event("e1", "One"));
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    world.script.forget_history();
    world.script.put_event("primary", "e2", event("e2", "Two"));
    world.script.remove_event("primary", "e1");
    world.pass(16);
    world.work().await;
    assert_eq!(
        world.summaries(&account).await,
        text(&["Two"]),
        "what was missed in between is caught up"
    );
    let asks_for_everything = world
        .script
        .calls()
        .iter()
        .filter(|call| call.as_str() == "changes_since primary -")
        .count();
    assert_eq!(
        asks_for_everything,
        2,
        "the first pull and the one that started again: {:?}",
        world.script.calls()
    );
    let view = world.account(account["id"].as_str().unwrap()).await;
    assert_eq!(view["status"], "active");
}

// ---------------------------------------------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_expired_access_token_is_renewed_before_the_pull() {
    let world = World::new(StoreKind::Memory).await;
    world.script.set_access_ttl(Duration::minutes(5));
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    assert_eq!(
        world.script.count(Call::Refresh),
        0,
        "the token of the connection is fresh"
    );
    world.script.put_event("primary", "e1", event("e1", "One"));
    world.pass(16);
    world.work().await;
    assert_eq!(world.script.count(Call::Refresh), 1);
    assert_eq!(world.summaries(&account).await, text(&["One"]));
    world.pass(16);
    world.work().await;
    assert_eq!(
        world.script.count(Call::Refresh),
        2,
        "and again when it has expired again"
    );
}

#[tokio::test]
async fn a_refresh_token_the_provider_rotated_is_the_one_that_is_kept() {
    let world = World::new(StoreKind::Memory).await;
    world.script.set_access_ttl(Duration::minutes(5));
    world.script.rotate_refresh_tokens(true);
    let account = world.connect(World::OWNER, "olivia").await;
    // Every renewal retires the refresh token it used: a pull that stored the old one would be refused at the next one.
    for round in 0..4 {
        world.script.put_event(
            "primary",
            &format!("e{round}"),
            event(&format!("e{round}"), &format!("Event {round}")),
        );
        world.pass(16);
        world.work().await;
        let view = world.account(account["id"].as_str().unwrap()).await;
        assert_eq!(view["status"], "active", "round {round}: {view}");
    }
    assert_eq!(world.script.count(Call::Refresh), 4);
    assert_eq!(world.summaries(&account).await.len(), 4);
}

#[tokio::test]
async fn a_token_the_provider_refuses_is_renewed_once_and_the_pull_repeated() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    // The access token is revoked at the provider while it is still valid by the clock; the refresh token is not.
    assert_eq!(world.script.live_access_tokens().len(), 1);
    world.script.revoke_access_tokens();
    world.script.put_event("primary", "e1", event("e1", "One"));
    world.pass(16);
    world.work().await;
    assert_eq!(world.script.count(Call::Refresh), 1);
    assert_eq!(world.summaries(&account).await, text(&["One"]));
}

#[tokio::test]
async fn a_provider_that_refuses_the_refresh_token_switches_the_account_off_and_says_so_once() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    let last_success = world.app.clock().now();
    world.work().await;
    let id = account["id"].as_str().unwrap().to_owned();
    // The person removed the application's access at the provider.
    world.script.revoke_access();
    world.pass(16);
    world.work().await;
    let view = world.account(&id).await;
    assert_eq!(view["status"], "disabled", "{view}");
    assert_eq!(view["last_sync_at"], serde_json::json!(last_success));
    assert!(
        view.get("next_sync_at").is_none(),
        "a revoked account has no retry: {view}"
    );
    assert_eq!(view["last_error_code"], "auth_revoked");
    assert!(
        view["last_error"].as_str().unwrap().starts_with("auth_revoked"),
        "{view}"
    );
    assert_eq!(world.failures_told().await, text(&["auth_revoked"]));
    // Nothing more is asked of the provider about an account that only a new connection can help.
    let calls = world.script.calls().len();
    world.pass(240);
    world.work().await;
    assert_eq!(world.script.calls().len(), calls);
    assert_eq!(world.failures_told().await.len(), 1);
}

// ---------------------------------------------------------------------------------------------------------------
// A provider that fails
// ---------------------------------------------------------------------------------------------------------------

async fn an_unavailable_provider_is_tried_again_after_a_growing_wait_and_told_once(store: StoreKind) {
    let world = World::new(store).await;
    let account = world.connect(World::OWNER, "olivia").await;
    let last_success = world.app.clock().now();
    world.work().await;
    let id = account["id"].as_str().unwrap().to_owned();
    world.script.put_event("primary", "e1", event("e1", "One"));
    world.script.fail_next(Call::Changes, PortError::unavailable("down"));
    world
        .script
        .fail_next(Call::Changes, PortError::unavailable("still down"));

    world.pass(16);
    let failure_at = world.app.clock().now();
    world.work().await;
    let view = world.account(&id).await;
    assert_eq!(view["status"], "error", "{view}");
    assert_eq!(view["last_error_code"], "provider_unavailable");
    assert_eq!(
        view["last_sync_at"],
        serde_json::json!(last_success),
        "a failure keeps the last success"
    );
    assert_eq!(
        view["next_sync_at"],
        serde_json::json!(failure_at + Duration::minutes(5))
    );
    assert!(
        view["last_error"].as_str().unwrap().starts_with("provider_unavailable"),
        "{view}"
    );
    assert!(
        !view["last_error"].as_str().unwrap().contains("down"),
        "what the provider said does not reach the view: {view}"
    );
    assert_eq!(world.failures_told().await, text(&["provider_unavailable"]));
    let asked = pulls(&world);

    // The first wait is a third of the interval.
    world.pass(4);
    world.work().await;
    assert_eq!(pulls(&world), asked, "not yet");
    world.pass(1);
    world.work().await;
    assert_eq!(pulls(&world), asked + 1, "the second try");
    let retry = world.account(&id).await;
    assert_eq!(retry["status"], "error");
    assert_eq!(retry["last_sync_at"], serde_json::json!(last_success));
    assert_eq!(
        retry["next_sync_at"],
        serde_json::json!(failure_at + Duration::minutes(15))
    );
    assert_eq!(
        world.failures_told().await.len(),
        1,
        "a failure that goes on is not told again"
    );

    // The second wait is twice as long.
    world.pass(9);
    world.work().await;
    assert_eq!(pulls(&world), asked + 1, "not yet");
    world.pass(1);
    world.work().await;
    assert_eq!(pulls(&world), asked + 2, "the third try works");
    let view = world.account(&id).await;
    assert_eq!(view["status"], "active", "{view}");
    assert!(view.get("last_error").is_none(), "{view}");
    assert!(
        view.get("last_error_code").is_none(),
        "recovery clears the error code: {view}"
    );
    assert_eq!(
        view["last_sync_at"],
        serde_json::json!(failure_at + Duration::minutes(15))
    );
    assert_eq!(
        view["next_sync_at"],
        serde_json::json!(failure_at + Duration::minutes(30))
    );
    assert_eq!(world.summaries(&account).await, text(&["One"]));

    // A new outage is a new thing to tell.
    world
        .script
        .fail_next(Call::Changes, PortError::unavailable("down again"));
    world.pass(16);
    world.work().await;
    assert_eq!(world.failures_told().await.len(), 2);
}

on_both_stores!(
    unavailable_provider_backoff,
    an_unavailable_provider_is_tried_again_after_a_growing_wait_and_told_once
);

#[tokio::test]
async fn a_calendar_the_provider_refuses_is_an_error_and_not_the_end_of_the_account() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    // The first refusal is answered with a new access token and a second try; a refusal of that is the provider's last word.
    world.script.fail_next(Call::Changes, PortError::rejected("403"));
    world.script.fail_next(Call::Changes, PortError::rejected("403 again"));
    world.pass(16);
    world.work().await;
    assert_eq!(world.script.count(Call::Refresh), 1);
    let view = world.account(account["id"].as_str().unwrap()).await;
    assert_eq!(view["status"], "error", "{view}");
    assert!(
        view["last_error"].as_str().unwrap().starts_with("provider_rejected"),
        "{view}"
    );
    assert_eq!(world.failures_told().await, text(&["provider_rejected"]));
    world.pass(6);
    world.work().await;
    assert_eq!(world.account(account["id"].as_str().unwrap()).await["status"], "active");
}

#[tokio::test]
async fn two_workers_never_pull_the_same_account_at_once() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    let (tenant, id) = (
        world.app.tenant_id("acme").unwrap(),
        ExternalAccountId::parse(account["id"].as_str().unwrap()).unwrap(),
    );
    let engine = ProviderSyncWorker::new(AppCore::new(world.app.deps().clone()));
    // Two workers want the same account at the same time: one pulls, the other finds it held.
    let (first, second) = tokio::join!(
        engine.engine().sync_account(tenant, id),
        engine.engine().sync_account(tenant, id)
    );
    let pulled = [&first, &second]
        .iter()
        .filter(|outcome| matches!(outcome, SyncOutcome::Pulled(_)))
        .count();
    let skipped = [&first, &second]
        .iter()
        .filter(|outcome| matches!(outcome, SyncOutcome::Skipped))
        .count();
    assert_eq!((pulled, skipped), (1, 1), "{first:?} {second:?}");
    assert_eq!(pulls(&world), 1, "the provider was asked once");
    // Not due again until the interval has passed.
    assert_eq!(engine.engine().sync_account(tenant, id).await, SyncOutcome::Skipped);
    world.pass(16);
    assert!(matches!(
        engine.engine().sync_account(tenant, id).await,
        SyncOutcome::Pulled(_)
    ));
}

// ---------------------------------------------------------------------------------------------------------------
// A client the provider refuses, a calendar that is too large
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_client_the_provider_refuses_is_the_deployments_fault_and_switches_no_account_off() {
    let world = World::new(StoreKind::Memory).await;
    // Access tokens that live five minutes, so that every pull has to renew its token.
    world.script.set_access_ttl(Duration::minutes(5));
    let account = world.connect(World::OWNER, "olivia").await;
    let id = account["id"].as_str().unwrap().to_owned();
    world.work().await;
    world.script.put_event("primary", "e1", event("e1", "One"));
    // The client secret of the app registration expired: the provider refuses the client, not the person.
    world.script.refuse_client(true);
    world.pass(16);
    world.work().await;
    assert_eq!(world.script.count(Call::Refresh), 1);
    let view = world.account(&id).await;
    assert_eq!(
        view["status"], "error",
        "a refused client is no revoked refresh token: nobody has to connect again: {view}"
    );
    assert!(view["last_error"].as_str().unwrap().starts_with("internal"), "{view}");
    assert_eq!(world.failures_told().await, text(&["internal"]));
    // The account is tried again after the wait, and works as soon as the client does.
    world.script.refuse_client(false);
    world.pass(6);
    world.work().await;
    let view = world.account(&id).await;
    assert_eq!(view["status"], "active", "{view}");
    assert!(view.get("last_error").is_none(), "{view}");
    assert_eq!(world.summaries(&account).await, text(&["One"]));
}

#[tokio::test]
async fn a_calendar_that_is_too_large_is_asked_for_once_and_not_answered_with_a_new_token() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    world.script.fail_next(
        Call::Changes,
        PortError::new(PortErrorKind::Unsupported, "more events than the import reads"),
    );
    world.pass(16);
    let asked = pulls(&world);
    world.work().await;
    assert_eq!(
        pulls(&world),
        asked + 1,
        "a new token and a new cursor do not make a calendar smaller: one request"
    );
    assert_eq!(world.script.count(Call::Refresh), 0);
    let view = world.account(account["id"].as_str().unwrap()).await;
    assert_eq!(view["status"], "error", "{view}");
    assert!(view["last_error"].as_str().unwrap().starts_with("too_large"), "{view}");
    assert_eq!(world.failures_told().await, text(&["too_large"]));
}

// ---------------------------------------------------------------------------------------------------------------
// Accounts nobody can pull, and pulls that are overtaken
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn accounts_of_suspended_principals_neither_take_the_places_of_the_others_nor_make_the_worker_spin() {
    // One account per pass: two suspended accounts would fill every pass of a batch of one, for ever.
    let world = World::tweaked(StoreKind::Memory, |builder| {
        builder.configure(|config| {
            config.provider_sync.batch_size = 1;
            config.provider_sync.concurrency = 1;
        })
    })
    .await;
    world.script.put_event("primary", "e1", event("e1", "One"));
    // The two that get suspended are the oldest accounts, so they are first in line. The account that is read back is the owner's
    // (the helpers read a mirror with the token of the owner of the world).
    let first = world.connect(names::OTHER_USER, "otto").await;
    let second = world.connect(names::GROUP_MEMBER, "mia").await;
    let active = world.connect(names::OWNER, "olivia").await;
    world.set_status(names::OTHER_USER, PrincipalStatus::Suspended).await;
    world.set_status(names::GROUP_MEMBER, PrincipalStatus::Suspended).await;

    let worker = ProviderSyncWorker::new(AppCore::new(world.app.deps().clone()));
    let report = worker.tick().await;
    assert_eq!((report.processed, report.failed), (1, 0), "{report:?}");
    assert!(
        !report.more,
        "nothing is left that a pass could pull: the worker sleeps until the next pass, it does not start one at once"
    );
    assert_eq!(world.summaries(&active).await, text(&["One"]));
    assert_eq!(pulls(&world), 1);
    for suspended in [&first, &second] {
        let view = world.account(suspended["id"].as_str().unwrap()).await;
        assert_eq!(view["status"], "active", "{view}");
        assert!(view.get("last_error").is_none(), "{view}");
    }
    assert!(worker.tick().await.is_idle(), "and a pass without accounts is idle");

    // The principal is active again: its account is pulled at the next pass, as it was due all along.
    world.set_status(names::OTHER_USER, PrincipalStatus::Active).await;
    let report = worker.tick().await;
    assert_eq!(report.processed, 1, "{report:?}");
    assert_eq!(pulls(&world), 2);
}

async fn a_reconnection_during_a_pull_is_not_undone_by_the_pull(store: StoreKind) {
    let (world, gate) = World::gated(store).await;
    world.script.put_event("primary", "e1", event("e1", "One"));
    let account = world.connect(World::OWNER, "olivia").await;
    let id = ExternalAccountId::parse(account["id"].as_str().unwrap()).unwrap();
    let tenant = world.app.tenant_id("acme").unwrap();
    // The person removed the access at the provider: the pull that starts now works from tokens that are dead, and will end in
    // `auth_revoked`.
    world.script.revoke_access();
    let worker = ProviderSyncWorker::new(AppCore::new(world.app.deps().clone()));
    let (outcome, ()) = tokio::join!(worker.engine().sync_account(tenant, id), async {
        // The pull holds the account and waits at the provider. Meanwhile the person connects the account again, with a new grant.
        gate.reached.notified().await;
        let again = world.connect(World::OWNER, "olivia").await;
        assert_eq!(again["id"], account["id"], "the same account");
        gate.release.notify_one();
    });
    assert_eq!(
        outcome,
        SyncOutcome::Skipped,
        "what the pull found belongs to the grant that was replaced"
    );
    let view = world.account(account["id"].as_str().unwrap()).await;
    assert_eq!(
        view["status"], "active",
        "the old pull did not switch the new connection off: {view}"
    );
    assert!(view.get("last_error").is_none(), "{view}");
    assert!(
        world.failures_told().await.is_empty(),
        "nobody is told about a failure of a grant that is gone"
    );
    // The account works with the new grant.
    world.work().await;
    assert_eq!(world.summaries(&account).await, text(&["One"]));
    assert_eq!(world.account(account["id"].as_str().unwrap()).await["status"], "active");
}

on_both_stores!(reconnection, a_reconnection_during_a_pull_is_not_undone_by_the_pull);

// ---------------------------------------------------------------------------------------------------------------
// A mirror that is gone
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_account_without_its_mirror_asks_the_provider_for_nothing_and_a_reconnection_makes_a_new_one() {
    let world = World::new(StoreKind::Memory).await;
    world.script.put_event("primary", "e1", event("e1", "One"));
    let account = world.connect(World::OWNER, "olivia").await;
    let id = account["id"].as_str().unwrap().to_owned();
    world.work().await;
    assert_eq!(world.summaries(&account).await, text(&["One"]));

    // The API refuses to delete a mirror; a purge or a statement of an operator does it.
    world.delete_mirror(&account).await;
    assert!(world.mirror(&account).await.is_none());
    world.pass(16);
    let calls = world.script.calls().len();
    world.work().await;
    assert_eq!(
        world.script.calls().len(),
        calls,
        "the provider is not asked, and the tokens of the person are not used, for a calendar that has nowhere to go"
    );
    let view = world.account(&id).await;
    assert_eq!(view["status"], "error", "{view}");
    assert!(
        view["last_error"].as_str().unwrap().starts_with("mirror_missing"),
        "{view}"
    );
    assert_eq!(world.failures_told().await, text(&["mirror_missing"]));

    // Connecting again is the way back: the same account, a new mirror, and the events are pulled into it.
    let again = world.connect(World::OWNER, "olivia").await;
    assert_eq!(again["id"], account["id"]);
    assert_ne!(again["mirror_calendar_id"], account["mirror_calendar_id"]);
    assert!(world.mirror(&again).await.is_some());
    world.work().await;
    assert_eq!(world.summaries(&again).await, text(&["One"]));
    let view = world.account(&id).await;
    assert_eq!(view["status"], "active", "{view}");
    assert!(view.get("last_error").is_none(), "{view}");
}

// ---------------------------------------------------------------------------------------------------------------
// Whose accounts they are
// ---------------------------------------------------------------------------------------------------------------

/// Connects the account `{name}@fake.example` for the user `principal` of the other tenant, with its own administrator.
async fn connect_in_the_other_tenant(world: &World, principal: &str, name: &str) -> Value {
    let other_admin = world.app.token(ActorRole::OtherTenantToken).unwrap();
    let other = world.app.api(&other_admin);
    let base = format!("/api/v1/tenants/{}", world.app.world().names.other_tenant);
    let code = format!("code-{name}");
    world.script.accept_code(&code, &format!("{name}@fake.example"));
    let started = other
        .post_json(
            &format!("{base}/external-accounts"),
            &serde_json::json!({"provider": "fake", "principal": principal}),
        )
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(started.status.as_u16(), 200, "{}", started.excerpt(300));
    let page = world
        .callback("fake", &format!("code={code}&state={}", World::state_of(&started)))
        .await;
    assert_eq!(page.status.as_u16(), 200, "{}", page.excerpt(300));
    let listed = other.get(&format!("{base}/external-accounts")).send().await.unwrap();
    assert_eq!(listed.status.as_u16(), 200, "{}", listed.excerpt(300));
    let page: Value = listed.json().unwrap();
    page["items"][0].clone()
}

async fn the_worker_keeps_the_tenants_apart(store: StoreKind) {
    let world = World::new(store).await;
    world.script.put_event("primary", "e1", event("e1", "One"));
    let ours = world.connect(World::OWNER, "olivia").await;
    let theirs = connect_in_the_other_tenant(&world, names::OTHER_TENANT_USER, "gina").await;
    assert_ne!(ours["id"], theirs["id"]);
    assert_eq!(
        world.accounts().await.len(),
        1,
        "each tenant lists its own account only"
    );

    // One worker pulls the accounts of both tenants; every mirror holds its own pull, and every event names its own tenant.
    world.work().await;
    assert_eq!(world.summaries(&ours).await, text(&["One"]));
    let acme = world.app.tenant_id("acme").unwrap();
    let globex = world.app.tenant_id("globex").unwrap();
    let mut tenants: Vec<_> = world
        .app
        .events()
        .of_type(EventType::CalendarObjectsChanged)
        .await
        .into_iter()
        .map(|envelope| envelope.tenant.as_uuid())
        .collect();
    tenants.sort();
    tenants.dedup();
    let mut both = vec![acme.as_uuid(), globex.as_uuid()];
    both.sort();
    assert_eq!(
        tenants, both,
        "a pull announces its changes in the tenant of the account"
    );

    // A pull that fails in one tenant is told in that tenant and does not stop the other.
    world.script.put_event("primary", "e2", event("e2", "Two"));
    world
        .script
        .fail_next(Call::Changes, PortError::unavailable("the provider is down"));
    world.pass(16);
    world.work().await;
    let other_admin = world.app.token(ActorRole::OtherTenantToken).unwrap();
    let listed = world
        .app
        .api(&other_admin)
        .get(&format!(
            "/api/v1/tenants/{}/external-accounts",
            world.app.world().names.other_tenant
        ))
        .send()
        .await
        .unwrap();
    let page: Value = listed.json().unwrap();
    let mut statuses = vec![
        world.account(ours["id"].as_str().unwrap()).await["status"]
            .as_str()
            .unwrap()
            .to_owned(),
        page["items"][0]["status"].as_str().unwrap().to_owned(),
    ];
    statuses.sort();
    assert_eq!(
        statuses,
        text(&["active", "error"]),
        "one pull failed and the account of the other tenant was pulled all the same"
    );
    assert_eq!(world.failures_told().await, text(&["provider_unavailable"]));
}

on_both_stores!(tenants_apart, the_worker_keeps_the_tenants_apart);

#[tokio::test]
async fn the_account_of_a_deleted_principal_is_switched_off_and_its_access_given_back() {
    let world = World::new(StoreKind::Memory).await;
    let account = world.connect(World::OWNER, "olivia").await;
    world.work().await;
    let id = account["id"].as_str().unwrap().to_owned();
    // Principals are deleted with a condition on their version.
    let principal = world
        .api()
        .get(&format!("{}/principals/olivia", world.base()))
        .send()
        .await
        .unwrap();
    let etag = principal.etag().unwrap().to_owned();
    let deleted = world
        .api()
        .delete(&format!("{}/principals/olivia", world.base()), Some(&etag))
        .send()
        .await
        .unwrap();
    assert!(deleted.is_success(), "{}", deleted.excerpt(300));
    world.pass(16);
    world.work().await;
    assert_eq!(world.script.revoked_tokens().len(), 1, "the access is given back");
    let view = world.account(&id).await;
    assert_eq!(view["status"], "disabled", "{view}");
    assert!(
        view["last_error"].as_str().unwrap().starts_with("principal_deleted"),
        "{view}"
    );
    assert_eq!(view["last_error_code"], "principal_deleted");
    assert!(
        view.get("next_sync_at").is_none(),
        "a deleted principal has no retry: {view}"
    );
    assert_eq!(pulls(&world), 1, "the pull after the deletion was never made");
}

#[tokio::test]
async fn a_provider_that_is_off_has_no_worker_and_its_accounts_are_left_alone() {
    let world = World::new(StoreKind::Memory).await;
    let core = AppCore::new(world.app.deps().clone());
    let names: Vec<&str> = davhaven_testkit::davhaven_app::workers::build(&core)
        .workers
        .iter()
        .map(|worker| worker.name())
        .collect();
    assert!(names.contains(&"provider_sync"), "{names:?}");
    let mut deps = world.app.deps().clone();
    deps.providers = Vec::new();
    let bare = AppCore::new(deps);
    let names: Vec<&str> = davhaven_testkit::davhaven_app::workers::build(&bare)
        .workers
        .iter()
        .map(|worker| worker.name())
        .collect();
    assert!(!names.contains(&"provider_sync"), "no provider, no worker: {names:?}");
    // A worker that was built anyway has nothing to do while the provider of the accounts is off.
    let off = World::with_provider(StoreKind::Memory, |clock| {
        davhaven_testkit::davhaven_provider_fake::provider::FakeProvider::new(std::sync::Arc::new(clock.clone()))
            .disabled()
    })
    .await;
    let worker = ProviderSyncWorker::new(AppCore::new(off.app.deps().clone()));
    assert!(worker.tick().await.is_idle());
    assert_eq!(
        off.script.calls().len(),
        0,
        "nothing was asked of a provider that is off"
    );
}

#[tokio::test]
async fn the_accounts_of_a_provider_that_is_switched_off_meanwhile_are_left_alone() {
    let world = World::new(StoreKind::Memory).await;
    world.script.put_event("primary", "e1", event("e1", "One"));
    let account = world.connect(World::OWNER, "olivia").await;
    let id = account["id"].as_str().unwrap().to_owned();
    // The same accounts, in a deployment whose provider of that name is off (`enabled = false`): its worker is built anyway.
    let off = davhaven_testkit::davhaven_provider_fake::provider::FakeProvider::new(std::sync::Arc::clone(
        &world.app.deps().clock,
    ))
    .disabled();
    let off_script = off.script();
    let off: std::sync::Arc<dyn Provider> = std::sync::Arc::new(off);
    let mut deps = world.app.deps().clone();
    deps.providers = vec![off];
    let worker = ProviderSyncWorker::new(AppCore::new(deps));
    let connected = world.script.calls().len();
    world.pass(16);
    assert!(
        worker.tick().await.is_idle(),
        "the account is due, and its provider is off"
    );
    assert_eq!(off_script.calls().len(), 0, "nothing was asked of the provider");
    assert_eq!(
        world.script.calls().len(),
        connected,
        "nothing was asked of the one that is on either"
    );
    let view = world.account(&id).await;
    assert_eq!(view["status"], "active", "the account is as it was: {view}");
    assert!(view.get("last_error").is_none(), "{view}");
    assert!(world.summaries(&account).await.is_empty(), "and nothing was pulled");
    // Switched on again, the same account is pulled at once.
    world.work().await;
    assert_eq!(world.summaries(&account).await, text(&["One"]));
}
