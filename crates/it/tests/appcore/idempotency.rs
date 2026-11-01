//! Idempotency keys of the management API: scope, replay, reuse, in-flight requests, secrets and expiry.

use std::time::Duration as StdDuration;

use davhaven_testkit::davhaven_app::services::{
    IdempotencyKey, IdempotencyOutcome, IdempotencyState, Reservation, Reserved, ResponseNote, Settlement,
    StoredResponse,
};
use davhaven_testkit::davhaven_domain::{ErrorKind, RequestContext};
use chrono::Duration;
use serde_json::json;

use super::support::{Fixture, Org, World, fixture};

fn key(text: &str) -> IdempotencyKey {
    IdempotencyKey {
        key: text.to_owned(),
        method: "POST".to_owned(),
        route: "/tenants/{tenant}/principals".to_owned(),
    }
}

fn response() -> StoredResponse {
    StoredResponse {
        status: 201,
        headers: vec![
            ("etag".to_owned(), "\"v1\"".to_owned()),
            ("location".to_owned(), "/x".to_owned()),
        ],
        body: json!({"id": "abc", "nested": {"list": [1, 2, 3]}}),
    }
}

async fn begin(world: &World, ctx: &RequestContext, key: IdempotencyKey, fingerprint: &str) -> IdempotencyState {
    world
        .services
        .idempotency
        .begin(ctx, key, fingerprint.to_owned())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_key_is_fresh_once_in_progress_while_running_and_replays_the_stored_response() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;

    assert_eq!(begin(&world, &ctx, key("k-1"), "fp-1").await, IdempotencyState::Fresh);
    assert_eq!(
        begin(&world, &ctx, key("k-1"), "fp-1").await,
        IdempotencyState::InProgress,
        "the same request while the first one is running"
    );
    world
        .services
        .idempotency
        .complete(&ctx, &key("k-1"), IdempotencyOutcome::Response(response()))
        .await
        .unwrap();
    assert_eq!(
        begin(&world, &ctx, key("k-1"), "fp-1").await,
        IdempotencyState::Replay(response()),
        "status, headers and body come back exactly as stored"
    );
    assert_eq!(
        begin(&world, &ctx, key("k-1"), "fp-1").await,
        IdempotencyState::Replay(response()),
        "again and again"
    );
}

#[tokio::test]
async fn using_a_key_for_another_request_is_a_reuse() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    assert_eq!(begin(&world, &ctx, key("k-1"), "fp-1").await, IdempotencyState::Fresh);
    world
        .services
        .idempotency
        .complete(&ctx, &key("k-1"), IdempotencyOutcome::Response(response()))
        .await
        .unwrap();
    assert_eq!(
        begin(&world, &ctx, key("k-1"), "fp-other-body").await,
        IdempotencyState::KeyReuse
    );
    let other_method = IdempotencyKey {
        method: "PUT".to_owned(),
        ..key("k-1")
    };
    assert_eq!(
        begin(&world, &ctx, other_method, "fp-1").await,
        IdempotencyState::KeyReuse
    );
    let other_route = IdempotencyKey {
        route: "/tenants/{tenant}/webhooks".to_owned(),
        ..key("k-1")
    };
    assert_eq!(
        begin(&world, &ctx, other_route, "fp-1").await,
        IdempotencyState::KeyReuse
    );
    // The original is still replayable afterwards.
    assert_eq!(
        begin(&world, &ctx, key("k-1"), "fp-1").await,
        IdempotencyState::Replay(response())
    );
    // A running request with another fingerprint is a reuse, too.
    assert_eq!(begin(&world, &ctx, key("k-2"), "fp-a").await, IdempotencyState::Fresh);
    assert_eq!(
        begin(&world, &ctx, key("k-2"), "fp-b").await,
        IdempotencyState::KeyReuse
    );
}

#[tokio::test]
async fn responses_with_secrets_are_not_stored_and_cannot_be_replayed() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    assert_eq!(begin(&world, &ctx, key("secret"), "fp").await, IdempotencyState::Fresh);
    world
        .services
        .idempotency
        .complete(&ctx, &key("secret"), IdempotencyOutcome::SecretResponse)
        .await
        .unwrap();
    assert_eq!(
        begin(&world, &ctx, key("secret"), "fp").await,
        IdempotencyState::NotReplayable
    );
    assert_eq!(
        begin(&world, &ctx, key("secret"), "other").await,
        IdempotencyState::KeyReuse,
        "another request with the key is still a reuse"
    );
}

#[tokio::test]
async fn an_abandoned_request_releases_its_key_for_a_retry() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    assert_eq!(begin(&world, &ctx, key("flaky"), "fp").await, IdempotencyState::Fresh);
    world
        .services
        .idempotency
        .complete(&ctx, &key("flaky"), IdempotencyOutcome::Abandon)
        .await
        .unwrap();
    assert_eq!(begin(&world, &ctx, key("flaky"), "fp").await, IdempotencyState::Fresh);
}

#[tokio::test]
async fn keys_are_scoped_to_the_tenant_and_the_token() {
    let Fixture { world, acme, .. } = fixture().await;
    let other: Org = world.org("other").await;
    let first = world.stored_admin(&acme).await;
    let second = world.stored_admin(&acme).await;
    let foreign = world.stored_admin(&other).await;
    assert_eq!(
        begin(&world, &first, key("shared-key"), "fp").await,
        IdempotencyState::Fresh
    );
    assert_eq!(
        begin(&world, &second, key("shared-key"), "fp").await,
        IdempotencyState::Fresh,
        "another token"
    );
    assert_eq!(
        begin(&world, &foreign, key("shared-key"), "fp").await,
        IdempotencyState::Fresh,
        "another tenant"
    );
    world
        .services
        .idempotency
        .complete(&first, &key("shared-key"), IdempotencyOutcome::Response(response()))
        .await
        .unwrap();
    assert_eq!(
        begin(&world, &second, key("shared-key"), "fp").await,
        IdempotencyState::InProgress
    );
    assert_eq!(
        begin(&world, &first, key("shared-key"), "fp").await,
        IdempotencyState::Replay(response())
    );
}

#[tokio::test]
async fn two_requests_with_one_key_at_the_same_time_run_only_once() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    let (a, b) = tokio::join!(
        world.services.idempotency.begin(&ctx, key("race"), "fp".to_owned()),
        world.services.idempotency.begin(&ctx, key("race"), "fp".to_owned()),
    );
    let mut states = [a.unwrap(), b.unwrap()];
    states.sort_by_key(|state| matches!(state, IdempotencyState::InProgress));
    assert_eq!(states, [IdempotencyState::Fresh, IdempotencyState::InProgress]);
}

#[tokio::test]
async fn a_process_that_died_releases_its_key_after_the_lease_and_old_keys_expire() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    assert_eq!(begin(&world, &ctx, key("crashed"), "fp").await, IdempotencyState::Fresh);
    world.clock.advance(Duration::seconds(80));
    assert_eq!(
        begin(&world, &ctx, key("crashed"), "fp").await,
        IdempotencyState::InProgress,
        "within the lease"
    );
    world.clock.advance(Duration::seconds(20));
    assert_eq!(
        begin(&world, &ctx, key("crashed"), "fp").await,
        IdempotencyState::Fresh,
        "the request that began it never finished: the next one takes over"
    );

    // Completed keys last for 24 hours.
    assert_eq!(begin(&world, &ctx, key("daily"), "fp").await, IdempotencyState::Fresh);
    world
        .services
        .idempotency
        .complete(&ctx, &key("daily"), IdempotencyOutcome::Response(response()))
        .await
        .unwrap();
    world.clock.advance(Duration::hours(23));
    assert_eq!(
        begin(&world, &ctx, key("daily"), "fp").await,
        IdempotencyState::Replay(response())
    );
    world.clock.advance(Duration::hours(2));
    assert_eq!(
        begin(&world, &ctx, key("daily"), "fp").await,
        IdempotencyState::Fresh,
        "expired"
    );
}

#[tokio::test]
async fn keys_must_be_printable_and_come_from_requests_with_an_api_token() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    for bad in ["", &"k".repeat(256), "line\nbreak", "tab\there"] {
        let error = world
            .services
            .idempotency
            .begin(&ctx, key(bad), "fp".to_owned())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{bad:?}");
    }
    assert_eq!(
        begin(&world, &ctx, key(&"k".repeat(255)), "fp").await,
        IdempotencyState::Fresh
    );
    // DAV sessions have no API token to scope a key to.
    let error = world
        .services
        .idempotency
        .begin(&world.dav(&acme, &anna), key("k"), "fp".to_owned())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    let error = world
        .services
        .idempotency
        .complete(&world.dav(&acme, &anna), &key("k"), IdempotencyOutcome::Abandon)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
}

/// Reserves `key` and returns the reservation of a fresh claim.
async fn reserved(world: &World, ctx: &RequestContext, key: IdempotencyKey, lease: StdDuration) -> Reservation {
    match world
        .services
        .idempotency
        .reserve(ctx, key, "fp".to_owned(), lease)
        .await
        .unwrap()
    {
        Reserved::Fresh(reservation) => reservation,
        other => panic!("expected a fresh key, got {other:?}"),
    }
}

#[tokio::test]
async fn a_request_that_outlived_its_lease_cannot_settle_the_key_of_the_retry_that_replaced_it() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    let service = &world.services.idempotency;
    let slow = |status| StoredResponse {
        status,
        headers: Vec::new(),
        body: json!({"from": status}),
    };

    let first = reserved(&world, &ctx, key("slow"), StdDuration::from_secs(90)).await;
    assert!(first.lease_until().is_some(), "the in-memory store fences claims");
    // The process of the first request is slow: its lease runs out and the retry takes the key over.
    world.clock.advance(Duration::seconds(100));
    let retry = reserved(&world, &ctx, key("slow"), StdDuration::from_secs(90)).await;
    assert_ne!(first, retry);

    // The first request finally answers. Neither its response nor its failure may touch the retry's claim.
    service
        .settle(&ctx, &key("slow"), &first, Settlement::Response(slow(201)))
        .await
        .unwrap();
    assert_eq!(
        begin(&world, &ctx, key("slow"), "fp").await,
        IdempotencyState::InProgress,
        "the retry still owns the key; the late response was not stored"
    );
    service
        .settle(&ctx, &key("slow"), &first, Settlement::Abandon)
        .await
        .unwrap();
    assert_eq!(
        begin(&world, &ctx, key("slow"), "fp").await,
        IdempotencyState::InProgress,
        "nor did its failure release the key"
    );

    // The retry settles its own claim.
    service
        .settle(&ctx, &key("slow"), &retry, Settlement::Response(slow(200)))
        .await
        .unwrap();
    assert_eq!(
        begin(&world, &ctx, key("slow"), "fp").await,
        IdempotencyState::Replay(slow(200))
    );
}

#[tokio::test]
async fn a_response_that_was_not_kept_leaves_its_status_and_location_for_the_repeat() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    let service = &world.services.idempotency;
    let reservation = reserved(&world, &ctx, key("secret"), StdDuration::from_secs(90)).await;
    let note = ResponseNote {
        status: 201,
        location: Some("/api/v1/tenants/acme/principals/anna/app-passwords/42".to_owned()),
    };
    service
        .settle(&ctx, &key("secret"), &reservation, Settlement::Secret(note.clone()))
        .await
        .unwrap();
    assert_eq!(
        service
            .reserve(&ctx, key("secret"), "fp".to_owned(), StdDuration::from_secs(90))
            .await
            .unwrap(),
        Reserved::NotReplayable(Some(note)),
        "the client whose first answer was lost can find what it created"
    );
    assert_eq!(
        begin(&world, &ctx, key("secret"), "fp").await,
        IdempotencyState::NotReplayable
    );

    // A caller that cannot say more than "used, not kept" leaves no note.
    assert_eq!(begin(&world, &ctx, key("plain"), "fp").await, IdempotencyState::Fresh);
    service
        .complete(&ctx, &key("plain"), IdempotencyOutcome::SecretResponse)
        .await
        .unwrap();
    assert_eq!(
        service
            .reserve(&ctx, key("plain"), "fp".to_owned(), StdDuration::from_secs(90))
            .await
            .unwrap(),
        Reserved::NotReplayable(None)
    );
}

#[tokio::test]
async fn the_lease_of_a_reservation_is_the_one_the_caller_asked_for() {
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    let reservation = reserved(&world, &ctx, key("asked"), StdDuration::from_secs(5)).await;
    assert_eq!(
        reservation.lease_until(),
        Some(world.now() + Duration::seconds(5)),
        "counted by the clock of the service"
    );
    world.clock.advance(Duration::seconds(4));
    assert_eq!(
        begin(&world, &ctx, key("asked"), "fp").await,
        IdempotencyState::InProgress
    );
    world.clock.advance(Duration::seconds(2));
    assert_eq!(begin(&world, &ctx, key("asked"), "fp").await, IdempotencyState::Fresh);
}

#[tokio::test]
async fn one_key_and_body_sent_to_two_resources_are_two_requests() {
    // The fingerprint covers the concrete path: the caller passes a different one for each calendar, and the service
    // must not mistake the second request for the first one's replay.
    let Fixture { world, acme, .. } = fixture().await;
    let ctx = world.stored_admin(&acme).await;
    let route = IdempotencyKey {
        key: "same-key".to_owned(),
        method: "PUT".to_owned(),
        route: "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/events/{event}".to_owned(),
    };
    assert_eq!(
        begin(
            &world,
            &ctx,
            route.clone(),
            "PUT /tenants/acme/principals/anna/calendars/work/events/x|body"
        )
        .await,
        IdempotencyState::Fresh
    );
    world
        .services
        .idempotency
        .complete(&ctx, &route, IdempotencyOutcome::Response(response()))
        .await
        .unwrap();
    assert_eq!(
        begin(
            &world,
            &ctx,
            route.clone(),
            "PUT /tenants/acme/principals/anna/calendars/home/events/x|body"
        )
        .await,
        IdempotencyState::KeyReuse,
        "another calendar is another request, whatever the body says"
    );
    assert_eq!(
        begin(
            &world,
            &ctx,
            route,
            "PUT /tenants/acme/principals/anna/calendars/work/events/x|body"
        )
        .await,
        IdempotencyState::Replay(response())
    );
}
