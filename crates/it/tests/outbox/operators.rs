//! The operator view of the outbox: listing and retrying items.

use davhaven_testkit::davhaven_app::outbox::OutboxServiceImpl;
use davhaven_testkit::davhaven_app::services::{OutboxFilter, OutboxService, PageRequest};
use davhaven_testkit::davhaven_domain::{ErrorKind, EventType, OutboxId, RequestContext, Scope};
use davhaven_testkit::davhaven_ports::OutboxStatus as StoreStatus;
use davhaven_testkit::davhaven_ports::{Clock, OutboxMessage, Reserved, WebhookDelivery};
use davhaven_testkit::davhaven_wire::OutboxStatus;
use uuid::Uuid;

use super::support::{Fate, World};

fn service(world: &World) -> OutboxServiceImpl {
    OutboxServiceImpl::new(world.core.clone())
}

fn operator() -> RequestContext {
    World::token_ctx(World::tenant(), &[Scope::OutboxManage])
}

#[tokio::test]
async fn items_are_listed_in_id_order_with_signed_cursors() {
    let world = World::new();
    let service = service(&world);
    let mut ids = Vec::new();
    for _ in 0..5 {
        ids.push(world.enqueue_dummy().await);
    }
    world
        .enqueue(World::other_tenant(), OutboxMessage::ProviderPush(Reserved::default()))
        .await;

    let first = service
        .list(&operator(), OutboxFilter::default(), PageRequest::with_limit(2))
        .await
        .unwrap();
    assert_eq!(
        first.items.iter().map(|item| item.id).collect::<Vec<_>>(),
        ids[..2].to_vec()
    );
    let second = service
        .list(
            &operator(),
            OutboxFilter::default(),
            PageRequest::with_limit(2).after(first.next_cursor.clone().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        second.items.iter().map(|item| item.id).collect::<Vec<_>>(),
        ids[2..4].to_vec()
    );
    let last = service
        .list(
            &operator(),
            OutboxFilter::default(),
            PageRequest::with_limit(2).after(second.next_cursor.clone().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        last.items.iter().map(|item| item.id).collect::<Vec<_>>(),
        ids[4..].to_vec()
    );
    assert!(last.next_cursor.is_none(), "the other tenant's item is not listed");

    let item = first.items.first().unwrap();
    assert_eq!(
        (item.kind.as_str(), item.status, item.attempts),
        ("provider_push", OutboxStatus::Pending, 0)
    );
    assert_eq!(item.last_error, None);
}

#[tokio::test]
async fn a_cursor_of_another_listing_or_tenant_is_refused() {
    let world = World::new();
    let service = service(&world);
    for _ in 0..3 {
        world.enqueue_dummy().await;
    }
    let page = service
        .list(&operator(), OutboxFilter::default(), PageRequest::with_limit(1))
        .await
        .unwrap();
    let cursor = page.next_cursor.unwrap();

    let elsewhere = World::token_ctx(World::other_tenant(), &[Scope::OutboxManage]);
    let error = service
        .list(&elsewhere, OutboxFilter::default(), PageRequest::first().after(cursor))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
}

#[tokio::test]
async fn the_status_filter_selects_dead_items() {
    let world = World::new();
    let service = service(&world);
    let dead = world.enqueue_dummy().await;
    world.settle(dead, Fate::Dead).await;
    let pending = world.enqueue_dummy().await;

    let dead_only = service.list_dead(&operator(), PageRequest::first()).await.unwrap();
    assert_eq!(
        dead_only.items.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![dead]
    );
    assert_eq!(dead_only.items.first().unwrap().status, OutboxStatus::Dead);
    let pending_only = service
        .list(
            &operator(),
            OutboxFilter {
                status: Some(OutboxStatus::Pending),
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(
        pending_only.items.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![pending]
    );
}

#[tokio::test]
async fn retry_makes_a_dead_item_due_again() {
    let world = World::new();
    let service = service(&world);
    let id = world.enqueue_dummy().await;
    for _ in 0..11 {
        world.settle(id, Fate::RetryNow).await;
    }
    world.settle(id, Fate::Dead).await;
    assert_eq!(world.record(id).await.attempts, 12);
    world.clock.advance(chrono::Duration::hours(3));

    let view = service.retry(&operator(), id).await.unwrap();
    assert_eq!((view.status, view.attempts), (OutboxStatus::Pending, 0));
    assert_eq!(view.next_attempt_at, world.clock.now());
    let stored = world.record(id).await;
    assert_eq!((stored.status, stored.attempts), (StoreStatus::Pending, 0));

    let audit = world.audit(World::tenant()).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].0, "outbox.retried");
    assert_eq!(audit[0].1["outbox"], serde_json::json!(id));
    assert_eq!(audit[0].1["kind"], "provider_push");
}

#[tokio::test]
async fn only_dead_items_can_be_retried() {
    let world = World::new();
    let service = service(&world);
    for (fate, status) in [(Fate::InFlight, StoreStatus::InFlight), (Fate::Done, StoreStatus::Done)] {
        let id = world.enqueue_dummy().await;
        world.settle(id, fate).await;
        let error = service.retry(&operator(), id).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Conflict, "{status:?}");
        assert_eq!(world.record(id).await.status, status, "unchanged");
    }
    let pending = world.enqueue_dummy().await;
    let error = service.retry(&operator(), pending).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(world.record(pending).await.status, StoreStatus::Pending, "unchanged");
    assert_eq!(
        world.audit(World::tenant()).await,
        Vec::new(),
        "a refused retry is not audited"
    );
}

#[tokio::test]
async fn unknown_and_foreign_items_are_not_found() {
    let world = World::new();
    let service = service(&world);
    let foreign = world
        .enqueue(World::other_tenant(), OutboxMessage::ProviderPush(Reserved::default()))
        .await;
    world.settle(foreign, Fate::Dead).await;
    for id in [foreign, OutboxId::from_uuid(Uuid::from_u128(1))] {
        let error = service.retry(&operator(), id).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }
    let stored = world.outbox_of(World::other_tenant()).await;
    assert_eq!(stored[0].status, StoreStatus::Dead, "untouched");
}

#[tokio::test]
async fn the_outbox_needs_the_outbox_scope() {
    let world = World::new();
    let service = service(&world);
    let id = world.enqueue_dummy().await;
    let wrong_scope = World::token_ctx(World::tenant(), &[Scope::WebhooksManage]);
    let anonymous = RequestContext {
        actor: davhaven_testkit::davhaven_domain::Actor::Anonymous,
        ..operator()
    };
    for ctx in [wrong_scope, anonymous] {
        let listed = service.list(&ctx, OutboxFilter::default(), PageRequest::first()).await;
        assert_eq!(listed.unwrap_err().kind(), ErrorKind::Forbidden);
        assert_eq!(service.retry(&ctx, id).await.unwrap_err().kind(), ErrorKind::Forbidden);
    }
    // Server-originated work is trusted.
    assert!(
        service
            .list(&World::ctx(), OutboxFilter::default(), PageRequest::first())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_store_outage_is_unavailable() {
    let world = World::new();
    let service = service(&world);
    world.db.set_outage(true);
    let error = service
        .list(&operator(), OutboxFilter::default(), PageRequest::first())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable);
}

#[tokio::test]
async fn a_cursor_of_one_status_filter_is_refused_for_another() {
    let world = World::new();
    let service = service(&world);
    for _ in 0..3 {
        let id = world.enqueue_dummy().await;
        world.settle(id, Fate::Dead).await;
    }
    let dead = OutboxFilter {
        status: Some(OutboxStatus::Dead),
    };
    let page = service
        .list(&operator(), dead, PageRequest::with_limit(1))
        .await
        .unwrap();
    let cursor = page.next_cursor.unwrap();
    for other in [
        OutboxFilter::default(),
        OutboxFilter {
            status: Some(OutboxStatus::Pending),
        },
    ] {
        let error = service
            .list(&operator(), other, PageRequest::first().after(cursor.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "the filter is part of the cursor");
    }
    let next = service
        .list(&operator(), dead, PageRequest::with_limit(1).after(cursor))
        .await
        .unwrap();
    assert_eq!(next.items.len(), 1, "the same filter continues the list");
}

#[tokio::test]
async fn dead_webhook_deliveries_are_redelivered_not_retried() {
    let world = World::new();
    let service = service(&world);
    let envelope = world.envelope(World::tenant(), EventType::CalendarCreated);
    let id = world
        .enqueue(
            World::tenant(),
            OutboxMessage::Webhook(WebhookDelivery {
                delivery: world.id(),
                webhook: world.id(),
                envelope,
                details: None,
            }),
        )
        .await;
    world.settle(id, Fate::Dead).await;
    let error = service.retry(&operator(), id).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(error.public_message().as_str().contains("redeliver"), "{error}");
    assert_eq!(world.record(id).await.status, StoreStatus::Dead, "unchanged");
}
