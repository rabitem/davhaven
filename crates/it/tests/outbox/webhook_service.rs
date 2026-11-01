//! The management of webhook subscriptions: registration, patches, secrets, test events, deliveries, redelivery and
//! the rules every operation shares (scopes, tenants, the store being down).

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Duration as ChronoDuration;
use davhaven_testkit::davhaven_app::AppCore;
use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::outbox::{OutboxServiceImpl, WebhookServiceImpl};
use davhaven_testkit::davhaven_app::services::{
    Conditions, MergePatch, OutboxService as _, PageRequest, WebhookService as _,
};
use davhaven_testkit::davhaven_domain::{
    Actor, Channel, CredentialKind, CredentialRef, DeliveryId, ErrorKind, EventType, OutboxId, PrincipalId,
    RequestContext, Scope, ScopeSet, TenantId, TokenId, WebhookId, WebhookSubscription,
};
use davhaven_testkit::davhaven_ports::testing::PlainSealer;
use davhaven_testkit::davhaven_ports::{
    AuditFilter, Clock, Database, DeliveryRecord, DeliveryStatus as StoreDeliveryStatus, OutboxMessage, PageReq,
    PortError, SealAad, Sealed, SecretSealer, TxMode, WebhookDelivery,
};
use davhaven_testkit::davhaven_wire::{DeliveryStatus, WebhookCreate, WebhookCreated};
use secrecy::ExposeSecret;
use serde_json::json;
use url::Url;
use uuid::Uuid;

use super::support::{Fate, World};

fn service(world: &World) -> WebhookServiceImpl {
    WebhookServiceImpl::new(world.core.clone())
}

fn operator() -> RequestContext {
    World::token_ctx(World::tenant(), &[Scope::WebhooksManage])
}

fn creation(url: &str, events: &[EventType]) -> WebhookCreate {
    WebhookCreate {
        url: Url::parse(url).unwrap(),
        description: None,
        events: events.to_vec(),
        include_details: false,
        active: true,
    }
}

async fn create(world: &World, events: &[EventType]) -> WebhookCreated {
    service(world)
        .create(&operator(), creation("https://hooks.example.org/in", events))
        .await
        .unwrap()
}

fn patch_of(document: serde_json::Value) -> MergePatch {
    MergePatch::new(document).unwrap()
}

fn unseal(bytes: &[u8], tenant: TenantId, id: WebhookId) -> Option<String> {
    let opened = PlainSealer
        .open(
            &Sealed::from_bytes(bytes.to_vec()),
            &SealAad::webhook_secret(tenant, id),
        )
        .ok()?;
    String::from_utf8(opened.expose_secret().to_vec()).ok()
}

/// The audit records of the world's tenant: action and details.
async fn audit(world: &World, tenant: TenantId) -> Vec<(String, serde_json::Value)> {
    let mut tx = world.read(tenant).await;
    tx.audit()
        .list(&AuditFilter::default(), PageReq::first(1000))
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|row| (row.action, row.details))
        .collect()
}

async fn actions(world: &World) -> Vec<String> {
    audit(world, World::tenant())
        .await
        .into_iter()
        .map(|(action, _)| action)
        .collect()
}

#[tokio::test]
async fn creating_a_subscription_returns_the_secret_once_and_keeps_it_sealed() {
    let world = World::ready().await;
    let created = create(
        &world,
        &[EventType::PrincipalCreated, EventType::CalendarObjectsChanged],
    )
    .await;

    let secret = created.secret.clone();
    let key = secret.strip_prefix("whsec_").expect("the Standard Webhooks prefix");
    assert_eq!(STANDARD.decode(key).unwrap().len(), 32);
    assert!(
        !format!("{created:?}").contains(&secret),
        "the secret is not debug printed"
    );

    let view = &created.webhook;
    assert_eq!(view.url.as_str(), "https://hooks.example.org/in");
    assert_eq!(
        view.events,
        vec![EventType::PrincipalCreated, EventType::CalendarObjectsChanged]
    );
    assert_eq!((view.version, view.active, view.failure_count), (1, true, 0));
    assert!(!view.include_details && view.disabled_reason.is_none() && view.secret_rotated_at.is_none());

    let stored = world.subscription_of(World::tenant(), view.id).await;
    assert_eq!(
        unseal(&stored.sealed_secret, World::tenant(), view.id),
        Some(secret.clone())
    );
    assert_eq!(
        unseal(&stored.sealed_secret, World::other_tenant(), view.id),
        None,
        "bound to the tenant"
    );
    assert_eq!(
        unseal(
            &stored.sealed_secret,
            World::tenant(),
            WebhookId::from_uuid(Uuid::from_u128(1))
        ),
        None,
        "bound to the row"
    );
    assert!(stored.sealed_secret_previous.is_none());
    assert_eq!(actions(&world).await, vec!["webhook.created"]);

    let other = create(&world, &[EventType::PrincipalCreated]).await;
    assert_ne!(other.secret, secret, "every subscription has its own secret");
}

#[tokio::test]
async fn the_egress_policy_decides_at_registration() {
    let world = World::ready().await;
    let service = service(&world);
    world.http.refuse("internal.example.org");
    for url in ["http://hooks.example.org/in", "https://internal.example.org/in"] {
        let error = service
            .create(&operator(), creation(url, &[EventType::PrincipalCreated]))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{url}");
        assert!(error.public_message().as_str().contains("not allowed"), "{url}");
    }
    assert_eq!(
        service
            .list(&operator(), PageRequest::first())
            .await
            .unwrap()
            .items
            .len(),
        0
    );
    assert_eq!(actions(&world).await, Vec::<String>::new());
}

#[tokio::test]
async fn the_writable_fields_are_normalized_and_checked() {
    let world = World::ready().await;
    let service = service(&world);
    let mut body = creation(
        "https://hooks.example.org/in",
        &[
            EventType::PrincipalCreated,
            EventType::PrincipalCreated,
            EventType::CalendarCreated,
        ],
    );
    body.description = Some("   ".to_owned());
    let created = service.create(&operator(), body).await.unwrap();
    assert_eq!(
        created.webhook.events,
        vec![EventType::PrincipalCreated, EventType::CalendarCreated]
    );
    assert_eq!(created.webhook.description, None);

    for description in ["x".repeat(501), "line\nbreak".to_owned()] {
        let mut bad = creation("https://hooks.example.org/in", &[EventType::PrincipalCreated]);
        bad.description = Some(description);
        let error = service.create(&operator(), bad).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid);
    }
    let mut long = creation("https://hooks.example.org/in", &[EventType::PrincipalCreated]);
    long.description = Some("ü".repeat(500));
    assert!(
        service.create(&operator(), long).await.is_ok(),
        "500 characters, not 500 bytes"
    );
}

#[tokio::test]
async fn subscriptions_are_listed_and_read_within_their_tenant() {
    let world = World::ready().await;
    let service = service(&world);
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(create(&world, &[EventType::PrincipalCreated]).await.webhook.id);
    }
    let foreign = world
        .add_subscription(world.subscription(World::other_tenant(), &[EventType::PrincipalCreated]))
        .await;

    let first = service.list(&operator(), PageRequest::with_limit(2)).await.unwrap();
    assert_eq!(
        first.items.iter().map(|view| view.id).collect::<Vec<_>>(),
        ids[..2].to_vec()
    );
    let second = service
        .list(
            &operator(),
            PageRequest::with_limit(2).after(first.next_cursor.unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        second.items.iter().map(|view| view.id).collect::<Vec<_>>(),
        ids[2..].to_vec()
    );
    assert!(second.next_cursor.is_none());

    assert_eq!(service.get(&operator(), ids[1]).await.unwrap().id, ids[1]);
    for id in [foreign.id, WebhookId::from_uuid(Uuid::from_u128(1))] {
        assert_eq!(
            service.get(&operator(), id).await.unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }
}

#[tokio::test]
async fn a_merge_patch_changes_the_writable_fields() {
    let world = World::ready().await;
    let service = service(&world);
    let created = create(&world, &[EventType::PrincipalCreated]).await;
    let id = created.webhook.id;

    let patch = patch_of(json!({
        "url": "https://other.example.org/hook",
        "description": "Billing",
        "events": ["calendar.created", "grant.created"],
        "include_details": true
    }));
    let patched = service
        .patch(&operator(), id, patch, Conditions::if_match(1))
        .await
        .unwrap();
    assert_eq!(patched.url.as_str(), "https://other.example.org/hook");
    assert_eq!(patched.description.as_deref(), Some("Billing"));
    assert_eq!(
        patched.events,
        vec![EventType::CalendarCreated, EventType::GrantCreated]
    );
    assert!(patched.include_details && patched.active);
    assert_eq!(patched.version, 2);

    let cleared = service
        .patch(
            &operator(),
            id,
            patch_of(json!({"description": null})),
            Conditions::none(),
        )
        .await
        .unwrap();
    assert_eq!((cleared.description, cleared.version), (None, 3));
    assert_eq!(
        actions(&world).await,
        vec!["webhook.created", "webhook.updated", "webhook.updated"]
    );
    let stored = world.subscription_of(World::tenant(), id).await;
    assert_eq!(
        unseal(&stored.sealed_secret, World::tenant(), id),
        Some(created.secret),
        "the secret is untouched"
    );
}

#[tokio::test]
async fn a_patch_is_checked_like_a_creation() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    world.http.refuse("internal.example.org");

    for document in [
        json!({"url": "http://hooks.example.org/in"}),
        json!({"url": "https://internal.example.org/in"}),
        json!({"url": 5}),
        json!({"events": ["no.such.event"]}),
        json!({"failure_count": 0}),
        json!({"secret": "whsec_abc"}),
        json!({"sealed_secret": "abc"}),
        json!({"description": "x".repeat(501)}),
    ] {
        let error = service
            .patch(&operator(), id, patch_of(document.clone()), Conditions::none())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{document}");
    }
    assert_eq!(
        service.get(&operator(), id).await.unwrap().version,
        1,
        "nothing changed"
    );
}

#[tokio::test]
async fn patches_honor_if_match() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let patch = || patch_of(json!({"description": "x"}));
    let error = service
        .patch(&operator(), id, patch(), Conditions::if_match(7))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
    assert!(
        service
            .patch(&operator(), id, patch(), Conditions::if_match(1))
            .await
            .is_ok()
    );
    let error = service
        .patch(
            &operator(),
            WebhookId::from_uuid(Uuid::from_u128(1)),
            patch(),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn switching_a_disabled_subscription_on_again_clears_its_failures() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    // The subscription fails twice (the counter lives next to the row) and is switched off by the dispatcher.
    let mut tx = world.write(World::tenant()).await;
    tx.webhooks().record_failure(id).await.unwrap();
    tx.webhooks().record_failure(id).await.unwrap();
    tx.webhooks().disable(id, "max_consecutive_failures").await.unwrap();
    tx.commit().await.unwrap();

    let still_off = service
        .patch(
            &operator(),
            id,
            patch_of(json!({"description": "d"})),
            Conditions::none(),
        )
        .await
        .unwrap();
    assert_eq!(
        (
            still_off.active,
            still_off.failure_count,
            still_off.disabled_reason.as_deref()
        ),
        (false, 2, Some("max_consecutive_failures")),
        "an edit does not hide why it is off"
    );
    let on = service
        .patch(&operator(), id, patch_of(json!({"active": true})), Conditions::none())
        .await
        .unwrap();
    assert_eq!((on.active, on.failure_count, on.disabled_reason), (true, 0, None));
}

#[tokio::test]
async fn deleting_removes_the_subscription_and_its_deliveries() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    service.ping(&operator(), id).await.unwrap();
    let foreign = world
        .add_subscription(world.subscription(World::other_tenant(), &[]))
        .await;
    assert_eq!(world.deliveries(World::tenant()).await.len(), 1);

    assert_eq!(
        service.delete(&operator(), foreign.id).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    service.delete(&operator(), id).await.unwrap();
    assert_eq!(
        service.get(&operator(), id).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        service.delete(&operator(), id).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(world.deliveries(World::tenant()).await, Vec::new());
    assert_eq!(
        actions(&world).await,
        vec!["webhook.created", "webhook.pinged", "webhook.deleted"]
    );
}

#[tokio::test]
async fn rotating_keeps_the_previous_secret_for_the_overlap() {
    let world = World::ready().await;
    let service = service(&world);
    let created = create(&world, &[EventType::PrincipalCreated]).await;
    let id = created.webhook.id;
    world.clock.advance(ChronoDuration::days(3));

    let rotated = service.rotate_secret(&operator(), id).await.unwrap();
    assert_ne!(rotated.secret, created.secret);
    assert!(rotated.secret.starts_with("whsec_"));
    assert_eq!(rotated.rotated_at, world.clock.now());
    assert!(!format!("{rotated:?}").contains(&rotated.secret));

    let stored = world.subscription_of(World::tenant(), id).await;
    assert_eq!(
        unseal(&stored.sealed_secret, World::tenant(), id),
        Some(rotated.secret.clone())
    );
    let previous = stored
        .sealed_secret_previous
        .expect("the old secret stays during the overlap");
    assert_eq!(unseal(&previous, World::tenant(), id), Some(created.secret));
    assert_eq!(
        (stored.secret_rotated_at, stored.version),
        (Some(rotated.rotated_at), 2)
    );
    assert_eq!(
        service.get(&operator(), id).await.unwrap().secret_rotated_at,
        Some(rotated.rotated_at)
    );
    assert_eq!(actions(&world).await, vec!["webhook.created", "webhook.secret_rotated"]);

    let unknown = service
        .rotate_secret(&operator(), WebhookId::from_uuid(Uuid::from_u128(1)))
        .await;
    assert_eq!(unknown.unwrap_err().kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn a_second_rotation_ends_the_overlap_of_the_first() {
    let world = World::ready().await;
    let service = service(&world);
    let created = create(&world, &[EventType::PrincipalCreated]).await;
    let id = created.webhook.id;
    let first = service.rotate_secret(&operator(), id).await.unwrap();
    let second = service.rotate_secret(&operator(), id).await.unwrap();
    let stored = world.subscription_of(World::tenant(), id).await;
    assert_eq!(
        unseal(&stored.sealed_secret, World::tenant(), id),
        Some(second.secret),
        "the newest secret signs"
    );
    let previous = stored.sealed_secret_previous.unwrap();
    assert_eq!(
        unseal(&previous, World::tenant(), id),
        Some(first.secret),
        "only the one before it overlaps"
    );
    assert_ne!(
        unseal(&previous, World::tenant(), id),
        Some(created.secret),
        "the original secret is revoked at once: rotating twice is how a leaked secret is retired"
    );
}

#[tokio::test]
async fn a_ping_queues_a_test_event_for_that_subscription_only() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let bystander = create(&world, &[EventType::CalendarCreated]).await.webhook.id;

    let delivery = service.ping(&operator(), id).await.unwrap();
    assert_eq!(
        (
            delivery.status,
            delivery.attempts,
            delivery.webhook_id,
            delivery.response_status
        ),
        (DeliveryStatus::Pending, 0, id, None)
    );

    let deliveries = world.deliveries(World::tenant()).await;
    let record = deliveries.iter().find(|record| record.id == delivery.id).unwrap();
    assert_eq!(record.event_id, delivery.event_id);
    let outbox = world.outbox().await;
    let queued = outbox
        .iter()
        .find(|queued| queued.id.as_uuid() == delivery.id.as_uuid())
        .expect("the outbox record has the id of its delivery");
    assert_eq!(queued.kind, "webhook");
    let Ok(OutboxMessage::Webhook(message)) = queued.message() else {
        panic!("a webhook message");
    };
    assert_eq!((message.webhook, message.delivery), (id, delivery.id));
    assert_eq!(message.envelope.event_type, EventType::WebhookPing);
    assert_eq!(message.envelope.tenant, World::tenant());
    assert_eq!(message.envelope.id, delivery.event_id);
    assert_eq!(message.envelope.occurred_at, world.clock.now());
    assert!(
        deliveries.iter().all(|record| record.subscription_id != bystander),
        "other subscriptions are not pinged"
    );
}

#[tokio::test]
async fn a_disabled_subscription_cannot_be_pinged() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    service
        .patch(&operator(), id, patch_of(json!({"active": false})), Conditions::none())
        .await
        .unwrap();
    assert_eq!(
        service.ping(&operator(), id).await.unwrap_err().kind(),
        ErrorKind::Conflict
    );
    assert_eq!(world.deliveries(World::tenant()).await, Vec::new());
    assert_eq!(
        service
            .ping(&operator(), WebhookId::from_uuid(Uuid::from_u128(1)))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn deliveries_are_listed_per_subscription() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let other = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let mut expected = Vec::new();
    for _ in 0..3 {
        expected.push(service.ping(&operator(), id).await.unwrap().id);
    }
    service.ping(&operator(), other).await.unwrap();

    let first = service
        .deliveries(&operator(), id, PageRequest::with_limit(2))
        .await
        .unwrap();
    assert_eq!(
        first.items.iter().map(|item| item.id).collect::<Vec<_>>(),
        expected[..2].to_vec()
    );
    let cursor = first.next_cursor.unwrap();
    let rest = service
        .deliveries(&operator(), id, PageRequest::with_limit(2).after(cursor.clone()))
        .await
        .unwrap();
    assert_eq!(
        rest.items.iter().map(|item| item.id).collect::<Vec<_>>(),
        expected[2..].to_vec()
    );

    let borrowed = service
        .deliveries(&operator(), other, PageRequest::first().after(cursor))
        .await
        .unwrap_err();
    assert_eq!(
        borrowed.kind(),
        ErrorKind::Invalid,
        "a cursor belongs to its subscription"
    );
    let unknown = service
        .deliveries(
            &operator(),
            WebhookId::from_uuid(Uuid::from_u128(1)),
            PageRequest::first(),
        )
        .await;
    assert_eq!(unknown.unwrap_err().kind(), ErrorKind::NotFound);
}

/// Puts the delivery row `id` into `status`, as an attempt would have left it.
async fn settle_delivery(world: &World, id: DeliveryId, status: StoreDeliveryStatus) {
    let mut tx = world.write(World::tenant()).await;
    let current = tx.webhooks().get_delivery(id).await.unwrap();
    tx.webhooks()
        .update_delivery(
            DeliveryRecord {
                status,
                attempts: 4,
                response_status: Some(500),
                last_error: Some("the receiver answered 500".to_owned()),
                ..current.clone()
            },
            current.version,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn webhook_records(
    records: &[davhaven_testkit::davhaven_ports::OutboxRecord],
) -> Vec<&davhaven_testkit::davhaven_ports::OutboxRecord> {
    records.iter().filter(|record| record.kind == "webhook").collect()
}

#[tokio::test]
async fn a_finished_delivery_can_be_sent_again() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let first = service.ping(&operator(), id).await.unwrap();
    let original = world
        .outbox()
        .await
        .into_iter()
        .find(|record| record.id.as_uuid() == first.id.as_uuid())
        .unwrap();

    for finished in [StoreDeliveryStatus::Dead, StoreDeliveryStatus::Delivered] {
        settle_delivery(&world, first.id, finished).await;
        world.clock.advance(ChronoDuration::hours(1));
        let again = service.redeliver(&operator(), id, first.id).await.unwrap();
        assert_eq!(
            (
                again.id,
                again.status,
                again.attempts,
                again.response_status,
                again.last_error.clone()
            ),
            (first.id, DeliveryStatus::Pending, 0, None, None),
            "{finished:?}"
        );
        assert_eq!(again.at, world.clock.now());
    }

    let outbox = world.outbox().await;
    let messages = webhook_records(&outbox);
    assert_eq!(messages.len(), 3, "the original and one new record per redelivery");
    for record in &messages {
        assert_eq!(record.payload, original.payload, "the same event goes out again");
    }
    let mut ids: Vec<OutboxId> = messages.iter().map(|record| record.id).collect();
    ids.dedup();
    assert_eq!(ids.len(), 3, "each record has its own id and its own retry window");
    assert_eq!(
        world.deliveries(World::tenant()).await.len(),
        1,
        "the delivery row is reused"
    );
}

#[tokio::test]
async fn deliveries_in_progress_or_without_their_event_cannot_be_sent_again() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let other = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let delivery = service.ping(&operator(), id).await.unwrap().id;

    for running in [StoreDeliveryStatus::Pending, StoreDeliveryStatus::Failed] {
        settle_delivery(&world, delivery, running).await;
        let error = service.redeliver(&operator(), id, delivery).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Conflict, "{running:?}");
    }

    settle_delivery(&world, delivery, StoreDeliveryStatus::Dead).await;
    let wrong = service.redeliver(&operator(), other, delivery).await.unwrap_err();
    assert_eq!(
        wrong.kind(),
        ErrorKind::NotFound,
        "the delivery of another subscription"
    );
    let unknown = service
        .redeliver(&operator(), id, DeliveryId::from_uuid(Uuid::from_u128(1)))
        .await
        .unwrap_err();
    assert_eq!(unknown.kind(), ErrorKind::NotFound);

    // Retention removes the outbox record that carried the event (done records after seven days).
    world.settle(OutboxId::from_uuid(delivery.as_uuid()), Fate::Done).await;
    world.clock.advance(ChronoDuration::days(8));
    let mut system = world.db.store().begin_system().await.unwrap();
    let cut = world.clock.now() - ChronoDuration::days(7);
    system.retention().purge_outbox(cut, cut).await.unwrap();
    system.commit().await.unwrap();
    let purged = service.redeliver(&operator(), id, delivery).await.unwrap_err();
    assert_eq!(purged.kind(), ErrorKind::Conflict, "retention removed the event");
    assert!(purged.public_message().as_str().contains("purged"));

    service
        .patch(&operator(), id, patch_of(json!({"active": false})), Conditions::none())
        .await
        .unwrap();
    assert_eq!(
        service.redeliver(&operator(), id, delivery).await.unwrap_err().kind(),
        ErrorKind::Conflict,
        "a disabled subscription receives nothing"
    );
}

#[tokio::test]
async fn a_delivery_whose_record_died_unsettled_can_be_sent_again_once_it_has_stalled() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let delivery = service.ping(&operator(), id).await.unwrap().id;
    // The record went dead (the store was down for the whole retry window) and the row never found out.
    world.settle(OutboxId::from_uuid(delivery.as_uuid()), Fate::Dead).await;
    settle_delivery(&world, delivery, StoreDeliveryStatus::Failed).await;

    let early = service.redeliver(&operator(), id, delivery).await.unwrap_err();
    assert_eq!(
        early.kind(),
        ErrorKind::Conflict,
        "a delivery that was touched a moment ago may still be in progress"
    );
    world.clock.advance(ChronoDuration::hours(3));
    let again = service.redeliver(&operator(), id, delivery).await.unwrap();
    assert_eq!(again.status, DeliveryStatus::Pending);
}

#[tokio::test]
async fn invalid_fields_are_named_by_pointer_and_code() {
    let world = World::ready().await;
    let service = service(&world);
    world.http.refuse("internal.example.org");
    let pointer_and_code = |error: &AppError| {
        error
            .field_errors()
            .iter()
            .map(|field| (field.pointer, field.code))
            .collect::<Vec<_>>()
    };

    let empty = service
        .create(&operator(), creation("https://hooks.example.org/in", &[]))
        .await
        .unwrap_err();
    assert_eq!(empty.kind(), ErrorKind::Invalid);
    assert_eq!(pointer_and_code(&empty), vec![("/events", "empty")]);

    let refused = service
        .create(
            &operator(),
            creation("https://internal.example.org/in", &[EventType::PrincipalCreated]),
        )
        .await
        .unwrap_err();
    assert_eq!(pointer_and_code(&refused), vec![("/url", "not-allowed")]);

    let long_url = format!("https://hooks.example.org/{}", "a".repeat(2100));
    let too_long = service
        .create(&operator(), creation(&long_url, &[EventType::PrincipalCreated]))
        .await
        .unwrap_err();
    assert_eq!(pointer_and_code(&too_long), vec![("/url", "too-long")]);
    assert!(
        too_long.public_message().as_str().contains("too long"),
        "an over-long URL is not called a policy refusal: {too_long}"
    );

    let mut bad = creation("https://hooks.example.org/in", &[EventType::PrincipalCreated]);
    bad.description = Some("x".repeat(501));
    assert_eq!(
        pointer_and_code(&service.create(&operator(), bad.clone()).await.unwrap_err()),
        vec![("/description", "too-long")]
    );
    bad.description = Some("line\nbreak".to_owned());
    assert_eq!(
        pointer_and_code(&service.create(&operator(), bad).await.unwrap_err()),
        vec![("/description", "control-characters")]
    );

    // A patch that empties the list is checked like a creation.
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let error = service
        .patch(&operator(), id, patch_of(json!({"events": []})), Conditions::none())
        .await
        .unwrap_err();
    assert_eq!(pointer_and_code(&error), vec![("/events", "empty")]);
}

#[tokio::test]
async fn the_test_event_cannot_be_subscribed_to() {
    // `webhook.ping` goes to the one subscription that asks for it and ignores every filter: listing it in
    // `events` would promise something the fan-out never does.
    let world = World::ready().await;
    let service = service(&world);
    let error = service
        .create(
            &operator(),
            creation(
                "https://hooks.example.org/in",
                &[EventType::PrincipalCreated, EventType::WebhookPing],
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(
        error
            .field_errors()
            .iter()
            .map(|field| (field.pointer, field.code))
            .collect::<Vec<_>>(),
        vec![("/events", "not-allowed")]
    );

    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let error = service
        .patch(
            &operator(),
            id,
            patch_of(json!({"events": ["webhook.ping"]})),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    // The notice of the automatic disabling can be subscribed to.
    assert!(
        service
            .patch(
                &operator(),
                id,
                patch_of(json!({"events": ["webhook.disabled"]})),
                Conditions::none()
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_name_that_does_not_resolve_and_a_name_the_policy_refuses_are_answered_alike() {
    let world = World::ready().await;
    let service = service(&world);
    world.http.refuse("internal.example.org");
    world.http.unresolvable("nowhere.example.org");
    let mut answers = Vec::new();
    for url in ["https://internal.example.org/in", "https://nowhere.example.org/in"] {
        let error = service
            .create(&operator(), creation(url, &[EventType::PrincipalCreated]))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{url}");
        answers.push((
            error.public_message().as_str().to_owned(),
            error
                .field_errors()
                .iter()
                .map(|field| (field.pointer, field.code))
                .collect::<Vec<_>>(),
        ));
    }
    assert_eq!(
        answers[0], answers[1],
        "the answer must not tell a tenant administrator which names exist in the private DNS"
    );
}

#[tokio::test]
async fn a_tenant_may_have_only_so_many_subscriptions() {
    let world = World::ready_with(|deps| deps.config.outbox.max_webhooks_per_tenant = 2).await;
    let service = service(&world);
    let first = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    create(&world, &[EventType::PrincipalCreated]).await;
    let error = service
        .create(
            &operator(),
            creation("https://hooks.example.org/in", &[EventType::PrincipalCreated]),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(error.public_message().as_str().contains("limit"), "{error}");
    assert_eq!(
        service
            .list(&operator(), PageRequest::first())
            .await
            .unwrap()
            .items
            .len(),
        2
    );

    // Subscriptions of other tenants do not count, and deleting one makes room.
    world
        .add_subscription(world.subscription(World::other_tenant(), &[EventType::PrincipalCreated]))
        .await;
    service.delete(&operator(), first).await.unwrap();
    assert!(
        service
            .create(
                &operator(),
                creation("https://hooks.example.org/in", &[EventType::PrincipalCreated])
            )
            .await
            .is_ok()
    );
}

/// An HTTP client whose URL check changes the subscription it is asked about, the way a concurrent request does
/// between the read and the write of a patch.
struct Racing {
    database: Arc<dyn davhaven_testkit::davhaven_ports::Database>,
    subscription: WebhookId,
    races: std::sync::atomic::AtomicU32,
}

#[async_trait]
impl davhaven_testkit::davhaven_ports::HttpClient for Racing {
    async fn send(
        &self,
        _request: davhaven_testkit::davhaven_ports::OutboundRequest,
    ) -> Result<davhaven_testkit::davhaven_ports::OutboundResponse, PortError> {
        Err(PortError::internal("not used"))
    }

    async fn validate_url(&self, _url: &Url) -> Result<(), PortError> {
        use std::sync::atomic::Ordering;
        if self.races.load(Ordering::SeqCst) > 0 {
            self.races.fetch_sub(1, Ordering::SeqCst);
            let mut tx = self.database.begin(World::tenant(), TxMode::ReadWrite).await?;
            let current = tx.webhooks().get(self.subscription).await?;
            let version = current.version;
            tx.webhooks()
                .update(
                    WebhookSubscription {
                        description: Some("changed meanwhile".to_owned()),
                        ..current
                    },
                    version,
                )
                .await?;
            tx.commit().await?;
        }
        Ok(())
    }
}

fn racing(world: &World, id: WebhookId, races: u32) -> WebhookServiceImpl {
    let mut deps = world.core.deps().clone();
    deps.http = Arc::new(Racing {
        database: Arc::clone(&deps.database),
        subscription: id,
        races: std::sync::atomic::AtomicU32::new(races),
    });
    WebhookServiceImpl::new(AppCore::new(deps))
}

#[tokio::test]
async fn a_patch_that_loses_a_race_is_computed_again_unless_the_client_named_a_version() {
    let world = World::ready().await;
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let patch = || patch_of(json!({"url": "https://other.example.org/hook"}));

    // Without If-Match a concurrent change is no reason to fail: the patch is applied to the new state.
    let patched = racing(&world, id, 2)
        .patch(&operator(), id, patch(), Conditions::none())
        .await
        .unwrap();
    assert_eq!(patched.url.as_str(), "https://other.example.org/hook");
    assert_eq!(
        patched.description.as_deref(),
        Some("changed meanwhile"),
        "the other change survived"
    );
    assert_eq!(patched.version, 4, "two concurrent changes and ours");

    // The attempts are bounded.
    let error = racing(&world, id, 10)
        .patch(
            &operator(),
            id,
            patch_of(json!({"url": "https://third.example.org/hook"})),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);

    // A client that named a version learns that it is stale, at once.
    let current = service(&world).get(&operator(), id).await.unwrap();
    let error = racing(&world, id, 1)
        .patch(
            &operator(),
            id,
            patch_of(json!({"url": "https://fourth.example.org/hook"})),
            Conditions::if_match(current.version),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
}

#[tokio::test]
async fn test_events_are_rate_limited_per_subscription_and_a_broken_limiter_does_not_block_them() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;

    service.ping(&operator(), id).await.unwrap();
    world.limiter.deny_next(std::time::Duration::from_secs(45));
    let error = service.ping(&operator(), id).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RateLimited);
    assert_eq!(error.retry_after(), Some(std::time::Duration::from_secs(45)));
    assert_eq!(
        world.deliveries(World::tenant()).await.len(),
        1,
        "the refused ping created nothing"
    );
    let checks = world.limiter.checks();
    assert!(
        checks
            .iter()
            .all(|(key, cost)| key.bucket == "webhook_ping" && *cost == 1),
        "{checks:?}"
    );

    world.limiter.break_down();
    assert!(service.ping(&operator(), id).await.is_ok(), "fail open");
}

#[tokio::test]
async fn the_audit_log_says_what_changed_and_where_the_events_go() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    service
        .patch(
            &operator(),
            id,
            patch_of(json!({"url": "https://other.example.org/secret/path?token=abc", "include_details": true})),
            Conditions::none(),
        )
        .await
        .unwrap();
    service
        .patch(&operator(), id, patch_of(json!({"active": false})), Conditions::none())
        .await
        .unwrap();

    let records = audit(&world, World::tenant()).await;
    let created = &records[0];
    assert_eq!(created.0, "webhook.created");
    assert_eq!(created.1["host"], "hooks.example.org");
    let url_change = &records[1];
    assert_eq!(url_change.0, "webhook.updated");
    assert_eq!(url_change.1["fields"], json!(["url", "include_details"]));
    assert_eq!(
        url_change.1["host"], "other.example.org",
        "the host, never the path or the query"
    );
    let switched_off = &records[2];
    assert_eq!(switched_off.1["fields"], json!(["active"]));
    assert!(switched_off.1.get("host").is_none(), "the URL did not change");
    let shown = serde_json::to_string(&records).unwrap();
    assert!(
        !shown.contains("secret/path") && !shown.contains("token=abc"),
        "{shown}"
    );
}

#[tokio::test]
async fn a_test_event_and_a_repeated_delivery_leave_an_audit_record() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let ping = service.ping(&operator(), id).await.unwrap();
    settle_delivery(&world, ping.id, StoreDeliveryStatus::Dead).await;
    service.redeliver(&operator(), id, ping.id).await.unwrap();

    let records = audit(&world, World::tenant()).await;
    let actions: Vec<&str> = records.iter().map(|(action, _)| action.as_str()).collect();
    assert_eq!(actions, ["webhook.created", "webhook.pinged", "webhook.redelivered"]);
    for (_, details) in &records[1..] {
        assert_eq!(details["webhook"], json!(id), "{details}");
        assert_eq!(details["delivery"], json!(ping.id), "{details}");
    }

    // A refused call changes nothing and says nothing.
    let refused = service
        .redeliver(&operator(), id, DeliveryId::from_uuid(Uuid::from_u128(1)))
        .await
        .unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::NotFound);
    assert_eq!(audit(&world, World::tenant()).await.len(), 3);
}

#[tokio::test]
async fn the_subscription_never_exposes_its_secret_through_the_views() {
    let world = World::ready().await;
    let service = service(&world);
    let created = create(&world, &[EventType::PrincipalCreated]).await;
    let id = created.webhook.id;
    let shown = [
        serde_json::to_string(&service.get(&operator(), id).await.unwrap()).unwrap(),
        serde_json::to_string(&service.list(&operator(), PageRequest::first()).await.unwrap()).unwrap(),
    ];
    let body = created.secret.strip_prefix("whsec_").unwrap().to_owned();
    for text in shown {
        assert!(!text.contains(&body) && !text.contains("sealed"), "{text}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Who may call, and which tenant they reach
// ---------------------------------------------------------------------------------------------------------------

/// The result of every operation of the service for `ctx` on the subscription `id` and its delivery `delivery`.
async fn every_operation(
    service: &WebhookServiceImpl,
    ctx: &RequestContext,
    id: WebhookId,
    delivery: DeliveryId,
) -> Vec<(&'static str, Option<AppError>)> {
    vec![
        (
            "create",
            service
                .create(
                    ctx,
                    creation("https://hooks.example.org/in", &[EventType::PrincipalCreated]),
                )
                .await
                .err(),
        ),
        ("list", service.list(ctx, PageRequest::first()).await.err()),
        ("get", service.get(ctx, id).await.err()),
        (
            "patch",
            service
                .patch(ctx, id, patch_of(json!({"active": false})), Conditions::none())
                .await
                .err(),
        ),
        ("delete", service.delete(ctx, id).await.err()),
        ("rotate_secret", service.rotate_secret(ctx, id).await.err()),
        ("ping", service.ping(ctx, id).await.err()),
        (
            "deliveries",
            service.deliveries(ctx, id, PageRequest::first()).await.err(),
        ),
        ("redeliver", service.redeliver(ctx, id, delivery).await.err()),
    ]
}

#[tokio::test]
async fn every_operation_needs_a_tenant_token_with_the_webhooks_scope() {
    let world = World::ready().await;
    let service = service(&world);
    let id = create(&world, &[EventType::PrincipalCreated]).await.webhook.id;
    let delivery = service.ping(&operator(), id).await.unwrap().id;
    let principal = PrincipalId::from_uuid(Uuid::from_u128(0x99));
    let token = TokenId::from_uuid(Uuid::from_u128(0x71));
    let all_scopes = ScopeSet::of(&[Scope::WebhooksManage, Scope::OutboxManage, Scope::EventsRead]);
    let denied: Vec<(&str, RequestContext)> = vec![
        (
            "a tenant token without the scope",
            World::token_ctx(World::tenant(), &[Scope::OutboxManage]),
        ),
        (
            "anonymous",
            RequestContext {
                actor: Actor::Anonymous,
                ..operator()
            },
        ),
        (
            "a principal token with the scope",
            RequestContext {
                actor: Actor::PrincipalToken { principal, token },
                scopes: all_scopes,
                ..operator()
            },
        ),
        (
            "a system token",
            RequestContext {
                actor: Actor::SystemToken(token),
                scopes: all_scopes,
                ..operator()
            },
        ),
        (
            "a principal on DAV",
            RequestContext {
                actor: Actor::Principal(principal),
                channel: Channel::Dav,
                scopes: all_scopes,
                credential: Some(CredentialRef {
                    kind: CredentialKind::AppPassword,
                    id: Uuid::from_u128(0x72),
                }),
                ..operator()
            },
        ),
        (
            "a feed reader",
            RequestContext {
                actor: Actor::FeedReader { principal, token },
                channel: Channel::Feed,
                scopes: all_scopes,
                ..operator()
            },
        ),
    ];
    for (who, ctx) in denied {
        for (operation, error) in every_operation(&service, &ctx, id, delivery).await {
            let error = error.unwrap_or_else(|| panic!("{who} may {operation}"));
            assert_eq!(error.kind(), ErrorKind::Forbidden, "{who}: {operation}");
        }
    }
    assert_eq!(
        service
            .list(&operator(), PageRequest::first())
            .await
            .unwrap()
            .items
            .len(),
        1,
        "nothing was created or deleted"
    );
}

#[tokio::test]
async fn nothing_of_another_tenant_can_be_reached_through_any_operation() {
    let world = World::ready().await;
    let service = service(&world);
    let outbox = OutboxServiceImpl::new(world.core.clone());

    // The other tenant has a subscription, a delivery and a dead outbox record.
    let theirs = World::other_tenant();
    let hook = world
        .add_subscription(world.subscription(theirs, &[EventType::PrincipalCreated]))
        .await;
    let envelope = world.envelope(theirs, EventType::PrincipalCreated);
    let delivery: DeliveryId = world.id();
    let now = world.clock.now();
    let mut tx = world.write(theirs).await;
    tx.webhooks()
        .create_delivery(DeliveryRecord {
            id: delivery,
            tenant_id: theirs,
            subscription_id: hook.id,
            event_id: envelope.id,
            status: StoreDeliveryStatus::Dead,
            attempts: 1,
            response_status: None,
            last_error: None,
            at: now,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let record = world
        .enqueue(
            theirs,
            OutboxMessage::Webhook(WebhookDelivery {
                delivery,
                webhook: hook.id,
                envelope,
                details: None,
            }),
        )
        .await;
    world.settle(record, Fate::Dead).await;
    let before = (
        world.subscription_of(theirs, hook.id).await,
        world.deliveries(theirs).await,
        world.outbox_of(theirs).await,
        audit(&world, theirs).await.len(),
    );

    let ctx = operator();
    let mut results = every_operation(&service, &ctx, hook.id, delivery).await;
    results.retain(|(operation, _)| !matches!(*operation, "create" | "list"));
    results.push((
        "outbox retry",
        outbox
            .retry(&World::token_ctx(World::tenant(), &[Scope::OutboxManage]), record)
            .await
            .err(),
    ));
    for (operation, error) in results {
        let error = error.unwrap_or_else(|| panic!("{operation} reached a foreign row"));
        assert_eq!(error.kind(), ErrorKind::NotFound, "{operation}");
    }

    // Nothing changed: no row, no outbox record, no audit record.
    let after = (
        world.subscription_of(theirs, hook.id).await,
        world.deliveries(theirs).await,
        world.outbox_of(theirs).await,
        audit(&world, theirs).await.len(),
    );
    assert_eq!(after, before);

    // Their rows are not listed to us either.
    let listed = service.list(&ctx, PageRequest::first()).await.unwrap();
    assert!(
        listed.items.iter().all(|view| view.id != hook.id),
        "no foreign subscription is listed"
    );
}

#[tokio::test]
async fn a_store_outage_is_unavailable() {
    let world = World::ready().await;
    let service = service(&world);
    world.db.set_outage(true);
    let error = service.list(&operator(), PageRequest::first()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    let error = service
        .create(
            &operator(),
            creation("https://hooks.example.org/in", &[EventType::PrincipalCreated]),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable);
}
