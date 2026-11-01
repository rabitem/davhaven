//! The `domain_event` handler: the fan-out of an event to the webhook subscriptions of its tenant and to the event
//! sinks, and the details of the objects an event is about (`include_details`).

use std::sync::Arc;

use davhaven_testkit::davhaven_app::imip::BackendError;
use davhaven_testkit::davhaven_app::outbox::DomainEventHandler;
use davhaven_testkit::davhaven_app::outbox::events::delivery_id;
use davhaven_testkit::davhaven_domain::events::{
    ObjectChange, ObjectChangeKind, ObjectsChangedPayload, RsvpPayload, WebhookPayload,
};
use davhaven_testkit::davhaven_domain::{
    AuditActor, CalendarId, CalendarKind, Classification, Envelope, EventData, EventPayload, EventType, ObjectId,
    ObjectUri, PartStat, SyncToken, TenantId, Uid, WebhookId,
};
use davhaven_testkit::davhaven_ports::{
    Clock as _, DeliveryStatus, HandlerError, OutboxHandler, OutboxMessage, OutboxRecord, OutboxStatus,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::support::{CapturingSink, FakeBackend, World};

fn other_tenant() -> TenantId {
    World::other_tenant()
}

async fn queue_event(world: &World, envelope: &Envelope) -> OutboxRecord {
    let id = world
        .enqueue(envelope.tenant, OutboxMessage::DomainEvent(envelope.clone()))
        .await;
    world.read(envelope.tenant).await.outbox().get(id).await.unwrap()
}

fn handler_with_backend(world: &World, backend: &Arc<FakeBackend>) -> DomainEventHandler {
    DomainEventHandler::with_backend(world.core.clone(), backend.as_backend())
}

fn handler(world: &World) -> DomainEventHandler {
    handler_with_backend(world, &FakeBackend::new(EventData::default()))
}

#[tokio::test]
async fn an_event_becomes_one_delivery_per_matching_active_subscription() {
    let world = World::new();
    let tenant = World::tenant();
    let wanted = world
        .add_subscription(world.subscription(tenant, &[EventType::PrincipalCreated, EventType::CalendarCreated]))
        .await;
    let also = world
        .add_subscription(world.subscription(tenant, &[EventType::PrincipalCreated]))
        .await;
    world
        .add_subscription(world.subscription(tenant, &[EventType::CalendarCreated]))
        .await;
    let mut inactive = world.subscription(tenant, &[EventType::PrincipalCreated]);
    inactive.active = false;
    world.add_subscription(inactive).await;
    world
        .add_subscription(world.subscription(other_tenant(), &[EventType::PrincipalCreated]))
        .await;
    let envelope = world.envelope(tenant, EventType::PrincipalCreated);
    let record = queue_event(&world, &envelope).await;

    handler(&world).handle(&record).await.unwrap();

    let deliveries = world.deliveries(tenant).await;
    let mut targets: Vec<WebhookId> = deliveries.iter().map(|delivery| delivery.subscription_id).collect();
    targets.sort();
    let mut expected = vec![wanted.id, also.id];
    expected.sort();
    assert_eq!(targets, expected);
    for delivery in &deliveries {
        assert_eq!(delivery.status, DeliveryStatus::Pending);
        assert_eq!(
            (delivery.attempts, delivery.event_id, delivery.tenant_id),
            (0, envelope.id, tenant)
        );
        assert_eq!(delivery.id, delivery_id(envelope.id, delivery.subscription_id));
    }
    assert!(
        world.deliveries(other_tenant()).await.is_empty(),
        "the other tenant's subscription did not get the event of this tenant"
    );
    let outbox = world.outbox().await;
    let messages = world.webhook_messages(tenant).await;
    assert_eq!(messages.len(), 2);
    for message in messages {
        assert_eq!(message.envelope, envelope);
        assert_eq!(message.delivery, delivery_id(envelope.id, message.webhook));
        let queued = outbox
            .iter()
            .find(|record| record.id.as_uuid() == message.delivery.as_uuid())
            .expect("the outbox record has the id of its delivery");
        assert_eq!(
            (queued.kind.as_str(), queued.status, queued.tenant_id),
            ("webhook", OutboxStatus::Pending, tenant)
        );
    }
}

#[tokio::test]
async fn handling_a_record_again_creates_nothing_twice() {
    let world = World::new();
    let tenant = World::tenant();
    world
        .add_subscription(world.subscription(tenant, &[EventType::PrincipalCreated]))
        .await;
    let handler = handler(&world);
    let envelope = world.envelope(tenant, EventType::PrincipalCreated);
    let record = queue_event(&world, &envelope).await;

    handler.handle(&record).await.unwrap();
    handler.handle(&record).await.unwrap();

    assert_eq!(world.deliveries(tenant).await.len(), 1);
    assert_eq!(world.webhook_messages(tenant).await.len(), 1);

    // A subscription that appears between two passes gets its delivery in the second one.
    world
        .add_subscription(world.subscription(tenant, &[EventType::PrincipalCreated]))
        .await;
    handler.handle(&record).await.unwrap();
    assert_eq!(world.deliveries(tenant).await.len(), 2);
}

#[tokio::test]
async fn sinks_see_every_event() {
    let first = CapturingSink::new("first");
    let second = CapturingSink::new("second");
    let world = World::with(|deps| {
        let sinks = [first.as_sink(), second.as_sink()];
        deps.event_sinks.extend(sinks);
    });
    let envelope = world.envelope(World::tenant(), EventType::CalendarCreated);
    let record = queue_event(&world, &envelope).await;

    handler(&world).handle(&record).await.unwrap();

    assert_eq!(first.delivered(), vec![envelope.id]);
    assert_eq!(second.delivered(), vec![envelope.id]);
}

#[tokio::test]
async fn an_unavailable_sink_asks_for_a_retry_but_the_deliveries_are_kept() {
    let tenant = World::tenant();
    let flaky = CapturingSink::new("flaky");
    let steady = CapturingSink::new("steady");
    let world = World::with(|deps| {
        let sinks = [flaky.as_sink(), steady.as_sink()];
        deps.event_sinks.extend(sinks);
    });
    world
        .add_subscription(world.subscription(tenant, &[EventType::CalendarCreated]))
        .await;
    flaky.fail_next(HandlerError::retryable("collector down"));
    let handler = handler(&world);
    let envelope = world.envelope(tenant, EventType::CalendarCreated);
    let record = queue_event(&world, &envelope).await;

    let error = handler.handle(&record).await.unwrap_err();
    assert_eq!(
        error,
        HandlerError::retryable("the event sink `flaky` is not available"),
        "the text of the sink stays in the log"
    );
    assert_eq!(world.deliveries(tenant).await.len(), 1, "the fan-out committed");
    assert_eq!(steady.delivered(), vec![envelope.id]);

    handler.handle(&record).await.unwrap();
    assert_eq!(
        world.deliveries(tenant).await.len(),
        1,
        "the retry does not duplicate it"
    );
    assert_eq!(flaky.delivered(), vec![envelope.id]);
    assert_eq!(
        steady.delivered(),
        vec![envelope.id, envelope.id],
        "sinks deduplicate on the id"
    );
}

#[tokio::test]
async fn a_sink_that_refuses_for_good_does_not_block_the_event() {
    let refusing = CapturingSink::new("refusing");
    let world = World::with(|deps| {
        let sinks = [refusing.as_sink()];
        deps.event_sinks.extend(sinks);
    });
    refusing.fail_next(HandlerError::permanent("schema mismatch"));
    let envelope = world.envelope(World::tenant(), EventType::CalendarCreated);
    let record = queue_event(&world, &envelope).await;
    handler(&world).handle(&record).await.unwrap();
    assert_eq!(refusing.delivered(), Vec::new());
}

#[tokio::test]
async fn pings_are_not_fanned_out() {
    let tenant = World::tenant();
    let sink = CapturingSink::new("log");
    let world = World::with(|deps| {
        let sinks = [sink.as_sink()];
        deps.event_sinks.extend(sinks);
    });
    world
        .add_subscription(world.subscription(tenant, &[EventType::WebhookPing]))
        .await;
    let envelope = world.envelope(tenant, EventType::WebhookPing);
    let record = queue_event(&world, &envelope).await;
    handler(&world).handle(&record).await.unwrap();
    assert_eq!(world.deliveries(tenant).await, Vec::new());
    assert_eq!(sink.delivered(), vec![envelope.id], "sinks still see it");
}

#[tokio::test]
async fn malformed_and_foreign_records_are_permanent_failures() {
    let world = World::new();
    let handler = handler(&world);
    let tenant = World::tenant();

    // An event of another tenant in this tenant's record.
    let foreign = world.envelope(other_tenant(), EventType::CalendarCreated);
    let id = world.enqueue(tenant, OutboxMessage::DomainEvent(foreign)).await;
    let record = world.record(id).await;
    let error = handler.handle(&record).await.unwrap_err();
    assert!(!error.is_retryable(), "{error}");
    assert!(error.message().contains("tenant"), "{error}");

    // A webhook message under the wrong kind label.
    let mut wrong = record.clone();
    wrong.kind = "webhook".to_owned();
    assert!(!handler.handle(&wrong).await.unwrap_err().is_retryable());

    // A payload that is not an envelope.
    let mut damaged = record;
    damaged.payload = json!({"id": 5, "recipient": "ann@example.org"});
    let error = handler.handle(&damaged).await.unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(
        error.message(),
        "the payload of the record cannot be decoded",
        "a static text: the payload can name people"
    );
}

#[tokio::test]
async fn a_store_outage_is_retried() {
    let world = World::new();
    let envelope = world.envelope(World::tenant(), EventType::CalendarCreated);
    let record = queue_event(&world, &envelope).await;
    world.db.set_outage(true);
    assert!(handler(&world).handle(&record).await.unwrap_err().is_retryable());
}

#[tokio::test]
async fn the_handler_serves_the_domain_event_kind() {
    let world = World::new();
    assert_eq!(handler(&world).kind(), "domain_event");
    assert!(handler(&world).limits_attempts());
}

// ---------------------------------------------------------------------------------------------------------------
// Details
// ---------------------------------------------------------------------------------------------------------------

fn change(object: Option<ObjectId>, kind: ObjectChangeKind, n: u32) -> ObjectChange {
    ObjectChange {
        kind,
        object,
        uri: ObjectUri::parse(&format!("c{n}.ics")).unwrap(),
        uid: Uid::parse(&format!("uid-c{n}")).unwrap(),
        external_key: None,
        etag: None,
    }
}

fn event_of(world: &World, tenant: TenantId, event_type: EventType, data: EventPayload) -> Envelope {
    Envelope::new(
        world.id(),
        event_type,
        tenant,
        world.clock.now(),
        AuditActor::system(),
        data,
    )
    .unwrap()
}

fn changed(world: &World, changes: Vec<ObjectChange>) -> Envelope {
    event_of(
        world,
        World::tenant(),
        EventType::CalendarObjectsChanged,
        EventPayload::ObjectsChanged(ObjectsChangedPayload {
            calendar: CalendarId::from_uuid(Uuid::from_u128(2)),
            sync_token: SyncToken::new(Uuid::from_u128(1), Uuid::from_u128(2), 9),
            changes,
            truncated: false,
        }),
    )
}

/// The details a subscription that asks for them receives with `envelope`, or `None` when it receives none.
///
/// A subscription of the tenant that wants details for the type of the event is made first (once per world and
/// type); the event is fanned out through the real handler, and the details are read from the delivery that the
/// handler wrote.
async fn described(world: &World, backend: &Arc<FakeBackend>, envelope: &Envelope) -> Option<Value> {
    let tenant = envelope.tenant;
    let wanted = envelope.event_type;
    let existing = world
        .read(tenant)
        .await
        .webhooks()
        .subscribed_to(wanted)
        .await
        .unwrap()
        .into_iter()
        .find(|subscription| subscription.include_details);
    let subscription = if let Some(subscription) = existing {
        subscription
    } else {
        let mut asking = world.subscription(tenant, &[wanted]);
        asking.include_details = true;
        world.add_subscription(asking).await
    };
    let record = queue_event(world, envelope).await;
    handler_with_backend(world, backend).handle(&record).await.unwrap();
    let message = world
        .webhook_messages(tenant)
        .await
        .into_iter()
        .find(|message| message.webhook == subscription.id && message.envelope.id == envelope.id)
        .expect("the delivery of the event");
    message.details
}

#[tokio::test]
async fn the_details_of_a_shared_calendar_travel_with_the_delivery_of_subscriptions_that_ask_for_them() {
    let world = World::new();
    let tenant = World::tenant();
    let mut asking = world.subscription(tenant, &[EventType::CalendarObjectsChanged]);
    asking.include_details = true;
    let asking = world.add_subscription(asking).await;
    let thin = world
        .add_subscription(world.subscription(tenant, &[EventType::CalendarObjectsChanged]))
        .await;
    let calendar = world.calendar_of_kind(tenant, CalendarKind::Group).await;
    let object = world
        .object_with_summary(&calendar, "Planning", Classification::Public)
        .await;
    let envelope = changed(&world, vec![change(Some(object.id), ObjectChangeKind::Updated, 1)]);
    let record = queue_event(&world, &envelope).await;

    handler(&world).handle(&record).await.unwrap();

    let messages = world.webhook_messages(tenant).await;
    assert_eq!(messages.len(), 2);
    for message in messages {
        if message.webhook == asking.id {
            let details = message.details.expect("the subscription asked for details");
            assert_eq!(details["objects"][0]["summary"], "Planning");
        } else {
            assert_eq!(message.webhook, thin.id);
            assert_eq!(message.details, None, "thin by default");
        }
    }
}

#[tokio::test]
async fn no_object_is_read_when_no_subscription_asks_for_details() {
    let world = World::new();
    let tenant = World::tenant();
    world
        .add_subscription(world.subscription(tenant, &[EventType::CalendarObjectsChanged]))
        .await;
    let calendar = world.calendar_of_kind(tenant, CalendarKind::Group).await;
    let object = world
        .object_with_summary(&calendar, "Planning", Classification::Public)
        .await;
    let record = queue_event(
        &world,
        &changed(&world, vec![change(Some(object.id), ObjectChangeKind::Updated, 1)]),
    )
    .await;
    // The backend would fail the delivery if anything asked it to describe the object.
    let backend = FakeBackend::new(EventData::default());
    backend.fail_with(Some(BackendError::Unavailable("must not be asked".to_owned())));
    handler_with_backend(&world, &backend).handle(&record).await.unwrap();
    assert_eq!(world.webhook_messages(tenant).await.len(), 1);
    assert_eq!(backend.requests().len(), 0);
}

#[tokio::test]
async fn changed_objects_of_group_and_managed_calendars_are_described() {
    let world = World::new();
    let backend = FakeBackend::new(EventData::default());
    for kind in [CalendarKind::Group, CalendarKind::Managed] {
        let calendar = world.calendar_of_kind(World::tenant(), kind).await;
        let public = world
            .object_with_summary(&calendar, "Planning", Classification::Public)
            .await;
        let private = world
            .object_with_summary(&calendar, "Doctor", Classification::Private)
            .await;
        let confidential = world
            .object_with_summary(&calendar, "Layoffs", Classification::Confidential)
            .await;
        let event = changed(
            &world,
            vec![
                change(Some(public.id), ObjectChangeKind::Created, 1),
                change(Some(private.id), ObjectChangeKind::Updated, 2),
                change(Some(confidential.id), ObjectChangeKind::Updated, 3),
                change(None, ObjectChangeKind::Deleted, 4),
                change(Some(public.id), ObjectChangeKind::Deleted, 5),
                change(
                    Some(ObjectId::from_uuid(Uuid::from_u128(404))),
                    ObjectChangeKind::Created,
                    6,
                ),
            ],
        );

        let details = described(&world, &backend, &event).await.unwrap();
        let objects = details["objects"].as_array().unwrap();
        assert_eq!(
            objects.len(),
            3,
            "{kind:?}: the deleted and the unknown object are left out"
        );
        assert_eq!(objects[0]["object"], json!(public.id));
        assert_eq!(objects[0]["summary"], "Planning");
        assert_eq!(objects[0]["restricted"], false);
        assert_eq!(objects[0]["recurring"], false);
        assert!(objects[0]["start"].is_string() && objects[0]["end"].is_string());
        for restricted in [&objects[1], &objects[2]] {
            assert_eq!(
                (restricted["summary"].clone(), restricted["restricted"].clone()),
                (Value::Null, json!(true))
            );
        }
        let shown = details.to_string();
        assert!(!shown.contains("Doctor") && !shown.contains("Layoffs"), "{shown}");
    }
}

#[tokio::test]
async fn objects_of_personal_user_and_mirror_calendars_are_never_described() {
    // A webhook belongs to the tenant, and a tenant token never reaches the calendars of principals (PLAN 2.6):
    // the subscriber learns that something changed, never what it is called or when it takes place.
    let world = World::new();
    let backend = FakeBackend::new(EventData::default());
    let tenant = World::tenant();
    for kind in [CalendarKind::Personal, CalendarKind::User, CalendarKind::Mirror] {
        let calendar = world.calendar_of_kind(tenant, kind).await;
        let object = world
            .object_with_summary(&calendar, "Job interview", Classification::Public)
            .await;
        let event = changed(&world, vec![change(Some(object.id), ObjectChangeKind::Created, 1)]);
        assert_eq!(described(&world, &backend, &event).await, None, "{kind:?}");
    }

    // One event about objects of both kinds describes only the shared one.
    let personal = world.calendar_of_kind(tenant, CalendarKind::Personal).await;
    let group = world.calendar_of_kind(tenant, CalendarKind::Group).await;
    let secret = world
        .object_with_summary(&personal, "Job interview", Classification::Public)
        .await;
    let shared = world
        .object_with_summary(&group, "Planning", Classification::Public)
        .await;
    let event = changed(
        &world,
        vec![
            change(Some(secret.id), ObjectChangeKind::Updated, 1),
            change(Some(shared.id), ObjectChangeKind::Updated, 2),
        ],
    );
    let details = described(&world, &backend, &event).await.unwrap();
    let shown = details.to_string();
    assert!(!shown.contains("Job interview"), "{shown}");
    assert!(
        !shown.contains(&secret.id.to_string()),
        "not even the id of the personal object: {shown}"
    );
    assert_eq!(details["objects"].as_array().unwrap().len(), 1);
    assert_eq!(details["objects"][0]["summary"], "Planning");
}

#[tokio::test]
async fn deleted_calendars_are_not_described() {
    let world = World::new();
    let backend = FakeBackend::new(EventData::default());
    let tenant = World::tenant();
    let calendar = world.calendar_of_kind(tenant, CalendarKind::Group).await;
    let object = world
        .object_with_summary(&calendar, "Old", Classification::Public)
        .await;
    let mut tx = world.write(tenant).await;
    tx.calendars().soft_delete(calendar.id, calendar.version).await.unwrap();
    tx.commit().await.unwrap();
    let event = changed(&world, vec![change(Some(object.id), ObjectChangeKind::Updated, 1)]);
    assert_eq!(described(&world, &backend, &event).await, None);
}

#[tokio::test]
async fn objects_of_other_tenants_are_not_reachable() {
    let world = World::new();
    let backend = FakeBackend::new(EventData::default());
    let calendar = world.calendar_of_kind(other_tenant(), CalendarKind::Group).await;
    let foreign = world
        .object_with_summary(&calendar, "Foreign", Classification::Public)
        .await;
    let event = changed(&world, vec![change(Some(foreign.id), ObjectChangeKind::Updated, 1)]);
    assert_eq!(described(&world, &backend, &event).await, None);
}

#[tokio::test]
async fn events_about_other_things_have_no_details_and_rsvp_events_describe_their_object() {
    let world = World::new();
    let backend = FakeBackend::new(EventData::default());
    let tenant = World::tenant();
    let calendar = world.calendar_of_kind(tenant, CalendarKind::Group).await;
    let object = world
        .object_with_summary(&calendar, "Planning", Classification::Public)
        .await;

    assert_eq!(described(&world, &backend, &changed(&world, Vec::new())).await, None);
    let gone = changed(
        &world,
        vec![change(
            Some(ObjectId::from_uuid(Uuid::from_u128(404))),
            ObjectChangeKind::Created,
            1,
        )],
    );
    assert_eq!(described(&world, &backend, &gone).await, None);

    let rsvp = event_of(
        &world,
        tenant,
        EventType::RsvpAnswered,
        EventPayload::Rsvp(RsvpPayload {
            calendar: calendar.id,
            object: object.id,
            uid: Uid::parse("uid-10").unwrap(),
            partstat: PartStat::Accepted,
        }),
    );
    let details = described(&world, &backend, &rsvp).await.unwrap();
    assert_eq!(details["objects"][0]["summary"], "Planning");

    // A ping goes to the one subscription that asked for it and is not fanned out at all.
    let ping = event_of(
        &world,
        tenant,
        EventType::WebhookPing,
        EventPayload::Webhook(WebhookPayload {
            webhook: WebhookId::from_uuid(Uuid::from_u128(5)),
            reason: WebhookPayload::PING.to_owned(),
        }),
    );
    let before = world.webhook_messages(tenant).await.len();
    let record = queue_event(&world, &ping).await;
    handler(&world).handle(&record).await.unwrap();
    assert_eq!(world.webhook_messages(tenant).await.len(), before);
}

#[tokio::test]
async fn a_summary_that_cannot_be_read_is_left_out_and_the_object_is_still_listed() {
    let world = World::new();
    let backend = FakeBackend::new(EventData::default());
    let calendar = world.calendar_of_kind(World::tenant(), CalendarKind::Managed).await;
    let object = world
        .object_with_summary(&calendar, "Planning", Classification::Public)
        .await;
    let event = changed(&world, vec![change(Some(object.id), ObjectChangeKind::Updated, 1)]);
    backend.fail_with(Some(BackendError::Unavailable("not implemented".to_owned())));
    let details = described(&world, &backend, &event).await.unwrap();
    assert_eq!(details["objects"][0]["summary"], Value::Null);
    assert_eq!(details["objects"][0]["object"], json!(object.id));
}

#[tokio::test]
async fn summaries_are_one_line_and_cut() {
    let world = World::new();
    let backend = FakeBackend::new(EventData::default());
    let calendar = world.calendar_of_kind(World::tenant(), CalendarKind::Group).await;
    let long = world
        .object_with_summary(
            &calendar,
            &format!("{}\r\nsecond line", "ü".repeat(900)),
            Classification::Public,
        )
        .await;
    let event = changed(&world, vec![change(Some(long.id), ObjectChangeKind::Updated, 1)]);
    let details = described(&world, &backend, &event).await.unwrap();
    let summary = details["objects"][0]["summary"].as_str().unwrap();
    assert_eq!(summary.chars().count(), 200, "cut at 200 characters");
    assert!(!summary.contains('\n') && !summary.contains('\r'));
}

#[tokio::test]
async fn a_store_outage_while_reading_details_is_retried_and_not_an_empty_answer() {
    let world = World::new();
    let backend = FakeBackend::new(EventData::default());
    let tenant = World::tenant();
    let mut asking = world.subscription(tenant, &[EventType::CalendarObjectsChanged]);
    asking.include_details = true;
    world.add_subscription(asking).await;
    let calendar = world.calendar_of_kind(tenant, CalendarKind::Group).await;
    let object = world
        .object_with_summary(&calendar, "Planning", Classification::Public)
        .await;
    let event = changed(&world, vec![change(Some(object.id), ObjectChangeKind::Updated, 1)]);
    let record = queue_event(&world, &event).await;
    world.db.set_outage(true);
    let error = handler_with_backend(&world, &backend)
        .handle(&record)
        .await
        .unwrap_err();
    assert!(error.is_retryable(), "{error}");
    assert!(
        world.webhook_messages(tenant).await.is_empty(),
        "nothing was delivered without its details"
    );
}
