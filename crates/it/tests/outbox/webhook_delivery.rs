//! The `webhook` outbox handler of the `hooks-webhook` adapter over the in-memory store: one signed HTTP delivery
//! per attempt, what the answers mean, retries bounded by time, and what counts against a subscription.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Duration as ChronoDuration;
use davhaven_testkit::davhaven_domain::events::{CalendarPayload, WebhookPayload};
use davhaven_testkit::davhaven_domain::{
    AuditActor, CalendarId, CalendarKind, DeliveryId, Envelope, EventId, EventPayload, EventType, OutboxId,
    PrincipalId, TenantId, WebhookId, WebhookSubscription,
};
use davhaven_testkit::davhaven_hooks_webhook::config::WebhooksConfig;
use davhaven_testkit::davhaven_hooks_webhook::signing::{SigningKey, Verifier};
use davhaven_testkit::davhaven_hooks_webhook::webhook::{
    NOOP_ERROR, NoopWebhookHandler, SKIPPED_ERROR, WebhookHandler,
};
use davhaven_testkit::davhaven_ports::testing::{FixedHasher, FixedKeyRing, PlainSealer};
use davhaven_testkit::davhaven_ports::{
    Clock, Database, DeliveryRecord, DeliveryStatus, HandlerError, HttpClient, HttpPurpose, IdGenerator, NewOutbox,
    OutboundRequest, OutboundResponse, OutboxHandler, OutboxMessage, OutboxRecord, PluginContext, PortError, RunMode,
    SealAad, SecretSealer, WebhookDelivery,
};
use davhaven_testkit::davhaven_wire::WebhookEnvelope;
use davhaven_testkit::http::Method;
use serde_json::{Value, json};
use uuid::Uuid;

use super::support::{FlakyDatabase, ScriptedHttp, World};

const SECRET: &str = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const PREVIOUS: &str = "whsec_ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

fn tenant() -> TenantId {
    World::tenant()
}

struct Setup {
    world: Arc<World>,
    context: PluginContext,
    handler: WebhookHandler,
}

impl Setup {
    async fn new() -> Self {
        Self::with(WebhooksConfig::default()).await
    }

    async fn with(config: WebhooksConfig) -> Self {
        Self::wrapping(config, |world| {
            let http: Arc<dyn HttpClient> = Arc::<ScriptedHttp>::clone(&world.http);
            http
        })
        .await
    }

    /// A setup whose handler talks to the HTTP client that `http` makes of the world.
    async fn wrapping(config: WebhooksConfig, http: impl FnOnce(&Arc<World>) -> Arc<dyn HttpClient>) -> Self {
        let world = Arc::new(World::ready().await);
        let context = Self::context(&world, http(&world));
        Self {
            handler: WebhookHandler::from_context(&context, config).unwrap(),
            world,
            context,
        }
    }

    fn context(world: &World, http: Arc<dyn HttpClient>) -> PluginContext {
        PluginContext::new(
            Arc::new(world.clock.clone()),
            Arc::new(world.ids.clone()),
            Arc::new(FixedKeyRing::default()),
            Arc::new(PlainSealer),
            Arc::new(FixedHasher::default()),
            RunMode::Dev,
        )
        .with_http(http)
        .with_database({
            let database: Arc<dyn davhaven_testkit::davhaven_ports::Database> = Arc::<FlakyDatabase>::clone(&world.db);
            database
        })
    }

    fn http(&self) -> &ScriptedHttp {
        &self.world.http
    }

    fn seal(id: WebhookId, secret: &str) -> Vec<u8> {
        PlainSealer
            .seal(secret.as_bytes(), &SealAad::webhook_secret(tenant(), id))
            .unwrap()
            .into_bytes()
    }

    /// Stores an active subscription for calendar events, signed with `SECRET`; `change` adjusts it.
    async fn subscription(&self, change: impl FnOnce(&mut WebhookSubscription) + Send) -> WebhookSubscription {
        let mut subscription = self.world.subscription(tenant(), &[EventType::CalendarCreated]);
        subscription.url = "https://hooks.example.org/in?token=s3cret".parse().unwrap();
        subscription.sealed_secret = Self::seal(subscription.id, SECRET);
        change(&mut subscription);
        self.world.add_subscription(subscription).await
    }

    /// Raises the failure counter of the subscription to `count`.
    async fn set_failures(&self, id: WebhookId, count: u32) {
        let mut tx = self.world.write(tenant()).await;
        for _ in 0..count {
            tx.webhooks().record_failure(id).await.unwrap();
        }
        tx.commit().await.unwrap();
    }

    fn envelope(&self) -> Envelope {
        Envelope::new(
            EventId::from_uuid(Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0e01)),
            EventType::CalendarCreated,
            tenant(),
            self.world.clock.now(),
            AuditActor::system(),
            EventPayload::Calendar(CalendarPayload {
                calendar: CalendarId::from_uuid(Uuid::from_u128(2)),
                owner: PrincipalId::from_uuid(Uuid::from_u128(3)),
                kind: CalendarKind::Group,
            }),
        )
        .unwrap()
    }

    /// An envelope with an id of its own, so that several deliveries of one subscription can exist.
    fn event(&self) -> Envelope {
        let mut envelope = self.envelope();
        envelope.id = self.world.id();
        envelope
    }

    /// Creates the delivery and its outbox record the way the fan-out does.
    async fn queue(&self, subscription: &WebhookSubscription, envelope: Envelope) -> OutboxRecord {
        self.queue_with(subscription, envelope, None).await
    }

    /// Creates the delivery and its outbox record, with the details the fan-out read.
    async fn queue_with(
        &self,
        subscription: &WebhookSubscription,
        envelope: Envelope,
        details: Option<Value>,
    ) -> OutboxRecord {
        let delivery = DeliveryId::from_uuid(self.world.ids.new_id());
        let now = self.world.clock.now();
        let outbox = OutboxId::from_uuid(delivery.as_uuid());
        let mut tx = self.world.write(tenant()).await;
        tx.webhooks()
            .create_delivery(DeliveryRecord {
                id: delivery,
                tenant_id: tenant(),
                subscription_id: subscription.id,
                event_id: envelope.id,
                status: DeliveryStatus::Pending,
                attempts: 0,
                response_status: None,
                last_error: None,
                at: now,
                created_at: now,
                updated_at: now,
                version: 1,
            })
            .await
            .unwrap();
        tx.outbox()
            .enqueue(NewOutbox::now(
                outbox,
                OutboxMessage::Webhook(WebhookDelivery {
                    delivery,
                    webhook: subscription.id,
                    envelope,
                    details,
                }),
            ))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        self.world.record(outbox).await
    }

    async fn delivery(&self, record: &OutboxRecord) -> DeliveryRecord {
        self.world
            .delivery_of(tenant(), DeliveryId::from_uuid(record.id.as_uuid()))
            .await
    }

    async fn webhook(&self, id: WebhookId) -> WebhookSubscription {
        self.world.subscription_of(tenant(), id).await
    }

    fn last_request(&self) -> OutboundRequest {
        self.http().requests().pop().unwrap()
    }
}

fn header<'a>(request: &'a OutboundRequest, name: &str) -> &'a str {
    request.headers.get(name).unwrap().to_str().unwrap()
}

#[tokio::test]
async fn a_delivery_is_a_signed_json_post_that_a_receiver_can_verify() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    setup.set_failures(subscription.id, 4).await;
    let envelope = setup.envelope();
    let record = setup.queue(&subscription, envelope.clone()).await;

    setup.handler.handle(&record).await.unwrap();

    let requests = setup.http().requests();
    assert_eq!(requests.len(), 1);
    let request = requests.first().unwrap();
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.url, subscription.url);
    assert_eq!(request.purpose, HttpPurpose::Webhook);
    assert_eq!(header(request, "content-type"), "application/json");
    assert!(header(request, "user-agent").starts_with("Davhaven-Webhooks/"));
    assert_eq!(header(request, "webhook-id"), "01900000-0000-7000-8000-000000000e01");
    assert_eq!(
        header(request, "webhook-timestamp"),
        setup.world.clock.now().timestamp().to_string()
    );

    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body, serde_json::to_value(WebhookEnvelope::from(&envelope)).unwrap());
    assert_eq!(body["type"], "calendar.created");
    assert_eq!(
        body["data"].get("details"),
        None,
        "payloads are thin unless asked otherwise"
    );

    Verifier::new(vec![SigningKey::parse(SECRET).unwrap()])
        .verify(
            header(request, "webhook-id"),
            header(request, "webhook-timestamp"),
            header(request, "webhook-signature"),
            &request.body,
            setup.world.clock.now(),
        )
        .unwrap();

    let delivery = setup.delivery(&record).await;
    assert_eq!(
        (
            delivery.status,
            delivery.attempts,
            delivery.response_status,
            delivery.last_error.clone()
        ),
        (DeliveryStatus::Delivered, 1, Some(200), None)
    );
    assert_eq!(delivery.at, setup.world.clock.now());
    assert_eq!(
        setup.webhook(subscription.id).await.failure_count,
        0,
        "a success clears the failures"
    );
}

#[tokio::test]
async fn every_attempt_is_signed_afresh_under_the_same_message_id() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    setup.http().answer(503);
    setup.handler.handle(&record).await.unwrap_err();
    setup.world.clock.advance(ChronoDuration::minutes(10));
    setup.handler.handle(&record).await.unwrap();

    let requests = setup.http().requests();
    assert_eq!(requests.len(), 2);
    let (first, second) = (requests.first().unwrap(), requests.last().unwrap());
    assert_eq!(
        header(first, "webhook-id"),
        header(second, "webhook-id"),
        "receivers deduplicate on it"
    );
    assert_ne!(header(first, "webhook-timestamp"), header(second, "webhook-timestamp"));
    assert_ne!(header(first, "webhook-signature"), header(second, "webhook-signature"));
    assert_eq!(first.body, second.body);
    assert_eq!(setup.delivery(&record).await.attempts, 2);
}

#[tokio::test]
async fn a_rotated_secret_signs_next_to_the_new_one_during_the_overlap() {
    let setup = Setup::new().await;
    let rotated_at = setup.world.clock.now();
    let subscription = setup
        .subscription(|subscription| {
            subscription.secret_rotated_at = Some(rotated_at);
            // The row holds the new secret; the previous one is sealed for the same row.
            subscription.sealed_secret_previous = Some(Setup::seal(subscription.id, PREVIOUS));
        })
        .await;
    let record = setup.queue(&subscription, setup.event()).await;

    setup.world.clock.advance(ChronoDuration::hours(1));
    setup.handler.handle(&record).await.unwrap();
    let request = setup.last_request();
    let signatures = header(&request, "webhook-signature").to_owned();
    assert_eq!(signatures.split(' ').count(), 2, "{signatures}");
    for secret in [SECRET, PREVIOUS] {
        Verifier::new(vec![SigningKey::parse(secret).unwrap()])
            .verify(
                header(&request, "webhook-id"),
                header(&request, "webhook-timestamp"),
                &signatures,
                &request.body,
                setup.world.clock.now(),
            )
            .unwrap();
    }

    // After the retry window nothing can be in flight that needs the old secret.
    setup.world.clock.advance(ChronoDuration::hours(24));
    let later = setup.queue(&subscription, setup.event()).await;
    setup.handler.handle(&later).await.unwrap();
    let request = setup.last_request();
    assert_eq!(header(&request, "webhook-signature").split(' ').count(), 1);
    assert!(
        Verifier::new(vec![SigningKey::parse(PREVIOUS).unwrap()])
            .verify(
                header(&request, "webhook-id"),
                header(&request, "webhook-timestamp"),
                header(&request, "webhook-signature"),
                &request.body,
                setup.world.clock.now(),
            )
            .is_err()
    );
}

/// The details the fan-out of the application writes into a delivery.
fn details() -> Value {
    json!({"objects": [
        {"object": "00000000-0000-0000-0000-00000000000a", "summary": "Planning", "restricted": false,
         "start": "2027-02-01T09:00:00Z", "end": "2027-02-01T10:30:00Z", "recurring": false},
        {"object": "00000000-0000-0000-0000-00000000000b", "summary": null, "restricted": true,
         "start": "2027-02-01T09:00:00Z", "end": "2027-02-01T10:30:00Z", "recurring": false}
    ]})
}

#[tokio::test]
async fn the_details_of_the_delivery_are_added_for_subscriptions_that_ask_for_them() {
    let setup = Setup::new().await;
    let subscription = setup
        .subscription(|subscription| subscription.include_details = true)
        .await;
    let record = setup.queue_with(&subscription, setup.envelope(), Some(details())).await;

    setup.handler.handle(&record).await.unwrap();

    let body: Value = serde_json::from_slice(&setup.last_request().body).unwrap();
    assert_eq!(body["data"]["details"], details());
    assert_eq!(
        body["data"]["calendar"], "00000000-0000-0000-0000-000000000002",
        "the thin payload is still there"
    );
}

#[tokio::test]
async fn details_reach_only_subscriptions_that_still_ask_for_them_and_only_when_the_delivery_has_them() {
    let setup = Setup::new().await;
    // The delivery was written with details, but the subscription switched them off in the meantime.
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue_with(&subscription, setup.event(), Some(details())).await;
    setup.handler.handle(&record).await.unwrap();
    let body: Value = serde_json::from_slice(&setup.last_request().body).unwrap();
    assert_eq!(body["data"].get("details"), None);

    // A subscription that asks for details but whose event has none (a personal calendar) gets none, and the
    // handler has no way to look the objects up itself.
    let asking = setup
        .subscription(|subscription| subscription.include_details = true)
        .await;
    let record = setup.queue_with(&asking, setup.event(), None).await;
    setup.handler.handle(&record).await.unwrap();
    let body = String::from_utf8(setup.last_request().body.to_vec()).unwrap();
    assert!(!body.contains("details"), "{body}");
}

#[tokio::test]
async fn a_failing_receiver_is_retried_and_a_failed_attempt_counts_for_nothing() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;

    for (status, expected) in [
        (503, "HTTP 503"),
        (429, "HTTP 429"),
        (500, "HTTP 500"),
        (301, "HTTP 301"),
        (404, "HTTP 404"),
    ] {
        setup.http().answer(status);
        let error = setup.handler.handle(&record).await.unwrap_err();
        assert_eq!(error, HandlerError::retryable(expected));
    }
    let delivery = setup.delivery(&record).await;
    assert_eq!(
        (
            delivery.status,
            delivery.attempts,
            delivery.response_status,
            delivery.last_error.as_deref()
        ),
        (DeliveryStatus::Failed, 5, Some(404), Some("HTTP 404"))
    );
    assert_eq!(
        setup.webhook(subscription.id).await.failure_count,
        0,
        "one delivery that is retried is not five failures of the subscription"
    );

    // The next answer is good: the delivery completes.
    setup.handler.handle(&record).await.unwrap();
    let delivery = setup.delivery(&record).await;
    assert_eq!(
        (delivery.status, delivery.attempts, delivery.last_error),
        (DeliveryStatus::Delivered, 6, None)
    );
}

#[tokio::test]
async fn many_events_failing_their_first_attempt_do_not_switch_the_subscription_off() {
    // A receiver that is down for a few minutes: every event pending for it fails once. With the default of 20
    // failures in a row the subscription must survive 25 of them, because none has used up its retry window.
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let mut records = Vec::new();
    for _ in 0..25 {
        records.push(setup.queue(&subscription, setup.event()).await);
    }
    for record in &records {
        setup.http().answer(503);
        setup.handler.handle(record).await.unwrap_err();
    }
    let row = setup.webhook(subscription.id).await;
    assert!(row.active, "{row:?}");
    assert_eq!(row.failure_count, 0);
    assert!(
        setup.world.queued_events().await.is_empty(),
        "nobody was told it was switched off"
    );

    // The receiver is back: the deliveries are retried and arrive.
    setup.world.clock.advance(ChronoDuration::minutes(5));
    for record in &records {
        setup.handler.handle(record).await.unwrap();
    }
    for record in &records {
        assert_eq!(setup.delivery(record).await.status, DeliveryStatus::Delivered);
    }
}

#[tokio::test]
async fn a_delivery_that_ends_dead_counts_once_and_a_success_starts_the_count_over() {
    let setup = Setup::with(WebhooksConfig {
        retry_window: Duration::from_secs(3600),
        max_consecutive_failures: 3,
    })
    .await;
    let subscription = setup.subscription(|_| {}).await;
    let mut dead = Vec::new();
    for _ in 0..2 {
        dead.push(setup.queue(&subscription, setup.event()).await);
    }
    let lucky = setup.queue(&subscription, setup.event()).await;
    let last = setup.queue(&subscription, setup.event()).await;

    // Every delivery fails during its first hour (retried, nothing counted) and is dead after it.
    for record in dead.iter().chain([&lucky, &last]) {
        setup.http().answer(502);
        setup.handler.handle(record).await.unwrap_err();
    }
    assert_eq!(setup.webhook(subscription.id).await.failure_count, 0);
    setup.world.clock.advance(ChronoDuration::hours(2));
    for record in &dead {
        setup.http().answer(502);
        let error = setup.handler.handle(record).await.unwrap_err();
        assert_eq!(error, HandlerError::permanent("the retry window ended (HTTP 502)"));
    }
    assert_eq!(
        setup.webhook(subscription.id).await.failure_count,
        2,
        "one per dead delivery"
    );
    assert!(setup.webhook(subscription.id).await.active);

    // A delivery that gets through resets the count.
    setup.handler.handle(&lucky).await.unwrap();
    assert_eq!(setup.webhook(subscription.id).await.failure_count, 0);

    // Three dead deliveries in a row switch it off.
    for _ in 0..2 {
        let record = setup.queue(&subscription, setup.event()).await;
        setup.http().answer(502);
        setup.handler.handle(&record).await.unwrap_err();
        setup.world.clock.advance(ChronoDuration::hours(2));
        setup.http().answer(502);
        setup.handler.handle(&record).await.unwrap_err();
    }
    assert!(setup.webhook(subscription.id).await.active, "two in a row");
    setup.http().answer(502);
    let error = setup.handler.handle(&last).await.unwrap_err();
    assert_eq!(error, HandlerError::permanent("the retry window ended (HTTP 502)"));

    let row = setup.webhook(subscription.id).await;
    assert!(!row.active);
    assert_eq!(row.disabled_reason.as_deref(), Some("max_consecutive_failures"));
    assert_eq!(row.failure_count, 3);

    let events = setup.world.queued_events().await;
    assert_eq!(events.len(), 1);
    let event = events.first().unwrap();
    assert_eq!(event.event_type, EventType::WebhookDisabled);
    assert_eq!(event.tenant, tenant());
    assert_eq!(event.actor, AuditActor::system());
    assert_eq!(
        event.data,
        EventPayload::Webhook(WebhookPayload {
            webhook: subscription.id,
            reason: "max_consecutive_failures".to_owned()
        })
    );
    let audit = setup.world.audit(tenant()).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0, "webhook.disabled");
    assert_eq!(audit[0].1["reason"], "max_consecutive_failures");
}

#[tokio::test]
async fn an_accepted_event_is_delivered_whatever_the_receiver_answers_with() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    setup.set_failures(subscription.id, 4).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    // An echoing receiver, or a proxy page: far more than the 64 KiB the client reads.
    setup.http().answer_with_body(200, Bytes::from(vec![b'x'; 200_000]));
    setup.handler.handle(&record).await.unwrap();

    let delivery = setup.delivery(&record).await;
    assert_eq!(
        (delivery.status, delivery.response_status, delivery.last_error),
        (DeliveryStatus::Delivered, Some(200), None)
    );
    assert_eq!(setup.webhook(subscription.id).await.failure_count, 0);
    assert!(setup.webhook(subscription.id).await.active);
}

#[tokio::test]
async fn network_failures_are_retried_and_named_by_kind_only() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    for (error, expected) in [
        (
            PortError::unavailable("connection refused by hooks.example.org"),
            "the request failed (unavailable)",
        ),
        (
            PortError::timeout("timed out after 10s talking to hooks.example.org"),
            "the request failed (timeout)",
        ),
        (
            PortError::internal("tls handshake with hooks.example.org failed"),
            "the request failed (internal)",
        ),
    ] {
        setup.http().fail(error);
        assert_eq!(
            setup.handler.handle(&record).await.unwrap_err(),
            HandlerError::retryable(expected)
        );
    }
    let delivery = setup.delivery(&record).await;
    assert_eq!(delivery.response_status, None);
    assert_eq!(delivery.last_error.as_deref(), Some("the request failed (internal)"));
}

#[tokio::test]
async fn a_target_the_egress_policy_refuses_is_dead_at_once() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    setup
        .http()
        .fail(PortError::rejected("hooks.example.org resolves to 10.0.0.7"));
    let error = setup.handler.handle(&record).await.unwrap_err();
    assert_eq!(error, HandlerError::permanent("the egress policy refused the request"));
    let delivery = setup.delivery(&record).await;
    assert_eq!(
        (delivery.status, delivery.last_error.as_deref()),
        (DeliveryStatus::Dead, Some("the egress policy refused the request"))
    );
    assert_eq!(
        setup.webhook(subscription.id).await.failure_count,
        1,
        "the subscription points somewhere it must not"
    );
    assert!(!format!("{delivery:?}").contains("10.0.0.7"));
}

#[tokio::test]
async fn retries_stop_when_the_retry_window_has_passed() {
    let setup = Setup::with(WebhooksConfig {
        retry_window: Duration::from_secs(3600),
        ..WebhooksConfig::default()
    })
    .await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;

    setup.world.clock.advance(ChronoDuration::minutes(59));
    setup.http().answer(502);
    assert_eq!(
        setup.handler.handle(&record).await.unwrap_err(),
        HandlerError::retryable("HTTP 502")
    );

    setup.world.clock.advance(ChronoDuration::minutes(1));
    setup.http().answer(502);
    let error = setup.handler.handle(&record).await.unwrap_err();
    assert_eq!(error, HandlerError::permanent("the retry window ended (HTTP 502)"));
    let delivery = setup.delivery(&record).await;
    assert_eq!((delivery.status, delivery.attempts), (DeliveryStatus::Dead, 2));
    assert!(
        setup.webhook(subscription.id).await.active,
        "a dead delivery alone does not switch a subscription off"
    );

    // Handling it again (a record that comes back) tries once more, and a success completes it.
    setup.handler.handle(&record).await.unwrap();
    let again = setup.delivery(&record).await;
    assert_eq!((again.status, again.attempts), (DeliveryStatus::Delivered, 3));
}

#[tokio::test]
async fn a_store_that_stays_down_does_not_keep_a_record_alive_past_the_window() {
    let setup = Setup::with(WebhooksConfig {
        retry_window: Duration::from_secs(3600),
        ..WebhooksConfig::default()
    })
    .await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;

    setup.world.db.set_outage(true);
    setup.world.clock.advance(ChronoDuration::minutes(59));
    assert_eq!(
        setup.handler.handle(&record).await.unwrap_err(),
        HandlerError::retryable("the store is not available"),
        "inside the window an outage is retried"
    );
    setup.world.clock.advance(ChronoDuration::minutes(2));
    assert_eq!(
        setup.handler.handle(&record).await.unwrap_err(),
        HandlerError::permanent("the retry window ended"),
        "after it the record ends, so it can be seen as dead and redelivered"
    );
    setup.world.db.set_outage(false);
    assert_eq!(setup.http().requests().len(), 0);
}

/// An HTTP client that answers 200 and makes the store fail the next transaction, the way a store that flaps
/// takes the settlement of an attempt that was sent.
struct SendsThenLosesTheStore {
    world: Arc<World>,
    inner: Arc<ScriptedHttp>,
}

#[async_trait]
impl HttpClient for SendsThenLosesTheStore {
    async fn send(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        let answer = self.inner.send(request).await;
        self.world.db.fail_next_begins(1);
        answer
    }
}

#[tokio::test]
async fn an_attempt_whose_settlement_is_lost_after_the_window_marks_the_delivery_dead() {
    let setup = Setup::wrapping(
        WebhooksConfig {
            retry_window: Duration::from_secs(3600),
            ..WebhooksConfig::default()
        },
        |world| {
            Arc::new(SendsThenLosesTheStore {
                world: Arc::clone(world),
                inner: Arc::clone(&world.http),
            })
        },
    )
    .await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;

    // The receiver accepted the event, but the store failed the settlement, and the retry window is over.
    setup.world.clock.advance(ChronoDuration::hours(2));
    let error = setup.handler.handle(&record).await.unwrap_err();
    assert_eq!(error, HandlerError::permanent("the retry window ended"));
    let row = setup.delivery(&record).await;
    assert_eq!(
        (row.status, row.last_error.as_deref()),
        (DeliveryStatus::Dead, Some("the retry window ended")),
        "the row says what became of the delivery, whatever became of its settlement"
    );
    assert_eq!(setup.http().requests().len(), 1);
}

#[tokio::test]
async fn a_receiver_that_is_gone_switches_the_subscription_off_at_once() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    setup.http().answer(410);

    let error = setup.handler.handle(&record).await.unwrap_err();
    assert_eq!(error, HandlerError::permanent("the receiver answered 410 Gone"));
    let row = setup.webhook(subscription.id).await;
    assert_eq!(
        (row.active, row.disabled_reason.as_deref()),
        (false, Some("endpoint_gone"))
    );
    let delivery = setup.delivery(&record).await;
    assert_eq!(
        (delivery.status, delivery.response_status),
        (DeliveryStatus::Dead, Some(410))
    );
    assert_eq!(setup.world.queued_events().await.len(), 1);
}

#[tokio::test]
async fn deliveries_of_a_disabled_subscription_are_skipped_and_the_record_is_done() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|subscription| subscription.active = false).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    // The record is done: nothing failed that an operator has to look at, so it neither dead-letters nor counts.
    setup.handler.handle(&record).await.unwrap();
    assert_eq!(setup.http().requests().len(), 0);
    let delivery = setup.delivery(&record).await;
    assert_eq!(
        (delivery.status, delivery.last_error.as_deref()),
        (DeliveryStatus::Dead, Some(SKIPPED_ERROR)),
        "the delivery row says why nothing was sent"
    );
    assert_eq!(setup.webhook(subscription.id).await.failure_count, 0);
    assert_eq!(setup.world.queued_events().await.len(), 0);
}

#[tokio::test]
async fn deliveries_still_pending_when_the_subscription_is_switched_off_end_without_noise() {
    let setup = Setup::with(WebhooksConfig {
        max_consecutive_failures: 1,
        retry_window: Duration::from_secs(3600),
    })
    .await;
    let subscription = setup.subscription(|_| {}).await;
    let first = setup.queue(&subscription, setup.event()).await;
    let waiting: Vec<OutboxRecord> = vec![
        setup.queue(&subscription, setup.event()).await,
        setup.queue(&subscription, setup.event()).await,
    ];
    setup.world.clock.advance(ChronoDuration::hours(2));
    setup.http().answer(502);
    setup.handler.handle(&first).await.unwrap_err();
    assert!(
        !setup.webhook(subscription.id).await.active,
        "the one death switched it off"
    );

    for record in &waiting {
        setup.handler.handle(record).await.unwrap();
        assert_eq!(setup.delivery(record).await.last_error.as_deref(), Some(SKIPPED_ERROR));
    }
    assert_eq!(setup.http().requests().len(), 1, "nothing more was sent");
    assert_eq!(
        setup.world.queued_events().await.len(),
        1,
        "one notice, however many deliveries were waiting"
    );
}

#[tokio::test]
async fn a_deleted_subscription_or_delivery_leaves_nothing_to_do() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;

    // The delivery row is gone (retention), the subscription exists.
    setup.world.clock.advance(ChronoDuration::days(31));
    let mut system = setup.world.db.store().begin_system().await.unwrap();
    system
        .retention()
        .purge_deliveries(setup.world.clock.now())
        .await
        .unwrap();
    system.commit().await.unwrap();
    setup.handler.handle(&record).await.unwrap();

    // The subscription is gone together with its deliveries.
    let other = setup.subscription(|_| {}).await;
    let queued = setup.queue(&other, setup.event()).await;
    let mut tx = setup.world.write(tenant()).await;
    tx.webhooks().delete(other.id).await.unwrap();
    tx.commit().await.unwrap();
    setup.handler.handle(&queued).await.unwrap();
    assert_eq!(setup.http().requests().len(), 0);
}

#[tokio::test]
async fn a_delivery_that_arrived_is_not_sent_twice() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    setup.handler.handle(&record).await.unwrap();
    // The settlement of the dispatcher was lost and the lease expired: the record comes back.
    setup.handler.handle(&record).await.unwrap();
    assert_eq!(setup.http().requests().len(), 1);
    assert_eq!(setup.delivery(&record).await.attempts, 1);
}

#[tokio::test]
async fn a_secret_that_cannot_be_used_ends_the_delivery_without_blaming_the_receiver() {
    let setup = Setup::new().await;
    let wrong_row = setup
        .subscription(|subscription| {
            // Sealed for another subscription: opening it with the right associated data fails.
            subscription.sealed_secret = PlainSealer
                .seal(
                    SECRET.as_bytes(),
                    &SealAad::webhook_secret(tenant(), WebhookId::from_uuid(Uuid::from_u128(9))),
                )
                .unwrap()
                .into_bytes();
        })
        .await;
    let garbage = setup
        .subscription(|subscription| subscription.sealed_secret = Setup::seal(subscription.id, "not a secret"))
        .await;

    for (subscription, expected) in [
        (&wrong_row, "the signing secret cannot be opened"),
        (&garbage, "the signing secret is not valid"),
    ] {
        let record = setup.queue(subscription, setup.event()).await;
        assert_eq!(
            setup.handler.handle(&record).await.unwrap_err(),
            HandlerError::permanent(expected)
        );
        assert_eq!(setup.delivery(&record).await.status, DeliveryStatus::Dead);
        assert_eq!(setup.webhook(subscription.id).await.failure_count, 0);
    }
    assert_eq!(setup.http().requests().len(), 0);
}

#[tokio::test]
async fn an_unreadable_previous_secret_does_not_stop_the_delivery() {
    let setup = Setup::new().await;
    let rotated_at = setup.world.clock.now();
    let subscription = setup
        .subscription(|subscription| {
            subscription.secret_rotated_at = Some(rotated_at);
            subscription.sealed_secret_previous = Some(b"garbage".to_vec());
        })
        .await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    setup.handler.handle(&record).await.unwrap();
    assert_eq!(header(&setup.last_request(), "webhook-signature").split(' ').count(), 1);
}

#[tokio::test]
async fn foreign_and_damaged_records_are_refused() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;

    let mut wrong_kind = record.clone();
    wrong_kind.kind = "domain_event".to_owned();
    assert!(!setup.handler.handle(&wrong_kind).await.unwrap_err().is_retryable());

    let mut newer = record.clone();
    newer.schema_version = 99;
    assert_eq!(
        setup.handler.handle(&newer).await.unwrap_err(),
        HandlerError::retryable("the payload was written by a newer version")
    );

    let mut other_tenant = record.clone();
    other_tenant.tenant_id = TenantId::from_uuid(Uuid::from_u128(0x99));
    assert_eq!(
        setup.handler.handle(&other_tenant).await.unwrap_err(),
        HandlerError::permanent("the tenant of the event is not the tenant of the record")
    );

    let mut damaged = record;
    damaged.payload = json!({"delivery": "x", "recipient": "ann@example.org"});
    let error = setup.handler.handle(&damaged).await.unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(
        error.message(),
        "the payload of the record cannot be decoded",
        "a static text: the payload can name people"
    );
    assert_eq!(setup.http().requests().len(), 0);
}

#[tokio::test]
async fn a_store_outage_is_retried_without_sending() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    setup.world.db.set_outage(true);
    assert!(setup.handler.handle(&record).await.unwrap_err().is_retryable());
    assert_eq!(setup.http().requests().len(), 0);
}

#[tokio::test]
async fn nothing_that_reaches_an_operator_names_the_url_or_the_secret() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    let mut seen = Vec::new();
    for status in [500, 404] {
        setup.http().answer(status);
        seen.push(setup.handler.handle(&record).await.unwrap_err().message().to_owned());
    }
    setup.http().fail(PortError::unavailable(
        "could not reach https://hooks.example.org/in?token=s3cret",
    ));
    seen.push(setup.handler.handle(&record).await.unwrap_err().message().to_owned());
    let delivery = setup.delivery(&record).await;
    seen.extend(delivery.last_error);
    for text in seen {
        for secret in ["s3cret", "hooks.example.org", "whsec_", "MDEyMzQ1"] {
            assert!(!text.contains(secret), "{text}");
        }
    }
}

#[tokio::test]
async fn the_handler_takes_webhook_records_and_bounds_retries_itself() {
    let setup = Setup::new().await;
    assert_eq!(setup.handler.kind(), "webhook");
    assert!(!setup.handler.limits_attempts());
    assert!(format!("{:?}", setup.handler).contains("WebhookHandler"));
    let noop = NoopWebhookHandler::from_context(&setup.context).unwrap();
    assert_eq!(noop.kind(), "webhook");
    assert!(noop.limits_attempts());
    assert!(format!("{noop:?}").contains("NoopWebhookHandler"));
}

#[tokio::test]
async fn the_noop_handler_completes_without_sending_and_marks_the_delivery_dead() {
    let setup = Setup::new().await;
    let subscription = setup.subscription(|_| {}).await;
    let record = setup.queue(&subscription, setup.envelope()).await;
    let noop = NoopWebhookHandler::from_context(&setup.context).unwrap();
    noop.handle(&record).await.unwrap();
    assert_eq!(setup.http().requests().len(), 0);

    let delivery = setup.delivery(&record).await;
    assert_eq!(
        (delivery.status, delivery.last_error.as_deref(), delivery.attempts),
        (DeliveryStatus::Dead, Some(NOOP_ERROR), 0),
        "the API shows that nothing was sent, not a delivery that stays pending for ever"
    );
    assert_eq!(
        setup.webhook(subscription.id).await.failure_count,
        0,
        "nobody is to blame"
    );

    // Handling it again, and records whose delivery is gone, are fine.
    noop.handle(&record).await.unwrap();
    setup.world.clock.advance(ChronoDuration::days(31));
    let mut system = setup.world.db.store().begin_system().await.unwrap();
    system
        .retention()
        .purge_deliveries(setup.world.clock.now())
        .await
        .unwrap();
    system.commit().await.unwrap();
    noop.handle(&record).await.unwrap();

    let mut foreign = record.clone();
    foreign.kind = "domain_event".to_owned();
    foreign.payload = json!({"id": 5});
    assert!(!noop.handle(&foreign).await.unwrap_err().is_retryable());
    setup.world.db.set_outage(true);
    assert!(noop.handle(&record).await.unwrap_err().is_retryable());
}

#[tokio::test]
async fn the_handler_needs_a_database_and_an_http_client() {
    let setup = Setup::new().await;
    let mut without_database = setup.context.clone();
    without_database.database = None;
    let error = WebhookHandler::from_context(&without_database, WebhooksConfig::default()).unwrap_err();
    assert!(error.to_string().contains("database"), "{error}");
    let mut without_http = setup.context.clone();
    without_http.http = None;
    let error = WebhookHandler::from_context(&without_http, WebhooksConfig::default()).unwrap_err();
    assert!(error.to_string().contains("http"), "{error}");
    let invalid = WebhooksConfig {
        max_consecutive_failures: 0,
        ..WebhooksConfig::default()
    };
    let error = WebhookHandler::from_context(&setup.context, invalid).unwrap_err();
    assert!(error.to_string().contains("max_consecutive_failures"), "{error}");
}
