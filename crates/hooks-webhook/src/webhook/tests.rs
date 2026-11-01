//! Tests of the parts of the webhook handler that need no store: how answers are classified, the request that is
//! built, and what the handler is built from. The attempts themselves (loading the subscription, settling the
//! delivery, counting failures, disabling) run against the in-memory store in `davhaven-it`.

use std::time::Duration;

use chrono::Duration as ChronoDuration;
use davhaven_domain::events::CalendarPayload;
use davhaven_domain::{CalendarId, CalendarKind, PrincipalId, WebhookId, WebhookSubscription};
use davhaven_ports::OutboundResponse;
use davhaven_ports::testing::ManualClock;
use http::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;
use crate::signing::Verifier;
use crate::support::Ports;

const SECRET: &str = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

fn tenant() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x7e))
}

fn envelope(clock: &ManualClock) -> Envelope {
    Envelope::new(
        EventId::from_uuid(Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0e01)),
        EventType::CalendarCreated,
        tenant(),
        davhaven_ports::Clock::now(clock),
        AuditActor::system(),
        EventPayload::Calendar(CalendarPayload {
            calendar: CalendarId::from_uuid(Uuid::from_u128(2)),
            owner: PrincipalId::from_uuid(Uuid::from_u128(3)),
            kind: CalendarKind::Group,
        }),
    )
    .unwrap()
}

fn subscription() -> WebhookSubscription {
    let now = davhaven_ports::Clock::now(&ManualClock::default());
    WebhookSubscription {
        id: WebhookId::from_uuid(Uuid::from_u128(0x77)),
        tenant_id: tenant(),
        url: "https://hooks.example.org/in?token=s3cret".parse().unwrap(),
        description: None,
        sealed_secret: Vec::new(),
        sealed_secret_previous: None,
        secret_rotated_at: None,
        events: vec![EventType::CalendarCreated],
        include_details: false,
        active: true,
        failure_count: 0,
        disabled_reason: None,
        created_at: now,
        updated_at: now,
        version: 1,
    }
}

fn delivery(clock: &ManualClock) -> WebhookDelivery {
    WebhookDelivery {
        delivery: davhaven_domain::DeliveryId::from_uuid(Uuid::from_u128(0xd1)),
        webhook: WebhookId::from_uuid(Uuid::from_u128(0x77)),
        envelope: envelope(clock),
        details: None,
    }
}

fn record(created_at: DateTime<Utc>) -> OutboxRecord {
    OutboxRecord {
        id: OutboxId::from_uuid(Uuid::from_u128(0xd1)),
        tenant_id: tenant(),
        kind: "webhook".to_owned(),
        schema_version: 1,
        payload: json!({}),
        status: davhaven_ports::OutboxStatus::InFlight,
        attempts: 1,
        next_attempt_at: created_at,
        locked_until: None,
        last_error: None,
        created_at,
        updated_at: created_at,
    }
}

fn answer(status: u16) -> OutboundResponse {
    OutboundResponse {
        status: StatusCode::from_u16(status).unwrap(),
        headers: http::HeaderMap::new(),
        body: Bytes::new(),
    }
}

fn classified(result: Result<OutboundResponse, PortError>, age: ChronoDuration) -> Outcome {
    let created = davhaven_ports::Clock::now(&ManualClock::default());
    WebhookHandler::classify(result, &record(created), created + age, ChronoDuration::hours(24))
}

#[test]
fn a_success_status_is_a_delivery_whatever_it_is() {
    for status in [200, 201, 202, 204, 299] {
        assert_eq!(
            classified(Ok(answer(status)), ChronoDuration::zero()),
            Outcome::Delivered { status },
            "{status}"
        );
    }
}

#[test]
fn every_other_status_is_a_failed_attempt_that_is_retried_inside_the_window() {
    for status in [301, 302, 400, 401, 403, 404, 408, 409, 429, 500, 502, 503, 504] {
        assert_eq!(
            classified(Ok(answer(status)), ChronoDuration::hours(23)),
            Outcome::Failed {
                status: Some(status),
                error: format!("HTTP {status}")
            },
            "{status}"
        );
    }
}

#[test]
fn a_failed_attempt_after_the_window_ends_the_delivery_and_counts_against_the_receiver() {
    assert_eq!(
        classified(Ok(answer(503)), ChronoDuration::hours(24)),
        Outcome::Dead {
            status: Some(503),
            error: "the retry window ended (HTTP 503)".to_owned(),
            counts: true,
            disable: None,
        }
    );
    assert_eq!(
        classified(Err(PortError::timeout("slow")), ChronoDuration::hours(25)),
        Outcome::Dead {
            status: None,
            error: "the retry window ended (the request failed (timeout))".to_owned(),
            counts: true,
            disable: None,
        }
    );
}

#[test]
fn gone_disables_the_subscription_at_once() {
    assert_eq!(
        classified(Ok(answer(410)), ChronoDuration::zero()),
        Outcome::Dead {
            status: Some(410),
            error: "the receiver answered 410 Gone".to_owned(),
            counts: true,
            disable: Some(ENDPOINT_GONE),
        }
    );
}

#[test]
fn network_failures_are_named_by_kind_and_never_by_their_text() {
    for (error, expected) in [
        (
            PortError::unavailable("refused by hooks.example.org"),
            "the request failed (unavailable)",
        ),
        (
            PortError::timeout("after 10s to hooks.example.org"),
            "the request failed (timeout)",
        ),
        (
            PortError::internal("tls for hooks.example.org"),
            "the request failed (internal)",
        ),
    ] {
        assert_eq!(
            classified(Err(error), ChronoDuration::zero()),
            Outcome::Failed {
                status: None,
                error: expected.to_owned()
            }
        );
    }
}

#[test]
fn the_egress_policy_and_unusable_requests_are_dead_at_once() {
    assert_eq!(
        classified(Err(PortError::rejected("10.0.0.7")), ChronoDuration::zero()),
        Outcome::Dead {
            status: None,
            error: "the egress policy refused the request".to_owned(),
            counts: true,
            disable: None,
        },
        "a subscription that points somewhere it must not is the receiver's doing"
    );
    for error in [PortError::invalid("method"), PortError::unsupported()] {
        assert_eq!(
            classified(Err(error), ChronoDuration::zero()),
            Outcome::Dead {
                status: None,
                error: "the request cannot be sent".to_owned(),
                counts: false,
                disable: None,
            },
            "nobody is to blame for a request that cannot be sent"
        );
    }
}

fn keys() -> Vec<SigningKey> {
    vec![SigningKey::parse(SECRET).unwrap()]
}

#[test]
fn the_request_is_a_signed_json_post_with_the_standard_headers() {
    let ports = Ports::new();
    let subscription = subscription();
    let delivery = delivery(&ports.clock);
    let now = davhaven_ports::Clock::now(&ports.clock);
    let request = WebhookHandler::request(&subscription, &delivery, None, &keys(), now).unwrap();

    assert_eq!(request.method, Method::POST);
    assert_eq!(request.url, subscription.url);
    assert_eq!(request.purpose, HttpPurpose::Webhook);
    let header = |name: &str| request.headers.get(name).unwrap().to_str().unwrap().to_owned();
    assert_eq!(header("content-type"), "application/json");
    assert!(header("user-agent").starts_with("Davhaven-Webhooks/"));
    assert_eq!(header("webhook-id"), "01900000-0000-7000-8000-000000000e01");
    assert_eq!(header("webhook-timestamp"), now.timestamp().to_string());
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(
        body,
        serde_json::to_value(WebhookEnvelope::from(&delivery.envelope)).unwrap()
    );
    assert_eq!(
        body["data"].get("details"),
        None,
        "thin unless the delivery carries details"
    );

    Verifier::new(keys())
        .verify(
            &header("webhook-id"),
            &header("webhook-timestamp"),
            &header("webhook-signature"),
            &request.body,
            now,
        )
        .unwrap();
}

#[test]
fn details_are_added_under_data_and_nowhere_else() {
    let ports = Ports::new();
    let delivery = delivery(&ports.clock);
    let now = davhaven_ports::Clock::now(&ports.clock);
    let details = json!({"objects": [{"object": "x", "summary": "Planning", "restricted": false}]});
    let request = WebhookHandler::request(&subscription(), &delivery, Some(details.clone()), &keys(), now).unwrap();
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["data"]["details"], details);
    assert_eq!(
        body["data"]["calendar"], "00000000-0000-0000-0000-000000000002",
        "the thin payload stays"
    );
}

#[test]
fn the_handler_takes_webhook_records_and_bounds_retries_itself() {
    let ports = Ports::new();
    let handler = WebhookHandler::from_context(&ports.context, WebhooksConfig::default()).unwrap();
    assert_eq!(handler.kind(), "webhook");
    assert!(!handler.limits_attempts());
    assert!(format!("{handler:?}").contains("WebhookHandler"));
    let noop = NoopWebhookHandler::from_context(&ports.context).unwrap();
    assert_eq!(noop.kind(), "webhook");
    assert!(noop.limits_attempts());
    assert!(format!("{noop:?}").contains("NoopWebhookHandler"));
}

#[test]
fn the_handler_needs_a_database_and_an_http_client() {
    let ports = Ports::new();
    let mut without_database = ports.context.clone();
    without_database.database = None;
    let error = WebhookHandler::from_context(&without_database, WebhooksConfig::default()).unwrap_err();
    assert!(error.to_string().contains("database"), "{error}");
    let mut without_http = ports.context.clone();
    without_http.http = None;
    let error = WebhookHandler::from_context(&without_http, WebhooksConfig::default()).unwrap_err();
    assert!(error.to_string().contains("http"), "{error}");
    let invalid = WebhooksConfig {
        max_consecutive_failures: 0,
        ..WebhooksConfig::default()
    };
    assert!(WebhookHandler::from_context(&ports.context, invalid).is_err());
}

#[test]
fn the_retry_window_is_measured_from_the_creation_of_the_record() {
    let ports = Ports::new();
    let handler = WebhookHandler::from_context(
        &ports.context,
        WebhooksConfig {
            retry_window: Duration::from_secs(3600),
            ..WebhooksConfig::default()
        },
    )
    .unwrap();
    let created = davhaven_ports::Clock::now(&ports.clock);
    assert!(!handler.window_ended(&record(created)));
    ports.clock.advance(ChronoDuration::minutes(59));
    assert!(!handler.window_ended(&record(created)));
    ports.clock.advance(ChronoDuration::minutes(1));
    assert!(handler.window_ended(&record(created)));
}
