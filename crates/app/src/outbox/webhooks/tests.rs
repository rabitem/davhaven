//! The pure parts of the webhook service: the normalization of a request body and what the audit log says about a
//! change. The operations themselves (registration, patches, secrets, test events, deliveries, who may call, which
//! tenant they reach) run against the in-memory store in `davhaven-it` (`webhook_service`).

use davhaven_domain::ErrorKind;

use super::*;

fn body(events: &[EventType]) -> WebhookCreate {
    WebhookCreate {
        url: Url::parse("https://hooks.example.org/in").unwrap(),
        description: None,
        events: events.to_vec(),
        include_details: false,
        active: true,
    }
}

fn pointers(error: &AppError) -> Vec<(&'static str, &'static str)> {
    error
        .field_errors()
        .iter()
        .map(|field| (field.pointer, field.code))
        .collect()
}

#[test]
fn events_are_deduplicated_in_order_and_blank_descriptions_dropped() {
    let mut request = body(&[
        EventType::PrincipalCreated,
        EventType::PrincipalCreated,
        EventType::CalendarCreated,
    ]);
    request.description = Some("   ".to_owned());
    let normalized = normalize(request).unwrap();
    assert_eq!(
        normalized.events,
        vec![EventType::PrincipalCreated, EventType::CalendarCreated]
    );
    assert_eq!(normalized.description, None);
}

#[test]
fn a_subscription_needs_events_and_cannot_ask_for_the_test_event() {
    let error = normalize(body(&[])).unwrap_err();
    assert_eq!(
        (error.kind(), pointers(&error)),
        (ErrorKind::Invalid, vec![("/events", "empty")])
    );
    let error = normalize(body(&[EventType::CalendarCreated, EventType::WebhookPing])).unwrap_err();
    assert_eq!(
        (error.kind(), pointers(&error)),
        (ErrorKind::Invalid, vec![("/events", "not-allowed")])
    );
    assert!(
        normalize(body(&[EventType::WebhookDisabled])).is_ok(),
        "the notice of the disabling can be subscribed to"
    );
}

#[test]
fn descriptions_are_bounded_in_characters_and_have_no_control_characters() {
    for (description, code) in [
        ("x".repeat(501), "too-long"),
        ("line\nbreak".to_owned(), "control-characters"),
    ] {
        let mut request = body(&[EventType::CalendarCreated]);
        request.description = Some(description);
        let error = normalize(request).unwrap_err();
        assert_eq!(pointers(&error), vec![("/description", code)]);
    }
    let mut ok = body(&[EventType::CalendarCreated]);
    ok.description = Some("ü".repeat(500));
    assert!(normalize(ok).is_ok(), "500 characters, not 500 bytes");
}

fn subscription() -> WebhookSubscription {
    let at = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    WebhookSubscription {
        id: WebhookId::from_uuid(uuid::Uuid::from_u128(1)),
        tenant_id: davhaven_domain::TenantId::from_uuid(uuid::Uuid::from_u128(2)),
        url: Url::parse("https://hooks.example.org/in").unwrap(),
        description: None,
        sealed_secret: Vec::new(),
        sealed_secret_previous: None,
        secret_rotated_at: None,
        events: vec![EventType::CalendarCreated],
        include_details: false,
        active: true,
        failure_count: 0,
        disabled_reason: None,
        created_at: at,
        updated_at: at,
        version: 1,
    }
}

#[test]
fn the_audit_log_names_the_settings_that_changed_in_a_stable_order() {
    let before = subscription();
    assert_eq!(changed_fields(&before, &before), Vec::<String>::new());
    let after = WebhookSubscription {
        url: Url::parse("https://other.example.org/in").unwrap(),
        include_details: true,
        active: false,
        events: vec![EventType::GrantCreated],
        description: Some("x".to_owned()),
        ..subscription()
    };
    assert_eq!(
        changed_fields(&before, &after),
        vec!["url", "description", "events", "include_details", "active"]
    );
}

#[test]
fn the_audit_log_names_the_host_and_never_the_path_or_the_query() {
    let url = Url::parse("https://hooks.example.org/secret/path?token=abc").unwrap();
    let details = WebhookServiceImpl::webhook_audit(WebhookId::from_uuid(uuid::Uuid::from_u128(1)), Some(&url));
    assert_eq!(details.host.as_deref(), Some("hooks.example.org"));
    let shown = serde_json::to_string(&details).unwrap();
    assert!(!shown.contains("secret") && !shown.contains("token"), "{shown}");
    let without = WebhookServiceImpl::webhook_audit(WebhookId::from_uuid(uuid::Uuid::from_u128(1)), None);
    assert_eq!(without.host, None);
}

#[test]
fn the_view_of_a_subscription_has_no_secret() {
    let view = view(&subscription());
    let shown = serde_json::to_string(&view).unwrap();
    assert!(!shown.contains("sealed") && !shown.contains("secret"), "{shown}");
}
