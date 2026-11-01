//! The id of a delivery. The fan-out itself (one delivery per matching subscription, sinks, details) runs against
//! the in-memory store in `davhaven-it` (`fan_out`).

use super::*;

#[test]
fn delivery_ids_are_stable_time_ordered_uuid_v7s() {
    let event = EventId::from_uuid(Uuid::from_u128(0x0190_1234_5678_7000_8000_0000_0000_0001));
    let later = EventId::from_uuid(Uuid::from_u128(0x0190_1234_9999_7000_8000_0000_0000_0001));
    let hook = WebhookId::from_uuid(Uuid::from_u128(0x77));
    let other_hook = WebhookId::from_uuid(Uuid::from_u128(0x78));

    let id = delivery_id(event, hook);
    assert_eq!(id, delivery_id(event, hook), "deterministic");
    assert_ne!(id, delivery_id(event, other_hook), "one per subscription");
    assert_ne!(id, delivery_id(later, hook), "one per event");
    let uuid = id.as_uuid();
    assert_eq!(uuid.get_version_num(), 7);
    assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
    assert_eq!(
        uuid.as_bytes().get(..6),
        event.as_uuid().as_bytes().get(..6),
        "the timestamp of the event"
    );
    assert!(
        delivery_id(event, hook) < delivery_id(later, hook),
        "ordered by event time"
    );
}
