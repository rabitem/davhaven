//! The pure parts of the details. Which objects are described (group and managed calendars only, never the
//! personal ones of principals) is tested against the in-memory store in `davhaven-it`.

use davhaven_domain::events::{ObjectChange, ObjectsChangedPayload, RsvpPayload, WebhookPayload};
use davhaven_domain::{AuditActor, CalendarId, EventId, EventType, ObjectUri, PartStat, SyncToken, Uid};
use uuid::Uuid;

use super::*;

fn envelope(event_type: EventType, data: EventPayload) -> Envelope {
    Envelope::new(
        EventId::from_uuid(Uuid::from_u128(0x99)),
        event_type,
        TenantId::from_uuid(Uuid::from_u128(1)),
        at(),
        AuditActor::system(),
        data,
    )
    .unwrap()
}

/// The fixed time of these tests.
fn at() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

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

fn object(n: u128) -> ObjectId {
    ObjectId::from_uuid(Uuid::from_u128(n))
}

#[test]
fn summaries_are_one_line_and_cut() {
    assert_eq!(
        one_line("  Planning \r\nsession\t"),
        Some("Planning   session".to_owned())
    );
    assert_eq!(one_line("\n \t"), None);
    assert_eq!(one_line("a\u{0}b"), Some("a b".to_owned()));
    assert_eq!(one_line(&"ü".repeat(500)).unwrap().chars().count(), MAX_SUMMARY_CHARS);
}

#[test]
fn the_objects_of_an_event_are_the_ones_that_still_exist_named_by_it() {
    let changed = envelope(
        EventType::CalendarObjectsChanged,
        EventPayload::ObjectsChanged(ObjectsChangedPayload {
            calendar: CalendarId::from_uuid(Uuid::from_u128(2)),
            sync_token: SyncToken::new(Uuid::from_u128(1), Uuid::from_u128(2), 9),
            changes: vec![
                change(Some(object(10)), ObjectChangeKind::Created, 1),
                change(Some(object(11)), ObjectChangeKind::Updated, 2),
                change(Some(object(12)), ObjectChangeKind::Deleted, 3),
                change(None, ObjectChangeKind::Updated, 4),
            ],
            truncated: false,
        }),
    );
    assert_eq!(
        objects_of(&changed),
        vec![object(10), object(11)],
        "deleted objects and changes without an object are left out"
    );

    let rsvp = envelope(
        EventType::RsvpAnswered,
        EventPayload::Rsvp(RsvpPayload {
            calendar: CalendarId::from_uuid(Uuid::from_u128(2)),
            object: object(20),
            uid: Uid::parse("uid-20").unwrap(),
            partstat: PartStat::Accepted,
        }),
    );
    assert_eq!(objects_of(&rsvp), vec![object(20)]);

    let ping = envelope(
        EventType::WebhookPing,
        EventPayload::Webhook(WebhookPayload {
            webhook: davhaven_domain::WebhookId::from_uuid(Uuid::from_u128(5)),
            reason: WebhookPayload::PING.to_owned(),
        }),
    );
    assert_eq!(objects_of(&ping), Vec::new());
}
