//! The pure parts of the RSVP link: the derivation of a token and the bounds of its validity. Minting, reusing and
//! replacing tokens run against the in-memory store in `davhaven-it` (`rsvp_links`).

use chrono::TimeZone;
use davhaven_domain::{Classification, ComponentKind, ContentHash, ETag, ObjectId, ObjectUri, PrincipalId, Uid};
use davhaven_ports::testing::FixedKeyRing;
use uuid::Uuid;

use super::*;

fn tenant(n: u128) -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(n))
}

fn token_id(n: u128) -> TokenId {
    TokenId::from_uuid(Uuid::from_u128(n))
}

/// An invitation that ends at `last_end`.
fn object(last_end: Option<DateTime<Utc>>) -> StoredObject {
    let at = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
    StoredObject {
        id: ObjectId::from_uuid(Uuid::from_u128(1)),
        tenant_id: tenant(1),
        calendar_id: davhaven_domain::CalendarId::from_uuid(Uuid::from_u128(2)),
        owner_id: PrincipalId::from_uuid(Uuid::from_u128(3)),
        uri: ObjectUri::parse("a.ics").unwrap(),
        uid: Uid::parse("uid-a").unwrap(),
        etag: ETag::from_bytes(b"a"),
        schedule_tag: None,
        content_hash: ContentHash::from_digest([0; 32]),
        component: ComponentKind::Event,
        data: "SOURCE".to_owned(),
        size: 6,
        first_start: Some(at),
        last_end,
        is_recurring: false,
        is_scheduling: true,
        organizer_address: None,
        sequence: 0,
        class: Classification::Public,
        external_key: None,
        origin: None,
        created_at: at,
        updated_at: at,
        version: 1,
    }
}

#[test]
fn a_derived_token_parses_with_the_one_definition_of_the_format() {
    // What the mail carries is what the authenticator of the web surface will read: the same module reads it back.
    let keyring = FixedKeyRing::default();
    let parts = derive(&keyring, tenant(1), token_id(2));
    let token = parts.token();
    let parsed = TokenText::parse(CredentialKind::RsvpToken, token.expose_secret()).expect("a valid RSVP token");
    assert_eq!(parsed.prefix(), parts.prefix);
    assert_eq!(parsed.secret(), parts.secret.expose_secret());
    assert!(TokenText::parse(CredentialKind::FeedToken, token.expose_secret()).is_none());
}

#[test]
fn tokens_have_the_documented_shape_and_are_reproducible() {
    let keyring = FixedKeyRing::default();
    let parts = derive(&keyring, tenant(1), token_id(2));
    let secret = parts.secret.expose_secret();
    assert_eq!(parts.prefix.len(), 12);
    assert!(
        parts
            .prefix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)),
        "{}",
        parts.prefix
    );
    assert_eq!(secret.len(), 43);
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "{secret}"
    );
    let token = parts.token();
    assert_eq!(token.expose_secret(), &format!("dvh_rsvp_{}_{secret}", parts.prefix));

    let again = derive(&keyring, tenant(1), token_id(2));
    assert_eq!(
        (parts.prefix.as_str(), secret),
        (again.prefix.as_str(), again.secret.expose_secret())
    );
}

#[test]
fn tokens_depend_on_tenant_id_and_key() {
    let keyring = FixedKeyRing::default();
    let base = derive(&keyring, tenant(1), token_id(2));
    let others = [
        derive(&keyring, tenant(9), token_id(2)),
        derive(&keyring, tenant(1), token_id(9)),
        derive(&FixedKeyRing::new("rotated"), tenant(1), token_id(2)),
    ];
    for different in others {
        assert_ne!(base.secret.expose_secret(), different.secret.expose_secret());
        assert_ne!(base.prefix, different.prefix);
    }
}

#[test]
fn the_secret_is_not_the_prefix() {
    // Both come from the same key but from different labels: knowing the prefix (which the row stores in the
    // clear) says nothing about the secret.
    let keyring = FixedKeyRing::default();
    let parts = derive(&keyring, tenant(1), token_id(2));
    assert!(
        !parts
            .secret
            .expose_secret()
            .to_ascii_lowercase()
            .contains(&parts.prefix)
    );
}

#[test]
fn links_expire_a_week_after_the_event_and_never_after_a_year() {
    let now = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
    let days = |n: i64| now + Duration::days(n);
    let mut object = object(None);

    object.last_end = Some(days(10));
    assert_eq!(expiry(&object, now), days(17));
    object.last_end = None;
    assert_eq!(expiry(&object, now), days(365), "an event without an end");
    object.last_end = Some(days(1000));
    assert_eq!(expiry(&object, now), days(365), "capped at a year");
    object.last_end = Some(days(-40));
    assert_eq!(expiry(&object, now), days(7), "a past event leaves a week to answer");
    object.last_end = Some(Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap());
    assert_eq!(expiry(&object, now), days(7));
}

#[test]
fn the_bound_a_token_is_measured_against_does_not_move_with_the_clock() {
    let created = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
    let days = |n: i64| created + Duration::days(n);
    let mut object = object(None);
    for (last_end, expected) in [
        (Some(days(10)), days(17)),
        (None, days(365)),
        (Some(days(400)), days(365)),
        (Some(days(358)), days(365)),
        (Some(days(-3)), days(4)),
    ] {
        object.last_end = last_end;
        assert_eq!(wanted(&object, created), expected, "{last_end:?}");
    }
}
