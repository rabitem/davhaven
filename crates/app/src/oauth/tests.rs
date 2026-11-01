//! The pure parts of the OAuth service: names, slugs and the choice of the calendar to mirror. The flow itself (the state, the
//! callback, the account and its mirror, the disconnection, who may do it, which tenant it reaches) runs against the in-memory
//! store in `davhaven-it` (`providers`), with the fake provider.

use davhaven_domain::{CalendarSlug, ErrorKind};
use uuid::Uuid;

use super::*;
use crate::outbox::fixture::Fixture;

#[test]
fn a_mirror_is_named_after_the_provider_and_the_account_in_printable_text_of_bounded_length() {
    assert_eq!(mirror_name("Google", "anna@example.org"), "Google: anna@example.org");
    assert_eq!(
        mirror_name("Google", "anna\u{7}@example.org\n"),
        "Google: anna@example.org",
        "control characters of the provider's text never reach a calendar name"
    );
    let long = mirror_name("Microsoft", &"x".repeat(1000));
    assert_eq!(long.chars().count(), MAX_NAME_CHARS);
    assert!(long.starts_with("Microsoft: x"));
    assert_eq!(
        mirror_name("Google", &"ä".repeat(300)).chars().count(),
        MAX_NAME_CHARS,
        "characters, not bytes"
    );
}

#[test]
fn the_slug_of_a_mirror_is_the_provider_and_the_random_end_of_the_account_id() {
    let account = ExternalAccountId::from_uuid(Uuid::from_u128(0x018f_3c1e_7b2a_7c3d_9e4f_0123_4567_89ab));
    let slug = mirror_slug("google", account).unwrap();
    assert_eq!(slug.as_str(), "google-0123456789ab");
    assert_ne!(
        slug,
        mirror_slug("google", ExternalAccountId::from_uuid(Uuid::from_u128(1))).unwrap(),
        "two accounts of a principal have two calendars"
    );
    // Every name a provider can have is a valid slug, so the calendar can always be created.
    for provider in ["google", "microsoft", "fake", "provider-2"] {
        CalendarSlug::parse(mirror_slug(provider, account).unwrap().as_str()).unwrap();
    }
}

#[test]
fn the_primary_calendar_is_mirrored_else_the_first() {
    assert!(choose(&[]).is_none());
    let calendars = [
        RemoteCalendar::new("work", "Work"),
        RemoteCalendar::new("main", "Main").primary(),
        RemoteCalendar::new("other", "Other"),
    ];
    assert_eq!(
        choose(&calendars).map(|calendar| calendar.remote_id.as_str()),
        Some("main")
    );
    assert_eq!(
        choose(&calendars[..1]).map(|calendar| calendar.remote_id.as_str()),
        Some("work")
    );
    assert_eq!(
        choose(&calendars[2..]).map(|calendar| calendar.remote_id.as_str()),
        Some("other")
    );
}

#[test]
fn the_project_ships_google_and_microsoft_and_a_state_lives_ten_minutes() {
    assert_eq!(KNOWN_PROVIDERS, ["google", "microsoft"]);
    assert_eq!(STATE_TTL.num_seconds(), 600);
}

#[tokio::test]
async fn nothing_is_asked_of_the_provider_or_the_store_before_the_scope_is_checked() {
    // A caller without `providers:manage` is refused at the door: the double of the store would answer `Unavailable` if the
    // service went on to look at it.
    let service = ExternalAccountServiceImpl::new(Fixture::new().core);
    let ctx = RequestContext {
        scopes: davhaven_domain::ScopeSet::empty(),
        ..RequestContext::internal(
            TenantId::from_uuid(Uuid::from_u128(1)),
            RequestId::from_uuid(Uuid::from_u128(2)),
        )
    };
    let tenant_token = RequestContext {
        actor: davhaven_domain::Actor::TenantToken(davhaven_domain::TokenId::from_uuid(Uuid::from_u128(3))),
        channel: davhaven_domain::Channel::Api,
        ..ctx
    };
    assert_eq!(
        service.providers(&tenant_token).await.unwrap_err().kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        service
            .start(&tenant_token, "google", &PrincipalName::parse("anna").unwrap())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        service
            .list(&tenant_token, PageRequest::first())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        service
            .delete(&tenant_token, ExternalAccountId::from_uuid(Uuid::from_u128(4)))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
}

#[tokio::test]
async fn the_callback_needs_a_state_that_names_a_tenant() {
    let service = ExternalAccountServiceImpl::new(Fixture::new().core);
    let ctx = RequestContext::internal(
        TenantId::from_uuid(Uuid::from_u128(1)),
        RequestId::from_uuid(Uuid::from_u128(2)),
    );
    for state in [None, Some("garbage".to_owned()), Some("x".repeat(80))] {
        let params = CallbackParams {
            code: Some(SecretString::from("4/0A")),
            state,
            error: None,
        };
        let error = service.complete(&ctx, "google", params).await.unwrap_err();
        assert_eq!(
            error.kind(),
            ErrorKind::NotFound,
            "a callback that cannot be ours reveals nothing"
        );
    }
}
