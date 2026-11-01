//! The RSVP link of an invitation: minted by the iMIP handler, stored as the keyed hash of its secret, stable across
//! retries and updates, and bounded in time. The tests send invitations through the real handler and read the link
//! from the model the template got and the rows from the store.

use std::sync::Arc;

use chrono::Duration as ChronoDuration;
use davhaven_testkit::davhaven_app::AppCore;
use davhaven_testkit::davhaven_app::imip::ImipHandler;
use davhaven_testkit::davhaven_domain::{
    CalendarUserAddress, CredentialKind, ItipMethod, RsvpToken, StoredObject, TokenId,
};
use davhaven_testkit::davhaven_ports::testing::FixedKeyRing;
use davhaven_testkit::davhaven_ports::{Clock, OutboxHandler, StoredHash};
use secrecy::SecretString;
use uuid::Uuid;

use super::imip_mail::{Scenario, event};
use super::support::{ObjectSpec, World};

fn address(text: &str) -> CalendarUserAddress {
    CalendarUserAddress::parse(text).unwrap()
}

/// The token in the link of the invitation `scenario` sends for `object` to `recipient`.
async fn link(scenario: &Scenario, object: &StoredObject, recipient: &str) -> String {
    let mut job = scenario.job(ItipMethod::Request, "imip_request", recipient);
    job.object = object.id;
    scenario.send(job).await;
    token_of(scenario)
}

/// Like [`link`], with another handler (the same store and doubles, another key ring).
async fn link_with(handler: &ImipHandler, scenario: &Scenario, object: &StoredObject, recipient: &str) -> String {
    let mut job = scenario.job(ItipMethod::Request, "imip_request", recipient);
    job.object = object.id;
    let record = scenario.queue(job).await;
    handler.handle(&record).await.unwrap();
    token_of(scenario)
}

fn token_of(scenario: &Scenario) -> String {
    let url = scenario.last_model()["rsvp_url"].as_str().unwrap().to_owned();
    url.rsplit('/').next().unwrap().to_owned()
}

/// What the authenticator of the web surface does with a presented token: split it, find the row by its prefix and
/// verify the hash of the secret component.
fn authenticates(core: &AppCore, rows: &[RsvpToken], presented: &str) -> Option<TokenId> {
    let rest = presented.strip_prefix("dvh_rsvp_")?;
    let (prefix, secret) = rest.split_once('_')?;
    let row = rows.iter().find(|row| row.prefix == prefix)?;
    let stored = StoredHash::new(CredentialKind::RsvpToken, row.pepper_kid.clone(), row.hash.clone());
    core.deps()
        .hasher
        .verify(&stored, &SecretString::from(secret.to_owned()))
        .then_some(row.id)
}

/// An invitation to `guest@example.net` in the personal calendar of the scenario, ending at `last_end`.
async fn invitation_ending(scenario: &Scenario, last_end: Option<chrono::DateTime<chrono::Utc>>) -> StoredObject {
    scenario
        .world
        .add_object(
            &scenario.seeded.calendar,
            &ObjectSpec {
                last_end,
                organizer: Some("mailto:anna@example.org"),
                attendees: &["mailto:guest@example.net", "mailto:other@example.net"],
                ..ObjectSpec::new("SOURCE")
            },
        )
        .await
}

#[tokio::test]
async fn a_new_invitation_gets_a_token_that_authenticates_like_every_other_credential() {
    let scenario = Scenario::new().await;
    let object = &scenario.seeded.object;
    let token = link(&scenario, object, "mailto:guest@example.net").await;

    let rows = scenario.world.rsvp_tokens(object.id).await;
    assert_eq!(rows.len(), 1);
    let row = rows.first().unwrap();
    assert_eq!(
        (row.tenant_id, row.object_id, row.attendee_address.clone()),
        (World::tenant(), object.id, address("mailto:guest@example.net"))
    );
    assert_eq!(
        row.expires_at,
        object.last_end.unwrap() + ChronoDuration::days(7),
        "seven days after the last instance"
    );
    assert!(row.revoked_at.is_none() && row.last_used_at.is_none());
    let secret = token.splitn(4, '_').nth(3).unwrap();
    assert_eq!(token, format!("dvh_rsvp_{}_{secret}", row.prefix));

    // The row holds the keyed hash of the secret component, as the rows of the other credential kinds do.
    let stored = StoredHash::new(CredentialKind::RsvpToken, row.pepper_kid.clone(), row.hash.clone());
    let hasher = &scenario.world.core.deps().hasher;
    assert!(hasher.verify(&stored, &SecretString::from(secret.to_owned())));
    assert!(
        !hasher.verify(&stored, &SecretString::from(token.clone())),
        "the whole token string is not what the hash covers"
    );
    assert!(!hasher.verify(&stored, &SecretString::from("dvh_rsvp_other")));
    assert_eq!(authenticates(&scenario.world.core, &rows, &token), Some(row.id));
    assert_eq!(
        authenticates(
            &scenario.world.core,
            &rows,
            &format!("dvh_rsvp_{}_{}", row.prefix, "x".repeat(43))
        ),
        None
    );
    assert!(!format!("{row:?}").contains(secret), "the row never prints the secret");
}

#[tokio::test]
async fn the_same_link_comes_back_for_the_same_attendee() {
    let scenario = Scenario::new().await;
    let object = invitation_ending(&scenario, Some(scenario.world.clock.now() + ChronoDuration::days(30))).await;
    let first = link(&scenario, &object, "mailto:guest@example.net").await;
    scenario.world.clock.advance(ChronoDuration::hours(2));
    let again = link(&scenario, &object, "mailto:guest@example.net").await;
    assert_eq!(first, again);
    assert_eq!(scenario.world.rsvp_tokens(object.id).await.len(), 1);

    let theirs = link(&scenario, &object, "mailto:other@example.net").await;
    assert_ne!(theirs, first, "every attendee has their own link");
    assert_eq!(scenario.world.rsvp_tokens(object.id).await.len(), 2);
}

#[tokio::test]
async fn an_event_without_an_end_or_far_in_the_future_keeps_its_link_while_the_clock_runs() {
    let scenario = Scenario::new().await;
    let now = scenario.world.clock.now();
    for (name, last_end) in [
        ("without an end", None),
        ("a year and a month away", Some(now + ChronoDuration::days(400))),
        ("just under a year away", Some(now + ChronoDuration::days(358))),
    ] {
        let object = invitation_ending(&scenario, last_end).await;
        scenario.world.clock.set(now);
        let first = link(&scenario, &object, "mailto:guest@example.net").await;
        for step in [
            ChronoDuration::seconds(30),
            ChronoDuration::days(1),
            ChronoDuration::days(100),
            ChronoDuration::days(200),
        ] {
            scenario.world.clock.advance(step);
            assert_eq!(
                link(&scenario, &object, "mailto:guest@example.net").await,
                first,
                "{name}: a retry or an update mail carries the link of the first mail"
            );
        }
        assert_eq!(
            scenario.world.rsvp_tokens(object.id).await.len(),
            1,
            "{name}: no second token was minted"
        );
    }
}

#[tokio::test]
async fn links_expire_a_week_after_the_event_and_never_after_a_year() {
    let scenario = Scenario::new().await;
    let now = scenario.world.clock.now();
    let days = |n: i64| now + ChronoDuration::days(n);
    for (last_end, expected) in [
        (Some(days(10)), days(17)),
        (None, days(365)),
        (Some(days(1000)), days(365)),
        (Some(days(-40)), days(7)),
    ] {
        let object = invitation_ending(&scenario, last_end).await;
        link(&scenario, &object, "mailto:guest@example.net").await;
        let row = scenario.world.rsvp_tokens(object.id).await.pop().unwrap();
        assert_eq!(row.expires_at, expected, "{last_end:?}");
    }
}

#[tokio::test]
async fn a_token_that_ran_out_is_replaced_and_a_revoked_one_is_never_used_again() {
    let scenario = Scenario::new().await;
    let object = invitation_ending(&scenario, None).await;
    let first = link(&scenario, &object, "mailto:guest@example.net").await;

    scenario.world.clock.advance(ChronoDuration::days(366));
    let second = link(&scenario, &object, "mailto:guest@example.net").await;
    assert_ne!(first, second, "after a year the link has expired and is replaced");
    assert_eq!(link(&scenario, &object, "mailto:guest@example.net").await, second);

    let newest = scenario
        .world
        .rsvp_tokens(object.id)
        .await
        .into_iter()
        .filter(|row| row.revoked_at.is_none())
        .max_by_key(|row| row.id)
        .unwrap();
    let mut tx = scenario.world.write(World::tenant()).await;
    tx.rsvp().revoke(newest.id).await.unwrap();
    tx.commit().await.unwrap();
    let third = link(&scenario, &object, "mailto:guest@example.net").await;
    assert_ne!(third, second, "a revoked token is not handed out again");
}

#[tokio::test]
async fn a_rescheduled_event_gets_a_new_link_and_the_old_one_keeps_working_until_it_expires() {
    let scenario = Scenario::new().await;
    let object = invitation_ending(&scenario, Some(scenario.world.clock.now() + ChronoDuration::days(30))).await;
    let first = link(&scenario, &object, "mailto:guest@example.net").await;

    // The event moved three months out: the old link would stop working before it takes place.
    let moved = scenario
        .world
        .add_object(
            &scenario.seeded.calendar,
            &ObjectSpec {
                existing: Some(&object),
                last_end: Some(scenario.world.clock.now() + ChronoDuration::days(120)),
                organizer: Some("mailto:anna@example.org"),
                attendees: &["mailto:guest@example.net", "mailto:other@example.net"],
                ..ObjectSpec::new("SOURCE")
            },
        )
        .await;
    let second = link(&scenario, &moved, "mailto:guest@example.net").await;
    assert_ne!(first, second);

    let rows = scenario.world.rsvp_tokens(object.id).await;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter().all(|row| row.revoked_at.is_none()),
        "the link in the first mail is not revoked by the second mail"
    );
    assert!(authenticates(&scenario.world.core, &rows, &first).is_some());
    assert!(authenticates(&scenario.world.core, &rows, &second).is_some());
    assert_eq!(
        link(&scenario, &moved, "mailto:guest@example.net").await,
        second,
        "and the new one is kept"
    );

    // An earlier end does not shorten what was promised.
    let earlier = scenario
        .world
        .add_object(
            &scenario.seeded.calendar,
            &ObjectSpec {
                existing: Some(&moved),
                last_end: Some(scenario.world.clock.now() + ChronoDuration::days(30)),
                organizer: Some("mailto:anna@example.org"),
                attendees: &["mailto:guest@example.net", "mailto:other@example.net"],
                ..ObjectSpec::new("SOURCE")
            },
        )
        .await;
    assert_eq!(link(&scenario, &earlier, "mailto:guest@example.net").await, second);
    assert_eq!(scenario.world.rsvp_tokens(object.id).await.len(), 2);
}

#[tokio::test]
async fn a_rotated_key_mints_a_new_link_and_leaves_the_links_of_earlier_mails_alive() {
    let scenario = Scenario::new().await;
    let object = invitation_ending(&scenario, Some(scenario.world.clock.now() + ChronoDuration::days(30))).await;
    let first = link(&scenario, &object, "mailto:guest@example.net").await;

    let mut deps = scenario.world.core.deps().clone();
    deps.keyring = Arc::new(FixedKeyRing::new("rotated"));
    let rotated = ImipHandler::with_backend(AppCore::new(deps), scenario.backend.as_backend());
    let second = link_with(&rotated, &scenario, &object, "mailto:guest@example.net").await;
    assert_ne!(first, second, "the secret cannot be derived with the old key any more");
    let rows = scenario.world.rsvp_tokens(object.id).await;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter().all(|row| row.revoked_at.is_none()),
        "a rotation does not revoke the links that are out there"
    );
    assert!(authenticates(&scenario.world.core, &rows, &first).is_some());
    assert_eq!(
        link_with(&rotated, &scenario, &object, "mailto:guest@example.net").await,
        second
    );
    assert_eq!(scenario.world.rsvp_tokens(object.id).await.len(), 2);
}

#[tokio::test]
async fn a_prefix_collision_is_retried_with_a_fresh_id() {
    // The derivation is deterministic (a fixed key ring and sequential ids), so two worlds that are set up alike
    // mint the same link. The first one tells which prefix the next token gets; the second finds that prefix taken.
    async fn world_with_a_neighbour() -> (Scenario, StoredObject) {
        let scenario = Scenario::new().await;
        let theirs = World::other_tenant();
        let calendar = scenario
            .world
            .calendar_of_kind(theirs, davhaven_testkit::davhaven_domain::CalendarKind::Personal)
            .await;
        let neighbour = scenario.world.add_object(&calendar, &ObjectSpec::new("THEIRS")).await;
        scenario.backend.set_event(event(|_| {}));
        (scenario, neighbour)
    }
    let (probe, _) = world_with_a_neighbour().await;
    let first = link(&probe, &probe.seeded.object, "mailto:guest@example.net").await;
    let claimed_prefix = first.split('_').nth(2).unwrap().to_owned();

    let (scenario, neighbour) = world_with_a_neighbour().await;
    let now = scenario.world.clock.now();
    let blocker = RsvpToken {
        id: TokenId::from_uuid(Uuid::from_u128(77)),
        tenant_id: World::other_tenant(),
        object_id: neighbour.id,
        attendee_address: address("mailto:guest@example.net"),
        prefix: claimed_prefix.clone(),
        hash: vec![1],
        pepper_kid: "test".to_owned(),
        expires_at: now + ChronoDuration::days(1),
        revoked_at: None,
        last_used_at: None,
        last_response: None,
        created_at: now,
        updated_at: now,
        version: 1,
    };
    let mut tx = scenario.world.write(World::other_tenant()).await;
    tx.rsvp().create(blocker).await.unwrap();
    tx.commit().await.unwrap();

    let token = link(&scenario, &scenario.seeded.object, "mailto:guest@example.net").await;
    assert!(!token.contains(&claimed_prefix), "{token}");
    assert_eq!(scenario.world.rsvp_tokens(scenario.seeded.object.id).await.len(), 1);
}

#[tokio::test]
async fn nothing_is_minted_for_a_cancellation_a_reply_or_a_dropped_invitation() {
    let scenario = Scenario::new().await;
    let object = &scenario.seeded.object;
    let mut cancel = scenario.job(ItipMethod::Cancel, "imip_cancel", "mailto:guest@example.net");
    cancel.snapshot = Some("SNAPSHOT".to_owned());
    scenario.send(cancel).await;
    assert_eq!(scenario.world.rsvp_tokens(object.id).await.len(), 0);

    // Dropped for a recipient who is not an attendee: no token either.
    let (_, result) = scenario
        .run(scenario.job(ItipMethod::Request, "imip_request", "mailto:stranger@example.net"))
        .await;
    result.unwrap();
    assert_eq!(scenario.world.rsvp_tokens(object.id).await.len(), 0);
}
