//! The fake provider runs the contract suite of the `Provider` port, in both of its modes, like every implementation.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::sync::Arc;

use davhaven_port_tests::provider::{Scenario, run_all};
use davhaven_ports::testing::ManualClock;
use davhaven_ports::{OAuthProvider, Provider};
use davhaven_provider_fake::provider::{FakeProvider, s256_challenge};
use davhaven_provider_fake::script::{Mode, simple_event};
use secrecy::SecretString;
use url::Url;

/// The world of the suite: one account, one primary calendar with two events, a code that signs the account in.
fn scenario(mode: Mode) -> Scenario {
    let fake = FakeProvider::new(Arc::new(ManualClock::default()));
    let script = fake.script();
    script.set_mode(mode);
    script.put_event(
        "primary",
        "e1",
        simple_event("uid-1", "Kick-off", "20270105T090000Z", "20270105T100000Z"),
    );
    script.put_event(
        "primary",
        "e2",
        simple_event("uid-2", "Review", "20270106T090000Z", "20270106T100000Z"),
    );
    let redirect = Url::parse("https://cal.example.org/oauth/fake/callback").unwrap();
    let verifier = "a-verifier-that-is-long-enough-to-be-real-0123456789";
    // The consent that the person gave: the challenge of the verifier is known to the provider.
    fake.authorize_url("state", &s256_challenge(verifier), &redirect)
        .unwrap();
    script.accept_code("good-code", "anna@fake.example");
    let (access, refresh) = script.issue_tokens();
    let provider: Arc<dyn Provider> = Arc::new(fake);
    let refusing = FakeProvider::new(Arc::new(ManualClock::default()));
    refusing.script().refuse_client(true);
    let refused_client: Arc<dyn Provider> = Arc::new(refusing);
    Scenario {
        provider,
        redirect,
        good_code: SecretString::from("good-code"),
        verifier: SecretString::from(verifier),
        bad_code: SecretString::from("rejected-code"),
        account_ref: "anna@fake.example".to_owned(),
        good_refresh_token: SecretString::from(refresh),
        revoked_refresh_token: SecretString::from("a-refresh-token-that-was-revoked"),
        access_token: SecretString::from(access),
        bad_access_token: SecretString::from("an-access-token-that-is-not-valid"),
        calendar: "primary".to_owned(),
        event_ids: vec!["e1".to_owned(), "e2".to_owned()],
        stale_cursor: matches!(mode, Mode::Delta).then(|| "not-a-cursor".to_owned()),
        refused_client: Some(refused_client),
    }
}

#[tokio::test]
async fn the_fake_with_a_change_feed_keeps_the_contract() {
    run_all(|| scenario(Mode::Delta)).await;
}

#[tokio::test]
async fn the_fake_that_lists_the_calendar_every_time_keeps_the_contract() {
    run_all(|| scenario(Mode::Snapshot)).await;
}
