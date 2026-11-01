//! The fake `OAuthProvider` and `RemoteCalendarApi`.
//!
//! [`FakeProvider`] behaves like a small, strict provider, so that a test of the application finds the mistakes a real one
//! would punish:
//!
//! * **PKCE is checked.** `authorize_url` remembers the challenge it was given and `exchange` refuses a verifier whose S256
//!   hash is none of them.
//! * **An authorization code works once.** A second exchange of the same code is refused, as is a code the script refuses.
//! * **Tokens expire with the clock** the provider was built with, and the API refuses an expired or revoked access token
//!   (`Rejected`), so the sync engine has to refresh.
//! * **A refresh token that was revoked is refused** (`Rejected`), the way a person who removed the app's access is.
//!
//! What the calendars hold, and which calls fail, is the business of the [`Script`].

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use davhaven_ports::{
    Clock, OAuthGrant, OAuthProvider, OAuthTokens, PortError, Provider, RemoteCalendar, RemoteCalendarApi,
    RemoteChange, RemoteChanges,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use url::Url;

use crate::script::{Call, Mode, Script};

/// The name of the provider.
pub const NAME: &str = "fake";

/// The host the consent URL points at. Nothing is ever sent there.
pub const CONSENT_HOST: &str = "https://fake-provider.example/authorize";

/// The S256 challenge of a verifier, as a client computes it (RFC 7636): the URL-safe base64 of the SHA-256 hash.
pub fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A scriptable provider: OAuth with PKCE and a calendar API over the world of a [`Script`].
#[derive(Clone)]
pub struct FakeProvider {
    script: Script,
    enabled: bool,
}

impl core::fmt::Debug for FakeProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeProvider")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl FakeProvider {
    /// A provider with a world of its own (see [`Script::new`]) whose tokens expire by `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_script(Script::new(clock))
    }

    /// A provider over an existing world.
    pub const fn with_script(script: Script) -> Self {
        Self { script, enabled: true }
    }

    /// The same provider, switched off (`enabled()` answers `false`), as a deployment that selected it and did not enable it.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// The world of the provider; the handle shares its state.
    pub fn script(&self) -> Script {
        self.script.clone()
    }
}

impl Provider for FakeProvider {
    fn name(&self) -> &'static str {
        NAME
    }

    fn display_name(&self) -> &'static str {
        "Fake"
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn oauth(&self) -> &dyn OAuthProvider {
        self
    }

    fn calendars(&self) -> &dyn RemoteCalendarApi {
        self
    }
}

fn tokens(access: String, expires: chrono::DateTime<chrono::Utc>, refresh: Option<String>) -> OAuthTokens {
    OAuthTokens {
        access_token: SecretString::from(access),
        refresh_token: refresh.map(SecretString::from),
        expires_at: Some(expires),
        scope: Some("calendar.read".to_owned()),
    }
}

#[async_trait]
impl OAuthProvider for FakeProvider {
    fn authorize_url(&self, state: &str, pkce_challenge: &str, redirect: &Url) -> Result<Url, PortError> {
        let mut url = Url::parse(CONSENT_HOST).map_err(|error| PortError::internal(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("state", state)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("redirect_uri", redirect.as_str());
        self.script
            .lock()
            .challenges
            .insert(pkce_challenge.to_owned(), redirect.as_str().to_owned());
        Ok(url)
    }

    async fn exchange(
        &self,
        code: &SecretString,
        verifier: &SecretString,
        redirect: &Url,
    ) -> Result<OAuthGrant, PortError> {
        let mut state = self.script.lock();
        state.enter(Call::Exchange, None)?;
        if state.client_refused {
            return Err(PortError::invalid("the client of the deployment is refused"));
        }
        // As a real provider does, the exchange must come with the redirect address of the authorization it finishes.
        match state.challenges.get(&s256_challenge(verifier.expose_secret())) {
            None => {
                return Err(PortError::rejected(
                    "the PKCE verifier does not match the challenge of any authorization",
                ));
            }
            Some(named) if named != redirect.as_str() => {
                return Err(PortError::rejected(
                    "the redirect address is not the one the authorization named",
                ));
            }
            Some(_) => {}
        }
        let Some(account_ref) = state.redeem_code(code.expose_secret()) else {
            return Err(PortError::rejected("the authorization code is refused"));
        };
        let (access, expires) = state.issue_access();
        let refresh = state.issue_refresh();
        Ok(OAuthGrant {
            tokens: tokens(access, expires, Some(refresh)),
            account_ref,
        })
    }

    async fn refresh(&self, refresh_token: &SecretString) -> Result<OAuthTokens, PortError> {
        let mut state = self.script.lock();
        state.enter(Call::Refresh, None)?;
        if state.client_refused {
            return Err(PortError::invalid("the client of the deployment is refused"));
        }
        if !state.knows_refresh(refresh_token.expose_secret()) {
            return Err(PortError::rejected("the refresh token is revoked or unknown"));
        }
        let (access, expires) = state.issue_access();
        let rotated = if state.rotate_refresh {
            state.retire_refresh(refresh_token.expose_secret());
            Some(state.issue_refresh())
        } else {
            None
        };
        Ok(tokens(access, expires, rotated))
    }

    async fn revoke(&self, token: &SecretString) -> Result<(), PortError> {
        let mut state = self.script.lock();
        state.enter(Call::Revoke, None)?;
        state.record_revoked(token.expose_secret());
        Ok(())
    }
}

#[async_trait]
impl RemoteCalendarApi for FakeProvider {
    async fn list_calendars(&self, token: &SecretString) -> Result<Vec<RemoteCalendar>, PortError> {
        let mut state = self.script.lock();
        state.enter(Call::ListCalendars, None)?;
        if !state.access_is_valid(token.expose_secret()) {
            return Err(PortError::rejected("the access token is not valid"));
        }
        Ok(state.calendars.clone())
    }

    async fn changes_since(
        &self,
        token: &SecretString,
        calendar: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteChanges, PortError> {
        let mut state = self.script.lock();
        state.enter(Call::Changes, Some(format!("{calendar} {}", cursor.unwrap_or("-"))))?;
        if !state.access_is_valid(token.expose_secret()) {
            return Err(PortError::rejected("the access token is not valid"));
        }
        if !state.has_calendar(calendar) {
            return Err(PortError::rejected("the calendar does not exist"));
        }
        let all = |state: &crate::script::State| {
            state
                .listing(calendar)
                .into_iter()
                .map(|(remote_id, etag, ics)| RemoteChange {
                    remote_id,
                    etag: Some(etag),
                    ics: Some(ics),
                })
                .collect::<Vec<_>>()
        };
        let now = state.cursor();
        match (state.mode, cursor) {
            (Mode::Snapshot, _) | (Mode::Delta, None) => Ok(RemoteChanges::snapshot(all(&state), now)),
            (Mode::Delta, Some(cursor)) => {
                let Some(since) = state.seq_of(cursor) else {
                    return Err(PortError::invalid("the cursor is stale or not one of this provider"));
                };
                let changes = state
                    .changes_after(calendar, since)
                    .into_iter()
                    .map(|(remote_id, etag, ics)| RemoteChange {
                        remote_id,
                        etag: Some(etag),
                        ics,
                    })
                    .collect();
                Ok(RemoteChanges::delta(changes, now))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use davhaven_ports::PortErrorKind;
    use davhaven_ports::testing::ManualClock;

    use super::*;
    use crate::script::simple_event;

    fn provider() -> (FakeProvider, ManualClock) {
        let clock = ManualClock::default();
        (FakeProvider::new(Arc::new(clock.clone())), clock)
    }

    fn redirect() -> Url {
        Url::parse("https://cal.example.org/oauth/fake/callback").unwrap()
    }

    /// Runs the consent and the exchange for `code`, returning the grant.
    async fn connect(provider: &FakeProvider, code: &str) -> OAuthGrant {
        let verifier = SecretString::from("verifier-0123456789");
        provider
            .authorize_url("state-1", &s256_challenge(verifier.expose_secret()), &redirect())
            .unwrap();
        provider
            .exchange(&SecretString::from(code), &verifier, &redirect())
            .await
            .unwrap()
    }

    #[test]
    fn the_consent_url_carries_the_state_the_challenge_and_the_redirect() {
        let (provider, _clock) = provider();
        let url = provider.authorize_url("s-1", "challenge-1", &redirect()).unwrap();
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        for wanted in [
            ("state", "s-1"),
            ("code_challenge", "challenge-1"),
            ("code_challenge_method", "S256"),
            ("redirect_uri", "https://cal.example.org/oauth/fake/callback"),
        ] {
            assert!(
                pairs.contains(&(wanted.0.to_owned(), wanted.1.to_owned())),
                "{wanted:?}: {pairs:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_exchange_checks_pkce_and_uses_a_code_once() {
        let (provider, _clock) = provider();
        let verifier = SecretString::from("a-verifier-that-is-long-enough-0123456789");
        provider
            .authorize_url("s", &s256_challenge(verifier.expose_secret()), &redirect())
            .unwrap();
        let wrong = provider
            .exchange(
                &SecretString::from("fake-anna"),
                &SecretString::from("another-verifier"),
                &redirect(),
            )
            .await
            .unwrap_err();
        assert_eq!(wrong.kind, PortErrorKind::Rejected);
        let grant = provider
            .exchange(&SecretString::from("fake-anna"), &verifier, &redirect())
            .await
            .unwrap();
        assert_eq!(grant.account_ref, "anna@fake.example");
        assert!(grant.tokens.refresh_token.is_some());
        let again = provider
            .exchange(&SecretString::from("fake-anna"), &verifier, &redirect())
            .await
            .unwrap_err();
        assert_eq!(again.kind, PortErrorKind::Rejected, "an authorization code works once");
    }

    #[tokio::test]
    async fn the_exchange_names_the_redirect_address_of_the_authorization() {
        let (provider, _clock) = provider();
        let verifier = SecretString::from("a-verifier-that-is-long-enough-0123456789");
        provider
            .authorize_url("s", &s256_challenge(verifier.expose_secret()), &redirect())
            .unwrap();
        let elsewhere = Url::parse("https://cal.example.org/oauth/other/callback").unwrap();
        let refused = provider
            .exchange(&SecretString::from("fake-anna"), &verifier, &elsewhere)
            .await
            .unwrap_err();
        assert_eq!(refused.kind, PortErrorKind::Rejected);
        assert!(refused.message.contains("redirect"), "{refused}");
        provider
            .exchange(&SecretString::from("fake-anna"), &verifier, &redirect())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revoking_the_access_tokens_alone_leaves_the_refresh_token_working() {
        let (provider, _clock) = provider();
        let grant = connect(&provider, "fake-anna").await;
        let access = grant.tokens.access_token.clone();
        let refresh = grant.tokens.refresh_token.clone().unwrap();
        assert!(provider.list_calendars(&access).await.is_ok());
        provider.script().revoke_access_tokens();
        assert_eq!(
            provider.list_calendars(&access).await.unwrap_err().kind,
            PortErrorKind::Rejected,
            "the access token was revoked before its time"
        );
        let renewed = provider.refresh(&refresh).await.unwrap();
        assert!(
            provider.list_calendars(&renewed.access_token).await.is_ok(),
            "the refresh token still gives a working access token"
        );
        // Revoking everything (the person removed the access) takes the refresh token too.
        provider.script().revoke_access();
        assert_eq!(
            provider.refresh(&refresh).await.unwrap_err().kind,
            PortErrorKind::Rejected
        );
    }

    #[tokio::test]
    async fn tokens_expire_and_refreshing_gives_a_new_access_token() {
        let (provider, clock) = provider();
        let grant = connect(&provider, "fake-anna").await;
        let access = grant.tokens.access_token.clone();
        let refresh = grant.tokens.refresh_token.clone().unwrap();
        assert_eq!(provider.list_calendars(&access).await.unwrap().len(), 1);
        clock.advance(Duration::hours(2));
        assert_eq!(
            provider.list_calendars(&access).await.unwrap_err().kind,
            PortErrorKind::Rejected,
            "the access token expired with the clock"
        );
        let renewed = provider.refresh(&refresh).await.unwrap();
        assert!(
            renewed.refresh_token.is_none(),
            "the refresh token stays unless the script rotates it"
        );
        assert!(provider.list_calendars(&renewed.access_token).await.is_ok());
    }

    #[tokio::test]
    async fn a_rotating_provider_hands_out_a_new_refresh_token_and_retires_the_old_one() {
        let (provider, _clock) = provider();
        provider.script().rotate_refresh_tokens(true);
        let grant = connect(&provider, "fake-anna").await;
        let old = grant.tokens.refresh_token.unwrap();
        let renewed = provider.refresh(&old).await.unwrap();
        let new = renewed.refresh_token.unwrap();
        assert_ne!(old.expose_secret(), new.expose_secret());
        assert_eq!(provider.refresh(&old).await.unwrap_err().kind, PortErrorKind::Rejected);
        assert!(provider.refresh(&new).await.is_ok());
    }

    #[tokio::test]
    async fn revoked_access_is_refused_everywhere() {
        let (provider, _clock) = provider();
        let grant = connect(&provider, "fake-anna").await;
        provider.script().revoke_access();
        let refresh = grant.tokens.refresh_token.unwrap();
        assert_eq!(
            provider.refresh(&refresh).await.unwrap_err().kind,
            PortErrorKind::Rejected
        );
        assert_eq!(
            provider
                .list_calendars(&grant.tokens.access_token)
                .await
                .unwrap_err()
                .kind,
            PortErrorKind::Rejected
        );
        provider.revoke(&refresh).await.unwrap();
        assert_eq!(
            provider.script().revoked_tokens(),
            vec![refresh.expose_secret().to_owned()]
        );
    }

    #[tokio::test]
    async fn the_delta_mode_lists_everything_first_and_then_what_changed() {
        let (provider, _clock) = provider();
        let script = provider.script();
        let token = connect(&provider, "fake-anna").await.tokens.access_token;
        script.put_event(
            "primary",
            "e1",
            simple_event("u1", "One", "20270105T090000Z", "20270105T100000Z"),
        );
        script.put_event(
            "primary",
            "e2",
            simple_event("u2", "Two", "20270106T090000Z", "20270106T100000Z"),
        );
        let first = provider.changes_since(&token, "primary", None).await.unwrap();
        assert!(first.snapshot, "without a cursor the answer is the whole calendar");
        assert_eq!(first.changes.len(), 2);
        let nothing = provider
            .changes_since(&token, "primary", Some(&first.cursor))
            .await
            .unwrap();
        assert!(!nothing.snapshot && nothing.changes.is_empty());
        script.put_event(
            "primary",
            "e1",
            simple_event("u1", "One, moved", "20270107T090000Z", "20270107T100000Z"),
        );
        script.remove_event("primary", "e2");
        let delta = provider
            .changes_since(&token, "primary", Some(&first.cursor))
            .await
            .unwrap();
        let summary: Vec<(&str, bool)> = delta
            .changes
            .iter()
            .map(|change| (change.remote_id.as_str(), change.ics.is_some()))
            .collect();
        assert_eq!(summary, vec![("e1", true), ("e2", false)]);
        assert_ne!(delta.cursor, first.cursor);
        script.forget_history();
        let stale = provider
            .changes_since(&token, "primary", Some(&delta.cursor))
            .await
            .unwrap_err();
        assert_eq!(
            stale.kind,
            PortErrorKind::Invalid,
            "a stale cursor makes the caller start again"
        );
    }

    #[tokio::test]
    async fn the_snapshot_mode_lists_the_calendar_on_every_call() {
        let (provider, _clock) = provider();
        let script = provider.script();
        script.set_mode(Mode::Snapshot);
        let token = connect(&provider, "fake-anna").await.tokens.access_token;
        script.put_event("primary", "e1", "x");
        let first = provider.changes_since(&token, "primary", None).await.unwrap();
        let second = provider
            .changes_since(&token, "primary", Some(&first.cursor))
            .await
            .unwrap();
        assert!(first.snapshot && second.snapshot);
        assert_eq!(second.changes.len(), 1);
    }

    #[tokio::test]
    async fn unknown_calendars_bad_tokens_and_scripted_failures_are_errors() {
        let (provider, _clock) = provider();
        let script = provider.script();
        let token = connect(&provider, "fake-anna").await.tokens.access_token;
        let missing = provider.changes_since(&token, "elsewhere", None).await.unwrap_err();
        assert_eq!(missing.kind, PortErrorKind::Rejected);
        let bad = provider
            .changes_since(&SecretString::from("not-a-token"), "primary", None)
            .await
            .unwrap_err();
        assert_eq!(bad.kind, PortErrorKind::Rejected);
        script.fail_next(Call::Changes, PortError::unavailable("the provider is down"));
        let down = provider.changes_since(&token, "primary", None).await.unwrap_err();
        assert_eq!(down.kind, PortErrorKind::Unavailable);
        assert!(
            provider.changes_since(&token, "primary", None).await.is_ok(),
            "the failure was used up"
        );
    }

    #[tokio::test]
    async fn the_provider_is_pull_only() {
        let (provider, _clock) = provider();
        let token = SecretString::from("any");
        let change = RemoteChange {
            remote_id: "e".to_owned(),
            etag: None,
            ics: Some("x".to_owned()),
        };
        assert_eq!(
            provider.upsert(&token, "primary", &change).await.unwrap_err().kind,
            PortErrorKind::Unsupported
        );
        assert_eq!(
            provider.delete(&token, "primary", "e").await.unwrap_err().kind,
            PortErrorKind::Unsupported
        );
    }

    #[test]
    fn a_provider_says_what_it_is_and_whether_it_is_on() {
        let (provider, _clock) = provider();
        assert_eq!((provider.name(), provider.display_name()), ("fake", "Fake"));
        assert!(provider.enabled());
        assert!(!provider.clone().disabled().enabled());
        assert_eq!(provider.script().calls().len(), 0, "building a provider calls nothing");
    }
}
