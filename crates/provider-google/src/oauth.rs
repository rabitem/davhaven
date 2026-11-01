//! The `OAuthProvider` implementation (authorization code with PKCE).
//!
//! The flow is the one Google documents for web server applications, with the extras that make it safe here:
//!
//! * the consent URL asks for the single scope `calendar.readonly` (the sync engine only reads), `access_type=offline` and
//!   `prompt=consent`, so that Google issues a refresh token every time (without the prompt it issues one only to the first
//!   consent of a person, and a reconnect would then have none);
//! * the S256 PKCE challenge and the single-use `state` are the application's, the provider only places them;
//! * the code is exchanged at the token endpoint with the verifier, and the account is named by its primary calendar (its id
//!   is the e-mail address of the account), so the application learns who connected without the `email` scope;
//! * a missing refresh token is an error: an account that cannot be refreshed would stop synchronizing after an hour.
//!
//! Every request goes through the `HttpClient` port.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_ports::{Clock, HttpClient, OAuthGrant, OAuthProvider, OAuthTokens, PortError, PortLabel, observe};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

use crate::transport::{api_get, form_post, json, revoke_error, token_error};

/// What `observe` labels the calls with.
pub(crate) const LABEL: PortLabel = PortLabel::new("provider", crate::config::PLUGIN);

/// The consent page.
pub const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// The token endpoint.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// The revocation endpoint.
pub const REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
/// The calendar of the account itself, whose id is the account's e-mail address.
pub const PRIMARY_CALENDAR_URL: &str = "https://www.googleapis.com/calendar/v3/calendars/primary";
/// The one scope the provider asks for: read access to calendars and events.
pub const SCOPE: &str = "https://www.googleapis.com/auth/calendar.readonly";

/// The client of the OAuth application and the means to call Google with it.
pub struct GoogleOAuth {
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
}

impl core::fmt::Debug for GoogleOAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GoogleOAuth")
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl GoogleOAuth {
    /// The flow of the client `client_id` with `client_secret`. A provider that is switched off has neither, and every call
    /// that needs them is refused as `Invalid`.
    pub fn new(
        client_id: Option<String>,
        client_secret: Option<SecretString>,
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            http,
            clock,
        }
    }

    fn credentials(&self) -> Result<(&str, &SecretString), PortError> {
        match (&self.client_id, &self.client_secret) {
            (Some(id), Some(secret)) => Ok((id.as_str(), secret)),
            _ => Err(PortError::invalid("the Google provider has no client credentials")),
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct PrimaryCalendar {
    id: String,
}

impl GoogleOAuth {
    fn tokens(&self, response: TokenResponse) -> OAuthTokens {
        let lifetime = response
            .expires_in
            .filter(|seconds| *seconds > 0)
            .and_then(chrono::Duration::try_seconds);
        OAuthTokens {
            access_token: SecretString::from(response.access_token),
            refresh_token: response
                .refresh_token
                .filter(|token| !token.is_empty())
                .map(SecretString::from),
            expires_at: lifetime.and_then(|lifetime| self.clock.now().checked_add_signed(lifetime)),
            scope: response.scope,
        }
    }

    /// The account that `tokens` belong to: the e-mail address that names its primary calendar.
    ///
    /// # Errors
    ///
    /// `Rejected` when Google issued no refresh token (an account that cannot be renewed would stop after an hour), the errors
    /// of the lookup otherwise.
    async fn account_of(&self, tokens: &OAuthTokens) -> Result<String, PortError> {
        if tokens.refresh_token.is_none() {
            return Err(PortError::rejected(
                "Google issued no refresh token: remove the application's access in the Google account and connect again",
            ));
        }
        // The primary calendar is named by the e-mail address of the account.
        let primary_url = Url::parse(PRIMARY_CALENDAR_URL).map_err(|error| PortError::internal(error.to_string()))?;
        let primary = self.http.send(api_get(primary_url, &tokens.access_token)?).await?;
        if !primary.status.is_success() {
            return Err(crate::transport::api_error("account lookup", &primary));
        }
        let account = json::<PrimaryCalendar>(&primary)?;
        if account.id.trim().is_empty() {
            return Err(PortError::unavailable(
                "Google named no account for the primary calendar",
            ));
        }
        Ok(account.id)
    }
}

#[async_trait]
impl OAuthProvider for GoogleOAuth {
    fn authorize_url(&self, state: &str, pkce_challenge: &str, redirect: &Url) -> Result<Url, PortError> {
        let (client_id, _secret) = self.credentials()?;
        let mut url = Url::parse(AUTHORIZE_URL).map_err(|error| PortError::internal(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", SCOPE)
            .append_pair("state", state)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent");
        Ok(url)
    }

    async fn exchange(
        &self,
        code: &SecretString,
        verifier: &SecretString,
        redirect: &Url,
    ) -> Result<OAuthGrant, PortError> {
        observe(LABEL, "exchange", async {
            let (client_id, client_secret) = self.credentials()?;
            let token_url = Url::parse(TOKEN_URL).map_err(|error| PortError::internal(error.to_string()))?;
            let response = self
                .http
                .send(form_post(
                    &token_url,
                    &[
                        ("grant_type", "authorization_code"),
                        ("code", code.expose_secret()),
                        ("code_verifier", verifier.expose_secret()),
                        ("redirect_uri", redirect.as_str()),
                        ("client_id", client_id),
                        ("client_secret", client_secret.expose_secret()),
                    ],
                ))
                .await?;
            if !response.status.is_success() {
                return Err(token_error("code exchange", &response));
            }
            let tokens = self.tokens(json::<TokenResponse>(&response)?);
            match self.account_of(&tokens).await {
                Ok(account_ref) => Ok(OAuthGrant { tokens, account_ref }),
                Err(error) => {
                    // Google issued a grant that the connection cannot use. The caller never sees the tokens, so nobody else can
                    // give them back: they are revoked here, best effort, instead of staying at Google for a connection that
                    // did not come about.
                    let token = tokens.refresh_token.as_ref().unwrap_or(&tokens.access_token);
                    self.revoke(token).await.ok();
                    Err(error)
                }
            }
        })
        .await
    }

    async fn refresh(&self, refresh_token: &SecretString) -> Result<OAuthTokens, PortError> {
        observe(LABEL, "refresh", async {
            let (client_id, client_secret) = self.credentials()?;
            let token_url = Url::parse(TOKEN_URL).map_err(|error| PortError::internal(error.to_string()))?;
            let response = self
                .http
                .send(form_post(
                    &token_url,
                    &[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", refresh_token.expose_secret()),
                        ("client_id", client_id),
                        ("client_secret", client_secret.expose_secret()),
                    ],
                ))
                .await?;
            if !response.status.is_success() {
                return Err(token_error("token refresh", &response));
            }
            // Google keeps the refresh token: the answer has none, and the caller keeps the one it has.
            Ok(self.tokens(json::<TokenResponse>(&response)?))
        })
        .await
    }

    async fn revoke(&self, token: &SecretString) -> Result<(), PortError> {
        observe(LABEL, "revoke", async {
            let revoke_url = Url::parse(REVOKE_URL).map_err(|error| PortError::internal(error.to_string()))?;
            let response = self
                .http
                .send(form_post(&revoke_url, &[("token", token.expose_secret())]))
                .await?;
            if response.status.is_success() {
                Ok(())
            } else {
                Err(revoke_error(&response))
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use davhaven_ports::PortErrorKind;
    use davhaven_ports::testing::{ManualClock, ReplayHttp, ReplayRule};

    use super::*;

    fn flow(http: &ReplayHttp, clock: &ManualClock) -> GoogleOAuth {
        GoogleOAuth::new(
            Some("1234.apps.googleusercontent.com".to_owned()),
            Some(SecretString::from("client-secret")),
            Arc::new(http.clone()),
            Arc::new(clock.clone()),
        )
    }

    fn redirect() -> Url {
        Url::parse("https://cal.example.org/oauth/google/callback").unwrap()
    }

    const TOKENS: &str = r#"{"access_token":"ya29.a","expires_in":3599,"refresh_token":"1//r","scope":"https://www.googleapis.com/auth/calendar.readonly","token_type":"Bearer"}"#;

    #[test]
    fn the_consent_url_asks_for_read_access_offline_with_pkce() {
        let clock = ManualClock::default();
        let url = flow(&ReplayHttp::new(), &clock)
            .authorize_url("state-1", "challenge-1", &redirect())
            .unwrap();
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        for (name, value) in [
            ("client_id", "1234.apps.googleusercontent.com"),
            ("redirect_uri", "https://cal.example.org/oauth/google/callback"),
            ("response_type", "code"),
            ("scope", SCOPE),
            ("state", "state-1"),
            ("code_challenge", "challenge-1"),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ] {
            assert!(
                pairs.contains(&(name.to_owned(), value.to_owned())),
                "{name}: {pairs:?}"
            );
        }
        assert!(
            !url.as_str().contains("client-secret"),
            "the secret never travels in the URL"
        );
    }

    #[test]
    fn a_provider_without_credentials_refuses_to_start() {
        let clock = ManualClock::default();
        let oauth = GoogleOAuth::new(None, None, Arc::new(ReplayHttp::new()), Arc::new(clock));
        assert_eq!(
            oauth.authorize_url("s", "c", &redirect()).unwrap_err().kind,
            PortErrorKind::Invalid
        );
        assert!(!format!("{oauth:?}").contains("client-secret"));
    }

    #[tokio::test]
    async fn the_code_is_exchanged_with_the_verifier_and_the_account_is_named_by_its_primary_calendar() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::post(TOKEN_URL)
                    .body_contains("grant_type=authorization_code")
                    .answers(200, TOKENS),
            )
            .with(
                ReplayRule::get(PRIMARY_CALENDAR_URL)
                    .header("authorization", "Bearer ya29.a")
                    .answers(200, r#"{"id":"anna@example.org","summary":"anna@example.org"}"#),
            );
        let grant = flow(&http, &clock)
            .exchange(
                &SecretString::from("4/0AbC"),
                &SecretString::from("the-verifier"),
                &redirect(),
            )
            .await
            .unwrap();
        assert_eq!(grant.account_ref, "anna@example.org");
        assert_eq!(grant.tokens.access_token.expose_secret(), "ya29.a");
        assert_eq!(
            grant.tokens.refresh_token.as_ref().map(ExposeSecret::expose_secret),
            Some("1//r")
        );
        assert_eq!(grant.tokens.expires_at, Some(clock.now() + Duration::seconds(3599)));
        let sent = http.requests();
        assert_eq!(sent.len(), 2);
        for (name, value) in [
            ("code", "4/0AbC"),
            ("code_verifier", "the-verifier"),
            ("redirect_uri", "https://cal.example.org/oauth/google/callback"),
            ("client_id", "1234.apps.googleusercontent.com"),
            ("client_secret", "client-secret"),
        ] {
            assert_eq!(sent[0].form_value(name).as_deref(), Some(value), "{name}");
        }
        assert_eq!(http.unmatched(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_refused_code_is_rejected_and_a_missing_refresh_token_is_an_error() {
        let clock = ManualClock::default();
        let refused = ReplayHttp::new().with(
            ReplayRule::post(TOKEN_URL).answers(400, r#"{"error":"invalid_grant","error_description":"Bad Request"}"#),
        );
        let error = flow(&refused, &clock)
            .exchange(&SecretString::from("bad"), &SecretString::from("v"), &redirect())
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Rejected);
        assert!(error.message.contains("invalid_grant"), "{error}");

        let without_refresh = ReplayHttp::new()
            .with(ReplayRule::post(TOKEN_URL).answers(
                200,
                r#"{"access_token":"ya29.a","expires_in":3599,"token_type":"Bearer"}"#,
            ))
            .with(
                ReplayRule::post(REVOKE_URL)
                    .body_contains("token=ya29.a")
                    .answers(200, "{}"),
            );
        let error = flow(&without_refresh, &clock)
            .exchange(&SecretString::from("c"), &SecretString::from("v"), &redirect())
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Rejected);
        assert!(error.message.contains("no refresh token"), "{error}");
        assert_eq!(
            without_refresh.requests().len(),
            2,
            "the account is not even looked up, and the access that was granted is given back"
        );
        assert_eq!(without_refresh.unmatched(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_grant_that_cannot_be_used_is_given_back_at_once() {
        let clock = ManualClock::default();
        // Google issued tokens, and then the account cannot be looked up: nobody else will ever see these tokens.
        let http = ReplayHttp::new()
            .with(ReplayRule::post(TOKEN_URL).answers(200, TOKENS))
            .with(ReplayRule::get(PRIMARY_CALENDAR_URL).answers(503, "{}"))
            .with(
                ReplayRule::post(REVOKE_URL)
                    .body_contains("token=1%2F%2Fr")
                    .answers(200, "{}"),
            );
        let error = flow(&http, &clock)
            .exchange(&SecretString::from("c"), &SecretString::from("v"), &redirect())
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable, "{error}");
        assert_eq!(
            http.requests().len(),
            3,
            "token, account lookup, and the revocation of the refresh token"
        );
        assert_eq!(http.unmatched(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_primary_calendar_without_a_name_is_no_account_and_its_grant_is_given_back() {
        // The account reference keys the connection: a blank one would let two people's connections collide.
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(ReplayRule::post(TOKEN_URL).answers(200, TOKENS))
            .with(ReplayRule::get(PRIMARY_CALENDAR_URL).answers(200, r#"{"id":"  ","summary":"x"}"#))
            .with(
                ReplayRule::post(REVOKE_URL)
                    .body_contains("token=1%2F%2Fr")
                    .answers(200, "{}"),
            );
        let error = flow(&http, &clock)
            .exchange(&SecretString::from("c"), &SecretString::from("v"), &redirect())
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable, "{error}");
        assert!(error.message.contains("no account"), "{error}");
        assert_eq!(http.requests().len(), 3, "token, account lookup and revocation");
        assert_eq!(http.unmatched(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_refresh_token_and_a_revoked_one_is_rejected() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::post(TOKEN_URL)
                    .body_contains("refresh_token=1%2F%2Fr&client_id")
                    .answers(
                        200,
                        r#"{"access_token":"ya29.b","expires_in":3599,"token_type":"Bearer"}"#,
                    ),
            )
            .with(ReplayRule::post(TOKEN_URL).answers(400, r#"{"error":"invalid_grant"}"#));
        let oauth = flow(&http, &clock);
        let renewed = oauth.refresh(&SecretString::from("1//r")).await.unwrap();
        assert_eq!(renewed.access_token.expose_secret(), "ya29.b");
        assert!(
            renewed.refresh_token.is_none(),
            "the caller keeps the refresh token it has"
        );
        let error = oauth.refresh(&SecretString::from("1//revoked")).await.unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Rejected);
    }

    #[tokio::test]
    async fn revocation_posts_the_token_and_reports_a_refusal() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::post(REVOKE_URL)
                    .body_contains("token=1%2F%2Fr")
                    .answers(200, "{}"),
            )
            .with(ReplayRule::post(REVOKE_URL).answers(400, r#"{"error":"invalid_token"}"#));
        let oauth = flow(&http, &clock);
        oauth.revoke(&SecretString::from("1//r")).await.unwrap();
        let error = oauth.revoke(&SecretString::from("old")).await.unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Rejected);
    }

    #[tokio::test]
    async fn transport_failures_pass_through() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new().with(ReplayRule::post(TOKEN_URL).fails(PortError::timeout("slow")));
        let error = flow(&http, &clock)
            .refresh(&SecretString::from("1//r"))
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Timeout);
    }
}
