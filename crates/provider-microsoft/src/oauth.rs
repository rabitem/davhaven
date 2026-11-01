//! The `OAuthProvider` implementation (authorization code with PKCE).
//!
//! The flow is the one the Microsoft identity platform (v2.0) documents for web apps, with the extras that make it safe here:
//!
//! * the consent URL asks for `Calendars.Read` (the sync engine only reads), `User.Read` (to name the account) and
//!   `offline_access`, which is what makes the platform issue a refresh token; `prompt=select_account` lets the person choose
//!   which of the accounts they are signed in to is connected;
//! * the S256 PKCE challenge and the single-use `state` are the application's, the provider only places them;
//! * the code is exchanged at the token endpoint of the configured directory (`common`, `organizations`, `consumers` or one
//!   organisation) with the verifier, and the account is named by its mail address (its user principal name when it has no
//!   mail), read from `/me`;
//! * a refresh **replaces** the refresh token (Microsoft rotates them), so the answer carries the new one.
//!
//! The identity platform has no endpoint that revokes the refresh token of an app (a person removes the app at
//! `myapps.microsoft.com`), so [`revoke`](OAuthProvider::revoke) has nothing to call and succeeds without a request: the
//! application deletes the tokens it holds, which ends its own access.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_ports::{Clock, HttpClient, OAuthGrant, OAuthProvider, OAuthTokens, PortError, PortLabel, observe};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

use crate::transport::{form_post, graph_error, graph_get, json, token_error};

/// What `observe` labels the calls with.
pub(crate) const LABEL: PortLabel = PortLabel::new("provider", crate::config::PLUGIN);

/// The permissions the provider asks for: read access to calendars, the profile that names the account, and a refresh token.
pub const SCOPES: &str = "offline_access Calendars.Read User.Read";
/// The profile of the signed-in person.
pub const ME_URL: &str = "https://graph.microsoft.com/v1.0/me";

/// The consent page for `directory`.
pub fn authorize_endpoint(directory: &str) -> String {
    format!("https://login.microsoftonline.com/{directory}/oauth2/v2.0/authorize")
}

/// The token endpoint for `directory`.
pub fn token_endpoint(directory: &str) -> String {
    format!("https://login.microsoftonline.com/{directory}/oauth2/v2.0/token")
}

/// The client of the app registration and the means to call Microsoft with it.
pub struct MicrosoftOAuth {
    directory: String,
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
}

impl core::fmt::Debug for MicrosoftOAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MicrosoftOAuth")
            .field("directory", &self.directory)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl MicrosoftOAuth {
    /// The flow of the client `client_id` with `client_secret` in `directory` (already validated: letters, digits, `-` and
    /// `.`). A provider that is switched off has neither id nor secret, and every call that needs them is refused as
    /// `Invalid`.
    pub fn new(
        directory: String,
        client_id: Option<String>,
        client_secret: Option<SecretString>,
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            directory,
            client_id,
            client_secret,
            http,
            clock,
        }
    }

    /// The token endpoint of the configured directory.
    fn token_url(&self) -> Result<Url, PortError> {
        Url::parse(&token_endpoint(&self.directory)).map_err(|error| PortError::internal(error.to_string()))
    }

    fn credentials(&self) -> Result<(&str, &SecretString), PortError> {
        match (&self.client_id, &self.client_secret) {
            (Some(id), Some(secret)) => Ok((id.as_str(), secret)),
            _ => Err(PortError::invalid("the Microsoft provider has no client credentials")),
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
struct Profile {
    id: Option<String>,
    mail: Option<String>,
    #[serde(rename = "userPrincipalName")]
    user_principal_name: Option<String>,
}

impl MicrosoftOAuth {
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
}

#[async_trait]
impl OAuthProvider for MicrosoftOAuth {
    fn authorize_url(&self, state: &str, pkce_challenge: &str, redirect: &Url) -> Result<Url, PortError> {
        let (client_id, _secret) = self.credentials()?;
        let mut url =
            Url::parse(&authorize_endpoint(&self.directory)).map_err(|error| PortError::internal(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect.as_str())
            .append_pair("response_mode", "query")
            .append_pair("scope", SCOPES)
            .append_pair("state", state)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account");
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
            let response = self
                .http
                .send(form_post(
                    &self.token_url()?,
                    &[
                        ("grant_type", "authorization_code"),
                        ("code", code.expose_secret()),
                        ("code_verifier", verifier.expose_secret()),
                        ("redirect_uri", redirect.as_str()),
                        ("scope", SCOPES),
                        ("client_id", client_id),
                        ("client_secret", client_secret.expose_secret()),
                    ],
                ))
                .await?;
            if !response.status.is_success() {
                return Err(token_error("code exchange", &response));
            }
            let tokens = self.tokens(json::<TokenResponse>(&response)?);
            if tokens.refresh_token.is_none() {
                return Err(PortError::rejected(
                    "Microsoft issued no refresh token: the app registration must allow `offline_access`",
                ));
            }
            let mut me = Url::parse(ME_URL).map_err(|error| PortError::internal(error.to_string()))?;
            me.set_query(Some("$select=id,mail,userPrincipalName"));
            let profile = self.http.send(graph_get(me, &tokens.access_token)?).await?;
            if !profile.status.is_success() {
                return Err(graph_error("account lookup", &profile));
            }
            let profile = json::<Profile>(&profile)?;
            let account_ref = [profile.mail, profile.user_principal_name, profile.id]
                .into_iter()
                .flatten()
                .find(|name| !name.trim().is_empty())
                .ok_or_else(|| PortError::unavailable("Microsoft named no account for the signed-in person"))?;
            Ok(OAuthGrant { tokens, account_ref })
        })
        .await
    }

    async fn refresh(&self, refresh_token: &SecretString) -> Result<OAuthTokens, PortError> {
        observe(LABEL, "refresh", async {
            let (client_id, client_secret) = self.credentials()?;
            let response = self
                .http
                .send(form_post(
                    &self.token_url()?,
                    &[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", refresh_token.expose_secret()),
                        ("scope", SCOPES),
                        ("client_id", client_id),
                        ("client_secret", client_secret.expose_secret()),
                    ],
                ))
                .await?;
            if !response.status.is_success() {
                return Err(token_error("token refresh", &response));
            }
            Ok(self.tokens(json::<TokenResponse>(&response)?))
        })
        .await
    }

    async fn revoke(&self, _token: &SecretString) -> Result<(), PortError> {
        // There is no endpoint to call (see the module documentation).
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use davhaven_ports::PortErrorKind;
    use davhaven_ports::testing::{ManualClock, ReplayHttp, ReplayRule};

    use super::*;

    fn flow(http: &ReplayHttp, clock: &ManualClock, directory: &str) -> MicrosoftOAuth {
        MicrosoftOAuth::new(
            directory.to_owned(),
            Some("11111111-2222-3333-4444-555555555555".to_owned()),
            Some(SecretString::from("client-secret")),
            Arc::new(http.clone()),
            Arc::new(clock.clone()),
        )
    }

    fn redirect() -> Url {
        Url::parse("https://cal.example.org/oauth/microsoft/callback").unwrap()
    }

    const TOKENS: &str = r#"{"token_type":"Bearer","scope":"Calendars.Read User.Read","expires_in":3599,"ext_expires_in":3599,"access_token":"EwB.a","refresh_token":"M.R3_BAY.r1"}"#;

    #[test]
    fn the_consent_url_is_the_one_of_the_directory_and_asks_for_read_access_offline_with_pkce() {
        let clock = ManualClock::default();
        for directory in ["common", "contoso.onmicrosoft.com"] {
            let url = flow(&ReplayHttp::new(), &clock, directory)
                .authorize_url("state-1", "challenge-1", &redirect())
                .unwrap();
            assert_eq!(url.host_str(), Some("login.microsoftonline.com"));
            assert_eq!(url.path(), format!("/{directory}/oauth2/v2.0/authorize"));
            let pairs: Vec<(String, String)> = url
                .query_pairs()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect();
            for (name, value) in [
                ("client_id", "11111111-2222-3333-4444-555555555555"),
                ("response_type", "code"),
                ("redirect_uri", "https://cal.example.org/oauth/microsoft/callback"),
                ("response_mode", "query"),
                ("scope", SCOPES),
                ("state", "state-1"),
                ("code_challenge", "challenge-1"),
                ("code_challenge_method", "S256"),
            ] {
                assert!(
                    pairs.contains(&(name.to_owned(), value.to_owned())),
                    "{name}: {pairs:?}"
                );
            }
            assert!(!url.as_str().contains("client-secret"));
        }
    }

    #[test]
    fn a_provider_without_credentials_refuses_to_start() {
        let clock = ManualClock::default();
        let oauth = MicrosoftOAuth::new(
            "common".to_owned(),
            None,
            None,
            Arc::new(ReplayHttp::new()),
            Arc::new(clock),
        );
        assert_eq!(
            oauth.authorize_url("s", "c", &redirect()).unwrap_err().kind,
            PortErrorKind::Invalid
        );
        assert!(!format!("{oauth:?}").contains("client-secret"));
    }

    #[tokio::test]
    async fn the_code_is_exchanged_with_the_verifier_and_the_account_is_named_by_its_mail_address() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::post(&token_endpoint("common"))
                    .body_contains("grant_type=authorization_code")
                    .answers(200, TOKENS),
            )
            .with(ReplayRule::get(ME_URL).header("authorization", "Bearer EwB.a").answers(
                200,
                r#"{"id":"00000000-0000-0000-0000-000000000001","mail":null,"userPrincipalName":"anna@contoso.com"}"#,
            ));
        let grant = flow(&http, &clock, "common")
            .exchange(
                &SecretString::from("0.AXQ.code"),
                &SecretString::from("the-verifier"),
                &redirect(),
            )
            .await
            .unwrap();
        assert_eq!(
            grant.account_ref, "anna@contoso.com",
            "no mail: the user principal name"
        );
        assert_eq!(
            grant.tokens.refresh_token.as_ref().map(ExposeSecret::expose_secret),
            Some("M.R3_BAY.r1")
        );
        assert_eq!(grant.tokens.expires_at, Some(clock.now() + Duration::seconds(3599)));
        let sent = http.requests();
        for (name, value) in [
            ("code", "0.AXQ.code"),
            ("code_verifier", "the-verifier"),
            ("client_secret", "client-secret"),
            ("scope", SCOPES),
        ] {
            assert_eq!(sent[0].form_value(name).as_deref(), Some(value), "{name}");
        }
        assert_eq!(
            sent[1].query_value("$select").as_deref(),
            Some("id,mail,userPrincipalName")
        );
        assert_eq!(http.unmatched(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn the_account_falls_back_to_its_id_and_a_refused_code_is_rejected() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::post(&token_endpoint("common"))
                    .body_contains("code=good")
                    .answers(200, TOKENS),
            )
            .with(
                ReplayRule::post(&token_endpoint("common"))
                    .answers(400, r#"{"error":"invalid_grant","error_codes":[70008]}"#),
            )
            .with(ReplayRule::get(ME_URL).answers(200, r#"{"id":"0000-id","mail":" ","userPrincipalName":null}"#));
        let oauth = flow(&http, &clock, "common");
        let grant = oauth
            .exchange(&SecretString::from("good"), &SecretString::from("v"), &redirect())
            .await
            .unwrap();
        assert_eq!(grant.account_ref, "0000-id");
        let error = oauth
            .exchange(&SecretString::from("stale"), &SecretString::from("v"), &redirect())
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Rejected);
        assert!(error.message.contains("invalid_grant"), "{error}");
    }

    #[tokio::test]
    async fn a_profile_without_any_name_is_no_account_and_a_failed_lookup_is_the_graphs_error() {
        // The account reference keys the connection: a blank one would let two people's connections collide.
        let clock = ManualClock::default();
        let nameless = ReplayHttp::new()
            .with(ReplayRule::post(&token_endpoint("common")).answers(200, TOKENS))
            .with(ReplayRule::get(ME_URL).answers(200, r#"{"id":"  ","mail":"","userPrincipalName":null}"#));
        let error = flow(&nameless, &clock, "common")
            .exchange(&SecretString::from("c"), &SecretString::from("v"), &redirect())
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable, "{error}");
        assert!(error.message.contains("no account"), "{error}");

        let unavailable = ReplayHttp::new()
            .with(ReplayRule::post(&token_endpoint("common")).answers(200, TOKENS))
            .with(ReplayRule::get(ME_URL).answers(503, "{}"));
        let error = flow(&unavailable, &clock, "common")
            .exchange(&SecretString::from("c"), &SecretString::from("v"), &redirect())
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable, "{error}");
        assert!(!error.message.contains("EwB"), "no token in the error: {error}");
    }

    #[tokio::test]
    async fn a_missing_refresh_token_is_an_error() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new().with(ReplayRule::post(&token_endpoint("common")).answers(
            200,
            r#"{"access_token":"EwB.a","expires_in":3599,"token_type":"Bearer"}"#,
        ));
        let error = flow(&http, &clock, "common")
            .exchange(&SecretString::from("c"), &SecretString::from("v"), &redirect())
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Rejected);
        assert!(error.message.contains("offline_access"), "{error}");
        assert_eq!(http.requests().len(), 1);
    }

    #[tokio::test]
    async fn a_refresh_returns_the_rotated_refresh_token_and_a_revoked_one_is_rejected() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::post(&token_endpoint("organizations"))
                    .body_contains("refresh_token=M.R3_BAY.r1&")
                    .answers(
                        200,
                        r#"{"token_type":"Bearer","expires_in":3599,"access_token":"EwB.b","refresh_token":"M.R3_BAY.r2"}"#,
                    ),
            )
            .with(ReplayRule::post(&token_endpoint("organizations")).answers(400, r#"{"error":"invalid_grant"}"#));
        let oauth = flow(&http, &clock, "organizations");
        let renewed = oauth.refresh(&SecretString::from("M.R3_BAY.r1")).await.unwrap();
        assert_eq!(renewed.access_token.expose_secret(), "EwB.b");
        assert_eq!(
            renewed.refresh_token.as_ref().map(ExposeSecret::expose_secret),
            Some("M.R3_BAY.r2")
        );
        let error = oauth
            .refresh(&SecretString::from("M.R3_BAY.revoked"))
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Rejected);
    }

    #[tokio::test]
    async fn revoking_needs_no_request() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new();
        flow(&http, &clock, "common")
            .revoke(&SecretString::from("M.R3_BAY.r1"))
            .await
            .unwrap();
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn transport_failures_pass_through() {
        let clock = ManualClock::default();
        let http =
            ReplayHttp::new().with(ReplayRule::post(&token_endpoint("common")).fails(PortError::timeout("slow")));
        let error = flow(&http, &clock, "common")
            .refresh(&SecretString::from("r"))
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Timeout);
    }
}
