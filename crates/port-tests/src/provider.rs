//! Contract suite of the `Provider` port.
//!
//! What every calendar provider promises, whatever it talks to: the consent URL carries the state, the challenge and the
//! redirect; a good code is exchanged for tokens and a refused one is `Rejected`; a refresh token that was revoked is
//! `Rejected`, and a client the provider refuses (a wrong or expired client secret) is `Invalid`, never `Rejected`, because
//! only a revoked refresh token switches an account off; the calendars of the account come with exactly one primary
//! calendar; the events of a calendar come as
//! iCalendar text that is a well-formed, CRLF-terminated calendar object; an answer without a cursor is the whole calendar
//! (a snapshot); and the push direction is `Unsupported`.
//!
//! A provider needs a remote to answer, so the suite does not build the provider alone: the factory returns a [`Scenario`],
//! **the world the provider is run in**. The fake provider fills it from its script; the adapters of Google and Microsoft
//! fill it with a replay of recorded HTTP exchanges (`davhaven_ports::testing::ReplayHttp`). The scenario says which code,
//! tokens and calendar that world knows and what it holds; the suite asserts what the provider makes of them.

use std::collections::BTreeSet;
use std::sync::Arc;

use davhaven_ports::{PortErrorKind, Provider, RemoteChange};
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::suite::{Checks, ContractReport, Suite};

/// The world a provider is run in, and what the suite expects of it.
pub struct Scenario {
    /// The provider under test, wired to the remote the scenario describes.
    pub provider: Arc<dyn Provider>,
    /// The callback URL passed to the provider.
    pub redirect: Url,
    /// A code that the remote accepts, with the verifier it was issued for.
    pub good_code: SecretString,
    /// The PKCE verifier of `good_code`.
    pub verifier: SecretString,
    /// A code that the remote refuses.
    pub bad_code: SecretString,
    /// The reference the remote gives the account that `good_code` signs in.
    pub account_ref: String,
    /// A refresh token that the remote accepts.
    pub good_refresh_token: SecretString,
    /// A refresh token that the remote refuses (the person removed the access).
    pub revoked_refresh_token: SecretString,
    /// An access token that the calendar API accepts.
    pub access_token: SecretString,
    /// An access token that the calendar API refuses.
    pub bad_access_token: SecretString,
    /// The remote id of the primary calendar.
    pub calendar: String,
    /// The remote ids of the events the primary calendar holds.
    pub event_ids: Vec<String>,
    /// A cursor that the provider no longer accepts, for a provider with a change feed; `None` for one that lists the
    /// calendar on every call.
    pub stale_cursor: Option<String>,
    /// The same provider talking to a remote that refuses its **client** (a wrong, rotated or expired client secret), for
    /// every token request; `None` for a world that cannot play that.
    pub refused_client: Option<Arc<dyn Provider>>,
}

/// The id the suite asks for to find out that a calendar that does not exist is refused.
pub const MISSING_CALENDAR: &str = "no-such-calendar";

fn is_calendar_object(ics: &str) -> bool {
    ics.starts_with("BEGIN:VCALENDAR\r\n")
        && ics.ends_with("END:VCALENDAR\r\n")
        && ics.contains("\r\nBEGIN:VEVENT\r\n")
        && !ics.replace("\r\n", "").contains('\n')
}

/// Runs the suite against the scenarios `factory` builds and returns the report.
#[expect(clippy::too_many_lines, reason = "one case after the other, like every suite")]
pub async fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Scenario,
{
    let mut suite = Suite::new("provider");

    let scenario = factory();
    let provider = &scenario.provider;
    let mut checks = Checks::new("the provider names itself");
    let name = provider.name();
    checks.that(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "the name is a short lowercase word (it is used in URLs and configuration)",
    );
    checks.that(!provider.display_name().is_empty(), "the display name is not empty");
    checks.equal(&factory().provider.name(), &name, "the name of another instance");
    suite.record(checks);

    let mut checks = Checks::new("the consent URL carries the state, the challenge and the redirect");
    let state = "state-0123456789";
    let challenge = "challenge-abcdefghijklmnopqrstuvwxyz0123456789ABC";
    if let Some(url) = checks.ok(
        provider.oauth().authorize_url(state, challenge, &scenario.redirect),
        "authorize_url",
    ) {
        checks.equal(&url.scheme(), &"https", "the consent page is served over https");
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let has = |name: &str, value: &str| pairs.iter().any(|(n, v)| n == name && v == value);
        checks.that(has("state", state), "the state is a query parameter");
        checks.that(
            has("code_challenge", challenge),
            "the code challenge is a query parameter",
        );
        checks.that(has("code_challenge_method", "S256"), "the challenge method is S256");
        checks.that(
            has("redirect_uri", scenario.redirect.as_str()),
            "the redirect is a query parameter",
        );
        checks.that(has("response_type", "code"), "the response type is code");
        checks.that(
            !url.as_str().contains("client_secret"),
            "the client secret never travels in the consent URL",
        );
    }
    suite.record(checks);

    let scenario = factory();
    let mut checks = Checks::new("a good code is exchanged for tokens");
    if let Some(grant) = checks.ok(
        scenario
            .provider
            .oauth()
            .exchange(&scenario.good_code, &scenario.verifier, &scenario.redirect)
            .await,
        "exchange of a good code",
    ) {
        checks.that(
            !grant.tokens.access_token.expose_secret().is_empty(),
            "the access token is not empty",
        );
        checks.that(grant.tokens.refresh_token.is_some(), "a refresh token is issued");
        checks.equal(
            &grant.account_ref,
            &scenario.account_ref,
            "the reference of the account",
        );
    }
    suite.record(checks);

    let scenario = factory();
    let mut checks = Checks::new("a refused code is rejected");
    if let Some(error) = checks.err(
        scenario
            .provider
            .oauth()
            .exchange(&scenario.bad_code, &scenario.verifier, &scenario.redirect)
            .await,
        "exchange of a refused code",
    ) {
        checks.equal(&error.kind, &PortErrorKind::Rejected, "the kind of the error");
    }
    suite.record(checks);

    let scenario = factory();
    let mut checks = Checks::new("a refresh token gives a new access token and a revoked one is rejected");
    if let Some(tokens) = checks.ok(
        scenario.provider.oauth().refresh(&scenario.good_refresh_token).await,
        "refresh with a good token",
    ) {
        checks.that(
            !tokens.access_token.expose_secret().is_empty(),
            "the new access token is not empty",
        );
    }
    if let Some(error) = checks.err(
        scenario.provider.oauth().refresh(&scenario.revoked_refresh_token).await,
        "refresh with a revoked token",
    ) {
        checks.equal(&error.kind, &PortErrorKind::Rejected, "the kind of the error");
    }
    suite.record(checks);

    if let Some(refused) = factory().refused_client {
        let scenario = factory();
        let mut checks = Checks::new("a client the provider refuses is not a revoked refresh token");
        if let Some(error) = checks.err(
            refused.oauth().refresh(&scenario.good_refresh_token).await,
            "refresh at a provider that refuses the client",
        ) {
            checks.equal(
                &error.kind,
                &PortErrorKind::Invalid,
                "the kind of the error of refresh (a fault of the deployment: the accounts stay on)",
            );
        }
        if let Some(error) = checks.err(
            refused
                .oauth()
                .exchange(&scenario.good_code, &scenario.verifier, &scenario.redirect)
                .await,
            "exchange at a provider that refuses the client",
        ) {
            checks.equal(
                &error.kind,
                &PortErrorKind::Invalid,
                "the kind of the error of exchange",
            );
        }
        suite.record(checks);
    }

    let scenario = factory();
    let mut checks = Checks::new("a token can be revoked");
    checks.ok(
        scenario.provider.oauth().revoke(&scenario.access_token).await,
        "revoke the access token",
    );
    suite.record(checks);

    let scenario = factory();
    let api = scenario.provider.calendars();
    let mut checks = Checks::new("the calendars of the account have exactly one primary calendar");
    if let Some(calendars) = checks.ok(api.list_calendars(&scenario.access_token).await, "list_calendars") {
        checks.that(!calendars.is_empty(), "the account has a calendar");
        let ids: BTreeSet<&str> = calendars.iter().map(|calendar| calendar.remote_id.as_str()).collect();
        checks.equal(&ids.len(), &calendars.len(), "the ids of the calendars are distinct");
        checks.that(
            calendars
                .iter()
                .all(|calendar| !calendar.remote_id.is_empty() && !calendar.display_name.is_empty()),
            "every calendar has an id and a name",
        );
        checks.that(
            calendars.iter().all(|calendar| {
                calendar.color.as_deref().is_none_or(|color| {
                    color.len() == 7 && color.starts_with('#') && color.chars().skip(1).all(|c| c.is_ascii_hexdigit())
                })
            }),
            "a color is #RRGGBB",
        );
        let primary: Vec<&str> = calendars
            .iter()
            .filter(|calendar| calendar.primary)
            .map(|calendar| calendar.remote_id.as_str())
            .collect();
        checks.equal(&primary, &vec![scenario.calendar.as_str()], "the one primary calendar");
    }
    if let Some(error) = checks.err(
        api.list_calendars(&scenario.bad_access_token).await,
        "list_calendars with a bad token",
    ) {
        checks.equal(&error.kind, &PortErrorKind::Rejected, "the kind of the error");
    }
    suite.record(checks);

    let scenario = factory();
    let api = scenario.provider.calendars();
    let mut checks =
        Checks::new("the events of a calendar are calendar objects and an answer without a cursor is a snapshot");
    if let Some(first) = checks.ok(
        api.changes_since(&scenario.access_token, &scenario.calendar, None)
            .await,
        "changes_since without a cursor",
    ) {
        checks.that(first.snapshot, "without a cursor the answer is the whole calendar");
        checks.that(!first.cursor.is_empty(), "a cursor comes back");
        let ids: BTreeSet<&str> = first.changes.iter().map(|change| change.remote_id.as_str()).collect();
        let expected: BTreeSet<&str> = scenario.event_ids.iter().map(String::as_str).collect();
        checks.equal(&ids, &expected, "the events of the calendar");
        for change in &first.changes {
            checks.that(
                change.ics.as_deref().is_some_and(is_calendar_object),
                "the iCalendar text of an event is a CRLF calendar object with an event",
            );
        }
        if let Some(second) = checks.ok(
            api.changes_since(&scenario.access_token, &scenario.calendar, Some(&first.cursor))
                .await,
            "changes_since with the cursor",
        ) {
            if second.snapshot {
                let again: BTreeSet<&str> = second.changes.iter().map(|change| change.remote_id.as_str()).collect();
                checks.equal(&again, &expected, "a snapshot lists the same events again");
            } else {
                checks.that(second.changes.is_empty(), "a delta of an unchanged calendar is empty");
            }
        }
    }
    if let Some(error) = checks.err(
        api.changes_since(&scenario.bad_access_token, &scenario.calendar, None)
            .await,
        "changes_since with a bad token",
    ) {
        checks.equal(&error.kind, &PortErrorKind::Rejected, "the kind of the error");
    }
    suite.record(checks);

    let scenario = factory();
    let api = scenario.provider.calendars();
    let mut checks = Checks::new("a calendar that does not exist is rejected");
    if let Some(error) = checks.err(
        api.changes_since(&scenario.access_token, MISSING_CALENDAR, None).await,
        "changes_since of a missing calendar",
    ) {
        checks.equal(&error.kind, &PortErrorKind::Rejected, "the kind of the error");
    }
    suite.record(checks);

    if factory().stale_cursor.is_some() {
        let scenario = factory();
        let api = scenario.provider.calendars();
        let mut checks = Checks::new("a cursor that is stale is invalid, which makes the caller start again");
        if let Some(stale) = scenario.stale_cursor.as_deref()
            && let Some(error) = checks.err(
                api.changes_since(&scenario.access_token, &scenario.calendar, Some(stale))
                    .await,
                "changes_since with a stale cursor",
            )
        {
            checks.equal(&error.kind, &PortErrorKind::Invalid, "the kind of the error");
        }
        suite.record(checks);
    }

    let scenario = factory();
    let api = scenario.provider.calendars();
    let mut checks = Checks::new("the push direction is not supported");
    let change = RemoteChange {
        remote_id: "pushed".to_owned(),
        etag: None,
        ics: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned()),
    };
    if let Some(error) = checks.err(
        api.upsert(&scenario.access_token, &scenario.calendar, &change).await,
        "upsert",
    ) {
        checks.equal(
            &error.kind,
            &PortErrorKind::Unsupported,
            "the kind of the error of upsert",
        );
    }
    if let Some(error) = checks.err(
        api.delete(&scenario.access_token, &scenario.calendar, "pushed").await,
        "delete",
    ) {
        checks.equal(
            &error.kind,
            &PortErrorKind::Unsupported,
            "the kind of the error of delete",
        );
    }
    suite.record(checks);

    suite.finish()
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_all<F>(factory: F)
where
    F: Fn() -> Scenario,
{
    run(factory).await.assert_ok();
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_ports::{
        OAuthGrant, OAuthProvider, OAuthTokens, PortError, RemoteCalendar, RemoteCalendarApi, RemoteChanges,
    };

    use super::*;

    /// A provider that keeps the contract, over a world of one calendar with two events, unless it has a flaw.
    #[derive(Clone, Copy, Default)]
    struct Model {
        flaw: Option<Flaw>,
        /// Its client is refused by the remote: every token request fails.
        refused: bool,
    }

    /// What a provider can get wrong.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Flaw {
        /// The consent URL leaves the state out.
        NoState,
        /// The exchange accepts any code.
        AnyCode,
        /// The calendar list has no primary calendar.
        NoPrimary,
        /// An event is not CRLF.
        BareLineFeeds,
        /// The provider pushes.
        Pushes,
        /// A refused client is reported like a revoked refresh token.
        RefusedClientIsRevoked,
    }

    const GOOD_CODE: &str = "good-code";
    const ACCESS: &str = "access-1";
    const REFRESH: &str = "refresh-1";

    impl Provider for Model {
        fn name(&self) -> &'static str {
            "model"
        }

        fn oauth(&self) -> &dyn OAuthProvider {
            self
        }

        fn calendars(&self) -> &dyn RemoteCalendarApi {
            self
        }
    }

    impl Model {
        /// What the provider answers when its client is refused.
        fn client_error(self) -> PortError {
            if self.flaw == Some(Flaw::RefusedClientIsRevoked) {
                PortError::rejected("client refused")
            } else {
                PortError::invalid("client refused")
            }
        }
    }

    #[async_trait]
    impl OAuthProvider for Model {
        fn authorize_url(&self, state: &str, challenge: &str, redirect: &Url) -> Result<Url, PortError> {
            let mut url = Url::parse("https://consent.example/auth").unwrap();
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("response_type", "code")
                    .append_pair("code_challenge", challenge)
                    .append_pair("code_challenge_method", "S256")
                    .append_pair("redirect_uri", redirect.as_str());
                if self.flaw != Some(Flaw::NoState) {
                    query.append_pair("state", state);
                }
            }
            Ok(url)
        }

        async fn exchange(
            &self,
            code: &SecretString,
            _verifier: &SecretString,
            _redirect: &Url,
        ) -> Result<OAuthGrant, PortError> {
            if self.refused {
                return Err(self.client_error());
            }
            if code.expose_secret() != GOOD_CODE && self.flaw != Some(Flaw::AnyCode) {
                return Err(PortError::rejected("refused"));
            }
            Ok(OAuthGrant {
                tokens: OAuthTokens {
                    access_token: SecretString::from(ACCESS),
                    refresh_token: Some(SecretString::from(REFRESH)),
                    expires_at: None,
                    scope: None,
                },
                account_ref: "anna@example.org".to_owned(),
            })
        }

        async fn refresh(&self, refresh_token: &SecretString) -> Result<OAuthTokens, PortError> {
            if self.refused {
                return Err(self.client_error());
            }
            if refresh_token.expose_secret() == REFRESH {
                Ok(OAuthTokens {
                    access_token: SecretString::from("access-2"),
                    refresh_token: None,
                    expires_at: None,
                    scope: None,
                })
            } else {
                Err(PortError::rejected("revoked"))
            }
        }

        async fn revoke(&self, _token: &SecretString) -> Result<(), PortError> {
            Ok(())
        }
    }

    fn event(uid: &str, newline: &str) -> String {
        [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "BEGIN:VEVENT",
            &format!("UID:{uid}"),
            "DTSTART:20270105T090000Z",
            "END:VEVENT",
            "END:VCALENDAR",
            "",
        ]
        .join(newline)
    }

    #[async_trait]
    impl RemoteCalendarApi for Model {
        async fn list_calendars(&self, token: &SecretString) -> Result<Vec<RemoteCalendar>, PortError> {
            if token.expose_secret() != ACCESS {
                return Err(PortError::rejected("bad token"));
            }
            let mut calendar = RemoteCalendar::new("cal-1", "Anna").with_color("#336699");
            if self.flaw != Some(Flaw::NoPrimary) {
                calendar = calendar.primary();
            }
            Ok(vec![calendar])
        }

        async fn changes_since(
            &self,
            token: &SecretString,
            calendar: &str,
            cursor: Option<&str>,
        ) -> Result<RemoteChanges, PortError> {
            if token.expose_secret() != ACCESS || calendar != "cal-1" {
                return Err(PortError::rejected("bad token or calendar"));
            }
            if cursor == Some("stale") {
                return Err(PortError::invalid("stale"));
            }
            let newline = if self.flaw == Some(Flaw::BareLineFeeds) {
                "\n"
            } else {
                "\r\n"
            };
            let changes = ["e1", "e2"]
                .into_iter()
                .map(|id| RemoteChange {
                    remote_id: id.to_owned(),
                    etag: None,
                    ics: Some(event(id, newline)),
                })
                .collect();
            Ok(match cursor {
                None => RemoteChanges::snapshot(changes, "c1"),
                Some(_) => RemoteChanges::delta(Vec::new(), "c2"),
            })
        }

        async fn upsert(
            &self,
            _token: &SecretString,
            _calendar: &str,
            change: &RemoteChange,
        ) -> Result<RemoteChange, PortError> {
            if self.flaw == Some(Flaw::Pushes) {
                Ok(change.clone())
            } else {
                Err(PortError::unsupported())
            }
        }
    }

    fn scenario(model: Model) -> Scenario {
        Scenario {
            provider: Arc::new(model),
            redirect: Url::parse("https://cal.example.org/oauth/model/callback").unwrap(),
            good_code: SecretString::from(GOOD_CODE),
            verifier: SecretString::from("verifier"),
            bad_code: SecretString::from("bad-code"),
            account_ref: "anna@example.org".to_owned(),
            good_refresh_token: SecretString::from(REFRESH),
            revoked_refresh_token: SecretString::from("revoked"),
            access_token: SecretString::from(ACCESS),
            bad_access_token: SecretString::from("bad"),
            calendar: "cal-1".to_owned(),
            event_ids: vec!["e1".to_owned(), "e2".to_owned()],
            stale_cursor: Some("stale".to_owned()),
            refused_client: Some(Arc::new(Model { refused: true, ..model })),
        }
    }

    #[tokio::test]
    async fn a_provider_that_keeps_the_contract_passes_every_case() {
        let report = run(|| scenario(Model::default())).await;
        report.assert_ok();
        assert_eq!(report.case_count(), 12, "{report}");
        run_all(|| scenario(Model::default())).await;
    }

    #[tokio::test]
    async fn the_cases_of_a_stale_cursor_are_left_out_for_a_provider_without_a_change_feed() {
        let report = run(|| Scenario {
            stale_cursor: None,
            ..scenario(Model::default())
        })
        .await;
        report.assert_ok();
        assert_eq!(report.case_count(), 11);
    }

    #[tokio::test]
    async fn broken_providers_are_caught_case_by_case() {
        for (flaw, case) in [
            (
                Flaw::NoState,
                "the consent URL carries the state, the challenge and the redirect",
            ),
            (Flaw::AnyCode, "a refused code is rejected"),
            (
                Flaw::NoPrimary,
                "the calendars of the account have exactly one primary calendar",
            ),
            (
                Flaw::BareLineFeeds,
                "the events of a calendar are calendar objects and an answer without a cursor is a snapshot",
            ),
            (Flaw::Pushes, "the push direction is not supported"),
            (
                Flaw::RefusedClientIsRevoked,
                "a client the provider refuses is not a revoked refresh token",
            ),
        ] {
            let report = run(|| {
                scenario(Model {
                    flaw: Some(flaw),
                    ..Model::default()
                })
            })
            .await;
            assert_eq!(report.failed_cases(), vec![case], "{report}");
        }
    }

    #[test]
    fn calendar_objects_are_recognized() {
        assert!(is_calendar_object(&event("u", "\r\n")));
        assert!(!is_calendar_object(&event("u", "\n")));
        assert!(!is_calendar_object("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"));
        assert!(!is_calendar_object(""));
    }
}
