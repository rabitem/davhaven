//! The Microsoft provider against recorded exchanges: the contract suite of the `Provider` port, and what the provider makes of
//! the events of an account.
//!
//! The exchanges are in `tests/fixtures`: the answers of the Microsoft identity platform and of Microsoft Graph as their
//! documentation describes them (no real app registration exists for these tests). `ReplayHttp` plays Microsoft: it answers by
//! method, URL, query and the `Authorization` header, so a provider that sends the wrong token, the wrong page or the wrong form is
//! refused the way Microsoft refuses it.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use davhaven_port_tests::provider::{Scenario, run_all};
use davhaven_ports::testing::{ManualClock, ReplayHttp, ReplayRule};
use davhaven_ports::{PortErrorKind, Provider};
use davhaven_provider_microsoft::config::MicrosoftConfig;
use davhaven_provider_microsoft::provider::MicrosoftProvider;
use secrecy::SecretString;
use url::Url;

const TOKEN: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const ME: &str = "https://graph.microsoft.com/v1.0/me";
const CALENDARS: &str = "https://graph.microsoft.com/v1.0/me/calendars";
const VIEW: &str = "https://graph.microsoft.com/v1.0/me/calendars/AAMkADDEFAULT=/calendarView";
const MISSING_VIEW: &str = "https://graph.microsoft.com/v1.0/me/calendars/no-such-calendar/calendarView";

const ACCESS: &str = "EwBwA8l6BAAUfixture-access-token";
const REFRESH: &str = "M.R3_BAY.-CfixtureRefreshToken1";
const BEARER: &str = "Bearer EwBwA8l6BAAUfixture-access-token";

/// Microsoft as the fixtures record it: the good code, the good tokens and one account with a calendar of events.
fn microsoft() -> ReplayHttp {
    ReplayHttp::new()
        .with(
            ReplayRule::post(TOKEN)
                .body_contains("code=0.AXQfixtureGood&")
                .answers(200, include_str!("fixtures/token_exchange.json")),
        )
        .with(
            ReplayRule::post(TOKEN)
                .body_contains("grant_type=refresh_token")
                .body_contains("refresh_token=M.R3_BAY.-CfixtureRefreshToken1&")
                .answers(200, include_str!("fixtures/token_refresh.json")),
        )
        .with(ReplayRule::post(TOKEN).answers(400, include_str!("fixtures/token_invalid_grant.json")))
        .with(
            ReplayRule::get(ME)
                .header("authorization", BEARER)
                .answers(200, include_str!("fixtures/me.json")),
        )
        .with(
            ReplayRule::get(CALENDARS)
                .header("authorization", BEARER)
                .answers(200, include_str!("fixtures/calendars.json")),
        )
        .with(
            ReplayRule::get(VIEW)
                .header("authorization", BEARER)
                .query("$skiptoken", "PAGE2")
                .answers(200, include_str!("fixtures/events_page_2.json")),
        )
        .with(
            ReplayRule::get(VIEW)
                .header("authorization", BEARER)
                .answers(200, include_str!("fixtures/events_page_1.json")),
        )
        .with(
            ReplayRule::get(MISSING_VIEW)
                .header("authorization", BEARER)
                .answers(404, include_str!("fixtures/error_not_found.json")),
        )
        .with(ReplayRule::get(ME).answers(401, include_str!("fixtures/error_unauthorized.json")))
        .with(ReplayRule::get(CALENDARS).answers(401, include_str!("fixtures/error_unauthorized.json")))
        .with(ReplayRule::get(VIEW).answers(401, include_str!("fixtures/error_unauthorized.json")))
}

/// Microsoft when it refuses the client of the deployment (an expired, rotated or wrong client secret): every token request is `401 invalid_client`.
fn microsoft_refusing_the_client() -> ReplayHttp {
    ReplayHttp::new().with(ReplayRule::post(TOKEN).answers(401, include_str!("fixtures/token_invalid_client.json")))
}

fn redirect() -> Url {
    Url::parse("https://cal.example.org/oauth/microsoft/callback").unwrap()
}

/// A provider that is on, with a client secret file, talking to `http`.
fn provider(http: &ReplayHttp) -> Arc<dyn Provider> {
    static FILES: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "davhaven-microsoft-contract-{}-{}",
        std::process::id(),
        FILES.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&path, "client-secret\n").unwrap();
    let config = MicrosoftConfig {
        enabled: true,
        client_id: Some("11111111-2222-3333-4444-555555555555".to_owned()),
        client_secret_file: Some(path.clone()),
        redirect_uri: Some(redirect()),
        ..MicrosoftConfig::default()
    };
    let provider = MicrosoftProvider::new(&config, Arc::new(http.clone()), Arc::new(ManualClock::default())).unwrap();
    std::fs::remove_file(&path).unwrap();
    Arc::new(provider)
}

fn scenario() -> Scenario {
    Scenario {
        provider: provider(&microsoft()),
        redirect: redirect(),
        good_code: SecretString::from("0.AXQfixtureGood"),
        verifier: SecretString::from("a-verifier-that-is-long-enough-to-be-real-0123456789"),
        bad_code: SecretString::from("0.AXQfixtureBad"),
        account_ref: "anna@contoso.com".to_owned(),
        good_refresh_token: SecretString::from(REFRESH),
        revoked_refresh_token: SecretString::from("M.R3_BAY.-CfixtureRevoked"),
        access_token: SecretString::from(ACCESS),
        bad_access_token: SecretString::from("EwBwA8l6BAAUexpired"),
        calendar: "AAMkADDEFAULT=".to_owned(),
        event_ids: vec![
            "AAMkADHOLIDAY=".to_owned(),
            "AAMkADPRIVATE=".to_owned(),
            "AAMkADSERIESEXC1=".to_owned(),
            "AAMkADSERIESOCC1=".to_owned(),
            "AAMkADSINGLE=".to_owned(),
        ],
        stale_cursor: None,
        refused_client: Some(provider(&microsoft_refusing_the_client())),
    }
}

#[tokio::test]
async fn microsoft_keeps_the_contract_of_the_provider_port() {
    run_all(scenario).await;
}

fn lines(text: &[&str]) -> String {
    let mut joined = text.join("\r\n");
    joined.push_str("\r\n");
    joined
}

#[tokio::test]
async fn the_occurrences_of_the_window_become_calendar_objects() {
    let http = microsoft();
    let provider = provider(&http);
    let changes = provider
        .calendars()
        .changes_since(&SecretString::from(ACCESS), "AAMkADDEFAULT=", None)
        .await
        .unwrap();
    assert!(changes.snapshot);
    let by_id = |id: &str| {
        changes
            .changes
            .iter()
            .find(|change| change.remote_id == id)
            .and_then(|change| change.ics.clone())
            .unwrap_or_else(|| panic!("no event {id}"))
    };
    assert_eq!(
        changes
            .changes
            .iter()
            .map(|change| change.remote_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "AAMkADHOLIDAY=",
            "AAMkADPRIVATE=",
            "AAMkADSERIESEXC1=",
            "AAMkADSERIESOCC1=",
            "AAMkADSINGLE="
        ],
        "an occurrence and an exception are events of their own; the cancelled event is not imported"
    );
    assert_eq!(
        by_id("AAMkADSINGLE="),
        lines(&[
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//Davhaven//Microsoft 365 calendar import//EN",
            "BEGIN:VEVENT",
            "UID:AAMkADSINGLE=",
            "DTSTAMP:20261020T093000Z",
            "CREATED:20260901T080000Z",
            "LAST-MODIFIED:20261020T093000Z",
            "SUMMARY:Kick-off\\, Q4",
            "DESCRIPTION:Agenda:\\n1. Plan\\n2. Budget",
            "LOCATION:Room 4",
            "DTSTART;TZID=W. Europe Standard Time:20270105T100000",
            "DTEND;TZID=W. Europe Standard Time:20270105T110000",
            "END:VEVENT",
            "END:VCALENDAR",
        ])
    );
    let holiday = by_id("AAMkADHOLIDAY=");
    for line in [
        "DTSTART;VALUE=DATE:20270118",
        "DTEND;VALUE=DATE:20270120",
        "TRANSP:TRANSPARENT",
    ] {
        assert!(holiday.contains(&format!("{line}\r\n")), "{line}\n{holiday}");
    }
    assert!(
        !holiday.contains("DESCRIPTION") && !holiday.contains("LOCATION"),
        "empty text is left out: {holiday}"
    );
    let doctor = by_id("AAMkADPRIVATE=");
    for line in ["STATUS:TENTATIVE", "CLASS:PRIVATE", "DTSTART:20270202T073000Z"] {
        assert!(doctor.contains(&format!("{line}\r\n")), "{line}\n{doctor}");
    }
    let exception = by_id("AAMkADSERIESEXC1=");
    assert!(
        exception.contains("DTSTART;TZID=W. Europe Standard Time:20270112T110000\r\n") && !exception.contains("RRULE"),
        "{exception}"
    );
    assert!(http.unmatched().is_empty(), "{:?}", http.unmatched());
}

#[tokio::test]
async fn the_requests_carry_the_token_the_window_and_the_client_secret_only_where_it_belongs() {
    let http = microsoft();
    let provider = provider(&http);
    let grant = provider
        .oauth()
        .exchange(
            &SecretString::from("0.AXQfixtureGood"),
            &SecretString::from("a-verifier-that-is-long-enough-to-be-real-0123456789"),
            &redirect(),
        )
        .await
        .unwrap();
    provider
        .calendars()
        .list_calendars(&grant.tokens.access_token)
        .await
        .unwrap();
    let requests = http.requests();
    let secret_holders: Vec<String> = requests
        .iter()
        .filter(|request| request.body_text().contains("client-secret"))
        .map(|request| format!("{request:?}"))
        .collect();
    assert_eq!(
        secret_holders,
        vec!["POST https://login.microsoftonline.com/common/oauth2/v2.0/token".to_owned()]
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.url.as_str().contains("client-secret")),
        "the secret is never in a URL"
    );
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.header("authorization") == Some(BEARER))
    );
}

#[tokio::test]
async fn an_account_names_its_calendars_with_the_default_one_marked() {
    let http = microsoft();
    let calendars = provider(&http)
        .calendars()
        .list_calendars(&SecretString::from(ACCESS))
        .await
        .unwrap();
    let summary: Vec<(&str, &str, bool, Option<&str>)> = calendars
        .iter()
        .map(|calendar| {
            (
                calendar.remote_id.as_str(),
                calendar.display_name.as_str(),
                calendar.primary,
                calendar.color.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("AAMkADFAMILY=", "Family", false, Some("#9fe1e7")),
            ("AAMkADDEFAULT=", "Calendar", true, None),
        ]
    );
}

#[tokio::test]
async fn a_client_microsoft_refuses_is_not_a_revoked_refresh_token() {
    let http = microsoft_refusing_the_client();
    let refusing = provider(&http);
    let refresh = refusing
        .oauth()
        .refresh(&SecretString::from(REFRESH))
        .await
        .unwrap_err();
    assert_eq!(
        refresh.kind,
        PortErrorKind::Invalid,
        "an expired client secret of the app registration is the deployment's fault: no account may be switched off for it: {refresh}"
    );
    assert!(refresh.message.contains("invalid_client"), "{refresh}");
    assert!(
        !refresh.message.contains("AADSTS"),
        "what the platform wrote beyond the code does not reach the message: {refresh}"
    );
    let exchange = refusing
        .oauth()
        .exchange(
            &SecretString::from("0.AXQfixtureGood"),
            &SecretString::from("a-verifier-that-is-long-enough-to-be-real-0123456789"),
            &redirect(),
        )
        .await
        .unwrap_err();
    assert_eq!(exchange.kind, PortErrorKind::Invalid, "{exchange}");
    // A refresh token that Microsoft itself calls expired or revoked is the other case, and the only one that ends an account.
    let revoked = provider(&microsoft())
        .oauth()
        .refresh(&SecretString::from("M.R3_BAY.-CfixtureRevoked"))
        .await
        .unwrap_err();
    assert_eq!(revoked.kind, PortErrorKind::Rejected, "{revoked}");
}
