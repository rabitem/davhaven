//! The Google provider against recorded exchanges: the contract suite of the `Provider` port, and what the provider makes of
//! the events of an account.
//!
//! The exchanges are in `tests/fixtures`: the answers of Google's OAuth endpoints and Calendar API as the API documentation
//! describes them (no real client exists for these tests). `ReplayHttp` plays Google: it answers by method, URL, query and the
//! `Authorization` header, so a provider that sends the wrong token, the wrong page or the wrong form is refused the way
//! Google refuses it.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use davhaven_port_tests::provider::{MISSING_CALENDAR, Scenario, run_all};
use davhaven_ports::testing::{ManualClock, ReplayHttp, ReplayRule};
use davhaven_ports::{PortErrorKind, Provider};
use davhaven_provider_google::config::GoogleConfig;
use davhaven_provider_google::provider::GoogleProvider;
use secrecy::SecretString;
use url::Url;

const TOKEN: &str = "https://oauth2.googleapis.com/token";
const REVOKE: &str = "https://oauth2.googleapis.com/revoke";
const PRIMARY: &str = "https://www.googleapis.com/calendar/v3/calendars/primary";
const CALENDAR_LIST: &str = "https://www.googleapis.com/calendar/v3/users/me/calendarList";
const EVENTS: &str = "https://www.googleapis.com/calendar/v3/calendars/anna@example.org/events";
const MISSING_EVENTS: &str = "https://www.googleapis.com/calendar/v3/calendars/no-such-calendar/events";

const ACCESS: &str = "ya29.a0AfB_fixture-access-token";
const REFRESH: &str = "1//0gFixtureRefreshToken";
const BEARER: &str = "Bearer ya29.a0AfB_fixture-access-token";

/// Google as the fixtures record it: the good code, the good tokens and one account with a calendar of events.
fn google() -> ReplayHttp {
    ReplayHttp::new()
        .with(
            ReplayRule::post(TOKEN)
                .body_contains("code=4%2F0AfGood&")
                .answers(200, include_str!("fixtures/token_exchange.json")),
        )
        .with(
            ReplayRule::post(TOKEN)
                .body_contains("grant_type=refresh_token")
                .body_contains("refresh_token=1%2F%2F0gFixtureRefreshToken&")
                .answers(200, include_str!("fixtures/token_refresh.json")),
        )
        .with(ReplayRule::post(TOKEN).answers(400, include_str!("fixtures/token_invalid_grant.json")))
        .with(ReplayRule::post(REVOKE).answers(200, "{}"))
        .with(
            ReplayRule::get(PRIMARY)
                .header("authorization", BEARER)
                .answers(200, include_str!("fixtures/calendar_primary.json")),
        )
        .with(
            ReplayRule::get(CALENDAR_LIST)
                .header("authorization", BEARER)
                .answers(200, include_str!("fixtures/calendar_list.json")),
        )
        .with(
            ReplayRule::get(EVENTS)
                .header("authorization", BEARER)
                .query("pageToken", "PAGE2")
                .answers(200, include_str!("fixtures/events_page_2.json")),
        )
        .with(
            ReplayRule::get(EVENTS)
                .header("authorization", BEARER)
                .answers(200, include_str!("fixtures/events_page_1.json")),
        )
        .with(
            ReplayRule::get(MISSING_EVENTS)
                .header("authorization", BEARER)
                .answers(404, include_str!("fixtures/error_not_found.json")),
        )
        .with(ReplayRule::get(PRIMARY).answers(401, include_str!("fixtures/error_unauthorized.json")))
        .with(ReplayRule::get(CALENDAR_LIST).answers(401, include_str!("fixtures/error_unauthorized.json")))
        .with(ReplayRule::get(EVENTS).answers(401, include_str!("fixtures/error_unauthorized.json")))
}

/// Google when it refuses the client of the deployment (an expired, rotated or wrong client secret): every token request is `401 invalid_client`.
fn google_refusing_the_client() -> ReplayHttp {
    ReplayHttp::new().with(ReplayRule::post(TOKEN).answers(401, include_str!("fixtures/token_invalid_client.json")))
}

fn redirect() -> Url {
    Url::parse("https://cal.example.org/oauth/google/callback").unwrap()
}

/// A provider that is on, with a client secret file, talking to `http`.
fn provider(http: &ReplayHttp) -> Arc<dyn Provider> {
    static FILES: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "davhaven-google-contract-{}-{}",
        std::process::id(),
        FILES.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&path, "client-secret\n").unwrap();
    let config = GoogleConfig {
        enabled: true,
        client_id: Some("1234-fixture.apps.googleusercontent.com".to_owned()),
        client_secret_file: Some(path.clone()),
        redirect_uri: Some(redirect()),
        ..GoogleConfig::default()
    };
    let provider = GoogleProvider::new(&config, Arc::new(http.clone()), Arc::new(ManualClock::default())).unwrap();
    std::fs::remove_file(&path).unwrap();
    Arc::new(provider)
}

fn scenario() -> Scenario {
    Scenario {
        provider: provider(&google()),
        redirect: redirect(),
        good_code: SecretString::from("4/0AfGood"),
        verifier: SecretString::from("a-verifier-that-is-long-enough-to-be-real-0123456789"),
        bad_code: SecretString::from("4/0AfBad"),
        account_ref: "anna@example.org".to_owned(),
        good_refresh_token: SecretString::from(REFRESH),
        revoked_refresh_token: SecretString::from("1//0gRevoked"),
        access_token: SecretString::from(ACCESS),
        bad_access_token: SecretString::from("ya29.expired"),
        calendar: "anna@example.org".to_owned(),
        event_ids: vec![
            "5s1dvkr7g5fc7h5q8k3l4n9p2o".to_owned(),
            "7ke2cubqs1gk9q8ob3q06hvf2d".to_owned(),
            "c0r4jn6p3u2l8q7s1t5v9a0b3e".to_owned(),
            "ho3cbdh72idrpkhssoau5fdm1g".to_owned(),
        ],
        stale_cursor: None,
        refused_client: Some(provider(&google_refusing_the_client())),
    }
}

#[tokio::test]
async fn google_keeps_the_contract_of_the_provider_port() {
    run_all(scenario).await;
}

fn lines(text: &[&str]) -> String {
    let mut joined = text.join("\r\n");
    joined.push_str("\r\n");
    joined
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the golden calendar objects are the point of the test"
)]
async fn the_events_of_the_account_become_calendar_objects() {
    let http = google();
    let provider = provider(&http);
    let changes = provider
        .calendars()
        .changes_since(&SecretString::from(ACCESS), "anna@example.org", None)
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
            "5s1dvkr7g5fc7h5q8k3l4n9p2o",
            "7ke2cubqs1gk9q8ob3q06hvf2d",
            "c0r4jn6p3u2l8q7s1t5v9a0b3e",
            "ho3cbdh72idrpkhssoau5fdm1g"
        ],
        "the series and its two instances are one object; the attendee and reminder data is not read"
    );
    assert_eq!(
        by_id("7ke2cubqs1gk9q8ob3q06hvf2d"),
        lines(&[
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//Davhaven//Google Calendar import//EN",
            "BEGIN:VEVENT",
            "UID:7ke2cubqs1gk9q8ob3q06hvf2d@google.com",
            "DTSTAMP:20261020T093000Z",
            "CREATED:20260901T080000Z",
            "LAST-MODIFIED:20261020T093000Z",
            "SEQUENCE:1",
            "SUMMARY:Kick-off\\, Q4",
            "DESCRIPTION:Agenda:\\n1. Plan\\n2. Budget",
            "LOCATION:Room 4",
            "STATUS:CONFIRMED",
            "DTSTART:20270105T090000Z",
            "DTEND:20270105T100000Z",
            "END:VEVENT",
            "END:VCALENDAR",
        ])
    );
    assert_eq!(
        by_id("5s1dvkr7g5fc7h5q8k3l4n9p2o"),
        lines(&[
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//Davhaven//Google Calendar import//EN",
            "BEGIN:VEVENT",
            "UID:5s1dvkr7g5fc7h5q8k3l4n9p2o@google.com",
            "DTSTAMP:20261020T093000Z",
            "CREATED:20260903T080000Z",
            "LAST-MODIFIED:20261020T093000Z",
            "SUMMARY:Stand-up",
            "STATUS:CONFIRMED",
            "DTSTART;TZID=Europe/Berlin:20270105T100000",
            "DTEND;TZID=Europe/Berlin:20270105T101500",
            "RRULE:FREQ=WEEKLY;BYDAY=TU",
            "EXDATE;TZID=Europe/Berlin:20270119T100000",
            "END:VEVENT",
            "BEGIN:VEVENT",
            "UID:5s1dvkr7g5fc7h5q8k3l4n9p2o@google.com",
            "DTSTAMP:20261021T093000Z",
            "CREATED:20260903T080000Z",
            "LAST-MODIFIED:20261021T093000Z",
            "SUMMARY:Stand-up (longer)",
            "STATUS:CONFIRMED",
            "RECURRENCE-ID;TZID=Europe/Berlin:20270112T100000",
            "DTSTART;TZID=Europe/Berlin:20270112T110000",
            "DTEND;TZID=Europe/Berlin:20270112T113000",
            "END:VEVENT",
            "END:VCALENDAR",
        ])
    );
    let holiday = by_id("ho3cbdh72idrpkhssoau5fdm1g");
    for line in [
        "DTSTART;VALUE=DATE:20270118",
        "DTEND;VALUE=DATE:20270120",
        "TRANSP:TRANSPARENT",
    ] {
        assert!(holiday.contains(&format!("{line}\r\n")), "{line}\n{holiday}");
    }
    let doctor = by_id("c0r4jn6p3u2l8q7s1t5v9a0b3e");
    for line in [
        "STATUS:TENTATIVE",
        "CLASS:PRIVATE",
        "SEQUENCE:3",
        "DTSTART:20270202T073000Z",
    ] {
        assert!(doctor.contains(&format!("{line}\r\n")), "{line}\n{doctor}");
    }
    assert!(
        changes
            .changes
            .iter()
            .all(|change| !change.ics.as_deref().unwrap_or_default().contains("ben@example.net")),
        "attendees are not imported"
    );
    assert!(http.unmatched().is_empty(), "{:?}", http.unmatched());
}

#[tokio::test]
async fn the_requests_carry_the_token_the_window_and_the_client_secret_only_where_it_belongs() {
    let http = google();
    let provider = provider(&http);
    let grant = provider
        .oauth()
        .exchange(
            &SecretString::from("4/0AfGood"),
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
        vec!["POST https://oauth2.googleapis.com/token".to_owned()]
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
async fn an_account_names_its_calendars_with_the_primary_one_marked() {
    let http = google();
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
            (
                "family12345678901234567890@group.calendar.google.com",
                "Family",
                false,
                Some("#9fe1e7")
            ),
            ("anna@example.org", "Anna", true, Some("#9a9cff")),
        ]
    );
    assert_ne!(MISSING_CALENDAR, "anna@example.org");
}

#[tokio::test]
async fn a_client_google_refuses_is_not_a_revoked_refresh_token() {
    let http = google_refusing_the_client();
    let refusing = provider(&http);
    let refresh = refusing
        .oauth()
        .refresh(&SecretString::from(REFRESH))
        .await
        .unwrap_err();
    assert_eq!(
        refresh.kind,
        PortErrorKind::Invalid,
        "an expired or rotated client secret is the deployment's fault: no account may be switched off for it: {refresh}"
    );
    assert!(refresh.message.contains("invalid_client"), "{refresh}");
    let exchange = refusing
        .oauth()
        .exchange(
            &SecretString::from("4/0AfGood"),
            &SecretString::from("a-verifier-that-is-long-enough-to-be-real-0123456789"),
            &redirect(),
        )
        .await
        .unwrap_err();
    assert_eq!(exchange.kind, PortErrorKind::Invalid, "{exchange}");
    // A refresh token that Google itself calls revoked is the other case, and the only one that ends an account.
    let revoked = provider(&google())
        .oauth()
        .refresh(&SecretString::from("1//0gRevoked"))
        .await
        .unwrap_err();
    assert_eq!(revoked.kind, PortErrorKind::Rejected, "{revoked}");
}
