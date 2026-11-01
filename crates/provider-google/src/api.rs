//! The `RemoteCalendarApi` implementation over the Google Calendar API v3.
//!
//! The calendars of the account come from `calendarList`, the events of one calendar from `events.list` with
//! `singleEvents=false`, so that a recurring event arrives once, as a master with its rules, and a changed or cancelled instance
//! arrives next to it (`ics.rs` makes one calendar object of them). The listing is limited to the **window** of the
//! configuration (`history_days` before and `future_days` after the time of the call) with `timeMin` and `timeMax`.
//!
//! # Every pull is a snapshot
//!
//! Google can hand out a sync token that makes the next pull a difference, but a difference is only as good as the memory that
//! applies it: a master and its changed instances arrive as separate events, and rebuilding the series of a changed instance
//! needs the rest of it. 1.0 therefore lists the window on every pull and lets the sync engine find what changed (a calendar
//! object whose content did not change is not written again, PLAN 2.7), which costs a request per hundred events on every
//! pull of the account (`providers.sync.interval`), and nothing else: no state of the provider has to be kept in step. The
//! answer is a **snapshot** (`RemoteChanges::snapshot`); the cursor it carries is the time of the pull and is not read back.
//!
//! A calendar with more than [`MAX_EVENTS`] events in the window is refused (`Unsupported`, which the sync engine does not answer
//! with a renewal of the token): the answer lives in memory, and a window that large is a sign that it should be narrower. A
//! listing that goes on beyond `MAX_EVENT_PAGES` pages is not followed (`Unavailable`).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, SecondsFormat};
use davhaven_ports::{
    Clock, HttpClient, PortError, PortErrorKind, PortLabel, RemoteCalendar, RemoteCalendarApi, RemoteChanges, observe,
};
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use crate::ics::{Event, convert};
use crate::transport::{api_error, api_get, json};

/// What `observe` labels the calls with.
const LABEL: PortLabel = PortLabel::new("provider", crate::config::PLUGIN);

/// The root of the calendar API.
pub const API_BASE: &str = "https://www.googleapis.com/calendar/v3/";

/// The most events of one calendar a pull reads.
pub const MAX_EVENTS: usize = 10_000;

/// Events per page of the listing: a page is an answer of at most a few megabytes even when descriptions are long, which the
/// egress limit for provider answers (`security.egress.provider_api_max_response_bytes`) allows.
const PAGE_SIZE: usize = 100;

/// The pages of the calendar list: a person has few calendars.
const MAX_CALENDAR_PAGES: usize = 10;

/// The pages of one listing of events: twice what [`MAX_EVENTS`] events fill, and some, because a page may hold fewer events
/// than asked for. A provider that goes on beyond that (a proxy that answers empty pages with a continuation for ever) is
/// not followed.
const MAX_EVENT_PAGES: usize = 2 * MAX_EVENTS / PAGE_SIZE + 10;

/// The members of an event that the import reads, so that attachments, attendees and conference data are not sent at all.
const EVENT_FIELDS: &str = "nextPageToken,items(id,etag,status,summary,description,location,start,end,recurrence,\
                            recurringEventId,originalStartTime,transparency,visibility,iCalUID,sequence,created,updated)";

/// The calendar API of one Google client.
pub struct GoogleCalendars {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    history: Duration,
    future: Duration,
}

impl core::fmt::Debug for GoogleCalendars {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GoogleCalendars")
            .field("history", &self.history)
            .field("future", &self.future)
            .finish_non_exhaustive()
    }
}

impl GoogleCalendars {
    /// The API with a window of `history_days` before and `future_days` after the time of a pull.
    pub fn new(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>, history_days: u32, future_days: u32) -> Self {
        Self {
            http,
            clock,
            history: Duration::days(i64::from(history_days)),
            future: Duration::days(i64::from(future_days)),
        }
    }
}

fn base() -> Result<Url, PortError> {
    Url::parse(API_BASE).map_err(|error| PortError::internal(error.to_string()))
}

#[derive(Deserialize)]
struct CalendarList {
    #[serde(default)]
    items: Vec<CalendarEntry>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct CalendarEntry {
    id: String,
    summary: Option<String>,
    #[serde(rename = "summaryOverride")]
    summary_override: Option<String>,
    #[serde(rename = "backgroundColor")]
    background_color: Option<String>,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    deleted: bool,
}

#[derive(Deserialize)]
struct EventList {
    #[serde(default)]
    items: Vec<Event>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

/// A color as `#RRGGBB`, or nothing for anything else.
fn color_of(text: Option<&str>) -> Option<String> {
    text.filter(|text| text.len() == 7 && text.starts_with('#') && text.chars().skip(1).all(|c| c.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
}

#[async_trait]
impl RemoteCalendarApi for GoogleCalendars {
    async fn list_calendars(&self, token: &SecretString) -> Result<Vec<RemoteCalendar>, PortError> {
        observe(LABEL, "list_calendars", async {
            let mut calendars = Vec::new();
            let mut page: Option<String> = None;
            for _ in 0..MAX_CALENDAR_PAGES {
                let mut url = base()?
                    .join("users/me/calendarList")
                    .map_err(|error| PortError::internal(error.to_string()))?;
                {
                    let mut query = url.query_pairs_mut();
                    query.append_pair("maxResults", "250");
                    if let Some(page) = &page {
                        query.append_pair("pageToken", page);
                    }
                }
                let response = self.http.send(api_get(url, token)?).await?;
                if !response.status.is_success() {
                    return Err(api_error("calendar list", &response));
                }
                let list = json::<CalendarList>(&response)?;
                for entry in list
                    .items
                    .into_iter()
                    .filter(|entry| !entry.deleted && !entry.id.is_empty())
                {
                    let name = entry
                        .summary_override
                        .filter(|name| !name.trim().is_empty())
                        .or(entry.summary)
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or_else(|| entry.id.clone());
                    let mut calendar = RemoteCalendar::new(entry.id, name);
                    if let Some(color) = color_of(entry.background_color.as_deref()) {
                        calendar = calendar.with_color(color);
                    }
                    if entry.primary {
                        calendar = calendar.primary();
                    }
                    calendars.push(calendar);
                }
                match list.next_page_token.filter(|token| !token.is_empty()) {
                    Some(next) => page = Some(next),
                    None => return Ok(calendars),
                }
            }
            Err(PortError::new(
                PortErrorKind::Unsupported,
                "the account has more calendars than the import reads",
            ))
        })
        .await
    }

    /// Lists the events of the window (see the module documentation); the cursor is not read.
    async fn changes_since(
        &self,
        token: &SecretString,
        calendar: &str,
        _cursor: Option<&str>,
    ) -> Result<RemoteChanges, PortError> {
        observe(LABEL, "changes_since", async {
            let now = self.clock.now();
            let from = now
                .checked_sub_signed(self.history)
                .ok_or_else(|| PortError::internal("the window starts before the earliest time"))?;
            let until = now
                .checked_add_signed(self.future)
                .ok_or_else(|| PortError::internal("the window ends after the latest time"))?;
            let mut events: Vec<Event> = Vec::new();
            let mut page: Option<String> = None;
            for _ in 0..MAX_EVENT_PAGES {
                let mut url = base()?;
                url.path_segments_mut()
                    .map_err(|()| PortError::internal("the API root cannot be a base"))?
                    .pop_if_empty()
                    .extend(["calendars", calendar, "events"]);
                {
                    let mut query = url.query_pairs_mut();
                    query
                        .append_pair("singleEvents", "false")
                        .append_pair("showDeleted", "false")
                        .append_pair("maxResults", &PAGE_SIZE.to_string())
                        .append_pair("timeMin", &from.to_rfc3339_opts(SecondsFormat::Secs, true))
                        .append_pair("timeMax", &until.to_rfc3339_opts(SecondsFormat::Secs, true))
                        .append_pair("fields", EVENT_FIELDS);
                    if let Some(page) = &page {
                        query.append_pair("pageToken", page);
                    }
                }
                let response = self.http.send(api_get(url, token)?).await?;
                if !response.status.is_success() {
                    return Err(api_error("event list", &response));
                }
                let list = json::<EventList>(&response)?;
                events.extend(list.items);
                if events.len() > MAX_EVENTS {
                    // A calendar that a renewed token does not make smaller: `Unsupported` is not answered with a renewal.
                    return Err(PortError::new(
                        PortErrorKind::Unsupported,
                        format!(
                            "the calendar has more than {MAX_EVENTS} events in the window of the import: narrow `history_days` and `future_days`"
                        ),
                    ));
                }
                match list.next_page_token.filter(|token| !token.is_empty()) {
                    Some(next) => page = Some(next),
                    None => {
                        return Ok(RemoteChanges::snapshot(
                            convert(events, now),
                            now.to_rfc3339_opts(SecondsFormat::Secs, true),
                        ));
                    }
                }
            }
            Err(PortError::unavailable(
                "Google went on answering pages of events beyond what a calendar of the allowed size fills",
            ))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use davhaven_ports::PortErrorKind;
    use davhaven_ports::testing::{ManualClock, ReplayHttp, ReplayRule};
    use secrecy::ExposeSecret;

    use super::*;

    fn api(http: &ReplayHttp, clock: &ManualClock) -> GoogleCalendars {
        GoogleCalendars::new(Arc::new(http.clone()), Arc::new(clock.clone()), 90, 365)
    }

    fn token() -> SecretString {
        SecretString::from("ya29.token")
    }

    const EVENTS: &str = "https://www.googleapis.com/calendar/v3/calendars/anna@example.org/events";

    #[tokio::test]
    async fn calendars_come_with_a_name_a_color_and_the_primary_flag() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::get("https://www.googleapis.com/calendar/v3/users/me/calendarList")
                    .query("pageToken", "p2")
                    .answers(
                        200,
                        r##"{"items":[{"id":"gone","summary":"Gone","deleted":true},{"id":"team","summary":"Team","summaryOverride":"  ","backgroundColor":"#9FE1E7"}]}"##,
                    ),
            )
            .with(
                ReplayRule::get("https://www.googleapis.com/calendar/v3/users/me/calendarList")
                    .header("authorization", "Bearer ya29.token")
                    .answers(
                        200,
                        r#"{"items":[{"id":"anna@example.org","summary":"anna@example.org","summaryOverride":"Anna","primary":true,"backgroundColor":"nonsense"}],"nextPageToken":"p2"}"#,
                    ),
            );
        let calendars = api(&http, &clock).list_calendars(&token()).await.unwrap();
        assert_eq!(calendars.len(), 2);
        assert_eq!(
            (
                calendars[0].remote_id.as_str(),
                calendars[0].display_name.as_str(),
                calendars[0].primary,
                calendars[0].color.as_deref()
            ),
            ("anna@example.org", "Anna", true, None),
            "the override is the name the person sees; a color that is not #RRGGBB is none"
        );
        assert_eq!(
            (
                calendars[1].remote_id.as_str(),
                calendars[1].display_name.as_str(),
                calendars[1].primary,
                calendars[1].color.as_deref()
            ),
            ("team", "Team", false, Some("#9fe1e7"))
        );
        assert_eq!(http.requests().len(), 2);
        assert_eq!(http.requests()[0].query_value("pageToken"), None);
    }

    #[tokio::test]
    async fn the_events_of_the_window_are_listed_page_by_page_and_are_a_snapshot() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::get(EVENTS).query("pageToken", "next").answers(
                    200,
                    r#"{"items":[{"id":"e2","recurringEventId":"e1","status":"cancelled","originalStartTime":{"date":"2027-01-12"}}]}"#,
                ),
            )
            .with(ReplayRule::get(EVENTS).without_query("pageToken").answers(
                200,
                r#"{"items":[{"id":"e1","iCalUID":"e1@google.com","start":{"date":"2027-01-05"},"end":{"date":"2027-01-06"},
                    "recurrence":["RRULE:FREQ=WEEKLY"]}],"nextPageToken":"next"}"#,
            ));
        let changes = api(&http, &clock)
            .changes_since(&token(), "anna@example.org", Some("ignored"))
            .await
            .unwrap();
        assert!(changes.snapshot);
        assert_eq!(
            changes.changes.len(),
            1,
            "the series and its cancelled instance are one object"
        );
        let ics = changes.changes[0].ics.as_deref().unwrap();
        assert!(ics.contains("EXDATE;VALUE=DATE:20270112\r\n"), "{ics}");
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        let first = &requests[0];
        assert_eq!(first.header("authorization"), Some("Bearer ya29.token"));
        assert_eq!(first.query_value("singleEvents").as_deref(), Some("false"));
        assert_eq!(first.query_value("showDeleted").as_deref(), Some("false"));
        assert_eq!(first.query_value("maxResults").as_deref(), Some("100"));
        let from = chrono::DateTime::parse_from_rfc3339(&first.query_value("timeMin").unwrap()).unwrap();
        let until = chrono::DateTime::parse_from_rfc3339(&first.query_value("timeMax").unwrap()).unwrap();
        assert_eq!(
            (until - from).num_days(),
            90 + 365,
            "the window of the configuration around the time of the clock"
        );
        assert!(first.query_value("fields").unwrap().contains("recurringEventId"));
        assert_eq!(requests[1].query_value("pageToken").as_deref(), Some("next"));
        assert_eq!(http.unmatched(), Vec::<String>::new());
        assert_ne!(changes.cursor, "");
    }

    #[tokio::test]
    async fn a_calendar_id_is_one_path_segment() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new().with(
            ReplayRule::get("https://www.googleapis.com/calendar/v3/calendars/a%2Fb%3Fc%23d/events")
                .answers(200, r#"{"items":[]}"#),
        );
        let changes = api(&http, &clock)
            .changes_since(&token(), "a/b?c#d", None)
            .await
            .unwrap();
        assert_eq!(changes.changes, Vec::<davhaven_ports::RemoteChange>::new());
        assert_eq!(http.unmatched(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn errors_are_mapped_for_the_sync_engine() {
        let clock = ManualClock::default();
        for (status, body, kind) in [
            (
                401,
                r#"{"error":{"code":401,"status":"UNAUTHENTICATED"}}"#,
                PortErrorKind::Rejected,
            ),
            (
                404,
                r#"{"error":{"code":404,"status":"NOT_FOUND"}}"#,
                PortErrorKind::Rejected,
            ),
            (
                403,
                r#"{"error":{"errors":[{"reason":"rateLimitExceeded"}]}}"#,
                PortErrorKind::Unavailable,
            ),
            (503, "", PortErrorKind::Unavailable),
            (200, "<html>captive portal</html>", PortErrorKind::Unavailable),
        ] {
            let http = ReplayHttp::new().with(ReplayRule::get(EVENTS).answers(status, body));
            let error = api(&http, &clock)
                .changes_since(&token(), "anna@example.org", None)
                .await
                .unwrap_err();
            assert_eq!(error.kind, kind, "{status}: {error}");
            assert!(!error.message.contains("ya29"), "{error}");
        }
    }

    #[tokio::test]
    async fn a_calendar_that_is_too_large_is_refused_instead_of_cut() {
        let clock = ManualClock::default();
        let page = format!(
            r#"{{"items":[{}],"nextPageToken":"more"}}"#,
            (0..100)
                .map(|n| format!(r#"{{"id":"e{n}","start":{{"date":"2027-01-05"}}}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let http = ReplayHttp::new().with(ReplayRule::get(EVENTS).answers(200, page));
        let error = api(&http, &clock)
            .changes_since(&token(), "anna@example.org", None)
            .await
            .unwrap_err();
        assert_eq!(
            error.kind,
            PortErrorKind::Unsupported,
            "not `Rejected`: a renewed token does not make the calendar smaller"
        );
        assert!(error.message.contains("10000"), "{error}");
        assert_eq!(
            http.requests().len(),
            MAX_EVENTS / PAGE_SIZE + 1,
            "the pages are read until the cap is passed"
        );
    }

    #[tokio::test]
    async fn a_provider_that_goes_on_answering_empty_pages_is_not_followed_for_ever() {
        let clock = ManualClock::default();
        let http =
            ReplayHttp::new().with(ReplayRule::get(EVENTS).answers(200, r#"{"items":[],"nextPageToken":"more"}"#));
        let error = api(&http, &clock)
            .changes_since(&token(), "anna@example.org", None)
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable, "{error}");
        assert_eq!(
            http.requests().len(),
            MAX_EVENT_PAGES,
            "one request per page, up to the cap"
        );
    }

    #[test]
    fn the_token_is_a_secret() {
        assert_eq!(token().expose_secret(), "ya29.token");
        let api = GoogleCalendars::new(Arc::new(ReplayHttp::new()), Arc::new(ManualClock::default()), 1, 2);
        assert!(format!("{api:?}").contains("GoogleCalendars"));
    }
}
