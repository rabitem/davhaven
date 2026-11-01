//! The `RemoteCalendarApi` implementation over Microsoft Graph (v1.0).
//!
//! The calendars of the account come from `/me/calendars`, the events of one calendar from its `calendarView` over the **window**
//! of the configuration (`history_days` before and `future_days` after the time of the call). A `calendarView` is the list of what
//! a person sees in a calendar app for a range of time: the single events and the occurrences and exceptions of recurring ones,
//! one entry each, which `ics.rs` turns into one calendar object each.
//!
//! # Every pull is a snapshot
//!
//! Graph has a delta query for the `calendarView`, but a delta is tied to the window it started with, which slides with the
//! clock, so it must be started again now and then and has to find out what disappeared. 1.0 lists the window on every pull
//! instead and lets the sync engine find what changed (a calendar object whose content did not change is not written again, PLAN
//! 2.7), which costs a request per fifty events on every pull of the account (`providers.sync.interval`), and nothing else: no state
//! of the provider has to be kept in step. The answer is a **snapshot** (`RemoteChanges::snapshot`); the cursor it carries is the
//! time of the pull and is not read back.
//!
//! A calendar with more than [`MAX_EVENTS`] events in the window is refused (`Unsupported`, which the sync engine does not answer
//! with a renewal of the token): the answer lives in memory, and a window that large is a sign that it should be narrower. A
//! listing that goes on beyond `MAX_EVENT_PAGES` pages is not followed (`Unavailable`).
//!
//! The next page of a listing is the URL Graph names in `@odata.nextLink`. It is followed only when it is on `graph.microsoft.com`
//! over https, so that an answer cannot send the access token somewhere else.

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
use crate::transport::{graph_error, graph_get, json};

/// What `observe` labels the calls with.
const LABEL: PortLabel = PortLabel::new("provider", crate::config::PLUGIN);

/// The host of Microsoft Graph.
pub const GRAPH_HOST: &str = "graph.microsoft.com";

/// The root of the API.
pub const API_BASE: &str = "https://graph.microsoft.com/v1.0/";

/// The most events of one calendar a pull reads.
pub const MAX_EVENTS: usize = 10_000;

/// Events per page: a page is an answer of at most a few megabytes even when descriptions are long, which the egress limit for
/// provider answers (`security.egress.provider_api_max_response_bytes`) allows.
const PAGE_SIZE: usize = 50;

/// The pages of the calendar list: a person has few calendars.
const MAX_CALENDAR_PAGES: usize = 10;

/// The pages of one listing of events: twice what [`MAX_EVENTS`] events fill, and some, because a page may hold fewer events
/// than asked for. A provider that goes on beyond that (a proxy that answers empty pages with a continuation for ever) is
/// not followed.
const MAX_EVENT_PAGES: usize = 2 * MAX_EVENTS / PAGE_SIZE + 10;

/// The members of an event that the import reads, so that attendees, attachments and online-meeting data are not sent at all.
const EVENT_SELECT: &str = "id,changeKey,subject,body,start,end,isAllDay,isCancelled,showAs,sensitivity,location,createdDateTime,lastModifiedDateTime";

/// The calendar API of one Microsoft client.
pub struct MicrosoftCalendars {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    history: Duration,
    future: Duration,
}

impl core::fmt::Debug for MicrosoftCalendars {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MicrosoftCalendars")
            .field("history", &self.history)
            .field("future", &self.future)
            .finish_non_exhaustive()
    }
}

impl MicrosoftCalendars {
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
    value: Vec<CalendarEntry>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct CalendarEntry {
    id: String,
    name: Option<String>,
    #[serde(rename = "hexColor")]
    hex_color: Option<String>,
    #[serde(rename = "isDefaultCalendar", default)]
    is_default: bool,
}

#[derive(Deserialize)]
struct EventList {
    #[serde(default)]
    value: Vec<Event>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

/// A color as `#RRGGBB`, or nothing for anything else (Graph answers an empty string for a calendar without one).
fn color_of(text: Option<&str>) -> Option<String> {
    text.filter(|text| text.len() == 7 && text.starts_with('#') && text.chars().skip(1).all(|c| c.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
}

/// The URL of the next page named by an answer: only on Graph over https.
///
/// # Errors
///
/// `Unavailable` for a link that points elsewhere.
fn next_page(link: &str) -> Result<Url, PortError> {
    let url = Url::parse(link).map_err(|_| PortError::unavailable("Microsoft named a next page that is not a URL"))?;
    if url.scheme() == "https"
        && url.host_str() == Some(GRAPH_HOST)
        && url.username().is_empty()
        && url.password().is_none()
    {
        Ok(url)
    } else {
        Err(PortError::unavailable(
            "Microsoft named a next page outside Microsoft Graph",
        ))
    }
}

#[async_trait]
impl RemoteCalendarApi for MicrosoftCalendars {
    async fn list_calendars(&self, token: &SecretString) -> Result<Vec<RemoteCalendar>, PortError> {
        observe(LABEL, "list_calendars", async {
            let mut calendars = Vec::new();
            let mut url = base()?
                .join("me/calendars")
                .map_err(|error| PortError::internal(error.to_string()))?;
            url.set_query(Some("$top=100&$select=id,name,hexColor,isDefaultCalendar"));
            for _ in 0..MAX_CALENDAR_PAGES {
                let response = self.http.send(graph_get(url.clone(), token)?).await?;
                if !response.status.is_success() {
                    return Err(graph_error("calendar list", &response));
                }
                let list = json::<CalendarList>(&response)?;
                for entry in list.value.into_iter().filter(|entry| !entry.id.is_empty()) {
                    let name = entry
                        .name
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or_else(|| entry.id.clone());
                    let mut calendar = RemoteCalendar::new(entry.id, name);
                    if let Some(color) = color_of(entry.hex_color.as_deref()) {
                        calendar = calendar.with_color(color);
                    }
                    if entry.is_default {
                        calendar = calendar.primary();
                    }
                    calendars.push(calendar);
                }
                match list.next_link.filter(|link| !link.is_empty()) {
                    Some(link) => url = next_page(&link)?,
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
            let mut url = base()?;
            url.path_segments_mut()
                .map_err(|()| PortError::internal("the API root cannot be a base"))?
                .pop_if_empty()
                .extend(["me", "calendars", calendar, "calendarView"]);
            url.query_pairs_mut()
                .append_pair("startDateTime", &from.to_rfc3339_opts(SecondsFormat::Secs, true))
                .append_pair("endDateTime", &until.to_rfc3339_opts(SecondsFormat::Secs, true))
                .append_pair("$top", &PAGE_SIZE.to_string())
                .append_pair("$select", EVENT_SELECT);
            let mut events: Vec<Event> = Vec::new();
            for _ in 0..MAX_EVENT_PAGES {
                let response = self.http.send(graph_get(url.clone(), token)?).await?;
                if !response.status.is_success() {
                    return Err(graph_error("event list", &response));
                }
                let list = json::<EventList>(&response)?;
                events.extend(list.value);
                if events.len() > MAX_EVENTS {
                    // A calendar that a renewed token does not make smaller: `Unsupported` is not answered with a renewal.
                    return Err(PortError::new(
                        PortErrorKind::Unsupported,
                        format!(
                            "the calendar has more than {MAX_EVENTS} events in the window of the import: narrow `history_days` and `future_days`"
                        ),
                    ));
                }
                match list.next_link.filter(|link| !link.is_empty()) {
                    Some(link) => url = next_page(&link)?,
                    None => {
                        return Ok(RemoteChanges::snapshot(
                            convert(&events, now),
                            now.to_rfc3339_opts(SecondsFormat::Secs, true),
                        ));
                    }
                }
            }
            Err(PortError::unavailable(
                "Microsoft went on answering pages of events beyond what a calendar of the allowed size fills",
            ))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use davhaven_ports::PortErrorKind;
    use davhaven_ports::testing::{ManualClock, ReplayHttp, ReplayRule};

    use super::*;

    fn api(http: &ReplayHttp, clock: &ManualClock) -> MicrosoftCalendars {
        MicrosoftCalendars::new(Arc::new(http.clone()), Arc::new(clock.clone()), 90, 365)
    }

    fn token() -> SecretString {
        SecretString::from("EwB.token")
    }

    const CALENDARS: &str = "https://graph.microsoft.com/v1.0/me/calendars";
    const VIEW: &str = "https://graph.microsoft.com/v1.0/me/calendars/AAMk=/calendarView";

    #[tokio::test]
    async fn calendars_come_with_a_name_a_color_and_the_default_flag() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(
                ReplayRule::get("https://graph.microsoft.com/v1.0/me/calendars")
                    .query("$skiptoken", "p2")
                    .answers(
                        200,
                        r##"{"value":[{"id":"AAMk2=","name":"Team","hexColor":"#9FE1E7","isDefaultCalendar":false}]}"##,
                    ),
            )
            .with(ReplayRule::get(CALENDARS).header("authorization", "Bearer EwB.token").answers(
                200,
                r#"{"value":[{"id":"AAMk=","name":"Calendar","hexColor":"","isDefaultCalendar":true},{"id":"","name":"No id"}],
                    "@odata.nextLink":"https://graph.microsoft.com/v1.0/me/calendars?$skiptoken=p2"}"#,
            ));
        let calendars = api(&http, &clock).list_calendars(&token()).await.unwrap();
        assert_eq!(calendars.len(), 2);
        assert_eq!(
            (
                calendars[0].remote_id.as_str(),
                calendars[0].display_name.as_str(),
                calendars[0].primary,
                calendars[0].color.as_deref()
            ),
            ("AAMk=", "Calendar", true, None),
            "a color that is empty is none"
        );
        assert_eq!(
            (
                calendars[1].remote_id.as_str(),
                calendars[1].primary,
                calendars[1].color.as_deref()
            ),
            ("AAMk2=", false, Some("#9fe1e7"))
        );
        assert_eq!(http.requests()[0].query_value("$top").as_deref(), Some("100"));
    }

    #[tokio::test]
    async fn the_events_of_the_window_are_listed_page_by_page_and_are_a_snapshot() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new()
            .with(ReplayRule::get(VIEW).query("$skiptoken", "p2").answers(
                200,
                r#"{"value":[{"id":"e2","start":{"dateTime":"2027-01-06T09:00:00.0000000","timeZone":"UTC"}}]}"#,
            ))
            .with(ReplayRule::get(VIEW).header("authorization", "Bearer EwB.token").answers(
                200,
                r#"{"value":[{"id":"e1","start":{"dateTime":"2027-01-05T09:00:00.0000000","timeZone":"UTC"}}],
                    "@odata.nextLink":"https://graph.microsoft.com/v1.0/me/calendars/AAMk=/calendarView?startDateTime=x&$skiptoken=p2"}"#,
            ));
        let changes = api(&http, &clock)
            .changes_since(&token(), "AAMk=", Some("ignored"))
            .await
            .unwrap();
        assert!(changes.snapshot);
        assert_eq!(
            changes
                .changes
                .iter()
                .map(|change| change.remote_id.as_str())
                .collect::<Vec<_>>(),
            vec!["e1", "e2"]
        );
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        let first = &requests[0];
        assert_eq!(first.header("authorization"), Some("Bearer EwB.token"));
        assert_eq!(first.header("prefer"), Some("outlook.body-content-type=\"text\""));
        assert_eq!(first.query_value("$top").as_deref(), Some("50"));
        assert!(first.query_value("$select").unwrap().contains("lastModifiedDateTime"));
        let from = chrono::DateTime::parse_from_rfc3339(&first.query_value("startDateTime").unwrap()).unwrap();
        let until = chrono::DateTime::parse_from_rfc3339(&first.query_value("endDateTime").unwrap()).unwrap();
        assert_eq!(
            (until - from).num_days(),
            90 + 365,
            "the window of the configuration around the time of the clock"
        );
        assert!(http.unmatched().is_empty(), "{:?}", http.unmatched());
    }

    #[tokio::test]
    async fn a_next_page_outside_graph_is_not_followed() {
        let clock = ManualClock::default();
        for link in [
            "https://evil.example/v1.0/me/calendarView",
            "http://graph.microsoft.com/v1.0/me/calendarView",
            "https://user:pw@graph.microsoft.com/v1.0/me/calendarView",
            "not a url",
        ] {
            let http = ReplayHttp::new().with(ReplayRule::get(VIEW).answers(
                200,
                format!(
                    r#"{{"value":[],"@odata.nextLink":{}}}"#,
                    serde_json::to_string(link).unwrap()
                ),
            ));
            let error = api(&http, &clock)
                .changes_since(&token(), "AAMk=", None)
                .await
                .unwrap_err();
            assert_eq!(error.kind, PortErrorKind::Unavailable, "{link}");
            assert_eq!(http.requests().len(), 1, "the token went nowhere else: {link}");
        }
    }

    #[tokio::test]
    async fn errors_are_mapped_for_the_sync_engine() {
        let clock = ManualClock::default();
        for (status, body, kind) in [
            (
                401,
                r#"{"error":{"code":"InvalidAuthenticationToken"}}"#,
                PortErrorKind::Rejected,
            ),
            (
                404,
                r#"{"error":{"code":"ErrorItemNotFound"}}"#,
                PortErrorKind::Rejected,
            ),
            (429, "", PortErrorKind::Unavailable),
            (503, "", PortErrorKind::Unavailable),
            (200, "<html>captive portal</html>", PortErrorKind::Unavailable),
        ] {
            let http = ReplayHttp::new().with(ReplayRule::get(VIEW).answers(status, body));
            let error = api(&http, &clock)
                .changes_since(&token(), "AAMk=", None)
                .await
                .unwrap_err();
            assert_eq!(error.kind, kind, "{status}: {error}");
            assert!(!error.message.contains("EwB"), "{error}");
        }
    }

    #[tokio::test]
    async fn a_calendar_that_is_too_large_is_refused_instead_of_cut() {
        let clock = ManualClock::default();
        let page = format!(
            r#"{{"value":[{}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/me/calendars/AAMk=/calendarView?$skiptoken=more"}}"#,
            (0..50)
                .map(|n| format!(r#"{{"id":"e{n}","start":{{"dateTime":"2027-01-05T09:00:00","timeZone":"UTC"}}}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let http = ReplayHttp::new().with(ReplayRule::get(VIEW).answers(200, page));
        let error = api(&http, &clock)
            .changes_since(&token(), "AAMk=", None)
            .await
            .unwrap_err();
        assert_eq!(
            error.kind,
            PortErrorKind::Unsupported,
            "not `Rejected`: a renewed token does not make the calendar smaller"
        );
        assert!(error.message.contains("10000"), "{error}");
        assert_eq!(http.requests().len(), MAX_EVENTS / PAGE_SIZE + 1);
    }

    #[tokio::test]
    async fn a_provider_that_goes_on_answering_empty_pages_is_not_followed_for_ever() {
        let clock = ManualClock::default();
        let http = ReplayHttp::new().with(ReplayRule::get(VIEW).answers(
            200,
            r#"{"value":[],"@odata.nextLink":"https://graph.microsoft.com/v1.0/me/calendars/AAMk=/calendarView?$skiptoken=more"}"#,
        ));
        let error = api(&http, &clock)
            .changes_since(&token(), "AAMk=", None)
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable, "{error}");
        assert_eq!(
            http.requests().len(),
            MAX_EVENT_PAGES,
            "one request per page, up to the cap"
        );
    }
}
