//! The reading tools: `list_calendars`, `list_events`, `get_event` and `search_events`.

use chrono::{DateTime, Duration, Utc};
use davhaven_app::AppResult;
use davhaven_app::services::{CalendarRef, EventSearch, ObjectSelector, PageRequest};
use davhaven_wire::mcp::{
    GetEventInput, GetEventOutput, ListCalendarsInput, ListCalendarsOutput, ListEventsInput, ListEventsOutput,
    SearchEventsInput,
};
use davhaven_wire::{EventView, Page};

use super::Settings;
use crate::caller::Caller;
use crate::input;
use crate::render;

/// `list_calendars`: the calendars of the person's home with the access they have to each.
pub(super) async fn list_calendars(caller: &Caller<'_>, _input: ListCalendarsInput) -> AppResult<ListCalendarsOutput> {
    let me = caller.me().await?;
    let bindings = caller.services.calendars.list_home(&caller.ctx, &me.name).await?;
    Ok(ListCalendarsOutput {
        calendars: bindings.iter().map(render::calendar).collect(),
    })
}

/// The page of a list: `limit` or the default page of the API limits, capped at `mcp.max_results`.
fn page_of(
    caller: &Caller<'_>,
    settings: &Settings<'_>,
    limit: Option<u32>,
    cursor: Option<davhaven_wire::Cursor>,
) -> PageRequest {
    let api = &caller.services.limits.api;
    let cap = settings.config.max_results.min(api.max_page_size);
    PageRequest {
        limit: Some(input::page_size(limit, api.default_page_size, cap)),
        cursor,
    }
}

/// `list_events`: the events of one calendar or of every visible one in a range, recurring events expanded.
pub(super) async fn list_events(
    caller: &Caller<'_>,
    settings: &Settings<'_>,
    input: ListEventsInput,
) -> AppResult<ListEventsOutput> {
    let range = input::time_range(input.start, input.end, settings.config.max_range_days)?;
    let search = EventSearch {
        calendars: input.calendar_id.map(CalendarRef::Id).into_iter().collect(),
        text: None,
        range: Some(range),
        expand: true,
    };
    let page = page_of(caller, settings, input.limit, input.cursor);
    let found = caller.services.objects.search_events(&caller.ctx, search, page).await?;
    events_page(caller, found, input.include_attendees).await
}

/// `get_event`: one event, or one instance of a recurring event.
pub(super) async fn get_event(caller: &Caller<'_>, input: GetEventInput) -> AppResult<GetEventOutput> {
    let view = caller
        .services
        .objects
        .get_event(
            &caller.ctx,
            &CalendarRef::Id(input.calendar_id),
            &ObjectSelector::Id(input.event_id),
            input.recurrence_id,
        )
        .await?;
    Ok(GetEventOutput {
        event: caller.event(view, input.include_attendees).await?,
    })
}

/// `search_events`: events by text in title, description and location within a range that starts now (the clock of the
/// application) and ends `mcp.max_range_days` later unless the call says otherwise.
pub(super) async fn search_events(
    caller: &Caller<'_>,
    settings: &Settings<'_>,
    input: SearchEventsInput,
) -> AppResult<ListEventsOutput> {
    let query = input::search_text(&input.query)?;
    let max_days = settings.config.max_range_days;
    let start = input.start.unwrap_or_else(|| caller.services.now());
    let end = input.end.unwrap_or_else(|| {
        start
            .checked_add_signed(Duration::days(i64::from(max_days)))
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    });
    let range = input::time_range(start, end, max_days)?;
    let search = EventSearch {
        calendars: input.calendar_id.map(CalendarRef::Id).into_iter().collect(),
        text: Some(query.to_owned()),
        range: Some(range),
        expand: true,
    };
    let page = page_of(caller, settings, input.limit, input.cursor);
    let found = caller.services.objects.search_events(&caller.ctx, search, page).await?;
    events_page(caller, found, input.include_attendees).await
}

/// The output of a listing: the events in their wire form, and whether another page follows. `truncated` is a cursor
/// that exists: the application only hands one out when more results are left.
async fn events_page(
    caller: &Caller<'_>,
    found: Page<EventView>,
    include_attendees: bool,
) -> AppResult<ListEventsOutput> {
    let Page { items, next_cursor } = found;
    Ok(ListEventsOutput {
        events: caller.events(items, include_attendees).await?,
        truncated: next_cursor.is_some(),
        next_cursor,
    })
}
