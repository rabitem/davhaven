//! The writing tools: `create_event`, `update_event`, `delete_event` and `respond_to_invitation`.
//!
//! All four act as the principal of the token through the services that DAV and the management API use, so the
//! decision (`mcp:write`, access to the calendar, managed and mirror calendars), the merge into the stored
//! component, scheduling, the change log, the domain events and the audit record (`mcp.write`, the tool and the ids,
//! never the content) are the services' own. The tools add the shape of the call and the wire form of the answer.
//!
//! The person behind the token is read **before** a write whenever the answer may say something about people: a
//! failure to describe the result must not come after the change, because an assistant that sees an error repeats the
//! call. A write-only token needs nothing else: reading the person (`PrincipalService::current`) takes no scope.

use davhaven_app::services::{
    CalendarRef, DeleteEventOptions, EventCreate, EventWrite, InvitationResponse, ObjectRef, ObjectSelector,
};
use davhaven_app::{AppResult, SafeMessage};
use davhaven_domain::EventData;
use davhaven_wire::EventView;
use davhaven_wire::mcp::{
    CreateEventInput, CreateEventOutput, DeleteEventInput, DeleteEventOutput, GetEventOutput, RespondToInvitationInput,
    UpdateEventInput,
};

use crate::caller::Caller;
use crate::input::{self, MAX_COMMENT_CHARS};

/// A title and a start are what an event needs to be one (`CreateEventInput::event`).
fn require_title_and_start(event: &EventData) -> AppResult<()> {
    let titled = event
        .summary
        .as_deref()
        .is_some_and(|summary| !summary.trim().is_empty());
    if !titled {
        return Err(input::field_error(
            "/event/summary",
            "required",
            SafeMessage::from_static("A new event needs a summary."),
        ));
    }
    if event.start.is_none() {
        return Err(input::field_error(
            "/event/start",
            "required",
            SafeMessage::from_static("A new event needs a start."),
        ));
    }
    Ok(())
}

/// `create_event`: a new event, or with a repeated `client_request_id` the event that id already made.
///
/// The id is the external key of the event: the UID derives from it (`UUIDv5(calendar, key)`). The service creates the
/// event **once**: a repeated call finds the event of the first one and returns it (`created: false`, nothing is written,
/// nobody is notified), and an id that already names an event with other content is a `conflict` that changes nothing,
/// so an assistant that reuses an id cannot rewrite an earlier event (or one that an integration manages).
pub(super) async fn create_event(caller: &Caller<'_>, input: CreateEventInput) -> AppResult<CreateEventOutput> {
    require_title_and_start(&input.event)?;
    if input.event.organizer.is_some() || input.event.attendees.as_ref().is_some_and(|people| !people.is_empty()) {
        // The answer will name people: read the person before anything is written.
        caller.me().await?;
    }
    let outcome = caller
        .services
        .objects
        .create_event(
            &caller.ctx,
            &CalendarRef::Id(input.calendar_id),
            EventCreate {
                key: input.client_request_id,
                event: EventView::from_data(input.event),
                notify_attendees: input.notify_attendees,
            },
        )
        .await?;
    Ok(CreateEventOutput {
        event: caller.event(outcome.event, false).await?,
        created: outcome.created,
    })
}

/// `update_event`: merges the changes into the stored event like a JSON Merge Patch (RFC 7396): fields that are absent
/// keep their value, fields that are `null` are removed.
///
/// `scope` and `recurrence_id` say which instances of a recurring event change; the instance is part of the call, so
/// it replaces any `recurrence_id` inside `changes`. `if_match` makes the change conditional on the entity tag the
/// assistant read.
pub(super) async fn update_event(caller: &Caller<'_>, input: UpdateEventInput) -> AppResult<GetEventOutput> {
    // The event may have people: read the person before anything is written.
    caller.me().await?;
    let mut changes = input.changes;
    if input.recurrence_id.is_some() {
        changes.recurrence_id = input.recurrence_id;
    }
    let write = EventWrite {
        target: Some(ObjectSelector::Id(input.event_id)),
        event: EventView::from_data(changes),
        notify_attendees: input.notify_attendees,
        if_match: input.if_match,
        scope: input.scope,
    };
    let outcome = caller
        .services
        .objects
        .put_event(&caller.ctx, &CalendarRef::Id(input.calendar_id), write)
        .await?;
    Ok(GetEventOutput {
        event: caller.event(outcome.event, false).await?,
    })
}

/// `delete_event`: the event, one instance of it, or an instance and every later one.
///
/// A whole event that is not there is `deleted: false`: the call asked for the event to be gone, and it is. The
/// service says so only after it decided that the person may delete in this calendar, so a denied deletion (an
/// invisible calendar, a read-only share) is a denial and never a success that did nothing. An instance of an event
/// that is not there and a stale `if_match` are `not-found` and `precondition-failed` as in the other channels.
pub(super) async fn delete_event(caller: &Caller<'_>, input: DeleteEventInput) -> AppResult<DeleteEventOutput> {
    let options = DeleteEventOptions {
        if_match: input.if_match,
        scope: input.scope,
        recurrence_id: input.recurrence_id,
        notify_attendees: input.notify_attendees,
    };
    let deleted = caller
        .services
        .objects
        .delete_event_if_present(
            &caller.ctx,
            &CalendarRef::Id(input.calendar_id),
            &ObjectSelector::Id(input.event_id),
            options,
        )
        .await?;
    Ok(DeleteEventOutput { deleted })
}

/// `respond_to_invitation`: accepts, declines or tentatively accepts an invitation the person received.
pub(super) async fn respond_to_invitation(
    caller: &Caller<'_>,
    input: RespondToInvitationInput,
) -> AppResult<GetEventOutput> {
    if !input.partstat.is_answer() {
        return Err(input::field_error(
            "/partstat",
            "not-an-answer",
            SafeMessage::from_static("The answer must be accepted, declined or tentative."),
        ));
    }
    if input
        .comment
        .as_deref()
        .is_some_and(|comment| comment.chars().count() > MAX_COMMENT_CHARS)
    {
        return Err(input::field_error(
            "/comment",
            "too-long",
            SafeMessage::sanitized(&format!("The comment is limited to {MAX_COMMENT_CHARS} characters.")),
        ));
    }
    // An invitation has people: read the person before anything is written.
    caller.me().await?;
    let view = caller
        .services
        .scheduling
        .respond(
            &caller.ctx,
            ObjectRef {
                calendar: CalendarRef::Id(input.calendar_id),
                object: ObjectSelector::Id(input.event_id),
            },
            InvitationResponse {
                partstat: input.partstat,
                comment: input.comment,
            },
        )
        .await?;
    Ok(GetEventOutput {
        event: caller.event(view, false).await?,
    })
}
