//! Calendar object resources: listing, batch upsert and access by external key.
//!
//! Events are exchanged as JSON (`EventView`) or, in batches, as iCalendar text; the services merge JSON into the
//! stored component and keep unknown properties, alarms and `X-` properties. A write through the API never
//! schedules unless the caller asks with `notify_attendees=true` (PLAN 2.8, 2.10). The `ETag` of an event is its
//! content ETag, identical to the one DAV serves.

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::ETAG;
use chrono::{DateTime, Utc};
use davhaven_app::services::{DeleteEventOptions, EventWrite, ObjectFilter, ObjectSelector, TimeRange};
use davhaven_domain::{CalendarSlug, ExternalKey, PrincipalName, TenantSlug};
use davhaven_http::{Authenticated, EdgeProblem};
use davhaven_wire::mcp::ChangeScope;
use davhaven_wire::{BatchRequest, BatchResult, EventView, FieldProblem, Page, ProblemCode};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::calendars::calendar_ref;
use crate::extract::{BatchBody, ContentTag, IdempotencyKeyHeader, JsonBody, Keys, PageParams, Paging, Params};
use crate::reply::Reply;
use crate::router::ApiState;

/// The routes of this module.
pub(crate) fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_objects))
        .routes(routes!(batch_objects))
        .routes(routes!(get_object_by_key, put_object_by_key, delete_object_by_key))
}

/// The filters of the object listing.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ObjectsQuery {
    /// Only objects that end after this instant (RFC 3339, written with `Z`; encode `+` as `%2B`).
    #[param(value_type = Option<String>, format = DateTime)]
    start: Option<DateTime<Utc>>,
    /// Only objects that start before this instant (RFC 3339).
    #[param(value_type = Option<String>, format = DateTime)]
    end: Option<DateTime<Utc>>,
    /// Only the object with this external key.
    #[param(value_type = Option<String>)]
    external_key: Option<ExternalKey>,
}

/// The options of writes and deletes of single events.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct NotifyQuery {
    /// Send scheduling messages to the attendees. Off by default: API writes do not schedule.
    #[serde(default)]
    notify_attendees: bool,
}

/// Lists the objects of a calendar as JSON events.
///
/// Recurring events are returned as their master and overrides, not expanded. Filter by time range or external key.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects",
    operation_id = "listObjects",
    tag = "events",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ObjectsQuery,
        PageParams
    ),
    responses((status = 200, description = "A page of events.", body = Page<EventView>))
)]
pub(crate) async fn list_objects(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
    Params(query): Params<ObjectsQuery>,
    paging: Paging,
) -> Result<Reply, EdgeProblem> {
    let filter = ObjectFilter {
        range: (query.start.is_some() || query.end.is_some()).then(|| TimeRange::new(query.start, query.end)),
        external_key: query.external_key,
        ..ObjectFilter::default()
    };
    let page = state
        .services
        .objects
        .list(&ctx, &calendar_ref(owner, slug), filter, paging.request())
        .await?;
    Ok(paging.reply(&page))
}

/// The pointer of the batch entry with `key`: `/items/{index}`, `/deletes/{index}`, or the whole body.
fn entry_pointer(items: &[ExternalKey], deletes: &[ExternalKey], key: &ExternalKey) -> String {
    if let Some(index) = items.iter().position(|candidate| candidate == key) {
        format!("/items/{index}")
    } else if let Some(index) = deletes.iter().position(|candidate| candidate == key) {
        format!("/deletes/{index}")
    } else {
        String::new()
    }
}

/// The 422 problem of a batch that did not apply: one error per failed entry, pointing at it.
fn batch_rejected(result: &BatchResult, items: &[ExternalKey], deletes: &[ExternalKey]) -> EdgeProblem {
    let mut problem = EdgeProblem::new(ProblemCode::ValidationFailed)
        .with_detail("The batch was rejected as a whole; nothing was written.");
    for entry in result.results.iter().filter(|entry| entry.problem.is_some()) {
        if let Some(failure) = &entry.problem {
            let message = failure.detail.clone().unwrap_or_else(|| failure.title.clone());
            let pointer = entry_pointer(items, deletes, &entry.external_key);
            problem = problem.with_error(FieldProblem::new(pointer, failure.code.code(), message));
        }
    }
    problem
}

/// Upserts and deletes objects of a calendar in one transaction.
///
/// All or nothing: when any entry fails the whole batch is rejected with 422 and one error per failed entry. Up to
/// 1000 entries; `Idempotency-Key` is required. The UID of an entry is derived from the calendar and its external
/// key unless the event carries one. One `calendar.objects_changed` event is emitted; the batch never schedules.
#[utoipa::path(
    post,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/batch",
    operation_id = "batchObjects",
    tag = "events",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug.")
    ),
    request_body = BatchRequest,
    responses((status = 200, description = "The outcome of every entry.", body = BatchResult))
)]
pub(crate) async fn batch_objects(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug)): Keys<(TenantSlug, PrincipalName, CalendarSlug)>,
    key: IdempotencyKeyHeader,
    BatchBody(request): BatchBody<BatchRequest>,
) -> Result<Reply, EdgeProblem> {
    key.require()?;
    request.validate(&state.services.limits.api).map_err(|error| {
        EdgeProblem::new(ProblemCode::ValidationFailed)
            .with_detail("The batch is invalid.")
            .with_error(FieldProblem::new(error.pointer, "invalid-batch", error.message))
    })?;
    let items: Vec<ExternalKey> = request.items.iter().map(|item| item.external_key.clone()).collect();
    let deletes = request.deletes.clone();
    let result = state
        .services
        .objects
        .batch(&ctx, &calendar_ref(owner, slug), request)
        .await?;
    if result.has_failures() {
        return Err(batch_rejected(&result, &items, &deletes));
    }
    Ok(Reply::json(StatusCode::OK, &result).replayable())
}

/// A JSON reply with the content ETag of the event.
fn event_reply(status: StatusCode, event: &EventView) -> Reply {
    let reply = Reply::json(status, event);
    match &event.etag {
        Some(etag) => reply.with_header(ETAG, etag.as_str()),
        None => reply,
    }
}

/// Reads an event by its external key.
#[utoipa::path(
    get,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/by-key/{external_key}",
    operation_id = "getObjectByKey",
    tag = "events",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ("external_key" = String, Path, description = "The external key (`[A-Za-z0-9._:~-]`, 1 to 200 characters).")
    ),
    responses((status = 200, description = "The event.", body = EventView,
        headers(("ETag" = String, description = "The content ETag of the event."))))
)]
pub(crate) async fn get_object_by_key(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug, key)): Keys<(TenantSlug, PrincipalName, CalendarSlug, ExternalKey)>,
) -> Result<Reply, EdgeProblem> {
    let event = state
        .services
        .objects
        .get_by_key(&ctx, &calendar_ref(owner, slug), &key)
        .await?;
    Ok(event_reply(StatusCode::OK, &event))
}

/// Creates or replaces an event by its external key.
///
/// The body is merged into the stored event like a JSON Merge Patch (RFC 7396) for the members of the event: a field
/// with a value replaces the stored one, a field that is absent keeps it and a field that is `null` is removed
/// (`location: null` clears the location). A member that is an object or a list replaces the stored one as a whole
/// (`recurrence`, `organizer`, `alarms`: a `recurrence` with only `exdates` drops the stored rule); attendees are
/// matched by address. `uid` and `start` cannot be removed and refuse `null` (422 at the pointer of the member);
/// `null` for `recurrence_id` and `sequence` is the same as leaving them out. Unknown properties, alarms and `X-`
/// properties are preserved.
/// `If-Match` takes the content ETag of the event.
#[utoipa::path(
    put,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/by-key/{external_key}",
    operation_id = "putObjectByKey",
    tag = "events",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ("external_key" = String, Path, description = "The external key."),
        ("If-Match" = Option<String>, Header, description = "The content ETag of the event the request applies to; a mismatch answers 412."),
        NotifyQuery
    ),
    request_body = EventView,
    responses(
        (status = 201, description = "The event was created.", body = EventView,
            headers(("ETag" = String), ("Location" = String))),
        (status = 200, description = "The event was replaced or left unchanged.", body = EventView,
            headers(("ETag" = String)))
    )
)]
pub(crate) async fn put_object_by_key(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((tenant, owner, slug, key)): Keys<(TenantSlug, PrincipalName, CalendarSlug, ExternalKey)>,
    ContentTag(if_match): ContentTag,
    Params(options): Params<NotifyQuery>,
    JsonBody(mut event): JsonBody<EventView>,
) -> Result<Reply, EdgeProblem> {
    if event.external_key.as_ref().is_some_and(|given| given != &key) {
        return Err(EdgeProblem::new(ProblemCode::ValidationFailed)
            .with_detail("The external key of the body differs from the one in the path.")
            .with_error(FieldProblem::new(
                "/external_key",
                "mismatch",
                "must equal the external key of the path",
            )));
    }
    event.external_key = Some(key.clone());
    let location = state.location(&format!(
        "tenants/{tenant}/principals/{owner}/calendars/{slug}/objects/by-key/{key}"
    ));
    let write = EventWrite {
        target: Some(ObjectSelector::Key(key)),
        event,
        notify_attendees: options.notify_attendees,
        if_match,
        scope: ChangeScope::default(),
    };
    let outcome = state
        .services
        .objects
        .put_event(&ctx, &calendar_ref(owner, slug), write)
        .await?;
    if outcome.created {
        let reply = event_reply(StatusCode::CREATED, &outcome.event);
        Ok(match &location {
            Some(url) => reply.with_location(url),
            None => reply,
        })
    } else {
        Ok(event_reply(StatusCode::OK, &outcome.event))
    }
}

/// Deletes an event by its external key.
///
/// Deleting an event that organizes a meeting sends cancellations only with `notify_attendees=true`.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant}/principals/{principal}/calendars/{calendar}/objects/by-key/{external_key}",
    operation_id = "deleteObjectByKey",
    tag = "events",
    params(
        ("tenant" = String, Path, description = "The tenant slug."),
        ("principal" = String, Path, description = "The immutable name of the principal; for calendars and what belongs to them, the owner."),
        ("calendar" = String, Path, description = "The immutable calendar slug."),
        ("external_key" = String, Path, description = "The external key."),
        ("If-Match" = Option<String>, Header, description = "The content ETag of the event the request applies to; a mismatch answers 412."),
        NotifyQuery
    ),
    responses((status = 204, description = "The event was deleted."))
)]
pub(crate) async fn delete_object_by_key(
    State(state): State<ApiState>,
    Authenticated(ctx): Authenticated,
    Keys((_tenant, owner, slug, key)): Keys<(TenantSlug, PrincipalName, CalendarSlug, ExternalKey)>,
    ContentTag(if_match): ContentTag,
    Params(options): Params<NotifyQuery>,
) -> Result<Reply, EdgeProblem> {
    let options = DeleteEventOptions {
        if_match,
        notify_attendees: options.notify_attendees,
        ..DeleteEventOptions::default()
    };
    state
        .services
        .objects
        .delete_by_key(&ctx, &calendar_ref(owner, slug), &key, options)
        .await?;
    Ok(Reply::no_content())
}

#[cfg(test)]
mod tests {
    use davhaven_domain::SyncToken;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn keys(names: &[&str]) -> Vec<ExternalKey> {
        serde_json::from_value(json!(names)).unwrap()
    }

    #[test]
    fn a_rejected_batch_points_at_every_failed_entry_and_only_at_those() {
        // The fake application never fails a deletion, so the pointers into `deletes` and the fallback to the title
        // are checked here, on the rejection the handler builds from the result of the service.
        let result = BatchResult {
            sync_token: SyncToken::new(Uuid::nil(), Uuid::nil(), 0),
            results: serde_json::from_value(json!([
                {"external_key": "a", "outcome": "created"},
                {"external_key": "b", "outcome": "failed",
                 "problem": {"type": "urn:davhaven:problem:validation-failed", "title": "Validation failed",
                             "status": 422, "code": "validation-failed", "detail": "The iCalendar data is not valid."}},
                {"external_key": "gone", "outcome": "failed",
                 "problem": {"type": "urn:davhaven:problem:forbidden", "title": "Forbidden", "status": 403,
                             "code": "forbidden"}},
                {"external_key": "replaced", "outcome": "failed",
                 "problem": {"type": "urn:davhaven:problem:conflict", "title": "Conflict", "status": 409,
                             "code": "conflict"}}
            ]))
            .unwrap(),
        };
        let problem = batch_rejected(&result, &keys(&["a", "b"]), &keys(&["x", "gone"]));
        assert_eq!(problem.code(), ProblemCode::ValidationFailed);
        assert_eq!(
            problem.detail(),
            Some("The batch was rejected as a whole; nothing was written.")
        );
        assert_eq!(
            problem.errors(),
            [
                FieldProblem::new("/items/1", "validation-failed", "The iCalendar data is not valid."),
                FieldProblem::new("/deletes/1", "forbidden", "Forbidden"),
                // A key that `replace` mode deleted is in neither list: the whole body.
                FieldProblem::new("", "conflict", "Conflict"),
            ]
        );
    }
}
