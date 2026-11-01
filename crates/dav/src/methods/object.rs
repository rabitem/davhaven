//! Calendar object resources: GET, HEAD, PUT, DELETE, MOVE and COPY (RFC 4791 section 5.3, RFC 4918 sections 9.3
//! to 9.9).
//!
//! The services do the work (validation, indexing, preconditions, the change log, scheduling); these handlers
//! translate the request into the service call and the outcome into the status and headers of the RFCs:
//!
//! | Method | Success | Headers |
//! | --- | --- | --- |
//! | `GET`, `HEAD` | 200 with `text/calendar` (or 304) | `ETag`, `Schedule-Tag`, `Last-Modified` |
//! | `PUT` | 201 created, 204 replaced | `ETag` only when the stored bytes equal the request body (RFC 4791 section 5.3.4), `Schedule-Tag` |
//! | `DELETE` | 204 | |
//! | `MOVE`, `COPY` | 201 target created, 204 target replaced | |
//!
//! A `PUT` body larger than `max_resource_size` answers 403 `CALDAV:max-resource-size`, a body that is not UTF-8
//! 403 `CALDAV:valid-calendar-data`. The media type is the service's to judge (`PutRequest::content_type`).

use axum::body::Body;
use axum::http::header::ETAG;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use davhaven_app::services::{
    CopyRequest, DeleteRequest, MoveRequest, ObjectView, PutOutcome, PutRequest, WritePrecondition,
};
use davhaven_domain::ResourcePath;
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use super::headers;
use super::{Call, Representation, read_text_body, represent, set_header, status_only};
use crate::props::object_content_type;

/// `Schedule-Tag` of RFC 6638.
const SCHEDULE_TAG: axum::http::HeaderName = axum::http::HeaderName::from_static("schedule-tag");

/// Serves GET and HEAD of a calendar object.
pub(crate) async fn get(call: &Call<'_>, head: bool) -> Result<Response, EdgeProblem> {
    let view = call.services().objects.get(call.ctx, call.resource).await?;
    object_response(call.headers(), view, head)
}

/// The answer to `GET` and `HEAD` of an object: the calendar data with its validators (`ETag`, `Schedule-Tag`,
/// `Last-Modified`), or the status the conditional headers of the request ask for instead (304, 412).
fn object_response(request: &HeaderMap, view: ObjectView, head: bool) -> Result<Response, EdgeProblem> {
    let data = view.data.ok_or_else(|| EdgeProblem::new(ProblemCode::Internal))?;
    let mut response = represent(
        request,
        head,
        Representation {
            content_type: &object_content_type(view.component),
            etag: &view.etag,
            last_modified: view.last_modified,
            body: data,
        },
    )?;
    if let Some(tag) = &view.schedule_tag {
        set_header(&mut response, SCHEDULE_TAG, tag.as_str());
    }
    Ok(response)
}

/// Serves a PUT of a calendar object.
pub(crate) async fn put(call: &Call<'_>, body: Body) -> Result<Response, EdgeProblem> {
    let preconditions = headers::write_precondition(call.headers())?;
    let text = read_text_body(
        call,
        body,
        ProblemCode::InvalidCalendarData,
        "The calendar data must be UTF-8.",
    )
    .await?;
    let request = PutRequest {
        path: call.resource.clone(),
        body: text,
        content_type: headers::text(call.headers(), "content-type"),
        preconditions,
        schedule_reply: headers::schedule_reply(call.headers()),
    };
    let outcome = call.services().objects.put(call.ctx, request).await?;
    Ok(put_response(&outcome))
}

/// The answer to a `PUT`: 201 or 204 with the `ETag` the stored bytes have only when they are the bytes the client
/// sent (RFC 4791 section 5.3.4) and the `Schedule-Tag` of a scheduling object resource.
fn put_response(outcome: &PutOutcome) -> Response {
    let mut response = status_only(if outcome.created {
        StatusCode::CREATED
    } else {
        StatusCode::NO_CONTENT
    });
    if let Some(etag) = &outcome.etag {
        set_header(&mut response, ETAG, etag.as_str());
    }
    if let Some(tag) = &outcome.schedule_tag {
        set_header(&mut response, SCHEDULE_TAG, tag.as_str());
    }
    response
}

/// Serves a DELETE of a calendar object.
pub(crate) async fn delete(call: &Call<'_>) -> Result<Response, EdgeProblem> {
    let request = DeleteRequest {
        path: call.resource.clone(),
        preconditions: headers::write_precondition(call.headers())?,
        schedule_reply: headers::schedule_reply(call.headers()),
    };
    call.services().objects.delete(call.ctx, request).await?;
    Ok(status_only(StatusCode::NO_CONTENT))
}

/// Which of the two relocating methods is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Relocation {
    /// `MOVE`: the source is removed.
    Move,
    /// `COPY`: the source stays.
    Copy,
}

/// Serves MOVE and COPY of a calendar object to the object resource named by `Destination`.
///
/// A destination on another server is 502 and one that is no object resource of this server (a collection, the
/// inbox) is 403. The conditional headers of a `MOVE` are evaluated by the service against the source; those of a
/// `COPY`, whose service call takes none, are evaluated here against the source as well.
pub(crate) async fn relocate(call: &Call<'_>, kind: Relocation) -> Result<Response, EdgeProblem> {
    let base = call.services().urls.dav_base();
    let ours = headers::Origin::new(base.host_str().unwrap_or_default(), base.port_or_known_default());
    let to = match headers::destination(call.headers(), &ours)? {
        headers::Destination::Here(path) => path,
        headers::Destination::Elsewhere => return Err(EdgeProblem::new(ProblemCode::ForeignDestination)),
    };
    if !matches!(to, ResourcePath::Object { .. }) {
        return Err(EdgeProblem::new(ProblemCode::Forbidden)
            .with_detail("The Destination must name a calendar object resource."));
    }
    if &to == call.resource {
        return Err(EdgeProblem::new(ProblemCode::Forbidden)
            .with_detail("The source and the destination are the same resource."));
    }
    let overwrite = headers::overwrite(call.headers())?;
    let from = call.resource.clone();
    let conditions = headers::write_precondition(call.headers())?;
    let outcome = match kind {
        Relocation::Move => {
            let request = MoveRequest {
                from,
                to,
                overwrite,
                preconditions: conditions,
            };
            call.services().objects.move_to(call.ctx, request).await?
        }
        Relocation::Copy => {
            if conditions != WritePrecondition::none() {
                let source = call.services().objects.get(call.ctx, &from).await?;
                headers::require_conditions(&conditions, &source.etag, source.schedule_tag.as_ref())?;
            }
            let request = CopyRequest { from, to, overwrite };
            call.services().objects.copy_to(call.ctx, request).await?
        }
    };
    Ok(status_only(if outcome.created {
        StatusCode::CREATED
    } else {
        StatusCode::NO_CONTENT
    }))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, LAST_MODIFIED};
    use chrono::{TimeZone, Utc};
    use davhaven_app::services::ScheduleOutcome;
    use davhaven_domain::{CalendarId, ComponentKind, ETag, ObjectId, PrivilegeSet, ScheduleTag, Uid};
    use uuid::Uuid;

    use super::*;

    const TAG: &str = "\"schedule-tag-1\"";

    fn view(schedule_tag: Option<&str>) -> ObjectView {
        ObjectView {
            path: ResourcePath::parse("/dav/calendars/acme/anna/work/meeting.ics").unwrap(),
            id: ObjectId::from_uuid(Uuid::from_u128(1)),
            calendar_id: CalendarId::from_uuid(Uuid::from_u128(2)),
            uid: Uid::parse("meeting-1@acme.example").unwrap(),
            component: ComponentKind::Event,
            etag: ETag::from_bytes(b"BEGIN:VCALENDAR"),
            schedule_tag: schedule_tag.map(|tag| ScheduleTag::parse(tag).unwrap()),
            size: 15,
            last_modified: Utc.with_ymd_and_hms(2027, 1, 2, 3, 4, 5).unwrap(),
            data: Some("BEGIN:VCALENDAR".to_owned()),
            privileges: PrivilegeSet::empty(),
        }
    }

    fn request(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn a_scheduling_object_is_served_with_its_schedule_tag() {
        let response = object_response(&HeaderMap::new(), view(Some(TAG)), false).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["schedule-tag"], TAG);
        assert_eq!(response.headers()[ETAG], view(None).etag.as_str());
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "text/calendar; charset=utf-8; component=vevent"
        );
        assert_eq!(response.headers()[LAST_MODIFIED], "Sat, 02 Jan 2027 03:04:05 GMT");
        assert_eq!(response.headers()[CACHE_CONTROL], "private, no-cache");
        let head = object_response(&HeaderMap::new(), view(Some(TAG)), true).unwrap();
        assert_eq!(head.headers()["schedule-tag"], TAG, "HEAD tells the tag as GET does");
        assert_eq!(head.headers()[CONTENT_LENGTH], "15");
    }

    #[test]
    fn an_object_that_does_not_schedule_has_no_schedule_tag() {
        let response = object_response(&HeaderMap::new(), view(None), false).unwrap();
        assert!(response.headers().get("schedule-tag").is_none());
    }

    #[test]
    fn a_conditional_read_does_not_carry_the_object() {
        let current = view(Some(TAG));
        let same = request(&[("if-none-match", current.etag.as_str())]);
        let response = object_response(&same, current.clone(), false).unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(response.headers()[ETAG], current.etag.as_str());
        let stale = request(&[("if-match", "\"another\"")]);
        let problem = object_response(&stale, current, false).unwrap_err();
        assert_eq!(problem.code(), ProblemCode::PreconditionFailed);
    }

    #[test]
    fn a_put_names_the_schedule_tag_of_what_it_stored() {
        let etag = ETag::from_bytes(b"stored");
        let outcome = |created, etag: Option<&ETag>, tag: Option<&str>| PutOutcome {
            etag: etag.cloned(),
            schedule_tag: tag.map(|tag| ScheduleTag::parse(tag).unwrap()),
            created,
            schedule: ScheduleOutcome::none(),
        };
        let created = put_response(&outcome(true, Some(&etag), Some(TAG)));
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(created.headers()[ETAG], etag.as_str());
        assert_eq!(created.headers()["schedule-tag"], TAG);
        let replaced = put_response(&outcome(false, None, Some(TAG)));
        assert_eq!(replaced.status(), StatusCode::NO_CONTENT);
        assert!(
            replaced.headers().get(ETAG).is_none(),
            "the server rewrote what the client sent, so it does not claim the tag of the client's bytes"
        );
        assert_eq!(replaced.headers()["schedule-tag"], TAG);
        let plain = put_response(&outcome(false, Some(&etag), None));
        assert!(plain.headers().get("schedule-tag").is_none());
    }
}
