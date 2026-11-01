//! The details a subscription with `include_details` receives next to the ids of an event.
//!
//! Webhook payloads are thin by default (ids, natural keys, ETags). A subscription that sets `include_details`
//! gets `data.details` as well: for every object the event is about, its summary and times.
//!
//! ```json
//! "details": { "objects": [ {
//!   "object": "018f…", "summary": "Planning", "restricted": false,
//!   "start": "2027-02-01T09:00:00Z", "end": "2027-02-01T10:30:00Z", "recurring": false
//! } ] }
//! ```
//!
//! `start` is the start of the first instance and `end` the end of the last one (`null` when the series has no
//! end). Objects of the classes `PRIVATE` and `CONFIDENTIAL` are `restricted`: they come without summary.
//!
//! # Whose events are described
//!
//! Only objects of **managed and group calendars**. A webhook subscription belongs to the tenant, and a tenant
//! token never reaches the personal or user calendars of principals (PLAN 2.6), so an event about an object of a
//! personal calendar, a user calendar or a mirror calendar is delivered with ids only, as if the subscription had
//! not asked for details. Objects that no longer exist are left out as well.
//!
//! The application reads the details when it fans an event out and writes them into the delivery
//! (`WebhookDelivery::details`); the summary comes from the iCalendar layer through [`CalendarBackend`], so no
//! adapter parses calendar data and the restriction cannot be bypassed by a handler that loads objects itself.

use chrono::{DateTime, Utc};
use davhaven_domain::events::ObjectChangeKind;
use davhaven_domain::{CalendarKind, Classification, Envelope, EventPayload, ObjectId, TenantId};
use davhaven_ports::{StoreError, TxMode};
use serde_json::{Value, json};

use crate::imip::CalendarBackend;
use crate::wiring::AppCore;

/// The most objects one event describes (the event itself lists at most as many changes).
const MAX_OBJECTS: usize = davhaven_domain::events::MAX_LISTED_CHANGES;

/// The longest summary, in characters.
const MAX_SUMMARY_CHARS: usize = 200;

/// The objects an event is about.
fn objects_of(envelope: &Envelope) -> Vec<ObjectId> {
    match &envelope.data {
        EventPayload::ObjectsChanged(payload) => payload
            .changes
            .iter()
            .filter(|change| change.kind != ObjectChangeKind::Deleted)
            .filter_map(|change| change.object)
            .take(MAX_OBJECTS)
            .collect(),
        EventPayload::SchedulingReply(payload) => payload.object.into_iter().collect(),
        EventPayload::Rsvp(payload) => vec![payload.object],
        EventPayload::MailFailure(payload) => payload.object.into_iter().collect(),
        _ => Vec::new(),
    }
}

/// An object that may be described, as the first transaction read it.
struct Candidate {
    id: ObjectId,
    restricted: bool,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    recurring: bool,
    /// The iCalendar text, for objects whose summary may be shown.
    data: Option<String>,
}

/// A summary on one line without control characters, cut to [`MAX_SUMMARY_CHARS`]; `None` for an empty one.
fn one_line(text: &str) -> Option<String> {
    let line: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let line: String = line.trim().chars().take(MAX_SUMMARY_CHARS).collect();
    (!line.is_empty()).then_some(line)
}

/// The `details` of an event, or `None` when it is about no object that may be described.
///
/// A summary that cannot be read (the calendar layer is not available, the data is damaged) is left out: details
/// are an addition, and the event is delivered without them rather than not at all.
///
/// # Errors
///
/// Store failures other than a missing object or calendar.
pub(crate) async fn details(
    core: &AppCore,
    backend: &dyn CalendarBackend,
    tenant: TenantId,
    envelope: &Envelope,
) -> Result<Option<Value>, StoreError> {
    let ids = objects_of(envelope);
    if ids.is_empty() {
        return Ok(None);
    }
    let mut candidates = Vec::new();
    {
        let mut tx = core.deps().database.begin(tenant, TxMode::ReadOnly).await?;
        for id in ids {
            let object = match tx.objects().get_by_id(id).await {
                Ok(object) => object,
                Err(StoreError::NotFound) => continue,
                Err(error) => return Err(error),
            };
            let calendar = match tx.calendars().get(object.calendar_id).await {
                Ok(calendar) => calendar,
                Err(StoreError::NotFound) => continue,
                Err(error) => return Err(error),
            };
            if calendar.deleted_at.is_some() || !matches!(calendar.kind, CalendarKind::Group | CalendarKind::Managed) {
                continue;
            }
            let restricted = object.class != Classification::Public;
            candidates.push(Candidate {
                id: object.id,
                restricted,
                start: object.first_start,
                end: object.last_end,
                recurring: object.is_recurring,
                data: (!restricted).then_some(object.data),
            });
        }
        tx.commit().await?;
    }
    let mut objects = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let summary = match &candidate.data {
            Some(data) => backend
                .describe(data)
                .await
                .ok()
                .and_then(|event| event.summary)
                .and_then(|summary| one_line(&summary)),
            None => None,
        };
        objects.push(json!({
            "object": candidate.id,
            "summary": summary,
            "restricted": candidate.restricted,
            "start": candidate.start,
            "end": candidate.end,
            "recurring": candidate.recurring,
        }));
    }
    Ok((!objects.is_empty()).then(|| json!({ "objects": objects })))
}

#[cfg(test)]
mod tests;
