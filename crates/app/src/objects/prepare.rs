//! Preparing an object for storage: validation, indexing, preconditions and conflict reporting.

use davhaven_domain::{
    CalendarId, CalendarUserAddress, ContentHash, Decision, ETag, Href, ObjectIndex, ObjectUri, Operation,
    Precondition, PrincipalId, RequestContext, ResourcePath, ScheduleTag, StoredObject, Uid, decide,
};
use davhaven_ical::{ErrorContext, ParsedCalendar, ValidatedObject};
use davhaven_ports::{StoreError, Tx, UniqueKey};

use super::locate::{WriteTarget, home_for};
use crate::authz::blocking;
use crate::error::{AppError, AppResult, SafeMessage};
use crate::principals::find_by_addresses;
use crate::services::{IfMatch, WritePrecondition};
use crate::wiring::AppCore;

/// An object that passed validation: parsed, indexed and hashed.
#[derive(Debug, Clone)]
pub(crate) struct Prepared {
    pub(crate) validated: ValidatedObject,
    pub(crate) index: ObjectIndex,
    pub(crate) hash: ContentHash,
}

impl Prepared {
    pub(crate) const fn calendar(&self) -> &ParsedCalendar {
        &self.validated.calendar
    }
}

/// Parses, validates, indexes and hashes iCalendar text on a blocking thread (PLAN 2.15: parsing runs in
/// `spawn_blocking` under a wall-clock budget).
///
/// # Errors
///
/// The CalDAV preconditions of invalid data: `valid-calendar-data`, `valid-calendar-object-resource`,
/// `max-resource-size`, `max-attendees-per-instance`, `max-instances`, the date limits, or `Unavailable` when the
/// budget runs out.
pub(crate) async fn prepare(core: &AppCore, text: &str) -> AppResult<Prepared> {
    let bytes = text.as_bytes().to_vec();
    blocking(core, ErrorContext::Store, move |limits| {
        let validated = davhaven_ical::validate::parse_and_validate(&bytes, limits)?;
        let index = davhaven_ical::index::index(&validated, limits)?;
        let hash = davhaven_ical::hash::content_hash(&validated.calendar)?;
        Ok(Prepared { validated, index, hash })
    })
    .await
}

/// Like [`prepare`] for a calendar that was parsed already (the result of a merge).
///
/// # Errors
///
/// As [`prepare`].
pub(crate) async fn prepare_calendar(core: &AppCore, calendar: ParsedCalendar) -> AppResult<(Prepared, String)> {
    blocking(core, ErrorContext::Store, move |limits| {
        let text = davhaven_ical::serialize::serialize(&calendar)?;
        let validated = davhaven_ical::validate::validate(calendar, limits)?;
        let index = davhaven_ical::index::index(&validated, limits)?;
        let hash = davhaven_ical::hash::content_hash(&validated.calendar)?;
        Ok((Prepared { validated, index, hash }, text))
    })
    .await
}

/// Whether `incoming` differs from the stored object `stored` at most in the state of alarms on a device:
/// acknowledgements and snoozes (`ACKNOWLEDGED`, `X-MOZ-LASTACK`, `X-MOZ-SNOOZE-TIME*`), and in the volatile stamps
/// (ADR 0004, rule 2). The stored text is parsed again, which is why only a write that is refused anyway asks.
///
/// # Errors
///
/// `Unavailable` when the budget runs out; stored data that no longer parses counts as a difference.
pub(crate) async fn differs_only_in_alarm_state(
    core: &AppCore,
    stored: &StoredObject,
    incoming: &Prepared,
) -> AppResult<bool> {
    let text = stored.data.clone();
    let incoming = incoming.calendar().clone();
    blocking(core, ErrorContext::Store, move |limits| {
        let Ok(stored) = davhaven_ical::parse::parse(text.as_bytes(), limits) else {
            return Ok(false);
        };
        Ok(davhaven_ical::hash::content_hash_ignoring_alarm_state(&stored)?
            == davhaven_ical::hash::content_hash_ignoring_alarm_state(&incoming)?)
    })
    .await
}

/// Checks the `Content-Type` of a `PUT`: absent or `text/calendar` (parameters are ignored).
///
/// # Errors
///
/// `Invalid` with `CALDAV:supported-calendar-data`.
pub(crate) fn check_media_type(content_type: Option<&str>) -> AppResult<()> {
    let Some(value) = content_type else {
        return Ok(());
    };
    let media = value.split(';').next().unwrap_or_default().trim();
    if media.eq_ignore_ascii_case("text/calendar") {
        Ok(())
    } else {
        Err(
            AppError::invalid(SafeMessage::from_static("Calendar data must be sent as text/calendar."))
                .with_precondition(Precondition::SupportedCalendarData),
        )
    }
}

/// Evaluates the conditional headers of a write against the stored object, in the order of PLAN 2.7:
/// `If-Schedule-Tag-Match`, then `If-Match`, then `If-None-Match: *`.
///
/// `merge_stale` says that the scheduler merges an attendee's write that is stale by `ETag` but current by
/// `Schedule-Tag` instead of answering `412`. The result says whether that excuse was used: the write is then
/// based on an older version than the stored one, and the scheduler decides in `before_write` whether that is
/// harmless for this writer (`WriteFacts::stale_etag_excused`).
///
/// # Errors
///
/// `PreconditionFailed`.
pub(crate) fn evaluate(
    preconditions: &WritePrecondition,
    existing: Option<&StoredObject>,
    merge_stale: bool,
) -> AppResult<bool> {
    let schedule_tag_matches = match (&preconditions.if_schedule_tag_match, existing) {
        (None, _) => None,
        (Some(wanted), Some(object)) => Some(object.schedule_tag.as_ref() == Some(wanted)),
        (Some(_), None) => Some(false),
    };
    if schedule_tag_matches == Some(false) {
        return Err(AppError::precondition_failed());
    }
    let etag_ok = match (&preconditions.if_match, existing) {
        (None, _) => true,
        (Some(IfMatch::Any), object) => object.is_some(),
        (Some(IfMatch::Tags(tags)), Some(object)) => tags.contains(&object.etag),
        (Some(IfMatch::Tags(_)), None) => false,
    };
    let excused = schedule_tag_matches == Some(true) && merge_stale;
    if !etag_ok && !excused {
        return Err(AppError::precondition_failed());
    }
    if preconditions.if_none_match_any && existing.is_some() {
        return Err(AppError::precondition_failed());
    }
    Ok(!etag_ok)
}

/// The principals the attendee addresses of an object resolve to (`object_attendees.principal_id`), in one lookup
/// for all of them: an event with 200 attendees must not cost 200 queries in a transaction that holds the calendar.
///
/// # Errors
///
/// Store failures.
pub(crate) async fn resolve_attendees(
    core: &AppCore,
    tx: &mut dyn Tx,
    scope: &WriteTarget<'_>,
    index: &ObjectIndex,
) -> AppResult<Vec<(CalendarUserAddress, PrincipalId)>> {
    if index.attendees.is_empty() {
        return Ok(Vec::new());
    }
    let addresses: Vec<CalendarUserAddress> = index
        .attendees
        .iter()
        .map(|attendee| attendee.address.clone())
        .collect();
    let found = find_by_addresses(tx, scope.tenant, &core.deps().urls, &addresses).await?;
    Ok(found
        .into_iter()
        .map(|(address, principal)| (address, principal.id))
        .collect())
}

/// The href of a stored object of the calendar, when the caller has the collection in a home.
fn href_in(scope: &WriteTarget<'_>, uri: &ObjectUri) -> Option<Href> {
    let (principal, binding) = scope.home?;
    Some(
        ResourcePath::Object {
            tenant: scope.tenant.slug.clone(),
            principal: principal.clone(),
            binding: binding.clone(),
            object: uri.clone(),
        }
        .href(),
    )
}

/// The href of the resource `uri` of another calendar, **only** when the caller can name it and read it: through
/// the caller's own binding of that calendar, and only when the decision for reading its objects is `Allow`.
/// Anything else would tell the caller that a calendar they cannot see exists and what is in it (PLAN 2.6).
async fn href_elsewhere(
    tx: &mut dyn Tx,
    ctx: &RequestContext,
    target: &WriteTarget<'_>,
    calendar: CalendarId,
    uri: &ObjectUri,
) -> Option<Href> {
    // Only principals have homes to be pointed at.
    let caller = ctx.principal()?;
    let facts = tx.calendars().access_facts(calendar, Some(caller)).await.ok()?;
    if decide(&ctx.subject(), ctx.channel, &facts, Operation::ReadObject) != Decision::Allow {
        return None;
    }
    let (principal, binding) = home_for(tx, ctx, calendar, target.calendar.owner_id).await.ok()??;
    Some(
        ResourcePath::Object {
            tenant: target.tenant.slug.clone(),
            principal,
            binding,
            object: uri.clone(),
        }
        .href(),
    )
}

/// Names the resource that caused a unique violation of a write (`C:no-uid-conflict` and
/// `C:unique-scheduling-object-resource` carry its href). The lookup happens while the calendar is still locked.
///
/// The href names only what the caller can see: a resource of the calendar they write to through their own
/// binding of it, a scheduling object of another calendar of the owner only when they can read that calendar too.
/// Otherwise a DAV caller gets the href of their home and the management API a plain conflict.
pub(crate) async fn conflict(
    tx: &mut dyn Tx,
    ctx: &RequestContext,
    target: &WriteTarget<'_>,
    key: UniqueKey,
    uid: &Uid,
) -> AppError {
    let plain = || AppError::from(StoreError::UniqueViolation(key));
    match key {
        UniqueKey::ObjectUid => match tx.objects().uri_for_uid(target.calendar.id, uid).await {
            Ok(Some(uri)) => match href_in(target, &uri) {
                Some(href) => AppError::conflict().with_precondition(Precondition::NoUidConflict(href)),
                None => plain(),
            },
            _ => plain(),
        },
        UniqueKey::SchedulingUid => match tx.objects().uri_for_scheduling_uid(target.calendar.owner_id, uid).await {
            Ok(Some((calendar, uri))) if calendar == target.calendar.id => match href_in(target, &uri) {
                Some(href) => {
                    AppError::conflict().with_precondition(Precondition::UniqueSchedulingObjectResource(href))
                }
                None => plain(),
            },
            Ok(Some((calendar, uri))) => {
                let href = match href_elsewhere(tx, ctx, target, calendar, &uri).await {
                    Some(href) => Some(href),
                    // The caller cannot see the other calendar: the best a DAV client gets is its own home.
                    None => target.home.map(|(principal, _)| {
                        ResourcePath::Home {
                            tenant: target.tenant.slug.clone(),
                            principal: principal.clone(),
                        }
                        .href()
                    }),
                };
                match href {
                    Some(href) => {
                        AppError::conflict().with_precondition(Precondition::UniqueSchedulingObjectResource(href))
                    }
                    None => plain(),
                }
            }
            _ => plain(),
        },
        _ => plain(),
    }
}

/// A fresh `Schedule-Tag` from an id.
pub(crate) fn fresh_schedule_tag(id: uuid::Uuid) -> ScheduleTag {
    ScheduleTag::from_uuid(id)
}

/// The `ETag` of stored text.
pub(crate) fn etag_of(text: &str) -> ETag {
    ETag::from_bytes(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;
    use davhaven_domain::{
        CalendarId, Classification, ComponentKind, ContentHash, ErrorKind, ExternalKey, ObjectId, PrincipalId,
    };
    use uuid::Uuid;

    use super::*;

    fn object(etag: &str, tag: Option<&str>) -> StoredObject {
        let at = DateTime::UNIX_EPOCH;
        StoredObject {
            id: ObjectId::from_uuid(Uuid::from_u128(1)),
            tenant_id: davhaven_domain::TenantId::from_uuid(Uuid::from_u128(2)),
            calendar_id: CalendarId::from_uuid(Uuid::from_u128(3)),
            owner_id: PrincipalId::from_uuid(Uuid::from_u128(4)),
            uri: ObjectUri::parse("a.ics").unwrap(),
            uid: Uid::parse("a").unwrap(),
            etag: ETag::from_bytes(etag.as_bytes()),
            schedule_tag: tag.map(|tag| ScheduleTag::parse(&format!("\"{tag}\"")).unwrap()),
            content_hash: ContentHash::from_digest([0; 32]),
            component: ComponentKind::Event,
            data: String::new(),
            size: 0,
            first_start: None,
            last_end: None,
            is_recurring: false,
            is_scheduling: false,
            organizer_address: None,
            sequence: 0,
            class: Classification::Public,
            external_key: None::<ExternalKey>,
            origin: None,
            created_at: at,
            updated_at: at,
            version: 1,
        }
    }

    fn failed<T>(result: AppResult<T>) -> bool {
        result.is_err_and(|error| error.kind() == ErrorKind::PreconditionFailed)
    }

    #[test]
    fn media_types_ignore_parameters_and_case() {
        for ok in [
            None,
            Some("text/calendar"),
            Some("TEXT/Calendar; charset=utf-8; component=vevent"),
        ] {
            assert!(check_media_type(ok).is_ok(), "{ok:?}");
        }
        for bad in ["text/plain", "application/json", "", "text/calendars"] {
            let error = check_media_type(Some(bad)).unwrap_err();
            assert_eq!(
                error.precondition().map(Precondition::code),
                Some("supported-calendar-data"),
                "{bad}"
            );
        }
    }

    #[test]
    fn if_match_needs_a_matching_representation() {
        let stored = object("a", None);
        let tags = |etag: &str| WritePrecondition::if_match(ETag::from_bytes(etag.as_bytes()));
        assert!(evaluate(&tags("a"), Some(&stored), false).is_ok());
        assert!(failed(evaluate(&tags("b"), Some(&stored), false)));
        assert!(
            failed(evaluate(&tags("a"), None, false)),
            "If-Match is false when nothing exists"
        );
        let any = WritePrecondition {
            if_match: Some(IfMatch::Any),
            ..WritePrecondition::default()
        };
        assert!(evaluate(&any, Some(&stored), false).is_ok());
        assert!(failed(evaluate(&any, None, false)));
        assert!(evaluate(&WritePrecondition::none(), None, false).is_ok());
    }

    #[test]
    fn if_none_match_needs_the_resource_to_be_absent() {
        let stored = object("a", None);
        assert!(evaluate(&WritePrecondition::create_only(), None, false).is_ok());
        assert!(failed(evaluate(
            &WritePrecondition::create_only(),
            Some(&stored),
            false
        )));
    }

    #[test]
    fn the_schedule_tag_is_evaluated_first_and_can_excuse_a_stale_etag() {
        let stored = object("a", Some("t1"));
        let tag = |text: &str| ScheduleTag::parse(&format!("\"{text}\"")).unwrap();
        let stale_etag = WritePrecondition {
            if_match: Some(IfMatch::Tags(vec![ETag::from_bytes(b"old")])),
            if_schedule_tag_match: Some(tag("t1")),
            ..WritePrecondition::default()
        };
        assert!(
            failed(evaluate(&stale_etag, Some(&stored), false)),
            "without a merging scheduler it is a 412"
        );
        assert_eq!(
            evaluate(&stale_etag, Some(&stored), true).ok(),
            Some(true),
            "the attendee's change is merged, and the scheduler is told that the excuse was used"
        );
        let current_etag = WritePrecondition {
            if_match: Some(IfMatch::Tags(vec![stored.etag.clone()])),
            if_schedule_tag_match: Some(tag("t1")),
            ..WritePrecondition::default()
        };
        assert_eq!(
            evaluate(&current_etag, Some(&stored), true).ok(),
            Some(false),
            "a current ETag needs no excuse"
        );
        let wrong_tag = WritePrecondition {
            if_schedule_tag_match: Some(tag("t2")),
            ..stale_etag.clone()
        };
        assert!(
            failed(evaluate(&wrong_tag, Some(&stored), true)),
            "a stale schedule tag is always a 412"
        );
        let no_object = WritePrecondition {
            if_schedule_tag_match: Some(tag("t1")),
            ..WritePrecondition::default()
        };
        assert!(failed(evaluate(&no_object, None, true)));
        // The ETag of the stored object does not matter when only the schedule tag is conditional.
        assert!(evaluate(&no_object, Some(&stored), false).is_ok());
    }
}
