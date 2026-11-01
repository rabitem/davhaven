//! Calendar objects and their attendees, under the write invariant of PLAN 2.7.
//!
//! `put`, `delete` and `move_to` check their preconditions first, then advance the calendar's `sync_seq` exactly
//! once per change, write the object and log the change at that sequence number. Nothing is changed when a check
//! fails, and the transaction's snapshot undoes everything on rollback.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{Calendar, CalendarId, ExternalKey, ObjectId, ObjectUri, PrincipalId, StoredObject, Uid};
use davhaven_ports::{
    ChangeKind, Expected, IndexFilter, NewVersion, ObjectAttendee, ObjectHead, ObjectRepo, PageReq, StoreError,
    StorePage, UniqueKey, WriteResult,
};

use super::{micros, no_nul, paginate};
use crate::state::TenantData;
use crate::tx::MemTx;

impl TenantData {
    /// The live object at `uri` in `calendar`.
    fn object_at(&self, calendar: CalendarId, uri: &ObjectUri) -> Option<&StoredObject> {
        self.objects
            .values()
            .find(|object| object.calendar_id == calendar && &object.uri == uri)
            .map(|object| &**object)
    }

    /// Whether an object other than `except` in `calendar` satisfies `taken`.
    fn other_in_calendar(
        &self,
        calendar: CalendarId,
        except: Option<ObjectId>,
        taken: impl Fn(&StoredObject) -> bool,
    ) -> bool {
        self.objects
            .values()
            .any(|object| object.calendar_id == calendar && Some(object.id) != except && taken(object))
    }

    /// Whether a live scheduling object of `owner` other than `except` has `uid`.
    fn scheduling_uid_taken(&self, owner: PrincipalId, uid: &Uid, except: Option<ObjectId>) -> bool {
        self.objects.values().any(|object| {
            object.owner_id == owner
                && &object.uid == uid
                && object.is_scheduling
                && Some(object.id) != except
                && self.object_is_live(object)
        })
    }

    /// The uniqueness rules of a write of `version` into `calendar`.
    fn check_unique(
        &self,
        calendar: &Calendar,
        version: &NewVersion,
        except: Option<ObjectId>,
    ) -> Result<(), StoreError> {
        if self.other_in_calendar(calendar.id, except, |object| object.uid == version.index.uid) {
            return Err(StoreError::UniqueViolation(UniqueKey::ObjectUid));
        }
        if let Some(key) = &version.external_key
            && self.other_in_calendar(calendar.id, except, |object| object.external_key.as_ref() == Some(key))
        {
            return Err(StoreError::UniqueViolation(UniqueKey::ExternalKey));
        }
        if version.index.is_scheduling && self.scheduling_uid_taken(calendar.owner_id, &version.index.uid, except) {
            return Err(StoreError::UniqueViolation(UniqueKey::SchedulingUid));
        }
        Ok(())
    }

    /// The attendee rows of a version. Principals that do not exist in the tenant are stored unresolved.
    fn attendee_rows(&self, object: ObjectId, version: &NewVersion) -> Vec<ObjectAttendee> {
        let mut seen = BTreeSet::new();
        let mut rows: Vec<ObjectAttendee> = version
            .index
            .attendees
            .iter()
            .filter(|attendee| seen.insert(attendee.address.as_str().to_owned()))
            .map(|attendee| ObjectAttendee {
                object_id: object,
                address: attendee.address.clone(),
                principal_id: version
                    .attendee_principals
                    .iter()
                    .find(|(address, _)| address == &attendee.address)
                    .map(|(_, principal)| *principal)
                    .filter(|principal| self.principals.contains_key(principal)),
                partstat: attendee.partstat,
            })
            .collect();
        rows.sort_by(|left, right| left.address.as_str().cmp(right.address.as_str()));
        rows
    }
}

/// Checks `expected` against the ETag found under the calendar lock.
fn check_expected(expected: &Expected, existing: Option<&str>) -> Result<(), StoreError> {
    let satisfied = match expected {
        Expected::Any => true,
        Expected::Absent => existing.is_none(),
        Expected::Etag(etag) => existing == Some(etag.as_str()),
    };
    if satisfied {
        Ok(())
    } else {
        Err(StoreError::PreconditionFailed)
    }
}

/// The whole of `put`.
fn write_object(
    data: &mut TenantData,
    calendar: CalendarId,
    version: NewVersion,
    expected: &Expected,
    now: DateTime<Utc>,
) -> Result<WriteResult, StoreError> {
    let calendar_row = data
        .calendars
        .get(&calendar)
        .filter(|row| row.deleted_at.is_none())
        .cloned()
        .ok_or(StoreError::NotFound)?;
    let existing = data.object_at(calendar, &version.uri).cloned();
    check_expected(expected, existing.as_ref().map(|object| object.etag.as_str()))?;
    data.check_unique(&calendar_row, &version, existing.as_ref().map(|object| object.id))?;
    let seq = data.bump_calendar(calendar).ok_or(StoreError::NotFound)?;
    let uri = version.uri.clone();
    let etag = version.etag.clone();
    let object_id = existing.as_ref().map_or(version.id, |object| object.id);
    let rows = data.attendee_rows(object_id, &version);
    let mut stored = version.into_stored(&calendar_row, now, existing.as_ref());
    stored.first_start = stored.first_start.map(micros);
    stored.last_end = stored.last_end.map(micros);
    data.objects.insert(object_id, Arc::new(stored));
    data.attendees.insert(object_id, rows);
    data.log_calendar_change(calendar, seq, &uri, ChangeKind::Upsert, now);
    Ok(WriteResult {
        object_id,
        seq,
        etag,
        created: existing.is_none(),
    })
}

/// The whole of `delete`.
fn delete_object(
    data: &mut TenantData,
    calendar: CalendarId,
    uri: &ObjectUri,
    expected: &Expected,
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    data.live_calendar_check(calendar)?;
    let Some(existing) = data.object_at(calendar, uri).cloned() else {
        // `If-Match` is false when no representation exists (RFC 7232 section 3.1): a 412, as for `put`.
        return Err(match expected {
            Expected::Etag(_) => StoreError::PreconditionFailed,
            Expected::Any | Expected::Absent => StoreError::NotFound,
        });
    };
    check_expected(expected, Some(existing.etag.as_str()))?;
    let seq = data.bump_calendar(calendar).ok_or(StoreError::NotFound)?;
    data.remove_object(existing.id);
    data.log_calendar_change(calendar, seq, uri, ChangeKind::Delete, now);
    Ok(seq)
}

/// The uniqueness checks of a move at the target.
fn check_move(
    data: &TenantData,
    moving: &StoredObject,
    target: &Calendar,
    target_uri: &ObjectUri,
) -> Result<(), StoreError> {
    if data.object_at(target.id, target_uri).is_some() {
        return Err(StoreError::UniqueViolation(UniqueKey::ObjectUri));
    }
    if data.other_in_calendar(target.id, Some(moving.id), |object| object.uid == moving.uid) {
        return Err(StoreError::UniqueViolation(UniqueKey::ObjectUid));
    }
    if let Some(key) = &moving.external_key
        && data.other_in_calendar(target.id, Some(moving.id), |object| {
            object.external_key.as_ref() == Some(key)
        })
    {
        return Err(StoreError::UniqueViolation(UniqueKey::ExternalKey));
    }
    if moving.is_scheduling && data.scheduling_uid_taken(target.owner_id, &moving.uid, Some(moving.id)) {
        return Err(StoreError::UniqueViolation(UniqueKey::SchedulingUid));
    }
    Ok(())
}

/// The whole of `move_to`.
fn move_object(
    data: &mut TenantData,
    source: CalendarId,
    uri: &ObjectUri,
    target: CalendarId,
    target_uri: &ObjectUri,
    now: DateTime<Utc>,
) -> Result<(u64, u64), StoreError> {
    data.live_calendar_check(source)?;
    let target_row = data
        .calendars
        .get(&target)
        .filter(|row| row.deleted_at.is_none())
        .cloned()
        .ok_or(StoreError::NotFound)?;
    let moving = data.object_at(source, uri).cloned().ok_or(StoreError::NotFound)?;
    check_move(data, &moving, &target_row, target_uri)?;
    let source_seq = data.bump_calendar(source).ok_or(StoreError::NotFound)?;
    data.log_calendar_change(source, source_seq, uri, ChangeKind::Delete, now);
    let target_seq = data.bump_calendar(target).ok_or(StoreError::NotFound)?;
    if let Some(stored) = data.objects.get_mut(&moving.id) {
        let stored = Arc::make_mut(stored);
        stored.calendar_id = target;
        stored.owner_id = target_row.owner_id;
        stored.uri = target_uri.clone();
        stored.updated_at = now;
        stored.version += 1;
    }
    data.log_calendar_change(target, target_seq, target_uri, ChangeKind::Upsert, now);
    Ok((source_seq, target_seq))
}

impl TenantData {
    /// `NotFound` unless the live calendar exists.
    fn live_calendar_check(&self, calendar: CalendarId) -> Result<(), StoreError> {
        if self.calendar_is_live(calendar) {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }
}

impl MemTx {
    fn live_object(&self, find: impl Fn(&StoredObject) -> bool) -> Option<StoredObject> {
        let data = self.view();
        data.objects
            .values()
            .find(|object| data.object_is_live(object) && find(object))
            .map(|object| StoredObject::clone(object))
    }

    fn query_objects(
        &self,
        calendar: CalendarId,
        filter: &IndexFilter,
        page: PageReq,
    ) -> Result<StorePage<StoredObject>, StoreError> {
        let data = self.view();
        data.live_calendar_check(calendar)?;
        let matching = data
            .objects
            .values()
            .filter(|object| object.calendar_id == calendar && filter.matches(object));
        Ok(paginate(
            matching.map(|object| StoredObject::clone(object)),
            &page,
            |object| object.id.as_uuid(),
        ))
    }
}

#[async_trait]
impl ObjectRepo for MemTx {
    async fn get(&mut self, calendar: CalendarId, uri: &ObjectUri) -> Result<StoredObject, StoreError> {
        observed!(
            "objects.get",
            self.live_object(|object| object.calendar_id == calendar && &object.uri == uri)
                .ok_or(StoreError::NotFound)
        )
    }

    async fn get_by_id(&mut self, id: ObjectId) -> Result<StoredObject, StoreError> {
        observed!(
            "objects.get_by_id",
            self.live_object(|object| object.id == id).ok_or(StoreError::NotFound)
        )
    }

    async fn get_by_uid(&mut self, calendar: CalendarId, uid: &Uid) -> Result<StoredObject, StoreError> {
        observed!(
            "objects.get_by_uid",
            self.live_object(|object| object.calendar_id == calendar && &object.uid == uid)
                .ok_or(StoreError::NotFound)
        )
    }

    async fn get_by_external_key(
        &mut self,
        calendar: CalendarId,
        key: &ExternalKey,
    ) -> Result<StoredObject, StoreError> {
        observed!(
            "objects.get_by_external_key",
            self.live_object(|object| object.calendar_id == calendar && object.external_key.as_ref() == Some(key))
                .ok_or(StoreError::NotFound)
        )
    }

    async fn find_scheduling_uid(&mut self, owner: PrincipalId, uid: &Uid) -> Result<Option<StoredObject>, StoreError> {
        observed!(
            "objects.find_scheduling_uid",
            Ok(self.live_object(|object| object.owner_id == owner && &object.uid == uid && object.is_scheduling))
        )
    }

    async fn put(
        &mut self,
        calendar: CalendarId,
        version: NewVersion,
        expected: Expected,
    ) -> Result<WriteResult, StoreError> {
        observed!("objects.put", {
            no_nul(
                "calendar object",
                [Some(version.data.as_str()), version.origin.as_deref()],
            )?;
            let now = self.now();
            write_object(self.writable()?, calendar, version, &expected, now)
        })
    }

    async fn delete(&mut self, calendar: CalendarId, uri: &ObjectUri, expected: Expected) -> Result<u64, StoreError> {
        observed!("objects.delete", {
            let now = self.now();
            delete_object(self.writable()?, calendar, uri, &expected, now)
        })
    }

    async fn move_to(
        &mut self,
        source: CalendarId,
        uri: &ObjectUri,
        target: CalendarId,
        target_uri: &ObjectUri,
    ) -> Result<(u64, u64), StoreError> {
        observed!("objects.move_to", {
            let now = self.now();
            move_object(self.writable()?, source, uri, target, target_uri, now)
        })
    }

    async fn query(
        &mut self,
        calendar: CalendarId,
        filter: &IndexFilter,
        page: PageReq,
    ) -> Result<StorePage<StoredObject>, StoreError> {
        observed!("objects.query", self.query_objects(calendar, filter, page))
    }

    async fn list(&mut self, calendar: CalendarId, page: PageReq) -> Result<StorePage<StoredObject>, StoreError> {
        observed!("objects.list", self.query_objects(calendar, &IndexFilter::all(), page))
    }

    async fn list_index(&mut self, calendar: CalendarId, page: PageReq) -> Result<StorePage<ObjectHead>, StoreError> {
        observed!("objects.list_index", {
            let page = self.query_objects(calendar, &IndexFilter::all(), page)?;
            Ok(page.map(|object| ObjectHead::from(&object)))
        })
    }

    async fn query_index(
        &mut self,
        calendar: CalendarId,
        filter: &IndexFilter,
        page: PageReq,
    ) -> Result<StorePage<ObjectHead>, StoreError> {
        observed!("objects.query_index", {
            let page = self.query_objects(calendar, filter, page)?;
            Ok(page.map(|object| ObjectHead::from(&object)))
        })
    }

    async fn uri_for_uid(&mut self, calendar: CalendarId, uid: &Uid) -> Result<Option<ObjectUri>, StoreError> {
        observed!("objects.uri_for_uid", {
            self.view().live_calendar_check(calendar)?;
            Ok(self
                .live_object(|object| object.calendar_id == calendar && &object.uid == uid)
                .map(|object| object.uri))
        })
    }

    async fn uri_for_scheduling_uid(
        &mut self,
        owner: PrincipalId,
        uid: &Uid,
    ) -> Result<Option<(CalendarId, ObjectUri)>, StoreError> {
        observed!(
            "objects.uri_for_scheduling_uid",
            Ok(self
                .live_object(|object| object.owner_id == owner && &object.uid == uid && object.is_scheduling)
                .map(|object| (object.calendar_id, object.uri)))
        )
    }

    async fn attendees(&mut self, object: ObjectId) -> Result<Vec<ObjectAttendee>, StoreError> {
        observed!("objects.attendees", {
            let data = self.view();
            if !data
                .objects
                .get(&object)
                .is_some_and(|found| data.object_is_live(found))
            {
                return Err(StoreError::NotFound);
            }
            Ok(data.attendees.get(&object).cloned().unwrap_or_default())
        })
    }
}
