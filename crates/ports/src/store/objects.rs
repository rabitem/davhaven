//! The repository for calendar objects: verbatim iCalendar data plus the index columns used for queries.
//!
//! # The write invariant (PLAN 2.7)
//!
//! [`ObjectRepo::put`], [`ObjectRepo::delete`] and [`ObjectRepo::move_to`] run in the caller's transaction and
//! always, as one unit:
//!
//! 1. advance the calendar's `sync_seq` (`UPDATE calendars SET sync_seq = sync_seq + 1 ... RETURNING sync_seq`),
//!    which serialises writers of that calendar and takes its row lock;
//! 2. check the [`Expected`] state under that lock;
//! 3. write the object and its change-log row at the new sequence number;
//! 4. return the sequence number (and the ETag).
//!
//! The change-log row is part of the write, so no caller can forget it, and the sequence number is used exactly
//! once per mutation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    Calendar, CalendarId, CalendarUserAddress, Classification, ComponentKind, ContentHash, ETag, ExternalKey, ObjectId,
    ObjectIndex, ObjectUri, PartStat, PrincipalId, ScheduleTag, StoredObject, Uid,
};

use super::{PageReq, StorePage};
use crate::error::StoreError;

/// The state the caller expects the object to be in, checked under the calendar lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    /// No expectation: create or replace (delete is idempotent only if the caller handles `NotFound`).
    Any,
    /// The object must not exist (`If-None-Match: *`).
    Absent,
    /// The object must exist with this ETag (`If-Match`).
    Etag(ETag),
}

/// A new version of an object, ready to store.
///
/// The application builds it from the client's bytes and the index `davhaven-ical` extracted. The store derives
/// the index columns of [`StoredObject`] from `index`, keeps `data` verbatim and fills in tenant, calendar, owner,
/// timestamps and version.
#[derive(Debug, Clone, PartialEq)]
pub struct NewVersion {
    /// The id to use if the object is created; ignored when an existing object is replaced.
    pub id: ObjectId,
    /// The resource name inside the calendar.
    pub uri: ObjectUri,
    /// The iCalendar text, verbatim.
    pub data: String,
    /// The strong ETag of `data`.
    pub etag: ETag,
    /// The new Schedule-Tag (scheduling objects); `None` clears it.
    pub schedule_tag: Option<ScheduleTag>,
    /// The content hash that ignores volatile properties.
    pub content_hash: ContentHash,
    /// The extracted index.
    pub index: ObjectIndex,
    /// For internal attendees: the principal each attendee address resolved to at write time
    /// (`object_attendees.principal_id`). Addresses that are not listed stay unresolved.
    pub attendee_principals: Vec<(CalendarUserAddress, PrincipalId)>,
    /// The caller-chosen key (management API).
    pub external_key: Option<ExternalKey>,
    /// Marker of the provider that imported the object (mirror calendars).
    pub origin: Option<String>,
}

impl NewVersion {
    /// Builds the [`StoredObject`] this version becomes in `calendar` at time `now`.
    ///
    /// `previous` is the object being replaced, if any: its id, creation time and version are carried over (the
    /// version is incremented). Adapters that do not map columns themselves (the memory store) use this to derive
    /// every index column from `index` in one place.
    pub fn into_stored(self, calendar: &Calendar, now: DateTime<Utc>, previous: Option<&StoredObject>) -> StoredObject {
        let size = u64::try_from(self.data.len()).unwrap_or(u64::MAX);
        StoredObject {
            id: previous.map_or(self.id, |object| object.id),
            tenant_id: calendar.tenant_id,
            calendar_id: calendar.id,
            owner_id: calendar.owner_id,
            uri: self.uri,
            uid: self.index.uid,
            etag: self.etag,
            schedule_tag: self.schedule_tag,
            content_hash: self.content_hash,
            component: self.index.component,
            data: self.data,
            size,
            first_start: self.index.first_start,
            last_end: self.index.last_end,
            is_recurring: self.index.is_recurring,
            is_scheduling: self.index.is_scheduling,
            organizer_address: self.index.organizer,
            sequence: self.index.sequence,
            class: self.index.class,
            external_key: self.external_key,
            origin: self.origin,
            created_at: previous.map_or(now, |object| object.created_at),
            updated_at: now,
            version: previous.map_or(1, |object| object.version.saturating_add(1)),
        }
    }
}

/// The result of a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    /// The id of the object (the existing one when it was replaced).
    pub object_id: ObjectId,
    /// The calendar's sequence number of this change.
    pub seq: u64,
    /// The ETag of the stored data.
    pub etag: ETag,
    /// Whether the object was created (`true`) or replaced (`false`).
    pub created: bool,
}

/// A time range of an index query; an absent bound is open. RFC 4791 section 9.9 ranges are half-open
/// (`[start, end)`), but the pre-filter treats both bounds as **inclusive** (see
/// [`davhaven_domain::index::interval_may_overlap`]), because some rows of the RFC table match when the range end
/// touches the anchor of the component (`DUE`, `COMPLETED`, a zero-length event).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeRange {
    /// The start, if bounded.
    pub start: Option<DateTime<Utc>>,
    /// The end, if bounded.
    pub end: Option<DateTime<Utc>>,
}

impl TimeRange {
    /// Whether an object spanning `[first_start, last_end]` can match the range. `None` for `first_start` means
    /// undated and `None` for `last_end` means unbounded (stored as infinity); both overlap everything on their
    /// open side. This is the superset pre-filter of PLAN 2.7: it never misses a match but may report one that
    /// exact evaluation rejects. It delegates to the one definition in `davhaven-domain`
    /// ([`davhaven_domain::index::interval_may_overlap`]), which the SQL of the PostgreSQL adapter mirrors
    /// (`last_end >= start AND first_start <= end`) and its tests compare against.
    pub fn may_overlap(&self, first_start: Option<DateTime<Utc>>, last_end: Option<DateTime<Utc>>) -> bool {
        davhaven_domain::index::interval_may_overlap(first_start, last_end, self.start, self.end)
    }
}

/// The index pre-filter of [`ObjectRepo::query`]. Every set field must match; the result is a superset of the
/// exact matches, which the application narrows down with `davhaven-ical`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IndexFilter {
    /// Only objects whose main component has this type.
    pub component: Option<ComponentKind>,
    /// Only objects whose indexed interval can overlap the range.
    pub time_range: Option<TimeRange>,
    /// Only the object with this UID.
    pub uid: Option<Uid>,
    /// Only objects with one of these resource names (multiget); `Some(vec![])` matches nothing.
    pub uris: Option<Vec<ObjectUri>>,
    /// Only the object with this external key.
    pub external_key: Option<ExternalKey>,
    /// Only objects whose external key starts with this prefix.
    pub external_key_prefix: Option<String>,
    /// Only objects organized by this address.
    pub organizer: Option<CalendarUserAddress>,
    /// Only scheduling (`true`) or non-scheduling (`false`) objects.
    pub is_scheduling: Option<bool>,
}

impl IndexFilter {
    /// A filter that matches every object.
    pub fn all() -> Self {
        Self::default()
    }

    /// Whether `object` passes the filter. Adapters that evaluate filters in memory (the memory store, test
    /// doubles) use this, so every adapter applies the same semantics as the SQL of the Postgres adapter.
    pub fn matches(&self, object: &StoredObject) -> bool {
        self.component.is_none_or(|component| component == object.component)
            && self
                .time_range
                .is_none_or(|range| range.may_overlap(object.first_start, object.last_end))
            && self.uid.as_ref().is_none_or(|uid| uid == &object.uid)
            && self.uris.as_ref().is_none_or(|uris| uris.contains(&object.uri))
            && self
                .external_key
                .as_ref()
                .is_none_or(|key| object.external_key.as_ref() == Some(key))
            && self.external_key_prefix.as_ref().is_none_or(|prefix| {
                object
                    .external_key
                    .as_ref()
                    .is_some_and(|key| key.as_str().starts_with(prefix.as_str()))
            })
            && self
                .organizer
                .as_ref()
                .is_none_or(|organizer| object.organizer_address.as_ref() == Some(organizer))
            && self
                .is_scheduling
                .is_none_or(|scheduling| scheduling == object.is_scheduling)
    }
}

/// An attendee row of an object (`object_attendees`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectAttendee {
    /// The object.
    pub object_id: ObjectId,
    /// The attendee's calendar user address.
    pub address: CalendarUserAddress,
    /// The internal principal the address resolved to when the object was written, if any.
    pub principal_id: Option<PrincipalId>,
    /// The attendee's participation status.
    pub partstat: PartStat,
}

/// A calendar object without its iCalendar text: everything [`StoredObject`] holds except `data`.
///
/// Listings that only need names, ETags and index columns (`PROPFIND` depth 1, an ETag-only `calendar-query`,
/// sync) use [`ObjectRepo::list_index`] and [`ObjectRepo::query_index`], which return heads, so a page of up to
/// [`MAX_PAGE_LIMIT`](super::MAX_PAGE_LIMIT) objects does not load that many resources of up to the
/// `max_resource_size` (`ENGINEERING_RULES` R14).
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectHead {
    /// The object id.
    pub id: ObjectId,
    /// The calendar the object lives in.
    pub calendar_id: CalendarId,
    /// The owner of the calendar.
    pub owner_id: PrincipalId,
    /// The resource name inside the calendar.
    pub uri: ObjectUri,
    /// The UID.
    pub uid: Uid,
    /// The strong ETag of the stored data.
    pub etag: ETag,
    /// The Schedule-Tag, for scheduling objects.
    pub schedule_tag: Option<ScheduleTag>,
    /// The content hash that ignores volatile properties.
    pub content_hash: ContentHash,
    /// The component type of the master component.
    pub component: ComponentKind,
    /// The size of the stored data in bytes.
    pub size: u64,
    /// The start of the first instance (see `ObjectIndex::first_start`).
    pub first_start: Option<DateTime<Utc>>,
    /// The end of the last instance (see `ObjectIndex::last_end`); `None` for infinity.
    pub last_end: Option<DateTime<Utc>>,
    /// Whether the object recurs.
    pub is_recurring: bool,
    /// Whether the object is a scheduling object resource.
    pub is_scheduling: bool,
    /// The organizer address.
    pub organizer_address: Option<CalendarUserAddress>,
    /// The `SEQUENCE` of the master component.
    pub sequence: i32,
    /// The `CLASS` of the master component.
    pub class: Classification,
    /// The caller-chosen key (management API).
    pub external_key: Option<ExternalKey>,
    /// Marker of the provider that imported the object.
    pub origin: Option<String>,
    /// When the object was created.
    pub created_at: DateTime<Utc>,
    /// When the object last changed.
    pub updated_at: DateTime<Utc>,
    /// The row version.
    pub version: i64,
}

impl From<&StoredObject> for ObjectHead {
    /// The head of a stored object (the memory store and test doubles derive heads this way).
    fn from(object: &StoredObject) -> Self {
        Self {
            id: object.id,
            calendar_id: object.calendar_id,
            owner_id: object.owner_id,
            uri: object.uri.clone(),
            uid: object.uid.clone(),
            etag: object.etag.clone(),
            schedule_tag: object.schedule_tag.clone(),
            content_hash: object.content_hash.clone(),
            component: object.component,
            size: object.size,
            first_start: object.first_start,
            last_end: object.last_end,
            is_recurring: object.is_recurring,
            is_scheduling: object.is_scheduling,
            organizer_address: object.organizer_address.clone(),
            sequence: object.sequence,
            class: object.class,
            external_key: object.external_key.clone(),
            origin: object.origin.clone(),
            created_at: object.created_at,
            updated_at: object.updated_at,
            version: object.version,
        }
    }
}

/// Calendar objects of the transaction's tenant.
#[async_trait]
pub trait ObjectRepo: Send {
    /// The object at `uri` in `calendar`.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar or the object does not exist.
    async fn get(&mut self, calendar: CalendarId, uri: &ObjectUri) -> Result<StoredObject, StoreError>;

    /// The object with `id`, wherever it lives in the tenant (RSVP and iTIP processing start from ids).
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_by_id(&mut self, id: ObjectId) -> Result<StoredObject, StoreError>;

    /// The object with `uid` in `calendar`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_by_uid(&mut self, calendar: CalendarId, uid: &Uid) -> Result<StoredObject, StoreError>;

    /// The object with the external key in `calendar`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_by_external_key(
        &mut self,
        calendar: CalendarId,
        key: &ExternalKey,
    ) -> Result<StoredObject, StoreError>;

    /// The scheduling object with `uid` among all calendars owned by `owner`
    /// (`C:unique-scheduling-object-resource`).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_scheduling_uid(&mut self, owner: PrincipalId, uid: &Uid) -> Result<Option<StoredObject>, StoreError>;

    /// Creates the object at `version.uri` or replaces the one that is there, under the write invariant of this
    /// module, after checking `expected`.
    ///
    /// # Errors
    ///
    /// * `NotFound`: the calendar does not exist.
    /// * `PreconditionFailed`: `expected` does not match.
    /// * `UniqueViolation` of `ObjectUid` (another resource in the calendar has the UID), `SchedulingUid` (another
    ///   calendar of the owner has a scheduling object with the UID) or `ExternalKey`.
    ///
    /// A failed write leaves no trace, including the calendar lock it took (the savepoint of the failed method is
    /// rolled back). The application names the conflicting resource (`C:no-uid-conflict` and
    /// `C:unique-scheduling-object-resource` carry its href) with [`uri_for_uid`](Self::uri_for_uid) or
    /// [`uri_for_scheduling_uid`](Self::uri_for_scheduling_uid) (or the heavier [`get_by_uid`](Self::get_by_uid) and
    /// [`find_scheduling_uid`](Self::find_scheduling_uid)) in the same transaction. The sequence that answers with
    /// the object that caused the violation is: lock the calendar (`CalendarRepo::lock`), `put`, and on the
    /// violation look the UID up while the lock is still held (a failed `put` rolls back only its own savepoint).
    /// Without the lock a concurrent delete can make the lookup find nothing, which the caller must tolerate (the
    /// write is then simply retried).
    async fn put(
        &mut self,
        calendar: CalendarId,
        version: NewVersion,
        expected: Expected,
    ) -> Result<WriteResult, StoreError>;

    /// Deletes the object at `uri` under the write invariant and returns the change's sequence number.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist, or when the object does not exist and the caller expects
    /// nothing in particular ([`Expected::Any`]); `PreconditionFailed` when `expected` does not match: a stale
    /// ETag, [`Expected::Absent`] (the object exists) and [`Expected::Etag`] for an object that does not exist.
    /// `If-Match` is evaluated before the method and is false when no representation exists (RFC 7232 sections
    /// 3.1 and 5), which is a 412 for `put` and `delete` alike.
    async fn delete(&mut self, calendar: CalendarId, uri: &ObjectUri, expected: Expected) -> Result<u64, StoreError>;

    /// Moves an object to `target_uri` in `target` (a relocation: the id, data, ETag and Schedule-Tag stay) and
    /// returns the sequence numbers of the change in the source and in the target calendar. Both calendars are
    /// locked in ascending id order. Moving within one calendar is a rename: two consecutive sequence numbers of
    /// the same calendar (a delete of the old name, then an upsert of the new one).
    ///
    /// # Errors
    ///
    /// `NotFound` (calendars or the source object) and `UniqueViolation` of `ObjectUri`, `ObjectUid` or
    /// `SchedulingUid` at the target.
    async fn move_to(
        &mut self,
        source: CalendarId,
        uri: &ObjectUri,
        target: CalendarId,
        target_uri: &ObjectUri,
    ) -> Result<(u64, u64), StoreError>;

    /// The candidates of an index query in ascending id order (a superset of the exact matches, see
    /// [`IndexFilter`]).
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist.
    async fn query(
        &mut self,
        calendar: CalendarId,
        filter: &IndexFilter,
        page: PageReq,
    ) -> Result<StorePage<StoredObject>, StoreError>;

    /// All objects of the calendar in ascending id order.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist.
    ///
    /// # Consistency of a full listing and its sync token
    ///
    /// The isolation level is READ COMMITTED: every statement of a transaction sees the data committed when it
    /// starts, so a listing and the sync token read in the same transaction are *not* one snapshot. A full or
    /// initial sync (no usable token) and a `PROPFIND` that report members together with a token must therefore
    /// read [`ChangeRepo::state`](super::ChangeRepo::state) **first** and list the members **afterwards**: a
    /// write that commits in between is then in the listing and after the token, and the client sees it again on
    /// its next sync (a harmless repeat). Reading the state after the listing loses such a write for good. Callers
    /// that want one snapshot for a whole paged listing open the transaction with
    /// [`TxMode::Snapshot`](super::TxMode::Snapshot). The incremental path
    /// ([`ChangeRepo::since`](super::ChangeRepo::since)) is safe in either order: it bounds its rows by the
    /// position it returns.
    async fn list(&mut self, calendar: CalendarId, page: PageReq) -> Result<StorePage<StoredObject>, StoreError>;

    /// [`list`](Self::list) without the iCalendar text, for listings that only need names, ETags and index
    /// columns. Additive method: the default reports [`StoreError::Unsupported`]; both store adapters override it.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist; `Unsupported` from stores that do not implement it.
    async fn list_index(&mut self, calendar: CalendarId, page: PageReq) -> Result<StorePage<ObjectHead>, StoreError> {
        let _ = (calendar, page);
        Err(StoreError::Unsupported)
    }

    /// [`query`](Self::query) without the iCalendar text (an ETag-only `calendar-query`, a `multiget` that does not
    /// ask for `calendar-data`). Additive method with the same default as [`list_index`](Self::list_index).
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist; `Unsupported` from stores that do not implement it.
    async fn query_index(
        &mut self,
        calendar: CalendarId,
        filter: &IndexFilter,
        page: PageReq,
    ) -> Result<StorePage<ObjectHead>, StoreError> {
        let _ = (calendar, filter, page);
        Err(StoreError::Unsupported)
    }

    /// The resource name of the object with `uid` in `calendar`, if any: the href that `C:no-uid-conflict`
    /// names after a `UniqueKey::ObjectUid` violation, without loading the object. Additive method: the default
    /// reports [`StoreError::Unsupported`]; both store adapters override it.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist; `Unsupported` from stores that do not implement it.
    async fn uri_for_uid(&mut self, calendar: CalendarId, uid: &Uid) -> Result<Option<ObjectUri>, StoreError> {
        let _ = (calendar, uid);
        Err(StoreError::Unsupported)
    }

    /// The calendar and resource name of the scheduling object with `uid` among the calendars owned by `owner`
    /// (the href of `C:unique-scheduling-object-resource` after a `UniqueKey::SchedulingUid` violation), without
    /// loading the object. Additive method with the same default as [`uri_for_uid`](Self::uri_for_uid).
    ///
    /// # Errors
    ///
    /// `Unsupported` from stores that do not implement it.
    async fn uri_for_scheduling_uid(
        &mut self,
        owner: PrincipalId,
        uid: &Uid,
    ) -> Result<Option<(CalendarId, ObjectUri)>, StoreError> {
        let _ = (owner, uid);
        Err(StoreError::Unsupported)
    }

    /// The attendee rows of an object, ordered by address.
    ///
    /// # Errors
    ///
    /// `NotFound` when the object does not exist.
    async fn attendees(&mut self, object: ObjectId) -> Result<Vec<ObjectAttendee>, StoreError>;
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use davhaven_domain::{CalendarKind, CalendarSlug, Classification, Transparency};
    use uuid::Uuid;

    use super::*;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 3, 1, hour, 0, 0).unwrap()
    }

    fn id<T: From<Uuid>>(n: u128) -> T {
        T::from(Uuid::from_u128(n))
    }

    fn calendar() -> Calendar {
        Calendar {
            id: id(10),
            tenant_id: id(11),
            owner_id: id(12),
            slug: CalendarSlug::parse("work").unwrap(),
            kind: CalendarKind::User,
            display_name: "Work".to_owned(),
            description: None,
            color: None,
            sort_order: 0,
            components: vec![ComponentKind::Event],
            timezone_ics: None,
            sync_seq: 0,
            sync_min_seq: 0,
            sync_epoch: Uuid::from_u128(13),
            deleted_at: None,
            created_at: at(0),
            updated_at: at(0),
            version: 1,
        }
    }

    fn index() -> ObjectIndex {
        ObjectIndex {
            uid: Uid::parse("uid-1").unwrap(),
            component: ComponentKind::Event,
            first_start: Some(at(10)),
            last_end: Some(at(12)),
            is_recurring: false,
            is_scheduling: true,
            organizer: Some(CalendarUserAddress::parse("mailto:anna@example.org").unwrap()),
            attendees: Vec::new(),
            sequence: 3,
            class: Classification::Private,
            transp: Transparency::Opaque,
        }
    }

    fn version() -> NewVersion {
        NewVersion {
            id: id(1),
            uri: ObjectUri::parse("uid-1.ics").unwrap(),
            data: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned(),
            etag: ETag::from_bytes(b"data"),
            schedule_tag: None,
            content_hash: ContentHash::from_digest([7; 32]),
            index: index(),
            attendee_principals: Vec::new(),
            external_key: Some(ExternalKey::parse("crm:42").unwrap()),
            origin: None,
        }
    }

    fn stored() -> StoredObject {
        version().into_stored(&calendar(), at(9), None)
    }

    #[test]
    fn into_stored_derives_every_column_from_the_index() {
        let object = stored();
        assert_eq!(object.id, id(1));
        assert_eq!(object.tenant_id, calendar().tenant_id);
        assert_eq!(object.calendar_id, calendar().id);
        assert_eq!(object.owner_id, calendar().owner_id);
        assert_eq!(object.uid.as_str(), "uid-1");
        assert_eq!(object.component, ComponentKind::Event);
        assert_eq!(object.size, 32);
        assert_eq!(object.first_start, Some(at(10)));
        assert_eq!(object.last_end, Some(at(12)));
        assert!(object.is_scheduling && !object.is_recurring);
        assert_eq!(object.sequence, 3);
        assert_eq!(object.class, Classification::Private);
        assert_eq!(object.created_at, at(9));
        assert_eq!(object.updated_at, at(9));
        assert_eq!(object.version, 1);
    }

    #[test]
    fn replacing_keeps_id_and_creation_time_and_bumps_the_version() {
        let first = stored();
        let mut next = version();
        next.id = id(99);
        next.data.push('X');
        let replaced = next.into_stored(&calendar(), at(11), Some(&first));
        assert_eq!(replaced.id, first.id, "the existing id wins");
        assert_eq!(replaced.created_at, at(9));
        assert_eq!(replaced.updated_at, at(11));
        assert_eq!(replaced.version, 2);
        assert_eq!(replaced.size, 33);
    }

    #[test]
    fn time_ranges_are_closed_supersets() {
        let range = TimeRange {
            start: Some(at(11)),
            end: Some(at(13)),
        };
        assert!(range.may_overlap(Some(at(10)), Some(at(12))));
        assert!(range.may_overlap(Some(at(12)), Some(at(14))));
        assert!(
            range.may_overlap(Some(at(13)), Some(at(14))),
            "an object that starts at the range end is a candidate: a to-do due then matches (RFC 4791 9.9)"
        );
        assert!(!range.may_overlap(Some(at(14)), Some(at(15))));
        assert!(
            range.may_overlap(Some(at(9)), Some(at(11))),
            "the object end is inclusive: an instant at the range start is a match"
        );
        assert!(
            !range.may_overlap(Some(at(9)), Some(at(10))),
            "but nothing that ends before the range starts"
        );
        assert!(
            range.may_overlap(Some(at(11)), Some(at(11))),
            "an instant at the range start (RFC 4791 section 9.9)"
        );
        assert!(
            range.may_overlap(Some(at(13)), Some(at(13))),
            "an instant at the range end is kept for the exact filter to drop"
        );
        assert!(range.may_overlap(None, None), "undated objects overlap everything");
        assert!(
            range.may_overlap(Some(at(12)), None),
            "unbounded objects overlap later ranges"
        );
        assert!(
            !range.may_overlap(Some(at(14)), None),
            "but not ranges before their start"
        );
        assert!(TimeRange::default().may_overlap(Some(at(1)), Some(at(2))));
    }

    #[test]
    fn time_ranges_agree_with_the_domain_prefilter() {
        let cases = [
            (Some(at(10)), Some(at(12))),
            (Some(at(10)), None),
            (None, None),
            (Some(at(1)), Some(at(2))),
        ];
        let bounds = [
            None,
            Some(at(0)),
            Some(at(10)),
            Some(at(11)),
            Some(at(12)),
            Some(at(23)),
        ];
        for (first_start, last_end) in cases {
            let mut object_index = index();
            object_index.first_start = first_start;
            object_index.last_end = last_end;
            for start in bounds {
                for end in bounds {
                    assert_eq!(
                        TimeRange { start, end }.may_overlap(first_start, last_end),
                        object_index.may_overlap(start, end),
                        "{first_start:?} {last_end:?} vs {start:?} {end:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn empty_filters_match_everything_and_set_fields_narrow_it() {
        let object = stored();
        assert!(IndexFilter::all().matches(&object));

        let accept = |filter: IndexFilter| filter.matches(&object);
        assert!(accept(IndexFilter {
            component: Some(ComponentKind::Event),
            ..IndexFilter::all()
        }));
        assert!(!accept(IndexFilter {
            component: Some(ComponentKind::Todo),
            ..IndexFilter::all()
        }));
        assert!(accept(IndexFilter {
            uid: Some(Uid::parse("uid-1").unwrap()),
            ..IndexFilter::all()
        }));
        assert!(!accept(IndexFilter {
            uid: Some(Uid::parse("uid-2").unwrap()),
            ..IndexFilter::all()
        }));
        assert!(accept(IndexFilter {
            uris: Some(vec![ObjectUri::parse("other.ics").unwrap(), object.uri.clone()]),
            ..IndexFilter::all()
        }));
        assert!(!accept(IndexFilter {
            uris: Some(Vec::new()),
            ..IndexFilter::all()
        }));
        assert!(accept(IndexFilter {
            external_key: Some(ExternalKey::parse("crm:42").unwrap()),
            ..IndexFilter::all()
        }));
        assert!(!accept(IndexFilter {
            external_key: Some(ExternalKey::parse("crm:43").unwrap()),
            ..IndexFilter::all()
        }));
        assert!(accept(IndexFilter {
            external_key_prefix: Some("crm:".to_owned()),
            ..IndexFilter::all()
        }));
        assert!(!accept(IndexFilter {
            external_key_prefix: Some("erp:".to_owned()),
            ..IndexFilter::all()
        }));
        assert!(accept(IndexFilter {
            organizer: Some(CalendarUserAddress::parse("MAILTO:Anna@Example.org").unwrap()),
            ..IndexFilter::all()
        }));
        assert!(!accept(IndexFilter {
            organizer: Some(CalendarUserAddress::parse("mailto:bob@example.org").unwrap()),
            ..IndexFilter::all()
        }));
        assert!(accept(IndexFilter {
            is_scheduling: Some(true),
            ..IndexFilter::all()
        }));
        assert!(!accept(IndexFilter {
            is_scheduling: Some(false),
            ..IndexFilter::all()
        }));
        assert!(accept(IndexFilter {
            time_range: Some(TimeRange {
                start: Some(at(11)),
                end: None
            }),
            ..IndexFilter::all()
        }));
        assert!(accept(IndexFilter {
            time_range: Some(TimeRange {
                start: Some(at(12)),
                end: None
            }),
            ..IndexFilter::all()
        }));
        assert!(!accept(IndexFilter {
            time_range: Some(TimeRange {
                start: Some(at(13)),
                end: None
            }),
            ..IndexFilter::all()
        }));
    }

    #[test]
    fn objects_without_an_external_key_never_match_key_filters() {
        let mut keyless = version();
        keyless.external_key = None;
        let object = keyless.into_stored(&calendar(), at(9), None);
        assert!(
            !IndexFilter {
                external_key_prefix: Some(String::new()),
                ..IndexFilter::all()
            }
            .matches(&object)
        );
        assert!(
            !IndexFilter {
                external_key: Some(ExternalKey::parse("crm:42").unwrap()),
                ..IndexFilter::all()
            }
            .matches(&object)
        );
    }
}
