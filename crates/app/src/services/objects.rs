//! Calendar objects: the DAV resource operations, queries, sync and the JSON event interface of the management
//! API and MCP.
//!
//! Both interfaces share one write path in the application (same change log, events and scheduling rules): a DAV
//! `PUT` and an API `PUT` of the same event produce the same stored object, change-log entry and domain event
//! (PLAN 2.10). `ObjectService::put` takes the bytes of the client verbatim; `put_event` takes JSON that is merged
//! into the stored component.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarId, CalendarUserAddress, ComponentKind, ETag, ErrorKind, EventTime, ExternalKey, ObjectId, ObjectUri,
    PrivilegeSet, RequestContext, ResourcePath, ScheduleTag, SyncToken, Uid,
};
use davhaven_ical::filter::{CalendarFilter, TimeRange};
use davhaven_ical::projection::Projection;
use davhaven_wire::mcp::ChangeScope;
use davhaven_wire::{BatchRequest, BatchResult, ChangeKind, ChangesResponse, EventView, Page};

use super::calendars::CalendarRef;
use super::common::PageRequest;
use crate::error::AppResult;

/// A stored calendar object as DAV shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectView {
    /// The resource in the viewer's home.
    pub path: ResourcePath,
    /// The object id.
    pub id: ObjectId,
    /// The calendar the object is stored in.
    pub calendar_id: CalendarId,
    /// The iCalendar UID.
    pub uid: Uid,
    /// The component type of the main component.
    pub component: ComponentKind,
    /// The strong entity tag of the stored bytes.
    pub etag: ETag,
    /// The `Schedule-Tag` of scheduling object resources.
    pub schedule_tag: Option<ScheduleTag>,
    /// The size of the stored bytes.
    pub size: u64,
    /// When the object was last changed (`getlastmodified`).
    pub last_modified: DateTime<Utc>,
    /// The iCalendar text, after the projection of the request; `None` when the request did not ask for data.
    pub data: Option<String>,
    /// The viewer's privileges on the object (`current-user-privilege-set`).
    pub privileges: PrivilegeSet,
}

/// The same type answers `calendar-query` hits.
pub type ObjectHit = ObjectView;

/// What `calendar-data` of a request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarDataSpec {
    /// Whether the iCalendar text is wanted at all (PROPFIND for `getetag` only does not).
    pub include_data: bool,
    /// Component and property selection, expansion and limits.
    pub projection: Projection,
}

impl Default for CalendarDataSpec {
    /// The whole object, unchanged.
    fn default() -> Self {
        Self {
            include_data: true,
            projection: Projection::default(),
        }
    }
}

impl CalendarDataSpec {
    /// No data: only the metadata of the objects.
    pub fn metadata_only() -> Self {
        Self {
            include_data: false,
            projection: Projection::default(),
        }
    }
}

/// How an `If-Match` header matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfMatch {
    /// `If-Match: *`: the resource must exist.
    Any,
    /// `If-Match: "a", "b"`: the stored ETag must be one of these.
    Tags(Vec<ETag>),
}

/// The conditional headers of a write, evaluated in the order `If-Schedule-Tag-Match`, `If-Match`,
/// `If-None-Match: *` (PLAN 2.7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WritePrecondition {
    /// `If-Match`.
    pub if_match: Option<IfMatch>,
    /// `If-None-Match: *`: only create.
    pub if_none_match_any: bool,
    /// `If-Schedule-Tag-Match`: when it matches, an attendee's change is merged instead of failing with 412.
    pub if_schedule_tag_match: Option<ScheduleTag>,
}

impl WritePrecondition {
    /// No conditions.
    pub fn none() -> Self {
        Self::default()
    }

    /// `If-None-Match: *`.
    pub fn create_only() -> Self {
        Self {
            if_none_match_any: true,
            ..Self::default()
        }
    }

    /// `If-Match` with one entity tag.
    pub fn if_match(etag: ETag) -> Self {
        Self {
            if_match: Some(IfMatch::Tags(vec![etag])),
            ..Self::default()
        }
    }
}

/// Whether an attendee's reply is sent when the attendee deletes or declines (`Schedule-Reply`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScheduleReply {
    /// Send the reply (default; `Schedule-Reply: T`).
    #[default]
    Send,
    /// Suppress it (`Schedule-Reply: F`).
    Suppress,
}

/// The `SCHEDULE-STATUS` of one recipient (RFC 6638, PLAN 2.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleStatus {
    /// `1.2`: delivered to an internal calendar.
    Delivered,
    /// `1.0`: queued for later delivery.
    Queued,
    /// `1.1`: sent as iMIP mail.
    ImipSent,
    /// `3.7`: the address is unknown, or a group address that is not expanded.
    UnknownAddress,
    /// `5.1`: delivery failed.
    Failed,
}

impl ScheduleStatus {
    /// The status code as written into `SCHEDULE-STATUS`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Delivered => "1.2",
            Self::Queued => "1.0",
            Self::ImipSent => "1.1",
            Self::UnknownAddress => "3.7",
            Self::Failed => "5.1",
        }
    }
}

/// The status of scheduling for one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientStatus {
    /// The recipient's calendar user address.
    pub address: CalendarUserAddress,
    /// What happened.
    pub status: ScheduleStatus,
}

/// What scheduling did during a write. Empty when the write did not schedule (see PLAN 2.8, "Not scheduled").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScheduleOutcome {
    /// One entry per recipient the write addressed.
    pub recipients: Vec<RecipientStatus>,
}

impl ScheduleOutcome {
    /// A write that did not schedule anything.
    pub const fn none() -> Self {
        Self { recipients: Vec::new() }
    }

    /// Whether the write sent or queued any scheduling message.
    pub fn is_scheduled(&self) -> bool {
        !self.recipients.is_empty()
    }
}

/// A `PUT` of a calendar object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutRequest {
    /// The resource to create or replace.
    pub path: ResourcePath,
    /// The iCalendar text, as the client sent it. It is stored verbatim.
    pub body: String,
    /// The `Content-Type` of the request.
    pub content_type: Option<String>,
    /// The conditional headers.
    pub preconditions: WritePrecondition,
    /// `Schedule-Reply`.
    pub schedule_reply: ScheduleReply,
}

/// The result of a `PUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutOutcome {
    /// The `ETag` response header: present only when the stored bytes equal the request body (RFC 4791 5.3.4).
    pub etag: Option<ETag>,
    /// The `Schedule-Tag` response header.
    pub schedule_tag: Option<ScheduleTag>,
    /// Whether the resource was created (201) or replaced (204).
    pub created: bool,
    /// What scheduling did.
    pub schedule: ScheduleOutcome,
}

/// A `DELETE` of a calendar object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteRequest {
    /// The resource to delete.
    pub path: ResourcePath,
    /// The conditional headers.
    pub preconditions: WritePrecondition,
    /// `Schedule-Reply`: whether an attendee's deletion sends `REPLY DECLINED`.
    pub schedule_reply: ScheduleReply,
}

/// The result of a `DELETE`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeleteOutcome {
    /// What scheduling did (cancellations of an organizer, declines of an attendee).
    pub schedule: ScheduleOutcome,
}

/// A `MOVE` of a calendar object. Moves within one owner are relocations: no iTIP, the schedule tag is kept and
/// the change is logged in both calendars (PLAN 2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveRequest {
    /// The object to move.
    pub from: ResourcePath,
    /// The new location.
    pub to: ResourcePath,
    /// The `Overwrite` header: whether an existing target is replaced.
    pub overwrite: bool,
    /// The conditional headers, evaluated against the source.
    pub preconditions: WritePrecondition,
}

/// The result of a `MOVE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveOutcome {
    /// Whether the target did not exist (201) or was overwritten (204).
    pub created: bool,
    /// The entity tag of the object at the new location.
    pub etag: ETag,
}

/// A `COPY` of a calendar object. The copy keeps the UID of the source, so a copy inside one calendar fails with
/// `no-uid-conflict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyRequest {
    /// The object to copy.
    pub from: ResourcePath,
    /// The location of the copy.
    pub to: ResourcePath,
    /// The `Overwrite` header.
    pub overwrite: bool,
}

/// The filter of `calendar-query` and of object listings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectFilter {
    /// The `CALDAV:filter` of a `calendar-query` REPORT.
    pub calendar_filter: Option<CalendarFilter>,
    /// Only objects with instances overlapping this range (API `range`).
    pub range: Option<TimeRange>,
    /// Only the object with this external key.
    pub external_key: Option<ExternalKey>,
    /// Only the object with this UID.
    pub uid: Option<Uid>,
    /// Only objects of this component type.
    pub component: Option<ComponentKind>,
}

/// One entry of a `calendar-multiget` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultigetEntry {
    /// The object exists and is visible.
    Found(ObjectView),
    /// The href names no visible object (a 404 entry in the multistatus).
    Missing(ResourcePath),
}

/// One change of a `sync-collection` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncChange {
    /// The member resource.
    pub path: ResourcePath,
    /// Whether the member exists after the change (reported with its ETag) or was deleted (a 404 entry).
    pub kind: ChangeKind,
    /// The entity tag of existing members.
    pub etag: Option<ETag>,
}

/// The answer of `sync-collection` (RFC 6578, `sync-level` 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResult {
    /// The token to continue from.
    pub sync_token: SyncToken,
    /// The changes since the requested token (all members for an initial sync), one entry per member.
    pub changes: Vec<SyncChange>,
    /// Whether the answer is truncated: the DAV layer reports `507` for the request URI and the usable token.
    pub truncated: bool,
}

/// How a JSON event interface picks an existing object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectSelector {
    /// The caller's stable key.
    Key(ExternalKey),
    /// The resource name inside the calendar.
    Uri(ObjectUri),
    /// The iCalendar UID.
    Uid(Uid),
    /// The object id.
    Id(ObjectId),
}

/// A JSON event write (management API `PUT …/by-key/{key}`, MCP `create_event` and `update_event`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWrite {
    /// The object to write. `None` creates a new object with a UID from the event or a generated one. A `Key`
    /// that does not exist creates the object with the deterministic UID `UUIDv5(calendar_id, key)`; the other
    /// selectors must name an existing object.
    pub target: Option<ObjectSelector>,
    /// The event fields to merge; metadata members are ignored.
    pub event: EventView,
    /// Whether attendees are notified (API and MCP never schedule unless asked).
    pub notify_attendees: bool,
    /// The entity tag the write is based on (`if_match` of MCP, `If-Match` of the API).
    pub if_match: Option<ETag>,
    /// Which instances of a recurring event the write affects; the instance comes from `event.data.recurrence_id`.
    pub scope: ChangeScope,
}

/// The creation of an event that is made **once** (MCP `create_event`): a retry of the same call must not create a
/// second event, and a key that names an event of different content must not rewrite it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCreate {
    /// The caller's stable key (MCP `client_request_id`). The UID of the new event derives from it
    /// (`UUIDv5(calendar_id, key)`). `None` creates an event under a UID of its own on every call.
    pub key: Option<ExternalKey>,
    /// The event fields; metadata members are ignored.
    pub event: EventView,
    /// Whether attendees are notified (API and MCP never schedule unless asked).
    pub notify_attendees: bool,
}

/// The result of an event write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWriteOutcome {
    /// The event as stored, with metadata.
    pub event: EventView,
    /// Whether the object was created by this call.
    pub created: bool,
    /// What scheduling did.
    pub schedule: ScheduleOutcome,
}

/// The options of an event deletion.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeleteEventOptions {
    /// The entity tag the deletion is based on.
    pub if_match: Option<ETag>,
    /// Which instances are deleted.
    pub scope: ChangeScope,
    /// The instance for `this` and `this_and_future`.
    pub recurrence_id: Option<EventTime>,
    /// Whether attendees are notified of the cancellation.
    pub notify_attendees: bool,
}

/// A search across the calendars the caller can read (MCP `list_events` and `search_events`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventSearch {
    /// The calendars to search; every visible calendar when empty.
    pub calendars: Vec<CalendarRef>,
    /// Text to look for in summary, description and location (at least two characters).
    pub text: Option<String>,
    /// Only events with instances in this range.
    pub range: Option<TimeRange>,
    /// Whether recurring events are expanded into instances (each with its `recurrence_id`) inside the range.
    pub expand: bool,
}

/// The object operations.
#[async_trait]
pub trait ObjectService: Send + Sync {
    /// Reads one object (GET, HEAD, PROPFIND of an object).
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown and invisible objects.
    async fn get(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<ObjectView>;

    /// Creates or replaces an object from client bytes: validation against the limits, indexing, preconditions,
    /// the change log, the domain event and scheduling in one transaction.
    ///
    /// # Errors
    ///
    /// `Invalid` or `TooLarge` with the matching CalDAV precondition for bad data, `Conflict` with
    /// `no-uid-conflict` or `unique-scheduling-object-resource`, `Forbidden` with `need-privileges` or a
    /// scheduling precondition, `PreconditionFailed`, `NotFound` for invisible collections.
    ///
    /// The href of `no-uid-conflict` and of `unique-scheduling-object-resource` goes to the client as it is, so it
    /// must name an object the caller may read. Scheduling objects are unique per owner: when the object that
    /// holds the UID lies in a calendar the caller cannot read, the href of the object being written is used
    /// instead, so that nothing about the other calendar is disclosed. The same holds for [`move_to`](Self::move_to)
    /// and [`copy_to`](Self::copy_to).
    async fn put(&self, ctx: &RequestContext, request: PutRequest) -> AppResult<PutOutcome>;

    /// Deletes an object.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `PreconditionFailed`.
    async fn delete(&self, ctx: &RequestContext, request: DeleteRequest) -> AppResult<DeleteOutcome>;

    /// Moves an object to another collection or name.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden` (both sides are checked), `PreconditionFailed`, `Conflict` when the target exists
    /// and `overwrite` is false.
    async fn move_to(&self, ctx: &RequestContext, request: MoveRequest) -> AppResult<MoveOutcome>;

    /// Copies an object to another collection or name.
    ///
    /// # Errors
    ///
    /// As [`move_to`](Self::move_to), plus `Conflict` with `no-uid-conflict` when the target calendar already
    /// holds the UID.
    async fn copy_to(&self, ctx: &RequestContext, request: CopyRequest) -> AppResult<MoveOutcome>;

    /// `calendar-multiget`: the listed objects of one collection, in request order.
    ///
    /// # Errors
    ///
    /// `NotFound` for an invisible collection, `Invalid` with `number-of-matches-within-limits` above the limit.
    async fn multiget(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        paths: Vec<ResourcePath>,
        data: CalendarDataSpec,
    ) -> AppResult<Vec<MultigetEntry>>;

    /// `calendar-query`: the objects matching a filter, ordered by resource name.
    ///
    /// # Errors
    ///
    /// `Invalid` with `valid-filter`, `max-instances` or the date limits, `NotFound` for an invisible collection.
    async fn query(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        filter: ObjectFilter,
        data: CalendarDataSpec,
    ) -> AppResult<Vec<ObjectHit>>;

    /// `sync-collection`: the changes of a collection since a token, or all members without one.
    ///
    /// # Errors
    ///
    /// `Invalid` with `valid-sync-token` for foreign, garbled, future and pruned tokens, `NotFound`.
    async fn sync(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<SyncResult>;

    /// Batch upsert into a managed calendar (`POST …/objects/batch`): one transaction, all or nothing.
    ///
    /// Items that cannot be written do not fail the call: nothing is written and the result lists every entry,
    /// the failed ones with `Failed` and their problem (`BatchResult::has_failures`); the API answers 422 with
    /// that result as the body.
    ///
    /// # Errors
    ///
    /// `Invalid` when the request breaks its own rules (`BatchRequest::validate`), `Forbidden`, `NotFound`,
    /// `Unavailable`.
    async fn batch(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        request: BatchRequest,
    ) -> AppResult<BatchResult>;

    /// Reads an event as JSON.
    ///
    /// `instance` selects one instance of a recurring event; the master is returned without it.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn get_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        instance: Option<EventTime>,
    ) -> AppResult<EventView>;

    /// Reads an event by its external key (management API).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn get_by_key(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        key: &ExternalKey,
    ) -> AppResult<EventView> {
        self.get_event(ctx, calendar, &ObjectSelector::Key(key.clone()), None)
            .await
    }

    /// Creates or changes an event from JSON, merging the fields into the stored component.
    ///
    /// # Errors
    ///
    /// `Invalid`, `NotFound` for selectors of missing objects, `PreconditionFailed`, `Conflict`, `Forbidden`
    /// (managed calendars accept writes from `events:write` tokens only).
    async fn put_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        write: EventWrite,
    ) -> AppResult<EventWriteOutcome>;

    /// Deletes an event (or instances of it).
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed`, `Forbidden`.
    async fn delete_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<()>;

    /// Creates an event once (MCP `create_event`).
    ///
    /// Without a key every call creates an event. With a key the call is repeatable: when no event of the calendar has
    /// the key it is created (`created: true`); when one has it and the fields of the request change nothing about
    /// it, that event is returned as it is (`created: false`, nothing is written, nobody is notified); when one has it
    /// and the fields would change it, the call is a `Conflict` (the key was used for another event) and nothing is
    /// written. This differs from [`put_event`](Self::put_event) with a key, which is an upsert (the management API's
    /// `PUT …/by-key/{key}`), on purpose: a retried call and a reused key are not the same thing.
    ///
    /// The default reads by the key and writes when there is none, which cannot tell a repeat from a reused key
    /// (the application does, in the transaction of the write).
    ///
    /// # Errors
    ///
    /// As [`put_event`](Self::put_event); `Conflict` for a key of an event with other content.
    async fn create_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        create: EventCreate,
    ) -> AppResult<EventWriteOutcome> {
        let EventCreate {
            key,
            event,
            notify_attendees,
        } = create;
        let target = match key {
            Some(key) => {
                match self
                    .get_event(ctx, calendar, &ObjectSelector::Key(key.clone()), None)
                    .await
                {
                    Ok(existing) => {
                        return Ok(EventWriteOutcome {
                            event: existing,
                            created: false,
                            schedule: ScheduleOutcome::none(),
                        });
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => Some(ObjectSelector::Key(key)),
                    Err(error) => return Err(error),
                }
            }
            None => None,
        };
        self.put_event(
            ctx,
            calendar,
            EventWrite {
                target,
                event,
                notify_attendees,
                if_match: None,
                scope: ChangeScope::All,
            },
        )
        .await
    }

    /// Deletes an event and says whether there was one: `true` when it was deleted, `false` when the calendar is
    /// readable and writable for the caller and holds no such event (MCP `delete_event`: the call asked for the event
    /// to be gone, and it is).
    ///
    /// Only the deletion of a whole event without `if_match` can find nothing to delete: an instance of an event that
    /// is not there, or an entity tag of an event that is not there, is `NotFound` as in
    /// [`delete_event`](Self::delete_event). What the caller may not see or delete is decided first, so a denied
    /// deletion is a denial and never `false`.
    ///
    /// The default is [`delete_event`](Self::delete_event) and cannot tell an absent event from an invisible one (both
    /// are `NotFound`).
    ///
    /// # Errors
    ///
    /// As [`delete_event`](Self::delete_event).
    async fn delete_event_if_present(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<bool> {
        self.delete_event(ctx, calendar, selector, options).await.map(|()| true)
    }

    /// Deletes an event by its external key (management API).
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed`, `Forbidden`.
    async fn delete_by_key(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        key: &ExternalKey,
        options: DeleteEventOptions,
    ) -> AppResult<()> {
        self.delete_event(ctx, calendar, &ObjectSelector::Key(key.clone()), options)
            .await
    }

    /// Lists the events of one calendar as JSON, ordered by id (management API `GET …/objects`).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Invalid` for a bad cursor or filter.
    async fn list(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        filter: ObjectFilter,
        page: PageRequest,
    ) -> AppResult<Page<EventView>>;

    /// Searches events across calendars, ordered by start (MCP).
    ///
    /// # Errors
    ///
    /// `Invalid` for ranges beyond the limits, short text and bad cursors; `Forbidden`.
    async fn search_events(
        &self,
        ctx: &RequestContext,
        search: EventSearch,
        page: PageRequest,
    ) -> AppResult<Page<EventView>>;

    /// The changes feed of a calendar (management API `GET …/changes`), based on the DAV sync token.
    ///
    /// # Errors
    ///
    /// `Invalid` with `valid-sync-token` (the API answers 410), `NotFound`, `Forbidden`.
    async fn changes(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<ChangesResponse>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_statuses_use_the_rfc_codes() {
        let codes: Vec<&str> = [
            ScheduleStatus::Delivered,
            ScheduleStatus::Queued,
            ScheduleStatus::ImipSent,
            ScheduleStatus::UnknownAddress,
            ScheduleStatus::Failed,
        ]
        .iter()
        .map(|status| status.code())
        .collect();
        assert_eq!(codes, vec!["1.2", "1.0", "1.1", "3.7", "5.1"]);
    }

    #[test]
    fn unscheduled_writes_have_an_empty_outcome() {
        assert!(!ScheduleOutcome::none().is_scheduled());
        let outcome = ScheduleOutcome {
            recipients: vec![RecipientStatus {
                address: CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
                status: ScheduleStatus::ImipSent,
            }],
        };
        assert!(outcome.is_scheduled());
    }

    #[test]
    fn preconditions_and_data_specs_have_sensible_defaults() {
        let none = WritePrecondition::none();
        assert!(none.if_match.is_none() && !none.if_none_match_any && none.if_schedule_tag_match.is_none());
        assert!(WritePrecondition::create_only().if_none_match_any);
        let etag = ETag::from_bytes(b"x");
        assert_eq!(
            WritePrecondition::if_match(etag.clone()).if_match,
            Some(IfMatch::Tags(vec![etag]))
        );
        assert!(CalendarDataSpec::default().include_data);
        assert!(CalendarDataSpec::default().projection.is_identity());
        assert!(!CalendarDataSpec::metadata_only().include_data);
        assert_eq!(ScheduleReply::default(), ScheduleReply::Send);
    }
}
