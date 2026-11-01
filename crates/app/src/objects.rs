//! Calendar object use cases: get, put, delete, move, multiget, query, sync, batch and the JSON event interface.
//!
//! Every write — a DAV `PUT`, an API `PUT` by key, a batch item, an MCP `create_event` — goes through one storage path
//! (`ObjectServiceImpl::store`): the same validation, the same change log entry, the same `calendar.objects_changed`
//! event, the same unique rules (PLAN 2.10). The write invariant itself is enforced by the store: every mutation of
//! a calendar advances its `sync_seq` exactly once, in the caller's transaction, under the calendar's row lock.
//!
//! | Submodule | Responsibility |
//! | --- | --- |
//! | `dav` | GET, PUT, DELETE, MOVE, COPY and the shared storage path |
//! | `query` | `calendar-multiget`, `calendar-query` and the projection of `calendar-data` |
//! | `sync` | `sync-collection` and the changes feed |
//! | `events` | the JSON event interface: read, create or change, delete, list |
//! | `search` | event search across calendars (MCP) |
//! | `sight` | what an MCP caller may see of events: the busy-only form of private events of others |
//! | `locate` | resolving collections, views and the domain event of changes |
//! | `prepare` | validation, preconditions and conflict reporting |
//! | `schedule` | the seam where server-side scheduling plugs into the write path |
//!
//! # Rules the use cases apply
//!
//! * **Bytes.** The client's bytes are stored verbatim and the `ETag` is `base64url(SHA-256(bytes))[..22]`; the server
//!   re-serializes only what it changes itself (JSON writes, instance removals, batch sequence bumps). A `PUT` answers
//!   an `ETag` only when the stored bytes are the request body (RFC 4791 section 5.3.4).
//! * **Validation** runs on a blocking thread under the wall-clock budget of the limits and answers the CalDAV
//!   preconditions of RFC 4791 and PLAN 2.15 (`valid-calendar-data`, `max-resource-size`, `max-attendees-per-instance`,
//!   `supported-calendar-component`, `no-uid-conflict` with the href of the conflicting resource, ...).
//! * **Conditional headers** are evaluated under the calendar lock in the order `If-Schedule-Tag-Match`, `If-Match`,
//!   `If-None-Match: *`.
//! * **Permissions** come from `domain::authz::decide` over the facts of the calendar, loaded in one store call;
//!   managed and mirror calendars refuse DAV writes (403) and accept them through the API.
//! * **Scheduling** is delegated to an [`ObjectScheduler`]; the default does nothing.

pub(crate) mod dav;
pub(crate) mod events;
pub(crate) mod locate;
pub(crate) mod prepare;
mod query;
pub(crate) use query::zone_of;
mod schedule;
mod search;
mod sight;
mod sync;

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{EventTime, RequestContext, ResourcePath, SyncToken};
use davhaven_wire::{BatchRequest, BatchResult, ChangesResponse, EventView, Page};

pub use schedule::{
    DeleteFacts, Handover, NoScheduling, ObjectScheduler, ScheduleTagPlan, ScheduledWrite, WriteFacts, Written,
};

use crate::error::AppResult;
use crate::services::{
    CalendarDataSpec, CalendarRef, CopyRequest, DeleteEventOptions, DeleteOutcome, DeleteRequest, EventCreate,
    EventSearch, EventWrite, EventWriteOutcome, MoveOutcome, MoveRequest, MultigetEntry, ObjectFilter, ObjectHit,
    ObjectSelector, ObjectService, ObjectView, PageRequest, PutOutcome, PutRequest, SyncResult,
};
use crate::wiring::AppCore;

/// The [`ObjectService`] of the application.
#[derive(Clone)]
pub struct ObjectServiceImpl {
    core: AppCore,
    scheduler: Arc<dyn ObjectScheduler>,
}

impl core::fmt::Debug for ObjectServiceImpl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectServiceImpl")
            .field("core", &self.core)
            .finish_non_exhaustive()
    }
}

impl ObjectServiceImpl {
    /// Creates the service on the shared application core, without server-side scheduling.
    pub fn new(core: AppCore) -> Self {
        Self::with_scheduler(core, Arc::new(NoScheduling))
    }

    /// Creates the service with the scheduler that delivers invitations and replies inside the write transaction
    /// (see the `schedule` module documentation).
    pub fn with_scheduler(core: AppCore, scheduler: Arc<dyn ObjectScheduler>) -> Self {
        Self { core, scheduler }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

#[async_trait]
impl ObjectService for ObjectServiceImpl {
    async fn get(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<ObjectView> {
        self.read_object(ctx, path).await
    }

    async fn put(&self, ctx: &RequestContext, request: PutRequest) -> AppResult<PutOutcome> {
        self.put_object(ctx, request).await
    }

    async fn delete(&self, ctx: &RequestContext, request: DeleteRequest) -> AppResult<DeleteOutcome> {
        self.delete_object(ctx, request).await
    }

    async fn move_to(&self, ctx: &RequestContext, request: MoveRequest) -> AppResult<MoveOutcome> {
        self.move_object(ctx, request).await
    }

    async fn copy_to(&self, ctx: &RequestContext, request: CopyRequest) -> AppResult<MoveOutcome> {
        self.copy_object(ctx, request).await
    }

    async fn multiget(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        paths: Vec<ResourcePath>,
        data: CalendarDataSpec,
    ) -> AppResult<Vec<MultigetEntry>> {
        self.multiget_objects(ctx, collection, paths, data).await
    }

    async fn query(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        filter: ObjectFilter,
        data: CalendarDataSpec,
    ) -> AppResult<Vec<ObjectHit>> {
        self.query_objects(ctx, collection, filter, data).await
    }

    async fn sync(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<SyncResult> {
        self.sync_members(ctx, collection, since, limit).await
    }

    async fn batch(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        request: BatchRequest,
    ) -> AppResult<BatchResult> {
        self.batch_upsert(ctx, calendar, request).await
    }

    async fn get_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        instance: Option<EventTime>,
    ) -> AppResult<EventView> {
        self.read_event(ctx, calendar, selector, instance).await
    }

    async fn put_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        write: EventWrite,
    ) -> AppResult<EventWriteOutcome> {
        self.write_event(ctx, calendar, write).await
    }

    async fn create_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        create: EventCreate,
    ) -> AppResult<EventWriteOutcome> {
        self.create_once(ctx, calendar, create).await
    }

    async fn delete_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<()> {
        self.remove_event(ctx, calendar, selector, options).await
    }

    async fn delete_event_if_present(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<bool> {
        self.remove_event_if_present(ctx, calendar, selector, options).await
    }

    async fn list(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        filter: ObjectFilter,
        page: PageRequest,
    ) -> AppResult<Page<EventView>> {
        self.list_events(ctx, calendar, filter, page).await
    }

    async fn search_events(
        &self,
        ctx: &RequestContext,
        search: EventSearch,
        page: PageRequest,
    ) -> AppResult<Page<EventView>> {
        self.search(ctx, search, page).await
    }

    async fn changes(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<ChangesResponse> {
        self.feed_changes(ctx, calendar, since, limit).await
    }
}
