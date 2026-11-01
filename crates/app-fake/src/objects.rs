//! Fake object service.
//!
//! Stores the bytes of DAV `PUT`s verbatim with strong ETags, keeps one change log per calendar for
//! `sync-collection` and the changes feed, enforces preconditions and the UID rules, and checks permissions with
//! `domain::authz::decide`. The JSON event interface renders a minimal `VEVENT` from the fields the fake
//! understands (UID, summary, description, location, start, end, duration, status).
//!
//! What the fake does not do: validate iCalendar beyond the envelope, a `UID` and a component type; evaluate
//! `calendar-query` filters (every object of the collection is a hit, narrowed by component, UID and external
//! key); expand recurrences; schedule. Protocol tests that need those use the real application.

use async_trait::async_trait;
use davhaven_app::error::{AppError, AppResult, SafeMessage};
use davhaven_app::services::{
    CalendarDataSpec, CalendarRef, CopyRequest, DeleteEventOptions, DeleteOutcome, DeleteRequest, EventCreate,
    EventSearch, EventWrite, EventWriteOutcome, IfMatch, MoveOutcome, MoveRequest, MultigetEntry, ObjectFilter,
    ObjectHit, ObjectSelector, ObjectService, ObjectView, PageRequest, PutOutcome, PutRequest, ScheduleOutcome,
    SyncChange, SyncResult, WritePrecondition,
};
use davhaven_domain::{
    Access, ApiLimits, Calendar, CalendarId, ComponentKind, ETag, ErrorKind, EventTime, ExternalKey, IcalLimits,
    ObjectUri, Operation, Precondition, RequestContext, ResourceKind, ResourcePath, StoredObject, SyncToken, Uid,
    effective_access, privileges,
};
use davhaven_wire::mcp::ChangeScope;
use davhaven_wire::{
    BatchItemResult, BatchMode, BatchOutcome, BatchRequest, BatchResult, ChangeView, ChangesResponse, EventView, Page,
    ProblemCode, ProblemDetails,
};

use crate::calendars::CollectionTarget;
use crate::icaltext::{component_of, event_data, has_envelope, render_event, uid_of};
use crate::state::{FakeState, FakeTenant, FakeWorld, paginate};

/// The fake [`ObjectService`].
#[derive(Debug, Clone)]
pub struct FakeObjects {
    state: FakeState,
}

impl FakeObjects {
    /// Creates the service on a shared world.
    pub const fn new(state: FakeState) -> Self {
        Self { state }
    }
}

fn invalid(text: &'static str) -> AppError {
    AppError::invalid(SafeMessage::from_static(text))
}

fn calendar_data_error(text: &'static str) -> AppError {
    invalid(text).with_precondition(Precondition::ValidCalendarData(text.to_owned()))
}

/// Evaluates `If-Match` and `If-None-Match: *` against the stored object.
fn check_preconditions(preconditions: &WritePrecondition, existing: Option<&StoredObject>) -> AppResult<()> {
    if preconditions.if_none_match_any && existing.is_some() {
        return Err(AppError::precondition_failed());
    }
    match &preconditions.if_match {
        None => Ok(()),
        Some(IfMatch::Any) => existing.map(|_| ()).ok_or_else(AppError::precondition_failed),
        Some(IfMatch::Tags(tags)) => match existing {
            Some(object) if tags.contains(&object.etag) => Ok(()),
            _ => Err(AppError::precondition_failed()),
        },
    }
}

/// Overlays the fields that `changes` sets onto `base` and removes the ones it names with `null`.
fn overlay(mut base: davhaven_domain::EventData, changes: &davhaven_domain::EventData) -> davhaven_domain::EventData {
    use davhaven_domain::EventField;

    macro_rules! take {
        ($($field:ident),+) => {
            $( if changes.$field.is_some() { base.$field.clone_from(&changes.$field); } )+
        };
    }
    macro_rules! remove {
        ($($field:ident => $variant:ident),+) => {
            $( if changes.removes(EventField::$variant) { base.$field = None; } )+
        };
    }
    take!(summary, description, location, start, end, duration, status);
    if changes.end.is_some() {
        base.duration = None;
    }
    if changes.duration.is_some() {
        base.end = None;
    }
    remove!(
        summary => Summary,
        description => Description,
        location => Location,
        end => End,
        duration => Duration,
        status => Status
    );
    base
}

impl FakeWorld {
    /// Resolves an object path to its collection and resource name.
    fn object_target(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<(CollectionTarget, ObjectUri)> {
        let ResourcePath::Object {
            tenant,
            principal,
            binding,
            object,
        } = path
        else {
            return Err(AppError::not_found());
        };
        let collection = ResourcePath::Collection {
            tenant: tenant.clone(),
            principal: principal.clone(),
            binding: binding.clone(),
        };
        Ok((self.resolve_collection(ctx, &collection)?, object.clone()))
    }

    fn calendar_of(&self, target: &CollectionTarget) -> AppResult<&Calendar> {
        self.calendars.get(&target.calendar).ok_or_else(AppError::not_found)
    }

    fn path_in(&self, target: &CollectionTarget, uri: &ObjectUri) -> ResourcePath {
        match self.bindings.get(&target.binding) {
            Some(binding) => Self::object_path(&target.tenant_slug, &target.home_name, &binding.slug, uri),
            None => ResourcePath::Root,
        }
    }

    fn object_view(
        &self,
        target: &CollectionTarget,
        object: &StoredObject,
        data: &CalendarDataSpec,
    ) -> AppResult<ObjectView> {
        let calendar = self.calendar_of(target)?;
        let facts = self.access_facts_for(Some(target.home), calendar);
        let access = effective_access(target.home, &facts).unwrap_or(Access::Read);
        Ok(ObjectView {
            path: self.path_in(target, &object.uri),
            id: object.id,
            calendar_id: object.calendar_id,
            uid: object.uid.clone(),
            component: object.component,
            etag: object.etag.clone(),
            schedule_tag: object.schedule_tag.clone(),
            size: object.size,
            last_modified: object.updated_at,
            data: data.include_data.then(|| object.data.clone()),
            privileges: privileges(access, calendar.kind, ResourceKind::Object),
        })
    }

    fn get_object(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<ObjectView> {
        let (target, uri) = self.object_target(ctx, path)?;
        let calendar = self.calendar_of(&target)?;
        self.enforce(ctx, calendar, Operation::ReadObject, || path.href())?;
        let object = self
            .object_by_uri(target.calendar, &uri)
            .ok_or_else(AppError::not_found)?;
        self.object_view(&target, object, &CalendarDataSpec::default())
    }

    /// Checks a body and returns its UID and component type.
    fn validate_body(&self, calendar: &Calendar, body: &str) -> AppResult<(Uid, ComponentKind)> {
        // The size an object may have is `limits.ical.max_resource_size` of the world (PLAN 2.15).
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > self.limits.ical.max_resource_size {
            return Err(AppError::too_large().with_precondition(Precondition::MaxResourceSize));
        }
        if !has_envelope(body) {
            return Err(calendar_data_error("The data is not an iCalendar object."));
        }
        let component =
            component_of(body).ok_or_else(|| calendar_data_error("The object has no event, to-do or journal."))?;
        let uid = uid_of(body).ok_or_else(|| calendar_data_error("The object has no UID."))?;
        if !calendar.components.contains(&component) {
            return Err(invalid("The calendar does not accept this component.")
                .with_precondition(Precondition::SupportedCalendarComponent));
        }
        Ok((uid, component))
    }

    /// The `no-uid-conflict` error when another object of the calendar has the UID.
    fn check_uid_free(&self, target: &CollectionTarget, uid: &Uid, allowed: &[&ObjectUri]) -> AppResult<()> {
        let conflict = self
            .objects_of(target.calendar)
            .into_iter()
            .find(|object| &object.uid == uid && !allowed.contains(&&object.uri));
        match conflict {
            Some(other) => Err(AppError::conflict()
                .with_precondition(Precondition::NoUidConflict(self.path_in(target, &other.uri).href()))),
            None => Ok(()),
        }
    }

    fn put_object(&mut self, ctx: &RequestContext, request: PutRequest) -> AppResult<PutOutcome> {
        let (target, uri) = self.object_target(ctx, &request.path)?;
        let existing = self.object_by_uri(target.calendar, &uri).cloned();
        let calendar = self.calendar_of(&target)?;
        let operation = if existing.is_some() {
            Operation::UpdateObject
        } else {
            Operation::CreateObject
        };
        self.enforce(ctx, calendar, operation, || request.path.href())?;
        check_preconditions(&request.preconditions, existing.as_ref())?;
        let (uid, component) = self.validate_body(calendar, &request.body)?;
        self.check_uid_free(&target, &uid, &[&uri])?;
        let stored = self.store_object(target.calendar, uri, uid, component, request.body, None)?;
        Ok(PutOutcome {
            etag: Some(stored.etag),
            schedule_tag: stored.schedule_tag,
            created: existing.is_none(),
            schedule: ScheduleOutcome::none(),
        })
    }

    fn delete_object(&mut self, ctx: &RequestContext, request: &DeleteRequest) -> AppResult<DeleteOutcome> {
        let (target, uri) = self.object_target(ctx, &request.path)?;
        let calendar = self.calendar_of(&target)?;
        self.enforce(ctx, calendar, Operation::DeleteObject, || request.path.href())?;
        let existing = self
            .object_by_uri(target.calendar, &uri)
            .cloned()
            .ok_or_else(AppError::not_found)?;
        check_preconditions(&request.preconditions, Some(&existing))?;
        self.remove_object(existing.id)?;
        Ok(DeleteOutcome::default())
    }

    fn relocate(
        &mut self,
        ctx: &RequestContext,
        from: &ResourcePath,
        to: &ResourcePath,
        overwrite: bool,
        preconditions: Option<&WritePrecondition>,
        keep_source: bool,
    ) -> AppResult<MoveOutcome> {
        let (source_target, source_uri) = self.object_target(ctx, from)?;
        let (dest_target, dest_uri) = self.object_target(ctx, to)?;
        let (from_op, to_op) = if keep_source {
            (Operation::CopyObjectFrom, Operation::CopyObjectTo)
        } else {
            (Operation::MoveObjectFrom, Operation::MoveObjectTo)
        };
        let source_calendar = self.calendar_of(&source_target)?;
        self.enforce(ctx, source_calendar, from_op, || from.href())?;
        let source = self
            .object_by_uri(source_target.calendar, &source_uri)
            .cloned()
            .ok_or_else(AppError::not_found)?;
        if let Some(preconditions) = preconditions {
            check_preconditions(preconditions, Some(&source))?;
        }
        let dest_calendar = self.calendar_of(&dest_target)?;
        let existing = self.object_by_uri(dest_target.calendar, &dest_uri).cloned();
        let dest_op = if existing.is_some() {
            Operation::UpdateObject
        } else {
            to_op
        };
        self.enforce(ctx, dest_calendar, dest_op, || to.href())?;
        if existing.is_some() && !overwrite {
            return Err(AppError::precondition_failed());
        }
        let same_place = source_target.calendar == dest_target.calendar && source_uri == dest_uri;
        if same_place {
            return Err(invalid("The source and the target are the same resource."));
        }
        let mut allowed: Vec<&ObjectUri> = vec![&dest_uri];
        if !keep_source && source_target.calendar == dest_target.calendar {
            allowed.push(&source_uri);
        }
        self.check_uid_free(&dest_target, &source.uid, &allowed)?;
        if !keep_source {
            self.remove_object(source.id)?;
        }
        let stored = self.store_object(
            dest_target.calendar,
            dest_uri,
            source.uid,
            source.component,
            source.data,
            None,
        )?;
        Ok(MoveOutcome {
            created: existing.is_none(),
            etag: stored.etag,
        })
    }

    fn multiget_objects(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        paths: &[ResourcePath],
        data: &CalendarDataSpec,
    ) -> AppResult<Vec<MultigetEntry>> {
        let target = self.resolve_collection(ctx, collection)?;
        let calendar = self.calendar_of(&target)?;
        self.enforce(ctx, calendar, Operation::ListObjects, || collection.href())?;
        let mut entries = Vec::with_capacity(paths.len());
        for path in paths {
            let found = match path {
                ResourcePath::Object {
                    tenant,
                    principal,
                    binding,
                    object,
                } if matches!(
                    collection,
                    ResourcePath::Collection { tenant: t, principal: p, binding: b }
                        if t == tenant && p == principal && b == binding
                ) =>
                {
                    self.object_by_uri(target.calendar, object)
                }
                _ => None,
            };
            entries.push(match found {
                Some(object) => MultigetEntry::Found(self.object_view(&target, object, data)?),
                None => MultigetEntry::Missing(path.clone()),
            });
        }
        Ok(entries)
    }

    fn query_objects(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        filter: &ObjectFilter,
        data: &CalendarDataSpec,
    ) -> AppResult<Vec<ObjectHit>> {
        let target = self.resolve_collection(ctx, collection)?;
        let calendar = self.calendar_of(&target)?;
        self.enforce(ctx, calendar, Operation::ListObjects, || collection.href())?;
        self.objects_of(target.calendar)
            .into_iter()
            .filter(|object| matches_filter(object, filter))
            .map(|object| self.object_view(&target, object, data))
            .collect()
    }

    fn sync_collection(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<SyncResult> {
        if !matches!(collection, ResourcePath::Collection { .. }) {
            // The home, the inbox and the notification collection have no members in the fake.
            let (ResourcePath::Home { tenant, principal }
            | ResourcePath::Inbox { tenant, principal }
            | ResourcePath::Notifications { tenant, principal }) = collection
            else {
                return Err(AppError::not_found());
            };
            let (tenant, home) = self.home_principal(ctx, tenant, principal)?;
            return Ok(SyncResult {
                sync_token: SyncToken::new(home.id.as_uuid(), tenant.id.as_uuid(), 0),
                changes: Vec::new(),
                truncated: false,
            });
        }
        let target = self.resolve_collection(ctx, collection)?;
        let calendar = self.calendar_of(&target)?;
        self.enforce(ctx, calendar, Operation::ListObjects, || collection.href())?;
        let current = u64::try_from(calendar.sync_seq).unwrap_or(0);
        let Some(token) = since else {
            let changes = self
                .objects_of(target.calendar)
                .into_iter()
                .map(|object| SyncChange {
                    path: self.path_in(&target, &object.uri),
                    kind: davhaven_wire::ChangeKind::Upsert,
                    etag: Some(object.etag.clone()),
                })
                .collect();
            return Ok(SyncResult {
                sync_token: SyncToken::new(calendar.id.as_uuid(), calendar.sync_epoch, current),
                changes,
                truncated: false,
            });
        };
        let from = token
            .resume_from(
                calendar.id.as_uuid(),
                calendar.sync_epoch,
                u64::try_from(calendar.sync_min_seq).unwrap_or(0),
                current,
            )
            .map_err(|_| {
                AppError::invalid(SafeMessage::from_static("The sync token is not valid."))
                    .with_precondition(Precondition::ValidSyncToken)
            })?;
        let (entries, resume, truncated) = self.changes_since(calendar.id, from, limit, current);
        let changes = entries
            .into_iter()
            .map(|(uri, deleted)| {
                let etag = self
                    .object_by_uri(target.calendar, &uri)
                    .map(|object| object.etag.clone());
                SyncChange {
                    path: self.path_in(&target, &uri),
                    kind: if deleted {
                        davhaven_wire::ChangeKind::Delete
                    } else {
                        davhaven_wire::ChangeKind::Upsert
                    },
                    etag: if deleted { None } else { etag },
                }
            })
            .collect();
        Ok(SyncResult {
            sync_token: SyncToken::new(calendar.id.as_uuid(), calendar.sync_epoch, resume),
            changes,
            truncated,
        })
    }

    /// The collapsed changes after `from`: one entry per resource name (the latest change wins), oldest first,
    /// at most `limit`. Returns the entries, the sequence number to resume from and whether the list is cut.
    fn changes_since(
        &self,
        calendar: CalendarId,
        from: u64,
        limit: Option<u32>,
        current: u64,
    ) -> (Vec<(ObjectUri, bool)>, u64, bool) {
        let log = self.changes.get(&calendar).map(Vec::as_slice).unwrap_or_default();
        let newer: Vec<_> = log
            .iter()
            .filter(|change| u64::try_from(change.seq).is_ok_and(|seq| seq > from))
            .collect();
        let mut collapsed: Vec<(ObjectUri, bool, i64)> = Vec::new();
        for change in newer {
            if let Some(entry) = collapsed.iter_mut().find(|(uri, _, _)| *uri == change.uri) {
                entry.1 = change.deleted;
                entry.2 = change.seq;
            } else {
                collapsed.push((change.uri.clone(), change.deleted, change.seq));
            }
        }
        collapsed.sort_by_key(|(_, _, seq)| *seq);
        let size = limit.map_or(usize::MAX, |limit| usize::try_from(limit.max(1)).unwrap_or(usize::MAX));
        let truncated = collapsed.len() > size;
        collapsed.truncate(size);
        let resume = if truncated {
            collapsed
                .last()
                .and_then(|(_, _, seq)| u64::try_from(*seq).ok())
                .unwrap_or(current)
        } else {
            current
        };
        (
            collapsed.into_iter().map(|(uri, deleted, _)| (uri, deleted)).collect(),
            resume,
            truncated,
        )
    }

    // -----------------------------------------------------------------------------------------------------
    // JSON events
    // -----------------------------------------------------------------------------------------------------

    fn event_view(&self, tenant: &FakeTenant, object: &StoredObject) -> AppResult<EventView> {
        let calendar = self
            .calendars
            .get(&object.calendar_id)
            .ok_or_else(AppError::not_found)?;
        let owner = self
            .principals
            .get(&calendar.owner_id)
            .ok_or_else(AppError::not_found)?;
        let binding = self
            .binding_for(owner.id, calendar.id)
            .map_or_else(|| calendar.slug.clone(), |binding| binding.slug.clone());
        let path = Self::object_path(&tenant.slug, &owner.name, &binding, &object.uri);
        let mut data = event_data(&object.data);
        data.uid = Some(object.uid.clone());
        Ok(EventView {
            id: Some(object.id),
            calendar_id: Some(object.calendar_id),
            uri: Some(object.uri.clone()),
            external_key: object.external_key.clone(),
            etag: Some(object.etag.clone()),
            schedule_tag: object.schedule_tag.clone(),
            dav_url: Some(self.urls.dav_url(&path)),
            created_at: Some(object.created_at),
            updated_at: Some(object.updated_at),
            data,
        })
    }

    fn selected(&self, calendar: CalendarId, selector: &ObjectSelector) -> AppResult<&StoredObject> {
        let objects = self.objects_of(calendar);
        let found = match selector {
            ObjectSelector::Key(key) => objects
                .into_iter()
                .find(|object| object.external_key.as_ref() == Some(key)),
            ObjectSelector::Uri(uri) => objects.into_iter().find(|object| &object.uri == uri),
            ObjectSelector::Uid(uid) => objects.into_iter().find(|object| &object.uid == uid),
            ObjectSelector::Id(id) => objects.into_iter().find(|object| object.id == *id),
        };
        found.ok_or_else(AppError::not_found)
    }

    fn api_calendar(&self, ctx: &RequestContext, reference: &CalendarRef, operation: Operation) -> AppResult<Calendar> {
        let id = self.calendar_id_of(ctx, reference)?;
        let calendar = self.calendar(ctx.tenant, id).ok_or_else(AppError::not_found)?;
        self.enforce(ctx, calendar, operation, || ResourcePath::Root.href())?;
        Ok(calendar.clone())
    }

    fn get_event_json(
        &self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        selector: &ObjectSelector,
        instance: Option<&EventTime>,
    ) -> AppResult<EventView> {
        let calendar = self.api_calendar(ctx, reference, Operation::ReadObject)?;
        let object = self.selected(calendar.id, selector)?;
        if instance.is_some() {
            // The fake has no recurring events, so no instance can be addressed.
            return Err(AppError::not_found());
        }
        self.event_view(self.tenant_of(ctx)?, object)
    }

    fn put_event_json(
        &mut self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        write: &EventWrite,
    ) -> AppResult<EventWriteOutcome> {
        // Decided before the object is looked up (as the application does): a caller who may not write here learns
        // nothing about what is here, and one who may only write does not need to read.
        let probe = self.api_calendar(ctx, reference, Operation::CreateObject)?;
        let existing = match &write.target {
            None => None,
            Some(ObjectSelector::Key(key)) => self
                .objects_of(probe.id)
                .into_iter()
                .find(|object| object.external_key.as_ref() == Some(key))
                .cloned(),
            Some(selector) => Some(self.selected(probe.id, selector)?.clone()),
        };
        let operation = if existing.is_some() {
            Operation::UpdateObject
        } else {
            Operation::CreateObject
        };
        let calendar = self.api_calendar(ctx, reference, operation)?;
        match (&write.if_match, &existing) {
            (Some(expected), Some(object)) if &object.etag != expected => return Err(AppError::precondition_failed()),
            (Some(_), None) => return Err(AppError::precondition_failed()),
            _ => {}
        }
        let key = match &write.target {
            Some(ObjectSelector::Key(key)) => Some(key.clone()),
            _ => None,
        };
        let (uid, uri, base) = if let Some(object) = &existing {
            (object.uid.clone(), object.uri.clone(), event_data(&object.data))
        } else {
            let uid = match (&key, &write.event.data.uid) {
                (Some(key), _) => Uid::deterministic(calendar.id, key),
                (None, Some(uid)) => uid.clone(),
                (None, None) => Uid::from_uuid(self.next_uuid()),
            };
            (
                uid.clone(),
                ObjectUri::for_uid(&uid),
                davhaven_domain::EventData::default(),
            )
        };
        let merged = overlay(base, &write.event.data);
        merged
            .validate(&IcalLimits::default())
            .map_err(|_| invalid("The event is not valid."))?;
        if existing.is_none() && merged.start.is_none() {
            return Err(invalid("A new event needs a start."));
        }
        let text = render_event(&merged, &uid, self.now());
        let tenant_id = calendar.tenant_id;
        if existing.is_none() && self.object_by_uri(calendar.id, &uri).is_some() {
            return Err(AppError::conflict().with_precondition(Precondition::NoUidConflict(
                self.path_in_calendar(tenant_id, &calendar, &uri)?,
            )));
        }
        let stored = self.store_object(calendar.id, uri, uid, ComponentKind::Event, text, key)?;
        let tenant = self.tenant(tenant_id).ok_or_else(AppError::not_found)?;
        Ok(EventWriteOutcome {
            event: self.event_view(tenant, &stored)?,
            created: existing.is_none(),
            schedule: ScheduleOutcome::none(),
        })
    }

    /// Creates an event once: with a key, an event that has it is returned when the fields would change nothing and is
    /// a conflict when they would (the fake merges without writing to tell).
    fn create_event_json(
        &mut self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        create: &EventCreate,
    ) -> AppResult<EventWriteOutcome> {
        let calendar = self.api_calendar(ctx, reference, Operation::CreateObject)?;
        let existing = create.key.as_ref().and_then(|key| {
            self.objects_of(calendar.id)
                .into_iter()
                .find(|object| object.external_key.as_ref() == Some(key))
                .cloned()
        });
        if let Some(object) = existing {
            let stored = event_data(&object.data);
            if overlay(stored.clone(), &create.event.data) != stored {
                return Err(AppError::conflict().with_public_message(SafeMessage::from_static(
                    "The key already names an event with other content.",
                )));
            }
            return Ok(EventWriteOutcome {
                event: self.event_view(self.tenant_of(ctx)?, &object)?,
                created: false,
                schedule: ScheduleOutcome::none(),
            });
        }
        let write = EventWrite {
            target: create.key.clone().map(ObjectSelector::Key),
            event: create.event.clone(),
            notify_attendees: create.notify_attendees,
            if_match: None,
            scope: ChangeScope::All,
        };
        self.put_event_json(ctx, reference, &write)
    }

    fn path_in_calendar(
        &self,
        tenant: davhaven_domain::TenantId,
        calendar: &Calendar,
        uri: &ObjectUri,
    ) -> AppResult<davhaven_domain::Href> {
        let tenant = self.tenant(tenant).ok_or_else(AppError::not_found)?;
        let owner = self
            .principals
            .get(&calendar.owner_id)
            .ok_or_else(AppError::not_found)?;
        let binding = self
            .binding_for(owner.id, calendar.id)
            .map_or_else(|| calendar.slug.clone(), |binding| binding.slug.clone());
        Ok(Self::object_path(&tenant.slug, &owner.name, &binding, uri).href())
    }

    /// Deletes an event. With `missing_ok`, a whole event without `if_match` that is not there is `Ok(false)`, after the
    /// deletion was decided (as the application answers it).
    fn delete_event_json(
        &mut self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        selector: &ObjectSelector,
        options: &DeleteEventOptions,
        missing_ok: bool,
    ) -> AppResult<bool> {
        let calendar = self.api_calendar(ctx, reference, Operation::DeleteObject)?;
        let object = match self.selected(calendar.id, selector) {
            Ok(object) => object.clone(),
            Err(error)
                if missing_ok
                    && error.kind() == ErrorKind::NotFound
                    && options.scope == ChangeScope::All
                    && options.if_match.is_none() =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if options
            .if_match
            .as_ref()
            .is_some_and(|expected| expected != &object.etag)
        {
            return Err(AppError::precondition_failed());
        }
        self.remove_object(object.id)?;
        Ok(true)
    }

    fn list_events(
        &self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        filter: &ObjectFilter,
        page: &PageRequest,
    ) -> AppResult<Page<EventView>> {
        let calendar = self.api_calendar(ctx, reference, Operation::ListObjects)?;
        let tenant = self.tenant_of(ctx)?;
        let mut items = Vec::new();
        for object in self
            .objects_of(calendar.id)
            .into_iter()
            .filter(|object| matches_filter(object, filter))
        {
            items.push((object.id.as_uuid(), self.event_view(tenant, object)?));
        }
        paginate(items, page.limit, page.cursor.as_ref())
    }

    fn search_all(&self, ctx: &RequestContext, search: &EventSearch, page: &PageRequest) -> AppResult<Page<EventView>> {
        let text = match &search.text {
            Some(text) => {
                let text = text.trim().to_lowercase();
                if text.chars().count() < 2 {
                    return Err(invalid("The search text needs at least two characters."));
                }
                Some(text)
            }
            None => None,
        };
        let tenant = self.tenant_of(ctx)?;
        let calendars: Vec<CalendarId> = if search.calendars.is_empty() {
            self.calendars
                .values()
                .filter(|calendar| calendar.tenant_id == tenant.id && calendar.deleted_at.is_none())
                .filter(|calendar| {
                    self.decision(ctx, calendar, Operation::ListObjects) == davhaven_domain::Decision::Allow
                })
                .map(|calendar| calendar.id)
                .collect()
        } else {
            let mut ids = Vec::new();
            for reference in &search.calendars {
                ids.push(self.api_calendar(ctx, reference, Operation::ListObjects)?.id);
            }
            ids
        };
        let mut items = Vec::new();
        for object in self
            .objects
            .values()
            .filter(|object| calendars.contains(&object.calendar_id))
        {
            let view = self.event_view(tenant, object)?;
            let matches_text = text.as_ref().is_none_or(|text| {
                [&view.data.summary, &view.data.description, &view.data.location]
                    .iter()
                    .filter_map(|field| field.as_ref())
                    .any(|field| field.to_lowercase().contains(text))
            });
            if matches_text {
                items.push((object.id.as_uuid(), view));
            }
        }
        paginate(items, page.limit, page.cursor.as_ref())
    }

    fn calendar_changes(
        &self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<ChangesResponse> {
        let calendar = self.api_calendar(ctx, reference, Operation::ListObjects)?;
        let current = u64::try_from(calendar.sync_seq).unwrap_or(0);
        let from = match since {
            None => 0,
            Some(token) => token
                .resume_from(
                    calendar.id.as_uuid(),
                    calendar.sync_epoch,
                    u64::try_from(calendar.sync_min_seq).unwrap_or(0),
                    current,
                )
                .map_err(|_| {
                    AppError::invalid(SafeMessage::from_static("The sync token is not valid."))
                        .with_precondition(Precondition::ValidSyncToken)
                })?,
        };
        let (entries, resume, truncated) = self.changes_since(calendar.id, from, limit, current);
        let changes = entries
            .into_iter()
            .map(|(uri, deleted)| {
                let object = self.object_by_uri(calendar.id, &uri);
                ChangeView {
                    kind: if deleted {
                        davhaven_wire::ChangeKind::Delete
                    } else {
                        davhaven_wire::ChangeKind::Upsert
                    },
                    uri,
                    uid: object.map(|object| object.uid.clone()),
                    external_key: object.and_then(|object| object.external_key.clone()),
                    etag: if deleted {
                        None
                    } else {
                        object.map(|object| object.etag.clone())
                    },
                }
            })
            .collect();
        Ok(ChangesResponse {
            sync_token: SyncToken::new(calendar.id.as_uuid(), calendar.sync_epoch, resume),
            changes,
            truncated,
        })
    }

    // -----------------------------------------------------------------------------------------------------
    // Batch
    // -----------------------------------------------------------------------------------------------------

    /// The object of the calendar with the external key.
    fn object_by_key(&self, calendar: CalendarId, key: &ExternalKey) -> Option<StoredObject> {
        self.objects_of(calendar)
            .into_iter()
            .find(|object| object.external_key.as_ref() == Some(key))
            .cloned()
    }

    /// The external keys a batch deletes: the explicit `deletes` and, in `replace` mode, every object of the
    /// scope that the batch does not list.
    fn batch_deletions(&self, calendar: CalendarId, request: &BatchRequest) -> AppResult<Vec<ExternalKey>> {
        let mut deleted_keys: Vec<ExternalKey> = request.deletes.clone();
        if request.mode == BatchMode::Replace {
            let prefix = request.replace_scope_prefix.clone().unwrap_or_default();
            for object in self.objects_of(calendar) {
                if let Some(key) = &object.external_key
                    && key.as_str().starts_with(&prefix)
                    && !request.items.iter().any(|item| &item.external_key == key)
                    && !deleted_keys.contains(key)
                {
                    deleted_keys.push(key.clone());
                }
            }
        }
        if request
            .max_deletes
            .is_some_and(|max| usize::try_from(max).is_ok_and(|max| deleted_keys.len() > max))
        {
            return Err(invalid("The batch would delete more objects than max_deletes allows."));
        }
        Ok(deleted_keys)
    }

    /// The sync token of a calendar as it is now.
    fn current_token(&self, calendar: CalendarId) -> AppResult<SyncToken> {
        let calendar = self.calendars.get(&calendar).ok_or_else(AppError::not_found)?;
        Ok(SyncToken::new(
            calendar.id.as_uuid(),
            calendar.sync_epoch,
            u64::try_from(calendar.sync_seq).unwrap_or(0),
        ))
    }

    fn batch_upsert(
        &mut self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        request: &BatchRequest,
    ) -> AppResult<BatchResult> {
        request.validate(&ApiLimits::default()).map_err(|error| {
            AppError::invalid(SafeMessage::sanitized(&format!("{}: {}", error.pointer, error.message)))
        })?;
        let calendar = self.api_calendar(ctx, reference, Operation::BatchUpsert)?;
        let plan: Vec<BatchStep> = request
            .items
            .iter()
            .map(|item| self.plan_item(&calendar, item, self.object_by_key(calendar.id, &item.external_key)))
            .collect();
        let deleted_keys = self.batch_deletions(calendar.id, request)?;
        let mut results: Vec<BatchItemResult> = plan.iter().map(BatchStep::result).collect();
        for key in &deleted_keys {
            let existing = self.object_by_key(calendar.id, key);
            results.push(BatchItemResult {
                external_key: key.clone(),
                outcome: if existing.is_some() {
                    BatchOutcome::Deleted
                } else {
                    BatchOutcome::Unchanged
                },
                uid: existing.as_ref().map(|object| object.uid.clone()),
                uri: existing.as_ref().map(|object| object.uri.clone()),
                etag: None,
                problem: None,
            });
        }
        if results.iter().any(|result| result.outcome == BatchOutcome::Failed) {
            return Ok(BatchResult {
                sync_token: self.current_token(calendar.id)?,
                results,
            });
        }
        let mut applied = Vec::new();
        for (step, result) in plan.into_iter().zip(results.iter()) {
            if matches!(result.outcome, BatchOutcome::Created | BatchOutcome::Updated)
                && let Some(write) = step.write
            {
                let stored = self.store_object(
                    calendar.id,
                    write.uri,
                    write.uid,
                    write.component,
                    write.text,
                    Some(write.key),
                )?;
                applied.push((stored.external_key.clone(), stored.etag));
            }
        }
        for key in &deleted_keys {
            if let Some(object) = self.object_by_key(calendar.id, key) {
                self.remove_object(object.id)?;
            }
        }
        for result in &mut results {
            if let Some((_, etag)) = applied
                .iter()
                .find(|(key, _)| key.as_ref() == Some(&result.external_key))
            {
                result.etag = Some(etag.clone());
            } else if result.outcome == BatchOutcome::Unchanged {
                result.etag = self
                    .object_by_key(calendar.id, &result.external_key)
                    .map(|object| object.etag);
            }
        }
        Ok(BatchResult {
            sync_token: self.current_token(calendar.id)?,
            results,
        })
    }

    fn plan_item(
        &self,
        calendar: &Calendar,
        item: &davhaven_wire::BatchItem,
        existing: Option<StoredObject>,
    ) -> BatchStep {
        let fail = |text: &'static str| BatchStep {
            key: item.external_key.clone(),
            outcome: BatchOutcome::Failed,
            uid: None,
            uri: None,
            problem: Some(ProblemDetails::new(ProblemCode::ValidationFailed).with_detail(text)),
            write: None,
            existing_etag: None,
        };
        let (uid, component, text) = match (&item.ical, &item.event) {
            (Some(ical), None) => match self.validate_body(calendar, ical) {
                Ok((uid, component)) => (uid, component, ical.clone()),
                Err(_) => return fail("The iCalendar data is not valid."),
            },
            (None, Some(view)) => {
                let uid = view
                    .data
                    .uid
                    .clone()
                    .unwrap_or_else(|| Uid::deterministic(calendar.id, &item.external_key));
                // Like the real application, the item is a patch of the stored event: what it does not name stays,
                // and `null` removes.
                let stored = existing
                    .as_ref()
                    .map(|object| event_data(&object.data))
                    .unwrap_or_default();
                let merged = overlay(stored, &view.data);
                if merged.start.is_none() {
                    return fail("An event needs a start.");
                }
                let text = render_event(&merged, &uid, self.now());
                (uid, ComponentKind::Event, text)
            }
            _ => return fail("Exactly one of event and ical is required."),
        };
        let uri = existing
            .as_ref()
            .map_or_else(|| ObjectUri::for_uid(&uid), |object| object.uri.clone());
        let unchanged = existing.as_ref().is_some_and(|object| match (&item.ical, &item.event) {
            (Some(ical), _) => &object.data == ical,
            (None, Some(view)) => {
                let stored = event_data(&object.data);
                overlay(stored.clone(), &view.data) == stored
            }
            _ => false,
        });
        BatchStep {
            key: item.external_key.clone(),
            outcome: if unchanged {
                BatchOutcome::Unchanged
            } else if existing.is_some() {
                BatchOutcome::Updated
            } else {
                BatchOutcome::Created
            },
            uid: Some(uid.clone()),
            uri: Some(uri.clone()),
            problem: None,
            existing_etag: existing.map(|object| object.etag),
            write: (!unchanged).then(|| BatchWrite {
                key: item.external_key.clone(),
                uid,
                uri,
                component,
                text,
            }),
        }
    }
}

/// What a batch entry will do.
struct BatchStep {
    key: ExternalKey,
    outcome: BatchOutcome,
    uid: Option<Uid>,
    uri: Option<ObjectUri>,
    problem: Option<ProblemDetails>,
    write: Option<BatchWrite>,
    existing_etag: Option<ETag>,
}

/// The write of a changed batch entry.
struct BatchWrite {
    key: ExternalKey,
    uid: Uid,
    uri: ObjectUri,
    component: ComponentKind,
    text: String,
}

impl BatchStep {
    fn result(&self) -> BatchItemResult {
        BatchItemResult {
            external_key: self.key.clone(),
            outcome: self.outcome,
            uid: self.uid.clone(),
            uri: self.uri.clone(),
            etag: self
                .existing_etag
                .clone()
                .filter(|_| self.outcome == BatchOutcome::Unchanged),
            problem: self.problem.clone(),
        }
    }
}

/// The narrowing the fake applies to queries and listings.
fn matches_filter(object: &StoredObject, filter: &ObjectFilter) -> bool {
    filter.component.is_none_or(|component| object.component == component)
        && filter.uid.as_ref().is_none_or(|uid| &object.uid == uid)
        && filter
            .external_key
            .as_ref()
            .is_none_or(|key| object.external_key.as_ref() == Some(key))
}

#[async_trait]
impl ObjectService for FakeObjects {
    async fn get(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<ObjectView> {
        self.state.read(|world| world.get_object(ctx, path)).await
    }

    async fn put(&self, ctx: &RequestContext, request: PutRequest) -> AppResult<PutOutcome> {
        self.state.write(|world| world.put_object(ctx, request)).await
    }

    async fn delete(&self, ctx: &RequestContext, request: DeleteRequest) -> AppResult<DeleteOutcome> {
        self.state.write(|world| world.delete_object(ctx, &request)).await
    }

    async fn move_to(&self, ctx: &RequestContext, request: MoveRequest) -> AppResult<MoveOutcome> {
        self.state
            .write(|world| {
                world.relocate(
                    ctx,
                    &request.from,
                    &request.to,
                    request.overwrite,
                    Some(&request.preconditions),
                    false,
                )
            })
            .await
    }

    async fn copy_to(&self, ctx: &RequestContext, request: CopyRequest) -> AppResult<MoveOutcome> {
        self.state
            .write(|world| world.relocate(ctx, &request.from, &request.to, request.overwrite, None, true))
            .await
    }

    async fn multiget(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        paths: Vec<ResourcePath>,
        data: CalendarDataSpec,
    ) -> AppResult<Vec<MultigetEntry>> {
        self.state
            .read(|world| world.multiget_objects(ctx, collection, &paths, &data))
            .await
    }

    async fn query(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        filter: ObjectFilter,
        data: CalendarDataSpec,
    ) -> AppResult<Vec<ObjectHit>> {
        self.state
            .read(|world| world.query_objects(ctx, collection, &filter, &data))
            .await
    }

    async fn sync(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<SyncResult> {
        self.state
            .read(|world| world.sync_collection(ctx, collection, since, limit))
            .await
    }

    async fn batch(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        request: BatchRequest,
    ) -> AppResult<BatchResult> {
        self.state
            .write(|world| world.batch_upsert(ctx, calendar, &request))
            .await
    }

    async fn get_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        instance: Option<EventTime>,
    ) -> AppResult<EventView> {
        self.state
            .read(|world| world.get_event_json(ctx, calendar, selector, instance.as_ref()))
            .await
    }

    async fn put_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        write: EventWrite,
    ) -> AppResult<EventWriteOutcome> {
        self.state
            .write(|world| world.put_event_json(ctx, calendar, &write))
            .await
    }

    async fn create_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        create: EventCreate,
    ) -> AppResult<EventWriteOutcome> {
        self.state
            .write(|world| world.create_event_json(ctx, calendar, &create))
            .await
    }

    async fn delete_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<()> {
        self.state
            .write(|world| world.delete_event_json(ctx, calendar, selector, &options, false))
            .await
            .map(|_| ())
    }

    async fn delete_event_if_present(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<bool> {
        self.state
            .write(|world| world.delete_event_json(ctx, calendar, selector, &options, true))
            .await
    }

    async fn list(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        filter: ObjectFilter,
        page: PageRequest,
    ) -> AppResult<Page<EventView>> {
        self.state
            .read(|world| world.list_events(ctx, calendar, &filter, &page))
            .await
    }

    async fn search_events(
        &self,
        ctx: &RequestContext,
        search: EventSearch,
        page: PageRequest,
    ) -> AppResult<Page<EventView>> {
        self.state.read(|world| world.search_all(ctx, &search, &page)).await
    }

    async fn changes(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<ChangesResponse> {
        self.state
            .read(|world| world.calendar_changes(ctx, calendar, since, limit))
            .await
    }
}
