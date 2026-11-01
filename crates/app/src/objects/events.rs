//! The JSON event interface of the management API and MCP.
//!
//! JSON writes are **merged** into the stored component (`davhaven_ical::merge`): the fields of the request replace
//! the stored values, absent fields keep them, and everything the event model does not know (unknown and `X-`
//! properties, attendee parameters, alarms the caller did not mention) survives. The write shares its storage path
//! with the DAV `PUT` ([`ObjectServiceImpl::store`]): the same change log, the same domain event, the same unique
//! rules. Differences that are the point of this interface:
//!
//! * the object is addressed by a stable key, resource name, UID or id (`ObjectSelector`); a key that does not exist
//!   creates the object with the deterministic UID `UUIDv5(calendar_id, key)`;
//! * a write whose result has the content hash of the stored object changes nothing (no `ETag`, no sequence bump), so
//!   polling integrations stay quiet (PLAN 2.7);
//! * attendees are told only when the caller asks (`notify_attendees`), and only where a scheduler is installed;
//! * "this and all following instances" splits the series in two objects like calendar clients do;
//! * MCP writes are audited (`mcp.write`) in the transaction of the write.

use chrono::{DateTime, Duration, Utc};
use davhaven_domain::audit::McpWriteAudit;
use davhaven_domain::events::{ObjectChange, ObjectChangeKind};
use davhaven_domain::{
    AuditEvent, CalendarId, CalendarKind, CalendarSlug, Channel, Classification, EventData, EventTime, ExternalKey,
    IcalLimits, ObjectUri, Operation, PrincipalName, RequestContext, StoredObject, Tenant, TimeZoneName, Uid,
};
use davhaven_ical::ErrorContext;
use davhaven_ical::merge::{EditScope, MergeContext};
use davhaven_ports::{Expected, PageReq, StoreError, Tx, TxMode, WriteResult};
use davhaven_wire::mcp::ChangeScope;
use davhaven_wire::{EventView, Page};
use url::Url;

use super::ObjectServiceImpl;
use super::dav::{Scheduling, StoreRequest};
use super::locate::{ApiCalendar, WriteTarget, api_calendar, api_calendar_raw, change, home_for, publish_changes};
use super::prepare::{Prepared, prepare_calendar};
use super::query::{index_filter_of, zone_of};
use super::schedule::DeleteFacts;
use super::sight::{busy_form, hides, masks};
use crate::audit::Journal;
use crate::authz::{blocking, busy_only, enforce_api, field_error, found, require_scope, retrying};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::paging;
use crate::services::{
    CalendarDataSpec, CalendarRef, DeleteEventOptions, EventCreate, EventWrite, EventWriteOutcome, ObjectFilter,
    ObjectSelector, PageRequest, ScheduleOutcome, ScheduleReply,
};

use crate::texts::DEFAULT_ALARM_TEXT;

/// How the events of one calendar are shown to the caller: the links to the collection in a home, when the caller
/// has one, and, for a caller that reads through MCP in a calendar it does not own, which events are only the time they
/// block (`sight`).
pub(crate) struct Linker {
    urls: davhaven_domain::PublicUrls,
    tenant: davhaven_domain::TenantSlug,
    home: Option<(PrincipalName, CalendarSlug)>,
    /// Whether the caller reads through MCP in a calendar it does not own: events that are private to others come out
    /// in their busy form. `false` shows every event as it is.
    masked: bool,
}

impl Linker {
    /// Whether an object of this class is only busy time to the caller (see the `sight` module): the caller reads
    /// through MCP in a calendar it does not own, and the class is restricted.
    pub(crate) fn hides_class(&self, class: Classification) -> bool {
        self.masked && busy_only(class, false)
    }

    /// The principal and the binding slug the links go through, when the caller has the collection in a home.
    pub(crate) fn home(&self) -> Option<(&PrincipalName, &CalendarSlug)> {
        self.home.as_ref().map(|(principal, binding)| (principal, binding))
    }

    /// The DAV URL of an object.
    pub(crate) fn url(&self, uri: &ObjectUri) -> Option<Url> {
        let (principal, binding) = self.home.as_ref()?;
        Some(self.urls.dav_url(&davhaven_domain::ResourcePath::Object {
            tenant: self.tenant.clone(),
            principal: principal.clone(),
            binding: binding.clone(),
            object: uri.clone(),
        }))
    }

    /// The view of an event: the stored metadata and the event fields, or for an event that the caller may only see
    /// as busy time (see the `sight` module) the identity of the object and the time it blocks.
    pub(crate) fn view(&self, object: &StoredObject, mut data: EventData) -> EventView {
        data.uid = Some(object.uid.clone());
        if self.masked && hides(object.class, &data) {
            return EventView {
                id: Some(object.id),
                calendar_id: Some(object.calendar_id),
                etag: Some(object.etag.clone()),
                data: busy_form(data, object.id),
                ..EventView::default()
            };
        }
        EventView {
            id: Some(object.id),
            calendar_id: Some(object.calendar_id),
            uri: Some(object.uri.clone()),
            external_key: object.external_key.clone(),
            etag: Some(object.etag.clone()),
            schedule_tag: object.schedule_tag.clone(),
            dav_url: self.url(&object.uri),
            created_at: Some(object.created_at),
            updated_at: Some(object.updated_at),
            data,
        }
    }
}

/// Whether the caller is the owner of the calendar (the owner reads everything in it).
pub(crate) fn owns(ctx: &RequestContext, target: &ApiCalendar) -> bool {
    ctx.principal() == Some(target.facts.owner)
}

/// The time zone floating and all-day values of an API write are read in: the calendar's, else the tenant's.
pub(crate) fn default_zone(calendar: &davhaven_domain::Calendar, tenant: &Tenant, limits: &IcalLimits) -> TimeZoneName {
    calendar
        .timezone_ics
        .as_deref()
        .and_then(|ics| davhaven_ical::tz::calendar_timezone(ics, limits).ok())
        .unwrap_or(tenant.settings.timezone)
}

fn edit_scope(scope: ChangeScope) -> EditScope {
    match scope {
        ChangeScope::This => EditScope::This,
        ChangeScope::ThisAndFuture => EditScope::ThisAndFuture,
        ChangeScope::All => EditScope::All,
    }
}

/// The stored object an event selector names.
async fn select(
    tx: &mut dyn Tx,
    calendar: davhaven_domain::CalendarId,
    selector: &ObjectSelector,
) -> AppResult<Option<StoredObject>> {
    let result = match selector {
        ObjectSelector::Key(key) => tx.objects().get_by_external_key(calendar, key).await,
        ObjectSelector::Uri(uri) => tx.objects().get(calendar, uri).await,
        ObjectSelector::Uid(uid) => tx.objects().get_by_uid(calendar, uid).await,
        ObjectSelector::Id(id) => match tx.objects().get_by_id(*id).await {
            Ok(object) if object.calendar_id == calendar => Ok(object),
            Ok(_) => Err(StoreError::NotFound),
            Err(error) => Err(error),
        },
    };
    found(result)
}

/// Reads events as JSON on a blocking thread: the master or the selected instance.
fn render_blocking(
    items: Vec<(StoredObject, Option<EventTime>)>,
    calendar_zone: Option<&str>,
    limits: &IcalLimits,
) -> Result<Vec<(StoredObject, EventData)>, davhaven_ical::IcalError> {
    let zone = zone_of(calendar_zone, limits);
    let mut rendered = Vec::with_capacity(items.len());
    for (object, instance) in items {
        let calendar = davhaven_ical::parse::parse(object.data.as_bytes(), limits)?;
        let data = match &instance {
            None => davhaven_ical::merge::to_event_data(&calendar, None)?,
            Some(rid) => match davhaven_ical::merge::to_event_data(&calendar, Some(rid)) {
                Ok(data) => data,
                // An instance without an override of its own is made from the master.
                Err(_) => instance_of(&calendar, rid, zone, limits)?,
            },
        };
        rendered.push((object, data));
    }
    Ok(rendered)
}

/// The instance `rid` of a recurring event that has no override: the master with the times of the instance.
fn instance_of(
    calendar: &davhaven_ical::ParsedCalendar,
    rid: &EventTime,
    zone: TimeZoneName,
    limits: &IcalLimits,
) -> Result<EventData, davhaven_ical::IcalError> {
    let start = rid
        .to_utc(zone)
        .ok_or_else(|| davhaven_ical::IcalError::invalid("the recurrence id is not a valid time"))?;
    let range =
        davhaven_ical::filter::TimeRange::new(Some(start - Duration::seconds(1)), Some(start + Duration::seconds(1)));
    let instances = davhaven_ical::expand::expand_in_zone(calendar, &range, limits, zone)?;
    let found = instances
        .into_iter()
        .find(|instance| &instance.recurrence_id == rid || instance.start == start)
        .ok_or_else(|| davhaven_ical::IcalError::invalid("the recurrence id names no instance of the event"))?;
    let mut data = davhaven_ical::merge::to_event_data(calendar, None)?;
    let times = |at: DateTime<Utc>| {
        if found.all_day {
            EventTime::Date(at.date_naive())
        } else {
            EventTime::Utc(at)
        }
    };
    data.start = Some(times(found.start));
    if data.end.is_some() || data.duration.is_none() {
        data.end = Some(times(found.end));
        data.duration = None;
    }
    data.recurrence = None;
    data.recurrence_id = Some(found.recurrence_id);
    Ok(data)
}

/// What a JSON write does with an object that exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Merges into it: the management API's upsert by key, and every write by id, resource name or UID.
    Upsert,
    /// Leaves it alone when the write changes nothing and refuses the write when it would change it (`create_event`: a
    /// retry of a call is not a second call, and a reused key is not an update).
    CreateOnce,
}

/// What a write of the JSON interface knows once the event is merged and prepared.
struct Pending<'a> {
    ctx: &'a RequestContext,
    journal: &'a Journal<'a>,
    target: &'a ApiCalendar,
    linker: &'a Linker,
    existing: Option<&'a StoredObject>,
    scheduling: Option<Scheduling<'static>>,
    /// The instance the caller addressed; the view shows it.
    instance: Option<EventTime>,
}

impl Pending<'_> {
    /// The write scope of the calendar.
    fn scope(&self) -> WriteTarget<'_> {
        WriteTarget {
            tenant: &self.target.tenant,
            calendar: &self.target.calendar,
            home: self.linker.home(),
        }
    }
}

/// What a removal changed: the change to publish, its sequence number and the UID the audit record names.
struct Removal {
    change: ObjectChange,
    seq: u64,
    uid: Uid,
}

/// Whether and how a write to a calendar tells attendees: managed and mirrored calendars never schedule.
fn scheduling_for(kind: CalendarKind, notify_attendees: bool) -> Option<Scheduling<'static>> {
    let schedules = !matches!(kind, CalendarKind::Managed | CalendarKind::Mirror);
    (notify_attendees && schedules).then_some(Scheduling {
        reply: ScheduleReply::Send,
        if_schedule_tag_match: None,
        notify: true,
        comment: None,
        stale_excused: false,
    })
}

/// The change a store made as the domain event lists it: the identity of the object and the new `ETag`.
fn listed(
    kind: ObjectChangeKind,
    result: &WriteResult,
    (uri, uid, external_key): (&ObjectUri, &Uid, Option<ExternalKey>),
) -> ObjectChange {
    ObjectChange {
        kind,
        object: Some(result.object_id),
        uri: uri.clone(),
        uid: uid.clone(),
        external_key,
        etag: Some(result.etag.clone()),
    }
}

/// The stored object a write addresses. A key that does not exist yet creates the object; every other selector must
/// find one.
async fn current(
    tx: &mut dyn Tx,
    calendar: CalendarId,
    selector: Option<&ObjectSelector>,
) -> AppResult<Option<StoredObject>> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    match select(tx, calendar, selector).await? {
        Some(object) => Ok(Some(object)),
        None if matches!(selector, ObjectSelector::Key(_)) => Ok(None),
        None => Err(AppError::not_found()),
    }
}

/// The external key and the UID of the object a write stores. `fresh` makes the UID of an object nobody named.
fn identity(
    target: &ApiCalendar,
    write: &EventWrite,
    existing: Option<&StoredObject>,
    fresh: impl FnOnce() -> Uid,
) -> (Option<ExternalKey>, Uid) {
    let key = match &write.target {
        Some(ObjectSelector::Key(key)) => Some(key.clone()),
        _ => existing.and_then(|object| object.external_key.clone()),
    };
    let uid = match existing {
        Some(object) => object.uid.clone(),
        None => match (&write.target, &write.event.data.uid) {
            (_, Some(uid)) => uid.clone(),
            (Some(ObjectSelector::Key(key)), None) => Uid::deterministic(target.calendar.id, key),
            _ => fresh(),
        },
    };
    (key, uid)
}

impl ObjectServiceImpl {
    /// The links of the events of a calendar for the caller: through the caller's own binding of it (a principal who
    /// has none, or hid it, gets no links: a path in somebody else's home is not theirs to use) and, for a tenant
    /// token, which has no home, through the owner's binding.
    ///
    /// For a caller that reads through MCP and does not own the calendar the linker also masks: private events of
    /// others come out as the time they block (the `sight` module).
    pub(crate) async fn linker(
        &self,
        tx: &mut dyn Tx,
        ctx: &RequestContext,
        target: &ApiCalendar,
    ) -> AppResult<Linker> {
        let home = home_for(tx, ctx, target.calendar.id, target.calendar.owner_id).await?;
        Ok(Linker {
            urls: self.core.deps().urls.for_tenant(&target.tenant.settings),
            tenant: target.tenant.slug.clone(),
            home,
            masked: masks(ctx) && !owns(ctx, target),
        })
    }

    /// Renders stored objects as event views.
    pub(crate) async fn render(
        &self,
        linker: &Linker,
        calendar_zone: Option<&str>,
        items: Vec<(StoredObject, Option<EventTime>)>,
    ) -> AppResult<Vec<EventView>> {
        let zone = calendar_zone.map(str::to_owned);
        let rendered = blocking(&self.core, ErrorContext::Query, move |limits| {
            render_blocking(items, zone.as_deref(), limits)
        })
        .await?;
        Ok(rendered
            .into_iter()
            .map(|(object, data)| linker.view(&object, data))
            .collect())
    }

    /// Reads an event as JSON.
    pub(crate) async fn read_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        instance: Option<EventTime>,
    ) -> AppResult<EventView> {
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let target = api_calendar(tx.as_mut(), ctx, calendar, Operation::ReadObject, false).await?;
        let object = select(tx.as_mut(), target.calendar.id, selector)
            .await?
            .ok_or_else(AppError::not_found)?;
        let linker = self.linker(tx.as_mut(), ctx, &target).await?;
        tx.commit().await?;
        let views = self
            .render(
                &linker,
                target.calendar.timezone_ics.as_deref(),
                vec![(object, instance)],
            )
            .await
            .map_err(|error| {
                // An instance the event does not have is a missing resource, not invalid input.
                if error.kind() == davhaven_domain::ErrorKind::Invalid {
                    AppError::not_found()
                } else {
                    error
                }
            })?;
        views.into_iter().next().ok_or_else(AppError::not_found)
    }

    /// Creates or changes an event from JSON.
    pub(crate) async fn write_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        write: EventWrite,
    ) -> AppResult<EventWriteOutcome> {
        require_scope(ctx, Operation::CreateObject)?;
        retrying(false, || self.write_event_once(ctx, calendar, &write, Mode::Upsert)).await
    }

    /// Creates an event once: with a key, a repeated call finds the event of the first one and changes nothing, and a
    /// key of an event with other content is a conflict (see [`ObjectService::create_event`](crate::services::ObjectService::create_event)).
    pub(crate) async fn create_once(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        create: EventCreate,
    ) -> AppResult<EventWriteOutcome> {
        require_scope(ctx, Operation::CreateObject)?;
        let EventCreate {
            key,
            event,
            notify_attendees,
        } = create;
        let write = EventWrite {
            target: key.map(ObjectSelector::Key),
            event,
            notify_attendees,
            if_match: None,
            scope: ChangeScope::All,
        };
        retrying(false, || self.write_event_once(ctx, calendar, &write, Mode::CreateOnce)).await
    }

    /// One attempt of a JSON write, in three steps so that the calendar stays locked for as short a time as possible
    /// (PLAN 2.15, `ENGINEERING_RULES` R14): what the write is based on is read without the lock; the merge, the
    /// validation and the serialization, which are CPU work, run on blocking threads outside any transaction; the
    /// write then locks the calendar, checks that the object is the one the merge was based on (otherwise the
    /// attempt starts over) and stores.
    async fn write_event_once(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        write: &EventWrite,
        mode: Mode,
    ) -> AppResult<EventWriteOutcome> {
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        // 1. Read: the calendar, the decision, the object the write names and the links of the answer.
        let (target, existing, linker) = {
            let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadOnly).await?;
            let target = api_calendar_raw(tx.as_mut(), ctx, calendar, false).await?;
            // Decided before the object is looked up: a caller who may not write here learns nothing about what is
            // here (PLAN 2.6), whether the selector names an object or not.
            enforce_api(ctx, &target.facts, Operation::CreateObject)?;
            let existing = current(tx.as_mut(), target.calendar.id, write.target.as_ref()).await?;
            let linker = self.linker(tx.as_mut(), ctx, &target).await?;
            tx.commit().await?;
            (target, existing, linker)
        };
        // A creation never changes an object that exists: it returns it or refuses (`Mode::CreateOnce`).
        let operation = if existing.is_some() && mode == Mode::Upsert {
            Operation::UpdateObject
        } else {
            Operation::CreateObject
        };
        enforce_api(ctx, &target.facts, operation)?;
        let zone = default_zone(&target.calendar, &target.tenant, &deps.limits.ical);
        if mode == Mode::Upsert {
            // Said after the decision, so a caller who may not write here is told that first.
            self.refuse_what_is_hidden(&linker, existing.as_ref(), write, zone)
                .await?;
        }
        // Which instances a change reaches is named by the instance: without it `this` and `this_and_future` would
        // silently edit the master and with it the whole series. Said after the decision: whoever may not write
        // here is told so first.
        if write.scope != ChangeScope::All && write.event.data.recurrence_id.is_none() {
            return Err(field_error(
                "/recurrence_id",
                "required",
                "Changing this instance or the following ones needs the recurrence id of the instance.",
            ));
        }
        if let Some(expected) = &write.if_match
            && existing.as_ref().is_none_or(|object| &object.etag != expected)
        {
            return Err(AppError::precondition_failed());
        }
        // 2. Merge and validate outside any transaction.
        let (key, uid) = identity(&target, write, existing.as_ref(), || Uid::from_uuid(deps.ids.new_id()));
        // Only an edit of "this and following" starts a second series.
        let continuation_uid = if write.scope == ChangeScope::ThisAndFuture {
            Uid::from_uuid(deps.ids.new_id())
        } else {
            uid.clone()
        };
        let merged = self
            .merge(
                existing.as_ref(),
                &write.event.data,
                write.scope,
                (&uid, &continuation_uid),
                zone,
            )
            .await?;
        let (primary, primary_text) = prepare_calendar(&self.core, merged.primary).await?;
        let instance = write.event.data.recurrence_id.clone();
        if merged.earlier.is_none()
            && let Some(object) = &existing
            && object.content_hash == primary.hash
        {
            // Nothing the server stores differs from what is stored: no write, no new `ETag`, no lock.
            let event = self.view_one(&linker, &target, object.clone(), instance).await?;
            return Ok(EventWriteOutcome {
                event,
                created: false,
                schedule: ScheduleOutcome::none(),
            });
        }
        if mode == Mode::CreateOnce && existing.is_some() {
            // The key names an event, and this call would change it: not a retry, a reuse of the key.
            return Err(AppError::conflict().with_public_message(SafeMessage::from_static(
                "The key already names an event with other content. Use a new key, or change that event with an update.",
            )));
        }
        let earlier = match merged.earlier {
            Some(earlier) => Some(prepare_calendar(&self.core, earlier).await?),
            None => None,
        };
        // 3. Write under the lock.
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let locked = api_calendar_raw(tx.as_mut(), ctx, calendar, true).await?;
        let again = current(tx.as_mut(), locked.calendar.id, write.target.as_ref()).await?;
        let unchanged = again.as_ref().map(|object| (object.id, &object.etag))
            == existing.as_ref().map(|object| (object.id, &object.etag));
        if !unchanged {
            // Another request changed the object between the read and the lock: the merge starts over from it.
            return Err(AppError::from(StoreError::SerializationFailure));
        }
        enforce_api(ctx, &locked.facts, operation)?;
        let pending = Pending {
            ctx,
            journal: &journal,
            target: &locked,
            linker: &linker,
            existing: existing.as_ref(),
            scheduling: scheduling_for(locked.calendar.kind, write.notify_attendees),
            instance,
        };
        // A series that was cut keeps its earlier part under its own UID.
        if let (Some(earlier), Some(object)) = (earlier, existing.as_ref()) {
            let continuation = (&primary, primary_text, continuation_uid);
            return self.write_split(tx, &pending, object, earlier, continuation).await;
        }
        let uri = existing
            .as_ref()
            .map_or_else(|| ObjectUri::for_uid(&uid), |object| object.uri.clone());
        self.write_single(tx, &pending, (&primary, primary_text), (uri, uid, key))
            .await
    }

    /// Stores the two parts of a series that was cut at "this and following": the shortened original and the
    /// continuation under its own UID.
    async fn write_split(
        &self,
        mut tx: Box<dyn Tx>,
        pending: &Pending<'_>,
        object: &StoredObject,
        (earlier, earlier_text): (Prepared, String),
        (primary, primary_text, continuation_uid): (&Prepared, String, Uid),
    ) -> AppResult<EventWriteOutcome> {
        let stored = self
            .store(
                tx.as_mut(),
                pending.ctx,
                pending.scope(),
                StoreRequest {
                    uri: &object.uri,
                    existing: Some(object),
                    prepared: &earlier,
                    data: earlier_text,
                    external_key: None,
                    scheduling: pending.scheduling,
                },
            )
            .await?;
        let continuation_uri = ObjectUri::for_uid(&continuation_uid);
        let continued = self
            .store(
                tx.as_mut(),
                pending.ctx,
                pending.scope(),
                StoreRequest {
                    uri: &continuation_uri,
                    existing: None,
                    prepared: primary,
                    data: primary_text,
                    external_key: None,
                    scheduling: pending.scheduling,
                },
            )
            .await?;
        let changes = [
            listed(
                ObjectChangeKind::Updated,
                &stored.result,
                (&object.uri, &object.uid, object.external_key.clone()),
            ),
            listed(
                ObjectChangeKind::Created,
                &continued.result,
                (&continuation_uri, &continuation_uid, None),
            ),
        ];
        self.finish_write(
            pending,
            tx.as_mut(),
            &changes,
            continued.result.seq,
            "update_event",
            primary,
        )
        .await?;
        let stored_object = tx.objects().get(pending.target.calendar.id, &continuation_uri).await?;
        tx.commit().await?;
        let event = self
            .view_one(pending.linker, pending.target, stored_object, None)
            .await?;
        Ok(EventWriteOutcome {
            event,
            created: true,
            schedule: continued.schedule,
        })
    }

    /// Stores one object: a new one or the changed existing one.
    async fn write_single(
        &self,
        mut tx: Box<dyn Tx>,
        pending: &Pending<'_>,
        (prepared, text): (&Prepared, String),
        (uri, uid, key): (ObjectUri, Uid, Option<ExternalKey>),
    ) -> AppResult<EventWriteOutcome> {
        let stored = self
            .store(
                tx.as_mut(),
                pending.ctx,
                pending.scope(),
                StoreRequest {
                    uri: &uri,
                    existing: pending.existing,
                    prepared,
                    data: text,
                    external_key: key.clone(),
                    scheduling: pending.scheduling,
                },
            )
            .await?;
        let (kind, tool) = if stored.result.created {
            (ObjectChangeKind::Created, "create_event")
        } else {
            (ObjectChangeKind::Updated, "update_event")
        };
        let changes = [listed(kind, &stored.result, (&uri, &uid, key))];
        self.finish_write(pending, tx.as_mut(), &changes, stored.result.seq, tool, prepared)
            .await?;
        let stored_object = tx.objects().get(pending.target.calendar.id, &uri).await?;
        tx.commit().await?;
        let event = self
            .view_one(pending.linker, pending.target, stored_object, pending.instance.clone())
            .await?;
        Ok(EventWriteOutcome {
            event,
            created: stored.result.created,
            schedule: stored.schedule,
        })
    }

    /// Writes the domain event and, for MCP, the audit record of a write.
    async fn finish_write(
        &self,
        pending: &Pending<'_>,
        tx: &mut dyn Tx,
        changes: &[ObjectChange],
        seq: u64,
        tool: &str,
        prepared: &Prepared,
    ) -> AppResult<()> {
        publish_changes(pending.journal, tx, &pending.target.calendar, seq, changes.to_vec()).await?;
        if pending.ctx.channel == Channel::Mcp {
            pending
                .journal
                .audit(
                    tx,
                    AuditEvent::McpWrite(McpWriteAudit {
                        tool: tool.to_owned(),
                        calendar: Some(pending.target.calendar.id),
                        object: changes.first().and_then(|change| change.object),
                        uid: Some(prepared.index.uid.clone()),
                    }),
                )
                .await?;
        }
        Ok(())
    }

    /// What the caller sees as busy time only (the `sight` module) it cannot change either: an update with `class:
    /// public` or `class: null` would otherwise be a way to read it, and one with `summary: null` a way to delete text
    /// it cannot read. That holds for an object whose class is restricted and, inside a series that is public, for an
    /// override that says `CLASS:PRIVATE` (the class of the instance decides): a write that names an instance and
    /// reaches such an override is refused.
    async fn refuse_what_is_hidden(
        &self,
        linker: &Linker,
        existing: Option<&StoredObject>,
        write: &EventWrite,
        zone: TimeZoneName,
    ) -> AppResult<()> {
        let Some(object) = existing else {
            return Ok(());
        };
        if linker.hides_class(object.class) {
            return Err(AppError::forbidden().with_public_message(SafeMessage::from_static(
                "This event is private to somebody else; it can only be seen as busy time and cannot be changed here.",
            )));
        }
        if linker.masked
            && let Some(instance) = write.event.data.recurrence_id.as_ref()
            && self
                .reaches_restricted_override(object, instance, write.scope, zone)
                .await?
        {
            return Err(AppError::forbidden().with_public_message(SafeMessage::from_static(
                "An instance of this event is private to somebody else; it can only be seen as busy time and cannot be changed here.",
            )));
        }
        Ok(())
    }

    /// Whether a write that names `instance` reaches an override of the object that is busy time to the caller: with
    /// `scope` `this` the override of that instance, with `this_and_future` that one and every later one (the series
    /// is cut there and the overrides after the cut move into the new series). `all` edits the master, which the
    /// class of the object decides.
    async fn reaches_restricted_override(
        &self,
        object: &StoredObject,
        instance: &EventTime,
        scope: ChangeScope,
        zone: TimeZoneName,
    ) -> AppResult<bool> {
        if scope == ChangeScope::All {
            return Ok(false);
        }
        let (text, class, instance) = (object.data.clone(), object.class, instance.clone());
        blocking(&self.core, ErrorContext::Store, move |limits| {
            let calendar = davhaven_ical::parse::parse(text.as_bytes(), limits)?;
            let from = instance.to_utc(zone);
            for id in davhaven_ical::merge::override_ids(&calendar)? {
                let reached = match (scope, id.to_utc(zone), from) {
                    (ChangeScope::This, Some(at), Some(from)) => at == from,
                    (ChangeScope::ThisAndFuture, Some(at), Some(from)) => at >= from,
                    // A time that does not exist in its zone is compared as it was written.
                    (ChangeScope::This | ChangeScope::ThisAndFuture, _, _) => id == instance,
                    (ChangeScope::All, _, _) => false,
                };
                if reached && hides(class, &davhaven_ical::merge::to_event_data(&calendar, Some(&id))?) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .await
    }

    async fn view_one(
        &self,
        linker: &Linker,
        target: &ApiCalendar,
        object: StoredObject,
        instance: Option<EventTime>,
    ) -> AppResult<EventView> {
        self.render(
            linker,
            target.calendar.timezone_ics.as_deref(),
            vec![(object, instance)],
        )
        .await?
        .into_iter()
        .next()
        .ok_or_else(AppError::not_found)
    }

    /// Merges the event into the stored object (or creates the calendar of a new one) on a blocking thread.
    pub(crate) async fn merge(
        &self,
        existing: Option<&StoredObject>,
        event: &EventData,
        scope: ChangeScope,
        uids: (&Uid, &Uid),
        zone: TimeZoneName,
    ) -> AppResult<Merged> {
        let text = existing.map(|object| object.data.clone());
        let event = event.clone();
        let scope = edit_scope(scope);
        let (uid, continuation_uid) = (uids.0.clone(), uids.1.clone());
        let now = self.core.deps().clock.now();
        blocking(&self.core, ErrorContext::Store, move |limits| {
            let stored = text
                .as_deref()
                .map(|text| davhaven_ical::parse::parse(text.as_bytes(), limits))
                .transpose()?;
            let context = MergeContext {
                uid: &uid,
                now,
                default_zone: zone,
                scope,
                limits,
                default_alarm_text: DEFAULT_ALARM_TEXT,
            };
            match (&stored, scope, &event.recurrence_id) {
                (Some(stored), EditScope::ThisAndFuture, Some(_)) => {
                    let split = davhaven_ical::merge::merge_event_split(stored, &event, &context, &continuation_uid)?;
                    Ok(Merged {
                        primary: split.continuation,
                        earlier: split.earlier,
                    })
                }
                _ => Ok(Merged {
                    primary: davhaven_ical::merge::merge_event(stored.as_ref(), &event, &context)?,
                    earlier: None,
                }),
            }
        })
        .await
    }

    /// Deletes an event or instances of it.
    pub(crate) async fn remove_event(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<()> {
        self.remove(ctx, calendar, selector, options, false).await.map(|_| ())
    }

    /// Deletes an event or instances of it and says whether there was something to delete: the deletion of a whole
    /// event without `if_match` that finds no event, after the caller was allowed to delete here, is `false`.
    pub(crate) async fn remove_event_if_present(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
    ) -> AppResult<bool> {
        self.remove(ctx, calendar, selector, options, true).await
    }

    async fn remove(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: DeleteEventOptions,
        missing_ok: bool,
    ) -> AppResult<bool> {
        require_scope(ctx, Operation::DeleteObject)?;
        retrying(false, || {
            self.remove_event_once(ctx, calendar, selector, &options, missing_ok)
        })
        .await
    }

    /// One attempt of a removal. An instance removal reads the object without the lock and cuts the calendar object
    /// outside any transaction (CPU work), then locks, checks that the object is the one it cut and stores; a removal
    /// of the whole event needs no such step.
    ///
    /// With `missing_ok` the removal of a whole event without `if_match` that finds no event is `Ok(false)`. The
    /// calendar was resolved and the deletion decided before that (`api_calendar`), so a caller who may not delete here
    /// never learns whether the event is there; an instance of a missing event and a stale entity tag of one stay
    /// `NotFound`.
    async fn remove_event_once(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        selector: &ObjectSelector,
        options: &DeleteEventOptions,
        missing_ok: bool,
    ) -> AppResult<bool> {
        let journal = Journal::new(&self.core, ctx);
        // 1. For an instance removal: what it is based on, read without the lock, and the cut object, prepared.
        let planned = if options.scope == ChangeScope::All {
            None
        } else {
            let object = {
                let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
                // Decided first: a caller who may not delete here learns nothing about what is here.
                let target = api_calendar(tx.as_mut(), ctx, calendar, Operation::DeleteObject, false).await?;
                // `this` and `this_and_future` name an instance. Without it the removal would fall through to the
                // whole series: the one thing the caller said they did not want.
                if options.recurrence_id.is_none() {
                    return Err(field_error(
                        "/recurrence_id",
                        "required",
                        "Deleting this instance or the following ones needs the recurrence id of the instance.",
                    ));
                }
                let object = select(tx.as_mut(), target.calendar.id, selector)
                    .await?
                    .ok_or_else(AppError::not_found)?;
                if options
                    .if_match
                    .as_ref()
                    .is_some_and(|expected| expected != &object.etag)
                {
                    return Err(AppError::precondition_failed());
                }
                tx.commit().await?;
                object
            };
            let cut = match self.reduce_instances(&object, options).await? {
                Some(reduced) => Some(prepare_calendar(&self.core, reduced).await?),
                None => None,
            };
            Some((object, cut))
        };
        // 2. Write under the lock.
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let target = api_calendar(tx.as_mut(), ctx, calendar, Operation::DeleteObject, true).await?;
        let Some(object) = select(tx.as_mut(), target.calendar.id, selector).await? else {
            let whole = options.scope == ChangeScope::All && options.if_match.is_none();
            if missing_ok && whole {
                tx.commit().await?;
                return Ok(false);
            }
            return Err(AppError::not_found());
        };
        if options
            .if_match
            .as_ref()
            .is_some_and(|expected| expected != &object.etag)
        {
            return Err(AppError::precondition_failed());
        }
        if planned
            .as_ref()
            .is_some_and(|(seen, _)| seen.id != object.id || seen.etag != object.etag)
        {
            // Another request changed the object between the read and the lock: the cut starts over from it.
            return Err(AppError::from(StoreError::SerializationFailure));
        }
        let scheduling = scheduling_for(target.calendar.kind, options.notify_attendees);
        let removal = if let Some((_, Some(cut))) = planned {
            // Instances were removed: the object stays, changed.
            enforce_api(ctx, &target.facts, Operation::UpdateObject)?;
            self.store_reduced(tx.as_mut(), ctx, &target, &object, cut, scheduling)
                .await?
        } else {
            self.delete_whole(tx.as_mut(), ctx, &target, &object, scheduling.is_some())
                .await?
        };
        publish_changes(
            &journal,
            tx.as_mut(),
            &target.calendar,
            removal.seq,
            vec![removal.change],
        )
        .await?;
        if ctx.channel == Channel::Mcp {
            journal
                .audit(
                    tx.as_mut(),
                    AuditEvent::McpWrite(McpWriteAudit {
                        tool: "delete_event".to_owned(),
                        calendar: Some(target.calendar.id),
                        object: Some(object.id),
                        uid: Some(removal.uid),
                    }),
                )
                .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    /// The event without the instances the options name, when they name some.
    async fn reduce_instances(
        &self,
        object: &StoredObject,
        options: &DeleteEventOptions,
    ) -> AppResult<Option<davhaven_ical::ParsedCalendar>> {
        let Some(rid) = options
            .recurrence_id
            .clone()
            .filter(|_| options.scope != ChangeScope::All)
        else {
            return Ok(None);
        };
        let text = object.data.clone();
        let scope = edit_scope(options.scope);
        blocking(&self.core, ErrorContext::Store, move |limits| {
            let calendar = davhaven_ical::parse::parse(text.as_bytes(), limits)?;
            davhaven_ical::merge::remove_instances_with_limits(&calendar, &rid, scope, limits)
        })
        .await
    }

    /// Stores the event after the removal of some of its instances.
    async fn store_reduced(
        &self,
        tx: &mut dyn Tx,
        ctx: &RequestContext,
        target: &ApiCalendar,
        object: &StoredObject,
        (prepared, text): (Prepared, String),
        scheduling: Option<Scheduling<'static>>,
    ) -> AppResult<Removal> {
        let linker = self.linker(tx, ctx, target).await?;
        let scope = WriteTarget {
            tenant: &target.tenant,
            calendar: &target.calendar,
            home: linker.home(),
        };
        let stored = self
            .store(
                tx,
                ctx,
                scope,
                StoreRequest {
                    uri: &object.uri,
                    existing: Some(object),
                    prepared: &prepared,
                    data: text,
                    external_key: None,
                    scheduling,
                },
            )
            .await?;
        Ok(Removal {
            seq: stored.result.seq,
            uid: prepared.index.uid.clone(),
            change: listed(
                ObjectChangeKind::Updated,
                &stored.result,
                (&object.uri, &object.uid, object.external_key.clone()),
            ),
        })
    }

    /// Deletes the object, after the scheduler had its say when the attendees are to be told.
    async fn delete_whole(
        &self,
        tx: &mut dyn Tx,
        ctx: &RequestContext,
        target: &ApiCalendar,
        object: &StoredObject,
        notify_attendees: bool,
    ) -> AppResult<Removal> {
        if notify_attendees {
            self.scheduler
                .before_delete(
                    tx,
                    &DeleteFacts {
                        ctx,
                        tenant: &target.tenant,
                        calendar: &target.calendar,
                        existing: object,
                        reply: ScheduleReply::Send,
                        notify_attendees: true,
                    },
                )
                .await?;
        }
        let seq = match tx
            .objects()
            .delete(target.calendar.id, &object.uri, Expected::Etag(object.etag.clone()))
            .await
        {
            Ok(seq) => seq,
            Err(StoreError::PreconditionFailed) => return Err(AppError::precondition_failed()),
            Err(error) => return Err(error.into()),
        };
        tx.rsvp().revoke_for_object(object.id).await?;
        Ok(Removal {
            seq,
            uid: object.uid.clone(),
            change: change(ObjectChangeKind::Deleted, object),
        })
    }

    /// Lists the events of one calendar as JSON, ordered by id.
    pub(crate) async fn list_events(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        filter: ObjectFilter,
        page: PageRequest,
    ) -> AppResult<Page<EventView>> {
        let limits = self.core.deps().limits.ical.clone();
        if let Some(query) = &filter.calendar_filter {
            davhaven_ical::filter::validate_filter(query, &limits)
                .map_err(|error| AppError::from_ical(error, ErrorContext::Query))?;
        }
        if let Some(range) = &filter.range {
            range
                .validate(&limits)
                .map_err(|error| AppError::from_ical(error, ErrorContext::Query))?;
        }
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let target = api_calendar(tx.as_mut(), ctx, calendar, Operation::ListObjects, false).await?;
        let listing = format!("events/{}", target.calendar.id);
        let request: PageReq = paging::page_request(&self.core, ctx, &listing, &page)?;
        let limit = usize::try_from(request.effective_limit()).unwrap_or(usize::MAX);
        let index = index_filter_of(&filter);
        let data = CalendarDataSpec::metadata_only();
        let scan_cap = usize::try_from(self.core.deps().limits.api.max_scanned_objects).unwrap_or(usize::MAX);
        let mut items: Vec<StoredObject> = Vec::new();
        let mut after = request.after;
        let mut scanned = 0_usize;
        let mut next_after: Option<uuid::Uuid> = None;
        loop {
            let batch = tx
                .objects()
                .query(
                    target.calendar.id,
                    &index,
                    PageReq {
                        limit: request.limit,
                        after,
                    },
                )
                .await?;
            scanned += batch.items.len();
            let matched = self
                .evaluate(target.calendar.timezone_ics.as_deref(), batch.items, &filter, &data)
                .await?;
            let room = limit - items.len();
            let cut = matched.len() > room;
            items.extend(matched.into_iter().take(room).map(|(object, _)| object));
            if cut {
                next_after = items.last().map(|object| object.id.as_uuid());
                break;
            }
            match batch.next {
                None => break,
                Some(cursor) => {
                    if items.len() >= limit || scanned >= scan_cap {
                        next_after = Some(cursor);
                        break;
                    }
                    after = Some(cursor);
                }
            }
        }
        let linker = self.linker(tx.as_mut(), ctx, &target).await?;
        tx.commit().await?;
        let next = paging::next_cursor(&self.core, ctx, &listing, next_after)?;
        let views = self
            .render(
                &linker,
                target.calendar.timezone_ics.as_deref(),
                items.into_iter().map(|object| (object, None)).collect(),
            )
            .await?;
        Ok(Page::new(views, next))
    }
}

/// The result of a merge: the object to store and, for an edit of "this and following", the shortened original.
pub(crate) struct Merged {
    pub(crate) primary: davhaven_ical::ParsedCalendar,
    pub(crate) earlier: Option<davhaven_ical::ParsedCalendar>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_scopes_map_one_to_one() {
        assert_eq!(edit_scope(ChangeScope::This), EditScope::This);
        assert_eq!(edit_scope(ChangeScope::ThisAndFuture), EditScope::ThisAndFuture);
        assert_eq!(edit_scope(ChangeScope::All), EditScope::All);
    }
}
