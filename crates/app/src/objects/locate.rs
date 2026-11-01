//! Locating the collection of a request, its views and the domain event of object changes.

use davhaven_domain::events::{MAX_LISTED_CHANGES, ObjectChange, ObjectChangeKind, ObjectsChangedPayload};
use davhaven_domain::{
    Access, AccessFacts, Binding, Calendar, CalendarId, CalendarSlug, EventPayload, EventType, ObjectUri, Operation,
    PrincipalId, PrincipalName, RequestContext, ResourceKind, ResourcePath, StoredObject, SyncToken, Tenant,
    TenantSlug, effective_access, privileges,
};
use davhaven_ports::Tx;

use crate::audit::Journal;
use crate::authz::{Home, calendar_of, enforce_api, facts_for, resolve_home};
use crate::error::{AppError, AppResult};
use crate::services::{CalendarRef, ObjectView};

/// The collection a DAV path names, with everything a write needs to know about it.
#[derive(Debug)]
pub(crate) struct Located {
    pub(crate) home: Home,
    pub(crate) binding: Binding,
    pub(crate) calendar: Calendar,
    pub(crate) facts: AccessFacts,
}

/// The parts of a DAV object path.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Target<'a> {
    pub(crate) tenant: &'a TenantSlug,
    pub(crate) principal: &'a PrincipalName,
    pub(crate) binding: &'a CalendarSlug,
}

impl Target<'_> {
    /// The target of a collection or object path; `None` for every other resource.
    pub(crate) fn of(path: &ResourcePath) -> Option<(Target<'_>, Option<&ObjectUri>)> {
        match path {
            ResourcePath::Collection {
                tenant,
                principal,
                binding,
            } => Some((
                Target {
                    tenant,
                    principal,
                    binding,
                },
                None,
            )),
            ResourcePath::Object {
                tenant,
                principal,
                binding,
                object,
            } => Some((
                Target {
                    tenant,
                    principal,
                    binding,
                },
                Some(object),
            )),
            _ => None,
        }
    }
}

/// Resolves the collection of a path inside the transaction: the home (tenant and principal of the path, usable by
/// the caller), the binding, the calendar (locked for writers) and the authorization facts of the caller.
///
/// # Errors
///
/// `NotFound` for unknown, invisible and foreign collections.
pub(crate) async fn locate(
    tx: &mut dyn Tx,
    ctx: &RequestContext,
    target: Target<'_>,
    lock: bool,
) -> AppResult<Located> {
    let home = resolve_home(tx, ctx, target.tenant, target.principal).await?;
    let binding = tx.bindings().get_by_slug(home.principal.id, target.binding).await?;
    let calendar = if lock {
        tx.calendars()
            .lock(&[binding.calendar_id])
            .await?
            .into_iter()
            .next()
            .ok_or_else(AppError::not_found)?
    } else {
        tx.calendars().get(binding.calendar_id).await?
    };
    let facts = facts_for(tx, ctx, calendar.id).await?;
    Ok(Located {
        home,
        binding,
        calendar,
        facts,
    })
}

impl Located {
    /// The path of a member of the collection in the caller's home.
    pub(crate) fn object_path(&self, uri: &ObjectUri) -> ResourcePath {
        ResourcePath::Object {
            tenant: self.home.tenant.slug.clone(),
            principal: self.home.principal.name.clone(),
            binding: self.binding.slug.clone(),
            object: uri.clone(),
        }
    }

    /// The collection in the caller's home.
    pub(crate) fn collection_path(&self) -> ResourcePath {
        ResourcePath::Collection {
            tenant: self.home.tenant.slug.clone(),
            principal: self.home.principal.name.clone(),
            binding: self.binding.slug.clone(),
        }
    }

    /// The view of a stored object for the viewer of the home.
    pub(crate) fn view(&self, object: &StoredObject, data: Option<String>) -> ObjectView {
        let access = effective_access(self.home.principal.id, &self.facts).unwrap_or(Access::Read);
        ObjectView {
            path: self.object_path(&object.uri),
            id: object.id,
            calendar_id: object.calendar_id,
            uid: object.uid.clone(),
            component: object.component,
            etag: object.etag.clone(),
            schedule_tag: object.schedule_tag.clone(),
            size: object.size,
            last_modified: object.updated_at,
            data,
            privileges: privileges(access, self.calendar.kind, ResourceKind::Object),
        }
    }
}

/// One change of an object, for the domain event.
pub(crate) fn change(kind: ObjectChangeKind, object: &StoredObject) -> ObjectChange {
    ObjectChange {
        kind,
        object: (kind != ObjectChangeKind::Deleted).then_some(object.id),
        uri: object.uri.clone(),
        uid: object.uid.clone(),
        external_key: object.external_key.clone(),
        etag: (kind != ObjectChangeKind::Deleted).then(|| object.etag.clone()),
    }
}

/// Writes `calendar.objects_changed` for the changes of one transaction in one calendar into the outbox. `seq` is the
/// sequence number of the last change; the token in the event is the state after it.
///
/// # Errors
///
/// Store failures.
pub(crate) async fn publish_changes(
    journal: &Journal<'_>,
    tx: &mut dyn Tx,
    calendar: &Calendar,
    seq: u64,
    mut changes: Vec<ObjectChange>,
) -> AppResult<()> {
    if changes.is_empty() {
        return Ok(());
    }
    let truncated = changes.len() > MAX_LISTED_CHANGES;
    changes.truncate(MAX_LISTED_CHANGES);
    journal
        .publish(
            tx,
            EventType::CalendarObjectsChanged,
            EventPayload::ObjectsChanged(ObjectsChangedPayload {
                calendar: calendar.id,
                sync_token: SyncToken::new(calendar.id.as_uuid(), calendar.sync_epoch, seq),
                changes,
                truncated,
            }),
        )
        .await
}

/// A calendar addressed through the management API or MCP (by id or natural key), with the facts of the caller.
#[derive(Debug)]
pub(crate) struct ApiCalendar {
    pub(crate) tenant: Tenant,
    pub(crate) calendar: Calendar,
    pub(crate) facts: AccessFacts,
}

/// Resolves a calendar reference of the management API inside the transaction without deciding anything: the
/// tenant, the calendar (locked for writers with `lock`) and the facts of the caller. The caller checks the scope
/// first (`require_scope`) and decides the operation (`enforce`).
///
/// # Errors
///
/// `NotFound` for unknown calendars.
pub(crate) async fn api_calendar_raw(
    tx: &mut dyn Tx,
    ctx: &RequestContext,
    reference: &CalendarRef,
    lock: bool,
) -> AppResult<ApiCalendar> {
    let tenant = tx.tenant().get().await?;
    let found = calendar_of(tx, reference).await?;
    let calendar = if lock {
        tx.calendars()
            .lock(&[found.id])
            .await?
            .into_iter()
            .next()
            .ok_or_else(AppError::not_found)?
    } else {
        found
    };
    let facts = facts_for(tx, ctx, calendar.id).await?;
    Ok(ApiCalendar {
        tenant,
        calendar,
        facts,
    })
}

/// Resolves a calendar reference of the management API inside the transaction and decides `operation` for the
/// caller. The scope is checked before anything is looked up.
///
/// # Errors
///
/// `NotFound` for unknown and invisible calendars, `Forbidden` for a missing scope or privilege.
pub(crate) async fn api_calendar(
    tx: &mut dyn Tx,
    ctx: &RequestContext,
    reference: &CalendarRef,
    operation: Operation,
    lock: bool,
) -> AppResult<ApiCalendar> {
    crate::authz::require_scope(ctx, operation)?;
    let target = api_calendar_raw(tx, ctx, reference, lock).await?;
    enforce_api(ctx, &target.facts, operation)?;
    Ok(target)
}

/// Where the caller addresses `calendar` in a home, if anywhere: the principal and the slug of the binding the
/// caller's own home has for it (a hidden binding is no address). A caller without a home of their own, a tenant
/// token, addresses the calendar through its owner's binding. Nobody is pointed at a home they cannot open.
///
/// # Errors
///
/// Store failures.
pub(crate) async fn home_for(
    tx: &mut dyn Tx,
    ctx: &RequestContext,
    calendar: CalendarId,
    owner: PrincipalId,
) -> AppResult<Option<(PrincipalName, CalendarSlug)>> {
    let holder = ctx.principal().unwrap_or(owner);
    match tx.bindings().find_for_calendar(holder, calendar).await? {
        Some(binding) if !binding.hidden => {
            let principal = tx.principals().get(holder).await?;
            Ok(Some((principal.name, binding.slug)))
        }
        _ => Ok(None),
    }
}

/// What a write needs to know about the calendar it writes to: the tenant, the calendar and, when the caller has
/// the collection in a home, where (the principal and the binding slug name the hrefs of conflicting resources).
#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteTarget<'a> {
    pub(crate) tenant: &'a Tenant,
    pub(crate) calendar: &'a Calendar,
    pub(crate) home: Option<(&'a PrincipalName, &'a CalendarSlug)>,
}

impl Located {
    /// The write target of the collection.
    pub(crate) fn scope(&self) -> WriteTarget<'_> {
        WriteTarget {
            tenant: &self.home.tenant,
            calendar: &self.calendar,
            home: Some((&self.home.principal.name, &self.binding.slug)),
        }
    }
}

/// The heads (everything but the text) of the objects of a calendar that match the index `filter`, one page. A
/// store without head queries answers with the full objects reduced to heads.
///
/// # Errors
///
/// `NotFound` when the calendar does not exist, store failures.
pub(crate) async fn query_heads(
    tx: &mut dyn Tx,
    calendar: CalendarId,
    filter: &davhaven_ports::IndexFilter,
    page: davhaven_ports::PageReq,
) -> AppResult<davhaven_ports::StorePage<davhaven_ports::ObjectHead>> {
    match tx.objects().query_index(calendar, filter, page).await {
        Ok(batch) => Ok(batch),
        Err(davhaven_ports::StoreError::Unsupported) => Ok(tx
            .objects()
            .query(calendar, filter, page)
            .await?
            .map(|object| davhaven_ports::ObjectHead::from(&object))),
        Err(error) => Err(error.into()),
    }
}

/// The heads of the objects of a calendar in id order, one page (see [`query_heads`]).
///
/// # Errors
///
/// `NotFound` when the calendar does not exist, store failures.
pub(crate) async fn list_heads(
    tx: &mut dyn Tx,
    calendar: CalendarId,
    page: davhaven_ports::PageReq,
) -> AppResult<davhaven_ports::StorePage<davhaven_ports::ObjectHead>> {
    match tx.objects().list_index(calendar, page).await {
        Ok(batch) => Ok(batch),
        Err(davhaven_ports::StoreError::Unsupported) => Ok(tx
            .objects()
            .list(calendar, page)
            .await?
            .map(|object| davhaven_ports::ObjectHead::from(&object))),
        Err(error) => Err(error.into()),
    }
}
