//! Calendar collection use cases: homes, bindings, MKCALENDAR, properties and deletion.
//!
//! A calendar is visible to a principal through a **binding** in the principal's home (PLAN 2.9): the owner's
//! bindings are created with the calendar, share bindings when an invitation is accepted, and the bindings of
//! group calendars, managed calendars and API grants lazily on the first home listing. Bindings carry the
//! principal's own display name, color, order and transparency and their dead properties; everything else belongs
//! to the calendar.
//!
//! | Submodule | Responsibility |
//! | --- | --- |
//! | `dav` | the home listing and its lazy bindings, collections, MKCALENDAR, deletion of bound collections |
//! | `props` | PROPPATCH: per-binding and shared properties, atomically |
//! | `manage` | the management API: read, list, create-or-replace, patch, delete, tenant-wide search |
//! | `bindings` | the management API's view of a home: the bindings of a principal, hidden ones included, and their restoration |
//! | `views` | the views of bindings and calendars |
//!
//! Permissions come from `domain::authz::decide` over facts loaded in one store call per calendar. Collections the
//! caller cannot see answer `NotFound`; visible but not permitted answers `Forbidden` with the missing privilege.

mod bindings;
mod dav;
mod manage;
mod props;
mod views;

use async_trait::async_trait;
use davhaven_domain::{
    Binding, BindingId, Calendar, CalendarId, CalendarKind, CalendarSlug, ComponentKind, Principal, PrincipalName,
    RequestContext, ResourcePath, Transparency,
};
use davhaven_ports::Tx;
use davhaven_wire::{CalendarView, HomeBindingView, Page};

pub(crate) use views::{Views, free_binding_slug};

use crate::error::AppResult;
use crate::services::{
    BindingFilter, BindingView, CalendarRef, CalendarSearch, CalendarService, CalendarSpec, CollectionView, Conditions,
    HomeDetail, MergePatch, MkCalendar, PageRequest, PropPatch, PropPatchOutcome, Upserted,
};
use crate::wiring::AppCore;

/// The [`CalendarService`] of the application.
#[derive(Debug, Clone)]
pub struct CalendarServiceImpl {
    core: AppCore,
}

impl CalendarServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

/// A calendar to create together with its owner's binding.
#[derive(Debug, Clone)]
pub(crate) struct NewCalendar {
    pub(crate) slug: CalendarSlug,
    pub(crate) kind: CalendarKind,
    pub(crate) display_name: String,
    pub(crate) description: Option<String>,
    pub(crate) color: Option<String>,
    pub(crate) sort_order: i32,
    pub(crate) components: Vec<ComponentKind>,
    pub(crate) timezone_ics: Option<String>,
    pub(crate) schedule_transp: Option<Transparency>,
}

/// Creates a calendar and the binding of its owner in the transaction (the collection of the owner's home has the
/// slug of the calendar).
///
/// # Errors
///
/// `Conflict` when the owner already has a calendar or a binding with the slug, store failures otherwise.
pub(crate) async fn provision(
    core: &AppCore,
    tx: &mut dyn Tx,
    owner: &Principal,
    new: NewCalendar,
) -> AppResult<(Calendar, Binding)> {
    let deps = core.deps();
    let now = deps.clock.now();
    let calendar = Calendar {
        id: CalendarId::from_uuid(deps.ids.new_id()),
        tenant_id: owner.tenant_id,
        owner_id: owner.id,
        slug: new.slug.clone(),
        kind: new.kind,
        display_name: new.display_name,
        description: new.description,
        color: new.color,
        sort_order: new.sort_order,
        components: new.components,
        timezone_ics: new.timezone_ics,
        sync_seq: 0,
        sync_min_seq: 0,
        sync_epoch: deps.ids.new_id(),
        deleted_at: None,
        created_at: now,
        updated_at: now,
        version: 1,
    };
    let calendar = tx.calendars().create(calendar).await?;
    let binding = Binding {
        id: BindingId::from_uuid(deps.ids.new_id()),
        tenant_id: owner.tenant_id,
        principal_id: owner.id,
        calendar_id: calendar.id,
        slug: new.slug,
        display_name: None,
        color: None,
        sort_order: None,
        schedule_transp: new.schedule_transp,
        hidden: false,
        created_at: now,
        updated_at: now,
        version: 1,
    };
    let binding = tx.bindings().create(binding).await?;
    Ok((calendar, binding))
}

#[async_trait]
impl CalendarService for CalendarServiceImpl {
    async fn list_home(&self, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Vec<BindingView>> {
        self.home_listing(ctx, principal).await
    }

    async fn list_home_collections(
        &self,
        ctx: &RequestContext,
        home: &ResourcePath,
        detail: HomeDetail,
    ) -> AppResult<Vec<CollectionView>> {
        self.home_collections(ctx, home, detail).await
    }

    async fn get_collection(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<CollectionView> {
        self.collection(ctx, path).await
    }

    async fn mkcalendar(&self, ctx: &RequestContext, request: MkCalendar) -> AppResult<BindingView> {
        self.create_in_home(ctx, request).await
    }

    async fn proppatch(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        changes: PropPatch,
    ) -> AppResult<PropPatchOutcome> {
        self.patch_properties(ctx, path, changes).await
    }

    async fn delete_collection(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        conditions: Conditions,
    ) -> AppResult<()> {
        self.delete_bound(ctx, path, conditions).await
    }

    async fn get(&self, ctx: &RequestContext, calendar: &CalendarRef) -> AppResult<CalendarView> {
        self.read_calendar(ctx, calendar).await
    }

    async fn list_owned(
        &self,
        ctx: &RequestContext,
        owner: &PrincipalName,
        page: PageRequest,
    ) -> AppResult<Page<CalendarView>> {
        self.list_calendars_of(ctx, owner, page).await
    }

    async fn upsert(
        &self,
        ctx: &RequestContext,
        spec: CalendarSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<CalendarView>> {
        self.upsert_calendar(ctx, spec, conditions).await
    }

    async fn patch(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<CalendarView> {
        self.patch_calendar(ctx, calendar, patch, conditions).await
    }

    async fn delete(&self, ctx: &RequestContext, calendar: &CalendarRef, conditions: Conditions) -> AppResult<()> {
        self.delete_calendar(ctx, calendar, conditions).await
    }

    async fn list_tenant(
        &self,
        ctx: &RequestContext,
        search: CalendarSearch,
        page: PageRequest,
    ) -> AppResult<Page<CalendarView>> {
        self.search_calendars(ctx, search, page).await
    }

    async fn list_bindings(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        filter: BindingFilter,
        page: PageRequest,
    ) -> AppResult<Page<HomeBindingView>> {
        self.list_bindings_of(ctx, principal, filter, page).await
    }

    async fn restore_binding(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        binding: &CalendarSlug,
    ) -> AppResult<HomeBindingView> {
        self.restore_binding_of(ctx, principal, binding).await
    }
}
