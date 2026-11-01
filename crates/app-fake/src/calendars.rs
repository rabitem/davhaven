//! Fake calendar service.
//!
//! Homes list the owner's bindings plus (lazily created) bindings of the calendars of groups the principal belongs
//! to; collections, MKCALENDAR, PROPPATCH (per-binding properties always, shared properties with write access) and
//! deletion follow the plan. Permissions come from `domain::authz::decide` over facts computed from the world, so
//! the status policy (404 for invisible, 403 with `need-privileges` for forbidden) is the real one. The fake has
//! no sharing: grants are always empty.

use async_trait::async_trait;
use davhaven_app::error::{AppError, AppResult, SafeMessage};
use davhaven_app::services::{
    BindingFilter, BindingView, CalendarRef, CalendarSearch, CalendarService, CalendarSpec, CollectionView, Conditions,
    MergePatch, MkCalendar, PageRequest, PrincipalSummary, PropPatch, PropPatchOutcome, PropertyChange,
    PropertyOutcome, PropertyStatus, SharingRole, Upserted,
};
use davhaven_domain::{
    Access, AdminDecision, AdminOperation, Binding, BindingId, Calendar, CalendarId, CalendarKind, CalendarSlug,
    Decision, Operation, Precondition, Principal, PrincipalId, PrincipalKind, PrincipalName, RequestContext,
    ResourceKind, ResourcePath, ScopeRule, SyncToken, TenantId, TenantSlug, Transparency, binding_required, decide,
    decide_admin, effective_access, privileges,
};
use davhaven_wire::{CalendarView, CalendarWrite, HomeBindingView, Page};

use crate::state::{FakeState, FakeTenant, FakeWorld, paginate};

/// The size of a dead property against `limits.dav.max_dead_property_size`: its namespace, its name and its value, in bytes, as
/// the real application counts it (`DeadProperty::size`).
fn property_size(namespace: &str, local: &str, value: &str) -> usize {
    namespace.len().saturating_add(local.len()).saturating_add(value.len())
}

/// The fake [`CalendarService`].
#[derive(Debug, Clone)]
pub struct FakeCalendars {
    state: FakeState,
}

impl FakeCalendars {
    /// Creates the service on a shared world.
    pub const fn new(state: FakeState) -> Self {
        Self { state }
    }
}

/// A resolved calendar collection of a home: ids and names, so callers can keep mutating the world.
#[derive(Debug, Clone)]
pub(crate) struct CollectionTarget {
    /// The tenant slug of the path.
    pub(crate) tenant_slug: TenantSlug,
    /// The principal whose home the collection is in.
    pub(crate) home: PrincipalId,
    /// The name of that principal.
    pub(crate) home_name: PrincipalName,
    /// The binding of the collection.
    pub(crate) binding: BindingId,
    /// The calendar behind it.
    pub(crate) calendar: CalendarId,
}

fn invalid(text: &'static str) -> AppError {
    AppError::invalid(SafeMessage::from_static(text))
}

/// Whether the caller may address the home of `principal`: the principal themselves, or a tenant administrator.
fn may_use_home(ctx: &RequestContext, principal: &Principal) -> bool {
    use davhaven_domain::Actor;
    match &ctx.actor {
        Actor::Principal(id) | Actor::PrincipalToken { principal: id, .. } => *id == principal.id,
        Actor::TenantToken(_) => true,
        _ => false,
    }
}

/// The scope an operation needs on the caller's channel.
fn require_scope(ctx: &RequestContext, operation: Operation) -> AppResult<()> {
    match operation.scope_rule(ctx.channel) {
        ScopeRule::Unavailable => Err(AppError::not_found()),
        ScopeRule::Required(scope) if !ctx.scopes.contains(scope) => Err(AppError::forbidden()),
        ScopeRule::Required(_) | ScopeRule::Unscoped => Ok(()),
    }
}

fn admin(ctx: &RequestContext, operation: AdminOperation) -> AppResult<()> {
    match decide_admin(&ctx.subject(), ctx.channel, operation) {
        AdminDecision::Allow => Ok(()),
        AdminDecision::Forbidden => Err(AppError::forbidden()),
    }
}

impl FakeWorld {
    /// The tenant of the path and the principal whose home it addresses, if the caller may use that home.
    pub(crate) fn home_principal(
        &self,
        ctx: &RequestContext,
        slug: &TenantSlug,
        name: &PrincipalName,
    ) -> AppResult<(&FakeTenant, &Principal)> {
        let tenant = self.tenant_for_path(ctx, slug)?;
        let principal = self.require_principal(tenant.id, name)?;
        if may_use_home(ctx, principal) {
            Ok((tenant, principal))
        } else {
            Err(AppError::not_found())
        }
    }

    /// Resolves the path of a calendar collection to the binding and calendar behind it. Collections the caller
    /// cannot see answer `NotFound`.
    pub(crate) fn resolve_collection(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<CollectionTarget> {
        let ResourcePath::Collection {
            tenant,
            principal,
            binding,
        } = path
        else {
            return Err(AppError::not_found());
        };
        let (tenant, home) = self.home_principal(ctx, tenant, principal)?;
        let binding = self.binding_by_slug(home.id, binding).ok_or_else(AppError::not_found)?;
        let calendar = self
            .calendar(tenant.id, binding.calendar_id)
            .ok_or_else(AppError::not_found)?;
        if self.decision(ctx, calendar, Operation::ReadCollection) == Decision::Hidden {
            return Err(AppError::not_found());
        }
        Ok(CollectionTarget {
            tenant_slug: tenant.slug.clone(),
            home: home.id,
            home_name: home.name.clone(),
            binding: binding.id,
            calendar: calendar.id,
        })
    }

    fn sync_token_of(calendar: &Calendar) -> SyncToken {
        SyncToken::new(
            calendar.id.as_uuid(),
            calendar.sync_epoch,
            u64::try_from(calendar.sync_seq).unwrap_or(0),
        )
    }

    fn summary(&self, id: PrincipalId) -> AppResult<PrincipalSummary> {
        let principal = self.principals.get(&id).ok_or_else(AppError::not_found)?;
        Ok(PrincipalSummary {
            id,
            name: principal.name.clone(),
            display_name: principal.display_name.clone(),
            kind: principal.kind,
        })
    }

    /// The binding with the calendar's properties and the home owner's access.
    pub(crate) fn binding_view(
        &self,
        tenant: &FakeTenant,
        home: &Principal,
        binding: &Binding,
        calendar: &Calendar,
    ) -> AppResult<BindingView> {
        let facts = self.access_facts_for(Some(home.id), calendar);
        let access = effective_access(home.id, &facts).unwrap_or(Access::Read);
        Ok(BindingView {
            binding_id: binding.id,
            calendar_id: calendar.id,
            path: ResourcePath::Collection {
                tenant: tenant.slug.clone(),
                principal: home.name.clone(),
                binding: binding.slug.clone(),
            },
            owner: self.summary(calendar.owner_id)?,
            kind: calendar.kind,
            display_name: binding
                .display_name
                .clone()
                .unwrap_or_else(|| calendar.display_name.clone()),
            description: calendar.description.clone(),
            color: binding.color.clone().or_else(|| calendar.color.clone()),
            sort_order: binding.sort_order.unwrap_or(calendar.sort_order),
            components: calendar.components.clone(),
            timezone_ics: calendar.timezone_ics.clone(),
            schedule_transp: binding.schedule_transp.unwrap_or(Transparency::Opaque),
            access,
            privileges: privileges(access, calendar.kind, ResourceKind::Collection),
            sharing: SharingRole::Unshared,
            shared_url: None,
            sync_token: Self::sync_token_of(calendar),
            created_at: calendar.created_at,
            updated_at: binding.updated_at.max(calendar.updated_at),
        })
    }

    /// Creates the bindings of group calendars the principal can see but has no binding for (PLAN 2.9).
    fn bind_group_calendars(&mut self, tenant: TenantId, principal: PrincipalId) {
        let groups = self.groups_of(principal);
        let missing: Vec<(CalendarId, CalendarSlug)> = self
            .calendars
            .values()
            .filter(|calendar| {
                calendar.tenant_id == tenant
                    && calendar.deleted_at.is_none()
                    && calendar.kind == CalendarKind::Group
                    && groups.contains(&calendar.owner_id)
                    && self.binding_for(principal, calendar.id).is_none()
            })
            .map(|calendar| (calendar.id, calendar.slug.clone()))
            .collect();
        for (calendar, slug) in missing {
            let slug = if self.binding_by_slug(principal, &slug).is_some() {
                CalendarSlug::parse(&format!("{slug}-group")).unwrap_or(slug)
            } else {
                slug
            };
            if self.binding_by_slug(principal, &slug).is_none() {
                self.add_binding(tenant, principal, calendar, slug);
            }
        }
    }

    fn list_home_views(
        &mut self,
        ctx: &RequestContext,
        slug: &TenantSlug,
        name: &PrincipalName,
    ) -> AppResult<Vec<BindingView>> {
        let (tenant_id, home_id) = {
            let (tenant, home) = self.home_principal(ctx, slug, name)?;
            (tenant.id, home.id)
        };
        self.bind_group_calendars(tenant_id, home_id);
        let (tenant, home) = self.home_principal(ctx, slug, name)?;
        let mut bindings: Vec<&Binding> = self
            .bindings
            .values()
            .filter(|binding| binding.principal_id == home.id && !binding.hidden)
            .collect();
        bindings.sort_by(|a, b| {
            let key = |binding: &Binding| {
                let order = binding
                    .sort_order
                    .or_else(|| {
                        self.calendar(tenant.id, binding.calendar_id)
                            .map(|calendar| calendar.sort_order)
                    })
                    .unwrap_or(0);
                (order, binding.slug.clone())
            };
            key(a).cmp(&key(b))
        });
        let mut views = Vec::new();
        for binding in bindings {
            if let Some(calendar) = self.calendar(tenant.id, binding.calendar_id) {
                views.push(self.binding_view(tenant, home, binding, calendar)?);
            }
        }
        Ok(views)
    }

    fn collection_view(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<CollectionView> {
        match path {
            ResourcePath::Collection { .. } => {
                let target = self.resolve_collection(ctx, path)?;
                let tenant = self.tenant_for_path(ctx, &target.tenant_slug)?;
                let home = self.require_principal(tenant.id, &target.home_name)?;
                let binding = self.bindings.get(&target.binding).ok_or_else(AppError::not_found)?;
                let calendar = self
                    .calendar(tenant.id, target.calendar)
                    .ok_or_else(AppError::not_found)?;
                let view = self.binding_view(tenant, home, binding, calendar)?;
                // The properties of the binding the collection is addressed through: what one sharee keeps on a shared calendar
                // is not shown to another.
                let dead_properties = self
                    .dead_properties_of(binding.id)
                    .into_iter()
                    .map(|(namespace, local, value)| davhaven_app::services::DeadProperty {
                        name: davhaven_app::services::PropertyName {
                            namespace: namespace.to_owned(),
                            local: local.to_owned(),
                        },
                        value_xml: value.to_owned(),
                    })
                    .collect();
                Ok(CollectionView {
                    path: path.clone(),
                    display_name: view.display_name.clone(),
                    privileges: view.privileges,
                    sync_token: Some(view.sync_token),
                    calendar: Some(view),
                    dead_properties,
                    invites: Vec::new(),
                })
            }
            ResourcePath::Home { tenant, principal }
            | ResourcePath::Inbox { tenant, principal }
            | ResourcePath::Outbox { tenant, principal }
            | ResourcePath::Notifications { tenant, principal } => {
                let (tenant, home) = self.home_principal(ctx, tenant, principal)?;
                let (resource, label, with_token) = match path {
                    ResourcePath::Home { .. } => (ResourceKind::Home, "Calendars", false),
                    ResourcePath::Inbox { .. } => (ResourceKind::Inbox, "Inbox", true),
                    ResourcePath::Outbox { .. } => (ResourceKind::Outbox, "Outbox", false),
                    _ => (ResourceKind::Notifications, "Notifications", true),
                };
                Ok(CollectionView {
                    path: path.clone(),
                    display_name: format!("{} {label}", home.display_name),
                    privileges: privileges(Access::Owner, CalendarKind::Personal, resource),
                    sync_token: with_token.then(|| SyncToken::new(home.id.as_uuid(), tenant.id.as_uuid(), 0)),
                    calendar: None,
                    dead_properties: Vec::new(),
                    invites: Vec::new(),
                })
            }
            _ => Err(AppError::not_found()),
        }
    }

    fn create_calendar(&mut self, ctx: &RequestContext, request: MkCalendar) -> AppResult<BindingView> {
        let ResourcePath::Collection {
            tenant: slug,
            principal: name,
            binding: calendar_slug,
        } = &request.path
        else {
            return Err(invalid("A calendar is created at a collection path."));
        };
        // The request is judged before anybody is asked whether they may make it, as the application does (`check_mkcalendar`): a
        // request that is both oversized and not allowed gets the same answer from the fake and from the application.
        let (max_count, max_size) = self.dead_property_limits();
        if request.dead_properties.len() > max_count
            || request
                .dead_properties
                .iter()
                .any(|property| property.size() > max_size)
        {
            return Err(invalid("A property is too large or there are too many properties."));
        }
        let (tenant, home) = self.home_principal(ctx, slug, name)?;
        let (tenant_id, home_id) = (tenant.id, home.id);
        let facts = davhaven_domain::AccessFacts {
            calendar_kind: CalendarKind::User,
            owner: home.id,
            owner_kind: home.kind,
            memberships: self.groups_of(home.id),
            grants: Vec::new(),
            binding: None,
            tenant_settings: std::sync::Arc::clone(&tenant.settings),
        };
        match decide(&ctx.subject(), ctx.channel, &facts, Operation::CreateCalendar) {
            Decision::Allow => {}
            Decision::Hidden => return Err(AppError::not_found()),
            Decision::Forbidden(privilege) => return Err(AppError::need_privilege(request.path.href(), privilege)),
        }
        if self.binding_by_slug(home_id, calendar_slug).is_some()
            || self.calendar_by_key(tenant_id, home_id, calendar_slug).is_some()
        {
            return Err(AppError::conflict().with_precondition(Precondition::ResourceMustBeNull));
        }
        let allowed = tenant.settings.allowed_components.clone();
        let calendar_id = self.add_calendar(
            home_id,
            calendar_slug.clone(),
            CalendarKind::User,
            request.display_name.as_deref().unwrap_or(calendar_slug.as_str()),
        );
        // The binding of the creator is the only one the new calendar has; the properties of the request belong to it.
        let binding_id = self
            .binding_for(home_id, calendar_id)
            .map(|binding| binding.id)
            .ok_or_else(|| AppError::internal(std::io::Error::other("a new calendar has no binding of its creator")))?;
        let now = self.tick();
        if let Some(calendar) = self.calendars.get_mut(&calendar_id) {
            calendar.description = request.description;
            calendar.color = request.color;
            calendar.sort_order = request.sort_order.unwrap_or(0);
            calendar.components = request.components.unwrap_or(allowed);
            calendar.timezone_ics = request.timezone_ics;
            calendar.updated_at = now;
        }
        if let Some(binding) = self.bindings.get_mut(&binding_id) {
            binding.schedule_transp = request.schedule_transp;
        }
        for property in request.dead_properties {
            self.dead_properties.insert(
                (binding_id, property.name.namespace, property.name.local),
                property.value_xml,
            );
        }
        let tenant = self.tenant_for_path(ctx, slug)?;
        let home = self.require_principal(tenant.id, name)?;
        let binding = self.binding_for(home.id, calendar_id).ok_or_else(AppError::not_found)?;
        let calendar = self.calendar(tenant.id, calendar_id).ok_or_else(AppError::not_found)?;
        self.binding_view(tenant, home, binding, calendar)
    }

    /// Computes the status of every change of a PROPPATCH without applying anything.
    fn proppatch_statuses(
        &self,
        ctx: &RequestContext,
        target: &CollectionTarget,
        patch: &PropPatch,
    ) -> AppResult<Vec<PropertyStatus>> {
        let calendar = self.calendars.get(&target.calendar).ok_or_else(AppError::not_found)?;
        let may_write_shared = self.decision(ctx, calendar, Operation::UpdateCalendar) == Decision::Allow;
        // The limits are those of the world (`limits.dav`), counted per binding like the real application does.
        let (max_count, max_size) = self.dead_property_limits();
        let mut dead_count = self.dead_properties_of(target.binding).len();
        let mut statuses = Vec::with_capacity(patch.changes.len());
        for change in &patch.changes {
            let status = match change {
                PropertyChange::Description(_) | PropertyChange::Timezone(_) if !may_write_shared => {
                    PropertyStatus::Forbidden
                }
                PropertyChange::Dead { name, value_xml } => {
                    let key = (target.binding, name.namespace.clone(), name.local.clone());
                    match value_xml {
                        Some(value) if property_size(&name.namespace, &name.local, value) > max_size => {
                            PropertyStatus::InsufficientStorage
                        }
                        Some(_) if !self.dead_properties.contains_key(&key) && dead_count >= max_count => {
                            PropertyStatus::InsufficientStorage
                        }
                        Some(_) => {
                            if !self.dead_properties.contains_key(&key) {
                                dead_count += 1;
                            }
                            PropertyStatus::Applied
                        }
                        None => PropertyStatus::Applied,
                    }
                }
                _ => PropertyStatus::Applied,
            };
            statuses.push(status);
        }
        Ok(statuses)
    }

    fn apply_proppatch(&mut self, target: &CollectionTarget, patch: PropPatch) {
        let now = self.tick();
        let mut shared_changed = false;
        for change in patch.changes {
            match change {
                PropertyChange::DisplayName(value) => {
                    if let Some(binding) = self.bindings.get_mut(&target.binding) {
                        binding.display_name = value;
                    }
                }
                PropertyChange::Color(value) => {
                    if let Some(binding) = self.bindings.get_mut(&target.binding) {
                        binding.color = value;
                    }
                }
                PropertyChange::Order(value) => {
                    if let Some(binding) = self.bindings.get_mut(&target.binding) {
                        binding.sort_order = value;
                    }
                }
                PropertyChange::ScheduleTransparency(value) => {
                    if let Some(binding) = self.bindings.get_mut(&target.binding) {
                        binding.schedule_transp = value;
                    }
                }
                PropertyChange::Description(value) => {
                    shared_changed = true;
                    if let Some(calendar) = self.calendars.get_mut(&target.calendar) {
                        calendar.description = value;
                    }
                }
                PropertyChange::Timezone(value) => {
                    shared_changed = true;
                    if let Some(calendar) = self.calendars.get_mut(&target.calendar) {
                        calendar.timezone_ics = value;
                    }
                }
                PropertyChange::Dead { name, value_xml } => {
                    let key = (target.binding, name.namespace, name.local);
                    match value_xml {
                        Some(value) => {
                            self.dead_properties.insert(key, value);
                        }
                        None => {
                            self.dead_properties.remove(&key);
                        }
                    }
                }
            }
        }
        if let Some(binding) = self.bindings.get_mut(&target.binding) {
            binding.updated_at = now;
            binding.version += 1;
        }
        if shared_changed && let Some(calendar) = self.calendars.get_mut(&target.calendar) {
            calendar.sync_seq += 1;
            calendar.updated_at = now;
            calendar.version += 1;
        }
    }

    fn proppatch_collection(
        &mut self,
        ctx: &RequestContext,
        path: &ResourcePath,
        request: PropPatch,
    ) -> AppResult<PropPatchOutcome> {
        let target = self.resolve_collection(ctx, path)?;
        let statuses = self.proppatch_statuses(ctx, &target, &request)?;
        let failed = statuses.iter().any(|status| *status != PropertyStatus::Applied);
        let results = request
            .changes
            .iter()
            .zip(&statuses)
            .map(|(change, status)| PropertyOutcome {
                name: change.name(),
                status: match (failed, *status) {
                    (true, PropertyStatus::Applied) => PropertyStatus::FailedDependency,
                    (_, status) => status,
                },
                // The fake accepts every time zone: it has no value to refuse with a precondition.
                precondition: None,
            })
            .collect();
        if !failed {
            self.apply_proppatch(&target, request);
        }
        Ok(PropPatchOutcome { results })
    }

    fn delete_collection_at(&mut self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<()> {
        let target = self.resolve_collection(ctx, path)?;
        let calendar = self.calendars.get(&target.calendar).ok_or_else(AppError::not_found)?;
        let owns = calendar.owner_id == target.home;
        let operation = if owns {
            Operation::DeleteCalendar
        } else {
            Operation::RemoveBinding
        };
        // DELETE needs `DAV:unbind` on the parent: for a binding that is the home.
        self.enforce(ctx, calendar, operation, || match (operation, path) {
            (Operation::RemoveBinding, ResourcePath::Collection { tenant, principal, .. }) => ResourcePath::Home {
                tenant: tenant.clone(),
                principal: principal.clone(),
            }
            .href(),
            _ => path.href(),
        })?;
        let now = self.tick();
        if owns {
            if let Some(calendar) = self.calendars.get_mut(&target.calendar) {
                calendar.deleted_at = Some(now);
                calendar.updated_at = now;
            }
            self.remove_bindings(|binding| binding.calendar_id == target.calendar);
            self.objects.retain(|_, object| object.calendar_id != target.calendar);
        } else if let Some(binding) = self.bindings.get_mut(&target.binding) {
            binding.hidden = true;
            binding.updated_at = now;
            binding.version += 1;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------------------
    // Management API
    // -----------------------------------------------------------------------------------------------------

    /// The calendar a reference names, inside the caller's tenant.
    fn resolve_ref(&self, ctx: &RequestContext, reference: &CalendarRef) -> AppResult<&Calendar> {
        match reference {
            CalendarRef::Id(id) => self.calendar(ctx.tenant, *id).ok_or_else(AppError::not_found),
            CalendarRef::Key { owner, slug } => {
                let owner = self.require_principal(ctx.tenant, owner)?;
                self.calendar_by_key(ctx.tenant, owner.id, slug)
                    .ok_or_else(AppError::not_found)
            }
        }
    }

    /// The id of the calendar a reference names; the object service uses it.
    pub(crate) fn calendar_id_of(&self, ctx: &RequestContext, reference: &CalendarRef) -> AppResult<CalendarId> {
        self.resolve_ref(ctx, reference).map(|calendar| calendar.id)
    }

    /// The collection of a calendar in its owner's home.
    fn calendar_path(&self, tenant: &FakeTenant, calendar: &Calendar) -> AppResult<ResourcePath> {
        let owner = self
            .principals
            .get(&calendar.owner_id)
            .ok_or_else(AppError::not_found)?;
        let binding = self
            .binding_for(owner.id, calendar.id)
            .map_or_else(|| calendar.slug.clone(), |binding| binding.slug.clone());
        Ok(ResourcePath::Collection {
            tenant: tenant.slug.clone(),
            principal: owner.name.clone(),
            binding,
        })
    }

    fn calendar_view(&self, tenant: &FakeTenant, calendar: &Calendar) -> AppResult<CalendarView> {
        let owner = self
            .principals
            .get(&calendar.owner_id)
            .ok_or_else(AppError::not_found)?;
        Ok(CalendarView {
            id: calendar.id,
            owner_id: owner.id,
            owner: owner.name.clone(),
            slug: calendar.slug.clone(),
            kind: calendar.kind,
            display_name: calendar.display_name.clone(),
            description: calendar.description.clone(),
            color: calendar.color.clone(),
            sort_order: calendar.sort_order,
            components: calendar.components.clone(),
            sync_token: Self::sync_token_of(calendar),
            dav_url: self.urls.dav_url(&self.calendar_path(tenant, calendar)?),
            created_at: calendar.created_at,
            updated_at: calendar.updated_at,
            version: calendar.version,
        })
    }

    fn calendar_write(calendar: &Calendar) -> CalendarWrite {
        CalendarWrite {
            kind: Some(calendar.kind),
            display_name: calendar.display_name.clone(),
            description: calendar.description.clone(),
            color: calendar.color.clone(),
            sort_order: Some(calendar.sort_order),
            components: Some(calendar.components.clone()),
        }
    }

    fn get_calendar(&self, ctx: &RequestContext, reference: &CalendarRef) -> AppResult<CalendarView> {
        let calendar = self.resolve_ref(ctx, reference)?;
        let tenant = self.tenant_of(ctx)?;
        self.enforce(ctx, calendar, Operation::ReadCollection, || {
            self.calendar_path(tenant, calendar)
                .map_or_else(|_| ResourcePath::Root.href(), |path| path.href())
        })?;
        self.calendar_view(tenant, calendar)
    }

    fn list_owned_calendars(
        &self,
        ctx: &RequestContext,
        owner: &PrincipalName,
        page: &PageRequest,
    ) -> AppResult<Page<CalendarView>> {
        require_scope(ctx, Operation::ReadCollection)?;
        let tenant = self.tenant_of(ctx)?;
        let owner = self.require_principal(tenant.id, owner)?;
        let mut items = Vec::new();
        for calendar in self.calendars.values().filter(|calendar| {
            calendar.tenant_id == tenant.id && calendar.owner_id == owner.id && calendar.deleted_at.is_none()
        }) {
            if self.decision(ctx, calendar, Operation::ReadCollection) == Decision::Allow {
                items.push((calendar.id.as_uuid(), self.calendar_view(tenant, calendar)?));
            }
        }
        paginate(items, page.limit, page.cursor.as_ref())
    }

    fn upsert_calendar(
        &mut self,
        ctx: &RequestContext,
        owner: &PrincipalName,
        slug: &CalendarSlug,
        body: CalendarWrite,
        conditions: Conditions,
    ) -> AppResult<Upserted<CalendarView>> {
        let tenant = self.tenant_of(ctx)?;
        let (tenant_id, allowed) = (tenant.id, tenant.settings.allowed_components.clone());
        let owner = self.require_principal(tenant_id, owner)?;
        let (owner_id, owner_kind) = (owner.id, owner.kind);
        if body.display_name.trim().is_empty() {
            return Err(invalid("The display name must not be empty."));
        }
        let existing = self.calendar_by_key(tenant_id, owner_id, slug).cloned();
        conditions.check(existing.as_ref().map(|calendar| calendar.version))?;
        let kind = match (&existing, body.kind) {
            (Some(calendar), Some(kind)) if kind != calendar.kind => {
                return Err(invalid("The kind of a calendar cannot change."));
            }
            (Some(calendar), _) => calendar.kind,
            (None, requested) => requested.unwrap_or(CalendarKind::User),
        };
        if existing.is_none() && matches!(kind, CalendarKind::Mirror | CalendarKind::Personal) {
            return Err(invalid("Personal and mirror calendars are created by the server."));
        }
        if existing.is_none() && (kind == CalendarKind::Group) != (owner_kind == PrincipalKind::Group) {
            return Err(invalid("Group calendars belong to groups and only to groups."));
        }
        let facts = davhaven_domain::AccessFacts {
            calendar_kind: kind,
            owner: owner_id,
            owner_kind,
            memberships: Vec::new(),
            grants: Vec::new(),
            binding: None,
            tenant_settings: std::sync::Arc::clone(&self.tenant_of(ctx)?.settings),
        };
        let operation = if existing.is_some() {
            Operation::UpdateCalendar
        } else {
            Operation::CreateCalendar
        };
        let facts = match &existing {
            Some(calendar) => self.access_facts(ctx, calendar),
            None => facts,
        };
        match decide(&ctx.subject(), ctx.channel, &facts, operation) {
            Decision::Allow => {}
            Decision::Hidden => return Err(AppError::not_found()),
            Decision::Forbidden(_) => return Err(AppError::forbidden()),
        }
        let created = existing.is_none();
        let id = match existing {
            Some(calendar) => calendar.id,
            None => self.add_calendar(owner_id, slug.clone(), kind, &body.display_name),
        };
        let now = self.tick();
        if let Some(calendar) = self.calendars.get_mut(&id) {
            let components = body
                .components
                .unwrap_or_else(|| if created { allowed } else { calendar.components.clone() });
            let changed = created
                || calendar.display_name != body.display_name
                || calendar.description != body.description
                || calendar.color != body.color
                || calendar.sort_order != body.sort_order.unwrap_or(0)
                || calendar.components != components;
            if changed {
                calendar.display_name = body.display_name;
                calendar.description = body.description;
                calendar.color = body.color;
                calendar.sort_order = body.sort_order.unwrap_or(0);
                calendar.components = components;
                calendar.updated_at = now;
                calendar.version += 1;
                if !created {
                    calendar.sync_seq += 1;
                }
            }
        }
        let tenant = self.tenant_of(ctx)?;
        let calendar = self.calendar(tenant_id, id).ok_or_else(AppError::not_found)?;
        let view = self.calendar_view(tenant, calendar)?;
        Ok(if created {
            Upserted::created(view)
        } else {
            Upserted::replaced(view)
        })
    }

    fn patch_calendar(
        &mut self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        patch: &MergePatch,
        conditions: Conditions,
    ) -> AppResult<CalendarView> {
        let calendar = self.resolve_ref(ctx, reference)?.clone();
        conditions.check(Some(calendar.version))?;
        let owner = self
            .principals
            .get(&calendar.owner_id)
            .ok_or_else(AppError::not_found)?
            .name
            .clone();
        let mut document = serde_json::to_value(Self::calendar_write(&calendar)).map_err(AppError::internal)?;
        patch.apply(&mut document);
        let body: CalendarWrite =
            serde_json::from_value(document).map_err(|_| invalid("The patched calendar is not valid."))?;
        let upserted = self.upsert_calendar(ctx, &owner, &calendar.slug, body, Conditions::none())?;
        Ok(upserted.value)
    }

    fn delete_calendar_ref(
        &mut self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        conditions: Conditions,
    ) -> AppResult<()> {
        let calendar = self.resolve_ref(ctx, reference)?.clone();
        conditions.require_if_match()?;
        conditions.check(Some(calendar.version))?;
        self.enforce(ctx, &calendar, Operation::DeleteCalendar, || ResourcePath::Root.href())?;
        let now = self.tick();
        if let Some(stored) = self.calendars.get_mut(&calendar.id) {
            stored.deleted_at = Some(now);
            stored.updated_at = now;
        }
        self.remove_bindings(|binding| binding.calendar_id == calendar.id);
        self.objects.retain(|_, object| object.calendar_id != calendar.id);
        Ok(())
    }

    /// A binding of a home as the management API lists it.
    fn home_binding_view(
        &self,
        tenant: &FakeTenant,
        home: &Principal,
        binding: &Binding,
        calendar: &Calendar,
    ) -> AppResult<HomeBindingView> {
        let owner = self
            .principals
            .get(&calendar.owner_id)
            .ok_or_else(AppError::not_found)?;
        let facts = self.access_facts_for(Some(home.id), calendar);
        let path = ResourcePath::Collection {
            tenant: tenant.slug.clone(),
            principal: home.name.clone(),
            binding: binding.slug.clone(),
        };
        Ok(HomeBindingView {
            id: binding.id,
            principal: home.name.clone(),
            slug: binding.slug.clone(),
            calendar_id: calendar.id,
            owner: owner.name.clone(),
            calendar: calendar.slug.clone(),
            kind: calendar.kind,
            display_name: binding
                .display_name
                .clone()
                .unwrap_or_else(|| calendar.display_name.clone()),
            hidden: binding.hidden,
            required: binding_required(home.id, &facts),
            dav_url: self.urls.dav_url(&path),
            created_at: binding.created_at,
            updated_at: binding.updated_at,
            version: binding.version,
        })
    }

    fn list_binding_views(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        filter: BindingFilter,
        page: &PageRequest,
    ) -> AppResult<Page<HomeBindingView>> {
        admin(ctx, AdminOperation::ListBindings)?;
        let tenant = self.tenant_of(ctx)?;
        let home = self.require_principal(tenant.id, principal)?;
        let mut items = Vec::new();
        for binding in self
            .bindings
            .values()
            .filter(|binding| binding.principal_id == home.id)
            .filter(|binding| filter.hidden.is_none_or(|hidden| binding.hidden == hidden))
        {
            if let Some(calendar) = self.calendar(tenant.id, binding.calendar_id) {
                // A calendar the principal has no access to any more is not in their home.
                if effective_access(home.id, &self.access_facts_for(Some(home.id), calendar)).is_none() {
                    continue;
                }
                items.push((
                    binding.id.as_uuid(),
                    self.home_binding_view(tenant, home, binding, calendar)?,
                ));
            }
        }
        items.sort_by_key(|(id, _)| *id);
        paginate(items, page.limit, page.cursor.as_ref())
    }

    fn restore_binding_view(
        &mut self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        slug: &CalendarSlug,
    ) -> AppResult<HomeBindingView> {
        admin(ctx, AdminOperation::RestoreBinding)?;
        let (tenant_id, home_id) = {
            let tenant = self.tenant_of(ctx)?;
            (tenant.id, self.require_principal(tenant.id, principal)?.id)
        };
        let id = self
            .bindings
            .values()
            .find(|binding| binding.principal_id == home_id && &binding.slug == slug)
            .map(|binding| binding.id)
            .ok_or_else(AppError::not_found)?;
        // A calendar the principal has no access to any more is not in their home and cannot be put there.
        let reachable = self
            .bindings
            .get(&id)
            .and_then(|binding| self.calendar(tenant_id, binding.calendar_id))
            .is_some_and(|calendar| {
                effective_access(home_id, &self.access_facts_for(Some(home_id), calendar)).is_some()
            });
        if !reachable {
            return Err(AppError::not_found());
        }
        let now = self.tick();
        if let Some(binding) = self.bindings.get_mut(&id)
            && binding.hidden
        {
            binding.hidden = false;
            binding.updated_at = now;
            binding.version += 1;
        }
        let tenant = self.tenant_of(ctx)?;
        let home = self.require_principal(tenant_id, principal)?;
        let binding = self.bindings.get(&id).ok_or_else(AppError::not_found)?;
        let calendar = self
            .calendar(tenant_id, binding.calendar_id)
            .ok_or_else(AppError::not_found)?;
        self.home_binding_view(tenant, home, binding, calendar)
    }

    fn search_calendars(
        &self,
        ctx: &RequestContext,
        search: &CalendarSearch,
        page: &PageRequest,
    ) -> AppResult<Page<CalendarView>> {
        admin(ctx, AdminOperation::SearchCalendars)?;
        let tenant = self.tenant_of(ctx)?;
        let owner = match &search.owner {
            Some(name) => Some(self.require_principal(tenant.id, name)?.id),
            None => None,
        };
        let query = search.query.as_ref().map(|query| query.to_lowercase());
        let mut items = Vec::new();
        for calendar in self.calendars.values().filter(|calendar| {
            calendar.tenant_id == tenant.id
                && calendar.deleted_at.is_none()
                && owner.is_none_or(|owner| calendar.owner_id == owner)
                && search.kind.is_none_or(|kind| calendar.kind == kind)
                && query
                    .as_ref()
                    .is_none_or(|query| calendar.display_name.to_lowercase().contains(query))
        }) {
            items.push((calendar.id.as_uuid(), self.calendar_view(tenant, calendar)?));
        }
        paginate(items, page.limit, page.cursor.as_ref())
    }
}

#[async_trait]
impl CalendarService for FakeCalendars {
    async fn list_home(&self, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Vec<BindingView>> {
        let tenant = self
            .state
            .read(|world| world.tenant_of(ctx).map(|tenant| tenant.slug.clone()))
            .await?;
        self.state
            .write(|world| world.list_home_views(ctx, &tenant, principal))
            .await
    }

    async fn get_collection(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<CollectionView> {
        self.state.read(|world| world.collection_view(ctx, path)).await
    }

    async fn mkcalendar(&self, ctx: &RequestContext, request: MkCalendar) -> AppResult<BindingView> {
        self.state.write(|world| world.create_calendar(ctx, request)).await
    }

    async fn proppatch(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        request: PropPatch,
    ) -> AppResult<PropPatchOutcome> {
        self.state
            .write(|world| world.proppatch_collection(ctx, path, request))
            .await
    }

    async fn delete_collection(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        _conditions: Conditions,
    ) -> AppResult<()> {
        self.state.write(|world| world.delete_collection_at(ctx, path)).await
    }

    async fn get(&self, ctx: &RequestContext, calendar: &CalendarRef) -> AppResult<CalendarView> {
        self.state.read(|world| world.get_calendar(ctx, calendar)).await
    }

    async fn list_owned(
        &self,
        ctx: &RequestContext,
        owner: &PrincipalName,
        page: PageRequest,
    ) -> AppResult<Page<CalendarView>> {
        self.state
            .read(|world| world.list_owned_calendars(ctx, owner, &page))
            .await
    }

    async fn upsert(
        &self,
        ctx: &RequestContext,
        spec: CalendarSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<CalendarView>> {
        self.state
            .write(|world| world.upsert_calendar(ctx, &spec.owner, &spec.slug, spec.body, conditions))
            .await
    }

    async fn patch(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<CalendarView> {
        self.state
            .write(|world| world.patch_calendar(ctx, calendar, &patch, conditions))
            .await
    }

    async fn delete(&self, ctx: &RequestContext, calendar: &CalendarRef, conditions: Conditions) -> AppResult<()> {
        self.state
            .write(|world| world.delete_calendar_ref(ctx, calendar, conditions))
            .await
    }

    async fn list_tenant(
        &self,
        ctx: &RequestContext,
        search: CalendarSearch,
        page: PageRequest,
    ) -> AppResult<Page<CalendarView>> {
        self.state
            .read(|world| world.search_calendars(ctx, &search, &page))
            .await
    }

    async fn list_bindings(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        filter: BindingFilter,
        page: PageRequest,
    ) -> AppResult<Page<HomeBindingView>> {
        self.state
            .read(|world| world.list_binding_views(ctx, principal, filter, &page))
            .await
    }

    async fn restore_binding(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        binding: &CalendarSlug,
    ) -> AppResult<HomeBindingView> {
        self.state
            .write(|world| world.restore_binding_view(ctx, principal, binding))
            .await
    }
}
