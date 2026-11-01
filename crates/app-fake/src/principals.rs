//! Fake principal service.
//!
//! Implements the whole [`PrincipalService`] on the in-memory world: create-or-replace with `If-Match`, merge
//! patches, soft deletion (deleted principals disappear), memberships, search and the DAV principal properties.
//! Administration needs a tenant token with the right scope (`decide_admin`); the DAV-facing lookups only need an
//! authenticated caller of the same tenant.

use async_trait::async_trait;
use davhaven_app::error::{AppError, AppResult, SafeMessage};
use davhaven_app::services::{
    AddressClass, Conditions, DeleteOptions, MAX_SEARCH_HITS, MergePatch, PageRequest, PrincipalFilter, PrincipalHit,
    PrincipalProps, PrincipalSearch, PrincipalSearchResult, PrincipalService, PrincipalSpec, SearchPlan, Upserted,
};
use davhaven_domain::{
    AdminDecision, AdminOperation, CalendarUserAddress, Principal, PrincipalId, PrincipalKind, PrincipalName,
    PrincipalStatus, RequestContext, ResourcePath, SearchCriterion, TenantId, decide_admin,
};
use davhaven_wire::{MembershipSet, Page, PrincipalView, PrincipalWrite};

use crate::state::{FakeState, FakeTenant, FakeWorld, paginate};

/// The fake [`PrincipalService`].
#[derive(Debug, Clone)]
pub struct FakePrincipals {
    state: FakeState,
}

impl FakePrincipals {
    /// Creates the service on a shared world.
    pub const fn new(state: FakeState) -> Self {
        Self { state }
    }
}

/// Checks the administration permission of the caller.
fn admin(ctx: &RequestContext, operation: AdminOperation) -> AppResult<()> {
    match decide_admin(&ctx.subject(), ctx.channel, operation) {
        AdminDecision::Allow => Ok(()),
        AdminDecision::Forbidden => Err(AppError::forbidden()),
    }
}

/// An authenticated caller is enough for DAV-facing lookups.
fn authenticated(ctx: &RequestContext) -> AppResult<()> {
    if ctx.actor.is_authenticated() {
        Ok(())
    } else {
        Err(AppError::unauthenticated())
    }
}

fn invalid(text: &'static str) -> AppError {
    AppError::invalid(SafeMessage::from_static(text))
}

fn conflict(text: &'static str) -> AppError {
    AppError::conflict().with_public_message(SafeMessage::from_static(text))
}

impl FakeWorld {
    /// All calendar user addresses of a principal: primary mail address, further addresses, the principal URL and
    /// the `urn:uuid` form.
    pub(crate) fn calendar_addresses(&self, tenant: &FakeTenant, principal: &Principal) -> Vec<CalendarUserAddress> {
        let mut addresses = Vec::new();
        if let Some(email) = &principal.email {
            addresses.push(CalendarUserAddress::mailto(email));
        }
        addresses.extend(self.extra_addresses.get(&principal.id).cloned().unwrap_or_default());
        let path = ResourcePath::Principal {
            tenant: tenant.slug.clone(),
            principal: principal.name.clone(),
        };
        if let Ok(url) = CalendarUserAddress::parse(&path.format()) {
            addresses.push(url);
        }
        addresses.push(CalendarUserAddress::urn_uuid(principal.id));
        addresses
    }

    fn principal_view(&self, tenant: &FakeTenant, principal: &Principal) -> PrincipalView {
        PrincipalView {
            id: principal.id,
            kind: principal.kind,
            name: principal.name.clone(),
            display_name: principal.display_name.clone(),
            email: principal.email.clone(),
            addresses: self.extra_addresses.get(&principal.id).cloned().unwrap_or_default(),
            locale: principal.locale.clone(),
            timezone: principal.timezone,
            external_ref: principal.external_ref.clone(),
            status: principal.status,
            dav_url: self.urls.dav_url(&ResourcePath::Principal {
                tenant: tenant.slug.clone(),
                principal: principal.name.clone(),
            }),
            created_at: principal.created_at,
            updated_at: principal.updated_at,
            version: principal.version,
        }
    }

    fn principal_write(&self, principal: &Principal) -> PrincipalWrite {
        PrincipalWrite {
            kind: principal.kind,
            display_name: principal.display_name.clone(),
            email: principal.email.clone(),
            addresses: self.extra_addresses.get(&principal.id).cloned().unwrap_or_default(),
            locale: principal.locale.clone(),
            timezone: principal.timezone,
            external_ref: principal.external_ref.clone(),
            status: Some(principal.status),
        }
    }

    fn view_of(&self, tenant: TenantId, id: PrincipalId) -> AppResult<PrincipalView> {
        let tenant = self.tenant(tenant).ok_or_else(AppError::not_found)?;
        let principal = self.principal_by_id(tenant.id, id).ok_or_else(AppError::not_found)?;
        Ok(self.principal_view(tenant, principal))
    }

    fn list_principals(
        &self,
        tenant: TenantId,
        filter: &PrincipalFilter,
        page: &PageRequest,
    ) -> AppResult<Page<PrincipalView>> {
        let tenant = self.tenant(tenant).ok_or_else(AppError::not_found)?;
        let items: Vec<_> = self
            .principals
            .values()
            .filter(|principal| principal.tenant_id == tenant.id && principal.status != PrincipalStatus::Deleted)
            .filter(|principal| filter.kind.is_none_or(|kind| principal.kind == kind))
            .filter(|principal| {
                filter
                    .external_ref
                    .as_ref()
                    .is_none_or(|wanted| principal.external_ref.as_ref() == Some(wanted))
            })
            .map(|principal| (principal.id.as_uuid(), self.principal_view(tenant, principal)))
            .collect();
        paginate(items, page.limit, page.cursor.as_ref())
    }

    fn upsert_principal(
        &mut self,
        tenant_id: TenantId,
        name: PrincipalName,
        body: PrincipalWrite,
        conditions: Conditions,
    ) -> AppResult<Upserted<PrincipalView>> {
        let existing = self
            .principal_by_name(tenant_id, &name)
            .map(|principal| (principal.id, principal.version, principal.kind));
        conditions.check(existing.map(|(_, version, _)| version))?;
        if body.status == Some(PrincipalStatus::Deleted) {
            return Err(invalid("A principal is deleted with DELETE."));
        }
        if body.display_name.trim().is_empty() {
            return Err(invalid("The display name must not be empty."));
        }
        let own_id = existing.map(|(id, _, _)| id);
        let taken = |address_email: Option<&davhaven_domain::Email>| {
            address_email.is_some_and(|email| {
                self.principals.values().any(|other| {
                    other.tenant_id == tenant_id && Some(other.id) != own_id && other.email.as_ref() == Some(email)
                })
            })
        };
        if taken(body.email.as_ref()) {
            return Err(conflict("This address already belongs to another principal."));
        }
        if let Some(reference) = &body.external_ref
            && self.principals.values().any(|other| {
                other.tenant_id == tenant_id
                    && Some(other.id) != own_id
                    && other.status != PrincipalStatus::Deleted
                    && other.external_ref.as_ref() == Some(reference)
            })
        {
            return Err(conflict("A principal with this external reference already exists."));
        }
        let created = existing.is_none();
        let id = if let Some((id, _, kind)) = existing {
            if kind != body.kind {
                return Err(invalid("The kind of a principal cannot change."));
            }
            id
        } else {
            let new_id = self.add_principal(tenant_id, body.kind, name, &body.display_name, body.email.clone());
            if let Some(principal) = self.principals.get_mut(&new_id) {
                principal.version = 0;
            }
            new_id
        };
        let changed = {
            let current = self.principals.get(&id).ok_or_else(AppError::not_found)?;
            let before = (
                current.display_name.clone(),
                current.email.clone(),
                current.locale.clone(),
                current.timezone,
                current.external_ref.clone(),
                current.status,
                self.extra_addresses.get(&id).cloned().unwrap_or_default(),
            );
            let after = (
                body.display_name.clone(),
                body.email.clone(),
                body.locale.clone().or_else(|| current.locale.clone()),
                body.timezone.or(current.timezone),
                body.external_ref.clone(),
                body.status.unwrap_or(PrincipalStatus::Active),
                body.addresses.clone(),
            );
            created || before != after
        };
        if changed {
            let now = self.tick();
            if let Some(principal) = self.principals.get_mut(&id) {
                principal.display_name = body.display_name;
                principal.email = body.email;
                principal.locale = body.locale.or_else(|| principal.locale.take());
                principal.timezone = body.timezone.or(principal.timezone);
                principal.external_ref = body.external_ref;
                principal.status = body.status.unwrap_or(PrincipalStatus::Active);
                principal.updated_at = now;
                principal.version += 1;
            }
            if body.addresses.is_empty() {
                self.extra_addresses.remove(&id);
            } else {
                self.extra_addresses.insert(id, body.addresses);
            }
        }
        let view = self.view_of(tenant_id, id)?;
        Ok(if created {
            Upserted::created(view)
        } else {
            Upserted::replaced(view)
        })
    }

    fn patch_principal(
        &mut self,
        tenant: TenantId,
        name: &PrincipalName,
        patch: &MergePatch,
        conditions: Conditions,
    ) -> AppResult<PrincipalView> {
        let current = self.require_principal(tenant, name)?;
        conditions.check(Some(current.version))?;
        let mut document = serde_json::to_value(self.principal_write(current)).map_err(AppError::internal)?;
        patch.apply(&mut document);
        let body: PrincipalWrite =
            serde_json::from_value(document).map_err(|_| invalid("The patched principal is not valid."))?;
        let upserted = self.upsert_principal(tenant, name.clone(), body, Conditions::none())?;
        Ok(upserted.value)
    }

    fn delete_principal(&mut self, tenant: TenantId, name: &PrincipalName, options: DeleteOptions) -> AppResult<()> {
        let current = self.require_principal(tenant, name)?;
        let id = current.id;
        let version = current.version;
        options.conditions.require_if_match()?;
        options.conditions.check(Some(version))?;
        let now = self.tick();
        self.members.retain(|(group, member)| *group != id && *member != id);
        for password in &mut self.app_passwords {
            if password.principal == id {
                password.revoked = true;
            }
        }
        for token in &mut self.api_tokens {
            if token.principal == Some(id) {
                token.revoked = true;
            }
        }
        if options.purge {
            self.principals.remove(&id);
            let owned: Vec<_> = self
                .calendars
                .values()
                .filter(|calendar| calendar.owner_id == id)
                .map(|calendar| calendar.id)
                .collect();
            for calendar in owned {
                self.calendars.remove(&calendar);
                self.remove_bindings(|binding| binding.calendar_id == calendar);
                self.objects.retain(|_, object| object.calendar_id != calendar);
            }
            self.remove_bindings(|binding| binding.principal_id == id);
        } else if let Some(principal) = self.principals.get_mut(&id) {
            principal.status = PrincipalStatus::Deleted;
            principal.deleted_at = Some(now);
            principal.updated_at = now;
            principal.version += 1;
        }
        Ok(())
    }

    fn group_of(&self, tenant: TenantId, name: &PrincipalName) -> AppResult<&Principal> {
        let group = self.require_principal(tenant, name)?;
        if group.kind == PrincipalKind::Group {
            Ok(group)
        } else {
            Err(invalid("The principal is not a group."))
        }
    }

    fn membership_set(&self, tenant: TenantId, group: PrincipalId) -> MembershipSet {
        let mut members: Vec<PrincipalName> = self
            .members_of(group)
            .into_iter()
            .filter_map(|member| self.principal_by_id(tenant, member))
            .map(|member| member.name.clone())
            .collect();
        members.sort();
        MembershipSet { members }
    }

    fn member_of(&self, tenant: TenantId, name: &PrincipalName) -> AppResult<PrincipalId> {
        let member = self
            .principal_by_name(tenant, name)
            .ok_or_else(|| invalid("A member does not exist."))?;
        if member.kind == PrincipalKind::Group {
            return Err(invalid("Groups cannot be members of groups."));
        }
        Ok(member.id)
    }

    fn set_members(
        &mut self,
        tenant: TenantId,
        group: &PrincipalName,
        names: &[PrincipalName],
    ) -> AppResult<MembershipSet> {
        let group_id = self.group_of(tenant, group)?.id;
        let mut ids = Vec::with_capacity(names.len());
        for name in names {
            ids.push(self.member_of(tenant, name)?);
        }
        self.members.retain(|(candidate, _)| *candidate != group_id);
        for id in ids {
            self.members.insert((group_id, id));
        }
        Ok(self.membership_set(tenant, group_id))
    }

    /// The search of the real application over the store: active people, groups and resources (never services) of
    /// the tenant that satisfy the text and the criteria of the search (over the name, the display name and the stored
    /// addresses), narrowed to `kinds` when they are given, ordered by display name, cut at the limit; the answer says
    /// whether the cut dropped hits.
    fn search_principals(&self, tenant: TenantId, search: &PrincipalSearch) -> AppResult<PrincipalSearchResult> {
        let (text, criteria) = match search.plan() {
            SearchPlan::Nothing => return Ok(PrincipalSearchResult::default()),
            SearchPlan::TooShort => return Err(invalid("The search text needs at least two characters.")),
            SearchPlan::Ask { text, criteria } => (text, criteria),
        };
        let tenant = self.tenant(tenant).ok_or_else(AppError::not_found)?;
        let limit =
            usize::try_from(search.limit.unwrap_or(MAX_SEARCH_HITS).clamp(1, MAX_SEARCH_HITS)).unwrap_or(usize::MAX);
        let findable = |kind: PrincipalKind| kind != PrincipalKind::Service;
        let wanted = |kind: PrincipalKind| findable(kind) && (search.kinds.is_empty() || search.kinds.contains(&kind));
        let satisfied = |principal: &Principal| {
            // Only the addresses the store keeps: not the principal URL and `urn:uuid:`, which are derived.
            let stored: Vec<CalendarUserAddress> = principal
                .email
                .iter()
                .map(CalendarUserAddress::mailto)
                .chain(self.extra_addresses.get(&principal.id).cloned().unwrap_or_default())
                .collect();
            let matches = |criterion: &SearchCriterion| {
                criterion.matches(principal.name.as_str(), &principal.display_name, &stored)
            };
            let in_text = text.is_empty() || matches(&SearchCriterion::contains(text.as_str()));
            let in_criteria = criteria.is_empty()
                || if search.any_of {
                    criteria.iter().any(matches)
                } else {
                    criteria.iter().all(matches)
                };
            in_text && in_criteria
        };
        let mut found: Vec<&Principal> = self
            .principals
            .values()
            .filter(|principal| {
                principal.tenant_id == tenant.id
                    && principal.status == PrincipalStatus::Active
                    && wanted(principal.kind)
                    && satisfied(principal)
            })
            .collect();
        found.sort_by(|a, b| a.display_name.cmp(&b.display_name).then_with(|| a.id.cmp(&b.id)));
        let truncated = found.len() > limit;
        found.truncate(limit);
        let hits = found
            .into_iter()
            .map(|principal| PrincipalHit {
                path: ResourcePath::Principal {
                    tenant: tenant.slug.clone(),
                    principal: principal.name.clone(),
                },
                id: principal.id,
                name: principal.name.clone(),
                display_name: principal.display_name.clone(),
                kind: principal.kind,
                addresses: self.calendar_addresses(tenant, principal),
            })
            .collect();
        Ok(PrincipalSearchResult { hits, truncated })
    }

    fn principal_props(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<PrincipalProps> {
        let ResourcePath::Principal {
            tenant: slug,
            principal: name,
        } = path
        else {
            return Err(AppError::not_found());
        };
        let tenant = self.tenant_for_path(ctx, slug)?;
        let principal = self.require_principal(tenant.id, name)?;
        let paths = |ids: Vec<PrincipalId>| -> Vec<ResourcePath> {
            let mut paths: Vec<ResourcePath> = ids
                .into_iter()
                .filter_map(|id| self.principal_by_id(tenant.id, id))
                .map(|other| ResourcePath::Principal {
                    tenant: tenant.slug.clone(),
                    principal: other.name.clone(),
                })
                .collect();
            paths.sort_by_key(ResourcePath::format);
            paths
        };
        Ok(PrincipalProps {
            path: path.clone(),
            id: principal.id,
            name: principal.name.clone(),
            display_name: principal.display_name.clone(),
            kind: principal.kind,
            addresses: self.calendar_addresses(tenant, principal),
            home: ResourcePath::Home {
                tenant: tenant.slug.clone(),
                principal: principal.name.clone(),
            },
            inbox: ResourcePath::Inbox {
                tenant: tenant.slug.clone(),
                principal: principal.name.clone(),
            },
            outbox: ResourcePath::Outbox {
                tenant: tenant.slug.clone(),
                principal: principal.name.clone(),
            },
            notifications: ResourcePath::Notifications {
                tenant: tenant.slug.clone(),
                principal: principal.name.clone(),
            },
            group_members: paths(self.members_of(principal.id)),
            group_membership: paths(self.groups_of(principal.id)),
        })
    }

    /// The properties of the principal the caller acts as.
    fn current_principal(&self, ctx: &RequestContext) -> AppResult<PrincipalProps> {
        let id = ctx.actor.principal().ok_or_else(AppError::unauthenticated)?;
        let tenant = self.tenant_of(ctx)?;
        let principal = self.principal_by_id(tenant.id, id).ok_or_else(AppError::not_found)?;
        let path = ResourcePath::Principal {
            tenant: tenant.slug.clone(),
            principal: principal.name.clone(),
        };
        self.principal_props(ctx, &path)
    }

    fn classify_address(&self, tenant: TenantId, address: &CalendarUserAddress) -> AppResult<AddressClass> {
        let tenant = self.tenant(tenant).ok_or_else(AppError::not_found)?;
        let internal = self
            .principals
            .values()
            .filter(|principal| principal.tenant_id == tenant.id && principal.status != PrincipalStatus::Deleted)
            .find(|principal| {
                self.calendar_addresses(tenant, principal)
                    .iter()
                    .any(|candidate| candidate == address)
            });
        Ok(match internal {
            Some(principal) => AddressClass::Internal {
                principal: principal.id,
                name: principal.name.clone(),
                kind: principal.kind,
            },
            None if address.email().is_some() => AddressClass::External,
            None => AddressClass::Unresolvable,
        })
    }
}

#[async_trait]
impl PrincipalService for FakePrincipals {
    async fn list(
        &self,
        ctx: &RequestContext,
        filter: PrincipalFilter,
        page: PageRequest,
    ) -> AppResult<Page<PrincipalView>> {
        admin(ctx, AdminOperation::ListPrincipals)?;
        self.state
            .read(|world| world.list_principals(ctx.tenant, &filter, &page))
            .await
    }

    async fn get(&self, ctx: &RequestContext, name: &PrincipalName) -> AppResult<PrincipalView> {
        admin(ctx, AdminOperation::GetPrincipal)?;
        self.state
            .read(|world| {
                let principal = world.require_principal(ctx.tenant, name)?;
                world.view_of(ctx.tenant, principal.id)
            })
            .await
    }

    async fn upsert(
        &self,
        ctx: &RequestContext,
        spec: PrincipalSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<PrincipalView>> {
        admin(ctx, AdminOperation::PutPrincipal)?;
        self.state
            .write(|world| world.upsert_principal(ctx.tenant, spec.name, spec.body, conditions))
            .await
    }

    async fn patch(
        &self,
        ctx: &RequestContext,
        name: &PrincipalName,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<PrincipalView> {
        admin(ctx, AdminOperation::PatchPrincipal)?;
        self.state
            .write(|world| world.patch_principal(ctx.tenant, name, &patch, conditions))
            .await
    }

    async fn delete(&self, ctx: &RequestContext, name: &PrincipalName, options: DeleteOptions) -> AppResult<()> {
        admin(ctx, AdminOperation::DeletePrincipal)?;
        self.state
            .write(|world| world.delete_principal(ctx.tenant, name, options))
            .await
    }

    async fn members(&self, ctx: &RequestContext, group: &PrincipalName) -> AppResult<MembershipSet> {
        admin(ctx, AdminOperation::GetMembers)?;
        self.state
            .read(|world| {
                let group = world.group_of(ctx.tenant, group)?;
                Ok(world.membership_set(ctx.tenant, group.id))
            })
            .await
    }

    async fn set_members(
        &self,
        ctx: &RequestContext,
        group: &PrincipalName,
        members: Vec<PrincipalName>,
    ) -> AppResult<MembershipSet> {
        admin(ctx, AdminOperation::SetMembers)?;
        self.state
            .write(|world| world.set_members(ctx.tenant, group, &members))
            .await
    }

    async fn add_member(&self, ctx: &RequestContext, group: &PrincipalName, member: &PrincipalName) -> AppResult<()> {
        admin(ctx, AdminOperation::AddMember)?;
        self.state
            .write(|world| {
                let group_id = world.group_of(ctx.tenant, group)?.id;
                let member_id = world.member_of(ctx.tenant, member)?;
                world.add_member(group_id, member_id);
                Ok(())
            })
            .await
    }

    async fn remove_member(
        &self,
        ctx: &RequestContext,
        group: &PrincipalName,
        member: &PrincipalName,
    ) -> AppResult<()> {
        admin(ctx, AdminOperation::RemoveMember)?;
        self.state
            .write(|world| {
                let group_id = world.group_of(ctx.tenant, group)?.id;
                let member_id = world.require_principal(ctx.tenant, member)?.id;
                world.members.remove(&(group_id, member_id));
                Ok(())
            })
            .await
    }

    async fn search(&self, ctx: &RequestContext, search: PrincipalSearch) -> AppResult<Vec<PrincipalHit>> {
        Ok(self.find_principals(ctx, search).await?.hits)
    }

    async fn find_principals(&self, ctx: &RequestContext, search: PrincipalSearch) -> AppResult<PrincipalSearchResult> {
        authenticated(ctx)?;
        self.state
            .read(|world| world.search_principals(ctx.tenant, &search))
            .await
    }

    async fn dav_properties(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<PrincipalProps> {
        authenticated(ctx)?;
        self.state.read(|world| world.principal_props(ctx, path)).await
    }

    async fn current(&self, ctx: &RequestContext) -> AppResult<PrincipalProps> {
        authenticated(ctx)?;
        self.state.read(|world| world.current_principal(ctx)).await
    }

    async fn resolve_address(&self, ctx: &RequestContext, address: &CalendarUserAddress) -> AppResult<AddressClass> {
        authenticated(ctx)?;
        self.state
            .read(|world| world.classify_address(ctx.tenant, address))
            .await
    }
}
