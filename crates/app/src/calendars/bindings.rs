//! The management API's view of a home: the bindings of a principal, hidden ones included, and their restoration.
//!
//! A principal who deletes a shared calendar (a group calendar, a managed one, a calendar of someone else) in a
//! calendar app hides the binding of their home; the calendar and the grant stay (PLAN 2.9). Nothing in a calendar app
//! brings it back, so the operator needs a way to see and to undo it: [`CalendarServiceImpl::list_bindings_of`] lists
//! the bindings of a principal with their state and [`CalendarServiceImpl::restore_binding_of`] shows a hidden one again.
//! Whether the principal can remove a calendar at all is the business of the `required` flag of grants
//! (`domain::binding_required`); the listing reports it.
//!
//! The listing is what the calendar apps of the principal can list: a binding of a calendar the principal has no access to
//! any more (a removed group member, a revoked grant) stays in the store but is not in the home, and neither the listing nor
//! the restoration knows it. A calendar the principal reaches through a group or a managed grant has a binding from their
//! first listing of the home on (PLAN 2.9), so the listing holds the bindings created so far.

use std::collections::HashMap;

use davhaven_domain::audit::BindingAudit;
use davhaven_domain::{
    AdminOperation, AuditEvent, Binding, BindingId, Calendar, CalendarSlug, Principal, PrincipalId, PrincipalName,
    RequestContext, ResourcePath, Tenant, binding_required, effective_access,
};
use davhaven_ports::{BoundCalendar, PageReq, TxMode};
use davhaven_wire::{HomeBindingView, Page};

use super::CalendarServiceImpl;
use crate::audit::Journal;
use crate::authz::{admin, lock_one, principal_named, retrying};
use crate::error::{AppError, AppResult};
use crate::paging;
use crate::services::{BindingFilter, PageRequest};

/// The state of the filter in the name of the listing, so that a cursor of one listing is refused by another.
const fn filter_label(filter: BindingFilter) -> &'static str {
    match filter.hidden {
        None => "all",
        Some(true) => "hidden",
        Some(false) => "visible",
    }
}

/// The view of a binding in the home of `principal`.
fn view_of(
    core: &crate::wiring::AppCore,
    tenant: &Tenant,
    principal: &Principal,
    owner: &PrincipalName,
    bound: &Binding,
    calendar: &Calendar,
    required: bool,
) -> HomeBindingView {
    let path = ResourcePath::Collection {
        tenant: tenant.slug.clone(),
        principal: principal.name.clone(),
        binding: bound.slug.clone(),
    };
    HomeBindingView {
        id: bound.id,
        principal: principal.name.clone(),
        slug: bound.slug.clone(),
        calendar_id: calendar.id,
        owner: owner.clone(),
        calendar: calendar.slug.clone(),
        kind: calendar.kind,
        display_name: bound
            .display_name
            .clone()
            .unwrap_or_else(|| calendar.display_name.clone()),
        hidden: bound.hidden,
        required,
        dav_url: core.deps().urls.for_tenant(&tenant.settings).dav_url(&path),
        created_at: bound.created_at,
        updated_at: bound.updated_at,
        version: bound.version,
    }
}

impl CalendarServiceImpl {
    /// Lists the bindings of a principal's home, hidden ones included, ordered by binding id.
    pub(super) async fn list_bindings_of(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        filter: BindingFilter,
        page: PageRequest,
    ) -> AppResult<Page<HomeBindingView>> {
        admin(ctx, AdminOperation::ListBindings)?;
        let listing = format!("bindings/{principal}/{}", filter_label(filter));
        let request: PageReq = paging::page_request(&self.core, ctx, &listing, &page)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let principal = principal_named(tx.as_mut(), principal).await?;
        let limit = usize::try_from(request.effective_limit()).unwrap_or(usize::MAX);
        let bound: Vec<BoundCalendar> = tx
            .bindings()
            .list_for(principal.id)
            .await?
            .into_iter()
            .filter(|entry| filter.hidden.is_none_or(|hidden| entry.binding.hidden == hidden))
            .filter(|entry| request.after.is_none_or(|after| entry.binding.id.as_uuid() > after))
            .collect();
        let more = bound.len() > limit;
        let shown: Vec<&BoundCalendar> = bound.iter().take(limit).collect();
        let calendar_ids: Vec<_> = shown.iter().map(|entry| entry.calendar.id).collect();
        let facts: HashMap<_, _> = tx
            .calendars()
            .access_facts_many(&calendar_ids, Some(principal.id))
            .await?
            .into_iter()
            .collect();
        let owner_ids: Vec<PrincipalId> = shown.iter().map(|entry| entry.calendar.owner_id).collect();
        let owners: HashMap<PrincipalId, PrincipalName> = tx
            .principals()
            .get_many(&owner_ids)
            .await?
            .into_iter()
            .map(|owner| (owner.id, owner.name))
            .collect();
        tx.commit().await?;
        let mut items = Vec::with_capacity(shown.len());
        let mut last: Option<BindingId> = None;
        for entry in shown {
            last = Some(entry.binding.id);
            // The owner of a calendar that is gone for good takes its calendars along; the listing does not stumble.
            let Some(owner) = owners.get(&entry.calendar.owner_id) else {
                continue;
            };
            // A calendar the principal has no access to any more is not in their home: the listing says what their calendar
            // apps list, as the home does.
            let Some(facts) = facts.get(&entry.calendar.id) else {
                continue;
            };
            if effective_access(principal.id, facts).is_none() {
                continue;
            }
            let required = binding_required(principal.id, facts);
            items.push(view_of(
                &self.core,
                &tenant,
                &principal,
                owner,
                &entry.binding,
                &entry.calendar,
                required,
            ));
        }
        let next = if more {
            paging::next_cursor(&self.core, ctx, &listing, last.map(BindingId::as_uuid))?
        } else {
            None
        };
        Ok(Page::new(items, next))
    }

    /// Shows a hidden binding in the home again. Restoring a binding that is visible changes nothing.
    pub(super) async fn restore_binding_of(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        binding: &CalendarSlug,
    ) -> AppResult<HomeBindingView> {
        admin(ctx, AdminOperation::RestoreBinding)?;
        retrying(false, || self.restore_once(ctx, principal, binding)).await
    }

    async fn restore_once(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        slug: &CalendarSlug,
    ) -> AppResult<HomeBindingView> {
        let journal = Journal::new(&self.core, ctx);
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let tenant = tx.tenant().get().await?;
        let principal = principal_named(tx.as_mut(), principal).await?;
        let found = tx.bindings().get_by_slug(principal.id, slug).await?;
        // The calendar is locked like for every change of a binding, and a calendar that is gone has no binding to show.
        let calendar = lock_one(tx.as_mut(), found.calendar_id).await?;
        let facts = tx.calendars().access_facts(calendar.id, Some(principal.id)).await?;
        // A calendar the principal has no access to any more is not in their home and cannot be put there: the binding is
        // as good as gone, which is what the listing says as well.
        if effective_access(principal.id, &facts).is_none() {
            return Err(AppError::not_found());
        }
        let shown = if found.hidden {
            let version = found.version;
            let restored = BindingAudit {
                principal: principal.id,
                calendar: calendar.id,
                binding: found.id,
            };
            let shown = tx
                .bindings()
                .update(Binding { hidden: false, ..found }, version)
                .await?;
            journal
                .audit(tx.as_mut(), AuditEvent::BindingRestored(restored))
                .await?;
            tx.calendars().touch(calendar.id).await?;
            shown
        } else {
            found
        };
        let owner = tx.principals().get(calendar.owner_id).await?;
        let required = binding_required(principal.id, &facts);
        let view = view_of(
            &self.core,
            &tenant,
            &principal,
            &owner.name,
            &shown,
            &calendar,
            required,
        );
        tx.commit().await?;
        Ok(view)
    }
}
