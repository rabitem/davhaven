//! The management API side of sharing: grants of a calendar.

use std::collections::HashSet;

use davhaven_domain::audit::BindingAudit;
use davhaven_domain::{
    Actor, AuditEvent, Binding, Calendar, Channel, ErrorKind, EventType, Grant, GrantAccess, GrantId, GrantSource,
    GrantStatus, Operation, Principal, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus, RequestContext,
};
use davhaven_ports::{PageReq, Tx, TxMode};
use davhaven_wire::{GrantView, GrantWrite, Page};

use super::{SharingServiceImpl, grant_audit, grant_payload};
use crate::audit::Journal;
use crate::authz::{
    calendar_of, enforce_api, facts_for, field_error, lock_one, principal_named, require_scope, retrying,
};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::paging;
use crate::services::{CalendarRef, Conditions, GrantSpec, PageRequest, Upserted};

/// The view of a grant; `calendar` and `grantee` are the natural keys the path of the grant uses.
fn view(grant: &Grant, calendar: &Calendar, grantee: &PrincipalName) -> GrantView {
    GrantView {
        id: grant.id,
        calendar_id: grant.calendar_id,
        calendar: calendar.slug.clone(),
        grantee_id: grant.grantee_id,
        grantee: grantee.clone(),
        access: grant.access,
        status: grant.status,
        source: grant.source,
        required: grant.required,
        created_at: grant.created_at,
        updated_at: grant.updated_at,
        version: grant.version,
    }
}

/// Removes the pending invitation of a grant from the grantee's notification collection, if it is still there.
pub(crate) async fn drop_invitation(tx: &mut dyn Tx, grant: &Grant) -> AppResult<()> {
    if let Some(uid) = &grant.invite_uid
        && let Some(notification) = tx.notifications().find_by_uid(grant.grantee_id, uid).await?
    {
        tx.notifications().delete(notification.id).await?;
    }
    Ok(())
}

/// Shows again the bindings that `people` hid on `calendar` and audits each one (`binding.restored`); returns how many came
/// back. A required calendar is always in the home of its people, so a binding that was hidden while the calendar was
/// optional, or before its owner joined the group the calendar is required for, comes back when the two meet: when the
/// grant is put ([`restore_for_grant`]) and when somebody joins the grantee group ([`restore_for_new_members`]).
async fn unhide_bindings(
    tx: &mut dyn Tx,
    journal: &Journal<'_>,
    calendar: &Calendar,
    people: &HashSet<PrincipalId>,
) -> AppResult<usize> {
    if people.is_empty() {
        return Ok(0);
    }
    let hidden: Vec<Binding> = tx
        .bindings()
        .list_for_calendar(calendar.id)
        .await?
        .into_iter()
        .filter(|binding| binding.hidden && people.contains(&binding.principal_id))
        .collect();
    let count = hidden.len();
    for binding in hidden {
        let version = binding.version;
        let restored = BindingAudit {
            principal: binding.principal_id,
            calendar: calendar.id,
            binding: binding.id,
        };
        tx.bindings()
            .update(
                Binding {
                    hidden: false,
                    ..binding
                },
                version,
            )
            .await?;
        journal.audit(tx, AuditEvent::BindingRestored(restored)).await?;
    }
    Ok(count)
}

/// Shows again what the people a required grant reaches had hidden on its calendar. They are the grantee, or the current
/// members of a grantee group. The calendar is locked by the caller.
async fn restore_for_grant(
    tx: &mut dyn Tx,
    journal: &Journal<'_>,
    calendar: &Calendar,
    grantee: &Principal,
) -> AppResult<usize> {
    let reached: HashSet<PrincipalId> = if grantee.kind == PrincipalKind::Group {
        tx.memberships().members(grantee.id).await?.into_iter().collect()
    } else {
        HashSet::from([grantee.id])
    };
    unhide_bindings(tx, journal, calendar, &reached).await
}

/// Shows again what new members of `group` had hidden on the calendars that are required for the group: somebody who hid an
/// optional calendar, and then joins the group the calendar is required for, finds it in their home again. Called by the
/// membership changes in their transaction; the calendars are locked in ascending id order like every writer of bindings.
///
/// # Errors
///
/// Store failures only.
pub(crate) async fn restore_for_new_members(
    tx: &mut dyn Tx,
    journal: &Journal<'_>,
    group: PrincipalId,
    added: &[PrincipalId],
) -> AppResult<()> {
    if added.is_empty() {
        return Ok(());
    }
    let mut calendars: Vec<_> = tx
        .grants()
        .for_grantee(group)
        .await?
        .into_iter()
        .filter(|grant| grant.required && grant.status == GrantStatus::Accepted)
        .map(|grant| grant.calendar_id)
        .collect();
    calendars.sort_unstable();
    calendars.dedup();
    let people: HashSet<PrincipalId> = added.iter().copied().collect();
    for id in calendars {
        // A calendar that is gone has no binding to show.
        let calendar = match lock_one(tx, id).await {
            Ok(calendar) => calendar,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if unhide_bindings(tx, journal, &calendar, &people).await? > 0 {
            tx.calendars().touch(calendar.id).await?;
        }
    }
    Ok(())
}

/// The rules of a grant that do not depend on what is stored: who may be granted, who may grant a group its own calendar, and
/// who may ask for `required`.
fn check_who_gets_what(
    ctx: &RequestContext,
    calendar: &Calendar,
    grantee: &Principal,
    body: &GrantWrite,
) -> AppResult<()> {
    if !matches!(
        grantee.kind,
        PrincipalKind::User | PrincipalKind::Group | PrincipalKind::Service
    ) {
        return Err(field_error(
            "/grantee",
            "not-allowed",
            "Calendars are shared with users, groups and service principals.",
        ));
    }
    // The owner has access to the calendar already. The one exception is a group that owns its calendar: the members get the
    // group's default access without a grant, and a grant for the group itself is how the calendar is marked as required for
    // them. It carries no access of its own, so it is `read` (the floor of every grant, which cannot add to what the group's
    // default gives the members) and the operator's alone.
    let own_group = grantee.id == calendar.owner_id;
    if own_group && grantee.kind != PrincipalKind::Group {
        return Err(field_error(
            "/grantee",
            "owner",
            "The owner of a calendar has access to it already.",
        ));
    }
    let operator = is_operator(ctx);
    if own_group {
        if !operator {
            return Err(AppError::forbidden().with_field_error(
                "/grantee",
                "not-allowed",
                SafeMessage::from_static("Only a tenant administrator grants a group its own calendar."),
            ));
        }
        if body.access != GrantAccess::Read {
            return Err(field_error(
                "/access",
                "not-allowed",
                "A group's grant on its own calendar only marks it as required: its access is read.",
            ));
        }
    }
    // The flag is the operator's. A principal cannot ask for it, and a grant they put again keeps the flag it has (a body
    // without it must not switch an operator's flag off).
    if !operator && body.required {
        return Err(AppError::forbidden().with_field_error(
            "/required",
            "not-allowed",
            SafeMessage::from_static("Only a tenant administrator makes a calendar required."),
        ));
    }
    Ok(())
}

/// Whether the caller is the operator: a tenant token, or server-originated work (the internal channel, which authentication
/// never produces). The `required` flag is the operator's: a principal that shares a calendar through the API (the owner, an
/// admin sharee, the service principal that owns a managed calendar) cannot put calendars into the home of other people for
/// good (PLAN 2.9).
const fn is_operator(ctx: &RequestContext) -> bool {
    matches!(ctx.actor, Actor::TenantToken(_)) || matches!(ctx.channel, Channel::Internal)
}

impl SharingServiceImpl {
    /// Lists the grants of a calendar, ordered by id.
    pub(super) async fn grants_of(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        page: PageRequest,
    ) -> AppResult<Page<GrantView>> {
        require_scope(ctx, Operation::ListGrants)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let calendar = calendar_of(tx.as_mut(), calendar).await?;
        let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
        enforce_api(ctx, &facts, Operation::ListGrants)?;
        let listing = format!("grants/{}", calendar.id);
        let request: PageReq = paging::page_request(&self.core, ctx, &listing, &page)?;
        let limit = usize::try_from(request.effective_limit()).unwrap_or(usize::MAX);
        let grants = tx.grants().for_calendar(calendar.id).await?;
        let mut rest = grants
            .iter()
            .filter(|grant| request.after.is_none_or(|after| grant.id.as_uuid() > after));
        let page: Vec<&Grant> = rest.by_ref().take(limit).collect();
        let ids: Vec<_> = page.iter().map(|grant| grant.grantee_id).collect();
        let grantees: std::collections::HashMap<_, _> = tx
            .principals()
            .get_many(&ids)
            .await?
            .into_iter()
            .map(|grantee| (grantee.id, grantee.name))
            .collect();
        tx.commit().await?;
        let mut items = Vec::with_capacity(page.len());
        let mut last = None;
        for grant in page {
            // A grantee that is gone for good takes its grant along; the listing does not stumble over it.
            if let Some(name) = grantees.get(&grant.grantee_id) {
                items.push(view(grant, &calendar, name));
            }
            last = Some(grant.id.as_uuid());
        }
        let more = rest.next().is_some();
        let next = if more {
            paging::next_cursor(&self.core, ctx, &listing, last)?
        } else {
            None
        };
        Ok(Page::new(items, next))
    }

    /// Creates or replaces the grant of one grantee; API grants are effective at once.
    pub(super) async fn upsert_grant(
        &self,
        ctx: &RequestContext,
        spec: GrantSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<GrantView>> {
        require_scope(ctx, Operation::PutGrant)?;
        retrying(conditions == Conditions::none(), || {
            self.put_once(ctx, &spec, conditions)
        })
        .await
    }

    async fn put_once(
        &self,
        ctx: &RequestContext,
        spec: &GrantSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<GrantView>> {
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let calendar = calendar_of(tx.as_mut(), &spec.calendar).await?;
        let calendar = lock_one(tx.as_mut(), calendar.id).await?;
        let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
        enforce_api(ctx, &facts, Operation::PutGrant)?;
        // A principal that shares through the API follows the switches of sharing like a client does through DAV; a
        // tenant token administers access whatever they say (PLAN 2.9).
        if ctx.actor.principal().is_some() && !(deps.config.sharing.enabled && facts.tenant_settings.sharing.enabled) {
            return Err(AppError::feature_not_enabled()
                .with_public_message(SafeMessage::from_static("Sharing is not enabled.")));
        }
        let grantee = principal_named(tx.as_mut(), &spec.grantee).await?;
        check_who_gets_what(ctx, &calendar, &grantee, &spec.body)?;
        let operator = is_operator(ctx);
        let existing = tx.grants().find(calendar.id, grantee.id).await?;
        conditions.check(existing.as_ref().map(|grant| grant.version))?;
        let required = if operator {
            spec.body.required
        } else {
            existing.as_ref().is_some_and(|grant| grant.required)
        };
        let now = deps.clock.now();
        let mut changed = true;
        let (stored, created) = match existing {
            None => {
                let grant = Grant {
                    id: GrantId::from_uuid(deps.ids.new_id()),
                    tenant_id: ctx.tenant,
                    calendar_id: calendar.id,
                    grantee_id: grantee.id,
                    access: spec.body.access,
                    status: GrantStatus::Accepted,
                    source: GrantSource::Api,
                    required,
                    invite_uid: None,
                    summary: None,
                    common_name: None,
                    created_at: now,
                    updated_at: now,
                    version: 1,
                };
                let stored = tx.grants().create(grant).await?;
                journal
                    .audit(tx.as_mut(), AuditEvent::GrantCreated(grant_audit(&stored, true)))
                    .await?;
                journal
                    .publish(tx.as_mut(), EventType::GrantCreated, grant_payload(&stored))
                    .await?;
                (stored, true)
            }
            Some(current) => {
                let updated = Grant {
                    access: spec.body.access,
                    status: GrantStatus::Accepted,
                    source: GrantSource::Api,
                    required,
                    ..current.clone()
                };
                if updated == current {
                    // Nothing to store. A grant that is required still brings back what its people hid since (below).
                    changed = false;
                    (current, false)
                } else {
                    let stored = tx.grants().update(updated, current.version).await?;
                    // An invitation that is still waiting is answered by the API: the sharee needs no notification.
                    drop_invitation(tx.as_mut(), &current).await?;
                    journal
                        .audit(tx.as_mut(), AuditEvent::GrantUpdated(grant_audit(&stored, true)))
                        .await?;
                    journal
                        .publish(tx.as_mut(), EventType::GrantUpdated, grant_payload(&stored))
                        .await?;
                    (stored, false)
                }
            }
        };
        let restored = if stored.required {
            restore_for_grant(tx.as_mut(), &journal, &calendar, &grantee).await?
        } else {
            0
        };
        if !changed && restored == 0 {
            tx.commit().await?;
            return Ok(Upserted::replaced(view(&stored, &calendar, &grantee.name)));
        }
        tx.calendars().touch(calendar.id).await?;
        tx.commit().await?;
        let view = view(&stored, &calendar, &grantee.name);
        Ok(if created {
            Upserted::created(view)
        } else {
            Upserted::replaced(view)
        })
    }

    /// Removes the grant of one grantee.
    pub(super) async fn remove_grant(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        grantee: &PrincipalName,
        conditions: Conditions,
    ) -> AppResult<()> {
        require_scope(ctx, Operation::DeleteGrant)?;
        retrying(false, || async {
            let journal = Journal::new(&self.core, ctx);
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
            let calendar = calendar_of(tx.as_mut(), calendar).await?;
            let calendar = lock_one(tx.as_mut(), calendar.id).await?;
            let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
            enforce_api(ctx, &facts, Operation::DeleteGrant)?;
            // The grantee may have been deleted already; the grant is removed all the same.
            let grantee = tx.principals().get_by_name(grantee).await?;
            let grant = tx
                .grants()
                .find(calendar.id, grantee.id)
                .await?
                .ok_or_else(AppError::not_found)?;
            conditions.check(Some(grant.version))?;
            // A grant that makes a calendar required is the operator's to remove, like it is to set.
            if grant.required && !is_operator(ctx) {
                return Err(AppError::forbidden().with_public_message(SafeMessage::from_static(
                    "Only a tenant administrator removes a grant that makes a calendar required.",
                )));
            }
            // The binding of a grantee goes with the grant, except the owner's: a group that was granted its own calendar
            // (to make it required for its members) keeps the binding that the calendar was created with.
            if grantee.status != PrincipalStatus::Deleted
                && grantee.id != calendar.owner_id
                && let Some(binding) = tx.bindings().find_for_calendar(grantee.id, calendar.id).await?
            {
                tx.bindings().delete(binding.id).await?;
            }
            drop_invitation(tx.as_mut(), &grant).await?;
            tx.grants().delete(grant.id).await?;
            journal
                .audit(tx.as_mut(), AuditEvent::GrantDeleted(grant_audit(&grant, false)))
                .await?;
            journal
                .publish(tx.as_mut(), EventType::GrantDeleted, grant_payload(&grant))
                .await?;
            tx.calendars().touch(calendar.id).await?;
            tx.commit().await?;
            Ok(())
        })
        .await
    }
}
