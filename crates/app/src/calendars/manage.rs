//! The management API side of calendars: read, list, create-or-replace, patch, delete and the tenant-wide search.

use std::collections::HashMap;

use davhaven_domain::events::CalendarPayload;
use davhaven_domain::{
    AccessFacts, AdminOperation, Calendar, CalendarId, CalendarKind, CalendarSlug, ComponentKind, EventPayload,
    EventType, Operation, Principal, PrincipalKind, PrincipalName, RequestContext, Tenant,
};
use davhaven_ports::{CalendarFilter, PageReq, Tx, TxMode};
use davhaven_wire::{CalendarView, CalendarWrite, Page};

use super::views::Views;
use super::{CalendarServiceImpl, NewCalendar, provision};
use crate::audit::Journal;
use crate::authz::{
    admin, calendar_of, check_color, clean_name, clean_optional_text, enforce_api, facts_for, field_error, found,
    lock_one, principal_by_id, principal_named, require_scope, retrying,
};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::paging;
use crate::services::{CalendarRef, CalendarSearch, CalendarSpec, Conditions, MergePatch, PageRequest, Upserted};

use super::dav::{MAX_DESCRIPTION, MAX_DISPLAY_NAME};

/// The listing names that bind cursors to the calendar lists.
const LISTING_OWNED: &str = "calendars/owned";
const LISTING_TENANT: &str = "calendars";

/// The body of a write after validation.
struct Checked {
    kind: Option<CalendarKind>,
    display_name: String,
    description: Option<String>,
    color: Option<String>,
    sort_order: Option<i32>,
    components: Option<Vec<ComponentKind>>,
}

impl Checked {
    fn of(body: &CalendarWrite) -> AppResult<Self> {
        Ok(Self {
            kind: body.kind,
            display_name: clean_name("/display_name", &body.display_name, MAX_DISPLAY_NAME)?,
            description: clean_optional_text("/description", body.description.as_deref(), MAX_DESCRIPTION)?,
            color: check_color("/color", body.color.as_deref())?,
            sort_order: body.sort_order,
            components: body.components.clone(),
        })
    }
}

/// What one attempt of a write needs besides the transaction.
struct Write<'a> {
    ctx: &'a RequestContext,
    journal: &'a Journal<'a>,
    tenant: &'a Tenant,
    body: &'a Checked,
    /// The component types the calendar will hold.
    components: Vec<ComponentKind>,
}

/// The writable form of a calendar, for merge patches.
fn writable(calendar: &Calendar) -> CalendarWrite {
    CalendarWrite {
        kind: Some(calendar.kind),
        display_name: calendar.display_name.clone(),
        description: calendar.description.clone(),
        color: calendar.color.clone(),
        sort_order: Some(calendar.sort_order),
        components: Some(calendar.components.clone()),
    }
}

pub(super) fn calendar_payload(calendar: &Calendar) -> EventPayload {
    EventPayload::Calendar(CalendarPayload {
        calendar: calendar.id,
        owner: calendar.owner_id,
        kind: calendar.kind,
    })
}

impl CalendarServiceImpl {
    /// Reads a calendar by natural key or id.
    pub(super) async fn read_calendar(&self, ctx: &RequestContext, reference: &CalendarRef) -> AppResult<CalendarView> {
        require_scope(ctx, Operation::ReadCollection)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let calendar = calendar_of(tx.as_mut(), reference).await?;
        let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
        enforce_api(ctx, &facts, Operation::ReadCollection)?;
        let view = Views::new(&self.core, &tenant)
            .calendar_view(tx.as_mut(), &calendar)
            .await?;
        tx.commit().await?;
        Ok(view)
    }

    /// Lists the calendars a principal owns that the caller may read, ordered by id.
    pub(super) async fn list_calendars_of(
        &self,
        ctx: &RequestContext,
        owner: &PrincipalName,
        page: PageRequest,
    ) -> AppResult<Page<CalendarView>> {
        require_scope(ctx, Operation::ReadCollection)?;
        let listing = format!("{LISTING_OWNED}/{owner}");
        let request: PageReq = paging::page_request(&self.core, ctx, &listing, &page)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let owner = principal_named(tx.as_mut(), owner).await?;
        // The owner's calendars come in id order; the page is cut after the permission filter so that calendars the
        // caller cannot see never show up as gaps.
        let calendars = tx.calendars().list_owned(owner.id).await?;
        let mut views = Views::for_listing(&self.core, &tenant);
        let limit = usize::try_from(request.effective_limit()).unwrap_or(usize::MAX);
        let mut items = Vec::new();
        let mut more = false;
        let candidates: Vec<&Calendar> = calendars
            .iter()
            .filter(|calendar| request.after.is_none_or(|after| calendar.id.as_uuid() > after))
            .collect();
        // One load of the facts of all of them, not one per calendar.
        let ids: Vec<CalendarId> = candidates.iter().map(|calendar| calendar.id).collect();
        let facts: HashMap<CalendarId, AccessFacts> = tx
            .calendars()
            .access_facts_many(&ids, ctx.principal())
            .await?
            .into_iter()
            .collect();
        for calendar in candidates {
            let Some(facts) = facts.get(&calendar.id) else {
                continue;
            };
            if enforce_api(ctx, facts, Operation::ReadCollection).is_err() {
                continue;
            }
            if items.len() == limit {
                more = true;
                break;
            }
            items.push((calendar.id.as_uuid(), views.calendar_view(tx.as_mut(), calendar).await?));
        }
        tx.commit().await?;
        let next = if more {
            paging::next_cursor(&self.core, ctx, &listing, items.last().map(|(id, _)| *id))?
        } else {
            None
        };
        Ok(Page::new(items.into_iter().map(|(_, view)| view).collect(), next))
    }

    /// Searches the calendars of the tenant.
    pub(super) async fn search_calendars(
        &self,
        ctx: &RequestContext,
        search: CalendarSearch,
        page: PageRequest,
    ) -> AppResult<Page<CalendarView>> {
        admin(ctx, AdminOperation::SearchCalendars)?;
        let request: PageReq = paging::page_request(&self.core, ctx, LISTING_TENANT, &page)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let owner = match &search.owner {
            Some(name) => Some(principal_named(tx.as_mut(), name).await?.id),
            None => None,
        };
        let filter = CalendarFilter {
            owner,
            kind: search.kind,
            slug: None,
            text: search.query.filter(|text| !text.trim().is_empty()),
        };
        let rows = tx.calendars().list(&filter, request).await?;
        let next = paging::next_cursor(&self.core, ctx, LISTING_TENANT, rows.next)?;
        let mut views = Views::for_listing(&self.core, &tenant);
        // A search lists calendars of many owners: read them and their collections once, not one owner at a time.
        let listed: Vec<&Calendar> = rows.items.iter().collect();
        views.prime(tx.as_mut(), &listed).await?;
        let mut items = Vec::with_capacity(rows.items.len());
        for calendar in &rows.items {
            items.push(views.calendar_view(tx.as_mut(), calendar).await?);
        }
        tx.commit().await?;
        Ok(Page::new(items, next))
    }

    /// Creates or replaces a calendar.
    pub(super) async fn upsert_calendar(
        &self,
        ctx: &RequestContext,
        spec: CalendarSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<CalendarView>> {
        require_scope(ctx, Operation::UpdateCalendar)?;
        let checked = Checked::of(&spec.body)?;
        retrying(conditions == Conditions::none(), || {
            self.upsert_once(ctx, &spec.owner, &spec.slug, &checked, conditions, false)
        })
        .await
    }

    async fn upsert_once(
        &self,
        ctx: &RequestContext,
        owner: &PrincipalName,
        slug: &CalendarSlug,
        body: &Checked,
        conditions: Conditions,
        must_exist: bool,
    ) -> AppResult<Upserted<CalendarView>> {
        let journal = Journal::new(&self.core, ctx);
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let tenant = tx.tenant().get().await?;
        let owner = principal_named(tx.as_mut(), owner).await?;
        let existing = found(tx.calendars().get_by_slug(owner.id, slug).await)?;
        if must_exist && existing.is_none() {
            return Err(AppError::not_found());
        }
        // The caller's right to see the calendar is decided before anything else is said about it: a stale
        // `If-Match`, `If-None-Match: *` or a body that does not fit the stored calendar would otherwise tell a
        // stranger whether the calendar exists (PLAN 2.6: what the caller may not see is `404`).
        let facts = if let Some(current) = &existing {
            let facts = facts_for(tx.as_mut(), ctx, current.id).await?;
            enforce_api(ctx, &facts, Operation::UpdateCalendar)?;
            Some(facts)
        } else {
            let mut facts = crate::authz::home_facts(&tenant, &owner);
            facts.calendar_kind = body.kind.unwrap_or(CalendarKind::User);
            enforce_api(ctx, &facts, Operation::CreateCalendar)?;
            None
        };
        conditions.check(existing.as_ref().map(|calendar| calendar.version))?;
        let allowed = &tenant.settings.allowed_components;
        let components = match (&body.components, &existing) {
            (Some(components), _) => components.clone(),
            (None, Some(calendar)) => calendar.components.clone(),
            (None, None) => allowed.clone(),
        };
        if components.is_empty() || components.iter().any(|component| !allowed.contains(component)) {
            return Err(field_error(
                "/components",
                "not-allowed",
                "The calendar cannot hold these component types.",
            ));
        }
        let write = Write {
            ctx,
            journal: &journal,
            tenant: &tenant,
            body,
            components,
        };
        let upserted = match (existing, facts) {
            (Some(current), Some(facts)) => self.replace_calendar(&write, tx.as_mut(), current, &facts).await?,
            _ => self.create_calendar(&write, tx.as_mut(), &owner, slug).await?,
        };
        tx.commit().await?;
        Ok(upserted)
    }

    /// Replaces the writable fields of an existing calendar; the same body again changes nothing.
    async fn replace_calendar(
        &self,
        write: &Write<'_>,
        tx: &mut dyn Tx,
        current: Calendar,
        facts: &AccessFacts,
    ) -> AppResult<Upserted<CalendarView>> {
        let (ctx, body) = (write.ctx, write.body);
        if body.kind.is_some_and(|kind| kind != current.kind) {
            return Err(field_error(
                "/kind",
                "immutable",
                "The kind of a calendar cannot change.",
            ));
        }
        let updated = Calendar {
            display_name: body.display_name.clone(),
            description: body.description.clone(),
            color: body.color.clone(),
            sort_order: body.sort_order.unwrap_or(0),
            components: write.components.clone(),
            ..current.clone()
        };
        let mut views = Views::new(&self.core, write.tenant);
        if updated == current {
            let view = views.calendar_view(tx, &current).await?;
            return Ok(Upserted::replaced(view));
        }
        if updated.display_name != current.display_name {
            enforce_api(ctx, facts, Operation::RenameCalendar)?;
        }
        let stored = tx.calendars().update(updated, current.version).await?;
        write
            .journal
            .publish(tx, EventType::CalendarUpdated, calendar_payload(&stored))
            .await?;
        let view = views.calendar_view(tx, &stored).await?;
        Ok(Upserted::replaced(view))
    }

    /// Creates a calendar of `owner` with the binding of its owner.
    async fn create_calendar(
        &self,
        write: &Write<'_>,
        tx: &mut dyn Tx,
        owner: &Principal,
        slug: &CalendarSlug,
    ) -> AppResult<Upserted<CalendarView>> {
        let body = write.body;
        let kind = body.kind.unwrap_or(CalendarKind::User);
        // The right to create in this home was decided before the conditions; what is left are the rules about
        // what can be created.
        if matches!(kind, CalendarKind::Personal | CalendarKind::Mirror) {
            return Err(field_error(
                "/kind",
                "not-allowed",
                "Personal calendars are created with their user and mirror calendars by the sync engine.",
            ));
        }
        if (kind == CalendarKind::Group) != (owner.kind == PrincipalKind::Group) {
            return Err(field_error(
                "/kind",
                "owner-mismatch",
                "Group calendars belong to groups, and groups own only group calendars.",
            ));
        }
        let (calendar, _binding) = provision(
            &self.core,
            tx,
            owner,
            NewCalendar {
                slug: slug.clone(),
                kind,
                display_name: body.display_name.clone(),
                description: body.description.clone(),
                color: body.color.clone(),
                sort_order: body.sort_order.unwrap_or(0),
                components: write.components.clone(),
                timezone_ics: None,
                schedule_transp: None,
            },
        )
        .await?;
        write
            .journal
            .publish(tx, EventType::CalendarCreated, calendar_payload(&calendar))
            .await?;
        let view = Views::new(&self.core, write.tenant)
            .calendar_view(tx, &calendar)
            .await?;
        Ok(Upserted::created(view))
    }
    /// Changes a calendar with a merge patch.
    pub(super) async fn patch_calendar(
        &self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<CalendarView> {
        require_scope(ctx, Operation::UpdateCalendar)?;
        let upserted = retrying(conditions == Conditions::none(), || async {
            let (current, owner) = {
                let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
                let current = calendar_of(tx.as_mut(), reference).await?;
                // Decided before the version is compared or the patch is applied: a stranger learns neither.
                let facts = facts_for(tx.as_mut(), ctx, current.id).await?;
                enforce_api(ctx, &facts, Operation::UpdateCalendar)?;
                let owner = principal_by_id(tx.as_mut(), current.owner_id).await?;
                tx.commit().await?;
                (current, owner)
            };
            conditions.check(Some(current.version))?;
            let mut document = serde_json::to_value(writable(&current)).map_err(AppError::internal)?;
            patch.apply(&mut document);
            let body: CalendarWrite = serde_json::from_value(document)
                .map_err(|_| AppError::invalid(SafeMessage::from_static("The patched calendar is not valid.")))?;
            let checked = Checked::of(&body)?;
            self.upsert_once(
                ctx,
                &owner.name,
                &current.slug,
                &checked,
                Conditions::if_match(current.version),
                true,
            )
            .await
            .map_err(|error| {
                if error.kind() == davhaven_domain::ErrorKind::PreconditionFailed {
                    AppError::from(davhaven_ports::StoreError::PreconditionFailed)
                } else {
                    error
                }
            })
        })
        .await?;
        Ok(upserted.value)
    }

    /// Deletes a calendar for everyone.
    pub(super) async fn delete_calendar(
        &self,
        ctx: &RequestContext,
        reference: &CalendarRef,
        conditions: Conditions,
    ) -> AppResult<()> {
        require_scope(ctx, Operation::DeleteCalendar)?;
        let expected = conditions.require_if_match()?;
        retrying(false, || async {
            let journal = Journal::new(&self.core, ctx);
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
            let calendar = calendar_of(tx.as_mut(), reference).await?;
            let calendar = lock_one(tx.as_mut(), calendar.id).await?;
            let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
            enforce_api(ctx, &facts, Operation::DeleteCalendar)?;
            if calendar.version != expected {
                return Err(AppError::precondition_failed());
            }
            tx.calendars().soft_delete(calendar.id, calendar.version).await?;
            journal
                .publish(tx.as_mut(), EventType::CalendarDeleted, calendar_payload(&calendar))
                .await?;
            tx.commit().await?;
            Ok(())
        })
        .await
    }
}
