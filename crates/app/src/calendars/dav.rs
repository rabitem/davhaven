//! The DAV side of calendars: homes, collections, MKCALENDAR and the deletion of bound collections.

use std::collections::{BTreeMap, HashMap, HashSet};

use davhaven_domain::events::CalendarPayload;
use davhaven_domain::{
    Access, AccessFacts, Binding, BindingId, Calendar, CalendarId, CalendarKind, CalendarUserAddress, CollectionKey,
    CollectionKind, Decision, ErrorKind, EventPayload, EventType, Grant, GrantSource, GrantStatus, Operation,
    Principal, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus, RequestContext, ResourceKind, ResourcePath,
    TenantSlug, decide, effective_access, privileges,
};
use davhaven_ical::ErrorContext;
use davhaven_ports::{BoundCalendar, CollectionProperty, PropertyScope, StoreError, Tx, TxMode, UniqueKey};

use super::views::{Views, free_binding_slug};
use super::{CalendarServiceImpl, NewCalendar, provision};
use crate::audit::Journal;
use crate::authz::{
    Home, blocking, check_color, clean_name, clean_optional_text, enforce, facts_for, found, home_facts, home_of,
    invalid, lock_one, require_scope, resolve_home, retrying,
};
use crate::error::{AppError, AppResult};
use crate::services::{
    BindingView, CollectionView, Conditions, DeadProperty, HomeDetail, InviteView, MkCalendar, PropertyName,
};

/// The longest display name of a calendar.
pub(super) const MAX_DISPLAY_NAME: usize = 255;

/// The longest description of a calendar.
pub(super) const MAX_DESCRIPTION: usize = 4096;

/// The calendars of a home as views, with the authorization facts of the home's principal that they were built from.
struct HomeListing {
    views: Vec<BindingView>,
    facts: HashMap<CalendarId, AccessFacts>,
}

/// The home a listing reads: the one the path names when there is a path, else the one of the principal's name.
async fn home_for_listing(
    tx: &mut dyn Tx,
    ctx: &RequestContext,
    tenant: Option<&TenantSlug>,
    principal: &PrincipalName,
) -> AppResult<Home> {
    match tenant {
        Some(slug) => resolve_home(tx, ctx, slug, principal).await,
        None => home_of(tx, ctx, principal).await,
    }
}

/// The dead properties as a list, ordered by namespace and name.
fn dead_property_list(properties: BTreeMap<(String, String), String>) -> Vec<DeadProperty> {
    properties
        .into_iter()
        .map(|((namespace, local), value_xml)| DeadProperty {
            name: PropertyName { namespace, local },
            value_xml,
        })
        .collect()
}

/// The invitations of a calendar as `CS:invite` lists them, from its grants and the principals they name. Deleted
/// principals and service principals are left out: the latter are grantees of the management API only (PLAN 2.9).
fn invite_views<'a>(
    grants: impl IntoIterator<Item = &'a Grant>,
    grantees: &HashMap<PrincipalId, Principal>,
) -> Vec<InviteView> {
    let mut invites = Vec::new();
    for grant in grants {
        let Some(grantee) = grantees.get(&grant.grantee_id) else {
            continue;
        };
        if grantee.status == PrincipalStatus::Deleted || grantee.kind == PrincipalKind::Service {
            continue;
        }
        let address = grantee.email.as_ref().map_or_else(
            || CalendarUserAddress::urn_uuid(grantee.id),
            CalendarUserAddress::mailto,
        );
        invites.push(InviteView {
            address,
            common_name: grant.common_name.clone().or(Some(grantee.display_name.clone())),
            access: grant.access,
            status: grant.status,
            summary: grant.summary.clone(),
        });
    }
    invites
}

/// A request to create a calendar after validation.
struct Checked {
    display_name: Option<String>,
    description: Option<String>,
    color: Option<String>,
    components: Option<Vec<davhaven_domain::ComponentKind>>,
}

impl CalendarServiceImpl {
    /// The calendars of a home. Bindings of calendars the principal sees through a group, a managed calendar or an
    /// API grant are created on the first listing (PLAN 2.9).
    pub(super) async fn home_listing(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
    ) -> AppResult<Vec<BindingView>> {
        require_scope(ctx, Operation::ReadCollection)?;
        let (mut tx, home) = self.open_home(ctx, None, principal).await?;
        let listing = self.render_home(tx.as_mut(), &home).await?;
        tx.commit().await?;
        Ok(listing.views)
    }

    /// Opens the read-only transaction in which a listing of a home reads, after the bindings the home lacks were
    /// created (that needs a transaction of its own, which writes): the first listing of a principal who sees
    /// calendars through a group or a grant costs one more transaction, every later one costs none. The caller commits
    /// the transaction after its last read.
    ///
    /// `tenant` is the tenant slug of a DAV path, which must be the tenant of the request; the listings that name no
    /// path leave it out.
    async fn open_home(
        &self,
        ctx: &RequestContext,
        tenant: Option<&TenantSlug>,
        principal: &PrincipalName,
    ) -> AppResult<(Box<dyn Tx>, Home)> {
        let database = &self.core.deps().database;
        {
            let mut tx = database.begin(ctx.tenant, TxMode::ReadOnly).await?;
            let home = home_for_listing(tx.as_mut(), ctx, tenant, principal).await?;
            if tx
                .calendars()
                .visible_without_binding(home.principal.id)
                .await?
                .is_empty()
            {
                return Ok((tx, home));
            }
            tx.commit().await?;
        }
        retrying(false, || self.bind_missing(ctx, principal)).await?;
        let mut tx = database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let home = home_for_listing(tx.as_mut(), ctx, tenant, principal).await?;
        Ok((tx, home))
    }

    /// Creates the bindings a home lacks.
    async fn bind_missing(&self, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<()> {
        let deps = self.core.deps();
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let home = home_of(tx.as_mut(), ctx, principal).await?;
        let missing = tx.calendars().visible_without_binding(home.principal.id).await?;
        if missing.is_empty() {
            tx.commit().await?;
            return Ok(());
        }
        let ids: Vec<CalendarId> = missing.iter().map(|calendar| calendar.id).collect();
        match tx.calendars().lock(&ids).await {
            Ok(_) => {}
            // A calendar was deleted while the home was being listed: the listing starts over without it.
            Err(StoreError::NotFound) => return Err(AppError::from(StoreError::SerializationFailure)),
            Err(error) => return Err(error.into()),
        }
        let mut taken: HashSet<String> = tx
            .bindings()
            .list_for(home.principal.id)
            .await?
            .into_iter()
            .map(|bound| bound.binding.slug.as_str().to_owned())
            .collect();
        let now = deps.clock.now();
        for calendar in &missing {
            let slug = free_binding_slug(&calendar.slug, &taken)?;
            let binding = Binding {
                id: BindingId::from_uuid(deps.ids.new_id()),
                tenant_id: ctx.tenant,
                principal_id: home.principal.id,
                calendar_id: calendar.id,
                slug: slug.clone(),
                display_name: None,
                color: None,
                sort_order: None,
                schedule_transp: None,
                hidden: false,
                created_at: now,
                updated_at: now,
                version: 1,
            };
            match tx.bindings().create(binding).await {
                Ok(_) => {
                    taken.insert(slug.as_str().to_owned());
                }
                // Another request bound the calendar first.
                Err(StoreError::UniqueViolation(UniqueKey::BindingCalendar)) => {}
                // Another request took the slug: this one lost a race and starts over with fresh data.
                Err(StoreError::UniqueViolation(UniqueKey::BindingSlug)) => {
                    return Err(AppError::from(StoreError::SerializationFailure));
                }
                Err(error) => return Err(error.into()),
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// The visible bindings of a home as views, ordered by sort order and name.
    async fn render_home(&self, tx: &mut dyn Tx, home: &Home) -> AppResult<HomeListing> {
        let bound: Vec<BoundCalendar> = tx
            .bindings()
            .list_for(home.principal.id)
            .await?
            .into_iter()
            .filter(|bound| !bound.binding.hidden)
            .collect();
        let ids: Vec<CalendarId> = bound.iter().map(|bound| bound.calendar.id).collect();
        let facts: HashMap<CalendarId, AccessFacts> = tx
            .calendars()
            .access_facts_many(&ids, Some(home.principal.id))
            .await?
            .into_iter()
            .collect();
        let mut views = Views::for_listing(&self.core, &home.tenant);
        // The owners and the collections they list the calendars under, read once for all of the calendars.
        let calendars: Vec<&Calendar> = bound.iter().map(|entry| &entry.calendar).collect();
        views.prime(tx, &calendars).await?;
        let mut listing = Vec::with_capacity(bound.len());
        for entry in &bound {
            let Some(facts) = facts.get(&entry.calendar.id) else {
                continue;
            };
            // A calendar whose access ended (a removed group member, a revoked grant) is no longer listed.
            if effective_access(home.principal.id, facts).is_none() {
                continue;
            }
            listing.push(
                views
                    .binding_view(tx, &home.principal, &entry.binding, &entry.calendar, facts)
                    .await?,
            );
        }
        listing.sort_by_key(|view| (view.sort_order, view.path.format()));
        Ok(HomeListing { views: listing, facts })
    }

    /// The collections of a home in one go (`CalendarService::list_home_collections`): the calendars, with their dead
    /// properties and invitations when `detail` asks for them, and the special collections of the home.
    ///
    /// The collections are what [`collection`](Self::collection) would answer for each of them, read with a fixed
    /// number of queries whatever the number of calendars (`ENGINEERING_RULES` R14): the authorization facts once for
    /// the whole home, the properties of all bindings with one query, the grants of all calendars the viewer may share
    /// with one, and the principals they name with one.
    pub(super) async fn home_collections(
        &self,
        ctx: &RequestContext,
        home_path: &ResourcePath,
        detail: HomeDetail,
    ) -> AppResult<Vec<CollectionView>> {
        let ResourcePath::Home { tenant, principal } = home_path else {
            return Err(AppError::not_found());
        };
        require_scope(ctx, Operation::ReadCollection)?;
        let (mut open, home) = self.open_home(ctx, Some(tenant), principal).await?;
        let tx = open.as_mut();
        let HomeListing {
            views: listed,
            facts: listed_facts,
        } = self.render_home(tx, &home).await?;
        let mut collections: Vec<CollectionView> = Vec::with_capacity(listed.len().saturating_add(3));
        if detail.dead_properties || detail.invites {
            // What `collection` decides for each calendar: the caller must be able to read it. The viewer of a
            // collection is the owner of the home, so for the usual caller (the owner of the home) the facts of the
            // listing are the caller's facts too.
            let caller_facts: HashMap<CalendarId, AccessFacts> = if ctx.principal() == Some(home.principal.id) {
                listed_facts
            } else {
                let ids: Vec<CalendarId> = listed.iter().map(|view| view.calendar_id).collect();
                tx.calendars()
                    .access_facts_many(&ids, ctx.principal())
                    .await?
                    .into_iter()
                    .collect()
            };
            let mut visible: Vec<BindingView> = Vec::with_capacity(listed.len());
            for view in listed {
                let Some(facts) = caller_facts.get(&view.calendar_id) else {
                    continue;
                };
                match enforce(ctx, facts, Operation::ReadCollection, || view.path.href()) {
                    Ok(()) => visible.push(view),
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            let mut dead = if detail.dead_properties {
                self.dead_properties_many(tx, &visible).await?
            } else {
                HashMap::new()
            };
            let mut invites = if detail.invites {
                self.invites_many(ctx, tx, &visible, &caller_facts).await?
            } else {
                HashMap::new()
            };
            for view in visible {
                collections.push(CollectionView {
                    dead_properties: dead.remove(&view.calendar_id).unwrap_or_default(),
                    invites: invites.remove(&view.calendar_id).unwrap_or_default(),
                    ..CollectionView::from_binding(&view)
                });
            }
        } else {
            collections.extend(listed.iter().map(CollectionView::from_binding));
        }
        if detail.special {
            let special = [
                ResourcePath::Inbox {
                    tenant: tenant.clone(),
                    principal: principal.clone(),
                },
                ResourcePath::Outbox {
                    tenant: tenant.clone(),
                    principal: principal.clone(),
                },
                ResourcePath::Notifications {
                    tenant: tenant.clone(),
                    principal: principal.clone(),
                },
            ];
            for path in &special {
                match self.home_level(tx, ctx, &home, path).await {
                    Ok(view) => collections.push(view),
                    Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::Forbidden) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        open.commit().await?;
        Ok(collections)
    }

    /// The dead properties of the bindings of a listing: for each calendar the shared ones overlaid with the
    /// binding's own, read with one query.
    async fn dead_properties_many(
        &self,
        tx: &mut dyn Tx,
        views: &[BindingView],
    ) -> AppResult<HashMap<CalendarId, Vec<DeadProperty>>> {
        let pairs: Vec<(CalendarId, BindingId)> =
            views.iter().map(|view| (view.calendar_id, view.binding_id)).collect();
        let mut merged: HashMap<CalendarId, BTreeMap<(String, String), String>> = HashMap::new();
        // The shared properties of a calendar come before the binding's own ones, so the latter overlay.
        for property in tx.properties().list_many(&pairs).await? {
            merged
                .entry(property.calendar_id)
                .or_default()
                .insert((property.ns, property.name), property.value_xml);
        }
        Ok(merged
            .into_iter()
            .map(|(calendar, properties)| (calendar, dead_property_list(properties)))
            .collect())
    }

    /// The invitations of the calendars of a listing that the caller may share (`CS:invite`), read with one query for
    /// the grants of all of them and one for the principals they name.
    async fn invites_many(
        &self,
        ctx: &RequestContext,
        tx: &mut dyn Tx,
        views: &[BindingView],
        caller_facts: &HashMap<CalendarId, AccessFacts>,
    ) -> AppResult<HashMap<CalendarId, Vec<InviteView>>> {
        let sharable: Vec<CalendarId> = views
            .iter()
            .filter(|view| {
                caller_facts.get(&view.calendar_id).is_some_and(|facts| {
                    decide(&ctx.subject(), ctx.channel, facts, Operation::ShareCalendar) == Decision::Allow
                })
            })
            .map(|view| view.calendar_id)
            .collect();
        if sharable.is_empty() {
            return Ok(HashMap::new());
        }
        self.invites_of(tx, &sharable).await
    }

    /// The invitations of `calendars`, whose viewer may share them: one query for their grants and one for the
    /// principals those name, whatever the number of calendars.
    async fn invites_of(
        &self,
        tx: &mut dyn Tx,
        calendars: &[CalendarId],
    ) -> AppResult<HashMap<CalendarId, Vec<InviteView>>> {
        let grants = tx.grants().for_calendars(calendars).await?;
        let grantee_ids: Vec<PrincipalId> = grants.iter().map(|grant| grant.grantee_id).collect();
        let grantees: HashMap<PrincipalId, Principal> = tx
            .principals()
            .get_many(&grantee_ids)
            .await?
            .into_iter()
            .map(|grantee| (grantee.id, grantee))
            .collect();
        let mut by_calendar: HashMap<CalendarId, Vec<&Grant>> = HashMap::new();
        for grant in &grants {
            by_calendar.entry(grant.calendar_id).or_default().push(grant);
        }
        Ok(calendars
            .iter()
            .map(|calendar| {
                let own = by_calendar.remove(calendar).unwrap_or_default();
                (*calendar, invite_views(own, &grantees))
            })
            .collect())
    }

    /// One collection of a home.
    pub(super) async fn collection(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<CollectionView> {
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        match path {
            ResourcePath::Collection {
                tenant,
                principal,
                binding,
            } => {
                let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
                let binding = tx.bindings().get_by_slug(home.principal.id, binding).await?;
                let calendar = tx.calendars().get(binding.calendar_id).await?;
                let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
                enforce(ctx, &facts, Operation::ReadCollection, || path.href())?;
                // The viewer of a collection is the owner of the home it is in.
                let view_facts = if ctx.principal() == Some(home.principal.id) {
                    facts.clone()
                } else {
                    tx.calendars()
                        .access_facts(calendar.id, Some(home.principal.id))
                        .await?
                };
                let mut views = Views::new(&self.core, &home.tenant);
                let view = views
                    .binding_view(tx.as_mut(), &home.principal, &binding, &calendar, &view_facts)
                    .await?;
                let dead_properties = self
                    .dead_properties_many(tx.as_mut(), std::slice::from_ref(&view))
                    .await?
                    .remove(&calendar.id)
                    .unwrap_or_default();
                let invites = self.invites(ctx, tx.as_mut(), &calendar, &facts).await?;
                tx.commit().await?;
                Ok(CollectionView {
                    dead_properties,
                    invites,
                    ..CollectionView::from_binding(&view)
                })
            }
            ResourcePath::Home { tenant, principal }
            | ResourcePath::Inbox { tenant, principal }
            | ResourcePath::Outbox { tenant, principal }
            | ResourcePath::Notifications { tenant, principal } => {
                let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
                let view = self.home_level(tx.as_mut(), ctx, &home, path).await?;
                tx.commit().await?;
                Ok(view)
            }
            _ => Err(AppError::not_found()),
        }
    }

    /// The home itself and its inbox, outbox and notification collection: they belong to the principal and have no
    /// calendar behind them.
    async fn home_level(
        &self,
        tx: &mut dyn Tx,
        ctx: &RequestContext,
        home: &Home,
        path: &ResourcePath,
    ) -> AppResult<CollectionView> {
        let (operation, resource, label, log) = match path {
            ResourcePath::Home { .. } => (Operation::ReadCollection, ResourceKind::Home, "Calendars", None),
            ResourcePath::Inbox { .. } => (
                Operation::ReadInbox,
                ResourceKind::Inbox,
                "Inbox",
                Some(CollectionKind::Inbox),
            ),
            ResourcePath::Outbox { .. } => (Operation::PostOutbox, ResourceKind::Outbox, "Outbox", None),
            ResourcePath::Notifications { .. } => (
                Operation::ReadNotifications,
                ResourceKind::Notifications,
                "Notifications",
                Some(CollectionKind::Notifications),
            ),
            _ => return Err(AppError::not_found()),
        };
        let facts = home_facts(&home.tenant, &home.principal);
        enforce(ctx, &facts, operation, || path.href())?;
        let sync_token = match log {
            Some(kind) => {
                let id = home.principal.id.as_uuid();
                let position = tx.changes().state(CollectionKey { kind, id }).await?;
                Some(position.token(id))
            }
            None => None,
        };
        Ok(CollectionView {
            path: path.clone(),
            display_name: label.to_owned(),
            privileges: privileges(Access::Owner, CalendarKind::Personal, resource),
            sync_token,
            calendar: None,
            dead_properties: Vec::new(),
            invites: Vec::new(),
        })
    }

    /// The invitations of a calendar the viewer may share (`CS:invite`).
    ///
    /// Service principals are left out: they are grantees of the management API only (PLAN 2.9), which client
    /// sharing does not offer, so a calendar client neither lists them nor can change or remove their grants
    /// (`Shared::protects` in the sharing module answers `need-privileges` for a removal that names one).
    async fn invites(
        &self,
        ctx: &RequestContext,
        tx: &mut dyn Tx,
        calendar: &davhaven_domain::Calendar,
        facts: &AccessFacts,
    ) -> AppResult<Vec<InviteView>> {
        if decide(&ctx.subject(), ctx.channel, facts, Operation::ShareCalendar) != Decision::Allow {
            return Ok(Vec::new());
        }
        Ok(self
            .invites_of(tx, &[calendar.id])
            .await?
            .remove(&calendar.id)
            .unwrap_or_default())
    }

    /// Validates a MKCALENDAR request before anything is stored.
    async fn check_mkcalendar(&self, request: &MkCalendar) -> AppResult<Checked> {
        let limits = &self.core.deps().limits.dav;
        let display_name = match &request.display_name {
            Some(name) => Some(clean_name("/displayname", name, MAX_DISPLAY_NAME)?),
            None => None,
        };
        let description =
            clean_optional_text("/calendar-description", request.description.as_deref(), MAX_DESCRIPTION)?;
        let color = check_color("/calendar-color", request.color.as_deref())?;
        if let Some(ics) = request.timezone_ics.clone() {
            blocking(&self.core, ErrorContext::Store, move |limits| {
                davhaven_ical::tz::calendar_timezone(&ics, limits).map(|_| ())
            })
            .await?;
        }
        let max_size = usize::try_from(limits.max_dead_property_size).unwrap_or(usize::MAX);
        let max_count = usize::try_from(limits.max_dead_properties).unwrap_or(usize::MAX);
        if request.dead_properties.len() > max_count
            || request
                .dead_properties
                .iter()
                .any(|property| property.size() > max_size)
        {
            return Err(invalid("A property is too large or there are too many properties."));
        }
        Ok(Checked {
            display_name,
            description,
            color,
            components: request.components.clone(),
        })
    }

    /// Creates a calendar in the home named by the path (MKCALENDAR, extended MKCOL).
    pub(super) async fn create_in_home(&self, ctx: &RequestContext, request: MkCalendar) -> AppResult<BindingView> {
        let ResourcePath::Collection {
            tenant,
            principal,
            binding: slug,
        } = &request.path
        else {
            return Err(invalid("A calendar is created at a collection path."));
        };
        let checked = self.check_mkcalendar(&request).await?;
        retrying(false, || {
            self.create_once(ctx, &request, &checked, (tenant, principal, slug))
        })
        .await
    }

    async fn create_once(
        &self,
        ctx: &RequestContext,
        request: &MkCalendar,
        checked: &Checked,
        target: (&TenantSlug, &PrincipalName, &davhaven_domain::CalendarSlug),
    ) -> AppResult<BindingView> {
        let (tenant_slug, principal, slug) = target;
        let journal = Journal::new(&self.core, ctx);
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant_slug, principal).await?;
        let mut facts = home_facts(&home.tenant, &home.principal);
        facts.calendar_kind = CalendarKind::User;
        enforce(ctx, &facts, Operation::CreateCalendar, || request.path.href())?;
        let taken = found(tx.bindings().get_by_slug(home.principal.id, slug).await)?.is_some()
            || found(tx.calendars().get_by_slug(home.principal.id, slug).await)?.is_some();
        if taken {
            return Err(AppError::conflict().with_precondition(davhaven_domain::Precondition::ResourceMustBeNull));
        }
        let allowed = &home.tenant.settings.allowed_components;
        let components = checked.components.clone().unwrap_or_else(|| allowed.clone());
        if components.is_empty() || components.iter().any(|component| !allowed.contains(component)) {
            return Err(AppError::invalid(crate::error::SafeMessage::from_static(
                "The calendar cannot hold these component types.",
            ))
            .with_precondition(davhaven_domain::Precondition::SupportedCalendarComponent));
        }
        let (calendar, binding) = provision(
            &self.core,
            tx.as_mut(),
            &home.principal,
            NewCalendar {
                slug: slug.clone(),
                kind: CalendarKind::User,
                display_name: checked.display_name.clone().unwrap_or_else(|| slug.as_str().to_owned()),
                description: checked.description.clone(),
                color: checked.color.clone(),
                sort_order: request.sort_order.unwrap_or(0),
                components,
                timezone_ics: request.timezone_ics.clone(),
                schedule_transp: request.schedule_transp,
            },
        )
        .await
        .map_err(|error| {
            if error.kind() == davhaven_domain::ErrorKind::Conflict {
                error.with_precondition(davhaven_domain::Precondition::ResourceMustBeNull)
            } else {
                error
            }
        })?;
        for property in &request.dead_properties {
            tx.properties()
                .set(CollectionProperty {
                    calendar_id: calendar.id,
                    scope: PropertyScope::Binding(binding.id),
                    ns: property.name.namespace.clone(),
                    name: property.name.local.clone(),
                    value_xml: property.value_xml.clone(),
                })
                .await?;
        }
        journal
            .publish(
                tx.as_mut(),
                EventType::CalendarCreated,
                EventPayload::Calendar(CalendarPayload {
                    calendar: calendar.id,
                    owner: calendar.owner_id,
                    kind: calendar.kind,
                }),
            )
            .await?;
        let facts = tx
            .calendars()
            .access_facts(calendar.id, Some(home.principal.id))
            .await?;
        let stored = tx.calendars().get(calendar.id).await?;
        let view = Views::new(&self.core, &home.tenant)
            .binding_view(tx.as_mut(), &home.principal, &binding, &stored, &facts)
            .await?;
        tx.commit().await?;
        Ok(view)
    }

    /// Deletes a bound collection: the owner deletes the calendar for everyone, a sharee leaves the share and
    /// everyone else (members of a group, grantees of a managed calendar) hides the binding (PLAN 2.9). A calendar that
    /// is **required** for the caller (an accepted grant with the `required` flag reaches them) is none of these: the
    /// decision refuses it (403, `DAV:need-privileges` naming `DAV:unbind`) and nothing changes. A hidden binding comes
    /// back through the management API (`restore_binding`).
    pub(super) async fn delete_bound(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        conditions: Conditions,
    ) -> AppResult<()> {
        let ResourcePath::Collection {
            tenant,
            principal,
            binding: slug,
        } = path
        else {
            return Err(AppError::not_found());
        };
        retrying(false, || {
            self.delete_once(ctx, path, (tenant, principal, slug), conditions)
        })
        .await
    }

    async fn delete_once(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        target: (&TenantSlug, &PrincipalName, &davhaven_domain::CalendarSlug),
        conditions: Conditions,
    ) -> AppResult<()> {
        let (tenant_slug, principal, slug) = target;
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant_slug, principal).await?;
        let binding = tx.bindings().get_by_slug(home.principal.id, slug).await?;
        let calendar = lock_one(tx.as_mut(), binding.calendar_id).await?;
        let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
        let owns = calendar.owner_id == home.principal.id;
        let operation = if owns {
            Operation::DeleteCalendar
        } else {
            Operation::RemoveBinding
        };
        // DELETE needs `DAV:unbind` on the parent of the resource (RFC 4918 section 9.6.1, RFC 3744): for a binding that is
        // the home, which is the collection a refusal names. (The collection's own privilege set lists `DAV:unbind` for its
        // members, so naming it would contradict what the server reports.)
        enforce(ctx, &facts, operation, || match operation {
            Operation::RemoveBinding => ResourcePath::Home {
                tenant: tenant_slug.clone(),
                principal: principal.clone(),
            }
            .href(),
            _ => path.href(),
        })?;
        if let Some(expected) = conditions.if_match
            && expected != calendar.version
        {
            return Err(AppError::precondition_failed());
        }
        if owns {
            tx.calendars().soft_delete(calendar.id, calendar.version).await?;
            journal
                .publish(
                    tx.as_mut(),
                    EventType::CalendarDeleted,
                    EventPayload::Calendar(CalendarPayload {
                        calendar: calendar.id,
                        owner: calendar.owner_id,
                        kind: calendar.kind,
                    }),
                )
                .await?;
        } else {
            let own_share = tx
                .grants()
                .find(calendar.id, home.principal.id)
                .await?
                .filter(|grant| grant.source == GrantSource::Share && grant.status == GrantStatus::Accepted);
            if let Some(grant) = own_share {
                crate::sharing::leave_share(&self.core, &journal, tx.as_mut(), &home, &calendar, &grant, &binding)
                    .await?;
            } else {
                let hidden = Binding {
                    hidden: true,
                    ..binding.clone()
                };
                tx.bindings().update(hidden, binding.version).await?;
            }
            tx.calendars().touch(calendar.id).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
