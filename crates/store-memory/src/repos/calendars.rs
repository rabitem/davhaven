//! Calendars, bindings, collection properties and grants.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{
    AccessFacts, Binding, BindingFact, BindingId, Calendar, CalendarId, CalendarSlug, CollectionKind, Grant, GrantFact,
    GrantId, GrantStatus, PrincipalId, TenantSettings, Uid,
};
use davhaven_ports::{
    BindingRepo, BoundCalendar, CalendarFilter, CalendarRepo, ChangeKind, CollectionProperty, GrantRepo, PageReq,
    PropertyRepo, PropertyScope, StoreError, StorePage, UniqueKey,
};

use super::{misuse, no_nul, paginate};
use crate::state::TenantData;
use crate::tx::MemTx;

impl TenantData {
    /// The live calendar, or `NotFound`.
    fn live_calendar(&self, id: CalendarId) -> Result<&Calendar, StoreError> {
        self.calendars
            .get(&id)
            .filter(|calendar| calendar.deleted_at.is_none())
            .ok_or(StoreError::NotFound)
    }

    /// The authorization facts of one live calendar.
    fn facts_of(
        &self,
        calendar: &Calendar,
        principal: Option<PrincipalId>,
        settings: &Arc<TenantSettings>,
    ) -> Option<AccessFacts> {
        let owner = self.principals.get(&calendar.owner_id)?;
        let memberships = principal.map(|principal| self.groups_of(principal)).unwrap_or_default();
        let binding = principal.and_then(|principal| {
            self.bindings
                .values()
                .find(|binding| binding.calendar_id == calendar.id && binding.principal_id == principal)
                .map(|binding| BindingFact {
                    id: binding.id,
                    hidden: binding.hidden,
                })
        });
        Some(AccessFacts {
            calendar_kind: calendar.kind,
            owner: calendar.owner_id,
            owner_kind: owner.kind,
            memberships,
            grants: self
                .grants
                .values()
                .filter(|grant| grant.calendar_id == calendar.id)
                .map(GrantFact::from)
                .collect(),
            binding,
            tenant_settings: Arc::clone(settings),
        })
    }

    /// The scope of a property operation after checking that the calendar (and the binding) exist.
    fn check_scope(&self, calendar: CalendarId, scope: PropertyScope) -> Result<Option<BindingId>, StoreError> {
        self.live_calendar(calendar)?;
        match scope {
            PropertyScope::Shared => Ok(None),
            PropertyScope::Binding(binding) => self
                .bindings
                .get(&binding)
                .filter(|found| found.calendar_id == calendar)
                .map(|found| Some(found.id))
                .ok_or(StoreError::NotFound),
        }
    }
}

impl MemTx {
    /// The facts of the calendars, in the order of `calendars`, skipping the ones that do not exist.
    fn facts_for(&self, calendars: &[CalendarId], principal: Option<PrincipalId>) -> Vec<(CalendarId, AccessFacts)> {
        let Some(entry) = self.guard.tenants.get(&self.tenant) else {
            return Vec::new();
        };
        let settings = Arc::new(entry.tenant.settings.clone());
        calendars
            .iter()
            .filter_map(|id| {
                let calendar = entry
                    .data
                    .calendars
                    .get(id)
                    .filter(|calendar| calendar.deleted_at.is_none())?;
                entry
                    .data
                    .facts_of(calendar, principal, &settings)
                    .map(|facts| (*id, facts))
            })
            .collect()
    }
}

#[async_trait]
impl CalendarRepo for MemTx {
    async fn get(&mut self, id: CalendarId) -> Result<Calendar, StoreError> {
        observed!("calendars.get", self.view().live_calendar(id).cloned())
    }

    async fn get_many(&mut self, ids: &[CalendarId]) -> Result<Vec<Calendar>, StoreError> {
        observed!("calendars.get_many", {
            let wanted: BTreeSet<CalendarId> = ids.iter().copied().collect();
            Ok(self
                .view()
                .calendars
                .values()
                .filter(|calendar| calendar.deleted_at.is_none() && wanted.contains(&calendar.id))
                .cloned()
                .collect())
        })
    }

    async fn get_by_slug(&mut self, owner: PrincipalId, slug: &CalendarSlug) -> Result<Calendar, StoreError> {
        observed!(
            "calendars.get_by_slug",
            self.view()
                .calendars
                .values()
                .find(|calendar| calendar.deleted_at.is_none() && calendar.owner_id == owner && &calendar.slug == slug)
                .cloned()
                .ok_or(StoreError::NotFound)
        )
    }

    async fn list_owned(&mut self, owner: PrincipalId) -> Result<Vec<Calendar>, StoreError> {
        observed!(
            "calendars.list_owned",
            Ok(self
                .view()
                .calendars
                .values()
                .filter(|calendar| calendar.deleted_at.is_none() && calendar.owner_id == owner)
                .cloned()
                .collect())
        )
    }

    async fn list(&mut self, filter: &CalendarFilter, page: PageReq) -> Result<StorePage<Calendar>, StoreError> {
        observed!("calendars.list", {
            let needle = filter.text.as_ref().map(|text| text.to_lowercase());
            let matching = self.view().calendars.values().filter(|calendar| {
                calendar.deleted_at.is_none()
                    && filter.owner.is_none_or(|owner| calendar.owner_id == owner)
                    && filter.kind.is_none_or(|kind| calendar.kind == kind)
                    && filter.slug.as_ref().is_none_or(|slug| &calendar.slug == slug)
                    && needle
                        .as_ref()
                        .is_none_or(|needle| calendar.display_name.to_lowercase().contains(needle.as_str()))
            });
            Ok(paginate(matching.cloned(), &page, |calendar| calendar.id.as_uuid()))
        })
    }

    async fn visible_without_binding(&mut self, principal: PrincipalId) -> Result<Vec<Calendar>, StoreError> {
        observed!("calendars.visible_without_binding", {
            let data = self.view();
            let groups = data.groups_of(principal);
            Ok(data
                .calendars
                .values()
                .filter(|calendar| {
                    calendar.deleted_at.is_none()
                        && calendar.owner_id != principal
                        && !data
                            .bindings
                            .values()
                            .any(|binding| binding.principal_id == principal && binding.calendar_id == calendar.id)
                        && (groups.contains(&calendar.owner_id)
                            || data.grants.values().any(|grant| {
                                grant.calendar_id == calendar.id
                                    && grant.status == GrantStatus::Accepted
                                    && (grant.grantee_id == principal || groups.contains(&grant.grantee_id))
                            }))
                })
                .cloned()
                .collect())
        })
    }

    async fn access_facts(
        &mut self,
        calendar: CalendarId,
        principal: Option<PrincipalId>,
    ) -> Result<AccessFacts, StoreError> {
        observed!("calendars.access_facts", {
            self.facts_for(&[calendar], principal)
                .into_iter()
                .next()
                .map(|(_, facts)| facts)
                .ok_or(StoreError::NotFound)
        })
    }

    async fn access_facts_many(
        &mut self,
        calendars: &[CalendarId],
        principal: Option<PrincipalId>,
    ) -> Result<Vec<(CalendarId, AccessFacts)>, StoreError> {
        observed!("calendars.access_facts_many", Ok(self.facts_for(calendars, principal)))
    }

    async fn create(&mut self, calendar: Calendar) -> Result<Calendar, StoreError> {
        observed!("calendars.create", {
            no_nul(
                "calendar text",
                [
                    Some(calendar.display_name.as_str()),
                    calendar.description.as_deref(),
                    calendar.color.as_deref(),
                    calendar.timezone_ics.as_deref(),
                ],
            )?;
            let now = self.now();
            let tenant = self.tenant;
            let data = self.writable()?;
            if data.calendars.contains_key(&calendar.id) {
                return Err(misuse("a calendar with this id exists already"));
            }
            if data.calendars.values().any(|other| {
                other.deleted_at.is_none() && other.owner_id == calendar.owner_id && other.slug == calendar.slug
            }) {
                return Err(StoreError::UniqueViolation(UniqueKey::CalendarSlug));
            }
            if !data.principals.contains_key(&calendar.owner_id) {
                return Err(StoreError::NotFound);
            }
            let stored = Calendar {
                tenant_id: tenant,
                sync_seq: 0,
                sync_min_seq: 0,
                deleted_at: None,
                created_at: now,
                updated_at: now,
                version: 1,
                ..calendar
            };
            data.calendars.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn update(&mut self, calendar: Calendar, expected_version: i64) -> Result<Calendar, StoreError> {
        observed!("calendars.update", {
            no_nul(
                "calendar text",
                [
                    Some(calendar.display_name.as_str()),
                    calendar.description.as_deref(),
                    calendar.color.as_deref(),
                    calendar.timezone_ics.as_deref(),
                ],
            )?;
            let now = self.now();
            let data = self.writable()?;
            data.live_calendar(calendar.id)?;
            let stored = data.calendars.get_mut(&calendar.id).ok_or(StoreError::NotFound)?;
            if stored.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            stored.display_name = calendar.display_name;
            stored.description = calendar.description;
            stored.color = calendar.color;
            stored.sort_order = calendar.sort_order;
            stored.components = calendar.components;
            stored.timezone_ics = calendar.timezone_ics;
            stored.updated_at = now;
            stored.version += 1;
            stored.sync_seq += 1;
            Ok(stored.clone())
        })
    }

    async fn soft_delete(&mut self, id: CalendarId, expected_version: i64) -> Result<(), StoreError> {
        observed!("calendars.soft_delete", {
            let now = self.now();
            let data = self.writable()?;
            data.live_calendar(id)?;
            let stored = data.calendars.get_mut(&id).ok_or(StoreError::NotFound)?;
            if stored.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            stored.deleted_at = Some(now);
            stored.updated_at = now;
            stored.version += 1;
            stored.sync_seq += 1;
            // Every binding goes with the calendar, and every home hears about it (see the PostgreSQL adapter).
            let mut doomed: Vec<(PrincipalId, String, BindingId)> = data
                .bindings
                .values()
                .filter(|binding| binding.calendar_id == id)
                .map(|binding| (binding.principal_id, binding.slug.as_str().to_owned(), binding.id))
                .collect();
            doomed.sort();
            for (principal, slug, binding) in doomed {
                data.remove_binding(binding);
                data.record_principal_change(principal, CollectionKind::Home, &slug, ChangeKind::Delete, now)?;
            }
            Ok(())
        })
    }

    async fn lock(&mut self, ids: &[CalendarId]) -> Result<Vec<Calendar>, StoreError> {
        observed!("calendars.lock", {
            // The PostgreSQL adapter takes row locks, which a read-only transaction refuses.
            self.require_write_mode()?;
            let wanted: BTreeSet<CalendarId> = ids.iter().copied().collect();
            let data = self.view();
            wanted.iter().map(|id| data.live_calendar(*id).cloned()).collect()
        })
    }

    async fn touch(&mut self, id: CalendarId) -> Result<u64, StoreError> {
        observed!(
            "calendars.touch",
            self.writable()?.bump_calendar(id).ok_or(StoreError::NotFound)
        )
    }

    async fn purge(&mut self, id: CalendarId) -> Result<(), StoreError> {
        observed!("calendars.purge", {
            let now = self.now();
            let data = self.writable()?;
            if data
                .calendars
                .get(&id)
                .is_none_or(|calendar| calendar.deleted_at.is_none())
            {
                return Err(StoreError::NotFound);
            }
            data.remove_calendar(id);
            // A feed token names its calendars without a reference the store could cascade: drop the dangling id.
            for token in data
                .feed_tokens
                .values_mut()
                .filter(|token| token.calendar_ids.contains(&id))
            {
                token.calendar_ids.retain(|calendar| *calendar != id);
                token.updated_at = now;
                token.version += 1;
            }
            Ok(())
        })
    }
}

#[async_trait]
impl BindingRepo for MemTx {
    async fn get(&mut self, id: BindingId) -> Result<Binding, StoreError> {
        observed!(
            "bindings.get",
            self.view().bindings.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn get_by_slug(&mut self, principal: PrincipalId, slug: &CalendarSlug) -> Result<Binding, StoreError> {
        observed!(
            "bindings.get_by_slug",
            self.view()
                .bindings
                .values()
                .find(|binding| binding.principal_id == principal && &binding.slug == slug)
                .cloned()
                .ok_or(StoreError::NotFound)
        )
    }

    async fn find_for_calendar(
        &mut self,
        principal: PrincipalId,
        calendar: CalendarId,
    ) -> Result<Option<Binding>, StoreError> {
        observed!(
            "bindings.find_for_calendar",
            Ok(self
                .view()
                .bindings
                .values()
                .find(|binding| binding.principal_id == principal && binding.calendar_id == calendar)
                .cloned())
        )
    }

    async fn list_for(&mut self, principal: PrincipalId) -> Result<Vec<BoundCalendar>, StoreError> {
        observed!("bindings.list_for", {
            let data = self.view();
            Ok(data
                .bindings
                .values()
                .filter(|binding| binding.principal_id == principal)
                .filter_map(|binding| {
                    data.calendars
                        .get(&binding.calendar_id)
                        .filter(|calendar| calendar.deleted_at.is_none())
                        .map(|calendar| BoundCalendar {
                            binding: binding.clone(),
                            calendar: calendar.clone(),
                        })
                })
                .collect())
        })
    }

    async fn find_for_calendars(&mut self, pairs: &[(PrincipalId, CalendarId)]) -> Result<Vec<Binding>, StoreError> {
        observed!("bindings.find_for_calendars", {
            if pairs.is_empty() {
                return Ok(Vec::new());
            }
            let wanted: BTreeSet<(PrincipalId, CalendarId)> = pairs.iter().copied().collect();
            let mut found: Vec<Binding> = self
                .view()
                .bindings
                .values()
                .filter(|binding| wanted.contains(&(binding.principal_id, binding.calendar_id)))
                .cloned()
                .collect();
            found.sort_by_key(|binding| (binding.calendar_id, binding.principal_id));
            Ok(found)
        })
    }

    async fn list_for_calendar(&mut self, calendar: CalendarId) -> Result<Vec<Binding>, StoreError> {
        observed!("bindings.list_for_calendar", {
            let data = self.view();
            data.live_calendar(calendar)?;
            Ok(data
                .bindings
                .values()
                .filter(|binding| binding.calendar_id == calendar)
                .cloned()
                .collect())
        })
    }

    async fn create(&mut self, binding: Binding) -> Result<Binding, StoreError> {
        observed!("bindings.create", {
            no_nul(
                "binding text",
                [binding.display_name.as_deref(), binding.color.as_deref()],
            )?;
            let now = self.now();
            let tenant = self.tenant;
            let data = self.writable()?;
            data.live_calendar(binding.calendar_id)?;
            if data.bindings.contains_key(&binding.id) {
                return Err(misuse("a binding with this id exists already"));
            }
            if data
                .bindings
                .values()
                .any(|other| other.principal_id == binding.principal_id && other.slug == binding.slug)
            {
                return Err(StoreError::UniqueViolation(UniqueKey::BindingSlug));
            }
            if data
                .bindings
                .values()
                .any(|other| other.principal_id == binding.principal_id && other.calendar_id == binding.calendar_id)
            {
                return Err(StoreError::UniqueViolation(UniqueKey::BindingCalendar));
            }
            if !data.principals.contains_key(&binding.principal_id) {
                return Err(StoreError::NotFound);
            }
            let stored = Binding {
                tenant_id: tenant,
                created_at: now,
                updated_at: now,
                version: 1,
                ..binding
            };
            data.record_principal_change(
                stored.principal_id,
                CollectionKind::Home,
                stored.slug.as_str(),
                ChangeKind::Upsert,
                now,
            )?;
            data.bindings.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn update(&mut self, binding: Binding, expected_version: i64) -> Result<Binding, StoreError> {
        observed!("bindings.update", {
            no_nul(
                "binding text",
                [binding.display_name.as_deref(), binding.color.as_deref()],
            )?;
            let now = self.now();
            let data = self.writable()?;
            let stored = data.bindings.get_mut(&binding.id).ok_or(StoreError::NotFound)?;
            if stored.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            stored.display_name = binding.display_name;
            stored.color = binding.color;
            stored.sort_order = binding.sort_order;
            stored.schedule_transp = binding.schedule_transp;
            stored.hidden = binding.hidden;
            stored.updated_at = now;
            stored.version += 1;
            let updated = stored.clone();
            data.record_principal_change(
                updated.principal_id,
                CollectionKind::Home,
                updated.slug.as_str(),
                ChangeKind::Upsert,
                now,
            )?;
            Ok(updated)
        })
    }

    async fn delete(&mut self, id: BindingId) -> Result<(), StoreError> {
        observed!("bindings.delete", {
            let now = self.now();
            let data = self.writable()?;
            let binding = data.bindings.get(&id).cloned().ok_or(StoreError::NotFound)?;
            data.record_principal_change(
                binding.principal_id,
                CollectionKind::Home,
                binding.slug.as_str(),
                ChangeKind::Delete,
                now,
            )?;
            data.remove_binding(id);
            Ok(())
        })
    }
}

#[async_trait]
impl PropertyRepo for MemTx {
    async fn list(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
    ) -> Result<Vec<CollectionProperty>, StoreError> {
        observed!("properties.list", {
            let data = self.view();
            let binding = data.check_scope(calendar, scope)?;
            Ok(data
                .properties
                .iter()
                .filter(|((owner, bound, _, _), _)| *owner == calendar && *bound == binding)
                .map(|(_, property)| property.clone())
                .collect())
        })
    }

    async fn list_many(&mut self, bindings: &[(CalendarId, BindingId)]) -> Result<Vec<CollectionProperty>, StoreError> {
        observed!("properties.list_many", {
            if bindings.is_empty() {
                return Ok(Vec::new());
            }
            let data = self.view();
            // The pairs that are valid: the binding belongs to the live calendar.
            let valid: BTreeSet<(CalendarId, BindingId)> = bindings
                .iter()
                .copied()
                .filter(|(calendar, binding)| data.check_scope(*calendar, PropertyScope::Binding(*binding)).is_ok())
                .collect();
            let calendars: BTreeSet<CalendarId> = valid.iter().map(|(calendar, _)| *calendar).collect();
            Ok(data
                .properties
                .iter()
                .filter(|((calendar, binding, _, _), _)| match binding {
                    None => calendars.contains(calendar),
                    Some(binding) => valid.contains(&(*calendar, *binding)),
                })
                .map(|(_, property)| property.clone())
                .collect())
        })
    }

    async fn get(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
        ns: &str,
        name: &str,
    ) -> Result<Option<CollectionProperty>, StoreError> {
        observed!("properties.get", {
            let data = self.view();
            let binding = data.check_scope(calendar, scope)?;
            Ok(data
                .properties
                .get(&(calendar, binding, ns.to_owned(), name.to_owned()))
                .cloned())
        })
    }

    async fn set(&mut self, property: CollectionProperty) -> Result<(), StoreError> {
        observed!("properties.set", {
            no_nul(
                "property",
                [
                    Some(property.ns.as_str()),
                    Some(property.name.as_str()),
                    Some(property.value_xml.as_str()),
                ],
            )?;
            let data = self.writable()?;
            let binding = data.check_scope(property.calendar_id, property.scope)?;
            let key = (
                property.calendar_id,
                binding,
                property.ns.clone(),
                property.name.clone(),
            );
            data.properties.insert(key, property);
            Ok(())
        })
    }

    async fn remove(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
        ns: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        observed!("properties.remove", {
            let data = self.writable()?;
            let binding = data.check_scope(calendar, scope)?;
            Ok(data
                .properties
                .remove(&(calendar, binding, ns.to_owned(), name.to_owned()))
                .is_some())
        })
    }

    async fn count(&mut self, calendar: CalendarId, scope: PropertyScope) -> Result<u64, StoreError> {
        observed!("properties.count", {
            let data = self.view();
            let binding = data.check_scope(calendar, scope)?;
            let count = data
                .properties
                .keys()
                .filter(|(owner, bound, _, _)| *owner == calendar && *bound == binding)
                .count();
            Ok(u64::try_from(count).unwrap_or(u64::MAX))
        })
    }
}

#[async_trait]
impl GrantRepo for MemTx {
    async fn get(&mut self, id: GrantId) -> Result<Grant, StoreError> {
        observed!(
            "grants.get",
            self.view().grants.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn find(&mut self, calendar: CalendarId, grantee: PrincipalId) -> Result<Option<Grant>, StoreError> {
        observed!(
            "grants.find",
            Ok(self
                .view()
                .grants
                .values()
                .find(|grant| grant.calendar_id == calendar && grant.grantee_id == grantee)
                .cloned())
        )
    }

    async fn find_by_invite_uid(&mut self, uid: &Uid) -> Result<Option<Grant>, StoreError> {
        observed!(
            "grants.find_by_invite_uid",
            Ok(self
                .view()
                .grants
                .values()
                .find(|grant| grant.invite_uid.as_ref() == Some(uid))
                .cloned())
        )
    }

    async fn for_calendar(&mut self, calendar: CalendarId) -> Result<Vec<Grant>, StoreError> {
        observed!("grants.for_calendar", {
            let data = self.view();
            data.live_calendar(calendar)?;
            Ok(data
                .grants
                .values()
                .filter(|grant| grant.calendar_id == calendar)
                .cloned()
                .collect())
        })
    }

    async fn for_calendars(&mut self, calendars: &[CalendarId]) -> Result<Vec<Grant>, StoreError> {
        observed!("grants.for_calendars", {
            if calendars.is_empty() {
                return Ok(Vec::new());
            }
            let data = self.view();
            let wanted: BTreeSet<CalendarId> = calendars
                .iter()
                .copied()
                .filter(|calendar| data.live_calendar(*calendar).is_ok())
                .collect();
            let mut found: Vec<Grant> = data
                .grants
                .values()
                .filter(|grant| wanted.contains(&grant.calendar_id))
                .cloned()
                .collect();
            found.sort_by_key(|grant| (grant.calendar_id, grant.id));
            Ok(found)
        })
    }

    async fn for_grantee(&mut self, grantee: PrincipalId) -> Result<Vec<Grant>, StoreError> {
        observed!(
            "grants.for_grantee",
            Ok(self
                .view()
                .grants
                .values()
                .filter(|grant| grant.grantee_id == grantee)
                .cloned()
                .collect())
        )
    }

    async fn create(&mut self, grant: Grant) -> Result<Grant, StoreError> {
        observed!("grants.create", {
            no_nul("grant text", [grant.summary.as_deref(), grant.common_name.as_deref()])?;
            let now = self.now();
            let tenant = self.tenant;
            let data = self.writable()?;
            data.live_calendar(grant.calendar_id)?;
            if data.grants.contains_key(&grant.id) {
                return Err(misuse("a grant with this id exists already"));
            }
            if data
                .grants
                .values()
                .any(|other| other.calendar_id == grant.calendar_id && other.grantee_id == grant.grantee_id)
            {
                return Err(StoreError::UniqueViolation(UniqueKey::Grant));
            }
            if !data.principals.contains_key(&grant.grantee_id) {
                return Err(StoreError::NotFound);
            }
            let stored = Grant {
                tenant_id: tenant,
                created_at: now,
                updated_at: now,
                version: 1,
                ..grant
            };
            data.grants.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn update(&mut self, grant: Grant, expected_version: i64) -> Result<Grant, StoreError> {
        observed!("grants.update", {
            no_nul("grant text", [grant.summary.as_deref(), grant.common_name.as_deref()])?;
            let now = self.now();
            let data = self.writable()?;
            let stored = data.grants.get_mut(&grant.id).ok_or(StoreError::NotFound)?;
            if stored.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            stored.access = grant.access;
            stored.status = grant.status;
            stored.source = grant.source;
            stored.required = grant.required;
            stored.invite_uid = grant.invite_uid;
            stored.summary = grant.summary;
            stored.common_name = grant.common_name;
            stored.updated_at = now;
            stored.version += 1;
            Ok(stored.clone())
        })
    }

    async fn delete(&mut self, id: GrantId) -> Result<(), StoreError> {
        observed!("grants.delete", {
            self.writable()?
                .grants
                .remove(&id)
                .map(|_| ())
                .ok_or(StoreError::NotFound)
        })
    }
}
