//! Principals, their addresses and group memberships.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::{micros, misuse, no_nul, paginate};
use crate::state::{PrincipalSync, TenantData};
use crate::tx::MemTx;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarId, CalendarUserAddress, CollectionKind, Principal, PrincipalId, PrincipalKind, PrincipalName,
    PrincipalStatus, SearchCriterion,
};
use davhaven_ports::store::MAX_PAGE_LIMIT;
use davhaven_ports::{
    MembershipDiff, MembershipRepo, PageReq, PrincipalAddress, PrincipalFilter, PrincipalMatch, PrincipalQuery,
    PrincipalRepo, StoreError, StorePage, UniqueKey,
};

/// The addresses of a principal, primary first, then in address order.
fn sorted_addresses(data: &TenantData, id: PrincipalId) -> Vec<PrincipalAddress> {
    let mut addresses = data.addresses.get(&id).cloned().unwrap_or_default();
    addresses.sort_by(|left, right| {
        right
            .primary
            .cmp(&left.primary)
            .then_with(|| left.address.as_str().cmp(right.address.as_str()))
    });
    addresses
}

/// Whether another principal owns an address that equals one of `wanted` (case-insensitively).
fn address_taken(data: &TenantData, owner: PrincipalId, wanted: &[PrincipalAddress]) -> bool {
    let wanted: BTreeSet<String> = wanted
        .iter()
        .map(|address| address.address.as_str().to_lowercase())
        .collect();
    data.addresses
        .iter()
        .filter(|(principal, _)| **principal != owner)
        .flat_map(|(_, addresses)| addresses.iter())
        .any(|address| wanted.contains(&address.address.as_str().to_lowercase()))
}

impl TenantData {
    /// Removes a principal and everything that belongs to it (retention purge). The calendars it owned also
    /// disappear from the feed tokens of other principals (a feed token names its calendars without a reference
    /// the store could cascade).
    fn remove_principal(&mut self, id: PrincipalId, now: DateTime<Utc>) {
        let owned: Vec<CalendarId> = self
            .calendars
            .values()
            .filter(|calendar| calendar.owner_id == id)
            .map(|calendar| calendar.id)
            .collect();
        for calendar in &owned {
            self.remove_calendar(*calendar);
        }
        for token in self
            .feed_tokens
            .values_mut()
            .filter(|token| token.principal_id != id && token.calendar_ids.iter().any(|c| owned.contains(c)))
        {
            token.calendar_ids.retain(|calendar| !owned.contains(calendar));
            token.updated_at = now;
            token.version += 1;
        }
        let bindings: Vec<_> = self
            .bindings
            .values()
            .filter(|binding| binding.principal_id == id)
            .map(|binding| binding.id)
            .collect();
        for binding in bindings {
            self.remove_binding(binding);
        }
        self.principals.remove(&id);
        self.addresses.remove(&id);
        self.memberships.retain(|(group, member)| *group != id && *member != id);
        self.sync.remove(&id);
        self.grants.retain(|_, grant| grant.grantee_id != id);
        self.notifications
            .retain(|_, notification| notification.principal_id != id);
        self.inbox.retain(|_, item| item.principal_id != id);
        self.app_passwords.retain(|_, password| password.principal_id != id);
        self.api_tokens.retain(|_, token| token.principal_id != Some(id));
        self.feed_tokens.retain(|_, token| token.principal_id != id);
        self.external_accounts.retain(|_, account| account.principal_id != id);
        self.oauth_states.retain(|_, state| state.principal_id != id);
        for kind in [
            CollectionKind::Home,
            CollectionKind::Inbox,
            CollectionKind::Notifications,
        ] {
            self.changes.remove(&(kind, id.as_uuid()));
        }
        for attendees in self.attendees.values_mut() {
            for attendee in attendees
                .iter_mut()
                .filter(|attendee| attendee.principal_id == Some(id))
            {
                attendee.principal_id = None;
            }
        }
    }
}

/// Whether the principal satisfies the conditions of the query that look at its properties: the plain text and the
/// criteria (`SearchCriterion::matches` is the rule).
fn matches_query(data: &TenantData, principal: &Principal, query: &PrincipalQuery) -> bool {
    let addresses: Vec<CalendarUserAddress> = data
        .addresses
        .get(&principal.id)
        .map(|stored| stored.iter().map(|address| address.address.clone()).collect())
        .unwrap_or_default();
    let satisfied =
        |criterion: &SearchCriterion| criterion.matches(principal.name.as_str(), &principal.display_name, &addresses);
    let text = query.text.is_empty() || satisfied(&SearchCriterion::contains(query.text.as_str()));
    let criteria = query.criteria.is_empty()
        || if query.any_of {
            query.criteria.iter().any(satisfied)
        } else {
            query.criteria.iter().all(satisfied)
        };
    text && criteria
}

#[async_trait]
impl PrincipalRepo for MemTx {
    async fn get(&mut self, id: PrincipalId) -> Result<Principal, StoreError> {
        observed!(
            "principals.get",
            self.view().principals.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn get_by_name(&mut self, name: &PrincipalName) -> Result<Principal, StoreError> {
        observed!(
            "principals.get_by_name",
            self.view()
                .principals
                .values()
                .find(|principal| &principal.name == name)
                .cloned()
                .ok_or(StoreError::NotFound)
        )
    }

    async fn find_by_external_ref(&mut self, external_ref: &str) -> Result<Option<Principal>, StoreError> {
        observed!(
            "principals.find_by_external_ref",
            Ok(self
                .view()
                .principals
                .values()
                .find(|principal| principal.external_ref.as_deref() == Some(external_ref))
                .cloned())
        )
    }

    async fn find_by_address(&mut self, address: &CalendarUserAddress) -> Result<Option<Principal>, StoreError> {
        observed!("principals.find_by_address", {
            let wanted = address.as_str().to_lowercase();
            let data = self.view();
            Ok(data
                .addresses
                .iter()
                .find(|(_, addresses)| {
                    addresses
                        .iter()
                        .any(|candidate| candidate.address.as_str().to_lowercase() == wanted)
                })
                .and_then(|(principal, _)| data.principals.get(principal))
                .cloned())
        })
    }

    async fn find_by_addresses(
        &mut self,
        addresses: &[CalendarUserAddress],
    ) -> Result<Vec<(CalendarUserAddress, Principal)>, StoreError> {
        observed!("principals.find_by_addresses", {
            if addresses.is_empty() {
                return Ok(Vec::new());
            }
            let data = self.view();
            // Every stored address once, by its lower-case form, then one look-up per requested address.
            let owners: HashMap<String, PrincipalId> = data
                .addresses
                .iter()
                .flat_map(|(principal, stored)| {
                    stored
                        .iter()
                        .map(move |address| (address.address.as_str().to_lowercase(), *principal))
                })
                .collect();
            let mut asked: HashSet<&CalendarUserAddress> = HashSet::with_capacity(addresses.len());
            let mut found: Vec<(CalendarUserAddress, Principal)> = Vec::new();
            for address in addresses {
                if !asked.insert(address) {
                    continue;
                }
                if let Some(principal) = owners
                    .get(&address.as_str().to_lowercase())
                    .and_then(|owner| data.principals.get(owner))
                {
                    found.push((address.clone(), principal.clone()));
                }
            }
            Ok(found)
        })
    }

    async fn get_many(&mut self, ids: &[PrincipalId]) -> Result<Vec<Principal>, StoreError> {
        observed!("principals.get_many", {
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let data = self.view();
            let mut seen = BTreeSet::new();
            Ok(ids
                .iter()
                .filter(|id| seen.insert(**id))
                .filter_map(|id| data.principals.get(id))
                .cloned()
                .collect())
        })
    }

    async fn get_many_by_name(&mut self, names: &[PrincipalName]) -> Result<Vec<Principal>, StoreError> {
        observed!("principals.get_many_by_name", {
            if names.is_empty() {
                return Ok(Vec::new());
            }
            let data = self.view();
            let by_name: HashMap<&PrincipalName, &Principal> = data
                .principals
                .values()
                .map(|principal| (&principal.name, principal))
                .collect();
            let mut seen = BTreeSet::new();
            Ok(names
                .iter()
                .filter(|name| seen.insert(name.as_str()))
                .filter_map(|name| by_name.get(name).copied())
                .cloned()
                .collect())
        })
    }

    async fn list(&mut self, filter: &PrincipalFilter, page: PageReq) -> Result<StorePage<Principal>, StoreError> {
        observed!("principals.list", {
            let matching = self.view().principals.values().filter(|principal| {
                filter.kind.is_none_or(|kind| principal.kind == kind)
                    && filter
                        .external_ref
                        .as_ref()
                        .is_none_or(|external_ref| principal.external_ref.as_ref() == Some(external_ref))
                    && match filter.status {
                        Some(status) => principal.status == status,
                        None => filter.include_deleted || principal.status != PrincipalStatus::Deleted,
                    }
            });
            Ok(paginate(matching.cloned(), &page, |principal| principal.id.as_uuid()))
        })
    }

    async fn search(&mut self, query: &PrincipalQuery) -> Result<Vec<PrincipalMatch>, StoreError> {
        observed!("principals.search", {
            let kinds: Vec<PrincipalKind> = if query.kinds.is_empty() {
                vec![PrincipalKind::User, PrincipalKind::Group, PrincipalKind::Resource]
            } else {
                query.kinds.clone()
            };
            let data = self.view();
            let mut found: Vec<&Principal> = data
                .principals
                .values()
                .filter(|principal| {
                    principal.status == PrincipalStatus::Active
                        && kinds.contains(&principal.kind)
                        && matches_query(data, principal, query)
                })
                .collect();
            found.sort_by(|left, right| {
                left.display_name
                    .cmp(&right.display_name)
                    .then_with(|| left.id.cmp(&right.id))
            });
            let limit = usize::try_from(query.limit.min(MAX_PAGE_LIMIT)).unwrap_or(usize::MAX);
            Ok(found
                .into_iter()
                .take(limit)
                .map(|principal| PrincipalMatch {
                    principal: principal.clone(),
                    addresses: sorted_addresses(data, principal.id),
                })
                .collect())
        })
    }

    async fn create(&mut self, principal: Principal) -> Result<Principal, StoreError> {
        observed!("principals.create", {
            no_nul(
                "principal text",
                [Some(principal.display_name.as_str()), principal.external_ref.as_deref()],
            )?;
            let now = self.now();
            let tenant = self.tenant;
            let epochs = [self.ids.new_id(), self.ids.new_id(), self.ids.new_id()];
            let data = self.writable()?;
            if data.principals.contains_key(&principal.id) {
                return Err(misuse("a principal with this id exists already"));
            }
            if data.principals.values().any(|other| other.name == principal.name) {
                return Err(StoreError::UniqueViolation(UniqueKey::PrincipalName));
            }
            if let Some(external_ref) = &principal.external_ref
                && data
                    .principals
                    .values()
                    .any(|other| other.external_ref.as_ref() == Some(external_ref))
            {
                return Err(StoreError::UniqueViolation(UniqueKey::ExternalRef));
            }
            let stored = Principal {
                tenant_id: tenant,
                deleted_at: principal.deleted_at.map(micros),
                created_at: now,
                updated_at: now,
                version: 1,
                ..principal
            };
            let fresh = |epoch| davhaven_ports::SyncPosition {
                epoch,
                seq: 0,
                min_seq: 0,
            };
            data.sync.insert(
                stored.id,
                PrincipalSync {
                    home: fresh(epochs[0]),
                    inbox: fresh(epochs[1]),
                    notifications: fresh(epochs[2]),
                },
            );
            data.principals.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn update(&mut self, principal: Principal, expected_version: i64) -> Result<Principal, StoreError> {
        observed!("principals.update", {
            let now = self.now();
            let data = self.writable()?;
            let current = data.principals.get(&principal.id).ok_or(StoreError::NotFound)?;
            if current.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            if let Some(external_ref) = &principal.external_ref
                && data
                    .principals
                    .values()
                    .any(|other| other.id != principal.id && other.external_ref.as_ref() == Some(external_ref))
            {
                return Err(StoreError::UniqueViolation(UniqueKey::ExternalRef));
            }
            let stored = data.principals.get_mut(&principal.id).ok_or(StoreError::NotFound)?;
            stored.display_name = principal.display_name;
            stored.email = principal.email;
            stored.locale = principal.locale;
            stored.timezone = principal.timezone;
            stored.external_ref = principal.external_ref;
            stored.status = principal.status;
            stored.deleted_at = principal.deleted_at.map(micros);
            stored.updated_at = now;
            stored.version += 1;
            Ok(stored.clone())
        })
    }

    async fn bump_credential_generation(&mut self, id: PrincipalId) -> Result<i32, StoreError> {
        observed!("principals.bump_credential_generation", {
            let stored = self.writable()?.principals.get_mut(&id).ok_or(StoreError::NotFound)?;
            stored.credential_generation = stored.credential_generation.saturating_add(1);
            Ok(stored.credential_generation)
        })
    }

    async fn addresses(&mut self, id: PrincipalId) -> Result<Vec<PrincipalAddress>, StoreError> {
        observed!("principals.addresses", {
            let data = self.view();
            if !data.principals.contains_key(&id) {
                return Err(StoreError::NotFound);
            }
            Ok(sorted_addresses(data, id))
        })
    }

    async fn addresses_many(&mut self, ids: &[PrincipalId]) -> Result<Vec<PrincipalAddress>, StoreError> {
        observed!("principals.addresses_many", {
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let data = self.view();
            let wanted: BTreeSet<PrincipalId> = ids.iter().copied().collect();
            Ok(wanted
                .into_iter()
                .filter(|id| data.principals.contains_key(id))
                .flat_map(|id| sorted_addresses(data, id))
                .collect())
        })
    }

    async fn set_addresses(&mut self, id: PrincipalId, addresses: Vec<PrincipalAddress>) -> Result<(), StoreError> {
        observed!("principals.set_addresses", {
            if addresses.iter().any(|address| address.principal_id != id) {
                return Err(misuse("an address names another principal than the one it is set for"));
            }
            if addresses.iter().filter(|address| address.primary).count() > 1 {
                return Err(misuse("a principal has at most one primary address"));
            }
            let mut seen = BTreeSet::new();
            for address in &addresses {
                if !seen.insert(address.address.as_str().to_lowercase()) {
                    return Err(StoreError::UniqueViolation(UniqueKey::Address));
                }
            }
            let data = self.writable()?;
            if !data.principals.contains_key(&id) {
                return Err(StoreError::NotFound);
            }
            if address_taken(data, id, &addresses) {
                return Err(StoreError::UniqueViolation(UniqueKey::Address));
            }
            data.addresses.insert(id, addresses);
            Ok(())
        })
    }

    async fn purge(&mut self, id: PrincipalId) -> Result<(), StoreError> {
        observed!("principals.purge", {
            let now = self.now();
            let data = self.writable()?;
            if !data.principals.contains_key(&id) {
                return Err(StoreError::NotFound);
            }
            data.remove_principal(id, now);
            Ok(())
        })
    }
}

#[async_trait]
impl MembershipRepo for MemTx {
    async fn members(&mut self, group: PrincipalId) -> Result<Vec<PrincipalId>, StoreError> {
        observed!("memberships.members", {
            let data = self.view();
            if !data.principals.contains_key(&group) {
                return Err(StoreError::NotFound);
            }
            Ok(data
                .memberships
                .iter()
                .filter(|(candidate, _)| *candidate == group)
                .map(|(_, member)| *member)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect())
        })
    }

    async fn groups_of(&mut self, member: PrincipalId) -> Result<Vec<PrincipalId>, StoreError> {
        observed!("memberships.groups_of", Ok(self.view().groups_of(member)))
    }

    async fn members_of_many(&mut self, groups: &[PrincipalId]) -> Result<Vec<(PrincipalId, PrincipalId)>, StoreError> {
        observed!("memberships.members_of_many", {
            if groups.is_empty() {
                return Ok(Vec::new());
            }
            let wanted: BTreeSet<PrincipalId> = groups.iter().copied().collect();
            Ok(self
                .view()
                .memberships
                .iter()
                .filter(|(group, _)| wanted.contains(group))
                .copied()
                .collect())
        })
    }

    async fn groups_of_many(&mut self, members: &[PrincipalId]) -> Result<Vec<(PrincipalId, PrincipalId)>, StoreError> {
        observed!("memberships.groups_of_many", {
            if members.is_empty() {
                return Ok(Vec::new());
            }
            let wanted: BTreeSet<PrincipalId> = members.iter().copied().collect();
            let mut pairs: Vec<(PrincipalId, PrincipalId)> = self
                .view()
                .memberships
                .iter()
                .filter(|(_, member)| wanted.contains(member))
                .map(|(group, member)| (*member, *group))
                .collect();
            pairs.sort_unstable();
            Ok(pairs)
        })
    }

    async fn set_members(&mut self, group: PrincipalId, members: &[PrincipalId]) -> Result<MembershipDiff, StoreError> {
        observed!("memberships.set_members", {
            let wanted: BTreeSet<PrincipalId> = members.iter().copied().collect();
            let data = self.writable()?;
            if !data.principals.contains_key(&group)
                || wanted.iter().any(|member| !data.principals.contains_key(member))
            {
                return Err(StoreError::NotFound);
            }
            let current: BTreeSet<PrincipalId> = data
                .memberships
                .iter()
                .filter(|(candidate, _)| *candidate == group)
                .map(|(_, member)| *member)
                .collect();
            let added: Vec<PrincipalId> = wanted.difference(&current).copied().collect();
            let removed: Vec<PrincipalId> = current.difference(&wanted).copied().collect();
            for member in &removed {
                data.memberships.remove(&(group, *member));
            }
            for member in &added {
                data.memberships.insert((group, *member));
            }
            Ok(MembershipDiff { added, removed })
        })
    }

    async fn add_member(&mut self, group: PrincipalId, member: PrincipalId) -> Result<bool, StoreError> {
        observed!("memberships.add_member", {
            let data = self.writable()?;
            if !data.principals.contains_key(&group) || !data.principals.contains_key(&member) {
                return Err(StoreError::NotFound);
            }
            Ok(data.memberships.insert((group, member)))
        })
    }

    async fn remove_member(&mut self, group: PrincipalId, member: PrincipalId) -> Result<bool, StoreError> {
        observed!("memberships.remove_member", {
            let data = self.writable()?;
            if !data.principals.contains_key(&group) {
                return Err(StoreError::NotFound);
            }
            Ok(data.memberships.remove(&(group, member)))
        })
    }
}
