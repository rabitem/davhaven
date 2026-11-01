//! Repositories for the tenant row, principals, their addresses and group memberships.

use std::collections::HashSet;

use async_trait::async_trait;
use davhaven_domain::{
    CalendarUserAddress, Principal, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus, SearchCriterion, Tenant,
};

use super::{PageReq, StorePage};
use crate::error::StoreError;

/// The tenant row of the transaction's tenant.
#[async_trait]
pub trait TenantRepo: Send {
    /// The tenant, including its settings (`TenantSettings`).
    ///
    /// # Errors
    ///
    /// `NotFound` when the transaction's tenant does not exist (or was deleted).
    async fn get(&mut self) -> Result<Tenant, StoreError>;
}

/// An address of a principal (`principal_addresses`).
///
/// Addresses are unique per tenant, case-insensitively; the addresses of deleted principals stay reserved until
/// the principal is purged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalAddress {
    /// The principal the address belongs to.
    pub principal_id: PrincipalId,
    /// The normalized calendar user address.
    pub address: CalendarUserAddress,
    /// Whether this is the principal's primary address (at most one per principal).
    pub primary: bool,
}

/// Filter of [`PrincipalRepo::list`]. Every set field must match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrincipalFilter {
    /// Only principals of this kind.
    pub kind: Option<PrincipalKind>,
    /// Only the principal with this external reference.
    pub external_ref: Option<String>,
    /// Only principals with this status.
    pub status: Option<PrincipalStatus>,
    /// Include principals with status `Deleted` (hidden, awaiting purge). They are excluded by default.
    pub include_deleted: bool,
}

/// Query of [`PrincipalRepo::search`] (principal search in CalDAV clients).
///
/// A principal is found when **every** condition holds: it is active and of one of the `kinds`; it contains `text`
/// (unless that is empty) in its name, display name or a stored address; and it satisfies the `criteria`, all of
/// them or, with `any_of`, at least one of them (no criteria are satisfied by every principal). Every condition is
/// applied before the `limit` cuts the result, so a hit is never lost to a limit that was applied to a broader
/// search. Matching ignores case ([`SearchCriterion::matches`] is the rule).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrincipalQuery {
    /// The text to look for in names, display names and addresses, case-insensitively, as a substring; empty means
    /// no such condition.
    pub text: String,
    /// Only principals of these kinds; empty means users, groups and resources.
    pub kinds: Vec<PrincipalKind>,
    /// The most hits to return.
    pub limit: u32,
    /// Further conditions on the properties a search can look into.
    pub criteria: Vec<SearchCriterion>,
    /// `criteria` are satisfied by one of them instead of all of them.
    pub any_of: bool,
}

/// A search hit: the principal and its addresses.
#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalMatch {
    /// The matching principal (only active principals are found).
    pub principal: Principal,
    /// The principal's addresses, primary first.
    pub addresses: Vec<PrincipalAddress>,
}

/// Principals of the transaction's tenant.
#[async_trait]
pub trait PrincipalRepo: Send {
    /// The principal with `id`, whatever its status (callers check suspended and deleted principals).
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: PrincipalId) -> Result<Principal, StoreError>;

    /// The principal with the immutable login name `name`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_by_name(&mut self, name: &PrincipalName) -> Result<Principal, StoreError>;

    /// The principal with the external reference, if any, whatever its status: the external reference of a deleted principal
    /// stays reserved until the purge and resolves, so callers can tell "taken" from "free" (as for
    /// [`find_by_address`](Self::find_by_address)).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_by_external_ref(&mut self, external_ref: &str) -> Result<Option<Principal>, StoreError>;

    /// The principal that owns `address` (case-insensitive match on the normalized form), whatever its status:
    /// reserved addresses of deleted principals resolve too, so callers can tell "taken" from "free".
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_by_address(&mut self, address: &CalendarUserAddress) -> Result<Option<Principal>, StoreError>;

    /// [`find_by_address`](Self::find_by_address) for several addresses at once: one entry for every distinct address
    /// of the request that has an owner, whatever the owner's status, in the order the addresses were given (an
    /// address that is repeated answers once). Two principals never share an address, but one principal may own
    /// several of the requested ones and then appears with each of them. Additive method: the default asks
    /// [`find_by_address`](Self::find_by_address) once per address; an adapter that can resolve all of them in one
    /// query overrides it (the PostgreSQL adapter does, `ENGINEERING_RULES` R14), and every caller (a write with up
    /// to 200 attendees per instance) benefits.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_by_addresses(
        &mut self,
        addresses: &[CalendarUserAddress],
    ) -> Result<Vec<(CalendarUserAddress, Principal)>, StoreError> {
        let mut asked: HashSet<&CalendarUserAddress> = HashSet::with_capacity(addresses.len());
        let mut found: Vec<(CalendarUserAddress, Principal)> = Vec::new();
        for address in addresses {
            if !asked.insert(address) {
                continue;
            }
            if let Some(principal) = self.find_by_address(address).await? {
                found.push((address.clone(), principal));
            }
        }
        Ok(found)
    }

    /// The principals with the given ids, in the order of `ids`, whatever their status; unknown ids are skipped and
    /// an id that is repeated answers once. Additive method: the default reads one principal per id; an adapter that
    /// can read them in one query overrides it (the PostgreSQL adapter does, `ENGINEERING_RULES` R14).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn get_many(&mut self, ids: &[PrincipalId]) -> Result<Vec<Principal>, StoreError> {
        let mut asked: HashSet<PrincipalId> = HashSet::with_capacity(ids.len());
        let mut principals: Vec<Principal> = Vec::with_capacity(ids.len());
        for id in ids {
            if !asked.insert(*id) {
                continue;
            }
            match self.get(*id).await {
                Ok(principal) => principals.push(principal),
                Err(StoreError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(principals)
    }

    /// The principals with the given immutable login names, in the order of `names`, whatever their status; unknown
    /// names are skipped and a name that is repeated answers once. Additive method like
    /// [`get_many`](Self::get_many): the default reads one principal per name.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn get_many_by_name(&mut self, names: &[PrincipalName]) -> Result<Vec<Principal>, StoreError> {
        let mut asked: HashSet<&PrincipalName> = HashSet::with_capacity(names.len());
        let mut principals: Vec<Principal> = Vec::with_capacity(names.len());
        for name in names {
            if !asked.insert(name) {
                continue;
            }
            match self.get_by_name(name).await {
                Ok(principal) => principals.push(principal),
                Err(StoreError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(principals)
    }

    /// Lists principals in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(&mut self, filter: &PrincipalFilter, page: PageReq) -> Result<StorePage<Principal>, StoreError>;

    /// Searches active principals by name, display name and address. Results are ordered by display name, then
    /// id.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn search(&mut self, query: &PrincipalQuery) -> Result<Vec<PrincipalMatch>, StoreError>;

    /// Creates a principal.
    ///
    /// # Errors
    ///
    /// `UniqueViolation` of `PrincipalName` or `ExternalRef`.
    async fn create(&mut self, principal: Principal) -> Result<Principal, StoreError>;

    /// Replaces a principal if its stored version equals `expected_version`. The immutable `name` cannot change.
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed` (stale version) and `UniqueViolation` of `ExternalRef`.
    async fn update(&mut self, principal: Principal, expected_version: i64) -> Result<Principal, StoreError>;

    /// Increments `credential_generation` atomically, which invalidates cached credential verifications of the
    /// principal, and returns the new value. Does not change `version`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn bump_credential_generation(&mut self, id: PrincipalId) -> Result<i32, StoreError>;

    /// The addresses of the principal, primary first, then in address order.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist.
    async fn addresses(&mut self, id: PrincipalId) -> Result<Vec<PrincipalAddress>, StoreError>;

    /// The addresses of several principals at once: every stored address of the given principals, grouped by
    /// principal in ascending id order and, within a principal, in the order of [`addresses`](Self::addresses)
    /// (primary first, then by address). Unknown principals are skipped and an id that is repeated counts once.
    /// Additive method: the default asks [`addresses`](Self::addresses) once per principal; an adapter that can read
    /// them in one query overrides it (the PostgreSQL adapter does, `ENGINEERING_RULES` R14).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn addresses_many(&mut self, ids: &[PrincipalId]) -> Result<Vec<PrincipalAddress>, StoreError> {
        let mut wanted: Vec<PrincipalId> = ids.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut found = Vec::new();
        for id in wanted {
            match self.addresses(id).await {
                Ok(addresses) => found.extend(addresses),
                Err(StoreError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(found)
    }

    /// Replaces the principal's addresses with `addresses` (all must name `id`; at most one primary).
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist and `UniqueViolation` of `Address` when another principal
    /// (even a deleted one) owns an address.
    async fn set_addresses(&mut self, id: PrincipalId, addresses: Vec<PrincipalAddress>) -> Result<(), StoreError>;

    /// Removes the principal and everything that belongs to it for good (retention purge): memberships, owned
    /// calendars with their objects, bindings, grants, credentials, notifications and inbox items.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn purge(&mut self, id: PrincipalId) -> Result<(), StoreError>;
}

/// The change of a membership set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MembershipDiff {
    /// Members that were added, in id order.
    pub added: Vec<PrincipalId>,
    /// Members that were removed, in id order.
    pub removed: Vec<PrincipalId>,
}

impl MembershipDiff {
    /// Whether nothing changed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Group memberships of the transaction's tenant. Members are principals of the same tenant; groups can contain
/// users, resources and services (nesting is not expanded).
#[async_trait]
pub trait MembershipRepo: Send {
    /// The members of `group`, in id order.
    ///
    /// # Errors
    ///
    /// `NotFound` when the group does not exist.
    async fn members(&mut self, group: PrincipalId) -> Result<Vec<PrincipalId>, StoreError>;

    /// The groups `member` currently belongs to, in id order.
    ///
    /// # Errors
    ///
    /// Store failures only; a principal without groups yields an empty list.
    async fn groups_of(&mut self, member: PrincipalId) -> Result<Vec<PrincipalId>, StoreError>;

    /// [`members`](Self::members) for several groups at once, as `(group, member)` pairs in ascending order of group
    /// id and then member id. Groups that do not exist are skipped and an id that is repeated counts once. Additive
    /// method: the default asks [`members`](Self::members) once per group; an adapter that can read them in one
    /// query overrides it (`ENGINEERING_RULES` R14).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn members_of_many(&mut self, groups: &[PrincipalId]) -> Result<Vec<(PrincipalId, PrincipalId)>, StoreError> {
        let mut wanted: Vec<PrincipalId> = groups.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut pairs = Vec::new();
        for group in wanted {
            match self.members(group).await {
                Ok(members) => pairs.extend(members.into_iter().map(|member| (group, member))),
                Err(StoreError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(pairs)
    }

    /// [`groups_of`](Self::groups_of) for several principals at once, as `(member, group)` pairs in ascending order
    /// of member id and then group id; an id that is repeated counts once. Additive method: the default asks
    /// [`groups_of`](Self::groups_of) once per principal; an adapter that can read them in one query overrides it
    /// (`ENGINEERING_RULES` R14).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn groups_of_many(&mut self, members: &[PrincipalId]) -> Result<Vec<(PrincipalId, PrincipalId)>, StoreError> {
        let mut wanted: Vec<PrincipalId> = members.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut pairs = Vec::new();
        for member in wanted {
            pairs.extend(self.groups_of(member).await?.into_iter().map(|group| (member, group)));
        }
        Ok(pairs)
    }

    /// Replaces the member set of `group` and reports what changed.
    ///
    /// # Errors
    ///
    /// `NotFound` when the group or any member does not exist.
    async fn set_members(&mut self, group: PrincipalId, members: &[PrincipalId]) -> Result<MembershipDiff, StoreError>;

    /// Adds a member; `false` when it already was one.
    ///
    /// # Errors
    ///
    /// `NotFound` when the group or the member does not exist.
    async fn add_member(&mut self, group: PrincipalId, member: PrincipalId) -> Result<bool, StoreError>;

    /// Removes a member; `false` when it was not one.
    ///
    /// # Errors
    ///
    /// `NotFound` when the group does not exist.
    async fn remove_member(&mut self, group: PrincipalId, member: PrincipalId) -> Result<bool, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_default_to_everything_but_deleted() {
        let filter = PrincipalFilter::default();
        assert!(filter.kind.is_none() && filter.external_ref.is_none() && filter.status.is_none());
        assert!(!filter.include_deleted);
    }

    #[test]
    fn membership_diffs_know_when_nothing_changed() {
        assert!(MembershipDiff::default().is_empty());
        let diff = MembershipDiff {
            added: vec![PrincipalId::from_uuid(uuid::Uuid::from_u128(1))],
            removed: Vec::new(),
        };
        assert!(!diff.is_empty());
    }
}
