//! Principals: users, groups, resources and services, their memberships and their DAV properties.

use async_trait::async_trait;
use davhaven_domain::{
    CalendarUserAddress, ErrorKind, PrincipalId, PrincipalKind, PrincipalName, RequestContext, ResourcePath,
    SearchCriterion,
};
use davhaven_wire::{MembershipSet, Page, PrincipalView, PrincipalWrite};
use futures::future::join_all;

use super::common::{Conditions, MergePatch, PageRequest, Upserted};
use crate::error::{AppError, AppResult};

/// The natural key and the body of a principal `PUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalSpec {
    /// The immutable principal name from the path.
    pub name: PrincipalName,
    /// The request body.
    pub body: PrincipalWrite,
}

/// The filters of `GET …/principals`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrincipalFilter {
    /// Only principals of this kind.
    pub kind: Option<PrincipalKind>,
    /// Only the principal with this external reference.
    pub external_ref: Option<String>,
}

/// The options of a principal `DELETE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeleteOptions {
    /// Purge immediately instead of after `retention.principal_purge_days`.
    pub purge: bool,
    /// Send CANCEL messages for events the principal organizes in group calendars (`?notify_attendees=true`).
    pub notify_attendees: bool,
    /// The conditional headers; `If-Match` is required for calendars and principals.
    pub conditions: Conditions,
}

/// The shortest search text (PLAN 2.9); a shorter one is `Invalid` with the code `too-short`.
pub const MIN_SEARCH_CHARS: usize = 2;

/// The most hits of a principal search (PLAN 2.9).
pub const MAX_SEARCH_HITS: u32 = 50;

/// The longest text that can find anything: no calendar user address is longer, so a longer text is no part of any
/// name or address and finds nobody.
pub const MAX_SEARCH_CHARS: usize = CalendarUserAddress::MAX_LEN;

/// A principal search (`DAV:principal-property-search`, `CS:calendarserver-principal-search`).
///
/// A principal is found when it is active and of one of the `kinds`, mentions `query` (unless that is empty) in its
/// name, display name or a stored address, and satisfies the `criteria`: all of them, or at least one of them with
/// `any_of`. **Every condition is applied before the limit**, so a search that names several terms is not answered
/// from the first hits of one of them.
///
/// The rules about the texts keep a search from listing the tenant: a text of fewer than [`MIN_SEARCH_CHARS`]
/// characters is `Invalid` (`too-short`) when it is the only condition or when one of several is enough (`any_of`);
/// with all conditions required a short text is a condition like any other as long as one text is long enough.
/// A text longer than [`MAX_SEARCH_CHARS`] finds nobody (and is left out of an `any_of` search).
/// [`is_askable`](PrincipalSearch::is_askable) says whether a search passes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PrincipalSearch {
    /// The text to look for in names, display names and addresses; may be empty when `criteria` are given.
    pub query: String,
    /// The most hits to return (at most [`MAX_SEARCH_HITS`]).
    pub limit: Option<u32>,
    /// Only principals of these kinds, applied before the limit. Empty means users, groups and resources; service
    /// principals are never found, whatever is asked for, and a list that names nothing else finds nothing.
    pub kinds: Vec<PrincipalKind>,
    /// Further conditions on the properties of the principal.
    pub criteria: Vec<SearchCriterion>,
    /// One satisfied criterion is enough instead of all of them.
    pub any_of: bool,
}

/// What a search comes to once its texts are judged ([`PrincipalSearch::plan`]): the one place that decides which
/// searches are asked, shared by every implementation of [`PrincipalService`] so that the real application and the
/// fake one answer alike.
#[derive(Debug, PartialEq, Eq)]
pub enum SearchPlan {
    /// No principal can satisfy the search: the answer is empty and the store is not asked.
    Nothing,
    /// The search has no text that is long enough: refused with `too-short`.
    TooShort,
    /// Ask the store for the text and the criteria that remain.
    Ask {
        /// The required text, trimmed; empty when the search has none.
        text: String,
        /// The criteria, trimmed, without those of `any_of` searches that no principal can satisfy.
        criteria: Vec<SearchCriterion>,
    },
}

impl PrincipalSearch {
    /// A search for a text in names, display names and addresses.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            ..Self::default()
        }
    }

    /// The same search returning at most `limit` hits.
    #[must_use]
    pub fn limited(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// The same search restricted to principals of `kinds`.
    #[must_use]
    pub fn of_kinds(mut self, kinds: Vec<PrincipalKind>) -> Self {
        self.kinds = kinds;
        self
    }

    /// The same search with `criteria`, all of which have to be satisfied or, with `any_of`, one of them.
    #[must_use]
    pub fn matching(mut self, criteria: Vec<SearchCriterion>, any_of: bool) -> Self {
        self.criteria = criteria;
        self.any_of = any_of;
        self
    }

    /// Whether the application answers the search with a lookup: it has a text that is long enough and nothing that
    /// no principal can satisfy. A protocol layer that wants to answer a search that cannot be asked with an empty
    /// result instead of an error asks this first.
    pub fn is_askable(&self) -> bool {
        matches!(self.plan(), SearchPlan::Ask { .. })
    }

    /// Judges the texts of the search (see the type documentation).
    pub fn plan(&self) -> SearchPlan {
        let length = |text: &str| text.trim().chars().count();
        let too_long = |text: &str| length(text) > MAX_SEARCH_CHARS;
        let text = self.query.trim();
        if too_long(text) {
            return SearchPlan::Nothing;
        }
        if !text.is_empty() && length(text) < MIN_SEARCH_CHARS {
            return SearchPlan::TooShort;
        }
        let trimmed = |criterion: &SearchCriterion| SearchCriterion {
            text: criterion.text.trim().to_owned(),
            ..criterion.clone()
        };
        let mut criteria: Vec<SearchCriterion> = self.criteria.iter().map(trimmed).collect();
        if self.any_of {
            // One satisfied criterion is enough, so a short one would list everybody.
            if criteria
                .iter()
                .any(|criterion| length(&criterion.text) < MIN_SEARCH_CHARS)
            {
                return SearchPlan::TooShort;
            }
            let named = !criteria.is_empty();
            criteria.retain(|criterion| !too_long(&criterion.text));
            if named && criteria.is_empty() {
                return SearchPlan::Nothing;
            }
            if !named && text.is_empty() {
                return SearchPlan::TooShort;
            }
        } else {
            if criteria.iter().any(|criterion| too_long(&criterion.text)) {
                return SearchPlan::Nothing;
            }
            // Short texts are conditions like the others, next to one that is long enough.
            let long_enough = length(text) >= MIN_SEARCH_CHARS
                || criteria
                    .iter()
                    .any(|criterion| length(&criterion.text) >= MIN_SEARCH_CHARS);
            if !long_enough {
                return SearchPlan::TooShort;
            }
        }
        SearchPlan::Ask {
            text: text.to_owned(),
            criteria,
        }
    }
}

/// The answer to a principal search.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrincipalSearchResult {
    /// The principals found, at most the limit of the search, ordered by display name.
    pub hits: Vec<PrincipalHit>,
    /// Whether more principals match than the hits hold: the limit cut the answer.
    pub truncated: bool,
}

/// One search hit: display name and addresses only (PLAN 2.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalHit {
    /// The principal resource.
    pub path: ResourcePath,
    /// The principal id.
    pub id: PrincipalId,
    /// The immutable name.
    pub name: PrincipalName,
    /// The display name.
    pub display_name: String,
    /// What the principal represents.
    pub kind: PrincipalKind,
    /// The calendar user addresses, `mailto:` addresses first.
    pub addresses: Vec<CalendarUserAddress>,
}

/// The properties of a principal resource that PROPFIND needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalProps {
    /// The principal resource.
    pub path: ResourcePath,
    /// The principal id.
    pub id: PrincipalId,
    /// The immutable name.
    pub name: PrincipalName,
    /// The display name.
    pub display_name: String,
    /// What the principal represents.
    pub kind: PrincipalKind,
    /// `calendar-user-address-set`: the primary address, further addresses, the principal URL and `urn:uuid`
    /// (and the login address when the tenant says so).
    pub addresses: Vec<CalendarUserAddress>,
    /// The calendar home.
    pub home: ResourcePath,
    /// The scheduling inbox.
    pub inbox: ResourcePath,
    /// The scheduling outbox.
    pub outbox: ResourcePath,
    /// The notification collection.
    pub notifications: ResourcePath,
    /// For groups: the member principals (`DAV:group-member-set`).
    pub group_members: Vec<ResourcePath>,
    /// The groups the principal belongs to (`DAV:group-membership`).
    pub group_membership: Vec<ResourcePath>,
}

/// How an address relates to the caller's tenant (PLAN 2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressClass {
    /// The address belongs to a principal of the same tenant.
    Internal {
        /// The principal.
        principal: PrincipalId,
        /// The principal's immutable name.
        name: PrincipalName,
        /// What the principal represents (groups are not expanded in 1.0).
        kind: PrincipalKind,
    },
    /// A mail address outside the tenant, including addresses of other tenants.
    External,
    /// An address that cannot receive scheduling messages: a `urn:uuid` or URL that resolves to nothing.
    Unresolvable,
}

/// Principal management and lookup.
#[async_trait]
pub trait PrincipalService: Send + Sync {
    /// Lists the principals of the tenant ordered by id.
    ///
    /// # Errors
    ///
    /// `Forbidden` without `principals:read`, `Invalid` for a bad cursor.
    async fn list(
        &self,
        ctx: &RequestContext,
        filter: PrincipalFilter,
        page: PageRequest,
    ) -> AppResult<Page<PrincipalView>>;

    /// Reads a principal. Deleted principals are invisible (404).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn get(&self, ctx: &RequestContext, name: &PrincipalName) -> AppResult<PrincipalView>;

    /// Creates or replaces a principal (declarative provisioning: the same body twice changes nothing).
    ///
    /// # Errors
    ///
    /// `PreconditionFailed`, `Conflict` for taken names, addresses or external references, `Invalid`,
    /// `Forbidden`.
    async fn upsert(
        &self,
        ctx: &RequestContext,
        spec: PrincipalSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<PrincipalView>>;

    /// Changes a principal with a JSON Merge Patch.
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed`, `Invalid`, `Conflict`, `Forbidden`.
    async fn patch(
        &self,
        ctx: &RequestContext,
        name: &PrincipalName,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<PrincipalView>;

    /// Deletes a principal: credentials, RSVP tokens and shares are revoked immediately, the principal is
    /// hidden and purged later (or at once with `purge`). Requires `If-Match`.
    ///
    /// # Errors
    ///
    /// `PreconditionRequired`, `PreconditionFailed`, `NotFound`, `Forbidden`.
    async fn delete(&self, ctx: &RequestContext, name: &PrincipalName, options: DeleteOptions) -> AppResult<()>;

    /// The member set of a group.
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown principals, `Invalid` when the principal is not a group, `Forbidden`.
    async fn members(&self, ctx: &RequestContext, group: &PrincipalName) -> AppResult<MembershipSet>;

    /// Replaces the member set of a group (`PUT …/members`).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Invalid` for unknown members or members that are groups, `Forbidden`.
    async fn set_members(
        &self,
        ctx: &RequestContext,
        group: &PrincipalName,
        members: Vec<PrincipalName>,
    ) -> AppResult<MembershipSet>;

    /// Adds one member (`PUT …/members/{member}`); adding an existing member changes nothing.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Invalid`, `Forbidden`.
    async fn add_member(&self, ctx: &RequestContext, group: &PrincipalName, member: &PrincipalName) -> AppResult<()>;

    /// Removes one member (`DELETE …/members/{member}`); removing a non-member changes nothing.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn remove_member(&self, ctx: &RequestContext, group: &PrincipalName, member: &PrincipalName)
    -> AppResult<()>;

    /// Searches the principals of the caller's tenant by name, display name and address.
    ///
    /// # Errors
    ///
    /// `Invalid` for queries shorter than two characters, `Forbidden`.
    async fn search(&self, ctx: &RequestContext, search: PrincipalSearch) -> AppResult<Vec<PrincipalHit>>;

    /// [`search`](Self::search) that also says whether the limit cut the answer: the hits and `truncated`, which is
    /// set when more principals match than the hits hold (the store is asked for one more than the limit).
    ///
    /// # Errors
    ///
    /// As [`search`](Self::search); the default answers `Unsupported`.
    async fn find_principals(&self, ctx: &RequestContext, search: PrincipalSearch) -> AppResult<PrincipalSearchResult> {
        let _ = (ctx, search);
        Err(AppError::unsupported())
    }

    /// The DAV properties of a principal resource.
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown principals and for principals of other tenants.
    async fn dav_properties(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<PrincipalProps>;

    /// The DAV properties of several principal resources at once, for `expand-property` (the members of a group,
    /// the groups of a principal). Principals that do not exist or are invisible to the caller are left out; the
    /// others come in the order of `paths`.
    ///
    /// Implementations read all principals with one query. The default asks
    /// [`dav_properties`](Self::dav_properties) for each path, concurrently.
    ///
    /// # Errors
    ///
    /// Only infrastructure failures.
    async fn dav_properties_many(
        &self,
        ctx: &RequestContext,
        paths: &[ResourcePath],
    ) -> AppResult<Vec<PrincipalProps>> {
        let mut found = Vec::with_capacity(paths.len());
        for read in join_all(paths.iter().map(|path| self.dav_properties(ctx, path))).await {
            match read {
                Ok(principal) => found.push(principal),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(found)
    }

    /// The principal the request is authenticated as, with the same properties as
    /// [`dav_properties`](Self::dav_properties): the answer to `DAV:current-user-principal`, with which every
    /// CalDAV client starts its discovery. The DAV layer cannot derive the principal's tenant slug and name from
    /// the context, which carries ids only.
    ///
    /// # Errors
    ///
    /// `Unauthenticated` for contexts that act as no principal (tenant and system tokens, anonymous requests),
    /// `NotFound` when the principal no longer exists. The default answers `Unsupported`.
    async fn current(&self, ctx: &RequestContext) -> AppResult<PrincipalProps> {
        let _ = ctx;
        Err(AppError::unsupported())
    }

    /// Classifies a calendar user address for scheduling.
    ///
    /// # Errors
    ///
    /// Only infrastructure failures.
    async fn resolve_address(&self, ctx: &RequestContext, address: &CalendarUserAddress) -> AppResult<AddressClass>;
}
