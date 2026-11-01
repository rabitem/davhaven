//! Views of calendars: the binding of a home as DAV shows it and the calendar as the management API shows it.

use std::collections::{HashMap, HashSet};

use davhaven_domain::{
    Access, AccessFacts, Binding, Calendar, CalendarId, CalendarSlug, GrantStatus, Principal, PrincipalId,
    ResourceKind, ResourcePath, SyncToken, Tenant, Transparency, effective_access, privileges,
};
use davhaven_ports::Tx;
use davhaven_wire::CalendarView;

use crate::error::{AppError, AppResult};
use crate::services::{BindingView, PrincipalSummary, SharingRole};
use crate::wiring::AppCore;

/// The owner of a calendar as other principals' resources refer to it.
fn summary_of(principal: Principal) -> PrincipalSummary {
    PrincipalSummary {
        id: principal.id,
        name: principal.name,
        display_name: principal.display_name,
        kind: principal.kind,
    }
}

/// The sync token (and `CTag`) of a calendar as of the row.
pub(crate) fn sync_token_of(calendar: &Calendar) -> SyncToken {
    SyncToken::new(
        calendar.id.as_uuid(),
        calendar.sync_epoch,
        u64::try_from(calendar.sync_seq).unwrap_or(0),
    )
}

/// Builds views and remembers what it looked up: owners of calendars and the owners' bindings.
pub(crate) struct Views<'a> {
    core: &'a AppCore,
    tenant: &'a Tenant,
    /// Whether many calendars of the same owners are viewed: then the bindings of an owner are read together.
    listing: bool,
    owners: HashMap<PrincipalId, PrincipalSummary>,
    owner_slugs: HashMap<(PrincipalId, CalendarId), CalendarSlug>,
    /// The owners whose bindings are all in `owner_slugs`.
    owners_read: HashSet<PrincipalId>,
    /// The calendars whose owner's binding [`Views::prime`] looked up: one of them that has no entry in `owner_slugs`
    /// is a calendar its owner does not list, which needs no further look-up.
    primed: HashSet<CalendarId>,
}

impl<'a> Views<'a> {
    /// Views for one calendar (or a few): the slug of the owner's collection is one lookup.
    pub(crate) fn new(core: &'a AppCore, tenant: &'a Tenant) -> Self {
        Self {
            core,
            tenant,
            listing: false,
            owners: HashMap::new(),
            owner_slugs: HashMap::new(),
            owners_read: HashSet::new(),
            primed: HashSet::new(),
        }
    }

    /// Reads what the views of `calendars` will ask for with two queries in all: their owners, and the collection each
    /// owner lists the calendar under (the target of a sharee's `shared-url`). Without it a listing of calendars of many
    /// owners costs a read of the principal and one of the bindings per owner (`ENGINEERING_RULES` R14). What is not
    /// found here (an owner that was purged, a calendar its owner does not list) is looked up on demand as before.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) async fn prime(&mut self, tx: &mut dyn Tx, calendars: &[&Calendar]) -> AppResult<()> {
        let mut owners: Vec<PrincipalId> = calendars
            .iter()
            .map(|calendar| calendar.owner_id)
            .filter(|owner| !self.owners.contains_key(owner))
            .collect();
        owners.sort_unstable();
        owners.dedup();
        if !owners.is_empty() {
            for principal in tx.principals().get_many(&owners).await? {
                self.owners.insert(principal.id, summary_of(principal));
            }
        }
        if self.listing {
            let pairs: Vec<(PrincipalId, CalendarId)> = calendars
                .iter()
                .filter(|calendar| {
                    !self.primed.contains(&calendar.id) && !self.owners_read.contains(&calendar.owner_id)
                })
                .map(|calendar| (calendar.owner_id, calendar.id))
                .collect();
            if !pairs.is_empty() {
                for binding in tx.bindings().find_for_calendars(&pairs).await? {
                    self.owner_slugs
                        .insert((binding.principal_id, binding.calendar_id), binding.slug);
                }
                self.primed.extend(pairs.iter().map(|(_, calendar)| *calendar));
            }
        }
        Ok(())
    }

    /// Views for a listing: the bindings of an owner are read once for all of the owner's calendars.
    pub(crate) fn for_listing(core: &'a AppCore, tenant: &'a Tenant) -> Self {
        Self {
            listing: true,
            ..Self::new(core, tenant)
        }
    }

    /// The owner of a calendar as other principals' resources refer to it.
    pub(crate) async fn owner(&mut self, tx: &mut dyn Tx, id: PrincipalId) -> AppResult<PrincipalSummary> {
        if let Some(summary) = self.owners.get(&id) {
            return Ok(summary.clone());
        }
        // A calendar outlives its deleted owner until the purge; the view still names it.
        let summary = summary_of(tx.principals().get(id).await?);
        self.owners.insert(id, summary.clone());
        Ok(summary)
    }

    /// The slug of the collection of `calendar` in its owner's home (the owner's binding), falling back to the
    /// calendar's own slug.
    pub(crate) async fn owner_slug(&mut self, tx: &mut dyn Tx, calendar: &Calendar) -> AppResult<CalendarSlug> {
        let key = (calendar.owner_id, calendar.id);
        if let Some(slug) = self.owner_slugs.get(&key) {
            return Ok(slug.clone());
        }
        if self.primed.contains(&calendar.id) {
            return Ok(calendar.slug.clone());
        }
        if self.listing {
            if self.owners_read.insert(calendar.owner_id) {
                for bound in tx.bindings().list_for(calendar.owner_id).await? {
                    self.owner_slugs
                        .insert((calendar.owner_id, bound.calendar.id), bound.binding.slug);
                }
            }
        } else if let Some(binding) = tx.bindings().find_for_calendar(calendar.owner_id, calendar.id).await? {
            self.owner_slugs.insert(key, binding.slug);
        }
        Ok(self
            .owner_slugs
            .get(&key)
            .cloned()
            .unwrap_or_else(|| calendar.slug.clone()))
    }

    /// The calendar as the management API shows it.
    pub(crate) async fn calendar_view(&mut self, tx: &mut dyn Tx, calendar: &Calendar) -> AppResult<CalendarView> {
        let owner = self.owner(tx, calendar.owner_id).await?;
        let slug = self.owner_slug(tx, calendar).await?;
        let path = ResourcePath::Collection {
            tenant: self.tenant.slug.clone(),
            principal: owner.name.clone(),
            binding: slug,
        };
        Ok(CalendarView {
            id: calendar.id,
            owner_id: owner.id,
            owner: owner.name,
            slug: calendar.slug.clone(),
            kind: calendar.kind,
            display_name: calendar.display_name.clone(),
            description: calendar.description.clone(),
            color: calendar.color.clone(),
            sort_order: calendar.sort_order,
            components: calendar.components.clone(),
            sync_token: sync_token_of(calendar),
            dav_url: self.core.deps().urls.for_tenant(&self.tenant.settings).dav_url(&path),
            created_at: calendar.created_at,
            updated_at: calendar.updated_at,
            version: calendar.version,
        })
    }

    /// The calendar in the home of `home` as DAV shows it: the binding's overrides over the calendar's values and
    /// the viewer's access.
    pub(crate) async fn binding_view(
        &mut self,
        tx: &mut dyn Tx,
        home: &davhaven_domain::Principal,
        binding: &Binding,
        calendar: &Calendar,
        facts: &AccessFacts,
    ) -> AppResult<BindingView> {
        let owner = self.owner(tx, calendar.owner_id).await?;
        let access = effective_access(home.id, facts).unwrap_or(Access::Read);
        let sharing = sharing_role(home.id, calendar, facts);
        let shared_url = if sharing == SharingRole::Sharee {
            let slug = self.owner_slug(tx, calendar).await?;
            Some(ResourcePath::Collection {
                tenant: self.tenant.slug.clone(),
                principal: owner.name.clone(),
                binding: slug,
            })
        } else {
            None
        };
        Ok(BindingView {
            binding_id: binding.id,
            calendar_id: calendar.id,
            path: ResourcePath::Collection {
                tenant: self.tenant.slug.clone(),
                principal: home.name.clone(),
                binding: binding.slug.clone(),
            },
            owner,
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
            sharing,
            shared_url,
            sync_token: sync_token_of(calendar),
            created_at: calendar.created_at,
            updated_at: binding.updated_at.max(calendar.updated_at),
        })
    }
}

/// How `viewer` relates to the sharing of the calendar: the owner of a shared calendar, a sharee through an
/// accepted grant of their own, or neither (a private calendar, or access through a group).
pub(crate) fn sharing_role(viewer: PrincipalId, calendar: &Calendar, facts: &AccessFacts) -> SharingRole {
    if calendar.owner_id == viewer {
        if facts.grants.iter().any(|grant| grant.status != GrantStatus::Declined) {
            SharingRole::Owner
        } else {
            SharingRole::Unshared
        }
    } else if facts
        .grants
        .iter()
        .any(|grant| grant.grantee == viewer && grant.status == GrantStatus::Accepted)
    {
        SharingRole::Sharee
    } else {
        SharingRole::Unshared
    }
}

/// A slug for a new binding of `base` in a home whose bindings use `taken`: the slug itself when it is free, else
/// the slug with a counter.
///
/// # Errors
///
/// `Internal` when no slug can be built (cannot happen for valid input).
pub(crate) fn free_binding_slug(base: &CalendarSlug, taken: &HashSet<String>) -> AppResult<CalendarSlug> {
    if !taken.contains(base.as_str()) {
        return Ok(base.clone());
    }
    for counter in 2..1000_u32 {
        let suffix = format!("-{counter}");
        let keep = 100_usize.saturating_sub(suffix.len());
        let stem: String = base.as_str().chars().take(keep).collect();
        let candidate = format!("{stem}{suffix}");
        if !taken.contains(&candidate) {
            return CalendarSlug::parse(&candidate).map_err(AppError::internal);
        }
    }
    Err(AppError::internal(davhaven_ports::StoreError::internal(
        "no free binding slug",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slug(text: &str) -> CalendarSlug {
        CalendarSlug::parse(text).unwrap()
    }

    #[test]
    fn a_free_slug_is_kept_and_a_taken_one_gets_a_counter() {
        let mut taken: HashSet<String> = HashSet::new();
        assert_eq!(free_binding_slug(&slug("work"), &taken).unwrap(), slug("work"));
        taken.insert("work".to_owned());
        assert_eq!(free_binding_slug(&slug("work"), &taken).unwrap(), slug("work-2"));
        taken.insert("work-2".to_owned());
        assert_eq!(free_binding_slug(&slug("work"), &taken).unwrap(), slug("work-3"));
    }

    #[test]
    fn counters_keep_long_slugs_within_the_limit() {
        let long = "a".repeat(100);
        let taken: HashSet<String> = std::iter::once(long.clone()).collect();
        let free = free_binding_slug(&slug(&long), &taken).unwrap();
        assert_eq!(free.as_str().len(), 100);
        assert!(free.as_str().ends_with("-2"));
    }
}
