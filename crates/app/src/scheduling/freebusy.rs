//! Free-busy: the `free-busy-query` of a collection, the busy time of people and the search for free slots.
//!
//! Free-busy is open to every principal of the tenant and to nobody else (PLAN 2.6, `FreeBusy` access): a person's
//! busy time says *when*, never *why* (private and confidential events count like any other; no summary, no
//! location, no attendee ever leaves this module). Another tenant's principals are not found, groups are not
//! expanded in 1.0 and addresses outside the tenant have no busy time to give: all of them answer an entry that is
//! `known: false` with no periods.
//!
//! The busy time of a person is the time of the events in the calendars they own (personal, user and mirror
//! calendars) and in the managed calendars they see, except calendars they hid or marked transparent for scheduling,
//! and the meetings they take part in (they organize them or are an `ATTENDEE` of them) in the calendars of their
//! groups and in the calendars that were shared with them. An event they declined is free time. Which calendars a
//! person sees follows from membership and accepted grants, not from the bindings of their home, which are created
//! when they first list it.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Duration, NaiveTime};
use davhaven_domain::{
    AccessFacts, CalendarKind, CalendarUserAddress, CuType, Operation, Principal, PrincipalId, PrincipalKind,
    RequestContext, ResourcePath, Tenant, TimeZoneName,
};
use davhaven_ical::ErrorContext;
use davhaven_ical::filter::TimeRange;
use davhaven_ical::freebusy::BusyPeriod;
use davhaven_ports::{Tx, TxMode};
use uuid::Uuid;

use super::SchedulingServiceImpl;
use super::busy::{
    BusyGroup, Fetched, busy_of, busy_of_principal_cached, candidates, free_slots, union, working_windows,
};
use crate::addresses::{Class, Directory};
use crate::authz::{enforce, field_error, invalid, require_scope};
use crate::error::{AppError, AppResult};
use crate::objects::locate::{Target, locate};
use crate::services::{
    FindSlotsRequest, FindSlotsResult, FreeBusyEntry, FreeBusyRequest, FreeBusyResult, FreeBusyTarget, Slot,
};

/// The longest slot `find_free_slots` looks for, in minutes (a day).
const MAX_SLOT_MINUTES: u32 = 24 * 60;

/// How many slots `find_free_slots` returns when the request names no limit.
const DEFAULT_SLOTS: u32 = 20;

/// The facts that stand for "a person of the tenant" when a request is not about one calendar: free-busy of people.
/// Nothing is granted by them: the decision for free-busy depends on who asks, not on a calendar.
fn person_facts(tenant: &Tenant) -> AccessFacts {
    AccessFacts {
        calendar_kind: CalendarKind::Personal,
        owner: PrincipalId::from_uuid(Uuid::nil()),
        owner_kind: PrincipalKind::User,
        memberships: Vec::new(),
        grants: Vec::new(),
        binding: None,
        tenant_settings: Arc::new(tenant.settings.clone()),
    }
}

/// A person a request asks about.
pub(super) struct Person {
    pub(super) address: CalendarUserAddress,
    pub(super) principal: Option<Principal>,
}

impl SchedulingServiceImpl {
    /// Checks that the caller may ask for the busy time of people, before anything about them is looked up.
    ///
    /// # Errors
    ///
    /// `NotFound` where the operation does not exist, `Forbidden` for tokens without the scope or for tenant
    /// tokens (their events scope reaches managed and group calendars only, never a person's own time).
    fn authorize_people(ctx: &RequestContext, tenant: &Tenant) -> AppResult<()> {
        require_scope(ctx, Operation::FreeBusyQuery)?;
        enforce(ctx, &person_facts(tenant), Operation::FreeBusyQuery, || {
            ResourcePath::Root.href()
        })
    }

    /// Checks the range of a request: both ends, within the limits of the iCalendar layer.
    pub(super) fn check_range(&self, range: &TimeRange) -> AppResult<()> {
        range
            .validate_bounded(&self.core.deps().limits.ical)
            .map_err(|error| AppError::from_ical(error, ErrorContext::Query))
    }

    /// Looks the addresses up in the tenant of the transaction: the principals of people and resources, nobody for
    /// everything else.
    ///
    /// # Errors
    ///
    /// `Invalid` for more addresses than an event may have attendees, store failures.
    pub(super) async fn people(
        &self,
        tx: &mut dyn Tx,
        tenant: &Tenant,
        addresses: &[CalendarUserAddress],
    ) -> AppResult<Vec<Person>> {
        let deps = self.core.deps();
        let most = usize::try_from(deps.limits.ical.max_attendees_per_instance).unwrap_or(usize::MAX);
        if addresses.len() > most {
            return Err(field_error(
                "/addresses",
                "too-many",
                "Too many people are asked about at once.",
            ));
        }
        let directory = Directory::load(tx, tenant, &deps.urls, addresses).await?;
        Ok(addresses
            .iter()
            .map(|address| {
                let principal = match directory.classify(address, CuType::Individual) {
                    Class::Internal(principal) | Class::Resource(principal) => Some(*principal),
                    Class::Group | Class::External | Class::Unknown => None,
                };
                Person {
                    address: address.clone(),
                    principal,
                }
            })
            .collect())
    }

    /// The busy periods of every person, in the order of `people` (nobody for a person without a principal). A
    /// principal named twice is computed once.
    pub(super) async fn busy_of_people(
        &self,
        tx: &mut dyn Tx,
        tenant: &Tenant,
        people: &[Person],
        range: TimeRange,
    ) -> AppResult<Vec<Vec<BusyPeriod>>> {
        let mut computed: HashMap<PrincipalId, Vec<BusyPeriod>> = HashMap::new();
        // The calendars of a group are read once for all its members.
        let mut fetched = Fetched::new();
        let mut lists = Vec::with_capacity(people.len());
        for person in people {
            let Some(principal) = &person.principal else {
                lists.push(Vec::new());
                continue;
            };
            if let Some(known) = computed.get(&principal.id) {
                lists.push(known.clone());
                continue;
            }
            let periods =
                busy_of_principal_cached(&self.core, tx, tenant, principal, range, None, &mut fetched).await?;
            computed.insert(principal.id, periods.clone());
            lists.push(periods);
        }
        Ok(lists)
    }

    /// Free-busy of a collection or of people.
    pub(super) async fn query_free_busy(
        &self,
        ctx: &RequestContext,
        request: FreeBusyRequest,
    ) -> AppResult<FreeBusyResult> {
        self.check_range(&request.range)?;
        let range = request.range;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let entries = match &request.target {
            FreeBusyTarget::Collection(path) => {
                require_scope(ctx, Operation::FreeBusyQuery)?;
                let Some((target, None)) = Target::of(path) else {
                    return Err(AppError::not_found());
                };
                let located = locate(tx.as_mut(), ctx, target, false).await?;
                enforce(ctx, &located.facts, Operation::FreeBusyQuery, || path.href())?;
                let objects = candidates(&self.core, tx.as_mut(), located.calendar.id, &range, None).await?;
                tx.commit().await?;
                let groups = if objects.is_empty() {
                    Vec::new()
                } else {
                    vec![BusyGroup {
                        zone_ics: located.calendar.timezone_ics.clone(),
                        objects: Arc::new(objects),
                        participating_only: None,
                    }]
                };
                let periods = busy_of(&self.core, groups, Vec::new(), range).await?;
                vec![FreeBusyEntry {
                    address: None,
                    known: true,
                    periods,
                }]
            }
            FreeBusyTarget::Addresses(addresses) => {
                let tenant = tx.tenant().get().await?;
                Self::authorize_people(ctx, &tenant)?;
                let people = self.people(tx.as_mut(), &tenant, addresses).await?;
                let lists = self.busy_of_people(tx.as_mut(), &tenant, &people, range).await?;
                tx.commit().await?;
                people
                    .into_iter()
                    .zip(lists)
                    .map(|(person, periods)| FreeBusyEntry {
                        known: person.principal.is_some(),
                        address: Some(person.address),
                        periods,
                    })
                    .collect()
            }
        };
        Ok(FreeBusyResult {
            range,
            entries,
            generated_at: self.core.deps().clock.now(),
        })
    }

    /// The slots in which everybody is free.
    pub(super) async fn search_free_slots(
        &self,
        ctx: &RequestContext,
        request: FindSlotsRequest,
    ) -> AppResult<FindSlotsResult> {
        let deps = self.core.deps();
        if request.duration_minutes == 0 || request.duration_minutes > MAX_SLOT_MINUTES {
            return Err(field_error(
                "/duration_minutes",
                "out-of-range",
                "A slot lasts between 1 minute and one day.",
            ));
        }
        let most = deps.limits.api.max_page_size;
        let limit = request.limit.unwrap_or(DEFAULT_SLOTS);
        if limit == 0 || limit > most {
            return Err(field_error(
                "/limit",
                "out-of-range",
                "The number of slots is out of range.",
            ));
        }
        if request.addresses.is_empty() {
            return Err(field_error("/addresses", "empty", "Name at least one person."));
        }
        self.check_range(&request.range)?;
        let (Some(start), Some(end)) = (request.range.start, request.range.end) else {
            return Err(invalid("The search needs a start and an end."));
        };
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        Self::authorize_people(ctx, &tenant)?;
        let people = self.people(tx.as_mut(), &tenant, &request.addresses).await?;
        if people.iter().any(|person| person.principal.is_none()) {
            return Err(field_error(
                "/addresses",
                "unknown-person",
                "Every address must belong to a person of this organisation.",
            ));
        }
        let zone = self
            .zone_of_caller(tx.as_mut(), ctx, &tenant, request.time_zone)
            .await?;
        let lists = self
            .busy_of_people(tx.as_mut(), &tenant, &people, request.range)
            .await?;
        tx.commit().await?;
        let busy = union(lists);
        let hours: Option<(NaiveTime, NaiveTime)> = request.working_hours.map(|hours| (hours.start, hours.end));
        let windows = working_windows((start, end), hours, zone);
        let wanted = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut found = free_slots(
            &busy,
            &windows,
            Duration::minutes(i64::from(request.duration_minutes)),
            wanted,
        );
        let truncated = found.len() > wanted;
        found.truncate(wanted);
        Ok(FindSlotsResult {
            slots: found.into_iter().map(|(start, end)| Slot { start, end }).collect(),
            truncated,
        })
    }

    /// The time zone working hours are read in: the one the request names, the caller's own, the tenant's.
    async fn zone_of_caller(
        &self,
        tx: &mut dyn Tx,
        ctx: &RequestContext,
        tenant: &Tenant,
        requested: Option<TimeZoneName>,
    ) -> AppResult<TimeZoneName> {
        if let Some(zone) = requested {
            return Ok(zone);
        }
        if let Some(id) = ctx.principal()
            && let Some(principal) = crate::authz::found(tx.principals().get(id).await)?
            && let Some(zone) = principal.timezone
        {
            return Ok(zone);
        }
        Ok(tenant.settings.timezone)
    }
}
