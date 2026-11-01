//! The single `ItipProcessor` path for every iTIP REPLY, REQUEST and CANCEL.
//!
//! Scheduling messages reach the application from four places: the organizer's write (invitations and
//! cancellations to internal attendees, [`crate::scheduling`]), an attendee's change of their own copy (a `REPLY` to
//! the organizer), the RSVP page of an external attendee ([`crate::rsvp`]) and a mail gateway
//! ([`crate::inbound`]). They all end in the two operations of the `ItipProcessor`, so the rules live in one place
//! (PLAN 2.8, "Replies"):
//!
//! | Operation | What it does |
//! | --- | --- |
//! | `ItipProcessor::apply_reply` | folds a `REPLY` into the organizer's copy under the lock of its calendar (the answer of the attendee, nothing else), keeps the `Schedule-Tag` (a server merge does not change it), logs the change, tells the organizer through the scheduling inbox and announces `scheduling.reply_received` |
//! | `ItipProcessor::deliver` | puts invitations and cancellations into the scheduling inbox of internal recipients and keeps their copy of the event (created by policy, replaced, or removed) in step, all in the caller's transaction, with the calendars of the copies locked together in ascending id order; it acts only on copies that **this organizer** sent |
//!
//! Both work inside the transaction of the caller and never commit; both are idempotent where the caller needs it
//! (an inbound message is applied once, whatever the gateway does).
//!
//! A `REPLY` is only ever *derived from* what the server knows: from the attendee's own copy (a calendar client
//! changed it), from the link the attendee holds (the RSVP page), or from a message that passed the checks of
//! `davhaven_ical::itip::parse_message` and names exactly the attendee the caller authenticated
//! (`apply_reply_with` refuses a reply for somebody else).
//!
//! # Whose copy a delivery may touch
//!
//! A scheduling object is unique per owner by its `UID` (PLAN 2.7), and a `UID` is not a secret: every attendee
//! sees it. If a delivery acted on whatever the recipient has under the `UID` of the message, anybody who can write
//! a calendar could name a meeting of somebody else in an event of their own and have the server replace or delete
//! the victim's object. `ItipProcessor::deliver` therefore touches an existing object of the recipient only when
//! its `ORGANIZER` is one of the addresses of the organizer the delivery is for (`DeliveryScope::organizers`), and
//! never delivers an older `SEQUENCE` over a newer one. Anything else is skipped: the recipient gets nothing.

mod delivery;
mod queued;
mod reply;

use std::collections::HashSet;
use std::sync::Arc;

use davhaven_domain::{
    Calendar, CalendarId, CalendarKind, CalendarUserAddress, ComponentKind, GrantAccess, GrantStatus, Principal,
    PrincipalId, StoredObject, Tenant, Uid,
};
use davhaven_ical::{ErrorContext, IcalError, IcalLimits};
use davhaven_ports::{Invite, PolicyTenant, StoreError, Tx};

pub(crate) use delivery::{CopyOp, DeliveryScope, InternalDelivery};
pub use queued::InternalDeliveryHandler;
pub(crate) use reply::{Notify, Rejection, ReplyError, ReplyInput};

use crate::authz::{blocking, found};
use crate::error::{AppError, AppResult};
use crate::principals::address_set;
use crate::wiring::AppCore;

/// The processor of iTIP messages (see the module documentation).
#[derive(Debug, Clone)]
pub(crate) struct ItipProcessor {
    core: AppCore,
}

impl ItipProcessor {
    /// Creates the processor on the shared application core.
    pub(crate) fn new(core: AppCore) -> Self {
        Self { core }
    }
}

/// Runs iCalendar `work` on a blocking thread under the wall-clock budget and hands back its own result, so that
/// the caller decides what an iCalendar error means (an unreadable message is a rejection, not a failure).
///
/// # Errors
///
/// `Unavailable` when the worker fails or runs out of time; the work's own errors are in the inner result.
pub(crate) async fn blocking_ical<T, F>(core: &AppCore, work: F) -> AppResult<Result<T, IcalError>>
where
    T: Send + 'static,
    F: FnOnce(&IcalLimits) -> Result<T, IcalError> + Send + 'static,
{
    blocking(core, ErrorContext::Scheduling, move |limits| Ok(work(limits))).await
}

/// Whether an iCalendar error says something about the data (the message or the copy is not usable) rather than
/// about the machine (the time budget ran out, a feature is missing).
pub(crate) fn is_data_error(error: &IcalError) -> bool {
    !error.is_transient() && !matches!(error, IcalError::Unsupported(_))
}

/// Maps an iCalendar failure that is not the data's fault to the error of the request.
pub(crate) fn machine_error(error: IcalError) -> AppError {
    AppError::from_ical(error, ErrorContext::Scheduling)
}

/// The calendar a new copy of an event goes to for `principal`: their personal calendar, or the first calendar of
/// their own for principals that have none (resources keep a calendar of their own).
///
/// # Errors
///
/// Store failures.
pub(crate) async fn default_calendar(tx: &mut dyn Tx, principal: &Principal) -> AppResult<Option<CalendarId>> {
    let owned = tx.calendars().list_owned(principal.id).await?;
    let takes_events = |calendar: &&Calendar| calendar.components.contains(&ComponentKind::Event);
    Ok(owned
        .iter()
        .filter(takes_events)
        .find(|calendar| calendar.kind == CalendarKind::Personal)
        .or_else(|| {
            owned
                .iter()
                .filter(takes_events)
                .find(|calendar| calendar.kind == CalendarKind::User)
        })
        .map(|calendar| calendar.id))
}

/// The tenant as the scheduling policy is asked about it.
pub(crate) fn policy_tenant(tenant: &Tenant) -> PolicyTenant {
    PolicyTenant {
        id: tenant.id,
        settings: Arc::new(tenant.settings.clone()),
    }
}

/// The people who see a calendar already: its owner, the current members of the group that owns it, and everybody
/// with an accepted grant, directly or through a group, except those who hid it.
///
/// This is *effective access* (PLAN 2.6) and not the list of the bindings of the calendar: bindings of group members
/// and sharees are created lazily when they first list their home (PLAN 2.9), so a binding says nothing about
/// whether somebody can see the calendar. It is loaded once for all the recipients of a write.
#[derive(Debug, Default)]
pub(crate) struct Viewers {
    sees: HashSet<PrincipalId>,
    hidden: HashSet<PrincipalId>,
}

impl Viewers {
    /// Loads who sees `calendar`.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) async fn load(tx: &mut dyn Tx, calendar: &Calendar) -> AppResult<Self> {
        let mut sees: HashSet<PrincipalId> = HashSet::new();
        sees.insert(calendar.owner_id);
        if calendar.kind == CalendarKind::Group {
            sees.extend(found(tx.memberships().members(calendar.owner_id).await)?.unwrap_or_default());
        }
        for grant in tx.grants().for_calendar(calendar.id).await? {
            if grant.status != GrantStatus::Accepted {
                continue;
            }
            sees.insert(grant.grantee_id);
            // A group that is granted access: its current members see the calendar.
            sees.extend(found(tx.memberships().members(grant.grantee_id).await)?.unwrap_or_default());
        }
        let hidden = tx
            .bindings()
            .list_for_calendar(calendar.id)
            .await?
            .into_iter()
            .filter(|binding| binding.hidden)
            .map(|binding| binding.principal_id)
            .collect();
        Ok(Self { sees, hidden })
    }

    /// Whether `principal` sees the calendar in their calendar list.
    pub(crate) fn includes(&self, principal: PrincipalId) -> bool {
        self.sees.contains(&principal) && !self.hidden.contains(&principal)
    }
}

/// The calendar an invitation of `organizer` is added to as a copy of the event for `principal`, if it is added.
///
/// The policy decides first (`SchedulingPolicy::auto_add`); a recipient who sees the organizer's calendar already
/// (`viewers`, effective access) gets only an inbox item (`scheduling.suppress_duplicate_copies`, PLAN 2.8). A
/// principal without a calendar for events has nowhere to put a copy.
///
/// # Errors
///
/// Store failures.
pub(crate) async fn wants_copy(
    core: &AppCore,
    tx: &mut dyn Tx,
    tenant: &Tenant,
    organizer: &CalendarUserAddress,
    viewers: Option<&Viewers>,
    principal: &Principal,
) -> AppResult<Option<CalendarId>> {
    let Some(calendar) = default_calendar(tx, principal).await? else {
        return Ok(None);
    };
    let wants = core
        .deps()
        .scheduling_policy
        .auto_add(&Invite {
            tenant: policy_tenant(tenant),
            organizer: organizer.clone(),
            attendee: principal.id,
            calendar,
        })
        .await;
    if !wants {
        return Ok(None);
    }
    let duplicate = tenant.settings.scheduling.suppress_duplicate_copies
        && viewers.is_some_and(|viewers| viewers.includes(principal.id));
    Ok((!duplicate).then_some(calendar))
}

/// The organizer's copy of the event `uid`: the scheduling object that names the organizer's address as its
/// `ORGANIZER`, wherever the organizer keeps it.
///
/// The copy lives in a calendar the organizer owns, in a calendar of a group the organizer belongs to (events of a
/// group calendar are organized by the member who wrote them), or in a calendar that was shared with the organizer
/// or one of their groups with write access. Scheduling objects are unique per owner (PLAN 2.7), so each candidate
/// owner has at most one; a copy that names somebody else as its organizer (the organizer's own invitation to an
/// event of another person) is not the organizer's copy.
///
/// The answer is deterministic: the copy in a calendar the organizer owns is **the** organizer's copy; otherwise
/// there has to be exactly one candidate. Several (the same `UID` organized by the same person in two group
/// calendars) are ambiguous and give no copy, because an answer must not land in whichever calendar sorts first.
///
/// # Errors
///
/// Store failures.
pub(crate) async fn organizer_copy(
    tx: &mut dyn Tx,
    tenant: &Tenant,
    organizer: &Principal,
    uid: &Uid,
) -> AppResult<Option<StoredObject>> {
    let rows = tx.principals().addresses(organizer.id).await?;
    let addresses: HashSet<CalendarUserAddress> = address_set(tenant, organizer, &rows).into_iter().collect();
    let names_organizer = |object: &StoredObject| {
        object
            .organizer_address
            .as_ref()
            .is_some_and(|address| addresses.contains(address))
    };
    if let Some(object) = tx.objects().find_scheduling_uid(organizer.id, uid).await?
        && names_organizer(&object)
    {
        return Ok(Some(object));
    }
    let groups = tx.memberships().groups_of(organizer.id).await?;
    let mut writers: Vec<PrincipalId> = vec![organizer.id];
    writers.extend(groups.iter().copied());
    let mut owners: Vec<PrincipalId> = groups;
    let mut shared: Vec<CalendarId> = Vec::new();
    for writer in &writers {
        for grant in tx.grants().for_grantee(*writer).await? {
            if grant.status == GrantStatus::Accepted
                && matches!(grant.access, GrantAccess::ReadWrite | GrantAccess::Admin)
            {
                shared.push(grant.calendar_id);
            }
        }
    }
    shared.sort();
    shared.dedup();
    if !shared.is_empty() {
        for calendar in tx.calendars().get_many(&shared).await? {
            owners.push(calendar.owner_id);
        }
    }
    let mut seen: HashSet<PrincipalId> = HashSet::from([organizer.id]);
    let mut candidates: Vec<StoredObject> = Vec::new();
    for owner in owners {
        if !seen.insert(owner) {
            continue;
        }
        if let Some(object) = tx.objects().find_scheduling_uid(owner, uid).await?
            && names_organizer(&object)
        {
            candidates.push(object);
        }
    }
    if candidates.len() > 1 {
        tracing::warn!(
            candidates = candidates.len(),
            "more than one calendar holds an object of the organizer under the same UID; no answer is applied"
        );
        return Ok(None);
    }
    Ok(candidates.pop())
}

/// Every address that names the organizer `address` is: the address itself and, when it belongs to a principal of the
/// tenant, all of the principal's addresses. These are the addresses a copy of the organizer's event may name as its
/// `ORGANIZER` (the copy of the recipient carries the form that is used on the wire, the organizer's own the form
/// the client wrote).
///
/// # Errors
///
/// Store failures.
pub(crate) async fn organizer_addresses(
    core: &AppCore,
    tx: &mut dyn Tx,
    tenant: &Tenant,
    address: &CalendarUserAddress,
) -> AppResult<Vec<CalendarUserAddress>> {
    let mut all = vec![address.clone()];
    if let Some(principal) = principal_of(core, tx, tenant, address).await? {
        let rows = tx.principals().addresses(principal.id).await?;
        all.extend(address_set(tenant, &principal, &rows));
    }
    all.sort();
    all.dedup();
    Ok(all)
}

/// The principal that owns `address` among the active principals of the tenant, if it names one.
///
/// # Errors
///
/// Store failures.
pub(crate) async fn principal_of(
    core: &AppCore,
    tx: &mut dyn Tx,
    tenant: &Tenant,
    address: &CalendarUserAddress,
) -> AppResult<Option<Principal>> {
    crate::principals::find_by_address(tx, tenant, &core.deps().urls, address).await
}

/// A store error that means "try the whole transaction again".
pub(crate) fn contention() -> AppError {
    AppError::from(StoreError::SerializationFailure)
}

#[cfg(test)]
mod tests {
    use davhaven_domain::ErrorKind;
    use davhaven_ical::LimitKind;

    use super::*;
    use crate::outbox::fixture::Fixture;

    #[test]
    fn only_errors_of_the_data_are_data_errors() {
        // A data error makes a message or a copy unusable (the reply is rejected, the copy is replaced); any other
        // failure is the machine's and is retried, so the two must never be confused.
        for data in [
            IcalError::invalid("DTEND is before DTSTART"),
            IcalError::object_rule("two UIDs"),
            IcalError::organizer_mismatch("two organizers"),
            IcalError::Limit(LimitKind::Attendees),
            IcalError::Limit(LimitKind::ResourceSize),
        ] {
            assert!(is_data_error(&data), "{data}");
        }
        for machine in [
            IcalError::Limit(LimitKind::TimeBudget),
            IcalError::unsupported("COUNTER"),
        ] {
            assert!(!is_data_error(&machine), "{machine}");
        }
        assert_eq!(
            machine_error(IcalError::Limit(LimitKind::TimeBudget)).kind(),
            ErrorKind::Unavailable
        );
        assert_eq!(
            machine_error(IcalError::unsupported("COUNTER")).kind(),
            ErrorKind::Unsupported
        );
    }

    #[tokio::test]
    async fn the_errors_of_the_work_stay_inside_and_a_failed_worker_is_unavailable() {
        let core = Fixture::new().core;
        let value = blocking_ical(&core, |_| Ok::<_, IcalError>(5)).await.unwrap();
        assert_eq!(value, Ok(5));
        let refused = blocking_ical(&core, |_| Err::<u32, _>(IcalError::invalid("bad")))
            .await
            .unwrap();
        assert_eq!(
            refused,
            Err(IcalError::invalid("bad")),
            "the caller decides what an error of the data means"
        );
        let crashed = blocking_ical(&core, |_| -> Result<u32, IcalError> { panic!("the worker fails") }).await;
        assert_eq!(crashed.unwrap_err().kind(), ErrorKind::Unavailable);
    }
}
