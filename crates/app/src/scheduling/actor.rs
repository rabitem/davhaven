//! Who writes: the principal behind a request and the addresses that make them the organizer or an attendee.

use davhaven_domain::{
    CalendarUserAddress, Channel, Principal, PrincipalId, PrincipalKind, PrincipalStatus, RequestContext, Tenant,
};
use davhaven_ports::Tx;

use crate::authz::found;
use crate::error::AppResult;
use crate::principals::address_set;

/// The principal a scheduling write acts as, with every address that names them (PLAN 2.6): the primary and
/// further addresses, the principal URL, `urn:uuid:{id}` and, when the tenant says so, the login address.
#[derive(Debug, Clone)]
pub(crate) struct ActorInfo {
    /// The acting principal.
    pub(crate) principal: Principal,
    /// Every calendar user address of the principal.
    pub(crate) addresses: Vec<CalendarUserAddress>,
    /// The owner of the calendar written to, when that is somebody else (a shared calendar): a writer with
    /// `ReadWrite` access may organize in the owner's name, and answer for them as an attendee (PLAN 2.8).
    pub(crate) owner: Option<(Principal, Vec<CalendarUserAddress>)>,
    /// Whether the calendar written to belongs to a group. Nobody speaks in the name of a group: on a group
    /// calendar the member is the organizer of what they write, and what another member organized is theirs.
    pub(crate) in_group_calendar: bool,
}

/// The primary mail address of a principal, as outside systems know them.
pub(crate) fn mailto_of(principal: &Principal) -> Option<CalendarUserAddress> {
    principal.email.as_ref().map(CalendarUserAddress::mailto)
}

impl ActorInfo {
    /// The acting principal of a request, or `None` when nobody acts as a principal (tenant and system tokens,
    /// feeds, RSVP links, server work: they never schedule on their own account).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) async fn resolve(
        tx: &mut dyn Tx,
        ctx: &RequestContext,
        tenant: &Tenant,
        calendar_owner: PrincipalId,
    ) -> AppResult<Option<Self>> {
        if ctx.channel == Channel::Internal {
            return Ok(None);
        }
        let Some(id) = ctx.principal() else {
            return Ok(None);
        };
        let Some(principal) = found(tx.principals().get(id).await)?.filter(|p| p.status == PrincipalStatus::Active)
        else {
            return Ok(None);
        };
        let rows = tx.principals().addresses(principal.id).await?;
        let addresses = address_set(tenant, &principal, &rows);
        let (owner, in_group_calendar) = if calendar_owner == principal.id {
            (None, false)
        } else if let Some(owner) = found(tx.principals().get(calendar_owner).await)? {
            if owner.kind == PrincipalKind::Group {
                (None, true)
            } else {
                let rows = tx.principals().addresses(owner.id).await?;
                let addresses = address_set(tenant, &owner, &rows);
                (Some((owner, addresses)), false)
            }
        } else {
            (None, false)
        };
        Ok(Some(Self {
            principal,
            addresses,
            owner,
            in_group_calendar,
        }))
    }

    /// Whether `address` names the acting principal.
    pub(crate) fn is_own(&self, address: &CalendarUserAddress) -> bool {
        self.addresses.contains(address)
    }

    /// Whether the actor may speak as `address`: it names them, or it names the owner of the calendar they write to
    /// (they write it with `ReadWrite` access, or the write would not have got this far). The actor organizes as
    /// the one and answers invitations as the other.
    pub(crate) fn speaks_for(&self, address: &CalendarUserAddress) -> bool {
        self.is_own(address)
            || self
                .owner
                .as_ref()
                .is_some_and(|(_, addresses)| addresses.contains(address))
    }

    /// The principal `address` names among those the actor speaks for: themselves or the owner of the calendar.
    pub(crate) fn identity_of(&self, address: &CalendarUserAddress) -> Option<&Principal> {
        if self.is_own(address) {
            return Some(&self.principal);
        }
        self.owner
            .as_ref()
            .filter(|(_, addresses)| addresses.contains(address))
            .map(|(owner, _)| owner)
    }

    /// The address the actor speaks as in `candidates`: theirs or the owner's.
    pub(crate) fn among<'a>(
        &self,
        candidates: impl IntoIterator<Item = &'a CalendarUserAddress>,
    ) -> Option<&'a CalendarUserAddress> {
        candidates.into_iter().find(|address| self.speaks_for(address))
    }

    /// Whether `principal` is one the actor speaks for.
    pub(crate) fn speaks_as(&self, principal: PrincipalId) -> bool {
        principal == self.principal.id || self.owner.as_ref().is_some_and(|(owner, _)| owner.id == principal)
    }

    /// Whether the organizer's name is the owner's and not the actor's own (the write is sent on behalf of the
    /// owner).
    pub(crate) fn on_behalf_of_owner(&self, organizer: &CalendarUserAddress) -> bool {
        !self.is_own(organizer) && self.speaks_for(organizer)
    }

    /// The primary mail address of the actor, as outside systems know them.
    pub(crate) fn mailto(&self) -> Option<CalendarUserAddress> {
        mailto_of(&self.principal)
    }
}
