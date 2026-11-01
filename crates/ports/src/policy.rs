//! The `SchedulingPolicy` port.
//!
//! The policy decides the questions of scheduling that deployments customise (PLAN 2.8): whether an invitation is
//! added to an internal attendee's calendar automatically, how a resource answers a booking request, and whether
//! mail to an external address is allowed. The default implementation lives in `davhaven-app` and follows the
//! tenant settings; a deployment can replace it with an adapter that calls its own service.
//!
//! The methods are infallible: an adapter that consults an external service applies its own fail-open or
//! fail-closed default when that service is unavailable.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarId, CalendarUserAddress, PartStat, PrincipalId, TenantId, TenantSettings};

/// The tenant a policy question is about: its id and its settings.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyTenant {
    /// The tenant id.
    pub id: TenantId,
    /// The tenant's settings (`scheduling.*` carries the defaults a policy follows).
    pub settings: Arc<TenantSettings>,
}

/// A period of busy time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusyPeriod {
    /// The start (inclusive).
    pub start: DateTime<Utc>,
    /// The end (exclusive).
    pub end: DateTime<Utc>,
}

impl BusyPeriod {
    /// Whether the period overlaps the half-open interval `[start, end)`.
    pub fn overlaps(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
        self.start < end && start < self.end
    }
}

/// The busy time of a principal over a range, as computed by the application from free-busy data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FreeBusy {
    /// The busy periods, in any order; they may overlap.
    pub busy: Vec<BusyPeriod>,
}

impl FreeBusy {
    /// Whether any busy period overlaps the half-open interval `[start, end)`.
    pub fn is_busy(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
        self.busy.iter().any(|period| period.overlaps(start, end))
    }
}

/// An invitation that reaches an internal attendee.
#[derive(Debug, Clone, PartialEq)]
pub struct Invite {
    /// The tenant of the organizer and the attendee.
    pub tenant: PolicyTenant,
    /// The organizer's calendar user address.
    pub organizer: CalendarUserAddress,
    /// The internal attendee who receives the invitation.
    pub attendee: PrincipalId,
    /// The calendar the invitation would be added to (the attendee's default calendar).
    pub calendar: CalendarId,
}

/// A booking request for a resource (room, equipment).
///
/// The busy time that goes with it (`free_busy` of [`SchedulingPolicy::resource_reply`]) is exactly the busy
/// periods of the resource that collide with an instance of the request, without the event's own copy. The
/// application expands the instances itself, for a single request and a recurring one alike, so a period in the
/// list is a collision whatever `start`, `end` and `recurring` say. A policy decides what a collision means (a
/// room is taken, a pool of equipment still has units left); the contract suite checks the mechanics only.
pub struct ResourceRequest {
    /// The tenant of the resource.
    pub tenant: PolicyTenant,
    /// The resource principal that is asked.
    pub resource: PrincipalId,
    /// The organizer's calendar user address.
    pub organizer: CalendarUserAddress,
    /// The start of the first instance.
    pub start: DateTime<Utc>,
    /// The end of the last instance of the examined span.
    pub end: DateTime<Utc>,
    /// Whether the request recurs.
    pub recurring: bool,
}

/// The customisation point of scheduling decisions.
#[async_trait]
pub trait SchedulingPolicy: Send + Sync {
    /// Whether the invitation is added to the attendee's calendar automatically (otherwise it waits in the
    /// scheduling inbox).
    async fn auto_add(&self, invite: &Invite) -> bool;

    /// How a resource answers a booking request: `Some(partstat)` answers automatically (accept or decline by
    /// `free_busy`), `None` leaves the request for a person to answer.
    ///
    /// `free_busy` holds the busy periods of the resource that collide with an instance of the request: the
    /// application has expanded the instances already, so every period in it is a collision, and an empty list
    /// means the resource is free for all of them. Whether a collision means "decline" is the policy's decision (a
    /// resource with capacity above one may accept a booking next to others).
    async fn resource_reply(&self, request: &ResourceRequest, free_busy: &FreeBusy) -> Option<PartStat>;

    /// Whether the tenant may send scheduling mail to `address`, an address outside the tenant.
    async fn external_allowed(&self, tenant: &PolicyTenant, address: &CalendarUserAddress) -> bool;
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 5, 4, hour, 0, 0).unwrap()
    }

    #[test]
    fn busy_periods_overlap_half_open_intervals() {
        let period = BusyPeriod {
            start: at(10),
            end: at(12),
        };
        assert!(period.overlaps(at(9), at(11)));
        assert!(period.overlaps(at(11), at(13)));
        assert!(period.overlaps(at(10), at(12)));
        assert!(period.overlaps(at(0), at(23)));
        assert!(!period.overlaps(at(12), at(14)), "the end is exclusive");
        assert!(!period.overlaps(at(8), at(10)), "the range end is exclusive");
    }

    #[test]
    fn free_busy_reports_any_overlap() {
        let free_busy = FreeBusy {
            busy: vec![
                BusyPeriod {
                    start: at(9),
                    end: at(10),
                },
                BusyPeriod {
                    start: at(14),
                    end: at(15),
                },
            ],
        };
        assert!(free_busy.is_busy(at(9), at(11)));
        assert!(free_busy.is_busy(at(14), at(16)));
        assert!(!free_busy.is_busy(at(10), at(14)));
        assert!(!FreeBusy::default().is_busy(at(0), at(23)));
    }
}
