//! The scheduling seam of the object write path.
//!
//! Server-side scheduling (RFC 6638, PLAN 2.8) is not part of the object use cases: they only know *when* a write
//! may schedule and call an [`ObjectScheduler`] at the three points where scheduling has to act **inside the
//! transaction of the write**:
//!
//! 1. [`before_write`](ObjectScheduler::before_write): the incoming object is about to be stored. The scheduler
//!    decides whether the write schedules (organizer or attendee of the actor), checks the scheduling preconditions
//!    (`organizer-allowed`, `allowed-attendee-scheduling-object-change`, ...), may replace the bytes to store (the
//!    server writes `SCHEDULE-STATUS` into the organizer's copy and keeps the answers of the attendees) and says what
//!    happens to the `Schedule-Tag`;
//! 2. [`after_write`](ObjectScheduler::after_write): the object is stored; the scheduler delivers to internal
//!    attendees, queues iMIP mail and reports the status of every recipient;
//! 3. [`before_delete`](ObjectScheduler::before_delete): an object is about to be deleted; the organizer's
//!    deletion cancels, an attendee's deletion declines.
//!
//! The default, [`NoScheduling`], does nothing: objects are stored as the client sent them, scheduling objects get a
//! fresh `Schedule-Tag` on every write and nothing is delivered. The `scheduling` module provides the real
//! implementation and installs it with [`ObjectServiceImpl::with_scheduler`](super::ObjectServiceImpl::with_scheduler).
//!
//! The rules of PLAN 2.8 that decide *whether* a write is offered to the scheduler at all are applied before the
//! call: managed and mirror calendars never schedule (writes to them come through the API or the sync engine and
//! pass `notify_attendees = false`), batch writes never schedule, and API and MCP writes schedule only when the
//! caller asks (`notify_attendees`).

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{
    Calendar, CalendarUserAddress, ETag, ObjectId, ObjectIndex, ObjectUri, PrincipalId, RequestContext, ScheduleTag,
    StoredObject, Tenant,
};
use davhaven_ical::ParsedCalendar;
use davhaven_ports::Tx;

use crate::error::AppResult;
use crate::services::{ScheduleOutcome, ScheduleReply};

/// What the scheduler is told about a write that is about to happen.
#[non_exhaustive]
#[derive(Debug)]
pub struct WriteFacts<'a> {
    /// The caller.
    pub ctx: &'a RequestContext,
    /// The tenant, with its settings (external policy, duplicate suppression).
    pub tenant: &'a Tenant,
    /// The calendar the object is written to (locked in the transaction).
    pub calendar: &'a Calendar,
    /// The stored object that is replaced; `None` for a creation.
    pub existing: Option<&'a StoredObject>,
    /// The incoming object after validation.
    pub incoming: &'a ParsedCalendar,
    /// The index of the incoming object (organizer, attendees, sequence).
    pub index: &'a ObjectIndex,
    /// The incoming iCalendar text, as the client sent it.
    pub body: &'a str,
    /// The resource name the object is stored under.
    pub uri: &'a ObjectUri,
    /// `Schedule-Reply`.
    pub reply: ScheduleReply,
    /// `If-Schedule-Tag-Match`, when the client sent it.
    pub if_schedule_tag_match: Option<&'a ScheduleTag>,
    /// Whether the caller asked for attendees to be notified. DAV writes always count as asking; API and MCP
    /// writes do only with `notify_attendees`.
    pub notify_attendees: bool,
    /// The remark an answer carries that the object cannot hold: the attendee's comment of `respond_to_invitation`,
    /// which becomes the `COMMENT` of the `REPLY`.
    pub reply_comment: Option<&'a str>,
    /// Whether the write path accepted a stale `If-Match` because `If-Schedule-Tag-Match` matched the stored
    /// `Schedule-Tag` (and [`ObjectScheduler::merges_stale_attendee_writes`] said it merges). The client's bytes are
    /// then based on an older version than the stored one. Only the scheduler knows whether that is harmless for
    /// this write: an attendee's answer and an organizer's edit are merged with what the server holds, anybody
    /// else's write would overwrite it and has to be refused (`PreconditionFailed`).
    pub stale_etag_excused: bool,
}

/// What happens to the `Schedule-Tag` of the stored object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ScheduleTagPlan {
    /// A fresh tag when the object is a scheduling object resource, none otherwise.
    #[default]
    Fresh,
    /// The stored tag stays (a server merge: a reply, a status update).
    Keep,
    /// This tag.
    Set(ScheduleTag),
    /// No tag.
    Clear,
}

/// What a scheduler hands from [`before_write`](ObjectScheduler::before_write) to
/// [`after_write`](ObjectScheduler::after_write) of the **same write**: its plan, whatever it is. The write path
/// carries it and does not look inside, so the two calls need no state of their own keyed by something that two
/// requests could share (a request id the client chose, a resource name that exists in many calendars), and a write
/// that fails between the two calls takes its plan with it.
#[derive(Clone, Default)]
pub struct Handover(Option<Arc<dyn Any + Send + Sync>>);

impl Handover {
    /// Holds `state`.
    pub fn new<T: Any + Send + Sync>(state: T) -> Self {
        Self(Some(Arc::new(state)))
    }

    /// The state, when this handover holds a `T`.
    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.0.as_deref().and_then(|state| state.downcast_ref::<T>())
    }

    /// Whether nothing is held (the scheduler planned nothing).
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

impl fmt::Debug for Handover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handover").field("held", &self.0.is_some()).finish()
    }
}

impl PartialEq for Handover {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Eq for Handover {}

/// The scheduler's decision about the bytes and tags of a write.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScheduledWrite {
    /// The text to store instead of the client's. The write path validates, indexes and hashes it again, so the
    /// index (attendees, `SEQUENCE`), the content hash and the attendee rows that are stored are those of **these**
    /// bytes: a scheduler may change what matters to scheduling (raise `SEQUENCE`, reset `PARTSTAT`, write
    /// `SCHEDULE-STATUS`, merge the answers of the attendees). It must keep the UID and the component type of the
    /// object. The `ETag` is computed from the stored text and the response of the `PUT` then carries no `ETag`, as
    /// RFC 4791 section 5.3.4 asks.
    pub data: Option<String>,
    /// What happens to the `Schedule-Tag`.
    pub schedule_tag: ScheduleTagPlan,
    /// The principals the attendee addresses resolved to, when the scheduler resolved them itself. `None` lets the
    /// object use case resolve them.
    pub attendee_principals: Option<Vec<(CalendarUserAddress, PrincipalId)>>,
    /// What the scheduler wants handed back to [`after_write`](ObjectScheduler::after_write) (see [`Handover`]).
    pub handover: Handover,
}

/// What the scheduler is told about a deletion that is about to happen.
#[non_exhaustive]
#[derive(Debug)]
pub struct DeleteFacts<'a> {
    /// The caller.
    pub ctx: &'a RequestContext,
    /// The tenant, with its settings.
    pub tenant: &'a Tenant,
    /// The calendar the object is deleted from (locked in the transaction).
    pub calendar: &'a Calendar,
    /// The object that is deleted.
    pub existing: &'a StoredObject,
    /// `Schedule-Reply`: whether an attendee's deletion declines.
    pub reply: ScheduleReply,
    /// Whether the caller asked for attendees to be notified (see `WriteFacts::notify_attendees`).
    pub notify_attendees: bool,
}

/// The object as stored by a write.
#[non_exhaustive]
#[derive(Debug)]
pub struct Written<'a> {
    /// The object id.
    pub object: ObjectId,
    /// The resource name.
    pub uri: &'a ObjectUri,
    /// The sequence number of the change in the calendar's log.
    pub seq: u64,
    /// The `ETag` of the stored text.
    pub etag: &'a ETag,
    /// The `Schedule-Tag` of the stored object.
    pub schedule_tag: Option<&'a ScheduleTag>,
    /// The stored text.
    pub data: &'a str,
    /// Whether the object was created by this write.
    pub created: bool,
    /// What [`before_write`](ObjectScheduler::before_write) handed over.
    pub handover: &'a Handover,
}

/// Scheduling hooks of the object write path (see the module documentation).
#[async_trait]
pub trait ObjectScheduler: Send + Sync {
    /// Called inside the write transaction before an object is stored.
    ///
    /// # Errors
    ///
    /// The scheduling preconditions: `Forbidden` with `organizer-allowed` or
    /// `allowed-attendee-scheduling-object-change`, `PreconditionFailed` for a stale `Schedule-Tag`, and store
    /// failures. An error aborts the write.
    async fn before_write(&self, tx: &mut dyn Tx, facts: &WriteFacts<'_>) -> AppResult<ScheduledWrite>;

    /// Called inside the write transaction after the object was stored: delivery and mail. `written.handover` is
    /// what `before_write` of the same write returned.
    ///
    /// # Errors
    ///
    /// Store failures; an error aborts the write.
    async fn after_write(
        &self,
        tx: &mut dyn Tx,
        facts: &WriteFacts<'_>,
        written: &Written<'_>,
    ) -> AppResult<ScheduleOutcome>;

    /// Called inside the transaction of a deletion before the object is removed.
    ///
    /// # Errors
    ///
    /// Store failures; an error aborts the deletion.
    async fn before_delete(&self, tx: &mut dyn Tx, facts: &DeleteFacts<'_>) -> AppResult<ScheduleOutcome>;

    /// Whether an attendee's write that is stale by `ETag` but current by `Schedule-Tag` is merged instead of
    /// answered with `412` (PLAN 2.7). The write path calls it only when `If-Schedule-Tag-Match` matches the stored
    /// tag and `If-Match` does not match the stored `ETag`; `WriteFacts::stale_etag_excused` then tells
    /// `before_write` that the excuse was used, and a scheduler that merges only for some writers refuses the
    /// others there.
    fn merges_stale_attendee_writes(&self) -> bool {
        false
    }
}

/// The default scheduler: nothing is scheduled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoScheduling;

#[async_trait]
impl ObjectScheduler for NoScheduling {
    async fn before_write(&self, _tx: &mut dyn Tx, _facts: &WriteFacts<'_>) -> AppResult<ScheduledWrite> {
        Ok(ScheduledWrite::default())
    }

    async fn after_write(
        &self,
        _tx: &mut dyn Tx,
        _facts: &WriteFacts<'_>,
        _written: &Written<'_>,
    ) -> AppResult<ScheduleOutcome> {
        Ok(ScheduleOutcome::none())
    }

    async fn before_delete(&self, _tx: &mut dyn Tx, _facts: &DeleteFacts<'_>) -> AppResult<ScheduleOutcome> {
        Ok(ScheduleOutcome::none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Plan(u32);

    #[test]
    fn a_handover_gives_back_its_state_only_as_the_type_it_was_given() {
        let handover = Handover::new(Plan(7));
        assert!(!handover.is_empty());
        assert_eq!(handover.get::<Plan>(), Some(&Plan(7)));
        assert_eq!(handover.get::<u32>(), None, "another type reads nothing");
        let nothing = Handover::default();
        assert!(nothing.is_empty());
        assert_eq!(nothing.get::<Plan>(), None);
        assert_eq!(format!("{handover:?}"), "Handover { held: true }");
        assert_eq!(format!("{nothing:?}"), "Handover { held: false }");
    }

    #[test]
    fn handovers_are_equal_only_when_they_hold_the_same_state() {
        let handover = Handover::new(Plan(7));
        assert_eq!(handover, handover.clone(), "a clone shares the state");
        assert_ne!(
            handover,
            Handover::new(Plan(7)),
            "the plan of another write is another plan, whatever it says"
        );
        assert_ne!(handover, Handover::default());
        assert_eq!(Handover::default(), Handover::default());
        assert_eq!(ScheduledWrite::default().handover, Handover::default());
    }
}
