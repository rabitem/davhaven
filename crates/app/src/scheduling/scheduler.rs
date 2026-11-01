//! The scheduler of the object write path: RFC 6638 implicit scheduling inside the transaction of the write.
//!
//! [`Scheduler`] implements the seam [`ObjectScheduler`] of the object use cases. A write is offered to it at three
//! points (see `objects::schedule`); what it does depends on **who** writes and **what** the object says:
//!
//! | The actor is … | before the write | after the write |
//! | --- | --- | --- |
//! | the organizer (the `ORGANIZER` is one of their addresses, or the owner's while they write that calendar) | compares the new copy with the stored one, keeps the answers and delivery states the server holds, raises `SEQUENCE`, classifies the attendees, asks the policy, writes `SCHEDULE-STATUS` | delivers to internal attendees (inbox, copy), queues iMIP mail and over-cap deliveries, revokes the RSVP links of removed attendees |
//! | an attendee (their address, or the owner's while they write that calendar, is on the object, the `ORGANIZER` is somebody else) | only their own `ATTENDEE` parameters, `PARTSTAT`, alarms and `TRANSP` may change (403 `allowed-attendee-scheduling-object-change`); a write that is stale by `ETag` but current by `Schedule-Tag` keeps the stored copy and takes over the answer | sends the answer to the organizer (the organizer's copy for an internal organizer, an iMIP `REPLY` for an external one) |
//! | neither | nothing, except the rules that keep an object from becoming somebody else's meeting: a new object, or one that was none, cannot name another internal principal as organizer (403 `organizer-allowed`), the `ORGANIZER` of a meeting cannot change, and on the calendar of a group only its organizer changes a meeting (403 `allowed-organizer-scheduling-object-change`) | nothing |
//!
//! The decision of `before_write` is carried to `after_write` in a [`Plan`] inside the
//! [`Handover`](crate::objects::Handover) of the write: the mails need the id the object gets when it is stored, and
//! nothing is kept anywhere else, so a write that fails in between takes its plan with it.

use async_trait::async_trait;
use davhaven_domain::{CalendarUserAddress, Channel, ComponentKind, Precondition, RequestContext};
use davhaven_ports::Tx;

use super::actor::ActorInfo;
use super::execute::{Plan, Subject};
use super::quota::Quotas;
use crate::error::{AppError, AppResult, SafeMessage};
use crate::itip::ItipProcessor;
use crate::objects::{DeleteFacts, Handover, ObjectScheduler, ScheduledWrite, WriteFacts, Written};
use crate::services::ScheduleOutcome;
use crate::wiring::AppCore;

/// The server-side scheduler (see the module documentation).
#[derive(Debug)]
pub struct Scheduler {
    pub(super) core: AppCore,
    pub(super) processor: ItipProcessor,
    pub(super) quotas: Quotas,
}

impl Scheduler {
    /// Creates the scheduler on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self {
            processor: ItipProcessor::new(core.clone()),
            core,
            quotas: Quotas::default(),
        }
    }

    /// The part the actor plays in a write.
    async fn role(&self, tx: &mut dyn Tx, facts: &WriteFacts<'_>, actor: &ActorInfo) -> AppResult<Role> {
        let existing_organizer = facts.existing.and_then(|object| object.organizer_address.clone());
        let Some(organizer) = existing_organizer.or_else(|| facts.index.organizer.clone()) else {
            return Ok(Role::None);
        };
        let invited = !facts.index.attendees.is_empty();
        if actor.speaks_for(&organizer) {
            let was_meeting = facts.existing.is_some_and(|object| object.is_scheduling);
            return Ok(if invited || was_meeting {
                Role::Organizer(organizer)
            } else {
                Role::None
            });
        }
        // An attendee: the actor, or the owner of the calendar they write (a delegate answers for the owner).
        let on_event = facts
            .index
            .attendees
            .iter()
            .any(|attendee| actor.speaks_for(&attendee.address));
        let was_attendee = match facts.existing {
            Some(object) if object.is_scheduling && !on_event => tx
                .objects()
                .attendees(object.id)
                .await?
                .iter()
                .any(|row| actor.speaks_for(&row.address)),
            _ => false,
        };
        if on_event || was_attendee {
            return Ok(Role::Attendee(organizer));
        }
        Ok(
            if invited || facts.existing.is_some_and(|object| object.is_scheduling) {
                Role::Foreign(organizer)
            } else {
                Role::None
            },
        )
    }

    /// What a write that does not schedule is: stored as the client sent it, unless the client based it on an older
    /// version than the stored one (`If-Schedule-Tag-Match` excused a stale `If-Match`): only an attendee's answer
    /// and an organizer's edit are merged with what the server holds, anybody else's write would overwrite it.
    fn unscheduled(facts: &WriteFacts<'_>) -> AppResult<ScheduledWrite> {
        if facts.stale_etag_excused {
            return Err(AppError::precondition_failed());
        }
        Ok(ScheduledWrite::default())
    }
}

/// The part an actor plays in a write.
#[derive(Debug)]
pub(super) enum Role {
    /// The actor organizes the event (with this `ORGANIZER`).
    Organizer(CalendarUserAddress),
    /// The actor is invited to an event somebody else organizes.
    Attendee(CalendarUserAddress),
    /// A scheduling object the actor has nothing to do with.
    Foreign(CalendarUserAddress),
    /// Not a scheduling write.
    None,
}

/// Whether a caller who acts as nobody (a tenant token) asked for attendees to be notified: invitations are sent in the
/// name of a person, so the request cannot be carried out, and the caller is told instead of getting a write that
/// silently told nobody (API and MCP only: DAV always has a person, and the server's own work asks for nothing).
pub(super) fn asks_for_a_person(ctx: &RequestContext, notify_attendees: bool) -> bool {
    notify_attendees && matches!(ctx.channel, Channel::Api | Channel::Mcp)
}

/// The refusal of a request that wants attendees notified without a person to do it in the name of.
pub(super) fn needs_a_person() -> AppError {
    AppError::invalid(SafeMessage::from_static(
        "Attendees can be notified only by a request that acts as a person: use a principal token, or do not ask for \
         attendees to be notified.",
    ))
}

/// The refusal of a precondition of RFC 6638.
pub(super) fn refuse(precondition: Precondition, message: &'static str) -> AppError {
    AppError::forbidden()
        .with_public_message(SafeMessage::from_static(message))
        .with_precondition(precondition)
}

#[async_trait]
impl ObjectScheduler for Scheduler {
    async fn before_write(&self, tx: &mut dyn Tx, facts: &WriteFacts<'_>) -> AppResult<ScheduledWrite> {
        // Only events are scheduled: to-dos and journal entries with an organizer and attendees are stored as they are.
        if facts.index.component != ComponentKind::Event {
            return Self::unscheduled(facts);
        }
        let Some(actor) = ActorInfo::resolve(tx, facts.ctx, facts.tenant, facts.calendar.owner_id).await? else {
            if facts.index.is_scheduling && asks_for_a_person(facts.ctx, facts.notify_attendees) {
                return Err(needs_a_person());
            }
            return Self::unscheduled(facts);
        };
        let planned = match self.role(tx, facts, &actor).await? {
            Role::Organizer(organizer) => self.plan_organizer(tx, facts, &actor, &organizer).await?,
            Role::Attendee(organizer) => self.plan_attendee(tx, facts, &actor, &organizer).await?,
            Role::Foreign(organizer) => {
                self.check_foreign(tx, facts, &actor, &organizer).await?;
                return Self::unscheduled(facts);
            }
            Role::None => return Self::unscheduled(facts),
        };
        Ok(ScheduledWrite {
            handover: Handover::new(planned.plan),
            ..planned.write
        })
    }

    async fn after_write(
        &self,
        tx: &mut dyn Tx,
        facts: &WriteFacts<'_>,
        written: &Written<'_>,
    ) -> AppResult<ScheduleOutcome> {
        // A write that did not schedule hands over nothing.
        let Some(plan) = written.handover.get::<Plan>() else {
            return Ok(ScheduleOutcome::none());
        };
        self.execute(
            tx,
            &Subject {
                ctx: facts.ctx,
                tenant: facts.tenant,
                calendar: facts.calendar.id,
                object: written.object,
                uid: &facts.index.uid,
            },
            plan,
        )
        .await?;
        Ok(plan.outcome.clone())
    }

    async fn before_delete(&self, tx: &mut dyn Tx, facts: &DeleteFacts<'_>) -> AppResult<ScheduleOutcome> {
        self.plan_delete(tx, facts).await
    }

    fn merges_stale_attendee_writes(&self) -> bool {
        true
    }
}

/// A plan together with what the write path is told before the write.
pub(super) struct Planned {
    /// What the write stores and how its `Schedule-Tag` goes.
    pub(super) write: ScheduledWrite,
    /// What happens after the write.
    pub(super) plan: Plan,
}
