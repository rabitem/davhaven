//! Deleting a scheduling object: the organizer's deletion cancels the event, an attendee's deletion declines it.

use davhaven_domain::{CalendarUserAddress, ComponentKind, PartStat, Precondition};
use davhaven_ical::ErrorContext;
use davhaven_ical::itip::{ReplySpec, apply_reply_with, reply_message};
use davhaven_ports::Tx;

use super::actor::{ActorInfo, mailto_of};
use super::execute::{Plan, ReplyPlan, Subject};
use super::organizer::{Change, Inputs};
use super::plan::{Decision, is_cancelled, scheduled_attendees};
use super::scheduler::{Scheduler, asks_for_a_person, needs_a_person, refuse};
use crate::error::{AppError, AppResult};
use crate::itip::{blocking_ical, is_data_error, machine_error};
use crate::objects::DeleteFacts;
use crate::services::{ScheduleOutcome, ScheduleReply};

impl Scheduler {
    /// Plans and carries out what deleting an object tells the others.
    ///
    /// * The organizer's deletion cancels the event for every attendee the server schedules (an event that is
    ///   cancelled already has told them), and their RSVP links stop working.
    /// * An attendee's deletion (or the deletion by somebody who writes the calendar of an attendee for them) answers
    ///   `DECLINED` to the organizer unless the client asked not to (`Schedule-Reply: F`) or the attendee had
    ///   declined already.
    /// * Anybody else deletes without a word, except on the calendar of a group: a meeting there is deleted by its
    ///   organizer only (403 `allowed-organizer-scheduling-object-change`), because the attendees would keep a
    ///   meeting nobody cancelled.
    pub(super) async fn plan_delete(&self, tx: &mut dyn Tx, facts: &DeleteFacts<'_>) -> AppResult<ScheduleOutcome> {
        let existing = facts.existing;
        let Some(actor) = ActorInfo::resolve(tx, facts.ctx, facts.tenant, facts.calendar.owner_id).await? else {
            if existing.is_scheduling && asks_for_a_person(facts.ctx, facts.notify_attendees) {
                return Err(needs_a_person());
            }
            return Ok(ScheduleOutcome::none());
        };
        if existing.component != ComponentKind::Event {
            return Ok(ScheduleOutcome::none());
        }
        let (true, Some(organizer)) = (existing.is_scheduling, existing.organizer_address.clone()) else {
            return Ok(ScheduleOutcome::none());
        };
        if actor.speaks_for(&organizer) {
            return self.cancel_event(tx, facts, &actor, &organizer).await;
        }
        let rows = tx.objects().attendees(existing.id).await?;
        if rows.iter().any(|row| actor.speaks_for(&row.address)) {
            if facts.reply == ScheduleReply::Send {
                return self.decline_event(tx, facts, &actor, &organizer).await;
            }
            return Ok(ScheduleOutcome::none());
        }
        if actor.in_group_calendar {
            return Err(refuse(
                Precondition::AllowedOrganizerSchedulingObjectChange,
                "Only the organizer deletes a meeting in the calendar of a group.",
            ));
        }
        Ok(ScheduleOutcome::none())
    }

    /// The organizer deletes: every attendee gets the cancellation.
    async fn cancel_event(
        &self,
        tx: &mut dyn Tx,
        facts: &DeleteFacts<'_>,
        actor: &ActorInfo,
        organizer: &CalendarUserAddress,
    ) -> AppResult<ScheduleOutcome> {
        let existing = facts.existing;
        let text = existing.data.clone();
        let (calendar, index) = blocking_ical(&self.core, move |limits| {
            let calendar = davhaven_ical::parse::parse(text.as_bytes(), limits)?;
            let validated = davhaven_ical::validate::validate(calendar.clone(), limits)?;
            let index = davhaven_ical::index::index(&validated, limits)?;
            Ok((calendar, index))
        })
        .await?
        .map_err(|error| AppError::from_ical(error, ErrorContext::Store))?;
        if is_cancelled(&calendar) {
            // Its attendees were told when it was cancelled.
            return Ok(ScheduleOutcome::none());
        }
        let is_organizer = |address: &CalendarUserAddress| address == organizer || actor.speaks_for(address);
        let targets = scheduled_attendees(&index.attendees, is_organizer);
        let decision = Decision {
            cancel_new: targets.iter().map(|attendee| attendee.address.clone()).collect(),
            ..Decision::default()
        };
        let inputs = Inputs {
            ctx: facts.ctx,
            tenant: facts.tenant,
            actor,
            calendar: facts.calendar,
            uid: &existing.uid,
            index: &index,
            organizer,
        };
        let (_, plan) = self
            .prepare(
                tx,
                &inputs,
                Change {
                    targets: &targets,
                    old_targets: &targets,
                    decision: &decision,
                    incoming: calendar.clone(),
                    calendar,
                    old: None,
                    write_statuses: false,
                },
            )
            .await?;
        self.execute(
            tx,
            &Subject {
                ctx: facts.ctx,
                tenant: facts.tenant,
                calendar: facts.calendar.id,
                object: existing.id,
                uid: &existing.uid,
            },
            &plan,
        )
        .await?;
        Ok(plan.outcome)
    }

    /// An attendee deletes their copy: the organizer hears `DECLINED`.
    async fn decline_event(
        &self,
        tx: &mut dyn Tx,
        facts: &DeleteFacts<'_>,
        actor: &ActorInfo,
        organizer: &CalendarUserAddress,
    ) -> AppResult<ScheduleOutcome> {
        let existing = facts.existing;
        let rows = tx.objects().attendees(existing.id).await?;
        let Some(row) = rows.iter().find(|row| actor.speaks_for(&row.address)) else {
            return Ok(ScheduleOutcome::none());
        };
        let Some(identity) = actor.identity_of(&row.address) else {
            return Ok(ScheduleOutcome::none());
        };
        if row.partstat == PartStat::Declined {
            return Ok(ScheduleOutcome::none());
        }
        let attendee = row.address.clone();
        let text = existing.data.clone();
        let (uid, sequence) = (existing.uid.clone(), existing.sequence);
        let (to, who) = (organizer.clone(), attendee.clone());
        let now = self.core.deps().clock.now();
        let declined = blocking_ical(&self.core, move |limits| {
            let copy = davhaven_ical::parse::parse(text.as_bytes(), limits)?;
            let message = reply_message(&ReplySpec {
                uid: &uid,
                organizer: &to,
                attendee: &who,
                partstat: PartStat::Declined,
                sequence,
                dtstamp: now,
                comment: None,
            })?;
            let applied = apply_reply_with(&copy, &message, limits, Some(&who))?;
            davhaven_ical::serialize::serialize(&applied.updated)
        })
        .await?;
        let copy = match declined {
            Ok(copy) => copy,
            // A copy the decline cannot be folded into is deleted without telling the organizer.
            Err(error) if is_data_error(&error) => return Ok(ScheduleOutcome::none()),
            Err(error) => return Err(machine_error(error)),
        };
        let plan = Plan {
            reply: Some(ReplyPlan {
                copy,
                principal: identity.id,
                attendee,
                mailto: mailto_of(identity),
                organizer: organizer.clone(),
                comment: None,
            }),
            ..Plan::default()
        };
        self.execute(
            tx,
            &Subject {
                ctx: facts.ctx,
                tenant: facts.tenant,
                calendar: facts.calendar.id,
                object: existing.id,
                uid: &existing.uid,
            },
            &plan,
        )
        .await?;
        Ok(ScheduleOutcome::none())
    }
}
