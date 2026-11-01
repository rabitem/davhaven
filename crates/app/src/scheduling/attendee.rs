//! The attendee's side of a write: what an attendee may change on their copy and the answer that follows.

use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarUserAddress, CuType, EventData, EventTime, IcalLimits, ItipMethod, PartStat, Precondition,
};
use davhaven_ical::itip::{MessageSpec, apply_reply_with, attendee_change_violations, build_message};
use davhaven_ical::{ErrorContext, IcalError, ParsedCalendar};
use davhaven_ports::Tx;

use super::actor::{ActorInfo, mailto_of};
use super::execute::{Plan, ReplyPlan};
use super::scheduler::{Planned, Scheduler, refuse};
use crate::addresses::{Class, Directory};
use crate::error::{AppError, AppResult};
use crate::itip::{blocking_ical, organizer_copy};
use crate::objects::{ScheduleTagPlan, ScheduledWrite, WriteFacts};

/// The answers of an attendee on the components of an event: the instance (`None` for the master) and the
/// participation status.
pub(super) type Answers = Vec<(Option<EventTime>, PartStat)>;

fn answer_in(data: &EventData, attendee: &CalendarUserAddress) -> Option<PartStat> {
    data.attendees
        .as_ref()?
        .iter()
        .find(|candidate| &candidate.address == attendee)
        .map(|candidate| candidate.partstat.unwrap_or_default())
}

/// The answers `attendee` gave on the components of `calendar`.
pub(super) fn answers_of(calendar: &ParsedCalendar, attendee: &CalendarUserAddress) -> Result<Answers, IcalError> {
    let mut found: Answers = Vec::new();
    if let Ok(master) = davhaven_ical::merge::to_event_data(calendar, None)
        && let Some(partstat) = answer_in(&master, attendee)
    {
        found.push((None, partstat));
    }
    for instance in davhaven_ical::merge::override_ids(calendar)? {
        if let Ok(data) = davhaven_ical::merge::to_event_data(calendar, Some(&instance))
            && let Some(partstat) = answer_in(&data, attendee)
        {
            found.push((Some(instance), partstat));
        }
    }
    Ok(found)
}

/// Whether the attendee answered something new: an answer (not `NEEDS-ACTION`) that differs from what the same
/// component said before, or, for an instance that had no answer of its own, from what the series said.
pub(super) fn needs_reply(before: &[(Option<EventTime>, PartStat)], after: &[(Option<EventTime>, PartStat)]) -> bool {
    let series = before
        .iter()
        .find(|(instance, _)| instance.is_none())
        .map(|(_, partstat)| *partstat);
    after.iter().any(|(instance, partstat)| {
        if !partstat.is_answer() {
            return false;
        }
        let previous = before
            .iter()
            .find(|(known, _)| known == instance)
            .map(|(_, previous)| *previous)
            .or(series);
        previous != Some(*partstat)
    })
}

/// What reading an attendee's write found.
#[derive(Debug)]
struct Review {
    /// What the attendee changed that only the organizer may.
    violations: Vec<String>,
    /// The stored copy with the attendee's answers, when the client's copy was based on an earlier version.
    merged: Option<String>,
    /// The answers before and after the write.
    before: Answers,
    after: Answers,
}

/// Reads an attendee's write: what may they change, what did they answer. Runs on a blocking thread.
fn review(
    old_text: Option<&str>,
    incoming: &ParsedCalendar,
    attendee: &CalendarUserAddress,
    organizer: &CalendarUserAddress,
    may_merge: bool,
    now: DateTime<Utc>,
    limits: &IcalLimits,
) -> Result<Review, IcalError> {
    let old = old_text
        .map(|text| davhaven_ical::parse::parse(text.as_bytes(), limits))
        .transpose()?;
    let before = old
        .as_ref()
        .map(|old| answers_of(old, attendee))
        .transpose()?
        .unwrap_or_default();
    let mut violations = match &old {
        Some(old) => attendee_change_violations(old, incoming, attendee)?,
        None => Vec::new(),
    };
    let mut after = answers_of(incoming, attendee)?;
    let mut merged = None;
    if !violations.is_empty()
        && may_merge
        && let Some(old) = &old
    {
        // The client's copy is based on an earlier version of the event that nothing significant has changed since
        // (its `Schedule-Tag` is current): the stored copy stays and takes over what the attendee answered.
        let message = build_message(
            incoming,
            &MessageSpec {
                replying_attendee: Some(attendee.clone()),
                ..MessageSpec::new(ItipMethod::Reply, organizer.clone(), now)
            },
        );
        if let Ok(message) = message
            && let Ok(applied) = apply_reply_with(old, &message, limits, Some(attendee))
        {
            after = answers_of(&applied.updated, attendee)?;
            merged = Some(davhaven_ical::serialize::serialize(&applied.updated)?);
            violations.clear();
        }
    }
    Ok(Review {
        violations,
        merged,
        before,
        after,
    })
}

impl Scheduler {
    /// Plans an attendee's write.
    pub(super) async fn plan_attendee(
        &self,
        tx: &mut dyn Tx,
        facts: &WriteFacts<'_>,
        actor: &ActorInfo,
        organizer: &CalendarUserAddress,
    ) -> AppResult<Planned> {
        let existing = facts.existing;
        if existing.is_none() {
            self.check_invited(tx, facts, actor, organizer).await?;
        }
        // The attendee is the actor, or the owner of the calendar when the actor writes it for them.
        let removal = || {
            refuse(
                Precondition::AllowedAttendeeSchedulingObjectChange,
                "An attendee cannot remove themselves from the event this way; delete the event to decline it.",
            )
        };
        let Some(attendee) = actor
            .among(facts.index.attendees.iter().map(|attendee| &attendee.address))
            .cloned()
        else {
            return Err(removal());
        };
        let Some(identity) = actor.identity_of(&attendee) else {
            return Err(removal());
        };
        let may_merge = match (existing, facts.if_schedule_tag_match) {
            (Some(object), Some(tag)) => object.schedule_tag.as_ref() == Some(tag),
            _ => false,
        };
        let old_text = existing.map(|object| object.data.clone());
        let incoming = facts.incoming.clone();
        let (who, to) = (attendee.clone(), organizer.clone());
        let now = self.core.deps().clock.now();
        let review = blocking_ical(&self.core, move |limits| {
            review(old_text.as_deref(), &incoming, &who, &to, may_merge, now, limits)
        })
        .await?
        .map_err(|error| AppError::from_ical(error, ErrorContext::Store))?;
        if !review.violations.is_empty() {
            return Err(refuse(
                Precondition::AllowedAttendeeSchedulingObjectChange,
                "An attendee may only change their own participation, alarms and transparency.",
            ));
        }
        let reply = needs_reply(&review.before, &review.after).then(|| ReplyPlan {
            copy: review.merged.clone().unwrap_or_else(|| facts.body.to_owned()),
            principal: identity.id,
            attendee,
            mailto: mailto_of(identity),
            organizer: organizer.clone(),
            comment: facts.reply_comment.map(str::to_owned),
        });
        Ok(Planned {
            write: ScheduledWrite {
                data: review.merged,
                schedule_tag: ScheduleTagPlan::Fresh,
                ..ScheduledWrite::default()
            },
            plan: Plan {
                reply,
                ..Plan::default()
            },
        })
    }

    /// Creating a copy of an event somebody in the tenant organizes needs an invitation: the organizer's copy has to
    /// name the writer as an attendee (`CALDAV:organizer-allowed`).
    async fn check_invited(
        &self,
        tx: &mut dyn Tx,
        facts: &WriteFacts<'_>,
        actor: &ActorInfo,
        organizer: &CalendarUserAddress,
    ) -> AppResult<()> {
        let urls = &self.core.deps().urls;
        let directory = Directory::load(tx, facts.tenant, urls, std::slice::from_ref(organizer)).await?;
        match directory.classify(organizer, CuType::Individual) {
            Class::Internal(principal) | Class::Resource(principal) => {
                let invited = match organizer_copy(tx, facts.tenant, &principal, &facts.index.uid).await? {
                    Some(copy) => tx.objects().attendees(copy.id).await?.iter().any(|row| {
                        row.principal_id.is_some_and(|id| actor.speaks_as(id)) || actor.speaks_for(&row.address)
                    }),
                    None => false,
                };
                if invited { Ok(()) } else { Err(not_allowed()) }
            }
            Class::Group => Err(not_allowed()),
            Class::External | Class::Unknown => Ok(()),
        }
    }

    /// An object that names somebody else as organizer and the writer as nothing.
    ///
    /// * A meeting that exists (a scheduling object) keeps its `ORGANIZER`: a write that names another one is the
    ///   way to put words in the mouth of a colleague and is refused (`CALDAV:allowed-organizer-scheduling-object-change`).
    ///   On the calendar of a group only the organizer changes a meeting, because what an other member writes would
    ///   reach nobody: the attendees keep the version the organizer sent. Anywhere else (the writer's own calendar,
    ///   or one whose owner they write for) an event of somebody else's is an imported one and is stored as it is.
    /// * A new object, and an object that was no meeting yet, cannot name another principal of the tenant as
    ///   organizer (`CALDAV:organizer-allowed`): writing the event in two steps is no way around the rule.
    pub(super) async fn check_foreign(
        &self,
        tx: &mut dyn Tx,
        facts: &WriteFacts<'_>,
        actor: &ActorInfo,
        organizer: &CalendarUserAddress,
    ) -> AppResult<()> {
        let incoming = facts.index.organizer.as_ref().unwrap_or(organizer);
        if let Some(existing) = facts.existing.filter(|object| object.is_scheduling) {
            if existing.organizer_address.as_ref() != facts.index.organizer.as_ref() {
                return Err(refuse(
                    Precondition::AllowedOrganizerSchedulingObjectChange,
                    "The organizer and the UID of a scheduling object cannot be changed.",
                ));
            }
            if actor.in_group_calendar {
                return Err(refuse(
                    Precondition::AllowedOrganizerSchedulingObjectChange,
                    "Only the organizer changes a meeting in the calendar of a group.",
                ));
            }
            return Ok(());
        }
        if actor.speaks_for(incoming) {
            return Ok(());
        }
        let urls = &self.core.deps().urls;
        let directory = Directory::load(tx, facts.tenant, urls, std::slice::from_ref(incoming)).await?;
        match directory.classify(incoming, CuType::Individual) {
            Class::Internal(_) | Class::Resource(_) | Class::Group => Err(not_allowed()),
            Class::External | Class::Unknown => Ok(()),
        }
    }
}

fn not_allowed() -> AppError {
    refuse(
        Precondition::OrganizerAllowed,
        "The organizer of a new event must be you, or somebody outside this organisation.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(day: u32) -> EventTime {
        EventTime::Utc(chrono::TimeZone::with_ymd_and_hms(&Utc, 2027, 3, day, 9, 0, 0).unwrap())
    }

    #[test]
    fn a_new_answer_needs_a_reply_and_a_repeated_one_does_not() {
        let before: Answers = vec![(None, PartStat::NeedsAction)];
        assert!(needs_reply(&before, &[(None, PartStat::Accepted)]));
        assert!(needs_reply(&before, &[(None, PartStat::Declined)]));
        assert!(!needs_reply(&before, &[(None, PartStat::NeedsAction)]));
        let answered: Answers = vec![(None, PartStat::Accepted)];
        assert!(!needs_reply(&answered, &answered));
        assert!(needs_reply(&answered, &[(None, PartStat::Tentative)]));
        assert!(
            !needs_reply(&answered, &[(None, PartStat::NeedsAction)]),
            "going back to no answer tells nobody anything"
        );
        assert!(
            needs_reply(&[], &[(None, PartStat::Accepted)]),
            "a copy that is created with an answer is an answer"
        );
        assert!(!needs_reply(&[], &[(None, PartStat::NeedsAction)]));
    }

    #[test]
    fn an_instance_is_compared_with_its_own_answer_or_the_series() {
        let before: Answers = vec![(None, PartStat::Accepted), (Some(instance(8)), PartStat::Declined)];
        let same: Answers = before.clone();
        assert!(!needs_reply(&before, &same));
        let new_override: Answers = vec![(None, PartStat::Accepted), (Some(instance(15)), PartStat::Accepted)];
        assert!(
            !needs_reply(&before, &new_override),
            "a new override that repeats the series says nothing new"
        );
        let moved: Answers = vec![(None, PartStat::Accepted), (Some(instance(15)), PartStat::Declined)];
        assert!(needs_reply(&before, &moved));
        let changed: Answers = vec![(None, PartStat::Accepted), (Some(instance(8)), PartStat::Accepted)];
        assert!(needs_reply(&before, &changed));
    }
}
