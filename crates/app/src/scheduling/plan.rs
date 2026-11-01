//! What an organizer's write sends to whom: the analysis of the two versions and the decision of PLAN 2.8.
//!
//! The decision mirrors the iTIP golden set of the `davhaven-ical` crate (`crates/fixtures/data/itip`): the pure parts of it
//! live here so they can be tested without a store, and the golden driver of `davhaven-ical` is the reference.

use davhaven_domain::{AttendeeRef, CalendarUserAddress, CuType, EventStatus, EventTime, IcalLimits, ScheduleAgent};
use davhaven_ical::itip::{
    ChangeClass, ItipDiff, OrganizerUpdate, apply_organizer_changes, organizer_change_violations,
};
use davhaven_ical::{IcalError, ParsedCalendar};

/// An attendee the server schedules for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attendee {
    /// The address as the organizer's copy names it.
    pub(crate) address: CalendarUserAddress,
    /// The calendar user type the event states.
    pub(crate) cutype: CuType,
}

/// The attendees of an event that the server sends messages to: those with `SCHEDULE-AGENT=SERVER`, except the
/// organizer's own lines (`is_organizer` says which addresses are the organizer's).
pub(crate) fn scheduled_attendees(
    attendees: &[AttendeeRef],
    is_organizer: impl Fn(&CalendarUserAddress) -> bool,
) -> Vec<Attendee> {
    attendees
        .iter()
        .filter(|attendee| attendee.schedule_agent == ScheduleAgent::Server && !is_organizer(&attendee.address))
        .map(|attendee| Attendee {
            address: attendee.address.clone(),
            cutype: attendee.cutype,
        })
        .collect()
}

/// The two versions of the organizer's copy, compared.
#[derive(Debug, Clone)]
pub(crate) struct Analysis {
    /// The stored copy, when there is one.
    pub(crate) old: Option<ParsedCalendar>,
    /// The attendees of the stored copy.
    pub(crate) old_attendees: Vec<AttendeeRef>,
    /// The new copy after the rules of PLAN 2.8 (answers and delivery states as the server holds them, `SEQUENCE`
    /// raised, answers reset where the change is significant) and the diff.
    pub(crate) update: OrganizerUpdate,
    /// What the client changed that nobody may change (`UID`, `ORGANIZER`).
    pub(crate) violations: Vec<String>,
    /// Whether the stored copy was cancelled already.
    pub(crate) old_cancelled: bool,
    /// Whether the new copy is cancelled.
    pub(crate) new_cancelled: bool,
    /// The copy the client sent, handed back so that nobody has to clone it for the comparison.
    pub(crate) incoming: ParsedCalendar,
}

/// Whether the master component of `calendar` is `STATUS:CANCELLED`.
pub(crate) fn is_cancelled(calendar: &ParsedCalendar) -> bool {
    davhaven_ical::merge::to_event_data(calendar, None)
        .ok()
        .and_then(|data| data.status)
        .is_some_and(|status| status == EventStatus::Cancelled)
}

/// Compares the stored organizer copy (`old_text`) with the new one. Runs on a blocking thread.
///
/// # Errors
///
/// The errors of parsing and of the iTIP diff.
pub(crate) fn analyse(
    old_text: Option<&str>,
    incoming: ParsedCalendar,
    limits: &IcalLimits,
) -> Result<Analysis, IcalError> {
    let old = old_text
        .map(|text| davhaven_ical::parse::parse(text.as_bytes(), limits))
        .transpose()?;
    let violations = match &old {
        Some(old) => organizer_change_violations(old, &incoming)?,
        None => Vec::new(),
    };
    let old_attendees = match &old {
        Some(old) => davhaven_ical::validate::validate(old.clone(), limits)
            .and_then(|validated| davhaven_ical::index::index(&validated, limits))
            .map(|index| index.attendees)
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let update = apply_organizer_changes(old.as_ref(), &incoming, limits)?;
    Ok(Analysis {
        old_cancelled: old.as_ref().is_some_and(is_cancelled),
        new_cancelled: is_cancelled(&update.calendar),
        old,
        old_attendees,
        update,
        violations,
        incoming,
    })
}

/// What an organizer's write sends to whom.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Decision {
    /// A `REQUEST` of the whole event, built from the new copy.
    pub(crate) request: Vec<CalendarUserAddress>,
    /// A `CANCEL` of the whole event, built from the new copy (the series was cancelled).
    pub(crate) cancel_new: Vec<CalendarUserAddress>,
    /// A `CANCEL` of the whole event, built from the stored copy (the attendee was removed from the event).
    pub(crate) cancel_old: Vec<CalendarUserAddress>,
    /// A `CANCEL` of single instances, built from the stored copy, with the instances.
    pub(crate) cancel_instances: Vec<(CalendarUserAddress, Vec<EventTime>)>,
    /// Attendees whose copy is brought up to date without a message (an insignificant edit).
    pub(crate) silent: Vec<CalendarUserAddress>,
}

impl Decision {
    /// Whether the copy of `address` has to follow the new organizer copy.
    pub(crate) fn updates_copy(&self, address: &CalendarUserAddress) -> bool {
        self.request.contains(address)
            || self.silent.contains(address)
            || self.cancel_instances.iter().any(|(who, _)| who == address)
    }
}

#[cfg(test)]
impl Decision {
    /// Whether `address` gets a message of any kind.
    fn messages(&self, address: &CalendarUserAddress) -> bool {
        self.request.contains(address)
            || self.cancel_new.contains(address)
            || self.cancel_old.contains(address)
            || self.cancel_instances.iter().any(|(who, _)| who == address)
    }

    /// Whether the decision sends and changes nothing.
    fn is_empty(&self) -> bool {
        self.request.is_empty()
            && self.cancel_new.is_empty()
            && self.cancel_old.is_empty()
            && self.cancel_instances.is_empty()
            && self.silent.is_empty()
    }
}

/// The facts the decision rests on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DecideInput<'a> {
    /// The comparison of the two versions.
    pub(crate) diff: &'a ItipDiff,
    /// The attendees of the new copy that the server schedules.
    pub(crate) targets: &'a [Attendee],
    /// The attendees of the stored copy that the server schedules.
    pub(crate) old_targets: &'a [Attendee],
    /// Whether the series was cancelled by this write.
    pub(crate) cancelled_series: bool,
}

/// Decides who gets which message (PLAN 2.8; the iTIP golden set is the reference):
///
/// * a cancelled series cancels the whole event for everybody (and for the attendees the same write removed from it),
///   and sends no `REQUEST`;
/// * a significant change of any instance, and a new object, sends a `REQUEST` of the whole event to everybody;
///   otherwise only the attendees who were added get one;
/// * attendees removed from the event get a `CANCEL` of the whole event built from the stored copy;
/// * cancelled instances (an added `EXDATE`, a removed override) and attendees dropped from single instances get a
///   `CANCEL` of those instances, built from the stored copy;
/// * an edit that is not significant sends nothing and brings the copies of the others up to date.
pub(crate) fn decide(input: &DecideInput<'_>) -> Decision {
    let addresses = |list: &[Attendee]| -> Vec<CalendarUserAddress> {
        list.iter().map(|attendee| attendee.address.clone()).collect()
    };
    if input.cancelled_series {
        // Attendees who were removed in the very write that cancels the series were invited, so they are told too;
        // their cancellation is built from the stored copy, which still lists them.
        let removed: Vec<Attendee> = input
            .old_targets
            .iter()
            .filter(|old| !input.targets.iter().any(|attendee| attendee.address == old.address))
            .cloned()
            .collect();
        return Decision {
            cancel_new: addresses(input.targets),
            cancel_old: addresses(&removed),
            ..Decision::default()
        };
    }
    let diff = input.diff;
    let changed = diff
        .instances
        .iter()
        .any(|instance| matches!(instance.change, ChangeClass::Created | ChangeClass::Significant));
    let request: Vec<CalendarUserAddress> = if changed {
        addresses(input.targets)
    } else {
        input
            .targets
            .iter()
            .filter(|attendee| diff.added_attendees.contains(&attendee.address))
            .map(|attendee| attendee.address.clone())
            .collect()
    };
    let cancel_old: Vec<CalendarUserAddress> = diff
        .removed_attendees
        .iter()
        .filter(|address| input.old_targets.iter().any(|attendee| &attendee.address == *address))
        .cloned()
        .collect();
    let mut cancel_instances: Vec<(CalendarUserAddress, Vec<EventTime>)> = Vec::new();
    let mut add_instances = |address: &CalendarUserAddress, instances: &[EventTime]| match cancel_instances
        .iter_mut()
        .find(|(who, _)| who == address)
    {
        Some((_, known)) => {
            for instance in instances {
                if !known.contains(instance) {
                    known.push(instance.clone());
                }
            }
        }
        None => cancel_instances.push((address.clone(), instances.to_vec())),
    };
    if !diff.cancelled_instances.is_empty() {
        for attendee in input.targets {
            add_instances(&attendee.address, &diff.cancelled_instances);
        }
    }
    for record in &diff.instance_attendees {
        let Some(instance) = &record.recurrence_id else {
            continue;
        };
        for removed in &record.removed {
            let still_invited = input.targets.iter().any(|attendee| &attendee.address == removed);
            if still_invited && !diff.removed_attendees.contains(removed) {
                add_instances(removed, std::slice::from_ref(instance));
            }
        }
    }
    let quiet = diff
        .instances
        .iter()
        .any(|instance| matches!(instance.change, ChangeClass::Insignificant | ChangeClass::Removed));
    let silent = if !changed && quiet {
        input
            .targets
            .iter()
            .filter(|attendee| !request.contains(&attendee.address))
            .map(|attendee| attendee.address.clone())
            .collect()
    } else {
        Vec::new()
    };
    Decision {
        request,
        cancel_new: Vec::new(),
        cancel_old,
        cancel_instances,
        silent,
    }
}

#[cfg(test)]
mod tests {
    use davhaven_ical::itip::InstanceAttendees;
    use davhaven_ical::itip::{InstanceDiff, ItipDiff};

    use super::*;

    fn address(name: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(&format!("mailto:{name}@example.net")).unwrap()
    }

    fn attendee(name: &str) -> Attendee {
        Attendee {
            address: address(name),
            cutype: CuType::Individual,
        }
    }

    fn instance(change: ChangeClass) -> InstanceDiff {
        InstanceDiff {
            recurrence_id: None,
            change,
            changed_properties: Vec::new(),
        }
    }

    fn diff(changes: &[ChangeClass]) -> ItipDiff {
        ItipDiff {
            instances: changes.iter().map(|change| instance(*change)).collect(),
            added_attendees: Vec::new(),
            removed_attendees: Vec::new(),
            cancelled_instances: Vec::new(),
            needs_sequence_bump: false,
            instance_attendees: Vec::new(),
        }
    }

    fn input<'a>(diff: &'a ItipDiff, targets: &'a [Attendee], old: &'a [Attendee], cancelled: bool) -> DecideInput<'a> {
        DecideInput {
            diff,
            targets,
            old_targets: old,
            cancelled_series: cancelled,
        }
    }

    #[test]
    fn a_new_object_requests_everybody() {
        let targets = [attendee("bob"), attendee("carol")];
        let diff = diff(&[ChangeClass::Created]);
        let decision = decide(&input(&diff, &targets, &[], false));
        assert_eq!(decision.request, vec![address("bob"), address("carol")]);
        assert!(decision.cancel_old.is_empty() && decision.silent.is_empty());
        assert!(decision.messages(&address("bob")) && decision.updates_copy(&address("carol")));
    }

    #[test]
    fn a_significant_change_requests_everybody_and_an_insignificant_one_nobody() {
        let targets = [attendee("bob"), attendee("carol")];
        let significant = diff(&[ChangeClass::Significant]);
        assert_eq!(decide(&input(&significant, &targets, &targets, false)).request.len(), 2);
        let quiet = diff(&[ChangeClass::Insignificant]);
        let decision = decide(&input(&quiet, &targets, &targets, false));
        assert!(decision.request.is_empty(), "an insignificant edit sends nothing");
        assert_eq!(
            decision.silent,
            vec![address("bob"), address("carol")],
            "the copies follow"
        );
        assert!(!decision.messages(&address("bob")) && decision.updates_copy(&address("bob")));
        let unchanged = diff(&[ChangeClass::Unchanged]);
        assert!(decide(&input(&unchanged, &targets, &targets, false)).is_empty());
    }

    #[test]
    fn an_added_attendee_is_requested_alone_when_nothing_else_changed() {
        let targets = [attendee("bob"), attendee("carol")];
        let mut quiet = diff(&[ChangeClass::Insignificant]);
        quiet.added_attendees = vec![address("carol")];
        let decision = decide(&input(&quiet, &targets, &targets[..1], false));
        assert_eq!(decision.request, vec![address("carol")]);
        assert_eq!(
            decision.silent,
            vec![address("bob")],
            "the others only get the update of their copy"
        );
    }

    #[test]
    fn removed_attendees_are_cancelled_from_the_stored_copy() {
        let targets = [attendee("bob")];
        let old = [attendee("bob"), attendee("carol")];
        let mut changed = diff(&[ChangeClass::Unchanged]);
        changed.removed_attendees = vec![address("carol")];
        let decision = decide(&input(&changed, &targets, &old, false));
        assert_eq!(decision.cancel_old, vec![address("carol")]);
        assert!(decision.messages(&address("carol")));
        assert!(
            !decision.updates_copy(&address("carol")),
            "their copy is removed, not updated"
        );
        let mut client_scheduled = changed.clone();
        client_scheduled.removed_attendees = vec![address("dave")];
        assert!(
            decide(&input(&client_scheduled, &targets, &old, false))
                .cancel_old
                .is_empty(),
            "somebody the server never scheduled gets nothing"
        );
    }

    #[test]
    fn cancelled_instances_and_instance_removals_cancel_instances() {
        let targets = [attendee("bob"), attendee("carol")];
        let moved = EventTime::Utc(chrono::DateTime::UNIX_EPOCH);
        let later = EventTime::Utc(chrono::DateTime::UNIX_EPOCH + chrono::Duration::days(7));
        let mut changed = diff(&[ChangeClass::Significant]);
        changed.cancelled_instances = vec![moved.clone()];
        changed.instance_attendees = vec![InstanceAttendees {
            recurrence_id: Some(later.clone()),
            added: Vec::new(),
            removed: vec![address("carol")],
        }];
        let decision = decide(&input(&changed, &targets, &targets, false));
        assert_eq!(decision.request.len(), 2, "the significant change is requested as well");
        let bob = decision
            .cancel_instances
            .iter()
            .find(|(who, _)| who == &address("bob"))
            .unwrap();
        assert_eq!(bob.1, vec![moved.clone()]);
        let carol = decision
            .cancel_instances
            .iter()
            .find(|(who, _)| who == &address("carol"))
            .unwrap();
        assert_eq!(
            carol.1,
            vec![moved, later],
            "dropped from one instance as well as the cancelled one"
        );
    }

    #[test]
    fn a_cancelled_series_is_cancelled_for_everybody_and_requests_nothing() {
        let targets = [attendee("bob"), attendee("carol")];
        let changed = diff(&[ChangeClass::Significant]);
        let decision = decide(&input(&changed, &targets, &targets, true));
        assert_eq!(decision.cancel_new, vec![address("bob"), address("carol")]);
        assert!(decision.request.is_empty() && decision.cancel_old.is_empty());
    }

    #[test]
    fn attendees_removed_by_the_write_that_cancels_the_series_are_cancelled_from_the_stored_copy() {
        let targets = [attendee("bob")];
        let old = [attendee("bob"), attendee("carol")];
        let changed = diff(&[ChangeClass::Significant]);
        let decision = decide(&input(&changed, &targets, &old, true));
        assert_eq!(decision.cancel_new, vec![address("bob")]);
        assert_eq!(
            decision.cancel_old,
            vec![address("carol")],
            "carol was invited and must hear that it is over"
        );
        assert_eq!(decision.request, Vec::new());
        assert!(
            !decision.updates_copy(&address("carol")),
            "their copy is removed, not updated"
        );
    }

    #[test]
    fn the_server_schedules_only_for_attendees_it_is_the_agent_of() {
        let mut client = AttendeeRef::new(address("client"));
        client.schedule_agent = ScheduleAgent::Client;
        let attendees = [
            AttendeeRef::new(address("bob")),
            client,
            AttendeeRef::new(address("anna")),
        ];
        let targets = scheduled_attendees(&attendees, |who| who == &address("anna"));
        assert_eq!(targets, vec![attendee("bob")]);
    }
}
