//! The decision table of the scheduling matrix: PLAN 2.8 and 3.3 in executable form.
//!
//! [`expected`] says what every cell of [`SchedulingCase::matrix`] must produce. It
//! is written from the rules of the plan and of the iTIP golden set (`crates/fixtures/data/itip/README.md`), **not**
//! computed from the code under test, and it knows nothing of the application: it looks at the dimensions of a case
//! and nothing else. The drivers (the one of `davhaven-it` that talks to the services, and [`super::driver`], which talks HTTP)
//! perform the case against the real application and compare.
//!
//! # The rules in one place
//!
//! **What an attendee is sent.** Over the creation of the event and one change, in order:
//!
//! | Change | Messages of an attendee in the tenant (inbox) | Mails to an attendee outside it |
//! | --- | --- | --- |
//! | create | `REQUEST` | `REQUEST` |
//! | significant (place, time, status, recurrence) | `REQUEST`, `REQUEST` | `REQUEST`, `REQUEST` |
//! | insignificant (description) | `REQUEST` (the copy follows silently) | `REQUEST` |
//! | an attendee is added | `REQUEST` (to the new one) | `REQUEST` |
//! | an attendee is removed | `REQUEST`, `CANCEL` (to the removed one) | `REQUEST`, `CANCEL` |
//! | one instance is cancelled (`EXDATE`) | `REQUEST`, `REQUEST`, `CANCEL` of the instance | `REQUEST`, `REQUEST` (the update carries the `EXDATE`) |
//! | the series is cancelled (`STATUS:CANCELLED`) | `REQUEST`, `CANCEL` | `REQUEST`, `CANCEL` |
//! | the organizer's copy is deleted | `REQUEST`, `CANCEL` | `REQUEST`, `CANCEL` |
//! | the copy is moved to another calendar of the owner | `REQUEST` (a relocation sends nothing) | `REQUEST` |
//!
//! A group address is never delivered to (`SCHEDULE-STATUS` 3.7, groups are not expanded in 1.0).
//!
//! **Where the answer can come from.** A principal of the tenant (also a resource) answers in a calendar client, by
//! changing the `PARTSTAT` of their copy. Somebody outside the tenant, other tenants included, answers on the RSVP
//! page or by a mail that a gateway forwards. The other channels do not exist for them: a person of the tenant has no
//! RSVP link, and a mail that says it is from a person of the tenant proves nothing (it is quarantined). An answer
//! only counts while the invitation is alive: once the attendee is removed or the event is cancelled or deleted, the
//! copy and the links are gone and a mail that arrives late is quarantined.
//!
//! **Resources** answer by themselves, by free-busy: a free room accepts at once, in the same transaction.
//!
//! **Answers are reset** by a significant change; cancelling the series is one, so after it nobody has answered.

use davhaven_domain::PartStat;

use super::{Answer, AttendeeKind, Change, ReplyChannel, SchedulingCase};

/// What a case must produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// The `METHOD` of every message in the attendee's scheduling inbox, in order of delivery.
    pub inbox: Vec<&'static str>,
    /// The copies of the event in the calendars the attendee owns.
    pub copies: usize,
    /// The `METHOD` of every mail to the attendee, in order of sending.
    pub mails: Vec<&'static str>,
    /// The `SCHEDULE-STATUS` of the attendee's line in the organizer's copy; `None` when the line is not there.
    pub schedule_status: Option<&'static str>,
    /// The `PARTSTAT` of the attendee in the organizer's copy after the change, before any answer; `None` when the
    /// attendee is not in an organizer's copy.
    pub partstat_before_reply: Option<PartStat>,
    /// The `PARTSTAT` after the attendee answered through the channel of the case.
    pub partstat_after_reply: Option<PartStat>,
    /// The scheduling events (`scheduling.reply_received`, `scheduling.reply_rejected`, `rsvp.answered`) from the
    /// change to the end of the reply, sorted: the order inside a transaction is not part of the contract.
    pub events: Vec<&'static str>,
}

/// An attendee in the tenant: a person or a resource.
const fn in_tenant(kind: AttendeeKind) -> bool {
    matches!(kind, AttendeeKind::Internal | AttendeeKind::Resource)
}

/// An attendee outside the tenant, mailed.
const fn mailed(kind: AttendeeKind) -> bool {
    matches!(kind, AttendeeKind::OtherTenant | AttendeeKind::External)
}

/// Whether the invitation is still alive after the change: the attendee is invited and the event stands.
pub const fn alive(change: Change) -> bool {
    !matches!(change, Change::RemoveAttendee | Change::CancelSeries | Change::Delete)
}

/// Whether the attendee is still listed in an organizer's copy after the change.
const fn listed(change: Change) -> bool {
    !matches!(change, Change::RemoveAttendee | Change::Delete)
}

/// The messages that reach an attendee in the tenant, in order.
fn inbox_of(change: Change) -> Vec<&'static str> {
    match change {
        Change::Create | Change::Insignificant | Change::AddAttendee | Change::Move => vec!["REQUEST"],
        Change::Significant => vec!["REQUEST", "REQUEST"],
        Change::RemoveAttendee | Change::CancelSeries | Change::Delete => vec!["REQUEST", "CANCEL"],
        Change::CancelInstance => vec!["REQUEST", "REQUEST", "CANCEL"],
    }
}

/// The mails that reach an attendee outside the tenant, in order.
fn mails_of(change: Change) -> Vec<&'static str> {
    match change {
        Change::Create | Change::Insignificant | Change::AddAttendee | Change::Move => vec!["REQUEST"],
        Change::Significant | Change::CancelInstance => vec!["REQUEST", "REQUEST"],
        Change::RemoveAttendee | Change::CancelSeries | Change::Delete => vec!["REQUEST", "CANCEL"],
    }
}

/// The answer as the organizer's copy shows it.
pub const fn partstat_of(answer: Answer) -> PartStat {
    match answer {
        Answer::Accept => PartStat::Accepted,
        Answer::Decline => PartStat::Declined,
        Answer::Tentative => PartStat::Tentative,
    }
}

/// Whether the channel exists for this kind of attendee at all (an answer can be attempted).
pub const fn channel_exists(kind: AttendeeKind, channel: ReplyChannel) -> bool {
    match kind {
        // A person of the tenant answers in a client; there is no link, and a mail is looked at (and not believed).
        AttendeeKind::Internal | AttendeeKind::Resource => matches!(channel, ReplyChannel::Dav | ReplyChannel::Inbound),
        // Somebody outside answers on the page or by mail; they have no calendar here.
        AttendeeKind::OtherTenant | AttendeeKind::External => {
            matches!(channel, ReplyChannel::Rsvp | ReplyChannel::Inbound)
        }
        // Nobody answers for a group.
        AttendeeKind::GroupAddress => false,
    }
}

/// Whether an answer through the channel is applied: the channel exists, the invitation is alive, and a mail from a
/// person of the tenant is never applied.
pub const fn answer_counts(kind: AttendeeKind, channel: ReplyChannel, change: Change) -> bool {
    if !channel_exists(kind, channel) || !alive(change) {
        return false;
    }
    !(in_tenant(kind) && matches!(channel, ReplyChannel::Inbound))
}

/// What the case must produce.
pub fn expected(case: SchedulingCase) -> Expected {
    let SchedulingCase {
        attendee: kind,
        change,
        reply,
        answer,
        ..
    } = case;
    let group = matches!(kind, AttendeeKind::GroupAddress);
    let inbox = if in_tenant(kind) { inbox_of(change) } else { Vec::new() };
    let mails = if mailed(kind) { mails_of(change) } else { Vec::new() };
    let copies = usize::from(in_tenant(kind) && alive(change));
    let schedule_status = listed(change).then_some(match kind {
        AttendeeKind::Internal | AttendeeKind::Resource => "1.2",
        AttendeeKind::OtherTenant | AttendeeKind::External => "1.1",
        AttendeeKind::GroupAddress => "3.7",
    });

    // A free room accepts in the transaction of the write; cancelling the series resets everybody.
    let resource_answers = matches!(kind, AttendeeKind::Resource)
        && matches!(
            change,
            Change::Create | Change::Significant | Change::AddAttendee | Change::CancelInstance
        );
    let before = listed(change).then_some(
        if matches!(kind, AttendeeKind::Resource) && !matches!(change, Change::CancelSeries) {
            PartStat::Accepted
        } else {
            PartStat::NeedsAction
        },
    );
    let counts = answer_counts(kind, reply, change);
    let after = if counts { Some(partstat_of(answer)) } else { before };

    let mut events: Vec<&'static str> = Vec::new();
    if resource_answers {
        events.push("scheduling.reply_received");
    }
    match reply {
        ReplyChannel::Dav if counts && after != before => events.push("scheduling.reply_received"),
        ReplyChannel::Rsvp if counts => {
            events.push("scheduling.reply_received");
            events.push("rsvp.answered");
        }
        // A mail is always looked at: it is applied, or it is quarantined and the organizer's side is told.
        ReplyChannel::Inbound if !group => {
            events.push(if counts {
                "scheduling.reply_received"
            } else {
                "scheduling.reply_rejected"
            });
        }
        ReplyChannel::Dav | ReplyChannel::Rsvp | ReplyChannel::Inbound => {}
    }
    events.sort_unstable();

    Expected {
        inbox,
        copies,
        mails,
        schedule_status,
        partstat_before_reply: before,
        partstat_after_reply: after,
        events,
    }
}

#[cfg(test)]
mod tests {
    use super::super::OrganizerSurface;
    use super::*;

    #[test]
    fn every_cell_of_the_matrix_has_an_expectation_and_the_surface_does_not_change_it() {
        let matrix = SchedulingCase::matrix();
        assert_eq!(matrix.len(), 135);
        for case in &matrix {
            let on_dav = SchedulingCase {
                organizer: OrganizerSurface::Dav,
                ..*case
            };
            assert_eq!(
                expected(*case),
                expected(on_dav),
                "{case}: the surface only changes how the write arrives"
            );
        }
    }

    #[test]
    fn the_rules_read_like_the_plan() {
        let case = |attendee, change, reply, answer| SchedulingCase {
            organizer: OrganizerSurface::Dav,
            attendee,
            change,
            reply,
            answer,
        };
        // A guest answers on the page: the organizer's copy shows the answer, the page and the reply are announced.
        let rsvp = expected(case(
            AttendeeKind::External,
            Change::Create,
            ReplyChannel::Rsvp,
            Answer::Decline,
        ));
        assert_eq!(rsvp.mails, vec!["REQUEST"]);
        assert_eq!(rsvp.schedule_status, Some("1.1"));
        assert_eq!(rsvp.partstat_after_reply, Some(PartStat::Declined));
        assert_eq!(rsvp.events, vec!["rsvp.answered", "scheduling.reply_received"]);
        // A colleague cannot answer by mail.
        let mail = expected(case(
            AttendeeKind::Internal,
            Change::Create,
            ReplyChannel::Inbound,
            Answer::Accept,
        ));
        assert_eq!(mail.partstat_after_reply, Some(PartStat::NeedsAction));
        assert_eq!(mail.events, vec!["scheduling.reply_rejected"]);
        // A room that is free accepts before anybody asks, and its own answer is what a repeated accept leaves.
        let room = expected(case(
            AttendeeKind::Resource,
            Change::Create,
            ReplyChannel::Dav,
            Answer::Accept,
        ));
        assert_eq!(room.partstat_before_reply, Some(PartStat::Accepted));
        assert_eq!(
            room.events,
            vec!["scheduling.reply_received"],
            "only the booking itself was answered"
        );
        // Cancelling the series ends every answer.
        let cancelled = expected(case(
            AttendeeKind::Resource,
            Change::CancelSeries,
            ReplyChannel::Dav,
            Answer::Accept,
        ));
        assert_eq!(cancelled.partstat_before_reply, Some(PartStat::NeedsAction));
        assert_eq!(cancelled.partstat_after_reply, Some(PartStat::NeedsAction));
        assert_eq!(cancelled.copies, 0);
        // Groups are not expanded.
        let group = expected(case(
            AttendeeKind::GroupAddress,
            Change::Create,
            ReplyChannel::Inbound,
            Answer::Accept,
        ));
        assert_eq!((group.inbox.len(), group.mails.len(), group.copies), (0, 0, 0));
        assert_eq!(group.schedule_status, Some("3.7"));
        assert_eq!(group.events.len(), 0);
        // A deleted event has no copy of the organizer to answer.
        let deleted = expected(case(
            AttendeeKind::OtherTenant,
            Change::Delete,
            ReplyChannel::Rsvp,
            Answer::Accept,
        ));
        assert_eq!(deleted.schedule_status, None);
        assert_eq!(deleted.partstat_after_reply, None);
        assert_eq!(deleted.mails, vec!["REQUEST", "CANCEL"]);
    }
}
