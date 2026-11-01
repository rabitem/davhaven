//! The scheduling matrix harness.
//!
//! The scheduling matrix (PLAN 3.3) crosses the surface the organizer uses with the kind of attendee, the change
//! the organizer makes, the channel an attendee replies through and the answer. It takes the full product of the
//! first three dimensions and covers the rest pairwise, which keeps the matrix at a few hundred cases while every
//! pair of values of any two dimensions still occurs together at least once.
//!
//! This module holds the dimensions and the generator of the cases. The decision table that says what each case must
//! produce is the executable form of PLAN 2.8 ([`table`]); the driver that performs a case over HTTP on the real
//! application and compares it with the table is [`driver`]; [`text`] reads and writes the iCalendar text, mail bodies
//! and pages the driver looks at.

use davhaven_fixtures::named_enum;

use crate::sample::cover;

pub mod driver;
pub mod table;
pub mod text;

named_enum! {
    /// The surface the organizer changes the event through.
    pub enum OrganizerSurface {
        /// A CalDAV client PUTs the organizer copy.
        Dav => "dav",
        /// The management API writes the event.
        Api => "api",
        /// An MCP tool writes the event.
        Mcp => "mcp",
    }
}

named_enum! {
    /// Who the attendee is.
    pub enum AttendeeKind {
        /// A principal of the organizer's tenant.
        Internal => "internal",
        /// A principal of another tenant, which counts as external.
        OtherTenant => "other_tenant",
        /// A group address, which is not expanded in 1.0 (`SCHEDULE-STATUS` 3.7).
        GroupAddress => "group_address",
        /// A resource principal with auto-accept policy.
        Resource => "resource",
        /// Any other address: iMIP mail and the RSVP page.
        External => "external",
    }
}

named_enum! {
    /// What the organizer does.
    pub enum Change {
        /// Creates the event with the attendee.
        Create => "create",
        /// Changes time, location, summary, status or the recurrence: resets the answers.
        Significant => "significant",
        /// Changes something else: updates silently, sends nothing.
        Insignificant => "insignificant",
        /// Adds an attendee to an existing event.
        AddAttendee => "add_attendee",
        /// Removes an attendee: the attendee receives a cancellation.
        RemoveAttendee => "remove_attendee",
        /// Cancels one instance of a recurring event.
        CancelInstance => "cancel_instance",
        /// Cancels the whole series (`STATUS:CANCELLED`).
        CancelSeries => "cancel_series",
        /// Deletes the organizer copy.
        Delete => "delete",
        /// Moves the event to another calendar of the same owner (a relocation, no scheduling).
        Move => "move",
    }
}

named_enum! {
    /// How the attendee's answer reaches the server.
    pub enum ReplyChannel {
        /// The attendee changes `PARTSTAT` in a CalDAV client.
        Dav => "dav",
        /// The attendee answers on the RSVP page.
        Rsvp => "rsvp",
        /// A mail gateway delivers the reply to the inbound iTIP endpoint.
        Inbound => "inbound",
    }
}

named_enum! {
    /// What the attendee answers.
    pub enum Answer {
        /// `ACCEPTED`.
        Accept => "accept",
        /// `DECLINED`.
        Decline => "decline",
        /// `TENTATIVE`.
        Tentative => "tentative",
    }
}

/// One cell of the scheduling matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchedulingCase {
    /// The surface the organizer uses.
    pub organizer: OrganizerSurface,
    /// Who the attendee is.
    pub attendee: AttendeeKind,
    /// What the organizer does.
    pub change: Change,
    /// How the attendee replies.
    pub reply: ReplyChannel,
    /// What the attendee answers.
    pub answer: Answer,
}

impl SchedulingCase {
    /// The full product of organizer surface, attendee kind and change, in a stable order.
    pub fn full_product() -> Vec<(OrganizerSurface, AttendeeKind, Change)> {
        let mut product = Vec::with_capacity(OrganizerSurface::ALL.len() * AttendeeKind::ALL.len() * Change::ALL.len());
        for organizer in OrganizerSurface::ALL {
            for attendee in AttendeeKind::ALL {
                for change in Change::ALL {
                    product.push((*organizer, *attendee, *change));
                }
            }
        }
        product
    }

    /// The cases of the matrix: the full product of the first three dimensions, each with one combination of reply
    /// channel and answer. The combinations rotate with the position of the case in its block of changes, shifted by
    /// the number of the block, so every pair of values of two different dimensions occurs at least once.
    pub fn matrix() -> Vec<Self> {
        let combinations = ReplyChannel::ALL.len() * Answer::ALL.len();
        let block = Change::ALL.len();
        Self::full_product()
            .into_iter()
            .enumerate()
            .map(|(index, (organizer, attendee, change))| {
                let combination = (index % block + index / block) % combinations;
                let reply = ReplyChannel::ALL.get(combination / Answer::ALL.len()).copied();
                let answer = Answer::ALL.get(combination % Answer::ALL.len()).copied();
                Self {
                    organizer,
                    attendee,
                    change,
                    reply: reply.unwrap_or(ReplyChannel::Dav),
                    answer: answer.unwrap_or(Answer::Accept),
                }
            })
            .collect()
    }
}

impl SchedulingCase {
    /// A representative subset of `cases`: few, and between them every kind of attendee, every change, every reply channel
    /// and every answer at least once, in the order given. A case runs in an application of its own, which costs seconds on
    /// PostgreSQL, so pull requests run this subset there (chosen greedily by `sample::cover`).
    pub fn representative(cases: &[Self]) -> Vec<Self> {
        cover(cases, |case| {
            vec![
                format!("attendee {}", case.attendee),
                format!("change {}", case.change),
                format!("reply {}", case.reply),
                format!("answer {}", case.answer),
            ]
        })
        .into_iter()
        .copied()
        .collect()
    }
}

impl core::fmt::Display for SchedulingCase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {} by {}, reply {} via {}",
            self.change, self.attendee, self.organizer, self.answer, self.reply
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn the_matrix_has_one_case_per_cell_of_the_full_product() {
        let product = SchedulingCase::full_product();
        assert_eq!(product.len(), 3 * 5 * 9);
        let matrix = SchedulingCase::matrix();
        assert_eq!(matrix.len(), product.len());
        let cells: BTreeSet<_> = matrix
            .iter()
            .map(|case| (case.organizer, case.attendee, case.change))
            .collect();
        assert_eq!(cells.len(), product.len(), "no cell twice");
        assert_eq!(matrix, SchedulingCase::matrix(), "the generator is deterministic");
    }

    /// The cases of one surface that a pull request runs on PostgreSQL: few, and every value of the dimensions of a surface is in them.
    #[test]
    fn the_sample_has_every_attendee_change_reply_and_answer_of_a_surface() {
        let surface: Vec<SchedulingCase> = SchedulingCase::matrix()
            .into_iter()
            .filter(|case| case.organizer == OrganizerSurface::Dav)
            .collect();
        let sample = SchedulingCase::representative(&surface);
        assert!(
            sample.len() < surface.len() / 2,
            "{} of {}",
            sample.len(),
            surface.len()
        );
        for case in &sample {
            assert!(surface.contains(case), "{case}");
        }
        let seen = |value: fn(&SchedulingCase) -> &'static str| -> BTreeSet<&'static str> {
            sample.iter().map(value).collect()
        };
        assert_eq!(seen(|case| case.attendee.as_str()).len(), AttendeeKind::ALL.len());
        assert_eq!(seen(|case| case.change.as_str()).len(), Change::ALL.len());
        assert_eq!(seen(|case| case.reply.as_str()).len(), ReplyChannel::ALL.len());
        assert_eq!(seen(|case| case.answer.as_str()).len(), Answer::ALL.len());
        let again = SchedulingCase::representative(&surface);
        assert_eq!(again, sample, "the sample is deterministic");
    }

    /// Every pair of values of two different dimensions occurs in at least one case.
    #[test]
    fn the_matrix_covers_every_pair_of_values() {
        let matrix = SchedulingCase::matrix();
        let values = |case: &SchedulingCase| -> [(usize, &'static str); 5] {
            [
                (0, case.organizer.as_str()),
                (1, case.attendee.as_str()),
                (2, case.change.as_str()),
                (3, case.reply.as_str()),
                (4, case.answer.as_str()),
            ]
        };
        let mut seen = BTreeSet::new();
        for case in &matrix {
            let row = values(case);
            for (i, left) in row.iter().enumerate() {
                for right in row.iter().skip(i + 1) {
                    seen.insert((*left, *right));
                }
            }
        }
        let sizes = [
            OrganizerSurface::ALL.len(),
            AttendeeKind::ALL.len(),
            Change::ALL.len(),
            ReplyChannel::ALL.len(),
            Answer::ALL.len(),
        ];
        let mut expected = 0;
        for (i, left) in sizes.iter().enumerate() {
            for right in sizes.iter().skip(i + 1) {
                expected += left * right;
            }
        }
        assert_eq!(
            seen.len(),
            expected,
            "every pair of values must occur together at least once"
        );
    }

    #[test]
    fn cases_read_like_sentences() {
        let case = SchedulingCase {
            organizer: OrganizerSurface::Api,
            attendee: AttendeeKind::External,
            change: Change::CancelSeries,
            reply: ReplyChannel::Rsvp,
            answer: Answer::Decline,
        };
        assert_eq!(
            case.to_string(),
            "cancel_series external by api, reply decline via rsvp"
        );
    }
}
