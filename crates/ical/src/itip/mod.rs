//! iTIP (RFC 5546) processing: per-instance diff, message building and reply application.
//!
//! Scheduling is decided in the application (PLAN 2.8); this module supplies the pure calendar operations it
//! needs. [`diff()`] compares the stored and the new organizer copy per instance (master plus every
//! `RECURRENCE-ID`) and classifies each change; [`build_message`] derives the iTIP message for a recipient from
//! the organizer copy; [`apply_reply`] folds an attendee's `REPLY` into the organizer copy; the remaining
//! functions parse inbound messages, record `SCHEDULE-STATUS` and strip `SCHEDULE-*` parameters from outgoing
//! messages. Golden fixtures drive the application's scheduling matrix.
//!
//! Beyond the plan's list the application needs [`apply_organizer_changes`] (sequence numbers, participation
//! state), [`organizer_change_violations`] and [`attendee_change_violations`] (what a copy may change),
//! [`rewrite_addresses`] (principal URLs and `urn:uuid` addresses become `mailto` before anything leaves the
//! server) and the `_with` variants of the functions that need the configured limits.
//!
//! # Who owns what
//!
//! The answers of the attendees are server-owned. `PARTSTAT` and `SCHEDULE-STATUS` of an attendee on the
//! organizer's copy change in exactly two ways: [`apply_reply`] writes the answer of a `REPLY`, delivery writes
//! the status ([`set_schedule_status`]). Whatever an organizer's client sends for them is replaced by
//! [`apply_organizer_changes`] with the stored value, or `NEEDS-ACTION` for an attendee that is new on that
//! instance. Nobody who can write the organizer's calendar can forge an answer, and a stale copy cannot
//! overwrite a reply that arrived after the client read it. The comment that came with an answer
//! (`X-CALENDARSERVER-ATTENDEE-COMMENT`) belongs to the answer and is the server's too: only [`apply_reply`] writes it,
//! [`apply_organizer_changes`] drops every comment a client sends and gives the stored ones of the same instance back to the
//! attendees that keep their answer, and a significant change that resets an answer takes its comment away.

mod attendee;
mod compare;
mod diff;
mod message;
mod object;
mod reply;

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use davhaven_domain::CalendarUserAddress;

pub use attendee::attendee_change_violations;
pub use diff::{
    ChangeClass, InstanceAttendees, InstanceDiff, ItipDiff, OrganizerUpdate, apply_organizer_changes, diff,
    organizer_change_violations,
};
pub use message::{
    AttendeeVisibility, ItipMessage, MessageScope, MessageSpec, build_message, parse_message, rewrite_addresses,
};
pub use object::{
    InlineAttachment, ReplySpec, carry_over_attendee_data, inline_attachments, reply_message, set_sent_by, strip_alarms,
};
pub use reply::{
    MAX_COMMENT_CHARS, ReplyApplication, apply_reply, apply_reply_with, set_schedule_status, strip_attendee_comments,
    strip_schedule_params,
};

use crate::calendar::{Moment, Node, Param, Prop, address_of, entry_moment, is_schedule_param};
use crate::zones::{RidKey, Zone, Zones};

/// A component of an object with the identity of the instance it describes.
pub(crate) struct View<'a> {
    pub(crate) node: &'a Node,
    pub(crate) rid: Option<Moment>,
    pub(crate) key: Option<RidKey>,
}

/// The stored components of an object: the master first, then the overrides ordered by recurrence id.
pub(crate) fn views<'a>(root: &'a Node, zones: &Zones) -> Vec<View<'a>> {
    let mut found: Vec<View<'a>> = root
        .children
        .iter()
        .filter(|node| node.component_kind().is_some())
        .map(|node| {
            let rid = node.first(&Prop::RecurrenceId).and_then(entry_moment);
            let key = rid.as_ref().and_then(|moment| zones.rid_key(moment));
            View { node, rid, key }
        })
        .collect();
    found.sort_by_key(|view| (view.rid.is_some(), view.key));
    found
}

/// The zones of an object with floating values read in UTC.
pub(crate) fn utc_zones(root: &Node) -> Zones {
    Zones::for_tree(root, Zone::utc())
}

/// The calendar user addresses of all attendees of an object, in order of appearance, each once.
pub(crate) fn attendee_addresses(root: &Node) -> Vec<CalendarUserAddress> {
    let mut seen: HashSet<CalendarUserAddress> = HashSet::new();
    let mut found: Vec<CalendarUserAddress> = Vec::new();
    for node in root.children.iter().filter(|node| node.component_kind().is_some()) {
        for entry in node.all(&Prop::Attendee) {
            if let Some(address) = address_of(entry)
                && seen.insert(address.clone())
            {
                found.push(address);
            }
        }
    }
    found
}

/// The `SEQUENCE` of a component (0 when absent).
pub(crate) fn sequence_of(node: &Node) -> i64 {
    node.integer(&Prop::Sequence).unwrap_or(0)
}

/// The organizer of the first component that names one.
pub(crate) fn organizer_of(root: &Node) -> Option<CalendarUserAddress> {
    root.children
        .iter()
        .filter(|node| node.component_kind().is_some())
        .find_map(|node| node.first(&Prop::Organizer).and_then(address_of))
}

pub(crate) fn upper(name: &str) -> String {
    name.to_ascii_uppercase()
}

/// Removes every `SCHEDULE-*` parameter from the properties of a component and its children.
pub(crate) fn strip_schedule_in(node: &mut Node) {
    for entry in &mut node.entries {
        entry.params.retain(|param| !is_schedule_param(&param.name));
    }
    for child in &mut node.children {
        strip_schedule_in(child);
    }
}

/// The parameters of an `ATTENDEE` line that belong to the server: the answer and the delivery status.
pub(crate) const SERVER_OWNED: [Param; 2] = [Param::Partstat, Param::ScheduleStatus];
