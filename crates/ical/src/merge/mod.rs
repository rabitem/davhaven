//! Merging `EventData` into stored components while keeping unknown properties.
//!
//! JSON event writes (management API, MCP) are merged into the stored component as a JSON Merge Patch (RFC 7396):
//! fields present in the [`EventData`](davhaven_domain::EventData) replace the stored values, absent fields keep
//! them, fields that are `null` ([`EventData::removed`](davhaven_domain::EventData::removed)) remove them, and
//! everything the model does not know (unknown and `X-` properties, alarms the caller did not mention, attendee
//! parameters) survives. Reading goes the other way: [`to_event_data`] renders one component of a stored calendar
//! as `EventData`.
//!
//! RFC 7396 holds for the members of the event and no deeper: an object or a list that is sent replaces the stored
//! one as a whole. `recurrence` replaces `RRULE`, `RDATE` and `EXDATE` together (an empty one, or `null`, removes
//! them, and `{"exdates": [..]}` alone drops the stored rule), `organizer` replaces the whole `ORGANIZER` (its name and
//! `SENT-BY` with it), and `alarms` replaces every `VALARM` of the component (`null` or an empty list removes them).
//! The organizer cannot be removed while attendees remain (an event with attendees names its organizer, RFC 5545
//! section 3.8.4.3: remove them in the same write), and in a series with overrides every component names the same
//! organizer, so the organizer of the master cannot be removed alone. Attendees are matched by address: a listed attendee keeps the
//! parameters the caller does not state, an attendee that is not listed is removed (`null` or an empty list
//! removes every attendee). The answers of the attendees (`PARTSTAT`) are theirs and stay as stored; only a
//! `REPLY` changes one. A text field that is empty is removed like one that is `null`.
//!
//! What the functions return passes the gate every stored object passes (it is written out and parsed and
//! validated again), so a result can always be stored and read back.
//!
//! Editing "this and all following instances" produces two objects, like the clients do it: see
//! [`merge_event_split`]. `RANGE=THISANDFUTURE` is understood when reading but never written.

mod instances;
mod read;
mod split;
mod write;

#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use davhaven_domain::{IcalLimits, TimeZoneName, Uid};

pub(crate) use instances::{instance_set, master_index, override_from_master, override_index, put_param, set_param};
pub use read::{override_ids, to_event_data};
pub use split::{SplitEdit, merge_event_split, remove_instances, remove_instances_with_limits};
pub use write::merge_event;

/// Which instances of a recurring event an edit or a deletion applies to (MCP `scope`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EditScope {
    /// Only the instance selected by the recurrence id.
    This,
    /// The selected instance and every later one (the series is split, see [`merge_event_split`]).
    ThisAndFuture,
    /// The whole series.
    All,
}

/// The context of a merge: values the caller supplies so that the merge itself stays deterministic.
#[derive(Debug, Clone, Copy)]
pub struct MergeContext<'a> {
    /// The UID of the object (the stored one when updating).
    pub uid: &'a Uid,
    /// The `DTSTAMP`/`LAST-MODIFIED` to write (from the `Clock`).
    pub now: DateTime<Utc>,
    /// The zone that floating and all-day values are interpreted in when a zone is needed.
    pub default_zone: TimeZoneName,
    /// Which instances an edit of a recurring event applies to.
    pub scope: EditScope,
    /// The limits the result must satisfy.
    pub limits: &'a IcalLimits,
    /// The text of an alarm that has none when the event has no title either (already localized by the caller).
    pub default_alarm_text: &'a str,
}
