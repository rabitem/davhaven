//! `ObjectIndex`: the indexed summary of a stored calendar object.
//!
//! `davhaven-ical` extracts the index when an object is written; the store keeps it in columns next to the
//! verbatim bytes and answers `query` from it. The index only has to be a *superset* filter: the application
//! re-checks every candidate exactly with `davhaven-ical` (PLAN 2.7, "Query semantics").

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::keys::{CalendarUserAddress, Uid};
use crate::vocab::{Classification, ComponentKind, CuType, PartStat, Role, ScheduleAgent, Transparency};

/// How far floating date-times (no time zone) are padded when they are converted to UTC for the index: a
/// floating time can fall anywhere between UTC-12 and UTC+14, so the indexed interval is widened by this many
/// hours on both sides and the pre-filter stays a superset.
pub const FLOATING_PADDING_HOURS: i64 = 14;

/// An attendee as far as the index and scheduling need to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttendeeRef {
    /// The attendee's calendar user address.
    pub address: CalendarUserAddress,
    /// The common name (`CN`), if the client sent one.
    pub common_name: Option<String>,
    /// The participation status.
    pub partstat: PartStat,
    /// The calendar user type.
    pub cutype: CuType,
    /// The participation role.
    pub role: Role,
    /// Who sends scheduling messages to this attendee.
    pub schedule_agent: ScheduleAgent,
}

impl AttendeeRef {
    /// An individual attendee with default parameters.
    pub fn new(address: CalendarUserAddress) -> Self {
        Self {
            address,
            common_name: None,
            partstat: PartStat::default(),
            cutype: CuType::default(),
            role: Role::default(),
            schedule_agent: ScheduleAgent::default(),
        }
    }
}

/// The index columns of a calendar object, extracted by `davhaven-ical`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObjectIndex {
    /// The UID shared by all components of the object.
    pub uid: Uid,
    /// The component type of the master (or only) component.
    pub component: ComponentKind,
    /// The start of the first instance in UTC (floating times padded). `None` means *undated*: the component has
    /// no `DTSTART` (a to-do with neither start nor due date, for instance), and the pre-filter matches it at every
    /// range. Components that RFC 4791 section 9.9 anchors on another property are indexed on that anchor: a
    /// `VTODO` with only `DUE` has `first_start == last_end == DUE`, one with only `COMPLETED` has both at
    /// `COMPLETED`.
    pub first_start: Option<DateTime<Utc>>,
    /// The end of the last instance in UTC (floating times padded); `None` when the set is unbounded (an
    /// infinite recurrence) or undated. The store keeps `None` as infinity. A component without `DTEND` or
    /// `DURATION` (or with a zero duration) is an instant: its `last_end` equals its `first_start`, except for a
    /// `DATE` start, which lasts one day (`last_end = DTSTART + P1D`). The pre-filter of
    /// [`ObjectIndex::may_overlap`] is closed at both ends and so admits every row of the RFC 4791 section 9.9
    /// table, including the ones that match when the range end or the range start touches the anchor.
    pub last_end: Option<DateTime<Utc>>,
    /// Whether the object has recurrence rules or dates.
    pub is_recurring: bool,
    /// Whether the object is a scheduling object resource: it has an organizer and at least one attendee.
    pub is_scheduling: bool,
    /// The organizer's calendar user address.
    pub organizer: Option<CalendarUserAddress>,
    /// The attendees of the master component and of all overrides, one entry per address.
    pub attendees: Vec<AttendeeRef>,
    /// The `SEQUENCE` of the master component (0 when absent).
    pub sequence: i32,
    /// The `CLASS` of the master component.
    pub class: Classification,
    /// The `TRANSP` of the master component.
    pub transp: Transparency,
}

/// The one definition of the index pre-filter: whether an object spanning `[first_start, last_end]` can match a
/// time range `[range_start, range_end]` (RFC 4791 section 9.9). `None` for `first_start` means undated and `None`
/// for `last_end` means unbounded (infinity); an absent range bound is open. Both intervals are treated as
/// **closed**, which makes the result a superset of every row of the section 9.9 table (see
/// [`ObjectIndex::may_overlap`]). The ports crate, the in-memory store and the SQL of the PostgreSQL store
/// (`last_end >= start AND first_start <= end`) all implement this function and are tested against it.
pub fn interval_may_overlap(
    first_start: Option<DateTime<Utc>>,
    last_end: Option<DateTime<Utc>>,
    range_start: Option<DateTime<Utc>>,
    range_end: Option<DateTime<Utc>>,
) -> bool {
    let starts_before_range_end = match (first_start, range_end) {
        (Some(first), Some(end)) => first <= end,
        _ => true,
    };
    let ends_after_range_start = match (last_end, range_start) {
        (Some(last), Some(start)) => last >= start,
        _ => true,
    };
    starts_before_range_end && ends_after_range_start
}

impl ObjectIndex {
    /// Whether the object's indexed interval can overlap the range `[start, end]`; an absent bound is open.
    /// Undated and unbounded objects overlap everything on that side. This is the pre-filter the stores apply
    /// ([`interval_may_overlap`]); it may report overlaps that exact evaluation rejects but never misses one.
    ///
    /// The comparison is **closed at both ends** although the range of RFC 4791 section 9.9 is half-open: the
    /// rows of that table that anchor on `DUE`, `COMPLETED` or a zero-length component match when the range end
    /// *touches* the anchor (`end >= DUE`), and `DURATION:PT0S` or `DTEND == DTSTART` match when the range start
    /// equals the anchor. The exact filter of `davhaven-ical` removes the extra candidates.
    pub fn may_overlap(&self, start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> bool {
        interval_may_overlap(self.first_start, self.last_end, start, end)
    }

    /// The attendee entry for `address`, if any.
    pub fn attendee(&self, address: &CalendarUserAddress) -> Option<&AttendeeRef> {
        self.attendees.iter().find(|attendee| &attendee.address == address)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 3, 1, hour, 0, 0).unwrap()
    }

    fn index(first_start: Option<DateTime<Utc>>, last_end: Option<DateTime<Utc>>) -> ObjectIndex {
        ObjectIndex {
            uid: Uid::parse("uid-1").unwrap(),
            component: ComponentKind::Event,
            first_start,
            last_end,
            is_recurring: false,
            is_scheduling: false,
            organizer: None,
            attendees: Vec::new(),
            sequence: 0,
            class: Classification::default(),
            transp: Transparency::default(),
        }
    }

    #[test]
    fn bounded_objects_overlap_ranges_that_intersect_them() {
        let event = index(Some(at(10)), Some(at(12)));
        assert!(event.may_overlap(Some(at(9)), Some(at(11))));
        assert!(event.may_overlap(Some(at(11)), Some(at(13))));
        assert!(event.may_overlap(Some(at(10)), Some(at(12))));
        assert!(event.may_overlap(Some(at(0)), Some(at(23))));
        assert!(
            event.may_overlap(Some(at(12)), Some(at(14))),
            "closed at the object end: an instant at the range start must not be lost"
        );
        assert!(
            event.may_overlap(Some(at(6)), Some(at(10))),
            "closed at the range end too"
        );
        assert!(!event.may_overlap(Some(at(13)), Some(at(14))), "but not beyond it");
        assert!(!event.may_overlap(Some(at(1)), Some(at(2))));
        assert!(!event.may_overlap(Some(at(6)), Some(at(9))));
    }

    #[test]
    fn open_range_bounds_match_everything_on_that_side() {
        let event = index(Some(at(10)), Some(at(12)));
        assert!(event.may_overlap(None, None));
        assert!(event.may_overlap(None, Some(at(11))));
        assert!(event.may_overlap(None, Some(at(10))), "closed at the range end");
        assert!(!event.may_overlap(None, Some(at(9))));
        assert!(event.may_overlap(Some(at(11)), None));
        assert!(event.may_overlap(Some(at(12)), None), "closed at the object end");
        assert!(!event.may_overlap(Some(at(13)), None));
    }

    #[test]
    fn instants_match_ranges_that_touch_them_on_either_side() {
        // RFC 4791 section 9.9: a component without DTEND or DURATION matches when start <= DTSTART < end; a
        // zero-length one (DTEND == DTSTART, DURATION:PT0S) when start <= DTSTART < end as well. The pre-filter
        // keeps the candidates at both boundaries and leaves the exact comparison to the application.
        let instant = index(Some(at(10)), Some(at(10)));
        assert!(
            instant.may_overlap(Some(at(10)), Some(at(11))),
            "the range start touches the instant"
        );
        assert!(instant.may_overlap(Some(at(10)), None));
        assert!(instant.may_overlap(Some(at(9)), Some(at(11))));
        assert!(
            instant.may_overlap(Some(at(9)), Some(at(10))),
            "the range end touches the instant: kept, the exact filter drops it"
        );
        assert!(!instant.may_overlap(Some(at(11)), Some(at(12))));
        assert!(!instant.may_overlap(Some(at(8)), Some(at(9))));
    }

    #[test]
    fn the_rfc_4791_table_rows_anchored_on_one_instant_are_never_missed() {
        // Each row: (what the component carries, the instant it is indexed at, a range that matches it according
        // to the RFC table and touches the instant). Every one must pass the pre-filter.
        let anchor = at(10);
        let todo_due_only = index(Some(anchor), Some(anchor)); // (start < DUE) AND (end >= DUE)
        assert!(
            todo_due_only.may_overlap(Some(at(9)), Some(anchor)),
            "end == DUE matches"
        );
        assert!(todo_due_only.may_overlap(Some(at(9)), Some(at(11))));
        let todo_completed_only = index(Some(anchor), Some(anchor)); // (start <= COMPLETED) AND (end >= COMPLETED)
        assert!(todo_completed_only.may_overlap(Some(anchor), Some(anchor)));
        assert!(
            todo_completed_only.may_overlap(Some(at(9)), Some(anchor)),
            "end == COMPLETED matches"
        );
        assert!(
            todo_completed_only.may_overlap(Some(anchor), Some(at(11))),
            "start == COMPLETED matches"
        );
        let zero_duration = index(Some(anchor), Some(anchor)); // DURATION:PT0S, DTEND == DTSTART
        assert!(zero_duration.may_overlap(Some(at(9)), Some(anchor)));
        assert!(zero_duration.may_overlap(Some(anchor), Some(at(11))));
        assert!(!zero_duration.may_overlap(Some(at(11)), Some(at(12))));
    }

    #[test]
    fn unbounded_and_undated_objects_overlap_everything_on_their_open_side() {
        let infinite = index(Some(at(10)), None);
        assert!(infinite.may_overlap(Some(at(20)), None));
        assert!(infinite.may_overlap(Some(at(20)), Some(at(23))));
        assert!(
            !infinite.may_overlap(Some(at(1)), Some(at(5))),
            "it still starts at 10:00"
        );

        let undated = index(None, None);
        assert!(undated.may_overlap(Some(at(1)), Some(at(2))));
        assert!(undated.may_overlap(None, None));
    }

    #[test]
    fn the_free_function_is_the_one_definition() {
        let bounds = [
            None,
            Some(at(0)),
            Some(at(10)),
            Some(at(11)),
            Some(at(12)),
            Some(at(23)),
        ];
        for first_start in bounds {
            for last_end in bounds {
                let object = index(first_start, last_end);
                for start in bounds {
                    for end in bounds {
                        assert_eq!(
                            object.may_overlap(start, end),
                            interval_may_overlap(first_start, last_end, start, end)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn attendees_are_found_by_normalized_address() {
        let guest = CalendarUserAddress::parse("MAILTO:Guest@Example.org").unwrap();
        let mut event = index(None, None);
        event.attendees.push(AttendeeRef::new(guest.clone()));
        assert!(
            event
                .attendee(&CalendarUserAddress::parse("mailto:guest@example.org").unwrap())
                .is_some()
        );
        assert!(
            event
                .attendee(&CalendarUserAddress::parse("mailto:other@example.org").unwrap())
                .is_none()
        );
        let attendee = AttendeeRef::new(guest);
        assert_eq!(attendee.partstat, PartStat::NeedsAction);
        assert_eq!(attendee.cutype, CuType::Individual);
        assert_eq!(attendee.role, Role::ReqParticipant);
        assert_eq!(attendee.schedule_agent, ScheduleAgent::Server);
    }

    #[test]
    fn serde_round_trip() {
        let mut event = index(Some(at(10)), Some(at(12)));
        event.is_scheduling = true;
        event.organizer = Some(CalendarUserAddress::parse("mailto:anna@example.org").unwrap());
        event.attendees.push(AttendeeRef::new(
            CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
        ));
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<ObjectIndex>(&json).unwrap(), event);
        assert_eq!(FLOATING_PADDING_HOURS, 14);
    }
}
