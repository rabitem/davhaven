//! What an attendee may change on their copy of an event.

use std::collections::BTreeSet;

use davhaven_domain::CalendarUserAddress;

use super::compare::{CompareOptions, compare};
use super::{sequence_of, utc_zones, views};
use crate::calendar::{Node, Prop, address_of, entry_moment};
use crate::error::IcalError;
use crate::parse::ParsedCalendar;
use crate::zones::Zones;

/// The properties that describe the recurrence set and the timing of an instance, left out when an override
/// is compared with the master it was derived from.
fn strip_timing(node: &mut Node) {
    node.entries.retain(|entry| {
        !matches!(
            entry.name,
            Prop::Rrule
                | Prop::Rdate
                | Prop::Exdate
                | Prop::Exrule
                | Prop::Dtstart
                | Prop::Dtend
                | Prop::Duration
                | Prop::Due
                | Prop::RecurrenceId
        )
    });
}

fn is_derived_from(master: &Node, derived: &Node, zones: &Zones, attendee: &CalendarUserAddress) -> bool {
    let (Some(rid), Some(start)) = (
        derived.first(&Prop::RecurrenceId).and_then(entry_moment),
        derived.first(&Prop::Dtstart).and_then(entry_moment),
    ) else {
        return false;
    };
    if !zones.same(&rid, &start) {
        return false;
    }
    let mut first = master.clone();
    let mut second = derived.clone();
    strip_timing(&mut first);
    strip_timing(&mut second);
    let options = CompareOptions {
        own: Some(attendee),
        attendee_mode: true,
    };
    let compared = compare(&first, zones, &second, zones, &options);
    compared.significant.is_empty() && compared.other.is_empty()
}

/// Whether the component has an `ATTENDEE` line for the address.
fn lists(node: &Node, attendee: &CalendarUserAddress) -> bool {
    node.all(&Prop::Attendee)
        .any(|entry| address_of(entry).as_ref() == Some(attendee))
}

/// Lists what an attendee changed on their copy of an event beyond what they may change.
///
/// An attendee may change the parameters of their own `ATTENDEE` lines (participation, comment), alarms and
/// `TRANSP`; client private properties (`X-APPLE-*`, `X-MOZ-*`) and the volatile stamps are ignored because they
/// never leave the server. Everything else, including `SEQUENCE`, the other attendees, the organizer and the
/// address of their own line (a line for another address is another attendee), must stay as it was; their own
/// line may not go. An override the attendee adds must only be the master copy for that instance. The result
/// lists the names of the offending properties; it is empty when the change is allowed.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn attendee_change_violations(
    old: &ParsedCalendar,
    new: &ParsedCalendar,
    attendee: &CalendarUserAddress,
) -> Result<Vec<String>, IcalError> {
    let old_zones = utc_zones(&old.root);
    let new_zones = utc_zones(&new.root);
    let old_views = views(&old.root, &old_zones);
    let new_views = views(&new.root, &new_zones);
    let options = CompareOptions {
        own: Some(attendee),
        attendee_mode: true,
    };
    let mut found: BTreeSet<String> = BTreeSet::new();
    for current in &new_views {
        if let Some(before) = old_views.iter().find(|view| view.key == current.key) {
            let compared = compare(before.node, &old_zones, current.node, &new_zones, &options);
            found.extend(compared.significant);
            found.extend(compared.other);
            if sequence_of(before.node) != sequence_of(current.node) {
                found.insert("SEQUENCE".to_owned());
            }
            if lists(before.node, attendee) && !lists(current.node, attendee) {
                found.insert("ATTENDEE".to_owned());
            }
        } else {
            let master = old_views.iter().find(|view| view.key.is_none());
            let derived = master.is_some_and(|master| is_derived_from(master.node, current.node, &new_zones, attendee));
            if !derived {
                found.insert("RECURRENCE-ID".to_owned());
            }
        }
    }
    if old_views
        .iter()
        .any(|before| !new_views.iter().any(|current| current.key == before.key))
    {
        found.insert("RECURRENCE-ID".to_owned());
    }
    Ok(found.into_iter().collect())
}
