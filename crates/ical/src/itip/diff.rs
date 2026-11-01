//! The per-instance diff of two versions of the organizer's copy and the rules applied to a new version.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use davhaven_domain::{CalendarUserAddress, EventTime, IcalLimits, PartStat, ScheduleAgent};

use super::compare::{CompareOptions, compare, date_set};
use super::reply::{drop_comments, restore_comments};
use super::{SERVER_OWNED, View, attendee_addresses, organizer_of, sequence_of, utc_zones, views};
use crate::calendar::{Moment, Node, Param, Prop, address_of, entry_moment, entry_moments, schedule_agent_of};
use crate::error::{IcalError, LimitKind};
use crate::merge::{master_index, override_from_master, override_index, put_param, set_param};
use crate::parse::ParsedCalendar;
use crate::zones::{RidKey, Zones};

/// How an instance changed between two versions of the organizer copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeClass {
    /// The instance is new (a new object, or an override that leaves the instance as the series produced it).
    Created,
    /// `DTSTART`, `DTEND`/`DURATION`, `RRULE`/`RDATE`/`EXDATE`, `LOCATION`, `SUMMARY` or `STATUS` changed:
    /// attendees' participation resets to `NEEDS-ACTION` and the sequence number rises.
    Significant,
    /// Only other properties changed: internal copies are updated silently and no mail is sent.
    Insignificant,
    /// The instance disappeared (a removed override).
    Removed,
    /// Nothing relevant changed.
    Unchanged,
}

/// The change of one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceDiff {
    /// The recurrence id of the instance; `None` for the master component.
    pub recurrence_id: Option<EventTime>,
    /// How it changed.
    pub change: ChangeClass,
    /// The names of the properties that changed, for diagnostics and audit.
    pub changed_properties: Vec<String>,
}

/// The attendees that were added to or removed from one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceAttendees {
    /// The recurrence id of the instance; `None` for the master component.
    pub recurrence_id: Option<EventTime>,
    /// Attendees the instance has now and did not have (the organizer's own line does not count).
    pub added: Vec<CalendarUserAddress>,
    /// Attendees the instance had and does not have any more. An attendee that an override drops while the
    /// series keeps them gets a `CANCEL` of that instance only (`MessageScope::Instances`), built from the stored
    /// copy.
    pub removed: Vec<CalendarUserAddress>,
}

/// The result of [`diff()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItipDiff {
    /// One entry per master or override instance that exists in either version.
    pub instances: Vec<InstanceDiff>,
    /// Attendees that are new on the object; the organizer's own `ATTENDEE` line does not count. Attendees that
    /// the server does not schedule (`SCHEDULE-AGENT` other than `SERVER`) are listed too: whom a message goes to
    /// is the application's decision (PLAN 2.8).
    pub added_attendees: Vec<CalendarUserAddress>,
    /// Attendees that were removed from the whole object: they receive a `CANCEL`; the organizer's own
    /// `ATTENDEE` line does not count.
    pub removed_attendees: Vec<CalendarUserAddress>,
    /// Instances that were cancelled (added `EXDATE`s and removed overrides): they produce a `CANCEL` with
    /// `RECURRENCE-ID`.
    pub cancelled_instances: Vec<EventTime>,
    /// Whether the new version needs a higher `SEQUENCE` than the client sent.
    pub needs_sequence_bump: bool,
    /// The attendees that came or went on single instances (an override that names other attendees than the
    /// series), only for the instances where that happened.
    pub instance_attendees: Vec<InstanceAttendees>,
}

/// The attendees of one component, without the organizer's own line, each once.
fn attendees_of(node: &Node) -> Vec<CalendarUserAddress> {
    let organizer = node.first(&Prop::Organizer).and_then(address_of);
    let mut seen: HashSet<CalendarUserAddress> = HashSet::new();
    let mut found = Vec::new();
    for entry in node.all(&Prop::Attendee) {
        if let Some(address) = address_of(entry)
            && organizer.as_ref() != Some(&address)
            && seen.insert(address.clone())
        {
            found.push(address);
        }
    }
    found
}

/// The attendees that differ between two components, as a record for the instance (`None` when they do not).
fn attendee_change(recurrence_id: Option<EventTime>, before: &Node, after: &Node) -> Option<InstanceAttendees> {
    let old = attendees_of(before);
    let new = attendees_of(after);
    let old_set: HashSet<&CalendarUserAddress> = old.iter().collect();
    let new_set: HashSet<&CalendarUserAddress> = new.iter().collect();
    let added: Vec<CalendarUserAddress> = new
        .iter()
        .filter(|address| !old_set.contains(address))
        .cloned()
        .collect();
    let removed: Vec<CalendarUserAddress> = old
        .iter()
        .filter(|address| !new_set.contains(address))
        .cloned()
        .collect();
    (!added.is_empty() || !removed.is_empty()).then_some(InstanceAttendees {
        recurrence_id,
        added,
        removed,
    })
}

/// Compares the previous organizer copy (`None` when the object is new) with the new one.
///
/// # Errors
///
/// [`IcalError::Limit`] when an object has more components than `max_components`.
pub fn diff(old: Option<&ParsedCalendar>, new: &ParsedCalendar, limits: &IcalLimits) -> Result<ItipDiff, IcalError> {
    let max_components = usize::try_from(limits.max_components).unwrap_or(usize::MAX);
    let new_zones = utc_zones(&new.root);
    let new_views = views(&new.root, &new_zones);
    let old_zones = old.map_or_else(
        || Zones::new(crate::zones::Zone::utc()),
        |calendar| utc_zones(&calendar.root),
    );
    let old_views = old.map_or_else(Vec::new, |calendar| views(&calendar.root, &old_zones));
    if new_views.len().max(old_views.len()) > max_components {
        return Err(IcalError::Limit(LimitKind::Components));
    }
    let keys: BTreeSet<Option<RidKey>> = new_views.iter().chain(old_views.iter()).map(|view| view.key).collect();
    let mut instances = Vec::new();
    let mut instance_attendees = Vec::new();
    let mut cancelled: BTreeMap<RidKey, EventTime> = BTreeMap::new();
    let mut needs_sequence_bump = false;
    for key in keys {
        let before = old_views.iter().find(|view| view.key == key);
        let after = new_views.iter().find(|view| view.key == key);
        let recurrence_id = match (after, before) {
            (Some(view), _) => view.rid.as_ref().map(|rid| rid.to_event_time(&new_zones)),
            (None, Some(view)) => view.rid.as_ref().map(|rid| rid.to_event_time(&old_zones)),
            (None, None) => None,
        };
        let (change, changed_properties) = match (before, after) {
            (None, Some(created)) => {
                let (class, names, base, derived) = classify_created(old, &old_zones, created, &new_zones);
                if class == ChangeClass::Significant && sequence_of(created.node) <= base {
                    needs_sequence_bump = true;
                }
                if let Some(derived) = derived {
                    instance_attendees.extend(attendee_change(recurrence_id.clone(), &derived, created.node));
                }
                (class, names)
            }
            (Some(removed), None) => {
                if let (Some(rid), Some(at)) = (&removed.rid, removed.key) {
                    cancelled.insert(at, rid.to_event_time(&old_zones));
                }
                (ChangeClass::Removed, Vec::new())
            }
            (Some(first), Some(second)) => {
                let (class, names) = classify(first, &old_zones, second, &new_zones);
                if class == ChangeClass::Significant && sequence_of(second.node) <= sequence_of(first.node) {
                    needs_sequence_bump = true;
                }
                instance_attendees.extend(attendee_change(recurrence_id.clone(), first.node, second.node));
                (class, names)
            }
            (None, None) => continue,
        };
        instances.push(InstanceDiff {
            recurrence_id,
            change,
            changed_properties,
        });
    }
    // Instances removed from the series with an EXDATE are cancelled as well.
    if let (Some(before), Some(after)) = (
        old_views.iter().find(|view| view.key.is_none()),
        new_views.iter().find(|view| view.key.is_none()),
    ) {
        let known = date_set(before.node, &Prop::Exdate, &old_zones);
        for entry in after.node.all(&Prop::Exdate) {
            for moment in entry_moments(entry).0 {
                if let Some(at) = new_zones.rid_key(&moment)
                    && !known.contains(&at)
                {
                    cancelled.entry(at).or_insert_with(|| moment.to_event_time(&new_zones));
                }
            }
        }
    }
    // The organizer's own `ATTENDEE` line is not a recipient of anything.
    let old_organizer = old.and_then(|calendar| organizer_of(&calendar.root));
    let new_organizer = organizer_of(&new.root);
    let old_addresses = old
        .map(|calendar| attendee_addresses(&calendar.root))
        .unwrap_or_default();
    let new_addresses = attendee_addresses(&new.root);
    let old_set: HashSet<&CalendarUserAddress> = old_addresses.iter().collect();
    let new_set: HashSet<&CalendarUserAddress> = new_addresses.iter().collect();
    Ok(ItipDiff {
        instances,
        added_attendees: new_addresses
            .iter()
            .filter(|address| !old_set.contains(address) && Some(*address) != new_organizer.as_ref())
            .cloned()
            .collect(),
        removed_attendees: old_addresses
            .iter()
            .filter(|address| !new_set.contains(address) && Some(*address) != old_organizer.as_ref())
            .cloned()
            .collect(),
        cancelled_instances: cancelled.into_values().collect(),
        needs_sequence_bump,
        instance_attendees,
    })
}

/// The class, the changed property names, the `SEQUENCE` to beat and the instance as the series produced it
/// (when there is one) for a component that is new.
///
/// A new override is not merely new: it replaces the instance the series produced, so moving one instance of a
/// series (the common "this event only" edit) is a significant change of that instance. The comparison is made
/// with the instance as the stored master produced it.
fn classify_created(
    old: Option<&ParsedCalendar>,
    old_zones: &Zones,
    created: &View<'_>,
    new_zones: &Zones,
) -> (ChangeClass, Vec<String>, i64, Option<Node>) {
    let derived = old.zip(created.rid.as_ref()).and_then(|(calendar, rid)| {
        let master = master_index(&calendar.root)?;
        override_from_master(&calendar.root, master, rid, old_zones).ok()
    });
    let Some(derived) = derived else {
        return (ChangeClass::Created, Vec::new(), 0, None);
    };
    let compared = compare(
        &derived,
        old_zones,
        created.node,
        new_zones,
        &CompareOptions::organizer(),
    );
    // A series rule or a list of dates does not describe a single instance.
    let mut names: Vec<String> = compared
        .significant
        .into_iter()
        .filter(|name| !matches!(name.as_str(), "RRULE" | "RDATE" | "EXDATE"))
        .collect();
    if names.is_empty() {
        return (ChangeClass::Created, Vec::new(), 0, Some(derived));
    }
    names.sort();
    let base = sequence_of(&derived);
    (ChangeClass::Significant, names, base, Some(derived))
}

/// The class and the changed property names of an instance that exists in both versions.
fn classify(first: &View<'_>, old_zones: &Zones, second: &View<'_>, new_zones: &Zones) -> (ChangeClass, Vec<String>) {
    let compared = compare(
        first.node,
        old_zones,
        second.node,
        new_zones,
        &CompareOptions::organizer(),
    );
    let class = if !compared.significant.is_empty() {
        ChangeClass::Significant
    } else if compared.other.is_empty() {
        ChangeClass::Unchanged
    } else {
        ChangeClass::Insignificant
    };
    let mut names: Vec<String> = compared.significant.into_iter().chain(compared.other).collect();
    names.sort();
    names.dedup();
    (class, names)
}

/// The new organizer copy after the rules of PLAN 2.8, with the diff it was derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizerUpdate {
    /// The new copy: the answers and delivery states of the attendees as the server holds them (a client cannot
    /// set them), `SEQUENCE` raised where a significant change needs it and `PARTSTAT` of the attendees reset to
    /// `NEEDS-ACTION` on significantly changed instances.
    pub calendar: ParsedCalendar,
    /// The comparison of the client's version with the stored one.
    pub diff: ItipDiff,
}

/// Compares `old` with `new` and applies the rules of PLAN 2.8 to `new`:
///
/// * the answer (`PARTSTAT`) and the delivery status (`SCHEDULE-STATUS`) of every attendee are the server's:
///   an attendee that is on the same instance of the stored copy keeps both as stored, an attendee that is new
///   on the instance (a new object, a new override, an added attendee) starts as `NEEDS-ACTION` without a
///   status, whatever the client sent. Only [`crate::itip::apply_reply`] changes an answer and only delivery
///   writes a status. The organizer's own `ATTENDEE` line and attendees with another `SCHEDULE-AGENT` than the
///   server are left alone (their answers do not come from the server);
/// * the comment an attendee gave with an answer (`X-CALENDARSERVER-ATTENDEE-COMMENT`) is the server's like the answer:
///   the comments the client sends are dropped, and the stored ones of the same instance stay with the attendees that
///   keep their answer, so a version that predates a reply does not lose the remark;
/// * every significantly changed instance gets a `SEQUENCE` above the stored one (unless the client already
///   raised it) and its attendees other than the organizer answer `NEEDS-ACTION` again, which takes their comments away.
///
/// A new override starts from the attendees of the series it was cut out of.
///
/// # Errors
///
/// As [`diff()`]; [`IcalError::Invalid`] when a value cannot be written back.
pub fn apply_organizer_changes(
    old: Option<&ParsedCalendar>,
    new: &ParsedCalendar,
    limits: &IcalLimits,
) -> Result<OrganizerUpdate, IcalError> {
    let report = diff(old, new, limits)?;
    let mut root = new.root.clone();
    let new_zones = utc_zones(&new.root);
    let old_zones = old.map(|calendar| utc_zones(&calendar.root));
    restore_server_state(&mut root, old.zip(old_zones.as_ref()))?;
    for instance in report
        .instances
        .iter()
        .filter(|instance| instance.change == ChangeClass::Significant)
    {
        let rid = instance.recurrence_id.as_ref().map(Moment::from_event_time);
        let index = match &rid {
            None => master_index(&root),
            Some(rid) => override_index(&root, &new_zones, rid),
        };
        let Some(node) = index.and_then(|index| root.children.get_mut(index)) else {
            continue;
        };
        let previous = old.and_then(|calendar| {
            let zones = old_zones.as_ref()?;
            // A new override starts from the sequence of the series it was cut out of.
            let index = match &rid {
                None => master_index(&calendar.root),
                Some(rid) => override_index(&calendar.root, zones, rid).or_else(|| master_index(&calendar.root)),
            }?;
            calendar.root.children.get(index).map(sequence_of)
        });
        let wanted = previous.map_or(0, |value| value.saturating_add(1));
        if sequence_of(node) < wanted {
            node.set(crate::calendar::entry_from_line(&format!("SEQUENCE:{wanted}"))?);
        }
        reset_participation(node)?;
    }
    Ok(OrganizerUpdate {
        calendar: ParsedCalendar::from_root(root),
        diff: report,
    })
}

/// The component of the stored copy that describes the same instance (the one with the same recurrence id, `true`)
/// or, for an override that is new, the master it is cut out of (`false`).
fn reference_component<'a>(root: &'a Node, zones: &Zones, rid: Option<&Moment>) -> Option<(&'a Node, bool)> {
    let (index, same_instance) = match rid {
        None => (master_index(root)?, true),
        Some(rid) => match override_index(root, zones, rid) {
            Some(index) => (index, true),
            None => (master_index(root)?, false),
        },
    };
    root.children.get(index).map(|node| (node, same_instance))
}

/// Gives the answers, the comments that came with them and the delivery states back to the server (see
/// [`apply_organizer_changes`]).
fn restore_server_state(root: &mut Node, old: Option<(&ParsedCalendar, &Zones)>) -> Result<(), IcalError> {
    for node in root.children.iter_mut().filter(|node| node.component_kind().is_some()) {
        let organizer = node.first(&Prop::Organizer).and_then(address_of);
        let rid = node.first(&Prop::RecurrenceId).and_then(entry_moment);
        let (reference, same_instance) = old
            .and_then(|(calendar, zones)| reference_component(&calendar.root, zones, rid.as_ref()))
            .map_or((None, false), |(node, same)| (Some(node), same));
        // The attendees whose answer the stored component of the same instance holds, with the comment that came with it.
        let mut answered: Vec<CalendarUserAddress> = Vec::new();
        for entry in node.entries.iter_mut().filter(|entry| entry.name == Prop::Attendee) {
            let Some(address) = address_of(entry) else {
                continue;
            };
            if organizer.as_ref() == Some(&address) || schedule_agent_of(entry) != ScheduleAgent::Server {
                continue;
            }
            let previous = reference.and_then(|node| {
                node.all(&Prop::Attendee)
                    .find(|stored| address_of(stored).as_ref() == Some(&address))
            });
            for name in &SERVER_OWNED {
                // A new instance has had nothing delivered yet: it takes the answer of the series, not its status.
                let inherits = same_instance || *name != Param::ScheduleStatus;
                let kept = previous
                    .filter(|_| inherits)
                    .and_then(|stored| stored.params.iter().find(|param| &param.name == name))
                    .cloned();
                put_param(entry, name, kept);
            }
            if previous.is_none() {
                set_param(entry, &Param::Partstat, "PARTSTAT", PartStat::NeedsAction.as_ical())?;
            } else if same_instance {
                answered.push(address);
            }
        }
        // The comments belong to the answers they came with: the client's are dropped, the stored ones of the same instance
        // are kept for the attendees that keep their answer.
        restore_comments(node, reference.filter(|_| same_instance), &answered);
    }
    Ok(())
}

/// Sets `PARTSTAT=NEEDS-ACTION` on every attendee except the organizer, and drops the comments of the answers that are gone.
fn reset_participation(node: &mut Node) -> Result<(), IcalError> {
    let organizer = node.first(&Prop::Organizer).and_then(address_of);
    for entry in node.entries.iter_mut().filter(|entry| entry.name == Prop::Attendee) {
        if address_of(entry).is_some() && address_of(entry) == organizer {
            continue;
        }
        set_param(entry, &Param::Partstat, "PARTSTAT", PartStat::NeedsAction.as_ical())?;
    }
    drop_comments(node, |who| Some(who) != organizer.as_ref());
    Ok(())
}

/// Lists what a new version of the organizer's copy changes that nobody may change: the `UID` (a resource is
/// one UID) and the `ORGANIZER` (RFC 6638 `CALDAV:allowed-organizer-scheduling-object-change`). A copy that did
/// not name an organizer may gain one (the event becomes a meeting); one that has an organizer keeps it. The
/// result lists the names of the offending properties; it is empty when the change is allowed.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn organizer_change_violations(old: &ParsedCalendar, new: &ParsedCalendar) -> Result<Vec<String>, IcalError> {
    let uid_of = |calendar: &ParsedCalendar| {
        calendar
            .root
            .children
            .iter()
            .filter(|node| node.component_kind().is_some())
            .find_map(Node::uid)
    };
    let mut found: BTreeSet<String> = BTreeSet::new();
    if uid_of(old) != uid_of(new) {
        found.insert("UID".to_owned());
    }
    match (organizer_of(&old.root), organizer_of(&new.root)) {
        (Some(before), Some(after)) if before != after => {
            found.insert("ORGANIZER".to_owned());
        }
        (Some(_), None) => {
            found.insert("ORGANIZER".to_owned());
        }
        _ => {}
    }
    Ok(found.into_iter().collect())
}
