//! Finding and building the components of single instances of a recurring object, shared by the merge and the
//! iTIP code.

use std::collections::HashSet;

use calcard::icalendar::{ICalendarEntry, ICalendarParameter};
use chrono::{DateTime, NaiveDate, TimeDelta, Utc};
use davhaven_domain::IcalLimits;

use crate::calendar::{
    Kind, Moment, Node, Param, Prop, entry_for_moment, entry_from_line, entry_moment, moment_line, param_value,
    remove_param,
};
use crate::error::IcalError;
use crate::filter::TimeRange;
use crate::occurrence::{Budget, Engine, Flow};
use crate::zones::Zones;

/// How long after an instance's recurrence id the search for the instance extends.
const INSTANCE_WINDOW_DAYS: i64 = 2;

pub(crate) fn invalid(message: &str) -> IcalError {
    IcalError::invalid(message)
}

/// The index of the master component (the stored component without `RECURRENCE-ID`).
pub(crate) fn master_index(root: &Node) -> Option<usize> {
    root.children
        .iter()
        .position(|node| node.component_kind().is_some() && !node.is_override())
}

/// The index of the override component for a recurrence id.
pub(crate) fn override_index(root: &Node, zones: &Zones, rid: &Moment) -> Option<usize> {
    root.children.iter().position(|node| {
        node.component_kind().is_some()
            && node
                .first(&Prop::RecurrenceId)
                .and_then(entry_moment)
                .is_some_and(|own| zones.same(&own, rid))
    })
}

/// A moment of the same kind and zone as `like` at the given instant.
pub(crate) fn moment_like(zones: &Zones, like: &Moment, instant: DateTime<Utc>) -> Moment {
    let local = zones.local_in_zone_of(like, instant);
    match like {
        Moment::Date(_) => Moment::Date(local.date()),
        Moment::Floating(_) => Moment::Floating(local),
        Moment::Utc(_) => Moment::Utc(instant.naive_utc()),
        Moment::Zoned { tzid, .. } => Moment::Zoned {
            local,
            tzid: tzid.clone(),
        },
    }
}

/// The instances the master of an object generates inside a window, as identities that recurrence ids can be
/// looked up in.
#[derive(Debug, Default)]
pub(crate) struct InstanceSet {
    instants: HashSet<DateTime<Utc>>,
    dates: HashSet<NaiveDate>,
    all_day_dates: HashSet<NaiveDate>,
}

impl InstanceSet {
    /// Whether the series generates the instance that `rid` names: all-day values match by date, everything
    /// else by instant.
    pub(crate) fn contains(&self, zones: &Zones, rid: &Moment) -> bool {
        if rid.is_date() {
            return self.dates.contains(&rid.date());
        }
        zones.to_utc(rid).is_some_and(|at| self.instants.contains(&at)) || self.all_day_dates.contains(&rid.date())
    }
}

/// The instances the series of the object generates inside `window` (overrides do not count), in one pass.
pub(crate) fn instance_set(
    root: &Node,
    zones: &Zones,
    limits: &IcalLimits,
    window: &TimeRange,
) -> Result<InstanceSet, IcalError> {
    let mut found = InstanceSet::default();
    let mut engine = Engine::new(zones, limits, Budget::new(limits)).without_instance_limit();
    engine.visit(root, window, &mut |occurrence| {
        if !occurrence.is_override {
            found.dates.insert(occurrence.recurrence_id.date());
            if occurrence.recurrence_id.is_date() {
                found.all_day_dates.insert(occurrence.recurrence_id.date());
            } else if let Some(at) = zones.to_utc(&occurrence.recurrence_id) {
                found.instants.insert(at);
            }
        }
        Ok(Flow::Continue)
    })?;
    Ok(found)
}

/// The window in which the search for the instance named by `rid` runs.
pub(crate) fn instance_window(zones: &Zones, rid: &Moment) -> Option<TimeRange> {
    let at = zones.to_utc(rid)?;
    let reach = TimeDelta::try_days(INSTANCE_WINDOW_DAYS).unwrap_or_default();
    Some(TimeRange::new(
        at.checked_sub_signed(reach),
        at.checked_add_signed(reach),
    ))
}

/// Whether the master generates an instance with this recurrence id.
pub(crate) fn names_instance(root: &Node, zones: &Zones, limits: &IcalLimits, rid: &Moment) -> Result<bool, IcalError> {
    let Some(window) = instance_window(zones, rid) else {
        return Ok(false);
    };
    Ok(instance_set(root, zones, limits, &window)?.contains(zones, rid))
}

/// A new override component: a copy of the master for one instance, with the instance's own start.
pub(crate) fn override_from_master(
    root: &Node,
    master_index: usize,
    rid: &Moment,
    zones: &Zones,
) -> Result<Node, IcalError> {
    let master = root
        .children
        .get(master_index)
        .ok_or_else(|| invalid("the master component is missing"))?;
    let master_start = master
        .first(&Prop::Dtstart)
        .and_then(entry_moment)
        .ok_or_else(|| invalid("the master has no DTSTART"))?;
    let instant = zones.to_utc(rid).ok_or_else(|| invalid("a date is out of range"))?;
    let start = if master_start.is_date() {
        Moment::Date(rid.date())
    } else {
        moment_like(zones, &master_start, instant)
    };
    let mut node = Node::new(master.kind.clone());
    node.children.clone_from(&master.children);
    for entry in &master.entries {
        let skipped = matches!(
            entry.name,
            Prop::Rrule
                | Prop::Rdate
                | Prop::Exdate
                | Prop::Exrule
                | Prop::RecurrenceId
                | Prop::Dtstart
                | Prop::Dtend
                | Prop::Due
        );
        if !skipped {
            node.entries.push(entry.clone());
        }
    }
    node.entries.push(entry_for_moment("DTSTART", &start)?);
    let end_name = if master.kind == Kind::VTodo {
        Prop::Due
    } else {
        Prop::Dtend
    };
    if let Some(end) = master.first(&end_name).and_then(entry_moment) {
        let shifted = shifted_end(zones, &master_start, &end, &start)?;
        node.entries.push(entry_for_moment(end_name.as_str(), &shifted)?);
    }
    // The recurrence id keeps the kind and zone of the master's start.
    let line = moment_line("RECURRENCE-ID", &start_like_rid(zones, &master_start, rid, instant));
    node.entries.push(entry_from_line(&line)?);
    Ok(node)
}

/// The recurrence id of an instance written the way the series writes its start.
fn start_like_rid(zones: &Zones, master_start: &Moment, rid: &Moment, instant: DateTime<Utc>) -> Moment {
    if master_start.is_date() {
        Moment::Date(rid.date())
    } else {
        moment_like(zones, master_start, instant)
    }
}

/// The end of an instance that starts at `new_start` when the master runs from `old_start` to `old_end`.
pub(crate) fn shifted_end(
    zones: &Zones,
    old_start: &Moment,
    old_end: &Moment,
    new_start: &Moment,
) -> Result<Moment, IcalError> {
    if let (Moment::Date(first), Moment::Date(last), Moment::Date(start)) = (old_start, old_end, new_start) {
        let days = last.signed_duration_since(*first);
        let end = start
            .checked_add_signed(days)
            .ok_or_else(|| invalid("a date is out of range"))?;
        return Ok(Moment::Date(end));
    }
    let (Some(first), Some(last), Some(start)) =
        (zones.to_utc(old_start), zones.to_utc(old_end), zones.to_utc(new_start))
    else {
        return Err(invalid("a date is out of range"));
    };
    let end = start
        .checked_add_signed(last.signed_duration_since(first))
        .ok_or_else(|| invalid("a date is out of range"))?;
    Ok(moment_like(zones, old_end, end))
}

/// A parameter value kept as a typed parameter, built the way the parser would build it.
fn param_of(name: &str, value: &str) -> Result<ICalendarParameter, IcalError> {
    let entry = entry_from_line(&format!("X-PARAM;{name}={}:x", param_value(value)))?;
    entry
        .params
        .into_iter()
        .next()
        .ok_or_else(|| invalid("a parameter value cannot be written"))
}

/// Sets the parameter `name` (written `text_name`) of a property to `value`. An existing parameter is replaced
/// where it stands (the order of the parameters of a line stays as the client wrote it), a missing one is added
/// at the end.
pub(crate) fn set_param(
    entry: &mut ICalendarEntry,
    name: &Param,
    text_name: &str,
    value: &str,
) -> Result<(), IcalError> {
    let new = param_of(text_name, value)?;
    put_param(entry, name, Some(new));
    Ok(())
}

/// Puts `param` in the place of the parameter `name` of the property (or at the end when there is none); `None`
/// removes the parameter. Further parameters of the same name go.
pub(crate) fn put_param(entry: &mut ICalendarEntry, name: &Param, param: Option<ICalendarParameter>) {
    let position = entry.params.iter().position(|existing| &existing.name == name);
    match (position, param) {
        (Some(position), Some(param)) => {
            if let Some(slot) = entry.params.get_mut(position) {
                *slot = param;
            }
            let mut index = 0usize;
            entry.params.retain(|existing| {
                let keep = index <= position || &existing.name != name;
                index = index.saturating_add(1);
                keep
            });
        }
        (None, Some(param)) => entry.params.push(param),
        (_, None) => remove_param(entry, name),
    }
}
