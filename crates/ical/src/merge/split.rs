//! Removing instances of a recurring event and splitting a series ("this and all following instances").
//!
//! Clients that edit or delete "this and future" shorten the series with an `UNTIL` before the instance and, for
//! an edit, start a second series with a UID of its own at the instance. `RANGE=THISANDFUTURE` on a
//! `RECURRENCE-ID` is allowed by RFC 5545 but few clients evaluate it, so the server never writes it (it only
//! reads it); the same two steps are done here for the API and MCP edits.

use std::collections::BTreeSet;

use calcard::icalendar::{
    ICalendarEntry, ICalendarPeriod, ICalendarRecurrenceRule, ICalendarValue, ICalendarValueType,
};
use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};
use davhaven_domain::{EventData, EventTime, IcalLimits, Uid};

use super::instances::{invalid, master_index, moment_like, names_instance, override_from_master, override_index};
use super::write::{apply, check_patch, finish, stamp};
use super::{EditScope, MergeContext, merge_event};
use crate::calendar::{
    Kind, Moment, Node, Param, Prop, entry_for_moment, entry_for_text, entry_from_line, entry_moment,
    moment_from_partial, param_text,
};
use crate::error::{IcalError, LimitKind};
use crate::filter::TimeRange;
use crate::occurrence::{Budget, Engine};
use crate::parse::ParsedCalendar;
use crate::recur::{RuleError, is_unbounded, rule_locals, rule_until_local};
use crate::zones::{Zone, Zones};

/// The two objects an edit of "this and all following instances" produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitEdit {
    /// The original object, shortened so that it ends before the edited instance; `None` when the edit starts at
    /// the first instance: there is nothing earlier to keep and `continuation` replaces the object.
    pub earlier: Option<ParsedCalendar>,
    /// The edited instance and everything after it. It is a series of its own with the UID of the original when
    /// `earlier` is `None`, and with the `continuation_uid` the caller supplied otherwise.
    pub continuation: ParsedCalendar,
}

/// Edits an instance of a recurring event and every later one the way calendar clients do: the series is cut
/// before the instance and the instance starts a new series with the edit applied.
///
/// * `earlier` is the stored object with the instance and everything after it removed (`UNTIL` before the
///   instance, later overrides and recurrence dates gone); it keeps its UID.
/// * `continuation` is a copy that begins with the instance as it is shown now (the override of the instance if
///   there is one), carries the recurrence rule (a `COUNT` is reduced by the instances before the cut), the
///   later overrides and the later recurrence dates under `continuation_uid`, and has `patch` applied. `patch`
///   must name the instance in `recurrence_id`; its fields change the new series (a `start` moves the whole new
///   series, a `recurrence` replaces its rule).
///
/// When the instance is the first one of the series, nothing remains before it: the result is the whole object
/// edited (`earlier` is `None`, the UID is kept).
///
/// Both objects pass the gate of [`merge_event`]. Whether and to whom the changes are sent is the caller's
/// business (the new series is a new scheduling object, the old one changed).
///
/// # Errors
///
/// [`IcalError::Invalid`] when the patch has no recurrence id, the recurrence id names no instance, the UID of
/// the continuation is the UID of the event, or the series cannot be cut (no recurrence); [`IcalError::Limit`]
/// when a result exceeds a limit.
pub fn merge_event_split(
    existing: &ParsedCalendar,
    patch: &EventData,
    context: &MergeContext<'_>,
    continuation_uid: &Uid,
) -> Result<SplitEdit, IcalError> {
    check_patch(patch, context)?;
    let rid_time = patch
        .recurrence_id
        .as_ref()
        .ok_or_else(|| invalid("a this-and-future edit needs the recurrence id of the first instance it changes"))?;
    if continuation_uid == context.uid {
        return Err(invalid("the continuation of a series needs a UID of its own"));
    }
    let root = &existing.root;
    let zones = Zones::for_tree(root, Zone::from_tz(context.default_zone.tz()));
    let rid = Moment::from_event_time(rid_time);
    let master = master_index(root).ok_or_else(|| invalid("the object has no master component"))?;
    let existing_override = override_index(root, &zones, &rid);
    if existing_override.is_none() && !names_instance(root, &zones, context.limits, &rid)? {
        return Err(invalid("the recurrence id names no instance of the event"));
    }
    let master_start = root
        .children
        .get(master)
        .and_then(|node| node.first(&Prop::Dtstart))
        .and_then(entry_moment)
        .ok_or_else(|| invalid("the master has no DTSTART"))?;
    let instant = zones.to_utc(&rid).ok_or_else(|| invalid("a date is out of range"))?;
    let first = zones
        .to_utc(&master_start)
        .ok_or_else(|| invalid("a date is out of range"))?;
    if first >= instant {
        let whole = MergeContext {
            scope: EditScope::All,
            ..*context
        };
        let continuation = merge_event(Some(existing), patch, &whole)?;
        return Ok(SplitEdit {
            earlier: None,
            continuation,
        });
    }
    let like = instance_like(&zones, &master_start, &rid, instant);
    let mut shortened = root.clone();
    truncate_before(&mut shortened, &zones, &master_start, &like, instant, context.limits)?;
    let tail = continuation_of(
        root,
        &zones,
        master,
        existing_override,
        (&rid, &like, instant),
        continuation_uid,
        patch,
        context,
    )?;
    Ok(SplitEdit {
        earlier: Some(finish(shortened, context.limits)?),
        continuation: finish(tail, context.limits)?,
    })
}

/// The recurrence id of an instance written the way the series writes its start.
fn instance_like(zones: &Zones, master_start: &Moment, rid: &Moment, instant: DateTime<Utc>) -> Moment {
    if master_start.is_date() {
        Moment::Date(rid.date())
    } else {
        moment_like(zones, master_start, instant)
    }
}

/// The new series that begins with the edited instance.
#[expect(
    clippy::too_many_arguments,
    reason = "the pieces of one split; grouping them in a struct used once would only move the list"
)]
fn continuation_of(
    root: &Node,
    zones: &Zones,
    master: usize,
    existing_override: Option<usize>,
    (rid, like, instant): (&Moment, &Moment, DateTime<Utc>),
    uid: &Uid,
    patch: &EventData,
    context: &MergeContext<'_>,
) -> Result<Node, IcalError> {
    let source = root
        .children
        .get(master)
        .ok_or_else(|| invalid("the master component is missing"))?;
    // The first instance as it is shown now: its override, or the series' own instance.
    let mut head = match existing_override.and_then(|index| root.children.get(index)) {
        Some(node) => node.clone(),
        None => override_from_master(root, master, rid, zones)?,
    };
    head.remove(&Prop::RecurrenceId);
    head.set(entry_for_text("UID", uid.as_str())?);
    head.set(entry_from_line("SEQUENCE:0")?);
    stamp(&mut head, context.now, true)?;
    // The recurrence set continues from the instance on.
    head.entries
        .extend(recurrence_of(source, zones, like, instant, context.limits)?);
    let mut tail = Node::new(Kind::VCalendar);
    tail.entries.clone_from(&root.entries);
    let mut components = vec![head];
    for node in root.children.iter().filter(|node| node.is_override()) {
        let at = node
            .first(&Prop::RecurrenceId)
            .and_then(entry_moment)
            .and_then(|moment| zones.to_utc(&moment));
        if at.is_some_and(|at| at > instant) {
            let mut moved = node.clone();
            moved.set(entry_for_text("UID", uid.as_str())?);
            components.push(moved);
        }
    }
    if let Some(first) = components.first_mut() {
        apply(first, patch, context, zones)?;
    }
    let used: BTreeSet<String> = components
        .iter()
        .flat_map(|node| node.entries.iter())
        .filter_map(|entry| param_text(entry, &Param::Tzid))
        .collect();
    for zone in root.children.iter().filter(|child| child.kind == Kind::VTimezone) {
        if zone.text(&Prop::Tzid).is_some_and(|tzid| used.contains(&tzid)) {
            tail.children.push(zone.clone());
        }
    }
    tail.children.extend(components);
    crate::tz::ensure_vtimezones(&mut tail);
    Ok(tail)
}

/// The recurrence properties of the new series: the rule (with a reduced `COUNT`), the recurrence dates and the
/// exclusions from the instance on.
fn recurrence_of(
    source: &Node,
    zones: &Zones,
    like: &Moment,
    instant: DateTime<Utc>,
    limits: &IcalLimits,
) -> Result<Vec<ICalendarEntry>, IcalError> {
    let mut found: Vec<ICalendarEntry> = Vec::new();
    let start = source.first(&Prop::Dtstart).and_then(entry_moment);
    if let Some(entry) = source.first(&Prop::Rrule)
        && let Some(ICalendarValue::RecurrenceRule(rule)) = entry.values.first()
        && let Some(start) = &start
        // An instance that comes from a recurrence date after the end of the rule starts a series without a rule.
        && rule_reaches(rule, start, like, zones, limits)?
    {
        let mut rule = (**rule).clone();
        if let Some(count) = rule.count {
            let before = instances_before(source, like, limits)?;
            let remaining = count.checked_sub(before).filter(|remaining| *remaining > 0);
            rule.count = Some(remaining.ok_or_else(|| invalid("the instance is beyond the end of the series"))?);
        }
        found.push(entry_from_line(&format!("RRULE:{rule}"))?);
    }
    let mut dates = Node::new(Kind::VEvent);
    dates.entries = source
        .entries
        .iter()
        .filter(|entry| matches!(entry.name, Prop::Rdate | Prop::Exdate))
        .cloned()
        .collect();
    // A recurrence date at the instant itself would repeat the start of the new series.
    filter_dates(&mut dates, zones, &|name, at| {
        if *name == Prop::Rdate {
            at > instant
        } else {
            at >= instant
        }
    });
    found.extend(dates.entries);
    Ok(found)
}

/// Whether the rule still produces an instance at or after `like`: a rule without an end always does, one that
/// ends (`COUNT` or `UNTIL`) when its last instance is not before `like`. When the rule is too long to tell, it
/// does.
fn rule_reaches(
    rule: &ICalendarRecurrenceRule,
    start: &Moment,
    like: &Moment,
    zones: &Zones,
    limits: &IcalLimits,
) -> Result<bool, IcalError> {
    if is_unbounded(rule) {
        return Ok(true);
    }
    let bound = rule_until_local(rule, zones.zone_of(start));
    let cap = usize::try_from(limits.max_iterator_steps).unwrap_or(usize::MAX);
    let generated = rule_locals(rule, start.local(), start.is_date(), bound, cap).map_err(|error| {
        let RuleError::Invalid(message) = error;
        IcalError::Invalid(message)
    })?;
    if generated.truncated {
        return Ok(true);
    }
    Ok(generated.dates.iter().any(|date| *date >= like.local()))
}

/// How many instances the rule of the series generates before the instance (the first instance included).
fn instances_before(source: &Node, like: &Moment, limits: &IcalLimits) -> Result<u32, IcalError> {
    let Some(ICalendarValue::RecurrenceRule(rule)) = source.first(&Prop::Rrule).and_then(|entry| entry.values.first())
    else {
        return Ok(0);
    };
    let start = source
        .first(&Prop::Dtstart)
        .and_then(entry_moment)
        .ok_or_else(|| invalid("the master has no DTSTART"))?;
    let cap = usize::try_from(limits.max_iterator_steps).unwrap_or(usize::MAX);
    let bound: Option<NaiveDateTime> = like.local().checked_sub_signed(TimeDelta::seconds(1));
    let generated = rule_locals(rule, start.local(), start.is_date(), bound, cap).map_err(|error| {
        let crate::recur::RuleError::Invalid(message) = error;
        IcalError::Invalid(message)
    })?;
    if generated.truncated {
        return Err(IcalError::Limit(LimitKind::IteratorSteps));
    }
    Ok(u32::try_from(generated.dates.len()).unwrap_or(u32::MAX))
}

// ---------------------------------------------------------------------------------------------------------------
// Removing instances
// ---------------------------------------------------------------------------------------------------------------

/// Removes instances of a recurring event: `This` adds an `EXDATE` and drops the override of that instance,
/// `ThisAndFuture` shortens the rule with an `UNTIL` before the instance, `All` removes the object. Returns
/// `None` when nothing remains and the object must be deleted.
///
/// Uses the default [`IcalLimits`]; the application calls [`remove_instances_with_limits`] with the configured
/// ones.
///
/// # Errors
///
/// As [`remove_instances_with_limits`].
pub fn remove_instances(
    calendar: &ParsedCalendar,
    recurrence_id: &EventTime,
    scope: EditScope,
) -> Result<Option<ParsedCalendar>, IcalError> {
    remove_instances_with_limits(calendar, recurrence_id, scope, &IcalLimits::default())
}

/// Like [`remove_instances`], with the configured limits: the instance that is looked for and the check that
/// something remains obey `limits`, and the result passes the gate of every stored object (so that repeated
/// removals cannot push the `EXDATE`s past `max_recurrence_dates`).
///
/// # Errors
///
/// [`IcalError::Invalid`] when `recurrence_id` names no instance or the series cannot be shortened;
/// [`IcalError::Limit`] when the result exceeds a limit.
pub fn remove_instances_with_limits(
    calendar: &ParsedCalendar,
    recurrence_id: &EventTime,
    scope: EditScope,
    limits: &IcalLimits,
) -> Result<Option<ParsedCalendar>, IcalError> {
    if scope == EditScope::All {
        return Ok(None);
    }
    let root = &calendar.root;
    let zones = Zones::for_tree(root, Zone::utc());
    let rid = Moment::from_event_time(recurrence_id);
    let master = master_index(root).ok_or_else(|| invalid("the object has no master component"))?;
    if override_index(root, &zones, &rid).is_none() && !names_instance(root, &zones, limits, &rid)? {
        return Err(invalid("the recurrence id names no instance of the event"));
    }
    let master_start = root
        .children
        .get(master)
        .and_then(|node| node.first(&Prop::Dtstart))
        .and_then(entry_moment)
        .ok_or_else(|| invalid("the master has no DTSTART"))?;
    let instant = zones.to_utc(&rid).ok_or_else(|| invalid("a date is out of range"))?;
    let like = instance_like(&zones, &master_start, &rid, instant);
    let mut result = root.clone();
    if scope == EditScope::This {
        remove_this(&mut result, &zones, &rid, &like)?;
    } else {
        if zones.to_utc(&master_start).is_some_and(|first| first >= instant) {
            // The first instance and everything after it: nothing remains.
            return Ok(None);
        }
        truncate_before(&mut result, &zones, &master_start, &like, instant, limits)?;
    }
    if !has_instances(&result, &zones, limits)? {
        return Ok(None);
    }
    Ok(Some(finish(result, limits)?))
}

fn remove_this(root: &mut Node, zones: &Zones, rid: &Moment, like: &Moment) -> Result<(), IcalError> {
    if let Some(index) = override_index(root, zones, rid) {
        root.children.remove(index);
    }
    let index = master_index(root).ok_or_else(|| invalid("the object has no master component"))?;
    let node = root
        .children
        .get_mut(index)
        .ok_or_else(|| invalid("the master component is missing"))?;
    node.entries.push(entry_for_moment("EXDATE", like)?);
    Ok(())
}

/// Cuts the series before `instant`: later overrides go, the rule ends with an `UNTIL` before the instance and
/// recurrence dates and exclusions from the instance on go (value by value, so that a list that spans the cut
/// keeps its earlier part). A series made of recurrence dates only has no rule to shorten.
fn truncate_before(
    root: &mut Node,
    zones: &Zones,
    master_start: &Moment,
    like: &Moment,
    instant: DateTime<Utc>,
    limits: &IcalLimits,
) -> Result<(), IcalError> {
    root.children.retain(|node| {
        let is_future_override = node.is_override()
            && node
                .first(&Prop::RecurrenceId)
                .and_then(entry_moment)
                .and_then(|moment| zones.to_utc(&moment))
                .is_some_and(|at| at >= instant);
        !is_future_override
    });
    let index = master_index(root).ok_or_else(|| invalid("the object has no master component"))?;
    let node = root
        .children
        .get_mut(index)
        .ok_or_else(|| invalid("the master component is missing"))?;
    let rule = node
        .first(&Prop::Rrule)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::RecurrenceRule(rule) => Some((**rule).clone()),
            _ => None,
        });
    match rule {
        // A rule that ended before the cut has nothing to shorten (the instance comes from a recurrence date).
        Some(rule) if !rule_reaches(&rule, master_start, like, zones, limits)? => {}
        Some(mut rule) => {
            // `UNTIL` is the last instant that stays: one second before the removed instance, written in the
            // form RFC 5545 requires for the kind of `DTSTART`.
            let until = match master_start {
                Moment::Date(_) => {
                    let day = like
                        .date()
                        .pred_opt()
                        .ok_or_else(|| invalid("a date is out of range"))?;
                    format!("{}", day.format("%Y%m%d"))
                }
                Moment::Floating(_) => {
                    let local = like
                        .local()
                        .checked_sub_signed(TimeDelta::seconds(1))
                        .ok_or_else(|| invalid("a date is out of range"))?;
                    format!("{}", local.format("%Y%m%dT%H%M%S"))
                }
                Moment::Utc(_) | Moment::Zoned { .. } => {
                    let at = instant
                        .checked_sub_signed(TimeDelta::seconds(1))
                        .ok_or_else(|| invalid("a date is out of range"))?;
                    format!("{}Z", at.naive_utc().format("%Y%m%dT%H%M%S"))
                }
            };
            rule.count = None;
            rule.until = None;
            node.set(entry_from_line(&format!("RRULE:{rule};UNTIL={until}"))?);
        }
        None if node.has(&Prop::Rdate) => {}
        None => return Err(invalid("the event has no recurrence to shorten")),
    }
    filter_dates(node, zones, &|_, at| at < instant);
    Ok(())
}

/// The first moment of one value of `RDATE` or `EXDATE`: the date or date-time, or the start of a period.
fn value_start(value: &ICalendarValue, tzid: Option<&str>, date_only: bool) -> Option<Moment> {
    match value {
        ICalendarValue::PartialDateTime(parts) => moment_from_partial(parts, date_only, tzid),
        ICalendarValue::Period(ICalendarPeriod::Range { start, .. } | ICalendarPeriod::Duration { start, .. }) => {
            moment_from_partial(start, false, tzid)
        }
        _ => None,
    }
}

/// Keeps the values of `RDATE` and `EXDATE` for which `keep` says so, one value at a time; a property without
/// values left goes. A value that cannot be read stays.
fn filter_dates(node: &mut Node, zones: &Zones, keep: &dyn Fn(&Prop, DateTime<Utc>) -> bool) {
    for entry in &mut node.entries {
        if !matches!(entry.name, Prop::Rdate | Prop::Exdate) {
            continue;
        }
        let name = entry.name.clone();
        let tzid = param_text(entry, &Param::Tzid);
        let date_only = entry.is_type(&ICalendarValueType::Date);
        entry.values.retain(|value| {
            let moment = value_start(value, tzid.as_deref(), date_only);
            match moment.and_then(|moment| zones.to_utc(&moment)) {
                Some(at) => keep(&name, at),
                None => true,
            }
        });
    }
    node.entries
        .retain(|entry| !matches!(entry.name, Prop::Rdate | Prop::Exdate) || !entry.values.is_empty());
}

/// Whether the object has at least one instance (within the dates the server accepts).
fn has_instances(root: &Node, zones: &Zones, limits: &IcalLimits) -> Result<bool, IcalError> {
    let range = TimeRange::new(limits.min_date_time(), limits.max_date_time());
    let mut engine = Engine::new(zones, limits, Budget::new(limits)).without_instance_limit();
    match engine.any(root, &range) {
        Ok(found) => Ok(found),
        // More work than the generator may do in one go: certainly not empty.
        Err(IcalError::Limit(LimitKind::IteratorSteps | LimitKind::Instances)) => Ok(true),
        Err(other) => Err(other),
    }
}
