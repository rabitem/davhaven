//! The expansion engine behind `expand`, `index`, `filter`, `freebusy` and `projection`.
//!
//! An object holds one master component with a recurrence set (`DTSTART`, `RRULE`, `RDATE`, `EXDATE`) and any
//! number of override components (`RECURRENCE-ID`). Expansion turns it into [`Occurrence`]s:
//!
//! 1. the instants of the recurrence set are generated on the wall clock of the start's time zone and mapped to
//!    instants with the rules of RFC 5545 section 3.3.5,
//! 2. `EXDATE` values remove instances, by instant (or by date for all-day series),
//! 3. every override replaces the generated instance it names, found by instant; an override that names no
//!    generated instance is an instance of its own (`RDATE` moves and invitations to one instance); an override
//!    with `RANGE=THISANDFUTURE` also moves and reshapes every later instance,
//! 4. what remains is filtered by the time range.
//!
//! The original calcard output paired overrides with the wrong instance (the master instance was reported next
//! to its override); step 3 is the pairing that fixes it.

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

use calcard::icalendar::{ICalendarRecurrenceRule, ICalendarValue};
use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};
use davhaven_domain::{ComponentKind, IcalLimits};

use crate::calendar::{
    Kind, Length, Moment, Node, Param, PeriodEnd, Prop, entry_duration, entry_moment, entry_moments, entry_periods,
    has_param,
};
use crate::error::{IcalError, LimitKind};
use crate::filter::TimeRange;
use crate::recur::{RuleError, add_years, is_sub_hourly, is_unbounded, rule_locals, rule_until_local};
use crate::zones::{RidKey, Zone, Zones};

/// A wall-clock budget for one operation.
///
/// The budget is a second line of defence behind the deterministic step budget of the engine: whether it runs
/// out depends on the load of the machine, so the error it raises is transient ([`LimitKind::TimeBudget`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    started: Instant,
    limit: Duration,
}

impl Budget {
    /// A budget of `time_budget_ms`, starting now.
    pub(crate) fn new(limits: &IcalLimits) -> Self {
        Self {
            started: Instant::now(),
            limit: Duration::from_millis(limits.time_budget_ms),
        }
    }

    /// Fails with [`LimitKind::TimeBudget`] once the budget is used up. A budget of zero is used up at once,
    /// which is how tests reach the error without sleeping.
    pub(crate) fn check(&self) -> Result<(), IcalError> {
        if self.started.elapsed() >= self.limit {
            Err(IcalError::Limit(LimitKind::TimeBudget))
        } else {
            Ok(())
        }
    }
}

/// Whether a walk over the instances goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    /// Deliver the next instance.
    Continue,
    /// Nothing more is needed: the walk ends without an error.
    Stop,
}

/// Receives the instances of a walk, one at a time.
pub(crate) type Sink<'s> = dyn FnMut(Occurrence) -> Result<Flow, IcalError> + 's;

/// Every this many candidates of a series the wall-clock budget is checked.
const BUDGET_CHECK_INTERVAL: usize = 256;

/// The timing facts of one `VTODO` instance, as RFC 4791 section 9.9 needs them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TodoTimes {
    pub(crate) dtstart: Option<DateTime<Utc>>,
    pub(crate) due: Option<DateTime<Utc>>,
    pub(crate) duration_end: Option<DateTime<Utc>>,
    pub(crate) completed: Option<DateTime<Utc>>,
    pub(crate) created: Option<DateTime<Utc>>,
}

impl TodoTimes {
    /// RFC 4791 section 9.9: whether a to-do with these properties matches a time range.
    fn matches(&self, range: &TimeRange) -> bool {
        let starts_by = |at: DateTime<Utc>| range.start.is_none_or(|start| start <= at);
        let starts_before = |at: DateTime<Utc>| range.start.is_none_or(|start| start < at);
        let ends_after = |at: DateTime<Utc>| range.end.is_none_or(|end| end > at);
        let ends_at_or_after = |at: DateTime<Utc>| range.end.is_none_or(|end| end >= at);
        match (self.dtstart, self.duration_end, self.due, self.completed, self.created) {
            (Some(start), Some(finish), _, _, _) => {
                starts_by(finish) && (ends_after(start) || ends_at_or_after(finish))
            }
            (Some(start), None, Some(due), _, _) => {
                (starts_before(due) || starts_by(start)) && (ends_after(start) || ends_at_or_after(due))
            }
            (Some(start), None, None, _, _) => starts_by(start) && ends_after(start),
            (None, _, Some(due), _, _) => starts_before(due) && ends_at_or_after(due),
            (None, _, None, Some(completed), Some(created)) => {
                (starts_by(created) || starts_by(completed))
                    && (ends_at_or_after(created) || ends_at_or_after(completed))
            }
            (None, _, None, Some(completed), None) => starts_by(completed) && ends_at_or_after(completed),
            (None, _, None, None, Some(created)) => ends_after(created),
            (None, _, None, None, None) => true,
        }
    }

    /// The representative start of the to-do.
    fn start(&self) -> Option<DateTime<Utc>> {
        self.dtstart.or(self.due).or(self.completed).or(self.created)
    }

    /// The representative end of the to-do.
    fn end(&self) -> Option<DateTime<Utc>> {
        self.due.or(self.duration_end).or_else(|| self.start())
    }
}

/// How an instance is matched against a time range (RFC 4791 section 9.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Matching {
    /// By overlap of the instance with the range.
    Overlap,
    /// A zero-length instance that a `DTEND` equal to `DTSTART` defines: the table of RFC 4791 section 9.9 matches
    /// it only when the instant lies strictly inside the range.
    StrictInstant,
}

impl Matching {
    /// The matching of an instance that is (or is not) an explicit zero-length one.
    const fn of(strict_instant: bool) -> Self {
        if strict_instant {
            Self::StrictInstant
        } else {
            Self::Overlap
        }
    }
}

/// One concrete instance of a component.
#[derive(Debug, Clone)]
pub(crate) struct Occurrence {
    /// Index of the component in the children of the `VCALENDAR` that this instance comes from.
    pub(crate) component: usize,
    /// The identity of the instance: its `RECURRENCE-ID` value.
    pub(crate) recurrence_id: Moment,
    /// The start of the instance.
    pub(crate) start: DateTime<Utc>,
    /// The end of the instance (equal to the start for zero-length instances).
    pub(crate) end: DateTime<Utc>,
    /// Whether the instance comes from an override component.
    pub(crate) is_override: bool,
    /// Whether the instance is an all-day instance.
    pub(crate) all_day: bool,
    /// Whether the instants are only known up to the unknown offset of a floating value.
    pub(crate) floating: bool,
    /// How the instance is matched against a time range.
    pub(crate) matching: Matching,
    /// To-do facts, for `VTODO` instances.
    pub(crate) todo: Option<TodoTimes>,
}

impl Occurrence {
    /// Whether the instance matches the time range (RFC 4791 section 9.9).
    pub(crate) fn overlaps(&self, range: &TimeRange) -> bool {
        match &self.todo {
            Some(todo) => todo.matches(range),
            None if self.matching == Matching::StrictInstant => {
                range.start.is_none_or(|from| from < self.start) && range.end.is_none_or(|until| until > self.start)
            }
            None => range.overlaps(self.start, self.end),
        }
    }

    /// The start as the public instance reports it: for to-dos the representative date.
    pub(crate) fn effective_start(&self) -> DateTime<Utc> {
        self.todo.as_ref().and_then(TodoTimes::start).unwrap_or(self.start)
    }

    /// The end as the public instance reports it.
    pub(crate) fn effective_end(&self) -> DateTime<Utc> {
        self.todo.as_ref().and_then(TodoTimes::end).unwrap_or(self.end)
    }

    /// Whether the occurrence carries any time information (undated to-dos have none).
    pub(crate) fn is_dated(&self) -> bool {
        self.todo.as_ref().is_none_or(|todo| todo.start().is_some())
    }
}

/// How long one instance lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extent {
    /// No length: an instant.
    Zero,
    /// An exact number of seconds (`DTEND` minus `DTSTART` of timed values).
    Exact(i64),
    /// A `DURATION`: calendar days on the wall clock plus exact seconds.
    Length(Length),
    /// A number of days on the wall clock (all-day values).
    Days(i64),
}

impl Extent {
    /// Whether the extent is a timed `DTEND` that equals `DTSTART` (as opposed to no end or a zero `DURATION`).
    /// A date-valued `DTEND` that equals `DTSTART` is not an instant: [`extent_of`] reads it as one day.
    const fn is_explicit_instant(self) -> bool {
        matches!(self, Self::Exact(0))
    }

    fn end(self, zone: &Zone, local: NaiveDateTime, start: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Self::Zero => Some(start),
            Self::Exact(seconds) => start.checked_add_signed(TimeDelta::try_seconds(seconds)?),
            Self::Days(days) => zone.local_to_utc(local.checked_add_signed(TimeDelta::try_days(days)?)?),
            Self::Length(length) => {
                let moved = zone.local_to_utc(local.checked_add_signed(TimeDelta::try_days(length.days)?)?)?;
                moved.checked_add_signed(TimeDelta::try_seconds(length.seconds)?)
            }
        }
    }
}

/// A calendar component with its index among the children of the `VCALENDAR`.
#[derive(Clone, Copy)]
struct Comp<'a> {
    index: usize,
    node: &'a Node,
    kind: ComponentKind,
}

/// The part of a component that drives expansion.
struct Series<'a> {
    comp: Comp<'a>,
    start: Option<Moment>,
    extent: Extent,
    has_own_extent: bool,
}

/// A series that has a start: the zone and the start value everything else is derived from.
struct Base<'a, 'b> {
    series: &'b Series<'a>,
    start: &'b Moment,
    zone: Zone,
}

/// An override component with the facts expansion needs.
struct OverrideInfo<'a> {
    series: Series<'a>,
    rid: Moment,
    this_and_future: bool,
}

fn out_of_range() -> IcalError {
    IcalError::invalid("a date is out of range")
}

pub(crate) fn start_moment(node: &Node) -> Result<Option<Moment>, IcalError> {
    if let Some(entry) = node.first(&Prop::Dtstart) {
        return entry_moment(entry)
            .map(Some)
            .ok_or_else(|| IcalError::invalid("DTSTART is not a valid date or date-time"));
    }
    if node.kind == Kind::VTodo
        && let Some(entry) = node.first(&Prop::Due)
    {
        // A to-do may be dated by its due date only.
        return entry_moment(entry)
            .map(Some)
            .ok_or_else(|| IcalError::invalid("DUE is not a valid date or date-time"));
    }
    Ok(None)
}

fn extent_of(node: &Node, start: &Moment, zones: &Zones) -> Result<(Extent, bool), IcalError> {
    let end_property = if node.kind == Kind::VTodo {
        Prop::Due
    } else {
        Prop::Dtend
    };
    let dated_by_start = node.has(&Prop::Dtstart) || node.kind != Kind::VTodo;
    if dated_by_start && let Some(entry) = node.first(&end_property) {
        let end = entry_moment(entry).ok_or_else(|| IcalError::invalid("DTEND is not a valid date or date-time"))?;
        let extent = if start.is_date() && end.is_date() {
            // `DTEND` equal to `DTSTART` on dates would be an instant at midnight that a query for the day (which
            // starts at midnight) never finds; clients mean the day, as for an all-day event without an end.
            Extent::Days(end.date().signed_duration_since(start.date()).num_days().max(1))
        } else {
            let from = zones.to_utc(start).ok_or_else(out_of_range)?;
            let to = zones.to_utc(&end).ok_or_else(out_of_range)?;
            Extent::Exact(to.signed_duration_since(from).num_seconds())
        };
        return Ok((extent, true));
    }
    if let Some(entry) = node.first(&Prop::Duration) {
        let duration = entry_duration(entry).ok_or_else(|| IcalError::invalid("DURATION is not a valid duration"))?;
        return Ok((Extent::Length(Length::from_duration(&duration)), true));
    }
    let default = if start.is_date() { Extent::Days(1) } else { Extent::Zero };
    Ok((default, false))
}

impl<'a> Series<'a> {
    fn of(comp: Comp<'a>, zones: &Zones) -> Result<Self, IcalError> {
        let start = start_moment(comp.node)?;
        let (extent, has_own_extent) = match &start {
            Some(start) => extent_of(comp.node, start, zones)?,
            None => (Extent::Zero, false),
        };
        Ok(Self {
            comp,
            start,
            extent,
            has_own_extent,
        })
    }

    fn is_all_day(&self) -> bool {
        self.start.as_ref().is_some_and(Moment::is_date)
    }

    fn rule(&self) -> Option<&'a ICalendarRecurrenceRule> {
        match self.comp.node.first(&Prop::Rrule)?.values.first()? {
            ICalendarValue::RecurrenceRule(rule) => Some(rule),
            _ => None,
        }
    }

    fn base<'b>(&'b self, zones: &Zones) -> Option<Base<'a, 'b>> {
        let start = self.start.as_ref()?;
        Some(Base {
            series: self,
            start,
            zone: zones.zone_of(start).clone(),
        })
    }
}

impl<'a> OverrideInfo<'a> {
    fn of(comp: Comp<'a>, zones: &Zones) -> Result<Self, IcalError> {
        let entry = comp
            .node
            .first(&Prop::RecurrenceId)
            .ok_or_else(|| IcalError::invalid("RECURRENCE-ID is missing"))?;
        let rid =
            entry_moment(entry).ok_or_else(|| IcalError::invalid("RECURRENCE-ID is not a valid date or date-time"))?;
        Ok(Self {
            series: Series::of(comp, zones)?,
            rid,
            // The parser keeps `RANGE` only for the value `THISANDFUTURE`.
            this_and_future: has_param(entry, &Param::Range),
        })
    }
}

/// A generated instance of a series before overrides are applied.
#[derive(Debug, Clone)]
struct Candidate {
    local: NaiveDateTime,
    /// An explicit end (`RDATE` periods).
    end: Option<DateTime<Utc>>,
}

fn key_of(moment: &Moment, zones: &Zones, all_day: bool) -> Option<RidKey> {
    if all_day || moment.is_date() {
        Some(RidKey::Date(moment.date()))
    } else {
        zones.to_utc(moment).map(RidKey::Instant)
    }
}

fn key_hits(key: RidKey, instant: DateTime<Utc>, local: NaiveDateTime, all_day: bool) -> bool {
    match key {
        RidKey::Date(date) => local.date() == date,
        RidKey::Instant(at) => !all_day && at == instant,
    }
}

/// Whether a set of exclusion keys contains the instance.
fn excluded(keys: &HashSet<RidKey>, instant: DateTime<Utc>, local: NaiveDateTime, all_day: bool) -> bool {
    if all_day {
        keys.contains(&RidKey::Date(local.date()))
    } else {
        keys.contains(&RidKey::Instant(instant)) || keys.contains(&RidKey::Date(local.date()))
    }
}

/// Whether a value is only meaningful relative to an unknown zone.
fn is_floating(moment: &Moment) -> bool {
    matches!(moment, Moment::Date(_) | Moment::Floating(_))
}

/// Everything expansion needs besides the calendar.
pub(crate) struct Engine<'a> {
    pub(crate) zones: &'a Zones,
    limits: &'a IcalLimits,
    budget: Budget,
    steps: usize,
    enforce_instances: bool,
}

/// Hands an instance to the sink when it overlaps the range.
fn emit(range: &TimeRange, occurrence: Occurrence, sink: &mut Sink<'_>) -> Result<Flow, IcalError> {
    if occurrence.overlaps(range) {
        sink(occurrence)
    } else {
        Ok(Flow::Continue)
    }
}

impl<'a> Engine<'a> {
    pub(crate) fn new(zones: &'a Zones, limits: &'a IcalLimits, budget: Budget) -> Self {
        Self {
            zones,
            limits,
            budget,
            steps: usize::try_from(limits.max_iterator_steps).unwrap_or(usize::MAX),
            enforce_instances: true,
        }
    }

    /// Lifts the limit on the number of instances that [`Engine::expand`] collects. Matching, free-busy and
    /// indexing only ask whether an instance exists or fold over all of them, so a long series is no reason to
    /// fail; the step budget and the time budget still apply.
    pub(crate) const fn without_instance_limit(mut self) -> Self {
        self.enforce_instances = false;
        self
    }

    /// Continues with the steps a previous engine has left, so that one budget covers several objects.
    pub(crate) const fn with_steps(mut self, steps: usize) -> Self {
        self.steps = steps;
        self
    }

    /// The generator steps left in the budget.
    pub(crate) const fn steps_left(&self) -> usize {
        self.steps
    }

    /// The instant after which no instance can overlap the range: generation stops there. It never lies beyond
    /// the latest date the server accepts (`max_year`), so that the cost of a read cannot exceed the dry run
    /// of the write that stored the object.
    fn horizon(&self, range: &TimeRange) -> Option<DateTime<Utc>> {
        let wanted = range.end.or_else(|| {
            let start = range.start?;
            let date = add_years(start.date_naive(), self.limits.max_time_range_years);
            Some(date.and_time(start.time()).and_utc())
        });
        match (wanted, self.limits.max_date_time()) {
            (Some(wanted), Some(ceiling)) => Some(wanted.min(ceiling)),
            (None, ceiling) => ceiling,
            (wanted, None) => wanted,
        }
    }

    /// Expands the whole object, keeping the instances that match `range`, ordered by start. With the instance
    /// limit in force (the default) more than `max_instances` matching instances are an error, raised as soon
    /// as the limit is passed.
    pub(crate) fn expand(&mut self, root: &Node, range: &TimeRange) -> Result<Vec<Occurrence>, IcalError> {
        let limit = usize::try_from(self.limits.max_instances).unwrap_or(usize::MAX);
        let enforce = self.enforce_instances;
        let mut kept: Vec<Occurrence> = Vec::new();
        self.visit(root, range, &mut |occurrence| {
            kept.push(occurrence);
            if enforce && kept.len() > limit {
                return Err(IcalError::Limit(LimitKind::Instances));
            }
            Ok(Flow::Continue)
        })?;
        kept.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| a.recurrence_id.local().cmp(&b.recurrence_id.local()))
                .then_with(|| a.component.cmp(&b.component))
        });
        Ok(kept)
    }

    /// Walks the instances of the whole object that overlap `range` in no particular order and hands each to
    /// `sink`, which may end the walk. Nothing is collected here and the instance limit does not apply: the
    /// caller decides what it keeps.
    pub(crate) fn visit(&mut self, root: &Node, range: &TimeRange, sink: &mut Sink<'_>) -> Result<(), IcalError> {
        let horizon = self.horizon(range);
        let components: Vec<Comp<'_>> = root
            .children
            .iter()
            .enumerate()
            .filter_map(|(index, node)| node.component_kind().map(|kind| Comp { index, node, kind }))
            .collect();
        for master in components.iter().filter(|comp| !comp.node.is_override()) {
            let uid = master.node.uid();
            let overrides: Vec<Comp<'_>> = components
                .iter()
                .filter(|comp| comp.node.is_override() && comp.node.uid() == uid)
                .copied()
                .collect();
            if self.series_occurrences(*master, &overrides, horizon, range, sink)? == Flow::Stop {
                return Ok(());
            }
            self.budget.check()?;
        }
        // Overrides without a master of the same UID stand on their own.
        for comp in components.iter().filter(|comp| comp.node.is_override()) {
            let has_master = components
                .iter()
                .any(|other| !other.node.is_override() && other.node.uid() == comp.node.uid());
            if !has_master {
                let info = OverrideInfo::of(*comp, self.zones)?;
                if let Some(occurrence) = self.override_occurrence(&info, None)?
                    && emit(range, occurrence, sink)? == Flow::Stop
                {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Whether any instance overlaps `range`.
    pub(crate) fn any(&mut self, root: &Node, range: &TimeRange) -> Result<bool, IcalError> {
        let mut found = false;
        self.visit(root, range, &mut |_| {
            found = true;
            Ok(Flow::Stop)
        })?;
        Ok(found)
    }

    fn series_occurrences(
        &mut self,
        master: Comp<'_>,
        overrides: &[Comp<'_>],
        horizon: Option<DateTime<Utc>>,
        range: &TimeRange,
        sink: &mut Sink<'_>,
    ) -> Result<Flow, IcalError> {
        let series = Series::of(master, self.zones)?;
        let all_day = series.is_all_day();
        let base = series.base(self.zones);
        let mut candidates = match &base {
            Some(base) => self.candidates(base, horizon)?,
            None => BTreeMap::new(),
        };
        let mut excluded_keys: HashSet<RidKey> = HashSet::new();
        for entry in master.node.all(&Prop::Exdate) {
            let (moments, _) = entry_moments(entry);
            excluded_keys.extend(moments.iter().filter_map(|moment| key_of(moment, self.zones, all_day)));
        }
        candidates.retain(|instant, candidate| !excluded(&excluded_keys, *instant, candidate.local, all_day));

        let mut infos = Vec::with_capacity(overrides.len());
        for comp in overrides {
            infos.push(OverrideInfo::of(*comp, self.zones)?);
        }
        let mut reshapes: Vec<(DateTime<Utc>, TimeDelta, usize)> = Vec::new();
        for (position, info) in infos.iter().enumerate() {
            if let Some(key) = key_of(&info.rid, self.zones, all_day) {
                candidates.retain(|instant, candidate| !key_hits(key, *instant, candidate.local, all_day));
            }
            if info.this_and_future
                && let (Some(at), Some(own)) = (
                    self.zones.to_utc(&info.rid),
                    info.series.start.as_ref().and_then(|start| self.zones.to_utc(start)),
                )
            {
                reshapes.push((at, own.signed_duration_since(at), position));
            }
            if let Some(occurrence) = self.override_occurrence(info, Some(&series))?
                && emit(range, occurrence, sink)? == Flow::Stop
            {
                return Ok(Flow::Stop);
            }
        }
        reshapes.sort_by_key(|(at, _, _)| *at);
        if let Some(base) = &base {
            for (count, (instant, candidate)) in candidates.into_iter().enumerate() {
                if count % BUDGET_CHECK_INTERVAL == 0 {
                    self.budget.check()?;
                }
                let reshape = reshapes.iter().rev().find(|(at, _, _)| *at < instant);
                let occurrence =
                    match reshape.and_then(|(_, shift, position)| infos.get(*position).map(|info| (*shift, info))) {
                        Some((shift, info)) => self.reshaped(base, info, shift, instant, &candidate)?,
                        None => self.plain(base, instant, &candidate)?,
                    };
                if emit(range, occurrence, sink)? == Flow::Stop {
                    return Ok(Flow::Stop);
                }
            }
        }
        Ok(Flow::Continue)
    }

    /// The instances of the recurrence set before exclusions and overrides.
    fn candidates(
        &mut self,
        base: &Base<'_, '_>,
        horizon: Option<DateTime<Utc>>,
    ) -> Result<BTreeMap<DateTime<Utc>, Candidate>, IcalError> {
        let mut found: BTreeMap<DateTime<Utc>, Candidate> = BTreeMap::new();
        let first = self.zones.to_utc(base.start).ok_or_else(out_of_range)?;
        found.insert(
            first,
            Candidate {
                local: base.start.local(),
                end: None,
            },
        );
        self.add_rdates(base, &mut found);
        if let Some(rule) = base.series.rule() {
            self.add_rule(base, rule, horizon, &mut found)?;
        }
        Ok(found)
    }

    fn add_rdates(&self, base: &Base<'_, '_>, found: &mut BTreeMap<DateTime<Utc>, Candidate>) {
        for entry in base.series.comp.node.all(&Prop::Rdate) {
            let (moments, _) = entry_moments(entry);
            for moment in moments {
                if let Some(instant) = self.zones.to_utc(&moment) {
                    found.entry(instant).or_insert(Candidate {
                        local: base.zone.utc_to_local(instant),
                        end: None,
                    });
                }
            }
            for period in entry_periods(entry) {
                let Some(instant) = self.zones.to_utc(&period.start) else {
                    continue;
                };
                let local = base.zone.utc_to_local(instant);
                let end = match &period.end {
                    PeriodEnd::At(end) => self.zones.to_utc(end),
                    PeriodEnd::Length(length) => {
                        Extent::Length(Length::from_duration(length)).end(&base.zone, local, instant)
                    }
                };
                found.insert(instant, Candidate { local, end });
            }
        }
    }

    fn add_rule(
        &mut self,
        base: &Base<'_, '_>,
        rule: &ICalendarRecurrenceRule,
        horizon: Option<DateTime<Utc>>,
        found: &mut BTreeMap<DateTime<Utc>, Candidate>,
    ) -> Result<(), IcalError> {
        if is_sub_hourly(rule) {
            return Err(IcalError::Limit(LimitKind::SubDailyFrequency));
        }
        let horizon_local = horizon.map(|at| base.zone.utc_to_local(at));
        let bound = match (rule_until_local(rule, &base.zone), horizon_local) {
            (Some(until), Some(limit)) => Some(until.min(limit)),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        };
        if bound.is_none() && is_unbounded(rule) {
            return Err(IcalError::Limit(LimitKind::IteratorSteps));
        }
        let generated =
            rule_locals(rule, base.start.local(), base.series.is_all_day(), bound, self.steps).map_err(|error| {
                let RuleError::Invalid(message) = error;
                IcalError::Invalid(message)
            })?;
        if generated.truncated {
            return Err(IcalError::Limit(LimitKind::IteratorSteps));
        }
        self.steps = self.steps.saturating_sub(generated.dates.len());
        self.budget.check()?;
        for local in generated.dates {
            if let Some(instant) = base.zone.local_to_utc(local) {
                found.entry(instant).or_insert(Candidate { local, end: None });
            }
        }
        Ok(())
    }

    fn plain(
        &self,
        base: &Base<'_, '_>,
        instant: DateTime<Utc>,
        candidate: &Candidate,
    ) -> Result<Occurrence, IcalError> {
        let end = match candidate.end {
            Some(end) => end,
            None => base
                .series
                .extent
                .end(&base.zone, candidate.local, instant)
                .ok_or_else(out_of_range)?,
        };
        Ok(Occurrence {
            component: base.series.comp.index,
            recurrence_id: base.start.with_local(candidate.local),
            start: instant,
            end,
            is_override: false,
            all_day: base.series.is_all_day(),
            floating: is_floating(base.start),
            matching: Matching::of(
                candidate.end.is_none() && base.series.extent.is_explicit_instant() && end == instant,
            ),
            todo: self.todo_times(&base.series.comp, instant, end),
        })
    }

    /// An instance reshaped by an earlier override with `RANGE=THISANDFUTURE`: it moves by the same amount the
    /// override moved its own instance and takes the override's length.
    fn reshaped(
        &self,
        base: &Base<'_, '_>,
        info: &OverrideInfo<'_>,
        shift: TimeDelta,
        instant: DateTime<Utc>,
        candidate: &Candidate,
    ) -> Result<Occurrence, IcalError> {
        let moved = instant.checked_add_signed(shift).ok_or_else(out_of_range)?;
        let local = base.zone.utc_to_local(moved);
        let extent = if info.series.has_own_extent {
            info.series.extent
        } else {
            base.series.extent
        };
        let end = extent.end(&base.zone, local, moved).ok_or_else(out_of_range)?;
        Ok(Occurrence {
            component: info.series.comp.index,
            recurrence_id: base.start.with_local(candidate.local),
            start: moved,
            end,
            is_override: true,
            all_day: info.series.is_all_day(),
            floating: is_floating(base.start),
            matching: Matching::of(extent.is_explicit_instant() && end == moved),
            todo: self.todo_times(&info.series.comp, moved, end),
        })
    }

    fn override_occurrence(
        &self,
        info: &OverrideInfo<'_>,
        master: Option<&Series<'_>>,
    ) -> Result<Option<Occurrence>, IcalError> {
        let own = &info.series;
        let start = own.start.clone().unwrap_or_else(|| info.rid.clone());
        let zone = self.zones.zone_of(&start);
        let instant = self.zones.to_utc(&start).ok_or_else(out_of_range)?;
        let extent = match master {
            Some(master) if !own.has_own_extent && master.start.is_some() => master.extent,
            _ => own.extent,
        };
        let end = extent.end(zone, start.local(), instant).ok_or_else(out_of_range)?;
        Ok(Some(Occurrence {
            component: own.comp.index,
            recurrence_id: info.rid.clone(),
            start: instant,
            end,
            is_override: true,
            all_day: start.is_date(),
            floating: is_floating(&start),
            matching: Matching::of(extent.is_explicit_instant() && end == instant),
            todo: self.todo_times(&own.comp, instant, end),
        }))
    }

    fn todo_times(&self, comp: &Comp<'_>, start: DateTime<Utc>, end: DateTime<Utc>) -> Option<TodoTimes> {
        if comp.kind != ComponentKind::Todo {
            return None;
        }
        let node = comp.node;
        let has_start = node.has(&Prop::Dtstart);
        let instant_of = |property: &Prop| {
            node.first(property)
                .and_then(entry_moment)
                .and_then(|moment| self.zones.to_utc(&moment))
        };
        Some(TodoTimes {
            dtstart: has_start.then_some(start),
            due: node.has(&Prop::Due).then_some(if has_start { end } else { start }),
            duration_end: (has_start && node.has(&Prop::Duration)).then_some(end),
            completed: instant_of(&Prop::Completed),
            created: instant_of(&Prop::Created),
        })
    }
}

#[cfg(test)]
mod tests {
    use calcard::{Entry, Parser};
    use chrono::TimeZone;

    use super::*;

    fn tree(text: &str) -> Node {
        let mut parser = Parser::new(text);
        let Entry::ICalendar(calendar) = parser.entry() else {
            panic!("not a calendar");
        };
        Node::from_calendar(&calendar).unwrap()
    }

    fn at(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, 0).unwrap()
    }

    fn expand_with(text: &str, range: &TimeRange, limits: &IcalLimits) -> Result<Vec<Occurrence>, IcalError> {
        let root = tree(text);
        let zones = Zones::for_tree(&root, Zone::utc());
        let mut engine = Engine::new(&zones, limits, Budget::new(limits));
        engine.expand(&root, range)
    }

    fn expand(text: &str, range: &TimeRange) -> Result<Vec<Occurrence>, IcalError> {
        expand_with(text, range, &IcalLimits::default())
    }

    fn event(body: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:u\r\n{body}END:VEVENT\r\nEND:VCALENDAR\r\n")
    }

    fn window(start: DateTime<Utc>, end: DateTime<Utc>) -> TimeRange {
        TimeRange::new(Some(start), Some(end))
    }

    #[test]
    fn a_single_event_is_one_occurrence() {
        let text = event("DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n");
        let found = expand(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 2, 0, 0))).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].start, at(2027, 3, 1, 10, 0));
        assert_eq!(found[0].end, at(2027, 3, 1, 11, 0));
        assert!(!found[0].is_override);
        let none = expand(&text, &window(at(2027, 3, 1, 11, 0), at(2027, 3, 2, 0, 0))).unwrap();
        assert!(none.is_empty(), "the end is exclusive");
    }

    #[test]
    fn weekly_series_with_exdate_skip_the_excluded_week() {
        let text = event(
            "DTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T110000\r\n\
             RRULE:FREQ=WEEKLY;COUNT=4\r\nEXDATE;TZID=Europe/Berlin:20270308T100000\r\n",
        );
        let found = expand(&text, &window(at(2027, 1, 1, 0, 0), at(2027, 12, 31, 0, 0))).unwrap();
        let starts: Vec<DateTime<Utc>> = found.iter().map(|o| o.start).collect();
        assert_eq!(
            starts,
            vec![at(2027, 3, 1, 9, 0), at(2027, 3, 15, 9, 0), at(2027, 3, 22, 9, 0)]
        );
    }

    const WITH_OVERRIDE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
        BEGIN:VEVENT\r\nUID:u\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:master\r\nEND:VEVENT\r\n\
        BEGIN:VEVENT\r\nUID:u\r\nRECURRENCE-ID:20270302T100000Z\r\nDTSTART:20270302T150000Z\r\nDTEND:20270302T160000Z\r\nSUMMARY:moved\r\nEND:VEVENT\r\n\
        END:VCALENDAR\r\n";

    #[test]
    fn an_override_replaces_the_instance_it_names() {
        let found = expand(WITH_OVERRIDE, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 10, 0, 0))).unwrap();
        let summary: Vec<(DateTime<Utc>, bool)> = found.iter().map(|o| (o.start, o.is_override)).collect();
        assert_eq!(
            summary,
            vec![
                (at(2027, 3, 1, 10, 0), false),
                (at(2027, 3, 2, 15, 0), true),
                (at(2027, 3, 3, 10, 0), false),
            ],
            "the master instance of March 2nd must not appear next to its override"
        );
    }

    #[test]
    fn an_override_that_leaves_the_window_still_removes_its_instance() {
        let text = WITH_OVERRIDE
            .replace("DTSTART:20270302T150000Z", "DTSTART:20270402T150000Z")
            .replace("DTEND:20270302T160000Z", "DTEND:20270402T160000Z");
        let found = expand(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 10, 0, 0))).unwrap();
        assert_eq!(found.len(), 2);
        let moved = expand(&text, &window(at(2027, 4, 1, 0, 0), at(2027, 4, 10, 0, 0))).unwrap();
        assert_eq!(moved.len(), 1);
        assert!(moved[0].is_override);
    }

    #[test]
    fn an_override_without_a_matching_instance_stands_on_its_own() {
        let text = WITH_OVERRIDE.replace("RECURRENCE-ID:20270302T100000Z", "RECURRENCE-ID:20270302T123000Z");
        let found = expand(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 10, 0, 0))).unwrap();
        assert_eq!(found.len(), 4);
    }

    #[test]
    fn this_and_future_overrides_reshape_later_instances() {
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
            BEGIN:VEVENT\r\nUID:u\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT=4\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:u\r\nRECURRENCE-ID;RANGE=THISANDFUTURE:20270302T100000Z\r\nDTSTART:20270302T120000Z\r\nDTEND:20270302T140000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let found = expand(text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 10, 0, 0))).unwrap();
        let shape: Vec<(DateTime<Utc>, DateTime<Utc>)> = found.iter().map(|o| (o.start, o.end)).collect();
        assert_eq!(
            shape,
            vec![
                (at(2027, 3, 1, 10, 0), at(2027, 3, 1, 11, 0)),
                (at(2027, 3, 2, 12, 0), at(2027, 3, 2, 14, 0)),
                (at(2027, 3, 3, 12, 0), at(2027, 3, 3, 14, 0)),
                (at(2027, 3, 4, 12, 0), at(2027, 3, 4, 14, 0)),
            ]
        );
    }

    #[test]
    fn a_this_and_future_override_without_a_length_of_its_own_keeps_the_length_of_the_series() {
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
            BEGIN:VEVENT\r\nUID:u\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:u\r\nRECURRENCE-ID;RANGE=THISANDFUTURE:20270302T100000Z\r\nDTSTART:20270302T120000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let found = expand(text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 10, 0, 0))).unwrap();
        let shape: Vec<(DateTime<Utc>, DateTime<Utc>, bool)> =
            found.iter().map(|o| (o.start, o.end, o.is_override)).collect();
        assert_eq!(
            shape,
            vec![
                (at(2027, 3, 1, 10, 0), at(2027, 3, 1, 11, 0), false),
                (at(2027, 3, 2, 12, 0), at(2027, 3, 2, 13, 0), true),
                (at(2027, 3, 3, 12, 0), at(2027, 3, 3, 13, 0), true),
            ]
        );
    }

    #[test]
    fn an_override_without_a_master_is_the_only_instance() {
        // What an attendee invited to one instance of a series stores.
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
            BEGIN:VEVENT\r\nUID:u\r\nRECURRENCE-ID:20270302T100000Z\r\nDTSTART:20270302T150000Z\r\nDTEND:20270302T160000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let found = expand(text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 10, 0, 0))).unwrap();
        let shape: Vec<(DateTime<Utc>, DateTime<Utc>, bool)> =
            found.iter().map(|o| (o.start, o.end, o.is_override)).collect();
        assert_eq!(shape, vec![(at(2027, 3, 2, 15, 0), at(2027, 3, 2, 16, 0), true)]);
        let elsewhere = expand(text, &window(at(2027, 3, 2, 10, 0), at(2027, 3, 2, 11, 0))).unwrap();
        assert!(elsewhere.is_empty(), "the instance is where the override puts it");
    }

    #[test]
    fn an_all_day_series_excludes_by_date() {
        let text = event("DTSTART;VALUE=DATE:20270301\r\nRRULE:FREQ=DAILY;COUNT=3\r\nEXDATE;VALUE=DATE:20270302\r\n");
        let found = expand(&text, &window(at(2027, 2, 1, 0, 0), at(2027, 4, 1, 0, 0))).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|o| o.all_day));
        assert_eq!(found[0].end.signed_duration_since(found[0].start), TimeDelta::days(1));
    }

    #[test]
    fn rdates_and_periods_add_instances() {
        let text = event(
            "DTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\nRDATE:20270305T100000Z\r\n\
             RDATE;VALUE=PERIOD:20270307T100000Z/20270307T130000Z\r\n",
        );
        let found = expand(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 10, 0, 0))).unwrap();
        let shape: Vec<(DateTime<Utc>, DateTime<Utc>)> = found.iter().map(|o| (o.start, o.end)).collect();
        assert_eq!(
            shape,
            vec![
                (at(2027, 3, 1, 10, 0), at(2027, 3, 1, 11, 0)),
                (at(2027, 3, 5, 10, 0), at(2027, 3, 5, 11, 0)),
                (at(2027, 3, 7, 10, 0), at(2027, 3, 7, 13, 0)),
            ]
        );
    }

    #[test]
    fn instances_across_a_dst_change_keep_the_wall_clock_time() {
        let text = event(
            "DTSTART;TZID=Europe/Berlin:20270327T100000\r\nDTEND;TZID=Europe/Berlin:20270327T110000\r\nRRULE:FREQ=DAILY;COUNT=3\r\n",
        );
        let found = expand(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 4, 1, 0, 0))).unwrap();
        let starts: Vec<DateTime<Utc>> = found.iter().map(|o| o.start).collect();
        // 10:00 CET (09:00Z) on the 27th, 10:00 CEST (08:00Z) from the 28th on.
        assert_eq!(
            starts,
            vec![at(2027, 3, 27, 9, 0), at(2027, 3, 28, 8, 0), at(2027, 3, 29, 8, 0)]
        );
    }

    #[test]
    fn the_unbounded_rule_is_cut_at_the_window_and_the_step_budget_applies() {
        let text = event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=DAILY\r\n");
        let found = expand(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 8, 0, 0))).unwrap();
        assert_eq!(found.len(), 7);
        let tight = IcalLimits {
            max_iterator_steps: 5,
            ..IcalLimits::default()
        };
        let result = expand_with(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 8, 0, 0)), &tight);
        assert!(matches!(result, Err(IcalError::Limit(LimitKind::IteratorSteps))));
    }

    #[test]
    fn too_many_instances_in_the_window_are_an_error() {
        let text = event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=DAILY\r\n");
        let limits = IcalLimits {
            max_instances: 10,
            ..IcalLimits::default()
        };
        let result = expand_with(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 4, 1, 0, 0)), &limits);
        assert!(matches!(result, Err(IcalError::Limit(LimitKind::Instances))));
    }

    #[test]
    fn sub_hourly_rules_are_rejected() {
        let text = event("DTSTART:20270301T100000Z\r\nRRULE:FREQ=MINUTELY;COUNT=5\r\n");
        let result = expand(&text, &window(at(2027, 3, 1, 0, 0), at(2027, 3, 2, 0, 0)));
        assert!(matches!(result, Err(IcalError::Limit(LimitKind::SubDailyFrequency))));
    }

    #[test]
    fn todos_follow_the_rfc_table() {
        let todo =
            |body: &str| format!("BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t\r\n{body}END:VTODO\r\nEND:VCALENDAR\r\n");
        let range = window(at(2027, 3, 1, 0, 0), at(2027, 3, 2, 0, 0));
        // DTSTART and DUE: matches when the range overlaps the span.
        let inside = expand(&todo("DTSTART:20270301T100000Z\r\nDUE:20270301T120000Z\r\n"), &range).unwrap();
        assert_eq!(inside.len(), 1);
        assert_eq!(
            expand(&todo("DTSTART:20270305T100000Z\r\nDUE:20270305T120000Z\r\n"), &range)
                .unwrap()
                .len(),
            0
        );
        // A to-do without any date always matches.
        let undated = expand(&todo("SUMMARY:x\r\n"), &range).unwrap();
        assert!(undated.is_empty() || undated.iter().all(|o| !o.is_dated()));
        // DUE only: (start < DUE) AND (end >= DUE).
        assert_eq!(expand(&todo("DUE:20270301T120000Z\r\n"), &range).unwrap().len(), 1);
        assert!(
            expand(&todo("DUE:20270302T000000Z\r\n"), &range).unwrap().len() == 1,
            "end >= DUE"
        );
        assert!(
            expand(&todo("DUE:20270301T000000Z\r\n"), &range).unwrap().is_empty(),
            "start < DUE"
        );
    }
}
