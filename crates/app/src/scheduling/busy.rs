//! Busy time: what free-busy queries, resource answers and the search for free slots are made of.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, NaiveTime, Utc};
use davhaven_domain::{
    Calendar, CalendarId, CalendarKind, CalendarUserAddress, ComponentKind, Precondition, Principal, StoredObject,
    Tenant, TimeZoneName, Transparency, Uid,
};
use davhaven_ical::filter::TimeRange;
use davhaven_ical::freebusy::{BusyKind, BusyPeriod, Participation, busy_periods_for, busy_periods_in_zone};
use davhaven_ical::{ErrorContext, ParsedCalendar};
use davhaven_ports::{IndexFilter, PageReq, TimeRange as IndexRange, Tx};

use crate::authz::{Deadline, blocking};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::objects::zone_of;
use crate::principals::address_set;
use crate::wiring::AppCore;

/// The size of the pages read from the store.
const PAGE: u32 = 200;

/// A calendar whose events can make a person busy, and how they count.
#[derive(Debug, Clone)]
pub(crate) struct BusyCalendar {
    /// The calendar.
    pub(crate) calendar: Calendar,
    /// Whether the calendar is the person's time as a whole (the calendars they own and the managed calendars in
    /// their home) or only the events they take part in count (the calendars of groups and calendars shared with
    /// them: they are somebody else's calendar, and the meetings in it that name the person are the person's).
    pub(crate) whole: bool,
}

/// The calendars whose events make `principal` busy: every calendar they see (the ones in their home and those they
/// see through a group or an accepted share without having listed their home yet, because bindings are created
/// lazily, PLAN 2.9), except the ones they hid or marked transparent for scheduling (`schedule-calendar-transp`).
///
/// The calendars they own and the managed calendars count as a whole; in the calendar of a group or one that was
/// shared with them only the events they organize or attend count, and not the ones they declined. PLAN 2.8: a
/// person's free-busy says when *they* are busy, wherever their meetings are kept.
///
/// # Errors
///
/// Store failures.
pub(crate) async fn busy_calendars(tx: &mut dyn Tx, principal: &Principal) -> AppResult<Vec<BusyCalendar>> {
    let bound = tx.bindings().list_for(principal.id).await?;
    let mut calendars: Vec<Calendar> = bound
        .into_iter()
        .filter(|entry| !entry.binding.hidden && entry.binding.schedule_transp != Some(Transparency::Transparent))
        .map(|entry| entry.calendar)
        .collect();
    calendars.extend(tx.calendars().visible_without_binding(principal.id).await?);
    Ok(calendars
        .into_iter()
        .filter(|calendar| calendar.components.contains(&ComponentKind::Event))
        .map(|calendar| BusyCalendar {
            whole: calendar.owner_id == principal.id || calendar.kind == CalendarKind::Managed,
            calendar,
        })
        .collect())
}

/// The events of `calendar` that can make time busy inside `range`, without the event `except`.
///
/// # Errors
///
/// Store failures; `invalid` with `number-of-matches-within-limits` when more candidates than
/// `limits.dav.max_query_candidates` have to be read.
pub(crate) async fn candidates(
    core: &AppCore,
    tx: &mut dyn Tx,
    calendar: CalendarId,
    range: &TimeRange,
    except: Option<&Uid>,
) -> AppResult<Vec<StoredObject>> {
    let cap = usize::try_from(core.deps().limits.dav.max_query_candidates).unwrap_or(usize::MAX);
    let filter = IndexFilter {
        component: Some(ComponentKind::Event),
        time_range: Some(IndexRange {
            start: range.start,
            end: range.end,
        }),
        ..IndexFilter::all()
    };
    let mut found: Vec<StoredObject> = Vec::new();
    let mut page = PageReq::first(PAGE);
    loop {
        let batch = tx.objects().query(calendar, &filter, page).await?;
        found.extend(batch.items.into_iter().filter(|object| except != Some(&object.uid)));
        if found.len() > cap {
            return Err(AppError::invalid(SafeMessage::from_static(
                "The range holds too many events to compute free-busy.",
            ))
            .with_precondition(Precondition::NumberOfMatchesWithinLimits));
        }
        match batch.next {
            Some(after) => page = page.after(after),
            None => return Ok(found),
        }
    }
}

/// The events of one calendar that are read for busy time, and how they count.
#[derive(Debug, Clone)]
pub(crate) struct BusyGroup {
    /// The time zone floating times are read in: the one of the calendar.
    pub(crate) zone_ics: Option<String>,
    /// The candidate events.
    pub(crate) objects: Arc<Vec<StoredObject>>,
    /// `None` when every event counts (the free-busy of a collection). For the busy time of a person: whether only
    /// the events they take part in count; what they declined never does.
    pub(crate) participating_only: Option<bool>,
}

/// The busy periods of the events in `groups` (each group read in the floating zone of its calendar) inside `range`,
/// merged. `who` are the addresses of the person the periods are for (not used for groups that are not about a
/// person). Runs on a blocking thread under the wall-clock budget.
///
/// # Errors
///
/// The mapped errors of the iCalendar layer (`valid-filter` for a range that is too long).
pub(crate) async fn busy_of(
    core: &AppCore,
    groups: Vec<BusyGroup>,
    who: Vec<CalendarUserAddress>,
    range: TimeRange,
) -> AppResult<Vec<BusyPeriod>> {
    let deadline = Deadline::of(core);
    blocking(core, ErrorContext::Query, move |limits| {
        let mut periods: Vec<BusyPeriod> = Vec::new();
        for group in groups {
            deadline.check()?;
            let zone: TimeZoneName = zone_of(group.zone_ics.as_deref(), limits);
            let parsed: Vec<ParsedCalendar> = group
                .objects
                .iter()
                .map(|object| davhaven_ical::parse::parse(object.data.as_bytes(), limits))
                .collect::<Result<_, _>>()?;
            let refs: Vec<&ParsedCalendar> = parsed.iter().collect();
            periods.extend(match group.participating_only {
                Some(participating_only) => busy_periods_for(
                    &refs,
                    &range,
                    limits,
                    zone,
                    &Participation {
                        addresses: &who,
                        participating_only,
                    },
                )?,
                None => busy_periods_in_zone(&refs, &range, limits, zone)?,
            });
        }
        Ok(merge(periods))
    })
    .await
}

/// Sorts the periods and combines overlapping and adjacent ones of the same kind.
pub(crate) fn merge(mut periods: Vec<BusyPeriod>) -> Vec<BusyPeriod> {
    periods.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.start.cmp(&b.start)).then(a.end.cmp(&b.end)));
    let mut merged: Vec<BusyPeriod> = Vec::with_capacity(periods.len());
    for period in periods {
        match merged.last_mut() {
            Some(last) if last.kind == period.kind && period.start <= last.end => {
                last.end = last.end.max(period.end);
            }
            _ => merged.push(period),
        }
    }
    merged.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)).then(a.kind.cmp(&b.kind)));
    merged
}

/// The candidate events read from calendars so far, to be shared by the people of one request who see the same
/// calendar (the members of a group).
pub(crate) type Fetched = HashMap<CalendarId, Arc<Vec<StoredObject>>>;

/// The busy time of `principal` inside `range`: the events of their busy calendars, without the event `except`.
///
/// # Errors
///
/// Store failures and the errors of [`candidates`] and [`busy_of`].
pub(crate) async fn busy_of_principal(
    core: &AppCore,
    tx: &mut dyn Tx,
    tenant: &Tenant,
    principal: &Principal,
    range: TimeRange,
    except: Option<&Uid>,
) -> AppResult<Vec<BusyPeriod>> {
    busy_of_principal_cached(core, tx, tenant, principal, range, except, &mut Fetched::new()).await
}

/// [`busy_of_principal`] that reads the events of a calendar once for everybody who shares `fetched` (one request,
/// one `range`).
///
/// # Errors
///
/// As [`busy_of_principal`].
pub(crate) async fn busy_of_principal_cached(
    core: &AppCore,
    tx: &mut dyn Tx,
    tenant: &Tenant,
    principal: &Principal,
    range: TimeRange,
    except: Option<&Uid>,
    fetched: &mut Fetched,
) -> AppResult<Vec<BusyPeriod>> {
    let rows = tx.principals().addresses(principal.id).await?;
    let who = address_set(tenant, principal, &rows);
    let mut groups: Vec<BusyGroup> = Vec::new();
    for busy in busy_calendars(tx, principal).await? {
        let objects = if let Some(known) = fetched.get(&busy.calendar.id) {
            Arc::clone(known)
        } else {
            let read = Arc::new(candidates(core, tx, busy.calendar.id, &range, None).await?);
            fetched.insert(busy.calendar.id, Arc::clone(&read));
            read
        };
        let objects = match except {
            Some(uid) if objects.iter().any(|object| &object.uid == uid) => {
                Arc::new(objects.iter().filter(|object| &object.uid != uid).cloned().collect())
            }
            _ => objects,
        };
        if !objects.is_empty() {
            groups.push(BusyGroup {
                zone_ics: busy.calendar.timezone_ics.clone(),
                objects,
                participating_only: Some(!busy.whole),
            });
        }
    }
    busy_of(core, groups, who, range).await
}

/// The free slots of `duration` that lie in no busy period, inside the windows.
///
/// Slots start on a quarter of an hour (UTC) and follow each other without a gap inside one free stretch. At most
/// `limit + 1` slots are found; the caller cuts the list and reports the truncation.
pub(crate) fn free_slots(
    busy: &[BusyPeriod],
    windows: &[(DateTime<Utc>, DateTime<Utc>)],
    duration: Duration,
    limit: usize,
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let mut sorted: Vec<(DateTime<Utc>, DateTime<Utc>)> =
        busy.iter().map(|period| (period.start, period.end)).collect();
    sorted.sort();
    let mut slots: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    // The windows come in ascending order: what ended before a window starts is never looked at again.
    let mut first = 0_usize;
    for (window_start, window_end) in windows {
        while sorted.get(first).is_some_and(|(_, end)| end <= window_start) {
            first += 1;
        }
        let mut cursor = *window_start;
        let mut stretches: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
        for (start, end) in sorted.get(first..).unwrap_or_default() {
            if *end <= cursor {
                continue;
            }
            if *start >= *window_end {
                break;
            }
            if *start > cursor {
                stretches.push((cursor, *start));
            }
            cursor = cursor.max(*end);
            if cursor >= *window_end {
                break;
            }
        }
        if cursor < *window_end {
            stretches.push((cursor, *window_end));
        }
        for (from, until) in stretches {
            let mut at = round_up_to_quarter(from);
            while at + duration <= until {
                slots.push((at, at + duration));
                if slots.len() > limit {
                    return slots;
                }
                at += duration;
            }
        }
    }
    slots
}

/// The next full quarter of an hour at or after `at` (UTC).
fn round_up_to_quarter(at: DateTime<Utc>) -> DateTime<Utc> {
    const QUARTER: i64 = 15 * 60;
    let seconds = at.timestamp();
    let rounded = seconds.div_euclid(QUARTER) * QUARTER;
    let target = if rounded == seconds && at.timestamp_subsec_nanos() == 0 {
        rounded
    } else {
        rounded + QUARTER
    };
    DateTime::from_timestamp(target, 0).unwrap_or(at)
}

/// The working windows inside `range`: one per local day between `start` and `end` in `zone` (days on which the
/// window does not exist, or is empty, are skipped), clipped to the range. Without working hours the range itself
/// is the only window.
pub(crate) fn working_windows(
    range: (DateTime<Utc>, DateTime<Utc>),
    hours: Option<(NaiveTime, NaiveTime)>,
    zone: TimeZoneName,
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let Some((from, until)) = hours else {
        return vec![range];
    };
    if until <= from {
        return Vec::new();
    }
    let tz = zone.tz();
    let first = range.0.with_timezone(&tz).date_naive();
    let last = range.1.with_timezone(&tz).date_naive();
    let mut windows = Vec::new();
    let mut day = first.pred_opt().unwrap_or(first);
    while day <= last {
        let local = |time: NaiveTime| {
            use chrono::TimeZone as _;
            tz.from_local_datetime(&day.and_time(time))
                .earliest()
                .map(|at| at.with_timezone(&Utc))
        };
        if let (Some(start), Some(end)) = (local(from), local(until)) {
            let start = start.max(range.0);
            let end = end.min(range.1);
            if start < end {
                windows.push((start, end));
            }
        }
        match day.succ_opt() {
            Some(next) => day = next,
            None => break,
        }
    }
    windows
}

/// Groups the periods of several people into one list that is busy when any of them is.
pub(crate) fn union(lists: Vec<Vec<BusyPeriod>>) -> Vec<BusyPeriod> {
    merge(
        lists
            .into_iter()
            .flatten()
            .map(|period| BusyPeriod {
                kind: BusyKind::Busy,
                ..period
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 3, day, hour, minute, 0).unwrap()
    }

    fn busy(start: DateTime<Utc>, end: DateTime<Utc>, kind: BusyKind) -> BusyPeriod {
        BusyPeriod { start, end, kind }
    }

    #[test]
    fn merging_combines_overlapping_and_adjacent_periods_of_one_kind() {
        let merged = merge(vec![
            busy(at(1, 9, 0), at(1, 10, 0), BusyKind::Busy),
            busy(at(1, 10, 0), at(1, 11, 0), BusyKind::Busy),
            busy(at(1, 10, 30), at(1, 12, 0), BusyKind::Busy),
            busy(at(1, 9, 30), at(1, 9, 45), BusyKind::BusyTentative),
            busy(at(1, 14, 0), at(1, 15, 0), BusyKind::Busy),
        ]);
        assert_eq!(
            merged,
            vec![
                busy(at(1, 9, 0), at(1, 12, 0), BusyKind::Busy),
                busy(at(1, 9, 30), at(1, 9, 45), BusyKind::BusyTentative),
                busy(at(1, 14, 0), at(1, 15, 0), BusyKind::Busy),
            ]
        );
    }

    #[test]
    fn a_union_is_busy_when_anybody_is() {
        let union = union(vec![
            vec![busy(at(1, 9, 0), at(1, 10, 0), BusyKind::Busy)],
            vec![busy(at(1, 9, 30), at(1, 11, 0), BusyKind::BusyTentative)],
        ]);
        assert_eq!(union, vec![busy(at(1, 9, 0), at(1, 11, 0), BusyKind::Busy)]);
    }

    #[test]
    fn slots_fill_the_free_stretches_on_quarter_hours() {
        let periods = [busy(at(1, 9, 0), at(1, 10, 10), BusyKind::Busy)];
        let window = [(at(1, 8, 0), at(1, 12, 0))];
        let slots = free_slots(&periods, &window, Duration::minutes(30), 10);
        assert_eq!(
            slots,
            vec![
                (at(1, 8, 0), at(1, 8, 30)),
                (at(1, 8, 30), at(1, 9, 0)),
                (at(1, 10, 15), at(1, 10, 45)),
                (at(1, 10, 45), at(1, 11, 15)),
                (at(1, 11, 15), at(1, 11, 45)),
            ],
            "the stretch after the busy time starts at the next quarter and the rest of it is too short"
        );
    }

    #[test]
    fn the_search_stops_one_past_the_limit_and_skips_what_does_not_fit() {
        let window = [(at(1, 8, 0), at(1, 12, 0))];
        assert_eq!(
            free_slots(&[], &window, Duration::hours(1), 2).len(),
            3,
            "limit + 1 tells the caller to truncate"
        );
        let nothing: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
        assert_eq!(free_slots(&[], &window, Duration::hours(5), 2), nothing);
        let all_day = [busy(at(1, 0, 0), at(2, 0, 0), BusyKind::BusyUnavailable)];
        assert_eq!(free_slots(&all_day, &window, Duration::minutes(15), 5), nothing);
    }

    #[test]
    fn working_windows_follow_the_local_day_and_the_range() {
        let berlin = TimeZoneName::parse("Europe/Berlin").unwrap();
        let (from, until) = (
            NaiveTime::from_hms_opt(9, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(17, 0, 0).unwrap(),
        );
        let hours = Some((from, until));
        let windows = working_windows((at(1, 0, 0), at(3, 0, 0)), hours, berlin);
        // 2027-03-01 and -02 in Berlin (UTC+1): 08:00-16:00 UTC; the range ends before 2027-03-03.
        assert_eq!(windows, vec![(at(1, 8, 0), at(1, 16, 0)), (at(2, 8, 0), at(2, 16, 0))]);
        let clipped = working_windows((at(1, 12, 0), at(2, 10, 0)), hours, berlin);
        assert_eq!(clipped, vec![(at(1, 12, 0), at(1, 16, 0)), (at(2, 8, 0), at(2, 10, 0))]);
        assert_eq!(
            working_windows((at(1, 0, 0), at(2, 0, 0)), None, berlin),
            vec![(at(1, 0, 0), at(2, 0, 0))]
        );
        let backwards = working_windows((at(1, 0, 0), at(2, 0, 0)), Some((until, from)), berlin);
        assert_eq!(backwards, Vec::<(DateTime<Utc>, DateTime<Utc>)>::new());
    }

    #[test]
    fn rounding_goes_up_to_the_quarter() {
        assert_eq!(round_up_to_quarter(at(1, 9, 0)), at(1, 9, 0));
        assert_eq!(round_up_to_quarter(at(1, 9, 1)), at(1, 9, 15));
        assert_eq!(round_up_to_quarter(at(1, 9, 45)), at(1, 9, 45));
        assert_eq!(round_up_to_quarter(at(1, 9, 46)), at(1, 10, 0));
    }
}
