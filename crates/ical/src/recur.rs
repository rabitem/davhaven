//! Recurrence rule evaluation on the wall clock.
//!
//! `calcard` implements the RFC 5545 expansion table, but only behind `ICalendar::expand_dates`, which also
//! resolves time zones with quirks (an ambiguous or skipped local time silently becomes a floating one) and
//! counts instances rather than steps. This module uses it for what it does best, generating the local dates
//! of one rule from one start, and nothing else: every time zone decision, `EXDATE`, `RDATE` and override is
//! handled by this crate. The generated values are naive wall-clock times; the caller maps them to instants.

use calcard::common::IanaString;
use calcard::common::timezone::Tz as CalendarTz;
use calcard::datecalc::error::{RRuleError, ValidationError};
use calcard::datecalc::rrule::RRule;
use calcard::icalendar::dates::CalendarErrorType;
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarFrequency, ICalendarProperty,
    ICalendarRecurrenceRule,
};
use chrono::{NaiveDate, NaiveDateTime, TimeDelta, TimeZone};

use crate::calendar::{contain, partial_from_local};
use crate::zones::Zone;

/// The local dates of one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Generated {
    /// The occurrences in ascending order, without the start itself unless the rule produces it.
    pub(crate) dates: Vec<NaiveDateTime>,
    /// Whether more occurrences exist than `cap` allowed.
    pub(crate) truncated: bool,
}

/// Why a rule could not be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuleError {
    /// The rule breaks the syntax or consistency rules of RFC 5545; the text is safe for clients.
    Invalid(String),
}

fn invalid(message: &str) -> RuleError {
    RuleError::Invalid(message.to_owned())
}

/// The name of a `BY` part as the generator reports it, if it looks like one; anything else is not echoed.
fn part_name(name: &str) -> &str {
    let plain = !name.is_empty() && name.len() <= 16 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if plain { name } else { "a part" }
}

/// A client-safe description of a rule the generator rejected. The text comes from a fixed table: the generator's
/// own messages describe its internals and are never passed on.
fn describe(error: &RRuleError) -> String {
    let RRuleError::ValidationError(error) = error else {
        return "the recurrence rule cannot be evaluated".to_owned();
    };
    match error {
        ValidationError::BySetPosWithoutByRule => "BYSETPOS needs another BY part in the recurrence rule".to_owned(),
        ValidationError::InvalidFieldValue { field, .. }
        | ValidationError::InvalidFieldValueRange { field, .. }
        | ValidationError::InvalidFieldValueRangeWithFreq { field, .. } => {
            format!("{} has an invalid value in the recurrence rule", part_name(field))
        }
        ValidationError::InvalidByRuleAndFrequency { by_rule, freq } => format!(
            "{} cannot be used with FREQ={} in the recurrence rule",
            part_name(by_rule),
            freq.as_str()
        ),
        ValidationError::UntilBeforeStart { .. } => "UNTIL is before the start of the recurrence".to_owned(),
        ValidationError::TooBigInterval(_) => "INTERVAL of the recurrence rule is too large".to_owned(),
        ValidationError::StartYearOutOfRange(_) => "the start of the recurrence is out of range".to_owned(),
        ValidationError::InvalidByRuleWithByEaster => "BYEASTER cannot be combined with other BY parts".to_owned(),
        ValidationError::DtStartUntilMismatchTimezone { .. } => {
            "UNTIL and DTSTART of the recurrence disagree on the time zone".to_owned()
        }
        ValidationError::UnableToGenerateTimeset => "the recurrence rule is not valid".to_owned(),
    }
}

/// A client-safe description of what went wrong when a component was expanded.
fn describe_expansion(error: &CalendarErrorType) -> String {
    match error {
        CalendarErrorType::RRule(error) => describe(error),
        CalendarErrorType::MissingDtStart => "the recurrence rule needs a DTSTART".to_owned(),
        _ => "a date of the recurrence cannot be evaluated".to_owned(),
    }
}

/// Whether the rule repeats forever.
pub(crate) fn is_unbounded(rule: &ICalendarRecurrenceRule) -> bool {
    rule.count.is_none() && rule.until.is_none()
}

/// Whether the rule is more frequent than the server accepts (`SECONDLY` and `MINUTELY`).
pub(crate) fn is_sub_hourly(rule: &ICalendarRecurrenceRule) -> bool {
    matches!(rule.freq, ICalendarFrequency::Secondly | ICalendarFrequency::Minutely)
}

/// The latest wall-clock time the rule's own `UNTIL` allows, in the time zone of the start. A date-valued
/// `UNTIL` includes the whole day.
pub(crate) fn rule_until_local(rule: &ICalendarRecurrenceRule, zone: &Zone) -> Option<NaiveDateTime> {
    let until = rule.until.as_ref()?;
    let parsed = until.to_date_time()?;
    if !until.has_time() {
        return parsed.date_time.date().and_hms_opt(23, 59, 59);
    }
    match parsed.offset {
        Some(offset) => {
            let shift = TimeDelta::try_seconds(i64::from(offset.local_minus_utc()))?;
            let utc = parsed.date_time.checked_sub_signed(shift)?;
            Some(zone.utc_to_local(utc.and_utc()))
        }
        None => Some(parsed.date_time),
    }
}

/// Checks a rule against the consistency rules of RFC 5545 (value ranges, `BYSETPOS` needs another `BY` part,
/// `BYWEEKNO` only with `YEARLY`, ...).
pub(crate) fn check_rule(rule: &ICalendarRecurrenceRule, start: NaiveDateTime) -> Result<(), RuleError> {
    let Some(parsed) = contain(|| RRule::from_floating_ical(rule))
        .ok_or_else(|| invalid("the recurrence rule cannot be evaluated"))?
    else {
        return Err(invalid("the UNTIL value of the recurrence rule is not a valid date"));
    };
    let Some(floating_start) = CalendarTz::Floating.from_local_datetime(&start).single() else {
        return Err(invalid("the start of the recurrence is not a valid date"));
    };
    contain(|| parsed.validate(floating_start))
        .ok_or_else(|| invalid("the recurrence rule cannot be evaluated"))?
        .map(|_| ())
        .map_err(|error| RuleError::Invalid(describe(&error)))
}

/// Generates the occurrences of `rule` from `start` on the wall clock, up to `until` (inclusive) and at most
/// `cap` of them. The `UNTIL` of the rule itself is ignored: the caller folds it into `until` with
/// [`rule_until_local`], because only the caller knows the time zone.
pub(crate) fn rule_locals(
    rule: &ICalendarRecurrenceRule,
    start: NaiveDateTime,
    all_day: bool,
    until: Option<NaiveDateTime>,
    cap: usize,
) -> Result<Generated, RuleError> {
    if until.is_some_and(|bound| bound < start) || cap == 0 {
        return Ok(Generated {
            dates: Vec::new(),
            truncated: false,
        });
    }
    let mut rule = rule.clone();
    rule.until = match until {
        Some(bound) => Some(partial_from_local(bound, true, false).ok_or_else(|| invalid("the date is out of range"))?),
        None => None,
    };
    let dtstart = partial_from_local(start, !all_day, false).ok_or_else(|| invalid("the date is out of range"))?;
    let mut event = ICalendarComponent::new(ICalendarComponentType::VEvent);
    event
        .entries
        .push(ICalendarEntry::new(ICalendarProperty::Dtstart).with_value(dtstart));
    event
        .entries
        .push(ICalendarEntry::new(ICalendarProperty::Rrule).with_value(rule));
    let mut root = ICalendarComponent::new(ICalendarComponentType::VCalendar);
    root.component_ids.push(1);
    let calendar = ICalendar {
        components: vec![root, event],
    };
    // The generator is third-party code; a panic inside it must never reach the caller.
    let expansion = contain(|| calendar.expand_dates(CalendarTz::Floating, cap.saturating_add(1)))
        .ok_or_else(|| invalid("the recurrence rule cannot be evaluated"))?;
    if let Some(error) = expansion.errors.first() {
        return Err(RuleError::Invalid(describe_expansion(&error.error)));
    }
    let truncated = expansion.events.len() > cap;
    let dates = expansion
        .events
        .into_iter()
        .take(cap)
        .map(|event| event.start.naive_local())
        .collect();
    Ok(Generated { dates, truncated })
}

/// The date `years` after `date`, clamped to the representable range.
pub(crate) fn add_years(date: NaiveDate, years: u32) -> NaiveDate {
    date.checked_add_months(chrono::Months::new(years.saturating_mul(12)))
        .unwrap_or(NaiveDate::MAX)
}

#[cfg(test)]
mod tests {
    use calcard::icalendar::{ICalendarDay, ICalendarMonth, ICalendarWeekday};

    use super::*;
    use crate::zones::Zone;

    fn local(year: i32, month: u32, day: u32, hour: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(hour, 0, 0)
            .unwrap()
    }

    fn rule(freq: ICalendarFrequency) -> ICalendarRecurrenceRule {
        ICalendarRecurrenceRule {
            freq,
            ..ICalendarRecurrenceRule::default()
        }
    }

    #[test]
    fn a_daily_rule_with_count_stops_at_the_count() {
        let mut daily = rule(ICalendarFrequency::Daily);
        daily.count = Some(3);
        let generated = rule_locals(&daily, local(2027, 3, 1, 10), false, None, 100).unwrap();
        assert_eq!(
            generated.dates,
            vec![local(2027, 3, 1, 10), local(2027, 3, 2, 10), local(2027, 3, 3, 10)]
        );
        assert!(!generated.truncated);
    }

    #[test]
    fn the_bound_is_inclusive_and_the_cap_reports_truncation() {
        let daily = rule(ICalendarFrequency::Daily);
        let bounded = rule_locals(&daily, local(2027, 3, 1, 10), false, Some(local(2027, 3, 3, 10)), 100).unwrap();
        assert_eq!(bounded.dates.len(), 3);
        let capped = rule_locals(&daily, local(2027, 3, 1, 10), false, None, 5).unwrap();
        assert_eq!(capped.dates.len(), 5);
        assert!(capped.truncated);
        let before = rule_locals(&daily, local(2027, 3, 1, 10), false, Some(local(2027, 2, 1, 0)), 5).unwrap();
        assert_eq!(before.dates.len(), 0);
    }

    #[test]
    fn weekly_rules_follow_byday_and_the_local_clock() {
        let mut weekly = rule(ICalendarFrequency::Weekly);
        weekly.byday = vec![
            ICalendarDay {
                ordwk: None,
                weekday: ICalendarWeekday::Monday,
            },
            ICalendarDay {
                ordwk: None,
                weekday: ICalendarWeekday::Wednesday,
            },
        ];
        weekly.count = Some(4);
        // 2027-03-01 is a Monday.
        let generated = rule_locals(&weekly, local(2027, 3, 1, 9), false, None, 100).unwrap();
        assert_eq!(
            generated.dates,
            vec![
                local(2027, 3, 1, 9),
                local(2027, 3, 3, 9),
                local(2027, 3, 8, 9),
                local(2027, 3, 10, 9)
            ]
        );
    }

    #[test]
    fn monthly_rules_with_ordinal_weekdays() {
        let mut monthly = rule(ICalendarFrequency::Monthly);
        monthly.byday = vec![ICalendarDay {
            ordwk: Some(-1),
            weekday: ICalendarWeekday::Friday,
        }];
        monthly.count = Some(3);
        let generated = rule_locals(&monthly, local(2027, 1, 29, 18), false, None, 100).unwrap();
        // The last Fridays of January, February and March 2027.
        assert_eq!(
            generated.dates,
            vec![local(2027, 1, 29, 18), local(2027, 2, 26, 18), local(2027, 3, 26, 18)]
        );
    }

    #[test]
    fn yearly_rules_and_all_day_starts() {
        let mut yearly = rule(ICalendarFrequency::Yearly);
        yearly.bymonth = vec![ICalendarMonth::new(2, false)];
        yearly.bymonthday = vec![29];
        yearly.count = Some(2);
        let generated = rule_locals(&yearly, local(2024, 2, 29, 0), true, None, 100).unwrap();
        assert_eq!(generated.dates, vec![local(2024, 2, 29, 0), local(2028, 2, 29, 0)]);
    }

    #[test]
    fn inconsistent_rules_are_rejected_with_a_message() {
        let mut bad = rule(ICalendarFrequency::Weekly);
        bad.bymonthday = vec![1];
        let error = check_rule(&bad, local(2027, 3, 1, 10)).unwrap_err();
        let RuleError::Invalid(text) = error;
        assert!(text.contains("BYMONTHDAY"), "{text}");
        assert!(!text.contains('`') && !text.contains("Iteration"), "{text}");
        assert!(rule_locals(&bad, local(2027, 3, 1, 10), false, None, 10).is_err());
        assert!(check_rule(&rule(ICalendarFrequency::Daily), local(2027, 3, 1, 10)).is_ok());
    }

    #[test]
    fn every_kind_of_inconsistent_rule_gets_its_own_client_safe_message() {
        let start = local(2027, 3, 1, 10);
        let mut set_pos_out_of_range = rule(ICalendarFrequency::Monthly);
        set_pos_out_of_range.byday = vec![ICalendarDay {
            ordwk: None,
            weekday: ICalendarWeekday::Monday,
        }];
        set_pos_out_of_range.bysetpos = vec![40];
        let mut week_number_monthly = rule(ICalendarFrequency::Monthly);
        week_number_monthly.byweekno = vec![10];
        let mut day_out_of_range = rule(ICalendarFrequency::Monthly);
        day_out_of_range.bymonthday = vec![32];
        let mut ends_before_start = rule(ICalendarFrequency::Daily);
        ends_before_start.until = Some(partial_from_local(local(2027, 2, 1, 10), true, false).unwrap());
        let cases = [
            (
                set_pos_out_of_range,
                "BYSETPOS has an invalid value in the recurrence rule",
            ),
            (
                week_number_monthly,
                "BYWEEKNO cannot be used with FREQ=MONTHLY in the recurrence rule",
            ),
            (
                day_out_of_range,
                "BYMONTHDAY has an invalid value in the recurrence rule",
            ),
            (ends_before_start, "UNTIL is before the start of the recurrence"),
        ];
        for (bad, expected) in cases {
            assert_eq!(check_rule(&bad, start), Err(RuleError::Invalid(expected.to_owned())));
        }
    }

    #[test]
    fn only_names_that_look_like_rule_parts_are_echoed() {
        assert_eq!(part_name("BYMONTHDAY"), "BYMONTHDAY");
        assert_eq!(part_name("X-PART-1"), "X-PART-1");
        assert_eq!(part_name(""), "a part");
        assert_eq!(part_name("BYDAY<script>"), "a part");
        assert_eq!(part_name("BYDAY;FREQ=DAILY"), "a part");
        assert_eq!(part_name(&"B".repeat(17)), "a part");
        assert_eq!(part_name(&"B".repeat(16)), "B".repeat(16));
    }

    #[test]
    fn the_rule_until_is_converted_to_the_zone_of_the_start() {
        let berlin = Zone::from_tz(chrono_tz::Europe::Berlin);
        let mut daily = rule(ICalendarFrequency::Daily);
        // 2027-03-05T09:00:00Z is 10:00 in Berlin (CET).
        daily.until = Some(partial_from_local(local(2027, 3, 5, 9), true, true).unwrap());
        assert_eq!(rule_until_local(&daily, &berlin), Some(local(2027, 3, 5, 10)));
        assert_eq!(rule_until_local(&daily, &Zone::utc()), Some(local(2027, 3, 5, 9)));
        daily.until = Some(partial_from_local(local(2027, 3, 5, 9), true, false).unwrap());
        assert_eq!(rule_until_local(&daily, &berlin), Some(local(2027, 3, 5, 9)));
        daily.until = Some(partial_from_local(local(2027, 3, 5, 0), false, false).unwrap());
        assert_eq!(
            rule_until_local(&daily, &berlin),
            NaiveDate::from_ymd_opt(2027, 3, 5).unwrap().and_hms_opt(23, 59, 59)
        );
        assert!(is_unbounded(&rule(ICalendarFrequency::Daily)));
        assert!(!is_unbounded(&daily));
        assert!(is_sub_hourly(&rule(ICalendarFrequency::Minutely)));
        assert!(!is_sub_hourly(&rule(ICalendarFrequency::Hourly)));
    }

    #[test]
    fn years_are_added_with_clamping() {
        let start = NaiveDate::from_ymd_opt(2024, 2, 29).unwrap();
        assert_eq!(add_years(start, 1), NaiveDate::from_ymd_opt(2025, 2, 28).unwrap());
        assert_eq!(add_years(NaiveDate::MAX, 1), NaiveDate::MAX);
    }
}
