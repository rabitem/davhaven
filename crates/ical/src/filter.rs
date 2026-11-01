//! Evaluation of CalDAV `calendar-query` filters and time ranges.
//!
//! The DAV layer parses the XML of a `calendar-query` REPORT into a [`CalendarFilter`]; the application first
//! narrows candidates with the store's index pre-filter and then decides each candidate exactly with
//! [`matches()`]. The structure follows RFC 4791 section 9.7: nested component filters, property filters with
//! text matching and parameter filters, and `time-range` restrictions at component and property level.

use chrono::{DateTime, Months, Utc};
use davhaven_domain::{IcalLimits, TimeZoneName};

use crate::error::{IcalError, LimitKind};
use crate::parse::ParsedCalendar;

/// A half-open time range `[start, end)` as in a CalDAV `time-range` element; an absent bound is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeRange {
    /// The inclusive start, or `None` for "from the beginning of time".
    pub start: Option<DateTime<Utc>>,
    /// The exclusive end, or `None` for "until the end of time".
    pub end: Option<DateTime<Utc>>,
}

impl TimeRange {
    /// Creates a range.
    pub const fn new(start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> Self {
        Self { start, end }
    }

    /// Checks a range used as a filter: it needs at least one bound, must not end before it starts and must lie
    /// within the configured date limits. Open-ended ranges are fine for filtering.
    ///
    /// # Errors
    ///
    /// [`IcalError::Invalid`] for a range without bounds or with `end < start`; [`IcalError::Limit`] with
    /// [`LimitKind::MinDateTime`] or [`LimitKind::MaxDateTime`] for bounds outside the configured years.
    pub fn validate(&self, limits: &IcalLimits) -> Result<(), IcalError> {
        if self.start.is_none() && self.end.is_none() {
            return Err(IcalError::invalid("a time-range needs a start or an end"));
        }
        if let (Some(start), Some(end)) = (self.start, self.end)
            && end < start
        {
            return Err(IcalError::invalid("the end of a time-range is before its start"));
        }
        let min = limits.min_date_time();
        let max = limits.max_date_time();
        if let (Some(min), Some(start)) = (min, self.start)
            && start < min
        {
            return Err(IcalError::Limit(LimitKind::MinDateTime));
        }
        if let (Some(max), Some(end)) = (max, self.end)
            && end > max
        {
            return Err(IcalError::Limit(LimitKind::MaxDateTime));
        }
        Ok(())
    }

    /// Checks a range used for expansion or free-busy: both bounds are required and the span may not exceed
    /// `max_time_range_years`, on top of the checks of [`TimeRange::validate`].
    ///
    /// # Errors
    ///
    /// As [`TimeRange::validate`]; [`IcalError::Invalid`] for an open-ended range and
    /// [`IcalError::Limit`] with [`LimitKind::TimeRange`] for a span that is too long.
    pub fn validate_bounded(&self, limits: &IcalLimits) -> Result<(), IcalError> {
        self.validate(limits)?;
        let (Some(start), Some(end)) = (self.start, self.end) else {
            return Err(IcalError::invalid("this time-range needs both a start and an end"));
        };
        check_span(start, end, limits)
    }

    /// Whether the instant lies in the range.
    pub fn contains(&self, instant: DateTime<Utc>) -> bool {
        self.start.is_none_or(|start| instant >= start) && self.end.is_none_or(|end| instant < end)
    }

    /// Whether the interval `[start, end)` overlaps the range. An empty interval (`start == end`) overlaps when
    /// its instant lies inside the range (RFC 4791 section 9.9).
    pub fn overlaps(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
        if start == end {
            return self.contains(start);
        }
        self.start.is_none_or(|range_start| end > range_start) && self.end.is_none_or(|range_end| start < range_end)
    }
}

/// How a text-match compares (the `collation` attribute of RFC 4791).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Collation {
    /// `i;ascii-casemap` (the default): ASCII case-insensitive.
    #[default]
    AsciiCasemap,
    /// `i;octet`: byte-for-byte comparison.
    Octet,
    /// `i;unicode-casemap`: Unicode case-insensitive.
    UnicodeCasemap,
}

/// A `text-match` condition: a substring test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextMatch {
    /// The text to look for.
    pub value: String,
    /// How to compare.
    pub collation: Collation,
    /// Invert the result (`negate-condition="yes"`).
    pub negate: bool,
}

/// A `param-filter`: a condition on a property parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamFilter {
    /// The parameter name, for example `PARTSTAT`.
    pub name: String,
    /// The parameter must not exist.
    pub is_not_defined: bool,
    /// A condition on the parameter value.
    pub text_match: Option<TextMatch>,
}

/// A `prop-filter`: a condition on a property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropFilter {
    /// The property name, for example `SUMMARY`.
    pub name: String,
    /// The property must not exist.
    pub is_not_defined: bool,
    /// A time-range on a date-time property.
    pub time_range: Option<TimeRange>,
    /// A condition on the property value.
    pub text_match: Option<TextMatch>,
    /// Conditions on parameters of the property.
    pub param_filters: Vec<ParamFilter>,
}

/// A `comp-filter`: a condition on a component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompFilter {
    /// The component name: `VCALENDAR` at the top, then `VEVENT`, `VTODO`, `VJOURNAL`, `VALARM`, ...
    pub name: String,
    /// The component must not exist.
    pub is_not_defined: bool,
    /// A time-range on the component.
    pub time_range: Option<TimeRange>,
    /// Conditions on properties of the component.
    pub prop_filters: Vec<PropFilter>,
    /// Conditions on child components.
    pub comp_filters: Vec<CompFilter>,
}

/// The filter of a `calendar-query` REPORT: the top-level `comp-filter` for `VCALENDAR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarFilter {
    /// The `VCALENDAR` comp-filter.
    pub root: CompFilter,
}

/// The deepest comp-filter nesting accepted whatever `max_nesting` says.
const MAX_FILTER_DEPTH: usize = 32;

/// Checks a filter for structure and limits: the root is `VCALENDAR`, time-ranges are valid, and the nesting
/// does not exceed `max_nesting`.
///
/// # Errors
///
/// [`IcalError::Invalid`] or [`IcalError::Limit`] (answered as `CALDAV:valid-filter`).
pub fn validate_filter(filter: &CalendarFilter, limits: &IcalLimits) -> Result<(), IcalError> {
    if !filter.root.name.eq_ignore_ascii_case("VCALENDAR") {
        return Err(IcalError::invalid("the top-level comp-filter must name VCALENDAR"));
    }
    let max_depth = usize::try_from(limits.max_nesting)
        .unwrap_or(usize::MAX)
        .min(MAX_FILTER_DEPTH);
    validate_comp(&filter.root, 1, max_depth, limits)
}

fn validate_range(range: &TimeRange, limits: &IcalLimits) -> Result<(), IcalError> {
    range.validate(limits)?;
    match (range.start, range.end) {
        (Some(start), Some(end)) => check_span(start, end, limits),
        _ => Ok(()),
    }
}

/// A span may not exceed `max_time_range_years` (PLAN 2.15: ten years).
fn check_span(start: DateTime<Utc>, end: DateTime<Utc>, limits: &IcalLimits) -> Result<(), IcalError> {
    let months = limits.max_time_range_years.saturating_mul(12);
    if start
        .checked_add_months(Months::new(months))
        .is_none_or(|latest| end > latest)
    {
        return Err(IcalError::Limit(LimitKind::TimeRange));
    }
    Ok(())
}

fn validate_comp(comp: &CompFilter, depth: usize, max_depth: usize, limits: &IcalLimits) -> Result<(), IcalError> {
    if depth > max_depth {
        return Err(IcalError::Limit(LimitKind::Nesting));
    }
    if comp.name.trim().is_empty() {
        return Err(IcalError::invalid("a comp-filter needs a component name"));
    }
    if comp.is_not_defined
        && (comp.time_range.is_some() || !comp.prop_filters.is_empty() || !comp.comp_filters.is_empty())
    {
        return Err(IcalError::invalid(
            "a comp-filter with is-not-defined cannot have conditions",
        ));
    }
    if let Some(range) = &comp.time_range {
        validate_range(range, limits)?;
        let name = comp.name.to_ascii_uppercase();
        if !matches!(name.as_str(), "VEVENT" | "VTODO" | "VJOURNAL" | "VFREEBUSY" | "VALARM") {
            return Err(IcalError::invalid("a time-range is not allowed on this component"));
        }
    }
    for property in &comp.prop_filters {
        validate_prop(property, limits)?;
    }
    for child in &comp.comp_filters {
        validate_comp(child, depth.saturating_add(1), max_depth, limits)?;
    }
    Ok(())
}

fn validate_prop(prop: &PropFilter, limits: &IcalLimits) -> Result<(), IcalError> {
    if prop.name.trim().is_empty() {
        return Err(IcalError::invalid("a prop-filter needs a property name"));
    }
    if prop.is_not_defined && (prop.time_range.is_some() || prop.text_match.is_some() || !prop.param_filters.is_empty())
    {
        return Err(IcalError::invalid(
            "a prop-filter with is-not-defined cannot have conditions",
        ));
    }
    if let Some(range) = &prop.time_range {
        validate_range(range, limits)?;
    }
    for param in &prop.param_filters {
        if param.name.trim().is_empty() {
            return Err(IcalError::invalid("a param-filter needs a parameter name"));
        }
        if param.is_not_defined && param.text_match.is_some() {
            return Err(IcalError::invalid(
                "a param-filter with is-not-defined cannot have a text-match",
            ));
        }
    }
    Ok(())
}

/// Decides whether `calendar` satisfies `filter`, evaluating recurrence sets exactly (an instance of a
/// recurring event inside a `time-range` matches the whole object).
///
/// Floating times and all-day dates are read as UTC; see [`matches_in_zone`].
///
/// # Errors
///
/// [`IcalError::Limit`] when expansion exceeds the limits.
pub fn matches(calendar: &ParsedCalendar, filter: &CalendarFilter, limits: &IcalLimits) -> Result<bool, IcalError> {
    matches_in_zone(calendar, filter, limits, TimeZoneName::utc())
}

/// Like [`matches()`], with floating times and all-day dates read in `floating_zone` (the time zone of the
/// calendar collection).
///
/// # Errors
///
/// [`IcalError::Limit`] when expansion exceeds the limits.
pub fn matches_in_zone(
    calendar: &ParsedCalendar,
    filter: &CalendarFilter,
    limits: &IcalLimits,
    floating_zone: TimeZoneName,
) -> Result<bool, IcalError> {
    crate::matcher::evaluate(calendar, filter, limits, floating_zone)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    fn range(start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> TimeRange {
        TimeRange::new(start, end)
    }

    #[test]
    fn contains_is_half_open() {
        let r = range(Some(at(2027, 3, 1, 10)), Some(at(2027, 3, 1, 12)));
        assert!(r.contains(at(2027, 3, 1, 10)));
        assert!(r.contains(at(2027, 3, 1, 11)));
        assert!(!r.contains(at(2027, 3, 1, 12)));
        assert!(!r.contains(at(2027, 3, 1, 9)));
        assert!(range(None, Some(at(2027, 3, 1, 12))).contains(at(1999, 1, 1, 0)));
        assert!(range(Some(at(2027, 3, 1, 10)), None).contains(at(2099, 1, 1, 0)));
        assert!(range(None, None).contains(at(2027, 3, 1, 10)));
    }

    #[test]
    fn overlap_follows_rfc_4791_section_9_9() {
        let r = range(Some(at(2027, 3, 1, 10)), Some(at(2027, 3, 1, 12)));
        // Intervals: (start, end, expected).
        let cases = [
            (at(2027, 3, 1, 9), at(2027, 3, 1, 11), true),
            (at(2027, 3, 1, 11), at(2027, 3, 1, 13), true),
            (at(2027, 3, 1, 10), at(2027, 3, 1, 12), true),
            (at(2027, 3, 1, 8), at(2027, 3, 1, 14), true),
            (at(2027, 3, 1, 10), at(2027, 3, 1, 11), true),
            (at(2027, 3, 1, 8), at(2027, 3, 1, 10), false),
            (at(2027, 3, 1, 12), at(2027, 3, 1, 14), false),
            (at(2027, 3, 1, 1), at(2027, 3, 1, 2), false),
            // Zero-length events count when their instant is inside the range.
            (at(2027, 3, 1, 10), at(2027, 3, 1, 10), true),
            (at(2027, 3, 1, 11), at(2027, 3, 1, 11), true),
            (at(2027, 3, 1, 12), at(2027, 3, 1, 12), false),
            (at(2027, 3, 1, 9), at(2027, 3, 1, 9), false),
        ];
        for (start, end, expected) in cases {
            assert_eq!(r.overlaps(start, end), expected, "{start} .. {end}");
        }
        assert!(range(None, None).overlaps(at(2027, 1, 1, 0), at(2027, 1, 2, 0)));
        assert!(range(Some(at(2027, 3, 1, 10)), None).overlaps(at(2027, 3, 1, 9), at(2027, 3, 1, 11)));
        assert!(!range(Some(at(2027, 3, 1, 10)), None).overlaps(at(2027, 3, 1, 8), at(2027, 3, 1, 10)));
        assert!(range(None, Some(at(2027, 3, 1, 10))).overlaps(at(2027, 3, 1, 9), at(2027, 3, 1, 11)));
        assert!(!range(None, Some(at(2027, 3, 1, 10))).overlaps(at(2027, 3, 1, 10), at(2027, 3, 1, 11)));
    }

    #[test]
    fn filter_ranges_are_validated_against_the_limits() {
        let limits = IcalLimits::default();
        assert!(
            range(Some(at(2027, 3, 1, 0)), Some(at(2027, 3, 2, 0)))
                .validate(&limits)
                .is_ok()
        );
        assert!(range(Some(at(2027, 3, 1, 0)), None).validate(&limits).is_ok());
        assert!(range(None, Some(at(2027, 3, 1, 0))).validate(&limits).is_ok());
        assert!(matches!(
            range(None, None).validate(&limits),
            Err(IcalError::Invalid(_))
        ));
        assert!(matches!(
            range(Some(at(2027, 3, 2, 0)), Some(at(2027, 3, 1, 0))).validate(&limits),
            Err(IcalError::Invalid(_))
        ));
        assert_eq!(
            range(Some(at(1899, 12, 31, 0)), None).validate(&limits),
            Err(IcalError::Limit(LimitKind::MinDateTime))
        );
        assert_eq!(
            range(None, Some(at(2100, 1, 1, 1))).validate(&limits),
            Err(IcalError::Limit(LimitKind::MaxDateTime))
        );
        assert!(
            range(Some(at(1900, 1, 1, 0)), Some(at(2100, 1, 1, 0)))
                .validate(&limits)
                .is_ok()
        );
    }

    #[test]
    fn bounded_ranges_need_both_ends_and_a_limited_span() {
        let limits = IcalLimits::default();
        assert!(
            range(Some(at(2027, 3, 1, 0)), Some(at(2027, 3, 2, 0)))
                .validate_bounded(&limits)
                .is_ok()
        );
        assert!(
            range(Some(at(2027, 3, 1, 0)), Some(at(2037, 3, 1, 0)))
                .validate_bounded(&limits)
                .is_ok(),
            "exactly 10 years"
        );
        assert_eq!(
            range(Some(at(2027, 3, 1, 0)), Some(at(2037, 3, 1, 1))).validate_bounded(&limits),
            Err(IcalError::Limit(LimitKind::TimeRange))
        );
        assert!(matches!(
            range(Some(at(2027, 3, 1, 0)), None).validate_bounded(&limits),
            Err(IcalError::Invalid(_))
        ));
        assert!(matches!(
            range(None, Some(at(2027, 3, 1, 0))).validate_bounded(&limits),
            Err(IcalError::Invalid(_))
        ));
        // The date limits still apply.
        assert_eq!(
            range(Some(at(1800, 1, 1, 0)), Some(at(1800, 1, 2, 0))).validate_bounded(&limits),
            Err(IcalError::Limit(LimitKind::MinDateTime))
        );
        let tight = IcalLimits {
            max_time_range_years: 1,
            ..IcalLimits::default()
        };
        assert_eq!(
            range(Some(at(2027, 3, 1, 0)), Some(at(2028, 3, 2, 0))).validate_bounded(&tight),
            Err(IcalError::Limit(LimitKind::TimeRange))
        );
    }

    #[test]
    fn collation_defaults_to_ascii_casemap() {
        assert_eq!(Collation::default(), Collation::AsciiCasemap);
    }
}
