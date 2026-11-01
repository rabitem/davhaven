//! Expansion, free-busy, projection and calendar-query matching over any accepted object and any time range.
//! The first eight bytes choose the range (days since 1970), the rest is the iCalendar object.

#![no_main]

use davhaven_domain::IcalLimits;
use davhaven_ical::expand::expand;
use davhaven_ical::filter::{CalendarFilter, CompFilter, TimeRange, matches};
use davhaven_ical::freebusy::busy_periods;
use davhaven_ical::projection::{ComponentSelection, Projection, project};
use davhaven_ical::validate::parse_and_validate;
use chrono::{DateTime, Utc};
use libfuzzer_sys::fuzz_target;

fn day(bytes: [u8; 4]) -> Option<DateTime<Utc>> {
    // Days between 1970 and about 2100.
    let days = i64::from(u32::from_le_bytes(bytes) % 47_500);
    DateTime::from_timestamp(days * 86_400, 0)
}

fn filter(range: TimeRange) -> CalendarFilter {
    CalendarFilter {
        root: CompFilter {
            name: "VCALENDAR".to_owned(),
            is_not_defined: false,
            time_range: None,
            prop_filters: Vec::new(),
            comp_filters: vec![CompFilter {
                name: "VEVENT".to_owned(),
                is_not_defined: false,
                time_range: Some(range),
                prop_filters: Vec::new(),
                comp_filters: Vec::new(),
            }],
        },
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((head, body)) = data.split_at_checked(8) else {
        return;
    };
    let (Some(first), Some(second)) = (
        head.first_chunk::<4>().copied().and_then(day),
        head.last_chunk::<4>().copied().and_then(day),
    ) else {
        return;
    };
    let (from, until) = if first <= second {
        (first, second)
    } else {
        (second, first)
    };
    let limits = IcalLimits {
        max_instances: 300,
        max_iterator_steps: 10_000,
        time_budget_ms: 1_500,
        ..IcalLimits::default()
    };
    let Ok(object) = parse_and_validate(body, &limits) else {
        return;
    };
    let range = TimeRange::new(Some(from), Some(until));
    if let Ok(instances) = expand(&object.calendar, &range, &limits) {
        assert!(instances.len() <= 300, "more instances than the limit");
        assert!(
            instances.windows(2).all(|pair| pair[0].start <= pair[1].start),
            "instances are not ordered"
        );
    }
    let _ = matches(&object.calendar, &filter(range.clone()), &limits);
    let _ = busy_periods(&[&object.calendar], &range, &limits);
    let _ = project(
        &object.calendar,
        &Projection {
            expand: Some(range),
            select: Some(ComponentSelection {
                name: "VCALENDAR".to_owned(),
                all_props: true,
                props: Vec::new(),
                all_comps: true,
                comps: Vec::new(),
            }),
            ..Projection::default()
        },
        &limits,
    );
});
