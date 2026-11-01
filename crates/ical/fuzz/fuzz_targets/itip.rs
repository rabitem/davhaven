//! Scheduling: the first byte splits the input into the stored copy and the new copy of an object; the diff,
//! the organizer rules, the attendee checks, the messages and the reply handling must hold for any pair.
//! The whole input is also an inbound message.

#![no_main]

use davhaven_domain::{CalendarUserAddress, IcalLimits, ItipMethod};
use davhaven_ical::freebusy::read_request;
use davhaven_ical::itip::{
    MessageSpec, apply_organizer_changes, apply_reply_with, attendee_change_violations, build_message, diff,
    organizer_change_violations, parse_message,
};
use davhaven_ical::serialize::serialize;
use davhaven_ical::validate::parse_and_validate;
use chrono::{TimeZone, Utc};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = IcalLimits {
        max_instances: 200,
        max_iterator_steps: 5_000,
        time_budget_ms: 1_500,
        ..IcalLimits::default()
    };
    if let Ok(message) = parse_message(data, &limits) {
        let _ = read_request(&message);
        let _ = message.object();
    }
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let at = usize::from(split) * rest.len() / 256;
    let Some((first, second)) = rest.split_at_checked(at) else {
        return;
    };
    let (Ok(old), Ok(new)) = (parse_and_validate(first, &limits), parse_and_validate(second, &limits)) else {
        return;
    };
    let attendee = CalendarUserAddress::parse("mailto:guest@example.org").expect("a valid address");
    let _ = diff(Some(&old.calendar), &new.calendar, &limits);
    let _ = organizer_change_violations(&old.calendar, &new.calendar);
    let _ = apply_organizer_changes(Some(&old.calendar), &new.calendar, &limits);
    let _ = attendee_change_violations(&old.calendar, &new.calendar, &attendee);
    for method in [ItipMethod::Request, ItipMethod::Cancel, ItipMethod::Reply] {
        let spec = MessageSpec {
            replying_attendee: Some(attendee.clone()),
            comment: Some("Fine with me".to_owned()),
            ..MessageSpec::new(method, attendee.clone(), Utc.with_ymd_and_hms(2027, 1, 2, 0, 0, 0).unwrap())
        };
        if let Ok(message) = build_message(&new.calendar, &spec) {
            let text = serialize(&message.calendar).expect("a built message serializes");
            let _ = parse_message(text.as_bytes(), &limits);
            let _ = apply_reply_with(&old.calendar, &message, &limits, Some(&attendee));
        }
    }
});
