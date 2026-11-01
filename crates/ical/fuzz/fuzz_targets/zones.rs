//! Time zone identifiers: Windows names, IANA names, anything else; and the VTIMEZONE of what resolves.

#![no_main]

use davhaven_ical::tz::{render_vtimezone, resolve_tzid, windows_to_iana};
use chrono::{TimeZone, Utc};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(name) = std::str::from_utf8(data) else {
        return;
    };
    let _ = windows_to_iana(name);
    if let Ok(Some(zone)) = resolve_tzid(name) {
        let from = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("a valid date");
        let until = Utc
            .with_ymd_and_hms(2029, 1, 1, 0, 0, 0)
            .single()
            .expect("a valid date");
        assert!(render_vtimezone(zone, from, until).is_ok(), "a resolved zone renders");
    }
});
