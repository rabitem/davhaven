//! The front door: whatever a client uploads is parsed, validated, indexed and serialized. Accepted data must
//! survive a round trip unchanged.

#![no_main]

use davhaven_domain::IcalLimits;
use davhaven_ical::hash::content_hash;
use davhaven_ical::index::index;
use davhaven_ical::parse::parse;
use davhaven_ical::serialize::serialize;
use davhaven_ical::validate::parse_and_validate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = IcalLimits {
        max_instances: 200,
        max_iterator_steps: 5_000,
        time_budget_ms: 1_500,
        ..IcalLimits::default()
    };
    if let Ok(object) = parse_and_validate(data, &limits) {
        let text = serialize(&object.calendar).expect("an accepted object serializes");
        let again = parse(text.as_bytes(), &limits).expect("what was serialized parses");
        assert_eq!(again, object.calendar, "the round trip changes the object");
        assert_eq!(
            serialize(&again).expect("serializes"),
            text,
            "serialization is not a fixed point"
        );
        assert_eq!(
            content_hash(&again).expect("hashes"),
            content_hash(&object.calendar).expect("hashes")
        );
        let _ = index(&object, &limits);
    }
});
