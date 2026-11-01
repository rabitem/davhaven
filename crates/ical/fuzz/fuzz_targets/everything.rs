//! Every entry point of the crate on the same input; the body is shared with the never-panic property test.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/exercise.rs"]
mod support;

fuzz_target!(|data: &[u8]| {
    support::exercise(data);
});
