//! Contract suite of the `Clock` port.
//!
//! What every clock promises: reads never go backwards, an `Arc` of a clock is a clock, and the time is a plausible
//! calendar date. The system clock and the `ManualClock` double both run this suite.

use std::sync::Arc;

use chrono::Datelike;
use davhaven_ports::Clock;

use crate::suite::{Checks, ContractReport, Suite};

/// How many consecutive reads the monotonicity case makes.
const READS: usize = 1000;

/// Runs the suite against clocks built by `factory` and returns the report.
pub fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn Clock>,
{
    let mut suite = Suite::new("clock");

    let mut checks = Checks::new("reads never go backwards");
    let clock = factory();
    let mut previous = clock.now();
    for read in 0..READS {
        let now = clock.now();
        if now < previous {
            checks.fail(format!(
                "read {read} returned {now}, earlier than the previous {previous}"
            ));
        }
        previous = now;
    }
    suite.record(checks);

    let mut checks = Checks::new("an Arc of a clock is a clock");
    let shared = factory();
    let nested: Arc<dyn Clock> = Arc::new(Arc::clone(&shared));
    let before = shared.now();
    let through = nested.now();
    let after = shared.now();
    checks.that(
        before <= through && through <= after,
        "reading through a nested Arc lies between two direct reads",
    );
    suite.record(checks);

    let mut checks = Checks::new("the time is a plausible calendar date");
    let year = factory().now().year();
    checks.that((2020..=2200).contains(&year), "the year is between 2020 and 2200");
    suite.record(checks);

    suite.finish()
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
#[track_caller]
pub fn run_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn Clock>,
{
    run(factory).assert_ok();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use chrono::{DateTime, Utc};
    use davhaven_ports::SystemClock;
    use davhaven_ports::testing::ManualClock;

    use super::*;

    #[test]
    fn the_system_clock_and_the_manual_clock_satisfy_the_contract() {
        run_all(|| Arc::new(SystemClock));
        run_all(|| Arc::new(ManualClock::default()));
        assert_eq!(run(|| Arc::new(SystemClock)).case_count(), 3);
    }

    /// A clock that jumps backwards on every read.
    struct Backwards(AtomicI64);

    impl Clock for Backwards {
        fn now(&self) -> DateTime<Utc> {
            let seconds = self.0.fetch_sub(1, Ordering::SeqCst);
            DateTime::from_timestamp(seconds, 0).unwrap_or(DateTime::UNIX_EPOCH)
        }
    }

    #[test]
    fn a_clock_that_runs_backwards_is_caught() {
        let report = run(|| Arc::new(Backwards(AtomicI64::new(1_800_000_000))));
        assert!(!report.is_ok());
        assert!(report.failed_cases().contains(&"reads never go backwards"), "{report}");
    }

    #[test]
    fn a_clock_stuck_in_the_past_is_caught() {
        let report = run(|| Arc::new(ManualClock::new(DateTime::UNIX_EPOCH)));
        assert_eq!(
            report.failed_cases(),
            vec!["the time is a plausible calendar date"],
            "{report}"
        );
    }
}
