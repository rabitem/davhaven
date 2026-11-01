//! The time of the application, for the protocol layers.
//!
//! Protocol crates never depend on `davhaven-ports` (`ENGINEERING_RULES` R1), so they cannot hold the `Clock` port,
//! and `Utc::now` is disallowed outside the production clock (R9). The one thing a protocol layer needs from the clock is
//! the present, for the defaults of a call: MCP's `search_events` starts "now" when the call names no start. [`AppClock`]
//! is that need: a read-only view of the clock that `app::build` was given (the system clock in production, the manual
//! clock of a test), so every layer of one application agrees on what time it is.

use core::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};

/// A read-only view of the application's clock.
#[derive(Clone)]
pub struct AppClock {
    now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

impl AppClock {
    /// A view that reads the present with `now`.
    pub fn new(now: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        Self { now: Arc::new(now) }
    }

    /// A view of a clock that never moves.
    pub fn fixed(at: DateTime<Utc>) -> Self {
        Self::new(move || at)
    }

    /// The present.
    pub fn now(&self) -> DateTime<Utc> {
        (self.now)()
    }
}

impl fmt::Debug for AppClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppClock").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_view_reads_the_clock_it_was_given() {
        let at = DateTime::parse_from_rfc3339("2027-03-01T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(AppClock::fixed(at).now(), at);
        let counter = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let ticking = {
            let counter = Arc::clone(&counter);
            AppClock::new(move || {
                DateTime::UNIX_EPOCH
                    + chrono::Duration::seconds(counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
            })
        };
        let copy = ticking.clone();
        assert_eq!(ticking.now(), DateTime::UNIX_EPOCH);
        assert_eq!(
            copy.now(),
            DateTime::UNIX_EPOCH + chrono::Duration::seconds(1),
            "a clone reads the same clock"
        );
    }
}
