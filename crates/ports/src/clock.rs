//! The `Clock` port and the system clock.
//!
//! Time reaches the application only through [`Clock`] (`ENGINEERING_RULES` R9): `Utc::now`, `Local::now` and
//! `SystemTime::now` are disallowed everywhere except in [`SystemClock`]. Tests use the `ManualClock` of the
//! `testing` feature and move time explicitly.

use std::sync::Arc;

use chrono::{DateTime, Utc};

/// The source of the current time.
///
/// Implementations are cheap and never block. Every timestamp that logic depends on (expiry, retention cut-offs,
/// `updated_at`, change-log times) comes from here, never from a database default.
pub trait Clock: Send + Sync {
    /// The current instant in UTC.
    fn now(&self) -> DateTime<Utc>;
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now(&self) -> DateTime<Utc> {
        (**self).now()
    }
}

/// The production clock: the operating system's wall clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[expect(
        clippy::disallowed_methods,
        reason = "this is the production clock behind the Clock port"
    )]
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_moves_forward() {
        let clock = SystemClock;
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
        assert!(first.timestamp() > 1_700_000_000, "the system clock is set");
    }

    #[test]
    fn clocks_work_behind_arcs_and_trait_objects() {
        let shared: Arc<dyn Clock> = Arc::new(SystemClock);
        let nested: Arc<dyn Clock> = Arc::new(Arc::clone(&shared));
        assert!(nested.now().timestamp() > 1_700_000_000);
    }
}
