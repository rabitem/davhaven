//! Contract suite of the `OutboxHandler` port.
//!
//! What every handler promises about itself: it takes exactly one, stable, known record kind. The behaviour of
//! `handle` (idempotency, retryable versus permanent failures) is specific to the kind; the suites of the handlers
//! (`imip`, `webhook`, ...) belong to the crates that implement them (PLAN 4.2).

use std::sync::Arc;

use davhaven_ports::OutboxHandler;
use davhaven_ports::outbox::kind;

use crate::suite::{Checks, ContractReport, Suite};

/// The record kinds a handler may take.
pub const KNOWN_KINDS: [&str; 5] = [
    kind::IMIP,
    kind::INTERNAL_DELIVERY,
    kind::WEBHOOK,
    kind::DOMAIN_EVENT,
    kind::PROVIDER_PUSH,
];

/// Runs the suite against handlers built by `factory` and returns the report.
pub fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn OutboxHandler>,
{
    let mut suite = Suite::new("outbox");
    let handler = factory();

    let mut checks = Checks::new("the kind is stable and known");
    checks.that(!handler.kind().is_empty(), "the kind is not empty");
    checks.equal(&handler.kind(), &factory().kind(), "the kinds of two instances");
    checks.that(
        KNOWN_KINDS.contains(&handler.kind()),
        "the kind is one of the record kinds of davhaven_ports::outbox::kind",
    );
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
    F: Fn() -> Arc<dyn OutboxHandler>,
{
    run(factory).assert_ok();
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_ports::{HandlerError, OutboxRecord};

    use super::*;

    struct Handler(&'static str);

    #[async_trait]
    impl OutboxHandler for Handler {
        fn kind(&self) -> &'static str {
            self.0
        }

        async fn handle(&self, _record: &OutboxRecord) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    #[test]
    fn known_kinds_pass_and_unknown_kinds_are_caught() {
        for known in KNOWN_KINDS {
            run_all(move || Arc::new(Handler(known)));
        }
        assert!(!run(|| Arc::new(Handler("made_up"))).is_ok());
        assert!(!run(|| Arc::new(Handler(""))).is_ok());
    }
}
