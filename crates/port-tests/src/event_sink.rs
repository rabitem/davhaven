//! Contract suite of the `EventSink` port.
//!
//! What every sink promises: a stable non-empty name, and acceptance of well-formed envelopes of every shape,
//! including the same envelope more than once (delivery is at-least-once, so sinks deduplicate on the envelope id
//! themselves and never fail on a repeat).

use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use davhaven_domain::events::{CalendarPayload, PrincipalPayload};
use davhaven_domain::{
    AuditActor, CalendarId, CalendarKind, Envelope, EventId, EventPayload, EventType, PrincipalId, TenantId,
};
use davhaven_ports::EventSink;
use uuid::Uuid;

use crate::suite::{Checks, ContractReport, Suite};

fn occurred_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 1, 12, 0, 0)
        .single()
        .unwrap_or(DateTime::UNIX_EPOCH)
}

/// A well-formed `calendar.created` envelope with the id `n`.
pub fn calendar_created(n: u128) -> Option<Envelope> {
    Envelope::new(
        EventId::from_uuid(Uuid::from_u128(n)),
        EventType::CalendarCreated,
        TenantId::from_uuid(Uuid::from_u128(1)),
        occurred_at(),
        AuditActor::system(),
        EventPayload::Calendar(CalendarPayload {
            calendar: CalendarId::from_uuid(Uuid::from_u128(2)),
            owner: PrincipalId::from_uuid(Uuid::from_u128(3)),
            kind: CalendarKind::User,
        }),
    )
    .ok()
}

/// A well-formed `principal.created` envelope with the id `n`.
pub fn principal_created(n: u128) -> Option<Envelope> {
    Envelope::new(
        EventId::from_uuid(Uuid::from_u128(n)),
        EventType::PrincipalCreated,
        TenantId::from_uuid(Uuid::from_u128(1)),
        occurred_at(),
        AuditActor::system(),
        EventPayload::Principal(PrincipalPayload {
            principal: PrincipalId::from_uuid(Uuid::from_u128(3)),
        }),
    )
    .ok()
}

/// Runs the suite against sinks built by `factory` and returns the report.
pub async fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn EventSink>,
{
    let mut suite = Suite::new("event_sink");
    let sink = factory();

    let mut checks = Checks::new("the name is stable and not empty");
    checks.that(!sink.name().is_empty(), "the name is not empty");
    checks.equal(&sink.name(), &factory().name(), "the names of two instances");
    suite.record(checks);

    let mut checks = Checks::new("well-formed envelopes of every shape are accepted");
    for (what, envelope) in [
        ("a calendar event", calendar_created(10)),
        ("a principal event", principal_created(11)),
    ] {
        match envelope {
            Some(envelope) => {
                checks.ok(sink.deliver(&envelope).await, what);
            }
            None => checks.fail(format!("the suite could not build {what}")),
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("repeated delivery of one envelope is accepted");
    match calendar_created(20) {
        Some(envelope) => {
            for attempt in 1..=3 {
                checks.ok(sink.deliver(&envelope).await, &format!("delivery attempt {attempt}"));
            }
        }
        None => checks.fail("the suite could not build an envelope"),
    }
    suite.record(checks);

    suite.finish()
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn EventSink>,
{
    run(factory).await.assert_ok();
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_ports::HandlerError;
    use tokio::sync::Mutex;

    use super::*;

    /// A sink that remembers the ids it saw and fails on a repeat.
    struct Strict {
        seen: Mutex<Vec<EventId>>,
    }

    #[async_trait]
    impl EventSink for Strict {
        fn name(&self) -> &'static str {
            "strict"
        }

        async fn deliver(&self, envelope: &Envelope) -> Result<(), HandlerError> {
            let mut seen = self.seen.lock().await;
            if seen.contains(&envelope.id) {
                return Err(HandlerError::Permanent("seen before".to_owned()));
            }
            seen.push(envelope.id);
            Ok(())
        }
    }

    /// A sink that accepts everything.
    struct Open;

    #[async_trait]
    impl EventSink for Open {
        fn name(&self) -> &'static str {
            "open"
        }

        async fn deliver(&self, _envelope: &Envelope) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_envelopes_of_the_suite_are_well_formed() {
        assert_eq!(calendar_created(5).unwrap().event_type, EventType::CalendarCreated);
        assert_eq!(principal_created(6).unwrap().event_type, EventType::PrincipalCreated);
    }

    #[tokio::test]
    async fn a_tolerant_sink_satisfies_the_contract() {
        run_all(|| Arc::new(Open)).await;
        assert_eq!(run(|| Arc::new(Open)).await.case_count(), 3);
    }

    #[tokio::test]
    async fn a_sink_that_fails_on_repeats_is_caught() {
        let report = run(|| {
            Arc::new(Strict {
                seen: Mutex::new(Vec::new()),
            })
        })
        .await;
        assert_eq!(
            report.failed_cases(),
            vec!["repeated delivery of one envelope is accepted"],
            "{report}"
        );
    }
}
