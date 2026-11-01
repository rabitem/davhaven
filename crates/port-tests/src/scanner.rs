//! Contract suite of the `ContentScanner` port.
//!
//! What every scanner promises: a stable non-empty name, empty and plainly harmless content is clean, and a
//! verdict does not depend on how often or in which order content is scanned.

use std::sync::Arc;

use davhaven_domain::{MediaType, TenantId};
use davhaven_ports::{ContentScanner, ScanContext, ScanVerdict};
use uuid::Uuid;

use crate::suite::{Checks, ContractReport, Suite};

fn context(content_type: Option<&str>) -> ScanContext {
    ScanContext {
        tenant: TenantId::from_uuid(Uuid::from_u128(1)),
        content_type: content_type.and_then(|text| MediaType::parse(text).ok()),
    }
}

/// Runs the suite against scanners built by `factory` and returns the report.
pub async fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn ContentScanner>,
{
    let mut suite = Suite::new("scanner");
    let scanner = factory();

    let mut checks = Checks::new("the name is stable and not empty");
    checks.that(!scanner.name().is_empty(), "the name is not empty");
    checks.equal(&scanner.name(), &factory().name(), "the names of two instances");
    suite.record(checks);

    let mut checks = Checks::new("empty and harmless content is clean");
    for (what, content, content_type) in [
        ("empty content", &b""[..], None),
        (
            "plain text",
            &b"Agenda:\n1. Welcome\n2. Planning\n"[..],
            Some("text/plain"),
        ),
        ("a small PNG header", &b"\x89PNG\r\n\x1a\n"[..], Some("image/png")),
    ] {
        if let Some(verdict) = checks.ok(scanner.scan(content, &context(content_type)).await, what) {
            checks.equal(&verdict, &ScanVerdict::Clean, what);
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("verdicts are repeatable");
    let content = b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
    let first = checks.ok(scanner.scan(content, &context(None)).await, "the first scan");
    let second = checks.ok(scanner.scan(content, &context(None)).await, "the second scan");
    checks.equal(&first, &second, "two scans of the same content");
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
    F: Fn() -> Arc<dyn ContentScanner>,
{
    run(factory).await.assert_ok();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use async_trait::async_trait;
    use davhaven_ports::PortError;

    use super::*;

    /// A scanner that flags content containing a marker.
    struct Marker;

    #[async_trait]
    impl ContentScanner for Marker {
        fn name(&self) -> &'static str {
            "marker"
        }

        async fn scan(&self, content: &[u8], _context: &ScanContext) -> Result<ScanVerdict, PortError> {
            let infected = content.windows(7).any(|window| window == b"MALWARE");
            Ok(if infected {
                ScanVerdict::Infected("marker".to_owned())
            } else {
                ScanVerdict::Clean
            })
        }
    }

    /// A scanner that alternates between verdicts.
    struct Flaky(AtomicU32);

    #[async_trait]
    impl ContentScanner for Flaky {
        fn name(&self) -> &'static str {
            "flaky"
        }

        async fn scan(&self, _content: &[u8], _context: &ScanContext) -> Result<ScanVerdict, PortError> {
            Ok(if self.0.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
                ScanVerdict::Clean
            } else {
                ScanVerdict::Infected("sometimes".to_owned())
            })
        }
    }

    #[tokio::test]
    async fn a_marker_scanner_satisfies_the_contract() {
        run_all(|| Arc::new(Marker)).await;
        assert_eq!(run(|| Arc::new(Marker)).await.case_count(), 3);
    }

    #[tokio::test]
    async fn a_scanner_with_unstable_verdicts_is_caught() {
        let report = run(|| Arc::new(Flaky(AtomicU32::new(0)))).await;
        assert!(report.failed_cases().contains(&"verdicts are repeatable"), "{report}");
        assert!(
            report.failed_cases().contains(&"empty and harmless content is clean"),
            "{report}"
        );
    }
}
