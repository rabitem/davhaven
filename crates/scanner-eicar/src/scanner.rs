//! The scanner: a search for the EICAR test string.

use async_trait::async_trait;
use davhaven_ports::{ContentScanner, PortError, ScanContext, ScanVerdict};

use crate::config::PLUGIN;

/// The EICAR anti-virus test file. The source holds it in three pieces, so that this file is not itself mistaken for one
/// by a scanner that reads the repository; `concat!` joins them at compile time.
pub const EICAR: &[u8] = concat!(
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
    "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!",
    "$H+H*"
)
.as_bytes();

/// The finding reported for the test string.
pub const FINDING: &str = "EICAR-Test-File";

/// A scanner that finds the EICAR test string and nothing else.
#[derive(Debug, Clone, Copy, Default)]
pub struct EicarScanner;

#[async_trait]
impl ContentScanner for EicarScanner {
    fn name(&self) -> &'static str {
        PLUGIN
    }

    async fn scan(&self, content: &[u8], _context: &ScanContext) -> Result<ScanVerdict, PortError> {
        if content.windows(EICAR.len()).any(|window| window == EICAR) {
            Ok(ScanVerdict::Infected(FINDING.to_owned()))
        } else {
            Ok(ScanVerdict::Clean)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use davhaven_domain::TenantId;
    use uuid::Uuid;

    use super::*;

    fn context() -> ScanContext {
        ScanContext {
            tenant: TenantId::from_uuid(Uuid::from_u128(1)),
            content_type: None,
        }
    }

    #[tokio::test]
    async fn the_scanner_finds_the_test_string_anywhere_in_the_content() {
        let scanner = EicarScanner;
        assert_eq!(scanner.name(), "eicar");
        assert_eq!(
            scanner.scan(b"harmless bytes", &context()).await.unwrap(),
            ScanVerdict::Clean
        );
        assert_eq!(scanner.scan(b"", &context()).await.unwrap(), ScanVerdict::Clean);
        let mut payload = b"prefix ".to_vec();
        payload.extend_from_slice(EICAR);
        payload.extend_from_slice(b" suffix");
        assert_eq!(
            scanner.scan(&payload, &context()).await.unwrap(),
            ScanVerdict::Infected(FINDING.to_owned())
        );
        let mut truncated = EICAR.to_vec();
        truncated.pop();
        assert_eq!(
            scanner.scan(&truncated, &context()).await.unwrap(),
            ScanVerdict::Clean,
            "a part of the string is not the string"
        );
    }

    #[test]
    fn the_constant_is_the_published_test_string() {
        // Spelled backwards here, so that neither this file nor the expectation is the constant under test: a typo in
        // one of its three pieces would make the scanner miss the real test file while every other test passed.
        let published: Vec<u8> = r"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X"
            .bytes()
            .rev()
            .collect();
        assert_eq!(EICAR.len(), 68);
        assert_eq!(EICAR, published.as_slice());
    }

    #[tokio::test]
    async fn the_scanner_runs_the_contract_suite_of_its_port() {
        davhaven_port_tests::scanner::run_all(|| Arc::new(EicarScanner)).await;
    }
}
