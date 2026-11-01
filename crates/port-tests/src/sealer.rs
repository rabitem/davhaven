//! Contract suites of the `SecretSealer` port.
//!
//! [`run`] holds what every sealer promises, including the `PlainSealer` double: values round-trip, they open only
//! with the associated data they were sealed with, and bytes that are not a sealed value are rejected as invalid.
//! [`run_authenticated`] adds what only a real AEAD promises (tampering is detected, nonces differ, the plaintext
//! is not visible) and is run by production sealers only.

use std::sync::Arc;

use davhaven_domain::TenantId;
use davhaven_ports::{PortErrorKind, SealAad, Sealed, SecretSealer};
use secrecy::ExposeSecret as _;
use uuid::Uuid;

use crate::suite::{Checks, ContractReport, Suite};

fn aad(tenant: u128, table: &'static str, row: u128, purpose: &'static str) -> SealAad {
    SealAad::new(
        TenantId::from_uuid(Uuid::from_u128(tenant)),
        table,
        Uuid::from_u128(row),
        purpose,
    )
}

fn base_aad() -> SealAad {
    aad(1, "webhook_subscriptions", 2, "webhook_secret")
}

/// Runs the suite every sealer must pass against sealers built by `factory` and returns the report.
///
/// All sealers a factory returns share their key material, so a value sealed by one opens with another.
pub fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn SecretSealer>,
{
    let mut suite = Suite::new("sealer");
    let sealer = factory();

    let mut checks = Checks::new("values round-trip");
    let large = vec![0xA5_u8; 4096];
    for plaintext in [
        &b""[..],
        &b"whsec_abcdefghijklmnop"[..],
        &b"\x00\x01\xff"[..],
        large.as_slice(),
    ] {
        if let Some(sealed) = checks.ok(sealer.seal(plaintext, &base_aad()), "sealing")
            && let Some(opened) = checks.ok(sealer.open(&sealed, &base_aad()), "opening")
        {
            checks.equal(
                &opened.expose_secret().to_vec(),
                &plaintext.to_vec(),
                "the opened plaintext",
            );
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("sealed values open with another sealer of the same keys");
    let first = factory();
    let second = factory();
    if let Some(sealed) = checks.ok(first.seal(b"secret", &base_aad()), "sealing")
        && let Some(opened) = checks.ok(second.open(&sealed, &base_aad()), "opening with a second sealer")
    {
        checks.equal(
            &opened.expose_secret().to_vec(),
            &b"secret".to_vec(),
            "the opened plaintext",
        );
    }
    suite.record(checks);

    let mut checks = Checks::new("the associated data is bound");
    if let Some(sealed) = checks.ok(sealer.seal(b"secret", &base_aad()), "sealing") {
        let variants = [
            ("another tenant", aad(9, "webhook_subscriptions", 2, "webhook_secret")),
            ("another table", aad(1, "oauth_states", 2, "webhook_secret")),
            ("another row", aad(1, "webhook_subscriptions", 3, "webhook_secret")),
            ("another purpose", aad(1, "webhook_subscriptions", 2, "oauth_tokens")),
        ];
        for (what, other) in variants {
            if let Some(error) = checks.err(sealer.open(&sealed, &other), what) {
                checks.equal(&error.kind, &PortErrorKind::Rejected, what);
            }
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("bytes that are not a sealed value are invalid");
    for garbage in [Vec::new(), b"nope".to_vec(), vec![0; 64], b"davhaven".repeat(8)] {
        if let Some(error) = checks.err(sealer.open(&Sealed::from_bytes(garbage), &base_aad()), "garbage") {
            checks.equal(&error.kind, &PortErrorKind::Invalid, "the kind of error for garbage");
        }
    }
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
    F: Fn() -> Arc<dyn SecretSealer>,
{
    run(factory).assert_ok();
}

/// Runs the cases only an authenticated, randomized encryption passes, and returns the report.
pub fn run_authenticated<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn SecretSealer>,
{
    let mut suite = Suite::new("sealer (authenticated)");
    let sealer = factory();
    let plaintext = b"whsec_abcdefghijklmnop";

    let mut checks = Checks::new("any modified byte is detected");
    if let Some(sealed) = checks.ok(sealer.seal(plaintext, &base_aad()), "sealing") {
        let bytes = sealed.as_bytes().to_vec();
        for index in 0..bytes.len() {
            let mut modified = bytes.clone();
            if let Some(byte) = modified.get_mut(index) {
                *byte ^= 0x01;
            }
            if sealer.open(&Sealed::from_bytes(modified), &base_aad()).is_ok() {
                checks.fail(format!(
                    "flipping a bit of byte {index} of {} went unnoticed",
                    bytes.len()
                ));
            }
        }
        let mut truncated = bytes.clone();
        truncated.pop();
        checks.that(
            sealer.open(&Sealed::from_bytes(truncated), &base_aad()).is_err(),
            "a truncated value is rejected",
        );
        let mut extended = bytes;
        extended.push(0);
        checks.that(
            sealer.open(&Sealed::from_bytes(extended), &base_aad()).is_err(),
            "an extended value is rejected",
        );
    }
    suite.record(checks);

    let mut checks = Checks::new("sealing is randomized and hides the plaintext");
    let first = checks.ok(sealer.seal(plaintext, &base_aad()), "sealing the first time");
    let second = checks.ok(sealer.seal(plaintext, &base_aad()), "sealing the second time");
    if let (Some(first), Some(second)) = (first, second) {
        checks.differ(
            &first.as_bytes(),
            &second.as_bytes(),
            "two sealed copies of one plaintext",
        );
        for sealed in [&first, &second] {
            let visible = sealed
                .as_bytes()
                .windows(plaintext.len())
                .any(|window| window == plaintext);
            checks.that(!visible, "the plaintext does not appear in the sealed bytes");
        }
    }
    suite.record(checks);

    suite.finish()
}

/// Runs the authenticated cases and fails the running test when any of them fails.
///
/// # Panics
///
/// When a case fails.
#[track_caller]
pub fn run_authenticated_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn SecretSealer>,
{
    run_authenticated(factory).assert_ok();
}

#[cfg(test)]
mod tests {
    use davhaven_ports::PortError;
    use davhaven_ports::SecretBytes;
    use davhaven_ports::testing::PlainSealer;

    use super::*;

    #[test]
    fn the_plain_sealer_satisfies_the_common_contract_but_is_not_authenticated() {
        run_all(|| Arc::new(PlainSealer));
        assert_eq!(run(|| Arc::new(PlainSealer)).case_count(), 4);
        let report = run_authenticated(|| Arc::new(PlainSealer));
        assert_eq!(
            report.failed_cases(),
            vec![
                "any modified byte is detected",
                "sealing is randomized and hides the plaintext"
            ],
            "the double does not encrypt, so it must not pass the authenticated suite: {report}"
        );
    }

    /// A sealer that ignores the associated data and reports every open error as invalid.
    struct IgnoresAad;

    impl SecretSealer for IgnoresAad {
        fn seal(&self, plaintext: &[u8], _aad: &SealAad) -> Result<Sealed, PortError> {
            Ok(Sealed::from_bytes(plaintext.to_vec()))
        }

        fn open(&self, sealed: &Sealed, _aad: &SealAad) -> Result<SecretBytes, PortError> {
            Ok(SecretBytes::from(sealed.as_bytes().to_vec()))
        }
    }

    #[test]
    fn a_sealer_that_ignores_the_associated_data_is_caught() {
        let report = run(|| Arc::new(IgnoresAad));
        let failed = report.failed_cases();
        assert!(failed.contains(&"the associated data is bound"), "{report}");
        assert!(
            failed.contains(&"bytes that are not a sealed value are invalid"),
            "{report}"
        );
    }
}
