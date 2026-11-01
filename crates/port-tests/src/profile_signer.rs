//! Contract suite of the `ProfileSigner` port.
//!
//! What every signer promises, the `FixedProfileSigner` double included: the signed document carries the profile
//! unchanged (a reader that ignores the signature still reads it), signing is repeatable and follows the profile, and an
//! empty profile is refused as invalid. What only a real signature promises (it verifies, it names the certificate) is
//! checked by the crate of the production signer.

use std::sync::Arc;

use chrono::{DateTime, TimeZone as _, Utc};
use davhaven_ports::{PortErrorKind, ProfileSigner};

use crate::suite::{Checks, ContractReport, Suite};

const FIRST: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>PayloadType</key>\
    <string>Configuration</string></dict></plist>";
const SECOND: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>PayloadType</key>\
    <string>Configuration</string><key>PayloadVersion</key><integer>2</integer></dict></plist>";

fn moment() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 12, 10, 0, 0)
        .single()
        .unwrap_or(DateTime::UNIX_EPOCH)
}

/// Whether `signed` contains `profile` as it is.
fn carries(signed: &[u8], profile: &[u8]) -> bool {
    signed.windows(profile.len()).any(|window| window == profile)
}

/// Runs the suite against signers built by `factory` and returns the report.
pub fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn ProfileSigner>,
{
    let mut suite = Suite::new("profile_signer");
    let signer = factory();

    let mut checks = Checks::new("the signed document carries the profile unchanged");
    for profile in [FIRST, SECOND] {
        if let Some(signed) = checks.ok(signer.sign(profile, moment()), "signing a profile") {
            checks.that(carries(&signed, profile), "the profile is in the signed document");
            checks.that(signed.len() > profile.len(), "the document is more than the profile");
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("signing is repeatable and follows the profile");
    let again = factory();
    let first = checks.ok(signer.sign(FIRST, moment()), "the first signing");
    let repeated = checks.ok(again.sign(FIRST, moment()), "the same profile with another signer");
    let second = checks.ok(signer.sign(SECOND, moment()), "another profile");
    if let (Some(first), Some(repeated), Some(second)) = (first, repeated, second) {
        checks.that(
            carries(&repeated, FIRST),
            "another signer of the same identity signs the same profile",
        );
        checks.differ(&first, &second, "the documents of two profiles");
    }
    suite.record(checks);

    let mut checks = Checks::new("an empty profile is refused");
    if let Some(error) = checks.err(signer.sign(b"", moment()), "signing nothing") {
        checks.equal(&error.kind, &PortErrorKind::Invalid, "the kind of the refusal");
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
    F: Fn() -> Arc<dyn ProfileSigner>,
{
    run(factory).assert_ok();
}

#[cfg(test)]
mod tests {
    use davhaven_ports::PortError;
    use davhaven_ports::testing::FixedProfileSigner;

    use super::*;

    #[test]
    fn the_fixed_signer_satisfies_the_contract() {
        run_all(|| Arc::new(FixedProfileSigner));
        assert_eq!(run(|| Arc::new(FixedProfileSigner)).case_count(), 3);
    }

    /// A signer that drops the profile: the document says nothing about it.
    struct Forgetful;

    impl ProfileSigner for Forgetful {
        fn sign(&self, _profile: &[u8], _signed_at: DateTime<Utc>) -> Result<Vec<u8>, PortError> {
            Ok(b"signature only".to_vec())
        }
    }

    #[test]
    fn a_signer_that_loses_the_profile_or_signs_nothing_is_caught() {
        let report = run(|| Arc::new(Forgetful));
        assert_eq!(
            report.failed_cases(),
            vec![
                "the signed document carries the profile unchanged",
                "signing is repeatable and follows the profile",
                "an empty profile is refused",
            ],
            "{report}"
        );
    }
}
