//! Contract suite of the `CredentialHasher` port.
//!
//! What every hasher promises: a secret verifies against its own hash, nothing else does (other secrets, other
//! credential kinds, tampered or truncated hashes, other pepper key ids), and hashing is deterministic because the
//! credential lookup never compares anything but the keyed hash. The `FixedHasher` double and the production
//! HMAC hasher run it.

use std::sync::Arc;

use davhaven_domain::CredentialKind;
use davhaven_ports::{CredentialHasher, StoredHash};
use secrecy::SecretString;

use crate::suite::{Checks, ContractReport, Suite};

const SECRET: &str = "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23";

fn secret(text: &str) -> SecretString {
    SecretString::from(text)
}

/// Runs the suite against hashers built by `factory` and returns the report.
///
/// All hashers a factory returns share their pepper, so a hash made by one verifies with another.
pub fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn CredentialHasher>,
{
    let mut suite = Suite::new("hasher");
    let hasher = factory();

    let mut checks = Checks::new("a secret verifies against its own hash");
    for kind in CredentialKind::ALL {
        let stored = hasher.hash(*kind, &secret(SECRET));
        checks.equal(&stored.kind, kind, "the kind of the stored hash");
        checks.that(!stored.pepper_kid.is_empty(), "the pepper key id is recorded");
        checks.that(stored.hash.len() >= 16, "the hash has at least 128 bits");
        checks.that(hasher.verify(&stored, &secret(SECRET)), "the right secret verifies");
    }
    suite.record(checks);

    let mut checks = Checks::new("other secrets do not verify");
    let stored = hasher.hash(CredentialKind::AppPassword, &secret(SECRET));
    for (what, other) in [
        ("the empty secret", ""),
        ("a changed last character", "abcd-efgh-ijkl-mnop-qrst-uvwx-yz24"),
        ("a prefix", "abcd-efgh-ijkl-mnop-qrst-uvwx-yz2"),
        ("an extension", "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23x"),
        ("upper case", "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23"),
        ("surrounding whitespace", " abcd-efgh-ijkl-mnop-qrst-uvwx-yz23"),
    ] {
        checks.that(!hasher.verify(&stored, &secret(other)), what);
    }
    suite.record(checks);

    let mut checks = Checks::new("hashes are deterministic, kind bound and secret bound");
    let again = hasher.hash(CredentialKind::AppPassword, &secret(SECRET));
    checks.equal(&stored, &again, "two hashes of the same secret and kind");
    let as_token = hasher.hash(CredentialKind::ApiToken, &secret(SECRET));
    checks.differ(&stored.hash, &as_token.hash, "hashes of one secret as two kinds");
    let relabelled = StoredHash::new(CredentialKind::ApiToken, stored.pepper_kid.clone(), stored.hash.clone());
    checks.that(
        !hasher.verify(&relabelled, &secret(SECRET)),
        "a hash relabelled as another kind does not verify",
    );
    let other_secret = hasher.hash(CredentialKind::AppPassword, &secret("another-secret"));
    checks.differ(&stored.hash, &other_secret.hash, "hashes of two secrets");
    suite.record(checks);

    let mut checks = Checks::new("tampered hashes do not verify");
    let mut flipped = stored.clone();
    if let Some(byte) = flipped.hash.first_mut() {
        *byte ^= 0x01;
    }
    checks.that(!hasher.verify(&flipped, &secret(SECRET)), "a flipped bit");
    let mut truncated = stored.clone();
    truncated.hash.pop();
    checks.that(!hasher.verify(&truncated, &secret(SECRET)), "a truncated hash");
    let mut extended = stored.clone();
    extended.hash.push(0);
    checks.that(!hasher.verify(&extended, &secret(SECRET)), "an extended hash");
    let empty = StoredHash::new(stored.kind, stored.pepper_kid.clone(), Vec::new());
    checks.that(!hasher.verify(&empty, &secret(SECRET)), "an empty hash");
    let unknown_key = StoredHash::new(stored.kind, "no-such-pepper", stored.hash.clone());
    checks.that(
        !hasher.verify(&unknown_key, &secret(SECRET)),
        "an unknown pepper key id",
    );
    suite.record(checks);

    let mut checks = Checks::new("hashes verify with another hasher of the same pepper");
    let second = factory();
    checks.that(
        second.verify(&stored, &secret(SECRET)),
        "a hash made by one hasher verifies with another",
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
    F: Fn() -> Arc<dyn CredentialHasher>,
{
    run(factory).assert_ok();
}

#[cfg(test)]
mod tests {
    use davhaven_ports::testing::FixedHasher;

    use super::*;

    #[test]
    fn the_fixed_hasher_satisfies_the_contract() {
        run_all(|| Arc::new(FixedHasher::default()));
        assert_eq!(run(|| Arc::new(FixedHasher::default())).case_count(), 5);
    }

    /// A hasher that ignores the credential kind and compares only prefixes.
    struct Sloppy;

    impl CredentialHasher for Sloppy {
        fn hash(&self, kind: CredentialKind, secret: &SecretString) -> StoredHash {
            use secrecy::ExposeSecret as _;
            let first = secret.expose_secret().bytes().next().unwrap_or(0);
            StoredHash::new(kind, "sloppy", vec![first; 16])
        }

        fn verify(&self, stored: &StoredHash, secret: &SecretString) -> bool {
            use secrecy::ExposeSecret as _;
            let first = secret.expose_secret().bytes().next().unwrap_or(0);
            stored.hash.first() == Some(&first)
        }
    }

    #[test]
    fn a_hasher_that_only_checks_the_first_character_is_caught() {
        let report = run(|| Arc::new(Sloppy));
        let failed = report.failed_cases();
        assert!(failed.contains(&"other secrets do not verify"), "{report}");
        assert!(failed.contains(&"tampered hashes do not verify"), "{report}");
    }

    #[test]
    fn hashers_with_different_peppers_are_caught_by_the_shared_pepper_case() {
        let counter = std::sync::atomic::AtomicU32::new(0);
        let report = run(|| {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Arc::new(FixedHasher::new(format!("pepper-{n}")))
        });
        assert!(
            report
                .failed_cases()
                .contains(&"hashes verify with another hasher of the same pepper"),
            "{report}"
        );
    }
}
