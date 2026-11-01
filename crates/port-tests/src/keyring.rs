//! Contract suite of the `KeyRing` port.
//!
//! What every key ring promises: signatures verify for the purpose and data they were made for and for nothing
//! else, tampering with any part of a signature is detected, signing is deterministic, and signatures made under a
//! retired key stay verifiable until the key is forgotten. The `FixedKeyRing` double and the production key ring
//! run it.

use std::sync::Arc;

use davhaven_ports::{KeyPurpose, KeyRing, Signature};

use crate::suite::{Checks, ContractReport, Suite};

/// The key ids of the key ring a factory must build.
///
/// The key material of a key id must be a function of the id alone: two rings that both know `k1` sign and verify
/// identically for `k1`. The rotation cases rely on that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRingSpec {
    /// The id of the key `sign` uses.
    pub active: String,
    /// Ids of keys that only verify.
    pub retired: Vec<String>,
}

impl KeyRingSpec {
    /// A ring with one key.
    pub fn single(active: &str) -> Self {
        Self {
            active: active.to_owned(),
            retired: Vec::new(),
        }
    }

    /// A ring whose active key is `active` and that still verifies signatures of `retired`.
    pub fn rotated(active: &str, retired: &[&str]) -> Self {
        Self {
            active: active.to_owned(),
            retired: retired.iter().map(|kid| (*kid).to_owned()).collect(),
        }
    }
}

const DATA: &[u8] = b"page=2&limit=50";

/// Runs the suite against key rings built by `factory` and returns the report.
pub fn run<F>(factory: F) -> ContractReport
where
    F: Fn(KeyRingSpec) -> Arc<dyn KeyRing>,
{
    let mut suite = Suite::new("keyring");
    let ring = factory(KeyRingSpec::single("k1"));

    let mut checks = Checks::new("signatures verify for their purpose and data");
    for purpose in KeyPurpose::ALL {
        let signature = ring.sign(purpose, DATA);
        checks.that(ring.verify(purpose, DATA, &signature), "a fresh signature verifies");
        checks.equal(
            &signature.kid,
            &ring.active_kid(purpose),
            "the key id of a fresh signature",
        );
        checks.that(!signature.mac.is_empty(), "the MAC is not empty");
        let empty = ring.sign(purpose, b"");
        checks.that(
            ring.verify(purpose, b"", &empty),
            "an empty message can be signed and verified",
        );
    }
    suite.record(checks);

    let mut checks = Checks::new("signing is deterministic and data bound");
    for purpose in KeyPurpose::ALL {
        let first = ring.sign(purpose, DATA);
        let second = ring.sign(purpose, DATA);
        checks.equal(&first, &second, "two signatures of the same data");
        let other = ring.sign(purpose, b"page=3&limit=50");
        checks.differ(&first.mac, &other.mac, "MACs of different data");
        checks.that(
            !ring.verify(purpose, b"page=3&limit=50", &first),
            "other data does not verify",
        );
    }
    suite.record(checks);

    let mut checks = Checks::new("purposes are isolated");
    for signing in KeyPurpose::ALL {
        let signature = ring.sign(signing, DATA);
        for verifying in KeyPurpose::ALL {
            if signing != verifying {
                checks.that(
                    !ring.verify(verifying, DATA, &signature),
                    "a signature never verifies for another purpose",
                );
            }
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("tampered signatures are rejected");
    let purpose = KeyPurpose::Cursor;
    let signature = ring.sign(purpose, DATA);
    let mut flipped = signature.clone();
    if let Some(byte) = flipped.mac.first_mut() {
        *byte ^= 0x01;
    }
    checks.that(!ring.verify(purpose, DATA, &flipped), "a flipped bit");
    let mut last = signature.clone();
    if let Some(byte) = last.mac.last_mut() {
        *byte ^= 0x80;
    }
    checks.that(!ring.verify(purpose, DATA, &last), "a flipped bit in the last byte");
    let mut truncated = signature.clone();
    truncated.mac.pop();
    checks.that(!ring.verify(purpose, DATA, &truncated), "a truncated MAC");
    let mut extended = signature.clone();
    extended.mac.push(0);
    checks.that(!ring.verify(purpose, DATA, &extended), "an extended MAC");
    checks.that(
        !ring.verify(purpose, DATA, &Signature::new(signature.kid.clone(), Vec::new())),
        "an empty MAC",
    );
    checks.that(
        !ring.verify(purpose, DATA, &Signature::new("unknown-key", signature.mac.clone())),
        "an unknown key id",
    );
    suite.record(checks);

    suite.record(rotation(&factory));

    suite.finish()
}

/// The rotation case: retired keys stay verifiable until they are forgotten.
fn rotation<F>(factory: &F) -> Checks
where
    F: Fn(KeyRingSpec) -> Arc<dyn KeyRing>,
{
    let mut checks = Checks::new("rotation keeps retired keys verifiable until they are forgotten");
    let old = factory(KeyRingSpec::single("k1"));
    let old_signature = old.sign(KeyPurpose::Rsvp, DATA);
    let rotated = factory(KeyRingSpec::rotated("k2", &["k1"]));
    checks.that(
        rotated.verify(KeyPurpose::Rsvp, DATA, &old_signature),
        "the rotated ring verifies a signature of the retired key",
    );
    checks.equal(
        &rotated.active_kid(KeyPurpose::Rsvp),
        &"k2".to_owned(),
        "the active key after rotation",
    );
    let new_signature = rotated.sign(KeyPurpose::Rsvp, DATA);
    checks.equal(
        &new_signature.kid,
        &"k2".to_owned(),
        "signatures are made with the new key",
    );
    checks.that(
        rotated.verify(KeyPurpose::Rsvp, DATA, &new_signature),
        "the rotated ring verifies its own signature",
    );
    let forgotten = factory(KeyRingSpec::single("k2"));
    checks.that(
        !forgotten.verify(KeyPurpose::Rsvp, DATA, &old_signature),
        "a ring that forgot the key rejects its signatures",
    );

    checks
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
#[track_caller]
pub fn run_all<F>(factory: F)
where
    F: Fn(KeyRingSpec) -> Arc<dyn KeyRing>,
{
    run(factory).assert_ok();
}

#[cfg(test)]
mod tests {
    use davhaven_ports::testing::FixedKeyRing;

    use super::*;

    fn fixed(spec: KeyRingSpec) -> Arc<dyn KeyRing> {
        let mut ring = FixedKeyRing::new(spec.active);
        for kid in spec.retired {
            ring = ring.with_retired_kid(kid);
        }
        Arc::new(ring)
    }

    #[test]
    fn the_fixed_key_ring_satisfies_the_contract() {
        run_all(fixed);
        assert_eq!(run(fixed).case_count(), 5);
    }

    /// A key ring whose MACs do not depend on the purpose and that accepts any MAC of the right length.
    struct Lax(FixedKeyRing);

    impl KeyRing for Lax {
        fn sign(&self, _purpose: KeyPurpose, data: &[u8]) -> Signature {
            self.0.sign(KeyPurpose::Cursor, data)
        }

        fn verify(&self, _purpose: KeyPurpose, data: &[u8], signature: &Signature) -> bool {
            self.0.verify(KeyPurpose::Cursor, data, signature)
        }

        fn active_kid(&self, purpose: KeyPurpose) -> String {
            self.0.active_kid(purpose)
        }
    }

    #[test]
    fn a_key_ring_without_purpose_separation_is_caught() {
        let report = run(|spec| Arc::new(Lax(FixedKeyRing::new(spec.active))));
        assert!(report.failed_cases().contains(&"purposes are isolated"), "{report}");
    }

    #[test]
    fn a_key_ring_that_cannot_rotate_is_caught() {
        let report = run(|spec| Arc::new(FixedKeyRing::new(spec.active)));
        assert_eq!(
            report.failed_cases(),
            vec!["rotation keeps retired keys verifiable until they are forgotten"],
            "{report}"
        );
    }
}
