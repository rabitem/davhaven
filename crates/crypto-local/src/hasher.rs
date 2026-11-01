//! The `CredentialHasher` implementation: keyed HMAC of server-generated credential secrets.
//!
//! Credentials carry at least 128 secret bits (PLAN 2.6, R6), so there is nothing to slow down: the stored form is
//! HMAC-SHA256 under the pepper subkey of the key ring ([`KeyPurpose::CredentialPepper`]), computed over a frame
//! that names the credential kind, so the hash of an app password never verifies as a token and a database dump
//! without the key ring reveals nothing that can be tested offline. Verification costs microseconds, compares in
//! constant time and names the pepper key by id, so hashes made before a key rotation keep verifying while the old
//! key stays configured, and a credential that is used moves to the active key (the authenticator hashes it again, see
//! `davhaven_auth_local`). Argon2id is reserved for human-chosen secrets, of which 1.0 has none.

use std::sync::Arc;

use davhaven_domain::CredentialKind;
use davhaven_ports::{CredentialHasher, KeyPurpose, KeyRing, Signature, StoredHash};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// The version label at the start of every hashed frame.
const FRAME: &[u8] = b"davhaven/credential/v1";

/// The bytes that are authenticated: the frame, the credential kind and the secret, separated by zero bytes so
/// that no two (kind, secret) pairs share an encoding. The buffer is zeroized when it is dropped.
fn message(kind: CredentialKind, secret: &SecretString) -> Zeroizing<Vec<u8>> {
    let secret = secret.expose_secret().as_bytes();
    let kind = kind.as_str().as_bytes();
    let mut message = Zeroizing::new(Vec::with_capacity(FRAME.len() + kind.len() + secret.len() + 2));
    message.extend_from_slice(FRAME);
    message.push(0);
    message.extend_from_slice(kind);
    message.push(0);
    message.extend_from_slice(secret);
    message
}

/// Hashes credentials with the pepper of a key ring.
#[derive(Clone)]
pub struct LocalHasher {
    keyring: Arc<dyn KeyRing>,
}

impl core::fmt::Debug for LocalHasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalHasher").finish_non_exhaustive()
    }
}

impl LocalHasher {
    /// A hasher whose pepper is the `CredentialPepper` key of `keyring`.
    pub fn new(keyring: Arc<dyn KeyRing>) -> Self {
        Self { keyring }
    }
}

impl CredentialHasher for LocalHasher {
    fn hash(&self, kind: CredentialKind, secret: &SecretString) -> StoredHash {
        let signature = self.keyring.sign(KeyPurpose::CredentialPepper, &message(kind, secret));
        StoredHash::new(kind, signature.kid, signature.mac)
    }

    fn verify(&self, stored: &StoredHash, secret: &SecretString) -> bool {
        let signature = Signature::new(stored.pepper_kid.clone(), stored.hash.clone());
        self.keyring
            .verify(KeyPurpose::CredentialPepper, &message(stored.kind, secret), &signature)
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use davhaven_port_tests::hasher::{run, run_all};

    use super::*;
    use crate::keyring::LocalKeyRing;
    use crate::keyring::fixtures::material_of;

    fn hasher() -> Arc<dyn CredentialHasher> {
        Arc::new(LocalHasher::new(Arc::new(LocalKeyRing::new(&material_of(
            "pepper-1",
            &[],
        )))))
    }

    #[test]
    fn the_local_hasher_satisfies_the_contract() {
        run_all(hasher);
        assert_eq!(run(hasher).case_count(), 5);
    }

    #[test]
    fn hashes_made_under_a_retired_pepper_keep_verifying_after_a_rotation() {
        let old = LocalHasher::new(Arc::new(LocalKeyRing::new(&material_of("pepper-1", &[]))));
        let rotated = LocalHasher::new(Arc::new(LocalKeyRing::new(&material_of(
            "pepper-2",
            &["pepper-1".to_owned()],
        ))));
        let secret = SecretString::from("abcd-efgh-ijkl-mnop-qrst-uvwx-yz23");
        let stored = old.hash(CredentialKind::AppPassword, &secret);
        assert_eq!(stored.pepper_kid, "pepper-1");
        assert!(rotated.verify(&stored, &secret));
        assert_eq!(
            rotated.hash(CredentialKind::AppPassword, &secret).pepper_kid,
            "pepper-2"
        );
        let forgotten = LocalHasher::new(Arc::new(LocalKeyRing::new(&material_of("pepper-2", &[]))));
        assert!(
            !forgotten.verify(&stored, &secret),
            "a forgotten pepper verifies nothing"
        );
    }

    #[test]
    fn the_frame_separates_kind_and_secret() {
        // Without separators ("api_token" + "x" and "api_toke" + "nx") could collide.
        let a = message(CredentialKind::ApiToken, &SecretString::from("x"));
        let b = message(CredentialKind::AppPassword, &SecretString::from("x"));
        assert_ne!(a.as_slice(), b.as_slice());
        assert!(a.starts_with(FRAME));
    }

    #[test]
    fn a_known_answer_pins_the_stored_form_of_a_credential() {
        // Computed with an independent implementation (Python `hmac` and HKDF from RFC 5869) over the frame
        // `davhaven/credential/v1 NUL {kind} NUL {secret}` under the pepper subkey of `pepper-1`. Every stored hash of
        // a deployment depends on these bytes: a change of the frame, the kind names or the derivation locks every
        // user out, so it must be deliberate.
        let secret = SecretString::from("abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh");
        let hasher = hasher();
        let hex = |bytes: &[u8]| {
            let mut hex = String::new();
            for byte in bytes {
                write!(hex, "{byte:02x}").unwrap();
            }
            hex
        };
        let app_password = hasher.hash(CredentialKind::AppPassword, &secret);
        assert_eq!(app_password.pepper_kid, "pepper-1");
        assert_eq!(app_password.kind, CredentialKind::AppPassword);
        assert_eq!(
            hex(&app_password.hash),
            "9fcf4d397837a64a745389c8332efd699fb83df98d23586ebed52b7ed1864c77"
        );
        let api_token = hasher.hash(CredentialKind::ApiToken, &secret);
        assert_eq!(
            hex(&api_token.hash),
            "d9d4f138078f4e1199e05ba0065c061b9eef7185636fbf37096415f5284c6f7d"
        );
        // The same secret stored as one kind does not verify as another.
        let relabelled = StoredHash::new(
            CredentialKind::ApiToken,
            app_password.pepper_kid.clone(),
            app_password.hash,
        );
        assert!(!hasher.verify(&relabelled, &secret));
    }

    #[test]
    fn debug_output_shows_nothing_secret() {
        let shown = format!(
            "{:?}",
            LocalHasher::new(Arc::new(LocalKeyRing::new(&material_of("k", &[]))))
        );
        assert_eq!(shown, "LocalHasher { .. }");
    }
}
