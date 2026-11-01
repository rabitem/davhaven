//! The `KeyRing` implementation and the key material the other primitives of this crate share.
//!
//! The deployment configures a list of keys (`[security] keys = [...]`), each a long random secret with an id
//! ([`KeysConfig`]). [`KeyMaterial`] holds those secrets. Nothing signs with a secret directly: for every purpose
//! of the ring ([`KeyPurpose`]) and for the sealer, a *subkey* is derived with HKDF-SHA256 from the secret, using a
//! label that names the use, so a MAC made for one purpose can never verify for another and the key of the sealer
//! is unrelated to every MAC key.
//!
//! * [`LocalKeyRing`] signs with HMAC-SHA256 under the subkey of the active key and verifies under the key a
//!   signature names, in constant time. Signatures made before a rotation verify as long as the old key stays in
//!   the configuration.
//! * [`LocalCrypto`] builds the three pure ports (key ring, sealer, credential hasher) from one [`KeyMaterial`], so
//!   the server wires them with one call.
//!
//! Secrets are held in `secrecy` types and derived keys in zeroizing buffers; nothing in this module prints them.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use davhaven_ports::{IdGenerator, KeyPurpose, KeyRing, PluginError, Signature};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::config::{KeyConfig, KeysConfig, MIN_SECRET_CHARS, PLUGIN, check_key_ids};
use crate::hasher::LocalHasher;
use crate::sealer::LocalSealer;

/// The salt of every derivation: it versions the derivation scheme.
const SALT: &[u8] = b"davhaven/key-derivation/v1";

/// A key derived from a configured secret: 256 bits, zeroized on drop.
pub(crate) type DerivedKey = Zeroizing<[u8; 32]>;

/// The secrets of the configured keys, by key id, and which of them is active.
///
/// `Debug` prints key ids only.
#[derive(Clone)]
pub struct KeyMaterial {
    active: String,
    /// The secret of the active key, kept apart so that deriving the signing keys cannot miss it.
    active_secret: SecretString,
    keys: BTreeMap<String, SecretString>,
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("active", &self.active)
            .field("kids", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl KeyMaterial {
    /// Creates key material from key ids and secrets; `active` is the key that signs, hashes and seals new data.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] when there is no key, an id is invalid or used twice, a secret is shorter
    /// than [`MIN_SECRET_CHARS`] characters or `active` names no key. Messages name the key id and never contain a
    /// secret.
    pub fn new(active: &str, keys: Vec<(String, SecretString)>) -> Result<Self, PluginError> {
        check_key_ids(keys.iter().map(|(kid, _)| kid.as_str()), Some(active))?;
        let mut by_id = BTreeMap::new();
        for (kid, secret) in keys {
            if secret.expose_secret().chars().count() < MIN_SECRET_CHARS {
                return Err(PluginError::invalid_config(
                    PLUGIN,
                    format!("the secret of key `{kid}` must be at least {MIN_SECRET_CHARS} characters"),
                ));
            }
            by_id.insert(kid, secret);
        }
        let active_secret = by_id
            .get(active)
            .cloned()
            .ok_or_else(|| PluginError::invalid_config(PLUGIN, "the active key is missing from `keys`"))?;
        Ok(Self {
            active: active.to_owned(),
            active_secret,
            keys: by_id,
        })
    }

    /// Reads the key secrets named by the configuration from their files.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for an invalid key list (the same checks as [`KeysConfig::validate`]) or a
    /// secret file that cannot be read or is too short.
    pub fn from_config(config: &KeysConfig) -> Result<Self, PluginError> {
        let keys = config
            .keys
            .iter()
            .map(|key: &KeyConfig| KeysConfig::read_secret(key).map(|secret| (key.id.clone(), secret)))
            .collect::<Result<Vec<_>, _>>()?;
        let active = config
            .active_key_id
            .clone()
            .or_else(|| config.keys.first().map(|key| key.id.clone()))
            .unwrap_or_default();
        Self::new(&active, keys)
    }

    /// The id of the key that signs, hashes and seals new data.
    pub fn active_kid(&self) -> &str {
        &self.active
    }

    /// The ids of all keys, in id order.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    /// Derives the 256-bit subkey of key `kid` for the use named by `label`, or `None` for an unknown key id.
    pub(crate) fn derive(&self, kid: &str, label: &str) -> Option<DerivedKey> {
        let secret = self.keys.get(kid)?;
        Some(expand(secret.expose_secret(), label))
    }

    /// Derives the subkey of the active key for `label`. The active key always exists, so unlike
    /// [`KeyMaterial::derive`] this cannot come back empty-handed.
    pub(crate) fn derive_active(&self, label: &str) -> DerivedKey {
        expand(self.active_secret.expose_secret(), label)
    }

    /// The derived key of every id, for a use named by `label`.
    pub(crate) fn derive_all(&self, label: &str) -> BTreeMap<String, DerivedKey> {
        self.keys
            .keys()
            .filter_map(|kid| self.derive(kid, label).map(|key| (kid.clone(), key)))
            .collect()
    }
}

/// HKDF-SHA256 of `secret` with the label as `info`, 256 bits.
fn expand(secret: &str, label: &str) -> DerivedKey {
    let hkdf = Hkdf::<Sha256>::new(Some(SALT), secret.as_bytes());
    let mut okm = Zeroizing::new([0_u8; 32]);
    if hkdf.expand(label.as_bytes(), okm.as_mut_slice()).is_err() {
        // 32 bytes are far below the HKDF limit of 255 hash lengths: the expansion cannot fail. Should it ever,
        // the key is still a function of the secret and the label (never a constant that anyone could compute).
        let digest = Sha256::new()
            .chain_update(SALT)
            .chain_update(label.as_bytes())
            .chain_update(secret.as_bytes())
            .finalize();
        okm.as_mut_slice().copy_from_slice(&digest);
    }
    okm
}

/// HMAC-SHA256 of `data` under `key`. An empty tag in the impossible case that the key is refused (HMAC accepts
/// every key length) is a tag that never verifies.
fn hmac_tag(key: &[u8], data: &[u8]) -> Vec<u8> {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return Vec::new();
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time check that `tag` is the HMAC-SHA256 of `data` under `key`.
fn hmac_verifies(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// The label of the subkey of a ring purpose.
fn purpose_label(purpose: KeyPurpose) -> String {
    format!("davhaven/keyring/v1/{}", purpose.as_str())
}

/// The signing keys of the active key, one per purpose, as fields: signing never looks up a key that might be
/// missing, and a purpose added to the port does not compile until it has its key here.
struct ActiveKeys {
    credential_pepper: DerivedKey,
    rsvp: DerivedKey,
    csrf: DerivedKey,
    cursor: DerivedKey,
    cache_key: DerivedKey,
}

impl ActiveKeys {
    fn derive(material: &KeyMaterial) -> Self {
        let of = |purpose: KeyPurpose| material.derive_active(&purpose_label(purpose));
        Self {
            credential_pepper: of(KeyPurpose::CredentialPepper),
            rsvp: of(KeyPurpose::Rsvp),
            csrf: of(KeyPurpose::Csrf),
            cursor: of(KeyPurpose::Cursor),
            cache_key: of(KeyPurpose::CacheKey),
        }
    }

    const fn of(&self, purpose: KeyPurpose) -> &DerivedKey {
        match purpose {
            KeyPurpose::CredentialPepper => &self.credential_pepper,
            KeyPurpose::Rsvp => &self.rsvp,
            KeyPurpose::Csrf => &self.csrf,
            KeyPurpose::Cursor => &self.cursor,
            KeyPurpose::CacheKey => &self.cache_key,
        }
    }
}

/// The key ring: HMAC-SHA256 with one HKDF-derived subkey per key id and purpose.
pub struct LocalKeyRing {
    active: String,
    signing: ActiveKeys,
    keys: BTreeMap<String, BTreeMap<KeyPurpose, DerivedKey>>,
}

impl fmt::Debug for LocalKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalKeyRing")
            .field("active", &self.active)
            .field("kids", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl LocalKeyRing {
    /// Derives the subkeys of every key of `material`.
    pub fn new(material: &KeyMaterial) -> Self {
        let mut keys: BTreeMap<String, BTreeMap<KeyPurpose, DerivedKey>> = BTreeMap::new();
        for purpose in KeyPurpose::ALL {
            for (kid, key) in material.derive_all(&purpose_label(purpose)) {
                keys.entry(kid).or_default().insert(purpose, key);
            }
        }
        Self {
            active: material.active_kid().to_owned(),
            signing: ActiveKeys::derive(material),
            keys,
        }
    }

    fn key(&self, kid: &str, purpose: KeyPurpose) -> Option<&DerivedKey> {
        self.keys.get(kid)?.get(&purpose)
    }
}

impl KeyRing for LocalKeyRing {
    fn sign(&self, purpose: KeyPurpose, data: &[u8]) -> Signature {
        Signature::new(self.active.clone(), hmac_tag(self.signing.of(purpose).as_slice(), data))
    }

    fn verify(&self, purpose: KeyPurpose, data: &[u8], signature: &Signature) -> bool {
        self.key(&signature.kid, purpose)
            .is_some_and(|key| hmac_verifies(key.as_slice(), data, &signature.mac))
    }

    fn active_kid(&self, _purpose: KeyPurpose) -> String {
        self.active.clone()
    }
}

/// The three pure cryptographic ports, built from one [`KeyMaterial`].
///
/// The server injects them directly into the plugin context and the application (PLAN 2.3); they are not selected
/// by name.
#[derive(Debug, Clone)]
pub struct LocalCrypto {
    /// Signs cursors, CSRF tokens, RSVP derivations and cache keys.
    pub keyring: Arc<LocalKeyRing>,
    /// Seals webhook secrets, OAuth tokens and PKCE verifiers at rest.
    pub sealer: Arc<LocalSealer>,
    /// Hashes the server-generated credential secrets.
    pub hasher: Arc<LocalHasher>,
}

impl LocalCrypto {
    /// Builds the ports from `material`. `ids` is the source of nonces for the sealer.
    pub fn new(material: &KeyMaterial, ids: Arc<dyn IdGenerator>) -> Self {
        let keyring = Arc::new(LocalKeyRing::new(material));
        let keyring_port: Arc<dyn KeyRing> = Arc::<LocalKeyRing>::clone(&keyring);
        Self {
            sealer: Arc::new(LocalSealer::new(material, ids)),
            hasher: Arc::new(LocalHasher::new(keyring_port)),
            keyring,
        }
    }

    /// Reads the keys of `config` and builds the ports.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`], see [`KeyMaterial::from_config`].
    pub fn from_config(config: &KeysConfig, ids: Arc<dyn IdGenerator>) -> Result<Self, PluginError> {
        Ok(Self::new(&KeyMaterial::from_config(config)?, ids))
    }
}

/// Key material for the tests of this crate.
#[cfg(test)]
pub(crate) mod fixtures {
    use secrecy::SecretString;

    use super::KeyMaterial;

    /// The secret of a key id: a function of the id alone, as the contract suites require.
    pub(crate) fn secret_of(kid: &str) -> SecretString {
        SecretString::from(format!("test-secret-of-key-{kid}-0123456789abcdef0123456789"))
    }

    /// Key material with an active key and retired ones.
    pub(crate) fn material_of(active: &str, retired: &[String]) -> KeyMaterial {
        let mut keys = vec![(active.to_owned(), secret_of(active))];
        keys.extend(retired.iter().map(|kid| (kid.clone(), secret_of(kid))));
        KeyMaterial::new(active, keys).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use davhaven_port_tests::keyring::{KeyRingSpec, run, run_all};
    use davhaven_ports::KeyPurpose;
    use proptest::prelude::*;

    use super::fixtures::{material_of, secret_of};
    use super::*;

    /// Active key id, the configured keys and the words of the expected error.
    type Case = (&'static str, Vec<(String, SecretString)>, &'static str);

    fn ring(spec: KeyRingSpec) -> Arc<dyn KeyRing> {
        let KeyRingSpec { active, retired } = spec;
        Arc::new(LocalKeyRing::new(&material_of(&active, &retired)))
    }

    #[test]
    fn the_local_key_ring_satisfies_the_contract() {
        run_all(ring);
        assert_eq!(run(ring).case_count(), 5);
    }

    #[test]
    fn material_is_validated_without_leaking_secrets() {
        let good = || secret_of("k1");
        let short = SecretString::from("short-secret-hunter2");
        let cases: Vec<Case> = vec![
            ("k1", vec![], "at least one key"),
            ("k1", vec![("K1".to_owned(), good())], "must be 1 to 32 characters"),
            ("k1", vec![("k1".to_owned(), short)], "at least 32 characters"),
            (
                "k1",
                vec![("k1".to_owned(), good()), ("k1".to_owned(), good())],
                "used twice",
            ),
            ("k2", vec![("k1".to_owned(), good())], "active_key_id"),
        ];
        for (active, keys, expected) in cases {
            let error = KeyMaterial::new(active, keys).unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
            assert!(!error.contains("hunter2"), "{error}");
        }
    }

    #[test]
    fn debug_output_names_key_ids_only() {
        let material = material_of("k1", &["k0".to_owned()]);
        let shown = format!("{material:?} {:?}", LocalKeyRing::new(&material));
        assert!(shown.contains("k1") && shown.contains("k0"), "{shown}");
        assert!(!shown.contains("test-secret"), "{shown}");
        assert_eq!(material.kids().collect::<Vec<_>>(), vec!["k0", "k1"]);
        assert_eq!(material.active_kid(), "k1");
    }

    #[test]
    fn subkeys_depend_on_key_and_purpose_and_are_stable() {
        let material = material_of("k1", &["k2".to_owned()]);
        let a = material.derive("k1", "davhaven/keyring/v1/cursor").unwrap();
        assert_eq!(a, material.derive("k1", "davhaven/keyring/v1/cursor").unwrap());
        assert_ne!(a, material.derive("k1", "davhaven/keyring/v1/csrf").unwrap());
        assert_ne!(a, material.derive("k2", "davhaven/keyring/v1/cursor").unwrap());
        assert!(material.derive("nope", "x").is_none());
        assert_eq!(
            material.derive_active("davhaven/keyring/v1/cursor"),
            material.derive("k1", "davhaven/keyring/v1/cursor").unwrap(),
            "the active key derives the same subkey without a lookup"
        );
    }

    #[test]
    fn signing_never_comes_back_empty_for_any_purpose() {
        let ring = LocalKeyRing::new(&material_of("k1", &["k2".to_owned()]));
        let mut seen = Vec::new();
        for purpose in KeyPurpose::ALL {
            let signature = ring.sign(purpose, b"data");
            assert_eq!(signature.mac.len(), 32, "{purpose}");
            assert_eq!(signature.kid, "k1");
            assert!(ring.verify(purpose, b"data", &signature));
            seen.push(signature.mac);
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), KeyPurpose::ALL.len(), "every purpose has its own key");
    }

    #[test]
    fn a_known_answer_pins_the_derivation_scheme() {
        // The MAC of one purpose and message under one fixed secret, computed with an independent implementation
        // (HKDF and HMAC of the Node.js crypto module). A change of the salt, the labels or the algorithms would
        // invalidate every stored credential hash and signed cursor, so it must be deliberate.
        let ring = LocalKeyRing::new(&material_of("k1", &[]));
        let signature = ring.sign(KeyPurpose::CredentialPepper, b"pin");
        let mut hex = String::new();
        for byte in &signature.mac {
            write!(hex, "{byte:02x}").unwrap();
        }
        assert_eq!(hex.len(), 64);
        assert_eq!(signature.kid, "k1");
        assert_eq!(
            hex, "d0369f61e681b809db7bfe2aeb13405bf50aa5634ef9de3f6ad4ace853c6ce61",
            "update this pin only when the key derivation changes on purpose"
        );
    }

    proptest! {
        #[test]
        fn signatures_verify_for_their_data_only(data in proptest::collection::vec(any::<u8>(), 0..200), other in proptest::collection::vec(any::<u8>(), 0..200)) {
            let ring = LocalKeyRing::new(&material_of("k1", &[]));
            let signature = ring.sign(KeyPurpose::Cursor, &data);
            prop_assert!(ring.verify(KeyPurpose::Cursor, &data, &signature));
            prop_assert_eq!(ring.verify(KeyPurpose::Cursor, &other, &signature), data == other);
        }
    }
}
