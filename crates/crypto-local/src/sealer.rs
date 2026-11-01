//! The `SecretSealer` implementation: XChaCha20-Poly1305 with associated data that binds the sealed value to its
//! place.
//!
//! Webhook secrets, OAuth tokens and PKCE verifiers are stored sealed (PLAN 2.4). A sealed value is
//!
//! ```text
//! version (1 byte, = 1) | key id length (1 byte) | key id | nonce (24 bytes) | ciphertext | tag (16 bytes)
//! ```
//!
//! The key is derived from the configured key secret with HKDF (label `davhaven/sealer/v1`), so it is unrelated to
//! every MAC key of the key ring. The nonce is 192 bits of randomness from the `IdGenerator`, which is large
//! enough that random nonces never repeat. The associated data is the version, the key id and the canonical
//! encoding of the [`SealAad`] (tenant, table, row and purpose): a sealed value opens only in the row and for the
//! purpose it was sealed for, and neither the key id nor the version can be altered without detection. Values keep
//! opening after a key rotation as long as the key named in the value stays configured; sealing always uses the
//! active key, so `admin rotate-keys` re-seals by opening and sealing again ([`LocalSealer::key_id_of`] tells which
//! values still use an old key).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use davhaven_ports::{IdGenerator, PortError, SealAad, Sealed, SecretBytes, SecretSealer};

use crate::keyring::{DerivedKey, KeyMaterial};

/// The label of the sealing subkey.
const LABEL: &str = "davhaven/sealer/v1";

/// The format version, the first byte of every sealed value.
const VERSION: u8 = 1;

/// The length of an XChaCha20 nonce in bytes.
const NONCE_LEN: usize = 24;

/// The length of the Poly1305 tag in bytes.
const TAG_LEN: usize = 16;

/// Seals secrets with XChaCha20-Poly1305 under keys derived from the configured key secrets.
pub struct LocalSealer {
    active: String,
    keys: BTreeMap<String, DerivedKey>,
    ids: Arc<dyn IdGenerator>,
}

impl fmt::Debug for LocalSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSealer")
            .field("active", &self.active)
            .field("kids", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// The length byte of a key id, as written into a sealed value and into its associated data.
fn kid_length(kid: &str) -> Result<u8, PortError> {
    u8::try_from(kid.len()).map_err(|_| PortError::internal("the key id is too long"))
}

/// The associated data of the AEAD: version, key id and the caller's [`SealAad`].
fn associated_data(kid: &str, aad: &SealAad) -> Result<Vec<u8>, PortError> {
    let encoded = aad.encode();
    let mut out = Vec::with_capacity(2 + kid.len() + encoded.len());
    out.push(VERSION);
    out.push(kid_length(kid)?);
    out.extend_from_slice(kid.as_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}

impl LocalSealer {
    /// Derives the sealing key of every key of `material`; `ids` supplies the nonces.
    pub fn new(material: &KeyMaterial, ids: Arc<dyn IdGenerator>) -> Self {
        Self {
            active: material.active_kid().to_owned(),
            keys: material.derive_all(LABEL),
            ids,
        }
    }

    /// The id of the key a sealed value was sealed with, or `None` when the bytes are not a sealed value of this
    /// format. `admin rotate-keys` uses it to find the values that still use a retired key.
    pub fn key_id_of(sealed: &Sealed) -> Option<&str> {
        let (kid, _) = split(sealed.as_bytes())?;
        Some(kid)
    }

    /// The id of the key `seal` uses.
    pub fn active_kid(&self) -> &str {
        &self.active
    }

    fn cipher(&self, kid: &str) -> Option<XChaCha20Poly1305> {
        let key = self.keys.get(kid)?;
        XChaCha20Poly1305::new_from_slice(key.as_slice()).ok()
    }
}

/// Splits sealed bytes into the key id and the rest (nonce, ciphertext and tag); `None` when the structure is not
/// that of a sealed value.
fn split(bytes: &[u8]) -> Option<(&str, &[u8])> {
    let (&version, rest) = bytes.split_first()?;
    if version != VERSION {
        return None;
    }
    let (&kid_len, rest) = rest.split_first()?;
    let (kid, rest) = rest.split_at_checked(usize::from(kid_len))?;
    if rest.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    Some((core::str::from_utf8(kid).ok()?, rest))
}

impl SecretSealer for LocalSealer {
    fn seal(&self, plaintext: &[u8], aad: &SealAad) -> Result<Sealed, PortError> {
        let cipher = self
            .cipher(&self.active)
            .ok_or_else(|| PortError::internal("the active sealing key is not available"))?;
        let nonce_bytes = self.ids.random_bytes(NONCE_LEN);
        let nonce = XNonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| PortError::internal("the id generator returned a nonce of the wrong length"))?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &associated_data(&self.active, aad)?,
                },
            )
            .map_err(|_| PortError::internal("sealing failed"))?;
        let kid = self.active.as_bytes();
        let kid_len = kid_length(&self.active)?;
        let mut out = Vec::with_capacity(2 + kid.len() + NONCE_LEN + ciphertext.len());
        out.push(VERSION);
        out.push(kid_len);
        out.extend_from_slice(kid);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(Sealed::from_bytes(out))
    }

    fn open(&self, sealed: &Sealed, aad: &SealAad) -> Result<SecretBytes, PortError> {
        let (kid, rest) = split(sealed.as_bytes()).ok_or_else(|| PortError::invalid("not a sealed value"))?;
        let (nonce_bytes, ciphertext) = rest
            .split_at_checked(NONCE_LEN)
            .ok_or_else(|| PortError::invalid("not a sealed value"))?;
        let rejected = || PortError::rejected("the sealed value does not authenticate");
        let cipher = self.cipher(kid).ok_or_else(rejected)?;
        let nonce = XNonce::try_from(nonce_bytes).map_err(|_| PortError::invalid("not a sealed value"))?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &associated_data(kid, aad).map_err(|_| rejected())?,
                },
            )
            .map_err(|_| rejected())?;
        Ok(SecretBytes::from(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use davhaven_domain::TenantId;
    use davhaven_port_tests::sealer::{run, run_all, run_authenticated, run_authenticated_all};
    use davhaven_ports::PortErrorKind;
    use davhaven_ports::testing::SeqIds;
    use proptest::prelude::*;
    use secrecy::ExposeSecret as _;
    use uuid::Uuid;

    use super::*;
    use crate::keyring::fixtures::material_of;

    fn sealer() -> Arc<dyn SecretSealer> {
        Arc::new(LocalSealer::new(&material_of("seal-1", &[]), Arc::new(SeqIds::new())))
    }

    fn aad(row: u128) -> SealAad {
        SealAad::new(
            TenantId::from_uuid(Uuid::from_u128(1)),
            "webhook_subscriptions",
            Uuid::from_u128(row),
            "webhook_secret",
        )
    }

    #[test]
    fn the_local_sealer_satisfies_the_common_and_the_authenticated_contract() {
        run_all(sealer);
        run_authenticated_all(sealer);
        assert_eq!(run(sealer).case_count(), 4);
        assert_eq!(run_authenticated(sealer).case_count(), 2);
    }

    #[test]
    fn values_have_the_documented_layout_and_hide_the_plaintext() {
        let sealed = sealer().seal(b"whsec_secret", &aad(1)).unwrap();
        let bytes = sealed.as_bytes();
        assert_eq!(&bytes[..2], &[1, 6], "version and key id length");
        assert_eq!(&bytes[2..8], b"seal-1");
        assert_eq!(bytes.len(), 2 + 6 + NONCE_LEN + b"whsec_secret".len() + TAG_LEN);
        assert_eq!(LocalSealer::key_id_of(&sealed), Some("seal-1"));
        assert_eq!(LocalSealer::key_id_of(&Sealed::from_bytes(vec![9, 9])), None);
    }

    #[test]
    fn values_sealed_under_a_retired_key_open_after_a_rotation_and_resealing_uses_the_active_key() {
        let old = LocalSealer::new(&material_of("seal-1", &[]), Arc::new(SeqIds::new()));
        let rotated = LocalSealer::new(&material_of("seal-2", &["seal-1".to_owned()]), Arc::new(SeqIds::new()));
        let sealed = old.seal(b"secret", &aad(1)).unwrap();
        assert_eq!(rotated.open(&sealed, &aad(1)).unwrap().expose_secret(), b"secret");
        assert_eq!(LocalSealer::key_id_of(&sealed), Some("seal-1"));
        let resealed = rotated.seal(b"secret", &aad(1)).unwrap();
        assert_eq!(LocalSealer::key_id_of(&resealed), Some("seal-2"));
        assert_eq!(rotated.active_kid(), "seal-2");
        let forgotten = LocalSealer::new(&material_of("seal-2", &[]), Arc::new(SeqIds::new()));
        let error = forgotten.open(&sealed, &aad(1)).unwrap_err();
        assert_eq!(
            error.kind,
            PortErrorKind::Rejected,
            "an unknown key id is an authentication failure"
        );
    }

    #[test]
    fn a_nonce_of_the_wrong_length_is_an_internal_error_not_a_weak_seal() {
        struct ShortIds;
        impl IdGenerator for ShortIds {
            fn new_id(&self) -> Uuid {
                Uuid::nil()
            }

            fn random_bytes(&self, len: usize) -> Vec<u8> {
                vec![7; len.saturating_sub(1)]
            }
        }
        let broken = LocalSealer::new(&material_of("seal-1", &[]), Arc::new(ShortIds));
        assert_eq!(broken.seal(b"x", &aad(1)).unwrap_err().kind, PortErrorKind::Internal);
    }

    #[test]
    fn a_rewritten_key_id_does_not_open_even_when_it_names_another_known_key() {
        let both = material_of("seal-1", &["seal-2".to_owned()]);
        let local = LocalSealer::new(&both, Arc::new(SeqIds::new()));
        let value = local.seal(b"secret", &aad(1)).unwrap();
        // The other key has the same length of id: the AEAD key and the associated data both change.
        let mut forged = value.as_bytes().to_vec();
        forged[2..8].copy_from_slice(b"seal-2");
        assert_eq!(
            local.open(&Sealed::from_bytes(forged), &aad(1)).unwrap_err().kind,
            PortErrorKind::Rejected
        );
    }

    #[test]
    fn bytes_that_are_not_a_sealed_value_are_invalid_and_a_damaged_value_does_not_authenticate() {
        let local = LocalSealer::new(&material_of("seal-1", &[]), Arc::new(SeqIds::new()));
        let value = local.seal(b"secret", &aad(1)).unwrap().as_bytes().to_vec();
        let shortest = 2 + 6 + NONCE_LEN + TAG_LEN;
        // The structure is wrong: no version, another version, a key id longer than the value, too short for a
        // nonce and a tag.
        let mut other_version = value.clone();
        other_version[0] = 2;
        let mut long_kid = value.clone();
        long_kid[1] = u8::MAX;
        for (bytes, what) in [
            (Vec::new(), "empty"),
            (vec![1], "a version only"),
            (other_version, "another version"),
            (long_kid, "a key id past the end"),
            (
                value.get(..shortest - 1).unwrap().to_vec(),
                "one byte short of nonce and tag",
            ),
        ] {
            assert_eq!(
                local.open(&Sealed::from_bytes(bytes), &aad(1)).unwrap_err().kind,
                PortErrorKind::Invalid,
                "{what}"
            );
        }
        // The structure is right but a byte of the nonce, the ciphertext or the tag changed.
        for index in [8, 8 + NONCE_LEN, value.len() - 1] {
            let mut damaged = value.clone();
            damaged[index] ^= 0x01;
            assert_eq!(
                local.open(&Sealed::from_bytes(damaged), &aad(1)).unwrap_err().kind,
                PortErrorKind::Rejected,
                "byte {index}"
            );
        }
        // Another tenant is another place: the same row id under another tenant does not open.
        let elsewhere = SealAad::new(
            TenantId::from_uuid(Uuid::from_u128(2)),
            "webhook_subscriptions",
            Uuid::from_u128(1),
            "webhook_secret",
        );
        assert_eq!(
            local.open(&Sealed::from_bytes(value), &elsewhere).unwrap_err().kind,
            PortErrorKind::Rejected
        );
    }

    #[test]
    fn debug_output_shows_key_ids_only() {
        let shown = format!(
            "{:?}",
            LocalSealer::new(&material_of("seal-1", &[]), Arc::new(SeqIds::new()))
        );
        assert!(shown.contains("seal-1") && !shown.contains("test-secret"), "{shown}");
    }

    proptest! {
        #[test]
        fn any_plaintext_round_trips_and_only_in_its_place(
            plaintext in proptest::collection::vec(any::<u8>(), 0..300),
            row in 1_u128..1000,
        ) {
            let sealer = LocalSealer::new(&material_of("seal-1", &[]), Arc::new(SeqIds::new()));
            let sealed = sealer.seal(&plaintext, &aad(row)).unwrap();
            let opened = sealer.open(&sealed, &aad(row)).unwrap();
            prop_assert_eq!(opened.expose_secret(), plaintext.as_slice());
            prop_assert!(sealer.open(&sealed, &aad(row + 1)).is_err());
        }
    }
}
