//! Test doubles for the pure ports: `ManualClock`, `SeqIds`, `FixedKeyRing`, `PlainSealer`, `FixedHasher` and
//! `FixedProfileSigner`, and two `Database` wrappers: [`FaultyDatabase`], which injects commit and begin failures,
//! and [`RollbackWatch`], which records the transactions that end without a commit.
//!
//! Available with the `testing` feature, which only test crates enable (`xtask arch-check` enforces it). The
//! doubles are deterministic and dependency-light so that tests of every layer can build a `PluginContext` with
//! [`PluginContext::for_tests`] and never touch the system clock, the operating system's random source or real key
//! material. **None of them is secure**; the key ring uses a fixed, public key and the sealer does not encrypt.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use chrono::{DateTime, Duration, TimeZone, Utc};
use davhaven_domain::CredentialKind;
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use uuid::Uuid;

use crate::clock::Clock;
use crate::crypto::{
    CredentialHasher, KeyPurpose, KeyRing, ProfileSigner, SealAad, Sealed, SecretBytes, SecretSealer, Signature,
    StoredHash,
};
use crate::error::PortError;
use crate::ids::IdGenerator;
use crate::plugin::{PluginContext, RunMode};

mod faults;
mod replay;
mod rollbacks;

pub use faults::FaultyDatabase;
pub use replay::{RecordedRequest, ReplayHttp, ReplayRule};
pub use rollbacks::RollbackWatch;

// ---------------------------------------------------------------------------------------------------------------
// ManualClock
// ---------------------------------------------------------------------------------------------------------------

/// A clock that only moves when the test says so. Clones share the same time.
#[derive(Debug, Clone)]
pub struct ManualClock {
    nanos: Arc<AtomicI64>,
}

fn to_nanos(time: DateTime<Utc>) -> i64 {
    time.timestamp_nanos_opt()
        .unwrap_or(if time.timestamp() < 0 { i64::MIN } else { i64::MAX })
}

impl ManualClock {
    /// A clock that starts at `start`.
    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            nanos: Arc::new(AtomicI64::new(to_nanos(start))),
        }
    }

    /// Sets the time (it may move backwards; tests of clock skew need that).
    pub fn set(&self, time: DateTime<Utc>) {
        self.nanos.store(to_nanos(time), Ordering::SeqCst);
    }

    /// Moves the time forward by `by` (backwards for a negative duration). Saturates at the representable range.
    pub fn advance(&self, by: Duration) {
        let delta = by
            .num_nanoseconds()
            .unwrap_or(if by < Duration::zero() { i64::MIN } else { i64::MAX });
        let applied = self.nanos.try_update(Ordering::SeqCst, Ordering::SeqCst, |nanos| {
            Some(nanos.saturating_add(delta))
        });
        debug_assert!(applied.is_ok(), "the update closure always returns Some");
    }
}

impl Default for ManualClock {
    /// Starts at 2027-01-01T00:00:00Z.
    fn default() -> Self {
        let start = Utc
            .with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
            .single()
            .unwrap_or(DateTime::UNIX_EPOCH);
        Self::new(start)
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_nanos(self.nanos.load(Ordering::SeqCst))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// SeqIds
// ---------------------------------------------------------------------------------------------------------------

/// The fixed part of every generated id: a UUIDv7 with a constant timestamp, so ids look like
/// `01900000-0000-7000-8000-000000000001` and sort in generation order.
const SEQ_BASE: u128 = (0x0190_0000_0000_u128 << 80) | (0x7_u128 << 76) | (0b10_u128 << 62);

/// A deterministic id generator: consecutive UUIDv7-shaped ids and reproducible "random" bytes. Clones share the
/// counters, so a generator handed to several components yields one sequence.
#[derive(Debug, Clone)]
pub struct SeqIds {
    next: Arc<AtomicU64>,
    entropy: Arc<AtomicU64>,
}

impl SeqIds {
    /// A generator whose first id ends in `...0001`.
    pub fn new() -> Self {
        Self::starting_at(1)
    }

    /// A generator whose first id ends in the hexadecimal digits of `first`.
    pub fn starting_at(first: u64) -> Self {
        Self {
            next: Arc::new(AtomicU64::new(first)),
            entropy: Arc::new(AtomicU64::new(0)),
        }
    }

    /// One step of the `SplitMix64` generator: deterministic, well mixed and good enough for fixtures.
    fn next_u64(&self) -> u64 {
        const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
        let state = self.entropy.fetch_add(GAMMA, Ordering::SeqCst).wrapping_add(GAMMA);
        let mixed = (state ^ (state >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        let mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }
}

impl Default for SeqIds {
    fn default() -> Self {
        Self::new()
    }
}

impl IdGenerator for SeqIds {
    fn new_id(&self) -> Uuid {
        let counter = self.next.fetch_add(1, Ordering::SeqCst);
        Uuid::from_u128(SEQ_BASE | u128::from(counter))
    }

    fn random_bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            let missing = len - bytes.len();
            bytes.extend(self.next_u64().to_le_bytes().into_iter().take(missing));
        }
        bytes
    }
}

// ---------------------------------------------------------------------------------------------------------------
// FixedKeyRing
// ---------------------------------------------------------------------------------------------------------------

/// HMAC-SHA256, or an empty tag in the impossible case that the key is rejected (HMAC accepts every key length), a
/// tag that never verifies.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return Vec::new();
    };
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

fn hmac_matches(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(tag).is_ok()
}

/// What [`FixedProfileSigner`] puts in front of a profile instead of a signature.
pub const FIXED_PROFILE_SIGNATURE: &[u8] = b"signed-by-the-test-double\n";

/// A profile signer that signs nothing: it puts [`FIXED_PROFILE_SIGNATURE`] in front of the profile, so a test sees that
/// a profile went through the signer and still reads the profile itself. **Not a signature.**
#[derive(Debug, Clone, Copy, Default)]
pub struct FixedProfileSigner;

impl ProfileSigner for FixedProfileSigner {
    fn sign(&self, profile: &[u8], _signed_at: DateTime<Utc>) -> Result<Vec<u8>, PortError> {
        if profile.is_empty() {
            return Err(PortError::invalid("the profile is empty"));
        }
        Ok([FIXED_PROFILE_SIGNATURE, profile].concat())
    }
}

/// A key ring with one fixed, public key per purpose. It really computes HMAC-SHA256, so signatures behave like the
/// production ones (purpose-bound, tamper-evident, kid-addressed); only the keys are known to everyone.
#[derive(Debug, Clone)]
pub struct FixedKeyRing {
    active: String,
    retired: Vec<String>,
}

impl FixedKeyRing {
    /// A key ring whose active key id is `kid`.
    pub fn new(kid: impl Into<String>) -> Self {
        Self {
            active: kid.into(),
            retired: Vec::new(),
        }
    }

    /// Also accepts signatures made under the retired key id `kid` (to test key rotation).
    #[must_use]
    pub fn with_retired_kid(mut self, kid: impl Into<String>) -> Self {
        self.retired.push(kid.into());
        self
    }

    fn key(kid: &str, purpose: KeyPurpose) -> Vec<u8> {
        format!("davhaven-test-key/{kid}/{}", purpose.as_str()).into_bytes()
    }

    fn knows(&self, kid: &str) -> bool {
        self.active == kid || self.retired.iter().any(|retired| retired == kid)
    }
}

impl Default for FixedKeyRing {
    /// Active key id `test`.
    fn default() -> Self {
        Self::new("test")
    }
}

impl KeyRing for FixedKeyRing {
    fn sign(&self, purpose: KeyPurpose, data: &[u8]) -> Signature {
        Signature::new(
            self.active.clone(),
            hmac_sha256(&Self::key(&self.active, purpose), &[data]),
        )
    }

    fn verify(&self, purpose: KeyPurpose, data: &[u8], signature: &Signature) -> bool {
        self.knows(&signature.kid) && hmac_matches(&Self::key(&signature.kid, purpose), &[data], &signature.mac)
    }

    fn active_kid(&self, _purpose: KeyPurpose) -> String {
        self.active.clone()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// PlainSealer
// ---------------------------------------------------------------------------------------------------------------

const SEALED_MAGIC: &[u8] = b"davhaven-test-sealed/v1";

/// A sealer that does not encrypt: the sealed value contains the plaintext in the clear, prefixed with the
/// associated data. It enforces what matters for tests of callers: a value only opens with the associated data it
/// was sealed with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlainSealer;

impl SecretSealer for PlainSealer {
    fn seal(&self, plaintext: &[u8], aad: &SealAad) -> Result<Sealed, PortError> {
        let aad = aad.encode();
        let aad_len =
            u32::try_from(aad.len()).map_err(|_| PortError::internal("associated data is too long to seal"))?;
        let mut out = Vec::with_capacity(SEALED_MAGIC.len() + 4 + aad.len() + plaintext.len());
        out.extend_from_slice(SEALED_MAGIC);
        out.extend_from_slice(&aad_len.to_be_bytes());
        out.extend_from_slice(&aad);
        out.extend_from_slice(plaintext);
        Ok(Sealed::from_bytes(out))
    }

    fn open(&self, sealed: &Sealed, aad: &SealAad) -> Result<SecretBytes, PortError> {
        let malformed = || PortError::invalid("not a sealed value");
        let rest = sealed.as_bytes().strip_prefix(SEALED_MAGIC).ok_or_else(malformed)?;
        let (len_bytes, rest) = rest.split_at_checked(4).ok_or_else(malformed)?;
        let len_bytes: [u8; 4] = len_bytes.try_into().map_err(|_| malformed())?;
        let aad_len = usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| malformed())?;
        let (sealed_aad, plaintext) = rest.split_at_checked(aad_len).ok_or_else(malformed)?;
        if sealed_aad != aad.encode() {
            return Err(PortError::rejected("sealed value does not authenticate"));
        }
        Ok(SecretBytes::from(plaintext.to_vec()))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// FixedHasher
// ---------------------------------------------------------------------------------------------------------------

/// A credential hasher with a fixed, public pepper: HMAC-SHA256 over the credential kind and the secret.
#[derive(Debug, Clone)]
pub struct FixedHasher {
    kid: String,
}

impl FixedHasher {
    /// A hasher whose pepper key id is `kid`.
    pub fn new(kid: impl Into<String>) -> Self {
        Self { kid: kid.into() }
    }

    fn key(&self) -> Vec<u8> {
        format!("davhaven-test-pepper/{}", self.kid).into_bytes()
    }
}

impl Default for FixedHasher {
    /// Pepper key id `test`.
    fn default() -> Self {
        Self::new("test")
    }
}

impl CredentialHasher for FixedHasher {
    fn hash(&self, kind: CredentialKind, secret: &SecretString) -> StoredHash {
        let hash = hmac_sha256(
            &self.key(),
            &[kind.as_str().as_bytes(), &[0], secret.expose_secret().as_bytes()],
        );
        StoredHash::new(kind, self.kid.clone(), hash)
    }

    fn verify(&self, stored: &StoredHash, secret: &SecretString) -> bool {
        stored.pepper_kid == self.kid
            && hmac_matches(
                &self.key(),
                &[stored.kind.as_str().as_bytes(), &[0], secret.expose_secret().as_bytes()],
                &stored.hash,
            )
    }
}

// ---------------------------------------------------------------------------------------------------------------
// PluginContext
// ---------------------------------------------------------------------------------------------------------------

impl PluginContext {
    /// A tier-0 context made of the doubles of this module (`ManualClock`, `SeqIds`, `FixedKeyRing`,
    /// `PlainSealer`, `FixedHasher`) in [`RunMode::Dev`], without HTTP client and database. Tests that need to
    /// move time keep their own handle: build the context with [`PluginContext::new`] instead.
    pub fn for_tests() -> Self {
        Self::new(
            Arc::new(ManualClock::default()),
            Arc::new(SeqIds::new()),
            Arc::new(FixedKeyRing::default()),
            Arc::new(PlainSealer),
            Arc::new(FixedHasher::default()),
            RunMode::Dev,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use davhaven_domain::TenantId;

    use super::*;
    use crate::ids::IdGeneratorExt;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 1, day, hour, 0, 0).unwrap()
    }

    #[test]
    fn the_manual_clock_only_moves_when_told() {
        let clock = ManualClock::new(at(1, 0));
        assert_eq!(clock.now(), at(1, 0));
        assert_eq!(clock.now(), at(1, 0), "reading does not advance");
        clock.advance(Duration::hours(36));
        assert_eq!(clock.now(), at(2, 12));
        clock.advance(Duration::milliseconds(1));
        assert_eq!(clock.now(), at(2, 12) + Duration::milliseconds(1));
        clock.advance(Duration::days(-2));
        assert_eq!(clock.now(), at(2, 12) + Duration::milliseconds(1) - Duration::days(2));
        clock.set(at(5, 5));
        assert_eq!(clock.now(), at(5, 5));
    }

    #[test]
    fn clones_of_the_manual_clock_share_time_and_the_default_is_new_year_2027() {
        let clock = ManualClock::default();
        assert_eq!(clock.now(), at(1, 0));
        let handle = clock.clone();
        let shared: Arc<dyn Clock> = Arc::new(clock);
        handle.advance(Duration::minutes(5));
        assert_eq!(shared.now(), at(1, 0) + Duration::minutes(5));
    }

    #[test]
    fn the_manual_clock_saturates_instead_of_wrapping() {
        let clock = ManualClock::new(at(1, 0));
        clock.advance(Duration::MAX);
        assert!(
            clock.now() > at(1, 0),
            "a huge advance moves forward, never wraps around"
        );
        clock.set(at(1, 0));
        clock.advance(Duration::MIN);
        assert!(clock.now() < at(1, 0));
    }

    #[test]
    fn sequential_ids_are_version_7_shaped_and_ordered() {
        let ids = SeqIds::new();
        let first = ids.new_id();
        let second = ids.new_id();
        assert_eq!(first.to_string(), "01900000-0000-7000-8000-000000000001");
        assert_eq!(second.to_string(), "01900000-0000-7000-8000-000000000002");
        assert_eq!(first.get_version_num(), 7);
        assert!(first < second);
        let tenant: TenantId = ids.new_typed();
        assert_eq!(tenant.to_string(), "01900000-0000-7000-8000-000000000003");
        assert_eq!(
            SeqIds::starting_at(0xabc).new_id().to_string(),
            "01900000-0000-7000-8000-000000000abc"
        );
    }

    #[test]
    fn generators_are_reproducible_and_clones_share_the_sequence() {
        let a = SeqIds::new();
        let b = SeqIds::new();
        assert_eq!(a.new_id(), b.new_id());
        assert_eq!(a.random_bytes(40), b.random_bytes(40));
        let shared = a.clone();
        let first = a.new_id();
        let second = shared.new_id();
        assert!(first < second, "clones continue one sequence");
        let mut seen = HashSet::new();
        for _ in 0..100 {
            assert!(seen.insert(a.new_id()));
        }
    }

    #[test]
    fn random_bytes_have_the_requested_length_and_vary() {
        let ids = SeqIds::new();
        for len in [0, 1, 7, 8, 9, 32, 33] {
            assert_eq!(ids.random_bytes(len).len(), len);
        }
        assert_ne!(ids.random_bytes(16), ids.random_bytes(16), "successive draws differ");
    }

    #[test]
    fn the_key_ring_signs_per_purpose_and_detects_tampering() {
        let ring = FixedKeyRing::default();
        let signature = ring.sign(KeyPurpose::Cursor, b"page=2");
        assert_eq!(signature.kid, "test");
        assert_eq!(signature.mac.len(), 32);
        assert!(ring.verify(KeyPurpose::Cursor, b"page=2", &signature));
        assert!(!ring.verify(KeyPurpose::Cursor, b"page=3", &signature), "other data");
        assert!(!ring.verify(KeyPurpose::Csrf, b"page=2", &signature), "other purpose");
        let mut tampered = signature.clone();
        tampered.mac[0] ^= 1;
        assert!(!ring.verify(KeyPurpose::Cursor, b"page=2", &tampered));
        let truncated = Signature::new("test", signature.mac[..16].to_vec());
        assert!(!ring.verify(KeyPurpose::Cursor, b"page=2", &truncated));
        assert!(!ring.verify(KeyPurpose::Cursor, b"page=2", &Signature::new("test", Vec::new())));
        assert_eq!(ring.active_kid(KeyPurpose::Rsvp), "test");
    }

    #[test]
    fn rotated_keys_keep_verifying_old_signatures() {
        let old = FixedKeyRing::new("k1");
        let signature = old.sign(KeyPurpose::Rsvp, b"token");
        let rotated = FixedKeyRing::new("k2").with_retired_kid("k1");
        assert!(rotated.verify(KeyPurpose::Rsvp, b"token", &signature));
        assert_eq!(rotated.active_kid(KeyPurpose::Rsvp), "k2");
        assert_eq!(rotated.sign(KeyPurpose::Rsvp, b"token").kid, "k2");
        let forgotten = FixedKeyRing::new("k2");
        assert!(
            !forgotten.verify(KeyPurpose::Rsvp, b"token", &signature),
            "unknown key id"
        );
    }

    fn aad(row: u128, purpose: &'static str) -> SealAad {
        SealAad::new(
            TenantId::from_uuid(Uuid::from_u128(1)),
            "webhook_subscriptions",
            Uuid::from_u128(row),
            purpose,
        )
    }

    #[test]
    fn sealed_values_open_only_with_their_associated_data() {
        let sealer = PlainSealer;
        let blob = sealer.seal(b"whsec_secret", &aad(2, "webhook_secret")).unwrap();
        assert_eq!(
            sealer.open(&blob, &aad(2, "webhook_secret")).unwrap().expose_secret(),
            b"whsec_secret"
        );

        let other_row = sealer.open(&blob, &aad(3, "webhook_secret")).unwrap_err();
        assert_eq!(other_row.kind, crate::error::PortErrorKind::Rejected);
        let other_purpose = sealer.open(&blob, &aad(2, "oauth_tokens")).unwrap_err();
        assert_eq!(other_purpose.kind, crate::error::PortErrorKind::Rejected);
    }

    #[test]
    fn garbage_is_not_a_sealed_value() {
        let sealer = PlainSealer;
        let invalid = crate::error::PortErrorKind::Invalid;
        for bytes in [
            Vec::new(),
            b"nope".to_vec(),
            SEALED_MAGIC.to_vec(),
            [SEALED_MAGIC, &[0, 0, 0, 9, 1]].concat(),
        ] {
            let error = sealer.open(&Sealed::from_bytes(bytes), &aad(2, "x")).unwrap_err();
            assert_eq!(error.kind, invalid);
        }
    }

    #[test]
    fn credential_hashes_are_keyed_and_kind_bound() {
        let hasher = FixedHasher::default();
        let secret = SecretString::from("abcd-efgh-ijkl-mnop-qrst-uvwx-yz23");
        let stored = hasher.hash(CredentialKind::AppPassword, &secret);
        assert_eq!(stored.kind, CredentialKind::AppPassword);
        assert_eq!(stored.pepper_kid, "test");
        assert_eq!(stored.hash.len(), 32);
        assert!(hasher.verify(&stored, &secret));
        assert!(!hasher.verify(&stored, &SecretString::from("abcd-efgh-ijkl-mnop-qrst-uvwx-yz24")));

        // The same secret hashes differently for another kind, and a hash relabelled as another kind fails.
        let as_token = hasher.hash(CredentialKind::ApiToken, &secret);
        assert_ne!(stored.hash, as_token.hash);
        let relabelled = StoredHash::new(CredentialKind::ApiToken, "test", stored.hash.clone());
        assert!(!hasher.verify(&relabelled, &secret));

        // Another pepper key id does not verify.
        assert!(!FixedHasher::new("other").verify(&stored, &secret));
        let wrong_kid = StoredHash::new(CredentialKind::AppPassword, "other", stored.hash);
        assert!(!hasher.verify(&wrong_kid, &secret));
    }

    #[test]
    fn the_test_context_is_a_dev_tier_zero_context() {
        let ctx = PluginContext::for_tests();
        assert_eq!(ctx.mode, RunMode::Dev);
        assert!(ctx.http.is_none() && ctx.database.is_none());
        assert_eq!(ctx.clock.now(), at(1, 0));
        assert_eq!(ctx.ids.new_id().to_string(), "01900000-0000-7000-8000-000000000001");
        let signature = ctx.keyring.sign(KeyPurpose::CacheKey, b"k");
        assert!(ctx.keyring.verify(KeyPurpose::CacheKey, b"k", &signature));
    }
}
