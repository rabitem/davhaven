//! Standard Webhooks signatures (<https://www.standardwebhooks.com>), version `v1`.
//!
//! A delivery carries three headers:
//!
//! * `webhook-id`: the id of the message (the event id), the same for every attempt and every redelivery;
//! * `webhook-timestamp`: the time of this attempt in seconds since the epoch;
//! * `webhook-signature`: one or more space-delimited signatures `v1,{base64}`, each the HMAC-SHA256 of
//!   `{id}.{timestamp}.{body}` under a signing key.
//!
//! A key is a secret `whsec_{base64}`; the HMAC key is the decoded bytes. While a secret rotates, deliveries are
//! signed with both the new and the previous secret, so a receiver that knows either one accepts them.
//!
//! [`Verifier`] is the reference implementation of the receiving side: it checks the timestamp against a tolerance
//! of five minutes (replay protection), skips signatures of other versions and compares in constant time. The tests
//! of this crate and the documentation (`docs/webhooks.md`) use it as the specification of what a receiver does.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Sha256;

/// The header with the id of the message.
pub const ID_HEADER: &str = "webhook-id";
/// The header with the timestamp of the attempt.
pub const TIMESTAMP_HEADER: &str = "webhook-timestamp";
/// The header with the signatures.
pub const SIGNATURE_HEADER: &str = "webhook-signature";
/// The prefix of a signing secret.
pub const SECRET_PREFIX: &str = "whsec_";
/// The version tag of the signature scheme implemented here.
pub const VERSION: &str = "v1";
/// How far a timestamp may be from the receiver's clock, in seconds.
pub const TOLERANCE_SECONDS: i64 = 300;

/// Reads base64 with or without padding: secrets of other senders are not always padded.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The shortest and the longest key (in bytes) a secret may decode to. The specification recommends 24 to 64
/// bytes; the limits are wider so that a secret of another sender is still verifiable.
const KEY_BYTES: core::ops::RangeInclusive<usize> = 16..=128;

/// Why a secret cannot be a signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SigningError {
    /// The text does not start with `whsec_`.
    #[error("a signing secret starts with `whsec_`")]
    Prefix,
    /// The rest is not base64.
    #[error("a signing secret is `whsec_` followed by base64")]
    Encoding,
    /// The key has an unusable length.
    #[error("a signing key has 16 to 128 bytes")]
    Length,
}

/// A signing key: the decoded bytes of a `whsec_` secret. The bytes never appear in `Debug` output.
#[derive(Debug)]
pub struct SigningKey {
    key: SecretSlice<u8>,
}

impl SigningKey {
    /// Reads a secret of the form `whsec_{base64}`.
    ///
    /// # Errors
    ///
    /// [`SigningError`] for a missing prefix, invalid base64 or a key of unusable length.
    pub fn parse(secret: &str) -> Result<Self, SigningError> {
        let encoded = secret.strip_prefix(SECRET_PREFIX).ok_or(SigningError::Prefix)?;
        let bytes = LENIENT.decode(encoded).map_err(|_| SigningError::Encoding)?;
        if !KEY_BYTES.contains(&bytes.len()) {
            return Err(SigningError::Length);
        }
        Ok(Self {
            key: SecretSlice::from(bytes),
        })
    }

    /// The MAC over `{id}.{timestamp}.{body}`; the timestamp is the text of the header, as the sender wrote it.
    fn mac(&self, id: &str, timestamp: &str, body: &[u8]) -> Option<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.expose_secret()).ok()?;
        mac.update(id.as_bytes());
        mac.update(b".");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body);
        Some(mac)
    }

    /// The signature of a message, `v1,{base64}`. A key that the HMAC rejects (impossible: HMAC takes every key
    /// length) yields an empty signature that no receiver accepts.
    pub fn sign(&self, id: &str, timestamp: i64, body: &[u8]) -> String {
        let tag = self
            .mac(id, &timestamp.to_string(), body)
            .map(|mac| STANDARD.encode(mac.finalize().into_bytes()))
            .unwrap_or_default();
        format!("{VERSION},{tag}")
    }
}

/// The value of the `webhook-signature` header: the signatures of every key, space-delimited.
pub fn signature_header(keys: &[SigningKey], id: &str, timestamp: i64, body: &[u8]) -> String {
    keys.iter()
        .map(|key| key.sign(id, timestamp, body))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why a delivery does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The timestamp is not a number of seconds.
    #[error("the webhook-timestamp is not a number of seconds")]
    BadTimestamp,
    /// The timestamp is older than the tolerance (a replay, or a very late retry).
    #[error("the webhook-timestamp is too old")]
    TooOld,
    /// The timestamp is further in the future than the tolerance.
    #[error("the webhook-timestamp is in the future")]
    TooNew,
    /// None of the signatures matches any key.
    #[error("no signature matches")]
    NoValidSignature,
}

/// The receiving side: verifies deliveries against one or more keys (more than one while a secret rotates on the
/// receiver's side too).
#[derive(Debug)]
pub struct Verifier {
    keys: Vec<SigningKey>,
    tolerance: Duration,
}

impl Verifier {
    /// A verifier for `keys` with the tolerance of the specification (five minutes).
    pub fn new(keys: Vec<SigningKey>) -> Self {
        Self {
            keys,
            tolerance: Duration::seconds(TOLERANCE_SECONDS),
        }
    }

    /// Uses another tolerance.
    #[must_use]
    pub const fn with_tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Verifies a delivery from the values of its three headers and its raw body, at the time `now`.
    ///
    /// # Errors
    ///
    /// [`VerifyError`]: the timestamp is malformed or outside the tolerance, or no signature matches.
    pub fn verify(
        &self,
        id: &str,
        timestamp: &str,
        signatures: &str,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(), VerifyError> {
        let sent = parse_timestamp(timestamp)?;
        let skew = Duration::seconds(now.timestamp().saturating_sub(sent));
        if skew > self.tolerance {
            return Err(VerifyError::TooOld);
        }
        if -skew > self.tolerance {
            return Err(VerifyError::TooNew);
        }
        let candidates = signatures.split_ascii_whitespace().filter_map(|entry| {
            let (version, encoded) = entry.split_once(',')?;
            if version != VERSION {
                return None;
            }
            STANDARD.decode(encoded).ok()
        });
        for candidate in candidates {
            for key in &self.keys {
                if key
                    .mac(id, timestamp, body)
                    .is_some_and(|mac| mac.verify_slice(&candidate).is_ok())
                {
                    return Ok(());
                }
            }
        }
        Err(VerifyError::NoValidSignature)
    }
}

/// Digits only, at most twelve of them.
fn parse_timestamp(text: &str) -> Result<i64, VerifyError> {
    if text.is_empty() || text.len() > 12 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(VerifyError::BadTimestamp);
    }
    text.parse().map_err(|_| VerifyError::BadTimestamp)
}

#[cfg(test)]
mod tests;
