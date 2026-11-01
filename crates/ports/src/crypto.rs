//! Cryptographic ports: `KeyRing`, `SecretSealer`, `CredentialHasher` and `ProfileSigner`.
//!
//! These are the pure ports of the plugin model (PLAN 2.3): they are injected directly, not selected by name, and
//! they perform no I/O, so their methods are synchronous. Callers on an async path run expensive implementations
//! (argon2id is reserved for human-chosen secrets) in `spawn_blocking` (`ENGINEERING_RULES` R14).
//!
//! * [`KeyRing`] signs and verifies with keys derived per [`KeyPurpose`]; signatures carry the key id, so tokens
//!   signed before a key rotation stay verifiable.
//! * [`SecretSealer`] seals secrets at rest with an AEAD whose associated data binds tenant, table, row and purpose
//!   ([`SealAad`]), so sealed bytes cannot be moved to another row or used for another purpose.
//! * [`CredentialHasher`] turns server-generated credential secrets into the keyed hash that is stored.
//! * [`ProfileSigner`] signs Apple configuration profiles with the certificate of the deployment, when it has one.

use core::fmt;

use chrono::{DateTime, Utc};
use davhaven_domain::{CredentialKind, ExternalAccountId, TenantId, WebhookId};
use secrecy::SecretString;
use uuid::Uuid;

use crate::error::PortError;

/// What a key of the [`KeyRing`] is used for. Each purpose has its own derived key, so a signature made for one
/// purpose never verifies for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyPurpose {
    /// The keyed pepper of stored credential hashes (app passwords, API tokens, feed tokens, RSVP tokens).
    CredentialPepper,
    /// Signatures of RSVP page state.
    Rsvp,
    /// CSRF tokens of the RSVP page (bound to the RSVP token, valid for one hour).
    Csrf,
    /// HMAC-signed pagination cursors of the management API.
    Cursor,
    /// Cache keys of the verified-credential cache.
    CacheKey,
}

impl KeyPurpose {
    /// Every purpose, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::CredentialPepper,
        Self::Rsvp,
        Self::Csrf,
        Self::Cursor,
        Self::CacheKey,
    ];

    /// A stable `snake_case` name, also used as the key-derivation label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialPepper => "credential_pepper",
            Self::Rsvp => "rsvp",
            Self::Csrf => "csrf",
            Self::Cursor => "cursor",
            Self::CacheKey => "cache_key",
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// A message authentication code together with the id of the key that produced it.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    /// The id of the key (`security.keys[].id`) that signed.
    pub kid: String,
    /// The MAC bytes (HMAC-SHA256 in production).
    pub mac: Vec<u8>,
}

impl Signature {
    /// Creates a signature value.
    pub fn new(kid: impl Into<String>, mac: Vec<u8>) -> Self {
        Self { kid: kid.into(), mac }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("kid", &self.kid)
            .field("mac", &format_args!("<{} bytes>", self.mac.len()))
            .finish()
    }
}

/// Signs and verifies with purpose-bound keys.
pub trait KeyRing: Send + Sync {
    /// Signs `data` with the active key of `purpose`.
    fn sign(&self, purpose: KeyPurpose, data: &[u8]) -> Signature;

    /// Verifies `signature` over `data` with the key named by `signature.kid`, in constant time. An unknown key id
    /// or a signature of the wrong length is simply `false`.
    fn verify(&self, purpose: KeyPurpose, data: &[u8], signature: &Signature) -> bool;

    /// The id of the key `sign` currently uses for `purpose`.
    fn active_kid(&self, purpose: KeyPurpose) -> String;
}

/// Secret bytes that are zeroized on drop and never printed.
pub type SecretBytes = secrecy::SecretSlice<u8>;

/// The associated data of a sealed value: it is authenticated but not stored, so opening with different data
/// fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealAad {
    /// The tenant that owns the row.
    pub tenant: TenantId,
    /// The table of the row, for example `webhook_subscriptions`.
    pub table: &'static str,
    /// The primary key of the row.
    pub row: Uuid,
    /// What the secret is for, for example `webhook_secret` or `oauth_tokens`.
    pub purpose: &'static str,
}

impl SealAad {
    /// Creates the associated data.
    pub const fn new(tenant: TenantId, table: &'static str, row: Uuid, purpose: &'static str) -> Self {
        Self {
            tenant,
            table,
            row,
            purpose,
        }
    }

    /// The associated data of the signing secret of the webhook subscription `webhook` (both the current and the
    /// previous sealed secret of the row). The application seals with it when it creates or rotates a secret and
    /// the webhook handler opens with it, so the two cannot drift apart.
    pub fn webhook_secret(tenant: TenantId, webhook: WebhookId) -> Self {
        Self::new(tenant, "webhook_subscriptions", webhook.as_uuid(), "webhook_secret")
    }

    /// The associated data of the OAuth tokens of the external account `account` (`external_accounts.sealed_tokens`).
    /// The application seals with it when an account is connected or its tokens are refreshed, and opens with it when the
    /// sync engine and the disconnection need the tokens, so a sealed value cannot be moved to another account.
    pub fn external_account_tokens(tenant: TenantId, account: ExternalAccountId) -> Self {
        Self::new(tenant, "external_accounts", account.as_uuid(), "oauth_tokens")
    }

    /// The associated data of the PKCE verifier of the OAuth authorization `state_row` (`oauth_states.pkce_verifier_sealed`;
    /// the id of the row of the state, not the `state` value itself).
    pub fn oauth_verifier(tenant: TenantId, state_row: Uuid) -> Self {
        Self::new(tenant, "oauth_states", state_row, "pkce_verifier")
    }

    /// The canonical byte encoding that implementations pass to the AEAD: a version label, the tenant, the
    /// length-prefixed table, the row and the length-prefixed purpose. The encoding is injective, so two different
    /// values never share bytes.
    pub fn encode(&self) -> Vec<u8> {
        const LABEL: &[u8] = b"davhaven/seal-aad/v1";
        let mut out = Vec::with_capacity(LABEL.len() + 16 + 4 + self.table.len() + 16 + 4 + self.purpose.len());
        out.extend_from_slice(LABEL);
        out.extend_from_slice(self.tenant.as_uuid().as_bytes());
        push_prefixed(&mut out, self.table.as_bytes());
        out.extend_from_slice(self.row.as_bytes());
        push_prefixed(&mut out, self.purpose.as_bytes());
        out
    }
}

fn push_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A sealed secret: an opaque blob that carries its own format version, key id and nonce.
///
/// The bytes are what the database stores (`bytea`); only the sealer that produced them can interpret them.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed(Vec<u8>);

impl Sealed {
    /// Wraps stored bytes.
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes to store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the value and returns the bytes to store.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sealed(<{} bytes>)", self.0.len())
    }
}

/// Seals secrets at rest with an AEAD (XChaCha20-Poly1305 in production).
pub trait SecretSealer: Send + Sync {
    /// Seals `plaintext`, binding it to `aad`.
    ///
    /// # Errors
    ///
    /// Fails with [`PortError`] of kind `Internal` when the key ring cannot provide a key.
    fn seal(&self, plaintext: &[u8], aad: &SealAad) -> Result<Sealed, PortError>;

    /// Opens a sealed value. The plaintext is returned in a zeroizing wrapper.
    ///
    /// # Errors
    ///
    /// Fails with kind `Invalid` when the bytes are not a sealed value of this sealer and with kind `Rejected` when
    /// authentication fails (tampering, wrong associated data, unknown key id).
    fn open(&self, sealed: &Sealed, aad: &SealAad) -> Result<SecretBytes, PortError>;
}

/// The stored form of a server-generated credential secret (`hash` and `pepper_kid` columns).
#[derive(Clone, PartialEq, Eq)]
pub struct StoredHash {
    /// The kind of credential; part of the keyed input, so a hash of an app password never verifies as a token.
    pub kind: CredentialKind,
    /// The id of the pepper key that produced `hash`.
    pub pepper_kid: String,
    /// The keyed hash (HMAC-SHA256 in production).
    pub hash: Vec<u8>,
}

impl StoredHash {
    /// Creates a stored hash from its columns.
    pub fn new(kind: CredentialKind, pepper_kid: impl Into<String>, hash: Vec<u8>) -> Self {
        Self {
            kind,
            pepper_kid: pepper_kid.into(),
            hash,
        }
    }
}

impl fmt::Debug for StoredHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredHash")
            .field("kind", &self.kind)
            .field("pepper_kid", &self.pepper_kid)
            .field("hash", &format_args!("<{} bytes redacted>", self.hash.len()))
            .finish()
    }
}

/// Hashes and verifies server-generated credential secrets.
///
/// Credentials carry at least 128 bits of entropy, so a keyed HMAC suffices (`ENGINEERING_RULES` R6): there is no
/// work factor to tune and verification costs microseconds.
pub trait CredentialHasher: Send + Sync {
    /// Hashes `secret` under the active pepper key.
    fn hash(&self, kind: CredentialKind, secret: &SecretString) -> StoredHash;

    /// Verifies `secret` against a stored hash in constant time, using the pepper key named by
    /// `stored.pepper_kid`. Unknown key ids and hashes of the wrong length are `false`.
    fn verify(&self, stored: &StoredHash, secret: &SecretString) -> bool;
}

/// Signs Apple configuration profiles (PLAN 2.10: "optional CMS signing with an operator certificate").
///
/// An unsigned profile installs but is shown as "Not Verified" by iOS and macOS; one that is signed with a certificate
/// the device trusts shows the name of the certificate. The certificate and its key belong to the deployment: a
/// deployment that provides none injects no signer, and its profiles stay unsigned. Like the other pure ports the signer
/// does no I/O when it signs (the certificate and the key are read when it is built), so the method is synchronous, and
/// callers on an async path run it on a blocking thread (`ENGINEERING_RULES` R14).
pub trait ProfileSigner: Send + Sync {
    /// The signed document for `profile`: a CMS `SignedData` (DER) that carries `profile` unchanged, so that a reader that
    /// ignores the signature still reads the profile. `signed_at` is the signing time recorded in the signature, from the
    /// `Clock`.
    ///
    /// # Errors
    ///
    /// [`PortError`] of kind `Invalid` for an empty profile and `Internal` when the signature cannot be made.
    fn sign(&self, profile: &[u8], signed_at: DateTime<Utc>) -> Result<Vec<u8>, PortError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aad(table: &'static str, purpose: &'static str) -> SealAad {
        SealAad::new(
            TenantId::from_uuid(Uuid::from_u128(1)),
            table,
            Uuid::from_u128(2),
            purpose,
        )
    }

    #[test]
    fn purposes_have_distinct_names() {
        let mut names: Vec<&str> = KeyPurpose::ALL.iter().map(|purpose| purpose.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), KeyPurpose::ALL.len());
        assert_eq!(KeyPurpose::CacheKey.to_string(), "cache_key");
    }

    #[test]
    fn aad_encoding_is_injective_across_field_boundaries() {
        // Without length prefixes these two would both encode "ab" + "c".
        assert_ne!(aad("ab", "c").encode(), aad("a", "bc").encode());
        assert_ne!(aad("t", "p").encode(), aad("t", "q").encode());
        let other_row = SealAad {
            row: Uuid::from_u128(3),
            ..aad("t", "p")
        };
        assert_ne!(aad("t", "p").encode(), other_row.encode());
        let other_tenant = SealAad {
            tenant: TenantId::from_uuid(Uuid::from_u128(9)),
            ..aad("t", "p")
        };
        assert_ne!(aad("t", "p").encode(), other_tenant.encode());
        assert_eq!(aad("t", "p").encode(), aad("t", "p").encode());
    }

    #[test]
    fn webhook_secrets_are_bound_to_tenant_and_subscription() {
        let tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let hook = WebhookId::from_uuid(Uuid::from_u128(2));
        let aad = SealAad::webhook_secret(tenant, hook);
        assert_eq!(
            aad,
            SealAad::new(tenant, "webhook_subscriptions", Uuid::from_u128(2), "webhook_secret")
        );
        assert_ne!(
            aad.encode(),
            SealAad::webhook_secret(TenantId::from_uuid(Uuid::from_u128(9)), hook).encode()
        );
        assert_ne!(
            aad.encode(),
            SealAad::webhook_secret(tenant, WebhookId::from_uuid(Uuid::from_u128(9))).encode()
        );
    }

    #[test]
    fn oauth_secrets_are_bound_to_tenant_row_and_purpose() {
        let tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let account = ExternalAccountId::from_uuid(Uuid::from_u128(2));
        let tokens = SealAad::external_account_tokens(tenant, account);
        assert_eq!(
            tokens,
            SealAad::new(tenant, "external_accounts", Uuid::from_u128(2), "oauth_tokens")
        );
        let verifier = SealAad::oauth_verifier(tenant, Uuid::from_u128(2));
        assert_eq!(
            verifier,
            SealAad::new(tenant, "oauth_states", Uuid::from_u128(2), "pkce_verifier")
        );
        // The same row id under another purpose or table is another value: tokens cannot be opened as a verifier.
        assert_ne!(tokens.encode(), verifier.encode());
        assert_ne!(
            tokens.encode(),
            SealAad::external_account_tokens(TenantId::from_uuid(Uuid::from_u128(9)), account).encode()
        );
    }

    #[test]
    fn secret_bearing_values_do_not_debug_print_bytes() {
        let signature = Signature::new("k1", vec![0xde, 0xad, 0xbe, 0xef]);
        let shown = format!("{signature:?}");
        assert!(shown.contains("k1") && shown.contains("<4 bytes>"), "{shown}");
        assert!(!shown.contains("222") && !shown.contains("dead"), "{shown}");

        let sealed = Sealed::from_bytes(vec![1, 2, 3]);
        assert_eq!(format!("{sealed:?}"), "Sealed(<3 bytes>)");
        assert_eq!(sealed.as_bytes(), &[1, 2, 3]);
        assert_eq!(sealed.into_bytes(), vec![1, 2, 3]);

        let stored = StoredHash::new(CredentialKind::ApiToken, "k2", vec![9; 32]);
        let shown = format!("{stored:?}");
        assert!(shown.contains("<32 bytes redacted>") && shown.contains("k2"), "{shown}");
    }
}
