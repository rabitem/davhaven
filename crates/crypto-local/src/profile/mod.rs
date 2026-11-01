//! Signing of Apple configuration profiles with a certificate of the deployment: the `ProfileSigner` port.
//!
//! An unsigned profile installs, but iOS and macOS mark it "Not Verified". A profile signed with a certificate that
//! chains to a root the device trusts (the TLS certificate of the server works, as does a code-signing or S/MIME
//! certificate of a public CA) shows the name of the certificate and "Verified". Signing is off unless the deployment
//! names a certificate and its key (`[security.profile_signing]`), and the certificate is the deployment's, never the
//! software's.
//!
//! [`CmsProfileSigner`] reads a PEM file with the certificate of the signer followed by its chain (the `fullchain.pem`
//! that ACME clients write) and a PEM file with the private key, and signs with RSA (PKCS#1 v1.5, SHA-256) or ECDSA over
//! P-256. Keys are PKCS#8 (`-----BEGIN PRIVATE KEY-----`) or PKCS#1 RSA keys; an encrypted key is refused, because the
//! process would need the password at every start. The key is checked against the certificate when the signer is built,
//! so a mismatch stops the start and is not found by the first person who installs a profile.
//!
//! The output is a DER `ContentInfo` (CMS `SignedData`, RFC 5652) that carries the profile itself, as
//! `openssl smime -sign -nodetach -outform der` writes it.
//!
//! [`CmsProfileSigner`] reads its files once. A deployment that renews the certificate (an ACME client replaces the files by
//! an atomic rename about every 60 days) uses [`ReloadingProfileSigner`], which signs with a [`CmsProfileSigner`] and swaps it
//! for a new one when the files change: see the [`reload`] module.

pub(crate) mod cms;
pub(crate) mod der;
pub mod reload;
pub(crate) mod x509;

use core::fmt;
use std::path::Path;

use chrono::{DateTime, Utc};
use davhaven_ports::{PluginError, PortError, ProfileSigner, read_secret_file};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
use secrecy::{ExposeSecret as _, SecretString};

pub use self::reload::{CHECK_INTERVAL, Refresh, ReloadingProfileSigner};

use self::cms::{Algorithm, SignedDataError, signed_data};
use self::x509::{Certificate, parse_certificate, pem_blocks};
use crate::config::ProfileSigningConfig;

/// The name used in error messages: the signer is not a registry plugin.
pub const PLUGIN: &str = "security.profile_signing";

/// The private key of the signer.
enum SigningKey {
    Rsa(RsaKeyPair),
    P256(EcdsaKeyPair),
}

impl SigningKey {
    const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa(_) => Algorithm::RsaSha256,
            Self::P256(_) => Algorithm::EcdsaP256Sha256,
        }
    }

    /// The public key in the form a certificate carries it: the `RSAPublicKey`, or the encoded point.
    fn public_key(&self) -> &[u8] {
        match self {
            Self::Rsa(key) => key.public_key().as_ref(),
            Self::P256(key) => key.public_key().as_ref(),
        }
    }

    fn sign(&self, random: &SystemRandom, message: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
        match self {
            Self::Rsa(key) => {
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, random, message, &mut signature)?;
                Ok(signature)
            }
            Self::P256(key) => Ok(key.sign(random, message)?.as_ref().to_vec()),
        }
    }
}

/// Signs profiles as CMS `SignedData` with the certificate and the key of the deployment (see the module documentation).
pub struct CmsProfileSigner {
    key: SigningKey,
    /// The certificate of the signer first, then the chain.
    certificates: Vec<Certificate>,
    random: SystemRandom,
}

impl fmt::Debug for CmsProfileSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CmsProfileSigner")
            .field("algorithm", &self.key.algorithm())
            .field("certificates", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

fn invalid(key: &str, message: &str) -> PluginError {
    PluginError::invalid_config(PLUGIN, format!("`{key}`: {message}"))
}

/// The key in a PEM text.
fn read_key(pem: &SecretString) -> Result<SigningKey, PluginError> {
    const KEY: &str = "private_key_file";
    let blocks = pem_blocks(pem.expose_secret()).map_err(|reason| invalid(KEY, reason))?;
    let random = SystemRandom::new();
    for block in blocks {
        let key = match block.label.as_str() {
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&block.der).map(SigningKey::Rsa).or_else(|_| {
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &block.der, &random).map(SigningKey::P256)
            }),
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(&block.der).map(SigningKey::Rsa),
            "ENCRYPTED PRIVATE KEY" => {
                return Err(invalid(
                    KEY,
                    "the key is encrypted; the server cannot ask for a password, so decrypt it first \
                     (`openssl pkcs8 -in key.pem -out key-plain.pem`)",
                ));
            }
            "EC PRIVATE KEY" => {
                return Err(invalid(
                    KEY,
                    "the elliptic curve key is in the SEC1 form; convert it to PKCS#8 \
                     (`openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem`)",
                ));
            }
            _ => continue,
        };
        return key.map_err(|_| {
            invalid(
                KEY,
                "the key is neither an RSA key nor an elliptic curve key on P-256, or it is damaged",
            )
        });
    }
    Err(invalid(KEY, "the file contains no private key"))
}

/// The certificates in a PEM text: the signer first, then the chain.
fn read_certificates(pem: &str) -> Result<Vec<Certificate>, PluginError> {
    const KEY: &str = "certificate_file";
    let certificates = pem_blocks(pem)
        .map_err(|reason| invalid(KEY, reason))?
        .into_iter()
        .filter(|block| block.label == "CERTIFICATE")
        .map(|block| parse_certificate(&block.der).ok_or_else(|| invalid(KEY, "a certificate cannot be read")))
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(invalid(KEY, "the file contains no certificate"));
    }
    Ok(certificates)
}

impl CmsProfileSigner {
    /// A signer for the certificates in `certificates_pem` (the certificate of the signer first, then the chain) and the
    /// key in `private_key_pem`.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for text that holds no certificate or no usable key, and for a key that does not
    /// belong to the first certificate. The message never contains key material.
    pub fn from_pem(certificates_pem: &str, private_key_pem: &SecretString) -> Result<Self, PluginError> {
        let certificates = read_certificates(certificates_pem)?;
        let key = read_key(private_key_pem)?;
        let belongs = certificates
            .first()
            .is_some_and(|signer| signer.public_key == key.public_key());
        if !belongs {
            return Err(invalid(
                "private_key_file",
                "the key does not belong to the first certificate of `certificate_file`; the certificate of the signer \
                 comes first, followed by its chain",
            ));
        }
        Ok(Self {
            key,
            certificates,
            random: SystemRandom::new(),
        })
    }

    /// The signer the configuration names, or `None` when signing is off (no file is named).
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] when only one of the two files is named, when a file cannot be read, or as
    /// [`from_pem`](Self::from_pem).
    pub fn from_config(config: &ProfileSigningConfig) -> Result<Option<Self>, PluginError> {
        config.validate()?;
        let (Some(certificate_file), Some(private_key_file)) = (&config.certificate_file, &config.private_key_file)
        else {
            return Ok(None);
        };
        Self::from_files(certificate_file, private_key_file).map(Some)
    }

    /// The signer for the certificates in `certificate_file` and the key in `private_key_file`. Both may name the same file
    /// (a combined PEM: the key, then the certificate of the signer, then its chain), which is then read once.
    ///
    /// # Errors
    ///
    /// As [`from_config`](Self::from_config).
    pub(crate) fn from_files(certificate_file: &Path, private_key_file: &Path) -> Result<Self, PluginError> {
        Pems::read(certificate_file, private_key_file)?.signer()
    }

    /// Whether `other` signs as this signer does: the same certificates, the leaf and the chain, byte for byte, and the same
    /// public key. A certificate file that was touched or copied again is the same identity; a renewal never is.
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.key.public_key() == other.key.public_key()
            && self.certificates.len() == other.certificates.len()
            && self
                .certificates
                .iter()
                .zip(&other.certificates)
                .all(|(ours, theirs)| ours.der == theirs.der)
    }

    /// When the certificate of the signer ends, if it says so in a form that can be read.
    pub fn not_after(&self) -> Option<DateTime<Utc>> {
        self.certificates.first().and_then(|signer| signer.not_after)
    }

    /// What the operator should hear when the certificate of the signer has run out or is about to: devices show a profile
    /// that is signed with an expired certificate as expired. `None` while the certificate is good for more than
    /// [`EXPIRY_WARNING_DAYS`] days (or does not say when it ends).
    pub fn expiry_warning(&self, now: DateTime<Utc>) -> Option<String> {
        let end = self.not_after()?;
        let day = end.format("%Y-%m-%d");
        if end <= now {
            return Some(format!(
                "the certificate of `[security.profile_signing]` expired on {day}: devices show the profiles it signs as \
                 expired; renew it (a running server picks up renewed files within a minute, a server that starts reads \
                 them at the start)"
            ));
        }
        let left = end.signed_duration_since(now).num_days();
        (left <= EXPIRY_WARNING_DAYS).then(|| {
            format!(
                "the certificate of `[security.profile_signing]` expires on {day} (in {left} days); renew it before then \
                 (a running server picks up renewed files within a minute, without a restart)"
            )
        })
    }
}

/// The text of the files of a signer, read and not yet parsed: the step that touches the file system, apart from the step
/// that judges what it read, so that a caller can tell a file that could not be read (tried again at the next look) from a pair
/// that was read and cannot be used (judged once for as long as the files stay as they are). Both texts are secrets and are
/// wiped when they go.
pub(crate) struct Pems {
    certificates: SecretString,
    /// The key, or `None` when one file holds the key and the certificates.
    key: Option<SecretString>,
}

impl Pems {
    /// Reads `certificate_file` and `private_key_file`; when both name the same path the file is read once, so a replacement
    /// between two reads cannot pair the new certificates with the old key.
    pub(crate) fn read(certificate_file: &Path, private_key_file: &Path) -> Result<Self, PluginError> {
        let certificates = read_secret_file(PLUGIN, "certificate_file", certificate_file)?;
        let key = if certificate_file == private_key_file {
            None
        } else {
            Some(read_secret_file(PLUGIN, "private_key_file", private_key_file)?)
        };
        Ok(Self { certificates, key })
    }

    /// The signer these files make.
    ///
    /// # Errors
    ///
    /// As [`CmsProfileSigner::from_pem`].
    pub(crate) fn signer(&self) -> Result<CmsProfileSigner, PluginError> {
        CmsProfileSigner::from_pem(
            self.certificates.expose_secret(),
            self.key.as_ref().unwrap_or(&self.certificates),
        )
    }
}

/// How many days before the end of its certificate the signer warns.
pub const EXPIRY_WARNING_DAYS: i64 = 14;

impl ProfileSigner for CmsProfileSigner {
    fn sign(&self, profile: &[u8], at: DateTime<Utc>) -> Result<Vec<u8>, PortError> {
        if profile.is_empty() {
            return Err(PortError::invalid("the profile is empty"));
        }
        signed_data(profile, at, &self.certificates, self.key.algorithm(), |message| {
            self.key.sign(&self.random, message)
        })
        .map_err(|error| match error {
            SignedDataError::NoSigner => PortError::internal("the signer has no certificate"),
            SignedDataError::Signing(_) => PortError::internal("the profile could not be signed"),
        })
    }
}

#[cfg(test)]
mod tests;
