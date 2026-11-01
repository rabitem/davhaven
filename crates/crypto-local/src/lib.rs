//! Local implementations of the cryptographic ports.
//!
//! `SecretSealer` with XChaCha20-Poly1305 and associated data binding tenant, table, row and purpose; `KeyRing`
//! with HMAC-SHA256 and HKDF-derived subkeys per purpose and key id; `CredentialHasher` with keyed HMAC (argon2id
//! reserved for human-chosen secrets); `ProfileSigner` with CMS signatures made with a certificate of the deployment, which a
//! running server exchanges when the files are renewed.

#![forbid(unsafe_code)]

pub mod config;
pub mod hasher;
pub mod keyring;
pub mod profile;
pub mod sealer;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
