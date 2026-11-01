//! Key configuration: key ids, secret files and the active key.
//!
//! The `[security]` table lists the keys of the key ring: `keys = [{id = "2027-01", secret_file = "..."}]`
//! and `active_key_id`. Every key has an id (stored next to hashes and signatures, so old data stays verifiable
//! after a rotation) and a file with the secret; the secret itself never appears in the configuration. The active
//! key signs and hashes new data; the others only verify. Without `active_key_id` the first key is active.

use std::collections::HashSet;
use std::path::PathBuf;

use davhaven_ports::{PluginError, read_secret_file};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

/// The name used in error messages: the key ring is not a registry plugin.
pub const PLUGIN: &str = "keys";

/// The shortest acceptable key secret, in characters (a base64 encoding of 256 bits is 43).
pub const MIN_SECRET_CHARS: usize = 32;

/// The longest key id, in characters.
pub const MAX_KEY_ID_CHARS: usize = 32;

/// One key of the ring.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// The key id: 1 to 32 characters of `a-z`, `0-9`, `-` and `_`. Never reuse an id for another secret.
    pub id: String,
    /// A file with the secret, at least 32 characters (for example `openssl rand -base64 48`).
    pub secret_file: PathBuf,
}

/// The key section of `[security]`: `keys` and `active_key_id`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct KeysConfig {
    /// The keys of the ring, in order.
    pub keys: Vec<KeyConfig>,
    /// The id of the key that signs and hashes new data; the first key when absent.
    pub active_key_id: Option<String>,
}

/// The `[security.profile_signing]` table: the certificate that signs the Apple configuration profiles. Off unless both
/// files are named.
///
/// An unsigned profile installs but shows "Not Verified" on iOS and macOS. With a certificate that chains to a root the
/// device trusts (the TLS certificate of the server will do), the profile shows the name of the certificate. The files
/// belong to the deployment, usually the `fullchain.pem` and `privkey.pem` that an ACME client keeps current, or one combined
/// PEM file (the key, then the chain with the leaf first) that both settings name. The server
/// reads them when it starts and looks at them again about once a minute: a renewed certificate, with the files replaced by
/// an atomic rename as ACME clients do, is picked up without a restart. A new pair that cannot be used (a key that does not
/// belong to the certificate, a file that is damaged, a certificate that has ended) is logged as a warning and does not
/// replace the pair in use. The files must be reachable through their directory: a file that is bind-mounted into a container
/// on its own, a Compose or Swarm secret and a Kubernetes `subPath` mount pin the file that was there at the start, and a
/// renewal then needs a restart.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileSigningConfig {
    /// A PEM file with the certificate of the signer first, followed by the certificates of its chain (without the root).
    /// It may be the same file as `private_key_file`: one combined PEM with the key and then the chain. The server reads it
    /// again within a minute of a change, so a renewed certificate needs no restart, provided the file is reached through a
    /// mounted directory (a single-file bind mount, a Compose or Swarm secret or a Kubernetes `subPath` pins the file: restart).
    pub certificate_file: Option<PathBuf>,
    /// A PEM file with the private key of the certificate: PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 RSA, RSA or ECDSA
    /// P-256, not encrypted. The same file as `certificate_file` when one combined PEM holds both. Read again together with
    /// the certificate.
    pub private_key_file: Option<PathBuf>,
}

impl ProfileSigningConfig {
    /// Checks that the two files come together.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the file that is missing.
    pub fn validate(&self) -> Result<(), PluginError> {
        match (&self.certificate_file, &self.private_key_file) {
            (Some(_), None) => Err(PluginError::invalid_config(
                crate::profile::PLUGIN,
                "`private_key_file` is missing: a certificate needs its key",
            )),
            (None, Some(_)) => Err(PluginError::invalid_config(
                crate::profile::PLUGIN,
                "`certificate_file` is missing: a key needs its certificate",
            )),
            _ => Ok(()),
        }
    }
}

pub(crate) fn is_valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_KEY_ID_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Checks a list of key ids: at least one, every id valid and unique, and an active key that is one of them. The one
/// validator of the key list: the configuration ([`KeysConfig::validate`]) and the key material
/// ([`crate::keyring::KeyMaterial::new`]) both ask it, so their messages cannot differ.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the offending key.
pub(crate) fn check_key_ids<'a>(
    ids: impl IntoIterator<Item = &'a str>,
    active: Option<&str>,
) -> Result<(), PluginError> {
    let invalid = |message: String| PluginError::invalid_config(PLUGIN, message);
    let mut seen = HashSet::new();
    for id in ids {
        if !is_valid_key_id(id) {
            return Err(invalid(format!(
                "the key id `{id}` must be 1 to {MAX_KEY_ID_CHARS} characters of a-z, 0-9, - and _"
            )));
        }
        if !seen.insert(id) {
            return Err(invalid(format!("the key id `{id}` is used twice")));
        }
    }
    if seen.is_empty() {
        return Err(invalid("`keys` needs at least one key".to_owned()));
    }
    if let Some(active) = active
        && !seen.contains(active)
    {
        return Err(invalid(format!(
            "`active_key_id` names `{active}`, which is not in `keys`"
        )));
    }
    Ok(())
}

impl KeysConfig {
    /// Checks the key list: at least one key, valid and unique ids, an active key that exists.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the offending key.
    pub fn validate(&self) -> Result<(), PluginError> {
        check_key_ids(
            self.keys.iter().map(|key| key.id.as_str()),
            self.active_key_id.as_deref(),
        )
    }

    /// The active key: `active_key_id` or else the first key.
    pub fn active_key(&self) -> Option<&KeyConfig> {
        match &self.active_key_id {
            Some(active) => self.keys.iter().find(|key| &key.id == active),
            None => self.keys.first(),
        }
    }

    /// Reads the secret of a key from its file and checks its length.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] when the file cannot be read or the secret is shorter than
    /// [`MIN_SECRET_CHARS`] characters. The message names the key id and never contains the secret.
    pub fn read_secret(key: &KeyConfig) -> Result<SecretString, PluginError> {
        let secret = read_secret_file(PLUGIN, "secret_file", &key.secret_file)?;
        if secret.expose_secret().chars().count() < MIN_SECRET_CHARS {
            return Err(PluginError::invalid_config(
                PLUGIN,
                format!(
                    "the secret of key `{}` must be at least {MIN_SECRET_CHARS} characters",
                    key.id
                ),
            ));
        }
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn parse(value: serde_json::Value) -> KeysConfig {
        davhaven_ports::parse_config(PLUGIN, value).unwrap()
    }

    fn two_keys() -> serde_json::Value {
        serde_json::json!({"keys": [
            {"id": "2027-01", "secret_file": "/run/secrets/key-2027-01"},
            {"id": "2026-07", "secret_file": "/run/secrets/key-2026-07"},
        ]})
    }

    #[test]
    fn the_first_key_is_active_unless_one_is_named() {
        let config = parse(two_keys());
        config.validate().unwrap();
        assert_eq!(config.active_key().unwrap().id, "2027-01");
        let named = parse(serde_json::json!({
            "keys": two_keys()["keys"].clone(),
            "active_key_id": "2026-07",
        }));
        named.validate().unwrap();
        assert_eq!(named.active_key().unwrap().id, "2026-07");
        assert!(KeysConfig::default().active_key().is_none());
    }

    #[test]
    fn validation_names_the_problem() {
        let cases = [
            (serde_json::json!({}), "at least one key"),
            (
                serde_json::json!({"keys": [{"id": "Upper", "secret_file": "/x"}]}),
                "Upper",
            ),
            (
                serde_json::json!({"keys": [{"id": "", "secret_file": "/x"}]}),
                "must be 1 to",
            ),
            (
                serde_json::json!({"keys": [{"id": "a", "secret_file": "/x"}, {"id": "a", "secret_file": "/y"}]}),
                "used twice",
            ),
            (
                serde_json::json!({"keys": [{"id": "a", "secret_file": "/x"}], "active_key_id": "b"}),
                "active_key_id",
            ),
        ];
        for (value, expected) in cases {
            let error = parse(value).validate().unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
        assert!(davhaven_ports::parse_config::<KeysConfig>(PLUGIN, serde_json::json!({"key": []})).is_err());
        assert!(
            davhaven_ports::parse_config::<KeysConfig>(
                PLUGIN,
                serde_json::json!({"keys": [{"id": "a", "secret": "inline"}]})
            )
            .is_err(),
            "secrets are never inline"
        );
    }

    #[test]
    fn secrets_are_read_from_files_and_must_be_long_enough() {
        let dir = std::env::temp_dir();
        let long = dir.join(format!("davhaven-keys-{}-long", std::process::id()));
        let short = dir.join(format!("davhaven-keys-{}-short", std::process::id()));
        std::fs::File::create(&long)
            .unwrap()
            .write_all(b"0123456789abcdef0123456789abcdef0123456789\n")
            .unwrap();
        std::fs::File::create(&short)
            .unwrap()
            .write_all(b"tooshort-secret\n")
            .unwrap();
        let key = |id: &str, file: &PathBuf| KeyConfig {
            id: id.to_owned(),
            secret_file: file.clone(),
        };
        let secret = KeysConfig::read_secret(&key("long", &long)).unwrap();
        assert_eq!(secret.expose_secret().len(), 42);
        let error = KeysConfig::read_secret(&key("short", &short)).unwrap_err().to_string();
        assert!(error.contains("short") && !error.contains("tooshort-secret"), "{error}");
        drop(std::fs::remove_file(&long));
        drop(std::fs::remove_file(&short));
    }
}
