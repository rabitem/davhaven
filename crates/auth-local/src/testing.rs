//! Minting of credentials for the tests of this crate.
//!
//! The server mints credentials in the application (`davhaven-app`), with the formats of
//! `davhaven_domain::credential_format`; this adapter only verifies them, so it has no generator of its own. The
//! tests need credentials to present, and build them the same way the application does: from the random bytes of
//! an `IdGenerator`, through the one definition of the formats.

use davhaven_domain::credential_format::{
    APP_PASSWORD_RANDOM_BYTES, TOKEN_PREFIX_RANDOM_BYTES, TOKEN_SECRET_RANDOM_BYTES,
};
use davhaven_domain::{AppPasswordText, CredentialKind, TokenText};
use davhaven_ports::IdGenerator;
use secrecy::SecretString;

/// A credential that was just minted: what the client presents and the two parts the store needs.
#[derive(Clone)]
pub(crate) struct Generated {
    /// What the client presents (the app password, or the whole token).
    pub(crate) presented: SecretString,
    /// The prefix that finds the row.
    pub(crate) prefix: String,
    /// The value that is hashed with `CredentialHasher::hash`.
    pub(crate) secret: SecretString,
}

impl core::fmt::Debug for Generated {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Generated")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// Mints an app password from the randomness of `ids`.
pub(crate) fn app_password(ids: &dyn IdGenerator) -> Generated {
    let password = AppPasswordText::from_random(&ids.random_bytes(APP_PASSWORD_RANDOM_BYTES))
        .expect("the generator returns as many bytes as asked");
    Generated {
        presented: SecretString::from(password.expose()),
        prefix: password.prefix().to_owned(),
        secret: SecretString::from(password.expose()),
    }
}

/// Mints a token of `kind` (an API, feed or RSVP token) from the randomness of `ids`.
pub(crate) fn token(kind: CredentialKind, ids: &dyn IdGenerator) -> Generated {
    let token = TokenText::from_random(
        kind,
        &ids.random_bytes(TOKEN_PREFIX_RANDOM_BYTES),
        &ids.random_bytes(TOKEN_SECRET_RANDOM_BYTES),
    )
    .expect("the kind is a token kind and the generator returns as many bytes as asked");
    Generated {
        presented: SecretString::from(token.expose().as_str()),
        prefix: token.prefix().to_owned(),
        secret: SecretString::from(token.secret()),
    }
}
