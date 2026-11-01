//! The values of one authorization: the `state`, the PKCE verifier and challenge.
//!
//! * The **state** is `{tenant}.{secret}`: the tenant id as 32 hex digits, a dot and 256 random bits as unpadded URL-safe base64.
//!   The callback carries no credential, so it has to say which tenant's transaction holds the state; the tenant id is not a
//!   secret, and the random part is what makes the state unguessable. The store keeps only a keyed hash of the whole value
//!   (R6: server-generated secrets are stored as HMAC under the pepper), and the value works once, for ten minutes.
//! * The **verifier** is 256 random bits as unpadded URL-safe base64 (43 characters, RFC 7636 section 4.1); the **challenge**
//!   is the unpadded URL-safe base64 of its SHA-256 (`S256`). The verifier is sealed in `oauth_states` and meets the provider
//!   only when the code is exchanged.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use davhaven_domain::TenantId;
use davhaven_ports::KeyPurpose;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::wiring::AppCore;

/// How many random bytes the secret part of the state and the verifier hold.
const SECRET_BYTES: usize = 32;

/// The length of the random part of a state: 32 bytes as unpadded base64.
const SECRET_CHARS: usize = 43;

/// The values of an authorization that is about to start.
pub(crate) struct Flow {
    /// The `state` value for the provider.
    pub(crate) state: String,
    /// The PKCE verifier, to be sealed.
    pub(crate) verifier: SecretString,
    /// The S256 challenge for the provider.
    pub(crate) challenge: String,
}

impl Flow {
    /// New values for a flow of `tenant`, from the id generator's random bytes.
    pub(crate) fn new(core: &AppCore, tenant: TenantId) -> Self {
        let ids = &core.deps().ids;
        let state = format!(
            "{}.{}",
            tenant.as_uuid().simple(),
            URL_SAFE_NO_PAD.encode(ids.random_bytes(SECRET_BYTES))
        );
        let verifier = URL_SAFE_NO_PAD.encode(ids.random_bytes(SECRET_BYTES));
        let challenge = challenge(&verifier);
        Self {
            state,
            verifier: SecretString::from(verifier),
            challenge,
        }
    }
}

/// The S256 challenge of a verifier.
pub(crate) fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The tenant a state belongs to, when it has the shape of a state at all.
pub(crate) fn tenant_of(state: &str) -> Option<TenantId> {
    let (tenant, secret) = state.split_once('.')?;
    let well_formed = tenant.len() == 32
        && tenant.bytes().all(|byte| byte.is_ascii_hexdigit())
        && secret.len() == SECRET_CHARS
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !well_formed {
        return None;
    }
    Uuid::parse_str(tenant).ok().map(TenantId::from_uuid)
}

/// The keyed hash of a state, as `oauth_states.state_hash` stores it.
pub(crate) fn hash(core: &AppCore, state: &str) -> Vec<u8> {
    core.deps()
        .keyring
        .sign(
            KeyPurpose::CredentialPepper,
            format!("davhaven/oauth-state/v1/{state}").as_bytes(),
        )
        .mac
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::outbox::fixture::Fixture;

    #[test]
    fn a_state_names_its_tenant_and_holds_a_secret_of_256_bits() {
        let core = Fixture::new().core;
        let tenant = TenantId::from_uuid(Uuid::from_u128(0x018f_3c1e_7b2a_7c3d_9e4f_0000_0000_0001));
        let flow = Flow::new(&core, tenant);
        assert!(
            flow.state.starts_with("018f3c1e7b2a7c3d9e4f000000000001."),
            "{}",
            flow.state
        );
        assert_eq!(tenant_of(&flow.state), Some(tenant));
        let secret = flow.state.split_once('.').unwrap().1;
        assert_eq!(secret.len(), SECRET_CHARS);
        assert_eq!(URL_SAFE_NO_PAD.decode(secret).unwrap().len(), SECRET_BYTES);
    }

    #[test]
    fn two_flows_share_nothing() {
        let core = Fixture::new().core;
        let tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let first = Flow::new(&core, tenant);
        let second = Flow::new(&core, tenant);
        assert_ne!(first.state, second.state);
        assert_ne!(first.verifier.expose_secret(), second.verifier.expose_secret());
        assert_ne!(hash(&core, &first.state), hash(&core, &second.state));
        assert_eq!(
            hash(&core, &first.state),
            hash(&core, &first.state),
            "the hash is repeatable"
        );
    }

    #[test]
    fn the_verifier_is_43_url_safe_characters_and_the_challenge_is_its_s256_hash() {
        let core = Fixture::new().core;
        let flow = Flow::new(&core, TenantId::from_uuid(Uuid::from_u128(1)));
        let verifier = flow.verifier.expose_secret();
        assert_eq!(verifier.len(), 43);
        assert!(
            verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_eq!(flow.challenge, challenge(verifier));
        // The example of RFC 7636 appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn what_is_not_a_state_names_no_tenant() {
        let secret = "a".repeat(SECRET_CHARS);
        let tenant = "018f3c1e7b2a7c3d9e4f000000000001";
        assert!(tenant_of(&format!("{tenant}.{secret}")).is_some());
        for bad in [
            String::new(),
            "no-dot".to_owned(),
            format!("{tenant}.{}", "a".repeat(SECRET_CHARS - 1)),
            format!("{tenant}.{}", "a".repeat(SECRET_CHARS + 1)),
            format!("{tenant}.{}=", "a".repeat(SECRET_CHARS - 1)),
            format!("{}.{secret}", "z".repeat(32)),
            format!("{}.{secret}", tenant.chars().take(31).collect::<String>()),
            format!("{tenant}.{secret}.more"),
            format!("{tenant}\u{e4}{secret}"),
        ] {
            assert!(tenant_of(&bad).is_none(), "{bad}");
        }
    }
}
