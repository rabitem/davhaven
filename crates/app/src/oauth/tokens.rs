//! The OAuth tokens of a connected account at rest.
//!
//! The tokens are one JSON document, sealed with the secret sealer and bound to the tenant, the account row and the purpose
//! `oauth_tokens` (`SealAad::external_account_tokens`), so a sealed value cannot be moved to another account and cannot be
//! opened as anything else. The plaintext lives in zeroizing buffers for as long as it takes to seal or open it.

use chrono::{DateTime, Utc};
use davhaven_domain::{ExternalAccountId, TenantId};
use davhaven_ports::{OAuthTokens, SealAad, Sealed};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{AppError, AppResult};
use crate::wiring::AppCore;

/// The sealed document.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Document {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    #[zeroize(skip)]
    scope: Option<String>,
}

/// Seals the tokens of `account` for storage in `external_accounts.sealed_tokens`.
///
/// # Errors
///
/// `Internal` when the sealer cannot seal (no key).
pub(crate) fn seal(
    core: &AppCore,
    tenant: TenantId,
    account: ExternalAccountId,
    tokens: &OAuthTokens,
) -> AppResult<Vec<u8>> {
    let document = Document {
        access_token: tokens.access_token.expose_secret().to_owned(),
        refresh_token: tokens
            .refresh_token
            .as_ref()
            .map(|token| token.expose_secret().to_owned()),
        expires_at: tokens.expires_at,
        scope: tokens.scope.clone(),
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&document).map_err(AppError::internal)?);
    let sealed = core
        .deps()
        .sealer
        .seal(&plaintext, &SealAad::external_account_tokens(tenant, account))?;
    Ok(sealed.into_bytes())
}

/// Opens the sealed tokens of `account`.
///
/// # Errors
///
/// `Internal` when the value is not sealed for this account (another key, another row, damage).
pub(crate) fn open(
    core: &AppCore,
    tenant: TenantId,
    account: ExternalAccountId,
    sealed: &[u8],
) -> AppResult<OAuthTokens> {
    let plaintext = core.deps().sealer.open(
        &Sealed::from_bytes(sealed.to_vec()),
        &SealAad::external_account_tokens(tenant, account),
    )?;
    let document: Document = serde_json::from_slice(plaintext.expose_secret()).map_err(AppError::internal)?;
    Ok(OAuthTokens {
        access_token: SecretString::from(document.access_token.clone()),
        refresh_token: document.refresh_token.clone().map(SecretString::from),
        expires_at: document.expires_at,
        scope: document.scope.clone(),
    })
}

/// The tokens after a refresh: the new access token, and the refresh token the provider issued, or else the one we had (a
/// provider that does not rotate refresh tokens does not repeat them).
pub(crate) fn refreshed(old: &OAuthTokens, new: OAuthTokens) -> OAuthTokens {
    OAuthTokens {
        refresh_token: new.refresh_token.or_else(|| old.refresh_token.clone()),
        scope: new.scope.or_else(|| old.scope.clone()),
        ..new
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::outbox::fixture::Fixture;

    /// The core of the doubles: its sealer authenticates the associated data like the real one.
    fn core() -> AppCore {
        Fixture::new().core
    }

    fn tokens() -> OAuthTokens {
        OAuthTokens {
            access_token: SecretString::from("ya29.access"),
            refresh_token: Some(SecretString::from("1//refresh")),
            expires_at: DateTime::from_timestamp(1_800_000_000, 0),
            scope: Some("calendar.readonly".to_owned()),
        }
    }

    fn ids() -> (TenantId, ExternalAccountId) {
        (
            TenantId::from_uuid(Uuid::from_u128(1)),
            ExternalAccountId::from_uuid(Uuid::from_u128(2)),
        )
    }

    #[test]
    fn tokens_come_back_as_they_were_sealed() {
        let core = core();
        let (tenant, account) = ids();
        let sealed = seal(&core, tenant, account, &tokens()).unwrap();
        let opened = open(&core, tenant, account, &sealed).unwrap();
        assert_eq!(opened.access_token.expose_secret(), "ya29.access");
        assert_eq!(
            opened.refresh_token.as_ref().map(ExposeSecret::expose_secret),
            Some("1//refresh")
        );
        assert_eq!(opened.expires_at, tokens().expires_at);
        assert_eq!(opened.scope.as_deref(), Some("calendar.readonly"));
    }

    #[test]
    fn a_sealed_value_opens_for_its_own_account_only() {
        let core = core();
        let (tenant, account) = ids();
        let sealed = seal(&core, tenant, account, &tokens()).unwrap();
        let other_account = ExternalAccountId::from_uuid(Uuid::from_u128(3));
        let other_tenant = TenantId::from_uuid(Uuid::from_u128(9));
        assert!(open(&core, tenant, other_account, &sealed).is_err());
        assert!(open(&core, other_tenant, account, &sealed).is_err());
        assert!(open(&core, tenant, account, b"not sealed at all").is_err());
    }

    #[test]
    fn a_refresh_keeps_the_refresh_token_unless_the_provider_rotates_it() {
        let old = tokens();
        let renewed = OAuthTokens {
            access_token: SecretString::from("ya29.renewed"),
            refresh_token: None,
            expires_at: None,
            scope: None,
        };
        let kept = refreshed(&old, renewed);
        assert_eq!(kept.access_token.expose_secret(), "ya29.renewed");
        assert_eq!(
            kept.refresh_token.as_ref().map(ExposeSecret::expose_secret),
            Some("1//refresh")
        );
        assert_eq!(kept.scope.as_deref(), Some("calendar.readonly"));
        let rotated = refreshed(
            &old,
            OAuthTokens {
                access_token: SecretString::from("ya29.renewed"),
                refresh_token: Some(SecretString::from("1//rotated")),
                expires_at: None,
                scope: None,
            },
        );
        assert_eq!(
            rotated.refresh_token.as_ref().map(ExposeSecret::expose_secret),
            Some("1//rotated")
        );
    }
}
