//! System tokens: the operator's credential for the tenant list of the management API.
//!
//! A system token carries the scope `system:tenants` and nothing else (PLAN 2.6): it creates, lists, changes and deletes
//! tenants through `/api/v1/tenants`, and it never reads calendar data. It belongs to no tenant, so the management API
//! cannot mint one (`CredentialService::create_api_token` refuses the kind); the operator mints it here, with the
//! configuration and the database of the server, and keeps it where the deployment keeps its secrets.
//!
//! A token has the format of every API token (`dvh_pat_{prefix}_{secret}`) and is stored as the keyed hash of its secret
//! under the pepper of the active key. The plaintext leaves this module exactly once, in [`CreatedSystemToken`].
//!
//! [`find_valid`] is the idempotency check of a deployment step, like that of `admin bootstrap`: a valid token with the
//! label is reported and not created twice by a repeated run. Two runs that race each other can still both create a
//! token; the label is a convenience for a person, not a unique key, and [`list`] shows both.
//!
//! **Audit.** The audit log of the store is kept per tenant, and a system token has none. Creating and revoking one is
//! logged at `info` with the target `davhaven::audit` (the id, the prefix and the label; never the secret), which is the
//! record of who did what on the host that ran the command.

use chrono::{DateTime, Utc};
use davhaven_domain::credential_format::{TOKEN_PREFIX_RANDOM_BYTES, TOKEN_SECRET_RANDOM_BYTES};
use davhaven_domain::{ApiToken, CredentialKind, Scope, ScopeSet, TokenId, TokenKind, TokenText};
use davhaven_ports::{StoreError, UniqueKey};
use secrecy::SecretString;

use super::MaintenanceError;
use crate::wiring::AppDeps;

/// The longest label of a token, as for every API token.
pub const MAX_LABEL_CHARS: usize = 100;

/// How often a token is made again when its prefix collides with an existing one (a chance of about 2^-40).
const ATTEMPTS: u32 = 3;

/// What a listing of system tokens shows: no secret and no hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemTokenInfo {
    /// The token id.
    pub id: TokenId,
    /// The label chosen at creation.
    pub label: String,
    /// The 12 character prefix (`dvh_pat_{prefix}_...`), which identifies the token in the logs.
    pub prefix: String,
    /// The scopes the token carries.
    pub scopes: ScopeSet,
    /// When the token expires, if it does.
    pub expires_at: Option<DateTime<Utc>>,
    /// When the token was last used (flushed at most every 15 minutes).
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the token was revoked, if it was.
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
}

impl SystemTokenInfo {
    fn of(token: &ApiToken) -> Self {
        Self {
            id: token.id,
            label: token.label.clone(),
            prefix: token.prefix.clone(),
            scopes: token.scopes,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
            revoked_at: token.revoked_at,
            created_at: token.created_at,
        }
    }

    /// Whether the token can authenticate at `now`: neither revoked nor expired.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expires| expires > now)
    }
}

/// A token that was just created, with the one chance to see its secret.
pub struct CreatedSystemToken {
    /// The token as listings show it.
    pub token: SystemTokenInfo,
    /// The complete token text (`dvh_pat_...`). It is not stored and cannot be shown again.
    pub secret: SecretString,
}

impl core::fmt::Debug for CreatedSystemToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CreatedSystemToken")
            .field("token", &self.token)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The scopes of a system token.
fn scopes() -> ScopeSet {
    Scope::ALL
        .into_iter()
        .filter(|scope| scope.allowed_for(TokenKind::System))
        .collect()
}

/// Checks the label: 1 to [`MAX_LABEL_CHARS`] characters without control characters, surrounding space removed. The
/// credential service reads the label of an API token the same way.
pub(super) fn clean_label(label: &str) -> Result<String, MaintenanceError> {
    let label = label.trim();
    if label.is_empty() {
        return Err(MaintenanceError::Invalid("the label must not be empty".to_owned()));
    }
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(MaintenanceError::Invalid(format!(
            "the label is longer than {MAX_LABEL_CHARS} characters"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(MaintenanceError::Invalid(
            "the label must not contain control characters".to_owned(),
        ));
    }
    Ok(label.to_owned())
}

/// The system tokens, revoked ones included, in id order.
///
/// # Errors
///
/// [`MaintenanceError::Store`] when the store fails.
pub async fn list(deps: &AppDeps) -> Result<Vec<SystemTokenInfo>, MaintenanceError> {
    let mut tx = deps.database.begin_system().await?;
    let tokens = tx.credential_lookup().list_system_tokens().await?;
    tx.commit().await?;
    Ok(tokens.iter().map(SystemTokenInfo::of).collect())
}

/// Creates a system token labelled `label`, valid until `expires_at` (without an expiry when `None`).
///
/// # Errors
///
/// [`MaintenanceError::Invalid`] for an unusable label or an expiry that is not in the future,
/// [`MaintenanceError::Store`] when the store fails.
pub async fn create(
    deps: &AppDeps,
    label: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Result<CreatedSystemToken, MaintenanceError> {
    let label = clean_label(label)?;
    let now = deps.clock.now();
    if expires_at.is_some_and(|at| at <= now) {
        return Err(MaintenanceError::Invalid("the expiry must be in the future".to_owned()));
    }
    for attempt in 1..=ATTEMPTS {
        let token = TokenText::from_random(
            CredentialKind::ApiToken,
            &deps.ids.random_bytes(TOKEN_PREFIX_RANDOM_BYTES),
            &deps.ids.random_bytes(TOKEN_SECRET_RANDOM_BYTES),
        )
        .ok_or(MaintenanceError::Randomness)?;
        let hashed = deps
            .hasher
            .hash(CredentialKind::ApiToken, &SecretString::from(token.secret().to_owned()));
        let row = ApiToken {
            id: TokenId::from_uuid(deps.ids.new_id()),
            tenant_id: None,
            kind: TokenKind::System,
            principal_id: None,
            label: label.clone(),
            scopes: scopes(),
            prefix: token.prefix().to_owned(),
            hash: hashed.hash,
            pepper_kid: hashed.pepper_kid,
            expires_at,
            created_by: None,
            allowed_origins: Vec::new(),
            last_used_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        let mut tx = deps.database.begin_system().await?;
        match tx.credential_lookup().create_system_token(row).await {
            Ok(stored) => {
                tx.commit().await?;
                tracing::info!(
                    target: "davhaven::audit",
                    token = %stored.id,
                    prefix = %stored.prefix,
                    label = %stored.label,
                    "a system token was created"
                );
                return Ok(CreatedSystemToken {
                    token: SystemTokenInfo::of(&stored),
                    secret: SecretString::from(token.expose().as_str().to_owned()),
                });
            }
            // A prefix that exists already: draw another one.
            Err(StoreError::UniqueViolation(UniqueKey::CredentialPrefix)) if attempt < ATTEMPTS => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(MaintenanceError::Store(StoreError::SerializationFailure))
}

/// The valid system token labelled `label`, if one exists: the idempotency check of a deployment step that makes sure a
/// token exists before it creates one.
///
/// # Errors
///
/// [`MaintenanceError::Invalid`] for an unusable label, [`MaintenanceError::Store`] when the store fails.
pub async fn find_valid(deps: &AppDeps, label: &str) -> Result<Option<SystemTokenInfo>, MaintenanceError> {
    let wanted = clean_label(label)?;
    let now = deps.clock.now();
    Ok(list(deps)
        .await?
        .into_iter()
        .find(|token| token.label == wanted && token.is_valid_at(now)))
}

/// Revokes the system token `id`. Revoking a revoked token changes nothing.
///
/// A token keeps working on an instance that verified it within the cache lifetime of the authenticator (five minutes
/// by default): a system token has no principal whose credential generation could invalidate the cache.
///
/// # Errors
///
/// [`MaintenanceError::Store`] with `NotFound` when no system token has the id.
pub async fn revoke(deps: &AppDeps, id: TokenId) -> Result<(), MaintenanceError> {
    let mut tx = deps.database.begin_system().await?;
    tx.credential_lookup().revoke_system_token(id).await?;
    tx.commit().await?;
    tracing::info!(target: "davhaven::audit", token = %id, "a system token was revoked");
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn a_system_token_carries_the_scope_of_the_tenant_list_and_nothing_else() {
        let scopes = scopes();
        assert!(scopes.contains(Scope::SystemTenants));
        assert_eq!(scopes.iter().count(), 1);
    }

    #[test]
    fn labels_are_checked() {
        assert_eq!(clean_label("  deploy  ").unwrap(), "deploy");
        for bad in ["", "   ", "a\nb", &"x".repeat(MAX_LABEL_CHARS + 1)] {
            assert!(matches!(clean_label(bad), Err(MaintenanceError::Invalid(_))), "{bad:?}");
        }
        assert!(clean_label(&"x".repeat(MAX_LABEL_CHARS)).is_ok());
    }

    #[test]
    fn a_token_is_valid_until_it_expires_or_is_revoked() {
        let now = Utc.with_ymd_and_hms(2027, 5, 1, 12, 0, 0).unwrap();
        let mut info = SystemTokenInfo {
            id: TokenId::from_uuid(uuid::Uuid::from_u128(1)),
            label: "deploy".to_owned(),
            prefix: "abcdefghijkl".to_owned(),
            scopes: scopes(),
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
            created_at: now,
        };
        assert!(info.is_valid_at(now));
        info.expires_at = Some(now + chrono::TimeDelta::hours(1));
        assert!(info.is_valid_at(now));
        assert!(
            !info.is_valid_at(now + chrono::TimeDelta::hours(1)),
            "the expiry is exclusive"
        );
        info.expires_at = None;
        info.revoked_at = Some(now);
        assert!(!info.is_valid_at(now));
    }

    #[test]
    fn the_secret_is_not_in_the_debug_output() {
        let created = CreatedSystemToken {
            token: SystemTokenInfo {
                id: TokenId::from_uuid(uuid::Uuid::from_u128(1)),
                label: "deploy".to_owned(),
                prefix: "abcdefghijkl".to_owned(),
                scopes: scopes(),
                expires_at: None,
                last_used_at: None,
                revoked_at: None,
                created_at: DateTime::UNIX_EPOCH,
            },
            secret: SecretString::from("dvh_pat_abcdefghijkl_secretsecretsecret".to_owned()),
        };
        let shown = format!("{created:?}");
        assert!(!shown.contains("secretsecret"), "{shown}");
    }
}
