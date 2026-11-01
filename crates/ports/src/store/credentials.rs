//! Repositories for credentials: app passwords, API tokens, feed tokens and RSVP tokens.
//!
//! Only keyed hashes are stored (`ENGINEERING_RULES` R6). Creating a credential inserts the row with the hash the
//! caller computed; the plaintext secret never reaches the store. Revoking stamps `revoked_at` and keeps the row,
//! so a later use of the revoked credential is recognised (and audited) instead of looking like an unknown one.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    ApiToken, AppPassword, CalendarUserAddress, CredentialId, CredentialKind, CredentialRef, DomainName, FeedToken,
    ObjectId, PartStat, PrincipalId, PrincipalName, PrincipalStatus, RsvpToken, TenantId, TenantSlug, TenantStatus,
    TokenId, TokenKind,
};
use uuid::Uuid;

use super::{PageReq, StorePage};
use crate::crypto::StoredHash;
use crate::error::StoreError;

/// Filter of [`CredentialRepo::list_api_tokens`]. Every set field must match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApiTokenFilter {
    /// Only tokens of this principal.
    pub principal: Option<PrincipalId>,
    /// Only tokens of this kind (a tenant transaction never sees system tokens).
    pub kind: Option<TokenKind>,
    /// Include revoked tokens. They are excluded by default.
    pub include_revoked: bool,
}

/// A recorded use of a credential, flushed in batches (at most every 15 minutes per credential).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialUse {
    /// The kind of credential. Feed tokens have no `last_used_at` and are ignored.
    pub kind: CredentialKind,
    /// The credential id (a `CredentialId` for app passwords, a `TokenId` otherwise).
    pub id: Uuid,
    /// When the credential was last used. A stored value that is already later is kept.
    pub at: DateTime<Utc>,
}

/// A stored credential hash to be replaced by one made under another pepper key (re-hash on use).
///
/// The application never knows the plaintext of a credential again after it was shown once, so a credential can only
/// move from a retired pepper key to the active one at the moment a client presents it and the old hash verified. The
/// authenticator then hashes the secret under the active key and asks the store to swap the two
/// ([`CredentialRepo::rehash`]).
///
/// `Debug` prints the new hash as redacted, like every other type that holds one (`ENGINEERING_RULES` R6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rehash {
    /// The credential whose hash is replaced. Its kind names the table, and its id is a `CredentialId` for app
    /// passwords and a `TokenId` otherwise.
    pub credential: CredentialRef,
    /// The pepper key id the stored hash must still name. A credential whose hash names another key has been
    /// re-hashed in the meantime (by a concurrent request) and is left alone.
    pub from_kid: String,
    /// The new keyed hash with the id of the pepper key that made it. Its `kind` is that of `credential`.
    pub to: StoredHash,
}

/// App passwords, API tokens and feed tokens of the transaction's tenant.
#[async_trait]
pub trait CredentialRepo: Send {
    /// Creates an app password.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist and `UniqueViolation` of `CredentialPrefix`.
    async fn create_app_password(&mut self, password: AppPassword) -> Result<AppPassword, StoreError>;

    /// The app password with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_app_password(&mut self, id: CredentialId) -> Result<AppPassword, StoreError>;

    /// The principal's app passwords (revoked ones included), in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list_app_passwords(&mut self, principal: PrincipalId) -> Result<Vec<AppPassword>, StoreError>;

    /// Revokes an app password. Revoking a revoked one keeps the first `revoked_at`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn revoke_app_password(&mut self, id: CredentialId) -> Result<(), StoreError>;

    /// Creates an API token of the tenant or of a principal (system tokens are created through
    /// [`CredentialLookup::create_system_token`]).
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist and `UniqueViolation` of `CredentialPrefix`.
    async fn create_api_token(&mut self, token: ApiToken) -> Result<ApiToken, StoreError>;

    /// The API token with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_api_token(&mut self, id: TokenId) -> Result<ApiToken, StoreError>;

    /// Lists API tokens in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list_api_tokens(
        &mut self,
        filter: &ApiTokenFilter,
        page: PageReq,
    ) -> Result<StorePage<ApiToken>, StoreError>;

    /// Revokes an API token (keeping the first `revoked_at`).
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn revoke_api_token(&mut self, id: TokenId) -> Result<(), StoreError>;

    /// Creates a feed token.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal or a calendar does not exist and `UniqueViolation` of `CredentialPrefix`.
    async fn create_feed_token(&mut self, token: FeedToken) -> Result<FeedToken, StoreError>;

    /// The feed token with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_feed_token(&mut self, id: TokenId) -> Result<FeedToken, StoreError>;

    /// The principal's feed tokens (revoked ones included), in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list_feed_tokens(&mut self, principal: PrincipalId) -> Result<Vec<FeedToken>, StoreError>;

    /// Revokes a feed token (keeping the first `revoked_at`).
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn revoke_feed_token(&mut self, id: TokenId) -> Result<(), StoreError>;

    /// Revokes every app password, principal API token and feed token of the principal and returns how many were
    /// newly revoked (principal deletion).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn revoke_all_for_principal(&mut self, principal: PrincipalId) -> Result<u64, StoreError>;

    /// Records credential uses in one batch and returns how many rows changed. Unknown credentials are skipped.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn touch_last_used(&mut self, uses: &[CredentialUse]) -> Result<u64, StoreError>;

    /// Replaces the keyed hash of a credential with one made under another pepper key, if the stored hash still names
    /// `rehash.from_kid`, and returns whether a row changed (the credential is unknown, belongs to another tenant or
    /// was re-hashed already: `false`). Only `hash` and `pepper_kid` change: the version and `updated_at` do not,
    /// because nothing a client can see changes. A revoked credential is re-hashed like any other (its row stays
    /// the record of a revoked credential).
    ///
    /// Additive method (ADR-0006): the default answers `Unsupported`, which the authenticator logs and ignores, so a
    /// store without the method only keeps its credentials under the key that made them.
    ///
    /// # Errors
    ///
    /// Store failures; `Unsupported` for a store that has not implemented the method.
    async fn rehash(&mut self, rehash: &Rehash) -> Result<bool, StoreError> {
        let _ = rehash;
        Err(StoreError::Unsupported)
    }
}

/// RSVP tokens of the transaction's tenant.
#[async_trait]
pub trait RsvpRepo: Send {
    /// Creates an RSVP token.
    ///
    /// # Errors
    ///
    /// `NotFound` when the object does not exist and `UniqueViolation` of `CredentialPrefix`.
    async fn create(&mut self, token: RsvpToken) -> Result<RsvpToken, StoreError>;

    /// The token with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: TokenId) -> Result<RsvpToken, StoreError>;

    /// The tokens issued for an invitation, in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn for_object(&mut self, object: ObjectId) -> Result<Vec<RsvpToken>, StoreError>;

    /// The token issued to `address` for the invitation that has not been revoked, if any. The name says "live"
    /// in the sense of "not revoked": an **expired** token is returned too, so the caller checks `expires_at` itself
    /// before it hands the token's link out again (and issues a new token when it has expired).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_live(
        &mut self,
        object: ObjectId,
        address: &CalendarUserAddress,
    ) -> Result<Option<RsvpToken>, StoreError>;

    /// Records a use of the token: `last_used_at` is set to the current time and, when `response` is given,
    /// `last_response` too. The token's `updated_at` is set and its `version` advances, like every other change of
    /// the row.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn record_use(&mut self, id: TokenId, response: Option<PartStat>) -> Result<(), StoreError>;

    /// Revokes one token (keeping the first `revoked_at`).
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn revoke(&mut self, id: TokenId) -> Result<(), StoreError>;

    /// Revokes all tokens of an invitation (cancellation or deletion) and returns how many were newly revoked.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn revoke_for_object(&mut self, object: ObjectId) -> Result<u64, StoreError>;

    /// Revokes the tokens issued to `address` for one invitation (the attendee was removed) and returns how many
    /// were newly revoked.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn revoke_for_attendee(&mut self, object: ObjectId, address: &CalendarUserAddress)
    -> Result<u64, StoreError>;

    /// Revokes every token issued to `address` in the tenant (principal deletion) and returns how many were newly
    /// revoked.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn revoke_for_address(&mut self, address: &CalendarUserAddress) -> Result<u64, StoreError>;
}

/// A credential found by prefix, of any kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialRecord {
    /// An app password.
    AppPassword(Box<AppPassword>),
    /// An API token (system, tenant or principal).
    ApiToken(Box<ApiToken>),
    /// A feed token.
    FeedToken(Box<FeedToken>),
    /// An RSVP token.
    RsvpToken(Box<RsvpToken>),
}

impl CredentialRecord {
    /// The kind of credential.
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::AppPassword(_) => CredentialKind::AppPassword,
            Self::ApiToken(_) => CredentialKind::ApiToken,
            Self::FeedToken(_) => CredentialKind::FeedToken,
            Self::RsvpToken(_) => CredentialKind::RsvpToken,
        }
    }

    /// The tenant of the credential; `None` for system tokens.
    pub fn tenant_id(&self) -> Option<TenantId> {
        match self {
            Self::AppPassword(credential) => Some(credential.tenant_id),
            Self::ApiToken(credential) => credential.tenant_id,
            Self::FeedToken(credential) => Some(credential.tenant_id),
            Self::RsvpToken(credential) => Some(credential.tenant_id),
        }
    }

    /// The principal the credential authenticates, for the kinds that belong to one.
    pub fn principal_id(&self) -> Option<PrincipalId> {
        match self {
            Self::AppPassword(credential) => Some(credential.principal_id),
            Self::ApiToken(credential) => credential.principal_id,
            Self::FeedToken(credential) => Some(credential.principal_id),
            Self::RsvpToken(_) => None,
        }
    }

    /// The id of the credential as a UUID (`CredentialId` or `TokenId`).
    pub fn id(&self) -> Uuid {
        match self {
            Self::AppPassword(credential) => credential.id.as_uuid(),
            Self::ApiToken(credential) => credential.id.as_uuid(),
            Self::FeedToken(credential) => credential.id.as_uuid(),
            Self::RsvpToken(credential) => credential.id.as_uuid(),
        }
    }

    /// When the credential was revoked, if it was.
    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::AppPassword(credential) => credential.revoked_at,
            Self::ApiToken(credential) => credential.revoked_at,
            Self::FeedToken(credential) => credential.revoked_at,
            Self::RsvpToken(credential) => credential.revoked_at,
        }
    }

    /// When the credential expires, if it can.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::ApiToken(credential) => credential.expires_at,
            Self::RsvpToken(credential) => Some(credential.expires_at),
            Self::AppPassword(_) | Self::FeedToken(_) => None,
        }
    }
}

/// The names of the tenant and the principal a credential belongs to: what authentication compares a login or the
/// tenant of a request path with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialOwner {
    /// The immutable slug of the credential's tenant.
    pub tenant_slug: TenantSlug,
    /// The domain of `name@login_domain` logins of the tenant, if it has one.
    pub login_domain: Option<DomainName>,
    /// The immutable login name of the principal; `None` for credentials without a principal (tenant tokens, RSVP
    /// tokens).
    pub principal_name: Option<PrincipalName>,
}

/// A credential together with the facts authentication needs besides the secret, loaded in one query.
///
/// One system query answers everything a request needs to decide whether a credential may be used: the row (secret
/// hash, revocation, expiry), the status of the tenant and the principal, and the names a login is compared with.
/// The authenticator therefore needs no second read, neither for a fresh verification nor to revalidate a cached one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookedUpCredential {
    /// The credential row.
    pub record: CredentialRecord,
    /// The status of the credential's tenant; `None` for system tokens.
    pub tenant_status: Option<TenantStatus>,
    /// The status of the principal the credential belongs to; `None` for credentials without a principal.
    pub principal_status: Option<PrincipalStatus>,
    /// The principal's `credential_generation`, which invalidates cached verifications.
    pub credential_generation: Option<i32>,
    /// The names of the credential's tenant and principal; `None` for system tokens.
    pub owner: Option<CredentialOwner>,
}

/// Credential lookup across tenants. Authentication has a prefix but not yet a tenant, so it cannot use a
/// tenant transaction; this system repository finds the row by prefix (unique across the installation).
#[async_trait]
pub trait CredentialLookup: Send {
    /// The credential of `kind` whose prefix is `prefix`, with its tenant and principal status.
    ///
    /// # Errors
    ///
    /// Store failures only; an unknown prefix is `None`.
    async fn find_by_prefix(
        &mut self,
        kind: CredentialKind,
        prefix: &str,
    ) -> Result<Option<LookedUpCredential>, StoreError>;

    /// Creates a system token (not bound to a tenant; `admin bootstrap` and key management use it).
    ///
    /// # Errors
    ///
    /// `UniqueViolation` of `CredentialPrefix`; [`StoreError::Internal`] when the token is not a system token.
    async fn create_system_token(&mut self, token: ApiToken) -> Result<ApiToken, StoreError>;

    /// The system tokens, revoked ones included, in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list_system_tokens(&mut self) -> Result<Vec<ApiToken>, StoreError>;

    /// Revokes a system token (keeping the first `revoked_at`).
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn revoke_system_token(&mut self, id: TokenId) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use davhaven_domain::{FeedMode, ScopeSet};

    use super::*;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 1, day, 0, 0, 0).unwrap()
    }

    fn id<T: From<Uuid>>(n: u128) -> T {
        T::from(Uuid::from_u128(n))
    }

    fn app_password() -> AppPassword {
        AppPassword {
            id: id(1),
            tenant_id: id(2),
            principal_id: id(3),
            label: "iPhone".to_owned(),
            prefix: "abcd-efgh".to_owned(),
            hash: vec![1, 2, 3],
            pepper_kid: "k1".to_owned(),
            last_used_at: None,
            revoked_at: Some(at(3)),
            created_at: at(1),
            updated_at: at(1),
            version: 1,
        }
    }

    fn api_token(tenant: Option<TenantId>, kind: TokenKind) -> ApiToken {
        ApiToken {
            id: id(4),
            tenant_id: tenant,
            kind,
            principal_id: None,
            label: "ci".to_owned(),
            scopes: ScopeSet::empty(),
            prefix: "abcdefghijkl".to_owned(),
            hash: vec![9],
            pepper_kid: "k1".to_owned(),
            expires_at: Some(at(9)),
            created_by: None,
            allowed_origins: Vec::new(),
            last_used_at: None,
            revoked_at: None,
            created_at: at(1),
            updated_at: at(1),
            version: 1,
        }
    }

    fn feed_token() -> FeedToken {
        FeedToken {
            id: id(5),
            tenant_id: id(2),
            principal_id: id(3),
            mode: FeedMode::Busy,
            calendar_ids: Vec::new(),
            prefix: "abcdefghijkl".to_owned(),
            hash: vec![9],
            pepper_kid: "k1".to_owned(),
            revoked_at: None,
            created_at: at(1),
            updated_at: at(1),
            version: 1,
        }
    }

    fn rsvp_token() -> RsvpToken {
        RsvpToken {
            id: id(6),
            tenant_id: id(2),
            object_id: id(7),
            attendee_address: CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
            prefix: "abcdefghijkl".to_owned(),
            hash: vec![9],
            pepper_kid: "k1".to_owned(),
            expires_at: at(20),
            revoked_at: None,
            last_used_at: None,
            last_response: None,
            created_at: at(1),
            updated_at: at(1),
            version: 1,
        }
    }

    #[test]
    fn records_expose_their_common_facts() {
        let tenant: TenantId = id(2);
        let principal: PrincipalId = id(3);
        let records = [
            (
                CredentialRecord::AppPassword(Box::new(app_password())),
                CredentialKind::AppPassword,
                Some(tenant),
                Some(principal),
                Uuid::from_u128(1),
                Some(at(3)),
                None,
            ),
            (
                CredentialRecord::ApiToken(Box::new(api_token(Some(tenant), TokenKind::Tenant))),
                CredentialKind::ApiToken,
                Some(tenant),
                None,
                Uuid::from_u128(4),
                None,
                Some(at(9)),
            ),
            (
                CredentialRecord::FeedToken(Box::new(feed_token())),
                CredentialKind::FeedToken,
                Some(tenant),
                Some(principal),
                Uuid::from_u128(5),
                None,
                None,
            ),
            (
                CredentialRecord::RsvpToken(Box::new(rsvp_token())),
                CredentialKind::RsvpToken,
                Some(tenant),
                None,
                Uuid::from_u128(6),
                None,
                Some(at(20)),
            ),
        ];
        for (record, kind, tenant_id, principal_id, uuid, revoked_at, expires_at) in records {
            assert_eq!(record.kind(), kind);
            assert_eq!(record.tenant_id(), tenant_id, "{kind}");
            assert_eq!(record.principal_id(), principal_id, "{kind}");
            assert_eq!(record.id(), uuid, "{kind}");
            assert_eq!(record.revoked_at(), revoked_at, "{kind}");
            assert_eq!(record.expires_at(), expires_at, "{kind}");
        }
    }

    #[test]
    fn system_tokens_have_no_tenant() {
        let record = CredentialRecord::ApiToken(Box::new(api_token(None, TokenKind::System)));
        assert_eq!(record.tenant_id(), None);
    }

    #[test]
    fn records_never_debug_print_hashes() {
        let record = CredentialRecord::AppPassword(Box::new(app_password()));
        let shown = format!("{record:?}");
        assert!(shown.contains("3 bytes redacted"), "{shown}");
        assert!(!shown.contains("[1, 2, 3]"), "{shown}");
    }

    #[test]
    fn token_filters_exclude_revoked_tokens_by_default() {
        assert!(!ApiTokenFilter::default().include_revoked);
    }

    #[test]
    fn a_rehash_never_debug_prints_the_new_hash() {
        let rehash = Rehash {
            credential: CredentialRef {
                kind: CredentialKind::ApiToken,
                id: Uuid::from_u128(7),
            },
            from_kid: "k1".to_owned(),
            to: StoredHash::new(CredentialKind::ApiToken, "k2", vec![0x5e, 0xc2, 0xe7, 0xd4]),
        };
        let shown = format!("{rehash:?}");
        assert!(shown.contains("4 bytes redacted"), "{shown}");
        assert!(!shown.contains("194") && !shown.contains("94"), "{shown}");
    }
}
