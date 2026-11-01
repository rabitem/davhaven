//! Credentials: app passwords, API tokens, feed tokens and client configuration.

use async_trait::async_trait;
use davhaven_domain::{CredentialId, PrincipalName, RequestContext, TokenId};
use davhaven_wire::{
    ApiTokenCreate, ApiTokenCreated, ApiTokenView, AppPasswordCreate, AppPasswordCreated, AppPasswordView,
    ClientConfigDavx5, ClientConfigGeneric, ClientConfigRequest, FeedTokenCreate, FeedTokenCreated, FeedTokenView,
    Page,
};

use super::common::PageRequest;
use crate::error::AppResult;

/// Which client configuration is asked for (PLAN 2.10, "Client config").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientConfigKind {
    /// The values to type into a client; no secret and no side effect.
    Generic,
    /// An Apple configuration profile; mints an app password for the device.
    AppleMobileconfig(ClientConfigRequest),
    /// A DAVx5 login URI for QR codes; mints an app password for the device.
    Davx5(ClientConfigRequest),
}

/// An Apple configuration profile (`application/x-apple-aspen-config`).
#[derive(Clone, PartialEq, Eq)]
pub struct MobileConfig {
    /// The file name to offer for download.
    pub filename: String,
    /// The profile bytes. They contain the minted app password; the response is `no-store`.
    pub body: Vec<u8>,
}

impl core::fmt::Debug for MobileConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MobileConfig")
            .field("filename", &self.filename)
            .field("body", &format_args!("<{} bytes redacted>", self.body.len()))
            .finish()
    }
}

/// The answer of a client configuration request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientConfigResponse {
    /// The generic values (JSON).
    Generic(Box<ClientConfigGeneric>),
    /// An Apple profile (binary).
    Mobileconfig(MobileConfig),
    /// A DAVx5 login (JSON, contains a secret).
    Davx5(ClientConfigDavx5),
}

/// Credential management for principals and tenants.
///
/// Secrets are server-generated, shown once in the response that creates them and stored only as keyed hashes.
/// Every creation and revocation is audited in the same transaction.
#[async_trait]
pub trait CredentialService: Send + Sync {
    /// Lists the app passwords of a principal, including revoked ones, ordered by id.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Invalid` for a bad cursor.
    async fn list_app_passwords(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        page: PageRequest,
    ) -> AppResult<Page<AppPasswordView>>;

    /// Creates an app password for a principal.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Invalid` for bad labels.
    async fn create_app_password(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        request: AppPasswordCreate,
    ) -> AppResult<AppPasswordCreated>;

    /// Revokes an app password. Revoking a revoked password changes nothing.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn revoke_app_password(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        id: CredentialId,
    ) -> AppResult<()>;

    /// Lists the API tokens of the tenant, including revoked ones, ordered by id.
    ///
    /// # Errors
    ///
    /// `Forbidden`, `Invalid` for a bad cursor.
    async fn list_api_tokens(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<ApiTokenView>>;

    /// Creates an API token. A token can only mint tokens whose scopes are a subset of its own and allowed for
    /// the kind, with one exception: a tenant token cannot hold the `mcp:*` scopes, so it may put them on a principal token
    /// for a **service principal** provided it holds the API scope that reaches the same data (`events:read` for
    /// `mcp:read`, `events:write` for `mcp:write` and `mcp:schedule_external`); for any other principal the plain rule
    /// stays, and the operator (the internal channel) is trusted. Tokens with `mcp:*` scopes need an expiry within
    /// `security.max_mcp_token_days` and a tenant that switched MCP on, and a minted token never outlives its minter.
    ///
    /// # Errors
    ///
    /// `Forbidden` when the scopes exceed the minting token's (outside the exception above), `Invalid` for scopes not
    /// allowed for the kind, a missing or too distant expiry and a group as principal, `NotFound` for unknown principals.
    async fn create_api_token(&self, ctx: &RequestContext, request: ApiTokenCreate) -> AppResult<ApiTokenCreated>;

    /// Revokes an API token.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn revoke_api_token(&self, ctx: &RequestContext, id: TokenId) -> AppResult<()>;

    /// Lists the feed tokens of a principal, ordered by id.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Invalid` for a bad cursor.
    async fn list_feed_tokens(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        page: PageRequest,
    ) -> AppResult<Page<FeedTokenView>>;

    /// Creates a feed token.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Conflict` with `feature-not-enabled` when feeds are disabled for the tenant,
    /// `Invalid` for calendars the principal cannot read.
    async fn create_feed_token(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        request: FeedTokenCreate,
    ) -> AppResult<FeedTokenCreated>;

    /// Revokes a feed token.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn revoke_feed_token(&self, ctx: &RequestContext, principal: &PrincipalName, id: TokenId) -> AppResult<()>;

    /// Replaces a feed token with a new secret for the same calendars; the old URL stops working at once.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn rotate_feed_token(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        id: TokenId,
    ) -> AppResult<FeedTokenCreated>;

    /// Client configuration for a principal: generic values, or a profile that mints an app password.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Invalid` for bad labels.
    async fn client_config(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        kind: ClientConfigKind,
    ) -> AppResult<ClientConfigResponse>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_configs_are_not_debug_printed() {
        let config = MobileConfig {
            filename: "calendar.mobileconfig".to_owned(),
            body: b"<plist>SECRET</plist>".to_vec(),
        };
        let shown = format!("{config:?}");
        assert!(!shown.contains("SECRET") && shown.contains("21 bytes"), "{shown}");
    }
}
