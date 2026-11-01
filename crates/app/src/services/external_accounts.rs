//! External provider accounts and the OAuth flow.

use async_trait::async_trait;
use davhaven_domain::{ExternalAccountId, PrincipalName, RequestContext};
use davhaven_wire::{AuthorizationUrl, ExternalAccountView, Page, ProviderView};
use secrecy::SecretString;

use super::common::{PageRequest, RenderedPage};
use crate::error::AppResult;

/// The query parameters of an OAuth callback.
#[derive(Debug)]
pub struct CallbackParams {
    /// The authorization code.
    pub code: Option<SecretString>,
    /// The `state` value that binds the callback to a tenant, principal and provider.
    pub state: Option<String>,
    /// The error code of a refused consent (`error`).
    pub error: Option<String>,
}

/// Provider accounts. Every method except [`complete`](Self::complete) needs `providers:manage`.
#[async_trait]
pub trait ExternalAccountService: Send + Sync {
    /// Lists the providers of the deployment and whether each is enabled.
    ///
    /// # Errors
    ///
    /// `Forbidden`.
    async fn providers(&self, ctx: &RequestContext) -> AppResult<Vec<ProviderView>>;

    /// Starts the OAuth flow: stores the single-use state (10 minutes) and the sealed PKCE verifier and returns
    /// the consent URL.
    ///
    /// # Errors
    ///
    /// `Conflict` with `feature-not-enabled` for disabled providers, `NotFound` for unknown providers and
    /// principals, `Forbidden`.
    async fn start(
        &self,
        ctx: &RequestContext,
        provider: &str,
        principal: &PrincipalName,
    ) -> AppResult<AuthorizationUrl>;

    /// Completes the flow at `/oauth/{provider}/callback`: checks and consumes the state, exchanges the code,
    /// creates the account and its mirror calendar (or, for an account that is connected already, replaces its tokens)
    /// and renders the result page. The request is not authenticated; the state names the tenant, so `ctx.tenant` is
    /// ignored.
    ///
    /// A refused consent, a code the provider rejects and an account without calendars are answered with the page of a
    /// failed connection (`success: false`), which says nothing of the reason; the person starts again.
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown, expired and used states and for a state that was made for another provider,
    /// `Unavailable` when the page cannot be rendered.
    async fn complete(&self, ctx: &RequestContext, provider: &str, params: CallbackParams) -> AppResult<RenderedPage>;

    /// Lists the connected accounts ordered by id.
    ///
    /// # Errors
    ///
    /// `Forbidden`, `Invalid` for a bad cursor.
    async fn list(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<ExternalAccountView>>;

    /// Disconnects an account: the tokens are revoked at the provider on a best-effort basis and deleted, the
    /// mirror calendar is removed.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`.
    async fn delete(&self, ctx: &RequestContext, id: ExternalAccountId) -> AppResult<()>;
}
