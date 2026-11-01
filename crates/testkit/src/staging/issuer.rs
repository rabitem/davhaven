//! Principal tokens that open MCP, issued by the operator.
//!
//! The management API issues the scopes of MCP (`mcp:read`, `mcp:write`, `mcp:schedule_external`) to the principal token of a
//! **service principal** and to nobody else: a token mints tokens with a subset of its own scopes, no tenant token can carry
//! the scopes of MCP, and the one exception (PLAN 2.6, ADR-0015) is for service principals. A user, who is what most of the
//! roles of the fixture world are, gets such a token only from the operator of the instance, with
//! `davhaven admin principal-token create --tenant T --principal P --label L --scope mcp:read ... --expires-in 30d
//! --print-token`, which runs on the host of the instance.
//!
//! A run builds the world itself, so the principals do not exist before it starts, and the tokens cannot be minted beforehand.
//! The run therefore asks an issuer for every token it needs after it has made the principal: [`PrincipalTokenIssuer`] is what
//! it asks. An issuer that runs the command of the operator (the `--principal-token-command` of `davhaven-conformance`) is
//! the one for a deployed instance, and the tests of the runner use one that calls the function the command calls. A run
//! without an issuer leaves out the MCP cases of the roles that need one, and says so ([`crate::permissions::mcp::NO_MCP_CREDENTIALS`]).

use async_trait::async_trait;
use davhaven_domain::{PrincipalName, Scope, TenantSlug};

/// What a token that opens MCP is asked for: the arguments of `davhaven admin principal-token create`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalTokenRequest {
    /// The slug of the tenant (`--tenant`).
    pub tenant: TenantSlug,
    /// The name of the principal the token acts as (`--principal`).
    pub principal: PrincipalName,
    /// The label of the token (`--label`); the run labels everything it makes with `conformance`.
    pub label: String,
    /// The scopes of the token (`--scope`, once each, written as `Scope::as_str` gives them): `mcp:read`, `events:read`, ...
    pub scopes: Vec<Scope>,
    /// The lifetime of the token in days (`--expires-in`); a token with the scopes of MCP expires. A run asks for
    /// [`RUN_TOKEN_DAYS`](super::provision::RUN_TOKEN_DAYS): the token is for the minutes of the run.
    pub expires_in_days: u32,
}

/// Issues principal tokens that open MCP.
///
/// Implementations create the token the way `davhaven admin principal-token create` does and hand back its secret, which
/// the run keeps in its [`CredentialBook`](crate::CredentialBook) and never prints.
#[async_trait]
pub trait PrincipalTokenIssuer: Send + Sync {
    /// Creates the token and returns its secret.
    ///
    /// # Errors
    ///
    /// Why the token could not be made. The text reaches the report of the run, so it must not contain a secret.
    async fn issue(&self, request: &PrincipalTokenRequest) -> Result<String, String>;
}
