//! Authentication: from a presented credential to a `RequestContext`.

use core::fmt;
use std::net::IpAddr;

use async_trait::async_trait;
use davhaven_domain::{Channel, CredentialKind, RequestContext, RequestId, TenantSlug};
use secrecy::SecretString;

use crate::error::AppResult;

/// A credential as a client presented it, before verification.
///
/// `Debug` never prints secrets or the login name.
pub enum PresentedCredential {
    /// HTTP Basic: the login (`name@login_domain`, or the bare name when the tenant comes from the path) and the
    /// app password.
    Basic {
        /// The login name from the `Authorization` header.
        username: String,
        /// The app password.
        password: SecretString,
    },
    /// An API token from a `Bearer` header.
    Bearer(SecretString),
    /// A feed token from a feed URL.
    Feed(SecretString),
    /// An RSVP token from an RSVP link.
    Rsvp(SecretString),
}

impl PresentedCredential {
    /// The kind of credential this presentation would have to be.
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::Basic { .. } => CredentialKind::AppPassword,
            Self::Bearer(_) => CredentialKind::ApiToken,
            Self::Feed(_) => CredentialKind::FeedToken,
            Self::Rsvp(_) => CredentialKind::RsvpToken,
        }
    }
}

impl fmt::Debug for PresentedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PresentedCredential::{:?}(<redacted>)", self.kind())
    }
}

/// What the edge knows about a request before authentication.
#[derive(Debug)]
pub struct AuthRequest {
    /// The surface the request arrived on; credentials are bound to their surface.
    pub channel: Channel,
    /// The tenant named by the request path or host, when it names one.
    pub tenant_hint: Option<TenantSlug>,
    /// The presented credential.
    pub credential: PresentedCredential,
    /// The client address after trusted-proxy processing, for failure backoff and audit.
    pub client_ip: Option<IpAddr>,
    /// The id of the request.
    pub request_id: RequestId,
}

/// The budget a call of a token is charged to ([`AuthService::charge_budget`]).
///
/// Budgets are rate buckets of the `RateLimiter` port, one per token and class (`ENGINEERING_RULES` R2: the limiter is
/// selected by the deployment, and the allowance is its configuration). Reads and writes have buckets of their own, so
/// a token that reads a lot cannot starve its own writes and a runaway writer cannot flood a calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BudgetClass {
    /// A tool call of an MCP token that only reads.
    McpRead,
    /// A tool call of an MCP token that changes calendars.
    McpWrite,
}

impl BudgetClass {
    /// The name of the class in metrics and audit records, and of its bucket in the limiter's configuration.
    pub const fn name(self) -> &'static str {
        match self {
            Self::McpRead => "mcp_read",
            Self::McpWrite => "mcp_write",
        }
    }
}

/// Verifies credentials and builds the context of a request.
///
/// The service runs the configured authenticator chain, checks that the principal and the tenant are active and
/// the credential is unexpired, applies the failure backoff (per login and IP, per IP) and records usage.
#[async_trait]
pub trait AuthService: Send + Sync {
    /// Charges one call of the token behind `ctx` to its budget of `class`.
    ///
    /// The allowance is the configuration of the rate limiter (`RateKey::MCP_READ`, `RateKey::MCP_WRITE`), so it is
    /// the same for every protocol and follows the limiter the deployment chose. A call that is over the budget costs
    /// nothing, is counted in `davhaven_budget_refusals_total{class}` and is audited as a `rate_limit.tripped` record
    /// (aggregated per token, class and minute). A limiter that does not answer lets the call through: a calendar
    /// tool must not stop because the thing that protects it is down. A context without a token (an app password
    /// on DAV) has no budget and is never refused.
    ///
    /// # Errors
    ///
    /// `RateLimited` with the time to wait. The default is `Unsupported`.
    async fn charge_budget(&self, ctx: &RequestContext, class: BudgetClass) -> AppResult<()> {
        let _ = (ctx, class);
        // unsupported-allowed: AuthServiceImpl implements the method; the default serves test doubles.
        Err(crate::error::AppError::unsupported())
    }

    /// Authenticates a request.
    ///
    /// The context of a **system token** is not bound to a tenant: its `tenant` is the tenant named by
    /// `tenant_hint` when that tenant exists and the nil tenant id otherwise; the tenant service ignores it.
    /// Contexts of other credentials always carry the credential's own tenant.
    ///
    /// A valid credential presented for the path of **another tenant** is authenticated: the resources of another
    /// tenant are invisible to it, so the request fails with `NotFound` (404), the answer for every resource the
    /// caller may not see (R4, PLAN 2.6), not with `Unauthenticated`. That failure is not a failed authentication:
    /// it never counts toward the failure backoff. The only credential whose validity depends on the tenant of
    /// the path is a bare login name (`anna`, without `@login_domain`), which means "anna of the tenant named by
    /// the path".
    ///
    /// # Errors
    ///
    /// `Unauthenticated` for unknown, wrong, revoked, expired or wrong-surface credentials and for suspended
    /// principals and tenants (the same answer for all of them), `NotFound` for a valid credential used on the
    /// path of another tenant, `RateLimited` with `retry_after` while the failure backoff applies, `Unavailable`
    /// when a dependency fails.
    async fn authenticate(&self, request: AuthRequest) -> AppResult<RequestContext>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_map_to_their_kind_and_hide_secrets() {
        let cases = [
            (
                PresentedCredential::Basic {
                    username: "anna@example.org".to_owned(),
                    password: SecretString::from("abcd-efgh-ijkl"),
                },
                CredentialKind::AppPassword,
            ),
            (
                PresentedCredential::Bearer(SecretString::from("dvh_pat_x")),
                CredentialKind::ApiToken,
            ),
            (
                PresentedCredential::Feed(SecretString::from("dvh_feed_x")),
                CredentialKind::FeedToken,
            ),
            (
                PresentedCredential::Rsvp(SecretString::from("dvh_rsvp_x")),
                CredentialKind::RsvpToken,
            ),
        ];
        for (credential, kind) in cases {
            assert_eq!(credential.kind(), kind);
            let shown = format!("{credential:?}");
            for secret in ["anna", "abcd", "dvh_"] {
                assert!(!shown.contains(secret), "{shown}");
            }
        }
    }
}
