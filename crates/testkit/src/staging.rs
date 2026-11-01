//! The staging runner: the harness against a deployed instance.
//!
//! The matrices and the client flows run in process on [`TestApp`](crate::TestApp) in CI. This module runs them against an
//! instance that is reached only over HTTP, for example the staging deployment that is gated on every merge to `main`
//! (PLAN 3.1 L7, 4.2): the same fixture world, the same requests, the same oracle, an ephemeral pair of tenants of
//! its own per run.
//!
//! # What the operator provides
//!
//! A run needs two tenants that exist and one administration token for each. The management API cannot mint the first
//! administration token of a tenant (that is what `davhaven admin bootstrap` is for), so the operator creates the
//! tenants of the run, `{run}-a` and `{run}-b` (see [`WorldNames::for_run`](davhaven_fixtures::WorldNames::for_run)),
//! and hands their tokens over:
//!
//! ```text
//! davhaven admin bootstrap --tenant r42-a --login-domain r42-a.example --mcp-enabled --print-token
//! davhaven admin bootstrap --tenant r42-b --login-domain r42-b.example --mcp-enabled --print-token
//! ```
//!
//! A system token is optional. With one the runner aligns the settings of the tenants (the login domain, the sender
//! domain, MCP switched on) and deletes both tenants when it is done; without one it only checks that the tenants are as it
//! needs them and leaves them in place.
//!
//! The cases of the MCP column need principal tokens that carry `mcp:*` scopes. The management API issues those to service
//! principals only (PLAN 2.6, ADR-0015), so the runner makes them for the service principals of the world itself, in a tenant
//! that has MCP switched on, and asks a [`PrincipalTokenIssuer`] for the others: the operator's command
//! `davhaven admin principal-token create`, which a user's token can only come from. Without an issuer the roles that are users
//! have no token that opens MCP and their cases are left out (reported as skipped, with the reason); with one, a tenant that has
//! MCP switched off stops the run, because the command would be asked for nothing there and every MCP case would be left out
//! without a word. The tokens a run issues live for [`provision::RUN_TOKEN_DAYS`] day, not for a month.
//!
//! # What a run does
//!
//! Before anything is written the run checks that the two tenants are the ones it was made for: each token reads its tenant,
//! the login domain is the one of the run, and the tenant holds no principal that a run did not make. A wrong run id that names
//! a real tenant, or the tokens of another tenant, stop the run there and change nothing, even with a system token. Everything a
//! run makes carries the label `conformance`, so that a reset deletes that and nothing else.
//!
//! [`Deployment::provision`] builds the fixture world through the management API and DAV, the way a provisioning system and
//! calendar clients do, and collects the credentials the instance issued into a
//! [`CredentialBook`](crate::CredentialBook): principals, memberships, calendars, events, accepted grants (also those to service
//! principals, which client sharing does not offer), the invitations
//! that are still pending or were declined (through the CalendarServer sharing flow, because the API only makes
//! accepted grants), app passwords, principal tokens (also one per scope for the owner) and tenant tokens of every scope. Mirror calendars cannot be made over
//! the API (a sync engine makes them), so the deployed world has none and the cases about them are left out.
//!
//! [`Deployment`] is a [`MatrixEnv`](crate::permissions::MatrixEnv): [`permissions::run`](crate::permissions::run) runs the
//! permission matrix and [`permissions::admin::run`](crate::permissions::admin::run) the administration matrix against it, and
//! [`run`] drives both and the client-flow scenarios ([`crate::flow`]). What a
//! deployed instance cannot show (its mail transport, its event sinks) is not part of the state the matrices compare; the
//! outbox, the sequence numbers, the objects, the grants and the collections of every principal are.
//!
//! A case that is *allowed* to change something needs a world of its own, so that no case sees what another did. An
//! in-process application builds one per case; a deployed instance has to be reset, which deletes the principals of the world
//! and of the harness (a principal that no run made makes it refuse), revokes the tokens and deletes the webhooks of the harness
//! and provisions the world again with new secrets ([`Deployment::reset`]). That takes a few hundred requests, so by default the
//! matrices leave such cases to the in-process run and run what must change nothing (refusals, reads), which is what a
//! deployment can get wrong that the in-process run cannot see: proxies, TLS, headers, the real database roles. A run with
//! `reset_between_writes` runs them all.
//!
//! The runner never reads the clock: the expiry of the tokens it mints comes from the [`Clock`] it is
//! given.

pub mod api;
pub mod env;
pub mod issuer;
pub mod provision;
pub mod runner;

use core::fmt;
use std::sync::Arc;

use davhaven_fixtures::FixtureError;
use davhaven_ports::Clock;
use url::Url;

pub use self::issuer::{PrincipalTokenIssuer, PrincipalTokenRequest};
pub use self::provision::Deployment;
pub use self::runner::{FlowSummary, Options, StagingReport, run};
use crate::transport::TransportError;

/// What a run needs to know about the instance.
#[derive(Clone)]
pub struct StagingConfig {
    /// The base URL of the instance, for example `https://calendar.example`.
    pub base_url: Url,
    /// The prefix of the names of the two tenants (`{run_id}-a`, `{run_id}-b`): unique per run.
    pub run_id: String,
    /// The administration token of the main tenant (`{run_id}-a`), with every tenant scope.
    pub tenant_token: String,
    /// The administration token of the other tenant (`{run_id}-b`), with every tenant scope.
    pub other_tenant_token: String,
    /// A system token: aligns the tenants with the world and deletes them at the end. Without it the system-token cases
    /// of the matrices are left out.
    pub system_token: Option<String>,
    /// Where the expiry dates of the tokens the runner mints come from.
    pub clock: Arc<dyn Clock>,
    /// Issues the principal tokens that open MCP for the users of the world, which the management API cannot
    /// ([`PrincipalTokenIssuer`]). Without one the MCP cases of the users are left out.
    pub token_issuer: Option<Arc<dyn PrincipalTokenIssuer>>,
}

impl fmt::Debug for StagingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagingConfig")
            .field("base_url", &self.base_url.as_str())
            .field("run_id", &self.run_id)
            .field("tokens", &"<redacted>")
            .field("system_token", &self.system_token.as_ref().map(|_| "<redacted>"))
            .field("token_issuer", &self.token_issuer.as_ref().map(|_| "given"))
            .finish_non_exhaustive()
    }
}

/// Why a run could not be prepared or carried out (a failed assertion is a result, not an error).
#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    /// A request could not be carried.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The instance answered a request of the preparation with another status than the one it needs.
    #[error("{what}: the instance answered {status}: {excerpt}")]
    Unexpected {
        /// What the request was for.
        what: String,
        /// The status of the answer.
        status: u16,
        /// The start of the body, flattened.
        excerpt: String,
    },
    /// The instance answered, but not with what the world needs (a missing field, a tenant with another login domain).
    #[error("{0}")]
    Setup(String),
    /// A lookup in the fixture world failed.
    #[error(transparent)]
    Fixture(#[from] FixtureError),
}

impl StagingError {
    /// A [`StagingError::Setup`] from a message.
    pub fn setup(message: impl Into<String>) -> Self {
        Self::Setup(message.into())
    }
}
