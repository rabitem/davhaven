//! Operator tasks that are use cases of the application: system tokens, the lookup of the API tokens that operator
//! commands make, and the resealing of stored secrets.
//!
//! The administrative commands of the server (`davhaven admin ...`) are thin: they build the application, call one
//! function of this module and print the result. What is sealed, how a token is minted and which tables a rotation has
//! to visit are decisions of the application, not of the binary, so they live here, next to the modules that seal
//! and mint.
//!
//! | Task | Module |
//! | --- | --- |
//! | System tokens (`admin system-token`): the operator's credential for `/api/v1/tenants` | [`system_tokens`] |
//! | Finding the tenant and principal tokens that `admin bootstrap` and `admin principal-token` make (idempotency by label) | [`api_tokens`] |
//! | Sealing stored secrets under the active key (`admin rotate-keys`) | [`keys`] |
//!
//! These tasks run with the internal channel: there is no request, no client address and no tenant administrator
//! behind them, only an operator with access to the configuration and the database.

pub mod api_tokens;
pub mod keys;
pub mod system_tokens;

use davhaven_ports::StoreError;

/// Why a maintenance task failed. The texts are for the operator who reads the terminal; they never contain a secret.
#[derive(Debug, thiserror::Error)]
pub enum MaintenanceError {
    /// The request is not valid (an empty label, an expiry in the past).
    #[error("{0}")]
    Invalid(String),
    /// The store failed.
    #[error("the store failed: {0}")]
    Store(#[from] StoreError),
    /// The source of randomness gave fewer bytes than a token needs.
    #[error("the random source did not provide enough bytes for a token")]
    Randomness,
}
