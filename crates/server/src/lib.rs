//! The Davhaven server.
//!
//! Loads and validates the configuration, wires the selected adapters through the plugin registry, builds the
//! application services, serves the configured listeners (public, internal, ops), runs the background workers and
//! provides the command line interface (`serve`, `migrate`, `config check`, `healthcheck`, `admin ...`).
//!
//! Adapters are compiled in through cargo features (all default adapters are on by default); the calendar
//! providers are opt-in features and disabled in configuration by default.
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | The command line and what each command does | [`cli`] |
//! | The typed configuration, environment overrides and redaction | [`config`] |
//! | Which table configures which adapter, and `config check` | [`plugins`] |
//! | Which adapters exist in this build | [`registry`] |
//! | Building the application from the configuration | [`assembly`] |
//! | Listeners, route groups and connection limits | [`listeners`], [`connection`], [`server`] |
//! | `/healthz`, `/readyz`, `/metrics` and the `healthcheck` command | [`ops`], [`healthcheck`] |
//! | Workers and their heartbeats | [`workers`] |
//! | The certificate that signs Apple profiles: following its files, the expiry gauge | [`profile_signing`] |
//! | Signals and the shutdown sequence | [`shutdown`] |
//! | Logs, metrics and traces | [`telemetry`] |
//! | The opt-in DAV capture | [`capture`] |
//! | `admin bootstrap`, `admin bump-sync-epoch`, `migrate` and friends | [`admin`] |
//! | The generated configuration reference | [`docs`] |
//! | Reading the JSON Schemas of configuration tables (defaults, unknown keys) | [`schema`] |

#![forbid(unsafe_code)]

pub mod admin;
pub mod assembly;
pub mod capture;
pub mod cli;
pub mod config;
pub mod connection;
pub mod docs;
pub mod error;
pub mod healthcheck;
pub mod listeners;
pub mod ops;
pub mod plugins;
pub mod profile_signing;
pub mod registry;
pub mod schema;
pub mod server;
pub mod shutdown;
pub mod telemetry;
pub mod workers;

pub use error::ServerError;

/// Installs the `ring` crypto provider as the process-wide default of rustls.
///
/// Every TLS client of the process (the database driver, the HTTP client of the egress adapter, the SMTP transport)
/// builds its configuration from the process default, and rustls refuses to guess when no provider is chosen or when
/// two are compiled in (`ENGINEERING_RULES` R11: one TLS stack, rustls with ring). The binary calls this first thing in
/// `main`; tests that exercise TLS clients call it too. Calling it again is harmless: a provider that is installed
/// already stays.
pub fn install_crypto_provider() {
    // An error means that a provider is installed already, which is what this function wants to achieve.
    drop(rustls::crypto::ring::default_provider().install_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ring_provider_becomes_the_process_default_and_installing_twice_is_harmless() {
        install_crypto_provider();
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
