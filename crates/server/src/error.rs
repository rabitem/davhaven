//! The error of starting and running the server.

use std::net::SocketAddr;

use davhaven_domain::UrlError;
use davhaven_ports::{PluginError, StoreError};

use crate::config::ConfigError;
use crate::telemetry::TelemetryError;

/// Why the server, or a command that builds the application, cannot start.
///
/// The texts are for the operator who reads the log or the terminal: they name the key or the adapter, and never
/// contain a secret (the adapters' errors are written that way).
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The configuration is not usable.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// An adapter cannot be built.
    #[error(transparent)]
    Plugin(#[from] PluginError),
    /// A listener cannot bind its address.
    #[error("cannot bind the {listener} listener to {address}: {source}")]
    Bind {
        /// The listener (`public`, `internal`, `ops`).
        listener: &'static str,
        /// The address from the configuration.
        address: SocketAddr,
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },
    /// Logging, metrics or tracing cannot start.
    #[error(transparent)]
    Telemetry(#[from] TelemetryError),
    /// The public base URL is not usable (checked by the configuration as well).
    #[error("invalid configuration `server.public_base_url`: {0}")]
    PublicUrl(String),
    /// The store failed during an administrative command.
    #[error("the store failed: {0}")]
    Store(#[from] StoreError),
    /// The operating system refused something the server needs (signal handlers, the files of a command).
    #[error("{context}: {source}")]
    Io {
        /// What was attempted.
        context: String,
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },
    /// A task on the blocking pool did not finish: it panicked, or the runtime ended while it ran.
    #[error("{task} did not finish: {source}")]
    Task {
        /// What the task was doing, as a noun phrase (`the check of the configuration`).
        task: &'static str,
        /// Why it did not finish.
        #[source]
        source: tokio::task::JoinError,
    },
    /// An administrative command cannot do what it was asked.
    #[error("{0}")]
    Command(String),
}

impl ServerError {
    /// An I/O error with the name of what was attempted.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

impl From<UrlError> for ServerError {
    fn from(error: UrlError) -> Self {
        Self::PublicUrl(error.reason().to_owned())
    }
}
