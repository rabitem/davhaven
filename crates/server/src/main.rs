//! The `davhaven` command.
//!
//! Entry point of the server binary. The command line interface (`serve`, `migrate`, `config check`,
//! `healthcheck`, `admin ...`) lives in the `davhaven_server::cli` module of the library.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // Before anything builds a TLS client: rustls needs to know which crypto provider the process uses.
    davhaven_server::install_crypto_provider();
    davhaven_server::cli::main_with(std::env::args_os())
}
