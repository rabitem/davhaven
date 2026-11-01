//! Black-box conformance runner of Davhaven.
//!
//! Runs the permission matrix and the client flows of `davhaven-testkit` over HTTP against a deployed instance (for example
//! the staging deployment that every merge to `main` is gated on), on an ephemeral pair of tenants of the run's own, and
//! checks and converts the files the harness reads and writes.
//!
//! ```text
//! davhaven-conformance check [--scenarios DIR] [--expectations FILE]
//! davhaven-conformance matrix-report
//! davhaven-conformance run --base-url URL --tenant-token-file A --other-tenant-token-file B [--system-token-file S]
//!                            [--principal-token-command COMMAND] [--data-dir DIR] [--scenarios DIR] [--insecure-http]
//!                            [--reset-between-writes] [--keep]
//! davhaven-conformance convert CAPTURE_DIR --name N --client C --feature F --provenance P [--out FILE]
//! ```
//!
//! * `check` reads the expectations file and every scenario, checks that the matrix covers every route, method and tool
//!   of the server, and prints the client-by-feature grid (PLAN 3.4): the cells that only have synthetic scenarios are the ones
//!   no real client has confirmed yet. It needs no network.
//! * `matrix-report` prints `docs/permission-matrix.md`; `cargo xtask matrix` runs it to write and to check the committed copy.
//! * `run` provisions the fixture world of the run on the instance, runs the matrices and the flows, and deletes the tenants.
//!   What the operator has to prepare is described in the documentation of `davhaven_testkit::staging` and in
//!   `docs/testing.md`; the MCP cases of the users need tokens that only `davhaven admin principal-token create` issues, which
//!   `--principal-token-command` runs (see the `issuer` module).
//! * `convert` turns the exchanges that `observability.dav_capture` recorded into a scenario marked `captured`.
//!
//! The exit status is 0 when everything passed, 1 when a case or a scenario failed and 2 when the runner itself could not run
//! (bad arguments, unreadable files, an instance that cannot be prepared).

#![forbid(unsafe_code)]

mod check;
mod cli;
mod convert;
mod issuer;
mod run;
#[cfg(test)]
mod scratch;

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser as _;
use davhaven_testkit::Expectations;
use davhaven_testkit::convert::ConvertError;
use davhaven_testkit::davhaven_ports::{Clock, SystemClock};
use davhaven_testkit::flow::FlowError;
use davhaven_testkit::matrix::MatrixError;
use davhaven_testkit::staging::StagingError;

use crate::cli::{Cli, Command};

/// Why the runner itself could not run.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RunnerError {
    /// The arguments do not make sense together.
    #[error("{0}")]
    Usage(String),
    /// A file cannot be read or written.
    #[error("{path}: {reason}")]
    File {
        /// The path.
        path: String,
        /// The operating system's message.
        reason: String,
    },
    /// The expectations file is not valid.
    #[error(transparent)]
    Matrix(#[from] MatrixError),
    /// A scenario file is not valid.
    #[error(transparent)]
    Flow(#[from] FlowError),
    /// The instance cannot be prepared.
    #[error(transparent)]
    Staging(#[from] StagingError),
    /// The captures cannot be converted.
    #[error(transparent)]
    Convert(#[from] ConvertError),
    /// The report cannot be written.
    #[error("cannot write the report: {0}")]
    Output(#[from] std::io::Error),
}

/// The expectations file at `path`, or the one bundled with the harness.
pub(crate) fn load_expectations(path: Option<&Path>) -> Result<Expectations, RunnerError> {
    match path {
        None => Ok(Expectations::bundled()?),
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|error| RunnerError::File {
                path: path.display().to_string(),
                reason: error.to_string(),
            })?;
            Ok(Expectations::parse(&text)?)
        }
    }
}

/// Runs the command and writes its report to `out`; the result says whether everything passed.
pub(crate) async fn execute(cli: &Cli, out: &mut dyn Write, clock: Arc<dyn Clock>) -> Result<bool, RunnerError> {
    match &cli.command {
        Command::Check(args) => check::check(args, out),
        Command::MatrixReport(args) => check::matrix_report(args, out),
        Command::Run(args) => run::run(args, out, clock).await,
        Command::Convert(args) => convert::convert(args, out),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stdout = std::io::stdout().lock();
    match execute(&cli, &mut stdout, Arc::new(SystemClock)).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            let mut stderr = std::io::stderr().lock();
            drop(writeln!(stderr, "davhaven-conformance: {error}"));
            ExitCode::from(2)
        }
    }
}
