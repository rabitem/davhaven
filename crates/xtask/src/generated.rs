//! Generated documents and their drift checks.
//!
//! Three documents are rendered by binaries of the workspace and committed: the configuration reference
//! (`config-docs`), the permission matrix report (`matrix`) and the problem catalog (`problems-docs`). Until the
//! generator of a document is registered, its command reports that there is nothing to generate and succeeds, so CI
//! runs the drift-check jobs with their final names. The contract documents (`contracts`: OpenAPI, MCP tool and event
//! schemas) have their own module, `contracts.rs`.
//!
//! The documents are rendered by running the binary that owns what they describe, not by linking it into this tool:
//!
//! * `config-docs` asks the server (`davhaven config reference` with every cargo feature on), because the
//!   reference is rendered from the schemas of the configuration structures and of the plugins that are compiled in,
//!   so the committed reference lists the optional adapters as well;
//! * `matrix` asks the conformance runner (`davhaven-conformance matrix-report`), because the report is rendered from
//!   the hand-reviewed expectations file by the harness that runs it, so the document a reviewer reads is the oracle
//!   the matrices run.
//!
//! Running the binaries keeps `cargo xtask arch-check` cheap (this tool does not depend on the server, the harness or
//! their dependency trees) and keeps `xtask` out of the test crates (R1).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use cargo_metadata::MetadataCommand;

use crate::contracts::{Document, Status, sync_document};
use crate::print_line;

/// The documents a command is responsible for.
fn documents(command: &str) -> &'static str {
    match command {
        "matrix" => "docs/permission-matrix.md",
        "config-docs" => "docs/configuration.md",
        "problems-docs" => "docs/problems.md",
        _ => "nothing",
    }
}

/// Generates the documents of `command`, or with `check` verifies that the committed files are current.
pub(crate) fn run(command: &str, check: bool) -> bool {
    match command {
        "config-docs" => generate(&Generated::CONFIG_REFERENCE, check),
        "matrix" => generate(&Generated::MATRIX_REPORT, check),
        _ => {
            let mode = if check { "check" } else { "generate" };
            print_line(format_args!(
                "xtask {command} ({mode}): no generator registered yet for {}; nothing to do",
                documents(command)
            ));
            true
        }
    }
}

/// A document that a binary of the workspace prints.
struct Generated {
    /// The command of this tool.
    command: &'static str,
    /// The arguments of `cargo` that run the binary.
    cargo_args: &'static [&'static str],
    /// What the invocation is called in messages.
    invocation: &'static str,
}

impl Generated {
    /// The configuration reference, printed by the server.
    const CONFIG_REFERENCE: Self = Self {
        command: "config-docs",
        cargo_args: &[
            "run",
            "--quiet",
            "--locked",
            "-p",
            "davhaven-server",
            "--all-features",
            "--",
            "config",
            "reference",
        ],
        invocation: "davhaven config reference",
    };

    /// The permission matrix report, printed by the conformance runner.
    const MATRIX_REPORT: Self = Self {
        command: "matrix",
        cargo_args: &[
            "run",
            "--quiet",
            "--locked",
            "-p",
            "davhaven-conformance",
            "--",
            "matrix-report",
        ],
        invocation: "davhaven-conformance matrix-report",
    };

    /// The text of the document, as the binary prints it.
    fn render(&self, root: &Path) -> Result<String, String> {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .current_dir(root)
            .args(self.cargo_args)
            .stderr(Stdio::inherit())
            .output()
            .map_err(|error| format!("cannot run cargo: {error}"))?;
        if !output.status.success() {
            return Err(format!("`{}` failed ({})", self.invocation, output.status));
        }
        String::from_utf8(output.stdout).map_err(|error| format!("the document is not UTF-8: {error}"))
    }
}

/// The root of the workspace this tool runs in.
fn workspace_root() -> Result<PathBuf, String> {
    MetadataCommand::new()
        .no_deps()
        .exec()
        .map(|metadata| metadata.workspace_root.into_std_path_buf())
        .map_err(|error| format!("cargo metadata failed: {error}"))
}

/// Writes the document of `generated` or checks that it is current.
fn generate(generated: &Generated, check: bool) -> bool {
    let command = generated.command;
    let outcome = workspace_root().and_then(|root| {
        let content = generated.render(&root)?;
        let document = Document {
            path: documents(command),
            content,
        };
        let status = sync_document(&root, &document, check).map_err(|error| error.to_string())?;
        Ok((document.path, status))
    });
    match outcome {
        Ok((path, Status::Current)) => {
            print_line(format_args!("{command}: {path} is up to date"));
            true
        }
        Ok((path, Status::Written)) => {
            print_line(format_args!("{command}: wrote {path}"));
            true
        }
        Ok((path, Status::Stale(difference))) => {
            print_line(format_args!(
                "error: {path} is out of date ({difference}); run `cargo xtask {command}` and commit the result"
            ));
            false
        }
        Err(error) => {
            print_line(format_args!("error: {command}: {error}"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_names_its_document() {
        assert_eq!(documents("config-docs"), "docs/configuration.md");
        assert_eq!(documents("matrix"), "docs/permission-matrix.md");
        assert_eq!(documents("problems-docs"), "docs/problems.md");
        for generated in [Generated::CONFIG_REFERENCE, Generated::MATRIX_REPORT] {
            assert_ne!(documents(generated.command), "nothing", "{}", generated.command);
        }
    }

    #[test]
    fn the_matrix_report_is_printed_by_the_conformance_runner() {
        let args = Generated::MATRIX_REPORT.cargo_args;
        assert_eq!(args.first(), Some(&"run"));
        assert!(args.contains(&"--locked"), "the lock file is never changed by a check");
        let package = args.iter().position(|arg| *arg == "-p").and_then(|at| args.get(at + 1));
        assert_eq!(package, Some(&"davhaven-conformance"));
        assert_eq!(args.last(), Some(&"matrix-report"));
    }

    #[test]
    fn the_configuration_reference_is_printed_by_the_server_with_every_feature() {
        let args = Generated::CONFIG_REFERENCE.cargo_args;
        assert!(args.contains(&"--all-features"));
        assert!(args.ends_with(&["config", "reference"]));
    }

    #[test]
    fn generators_that_are_not_registered_succeed_without_doing_anything() {
        assert!(run("problems-docs", false));
        assert!(run("problems-docs", true));
    }

    /// A generator that runs `cargo` with `cargo_args` instead of a binary of the workspace.
    fn stand_in(command: &'static str, cargo_args: &'static [&'static str]) -> Generated {
        Generated {
            command,
            cargo_args,
            invocation: "stand-in generator",
        }
    }

    #[test]
    fn the_document_is_what_the_binary_prints_on_standard_output() {
        let root = workspace_root().unwrap();
        let text = stand_in("config-docs", &["--version"]).render(&root).unwrap();
        assert!(text.starts_with("cargo "), "{text}");
    }

    #[test]
    fn a_generator_that_fails_fails_the_command_and_writes_nothing() {
        let root = workspace_root().unwrap();
        let broken = stand_in("unregistered", &["no-such-subcommand-of-cargo"]);
        let error = broken.render(&root).unwrap_err();
        assert!(error.starts_with("`stand-in generator` failed"), "{error}");
        assert!(!generate(&broken, false));
        assert!(
            !root.join(documents("unregistered")).exists(),
            "a failed generator leaves no file behind"
        );
    }

    #[test]
    fn a_committed_document_that_differs_from_the_output_fails_the_check() {
        // `cargo --version` is not the configuration reference, so the committed reference is stale for this generator; the
        // check reports it and leaves the file alone.
        let path = workspace_root().unwrap().join("docs/configuration.md");
        let before = std::fs::read(&path).unwrap();
        assert!(!generate(&stand_in("config-docs", &["--version"]), true));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
