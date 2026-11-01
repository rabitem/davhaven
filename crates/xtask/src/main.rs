//! Repository automation for Davhaven.
//!
//! Run with `cargo xtask <command>` (alias defined in `.cargo/config.toml`) or
//! `cargo run -p xtask -- <command>`:
//!
//! * `arch-check` enforces the layering rules (`ENGINEERING_RULES.md` R1, PLAN 2.1) on normal, build and
//!   dev-dependencies, plus manifest hygiene (workspace lints, workspace dependencies, `forbid(unsafe_code)`) and the fuzz
//!   targets (each one runs in the nightly workflow, `fuzz.rs`).
//! * `contracts` writes `docs/openapi.json`, `docs/contracts/mcp-tools.json` and `docs/contracts/events.schema.json`
//!   from code; `matrix`, `config-docs` and `problems-docs` generate the other committed documents. With `--check`
//!   they fail when the committed files differ from the generated ones.
//! * `unsupported` lists the `AppError::unsupported()` / `PortError::unsupported()` stubs in the code the server
//!   binary links, without test code (R5); with `--deny` (release tags) any stub without an `unsupported-allowed:`
//!   annotation fails the command.

#![forbid(unsafe_code)]

mod arch;
mod contracts;
mod fuzz;
mod generated;
mod unsupported;

use std::fmt::Display;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

/// Errors of the xtask commands.
#[derive(Debug, thiserror::Error)]
enum XtaskError {
    #[error("usage: {0}")]
    Usage(String),
    #[error("cargo metadata failed: {0}")]
    Metadata(#[from] cargo_metadata::Error),
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot serialize a contract document: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("cannot parse {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
}

const USAGE: &str = "cargo xtask <command>

Commands:
  arch-check               check layering rules, manifest hygiene and the fuzz targets
  contracts [--check]      generate (or check) OpenAPI, MCP tool and event schemas
  matrix [--check]         generate (or check) docs/permission-matrix.md
  config-docs [--check]    generate (or check) docs/configuration.md
  problems-docs [--check]  generate (or check) docs/problems.md
  unsupported [--deny]     list remaining unsupported() stubs (fail with --deny)
  help                     show this message";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprint_line(format_args!("xtask: {err}"));
            ExitCode::from(2)
        }
    }
}

/// Runs one command; `Ok(false)` means the command ran and found problems.
fn run(args: &[String]) -> Result<bool, XtaskError> {
    let (command, rest) = match args.split_first() {
        Some((command, rest)) => (command.as_str(), rest),
        None => ("help", &[][..]),
    };
    match command {
        "arch-check" => {
            no_extra_args(command, rest)?;
            arch::run()
        }
        "contracts" => {
            let check = parse_flag(command, rest, "--check")?;
            contracts::run(check)
        }
        "matrix" | "config-docs" | "problems-docs" => {
            let check = parse_flag(command, rest, "--check")?;
            Ok(generated::run(command, check))
        }
        "unsupported" => {
            let deny = parse_flag(command, rest, "--deny")?;
            unsupported::run(deny)
        }
        "help" | "--help" | "-h" => {
            print_line(USAGE);
            Ok(true)
        }
        other => Err(XtaskError::Usage(format!("unknown command `{other}`\n\n{USAGE}"))),
    }
}

fn no_extra_args(command: &str, rest: &[String]) -> Result<(), XtaskError> {
    match rest.first() {
        None => Ok(()),
        Some(arg) => Err(XtaskError::Usage(format!("`{command}` takes no argument, got `{arg}`"))),
    }
}

/// Parses the single optional `flag` of a command.
fn parse_flag(command: &str, rest: &[String], flag: &str) -> Result<bool, XtaskError> {
    match rest {
        [] => Ok(false),
        [arg] if arg == flag => Ok(true),
        [arg, ..] => Err(XtaskError::Usage(format!(
            "`{command}` accepts only `{flag}`, got `{arg}`"
        ))),
    }
}

/// Writes one line to standard output; a closed pipe is not an error worth reporting.
fn print_line(line: impl Display) {
    let mut out = std::io::stdout().lock();
    drop(writeln!(out, "{line}"));
}

/// Writes one line to standard error.
fn eprint_line(line: impl Display) {
    let mut err = std::io::stderr().lock();
    drop(writeln!(err, "{line}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    fn usage_error(list: &[&str]) -> String {
        match run(&args(list)) {
            Err(XtaskError::Usage(message)) => message,
            other => panic!("{list:?}: expected a usage error, got {other:?}"),
        }
    }

    #[test]
    fn without_a_command_the_usage_is_shown_and_the_run_succeeds() {
        assert!(run(&[]).unwrap());
        for help in ["help", "--help", "-h"] {
            assert!(run(&args(&[help])).unwrap(), "{help}");
        }
    }

    #[test]
    fn an_unknown_command_is_a_usage_error_that_lists_the_commands() {
        let message = usage_error(&["contract"]);
        assert!(message.starts_with("unknown command `contract`"), "{message}");
        assert!(message.contains("arch-check"), "{message}");
    }

    #[test]
    fn a_misspelt_flag_never_runs_the_command_in_the_other_mode() {
        // `contracts --chek` in a CI job must fail instead of regenerating the documents and passing.
        assert_eq!(
            usage_error(&["contracts", "--chek"]),
            "`contracts` accepts only `--check`, got `--chek`"
        );
        assert_eq!(
            usage_error(&["matrix", "--deny"]),
            "`matrix` accepts only `--check`, got `--deny`"
        );
        assert_eq!(
            usage_error(&["unsupported", "--check"]),
            "`unsupported` accepts only `--deny`, got `--check`"
        );
        // A second argument after the flag is refused as well.
        assert!(usage_error(&["config-docs", "--check", "--check"]).contains("accepts only `--check`"));
    }

    #[test]
    fn the_architecture_check_takes_no_argument() {
        assert_eq!(
            usage_error(&["arch-check", "--check"]),
            "`arch-check` takes no argument, got `--check`"
        );
    }

    #[test]
    fn each_command_recognises_only_its_own_flag() {
        assert!(!parse_flag("contracts", &[], "--check").unwrap());
        assert!(parse_flag("contracts", &args(&["--check"]), "--check").unwrap());
        assert!(parse_flag("unsupported", &args(&["--deny"]), "--deny").unwrap());
        assert!(no_extra_args("arch-check", &[]).is_ok());
    }

    #[test]
    fn a_command_without_a_generator_succeeds_through_the_dispatcher() {
        assert!(run(&args(&["problems-docs", "--check"])).unwrap());
    }
}
