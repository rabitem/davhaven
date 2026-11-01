//! The exit status of `davhaven-conformance` as a process: 0 when everything passed, 1 when a case or a scenario failed, 2
//! when the runner itself could not run. CI and the staging gate decide on these numbers alone, so a failure that exits with 0
//! would let a broken harness or a broken instance through.

#![expect(
    clippy::expect_used,
    reason = "the helpers of an integration test crate are not covered by allow-expect-in-tests"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Runs the binary with `args`.
fn conformance(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_davhaven-conformance"))
        .args(args)
        .output()
        .expect("the binary starts")
}

/// The scenarios of the repository.
fn scenarios() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../it/tests/scenarios")
}

/// A directory of its own below the temporary directory, removed when it is dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("davhaven-conformance-exit-{name}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

#[test]
fn the_matrix_report_exits_with_zero_and_prints_the_document() {
    let output = conformance(&["matrix-report"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.starts_with(b"# Permission matrix\n"));
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn a_check_that_finds_a_problem_exits_with_one() {
    let scratch = Scratch::new("duplicates");
    let crud = std::fs::read_to_string(scenarios().join("apple-calendar/crud.yaml")).unwrap();
    std::fs::write(scratch.0.join("first.yaml"), &crud).unwrap();
    std::fs::write(scratch.0.join("second.yaml"), &crud).unwrap();
    let output = conformance(&["check", "--scenarios", scratch.0.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("is used by 2 scenarios"));
}

#[test]
fn a_runner_that_cannot_read_its_files_exits_with_two_and_says_why_on_standard_error() {
    let scratch = Scratch::new("missing");
    let missing = scratch.0.join("expectations.toml");
    let output = conformance(&["check", "--expectations", missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with(&format!("davhaven-conformance: {}: ", missing.display())),
        "{stderr}"
    );
}

#[test]
fn a_run_that_would_send_the_tokens_in_clear_text_exits_with_two_before_it_sends_anything() {
    // The address is never contacted: the transport is refused before a token is read.
    let output = conformance(&["run", "--base-url", "http://calendar.example/", "--no-flows"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--insecure-http"));
    assert_eq!(output.stdout, Vec::<u8>::new());
}

#[test]
fn an_unknown_command_is_a_usage_error() {
    let output = conformance(&["verify"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}
