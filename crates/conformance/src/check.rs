//! `check` and `matrix-report`: the commands that read the harness' own files and send nothing.

use std::collections::BTreeMap;
use std::io::Write;

use davhaven_testkit::report::permission_matrix;
use davhaven_testkit::{coverage, flow};

use crate::cli::{CheckArgs, MatrixReportArgs};
use crate::{RunnerError, load_expectations};

/// Validates the expectations and the scenarios and prints the client-by-feature grid. The result is `false` when something
/// is wrong with the files; a grid with synthetic cells is a report, not a failure.
pub(crate) fn check(args: &CheckArgs, out: &mut dyn Write) -> Result<bool, RunnerError> {
    let mut clean = true;
    let expectations = load_expectations(args.expectations.as_deref())?;
    let shadowed = expectations.shadowed_exceptions();
    writeln!(
        out,
        "expectations: valid, {} exception rows, {} of them shadowed by earlier rows",
        expectations.exception_count(),
        shadowed.len()
    )?;
    if !shadowed.is_empty() {
        clean = false;
        writeln!(
            out,
            "  the exception rows {shadowed:?} (counting from zero) decide no case: remove or move them"
        )?;
    }

    let coverage = coverage::check(&expectations);
    writeln!(
        out,
        "coverage: {} API operations, {} DAV methods on the kinds of resources, {} MCP tools and the web pages map to the matrix",
        coverage.api_operations, coverage.dav_methods, coverage.mcp_tools
    )?;
    for problem in &coverage.problems {
        clean = false;
        writeln!(out, "  {problem}")?;
    }

    let scenarios = flow::load_scenarios(&args.scenarios)?;
    writeln!(
        out,
        "scenarios: {} read from {}",
        scenarios.len(),
        args.scenarios.display()
    )?;
    let mut names: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, scenario) in &scenarios {
        *names.entry(scenario.name.as_str()).or_default() += 1;
    }
    for (name, count) in names.iter().filter(|(_, count)| **count > 1) {
        clean = false;
        writeln!(out, "  the name `{name}` is used by {count} scenarios")?;
    }
    let with_known_issue = scenarios
        .iter()
        .filter(|(_, scenario)| scenario.known_issue.is_some())
        .count();
    if with_known_issue > 0 {
        writeln!(
            out,
            "  {with_known_issue} scenarios document a known issue of the server"
        )?;
    }
    let cells = flow::grid(scenarios.iter().map(|(_, scenario)| scenario));
    let synthetic_only = cells.values().filter(|cell| cell.captured == 0).count();
    writeln!(
        out,
        "client-by-feature grid: {} cells, {synthetic_only} with synthetic scenarios only",
        cells.len()
    )?;
    for ((client, feature), cell) in &cells {
        let note = if cell.captured == 0 { "  (synthetic only)" } else { "" };
        writeln!(
            out,
            "  {client} x {feature}: {} synthetic, {} captured{note}",
            cell.synthetic, cell.captured
        )?;
    }
    Ok(clean)
}

/// Prints the permission matrix document, byte for byte what `docs/permission-matrix.md` holds.
pub(crate) fn matrix_report(args: &MatrixReportArgs, out: &mut dyn Write) -> Result<bool, RunnerError> {
    let expectations = load_expectations(args.expectations.as_deref())?;
    let document = permission_matrix(&expectations)?;
    out.write_all(document.as_bytes())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::default_scenarios;
    use crate::scratch::Scratch;

    fn run_check(scenarios: PathBuf, expectations: Option<PathBuf>) -> (Result<bool, RunnerError>, String) {
        let mut report = Vec::new();
        let result = check(
            &CheckArgs {
                scenarios,
                expectations,
            },
            &mut report,
        );
        (result, String::from_utf8(report).unwrap())
    }

    #[test]
    fn the_repository_passes_its_own_check_and_the_grid_is_printed() {
        let (result, text) = run_check(default_scenarios(), None);
        assert!(result.unwrap(), "{text}");
        assert!(text.contains("expectations: valid"), "{text}");
        assert!(text.contains("0 of them shadowed"), "{text}");
        assert!(text.contains("coverage: 61 API operations"), "{text}");
        assert!(text.contains("apple-calendar x crud: "), "{text}");
        assert!(text.contains("(synthetic only)"), "{text}");
    }

    #[test]
    fn a_missing_directory_or_file_is_a_runner_error() {
        let (result, _) = run_check(PathBuf::from("/no/such/dir"), None);
        assert!(matches!(result, Err(RunnerError::Flow(_))));
        let (result, _) = run_check(default_scenarios(), Some(PathBuf::from("/no/such/file.toml")));
        assert!(matches!(result, Err(RunnerError::File { .. })));
    }

    #[test]
    fn an_exception_row_that_decides_no_case_fails_the_check() {
        // The row of the requests without a credential again, at the end: every case it matches is decided by the earlier one.
        let scratch = Scratch::new("shadowed");
        let rows = davhaven_testkit::Expectations::bundled().unwrap().exception_count();
        let expectations = scratch.file(
            "expectations.toml",
            &format!(
                "{}\n[[exception]]\nactor = \"anonymous\"\nexpect = \"unauthenticated\"\n",
                davhaven_testkit::matrix::BUNDLED
            ),
        );
        let (result, text) = run_check(default_scenarios(), Some(expectations));
        assert!(!result.unwrap(), "{text}");
        assert!(
            text.contains(&format!("{} exception rows, 1 of them shadowed", rows + 1)),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "the exception rows [{rows}] (counting from zero) decide no case"
            )),
            "{text}"
        );
    }

    #[test]
    fn an_expectations_file_that_is_not_valid_is_a_runner_error() {
        let scratch = Scratch::new("invalid-expectations");
        let expectations = scratch.file("expectations.toml", "[[exception]]\nactor = \"nobody\"\n");
        let (result, _) = run_check(default_scenarios(), Some(expectations));
        assert!(matches!(result, Err(RunnerError::Matrix(_))), "{result:?}");
    }

    #[test]
    fn two_scenarios_with_one_name_fail_the_check() {
        let scratch = Scratch::new("duplicate-names");
        let crud = std::fs::read_to_string(default_scenarios().join("apple-calendar/crud.yaml")).unwrap();
        scratch.file("first.yaml", &crud);
        scratch.file("second.yaml", &crud);
        let (result, text) = run_check(scratch.0.clone(), None);
        assert!(!result.unwrap(), "{text}");
        assert!(text.contains("scenarios: 2 read from"), "{text}");
        assert!(text.contains("is used by 2 scenarios"), "{text}");
        // The grid is a report: one client and one feature, confirmed by no captured scenario.
        assert!(
            text.contains("client-by-feature grid: 1 cells, 1 with synthetic scenarios only"),
            "{text}"
        );
        assert!(
            text.contains("apple-calendar x crud: 2 synthetic, 0 captured  (synthetic only)"),
            "{text}"
        );
    }

    #[test]
    fn the_matrix_report_is_the_document_the_harness_renders() {
        let mut printed = Vec::new();
        assert!(matrix_report(&MatrixReportArgs { expectations: None }, &mut printed).unwrap());
        let text = String::from_utf8(printed).unwrap();
        assert!(
            text.starts_with("# Permission matrix\n"),
            "{}",
            text.chars().take(80).collect::<String>()
        );
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
    }
}
