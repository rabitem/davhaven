//! `unsupported`: lists the remaining `AppError::unsupported()` / `PortError::unsupported()` stubs.
//!
//! `ENGINEERING_RULES.md` R5 allows these stubs only while an operation is not implemented yet. CI runs the scan on every pull
//! request and on `main` as a warning (GitHub annotations) and with `--deny` on release tags, where any stub is an
//! error.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cargo_metadata::MetadataCommand;

use crate::{XtaskError, print_line};

/// The call pattern of a stub: an associated `unsupported()` constructor reached through a path.
const PATTERN: &str = "::unsupported()";

/// One stub call site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Stub {
    /// Path relative to the workspace root, with `/` separators.
    pub(crate) path: String,
    /// One-based line number.
    pub(crate) line: usize,
}

/// Scans the workspace; with `deny` any stub fails the command, otherwise stubs are reported as warnings.
pub(crate) fn run(deny: bool) -> Result<bool, XtaskError> {
    let metadata = MetadataCommand::new().no_deps().exec()?;
    let root = metadata.workspace_root.into_std_path_buf();
    let mut files = BTreeSet::new();
    collect_rust_files(&root.join("crates"), &mut files)?;

    let mut stubs = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&root).unwrap_or(file);
        let shown = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if shown.starts_with("crates/xtask/") {
            continue;
        }
        let source = std::fs::read_to_string(file).map_err(|source| XtaskError::Read {
            path: file.clone(),
            source,
        })?;
        stubs.extend(find_stubs(&shown, &source));
    }

    let annotate = std::env::var_os("GITHUB_ACTIONS").is_some();
    let level = if deny { "error" } else { "warning" };
    for stub in &stubs {
        if annotate {
            print_line(format_args!(
                "::{level} file={},line={}::unsupported() stub left (R5)",
                stub.path, stub.line
            ));
        } else {
            print_line(format_args!(
                "{level}: {}:{}: unsupported() stub left (R5)",
                stub.path, stub.line
            ));
        }
    }
    print_line(format_args!(
        "unsupported: {} stub(s) in {} file(s) scanned",
        stubs.len(),
        files.len()
    ));
    Ok(!deny || stubs.is_empty())
}

/// Recursively collects `*.rs` files below `dir`, skipping build output.
fn collect_rust_files(dir: &Path, out: &mut BTreeSet<PathBuf>) -> Result<(), XtaskError> {
    let entries = std::fs::read_dir(dir).map_err(|source| XtaskError::Read {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| XtaskError::Read {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| XtaskError::Read {
            path: path.clone(),
            source,
        })?;
        if file_type.is_dir() {
            if entry.file_name() != "target" {
                collect_rust_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.insert(path);
        }
    }
    Ok(())
}

/// Stub call sites in one source file; comment lines (including doc comments) are ignored.
pub(crate) fn find_stubs(path: &str, source: &str) -> Vec<Stub> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.trim_start();
            !code.starts_with("//") && code.contains(PATTERN)
        })
        .map(|(index, _)| Stub {
            path: path.to_owned(),
            line: index + 1,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_calls_but_not_definitions_or_comments() {
        let source = "\
/// Returns `AppError::unsupported()` not implemented yet.
pub fn unsupported() -> Self { todo }
fn a() -> Result<(), AppError> { Err(AppError::unsupported()) }
    // PortError::unsupported() in a comment
fn b() -> Result<(), PortError> {
    Err(Self::unsupported())
}
";
        let stubs = find_stubs("crates/app/src/x.rs", source);
        assert_eq!(
            stubs,
            vec![
                Stub {
                    path: "crates/app/src/x.rs".to_owned(),
                    line: 3
                },
                Stub {
                    path: "crates/app/src/x.rs".to_owned(),
                    line: 6
                },
            ]
        );
    }

    #[test]
    fn clean_sources_have_no_stubs() {
        assert_eq!(find_stubs("a.rs", "fn main() {}\n"), Vec::<Stub>::new());
    }

    #[test]
    fn a_call_followed_by_a_comment_is_still_a_stub() {
        let stubs = find_stubs("a.rs", "    Err(AppError::unsupported()) // not implemented yet\n");
        assert_eq!(
            stubs,
            vec![Stub {
                path: "a.rs".to_owned(),
                line: 1
            }]
        );
    }

    #[test]
    fn every_rust_file_below_the_crates_is_scanned_except_build_output() {
        let root = tempfile::tempdir().unwrap();
        for file in [
            "app/src/lib.rs",
            "app/src/deep/nested/mod.rs",
            "app/tests/flow.rs",
            "app/README.md",
            "app/target/debug/build/out.rs",
        ] {
            let path = root.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "").unwrap();
        }
        let mut files = BTreeSet::new();
        collect_rust_files(root.path(), &mut files).unwrap();
        let found: Vec<PathBuf> = files
            .into_iter()
            .map(|file| file.strip_prefix(root.path()).unwrap().to_path_buf())
            .collect();
        assert_eq!(
            found,
            vec![
                Path::new("app/src/deep/nested/mod.rs").to_path_buf(),
                Path::new("app/src/lib.rs").to_path_buf(),
                Path::new("app/tests/flow.rs").to_path_buf(),
            ]
        );
    }

    #[test]
    fn a_missing_directory_is_an_error_that_names_it() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("crates");
        match collect_rust_files(&missing, &mut BTreeSet::new()) {
            Err(XtaskError::Read { path, .. }) => assert_eq!(path, missing),
            other => panic!("expected a read error, got {other:?}"),
        }
    }
}
