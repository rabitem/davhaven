//! `unsupported`: lists the `AppError::unsupported()` / `PortError::unsupported()` stubs that a release ships.
//!
//! `ENGINEERING_RULES.md` R5 allows these stubs only while an operation is not implemented yet. The scan covers the code
//! a user can reach: the library and binary sources of the workspace packages that the server binary links
//! (`davhaven-server` and its normal dependencies, optional ones included, so every cargo feature counts), without
//! test code (`#[cfg(test)]` items and the modules they declare out of line). Test doubles, test-support crates
//! (`davhaven-app-fake`, `davhaven-port-tests`, ...), integration tests and benches are not scanned: no user reaches
//! them.
//!
//! A stub that ships but that no user can reach, such as the default body of a service-trait method that every
//! production implementation overrides, is allowed when an annotation with a reason sits on its line or in the comment
//! block directly above it:
//!
//! ```text
//! // unsupported-allowed: AuthServiceImpl implements the method; the default serves test doubles
//! Err(AppError::unsupported())
//! ```
//!
//! Allowed stubs are listed with their reason as notes, never dropped silently. An adapter that permanently lacks a
//! capability does not use the stub at all: it answers `PortErrorKind::Unsupported` through `PortError::new`.
//!
//! CI runs the scan on every pull request and on `main` as a warning (GitHub annotations) and with `--deny` on release
//! tags, where any stub that is not allowed fails the run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use cargo_metadata::{DependencyKind, MetadataCommand, TargetKind};

use crate::{XtaskError, print_line};

/// The call pattern of a stub: an associated `unsupported()` constructor reached through a path.
const PATTERN: &str = "::unsupported()";

/// The annotation that allows a stub; the reason follows it on the same line.
const ALLOW_MARKER: &str = "unsupported-allowed:";

/// The packages whose binaries are released (the container image builds `davhaven-server`).
const SHIPPED_ROOTS: &[&str] = &["davhaven-server"];

/// One stub call site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Stub {
    /// Path relative to the workspace root, with `/` separators.
    pub(crate) path: String,
    /// One-based line number.
    pub(crate) line: usize,
}

/// A stub with an `unsupported-allowed:` annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Allowed {
    /// The call site.
    pub(crate) stub: Stub,
    /// The reason the annotation gives.
    pub(crate) reason: String,
}

/// What the scan finds in one source file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FileScan {
    /// Stubs outside test code without an annotation.
    pub(crate) stubs: Vec<Stub>,
    /// Stubs outside test code with an annotation.
    pub(crate) allowed: Vec<Allowed>,
    /// The modules the file declares out of line under `#[cfg(test)]` (`mod tests;`).
    pub(crate) test_modules: Vec<String>,
}

/// Scans the shipped code; with `deny` any stub that is not allowed fails the command, otherwise stubs are warnings.
pub(crate) fn run(deny: bool) -> Result<bool, XtaskError> {
    let metadata = MetadataCommand::new().no_deps().exec()?;
    let root = metadata.workspace_root.clone().into_std_path_buf();
    let packages = metadata.workspace_packages();

    let graph: BTreeMap<String, Vec<String>> = packages
        .iter()
        .map(|package| {
            let normal = package
                .dependencies
                .iter()
                .filter(|dependency| dependency.kind == DependencyKind::Normal)
                .map(|dependency| dependency.name.clone())
                .collect();
            (package.name.to_string(), normal)
        })
        .collect();
    let shipped = shipped_packages(&graph, SHIPPED_ROOTS);

    let mut crate_roots = BTreeSet::new();
    let mut files = BTreeSet::new();
    for package in packages
        .iter()
        .filter(|package| shipped.contains(package.name.as_str()))
    {
        for target in &package.targets {
            let ships = target.kind.iter().any(|kind| {
                matches!(
                    kind,
                    TargetKind::Lib | TargetKind::RLib | TargetKind::Bin | TargetKind::ProcMacro
                )
            });
            if !ships {
                continue;
            }
            let src_path = target.src_path.clone().into_std_path_buf();
            if let Some(dir) = src_path.parent() {
                collect_rust_files(dir, &mut files)?;
            }
            crate_roots.insert(src_path);
        }
    }

    let mut scans = BTreeMap::new();
    for file in &files {
        let source = std::fs::read_to_string(file).map_err(|source| XtaskError::Read {
            path: file.clone(),
            source,
        })?;
        scans.insert(file.clone(), scan_source(&shown_path(&root, file), &source));
    }
    let test_files = test_module_files(&scans, &crate_roots);

    let annotate = std::env::var_os("GITHUB_ACTIONS").is_some();
    let level = if deny { "error" } else { "warning" };
    let (mut stubs, mut allowed) = (Vec::new(), Vec::new());
    for (file, scan) in &scans {
        if !test_files.contains(file) {
            stubs.extend(scan.stubs.iter().cloned());
            allowed.extend(scan.allowed.iter().cloned());
        }
    }
    for entry in &allowed {
        let Allowed { stub, reason } = entry;
        if annotate {
            print_line(format_args!(
                "::notice file={},line={}::allowed unsupported() stub: {reason}",
                stub.path, stub.line
            ));
        } else {
            print_line(format_args!(
                "note: {}:{}: allowed unsupported() stub: {reason}",
                stub.path, stub.line
            ));
        }
    }
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
        "unsupported: {} stub(s), {} allowed, in {} shipped file(s) of {} package(s) ({} test file(s) skipped)",
        stubs.len(),
        allowed.len(),
        files.len() - test_files.len(),
        shipped.len(),
        test_files.len()
    ));
    Ok(!deny || stubs.is_empty())
}

/// `file` relative to `root`, with `/` separators.
fn shown_path(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// The packages of `graph` (package to its normal dependencies) that `roots` reach, the roots included. Dependencies
/// outside the graph (crates.io) are ignored; development and build dependencies are not in the graph.
pub(crate) fn shipped_packages(graph: &BTreeMap<String, Vec<String>>, roots: &[&str]) -> BTreeSet<String> {
    let mut reached = BTreeSet::new();
    let mut pending: Vec<String> = roots
        .iter()
        .filter(|root| graph.contains_key(**root))
        .map(|root| (*root).to_owned())
        .collect();
    while let Some(package) = pending.pop() {
        if !reached.insert(package.clone()) {
            continue;
        }
        if let Some(dependencies) = graph.get(&package) {
            pending.extend(
                dependencies
                    .iter()
                    .filter(|dependency| graph.contains_key(dependency.as_str()) && !reached.contains(*dependency))
                    .cloned(),
            );
        }
    }
    reached
}

/// The directory that holds the out-of-line child modules of `file`: its own directory for a crate root and a
/// `mod.rs`, a directory named after it otherwise.
fn module_dir(file: &Path, crate_roots: &BTreeSet<PathBuf>) -> PathBuf {
    let parent = file.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
    let is_mod_rs = file.file_name().is_some_and(|name| name == "mod.rs");
    if is_mod_rs || crate_roots.contains(file) {
        return parent;
    }
    match file.file_stem() {
        Some(stem) => parent.join(stem),
        None => parent,
    }
}

/// The files of `scans` that belong to a module declared under `#[cfg(test)]`: `name.rs`, `name/mod.rs` and
/// everything below `name/` next to the declaring file.
pub(crate) fn test_module_files(
    scans: &BTreeMap<PathBuf, FileScan>,
    crate_roots: &BTreeSet<PathBuf>,
) -> BTreeSet<PathBuf> {
    let mut test_dirs = Vec::new();
    let mut test_files = BTreeSet::new();
    for (file, scan) in scans {
        let dir = module_dir(file, crate_roots);
        for name in &scan.test_modules {
            test_files.insert(dir.join(format!("{name}.rs")));
            test_dirs.push(dir.join(name));
        }
    }
    scans
        .keys()
        .filter(|file| test_files.contains(*file) || test_dirs.iter().any(|dir| file.starts_with(dir)))
        .cloned()
        .collect()
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

/// Stub call sites of one source file outside its test code; comment lines (including doc comments) are ignored.
pub(crate) fn scan_source(path: &str, source: &str) -> FileScan {
    let lines: Vec<&str> = source.lines().collect();
    let (in_test, test_modules) = test_lines(source, lines.len());
    let mut scan = FileScan {
        test_modules,
        ..FileScan::default()
    };
    for (index, line) in lines.iter().enumerate() {
        let code = line.trim_start();
        if in_test.get(index).copied().unwrap_or(false) || code.starts_with("//") || !code.contains(PATTERN) {
            continue;
        }
        let stub = Stub {
            path: path.to_owned(),
            line: index + 1,
        };
        match allowance(&lines, index) {
            Some(reason) => scan.allowed.push(Allowed { stub, reason }),
            None => scan.stubs.push(stub),
        }
    }
    scan
}

/// The reason of an `unsupported-allowed:` annotation on line `index` or in the comment lines directly above it.
fn allowance(lines: &[&str], index: usize) -> Option<String> {
    if let Some(reason) = lines.get(index).and_then(|line| marker_reason(line)) {
        return Some(reason);
    }
    lines
        .get(..index)?
        .iter()
        .rev()
        .take_while(|line| line.trim_start().starts_with("//"))
        .find_map(|line| marker_reason(line))
}

/// The non-empty reason of an annotation in the comment of `line`.
fn marker_reason(line: &str) -> Option<String> {
    let (_, comment) = line.split_once("//")?;
    let (_, reason) = comment.split_once(ALLOW_MARKER)?;
    let reason = reason.trim();
    (!reason.is_empty()).then(|| reason.to_owned())
}

/// The number of characters of indentation of `line`.
fn indentation(line: &str) -> usize {
    line.chars().count() - line.trim_start().chars().count()
}

/// Which of the `count` lines of `source` are test code, and the modules declared out of line under `#[cfg(test)]`.
///
/// The item after a `#[cfg(test)]` attribute is test code up to its closing brace or semicolon; `#![cfg(test)]`
/// makes the whole file test code. Other conditions (`cfg(any(test, ...))`) may hold in a release and are not test code.
fn test_lines(source: &str, count: usize) -> (Vec<bool>, Vec<String>) {
    let lines: Vec<&str> = source.lines().collect();
    if lines.iter().any(|line| line.trim() == "#![cfg(test)]") {
        return (vec![true; count], Vec::new());
    }
    let text: Vec<char> = source.chars().collect();
    let mut line_starts = vec![0_usize];
    line_starts.extend(
        text.iter()
            .enumerate()
            .filter(|(_, c)| **c == '\n')
            .map(|(at, _)| at + 1),
    );
    let line_start = |line: usize| line_starts.get(line).copied().unwrap_or(text.len());
    let line_of = |position: usize| {
        line_starts
            .partition_point(|start| *start <= position)
            .saturating_sub(1)
    };

    let mut in_test = vec![false; count];
    let mut modules = Vec::new();
    let mut index = 0;
    while let Some(line) = lines.get(index) {
        let Some(rest) = line.trim_start().strip_prefix("#[cfg(test)]") else {
            index += 1;
            continue;
        };
        // The item starts after the attribute on the same line, or on the next line that is not blank, a comment or
        // another attribute.
        let start = if rest.trim().is_empty() || rest.trim_start().starts_with("//") {
            let next = lines.iter().enumerate().skip(index + 1).find(|(_, line)| {
                let line = line.trim_start();
                !(line.is_empty() || line.starts_with("//") || line.starts_with("#["))
            });
            match next {
                Some((at, line)) => line_start(at) + indentation(line),
                None => break,
            }
        } else {
            line_start(index) + (line.chars().count() - rest.chars().count())
        };
        let end = item_end(&text, start);
        let item: String = text.iter().skip(start).take((end + 1).saturating_sub(start)).collect();
        if let Some(name) = out_of_line_module(&item) {
            modules.push(name);
        }
        let last = line_of(end).min(count.saturating_sub(1));
        for flag in in_test.iter_mut().take(last + 1).skip(index) {
            *flag = true;
        }
        index = last + 1;
    }
    (in_test, modules)
}

/// The name of a `mod name;` item (with any visibility).
fn out_of_line_module(item: &str) -> Option<String> {
    let declaration = item.trim().strip_suffix(';')?;
    let words: Vec<&str> = declaration.split_whitespace().collect();
    match words.as_slice() {
        [.., "mod", name] if words.len() <= 3 => Some((*name).to_owned()),
        _ => None,
    }
}

/// The character at `at`, if there is one.
fn char_at(text: &[char], at: usize) -> Option<char> {
    text.get(at).copied()
}

/// The position of the last character of the item that starts at `start`: its closing brace, or the semicolon of an
/// item without a body. Braces in comments, strings and character literals do not count.
fn item_end(text: &[char], start: usize) -> usize {
    let mut depth = 0_usize;
    let mut at = start;
    while let Some(current) = char_at(text, at) {
        let next = char_at(text, at + 1);
        match current {
            '/' if next == Some('/') => {
                at = (at..text.len())
                    .find(|&end| char_at(text, end) == Some('\n'))
                    .unwrap_or(text.len());
                continue;
            }
            '/' if next == Some('*') => {
                at = block_comment_end(text, at);
                continue;
            }
            '"' => {
                at = string_end(text, at + 1);
                continue;
            }
            '\'' => {
                at = quote_end(text, at);
                continue;
            }
            'r' | 'b' => {
                if let Some(end) = raw_string_end(text, at) {
                    at = end;
                    continue;
                }
            }
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return at;
                }
            }
            ';' if depth == 0 => return at,
            _ => {}
        }
        at += 1;
    }
    text.len().saturating_sub(1)
}

/// The position after the `*/` that closes the (possibly nested) block comment at `start`.
fn block_comment_end(text: &[char], start: usize) -> usize {
    let mut depth = 0_usize;
    let mut at = start;
    while let Some(current) = char_at(text, at) {
        match (current, char_at(text, at + 1)) {
            ('/', Some('*')) => {
                depth += 1;
                at += 2;
            }
            ('*', Some('/')) => {
                depth = depth.saturating_sub(1);
                at += 2;
                if depth == 0 {
                    return at;
                }
            }
            _ => at += 1,
        }
    }
    at
}

/// The position after the quote that closes the string whose content starts at `start`.
fn string_end(text: &[char], start: usize) -> usize {
    let mut at = start;
    while let Some(current) = char_at(text, at) {
        match current {
            '\\' => at += 2,
            '"' => return at + 1,
            _ => at += 1,
        }
    }
    at
}

/// The position after a character literal at `start`, or after the quote of a lifetime or label.
fn quote_end(text: &[char], start: usize) -> usize {
    match (char_at(text, start + 1), char_at(text, start + 2)) {
        (Some('\\'), _) => (start + 3..text.len())
            .find(|&at| char_at(text, at) == Some('\''))
            .map_or(text.len(), |at| at + 1),
        (Some(_), Some('\'')) => start + 3,
        _ => start + 1,
    }
}

/// The position after a raw string (`r"..."`, `r#"..."#`, `br"..."`) that starts at `start`, if one does.
fn raw_string_end(text: &[char], start: usize) -> Option<usize> {
    let after_identifier = start
        .checked_sub(1)
        .and_then(|before| char_at(text, before))
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    if after_identifier {
        return None;
    }
    let mut at = start;
    if char_at(text, at) == Some('b') {
        at += 1;
    }
    if char_at(text, at) != Some('r') {
        return None;
    }
    at += 1;
    let hashes = text.iter().skip(at).take_while(|c| **c == '#').count();
    at += hashes;
    if char_at(text, at) != Some('"') {
        return None;
    }
    at += 1;
    while let Some(current) = char_at(text, at) {
        let closes = current == '"' && text.iter().skip(at + 1).take(hashes).filter(|c| **c == '#').count() == hashes;
        if closes {
            return Some(at + 1 + hashes);
        }
        at += 1;
    }
    Some(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub(path: &str, line: usize) -> Stub {
        Stub {
            path: path.to_owned(),
            line,
        }
    }

    fn stubs(source: &str) -> Vec<usize> {
        scan_source("a.rs", source).stubs.iter().map(|stub| stub.line).collect()
    }

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
        let scan = scan_source("crates/app/src/x.rs", source);
        assert_eq!(
            scan.stubs,
            vec![stub("crates/app/src/x.rs", 3), stub("crates/app/src/x.rs", 6)]
        );
        assert_eq!(scan.allowed, Vec::new());
    }

    #[test]
    fn clean_sources_have_no_stubs() {
        assert_eq!(scan_source("a.rs", "fn main() {}\n"), FileScan::default());
    }

    #[test]
    fn a_call_followed_by_a_comment_is_still_a_stub() {
        assert_eq!(
            stubs("    Err(AppError::unsupported()) // not implemented yet\n"),
            vec![1]
        );
    }

    #[test]
    fn an_inline_test_module_is_skipped_and_the_code_after_it_is_scanned() {
        let source = "\
fn a() { Err(AppError::unsupported()) }
#[cfg(test)]
mod tests {
    struct Double;
    impl Port for Double {
        fn call(&self) -> Result<(), PortError> {
            Err(PortError::unsupported())
        }
    }
}
fn b() { Err(AppError::unsupported()) }
";
        let scan = scan_source("a.rs", source);
        assert_eq!(scan.stubs, vec![stub("a.rs", 1), stub("a.rs", 11)]);
        assert!(scan.test_modules.is_empty(), "an inline module has no file of its own");
    }

    #[test]
    fn any_item_under_cfg_test_is_test_code() {
        let source = "\
#[cfg(test)]
#[allow(dead_code)]
fn helper() -> PortError { PortError::unsupported() }
#[cfg(test)] impl Double { fn f() { AppError::unsupported(); } }
fn shipped() { AppError::unsupported(); }
";
        assert_eq!(stubs(source), vec![5]);
    }

    #[test]
    fn braces_in_strings_characters_and_comments_do_not_end_a_test_module() {
        let source = r##"
#[cfg(test)]
mod tests {
    const A: &str = "}}";
    const B: char = '}';
    const C: char = '\'';
    const D: &str = r#"}"#;
    const E: &[u8] = br"}";
    fn f<'a>(x: &'a str) -> &'a str { x } // }
    /* } /* nested } */ } */
    fn g() { Err(PortError::unsupported()) }
}
fn shipped() { AppError::unsupported(); }
"##;
        assert_eq!(stubs(source), vec![13]);
    }

    #[test]
    fn a_whole_file_under_an_inner_cfg_test_is_skipped() {
        assert_eq!(
            stubs("#![cfg(test)]\nfn f() { AppError::unsupported(); }\n"),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn a_condition_that_can_hold_in_a_release_is_not_test_code() {
        let source = "#[cfg(any(test, feature = \"fake\"))]\nfn f() { AppError::unsupported(); }\n";
        assert_eq!(stubs(source), vec![2]);
    }

    #[test]
    fn out_of_line_test_modules_are_recorded_with_any_visibility() {
        let source = "\
mod shipped;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)] mod inline_same_line;
";
        let scan = scan_source("a.rs", source);
        assert_eq!(scan.test_modules, vec!["tests", "fixture", "inline_same_line"]);
    }

    #[test]
    fn an_annotation_with_a_reason_allows_a_stub_on_its_line_or_directly_above() {
        let source = "\
fn a() {
    // The default of a trait method.
    // unsupported-allowed: the implementation overrides it
    Err(AppError::unsupported())
}
fn b() { Err(AppError::unsupported()) } // unsupported-allowed: same line
fn c() {
    // unsupported-allowed: separated by code
    let _ = 1;
    Err(AppError::unsupported())
}
fn d() {
    // unsupported-allowed:
    Err(AppError::unsupported())
}
";
        let scan = scan_source("a.rs", source);
        assert_eq!(
            scan.allowed,
            vec![
                Allowed {
                    stub: stub("a.rs", 4),
                    reason: "the implementation overrides it".to_owned()
                },
                Allowed {
                    stub: stub("a.rs", 6),
                    reason: "same line".to_owned()
                },
            ]
        );
        assert_eq!(
            scan.stubs,
            vec![stub("a.rs", 10), stub("a.rs", 14)],
            "an annotation away from the call or without a reason allows nothing"
        );
    }

    #[test]
    fn shipped_packages_follow_normal_dependencies_within_the_workspace() {
        let graph: BTreeMap<String, Vec<String>> = [
            ("server", vec!["app", "serde"]),
            ("app", vec!["ports"]),
            ("ports", vec![]),
            ("app-fake", vec!["app"]),
            ("it", vec!["server", "app-fake"]),
        ]
        .into_iter()
        .map(|(name, deps)| (name.to_owned(), deps.into_iter().map(str::to_owned).collect()))
        .collect();
        let shipped = shipped_packages(&graph, &["server"]);
        assert_eq!(
            shipped.into_iter().collect::<Vec<_>>(),
            vec!["app", "ports", "server"],
            "crates.io crates and the crates that depend on the server are not shipped"
        );
        assert!(shipped_packages(&graph, &["missing"]).is_empty());
    }

    #[test]
    fn the_files_of_test_modules_are_found_next_to_the_declaring_file() {
        let scan = |modules: &[&str]| FileScan {
            test_modules: modules.iter().map(|name| (*name).to_owned()).collect(),
            ..FileScan::default()
        };
        let path = |file: &str| PathBuf::from("crate/src").join(file);
        let scans: BTreeMap<PathBuf, FileScan> = [
            (path("lib.rs"), scan(&["tests"])),
            (path("tests.rs"), scan(&[])),
            (path("tests/more.rs"), scan(&[])),
            (path("outbox.rs"), scan(&["fixture"])),
            (path("outbox/fixture.rs"), scan(&[])),
            (path("outbox/dispatcher.rs"), scan(&[])),
            (path("store/mod.rs"), scan(&["memory"])),
            (path("store/memory/mod.rs"), scan(&[])),
            (path("store/real.rs"), scan(&[])),
        ]
        .into_iter()
        .collect();
        let roots = [path("lib.rs")].into_iter().collect();
        let found = test_module_files(&scans, &roots);
        assert_eq!(
            found,
            [
                path("outbox/fixture.rs"),
                path("store/memory/mod.rs"),
                path("tests.rs"),
                path("tests/more.rs"),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn every_rust_file_below_a_directory_is_collected_except_build_output() {
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
