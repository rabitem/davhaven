//! `arch-check`, fuzz targets: every cargo-fuzz target of the repository is run by the nightly workflow.
//!
//! The fuzz packages live next to the crates they exercise (`crates/<crate>/fuzz`, outside the workspace: they need a nightly
//! toolchain). A target that the nightly workflow does not name is never run, and nothing says so: the job is green. This check
//! reads the packages and the workflow and fails when they disagree, so that adding a target (or a package) without adding it to
//! the matrix of `nightly.yml`, to the `checks` job of `ci.yml` (it compiles and audits every package) and to `dependabot.yml`
//! (its own lock file) is a failure of `cargo xtask arch-check`, and so is a matrix entry that names nothing.

use std::collections::BTreeSet;
use std::path::Path;

use crate::XtaskError;
use crate::arch::read;

/// A `[[bin]]` of a cargo-fuzz package.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FuzzBin {
    /// Its name, which `cargo fuzz run` takes and the matrix of the nightly workflow names.
    name: String,
    /// The file it is built from, relative to the package (`fuzz_targets/parse_validate.rs`).
    path: String,
    /// Whether that file exists.
    exists: bool,
}

/// A cargo-fuzz package.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FuzzPackage {
    /// The directory name of the crate it exercises (`ical` for `crates/ical/fuzz`).
    krate: String,
    /// Its `[[bin]]` entries.
    bins: Vec<FuzzBin>,
    /// The files of `fuzz_targets/*.rs`, relative to the package.
    files: Vec<String>,
}

/// One entry of the fuzz matrix of the nightly workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MatrixEntry {
    package: String,
    target: String,
    corpus: Option<String>,
}

/// Everything the check reads.
struct Inputs<'a> {
    packages: &'a [FuzzPackage],
    nightly: &'a str,
    ci: &'a str,
    dependabot: &'a str,
}

/// The fuzz packages under `crates/`.
fn packages(root: &Path) -> Result<Vec<FuzzPackage>, XtaskError> {
    let crates = root.join("crates");
    let listing = std::fs::read_dir(&crates).map_err(|source| XtaskError::Read {
        path: crates.clone(),
        source,
    })?;
    let mut found = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|source| XtaskError::Read {
            path: crates.clone(),
            source,
        })?;
        let manifest_path = entry.path().join("fuzz").join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest: toml::Table = toml::from_str(&read(&manifest_path)?).map_err(|source| XtaskError::Toml {
            path: manifest_path.clone(),
            source: Box::new(source),
        })?;
        let package_directory = entry.path().join("fuzz");
        let bins = manifest
            .get("bin")
            .and_then(toml::Value::as_array)
            .map(|bins| {
                bins.iter()
                    .filter_map(|bin| {
                        let name = bin.get("name").and_then(toml::Value::as_str)?;
                        // The file of a `[[bin]]` is its `path`; without one cargo looks in `src/bin`.
                        let path = bin.get("path").and_then(toml::Value::as_str).map_or_else(
                            || format!("src/bin/{name}.rs"),
                            |path| path.trim_start_matches("./").to_owned(),
                        );
                        Some(FuzzBin {
                            name: name.to_owned(),
                            exists: package_directory.join(&path).is_file(),
                            path,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let directory = package_directory.join("fuzz_targets");
        let mut files = Vec::new();
        if directory.is_dir() {
            let sources = std::fs::read_dir(&directory).map_err(|source| XtaskError::Read {
                path: directory.clone(),
                source,
            })?;
            for source in sources {
                let source = source.map_err(|source| XtaskError::Read {
                    path: directory.clone(),
                    source,
                })?;
                let path = source.path();
                if path.extension().is_some_and(|extension| extension == "rs")
                    && let Some(name) = path.file_name().and_then(|name| name.to_str())
                {
                    files.push(format!("fuzz_targets/{name}"));
                }
            }
        }
        files.sort();
        found.push(FuzzPackage {
            krate: entry.file_name().to_string_lossy().into_owned(),
            bins,
            files,
        });
    }
    found.sort_by(|a, b| a.krate.cmp(&b.krate));
    Ok(found)
}

/// The entries of the matrix of the fuzz job of the nightly workflow: the lines of the form
/// `- { package: ical, target: parse_validate, corpus: testdata/corpus, libfuzzer: "..." }`.
fn matrix_entries(nightly: &str) -> Vec<MatrixEntry> {
    nightly
        .lines()
        .filter_map(|line| {
            let inner = line.trim().strip_prefix("- {")?.trim_end().strip_suffix('}')?;
            let mut package = None;
            let mut target = None;
            let mut corpus = None;
            for part in inner.split(',') {
                let Some((key, value)) = part.split_once(':') else {
                    continue;
                };
                let value = value.trim().trim_matches('"').to_owned();
                match key.trim() {
                    "package" => package = Some(value),
                    "target" => target = Some(value),
                    "corpus" => corpus = Some(value),
                    _ => {}
                }
            }
            Some(MatrixEntry {
                package: package?,
                target: target?,
                corpus,
            })
        })
        .collect()
}

/// What is wrong with the way the fuzz packages and the workflows fit together.
fn violations_of(inputs: &Inputs<'_>, corpus_exists: &dyn Fn(&str) -> bool) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let entries = matrix_entries(inputs.nightly);
    for package in inputs.packages {
        let name = &package.krate;
        for bin in &package.bins {
            let target = &bin.name;
            if !entries
                .iter()
                .any(|entry| &entry.package == name && &entry.target == target)
            {
                out.insert(format!(
                    "the fuzz target `{name}/{target}` is not in the matrix of the fuzz job of `.github/workflows/nightly.yml`: \
                     it is never run"
                ));
            }
            if !bin.exists {
                out.insert(format!(
                    "`crates/{name}/fuzz/Cargo.toml` declares the target `{target}` with the file `{}`, which does not exist",
                    bin.path
                ));
            }
        }
        for file in &package.files {
            if !package.bins.iter().any(|bin| &bin.path == file) {
                out.insert(format!(
                    "`crates/{name}/fuzz/{file}` is the file of no `[[bin]]` of `crates/{name}/fuzz/Cargo.toml`: \
                     it is never built or run"
                ));
            }
        }
        let manifest = format!("--manifest-path crates/{name}/fuzz/Cargo.toml");
        for (what, command) in [("compile", "cargo check"), ("cargo-deny", "cargo deny")] {
            if !inputs.ci.contains(&format!("{command} {manifest}")) {
                out.insert(format!(
                    "the `checks` job of `.github/workflows/ci.yml` does not {what} the fuzz package of `{name}` \
                     (`{command} {manifest}`)"
                ));
            }
        }
        if !inputs.dependabot.contains(&format!("directory: /crates/{name}/fuzz")) {
            out.insert(format!(
                "`.github/dependabot.yml` does not update the lock file of the fuzz package of `{name}` \
                 (`directory: /crates/{name}/fuzz`)"
            ));
        }
    }
    for entry in &entries {
        let known = inputs
            .packages
            .iter()
            .any(|package| package.krate == entry.package && package.bins.iter().any(|bin| bin.name == entry.target));
        if !known {
            out.insert(format!(
                "the matrix of `.github/workflows/nightly.yml` names the fuzz target `{}/{}`, which does not exist",
                entry.package, entry.target
            ));
        }
        match entry.corpus.as_deref() {
            Some(corpus) if !corpus_exists(corpus) => {
                out.insert(format!(
                    "the fuzz target `{}/{}` starts from the corpus `{corpus}`, which is no directory of the repository",
                    entry.package, entry.target
                ));
            }
            Some(_) => {}
            None => {
                out.insert(format!(
                    "the matrix entry of the fuzz target `{}/{}` names no `corpus`",
                    entry.package, entry.target
                ));
            }
        }
    }
    out
}

/// The violations of the repository at `root`.
pub(crate) fn violations(root: &Path) -> Result<BTreeSet<String>, XtaskError> {
    let packages = packages(root)?;
    let nightly = read(&root.join(".github/workflows/nightly.yml"))?;
    let ci = read(&root.join(".github/workflows/ci.yml"))?;
    let dependabot = read(&root.join(".github/dependabot.yml"))?;
    let inputs = Inputs {
        packages: &packages,
        nightly: &nightly,
        ci: &ci,
        dependabot: &dependabot,
    };
    Ok(violations_of(&inputs, &|corpus| root.join(corpus).is_dir()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NIGHTLY: &str = "\
    strategy:
      matrix:
        include:
          # The parser.
          - { package: ical, target: parse_validate, corpus: testdata/corpus, libfuzzer: \"-max_len=1048576\" }
          - { package: ical, target: zones, corpus: testdata/corpus, libfuzzer: \"-max_len=1048576\" }
          - { package: dav, target: xml_reader, corpus: testdata/dav, libfuzzer: \"-max_len=262144 -rss_limit_mb=512\" }
    steps:
      - { name: not a matrix entry }
";

    const CI: &str = "run: cargo check --manifest-path crates/ical/fuzz/Cargo.toml --locked\n\
                      run: cargo deny --manifest-path crates/ical/fuzz/Cargo.toml --locked check\n\
                      run: cargo check --manifest-path crates/dav/fuzz/Cargo.toml --locked\n\
                      run: cargo deny --manifest-path crates/dav/fuzz/Cargo.toml --locked check\n";

    const DEPENDABOT: &str = "directory: /crates/ical/fuzz\ndirectory: /crates/dav/fuzz\n";

    fn package(krate: &str, targets: &[&str]) -> FuzzPackage {
        FuzzPackage {
            krate: krate.to_owned(),
            bins: targets
                .iter()
                .map(|target| FuzzBin {
                    name: (*target).to_owned(),
                    path: format!("fuzz_targets/{target}.rs"),
                    exists: true,
                })
                .collect(),
            files: targets
                .iter()
                .map(|target| format!("fuzz_targets/{target}.rs"))
                .collect(),
        }
    }

    fn found(packages: &[FuzzPackage], nightly: &str, ci: &str, dependabot: &str) -> Vec<String> {
        violations_of(
            &Inputs {
                packages,
                nightly,
                ci,
                dependabot,
            },
            &|corpus| corpus == "testdata/corpus" || corpus == "testdata/dav",
        )
        .into_iter()
        .collect()
    }

    #[test]
    fn the_matrix_is_read_line_by_line() {
        let entries = matrix_entries(NIGHTLY);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].package, "ical");
        assert_eq!(entries[0].target, "parse_validate");
        assert_eq!(entries[0].corpus.as_deref(), Some("testdata/corpus"));
        assert_eq!(entries[2].target, "xml_reader");
    }

    #[test]
    fn packages_that_match_the_workflows_are_fine() {
        let packages = [
            package("ical", &["parse_validate", "zones"]),
            package("dav", &["xml_reader"]),
        ];
        assert_eq!(found(&packages, NIGHTLY, CI, DEPENDABOT), Vec::<String>::new());
    }

    #[test]
    fn a_target_that_the_nightly_workflow_does_not_run_is_reported() {
        let packages = [
            package("ical", &["parse_validate", "zones", "itip"]),
            package("dav", &["xml_reader"]),
        ];
        let problems = found(&packages, NIGHTLY, CI, DEPENDABOT);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("`ical/itip` is not in the matrix"), "{problems:?}");
    }

    #[test]
    fn a_matrix_entry_without_a_target_is_reported() {
        let packages = [package("ical", &["parse_validate"]), package("dav", &["xml_reader"])];
        let problems = found(&packages, NIGHTLY, CI, DEPENDABOT);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("`ical/zones`, which does not exist"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_missing_corpus_is_reported() {
        let packages = [
            package("ical", &["parse_validate", "zones"]),
            package("dav", &["xml_reader"]),
        ];
        let nightly = NIGHTLY.replace("corpus: testdata/dav", "corpus: testdata/corpus/dav");
        let problems = found(&packages, &nightly, CI, DEPENDABOT);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("`testdata/corpus/dav`"), "{problems:?}");
    }

    #[test]
    fn a_new_package_must_be_compiled_audited_and_kept_current() {
        let packages = [
            package("ical", &["parse_validate", "zones"]),
            package("dav", &["xml_reader"]),
            package("wire", &["roundtrip"]),
        ];
        let nightly = format!("{NIGHTLY}          - {{ package: wire, target: roundtrip, corpus: testdata/corpus }}\n");
        let problems = found(&packages, &nightly, CI, DEPENDABOT);
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems.iter().any(|problem| problem.contains("does not compile")));
        assert!(problems.iter().any(|problem| problem.contains("does not cargo-deny")));
        assert!(problems.iter().any(|problem| problem.contains("dependabot.yml")));
    }

    #[test]
    fn a_target_file_and_a_declaration_must_come_in_pairs() {
        let mut lonely = package("ical", &["parse_validate", "zones"]);
        lonely.files.push("fuzz_targets/itip.rs".to_owned());
        lonely.files.retain(|file| file != "fuzz_targets/zones.rs");
        if let Some(zones) = lonely.bins.iter_mut().find(|bin| bin.name == "zones") {
            zones.exists = false;
        }
        let packages = [lonely, package("dav", &["xml_reader"])];
        let problems = found(&packages, NIGHTLY, CI, DEPENDABOT);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems.iter().any(|problem| {
            problem.contains("the target `zones` with the file `fuzz_targets/zones.rs`, which does not exist")
        }));
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("fuzz/fuzz_targets/itip.rs` is the file of no `[[bin]]`"))
        );
    }

    #[test]
    fn a_bin_is_its_path_and_not_its_name() {
        // A target whose `path` is not `fuzz_targets/<name>.rs` is fine when that file is there and no other file is left over, and
        // a file of the directory that no bin points at is reported, whatever its name.
        let mut renamed = package("dav", &["xml_reader"]);
        renamed.bins[0].path = "fuzz_targets/reader.rs".to_owned();
        renamed.files = vec!["fuzz_targets/reader.rs".to_owned()];
        let packages = [package("ical", &["parse_validate", "zones"]), renamed.clone()];
        assert_eq!(found(&packages, NIGHTLY, CI, DEPENDABOT), Vec::<String>::new());

        renamed.files.push("fuzz_targets/xml_reader.rs".to_owned());
        let packages = [package("ical", &["parse_validate", "zones"]), renamed];
        let problems = found(&packages, NIGHTLY, CI, DEPENDABOT);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("fuzz/fuzz_targets/xml_reader.rs` is the file of no `[[bin]]`"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_matrix_entry_without_a_corpus_is_reported() {
        let packages = [
            package("ical", &["parse_validate", "zones"]),
            package("dav", &["xml_reader"]),
        ];
        let nightly = NIGHTLY.replace("target: zones, corpus: testdata/corpus,", "target: zones,");
        let problems = found(&packages, &nightly, CI, DEPENDABOT);
        assert_eq!(
            problems,
            vec!["the matrix entry of the fuzz target `ical/zones` names no `corpus`".to_owned()]
        );
    }

    #[test]
    fn a_line_without_a_package_or_a_target_is_no_matrix_entry() {
        let nightly = "          - { package: ical, corpus: testdata/corpus }\n          - { target: zones }\n";
        assert_eq!(matrix_entries(nightly), Vec::<MatrixEntry>::new());
    }

    #[test]
    fn packages_are_read_from_the_fuzz_directories_of_the_crates() {
        let root = tempfile::tempdir().unwrap();
        let write = |path: &str, text: &str| {
            let path = root.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write(
            "crates/ical/fuzz/Cargo.toml",
            "[package]\nname = \"ical-fuzz\"\n\n\
             [[bin]]\nname = \"zones\"\npath = \"./fuzz_targets/zones.rs\"\n\n\
             [[bin]]\nname = \"itip\"\npath = \"fuzz_targets/itip.rs\"\n\n\
             [[bin]]\nname = \"legacy\"\n",
        );
        write("crates/ical/fuzz/fuzz_targets/zones.rs", "");
        write("crates/ical/fuzz/fuzz_targets/extra.rs", "");
        write("crates/ical/fuzz/fuzz_targets/README.md", "");
        write("crates/ical/fuzz/src/bin/legacy.rs", "");
        write("crates/dav/fuzz/Cargo.toml", "[package]\nname = \"dav-fuzz\"\n");
        // A crate without a fuzz package is no package.
        write("crates/domain/Cargo.toml", "[package]\nname = \"davhaven-domain\"\n");

        let found = packages(root.path()).unwrap();
        let bin = |name: &str, path: &str, exists: bool| FuzzBin {
            name: name.to_owned(),
            path: path.to_owned(),
            exists,
        };
        assert_eq!(
            found,
            vec![
                FuzzPackage {
                    krate: "dav".to_owned(),
                    bins: Vec::new(),
                    files: Vec::new(),
                },
                FuzzPackage {
                    krate: "ical".to_owned(),
                    bins: vec![
                        bin("zones", "fuzz_targets/zones.rs", true),
                        bin("itip", "fuzz_targets/itip.rs", false),
                        bin("legacy", "src/bin/legacy.rs", true),
                    ],
                    files: vec!["fuzz_targets/extra.rs".to_owned(), "fuzz_targets/zones.rs".to_owned()],
                },
            ]
        );
    }

    #[test]
    fn a_fuzz_manifest_that_is_no_toml_is_an_error_that_names_it() {
        let root = tempfile::tempdir().unwrap();
        let manifest = root.path().join("crates/ical/fuzz/Cargo.toml");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::write(&manifest, "[[bin]\nname = ").unwrap();
        match packages(root.path()) {
            Err(XtaskError::Toml { path, .. }) => assert_eq!(path, manifest),
            other => panic!("expected a TOML error, got {other:?}"),
        }
    }

    #[test]
    fn the_repository_passes_its_own_check() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        // The check passes vacuously when it finds no package: the packages of the parser and of the XML reader are there.
        let crates: Vec<String> = packages(&root)
            .unwrap()
            .into_iter()
            .map(|package| package.krate)
            .collect();
        for expected in ["dav", "ical"] {
            assert!(crates.iter().any(|krate| krate == expected), "{crates:?}");
        }
        let problems = violations(&root).unwrap();
        assert!(problems.is_empty(), "{problems:?}");
    }
}
