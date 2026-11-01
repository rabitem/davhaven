//! The monitoring files that ship with the server (`deploy/`) against the code and the runbook.
//!
//! An alert on a metric that does not exist never fires, and a dashboard panel on one stays empty: both fail
//! silently. These tests read the shipped Prometheus rules and the Grafana dashboard and check that every metric
//! they mention is registered in the production code of the workspace (`crates/*/src`, test modules and test directories
//! excluded, so a name that only a test mentions does not vouch for an alert), that every alert is complete (an
//! expression, a severity, a summary and a runbook link) and that the runbook link points at a heading that exists.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    let full = workspace().join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|error| panic!("cannot read {}: {error}", full.display()))
}

/// Every `.rs` file below `directory`, except those in directories called `tests`, `target` or `fuzz` and files called
/// `tests.rs`.
fn rust_files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        if path.is_dir() {
            if !matches!(name, "target" | "fuzz" | "tests") {
                rust_files(&path, found);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") && name != "tests.rs" {
            found.push(path);
        }
    }
}

/// The production part of a source file: everything before its first `#[cfg(test)]` item. Test modules sit at the end of
/// the files of this workspace.
fn production_part(text: &str) -> &str {
    text.split("\n#[cfg(test)]").next().unwrap_or_default()
}

/// The names that look like metric names (`davhaven_` and then lower case letters, digits and underscores).
fn metric_names(text: &str) -> BTreeSet<String> {
    const PREFIX: &[u8] = b"davhaven_";
    let bytes = text.as_bytes();
    let is_name_byte = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_';
    let mut names = BTreeSet::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index..].starts_with(PREFIX) {
            index += 1;
            continue;
        }
        let preceded_by_identifier = index > 0
            && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_' || bytes[index - 1] == b'-');
        let mut end = index;
        while end < bytes.len() && is_name_byte(bytes[end]) {
            end += 1;
        }
        if !preceded_by_identifier {
            let name = String::from_utf8_lossy(&bytes[index..end]).into_owned();
            names.insert(name.trim_end_matches('_').to_owned());
        }
        index = end;
    }
    names
}

/// The metric names in the string literals of `text`: only literals count (the segments between quotes), a name in a
/// comment registers nothing.
fn literal_names(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in text.lines() {
        for literal in line.split('"').skip(1).step_by(2) {
            names.extend(metric_names(literal));
        }
    }
    names
}

/// The metric names in the string literals of the production code of the crates of the workspace (`crates/*/src`).
fn registered() -> BTreeSet<String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(workspace().join("crates")).unwrap() {
        let source = entry.unwrap().path().join("src");
        if source.is_dir() {
            rust_files(&source, &mut files);
        }
    }
    assert!(files.len() > 100, "the sources of the workspace were not found");
    let mut names = BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        names.extend(literal_names(production_part(&text)));
    }
    names
}

/// A series name as the code registers it: histogram series carry `_bucket`, `_sum` and `_count` in the exposition.
fn registered_name(name: &str, registered: &BTreeSet<String>) -> bool {
    registered.contains(name)
        || ["_bucket", "_sum", "_count"]
            .iter()
            .any(|suffix| name.strip_suffix(suffix).is_some_and(|base| registered.contains(base)))
}

#[derive(Debug, Deserialize)]
struct Rules {
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize)]
struct Group {
    name: String,
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct Rule {
    alert: String,
    expr: String,
    #[serde(rename = "for")]
    wait: Option<String>,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
}

/// The anchor GitHub gives a heading: lower case, punctuation removed, spaces turned into hyphens.
fn anchor(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter(|character| character.is_alphanumeric() || *character == ' ' || *character == '-')
        .map(|character| if character == ' ' { '-' } else { character })
        .collect()
}

fn headings(markdown: &str) -> BTreeSet<String> {
    markdown
        .lines()
        .filter(|line| line.starts_with('#'))
        .map(|line| anchor(line.trim_start_matches('#')))
        .collect()
}

#[test]
fn the_names_in_the_files_are_found_the_way_the_test_reads_them() {
    let names = metric_names("rate(davhaven_http_requests_total{a=\"b\"}[5m]) / davhaven_outbox_pending_");
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        vec!["davhaven_http_requests_total", "davhaven_outbox_pending"]
    );
    assert!(metric_names("docs/davhaven-rules.yml and adavhaven_x").is_empty());
    let known = BTreeSet::from(["davhaven_x_seconds".to_owned()]);
    assert!(registered_name("davhaven_x_seconds_bucket", &known));
    assert!(!registered_name("davhaven_y_bucket", &known));
    assert_eq!(anchor("DavhavenDown"), "davhavendown");
    assert_eq!(anchor(" Image retention "), "image-retention");
}

#[test]
fn a_name_that_only_a_test_module_mentions_registers_nothing() {
    let source = r#"pub const A: &str = "davhaven_a_total";
// davhaven_in_a_comment_total
#[cfg(test)]
mod tests {
    const B: &str = "davhaven_b_total";
}
"#;
    let names = literal_names(production_part(source));
    assert_eq!(names.into_iter().collect::<Vec<_>>(), vec!["davhaven_a_total"]);
}

#[test]
fn the_alert_rules_are_complete_and_use_metrics_that_exist() {
    let text = read("deploy/prometheus/davhaven-rules.yml");
    let rules: Rules = serde_saphyr::from_str(&text).unwrap();
    let known = registered();
    let runbook = headings(&read("docs/operations/runbook.md"));
    let mut seen = BTreeSet::new();
    assert!(!rules.groups.is_empty());
    for group in &rules.groups {
        assert!(group.name.starts_with("davhaven."), "{}", group.name);
        for rule in &group.rules {
            assert!(seen.insert(rule.alert.clone()), "{} is defined twice", rule.alert);
            assert!(rule.alert.starts_with("Davhaven"), "{}", rule.alert);
            assert!(!rule.expr.trim().is_empty(), "{}", rule.alert);
            assert!(
                matches!(
                    rule.labels.get("severity").map(String::as_str),
                    Some("warning" | "critical")
                ),
                "{}: severity",
                rule.alert
            );
            for annotation in ["summary", "description", "runbook"] {
                assert!(
                    rule.annotations
                        .get(annotation)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "{}: {annotation}",
                    rule.alert
                );
            }
            if let Some(wait) = &rule.wait {
                assert!(
                    wait.ends_with('m') || wait.ends_with('h'),
                    "{}: for: {wait}",
                    rule.alert
                );
            }
            let link = &rule.annotations["runbook"];
            let target = link.strip_prefix("docs/operations/runbook.md#").unwrap_or_else(|| {
                panic!(
                    "{}: the runbook link {link} does not point into the runbook",
                    rule.alert
                )
            });
            assert!(
                runbook.contains(target),
                "{}: the runbook has no heading with the anchor #{target}",
                rule.alert
            );
            for name in metric_names(&rule.expr) {
                assert!(
                    registered_name(&name, &known),
                    "{}: the metric {name} is registered nowhere in the sources",
                    rule.alert
                );
            }
        }
    }
    // The runbook documents every alert it is linked from and nothing that does not exist.
    for heading in runbook.iter().filter(|heading| heading.starts_with("davhaven")) {
        assert!(
            seen.iter().any(|alert| alert.to_lowercase() == *heading),
            "the runbook has a section for {heading}, which no alert uses"
        );
    }
}

#[test]
fn the_dashboard_is_importable_and_shows_metrics_that_exist() {
    let dashboard: Value = serde_json::from_str(&read("deploy/grafana/davhaven-dashboard.json")).unwrap();
    assert_eq!(dashboard["uid"], "davhaven-overview");
    assert!(dashboard["schemaVersion"].as_u64().unwrap() >= 36);
    let known = registered();
    let panels = dashboard["panels"].as_array().unwrap();
    let mut ids = BTreeSet::new();
    let mut graphs = 0;
    for panel in panels {
        assert!(ids.insert(panel["id"].as_u64().unwrap()), "panel ids are unique");
        assert!(panel["gridPos"]["w"].as_u64().unwrap() <= 24);
        if panel["type"] == "row" {
            continue;
        }
        graphs += 1;
        let title = panel["title"].as_str().unwrap();
        let targets = panel["targets"].as_array().unwrap();
        assert!(!targets.is_empty(), "{title}");
        for target in targets {
            let expression = target["expr"].as_str().unwrap();
            let names = metric_names(expression);
            assert!(!names.is_empty(), "{title}: {expression} names no metric");
            for name in names {
                assert!(
                    registered_name(&name, &known),
                    "{title}: {name} is registered nowhere in the sources"
                );
            }
        }
    }
    assert!(
        graphs >= 15,
        "the dashboard covers requests, outbox, mail, adapters, workers and retention"
    );
    let variables: Vec<&str> = dashboard["templating"]["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|variable| variable["name"].as_str().unwrap())
        .collect();
    assert_eq!(variables, vec!["datasource", "job", "instance"]);
}

#[test]
fn the_metrics_of_the_runbook_exist() {
    let known = registered();
    let runbook = read("docs/operations/runbook.md");
    for name in metric_names(&runbook) {
        assert!(
            registered_name(&name, &known),
            "the runbook mentions the metric {name}, which is registered nowhere in the sources"
        );
    }
}
