//! The client flows (PLAN 3.4) on the real application.
//!
//! Every scenario of `tests/scenarios` (YAML: templated requests, captures, structural assertions) is run against an
//! application of its own, in process, through the routers of the server. The scenarios are the conversations of the
//! clients of PLAN G1 (Apple Calendar on macOS and iOS, DAVx5, Thunderbird, Evolution, CalDAV Synchronizer) and of the
//! public test suites that Davhaven is held against (python `caldav`, the CalendarServer test suite), written as
//! the requests they send and what they need from the answers. Scenarios are `synthetic` until a capture from a real
//! client replaces them (`davhaven-conformance convert`); the client-by-feature grid reports the cells that only have
//! synthetic scenarios.
//!
//! A scenario with a `known_issue` is expected to fail today: the server deviates from what the client needs and the
//! deviation is tracked. The test passes when it fails and fails when it passes, so a fixed deviation does not stay.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;

use davhaven_testkit::busy;
use davhaven_testkit::flow::{self, FlowVerdict, ScenarioReport};
use davhaven_testkit::permissions::{RunOptions, Sampling};
use davhaven_testkit::{Scenario, StoreKind, TestApp, run_scenario};
use futures::StreamExt as _;

fn scenario_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/scenarios")
}

fn load() -> Vec<(PathBuf, Scenario)> {
    flow::load_scenarios(&scenario_dir()).unwrap()
}

/// Runs a scenario on an application of its own, and returns the report and how often the scenario was run again. A PostgreSQL
/// server that is busy with other test processes makes the store answer 503 now and then: a scenario that failed while its
/// application had answered that it was too busy is run again on a new application (the world of the first attempt is thrown away
/// with whatever the scenario did to it, so nothing is done twice), at most [`busy::Policy::STANDARD`] times. What the last
/// attempt reports is the result.
async fn run_one(store: StoreKind, scenario: &Scenario) -> (ScenarioReport, u32) {
    busy::repeat_while_busy(busy::Policy::STANDARD, || async {
        let app = TestApp::build_with_retries(|| TestApp::builder().store(store))
            .await
            .unwrap();
        let report = run_scenario(&app.scenario_env(), scenario).await;
        let busy_effect = (!report.is_success() && app.busy_answers() > 0).then_some(busy::Effect::Discarded);
        busy::Attempt {
            value: report,
            busy: busy_effect,
        }
    })
    .await
}

/// The scenarios a run on `store` performs. Every scenario runs in a world of its own, which costs seconds on PostgreSQL, so
/// there the run is a sample ([`flow::representative`]: every client and every feature at least once), as the matrices are,
/// and `CONFORMANCE_FULL=1` (the nightly run) runs all of them. The memory store always runs all.
fn scenarios_of(store: StoreKind) -> Vec<(PathBuf, Scenario)> {
    let mut scenarios = load();
    assert!(!scenarios.is_empty(), "no scenarios were found");
    if RunOptions::for_store(store).sampling == Sampling::Everything {
        return scenarios;
    }
    let chosen: BTreeSet<String> = flow::representative(scenarios.iter().map(|(_, scenario)| scenario))
        .iter()
        .map(|scenario| scenario.name.clone())
        .collect();
    let all = scenarios.len();
    scenarios.retain(|(_, scenario)| chosen.contains(&scenario.name));
    drop(writeln!(
        std::io::stderr(),
        "{} of {all} scenarios on {store} (CONFORMANCE_FULL=1 runs all of them):\n  {}",
        scenarios.len(),
        scenarios
            .iter()
            .map(|(path, _)| path.strip_prefix(scenario_dir()).unwrap_or(path).display().to_string())
            .collect::<Vec<_>>()
            .join("\n  ")
    ));
    scenarios
}

async fn run_all(store: StoreKind) {
    let scenarios = scenarios_of(store);
    let results: Vec<(PathBuf, Scenario, ScenarioReport, u32)> = futures::stream::iter(scenarios)
        .map(|(path, scenario)| async move {
            let (report, reruns) = run_one(store, &scenario).await;
            (path, scenario, report, reruns)
        })
        .buffer_unordered(if store == StoreKind::Postgres { 2 } else { 4 })
        .collect()
        .await;
    // The scenarios that were run again because the host was too busy are named, and many of them are not a busy host: a server
    // that is unavailable now and then is a finding.
    let mut rerun: Vec<String> = results
        .iter()
        .filter(|(_, _, _, reruns)| *reruns > 0)
        .map(|(path, _, _, reruns)| {
            format!(
                "{} (run again {reruns} times)",
                path.strip_prefix(scenario_dir()).unwrap_or(path).display()
            )
        })
        .collect();
    rerun.sort();
    if !rerun.is_empty() {
        drop(writeln!(
            std::io::stderr(),
            "{} scenario(s) were run again on {store} because the host was too busy:\n  {}",
            rerun.len(),
            rerun.join("\n  ")
        ));
    }
    assert!(
        !busy::excessive(rerun.len(), results.len()),
        "{} of {} scenarios were run again on {store}: the server is unavailable too often, which a busy host does not explain:\n  {}",
        rerun.len(),
        results.len(),
        rerun.join("\n  ")
    );
    let mut problems = Vec::new();
    let mut known = Vec::new();
    for (path, scenario, report, _) in &results {
        let name = path.strip_prefix(scenario_dir()).unwrap_or(path).display();
        match flow::verdict(scenario, report) {
            FlowVerdict::Passed => {}
            FlowVerdict::Failed => problems.push(format!("{name}\n{report}")),
            FlowVerdict::KnownIssue(reason) => known.push(format!("{name}: {reason}")),
            FlowVerdict::KnownIssueFixed(reason) => problems.push(format!(
                "{name}: the known issue is fixed, remove `known_issue` ({reason})"
            )),
        }
    }
    known.sort();
    if !known.is_empty() {
        drop(writeln!(
            std::io::stderr(),
            "{} scenario(s) with a known issue on {store}:\n  {}",
            known.len(),
            known.join("\n  ")
        ));
    }
    assert!(
        problems.is_empty(),
        "{} scenario(s) differ on {store}:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_client_flow_passes_on_the_memory_store() {
    run_all(StoreKind::Memory).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_client_flow_passes_on_postgres() {
    if davhaven_testkit::postgres::require_database() {
        run_all(StoreKind::Postgres).await;
    }
}

#[test]
fn the_sample_for_pull_requests_has_every_client_and_every_feature_and_is_smaller_than_the_whole() {
    let all = load();
    let sample = flow::representative(all.iter().map(|(_, scenario)| scenario));
    let clients: BTreeSet<&str> = sample.iter().map(|scenario| scenario.client.as_str()).collect();
    let features: BTreeSet<&str> = sample.iter().map(|scenario| scenario.feature.as_str()).collect();
    for client in CLIENTS {
        assert!(
            clients.contains(client),
            "the sample has no scenario of {client}: {clients:?}"
        );
    }
    for feature in FEATURES {
        assert!(
            features.contains(feature),
            "the sample has no scenario of the feature {feature}: {features:?}"
        );
    }
    // Whatever else the scenarios have (features that are not columns of the grid) is in the sample too.
    for (_, scenario) in &all {
        assert!(clients.contains(scenario.client.as_str()), "{}", scenario.client);
        assert!(features.contains(scenario.feature.as_str()), "{}", scenario.feature);
    }
    assert!(
        sample.len() * 4 < all.len(),
        "{} of {} scenarios is not a sample",
        sample.len(),
        all.len()
    );
}

#[test]
fn scenario_names_are_unique_and_every_cell_of_the_grid_has_a_scenario() {
    let scenarios = load();
    let mut names: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, scenario) in &scenarios {
        *names.entry(scenario.name.as_str()).or_default() += 1;
    }
    let repeated: Vec<&&str> = names
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(name, _)| name)
        .collect();
    assert!(repeated.is_empty(), "scenario names must be unique: {repeated:?}");

    let grid = flow::grid(scenarios.iter().map(|(_, scenario)| scenario));
    let mut missing = Vec::new();
    for client in CLIENTS {
        for feature in FEATURES {
            if NOT_APPLICABLE.contains(&(client, feature)) {
                continue;
            }
            if !grid.contains_key(&((*client).to_owned(), (*feature).to_owned())) {
                missing.push(format!("{client} x {feature}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "cells of the client-by-feature grid without a scenario: {missing:?}"
    );

    let synthetic_only: Vec<String> = grid
        .iter()
        .filter(|(_, cell)| cell.captured == 0)
        .map(|((client, feature), cell)| format!("{client} x {feature} ({} synthetic)", cell.synthetic))
        .collect();
    drop(writeln!(
        std::io::stderr(),
        "{} of {} cells of the client-by-feature grid have synthetic scenarios only:\n  {}",
        synthetic_only.len(),
        grid.len(),
        synthetic_only.join("\n  ")
    ));
}

/// The clients of the grid (PLAN G1, 3.4).
const CLIENTS: &[&str] = &[
    "apple-calendar",
    "ios-calendar",
    "davx5",
    "thunderbird",
    "evolution",
    "caldav-synchronizer",
    "python-caldav",
    "ccs-caldavtester",
];

/// The features of the grid (PLAN 3.4).
const FEATURES: &[&str] = &[
    "account-setup",
    "crud",
    "recurring-override",
    "invite-internal",
    "invite-external",
    "accept",
    "share",
    "sync-after-token-expiry",
    "read-only-edit",
];

/// Cells that a client has no flow for because it does not offer the feature. DAVx5, Thunderbird, Evolution, CalDAV
/// Synchronizer and python `caldav` show the calendars that others share (their read-only edit attempts are in the
/// grid) but have no part in CalendarServer sharing: no request that offers, answers or withdraws a share.
const NOT_APPLICABLE: &[(&str, &str)] = &[
    ("davx5", "share"),
    ("thunderbird", "share"),
    ("evolution", "share"),
    ("caldav-synchronizer", "share"),
    ("python-caldav", "share"),
];
