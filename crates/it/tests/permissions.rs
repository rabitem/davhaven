//! The permission matrix (PLAN 3.2) against the real application over HTTP, in process.
//!
//! Every actor x calendar x surface x operation of the hand-reviewed expectations file
//! (`crates/testkit/matrix/expectations.toml`) is performed on the real application and its answer, the state it leaves and
//! the body of its answer are compared with the oracle. The application is the one `davhaven serve` builds (`TestApp`): the
//! real services over the memory store or PostgreSQL, the routers of the server, the local authenticator, with the matrix
//! profile of the rate limiter (none) and warm credentials.
//!
//! A case that was left out is not a case that passed. The run is checked for what it did not do: every skipped case has one
//! of the reasons this test accepts, no operation is "not applicable" for a reason nobody expected, every surface (MCP too:
//! it is part of the application and answers 404 where it is switched off) was sent to the server, and every token scope of the
//! file was sent in at least one case. A route or tool that no probe sends is reported by the coverage check.
//!
//! The matrix is also run against files that are wrong on purpose: a harness that cannot tell a wrong oracle from a
//! right one would pass whatever the server does. The tests of the detectors (state, leaks, hidden against missing) are in
//! `matrix_detectors.rs`.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::io::Write as _;

use davhaven_testkit::davhaven_fixtures::{ActorRole, CalendarRole};
use davhaven_testkit::matrix::{BUNDLED, Case, Expectation, Operation, Surface};
use davhaven_testkit::permissions::{
    AppEnv, IN_PROCESS_NOT_APPLICABLE, IN_PROCESS_SKIPS, MatrixReport, RunOptions, Verdict, run,
};
use davhaven_testkit::{Expectations, StoreKind, TestApp, coverage};

/// Prints the report of a run to the error stream when the environment asks for it (`CONFORMANCE_MATRIX_REPORT=1`).
fn show(label: &str, text: &str) {
    if std::env::var("CONFORMANCE_MATRIX_REPORT").is_ok_and(|value| value == "1") {
        drop(writeln!(std::io::stderr(), "--- {label} ---\n{text}"));
    }
}

fn describe(results: &[&davhaven_testkit::permissions::CaseResult]) -> String {
    results
        .iter()
        .take(20)
        .map(|result| format!("  {}: {}", result.case, result.note.as_deref().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Everything a run of the matrix in process must show besides "no case differs".
fn assert_the_run_is_complete(report: &MatrixReport, expectations: &Expectations, text: &str) {
    assert!(report.is_clean(), "{text}");
    // A request that the host was too busy to answer (503) is sent again, and the report names the cases that needed it. Many of
    // them are not a busy host: a server that is unavailable now and then is a finding.
    let repeated = report.repeated();
    if !repeated.is_empty() {
        drop(writeln!(
            std::io::stderr(),
            "{} cases needed a request sent again because the host was too busy:\n{}",
            repeated.len(),
            repeated
                .iter()
                .take(20)
                .map(|result| format!("  {} (sent again {} times)", result.case, result.repeats()))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    assert!(
        !report.too_many_repeats(),
        "{} of {} cases needed a request sent again: the server is unavailable too often, which a busy host does not explain\n{text}",
        repeated.len(),
        report.executed()
    );
    let skipped = report.unexpected_skips(IN_PROCESS_SKIPS);
    assert!(
        skipped.is_empty(),
        "{} cases were left out for a reason nobody expected:\n{}",
        skipped.len(),
        describe(&skipped)
    );
    let not_applicable = report.unexpected_not_applicable(IN_PROCESS_NOT_APPLICABLE);
    assert!(
        not_applicable.is_empty(),
        "{} cases have no request for a reason nobody expected:\n{}",
        not_applicable.len(),
        describe(&not_applicable)
    );
    // Every surface was sent to the server, and almost everything of it: what is left out is what the pinned reasons name.
    for surface in Surface::ALL {
        let total = report
            .results
            .iter()
            .filter(|result| result.case.surface == *surface)
            .count();
        let sent = report.executed_on(*surface);
        assert!(sent > 0, "no case of {surface} was sent:\n{text}");
        assert!(
            sent * 4 >= total * 3,
            "only {sent} of {total} cases of {surface} were sent:\n{text}"
        );
    }
    assert!(
        report.executed() > 1000,
        "the matrix ran only {} cases:\n{text}",
        report.executed()
    );
    // The scopes of the file are sent to the server, tenant tokens and principal tokens, on the API and on MCP.
    let unreached = report.scope_rows_unreached(expectations);
    assert!(unreached.is_empty(), "no case sent the scope of {unreached:?}");
    // The cases that carry a stale condition exist for every surface that has conditional writes.
    assert!(
        report
            .results
            .iter()
            .flat_map(|result| result.probes.iter())
            .any(|probe| probe.when_allowed == Expectation::PreconditionFailed),
        "no probe carries a stale condition"
    );
}

async fn matrix_on(store: StoreKind) {
    if store == StoreKind::Postgres && !davhaven_testkit::postgres::require_database() {
        return;
    }
    let expectations = Expectations::bundled().unwrap();
    let env = AppEnv::new(move || TestApp::builder().store(store)).await.unwrap();
    let report = run(&env, &expectations, &RunOptions::for_store(store)).await;
    let text = report.to_string();
    show(&format!("the permission matrix on {store}"), &text);
    assert_the_run_is_complete(&report, &expectations, &text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_permission_matrix_holds_on_the_memory_store() {
    matrix_on(StoreKind::Memory).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_permission_matrix_holds_on_postgres() {
    matrix_on(StoreKind::Postgres).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_route_and_tool_of_the_server_is_sent_by_some_probe() {
    // The tables of the coverage check say what the matrix is meant to send; the planners are run for every case to see what
    // their probes really send.
    let expectations = Expectations::bundled().unwrap();
    let env = AppEnv::new(TestApp::builder).await.unwrap();
    let sent = coverage::probes_sent(&env, &expectations).await;
    let problems = coverage::check_probes(&sent);
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
    assert!(sent.len() > 40, "only {} routes were sent", sent.len());
}

/// The cases of one sharee on the shared calendar over DAV: enough to see whether the harness notices a wrong oracle.
fn sharee_on_shared(case: &Case) -> bool {
    case.actor == ActorRole::ShareeRead && case.calendar == CalendarRole::Shared && case.surface == Surface::Dav
}

fn small() -> RunOptions {
    RunOptions {
        filter: Some(sharee_on_shared),
        ..RunOptions::default()
    }
}

/// The bundled file with the read-only sharee given write access to the shared calendar.
fn sharee_may_write() -> String {
    let right = "actor = \"sharee_read\"\ncalendar = \"shared\"\nlevel = \"read\"";
    let wrong = "actor = \"sharee_read\"\ncalendar = \"shared\"\nlevel = \"read_write\"";
    let file = BUNDLED.replace(right, wrong);
    assert_ne!(file, BUNDLED, "the row to change was found");
    file
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_oracle_is_caught_case_by_case() {
    // A file that gives the read-only sharee write access: the server refuses what the file allows.
    let env = AppEnv::new(TestApp::builder).await.unwrap();
    let report = run(&env, &Expectations::parse(&sharee_may_write()).unwrap(), &small()).await;
    assert!(!report.is_clean(), "a wrong oracle must fail the matrix:\n{report}");
    let failed: Vec<String> = report
        .with(&Verdict::Failed)
        .iter()
        .map(|result| result.case.to_string())
        .collect();
    for operation in ["create_object", "update_object", "delete_object"] {
        let wanted = format!("sharee_read {operation} on shared via dav");
        assert!(failed.contains(&wanted), "{wanted} should differ: {failed:?}");
    }
    // The cases the wrong row does not touch still pass.
    assert!(
        report
            .with(&Verdict::Passed)
            .iter()
            .any(|result| result.case.operation == Operation::ReadObject)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scope_that_the_file_gets_wrong_is_caught_for_principal_tokens_too() {
    // The file says that reading an event over MCP needs `mcp:write`: the server lets the token with `mcp:read` in and keeps the
    // one with `mcp:write` out, and the principal tokens of the owner are what shows it.
    let wrong = BUNDLED.replace(
        "[[scope]]\nsurface = \"mcp\"\noperation = [\"read_collection\", \"list_objects\", \"read_object\", \"free_busy_query\"]\nscope = \"mcp:read\"",
        "[[scope]]\nsurface = \"mcp\"\noperation = [\"read_collection\", \"list_objects\", \"read_object\", \"free_busy_query\"]\nscope = \"mcp:write\"",
    );
    assert_ne!(wrong, BUNDLED, "the row to change was found");
    let env = AppEnv::new(TestApp::builder).await.unwrap();
    let report = run(
        &env,
        &Expectations::parse(&wrong).unwrap(),
        &RunOptions {
            filter: Some(|case: &Case| {
                case.actor == ActorRole::Owner
                    && case.calendar == CalendarRole::Personal
                    && case.surface == Surface::Mcp
                    && case.operation == Operation::ReadObject
            }),
            ..RunOptions::default()
        },
    )
    .await;
    let failed: Vec<String> = report
        .with(&Verdict::Failed)
        .iter()
        .map(|result| result.case.to_string())
        .collect();
    for wanted in [
        "owner[mcp:read] read_object on personal via mcp",
        "owner[mcp:write] read_object on personal via mcp",
    ] {
        assert!(
            failed.iter().any(|case| case == wanted),
            "{wanted} should differ: {failed:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_known_deviation_is_checked_against_the_server_and_a_fixed_one_is_reported() {
    // The file says the sharee may create objects, documents that the server refuses (403), and that is what it does.
    let documented = format!(
        "{}\n[[known_issue]]\nactor = \"sharee_read\"\ncalendar = \"shared\"\nsurface = \"dav\"\n\
         operation = [\"create_object\", \"update_object\", \"delete_object\", \"move_object_from\", \
         \"move_object_to\", \"copy_object_to\", \"update_calendar\"]\n\
         observed = \"forbidden\"\nreason = \"the file is wrong on purpose\"\n",
        sharee_may_write()
    );
    let env = AppEnv::new(TestApp::builder).await.unwrap();
    let report = run(&env, &Expectations::parse(&documented).unwrap(), &small()).await;
    let mut deviations: Vec<String> = report
        .with(&Verdict::KnownDeviation)
        .iter()
        .map(|result| result.case.operation.to_string())
        .collect();
    deviations.sort();
    assert_eq!(
        deviations,
        vec![
            "copy_object_to",
            "create_object",
            "delete_object",
            "move_object_from",
            "move_object_to",
            "update_calendar",
            "update_object"
        ],
        "{report}"
    );
    assert!(report.is_clean(), "{report}");

    // The server does what the oracle says (the correct file), but the deviation is still documented: it is stale.
    let stale = format!(
        "{BUNDLED}\n[[known_issue]]\nactor = \"sharee_read\"\ncalendar = \"shared\"\nsurface = \"dav\"\n\
         operation = \"create_object\"\nobserved = \"allow\"\nreason = \"fixed in the meantime\"\n"
    );
    let report = run(&env, &Expectations::parse(&stale).unwrap(), &small()).await;
    let stale_cases: Vec<String> = report
        .with(&Verdict::StaleKnownIssue)
        .iter()
        .map(|result| result.case.to_string())
        .collect();
    assert_eq!(
        stale_cases,
        vec!["sharee_read create_object on shared via dav"],
        "{report}"
    );
    assert!(!report.is_clean());
    assert_eq!(
        Expectations::parse(&stale)
            .unwrap()
            .known_issues()
            .first()
            .map(|issue| issue.observed),
        Some(Expectation::Allow)
    );
}

/// No report is defined on a home, so `sync-collection` of one is refused whatever the caller may do with the home: the matrix
/// leaves it out (`davhaven_testkit::coverage`) and this test pins that. The tenant of the path is judged before the report is,
/// so a user of another tenant is answered 404, like for every request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_on_a_home_is_refused_to_everybody_alike() {
    const SYNC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<sync-collection xmlns="DAV:"><sync-token/><sync-level>1</sync-level><prop><getetag/></prop></sync-collection>"#;
    let app = TestApp::builder().build().await.unwrap();
    let mut answers = Vec::new();
    for role in [ActorRole::Owner, ActorRole::OtherUser] {
        let actor = app.actor(role).unwrap();
        let answer = app
            .dav(&actor)
            .report("/dav/calendars/acme/olivia/", "0", SYNC)
            .send()
            .await
            .unwrap();
        assert_eq!(answer.status.as_u16(), 403, "{role}: {}", answer.text());
        assert!(answer.text().contains("supported-report"), "{role}: {}", answer.text());
        answers.push(answer.text());
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "the same answer whoever asks: {answers:?}"
    );
    let stranger = app.actor(ActorRole::OtherTenantUser).unwrap();
    let answer = app
        .dav(&stranger)
        .report("/dav/calendars/acme/olivia/", "0", SYNC)
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status.as_u16(), 404, "{}", answer.text());
}
