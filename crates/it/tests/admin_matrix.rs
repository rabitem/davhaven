//! The administration operations of the management API in the permission matrix (PLAN 3.2: every API operation x scope),
//! on the real application over HTTP, in process.
//!
//! Every operation of the API that is not about one calendar (tenants, principals, credentials, webhooks, providers, the
//! audit log, the outbox, inbound iTIP, the search for calendars) is performed by every actor, by tenant tokens that carry
//! each scope a tenant token can carry, and, where the operation names an id, by the administrator of another tenant who
//! asks for the ids of the main tenant. The expected answers are the rows of the expectations file (`[[admin_actor]]`,
//! `[[token_scopes]]`, `[[admin]]`); the harness also checks that a refusal changes nothing (the tenant, its principals,
//! credentials, webhooks and audit log are observed around every refused request), that another tenant's resources answer
//! like resources that do not exist, and the details of a refusal (the challenge, the problem code).
//!
//! The inbound endpoint for mail gateways is switched on in this application, so that its allowed answer is the one of an
//! endpoint that takes a message and its refusals are those of the authorization and not of a switch that is off.
//!
//! A case that was left out is not a case that passed: no case may be skipped here (the operations that a service does not offer yet are
//! `[[pending]]` rows of the file, which are run and must answer 501).

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::io::Write as _;

use davhaven_testkit::matrix::BUNDLED;
use davhaven_testkit::permissions::admin::{self, AdminReport};
use davhaven_testkit::permissions::{AppEnv, RunOptions, Verdict};
use davhaven_testkit::{Expectations, StoreKind, TestApp, TestAppBuilder};

fn show(label: &str, report: &AdminReport) {
    if std::env::var("CONFORMANCE_MATRIX_REPORT").is_ok_and(|value| value == "1") {
        drop(writeln!(std::io::stderr(), "--- {label} ---\n{report}"));
    }
}

/// The application of the matrix: the defaults, with the inbound endpoint for mail gateways switched on.
fn application(store: StoreKind) -> TestAppBuilder {
    TestApp::builder()
        .store(store)
        .configure(|config| config.scheduling.inbound_itip.enabled = true)
}

async fn matrix_on(store: StoreKind) {
    if store == StoreKind::Postgres && !davhaven_testkit::postgres::require_database() {
        return;
    }
    let expectations = Expectations::bundled().unwrap();
    let env = AppEnv::new(move || application(store)).await.unwrap();
    let report = admin::run(&env, &expectations, &RunOptions::for_store(store)).await;
    show(&format!("the administration matrix on {store}"), &report);
    // A case that the run lost names itself: its world could not be made, and nothing said so.
    let all = admin::cases(&expectations);
    let missing = report.missing(&all);
    assert!(
        missing.is_empty(),
        "{} of {} cases are neither a result nor left out of the sample:\n{}\n{report}",
        missing.len(),
        all.len(),
        missing
            .iter()
            .map(|case| format!("  {case}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        report.results.len() + report.left_out.len(),
        all.len(),
        "one result for every case that the sample has"
    );
    // Every operation with every actor, with every scope, and with the ids of another tenant.
    let operations = admin::OPERATIONS.len();
    let actors = davhaven_testkit::davhaven_fixtures::ActorRole::ALL.len();
    let scopes = admin::tenant_scopes(&expectations).len();
    assert!(
        report.results.len() + report.left_out.len() >= operations * (actors + scopes),
        "{} cases for {operations} operations, {actors} actors and {scopes} scopes",
        report.results.len()
    );
    assert!(
        report.executed() > 900,
        "the matrix ran only {} cases:\n{report}",
        report.executed()
    );
    let skipped = report.unexpected_skips(&[]);
    assert!(
        skipped.is_empty(),
        "{} cases were left out:\n{}",
        skipped.len(),
        skipped
            .iter()
            .take(20)
            .map(|result| format!("  {}: {}", result.case, result.note.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(report.is_clean(), "{report}");
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
                .map(|result| format!("  {} (sent again {} times)", result.case, result.repeats))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    assert!(
        !report.too_many_repeats(),
        "{} of {} cases needed a request sent again: the server is unavailable too often, which a busy host does not explain\n{report}",
        repeated.len(),
        report.executed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_administration_matrix_holds_on_the_memory_store() {
    matrix_on(StoreKind::Memory).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_administration_matrix_holds_on_postgres() {
    matrix_on(StoreKind::Postgres).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_scope_in_the_oracle_is_caught_case_by_case() {
    // The file says that reading the audit log needs `outbox:manage`: the server lets the token with `audit:read` in and
    // keeps the one with `outbox:manage` out.
    let wrong = BUNDLED.replace(
        "operation = \"listAuditEvents\"\nscopes = [\"audit:read\"]",
        "operation = \"listAuditEvents\"\nscopes = [\"outbox:manage\"]",
    );
    assert_ne!(wrong, BUNDLED, "the row to change was found");
    let env = AppEnv::new(|| application(StoreKind::Memory)).await.unwrap();
    let report = admin::run(&env, &Expectations::parse(&wrong).unwrap(), &RunOptions::default()).await;
    assert!(!report.is_clean(), "a wrong oracle must fail the matrix");
    let failed: Vec<String> = report
        .with(&Verdict::Failed)
        .iter()
        .map(|result| result.case.to_string())
        .collect();
    for wanted in [
        "tenant_token[audit:read] listAuditEvents",
        "tenant_token[outbox:manage] listAuditEvents",
    ] {
        assert!(
            failed.iter().any(|case| case == wanted),
            "{wanted} should differ: {failed:?}"
        );
    }
    assert!(
        failed.iter().all(|case| case.contains("listAuditEvents")),
        "only the operation with the wrong row differs: {failed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_actor_rule_in_the_oracle_is_caught_for_every_operation() {
    // The file says that the owner of a calendar administers the tenant, within the scopes of a tenant token: the server
    // refuses (403) every one of those operations.
    let wrong = BUNDLED.replace(
        "rule = \"refused\"\nnote = \"principals never administer anything",
        "rule = \"by_scope\"\nnote = \"principals never administer anything",
    );
    assert_ne!(wrong, BUNDLED, "the row to change was found");
    let env = AppEnv::new(|| application(StoreKind::Memory)).await.unwrap();
    let report = admin::run(&env, &Expectations::parse(&wrong).unwrap(), &RunOptions::default()).await;
    assert!(!report.is_clean(), "a wrong oracle must fail the matrix");
    let failed: Vec<String> = report
        .with(&Verdict::Failed)
        .iter()
        .map(|result| result.case.to_string())
        .collect();
    for wanted in [
        "owner listAuditEvents",
        "service_principal listWebhooks",
        "other_user listPrincipals",
    ] {
        assert!(
            failed.iter().any(|case| case == wanted),
            "{wanted} should differ: {failed:?}"
        );
    }
    assert!(
        failed
            .iter()
            .all(|case| !case.starts_with("tenant_token") && !case.starts_with("system_token")),
        "the rows of the tokens are right: {failed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_inbound_endpoint_that_is_switched_off_answers_conflict_to_those_who_may_use_it() {
    // The default application has the endpoint off: the oracle of that environment expects 409 where the endpoint would take
    // the message, and the refusals of the authorization are the same.
    let env = AppEnv::new(TestApp::builder).await.unwrap();
    let report = admin::run(&env, &Expectations::bundled().unwrap(), &RunOptions::default()).await;
    show("the administration matrix with the inbound endpoint off", &report);
    assert!(report.is_clean(), "{report}");
}
