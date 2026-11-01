//! The detectors of the permission matrices are tested with servers that are wrong on purpose.
//!
//! A matrix that passes against a correct server proves nothing about its own ability to fail: a probe that never notices a
//! refusal that changed something, an answer that leaks, a hidden calendar that is answered differently from a missing one
//! or busy time that is shown to another tenant would pass everything. Each test here runs one case of the matrix against a
//! scripted server (`ScriptedEnv`: an answering closure and a state closure) that does exactly one thing wrong, checks that the
//! case fails with the problem of that detector, and runs the same case against the scripted server that does it right, which
//! must pass: so that the detector is neither blind nor trigger-happy.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use davhaven_testkit::davhaven_fixtures::{ActorRole, CalendarRole, FixtureWorld};
use davhaven_testkit::matrix::{Case, Expectation, Operation, Surface};
use davhaven_testkit::permissions::admin::{self, AdminCase};
use davhaven_testkit::permissions::{self, Addressing, CaseResult, RunOptions, Sampling, ScriptedEnv, Verdict};
use davhaven_testkit::{Expectations, Observation, TestRequest, TestResponse};
use serde_json::json;

/// The problem document of a refusal on the API.
fn problem(status: u16, code: &str, detail: &str) -> TestResponse {
    TestResponse::new(
        status,
        json!({
            "type": format!("urn:davhaven:problem:{code}"),
            "title": "refused",
            "status": status,
            "code": code,
            "detail": detail
        })
        .to_string(),
    )
    .with_header("content-type", "application/problem+json")
}

/// The code the policy names for an outcome on the API.
fn code_of(expectations: &Expectations, outcome: Expectation) -> String {
    expectations
        .status()
        .rule(outcome)
        .and_then(|rule| rule.problem_code.clone())
        .unwrap()
}

/// The 403 of DAV that names the resource and the privilege that is missing.
fn need_privileges() -> TestResponse {
    TestResponse::new(
        403,
        "<?xml version=\"1.0\"?><D:error xmlns:D=\"DAV:\"><D:need-privileges><D:resource>\
         <D:href>/dav/calendars/acme/rita/projects/</D:href><D:privilege><D:write-content/></D:privilege>\
         </D:resource></D:need-privileges></D:error>",
    )
    .with_header("content-type", "application/xml; charset=utf-8")
}

/// A state with one fact that is whatever the counter says.
fn counted(counter: &Arc<AtomicUsize>) -> impl Fn() -> Observation + Send + Sync + 'static {
    let counter = Arc::clone(counter);
    move || {
        let mut state = Observation::new();
        state.insert("objects", counter.load(Ordering::SeqCst).to_string());
        state
    }
}

fn problems_of(result: &CaseResult) -> String {
    result.problems().join("\n")
}

fn assert_caught(result: &CaseResult, needle: &str) {
    assert_eq!(result.verdict, Verdict::Failed, "{}", problems_of(result));
    assert!(
        result.problems().iter().any(|problem| problem.contains(needle)),
        "no problem mentions `{needle}`:\n{}",
        problems_of(result)
    );
}

fn assert_passes(result: &CaseResult) {
    assert_eq!(result.verdict, Verdict::Passed, "{}", problems_of(result));
}

fn expectations() -> Expectations {
    Expectations::bundled().unwrap()
}

// ---------------------------------------------------------------------------------------------------------------
// A refusal that changes the state
// ---------------------------------------------------------------------------------------------------------------

fn sharee_creates_on_shared() -> Case {
    Case::new(
        ActorRole::ShareeRead,
        CalendarRole::Shared,
        Surface::Dav,
        Operation::CreateObject,
    )
}

#[tokio::test]
async fn a_refusal_that_changed_the_state_fails_the_case_and_taints_the_environment() {
    let expectations = expectations();
    let case = sharee_creates_on_shared();
    assert_eq!(
        expectations.resolve(&case).unwrap().expectation,
        Expectation::Forbidden,
        "the case is a refusal"
    );

    // The server answers 403 and writes the object all the same.
    let writes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&writes);
    let wrong = ScriptedEnv::new(
        move |request: &TestRequest| {
            if request.method.as_str() == "PUT" {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            need_privileges()
        },
        counted(&writes),
    );
    let (result, tainted) = permissions::run_case(&wrong, &expectations, &case, 1).await;
    assert_caught(&result, "changed the state");
    assert!(tainted, "an environment whose state a refusal changed must be replaced");

    // The server that refuses and leaves everything as it was passes.
    let still = Arc::new(AtomicUsize::new(0));
    let right = ScriptedEnv::new(|_: &TestRequest| need_privileges(), counted(&still));
    let (result, tainted) = permissions::run_case(&right, &expectations, &case, 1).await;
    assert_passes(&result);
    assert!(!tainted);
}

#[tokio::test]
async fn a_refused_request_that_is_answered_with_success_fails_the_case() {
    let expectations = expectations();
    let case = sharee_creates_on_shared();
    let still = Arc::new(AtomicUsize::new(0));
    let wrong = ScriptedEnv::new(|_: &TestRequest| TestResponse::new(201, ""), counted(&still));
    let (result, _) = permissions::run_case(&wrong, &expectations, &case, 1).await;
    assert_caught(&result, "expected forbidden");
}

#[tokio::test]
async fn a_403_on_dav_without_the_precondition_document_fails_the_case() {
    let expectations = expectations();
    let case = sharee_creates_on_shared();
    let still = Arc::new(AtomicUsize::new(0));
    let wrong = ScriptedEnv::new(|_: &TestRequest| TestResponse::new(403, "forbidden"), counted(&still));
    let (result, _) = permissions::run_case(&wrong, &expectations, &case, 1).await;
    assert_caught(&result, "DAV:error");
}

// ---------------------------------------------------------------------------------------------------------------
// A refusal that leaks
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_answer_to_somebody_without_access_that_repeats_the_event_fails_the_case() {
    let expectations = expectations();
    let case = Case::new(
        ActorRole::OtherUser,
        CalendarRole::Personal,
        Surface::Dav,
        Operation::ReadObject,
    );
    assert_eq!(
        expectations.resolve(&case).unwrap().expectation,
        Expectation::Hidden,
        "the case is a hidden calendar"
    );
    let summary = FixtureWorld::standard()
        .event(CalendarRole::Personal)
        .unwrap()
        .summary
        .clone();

    // A 404 whose body is the event.
    let leaking = {
        let summary = summary.clone();
        ScriptedEnv::new(
            move |request: &TestRequest| {
                if request.target.contains("no-such") {
                    TestResponse::new(404, "")
                } else {
                    TestResponse::new(404, format!("<error>no such object: {summary}</error>"))
                }
            },
            Observation::new,
        )
    };
    let (result, _) = permissions::run_case(&leaking, &expectations, &case, 1).await;
    assert_caught(&result, &format!("leaks `{summary}`"));

    let tight = ScriptedEnv::new(|_: &TestRequest| TestResponse::new(404, ""), Observation::new);
    let (result, _) = permissions::run_case(&tight, &expectations, &case, 1).await;
    assert_passes(&result);
}

// ---------------------------------------------------------------------------------------------------------------
// Hidden and missing look different
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_hidden_calendar_that_is_answered_differently_from_a_missing_one_fails_the_case() {
    let expectations = expectations();
    let case = Case::new(
        ActorRole::OtherUser,
        CalendarRole::Personal,
        Surface::Api,
        Operation::ReadCollection,
    );
    assert_eq!(expectations.resolve(&case).unwrap().expectation, Expectation::Hidden);
    let code = code_of(&expectations, Expectation::Hidden);
    let world = FixtureWorld::standard();
    let slug = Addressing::new(&world).slug(CalendarRole::Personal);

    // The calendar that exists is refused with a sentence that says that it does.
    let telling = {
        let (code, slug) = (code.clone(), slug.clone());
        ScriptedEnv::new(
            move |request: &TestRequest| {
                if request.target.ends_with(&format!("/{slug}")) {
                    problem(404, &code, "the calendar exists, but you may not see it")
                } else {
                    problem(404, &code, "there is no such calendar")
                }
            },
            Observation::new,
        )
    };
    let (result, _) = permissions::run_case(&telling, &expectations, &case, 1).await;
    assert_caught(&result, "is distinguishable from");

    let silent = ScriptedEnv::new(
        move |_: &TestRequest| problem(404, &code, "there is no such calendar"),
        Observation::new,
    );
    let (result, _) = permissions::run_case(&silent, &expectations, &case, 1).await;
    assert!(
        !result
            .problems()
            .iter()
            .any(|problem| problem.contains("is distinguishable from")),
        "{}",
        problems_of(&result)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Busy time of another tenant
// ---------------------------------------------------------------------------------------------------------------

fn other_tenant_asks_for_free_busy(surface: Surface) -> Case {
    Case::new(
        ActorRole::OtherTenantUser,
        CalendarRole::Personal,
        surface,
        Operation::FreeBusyQuery,
    )
}

fn tool_result(entry: &serde_json::Value) -> TestResponse {
    TestResponse::new(
        200,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}], "structuredContent": {"entries": [entry]}}
        })
        .to_string(),
    )
    .with_header("content-type", "application/json")
}

#[tokio::test]
async fn busy_time_of_another_tenants_person_over_mcp_fails_the_case() {
    let expectations = expectations();
    let case = other_tenant_asks_for_free_busy(Surface::Mcp);
    assert_eq!(expectations.resolve(&case).unwrap().expectation, Expectation::Allow);

    let telling = ScriptedEnv::new(
        |_: &TestRequest| {
            tool_result(&json!({
                "address": "mailto:olivia@acme.example",
                "known": true,
                "busy": [{"start": "2027-03-15T09:00:00Z", "end": "2027-03-15T10:00:00Z"}]
            }))
        },
        Observation::new,
    );
    let (result, _) = permissions::run_case(&telling, &expectations, &case, 1).await;
    assert_caught(&result, "is known to free_busy");

    let silent = ScriptedEnv::new(
        |_: &TestRequest| tool_result(&json!({"address": "mailto:olivia@acme.example", "known": false, "busy": []})),
        Observation::new,
    );
    let (result, _) = permissions::run_case(&silent, &expectations, &case, 1).await;
    assert_passes(&result);
}

#[tokio::test]
async fn busy_time_of_another_tenants_person_over_dav_fails_the_case() {
    let expectations = expectations();
    let case = other_tenant_asks_for_free_busy(Surface::Dav);
    assert_eq!(expectations.resolve(&case).unwrap().expectation, Expectation::Allow);

    let telling = ScriptedEnv::new(
        |_: &TestRequest| {
            TestResponse::new(
                200,
                "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nBEGIN:VFREEBUSY\r\nFREEBUSY;FBTYPE=BUSY:20270315T090000Z/20270315T100000Z\r\n\
                 END:VFREEBUSY\r\nEND:VCALENDAR\r\n",
            )
            .with_header("content-type", "text/calendar")
        },
        Observation::new,
    );
    let (result, _) = permissions::run_case(&telling, &expectations, &case, 1).await;
    assert_caught(&result, "busy time");

    let silent = ScriptedEnv::new(
        |_: &TestRequest| {
            TestResponse::new(
                200,
                "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nBEGIN:VFREEBUSY\r\nREQUEST-STATUS:3.7;Invalid calendar user\r\n\
                 END:VFREEBUSY\r\nEND:VCALENDAR\r\n",
            )
            .with_header("content-type", "text/calendar")
        },
        Observation::new,
    );
    let (result, _) = permissions::run_case(&silent, &expectations, &case, 1).await;
    assert_passes(&result);
}

// ---------------------------------------------------------------------------------------------------------------
// The administration matrix
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_refused_administration_request_that_changed_the_state_fails_the_case() {
    let expectations = expectations();
    let code = code_of(&expectations, Expectation::Forbidden);
    let case = AdminCase::new("createApiToken", ActorRole::Owner);
    assert_eq!(admin::expected(&expectations, &case).unwrap(), Expectation::Forbidden);

    // The server refuses to mint the token, and mints it.
    let minted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&minted);
    let wrong = {
        let code = code.clone();
        ScriptedEnv::new(
            move |request: &TestRequest| {
                if request.method.as_str() == "POST" {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                problem(403, &code, "not allowed")
            },
            counted(&minted),
        )
    };
    let (result, tainted) = admin::run_case(
        &wrong,
        &expectations,
        &admin::Fixtures::default(),
        &case,
        Expectation::Forbidden,
        1,
    )
    .await;
    assert_eq!(result.verdict, Verdict::Failed, "{:?}", result.problems);
    assert!(
        result
            .problems
            .iter()
            .any(|problem| problem.contains("the refused request changed the state")),
        "{:?}",
        result.problems
    );
    assert!(tainted);

    let kept = Arc::new(AtomicUsize::new(0));
    let right = ScriptedEnv::new(
        move |_: &TestRequest| problem(403, &code, "not allowed"),
        counted(&kept),
    );
    let (result, tainted) = admin::run_case(
        &right,
        &expectations,
        &admin::Fixtures::default(),
        &case,
        Expectation::Forbidden,
        1,
    )
    .await;
    assert_eq!(result.verdict, Verdict::Passed, "{:?}", result.problems);
    assert!(!tainted);
}

#[tokio::test]
async fn another_tenant_that_is_answered_differently_from_a_missing_one_fails_the_case() {
    let expectations = expectations();
    let code = code_of(&expectations, Expectation::Hidden);
    let case = AdminCase::new("getTenant", ActorRole::OtherTenantToken);
    assert_eq!(admin::expected(&expectations, &case).unwrap(), Expectation::Hidden);
    let tenant = FixtureWorld::standard().names.tenant.clone();

    let telling = {
        let code = code.clone();
        ScriptedEnv::new(
            move |request: &TestRequest| {
                if request.target.contains(&format!("/tenants/{tenant}")) {
                    problem(404, &code, "the tenant exists, and is not yours")
                } else {
                    problem(404, &code, "there is no such tenant")
                }
            },
            Observation::new,
        )
    };
    let (result, _) = admin::run_case(
        &telling,
        &expectations,
        &admin::Fixtures::default(),
        &case,
        Expectation::Hidden,
        1,
    )
    .await;
    assert_eq!(result.verdict, Verdict::Failed, "{:?}", result.problems);
    assert!(
        result
            .problems
            .iter()
            .any(|problem| problem.contains("distinguishable")),
        "{:?}",
        result.problems
    );

    let silent = ScriptedEnv::new(
        move |_: &TestRequest| problem(404, &code, "there is no such tenant"),
        Observation::new,
    );
    let (result, _) = admin::run_case(
        &silent,
        &expectations,
        &admin::Fixtures::default(),
        &case,
        Expectation::Hidden,
        1,
    )
    .await;
    assert_eq!(result.verdict, Verdict::Passed, "{:?}", result.problems);
}

#[tokio::test]
async fn an_operation_that_is_pending_must_answer_501_and_a_stale_row_is_reported() {
    // No operation of the server is pending any more (the last rows went with the providers), so the file gets a row for the
    // mechanism: an operation that a service does not offer yet, in a copy of the bundled file.
    let expectations = Expectations::parse(&format!(
        "{}\n[[pending]]\noperation = \"listProviders\"\nobserved = \"not_implemented\"\nreason = \"a service that is not merged\"\n",
        davhaven_testkit::matrix::BUNDLED
    ))
    .unwrap();
    assert!(
        Expectations::bundled().unwrap().pending_operations().is_empty(),
        "every operation of the management API is offered"
    );
    let case = AdminCase::new("listProviders", ActorRole::TenantToken);
    assert!(
        expectations.pending("listProviders").is_some(),
        "an operation that is not implemented yet is a pending row"
    );
    let still = Arc::new(AtomicUsize::new(0));

    // The service is not there: 501 is what the row says.
    let missing = ScriptedEnv::new(
        |_: &TestRequest| TestResponse::new(501, "{}").with_header("content-type", "application/problem+json"),
        counted(&still),
    );
    let (result, _) = admin::run_case(
        &missing,
        &expectations,
        &admin::Fixtures::default(),
        &case,
        Expectation::Allow,
        1,
    )
    .await;
    assert_eq!(result.verdict, Verdict::Passed, "{:?}", result.problems);

    // The service is there now: the row is stale.
    let merged = ScriptedEnv::new(
        |_: &TestRequest| TestResponse::new(200, "{\"items\": []}"),
        counted(&still),
    );
    let (result, _) = admin::run_case(
        &merged,
        &expectations,
        &admin::Fixtures::default(),
        &case,
        Expectation::Allow,
        1,
    )
    .await;
    assert_eq!(result.verdict, Verdict::Failed);
    assert!(
        result.problems.iter().any(|problem| problem.contains("[[pending]]")),
        "{:?}",
        result.problems
    );
}

#[tokio::test]
async fn a_case_whose_world_cannot_be_made_is_a_failed_case_and_not_a_missing_one() {
    let expectations = expectations();
    let code = code_of(&expectations, Expectation::Forbidden);
    // The server refuses everybody, and its cluster is too busy to make a world for any case that changes something.
    let busy = ScriptedEnv::new(
        move |_: &TestRequest| problem(403, &code, "not allowed"),
        Observation::new,
    )
    .offering_worlds();
    let sample = RunOptions {
        sampling: Sampling::Rotation { of: 3 },
        ..RunOptions::default()
    };
    let report = admin::run(&busy, &expectations, &sample).await;

    let all = admin::cases(&expectations);
    let missing: Vec<String> = report.missing(&all).iter().map(ToString::to_string).collect();
    assert!(missing.is_empty(), "the run lost cases: {missing:?}");
    assert_eq!(report.results.len() + report.left_out.len(), all.len());
    assert!(
        !report.left_out.is_empty(),
        "the sample leaves out the repeats of each operation"
    );
    // The first case of an operation that changes something asks for a world, and the failure is its own.
    let lost: Vec<String> = report
        .with(&Verdict::Failed)
        .iter()
        .filter(|result| {
            result
                .problems
                .iter()
                .any(|problem| problem.contains("no world of its own"))
        })
        .map(|result| result.case.to_string())
        .collect();
    assert!(
        lost.iter().any(|case| case == "tenant_token createApiToken"),
        "the case is a failure that says why: {lost:?}"
    );
    assert!(
        !report.is_clean(),
        "a run that could not make a world is not a clean run"
    );
}

#[tokio::test]
async fn cases_that_are_left_without_an_environment_are_failed_cases_and_not_missing_ones() {
    let expectations = expectations();
    let code = code_of(&expectations, Expectation::Forbidden);
    // Every refusal changes the state, so the environment is replaced after the first one, and no other can be made.
    let looks = Arc::new(AtomicUsize::new(0));
    let changing = move || {
        let mut state = Observation::new();
        state.insert("looks", looks.fetch_add(1, Ordering::SeqCst).to_string());
        state
    };
    let env = ScriptedEnv::new(move |_: &TestRequest| problem(403, &code, "not allowed"), changing);
    let report = admin::run(&env, &expectations, &RunOptions::default()).await;

    let all = admin::cases(&expectations);
    let missing: Vec<String> = report.missing(&all).iter().map(ToString::to_string).collect();
    assert!(missing.is_empty(), "the run lost cases: {missing:?}");
    let stranded = report
        .with(&Verdict::Failed)
        .iter()
        .filter(|result| {
            result
                .problems
                .iter()
                .any(|problem| problem.contains("no environment replaces"))
        })
        .count();
    assert!(
        stranded > 100,
        "the cases after the first refusal have no environment: {stranded}"
    );
}
