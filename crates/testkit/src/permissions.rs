//! The permission matrix harness (PLAN 3.2).
//!
//! The matrix crosses every actor with every calendar, surface and operation. [`run`] resolves the expected outcome of
//! each case from the hand-reviewed expectations file ([`Expectations`]), builds the requests that perform the
//! operation on the surface ([`dav`], [`api`], [`mcp`], [`web`]), sends them through the transport of the environment
//! and compares:
//!
//! * the **status** of the answer with the status policy (allowed, 401 with its challenge, 404, 403 in the form of the
//!   surface, 412 for a stale precondition), and the form of a refusal ([`detail_problems`]);
//! * the **state** of the application before and after: a refused request changes nothing (sequence numbers, objects,
//!   grants, bindings, notifications, inboxes, outbox, mails, events, and the tenant, its principals, credentials and
//!   webhooks), and an allowed write does change something;
//! * the **body** of an answer: a refusal carries nothing of the event of the calendar it was refused for, an allowed read
//!   shows the event it was allowed to read, a free-busy answer to a user of another tenant shows no busy time, and a
//!   hidden calendar, home or object is answered like one that does not exist.
//!
//! The harness never decides what is allowed. When it and the server disagree, the case fails and a person decides
//! whether the file or the server is wrong; a deviation that is known and documented is a `[[known_issue]]` row of the
//! file, which the harness checks against what the server does today.
//!
//! # Environments
//!
//! A [`MatrixEnv`] is an application with its fixture world, its credentials and a way to look at its state: the
//! in-process application of [`TestApp`](crate::TestApp) ([`AppEnv`]), or a deployed instance that the staging runner
//! provisioned. Cases that cannot change anything run one after the other on a few shared environments; a case that
//! is allowed to change something runs on an environment of its own, so that no case sees what another did.
//!
//! # What is left out
//!
//! A case that cannot be performed is reported as skipped (the environment has no token that opens MCP, a fixture the case
//! needs is not there) or as not applicable (the request of the operation is another operation's), and a test that runs the
//! matrix in process pins the reasons it accepts ([`MatrixReport::unexpected_skips`]): a skip is never a pass, so a surface
//! that stops answering cannot turn the matrix green by being left out.

pub mod addressing;
pub mod admin;
pub mod api;
pub mod classify;
pub mod dav;
pub mod env;
pub mod mcp;
pub mod web;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use davhaven_fixtures::{ActorRole, CalendarRole};
use futures::StreamExt as _;
use serde_json::Value;

pub use self::addressing::Addressing;
pub use self::classify::{
    Classified, Classifier, Observed, classify, detail_problems, no_busy_time, same_kind, shape_of,
};
pub use self::env::{AppEnv, Isolation, MatrixEnv, ScriptedEnv};
use crate::busy::{self, Effect};
use crate::handles::{Actor, MCP_PATH};
use crate::matrix::{
    Case, Expectation, Expectations, KnownIssue, Level, Operation, Resolution, StatusPolicy, Surface, Target,
};
use crate::observe::Observation;
use crate::transport::TestRequest;

/// A request of a probe with the credentials of its actor.
#[must_use]
pub fn request(actor: &Actor, method: &str, target: &str) -> TestRequest {
    let request = TestRequest::new(method, target);
    match actor.authorization() {
        Some(authorization) => request.header("authorization", &authorization),
        None => request,
    }
}

/// One request of a case, with what it needs before it and how its answer is read.
#[derive(Debug, Clone)]
pub struct Probe {
    /// What the probe does, for reports.
    pub name: String,
    /// Requests sent before the state is observed: they prepare what the probe works on (an object to move, an inbox
    /// item to delete). They are sent as they are; a setup that fails is reported with the probe.
    pub setup: Vec<TestRequest>,
    /// The request under test.
    pub request: TestRequest,
    /// How the answer is read.
    pub classifier: Classifier,
    /// What the probe answers when the case is allowed: [`Expectation::Allow`], or [`Expectation::PreconditionFailed`] for a
    /// probe that carries a condition that is false (the permission is decided before the condition: a caller who is
    /// refused is refused, whatever the condition says).
    pub when_allowed: Expectation,
    /// Texts that the answer shows when the probe is allowed: the event or the calendar the caller was allowed to read.
    pub shows: Vec<String>,
    /// Whether the answer must show no busy time (a free-busy request of somebody who may not see it).
    pub no_busy_time: bool,
}

impl Probe {
    /// A probe without setup that is read by its status.
    pub fn new(name: impl Into<String>, request: TestRequest) -> Self {
        Self {
            name: name.into(),
            setup: Vec::new(),
            request,
            classifier: Classifier::Http,
            when_allowed: Expectation::Allow,
            shows: Vec::new(),
            no_busy_time: false,
        }
    }

    /// Adds a request that runs before the probe.
    #[must_use]
    pub fn after(mut self, setup: TestRequest) -> Self {
        self.setup.push(setup);
        self
    }

    /// Reads the answer with `classifier`.
    #[must_use]
    pub fn read_as(mut self, classifier: Classifier) -> Self {
        self.classifier = classifier;
        self
    }

    /// The probe carries a condition that is false: where the case is allowed, the answer is 412 and nothing changes.
    #[must_use]
    pub const fn stale(mut self) -> Self {
        self.when_allowed = Expectation::PreconditionFailed;
        self
    }

    /// Where the probe is allowed, the answer shows these texts.
    #[must_use]
    pub fn showing(mut self, texts: &[&str]) -> Self {
        self.shows.extend(texts.iter().map(|text| (*text).to_owned()));
        self
    }

    /// The answer must show no busy time.
    #[must_use]
    pub const fn without_busy_time(mut self) -> Self {
        self.no_busy_time = true;
        self
    }
}

/// What a case does on a surface.
#[derive(Debug, Clone)]
pub enum Plan {
    /// The requests that perform the operation. All of them must give the expected outcome.
    Probes(Vec<Probe>),
    /// The operation has no request on this surface for this actor and calendar (the request is another operation's).
    NotApplicable(String),
    /// The case cannot run in this environment, with the reason (no token that opens MCP, a fixture that is missing).
    Skip(String),
}

/// The ids of the objects that MCP tools are addressed by.
#[derive(Debug, Clone)]
pub struct McpIds {
    /// The id of the calendar.
    pub calendar_id: String,
    /// The id of the event of the calendar.
    pub event_id: String,
}

/// The outcome of one probe.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// The name of the probe.
    pub name: String,
    /// The HTTP status of the answer (0 when nothing was sent).
    pub status: u16,
    /// What the server answered in the vocabulary of the policy.
    pub observed: Option<Observed>,
    /// What is wrong, empty when the probe is as expected.
    pub problems: Vec<String>,
    /// What the probe answers where its case is allowed (see [`Probe::when_allowed`]).
    pub when_allowed: Expectation,
    /// How often a request of the probe, its setup included, was sent again because the host answered that it was too busy
    /// ([`crate::busy`]); 0 when none was.
    pub repeats: u32,
}

/// How a case ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The server did what the oracle says.
    Passed,
    /// The server deviates from the oracle in a way the file documents as a known issue, and it still does exactly that.
    KnownDeviation,
    /// The server does not do what the oracle says.
    Failed,
    /// A known issue is documented, but the server no longer deviates: the row is to be removed.
    StaleKnownIssue,
    /// The operation has no request here.
    NotApplicable,
    /// The case did not run, with the reason.
    Skipped,
}

/// The result of one case.
#[derive(Debug, Clone)]
pub struct CaseResult {
    /// The case.
    pub case: Case,
    /// What the oracle expects and why.
    pub resolution: Resolution,
    /// The documented deviation that covers the case, if any.
    pub known: Option<KnownIssue>,
    /// The probes.
    pub probes: Vec<ProbeResult>,
    /// The verdict.
    pub verdict: Verdict,
    /// Why the case was skipped or is not applicable.
    pub note: Option<String>,
}

impl CaseResult {
    /// The problems of every probe, one line each, prefixed with the probe.
    pub fn problems(&self) -> Vec<String> {
        self.probes
            .iter()
            .flat_map(|probe| {
                probe
                    .problems
                    .iter()
                    .map(|problem| format!("{}: {problem}", probe.name))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// How often a request of the case was sent again because the host answered that it was too busy ([`crate::busy`]).
    pub fn repeats(&self) -> u32 {
        self.probes.iter().map(|probe| probe.repeats).sum()
    }
}

/// How much of the matrix a run performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sampling {
    /// Every case.
    #[default]
    Everything,
    /// One case in `of`, chosen so that every actor, surface and operation is in the sample with some calendar (a case and its
    /// variants that carry one scope go together), and of the cases that change something, which need a world of their own (seconds
    /// on PostgreSQL), the first of each operation on each surface. This is what runs on PostgreSQL: a case costs hundreds of queries
    /// there, the
    /// rules above the store are the ones the memory store runs in every case, and what only the store can get wrong (row-level
    /// security, the queries of effective access) is in every row of the sample. `CONFORMANCE_FULL=1` runs everything.
    Rotation {
        /// The size of the rotation.
        of: usize,
    },
}

/// The position of an item in the list of its kind.
fn position_of<T: PartialEq>(all: &[T], item: &T) -> usize {
    all.iter().position(|candidate| candidate == item).unwrap_or(0)
}

/// Whether the nightly run, or a person before a release, asked for every case of the suites that run a sample on pull requests
/// (`CONFORMANCE_FULL=1`).
fn full_run_requested() -> bool {
    std::env::var("CONFORMANCE_FULL").is_ok_and(|value| value == "1")
}

impl Sampling {
    /// What a pull request runs of a suite whose cases are expensive: [`Sampling::Rotation`] of three, or every case when
    /// `CONFORMANCE_FULL=1` asks for it (the nightly workflow sets it).
    #[must_use]
    pub fn for_pull_requests() -> Self {
        if full_run_requested() {
            Self::Everything
        } else {
            Self::Rotation { of: 3 }
        }
    }

    /// Whether the sample has the case.
    #[must_use]
    pub fn keeps(self, case: &Case) -> bool {
        match self {
            Self::Everything => true,
            Self::Rotation { of } => {
                let at = position_of(ActorRole::ALL, &case.actor)
                    + position_of(CalendarRole::ALL, &case.calendar)
                    + position_of(Surface::ALL, &case.surface)
                    + position_of(Operation::ALL, &case.operation);
                at.is_multiple_of(of.max(1))
            }
        }
    }
}

/// How a run is configured.
#[derive(Clone)]
pub struct RunOptions {
    /// How many environments are used at the same time.
    pub concurrency: usize,
    /// Whether tokens that carry one scope are part of the matrix: tenant tokens on the API, and the owner's principal
    /// tokens on the API and MCP.
    pub token_scopes: bool,
    /// Only the cases for which the filter says yes (all by default).
    pub filter: Option<fn(&Case) -> bool>,
    /// How much of the matrix runs (and, in the administration matrix, how many of the cases that need a world of their own).
    pub sampling: Sampling,
}

impl RunOptions {
    /// The options for a run on a store. A world on PostgreSQL is a database with connections of its own, and the cluster that
    /// CI starts allows a hundred of them to everything that runs at the same time, so fewer worlds are used at once.
    #[must_use]
    pub fn for_store(store: crate::app::StoreKind) -> Self {
        let postgres = store == crate::app::StoreKind::Postgres;
        Self {
            concurrency: if postgres { 2 } else { 4 },
            sampling: if postgres {
                Sampling::for_pull_requests()
            } else {
                Sampling::Everything
            },
            ..Self::default()
        }
    }
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            concurrency: 4,
            token_scopes: true,
            filter: None,
            sampling: Sampling::Everything,
        }
    }
}

/// The skips an in-process run accepts: the allowed answer to an invitation is not performed, because the fixture world has
/// no event that invites somebody who may write to its calendar. Everything else that is skipped is a failure of the run.
pub const IN_PROCESS_SKIPS: &[&str] = &[mcp::NO_INVITATION];

/// The reasons for which an operation has no request of its own (its request is another operation's): `DELETE` of a bound
/// collection removes the binding for somebody who is not the owner, and deletes the calendar for the owner.
pub const IN_PROCESS_NOT_APPLICABLE: &[&str] = &[dav::DELETE_IS_REMOVE_BINDING, dav::DELETE_IS_DELETE_CALENDAR];

/// The result of a run.
#[derive(Debug, Clone, Default)]
pub struct MatrixReport {
    /// Every case, in the order of the matrix.
    pub results: Vec<CaseResult>,
    /// Problems with the environment itself (an environment that could not be created).
    pub environment_problems: Vec<String>,
    /// How many cases the sample left out ([`Sampling`]); they are not among the results.
    pub left_out: usize,
}

/// Whether a verdict means that the case was sent to the server.
const fn was_sent(verdict: &Verdict) -> bool {
    matches!(
        verdict,
        Verdict::Passed | Verdict::KnownDeviation | Verdict::Failed | Verdict::StaleKnownIssue
    )
}

impl MatrixReport {
    /// The results with a verdict.
    pub fn with(&self, verdict: &Verdict) -> Vec<&CaseResult> {
        self.results
            .iter()
            .filter(|result| &result.verdict == verdict)
            .collect()
    }

    /// Whether nothing failed: no failed case, no stale known issue and a sound environment.
    pub fn is_clean(&self) -> bool {
        self.environment_problems.is_empty()
            && self
                .results
                .iter()
                .all(|result| !matches!(result.verdict, Verdict::Failed | Verdict::StaleKnownIssue))
    }

    /// The cases that needed a request sent again because the host answered that it was too busy ([`crate::busy`]). The run
    /// says how many, so that a server that is unavailable now and then does not hide behind the repeats
    /// ([`MatrixReport::too_many_repeats`]).
    pub fn repeated(&self) -> Vec<&CaseResult> {
        self.results.iter().filter(|result| result.repeats() > 0).collect()
    }

    /// Whether more cases needed a repeat than a busy host explains ([`crate::busy::excessive`]).
    pub fn too_many_repeats(&self) -> bool {
        crate::busy::excessive(self.repeated().len(), self.executed())
    }

    /// The number of cases that were sent to the server.
    pub fn executed(&self) -> usize {
        self.results.iter().filter(|result| was_sent(&result.verdict)).count()
    }

    /// The number of cases of a surface that were sent to the server.
    pub fn executed_on(&self, surface: Surface) -> usize {
        self.results
            .iter()
            .filter(|result| result.case.surface == surface && was_sent(&result.verdict))
            .count()
    }

    /// The skipped cases whose reason is not in `allowed`: a skip that nobody expected.
    pub fn unexpected_skips(&self, allowed: &[&str]) -> Vec<&CaseResult> {
        self.with(&Verdict::Skipped)
            .into_iter()
            .filter(|result| !result.note.as_deref().is_some_and(|note| allowed.contains(&note)))
            .collect()
    }

    /// The not applicable cases whose reason does not start with one of `allowed`.
    pub fn unexpected_not_applicable(&self, allowed: &[&str]) -> Vec<&CaseResult> {
        self.with(&Verdict::NotApplicable)
            .into_iter()
            .filter(|result| {
                !result
                    .note
                    .as_deref()
                    .is_some_and(|note| allowed.iter().any(|reason| note.starts_with(reason)))
            })
            .collect()
    }

    /// The `[[scope]]` rows of the file that no executed case that carries one scope reached: a row that is only ever read by
    /// a coverage check and never sent to the server (`surface/operation`).
    pub fn scope_rows_unreached(&self, expectations: &Expectations) -> Vec<String> {
        let reached: std::collections::BTreeSet<(Surface, Operation)> = self
            .results
            .iter()
            .filter(|result| result.case.token_scope.is_some() && was_sent(&result.verdict))
            .map(|result| (result.case.surface, result.case.operation))
            .collect();
        let mut unreached = Vec::new();
        for surface in Surface::ALL {
            for operation in expectations.operations_on(*surface) {
                if expectations.scope_of(*surface, operation).is_some() && !reached.contains(&(*surface, operation)) {
                    unreached.push(format!("{surface}/{operation}"));
                }
            }
        }
        unreached
    }
}

impl fmt::Display for MatrixReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = |verdict| self.with(&verdict).len();
        writeln!(
            f,
            "{} cases: {} passed, {} known deviations, {} failed, {} stale known issues, {} not applicable, {} skipped",
            self.results.len(),
            count(Verdict::Passed),
            count(Verdict::KnownDeviation),
            count(Verdict::Failed),
            count(Verdict::StaleKnownIssue),
            count(Verdict::NotApplicable),
            count(Verdict::Skipped)
        )?;
        if self.left_out > 0 {
            writeln!(f, "{} more cases are not in the sample of this run", self.left_out)?;
        }
        for problem in &self.environment_problems {
            writeln!(f, "environment: {problem}")?;
        }
        let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
        for result in self.with(&Verdict::Skipped) {
            *skipped.entry(result.note.clone().unwrap_or_default()).or_default() += 1;
        }
        for (reason, number) in skipped {
            writeln!(f, "skipped ({number}): {reason}")?;
        }
        let repeated = self.repeated();
        if !repeated.is_empty() {
            let sent = repeated.iter().map(|result| result.repeats()).sum::<u32>();
            writeln!(
                f,
                "{} of {} cases needed a request sent again ({sent} times in all) because the host answered that it was too busy (503):",
                repeated.len(),
                self.executed()
            )?;
            for result in repeated.iter().take(10) {
                writeln!(f, "  {} (sent again {} times)", result.case, result.repeats())?;
            }
            if repeated.len() > 10 {
                writeln!(f, "  and {} more", repeated.len() - 10)?;
            }
        }
        let mut failures: BTreeMap<(Surface, Operation), Vec<&CaseResult>> = BTreeMap::new();
        for result in self
            .results
            .iter()
            .filter(|result| matches!(result.verdict, Verdict::Failed | Verdict::StaleKnownIssue))
        {
            failures
                .entry((result.case.surface, result.case.operation))
                .or_default()
                .push(result);
        }
        for ((surface, operation), results) in failures {
            writeln!(f, "\n{operation} via {surface}: {} case(s) differ", results.len())?;
            // The same problem in many cases is shown once, with the cases it occurs in.
            let mut by_problem: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
            for result in &results {
                let expected = format!("{}", result.resolution.expectation);
                for problem in result.problems() {
                    by_problem
                        .entry(signature(&problem, &expected))
                        .or_default()
                        .push((result.case.to_string(), problem));
                }
            }
            for (signature, cases) in by_problem {
                writeln!(f, "  x{} {signature}", cases.len())?;
                for (case, problem) in cases.iter().take(3) {
                    writeln!(f, "      e.g. {case}")?;
                    writeln!(f, "           {problem}")?;
                }
            }
        }
        Ok(())
    }
}

/// A problem text without what differs between cases: numbers and names of resources are replaced.
fn signature(problem: &str, expected: &str) -> String {
    let mut text = String::new();
    let mut in_number = false;
    for character in problem.chars().take(140) {
        if character.is_ascii_digit() {
            if !in_number {
                text.push('#');
            }
            in_number = true;
        } else {
            in_number = false;
            text.push(character);
        }
    }
    format!("[oracle: {expected}] {text}")
}

// ---------------------------------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------------------------------

/// The scope that a token carries to be refused where it lacks the scope of the operation: another scope of the same family.
fn other_scope(surface: Surface, needed: &str) -> &'static str {
    match surface {
        Surface::Mcp => {
            if needed == "mcp:read" {
                "mcp:write"
            } else {
                "mcp:read"
            }
        }
        _ => {
            if needed == "events:read" {
                "calendars:read"
            } else {
                "events:read"
            }
        }
    }
}

/// Whether the matrix holds tokens that carry one scope for an actor on a surface: tenant tokens on the API, and the
/// owner's principal tokens on the API and MCP (the scope of a token is checked before anything about its principal, so
/// one principal stands for all).
fn carries_one_scope(actor: ActorRole, surface: Surface) -> bool {
    matches!(
        (actor, surface),
        (ActorRole::TenantToken, Surface::Api) | (ActorRole::Owner, Surface::Api | Surface::Mcp)
    )
}

/// The cases of the matrix for `expectations`: every actor, calendar, surface and operation that exists on the surface,
/// and for the tokens that carry one scope (tenant tokens on the API, the owner's principal tokens on the API and MCP) the
/// token that carries exactly the scope of the operation as well as one that carries another scope.
pub fn cases(expectations: &Expectations, options: &RunOptions) -> Vec<Case> {
    let mut cases = Vec::new();
    for actor in ActorRole::ALL {
        for calendar in CalendarRole::ALL {
            for surface in Surface::ALL {
                for operation in expectations.operations_on(*surface) {
                    let case = Case::new(*actor, *calendar, *surface, operation);
                    if !options.sampling.keeps(&case) {
                        continue;
                    }
                    if options.filter.is_none_or(|keep| keep(&case)) {
                        cases.push(case.clone());
                    }
                    if options.token_scopes
                        && carries_one_scope(*actor, *surface)
                        && let Some(scope) = expectations.scope_of(*surface, operation)
                    {
                        for carried in [scope, other_scope(*surface, scope)] {
                            let scoped = case.clone().with_scope(carried);
                            if options.filter.is_none_or(|keep| keep(&scoped)) {
                                cases.push(scoped);
                            }
                        }
                    }
                }
            }
        }
    }
    cases
}

/// What a case is compared with: the documented deviation, if there is one, otherwise the oracle.
fn target_of(resolution: &Resolution, known: Option<&KnownIssue>) -> Expectation {
    known.map_or(resolution.expectation, |issue| issue.observed)
}

/// Whether a case has to run on an environment of its own: it is allowed to change state (by the oracle or by a
/// documented deviation).
fn needs_own_environment(case: &Case, resolution: &Resolution, known: Option<&KnownIssue>) -> bool {
    case.operation.mutates()
        && (target_of(resolution, known) == Expectation::Allow || resolution.expectation == Expectation::Allow)
}

/// Plans the requests of a case.
pub async fn plan(env: &dyn MatrixEnv, case: &Case, resolution: &Resolution, seq: usize) -> Plan {
    match case.surface {
        Surface::Dav => dav::plan(env, case, resolution, seq).await,
        Surface::Api => api::plan(env, case, resolution, seq).await,
        Surface::Mcp => mcp::plan(env, case, resolution, seq).await,
        Surface::Feed | Surface::Rsvp => web::plan(env, case, resolution, seq).await,
    }
}

/// The texts that an answer of the case must not contain, because they are what the caller has no right to see.
///
/// * The event of the calendar: its summary and `BEGIN:VEVENT` (the `UID` is not one of them: objects are named after it, so a
///   refusal that repeats the path it was asked for repeats it).
/// * For a user of another tenant, nothing of the busy time of the tenant's people: the start of the event as iCalendar and
///   as RFC 3339 write it. (A `FREEBUSY` property is looked for by [`no_busy_time`] where the probe asks for free-busy, line by
///   line: the text `FREEBUSY` is in `VFREEBUSY`, which a correct answer carries.)
/// * For a refused request for the home and the principal resource of a calendar's owner, what they list or name: the
///   calendars of the home, and the name and address of the principal.
fn leak_needles(env: &dyn MatrixEnv, case: &Case, refused: bool) -> Vec<String> {
    let at = Addressing::new(env.world());
    let event = at.event(case.calendar);
    let mut needles = vec![event.summary.clone(), "BEGIN:VEVENT".to_owned()];
    if case.actor == ActorRole::OtherTenantUser {
        needles.extend(event_time_needles(&event.ics));
    }
    match case.operation {
        Operation::ReadHome if refused => {
            let home = at.dav_owner_home(case.calendar);
            for role in CalendarRole::ALL {
                if at.owner(*role) == at.owner(case.calendar) && at.tenant(*role) == at.tenant(case.calendar) {
                    needles.push(format!("{home}{}/", at.slug(*role)));
                    needles.push(at.calendar(*role).display_name.clone());
                }
            }
        }
        Operation::ReadPrincipal if refused => {
            if let Ok(principal) = env
                .world()
                .principal_named(at.tenant(case.calendar).as_str(), at.owner(case.calendar).as_str())
            {
                needles.push(principal.display_name.clone());
                if let Some(email) = &principal.email {
                    needles.push(email.as_str().to_owned());
                }
            }
        }
        _ => {}
    }
    needles
}

/// The start of an event written as iCalendar (`20270315T090000Z`) and as RFC 3339 (`2027-03-15T09:00:00Z`), when the event
/// starts at a UTC time.
fn event_time_needles(ics: &str) -> Vec<String> {
    let unfolded = ics.replace("\r\n ", "");
    let Some(value) = unfolded
        .lines()
        .find_map(|line| line.trim_end_matches('\r').strip_prefix("DTSTART:"))
    else {
        return Vec::new();
    };
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() != 16 || bytes.get(8) != Some(&b'T') || bytes.get(15) != Some(&b'Z') {
        return Vec::new();
    }
    let part = |from: usize, to: usize| value.get(from..to).unwrap_or_default();
    let rfc3339 = format!(
        "{}-{}-{}T{}:{}:{}Z",
        part(0, 4),
        part(4, 6),
        part(6, 8),
        part(9, 11),
        part(11, 13),
        part(13, 15)
    );
    vec![value.to_owned(), rfc3339]
}

/// The state of the environment, or nothing when the case does not look at it.
async fn observe(env: &dyn MatrixEnv, observed: bool) -> Result<crate::observe::Observation, String> {
    if observed {
        env.observe().await
    } else {
        Ok(crate::observe::Observation::new())
    }
}

/// What a probe is compared with: what the case is, or for a probe that carries a false condition the 412 it answers when the
/// case is allowed.
fn wanted_of(target: Expectation, probe: &Probe) -> Expectation {
    if target == Expectation::Allow {
        probe.when_allowed
    } else {
        target
    }
}

/// Who looks at the state around the requests of a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Around {
    /// The probe, around its own request: a case that is allowed has probes of different outcomes (the stale ones change
    /// nothing, the last one does).
    Probe,
    /// The case, once around all its requests: a case that is refused has probes that all change nothing, and the state is
    /// the costly part of a probe (on PostgreSQL, hundreds of queries).
    Case,
}

/// What the preparation of a probe did: what went wrong with it, and how often a request of it was sent again because the host
/// answered that it was too busy ([`crate::busy`]).
#[derive(Debug, Default)]
struct Preparation {
    problems: Vec<String>,
    repeats: u32,
}

/// Prepares what a probe needs, and says what went wrong with it.
async fn run_setups(env: &dyn MatrixEnv, target: Expectation, probe: &Probe) -> Preparation {
    let transport = env.transport();
    let mut prepared = Preparation::default();
    for setup in &probe.setup {
        let (sent, repeats) = busy::send_preparation(transport.as_ref(), setup).await;
        prepared.repeats += repeats;
        match sent {
            Ok(response) if response.status.is_success() => {}
            // An actor that cannot be authenticated cannot prepare anything either; that is the case being tested.
            Ok(response) if target != Expectation::Allow && response.status.as_u16() == 401 => {}
            Ok(response) => prepared.problems.push(format!(
                "the setup {} {} was answered {}",
                setup.method,
                setup.target,
                response.status.as_u16()
            )),
            Err(error) => prepared
                .problems
                .push(format!("the setup {} cannot be sent: {error}", setup.target)),
        }
    }
    prepared
}

/// What the world shows about a request of a case that the host answered as too busy ([`crate::busy::is_busy`]): whether it may
/// be sent again. A request of an operation that only reads may always be; one that may change something may when the state of
/// the application is what it was before the request. `observed` says that the state was looked at around the request (and
/// `after` is the result); otherwise the case looks at it once around all its requests, and the state is looked at now.
async fn effect_of_busy_answer(
    env: &dyn MatrixEnv,
    case: &Case,
    baseline: Option<&Observation>,
    observed: Option<&Result<Observation, String>>,
) -> Effect {
    if !case.operation.mutates() {
        return Effect::Repeatable;
    }
    match observed {
        Some(after) => Effect::of_request(true, baseline, after.as_ref().ok()),
        None => Effect::of_request(true, baseline, env.observe().await.ok().as_ref()),
    }
}

/// Sends one probe and compares everything that can be compared. For [`Around::Case`] the caller has made the setups
/// (`prepared` says what went wrong with them) and looks at the state.
///
/// An answer that says that the host was too busy (503) is sent again, up to the attempts of [`busy::Policy::STANDARD`], when the
/// operation only reads, or when the state of the application shows that the request changed nothing ([`effect_of_busy_answer`]):
/// a case is about what the server decides, and a server that has no time to decide has not decided anything. A request that did
/// change something, or whose effect cannot be seen, keeps the answer, which fails the case; so does an answer that stays busy.
#[expect(
    clippy::too_many_lines,
    reason = "one pass over the checks that every probe gets, in the order of the report"
)]
async fn run_probe(
    env: &dyn MatrixEnv,
    case: &Case,
    target: Expectation,
    probe: &Probe,
    checks: &Checks<'_>,
    around: Around,
    prepared: Preparation,
) -> (ProbeResult, bool) {
    let mut result = ProbeResult {
        name: probe.name.clone(),
        status: 0,
        observed: None,
        problems: prepared.problems,
        when_allowed: probe.when_allowed,
        repeats: prepared.repeats,
    };
    let wanted = wanted_of(target, probe);
    let refused = wanted != Expectation::Allow;
    let transport = env.transport();
    if around == Around::Probe {
        let prepared = run_setups(env, target, probe).await;
        result.problems.extend(prepared.problems);
        result.repeats += prepared.repeats;
    }
    // The state is looked at around what can change it, and around every request that is refused: a refusal that left a
    // trace is the failure the matrix is for. An allowed read changes nothing that anybody could check.
    let observed = around == Around::Probe && (case.operation.mutates() || (refused && env.observes_reads()));
    let before = match observe(env, observed).await {
        Ok(before) => before,
        Err(error) => {
            result.problems.push(format!("the state cannot be observed: {error}"));
            return (result, false);
        }
    };
    // What a request that was answered as too busy is compared with: the state before the probe, or (for a refused case, which
    // looks at the state once) before the case.
    let baseline = if observed { Some(&before) } else { checks.baseline };
    let (sent, repeats) = busy::repeat_while_busy(busy::Policy::STANDARD, || async {
        let response = transport.send(probe.request.clone()).await;
        let after = match &response {
            Ok(_) => observe(env, observed).await,
            Err(_) => Ok(Observation::new()),
        };
        let busy_effect = match &response {
            Ok(response) if busy::is_busy(response) => {
                Some(effect_of_busy_answer(env, case, baseline, observed.then_some(&after)).await)
            }
            _ => None,
        };
        busy::Attempt {
            value: (response, after),
            busy: busy_effect,
        }
    })
    .await;
    result.repeats += repeats;
    let (response, after) = sent;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            result.problems.push(format!("the request cannot be sent: {error}"));
            return (result, false);
        }
    };
    let after = match after {
        Ok(after) => after,
        Err(error) => {
            result.problems.push(format!("the state cannot be observed: {error}"));
            return (result, false);
        }
    };
    let classified = classify(&probe.classifier, &response);
    result.status = classified.status;
    let wanted_observed = Observed::Is(wanted);
    if classified.observed == wanted_observed {
        // A listing that does not show the calendar is a 200: the details are those of a refusal.
        if checks.details && !response.status.is_success() {
            result.problems.extend(
                detail_problems(case.surface, &classified.observed, &response, checks.policy)
                    .into_iter()
                    .map(|problem| format!("{problem} ({})", response.excerpt(160))),
            );
        }
        if wanted == Expectation::Allow {
            let text = response.text();
            for shown in &probe.shows {
                if !text.contains(shown) {
                    result.problems.push(format!(
                        "the allowed answer does not show `{shown}` ({})",
                        response.excerpt(160)
                    ));
                }
            }
        }
    } else {
        result.problems.push(format!(
            "answered {} (status {}), expected {} ({})",
            classified.observed,
            classified.status,
            wanted,
            response.excerpt(160)
        ));
    }
    if probe.no_busy_time {
        result.problems.extend(
            no_busy_time(case.surface, &response)
                .into_iter()
                .map(|problem| format!("{problem} ({})", response.excerpt(160))),
        );
    }
    let differences = before.diff(&after);
    if refused && !differences.is_empty() {
        result.problems.push(format!(
            "the refused request changed the state: {}",
            differences.iter().take(6).cloned().collect::<Vec<_>>().join("; ")
        ));
    }
    if around == Around::Probe
        && !refused
        && case.operation.mutates()
        && classified.observed == wanted_observed
        && differences.is_empty()
    {
        result
            .problems
            .push("the request was allowed but changed nothing".to_owned());
    }
    if let Some(Control { request, what, texts }) = control_for(env, case, wanted, checks.reads_objects, &probe.request)
    {
        // The control asks for something that is not there: it changes nothing, so a busy answer to it is sent again too.
        let (sent, repeats) = busy::send_repeatable(transport.as_ref(), &request).await;
        result.repeats += repeats;
        if let Ok(missing) = sent {
            let subjects: Vec<&str> = texts.iter().map(String::as_str).collect();
            if let Err(difference) = same_kind(&response, &missing, &subjects) {
                result.problems.push(format!(
                    "{} is distinguishable from {}: {difference}",
                    what.hidden(),
                    what.missing()
                ));
            }
        }
    }
    if checks.no_access {
        let text = response.text();
        for needle in leak_needles(env, case, refused) {
            if text.contains(&needle) {
                result
                    .problems
                    .push(format!("the answer to an actor without access leaks `{needle}`"));
            }
        }
    }
    result.observed = Some(classified.observed);
    (result, refused && !differences.is_empty())
}

// ---------------------------------------------------------------------------------------------------------------
// Hidden looks like missing
// ---------------------------------------------------------------------------------------------------------------

/// The slug of a calendar that does not exist.
const MISSING_CALENDAR: &str = "no-such-calendar-xyz";
/// The name of a principal that does not exist.
const MISSING_PRINCIPAL: &str = "no-such-principal-xyz";
/// The name of an object that does not exist.
const MISSING_OBJECT: &str = "no-such-object-xyz";
/// An id that nothing has.
const MISSING_ID: &str = "00000000-0000-7000-8000-00000000f00d";

/// What a control request changes in the request of a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// The calendar: its slug in a path, its id in the arguments of a tool.
    Calendar,
    /// The home of the calendar's owner: the name of the principal in a path.
    Home,
    /// The object: its name or key in a path, its id in the arguments of a tool.
    Object,
}

impl Subject {
    const fn hidden(self) -> &'static str {
        match self {
            Self::Calendar => "a hidden calendar",
            Self::Home => "a hidden home",
            Self::Object => "an object that is refused",
        }
    }

    const fn missing(self) -> &'static str {
        match self {
            Self::Calendar => "a missing one",
            Self::Home => "the home of a principal that does not exist",
            Self::Object => "an object that does not exist",
        }
    }
}

/// The request that asks the same thing about something that does not exist, with what differs between the two requests.
#[derive(Debug, Clone)]
pub struct Control {
    /// The request.
    pub request: TestRequest,
    /// What the control changed.
    pub what: Subject,
    /// The texts in which the two requests differ: what an answer may repeat of the request without it being a difference.
    pub texts: Vec<String>,
}

/// Replaces the argument `name` of the arguments of a tool call; returns the text that was replaced.
fn replace_tool_argument(request: &TestRequest, name: &str) -> Option<(TestRequest, String)> {
    if request.target != MCP_PATH {
        return None;
    }
    let mut body: Value = serde_json::from_slice(&request.body).ok()?;
    let argument = body.pointer_mut(&format!("/params/arguments/{name}"))?;
    let old = argument.as_str()?.to_owned();
    *argument = Value::String(MISSING_ID.to_owned());
    let mut control = request.clone();
    control.body = Bytes::from(serde_json::to_vec(&body).ok()?);
    Some((control, old))
}

/// The names of the thing a probe addresses, so that its control can be made.
#[derive(Debug, Clone, Copy)]
pub struct ControlNames<'a> {
    /// The slug of the calendar.
    pub calendar: &'a str,
    /// The name of the principal that owns it.
    pub owner: &'a str,
    /// The name of the fixture event as a DAV path segment.
    pub object: &'a str,
}

/// The control of a probe: the same request aimed at something that does not exist. A refusal must not tell a caller that the
/// thing exists.
///
/// * [`Subject::Calendar`]: the slug of the calendar (a path), or its id (the arguments of a tool);
/// * [`Subject::Home`]: the name of the principal that owns the home;
/// * [`Subject::Object`]: the name of the event (DAV), its key (API) or its id (a tool).
///
/// `None` when the request names no such thing (a listing, for example).
pub fn control_of(request: &TestRequest, subject: Subject, names: &ControlNames<'_>) -> Option<Control> {
    let replaced = |control: TestRequest, old: &str, new: &str| Control {
        request: control,
        what: subject,
        texts: vec![old.to_owned(), new.to_owned()],
    };
    match subject {
        Subject::Calendar | Subject::Object if request.target == MCP_PATH => {
            let argument = if subject == Subject::Calendar {
                "calendar_id"
            } else {
                "event_id"
            };
            let (control, old) = replace_tool_argument(request, argument)?;
            Some(replaced(control, &old, MISSING_ID))
        }
        Subject::Calendar => {
            let middle = format!("/{}/", names.calendar);
            let target = if request.target.contains(&middle) {
                request.target.replacen(&middle, &format!("/{MISSING_CALENDAR}/"), 1)
            } else {
                let stem = request.target.strip_suffix(&format!("/{}", names.calendar))?;
                format!("{stem}/{MISSING_CALENDAR}")
            };
            let mut control = request.clone();
            control.target = target;
            Some(replaced(control, names.calendar, MISSING_CALENDAR))
        }
        Subject::Home => {
            // Only the home of the owner is replaced: `/{owner}/` in a DAV or an API path.
            let middle = format!("/{}/", names.owner);
            let position = request.target.find(&middle)?;
            let (before, after) = request.target.split_at(position);
            let rest = after.get(middle.len()..)?;
            let mut control = request.clone();
            control.target = format!("{before}/{MISSING_PRINCIPAL}/{rest}");
            Some(replaced(control, names.owner, MISSING_PRINCIPAL))
        }
        Subject::Object => {
            let (target, old, new) = if let Some((stem, key)) = request.target.split_once("/objects/by-key/") {
                let key = key.split('?').next().unwrap_or(key);
                (
                    format!("{stem}/objects/by-key/{MISSING_OBJECT}"),
                    key.to_owned(),
                    MISSING_OBJECT.to_owned(),
                )
            } else {
                let stem = request.target.strip_suffix(&format!("/{}", names.object))?;
                (
                    format!("{stem}/{MISSING_OBJECT}.ics"),
                    names.object.to_owned(),
                    format!("{MISSING_OBJECT}.ics"),
                )
            };
            let mut control = request.clone();
            control.target = target;
            Some(replaced(control, &old, &new))
        }
    }
}

/// The control of a probe whose answer is a refusal: a hidden calendar (or home) is compared with one that does not exist,
/// and an object that the caller may see the calendar of but not act on is compared with an object that does not exist, so
/// that neither can be used to find out what exists.
fn control_for(
    env: &dyn MatrixEnv,
    case: &Case,
    wanted: Expectation,
    reads_objects: bool,
    request: &TestRequest,
) -> Option<Control> {
    let at = Addressing::new(env.world());
    let calendar = at.slug(case.calendar);
    let owner = at.owner(case.calendar);
    let object = addressing::object_segment(at.event(case.calendar).uri.as_str());
    let names = ControlNames {
        calendar: &calendar,
        owner: &owner,
        object: &object,
    };
    match wanted {
        Expectation::Hidden => {
            let home_operation = matches!(
                case.operation,
                Operation::CreateCalendar
                    | Operation::ReadInbox
                    | Operation::DeleteInboxItem
                    | Operation::PostOutbox
                    | Operation::ReadNotifications
                    | Operation::DeleteNotification
                    | Operation::ReadHome
            );
            if home_operation {
                control_of(request, Subject::Home, &names)
            } else {
                control_of(request, Subject::Calendar, &names)
            }
        }
        // Somebody who may read the objects of the calendar knows which exist: what the refusal says about one that is there (the
        // privilege it lacks, `write-content` for a resource that exists and `bind` for one that is made) is no secret.
        Expectation::Forbidden if !reads_objects => control_of(request, Subject::Object, &names),
        _ => None,
    }
}

/// What a case checks besides the status.
#[derive(Debug, Clone, Copy)]
struct Checks<'a> {
    /// Whether the details of a refusal are checked (the challenge, the precondition element).
    details: bool,
    /// Whether the actor has no access to the calendar, so that nothing of it may appear in an answer.
    no_access: bool,
    /// Whether the actor may read the objects of the calendar (it then knows which exist, and a refusal that names one is no leak).
    reads_objects: bool,
    /// The status policy, which names the code of each refusal.
    policy: &'a StatusPolicy,
    /// The state before the requests of a case that looks at it once, around all of them (a case that is refused): what a request
    /// that the host answered as too busy is compared with, to know whether it did anything.
    baseline: Option<&'a Observation>,
}

/// The result of a case whose oracle cannot be resolved: the file lacks a row, which is a failure of the file and not a
/// reason to expect anything.
fn unresolved(case: &Case, error: &crate::matrix::MatrixError) -> CaseResult {
    CaseResult {
        case: case.clone(),
        resolution: Resolution {
            expectation: Expectation::Hidden,
            source: crate::matrix::Source::Unavailable,
        },
        known: None,
        probes: vec![ProbeResult {
            name: "the oracle".to_owned(),
            status: 0,
            observed: None,
            problems: vec![format!("the expectations file does not decide the case: {error}")],
            when_allowed: Expectation::Allow,
            repeats: 0,
        }],
        verdict: Verdict::Failed,
        note: None,
    }
}

/// What the requests of a refused case did to the state that was read before them: the problems, and whether they changed it.
async fn state_problems(
    env: &dyn MatrixEnv,
    before: Result<crate::observe::Observation, String>,
) -> (Vec<String>, bool) {
    match (before, env.observe().await) {
        (Ok(before), Ok(after)) => {
            let differences = before.diff(&after);
            if differences.is_empty() {
                (Vec::new(), false)
            } else {
                (
                    vec![format!(
                        "the refused requests changed the state: {}",
                        differences.iter().take(6).cloned().collect::<Vec<_>>().join("; ")
                    )],
                    true,
                )
            }
        }
        (Err(error), _) | (_, Err(error)) => (vec![format!("the state cannot be observed: {error}")], false),
    }
}

/// Runs one case on an environment; the flag says that a refused request changed the state (the environment must not
/// be used for the next case).
pub async fn run_case(env: &dyn MatrixEnv, expectations: &Expectations, case: &Case, seq: usize) -> (CaseResult, bool) {
    let resolution = match expectations.resolve(case) {
        Ok(resolution) => resolution,
        Err(error) => return (unresolved(case, &error), false),
    };
    let known = expectations.known_issue(case);
    let target = target_of(&resolution, known.as_ref());
    let mut result = CaseResult {
        case: case.clone(),
        resolution: resolution.clone(),
        known: known.clone(),
        probes: Vec::new(),
        verdict: Verdict::Passed,
        note: None,
    };
    let probes = match plan(env, case, &resolution, seq).await {
        Plan::Probes(probes) => probes,
        Plan::NotApplicable(note) => {
            result.verdict = Verdict::NotApplicable;
            result.note = Some(note);
            return (result, false);
        }
        Plan::Skip(note) => {
            result.verdict = Verdict::Skipped;
            result.note = Some(note);
            return (result, false);
        }
    };
    // A case that is refused looks at the state once, around all its requests; a case that is allowed looks at it around each.
    let around_case = target != Expectation::Allow;
    let looks = around_case && (case.operation.mutates() || env.observes_reads());
    let mut prepared: Vec<Preparation> = Vec::new();
    for probe in &probes {
        prepared.push(if around_case {
            run_setups(env, target, probe).await
        } else {
            Preparation::default()
        });
    }
    let before = observe(env, looks).await;
    let checks = Checks {
        details: expectations.waiver(&resolution).is_none(),
        no_access: target != Expectation::Allow
            || expectations.level_of(case.actor, case.calendar, case.surface) == Level::Nothing,
        reads_objects: expectations.level_of(case.actor, case.calendar, case.surface) >= Level::Read,
        policy: expectations.status(),
        baseline: before.as_ref().ok().filter(|_| looks),
    };
    let mut tainted = false;
    for (probe, prepared) in probes.iter().zip(prepared) {
        let around = if around_case { Around::Case } else { Around::Probe };
        let (probe_result, changed) = run_probe(env, case, target, probe, &checks, around, prepared).await;
        tainted |= changed;
        result.probes.push(probe_result);
    }
    if looks {
        let (problems, changed) = state_problems(env, before).await;
        tainted |= changed;
        if !problems.is_empty() {
            result.probes.push(ProbeResult {
                name: "the state around the requests of the case".to_owned(),
                status: 0,
                observed: None,
                problems,
                when_allowed: Expectation::Allow,
                repeats: 0,
            });
        }
    }
    let problems = result.problems();
    result.verdict = match (&known, problems.is_empty()) {
        (Some(_), true) => Verdict::KnownDeviation,
        (Some(_), false) => {
            // The server does not do what the file says it does today. When it does what the oracle says, the known
            // issue is stale; otherwise the deviation changed.
            let oracle_holds = rerun_matches(&result, resolution.expectation);
            if oracle_holds {
                Verdict::StaleKnownIssue
            } else {
                Verdict::Failed
            }
        }
        (None, true) => Verdict::Passed,
        (None, false) => Verdict::Failed,
    };
    if result.verdict == Verdict::StaleKnownIssue {
        result.probes.push(ProbeResult {
            name: "known issue".to_owned(),
            status: 0,
            observed: None,
            problems: vec![format!(
                "the server answers as the oracle says ({}) but the file documents a deviation: remove the known_issue row ({})",
                resolution.expectation,
                known.map_or_else(String::new, |issue| issue.reason)
            )],
            when_allowed: Expectation::Allow,
            repeats: 0,
        });
    }
    (result, tainted)
}

/// Whether every probe of the result observed what the oracle says (a probe that carries a false condition is 412 where the
/// case is allowed).
fn rerun_matches(result: &CaseResult, expectation: Expectation) -> bool {
    !result.probes.is_empty()
        && result.probes.iter().filter(|probe| probe.status != 0).all(|probe| {
            let wanted = if expectation == Expectation::Allow {
                probe.when_allowed
            } else {
                expectation
            };
            probe.observed == Some(Observed::Is(wanted))
        })
}

// ---------------------------------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------------------------------

/// Why a case that may change something is left out of an environment that cannot make a world for it.
pub const NEEDS_OWN_WORLD: &str =
    "the case may change something and needs a world of its own, which this environment does not make";

/// Runs the matrix against an environment.
///
/// Cases that cannot change state run in sequence on a few shared environments (the given one and clones of it); a
/// case that may change state runs on an environment of its own. An environment whose state a refused request changed
/// is replaced, so one misbehaving case does not make the cases after it fail.
pub async fn run(env: &dyn MatrixEnv, expectations: &Expectations, options: &RunOptions) -> MatrixReport {
    let all = cases(expectations, options);
    let everything = RunOptions {
        sampling: Sampling::Everything,
        ..options.clone()
    };
    let mut report = MatrixReport {
        left_out: cases(expectations, &everything).len().saturating_sub(all.len()),
        ..MatrixReport::default()
    };

    let can_isolate = env.isolation() == Isolation::PerCase;
    let mut shared: Vec<(usize, Case)> = Vec::new();
    let mut own: Vec<(usize, Case)> = Vec::new();
    let mut collected: Vec<(usize, CaseResult)> = Vec::new();
    // A world of their own costs seconds on PostgreSQL: a sample runs the first case of each operation on each surface in one.
    let mut worlds: BTreeSet<(Surface, Operation)> = BTreeSet::new();
    for (seq, case) in all.iter().enumerate() {
        if !env.has_calendar(case.calendar) {
            continue;
        }
        let resolution = expectations.resolve(case);
        let known = expectations.known_issue(case);
        let isolated = resolution
            .as_ref()
            .is_ok_and(|resolution| needs_own_environment(case, resolution, known.as_ref()));
        match (isolated, can_isolate, resolution) {
            (true, true, _) => {
                if options.sampling == Sampling::Everything || worlds.insert((case.surface, case.operation)) {
                    own.push((seq, case.clone()));
                } else {
                    report.left_out += 1;
                }
            }
            (true, false, Ok(resolution)) => collected.push((
                seq,
                CaseResult {
                    case: case.clone(),
                    resolution,
                    known,
                    probes: Vec::new(),
                    verdict: Verdict::Skipped,
                    note: Some(NEEDS_OWN_WORLD.to_owned()),
                },
            )),
            _ => shared.push((seq, case.clone())),
        }
    }

    let shards = if env.parallel_worlds() {
        options.concurrency.max(1)
    } else {
        1
    };
    let mut shard_cases: Vec<Vec<(usize, Case)>> = vec![Vec::new(); shards];
    for (position, entry) in shared.into_iter().enumerate() {
        if let Some(shard) = shard_cases.get_mut(position % shards) {
            shard.push(entry);
        }
    }

    let mut problems: Vec<String> = Vec::new();

    // Shared environments: one per shard, each running its cases one after the other.
    let mut shard_runs = Vec::new();
    for (number, cases) in shard_cases.into_iter().enumerate() {
        if cases.is_empty() {
            continue;
        }
        shard_runs.push(run_shard(env, expectations, cases, number));
    }
    for shard in futures::future::join_all(shard_runs).await {
        let (results, shard_problems) = shard;
        collected.extend(results);
        problems.extend(shard_problems);
    }

    // Cases that change state: an environment each.
    let isolated_runs = own.into_iter().map(|(seq, case)| async move {
        let fresh = match env.fresh().await {
            Ok(fresh) => fresh,
            Err(error) => return (seq, Err(format!("an environment for `{case}`: {error}"))),
        };
        let (result, _) = run_case(fresh.as_ref(), expectations, &case, seq).await;
        (seq, Ok(result))
    });
    let finished: Vec<(usize, Result<CaseResult, String>)> = futures::stream::iter(isolated_runs)
        .buffer_unordered(shards)
        .collect()
        .await;
    for (seq, outcome) in finished {
        match outcome {
            Ok(result) => collected.push((seq, result)),
            Err(problem) => problems.push(problem),
        }
    }

    collected.sort_by_key(|(seq, _)| *seq);
    report.results = collected.into_iter().map(|(_, result)| result).collect();
    report.environment_problems = problems;
    report
}

/// Runs the cases of one shard in sequence on an environment of its own (the first shard uses `env` itself).
async fn run_shard(
    env: &dyn MatrixEnv,
    expectations: &Expectations,
    cases: Vec<(usize, Case)>,
    number: usize,
) -> (Vec<(usize, CaseResult)>, Vec<String>) {
    let mut results = Vec::new();
    let mut problems = Vec::new();
    let mut owned: Option<Box<dyn MatrixEnv>> = None;
    if number > 0 {
        match env.fresh().await {
            Ok(fresh) => owned = Some(fresh),
            Err(error) => {
                problems.push(format!("an environment for shard {number}: {error}"));
                return (results, problems);
            }
        }
    }
    for (seq, case) in cases {
        let (result, tainted) = {
            let current: &dyn MatrixEnv = owned.as_deref().unwrap_or(env);
            run_case(current, expectations, &case, seq).await
        };
        results.push((seq, result));
        if tainted {
            match env.fresh().await {
                Ok(fresh) => owned = Some(fresh),
                Err(error) => {
                    problems.push(format!("a replacement environment for shard {number}: {error}"));
                    break;
                }
            }
        }
    }
    (results, problems)
}

/// Whether an operation addresses the home of the owner of a calendar and not the calendar itself.
#[must_use]
pub fn addresses_a_home(expectations: &Expectations, operation: Operation) -> bool {
    expectations
        .need_of(operation)
        .is_some_and(|(_, target)| target == Target::Home)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names<'a>() -> ControlNames<'a> {
        ControlNames {
            calendar: "projects",
            owner: "olivia",
            object: "shared-event@acme.example.ics",
        }
    }

    #[test]
    fn the_control_of_a_calendar_replaces_its_slug_in_dav_and_api_paths() {
        let dav_collection = TestRequest::new("PROPFIND", "/dav/calendars/acme/rita/projects/");
        let control = control_of(&dav_collection, Subject::Calendar, &names()).unwrap();
        assert_eq!(control.request.target, "/dav/calendars/acme/rita/no-such-calendar-xyz/");
        let dav_object = TestRequest::new("GET", "/dav/calendars/acme/rita/projects/shared-event@acme.example.ics");
        assert_eq!(
            control_of(&dav_object, Subject::Calendar, &names())
                .unwrap()
                .request
                .target,
            "/dav/calendars/acme/rita/no-such-calendar-xyz/shared-event@acme.example.ics"
        );
        let api = TestRequest::new("GET", "/api/v1/tenants/acme/principals/olivia/calendars/projects");
        assert_eq!(
            control_of(&api, Subject::Calendar, &names()).unwrap().request.target,
            "/api/v1/tenants/acme/principals/olivia/calendars/no-such-calendar-xyz"
        );
        let listing = TestRequest::new("GET", "/api/v1/tenants/acme/principals/olivia/calendars");
        assert!(
            control_of(&listing, Subject::Calendar, &names()).is_none(),
            "a listing names no calendar"
        );
        let deep = TestRequest::new(
            "GET",
            "/api/v1/tenants/acme/principals/olivia/calendars/projects/objects",
        );
        assert_eq!(
            control_of(&deep, Subject::Calendar, &names()).unwrap().request.target,
            "/api/v1/tenants/acme/principals/olivia/calendars/no-such-calendar-xyz/objects"
        );
    }

    #[test]
    fn the_control_of_a_home_replaces_the_name_of_its_principal() {
        let inbox = TestRequest::new("PROPFIND", "/dav/calendars/acme/olivia/inbox/");
        assert_eq!(
            control_of(&inbox, Subject::Home, &names()).unwrap().request.target,
            "/dav/calendars/acme/no-such-principal-xyz/inbox/"
        );
        let create = TestRequest::new("PUT", "/api/v1/tenants/acme/principals/olivia/calendars/mx-1");
        assert_eq!(
            control_of(&create, Subject::Home, &names()).unwrap().request.target,
            "/api/v1/tenants/acme/principals/no-such-principal-xyz/calendars/mx-1"
        );
        assert!(control_of(&TestRequest::new("GET", "/dav/"), Subject::Home, &names()).is_none());
    }

    #[test]
    fn the_control_of_an_object_replaces_its_name_its_key_or_its_id() {
        let dav = TestRequest::new(
            "DELETE",
            "/dav/calendars/acme/rita/projects/shared-event@acme.example.ics",
        );
        assert_eq!(
            control_of(&dav, Subject::Object, &names()).unwrap().request.target,
            "/dav/calendars/acme/rita/projects/no-such-object-xyz.ics"
        );
        let api = TestRequest::new(
            "PUT",
            "/api/v1/tenants/acme/principals/olivia/calendars/projects/objects/by-key/shared-event",
        );
        assert_eq!(
            control_of(&api, Subject::Object, &names()).unwrap().request.target,
            "/api/v1/tenants/acme/principals/olivia/calendars/projects/objects/by-key/no-such-object-xyz"
        );
        let collection = TestRequest::new("PROPPATCH", "/dav/calendars/acme/rita/projects/");
        assert!(
            control_of(&collection, Subject::Object, &names()).is_none(),
            "no object named"
        );

        let call = mcp::tool_call(
            &Actor::bearer("t"),
            1,
            "get_event",
            &serde_json::json!({"calendar_id": "c1", "event_id": "e1"}),
        );
        let object = control_of(&call, Subject::Object, &names()).unwrap();
        let body: Value = serde_json::from_slice(&object.request.body).unwrap();
        assert_eq!(body["params"]["arguments"]["event_id"], MISSING_ID);
        assert_eq!(
            body["params"]["arguments"]["calendar_id"], "c1",
            "only the event changes"
        );
        let calendar = control_of(&call, Subject::Calendar, &names()).unwrap();
        let body: Value = serde_json::from_slice(&calendar.request.body).unwrap();
        assert_eq!(body["params"]["arguments"]["calendar_id"], MISSING_ID);
        assert_eq!(calendar.texts, vec!["c1".to_owned(), MISSING_ID.to_owned()]);
        let listing = mcp::tool_call(&Actor::bearer("t"), 1, "list_calendars", &serde_json::json!({}));
        assert!(control_of(&listing, Subject::Calendar, &names()).is_none());
    }

    #[test]
    fn the_start_of_an_event_is_a_needle_in_both_forms() {
        let ics = "BEGIN:VEVENT\r\nDTSTART:20270315T090000Z\r\nEND:VEVENT\r\n";
        assert_eq!(
            event_time_needles(ics),
            vec!["20270315T090000Z".to_owned(), "2027-03-15T09:00:00Z".to_owned()]
        );
        assert_eq!(
            event_time_needles("DTSTART;TZID=Europe/Berlin:20270315T090000\r\n"),
            Vec::<String>::new()
        );
        assert_eq!(event_time_needles("no event"), Vec::<String>::new());
    }

    #[test]
    fn scope_variants_exist_for_tenant_tokens_on_the_api_and_for_the_owner_on_the_api_and_mcp() {
        let expectations = Expectations::bundled().unwrap();
        let all = cases(&expectations, &RunOptions::default());
        let scoped: Vec<&Case> = all.iter().filter(|case| case.token_scope.is_some()).collect();
        assert!(
            scoped
                .iter()
                .any(|case| case.actor == ActorRole::TenantToken && case.surface == Surface::Api)
        );
        assert!(
            scoped
                .iter()
                .any(|case| case.actor == ActorRole::Owner && case.surface == Surface::Api)
        );
        assert!(
            scoped
                .iter()
                .any(|case| case.actor == ActorRole::Owner && case.surface == Surface::Mcp)
        );
        assert!(
            scoped
                .iter()
                .all(|case| matches!(case.actor, ActorRole::TenantToken | ActorRole::Owner)),
            "no other actor holds single-scope tokens"
        );
        // Every operation with a scope gets the token that carries it and one that carries another scope.
        let reads: Vec<&str> = scoped
            .iter()
            .filter(|case| {
                case.actor == ActorRole::Owner
                    && case.surface == Surface::Mcp
                    && case.calendar == CalendarRole::Personal
                    && case.operation == Operation::ReadObject
            })
            .filter_map(|case| case.token_scope.as_deref())
            .collect();
        assert_eq!(reads, vec!["mcp:read", "mcp:write"]);
        let none = cases(
            &expectations,
            &RunOptions {
                token_scopes: false,
                ..RunOptions::default()
            },
        );
        assert!(none.iter().all(|case| case.token_scope.is_none()));
    }

    /// A result as the runner records it: one probe with the given problems and repeats.
    fn result(case: Case, verdict: Verdict, problems: &[&str], repeats: u32) -> CaseResult {
        CaseResult {
            case,
            resolution: Resolution {
                expectation: Expectation::Hidden,
                source: crate::matrix::Source::NoAccess,
            },
            known: None,
            probes: vec![ProbeResult {
                name: "read".to_owned(),
                status: 200,
                observed: Some(Observed::Is(Expectation::Allow)),
                problems: problems.iter().map(|problem| (*problem).to_owned()).collect(),
                when_allowed: Expectation::Allow,
                repeats,
            }],
            note: matches!(verdict, Verdict::Skipped | Verdict::NotApplicable).then(|| "no world".to_owned()),
            verdict,
        }
    }

    fn case(actor: ActorRole, surface: Surface) -> Case {
        Case::new(actor, CalendarRole::Personal, surface, Operation::ReadObject)
    }

    #[test]
    fn a_report_is_clean_only_without_failures_stale_known_issues_and_problems_of_the_environment() {
        let mut report = MatrixReport {
            results: vec![
                result(case(ActorRole::Owner, Surface::Dav), Verdict::Passed, &[], 0),
                result(
                    case(ActorRole::OtherUser, Surface::Api),
                    Verdict::KnownDeviation,
                    &[],
                    0,
                ),
                result(
                    case(ActorRole::ShareeRead, Surface::Dav),
                    Verdict::NotApplicable,
                    &[],
                    0,
                ),
                result(case(ActorRole::GroupMember, Surface::Dav), Verdict::Skipped, &[], 0),
            ],
            environment_problems: Vec::new(),
            left_out: 0,
        };
        assert!(report.is_clean());
        assert_eq!(report.executed(), 2, "what was not sent is not executed");
        assert_eq!(report.executed_on(Surface::Dav), 1);
        assert_eq!(report.executed_on(Surface::Mcp), 0);
        assert!(report.unexpected_skips(&["no world"]).is_empty());
        assert_eq!(report.unexpected_skips(&["another reason"]).len(), 1);

        for verdict in [Verdict::Failed, Verdict::StaleKnownIssue] {
            let mut failing = report.clone();
            failing.results[0].verdict = verdict.clone();
            assert!(!failing.is_clean(), "{verdict:?}");
            assert_eq!(failing.executed(), 2, "{verdict:?} was sent");
        }
        report.environment_problems.push("no database".to_owned());
        assert!(!report.is_clean(), "an unsound environment is not a clean run");
    }

    #[test]
    fn the_report_groups_the_same_problem_of_many_cases_and_counts_what_was_sent_again() {
        let report = MatrixReport {
            results: vec![
                result(
                    case(ActorRole::OtherUser, Surface::Dav),
                    Verdict::Failed,
                    &["the status is 200 where 404 was expected"],
                    0,
                ),
                result(
                    Case::new(
                        ActorRole::OtherUser,
                        CalendarRole::Group,
                        Surface::Dav,
                        Operation::ReadObject,
                    ),
                    Verdict::Failed,
                    &["the status is 207 where 404 was expected"],
                    3,
                ),
                result(case(ActorRole::Owner, Surface::Mcp), Verdict::Passed, &[], 0),
                result(case(ActorRole::ShareeRead, Surface::Dav), Verdict::Skipped, &[], 0),
            ],
            environment_problems: vec!["the world was seeded twice".to_owned()],
            left_out: 7,
        };
        let text = report.to_string();
        assert!(
            text.starts_with(
                "4 cases: 1 passed, 0 known deviations, 2 failed, 0 stale known issues, 0 not applicable, 1 skipped\n"
            ),
            "{text}"
        );
        for line in [
            "7 more cases are not in the sample of this run",
            "environment: the world was seeded twice",
            "skipped (1): no world",
            "1 of 3 cases needed a request sent again (3 times in all)",
            "read_object via dav: 2 case(s) differ",
            // The two problems differ only in their numbers: one entry, with both cases.
            "  x2 [oracle: hidden] read: the status is # where # was expected",
            "           read: the status is 207 where 404 was expected",
        ] {
            assert!(text.contains(line), "`{line}` is not in:\n{text}");
        }
        assert_eq!(text.matches("  x").count(), 1, "{text}");
    }

    #[test]
    fn a_scope_row_counts_as_reached_only_by_a_case_with_one_scope_that_was_sent() {
        let expectations = Expectations::bundled().unwrap();
        let scoped = |operation, verdict| {
            let case = Case::new(ActorRole::TenantToken, CalendarRole::Group, Surface::Api, operation)
                .with_scope("calendars:read");
            result(case, verdict, &[], 0)
        };
        let report = MatrixReport {
            results: vec![
                scoped(Operation::ReadCollection, Verdict::Failed),
                scoped(Operation::ListObjects, Verdict::Skipped),
                // A case without a single scope says nothing about the scope rows.
                result(
                    Case::new(
                        ActorRole::TenantToken,
                        CalendarRole::Group,
                        Surface::Api,
                        Operation::ReadObject,
                    ),
                    Verdict::Passed,
                    &[],
                    0,
                ),
            ],
            environment_problems: Vec::new(),
            left_out: 0,
        };
        let unreached = report.scope_rows_unreached(&expectations);
        assert!(!unreached.contains(&"api/read_collection".to_owned()), "{unreached:?}");
        assert!(
            unreached.contains(&"api/list_objects".to_owned()),
            "a skipped case was not sent"
        );
        assert!(unreached.contains(&"api/read_object".to_owned()), "{unreached:?}");
        assert!(unreached.contains(&"mcp/read_object".to_owned()), "{unreached:?}");
        assert!(
            !unreached.iter().any(|row| row.starts_with("dav/")),
            "DAV has no scope rows: {unreached:?}"
        );
    }
}
