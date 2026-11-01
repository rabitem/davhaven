//! A run against a deployed instance: provision, run the matrices and the client flows, tear down.

use core::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use super::{Deployment, StagingConfig, StagingError};
use crate::flow::{FlowVerdict, Scenario, ScenarioReport, run_scenario, verdict};
use crate::matrix::Expectations;
use crate::permissions::admin::{self, AdminReport};
use crate::permissions::{self, MatrixReport, RunOptions, Sampling};
use crate::transport::{HttpTransport, Transport};

/// What a run does.
#[derive(Debug, Clone)]
pub struct Options {
    /// Whether to run the permission matrix and the administration matrix.
    pub matrices: bool,
    /// The scenarios to run, each with the path of the file it was read from (for the report); none to run no flows.
    pub flows: Vec<(PathBuf, Scenario)>,
    /// The directory `body_file`s of the scenarios are read from.
    pub data_dir: Option<PathBuf>,
    /// Whether the matrices run the cases that change something, each on a world that is built again for it
    /// ([`Deployment::reset`]); otherwise those cases are left out and reported as skipped.
    pub reset_between_writes: bool,
    /// Whether the tenants stay after the run (by default they are deleted when the run has a system token).
    pub keep: bool,
    /// How much of the permission matrix runs: every case by default, which is what a run against a deployed instance wants. The
    /// tests of the runner over a socket run a sample on pull requests ([`Sampling::for_pull_requests`]) like the other suites.
    pub sampling: Sampling,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            matrices: true,
            flows: Vec::new(),
            data_dir: None,
            reset_between_writes: false,
            keep: false,
            sampling: Sampling::Everything,
        }
    }
}

/// How the flows of a run went.
#[derive(Debug, Clone, Default)]
pub struct FlowSummary {
    /// Every scenario with the judgement of its report.
    pub results: Vec<(PathBuf, FlowVerdict, ScenarioReport)>,
}

impl FlowSummary {
    /// Whether every scenario did what it should: passed, or failed as its known issue says.
    pub fn is_clean(&self) -> bool {
        self.results
            .iter()
            .all(|(_, verdict, _)| matches!(verdict, FlowVerdict::Passed | FlowVerdict::KnownIssue(_)))
    }
}

impl fmt::Display for FlowSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut passed = 0_usize;
        for (path, verdict, report) in &self.results {
            match verdict {
                FlowVerdict::Passed => passed += 1,
                FlowVerdict::KnownIssue(reason) => {
                    passed += 1;
                    writeln!(f, "known issue: {} ({})", report.scenario, reason.trim())?;
                }
                FlowVerdict::KnownIssueFixed(reason) => {
                    writeln!(
                        f,
                        "{}: the known issue is fixed, remove `known_issue` ({})",
                        path.display(),
                        reason.trim()
                    )?;
                }
                FlowVerdict::Failed => {
                    write!(f, "{report}")?;
                    writeln!(f, "  (from {})", path.display())?;
                }
            }
        }
        writeln!(f, "{passed} of {} scenarios did what they should", self.results.len())
    }
}

/// The result of a run.
#[derive(Debug, Clone, Default)]
pub struct StagingReport {
    /// The permission matrix, when it ran.
    pub matrix: Option<MatrixReport>,
    /// The administration operations of the management API, when the matrices ran.
    pub admin: Option<AdminReport>,
    /// The client flows, when there were any.
    pub flows: Option<FlowSummary>,
    /// Whether the tenants of the run were deleted at the end.
    pub torn_down: bool,
    /// Why the tenants could not be deleted, when they could not: the operator removes them.
    pub teardown_problem: Option<String>,
}

impl StagingReport {
    /// Whether nothing failed.
    pub fn is_clean(&self) -> bool {
        self.matrix.as_ref().is_none_or(MatrixReport::is_clean)
            && self.admin.as_ref().is_none_or(AdminReport::is_clean)
            && self.flows.as_ref().is_none_or(FlowSummary::is_clean)
    }
}

impl fmt::Display for StagingReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(matrix) = &self.matrix {
            writeln!(f, "permission matrix: {matrix}")?;
        }
        if let Some(administration) = &self.admin {
            writeln!(f, "administration matrix: {administration}")?;
        }
        if let Some(flows) = &self.flows {
            writeln!(f, "client flows:\n{flows}")?;
        }
        if self.torn_down {
            writeln!(f, "the tenants of the run were deleted")?;
        }
        if let Some(problem) = &self.teardown_problem {
            writeln!(f, "the tenants of the run could not be deleted: {problem}")?;
        }
        Ok(())
    }
}

/// Runs the harness against the instance of `config`.
///
/// The world is built, the matrices run on it, each scenario runs on a world of its own (the world is built again before
/// every scenario that follows a run that changed it), and the tenants are deleted at the end unless `options.keep`.
/// The tenants are deleted also when a step fails (including the building of the world, once it has started to write), so
/// that a run that dies half way leaves nothing behind but what the operator created. A run whose tenants are not the ones it
/// was made for (the tokens belong to others, a tenant holds a principal that no run made) stops before it writes anything and
/// deletes nothing.
///
/// # Errors
///
/// [`StagingError`] when the instance cannot be prepared (the failed assertions of a run are in the report).
pub async fn run(
    config: StagingConfig,
    expectations: &Expectations,
    options: Options,
) -> Result<StagingReport, StagingError> {
    let transport: Arc<dyn Transport> = Arc::new(HttpTransport::new(config.base_url.clone())?);
    let mut deployment = match Deployment::provision_keeping_partial(config, transport, 0).await {
        Ok(deployment) => deployment.with_resets(options.reset_between_writes),
        Err(failure) => {
            let (error, partial) = *failure;
            // A failure before the run wrote anything (tokens of another tenant, a tenant that holds what the run did not make)
            // touches nothing. A later one takes down what was built, and the tenants too unless they are to stay.
            let Some(partial) = partial else {
                return Err(error);
            };
            let error = partial.abandon(error).await;
            if !options.keep {
                drop(partial.teardown().await);
            }
            return Err(error);
        }
    };
    let outcome = carry_out(&mut deployment, expectations, &options).await;
    let (torn_down, teardown_problem) = if options.keep {
        (false, None)
    } else {
        match deployment.teardown().await {
            Ok(done) => (done, None),
            Err(error) => (false, Some(error.to_string())),
        }
    };
    let mut report = outcome?;
    report.torn_down = torn_down;
    report.teardown_problem = teardown_problem;
    Ok(report)
}

async fn carry_out(
    deployment: &mut Deployment,
    expectations: &Expectations,
    options: &Options,
) -> Result<StagingReport, StagingError> {
    let mut report = StagingReport::default();
    let mut dirty = false;
    if options.matrices {
        let run_options = RunOptions {
            concurrency: 1,
            sampling: options.sampling,
            ..RunOptions::default()
        };
        report.matrix = Some(permissions::run(&*deployment, expectations, &run_options).await);
        report.admin = Some(admin::run(&*deployment, expectations, &run_options).await);
        // The matrix resets the world around the cases that change something; what it leaves is not the world it started
        // from.
        dirty = options.reset_between_writes;
    }
    if !options.flows.is_empty() {
        let mut summary = FlowSummary::default();
        for (path, scenario) in &options.flows {
            if dirty {
                *deployment = deployment.reset().await?.with_resets(options.reset_between_writes);
            }
            let env = deployment.scenario_env(options.data_dir.clone());
            let scenario_report = run_scenario(&env, scenario).await;
            dirty = true;
            summary
                .results
                .push((path.clone(), verdict(scenario, &scenario_report), scenario_report));
        }
        report.flows = Some(summary);
    }
    Ok(report)
}

impl Deployment {
    /// An environment for the client-flow runner: the transport to the instance, the credentials of every role and the
    /// variables of the world of this run (`tenant`, `login_domain`, `other_tenant`, `other_login_domain`, `base_url`).
    pub fn scenario_env(&self, data_dir: Option<PathBuf>) -> crate::flow::ScenarioEnv {
        crate::flow::ScenarioEnv::for_world(
            self.transport(),
            Arc::new(self.book.clone()),
            &self.world,
            self.config.base_url.as_str().trim_end_matches('/'),
            data_dir,
        )
    }
}
