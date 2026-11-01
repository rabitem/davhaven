//! Client-flow scenarios (YAML) and `run_scenario`.
//!
//! A scenario is the recorded or hand-written conversation of one client with the server: account discovery, a
//! PUT, a REPORT, a share, a sync after the token expired. It is a YAML file (see [`Scenario`] for the schema and
//! `docs/testing.md` for an annotated example) that names its client and feature, says whether it is `synthetic`
//! or `captured` and where it comes from, and lists steps. A step sends one templated request, captures values
//! (an `ETag`, a sync token, a `Location`), and asserts structurally: status, headers, per-href statuses of a
//! multistatus, properties, path expressions on XML ([`crate::xml`]) and JSON pointers.
//!
//! [`run_scenario`] executes a scenario through any [`Transport`], so the same file runs in process against
//! `TestApp` and over HTTP against a deployed instance. Steps run in order; after the first failing step the
//! remaining steps are skipped, because later requests depend on what earlier ones captured.
//!
//! # Templates
//!
//! `{{name}}` in a request path, a header value, a body or an expectation is replaced by a variable: the
//! variables of the [`ScenarioEnv`] (for example `tenant` and `login_domain`), then the `variables` of the
//! scenario, then everything captured so far. An unknown variable fails the step.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use davhaven_fixtures::{ActorRole, named_enum};
use serde::Deserialize;

use crate::handles::Actor;
use crate::matrix::Surface;
use crate::sample::cover;
use crate::transport::{TestRequest, TestResponse, Transport};
use crate::xml::Document;

/// The only schema version this reader accepts.
pub const SCHEMA_VERSION: u32 = 1;

named_enum! {
    /// Where a scenario comes from; the client-by-feature grid reports synthetic cells.
    pub enum Origin {
        /// Written by hand from a specification or a client's documented behaviour.
        Synthetic => "synthetic",
        /// Recorded from a real client or a deployed instance (the provenance says which).
        Captured => "captured",
    }
}

/// Problems with reading or running scenarios (not failed assertions, which are in the [`ScenarioReport`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlowError {
    /// The YAML cannot be read into the schema.
    #[error("cannot read scenario: {0}")]
    Parse(String),
    /// The scenario is well-formed YAML but violates a rule of the schema.
    #[error("invalid scenario `{scenario}`: {reason}")]
    Invalid {
        /// The scenario's name.
        scenario: String,
        /// The violated rule.
        reason: String,
    },
    /// A scenario file or directory cannot be read.
    #[error("cannot read {path}: {reason}")]
    Io {
        /// The path.
        path: String,
        /// The operating system's message.
        reason: String,
    },
    /// A `{{variable}}` has no value.
    #[error("the variable `{0}` is not defined")]
    UnknownVariable(String),
    /// A template is malformed.
    #[error("invalid template: {0}")]
    Template(String),
}

/// The expected status of a response: one code, one of several, or a class such as `2xx`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum StatusSpec {
    /// Exactly this status.
    Exact(u16),
    /// Any of these statuses.
    OneOf(Vec<u16>),
    /// A class written `Nxx`.
    Class(String),
}

impl StatusSpec {
    /// Whether `status` satisfies the specification.
    pub fn accepts(&self, status: u16) -> bool {
        match self {
            Self::Exact(expected) => *expected == status,
            Self::OneOf(options) => options.contains(&status),
            Self::Class(class) => class
                .strip_suffix("xx")
                .and_then(|digit| digit.parse::<u16>().ok())
                .is_some_and(|digit| status / 100 == digit),
        }
    }
}

impl fmt::Display for StatusSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(status) => write!(f, "{status}"),
            Self::OneOf(options) => {
                let listed: Vec<String> = options.iter().map(u16::to_string).collect();
                write!(f, "one of {}", listed.join(", "))
            }
            Self::Class(class) => f.write_str(class),
        }
    }
}

/// The request of a step.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSpec {
    /// The HTTP method, for example `PROPFIND`.
    pub method: String,
    /// The request target, an absolute path with an optional query. Templated.
    pub path: String,
    /// Additional headers. Templated values.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// The body. Templated.
    #[serde(default)]
    pub body: Option<String>,
    /// A file below the data directory of the environment (`corpus/apple-macos-weekly-override.ics`,
    /// `dav/macos-propfind-home.xml`) that is sent byte for byte as the body: it is read as bytes and not templated, so a
    /// body of a real client reaches the server as the file has it.
    #[serde(default)]
    pub body_file: Option<String>,
    /// An iCalendar object written with plain line breaks: they are sent as CRLF, with a final one, and the
    /// `Content-Type` is `text/calendar; charset=utf-8` unless the step sets one. Templated.
    #[serde(default)]
    pub ical: Option<String>,
}

/// Where a captured value comes from; exactly one source is set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSpec {
    /// A response header, for example `ETag`.
    #[serde(default)]
    pub header: Option<String>,
    /// The first match of a path on the XML body (see [`crate::xml`]); its trimmed text is captured.
    #[serde(default)]
    pub xpath: Option<String>,
    /// A JSON pointer on the JSON body; strings are captured as they are, other values as JSON text.
    #[serde(default)]
    pub json: Option<String>,
}

/// An assertion on a header.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum HeaderExpect {
    /// The header has exactly this value.
    Equals(String),
    /// The header is present or absent, equals or contains a text.
    Rule(HeaderRule),
}

/// The detailed form of a header assertion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderRule {
    /// Whether the header must be present (`true`) or absent (`false`).
    #[serde(default)]
    pub present: Option<bool>,
    /// The exact value.
    #[serde(default)]
    pub equals: Option<String>,
    /// A text the value contains.
    #[serde(default)]
    pub contains: Option<String>,
    /// A value the header must differ from (a tag that has to change). Templated.
    #[serde(default)]
    pub not_equals: Option<String>,
}

/// An assertion on a property of a multistatus response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyExpect {
    /// The `href` of the response (as sent). Templated.
    pub href: String,
    /// The property in Clark notation, for example `{DAV:}getetag`. Templated.
    pub name: String,
    /// Whether the property must be present with a 2xx status (`true`, the default) or absent.
    #[serde(default = "yes")]
    pub present: bool,
    /// The exact text of the property. Templated.
    #[serde(default)]
    pub value: Option<String>,
}

const fn yes() -> bool {
    true
}

/// An assertion on a path of the XML body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XPathExpect {
    /// The path (see [`crate::xml`]). Templated.
    pub path: String,
    /// The exact number of matches. Without it (and without `equals` and `contains`) at least one match is
    /// required.
    #[serde(default)]
    pub count: Option<usize>,
    /// Some match has exactly this trimmed text. Templated.
    #[serde(default)]
    pub equals: Option<String>,
    /// Some match contains this text. Templated.
    #[serde(default)]
    pub contains: Option<String>,
    /// No match has exactly this trimmed text (a value that has to differ from an earlier one). Templated.
    #[serde(default)]
    pub not_equals: Option<String>,
}

/// An assertion on a JSON pointer of the body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonExpect {
    /// The JSON pointer, for example `/items/0/id`.
    pub pointer: String,
    /// Whether the value must be present (`true`, the default) or absent.
    #[serde(default = "yes")]
    pub present: bool,
    /// The value as text (strings as they are, other values as JSON text). Templated.
    #[serde(default)]
    pub equals: Option<String>,
}

/// What a step asserts about the response. Everything that is left out is not checked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    /// The status.
    #[serde(default)]
    pub status: Option<StatusSpec>,
    /// Headers by name.
    #[serde(default)]
    pub headers: BTreeMap<String, HeaderExpect>,
    /// The status of each `href` of a multistatus (a response status or one of its propstat statuses).
    #[serde(default)]
    pub statuses: BTreeMap<String, u16>,
    /// Properties of multistatus responses.
    #[serde(default)]
    pub properties: Vec<PropertyExpect>,
    /// Paths on the XML body.
    #[serde(default)]
    pub xpath: Vec<XPathExpect>,
    /// Pointers on the JSON body.
    #[serde(default)]
    pub json: Vec<JsonExpect>,
    /// Texts the body contains. Templated.
    #[serde(default)]
    pub body_contains: Vec<String>,
    /// Texts the body does not contain. Templated.
    #[serde(default)]
    pub body_excludes: Vec<String>,
    /// Texts the body contains once the line folding of iCalendar is undone (a server that rewrites an object folds its
    /// lines at 75 octets, so where a property is cut is not the client's business). Templated.
    #[serde(default)]
    pub ical_contains: Vec<String>,
    /// Texts the body does not contain once the line folding of iCalendar is undone. Templated.
    #[serde(default)]
    pub ical_excludes: Vec<String>,
}

/// One request and its assertions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// What the step does, for reports.
    pub name: String,
    /// The logical actor (a key of the scenario's `actors`) that sends the request; without one the request is
    /// anonymous.
    #[serde(rename = "as", default)]
    pub actor: Option<String>,
    /// The surface the request goes to (selects the credential of the actor); `dav` by default.
    #[serde(default = "dav")]
    pub surface: Surface,
    /// The request.
    pub request: RequestSpec,
    /// Values to capture from the response, by variable name.
    #[serde(default)]
    pub capture: BTreeMap<String, CaptureSpec>,
    /// The assertions.
    #[serde(default)]
    pub expect: Expect,
}

const fn dav() -> Surface {
    Surface::Dav
}

/// A client-flow scenario.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Must be [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// A unique, human readable name.
    pub name: String,
    /// What the scenario shows.
    #[serde(default)]
    pub description: Option<String>,
    /// The client the flow belongs to, for example `apple-calendar`, `davx5`, `thunderbird`, `python-caldav`.
    pub client: String,
    /// The feature of the client-by-feature grid, for example `account-setup`, `crud`, `invite-internal`.
    pub feature: String,
    /// Synthetic or captured.
    pub origin: Origin,
    /// Where the scenario comes from: the script of ccs-caldavtester, the functional test of python caldav, the
    /// date and source of a capture.
    pub provenance: String,
    /// The logical actors of the scenario, each a role of the fixture world.
    #[serde(default)]
    pub actors: BTreeMap<String, ActorRole>,
    /// Variables available to templates.
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    /// A reason why the scenario is expected to fail today: the server deviates from what the client needs, and the
    /// deviation is tracked elsewhere. The scenario still states what the client needs; a run of a scenario with a
    /// known issue passes when it fails and **fails when it passes**, so a fixed deviation does not stay listed.
    #[serde(default)]
    pub known_issue: Option<String>,
    /// The steps, in order.
    pub steps: Vec<Step>,
}

impl Scenario {
    /// Reads a scenario from YAML and validates it.
    ///
    /// # Errors
    ///
    /// [`FlowError::Parse`] when the text does not match the schema, [`FlowError::Invalid`] when it violates a rule
    /// of the schema (see [`Scenario::validate`]).
    pub fn from_yaml(text: &str) -> Result<Self, FlowError> {
        let scenario: Self = serde_saphyr::from_str(text).map_err(|error| FlowError::Parse(error.to_string()))?;
        scenario.validate()?;
        Ok(scenario)
    }

    /// Checks the rules the types cannot express: the schema version, a name, a provenance and at least one step;
    /// unique step names; every step actor is declared; every capture has exactly one source; every method is a
    /// valid token and every path is an absolute path.
    ///
    /// # Errors
    ///
    /// [`FlowError::Invalid`] naming the first violated rule.
    pub fn validate(&self) -> Result<(), FlowError> {
        let invalid = |reason: String| FlowError::Invalid {
            scenario: self.name.clone(),
            reason,
        };
        if self.schema_version != SCHEMA_VERSION {
            return Err(invalid(format!(
                "schema_version is {}, this harness reads {SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.name.trim().is_empty() || self.client.trim().is_empty() || self.feature.trim().is_empty() {
            return Err(invalid("name, client and feature must not be empty".to_owned()));
        }
        if self.provenance.trim().is_empty() {
            return Err(invalid(
                "the provenance must say where the scenario comes from".to_owned(),
            ));
        }
        if self.steps.is_empty() {
            return Err(invalid("a scenario needs at least one step".to_owned()));
        }
        let mut names = BTreeSet::new();
        for step in &self.steps {
            if !names.insert(step.name.as_str()) {
                return Err(invalid(format!("the step name `{}` is used twice", step.name)));
            }
            if let Some(actor) = &step.actor
                && !self.actors.contains_key(actor)
            {
                return Err(invalid(format!(
                    "step `{}` acts as `{actor}`, which is not in `actors`",
                    step.name
                )));
            }
            if http::Method::from_bytes(step.request.method.as_bytes()).is_err() {
                return Err(invalid(format!(
                    "step `{}` has the invalid method `{}`",
                    step.name, step.request.method
                )));
            }
            if !step.request.path.starts_with('/') && !step.request.path.starts_with("{{") {
                return Err(invalid(format!("step `{}` has a path that is not absolute", step.name)));
            }
            let bodies = [
                step.request.body.is_some(),
                step.request.body_file.is_some(),
                step.request.ical.is_some(),
            ];
            if bodies.iter().filter(|set| **set).count() > 1 {
                return Err(invalid(format!(
                    "step `{}` sets more than one of body, body_file and ical",
                    step.name
                )));
            }
            if let Some(file) = &step.request.body_file
                && (file.starts_with('/') || file.split('/').any(|part| part == ".." || part.is_empty()))
            {
                return Err(invalid(format!(
                    "step `{}` names the body file `{file}`, which is not a relative path below the data directory",
                    step.name
                )));
            }
            for (name, capture) in &step.capture {
                let sources = [&capture.header, &capture.xpath, &capture.json]
                    .iter()
                    .filter(|source| source.is_some())
                    .count();
                if sources != 1 {
                    return Err(invalid(format!(
                        "capture `{name}` of step `{}` needs exactly one of header, xpath and json",
                        step.name
                    )));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Loading and the client-by-feature grid
// ---------------------------------------------------------------------------------------------------------------

/// Reads every `*.yaml` and `*.yml` file below `dir` (recursively, in path order) as a scenario.
///
/// # Errors
///
/// [`FlowError::Io`] when a directory or file cannot be read, and the error of [`Scenario::from_yaml`] (with the file
/// name prepended) for a file that is not a valid scenario.
pub fn load_scenarios(dir: &Path) -> Result<Vec<(PathBuf, Scenario)>, FlowError> {
    let mut files = Vec::new();
    collect_files(dir, &mut files)?;
    files.sort();
    let mut scenarios = Vec::with_capacity(files.len());
    for file in files {
        let text = std::fs::read_to_string(&file).map_err(|error| FlowError::Io {
            path: file.display().to_string(),
            reason: error.to_string(),
        })?;
        let scenario = Scenario::from_yaml(&text).map_err(|error| match error {
            FlowError::Parse(reason) => FlowError::Parse(format!("{}: {reason}", file.display())),
            other => other,
        })?;
        scenarios.push((file, scenario));
    }
    Ok(scenarios)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), FlowError> {
    let io = |error: std::io::Error| FlowError::Io {
        path: dir.display().to_string(),
        reason: error.to_string(),
    };
    for entry in std::fs::read_dir(dir).map_err(io)? {
        let path = entry.map_err(io)?.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "yaml" || extension == "yml")
        {
            out.push(path);
        }
    }
    Ok(())
}

/// How many scenarios cover one cell of the client-by-feature grid.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GridCell {
    /// Scenarios written by hand.
    pub synthetic: usize,
    /// Scenarios recorded from real clients.
    pub captured: usize,
}

/// The client-by-feature grid of a set of scenarios (PLAN 3.4): CI reports the cells that only have synthetic
/// scenarios, because those are the ones not yet confirmed by a real client.
pub fn grid<'a>(scenarios: impl IntoIterator<Item = &'a Scenario>) -> BTreeMap<(String, String), GridCell> {
    let mut cells: BTreeMap<(String, String), GridCell> = BTreeMap::new();
    for scenario in scenarios {
        let cell = cells
            .entry((scenario.client.clone(), scenario.feature.clone()))
            .or_default();
        match scenario.origin {
            Origin::Synthetic => cell.synthetic += 1,
            Origin::Captured => cell.captured += 1,
        }
    }
    cells
}

/// A representative set of scenarios: few, and between them every client and every feature at least once.
///
/// A scenario on PostgreSQL runs in a world of its own, which costs seconds there, so pull requests run this set and the
/// nightly run all of them. The set is chosen greedily (`sample::cover`) from the scenarios in the order of their
/// names, so the same scenarios are chosen whatever the order they are given in, and it is in the order of the names.
pub fn representative<'a>(scenarios: impl IntoIterator<Item = &'a Scenario>) -> Vec<&'a Scenario> {
    let mut by_name: Vec<&Scenario> = scenarios.into_iter().collect();
    by_name.sort_by(|a, b| a.name.cmp(&b.name));
    cover(&by_name, |scenario| {
        vec![
            format!("client {}", scenario.client),
            format!("feature {}", scenario.feature),
        ]
    })
    .into_iter()
    .copied()
    .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------------------------------

/// Gives the credentials of a role on a surface, or `None` when the role has none there.
pub type CredentialResolver = Arc<dyn Fn(ActorRole, Surface) -> Option<Actor> + Send + Sync>;

/// What a scenario runs against: a transport, the credentials of the actors and the base variables.
#[derive(Clone)]
pub struct ScenarioEnv {
    transport: Arc<dyn Transport>,
    credentials: CredentialResolver,
    variables: BTreeMap<String, String>,
    data_dir: Option<PathBuf>,
}

impl fmt::Debug for ScenarioEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScenarioEnv")
            .field("variables", &self.variables.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ScenarioEnv {
    /// An environment that sends through `transport` and takes credentials from `credentials`.
    pub fn new(transport: Arc<dyn Transport>, credentials: CredentialResolver) -> Self {
        Self {
            transport,
            credentials,
            variables: BTreeMap::new(),
            data_dir: None,
        }
    }

    /// An environment for the roles of `world`: the credentials come from `book`, and the variables are those the scenarios of
    /// the repository use (`tenant`, `login_domain`, `other_tenant`, `other_login_domain`, `base_url`). `body_file`s are read
    /// from `data_dir`, the `testdata` directory of the repository when it is `None`.
    pub fn for_world(
        transport: Arc<dyn Transport>,
        book: Arc<crate::credentials::CredentialBook>,
        world: &davhaven_fixtures::FixtureWorld,
        base_url: &str,
        data_dir: Option<PathBuf>,
    ) -> Self {
        let credentials: CredentialResolver = Arc::new(move |role, surface| book.actor(role, surface, None));
        Self::new(transport, credentials)
            .with_variable("tenant", &world.names.tenant)
            .with_variable("login_domain", &world.names.login_domain)
            .with_variable("other_tenant", &world.names.other_tenant)
            .with_variable("other_login_domain", &world.names.other_login_domain)
            .with_variable("base_url", base_url)
            .with_data_dir(data_dir.unwrap_or_else(davhaven_fixtures::corpus::data_dir))
    }

    /// Sets the directory that `body_file` is read from (the `testdata` directory of the repository).
    #[must_use]
    pub fn with_data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    /// Defines a variable for the templates of every scenario.
    #[must_use]
    pub fn with_variable(mut self, name: &str, value: &str) -> Self {
        self.variables.insert(name.to_owned(), value.to_owned());
        self
    }
}

/// How a step ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// The request was sent and every assertion held.
    Passed,
    /// The step failed; the texts say why.
    Failed(Vec<String>),
    /// An earlier step failed, so this one did not run.
    Skipped,
}

/// The result of one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// The name of the step.
    pub name: String,
    /// How it ended.
    pub outcome: StepOutcome,
}

/// The result of running a scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioReport {
    /// The name of the scenario.
    pub scenario: String,
    /// Whether the scenario is synthetic or captured.
    pub origin: Origin,
    /// One report per step, in order.
    pub steps: Vec<StepReport>,
}

impl ScenarioReport {
    /// Whether every step passed.
    pub fn is_success(&self) -> bool {
        self.steps.iter().all(|step| step.outcome == StepOutcome::Passed)
    }

    /// Every failure text, prefixed with the step.
    pub fn failures(&self) -> Vec<String> {
        self.steps
            .iter()
            .filter_map(|step| match &step.outcome {
                StepOutcome::Failed(reasons) => Some(
                    reasons
                        .iter()
                        .map(|reason| format!("step `{}`: {reason}", step.name))
                        .collect::<Vec<_>>(),
                ),
                StepOutcome::Passed | StepOutcome::Skipped => None,
            })
            .flatten()
            .collect()
    }
}

impl fmt::Display for ScenarioReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verdict = if self.is_success() { "passed" } else { "FAILED" };
        writeln!(f, "scenario `{}` ({}): {verdict}", self.scenario, self.origin)?;
        for step in &self.steps {
            match &step.outcome {
                StepOutcome::Passed => writeln!(f, "  ok       {}", step.name)?,
                StepOutcome::Skipped => writeln!(f, "  skipped  {}", step.name)?,
                StepOutcome::Failed(reasons) => {
                    writeln!(f, "  FAILED   {}", step.name)?;
                    for reason in reasons {
                        writeln!(f, "             - {reason}")?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// What a scenario has to do on a given run: pass, or fail the way its `known_issue` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowVerdict {
    /// The scenario has no known issue and passed.
    Passed,
    /// The scenario failed and the failure is its documented `known_issue`.
    KnownIssue(String),
    /// The scenario passed although it documents a `known_issue`: the deviation is fixed and the line is to be removed.
    KnownIssueFixed(String),
    /// The scenario failed without a known issue.
    Failed,
}

/// Judges the report of a scenario against its `known_issue`: a run of a scenario with a known issue passes when it fails and
/// fails when it passes, so that a fixed deviation does not stay listed.
pub fn verdict(scenario: &Scenario, report: &ScenarioReport) -> FlowVerdict {
    match (&scenario.known_issue, report.is_success()) {
        (None, true) => FlowVerdict::Passed,
        (None, false) => FlowVerdict::Failed,
        (Some(reason), false) => FlowVerdict::KnownIssue(reason.clone()),
        (Some(reason), true) => FlowVerdict::KnownIssueFixed(reason.clone()),
    }
}

/// Runs a scenario against `env`.
///
/// The scenario is run as it is: call [`Scenario::validate`] (or read it with [`Scenario::from_yaml`], which does)
/// first. Failures of any kind (an unknown variable, a missing credential, a transport error, a violated
/// assertion) are reported in the [`ScenarioReport`]; this function itself does not fail.
pub async fn run_scenario(env: &ScenarioEnv, scenario: &Scenario) -> ScenarioReport {
    // The variables of a scenario may use the variables of the environment, but not each other.
    let mut variables = env.variables.clone();
    let mut setup_error = None;
    for (name, value) in &scenario.variables {
        match render(value, &env.variables) {
            Ok(rendered) => {
                variables.insert(name.clone(), rendered);
            }
            Err(error) => {
                setup_error.get_or_insert(error);
            }
        }
    }
    let mut steps = Vec::with_capacity(scenario.steps.len());
    let mut failed = false;
    for step in &scenario.steps {
        let outcome = if failed {
            StepOutcome::Skipped
        } else if let Some(error) = &setup_error {
            StepOutcome::Failed(vec![format!("the variables of the scenario: {error}")])
        } else {
            match run_step(env, scenario, step, &mut variables).await {
                Ok(failures) if failures.is_empty() => StepOutcome::Passed,
                Ok(failures) => StepOutcome::Failed(failures),
                Err(error) => StepOutcome::Failed(vec![error.to_string()]),
            }
        };
        failed |= matches!(outcome, StepOutcome::Failed(_));
        steps.push(StepReport {
            name: step.name.clone(),
            outcome,
        });
    }
    ScenarioReport {
        scenario: scenario.name.clone(),
        origin: scenario.origin,
        steps,
    }
}

/// Replaces `{{name}}` by the variable `name`.
fn render(template: &str, variables: &BTreeMap<String, String>) -> Result<String, FlowError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(rest.get(..start).unwrap_or(""));
        let after = rest.get(start + 2..).unwrap_or("");
        let Some(end) = after.find("}}") else {
            return Err(FlowError::Template(format!("`{{{{` is not closed in `{template}`")));
        };
        let name = after.get(..end).unwrap_or("").trim();
        let value = variables
            .get(name)
            .ok_or_else(|| FlowError::UnknownVariable(name.to_owned()))?;
        out.push_str(value);
        rest = after.get(end + 2..).unwrap_or("");
    }
    out.push_str(rest);
    Ok(out)
}

/// Sends the request of a step, captures values and checks the assertions; returns the failed assertions.
async fn run_step(
    env: &ScenarioEnv,
    scenario: &Scenario,
    step: &Step,
    variables: &mut BTreeMap<String, String>,
) -> Result<Vec<String>, StepError> {
    let actor = match &step.actor {
        None => Actor::Anonymous,
        Some(name) => {
            let role = scenario
                .actors
                .get(name)
                .ok_or_else(|| StepError::Message(format!("the actor `{name}` is not declared")))?;
            (env.credentials)(*role, step.surface).ok_or_else(|| {
                StepError::Message(format!(
                    "the role `{role}` has no credential on the surface `{}`",
                    step.surface
                ))
            })?
        }
    };

    let path = render(&step.request.path, variables)?;
    let mut request = TestRequest::new(&step.request.method, path);
    if let Some(authorization) = actor.authorization() {
        request = request.header("authorization", &authorization);
    }
    for (name, value) in &step.request.headers {
        request = request.header(name, &render(value, variables)?);
    }
    if let Some(body) = &step.request.body {
        request = request.body(render(body, variables)?);
    }
    if let Some(file) = &step.request.body_file {
        let dir = env.data_dir.as_ref().ok_or_else(|| {
            StepError::Message("the step has a body file, but the environment has no data directory".to_owned())
        })?;
        let bytes = std::fs::read(dir.join(file))
            .map_err(|error| StepError::Message(format!("cannot read the body file `{file}`: {error}")))?;
        request = request.body(bytes);
    }
    if let Some(ical) = &step.request.ical {
        let text = render(ical, variables)?;
        let mut crlf = String::with_capacity(text.len() + 16);
        for line in text.lines() {
            crlf.push_str(line);
            crlf.push_str("\r\n");
        }
        if !step
            .request
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-type"))
        {
            request = request.header("content-type", "text/calendar; charset=utf-8");
        }
        request = request.body(crlf);
    }
    let response = env.transport.send(request).await?;

    for (name, spec) in &step.capture {
        let value =
            capture(spec, &response).map_err(|reason| StepError::Message(format!("capture `{name}`: {reason}")))?;
        variables.insert(name.clone(), value);
    }
    check(&step.expect, &response, variables)
}

/// Why a step could not run to its assertions.
#[derive(Debug, thiserror::Error)]
enum StepError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Flow(#[from] FlowError),
    #[error("transport: {0}")]
    Transport(#[from] crate::transport::TransportError),
}

/// Reads one captured value out of a response.
fn capture(spec: &CaptureSpec, response: &TestResponse) -> Result<String, String> {
    if let Some(header) = &spec.header {
        return response
            .header(header)
            .map(str::to_owned)
            .ok_or_else(|| format!("the response has no `{header}` header"));
    }
    if let Some(path) = &spec.xpath {
        let document = Document::parse(&response.text()).map_err(|error| error.to_string())?;
        return document
            .select(path)
            .map_err(|error| error.to_string())?
            .into_iter()
            .next()
            .map(|value| value.trim().to_owned())
            .ok_or_else(|| format!("the path `{path}` matches nothing"));
    }
    if let Some(pointer) = &spec.json {
        let value: serde_json::Value = response.json().map_err(|error| error.to_string())?;
        return value
            .pointer(pointer)
            .map(json_text)
            .ok_or_else(|| format!("the pointer `{pointer}` matches nothing"));
    }
    Err("no source".to_owned())
}

fn json_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Checks every assertion of `expect` and returns the violated ones.
fn check(
    expect: &Expect,
    response: &TestResponse,
    variables: &BTreeMap<String, String>,
) -> Result<Vec<String>, StepError> {
    let mut failures = Vec::new();
    if let Some(spec) = &expect.status
        && !spec.accepts(response.status.as_u16())
    {
        failures.push(format!("expected status {spec}, got {}", response.status.as_u16()));
    }
    for (name, rule) in &expect.headers {
        check_header(name, rule, response, variables, &mut failures)?;
    }
    let text = response.text();
    for needle in &expect.body_contains {
        let needle = render(needle, variables)?;
        if !text.contains(&needle) {
            failures.push(format!("the body does not contain `{needle}`"));
        }
    }
    for needle in &expect.body_excludes {
        let needle = render(needle, variables)?;
        if text.contains(&needle) {
            failures.push(format!("the body contains `{needle}`"));
        }
    }
    if !expect.ical_contains.is_empty() || !expect.ical_excludes.is_empty() {
        let unfolded = text
            .replace("\r\n ", "")
            .replace("\r\n\t", "")
            .replace("\n ", "")
            .replace("\n\t", "");
        for needle in &expect.ical_contains {
            let needle = render(needle, variables)?;
            if !unfolded.contains(&needle) {
                failures.push(format!("the iCalendar text does not contain `{needle}`"));
            }
        }
        for needle in &expect.ical_excludes {
            let needle = render(needle, variables)?;
            if unfolded.contains(&needle) {
                failures.push(format!("the iCalendar text contains `{needle}`"));
            }
        }
    }
    if !expect.statuses.is_empty() || !expect.properties.is_empty() || !expect.xpath.is_empty() {
        check_xml(expect, &text, variables, &mut failures)?;
    }
    if !expect.json.is_empty() {
        check_json(&expect.json, response, variables, &mut failures)?;
    }
    if !response.body.is_empty()
        && let Some(last) = failures.last_mut()
    {
        // What the server answered, so that a failed assertion can be understood from the report alone.
        let shown: String = text
            .replace("\r\n", "\\r\\n")
            .replace('\n', "\\n")
            .chars()
            .take(600)
            .collect();
        last.push_str(" (the response was ");
        last.push_str(&response.status.as_u16().to_string());
        last.push_str(": ");
        last.push_str(&shown);
        last.push(')');
    }
    Ok(failures)
}

fn check_header(
    name: &str,
    rule: &HeaderExpect,
    response: &TestResponse,
    variables: &BTreeMap<String, String>,
    failures: &mut Vec<String>,
) -> Result<(), StepError> {
    let (present, equals, contains, not_equals) = match rule {
        HeaderExpect::Equals(value) => (None, Some(value), None, None),
        HeaderExpect::Rule(rule) => (
            rule.present,
            rule.equals.as_ref(),
            rule.contains.as_ref(),
            rule.not_equals.as_ref(),
        ),
    };
    // A rule that says nothing about presence wants the header to be there.
    match (response.header(name), present) {
        (None, Some(false)) => {}
        (None, _) => failures.push(format!("the header `{name}` is missing")),
        (Some(value), Some(false)) => failures.push(format!("the header `{name}` is present with `{value}`")),
        (Some(actual), _) => {
            if let Some(expected) = equals {
                let expected = render(expected, variables)?;
                if actual != expected {
                    failures.push(format!("the header `{name}` is `{actual}`, expected `{expected}`"));
                }
            }
            if let Some(needle) = contains {
                let needle = render(needle, variables)?;
                if !actual.contains(&needle) {
                    failures.push(format!(
                        "the header `{name}` is `{actual}`, which does not contain `{needle}`"
                    ));
                }
            }
            if let Some(unwanted) = not_equals {
                let unwanted = render(unwanted, variables)?;
                if actual == unwanted {
                    failures.push(format!("the header `{name}` is `{actual}`, which it must not be"));
                }
            }
        }
    }
    Ok(())
}

fn check_xml(
    expect: &Expect,
    text: &str,
    variables: &BTreeMap<String, String>,
    failures: &mut Vec<String>,
) -> Result<(), StepError> {
    let document = match Document::parse(text) {
        Ok(document) => document,
        Err(error) => {
            failures.push(format!("the body is not XML: {error}"));
            return Ok(());
        }
    };
    if !expect.statuses.is_empty() || !expect.properties.is_empty() {
        match document.multistatus() {
            Ok(entries) => {
                for (href, status) in &expect.statuses {
                    let href = render(href, variables)?;
                    match entries.iter().find(|entry| entry.href == href) {
                        Some(entry) if entry.has_status(*status) => {}
                        Some(_) => failures.push(format!("`{href}` does not have the status {status}")),
                        None => failures.push(format!("the multistatus has no response for `{href}`")),
                    }
                }
                for property in &expect.properties {
                    let href = render(&property.href, variables)?;
                    let name = render(&property.name, variables)?;
                    let Some(entry) = entries.iter().find(|entry| entry.href == href) else {
                        failures.push(format!("the multistatus has no response for `{href}`"));
                        continue;
                    };
                    match (entry.property(&name), property.present) {
                        (Some(_), false) => failures.push(format!("`{href}` has the property `{name}`")),
                        (None, true) => failures.push(format!("`{href}` lacks the property `{name}`")),
                        (Some(actual), true) => {
                            if let Some(expected) = &property.value {
                                let expected = render(expected, variables)?;
                                if actual.trim() != expected {
                                    failures.push(format!(
                                        "`{href}` has {name} = `{}`, expected `{expected}`",
                                        actual.trim()
                                    ));
                                }
                            }
                        }
                        (None, false) => {}
                    }
                }
            }
            Err(error) => failures.push(error.to_string()),
        }
    }
    for expectation in &expect.xpath {
        let path = render(&expectation.path, variables)?;
        let values = match document.select(&path) {
            Ok(values) => values,
            Err(error) => {
                failures.push(error.to_string());
                continue;
            }
        };
        if let Some(count) = expectation.count {
            if values.len() != count {
                failures.push(format!("`{path}` matches {} times, expected {count}", values.len()));
            }
        } else if expectation.equals.is_none() && expectation.contains.is_none() && values.is_empty() {
            failures.push(format!("`{path}` matches nothing"));
        }
        if let Some(expected) = &expectation.equals {
            let expected = render(expected, variables)?;
            if !values.iter().any(|value| value.trim() == expected) {
                failures.push(format!("no match of `{path}` equals `{expected}` (found {values:?})"));
            }
        }
        if let Some(needle) = &expectation.contains {
            let needle = render(needle, variables)?;
            if !values.iter().any(|value| value.contains(&needle)) {
                failures.push(format!("no match of `{path}` contains `{needle}` (found {values:?})"));
            }
        }
        if let Some(unwanted) = &expectation.not_equals {
            let unwanted = render(unwanted, variables)?;
            if values.iter().any(|value| value.trim() == unwanted) {
                failures.push(format!("a match of `{path}` equals `{unwanted}`, which it must not"));
            }
        }
    }
    Ok(())
}

fn check_json(
    expectations: &[JsonExpect],
    response: &TestResponse,
    variables: &BTreeMap<String, String>,
    failures: &mut Vec<String>,
) -> Result<(), StepError> {
    let value: serde_json::Value = match response.json() {
        Ok(value) => value,
        Err(error) => {
            failures.push(format!("the body is not JSON: {error}"));
            return Ok(());
        }
    };
    for expectation in expectations {
        let found = value.pointer(&expectation.pointer);
        match (found, expectation.present) {
            (None, true) => failures.push(format!("the pointer `{}` matches nothing", expectation.pointer)),
            (Some(_), false) => failures.push(format!("the pointer `{}` matches a value", expectation.pointer)),
            (Some(actual), true) => {
                if let Some(expected) = &expectation.equals {
                    let expected = render(expected, variables)?;
                    if json_text(actual) != expected {
                        failures.push(format!(
                            "`{}` is `{}`, expected `{expected}`",
                            expectation.pointer,
                            json_text(actual)
                        ));
                    }
                }
            }
            (None, false) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{FnTransport, TransportError};

    const SCENARIO: &str = r#"
schema_version: 1
name: discover-and-store
description: Finds the principal, then stores and reads back an event.
client: python-caldav
feature: crud
origin: synthetic
provenance: written from RFC 4791 section 5.3.2; no capture yet
actors:
  olivia: owner
variables:
  home: /dav/calendars/{{tenant}}/olivia/personal
steps:
  - name: discover
    as: olivia
    request:
      method: PROPFIND
      path: /dav/
      headers:
        Depth: "0"
      body: "<propfind xmlns='DAV:'><prop><current-user-principal/></prop></propfind>"
    expect:
      status: 207
      headers:
        content-type:
          contains: xml
      xpath:
        - path: "/{DAV:}multistatus/{DAV:}response"
          count: 1
  - name: store
    as: olivia
    request:
      method: PUT
      path: "{{home}}/new.ics"
      headers:
        Content-Type: text/calendar
        If-None-Match: "*"
      body: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"
    capture:
      etag:
        header: ETag
    expect:
      status: [201, 204]
      headers:
        etag: {}
  - name: read back
    as: olivia
    request:
      method: GET
      path: "{{home}}/new.ics"
    expect:
      status: 200
      headers:
        etag: "{{etag}}"
      body_contains: ["VCALENDAR"]
      body_excludes: ["SECRET"]
"#;

    #[test]
    fn scenarios_parse_from_yaml_and_validate() {
        let scenario = Scenario::from_yaml(SCENARIO).unwrap();
        assert_eq!(scenario.name, "discover-and-store");
        assert_eq!(scenario.origin, Origin::Synthetic);
        assert_eq!(scenario.actors["olivia"], ActorRole::Owner);
        assert_eq!(scenario.steps.len(), 3);
        assert_eq!(scenario.steps[0].surface, Surface::Dav);
        assert_eq!(scenario.steps[0].expect.status, Some(StatusSpec::Exact(207)));
        assert_eq!(scenario.steps[1].expect.status, Some(StatusSpec::OneOf(vec![201, 204])));
        assert_eq!(scenario.steps[1].capture["etag"].header.as_deref(), Some("ETag"));
        assert!(scenario.steps[2].expect.body_excludes.contains(&"SECRET".to_owned()));
    }

    fn broken(replace: &str, with: &str) -> FlowError {
        Scenario::from_yaml(&SCENARIO.replace(replace, with)).unwrap_err()
    }

    #[test]
    fn invalid_scenarios_are_rejected_with_a_reason() {
        assert!(matches!(
            Scenario::from_yaml("not: [a scenario"),
            Err(FlowError::Parse(_))
        ));
        assert!(matches!(
            broken("origin: synthetic", "origin: invented"),
            FlowError::Parse(_)
        ));
        assert!(matches!(
            broken("client: python-caldav", "client: python-caldav\nextra: 1"),
            FlowError::Parse(_)
        ));
        let reason = |error: FlowError| match error {
            FlowError::Invalid { reason, .. } => reason,
            other => panic!("{other}"),
        };
        assert!(reason(broken("schema_version: 1", "schema_version: 2")).contains("schema_version"));
        assert!(
            reason(broken(
                "provenance: written from RFC 4791 section 5.3.2; no capture yet",
                "provenance: ' '"
            ))
            .contains("provenance")
        );
        assert!(reason(broken("name: store", "name: discover")).contains("twice"));
        assert!(
            reason(broken(
                "    as: olivia\n    request:\n      method: GET",
                "    as: nobody\n    request:\n      method: GET"
            ))
            .contains("nobody")
        );
        assert!(reason(broken("method: GET", "method: 'NOT A METHOD'")).contains("invalid method"));
        assert!(reason(broken("path: /dav/\n", "path: dav/\n")).contains("absolute"));
        assert!(
            reason(broken(
                "      etag:\n        header: ETag",
                "      etag:\n        header: ETag\n        json: /x"
            ))
            .contains("exactly one")
        );
        assert!(reason(broken("      etag:\n        header: ETag", "      etag: {}")).contains("exactly one"));
    }

    #[test]
    fn statuses_headers_and_templates_work() {
        assert!(StatusSpec::Exact(207).accepts(207) && !StatusSpec::Exact(207).accepts(200));
        assert!(StatusSpec::OneOf(vec![201, 204]).accepts(204));
        assert!(StatusSpec::Class("2xx".to_owned()).accepts(299) && !StatusSpec::Class("2xx".to_owned()).accepts(300));
        assert!(!StatusSpec::Class("zz".to_owned()).accepts(200));
        assert_eq!(StatusSpec::OneOf(vec![1, 2]).to_string(), "one of 1, 2");
        let variables = BTreeMap::from([("a".to_owned(), "1".to_owned())]);
        assert_eq!(render("x{{a}}y{{ a }}", &variables).unwrap(), "x1y1");
        assert_eq!(render("no variables", &variables).unwrap(), "no variables");
        assert_eq!(
            render("{{b}}", &variables),
            Err(FlowError::UnknownVariable("b".to_owned()))
        );
        assert!(render("{{a", &variables).is_err());
    }

    /// A server with one calendar object: PROPFIND answers a multistatus, PUT stores, GET returns it.
    fn server() -> Arc<dyn Transport> {
        let stored = Arc::new(std::sync::atomic::AtomicBool::new(false));
        Arc::new(FnTransport::new(move |request: &TestRequest| {
            let authorized = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Basic "));
            if !authorized {
                return Ok(TestResponse::new(401, ""));
            }
            Ok(match (request.method.as_str(), request.target.as_str()) {
                ("PROPFIND", "/dav/") => TestResponse::new(
                    207,
                    r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/principals/acme/olivia/</D:href></D:response></D:multistatus>"#,
                )
                .with_header("content-type", "application/xml; charset=utf-8"),
                ("PUT", "/dav/calendars/acme/olivia/personal/new.ics") => {
                    stored.store(true, std::sync::atomic::Ordering::SeqCst);
                    TestResponse::new(201, "").with_header("etag", "\"abc123\"")
                }
                ("GET", "/dav/calendars/acme/olivia/personal/new.ics")
                    if stored.load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    TestResponse::new(200, "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").with_header("etag", "\"abc123\"")
                }
                _ => TestResponse::new(404, ""),
            })
        }))
    }

    fn env(transport: Arc<dyn Transport>) -> ScenarioEnv {
        let credentials: CredentialResolver = Arc::new(|role, surface| {
            (role == ActorRole::Owner && surface == Surface::Dav).then(|| Actor::basic("olivia@acme.example", "pw"))
        });
        ScenarioEnv::new(transport, credentials).with_variable("tenant", "acme")
    }

    #[tokio::test]
    async fn a_scenario_runs_captures_and_asserts_through_the_transport() {
        let scenario = Scenario::from_yaml(SCENARIO).unwrap();
        let report = run_scenario(&env(server()), &scenario).await;
        assert!(report.is_success(), "{report}");
        assert_eq!(report.steps.len(), 3);
        assert_eq!(report.failures(), Vec::<String>::new());
        assert!(report.to_string().contains("passed"));
    }

    #[tokio::test]
    async fn a_failing_step_is_reported_and_the_rest_is_skipped() {
        let mut scenario = Scenario::from_yaml(SCENARIO).unwrap();
        scenario.steps[0].expect.status = Some(StatusSpec::Exact(200));
        scenario.steps[0].expect.xpath[0].count = Some(2);
        let report = run_scenario(&env(server()), &scenario).await;
        assert!(!report.is_success());
        let failures = report.failures();
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(failures[0].contains("expected status 200, got 207"), "{failures:?}");
        assert!(failures[1].contains("matches 1 times, expected 2"), "{failures:?}");
        assert_eq!(report.steps[1].outcome, StepOutcome::Skipped);
        assert_eq!(report.steps[2].outcome, StepOutcome::Skipped);
        assert!(report.to_string().contains("FAILED") && report.to_string().contains("skipped"));
    }

    #[tokio::test]
    async fn missing_credentials_unknown_variables_and_transport_errors_fail_the_step() {
        let scenario = Scenario::from_yaml(SCENARIO).unwrap();
        let nobody: CredentialResolver = Arc::new(|_, _| None);
        let report = run_scenario(
            &ScenarioEnv::new(server(), nobody).with_variable("tenant", "acme"),
            &scenario,
        )
        .await;
        assert!(
            report.failures()[0].contains("has no credential"),
            "{:?}",
            report.failures()
        );

        let without_tenant = ScenarioEnv::new(server(), Arc::new(|_, _| Some(Actor::basic("a", "b"))));
        let report = run_scenario(&without_tenant, &scenario).await;
        assert!(
            report.failures()[0].contains("`tenant` is not defined"),
            "{:?}",
            report.failures()
        );

        let unreachable: Arc<dyn Transport> = Arc::new(FnTransport::new(|_: &TestRequest| {
            Err(TransportError::Connection("refused".to_owned()))
        }));
        let report = run_scenario(&env(unreachable), &scenario).await;
        assert!(report.failures()[0].contains("refused"), "{:?}", report.failures());
    }

    #[tokio::test]
    async fn captures_read_headers_paths_and_pointers_and_assertions_cover_the_body() {
        let yaml = r#"
schema_version: 1
name: api-flow
client: api
feature: provisioning
origin: captured
provenance: recorded against a development instance
steps:
  - name: list
    request:
      method: GET
      path: /api/v1/things
    capture:
      first_id:
        json: /items/0/id
      count:
        json: /count
      href:
        xpath: "/{DAV:}multistatus/{DAV:}response[1]/{DAV:}href"
    expect:
      json:
        - pointer: /items/0/id
          equals: abc
        - pointer: /nothing
          present: false
        - pointer: /count
          equals: "2"
      statuses:
        /a/: 200
      properties:
        - href: /a/
          name: "{DAV:}getetag"
          value: '"e1"'
        - href: /a/
          name: "{DAV:}missing"
          present: false
      xpath:
        - path: "//{DAV:}href"
          count: 1
        - path: "//{DAV:}getetag"
          equals: '"e1"'
        - path: "//{DAV:}getetag"
          contains: e1
  - name: second
    request:
      method: GET
      path: "/things/{{first_id}}/{{count}}"
    expect:
      status: 404
"#;
        let body = r#"{"items": [{"id": "abc"}], "count": 2}"#;
        let multistatus = r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>/a/</D:href><D:propstat><D:prop><D:getetag>"e1"</D:getetag></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"#;
        // One response that is both JSON-looking for the JSON assertions and XML for the XML ones is impossible,
        // so this scenario splits the work: the JSON and XML assertions run against two servers.
        let scenario = Scenario::from_yaml(yaml).unwrap();
        let mut json_only = scenario.clone();
        json_only.steps[0].capture.remove("href");
        json_only.steps[0].expect.statuses.clear();
        json_only.steps[0].expect.properties.clear();
        json_only.steps[0].expect.xpath.clear();
        let json_server: Arc<dyn Transport> = Arc::new(FnTransport::new(move |request: &TestRequest| {
            Ok(if request.target == "/api/v1/things" {
                TestResponse::new(200, body)
            } else {
                TestResponse::new(404, "")
            })
        }));
        let report = run_scenario(&env(json_server), &json_only).await;
        assert!(report.is_success(), "{report}");
        assert_eq!(report.origin, Origin::Captured);

        let mut xml_only = scenario;
        xml_only.steps[0].capture.retain(|name, _| name == "href");
        xml_only.steps[0].expect.json.clear();
        xml_only.steps.pop();
        let xml_server: Arc<dyn Transport> = Arc::new(FnTransport::new(move |_: &TestRequest| {
            Ok(TestResponse::new(207, multistatus))
        }));
        let report = run_scenario(&env(xml_server), &xml_only).await;
        assert!(report.is_success(), "{report}");
    }

    #[tokio::test]
    async fn header_and_body_assertions_report_what_is_wrong() {
        let yaml = r"
schema_version: 1
name: asserts
client: c
feature: f
origin: synthetic
provenance: test
steps:
  - name: only
    request:
      method: GET
      path: /x
    expect:
      headers:
        x-missing: present-please
        x-forbidden:
          present: false
        x-wrong: expected
        x-contains:
          contains: needle
        x-required:
          present: true
      body_contains: [absent]
      body_excludes: [present]
      xpath:
        - path: /nothing
      statuses:
        /unknown/: 200
";
        let transport: Arc<dyn Transport> = Arc::new(FnTransport::new(|_: &TestRequest| {
            Ok(TestResponse::new(200, "<a>present</a>")
                .with_header("x-forbidden", "here")
                .with_header("x-wrong", "actual")
                .with_header("x-contains", "haystack"))
        }));
        let scenario = Scenario::from_yaml(yaml).unwrap();
        let report = run_scenario(&env(transport), &scenario).await;
        let failures = report.failures().join("\n");
        for expected in [
            "`x-missing` is missing",
            "`x-forbidden` is present",
            "`x-wrong` is `actual`, expected `expected`",
            "`x-contains` is `haystack`, which does not contain `needle`",
            "`x-required` is missing",
            "does not contain `absent`",
            "contains `present`",
            "`/nothing` matches nothing",
            "not {DAV:}multistatus",
        ] {
            assert!(failures.contains(expected), "{expected} in {failures}");
        }
    }

    #[test]
    fn the_grid_counts_synthetic_and_captured_scenarios_per_cell() {
        let synthetic = Scenario::from_yaml(SCENARIO).unwrap();
        let mut captured = synthetic.clone();
        captured.origin = Origin::Captured;
        let mut other = synthetic.clone();
        other.feature = "sync".to_owned();
        let cells = grid([&synthetic, &captured, &other, &synthetic]);
        assert_eq!(
            cells[&("python-caldav".to_owned(), "crud".to_owned())],
            GridCell {
                synthetic: 2,
                captured: 1
            }
        );
        assert_eq!(
            cells[&("python-caldav".to_owned(), "sync".to_owned())],
            GridCell {
                synthetic: 1,
                captured: 0
            }
        );
    }

    #[test]
    fn the_representative_set_has_every_client_and_every_feature_and_does_not_depend_on_the_order() {
        let base = Scenario::from_yaml(SCENARIO).unwrap();
        let make = |name: &str, client: &str, feature: &str| {
            let mut scenario = base.clone();
            name.clone_into(&mut scenario.name);
            client.clone_into(&mut scenario.client);
            feature.clone_into(&mut scenario.feature);
            scenario
        };
        let all = vec![
            make("a", "davx5", "crud"),
            make("b", "davx5", "share"),
            make("c", "thunderbird", "crud"),
            make("d", "thunderbird", "share"),
            make("e", "evolution", "crud"),
            make("f", "evolution", "accept"),
            make("g", "evolution", "crud"),
        ];
        let chosen: Vec<&str> = representative(&all)
            .iter()
            .map(|scenario| scenario.name.as_str())
            .collect();
        // Everything adds two facets to begin with and `a` is the first by name; then `d` adds two (thunderbird, share) and so
        // does `f` (evolution, accept), while the others add one.
        assert_eq!(chosen, vec!["a", "d", "f"]);
        let mut reversed = all.clone();
        reversed.reverse();
        let again: Vec<&str> = representative(&reversed)
            .iter()
            .map(|scenario| scenario.name.as_str())
            .collect();
        assert_eq!(again, chosen);
        // Nothing to choose from, nothing chosen.
        assert_eq!(representative(&[]), Vec::<&Scenario>::new());
    }

    #[test]
    fn scenario_files_are_loaded_recursively_in_path_order() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().to_path_buf();
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        std::fs::write(dir.join("b.yaml"), SCENARIO.replace("discover-and-store", "b")).unwrap();
        std::fs::write(
            dir.join("nested").join("a.yml"),
            SCENARIO.replace("discover-and-store", "a"),
        )
        .unwrap();
        std::fs::write(dir.join("ignored.txt"), "not a scenario").unwrap();
        let loaded = load_scenarios(&dir).unwrap();
        let names: Vec<&str> = loaded.iter().map(|(_, scenario)| scenario.name.as_str()).collect();
        assert_eq!(names, vec!["b", "a"], "b.yaml sorts before nested/a.yml");
        std::fs::write(dir.join("broken.yaml"), "name: [").unwrap();
        let error = load_scenarios(&dir).unwrap_err();
        assert!(error.to_string().contains("broken.yaml"), "{error}");
        assert!(matches!(
            load_scenarios(&dir.join("missing")),
            Err(FlowError::Io { .. })
        ));
    }

    /// A transport that records what it is sent and answers 204.
    fn recorder() -> (Arc<dyn Transport>, std::sync::mpsc::Receiver<TestRequest>) {
        let (sender, seen) = std::sync::mpsc::channel();
        let transport = FnTransport::new(move |request: &TestRequest| {
            drop(sender.send(request.clone()));
            Ok(TestResponse::new(204, ""))
        });
        (Arc::new(transport), seen)
    }

    const BODIES: &str = r"
schema_version: 1
name: bodies
client: python-caldav
feature: crud
origin: synthetic
provenance: written for the tests of the runner
actors:
  olivia: owner
variables:
  uid: u-1
steps:
  - name: ical
    as: olivia
    request:
      method: PUT
      path: /x/a.ics
      ical: |
        BEGIN:VCALENDAR
        UID:{{uid}}
        END:VCALENDAR
  - name: ical with its own type
    as: olivia
    request:
      method: PUT
      path: /x/b.ics
      headers: { Content-Type: text/plain }
      ical: |
        BEGIN:VCALENDAR
        END:VCALENDAR
  - name: file
    as: olivia
    request:
      method: PUT
      path: /x/c.ics
      body_file: corpus/lenient-lf-line-endings.ics
";

    #[tokio::test]
    async fn ical_bodies_get_crlf_and_files_are_sent_byte_for_byte() {
        let scenario = Scenario::from_yaml(BODIES).unwrap();
        let (transport, seen) = recorder();
        let credentials: CredentialResolver = Arc::new(|_, _| Some(Actor::basic("o", "p")));
        let env = ScenarioEnv::new(transport, credentials).with_data_dir(davhaven_fixtures::corpus::data_dir());
        let report = run_scenario(&env, &scenario).await;
        assert!(report.is_success(), "{report}");
        let requests: Vec<TestRequest> = seen.try_iter().collect();
        assert_eq!(requests[0].body, "BEGIN:VCALENDAR\r\nUID:u-1\r\nEND:VCALENDAR\r\n");
        assert_eq!(requests[0].headers["content-type"], "text/calendar; charset=utf-8");
        assert_eq!(
            requests[1].headers["content-type"], "text/plain",
            "a type the step sets is kept"
        );
        let file = std::fs::read(davhaven_fixtures::corpus::root().join("lenient-lf-line-endings.ics")).unwrap();
        assert_eq!(requests[2].body.as_ref(), file.as_slice(), "no line ending is changed");

        // Without a data directory a body file cannot be read.
        let (transport, _) = recorder();
        let credentials: CredentialResolver = Arc::new(|_, _| Some(Actor::basic("o", "p")));
        let bare = run_scenario(&ScenarioEnv::new(transport, credentials), &scenario).await;
        assert!(
            bare.failures()
                .iter()
                .any(|failure| failure.contains("no data directory")),
            "{bare}"
        );
    }

    #[test]
    fn bodies_are_exclusive_files_stay_below_the_data_directory_and_known_issues_parse() {
        let with = |request: &str| {
            format!(
                "schema_version: 1
name: x
client: c
feature: f
origin: synthetic
provenance: p
known_issue: tracked elsewhere
steps:
  - name: s
    request:
      method: PUT
      path: /a
{request}"
            )
        };
        let scenario = Scenario::from_yaml(&with(
            "      body: x
",
        ))
        .unwrap();
        assert_eq!(scenario.known_issue.as_deref(), Some("tracked elsewhere"));
        for bad in [
            "      body: x
      ical: y
",
            "      body: x
      body_file: corpus/a.ics
",
            "      body_file: ../secret
",
            "      body_file: /etc/passwd
",
            "      body_file: corpus//a.ics
",
        ] {
            assert!(Scenario::from_yaml(&with(bad)).is_err(), "{bad}");
        }
    }
}
