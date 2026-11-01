//! The small framework the contract suites are written in.
//!
//! A suite is a list of named cases. A case collects [`Checks`] instead of panicking at the first violated
//! expectation, so one run reports everything a port implementation gets wrong. [`Suite::finish`] produces a
//! [`ContractReport`]; the `run_all` entry points of the port modules assert that the report is clean, while the
//! `run` functions return it, which is how the suites test themselves against deliberately broken doubles.

use core::fmt;

/// The outcome of one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseResult {
    /// The name of the case.
    pub name: &'static str,
    /// What went wrong; empty when the case passed.
    pub failures: Vec<String>,
}

impl CaseResult {
    /// Whether the case passed.
    pub const fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// The checks of one case.
#[derive(Debug)]
pub struct Checks {
    name: &'static str,
    failures: Vec<String>,
    /// The `what` of every check that ran, passed or failed (see [`Checks::ran`]).
    ran: Vec<String>,
}

impl Checks {
    /// Starts a case.
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            failures: Vec::new(),
            ran: Vec::new(),
        }
    }

    /// Remembers that a check ran. The memory is bounded: a case with a very large number of checks (the model case
    /// of the sync log) keeps the first ones, which is enough for the cases that look their checks up.
    fn remember(&mut self, what: &str) {
        if self.ran.len() < 20_000 {
            self.ran.push(what.to_owned());
        }
    }

    /// Whether a check described by `what` ran in this case, whatever its outcome. A description counts as `what`
    /// when it is equal to it or starts with it followed by a space (`"objects.get (more words)"`). The store
    /// suite uses it to prove that every operation it lists was really called, not only mentioned.
    pub fn ran(&self, what: &str) -> bool {
        self.ran
            .iter()
            .any(|done| done == what || done.strip_prefix(what).is_some_and(|rest| rest.starts_with(' ')))
    }

    /// Records a failure with a ready-made message.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.failures.push(message.into());
    }

    /// Checks a condition; `what` says what was expected.
    pub fn that(&mut self, condition: bool, what: &str) {
        self.remember(what);
        if !condition {
            self.fail(format!("expected: {what}"));
        }
    }

    /// Checks that two values are equal.
    pub fn equal<T: PartialEq + fmt::Debug>(&mut self, actual: &T, expected: &T, what: &str) {
        self.remember(what);
        if actual != expected {
            self.fail(format!("{what}: expected {expected:?}, got {actual:?}"));
        }
    }

    /// Checks that two values differ.
    pub fn differ<T: PartialEq + fmt::Debug>(&mut self, actual: &T, other: &T, what: &str) {
        self.remember(what);
        if actual == other {
            self.fail(format!("{what}: both are {actual:?}"));
        }
    }

    /// Takes the value of a result that must be `Ok`; records the error and returns `None` otherwise.
    pub fn ok<T, E: fmt::Debug>(&mut self, result: Result<T, E>, what: &str) -> Option<T> {
        self.remember(what);
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.fail(format!("{what}: expected success, got error {error:?}"));
                None
            }
        }
    }

    /// Takes the error of a result that must be `Err`; records the value and returns `None` otherwise.
    pub fn err<T: fmt::Debug, E>(&mut self, result: Result<T, E>, what: &str) -> Option<E> {
        self.remember(what);
        match result {
            Err(error) => Some(error),
            Ok(value) => {
                self.fail(format!("{what}: expected an error, got {value:?}"));
                None
            }
        }
    }

    /// Whether no check has failed so far (a long case stops early at its first failure).
    pub const fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    /// Ends the case.
    pub fn finish(self) -> CaseResult {
        CaseResult {
            name: self.name,
            failures: self.failures,
        }
    }
}

/// A suite under construction: the cases recorded so far.
#[derive(Debug)]
pub struct Suite {
    port: &'static str,
    cases: Vec<CaseResult>,
}

impl Suite {
    /// Starts the suite of `port` (the module name, for example `clock`).
    pub const fn new(port: &'static str) -> Self {
        Self {
            port,
            cases: Vec::new(),
        }
    }

    /// Adds a finished case.
    pub fn record(&mut self, checks: Checks) {
        self.cases.push(checks.finish());
    }

    /// Ends the suite.
    pub fn finish(self) -> ContractReport {
        ContractReport {
            port: self.port,
            cases: self.cases,
        }
    }
}

/// The result of running a suite against one implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractReport {
    /// The port that was tested.
    pub port: &'static str,
    /// The cases in the order they ran.
    pub cases: Vec<CaseResult>,
}

impl ContractReport {
    /// A report of a suite that has no cases yet; the crate that implements the port adds them (PLAN 4.2).
    pub const fn pending(port: &'static str) -> Self {
        Self {
            port,
            cases: Vec::new(),
        }
    }

    /// Whether every case passed.
    pub fn is_ok(&self) -> bool {
        self.cases.iter().all(CaseResult::passed)
    }

    /// The number of cases that ran.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }

    /// The names of the cases that failed.
    pub fn failed_cases(&self) -> Vec<&'static str> {
        self.cases
            .iter()
            .filter(|case| !case.passed())
            .map(|case| case.name)
            .collect()
    }

    /// Fails the running test when any case failed, listing every failure.
    ///
    /// # Panics
    ///
    /// When at least one case failed (that is the point: contract suites run inside the tests of an adapter).
    #[track_caller]
    pub fn assert_ok(&self) {
        assert!(self.is_ok(), "{self}");
    }
}

impl fmt::Display for ContractReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let failed = self.failed_cases().len();
        writeln!(
            f,
            "contract suite `{}`: {} of {} cases failed",
            self.port,
            failed,
            self.cases.len()
        )?;
        for case in self.cases.iter().filter(|case| !case.passed()) {
            writeln!(f, "  case `{}`:", case.name)?;
            for failure in &case.failures {
                writeln!(f, "    - {failure}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_collect_every_failure_instead_of_stopping() {
        let mut checks = Checks::new("demo");
        checks.that(true, "fine");
        checks.that(false, "this is violated");
        checks.equal(&1, &2, "numbers");
        checks.differ(&3, &3, "different");
        assert_eq!(checks.ok::<u8, &str>(Err("boom"), "call"), None);
        assert_eq!(checks.err::<u8, ()>(Ok(7), "call"), None);
        assert_eq!(checks.ok::<u8, ()>(Ok(7), "call"), Some(7));
        assert_eq!(checks.err::<u8, &str>(Err("x"), "call"), Some("x"));
        checks.fail("custom");
        let result = checks.finish();
        assert_eq!(result.name, "demo");
        assert_eq!(result.failures.len(), 6, "{:?}", result.failures);
        assert!(!result.passed());
    }

    #[test]
    fn reports_list_failed_cases_and_assert_only_when_something_failed() {
        let mut suite = Suite::new("demo");
        suite.record(Checks::new("good"));
        let mut bad = Checks::new("bad");
        bad.fail("nope");
        suite.record(bad);
        let report = suite.finish();
        assert!(!report.is_ok());
        assert_eq!(report.case_count(), 2);
        assert_eq!(report.failed_cases(), vec!["bad"]);
        let text = report.to_string();
        assert!(
            text.contains("1 of 2 cases failed") && text.contains("- nope"),
            "{text}"
        );

        let mut clean = Suite::new("demo");
        clean.record(Checks::new("good"));
        clean.finish().assert_ok();
        assert!(ContractReport::pending("later").is_ok());
        assert_eq!(ContractReport::pending("later").case_count(), 0);
    }

    #[test]
    #[should_panic(expected = "1 of 1 cases failed")]
    fn a_failed_report_fails_the_test() {
        let mut suite = Suite::new("demo");
        let mut bad = Checks::new("bad");
        bad.fail("nope");
        suite.record(bad);
        suite.finish().assert_ok();
    }
}
