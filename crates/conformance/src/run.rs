//! `run`: the harness against a deployed instance.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use davhaven_testkit::davhaven_ports::Clock;
use davhaven_testkit::flow;
use davhaven_testkit::permissions::Sampling;
use davhaven_testkit::staging::{self, Options, PrincipalTokenIssuer, StagingConfig};
use url::Host;

use crate::cli::RunArgs;
use crate::issuer::CommandIssuer;
use crate::{RunnerError, load_expectations};

/// The environment variables the tokens can come from instead of files.
const TENANT_TOKEN_ENV: &str = "CONFORMANCE_TENANT_TOKEN";
const OTHER_TENANT_TOKEN_ENV: &str = "CONFORMANCE_OTHER_TENANT_TOKEN";
const SYSTEM_TOKEN_ENV: &str = "CONFORMANCE_SYSTEM_TOKEN";

/// A secret from a file (its first line) or, without a file, from an environment variable.
fn secret(file: Option<&Path>, variable: &str) -> Result<Option<String>, RunnerError> {
    let text = match file {
        Some(path) => Some(std::fs::read_to_string(path).map_err(|error| RunnerError::File {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?),
        None => std::env::var(variable).ok(),
    };
    Ok(text
        .as_deref()
        .and_then(|text| text.lines().next())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned))
}

fn required(file: Option<&Path>, variable: &str, flag: &str, what: &str) -> Result<String, RunnerError> {
    secret(file, variable)?.ok_or_else(|| {
        RunnerError::Usage(format!(
            "the administration token of {what} is needed: give a file with {flag} or set {variable}"
        ))
    })
}

/// Refuses an instance that is neither reached over https nor on this machine, unless the operator says that it is fine: the
/// administration tokens of the tenants and the system token travel in every request.
pub(crate) fn check_transport(args: &RunArgs) -> Result<(), RunnerError> {
    let url = &args.base_url;
    let on_this_machine = match url.host() {
        Some(Host::Domain(name)) => {
            let name = name.to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if url.scheme() == "https" || on_this_machine || args.insecure_http {
        Ok(())
    } else {
        Err(RunnerError::Usage(format!(
            "{url} is not reached over https: the tokens would travel in clear text. Use an https URL, or give --insecure-http \
             if the network is yours"
        )))
    }
}

/// Checks that the directories the flows need exist: the defaults are those of the checkout the binary was built from, which
/// a binary that was built in one place and runs in another does not have.
pub(crate) fn check_directories(args: &RunArgs) -> Result<(), RunnerError> {
    if args.no_flows {
        return Ok(());
    }
    for (what, path, option) in [
        ("scenarios", &args.scenarios, "--scenarios"),
        ("data (`body_file`s)", &args.data_dir, "--data-dir"),
    ] {
        if !path.is_dir() {
            return Err(RunnerError::Usage(format!(
                "the {what} directory {} does not exist (the default is the one of the checkout this binary was built from): give \
                 {option} DIR, or --no-flows",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Runs the harness against the instance and writes the report; `true` when nothing failed.
pub(crate) async fn run(args: &RunArgs, out: &mut dyn Write, clock: Arc<dyn Clock>) -> Result<bool, RunnerError> {
    check_transport(args)?;
    check_directories(args)?;
    let expectations = load_expectations(args.expectations.as_deref())?;
    let run_id = args
        .run_id
        .clone()
        .unwrap_or_else(|| format!("r{}", clock.now().format("%Y%m%d%H%M%S")));
    let tenant_token = required(
        args.tenant_token_file.as_deref(),
        TENANT_TOKEN_ENV,
        "--tenant-token-file",
        &format!("the tenant `{run_id}-a`"),
    )?;
    let other_tenant_token = required(
        args.other_tenant_token_file.as_deref(),
        OTHER_TENANT_TOKEN_ENV,
        "--other-tenant-token-file",
        &format!("the tenant `{run_id}-b`"),
    )?;
    let system_token = secret(args.system_token_file.as_deref(), SYSTEM_TOKEN_ENV)?;
    let flows = if args.no_flows {
        Vec::new()
    } else {
        flow::load_scenarios(&args.scenarios)?
    };
    let token_issuer = args
        .principal_token_command
        .as_deref()
        .filter(|command| !command.trim().is_empty())
        .map(|command| -> Arc<dyn PrincipalTokenIssuer> { Arc::new(CommandIssuer::new(command)) });
    writeln!(
        out,
        "run {run_id} against {} (tenants {run_id}-a and {run_id}-b; {} scenarios; matrix {}; system token {}; MCP tokens of users {})",
        args.base_url,
        flows.len(),
        if args.no_matrix { "off" } else { "on" },
        if system_token.is_some() { "given" } else { "not given" },
        if token_issuer.is_some() {
            "from the command"
        } else {
            "not issued"
        }
    )?;

    let report = staging::run(
        StagingConfig {
            base_url: args.base_url.clone(),
            run_id,
            tenant_token,
            other_tenant_token,
            system_token,
            clock,
            token_issuer,
        },
        &expectations,
        Options {
            matrices: !args.no_matrix,
            flows,
            data_dir: Some(args.data_dir.clone()),
            reset_between_writes: args.reset_between_writes,
            keep: args.keep,
            sampling: Sampling::Everything,
        },
    )
    .await?;
    write!(out, "{report}")?;
    Ok(report.is_clean())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use davhaven_testkit::TestApp;
    use davhaven_testkit::davhaven_domain::{DomainName, TenantSlug};
    use davhaven_testkit::davhaven_server::admin::{
        BootstrapRequest, SettingsFlags, TokenSink, bootstrap, default_scopes, system_token,
    };
    use url::Url;

    use super::*;
    use crate::cli::{default_data_dir, default_scenarios};
    use crate::scratch::Scratch;

    async fn token_of(app: &TestApp, slug: &str) -> String {
        let mut printed = Vec::new();
        bootstrap(
            app.deps(),
            app.services(),
            &BootstrapRequest {
                tenant: TenantSlug::parse(slug).unwrap(),
                display_name: None,
                login_domain: Some(DomainName::parse(&format!("{slug}.example")).unwrap()),
                settings: SettingsFlags::default(),
                label: "bootstrap".to_owned(),
                scopes: default_scopes(),
                expires_at: None,
            },
            &TokenSink::Stdout,
            &mut printed,
        )
        .await
        .unwrap();
        String::from_utf8(printed).unwrap().trim().to_owned()
    }

    fn args(base_url: &Url, run_id: &str, scratch: &Scratch, scenarios: PathBuf) -> RunArgs {
        RunArgs {
            base_url: base_url.clone(),
            run_id: Some(run_id.to_owned()),
            tenant_token_file: Some(scratch.0.join("a.token")),
            other_tenant_token_file: Some(scratch.0.join("b.token")),
            system_token_file: Some(scratch.0.join("system.token")),
            principal_token_command: None,
            scenarios,
            data_dir: default_data_dir(),
            expectations: None,
            insecure_http: false,
            no_matrix: true,
            no_flows: false,
            reset_between_writes: false,
            keep: false,
        }
    }

    #[test]
    fn secrets_come_from_the_first_line_of_a_file_or_from_the_environment() {
        let scratch = Scratch::new("secrets");
        let file = scratch.file("token", "  dvh_pat_abc  \nsecond line\n");
        assert_eq!(
            secret(Some(&file), "CONFORMANCE_TEST_UNSET").unwrap().as_deref(),
            Some("dvh_pat_abc")
        );
        assert_eq!(secret(None, "CONFORMANCE_TEST_UNSET").unwrap(), None);
        let empty = scratch.file("empty", "\n");
        assert_eq!(secret(Some(&empty), "X").unwrap(), None);
        assert!(matches!(
            secret(Some(&scratch.0.join("missing")), "X"),
            Err(RunnerError::File { .. })
        ));
        let error = required(
            None,
            "CONFORMANCE_TEST_UNSET",
            "--tenant-token-file",
            "the tenant `r1-a`",
        )
        .unwrap_err();
        assert!(error.to_string().contains("--tenant-token-file"), "{error}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_flows_run_against_a_server_and_the_tenants_are_deleted_at_the_end() {
        let app = TestApp::builder().empty().build().await.unwrap();
        let scratch = Scratch::new("run");
        scratch.file("a.token", &format!("{}\n", token_of(&app, "r1-a").await));
        scratch.file("b.token", &format!("{}\n", token_of(&app, "r1-b").await));
        let mut printed = Vec::new();
        system_token(app.deps(), "conformance", None, &TokenSink::Stdout, &mut printed)
            .await
            .unwrap();
        scratch.file("system.token", &String::from_utf8(printed).unwrap());
        let scenarios = scratch.0.join("scenarios");
        std::fs::create_dir_all(&scenarios).unwrap();
        for name in ["apple-calendar/crud.yaml", "thunderbird/accept.yaml"] {
            let text = std::fs::read_to_string(default_scenarios().join(name)).unwrap();
            std::fs::write(scenarios.join(name.replace('/', "-")), text).unwrap();
        }
        let served = app.serve().await.unwrap();

        let mut report = Vec::new();
        let clean = run(
            &args(&served.base_url, "r1", &scratch, scenarios),
            &mut report,
            Arc::clone(&app.deps().clock),
        )
        .await
        .unwrap();
        let text = String::from_utf8(report).unwrap();
        assert!(clean, "{text}");
        assert!(text.contains("run r1 against"), "{text}");
        assert!(text.contains("2 of 2 scenarios did what they should"), "{text}");
        assert!(text.contains("the tenants of the run were deleted"), "{text}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_the_instance_refuses_is_a_runner_error_and_not_a_failed_case() {
        let app = TestApp::builder().empty().build().await.unwrap();
        let scratch = Scratch::new("refused");
        scratch.file(
            "a.token",
            "dvh_pat_aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        );
        scratch.file(
            "b.token",
            "dvh_pat_aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        );
        let served = app.serve().await.unwrap();
        let mut report = Vec::new();
        let mut run_args = args(&served.base_url, "r2", &scratch, default_scenarios());
        run_args.system_token_file = None;
        let error = run(&run_args, &mut report, Arc::clone(&app.deps().clock))
            .await
            .unwrap_err();
        assert!(matches!(error, RunnerError::Staging(_)), "{error}");
    }

    #[tokio::test]
    async fn the_tokens_travel_over_https_or_to_this_machine_unless_the_operator_says_otherwise() {
        let scratch = Scratch::new("transport");
        let with = |base: &str| args(&Url::parse(base).unwrap(), "r4", &scratch, default_scenarios());
        assert!(check_transport(&with("https://calendar.example")).is_ok());
        for local in [
            "http://127.0.0.1:8080/",
            "http://localhost/",
            "http://[::1]:3000/",
            "http://app.localhost/",
        ] {
            assert!(check_transport(&with(local)).is_ok(), "{local}");
        }
        let error = check_transport(&with("http://calendar.example/")).unwrap_err();
        assert!(
            matches!(error, RunnerError::Usage(_)) && error.to_string().contains("--insecure-http"),
            "{error}"
        );
        // A name that only starts like this machine's is somebody else's host.
        for remote in [
            "http://localhost.calendar.example/",
            "http://calendar-localhost/",
            "http://10.0.0.1/",
            "http://[2001:db8::1]/",
        ] {
            assert!(
                matches!(check_transport(&with(remote)), Err(RunnerError::Usage(_))),
                "{remote}"
            );
        }
        assert!(
            check_transport(&with("http://127.10.0.1/")).is_ok(),
            "the whole loopback network"
        );
        let mut allowed = with("http://calendar.example/");
        allowed.insecure_http = true;
        assert!(check_transport(&allowed).is_ok());
        // `run` refuses before it reads a token or sends anything.
        let error = run(
            &with("http://calendar.example/"),
            &mut Vec::new(),
            Arc::new(davhaven_testkit::davhaven_ports::SystemClock),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RunnerError::Usage(_)), "{error}");
    }

    #[test]
    fn a_binary_that_runs_where_it_was_not_built_says_which_directory_is_missing() {
        let scratch = Scratch::new("directories");
        let base = Url::parse("https://calendar.example").unwrap();
        let mut run_args = args(&base, "r5", &scratch, scratch.0.join("no-scenarios"));
        let error = check_directories(&run_args).unwrap_err();
        assert!(error.to_string().contains("--scenarios"), "{error}");
        run_args.scenarios = default_scenarios();
        run_args.data_dir = scratch.0.join("no-data");
        let error = check_directories(&run_args).unwrap_err();
        assert!(error.to_string().contains("--data-dir"), "{error}");
        run_args.no_flows = true;
        assert!(check_directories(&run_args).is_ok(), "without flows nothing is read");
        run_args.no_flows = false;
        run_args.data_dir = default_data_dir();
        assert!(check_directories(&run_args).is_ok());
    }

    #[tokio::test]
    async fn the_tokens_are_required() {
        let scratch = Scratch::new("required");
        let mut run_args = args(
            &Url::parse("http://127.0.0.1:1/").unwrap(),
            "r3",
            &scratch,
            default_scenarios(),
        );
        run_args.tenant_token_file = None;
        let error = run(
            &run_args,
            &mut Vec::new(),
            Arc::new(davhaven_testkit::davhaven_ports::SystemClock),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RunnerError::Usage(_)), "{error}");
        assert_eq!(
            error.to_string(),
            "the administration token of the tenant `r3-a` is needed: give a file with --tenant-token-file or set \
             CONFORMANCE_TENANT_TOKEN"
        );

        scratch.file(
            "a.token",
            "dvh_pat_aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        );
        run_args.tenant_token_file = Some(scratch.0.join("a.token"));
        run_args.other_tenant_token_file = None;
        let error = run(
            &run_args,
            &mut Vec::new(),
            Arc::new(davhaven_testkit::davhaven_ports::SystemClock),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the administration token of the tenant `r3-b` is needed: give a file with --other-tenant-token-file or set \
             CONFORMANCE_OTHER_TENANT_TOKEN"
        );
    }
}
