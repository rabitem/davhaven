//! The command line of `davhaven-conformance`.

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use davhaven_testkit::davhaven_fixtures::{ActorRole, WorldNames};
use url::Url;

/// The command line.
#[derive(Debug, Parser)]
#[command(
    name = "davhaven-conformance",
    version,
    about = "Runs the Davhaven permission matrix and client flows against a deployed instance, and checks and converts the files they use",
    propagate_version = true
)]
pub(crate) struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// The commands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Validate the expectations file, the scenarios and the coverage of the matrix, and print the client-by-feature grid.
    /// Nothing is sent anywhere.
    Check(CheckArgs),
    /// Print the permission matrix document (`docs/permission-matrix.md`), rendered from the expectations file. `cargo xtask
    /// matrix` writes and checks the committed copy with it.
    MatrixReport(MatrixReportArgs),
    /// Run the matrices and the client flows against a deployed instance, on an ephemeral pair of tenants of their own.
    Run(Box<RunArgs>),
    /// Convert the DAV exchanges a server recorded (`observability.dav_capture`) into a client-flow scenario.
    Convert(ConvertArgs),
}

/// The scenarios of the repository: `crates/it/tests/scenarios` of the checkout this binary was built from. A binary that is
/// run elsewhere than where it was built has no such directory; [`crate::run::check_directories`] says so, and `--scenarios`
/// names another one.
pub(crate) fn default_scenarios() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../it/tests/scenarios")
}

/// The directory the `body_file`s of the scenarios are read from: `testdata` of the checkout this binary was built from, as
/// the fixtures crate knows it (`--data-dir` names another one).
pub(crate) fn default_data_dir() -> PathBuf {
    davhaven_testkit::davhaven_fixtures::corpus::data_dir()
}

/// The prefix of a run, checked: the tenants `{id}-a` and `{id}-b` and their login domains must be valid names (lower case
/// letters, digits and hyphens), or the run could not create them.
fn parse_run_id(text: &str) -> Result<String, String> {
    WorldNames::try_for_run(text)
        .map(|_| text.to_owned())
        .map_err(|error| format!("{error}; use lower case letters, digits and hyphens, for example `r42`"))
}

/// Arguments of `check`.
#[derive(Debug, Args)]
pub(crate) struct CheckArgs {
    /// A directory with scenario files (`*.yaml`), searched recursively.
    #[arg(long, value_name = "DIR", default_value_os_t = default_scenarios())]
    pub(crate) scenarios: PathBuf,

    /// An expectations file to validate instead of the one bundled with the harness.
    #[arg(long, value_name = "FILE")]
    pub(crate) expectations: Option<PathBuf>,
}

/// Arguments of `matrix-report`.
#[derive(Debug, Args)]
pub(crate) struct MatrixReportArgs {
    /// An expectations file to render instead of the one bundled with the harness.
    #[arg(long, value_name = "FILE")]
    pub(crate) expectations: Option<PathBuf>,
}

/// Arguments of `run`.
#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the switches of a command line are independent flags, each its own option"
)]
pub(crate) struct RunArgs {
    /// The base URL of the instance, for example `https://calendar.example`.
    #[arg(long, env = "CONFORMANCE_BASE_URL", value_name = "URL")]
    pub(crate) base_url: Url,

    /// The prefix of the names of the two tenants of the run (`{id}-a` and `{id}-b`); unique per run. The tenants must exist:
    /// `davhaven admin bootstrap --tenant {id}-a --login-domain {id}-a.example --mcp-enabled --print-token`, and the same for `-b`.
    /// Default: `r` and the time of the run.
    #[arg(long, value_name = "ID", value_parser = parse_run_id)]
    pub(crate) run_id: Option<String>,

    /// A file with the administration token of the tenant `{id}-a` (as `admin bootstrap` printed it).
    #[arg(long, value_name = "FILE")]
    pub(crate) tenant_token_file: Option<PathBuf>,

    /// A file with the administration token of the tenant `{id}-b`.
    #[arg(long, value_name = "FILE")]
    pub(crate) other_tenant_token_file: Option<PathBuf>,

    /// A file with a system token (`davhaven admin system-token create`): with it the runner aligns the tenants with what it
    /// needs and deletes both at the end; without it the cases of the system token are left out and the tenants stay.
    #[arg(long, value_name = "FILE")]
    pub(crate) system_token_file: Option<PathBuf>,

    /// A shell command that prints a principal token for MCP, which the run runs for every user of its world after it made the
    /// user (the management API issues the scopes of MCP to service principals only): `davhaven admin principal-token create`
    /// on the host of the instance, with `{tenant}`, `{principal}`, `{label}`, `{scopes}` (as `--scope a --scope b`) and
    /// `{expires_in}` filled in; every one of them has to be in the command. Without it the MCP cases of the users are left out. For
    /// example: `ssh staging docker exec davhaven davhaven admin principal-token create --tenant {tenant} --principal
    /// {principal} --label {label} {scopes} --expires-in {expires_in} --print-token`. The tenants must have MCP switched on (`admin
    /// bootstrap --mcp-enabled`), or the run stops. The command runs without a terminal and has two minutes for each token.
    #[arg(
        long,
        env = "CONFORMANCE_PRINCIPAL_TOKEN_COMMAND",
        value_name = "COMMAND",
        value_parser = crate::issuer::parse_template
    )]
    pub(crate) principal_token_command: Option<String>,

    /// A directory with scenario files (`*.yaml`), searched recursively. The default is the directory of the checkout the
    /// binary was built from; a binary that runs elsewhere needs this option (and `--data-dir`) or `--no-flows`.
    #[arg(long, value_name = "DIR", default_value_os_t = default_scenarios())]
    pub(crate) scenarios: PathBuf,

    /// The directory the `body_file`s of the scenarios are read from (`testdata` of a checkout).
    #[arg(long, value_name = "DIR", default_value_os_t = default_data_dir())]
    pub(crate) data_dir: PathBuf,

    /// An expectations file to run instead of the one bundled with the harness.
    #[arg(long, value_name = "FILE")]
    pub(crate) expectations: Option<PathBuf>,

    /// Send the tokens in clear text to an instance that is not reached over https and is not on this machine. Without it the
    /// runner refuses: the administration token of a tenant and the system token travel in every request.
    #[arg(long)]
    pub(crate) insecure_http: bool,

    /// Do not run the permission matrix.
    #[arg(long)]
    pub(crate) no_matrix: bool,

    /// Do not run the client flows.
    #[arg(long)]
    pub(crate) no_flows: bool,

    /// Run the cases that change something too, each on a world that is built again for it (several hundred requests per
    /// case); by default they are left to the in-process run and reported as skipped. With `--principal-token-command` every new
    /// world asks the command again for every user token (an `ssh` each), which adds some tens of seconds to every such case.
    #[arg(long)]
    pub(crate) reset_between_writes: bool,

    /// Leave the tenants in place at the end.
    #[arg(long)]
    pub(crate) keep: bool,
}

/// Arguments of `convert`.
#[derive(Debug, Args)]
pub(crate) struct ConvertArgs {
    /// The directory the server wrote the captures to (`observability.dav_capture.dir`): one tenant, one client doing one
    /// thing.
    #[arg(value_name = "DIR")]
    pub(crate) captures: PathBuf,

    /// The unique name of the scenario, for example `apple-calendar-crud-captured`.
    #[arg(long)]
    pub(crate) name: String,

    /// The client of the client-by-feature grid: `apple-calendar`, `ios-calendar`, `davx5`, `thunderbird`, `evolution`,
    /// `caldav-synchronizer`, ...
    #[arg(long)]
    pub(crate) client: String,

    /// The feature of the grid: `account-setup`, `crud`, `recurring-override`, `invite-internal`, `invite-external`,
    /// `accept`, `share`, `sync-after-token-expiry`, `read-only-edit`.
    #[arg(long)]
    pub(crate) feature: String,

    /// Where the capture comes from: the client and its version, the device, the date.
    #[arg(long)]
    pub(crate) provenance: String,

    /// What the scenario shows.
    #[arg(long)]
    pub(crate) description: Option<String>,

    /// The login domain of the captured tenant; it becomes `{{login_domain}}` in the scenario.
    #[arg(long, value_name = "DOMAIN")]
    pub(crate) login_domain: Option<String>,

    /// The role of the fixture world the captured user plays (default: found by the name of the user in the paths).
    #[arg(long, value_name = "ROLE", value_parser = parse_role)]
    pub(crate) actor: Option<ActorRole>,

    /// Keep the free text of the calendar data (summaries, descriptions, locations, names of people) instead of replacing it.
    #[arg(long)]
    pub(crate) keep_text: bool,

    /// Write the scenario to this file instead of standard output. An existing file is never overwritten.
    #[arg(long, value_name = "FILE")]
    pub(crate) out: Option<PathBuf>,
}

fn parse_role(text: &str) -> Result<ActorRole, String> {
    text.parse::<ActorRole>().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn the_command_line_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn a_run_id_that_cannot_name_tenants_is_a_usage_error_and_not_a_panic() {
        let parse = |id: &str| {
            Cli::try_parse_from([
                "davhaven-conformance",
                "run",
                "--base-url",
                "https://calendar.example",
                "--run-id",
                id,
            ])
        };
        for bad in ["R42", "r_42", "r 42"] {
            let error = parse(bad).unwrap_err();
            assert_eq!(error.exit_code(), 2, "{bad}: clap's usage error");
        }
        assert!(parse("r42").is_ok() && parse("nightly-7").is_ok());
    }

    #[test]
    fn the_default_data_directory_is_the_testdata_of_the_checkout() {
        assert!(
            default_data_dir().join("corpus").is_dir(),
            "{}",
            default_data_dir().display()
        );
    }

    #[test]
    fn the_default_scenarios_are_those_of_the_repository() {
        assert!(
            default_scenarios().join("apple-calendar").is_dir(),
            "{}",
            default_scenarios().display()
        );
    }

    /// A command that has every placeholder.
    const TOKEN_COMMAND: &str = "ssh staging davhaven admin principal-token create --tenant {tenant} --principal {principal} \
                                 --label {label} {scopes} --expires-in {expires_in} --print-token";

    #[test]
    fn a_token_command_without_a_placeholder_is_a_usage_error_and_not_a_run_that_fails_later() {
        let parse = |command: &str| {
            Cli::try_parse_from([
                "davhaven-conformance",
                "run",
                "--base-url",
                "https://calendar.example",
                "--principal-token-command",
                command,
            ])
        };
        let error =
            parse("ssh staging davhaven admin principal-token create --tenant {tenant} --print-token").unwrap_err();
        assert_eq!(error.exit_code(), 2, "clap's usage error");
        assert!(
            error
                .to_string()
                .contains("{principal}, {label}, {scopes}, {expires_in}"),
            "{error}"
        );
        assert!(parse(TOKEN_COMMAND).is_ok());
    }

    #[test]
    fn run_needs_a_base_url_and_reads_the_rest_from_options() {
        let parsed = Cli::try_parse_from([
            "davhaven-conformance",
            "run",
            "--base-url",
            "https://calendar.example",
            "--run-id",
            "r42",
            "--tenant-token-file",
            "a",
            "--principal-token-command",
            TOKEN_COMMAND,
            "--reset-between-writes",
        ])
        .unwrap();
        let Command::Run(args) = parsed.command else {
            panic!("run");
        };
        assert_eq!(args.base_url.as_str(), "https://calendar.example/");
        assert_eq!(args.run_id.as_deref(), Some("r42"));
        assert!(args.reset_between_writes && !args.keep && !args.no_flows);
        assert_eq!(args.principal_token_command.as_deref(), Some(TOKEN_COMMAND));
        assert!(Cli::try_parse_from(["davhaven-conformance", "run"]).is_err());
        assert!(Cli::try_parse_from(["davhaven-conformance", "run", "--base-url", "not a url"]).is_err());
    }

    #[test]
    fn convert_takes_the_directory_and_the_facts_about_the_capture() {
        let parsed = Cli::try_parse_from([
            "davhaven-conformance",
            "convert",
            "captures",
            "--name",
            "n",
            "--client",
            "davx5",
            "--feature",
            "crud",
            "--provenance",
            "DAVx5 4.5 on a Pixel",
            "--actor",
            "owner",
        ])
        .unwrap();
        let Command::Convert(args) = parsed.command else {
            panic!("convert");
        };
        assert_eq!(args.captures, PathBuf::from("captures"));
        assert_eq!(args.actor, Some(ActorRole::Owner));
        assert!(
            Cli::try_parse_from([
                "davhaven-conformance",
                "convert",
                "captures",
                "--name",
                "n",
                "--client",
                "c",
                "--feature",
                "f",
                "--provenance",
                "p",
                "--actor",
                "nobody"
            ])
            .is_err()
        );
    }
}
