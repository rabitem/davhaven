//! The command line interface.
//!
//! ```text
//! davhaven [--config <path>] <command>
//!
//! serve                         run the server
//! migrate                       apply pending database migrations (owner role)
//! healthcheck                   exit 0 when /readyz of the ops listener says ready, 1 otherwise
//! config check                  validate the configuration and its secret files (no database needed)
//! config reference              print the configuration reference (docs/configuration.md)
//! admin bootstrap               create a tenant (with its settings) and its administration token (idempotent)
//! admin system-token create     create a system token for /api/v1/tenants (idempotent by label)
//! admin system-token list       list the system tokens
//! admin system-token revoke     revoke a system token
//! admin principal-token create  create a principal token (API, MCP) of a principal (idempotent by principal and label)
//! admin principal-token list    list the principal tokens of a tenant
//! admin principal-token revoke  revoke a principal token
//! admin bump-sync-epoch         invalidate all sync tokens (after a restore)
//! admin purge-audit             remove audit events past their retention (owner role)
//! admin rotate-keys             re-seal stored secrets under the active key
//! ```
//!
//! `--config` (or `DAVHAVEN_CONFIG`) names the TOML file; without it the `DAVHAVEN_*` environment alone configures
//! the server (see `docs/configuration.md`). Exit codes: 0 success, 1 the command failed (the reason is on standard
//! error), 2 the command line is wrong.
//!
//! Each command loads only what it needs, so that a job holds only the secrets of its task: `healthcheck` reads the
//! listener addresses, `migrate` and `admin purge-audit` the `[database]` table, `admin bump-sync-epoch` the store,
//! `config check`, `serve` and the other `admin` commands the whole configuration with its key files. Only `serve` runs
//! on a multi-threaded runtime; a probe or a one-off job needs no worker pool.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use clap::{Args, Parser, Subcommand};
use davhaven_domain::{DomainName, Locale, PrincipalName, Scope, ScopeSet, TenantSlug, TimeZoneName, TokenId};
use davhaven_ports::Clock;
use davhaven_wire::ApiTokenView;
use uuid::Uuid;

use crate::admin::{
    self, BootstrapRequest, EpochScope, PrincipalTokenRequest, SettingsFlags, SystemTokenOutcome, TokenOutcome,
    TokenSink,
};
use crate::assembly::{Assembly, Foundation};
use crate::config::Config;
use crate::error::ServerError;
use crate::healthcheck;
use crate::plugins::{self, CheckReport};
use crate::registry::registry;
use crate::server;
use crate::shutdown;
use crate::telemetry;

/// The command line of the `davhaven` binary.
#[derive(Debug, Parser)]
#[command(
    name = "davhaven",
    version,
    about = "Davhaven: a multi-tenant CalDAV and scheduling server",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// The TOML configuration file. The `DAVHAVEN_*` environment variables override it; without a file they are
    /// the whole configuration.
    #[arg(long, global = true, env = "DAVHAVEN_CONFIG", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the server: the listeners, the workers and the shutdown on SIGTERM.
    Serve,
    /// Apply the pending database migrations with the owner role (`database.migration_url`).
    Migrate,
    /// Ask /readyz of the ops listener; exit 0 when the instance is ready, 1 otherwise (for the container's
    /// HEALTHCHECK).
    Healthcheck(HealthcheckArgs),
    /// Inspect the configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Administrative tasks that run once from an operator or a deployment step.
    #[command(subcommand)]
    Admin(AdminCommand),
}

/// Arguments of `healthcheck`.
#[derive(Debug, Args)]
pub struct HealthcheckArgs {
    /// The address of the ops listener, when it is not the one in the configuration.
    #[arg(long, value_name = "HOST:PORT")]
    pub address: Option<std::net::SocketAddr>,

    /// How long to wait for the answer. The default is shorter than the 503 body of a slow component takes to be
    /// built (`davhaven_server::ops::COMPONENT_TIMEOUT`), so that a probe reports the component and not its own
    /// timeout.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = healthcheck::DEFAULT_TIMEOUT_TEXT,
        value_parser = parse_duration
    )]
    pub timeout: Duration,
}

/// The configuration commands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration and every secret file it names, and print the effective configuration (the defaults of
    /// this build with the settings of the file and the environment laid over them, secrets redacted). No database is
    /// contacted.
    Check(CheckArgs),
    /// Print the configuration reference of this build as Markdown (what `docs/configuration.md` contains).
    Reference,
}

/// Arguments of `config check`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Print only the settings that the file and the environment give, without the defaults of the keys they leave
    /// alone.
    #[arg(long)]
    pub explicit: bool,
}

/// The administrative commands.
#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Create a tenant and an administration token for it, from flags. Running it again changes nothing: a tenant
    /// that exists is left as it is and a valid token with the same label is not created again.
    Bootstrap(Box<BootstrapArgs>),
    /// Create, list and revoke the system tokens that `/api/v1/tenants` needs (scope `system:tenants`).
    #[command(subcommand)]
    SystemToken(SystemTokenCommand),
    /// Create, list and revoke the principal tokens of a tenant: the credentials with which an assistant or an
    /// integration acts as one principal on the API and on MCP (`mcp:*` scopes).
    #[command(subcommand)]
    PrincipalToken(PrincipalTokenCommand),
    /// Give every collection a new sync epoch: all outstanding sync tokens become invalid, so that clients resync
    /// after a database restore.
    BumpSyncEpoch(BumpArgs),
    /// Remove the audit events older than `retention.audit_days` with the owner credentials
    /// (`database.migration_url`); the runtime role cannot delete audit records.
    PurgeAudit,
    /// Seal the stored secrets (webhook signing secrets) again under the active key, so that a retired key can be
    /// removed from `security.keys`.
    RotateKeys,
}

/// The commands of `admin system-token`.
#[derive(Debug, Subcommand)]
pub enum SystemTokenCommand {
    /// Create a system token and show its secret once. Running it again with the same label changes nothing: a valid
    /// token with the label is not created again.
    Create(SystemTokenCreateArgs),
    /// List the system tokens (id, label, prefix, state); no secret is shown.
    List,
    /// Revoke the system token with this id.
    Revoke(SystemTokenRevokeArgs),
}

/// Arguments of `admin system-token create`.
#[derive(Debug, Args)]
pub struct SystemTokenCreateArgs {
    /// The label of the token; an existing valid token with this label is not created again.
    #[arg(long, value_name = "LABEL", default_value = "system")]
    pub label: String,

    /// The lifetime of the token (`90d`); it does not expire without this.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub expires_in: Option<Duration>,

    /// Write the secret of a new token to this file (created with mode 0600; an existing file is never
    /// overwritten).
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "print_token",
        required_unless_present = "print_token"
    )]
    pub token_file: Option<PathBuf>,

    /// Print the secret of a new token to standard output (and nothing else there).
    #[arg(long)]
    pub print_token: bool,
}

/// Arguments of `admin system-token revoke`.
#[derive(Debug, Args)]
pub struct SystemTokenRevokeArgs {
    /// The id of the token, as `admin system-token list` shows it.
    #[arg(value_name = "ID", value_parser = parse_token_id)]
    pub id: TokenId,
}

/// The commands of `admin principal-token`.
#[derive(Debug, Subcommand)]
pub enum PrincipalTokenCommand {
    /// Create a principal token and show its secret once. Running it again with the same principal and label changes
    /// nothing: a valid token with the label is not created again, so a token that is to be replaced needs a new label
    /// (revoke the old one when the new one is in use).
    Create(PrincipalTokenCreateArgs),
    /// List the principal tokens of a tenant (id, state, principal, prefix, expiry, scopes, label); no secret is shown.
    List(PrincipalTokenListArgs),
    /// Revoke the principal token with this id.
    Revoke(PrincipalTokenRevokeArgs),
}

/// Arguments of `admin principal-token create`.
#[derive(Debug, Args)]
pub struct PrincipalTokenCreateArgs {
    /// The slug of the tenant.
    #[arg(long, value_name = "SLUG", value_parser = parse_slug)]
    pub tenant: TenantSlug,

    /// The name of the principal the token acts as: any principal except a group (a user, a service principal or a
    /// resource); a group cannot act.
    #[arg(long, value_name = "NAME", value_parser = parse_principal)]
    pub principal: PrincipalName,

    /// The label of the token, which names the integration in the audit log; an existing valid token of the principal
    /// with this label is not created again.
    #[arg(long, value_name = "LABEL")]
    pub label: String,

    /// A scope of the token; repeat for several (`mcp:read`, `mcp:write`, `mcp:schedule_external`, `events:read`,
    /// `events:write`, `calendars:read`, `calendars:write`). A token with `mcp:*` scopes needs `--expires-in` and a
    /// tenant that switched MCP on.
    #[arg(long = "scope", value_name = "SCOPE", value_parser = parse_scope, required = true)]
    pub scopes: Vec<Scope>,

    /// The lifetime of the token (`90d`); required for `mcp:*` scopes, at most `security.max_mcp_token_days` (90).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub expires_in: Option<Duration>,

    /// Write the secret of a new token to this file (created with mode 0600; an existing file is never
    /// overwritten).
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "print_token",
        required_unless_present = "print_token"
    )]
    pub token_file: Option<PathBuf>,

    /// Print the secret of a new token to standard output (and nothing else there).
    #[arg(long)]
    pub print_token: bool,
}

/// Arguments of `admin principal-token list`.
#[derive(Debug, Args)]
pub struct PrincipalTokenListArgs {
    /// The slug of the tenant.
    #[arg(long, value_name = "SLUG", value_parser = parse_slug)]
    pub tenant: TenantSlug,

    /// Only the tokens of this principal.
    #[arg(long, value_name = "NAME", value_parser = parse_principal)]
    pub principal: Option<PrincipalName>,
}

/// Arguments of `admin principal-token revoke`.
#[derive(Debug, Args)]
pub struct PrincipalTokenRevokeArgs {
    /// The slug of the tenant the token belongs to.
    #[arg(long, value_name = "SLUG", value_parser = parse_slug)]
    pub tenant: TenantSlug,

    /// The id of the token, as `admin principal-token list` shows it.
    #[arg(value_name = "ID", value_parser = parse_token_id)]
    pub id: TokenId,
}

/// Arguments of `admin bootstrap`.
#[derive(Debug, Args)]
pub struct BootstrapArgs {
    /// The slug of the tenant: lower case letters, digits and `-`.
    #[arg(long, value_name = "SLUG", value_parser = parse_slug)]
    pub tenant: TenantSlug,

    /// The display name of a tenant that is created (the slug when absent).
    #[arg(long, value_name = "NAME")]
    pub display_name: Option<String>,

    /// The login domain of a tenant that is created (`name@domain` logins).
    #[arg(long, value_name = "DOMAIN", value_parser = parse_domain)]
    pub login_domain: Option<DomainName>,

    /// The default locale of mail and pages of a tenant that is created (`de`, `de-DE`, `en`; the application
    /// default is `en`).
    #[arg(long, value_name = "LOCALE", value_parser = parse_locale)]
    pub locale: Option<Locale>,

    /// The default time zone of principals without one, of a tenant that is created (an IANA name such as
    /// `Europe/Berlin`; the application default is `UTC`).
    #[arg(long, value_name = "ZONE", value_parser = parse_timezone)]
    pub timezone: Option<TimeZoneName>,

    /// The template theme of a tenant that is created. Without it the tenant follows `templates.default_theme`.
    #[arg(long, value_name = "THEME")]
    pub theme: Option<String>,

    /// The domain mail is sent from, for a tenant that is created: `noreply@DOMAIN` is the sender address. Mail cannot
    /// be sent for a tenant without one.
    #[arg(long, value_name = "DOMAIN", value_parser = parse_domain)]
    pub sender_domain: Option<DomainName>,

    /// The name shown after "via" in the sender of the mail of a tenant that is created (the display name of the
    /// tenant when absent).
    #[arg(long, value_name = "NAME")]
    pub sender_display_name: Option<String>,

    /// Whether a new user of a tenant that is created gets a personal calendar (`true` or `false`; the application
    /// default is `true`).
    #[arg(
        long,
        value_name = "BOOL",
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub auto_create_personal_calendar: Option<bool>,

    /// The reverse-DNS prefix of the identifiers of the Apple configuration profiles of a tenant that is created
    /// (`com.example`).
    #[arg(long, value_name = "PREFIX")]
    pub apple_identifier_prefix: Option<String>,

    /// The organization name shown in the configuration profiles of a tenant that is created.
    #[arg(long, value_name = "NAME")]
    pub organization_name: Option<String>,

    /// Whether the principals of a tenant that is created may use the MCP endpoint (`--mcp-enabled`, or
    /// `--mcp-enabled=false`; off by default). Principal tokens with `mcp:*` scopes are minted only for a tenant that
    /// switched it on.
    #[arg(
        long,
        value_name = "BOOL",
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub mcp_enabled: Option<bool>,

    /// The label of the administration token; an existing valid token with this label is not created again.
    #[arg(long, value_name = "LABEL", default_value = "bootstrap")]
    pub label: String,

    /// A scope of the token; repeat for several. Without any the token gets every scope a tenant token may hold
    /// without an expiry.
    #[arg(long = "scope", value_name = "SCOPE", value_parser = parse_scope)]
    pub scopes: Vec<Scope>,

    /// The lifetime of the token (`90d`); it does not expire without this.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub expires_in: Option<Duration>,

    /// Write the secret of a new token to this file (created with mode 0600; an existing file is never
    /// overwritten).
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "print_token",
        required_unless_present = "print_token"
    )]
    pub token_file: Option<PathBuf>,

    /// Print the secret of a new token to standard output (and nothing else there).
    #[arg(long)]
    pub print_token: bool,
}

/// Arguments of `admin bump-sync-epoch`.
#[derive(Debug, Args)]
pub struct BumpArgs {
    /// Every collection of every tenant.
    #[arg(long, conflicts_with = "tenant", required_unless_present = "tenant")]
    pub all: bool,

    /// Only the collections of this tenant.
    #[arg(long, value_name = "SLUG", value_parser = parse_slug)]
    pub tenant: Option<TenantSlug>,
}

fn parse_slug(text: &str) -> Result<TenantSlug, String> {
    TenantSlug::parse(text).map_err(|error| error.to_string())
}

fn parse_domain(text: &str) -> Result<DomainName, String> {
    DomainName::parse(text).map_err(|error| error.to_string())
}

fn parse_principal(text: &str) -> Result<PrincipalName, String> {
    PrincipalName::parse(text).map_err(|error| error.to_string())
}

fn parse_locale(text: &str) -> Result<Locale, String> {
    Locale::parse(text).map_err(|error| error.to_string())
}

fn parse_timezone(text: &str) -> Result<TimeZoneName, String> {
    TimeZoneName::parse(text).map_err(|error| error.to_string())
}

fn parse_scope(text: &str) -> Result<Scope, String> {
    text.parse::<Scope>().map_err(|error| error.to_string())
}

fn parse_duration(text: &str) -> Result<Duration, String> {
    humantime_serde::re::humantime::parse_duration(text)
        .map_err(|error| format!("`{text}` is not a duration like 30s, 5m or 90d: {error}"))
}

fn parse_token_id(text: &str) -> Result<TokenId, String> {
    Uuid::parse_str(text)
        .map(TokenId::from_uuid)
        .map_err(|_| format!("`{text}` is not a token id (a UUID, as `admin system-token list` shows it)"))
}

/// Loads the configuration without validating it: for the commands that need only part of it.
fn load(cli: &Cli) -> Result<Config, ServerError> {
    Ok(Config::load(cli.config.as_deref())?)
}

/// Loads and checks the whole configuration (every secret file is read).
///
/// The check reads files and loads and renders every theme (the template renderer judges its own table by doing what its
/// build does), which is blocking work: it runs on the blocking pool, not on a thread of the runtime that `serve` is about to
/// use for requests (`ENGINEERING_RULES` R14), through the function that the assembly uses as well
/// ([`plugins::check_on_blocking_pool`]).
async fn load_checked(
    cli: &Cli,
    registry: &Arc<davhaven_ports::PluginRegistry>,
) -> Result<(Arc<Config>, CheckReport), ServerError> {
    let config = Arc::new(load(cli)?);
    let report = plugins::check_on_blocking_pool(&config, registry).await?;
    Ok((config, report))
}

fn write_line(out: &mut dyn Write, line: impl std::fmt::Display) -> Result<(), ServerError> {
    writeln!(out, "{line}").map_err(|error| ServerError::io("cannot write the output", error))
}

/// `davhaven serve`: runs until the process is asked to stop.
///
/// The configuration is checked once, here; [`Foundation::assemble`] builds from that report and does not check it again.
async fn serve(cli: &Cli) -> Result<(), ServerError> {
    let registry = Arc::new(registry()?);
    let (config, report) = load_checked(cli, &registry).await?;
    let telemetry = telemetry::init(&config.observability)?;
    let metrics = telemetry::install_metrics()?;
    for warning in &report.warnings {
        tracing::warn!("{warning}");
    }
    let assembly = Foundation::new(Arc::clone(&config), &registry)?
        .assemble(&registry, report)
        .await?;
    let running = server::start(assembly, Some(metrics)).await?;
    tracing::info!(
        mode = %config.server.mode,
        version = env!("CARGO_PKG_VERSION"),
        listeners = ?running.addresses(),
        "davhaven started"
    );
    match shutdown::termination_signal().await {
        Ok(signal) => tracing::info!(signal, "termination requested"),
        Err(error) => tracing::error!(%error, "cannot wait for signals; stopping"),
    }
    let clean = running.shutdown().await;
    if !clean {
        tracing::warn!("some workers were cut off at the end of the grace period");
    }
    // Flushing the spans that are still queued blocks until the collector has them (or a timeout), so it must not
    // hold a thread of the runtime that the exporter itself needs.
    let flush = tokio::task::spawn_blocking(move || telemetry.shutdown());
    if tokio::time::timeout(shutdown::FLUSH_BUDGET, flush).await.is_err() {
        tracing::warn!("the trace exporter did not flush within its budget; the spans that are still queued are lost");
    }
    Ok(())
}

/// `davhaven migrate`.
#[cfg(feature = "store-postgres")]
async fn migrate(cli: &Cli, out: &mut dyn Write) -> Result<(), ServerError> {
    let config = load(cli)?;
    let _telemetry = telemetry::init(&config.observability)?;
    let report = admin::migrate(&config).await?;
    let version = |version: Option<i64>| version.map_or_else(|| "none".to_owned(), |version| version.to_string());
    if report.changed() {
        write_line(
            out,
            format_args!(
                "migrated the schema from version {} to {}",
                version(report.before),
                version(report.after)
            ),
        )?;
    } else {
        write_line(
            out,
            format_args!("the schema is up to date at version {}", version(report.after)),
        )?;
    }
    write_line(out, format_args!("role model: {}", report.role_model))
}

#[cfg(not(feature = "store-postgres"))]
#[expect(
    clippy::unused_async,
    reason = "the signature is that of the build with the PostgreSQL store"
)]
async fn migrate(_cli: &Cli, _out: &mut dyn Write) -> Result<(), ServerError> {
    Err(ServerError::Command(
        "this build does not include the PostgreSQL store (cargo feature `store-postgres`), so there is nothing to migrate"
            .to_owned(),
    ))
}

/// `davhaven healthcheck`.
async fn healthcheck(cli: &Cli, args: &HealthcheckArgs, out: &mut dyn Write) -> Result<(), ServerError> {
    let address = match args.address {
        Some(address) => address,
        None => healthcheck::ops_address(&load(cli)?)?,
    };
    let status = healthcheck::check(address, args.timeout).await?;
    write_line(out, status)
}

/// `davhaven config check`.
async fn config_check(cli: &Cli, args: &CheckArgs, out: &mut dyn Write) -> Result<(), ServerError> {
    let registry = Arc::new(registry()?);
    let (config, report) = load_checked(cli, &registry).await?;
    write_line(
        out,
        format_args!("configuration is valid (server.mode = {})", config.server.mode),
    )?;
    write_line(out, "")?;
    write_line(out, "plugins:")?;
    for selection in &report.selections {
        write_line(
            out,
            format_args!("  {:<18} {}", selection.kind.name, selection.names.join(", ")),
        )?;
    }
    write_line(out, "")?;
    write_line(out, "listeners:")?;
    for listener in &report.listeners {
        let routes: Vec<&str> = listener.routes.iter().map(|group| group.as_str()).collect();
        write_line(
            out,
            format_args!(
                "  {:<9} {}  {}",
                listener.name.as_str(),
                listener.bind,
                routes.join(", ")
            ),
        )?;
    }
    if let Some(active) = &report.active_key {
        write_line(out, "")?;
        write_line(out, format_args!("keys: {} (active: {active})", report.keys.join(", ")))?;
    }
    if report.profile_signer.is_on() {
        write_line(out, "")?;
        write_line(out, "profile signing: on (Apple configuration profiles are signed)")?;
    }
    for warning in &report.warnings {
        write_line(out, format_args!("warning: {warning}"))?;
    }
    write_line(out, "")?;
    let (heading, settings) = if args.explicit {
        (
            "settings from the file and the environment (secrets redacted; every other key has its default):",
            Config::explicit_settings(cli.config.as_deref())?,
        )
    } else {
        (
            "effective settings: the defaults of this build with the file and the environment laid over them (secrets \
             redacted; `plugin_settings` holds the table of every selected plugin):",
            config.effective_settings(cli.config.as_deref(), &registry)?,
        )
    };
    write_line(out, heading)?;
    let pretty = serde_json::to_string_pretty(&settings)
        .map_err(|error| ServerError::Command(format!("cannot render the settings: {error}")))?;
    write_line(out, pretty)
}

/// `davhaven config reference`.
fn config_reference(out: &mut dyn Write) -> Result<(), ServerError> {
    let registry = registry()?;
    write!(out, "{}", crate::docs::configuration_reference(&registry))
        .map_err(|error| ServerError::io("cannot write the output", error))
}

/// The moment `lifetime` after `now`, for `--expires-in`.
fn expiry(now: DateTime<Utc>, lifetime: Option<Duration>) -> Result<Option<DateTime<Utc>>, ServerError> {
    let Some(lifetime) = lifetime else {
        return Ok(None);
    };
    let too_long = || ServerError::Command("--expires-in is too long".to_owned());
    let delta = TimeDelta::from_std(lifetime).map_err(|_| too_long())?;
    now.checked_add_signed(delta).map(Some).ok_or_else(too_long)
}

/// The settings the flags of `admin bootstrap` give.
fn settings_flags(args: &BootstrapArgs) -> SettingsFlags {
    SettingsFlags {
        locale: args.locale.clone(),
        timezone: args.timezone,
        theme: args.theme.clone(),
        sender_domain: args.sender_domain.clone(),
        sender_display_name: args.sender_display_name.clone(),
        auto_create_personal_calendar: args.auto_create_personal_calendar,
        apple_identifier_prefix: args.apple_identifier_prefix.clone(),
        organization_name: args.organization_name.clone(),
        mcp_enabled: args.mcp_enabled,
    }
}

/// `davhaven admin bootstrap`.
async fn bootstrap(cli: &Cli, args: &BootstrapArgs, out: &mut dyn Write) -> Result<(), ServerError> {
    let registry = Arc::new(registry()?);
    let (config, report) = load_checked(cli, &registry).await?;
    require_keys(&config, "admin bootstrap")?;
    let _telemetry = telemetry::init(&config.observability)?;
    let assembly = assemble_for_command(config, &registry, report).await?;
    let now = assembly.deps.clock.now();
    let expires_at = expiry(now, args.expires_in)?;
    let scopes = if args.scopes.is_empty() {
        admin::default_scopes()
    } else {
        args.scopes.iter().copied().collect::<ScopeSet>()
    };
    let request = BootstrapRequest {
        tenant: args.tenant.clone(),
        display_name: args.display_name.clone(),
        login_domain: args.login_domain.clone(),
        settings: settings_flags(args),
        label: args.label.clone(),
        scopes,
        expires_at,
    };
    let sink = match &args.token_file {
        Some(path) => TokenSink::File(path.clone()),
        None => TokenSink::Stdout,
    };
    let result = admin::bootstrap(&assembly.deps, &assembly.services, &request, &sink, out).await;
    assembly_shutdown(assembly).await;
    let outcome = result?;
    // Everything but the secret goes to standard error, so that `--print-token > file` captures the secret alone.
    let mut err = std::io::stderr().lock();
    let said = |error: std::io::Error| ServerError::io("cannot write the report", error);
    writeln!(
        err,
        "tenant {} {}",
        outcome.tenant.slug,
        if outcome.tenant_created { "created" } else { "exists" }
    )
    .map_err(said)?;
    for difference in &outcome.differences {
        writeln!(
            err,
            "warning: the existing tenant differs in {difference}; it was not changed"
        )
        .map_err(said)?;
    }
    match &outcome.token {
        TokenOutcome::Created(token) => {
            writeln!(
                err,
                "token `{}` created; its secret was written to {} and is not shown again",
                token.label,
                sink_name(&sink)
            )
            .map_err(said)?;
        }
        TokenOutcome::Exists {
            token,
            missing_scopes,
            expiry_differs,
        } => {
            writeln!(
                err,
                "token `{}` exists already; its secret cannot be shown again",
                token.label
            )
            .map_err(said)?;
            report_existing_token(&mut err, token, missing_scopes, *expiry_differs)?;
        }
    }
    Ok(())
}

/// What an existing token lacks of what a run asked for, as warnings on `err`: the same for the administration token of
/// `admin bootstrap` and the tokens of `admin principal-token create`. The secret of an existing token cannot be shown
/// again, so what differs is the only thing the operator can act on.
fn report_existing_token(
    err: &mut dyn Write,
    token: &ApiTokenView,
    missing_scopes: &[Scope],
    expiry_differs: bool,
) -> Result<(), ServerError> {
    let said = |error: std::io::Error| ServerError::io("cannot write the report", error);
    if expiry_differs {
        let state = match token.expires_at {
            Some(_) => format!("expires at {}", expiry_text(token.expires_at)),
            None => "does not expire".to_owned(),
        };
        writeln!(
            err,
            "warning: the existing token {state}, which differs from what was asked for with --expires-in; revoke it, \
             or choose another label, to get a token that matches"
        )
        .map_err(said)?;
    }
    if !missing_scopes.is_empty() {
        let missing: Vec<&str> = missing_scopes.iter().map(|scope| scope.as_str()).collect();
        writeln!(
            err,
            "warning: the existing token lacks the scopes {}; revoke it, or choose another label, to get a token that \
             has them",
            missing.join(", ")
        )
        .map_err(said)?;
    }
    Ok(())
}

/// How a listing shows the state of a token at `now`.
fn token_state(
    revoked_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> &'static str {
    if revoked_at.is_some() {
        "revoked"
    } else if expires_at.is_some_and(|expires| expires <= now) {
        "expired"
    } else {
        "valid"
    }
}

/// How a listing shows the expiry of a token: the time in UTC, or `never`.
fn expiry_text(expires_at: Option<DateTime<Utc>>) -> String {
    expires_at.map_or_else(
        || "never".to_owned(),
        |at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

/// Where a token's secret goes, for the report.
fn sink_name(sink: &TokenSink) -> String {
    match sink {
        TokenSink::File(path) => path.display().to_string(),
        TokenSink::Stdout => "standard output".to_owned(),
    }
}

/// Refuses a command that hashes or seals secrets when no key ring is configured: without `security.keys` the process
/// makes up a key ring of its own (development mode), so whatever the command stores could never be verified by
/// the server.
fn require_keys(config: &Config, command: &str) -> Result<(), ServerError> {
    if config.security.keys.is_empty() {
        return Err(ServerError::Command(format!(
            "{command} needs signing keys (`security.keys`): without them the secrets it stores depend on a key ring \
             that exists only in this process, and the server could not verify them"
        )));
    }
    Ok(())
}

/// Builds the application for an administrative command that needs the services; nothing is served.
async fn assemble_for_command(
    config: Arc<Config>,
    registry: &davhaven_ports::PluginRegistry,
    report: CheckReport,
) -> Result<Assembly, ServerError> {
    Foundation::new(config, registry)?.assemble(registry, report).await
}

/// Runs the shutdown hooks of an assembly that was built for a command (the database closes its pool).
async fn assembly_shutdown(assembly: Assembly) {
    let hooks = assembly.hooks.into_iter().rev().map(|hook| (hook.name, hook.lifecycle));
    shutdown::run_hooks(shutdown::HOOK_BUDGET, hooks).await;
}

/// `davhaven admin system-token ...`.
async fn system_token(cli: &Cli, command: &SystemTokenCommand, out: &mut dyn Write) -> Result<(), ServerError> {
    let registry = Arc::new(registry()?);
    let (config, report) = load_checked(cli, &registry).await?;
    if matches!(command, SystemTokenCommand::Create(_)) {
        require_keys(&config, "admin system-token create")?;
    }
    let _telemetry = telemetry::init(&config.observability)?;
    let assembly = assemble_for_command(config, &registry, report).await?;
    let result = run_system_token(&assembly, command, out).await;
    assembly_shutdown(assembly).await;
    result
}

/// What a system-token command does with an assembled application.
async fn run_system_token(
    assembly: &Assembly,
    command: &SystemTokenCommand,
    out: &mut dyn Write,
) -> Result<(), ServerError> {
    let deps = &assembly.deps;
    match command {
        SystemTokenCommand::Create(args) => {
            let expires_at = expiry(deps.clock.now(), args.expires_in)?;
            let sink = match &args.token_file {
                Some(path) => TokenSink::File(path.clone()),
                None => TokenSink::Stdout,
            };
            let outcome = admin::system_token(deps, &args.label, expires_at, &sink, out).await?;
            // Everything but the secret goes to standard error.
            let mut err = std::io::stderr().lock();
            let said = |error: std::io::Error| ServerError::io("cannot write the report", error);
            let written = match outcome {
                SystemTokenOutcome::Created(token) => writeln!(
                    err,
                    "system token `{}` ({}) created; its secret was written to {} and is not shown again",
                    token.label,
                    token.id,
                    sink_name(&sink)
                ),
                SystemTokenOutcome::Exists(token) => writeln!(
                    err,
                    "system token `{}` ({}) exists already; its secret cannot be shown again",
                    token.label, token.id
                ),
            };
            written.map_err(said)
        }
        SystemTokenCommand::List => {
            let now = deps.clock.now();
            let tokens = admin::system_tokens(deps).await?;
            if tokens.is_empty() {
                return write_line(out, "there are no system tokens");
            }
            for token in tokens {
                let state = token_state(token.revoked_at, token.expires_at, now);
                let expires = expiry_text(token.expires_at);
                write_line(
                    out,
                    format_args!(
                        "{}  {:<7}  {}  expires {expires}  {}",
                        token.id, state, token.prefix, token.label
                    ),
                )?;
            }
            Ok(())
        }
        SystemTokenCommand::Revoke(args) => {
            admin::revoke_system_token(deps, args.id).await?;
            write_line(out, format_args!("system token {} revoked", args.id))
        }
    }
}

/// `davhaven admin principal-token ...`.
async fn principal_token(cli: &Cli, command: &PrincipalTokenCommand, out: &mut dyn Write) -> Result<(), ServerError> {
    let registry = Arc::new(registry()?);
    let (config, report) = load_checked(cli, &registry).await?;
    if matches!(command, PrincipalTokenCommand::Create(_)) {
        require_keys(&config, "admin principal-token create")?;
    }
    let _telemetry = telemetry::init(&config.observability)?;
    let assembly = assemble_for_command(config, &registry, report).await?;
    let result = run_principal_token(&assembly, command, out).await;
    assembly_shutdown(assembly).await;
    result
}

/// What a principal-token command does with an assembled application.
async fn run_principal_token(
    assembly: &Assembly,
    command: &PrincipalTokenCommand,
    out: &mut dyn Write,
) -> Result<(), ServerError> {
    let deps = &assembly.deps;
    match command {
        PrincipalTokenCommand::Create(args) => create_principal_token(assembly, args, out).await,
        PrincipalTokenCommand::List(args) => list_principal_tokens(assembly, args, out).await,
        PrincipalTokenCommand::Revoke(args) => {
            admin::revoke_principal_token(deps, &assembly.services, &args.tenant, args.id).await?;
            write_line(
                out,
                format_args!("principal token {} of tenant {} revoked", args.id, args.tenant),
            )
        }
    }
}

/// `davhaven admin principal-token create`: the secret goes to the sink, everything else to standard error.
async fn create_principal_token(
    assembly: &Assembly,
    args: &PrincipalTokenCreateArgs,
    out: &mut dyn Write,
) -> Result<(), ServerError> {
    let deps = &assembly.deps;
    let request = PrincipalTokenRequest {
        tenant: args.tenant.clone(),
        principal: args.principal.clone(),
        label: args.label.clone(),
        scopes: args.scopes.iter().copied().collect::<ScopeSet>(),
        expires_at: expiry(deps.clock.now(), args.expires_in)?,
    };
    let sink = match &args.token_file {
        Some(path) => TokenSink::File(path.clone()),
        None => TokenSink::Stdout,
    };
    let outcome = admin::principal_token(deps, &assembly.services, &request, &sink, out).await?;
    let mut err = std::io::stderr().lock();
    let said = |error: std::io::Error| ServerError::io("cannot write the report", error);
    match outcome {
        TokenOutcome::Created(token) => writeln!(
            err,
            "principal token `{}` ({}) of `{}` created; its secret was written to {} and is not shown again",
            token.label,
            token.id,
            args.principal,
            sink_name(&sink)
        )
        .map_err(said),
        TokenOutcome::Exists {
            token,
            missing_scopes,
            expiry_differs,
        } => {
            writeln!(
                err,
                "principal token `{}` ({}) of `{}` exists already; its secret cannot be shown again",
                token.label, token.id, args.principal
            )
            .map_err(said)?;
            report_existing_token(&mut err, &token, &missing_scopes, expiry_differs)
        }
    }
}

/// `davhaven admin principal-token list`: one line per token, never a secret.
async fn list_principal_tokens(
    assembly: &Assembly,
    args: &PrincipalTokenListArgs,
    out: &mut dyn Write,
) -> Result<(), ServerError> {
    let deps = &assembly.deps;
    let now = deps.clock.now();
    let tokens = admin::principal_tokens(deps, &assembly.services, &args.tenant, args.principal.as_ref()).await?;
    if tokens.is_empty() {
        return write_line(out, "there are no principal tokens");
    }
    for token in tokens {
        let state = token_state(token.revoked_at, token.expires_at, now);
        let expires = expiry_text(token.expires_at);
        let principal = token.principal.as_ref().map_or("-", PrincipalName::as_str);
        write_line(
            out,
            format_args!(
                "{}  {:<7}  {}  {}  expires {expires}  [{}]  {}",
                token.id,
                state,
                principal,
                token.prefix,
                token.scopes.to_strings().join(","),
                token.label
            ),
        )?;
    }
    Ok(())
}

/// `davhaven admin bump-sync-epoch`.
async fn bump_sync_epoch(cli: &Cli, args: &BumpArgs, out: &mut dyn Write) -> Result<(), ServerError> {
    let config = Arc::new(load(cli)?);
    let _telemetry = telemetry::init(&config.observability)?;
    let registry = registry()?;
    // The store seals nothing: this job holds none of the key files.
    let foundation = Foundation::for_store(config, &registry)?;
    let built = foundation.database(&registry).await?;
    let scope = match &args.tenant {
        Some(slug) => EpochScope::Tenant(slug.clone()),
        None => EpochScope::All,
    };
    let result = admin::bump_sync_epoch(built.port.as_ref(), &scope).await;
    if let Some(lifecycle) = &built.lifecycle
        && !shutdown::within(shutdown::HOOK_BUDGET, lifecycle.shutdown()).await
    {
        tracing::warn!("the database did not shut down in time");
    }
    let changed = result?;
    write_line(out, format_args!("{changed} collections have a new sync epoch"))
}

/// `davhaven admin purge-audit`.
#[cfg(feature = "store-postgres")]
async fn purge_audit(cli: &Cli, out: &mut dyn Write) -> Result<(), ServerError> {
    let config = load(cli)?;
    let _telemetry = telemetry::init(&config.observability)?;
    let removed = admin::purge_audit(&config, &davhaven_ports::SystemClock).await?;
    write_line(out, format_args!("{removed} audit events removed"))
}

#[cfg(not(feature = "store-postgres"))]
#[expect(
    clippy::unused_async,
    reason = "the signature is that of the build with the PostgreSQL store"
)]
async fn purge_audit(_cli: &Cli, _out: &mut dyn Write) -> Result<(), ServerError> {
    Err(ServerError::Command(
        "this build does not include the PostgreSQL store (cargo feature `store-postgres`)".to_owned(),
    ))
}

/// `davhaven admin rotate-keys`.
async fn rotate_keys(cli: &Cli, out: &mut dyn Write) -> Result<(), ServerError> {
    let registry = Arc::new(registry()?);
    let (config, report) = load_checked(cli, &registry).await?;
    require_keys(&config, "admin rotate-keys")?;
    let _telemetry = telemetry::init(&config.observability)?;
    let assembly = assemble_for_command(config, &registry, report).await?;
    let result = admin::rotate_keys(&assembly.core).await;
    assembly_shutdown(assembly).await;
    let report = result?;
    write_line(
        out,
        format_args!(
            "active key `{}`: {} secrets resealed, {} already used it",
            report.active_key, report.total.resealed, report.total.current
        ),
    )?;
    if report.total.failed > 0 {
        for (name, counts) in &report.by_resealer {
            if counts.failed > 0 {
                write_line(
                    out,
                    format_args!("  {name}: {} secrets could not be resealed", counts.failed),
                )?;
            }
        }
        return Err(ServerError::Command(format!(
            "{} secrets could not be resealed (see the log); keep the retired keys in `security.keys`",
            report.total.failed
        )));
    }
    Ok(())
}

/// Runs a parsed command line. The result is what `main` turns into the exit status.
///
/// # Errors
///
/// Whatever the command fails with; the message is meant for the operator and never contains a secret.
pub async fn execute(cli: &Cli, out: &mut dyn Write) -> Result<(), ServerError> {
    match &cli.command {
        Command::Serve => serve(cli).await,
        Command::Migrate => migrate(cli, out).await,
        Command::Healthcheck(args) => healthcheck(cli, args, out).await,
        Command::Config(ConfigCommand::Check(args)) => config_check(cli, args, out).await,
        Command::Config(ConfigCommand::Reference) => config_reference(out),
        Command::Admin(AdminCommand::Bootstrap(args)) => bootstrap(cli, args, out).await,
        Command::Admin(AdminCommand::SystemToken(command)) => system_token(cli, command, out).await,
        Command::Admin(AdminCommand::PrincipalToken(command)) => principal_token(cli, command, out).await,
        Command::Admin(AdminCommand::BumpSyncEpoch(args)) => bump_sync_epoch(cli, args, out).await,
        Command::Admin(AdminCommand::PurgeAudit) => purge_audit(cli, out).await,
        Command::Admin(AdminCommand::RotateKeys) => rotate_keys(cli, out).await,
    }
}

/// The runtime a command runs on: the server gets a pool of worker threads, everything else (the probe of the image's
/// `HEALTHCHECK` every 30 seconds, one-off administrative jobs, the configuration check) runs on the calling thread.
fn runtime_for(command: &Command) -> std::io::Result<tokio::runtime::Runtime> {
    let mut builder = if matches!(command, Command::Serve) {
        tokio::runtime::Builder::new_multi_thread()
    } else {
        tokio::runtime::Builder::new_current_thread()
    };
    builder.enable_all().build()
}

/// The body of `main`: parses the arguments, runs the command on its runtime and returns the exit status.
pub fn main_with<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            // `--help` and `--version` are not failures.
            let code = if error.use_stderr() { 2 } else { 0 };
            drop(error.print());
            return ExitCode::from(code);
        }
    };
    let runtime = match runtime_for(&cli.command) {
        Ok(runtime) => runtime,
        Err(error) => {
            drop(writeln!(
                std::io::stderr(),
                "davhaven: cannot start the async runtime: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };
    let mut stdout = std::io::stdout().lock();
    let result = runtime.block_on(execute(&cli, &mut stdout));
    // A blocking thread that is stuck (a flush that waits for a collector) must not keep the process from ending.
    runtime.shutdown_timeout(shutdown::RUNTIME_BUDGET);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            drop(stdout.flush());
            drop(writeln!(std::io::stderr(), "davhaven: {error}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn parse(arguments: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("davhaven").chain(arguments.iter().copied()))
    }

    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_commands_of_the_deployment_contract_parse() {
        let cli = parse(&["--config", "/etc/davhaven/davhaven.toml", "serve"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/etc/davhaven/davhaven.toml")));
        assert!(matches!(cli.command, Command::Serve));
        // The global flag may follow the subcommand.
        let cli = parse(&["migrate", "--config", "c.toml"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("c.toml")));
        assert!(matches!(cli.command, Command::Migrate));
        assert!(matches!(
            parse(&["healthcheck"]).unwrap().command,
            Command::Healthcheck(HealthcheckArgs { address: None, .. })
        ));
        assert!(matches!(
            parse(&["config", "check"]).unwrap().command,
            Command::Config(ConfigCommand::Check(CheckArgs { explicit: false }))
        ));
        assert!(matches!(
            parse(&["config", "check", "--explicit"]).unwrap().command,
            Command::Config(ConfigCommand::Check(CheckArgs { explicit: true }))
        ));
        assert!(matches!(
            parse(&["config", "reference"]).unwrap().command,
            Command::Config(ConfigCommand::Reference)
        ));
        let Command::Admin(AdminCommand::BumpSyncEpoch(bump)) =
            parse(&["admin", "bump-sync-epoch", "--all"]).unwrap().command
        else {
            panic!("bump-sync-epoch --all");
        };
        assert!(bump.all && bump.tenant.is_none());
        assert!(matches!(
            parse(&["admin", "purge-audit"]).unwrap().command,
            Command::Admin(AdminCommand::PurgeAudit)
        ));
        assert!(matches!(
            parse(&["admin", "rotate-keys"]).unwrap().command,
            Command::Admin(AdminCommand::RotateKeys)
        ));
    }

    #[test]
    fn the_healthcheck_default_comes_from_the_constant_of_the_probe() {
        let Command::Healthcheck(args) = parse(&["healthcheck"]).unwrap().command else {
            panic!("healthcheck");
        };
        assert_eq!(args.timeout, healthcheck::DEFAULT_TIMEOUT);
        assert_eq!(
            parse_duration(healthcheck::DEFAULT_TIMEOUT_TEXT).unwrap(),
            healthcheck::DEFAULT_TIMEOUT,
            "the text clap shows and the duration the probe uses cannot drift apart"
        );
    }

    #[test]
    fn system_tokens_are_created_listed_and_revoked_from_the_command_line() {
        let Command::Admin(AdminCommand::SystemToken(SystemTokenCommand::Create(args))) = parse(&[
            "admin",
            "system-token",
            "create",
            "--label",
            "ci",
            "--expires-in",
            "30d",
            "--token-file",
            "/run/secrets/system-token",
        ])
        .unwrap()
        .command
        else {
            panic!("system-token create");
        };
        assert_eq!(args.label, "ci");
        assert_eq!(args.expires_in, Some(Duration::from_hours(30 * 24)));
        assert_eq!(args.token_file, Some(PathBuf::from("/run/secrets/system-token")));
        assert!(!args.print_token);
        let Command::Admin(AdminCommand::SystemToken(SystemTokenCommand::Create(defaults))) =
            parse(&["admin", "system-token", "create", "--print-token"])
                .unwrap()
                .command
        else {
            panic!("system-token create --print-token");
        };
        assert_eq!(defaults.label, "system");
        assert!(matches!(
            parse(&["admin", "system-token", "list"]).unwrap().command,
            Command::Admin(AdminCommand::SystemToken(SystemTokenCommand::List))
        ));
        let id = "018f3c1e-7b2a-7c3d-9e4f-000000000001";
        let Command::Admin(AdminCommand::SystemToken(SystemTokenCommand::Revoke(revoke))) =
            parse(&["admin", "system-token", "revoke", id]).unwrap().command
        else {
            panic!("system-token revoke");
        };
        assert_eq!(revoke.id.as_uuid().to_string(), id);
        for bad in [
            vec!["admin", "system-token"],
            vec!["admin", "system-token", "create"],
            vec!["admin", "system-token", "create", "--print-token", "--token-file", "x"],
            vec!["admin", "system-token", "revoke"],
            vec!["admin", "system-token", "revoke", "not-an-id"],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario of the command line: what parses and what does not"
    )]
    fn principal_tokens_are_created_listed_and_revoked_from_the_command_line() {
        let Command::Admin(AdminCommand::PrincipalToken(PrincipalTokenCommand::Create(args))) = parse(&[
            "admin",
            "principal-token",
            "create",
            "--tenant",
            "acme",
            "--principal",
            "robot",
            "--label",
            "assistant-mcp",
            "--scope",
            "mcp:read",
            "--scope",
            "mcp:write",
            "--expires-in",
            "30d",
            "--token-file",
            "/run/secrets/robot-token",
        ])
        .unwrap()
        .command
        else {
            panic!("principal-token create");
        };
        assert_eq!(args.tenant.as_str(), "acme");
        assert_eq!(args.principal.as_str(), "robot");
        assert_eq!(args.label, "assistant-mcp");
        assert_eq!(args.scopes, vec![Scope::McpRead, Scope::McpWrite]);
        assert_eq!(args.expires_in, Some(Duration::from_hours(30 * 24)));
        assert_eq!(args.token_file, Some(PathBuf::from("/run/secrets/robot-token")));
        assert!(!args.print_token);
        let Command::Admin(AdminCommand::PrincipalToken(PrincipalTokenCommand::Create(printed))) = parse(&[
            "admin",
            "principal-token",
            "create",
            "--tenant",
            "acme",
            "--principal",
            "olivia",
            "--label",
            "ops",
            "--scope",
            "events:read",
            "--print-token",
        ])
        .unwrap()
        .command
        else {
            panic!("principal-token create --print-token");
        };
        assert!(printed.print_token && printed.expires_in.is_none());

        let Command::Admin(AdminCommand::PrincipalToken(PrincipalTokenCommand::List(list))) = parse(&[
            "admin",
            "principal-token",
            "list",
            "--tenant",
            "acme",
            "--principal",
            "robot",
        ])
        .unwrap()
        .command
        else {
            panic!("principal-token list");
        };
        assert_eq!(list.principal.as_ref().map(PrincipalName::as_str), Some("robot"));
        let id = "018f3c1e-7b2a-7c3d-9e4f-000000000001";
        let Command::Admin(AdminCommand::PrincipalToken(PrincipalTokenCommand::Revoke(revoke))) =
            parse(&["admin", "principal-token", "revoke", "--tenant", "acme", id])
                .unwrap()
                .command
        else {
            panic!("principal-token revoke");
        };
        assert_eq!(
            (revoke.tenant.as_str(), revoke.id.as_uuid().to_string()),
            ("acme", id.to_owned())
        );

        let create = ["admin", "principal-token", "create"];
        let full = [
            "--tenant",
            "acme",
            "--principal",
            "robot",
            "--label",
            "x",
            "--scope",
            "mcp:read",
        ];
        for missing in 0..4 {
            // Every one of tenant, principal, label and scope is required.
            let mut arguments: Vec<&str> = create.to_vec();
            let mut index = 0;
            while index < 8 {
                if index / 2 != missing {
                    arguments.extend_from_slice(&full[index..index + 2]);
                }
                index += 2;
            }
            arguments.push("--print-token");
            assert!(parse(&arguments).is_err(), "{arguments:?}");
        }
        for bad in [
            vec!["admin", "principal-token"],
            vec!["admin", "principal-token", "create"],
            // The secret goes to a file or to standard output, not to both and not nowhere.
            vec![
                "admin",
                "principal-token",
                "create",
                "--tenant",
                "acme",
                "--principal",
                "robot",
                "--label",
                "x",
                "--scope",
                "mcp:read",
                "--print-token",
                "--token-file",
                "x",
            ],
            vec![
                "admin",
                "principal-token",
                "create",
                "--tenant",
                "acme",
                "--principal",
                "robot",
                "--label",
                "x",
                "--scope",
                "mcp:read",
            ],
            // A scope and a principal name that do not exist.
            vec![
                "admin",
                "principal-token",
                "create",
                "--tenant",
                "acme",
                "--principal",
                "robot",
                "--label",
                "x",
                "--scope",
                "mcp:everything",
                "--print-token",
            ],
            vec![
                "admin",
                "principal-token",
                "create",
                "--tenant",
                "acme",
                "--principal",
                "Not A Name",
                "--label",
                "x",
                "--scope",
                "mcp:read",
                "--print-token",
            ],
            vec!["admin", "principal-token", "list"],
            vec!["admin", "principal-token", "revoke", "--tenant", "acme"],
            vec!["admin", "principal-token", "revoke", "--tenant", "acme", "not-an-id"],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario of the command line: what parses and what does not"
    )]
    fn bootstrap_takes_the_settings_of_the_tenant_as_flags() {
        let Command::Admin(AdminCommand::Bootstrap(args)) = parse(&[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--print-token",
            "--locale",
            "de-DE",
            "--timezone",
            "Europe/Berlin",
            "--theme",
            "corporate",
            "--sender-domain",
            "mail.acme.example",
            "--sender-display-name",
            "Acme Courses",
            "--auto-create-personal-calendar=false",
            "--apple-identifier-prefix",
            "example.acme",
            "--organization-name",
            "Acme Courses Ltd.",
            "--mcp-enabled",
        ])
        .unwrap()
        .command
        else {
            panic!("bootstrap");
        };
        let flags = settings_flags(&args);
        assert_eq!(flags.locale.as_ref().map(Locale::as_str), Some("de-DE"));
        assert_eq!(flags.timezone.map(|zone| zone.as_str()), Some("Europe/Berlin"));
        assert_eq!(flags.theme.as_deref(), Some("corporate"));
        assert_eq!(
            flags.sender_domain.as_ref().map(DomainName::as_str),
            Some("mail.acme.example")
        );
        assert_eq!(flags.sender_display_name.as_deref(), Some("Acme Courses"));
        assert_eq!(flags.auto_create_personal_calendar, Some(false));
        assert_eq!(flags.apple_identifier_prefix.as_deref(), Some("example.acme"));
        assert_eq!(flags.organization_name.as_deref(), Some("Acme Courses Ltd."));
        assert_eq!(flags.mcp_enabled, Some(true), "the bare switch turns it on");

        // Without a flag nothing is set, and the switches take an explicit value after an equals sign.
        let Command::Admin(AdminCommand::Bootstrap(bare)) =
            parse(&["admin", "bootstrap", "--tenant", "acme", "--print-token"])
                .unwrap()
                .command
        else {
            panic!("bootstrap");
        };
        assert!(settings_flags(&bare).is_empty());
        let Command::Admin(AdminCommand::Bootstrap(off)) = parse(&[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--print-token",
            "--mcp-enabled=false",
            "--auto-create-personal-calendar",
        ])
        .unwrap()
        .command
        else {
            panic!("bootstrap");
        };
        let flags = settings_flags(&off);
        assert_eq!(flags.mcp_enabled, Some(false));
        assert_eq!(flags.auto_create_personal_calendar, Some(true));

        for bad in [
            vec![
                "admin",
                "bootstrap",
                "--tenant",
                "acme",
                "--print-token",
                "--locale",
                "not a locale",
            ],
            vec![
                "admin",
                "bootstrap",
                "--tenant",
                "acme",
                "--print-token",
                "--timezone",
                "Mars/Olympus",
            ],
            vec![
                "admin",
                "bootstrap",
                "--tenant",
                "acme",
                "--print-token",
                "--sender-domain",
                "not a domain",
            ],
            vec![
                "admin",
                "bootstrap",
                "--tenant",
                "acme",
                "--print-token",
                "--mcp-enabled=maybe",
            ],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn bootstrap_takes_a_tenant_and_a_place_for_the_secret() {
        let Command::Admin(AdminCommand::Bootstrap(args)) = parse(&[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--display-name",
            "Acme Corp",
            "--login-domain",
            "acme.example",
            "--scope",
            "events:read",
            "--scope",
            "events:write",
            "--expires-in",
            "90d",
            "--token-file",
            "/run/secrets/token",
        ])
        .unwrap()
        .command
        else {
            panic!("bootstrap");
        };
        assert_eq!(args.tenant.as_str(), "acme");
        assert_eq!(args.display_name.as_deref(), Some("Acme Corp"));
        assert_eq!(args.login_domain.unwrap().as_str(), "acme.example");
        assert_eq!(args.scopes, vec![Scope::EventsRead, Scope::EventsWrite]);
        assert_eq!(args.expires_in, Some(Duration::from_hours(90 * 24)));
        assert_eq!(args.label, "bootstrap");
        assert_eq!(args.token_file, Some(PathBuf::from("/run/secrets/token")));
        assert!(!args.print_token);
        assert!(parse(&["admin", "bootstrap", "--tenant", "acme", "--print-token"]).is_ok());
    }

    #[test]
    fn mistakes_are_refused_with_a_usage_error() {
        for bad in [
            vec![],
            vec!["serv"],
            vec!["admin"],
            vec!["admin", "bump-sync-epoch"],
            vec!["admin", "bump-sync-epoch", "--all", "--tenant", "acme"],
            vec!["admin", "bootstrap", "--tenant", "acme"],
            vec!["admin", "bootstrap", "--tenant", "Not A Slug", "--print-token"],
            vec![
                "admin",
                "bootstrap",
                "--tenant",
                "acme",
                "--print-token",
                "--token-file",
                "x",
            ],
            vec![
                "admin",
                "bootstrap",
                "--tenant",
                "acme",
                "--print-token",
                "--scope",
                "everything",
            ],
            vec![
                "admin",
                "bootstrap",
                "--tenant",
                "acme",
                "--print-token",
                "--expires-in",
                "soon",
            ],
            vec!["healthcheck", "--address", "not-an-address"],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn help_and_version_are_not_failures() {
        let help = parse(&["--help"]).unwrap_err();
        assert!(!help.use_stderr());
        let version = parse(&["--version"]).unwrap_err();
        assert!(!version.use_stderr());
        assert!(version.to_string().contains(env!("CARGO_PKG_VERSION")));
        assert_eq!(main_with(["davhaven", "--version"]), ExitCode::SUCCESS);
        assert_eq!(main_with(["davhaven", "bogus"]), ExitCode::from(2));
    }

    #[test]
    fn only_the_server_gets_a_pool_of_worker_threads() {
        for (arguments, workers) in [
            (vec!["serve"], true),
            (vec!["healthcheck"], false),
            (vec!["migrate"], false),
            (vec!["config", "check"], false),
            (vec!["admin", "rotate-keys"], false),
            (vec!["admin", "system-token", "list"], false),
        ] {
            let cli = parse(&arguments).unwrap();
            let runtime = runtime_for(&cli.command).unwrap();
            // A current-thread runtime runs its tasks on the thread that blocks on it; a pool runs them on its workers.
            let thread = runtime.block_on(async { tokio::spawn(async { std::thread::current().id() }).await.unwrap() });
            let here = std::thread::current().id();
            assert_eq!(thread == here, !workers, "{arguments:?}");
        }
    }

    #[test]
    fn the_key_requirement_names_the_command_in_one_readable_sentence() {
        let config = Config::from_toml("[server]\npublic_base_url = \"https://cal.example.org\"").unwrap();
        let message = require_keys(&config, "admin bootstrap").unwrap_err().to_string();
        assert!(
            message.starts_with("admin bootstrap needs signing keys (`security.keys`)"),
            "{message}"
        );
        assert!(
            !message.contains("  "),
            "the message has a run of spaces where a line continuation was lost: {message:?}"
        );
        assert!(
            message.contains("key ring that exists only in this process"),
            "{message}"
        );
    }

    #[test]
    #[expect(
        clippy::result_large_err,
        reason = "figment's Jail API fixes the error type of the closure"
    )]
    fn the_environment_names_the_configuration_file() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("DAVHAVEN_CONFIG", "/etc/davhaven/davhaven.toml");
            let cli = parse(&["serve"]).map_err(|error| error.to_string())?;
            assert_eq!(cli.config, Some(PathBuf::from("/etc/davhaven/davhaven.toml")));
            Ok(())
        });
    }

    /// A development configuration file with the memory adapters and `extra`.
    fn dev_file(directory: &std::path::Path, extra: &str) -> PathBuf {
        let path = directory.join("davhaven.toml");
        std::fs::write(
            &path,
            format!(
                "[server]\nmode = \"dev\"\npublic_base_url = \"http://localhost:8080\"\n\
                 [plugins]\nstore = \"memory\"\nmail_transport = \"memory\"\nhttp_client = \"recording\"\n{extra}"
            ),
        )
        .unwrap();
        path
    }

    fn check(path: PathBuf, explicit: bool) -> Cli {
        Cli {
            config: Some(path),
            command: Command::Config(ConfigCommand::Check(CheckArgs { explicit })),
        }
    }

    #[tokio::test]
    async fn config_check_reports_what_is_configured_without_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let path = dev_file(
            directory.path(),
            "[plugin.smtp]\nhost = \"smtp.example.org\"\npassword = \"hunter2\"\n\
             [database]\nurl = \"postgres://dbuser:token9@db.example.org/davhaven\"\n",
        );
        let mut out = Vec::new();
        execute(&check(path, false), &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("configuration is valid (server.mode = dev)"), "{text}");
        assert!(text.contains("database") && text.contains("memory"), "{text}");
        assert!(text.contains("127.0.0.1:9090") && text.contains("ops"), "{text}");
        assert!(text.contains("warning:"), "{text}");
        assert!(text.contains("<redacted>") && !text.contains("hunter2"), "{text}");
        assert!(
            !text.contains("token9"),
            "the password of the database URL leaked: {text}"
        );
    }

    #[tokio::test]
    async fn config_check_prints_the_effective_settings_and_explicit_prints_only_the_given_ones() {
        let directory = tempfile::tempdir().unwrap();
        let path = dev_file(
            directory.path(),
            "[outbox]\nbatch_size = 7\n[plugin.mail_transport.memory]\nmax_messages = 5\n",
        );
        let mut effective = Vec::new();
        execute(&check(path.clone(), false), &mut effective).await.unwrap();
        let effective = String::from_utf8(effective).unwrap();
        // The given values win over the defaults, and keys the file leaves alone show their default.
        assert!(effective.contains("\"batch_size\": 7"), "{effective}");
        assert!(
            effective.contains("\"max_attempts\": 12"),
            "a default of the outbox: {effective}"
        );
        assert!(
            effective.contains("\"max_connections\": 4096"),
            "a default of the server: {effective}"
        );
        assert!(effective.contains("plugin_settings"), "{effective}");
        assert!(effective.contains("\"max_messages\": 5"), "{effective}");

        let mut explicit = Vec::new();
        execute(&check(path, true), &mut explicit).await.unwrap();
        let explicit = String::from_utf8(explicit).unwrap();
        assert!(explicit.contains("\"batch_size\": 7"), "{explicit}");
        assert!(
            !explicit.contains("max_attempts") && !explicit.contains("plugin_settings"),
            "{explicit}"
        );
    }

    #[tokio::test]
    async fn config_check_fails_on_a_bad_configuration_and_names_the_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("davhaven.toml");
        std::fs::write(&path, "[server]\npublic_base_ur = \"https://cal.example.org\"\n").unwrap();
        let error = execute(&check(path, false), &mut Vec::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("public_base_ur"), "{error}");
        let missing = check(directory.path().join("missing.toml"), false);
        let error = execute(&missing, &mut Vec::new()).await.unwrap_err().to_string();
        assert!(error.contains("missing.toml"), "the error names the file: {error}");
    }

    #[tokio::test]
    async fn the_reference_command_prints_the_generated_document() {
        let cli = Cli {
            config: None,
            command: Command::Config(ConfigCommand::Reference),
        };
        let mut out = Vec::new();
        execute(&cli, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("# Configuration reference"),
            "{}",
            text.lines().next().unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn the_healthcheck_fails_when_nothing_listens() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let cli = Cli {
            config: None,
            command: Command::Healthcheck(HealthcheckArgs {
                address: Some(address),
                timeout: Duration::from_secs(2),
            }),
        };
        let error = execute(&cli, &mut Vec::new()).await.unwrap_err().to_string();
        assert!(
            error.starts_with(&format!("GET http://{address}/readyz: ")),
            "the probe names what it asked: {error}"
        );
    }

    /// The application of a development configuration on the memory store, on `clock` and sequential ids.
    async fn assembly_on(clock: &Arc<davhaven_ports::testing::ManualClock>) -> Assembly {
        let config = dev_config();
        crate::assembly::assemble_with_ports(
            Arc::new(config),
            &Arc::new(registry().unwrap()),
            Arc::<davhaven_ports::testing::ManualClock>::clone(clock),
            Arc::new(davhaven_ports::testing::SeqIds::new()),
        )
        .await
        .unwrap()
    }

    fn dev_config() -> Config {
        Config::from_toml(
            "[server]\nmode = \"dev\"\npublic_base_url = \"http://localhost:8080\"\n\
             [plugins]\nstore = \"memory\"\nmail_transport = \"memory\"\nrate_limiter = \"memory\"\n\
             http_client = \"recording\"\n",
        )
        .unwrap()
    }

    /// What a system-token command prints on standard output.
    async fn system_output(assembly: &Assembly, command: &SystemTokenCommand) -> Result<String, ServerError> {
        let mut out = Vec::new();
        run_system_token(assembly, command, &mut out).await?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn create_system_token(label: &str, expires_in: Option<Duration>) -> SystemTokenCommand {
        SystemTokenCommand::Create(SystemTokenCreateArgs {
            label: label.to_owned(),
            expires_in,
            token_file: None,
            print_token: true,
        })
    }

    #[tokio::test]
    async fn the_system_token_listing_shows_the_state_and_expiry_of_every_token_and_never_a_secret() {
        let clock = Arc::new(davhaven_ports::testing::ManualClock::default());
        let assembly = assembly_on(&clock).await;
        assert_eq!(
            system_output(&assembly, &SystemTokenCommand::List).await.unwrap(),
            "there are no system tokens\n"
        );

        let secret = system_output(&assembly, &create_system_token("ci", Some(Duration::from_hours(24))))
            .await
            .unwrap();
        assert!(
            secret.starts_with("dvh_pat_") && secret.lines().count() == 1,
            "{secret}"
        );
        let secret = secret.trim().to_owned();
        assert_eq!(
            system_output(&assembly, &create_system_token("ci", None))
                .await
                .unwrap(),
            "",
            "a run that finds the token prints nothing where the secret would go"
        );
        system_output(&assembly, &create_system_token("forever", None))
            .await
            .unwrap();

        let tokens = admin::system_tokens(&assembly.deps).await.unwrap();
        let ci = tokens.iter().find(|token| token.label == "ci").unwrap();
        let forever = tokens.iter().find(|token| token.label == "forever").unwrap();
        assert!(
            secret.contains(&ci.prefix),
            "the listing identifies a token by its prefix"
        );
        let listing = system_output(&assembly, &SystemTokenCommand::List).await.unwrap();
        assert!(!listing.contains(&secret), "{listing}");
        assert_eq!(listing.lines().count(), 2, "{listing}");
        assert!(
            listing.contains(&format!(
                "{}  valid    {}  expires 2027-01-02T00:00:00Z  ci\n",
                ci.id, ci.prefix
            )),
            "{listing}"
        );
        assert!(
            listing.contains(&format!(
                "{}  valid    {}  expires never  forever\n",
                forever.id, forever.prefix
            )),
            "{listing}"
        );

        // A day later the first token is expired; the second is revoked.
        clock.advance(TimeDelta::days(1));
        let revoke = SystemTokenCommand::Revoke(SystemTokenRevokeArgs { id: forever.id });
        assert_eq!(
            system_output(&assembly, &revoke).await.unwrap(),
            format!("system token {} revoked\n", forever.id)
        );
        let listing = system_output(&assembly, &SystemTokenCommand::List).await.unwrap();
        assert!(listing.contains(&format!("{}  expired  ", ci.id)), "{listing}");
        assert!(listing.contains(&format!("{}  revoked  ", forever.id)), "{listing}");

        let unknown = SystemTokenCommand::Revoke(SystemTokenRevokeArgs {
            id: TokenId::from_uuid(Uuid::from_u128(7)),
        });
        let error = system_output(&assembly, &unknown).await.unwrap_err().to_string();
        assert!(error.contains("there is no system token"), "{error}");
    }

    /// What a principal-token command prints on standard output.
    async fn principal_output(assembly: &Assembly, command: &PrincipalTokenCommand) -> Result<String, ServerError> {
        let mut out = Vec::new();
        run_principal_token(assembly, command, &mut out).await?;
        Ok(String::from_utf8(out).unwrap())
    }

    /// Makes the tenant `slug` the way `admin bootstrap` does and, in it, the user `olivia`.
    async fn tenant_with_olivia(assembly: &Assembly, slug: &str) {
        let outcome = admin::bootstrap(
            &assembly.deps,
            &assembly.services,
            &BootstrapRequest {
                tenant: TenantSlug::parse(slug).unwrap(),
                display_name: None,
                login_domain: Some(DomainName::parse(&format!("{slug}.example")).unwrap()),
                settings: SettingsFlags::default(),
                label: "bootstrap".to_owned(),
                scopes: admin::default_scopes(),
                expires_at: None,
            },
            &TokenSink::Stdout,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        let ctx = davhaven_domain::RequestContext::internal(
            outcome.tenant.id,
            davhaven_domain::RequestId::from_uuid(assembly.deps.ids.new_id()),
        );
        assembly
            .services
            .principals
            .upsert(
                &ctx,
                davhaven_app::services::PrincipalSpec {
                    name: PrincipalName::parse("olivia").unwrap(),
                    body: davhaven_wire::PrincipalWrite {
                        kind: davhaven_domain::PrincipalKind::User,
                        display_name: "Olivia".to_owned(),
                        email: None,
                        addresses: Vec::new(),
                        locale: None,
                        timezone: None,
                        external_ref: None,
                        status: None,
                    },
                },
                davhaven_app::services::Conditions::none(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_principal_token_listing_shows_principal_scopes_and_state_and_stays_within_the_tenant() {
        let clock = Arc::new(davhaven_ports::testing::ManualClock::default());
        let assembly = assembly_on(&clock).await;
        tenant_with_olivia(&assembly, "acme").await;
        tenant_with_olivia(&assembly, "globex").await;
        let acme = TenantSlug::parse("acme").unwrap();
        let globex = TenantSlug::parse("globex").unwrap();
        let olivia = PrincipalName::parse("olivia").unwrap();
        let list = |tenant: &TenantSlug, principal: Option<&PrincipalName>| {
            PrincipalTokenCommand::List(PrincipalTokenListArgs {
                tenant: tenant.clone(),
                principal: principal.cloned(),
            })
        };
        assert_eq!(
            principal_output(&assembly, &list(&acme, None)).await.unwrap(),
            "there are no principal tokens\n"
        );

        let create = PrincipalTokenCommand::Create(PrincipalTokenCreateArgs {
            tenant: acme.clone(),
            principal: olivia.clone(),
            label: "calendar-sync".to_owned(),
            scopes: vec![Scope::EventsWrite, Scope::EventsRead],
            expires_in: None,
            token_file: None,
            print_token: true,
        });
        let secret = principal_output(&assembly, &create).await.unwrap();
        assert!(
            secret.starts_with("dvh_pat_") && secret.lines().count() == 1,
            "{secret}"
        );
        let secret = secret.trim().to_owned();
        assert_eq!(
            principal_output(&assembly, &create).await.unwrap(),
            "",
            "a run that finds the token prints nothing where the secret would go"
        );

        let tokens = admin::principal_tokens(&assembly.deps, &assembly.services, &acme, None)
            .await
            .unwrap();
        let [token] = tokens.as_slice() else {
            panic!("one token: {tokens:?}");
        };
        let listing = principal_output(&assembly, &list(&acme, Some(&olivia))).await.unwrap();
        assert_eq!(
            listing,
            format!(
                "{}  valid    olivia  {}  expires never  [events:read,events:write]  calendar-sync\n",
                token.id, token.prefix
            )
        );
        assert!(!listing.contains(&secret));

        // The other tenant has a user of the same name: it sees none of this token and cannot revoke it.
        assert_eq!(
            principal_output(&assembly, &list(&globex, Some(&olivia)))
                .await
                .unwrap(),
            "there are no principal tokens\n"
        );
        let foreign = PrincipalTokenCommand::Revoke(PrincipalTokenRevokeArgs {
            tenant: globex.clone(),
            id: token.id,
        });
        let error = principal_output(&assembly, &foreign).await.unwrap_err().to_string();
        assert!(error.contains("tenant `globex` has no principal token"), "{error}");

        let revoke = PrincipalTokenCommand::Revoke(PrincipalTokenRevokeArgs {
            tenant: acme.clone(),
            id: token.id,
        });
        assert_eq!(
            principal_output(&assembly, &revoke).await.unwrap(),
            format!("principal token {} of tenant acme revoked\n", token.id)
        );
        let listing = principal_output(&assembly, &list(&acme, None)).await.unwrap();
        assert!(
            listing.starts_with(&format!("{}  revoked  olivia  ", token.id)),
            "{listing}"
        );
    }

    #[test]
    fn a_token_is_expired_from_the_moment_of_its_expiry_and_revoked_wins_over_expired() {
        let now = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let second = TimeDelta::seconds(1);
        assert_eq!(token_state(None, None, now), "valid");
        assert_eq!(token_state(None, Some(now + second), now), "valid");
        assert_eq!(token_state(None, Some(now), now), "expired");
        assert_eq!(token_state(None, Some(now - second), now), "expired");
        assert_eq!(token_state(Some(now), Some(now - second), now), "revoked");
        assert_eq!(token_state(Some(now), None, now), "revoked");
        assert_eq!(expiry_text(None), "never");
        assert_eq!(expiry_text(Some(now)), "2027-01-15T08:00:00Z");
    }

    #[test]
    fn what_an_existing_token_lacks_is_reported_as_warnings() {
        let token = ApiTokenView {
            id: TokenId::from_uuid(Uuid::from_u128(1)),
            kind: davhaven_domain::TokenKind::Principal,
            principal_id: None,
            principal: None,
            label: "assistant".to_owned(),
            scopes: [Scope::McpRead].into_iter().collect(),
            prefix: "abcdefghijkl".to_owned(),
            expires_at: None,
            allowed_origins: Vec::new(),
            created_by: None,
            last_used_at: None,
            revoked_at: None,
            created_at: DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap(),
        };
        let mut nothing = Vec::new();
        report_existing_token(&mut nothing, &token, &[], false).unwrap();
        assert!(
            nothing.is_empty(),
            "a token that matches is reported by its caller alone"
        );

        let mut said = Vec::new();
        report_existing_token(&mut said, &token, &[Scope::McpWrite, Scope::McpScheduleExternal], true).unwrap();
        let said = String::from_utf8(said).unwrap();
        assert_eq!(
            said,
            "warning: the existing token does not expire, which differs from what was asked for with --expires-in; \
             revoke it, or choose another label, to get a token that matches\n\
             warning: the existing token lacks the scopes mcp:write, mcp:schedule_external; revoke it, or choose another \
             label, to get a token that has them\n"
        );
    }

    #[test]
    fn a_lifetime_becomes_an_expiry_and_a_huge_one_is_refused() {
        let now = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        assert_eq!(expiry(now, None).unwrap(), None);
        assert_eq!(
            expiry(now, Some(Duration::from_hours(24))).unwrap(),
            Some(now + TimeDelta::days(1))
        );
        assert!(expiry(now, Some(Duration::MAX)).is_err());
    }
}
