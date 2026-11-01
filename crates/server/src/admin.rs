//! Administrative commands: `admin bootstrap`, `admin system-token`, `admin principal-token`, `admin bump-sync-epoch`,
//! `admin purge-audit`, `admin rotate-keys` and `migrate`.
//!
//! These run once, from an operator or a deployment step, with the same configuration as the server. They are thin: what a
//! command knows about the data (which values are sealed, how a token is minted, which token a repeated run finds again)
//! is the application's business and lives in `davhaven_app::maintenance`; this module and the command line only call it,
//! keep the secret of a new token where the operator asked and say what happened.
//!
//! * **`admin bootstrap`** creates a tenant and an administration token for it, the first step of a new
//!   deployment (everything else is done through the management API with that token). The tenant can be given its
//!   settings with flags ([`SettingsFlags`]: locale, time zone, theme, the sender of mail, the personal calendar, the
//!   branding of client configuration, MCP), so that a first deployment needs no system token and no `PATCH`. It is
//!   idempotent: a tenant that exists is left as it is (differences to the flags are reported, never applied) and a
//!   valid tenant token with the label is not created again (when it lacks scopes that were asked for, or expires
//!   although no expiry was asked for or the other way round, that is reported, like the differences of an existing
//!   tenant). The tenant is created with `If-None-Match: *`, so two runs at the same time cannot replace each other's
//!   tenant; they can both create a token, which is the one thing the label does not prevent. The secret of a new token is shown exactly once, written to
//!   the file named by `--token-file` (created with mode 0600; an existing file is never overwritten) or, with
//!   `--print-token`, to standard output. Everything else the command says goes to standard error, so
//!   `davhaven admin bootstrap ... --print-token > token` captures the secret and nothing else.
//! * **`admin system-token`** creates, lists and revokes the system tokens that `/api/v1/tenants` needs (scope
//!   `system:tenants`): the management API cannot mint them. Creation is idempotent by label, like `bootstrap`
//!   ([`davhaven_app::maintenance::system_tokens`]).
//! * **`admin principal-token`** creates, lists and revokes the **principal tokens** of a tenant (`dvh_pat_...` that act
//!   as one principal on the API and on MCP): the way to give an assistant or an integration its `mcp:*` token when no
//!   tenant token with `credentials:write` exists yet, or when the operator wants the minting to be a deployment step.
//!   It goes through the credential service with the internal channel, like `bootstrap`, so the token is minted by
//!   the same rules as through the management API (scopes of the kind, `mcp:*` only for a tenant that switched MCP on,
//!   an expiry for `mcp:*` within `security.max_mcp_token_days`) and leaves the same `token.created` and
//!   `token.revoked` audit records; the internal channel is the operator, so the rule that a token mints only tokens
//!   of its own scopes does not apply to it. Creation is idempotent by (principal, label), like `bootstrap`: both
//!   commands share `ensure_api_token`, so a token that exists is found, compared and reported the same way. A new
//!   token needs a **new label** while the old one is still valid, which is how a token is replaced without a gap
//!   (`docs/operations/runbook.md`).
//! * **`admin bump-sync-epoch`** gives every collection a new sync epoch, which invalidates all sync tokens; run it
//!   after a restore (PLAN 2.7). It writes through the store and not through a service, and the audit catalog has no
//!   event for it, so the command's output and the process log are its record.
//! * **`admin purge-audit`** removes audit events older than `retention.audit_days` with the owner credentials of
//!   `database.migration_url`: the runtime role cannot delete audit records (`docs/operations/database.md`).
//! * **`admin rotate-keys`** seals the stored secrets again under the active key
//!   ([`davhaven_app::maintenance::keys`]).
//! * **`migrate`** applies the pending database migrations with the owner role.
//!
//! `bootstrap` goes through the application services with the internal channel, so it leaves the same audit records and
//! events as the management API does; `rotate-keys` audits through the resealers it runs.

use chrono::{DateTime, Utc};
use davhaven_app::maintenance::MaintenanceError;
use davhaven_app::maintenance::api_tokens;
use davhaven_app::maintenance::keys::{RotationReport, reseal_all};
use davhaven_app::maintenance::system_tokens::{self, SystemTokenInfo};
use davhaven_app::services::{Conditions, TenantSpec};
use davhaven_app::{AppCore, AppDeps, AppError, AppServices};
use davhaven_crypto_local::sealer::LocalSealer;
use davhaven_domain::{
    DomainName, ErrorKind, Locale, PrincipalName, RequestContext, RequestId, Scope, ScopeSet, TenantId, TenantSettings,
    TenantSlug, TimeZoneName, TokenId, TokenKind,
};
use davhaven_ports::{Database, StoreError};
use davhaven_wire::{ApiTokenCreate, ApiTokenView, TenantView, TenantWrite};
use secrecy::ExposeSecret as _;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::error::ServerError;

/// Where the secret of a new token goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSink {
    /// A new file with mode 0600; the command refuses to overwrite one.
    File(PathBuf),
    /// Standard output (`--print-token`).
    Stdout,
}

/// The settings of a tenant that `admin bootstrap` can set with flags.
///
/// A flag that is not given leaves the setting at the default of the application (`TenantSettings::default()`) for a
/// tenant that is created and says nothing about a tenant that exists, exactly like the display name and the login
/// domain: a run with fewer flags than the first one does not report the settings it leaves out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsFlags {
    /// `--locale`: the default locale of mail and pages.
    pub locale: Option<Locale>,
    /// `--timezone`: the default time zone of principals without one.
    pub timezone: Option<TimeZoneName>,
    /// `--theme`: the template theme of the tenant. Without it the tenant follows `templates.default_theme`.
    pub theme: Option<String>,
    /// `--sender-domain`: the domain mail is sent from (mail cannot be sent for the tenant without one).
    pub sender_domain: Option<DomainName>,
    /// `--sender-display-name`: the name shown after "via" in the sender of mail.
    pub sender_display_name: Option<String>,
    /// `--auto-create-personal-calendar`: whether a new user gets a personal calendar.
    pub auto_create_personal_calendar: Option<bool>,
    /// `--apple-identifier-prefix`: the reverse-DNS prefix of the identifiers of Apple configuration profiles.
    pub apple_identifier_prefix: Option<String>,
    /// `--organization-name`: the organization name shown in configuration profiles.
    pub organization_name: Option<String>,
    /// `--mcp-enabled`: whether the principals of the tenant may use the MCP endpoint. A principal token with `mcp:*`
    /// scopes can be minted only for a tenant that switched MCP on.
    pub mcp_enabled: Option<bool>,
}

impl SettingsFlags {
    /// Whether no flag is given.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The settings of a tenant that is created: the defaults of the application with the flags laid over them.
    pub fn settings(&self) -> TenantSettings {
        let mut settings = TenantSettings::default();
        if let Some(locale) = &self.locale {
            settings.locale = locale.clone();
        }
        if let Some(timezone) = self.timezone {
            settings.timezone = timezone;
        }
        if let Some(theme) = &self.theme {
            settings.theme = Some(theme.clone());
        }
        if let Some(domain) = &self.sender_domain {
            settings.sender.domain = Some(domain.clone());
        }
        if let Some(name) = &self.sender_display_name {
            settings.sender.display_name = Some(name.clone());
        }
        if let Some(on) = self.auto_create_personal_calendar {
            settings.auto_create_personal_calendar = on;
        }
        if let Some(prefix) = &self.apple_identifier_prefix {
            settings.client_config.apple_identifier_prefix = Some(prefix.clone());
        }
        if let Some(name) = &self.organization_name {
            settings.client_config.organization_name = Some(name.clone());
        }
        if let Some(on) = self.mcp_enabled {
            settings.mcp_enabled = on;
        }
        settings
    }

    /// The settings of an existing tenant that differ from the flags, by the names of the settings prefixed with
    /// `settings.` (`settings.sender.domain`); only the flags that are given are compared.
    pub fn differences(&self, existing: &TenantSettings) -> Vec<&'static str> {
        let wanted = self.settings();
        let mut differences = Vec::new();
        let mut check = |given: bool, differs: bool, name: &'static str| {
            if given && differs {
                differences.push(name);
            }
        };
        check(
            self.locale.is_some(),
            wanted.locale != existing.locale,
            "settings.locale",
        );
        check(
            self.timezone.is_some(),
            wanted.timezone != existing.timezone,
            "settings.timezone",
        );
        check(self.theme.is_some(), wanted.theme != existing.theme, "settings.theme");
        check(
            self.sender_domain.is_some(),
            wanted.sender.domain != existing.sender.domain,
            "settings.sender.domain",
        );
        check(
            self.sender_display_name.is_some(),
            wanted.sender.display_name != existing.sender.display_name,
            "settings.sender.display_name",
        );
        check(
            self.auto_create_personal_calendar.is_some(),
            wanted.auto_create_personal_calendar != existing.auto_create_personal_calendar,
            "settings.auto_create_personal_calendar",
        );
        check(
            self.apple_identifier_prefix.is_some(),
            wanted.client_config.apple_identifier_prefix != existing.client_config.apple_identifier_prefix,
            "settings.client_config.apple_identifier_prefix",
        );
        check(
            self.organization_name.is_some(),
            wanted.client_config.organization_name != existing.client_config.organization_name,
            "settings.client_config.organization_name",
        );
        check(
            self.mcp_enabled.is_some(),
            wanted.mcp_enabled != existing.mcp_enabled,
            "settings.mcp_enabled",
        );
        differences
    }
}

/// What `admin bootstrap` is asked to make sure of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRequest {
    /// The slug of the tenant.
    pub tenant: TenantSlug,
    /// The display name of a tenant that is created (the slug when absent). Compared with the stored one only when given.
    pub display_name: Option<String>,
    /// The login domain of a tenant that is created. Compared with the stored one only when given.
    pub login_domain: Option<DomainName>,
    /// The settings of a tenant that is created. Compared with the stored ones only for the flags that are given.
    pub settings: SettingsFlags,
    /// The label of the administration token; the token is found by it.
    pub label: String,
    /// The scopes of the token.
    pub scopes: ScopeSet,
    /// When the token expires, if it should.
    pub expires_at: Option<DateTime<Utc>>,
}

/// What happened to the token of a command that makes sure one exists (`admin bootstrap`, `admin principal-token create`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenOutcome {
    /// A token was created; its secret went to the sink.
    Created(Box<ApiTokenView>),
    /// A valid token of the same kind and principal with the label exists; its secret cannot be shown again.
    Exists {
        /// The existing token.
        token: Box<ApiTokenView>,
        /// The scopes that were asked for and that it does not hold.
        missing_scopes: Vec<Scope>,
        /// Whether it expires although none was asked for, or does not expire although an expiry was asked for. Two
        /// runs ask for expiry dates that differ by the time between them, so only the presence is compared.
        expiry_differs: bool,
    },
}

/// What `admin bootstrap` did.
#[derive(Debug, Clone, PartialEq)]
pub struct BootstrapOutcome {
    /// The tenant as stored.
    pub tenant: TenantView,
    /// Whether this run created the tenant.
    pub tenant_created: bool,
    /// The values of an existing tenant that differ from the flags (not changed).
    pub differences: Vec<&'static str>,
    /// What happened to the administration token.
    pub token: TokenOutcome,
}

/// The scopes of a bootstrap token when none are asked for: everything a tenant token may hold, except the scopes
/// that need an expiry (MCP, which belongs to principal tokens).
pub fn default_scopes() -> ScopeSet {
    Scope::ALL
        .into_iter()
        .filter(|scope| scope.allowed_for(TokenKind::Tenant) && !scope.requires_expiry())
        .collect()
}

fn failed(what: &str, error: &dyn std::fmt::Display) -> ServerError {
    ServerError::Command(format!("{what}: {error}"))
}

/// Creates the file of a new token secret: new, mode 0600 where the platform has modes.
fn create_secret_file(path: &Path) -> Result<std::fs::File, ServerError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            ServerError::Command(format!(
                "{} exists, and no valid token with this label does: remove the file or choose another one",
                path.display()
            ))
        } else {
            ServerError::io(format!("cannot create {}", path.display()), error)
        }
    })
}

/// The place a secret goes to, made ready before the secret exists (a file is created, so a failure to create it is known
/// while there is still nothing to revoke).
struct PreparedSink {
    file: Option<(std::fs::File, PathBuf)>,
}

impl PreparedSink {
    /// Creates the file of a [`TokenSink::File`]; standard output needs no preparation.
    fn prepare(sink: &TokenSink) -> Result<Self, ServerError> {
        let file = match sink {
            TokenSink::File(path) => Some((create_secret_file(path)?, path.clone())),
            TokenSink::Stdout => None,
        };
        Ok(Self { file })
    }

    /// Writes `secret` and a line break, and makes sure it is on disk.
    fn write(&mut self, stdout: &mut dyn std::io::Write, secret: &str) -> Result<(), ServerError> {
        match &mut self.file {
            Some((handle, path)) => writeln!(handle, "{secret}")
                .and_then(|()| handle.sync_all())
                .map_err(|error| ServerError::io(format!("cannot write {}", path.display()), error)),
            None => writeln!(stdout, "{secret}")
                .and_then(|()| stdout.flush())
                .map_err(|error| ServerError::io("cannot write the token to standard output", error)),
        }
    }

    /// Removes the file again (the secret was not created, or could not be written to it).
    fn discard(&self) {
        if let Some((_, path)) = &self.file {
            drop(std::fs::remove_file(path));
        }
    }
}

/// What `admin system-token create` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemTokenOutcome {
    /// A token was created; its secret went to the sink.
    Created(SystemTokenInfo),
    /// A valid token with the label exists; its secret cannot be shown again.
    Exists(SystemTokenInfo),
}

/// Makes sure a system token labelled `label` exists, like `bootstrap` does for the administration token of a tenant: a valid
/// token with the label is reported, otherwise one is created and its secret goes to `sink` (once; never overwriting a
/// file).
///
/// # Errors
///
/// [`ServerError::Command`] for an unusable label or expiry, a store that fails or a sink that cannot be written. A token
/// whose secret could not be written is revoked again, so that the next run can create it.
pub async fn system_token(
    deps: &AppDeps,
    label: &str,
    expires_at: Option<DateTime<Utc>>,
    sink: &TokenSink,
    stdout: &mut dyn std::io::Write,
) -> Result<SystemTokenOutcome, ServerError> {
    if let Some(existing) = system_tokens::find_valid(deps, label)
        .await
        .map_err(|error| failed("cannot list the system tokens", &error))?
    {
        return Ok(SystemTokenOutcome::Exists(existing));
    }
    let mut prepared = PreparedSink::prepare(sink)?;
    let created = match system_tokens::create(deps, label, expires_at).await {
        Ok(created) => created,
        Err(error) => {
            prepared.discard();
            return Err(failed("cannot create the system token", &error));
        }
    };
    if let Err(error) = prepared.write(stdout, created.secret.expose_secret()) {
        prepared.discard();
        drop(system_tokens::revoke(deps, created.token.id).await);
        return Err(error);
    }
    Ok(SystemTokenOutcome::Created(created.token))
}

/// The system tokens, revoked ones included.
///
/// # Errors
///
/// [`ServerError::Command`] when the store fails.
pub async fn system_tokens(deps: &AppDeps) -> Result<Vec<SystemTokenInfo>, ServerError> {
    system_tokens::list(deps)
        .await
        .map_err(|error| failed("cannot list the system tokens", &error))
}

/// Revokes the system token `id`.
///
/// # Errors
///
/// [`ServerError::Command`] when no system token has the id or the store fails.
pub async fn revoke_system_token(deps: &AppDeps, id: TokenId) -> Result<(), ServerError> {
    match system_tokens::revoke(deps, id).await {
        Ok(()) => Ok(()),
        Err(MaintenanceError::Store(StoreError::NotFound)) => {
            Err(ServerError::Command(format!("there is no system token `{id}`")))
        }
        Err(error) => Err(failed("cannot revoke the system token", &error)),
    }
}

/// An error of an application service, for the operator: what it says, and the fields of the request it names (a
/// refused scope, an expiry that is missing, a setting that does not validate).
fn failed_app(what: &str, error: &AppError) -> ServerError {
    let mut text = format!("{what}: {error}");
    for field in error.field_errors() {
        let _ = write!(text, "; {} {}: {}", field.pointer, field.code, field.message);
    }
    ServerError::Command(text)
}

/// The request context of the operator for the tenant `slug`: the internal channel, which is trusted and leaves the audit
/// records of a system actor. The commands that name a tenant by its slug get its existence checked here.
async fn tenant_context(
    deps: &AppDeps,
    services: &AppServices,
    slug: &TenantSlug,
) -> Result<RequestContext, ServerError> {
    let system = RequestContext::internal(
        TenantId::from_uuid(Uuid::nil()),
        RequestId::from_uuid(deps.ids.new_id()),
    );
    let tenant = services.tenants.get(&system, slug).await.map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            ServerError::Command(format!("there is no tenant `{slug}`"))
        } else {
            failed_app("cannot read the tenant", &error)
        }
    })?;
    Ok(RequestContext::internal(
        tenant.id,
        RequestId::from_uuid(deps.ids.new_id()),
    ))
}

/// Makes sure an API token like `create` describes exists in the tenant of `ctx`: a valid token of the same kind and
/// principal with the label is reported (with what it lacks of what was asked for), otherwise one is created through the
/// credential service and its secret goes to `sink` (once; never overwriting a file). The administration token of
/// `bootstrap` and the tokens of `principal-token create` go through this one sequence.
///
/// # Errors
///
/// [`ServerError::Command`] for a request the credential service refuses (the message names the fields), a principal that
/// does not exist, a sink that cannot be written, or a store that fails. A token whose secret could not be written is
/// revoked again, so that the next run can create it.
async fn ensure_api_token(
    deps: &AppDeps,
    services: &AppServices,
    ctx: &RequestContext,
    create: ApiTokenCreate,
    sink: &TokenSink,
    stdout: &mut dyn std::io::Write,
) -> Result<TokenOutcome, ServerError> {
    if let Some(existing) = api_tokens::find_existing(deps, ctx.tenant, &create)
        .await
        .map_err(|error| failed("cannot list the API tokens", &error))?
    {
        return Ok(TokenOutcome::Exists {
            token: Box::new(existing.token),
            missing_scopes: existing.missing_scopes,
            expiry_differs: existing.expiry_differs,
        });
    }

    // The sink is prepared before the token exists, so a secret is never created that nowhere can be put.
    let mut prepared = PreparedSink::prepare(sink)?;
    let principal = create.principal.clone();
    let created = match services.credentials.create_api_token(ctx, create).await {
        Ok(created) => created,
        Err(error) => {
            prepared.discard();
            return Err(match principal {
                Some(name) if error.kind() == ErrorKind::NotFound => {
                    ServerError::Command(format!("the tenant has no principal `{name}`"))
                }
                _ => failed_app("cannot create the token", &error),
            });
        }
    };
    if let Err(error) = prepared.write(stdout, &created.secret) {
        // The secret exists nowhere: revoke the token so that the next run creates a new one.
        prepared.discard();
        drop(services.credentials.revoke_api_token(ctx, created.token.id).await);
        return Err(error);
    }
    Ok(TokenOutcome::Created(Box::new(created.token)))
}

/// What `admin principal-token create` is asked to make sure of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalTokenRequest {
    /// The slug of the tenant.
    pub tenant: TenantSlug,
    /// The name of the principal the token acts as: any principal except a group (a user, a service principal or a
    /// resource); a group cannot act.
    pub principal: PrincipalName,
    /// The label of the token, which identifies the integration in the audit log; the token is found by it.
    pub label: String,
    /// The scopes of the token (`mcp:*` need an expiry and a tenant that switched MCP on).
    pub scopes: ScopeSet,
    /// When the token expires, if it should.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Makes sure a principal token of `request.principal` labelled `request.label` exists, like `bootstrap` does for the
/// administration token of a tenant (`ensure_api_token`).
///
/// # Errors
///
/// [`ServerError::Command`] for an unknown tenant or principal, a request the credential service refuses, a sink that
/// cannot be written, or a store that fails.
pub async fn principal_token(
    deps: &AppDeps,
    services: &AppServices,
    request: &PrincipalTokenRequest,
    sink: &TokenSink,
    stdout: &mut dyn std::io::Write,
) -> Result<TokenOutcome, ServerError> {
    let ctx = tenant_context(deps, services, &request.tenant).await?;
    let create = ApiTokenCreate {
        kind: TokenKind::Principal,
        principal: Some(request.principal.clone()),
        label: request.label.clone(),
        scopes: request.scopes,
        expires_at: request.expires_at,
        allowed_origins: Vec::new(),
    };
    ensure_api_token(deps, services, &ctx, create, sink, stdout).await
}

/// The principal tokens of a tenant, revoked ones included (no secret is shown); with `principal`, only that
/// principal's.
///
/// # Errors
///
/// [`ServerError::Command`] for an unknown tenant or a store that fails.
pub async fn principal_tokens(
    deps: &AppDeps,
    services: &AppServices,
    tenant: &TenantSlug,
    principal: Option<&PrincipalName>,
) -> Result<Vec<ApiTokenView>, ServerError> {
    let ctx = tenant_context(deps, services, tenant).await?;
    api_tokens::list(deps, ctx.tenant, TokenKind::Principal, principal)
        .await
        .map_err(|error| failed("cannot list the API tokens", &error))
}

/// Revokes the principal token `id` of a tenant. Revoking a revoked token changes nothing. Only principal tokens are
/// revoked here: the id of a tenant token is not one (the management API revokes those).
///
/// # Errors
///
/// [`ServerError::Command`] for an unknown tenant, an id that is no principal token of the tenant, or a store that
/// fails.
pub async fn revoke_principal_token(
    deps: &AppDeps,
    services: &AppServices,
    tenant: &TenantSlug,
    id: TokenId,
) -> Result<(), ServerError> {
    let ctx = tenant_context(deps, services, tenant).await?;
    if !api_tokens::has_token(deps, ctx.tenant, TokenKind::Principal, id)
        .await
        .map_err(|error| failed("cannot read the API tokens", &error))?
    {
        return Err(ServerError::Command(format!(
            "tenant `{tenant}` has no principal token `{id}`"
        )));
    }
    services
        .credentials
        .revoke_api_token(&ctx, id)
        .await
        .map_err(|error| failed_app("cannot revoke the token", &error))
}

/// The tenant of a bootstrap: created with `If-None-Match: *`, or, when it exists, read and compared to the flags.
async fn ensure_tenant(
    services: &AppServices,
    system: &RequestContext,
    request: &BootstrapRequest,
) -> Result<(TenantView, bool, Vec<&'static str>), ServerError> {
    let spec = TenantSpec {
        slug: request.tenant.clone(),
        body: TenantWrite {
            display_name: request
                .display_name
                .clone()
                .unwrap_or_else(|| request.tenant.to_string()),
            login_domain: request.login_domain.clone(),
            status: None,
            settings: (!request.settings.is_empty()).then(|| request.settings.settings()),
        },
    };
    match services.tenants.upsert(system, spec, Conditions::create_only()).await {
        Ok(created) => Ok((created.value, true, Vec::new())),
        // It exists, or a run at the same time created it a moment ago: report, never replace.
        Err(error) if error.kind() == ErrorKind::PreconditionFailed => {
            let existing = services
                .tenants
                .get(system, &request.tenant)
                .await
                .map_err(|error| failed_app("cannot read the tenant", &error))?;
            // Only what the run was asked for is compared: a run with fewer flags than the first one says nothing about the
            // values it left out.
            let mut differences = Vec::new();
            if request
                .display_name
                .as_ref()
                .is_some_and(|name| *name != existing.display_name)
            {
                differences.push("display_name");
            }
            if request
                .login_domain
                .as_ref()
                .is_some_and(|domain| existing.login_domain.as_ref() != Some(domain))
            {
                differences.push("login_domain");
            }
            differences.extend(request.settings.differences(&existing.settings));
            Ok((existing, false, differences))
        }
        Err(error) => Err(failed_app("cannot create the tenant", &error)),
    }
}

/// Makes sure the tenant and its administration token exist. See the module documentation.
///
/// The secret of a token that was created goes to `sink`, before the command reports success; it is the only place the
/// secret is ever shown.
///
/// # Errors
///
/// [`ServerError::Command`] for a failing service call or a sink that cannot be written. A token that was created
/// and whose secret could not be written is revoked again, so that the next run can create it.
pub async fn bootstrap(
    deps: &AppDeps,
    services: &AppServices,
    request: &BootstrapRequest,
    sink: &TokenSink,
    stdout: &mut dyn std::io::Write,
) -> Result<BootstrapOutcome, ServerError> {
    let system = RequestContext::internal(
        TenantId::from_uuid(Uuid::nil()),
        RequestId::from_uuid(deps.ids.new_id()),
    );
    let (tenant, tenant_created, differences) = ensure_tenant(services, &system, request).await?;

    let ctx = RequestContext::internal(tenant.id, RequestId::from_uuid(deps.ids.new_id()));
    let create = ApiTokenCreate {
        kind: TokenKind::Tenant,
        principal: None,
        label: request.label.clone(),
        scopes: request.scopes,
        expires_at: request.expires_at,
        allowed_origins: Vec::new(),
    };
    let token = ensure_api_token(deps, services, &ctx, create, sink, stdout).await?;
    Ok(BootstrapOutcome {
        tenant,
        tenant_created,
        differences,
        token,
    })
}

/// Which collections `admin bump-sync-epoch` renews the epoch of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochScope {
    /// Every collection of every tenant.
    All,
    /// Every collection of one tenant.
    Tenant(TenantSlug),
}

/// Gives the collections in `scope` a new sync epoch. Returns how many collections changed.
///
/// # Errors
///
/// [`ServerError::Command`] when the tenant does not exist and [`ServerError::Store`] for store failures.
pub async fn bump_sync_epoch(database: &dyn Database, scope: &EpochScope) -> Result<u64, ServerError> {
    let mut tx = database.begin_system().await?;
    let tenant = match scope {
        EpochScope::All => None,
        EpochScope::Tenant(slug) => {
            let found = tx.tenants().find_by_slug(slug).await?;
            let tenant = found.ok_or_else(|| ServerError::Command(format!("there is no tenant `{slug}`")))?;
            Some(tenant.id)
        }
    };
    let changed = tx.tenants().bump_sync_epoch(tenant).await?;
    tx.commit().await?;
    tracing::info!(
        scope = ?scope,
        collections = changed,
        "sync epochs were renewed: every outstanding sync token of these collections is invalid"
    );
    Ok(changed)
}

/// Applies the pending migrations with the owner role of `database.migration_url`, and then the role model of the
/// database: what the runtime roles may and may not do, which a database restored from a dump needs even when no
/// migration is pending (docs/operations/backup.md).
///
/// Production refuses to connect when the owner URL may travel unencrypted to a remote host, unless
/// `database.allow_insecure_transport` accepts the risk, as it does for the URLs of `serve`.
///
/// # Errors
///
/// [`ServerError::Command`] when the selected store has no migrations or the role of the URL does not own the tables (it
/// could not apply the role model, which is part of the command: a job with the wrong credentials must not report
/// success), [`ServerError::Plugin`] when the owner URL is refused, or the database cannot be reached or migrated.
#[cfg(feature = "store-postgres")]
pub async fn migrate(
    config: &crate::config::Config,
) -> Result<davhaven_store_postgres::migrate::MigrationReport, ServerError> {
    let database = owner_config(config)?;
    let report = davhaven_store_postgres::migrate::run(&database).await?;
    if report.role_model == davhaven_store_postgres::migrate::RoleModel::NotOwner {
        return Err(ServerError::Command(
            "the database role of `database.migration_url` (or of `database.url`, when no migration URL is set) does not \
             own the tables, so the role model of the database was not applied and nothing was changed; run \
             `davhaven migrate` with the owner role, and restore a dump as the owner (`pg_restore --no-owner \
             --role=<owner>`, docs/operations/backup.md)"
                .to_owned(),
        ));
    }
    Ok(report)
}

/// Removes the audit events older than `retention.audit_days` with the owner role.
///
/// # Errors
///
/// As [`migrate`].
#[cfg(feature = "store-postgres")]
pub async fn purge_audit(
    config: &crate::config::Config,
    clock: &dyn davhaven_ports::Clock,
) -> Result<u64, ServerError> {
    let database = owner_config(config)?;
    let cutoff = davhaven_app::retention::Cutoffs::at(clock.now(), &config.retention).audit;
    Ok(davhaven_store_postgres::migrate::purge_audit(&database, cutoff).await?)
}

/// The `[database]` table of a command that connects with the owner role. These commands do not build the plugin, so
/// the transport rule of production that the plugin applies to its URLs is applied here to the owner URL, before
/// anything connects: the owner credentials are the most powerful ones (`database.allow_insecure_transport` accepts the
/// risk, and what it accepts is logged).
#[cfg(feature = "store-postgres")]
fn owner_config(
    config: &crate::config::Config,
) -> Result<davhaven_store_postgres::config::DatabaseConfig, ServerError> {
    let database = postgres_config(config)?;
    for warning in davhaven_store_postgres::plugin::check_migration_transport(&database, config.server.mode)? {
        tracing::warn!(
            plugin = davhaven_store_postgres::config::PLUGIN,
            mode = %config.server.mode,
            allowed = database.allow_insecure_transport,
            "{warning}"
        );
    }
    Ok(database)
}

/// The `[database]` table of the `postgres` plugin.
#[cfg(feature = "store-postgres")]
fn postgres_config(
    config: &crate::config::Config,
) -> Result<davhaven_store_postgres::config::DatabaseConfig, ServerError> {
    if config.plugins.store != "postgres" {
        return Err(ServerError::Command(format!(
            "the selected store `{}` has no database to manage; only `postgres` does",
            config.plugins.store
        )));
    }
    // The registry says which table configures the plugin (`[database]`); nothing is built from it.
    let registry = crate::registry::registry()?;
    let table = config
        .plugin_tables(&registry)?
        .get("database", "postgres")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(davhaven_ports::parse_config("postgres", table)?)
}

/// Seals every stored secret under the active key of the key ring, so that a retired key can be removed from
/// `security.keys` The work is the application's ([`davhaven_app::maintenance::keys`]); this function tells it
/// which key a sealed value names, which is a matter of the production sealer's format.
///
/// The credential hashes are not touched, because their plaintext is unknown (a credential keeps verifying under the key it
/// was hashed with and is replaced by issuing a new one, `docs/operations/keys.md`).
///
/// # Errors
///
/// [`ServerError::Command`] when the store fails.
pub async fn rotate_keys(core: &AppCore) -> Result<RotationReport, ServerError> {
    let key_of = |sealed: &davhaven_ports::Sealed| LocalSealer::key_id_of(sealed).map(str::to_owned);
    reseal_all(core, &key_of)
        .await
        .map_err(|error| failed("cannot rotate the keys", &error))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use davhaven_app::maintenance::keys::Counts;
    use davhaven_app::services::{PageRequest, PrincipalSpec};
    use davhaven_crypto_local::keyring::{KeyMaterial, LocalCrypto};
    use davhaven_domain::{CollectionKey, CollectionKind, EventType, PrincipalKind, PrincipalName};
    use davhaven_ports::{KeyPurpose, PageReq, SealAad, Sealed, StoreError, TxMode};
    use davhaven_wire::{PrincipalWrite, WebhookCreate};
    use secrecy::SecretString;

    use super::*;
    use crate::assembly::{Assembly, assemble};
    use crate::config::Config;
    use crate::registry::registry;

    const DEV: &str = r#"
        [server]
        mode = "dev"
        public_base_url = "http://localhost:8080"
        [plugins]
        store = "memory"
        mail_transport = "memory"
        rate_limiter = "memory"
        http_client = "recording"
    "#;

    async fn world() -> Assembly {
        let config = Arc::new(Config::from_toml(DEV).unwrap());
        assemble(config, &Arc::new(registry().unwrap())).await.unwrap()
    }

    fn request(label: &str) -> BootstrapRequest {
        BootstrapRequest {
            tenant: TenantSlug::parse("acme").unwrap(),
            display_name: Some("Acme".to_owned()),
            login_domain: Some(DomainName::parse("acme.example").unwrap()),
            settings: SettingsFlags::default(),
            label: label.to_owned(),
            scopes: default_scopes(),
            expires_at: None,
        }
    }

    async fn run(
        world: &Assembly,
        request: &BootstrapRequest,
        sink: &TokenSink,
    ) -> Result<BootstrapOutcome, ServerError> {
        let mut stdout = Vec::new();
        bootstrap(&world.deps, &world.services, request, sink, &mut stdout).await
    }

    #[tokio::test]
    async fn bootstrap_creates_the_tenant_and_a_token_once() {
        let world = world().await;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("token");
        let sink = TokenSink::File(file.clone());
        let mut stdout = Vec::new();

        let first = bootstrap(&world.deps, &world.services, &request("deploy"), &sink, &mut stdout)
            .await
            .unwrap();
        assert!(first.tenant_created && first.differences.is_empty());
        let TokenOutcome::Created(token) = &first.token else {
            panic!("a token was expected: {first:?}");
        };
        assert_eq!(token.label, "deploy");
        assert_eq!(token.kind, TokenKind::Tenant);
        assert!(!token.scopes.contains(Scope::SystemTenants) && token.scopes.contains(Scope::EventsWrite));
        let secret = std::fs::read_to_string(&file).unwrap();
        assert!(secret.starts_with("dvh_pat_") && secret.ends_with('\n'), "{secret:?}");
        assert!(stdout.is_empty(), "nothing goes to standard output with a token file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // Running again changes nothing and shows no secret.
        let second = run(&world, &request("deploy"), &sink).await.unwrap();
        assert!(!second.tenant_created);
        assert!(
            matches!(&second.token, TokenOutcome::Exists { token: existing, missing_scopes, expiry_differs }
                if existing.id == token.id && missing_scopes.is_empty() && !expiry_differs),
            "{:?}",
            second.token
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), secret, "the file is untouched");
    }

    #[tokio::test]
    async fn the_created_token_authenticates_against_the_tenant() {
        let world = world().await;
        let mut stdout = Vec::new();
        bootstrap(
            &world.deps,
            &world.services,
            &request("deploy"),
            &TokenSink::Stdout,
            &mut stdout,
        )
        .await
        .unwrap();
        let secret = String::from_utf8(stdout).unwrap();
        let secret = secret.trim();
        assert!(secret.starts_with("dvh_pat_"), "{secret}");
        let context = world
            .services
            .auth
            .authenticate(davhaven_app::services::AuthRequest {
                channel: davhaven_domain::Channel::Api,
                tenant_hint: Some(TenantSlug::parse("acme").unwrap()),
                credential: davhaven_app::services::PresentedCredential::Bearer(SecretString::from(secret)),
                client_ip: None,
                request_id: RequestId::from_uuid(world.deps.ids.new_id()),
            })
            .await
            .unwrap();
        assert_eq!(context.channel, davhaven_domain::Channel::Api);
        assert!(matches!(context.actor, davhaven_domain::Actor::TenantToken(_)));
    }

    #[tokio::test]
    async fn an_existing_tenant_is_not_changed_and_differences_are_reported() {
        let world = world().await;
        run(&world, &request("deploy"), &TokenSink::Stdout).await.unwrap();
        let mut other = request("deploy");
        other.display_name = Some("Acme Corporation".to_owned());
        other.login_domain = Some(DomainName::parse("acme.example.org").unwrap());
        let outcome = run(&world, &other, &TokenSink::Stdout).await.unwrap();
        assert!(!outcome.tenant_created);
        assert_eq!(outcome.differences, vec!["display_name", "login_domain"]);
        assert_eq!(outcome.tenant.display_name, "Acme", "the tenant keeps its values");
    }

    #[tokio::test]
    async fn a_run_with_fewer_flags_reports_no_differences_for_the_values_it_left_out() {
        let world = world().await;
        run(&world, &request("deploy"), &TokenSink::Stdout).await.unwrap();
        // The documented idempotent job: only the tenant and the label.
        let mut bare = request("deploy");
        bare.display_name = None;
        bare.login_domain = None;
        let outcome = run(&world, &bare, &TokenSink::Stdout).await.unwrap();
        assert!(!outcome.tenant_created);
        assert!(outcome.differences.is_empty(), "{:?}", outcome.differences);
        assert_eq!(outcome.tenant.display_name, "Acme");
        // The display name of a tenant that is created without one is its slug.
        let mut fresh = request("deploy");
        fresh.tenant = TenantSlug::parse("globex").unwrap();
        fresh.display_name = None;
        fresh.login_domain = None;
        let created = run(&world, &fresh, &TokenSink::Stdout).await.unwrap();
        assert!(created.tenant_created);
        assert_eq!(created.tenant.display_name, "globex");
    }

    #[tokio::test]
    async fn a_second_label_gets_a_second_token_and_a_taken_file_is_refused() {
        let world = world().await;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("token");
        std::fs::write(&file, "occupied").unwrap();
        let error = run(&world, &request("deploy"), &TokenSink::File(file.clone()))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("exists") && error.contains("no valid token"), "{error}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "occupied");
        let other = run(&world, &request("other"), &TokenSink::Stdout).await.unwrap();
        assert!(matches!(other.token, TokenOutcome::Created(_)));
    }

    #[tokio::test]
    async fn a_principal_token_with_the_same_label_does_not_count_as_the_administration_token() {
        let world = world().await;
        run(&world, &request("deploy"), &TokenSink::Stdout).await.unwrap();
        let ctx = RequestContext::internal(
            run(&world, &request("deploy"), &TokenSink::Stdout)
                .await
                .unwrap()
                .tenant
                .id,
            RequestId::from_uuid(world.deps.ids.new_id()),
        );
        world
            .services
            .principals
            .upsert(
                &ctx,
                PrincipalSpec {
                    name: PrincipalName::parse("olivia").unwrap(),
                    body: PrincipalWrite {
                        kind: PrincipalKind::User,
                        display_name: "Olivia".to_owned(),
                        email: None,
                        addresses: Vec::new(),
                        locale: None,
                        timezone: None,
                        external_ref: None,
                        status: None,
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap();
        world
            .services
            .credentials
            .create_api_token(
                &ctx,
                ApiTokenCreate {
                    kind: TokenKind::Principal,
                    principal: Some(PrincipalName::parse("olivia").unwrap()),
                    label: "ops".to_owned(),
                    scopes: [Scope::EventsRead].into_iter().collect(),
                    expires_at: None,
                    allowed_origins: Vec::new(),
                },
            )
            .await
            .unwrap();
        // A user labelled her token like the administration token of the next run.
        let outcome = run(&world, &request("ops"), &TokenSink::Stdout).await.unwrap();
        let TokenOutcome::Created(token) = outcome.token else {
            panic!("the principal token must not stand in for the administration token");
        };
        assert_eq!((token.kind, token.principal_id), (TokenKind::Tenant, None));
    }

    #[tokio::test]
    async fn a_label_with_surrounding_space_is_found_again_by_the_next_run() {
        let world = world().await;
        let first = run(&world, &request(" deploy "), &TokenSink::Stdout).await.unwrap();
        let TokenOutcome::Created(token) = &first.token else {
            panic!("a token was expected: {first:?}");
        };
        assert_eq!(token.label, "deploy", "the credential service stores the label trimmed");
        // The label that the run typed is the one that is looked for: the token is found, not made a second time.
        let second = run(&world, &request(" deploy "), &TokenSink::Stdout).await.unwrap();
        assert!(
            matches!(&second.token, TokenOutcome::Exists { token: existing, .. } if existing.id == token.id),
            "{:?}",
            second.token
        );
        let third = run(&world, &request("deploy"), &TokenSink::Stdout).await.unwrap();
        assert!(matches!(third.token, TokenOutcome::Exists { .. }), "{:?}", third.token);
    }

    #[tokio::test]
    async fn an_existing_token_that_lacks_scopes_is_reported() {
        let world = world().await;
        let mut narrow = request("deploy");
        narrow.scopes = [Scope::EventsRead].into_iter().collect();
        run(&world, &narrow, &TokenSink::Stdout).await.unwrap();
        let outcome = run(&world, &request("deploy"), &TokenSink::Stdout).await.unwrap();
        let TokenOutcome::Exists { missing_scopes, .. } = &outcome.token else {
            panic!("the token exists: {outcome:?}");
        };
        assert!(
            missing_scopes.contains(&Scope::EventsWrite) && !missing_scopes.contains(&Scope::EventsRead),
            "{missing_scopes:?}"
        );
    }

    #[tokio::test]
    async fn an_existing_token_that_differs_in_its_expiry_is_reported() {
        let world = world().await;
        let mut expiring = request("deploy");
        expiring.expires_at = Some(world.deps.clock.now() + chrono::TimeDelta::days(30));
        run(&world, &expiring, &TokenSink::Stdout).await.unwrap();
        // Same label, now without an expiry: the token that exists does expire.
        let outcome = run(&world, &request("deploy"), &TokenSink::Stdout).await.unwrap();
        assert!(
            matches!(
                outcome.token,
                TokenOutcome::Exists {
                    expiry_differs: true,
                    ..
                }
            ),
            "{:?}",
            outcome.token
        );
        // Asking for an expiry again, a moment later, is no difference: both expire.
        let mut again = expiring.clone();
        again.expires_at = Some(world.deps.clock.now() + chrono::TimeDelta::days(30));
        let outcome = run(&world, &again, &TokenSink::Stdout).await.unwrap();
        assert!(
            matches!(
                outcome.token,
                TokenOutcome::Exists {
                    expiry_differs: false,
                    ..
                }
            ),
            "{:?}",
            outcome.token
        );
    }

    #[tokio::test]
    async fn two_runs_at_the_same_time_create_the_tenant_once() {
        let world = world().await;
        let (asked, sink) = (request("deploy"), TokenSink::Stdout);
        let (first, second) = tokio::join!(run(&world, &asked, &sink), run(&world, &asked, &sink));
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_eq!(
            u8::from(first.tenant_created) + u8::from(second.tenant_created),
            1,
            "exactly one run created the tenant, the other found it and replaced nothing"
        );
        assert_eq!(first.tenant.id, second.tenant.id);
    }

    /// A tenant with a user (and so a personal calendar), returning the calendar's collection key.
    async fn tenant_with_a_calendar(world: &Assembly, slug: &str) -> (TenantId, CollectionKey) {
        let mut asked = request("deploy");
        asked.tenant = TenantSlug::parse(slug).unwrap();
        asked.login_domain = Some(DomainName::parse(&format!("{slug}.example")).unwrap());
        let tenant = run(world, &asked, &TokenSink::Stdout).await.unwrap().tenant.id;
        let ctx = RequestContext::internal(tenant, RequestId::from_uuid(world.deps.ids.new_id()));
        world
            .services
            .principals
            .upsert(
                &ctx,
                PrincipalSpec {
                    name: PrincipalName::parse("olivia").unwrap(),
                    body: PrincipalWrite {
                        kind: PrincipalKind::User,
                        display_name: "Olivia".to_owned(),
                        email: None,
                        addresses: Vec::new(),
                        locale: None,
                        timezone: None,
                        external_ref: None,
                        status: None,
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap();
        let mut tx = world.deps.database.begin(tenant, TxMode::ReadOnly).await.unwrap();
        let owner = tx
            .principals()
            .get_by_name(&PrincipalName::parse("olivia").unwrap())
            .await
            .unwrap();
        let calendars = tx.calendars().list_owned(owner.id).await.unwrap();
        let calendar = calendars.first().expect("the user has a personal calendar");
        (
            tenant,
            CollectionKey {
                kind: CollectionKind::Calendar,
                id: calendar.id.as_uuid(),
            },
        )
    }

    /// The epoch of a collection.
    async fn epoch_of(world: &Assembly, tenant: TenantId, key: CollectionKey) -> Uuid {
        let mut tx = world.deps.database.begin(tenant, TxMode::ReadOnly).await.unwrap();
        tx.changes().state(key).await.unwrap().epoch
    }

    #[tokio::test]
    async fn bumping_the_epoch_reaches_every_collection_or_one_tenant() {
        let world = world().await;
        let database = world.deps.database.as_ref();
        let (acme, acme_calendar) = tenant_with_a_calendar(&world, "acme").await;
        let (globex, globex_calendar) = tenant_with_a_calendar(&world, "globex").await;
        let acme_before = epoch_of(&world, acme, acme_calendar).await;
        let globex_before = epoch_of(&world, globex, globex_calendar).await;

        let one = bump_sync_epoch(database, &EpochScope::Tenant(TenantSlug::parse("acme").unwrap()))
            .await
            .unwrap();
        assert!(one > 0, "the collections of the tenant changed");
        let acme_after = epoch_of(&world, acme, acme_calendar).await;
        assert_ne!(acme_after, acme_before, "the epoch of the tenant's calendar is new");
        assert_eq!(
            epoch_of(&world, globex, globex_calendar).await,
            globex_before,
            "another tenant is not touched"
        );

        // A token issued before the bump: the one of the other tenant still works, the bumped tenant's does not.
        let mut tx = world.deps.database.begin(globex, TxMode::ReadOnly).await.unwrap();
        tx.changes().since(globex_calendar, globex_before, 0, 10).await.unwrap();
        drop(tx);
        let mut tx = world.deps.database.begin(acme, TxMode::ReadOnly).await.unwrap();
        assert!(matches!(
            tx.changes().since(acme_calendar, acme_before, 0, 10).await,
            Err(StoreError::InvalidSyncToken)
        ));
        drop(tx);

        let all = bump_sync_epoch(database, &EpochScope::All).await.unwrap();
        assert!(all > one, "every tenant's collections: {all} against {one}");
        assert_ne!(epoch_of(&world, globex, globex_calendar).await, globex_before);
        assert_ne!(epoch_of(&world, acme, acme_calendar).await, acme_after);

        let missing = bump_sync_epoch(database, &EpochScope::Tenant(TenantSlug::parse("nobody").unwrap()))
            .await
            .unwrap_err()
            .to_string();
        assert!(missing.contains("no tenant `nobody`"), "{missing}");
    }

    #[test]
    fn the_default_scopes_are_what_a_tenant_token_may_hold_without_an_expiry() {
        let scopes = default_scopes();
        assert!(scopes.contains(Scope::PrincipalsWrite) && scopes.contains(Scope::CredentialsWrite));
        assert!(!scopes.contains(Scope::SystemTenants));
        assert!(!scopes.contains(Scope::McpRead) && !scopes.contains(Scope::McpWrite));
    }

    // ---- settings flags ----------------------------------------------------------------------------------------

    /// Every flag of `admin bootstrap` that sets a tenant setting.
    fn flags() -> SettingsFlags {
        SettingsFlags {
            locale: Some(Locale::parse("de-DE").unwrap()),
            timezone: Some(TimeZoneName::parse("Europe/Berlin").unwrap()),
            theme: Some("corporate".to_owned()),
            sender_domain: Some(DomainName::parse("mail.acme.example").unwrap()),
            sender_display_name: Some("Acme Courses".to_owned()),
            auto_create_personal_calendar: Some(false),
            apple_identifier_prefix: Some("example.acme".to_owned()),
            organization_name: Some("Acme Courses Ltd.".to_owned()),
            mcp_enabled: Some(true),
        }
    }

    #[tokio::test]
    async fn the_flags_make_the_settings_of_a_tenant_that_is_created() {
        let world = world().await;
        let mut asked = request("deploy");
        asked.settings = flags();
        let outcome = run(&world, &asked, &TokenSink::Stdout).await.unwrap();
        assert!(outcome.tenant_created);
        let settings = outcome.tenant.settings;
        assert_eq!(settings.locale.as_str(), "de-DE");
        assert_eq!(settings.timezone.as_str(), "Europe/Berlin");
        assert_eq!(settings.theme.as_deref(), Some("corporate"));
        assert_eq!(
            settings.sender.domain.as_ref().map(DomainName::as_str),
            Some("mail.acme.example")
        );
        assert_eq!(settings.sender.display_name.as_deref(), Some("Acme Courses"));
        assert!(!settings.auto_create_personal_calendar);
        assert_eq!(
            settings.client_config.apple_identifier_prefix.as_deref(),
            Some("example.acme")
        );
        assert_eq!(
            settings.client_config.organization_name.as_deref(),
            Some("Acme Courses Ltd.")
        );
        assert!(settings.mcp_enabled);
        // What no flag names keeps the default of the application.
        let defaults = TenantSettings::default();
        assert_eq!(settings.feeds_enabled, defaults.feeds_enabled);
        assert_eq!(settings.sharing, defaults.sharing);
        assert_eq!(settings.scheduling, defaults.scheduling);

        // No flag at all creates the defaults: no theme of its own, so that `templates.default_theme` applies.
        let mut fresh = request("deploy");
        fresh.tenant = TenantSlug::parse("globex").unwrap();
        fresh.login_domain = None;
        let created = run(&world, &fresh, &TokenSink::Stdout).await.unwrap();
        assert_eq!(created.tenant.settings, defaults);
        assert_eq!(created.tenant.settings.theme, None);
    }

    #[tokio::test]
    async fn the_flags_never_change_an_existing_tenant_and_only_the_given_ones_are_compared() {
        let world = world().await;
        let mut first = request("deploy");
        first.settings = flags();
        run(&world, &first, &TokenSink::Stdout).await.unwrap();

        // The same flags again, and fewer flags: nothing to report.
        let same = run(&world, &first, &TokenSink::Stdout).await.unwrap();
        assert!(!same.tenant_created);
        assert!(same.differences.is_empty(), "{:?}", same.differences);
        let mut fewer = request("deploy");
        fewer.settings = SettingsFlags {
            theme: Some("corporate".to_owned()),
            ..SettingsFlags::default()
        };
        let fewer_flags = run(&world, &fewer, &TokenSink::Stdout).await.unwrap();
        assert!(fewer_flags.differences.is_empty(), "{:?}", fewer_flags.differences);

        // Other values: reported by the name of the setting, and the tenant keeps what it has.
        let mut other = request("deploy");
        other.settings = SettingsFlags {
            locale: Some(Locale::en()),
            theme: Some("plain".to_owned()),
            sender_domain: Some(DomainName::parse("other.example").unwrap()),
            auto_create_personal_calendar: Some(true),
            mcp_enabled: Some(false),
            ..SettingsFlags::default()
        };
        let outcome = run(&world, &other, &TokenSink::Stdout).await.unwrap();
        assert_eq!(
            outcome.differences,
            vec![
                "settings.locale",
                "settings.theme",
                "settings.sender.domain",
                "settings.auto_create_personal_calendar",
                "settings.mcp_enabled"
            ]
        );
        assert_eq!(outcome.tenant.settings.locale.as_str(), "de-DE");
        assert_eq!(outcome.tenant.settings.theme.as_deref(), Some("corporate"));
        assert!(outcome.tenant.settings.mcp_enabled);
    }

    #[tokio::test]
    async fn settings_that_do_not_validate_are_reported_with_the_field() {
        let world = world().await;
        let mut asked = request("deploy");
        asked.settings = SettingsFlags {
            theme: Some("Not Valid!".to_owned()),
            ..SettingsFlags::default()
        };
        let error = run(&world, &asked, &TokenSink::Stdout).await.unwrap_err().to_string();
        assert!(
            error.contains("cannot create the tenant") && error.contains("/settings") && error.contains("theme"),
            "{error}"
        );
        // Nothing was created: the corrected run creates the tenant.
        let created = run(&world, &request("deploy"), &TokenSink::Stdout).await.unwrap();
        assert!(created.tenant_created);
    }

    // ---- principal tokens --------------------------------------------------------------------------------------

    /// A tenant `acme` with the service principal `robot`, the user `olivia` and the group `team`; MCP is switched on
    /// with a flag of `admin bootstrap` when `mcp` says so.
    async fn tenant_with_principals(world: &Assembly, mcp: bool) -> TenantId {
        let mut asked = request("deploy");
        asked.settings = SettingsFlags {
            mcp_enabled: Some(mcp),
            ..SettingsFlags::default()
        };
        let tenant = run(world, &asked, &TokenSink::Stdout).await.unwrap().tenant.id;
        let ctx = RequestContext::internal(tenant, RequestId::from_uuid(world.deps.ids.new_id()));
        for (name, kind) in [
            ("robot", PrincipalKind::Service),
            ("olivia", PrincipalKind::User),
            ("team", PrincipalKind::Group),
        ] {
            world
                .services
                .principals
                .upsert(
                    &ctx,
                    PrincipalSpec {
                        name: PrincipalName::parse(name).unwrap(),
                        body: PrincipalWrite {
                            kind,
                            display_name: name.to_owned(),
                            email: None,
                            addresses: Vec::new(),
                            locale: None,
                            timezone: None,
                            external_ref: None,
                            status: None,
                        },
                    },
                    Conditions::none(),
                )
                .await
                .unwrap();
        }
        tenant
    }

    /// A request for a token of `principal` in `acme`, valid for `days` days.
    fn token_request(
        world: &Assembly,
        principal: &str,
        label: &str,
        scopes: &[Scope],
        days: Option<i64>,
    ) -> PrincipalTokenRequest {
        PrincipalTokenRequest {
            tenant: TenantSlug::parse("acme").unwrap(),
            principal: PrincipalName::parse(principal).unwrap(),
            label: label.to_owned(),
            scopes: scopes.iter().copied().collect(),
            expires_at: days.map(|days| world.deps.clock.now() + chrono::TimeDelta::days(days)),
        }
    }

    async fn mint(
        world: &Assembly,
        request: &PrincipalTokenRequest,
        sink: &TokenSink,
        stdout: &mut Vec<u8>,
    ) -> Result<TokenOutcome, ServerError> {
        principal_token(&world.deps, &world.services, request, sink, stdout).await
    }

    /// The context that the authentication of `secret` on MCP gives.
    async fn authenticate_mcp(world: &Assembly, secret: &str) -> Result<RequestContext, davhaven_app::AppError> {
        world
            .services
            .auth
            .authenticate(davhaven_app::services::AuthRequest {
                channel: davhaven_domain::Channel::Mcp,
                tenant_hint: None,
                credential: davhaven_app::services::PresentedCredential::Bearer(SecretString::from(secret.to_owned())),
                client_ip: None,
                request_id: RequestId::from_uuid(world.deps.ids.new_id()),
            })
            .await
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "one scenario from creation to revocation")]
    async fn a_principal_token_is_created_once_listed_used_over_mcp_and_revoked() {
        let world = world().await;
        let tenant = tenant_with_principals(&world, true).await;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("token");
        let sink = TokenSink::File(file.clone());
        let mut stdout = Vec::new();
        let asked = token_request(
            &world,
            "robot",
            "assistant",
            &[Scope::McpRead, Scope::McpWrite],
            Some(30),
        );

        let first = mint(&world, &asked, &sink, &mut stdout).await.unwrap();
        let TokenOutcome::Created(token) = &first else {
            panic!("a token was expected: {first:?}");
        };
        assert_eq!((token.kind, token.label.as_str()), (TokenKind::Principal, "assistant"));
        assert_eq!(token.principal.as_ref().map(PrincipalName::as_str), Some("robot"));
        assert_eq!(token.scopes, asked.scopes);
        // The store keeps microseconds.
        assert_eq!(
            token.expires_at.map(|at| at.timestamp_micros()),
            asked.expires_at.map(|at| at.timestamp_micros())
        );
        let secret = std::fs::read_to_string(&file).unwrap().trim().to_owned();
        assert!(secret.starts_with("dvh_pat_"), "{secret}");
        assert!(stdout.is_empty(), "nothing goes to standard output with a token file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // It is the service principal on MCP, with the scopes it was minted with.
        let context = authenticate_mcp(&world, &secret).await.unwrap();
        assert_eq!(context.tenant, tenant);
        assert!(
            matches!(context.actor, davhaven_domain::Actor::PrincipalToken { principal, .. } if Some(principal) == token.principal_id),
            "{context:?}"
        );
        assert!(context.scopes.contains(Scope::McpRead) && context.scopes.contains(Scope::McpWrite));
        // It does not administer anything.
        assert!(
            world
                .services
                .principals
                .list(
                    &context,
                    davhaven_app::services::PrincipalFilter::default(),
                    PageRequest::first()
                )
                .await
                .is_err()
        );

        // A second run finds it: no secret, no file touched, and what differs is said.
        let second = mint(&world, &asked, &sink, &mut stdout).await.unwrap();
        assert!(
            matches!(&second, TokenOutcome::Exists { token: existing, missing_scopes, expiry_differs }
                if existing.id == token.id && missing_scopes.is_empty() && !expiry_differs),
            "{second:?}"
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap().trim(), secret);
        let wider = token_request(
            &world,
            "robot",
            "assistant",
            &[Scope::McpRead, Scope::McpScheduleExternal],
            None,
        );
        let third = mint(&world, &wider, &sink, &mut stdout).await.unwrap();
        assert!(
            matches!(&third, TokenOutcome::Exists { missing_scopes, expiry_differs, .. }
                if missing_scopes == &[Scope::McpScheduleExternal] && *expiry_differs),
            "{third:?}"
        );

        // The listing is per tenant or per principal and shows no secret.
        let acme = TenantSlug::parse("acme").unwrap();
        let robot = PrincipalName::parse("robot").unwrap();
        let olivia = PrincipalName::parse("olivia").unwrap();
        let all = principal_tokens(&world.deps, &world.services, &acme, None)
            .await
            .unwrap();
        assert_eq!(all.len(), 1);
        assert!(!format!("{all:?}").contains(&secret));
        assert_eq!(
            principal_tokens(&world.deps, &world.services, &acme, Some(&robot))
                .await
                .unwrap()
                .len(),
            1
        );
        let of_olivia = principal_tokens(&world.deps, &world.services, &acme, Some(&olivia))
            .await
            .unwrap();
        assert!(of_olivia.is_empty(), "{of_olivia:?}");

        // The creation is audited like the same request over the management API, with the operator as the actor.
        let actions = audit_actions(&world, tenant).await;
        assert!(actions.contains(&"token.created".to_owned()), "{actions:?}");

        // Revoked, the token stops at once; revoking again changes nothing; the label is free again.
        revoke_principal_token(&world.deps, &world.services, &acme, token.id)
            .await
            .unwrap();
        revoke_principal_token(&world.deps, &world.services, &acme, token.id)
            .await
            .unwrap();
        assert!(authenticate_mcp(&world, &secret).await.is_err());
        assert!(
            principal_tokens(&world.deps, &world.services, &acme, None)
                .await
                .unwrap()[0]
                .revoked_at
                .is_some()
        );
        let actions = audit_actions(&world, tenant).await;
        assert_eq!(actions.iter().filter(|action| *action == "token.revoked").count(), 1);
        let fresh_file = directory.path().join("fresh");
        let again = mint(&world, &asked, &TokenSink::File(fresh_file), &mut stdout)
            .await
            .unwrap();
        assert!(matches!(again, TokenOutcome::Created(ref fresh) if fresh.id != token.id));

        // Only principal tokens of the tenant are revoked here.
        let unknown = TokenId::from_uuid(Uuid::from_u128(1));
        let error = revoke_principal_token(&world.deps, &world.services, &acme, unknown)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("no principal token"), "{error}");
        let administration = run(&world, &request("deploy"), &TokenSink::Stdout).await.unwrap();
        let TokenOutcome::Exists {
            token: tenant_token, ..
        } = administration.token
        else {
            panic!("the administration token of the tenant exists");
        };
        let error = revoke_principal_token(&world.deps, &world.services, &acme, tenant_token.id)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no principal token"),
            "a tenant token is not revoked here: {error}"
        );
    }

    #[tokio::test]
    async fn a_token_is_replaced_without_a_gap_by_a_new_label() {
        let world = world().await;
        tenant_with_principals(&world, true).await;
        let mut stdout = Vec::new();
        let scopes = [Scope::McpRead, Scope::McpWrite];
        let old = mint(
            &world,
            &token_request(&world, "robot", "assistant-2027-01", &scopes, Some(60)),
            &TokenSink::Stdout,
            &mut stdout,
        )
        .await
        .unwrap();
        let TokenOutcome::Created(old) = old else {
            panic!("a token was expected: {old:?}");
        };
        let old_secret = String::from_utf8(std::mem::take(&mut stdout))
            .unwrap()
            .trim()
            .to_owned();

        // The same label while the token is valid mints nothing: the run reports that it exists.
        let same = mint(
            &world,
            &token_request(&world, "robot", "assistant-2027-01", &scopes, Some(60)),
            &TokenSink::Stdout,
            &mut stdout,
        )
        .await
        .unwrap();
        assert!(matches!(same, TokenOutcome::Exists { .. }), "{same:?}");
        assert!(stdout.is_empty(), "no secret is shown for a token that exists");

        // A new label gives a second token that works next to the first, so the connector can be switched over before the
        // old one is revoked.
        let next = mint(
            &world,
            &token_request(&world, "robot", "assistant-2027-02", &scopes, Some(60)),
            &TokenSink::Stdout,
            &mut stdout,
        )
        .await
        .unwrap();
        assert!(matches!(next, TokenOutcome::Created(_)), "{next:?}");
        let next_secret = String::from_utf8(std::mem::take(&mut stdout))
            .unwrap()
            .trim()
            .to_owned();
        assert!(authenticate_mcp(&world, &old_secret).await.is_ok());
        assert!(authenticate_mcp(&world, &next_secret).await.is_ok());

        let acme = TenantSlug::parse("acme").unwrap();
        revoke_principal_token(&world.deps, &world.services, &acme, old.id)
            .await
            .unwrap();
        assert!(authenticate_mcp(&world, &old_secret).await.is_err());
        assert!(authenticate_mcp(&world, &next_secret).await.is_ok());
    }

    #[tokio::test]
    async fn a_principal_token_follows_the_rules_of_the_credential_service() {
        let world = world().await;
        tenant_with_principals(&world, true).await;
        let mut stdout = Vec::new();
        let mcp = [Scope::McpRead];
        let cases: Vec<(PrincipalTokenRequest, &str)> = vec![
            (token_request(&world, "robot", "a", &mcp, None), "/expires_at required"),
            (
                token_request(&world, "robot", "a", &mcp, Some(91)),
                "/expires_at too-far",
            ),
            (
                token_request(&world, "robot", "a", &mcp, Some(-1)),
                "must be in the future",
            ),
            (
                token_request(&world, "robot", "a", &[Scope::PrincipalsWrite], None),
                "/scopes not-allowed",
            ),
            (
                token_request(&world, "team", "a", &mcp, Some(30)),
                "/principal not-allowed",
            ),
            (
                token_request(&world, "nobody", "a", &mcp, Some(30)),
                "has no principal `nobody`",
            ),
            (token_request(&world, "robot", "  ", &mcp, Some(30)), "/label"),
        ];
        for (request, expected) in cases {
            let error = mint(&world, &request, &TokenSink::Stdout, &mut stdout)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
        let mut unknown_tenant = token_request(&world, "robot", "a", &mcp, Some(30));
        unknown_tenant.tenant = TenantSlug::parse("nowhere").unwrap();
        let error = mint(&world, &unknown_tenant, &TokenSink::Stdout, &mut stdout)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("there is no tenant `nowhere`"), "{error}");
        assert!(stdout.is_empty(), "no secret was shown for a refused request");
        let acme = TenantSlug::parse("acme").unwrap();
        assert!(
            principal_tokens(&world.deps, &world.services, &acme, None)
                .await
                .unwrap()
                .is_empty(),
            "nothing was created"
        );

        // The operator is trusted: a user gets MCP scopes from the command line, which the management API refuses for a
        // token without them.
        let for_user = token_request(&world, "olivia", "assistant", &mcp, Some(30));
        assert!(matches!(
            mint(&world, &for_user, &TokenSink::Stdout, &mut stdout).await.unwrap(),
            TokenOutcome::Created(_)
        ));
        assert!(
            String::from_utf8(std::mem::take(&mut stdout))
                .unwrap()
                .starts_with("dvh_pat_")
        );

        // A taken file is refused before anything exists: no token is left without a secret.
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("token");
        std::fs::write(&file, "occupied").unwrap();
        let blocked = token_request(&world, "robot", "blocked", &mcp, Some(30));
        let error = mint(&world, &blocked, &TokenSink::File(file.clone()), &mut stdout)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("exists"), "{error}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "occupied");
        let listed = principal_tokens(&world.deps, &world.services, &acme, None)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1, "only the token of olivia exists");
    }

    #[tokio::test]
    async fn a_tenant_that_did_not_switch_mcp_on_gets_no_mcp_token() {
        let world = world().await;
        tenant_with_principals(&world, false).await;
        let mut stdout = Vec::new();
        let error = mint(
            &world,
            &token_request(&world, "robot", "assistant", &[Scope::McpRead], Some(30)),
            &TokenSink::Stdout,
            &mut stdout,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("MCP is not enabled"), "{error}");
        // Scopes of the API alone are not the switch's business.
        let outcome = mint(
            &world,
            &token_request(&world, "robot", "integration", &[Scope::EventsRead], None),
            &TokenSink::Stdout,
            &mut stdout,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, TokenOutcome::Created(_)));
    }

    #[tokio::test]
    async fn the_principal_tokens_of_a_tenant_are_neither_listed_nor_revoked_through_another_tenant() {
        let world = world().await;
        tenant_with_principals(&world, false).await;
        let mut globex = request("deploy");
        globex.tenant = TenantSlug::parse("globex").unwrap();
        globex.login_domain = Some(DomainName::parse("globex.example").unwrap());
        run(&world, &globex, &TokenSink::Stdout).await.unwrap();
        let mut secret = Vec::new();
        let outcome = mint(
            &world,
            &token_request(&world, "olivia", "calendar-sync", &[Scope::EventsRead], None),
            &TokenSink::Stdout,
            &mut secret,
        )
        .await
        .unwrap();
        let TokenOutcome::Created(token) = outcome else {
            panic!("a token was expected: {outcome:?}");
        };
        let secret = String::from_utf8(secret).unwrap().trim().to_owned();

        let globex = TenantSlug::parse("globex").unwrap();
        let error = revoke_principal_token(&world.deps, &world.services, &globex, token.id)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("tenant `globex` has no principal token `{}`", token.id)),
            "{error}"
        );
        let listed = principal_tokens(&world.deps, &world.services, &globex, None)
            .await
            .unwrap();
        assert!(listed.is_empty(), "{listed:?}");

        // The token of `acme` is untouched and still authenticates.
        let acme = TenantSlug::parse("acme").unwrap();
        let of_acme = principal_tokens(&world.deps, &world.services, &acme, None)
            .await
            .unwrap();
        assert_eq!(of_acme.len(), 1);
        assert_eq!(of_acme[0].revoked_at, None);
        assert!(matches!(
            authenticate_api(&world, &secret).await.actor,
            davhaven_domain::Actor::PrincipalToken { .. }
        ));
    }

    // ---- system tokens -----------------------------------------------------------------------------------------

    /// The context that the authentication of `secret` on the management API gives.
    async fn authenticate_api(world: &Assembly, secret: &str) -> RequestContext {
        world
            .services
            .auth
            .authenticate(davhaven_app::services::AuthRequest {
                channel: davhaven_domain::Channel::Api,
                tenant_hint: None,
                credential: davhaven_app::services::PresentedCredential::Bearer(SecretString::from(secret.to_owned())),
                client_ip: None,
                request_id: RequestId::from_uuid(world.deps.ids.new_id()),
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_system_token_is_created_once_and_manages_tenants() {
        let world = world().await;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("system-token");
        let sink = TokenSink::File(file.clone());
        let mut stdout = Vec::new();

        let first = system_token(&world.deps, "operator", None, &sink, &mut stdout)
            .await
            .unwrap();
        let SystemTokenOutcome::Created(info) = &first else {
            panic!("a token was expected: {first:?}");
        };
        assert_eq!(info.label, "operator");
        assert!(info.scopes.contains(Scope::SystemTenants) && info.scopes.iter().count() == 1);
        let secret = std::fs::read_to_string(&file).unwrap().trim().to_owned();
        assert!(secret.starts_with("dvh_pat_"), "{secret}");
        assert_eq!(stdout, Vec::<u8>::new());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // The token is what `/api/v1/tenants` needs: it authenticates as a system token and creates a tenant.
        let context = authenticate_api(&world, &secret).await;
        assert!(
            matches!(context.actor, davhaven_domain::Actor::SystemToken(_)),
            "{context:?}"
        );
        let created = world
            .services
            .tenants
            .upsert(
                &context,
                TenantSpec {
                    slug: TenantSlug::parse("newco").unwrap(),
                    body: TenantWrite {
                        display_name: "Newco".to_owned(),
                        login_domain: None,
                        status: None,
                        settings: None,
                    },
                },
                Conditions::create_only(),
            )
            .await
            .unwrap();
        assert!(created.created);
        // ... and it reads no calendar data: a tenant token's operations are refused.
        assert!(
            world
                .services
                .principals
                .list(
                    &context,
                    davhaven_app::services::PrincipalFilter::default(),
                    PageRequest::first()
                )
                .await
                .is_err()
        );

        // A second run reports the token and neither shows a secret nor touches the file.
        let second = system_token(&world.deps, "operator", None, &sink, &mut stdout)
            .await
            .unwrap();
        assert!(matches!(second, SystemTokenOutcome::Exists(ref existing) if existing.id == info.id));
        assert_eq!(std::fs::read_to_string(&file).unwrap().trim(), secret);

        // Listing shows it without a secret; after the revocation the label is free again.
        let listed = system_tokens(&world.deps).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].revoked_at.is_none());
        revoke_system_token(&world.deps, info.id).await.unwrap();
        revoke_system_token(&world.deps, info.id).await.unwrap();
        assert!(system_tokens(&world.deps).await.unwrap()[0].revoked_at.is_some());
        let again = system_token(&world.deps, "operator", None, &TokenSink::Stdout, &mut stdout)
            .await
            .unwrap();
        assert!(matches!(again, SystemTokenOutcome::Created(ref fresh) if fresh.id != info.id));
        assert!(String::from_utf8(stdout).unwrap().trim().starts_with("dvh_pat_"));
    }

    #[tokio::test]
    async fn a_system_token_that_cannot_be_delivered_is_not_left_behind() {
        let world = world().await;
        let directory = tempfile::tempdir().unwrap();
        let taken = directory.path().join("taken");
        std::fs::write(&taken, "occupied").unwrap();
        let error = system_token(
            &world.deps,
            "operator",
            None,
            &TokenSink::File(taken.clone()),
            &mut Vec::new(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("exists"), "{error}");
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "occupied");
        assert!(
            system_tokens(&world.deps).await.unwrap().is_empty(),
            "no token without a place for its secret"
        );
        for bad in ["", "a\nb"] {
            assert!(
                system_token(&world.deps, bad, None, &TokenSink::Stdout, &mut Vec::new())
                    .await
                    .is_err()
            );
        }
        let missing = revoke_system_token(&world.deps, TokenId::from_uuid(Uuid::from_u128(7)))
            .await
            .unwrap_err()
            .to_string();
        assert!(missing.contains("no system token"), "{missing}");
    }

    // ---- rotate-keys -------------------------------------------------------------------------------------------

    /// A key file of 48 hex characters for `kid`.
    fn key_secret(kid: &str) -> SecretString {
        SecretString::from(format!("{kid:0<48}").replace('-', "0"))
    }

    /// The crypto of a key ring that holds `keys` with `active` as the key that seals.
    fn crypto(world: &Assembly, active: &str, keys: &[&str]) -> LocalCrypto {
        let material = KeyMaterial::new(
            active,
            keys.iter().map(|kid| ((*kid).to_owned(), key_secret(kid))).collect(),
        )
        .unwrap();
        LocalCrypto::new(&material, Arc::clone(&world.deps.ids))
    }

    /// The assembly's application core with another key ring: the same store, so rows sealed earlier are there.
    fn core_with(world: &Assembly, crypto: LocalCrypto) -> AppCore {
        let mut deps = world.deps.clone();
        deps.keyring = crypto.keyring;
        deps.sealer = crypto.sealer;
        deps.hasher = crypto.hasher;
        AppCore::new(deps)
    }

    /// The two signing secrets of a webhook subscription as the API handed them out, which is what the sealed values must
    /// still say after a rotation of the keys: an oracle that is not the sealer under test.
    struct HandedOut {
        /// The secret of the rotation: the current one.
        current: String,
        /// The secret the subscription was created with: the previous one.
        previous: String,
    }

    /// A tenant with one webhook subscription whose secret was rotated once, so that it holds a current and a previous
    /// sealed secret. Returns the tenant, the subscription and the plaintext secrets as the API gave them out.
    async fn tenant_with_a_webhook(
        world: &Assembly,
        core: &AppCore,
    ) -> (TenantId, davhaven_domain::WebhookId, HandedOut) {
        let tenant = run(world, &request("deploy"), &TokenSink::Stdout)
            .await
            .unwrap()
            .tenant
            .id;
        let ctx = RequestContext::internal(tenant, RequestId::from_uuid(world.deps.ids.new_id()));
        let services = davhaven_app::build_from_core(core);
        let created = services
            .webhooks
            .create(
                &ctx,
                WebhookCreate {
                    url: "https://hooks.example.org/davhaven".parse().unwrap(),
                    description: None,
                    events: vec![EventType::PrincipalCreated],
                    include_details: false,
                    active: true,
                },
            )
            .await
            .unwrap();
        let rotated = services.webhooks.rotate_secret(&ctx, created.webhook.id).await.unwrap();
        (
            tenant,
            created.webhook.id,
            HandedOut {
                current: rotated.secret,
                previous: created.secret,
            },
        )
    }

    /// The two sealed secrets of a subscription and the key ids they name.
    async fn sealed_secrets(world: &Assembly, tenant: TenantId, id: davhaven_domain::WebhookId) -> (Sealed, Sealed) {
        let mut tx = world.deps.database.begin(tenant, TxMode::ReadOnly).await.unwrap();
        let row = tx.webhooks().get(id).await.unwrap();
        (
            Sealed::from_bytes(row.sealed_secret),
            Sealed::from_bytes(
                row.sealed_secret_previous
                    .expect("a rotated secret keeps the previous one"),
            ),
        )
    }

    async fn audit_actions(world: &Assembly, tenant: TenantId) -> Vec<String> {
        let mut tx = world.deps.database.begin(tenant, TxMode::ReadOnly).await.unwrap();
        tx.audit()
            .list(&davhaven_ports::AuditFilter::default(), PageReq::first(1000))
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|row| row.action)
            .collect()
    }

    #[tokio::test]
    async fn rotating_the_keys_seals_every_webhook_secret_under_the_active_key() {
        use secrecy::ExposeSecret as _;

        let world = world().await;
        let before = core_with(&world, crypto(&world, "k1", &["k1"]));
        let (tenant, webhook, secrets) = tenant_with_a_webhook(&world, &before).await;
        let (current, previous) = sealed_secrets(&world, tenant, webhook).await;
        assert_eq!(LocalSealer::key_id_of(&current), Some("k1"));
        assert_eq!(LocalSealer::key_id_of(&previous), Some("k1"));

        // What the sealed values must say is what the API handed out, not what the sealer under test opens. The two
        // secrets differ, so that a sealer or a reseal that swapped the columns would be seen.
        assert_ne!(secrets.current, secrets.previous, "a rotation hands out a new secret");
        let plaintexts: Vec<Vec<u8>> = vec![secrets.current.into_bytes(), secrets.previous.into_bytes()];

        // k2 is the active key now; k1 stays in the ring so that the old values open. Before anything is resealed the
        // ciphertext of k1 is still readable under the new ring, and it says what the API said.
        let after = core_with(&world, crypto(&world, "k2", &["k2", "k1"]));
        let aad = SealAad::webhook_secret(tenant, webhook);
        for (sealed, expected) in [&current, &previous].into_iter().zip(&plaintexts) {
            assert_eq!(
                after.deps().sealer.open(sealed, &aad).unwrap().expose_secret(),
                expected.as_slice(),
                "the retired key stays in the ring, so the old ciphertext opens before the rotation has run"
            );
        }
        let report = rotate_keys(&after).await.unwrap();
        assert_eq!(report.active_key, "k2");
        assert_eq!(
            report.total,
            Counts {
                resealed: 2,
                current: 0,
                failed: 0
            },
            "both secrets of the subscription: {report:?}"
        );
        let (current, previous) = sealed_secrets(&world, tenant, webhook).await;
        assert_eq!(LocalSealer::key_id_of(&current), Some("k2"));
        assert_eq!(LocalSealer::key_id_of(&previous), Some("k2"));

        // With k1 removed from the ring both values still open, and a second run changes nothing.
        let only_k2 = core_with(&world, crypto(&world, "k2", &["k2"]));
        for (sealed, expected) in [&current, &previous].into_iter().zip(&plaintexts) {
            assert_eq!(
                only_k2.deps().sealer.open(sealed, &aad).unwrap().expose_secret(),
                expected.as_slice(),
                "resealed, the values say what they said before and open without the retired key"
            );
        }
        let again = rotate_keys(&only_k2).await.unwrap();
        assert_eq!(
            again.total,
            Counts {
                resealed: 0,
                current: 2,
                failed: 0
            }
        );
        let keys_rotated: Vec<String> = audit_actions(&world, tenant)
            .await
            .into_iter()
            .filter(|action| action == "keys.rotated")
            .collect();
        assert_eq!(keys_rotated.len(), 1, "one record for the run that changed something");
    }

    #[tokio::test]
    async fn a_secret_whose_key_is_gone_is_reported_and_left_alone() {
        let world = world().await;
        let before = core_with(&world, crypto(&world, "k1", &["k1"]));
        let (tenant, webhook, _) = tenant_with_a_webhook(&world, &before).await;
        let (current_before, previous_before) = sealed_secrets(&world, tenant, webhook).await;

        // The ring forgot k1: nothing can be opened, so nothing may change and nothing may be reported as done.
        let forgetful = core_with(&world, crypto(&world, "k2", &["k2"]));
        let report = rotate_keys(&forgetful).await.unwrap();
        assert_eq!(report.total.failed, 2, "{report:?}");
        assert_eq!(report.total.resealed, 0);
        let (current, previous) = sealed_secrets(&world, tenant, webhook).await;
        assert_eq!(
            (current, previous),
            (current_before, previous_before),
            "the rows are unchanged"
        );
        assert!(
            !audit_actions(&world, tenant).await.contains(&"keys.rotated".to_owned()),
            "nothing changed, so nothing is audited"
        );
    }

    #[tokio::test]
    async fn the_values_of_every_tenant_are_resealed() {
        let world = world().await;
        let before = core_with(&world, crypto(&world, "k1", &["k1"]));
        let (first, _, _) = tenant_with_a_webhook(&world, &before).await;
        // A second tenant.
        let mut other = request("deploy");
        other.tenant = TenantSlug::parse("globex").unwrap();
        other.login_domain = Some(DomainName::parse("globex.example").unwrap());
        let second = run(&world, &other, &TokenSink::Stdout).await.unwrap().tenant.id;
        let ctx = RequestContext::internal(second, RequestId::from_uuid(world.deps.ids.new_id()));
        davhaven_app::build_from_core(&before)
            .webhooks
            .create(
                &ctx,
                WebhookCreate {
                    url: "https://hooks.example.org/other".parse().unwrap(),
                    description: None,
                    events: vec![EventType::PrincipalCreated],
                    include_details: false,
                    active: true,
                },
            )
            .await
            .unwrap();
        let after = core_with(&world, crypto(&world, "k2", &["k2", "k1"]));
        let report = rotate_keys(&after).await.unwrap();
        assert_eq!(
            report.total.resealed, 3,
            "two secrets of the first tenant and one of the second: {report:?}"
        );
        assert_eq!(report.total.failed, 0);
        assert!(audit_actions(&world, first).await.contains(&"keys.rotated".to_owned()));
        assert!(audit_actions(&world, second).await.contains(&"keys.rotated".to_owned()));
    }

    /// A tenant with a user and an external account whose sealed tokens say `tokens`, sealed by `core` for the account.
    async fn tenant_with_an_account(
        world: &Assembly,
        core: &AppCore,
        tokens: &[u8],
    ) -> (TenantId, davhaven_domain::ExternalAccountId) {
        let tenant = run(world, &request("deploy"), &TokenSink::Stdout)
            .await
            .unwrap()
            .tenant
            .id;
        let ctx = RequestContext::internal(tenant, RequestId::from_uuid(world.deps.ids.new_id()));
        let services = davhaven_app::build_from_core(core);
        let name = PrincipalName::parse("anna").unwrap();
        services
            .principals
            .upsert(
                &ctx,
                PrincipalSpec {
                    name: name.clone(),
                    body: serde_json::from_str(r#"{"kind": "user", "display_name": "Anna"}"#).unwrap(),
                },
                davhaven_app::services::Conditions::none(),
            )
            .await
            .unwrap();
        let mut tx = core.deps().database.begin(tenant, TxMode::ReadWrite).await.unwrap();
        let principal = tx.principals().get_by_name(&name).await.unwrap();
        let id = davhaven_domain::ExternalAccountId::from_uuid(world.deps.ids.new_id());
        let now = core.deps().clock.now();
        let sealed = core
            .deps()
            .sealer
            .seal(tokens, &SealAad::external_account_tokens(tenant, id))
            .unwrap();
        tx.external_accounts()
            .create(davhaven_domain::ExternalAccount {
                id,
                tenant_id: tenant,
                principal_id: principal.id,
                provider: "google".to_owned(),
                account_ref: "anna@example.org".to_owned(),
                sealed_tokens: sealed.into_bytes(),
                mirror_calendar_id: None,
                sync_state: serde_json::json!({}),
                status: davhaven_domain::ExternalAccountStatus::Active,
                last_error: None,
                created_at: now,
                updated_at: now,
                version: 1,
            })
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (tenant, id)
    }

    async fn sealed_tokens(
        world: &Assembly,
        tenant: TenantId,
        id: davhaven_domain::ExternalAccountId,
    ) -> (Sealed, i64) {
        let mut tx = world.deps.database.begin(tenant, TxMode::ReadOnly).await.unwrap();
        let row = tx.external_accounts().get(id).await.unwrap();
        (Sealed::from_bytes(row.sealed_tokens), row.version)
    }

    #[tokio::test]
    async fn rotating_the_keys_seals_the_tokens_of_external_accounts_under_the_active_key() {
        use secrecy::ExposeSecret as _;

        let world = world().await;
        let before = core_with(&world, crypto(&world, "k1", &["k1"]));
        // What the tokens say is what this test sealed, not what the sealer under test gives back.
        let tokens: &[u8] = br#"{"access_token":"ya29.a","refresh_token":"1//r"}"#;
        let (tenant, account) = tenant_with_an_account(&world, &before, tokens).await;
        let (sealed, version) = sealed_tokens(&world, tenant, account).await;
        assert_eq!(LocalSealer::key_id_of(&sealed), Some("k1"));

        let after = core_with(&world, crypto(&world, "k2", &["k2", "k1"]));
        let report = rotate_keys(&after).await.unwrap();
        assert_eq!(
            report.total,
            Counts {
                resealed: 1,
                current: 0,
                failed: 0
            },
            "{report:?}"
        );
        let (resealed, new_version) = sealed_tokens(&world, tenant, account).await;
        assert_eq!(LocalSealer::key_id_of(&resealed), Some("k2"));
        assert!(new_version > version, "the row was written");
        // Without the retired key the tokens still open, with the associated data of their account only.
        let only_k2 = core_with(&world, crypto(&world, "k2", &["k2"]));
        assert_eq!(
            only_k2
                .deps()
                .sealer
                .open(&resealed, &SealAad::external_account_tokens(tenant, account))
                .unwrap()
                .expose_secret(),
            tokens
        );
        assert!(
            only_k2
                .deps()
                .sealer
                .open(
                    &resealed,
                    &SealAad::external_account_tokens(
                        tenant,
                        davhaven_domain::ExternalAccountId::from_uuid(uuid::Uuid::from_u128(1))
                    )
                )
                .is_err(),
            "the tokens of one account do not open as those of another"
        );
        let again = rotate_keys(&only_k2).await.unwrap();
        assert_eq!(
            again.total,
            Counts {
                resealed: 0,
                current: 1,
                failed: 0
            }
        );
        assert!(audit_actions(&world, tenant).await.contains(&"keys.rotated".to_owned()));
    }

    #[tokio::test]
    async fn tokens_whose_key_is_gone_are_reported_and_left_alone() {
        let world = world().await;
        let before = core_with(&world, crypto(&world, "k1", &["k1"]));
        let (tenant, account) = tenant_with_an_account(&world, &before, b"{}").await;
        let (sealed, version) = sealed_tokens(&world, tenant, account).await;
        let forgetful = core_with(&world, crypto(&world, "k2", &["k2"]));
        let report = rotate_keys(&forgetful).await.unwrap();
        assert_eq!(report.total.failed, 1, "{report:?}");
        assert_eq!(report.total.resealed, 0);
        let (after, after_version) = sealed_tokens(&world, tenant, account).await;
        assert_eq!((after, after_version), (sealed, version), "the row is unchanged");
    }

    /// A production configuration of a job that holds the owner credentials: `database` is the body of `[database]`.
    #[cfg(feature = "store-postgres")]
    fn owner_job(database: &str) -> Config {
        Config::from_toml(&format!(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[plugins]\nstore = \"postgres\"\n\
             [database]\n{database}"
        ))
        .unwrap()
    }

    /// Both commands refuse before they connect: no database is needed, and a connection to `db.internal` would fail
    /// with another error.
    #[cfg(feature = "store-postgres")]
    #[tokio::test]
    async fn the_commands_with_the_owner_role_refuse_an_unencrypted_remote_url_in_production() {
        let clock = davhaven_ports::testing::ManualClock::default();
        for database in [
            r#"migration_url = "postgres://owner:pw@db.internal/davhaven""#,
            // The owner URL falls back to the runtime URL.
            r#"url = "postgres://app:pw@db.internal/davhaven?sslmode=prefer""#,
            // The runtime URL is encrypted, the owner's is not: the owner's is the one these commands open.
            "url = \"postgres://app:pw@db.internal/davhaven?sslmode=verify-full\"\n\
             migration_url = \"postgres://owner:pw@db.internal/davhaven\"",
        ] {
            let config = owner_job(database);
            let errors = [
                migrate(&config).await.unwrap_err().to_string(),
                purge_audit(&config, &clock).await.unwrap_err().to_string(),
            ];
            for error in errors {
                assert!(
                    error.contains("invalid configuration for plugin `postgres`")
                        && error.contains("sslmode=verify-full")
                        && error.contains("`database.allow_insecure_transport = true`")
                        && !error.contains("pw"),
                    "{database}: {error}"
                );
            }
        }
    }

    #[tokio::test]
    async fn the_active_key_of_the_ring_is_the_one_the_report_names() {
        let world = world().await;
        let core = core_with(&world, crypto(&world, "k9", &["k9"]));
        let report = rotate_keys(&core).await.unwrap();
        assert_eq!(
            report.active_key,
            core.deps().keyring.active_kid(KeyPurpose::CredentialPepper)
        );
        assert_eq!(report.total, Counts::default());
    }
}
