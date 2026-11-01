//! Building the fixture world on a deployed instance, and taking it apart again.
//!
//! Everything is made with the requests an operator and calendar clients make: the management API with the
//! administration tokens of the two tenants of the run, and DAV with the app passwords the instance issued for the
//! principals of the world (the invitations of CalendarServer sharing that are still pending, or were declined, cannot be
//! made any other way).

use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::Duration;
use davhaven_domain::{
    GrantAccess, GrantStatus, PrincipalKind, PrincipalName, PrincipalStatus, Scope, ScopeSet, TenantSettings, TokenKind,
};
use davhaven_fixtures::{
    ActorRole, CalendarRef as FixtureCalendarRef, CalendarRole, FixtureCalendar, FixtureCredential, FixtureGrant,
    FixturePrincipal, FixtureWorld, PRINCIPAL_TOKEN_SCOPE_LABEL, TENANT_TOKEN_SCOPE_LABEL, WorldNames,
};
use davhaven_wire::credentials::{ApiTokenCreate, ApiTokenCreated, AppPasswordCreate, AppPasswordCreated};
use davhaven_wire::{
    BatchItem, BatchRequest, BatchResult, CalendarWrite, GrantWrite, MembershipSet, PrincipalView, PrincipalWrite,
    TenantView, TenantWrite,
};
use serde_json::json;

use super::api::{Api, DELETED, V1, WRITTEN};
use super::issuer::{PrincipalTokenIssuer, PrincipalTokenRequest};
use super::{StagingConfig, StagingError};
use crate::credentials::CredentialBook;
use crate::handles::Actor;
use crate::matrix::Surface;
use crate::seed::SENDER_DOMAIN;
use crate::transport::{HttpTransport, TestRequest, Transport};
use crate::xml::Document;

/// The label of everything the runner makes that carries one (tokens, app passwords, webhooks), so that a reset finds it
/// again and never touches what the operator made. The matrices label what they create with it too
/// ([`crate::permissions::admin`]).
pub const LABEL: &str = "conformance";

/// The start of the name of every principal the matrices make (the fixture world has fixed names; these are the others).
pub const HARNESS_PRINCIPAL_PREFIX: &str = "conformance-";

/// The namespace of the CalendarServer extensions.
const CS: &str = "http://calendarserver.org/ns/";

/// A world that exists on a deployed instance.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub(super) config: StagingConfig,
    pub(super) transport: Arc<dyn Transport>,
    pub(super) world: FixtureWorld,
    pub(super) book: CredentialBook,
    /// Whether cases that change something get a world of their own by a reset.
    pub(super) resets: bool,
    /// How many times the world was built again on this instance by this run: part of the idempotency keys of the batches,
    /// because a batch of a new world must not be taken for a repetition of the batch of the old one.
    pub(super) generation: u32,
}

/// `/api/v1/tenants/{slug}`.
pub(super) fn tenant_path(slug: &str) -> String {
    format!("{V1}/tenants/{slug}")
}

/// The management API path of a principal.
pub(super) fn principal_path(tenant: &str, name: &str) -> String {
    format!("{}/principals/{name}", tenant_path(tenant))
}

/// The management API path of a calendar.
pub(super) fn calendar_path(key: &FixtureCalendarRef) -> String {
    format!(
        "{}/calendars/{}",
        principal_path(key.tenant.as_str(), key.owner.as_str()),
        key.slug
    )
}

impl Deployment {
    /// Builds the world of the run on the instance and collects the credentials it issued.
    ///
    /// # Errors
    ///
    /// [`StagingError`] naming the step that failed: an unreachable instance, a tenant that does not exist or has another
    /// login domain than the run needs, a refused request.
    pub async fn provision(config: StagingConfig) -> Result<Self, StagingError> {
        let transport: Arc<dyn Transport> = Arc::new(HttpTransport::new(config.base_url.clone())?);
        Self::provision_over(config, transport).await
    }

    /// [`Deployment::provision`] over another transport (the tests of the runner reach an application over a socket
    /// of their own).
    ///
    /// # Errors
    ///
    /// As [`Deployment::provision`].
    pub async fn provision_over(config: StagingConfig, transport: Arc<dyn Transport>) -> Result<Self, StagingError> {
        match Self::provision_keeping_partial(config, transport, 0).await {
            Ok(deployment) => Ok(deployment),
            Err(failure) => {
                let (error, partial) = *failure;
                Err(match partial {
                    Some(partial) => partial.abandon(error).await,
                    None => error,
                })
            }
        }
    }

    /// Builds the world of generation `generation`. A failure that came after the run had started to write carries what was
    /// built until then, so that the caller can take it apart again; a failure before that (the tokens do not belong to the
    /// tenants, a tenant holds what the run did not make) carries nothing, and nothing is touched.
    pub(super) async fn provision_keeping_partial(
        config: StagingConfig,
        transport: Arc<dyn Transport>,
        generation: u32,
    ) -> Result<Self, Box<(StagingError, Option<Self>)>> {
        let names =
            WorldNames::try_for_run(&config.run_id).map_err(|error| Box::new((StagingError::from(error), None)))?;
        let world = FixtureWorld::with_names(names);
        let mut provisioner = Provisioner::new(&config, Arc::clone(&transport), &world, generation);
        let outcome = provisioner.run().await;
        let Provisioner { book, touched, .. } = provisioner;
        let built = Self {
            config,
            transport,
            world,
            book,
            resets: false,
            generation,
        };
        match outcome {
            Ok(()) => Ok(built),
            Err(error) => Err(Box::new((error, touched.then_some(built)))),
        }
    }

    /// Takes down what a provisioning that failed had built (principals, tokens, webhooks of the run; never a tenant), and
    /// says what went wrong in the first place; when the clean-up fails too, the error says that as well.
    pub(super) async fn abandon(&self, error: StagingError) -> StagingError {
        match self.clear().await {
            Ok(()) => error,
            Err(cleanup) => StagingError::setup(format!("{error}; and taking down what was built failed: {cleanup}")),
        }
    }

    /// The configuration of the run.
    pub const fn config(&self) -> &StagingConfig {
        &self.config
    }

    /// The world, with the names of this run.
    pub const fn world(&self) -> &FixtureWorld {
        &self.world
    }

    /// The credentials the instance issued.
    pub const fn book(&self) -> &CredentialBook {
        &self.book
    }

    /// The transport to the instance.
    pub fn transport(&self) -> Arc<dyn Transport> {
        Arc::clone(&self.transport)
    }

    /// The management API as the administrator of a tenant of the run.
    pub(super) fn admin(&self, tenant: &str) -> Api {
        admin_of(&self.config, &self.world, &self.transport, tenant)
    }

    /// Deletes every principal of both tenants that the run made (with their calendars), the tokens and webhooks the runner
    /// and the matrices made, and builds the world again. What a case that changes something needs: the state it starts
    /// from is the state of a fresh run, with new secrets.
    ///
    /// A tenant that holds a principal the run did not make is not reset: the run would delete somebody else's data.
    ///
    /// # Errors
    ///
    /// [`StagingError`] naming the step that failed.
    pub async fn reset(&self) -> Result<Self, StagingError> {
        self.clear().await?;
        match Self::provision_keeping_partial(
            self.config.clone(),
            Arc::clone(&self.transport),
            self.generation.saturating_add(1),
        )
        .await
        {
            Ok(deployment) => Ok(deployment),
            Err(failure) => {
                let (error, partial) = *failure;
                Err(match partial {
                    Some(partial) => partial.abandon(error).await,
                    None => error,
                })
            }
        }
    }

    /// Whether a principal of a tenant of the run is one that the run made: a principal of the fixture world, or one that a
    /// matrix made (their names start with [`HARNESS_PRINCIPAL_PREFIX`]).
    fn made_by_the_run(&self, tenant: &str, name: &str) -> bool {
        name.starts_with(HARNESS_PRINCIPAL_PREFIX)
            || self
                .world
                .principals
                .iter()
                .any(|principal| principal.tenant.as_str() == tenant && principal.name.as_str() == name)
    }

    /// Deletes what the run made in both tenants: principals, tokens and webhooks. Everything else stays where it is, and a
    /// tenant that holds a principal the run did not make is refused before anything is deleted in it.
    pub(super) async fn clear(&self) -> Result<(), StagingError> {
        for tenant in [&self.world.names.tenant, &self.world.names.other_tenant] {
            let admin = self.admin(tenant);
            let principals: Vec<PrincipalView> = admin
                .all("listing the principals", &format!("{}/principals", tenant_path(tenant)))
                .await?;
            let foreign: Vec<&str> = principals
                .iter()
                .map(|principal| principal.name.as_str())
                .filter(|name| !self.made_by_the_run(tenant, name))
                .collect();
            if !foreign.is_empty() {
                return Err(StagingError::setup(format!(
                    "the tenant `{tenant}` holds principals that the run did not make ({}): the run does not delete them",
                    foreign.join(", ")
                )));
            }
            for principal in principals {
                admin
                    .call_with(
                        &format!("deleting the principal `{}`", principal.name),
                        "DELETE",
                        &format!("{}?purge=true", principal_path(tenant, principal.name.as_str())),
                        None::<&()>,
                        &[("if-match", &format!("\"v{}\"", principal.version))],
                        DELETED,
                    )
                    .await?;
            }
            let tokens: Vec<davhaven_wire::credentials::ApiTokenView> = admin
                .all("listing the tokens", &format!("{}/api-tokens", tenant_path(tenant)))
                .await?;
            for token in tokens
                .into_iter()
                .filter(|token| token.label.starts_with(LABEL) && token.revoked_at.is_none())
            {
                admin
                    .call(
                        &format!("revoking the token `{}`", token.label),
                        "DELETE",
                        &format!("{}/api-tokens/{}", tenant_path(tenant), token.id),
                        None::<&()>,
                        DELETED,
                    )
                    .await?;
            }
            let webhooks: Vec<davhaven_wire::WebhookView> = admin
                .all("listing the webhooks", &format!("{}/webhooks", tenant_path(tenant)))
                .await?;
            for webhook in webhooks.into_iter().filter(|webhook| {
                webhook
                    .description
                    .as_deref()
                    .is_some_and(|text| text.starts_with(LABEL))
            }) {
                admin
                    .call(
                        &format!("deleting the webhook `{}`", webhook.id),
                        "DELETE",
                        &format!("{}/webhooks/{}", tenant_path(tenant), webhook.id),
                        None::<&()>,
                        DELETED,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Deletes both tenants of the run, when the run has a system token; without one the tenants stay.
    ///
    /// # Errors
    ///
    /// [`StagingError`] when a deletion is refused.
    pub async fn teardown(&self) -> Result<bool, StagingError> {
        let Some(system) = &self.config.system_token else {
            return Ok(false);
        };
        let system = Api::new(Arc::clone(&self.transport), Actor::bearer(system));
        for tenant in [&self.world.names.other_tenant, &self.world.names.tenant] {
            let path = tenant_path(tenant);
            let view: TenantView = system.get("reading the tenant", &path).await?;
            system
                .call_with(
                    &format!("deleting the tenant `{tenant}`"),
                    "DELETE",
                    &path,
                    None::<&()>,
                    &[("if-match", &format!("\"v{}\"", view.version))],
                    DELETED,
                )
                .await?;
        }
        Ok(true)
    }
}

/// The management API as the administrator of `tenant`.
fn admin_of(config: &StagingConfig, world: &FixtureWorld, transport: &Arc<dyn Transport>, tenant: &str) -> Api {
    let token = if tenant == world.names.other_tenant {
        &config.other_tenant_token
    } else {
        &config.tenant_token
    };
    Api::new(Arc::clone(transport), Actor::bearer(token))
}

/// The lifetime in days of the principal tokens a run issues: they carry every scope of a principal, the scopes of MCP among them,
/// and a run takes minutes, so a run that leaves its tenants in place (`--keep`, or no system token) leaves nothing that works for a
/// month. The run asks for new tokens whenever it builds its world again.
pub const RUN_TOKEN_DAYS: u32 = 1;

/// How a token of the world is made on a deployed instance.
#[derive(Clone, Copy)]
enum Issue<'a> {
    /// By the management API with the administration token of the tenant, with or without the scopes of MCP.
    Api {
        /// Whether the token carries the scopes of MCP (a service principal of a tenant that has MCP switched on).
        with_mcp: bool,
    },
    /// By the command of the operator (`davhaven admin principal-token create`), the only way a user gets the scopes of MCP.
    Operator {
        /// What runs the command.
        issuer: &'a dyn PrincipalTokenIssuer,
        /// The principal the token acts as.
        principal: &'a PrincipalName,
    },
}

impl Issue<'_> {
    /// Whether the token that is made this way carries the scopes of MCP.
    const fn carries_mcp_scopes(&self) -> bool {
        matches!(self, Self::Operator { .. } | Self::Api { with_mcp: true })
    }
}

/// The state of one provisioning.
struct Provisioner<'a> {
    config: &'a StagingConfig,
    transport: Arc<dyn Transport>,
    world: &'a FixtureWorld,
    book: CredentialBook,
    /// Counts the batches, for their idempotency keys.
    batches: usize,
    /// How many times the world was built again before this one; part of the idempotency keys.
    generation: u32,
    /// Whether the run has started to write: from then on a failure leaves something to take down.
    touched: bool,
    /// The slugs of the tenants that have MCP switched on: only there can a token that opens MCP be issued.
    mcp_tenants: BTreeSet<String>,
}

impl<'a> Provisioner<'a> {
    fn new(config: &'a StagingConfig, transport: Arc<dyn Transport>, world: &'a FixtureWorld, generation: u32) -> Self {
        Self {
            config,
            transport,
            world,
            book: CredentialBook::new(),
            batches: 0,
            generation,
            touched: false,
            mcp_tenants: BTreeSet::new(),
        }
    }

    fn admin(&self, tenant: &str) -> Api {
        admin_of(self.config, self.world, &self.transport, tenant)
    }

    async fn run(&mut self) -> Result<(), StagingError> {
        self.verify_ownership().await?;
        self.touched = true;
        self.tenants().await?;
        self.principals().await?;
        self.memberships().await?;
        // The credentials come before the events: the administration token reaches the events of group and managed calendars
        // only, so the events of the calendars of users are written by their owners.
        self.app_passwords().await?;
        self.tokens().await?;
        self.calendars().await?;
        self.events().await?;
        self.grants().await?;
        self.bindings().await?;
        self.suspensions().await?;
        Ok(())
    }

    /// Checks, before anything is written, that the two tenants are the ones the run was made for: each token reads its tenant,
    /// the login domain is the one the run needs, and the tenant holds nothing but what a run makes (no principal that is not
    /// one of the world). A wrong `--run-id`, tokens of another tenant or a tenant that is somebody's real one stop the run
    /// here, and nothing is changed: not even with a system token, which could replace the settings of a tenant.
    async fn verify_ownership(&self) -> Result<(), StagingError> {
        for tenant in &self.world.tenants {
            let slug = tenant.slug.as_str();
            let view: TenantView = self
                .admin(slug)
                .get(
                    &format!(
                        "reading the tenant `{slug}` with its administration token (does the token belong to the tenant, and does the tenant exist? the run never creates one)"
                    ),
                    &tenant_path(slug),
                )
                .await?;
            if view.login_domain.as_ref() != Some(&tenant.login_domain) {
                return Err(StagingError::setup(format!(
                    "the tenant `{slug}` has the login domain {:?}, the run needs `{}`: create it with `{}`",
                    view.login_domain.as_ref().map(ToString::to_string),
                    tenant.login_domain,
                    bootstrap_command(slug, tenant.login_domain.as_str())
                )));
            }
            let principals: Vec<PrincipalView> = self
                .admin(slug)
                .all("listing the principals", &format!("{}/principals", tenant_path(slug)))
                .await?;
            let foreign: Vec<&str> = principals
                .iter()
                .map(|principal| principal.name.as_str())
                .filter(|name| {
                    !name.starts_with(HARNESS_PRINCIPAL_PREFIX)
                        && !self
                            .world
                            .principals
                            .iter()
                            .any(|principal| principal.tenant.as_str() == slug && principal.name.as_str() == *name)
                })
                .collect();
            if !foreign.is_empty() {
                return Err(StagingError::setup(format!(
                    "refusing to use the tenant `{slug}`: it holds principals that are not part of the fixture world ({}). \
                     A run needs tenants of its own; was the `--run-id` taken from a real tenant?",
                    foreign.join(", ")
                )));
            }
        }
        Ok(())
    }

    /// Aligns the settings of the tenants with the world (with a system token): the tenants exist and were verified, so this
    /// never creates one.
    async fn tenants(&mut self) -> Result<(), StagingError> {
        for tenant in &self.world.tenants {
            let slug = tenant.slug.as_str();
            let path = tenant_path(slug);
            if let Some(system) = &self.config.system_token {
                let mut settings = TenantSettings::default();
                settings.sender.domain = davhaven_domain::DomainName::parse(SENDER_DOMAIN).ok();
                settings.mcp_enabled = true;
                let system = Api::new(Arc::clone(&self.transport), Actor::bearer(system));
                system
                    .call(
                        &format!("aligning the tenant `{slug}`"),
                        "PUT",
                        &path,
                        Some(&TenantWrite {
                            display_name: tenant.display_name.clone(),
                            login_domain: Some(tenant.login_domain.clone()),
                            status: None,
                            settings: Some(settings),
                        }),
                        WRITTEN,
                    )
                    .await?;
            }
            let view: TenantView = self
                .admin(slug)
                .get(&format!("reading the tenant `{slug}`"), &path)
                .await?;
            if view.login_domain.as_ref() != Some(&tenant.login_domain) {
                return Err(StagingError::setup(format!(
                    "the tenant `{slug}` has the login domain {:?}, the run needs `{}`: create it with `{}`",
                    view.login_domain.as_ref().map(ToString::to_string),
                    tenant.login_domain,
                    bootstrap_command(slug, tenant.login_domain.as_str())
                )));
            }
            if view.settings.mcp_enabled {
                self.mcp_tenants.insert(slug.to_owned());
            } else if self.config.token_issuer.is_some() {
                // The operator asked for the tokens of MCP and this tenant cannot have any: the command would be asked for none,
                // and every MCP case of the run would be left out without anybody being told why.
                return Err(StagingError::setup(format!(
                    "the tenant `{slug}` has MCP switched off, so the command for the principal tokens that open MCP has nothing to \
                     issue there: create the tenant with `{}`, give a system token (the run then switches MCP on), or leave \
                     `--principal-token-command` out and the MCP cases of the users are left out",
                    bootstrap_command(slug, tenant.login_domain.as_str())
                )));
            }
        }
        Ok(())
    }

    async fn principals(&self) -> Result<(), StagingError> {
        for principal in &self.world.principals {
            let tenant = principal.tenant.as_str();
            self.admin(tenant)
                .call(
                    &format!("the principal `{}`", principal.name),
                    "PUT",
                    &principal_path(tenant, principal.name.as_str()),
                    Some(&PrincipalWrite {
                        kind: principal.kind,
                        display_name: principal.display_name.clone(),
                        email: principal.email.clone(),
                        addresses: Vec::new(),
                        locale: None,
                        timezone: None,
                        external_ref: None,
                        status: None,
                    }),
                    WRITTEN,
                )
                .await?;
        }
        Ok(())
    }

    async fn memberships(&self) -> Result<(), StagingError> {
        for group in self
            .world
            .principals
            .iter()
            .filter(|principal| principal.kind == PrincipalKind::Group)
        {
            let members = self
                .world
                .memberships
                .iter()
                .filter(|membership| membership.tenant == group.tenant && membership.group == group.name)
                .map(|membership| membership.member.clone())
                .collect();
            let tenant = group.tenant.as_str();
            self.admin(tenant)
                .call(
                    &format!("the members of `{}`", group.name),
                    "PUT",
                    &format!("{}/members", principal_path(tenant, group.name.as_str())),
                    Some(&MembershipSet { members }),
                    WRITTEN,
                )
                .await?;
        }
        Ok(())
    }

    /// Whether a calendar of the world can be made over the API.
    fn is_made_over_the_api(calendar: &FixtureCalendar) -> bool {
        calendar.role != Some(CalendarRole::Mirror) && calendar.kind != davhaven_domain::CalendarKind::Mirror
    }

    async fn calendars(&self) -> Result<(), StagingError> {
        for calendar in self
            .world
            .calendars
            .iter()
            .filter(|calendar| Self::is_made_over_the_api(calendar))
        {
            let tenant = calendar.key.tenant.as_str();
            let admin = self.admin(tenant);
            let path = calendar_path(&calendar.key);
            if calendar.implicit {
                // The personal calendar of a user exists with its user; a tenant that does not create them is not the
                // tenant the world is made for.
                admin
                    .call(
                        &format!(
                            "the personal calendar of `{}` (the tenant setting `auto_create_personal_calendar` must be on)",
                            calendar.key.owner
                        ),
                        "GET",
                        &path,
                        None::<&()>,
                        &[200],
                    )
                    .await?;
                continue;
            }
            admin
                .call(
                    &format!("the calendar `{}`", calendar.key.slug),
                    "PUT",
                    &path,
                    Some(&CalendarWrite {
                        kind: Some(calendar.kind),
                        display_name: calendar.display_name.clone(),
                        description: None,
                        color: None,
                        sort_order: None,
                        components: None,
                    }),
                    WRITTEN,
                )
                .await?;
        }
        Ok(())
    }

    async fn events(&mut self) -> Result<(), StagingError> {
        let calendars: Vec<&FixtureCalendar> = self
            .world
            .calendars
            .iter()
            .filter(|calendar| Self::is_made_over_the_api(calendar))
            .collect();
        for calendar in calendars {
            let items: Vec<BatchItem> = self
                .world
                .events
                .iter()
                .filter(|event| event.calendar == calendar.key)
                .map(|event| BatchItem {
                    external_key: event.external_key.clone(),
                    event: None,
                    ical: Some(event.ics.clone()),
                })
                .collect();
            if items.is_empty() {
                continue;
            }
            self.batches += 1;
            // The key names the run, the world (a reset builds the world again, and a batch of the new world is not a
            // repetition of the batch of the old one) and the batch. A calendar that nobody owns is written with the token of
            // the operator, which is the same token in every world, so the key is what tells the worlds apart.
            let key = format!("{LABEL}-{}-{}-{}", self.config.run_id, self.generation, self.batches);
            let writer = self.event_writer(&calendar.key);
            let response = writer
                .call_with(
                    &format!("the events of `{}`", calendar.key.slug),
                    "POST",
                    &format!("{}/objects/batch", calendar_path(&calendar.key)),
                    Some(&BatchRequest {
                        items,
                        ..BatchRequest::default()
                    }),
                    &[("idempotency-key", &key)],
                    &[200, 201],
                )
                .await?;
            if response.header("idempotent-replayed").is_some() {
                return Err(StagingError::setup(format!(
                    "the batch of the events of `{}` was answered from the idempotency store (the key `{key}` was used before): \
                     nothing was written",
                    calendar.key.slug
                )));
            }
            let result: BatchResult = response
                .json()
                .map_err(|error| StagingError::setup(format!("the answer to the batch cannot be read: {error}")))?;
            if result.has_failures() {
                return Err(StagingError::setup(format!(
                    "the batch of the events of `{}` had failures: {:?}",
                    calendar.key.slug, result.results
                )));
            }
        }
        Ok(())
    }

    /// The API as the one that writes the events of a calendar: its owner when the owner has a token, otherwise the
    /// administrator of the tenant (whose `events:*` scopes reach group and managed calendars).
    fn event_writer(&self, calendar: &FixtureCalendarRef) -> Api {
        let owner_token = self
            .world
            .principal_named(calendar.tenant.as_str(), calendar.owner.as_str())
            .ok()
            .and_then(|principal| principal.role)
            .and_then(|role| self.book.principal_token(role));
        match owner_token {
            Some(token) => Api::new(Arc::clone(&self.transport), Actor::bearer(token)),
            None => self.admin(calendar.tenant.as_str()),
        }
    }

    /// The principals of the world that play a role and are users.
    fn users(&self) -> impl Iterator<Item = &FixturePrincipal> {
        self.world
            .principals
            .iter()
            .filter(|principal| principal.kind == PrincipalKind::User && principal.role.is_some())
    }

    async fn app_passwords(&mut self) -> Result<(), StagingError> {
        let users: Vec<(ActorRole, String, String, String)> = self
            .users()
            .filter_map(|principal| {
                let role = principal.role?;
                let login = principal.login(self.world).ok()?;
                Some((role, principal.tenant.to_string(), principal.name.to_string(), login))
            })
            .collect();
        for (role, tenant, name, login) in users {
            let created: AppPasswordCreated = self
                .admin(&tenant)
                .json(
                    &format!("an app password for `{name}`"),
                    "POST",
                    &format!("{}/app-passwords", principal_path(&tenant, &name)),
                    Some(&AppPasswordCreate {
                        label: LABEL.to_owned(),
                    }),
                    WRITTEN,
                )
                .await?;
            self.book.set_app_password(role, &login, &created.password);
        }
        Ok(())
    }

    /// The login and app password of a principal of the world, as DAV takes them.
    fn dav_actor(&self, tenant: &str, name: &str) -> Result<Actor, StagingError> {
        let principal = self.world.principal_named(tenant, name)?;
        let role = principal
            .role
            .ok_or_else(|| StagingError::setup(format!("the principal `{name}` plays no role")))?;
        self.book
            .actor(role, Surface::Dav, None)
            .ok_or_else(|| StagingError::setup(format!("the principal `{name}` has no app password")))
    }

    /// Accepted grants and grants of groups through the API; invitations that are pending or were declined through the
    /// sharing flow of CalendarServer.
    async fn grants(&self) -> Result<(), StagingError> {
        for grant in &self.world.grants {
            let tenant = grant.calendar.tenant.as_str();
            let grantee = self.world.principal_named(tenant, grant.grantee.as_str())?;
            if grant.status == GrantStatus::Accepted || grantee.kind == PrincipalKind::Group {
                self.admin(tenant)
                    .call(
                        &format!("the grant to `{}`", grant.grantee),
                        "PUT",
                        &format!("{}/grants/{}", calendar_path(&grant.calendar), grant.grantee),
                        Some(&GrantWrite {
                            access: grant.access,
                            required: grant.required,
                        }),
                        WRITTEN,
                    )
                    .await?;
            } else {
                self.invite(grant, grantee).await?;
            }
        }
        Ok(())
    }

    /// The owner shares the calendar the way a CalDAV client does; a sharee who declined answers with the invitation they
    /// find in their notification collection.
    async fn invite(&self, grant: &FixtureGrant, grantee: &FixturePrincipal) -> Result<(), StagingError> {
        let tenant = grant.calendar.tenant.as_str();
        let owner = self.dav_actor(tenant, grant.calendar.owner.as_str())?;
        let collection = format!(
            "/dav/calendars/{tenant}/{}/{}/",
            grant.calendar.owner, grant.calendar.slug
        );
        let address = grantee
            .address()
            .ok_or_else(|| StagingError::setup(format!("the sharee `{}` has no address", grant.grantee)))?;
        let access = match grant.access {
            GrantAccess::Read => "read",
            GrantAccess::ReadWrite => "read-write",
            access @ GrantAccess::Admin => {
                return Err(StagingError::setup(format!(
                    "CalendarServer sharing has no way to offer the access `{access}`"
                )));
            }
        };
        let share = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CS:share xmlns:CS=\"{CS}\"><CS:set><D:href xmlns:D=\"DAV:\">{}</D:href>\
             <CS:common-name>{}</CS:common-name><CS:{access}/></CS:set></CS:share>",
            address.as_str(),
            escape(&grantee.display_name)
        );
        let response = self
            .transport
            .send(dav(&owner, "POST", &collection).content("application/xml; charset=utf-8", share))
            .await?;
        if !response.status.is_success() {
            return Err(StagingError::Unexpected {
                what: format!("the invitation of `{}`", grant.grantee),
                status: response.status.as_u16(),
                excerpt: super::api::excerpt(&response),
            });
        }
        if grant.status != GrantStatus::Declined {
            return Ok(());
        }
        let sharee = self.dav_actor(tenant, grant.grantee.as_str())?;
        let uid = invitation_uid(&self.transport, &sharee, tenant, grant.grantee.as_str())
            .await?
            .ok_or_else(|| StagingError::setup(format!("`{}` received no invitation", grant.grantee)))?;
        let reply = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CS:invite-reply xmlns:CS=\"{CS}\"><CS:invite-declined/><CS:hosturl>\
             <D:href xmlns:D=\"DAV:\">{collection}</D:href></CS:hosturl><CS:in-reply-to>{uid}</CS:in-reply-to></CS:invite-reply>"
        );
        let home = format!("/dav/calendars/{tenant}/{}/", grant.grantee);
        let response = self
            .transport
            .send(dav(&sharee, "POST", &home).content("application/xml; charset=utf-8", reply))
            .await?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(StagingError::Unexpected {
                what: format!("the answer of `{}`", grant.grantee),
                status: response.status.as_u16(),
                excerpt: super::api::excerpt(&response),
            })
        }
    }

    /// Makes the bindings of the principals who see calendars of others (accepted sharees, members of a group, grantees of a
    /// managed calendar): the application creates them when a home is listed for the first time, so every one of them lists
    /// their home once, as their calendar client does after login.
    async fn bindings(&self) -> Result<(), StagingError> {
        let mut listed = std::collections::BTreeSet::new();
        for calendar in self
            .world
            .calendars
            .iter()
            .filter(|calendar| Self::is_made_over_the_api(calendar))
        {
            let tenant = calendar.key.tenant.as_str();
            for bound in &calendar.bound {
                if !listed.insert((tenant, bound.as_str())) {
                    continue;
                }
                if self.world.principal_named(tenant, bound.as_str())?.kind == PrincipalKind::Service {
                    self.list_home_over_mcp(tenant, bound.as_str()).await?;
                    continue;
                }
                let actor = self.dav_actor(tenant, bound.as_str())?;
                let home = format!("/dav/calendars/{tenant}/{bound}/");
                let response = self
                    .transport
                    .send(dav(&actor, "PROPFIND", &home).header("depth", "1").content(
                        "application/xml; charset=utf-8",
                        "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><prop><displayname/></prop></propfind>",
                    ))
                    .await?;
                if response.status.as_u16() != 207 {
                    return Err(StagingError::Unexpected {
                        what: format!("the home of `{bound}`"),
                        status: response.status.as_u16(),
                        excerpt: super::api::excerpt(&response),
                    });
                }
            }
        }
        Ok(())
    }

    /// Makes the bindings of a service principal. It has no app password and no DAV, and the client it has instead of a calendar
    /// client is MCP, whose `list_calendars` lists the home and makes the bindings. A service principal without a token that opens
    /// MCP (a tenant that has MCP switched off) has nothing to list, and nothing is made.
    async fn list_home_over_mcp(&self, tenant: &str, name: &str) -> Result<(), StagingError> {
        let principal = self.world.principal_named(tenant, name)?;
        let Some(role) = principal.role.filter(|role| !self.book.lacks_mcp_token(*role, None)) else {
            return Ok(());
        };
        let actor = self.book.actor(role, Surface::Mcp, None).ok_or_else(|| {
            StagingError::setup(format!(
                "the book has a token of `{name}` that opens MCP and no credential to present it"
            ))
        })?;
        let response = self
            .transport
            .send(crate::permissions::mcp::tool_call(
                &actor,
                1,
                "list_calendars",
                &json!({}),
            ))
            .await?;
        let unexpected = || StagingError::Unexpected {
            what: format!("the home of `{name}` listed through MCP"),
            status: response.status.as_u16(),
            excerpt: super::api::excerpt(&response),
        };
        if !response.status.is_success() {
            return Err(unexpected());
        }
        // A protocol error (`{"error": ...}`, as an answer to an unknown method or invalid parameters) is as much a failure as a
        // tool that reports one: the bindings are made only when the listing was answered with calendars.
        let message = crate::handles::mcp_message(&response)?;
        let listed = message.get("error").is_none()
            && message.pointer("/result/isError") != Some(&serde_json::Value::Bool(true))
            && message
                .pointer("/result/structuredContent/calendars")
                .is_some_and(serde_json::Value::is_array);
        if listed { Ok(()) } else { Err(unexpected()) }
    }

    /// How a credential of the world is made: through the management API (without the scopes of MCP, or with them for a service
    /// principal of a tenant that has MCP switched on), by the command of the operator for a user who needs the scopes of MCP, or
    /// not at all (`None`: nobody can issue this token to this instance, and the cases that need it are left out).
    fn way_to_issue<'x>(
        &'x self,
        credential: &'x FixtureCredential,
        tenant: &str,
    ) -> Result<Option<Issue<'x>>, StagingError> {
        let opens_mcp = credential.scopes.iter().any(Scope::requires_expiry);
        let Some(name) = credential.principal.as_ref().filter(|_| opens_mcp) else {
            // Tenant tokens, and the tokens that carry no scope of MCP.
            return Ok(Some(Issue::Api { with_mcp: false }));
        };
        // Where nothing issues the scopes of MCP, a token for one of them cannot be made, and the one with every scope is made
        // without them.
        let without_mcp =
            (!credential.label.starts_with(PRINCIPAL_TOKEN_SCOPE_LABEL)).then_some(Issue::Api { with_mcp: false });
        let service = self.world.principal_named(tenant, name.as_str())?.kind == PrincipalKind::Service;
        Ok(if !self.mcp_tenants.contains(tenant) {
            without_mcp
        } else if service {
            Some(Issue::Api { with_mcp: true })
        } else if let Some(issuer) = self.config.token_issuer.as_deref() {
            Some(Issue::Operator {
                issuer,
                principal: name,
            })
        } else {
            without_mcp
        })
    }

    /// Principal tokens of every principal that has credentials, tenant tokens of every scope, and the tokens the operator
    /// handed over.
    ///
    /// The scopes of MCP are the exception to what the management API issues (a token only mints tokens with a subset of its
    /// own scopes, and no tenant token can carry `mcp:*`): a service principal gets them from the administration token of its
    /// tenant (ADR-0015), a user only from the operator, whose command the [`PrincipalTokenIssuer`](super::PrincipalTokenIssuer)
    /// of the run runs. The book keeps with each principal token whether it carries them
    /// ([`CredentialBook::set_principal_token`]); the roles whose token does not are asked only what their credential alone
    /// decides.
    async fn tokens(&mut self) -> Result<(), StagingError> {
        let credentials = self.world.credentials.clone();
        for credential in credentials {
            let (Some(token_kind), Some(tenant)) = (credential.token_kind, credential.tenant.as_ref()) else {
                continue;
            };
            let tenant = tenant.as_str();
            // The administration tokens of the tenants are the operator's, and the system token is not minted at all.
            let one_scope = credential.label.starts_with(TENANT_TOKEN_SCOPE_LABEL);
            if token_kind == TokenKind::Tenant && !one_scope {
                continue;
            }
            let Some(issue) = self.way_to_issue(&credential, tenant)? else {
                continue;
            };
            let carries_mcp_scopes = issue.carries_mcp_scopes();
            let secret = self.issue_token(&credential, token_kind, tenant, issue).await?;
            self.record_token(&credential, token_kind, tenant, carries_mcp_scopes, &secret)?;
        }
        self.book.set_tenant_token(None, &self.config.tenant_token);
        self.book.set_other_tenant_admin(&self.config.other_tenant_token);
        if let Some(system) = &self.config.system_token {
            self.book.set_system_token(system);
        }
        Ok(())
    }

    /// Makes the token of a credential of the world the way `issue` says and returns its secret.
    async fn issue_token(
        &self,
        credential: &FixtureCredential,
        token_kind: TokenKind,
        tenant: &str,
        issue: Issue<'_>,
    ) -> Result<String, StagingError> {
        let label = format!("{LABEL}-{}", credential.label);
        match issue {
            Issue::Operator { issuer, principal } => issuer
                .issue(&PrincipalTokenRequest {
                    tenant: self.world.tenant(tenant)?.slug.clone(),
                    principal: principal.clone(),
                    label,
                    scopes: credential.scopes.into(),
                    expires_in_days: RUN_TOKEN_DAYS,
                })
                .await
                .map_err(|reason| {
                    StagingError::setup(format!(
                        "the principal token of `{principal}` in the tenant `{tenant}` could not be issued by the command of the \
                         operator: {reason}"
                    ))
                }),
            Issue::Api { with_mcp } => {
                let login_domain = self.world.tenant(tenant)?.login_domain.to_string();
                let scopes: ScopeSet = credential
                    .scopes
                    .iter()
                    .filter(|scope| with_mcp || !scope.requires_expiry())
                    .collect();
                let now = self.config.clock.now();
                let created: ApiTokenCreated = self
                    .admin(tenant)
                    .json(
                        &format!("the token `{}`", credential.label),
                        "POST",
                        &format!("{}/api-tokens", tenant_path(tenant)),
                        Some(&ApiTokenCreate {
                            kind: token_kind,
                            principal: credential.principal.clone(),
                            label,
                            scopes,
                            // A token of the world that expires does so after the run, not after the lifetime the in-process
                            // world gives it.
                            expires_at: credential
                                .expires_in_days
                                .map(|_| now + Duration::days(i64::from(RUN_TOKEN_DAYS))),
                            allowed_origins: Vec::new(),
                        }),
                        WRITTEN,
                    )
                    .await
                    .map_err(|error| too_weak(error, tenant, &login_domain))?;
                Ok(created.secret)
            }
        }
    }

    /// Puts the secret of a token that was made into the book, under the role it belongs to, and with whether it carries the
    /// scopes of MCP.
    fn record_token(
        &mut self,
        credential: &FixtureCredential,
        token_kind: TokenKind,
        tenant: &str,
        carries_mcp_scopes: bool,
        secret: &str,
    ) -> Result<(), StagingError> {
        let mut carried = credential.scopes.iter();
        let one_scope = match (carried.next(), carried.next()) {
            (Some(scope), None) => Some(scope),
            _ => None,
        };
        match (token_kind, credential.principal.as_ref()) {
            (TokenKind::Principal, Some(name)) => {
                let Some(role) = self.world.principal_named(tenant, name.as_str())?.role else {
                    return Ok(());
                };
                if credential.label.starts_with(PRINCIPAL_TOKEN_SCOPE_LABEL) {
                    if let Some(scope) = one_scope {
                        self.book.set_scoped_principal_token(role, scope.as_str(), secret);
                    }
                } else {
                    self.book.set_principal_token(role, secret, carries_mcp_scopes);
                }
            }
            (TokenKind::Tenant, _) => {
                if let Some(scope) = one_scope {
                    self.book.set_tenant_token(Some(scope.as_str()), secret);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Suspends the principals of the world that are not active; last, because nothing above could act for them otherwise.
    async fn suspensions(&self) -> Result<(), StagingError> {
        for principal in self
            .world
            .principals
            .iter()
            .filter(|p| p.status != PrincipalStatus::Active)
        {
            let tenant = principal.tenant.as_str();
            self.admin(tenant)
                .call(
                    &format!("suspending `{}`", principal.name),
                    "PATCH",
                    &principal_path(tenant, principal.name.as_str()),
                    Some(&json!({"status": principal.status.as_str()})),
                    WRITTEN,
                )
                .await?;
        }
        Ok(())
    }
}

/// The command that creates a tenant a run can use: with the administration token a run needs, which carries every scope a
/// tenant token may hold (the default of the command) and does not expire, and with MCP switched on (the MCP column needs it).
pub fn bootstrap_command(tenant: &str, login_domain: &str) -> String {
    format!("davhaven admin bootstrap --tenant {tenant} --login-domain {login_domain} --mcp-enabled --print-token")
}

/// Explains a refusal to mint a token that the administration token of the tenant is too weak for.
fn too_weak(error: StagingError, tenant: &str, login_domain: &str) -> StagingError {
    match &error {
        StagingError::Unexpected {
            status: 403,
            excerpt,
            what,
        } if excerpt.contains("cannot grant scopes") => StagingError::setup(format!(
            "{what}: the administration token of the tenant `{tenant}` does not carry every scope the run needs. Create the \
             tenant with `{}` (without `--scope`)",
            bootstrap_command(tenant, login_domain)
        )),
        _ => error,
    }
}

/// A DAV request with the credentials of `actor`.
pub(super) fn dav(actor: &Actor, method: &str, target: &str) -> TestRequest {
    crate::permissions::request(actor, method, target)
}

/// The text of an XML element or attribute value.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The `UID` of the first invitation in the notification collection of a principal, as that principal reads it.
///
/// # Errors
///
/// [`StagingError`] when a request fails.
pub(super) async fn invitation_uid(
    transport: &Arc<dyn Transport>,
    actor: &Actor,
    tenant: &str,
    name: &str,
) -> Result<Option<String>, StagingError> {
    let collection = format!("/dav/calendars/{tenant}/{name}/notifications/");
    let listing = transport
        .send(dav(actor, "PROPFIND", &collection).header("depth", "1").content(
            "application/xml; charset=utf-8",
            "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><prop><getetag/><resourcetype/></prop></propfind>",
        ))
        .await?;
    if listing.status.as_u16() != 207 {
        return Err(StagingError::Unexpected {
            what: format!("the notifications of `{name}`"),
            status: listing.status.as_u16(),
            excerpt: super::api::excerpt(&listing),
        });
    }
    let entries = Document::parse(&listing.text())
        .and_then(|document| document.multistatus())
        .map_err(|error| StagingError::setup(format!("the notification listing cannot be read: {error}")))?;
    for entry in entries.iter().filter(|entry| entry.href != collection) {
        let notification = transport.send(dav(actor, "GET", &entry.href)).await?;
        if !notification.status.is_success() {
            continue;
        }
        let uids = Document::parse(&notification.text())
            .and_then(|document| document.select(&format!("//{{{CS}}}invite-notification/{{{CS}}}uid")))
            .map_err(|error| StagingError::setup(format!("a notification cannot be read: {error}")))?;
        if let Some(uid) = uids.first() {
            return Ok(Some(uid.trim().to_owned()));
        }
    }
    Ok(None)
}
