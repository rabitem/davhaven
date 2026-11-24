//! OAuth (PKCE) flows for external calendar providers and the management of connected accounts (PLAN 2.10, 4.2).
//!
//! A tenant administrator with `providers:manage` connects an account for a principal:
//!
//! 1. `POST …/external-accounts` ([`ExternalAccountService::start`]) stores a **single-use state** (ten minutes, bound to the
//!    tenant, the principal and the provider) with the sealed PKCE verifier and answers the provider's consent URL. The state
//!    is `{tenant}.{secret}` (see the `flow` module), because the callback carries no credential and has to find the transaction of the
//!    tenant that holds it.
//! 2. The person consents at the provider, which sends the browser to `GET /oauth/{provider}/callback`
//!    ([`ExternalAccountService::complete`], served by the web surface). The state is **consumed first**, in a transaction of
//!    its own, so that nothing that happens next can use it twice; the code is exchanged with the verifier; the calendar to
//!    mirror is chosen (the primary one); and **in one transaction** the mirror calendar (kind `mirror`, owned by the
//!    principal, read-only for everybody but the sync engine), the account with its sealed tokens and the audit record are
//!    written. The answer is the `oauth_result` page, a success page or, whatever went wrong at the provider (a refused
//!    consent, a rejected code, an account without calendars), a failure page that says so without saying why: the person
//!    starts again. An unknown, expired or used state and a provider other than the state's answer 404 and reveal nothing.
//! 3. The sync engine (`crate::sync_engine`) pulls the mirror from then on.
//!
//! Connecting the same account of the same provider for the same principal again **replaces its tokens** and switches it on
//! again (the way back from `disabled`, after the person removed the access, and from `mirror_missing`), and keeps its mirror
//! calendar, or makes a new one when the old one is gone. The update is retried when a worker claimed the account at the same
//! moment. Both are audited as `external_account.created`: a connection. The tokens of a connection that could not be stored are
//! given back to the provider only when no account holds the grant: at Google, revoking a token ends the whole grant of the person
//! to this client, so it would end the access of the account that is connected already.
//!
//! Disconnecting ([`ExternalAccountService::delete`]) soft-deletes the mirror calendar (like any calendar, it is purged after
//! `retention.deleted_calendar_days`; the API refuses to delete a mirror directly, because the account would be left without one),
//! deletes the account and **then** asks the provider to revoke the tokens, best effort: a provider that cannot be reached must
//! not keep an account connected, and a grant that another account of the tenant still holds (the same account of the provider
//! connected for two principals) is not revoked.
//!
//! # What the provider list shows
//!
//! Every provider of the build that was selected, whether it is switched on or not, and the providers the project ships
//! ([`KNOWN_PROVIDERS`]) when the build has them not, as switched off. The management API and its documents therefore do not
//! depend on cargo features (PLAN 2.10); starting a flow for a provider that is off answers 409 `feature-not-enabled`, and for
//! a name that is none of them 404.

mod flow;
pub(crate) mod tokens;

use async_trait::async_trait;
use chrono::TimeDelta;
use davhaven_domain::audit::ExternalAccountAudit;
use davhaven_domain::events::CalendarPayload;
use davhaven_domain::{
    AdminOperation, AuditEvent, Calendar, CalendarKind, CalendarSlug, ComponentKind, ErrorKind, EventPayload,
    EventType, ExternalAccount, ExternalAccountId, ExternalAccountStatus, Principal, PrincipalId, PrincipalKind,
    PrincipalName, PrincipalStatus, RequestContext, RequestId, Tenant, TenantId, TenantStatus,
};
use davhaven_ports::{
    ExternalAccountFilter, OAuthGrant, OAuthState, OAuthTokens, PageReq, Provider, RemoteCalendar, RenderRequest,
    SealAad, Sealed, StoreError, TemplateName, Tx, TxMode,
};
use davhaven_wire::{AuthorizationUrl, ExternalAccountView, Page, ProviderView};
use secrecy::{ExposeSecret, SecretString};

use crate::audit::Journal;
use crate::authz::{admin, check_color, lock_one, principal_by_id, principal_named};
use crate::calendars::{NewCalendar, provision};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::paging;
use crate::services::{CallbackParams, ExternalAccountService, PageRequest, RenderedPage};
use crate::sync_engine::{SyncState, error_code};
use crate::wiring::AppCore;

/// The providers the project ships. A deployment whose build lacks one still lists it, as switched off.
pub const KNOWN_PROVIDERS: [&str; 2] = ["google", "microsoft"];

/// How long a state is valid: the time the person has at the consent screen.
const STATE_TTL: TimeDelta = TimeDelta::minutes(10);

/// The listing name that binds cursors to the list of accounts.
const LISTING: &str = "external-accounts";

/// The longest display name of a mirror calendar, in characters.
const MAX_NAME_CHARS: usize = 200;

/// How many accounts of one provider of one principal a reconnection looks at, as the page size of that listing. It is no limit of
/// accounts: a person with more has the later ones connected again as new accounts instead of replaced.
const ACCOUNTS_PER_PAGE: u32 = 200;

/// How often the update of a reconnection is tried when the account changed in between (a worker claimed it).
const CONNECT_ATTEMPTS: u32 = 3;

/// The [`ExternalAccountService`] of the application.
#[derive(Debug, Clone)]
pub struct ExternalAccountServiceImpl {
    core: AppCore,
}

/// A provider by name, as the deployment has it.
enum Lookup<'a> {
    /// Selected and switched on.
    On(&'a dyn Provider),
    /// Known, but not selected, not built or switched off.
    Off,
    /// Not a provider of the project and not selected.
    Unknown,
}

/// What a connection brings: the provider it is at, the grant that was given and the calendar to mirror.
#[derive(Clone, Copy)]
struct Connection<'a> {
    provider: &'a dyn Provider,
    grant: &'a OAuthGrant,
    remote: &'a RemoteCalendar,
}

/// The display name of a calendar that mirrors `account_ref` of a provider: printable text of a bounded length.
fn mirror_name(provider: &str, account_ref: &str) -> String {
    let text: String = format!("{provider}: {account_ref}")
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_NAME_CHARS)
        .collect();
    text.trim().to_owned()
}

/// The slug of the mirror calendar of `account` at `provider`: the provider and the random end of the account id.
fn mirror_slug(provider: &str, account: ExternalAccountId) -> AppResult<CalendarSlug> {
    let tail: String = account.as_uuid().simple().to_string().chars().skip(20).collect();
    CalendarSlug::parse(&format!("{provider}-{tail}")).map_err(AppError::internal)
}

/// The calendar to mirror: the primary one of the account, else the first.
fn choose(calendars: &[RemoteCalendar]) -> Option<&RemoteCalendar> {
    calendars.iter().find(|calendar| calendar.primary).or(calendars.first())
}

fn payload_of(calendar: &Calendar) -> EventPayload {
    EventPayload::Calendar(CalendarPayload {
        calendar: calendar.id,
        owner: calendar.owner_id,
        kind: calendar.kind,
    })
}

fn audit_of(account: &ExternalAccount) -> ExternalAccountAudit {
    ExternalAccountAudit {
        external_account: account.id,
        principal: account.principal_id,
        provider: account.provider.clone(),
    }
}

impl ExternalAccountServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }

    fn lookup(&self, name: &str) -> Lookup<'_> {
        match self.core.provider(name) {
            Some(provider) if provider.enabled() => Lookup::On(provider.as_ref()),
            Some(_) => Lookup::Off,
            None if KNOWN_PROVIDERS.contains(&name) => Lookup::Off,
            None => Lookup::Unknown,
        }
    }

    /// The `oauth_result` page, in the language of the visitor when the context carries one (the web surface sends none for a
    /// callback today), else of the tenant.
    async fn result_page(
        &self,
        ctx: &RequestContext,
        tenant: &Tenant,
        provider: &str,
        success: bool,
    ) -> AppResult<RenderedPage> {
        let display = self
            .core
            .provider(provider)
            .map_or(provider, |candidate| candidate.display_name());
        let rendered = self
            .core
            .deps()
            .templates
            .render(RenderRequest {
                template: TemplateName::parse("oauth_result").map_err(AppError::internal)?,
                locale: ctx.locale.clone().unwrap_or_else(|| tenant.settings.locale.clone()),
                theme: tenant.settings.theme_name().to_owned(),
                model: serde_json::json!({"success": success, "provider": display}),
            })
            .await?;
        Ok(RenderedPage { html: rendered.html })
    }

    /// The verifier that `start` sealed for `state`.
    fn open_verifier(&self, tenant: TenantId, state: &OAuthState) -> Option<SecretString> {
        let sealed = Sealed::from_bytes(state.pkce_verifier_sealed.clone());
        let opened = self
            .core
            .deps()
            .sealer
            .open(&sealed, &SealAad::oauth_verifier(tenant, state.id))
            .ok()?;
        std::str::from_utf8(opened.expose_secret()).ok().map(SecretString::from)
    }

    /// Asks the provider to revoke `tokens`, best effort: the refresh token ends the access for good, an access token only
    /// the hour that is left of it.
    async fn revoke(&self, provider: &dyn Provider, tokens: &OAuthTokens) {
        let token = tokens.refresh_token.as_ref().unwrap_or(&tokens.access_token);
        if let Err(error) = provider.oauth().revoke(token).await {
            tracing::warn!(
                provider = provider.name(),
                kind = error.kind.as_str(),
                "the provider did not revoke the tokens of a disconnected account"
            );
        }
    }

    /// Whether an account of the tenant at `provider` holds the grant of `account_ref`, whoever connected it.
    ///
    /// A provider may end the whole grant of a person to the client when one token of it is revoked, so a token is revoked only
    /// when no account is left that depends on the grant. `true` for an answer that cannot be had (the store failed): then the
    /// token is left alone.
    async fn grant_is_held(&self, tenant: TenantId, provider: &str, account_ref: &str) -> bool {
        match self.find_account(tenant, None, provider, account_ref).await {
            Ok(found) => found.is_some(),
            Err(error) => {
                tracing::warn!(
                    provider, kind = ?error.kind(),
                    "the accounts that hold a grant cannot be listed, so its tokens are not revoked"
                );
                true
            }
        }
    }

    /// The account of `provider` for `account_ref` in the tenant: of `principal` when given, of anyone else.
    async fn find_account(
        &self,
        tenant: TenantId,
        principal: Option<PrincipalId>,
        provider: &str,
        account_ref: &str,
    ) -> AppResult<Option<ExternalAccount>> {
        let mut tx = self.core.deps().database.begin(tenant, TxMode::ReadOnly).await?;
        let account = Self::account_of(tx.as_mut(), principal, provider, account_ref).await?;
        tx.commit().await?;
        Ok(account)
    }

    /// The account of `provider` for `account_ref` (case-insensitive) in the transaction, looked for among the accounts of
    /// `principal` or, without one, of everybody.
    async fn account_of(
        tx: &mut dyn Tx,
        principal: Option<PrincipalId>,
        provider: &str,
        account_ref: &str,
    ) -> AppResult<Option<ExternalAccount>> {
        let filter = ExternalAccountFilter {
            principal,
            provider: Some(provider.to_owned()),
        };
        let mut request = PageReq::first(ACCOUNTS_PER_PAGE);
        loop {
            let page = tx.external_accounts().list(&filter, request).await?;
            if let Some(found) = page
                .items
                .into_iter()
                .find(|account| account.account_ref.eq_ignore_ascii_case(account_ref))
            {
                return Ok(Some(found));
            }
            match page.next {
                Some(after) => request = request.after(after),
                None => return Ok(None),
            }
        }
    }

    /// Gives back the access of a grant that no account of the tenant holds: the connection did not come about.
    async fn give_back(&self, tenant: TenantId, provider: &dyn Provider, grant: &OAuthGrant) {
        if self.grant_is_held(tenant, provider.name(), &grant.account_ref).await {
            tracing::info!(
                provider = provider.name(),
                "the tokens of an authorization that was not stored are kept: an account holds the grant"
            );
        } else {
            self.revoke(provider, &grant.tokens).await;
        }
    }

    /// Writes the result of a successful authorization: the account and its mirror calendar, or, for an account that is
    /// connected already, its new tokens. The update of an account that a worker claimed at the same moment is tried again.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal is not there any more or cannot own a calendar, store failures.
    async fn connect(&self, tenant: TenantId, principal: PrincipalId, connection: &Connection<'_>) -> AppResult<()> {
        let mut attempt = 1;
        loop {
            match self.connect_once(tenant, principal, connection).await {
                // A worker claimed the account (its lease is a new version) between the reading and the update: read it again.
                Err(error) if error.kind() == ErrorKind::PreconditionFailed && attempt < CONNECT_ATTEMPTS => {
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    /// One try at [`connect`](Self::connect).
    async fn connect_once(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
        connection: &Connection<'_>,
    ) -> AppResult<()> {
        let Connection {
            provider,
            grant,
            remote,
        } = *connection;
        let deps = self.core.deps();
        let ctx = RequestContext::internal(tenant, RequestId::from_uuid(deps.ids.new_id()));
        let journal = Journal::new(&self.core, &ctx);
        let mut tx = deps.database.begin(tenant, TxMode::ReadWrite).await?;
        let owner = principal_by_id(tx.as_mut(), principal).await?;
        if owner.status != PrincipalStatus::Active || owner.kind != PrincipalKind::User {
            return Err(AppError::not_found());
        }
        let now = deps.clock.now();
        let connected = Self::account_of(tx.as_mut(), Some(owner.id), provider.name(), &grant.account_ref).await?;
        let account = if let Some(account) = connected {
            // The way back from `disabled`, or new tokens for an account that works: a connection like the first one. Whatever
            // the account remembered of its failures and of its cursor is of the access that was there before, except for the
            // calendar it mirrors, which is kept while the account still has it. Clearing the state also clears the lease of a
            // pull that is running: that pull works from the grant that was replaced, and its result is dropped.
            let before = SyncState::read(&account.sync_state);
            // The mirror calendar is kept while it is there. One that was deleted (or never recorded) is made again, which is
            // the way back from `mirror_missing`.
            let kept = match account.mirror_calendar_id {
                Some(calendar) => match tx.calendars().get(calendar).await {
                    Ok(_) => Some(calendar),
                    Err(StoreError::NotFound) => None,
                    Err(error) => return Err(error.into()),
                },
                None => None,
            };
            // The cursor goes on only for a mirror that holds what it names: a new mirror is empty, and a pull that asked for
            // the changes since the cursor would never fill it.
            let cursor = before
                .cursor
                .filter(|_| kept.is_some() && before.calendar.as_deref() == Some(remote.remote_id.as_str()));
            let state = SyncState {
                calendar: Some(remote.remote_id.clone()),
                cursor,
                ..SyncState::default()
            };
            let mirror = match kept {
                Some(calendar) => calendar,
                None => {
                    self.new_mirror(tx.as_mut(), &journal, &owner, account.id, connection)
                        .await?
                        .id
                }
            };
            let updated = ExternalAccount {
                sealed_tokens: tokens::seal(&self.core, tenant, account.id, &grant.tokens)?,
                mirror_calendar_id: Some(mirror),
                sync_state: state.document(),
                status: ExternalAccountStatus::Active,
                last_error: None,
                updated_at: now,
                ..account.clone()
            };
            tx.external_accounts().update(updated, account.version).await?
        } else {
            let id = ExternalAccountId::from_uuid(deps.ids.new_id());
            let calendar = self.new_mirror(tx.as_mut(), &journal, &owner, id, connection).await?;
            let state = SyncState {
                calendar: Some(remote.remote_id.clone()),
                ..SyncState::default()
            };
            tx.external_accounts()
                .create(ExternalAccount {
                    id,
                    tenant_id: tenant,
                    principal_id: owner.id,
                    provider: provider.name().to_owned(),
                    account_ref: grant.account_ref.clone(),
                    sealed_tokens: tokens::seal(&self.core, tenant, id, &grant.tokens)?,
                    mirror_calendar_id: Some(calendar.id),
                    sync_state: state.document(),
                    status: ExternalAccountStatus::Active,
                    last_error: None,
                    created_at: now,
                    updated_at: now,
                    version: 1,
                })
                .await?
        };
        journal
            .audit(tx.as_mut(), AuditEvent::ExternalAccountCreated(audit_of(&account)))
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Makes the mirror calendar of `account` for `owner` and announces it.
    async fn new_mirror(
        &self,
        tx: &mut dyn Tx,
        journal: &Journal<'_>,
        owner: &Principal,
        account: ExternalAccountId,
        connection: &Connection<'_>,
    ) -> AppResult<Calendar> {
        let Connection {
            provider,
            grant,
            remote,
        } = *connection;
        let (calendar, _binding) = provision(
            &self.core,
            tx,
            owner,
            NewCalendar {
                slug: mirror_slug(provider.name(), account)?,
                kind: CalendarKind::Mirror,
                display_name: mirror_name(provider.display_name(), &grant.account_ref),
                description: None,
                color: remote
                    .color
                    .as_deref()
                    .and_then(|color| check_color("/color", Some(color)).ok().flatten()),
                sort_order: 0,
                components: vec![ComponentKind::Event],
                timezone_ics: None,
                schedule_transp: None,
            },
        )
        .await?;
        journal
            .publish(tx, EventType::CalendarCreated, payload_of(&calendar))
            .await?;
        Ok(calendar)
    }
}

/// An invalid body: the field and what is wrong with it.
fn field_problem(pointer: &'static str, code: &'static str, text: &'static str) -> AppError {
    AppError::invalid(SafeMessage::from_static(text)).with_field_error(pointer, code, SafeMessage::from_static(text))
}

fn view(account: &ExternalAccount, principal: PrincipalName) -> ExternalAccountView {
    let sync = SyncState::read(&account.sync_state);
    ExternalAccountView {
        id: account.id,
        principal_id: account.principal_id,
        principal,
        provider: account.provider.clone(),
        account_ref: account.account_ref.clone(),
        mirror_calendar_id: account.mirror_calendar_id,
        status: account.status,
        last_error: account.last_error.clone(),
        last_error_code: account.last_error.as_deref().and_then(error_code).map(str::to_owned),
        last_sync_at: sync.last_sync_at,
        next_sync_at: sync.next_sync_at,
        created_at: account.created_at,
        updated_at: account.updated_at,
    }
}

#[async_trait]
impl ExternalAccountService for ExternalAccountServiceImpl {
    async fn providers(&self, ctx: &RequestContext) -> AppResult<Vec<ProviderView>> {
        admin(ctx, AdminOperation::ListProviders)?;
        let mut views: Vec<ProviderView> = self
            .core
            .deps()
            .providers
            .iter()
            .map(|provider| ProviderView {
                name: provider.name().to_owned(),
                enabled: provider.enabled(),
            })
            .collect();
        for name in KNOWN_PROVIDERS {
            if !views.iter().any(|view| view.name == name) {
                views.push(ProviderView {
                    name: name.to_owned(),
                    enabled: false,
                });
            }
        }
        views.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(views)
    }

    async fn start(
        &self,
        ctx: &RequestContext,
        provider: &str,
        principal: &PrincipalName,
    ) -> AppResult<AuthorizationUrl> {
        admin(ctx, AdminOperation::CreateExternalAccount)?;
        let adapter = match self.lookup(provider) {
            Lookup::On(adapter) => adapter,
            Lookup::Off => return Err(AppError::feature_not_enabled()),
            Lookup::Unknown => return Err(AppError::not_found()),
        };
        let deps = self.core.deps();
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let owner = principal_named(tx.as_mut(), principal).await?;
        if owner.kind != PrincipalKind::User {
            return Err(field_problem(
                "/principal",
                "not-a-user",
                "Only users connect accounts; groups, resources and service principals have no calendar to mirror one into.",
            ));
        }
        if owner.status != PrincipalStatus::Active {
            return Err(field_problem(
                "/principal",
                "suspended",
                "The principal is suspended and cannot connect an account.",
            ));
        }
        let flow = flow::Flow::new(&self.core, ctx.tenant);
        let redirect = deps.urls.oauth_callback_url(adapter.name());
        let url = adapter.oauth().authorize_url(&flow.state, &flow.challenge, &redirect)?;
        let row = deps.ids.new_id();
        let now = deps.clock.now();
        let sealed = deps.sealer.seal(
            flow.verifier.expose_secret().as_bytes(),
            &SealAad::oauth_verifier(ctx.tenant, row),
        )?;
        tx.oauth_states()
            .create(OAuthState {
                id: row,
                tenant_id: ctx.tenant,
                principal_id: owner.id,
                provider: adapter.name().to_owned(),
                state_hash: flow::hash(&self.core, &flow.state),
                pkce_verifier_sealed: sealed.into_bytes(),
                expires_at: now + STATE_TTL,
                used_at: None,
                created_at: now,
            })
            .await?;
        tx.commit().await?;
        Ok(AuthorizationUrl { authorization_url: url })
    }

    async fn complete(&self, ctx: &RequestContext, provider: &str, params: CallbackParams) -> AppResult<RenderedPage> {
        let deps = self.core.deps();
        let state_text = params.state.as_deref().ok_or_else(AppError::not_found)?;
        let tenant = flow::tenant_of(state_text).ok_or_else(AppError::not_found)?;
        // The state is consumed first, in a transaction of its own: whatever happens next, it cannot be used again.
        let (state, tenant_row) = {
            let mut tx = deps.database.begin(tenant, TxMode::ReadWrite).await?;
            let state = tx.oauth_states().consume(&flow::hash(&self.core, state_text)).await?;
            let tenant_row = tx.tenant().get().await?;
            tx.commit().await?;
            (state, tenant_row)
        };
        if state.provider != provider || tenant_row.status != TenantStatus::Active {
            return Err(AppError::not_found());
        }
        let failed = || self.result_page(ctx, &tenant_row, provider, false);
        let Lookup::On(adapter) = self.lookup(provider) else {
            return failed().await;
        };
        let Some(code) = params.code.filter(|_| params.error.is_none()) else {
            tracing::info!(provider, "the person did not consent, or the provider sent no code");
            return failed().await;
        };
        let Some(verifier) = self.open_verifier(tenant, &state) else {
            tracing::error!(provider, "the PKCE verifier of an authorization cannot be opened");
            return failed().await;
        };
        let redirect = deps.urls.oauth_callback_url(provider);
        let grant = match adapter.oauth().exchange(&code, &verifier, &redirect).await {
            Ok(grant) => grant,
            Err(error) => {
                tracing::warn!(
                    provider,
                    kind = error.kind.as_str(),
                    "the provider refused the authorization code"
                );
                return failed().await;
            }
        };
        let remote = match adapter.calendars().list_calendars(&grant.tokens.access_token).await {
            Ok(calendars) => choose(&calendars).cloned(),
            Err(error) => {
                tracing::warn!(
                    provider,
                    kind = error.kind.as_str(),
                    "the calendars of a new account cannot be listed"
                );
                None
            }
        };
        let Some(remote) = remote else {
            // Nothing was stored, and the access just granted is of no use: give it back (unless an account holds the grant).
            self.give_back(tenant, adapter, &grant).await;
            return failed().await;
        };
        let connection = Connection {
            provider: adapter,
            grant: &grant,
            remote: &remote,
        };
        match self.connect(tenant, state.principal_id, &connection).await {
            Ok(()) => self.result_page(ctx, &tenant_row, provider, true).await,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                // The principal was deleted or suspended while the person was at the consent screen: no account was written, and
                // the access just granted is of no use.
                self.give_back(tenant, adapter, &grant).await;
                failed().await
            }
            Err(error) => {
                // The store failed, or the account changed again and again. The new tokens are **not** revoked: an account of this
                // grant may be connected already, and at Google revoking a token ends the whole grant of the person to this client,
                // which would end the access of that account. A later connection replaces the tokens that are left.
                tracing::warn!(
                    provider, kind = ?error.kind(),
                    "a new authorization could not be stored; its tokens are left unused at the provider"
                );
                Err(error)
            }
        }
    }

    async fn list(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<ExternalAccountView>> {
        admin(ctx, AdminOperation::ListExternalAccounts)?;
        let request = paging::page_request(&self.core, ctx, LISTING, &page)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let rows = tx
            .external_accounts()
            .list(&ExternalAccountFilter::default(), request)
            .await?;
        let owners: Vec<PrincipalId> = rows.items.iter().map(|account| account.principal_id).collect();
        let names: std::collections::HashMap<PrincipalId, PrincipalName> = tx
            .principals()
            .get_many(&owners)
            .await?
            .into_iter()
            .map(|principal| (principal.id, principal.name))
            .collect();
        tx.commit().await?;
        let next = paging::next_cursor(&self.core, ctx, LISTING, rows.next)?;
        let items = rows
            .items
            .iter()
            .filter_map(|account| names.get(&account.principal_id).map(|name| view(account, name.clone())))
            .collect();
        Ok(Page::new(items, next))
    }

    async fn delete(&self, ctx: &RequestContext, id: ExternalAccountId) -> AppResult<()> {
        admin(ctx, AdminOperation::DeleteExternalAccount)?;
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let account = tx.external_accounts().get(id).await?;
        if let Some(calendar) = account.mirror_calendar_id {
            // The mirror goes with the account. A calendar that is gone already is what this wants.
            let mirror = match lock_one(tx.as_mut(), calendar).await {
                Ok(locked) => Some(locked),
                Err(error) if error.kind() == ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            if let Some(locked) = mirror.filter(|locked| locked.deleted_at.is_none()) {
                tx.calendars().soft_delete(locked.id, locked.version).await?;
                journal
                    .publish(tx.as_mut(), EventType::CalendarDeleted, payload_of(&locked))
                    .await?;
            }
        }
        tx.external_accounts().delete(id).await?;
        journal
            .audit(tx.as_mut(), AuditEvent::ExternalAccountDeleted(audit_of(&account)))
            .await?;
        tx.commit().await?;
        // After the commit: whether the provider revokes or not, the account is gone.
        match (
            self.core.provider(&account.provider),
            tokens::open(&self.core, ctx.tenant, id, &account.sealed_tokens),
        ) {
            (Some(adapter), Ok(tokens)) => {
                // The same account of the provider may be connected for another principal of the tenant: the grant is theirs too,
                // and revoking one token of it can end it for all.
                if self
                    .grant_is_held(ctx.tenant, &account.provider, &account.account_ref)
                    .await
                {
                    tracing::info!(
                        provider = %account.provider,
                        "the tokens of a disconnected account are kept: another account holds the grant"
                    );
                } else {
                    self.revoke(adapter.as_ref(), &tokens).await;
                }
            }
            (Some(_), Err(error)) => {
                tracing::warn!(
                    %error,
                    "the tokens of a disconnected account cannot be opened, so they are not revoked"
                );
            }
            (None, _) => {
                tracing::warn!(
                    provider = %account.provider,
                    "the provider of a disconnected account is not in this build, so its tokens are not revoked"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
