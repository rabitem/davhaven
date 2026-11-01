//! Fake authentication service.
//!
//! Credentials are registered in the [`FakeWorld`] (`add_app_password`, `add_api_token`, `add_feed_token`,
//! `add_rsvp_token`) and compared in plain text. The rules mirror the real service where tests depend on them:
//! credentials are bound to their surface (app passwords on `dav`, API tokens on `api` and `mcp`, feed and RSVP
//! tokens on their pages), suspended principals cannot log in, a valid credential presented for the path of another
//! tenant is authenticated and then fails with `NotFound` (the resources of another tenant are invisible to it, R4),
//! and every other failure is the same `Unauthenticated` answer.

use async_trait::async_trait;
use davhaven_app::error::{AppError, AppResult};
use davhaven_app::services::{AuthRequest, AuthService, BudgetClass, ExposeSecret, PresentedCredential};
use davhaven_domain::{
    Actor, Channel, CredentialRef, PrincipalName, PrincipalStatus, RequestContext, ScopeSet, TenantId, TokenKind,
};
use uuid::Uuid;

use crate::state::{FakeState, FakeWorld};

/// The fake [`AuthService`].
#[derive(Debug, Clone)]
pub struct FakeAuth {
    state: FakeState,
}

impl FakeAuth {
    /// Creates the service on a shared world.
    pub const fn new(state: FakeState) -> Self {
        Self { state }
    }
}

/// The context of an authenticated request.
fn context(
    request: &AuthRequest,
    tenant: TenantId,
    actor: Actor,
    scopes: ScopeSet,
    credential: CredentialRef,
) -> RequestContext {
    RequestContext {
        tenant,
        actor,
        scopes,
        channel: request.channel,
        credential: Some(credential),
        request_id: request.request_id,
        locale: None,
        client_ip: request.client_ip,
    }
}

impl FakeWorld {
    /// Resolves the tenant and the principal of a Basic login (`name@login_domain`, or a bare name with a
    /// tenant hint).
    fn login_principal(
        &self,
        request: &AuthRequest,
        username: &str,
    ) -> Option<(TenantId, davhaven_domain::PrincipalId)> {
        let login = username.trim();
        let (name, tenant) = if let Some((name, domain)) = login.rsplit_once('@') {
            let tenant = self.tenants.values().find(|tenant| {
                tenant
                    .login_domain
                    .as_ref()
                    .is_some_and(|candidate| candidate.as_str().eq_ignore_ascii_case(domain))
            })?;
            (name, tenant)
        } else {
            let slug = request.tenant_hint.as_ref()?;
            (login, self.tenant_by_slug(slug)?)
        };
        let name = PrincipalName::from_login(name).ok()?;
        let principal = self.principal_by_name(tenant.id, &name)?;
        (principal.status == PrincipalStatus::Active).then_some((tenant.id, principal.id))
    }

    /// The tenant a system token's context is bound to: the hinted tenant when it exists, the nil tenant
    /// otherwise.
    fn system_tenant(&self, request: &AuthRequest) -> TenantId {
        request
            .tenant_hint
            .as_ref()
            .and_then(|slug| self.tenant_by_slug(slug))
            .map_or_else(|| TenantId::from_uuid(Uuid::nil()), |tenant| tenant.id)
    }

    fn authenticate_basic(&self, request: &AuthRequest, username: &str, password: &str) -> Option<RequestContext> {
        if request.channel != Channel::Dav {
            return None;
        }
        let (tenant, principal) = self.login_principal(request, username)?;
        let credential = self.app_passwords.iter().find(|candidate| {
            candidate.principal == principal && !candidate.revoked && candidate.password == password
        })?;
        Some(context(
            request,
            tenant,
            Actor::Principal(principal),
            ScopeSet::empty(),
            CredentialRef::app_password(credential.id),
        ))
    }

    fn authenticate_bearer(&self, request: &AuthRequest, secret: &str) -> Option<RequestContext> {
        if !matches!(request.channel, Channel::Api | Channel::Mcp) {
            return None;
        }
        let token = self
            .api_tokens
            .iter()
            .find(|candidate| !candidate.revoked && candidate.secret == secret)?;
        let credential = CredentialRef::api_token(token.id);
        if token.kind == TokenKind::System {
            return Some(context(
                request,
                self.system_tenant(request),
                Actor::SystemToken(token.id),
                token.scopes,
                credential,
            ));
        }
        let tenant = token.tenant?;
        let actor = match (token.kind, token.principal) {
            (TokenKind::Principal, Some(principal)) => {
                let live = self.principal_by_id(tenant, principal)?;
                if live.status != PrincipalStatus::Active {
                    return None;
                }
                Actor::PrincipalToken {
                    principal,
                    token: token.id,
                }
            }
            (TokenKind::Tenant, _) => Actor::TenantToken(token.id),
            _ => return None,
        };
        Some(context(request, tenant, actor, token.scopes, credential))
    }

    fn authenticate_feed(&self, request: &AuthRequest, secret: &str) -> Option<RequestContext> {
        if request.channel != Channel::Feed {
            return None;
        }
        let token = self.feed_tokens.iter().find(|candidate| candidate.secret == secret)?;
        Some(context(
            request,
            token.tenant,
            Actor::FeedReader {
                principal: token.principal,
                token: token.id,
            },
            ScopeSet::empty(),
            CredentialRef::feed_token(token.id),
        ))
    }

    fn authenticate_rsvp(&self, request: &AuthRequest, secret: &str) -> Option<RequestContext> {
        if request.channel != Channel::Rsvp {
            return None;
        }
        let token = self.rsvp_tokens.iter().find(|candidate| candidate.secret == secret)?;
        Some(context(
            request,
            token.tenant,
            Actor::RsvpAttendee {
                object: token.object,
                address: token.address.clone(),
            },
            ScopeSet::empty(),
            CredentialRef::rsvp_token(token.id),
        ))
    }

    /// A valid credential of one tenant on the path of another: the resources there are invisible to it (R4), so the
    /// request is not authenticated for them. System tokens belong to no tenant and name any.
    fn refuse_other_tenants(&self, request: &AuthRequest, context: &RequestContext) -> AppResult<()> {
        let Some(hint) = request.tenant_hint.as_ref() else {
            return Ok(());
        };
        if matches!(context.actor, Actor::SystemToken(_)) {
            return Ok(());
        }
        let own = self.tenants.values().find(|tenant| tenant.id == context.tenant);
        if own.is_some_and(|tenant| &tenant.slug == hint) {
            Ok(())
        } else {
            Err(AppError::not_found())
        }
    }

    fn authenticate(&self, request: &AuthRequest) -> Option<RequestContext> {
        match &request.credential {
            PresentedCredential::Basic { username, password } => {
                self.authenticate_basic(request, username, password.expose_secret())
            }
            PresentedCredential::Bearer(secret) => self.authenticate_bearer(request, secret.expose_secret()),
            PresentedCredential::Feed(secret) => self.authenticate_feed(request, secret.expose_secret()),
            PresentedCredential::Rsvp(secret) => self.authenticate_rsvp(request, secret.expose_secret()),
        }
    }
}

#[async_trait]
impl AuthService for FakeAuth {
    /// The fake has no limiter: every call is within its budget.
    async fn charge_budget(&self, _ctx: &RequestContext, _class: BudgetClass) -> AppResult<()> {
        Ok(())
    }

    async fn authenticate(&self, request: AuthRequest) -> AppResult<RequestContext> {
        self.state
            .read(|world| {
                let context = world.authenticate(&request).ok_or_else(AppError::unauthenticated)?;
                world.refuse_other_tenants(&request, &context)?;
                Ok(context)
            })
            .await
    }
}
