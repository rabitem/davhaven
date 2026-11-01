//! Loading of authorization facts (one query per request) and enforcement via `domain::authz`.
//!
//! The use cases of this crate never decide permissions themselves: they load the [`AccessFacts`] of the calendar
//! they are about with **one** store call (`CalendarRepo::access_facts`) and hand them to
//! [`davhaven_domain::decide`], or for operations that are not bound to a calendar to
//! [`davhaven_domain::decide_admin`]. This module holds the glue every service shares:
//!
//! * `admin` and `require_scope` turn the scope rules of the plan into answers (a missing scope is `Forbidden`
//!   before anything about the resource is looked up, so a token cannot probe which calendars exist);
//! * `enforce` maps a `Decision` to the status policy of PLAN 2.6: `Hidden` is `NotFound`, `Forbidden` carries the
//!   missing privilege as `DAV:need-privileges`;
//! * the *home* helpers resolve `/dav/calendars/{tenant}/{principal}/…` paths: the tenant slug must be the one of
//!   the request's tenant and the home must be the caller's own (or the caller a tenant administrator), otherwise the
//!   answer is `NotFound`;
//! * `retrying` and `blocking` are the two execution helpers: a transaction that lost a race is repeated up to
//!   three times (PLAN 2.7), and CPU-heavy iCalendar work runs on a blocking thread under the wall-clock budget.

mod input;
mod tx;

use std::sync::Arc;

use davhaven_domain::{
    AccessFacts, Actor, AdminDecision, AdminOperation, Calendar, CalendarId, Channel, Classification, Decision, Href,
    Operation, Principal, PrincipalId, PrincipalName, PrincipalStatus, RequestContext, ScopeRule, Tenant, TenantSlug,
    decide, decide_admin,
};
use davhaven_ports::{StoreError, Tx};

pub(crate) use input::{check_color, clean_name, clean_optional_text, field_error, invalid};
pub(crate) use tx::{Deadline, blocking, retrying};

use crate::error::{AppError, AppResult};
use crate::services::CalendarRef;

/// Checks the administration permission of the caller for an operation that is not bound to a calendar.
///
/// # Errors
///
/// `Forbidden` unless the caller is a token that carries one of the scopes the operation accepts.
pub(crate) fn admin(ctx: &RequestContext, operation: AdminOperation) -> AppResult<()> {
    match decide_admin(&ctx.subject(), ctx.channel, operation) {
        AdminDecision::Allow => Ok(()),
        AdminDecision::Forbidden => Err(AppError::forbidden()),
    }
}

/// Checks the token scope an operation needs on the caller's channel, before any resource is looked up.
///
/// # Errors
///
/// `NotFound` when the operation does not exist on the channel, `Forbidden` when the token lacks the scope.
pub(crate) fn require_scope(ctx: &RequestContext, operation: Operation) -> AppResult<()> {
    match operation.scope_rule(ctx.channel) {
        ScopeRule::Unavailable => Err(AppError::not_found()),
        ScopeRule::Required(scope) if !ctx.scopes.contains(scope) => Err(AppError::forbidden()),
        ScopeRule::Required(_) | ScopeRule::Unscoped => Ok(()),
    }
}

/// Whether a reader sees an event only as the time it blocks: its class is `PRIVATE` or `CONFIDENTIAL` and the reader
/// is not the owner of the calendar it is in (PLAN 2.13).
///
/// This is the one rule of the readers that must not see what other people wrote: subscription feeds apply it in every
/// mode, and MCP applies it to every event it shows an assistant (`objects::sight`). DAV and the management API show the
/// person's own clients everything the person may read, as the rule of the plan says.
pub(crate) const fn busy_only(class: Classification, owner_view: bool) -> bool {
    class.is_restricted() && !owner_view
}

/// Decides `operation` for the caller on the calendar described by `facts` and maps the decision to an error.
///
/// `href` is built only when the answer is `Forbidden`: it names the resource in `DAV:need-privileges`.
///
/// # Errors
///
/// `NotFound` for `Decision::Hidden`, `Forbidden` with the missing privilege for `Decision::Forbidden`.
pub(crate) fn enforce(
    ctx: &RequestContext,
    facts: &AccessFacts,
    operation: Operation,
    href: impl FnOnce() -> Href,
) -> AppResult<()> {
    match decide(&ctx.subject(), ctx.channel, facts, operation) {
        Decision::Allow => Ok(()),
        Decision::Hidden => Err(AppError::not_found()),
        Decision::Forbidden(privilege) => Err(AppError::need_privilege(href(), privilege)),
    }
}

/// Like [`enforce`] for the management API and MCP, which have no DAV resource to name: a missing privilege is a
/// plain `Forbidden` (an href of the DAV root in `DAV:need-privileges` would name the wrong resource).
///
/// # Errors
///
/// `NotFound` for `Decision::Hidden`, `Forbidden` for `Decision::Forbidden`.
pub(crate) fn enforce_api(ctx: &RequestContext, facts: &AccessFacts, operation: Operation) -> AppResult<()> {
    match decide(&ctx.subject(), ctx.channel, facts, operation) {
        Decision::Allow => Ok(()),
        Decision::Hidden => Err(AppError::not_found()),
        Decision::Forbidden(_) => Err(AppError::forbidden()),
    }
}

/// Locks one calendar for the rest of the transaction and returns it with its current sync state.
///
/// # Errors
///
/// `NotFound` when the calendar does not exist.
pub(crate) async fn lock_one(tx: &mut dyn Tx, id: CalendarId) -> AppResult<Calendar> {
    tx.calendars()
        .lock(&[id])
        .await?
        .into_iter()
        .next()
        .ok_or_else(AppError::not_found)
}

/// Whether `ctx` may address the home of `principal`: the principal itself, a tenant administrator, or server work.
pub(crate) fn may_use_home(ctx: &RequestContext, principal: &Principal) -> bool {
    if ctx.channel == Channel::Internal {
        return true;
    }
    match &ctx.actor {
        Actor::Principal(id) | Actor::PrincipalToken { principal: id, .. } => *id == principal.id,
        Actor::TenantToken(_) => true,
        Actor::SystemToken(_) | Actor::FeedReader { .. } | Actor::RsvpAttendee { .. } | Actor::Anonymous => false,
    }
}

/// The tenant of the transaction, if its slug is the one the path names.
///
/// # Errors
///
/// `NotFound` for another slug (other tenants' resources are invisible) and for a tenant that does not exist.
pub(crate) async fn tenant_for_path(tx: &mut dyn Tx, slug: &TenantSlug) -> AppResult<Tenant> {
    let tenant = tx.tenant().get().await?;
    if &tenant.slug == slug {
        Ok(tenant)
    } else {
        Err(AppError::not_found())
    }
}

/// The principal with the immutable `name`; deleted principals are invisible.
///
/// # Errors
///
/// `NotFound`.
pub(crate) async fn principal_named(tx: &mut dyn Tx, name: &PrincipalName) -> AppResult<Principal> {
    let principal = tx.principals().get_by_name(name).await?;
    if principal.status == PrincipalStatus::Deleted {
        Err(AppError::not_found())
    } else {
        Ok(principal)
    }
}

/// The principal with `id`; deleted principals are invisible.
///
/// # Errors
///
/// `NotFound`.
pub(crate) async fn principal_by_id(tx: &mut dyn Tx, id: PrincipalId) -> AppResult<Principal> {
    let principal = tx.principals().get(id).await?;
    if principal.status == PrincipalStatus::Deleted {
        Err(AppError::not_found())
    } else {
        Ok(principal)
    }
}

/// A calendar home: the tenant of the request and the principal whose home a DAV path addresses.
#[derive(Debug, Clone)]
pub(crate) struct Home {
    pub(crate) tenant: Tenant,
    pub(crate) principal: Principal,
}

/// Resolves the tenant and the principal of a DAV path and checks that the caller may use that home.
///
/// # Errors
///
/// `NotFound` for another tenant, an unknown or deleted principal and a home the caller may not use.
pub(crate) async fn resolve_home(
    tx: &mut dyn Tx,
    ctx: &RequestContext,
    tenant: &TenantSlug,
    principal: &PrincipalName,
) -> AppResult<Home> {
    let tenant = tenant_for_path(tx, tenant).await?;
    let principal = principal_named(tx, principal).await?;
    if may_use_home(ctx, &principal) {
        Ok(Home { tenant, principal })
    } else {
        Err(AppError::not_found())
    }
}

/// Like [`resolve_home`] for callers that already know the tenant is the request's own (the service methods that
/// take only the principal's name).
///
/// # Errors
///
/// `NotFound` for an unknown or deleted principal and a home the caller may not use.
pub(crate) async fn home_of(tx: &mut dyn Tx, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Home> {
    let tenant = tx.tenant().get().await?;
    let principal = principal_named(tx, principal).await?;
    if may_use_home(ctx, &principal) {
        Ok(Home { tenant, principal })
    } else {
        Err(AppError::not_found())
    }
}

/// The facts for operations on a principal's own home, scheduling collections and notifications: the principal is
/// the owner, nobody else has a grant.
pub(crate) fn home_facts(tenant: &Tenant, principal: &Principal) -> AccessFacts {
    AccessFacts {
        calendar_kind: davhaven_domain::CalendarKind::Personal,
        owner: principal.id,
        owner_kind: principal.kind,
        memberships: Vec::new(),
        grants: Vec::new(),
        binding: None,
        tenant_settings: Arc::new(tenant.settings.clone()),
    }
}

/// The live calendar a management API reference names, inside the transaction's tenant.
///
/// # Errors
///
/// `NotFound` for unknown calendars, unknown or deleted owners and calendars of other tenants.
pub(crate) async fn calendar_of(tx: &mut dyn Tx, reference: &CalendarRef) -> AppResult<Calendar> {
    match reference {
        CalendarRef::Id(id) => Ok(tx.calendars().get(*id).await?),
        CalendarRef::Key { owner, slug } => {
            let owner = principal_named(tx, owner).await?;
            Ok(tx.calendars().get_by_slug(owner.id, slug).await?)
        }
    }
}

/// The authorization facts of `calendar` for the caller, in one store call.
///
/// # Errors
///
/// `NotFound` when the calendar does not exist in the tenant.
pub(crate) async fn facts_for(tx: &mut dyn Tx, ctx: &RequestContext, calendar: CalendarId) -> AppResult<AccessFacts> {
    Ok(tx.calendars().access_facts(calendar, ctx.principal()).await?)
}

/// Turns a missing row into `None`.
///
/// # Errors
///
/// Every store error except `NotFound`.
pub(crate) fn found<T>(result: Result<T, StoreError>) -> AppResult<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(StoreError::NotFound) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use davhaven_domain::{ErrorKind, RequestId, Scope, ScopeSet, TenantId, TokenId};
    use uuid::Uuid;

    use super::*;

    fn token_ctx(channel: Channel, scopes: &[Scope]) -> RequestContext {
        RequestContext {
            tenant: TenantId::from_uuid(Uuid::from_u128(1)),
            actor: Actor::TenantToken(TokenId::from_uuid(Uuid::from_u128(2))),
            scopes: ScopeSet::of(scopes),
            channel,
            credential: None,
            request_id: RequestId::from_uuid(Uuid::from_u128(3)),
            locale: None,
            client_ip: None,
        }
    }

    #[test]
    fn a_missing_scope_is_forbidden_and_an_absent_operation_is_hidden() {
        let ctx = token_ctx(Channel::Api, &[Scope::EventsRead]);
        assert!(require_scope(&ctx, Operation::ReadObject).is_ok());
        assert_eq!(
            require_scope(&ctx, Operation::CreateObject).unwrap_err().kind(),
            ErrorKind::Forbidden
        );
        assert_eq!(
            require_scope(&ctx, Operation::ReadInbox).unwrap_err().kind(),
            ErrorKind::NotFound,
            "the inbox does not exist on the management API"
        );
        let dav = token_ctx(Channel::Dav, &[]);
        assert!(require_scope(&dav, Operation::ReadObject).is_ok(), "DAV is not scoped");
    }

    #[test]
    fn administration_follows_the_scope_table() {
        let ctx = token_ctx(Channel::Api, &[Scope::PrincipalsRead]);
        assert!(admin(&ctx, AdminOperation::ListPrincipals).is_ok());
        assert_eq!(
            admin(&ctx, AdminOperation::PutPrincipal).unwrap_err().kind(),
            ErrorKind::Forbidden
        );
        let internal = RequestContext::internal(ctx.tenant, ctx.request_id);
        assert!(
            admin(&internal, AdminOperation::DeleteTenant).is_ok(),
            "server work is trusted"
        );
    }
}
