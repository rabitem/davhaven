//! The API tokens that operator commands look for: the administration token of a tenant (`admin bootstrap`) and the
//! tokens of principals (`admin principal-token`).
//!
//! Both commands are idempotent by label, like `admin system-token` ([`super::system_tokens`]): a valid token with the
//! label is reported and not created twice by a repeated run. This module owns the rules of that lookup, so that the
//! binary only parses, prints and writes the secret:
//!
//! * the candidates are the tokens of the **same kind and the same principal** (a principal token that a user happened to
//!   give the label of an administration token is none), asked of the store with its filter and not read in full and
//!   filtered in memory;
//! * a token is valid until it is revoked or expires (the expiry is exclusive);
//! * the label is read as the credential service reads it (trimmed), so that the label a run created is found by the next
//!   run however it was typed;
//! * what an existing token lacks of what was asked for is worked out here ([`ExistingToken`]).
//!
//! Creating and revoking stay with the credential service (`CredentialService::create_api_token`,
//! `revoke_api_token`): the operator mints through the same validation as the management API and leaves the same audit
//! records. Two runs that race each other can still both create a token; the label is a convenience for a person, not a
//! unique key, and [`list`] shows both.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use davhaven_domain::{ApiToken, PrincipalId, PrincipalName, Scope, TenantId, TokenId, TokenKind};
use davhaven_ports::store::{ApiTokenFilter, MAX_PAGE_LIMIT};
use davhaven_ports::{PageReq, StoreError, StorePage, Tx, TxMode};
use davhaven_wire::{ApiTokenCreate, ApiTokenView};

use super::MaintenanceError;
use super::system_tokens::clean_label;
use crate::credentials::api_token_view;
use crate::wiring::AppDeps;

/// A token that exists already, compared with what a run asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingToken {
    /// The token, as the credential service lists it.
    pub token: ApiTokenView,
    /// The scopes that were asked for and that the token does not hold.
    pub missing_scopes: Vec<Scope>,
    /// Whether the token expires although none was asked for, or does not expire although an expiry was asked for. Two
    /// runs ask for expiry dates that differ by the time between them, so only the presence is compared.
    pub expiry_differs: bool,
}

impl ExistingToken {
    /// Compares `token` with the request that found it.
    fn of(token: ApiTokenView, wanted: &ApiTokenCreate) -> Self {
        let missing_scopes = wanted
            .scopes
            .iter()
            .filter(|scope| !token.scopes.contains(*scope))
            .collect();
        let expiry_differs = wanted.expires_at.is_some() != token.expires_at.is_some();
        Self {
            token,
            missing_scopes,
            expiry_differs,
        }
    }
}

/// Whether `token` can authenticate at `now`: neither revoked nor expired.
fn is_valid_at(token: &ApiToken, now: DateTime<Utc>) -> bool {
    token.revoked_at.is_none() && token.expires_at.is_none_or(|expires| expires > now)
}

/// The filter for the tokens of `kind` and, when one is named, of `principal`; `None` when the principal does not exist
/// in the tenant, so that no token can be theirs.
async fn filter_for(
    tx: &mut dyn Tx,
    kind: TokenKind,
    principal: Option<&PrincipalName>,
    include_revoked: bool,
) -> Result<Option<ApiTokenFilter>, MaintenanceError> {
    let principal = match principal {
        Some(name) => match tx.principals().get_by_name(name).await {
            Ok(found) => Some(found.id),
            Err(StoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.into()),
        },
        None => None,
    };
    Ok(Some(ApiTokenFilter {
        principal,
        kind: Some(kind),
        include_revoked,
    }))
}

/// Every token that matches `filter`, in id order.
async fn matching(tx: &mut dyn Tx, filter: &ApiTokenFilter) -> Result<Vec<ApiToken>, MaintenanceError> {
    let mut found = Vec::new();
    let mut page = PageReq::first(MAX_PAGE_LIMIT);
    loop {
        let StorePage { items, next } = tx.credentials().list_api_tokens(filter, page).await?;
        found.extend(items);
        match next {
            Some(cursor) => page = page.after(cursor),
            None => return Ok(found),
        }
    }
}

/// The tokens as the credential service shows them: with the name of the principal they act as.
async fn views(tx: &mut dyn Tx, tokens: &[ApiToken]) -> Result<Vec<ApiTokenView>, MaintenanceError> {
    let mut seen = HashSet::new();
    let ids: Vec<PrincipalId> = tokens
        .iter()
        .filter_map(|token| token.principal_id)
        .filter(|id| seen.insert(*id))
        .collect();
    let names: HashMap<PrincipalId, PrincipalName> = tx
        .principals()
        .get_many(&ids)
        .await?
        .into_iter()
        .map(|principal| (principal.id, principal.name))
        .collect();
    Ok(tokens
        .iter()
        .map(|token| api_token_view(token, token.principal_id.and_then(|id| names.get(&id).cloned())))
        .collect())
}

/// The valid token that a run asking for `wanted` would create again: of the same kind and principal, with the same label.
/// `None` when there is none, and also when the label cannot belong to a token (the credential service refuses it and
/// says why when the run goes on to create the token).
///
/// # Errors
///
/// [`MaintenanceError::Store`] when the store fails.
pub async fn find_existing(
    deps: &AppDeps,
    tenant: TenantId,
    wanted: &ApiTokenCreate,
) -> Result<Option<ExistingToken>, MaintenanceError> {
    let Ok(label) = clean_label(&wanted.label) else {
        return Ok(None);
    };
    let now = deps.clock.now();
    let mut tx = deps.database.begin(tenant, TxMode::ReadOnly).await?;
    let Some(filter) = filter_for(tx.as_mut(), wanted.kind, wanted.principal.as_ref(), false).await? else {
        tx.commit().await?;
        return Ok(None);
    };
    let found = matching(tx.as_mut(), &filter)
        .await?
        .into_iter()
        .find(|token| token.label == label && is_valid_at(token, now));
    let Some(token) = found else {
        tx.commit().await?;
        return Ok(None);
    };
    let mut shown = views(tx.as_mut(), &[token]).await?;
    tx.commit().await?;
    Ok(shown.pop().map(|token| ExistingToken::of(token, wanted)))
}

/// The tokens of `kind` of a tenant, revoked ones included, in id order; with `principal`, only that principal's (none for
/// a principal that does not exist).
///
/// # Errors
///
/// [`MaintenanceError::Store`] when the store fails.
pub async fn list(
    deps: &AppDeps,
    tenant: TenantId,
    kind: TokenKind,
    principal: Option<&PrincipalName>,
) -> Result<Vec<ApiTokenView>, MaintenanceError> {
    let mut tx = deps.database.begin(tenant, TxMode::ReadOnly).await?;
    let Some(filter) = filter_for(tx.as_mut(), kind, principal, true).await? else {
        tx.commit().await?;
        return Ok(Vec::new());
    };
    let tokens = matching(tx.as_mut(), &filter).await?;
    let shown = views(tx.as_mut(), &tokens).await?;
    tx.commit().await?;
    Ok(shown)
}

/// Whether the tenant has an API token of `kind` with `id` (a revoked one counts): the commands that revoke one kind of
/// token refuse the id of another.
///
/// # Errors
///
/// [`MaintenanceError::Store`] when the store fails.
pub async fn has_token(
    deps: &AppDeps,
    tenant: TenantId,
    kind: TokenKind,
    id: TokenId,
) -> Result<bool, MaintenanceError> {
    let mut tx = deps.database.begin(tenant, TxMode::ReadOnly).await?;
    let token = match tx.credentials().get_api_token(id).await {
        Ok(token) => Some(token),
        Err(StoreError::NotFound) => None,
        Err(error) => return Err(error.into()),
    };
    tx.commit().await?;
    Ok(token.is_some_and(|token| token.kind == kind))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use davhaven_domain::ScopeSet;

    use super::*;

    fn view(scopes: &[Scope], expires_at: Option<DateTime<Utc>>) -> ApiTokenView {
        ApiTokenView {
            id: TokenId::from_uuid(uuid::Uuid::from_u128(1)),
            kind: TokenKind::Principal,
            principal_id: None,
            principal: None,
            label: "assistant".to_owned(),
            scopes: ScopeSet::of(scopes),
            prefix: "abcdefghijkl".to_owned(),
            expires_at,
            allowed_origins: Vec::new(),
            created_by: None,
            last_used_at: None,
            revoked_at: None,
            created_at: DateTime::UNIX_EPOCH,
        }
    }

    fn wanted(scopes: &[Scope], expires_at: Option<DateTime<Utc>>) -> ApiTokenCreate {
        ApiTokenCreate {
            kind: TokenKind::Principal,
            principal: Some(PrincipalName::parse("robot").unwrap()),
            label: "assistant".to_owned(),
            scopes: ScopeSet::of(scopes),
            expires_at,
            allowed_origins: Vec::new(),
        }
    }

    #[test]
    fn an_existing_token_is_compared_with_what_was_asked_for() {
        let at = Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap();
        let same = ExistingToken::of(
            view(&[Scope::McpRead, Scope::McpWrite], Some(at)),
            &wanted(&[Scope::McpRead], Some(at + chrono::TimeDelta::days(1))),
        );
        assert!(
            same.missing_scopes.is_empty(),
            "a token may hold more than was asked for"
        );
        assert!(
            !same.expiry_differs,
            "both expire: the dates differ by the time between two runs"
        );

        let narrower = ExistingToken::of(
            view(&[Scope::McpRead], None),
            &wanted(&[Scope::McpRead, Scope::McpWrite], Some(at)),
        );
        assert_eq!(narrower.missing_scopes, vec![Scope::McpWrite]);
        assert!(narrower.expiry_differs, "it does not expire, an expiry was asked for");

        let forever = ExistingToken::of(view(&[Scope::McpRead], Some(at)), &wanted(&[Scope::McpRead], None));
        assert!(forever.expiry_differs, "it expires, none was asked for");
    }

    #[test]
    fn a_token_is_valid_until_it_is_revoked_or_expires() {
        let now = Utc.with_ymd_and_hms(2027, 3, 1, 12, 0, 0).unwrap();
        let mut token = ApiToken {
            id: TokenId::from_uuid(uuid::Uuid::from_u128(1)),
            tenant_id: Some(TenantId::from_uuid(uuid::Uuid::from_u128(2))),
            kind: TokenKind::Tenant,
            principal_id: None,
            label: "deploy".to_owned(),
            scopes: ScopeSet::of(&[Scope::EventsRead]),
            prefix: "abcdefghijkl".to_owned(),
            hash: Vec::new(),
            pepper_kid: "k".to_owned(),
            expires_at: None,
            created_by: None,
            allowed_origins: Vec::new(),
            last_used_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        assert!(is_valid_at(&token, now));
        token.expires_at = Some(now + chrono::TimeDelta::hours(1));
        assert!(is_valid_at(&token, now));
        assert!(
            !is_valid_at(&token, now + chrono::TimeDelta::hours(1)),
            "the expiry is exclusive"
        );
        token.expires_at = None;
        token.revoked_at = Some(now);
        assert!(!is_valid_at(&token, now));
    }
}
