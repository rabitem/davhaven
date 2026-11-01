//! The pull of one account: claim, pull, settle (see the module documentation of `sync_engine`).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::events::ExternalAccountPayload;
use davhaven_domain::{
    ErrorKind, EventPayload, EventType, ExternalAccount, ExternalAccountId, ExternalAccountStatus, PrincipalStatus,
    RequestContext, RequestId, TenantId,
};
use davhaven_ports::{OAuthTokens, PortErrorKind, Provider, RemoteChanges, StoreError, Tx, TxMode};

use super::apply::{Applied, Mirror};
use super::state::{Failure, SyncState, after, backoff};
use crate::audit::Journal;
use crate::error::AppResult;
use crate::oauth::tokens;
use crate::objects::ObjectServiceImpl;
use crate::wiring::AppCore;

/// How soon before an access token expires it is renewed.
const RENEW_BEFORE: TimeDelta = TimeDelta::seconds(60);

/// How much longer than the timeout of a pull a worker holds an account.
const LEASE_EXTRA: Duration = Duration::from_secs(60);

/// How many times the result of a pull is stored again when the account changed meanwhile.
const SETTLE_ATTEMPTS: u32 = 3;

/// What became of one pull.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The account was pulled; this is what the mirror got.
    Pulled(Applied),
    /// Nothing was done: the account is not due, held by another worker, switched off, gone, of a provider that is off, or of a
    /// principal who cannot use it.
    Skipped,
    /// The pull failed and the failure was stored; the reason as `external_account.sync_failed` and the metrics name it
    /// (`auth_revoked`, `provider_rejected`, `provider_unavailable`, `too_large`, `mirror_missing`, `internal`).
    Failed(&'static str),
    /// The account could not even be claimed because the store failed. It stays due, so a later pass tries it again; a pass
    /// that has nothing but these made no progress and does not start the next one at once.
    Unclaimed,
}

/// An account that this worker holds.
struct Claim {
    tenant: TenantId,
    account: ExternalAccount,
    state: SyncState,
    provider: Arc<dyn Provider>,
    /// The lease this worker wrote into the account: the **fencing token** of the pull. What the pull stores (renewed tokens, its
    /// result) is stored only while the account still holds exactly this lease. A reconnection clears it and the claim of another
    /// worker replaces it, and either says that the pull works from a state that is no longer the account's.
    lease: DateTime<Utc>,
    /// Whether the mirror calendar was there (and not deleted) when the account was claimed.
    mirror: bool,
}

/// What a successful pull brings to the settling.
struct Pulled {
    applied: Applied,
    cursor: String,
}

/// The engine that pulls provider accounts into their mirror calendars.
#[derive(Clone)]
pub struct SyncEngine {
    core: AppCore,
    objects: ObjectServiceImpl,
}

impl core::fmt::Debug for SyncEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncEngine").finish_non_exhaustive()
    }
}

/// The end of a claim that found nothing to do with the account: what it read is committed, nothing was written.
async fn unclaimed(tx: Box<dyn Tx>) -> AppResult<Option<Claim>> {
    tx.commit().await?;
    Ok(None)
}

impl SyncEngine {
    /// The engine on the shared application core. Its writes to the mirror calendars go through the object service without
    /// server-side scheduling (a mirror calendar does not schedule).
    pub fn new(core: AppCore) -> Self {
        let objects = ObjectServiceImpl::new(core.clone());
        Self { core, objects }
    }

    /// The shared application core.
    pub const fn core(&self) -> &AppCore {
        &self.core
    }

    /// Pulls `account` of `tenant` if it is due.
    pub async fn sync_account(&self, tenant: TenantId, account: ExternalAccountId) -> SyncOutcome {
        let claim = match self.claim(tenant, account).await {
            Ok(Some(claim)) => claim,
            Ok(None) => return SyncOutcome::Skipped,
            Err(error) => {
                tracing::warn!(
                    %tenant, %account, kind = ?error.kind(),
                    "an account of a provider cannot be claimed"
                );
                return SyncOutcome::Unclaimed;
            }
        };
        let timeout = self.core.deps().config.provider_sync.timeout;
        let result = match tokio::time::timeout(timeout, self.pull(&claim)).await {
            Ok(result) => result,
            Err(_elapsed) => {
                tracing::warn!(
                    %tenant, %account,
                    "a pull took longer than `providers.sync.timeout` and was abandoned"
                );
                Err(Failure::ProviderUnavailable)
            }
        };
        self.settle(&claim, result).await
    }

    // -----------------------------------------------------------------------------------------------------------
    // Claim
    // -----------------------------------------------------------------------------------------------------------

    /// Takes the account for one pull. `None` when there is nothing to do with it now.
    async fn claim(&self, tenant: TenantId, id: ExternalAccountId) -> AppResult<Option<Claim>> {
        let deps = self.core.deps();
        let now = deps.clock.now();
        let mut tx = deps.database.begin(tenant, TxMode::ReadWrite).await?;
        let account = match tx.external_accounts().get(id).await {
            Ok(account) => account,
            Err(StoreError::NotFound) => return unclaimed(tx).await,
            Err(error) => return Err(error.into()),
        };
        if account.status == ExternalAccountStatus::Disabled {
            return unclaimed(tx).await;
        }
        let Some(provider) = self
            .core
            .provider(&account.provider)
            .filter(|provider| provider.enabled())
        else {
            return unclaimed(tx).await;
        };
        let owner = tx.principals().get(account.principal_id).await?;
        match owner.status {
            PrincipalStatus::Active => {}
            // The worker does not list the accounts of a suspended principal (`due_in`); one that is suspended between the
            // listing and the claim is left as it is, and pulled when the principal is active again.
            PrincipalStatus::Suspended => return unclaimed(tx).await,
            PrincipalStatus::Deleted => {
                // Nobody owns the calendar any more: the account stops, and the provider is asked to forget the access.
                let state = SyncState::read(&account.sync_state);
                let stopped = ExternalAccount {
                    status: ExternalAccountStatus::Disabled,
                    last_error: Some("principal_deleted: the principal was deleted".to_owned()),
                    sync_state: SyncState {
                        lease_until: None,
                        next_sync_at: None,
                        ..state
                    }
                    .document(),
                    updated_at: now,
                    ..account.clone()
                };
                match tx.external_accounts().update(stopped, account.version).await {
                    Ok(_) => tx.commit().await?,
                    Err(StoreError::PreconditionFailed | StoreError::NotFound) => return unclaimed(tx).await,
                    Err(error) => return Err(error.into()),
                }
                if let Ok(opened) = tokens::open(&self.core, tenant, id, &account.sealed_tokens) {
                    let token = opened.refresh_token.as_ref().unwrap_or(&opened.access_token);
                    if let Err(error) = provider.oauth().revoke(token).await {
                        tracing::warn!(
                            provider = provider.name(),
                            kind = error.kind.as_str(),
                            "the tokens of an account of a deleted principal were not revoked"
                        );
                    }
                }
                return Ok(None);
            }
        }
        let state = SyncState::read(&account.sync_state);
        if !state.is_due(now) {
            return unclaimed(tx).await;
        }
        // A pull of an account whose mirror is gone is no pull: the provider is not asked, and the tokens of the person are not
        // used.
        let mirror = match account.mirror_calendar_id {
            Some(calendar) => match tx.calendars().get(calendar).await {
                Ok(_) => true,
                Err(StoreError::NotFound) => false,
                Err(error) => return Err(error.into()),
            },
            None => false,
        };
        let lease = after(now, deps.config.provider_sync.timeout.saturating_add(LEASE_EXTRA));
        let held = SyncState {
            lease_until: Some(lease),
            ..state.clone()
        };
        let claimed = ExternalAccount {
            sync_state: held.document(),
            ..account.clone()
        };
        match tx.external_accounts().update(claimed, account.version).await {
            Ok(stored) => {
                tx.commit().await?;
                Ok(Some(Claim {
                    tenant,
                    account: stored,
                    state,
                    provider: Arc::clone(provider),
                    lease,
                    mirror,
                }))
            }
            // Another worker took the account first, or the account was changed or deleted meanwhile.
            Err(StoreError::PreconditionFailed | StoreError::NotFound) => unclaimed(tx).await,
            Err(error) => Err(error.into()),
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // Pull
    // -----------------------------------------------------------------------------------------------------------

    async fn pull(&self, claim: &Claim) -> Result<Pulled, Failure> {
        let deps = self.core.deps();
        let mirror = match claim.account.mirror_calendar_id {
            Some(mirror) if claim.mirror => mirror,
            _ => {
                tracing::warn!(
                    tenant = %claim.tenant, account = %claim.account.id,
                    "the mirror calendar of an account is gone, so the provider is not asked"
                );
                return Err(Failure::MirrorMissing);
            }
        };
        let mut tokens = tokens::open(&self.core, claim.tenant, claim.account.id, &claim.account.sealed_tokens)
            .map_err(|error| {
                tracing::error!(
                    tenant = %claim.tenant, account = %claim.account.id, kind = ?error.kind(),
                    "the sealed tokens of an account cannot be opened"
                );
                Failure::Internal
            })?;
        let mut renewed = false;
        if tokens.expires_at.is_some_and(|at| {
            at <= deps
                .clock
                .now()
                .checked_add_signed(RENEW_BEFORE)
                .unwrap_or(DateTime::<Utc>::MAX_UTC)
        }) {
            tokens = self.renew(claim, &tokens).await?;
            renewed = true;
        }
        let Some(calendar) = claim.state.calendar.clone() else {
            // Connected by a version that did not record the calendar: there is nothing to say which one to mirror.
            tracing::error!(
                tenant = %claim.tenant, account = %claim.account.id,
                "an account does not say which calendar it mirrors"
            );
            return Err(Failure::Internal);
        };
        let changes = self.fetch(claim, &mut tokens, &calendar, renewed).await?;
        let applied = Mirror::new(&self.core, &self.objects, claim.tenant, mirror)
            .apply(&changes)
            .await
            .map_err(|error| {
                if error.kind() == ErrorKind::NotFound {
                    Failure::MirrorMissing
                } else {
                    tracing::error!(
                        tenant = %claim.tenant, account = %claim.account.id, kind = ?error.kind(),
                        "the changes of a provider calendar cannot be stored"
                    );
                    Failure::Internal
                }
            })?;
        Ok(Pulled {
            applied,
            cursor: changes.cursor,
        })
    }

    /// Asks the provider what changed. A token it refuses is renewed once; a cursor it no longer accepts starts a full pull.
    async fn fetch(
        &self,
        claim: &Claim,
        tokens: &mut OAuthTokens,
        calendar: &str,
        mut renewed: bool,
    ) -> Result<RemoteChanges, Failure> {
        let api = claim.provider.calendars();
        let mut cursor = claim.state.cursor.clone();
        let mut reset = false;
        loop {
            let error = match api
                .changes_since(&tokens.access_token, calendar, cursor.as_deref())
                .await
            {
                Ok(changes) => return Ok(changes),
                Err(error) => error,
            };
            match error.kind {
                // The access token was revoked or expired early: a fresh one, once. A token that is fresh and refused is the
                // account's doing (access narrowed, calendar gone), and a renewal would not help.
                PortErrorKind::Rejected if !renewed && tokens.refresh_token.is_some() => {
                    *tokens = self.renew(claim, tokens).await?;
                    renewed = true;
                }
                // The provider forgot the cursor: what it gave is no use any more, so everything is asked for again.
                PortErrorKind::Invalid if cursor.is_some() && !reset => {
                    cursor = None;
                    reset = true;
                }
                // The calendar is beyond what the adapter imports: neither a new token nor a new cursor makes it smaller.
                PortErrorKind::Unsupported => {
                    tracing::warn!(
                        tenant = %claim.tenant, account = %claim.account.id, provider = claim.provider.name(),
                        "a provider calendar has more events in the window than the import reads"
                    );
                    return Err(Failure::TooLarge);
                }
                _ => {
                    tracing::warn!(
                        tenant = %claim.tenant, account = %claim.account.id, provider = claim.provider.name(),
                        kind = error.kind.as_str(), "a provider did not give the changes of a calendar"
                    );
                    return Err(Failure::of(&error));
                }
            }
        }
    }

    /// A new access token for the refresh token, stored at once.
    ///
    /// Only a refresh token that the provider calls invalid (`Rejected`) ends the account. A provider that refuses the client
    /// of the deployment (`Invalid`: a wrong, rotated or expired client secret) is a fault of the deployment: every account
    /// fails the same way until the operator fixes the client, and every one of them is on again by itself afterwards.
    async fn renew(&self, claim: &Claim, tokens: &OAuthTokens) -> Result<OAuthTokens, Failure> {
        let Some(refresh) = &tokens.refresh_token else {
            // An access token that cannot be renewed ends with the hour: only a new connection helps.
            return Err(Failure::AuthRevoked);
        };
        let renewed = match claim.provider.oauth().refresh(refresh).await {
            Ok(new) => tokens::refreshed(tokens, new),
            Err(error) if error.kind == PortErrorKind::Rejected => {
                tracing::warn!(
                    tenant = %claim.tenant, account = %claim.account.id, provider = claim.provider.name(),
                    "a provider refused the refresh token of an account"
                );
                return Err(Failure::AuthRevoked);
            }
            Err(error) => {
                if error.kind == PortErrorKind::Invalid {
                    tracing::error!(
                        tenant = %claim.tenant, account = %claim.account.id, provider = claim.provider.name(),
                        "a provider refuses the OAuth client of the deployment: check `client_id` and the client secret; \
                         no account is switched off for it"
                    );
                } else {
                    tracing::warn!(
                        tenant = %claim.tenant, account = %claim.account.id, provider = claim.provider.name(),
                        kind = error.kind.as_str(), "a provider did not renew the access token of an account"
                    );
                }
                return Err(Failure::of(&error));
            }
        };
        // A provider that rotates refresh tokens has retired the old one: the new tokens are stored before anything else.
        if let Err(error) = self.store_tokens(claim, &renewed).await {
            if error.kind() == ErrorKind::PreconditionFailed {
                tracing::info!(
                    tenant = %claim.tenant, account = %claim.account.id,
                    "the account was reconnected or claimed again during a pull; the renewed tokens are dropped"
                );
            } else {
                tracing::error!(
                    tenant = %claim.tenant, account = %claim.account.id, kind = ?error.kind(),
                    "the renewed tokens of an account cannot be stored"
                );
            }
            return Err(Failure::Internal);
        }
        Ok(renewed)
    }

    /// Stores renewed tokens, while the account still holds the lease of this pull.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` when the lease is not this pull's any more (a reconnection stored a new grant, or another worker
    /// claimed the account): the tokens of a grant that was replaced are not written over the new one. Store failures.
    async fn store_tokens(&self, claim: &Claim, new: &OAuthTokens) -> AppResult<()> {
        let deps = self.core.deps();
        let sealed = tokens::seal(&self.core, claim.tenant, claim.account.id, new)?;
        for attempt in 1..=SETTLE_ATTEMPTS {
            let mut tx = deps.database.begin(claim.tenant, TxMode::ReadWrite).await?;
            let current = tx.external_accounts().get(claim.account.id).await?;
            if !Self::holds(claim, &current) {
                return Err(StoreError::PreconditionFailed.into());
            }
            let updated = ExternalAccount {
                sealed_tokens: sealed.clone(),
                ..current.clone()
            };
            match tx.external_accounts().update(updated, current.version).await {
                Ok(_) => {
                    tx.commit().await?;
                    return Ok(());
                }
                Err(StoreError::PreconditionFailed) if attempt < SETTLE_ATTEMPTS => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(StoreError::PreconditionFailed.into())
    }

    /// Whether `current` is still held by the pull of `claim`: its lease is the one the claim wrote.
    fn holds(claim: &Claim, current: &ExternalAccount) -> bool {
        SyncState::read(&current.sync_state).lease_until == Some(claim.lease)
    }

    // -----------------------------------------------------------------------------------------------------------
    // Settle
    // -----------------------------------------------------------------------------------------------------------

    /// Stores the result of the pull and answers what it was.
    async fn settle(&self, claim: &Claim, result: Result<Pulled, Failure>) -> SyncOutcome {
        for attempt in 1..=SETTLE_ATTEMPTS {
            match self.settle_once(claim, &result).await {
                Ok(true) => break,
                // The account was deleted while it was pulled, or reconnected or claimed again: the result is of a state that
                // is gone, and there is nobody to tell.
                Ok(false) => return SyncOutcome::Skipped,
                Err(error) if error.kind() == ErrorKind::PreconditionFailed && attempt < SETTLE_ATTEMPTS => {}
                Err(error) => {
                    tracing::error!(
                        tenant = %claim.tenant, account = %claim.account.id, kind = ?error.kind(),
                        "the result of a pull cannot be stored; the account is pulled again when its claim runs out"
                    );
                    break;
                }
            }
        }
        match result {
            Ok(pulled) => {
                tracing::info!(
                    tenant = %claim.tenant, account = %claim.account.id, provider = claim.provider.name(),
                    created = pulled.applied.created, updated = pulled.applied.updated,
                    deleted = pulled.applied.deleted, unchanged = pulled.applied.unchanged,
                    skipped = pulled.applied.skipped,
                    "a provider calendar was pulled"
                );
                SyncOutcome::Pulled(pulled.applied)
            }
            Err(failure) => SyncOutcome::Failed(failure.code()),
        }
    }

    /// One try at storing the result. `false` when the account is gone or no longer held by this pull.
    async fn settle_once(&self, claim: &Claim, result: &Result<Pulled, Failure>) -> AppResult<bool> {
        let deps = self.core.deps();
        let config = &deps.config.provider_sync;
        let now = deps.clock.now();
        let mut tx = deps.database.begin(claim.tenant, TxMode::ReadWrite).await?;
        let current = match tx.external_accounts().get(claim.account.id).await {
            Ok(account) => account,
            Err(StoreError::NotFound) => {
                tx.commit().await?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        // The lease is the fencing token of the pull. A reconnection clears it (and brings tokens and a state of its own), and
        // the claim of another worker replaces it: what this pull found belongs to a state that is not the account's any more,
        // and storing it would undo the reconnection (a status, an error and a due time of the old grant over the new one).
        if !Self::holds(claim, &current) {
            tracing::info!(
                tenant = %claim.tenant, account = %claim.account.id,
                "the account was reconnected or claimed again during a pull; the result is dropped"
            );
            tx.commit().await?;
            return Ok(false);
        }
        let held = SyncState::read(&current.sync_state);
        let (updated, announce) = match result {
            Ok(pulled) => (
                ExternalAccount {
                    status: ExternalAccountStatus::Active,
                    last_error: None,
                    sync_state: SyncState {
                        cursor: Some(pulled.cursor.clone()),
                        next_sync_at: Some(after(now, config.interval)),
                        lease_until: None,
                        last_sync_at: Some(now),
                        failures: 0,
                        ..held
                    }
                    .document(),
                    updated_at: now,
                    ..current.clone()
                },
                None,
            ),
            Err(failure) => {
                let failures = claim.state.failures.saturating_add(1);
                let next = match failure {
                    Failure::AuthRevoked => None,
                    _ => Some(after(now, backoff(config.interval, failures, config.backoff_max))),
                };
                // Told once: when the account was working, or when it is switched off for good.
                let announce = current.status == ExternalAccountStatus::Active
                    || (failure.status() == ExternalAccountStatus::Disabled
                        && current.status != ExternalAccountStatus::Disabled);
                (
                    ExternalAccount {
                        status: failure.status(),
                        last_error: Some(failure.message().to_owned()),
                        sync_state: SyncState {
                            next_sync_at: next,
                            lease_until: None,
                            failures,
                            ..held
                        }
                        .document(),
                        updated_at: now,
                        ..current.clone()
                    },
                    announce.then_some(*failure),
                )
            }
        };
        tx.external_accounts().update(updated, current.version).await?;
        if let Some(failure) = announce {
            let ctx = RequestContext::internal(claim.tenant, RequestId::from_uuid(deps.ids.new_id()));
            Journal::new(&self.core, &ctx)
                .publish(
                    tx.as_mut(),
                    EventType::ExternalAccountSyncFailed,
                    EventPayload::ExternalAccount(ExternalAccountPayload {
                        external_account: current.id,
                        principal: current.principal_id,
                        provider: current.provider.clone(),
                        reason: failure.code().to_owned(),
                    }),
                )
                .await?;
        }
        tx.commit().await?;
        Ok(true)
    }
}
