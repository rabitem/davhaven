//! The worker that pulls the accounts that are due (see the module documentation of `sync_engine`).

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{ExternalAccountId, ExternalAccountStatus, PrincipalId, PrincipalStatus, TenantId, TenantStatus};
use davhaven_ports::{ExternalAccountFilter, PageReq, TxMode, WorkReport, Worker};
use futures::StreamExt as _;

use super::SyncState;
use super::account::{SyncEngine, SyncOutcome};
use crate::error::AppResult;
use crate::wiring::AppCore;

/// The longest a single pass of any worker may run before `/readyz` calls the worker stalled. The server holds the same figure
/// (`davhaven_server::workers::PASS_STALL_LIMIT`; a test there keeps the two equal), and the configuration of the sync engine
/// is validated against it: [`PASS_BUDGET`], the longest pull (`providers.sync.timeout`) and [`STALL_MARGIN`] fit into it.
pub const STALL_LIMIT: Duration = Duration::from_mins(5);

/// What a pass keeps clear of [`STALL_LIMIT`] for the transactions that claim and settle accounts, which run outside the
/// timeout of a pull.
pub const STALL_MARGIN: Duration = Duration::from_secs(30);

/// After this long a pass starts no further account. A pass ends at the latest after the budget, the longest pull (the
/// configuration refuses a `providers.sync.timeout` for which the three do not fit into [`STALL_LIMIT`]) and a margin.
pub const PASS_BUDGET: Duration = Duration::from_mins(2);

/// The counter of pulls, labelled with the provider and the outcome (`pulled`, `failed`, `skipped`).
pub const SYNC_TOTAL: &str = "davhaven_provider_sync_total";

/// How many tenants and accounts one page of a listing reads.
const PAGE: u32 = 200;

/// An account that is due: where it is, since when it is due and the provider it is at (a label of the metrics).
type Due = (TenantId, ExternalAccountId, DateTime<Utc>, String);

/// The sync worker.
#[derive(Debug, Clone)]
pub struct ProviderSyncWorker {
    engine: SyncEngine,
}

impl ProviderSyncWorker {
    /// The name of the worker, in logs, metrics and heartbeats.
    pub const NAME: &'static str = "provider_sync";

    /// The worker on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self {
            engine: SyncEngine::new(core),
        }
    }

    /// The engine the worker drives.
    pub const fn engine(&self) -> &SyncEngine {
        &self.engine
    }

    /// The accounts of the providers that are on whose time has come, oldest first.
    async fn due(&self) -> AppResult<Vec<Due>> {
        let deps = self.engine.core().deps();
        let now = deps.clock.now();
        let mut tenants: Vec<TenantId> = Vec::new();
        {
            let mut tx = deps.database.begin_system().await?;
            let mut request = PageReq::first(PAGE);
            loop {
                let page = tx.tenants().list(request).await?;
                tenants.extend(
                    page.items
                        .into_iter()
                        .filter(|tenant| tenant.status == TenantStatus::Active)
                        .map(|tenant| tenant.id),
                );
                match page.next {
                    Some(after) => request = request.after(after),
                    None => break,
                }
            }
            tx.commit().await?;
        }
        let mut due: Vec<Due> = Vec::new();
        for tenant in tenants {
            // One tenant that cannot be read must not stop the others.
            if let Err(error) = self.due_in(tenant, now, &mut due).await {
                tracing::warn!(
                    %tenant, kind = ?error.kind(),
                    "the accounts of a tenant cannot be listed for the sync of providers"
                );
            }
        }
        due.sort_by_key(|(tenant, account, since, _provider)| (*since, tenant.as_uuid(), account.as_uuid()));
        Ok(due)
    }

    /// The accounts of `tenant` that are due and that a pull can be made for: of a provider that is on, not switched off, and of a
    /// principal who is not suspended. The accounts of a suspended principal stay as they are and are due again the moment the
    /// principal is active; listed, they would be the oldest due accounts for as long as they are suspended and take the places
    /// of the others in every pass.
    async fn due_in(&self, tenant: TenantId, now: DateTime<Utc>, due: &mut Vec<Due>) -> AppResult<()> {
        let core = self.engine.core();
        let mut tx = core.deps().database.begin(tenant, TxMode::ReadOnly).await?;
        let mut request = PageReq::first(PAGE);
        loop {
            let page = tx
                .external_accounts()
                .list(&ExternalAccountFilter::default(), request)
                .await?;
            let mut candidates: Vec<(ExternalAccountId, PrincipalId, DateTime<Utc>, String)> = Vec::new();
            for account in page.items {
                let Some(provider) = core.provider(&account.provider).filter(|provider| provider.enabled()) else {
                    continue;
                };
                if account.status == ExternalAccountStatus::Disabled {
                    continue;
                }
                let state = SyncState::read(&account.sync_state);
                if state.is_due(now) {
                    candidates.push((
                        account.id,
                        account.principal_id,
                        state.due_at(),
                        provider.name().to_owned(),
                    ));
                }
            }
            if !candidates.is_empty() {
                let owners: Vec<PrincipalId> = candidates.iter().map(|(_, owner, _, _)| *owner).collect();
                let suspended: HashSet<PrincipalId> = tx
                    .principals()
                    .get_many(&owners)
                    .await?
                    .into_iter()
                    .filter(|principal| principal.status == PrincipalStatus::Suspended)
                    .map(|principal| principal.id)
                    .collect();
                due.extend(
                    candidates
                        .into_iter()
                        .filter(|(_, owner, _, _)| !suspended.contains(owner))
                        .map(|(account, _, since, provider)| (tenant, account, since, provider)),
                );
            }
            let Some(after) = page.next else {
                tx.commit().await?;
                return Ok(());
            };
            request = request.after(after);
        }
    }
}

#[async_trait]
impl Worker for ProviderSyncWorker {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    #[expect(
        clippy::misnamed_getters,
        reason = "the interval of a worker is how long it sleeps between passes, `poll_interval`; `interval` of the configuration is the time between two pulls of one account"
    )]
    fn interval(&self) -> Duration {
        self.engine.core().deps().config.provider_sync.poll_interval
    }

    async fn tick(&self) -> WorkReport {
        let config = &self.engine.core().deps().config.provider_sync;
        let started = tokio::time::Instant::now();
        let mut due = match self.due().await {
            Ok(due) => due,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "the accounts of the providers cannot be listed");
                return WorkReport {
                    processed: 0,
                    failed: 1,
                    more: false,
                };
            }
        };
        let batch = usize::try_from(config.batch_size).unwrap_or(usize::MAX);
        let waiting = due.len().saturating_sub(batch);
        due.truncate(batch);
        let ready = due.len();
        let concurrency = usize::try_from(config.concurrency).unwrap_or(1).max(1);
        let engine = &self.engine;
        let outcomes: Vec<(String, SyncOutcome)> =
            futures::stream::iter(due)
                .take_while(|_| std::future::ready(started.elapsed() < PASS_BUDGET))
                .map(|(tenant, account, _since, provider)| async move {
                    (provider, engine.sync_account(tenant, account).await)
                })
                .buffer_unordered(concurrency)
                .collect()
                .await;
        let mut report = WorkReport::idle();
        let mut progressed = false;
        for (provider, outcome) in &outcomes {
            let label = match outcome {
                SyncOutcome::Pulled(_) => {
                    report.processed = report.processed.saturating_add(1);
                    progressed = true;
                    "pulled"
                }
                SyncOutcome::Failed(_) => {
                    report.failed = report.failed.saturating_add(1);
                    progressed = true;
                    "failed"
                }
                // Not claimed because the store failed: the account is due still, so it made no progress.
                SyncOutcome::Unclaimed => {
                    report.failed = report.failed.saturating_add(1);
                    "failed"
                }
                SyncOutcome::Skipped => "skipped",
            };
            metrics::counter!(SYNC_TOTAL, "provider" => provider.clone(), "outcome" => label).increment(1);
        }
        // Accounts beyond the batch, or the ones this pass had no time for, are due still, and the next pass starts at once, **if**
        // this one got somewhere: a pass that pulled or failed nothing (accounts that cannot be claimed, a store that is down) would
        // be followed by the same pass without a pause, and the worker would spin.
        report.more = progressed && (waiting > 0 || outcomes.len() < ready);
        report
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::config::AppConfig;
    use crate::outbox::fixture::Fixture;

    #[tokio::test]
    async fn an_account_that_cannot_be_claimed_because_the_store_is_down_is_unclaimed_not_skipped() {
        // `Unclaimed` keeps the account due and counts as a failure of the pass; `Skipped` would hide a store that is
        // down behind "nothing to do".
        let worker = ProviderSyncWorker::new(Fixture::new().core);
        let outcome = worker
            .engine()
            .sync_account(
                TenantId::from_uuid(Uuid::from_u128(1)),
                ExternalAccountId::from_uuid(Uuid::from_u128(2)),
            )
            .await;
        assert_eq!(outcome, SyncOutcome::Unclaimed);
    }

    #[tokio::test]
    async fn a_pass_that_cannot_list_the_accounts_fails_once_and_does_not_ask_to_run_again_at_once() {
        let worker = ProviderSyncWorker::new(Fixture::new().core);
        let report = worker.tick().await;
        assert_eq!((report.processed, report.failed, report.more), (0, 1, false));
        assert_eq!(worker.name(), "provider_sync");
        assert_eq!(
            worker.interval(),
            AppConfig::default().provider_sync.poll_interval,
            "the worker sleeps for the poll interval, not for the interval between two pulls of an account"
        );
    }
}
