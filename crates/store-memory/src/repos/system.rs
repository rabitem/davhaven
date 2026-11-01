//! System repositories: tenant management, credential lookup, the outbox queue and retention.
//!
//! They run in a [`MemSystemTx`] and iterate over all tenants. Retention removes at most one batch per call, like
//! the PostgreSQL adapter, and keeps the change logs consistent (pruned history raises `sync_min_seq`, purged
//! delivered inbox items are logged as deletions, quarantined ones never are).

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    ApiToken, AuditEvent, CalendarId, CollectionKind, CredentialKind, DomainName, ObjectUri, PrincipalId, Tenant,
    TenantId, TenantSlug, TokenId, TokenKind,
};
use davhaven_ports::{
    AuditRow, CredentialLookup, CredentialOwner, CredentialRecord, LookedUpCredential, NewTenantAudit, OutboxClaim,
    OutboxFailure, OutboxKey, OutboxQueue, OutboxRecord, OutboxStats, OutboxStatus, PageReq, RetentionRepo, StoreError,
    StorePage, SystemTenantRepo, UniqueKey,
};
use uuid::Uuid;

use super::credentials::token_prefix_taken;
use super::sync::raise_min_seq;
use super::{PURGE_BATCH, lease_end, micros, misuse, no_nul, paginate};
use crate::state::{ChangeEntry, State, TenantData, TenantEntry};
use crate::tx::MemSystemTx;

#[async_trait]
impl SystemTenantRepo for MemSystemTx {
    async fn get(&mut self, id: TenantId) -> Result<Tenant, StoreError> {
        observed!(
            "tenants.get",
            self.guard
                .tenants
                .get(&id)
                .map(|entry| entry.tenant.clone())
                .ok_or(StoreError::NotFound)
        )
    }

    async fn find_by_slug(&mut self, slug: &TenantSlug) -> Result<Option<Tenant>, StoreError> {
        observed!(
            "tenants.find_by_slug",
            Ok(self
                .guard
                .tenants
                .values()
                .find(|entry| &entry.tenant.slug == slug)
                .map(|entry| entry.tenant.clone()))
        )
    }

    async fn find_by_login_domain(&mut self, domain: &DomainName) -> Result<Option<Tenant>, StoreError> {
        observed!("tenants.find_by_login_domain", {
            let wanted = domain.as_str().to_lowercase();
            Ok(self
                .guard
                .tenants
                .values()
                .find(|entry| {
                    entry
                        .tenant
                        .login_domain
                        .as_ref()
                        .is_some_and(|candidate| candidate.as_str().to_lowercase() == wanted)
                })
                .map(|entry| entry.tenant.clone()))
        })
    }

    async fn list(&mut self, page: PageReq) -> Result<StorePage<Tenant>, StoreError> {
        observed!(
            "tenants.list",
            Ok(paginate(
                self.guard.tenants.values().map(|entry| entry.tenant.clone()),
                &page,
                |tenant| tenant.id.as_uuid()
            ))
        )
    }

    async fn create(&mut self, tenant: Tenant) -> Result<Tenant, StoreError> {
        observed!("tenants.create", {
            no_nul("tenant text", [Some(tenant.display_name.as_str())])?;
            let now = self.now();
            if self.guard.tenants.contains_key(&tenant.id) {
                return Err(misuse("a tenant with this id exists already"));
            }
            if self
                .guard
                .tenants
                .values()
                .any(|entry| entry.tenant.slug == tenant.slug)
            {
                return Err(StoreError::UniqueViolation(UniqueKey::TenantSlug));
            }
            if domain_taken(&self.guard, tenant.id, tenant.login_domain.as_ref()) {
                return Err(StoreError::UniqueViolation(UniqueKey::LoginDomain));
            }
            let stored = Tenant {
                created_at: now,
                updated_at: now,
                version: 1,
                ..tenant
            };
            self.guard.tenants.insert(
                stored.id,
                TenantEntry {
                    tenant: stored.clone(),
                    data: TenantData::default(),
                },
            );
            Ok(stored)
        })
    }

    async fn update(&mut self, tenant: Tenant, expected_version: i64) -> Result<Tenant, StoreError> {
        observed!("tenants.update", {
            let now = self.now();
            let current = self.guard.tenants.get(&tenant.id).ok_or(StoreError::NotFound)?;
            if current.tenant.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            if domain_taken(&self.guard, tenant.id, tenant.login_domain.as_ref()) {
                return Err(StoreError::UniqueViolation(UniqueKey::LoginDomain));
            }
            let stored = &mut self
                .guard
                .tenants
                .get_mut(&tenant.id)
                .ok_or(StoreError::NotFound)?
                .tenant;
            stored.display_name = tenant.display_name;
            stored.login_domain = tenant.login_domain;
            stored.status = tenant.status;
            stored.settings = tenant.settings;
            stored.updated_at = now;
            stored.version += 1;
            Ok(stored.clone())
        })
    }

    async fn delete(&mut self, id: TenantId) -> Result<(), StoreError> {
        observed!("tenants.delete", {
            self.guard.tenants.remove(&id).map(|_| ()).ok_or(StoreError::NotFound)
        })
    }

    async fn append_audit(&mut self, tenant: TenantId, entry: NewTenantAudit) -> Result<(), StoreError> {
        observed!("tenants.append_audit", {
            if !self.guard.tenants.contains_key(&tenant) {
                return Err(StoreError::NotFound);
            }
            let record = AuditEvent::from(entry.event).record();
            let at = self.now();
            let slot = (tenant, entry.id);
            if self.guard.audit.contains_key(&slot) {
                return Err(misuse("an audit record with this id exists already"));
            }
            self.guard.audit.insert(
                slot,
                AuditRow {
                    id: entry.id,
                    tenant_id: tenant,
                    at,
                    actor: entry.actor,
                    action: record.action.to_owned(),
                    target: record.target,
                    details: record.details,
                },
            );
            Ok(())
        })
    }

    async fn bump_sync_epoch(&mut self, tenant: Option<TenantId>) -> Result<u64, StoreError> {
        observed!("tenants.bump_sync_epoch", {
            let epoch = self.ids.new_id();
            if let Some(tenant) = tenant
                && !self.guard.tenants.contains_key(&tenant)
            {
                return Err(StoreError::NotFound);
            }
            let mut changed = 0_u64;
            for (id, entry) in &mut self.guard.tenants {
                if tenant.is_some_and(|wanted| wanted != *id) {
                    continue;
                }
                for calendar in entry.data.calendars.values_mut() {
                    calendar.sync_epoch = epoch;
                    changed += 1;
                }
                for sync in entry.data.sync.values_mut() {
                    sync.home.epoch = epoch;
                    sync.inbox.epoch = epoch;
                    sync.notifications.epoch = epoch;
                    changed += 3;
                }
            }
            Ok(changed)
        })
    }
}

/// Whether another tenant than `except` has the login domain (case-insensitively).
fn domain_taken(state: &State, except: TenantId, domain: Option<&DomainName>) -> bool {
    domain.is_some_and(|domain| {
        let wanted = domain.as_str().to_lowercase();
        state.tenants.values().any(|entry| {
            entry.tenant.id != except
                && entry
                    .tenant
                    .login_domain
                    .as_ref()
                    .is_some_and(|candidate| candidate.as_str().to_lowercase() == wanted)
        })
    })
}

#[async_trait]
impl CredentialLookup for MemSystemTx {
    async fn find_by_prefix(
        &mut self,
        kind: CredentialKind,
        prefix: &str,
    ) -> Result<Option<LookedUpCredential>, StoreError> {
        observed!("credentials.find_by_prefix", {
            if kind == CredentialKind::ApiToken
                && let Some(token) = self.guard.system_tokens.values().find(|token| token.prefix == prefix)
            {
                return Ok(Some(LookedUpCredential {
                    record: CredentialRecord::ApiToken(Box::new(token.clone())),
                    tenant_status: None,
                    principal_status: None,
                    credential_generation: None,
                    owner: None,
                }));
            }
            for entry in self.guard.tenants.values() {
                let data = &entry.data;
                let (record, principal) = match kind {
                    CredentialKind::AppPassword => {
                        let Some(found) = data.app_passwords.values().find(|found| found.prefix == prefix) else {
                            continue;
                        };
                        (
                            CredentialRecord::AppPassword(Box::new(found.clone())),
                            Some(found.principal_id),
                        )
                    }
                    CredentialKind::ApiToken => {
                        let Some(found) = data.api_tokens.values().find(|found| found.prefix == prefix) else {
                            continue;
                        };
                        (CredentialRecord::ApiToken(Box::new(found.clone())), found.principal_id)
                    }
                    CredentialKind::FeedToken => {
                        let Some(found) = data.feed_tokens.values().find(|found| found.prefix == prefix) else {
                            continue;
                        };
                        (
                            CredentialRecord::FeedToken(Box::new(found.clone())),
                            Some(found.principal_id),
                        )
                    }
                    CredentialKind::RsvpToken => {
                        let Some(found) = data.rsvp_tokens.values().find(|found| found.prefix == prefix) else {
                            continue;
                        };
                        (CredentialRecord::RsvpToken(Box::new(found.clone())), None)
                    }
                };
                let principal = principal.and_then(|id| data.principals.get(&id));
                return Ok(Some(LookedUpCredential {
                    record,
                    tenant_status: Some(entry.tenant.status),
                    principal_status: principal.map(|principal| principal.status),
                    credential_generation: principal.map(|principal| principal.credential_generation),
                    owner: Some(CredentialOwner {
                        tenant_slug: entry.tenant.slug.clone(),
                        login_domain: entry.tenant.login_domain.clone(),
                        principal_name: principal.map(|principal| principal.name.clone()),
                    }),
                }));
            }
            Ok(None)
        })
    }

    async fn create_system_token(&mut self, token: ApiToken) -> Result<ApiToken, StoreError> {
        observed!("credentials.create_system_token", {
            if token.kind != TokenKind::System {
                return Err(misuse("only system tokens are created through the credential lookup"));
            }
            let now = self.now();
            if token_prefix_taken(&self.guard, &token.prefix) {
                return Err(StoreError::UniqueViolation(UniqueKey::CredentialPrefix));
            }
            let creator_known = token.created_by.is_none_or(|creator| {
                self.guard.system_tokens.contains_key(&creator)
                    || self
                        .guard
                        .tenants
                        .values()
                        .any(|entry| entry.data.api_tokens.contains_key(&creator))
            });
            if !creator_known {
                return Err(StoreError::NotFound);
            }
            if self.guard.system_tokens.contains_key(&token.id) {
                return Err(misuse("an API token with this id exists already"));
            }
            let stored = ApiToken {
                tenant_id: None,
                expires_at: token.expires_at.map(micros),
                last_used_at: token.last_used_at.map(micros),
                revoked_at: token.revoked_at.map(micros),
                created_at: now,
                updated_at: now,
                version: 1,
                ..token
            };
            self.guard.system_tokens.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn list_system_tokens(&mut self) -> Result<Vec<ApiToken>, StoreError> {
        observed!(
            "credentials.list_system_tokens",
            Ok(self.guard.system_tokens.values().cloned().collect())
        )
    }

    async fn revoke_system_token(&mut self, id: TokenId) -> Result<(), StoreError> {
        observed!("credentials.revoke_system_token", {
            let now = self.now();
            let stored = self.guard.system_tokens.get_mut(&id).ok_or(StoreError::NotFound)?;
            if stored.revoked_at.is_none() {
                stored.revoked_at = Some(now);
                stored.updated_at = now;
                stored.version += 1;
            }
            Ok(())
        })
    }
}

/// The values of a claim that fence a settle: the attempt number and the lease end the claim wrote. `None` for the
/// unfenced settle, which only requires the record to be in flight.
type Fence = Option<(u32, DateTime<Utc>)>;

/// The attempt number and lease end that a claim wrote.
fn fence_of(claim: &OutboxClaim) -> (u32, DateTime<Utc>) {
    (claim.attempt, micros(claim.locked_until))
}

impl MemSystemTx {
    /// The outbox record of a key, for changing it.
    fn outbox_record(&mut self, key: OutboxKey) -> Result<&mut OutboxRecord, StoreError> {
        self.guard
            .tenants
            .get_mut(&key.tenant)
            .and_then(|entry| entry.data.outbox.get_mut(&key.id))
            .ok_or(StoreError::NotFound)
    }

    /// The record of `key` while it is in flight (and, with a fence, still held by that claim).
    ///
    /// # Errors
    ///
    /// `NotFound` for a missing record, `LeaseLost` for one that was settled, released or reclaimed by someone
    /// else in the meantime: that outcome stands.
    fn held_record(&mut self, key: OutboxKey, fence: Fence) -> Result<&mut OutboxRecord, StoreError> {
        let record = self.outbox_record(key)?;
        let held = record.status == OutboxStatus::InFlight
            && fence.is_none_or(|(attempt, until)| record.attempts == attempt && record.locked_until == Some(until));
        if held { Ok(record) } else { Err(StoreError::LeaseLost) }
    }

    /// Marks a record done.
    fn settle_done(&mut self, key: OutboxKey, fence: Fence) -> Result<(), StoreError> {
        let now = self.now();
        let record = self.held_record(key, fence)?;
        record.status = OutboxStatus::Done;
        record.locked_until = None;
        record.updated_at = now;
        Ok(())
    }

    /// Records a failed attempt.
    fn settle_failed(&mut self, key: OutboxKey, failure: OutboxFailure, fence: Fence) -> Result<(), StoreError> {
        let now = self.now();
        let record = self.held_record(key, fence)?;
        match failure.retry_at {
            Some(retry_at) => {
                record.status = OutboxStatus::Pending;
                record.next_attempt_at = micros(retry_at);
            }
            None => record.status = OutboxStatus::Dead,
        }
        record.locked_until = None;
        record.last_error = Some(failure.error);
        record.updated_at = now;
        Ok(())
    }

    /// Puts a record back for later without counting the claim (nothing was attempted).
    fn settle_deferred(
        &mut self,
        key: OutboxKey,
        until: DateTime<Utc>,
        note: &str,
        fence: Fence,
    ) -> Result<(), StoreError> {
        let now = self.now();
        let record = self.held_record(key, fence)?;
        record.status = OutboxStatus::Pending;
        record.next_attempt_at = micros(until);
        record.locked_until = None;
        record.attempts = record.attempts.saturating_sub(1);
        record.last_error = Some(note.to_owned());
        record.updated_at = now;
        Ok(())
    }

    /// Hands the given leases back; the attempt that never finished is not counted.
    fn release_held(&mut self, held: &[(OutboxKey, Fence)]) -> u64 {
        let now = self.now();
        let mut released = 0_u64;
        for (key, fence) in held {
            let Ok(record) = self.held_record(*key, *fence) else {
                continue;
            };
            record.status = OutboxStatus::Pending;
            record.locked_until = None;
            record.next_attempt_at = now;
            record.attempts = record.attempts.saturating_sub(1);
            record.updated_at = now;
            released += 1;
        }
        released
    }
}

#[async_trait]
impl OutboxQueue for MemSystemTx {
    async fn claim(&mut self, limit: u32, lease: Duration) -> Result<Vec<OutboxRecord>, StoreError> {
        observed!("outbox.claim", {
            let now = self.now();
            let until = micros(lease_end(now, lease));
            let take = usize::try_from(limit.min(davhaven_ports::store::MAX_PAGE_LIMIT)).unwrap_or(usize::MAX);
            let mut due: Vec<(DateTime<Utc>, davhaven_domain::OutboxId, TenantId)> = Vec::new();
            for (tenant, entry) in &self.guard.tenants {
                for record in entry.data.outbox.values() {
                    let ready = match record.status {
                        OutboxStatus::Pending => record.next_attempt_at <= now,
                        OutboxStatus::InFlight => record.locked_until.is_some_and(|locked| locked <= now),
                        OutboxStatus::Done | OutboxStatus::Dead => false,
                    };
                    if ready {
                        due.push((record.next_attempt_at, record.id, *tenant));
                    }
                }
            }
            due.sort();
            due.truncate(take);
            let mut claimed = Vec::with_capacity(due.len());
            for (_, id, tenant) in due {
                let record = self.outbox_record(OutboxKey { tenant, id })?;
                record.status = OutboxStatus::InFlight;
                record.locked_until = Some(until);
                record.attempts = record.attempts.saturating_add(1);
                record.updated_at = now;
                claimed.push(record.clone());
            }
            Ok(claimed)
        })
    }

    async fn complete(&mut self, key: OutboxKey) -> Result<(), StoreError> {
        observed!("outbox.complete", self.settle_done(key, None))
    }

    async fn fail(&mut self, key: OutboxKey, failure: OutboxFailure) -> Result<(), StoreError> {
        observed!("outbox.fail", self.settle_failed(key, failure, None))
    }

    async fn complete_claimed(&mut self, claim: OutboxClaim) -> Result<(), StoreError> {
        observed!(
            "outbox.complete_claimed",
            self.settle_done(claim.key, Some(fence_of(&claim)))
        )
    }

    async fn fail_claimed(&mut self, claim: OutboxClaim, failure: OutboxFailure) -> Result<(), StoreError> {
        observed!(
            "outbox.fail_claimed",
            self.settle_failed(claim.key, failure, Some(fence_of(&claim)))
        )
    }

    async fn defer_claimed(&mut self, claim: OutboxClaim, until: DateTime<Utc>, note: &str) -> Result<(), StoreError> {
        observed!(
            "outbox.defer_claimed",
            self.settle_deferred(claim.key, until, note, Some(fence_of(&claim)))
        )
    }

    async fn release_leases(&mut self, held: &[OutboxKey]) -> Result<u64, StoreError> {
        observed!("outbox.release_leases", {
            let held: Vec<(OutboxKey, Fence)> = held.iter().map(|key| (*key, None)).collect();
            Ok(self.release_held(&held))
        })
    }

    async fn release_claimed(&mut self, held: &[OutboxClaim]) -> Result<u64, StoreError> {
        observed!("outbox.release_claimed", {
            let held: Vec<(OutboxKey, Fence)> = held.iter().map(|claim| (claim.key, Some(fence_of(claim)))).collect();
            Ok(self.release_held(&held))
        })
    }

    async fn stats(&mut self) -> Result<OutboxStats, StoreError> {
        observed!("outbox.stats", {
            let mut stats = OutboxStats::default();
            for record in self.guard.tenants.values().flat_map(|entry| entry.data.outbox.values()) {
                match record.status {
                    OutboxStatus::Pending => {
                        stats.pending += 1;
                        stats.oldest_pending_at = Some(
                            stats
                                .oldest_pending_at
                                .map_or(record.next_attempt_at, |oldest| oldest.min(record.next_attempt_at)),
                        );
                    }
                    OutboxStatus::InFlight => stats.in_flight += 1,
                    OutboxStatus::Dead => stats.dead += 1,
                    OutboxStatus::Done => {}
                }
            }
            Ok(stats)
        })
    }
}

/// One principal's expired inbox items.
struct ExpiredInbox {
    tenant: TenantId,
    principal: PrincipalId,
    /// Every expired item, with whether its deletion is logged (a quarantined item was never shown to clients).
    items: Vec<(davhaven_domain::InboxItemId, ObjectUri, bool)>,
}

#[async_trait]
impl RetentionRepo for MemSystemTx {
    async fn purge_outbox(
        &mut self,
        done_before: DateTime<Utc>,
        dead_before: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        observed!("retention.purge_outbox", {
            let (done_before, dead_before) = (micros(done_before), micros(dead_before));
            let mut doomed: Vec<(TenantId, davhaven_domain::OutboxId)> = Vec::new();
            for (tenant, entry) in &self.guard.tenants {
                for record in entry.data.outbox.values() {
                    let expired = match record.status {
                        OutboxStatus::Done => record.updated_at < done_before,
                        OutboxStatus::Dead => record.updated_at < dead_before,
                        OutboxStatus::Pending | OutboxStatus::InFlight => false,
                    };
                    if expired {
                        doomed.push((*tenant, record.id));
                    }
                }
            }
            doomed.truncate(PURGE_BATCH);
            let removed = u64::try_from(doomed.len()).unwrap_or(u64::MAX);
            for (tenant, id) in doomed {
                if let Some(entry) = self.guard.tenants.get_mut(&tenant) {
                    entry.data.outbox.remove(&id);
                }
            }
            Ok(removed)
        })
    }

    async fn prune_changes(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.prune_changes", {
            let before = micros(before);
            let mut candidates: Vec<(DateTime<Utc>, TenantId, CollectionKind, Uuid, u64)> = Vec::new();
            for (tenant, entry) in &self.guard.tenants {
                for ((kind, collection), entries) in entry.data.changes.iter() {
                    candidates.extend(
                        entries
                            .iter()
                            .filter(|change| change.at < before)
                            .map(|change| (change.at, *tenant, *kind, *collection, change.seq)),
                    );
                }
            }
            candidates.sort();
            candidates.truncate(PURGE_BATCH);
            let removed = u64::try_from(candidates.len()).unwrap_or(u64::MAX);
            let mut highest: BTreeMap<(TenantId, CollectionKind, Uuid), u64> = BTreeMap::new();
            for (_, tenant, kind, collection, seq) in &candidates {
                let slot = highest.entry((*tenant, *kind, *collection)).or_insert(0);
                *slot = (*slot).max(*seq);
            }
            let doomed: BTreeMap<(TenantId, CollectionKind, Uuid), Vec<u64>> =
                candidates
                    .iter()
                    .fold(BTreeMap::new(), |mut map, (_, tenant, kind, collection, seq)| {
                        map.entry((*tenant, *kind, *collection)).or_default().push(*seq);
                        map
                    });
            for ((tenant, kind, collection), seqs) in doomed {
                let Some(entry) = self.guard.tenants.get_mut(&tenant) else {
                    continue;
                };
                if let Some(log) = entry.data.changes.get_mut(&(kind, collection)) {
                    log.retain(|change| !seqs.contains(&change.seq));
                }
                if let Some(max_pruned) = highest.get(&(tenant, kind, collection)) {
                    raise_min_seq(&mut entry.data, kind, collection, *max_pruned);
                }
            }
            Ok(removed)
        })
    }

    async fn purge_audit(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_audit", {
            let before = micros(before);
            let mut doomed: Vec<(DateTime<Utc>, TenantId, Uuid)> = self
                .guard
                .audit
                .values()
                .filter(|row| row.at < before)
                .map(|row| (row.at, row.tenant_id, row.id))
                .collect();
            doomed.sort();
            doomed.truncate(PURGE_BATCH);
            let removed = u64::try_from(doomed.len()).unwrap_or(u64::MAX);
            for (_, tenant, id) in doomed {
                self.guard.audit.remove(&(tenant, id));
            }
            Ok(removed)
        })
    }

    async fn oldest_audit_at(&mut self) -> Result<Option<DateTime<Utc>>, StoreError> {
        observed!("retention.oldest_audit_at", {
            Ok(self.guard.audit.values().map(|row| row.at).min())
        })
    }

    async fn purge_deliveries(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_deliveries", {
            let before = micros(before);
            let mut doomed: Vec<(DateTime<Utc>, TenantId, davhaven_domain::DeliveryId)> = Vec::new();
            for (tenant, entry) in &self.guard.tenants {
                for delivery in entry.data.deliveries.values() {
                    if delivery.created_at < before {
                        doomed.push((delivery.created_at, *tenant, delivery.id));
                    }
                }
            }
            doomed.sort();
            doomed.truncate(PURGE_BATCH);
            let removed = u64::try_from(doomed.len()).unwrap_or(u64::MAX);
            for (_, tenant, id) in doomed {
                if let Some(entry) = self.guard.tenants.get_mut(&tenant) {
                    entry.data.deliveries.remove(&id);
                }
            }
            Ok(removed)
        })
    }

    async fn purge_inbox(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_inbox", {
            let before = micros(before);
            let now = self.now();
            let mut expired: Vec<(
                TenantId,
                PrincipalId,
                davhaven_domain::InboxItemId,
                ObjectUri,
                bool,
                DateTime<Utc>,
            )> = Vec::new();
            for (tenant, entry) in &self.guard.tenants {
                for item in entry.data.inbox.values().filter(|item| item.created_at < before) {
                    expired.push((
                        *tenant,
                        item.principal_id,
                        item.id,
                        item.uri.clone(),
                        !item.quarantined,
                        item.created_at,
                    ));
                }
            }
            // The oldest first, like the PostgreSQL adapter (`ORDER BY created_at, id`), then grouped per principal.
            expired.sort_by_key(|item| (item.5, item.2));
            expired.truncate(PURGE_BATCH);
            let removed = u64::try_from(expired.len()).unwrap_or(u64::MAX);
            let mut groups: BTreeMap<(TenantId, PrincipalId), ExpiredInbox> = BTreeMap::new();
            for (tenant, principal, id, uri, logged, _) in expired {
                groups
                    .entry((tenant, principal))
                    .or_insert_with(|| ExpiredInbox {
                        tenant,
                        principal,
                        items: Vec::new(),
                    })
                    .items
                    .push((id, uri, logged));
            }
            for group in groups.into_values() {
                let Some(entry) = self.guard.tenants.get_mut(&group.tenant) else {
                    continue;
                };
                let data = &mut entry.data;
                for (id, _, _) in &group.items {
                    data.inbox.remove(id);
                }
                if let Some(position) = data
                    .sync
                    .get_mut(&group.principal)
                    .and_then(|sync| sync.position_mut(CollectionKind::Inbox))
                {
                    for (_, uri, _) in group.items.iter().filter(|(_, _, logged)| *logged) {
                        position.seq = position.seq.saturating_add(1);
                        let seq = position.seq;
                        data.changes
                            .entry((CollectionKind::Inbox, group.principal.as_uuid()))
                            .or_default()
                            .push(ChangeEntry {
                                seq,
                                uri: uri.clone(),
                                kind: davhaven_ports::ChangeKind::Delete,
                                at: now,
                            });
                    }
                }
            }
            Ok(removed)
        })
    }

    async fn purge_idempotency(&mut self) -> Result<u64, StoreError> {
        observed!("retention.purge_idempotency", {
            let now = self.now();
            let mut removed = 0_u64;
            for entry in self.guard.tenants.values_mut() {
                let before = entry.data.idempotency.len();
                entry.data.idempotency.retain(|_, held| held.record.expires_at > now);
                removed += u64::try_from(before - entry.data.idempotency.len()).unwrap_or(u64::MAX);
            }
            Ok(removed)
        })
    }

    async fn purge_oauth_states(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_oauth_states", {
            let before = micros(before);
            let mut removed = 0_u64;
            for entry in self.guard.tenants.values_mut() {
                let count = entry.data.oauth_states.len();
                entry.data.oauth_states.retain(|_, state| state.expires_at >= before);
                removed += u64::try_from(count - entry.data.oauth_states.len()).unwrap_or(u64::MAX);
            }
            Ok(removed)
        })
    }

    async fn purge_rsvp_tokens(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_rsvp_tokens", {
            let before = micros(before);
            let mut removed = 0_u64;
            for entry in self.guard.tenants.values_mut() {
                let count = entry.data.rsvp_tokens.len();
                entry.data.rsvp_tokens.retain(|_, token| {
                    token.expires_at >= before && token.revoked_at.is_none_or(|revoked| revoked >= before)
                });
                removed += u64::try_from(count - entry.data.rsvp_tokens.len()).unwrap_or(u64::MAX);
            }
            Ok(removed)
        })
    }

    async fn due_principals(
        &mut self,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(TenantId, PrincipalId)>, StoreError> {
        observed!("retention.due_principals", {
            let before = micros(before);
            let mut due: Vec<(DateTime<Utc>, PrincipalId, TenantId)> = Vec::new();
            for (tenant, entry) in &self.guard.tenants {
                for principal in entry.data.principals.values() {
                    if let Some(deleted_at) = principal.deleted_at
                        && principal.status == davhaven_domain::PrincipalStatus::Deleted
                        && deleted_at < before
                    {
                        due.push((deleted_at, principal.id, *tenant));
                    }
                }
            }
            due.sort();
            due.truncate(usize::try_from(limit.min(davhaven_ports::store::MAX_PAGE_LIMIT)).unwrap_or(usize::MAX));
            Ok(due
                .into_iter()
                .map(|(_, principal, tenant)| (tenant, principal))
                .collect())
        })
    }

    async fn due_calendars(
        &mut self,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(TenantId, CalendarId)>, StoreError> {
        observed!("retention.due_calendars", {
            let before = micros(before);
            let mut due: Vec<(DateTime<Utc>, CalendarId, TenantId)> = Vec::new();
            for (tenant, entry) in &self.guard.tenants {
                for calendar in entry.data.calendars.values() {
                    if let Some(deleted_at) = calendar.deleted_at
                        && deleted_at < before
                    {
                        due.push((deleted_at, calendar.id, *tenant));
                    }
                }
            }
            due.sort();
            due.truncate(usize::try_from(limit.min(davhaven_ports::store::MAX_PAGE_LIMIT)).unwrap_or(usize::MAX));
            Ok(due
                .into_iter()
                .map(|(_, calendar, tenant)| (tenant, calendar))
                .collect())
        })
    }
}
