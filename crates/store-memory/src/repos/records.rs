//! Idempotency keys and the audit log.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::TokenId;
use davhaven_ports::{
    AuditFilter, AuditRepo, AuditRow, IdempotencyClaim, IdempotencyRecord, IdempotencyRepo, IdempotencyStatus,
    LeasedClaim, NewAudit, PageReq, StoreError, StorePage,
};
use uuid::Uuid;

use super::{lease_end, micros, misuse, paginate};
use crate::state::IdempotencyEntry;
use crate::tx::MemTx;

impl MemTx {
    /// Claims the key and returns the outcome together with the end of the lease it took.
    fn claim_inner(
        &mut self,
        record: IdempotencyRecord,
        lease: Duration,
    ) -> Result<(IdempotencyClaim, DateTime<Utc>), StoreError> {
        let now = self.now();
        let lease_until = micros(lease_end(now, lease));
        let data = self.writable()?;
        let key = (record.token_id, record.key.clone());
        if let Some(held) = data.idempotency.get(&key) {
            let expired = held.record.expires_at <= now;
            let abandoned =
                held.record.status == IdempotencyStatus::InFlight && held.lease_until.is_some_and(|until| until <= now);
            if !expired && !abandoned {
                return Ok((IdempotencyClaim::Existing(held.record.clone()), lease_until));
            }
        }
        data.idempotency.insert(
            key,
            IdempotencyEntry {
                record: IdempotencyRecord {
                    status: IdempotencyStatus::InFlight,
                    response_status: None,
                    response: None,
                    expires_at: micros(record.expires_at),
                    ..record
                },
                lease_until: Some(lease_until),
            },
        );
        Ok((IdempotencyClaim::Claimed, lease_until))
    }

    /// Marks the key done; with `fence` only while the key is in flight with exactly that lease end.
    fn complete_key(
        &mut self,
        token: TokenId,
        key: &str,
        fence: Option<DateTime<Utc>>,
        response_status: u16,
        response: Option<serde_json::Value>,
    ) -> Result<(), StoreError> {
        let stored = self
            .writable()?
            .idempotency
            .get_mut(&(token, key.to_owned()))
            .ok_or(StoreError::NotFound)?;
        if let Some(fence) = fence
            && !(stored.record.status == IdempotencyStatus::InFlight && stored.lease_until == Some(fence))
        {
            return Err(StoreError::LeaseLost);
        }
        stored.record.status = IdempotencyStatus::Done;
        stored.record.response_status = Some(response_status);
        stored.record.response = response;
        stored.lease_until = None;
        Ok(())
    }

    /// Removes an in-flight key; with `fence` only while its lease end is exactly that.
    fn release_key(&mut self, token: TokenId, key: &str, fence: Option<DateTime<Utc>>) -> Result<(), StoreError> {
        let data = self.writable()?;
        let slot = (token, key.to_owned());
        if data.idempotency.get(&slot).is_some_and(|stored| {
            stored.record.status == IdempotencyStatus::InFlight
                && fence.is_none_or(|fence| stored.lease_until == Some(fence))
        }) {
            data.idempotency.remove(&slot);
        }
        Ok(())
    }
}

#[async_trait]
impl IdempotencyRepo for MemTx {
    async fn claim_with_lease(
        &mut self,
        record: IdempotencyRecord,
        lease: Duration,
    ) -> Result<IdempotencyClaim, StoreError> {
        observed!("idempotency.claim", Ok(self.claim_inner(record, lease)?.0))
    }

    async fn claim_leased(&mut self, record: IdempotencyRecord, lease: Duration) -> Result<LeasedClaim, StoreError> {
        observed!("idempotency.claim_leased", {
            let (claim, lease_until) = self.claim_inner(record, lease)?;
            Ok(match claim {
                IdempotencyClaim::Claimed => LeasedClaim::Claimed { lease_until },
                IdempotencyClaim::Existing(existing) => LeasedClaim::Existing(existing),
            })
        })
    }

    async fn complete(
        &mut self,
        token: TokenId,
        key: &str,
        response_status: u16,
        response: Option<serde_json::Value>,
    ) -> Result<(), StoreError> {
        observed!(
            "idempotency.complete",
            self.complete_key(token, key, None, response_status, response)
        )
    }

    async fn complete_leased(
        &mut self,
        token: TokenId,
        key: &str,
        lease_until: DateTime<Utc>,
        response_status: u16,
        response: Option<serde_json::Value>,
    ) -> Result<(), StoreError> {
        observed!(
            "idempotency.complete_leased",
            self.complete_key(token, key, Some(micros(lease_until)), response_status, response)
        )
    }

    async fn release(&mut self, token: TokenId, key: &str) -> Result<(), StoreError> {
        observed!("idempotency.release", self.release_key(token, key, None))
    }

    async fn release_leased(
        &mut self,
        token: TokenId,
        key: &str,
        lease_until: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        observed!(
            "idempotency.release_leased",
            self.release_key(token, key, Some(micros(lease_until)))
        )
    }
}

#[async_trait]
impl AuditRepo for MemTx {
    async fn append(&mut self, entry: NewAudit) -> Result<(), StoreError> {
        observed!("audit.append", {
            self.require_write_mode()?;
            let record = entry.event.record();
            let at = self.now();
            let tenant = self.tenant;
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

    async fn list(&mut self, filter: &AuditFilter, page: PageReq) -> Result<StorePage<AuditRow>, StoreError> {
        observed!("audit.list", {
            let tenant = self.tenant;
            let (since, until) = (filter.since.map(micros), filter.until.map(micros));
            let matching = self
                .guard
                .audit
                .range((tenant, Uuid::nil())..=(tenant, Uuid::max()))
                .map(|(_, row)| row)
                .filter(|row| {
                    filter.action.as_ref().is_none_or(|action| &row.action == action)
                        && since.is_none_or(|since| row.at >= since)
                        && until.is_none_or(|until| row.at < until)
                        && filter
                            .principal
                            .is_none_or(|principal| row.actor.principal_id == Some(principal))
                        && filter
                            .target
                            .as_ref()
                            .is_none_or(|target| row.target.as_ref() == Some(target))
                });
            Ok(paginate(matching.cloned(), &page, |row| row.id))
        })
    }
}
