//! Idempotency keys and the audit log.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{AuditActor, PrincipalId, TenantId, TokenId};
use davhaven_ports::{
    AuditFilter, AuditRepo, AuditRow, IdempotencyClaim, IdempotencyRecord, IdempotencyRepo, IdempotencyStatus,
    LeasedClaim, NewAudit, PageReq, StoreError, StorePage,
};
use uuid::Uuid;

use super::{DbResult, corrupt, lease_end, micros};
use crate::tx::PgTx;

/// How often a claim retries when the conflicting key disappears between the insert and the read.
const CLAIM_ATTEMPTS: usize = 3;

/// A row of `idempotency_keys`.
#[derive(sqlx::FromRow)]
struct IdempotencyRow {
    token_id: Uuid,
    key: String,
    method: String,
    path: String,
    fingerprint: String,
    status: String,
    response_status: Option<i32>,
    response: Option<serde_json::Value>,
    expires_at: DateTime<Utc>,
}

impl IdempotencyRow {
    fn into_record(self) -> Result<IdempotencyRecord, StoreError> {
        let status = match self.status.as_str() {
            "in_flight" => IdempotencyStatus::InFlight,
            "done" => IdempotencyStatus::Done,
            other => return Err(corrupt("idempotency status", other)),
        };
        Ok(IdempotencyRecord {
            token_id: TokenId::from_uuid(self.token_id),
            key: self.key,
            method: self.method,
            path: self.path,
            fingerprint: self.fingerprint,
            status,
            response_status: self
                .response_status
                .map(|code| u16::try_from(code).map_err(|_| corrupt("response status", code)))
                .transpose()?,
            response: self.response,
            expires_at: self.expires_at,
        })
    }
}

impl PgTx {
    /// Claims the key and returns the outcome together with the end of the lease it took.
    async fn claim_inner(
        &mut self,
        record: IdempotencyRecord,
        lease: Duration,
    ) -> Result<(IdempotencyClaim, DateTime<Utc>), StoreError> {
        let now = micros(self.clock.now());
        let lease_until = micros(lease_end(now, lease));
        let tenant = self.tenant.as_uuid();
        for _ in 0..CLAIM_ATTEMPTS {
            let id = self.ids.new_id();
            let owned = record.clone();
            let claimed = self
                .guarded(move |conn| {
                    Box::pin(async move {
                        // A key is taken over when it expired, or when it is still in flight although its
                        // claimant's lease ran out (the process died before it could complete or release).
                        let claimed = sqlx::query_scalar::<_, i32>(
                            "INSERT INTO idempotency_keys (tenant_id, id, token_id, key, method, path, \
                             fingerprint, status, response_status, response, lease_until, expires_at, \
                             created_at, updated_at) \
                             VALUES ($1, $2, $3, $4, $5, $6, $7, 'in_flight', NULL, NULL, $10, $8, $9, $9) \
                             ON CONFLICT ON CONSTRAINT idempotency_keys_key DO UPDATE SET \
                               method = EXCLUDED.method, path = EXCLUDED.path, fingerprint = EXCLUDED.fingerprint, \
                               status = 'in_flight', response_status = NULL, response = NULL, \
                               lease_until = EXCLUDED.lease_until, \
                               expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at, \
                               updated_at = EXCLUDED.updated_at \
                             WHERE idempotency_keys.expires_at <= $9 \
                                OR (idempotency_keys.status = 'in_flight' AND idempotency_keys.lease_until <= $9) \
                             RETURNING 1",
                        )
                        .bind(tenant)
                        .bind(id)
                        .bind(owned.token_id.as_uuid())
                        .bind(&owned.key)
                        .bind(&owned.method)
                        .bind(&owned.path)
                        .bind(&owned.fingerprint)
                        .bind(micros(owned.expires_at))
                        .bind(now)
                        .bind(lease_until)
                        .fetch_optional(&mut *conn)
                        .await
                        .db()?;
                        Ok(claimed.is_some())
                    })
                })
                .await?;
            if claimed {
                return Ok((IdempotencyClaim::Claimed, lease_until));
            }
            let existing = sqlx::query_as::<_, IdempotencyRow>(concat!(
                "SELECT ",
                idempotency_columns!(""),
                " FROM idempotency_keys WHERE tenant_id = $1 AND token_id = $2 AND key = $3"
            ))
            .bind(tenant)
            .bind(record.token_id.as_uuid())
            .bind(&record.key)
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            if let Some(existing) = existing {
                return Ok((IdempotencyClaim::Existing(existing.into_record()?), lease_until));
            }
        }
        Err(StoreError::internal(
            "an idempotency key kept changing while it was claimed",
        ))
    }

    /// Marks the key done. `lease_until` fences the update to one claim; `None` accepts any in-flight or done key
    /// (the unfenced `complete`).
    async fn complete_key(
        &mut self,
        token: TokenId,
        key: &str,
        lease_until: Option<DateTime<Utc>>,
        response_status: u16,
        response: Option<serde_json::Value>,
    ) -> Result<(), StoreError> {
        let now = micros(self.clock.now());
        let tenant = self.tenant.as_uuid();
        let key = key.to_owned();
        self.guarded(move |conn| {
            Box::pin(async move {
                let changed = sqlx::query(
                    "UPDATE idempotency_keys SET status = 'done', response_status = $4, response = $5, \
                     lease_until = NULL, updated_at = $6 \
                     WHERE tenant_id = $1 AND token_id = $2 AND key = $3 \
                       AND ($7::timestamptz IS NULL OR (status = 'in_flight' AND lease_until = $7))",
                )
                .bind(tenant)
                .bind(token.as_uuid())
                .bind(&key)
                .bind(i32::from(response_status))
                .bind(response)
                .bind(now)
                .bind(lease_until.map(micros))
                .execute(&mut *conn)
                .await
                .db()?
                .rows_affected();
                if changed > 0 {
                    return Ok(());
                }
                // The fence did not match: the key is gone, or someone else holds or finished it.
                let exists = sqlx::query_scalar::<_, i32>(
                    "SELECT 1 FROM idempotency_keys WHERE tenant_id = $1 AND token_id = $2 AND key = $3",
                )
                .bind(tenant)
                .bind(token.as_uuid())
                .bind(&key)
                .fetch_optional(&mut *conn)
                .await
                .db()?;
                match (exists, lease_until) {
                    (Some(_), Some(_)) => Err(StoreError::LeaseLost),
                    _ => Err(StoreError::NotFound),
                }
            })
        })
        .await
    }

    /// Removes an in-flight key; `lease_until` fences the delete to one claim.
    async fn release_key(
        &mut self,
        token: TokenId,
        key: &str,
        lease_until: Option<DateTime<Utc>>,
    ) -> Result<(), StoreError> {
        let tenant = self.tenant.as_uuid();
        let key = key.to_owned();
        self.guarded(move |conn| {
            Box::pin(async move {
                sqlx::query(
                    "DELETE FROM idempotency_keys \
                     WHERE tenant_id = $1 AND token_id = $2 AND key = $3 AND status = 'in_flight' \
                       AND ($4::timestamptz IS NULL OR lease_until = $4)",
                )
                .bind(tenant)
                .bind(token.as_uuid())
                .bind(&key)
                .bind(lease_until.map(micros))
                .execute(&mut *conn)
                .await
                .db()?;
                Ok(())
            })
        })
        .await
    }
}

#[async_trait]
impl IdempotencyRepo for PgTx {
    async fn claim_with_lease(
        &mut self,
        record: IdempotencyRecord,
        lease: Duration,
    ) -> Result<IdempotencyClaim, StoreError> {
        observed!("idempotency.claim", Ok(self.claim_inner(record, lease).await?.0))
    }

    async fn claim_leased(&mut self, record: IdempotencyRecord, lease: Duration) -> Result<LeasedClaim, StoreError> {
        observed!("idempotency.claim_leased", {
            let (claim, lease_until) = self.claim_inner(record, lease).await?;
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
            self.complete_key(token, key, None, response_status, response).await
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
            self.complete_key(token, key, Some(lease_until), response_status, response)
                .await
        )
    }

    async fn release(&mut self, token: TokenId, key: &str) -> Result<(), StoreError> {
        observed!("idempotency.release", self.release_key(token, key, None).await)
    }

    async fn release_leased(
        &mut self,
        token: TokenId,
        key: &str,
        lease_until: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        observed!(
            "idempotency.release_leased",
            self.release_key(token, key, Some(lease_until)).await
        )
    }
}

/// A row of `audit_events`.
#[derive(sqlx::FromRow)]
struct AuditEventRow {
    tenant_id: Uuid,
    id: Uuid,
    actor: serde_json::Value,
    action: String,
    target: Option<String>,
    details: serde_json::Value,
    at: DateTime<Utc>,
}

impl AuditEventRow {
    fn into_row(self) -> Result<AuditRow, StoreError> {
        Ok(AuditRow {
            id: self.id,
            tenant_id: TenantId::from_uuid(self.tenant_id),
            at: self.at,
            actor: serde_json::from_value::<AuditActor>(self.actor).map_err(|error| corrupt("audit actor", error))?,
            action: self.action,
            target: self.target,
            details: self.details,
        })
    }
}

#[async_trait]
impl AuditRepo for PgTx {
    async fn append(&mut self, entry: NewAudit) -> Result<(), StoreError> {
        observed!("audit.append", {
            let record = entry.event.record();
            let actor = serde_json::to_value(&entry.actor)
                .map_err(|error| StoreError::internal(format!("audit actor cannot be serialized: {error}")))?;
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    )
                    .bind(tenant)
                    .bind(entry.id)
                    .bind(actor)
                    .bind(record.action)
                    .bind(record.target)
                    .bind(record.details)
                    .bind(now)
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    Ok(())
                })
            })
            .await
        })
    }

    async fn list(&mut self, filter: &AuditFilter, page: PageReq) -> Result<StorePage<AuditRow>, StoreError> {
        observed!("audit.list", {
            let rows = sqlx::query_as::<_, AuditEventRow>(concat!(
                "SELECT ",
                audit_columns!(""),
                " FROM audit_events WHERE tenant_id = $1 \
                 AND ($2::text IS NULL OR action = $2) \
                 AND ($3::timestamptz IS NULL OR at >= $3) \
                 AND ($4::timestamptz IS NULL OR at < $4) \
                 AND ($5::text IS NULL OR actor ->> 'principal_id' = $5) \
                 AND ($6::text IS NULL OR target = $6) \
                 AND ($7::uuid IS NULL OR id > $7) \
                 ORDER BY id LIMIT $8"
            ))
            .bind(self.tenant.as_uuid())
            .bind(filter.action.as_deref())
            .bind(filter.since.map(micros))
            .bind(filter.until.map(micros))
            .bind(filter.principal.map(|principal: PrincipalId| principal.to_string()))
            .bind(filter.target.as_deref())
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let entries = rows
                .into_iter()
                .map(AuditEventRow::into_row)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(entries, &page, |entry| entry.id))
        })
    }
}
