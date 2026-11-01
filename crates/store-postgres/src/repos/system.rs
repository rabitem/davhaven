//! System repositories: tenant management, credential lookup, the outbox queue and retention.
//!
//! They run in a [`PgSystemTx`], which sets `davhaven.system`; the row-level security policies of the tables they
//! touch admit that scope (and no other table has such a policy). Retention deletes in bounded batches, so one
//! call never holds locks for long; the cleanup worker repeats until a call removes less than a batch.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    ApiToken, AuditEvent, CalendarId, CredentialKind, DomainName, PrincipalId, PrincipalName, PrincipalStatus, Tenant,
    TenantId, TenantSlug, TenantStatus, TokenId, TokenKind,
};
use davhaven_ports::store::MAX_PAGE_LIMIT;
use davhaven_ports::{
    AuditPurge, CredentialLookup, CredentialOwner, CredentialRecord, LookedUpCredential, NewTenantAudit, OutboxClaim,
    OutboxFailure, OutboxKey, OutboxQueue, OutboxRecord, OutboxStats, PageReq, RetentionRepo, StoreError, StorePage,
    SystemTenantRepo,
};
use sqlx::PgConnection;
use std::collections::BTreeMap;
use uuid::Uuid;

use super::credentials::{ApiTokenRow, AppPasswordRow, FeedTokenRow, RsvpTokenRow};
use super::delivery::OutboxRow;
use super::tenant::TenantRow;
use super::{DbResult, corrupt, decode, decode_opt, lease_end, micros, misuse, stale_or_missing_global, to_u64};
use crate::error::map_sqlx;
use crate::tx::{PgSystemTx, begin_maintenance, end_maintenance};

/// The most rows one retention call deletes.
const PURGE_BATCH: i64 = 5000;

#[async_trait]
impl SystemTenantRepo for PgSystemTx {
    async fn get(&mut self, id: TenantId) -> Result<Tenant, StoreError> {
        observed!("tenants.get", {
            let row =
                sqlx::query_as::<_, TenantRow>(concat!("SELECT ", tenant_columns!(""), " FROM tenants WHERE id = $1"))
                    .bind(id.as_uuid())
                    .fetch_optional(&mut *self.conn)
                    .await
                    .db()?;
            row.ok_or(StoreError::NotFound)?.into_tenant()
        })
    }

    async fn find_by_slug(&mut self, slug: &TenantSlug) -> Result<Option<Tenant>, StoreError> {
        observed!("tenants.find_by_slug", {
            let row = sqlx::query_as::<_, TenantRow>(concat!(
                "SELECT ",
                tenant_columns!(""),
                " FROM tenants WHERE slug = $1"
            ))
            .bind(slug.as_str())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.map(TenantRow::into_tenant).transpose()
        })
    }

    async fn find_by_login_domain(&mut self, domain: &DomainName) -> Result<Option<Tenant>, StoreError> {
        observed!("tenants.find_by_login_domain", {
            let row = sqlx::query_as::<_, TenantRow>(concat!(
                "SELECT ",
                tenant_columns!(""),
                " FROM tenants WHERE lower(login_domain) = lower($1)"
            ))
            .bind(domain.as_str())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.map(TenantRow::into_tenant).transpose()
        })
    }

    async fn list(&mut self, page: PageReq) -> Result<StorePage<Tenant>, StoreError> {
        observed!("tenants.list", {
            let rows = sqlx::query_as::<_, TenantRow>(concat!(
                "SELECT ",
                tenant_columns!(""),
                " FROM tenants WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2"
            ))
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let tenants = rows
                .into_iter()
                .map(TenantRow::into_tenant)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(tenants, &page, |tenant| {
                tenant.id.as_uuid()
            }))
        })
    }

    async fn create(&mut self, tenant: Tenant) -> Result<Tenant, StoreError> {
        observed!("tenants.create", {
            let now = micros(self.clock.now());
            let settings = serde_json::to_value(&tenant.settings)
                .map_err(|error| StoreError::internal(format!("tenant settings cannot be serialized: {error}")))?;
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, TenantRow>(concat!(
                        "INSERT INTO tenants (id, slug, display_name, login_domain, status, settings, created_at, \
                         updated_at, version) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 1) RETURNING ",
                        tenant_columns!("")
                    ))
                    .bind(tenant.id.as_uuid())
                    .bind(tenant.slug.as_str())
                    .bind(&tenant.display_name)
                    .bind(tenant.login_domain.as_ref().map(DomainName::as_str))
                    .bind(tenant.status.as_str())
                    .bind(settings)
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    row.into_tenant()
                })
            })
            .await
        })
    }

    async fn update(&mut self, tenant: Tenant, expected_version: i64) -> Result<Tenant, StoreError> {
        observed!("tenants.update", {
            let now = micros(self.clock.now());
            let settings = serde_json::to_value(&tenant.settings)
                .map_err(|error| StoreError::internal(format!("tenant settings cannot be serialized: {error}")))?;
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, TenantRow>(concat!(
                        "UPDATE tenants SET display_name = $2, login_domain = $3, status = $4, settings = $5, \
                         updated_at = $6, version = version + 1 WHERE id = $1 AND version = $7 RETURNING ",
                        tenant_columns!("")
                    ))
                    .bind(tenant.id.as_uuid())
                    .bind(&tenant.display_name)
                    .bind(tenant.login_domain.as_ref().map(DomainName::as_str))
                    .bind(tenant.status.as_str())
                    .bind(settings)
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    match row {
                        Some(row) => row.into_tenant(),
                        None => Err(stale_or_missing_global(
                            conn,
                            "SELECT 1 FROM tenants WHERE id = $1",
                            tenant.id.as_uuid(),
                        )
                        .await),
                    }
                })
            })
            .await
        })
    }

    async fn delete(&mut self, id: TenantId) -> Result<(), StoreError> {
        observed!("tenants.delete", {
            let maintenance = self.maintenance_timeout;
            self.guarded(move |conn| {
                Box::pin(async move {
                    // The cascade reaches every row of the tenant, which can take longer than a request may.
                    let previous = begin_maintenance(conn, maintenance).await?;
                    let removed = sqlx::query("DELETE FROM tenants WHERE id = $1")
                        .bind(id.as_uuid())
                        .execute(&mut *conn)
                        .await
                        .db()?
                        .rows_affected();
                    if removed == 0 {
                        return Err(StoreError::NotFound);
                    }
                    end_maintenance(conn, &previous).await
                })
            })
            .await
        })
    }

    async fn append_audit(&mut self, tenant: TenantId, entry: NewTenantAudit) -> Result<(), StoreError> {
        observed!("tenants.append_audit", {
            let record = AuditEvent::from(entry.event).record();
            let actor = serde_json::to_value(&entry.actor)
                .map_err(|error| StoreError::internal(format!("audit actor cannot be serialized: {error}")))?;
            let now = micros(self.clock.now());
            self.guarded(move |conn| {
                Box::pin(async move {
                    // The row is selected from the tenant, so a tenant that does not exist inserts nothing (the audit
                    // log has no foreign key to it on purpose). The policy of the table admits system scope for the
                    // two tenant events only; any other action is refused by it.
                    let done = sqlx::query(
                        "INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at) \
                         SELECT t.id, $2, $3, $4, $5, $6, $7 FROM tenants t WHERE t.id = $1",
                    )
                    .bind(tenant.as_uuid())
                    .bind(entry.id)
                    .bind(actor)
                    .bind(record.action)
                    .bind(record.target)
                    .bind(record.details)
                    .bind(now)
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    if done.rows_affected() == 0 {
                        return Err(StoreError::NotFound);
                    }
                    Ok(())
                })
            })
            .await
        })
    }

    async fn bump_sync_epoch(&mut self, tenant: Option<TenantId>) -> Result<u64, StoreError> {
        observed!("tenants.bump_sync_epoch", {
            let epoch = self.ids.new_id();
            let scope = tenant.map(TenantId::as_uuid);
            let maintenance = self.maintenance_timeout;
            self.guarded(move |conn| {
                Box::pin(async move {
                    // One UPDATE over every calendar and principal of the installation after a restore.
                    let previous = begin_maintenance(conn, maintenance).await?;
                    if let Some(scope) = scope {
                        let exists = sqlx::query_scalar::<_, i32>("SELECT 1 FROM tenants WHERE id = $1")
                            .bind(scope)
                            .fetch_optional(&mut *conn)
                            .await
                            .db()?;
                        if exists.is_none() {
                            return Err(StoreError::NotFound);
                        }
                    }
                    let calendars =
                        sqlx::query("UPDATE calendars SET sync_epoch = $1 WHERE ($2::uuid IS NULL OR tenant_id = $2)")
                            .bind(epoch)
                            .bind(scope)
                            .execute(&mut *conn)
                            .await
                            .db()?
                            .rows_affected();
                    let principals = sqlx::query(
                        "UPDATE principals_sync SET home_epoch = $1, inbox_epoch = $1, notifications_epoch = $1 \
                         WHERE ($2::uuid IS NULL OR tenant_id = $2)",
                    )
                    .bind(epoch)
                    .bind(scope)
                    .execute(&mut *conn)
                    .await
                    .db()?
                    .rows_affected();
                    end_maintenance(conn, &previous).await?;
                    // A principal row holds three collections: the home, the inbox and the notifications.
                    Ok(calendars + principals * 3)
                })
            })
            .await
        })
    }
}

/// The facts of a credential that authentication needs besides the secret.
#[derive(sqlx::FromRow)]
struct LookupFacts {
    tenant_status: Option<String>,
    principal_status: Option<String>,
    credential_generation: Option<i32>,
    tenant_slug: Option<String>,
    login_domain: Option<String>,
    principal_name: Option<String>,
}

impl LookupFacts {
    fn into_looked_up(self, record: CredentialRecord) -> Result<LookedUpCredential, StoreError> {
        Ok(LookedUpCredential {
            record,
            tenant_status: self
                .tenant_status
                .as_deref()
                .map(|status| decode("tenant status", status.parse::<TenantStatus>()))
                .transpose()?,
            principal_status: self
                .principal_status
                .as_deref()
                .map(|status| decode("principal status", status.parse::<PrincipalStatus>()))
                .transpose()?,
            credential_generation: self.credential_generation,
            owner: self
                .tenant_slug
                .as_deref()
                .map(|slug| {
                    Ok(CredentialOwner {
                        tenant_slug: decode("tenant slug", TenantSlug::parse(slug))?,
                        login_domain: decode_opt("login domain", self.login_domain.as_deref(), DomainName::parse)?,
                        principal_name: decode_opt(
                            "principal name",
                            self.principal_name.as_deref(),
                            PrincipalName::parse,
                        )?,
                    })
                })
                .transpose()?,
        })
    }
}

/// An app password with its facts.
#[derive(sqlx::FromRow)]
struct LookedAppPassword {
    #[sqlx(flatten)]
    row: AppPasswordRow,
    #[sqlx(flatten)]
    facts: LookupFacts,
}

/// An API token with its facts.
#[derive(sqlx::FromRow)]
struct LookedApiToken {
    #[sqlx(flatten)]
    row: ApiTokenRow,
    #[sqlx(flatten)]
    facts: LookupFacts,
}

/// A feed token with its facts.
#[derive(sqlx::FromRow)]
struct LookedFeedToken {
    #[sqlx(flatten)]
    row: FeedTokenRow,
    #[sqlx(flatten)]
    facts: LookupFacts,
}

/// An RSVP token with its facts.
#[derive(sqlx::FromRow)]
struct LookedRsvpToken {
    #[sqlx(flatten)]
    row: RsvpTokenRow,
    #[sqlx(flatten)]
    facts: LookupFacts,
}

#[async_trait]
impl CredentialLookup for PgSystemTx {
    async fn find_by_prefix(
        &mut self,
        kind: CredentialKind,
        prefix: &str,
    ) -> Result<Option<LookedUpCredential>, StoreError> {
        observed!("credentials.find_by_prefix", {
            match kind {
                CredentialKind::AppPassword => {
                    let found = sqlx::query_as::<_, LookedAppPassword>(concat!(
                        "SELECT ",
                        app_password_columns!("a."),
                        ", t.status AS tenant_status, p.status AS principal_status, \
                         p.credential_generation AS credential_generation, t.slug AS tenant_slug, \
                         t.login_domain AS login_domain, p.name AS principal_name \
                         FROM app_passwords a JOIN tenants t ON t.id = a.tenant_id \
                         JOIN principals p ON p.tenant_id = a.tenant_id AND p.id = a.principal_id \
                         WHERE a.prefix = $1"
                    ))
                    .bind(prefix)
                    .fetch_optional(&mut *self.conn)
                    .await
                    .db()?;
                    found
                        .map(|found| {
                            let record = CredentialRecord::AppPassword(Box::new(found.row.into_password()));
                            found.facts.into_looked_up(record)
                        })
                        .transpose()
                }
                CredentialKind::ApiToken => {
                    let found = sqlx::query_as::<_, LookedApiToken>(concat!(
                        "SELECT ",
                        api_token_columns!("a."),
                        ", t.status AS tenant_status, p.status AS principal_status, \
                         p.credential_generation AS credential_generation, t.slug AS tenant_slug, \
                         t.login_domain AS login_domain, p.name AS principal_name \
                         FROM api_tokens a LEFT JOIN tenants t ON t.id = a.tenant_id \
                         LEFT JOIN principals p ON p.tenant_id = a.tenant_id AND p.id = a.principal_id \
                         WHERE a.prefix = $1"
                    ))
                    .bind(prefix)
                    .fetch_optional(&mut *self.conn)
                    .await
                    .db()?;
                    found
                        .map(|found| {
                            let record = CredentialRecord::ApiToken(Box::new(found.row.into_token()?));
                            found.facts.into_looked_up(record)
                        })
                        .transpose()
                }
                CredentialKind::FeedToken => {
                    let found = sqlx::query_as::<_, LookedFeedToken>(concat!(
                        "SELECT ",
                        feed_token_columns!("a."),
                        ", t.status AS tenant_status, p.status AS principal_status, \
                         p.credential_generation AS credential_generation, t.slug AS tenant_slug, \
                         t.login_domain AS login_domain, p.name AS principal_name \
                         FROM feed_tokens a JOIN tenants t ON t.id = a.tenant_id \
                         JOIN principals p ON p.tenant_id = a.tenant_id AND p.id = a.principal_id \
                         WHERE a.prefix = $1"
                    ))
                    .bind(prefix)
                    .fetch_optional(&mut *self.conn)
                    .await
                    .db()?;
                    found
                        .map(|found| {
                            let record = CredentialRecord::FeedToken(Box::new(found.row.into_token()?));
                            found.facts.into_looked_up(record)
                        })
                        .transpose()
                }
                CredentialKind::RsvpToken => {
                    let found = sqlx::query_as::<_, LookedRsvpToken>(concat!(
                        "SELECT ",
                        rsvp_token_columns!("a."),
                        ", t.status AS tenant_status, NULL::text AS principal_status, \
                         NULL::integer AS credential_generation, t.slug AS tenant_slug, \
                         t.login_domain AS login_domain, NULL::text AS principal_name \
                         FROM rsvp_tokens a JOIN tenants t ON t.id = a.tenant_id \
                         WHERE a.prefix = $1"
                    ))
                    .bind(prefix)
                    .fetch_optional(&mut *self.conn)
                    .await
                    .db()?;
                    found
                        .map(|found| {
                            let record = CredentialRecord::RsvpToken(Box::new(found.row.into_token()?));
                            found.facts.into_looked_up(record)
                        })
                        .transpose()
                }
            }
        })
    }

    async fn create_system_token(&mut self, token: ApiToken) -> Result<ApiToken, StoreError> {
        observed!("credentials.create_system_token", {
            if token.kind != TokenKind::System {
                return Err(misuse("only system tokens are created through the credential lookup"));
            }
            let now = micros(self.clock.now());
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, ApiTokenRow>(concat!(
                        "INSERT INTO api_tokens (tenant_id, id, kind, principal_id, label, scopes, prefix, hash, \
                         pepper_kid, expires_at, created_by, allowed_origins, last_used_at, revoked_at, created_at, \
                         updated_at, version) \
                         VALUES (NULL, $1, 'system', NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, 1) \
                         RETURNING ",
                        api_token_columns!("")
                    ))
                    .bind(token.id.as_uuid())
                    .bind(&token.label)
                    .bind(token.scopes.to_strings())
                    .bind(&token.prefix)
                    .bind(&token.hash)
                    .bind(&token.pepper_kid)
                    .bind(token.expires_at.map(micros))
                    .bind(token.created_by.map(TokenId::as_uuid))
                    .bind(&token.allowed_origins)
                    .bind(token.last_used_at.map(micros))
                    .bind(token.revoked_at.map(micros))
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    row.into_token()
                })
            })
            .await
        })
    }

    async fn list_system_tokens(&mut self) -> Result<Vec<ApiToken>, StoreError> {
        observed!("credentials.list_system_tokens", {
            let rows = sqlx::query_as::<_, ApiTokenRow>(concat!(
                "SELECT ",
                api_token_columns!(""),
                " FROM api_tokens WHERE kind = 'system' ORDER BY id"
            ))
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            rows.into_iter().map(ApiTokenRow::into_token).collect()
        })
    }

    async fn revoke_system_token(&mut self, id: TokenId) -> Result<(), StoreError> {
        observed!("credentials.revoke_system_token", {
            let now = micros(self.clock.now());
            self.guarded(move |conn| {
                Box::pin(async move {
                    let changed = sqlx::query(
                        "UPDATE api_tokens SET revoked_at = $2, updated_at = $2, version = version + 1 \
                         WHERE id = $1 AND kind = 'system' AND revoked_at IS NULL",
                    )
                    .bind(id.as_uuid())
                    .bind(now)
                    .execute(&mut *conn)
                    .await
                    .db()?
                    .rows_affected();
                    if changed > 0 {
                        return Ok(());
                    }
                    let exists =
                        sqlx::query_scalar::<_, i32>("SELECT 1 FROM api_tokens WHERE id = $1 AND kind = 'system'")
                            .bind(id.as_uuid())
                            .fetch_optional(&mut *conn)
                            .await
                            .db()?;
                    exists.map(|_| ()).ok_or(StoreError::NotFound)
                })
            })
            .await
        })
    }
}

/// The error of a settle that matched no `in_flight` record (or, for a fenced settle, no record of that claim):
/// `NotFound` when the record does not exist, `LeaseLost` when it exists but was settled, released or reclaimed by
/// someone else.
async fn unsettled(conn: &mut PgConnection, key: OutboxKey) -> StoreError {
    match sqlx::query_scalar::<_, i32>("SELECT 1 FROM outbox WHERE tenant_id = $1 AND id = $2")
        .bind(key.tenant.as_uuid())
        .bind(key.id.as_uuid())
        .fetch_optional(&mut *conn)
        .await
    {
        Ok(Some(_)) => StoreError::LeaseLost,
        Ok(None) => StoreError::NotFound,
        Err(error) => map_sqlx(error),
    }
}

/// The values of a claim that fence a settle: the attempt number and the lease end the claim wrote. `None` for the
/// unfenced settle, which only requires the record to be in flight.
type Fence = Option<(i32, DateTime<Utc>)>;

/// The fence of a claim.
fn fence_of(claim: &OutboxClaim) -> Result<Fence, StoreError> {
    let attempt = i32::try_from(claim.attempt).map_err(|_| StoreError::internal("an attempt number is too large"))?;
    Ok(Some((attempt, micros(claim.locked_until))))
}

impl PgSystemTx {
    /// Marks a record done while it is in flight (and, with a fence, still held by that claim).
    async fn settle_done(&mut self, key: OutboxKey, fence: Fence) -> Result<(), StoreError> {
        let now = micros(self.clock.now());
        self.guarded(move |conn| {
            Box::pin(async move {
                let changed = sqlx::query(
                    "UPDATE outbox SET status = 'done', locked_until = NULL, updated_at = $3 \
                     WHERE tenant_id = $1 AND id = $2 AND status = 'in_flight' \
                       AND ($4::int IS NULL OR (attempts = $4 AND locked_until = $5))",
                )
                .bind(key.tenant.as_uuid())
                .bind(key.id.as_uuid())
                .bind(now)
                .bind(fence.map(|(attempt, _)| attempt))
                .bind(fence.map(|(_, until)| until))
                .execute(&mut *conn)
                .await
                .db()?
                .rows_affected();
                if changed == 0 {
                    Err(unsettled(conn, key).await)
                } else {
                    Ok(())
                }
            })
        })
        .await
    }

    /// Puts a record back for later while it is in flight (and, with a fence, still held by that claim). Nothing
    /// was attempted, so the claim does not count.
    async fn settle_deferred(
        &mut self,
        key: OutboxKey,
        until: DateTime<Utc>,
        note: &str,
        fence: Fence,
    ) -> Result<(), StoreError> {
        let now = micros(self.clock.now());
        let until = micros(until);
        let note = note.to_owned();
        self.guarded(move |conn| {
            Box::pin(async move {
                let changed = sqlx::query(
                    "UPDATE outbox SET status = 'pending', next_attempt_at = $3, locked_until = NULL, \
                     attempts = GREATEST(attempts - 1, 0), last_error = $4, updated_at = $5 \
                     WHERE tenant_id = $1 AND id = $2 AND status = 'in_flight' \
                       AND ($6::int IS NULL OR (attempts = $6 AND locked_until = $7))",
                )
                .bind(key.tenant.as_uuid())
                .bind(key.id.as_uuid())
                .bind(until)
                .bind(&note)
                .bind(now)
                .bind(fence.map(|(attempt, _)| attempt))
                .bind(fence.map(|(_, until)| until))
                .execute(&mut *conn)
                .await
                .db()?
                .rows_affected();
                if changed == 0 {
                    Err(unsettled(conn, key).await)
                } else {
                    Ok(())
                }
            })
        })
        .await
    }

    /// Records a failed attempt while the record is in flight (and, with a fence, still held by that claim).
    async fn settle_failed(&mut self, key: OutboxKey, failure: OutboxFailure, fence: Fence) -> Result<(), StoreError> {
        let now = micros(self.clock.now());
        self.guarded(move |conn| {
            Box::pin(async move {
                let changed = sqlx::query(
                    "UPDATE outbox SET status = CASE WHEN $4::timestamptz IS NULL THEN 'dead' ELSE 'pending' END, \
                     next_attempt_at = COALESCE($4::timestamptz, next_attempt_at), locked_until = NULL, \
                     last_error = $5, updated_at = $3 \
                     WHERE tenant_id = $1 AND id = $2 AND status = 'in_flight' \
                       AND ($6::int IS NULL OR (attempts = $6 AND locked_until = $7))",
                )
                .bind(key.tenant.as_uuid())
                .bind(key.id.as_uuid())
                .bind(now)
                .bind(failure.retry_at.map(micros))
                .bind(&failure.error)
                .bind(fence.map(|(attempt, _)| attempt))
                .bind(fence.map(|(_, until)| until))
                .execute(&mut *conn)
                .await
                .db()?
                .rows_affected();
                if changed == 0 {
                    Err(unsettled(conn, key).await)
                } else {
                    Ok(())
                }
            })
        })
        .await
    }

    /// Hands the given leases back (the attempt that never finished is not counted). With fences only the leases
    /// that are still the claim's are released.
    async fn release_held(&mut self, held: Vec<(OutboxKey, Fence)>) -> Result<u64, StoreError> {
        let now = micros(self.clock.now());
        let tenants: Vec<Uuid> = held.iter().map(|(key, _)| key.tenant.as_uuid()).collect();
        let ids: Vec<Uuid> = held.iter().map(|(key, _)| key.id.as_uuid()).collect();
        let attempts: Vec<Option<i32>> = held
            .iter()
            .map(|(_, fence)| fence.map(|(attempt, _)| attempt))
            .collect();
        let untils: Vec<Option<DateTime<Utc>>> = held.iter().map(|(_, fence)| fence.map(|(_, until)| until)).collect();
        self.guarded(move |conn| {
            Box::pin(async move {
                Ok(sqlx::query(
                    "UPDATE outbox o SET status = 'pending', locked_until = NULL, next_attempt_at = $3, \
                     attempts = GREATEST(o.attempts - 1, 0), updated_at = $3 \
                     FROM unnest($1::uuid[], $2::uuid[], $4::int[], $5::timestamptz[]) \
                          AS h(tenant_id, id, attempts, locked_until) \
                     WHERE o.tenant_id = h.tenant_id AND o.id = h.id AND o.status = 'in_flight' \
                       AND (h.attempts IS NULL OR (o.attempts = h.attempts AND o.locked_until = h.locked_until))",
                )
                .bind(&tenants)
                .bind(&ids)
                .bind(now)
                .bind(&attempts)
                .bind(&untils)
                .execute(&mut *conn)
                .await
                .db()?
                .rows_affected())
            })
        })
        .await
    }
}

#[async_trait]
impl OutboxQueue for PgSystemTx {
    async fn claim(&mut self, limit: u32, lease: Duration) -> Result<Vec<OutboxRecord>, StoreError> {
        observed!("outbox.claim", {
            let now = micros(self.clock.now());
            let until = micros(lease_end(now, lease));
            let take = i64::from(limit.min(davhaven_ports::store::MAX_PAGE_LIMIT));
            let rows = self
                .guarded(move |conn| {
                    Box::pin(async move {
                        sqlx::query_as::<_, OutboxRow>(concat!(
                            "WITH due AS ( \
                               SELECT tenant_id, id FROM outbox \
                               WHERE (status = 'pending' AND next_attempt_at <= $1) \
                                  OR (status = 'in_flight' AND locked_until <= $1) \
                               ORDER BY next_attempt_at, id LIMIT $2 FOR UPDATE SKIP LOCKED) \
                             UPDATE outbox o SET status = 'in_flight', locked_until = $3, attempts = o.attempts + 1, \
                               updated_at = $1 \
                             FROM due WHERE o.tenant_id = due.tenant_id AND o.id = due.id \
                             RETURNING ",
                            outbox_columns!("o.")
                        ))
                        .bind(now)
                        .bind(take)
                        .bind(until)
                        .fetch_all(&mut *conn)
                        .await
                        .db()
                    })
                })
                .await?;
            let mut records = rows
                .into_iter()
                .map(OutboxRow::into_record)
                .collect::<Result<Vec<_>, _>>()?;
            records.sort_by_key(|record| (record.next_attempt_at, record.id));
            Ok(records)
        })
    }

    async fn complete(&mut self, key: OutboxKey) -> Result<(), StoreError> {
        observed!("outbox.complete", self.settle_done(key, None).await)
    }

    async fn fail(&mut self, key: OutboxKey, failure: OutboxFailure) -> Result<(), StoreError> {
        observed!("outbox.fail", self.settle_failed(key, failure, None).await)
    }

    async fn complete_claimed(&mut self, claim: OutboxClaim) -> Result<(), StoreError> {
        observed!("outbox.complete_claimed", {
            let fence = fence_of(&claim)?;
            self.settle_done(claim.key, fence).await
        })
    }

    async fn fail_claimed(&mut self, claim: OutboxClaim, failure: OutboxFailure) -> Result<(), StoreError> {
        observed!("outbox.fail_claimed", {
            let fence = fence_of(&claim)?;
            self.settle_failed(claim.key, failure, fence).await
        })
    }

    async fn defer_claimed(&mut self, claim: OutboxClaim, until: DateTime<Utc>, note: &str) -> Result<(), StoreError> {
        observed!("outbox.defer_claimed", {
            let fence = fence_of(&claim)?;
            self.settle_deferred(claim.key, until, note, fence).await
        })
    }

    async fn release_leases(&mut self, held: &[OutboxKey]) -> Result<u64, StoreError> {
        observed!("outbox.release_leases", {
            self.release_held(held.iter().map(|key| (*key, None)).collect()).await
        })
    }

    async fn release_claimed(&mut self, held: &[OutboxClaim]) -> Result<u64, StoreError> {
        observed!("outbox.release_claimed", {
            let held = held
                .iter()
                .map(|claim| fence_of(claim).map(|fence| (claim.key, fence)))
                .collect::<Result<Vec<_>, _>>()?;
            self.release_held(held).await
        })
    }

    async fn stats(&mut self) -> Result<OutboxStats, StoreError> {
        observed!("outbox.stats", {
            let rows = sqlx::query_as::<_, (String, i64, Option<DateTime<Utc>>)>(
                "SELECT status, count(*), min(next_attempt_at) FROM outbox \
                 WHERE status IN ('pending', 'in_flight', 'dead') GROUP BY status",
            )
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let mut stats = OutboxStats::default();
            for (status, count, oldest) in rows {
                match status.as_str() {
                    "pending" => {
                        stats.pending = to_u64(count)?;
                        stats.oldest_pending_at = oldest;
                    }
                    "in_flight" => stats.in_flight = to_u64(count)?,
                    "dead" => stats.dead = to_u64(count)?,
                    other => return Err(corrupt("outbox status", other)),
                }
            }
            Ok(stats)
        })
    }
}

/// Deletes in a batch with `sql` (`$1` and `$2` are the cut-offs or the single cut-off, the last parameter the
/// batch size) and returns how many rows were removed.
async fn delete_batch(
    conn: &mut PgConnection,
    sql: &'static str,
    first: DateTime<Utc>,
    second: Option<DateTime<Utc>>,
) -> Result<u64, StoreError> {
    delete_limited(conn, sql, first, second, PURGE_BATCH).await
}

/// [`delete_batch`] with an explicit row limit.
async fn delete_limited(
    conn: &mut PgConnection,
    sql: &'static str,
    first: DateTime<Utc>,
    second: Option<DateTime<Utc>>,
    limit: i64,
) -> Result<u64, StoreError> {
    let mut query = sqlx::query(sql).bind(first);
    if let Some(second) = second {
        query = query.bind(second);
    }
    Ok(query.bind(limit).execute(&mut *conn).await.db()?.rows_affected())
}

/// One principal's expired inbox items: every id to delete, and the names of the delivered ones, whose deletion is
/// logged (a quarantined item was never shown to clients, so its expiry is not a change of the inbox).
struct ExpiredInbox {
    tenant: Uuid,
    principal: Uuid,
    ids: Vec<Uuid>,
    uris: Vec<String>,
}

/// Groups the rows of the expired-items query by principal (tenant and principal order). The query orders by age,
/// which the `created_at` index serves; within a principal the rows keep that order, so the deletions are logged in
/// the order the items were created.
fn group_expired(rows: Vec<(Uuid, Uuid, Uuid, String, bool)>) -> Vec<ExpiredInbox> {
    let mut groups: BTreeMap<(Uuid, Uuid), ExpiredInbox> = BTreeMap::new();
    for (tenant, principal, id, uri, quarantined) in rows {
        let logged = (!quarantined).then_some(uri);
        let group = groups.entry((tenant, principal)).or_insert_with(|| ExpiredInbox {
            tenant,
            principal,
            ids: Vec::new(),
            uris: Vec::new(),
        });
        group.ids.push(id);
        group.uris.extend(logged);
    }
    groups.into_values().collect()
}

/// Deletes one principal's expired inbox items and logs the deletions in the principal's inbox change log.
async fn purge_inbox_of(conn: &mut PgConnection, group: &ExpiredInbox, now: DateTime<Utc>) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM scheduling_inbox WHERE tenant_id = $1 AND id = ANY($2)")
        .bind(group.tenant)
        .bind(&group.ids)
        .execute(&mut *conn)
        .await
        .db()?;
    if group.uris.is_empty() {
        return Ok(());
    }
    let count = i64::try_from(group.uris.len()).unwrap_or(i64::MAX);
    let last = sqlx::query_scalar::<_, i64>(
        "UPDATE principals_sync SET inbox_seq = inbox_seq + $3 \
         WHERE tenant_id = $1 AND principal_id = $2 RETURNING inbox_seq",
    )
    .bind(group.tenant)
    .bind(group.principal)
    .bind(count)
    .fetch_optional(&mut *conn)
    .await
    .db()?;
    let Some(last) = last else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO collection_changes (tenant_id, collection_kind, collection_id, seq, uri, kind, at) \
         SELECT $1, 'inbox', $2, $3 + u.position, u.uri, 'delete', $4 \
         FROM unnest($5::text[]) WITH ORDINALITY AS u(uri, position)",
    )
    .bind(group.tenant)
    .bind(group.principal)
    .bind(last - count)
    .bind(now)
    .bind(&group.uris)
    .execute(&mut *conn)
    .await
    .db()?;
    Ok(())
}

/// `insufficient_privilege`: the runtime role is not allowed to call `davhaven_purge_audit`.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// Whether the error says the role lacks the privilege to call the audit purge.
fn is_missing_audit_privilege(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database) if database.code().as_deref() == Some(INSUFFICIENT_PRIVILEGE))
}

impl PgSystemTx {
    /// Runs one batch of the audit purge, or reports that this role may not. The function is deliberately not
    /// granted to the runtime role (the audit log is append-only for a compromised server), so the answer in the
    /// supported setup is [`AuditPurge::NotPermitted`], which is a state of the deployment (the purge is a job
    /// outside the server), not an error.
    async fn run_audit_purge(&mut self, before: DateTime<Utc>) -> Result<AuditPurge, StoreError> {
        let permitted = sqlx::query_scalar::<_, bool>(
            "SELECT has_function_privilege('davhaven_purge_audit(timestamptz, integer)', 'EXECUTE')",
        )
        .fetch_one(&mut *self.conn)
        .await
        .db()?;
        if !permitted {
            return Ok(AuditPurge::NotPermitted);
        }
        let outcome = self
            .guarded(move |conn| {
                Box::pin(async move {
                    match sqlx::query_scalar::<_, i64>("SELECT davhaven_purge_audit($1, $2)")
                        .bind(before)
                        .bind(i32::try_from(PURGE_BATCH).unwrap_or(i32::MAX))
                        .fetch_one(&mut *conn)
                        .await
                    {
                        Ok(removed) => Ok(Some(removed)),
                        Err(error) if is_missing_audit_privilege(&error) => Ok(None),
                        Err(error) => Err(map_sqlx(error)),
                    }
                })
            })
            .await?;
        match outcome {
            Some(removed) => Ok(AuditPurge::Purged(to_u64(removed)?)),
            None => Ok(AuditPurge::NotPermitted),
        }
    }
}

#[async_trait]
impl RetentionRepo for PgSystemTx {
    async fn purge_outbox(
        &mut self,
        done_before: DateTime<Utc>,
        dead_before: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        observed!("retention.purge_outbox", {
            let (done, dead) = (micros(done_before), micros(dead_before));
            self.guarded(move |conn| {
                Box::pin(async move {
                    delete_batch(
                        conn,
                        "WITH doomed AS (SELECT tenant_id, id FROM outbox \
                           WHERE (status = 'done' AND updated_at < $1) OR (status = 'dead' AND updated_at < $2) \
                           LIMIT $3) \
                         DELETE FROM outbox o USING doomed d WHERE o.tenant_id = d.tenant_id AND o.id = d.id",
                        done,
                        Some(dead),
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn prune_changes(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.prune_changes", {
            let before = micros(before);
            let pruned = self
                .guarded(move |conn| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, i64>(
                            "WITH doomed AS ( \
                               SELECT tenant_id, collection_kind, collection_id, seq FROM collection_changes \
                               WHERE at < $1 ORDER BY at LIMIT $2), \
                             pruned AS ( \
                               DELETE FROM collection_changes c USING doomed d \
                               WHERE c.tenant_id = d.tenant_id AND c.collection_kind = d.collection_kind \
                                 AND c.collection_id = d.collection_id AND c.seq = d.seq \
                               RETURNING c.tenant_id, c.collection_kind, c.collection_id, c.seq), \
                             agg AS ( \
                               SELECT tenant_id, collection_kind, collection_id, max(seq) AS max_seq, count(*) AS n \
                               FROM pruned GROUP BY tenant_id, collection_kind, collection_id), \
                             cal AS ( \
                               UPDATE calendars x SET sync_min_seq = GREATEST(x.sync_min_seq, a.max_seq) FROM agg a \
                               WHERE a.collection_kind = 'calendar' AND x.tenant_id = a.tenant_id \
                                 AND x.id = a.collection_id RETURNING 1), \
                             per_principal AS ( \
                               SELECT tenant_id, collection_id AS principal_id, \
                                      max(max_seq) FILTER (WHERE collection_kind = 'home') AS home_seq, \
                                      max(max_seq) FILTER (WHERE collection_kind = 'inbox') AS inbox_seq, \
                                      max(max_seq) FILTER (WHERE collection_kind = 'notifications') AS notes_seq \
                               FROM agg WHERE collection_kind <> 'calendar' \
                               GROUP BY tenant_id, collection_id), \
                             principal_updates AS ( \
                               UPDATE principals_sync x SET \
                                 home_min_seq = GREATEST(x.home_min_seq, COALESCE(p.home_seq, 0)), \
                                 inbox_min_seq = GREATEST(x.inbox_min_seq, COALESCE(p.inbox_seq, 0)), \
                                 notifications_min_seq = GREATEST(x.notifications_min_seq, COALESCE(p.notes_seq, 0)) \
                               FROM per_principal p WHERE x.tenant_id = p.tenant_id \
                                 AND x.principal_id = p.principal_id RETURNING 1) \
                             SELECT COALESCE(sum(n), 0)::bigint FROM agg",
                        )
                        .bind(before)
                        .bind(PURGE_BATCH)
                        .fetch_one(&mut *conn)
                        .await
                        .db()
                    })
                })
                .await?;
            to_u64(pruned)
        })
    }

    async fn purge_audit(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_audit", {
            Ok(match self.run_audit_purge(micros(before)).await? {
                AuditPurge::Purged(removed) => removed,
                AuditPurge::NotPermitted => 0,
            })
        })
    }

    async fn purge_audit_checked(&mut self, before: DateTime<Utc>) -> Result<AuditPurge, StoreError> {
        observed!(
            "retention.purge_audit_checked",
            self.run_audit_purge(micros(before)).await
        )
    }

    async fn oldest_audit_at(&mut self) -> Result<Option<DateTime<Utc>>, StoreError> {
        observed!("retention.oldest_audit_at", {
            // The first row of `audit_events_at_idx`: a scan of that index with a limit of one, which is what the planner chooses for
            // an ordered read of one row (the test of the plan turns sequential scans off). It crosses tenants, which
            // the policy `system_scope_select` of the table admits for a system transaction and for no other.
            sqlx::query_scalar::<_, DateTime<Utc>>("SELECT at FROM audit_events ORDER BY at LIMIT 1")
                .fetch_optional(&mut *self.conn)
                .await
                .db()
        })
    }

    async fn purge_deliveries(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_deliveries", {
            let before = micros(before);
            self.guarded(move |conn| {
                Box::pin(async move {
                    delete_batch(
                        conn,
                        "WITH doomed AS (SELECT tenant_id, id FROM webhook_deliveries WHERE created_at < $1 LIMIT $2) \
                         DELETE FROM webhook_deliveries w USING doomed d WHERE w.tenant_id = d.tenant_id AND w.id = d.id",
                        before,
                        None,
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn purge_inbox(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_inbox", {
            let before = micros(before);
            let now = micros(self.clock.now());
            self.guarded(move |conn| {
                Box::pin(async move {
                    let rows = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, bool)>(
                        "SELECT tenant_id, principal_id, id, uri, quarantined FROM scheduling_inbox WHERE created_at < $1 \
                         ORDER BY created_at, id LIMIT $2",
                    )
                    .bind(before)
                    .bind(PURGE_BATCH)
                    .fetch_all(&mut *conn)
                    .await
                    .db()?;
                    let removed = u64::try_from(rows.len()).unwrap_or(u64::MAX);
                    for group in group_expired(rows) {
                        purge_inbox_of(conn, &group, now).await?;
                    }
                    Ok(removed)
                })
            })
            .await
        })
    }

    async fn purge_idempotency(&mut self) -> Result<u64, StoreError> {
        observed!("retention.purge_idempotency", {
            let now = micros(self.clock.now());
            self.guarded(move |conn| {
                Box::pin(async move {
                    delete_batch(
                        conn,
                        "WITH doomed AS (SELECT tenant_id, id FROM idempotency_keys WHERE expires_at <= $1 LIMIT $2) \
                         DELETE FROM idempotency_keys k USING doomed d WHERE k.tenant_id = d.tenant_id AND k.id = d.id",
                        now,
                        None,
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn purge_oauth_states(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_oauth_states", {
            let before = micros(before);
            self.guarded(move |conn| {
                Box::pin(async move {
                    delete_batch(
                        conn,
                        "WITH doomed AS (SELECT tenant_id, id FROM oauth_states WHERE expires_at < $1 LIMIT $2) \
                         DELETE FROM oauth_states s USING doomed d WHERE s.tenant_id = d.tenant_id AND s.id = d.id",
                        before,
                        None,
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn purge_rsvp_tokens(&mut self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        observed!("retention.purge_rsvp_tokens", {
            let before = micros(before);
            self.guarded(move |conn| {
                Box::pin(async move {
                    // Two statements instead of `expires_at < $1 OR revoked_at < $1`: each one is served by its own
                    // index (`expires_at`, and the partial index on `revoked_at`) where the OR scans the table.
                    let expired = delete_batch(
                        conn,
                        "WITH doomed AS (SELECT tenant_id, id FROM rsvp_tokens WHERE expires_at < $1 LIMIT $2) \
                         DELETE FROM rsvp_tokens r USING doomed d WHERE r.tenant_id = d.tenant_id AND r.id = d.id",
                        before,
                        None,
                    )
                    .await?;
                    let room = PURGE_BATCH.saturating_sub(i64::try_from(expired).unwrap_or(PURGE_BATCH));
                    if room == 0 {
                        return Ok(expired);
                    }
                    let revoked = delete_limited(
                        conn,
                        "WITH doomed AS (SELECT tenant_id, id FROM rsvp_tokens \
                           WHERE revoked_at IS NOT NULL AND revoked_at < $1 LIMIT $2) \
                         DELETE FROM rsvp_tokens r USING doomed d WHERE r.tenant_id = d.tenant_id AND r.id = d.id",
                        before,
                        None,
                        room,
                    )
                    .await?;
                    Ok(expired + revoked)
                })
            })
            .await
        })
    }

    async fn due_principals(
        &mut self,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(TenantId, PrincipalId)>, StoreError> {
        observed!("retention.due_principals", {
            let rows = sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT tenant_id, id FROM principals WHERE status = 'deleted' AND deleted_at < $1 \
                 ORDER BY deleted_at, id LIMIT $2",
            )
            .bind(micros(before))
            .bind(i64::from(limit.min(MAX_PAGE_LIMIT)))
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            Ok(rows
                .into_iter()
                .map(|(tenant, principal)| (TenantId::from_uuid(tenant), PrincipalId::from_uuid(principal)))
                .collect())
        })
    }

    async fn due_calendars(
        &mut self,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(TenantId, CalendarId)>, StoreError> {
        observed!("retention.due_calendars", {
            let rows = sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT tenant_id, id FROM calendars WHERE deleted_at < $1 ORDER BY deleted_at, id LIMIT $2",
            )
            .bind(micros(before))
            .bind(i64::from(limit.min(MAX_PAGE_LIMIT)))
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            Ok(rows
                .into_iter()
                .map(|(tenant, calendar)| (TenantId::from_uuid(tenant), CalendarId::from_uuid(calendar)))
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    #[test]
    fn expired_items_are_grouped_by_principal() {
        let tenant = Uuid::from_u128(1);
        let rows = vec![
            (
                tenant,
                Uuid::from_u128(10),
                Uuid::from_u128(100),
                "a.ics".to_owned(),
                false,
            ),
            (
                tenant,
                Uuid::from_u128(10),
                Uuid::from_u128(101),
                "b.ics".to_owned(),
                false,
            ),
            (
                tenant,
                Uuid::from_u128(10),
                Uuid::from_u128(103),
                "q.ics".to_owned(),
                true,
            ),
            (
                tenant,
                Uuid::from_u128(11),
                Uuid::from_u128(102),
                "c.ics".to_owned(),
                false,
            ),
            (
                tenant,
                Uuid::from_u128(12),
                Uuid::from_u128(104),
                "r.ics".to_owned(),
                true,
            ),
        ];
        let groups = group_expired(rows);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].uris, vec!["a.ics".to_owned(), "b.ics".to_owned()]);
        assert_eq!(groups[0].ids.len(), 3, "a quarantined item is deleted ...");
        assert_eq!(groups[0].uris.len(), 2, "... but not logged");
        assert_eq!(groups[1].principal, Uuid::from_u128(11));
        assert!(groups[2].uris.is_empty() && groups[2].ids.len() == 1);
    }

    #[test]
    fn leases_saturate_instead_of_overflowing() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        assert_eq!(lease_end(now, Duration::from_secs(60)), now + TimeDelta::seconds(60));
        assert_eq!(lease_end(now, Duration::MAX), DateTime::<Utc>::MAX_UTC);
    }
}
