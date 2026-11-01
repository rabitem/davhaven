//! Credentials: app passwords, API tokens, feed tokens and RSVP tokens.
//!
//! Only keyed hashes are stored. Revoking stamps `revoked_at` and keeps the row, so a later use of the revoked
//! credential is recognised instead of looking like an unknown one; the first revocation time is kept.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    ApiToken, AppPassword, CalendarId, CalendarUserAddress, CredentialId, CredentialKind, FeedMode, FeedToken,
    ObjectId, PartStat, PrincipalId, RsvpToken, Scope, ScopeSet, TenantId, TokenId, TokenKind,
};
use davhaven_ports::store::ApiTokenFilter;
use davhaven_ports::{CredentialRepo, CredentialUse, PageReq, Rehash, RsvpRepo, StoreError, StorePage};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{DbResult, corrupt, decode, micros, misuse};
use crate::tx::PgTx;

/// A row of `app_passwords`.
#[derive(sqlx::FromRow)]
pub(super) struct AppPasswordRow {
    tenant_id: Uuid,
    id: Uuid,
    principal_id: Uuid,
    label: String,
    prefix: String,
    hash: Vec<u8>,
    pepper_kid: String,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl AppPasswordRow {
    pub(super) fn into_password(self) -> AppPassword {
        AppPassword {
            id: CredentialId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            principal_id: PrincipalId::from_uuid(self.principal_id),
            label: self.label,
            prefix: self.prefix,
            hash: self.hash,
            pepper_kid: self.pepper_kid,
            last_used_at: self.last_used_at,
            revoked_at: self.revoked_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        }
    }
}

/// A row of `api_tokens`.
#[derive(sqlx::FromRow)]
pub(super) struct ApiTokenRow {
    tenant_id: Option<Uuid>,
    id: Uuid,
    kind: String,
    principal_id: Option<Uuid>,
    label: String,
    scopes: Vec<String>,
    prefix: String,
    hash: Vec<u8>,
    pepper_kid: String,
    expires_at: Option<DateTime<Utc>>,
    created_by: Option<Uuid>,
    allowed_origins: Vec<String>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

/// The kind of a token from its database spelling.
pub(super) fn token_kind(text: &str) -> Result<TokenKind, StoreError> {
    TokenKind::ALL
        .into_iter()
        .find(|kind| kind.as_str() == text)
        .ok_or_else(|| corrupt("token kind", text))
}

impl ApiTokenRow {
    pub(super) fn into_token(self) -> Result<ApiToken, StoreError> {
        // A scope written by a newer release is dropped: the token then carries less, never more.
        let scopes: ScopeSet = self
            .scopes
            .iter()
            .filter_map(|scope| scope.parse::<Scope>().ok())
            .collect();
        Ok(ApiToken {
            id: TokenId::from_uuid(self.id),
            tenant_id: self.tenant_id.map(TenantId::from_uuid),
            kind: token_kind(&self.kind)?,
            principal_id: self.principal_id.map(PrincipalId::from_uuid),
            label: self.label,
            scopes,
            prefix: self.prefix,
            hash: self.hash,
            pepper_kid: self.pepper_kid,
            expires_at: self.expires_at,
            created_by: self.created_by.map(TokenId::from_uuid),
            allowed_origins: self.allowed_origins,
            last_used_at: self.last_used_at,
            revoked_at: self.revoked_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

/// A row of `feed_tokens`.
#[derive(sqlx::FromRow)]
pub(super) struct FeedTokenRow {
    tenant_id: Uuid,
    id: Uuid,
    principal_id: Uuid,
    mode: String,
    calendar_ids: Vec<Uuid>,
    prefix: String,
    hash: Vec<u8>,
    pepper_kid: String,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl FeedTokenRow {
    pub(super) fn into_token(self) -> Result<FeedToken, StoreError> {
        Ok(FeedToken {
            id: TokenId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            principal_id: PrincipalId::from_uuid(self.principal_id),
            mode: decode("feed mode", self.mode.parse::<FeedMode>())?,
            calendar_ids: self.calendar_ids.into_iter().map(CalendarId::from_uuid).collect(),
            prefix: self.prefix,
            hash: self.hash,
            pepper_kid: self.pepper_kid,
            revoked_at: self.revoked_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

/// A row of `rsvp_tokens`.
#[derive(sqlx::FromRow)]
pub(super) struct RsvpTokenRow {
    tenant_id: Uuid,
    id: Uuid,
    object_id: Uuid,
    attendee_address: String,
    prefix: String,
    hash: Vec<u8>,
    pepper_kid: String,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    last_response: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl RsvpTokenRow {
    pub(super) fn into_token(self) -> Result<RsvpToken, StoreError> {
        Ok(RsvpToken {
            id: TokenId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            object_id: ObjectId::from_uuid(self.object_id),
            attendee_address: decode("attendee address", CalendarUserAddress::parse(&self.attendee_address))?,
            prefix: self.prefix,
            hash: self.hash,
            pepper_kid: self.pepper_kid,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
            last_used_at: self.last_used_at,
            last_response: self
                .last_response
                .as_deref()
                .map(|token| PartStat::from_ical(token).ok_or_else(|| corrupt("rsvp response", token)))
                .transpose()?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

/// Stamps the revocation of one credential. A credential that is revoked already keeps its first revocation time;
/// a missing one is `NotFound`.
async fn revoke_one(
    conn: &mut PgConnection,
    update: &'static str,
    exists: &'static str,
    tenant: Uuid,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let changed = sqlx::query(update)
        .bind(tenant)
        .bind(id)
        .bind(now)
        .execute(&mut *conn)
        .await
        .db()?
        .rows_affected();
    if changed > 0 {
        return Ok(());
    }
    let found = sqlx::query_scalar::<_, i32>(exists)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .db()?;
    found.map(|_| ()).ok_or(StoreError::NotFound)
}

/// Runs a revoking `UPDATE` with `$1` = tenant, `$2` = scope id, `$3` = time and returns how many rows changed.
async fn revoke_many(
    conn: &mut PgConnection,
    update: &'static str,
    tenant: Uuid,
    scope: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    Ok(sqlx::query(update)
        .bind(tenant)
        .bind(scope)
        .bind(now)
        .execute(&mut *conn)
        .await
        .db()?
        .rows_affected())
}

impl PgTx {
    async fn select_tokens(&mut self, sql: &'static str, scope: Uuid) -> Result<Vec<FeedToken>, StoreError> {
        let rows = sqlx::query_as::<_, FeedTokenRow>(sql)
            .bind(self.tenant.as_uuid())
            .bind(scope)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
        rows.into_iter().map(FeedTokenRow::into_token).collect()
    }
}

#[async_trait]
impl CredentialRepo for PgTx {
    async fn create_app_password(&mut self, password: AppPassword) -> Result<AppPassword, StoreError> {
        observed!("credentials.create_app_password", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, AppPasswordRow>(concat!(
                        "INSERT INTO app_passwords (tenant_id, id, principal_id, label, prefix, hash, pepper_kid, \
                         last_used_at, revoked_at, created_at, updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, 1) RETURNING ",
                        app_password_columns!("")
                    ))
                    .bind(tenant)
                    .bind(password.id.as_uuid())
                    .bind(password.principal_id.as_uuid())
                    .bind(&password.label)
                    .bind(&password.prefix)
                    .bind(&password.hash)
                    .bind(&password.pepper_kid)
                    .bind(password.last_used_at.map(micros))
                    .bind(password.revoked_at.map(micros))
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    Ok(row.into_password())
                })
            })
            .await
        })
    }

    async fn get_app_password(&mut self, id: CredentialId) -> Result<AppPassword, StoreError> {
        observed!("credentials.get_app_password", {
            let row = sqlx::query_as::<_, AppPasswordRow>(concat!(
                "SELECT ",
                app_password_columns!(""),
                " FROM app_passwords WHERE tenant_id = $1 AND id = $2"
            ))
            .bind(self.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.map(AppPasswordRow::into_password).ok_or(StoreError::NotFound)
        })
    }

    async fn list_app_passwords(&mut self, principal: PrincipalId) -> Result<Vec<AppPassword>, StoreError> {
        observed!("credentials.list_app_passwords", {
            let rows = sqlx::query_as::<_, AppPasswordRow>(concat!(
                "SELECT ",
                app_password_columns!(""),
                " FROM app_passwords WHERE tenant_id = $1 AND principal_id = $2 ORDER BY id"
            ))
            .bind(self.tenant.as_uuid())
            .bind(principal.as_uuid())
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            Ok(rows.into_iter().map(AppPasswordRow::into_password).collect())
        })
    }

    async fn revoke_app_password(&mut self, id: CredentialId) -> Result<(), StoreError> {
        observed!("credentials.revoke_app_password", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    revoke_one(
                        conn,
                        "UPDATE app_passwords SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
                        "SELECT 1 FROM app_passwords WHERE tenant_id = $1 AND id = $2",
                        tenant,
                        id.as_uuid(),
                        now,
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn create_api_token(&mut self, token: ApiToken) -> Result<ApiToken, StoreError> {
        observed!("credentials.create_api_token", {
            if token.kind == TokenKind::System {
                return Err(misuse("system tokens are created through the credential lookup"));
            }
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, ApiTokenRow>(concat!(
                        "INSERT INTO api_tokens (tenant_id, id, kind, principal_id, label, scopes, prefix, hash, \
                         pepper_kid, expires_at, created_by, allowed_origins, last_used_at, revoked_at, created_at, \
                         updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15, 1) RETURNING ",
                        api_token_columns!("")
                    ))
                    .bind(tenant)
                    .bind(token.id.as_uuid())
                    .bind(token.kind.as_str())
                    .bind(token.principal_id.map(PrincipalId::as_uuid))
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

    async fn get_api_token(&mut self, id: TokenId) -> Result<ApiToken, StoreError> {
        observed!("credentials.get_api_token", {
            let row = sqlx::query_as::<_, ApiTokenRow>(concat!(
                "SELECT ",
                api_token_columns!(""),
                " FROM api_tokens WHERE tenant_id = $1 AND id = $2"
            ))
            .bind(self.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_token()
        })
    }

    async fn list_api_tokens(
        &mut self,
        filter: &ApiTokenFilter,
        page: PageReq,
    ) -> Result<StorePage<ApiToken>, StoreError> {
        observed!("credentials.list_api_tokens", {
            let rows = sqlx::query_as::<_, ApiTokenRow>(concat!(
                "SELECT ",
                api_token_columns!(""),
                " FROM api_tokens WHERE tenant_id = $1 \
                 AND ($2::uuid IS NULL OR principal_id = $2) \
                 AND ($3::text IS NULL OR kind = $3) \
                 AND ($4::boolean OR revoked_at IS NULL) \
                 AND ($5::uuid IS NULL OR id > $5) \
                 ORDER BY id LIMIT $6"
            ))
            .bind(self.tenant.as_uuid())
            .bind(filter.principal.map(PrincipalId::as_uuid))
            .bind(filter.kind.map(TokenKind::as_str))
            .bind(filter.include_revoked)
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let tokens = rows
                .into_iter()
                .map(ApiTokenRow::into_token)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(tokens, &page, |token| token.id.as_uuid()))
        })
    }

    async fn revoke_api_token(&mut self, id: TokenId) -> Result<(), StoreError> {
        observed!("credentials.revoke_api_token", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    revoke_one(
                        conn,
                        "UPDATE api_tokens SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
                        "SELECT 1 FROM api_tokens WHERE tenant_id = $1 AND id = $2",
                        tenant,
                        id.as_uuid(),
                        now,
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn create_feed_token(&mut self, token: FeedToken) -> Result<FeedToken, StoreError> {
        observed!("credentials.create_feed_token", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let mut calendars: Vec<Uuid> =
                        token.calendar_ids.iter().copied().map(CalendarId::as_uuid).collect();
                    calendars.sort_unstable();
                    calendars.dedup();
                    let existing = sqlx::query_scalar::<_, i64>(
                        "SELECT count(*) FROM calendars WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL",
                    )
                    .bind(tenant)
                    .bind(&calendars)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    if usize::try_from(existing).ok() != Some(calendars.len()) {
                        return Err(StoreError::NotFound);
                    }
                    let ids: Vec<Uuid> = token.calendar_ids.iter().copied().map(CalendarId::as_uuid).collect();
                    let row = sqlx::query_as::<_, FeedTokenRow>(concat!(
                        "INSERT INTO feed_tokens (tenant_id, id, principal_id, mode, calendar_ids, prefix, hash, \
                         pepper_kid, revoked_at, created_at, updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, 1) RETURNING ",
                        feed_token_columns!("")
                    ))
                    .bind(tenant)
                    .bind(token.id.as_uuid())
                    .bind(token.principal_id.as_uuid())
                    .bind(token.mode.as_str())
                    .bind(&ids)
                    .bind(&token.prefix)
                    .bind(&token.hash)
                    .bind(&token.pepper_kid)
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

    async fn get_feed_token(&mut self, id: TokenId) -> Result<FeedToken, StoreError> {
        observed!("credentials.get_feed_token", {
            self.select_tokens(
                concat!(
                    "SELECT ",
                    feed_token_columns!(""),
                    " FROM feed_tokens WHERE tenant_id = $1 AND id = $2"
                ),
                id.as_uuid(),
            )
            .await?
            .pop()
            .ok_or(StoreError::NotFound)
        })
    }

    async fn list_feed_tokens(&mut self, principal: PrincipalId) -> Result<Vec<FeedToken>, StoreError> {
        observed!("credentials.list_feed_tokens", {
            self.select_tokens(
                concat!(
                    "SELECT ",
                    feed_token_columns!(""),
                    " FROM feed_tokens WHERE tenant_id = $1 AND principal_id = $2 ORDER BY id"
                ),
                principal.as_uuid(),
            )
            .await
        })
    }

    async fn revoke_feed_token(&mut self, id: TokenId) -> Result<(), StoreError> {
        observed!("credentials.revoke_feed_token", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    revoke_one(
                        conn,
                        "UPDATE feed_tokens SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
                        "SELECT 1 FROM feed_tokens WHERE tenant_id = $1 AND id = $2",
                        tenant,
                        id.as_uuid(),
                        now,
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn revoke_all_for_principal(&mut self, principal: PrincipalId) -> Result<u64, StoreError> {
        observed!("credentials.revoke_all_for_principal", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let who = principal.as_uuid();
                    let passwords = revoke_many(
                        conn,
                        "UPDATE app_passwords SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND principal_id = $2 AND revoked_at IS NULL",
                        tenant,
                        who,
                        now,
                    )
                    .await?;
                    let tokens = revoke_many(
                        conn,
                        "UPDATE api_tokens SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND principal_id = $2 AND kind = 'principal' AND revoked_at IS NULL",
                        tenant,
                        who,
                        now,
                    )
                    .await?;
                    let feeds = revoke_many(
                        conn,
                        "UPDATE feed_tokens SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND principal_id = $2 AND revoked_at IS NULL",
                        tenant,
                        who,
                        now,
                    )
                    .await?;
                    Ok(passwords + tokens + feeds)
                })
            })
            .await
        })
    }

    async fn touch_last_used(&mut self, uses: &[CredentialUse]) -> Result<u64, StoreError> {
        observed!("credentials.touch_last_used", {
            // One entry per credential, the latest use.
            let mut latest: BTreeMap<(CredentialKind, Uuid), DateTime<Utc>> = BTreeMap::new();
            for used in uses {
                let at = micros(used.at);
                latest
                    .entry((used.kind, used.id))
                    .and_modify(|seen| *seen = (*seen).max(at))
                    .or_insert(at);
            }
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let mut changed = 0;
                    for (kind, table_sql) in [
                        (
                            CredentialKind::AppPassword,
                            "UPDATE app_passwords t SET last_used_at = u.used_at \
                             FROM unnest($2::uuid[], $3::timestamptz[]) AS u(id, used_at) \
                             WHERE t.tenant_id = $1 AND t.id = u.id \
                             AND (t.last_used_at IS NULL OR t.last_used_at < u.used_at)",
                        ),
                        (
                            CredentialKind::ApiToken,
                            "UPDATE api_tokens t SET last_used_at = u.used_at \
                             FROM unnest($2::uuid[], $3::timestamptz[]) AS u(id, used_at) \
                             WHERE t.tenant_id = $1 AND t.id = u.id \
                             AND (t.last_used_at IS NULL OR t.last_used_at < u.used_at)",
                        ),
                        (
                            CredentialKind::RsvpToken,
                            "UPDATE rsvp_tokens t SET last_used_at = u.used_at \
                             FROM unnest($2::uuid[], $3::timestamptz[]) AS u(id, used_at) \
                             WHERE t.tenant_id = $1 AND t.id = u.id \
                             AND (t.last_used_at IS NULL OR t.last_used_at < u.used_at)",
                        ),
                    ] {
                        let (ids, times): (Vec<Uuid>, Vec<DateTime<Utc>>) = latest
                            .iter()
                            .filter(|((used_kind, _), _)| *used_kind == kind)
                            .map(|((_, id), at)| (*id, *at))
                            .unzip();
                        if ids.is_empty() {
                            continue;
                        }
                        changed += sqlx::query(table_sql)
                            .bind(tenant)
                            .bind(&ids)
                            .bind(&times)
                            .execute(&mut *conn)
                            .await
                            .db()?
                            .rows_affected();
                    }
                    Ok(changed)
                })
            })
            .await
        })
    }

    async fn rehash(&mut self, rehash: &Rehash) -> Result<bool, StoreError> {
        observed!("credentials.rehash", {
            // The hash changes only while it still names the key it was read under, so two requests that re-hash the
            // same credential at once cannot undo each other; nothing but `hash` and `pepper_kid` is touched.
            let sql: &'static str = match rehash.credential.kind {
                CredentialKind::AppPassword => {
                    concat!(
                        "UPDATE app_passwords SET hash = $3, pepper_kid = $4 ",
                        "WHERE tenant_id = $1 AND id = $2 AND pepper_kid = $5"
                    )
                }
                CredentialKind::ApiToken => {
                    concat!(
                        "UPDATE api_tokens SET hash = $3, pepper_kid = $4 ",
                        "WHERE tenant_id = $1 AND id = $2 AND pepper_kid = $5"
                    )
                }
                CredentialKind::FeedToken => {
                    concat!(
                        "UPDATE feed_tokens SET hash = $3, pepper_kid = $4 ",
                        "WHERE tenant_id = $1 AND id = $2 AND pepper_kid = $5"
                    )
                }
                CredentialKind::RsvpToken => {
                    concat!(
                        "UPDATE rsvp_tokens SET hash = $3, pepper_kid = $4 ",
                        "WHERE tenant_id = $1 AND id = $2 AND pepper_kid = $5"
                    )
                }
            };
            let tenant = self.tenant.as_uuid();
            let id = rehash.credential.id;
            let hash = rehash.to.hash.clone();
            let pepper_kid = rehash.to.pepper_kid.clone();
            let from_kid = rehash.from_kid.clone();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let done = sqlx::query(sql)
                        .bind(tenant)
                        .bind(id)
                        .bind(&hash)
                        .bind(&pepper_kid)
                        .bind(&from_kid)
                        .execute(&mut *conn)
                        .await
                        .db()?;
                    Ok(done.rows_affected() > 0)
                })
            })
            .await
        })
    }
}

impl PgTx {
    async fn select_rsvp(
        &mut self,
        sql: &'static str,
        first: Uuid,
        second: Option<&str>,
    ) -> Result<Vec<RsvpToken>, StoreError> {
        let mut query = sqlx::query_as::<_, RsvpTokenRow>(sql)
            .bind(self.tenant.as_uuid())
            .bind(first);
        if let Some(second) = second {
            query = query.bind(second.to_owned());
        }
        let rows = query.fetch_all(&mut *self.conn).await.db()?;
        rows.into_iter().map(RsvpTokenRow::into_token).collect()
    }
}

#[async_trait]
impl RsvpRepo for PgTx {
    async fn create(&mut self, token: RsvpToken) -> Result<RsvpToken, StoreError> {
        observed!("rsvp.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, RsvpTokenRow>(concat!(
                        "INSERT INTO rsvp_tokens (tenant_id, id, object_id, attendee_address, prefix, hash, \
                         pepper_kid, expires_at, revoked_at, last_used_at, last_response, created_at, updated_at, \
                         version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, 1) RETURNING ",
                        rsvp_token_columns!("")
                    ))
                    .bind(tenant)
                    .bind(token.id.as_uuid())
                    .bind(token.object_id.as_uuid())
                    .bind(token.attendee_address.as_str())
                    .bind(&token.prefix)
                    .bind(&token.hash)
                    .bind(&token.pepper_kid)
                    .bind(micros(token.expires_at))
                    .bind(token.revoked_at.map(micros))
                    .bind(token.last_used_at.map(micros))
                    .bind(token.last_response.map(PartStat::as_ical))
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

    async fn get(&mut self, id: TokenId) -> Result<RsvpToken, StoreError> {
        observed!("rsvp.get", {
            self.select_rsvp(
                concat!(
                    "SELECT ",
                    rsvp_token_columns!(""),
                    " FROM rsvp_tokens WHERE tenant_id = $1 AND id = $2"
                ),
                id.as_uuid(),
                None,
            )
            .await?
            .pop()
            .ok_or(StoreError::NotFound)
        })
    }

    async fn for_object(&mut self, object: ObjectId) -> Result<Vec<RsvpToken>, StoreError> {
        observed!("rsvp.for_object", {
            self.select_rsvp(
                concat!(
                    "SELECT ",
                    rsvp_token_columns!(""),
                    " FROM rsvp_tokens WHERE tenant_id = $1 AND object_id = $2 ORDER BY id"
                ),
                object.as_uuid(),
                None,
            )
            .await
        })
    }

    async fn find_live(
        &mut self,
        object: ObjectId,
        address: &CalendarUserAddress,
    ) -> Result<Option<RsvpToken>, StoreError> {
        observed!("rsvp.find_live", {
            Ok(self
                .select_rsvp(
                    concat!(
                        "SELECT ",
                        rsvp_token_columns!(""),
                        " FROM rsvp_tokens WHERE tenant_id = $1 AND object_id = $2 AND attendee_address = $3 \
                         AND revoked_at IS NULL ORDER BY id LIMIT 1"
                    ),
                    object.as_uuid(),
                    Some(address.as_str()),
                )
                .await?
                .pop())
        })
    }

    async fn record_use(&mut self, id: TokenId, response: Option<PartStat>) -> Result<(), StoreError> {
        observed!("rsvp.record_use", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let changed = sqlx::query(
                        "UPDATE rsvp_tokens SET last_used_at = $3, last_response = COALESCE($4, last_response), \
                         updated_at = $3, version = version + 1 WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .bind(now)
                    .bind(response.map(PartStat::as_ical))
                    .execute(&mut *conn)
                    .await
                    .db()?
                    .rows_affected();
                    if changed == 0 {
                        Err(StoreError::NotFound)
                    } else {
                        Ok(())
                    }
                })
            })
            .await
        })
    }

    async fn revoke(&mut self, id: TokenId) -> Result<(), StoreError> {
        observed!("rsvp.revoke", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    revoke_one(
                        conn,
                        "UPDATE rsvp_tokens SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
                        "SELECT 1 FROM rsvp_tokens WHERE tenant_id = $1 AND id = $2",
                        tenant,
                        id.as_uuid(),
                        now,
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn revoke_for_object(&mut self, object: ObjectId) -> Result<u64, StoreError> {
        observed!("rsvp.revoke_for_object", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    revoke_many(
                        conn,
                        "UPDATE rsvp_tokens SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND object_id = $2 AND revoked_at IS NULL",
                        tenant,
                        object.as_uuid(),
                        now,
                    )
                    .await
                })
            })
            .await
        })
    }

    async fn revoke_for_attendee(
        &mut self,
        object: ObjectId,
        address: &CalendarUserAddress,
    ) -> Result<u64, StoreError> {
        observed!("rsvp.revoke_for_attendee", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let address = address.as_str().to_owned();
            self.guarded(move |conn| {
                Box::pin(async move {
                    Ok(sqlx::query(
                        "UPDATE rsvp_tokens SET revoked_at = $3, updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND object_id = $2 AND attendee_address = $4 AND revoked_at IS NULL",
                    )
                    .bind(tenant)
                    .bind(object.as_uuid())
                    .bind(now)
                    .bind(&address)
                    .execute(&mut *conn)
                    .await
                    .db()?
                    .rows_affected())
                })
            })
            .await
        })
    }

    async fn revoke_for_address(&mut self, address: &CalendarUserAddress) -> Result<u64, StoreError> {
        observed!("rsvp.revoke_for_address", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let address = address.as_str().to_owned();
            self.guarded(move |conn| {
                Box::pin(async move {
                    Ok(sqlx::query(
                        "UPDATE rsvp_tokens SET revoked_at = $2, updated_at = $2, version = version + 1 \
                         WHERE tenant_id = $1 AND attendee_address = $3 AND revoked_at IS NULL",
                    )
                    .bind(tenant)
                    .bind(now)
                    .bind(&address)
                    .execute(&mut *conn)
                    .await
                    .db()?
                    .rows_affected())
                })
            })
            .await
        })
    }
}
