//! The change log behind sync tokens, and the helpers that advance it.
//!
//! The sequence of a calendar lives on the calendar row (`sync_seq`), the sequences of a principal's home, inbox
//! and notification collection in `principals_sync`. Every write that changes what a client sees advances the
//! sequence with one `UPDATE ... RETURNING` (which also serialises writers of the collection) and writes the
//! change-log row at that sequence number, in the caller's transaction, so no change can be logged twice or
//! forgotten.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{CollectionKey, CollectionKind, ObjectUri, PrincipalId};
use davhaven_ports::store::MAX_PAGE_LIMIT;
use davhaven_ports::{Change, ChangeBatch, ChangeKind, ChangeRepo, StoreError, SyncPosition};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{DbResult, decode, misuse, to_i64, to_u64};
use crate::tx::PgTx;

/// Advances the sequence of a live calendar and returns the new value; `None` when the calendar does not exist.
pub(super) async fn bump_calendar(
    conn: &mut PgConnection,
    tenant: Uuid,
    calendar: Uuid,
) -> Result<Option<i64>, StoreError> {
    sqlx::query_scalar::<_, i64>(
        "UPDATE calendars SET sync_seq = sync_seq + 1 \
         WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL RETURNING sync_seq",
    )
    .bind(tenant)
    .bind(calendar)
    .fetch_optional(&mut *conn)
    .await
    .db()
}

/// Advances the sequence of a principal's home, inbox or notification collection and returns the new value;
/// `None` when the principal does not exist.
pub(super) async fn bump_principal_collection(
    conn: &mut PgConnection,
    tenant: Uuid,
    principal: Uuid,
    kind: CollectionKind,
) -> Result<Option<i64>, StoreError> {
    let sql = match kind {
        CollectionKind::Home => {
            "UPDATE principals_sync SET home_seq = home_seq + 1 \
             WHERE tenant_id = $1 AND principal_id = $2 RETURNING home_seq"
        }
        CollectionKind::Inbox => {
            "UPDATE principals_sync SET inbox_seq = inbox_seq + 1 \
             WHERE tenant_id = $1 AND principal_id = $2 RETURNING inbox_seq"
        }
        CollectionKind::Notifications => {
            "UPDATE principals_sync SET notifications_seq = notifications_seq + 1 \
             WHERE tenant_id = $1 AND principal_id = $2 RETURNING notifications_seq"
        }
        CollectionKind::Calendar => return Err(misuse("a calendar's sequence is advanced on the calendar row")),
    };
    sqlx::query_scalar::<_, i64>(sql)
        .bind(tenant)
        .bind(principal)
        .fetch_optional(&mut *conn)
        .await
        .db()
}

/// One change-log row.
pub(super) struct LogEntry<'a> {
    /// The tenant.
    pub(super) tenant: Uuid,
    /// The kind of collection.
    pub(super) kind: CollectionKind,
    /// The calendar id or principal id.
    pub(super) collection: Uuid,
    /// The sequence number of the change.
    pub(super) seq: i64,
    /// The name of the member that changed.
    pub(super) uri: &'a str,
    /// What happened to it.
    pub(super) change: ChangeKind,
    /// When it happened.
    pub(super) at: DateTime<Utc>,
}

/// Writes the change-log row of the change at its sequence number.
pub(super) async fn log_change(conn: &mut PgConnection, entry: &LogEntry<'_>) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO collection_changes (tenant_id, collection_kind, collection_id, seq, uri, kind, at) 
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(entry.tenant)
    .bind(entry.kind.as_str())
    .bind(entry.collection)
    .bind(entry.seq)
    .bind(entry.uri)
    .bind(entry.change.as_str())
    .bind(entry.at)
    .execute(&mut *conn)
    .await
    .db()?;
    Ok(())
}

/// A change of a principal's collection (home, inbox or notifications).
pub(super) struct PrincipalChange<'a> {
    /// The tenant.
    pub(super) tenant: Uuid,
    /// The principal.
    pub(super) principal: Uuid,
    /// Home, inbox or notifications.
    pub(super) kind: CollectionKind,
    /// The name of the member that changed.
    pub(super) uri: &'a str,
    /// What happened to it.
    pub(super) change: ChangeKind,
    /// When it happened.
    pub(super) at: DateTime<Utc>,
}

/// Advances a principal collection and logs the change in one step; returns the new sequence number.
pub(super) async fn record_principal_change(
    conn: &mut PgConnection,
    change: &PrincipalChange<'_>,
) -> Result<i64, StoreError> {
    let seq = bump_principal_collection(&mut *conn, change.tenant, change.principal, change.kind)
        .await?
        .ok_or(StoreError::NotFound)?;
    let entry = LogEntry {
        tenant: change.tenant,
        kind: change.kind,
        collection: change.principal,
        seq,
        uri: change.uri,
        change: change.change,
        at: change.at,
    };
    log_change(conn, &entry).await?;
    Ok(seq)
}

/// A row of the sync position of one collection.
#[derive(sqlx::FromRow)]
struct PositionRow {
    epoch: Uuid,
    seq: i64,
    min_seq: i64,
}

impl PositionRow {
    fn into_position(self) -> Result<SyncPosition, StoreError> {
        Ok(SyncPosition {
            epoch: self.epoch,
            seq: to_u64(self.seq)?,
            min_seq: to_u64(self.min_seq)?,
        })
    }
}

/// A row of `collection_changes`.
#[derive(sqlx::FromRow)]
struct ChangeRow {
    seq: i64,
    uri: String,
    kind: String,
}

impl ChangeRow {
    fn into_change(self) -> Result<Change, StoreError> {
        Ok(Change {
            seq: to_u64(self.seq)?,
            uri: decode("change uri", ObjectUri::parse(&self.uri))?,
            kind: match self.kind.as_str() {
                "upsert" => ChangeKind::Upsert,
                "delete" => ChangeKind::Delete,
                other => return Err(super::corrupt("change kind", other)),
            },
        })
    }
}

impl PgTx {
    /// The sync position of a collection.
    async fn position_of(&mut self, collection: CollectionKey) -> Result<SyncPosition, StoreError> {
        let sql = match collection.kind {
            CollectionKind::Calendar => {
                "SELECT sync_epoch AS epoch, sync_seq AS seq, sync_min_seq AS min_seq FROM calendars \
                 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL"
            }
            CollectionKind::Home => {
                "SELECT home_epoch AS epoch, home_seq AS seq, home_min_seq AS min_seq FROM principals_sync \
                 WHERE tenant_id = $1 AND principal_id = $2"
            }
            CollectionKind::Inbox => {
                "SELECT inbox_epoch AS epoch, inbox_seq AS seq, inbox_min_seq AS min_seq FROM principals_sync \
                 WHERE tenant_id = $1 AND principal_id = $2"
            }
            CollectionKind::Notifications => {
                "SELECT notifications_epoch AS epoch, notifications_seq AS seq, \
                 notifications_min_seq AS min_seq FROM principals_sync WHERE tenant_id = $1 AND principal_id = $2"
            }
        };
        sqlx::query_as::<_, PositionRow>(sql)
            .bind(self.tenant.as_uuid())
            .bind(collection.id)
            .fetch_optional(&mut *self.conn)
            .await
            .db()?
            .ok_or(StoreError::NotFound)?
            .into_position()
    }

    /// Advances a principal collection without a change-log row (`touch_*`).
    async fn touch_principal(&mut self, principal: PrincipalId, kind: CollectionKind) -> Result<u64, StoreError> {
        let tenant = self.tenant.as_uuid();
        let seq = self
            .guarded(move |conn| {
                Box::pin(async move {
                    bump_principal_collection(conn, tenant, principal.as_uuid(), kind)
                        .await?
                        .ok_or(StoreError::NotFound)
                })
            })
            .await?;
        to_u64(seq)
    }
}

#[async_trait]
impl ChangeRepo for PgTx {
    async fn state(&mut self, collection: CollectionKey) -> Result<SyncPosition, StoreError> {
        observed!("changes.state", self.position_of(collection).await)
    }

    async fn since(
        &mut self,
        collection: CollectionKey,
        epoch: Uuid,
        seq: u64,
        limit: u32,
    ) -> Result<ChangeBatch, StoreError> {
        observed!("changes.since", {
            let current = self.position_of(collection).await?;
            if epoch != current.epoch || seq < current.min_seq || seq > current.seq {
                return Err(StoreError::InvalidSyncToken);
            }
            let limit = limit.clamp(1, MAX_PAGE_LIMIT);
            let rows = sqlx::query_as::<_, ChangeRow>(
                "SELECT seq, uri, kind FROM ( \
                   SELECT DISTINCT ON (uri) seq, uri, kind FROM collection_changes \
                   WHERE tenant_id = $1 AND collection_kind = $2 AND collection_id = $3 AND seq > $4 AND seq <= $5 \
                   ORDER BY uri, seq DESC) latest \
                 ORDER BY seq LIMIT $6",
            )
            .bind(self.tenant.as_uuid())
            .bind(collection.kind.as_str())
            .bind(collection.id)
            .bind(to_i64(seq)?)
            .bind(to_i64(current.seq)?)
            .bind(i64::from(limit) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let mut changes = rows
                .into_iter()
                .map(ChangeRow::into_change)
                .collect::<Result<Vec<_>, _>>()?;
            let truncated = changes.len() > usize::try_from(limit).unwrap_or(usize::MAX);
            changes.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            Ok(ChangeBatch {
                changes,
                current,
                truncated,
            })
        })
    }

    async fn touch_home(&mut self, principal: PrincipalId) -> Result<u64, StoreError> {
        observed!(
            "changes.touch_home",
            self.touch_principal(principal, CollectionKind::Home).await
        )
    }

    async fn touch_inbox(&mut self, principal: PrincipalId) -> Result<u64, StoreError> {
        observed!(
            "changes.touch_inbox",
            self.touch_principal(principal, CollectionKind::Inbox).await
        )
    }

    async fn touch_notifications(&mut self, principal: PrincipalId) -> Result<u64, StoreError> {
        observed!(
            "changes.touch_notifications",
            self.touch_principal(principal, CollectionKind::Notifications).await
        )
    }
}
