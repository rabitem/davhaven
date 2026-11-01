//! CalendarServer notifications and the scheduling inbox.
//!
//! Both collections have a change log: every create, update and delete advances the recipient's sequence and
//! writes the change-log row in the same savepoint.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CollectionKind, ETag, InboxItem, InboxItemId, Notification, NotificationId, NotificationKind, ObjectUri,
    PrincipalId, TenantId, Uid,
};
use davhaven_ports::{ChangeKind, InboxRepo, InboxScope, NotificationRepo, StoreError};
use uuid::Uuid;

use super::sync::{PrincipalChange, record_principal_change};
use super::{DbResult, decode, micros, stale_or_missing};
use crate::tx::PgTx;

/// A row of `notifications`.
#[derive(sqlx::FromRow)]
struct NotificationRow {
    tenant_id: Uuid,
    id: Uuid,
    principal_id: Uuid,
    uri: String,
    uid: String,
    etag: String,
    #[sqlx(rename = "type")]
    kind: String,
    body_xml: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl NotificationRow {
    fn into_notification(self) -> Result<Notification, StoreError> {
        Ok(Notification {
            id: NotificationId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            principal_id: PrincipalId::from_uuid(self.principal_id),
            uri: decode("notification uri", ObjectUri::parse(&self.uri))?,
            uid: decode("notification uid", Uid::parse(&self.uid))?,
            etag: decode("etag", ETag::parse(&self.etag))?,
            kind: decode("notification type", self.kind.parse::<NotificationKind>())?,
            body_xml: self.body_xml,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

impl PgTx {
    async fn select_notifications(
        &mut self,
        sql: &'static str,
        first: Uuid,
        second: Option<&str>,
    ) -> Result<Vec<Notification>, StoreError> {
        let mut query = sqlx::query_as::<_, NotificationRow>(sql)
            .bind(self.tenant.as_uuid())
            .bind(first);
        if let Some(second) = second {
            query = query.bind(second.to_owned());
        }
        let rows = query.fetch_all(&mut *self.conn).await.db()?;
        rows.into_iter().map(NotificationRow::into_notification).collect()
    }
}

#[async_trait]
impl NotificationRepo for PgTx {
    async fn get(&mut self, id: NotificationId) -> Result<Notification, StoreError> {
        observed!("notifications.get", {
            self.select_notifications(
                concat!(
                    "SELECT ",
                    notification_columns!(""),
                    " FROM notifications WHERE tenant_id = $1 AND id = $2"
                ),
                id.as_uuid(),
                None,
            )
            .await?
            .pop()
            .ok_or(StoreError::NotFound)
        })
    }

    async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<Notification, StoreError> {
        observed!("notifications.get_by_uri", {
            self.select_notifications(
                concat!(
                    "SELECT ",
                    notification_columns!(""),
                    " FROM notifications WHERE tenant_id = $1 AND principal_id = $2 AND uri = $3"
                ),
                principal.as_uuid(),
                Some(uri.as_str()),
            )
            .await?
            .pop()
            .ok_or(StoreError::NotFound)
        })
    }

    async fn get_many_by_uri(
        &mut self,
        principal: PrincipalId,
        uris: &[ObjectUri],
    ) -> Result<Vec<Notification>, StoreError> {
        observed!("notifications.get_many_by_uri", {
            let names: Vec<&str> = uris.iter().map(ObjectUri::as_str).collect();
            let rows = sqlx::query_as::<_, NotificationRow>(concat!(
                "SELECT ",
                notification_columns!(""),
                " FROM notifications WHERE tenant_id = $1 AND principal_id = $2 AND uri = ANY($3)"
            ))
            .bind(self.tenant.as_uuid())
            .bind(principal.as_uuid())
            .bind(&names)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let mut stored: std::collections::HashMap<String, Notification> = std::collections::HashMap::new();
            for row in rows {
                let notification = row.into_notification()?;
                stored.insert(notification.uri.as_str().to_owned(), notification);
            }
            Ok(uris.iter().filter_map(|uri| stored.remove(uri.as_str())).collect())
        })
    }

    async fn find_by_uid(&mut self, principal: PrincipalId, uid: &Uid) -> Result<Option<Notification>, StoreError> {
        observed!("notifications.find_by_uid", {
            Ok(self
                .select_notifications(
                    concat!(
                        "SELECT ",
                        notification_columns!(""),
                        " FROM notifications WHERE tenant_id = $1 AND principal_id = $2 AND uid = $3 \
                         ORDER BY id LIMIT 1"
                    ),
                    principal.as_uuid(),
                    Some(uid.as_str()),
                )
                .await?
                .pop())
        })
    }

    async fn list(&mut self, principal: PrincipalId) -> Result<Vec<Notification>, StoreError> {
        observed!("notifications.list", {
            self.select_notifications(
                concat!(
                    "SELECT ",
                    notification_columns!(""),
                    " FROM notifications WHERE tenant_id = $1 AND principal_id = $2 ORDER BY id"
                ),
                principal.as_uuid(),
                None,
            )
            .await
        })
    }

    async fn create(&mut self, notification: Notification) -> Result<Notification, StoreError> {
        observed!("notifications.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, NotificationRow>(concat!(
                        "INSERT INTO notifications (tenant_id, id, principal_id, uri, uid, etag, type, body_xml, \
                         created_at, updated_at, version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, 1) RETURNING ",
                        notification_columns!("")
                    ))
                    .bind(tenant)
                    .bind(notification.id.as_uuid())
                    .bind(notification.principal_id.as_uuid())
                    .bind(notification.uri.as_str())
                    .bind(notification.uid.as_str())
                    .bind(notification.etag.as_str())
                    .bind(notification.kind.as_str())
                    .bind(&notification.body_xml)
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    let created = row.into_notification()?;
                    let change = PrincipalChange {
                        tenant,
                        principal: created.principal_id.as_uuid(),
                        kind: CollectionKind::Notifications,
                        uri: created.uri.as_str(),
                        change: ChangeKind::Upsert,
                        at: now,
                    };
                    record_principal_change(&mut *conn, &change).await?;
                    Ok(created)
                })
            })
            .await
        })
    }

    async fn update(&mut self, notification: Notification, expected_version: i64) -> Result<Notification, StoreError> {
        observed!("notifications.update", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, NotificationRow>(concat!(
                        "UPDATE notifications SET uid = $3, etag = $4, type = $5, body_xml = $6, updated_at = $7, \
                         version = version + 1 WHERE tenant_id = $1 AND id = $2 AND version = $8 RETURNING ",
                        notification_columns!("")
                    ))
                    .bind(tenant)
                    .bind(notification.id.as_uuid())
                    .bind(notification.uid.as_str())
                    .bind(notification.etag.as_str())
                    .bind(notification.kind.as_str())
                    .bind(&notification.body_xml)
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    let Some(row) = row else {
                        return Err(stale_or_missing(
                            conn,
                            "SELECT 1 FROM notifications WHERE tenant_id = $1 AND id = $2",
                            tenant,
                            notification.id.as_uuid(),
                        )
                        .await);
                    };
                    let updated = row.into_notification()?;
                    let change = PrincipalChange {
                        tenant,
                        principal: updated.principal_id.as_uuid(),
                        kind: CollectionKind::Notifications,
                        uri: updated.uri.as_str(),
                        change: ChangeKind::Upsert,
                        at: now,
                    };
                    record_principal_change(&mut *conn, &change).await?;
                    Ok(updated)
                })
            })
            .await
        })
    }

    async fn delete(&mut self, id: NotificationId) -> Result<(), StoreError> {
        observed!("notifications.delete", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let removed = sqlx::query_as::<_, (Uuid, String)>(
                        "DELETE FROM notifications WHERE tenant_id = $1 AND id = $2 RETURNING principal_id, uri",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    let Some((principal, uri)) = removed else {
                        return Err(StoreError::NotFound);
                    };
                    let change = PrincipalChange {
                        tenant,
                        principal,
                        kind: CollectionKind::Notifications,
                        uri: &uri,
                        change: ChangeKind::Delete,
                        at: now,
                    };
                    record_principal_change(&mut *conn, &change).await?;
                    Ok(())
                })
            })
            .await
        })
    }
}

/// A row of `scheduling_inbox`.
#[derive(sqlx::FromRow)]
struct InboxRow {
    tenant_id: Uuid,
    id: Uuid,
    principal_id: Uuid,
    uri: String,
    etag: String,
    data: String,
    quarantined: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl InboxRow {
    fn into_item(self) -> Result<InboxItem, StoreError> {
        Ok(InboxItem {
            id: InboxItemId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            principal_id: PrincipalId::from_uuid(self.principal_id),
            uri: decode("inbox uri", ObjectUri::parse(&self.uri))?,
            etag: decode("etag", ETag::parse(&self.etag))?,
            data: self.data,
            quarantined: self.quarantined,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

#[async_trait]
impl InboxRepo for PgTx {
    async fn get(&mut self, id: InboxItemId) -> Result<InboxItem, StoreError> {
        observed!("inbox.get", {
            let row = sqlx::query_as::<_, InboxRow>(concat!(
                "SELECT ",
                inbox_columns!(""),
                " FROM scheduling_inbox WHERE tenant_id = $1 AND id = $2"
            ))
            .bind(self.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_item()
        })
    }

    async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<InboxItem, StoreError> {
        observed!("inbox.get_by_uri", {
            let row = sqlx::query_as::<_, InboxRow>(concat!(
                "SELECT ",
                inbox_columns!(""),
                " FROM scheduling_inbox WHERE tenant_id = $1 AND principal_id = $2 AND uri = $3"
            ))
            .bind(self.tenant.as_uuid())
            .bind(principal.as_uuid())
            .bind(uri.as_str())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_item()
        })
    }

    async fn get_many_by_uri(
        &mut self,
        principal: PrincipalId,
        uris: &[ObjectUri],
    ) -> Result<Vec<InboxItem>, StoreError> {
        observed!("inbox.get_many_by_uri", {
            let names: Vec<&str> = uris.iter().map(ObjectUri::as_str).collect();
            let rows = sqlx::query_as::<_, InboxRow>(concat!(
                "SELECT ",
                inbox_columns!(""),
                " FROM scheduling_inbox WHERE tenant_id = $1 AND principal_id = $2 AND uri = ANY($3)"
            ))
            .bind(self.tenant.as_uuid())
            .bind(principal.as_uuid())
            .bind(&names)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let mut stored: std::collections::HashMap<String, InboxItem> = std::collections::HashMap::new();
            for row in rows {
                let item = row.into_item()?;
                stored.insert(item.uri.as_str().to_owned(), item);
            }
            Ok(uris.iter().filter_map(|uri| stored.remove(uri.as_str())).collect())
        })
    }

    async fn list(&mut self, principal: PrincipalId, scope: InboxScope) -> Result<Vec<InboxItem>, StoreError> {
        observed!("inbox.list", {
            let rows = sqlx::query_as::<_, InboxRow>(concat!(
                "SELECT ",
                inbox_columns!(""),
                " FROM scheduling_inbox WHERE tenant_id = $1 AND principal_id = $2 AND quarantined = $3 ORDER BY id"
            ))
            .bind(self.tenant.as_uuid())
            .bind(principal.as_uuid())
            .bind(scope == InboxScope::Quarantined)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            rows.into_iter().map(InboxRow::into_item).collect()
        })
    }

    async fn create(&mut self, item: InboxItem) -> Result<InboxItem, StoreError> {
        observed!("inbox.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, InboxRow>(concat!(
                        "INSERT INTO scheduling_inbox (tenant_id, id, principal_id, uri, etag, data, quarantined, \
                         created_at, updated_at, version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, 1) RETURNING ",
                        inbox_columns!("")
                    ))
                    .bind(tenant)
                    .bind(item.id.as_uuid())
                    .bind(item.principal_id.as_uuid())
                    .bind(item.uri.as_str())
                    .bind(item.etag.as_str())
                    .bind(&item.data)
                    .bind(item.quarantined)
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    let created = row.into_item()?;
                    // A quarantined item is never shown to clients: it does not move the inbox's sync token.
                    if !created.quarantined {
                        let change = PrincipalChange {
                            tenant,
                            principal: created.principal_id.as_uuid(),
                            kind: CollectionKind::Inbox,
                            uri: created.uri.as_str(),
                            change: ChangeKind::Upsert,
                            at: now,
                        };
                        record_principal_change(&mut *conn, &change).await?;
                    }
                    Ok(created)
                })
            })
            .await
        })
    }

    async fn delete(&mut self, id: InboxItemId) -> Result<(), StoreError> {
        observed!("inbox.delete", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let removed = sqlx::query_as::<_, (Uuid, String, bool)>(
                        "DELETE FROM scheduling_inbox WHERE tenant_id = $1 AND id = $2 \
                         RETURNING principal_id, uri, quarantined",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    let Some((principal, uri, quarantined)) = removed else {
                        return Err(StoreError::NotFound);
                    };
                    if quarantined {
                        return Ok(());
                    }
                    let change = PrincipalChange {
                        tenant,
                        principal,
                        kind: CollectionKind::Inbox,
                        uri: &uri,
                        change: ChangeKind::Delete,
                        at: now,
                    };
                    record_principal_change(&mut *conn, &change).await?;
                    Ok(())
                })
            })
            .await
        })
    }
}
