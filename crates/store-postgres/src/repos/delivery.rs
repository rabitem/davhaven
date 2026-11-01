//! The outbox, webhook subscriptions and deliveries, provider accounts and OAuth states.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarId, DeliveryId, EventId, EventType, ExternalAccount, ExternalAccountId, ExternalAccountStatus, OutboxId,
    PrincipalId, TenantId, WebhookId, WebhookSubscription,
};
use davhaven_ports::{
    DeliveryRecord, DeliveryStatus, ExternalAccountFilter, ExternalAccountRepo, NewOutbox, OAuthState, OAuthStateRepo,
    OutboxFilter, OutboxRecord, OutboxRepo, OutboxStatus, PageReq, StoreError, StorePage, WebhookRepo,
};
use uuid::Uuid;

use super::{DbResult, corrupt, decode, micros, stale_or_missing};
use crate::tx::PgTx;

/// A row of `outbox`.
#[derive(sqlx::FromRow)]
pub(super) struct OutboxRow {
    tenant_id: Uuid,
    id: Uuid,
    kind: String,
    payload: serde_json::Value,
    schema_version: i32,
    status: String,
    attempts: i32,
    next_attempt_at: DateTime<Utc>,
    locked_until: Option<DateTime<Utc>>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl OutboxRow {
    pub(super) fn into_record(self) -> Result<OutboxRecord, StoreError> {
        Ok(OutboxRecord {
            id: OutboxId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            kind: self.kind,
            schema_version: u32::try_from(self.schema_version)
                .map_err(|_| corrupt("outbox schema version", "negative"))?,
            payload: self.payload,
            status: OutboxStatus::ALL
                .into_iter()
                .find(|status| status.as_str() == self.status)
                .ok_or_else(|| corrupt("outbox status", &self.status))?,
            attempts: u32::try_from(self.attempts).map_err(|_| corrupt("outbox attempts", "negative"))?,
            next_attempt_at: self.next_attempt_at,
            locked_until: self.locked_until,
            last_error: self.last_error,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[async_trait]
impl OutboxRepo for PgTx {
    async fn enqueue(&mut self, message: NewOutbox) -> Result<(), StoreError> {
        observed!("outbox.enqueue", {
            let (kind, schema_version, payload) = message
                .message
                .to_parts()
                .map_err(|error| StoreError::internal(format!("outbox message cannot be serialized: {error}")))?;
            let now = micros(self.clock.now());
            let due = message.not_before.map_or(now, micros);
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO outbox (tenant_id, id, kind, payload, schema_version, status, attempts, \
                         next_attempt_at, locked_until, last_error, created_at, updated_at) \
                         VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6, NULL, NULL, $7, $7)",
                    )
                    .bind(tenant)
                    .bind(message.id.as_uuid())
                    .bind(kind)
                    .bind(payload)
                    .bind(i32::try_from(schema_version).unwrap_or(i32::MAX))
                    .bind(due)
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

    async fn get(&mut self, id: OutboxId) -> Result<OutboxRecord, StoreError> {
        observed!("outbox.get", {
            let row = sqlx::query_as::<_, OutboxRow>(concat!(
                "SELECT ",
                outbox_columns!(""),
                " FROM outbox WHERE tenant_id = $1 AND id = $2"
            ))
            .bind(self.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_record()
        })
    }

    async fn list(&mut self, filter: &OutboxFilter, page: PageReq) -> Result<StorePage<OutboxRecord>, StoreError> {
        observed!("outbox.list", {
            let rows = sqlx::query_as::<_, OutboxRow>(concat!(
                "SELECT ",
                outbox_columns!(""),
                " FROM outbox WHERE tenant_id = $1 \
                 AND ($2::text IS NULL OR status = $2) \
                 AND ($3::text IS NULL OR kind = $3) \
                 AND ($4::uuid IS NULL OR id > $4) \
                 ORDER BY id LIMIT $5"
            ))
            .bind(self.tenant.as_uuid())
            .bind(filter.status.map(OutboxStatus::as_str))
            .bind(filter.kind.as_deref())
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let records = rows
                .into_iter()
                .map(OutboxRow::into_record)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(records, &page, |record| {
                record.id.as_uuid()
            }))
        })
    }

    async fn requeue(&mut self, id: OutboxId) -> Result<(), StoreError> {
        observed!("outbox.requeue", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let done = sqlx::query_scalar::<_, i32>(
                        "UPDATE outbox SET status = 'pending', attempts = 0, next_attempt_at = $3, \
                         locked_until = NULL, updated_at = $3 \
                         WHERE tenant_id = $1 AND id = $2 AND status = 'dead' RETURNING 1",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .bind(now)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    if done.is_some() {
                        return Ok(());
                    }
                    Err(stale_or_missing(
                        conn,
                        "SELECT 1 FROM outbox WHERE tenant_id = $1 AND id = $2",
                        tenant,
                        id.as_uuid(),
                    )
                    .await)
                })
            })
            .await
        })
    }
}

/// A row of `webhook_subscriptions`.
#[derive(sqlx::FromRow)]
struct WebhookRow {
    tenant_id: Uuid,
    id: Uuid,
    url: String,
    description: Option<String>,
    sealed_secret: Vec<u8>,
    sealed_secret_previous: Option<Vec<u8>>,
    secret_rotated_at: Option<DateTime<Utc>>,
    events: Vec<String>,
    include_details: bool,
    active: bool,
    failure_count: i32,
    disabled_reason: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl WebhookRow {
    fn into_subscription(self) -> Result<WebhookSubscription, StoreError> {
        Ok(WebhookSubscription {
            id: WebhookId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            url: url::Url::parse(&self.url).map_err(|error| corrupt("webhook url", error))?,
            description: self.description,
            sealed_secret: self.sealed_secret,
            sealed_secret_previous: self.sealed_secret_previous,
            secret_rotated_at: self.secret_rotated_at,
            // An event type written by a newer release is not shown (the entity cannot hold it): the subscription
            // then receives less here, and `update` keeps the stored name instead of writing the shorter list back
            // (R16: an old instance that patches a subscription must not remove what a newer one wrote).
            events: self
                .events
                .iter()
                .filter_map(|event| event.parse::<EventType>().ok())
                .collect(),
            include_details: self.include_details,
            active: self.active,
            failure_count: u32::try_from(self.failure_count).map_err(|_| corrupt("failure count", "negative"))?,
            disabled_reason: self.disabled_reason,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

/// A row of `webhook_deliveries`.
#[derive(sqlx::FromRow)]
struct DeliveryRow {
    tenant_id: Uuid,
    id: Uuid,
    subscription_id: Uuid,
    event_id: Uuid,
    status: String,
    attempts: i32,
    response_status: Option<i32>,
    last_error: Option<String>,
    at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl DeliveryRow {
    fn into_delivery(self) -> Result<DeliveryRecord, StoreError> {
        Ok(DeliveryRecord {
            id: DeliveryId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            subscription_id: WebhookId::from_uuid(self.subscription_id),
            event_id: EventId::from_uuid(self.event_id),
            status: DeliveryStatus::ALL
                .into_iter()
                .find(|status| status.as_str() == self.status)
                .ok_or_else(|| corrupt("delivery status", &self.status))?,
            attempts: u32::try_from(self.attempts).map_err(|_| corrupt("delivery attempts", "negative"))?,
            response_status: self
                .response_status
                .map(|status| u16::try_from(status).map_err(|_| corrupt("response status", status)))
                .transpose()?,
            last_error: self.last_error,
            at: self.at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

/// The spelling of the event types; `update` also sends the names this release knows, so the statement can
/// keep the stored ones it does not.
fn event_names(events: &[EventType]) -> Vec<&'static str> {
    events.iter().copied().map(EventType::as_str).collect()
}

#[async_trait]
impl WebhookRepo for PgTx {
    async fn get(&mut self, id: WebhookId) -> Result<WebhookSubscription, StoreError> {
        observed!("webhooks.get", {
            let row = sqlx::query_as::<_, WebhookRow>(concat!(
                "SELECT ",
                webhook_columns!(""),
                " FROM webhook_subscriptions WHERE tenant_id = $1 AND id = $2"
            ))
            .bind(self.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_subscription()
        })
    }

    async fn list(&mut self, page: PageReq) -> Result<StorePage<WebhookSubscription>, StoreError> {
        observed!("webhooks.list", {
            let rows = sqlx::query_as::<_, WebhookRow>(concat!(
                "SELECT ",
                webhook_columns!(""),
                " FROM webhook_subscriptions WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2) \
                 ORDER BY id LIMIT $3"
            ))
            .bind(self.tenant.as_uuid())
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let subscriptions = rows
                .into_iter()
                .map(WebhookRow::into_subscription)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(subscriptions, &page, |subscription| {
                subscription.id.as_uuid()
            }))
        })
    }

    async fn subscribed_to(&mut self, event_type: EventType) -> Result<Vec<WebhookSubscription>, StoreError> {
        observed!("webhooks.subscribed_to", {
            let rows = sqlx::query_as::<_, WebhookRow>(concat!(
                "SELECT ",
                webhook_columns!(""),
                " FROM webhook_subscriptions WHERE tenant_id = $1 AND active AND $2 = ANY(events) ORDER BY id"
            ))
            .bind(self.tenant.as_uuid())
            .bind(event_type.as_str())
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            rows.into_iter().map(WebhookRow::into_subscription).collect()
        })
    }

    async fn create(&mut self, subscription: WebhookSubscription) -> Result<WebhookSubscription, StoreError> {
        observed!("webhooks.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, WebhookRow>(concat!(
                        "INSERT INTO webhook_subscriptions (tenant_id, id, url, description, sealed_secret, \
                         sealed_secret_previous, secret_rotated_at, events, include_details, active, failure_count, \
                         disabled_reason, created_at, updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13, 1) RETURNING ",
                        webhook_columns!("")
                    ))
                    .bind(tenant)
                    .bind(subscription.id.as_uuid())
                    .bind(subscription.url.as_str())
                    .bind(subscription.description.as_deref())
                    .bind(&subscription.sealed_secret)
                    .bind(subscription.sealed_secret_previous.as_deref())
                    .bind(subscription.secret_rotated_at.map(micros))
                    .bind(event_names(&subscription.events))
                    .bind(subscription.include_details)
                    .bind(subscription.active)
                    .bind(i32::try_from(subscription.failure_count).unwrap_or(i32::MAX))
                    .bind(subscription.disabled_reason.as_deref())
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    row.into_subscription()
                })
            })
            .await
        })
    }

    async fn update(
        &mut self,
        subscription: WebhookSubscription,
        expected_version: i64,
    ) -> Result<WebhookSubscription, StoreError> {
        observed!("webhooks.update", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, WebhookRow>(concat!(
                        "UPDATE webhook_subscriptions SET url = $3, description = $4, sealed_secret = $5, \
                         sealed_secret_previous = $6, secret_rotated_at = $7, \
                         events = $8::text[] || ARRAY(SELECT e FROM unnest(events) AS e WHERE e <> ALL($14::text[])), \
                         include_details = $9, \
                         failure_count = CASE WHEN $10 AND NOT active THEN 0 ELSE failure_count END, \
                         active = $10, disabled_reason = $11, updated_at = $12, \
                         version = version + 1 WHERE tenant_id = $1 AND id = $2 AND version = $13 RETURNING ",
                        webhook_columns!("")
                    ))
                    .bind(tenant)
                    .bind(subscription.id.as_uuid())
                    .bind(subscription.url.as_str())
                    .bind(subscription.description.as_deref())
                    .bind(&subscription.sealed_secret)
                    .bind(subscription.sealed_secret_previous.as_deref())
                    .bind(subscription.secret_rotated_at.map(micros))
                    .bind(event_names(&subscription.events))
                    .bind(subscription.include_details)
                    .bind(subscription.active)
                    .bind(subscription.disabled_reason.as_deref())
                    .bind(now)
                    .bind(expected_version)
                    .bind(event_names(EventType::ALL))
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    match row {
                        Some(row) => row.into_subscription(),
                        None => Err(stale_or_missing(
                            conn,
                            "SELECT 1 FROM webhook_subscriptions WHERE tenant_id = $1 AND id = $2",
                            tenant,
                            subscription.id.as_uuid(),
                        )
                        .await),
                    }
                })
            })
            .await
        })
    }

    async fn delete(&mut self, id: WebhookId) -> Result<(), StoreError> {
        observed!("webhooks.delete", {
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let removed = sqlx::query("DELETE FROM webhook_subscriptions WHERE tenant_id = $1 AND id = $2")
                        .bind(tenant)
                        .bind(id.as_uuid())
                        .execute(&mut *conn)
                        .await
                        .db()?
                        .rows_affected();
                    if removed == 0 {
                        Err(StoreError::NotFound)
                    } else {
                        Ok(())
                    }
                })
            })
            .await
        })
    }

    async fn record_success(&mut self, id: WebhookId) -> Result<(), StoreError> {
        observed!("webhooks.record_success", {
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let changed = sqlx::query(
                        "UPDATE webhook_subscriptions SET failure_count = 0 WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
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

    async fn record_failure(&mut self, id: WebhookId) -> Result<u32, StoreError> {
        observed!("webhooks.record_failure", {
            let tenant = self.tenant.as_uuid();
            let count = self
                .guarded(move |conn| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, i32>(
                            "UPDATE webhook_subscriptions SET failure_count = failure_count + 1 \
                             WHERE tenant_id = $1 AND id = $2 RETURNING failure_count",
                        )
                        .bind(tenant)
                        .bind(id.as_uuid())
                        .fetch_optional(&mut *conn)
                        .await
                        .db()?
                        .ok_or(StoreError::NotFound)
                    })
                })
                .await?;
            u32::try_from(count).map_err(|_| corrupt("failure count", "negative"))
        })
    }

    async fn disable(&mut self, id: WebhookId, reason: &str) -> Result<(), StoreError> {
        observed!("webhooks.disable", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let reason = reason.to_owned();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let changed = sqlx::query(
                        "UPDATE webhook_subscriptions SET active = false, disabled_reason = $3, updated_at = $4, \
                         version = version + 1 WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .bind(&reason)
                    .bind(now)
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

    async fn create_delivery(&mut self, delivery: DeliveryRecord) -> Result<DeliveryRecord, StoreError> {
        observed!("webhooks.create_delivery", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, DeliveryRow>(concat!(
                        "INSERT INTO webhook_deliveries (tenant_id, id, subscription_id, event_id, status, attempts, \
                         response_status, last_error, at, created_at, updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, 1) \
                         ON CONFLICT (tenant_id, subscription_id, event_id) DO NOTHING RETURNING ",
                        delivery_columns!("")
                    ))
                    .bind(tenant)
                    .bind(delivery.id.as_uuid())
                    .bind(delivery.subscription_id.as_uuid())
                    .bind(delivery.event_id.as_uuid())
                    .bind(delivery.status.as_str())
                    .bind(i32::try_from(delivery.attempts).unwrap_or(i32::MAX))
                    .bind(delivery.response_status.map(i32::from))
                    .bind(delivery.last_error.as_deref())
                    .bind(micros(delivery.at))
                    .bind(now)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    if let Some(row) = row {
                        return row.into_delivery();
                    }
                    // The event was fanned out to this subscription before (a repeated fan-out): that record stands.
                    let existing = sqlx::query_as::<_, DeliveryRow>(concat!(
                        "SELECT ",
                        delivery_columns!(""),
                        " FROM webhook_deliveries WHERE tenant_id = $1 AND subscription_id = $2 AND event_id = $3"
                    ))
                    .bind(tenant)
                    .bind(delivery.subscription_id.as_uuid())
                    .bind(delivery.event_id.as_uuid())
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    existing.into_delivery()
                })
            })
            .await
        })
    }

    async fn get_delivery(&mut self, id: DeliveryId) -> Result<DeliveryRecord, StoreError> {
        observed!("webhooks.get_delivery", {
            let row = sqlx::query_as::<_, DeliveryRow>(concat!(
                "SELECT ",
                delivery_columns!(""),
                " FROM webhook_deliveries WHERE tenant_id = $1 AND id = $2"
            ))
            .bind(self.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_delivery()
        })
    }

    async fn list_deliveries(
        &mut self,
        subscription: WebhookId,
        page: PageReq,
    ) -> Result<StorePage<DeliveryRecord>, StoreError> {
        observed!("webhooks.list_deliveries", {
            let tenant = self.tenant.as_uuid();
            let exists =
                sqlx::query_scalar::<_, i32>("SELECT 1 FROM webhook_subscriptions WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant)
                    .bind(subscription.as_uuid())
                    .fetch_optional(&mut *self.conn)
                    .await
                    .db()?;
            if exists.is_none() {
                return Err(StoreError::NotFound);
            }
            let rows = sqlx::query_as::<_, DeliveryRow>(concat!(
                "SELECT ",
                delivery_columns!(""),
                " FROM webhook_deliveries WHERE tenant_id = $1 AND subscription_id = $2 \
                 AND ($3::uuid IS NULL OR id > $3) ORDER BY id LIMIT $4"
            ))
            .bind(tenant)
            .bind(subscription.as_uuid())
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let deliveries = rows
                .into_iter()
                .map(DeliveryRow::into_delivery)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(deliveries, &page, |delivery| {
                delivery.id.as_uuid()
            }))
        })
    }

    async fn update_delivery(
        &mut self,
        delivery: DeliveryRecord,
        expected_version: i64,
    ) -> Result<DeliveryRecord, StoreError> {
        observed!("webhooks.update_delivery", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, DeliveryRow>(concat!(
                        "UPDATE webhook_deliveries SET status = $3, attempts = $4, response_status = $5, \
                         last_error = $6, at = $7, updated_at = $8, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND version = $9 RETURNING ",
                        delivery_columns!("")
                    ))
                    .bind(tenant)
                    .bind(delivery.id.as_uuid())
                    .bind(delivery.status.as_str())
                    .bind(i32::try_from(delivery.attempts).unwrap_or(i32::MAX))
                    .bind(delivery.response_status.map(i32::from))
                    .bind(delivery.last_error.as_deref())
                    .bind(micros(delivery.at))
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    match row {
                        Some(row) => row.into_delivery(),
                        None => Err(stale_or_missing(
                            conn,
                            "SELECT 1 FROM webhook_deliveries WHERE tenant_id = $1 AND id = $2",
                            tenant,
                            delivery.id.as_uuid(),
                        )
                        .await),
                    }
                })
            })
            .await
        })
    }
}

/// A row of `external_accounts`.
#[derive(sqlx::FromRow)]
struct AccountRow {
    tenant_id: Uuid,
    id: Uuid,
    principal_id: Uuid,
    provider: String,
    account_ref: String,
    sealed_tokens: Vec<u8>,
    mirror_calendar_id: Option<Uuid>,
    sync_state: serde_json::Value,
    status: String,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl AccountRow {
    fn into_account(self) -> Result<ExternalAccount, StoreError> {
        Ok(ExternalAccount {
            id: ExternalAccountId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            principal_id: PrincipalId::from_uuid(self.principal_id),
            provider: self.provider,
            account_ref: self.account_ref,
            sealed_tokens: self.sealed_tokens,
            mirror_calendar_id: self.mirror_calendar_id.map(CalendarId::from_uuid),
            sync_state: self.sync_state,
            status: decode("account status", self.status.parse::<ExternalAccountStatus>())?,
            last_error: self.last_error,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

#[async_trait]
impl ExternalAccountRepo for PgTx {
    async fn get(&mut self, id: ExternalAccountId) -> Result<ExternalAccount, StoreError> {
        observed!("external_accounts.get", {
            let row = sqlx::query_as::<_, AccountRow>(concat!(
                "SELECT ",
                external_account_columns!(""),
                " FROM external_accounts WHERE tenant_id = $1 AND id = $2"
            ))
            .bind(self.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_account()
        })
    }

    async fn list(
        &mut self,
        filter: &ExternalAccountFilter,
        page: PageReq,
    ) -> Result<StorePage<ExternalAccount>, StoreError> {
        observed!("external_accounts.list", {
            let rows = sqlx::query_as::<_, AccountRow>(concat!(
                "SELECT ",
                external_account_columns!(""),
                " FROM external_accounts WHERE tenant_id = $1 \
                 AND ($2::uuid IS NULL OR principal_id = $2) \
                 AND ($3::text IS NULL OR provider = $3) \
                 AND ($4::uuid IS NULL OR id > $4) \
                 ORDER BY id LIMIT $5"
            ))
            .bind(self.tenant.as_uuid())
            .bind(filter.principal.map(PrincipalId::as_uuid))
            .bind(filter.provider.as_deref())
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let accounts = rows
                .into_iter()
                .map(AccountRow::into_account)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(accounts, &page, |account| {
                account.id.as_uuid()
            }))
        })
    }

    async fn create(&mut self, account: ExternalAccount) -> Result<ExternalAccount, StoreError> {
        observed!("external_accounts.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, AccountRow>(concat!(
                        "INSERT INTO external_accounts (tenant_id, id, principal_id, provider, account_ref, \
                         sealed_tokens, mirror_calendar_id, sync_state, status, last_error, created_at, updated_at, \
                         version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, 1) RETURNING ",
                        external_account_columns!("")
                    ))
                    .bind(tenant)
                    .bind(account.id.as_uuid())
                    .bind(account.principal_id.as_uuid())
                    .bind(&account.provider)
                    .bind(&account.account_ref)
                    .bind(&account.sealed_tokens)
                    .bind(account.mirror_calendar_id.map(CalendarId::as_uuid))
                    .bind(&account.sync_state)
                    .bind(account.status.as_str())
                    .bind(account.last_error.as_deref())
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    row.into_account()
                })
            })
            .await
        })
    }

    async fn update(&mut self, account: ExternalAccount, expected_version: i64) -> Result<ExternalAccount, StoreError> {
        observed!("external_accounts.update", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, AccountRow>(concat!(
                        "UPDATE external_accounts SET account_ref = $3, sealed_tokens = $4, mirror_calendar_id = $5, \
                         sync_state = $6, status = $7, last_error = $8, updated_at = $9, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND version = $10 RETURNING ",
                        external_account_columns!("")
                    ))
                    .bind(tenant)
                    .bind(account.id.as_uuid())
                    .bind(&account.account_ref)
                    .bind(&account.sealed_tokens)
                    .bind(account.mirror_calendar_id.map(CalendarId::as_uuid))
                    .bind(&account.sync_state)
                    .bind(account.status.as_str())
                    .bind(account.last_error.as_deref())
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    match row {
                        Some(row) => row.into_account(),
                        None => Err(stale_or_missing(
                            conn,
                            "SELECT 1 FROM external_accounts WHERE tenant_id = $1 AND id = $2",
                            tenant,
                            account.id.as_uuid(),
                        )
                        .await),
                    }
                })
            })
            .await
        })
    }

    async fn delete(&mut self, id: ExternalAccountId) -> Result<(), StoreError> {
        observed!("external_accounts.delete", {
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let removed = sqlx::query("DELETE FROM external_accounts WHERE tenant_id = $1 AND id = $2")
                        .bind(tenant)
                        .bind(id.as_uuid())
                        .execute(&mut *conn)
                        .await
                        .db()?
                        .rows_affected();
                    if removed == 0 {
                        Err(StoreError::NotFound)
                    } else {
                        Ok(())
                    }
                })
            })
            .await
        })
    }
}

/// A row of `oauth_states`.
#[derive(sqlx::FromRow)]
struct OAuthStateRow {
    tenant_id: Uuid,
    id: Uuid,
    principal_id: Uuid,
    provider: String,
    state_hash: Vec<u8>,
    pkce_verifier_sealed: Vec<u8>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl OAuthStateRow {
    fn into_state(self) -> OAuthState {
        OAuthState {
            id: self.id,
            tenant_id: TenantId::from_uuid(self.tenant_id),
            principal_id: PrincipalId::from_uuid(self.principal_id),
            provider: self.provider,
            state_hash: self.state_hash,
            pkce_verifier_sealed: self.pkce_verifier_sealed,
            expires_at: self.expires_at,
            used_at: self.used_at,
            created_at: self.created_at,
        }
    }
}

#[async_trait]
impl OAuthStateRepo for PgTx {
    async fn create(&mut self, state: OAuthState) -> Result<OAuthState, StoreError> {
        observed!("oauth_states.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, OAuthStateRow>(concat!(
                        "INSERT INTO oauth_states (tenant_id, id, principal_id, provider, state_hash, \
                         pkce_verifier_sealed, expires_at, used_at, created_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING ",
                        oauth_state_columns!("")
                    ))
                    .bind(tenant)
                    .bind(state.id)
                    .bind(state.principal_id.as_uuid())
                    .bind(&state.provider)
                    .bind(&state.state_hash)
                    .bind(&state.pkce_verifier_sealed)
                    .bind(micros(state.expires_at))
                    .bind(state.used_at.map(micros))
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    Ok(row.into_state())
                })
            })
            .await
        })
    }

    async fn consume(&mut self, state_hash: &[u8]) -> Result<OAuthState, StoreError> {
        observed!("oauth_states.consume", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let hash = state_hash.to_vec();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, OAuthStateRow>(concat!(
                        "UPDATE oauth_states SET used_at = $3 \
                         WHERE tenant_id = $1 AND state_hash = $2 AND used_at IS NULL AND expires_at > $3 RETURNING ",
                        oauth_state_columns!("")
                    ))
                    .bind(tenant)
                    .bind(&hash)
                    .bind(now)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    row.map(OAuthStateRow::into_state).ok_or(StoreError::NotFound)
                })
            })
            .await
        })
    }
}
