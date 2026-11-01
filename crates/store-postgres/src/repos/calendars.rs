//! Calendars, bindings, collection properties and grants.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    AccessFacts, Binding, BindingFact, BindingId, Calendar, CalendarId, CalendarKind, CalendarSlug, CollectionKind,
    ComponentKind, Grant, GrantAccess, GrantFact, GrantId, GrantSource, GrantStatus, PrincipalId, PrincipalKind,
    TenantId, TenantSettings, Transparency, Uid,
};
use davhaven_ports::{
    BindingRepo, BoundCalendar, CalendarFilter, CalendarRepo, ChangeKind, CollectionProperty, GrantRepo, PageReq,
    PropertyRepo, PropertyScope, StoreError, StorePage,
};
use serde::Deserialize;
use sqlx::PgConnection;
use uuid::Uuid;

use super::sync::{PrincipalChange, bump_calendar, record_principal_change};
use super::{DbResult, corrupt, decode, decode_opt, micros, stale_or_missing, to_u64};
use crate::tx::{PgTx, begin_maintenance, end_maintenance};

/// A row of `calendars`.
#[derive(sqlx::FromRow)]
pub(super) struct CalendarRow {
    tenant_id: Uuid,
    id: Uuid,
    owner_id: Uuid,
    slug: String,
    kind: String,
    display_name: String,
    description: Option<String>,
    color: Option<String>,
    sort_order: i32,
    components: Vec<String>,
    timezone_ics: Option<String>,
    sync_seq: i64,
    sync_min_seq: i64,
    sync_epoch: Uuid,
    deleted_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl CalendarRow {
    /// Validates the row and builds the entity.
    pub(super) fn into_calendar(self) -> Result<Calendar, StoreError> {
        let components = self
            .components
            .iter()
            .map(|token| ComponentKind::from_ical(token).ok_or_else(|| corrupt("calendar component", token)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Calendar {
            id: CalendarId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            owner_id: PrincipalId::from_uuid(self.owner_id),
            slug: decode("calendar slug", CalendarSlug::parse(&self.slug))?,
            kind: decode("calendar kind", self.kind.parse::<CalendarKind>())?,
            display_name: self.display_name,
            description: self.description,
            color: self.color,
            sort_order: self.sort_order,
            components,
            timezone_ics: self.timezone_ics,
            sync_seq: self.sync_seq,
            sync_min_seq: self.sync_min_seq,
            sync_epoch: self.sync_epoch,
            deleted_at: self.deleted_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

/// The `components` column: the iCalendar tokens of the component types.
fn component_tokens(components: &[ComponentKind]) -> Vec<&'static str> {
    components.iter().copied().map(ComponentKind::as_ical).collect()
}

/// Whether the live (not soft-deleted) calendar exists in the tenant.
pub(super) async fn calendar_exists(conn: &mut PgConnection, tenant: Uuid, id: Uuid) -> Result<bool, StoreError> {
    let found =
        sqlx::query_scalar::<_, i32>("SELECT 1 FROM calendars WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .db()?;
    Ok(found.is_some())
}

/// `NotFound` unless the live calendar exists in the tenant.
pub(super) async fn require_calendar(conn: &mut PgConnection, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
    if calendar_exists(conn, tenant, id).await? {
        Ok(())
    } else {
        Err(StoreError::NotFound)
    }
}

/// The row of the one-query authorization facts.
#[derive(sqlx::FromRow)]
struct FactsRow {
    id: Uuid,
    kind: String,
    owner_id: Uuid,
    owner_kind: String,
    settings: serde_json::Value,
    memberships: Vec<Uuid>,
    grants: serde_json::Value,
    binding_id: Option<Uuid>,
    binding_hidden: Option<bool>,
}

/// One grant inside the JSON aggregate of [`FactsRow`].
#[derive(Deserialize)]
struct GrantJson {
    grantee: Uuid,
    access: String,
    status: String,
    required: bool,
}

impl FactsRow {
    fn into_facts(self, settings: Arc<TenantSettings>) -> Result<(CalendarId, AccessFacts), StoreError> {
        let grants: Vec<GrantJson> =
            serde_json::from_value(self.grants).map_err(|error| corrupt("grant aggregate", error))?;
        let grants = grants
            .into_iter()
            .map(|grant| {
                Ok(GrantFact {
                    grantee: PrincipalId::from_uuid(grant.grantee),
                    access: decode("grant access", grant.access.parse::<GrantAccess>())?,
                    status: decode("grant status", grant.status.parse::<GrantStatus>())?,
                    required: grant.required,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let binding = match (self.binding_id, self.binding_hidden) {
            (Some(id), Some(hidden)) => Some(BindingFact {
                id: BindingId::from_uuid(id),
                hidden,
            }),
            _ => None,
        };
        let facts = AccessFacts {
            calendar_kind: decode("calendar kind", self.kind.parse::<CalendarKind>())?,
            owner: PrincipalId::from_uuid(self.owner_id),
            owner_kind: decode("principal kind", self.owner_kind.parse::<PrincipalKind>())?,
            memberships: self.memberships.into_iter().map(PrincipalId::from_uuid).collect(),
            grants,
            binding,
            tenant_settings: settings,
        };
        Ok((CalendarId::from_uuid(self.id), facts))
    }
}

impl PgTx {
    /// Loads the authorization facts of the calendars in one query.
    async fn facts_for(
        &mut self,
        calendars: &[Uuid],
        principal: Option<PrincipalId>,
    ) -> Result<BTreeMap<CalendarId, AccessFacts>, StoreError> {
        let rows = sqlx::query_as::<_, FactsRow>(
            "SELECT c.id, c.kind, c.owner_id, o.kind AS owner_kind, t.settings, \
               COALESCE((SELECT array_agg(m.group_id ORDER BY m.group_id) FROM memberships m \
                         WHERE m.tenant_id = c.tenant_id AND m.member_id = $3::uuid), ARRAY[]::uuid[]) AS memberships, \
               COALESCE((SELECT jsonb_agg(jsonb_build_object('grantee', g.grantee_id, 'access', g.access, \
                                                             'status', g.status, 'required', g.required) \
                                         ORDER BY g.id) \
                         FROM calendar_grants g WHERE g.tenant_id = c.tenant_id AND g.calendar_id = c.id), \
                        '[]'::jsonb) AS grants, \
               b.id AS binding_id, b.hidden AS binding_hidden \
             FROM calendars c \
             JOIN principals o ON o.tenant_id = c.tenant_id AND o.id = c.owner_id \
             JOIN tenants t ON t.id = c.tenant_id \
             LEFT JOIN calendar_bindings b ON b.tenant_id = c.tenant_id AND b.calendar_id = c.id \
                                          AND b.principal_id = $3::uuid \
             WHERE c.tenant_id = $1 AND c.id = ANY($2) AND c.deleted_at IS NULL",
        )
        .bind(self.tenant.as_uuid())
        .bind(calendars)
        .bind(principal.map(PrincipalId::as_uuid))
        .fetch_all(&mut *self.conn)
        .await
        .db()?;
        let mut settings: Option<Arc<TenantSettings>> = None;
        let mut facts = BTreeMap::new();
        for row in rows {
            let shared = if let Some(shared) = &settings {
                Arc::clone(shared)
            } else {
                let parsed: TenantSettings =
                    serde_json::from_value(row.settings.clone()).map_err(|error| corrupt("tenant settings", error))?;
                let shared = Arc::new(parsed);
                settings = Some(Arc::clone(&shared));
                shared
            };
            let (id, row_facts) = row.into_facts(shared)?;
            facts.insert(id, row_facts);
        }
        Ok(facts)
    }

    /// The live calendars with the ids, in id order.
    async fn calendars_by_ids(&mut self, ids: &[Uuid]) -> Result<Vec<Calendar>, StoreError> {
        let rows = sqlx::query_as::<_, CalendarRow>(concat!(
            "SELECT ",
            calendar_columns!(""),
            " FROM calendars WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL ORDER BY id"
        ))
        .bind(self.tenant.as_uuid())
        .bind(ids)
        .fetch_all(&mut *self.conn)
        .await
        .db()?;
        rows.into_iter().map(CalendarRow::into_calendar).collect()
    }
}

#[async_trait]
impl CalendarRepo for PgTx {
    async fn get(&mut self, id: CalendarId) -> Result<Calendar, StoreError> {
        observed!("calendars.get", {
            let mut calendars = self.calendars_by_ids(&[id.as_uuid()]).await?;
            calendars.pop().ok_or(StoreError::NotFound)
        })
    }

    async fn get_many(&mut self, ids: &[CalendarId]) -> Result<Vec<Calendar>, StoreError> {
        observed!("calendars.get_many", {
            let uuids: Vec<Uuid> = ids.iter().copied().map(CalendarId::as_uuid).collect();
            self.calendars_by_ids(&uuids).await
        })
    }

    async fn get_by_slug(&mut self, owner: PrincipalId, slug: &CalendarSlug) -> Result<Calendar, StoreError> {
        observed!("calendars.get_by_slug", {
            let row = sqlx::query_as::<_, CalendarRow>(concat!(
                "SELECT ",
                calendar_columns!(""),
                " FROM calendars WHERE tenant_id = $1 AND owner_id = $2 AND slug = $3 AND deleted_at IS NULL"
            ))
            .bind(self.tenant.as_uuid())
            .bind(owner.as_uuid())
            .bind(slug.as_str())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_calendar()
        })
    }

    async fn list_owned(&mut self, owner: PrincipalId) -> Result<Vec<Calendar>, StoreError> {
        observed!("calendars.list_owned", {
            let rows = sqlx::query_as::<_, CalendarRow>(concat!(
                "SELECT ",
                calendar_columns!(""),
                " FROM calendars WHERE tenant_id = $1 AND owner_id = $2 AND deleted_at IS NULL ORDER BY id"
            ))
            .bind(self.tenant.as_uuid())
            .bind(owner.as_uuid())
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            rows.into_iter().map(CalendarRow::into_calendar).collect()
        })
    }

    async fn list(&mut self, filter: &CalendarFilter, page: PageReq) -> Result<StorePage<Calendar>, StoreError> {
        observed!("calendars.list", {
            let rows = sqlx::query_as::<_, CalendarRow>(concat!(
                "SELECT ",
                calendar_columns!(""),
                " FROM calendars WHERE tenant_id = $1 AND deleted_at IS NULL \
                 AND ($2::uuid IS NULL OR owner_id = $2) \
                 AND ($3::text IS NULL OR kind = $3) \
                 AND ($4::text IS NULL OR slug = $4) \
                 AND ($5::text IS NULL OR strpos(lower(display_name), $5) > 0) \
                 AND ($6::uuid IS NULL OR id > $6) \
                 ORDER BY id LIMIT $7"
            ))
            .bind(self.tenant.as_uuid())
            .bind(filter.owner.map(PrincipalId::as_uuid))
            .bind(filter.kind.map(CalendarKind::as_str))
            .bind(filter.slug.as_ref().map(CalendarSlug::as_str))
            .bind(filter.text.as_ref().map(|text| text.to_lowercase()))
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let calendars = rows
                .into_iter()
                .map(CalendarRow::into_calendar)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(calendars, &page, |calendar| {
                calendar.id.as_uuid()
            }))
        })
    }

    async fn visible_without_binding(&mut self, principal: PrincipalId) -> Result<Vec<Calendar>, StoreError> {
        observed!("calendars.visible_without_binding", {
            let rows = sqlx::query_as::<_, CalendarRow>(concat!(
                "SELECT ",
                calendar_columns!("c."),
                " FROM calendars c WHERE c.tenant_id = $1 AND c.deleted_at IS NULL AND c.owner_id <> $2 \
                 AND NOT EXISTS (SELECT 1 FROM calendar_bindings b WHERE b.tenant_id = c.tenant_id \
                                 AND b.principal_id = $2 AND b.calendar_id = c.id) \
                 AND (c.owner_id IN (SELECT m.group_id FROM memberships m WHERE m.tenant_id = $1 AND m.member_id = $2) \
                      OR EXISTS (SELECT 1 FROM calendar_grants g WHERE g.tenant_id = c.tenant_id \
                                 AND g.calendar_id = c.id AND g.status = 'accepted' \
                                 AND (g.grantee_id = $2 OR g.grantee_id IN \
                                      (SELECT m.group_id FROM memberships m WHERE m.tenant_id = $1 AND m.member_id = $2)))) \
                 ORDER BY c.id"
            ))
            .bind(self.tenant.as_uuid())
            .bind(principal.as_uuid())
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            rows.into_iter().map(CalendarRow::into_calendar).collect()
        })
    }

    async fn access_facts(
        &mut self,
        calendar: CalendarId,
        principal: Option<PrincipalId>,
    ) -> Result<AccessFacts, StoreError> {
        observed!("calendars.access_facts", {
            let mut facts = self.facts_for(&[calendar.as_uuid()], principal).await?;
            facts.remove(&calendar).ok_or(StoreError::NotFound)
        })
    }

    async fn access_facts_many(
        &mut self,
        calendars: &[CalendarId],
        principal: Option<PrincipalId>,
    ) -> Result<Vec<(CalendarId, AccessFacts)>, StoreError> {
        observed!("calendars.access_facts_many", {
            let ids: Vec<Uuid> = calendars.iter().copied().map(CalendarId::as_uuid).collect();
            let facts = self.facts_for(&ids, principal).await?;
            Ok(calendars
                .iter()
                .filter_map(|id| facts.get(id).map(|found| (*id, found.clone())))
                .collect())
        })
    }

    async fn create(&mut self, calendar: Calendar) -> Result<Calendar, StoreError> {
        observed!("calendars.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, CalendarRow>(concat!(
                        "INSERT INTO calendars (tenant_id, id, owner_id, slug, kind, display_name, description, color, \
                         sort_order, components, timezone_ics, sync_seq, sync_min_seq, sync_epoch, deleted_at, \
                         created_at, updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 0, 0, $12, NULL, $13, $13, 1) RETURNING ",
                        calendar_columns!("")
                    ))
                    .bind(tenant)
                    .bind(calendar.id.as_uuid())
                    .bind(calendar.owner_id.as_uuid())
                    .bind(calendar.slug.as_str())
                    .bind(calendar.kind.as_str())
                    .bind(&calendar.display_name)
                    .bind(calendar.description.as_deref())
                    .bind(calendar.color.as_deref())
                    .bind(calendar.sort_order)
                    .bind(component_tokens(&calendar.components))
                    .bind(calendar.timezone_ics.as_deref())
                    .bind(calendar.sync_epoch)
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    row.into_calendar()
                })
            })
            .await
        })
    }

    async fn update(&mut self, calendar: Calendar, expected_version: i64) -> Result<Calendar, StoreError> {
        observed!("calendars.update", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, CalendarRow>(concat!(
                        "UPDATE calendars SET display_name = $3, description = $4, color = $5, sort_order = $6, \
                         components = $7, timezone_ics = $8, updated_at = $9, version = version + 1, \
                         sync_seq = sync_seq + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND version = $10 AND deleted_at IS NULL RETURNING ",
                        calendar_columns!("")
                    ))
                    .bind(tenant)
                    .bind(calendar.id.as_uuid())
                    .bind(&calendar.display_name)
                    .bind(calendar.description.as_deref())
                    .bind(calendar.color.as_deref())
                    .bind(calendar.sort_order)
                    .bind(component_tokens(&calendar.components))
                    .bind(calendar.timezone_ics.as_deref())
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    match row {
                        Some(row) => row.into_calendar(),
                        None => Err(stale_or_missing(
                            conn,
                            "SELECT 1 FROM calendars WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL",
                            tenant,
                            calendar.id.as_uuid(),
                        )
                        .await),
                    }
                })
            })
            .await
        })
    }

    async fn soft_delete(&mut self, id: CalendarId, expected_version: i64) -> Result<(), StoreError> {
        observed!("calendars.soft_delete", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let maintenance = self.maintenance_timeout;
            self.guarded(move |conn| {
                Box::pin(async move {
                    let done = sqlx::query_scalar::<_, i32>(
                        "UPDATE calendars SET deleted_at = $3, updated_at = $3, version = version + 1, \
                         sync_seq = sync_seq + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND version = $4 AND deleted_at IS NULL RETURNING 1",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    if done.is_none() {
                        return Err(stale_or_missing(
                            conn,
                            "SELECT 1 FROM calendars WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL",
                            tenant,
                            id.as_uuid(),
                        )
                        .await);
                    }
                    // One UPDATE over every object row of the calendar (the flag is part of partial index
                    // predicates, so each row rewrites its index entries): as large as the calendar, hence under
                    // the maintenance timeout like the purge, not the 15 s of a request.
                    let previous = begin_maintenance(conn, maintenance).await?;
                    sqlx::query("UPDATE calendar_objects SET live = false WHERE tenant_id = $1 AND calendar_id = $2")
                        .bind(tenant)
                        .bind(id.as_uuid())
                        .execute(&mut *conn)
                        .await
                        .db()?;
                    end_maintenance(conn, &previous).await?;
                    // Every binding goes with the calendar (the properties private to a binding cascade): the
                    // owner's binding would otherwise keep its slug, so a calendar created under the same name
                    // could not be bound for the whole retention period, and the homes of the sharees would
                    // never learn that the collection is gone.
                    let removed = sqlx::query_as::<_, (Uuid, String)>(
                        "DELETE FROM calendar_bindings WHERE tenant_id = $1 AND calendar_id = $2 \
                         RETURNING principal_id, slug",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .fetch_all(&mut *conn)
                    .await
                    .db()?;
                    let mut removed = removed;
                    removed.sort();
                    for (principal, slug) in &removed {
                        let change = PrincipalChange {
                            tenant,
                            principal: *principal,
                            kind: CollectionKind::Home,
                            uri: slug,
                            change: ChangeKind::Delete,
                            at: now,
                        };
                        record_principal_change(&mut *conn, &change).await?;
                    }
                    Ok(())
                })
            })
            .await
        })
    }

    async fn lock(&mut self, ids: &[CalendarId]) -> Result<Vec<Calendar>, StoreError> {
        observed!("calendars.lock", {
            let mut uuids: Vec<Uuid> = ids.iter().copied().map(CalendarId::as_uuid).collect();
            uuids.sort_unstable();
            uuids.dedup();
            let tenant = self.tenant.as_uuid();
            // In a savepoint, like every statement that can fail: a read-only transaction refuses row locks, and
            // that refusal must not abort the whole transaction.
            self.guarded(move |conn| {
                Box::pin(async move {
                    let rows = sqlx::query_as::<_, CalendarRow>(concat!(
                        "SELECT ",
                        calendar_columns!(""),
                        " FROM calendars WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL \
                         ORDER BY id FOR NO KEY UPDATE"
                    ))
                    .bind(tenant)
                    .bind(&uuids)
                    .fetch_all(&mut *conn)
                    .await
                    .db()?;
                    if rows.len() != uuids.len() {
                        return Err(StoreError::NotFound);
                    }
                    rows.into_iter().map(CalendarRow::into_calendar).collect()
                })
            })
            .await
        })
    }

    async fn touch(&mut self, id: CalendarId) -> Result<u64, StoreError> {
        observed!("calendars.touch", {
            let tenant = self.tenant.as_uuid();
            let seq = self
                .guarded(move |conn| {
                    Box::pin(async move {
                        bump_calendar(conn, tenant, id.as_uuid())
                            .await?
                            .ok_or(StoreError::NotFound)
                    })
                })
                .await?;
            to_u64(seq)
        })
    }

    async fn purge(&mut self, id: CalendarId) -> Result<(), StoreError> {
        observed!("calendars.purge", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let maintenance = self.maintenance_timeout;
            self.guarded(move |conn| {
                Box::pin(async move {
                    let previous = begin_maintenance(conn, maintenance).await?;
                    sqlx::query(
                        "DELETE FROM collection_changes \
                         WHERE tenant_id = $1 AND collection_kind = 'calendar' AND collection_id = $2",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    let removed = sqlx::query(
                        "DELETE FROM calendars WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NOT NULL",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .execute(&mut *conn)
                    .await
                    .db()?
                    .rows_affected();
                    if removed == 0 {
                        return Err(StoreError::NotFound);
                    }
                    // A feed token names its calendars in an array without a foreign key: drop the dangling id.
                    sqlx::query(
                        "UPDATE feed_tokens SET calendar_ids = array_remove(calendar_ids, $2), updated_at = $3, \
                         version = version + 1 WHERE tenant_id = $1 AND $2 = ANY(calendar_ids)",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .bind(now)
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    end_maintenance(conn, &previous).await
                })
            })
            .await
        })
    }
}

/// A row of `calendar_bindings`.
#[derive(sqlx::FromRow)]
struct BindingRow {
    tenant_id: Uuid,
    id: Uuid,
    principal_id: Uuid,
    calendar_id: Uuid,
    slug: String,
    display_name: Option<String>,
    color: Option<String>,
    sort_order: Option<i32>,
    schedule_transp: Option<String>,
    hidden: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl BindingRow {
    fn into_binding(self) -> Result<Binding, StoreError> {
        Ok(Binding {
            id: BindingId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            principal_id: PrincipalId::from_uuid(self.principal_id),
            calendar_id: CalendarId::from_uuid(self.calendar_id),
            slug: decode("binding slug", CalendarSlug::parse(&self.slug))?,
            display_name: self.display_name,
            color: self.color,
            sort_order: self.sort_order,
            schedule_transp: self
                .schedule_transp
                .as_deref()
                .map(|token| Transparency::from_ical(token).ok_or_else(|| corrupt("binding transparency", token)))
                .transpose()?,
            hidden: self.hidden,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

impl PgTx {
    async fn select_bindings(
        &mut self,
        sql: &'static str,
        first: Uuid,
        second: Option<Uuid>,
    ) -> Result<Vec<Binding>, StoreError> {
        let mut query = sqlx::query_as::<_, BindingRow>(sql)
            .bind(self.tenant.as_uuid())
            .bind(first);
        if let Some(second) = second {
            query = query.bind(second);
        }
        let rows = query.fetch_all(&mut *self.conn).await.db()?;
        rows.into_iter().map(BindingRow::into_binding).collect()
    }
}

#[async_trait]
impl BindingRepo for PgTx {
    async fn get(&mut self, id: BindingId) -> Result<Binding, StoreError> {
        observed!("bindings.get", {
            self.select_bindings(
                concat!(
                    "SELECT ",
                    binding_columns!(""),
                    " FROM calendar_bindings WHERE tenant_id = $1 AND id = $2"
                ),
                id.as_uuid(),
                None,
            )
            .await?
            .pop()
            .ok_or(StoreError::NotFound)
        })
    }

    async fn get_by_slug(&mut self, principal: PrincipalId, slug: &CalendarSlug) -> Result<Binding, StoreError> {
        observed!("bindings.get_by_slug", {
            let row = sqlx::query_as::<_, BindingRow>(concat!(
                "SELECT ",
                binding_columns!(""),
                " FROM calendar_bindings WHERE tenant_id = $1 AND principal_id = $2 AND slug = $3"
            ))
            .bind(self.tenant.as_uuid())
            .bind(principal.as_uuid())
            .bind(slug.as_str())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_binding()
        })
    }

    async fn find_for_calendar(
        &mut self,
        principal: PrincipalId,
        calendar: CalendarId,
    ) -> Result<Option<Binding>, StoreError> {
        observed!("bindings.find_for_calendar", {
            Ok(self
                .select_bindings(
                    concat!(
                        "SELECT ",
                        binding_columns!(""),
                        " FROM calendar_bindings WHERE tenant_id = $1 AND principal_id = $2 AND calendar_id = $3"
                    ),
                    principal.as_uuid(),
                    Some(calendar.as_uuid()),
                )
                .await?
                .pop())
        })
    }

    async fn list_for(&mut self, principal: PrincipalId) -> Result<Vec<BoundCalendar>, StoreError> {
        observed!("bindings.list_for", {
            let bindings = self
                .select_bindings(
                    concat!(
                        "SELECT ",
                        binding_columns!(""),
                        " FROM calendar_bindings WHERE tenant_id = $1 AND principal_id = $2 ORDER BY id"
                    ),
                    principal.as_uuid(),
                    None,
                )
                .await?;
            let ids: Vec<Uuid> = bindings.iter().map(|binding| binding.calendar_id.as_uuid()).collect();
            let calendars: BTreeMap<CalendarId, Calendar> = self
                .calendars_by_ids(&ids)
                .await?
                .into_iter()
                .map(|calendar| (calendar.id, calendar))
                .collect();
            Ok(bindings
                .into_iter()
                .filter_map(|binding| {
                    calendars.get(&binding.calendar_id).map(|calendar| BoundCalendar {
                        calendar: calendar.clone(),
                        binding,
                    })
                })
                .collect())
        })
    }

    async fn find_for_calendars(&mut self, pairs: &[(PrincipalId, CalendarId)]) -> Result<Vec<Binding>, StoreError> {
        observed!("bindings.find_for_calendars", {
            if pairs.is_empty() {
                return Ok(Vec::new());
            }
            let wanted: BTreeSet<(Uuid, Uuid)> = pairs
                .iter()
                .map(|(principal, calendar)| (principal.as_uuid(), calendar.as_uuid()))
                .collect();
            let principals: Vec<Uuid> = wanted.iter().map(|(principal, _)| *principal).collect();
            let calendars: Vec<Uuid> = wanted.iter().map(|(_, calendar)| *calendar).collect();
            let rows = sqlx::query_as::<_, BindingRow>(concat!(
                "SELECT ",
                binding_columns!("b."),
                " FROM unnest($2::uuid[], $3::uuid[]) AS r(principal_id, calendar_id) \
                 JOIN calendar_bindings b ON b.tenant_id = $1 AND b.principal_id = r.principal_id \
                 AND b.calendar_id = r.calendar_id ORDER BY b.calendar_id, b.principal_id"
            ))
            .bind(self.tenant.as_uuid())
            .bind(&principals)
            .bind(&calendars)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            rows.into_iter().map(BindingRow::into_binding).collect()
        })
    }

    async fn list_for_calendar(&mut self, calendar: CalendarId) -> Result<Vec<Binding>, StoreError> {
        observed!("bindings.list_for_calendar", {
            let tenant = self.tenant.as_uuid();
            require_calendar(&mut self.conn, tenant, calendar.as_uuid()).await?;
            self.select_bindings(
                concat!(
                    "SELECT ",
                    binding_columns!(""),
                    " FROM calendar_bindings WHERE tenant_id = $1 AND calendar_id = $2 ORDER BY id"
                ),
                calendar.as_uuid(),
                None,
            )
            .await
        })
    }

    async fn create(&mut self, binding: Binding) -> Result<Binding, StoreError> {
        observed!("bindings.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    require_calendar(&mut *conn, tenant, binding.calendar_id.as_uuid()).await?;
                    let row = sqlx::query_as::<_, BindingRow>(concat!(
                        "INSERT INTO calendar_bindings (tenant_id, id, principal_id, calendar_id, slug, display_name, \
                         color, sort_order, schedule_transp, hidden, created_at, updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, 1) RETURNING ",
                        binding_columns!("")
                    ))
                    .bind(tenant)
                    .bind(binding.id.as_uuid())
                    .bind(binding.principal_id.as_uuid())
                    .bind(binding.calendar_id.as_uuid())
                    .bind(binding.slug.as_str())
                    .bind(binding.display_name.as_deref())
                    .bind(binding.color.as_deref())
                    .bind(binding.sort_order)
                    .bind(binding.schedule_transp.map(Transparency::as_ical))
                    .bind(binding.hidden)
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    let created = row.into_binding()?;
                    let change = PrincipalChange {
                        tenant,
                        principal: created.principal_id.as_uuid(),
                        kind: CollectionKind::Home,
                        uri: created.slug.as_str(),
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

    async fn update(&mut self, binding: Binding, expected_version: i64) -> Result<Binding, StoreError> {
        observed!("bindings.update", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, BindingRow>(concat!(
                        "UPDATE calendar_bindings SET display_name = $3, color = $4, sort_order = $5, \
                         schedule_transp = $6, hidden = $7, updated_at = $8, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND version = $9 RETURNING ",
                        binding_columns!("")
                    ))
                    .bind(tenant)
                    .bind(binding.id.as_uuid())
                    .bind(binding.display_name.as_deref())
                    .bind(binding.color.as_deref())
                    .bind(binding.sort_order)
                    .bind(binding.schedule_transp.map(Transparency::as_ical))
                    .bind(binding.hidden)
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    let Some(row) = row else {
                        return Err(stale_or_missing(
                            conn,
                            "SELECT 1 FROM calendar_bindings WHERE tenant_id = $1 AND id = $2",
                            tenant,
                            binding.id.as_uuid(),
                        )
                        .await);
                    };
                    let updated = row.into_binding()?;
                    let change = PrincipalChange {
                        tenant,
                        principal: updated.principal_id.as_uuid(),
                        kind: CollectionKind::Home,
                        uri: updated.slug.as_str(),
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

    async fn delete(&mut self, id: BindingId) -> Result<(), StoreError> {
        observed!("bindings.delete", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let removed = sqlx::query_as::<_, (Uuid, String)>(
                        "DELETE FROM calendar_bindings WHERE tenant_id = $1 AND id = $2 RETURNING principal_id, slug",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    let Some((principal, slug)) = removed else {
                        return Err(StoreError::NotFound);
                    };
                    let change = PrincipalChange {
                        tenant,
                        principal,
                        kind: CollectionKind::Home,
                        uri: &slug,
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

/// The read of [`PropertyRepo::list_many`], with its reasoning, as a file of its own: the test of the query plan reads the
/// same text.
const LIST_MANY_PROPERTIES: &str = include_str!("list_many_properties.sql");

/// A row of `collection_properties`.
#[derive(sqlx::FromRow)]
struct PropertyRow {
    calendar_id: Uuid,
    binding_id: Option<Uuid>,
    ns: String,
    name: String,
    value_xml: String,
}

impl PropertyRow {
    fn into_property(self) -> CollectionProperty {
        CollectionProperty {
            calendar_id: CalendarId::from_uuid(self.calendar_id),
            scope: self.binding_id.map_or(PropertyScope::Shared, |id| {
                PropertyScope::Binding(BindingId::from_uuid(id))
            }),
            ns: self.ns,
            name: self.name,
            value_xml: self.value_xml,
        }
    }
}

/// The binding of a scope, after checking that the calendar and the binding exist and belong together.
async fn check_scope(
    conn: &mut PgConnection,
    tenant: Uuid,
    calendar: CalendarId,
    scope: PropertyScope,
) -> Result<Option<Uuid>, StoreError> {
    require_calendar(&mut *conn, tenant, calendar.as_uuid()).await?;
    match scope {
        PropertyScope::Shared => Ok(None),
        PropertyScope::Binding(binding) => {
            let found = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM calendar_bindings WHERE tenant_id = $1 AND id = $2 AND calendar_id = $3",
            )
            .bind(tenant)
            .bind(binding.as_uuid())
            .bind(calendar.as_uuid())
            .fetch_optional(&mut *conn)
            .await
            .db()?;
            found.map(|_| Some(binding.as_uuid())).ok_or(StoreError::NotFound)
        }
    }
}

#[async_trait]
impl PropertyRepo for PgTx {
    async fn list(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
    ) -> Result<Vec<CollectionProperty>, StoreError> {
        observed!("properties.list", {
            let tenant = self.tenant.as_uuid();
            let binding = check_scope(&mut self.conn, tenant, calendar, scope).await?;
            let rows = sqlx::query_as::<_, PropertyRow>(
                "SELECT calendar_id, binding_id, ns, name, value_xml FROM collection_properties \
                 WHERE tenant_id = $1 AND calendar_id = $2 AND binding_id IS NOT DISTINCT FROM $3::uuid \
                 ORDER BY ns COLLATE \"C\", name COLLATE \"C\"",
            )
            .bind(tenant)
            .bind(calendar.as_uuid())
            .bind(binding)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            Ok(rows.into_iter().map(PropertyRow::into_property).collect())
        })
    }

    async fn list_many(&mut self, bindings: &[(CalendarId, BindingId)]) -> Result<Vec<CollectionProperty>, StoreError> {
        observed!("properties.list_many", {
            if bindings.is_empty() {
                return Ok(Vec::new());
            }
            let calendars: Vec<Uuid> = bindings.iter().map(|(calendar, _)| calendar.as_uuid()).collect();
            let binding_ids: Vec<Uuid> = bindings.iter().map(|(_, binding)| binding.as_uuid()).collect();
            // The pairs that are valid (the binding belongs to the live calendar) decide which properties are read:
            // the shared ones of their calendars and the private ones of their bindings. Each of the two reads is driven
            // from `wanted` and joins the partial unique index that serves it (`collection_properties_shared_key`,
            // `collection_properties_binding_key`), so it touches the rows of the listed calendars only. A single
            // `WHERE ... OR ...` over both kinds could not: PostgreSQL runs a sub-select under an `OR` as a filter over
            // every property row of the tenant (`ENGINEERING_RULES` R14).
            let rows = sqlx::query_as::<_, PropertyRow>(LIST_MANY_PROPERTIES)
                .bind(self.tenant.as_uuid())
                .bind(&calendars)
                .bind(&binding_ids)
                .fetch_all(&mut *self.conn)
                .await
                .db()?;
            Ok(rows.into_iter().map(PropertyRow::into_property).collect())
        })
    }

    async fn get(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
        ns: &str,
        name: &str,
    ) -> Result<Option<CollectionProperty>, StoreError> {
        observed!("properties.get", {
            let tenant = self.tenant.as_uuid();
            let binding = check_scope(&mut self.conn, tenant, calendar, scope).await?;
            let row = sqlx::query_as::<_, PropertyRow>(
                "SELECT calendar_id, binding_id, ns, name, value_xml FROM collection_properties \
                 WHERE tenant_id = $1 AND calendar_id = $2 AND binding_id IS NOT DISTINCT FROM $3::uuid \
                 AND ns = $4 AND name = $5",
            )
            .bind(tenant)
            .bind(calendar.as_uuid())
            .bind(binding)
            .bind(ns)
            .bind(name)
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            Ok(row.map(PropertyRow::into_property))
        })
    }

    async fn set(&mut self, property: CollectionProperty) -> Result<(), StoreError> {
        observed!("properties.set", {
            let tenant = self.tenant.as_uuid();
            let id = self.ids.new_id();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let binding = check_scope(&mut *conn, tenant, property.calendar_id, property.scope).await?;
                    let sql = if binding.is_some() {
                        "INSERT INTO collection_properties (tenant_id, id, calendar_id, binding_id, ns, name, value_xml) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) \
                         ON CONFLICT (tenant_id, calendar_id, binding_id, ns, name) WHERE binding_id IS NOT NULL \
                         DO UPDATE SET value_xml = EXCLUDED.value_xml"
                    } else {
                        "INSERT INTO collection_properties (tenant_id, id, calendar_id, binding_id, ns, name, value_xml) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) \
                         ON CONFLICT (tenant_id, calendar_id, ns, name) WHERE binding_id IS NULL \
                         DO UPDATE SET value_xml = EXCLUDED.value_xml"
                    };
                    sqlx::query(sql)
                        .bind(tenant)
                        .bind(id)
                        .bind(property.calendar_id.as_uuid())
                        .bind(binding)
                        .bind(&property.ns)
                        .bind(&property.name)
                        .bind(&property.value_xml)
                        .execute(&mut *conn)
                        .await
                        .db()?;
                    Ok(())
                })
            })
            .await
        })
    }

    async fn remove(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
        ns: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        observed!("properties.remove", {
            let tenant = self.tenant.as_uuid();
            let (ns, name) = (ns.to_owned(), name.to_owned());
            self.guarded(move |conn| {
                Box::pin(async move {
                    let binding = check_scope(&mut *conn, tenant, calendar, scope).await?;
                    let removed = sqlx::query(
                        "DELETE FROM collection_properties WHERE tenant_id = $1 AND calendar_id = $2 \
                         AND binding_id IS NOT DISTINCT FROM $3::uuid AND ns = $4 AND name = $5",
                    )
                    .bind(tenant)
                    .bind(calendar.as_uuid())
                    .bind(binding)
                    .bind(&ns)
                    .bind(&name)
                    .execute(&mut *conn)
                    .await
                    .db()?
                    .rows_affected();
                    Ok(removed > 0)
                })
            })
            .await
        })
    }

    async fn count(&mut self, calendar: CalendarId, scope: PropertyScope) -> Result<u64, StoreError> {
        observed!("properties.count", {
            let tenant = self.tenant.as_uuid();
            let binding = check_scope(&mut self.conn, tenant, calendar, scope).await?;
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM collection_properties \
                 WHERE tenant_id = $1 AND calendar_id = $2 AND binding_id IS NOT DISTINCT FROM $3::uuid",
            )
            .bind(tenant)
            .bind(calendar.as_uuid())
            .bind(binding)
            .fetch_one(&mut *self.conn)
            .await
            .db()?;
            to_u64(count)
        })
    }
}

/// A row of `calendar_grants`.
#[derive(sqlx::FromRow)]
struct GrantRow {
    tenant_id: Uuid,
    id: Uuid,
    calendar_id: Uuid,
    grantee_id: Uuid,
    access: String,
    status: String,
    source: String,
    required: bool,
    invite_uid: Option<String>,
    summary: Option<String>,
    common_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl GrantRow {
    fn into_grant(self) -> Result<Grant, StoreError> {
        Ok(Grant {
            id: GrantId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            calendar_id: CalendarId::from_uuid(self.calendar_id),
            grantee_id: PrincipalId::from_uuid(self.grantee_id),
            access: decode("grant access", self.access.parse::<GrantAccess>())?,
            status: decode("grant status", self.status.parse::<GrantStatus>())?,
            source: decode("grant source", self.source.parse::<GrantSource>())?,
            required: self.required,
            invite_uid: decode_opt("invite uid", self.invite_uid.as_deref(), Uid::parse)?,
            summary: self.summary,
            common_name: self.common_name,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

impl PgTx {
    async fn select_grants(
        &mut self,
        sql: &'static str,
        first: Uuid,
        second: Option<Uuid>,
    ) -> Result<Vec<Grant>, StoreError> {
        let mut query = sqlx::query_as::<_, GrantRow>(sql)
            .bind(self.tenant.as_uuid())
            .bind(first);
        if let Some(second) = second {
            query = query.bind(second);
        }
        let rows = query.fetch_all(&mut *self.conn).await.db()?;
        rows.into_iter().map(GrantRow::into_grant).collect()
    }
}

#[async_trait]
impl GrantRepo for PgTx {
    async fn get(&mut self, id: GrantId) -> Result<Grant, StoreError> {
        observed!("grants.get", {
            self.select_grants(
                concat!(
                    "SELECT ",
                    grant_columns!(""),
                    " FROM calendar_grants WHERE tenant_id = $1 AND id = $2"
                ),
                id.as_uuid(),
                None,
            )
            .await?
            .pop()
            .ok_or(StoreError::NotFound)
        })
    }

    async fn find(&mut self, calendar: CalendarId, grantee: PrincipalId) -> Result<Option<Grant>, StoreError> {
        observed!("grants.find", {
            Ok(self
                .select_grants(
                    concat!(
                        "SELECT ",
                        grant_columns!(""),
                        " FROM calendar_grants WHERE tenant_id = $1 AND calendar_id = $2 AND grantee_id = $3"
                    ),
                    calendar.as_uuid(),
                    Some(grantee.as_uuid()),
                )
                .await?
                .pop())
        })
    }

    async fn find_by_invite_uid(&mut self, uid: &Uid) -> Result<Option<Grant>, StoreError> {
        observed!("grants.find_by_invite_uid", {
            let row = sqlx::query_as::<_, GrantRow>(concat!(
                "SELECT ",
                grant_columns!(""),
                " FROM calendar_grants WHERE tenant_id = $1 AND invite_uid = $2 ORDER BY id LIMIT 1"
            ))
            .bind(self.tenant.as_uuid())
            .bind(uid.as_str())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.map(GrantRow::into_grant).transpose()
        })
    }

    async fn for_calendar(&mut self, calendar: CalendarId) -> Result<Vec<Grant>, StoreError> {
        observed!("grants.for_calendar", {
            let tenant = self.tenant.as_uuid();
            require_calendar(&mut self.conn, tenant, calendar.as_uuid()).await?;
            self.select_grants(
                concat!(
                    "SELECT ",
                    grant_columns!(""),
                    " FROM calendar_grants WHERE tenant_id = $1 AND calendar_id = $2 ORDER BY id"
                ),
                calendar.as_uuid(),
                None,
            )
            .await
        })
    }

    async fn for_calendars(&mut self, calendars: &[CalendarId]) -> Result<Vec<Grant>, StoreError> {
        observed!("grants.for_calendars", {
            if calendars.is_empty() {
                return Ok(Vec::new());
            }
            let ids: Vec<Uuid> = calendars.iter().copied().map(CalendarId::as_uuid).collect();
            let rows = sqlx::query_as::<_, GrantRow>(concat!(
                "SELECT ",
                grant_columns!("g."),
                " FROM calendar_grants g JOIN calendars c ON c.tenant_id = g.tenant_id AND c.id = g.calendar_id \
                 WHERE g.tenant_id = $1 AND g.calendar_id = ANY($2) AND c.deleted_at IS NULL \
                 ORDER BY g.calendar_id, g.id"
            ))
            .bind(self.tenant.as_uuid())
            .bind(&ids)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            rows.into_iter().map(GrantRow::into_grant).collect()
        })
    }

    async fn for_grantee(&mut self, grantee: PrincipalId) -> Result<Vec<Grant>, StoreError> {
        observed!("grants.for_grantee", {
            self.select_grants(
                concat!(
                    "SELECT ",
                    grant_columns!(""),
                    " FROM calendar_grants WHERE tenant_id = $1 AND grantee_id = $2 ORDER BY id"
                ),
                grantee.as_uuid(),
                None,
            )
            .await
        })
    }

    async fn create(&mut self, grant: Grant) -> Result<Grant, StoreError> {
        observed!("grants.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    require_calendar(&mut *conn, tenant, grant.calendar_id.as_uuid()).await?;
                    let row = sqlx::query_as::<_, GrantRow>(concat!(
                        "INSERT INTO calendar_grants (tenant_id, id, calendar_id, grantee_id, access, status, source, \
                         required, invite_uid, summary, common_name, created_at, updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, 1) RETURNING ",
                        grant_columns!("")
                    ))
                    .bind(tenant)
                    .bind(grant.id.as_uuid())
                    .bind(grant.calendar_id.as_uuid())
                    .bind(grant.grantee_id.as_uuid())
                    .bind(grant.access.as_str())
                    .bind(grant.status.as_str())
                    .bind(grant.source.as_str())
                    .bind(grant.required)
                    .bind(grant.invite_uid.as_ref().map(Uid::as_str))
                    .bind(grant.summary.as_deref())
                    .bind(grant.common_name.as_deref())
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    row.into_grant()
                })
            })
            .await
        })
    }

    async fn update(&mut self, grant: Grant, expected_version: i64) -> Result<Grant, StoreError> {
        observed!("grants.update", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, GrantRow>(concat!(
                        "UPDATE calendar_grants SET access = $3, status = $4, source = $5, required = $6, \
                         invite_uid = $7, summary = $8, common_name = $9, updated_at = $10, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND version = $11 RETURNING ",
                        grant_columns!("")
                    ))
                    .bind(tenant)
                    .bind(grant.id.as_uuid())
                    .bind(grant.access.as_str())
                    .bind(grant.status.as_str())
                    .bind(grant.source.as_str())
                    .bind(grant.required)
                    .bind(grant.invite_uid.as_ref().map(Uid::as_str))
                    .bind(grant.summary.as_deref())
                    .bind(grant.common_name.as_deref())
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    match row {
                        Some(row) => row.into_grant(),
                        None => Err(stale_or_missing(
                            conn,
                            "SELECT 1 FROM calendar_grants WHERE tenant_id = $1 AND id = $2",
                            tenant,
                            grant.id.as_uuid(),
                        )
                        .await),
                    }
                })
            })
            .await
        })
    }

    async fn delete(&mut self, id: GrantId) -> Result<(), StoreError> {
        observed!("grants.delete", {
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let removed = sqlx::query("DELETE FROM calendar_grants WHERE tenant_id = $1 AND id = $2")
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
