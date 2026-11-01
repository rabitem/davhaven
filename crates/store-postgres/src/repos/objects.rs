//! Calendar objects and their attendees, under the write invariant of PLAN 2.7.
//!
//! `put`, `delete` and `move_to` lock the calendar row (`SELECT ... FOR NO KEY UPDATE`, in ascending id order when
//! there are two), check their preconditions under that lock, advance the calendar's `sync_seq` exactly once per
//! change, write the object and write the change-log row at that sequence number. The sequence is advanced only
//! after every check passed, so a rejected write never moves it, and the savepoint of
//! [`PgTx::guarded`](crate::tx::PgTx::guarded) undoes everything when a later statement fails.

use std::collections::BTreeSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarId, CalendarUserAddress, Classification, CollectionKind, ComponentKind, ContentHash, ETag, ExternalKey,
    ObjectId, ObjectUri, PartStat, PrincipalId, ScheduleTag, StoredObject, TenantId, Uid,
};
use davhaven_ports::{
    ChangeKind, Expected, IndexFilter, NewVersion, ObjectAttendee, ObjectHead, ObjectRepo, PageReq, StoreError,
    StorePage, UniqueKey, WriteResult,
};
use sqlx::{PgConnection, Postgres, QueryBuilder};
use uuid::Uuid;

use super::calendars::require_calendar;
use super::sync::{LogEntry, bump_calendar, log_change};
use super::{DbResult, corrupt, decode, decode_opt, micros, to_i64, to_u64};
use crate::tx::PgTx;

/// A row of `calendar_objects` (`last_end` is NULL for infinity).
#[derive(sqlx::FromRow)]
struct ObjectRow {
    tenant_id: Uuid,
    id: Uuid,
    calendar_id: Uuid,
    owner_id: Uuid,
    uri: String,
    uid: String,
    etag: String,
    schedule_tag: Option<String>,
    content_hash: String,
    component: String,
    data: String,
    size: i64,
    first_start: Option<DateTime<Utc>>,
    last_end: Option<DateTime<Utc>>,
    is_recurring: bool,
    is_scheduling: bool,
    organizer_address: Option<String>,
    sequence: i32,
    class: String,
    external_key: Option<String>,
    origin: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl ObjectRow {
    fn into_object(self) -> Result<StoredObject, StoreError> {
        Ok(StoredObject {
            id: ObjectId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            calendar_id: CalendarId::from_uuid(self.calendar_id),
            owner_id: PrincipalId::from_uuid(self.owner_id),
            uri: decode("object uri", ObjectUri::parse(&self.uri))?,
            uid: decode("object uid", Uid::parse(&self.uid))?,
            etag: decode("etag", ETag::parse(&self.etag))?,
            schedule_tag: decode_opt("schedule tag", self.schedule_tag.as_deref(), ScheduleTag::parse)?,
            content_hash: decode("content hash", ContentHash::parse(&self.content_hash))?,
            component: ComponentKind::from_ical(&self.component)
                .ok_or_else(|| corrupt("component", &self.component))?,
            data: self.data,
            size: to_u64(self.size)?,
            first_start: self.first_start,
            last_end: self.last_end,
            is_recurring: self.is_recurring,
            is_scheduling: self.is_scheduling,
            organizer_address: decode_opt(
                "organizer address",
                self.organizer_address.as_deref(),
                CalendarUserAddress::parse,
            )?,
            sequence: self.sequence,
            class: Classification::from_ical(&self.class).ok_or_else(|| corrupt("classification", &self.class))?,
            external_key: decode_opt("external key", self.external_key.as_deref(), ExternalKey::parse)?,
            origin: self.origin,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

/// The identity of the object a write replaces or deletes.
#[derive(sqlx::FromRow)]
struct ExistingRow {
    id: Uuid,
    etag: String,
}

/// The object a move relocates.
#[derive(sqlx::FromRow)]
struct MovingRow {
    id: Uuid,
    uid: String,
    is_scheduling: bool,
    external_key: Option<String>,
}

/// A row of `object_attendees`.
#[derive(sqlx::FromRow)]
struct AttendeeRow {
    object_id: Uuid,
    address: String,
    principal_id: Option<Uuid>,
    partstat: String,
}

/// The calendar of a write, locked, with its owner.
async fn lock_calendar(conn: &mut PgConnection, tenant: Uuid, calendar: Uuid) -> Result<Uuid, StoreError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT owner_id FROM calendars WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR NO KEY UPDATE",
    )
    .bind(tenant)
    .bind(calendar)
    .fetch_optional(&mut *conn)
    .await
    .db()?
    .ok_or(StoreError::NotFound)
}

/// Checks `expected` against the state found under the calendar lock.
fn check_expected(expected: &Expected, existing: Option<&str>) -> Result<(), StoreError> {
    let satisfied = match expected {
        Expected::Any => true,
        Expected::Absent => existing.is_none(),
        Expected::Etag(etag) => existing == Some(etag.as_str()),
    };
    if satisfied {
        Ok(())
    } else {
        Err(StoreError::PreconditionFailed)
    }
}

/// Whether a row matches the existence query (`SELECT 1 ...`).
async fn any_row(
    conn: &mut PgConnection,
    sql: &'static str,
    tenant: Uuid,
    scope: Uuid,
    value: &str,
    except: Option<Uuid>,
) -> Result<bool, StoreError> {
    let found = sqlx::query_scalar::<_, i32>(sql)
        .bind(tenant)
        .bind(scope)
        .bind(value)
        .bind(except)
        .fetch_optional(&mut *conn)
        .await
        .db()?;
    Ok(found.is_some())
}

const UID_TAKEN: &str = "SELECT 1 FROM calendar_objects WHERE tenant_id = $1 AND calendar_id = $2 AND uid = $3 \
                         AND id IS DISTINCT FROM $4::uuid";
const KEY_TAKEN: &str = "SELECT 1 FROM calendar_objects WHERE tenant_id = $1 AND calendar_id = $2 \
                         AND external_key = $3 AND id IS DISTINCT FROM $4::uuid";
const SCHEDULING_UID_TAKEN: &str = "SELECT 1 FROM calendar_objects WHERE tenant_id = $1 AND owner_id = $2 \
                                    AND uid = $3 AND is_scheduling AND live AND id IS DISTINCT FROM $4::uuid";

/// Everything a write must check under the lock, besides `expected`: the three uniqueness rules.
async fn check_unique(
    conn: &mut PgConnection,
    tenant: Uuid,
    calendar: Uuid,
    owner: Uuid,
    version: &NewVersion,
    except: Option<Uuid>,
) -> Result<(), StoreError> {
    if any_row(conn, UID_TAKEN, tenant, calendar, version.index.uid.as_str(), except).await? {
        return Err(StoreError::UniqueViolation(UniqueKey::ObjectUid));
    }
    if let Some(key) = &version.external_key
        && any_row(conn, KEY_TAKEN, tenant, calendar, key.as_str(), except).await?
    {
        return Err(StoreError::UniqueViolation(UniqueKey::ExternalKey));
    }
    if version.index.is_scheduling
        && any_row(
            conn,
            SCHEDULING_UID_TAKEN,
            tenant,
            owner,
            version.index.uid.as_str(),
            except,
        )
        .await?
    {
        return Err(StoreError::UniqueViolation(UniqueKey::SchedulingUid));
    }
    Ok(())
}

/// Inserts a new object row.
async fn insert_object(
    conn: &mut PgConnection,
    tenant: Uuid,
    calendar: Uuid,
    owner: Uuid,
    version: &NewVersion,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let index = &version.index;
    sqlx::query(
        "INSERT INTO calendar_objects (tenant_id, id, calendar_id, owner_id, uri, uid, etag, schedule_tag, \
         content_hash, component, data, size, first_start, last_end, is_recurring, is_scheduling, \
         organizer_address, sequence, class, external_key, origin, live, created_at, updated_at, version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, COALESCE($14::timestamptz, 'infinity'), \
         $15, $16, $17, $18, $19, $20, $21, true, $22, $22, 1)",
    )
    .bind(tenant)
    .bind(version.id.as_uuid())
    .bind(calendar)
    .bind(owner)
    .bind(version.uri.as_str())
    .bind(index.uid.as_str())
    .bind(version.etag.as_str())
    .bind(version.schedule_tag.as_ref().map(ScheduleTag::as_str))
    .bind(version.content_hash.as_str())
    .bind(index.component.as_ical())
    .bind(&version.data)
    .bind(to_i64(u64::try_from(version.data.len()).unwrap_or(u64::MAX))?)
    .bind(index.first_start.map(micros))
    .bind(index.last_end.map(micros))
    .bind(index.is_recurring)
    .bind(index.is_scheduling)
    .bind(index.organizer.as_ref().map(CalendarUserAddress::as_str))
    .bind(index.sequence)
    .bind(index.class.as_ical())
    .bind(version.external_key.as_ref().map(ExternalKey::as_str))
    .bind(version.origin.as_deref())
    .bind(now)
    .execute(&mut *conn)
    .await
    .db()?;
    Ok(())
}

/// Replaces the content of an existing object row.
async fn update_object(
    conn: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    version: &NewVersion,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let index = &version.index;
    sqlx::query(
        "UPDATE calendar_objects SET uid = $3, etag = $4, schedule_tag = $5, content_hash = $6, component = $7, \
         data = $8, size = $9, first_start = $10, last_end = COALESCE($11::timestamptz, 'infinity'), \
         is_recurring = $12, is_scheduling = $13, organizer_address = $14, sequence = $15, class = $16, \
         external_key = $17, origin = $18, updated_at = $19, version = version + 1 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant)
    .bind(id)
    .bind(index.uid.as_str())
    .bind(version.etag.as_str())
    .bind(version.schedule_tag.as_ref().map(ScheduleTag::as_str))
    .bind(version.content_hash.as_str())
    .bind(index.component.as_ical())
    .bind(&version.data)
    .bind(to_i64(u64::try_from(version.data.len()).unwrap_or(u64::MAX))?)
    .bind(index.first_start.map(micros))
    .bind(index.last_end.map(micros))
    .bind(index.is_recurring)
    .bind(index.is_scheduling)
    .bind(index.organizer.as_ref().map(CalendarUserAddress::as_str))
    .bind(index.sequence)
    .bind(index.class.as_ical())
    .bind(version.external_key.as_ref().map(ExternalKey::as_str))
    .bind(version.origin.as_deref())
    .bind(now)
    .execute(&mut *conn)
    .await
    .db()?;
    Ok(())
}

/// Replaces the attendee rows of the object. Principals that do not exist in the tenant are stored unresolved.
async fn store_attendees(
    conn: &mut PgConnection,
    tenant: Uuid,
    object: Uuid,
    version: &NewVersion,
    replace: bool,
) -> Result<(), StoreError> {
    if replace {
        sqlx::query("DELETE FROM object_attendees WHERE tenant_id = $1 AND object_id = $2")
            .bind(tenant)
            .bind(object)
            .execute(&mut *conn)
            .await
            .db()?;
    }
    let mut seen = BTreeSet::new();
    let attendees: Vec<_> = version
        .index
        .attendees
        .iter()
        .filter(|attendee| seen.insert(attendee.address.as_str()))
        .collect();
    if attendees.is_empty() {
        return Ok(());
    }
    let wanted: Vec<Uuid> = version
        .attendee_principals
        .iter()
        .map(|(_, principal)| principal.as_uuid())
        .collect();
    let existing: BTreeSet<Uuid> =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM principals WHERE tenant_id = $1 AND id = ANY($2)")
            .bind(tenant)
            .bind(&wanted)
            .fetch_all(&mut *conn)
            .await
            .db()?
            .into_iter()
            .collect();
    let addresses: Vec<&str> = attendees.iter().map(|attendee| attendee.address.as_str()).collect();
    let principals: Vec<Option<Uuid>> = attendees
        .iter()
        .map(|attendee| {
            version
                .attendee_principals
                .iter()
                .find(|(address, _)| address == &attendee.address)
                .map(|(_, principal)| principal.as_uuid())
                .filter(|principal| existing.contains(principal))
        })
        .collect();
    let partstats: Vec<&str> = attendees.iter().map(|attendee| attendee.partstat.as_ical()).collect();
    sqlx::query(
        "INSERT INTO object_attendees (tenant_id, object_id, address, principal_id, partstat) \
         SELECT $1, $2, a.address, a.principal_id, a.partstat \
         FROM unnest($3::text[], $4::uuid[], $5::text[]) AS a(address, principal_id, partstat)",
    )
    .bind(tenant)
    .bind(object)
    .bind(&addresses)
    .bind(&principals)
    .bind(&partstats)
    .execute(&mut *conn)
    .await
    .db()?;
    Ok(())
}

/// The whole of `put`, inside the savepoint.
async fn write_object(
    conn: &mut PgConnection,
    tenant: Uuid,
    calendar: Uuid,
    version: NewVersion,
    expected: Expected,
    now: DateTime<Utc>,
) -> Result<WriteResult, StoreError> {
    let owner = lock_calendar(conn, tenant, calendar).await?;
    let existing = sqlx::query_as::<_, ExistingRow>(
        "SELECT id, etag FROM calendar_objects \
         WHERE tenant_id = $1 AND calendar_id = $2 AND uri = $3 FOR NO KEY UPDATE",
    )
    .bind(tenant)
    .bind(calendar)
    .bind(version.uri.as_str())
    .fetch_optional(&mut *conn)
    .await
    .db()?;
    check_expected(&expected, existing.as_ref().map(|row| row.etag.as_str()))?;
    check_unique(
        conn,
        tenant,
        calendar,
        owner,
        &version,
        existing.as_ref().map(|row| row.id),
    )
    .await?;
    let seq = bump_calendar(conn, tenant, calendar)
        .await?
        .ok_or(StoreError::NotFound)?;
    let object_id = if let Some(row) = &existing {
        update_object(conn, tenant, row.id, &version, now).await?;
        row.id
    } else {
        insert_object(conn, tenant, calendar, owner, &version, now).await?;
        version.id.as_uuid()
    };
    store_attendees(conn, tenant, object_id, &version, existing.is_some()).await?;
    let entry = LogEntry {
        tenant,
        kind: CollectionKind::Calendar,
        collection: calendar,
        seq,
        uri: version.uri.as_str(),
        change: ChangeKind::Upsert,
        at: now,
    };
    log_change(conn, &entry).await?;
    Ok(WriteResult {
        object_id: ObjectId::from_uuid(object_id),
        seq: to_u64(seq)?,
        etag: version.etag,
        created: existing.is_none(),
    })
}

/// The whole of `delete`, inside the savepoint.
async fn delete_object(
    conn: &mut PgConnection,
    tenant: Uuid,
    calendar: Uuid,
    uri: &ObjectUri,
    expected: &Expected,
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    lock_calendar(conn, tenant, calendar).await?;
    let existing = sqlx::query_as::<_, ExistingRow>(
        "SELECT id, etag FROM calendar_objects \
         WHERE tenant_id = $1 AND calendar_id = $2 AND uri = $3 FOR NO KEY UPDATE",
    )
    .bind(tenant)
    .bind(calendar)
    .bind(uri.as_str())
    .fetch_optional(&mut *conn)
    .await
    .db()?;
    let Some(existing) = existing else {
        // `If-Match` is false when no representation exists (RFC 7232 section 3.1): a 412, as for `put`.
        return Err(match expected {
            Expected::Etag(_) => StoreError::PreconditionFailed,
            Expected::Any | Expected::Absent => StoreError::NotFound,
        });
    };
    check_expected(expected, Some(&existing.etag))?;
    let seq = bump_calendar(conn, tenant, calendar)
        .await?
        .ok_or(StoreError::NotFound)?;
    sqlx::query("DELETE FROM calendar_objects WHERE tenant_id = $1 AND id = $2")
        .bind(tenant)
        .bind(existing.id)
        .execute(&mut *conn)
        .await
        .db()?;
    let entry = LogEntry {
        tenant,
        kind: CollectionKind::Calendar,
        collection: calendar,
        seq,
        uri: uri.as_str(),
        change: ChangeKind::Delete,
        at: now,
    };
    log_change(conn, &entry).await?;
    to_u64(seq)
}

/// The two calendars of a move.
struct MoveTarget<'a> {
    source: Uuid,
    uri: &'a ObjectUri,
    target: Uuid,
    target_uri: &'a ObjectUri,
}

/// The uniqueness checks of a move at the target.
async fn check_move(
    conn: &mut PgConnection,
    tenant: Uuid,
    moving: &MovingRow,
    target: Uuid,
    target_uri: &ObjectUri,
    target_owner: Uuid,
) -> Result<(), StoreError> {
    if any_row(
        conn,
        "SELECT 1 FROM calendar_objects WHERE tenant_id = $1 AND calendar_id = $2 AND uri = $3 \
         AND id IS DISTINCT FROM $4::uuid",
        tenant,
        target,
        target_uri.as_str(),
        None,
    )
    .await?
    {
        return Err(StoreError::UniqueViolation(UniqueKey::ObjectUri));
    }
    if any_row(conn, UID_TAKEN, tenant, target, &moving.uid, Some(moving.id)).await? {
        return Err(StoreError::UniqueViolation(UniqueKey::ObjectUid));
    }
    if let Some(key) = &moving.external_key
        && any_row(conn, KEY_TAKEN, tenant, target, key, Some(moving.id)).await?
    {
        return Err(StoreError::UniqueViolation(UniqueKey::ExternalKey));
    }
    if moving.is_scheduling
        && any_row(
            conn,
            SCHEDULING_UID_TAKEN,
            tenant,
            target_owner,
            &moving.uid,
            Some(moving.id),
        )
        .await?
    {
        return Err(StoreError::UniqueViolation(UniqueKey::SchedulingUid));
    }
    Ok(())
}

/// The whole of `move_to`, inside the savepoint.
async fn move_object(
    conn: &mut PgConnection,
    tenant: Uuid,
    request: &MoveTarget<'_>,
    now: DateTime<Utc>,
) -> Result<(u64, u64), StoreError> {
    let mut wanted = vec![request.source, request.target];
    wanted.sort_unstable();
    wanted.dedup();
    let locked = sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT id, owner_id FROM calendars WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL \
         ORDER BY id FOR NO KEY UPDATE",
    )
    .bind(tenant)
    .bind(&wanted)
    .fetch_all(&mut *conn)
    .await
    .db()?;
    if locked.len() != wanted.len() {
        return Err(StoreError::NotFound);
    }
    let owner_of = |calendar: Uuid| locked.iter().find(|(id, _)| *id == calendar).map(|(_, owner)| *owner);
    let target_owner = owner_of(request.target).ok_or(StoreError::NotFound)?;
    let moving = sqlx::query_as::<_, MovingRow>(
        "SELECT id, uid, is_scheduling, external_key FROM calendar_objects \
         WHERE tenant_id = $1 AND calendar_id = $2 AND uri = $3 FOR NO KEY UPDATE",
    )
    .bind(tenant)
    .bind(request.source)
    .bind(request.uri.as_str())
    .fetch_optional(&mut *conn)
    .await
    .db()?
    .ok_or(StoreError::NotFound)?;
    check_move(conn, tenant, &moving, request.target, request.target_uri, target_owner).await?;
    let source_seq = bump_calendar(conn, tenant, request.source)
        .await?
        .ok_or(StoreError::NotFound)?;
    let removed = LogEntry {
        tenant,
        kind: CollectionKind::Calendar,
        collection: request.source,
        seq: source_seq,
        uri: request.uri.as_str(),
        change: ChangeKind::Delete,
        at: now,
    };
    log_change(conn, &removed).await?;
    let target_seq = bump_calendar(conn, tenant, request.target)
        .await?
        .ok_or(StoreError::NotFound)?;
    sqlx::query(
        "UPDATE calendar_objects SET calendar_id = $3, owner_id = $4, uri = $5, updated_at = $6, \
         version = version + 1 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant)
    .bind(moving.id)
    .bind(request.target)
    .bind(target_owner)
    .bind(request.target_uri.as_str())
    .bind(now)
    .execute(&mut *conn)
    .await
    .db()?;
    let added = LogEntry {
        tenant,
        kind: CollectionKind::Calendar,
        collection: request.target,
        seq: target_seq,
        uri: request.target_uri.as_str(),
        change: ChangeKind::Upsert,
        at: now,
    };
    log_change(conn, &added).await?;
    Ok((to_u64(source_seq)?, to_u64(target_seq)?))
}

impl PgTx {
    async fn select_object(
        &mut self,
        sql: &'static str,
        first: Uuid,
        second: Option<&str>,
    ) -> Result<Option<StoredObject>, StoreError> {
        let mut query = sqlx::query_as::<_, ObjectRow>(sql)
            .bind(self.tenant.as_uuid())
            .bind(first);
        if let Some(second) = second {
            query = query.bind(second.to_owned());
        }
        let row = query.fetch_optional(&mut *self.conn).await.db()?;
        row.map(ObjectRow::into_object).transpose()
    }

    async fn select_object_in(
        &mut self,
        sql: &'static str,
        calendar: CalendarId,
        key: &str,
    ) -> Result<StoredObject, StoreError> {
        self.select_object(sql, calendar.as_uuid(), Some(key))
            .await?
            .ok_or(StoreError::NotFound)
    }

    /// The candidates of an index query; `with_data` false leaves the iCalendar text out of the select list.
    async fn query_objects(
        &mut self,
        calendar: CalendarId,
        filter: &IndexFilter,
        page: PageReq,
        with_data: bool,
    ) -> Result<StorePage<StoredObject>, StoreError> {
        let tenant = self.tenant.as_uuid();
        require_calendar(&mut self.conn, tenant, calendar.as_uuid()).await?;
        let range = filter.time_range.unwrap_or_default();
        // Only the conditions the filter sets appear in the statement. A catch-all statement with
        // `($n IS NULL OR column > $n)` predicates is planned once for all shapes (PostgreSQL switches prepared
        // statements to a generic plan after a few executions), and a generic plan cannot use the time-range
        // indexes. Every value is still a bind parameter; the statement text depends on the shape only.
        let mut query = QueryBuilder::<Postgres>::new(if with_data {
            concat!(
                "SELECT ",
                object_columns!(""),
                " FROM calendar_objects WHERE live AND tenant_id = "
            )
        } else {
            concat!(
                "SELECT ",
                object_head_columns!(""),
                " FROM calendar_objects WHERE live AND tenant_id = "
            )
        });
        query.push_bind(tenant);
        query.push(" AND calendar_id = ").push_bind(calendar.as_uuid());
        if let Some(component) = filter.component {
            query.push(" AND component = ").push_bind(component.as_ical());
        }
        // The pre-filter is closed at both ends: `davhaven_domain::index::interval_may_overlap` is the one
        // definition and these two conditions mirror it (a test compares them). Rows of the RFC 4791 section 9.9
        // table match when the range end touches the anchor (`end >= DUE`) or the range start equals it.
        if let Some(start) = range.start {
            query.push(" AND last_end >= ").push_bind(micros(start));
        }
        if let Some(end) = range.end {
            query
                .push(" AND (first_start IS NULL OR first_start <= ")
                .push_bind(micros(end))
                .push(")");
        }
        if let Some(uid) = &filter.uid {
            query.push(" AND uid = ").push_bind(uid.as_str());
        }
        if let Some(uris) = &filter.uris {
            let names: Vec<&str> = uris.iter().map(ObjectUri::as_str).collect();
            query.push(" AND uri = ANY(").push_bind(names).push(")");
        }
        if let Some(key) = &filter.external_key {
            query.push(" AND external_key = ").push_bind(key.as_str());
        }
        if let Some(prefix) = &filter.external_key_prefix {
            query
                .push(" AND starts_with(external_key, ")
                .push_bind(prefix.as_str())
                .push(")");
        }
        if let Some(organizer) = &filter.organizer {
            query.push(" AND organizer_address = ").push_bind(organizer.as_str());
        }
        if let Some(scheduling) = filter.is_scheduling {
            query.push(" AND is_scheduling = ").push_bind(scheduling);
        }
        if let Some(after) = page.after {
            query.push(" AND id > ").push_bind(after);
        }
        query
            .push(" ORDER BY id LIMIT ")
            .push_bind(i64::from(page.effective_limit()) + 1);
        let rows = query
            .build_query_as::<ObjectRow>()
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
        let objects = rows
            .into_iter()
            .map(ObjectRow::into_object)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StorePage::from_overfetched(objects, &page, |object| {
            object.id.as_uuid()
        }))
    }
}

#[async_trait]
impl ObjectRepo for PgTx {
    async fn get(&mut self, calendar: CalendarId, uri: &ObjectUri) -> Result<StoredObject, StoreError> {
        observed!("objects.get", {
            self.select_object_in(
                concat!(
                    "SELECT ",
                    object_columns!(""),
                    " FROM calendar_objects WHERE tenant_id = $1 AND calendar_id = $2 AND uri = $3 AND live"
                ),
                calendar,
                uri.as_str(),
            )
            .await
        })
    }

    async fn get_by_id(&mut self, id: ObjectId) -> Result<StoredObject, StoreError> {
        observed!("objects.get_by_id", {
            self.select_object(
                concat!(
                    "SELECT ",
                    object_columns!(""),
                    " FROM calendar_objects WHERE tenant_id = $1 AND id = $2 AND live"
                ),
                id.as_uuid(),
                None,
            )
            .await?
            .ok_or(StoreError::NotFound)
        })
    }

    async fn get_by_uid(&mut self, calendar: CalendarId, uid: &Uid) -> Result<StoredObject, StoreError> {
        observed!("objects.get_by_uid", {
            self.select_object_in(
                concat!(
                    "SELECT ",
                    object_columns!(""),
                    " FROM calendar_objects WHERE tenant_id = $1 AND calendar_id = $2 AND uid = $3 AND live"
                ),
                calendar,
                uid.as_str(),
            )
            .await
        })
    }

    async fn get_by_external_key(
        &mut self,
        calendar: CalendarId,
        key: &ExternalKey,
    ) -> Result<StoredObject, StoreError> {
        observed!("objects.get_by_external_key", {
            self.select_object_in(
                concat!(
                    "SELECT ",
                    object_columns!(""),
                    " FROM calendar_objects WHERE tenant_id = $1 AND calendar_id = $2 AND external_key = $3 AND live"
                ),
                calendar,
                key.as_str(),
            )
            .await
        })
    }

    async fn find_scheduling_uid(&mut self, owner: PrincipalId, uid: &Uid) -> Result<Option<StoredObject>, StoreError> {
        observed!("objects.find_scheduling_uid", {
            self.select_object(
                concat!(
                    "SELECT ",
                    object_columns!(""),
                    " FROM calendar_objects WHERE tenant_id = $1 AND owner_id = $2 AND uid = $3 \
                     AND is_scheduling AND live"
                ),
                owner.as_uuid(),
                Some(uid.as_str()),
            )
            .await
        })
    }

    async fn put(
        &mut self,
        calendar: CalendarId,
        version: NewVersion,
        expected: Expected,
    ) -> Result<WriteResult, StoreError> {
        observed!("objects.put", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move { write_object(conn, tenant, calendar.as_uuid(), version, expected, now).await })
            })
            .await
        })
    }

    async fn delete(&mut self, calendar: CalendarId, uri: &ObjectUri, expected: Expected) -> Result<u64, StoreError> {
        observed!("objects.delete", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let uri = uri.clone();
            self.guarded(move |conn| {
                Box::pin(async move { delete_object(conn, tenant, calendar.as_uuid(), &uri, &expected, now).await })
            })
            .await
        })
    }

    async fn move_to(
        &mut self,
        source: CalendarId,
        uri: &ObjectUri,
        target: CalendarId,
        target_uri: &ObjectUri,
    ) -> Result<(u64, u64), StoreError> {
        observed!("objects.move_to", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let (uri, target_uri) = (uri.clone(), target_uri.clone());
            self.guarded(move |conn| {
                Box::pin(async move {
                    let request = MoveTarget {
                        source: source.as_uuid(),
                        uri: &uri,
                        target: target.as_uuid(),
                        target_uri: &target_uri,
                    };
                    move_object(conn, tenant, &request, now).await
                })
            })
            .await
        })
    }

    async fn query(
        &mut self,
        calendar: CalendarId,
        filter: &IndexFilter,
        page: PageReq,
    ) -> Result<StorePage<StoredObject>, StoreError> {
        observed!("objects.query", self.query_objects(calendar, filter, page, true).await)
    }

    async fn list(&mut self, calendar: CalendarId, page: PageReq) -> Result<StorePage<StoredObject>, StoreError> {
        observed!(
            "objects.list",
            self.query_objects(calendar, &IndexFilter::all(), page, true).await
        )
    }

    async fn list_index(&mut self, calendar: CalendarId, page: PageReq) -> Result<StorePage<ObjectHead>, StoreError> {
        observed!("objects.list_index", {
            let page = self.query_objects(calendar, &IndexFilter::all(), page, false).await?;
            Ok(page.map(|object| ObjectHead::from(&object)))
        })
    }

    async fn query_index(
        &mut self,
        calendar: CalendarId,
        filter: &IndexFilter,
        page: PageReq,
    ) -> Result<StorePage<ObjectHead>, StoreError> {
        observed!("objects.query_index", {
            let page = self.query_objects(calendar, filter, page, false).await?;
            Ok(page.map(|object| ObjectHead::from(&object)))
        })
    }

    async fn uri_for_uid(&mut self, calendar: CalendarId, uid: &Uid) -> Result<Option<ObjectUri>, StoreError> {
        observed!("objects.uri_for_uid", {
            let tenant = self.tenant.as_uuid();
            require_calendar(&mut self.conn, tenant, calendar.as_uuid()).await?;
            let uri = sqlx::query_scalar::<_, String>(
                "SELECT uri FROM calendar_objects WHERE tenant_id = $1 AND calendar_id = $2 AND uid = $3 AND live",
            )
            .bind(tenant)
            .bind(calendar.as_uuid())
            .bind(uid.as_str())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            decode_opt("object uri", uri.as_deref(), ObjectUri::parse)
        })
    }

    async fn uri_for_scheduling_uid(
        &mut self,
        owner: PrincipalId,
        uid: &Uid,
    ) -> Result<Option<(CalendarId, ObjectUri)>, StoreError> {
        observed!("objects.uri_for_scheduling_uid", {
            let row = sqlx::query_as::<_, (Uuid, String)>(
                "SELECT calendar_id, uri FROM calendar_objects \
                 WHERE tenant_id = $1 AND owner_id = $2 AND uid = $3 AND is_scheduling AND live",
            )
            .bind(self.tenant.as_uuid())
            .bind(owner.as_uuid())
            .bind(uid.as_str())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.map(|(calendar, uri)| {
                Ok((
                    CalendarId::from_uuid(calendar),
                    decode("object uri", ObjectUri::parse(&uri))?,
                ))
            })
            .transpose()
        })
    }

    async fn attendees(&mut self, object: ObjectId) -> Result<Vec<ObjectAttendee>, StoreError> {
        observed!("objects.attendees", {
            let tenant = self.tenant.as_uuid();
            let exists = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM calendar_objects WHERE tenant_id = $1 AND id = $2 AND live",
            )
            .bind(tenant)
            .bind(object.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            if exists.is_none() {
                return Err(StoreError::NotFound);
            }
            let rows = sqlx::query_as::<_, AttendeeRow>(
                "SELECT object_id, address, principal_id, partstat FROM object_attendees \
                 WHERE tenant_id = $1 AND object_id = $2 ORDER BY address COLLATE \"C\"",
            )
            .bind(tenant)
            .bind(object.as_uuid())
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            rows.into_iter()
                .map(|row| -> Result<ObjectAttendee, StoreError> {
                    Ok(ObjectAttendee {
                        object_id: ObjectId::from_uuid(row.object_id),
                        address: decode("attendee address", CalendarUserAddress::parse(&row.address))?,
                        principal_id: row.principal_id.map(PrincipalId::from_uuid),
                        partstat: PartStat::from_ical(&row.partstat)
                            .ok_or_else(|| corrupt("attendee partstat", &row.partstat))?,
                    })
                })
                .collect()
        })
    }
}
