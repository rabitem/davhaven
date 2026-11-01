//! Principals, their addresses and group memberships.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarUserAddress, Email, Locale, Principal, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus,
    SearchCriterion, SearchField, TenantId, TextMatch, TimeZoneName,
};
use davhaven_ports::store::MAX_PAGE_LIMIT;
use davhaven_ports::{
    MembershipDiff, MembershipRepo, PageReq, PrincipalAddress, PrincipalFilter, PrincipalMatch, PrincipalQuery,
    PrincipalRepo, StoreError, StorePage, UniqueKey,
};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{DbResult, decode, decode_opt, micros, misuse};
use crate::tx::{PgTx, begin_maintenance, end_maintenance};

/// A row of `principals`.
#[derive(sqlx::FromRow)]
pub(super) struct PrincipalRow {
    tenant_id: Uuid,
    id: Uuid,
    kind: String,
    name: String,
    display_name: String,
    email: Option<String>,
    locale: Option<String>,
    timezone: Option<String>,
    external_ref: Option<String>,
    status: String,
    deleted_at: Option<DateTime<Utc>>,
    credential_generation: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl PrincipalRow {
    /// Validates the row and builds the entity.
    pub(super) fn into_principal(self) -> Result<Principal, StoreError> {
        Ok(Principal {
            id: PrincipalId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            kind: decode("principal kind", self.kind.parse::<PrincipalKind>())?,
            name: decode("principal name", PrincipalName::parse(&self.name))?,
            display_name: self.display_name,
            email: decode_opt("principal email", self.email.as_deref(), Email::parse)?,
            locale: decode_opt("principal locale", self.locale.as_deref(), Locale::parse)?,
            timezone: decode_opt("principal time zone", self.timezone.as_deref(), TimeZoneName::parse)?,
            external_ref: self.external_ref,
            status: decode("principal status", self.status.parse::<PrincipalStatus>())?,
            deleted_at: self.deleted_at,
            credential_generation: self.credential_generation,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }
}

/// A principal found by one of several requested addresses: the position of the address in the request (from 1) and
/// the principal.
#[derive(sqlx::FromRow)]
struct AddressHit {
    ord: i64,
    #[sqlx(flatten)]
    principal: PrincipalRow,
}

/// A row of `principal_addresses`.
#[derive(sqlx::FromRow)]
struct AddressRow {
    principal_id: Uuid,
    address: String,
    is_primary: bool,
}

impl AddressRow {
    fn into_address(self) -> Result<PrincipalAddress, StoreError> {
        Ok(PrincipalAddress {
            principal_id: PrincipalId::from_uuid(self.principal_id),
            address: decode("principal address", CalendarUserAddress::parse(&self.address))?,
            primary: self.is_primary,
        })
    }
}

/// The SQL condition that the value `$value` matches the text of the criterion `c`, ignoring case (the criterion's
/// text is lower case already): how it is compared is `c.how` (0 contains, 1 starts with, 2 equals).
macro_rules! compare {
    ($value:literal) => {
        concat!(
            "(CASE c.how WHEN 0 THEN strpos(",
            $value,
            ", c.needle) > 0 WHEN 1 THEN starts_with(",
            $value,
            ", c.needle) ELSE ",
            $value,
            " = c.needle END)"
        )
    };
}

/// The SQL condition that the principal `p` satisfies the criterion `c`: the text matches one of the properties the
/// bits of `c.fields` name (1 name, 2 display name, 4 stored addresses, 8 the e-mail part of `mailto:` addresses).
macro_rules! criterion_matches {
    () => {
        concat!(
            "(((c.fields & 1) <> 0 AND ",
            compare!("lower(p.name)"),
            ") OR ((c.fields & 2) <> 0 AND ",
            compare!("lower(p.display_name)"),
            ") OR ((c.fields & 4) <> 0 AND EXISTS (SELECT 1 FROM principal_addresses a \
             WHERE a.tenant_id = p.tenant_id AND a.principal_id = p.id AND ",
            compare!("lower(a.address)"),
            ")) OR ((c.fields & 8) <> 0 AND EXISTS (SELECT 1 FROM principal_addresses a \
             WHERE a.tenant_id = p.tenant_id AND a.principal_id = p.id AND starts_with(lower(a.address), 'mailto:') \
             AND ",
            compare!("substr(lower(a.address), 8)"),
            ")))"
        )
    };
}

/// The criteria of a search as the parallel arrays the statement unnests: the lower-case texts, how each is
/// compared and the bit set of the properties each looks into.
struct CriteriaColumns {
    needles: Vec<String>,
    how: Vec<i32>,
    fields: Vec<i32>,
}

impl CriteriaColumns {
    fn of(criteria: &[SearchCriterion]) -> Self {
        let mut columns = Self {
            needles: Vec::with_capacity(criteria.len()),
            how: Vec::with_capacity(criteria.len()),
            fields: Vec::with_capacity(criteria.len()),
        };
        for criterion in criteria {
            columns.needles.push(criterion.text.to_lowercase());
            columns.how.push(match criterion.matching {
                TextMatch::Contains => 0,
                TextMatch::StartsWith => 1,
                TextMatch::Equals => 2,
            });
            columns.fields.push(
                criterion
                    .searched()
                    .iter()
                    .map(|field| match field {
                        SearchField::Name => 1,
                        SearchField::DisplayName => 2,
                        SearchField::Address => 4,
                        SearchField::Email => 8,
                    })
                    .fold(0, |mask, bit| mask | bit),
            );
        }
        columns
    }
}

/// Whether the principal exists in the tenant.
pub(super) async fn principal_exists(conn: &mut PgConnection, tenant: Uuid, id: Uuid) -> Result<bool, StoreError> {
    let found = sqlx::query_scalar::<_, i32>("SELECT 1 FROM principals WHERE tenant_id = $1 AND id = $2")
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .db()?;
    Ok(found.is_some())
}

/// `NotFound` unless the principal exists in the tenant.
pub(super) async fn require_principal(conn: &mut PgConnection, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
    if principal_exists(conn, tenant, id).await? {
        Ok(())
    } else {
        Err(StoreError::NotFound)
    }
}

/// Locks the principal's row for the rest of the transaction (`FOR NO KEY UPDATE`: writers of the principal's
/// memberships and addresses queue, while inserts that merely reference the principal do not wait) and answers
/// `NotFound` when it does not exist.
///
/// Without the lock two concurrent provisioning calls for the same group both read the old member set and both
/// insert the same rows; the loser would fail on the primary key. Locking the owner of the rows serialises them,
/// and each one then sees what the other committed (READ COMMITTED takes a fresh snapshot per statement).
async fn lock_principal(conn: &mut PgConnection, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
    sqlx::query_scalar::<_, i32>("SELECT 1 FROM principals WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE")
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .db()?
        .map(|_| ())
        .ok_or(StoreError::NotFound)
}

impl PgTx {
    async fn select_principal(&mut self, sql: &'static str, key: &str) -> Result<Option<Principal>, StoreError> {
        let row = sqlx::query_as::<_, PrincipalRow>(sql)
            .bind(self.tenant.as_uuid())
            .bind(key)
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
        row.map(PrincipalRow::into_principal).transpose()
    }

    /// The addresses of the principals, in the order of the contract: by principal id, the primary address first and
    /// then by address.
    async fn address_rows(&mut self, principals: &[Uuid]) -> Result<Vec<AddressRow>, StoreError> {
        sqlx::query_as::<_, AddressRow>(
            "SELECT principal_id, address, is_primary FROM principal_addresses \
             WHERE tenant_id = $1 AND principal_id = ANY($2) \
             ORDER BY principal_id, is_primary DESC, address COLLATE \"C\"",
        )
        .bind(self.tenant.as_uuid())
        .bind(principals)
        .fetch_all(&mut *self.conn)
        .await
        .db()
    }

    async fn addresses_of(&mut self, principals: &[Uuid]) -> Result<BTreeMap<Uuid, Vec<PrincipalAddress>>, StoreError> {
        let rows = self.address_rows(principals).await?;
        let mut grouped: BTreeMap<Uuid, Vec<PrincipalAddress>> = BTreeMap::new();
        for row in rows {
            let key = row.principal_id;
            grouped.entry(key).or_default().push(row.into_address()?);
        }
        Ok(grouped)
    }
}

#[async_trait]
impl PrincipalRepo for PgTx {
    async fn get(&mut self, id: PrincipalId) -> Result<Principal, StoreError> {
        observed!("principals.get", {
            let row = sqlx::query_as::<_, PrincipalRow>(concat!(
                "SELECT ",
                principal_columns!(""),
                " FROM principals WHERE tenant_id = $1 AND id = $2"
            ))
            .bind(self.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_optional(&mut *self.conn)
            .await
            .db()?;
            row.ok_or(StoreError::NotFound)?.into_principal()
        })
    }

    async fn get_by_name(&mut self, name: &PrincipalName) -> Result<Principal, StoreError> {
        observed!("principals.get_by_name", {
            self.select_principal(
                concat!(
                    "SELECT ",
                    principal_columns!(""),
                    " FROM principals WHERE tenant_id = $1 AND name = $2"
                ),
                name.as_str(),
            )
            .await?
            .ok_or(StoreError::NotFound)
        })
    }

    async fn find_by_external_ref(&mut self, external_ref: &str) -> Result<Option<Principal>, StoreError> {
        observed!("principals.find_by_external_ref", {
            self.select_principal(
                concat!(
                    "SELECT ",
                    principal_columns!(""),
                    " FROM principals WHERE tenant_id = $1 AND external_ref = $2"
                ),
                external_ref,
            )
            .await
        })
    }

    async fn find_by_address(&mut self, address: &CalendarUserAddress) -> Result<Option<Principal>, StoreError> {
        observed!("principals.find_by_address", {
            self.select_principal(
                concat!(
                    "SELECT ",
                    principal_columns!(""),
                    " FROM principals WHERE tenant_id = $1 AND id = (SELECT principal_id FROM principal_addresses \
                     WHERE tenant_id = $1 AND lower(address) = lower($2))"
                ),
                address.as_str(),
            )
            .await
        })
    }

    async fn find_by_addresses(
        &mut self,
        addresses: &[CalendarUserAddress],
    ) -> Result<Vec<(CalendarUserAddress, Principal)>, StoreError> {
        observed!("principals.find_by_addresses", {
            // Every distinct address once, in the order given; the statement answers with the position of the address
            // it matched, so each hit is paired with the address as the caller wrote it.
            let mut distinct: Vec<&CalendarUserAddress> = Vec::with_capacity(addresses.len());
            for address in addresses {
                if !distinct.contains(&address) {
                    distinct.push(address);
                }
            }
            if distinct.is_empty() {
                return Ok(Vec::new());
            }
            let texts: Vec<&str> = distinct.iter().map(|address| address.as_str()).collect();
            let hits = sqlx::query_as::<_, AddressHit>(concat!(
                "SELECT q.ord, ",
                principal_columns!("p."),
                " FROM unnest($2::text[]) WITH ORDINALITY AS q(address, ord) \
                 JOIN principal_addresses a ON a.tenant_id = $1 AND lower(a.address) = lower(q.address) \
                 JOIN principals p ON p.tenant_id = a.tenant_id AND p.id = a.principal_id \
                 ORDER BY q.ord"
            ))
            .bind(self.tenant.as_uuid())
            .bind(&texts)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let mut found = Vec::with_capacity(hits.len());
            for hit in hits {
                let position = usize::try_from(hit.ord - 1).map_err(|_| misuse("an address position is negative"))?;
                let Some(address) = distinct.get(position) else {
                    return Err(misuse("the database matched an address that was not asked for"));
                };
                found.push(((*address).clone(), hit.principal.into_principal()?));
            }
            Ok(found)
        })
    }

    async fn get_many(&mut self, ids: &[PrincipalId]) -> Result<Vec<Principal>, StoreError> {
        observed!("principals.get_many", {
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let uuids: Vec<Uuid> = ids.iter().copied().map(PrincipalId::as_uuid).collect();
            let rows = sqlx::query_as::<_, PrincipalRow>(concat!(
                "SELECT ",
                principal_columns!(""),
                " FROM principals WHERE tenant_id = $1 AND id = ANY($2)"
            ))
            .bind(self.tenant.as_uuid())
            .bind(&uuids)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let mut stored: BTreeMap<Uuid, Principal> = BTreeMap::new();
            for row in rows {
                let principal = row.into_principal()?;
                stored.insert(principal.id.as_uuid(), principal);
            }
            // The order of the request, each principal once.
            Ok(uuids.iter().filter_map(|id| stored.remove(id)).collect())
        })
    }

    async fn get_many_by_name(&mut self, names: &[PrincipalName]) -> Result<Vec<Principal>, StoreError> {
        observed!("principals.get_many_by_name", {
            if names.is_empty() {
                return Ok(Vec::new());
            }
            let texts: Vec<&str> = names.iter().map(PrincipalName::as_str).collect();
            let rows = sqlx::query_as::<_, PrincipalRow>(concat!(
                "SELECT ",
                principal_columns!(""),
                " FROM principals WHERE tenant_id = $1 AND name = ANY($2)"
            ))
            .bind(self.tenant.as_uuid())
            .bind(&texts)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let mut stored: BTreeMap<String, Principal> = BTreeMap::new();
            for row in rows {
                let principal = row.into_principal()?;
                stored.insert(principal.name.as_str().to_owned(), principal);
            }
            Ok(texts.iter().filter_map(|name| stored.remove(*name)).collect())
        })
    }

    async fn list(&mut self, filter: &PrincipalFilter, page: PageReq) -> Result<StorePage<Principal>, StoreError> {
        observed!("principals.list", {
            let rows = sqlx::query_as::<_, PrincipalRow>(concat!(
                "SELECT ",
                principal_columns!(""),
                " FROM principals WHERE tenant_id = $1 \
                 AND ($2::text IS NULL OR kind = $2) \
                 AND ($3::text IS NULL OR external_ref = $3) \
                 AND (($4::text IS NOT NULL AND status = $4) OR ($4::text IS NULL AND ($5::boolean OR status <> 'deleted'))) \
                 AND ($6::uuid IS NULL OR id > $6) \
                 ORDER BY id LIMIT $7"
            ))
            .bind(self.tenant.as_uuid())
            .bind(filter.kind.map(PrincipalKind::as_str))
            .bind(filter.external_ref.as_deref())
            .bind(filter.status.map(PrincipalStatus::as_str))
            .bind(filter.include_deleted)
            .bind(page.after)
            .bind(i64::from(page.effective_limit()) + 1)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let principals = rows
                .into_iter()
                .map(PrincipalRow::into_principal)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(StorePage::from_overfetched(principals, &page, |principal| {
                principal.id.as_uuid()
            }))
        })
    }

    async fn search(&mut self, query: &PrincipalQuery) -> Result<Vec<PrincipalMatch>, StoreError> {
        observed!("principals.search", {
            let kinds: Vec<&str> = if query.kinds.is_empty() {
                vec![
                    PrincipalKind::User.as_str(),
                    PrincipalKind::Group.as_str(),
                    PrincipalKind::Resource.as_str(),
                ]
            } else {
                query.kinds.iter().copied().map(PrincipalKind::as_str).collect()
            };
            let criteria = CriteriaColumns::of(&query.criteria);
            // The plain text, the kinds, the status and the criteria are conditions of one statement, so that the
            // limit cuts what matched. The criteria are the rows of `c`, all of which have to match (no row that does
            // not) or, with `any_of`, at least one of them.
            let rows = sqlx::query_as::<_, PrincipalRow>(concat!(
                "SELECT ",
                principal_columns!("p."),
                " FROM principals p WHERE p.tenant_id = $1 AND p.status = 'active' AND p.kind = ANY($2) \
                 AND ($3 = '' OR strpos(lower(p.name), $3) > 0 OR strpos(lower(p.display_name), $3) > 0 \
                      OR EXISTS (SELECT 1 FROM principal_addresses a WHERE a.tenant_id = p.tenant_id \
                                 AND a.principal_id = p.id AND strpos(lower(a.address), $3) > 0)) \
                 AND (cardinality($5::text[]) = 0 OR CASE WHEN $8 \
                      THEN EXISTS (SELECT 1 FROM unnest($5::text[], $6::int4[], $7::int4[]) AS c(needle, how, fields) \
                                   WHERE ",
                criterion_matches!(),
                ") ELSE NOT EXISTS (SELECT 1 FROM unnest($5::text[], $6::int4[], $7::int4[]) \
                                    AS c(needle, how, fields) WHERE NOT ",
                criterion_matches!(),
                ") END) \
                 ORDER BY p.display_name COLLATE \"C\", p.id LIMIT $4"
            ))
            .bind(self.tenant.as_uuid())
            .bind(&kinds)
            .bind(query.text.to_lowercase())
            .bind(i64::from(query.limit.min(MAX_PAGE_LIMIT)))
            .bind(&criteria.needles)
            .bind(&criteria.how)
            .bind(&criteria.fields)
            .bind(query.any_of)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            let ids: Vec<Uuid> = rows.iter().map(|row| row.id).collect();
            let mut addresses = self.addresses_of(&ids).await?;
            rows.into_iter()
                .map(|row| -> Result<PrincipalMatch, StoreError> {
                    let principal = row.into_principal()?;
                    let addresses = addresses.remove(&principal.id.as_uuid()).unwrap_or_default();
                    Ok(PrincipalMatch { principal, addresses })
                })
                .collect()
        })
    }

    async fn create(&mut self, principal: Principal) -> Result<Principal, StoreError> {
        observed!("principals.create", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let epochs = [self.ids.new_id(), self.ids.new_id(), self.ids.new_id()];
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, PrincipalRow>(concat!(
                        "INSERT INTO principals (tenant_id, id, kind, name, display_name, email, locale, timezone, \
                         external_ref, status, deleted_at, credential_generation, created_at, updated_at, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13, 1) RETURNING ",
                        principal_columns!("")
                    ))
                    .bind(tenant)
                    .bind(principal.id.as_uuid())
                    .bind(principal.kind.as_str())
                    .bind(principal.name.as_str())
                    .bind(&principal.display_name)
                    .bind(principal.email.as_ref().map(Email::as_str))
                    .bind(principal.locale.as_ref().map(Locale::as_str))
                    .bind(principal.timezone.as_ref().map(TimeZoneName::as_str))
                    .bind(principal.external_ref.as_deref())
                    .bind(principal.status.as_str())
                    .bind(principal.deleted_at.map(micros))
                    .bind(principal.credential_generation)
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    sqlx::query(
                        "INSERT INTO principals_sync (tenant_id, principal_id, home_seq, home_min_seq, home_epoch, \
                         inbox_seq, inbox_min_seq, inbox_epoch, notifications_seq, notifications_min_seq, \
                         notifications_epoch) VALUES ($1, $2, 0, 0, $3, 0, 0, $4, 0, 0, $5)",
                    )
                    .bind(tenant)
                    .bind(principal.id.as_uuid())
                    .bind(epochs[0])
                    .bind(epochs[1])
                    .bind(epochs[2])
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    row.into_principal()
                })
            })
            .await
        })
    }

    async fn update(&mut self, principal: Principal, expected_version: i64) -> Result<Principal, StoreError> {
        observed!("principals.update", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, PrincipalRow>(concat!(
                        "UPDATE principals SET display_name = $3, email = $4, locale = $5, timezone = $6, \
                         external_ref = $7, status = $8, deleted_at = $9, updated_at = $10, version = version + 1 \
                         WHERE tenant_id = $1 AND id = $2 AND version = $11 RETURNING ",
                        principal_columns!("")
                    ))
                    .bind(tenant)
                    .bind(principal.id.as_uuid())
                    .bind(&principal.display_name)
                    .bind(principal.email.as_ref().map(Email::as_str))
                    .bind(principal.locale.as_ref().map(Locale::as_str))
                    .bind(principal.timezone.as_ref().map(TimeZoneName::as_str))
                    .bind(principal.external_ref.as_deref())
                    .bind(principal.status.as_str())
                    .bind(principal.deleted_at.map(micros))
                    .bind(now)
                    .bind(expected_version)
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?;
                    match row {
                        Some(row) => row.into_principal(),
                        None => Err(super::stale_or_missing(
                            conn,
                            "SELECT 1 FROM principals WHERE tenant_id = $1 AND id = $2",
                            tenant,
                            principal.id.as_uuid(),
                        )
                        .await),
                    }
                })
            })
            .await
        })
    }

    async fn bump_credential_generation(&mut self, id: PrincipalId) -> Result<i32, StoreError> {
        observed!("principals.bump_credential_generation", {
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, i32>(
                        "UPDATE principals SET credential_generation = credential_generation + 1 \
                         WHERE tenant_id = $1 AND id = $2 RETURNING credential_generation",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .fetch_optional(&mut *conn)
                    .await
                    .db()?
                    .ok_or(StoreError::NotFound)
                })
            })
            .await
        })
    }

    async fn addresses(&mut self, id: PrincipalId) -> Result<Vec<PrincipalAddress>, StoreError> {
        observed!("principals.addresses", {
            let tenant = self.tenant.as_uuid();
            require_principal(&mut self.conn, tenant, id.as_uuid()).await?;
            let mut grouped = self.addresses_of(&[id.as_uuid()]).await?;
            Ok(grouped.remove(&id.as_uuid()).unwrap_or_default())
        })
    }

    async fn addresses_many(&mut self, ids: &[PrincipalId]) -> Result<Vec<PrincipalAddress>, StoreError> {
        observed!("principals.addresses_many", {
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let uuids: Vec<Uuid> = ids.iter().copied().map(PrincipalId::as_uuid).collect();
            self.address_rows(&uuids)
                .await?
                .into_iter()
                .map(AddressRow::into_address)
                .collect()
        })
    }

    async fn set_addresses(&mut self, id: PrincipalId, addresses: Vec<PrincipalAddress>) -> Result<(), StoreError> {
        observed!("principals.set_addresses", {
            if addresses.iter().any(|address| address.principal_id != id) {
                return Err(misuse("an address names another principal than the one it is set for"));
            }
            if addresses.iter().filter(|address| address.primary).count() > 1 {
                return Err(misuse("a principal has at most one primary address"));
            }
            let mut seen = BTreeSet::new();
            for address in &addresses {
                if !seen.insert(address.address.as_str().to_lowercase()) {
                    return Err(StoreError::UniqueViolation(UniqueKey::Address));
                }
            }
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    lock_principal(&mut *conn, tenant, id.as_uuid()).await?;
                    sqlx::query("DELETE FROM principal_addresses WHERE tenant_id = $1 AND principal_id = $2")
                        .bind(tenant)
                        .bind(id.as_uuid())
                        .execute(&mut *conn)
                        .await
                        .db()?;
                    let texts: Vec<&str> = addresses.iter().map(|address| address.address.as_str()).collect();
                    let primaries: Vec<bool> = addresses.iter().map(|address| address.primary).collect();
                    sqlx::query(
                        "INSERT INTO principal_addresses (tenant_id, principal_id, address, is_primary) \
                         SELECT $1, $2, a.address, a.is_primary FROM unnest($3::text[], $4::boolean[]) \
                         AS a(address, is_primary)",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .bind(&texts)
                    .bind(&primaries)
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    Ok(())
                })
            })
            .await
        })
    }

    async fn purge(&mut self, id: PrincipalId) -> Result<(), StoreError> {
        observed!("principals.purge", {
            let now = micros(self.clock.now());
            let tenant = self.tenant.as_uuid();
            let maintenance = self.maintenance_timeout;
            self.guarded(move |conn| {
                Box::pin(async move {
                    let previous = begin_maintenance(conn, maintenance).await?;
                    // A feed token names its calendars in an array without a foreign key. The calendars of this
                    // principal go with it (owner foreign key), so other principals' feed tokens (a grantee's
                    // feed) must stop naming them, as they do when a single calendar is purged.
                    sqlx::query(
                        "UPDATE feed_tokens SET calendar_ids = ARRAY( \
                           SELECT c FROM unnest(calendar_ids) AS c WHERE c NOT IN ( \
                             SELECT id FROM calendars WHERE tenant_id = $1 AND owner_id = $2)), \
                           updated_at = $3, version = version + 1 \
                         WHERE tenant_id = $1 AND principal_id <> $2 AND calendar_ids && ARRAY( \
                           SELECT id FROM calendars WHERE tenant_id = $1 AND owner_id = $2)",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .bind(now)
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    // The change logs have no foreign key (their collection is a calendar or a principal).
                    sqlx::query(
                        "DELETE FROM collection_changes WHERE tenant_id = $1 AND \
                         ((collection_kind = 'calendar' AND collection_id IN \
                           (SELECT id FROM calendars WHERE tenant_id = $1 AND owner_id = $2)) \
                          OR (collection_kind IN ('home', 'inbox', 'notifications') AND collection_id = $2))",
                    )
                    .bind(tenant)
                    .bind(id.as_uuid())
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    let removed = sqlx::query("DELETE FROM principals WHERE tenant_id = $1 AND id = $2")
                        .bind(tenant)
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
}

#[async_trait]
impl MembershipRepo for PgTx {
    async fn members(&mut self, group: PrincipalId) -> Result<Vec<PrincipalId>, StoreError> {
        observed!("memberships.members", {
            let tenant = self.tenant.as_uuid();
            require_principal(&mut self.conn, tenant, group.as_uuid()).await?;
            let ids = sqlx::query_scalar::<_, Uuid>(
                "SELECT member_id FROM memberships WHERE tenant_id = $1 AND group_id = $2 ORDER BY member_id",
            )
            .bind(tenant)
            .bind(group.as_uuid())
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            Ok(ids.into_iter().map(PrincipalId::from_uuid).collect())
        })
    }

    async fn groups_of(&mut self, member: PrincipalId) -> Result<Vec<PrincipalId>, StoreError> {
        observed!("memberships.groups_of", {
            let ids = sqlx::query_scalar::<_, Uuid>(
                "SELECT group_id FROM memberships WHERE tenant_id = $1 AND member_id = $2 ORDER BY group_id",
            )
            .bind(self.tenant.as_uuid())
            .bind(member.as_uuid())
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            Ok(ids.into_iter().map(PrincipalId::from_uuid).collect())
        })
    }

    async fn members_of_many(&mut self, groups: &[PrincipalId]) -> Result<Vec<(PrincipalId, PrincipalId)>, StoreError> {
        observed!("memberships.members_of_many", {
            if groups.is_empty() {
                return Ok(Vec::new());
            }
            let uuids: Vec<Uuid> = groups.iter().copied().map(PrincipalId::as_uuid).collect();
            let rows = sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT group_id, member_id FROM memberships WHERE tenant_id = $1 AND group_id = ANY($2) \
                 ORDER BY group_id, member_id",
            )
            .bind(self.tenant.as_uuid())
            .bind(&uuids)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            Ok(rows
                .into_iter()
                .map(|(group, member)| (PrincipalId::from_uuid(group), PrincipalId::from_uuid(member)))
                .collect())
        })
    }

    async fn groups_of_many(&mut self, members: &[PrincipalId]) -> Result<Vec<(PrincipalId, PrincipalId)>, StoreError> {
        observed!("memberships.groups_of_many", {
            if members.is_empty() {
                return Ok(Vec::new());
            }
            let uuids: Vec<Uuid> = members.iter().copied().map(PrincipalId::as_uuid).collect();
            let rows = sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT member_id, group_id FROM memberships WHERE tenant_id = $1 AND member_id = ANY($2) \
                 ORDER BY member_id, group_id",
            )
            .bind(self.tenant.as_uuid())
            .bind(&uuids)
            .fetch_all(&mut *self.conn)
            .await
            .db()?;
            Ok(rows
                .into_iter()
                .map(|(member, group)| (PrincipalId::from_uuid(member), PrincipalId::from_uuid(group)))
                .collect())
        })
    }

    async fn set_members(&mut self, group: PrincipalId, members: &[PrincipalId]) -> Result<MembershipDiff, StoreError> {
        observed!("memberships.set_members", {
            let tenant = self.tenant.as_uuid();
            let wanted: BTreeSet<Uuid> = members.iter().map(|member| member.as_uuid()).collect();
            self.guarded(move |conn| {
                Box::pin(async move {
                    lock_principal(&mut *conn, tenant, group.as_uuid()).await?;
                    let wanted_list: Vec<Uuid> = wanted.iter().copied().collect();
                    let existing = sqlx::query_scalar::<_, i64>(
                        "SELECT count(*) FROM principals WHERE tenant_id = $1 AND id = ANY($2)",
                    )
                    .bind(tenant)
                    .bind(&wanted_list)
                    .fetch_one(&mut *conn)
                    .await
                    .db()?;
                    if usize::try_from(existing).ok() != Some(wanted_list.len()) {
                        return Err(StoreError::NotFound);
                    }
                    let current: BTreeSet<Uuid> = sqlx::query_scalar::<_, Uuid>(
                        "SELECT member_id FROM memberships WHERE tenant_id = $1 AND group_id = $2",
                    )
                    .bind(tenant)
                    .bind(group.as_uuid())
                    .fetch_all(&mut *conn)
                    .await
                    .db()?
                    .into_iter()
                    .collect();
                    let added: Vec<Uuid> = wanted.difference(&current).copied().collect();
                    let removed: Vec<Uuid> = current.difference(&wanted).copied().collect();
                    sqlx::query(
                        "DELETE FROM memberships WHERE tenant_id = $1 AND group_id = $2 AND member_id = ANY($3)",
                    )
                    .bind(tenant)
                    .bind(group.as_uuid())
                    .bind(&removed)
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    sqlx::query(
                        "INSERT INTO memberships (tenant_id, group_id, member_id) \
                         SELECT $1, $2, m FROM unnest($3::uuid[]) AS m ON CONFLICT DO NOTHING",
                    )
                    .bind(tenant)
                    .bind(group.as_uuid())
                    .bind(&added)
                    .execute(&mut *conn)
                    .await
                    .db()?;
                    Ok(MembershipDiff {
                        added: added.into_iter().map(PrincipalId::from_uuid).collect(),
                        removed: removed.into_iter().map(PrincipalId::from_uuid).collect(),
                    })
                })
            })
            .await
        })
    }

    async fn add_member(&mut self, group: PrincipalId, member: PrincipalId) -> Result<bool, StoreError> {
        observed!("memberships.add_member", {
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    lock_principal(&mut *conn, tenant, group.as_uuid()).await?;
                    require_principal(&mut *conn, tenant, member.as_uuid()).await?;
                    let added = sqlx::query(
                        "INSERT INTO memberships (tenant_id, group_id, member_id) VALUES ($1, $2, $3) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(tenant)
                    .bind(group.as_uuid())
                    .bind(member.as_uuid())
                    .execute(&mut *conn)
                    .await
                    .db()?
                    .rows_affected();
                    Ok(added > 0)
                })
            })
            .await
        })
    }

    async fn remove_member(&mut self, group: PrincipalId, member: PrincipalId) -> Result<bool, StoreError> {
        observed!("memberships.remove_member", {
            let tenant = self.tenant.as_uuid();
            self.guarded(move |conn| {
                Box::pin(async move {
                    lock_principal(&mut *conn, tenant, group.as_uuid()).await?;
                    let removed = sqlx::query(
                        "DELETE FROM memberships WHERE tenant_id = $1 AND group_id = $2 AND member_id = $3",
                    )
                    .bind(tenant)
                    .bind(group.as_uuid())
                    .bind(member.as_uuid())
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
}
