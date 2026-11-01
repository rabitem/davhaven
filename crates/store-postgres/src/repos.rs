//! Repository implementations.
//!
//! [`PgTx`](crate::tx::PgTx) and [`PgSystemTx`](crate::tx::PgSystemTx) implement the repository traits of the
//! `Database` port, one module per group of aggregates. The modules share a few conventions:
//!
//! * every method runs inside [`observe`](davhaven_ports::observe()) (`ENGINEERING_RULES` R8) through the
//!   `observed!` macro, with a static operation name such as `principals.get`;
//! * every query is a literal `&'static str` with bind parameters (the object query alone is assembled from the shape of
//!   its filter with `QueryBuilder`, so that the time-range indexes stay usable; every value is still a bound
//!   parameter) and names the tenant explicitly (the row-level security policies are the second line of defence, not
//!   the first);
//! * rows are read into private `FromRow` structs and converted to domain entities with the validating
//!   constructors, so a corrupt row surfaces as [`StoreError::Internal`] instead of an invalid entity;
//! * writes run in a savepoint (`PgTx::guarded`), so a failed write changes nothing;
//! * timestamps come from the injected clock and are truncated to the microseconds PostgreSQL stores.

use core::fmt::Display;

pub(crate) use davhaven_ports::store::{lease_end, micros};
use davhaven_ports::{PortLabel, StoreError};

use crate::error::map_sqlx;

/// The label of every observed call of this adapter.
pub(crate) const LABEL: PortLabel = PortLabel::new("database", "postgres");

/// Runs `$body` (an expression that may use `?` and `.await`) as the observed operation `$op`.
macro_rules! observed {
    ($op:literal, $body:expr) => {
        ::davhaven_ports::observe($crate::repos::LABEL, $op, async move { $body }).await
    };
}

#[macro_use]
mod columns;
mod calendars;
mod credentials;
mod delivery;
mod messages;
mod objects;
mod principals;
mod records;
mod sync;
mod system;
mod tenant;

/// Turns a driver result into a store result.
pub(crate) trait DbResult<T> {
    /// Maps the driver error with [`map_sqlx`].
    fn db(self) -> Result<T, StoreError>;
}

impl<T> DbResult<T> for Result<T, sqlx::Error> {
    fn db(self) -> Result<T, StoreError> {
        self.map_err(map_sqlx)
    }
}

/// The error for a stored value that fails validation: the row is corrupt or was written by a bug.
pub(crate) fn corrupt(what: &str, error: impl Display) -> StoreError {
    StoreError::internal(format!("stored {what} is invalid: {error}"))
}

/// Validates a stored value with the constructor of its domain type.
pub(crate) fn decode<T, E: Display>(what: &str, result: Result<T, E>) -> Result<T, StoreError> {
    result.map_err(|error| corrupt(what, error))
}

/// Validates an optional stored value.
pub(crate) fn decode_opt<T, E: Display>(
    what: &str,
    value: Option<&str>,
    parse: impl FnOnce(&str) -> Result<T, E>,
) -> Result<Option<T>, StoreError> {
    value.map(parse).transpose().map_err(|error| corrupt(what, error))
}

/// A `u64` as the `bigint` the database stores.
pub(crate) fn to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::internal("a number does not fit the database column"))
}

/// A `bigint` as a `u64`.
pub(crate) fn to_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| corrupt("sequence number", "negative"))
}

/// The error for a write attempted through a repository that cannot do it.
pub(crate) fn misuse(message: &str) -> StoreError {
    StoreError::internal(message.to_owned())
}

/// The error for an update or delete that matched no row because of its version condition: `NotFound` when the
/// row does not exist (`exists` is `SELECT 1 ... WHERE tenant_id = $1 AND id = $2`), `PreconditionFailed` when it
/// exists with another version.
pub(crate) async fn stale_or_missing(
    conn: &mut sqlx::PgConnection,
    exists: &'static str,
    tenant: uuid::Uuid,
    id: uuid::Uuid,
) -> StoreError {
    match sqlx::query_scalar::<_, i32>(exists)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
    {
        Ok(Some(_)) => StoreError::PreconditionFailed,
        Ok(None) => StoreError::NotFound,
        Err(error) => map_sqlx(error),
    }
}

/// Like [`stale_or_missing`] for a row that has no tenant (`SELECT 1 FROM tenants WHERE id = $1`).
pub(crate) async fn stale_or_missing_global(
    conn: &mut sqlx::PgConnection,
    exists: &'static str,
    id: uuid::Uuid,
) -> StoreError {
    match sqlx::query_scalar::<_, i32>(exists)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
    {
        Ok(Some(_)) => StoreError::PreconditionFailed,
        Ok(None) => StoreError::NotFound,
        Err(error) => map_sqlx(error),
    }
}

#[cfg(test)]
mod tests {
    /// R4: the contract suite calls every repository method of a tenant transaction with the ids of another tenant.
    /// This fails when a method is added to a tenant-bound module without being listed (and so without a case).
    #[test]
    fn every_tenant_operation_has_an_isolation_case() {
        davhaven_port_tests::store::assert_isolation_covers(&[
            ("calendars.rs", include_str!("repos/calendars.rs")),
            ("credentials.rs", include_str!("repos/credentials.rs")),
            ("delivery.rs", include_str!("repos/delivery.rs")),
            ("messages.rs", include_str!("repos/messages.rs")),
            ("objects.rs", include_str!("repos/objects.rs")),
            ("principals.rs", include_str!("repos/principals.rs")),
            ("records.rs", include_str!("repos/records.rs")),
            ("sync.rs", include_str!("repos/sync.rs")),
            ("tenant.rs", include_str!("repos/tenant.rs")),
        ]);
    }
}
