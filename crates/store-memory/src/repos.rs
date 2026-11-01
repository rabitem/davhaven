//! Repository implementations.
//!
//! [`MemTx`](crate::tx::MemTx) and [`MemSystemTx`](crate::tx::MemSystemTx) implement the repository traits of the
//! `Database` port, one module per group of aggregates, with the semantics of the PostgreSQL adapter: the same
//! errors in the same situations (a parent that does not exist is `NotFound`, unique keys are typed, a stale
//! version is `PreconditionFailed`), the same orderings, the same write invariant. The port contract suite runs
//! against both, so they cannot drift apart.
//!
//! A failed method leaves the state as it was: every method checks everything before it changes anything.

pub(crate) use davhaven_ports::store::{lease_end, micros};
use davhaven_ports::{PageReq, PortLabel, StoreError, StorePage};
use uuid::Uuid;

/// The label of every observed call of this adapter.
pub(crate) const LABEL: PortLabel = PortLabel::new("database", "memory");

/// Runs `$body` (an expression that may use `?`) as the observed operation `$op`.
macro_rules! observed {
    ($op:literal, $body:expr) => {
        ::davhaven_ports::observe($crate::repos::LABEL, $op, async move { $body }).await
    };
}

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

/// Refuses text the PostgreSQL adapter cannot store: PostgreSQL rejects the character U+0000 in `text` and `jsonb`
/// (SQLSTATE 22021 and 22P05), so a test on this adapter that stores it would pass for input that is an error in
/// production. Both adapters answer [`StoreError::InvalidData`]. Only the free-text fields people can type are
/// checked (names, descriptions, labels, summaries, properties, iCalendar and notification text); machine-made
/// JSON and validated keys cannot contain it.
pub(crate) fn no_nul<'a>(what: &str, texts: impl IntoIterator<Item = Option<&'a str>>) -> Result<(), StoreError> {
    if texts.into_iter().flatten().any(|text| text.contains('\0')) {
        Err(StoreError::InvalidData(format!("{what} contains the character U+0000")))
    } else {
        Ok(())
    }
}

/// The error for a misuse of a repository (a value that cannot be stored this way).
pub(crate) fn misuse(message: &str) -> StoreError {
    StoreError::internal(message.to_owned())
}

/// Builds the page after `page.after` from items in ascending id order.
pub(crate) fn paginate<T>(items: impl Iterator<Item = T>, page: &PageReq, id_of: impl Fn(&T) -> Uuid) -> StorePage<T> {
    let limit = usize::try_from(page.effective_limit()).unwrap_or(usize::MAX);
    let rows: Vec<T> = items
        .filter(|item| page.after.is_none_or(|after| id_of(item) > after))
        .take(limit.saturating_add(1))
        .collect();
    StorePage::from_overfetched(rows, page, id_of)
}

/// A `u64` sequence number as the `i64` of the entity.
pub(crate) fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The most rows a retention call removes, as in the PostgreSQL adapter.
pub(crate) const PURGE_BATCH: usize = 5000;

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
