//! The change log behind sync tokens (`collection_changes`, `principals_sync`).
//!
//! Every collection with a change log (calendar, home, inbox, notifications) has an *epoch*, a *sequence number*
//! and a *minimum sequence number* (older history was pruned). A sync token names `{collection}:{epoch}:{seq}`
//! (PLAN 2.7); the `CTag` is the same string. The store advances the sequence inside the write that causes a
//! change, so the log can never miss one:
//!
//! * calendar objects: [`ObjectRepo`](super::ObjectRepo) writes and [`CalendarRepo::touch`](super::CalendarRepo::touch);
//! * the home: bindings (`BindingRepo`) and [`ChangeRepo::touch_home`];
//! * the inbox and the notification collection: `InboxRepo`, `NotificationRepo` and the matching `touch_*`.

use async_trait::async_trait;
use davhaven_domain::{CollectionKey, ObjectUri, PrincipalId, SyncToken};
use uuid::Uuid;

use crate::error::StoreError;

/// What happened to a member of a collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeKind {
    /// The member was created or changed.
    Upsert,
    /// The member was deleted (sync reports it as a 404 response).
    Delete,
}

impl ChangeKind {
    /// The database spelling: `upsert` or `delete`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

/// One entry of a collection's change log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The sequence number of the change.
    pub seq: u64,
    /// The member's name: an object name in a calendar, a binding slug in a home, an item name in an inbox or a
    /// notification collection.
    pub uri: ObjectUri,
    /// What happened.
    pub kind: ChangeKind,
}

/// The sync state of a collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncPosition {
    /// The epoch of the log; bumped after a restore so old tokens stop working.
    pub epoch: Uuid,
    /// The sequence number of the latest change.
    pub seq: u64,
    /// The oldest sequence number a token can still resume from.
    pub min_seq: u64,
}

impl SyncPosition {
    /// The sync token (and `CTag`) of the collection at this position.
    pub const fn token(&self, collection: Uuid) -> SyncToken {
        SyncToken::new(collection, self.epoch, self.seq)
    }
}

/// The changes after a sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeBatch {
    /// At most one entry per member, the latest, ordered by sequence number.
    pub changes: Vec<Change>,
    /// The collection's current position.
    pub current: SyncPosition,
    /// Whether more changes exist than `limit` allowed; the caller continues from the last returned `seq`.
    pub truncated: bool,
}

/// The change log of the transaction's tenant.
#[async_trait]
pub trait ChangeRepo: Send {
    /// The current sync position of a collection (for `CTag`s and for tokens of an up-to-date client).
    ///
    /// # Ordering rule for full listings
    ///
    /// READ COMMITTED gives every statement a fresh snapshot, so a member listing and this position are not
    /// atomic. A full (initial) sync, or any answer that lists members together with a token, reads **this
    /// position first** and lists the members afterwards (`ObjectRepo::list`, `query`): a write that commits
    /// between the two reads is then in the listing *and* after the token, so the client sees it once more on
    /// its next sync, which is harmless. The other order loses the write: it is in the token but missing from
    /// the listing. `TxMode::Snapshot` makes both reads one snapshot and removes the question. The incremental
    /// path ([`since`](Self::since)) bounds its rows by the position it returns and is safe in either order.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar or principal behind the key does not exist.
    async fn state(&mut self, collection: CollectionKey) -> Result<SyncPosition, StoreError>;

    /// The changes of a collection after `seq`, at most `limit` entries (clamped to `1..=1000`).
    ///
    /// The token must be usable: `epoch` must equal the collection's epoch and `seq` must lie between `min_seq`
    /// and the current sequence number. Entries for the same member are collapsed to the latest.
    ///
    /// # Errors
    ///
    /// `InvalidSyncToken` for an unusable token (wrong epoch, pruned or from the future); the application maps
    /// it to `DAV:valid-sync-token` (the API answers 410 `sync-token-expired`). It is a variant of its own, so it
    /// is never mistaken for the 412 of a stale `If-Match` (`PreconditionFailed`). The application validates a
    /// client's token against [`state`](Self::state) with `SyncToken::resume_from` before calling, which is the
    /// cheaper check anyway. `NotFound` when the collection does not exist. For a truncated batch the caller
    /// builds the continuation token from the last returned `seq`.
    async fn since(
        &mut self,
        collection: CollectionKey,
        epoch: Uuid,
        seq: u64,
        limit: u32,
    ) -> Result<ChangeBatch, StoreError>;

    /// Advances the sequence of the principal's home collection and returns the new sequence number.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist.
    async fn touch_home(&mut self, principal: PrincipalId) -> Result<u64, StoreError>;

    /// Advances the sequence of the principal's scheduling inbox.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist.
    async fn touch_inbox(&mut self, principal: PrincipalId) -> Result<u64, StoreError>;

    /// Advances the sequence of the principal's notification collection.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist.
    async fn touch_notifications(&mut self, principal: PrincipalId) -> Result<u64, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_render_sync_tokens() {
        let position = SyncPosition {
            epoch: Uuid::from_u128(2),
            seq: 41,
            min_seq: 5,
        };
        let collection = Uuid::from_u128(1);
        let token = position.token(collection);
        assert_eq!(token, SyncToken::new(collection, Uuid::from_u128(2), 41));
        assert_eq!(
            token.resume_from(collection, position.epoch, position.min_seq, position.seq),
            Ok(41)
        );
    }

    #[test]
    fn change_kinds_use_their_database_spelling() {
        assert_eq!(ChangeKind::Upsert.as_str(), "upsert");
        assert_eq!(ChangeKind::Delete.as_str(), "delete");
    }
}
