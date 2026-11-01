//! The change log behind sync tokens, and the helpers that advance it.
//!
//! The sequence of a calendar lives on the calendar (`sync_seq`), the sequences of a principal's home, inbox and
//! notification collection in the principal's [`PrincipalSync`](crate::state::PrincipalSync). Every write that
//! changes what a client sees advances the sequence exactly once and logs the change at that sequence number.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarId, CollectionKey, CollectionKind, ObjectUri, PrincipalId};
use davhaven_ports::store::MAX_PAGE_LIMIT;
use davhaven_ports::{Change, ChangeBatch, ChangeKind, ChangeRepo, StoreError, SyncPosition};
use uuid::Uuid;

use super::{misuse, to_i64};
use crate::state::{ChangeEntry, TenantData};
use crate::tx::MemTx;

impl TenantData {
    /// Advances the sequence of a live calendar and returns the new value; `None` when it does not exist.
    pub(super) fn bump_calendar(&mut self, id: CalendarId) -> Option<u64> {
        let calendar = self
            .calendars
            .get_mut(&id)
            .filter(|calendar| calendar.deleted_at.is_none())?;
        calendar.sync_seq = calendar.sync_seq.saturating_add(1);
        u64::try_from(calendar.sync_seq).ok()
    }

    /// Advances the sequence of a principal's home, inbox or notification collection.
    pub(super) fn bump_principal(&mut self, principal: PrincipalId, kind: CollectionKind) -> Option<u64> {
        let position = self.sync.get_mut(&principal)?.position_mut(kind)?;
        position.seq = position.seq.saturating_add(1);
        Some(position.seq)
    }

    /// Advances a principal collection and logs the change in one step; returns the new sequence number.
    pub(super) fn record_principal_change(
        &mut self,
        principal: PrincipalId,
        kind: CollectionKind,
        uri: &str,
        change: ChangeKind,
        at: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        let uri = ObjectUri::parse(uri).map_err(|error| misuse(&error.to_string()))?;
        let seq = self.bump_principal(principal, kind).ok_or(StoreError::NotFound)?;
        self.log(
            kind,
            principal.as_uuid(),
            ChangeEntry {
                seq,
                uri,
                kind: change,
                at,
            },
        );
        Ok(seq)
    }

    /// Logs the change of a calendar object at an already advanced sequence number.
    pub(super) fn log_calendar_change(
        &mut self,
        calendar: CalendarId,
        seq: u64,
        uri: &ObjectUri,
        change: ChangeKind,
        at: DateTime<Utc>,
    ) {
        self.log(
            CollectionKind::Calendar,
            calendar.as_uuid(),
            ChangeEntry {
                seq,
                uri: uri.clone(),
                kind: change,
                at,
            },
        );
    }

    /// The sync position of a collection.
    pub(super) fn position(&self, collection: CollectionKey) -> Option<SyncPosition> {
        if collection.kind == CollectionKind::Calendar {
            let calendar = self
                .calendars
                .get(&CalendarId::from_uuid(collection.id))
                .filter(|calendar| calendar.deleted_at.is_none())?;
            return Some(SyncPosition {
                epoch: calendar.sync_epoch,
                seq: u64::try_from(calendar.sync_seq).ok()?,
                min_seq: u64::try_from(calendar.sync_min_seq).ok()?,
            });
        }
        self.sync
            .get(&PrincipalId::from_uuid(collection.id))?
            .position(collection.kind)
            .copied()
    }
}

/// Sets the minimum sequence of a collection (retention).
pub(super) fn raise_min_seq(data: &mut TenantData, kind: CollectionKind, collection: Uuid, max_pruned: u64) {
    if kind == CollectionKind::Calendar {
        if let Some(calendar) = data.calendars.get_mut(&CalendarId::from_uuid(collection)) {
            calendar.sync_min_seq = calendar.sync_min_seq.max(to_i64(max_pruned));
        }
    } else if let Some(position) = data
        .sync
        .get_mut(&PrincipalId::from_uuid(collection))
        .and_then(|sync| sync.position_mut(kind))
    {
        position.min_seq = position.min_seq.max(max_pruned);
    }
}

#[async_trait]
impl ChangeRepo for MemTx {
    async fn state(&mut self, collection: CollectionKey) -> Result<SyncPosition, StoreError> {
        observed!(
            "changes.state",
            self.view().position(collection).ok_or(StoreError::NotFound)
        )
    }

    async fn since(
        &mut self,
        collection: CollectionKey,
        epoch: Uuid,
        seq: u64,
        limit: u32,
    ) -> Result<ChangeBatch, StoreError> {
        observed!("changes.since", {
            let data = self.view();
            let current = data.position(collection).ok_or(StoreError::NotFound)?;
            if epoch != current.epoch || seq < current.min_seq || seq > current.seq {
                return Err(StoreError::InvalidSyncToken);
            }
            let limit = usize::try_from(limit.clamp(1, MAX_PAGE_LIMIT)).unwrap_or(usize::MAX);
            let mut latest: BTreeMap<&ObjectUri, &ChangeEntry> = BTreeMap::new();
            if let Some(entries) = data.changes.get(&(collection.kind, collection.id)) {
                for entry in entries
                    .iter()
                    .filter(|entry| entry.seq > seq && entry.seq <= current.seq)
                {
                    latest.insert(&entry.uri, entry);
                }
            }
            let mut changes: Vec<Change> = latest
                .values()
                .map(|entry| Change {
                    seq: entry.seq,
                    uri: entry.uri.clone(),
                    kind: entry.kind,
                })
                .collect();
            changes.sort_by_key(|change| change.seq);
            let truncated = changes.len() > limit;
            changes.truncate(limit);
            Ok(ChangeBatch {
                changes,
                current,
                truncated,
            })
        })
    }

    async fn touch_home(&mut self, principal: PrincipalId) -> Result<u64, StoreError> {
        observed!("changes.touch_home", {
            self.writable()?
                .bump_principal(principal, CollectionKind::Home)
                .ok_or(StoreError::NotFound)
        })
    }

    async fn touch_inbox(&mut self, principal: PrincipalId) -> Result<u64, StoreError> {
        observed!("changes.touch_inbox", {
            self.writable()?
                .bump_principal(principal, CollectionKind::Inbox)
                .ok_or(StoreError::NotFound)
        })
    }

    async fn touch_notifications(&mut self, principal: PrincipalId) -> Result<u64, StoreError> {
        observed!("changes.touch_notifications", {
            self.writable()?
                .bump_principal(principal, CollectionKind::Notifications)
                .ok_or(StoreError::NotFound)
        })
    }
}
