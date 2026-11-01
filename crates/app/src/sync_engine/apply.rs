//! Writing what a pull found into the mirror calendar.
//!
//! The mirror is written through the batch use case of the object service (`ObjectService::batch`, PLAN 2.10), on the internal
//! channel that the sync engine is trusted with (`decide` allows `Channel::Internal` everything, which is how mirror
//! calendars, read-only for every principal, are written at all). So a pull has the same effects as any other write to a
//! calendar: the change log and the sync token advance exactly once per batch, `calendar.objects_changed` is emitted, the
//! content hash makes an unchanged event a no-op, and nothing is ever scheduled (mirror calendars do not schedule).
//!
//! # Keys
//!
//! An event is the object whose external key is [`event_key`] of the provider's id of the event: `r:` and 32 hex digits of the
//! SHA-256 of the id, so ids of any length and alphabet fit the `[A-Za-z0-9._:~-]{1,200}` of external keys and are unique.
//! Everything of a mirror calendar has the prefix [`KEY_PREFIX`], which is the scope of a snapshot.
//!
//! # What is tolerated
//!
//! A batch is all or nothing, and a provider that sends one event that cannot be stored (an unreadable event, two events with
//! the UID of one) must not stop the calendar. A chunk that fails is stored again without the entries that failed, up to
//! [`ROUNDS`] times; the entries that were left out are counted and logged, and the cursor moves on. A **delta** names an
//! event once, so one that was left out is not offered again with the same content. A **snapshot**, which is what the adapters
//! of 1.0 answer, lists every event on every pull, so an event that cannot be stored is tried again at every pull and left
//! out again (with a warning in the log) until the event changes at the provider.
//!
//! Deletions are applied **before** the stores: an event that comes back under a new id of the provider with the UID of the
//! old one would otherwise be refused for as long as the old object holds the UID. The chunks of a pull are separate
//! transactions: a pull that is cut off in the middle stores nothing of its cursor and starts again, and what it stored is
//! unchanged then.

use std::collections::HashSet;
use std::fmt::Write as _;

use davhaven_domain::{CalendarId, ExternalKey, RequestContext, RequestId, TenantId};
use davhaven_ports::{IndexFilter, PageReq, RemoteChanges, TxMode};
use davhaven_wire::{BatchItem, BatchMode, BatchOutcome, BatchRequest};
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::objects::locate::query_heads;
use crate::services::{CalendarRef, ObjectService};
use crate::wiring::AppCore;

/// The prefix of the external key of every object of a mirror calendar.
pub(crate) const KEY_PREFIX: &str = "r:";

/// How many times a chunk is stored again without the entries that failed.
const ROUNDS: usize = 5;

/// The most bytes of calendar data one chunk holds, so that a chunk of large events stays in memory bounds (the batch limit
/// of the API is 10 MiB).
const CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// How many objects of a mirror one page of the listing of its keys reads.
const KEY_PAGE: u32 = 1000;

/// What a pull did to the mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Applied {
    /// Events that were new.
    pub created: u32,
    /// Events whose content changed.
    pub updated: u32,
    /// Events that were as they were.
    pub unchanged: u32,
    /// Events that were removed.
    pub deleted: u32,
    /// Events that could not be stored and were left out.
    pub skipped: u32,
}

/// The external key of the event with the provider's id `remote_id`.
///
/// # Errors
///
/// `Internal` for a key that does not fit the alphabet of external keys, which the prefix and the hex digits always do.
pub(crate) fn event_key(remote_id: &str) -> AppResult<ExternalKey> {
    let digest = Sha256::digest(remote_id.as_bytes());
    let mut text = String::with_capacity(KEY_PREFIX.len() + 32);
    text.push_str(KEY_PREFIX);
    for byte in digest.iter().take(16) {
        // Writing into a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    ExternalKey::parse(&text).map_err(AppError::internal)
}

/// The batch writer of one mirror calendar.
pub(crate) struct Mirror<'a> {
    core: &'a AppCore,
    objects: &'a dyn ObjectService,
    tenant: TenantId,
    calendar: CalendarId,
}

impl<'a> Mirror<'a> {
    /// The writer of `calendar` of `tenant`.
    pub(crate) const fn new(
        core: &'a AppCore,
        objects: &'a dyn ObjectService,
        tenant: TenantId,
        calendar: CalendarId,
    ) -> Self {
        Self {
            core,
            objects,
            tenant,
            calendar,
        }
    }

    fn context(&self) -> RequestContext {
        RequestContext::internal(self.tenant, RequestId::from_uuid(self.core.deps().ids.new_id()))
    }

    /// The keys of every event the mirror holds.
    async fn held(&self) -> AppResult<HashSet<ExternalKey>> {
        let mut keys = HashSet::new();
        let mut tx = self.core.deps().database.begin(self.tenant, TxMode::ReadOnly).await?;
        let filter = IndexFilter {
            external_key_prefix: Some(KEY_PREFIX.to_owned()),
            ..IndexFilter::all()
        };
        let mut page = PageReq::first(KEY_PAGE);
        loop {
            let heads = query_heads(tx.as_mut(), self.calendar, &filter, page).await?;
            keys.extend(heads.items.into_iter().filter_map(|head| head.external_key));
            match heads.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        tx.commit().await?;
        Ok(keys)
    }

    /// Applies what a pull found: stores the events that are listed with their text, and removes what the provider deleted, or,
    /// for a snapshot, everything the list does not name.
    ///
    /// # Errors
    ///
    /// The failures of the store and of the calendar (`NotFound` when it is gone); an event that cannot be stored is counted in
    /// [`Applied::skipped`] instead.
    pub(crate) async fn apply(&self, changes: &RemoteChanges) -> AppResult<Applied> {
        let mut applied = Applied::default();
        let mut upserts: Vec<(ExternalKey, &str)> = Vec::new();
        let mut doomed: Vec<ExternalKey> = Vec::new();
        let mut listed: HashSet<ExternalKey> = HashSet::new();
        for change in &changes.changes {
            let key = event_key(&change.remote_id)?;
            match change.ics.as_deref() {
                Some(ics) => {
                    listed.insert(key.clone());
                    upserts.push((key, ics));
                }
                None => doomed.push(key),
            }
        }
        if changes.snapshot {
            // What the mirror holds and the list does not name was deleted remotely.
            let held = self.held().await?;
            doomed = held.into_iter().filter(|key| !listed.contains(key)).collect();
            doomed.sort();
        }
        // An event that is deleted and listed in the same answer is listed.
        doomed.retain(|key| !listed.contains(key));
        doomed.dedup();
        let limit = usize::try_from(self.core.deps().limits.api.max_batch_items)
            .unwrap_or(usize::MAX)
            .max(1);
        // Deletions first (they are idempotent): an event that came back under a new id of the provider holds the UID of the one
        // that is deleted, and would be refused as long as the old object is there.
        for chunk in doomed.chunks(limit) {
            let request = BatchRequest {
                deletes: chunk.to_vec(),
                ..BatchRequest::default()
            };
            let result = self
                .objects
                .batch(&self.context(), &CalendarRef::Id(self.calendar), request)
                .await?;
            applied.deleted = applied.deleted.saturating_add(count(&result, BatchOutcome::Deleted));
        }
        for chunk in chunks(upserts, limit) {
            self.store(chunk, &mut applied).await?;
        }
        Ok(applied)
    }

    /// Stores one chunk, again and again without the entries that failed.
    async fn store(&self, chunk: Vec<(ExternalKey, &str)>, applied: &mut Applied) -> AppResult<()> {
        let mut items: Vec<BatchItem> = chunk
            .into_iter()
            .map(|(external_key, ics)| BatchItem {
                external_key,
                event: None,
                ical: Some(ics.to_owned()),
            })
            .collect();
        for _round in 0..ROUNDS {
            if items.is_empty() {
                return Ok(());
            }
            let request = BatchRequest {
                mode: BatchMode::Merge,
                items: items.clone(),
                ..BatchRequest::default()
            };
            let result = self
                .objects
                .batch(&self.context(), &CalendarRef::Id(self.calendar), request)
                .await?;
            if !result.has_failures() {
                applied.created = applied.created.saturating_add(count(&result, BatchOutcome::Created));
                applied.updated = applied.updated.saturating_add(count(&result, BatchOutcome::Updated));
                applied.unchanged = applied
                    .unchanged
                    .saturating_add(count(&result, BatchOutcome::Unchanged));
                return Ok(());
            }
            let failed: HashSet<ExternalKey> = result
                .results
                .iter()
                .filter(|entry| entry.outcome == BatchOutcome::Failed)
                .map(|entry| entry.external_key.clone())
                .collect();
            for entry in result
                .results
                .iter()
                .filter(|entry| entry.outcome == BatchOutcome::Failed)
            {
                tracing::warn!(
                    tenant = %self.tenant,
                    calendar = %self.calendar,
                    key = %entry.external_key,
                    problem = entry.problem.as_ref().map_or("unknown", |problem| problem.code.code()),
                    "an event of a provider calendar cannot be stored and is left out"
                );
            }
            applied.skipped = applied
                .skipped
                .saturating_add(u32::try_from(failed.len()).unwrap_or(u32::MAX));
            items.retain(|item| !failed.contains(&item.external_key));
        }
        // Entries that failed only after the others were taken out, five times over: leave them out rather than loop.
        applied.skipped = applied
            .skipped
            .saturating_add(u32::try_from(items.len()).unwrap_or(u32::MAX));
        Ok(())
    }
}

/// The entries of `result` with `outcome`.
fn count(result: &davhaven_wire::BatchResult, outcome: BatchOutcome) -> u32 {
    u32::try_from(result.results.iter().filter(|entry| entry.outcome == outcome).count()).unwrap_or(u32::MAX)
}

/// Splits the events into chunks of at most `limit` entries and [`CHUNK_BYTES`] of calendar data.
fn chunks(events: Vec<(ExternalKey, &str)>, limit: usize) -> Vec<Vec<(ExternalKey, &str)>> {
    let mut chunks = Vec::new();
    let mut current: Vec<(ExternalKey, &str)> = Vec::new();
    let mut bytes = 0_usize;
    for event in events {
        let size = event.1.len();
        if !current.is_empty() && (current.len() >= limit || bytes.saturating_add(size) > CHUNK_BYTES) {
            chunks.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes = bytes.saturating_add(size);
        current.push(event);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_fixed_short_and_unique_for_any_provider_id() {
        let plain = event_key("abc123").unwrap();
        assert_eq!(plain.as_str().len(), 34);
        assert!(plain.as_str().starts_with(KEY_PREFIX));
        assert_eq!(plain, event_key("abc123").unwrap(), "the same id has the same key");
        assert_ne!(plain, event_key("abc124").unwrap());
        // Graph ids carry `=`, `-` and `_`; Google ids can be long; neither fits an external key as it is.
        let graph = event_key("AAMkAGI2TG93AAA=").unwrap();
        let long = event_key(&"x".repeat(5000)).unwrap();
        for key in [graph, long] {
            assert_eq!(key.as_str().len(), 34);
        }
        assert_eq!(
            event_key("a").unwrap().as_str(),
            "r:ca978112ca1bbdcafac231b39a23dc4d",
            "the first 128 bits of the SHA-256 of the id"
        );
    }

    #[test]
    fn chunks_respect_the_entry_and_the_byte_limits_and_keep_the_order() {
        let key = |n: u32| event_key(&n.to_string()).unwrap();
        let events: Vec<(ExternalKey, &str)> = (0..7).map(|n| (key(n), "BEGIN:VCALENDAR")).collect();
        let sizes: Vec<usize> = chunks(events, 3).iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![3, 3, 1]);
        assert_eq!(chunks(Vec::new(), 3).len(), 0);
        let big = "x".repeat(CHUNK_BYTES / 2 + 1);
        let events = vec![(key(1), big.as_str()), (key(2), big.as_str()), (key(3), "small")];
        let sizes: Vec<usize> = chunks(events, 1000).iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![1, 2], "two large events do not share a chunk");
        let single = vec![(key(1), big.as_str())];
        assert_eq!(
            chunks(single, 1000).len(),
            1,
            "an event larger than the budget still has a chunk"
        );
    }
}
