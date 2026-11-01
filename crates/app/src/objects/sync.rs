//! `sync-collection` (RFC 6578, `sync-level` 1) and the changes feed of the management API.
//!
//! Both are answered from the change log the store keeps next to every collection (PLAN 2.7). The state of the
//! collection is read **before** its members are listed, so a write that commits in between is both in the listing
//! and after the token: the client sees it once more on its next sync, and never misses it. A token that is
//! foreign, garbled, from another epoch, from the future or older than the pruned history answers
//! `DAV:valid-sync-token` (the API answers 410 `sync-token-expired`). Members that were deleted are reported with
//! their name only.
//!
//! Truncation (`limit`): an incremental answer stops after `limit` members and carries the token of the last one,
//! so the client continues from there. An initial answer can only be cut when the log was never pruned
//! (`sync_min_seq` is 0): its token then is "the beginning of the log", from which the remaining members arrive as
//! changes. With a pruned log the whole listing is returned.

use std::collections::HashMap;

use davhaven_domain::{
    AccessFacts, CalendarId, CollectionKey, CollectionKind, ETag, ExternalKey, ObjectUri, Operation, Precondition,
    RequestContext, ResourcePath, SyncToken, Uid, effective_access,
};
use davhaven_ports::{ChangeKind, IndexFilter, ObjectHead, PageReq, Tx, TxMode};
use davhaven_wire::{ChangeKind as WireChange, ChangeView, ChangesResponse};

use super::ObjectServiceImpl;
use super::locate::{Target, api_calendar, list_heads, locate, query_heads};
use crate::authz::{Home, enforce, home_facts, resolve_home};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::services::{CalendarRef, SyncChange, SyncResult};

/// The most changes one incremental answer carries (the limit of the change log).
const MAX_CHANGES: u32 = 1000;

fn invalid_token() -> AppError {
    AppError::invalid(SafeMessage::from_static(
        "The sync token is not valid; start a new sync.",
    ))
    .with_precondition(Precondition::ValidSyncToken)
}

/// One member of an answer: a name and, when it exists, its head.
struct Entry {
    uri: ObjectUri,
    head: Option<ObjectHead>,
}

/// The members of an answer, the token to continue from and whether the answer is cut.
struct Collected {
    token: SyncToken,
    entries: Vec<Entry>,
    truncated: bool,
}

/// All heads of a calendar, in id order, up to `max_members` (`limits.dav.max_sync_members`).
async fn all_heads(
    tx: &mut dyn Tx,
    calendar: davhaven_domain::CalendarId,
    max_members: usize,
) -> AppResult<Vec<ObjectHead>> {
    let mut heads = Vec::new();
    let mut page = PageReq::first(500);
    loop {
        let batch = list_heads(tx, calendar, page).await?;
        heads.extend(batch.items);
        if heads.len() > max_members {
            return Err(
                AppError::invalid(SafeMessage::from_static("The collection is too large to list."))
                    .with_precondition(Precondition::NumberOfMatchesWithinLimits),
            );
        }
        match batch.next {
            Some(after) => page = page.after(after),
            None => return Ok(heads),
        }
    }
}

/// The heads of the named objects.
async fn heads_named(
    tx: &mut dyn Tx,
    calendar: davhaven_domain::CalendarId,
    names: &[ObjectUri],
) -> AppResult<HashMap<ObjectUri, ObjectHead>> {
    let mut found = HashMap::new();
    for chunk in names.chunks(1000) {
        let filter = IndexFilter {
            uris: Some(chunk.to_vec()),
            ..IndexFilter::all()
        };
        let batch = query_heads(tx, calendar, &filter, PageReq::first(1000)).await?;
        found.extend(batch.items.into_iter().map(|head| (head.uri.clone(), head)));
    }
    Ok(found)
}

/// The change log entries of a calendar after `since`, or all members without a token.
async fn collect(
    tx: &mut dyn Tx,
    calendar: &davhaven_domain::Calendar,
    since: Option<SyncToken>,
    limit: Option<u32>,
    max_members: usize,
) -> AppResult<Collected> {
    let calendar = calendar.id;
    let collection = calendar.as_uuid();
    let key = CollectionKey {
        kind: CollectionKind::Calendar,
        id: collection,
    };
    // The state is read first: see the module documentation.
    let position = tx.changes().state(key).await?;
    let Some(token) = since else {
        let mut heads = all_heads(tx, calendar, max_members).await?;
        let cut = limit
            .and_then(|limit| usize::try_from(limit.max(1)).ok())
            .filter(|limit| position.min_seq == 0 && heads.len() > *limit);
        if let Some(limit) = cut {
            heads.truncate(limit);
        }
        return Ok(Collected {
            token: SyncToken::new(collection, position.epoch, if cut.is_some() { 0 } else { position.seq }),
            entries: heads
                .into_iter()
                .map(|head| Entry {
                    uri: head.uri.clone(),
                    head: Some(head),
                })
                .collect(),
            truncated: cut.is_some(),
        });
    };
    let from = token
        .resume_from(collection, position.epoch, position.min_seq, position.seq)
        .map_err(|_| invalid_token())?;
    let batch = tx
        .changes()
        .since(
            key,
            position.epoch,
            from,
            limit.unwrap_or(MAX_CHANGES).clamp(1, MAX_CHANGES),
        )
        .await?;
    let upserts: Vec<ObjectUri> = batch
        .changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Upsert)
        .map(|change| change.uri.clone())
        .collect();
    let mut heads = heads_named(tx, calendar, &upserts).await?;
    let resume = if batch.truncated {
        batch.changes.last().map_or(batch.current.seq, |change| change.seq)
    } else {
        batch.current.seq
    };
    let entries = batch
        .changes
        .iter()
        .map(|change| Entry {
            uri: change.uri.clone(),
            // An object that was deleted after the batch was cut is reported as deleted.
            head: match change.kind {
                ChangeKind::Upsert => heads.remove(&change.uri),
                ChangeKind::Delete => None,
            },
        })
        .collect();
    Ok(Collected {
        token: SyncToken::new(collection, batch.current.epoch, resume),
        entries,
        truncated: batch.truncated,
    })
}

/// What the answer for a home-level collection is made of.
struct HomeAnswer {
    /// The member names and whether each was deleted.
    members: Vec<(ObjectUri, bool)>,
    /// What the collection has now: the name of every member and, for those that have one, its `ETag`.
    live: HashMap<ObjectUri, Option<ETag>>,
    /// The token to continue from.
    token: SyncToken,
    /// Whether the answer is cut.
    truncated: bool,
}

/// What a home-level collection holds now, read together for all members: the bindings of a home that are visible
/// (not hidden, and the caller still has access to the calendar: a removed group member or a revoked grant ends
/// the access without any change of the binding), the delivered inbox items or the notifications, with their
/// `ETag`s. A member that is not here is reported as deleted, however the change log came to name it.
async fn current_members(
    tx: &mut dyn Tx,
    home: &Home,
    kind: CollectionKind,
) -> AppResult<Vec<(ObjectUri, Option<ETag>)>> {
    Ok(match kind {
        CollectionKind::Home => {
            let bound: Vec<_> = tx
                .bindings()
                .list_for(home.principal.id)
                .await?
                .into_iter()
                .filter(|bound| !bound.binding.hidden)
                .collect();
            let ids: Vec<CalendarId> = bound.iter().map(|bound| bound.calendar.id).collect();
            let facts: HashMap<CalendarId, AccessFacts> = tx
                .calendars()
                .access_facts_many(&ids, Some(home.principal.id))
                .await?
                .into_iter()
                .collect();
            bound
                .into_iter()
                .filter(|bound| {
                    facts
                        .get(&bound.calendar.id)
                        .is_some_and(|facts| effective_access(home.principal.id, facts).is_some())
                })
                .filter_map(|bound| ObjectUri::parse(bound.binding.slug.as_str()).ok())
                .map(|uri| (uri, None))
                .collect()
        }
        CollectionKind::Inbox => tx
            .inbox()
            .list(home.principal.id, davhaven_ports::InboxScope::Delivered)
            .await?
            .into_iter()
            .map(|item| (item.uri, Some(item.etag)))
            .collect(),
        _ => tx
            .notifications()
            .list(home.principal.id)
            .await?
            .into_iter()
            .map(|notification| (notification.uri, Some(notification.etag)))
            .collect(),
    })
}

/// The members of an answer for a home-level collection: all of them without a token, the changes since it with one.
async fn home_members(
    tx: &mut dyn Tx,
    home: &Home,
    kind: CollectionKind,
    since: Option<SyncToken>,
    limit: Option<u32>,
) -> AppResult<HomeAnswer> {
    let id = home.principal.id.as_uuid();
    let key = CollectionKey { kind, id };
    // The state is read first: see the module documentation.
    let position = tx.changes().state(key).await?;
    let Some(token) = since else {
        let current = current_members(tx, home, kind).await?;
        return Ok(HomeAnswer {
            members: current.iter().map(|(uri, _)| (uri.clone(), false)).collect(),
            live: current.into_iter().collect(),
            token: position.token(id),
            truncated: false,
        });
    };
    let from = token
        .resume_from(id, position.epoch, position.min_seq, position.seq)
        .map_err(|_| invalid_token())?;
    let batch = tx
        .changes()
        .since(
            key,
            position.epoch,
            from,
            limit.unwrap_or(MAX_CHANGES).clamp(1, MAX_CHANGES),
        )
        .await?;
    let resume = if batch.truncated {
        batch.changes.last().map_or(batch.current.seq, |change| change.seq)
    } else {
        batch.current.seq
    };
    let live = current_members(tx, home, kind).await?.into_iter().collect();
    Ok(HomeAnswer {
        members: batch
            .changes
            .iter()
            .map(|change| (change.uri.clone(), change.kind == ChangeKind::Delete))
            .collect(),
        live,
        token: SyncToken::new(id, batch.current.epoch, resume),
        truncated: batch.truncated,
    })
}

/// The resource of a member of a home-level collection: bindings are collections of the home, the others are
/// children of the collection.
fn member_path(collection: &ResourcePath, home: &Home, kind: CollectionKind, uri: &ObjectUri) -> Option<ResourcePath> {
    match kind {
        CollectionKind::Home => {
            davhaven_domain::CalendarSlug::parse(uri.as_str())
                .ok()
                .map(|binding| ResourcePath::Collection {
                    tenant: home.tenant.slug.clone(),
                    principal: home.principal.name.clone(),
                    binding,
                })
        }
        _ => collection.child(uri.clone()),
    }
}

impl ObjectServiceImpl {
    /// `sync-collection` on a calendar, the home, the inbox or the notification collection.
    pub(crate) async fn sync_members(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<SyncResult> {
        if let Some((target, None)) = Target::of(collection) {
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
            let located = locate(tx.as_mut(), ctx, target, false).await?;
            enforce(ctx, &located.facts, Operation::ListObjects, || collection.href())?;
            let max_members = usize::try_from(self.core.deps().limits.dav.max_sync_members).unwrap_or(usize::MAX);
            let collected = collect(tx.as_mut(), &located.calendar, since, limit, max_members).await?;
            tx.commit().await?;
            let changes = collected
                .entries
                .into_iter()
                .map(|entry| SyncChange {
                    path: located.object_path(&entry.uri),
                    kind: if entry.head.is_some() {
                        WireChange::Upsert
                    } else {
                        WireChange::Delete
                    },
                    etag: entry.head.map(|head| head.etag),
                })
                .collect();
            return Ok(SyncResult {
                sync_token: collected.token,
                changes,
                truncated: collected.truncated,
            });
        }
        self.sync_home_level(ctx, collection, since, limit).await
    }

    /// The change logs of a principal: home, inbox and notifications.
    async fn sync_home_level(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<SyncResult> {
        let (tenant, principal, kind, operation) = match collection {
            ResourcePath::Home { tenant, principal } => {
                (tenant, principal, CollectionKind::Home, Operation::ReadCollection)
            }
            ResourcePath::Inbox { tenant, principal } => {
                (tenant, principal, CollectionKind::Inbox, Operation::ReadInbox)
            }
            ResourcePath::Notifications { tenant, principal } => (
                tenant,
                principal,
                CollectionKind::Notifications,
                Operation::ReadNotifications,
            ),
            _ => return Err(AppError::not_found()),
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
        enforce(ctx, &home_facts(&home.tenant, &home.principal), operation, || {
            collection.href()
        })?;
        let answer = home_members(tx.as_mut(), &home, kind, since, limit).await?;
        tx.commit().await?;
        let mut changes = Vec::with_capacity(answer.members.len());
        for (uri, deleted) in answer.members {
            let Some(path) = member_path(collection, &home, kind, &uri) else {
                continue;
            };
            // A member that is not there by now (deleted after the change was logged, a binding that was hidden or
            // lost its access) is reported as deleted, the way a `PROPFIND` and the initial listing treat it.
            let live = (!deleted).then(|| answer.live.get(&uri)).flatten();
            changes.push(SyncChange {
                path,
                kind: if live.is_some() {
                    WireChange::Upsert
                } else {
                    WireChange::Delete
                },
                etag: live.cloned().flatten(),
            });
        }
        Ok(SyncResult {
            sync_token: answer.token,
            changes,
            truncated: answer.truncated,
        })
    }
    /// The changes feed of a calendar (management API).
    pub(crate) async fn feed_changes(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        since: Option<SyncToken>,
        limit: Option<u32>,
    ) -> AppResult<ChangesResponse> {
        crate::authz::require_scope(ctx, Operation::ListObjects)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let target = api_calendar(tx.as_mut(), ctx, calendar, Operation::ListObjects, false).await?;
        let max_members = usize::try_from(self.core.deps().limits.dav.max_sync_members).unwrap_or(usize::MAX);
        let collected = collect(tx.as_mut(), &target.calendar, since, limit, max_members).await?;
        tx.commit().await?;
        let changes = collected
            .entries
            .into_iter()
            .map(|entry| match entry.head {
                Some(head) => ChangeView {
                    kind: WireChange::Upsert,
                    uri: head.uri,
                    uid: Some(head.uid),
                    external_key: head.external_key,
                    etag: Some(head.etag),
                },
                None => ChangeView {
                    kind: WireChange::Delete,
                    uri: entry.uri,
                    uid: None::<Uid>,
                    external_key: None::<ExternalKey>,
                    etag: None,
                },
            })
            .collect();
        Ok(ChangesResponse {
            sync_token: collected.token,
            changes,
            truncated: collected.truncated,
        })
    }
}
