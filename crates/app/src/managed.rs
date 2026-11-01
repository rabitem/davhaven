//! Managed calendars written through the management API: batch upsert.
//!
//! `POST …/calendars/{calendar}/objects/batch` (PLAN 2.10) writes up to 1000 objects, keyed by the caller's
//! `external_key`, in **one transaction, all or nothing**:
//!
//! * `merge` mode touches only the listed objects and the explicit `deletes`; `replace` mode also deletes the objects
//!   whose key starts with `replace_scope_prefix` and that are not listed, so one integration cannot wipe the objects
//!   of another. `max_deletes` bounds how many objects a batch may delete, and a `replace` batch without items, which
//!   deletes everything in its scope whatever `deletes` adds, is only accepted with `allow_empty`.
//! * An item is either an `event` (JSON, merged into the stored component like every JSON write) or `ical`
//!   (iCalendar text). The UID is `UUIDv5(calendar_id, external_key)` unless the item carries one.
//! * An item whose content hash equals the stored one is `unchanged`: nothing is written, the `ETag` and the sync
//!   token stay. A changed object gets a higher `SEQUENCE` than the stored one.
//! * A batch **never schedules**: attendees are not notified, whatever the objects say.
//! * When any item fails, nothing is written: the result lists every entry, the failed ones with their problem
//!   (the API answers 422), and the sync token is the unchanged one.
//! * One `calendar.objects_changed` event describes the whole batch.
//!
//! # Work outside the lock
//!
//! A batch is up to 10 MiB of calendar data, and every writer of the calendar queues behind the lock the write takes
//! (PLAN 2.15, `ENGINEERING_RULES` R14). So the lock is taken for the stores only. The batch is read without it
//! (the calendar, the objects its items name, what a `replace` would delete); every item is merged, validated,
//! indexed and given its `SEQUENCE` on blocking threads outside any transaction; an item that fails here fails the
//! batch without the lock having been taken at all. Only then is the calendar locked and checked: when it moved
//! since the read, every item must still be based on the object it was merged with, otherwise the attempt starts
//! over. After the first entry that fails in the store, the remaining entries are validated but no longer stored.

use std::collections::{HashMap, HashSet};

use davhaven_domain::events::{ObjectChange, ObjectChangeKind};
use davhaven_domain::{
    ETag, ErrorKind, EventData, ExternalKey, ObjectId, ObjectUri, Operation, StoredObject, SyncToken, Uid,
};
use davhaven_ports::{Expected, IndexFilter, ObjectHead, PageReq, StoreError, Tx, TxMode};
use davhaven_wire::mcp::ChangeScope;
use davhaven_wire::{BatchItem, BatchItemResult, BatchMode, BatchOutcome, BatchRequest, BatchResult};

use crate::audit::Journal;
use crate::authz::{blocking, field_error, found, retrying};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::objects::ObjectServiceImpl;
use crate::objects::dav::StoreRequest;
use crate::objects::events::{Linker, default_zone};
use crate::objects::locate::{ApiCalendar, WriteTarget, api_calendar, publish_changes, query_heads};
use crate::objects::prepare::{Prepared, prepare, prepare_calendar};
use crate::services::CalendarRef;
use crate::texts::DEFAULT_ALARM_TEXT;

/// Whether an error says something about the item (and fails the batch) instead of about the server (and aborts it).
fn is_item_error(error: &AppError) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Invalid | ErrorKind::Conflict | ErrorKind::TooLarge | ErrorKind::Forbidden
    )
}

/// What an item turned out to need, decided outside the transaction.
enum Planned {
    /// The item is valid; what has to be stored.
    Ready(Plan),
    /// The item cannot be stored; why.
    Failed(AppError),
}

/// The decision about one valid item.
enum Plan {
    /// The content hash equals the stored one: nothing to write.
    Unchanged { uid: Uid, uri: ObjectUri, etag: ETag },
    /// The object to store, validated, indexed and ready.
    Write(Box<Write>),
}

/// An object to store.
struct Write {
    prepared: Prepared,
    text: String,
    uid: Uid,
    uri: ObjectUri,
    /// The object the item was merged with: the write is only valid while it is the stored one.
    base: Option<(ObjectId, ETag)>,
}

/// The keys a batch deletes with the object each names (`None` for a key that names nothing).
type Doomed = Vec<(ExternalKey, Option<ObjectHead>)>;

/// What the read before the lock found.
struct Snapshot {
    target: ApiCalendar,
    linker: Linker,
    existing: HashMap<ExternalKey, StoredObject>,
    doomed: Doomed,
}

/// What became of one entry in the store.
struct Done {
    outcome: BatchOutcome,
    uid: Uid,
    uri: ObjectUri,
    etag: Option<ETag>,
    change: Option<ObjectChange>,
    seq: Option<u64>,
}

fn failed(key: &ExternalKey, error: &AppError) -> BatchItemResult {
    BatchItemResult {
        external_key: key.clone(),
        outcome: BatchOutcome::Failed,
        uid: None,
        uri: None,
        etag: None,
        problem: Some(error.problem_details()),
    }
}

/// The entry of an item that would have been stored (or was found unchanged), without an `ETag`.
fn predicted(key: &ExternalKey, plan: &Plan) -> BatchItemResult {
    let (outcome, uid, uri) = match plan {
        Plan::Unchanged { uid, uri, .. } => (BatchOutcome::Unchanged, uid, uri),
        Plan::Write(write) => (
            if write.base.is_some() {
                BatchOutcome::Updated
            } else {
                BatchOutcome::Created
            },
            &write.uid,
            &write.uri,
        ),
    };
    BatchItemResult {
        external_key: key.clone(),
        outcome,
        uid: Some(uid.clone()),
        uri: Some(uri.clone()),
        etag: None,
        problem: None,
    }
}

/// The entry of a key of `deletes` or of a `replace` scope: deleted when the object exists, unchanged when not.
fn doomed_entry(key: &ExternalKey, head: Option<&ObjectHead>) -> BatchItemResult {
    match head {
        Some(head) => BatchItemResult {
            external_key: key.clone(),
            outcome: BatchOutcome::Deleted,
            uid: Some(head.uid.clone()),
            uri: Some(head.uri.clone()),
            etag: None,
            problem: None,
        },
        None => BatchItemResult {
            external_key: key.clone(),
            outcome: BatchOutcome::Unchanged,
            uid: None,
            uri: None,
            etag: None,
            problem: None,
        },
    }
}

impl ObjectServiceImpl {
    /// Batch upsert into a calendar.
    pub(crate) async fn batch_upsert(
        &self,
        ctx: &davhaven_domain::RequestContext,
        calendar: &CalendarRef,
        request: BatchRequest,
    ) -> AppResult<BatchResult> {
        request.validate(&self.core().deps().limits.api).map_err(|error| {
            let message = SafeMessage::sanitized(&format!("{}: {}", error.pointer, error.message));
            AppError::invalid(message.clone()).with_field_error("/items", "invalid", message)
        })?;
        crate::authz::require_scope(ctx, Operation::BatchUpsert)?;
        // A `replace` batch that lists nothing deletes everything in its scope, whatever `deletes` adds to it. Only
        // `allow_empty` says that this is meant (PLAN 2.10, OP5).
        if request.mode == BatchMode::Replace && request.items.is_empty() && !request.allow_empty {
            return Err(field_error(
                "/allow_empty",
                "required",
                "A replace batch without items deletes everything in its scope; set allow_empty to say that is meant.",
            ));
        }
        retrying(false, || self.batch_once(ctx, calendar, &request)).await
    }

    async fn batch_once(
        &self,
        ctx: &davhaven_domain::RequestContext,
        calendar: &CalendarRef,
        request: &BatchRequest,
    ) -> AppResult<BatchResult> {
        // 1. Read without the lock: the calendar, the objects the items name and what a replace would delete.
        let snapshot = self.read_for_batch(ctx, calendar, request).await?;
        // 2. Merge, validate and index every item outside any transaction.
        let mut planned: Vec<(&BatchItem, Planned)> = Vec::with_capacity(request.items.len());
        for item in &request.items {
            let plan = match self
                .prepare_item(&snapshot.target, item, snapshot.existing.get(&item.external_key))
                .await
            {
                Ok(plan) => Planned::Ready(plan),
                Err(error) if is_item_error(&error) => Planned::Failed(error),
                Err(error) => return Err(error),
            };
            planned.push((item, plan));
        }
        if planned.iter().any(|(_, plan)| matches!(plan, Planned::Failed(_))) {
            // All or nothing: the batch fails before the calendar was locked. What the other entries would have
            // done is reported without the `ETag`s of writes that never happen.
            let mut results = Vec::with_capacity(planned.len() + snapshot.doomed.len());
            for (item, plan) in &planned {
                results.push(match plan {
                    Planned::Ready(plan) => predicted(&item.external_key, plan),
                    Planned::Failed(error) => failed(&item.external_key, error),
                });
            }
            for (key, head) in &snapshot.doomed {
                results.push(doomed_entry(key, head.as_ref()));
            }
            return Ok(BatchResult {
                sync_token: token_of(&snapshot.target.calendar, None),
                results,
            });
        }
        // 3. Store under the lock.
        self.store_batch(ctx, calendar, request, &snapshot, planned).await
    }

    /// The read before the lock: the calendar and the caller's right to write to it, the links of the answer, the
    /// objects the items name and what a `replace` would delete.
    async fn read_for_batch(
        &self,
        ctx: &davhaven_domain::RequestContext,
        calendar: &CalendarRef,
        request: &BatchRequest,
    ) -> AppResult<Snapshot> {
        let mut tx = self.core().deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let target = api_calendar(tx.as_mut(), ctx, calendar, Operation::BatchUpsert, false).await?;
        let linker = self.linker(tx.as_mut(), ctx, &target).await?;
        let mut existing: HashMap<ExternalKey, StoredObject> = HashMap::with_capacity(request.items.len());
        for item in &request.items {
            if let Some(object) = found(
                tx.objects()
                    .get_by_external_key(target.calendar.id, &item.external_key)
                    .await,
            )? {
                existing.insert(item.external_key.clone(), object);
            }
        }
        let doomed = self.planned_deletes(tx.as_mut(), &target, request).await?;
        tx.commit().await?;
        Ok(Snapshot {
            target,
            linker,
            existing,
            doomed,
        })
    }

    /// The writes of a batch whose items are all valid, under the lock of the calendar. After the first entry that
    /// fails in the store the remaining ones are validated but no longer stored, and the transaction is dropped.
    async fn store_batch(
        &self,
        ctx: &davhaven_domain::RequestContext,
        calendar: &CalendarRef,
        request: &BatchRequest,
        snapshot: &Snapshot,
        planned: Vec<(&BatchItem, Planned)>,
    ) -> AppResult<BatchResult> {
        let journal = Journal::new(self.core(), ctx);
        let mut tx = self.core().deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let locked = api_calendar(tx.as_mut(), ctx, calendar, Operation::BatchUpsert, true).await?;
        if locked.calendar.sync_seq != snapshot.target.calendar.sync_seq {
            self.check_bases(tx.as_mut(), &locked, request, &snapshot.existing)
                .await?;
        }
        // What a replace deletes is read again under the lock: this is the authoritative list.
        let doomed = self.planned_deletes(tx.as_mut(), &locked, request).await?;
        let scope = WriteTarget {
            tenant: &locked.tenant,
            calendar: &locked.calendar,
            home: snapshot.linker.home(),
        };
        let mut results: Vec<BatchItemResult> = Vec::with_capacity(request.items.len() + doomed.len());
        let mut changes: Vec<ObjectChange> = Vec::new();
        let mut last_seq: Option<u64> = None;
        let mut stopped = false;
        for (item, plan) in planned {
            // The check before the stores guarantees that every plan is ready.
            let Planned::Ready(plan) = plan else {
                continue;
            };
            if stopped {
                // The batch has failed: the rest is validated, no longer stored.
                results.push(predicted(&item.external_key, &plan));
                continue;
            }
            match self
                .store_item(
                    tx.as_mut(),
                    ctx,
                    scope,
                    &item.external_key,
                    &plan,
                    snapshot.existing.get(&item.external_key),
                )
                .await
            {
                Ok(done) => {
                    changes.extend(done.change);
                    last_seq = done.seq.or(last_seq);
                    results.push(BatchItemResult {
                        external_key: item.external_key.clone(),
                        outcome: done.outcome,
                        uid: Some(done.uid),
                        uri: Some(done.uri),
                        etag: done.etag,
                        problem: None,
                    });
                }
                Err(error) if is_item_error(&error) => {
                    stopped = true;
                    results.push(failed(&item.external_key, &error));
                }
                Err(error) => return Err(error),
            }
        }
        for (key, head) in &doomed {
            if let Some(head) = head.as_ref().filter(|_| !stopped) {
                let seq = tx
                    .objects()
                    .delete(locked.calendar.id, &head.uri, Expected::Etag(head.etag.clone()))
                    .await?;
                tx.rsvp().revoke_for_object(head.id).await?;
                changes.push(ObjectChange {
                    kind: ObjectChangeKind::Deleted,
                    object: None,
                    uri: head.uri.clone(),
                    uid: head.uid.clone(),
                    external_key: head.external_key.clone(),
                    etag: None,
                });
                last_seq = Some(seq);
            }
            results.push(doomed_entry(key, head.as_ref()));
        }
        if stopped {
            // The transaction is dropped, which rolls back the entries stored before the failed one: the calendar is as
            // it was, and its entries say what they would have done.
            for result in &mut results {
                result.etag = None;
            }
            return Ok(BatchResult {
                sync_token: token_of(&locked.calendar, None),
                results,
            });
        }
        if let Some(seq) = last_seq {
            publish_changes(&journal, tx.as_mut(), &locked.calendar, seq, changes).await?;
        }
        tx.commit().await?;
        Ok(BatchResult {
            sync_token: token_of(&locked.calendar, last_seq),
            results,
        })
    }

    /// The calendar moved since it was read: every item must still be based on the object it was merged with.
    ///
    /// # Errors
    ///
    /// A lost race (`SerializationFailure`) when one is not, so that the attempt starts over.
    async fn check_bases(
        &self,
        tx: &mut dyn Tx,
        locked: &ApiCalendar,
        request: &BatchRequest,
        existing: &HashMap<ExternalKey, StoredObject>,
    ) -> AppResult<()> {
        for item in &request.items {
            let current = found(
                tx.objects()
                    .get_by_external_key(locked.calendar.id, &item.external_key)
                    .await,
            )?;
            let same = match (&current, existing.get(&item.external_key)) {
                (Some(current), Some(base)) => current.id == base.id && current.etag == base.etag,
                (None, None) => true,
                _ => false,
            };
            if !same {
                return Err(AppError::from(StoreError::SerializationFailure));
            }
        }
        Ok(())
    }

    /// The external keys a batch deletes with the object each names (`None` for a key that names nothing): the
    /// explicit ones and, in `replace` mode, every object of the scope that the batch does not list.
    async fn planned_deletes(
        &self,
        tx: &mut dyn Tx,
        target: &ApiCalendar,
        request: &BatchRequest,
    ) -> AppResult<Doomed> {
        let max = request
            .max_deletes
            .map(|max| usize::try_from(max).unwrap_or(usize::MAX));
        let too_many = || {
            AppError::invalid(SafeMessage::from_static(
                "The batch would delete more objects than max_deletes allows.",
            ))
            .with_field_error(
                "/max_deletes",
                "exceeded",
                SafeMessage::from_static("The batch would delete more objects than max_deletes allows."),
            )
        };
        let mut seen: HashSet<ExternalKey> = HashSet::new();
        let mut deletes: Doomed = Vec::new();
        for key in &request.deletes {
            if seen.insert(key.clone()) {
                let head = found(tx.objects().get_by_external_key(target.calendar.id, key).await)?
                    .map(|object| ObjectHead::from(&object));
                deletes.push((key.clone(), head));
            }
        }
        if request.mode == BatchMode::Replace
            && let Some(prefix) = &request.replace_scope_prefix
        {
            let listed: HashSet<&ExternalKey> = request.items.iter().map(|item| &item.external_key).collect();
            let filter = IndexFilter {
                external_key_prefix: Some(prefix.clone()),
                ..IndexFilter::all()
            };
            let mut page = PageReq::first(1000);
            loop {
                let batch = query_heads(tx, target.calendar.id, &filter, page).await?;
                for head in batch.items {
                    if let Some(key) = head.external_key.clone()
                        && !listed.contains(&key)
                        && seen.insert(key.clone())
                    {
                        deletes.push((key, Some(head)));
                        if max.is_some_and(|max| deletes.len() > max) {
                            return Err(too_many());
                        }
                    }
                }
                match batch.next {
                    Some(after) => page = page.after(after),
                    None => break,
                }
            }
        }
        if max.is_some_and(|max| deletes.len() > max) {
            return Err(too_many());
        }
        Ok(deletes)
    }

    /// Merges, validates and indexes one item outside any transaction and decides what it needs.
    async fn prepare_item(
        &self,
        target: &ApiCalendar,
        item: &BatchItem,
        existing: Option<&StoredObject>,
    ) -> AppResult<Plan> {
        let deps = self.core().deps();
        let key = &item.external_key;
        let (mut prepared, mut text) = match (&item.event, &item.ical) {
            (Some(view), None) => {
                let uid = existing
                    .map(|object| object.uid.clone())
                    .or_else(|| view.data.uid.clone())
                    .unwrap_or_else(|| Uid::deterministic(target.calendar.id, key));
                let zone = default_zone(&target.calendar, &target.tenant, &deps.limits.ical);
                let merged = self
                    .merge(existing, &view.data, ChangeScope::All, (&uid, &uid), zone)
                    .await?;
                prepare_calendar(self.core(), merged.primary).await?
            }
            (None, Some(ical)) => {
                let prepared = prepare(self.core(), ical).await?;
                (prepared, ical.clone())
            }
            _ => {
                return Err(AppError::invalid(SafeMessage::from_static(
                    "Exactly one of event and ical is required.",
                )));
            }
        };
        let uid = prepared.index.uid.clone();
        if let Some(object) = existing {
            if object.uid != uid {
                return Err(AppError::invalid(SafeMessage::from_static(
                    "The UID of an existing object cannot change.",
                )));
            }
            if object.content_hash == prepared.hash {
                return Ok(Plan::Unchanged {
                    uid,
                    uri: object.uri.clone(),
                    etag: object.etag.clone(),
                });
            }
            // A changed object has a higher SEQUENCE than the one before.
            if prepared.index.sequence <= object.sequence {
                (prepared, text) = self.with_sequence(&prepared, text, object.sequence).await?;
            }
        }
        if !target.calendar.components.contains(&prepared.validated.component) {
            return Err(AppError::invalid(SafeMessage::from_static(
                "The calendar does not accept this component type.",
            ))
            .with_precondition(davhaven_domain::Precondition::SupportedCalendarComponent));
        }
        let uri = existing.map_or_else(|| ObjectUri::for_uid(&uid), |object| object.uri.clone());
        Ok(Plan::Write(Box::new(Write {
            prepared,
            text,
            uid,
            uri,
            base: existing.map(|object| (object.id, object.etag.clone())),
        })))
    }

    /// Stores one planned item in the locked calendar.
    async fn store_item(
        &self,
        tx: &mut dyn Tx,
        ctx: &davhaven_domain::RequestContext,
        scope: WriteTarget<'_>,
        key: &ExternalKey,
        plan: &Plan,
        existing: Option<&StoredObject>,
    ) -> AppResult<Done> {
        let write = match plan {
            Plan::Unchanged { uid, uri, etag } => {
                return Ok(Done {
                    outcome: BatchOutcome::Unchanged,
                    uid: uid.clone(),
                    uri: uri.clone(),
                    etag: Some(etag.clone()),
                    change: None,
                    seq: None,
                });
            }
            Plan::Write(write) => write,
        };
        let Write {
            prepared,
            text,
            uid,
            uri,
            ..
        } = write.as_ref();
        let stored = match self
            .store(
                tx,
                ctx,
                scope,
                StoreRequest {
                    uri,
                    existing,
                    prepared,
                    data: text.clone(),
                    external_key: Some(key.clone()),
                    scheduling: None,
                },
            )
            .await
        {
            Ok(stored) => stored,
            // A creation whose resource name is taken: another object of the calendar already has this UID, which
            // says something about this item and not about the server.
            Err(error) if existing.is_none() && error.kind() == ErrorKind::PreconditionFailed => {
                return Err(AppError::conflict());
            }
            Err(error) => return Err(error),
        };
        let created = stored.result.created;
        Ok(Done {
            outcome: if created {
                BatchOutcome::Created
            } else {
                BatchOutcome::Updated
            },
            uid: uid.clone(),
            uri: uri.clone(),
            etag: Some(stored.result.etag.clone()),
            change: Some(ObjectChange {
                kind: if created {
                    ObjectChangeKind::Created
                } else {
                    ObjectChangeKind::Updated
                },
                object: Some(stored.result.object_id),
                uri: uri.clone(),
                uid: uid.clone(),
                external_key: Some(key.clone()),
                etag: Some(stored.result.etag),
            }),
            seq: Some(stored.result.seq),
        })
    }

    /// Raises the `SEQUENCE` of a prepared object above `stored`. Only events carry the property in the JSON model;
    /// objects of other component types keep the sequence they came with.
    async fn with_sequence(&self, prepared: &Prepared, text: String, stored: i32) -> AppResult<(Prepared, String)> {
        if prepared.validated.component != davhaven_domain::ComponentKind::Event {
            return Ok((prepared.clone(), text));
        }
        let calendar = prepared.calendar().clone();
        let uid = prepared.index.uid.clone();
        let now = self.core().deps().clock.now();
        let patch = EventData {
            sequence: Some(stored.saturating_add(1)),
            ..EventData::default()
        };
        let merged = blocking(self.core(), davhaven_ical::ErrorContext::Store, move |limits| {
            let context = davhaven_ical::merge::MergeContext {
                uid: &uid,
                now,
                default_zone: davhaven_domain::TimeZoneName::utc(),
                scope: davhaven_ical::merge::EditScope::All,
                limits,
                default_alarm_text: DEFAULT_ALARM_TEXT,
            };
            davhaven_ical::merge::merge_event(Some(&calendar), &patch, &context)
        })
        .await?;
        prepare_calendar(self.core(), merged).await
    }
}

/// The sync token of the calendar as the row states it, or after the change `seq`.
fn token_of(calendar: &davhaven_domain::Calendar, seq: Option<u64>) -> SyncToken {
    SyncToken::new(
        calendar.id.as_uuid(),
        calendar.sync_epoch,
        seq.unwrap_or_else(|| u64::try_from(calendar.sync_seq).unwrap_or(0)),
    )
}
