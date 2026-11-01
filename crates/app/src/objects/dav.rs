//! The DAV resource operations: GET, PUT, DELETE, MOVE and COPY of calendar objects.

use davhaven_domain::events::{ObjectChange, ObjectChangeKind};
use davhaven_domain::{
    Calendar, CalendarKind, ETag, ErrorKind, ExternalKey, ObjectId, ObjectUri, Operation, Precondition, RequestContext,
    ResourcePath, ScheduleTag, StoredObject,
};
use davhaven_ports::{Expected, NewVersion, StoreError, Tx, TxMode, WriteResult};

use super::ObjectServiceImpl;
use super::locate::{Located, Target, WriteTarget, change, locate, publish_changes};
use super::prepare::{
    Prepared, check_media_type, conflict, differs_only_in_alarm_state, etag_of, evaluate, fresh_schedule_tag, prepare,
    resolve_attendees,
};
use super::schedule::{DeleteFacts, ScheduleTagPlan, WriteFacts, Written};
use crate::audit::Journal;
use crate::authz::{enforce, found, retrying};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::services::{
    CopyRequest, DeleteOutcome, DeleteRequest, MoveOutcome, MoveRequest, ObjectView, PutOutcome, PutRequest,
    ScheduleOutcome, ScheduleReply, WritePrecondition,
};

/// How a write may schedule.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scheduling<'a> {
    pub(crate) reply: ScheduleReply,
    pub(crate) if_schedule_tag_match: Option<&'a ScheduleTag>,
    pub(crate) notify: bool,
    /// The remark of an answer (`WriteFacts::reply_comment`).
    pub(crate) comment: Option<&'a str>,
    /// Whether a stale `If-Match` was excused by the `Schedule-Tag` (`WriteFacts::stale_etag_excused`).
    pub(crate) stale_excused: bool,
}

/// One object to store.
#[derive(Debug)]
pub(crate) struct StoreRequest<'a> {
    pub(crate) uri: &'a ObjectUri,
    pub(crate) existing: Option<&'a StoredObject>,
    pub(crate) prepared: &'a Prepared,
    pub(crate) data: String,
    pub(crate) external_key: Option<ExternalKey>,
    pub(crate) scheduling: Option<Scheduling<'a>>,
}

/// What a store did.
#[derive(Debug)]
pub(crate) struct Stored {
    pub(crate) result: WriteResult,
    pub(crate) data: String,
    /// Whether the scheduler replaced the bytes of the client.
    pub(crate) rewritten: bool,
    pub(crate) schedule_tag: Option<ScheduleTag>,
    pub(crate) schedule: ScheduleOutcome,
}

/// What arrived in the target of a move.
struct Arrival {
    /// The object at its new place.
    moved: StoredObject,
    /// Whether the target did not exist before.
    created: bool,
    /// The object the move overwrote.
    replaced: Option<StoredObject>,
}

/// Publishes the changes of a move: the removal at the source and the arrival (and an overwritten object) at the
/// target. Within one calendar these are one batch of changes with one token.
async fn publish_move(
    journal: &Journal<'_>,
    tx: &mut dyn Tx,
    (source, source_seq): (&Calendar, u64),
    (target, target_seq): (&Calendar, u64),
    object: &StoredObject,
    arrival: Arrival,
) -> AppResult<()> {
    let kind = if arrival.created {
        ObjectChangeKind::Created
    } else {
        ObjectChangeKind::Updated
    };
    let mut at_target = Vec::new();
    if let Some(old) = &arrival.replaced {
        at_target.push(change(ObjectChangeKind::Deleted, old));
    }
    let removed = change(ObjectChangeKind::Deleted, object);
    if source.id == target.id {
        at_target.push(removed);
    } else {
        publish_changes(journal, tx, source, source_seq, vec![removed]).await?;
    }
    at_target.push(change(kind, &arrival.moved));
    publish_changes(journal, tx, target, target_seq, at_target).await
}

impl ObjectServiceImpl {
    /// Stores one object in the located calendar inside the transaction: the scheduler may adjust the bytes and the
    /// tags, the store enforces the write invariant (change log, UID uniqueness), and the scheduler delivers.
    ///
    /// The calendar must be locked (`locate` or `api_calendar` with `lock = true`) and the caller must have decided the
    /// operation.
    ///
    /// # Errors
    ///
    /// The preconditions of the scheduler, `NoUidConflict` and `UniqueSchedulingObjectResource` with the href of the
    /// conflicting resource, `PreconditionFailed` when the stored object changed, store failures.
    pub(crate) async fn store(
        &self,
        tx: &mut dyn Tx,
        ctx: &RequestContext,
        scope: WriteTarget<'_>,
        request: StoreRequest<'_>,
    ) -> AppResult<Stored> {
        let deps = self.core.deps();
        let facts = request.scheduling.map(|scheduling| WriteFacts {
            ctx,
            tenant: scope.tenant,
            calendar: scope.calendar,
            existing: request.existing,
            incoming: request.prepared.calendar(),
            index: &request.prepared.index,
            body: &request.data,
            uri: request.uri,
            reply: scheduling.reply,
            if_schedule_tag_match: scheduling.if_schedule_tag_match,
            notify_attendees: scheduling.notify,
            reply_comment: scheduling.comment,
            stale_etag_excused: scheduling.stale_excused,
        });
        let mut scheduled = match &facts {
            Some(facts) => self.scheduler.before_write(tx, facts).await?,
            None => super::schedule::ScheduledWrite::default(),
        };
        let handover = std::mem::take(&mut scheduled.handover);
        // What is stored is what was validated and indexed. When the scheduler replaced the bytes (it writes
        // `SCHEDULE-STATUS`, keeps the answers of the attendees, raises `SEQUENCE`), the index, the content hash
        // and the attendee rows are those of the bytes that are stored, not of the client's: they decide no-op
        // detection, the `SEQUENCE` of later batches and the answers shown.
        let rewritten = scheduled.data.is_some();
        let (data, replaced) = self.bytes_to_store(&request, scheduled.data).await?;
        let prepared = replaced.as_ref().unwrap_or(request.prepared);
        let etag = etag_of(&data);
        let schedule_tag = match scheduled.schedule_tag {
            ScheduleTagPlan::Fresh => prepared
                .index
                .is_scheduling
                .then(|| fresh_schedule_tag(deps.ids.new_id())),
            ScheduleTagPlan::Keep => request.existing.and_then(|object| object.schedule_tag.clone()),
            ScheduleTagPlan::Set(tag) => Some(tag),
            ScheduleTagPlan::Clear => None,
        };
        let attendee_principals = match scheduled.attendee_principals {
            Some(resolved) => resolved,
            None => resolve_attendees(&self.core, tx, &scope, &prepared.index).await?,
        };
        let version = NewVersion {
            id: ObjectId::from_uuid(deps.ids.new_id()),
            uri: request.uri.clone(),
            data: data.clone(),
            etag: etag.clone(),
            schedule_tag: schedule_tag.clone(),
            content_hash: prepared.hash.clone(),
            index: prepared.index.clone(),
            attendee_principals,
            external_key: request
                .external_key
                .clone()
                .or_else(|| request.existing.and_then(|object| object.external_key.clone())),
            origin: request.existing.and_then(|object| object.origin.clone()),
        };
        let expected = request
            .existing
            .map_or(Expected::Absent, |object| Expected::Etag(object.etag.clone()));
        let result = match tx.objects().put(scope.calendar.id, version, expected).await {
            Ok(result) => result,
            Err(StoreError::UniqueViolation(key)) => {
                return Err(conflict(tx, ctx, &scope, key, &prepared.index.uid).await);
            }
            Err(error) => return Err(error.into()),
        };
        let schedule = match &facts {
            Some(facts) => {
                self.scheduler
                    .after_write(
                        tx,
                        facts,
                        &Written {
                            object: result.object_id,
                            uri: request.uri,
                            seq: result.seq,
                            etag: &result.etag,
                            schedule_tag: schedule_tag.as_ref(),
                            data: &data,
                            created: result.created,
                            handover: &handover,
                        },
                    )
                    .await?
            }
            None => ScheduleOutcome::none(),
        };
        Ok(Stored {
            result,
            data,
            rewritten,
            schedule_tag,
            schedule,
        })
    }

    /// The bytes to store and, when the scheduler replaced the client's, their prepared form.
    ///
    /// # Errors
    ///
    /// The preconditions of invalid data, `Internal` when the replacement is another object than the one written.
    async fn bytes_to_store(
        &self,
        request: &StoreRequest<'_>,
        replacement: Option<String>,
    ) -> AppResult<(String, Option<Prepared>)> {
        let Some(text) = replacement else {
            return Ok((request.data.clone(), None));
        };
        let replaced = prepare(&self.core, &text).await?;
        if replaced.index.uid != request.prepared.index.uid
            || replaced.validated.component != request.prepared.validated.component
        {
            return Err(AppError::internal(StoreError::internal(
                "the scheduler changed the identity of the object it was asked to store",
            )));
        }
        Ok((text, Some(replaced)))
    }

    /// Reads one object.
    pub(crate) async fn read_object(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<ObjectView> {
        let Some((target, Some(uri))) = Target::of(path) else {
            return Err(AppError::not_found());
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let located = locate(tx.as_mut(), ctx, target, false).await?;
        enforce(ctx, &located.facts, Operation::ReadObject, || path.href())?;
        let object = tx.objects().get(located.calendar.id, uri).await?;
        tx.commit().await?;
        let data = Some(object.data.clone());
        Ok(located.view(&object, data))
    }

    /// Creates or replaces an object from the bytes of a client.
    pub(crate) async fn put_object(&self, ctx: &RequestContext, request: PutRequest) -> AppResult<PutOutcome> {
        self.put_stored(ctx, request).await.map(|(outcome, _)| outcome)
    }

    /// [`put_object`](Self::put_object) that also reports the `ETag` of what is stored, which is the one of the
    /// request body only when the scheduler left the bytes alone.
    async fn put_stored(&self, ctx: &RequestContext, request: PutRequest) -> AppResult<(PutOutcome, Option<ETag>)> {
        let Some((target, Some(uri))) = Target::of(&request.path) else {
            return Err(AppError::not_found());
        };
        check_media_type(request.content_type.as_deref())?;
        let prepared = prepare(&self.core, &request.body).await?;
        retrying(false, || self.put_once(ctx, &request, target, uri, &prepared)).await
    }

    async fn put_once(
        &self,
        ctx: &RequestContext,
        request: &PutRequest,
        target: Target<'_>,
        uri: &ObjectUri,
        prepared: &Prepared,
    ) -> AppResult<(PutOutcome, Option<ETag>)> {
        let journal = Journal::new(&self.core, ctx);
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let located = locate(tx.as_mut(), ctx, target, true).await?;
        let existing = found(tx.objects().get(located.calendar.id, uri).await)?;
        let operation = if existing.is_some() {
            Operation::UpdateObject
        } else {
            Operation::CreateObject
        };
        if let Err(refused) = enforce(ctx, &located.facts, operation, || request.path.href()) {
            // ADR 0004, rule 2: a client that may only read a calendar acknowledges and snoozes reminders in it, and
            // is not told off for it. A write whose only differences are those is answered as done, and not stored.
            if refused.kind() == ErrorKind::Forbidden
                && operation == Operation::UpdateObject
                && let Some(object) = &existing
                && differs_only_in_alarm_state(&self.core, object, prepared).await?
            {
                tx.commit().await?;
                return Ok((
                    PutOutcome {
                        etag: None,
                        schedule_tag: object.schedule_tag.clone(),
                        created: false,
                        schedule: ScheduleOutcome::none(),
                    },
                    None,
                ));
            }
            return Err(refused);
        }
        let stale_excused = evaluate(
            &request.preconditions,
            existing.as_ref(),
            self.scheduler.merges_stale_attendee_writes(),
        )?;
        if !located.calendar.components.contains(&prepared.validated.component) {
            return Err(AppError::invalid(SafeMessage::from_static(
                "The calendar does not accept this component type.",
            ))
            .with_precondition(Precondition::SupportedCalendarComponent));
        }
        let schedules = !matches!(located.calendar.kind, CalendarKind::Managed | CalendarKind::Mirror);
        let stored = self
            .store(
                tx.as_mut(),
                ctx,
                located.scope(),
                StoreRequest {
                    uri,
                    existing: existing.as_ref(),
                    prepared,
                    data: request.body.clone(),
                    external_key: None,
                    scheduling: schedules.then_some(Scheduling {
                        reply: request.schedule_reply,
                        if_schedule_tag_match: request.preconditions.if_schedule_tag_match.as_ref(),
                        notify: true,
                        comment: None,
                        stale_excused,
                    }),
                },
            )
            .await?;
        let kind = if stored.result.created {
            ObjectChangeKind::Created
        } else {
            ObjectChangeKind::Updated
        };
        let written = ObjectChange {
            kind,
            object: Some(stored.result.object_id),
            uri: uri.clone(),
            uid: prepared.index.uid.clone(),
            external_key: existing.as_ref().and_then(|object| object.external_key.clone()),
            etag: Some(stored.result.etag.clone()),
        };
        publish_changes(
            &journal,
            tx.as_mut(),
            &located.calendar,
            stored.result.seq,
            vec![written],
        )
        .await?;
        tx.commit().await?;
        let exact = !stored.rewritten || stored.data == request.body;
        Ok((
            PutOutcome {
                // RFC 4791 section 5.3.4: the `ETag` is returned only when the stored bytes are the client's.
                etag: exact.then(|| stored.result.etag.clone()),
                schedule_tag: stored.schedule_tag,
                created: stored.result.created,
                schedule: stored.schedule,
            },
            Some(stored.result.etag),
        ))
    }

    /// Deletes an object.
    pub(crate) async fn delete_object(&self, ctx: &RequestContext, request: DeleteRequest) -> AppResult<DeleteOutcome> {
        let Some((target, Some(uri))) = Target::of(&request.path) else {
            return Err(AppError::not_found());
        };
        retrying(false, || self.delete_once(ctx, &request, target, uri)).await
    }

    async fn delete_once(
        &self,
        ctx: &RequestContext,
        request: &DeleteRequest,
        target: Target<'_>,
        uri: &ObjectUri,
    ) -> AppResult<DeleteOutcome> {
        let journal = Journal::new(&self.core, ctx);
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let located = locate(tx.as_mut(), ctx, target, true).await?;
        enforce(ctx, &located.facts, Operation::DeleteObject, || request.path.href())?;
        let existing = tx.objects().get(located.calendar.id, uri).await?;
        evaluate(&request.preconditions, Some(&existing), false)?;
        let schedules = !matches!(located.calendar.kind, CalendarKind::Managed | CalendarKind::Mirror);
        let schedule = if schedules {
            self.scheduler
                .before_delete(
                    tx.as_mut(),
                    &DeleteFacts {
                        ctx,
                        tenant: &located.home.tenant,
                        calendar: &located.calendar,
                        existing: &existing,
                        reply: request.schedule_reply,
                        notify_attendees: true,
                    },
                )
                .await?
        } else {
            ScheduleOutcome::none()
        };
        let seq = match tx
            .objects()
            .delete(located.calendar.id, uri, Expected::Etag(existing.etag.clone()))
            .await
        {
            Ok(seq) => seq,
            Err(StoreError::PreconditionFailed) => return Err(AppError::precondition_failed()),
            Err(error) => return Err(error.into()),
        };
        // Links in mails that were sent for the invitation stop working with it.
        tx.rsvp().revoke_for_object(existing.id).await?;
        publish_changes(
            &journal,
            tx.as_mut(),
            &located.calendar,
            seq,
            vec![change(ObjectChangeKind::Deleted, &existing)],
        )
        .await?;
        tx.commit().await?;
        Ok(DeleteOutcome { schedule })
    }

    /// Moves an object: a relocation (the id, the bytes, the `ETag` and the `Schedule-Tag` stay).
    pub(crate) async fn move_object(&self, ctx: &RequestContext, request: MoveRequest) -> AppResult<MoveOutcome> {
        let (Some((from, Some(from_uri))), Some((to, Some(to_uri)))) =
            (Target::of(&request.from), Target::of(&request.to))
        else {
            return Err(AppError::not_found());
        };
        retrying(false, || self.move_once(ctx, &request, (from, from_uri), (to, to_uri))).await
    }

    async fn move_once(
        &self,
        ctx: &RequestContext,
        request: &MoveRequest,
        from: (Target<'_>, &ObjectUri),
        to: (Target<'_>, &ObjectUri),
    ) -> AppResult<MoveOutcome> {
        let journal = Journal::new(&self.core, ctx);
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let source = locate(tx.as_mut(), ctx, from.0, false).await?;
        let target = locate(tx.as_mut(), ctx, to.0, false).await?;
        // Both calendars are locked together, in ascending id order (PLAN 2.7).
        let mut ids = vec![source.calendar.id, target.calendar.id];
        ids.sort();
        ids.dedup();
        let locked = tx.calendars().lock(&ids).await?;
        let calendar_of = |id| locked.iter().find(|calendar| calendar.id == id).cloned();
        let (Some(source_calendar), Some(target_calendar)) =
            (calendar_of(source.calendar.id), calendar_of(target.calendar.id))
        else {
            return Err(AppError::not_found());
        };
        let source = Located {
            calendar: source_calendar,
            ..source
        };
        let target = Located {
            calendar: target_calendar,
            ..target
        };
        enforce(ctx, &source.facts, Operation::MoveObjectFrom, || request.from.href())?;
        let object = tx.objects().get(source.calendar.id, from.1).await?;
        evaluate(&request.preconditions, Some(&object), false)?;
        let existing = found(tx.objects().get(target.calendar.id, to.1).await)?;
        let operation = if existing.is_some() {
            Operation::UpdateObject
        } else {
            Operation::MoveObjectTo
        };
        enforce(ctx, &target.facts, operation, || request.to.href())?;
        if source.calendar.id == target.calendar.id && from.1 == to.1 {
            // RFC 4918 section 9.9.4: moving a resource onto itself is forbidden.
            return Err(AppError::forbidden().with_public_message(SafeMessage::from_static(
                "The source and the target are the same resource.",
            )));
        }
        if existing.is_some() && !request.overwrite {
            return Err(AppError::precondition_failed());
        }
        if object.is_scheduling && source.calendar.owner_id != target.calendar.owner_id {
            // A move between owners would change the organizer's or attendee's own copy: not a relocation.
            return Err(AppError::forbidden());
        }
        if !target.calendar.components.contains(&object.component) {
            return Err(AppError::invalid(SafeMessage::from_static(
                "The calendar does not accept this component type.",
            ))
            .with_precondition(Precondition::SupportedCalendarComponent));
        }
        if let Some(existing) = &existing {
            tx.objects()
                .delete(target.calendar.id, to.1, Expected::Etag(existing.etag.clone()))
                .await?;
            tx.rsvp().revoke_for_object(existing.id).await?;
        }
        let (source_seq, target_seq) = match tx
            .objects()
            .move_to(source.calendar.id, from.1, target.calendar.id, to.1)
            .await
        {
            Ok(seqs) => seqs,
            Err(StoreError::UniqueViolation(key)) => {
                return Err(conflict(tx.as_mut(), ctx, &target.scope(), key, &object.uid).await);
            }
            Err(error) => return Err(error.into()),
        };
        let created = existing.is_none();
        let arrival = Arrival {
            moved: StoredObject {
                uri: to.1.clone(),
                calendar_id: target.calendar.id,
                ..object.clone()
            },
            created,
            replaced: existing,
        };
        let (source, target) = (&source.calendar, &target.calendar);
        publish_move(
            &journal,
            tx.as_mut(),
            (source, source_seq),
            (target, target_seq),
            &object,
            arrival,
        )
        .await?;
        tx.commit().await?;
        Ok(MoveOutcome {
            created,
            etag: object.etag,
        })
    }

    /// Copies an object: the bytes of the source are stored at the target like a `PUT`, with the UID of the source.
    pub(crate) async fn copy_object(&self, ctx: &RequestContext, request: CopyRequest) -> AppResult<MoveOutcome> {
        let source = {
            let Some((target, Some(uri))) = Target::of(&request.from) else {
                return Err(AppError::not_found());
            };
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
            let located = locate(tx.as_mut(), ctx, target, false).await?;
            enforce(ctx, &located.facts, Operation::CopyObjectFrom, || request.from.href())?;
            let source = tx.objects().get(located.calendar.id, uri).await?;
            tx.commit().await?;
            source
        };
        let (outcome, stored_etag) = self
            .put_stored(
                ctx,
                PutRequest {
                    path: request.to.clone(),
                    body: source.data.clone(),
                    content_type: Some("text/calendar".to_owned()),
                    preconditions: if request.overwrite {
                        WritePrecondition::none()
                    } else {
                        WritePrecondition::create_only()
                    },
                    schedule_reply: ScheduleReply::Send,
                },
            )
            .await?;
        // The entity tag of the copy is the one of what is stored, never one made up from the source: the scheduler
        // may have rewritten the bytes, and a tag that matches no stored version breaks the next `If-Match`.
        let Some(etag) = stored_etag.or(outcome.etag) else {
            return Err(AppError::internal(StoreError::internal(
                "a copy was stored without an entity tag",
            )));
        };
        Ok(MoveOutcome {
            created: outcome.created,
            etag,
        })
    }
}
