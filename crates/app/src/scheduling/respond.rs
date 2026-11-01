//! Answering an invitation through the management API or MCP (`respond_to_invitation`).
//!
//! An answer is a change of the caller's *own copy* of the event: their `PARTSTAT` on the `ATTENDEE` line that names
//! them. It is stored through the write path every other write uses ([`ObjectServiceImpl::store`]), so the rest
//! follows from the rules of an attendee's write (PLAN 2.8): the scheduler sees that the answer changed, builds the
//! `REPLY` from the copy and hands it to the [`ItipProcessor`](crate::itip::ItipProcessor), which folds it into the
//! organizer's copy (an internal organizer) or queues an iMIP mail (an external one). The remark of the attendee
//! travels beside the copy (`WriteFacts::reply_comment`), because the iCalendar object of the attendee has no place
//! for it. An answer that repeats the stored one still reaches the organizer when it comes with a remark, as an
//! answer through the RSVP page or a mail gateway does.
//!
//! The answer is merged by the iCalendar layer like a `REPLY` is: it changes the answer of the caller on the master
//! and on the overrides that still carry their earlier answer, and nothing else.
//!
//! A caller who sees the event but is not one of its attendees (the organizer, a colleague, a tenant token) is
//! refused (403): the event is theirs to read, not to answer.

use davhaven_domain::audit::McpWriteAudit;
use davhaven_domain::events::{ObjectChange, ObjectChangeKind};
use davhaven_domain::{
    AuditEvent, CalendarId, CalendarUserAddress, Channel, ObjectUri, Operation, PartStat, RequestContext, StoredObject,
    Tenant,
};
use davhaven_ical::ErrorContext;
use davhaven_ical::itip::{ReplySpec, apply_reply_with, reply_message};
use davhaven_ports::{Tx, TxMode};
use davhaven_wire::EventView;

use super::SchedulingServiceImpl;
use super::actor::{ActorInfo, mailto_of};
use super::execute::{Plan, ReplyPlan, Subject};
use crate::audit::Journal;
use crate::authz::{blocking, clean_optional_text, enforce_api, field_error, found, require_scope, retrying};
use crate::error::{AppError, AppResult};
use crate::objects::dav::{Scheduling, StoreRequest};
use crate::objects::events::Linker;
use crate::objects::locate::{ApiCalendar, WriteTarget, api_calendar_raw, publish_changes};
use crate::objects::prepare::{Prepared, prepare_calendar};
use crate::rsvp::MAX_COMMENT_CHARS;
use crate::services::{InvitationResponse, ObjectRef, ObjectSelector, ScheduleReply};

/// The stored object an event selector names, if there is one.
async fn select(tx: &mut dyn Tx, calendar: CalendarId, selector: &ObjectSelector) -> AppResult<Option<StoredObject>> {
    let result = match selector {
        ObjectSelector::Key(key) => tx.objects().get_by_external_key(calendar, key).await,
        ObjectSelector::Uri(uri) => tx.objects().get(calendar, uri).await,
        ObjectSelector::Uid(uid) => tx.objects().get_by_uid(calendar, uid).await,
        ObjectSelector::Id(id) => match tx.objects().get_by_id(*id).await {
            Ok(object) if object.calendar_id == calendar => Ok(object),
            Ok(_) => Err(davhaven_ports::StoreError::NotFound),
            Err(error) => Err(error),
        },
    };
    found(result)
}

/// The address the caller is on the event of `stored` with: they must be one of its attendees, and the event must be
/// somebody else's.
async fn attendee_of(
    tx: &mut dyn Tx,
    stored: &StoredObject,
    actor: &ActorInfo,
) -> AppResult<Option<CalendarUserAddress>> {
    if !stored.is_scheduling || stored.organizer_address.as_ref().is_none_or(|who| actor.is_own(who)) {
        return Ok(None);
    }
    Ok(tx
        .objects()
        .attendees(stored.id)
        .await?
        .into_iter()
        .find(|row| row.principal_id == Some(actor.principal.id) || actor.is_own(&row.address))
        .map(|row| row.address))
}

impl SchedulingServiceImpl {
    /// Changes the answer of the caller on their copy of an invitation and replies to the organizer.
    pub(super) async fn respond_to_invitation(
        &self,
        ctx: &RequestContext,
        object: ObjectRef,
        response: InvitationResponse,
    ) -> AppResult<EventView> {
        require_scope(ctx, Operation::RespondToInvitation)?;
        if !response.partstat.is_answer() {
            return Err(field_error(
                "/partstat",
                "invalid",
                "The answer must be accepted, declined or tentative.",
            ));
        }
        let comment = clean_optional_text("/comment", response.comment.as_deref(), MAX_COMMENT_CHARS)?;
        retrying(false, || {
            self.respond_once(ctx, &object, response.partstat, comment.as_deref())
        })
        .await
    }

    async fn respond_once(
        &self,
        ctx: &RequestContext,
        object: &ObjectRef,
        partstat: PartStat,
        comment: Option<&str>,
    ) -> AppResult<EventView> {
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let target = api_calendar_raw(tx.as_mut(), ctx, &object.calendar, true).await?;
        enforce_api(ctx, &target.facts, Operation::RespondToInvitation)?;
        let stored = select(tx.as_mut(), target.calendar.id, &object.object)
            .await?
            .ok_or_else(AppError::not_found)?;
        let linker = self.objects.linker(tx.as_mut(), ctx, &target).await?;
        // The event is visible: whoever is not an attendee of it is refused, not told that it does not exist.
        let actor = ActorInfo::resolve(tx.as_mut(), ctx, &target.tenant, target.calendar.owner_id)
            .await?
            .ok_or_else(AppError::forbidden)?;
        let (Some(attendee), Some(organizer)) = (
            attendee_of(tx.as_mut(), &stored, &actor).await?,
            stored.organizer_address.clone(),
        ) else {
            return Err(AppError::forbidden());
        };
        let folded = self.answer_in_copy(&stored, (&organizer, &attendee), partstat).await?;
        let Some((prepared, text)) = folded else {
            // Nothing to change: the copy says this already. The answer is repeatable and sends nothing again, unless
            // it comes with a remark: that reaches the organizer like the remark of any other answer.
            if let Some(comment) = comment {
                self.repeat_with_remark(
                    tx.as_mut(),
                    ctx,
                    &target.tenant,
                    &stored,
                    (&actor, attendee, organizer),
                    comment,
                )
                .await?;
            }
            tx.commit().await?;
            return self.view_of(&linker, &target, stored).await;
        };
        let scope = WriteTarget {
            tenant: &target.tenant,
            calendar: &target.calendar,
            home: linker.home(),
        };
        let uri: &ObjectUri = &stored.uri;
        let written = self
            .objects
            .store(
                tx.as_mut(),
                ctx,
                scope,
                StoreRequest {
                    uri,
                    existing: Some(&stored),
                    prepared: &prepared,
                    data: text,
                    external_key: None,
                    scheduling: Some(Scheduling {
                        reply: ScheduleReply::Send,
                        if_schedule_tag_match: None,
                        notify: true,
                        comment,
                        stale_excused: false,
                    }),
                },
            )
            .await?;
        publish_changes(
            &journal,
            tx.as_mut(),
            &target.calendar,
            written.result.seq,
            vec![ObjectChange {
                kind: ObjectChangeKind::Updated,
                object: Some(written.result.object_id),
                uri: stored.uri.clone(),
                uid: stored.uid.clone(),
                external_key: stored.external_key.clone(),
                etag: Some(written.result.etag.clone()),
            }],
        )
        .await?;
        if ctx.channel == Channel::Mcp {
            journal
                .audit(
                    tx.as_mut(),
                    AuditEvent::McpWrite(McpWriteAudit {
                        tool: "respond_to_invitation".to_owned(),
                        calendar: Some(target.calendar.id),
                        object: Some(written.result.object_id),
                        uid: Some(stored.uid.clone()),
                    }),
                )
                .await?;
        }
        let current = tx.objects().get(target.calendar.id, &stored.uri).await?;
        tx.commit().await?;
        self.view_of(&linker, &target, current).await
    }

    /// The caller repeated their answer and added a remark: the copy stays as it is and the organizer gets the answer
    /// again with the remark, through the same path as any other answer.
    async fn repeat_with_remark(
        &self,
        tx: &mut dyn Tx,
        ctx: &RequestContext,
        tenant: &Tenant,
        stored: &StoredObject,
        (actor, attendee, organizer): (&ActorInfo, CalendarUserAddress, CalendarUserAddress),
        comment: &str,
    ) -> AppResult<()> {
        let plan = Plan {
            reply: Some(ReplyPlan {
                copy: stored.data.clone(),
                principal: actor.principal.id,
                attendee,
                mailto: mailto_of(&actor.principal),
                organizer,
                comment: Some(comment.to_owned()),
            }),
            ..Plan::default()
        };
        self.scheduler
            .execute(
                tx,
                &Subject {
                    ctx,
                    tenant,
                    calendar: stored.calendar_id,
                    object: stored.id,
                    uid: &stored.uid,
                },
                &plan,
            )
            .await
    }

    /// The copy with the answer of `attendee`, prepared for storage; `None` when it holds that answer already.
    /// Runs on a blocking thread.
    async fn answer_in_copy(
        &self,
        stored: &StoredObject,
        (organizer, attendee): (&CalendarUserAddress, &CalendarUserAddress),
        partstat: PartStat,
    ) -> AppResult<Option<(Prepared, String)>> {
        let text = stored.data.clone();
        let (uid, sequence) = (stored.uid.clone(), stored.sequence);
        let (organizer, attendee) = (organizer.clone(), attendee.clone());
        let now = self.core.deps().clock.now();
        let updated = blocking(&self.core, ErrorContext::Store, move |limits| {
            let copy = davhaven_ical::parse::parse(text.as_bytes(), limits)?;
            let reply = reply_message(&ReplySpec {
                uid: &uid,
                organizer: &organizer,
                attendee: &attendee,
                partstat,
                sequence,
                dtstamp: now,
                comment: None,
            })?;
            let applied = apply_reply_with(&copy, &reply, limits, Some(&attendee))?;
            Ok((applied.updated != copy).then_some(applied.updated))
        })
        .await?;
        match updated {
            Some(calendar) => Ok(Some(prepare_calendar(&self.core, calendar).await?)),
            None => Ok(None),
        }
    }

    /// The event as the JSON interface shows it.
    async fn view_of(&self, linker: &Linker, target: &ApiCalendar, object: StoredObject) -> AppResult<EventView> {
        self.objects
            .render(linker, target.calendar.timezone_ics.as_deref(), vec![(object, None)])
            .await?
            .into_iter()
            .next()
            .ok_or_else(AppError::not_found)
    }
}
