//! Carrying out what the scheduler decided: mails, deliveries, replies.
//!
//! The scheduler decides in `before_write` (it needs the answer of the policy, the busy time of resources and the
//! classification of every attendee to write the `SCHEDULE-STATUS` into the organizer's copy) and acts in
//! `after_write` (the mails need the id the object got when it was stored). A [`Plan`] carries the decision from
//! one to the other, through the [`Handover`](crate::objects::Handover) of the write.

use chrono::{DateTime, Utc};
use davhaven_domain::events::SchedulingReplyPayload;
use davhaven_domain::{
    CalendarId, CalendarUserAddress, Channel, CuType, EventPayload, EventType, ItipMethod, ObjectId, OutboxId,
    PartStat, Principal, PrincipalId, RequestContext, Scope, Tenant, TenantId, Uid,
};
use davhaven_ical::itip::{MessageScope, MessageSpec, build_message, rewrite_addresses};
use davhaven_ports::{DeliveryJob, ImipJob, NewOutbox, OutboxMessage, TemplateName, Tx};

use super::scheduler::Scheduler;
use crate::addresses::{Class, Directory};
use crate::audit::Journal;
use crate::error::{AppError, AppResult, SafeMessage};
use crate::itip::{
    DeliveryScope, InternalDelivery, Notify, ReplyError, ReplyInput, blocking_ical, is_data_error, machine_error,
    organizer_copy, policy_tenant,
};
use crate::services::ScheduleOutcome;

/// The mail template of an invitation (`REQUEST`).
pub(crate) const TEMPLATE_REQUEST: &str = "imip_request";
/// The mail template of a cancellation (`CANCEL`).
pub(crate) const TEMPLATE_CANCEL: &str = "imip_cancel";
/// The mail template of an answer (`REPLY`).
pub(crate) const TEMPLATE_REPLY: &str = "imip_reply";

/// An iMIP mail to queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MailJob {
    /// The external recipient.
    pub(crate) recipient: CalendarUserAddress,
    /// The method.
    pub(crate) method: ItipMethod,
    /// The template.
    pub(crate) template: &'static str,
    /// The text the mail is built from, when it must not be read from the stored object.
    pub(crate) snapshot: Option<String>,
    /// For a reply: the answering attendee.
    pub(crate) replying_attendee: Option<CalendarUserAddress>,
    /// For a reply: the remark.
    pub(crate) comment: Option<String>,
}

/// A delivery to internal recipients above the synchronous cap: one outbox record per kind of delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueuedDelivery {
    /// `Request` delivers an invitation (or only brings the copies up to date, with `copy_only`), `Cancel` delivers
    /// a cancellation and removes the copies.
    pub(crate) method: ItipMethod,
    /// Whether only the copies follow the organizer's, without a message (an edit that is not significant).
    pub(crate) copy_only: bool,
    /// The recipients.
    pub(crate) recipients: Vec<PrincipalId>,
    /// The organizer's copy as the messages are built from it, with the addresses of the wire.
    pub(crate) snapshot: String,
}

/// A resource answered a request on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResourceAnswer {
    /// The resource.
    pub(crate) principal: PrincipalId,
    /// The answer.
    pub(crate) partstat: PartStat,
}

/// The answer of an internal attendee to the organizer, derived from their copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplyPlan {
    /// The attendee's copy after the change (or, for a deletion, as it was with the answer `DECLINED`).
    pub(crate) copy: String,
    /// The principal who answers.
    pub(crate) principal: PrincipalId,
    /// The address of the attendee in that copy.
    pub(crate) attendee: CalendarUserAddress,
    /// The mail address of the attendee outside the server, when they have one.
    pub(crate) mailto: Option<CalendarUserAddress>,
    /// The `ORGANIZER` of the copy.
    pub(crate) organizer: CalendarUserAddress,
    /// The remark of the attendee.
    pub(crate) comment: Option<String>,
}

/// Invitations to outside recipients that count against the quotas once they are mailed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuotaUse {
    /// The tenant.
    pub(crate) tenant: TenantId,
    /// Who sends them.
    pub(crate) principal: PrincipalId,
    /// How many recipients.
    pub(crate) recipients: u32,
}

/// Everything an organizer's or attendee's write sends.
#[derive(Debug, Clone, Default)]
pub(crate) struct Plan {
    /// iMIP mails.
    pub(crate) mails: Vec<MailJob>,
    /// Internal deliveries inside the transaction.
    pub(crate) deliveries: Vec<InternalDelivery>,
    /// Internal deliveries that are queued.
    pub(crate) queued: Vec<QueuedDelivery>,
    /// Attendees whose RSVP links stop working (they were removed).
    pub(crate) revoke: Vec<CalendarUserAddress>,
    /// Whether every RSVP link of the event stops working (it was cancelled).
    pub(crate) revoke_all: bool,
    /// Resources that answered.
    pub(crate) answers: Vec<ResourceAnswer>,
    /// The answer to send to the organizer.
    pub(crate) reply: Option<ReplyPlan>,
    /// What the caller is told.
    pub(crate) outcome: ScheduleOutcome,
    /// Every address that names the organizer the deliveries are for.
    pub(crate) organizers: Vec<CalendarUserAddress>,
    /// What is recorded against the quotas once the mails are enqueued.
    pub(crate) quota: Option<QuotaUse>,
}

/// The event a plan is carried out for.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Subject<'a> {
    /// The caller.
    pub(crate) ctx: &'a RequestContext,
    /// The tenant.
    pub(crate) tenant: &'a Tenant,
    /// The calendar of the event.
    pub(crate) calendar: CalendarId,
    /// The object, as stored.
    pub(crate) object: ObjectId,
    /// The UID of the event.
    pub(crate) uid: &'a Uid,
}

impl Scheduler {
    /// Carries out a plan inside the transaction of the write.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) async fn execute(&self, tx: &mut dyn Tx, subject: &Subject<'_>, plan: &Plan) -> AppResult<()> {
        let deps = self.core.deps();
        if plan.revoke_all {
            tx.rsvp().revoke_for_object(subject.object).await?;
        }
        for attendee in &plan.revoke {
            tx.rsvp().revoke_for_attendee(subject.object, attendee).await?;
        }
        for job in &plan.mails {
            self.enqueue_mail(tx, subject.object, job.clone()).await?;
        }
        if !plan.deliveries.is_empty() {
            self.processor
                .deliver(
                    tx,
                    &DeliveryScope {
                        ctx: subject.ctx,
                        uid: subject.uid,
                        organizers: &plan.organizers,
                    },
                    &plan.deliveries,
                )
                .await?;
        }
        for queued in &plan.queued {
            tx.outbox()
                .enqueue(NewOutbox::now(
                    OutboxId::from_uuid(deps.ids.new_id()),
                    OutboxMessage::InternalDelivery(DeliveryJob {
                        calendar: subject.calendar,
                        object: subject.object,
                        method: queued.method,
                        recipients: queued.recipients.clone(),
                        snapshot: Some(queued.snapshot.clone()),
                        copy_only: queued.copy_only,
                    }),
                ))
                .await?;
        }
        if !plan.answers.is_empty() {
            let journal = Journal::new(&self.core, subject.ctx);
            for answer in &plan.answers {
                journal
                    .publish(
                        tx,
                        EventType::SchedulingReplyReceived,
                        EventPayload::SchedulingReply(SchedulingReplyPayload {
                            calendar: Some(subject.calendar),
                            object: Some(subject.object),
                            uid: Some(subject.uid.clone()),
                            attendee: Some(answer.principal),
                            partstat: Some(answer.partstat),
                            reason: None,
                        }),
                    )
                    .await?;
            }
        }
        if let Some(reply) = &plan.reply {
            self.send_reply(tx, subject, reply).await?;
        }
        // The invitations that were mailed use up the quotas, once the object is stored and nothing failed.
        if let Some(used) = &plan.quota {
            self.quotas
                .record(deps.clock.now(), used.tenant, used.principal, used.recipients)
                .await;
        }
        Ok(())
    }

    /// Queues one iMIP mail.
    async fn enqueue_mail(&self, tx: &mut dyn Tx, object: ObjectId, job: MailJob) -> AppResult<()> {
        let deps = self.core.deps();
        let template = TemplateName::parse(job.template).map_err(AppError::internal)?;
        tx.outbox()
            .enqueue(NewOutbox::now(
                OutboxId::from_uuid(deps.ids.new_id()),
                OutboxMessage::Imip(ImipJob {
                    object,
                    recipient: job.recipient,
                    method: job.method,
                    locale: None,
                    template,
                    snapshot: job.snapshot,
                    replying_attendee: job.replying_attendee,
                    comment: job.comment,
                }),
            ))
            .await?;
        Ok(())
    }

    /// Sends the answer of an internal attendee to the organizer: into the organizer's copy when the organizer is in
    /// the tenant, as a mail when they are outside it.
    async fn send_reply(&self, tx: &mut dyn Tx, subject: &Subject<'_>, reply: &ReplyPlan) -> AppResult<()> {
        let deps = self.core.deps();
        let directory = Directory::load(tx, subject.tenant, &deps.urls, std::slice::from_ref(&reply.organizer)).await?;
        match directory.classify(&reply.organizer, CuType::Individual) {
            Class::Internal(organizer) | Class::Resource(organizer) => {
                self.reply_to_internal(tx, subject, reply, &organizer).await
            }
            Class::External => self.reply_by_mail(tx, subject, reply).await,
            Class::Group | Class::Unknown => Ok(()),
        }
    }

    /// The answer reaches the organizer's copy through the processor, like every other answer.
    async fn reply_to_internal(
        &self,
        tx: &mut dyn Tx,
        subject: &Subject<'_>,
        reply: &ReplyPlan,
        organizer: &Principal,
    ) -> AppResult<()> {
        let deps = self.core.deps();
        // The organizer's copy is gone (they deleted the event meanwhile): the answer stays in the attendee's copy.
        let Some(copy) = organizer_copy(tx, subject.tenant, organizer, subject.uid).await? else {
            return Ok(());
        };
        let rows = tx.objects().attendees(copy.id).await?;
        let Some(named) = rows
            .iter()
            .find(|row| row.principal_id == Some(reply.principal))
            .map(|row| row.address.clone())
        else {
            return Ok(());
        };
        let text = reply.copy.clone();
        let from = reply.attendee.clone();
        let to = named.clone();
        let comment = reply.comment.clone();
        let organizer_address = reply.organizer.clone();
        let now = deps.clock.now();
        let built = blocking_ical(&self.core, move |limits| {
            let calendar = davhaven_ical::parse::parse(text.as_bytes(), limits)?;
            let renamed = rewrite_addresses(&calendar, &|address| (address == &from).then(|| to.clone()))?;
            let message = build_message(
                &renamed,
                &MessageSpec {
                    replying_attendee: Some(to.clone()),
                    comment,
                    ..MessageSpec::new(ItipMethod::Reply, organizer_address, now)
                },
            )?;
            let serialized = davhaven_ical::serialize::serialize(&message.calendar)?;
            Ok((message, serialized))
        })
        .await?;
        let (message, serialized) = match built {
            Ok(built) => built,
            // A copy that cannot make a reply is not the attendee's mistake: the answer stays in their copy.
            Err(error) if is_data_error(&error) => return Ok(()),
            Err(error) => return Err(machine_error(error)),
        };
        let outcome = self
            .processor
            .apply_reply(
                tx,
                ReplyInput {
                    ctx: subject.ctx,
                    organizer: &copy,
                    message: &message,
                    attendee: &named,
                    attendee_principal: Some(reply.principal),
                    notify: Notify {
                        inbox_principal: Some(organizer.id),
                        inbox_uri: None,
                        text: &serialized,
                    },
                    announce: copy.id == subject.object,
                },
            )
            .await;
        match outcome {
            Ok(_) => Ok(()),
            // The answer does not fit the organizer's copy (it answers an overtaken version, the attendee is no longer
            // on the event): it stays in the attendee's own copy, and nothing is wrong with the write.
            Err(ReplyError::Rejected(why)) => {
                tracing::debug!(
                    reason = crate::inbound::QuarantineReason::from(why).as_str(),
                    "the answer of an attendee was not applied to the organizer's copy"
                );
                Ok(())
            }
            Err(ReplyError::Failed(error)) => Err(error),
        }
    }

    /// The answer goes to an organizer outside the tenant as an iMIP mail.
    ///
    /// It leaves the tenant like an invitation does, so it is held to the same controls: the tenant's external
    /// policy, the scope an MCP caller needs for mail to outside people (`mcp:schedule_external`) and the quotas
    /// (the answering person is the sender, so toggling an answer back and forth cannot be used to mail somebody
    /// outside again and again).
    async fn reply_by_mail(&self, tx: &mut dyn Tx, subject: &Subject<'_>, reply: &ReplyPlan) -> AppResult<()> {
        let deps = self.core.deps();
        if !deps
            .scheduling_policy
            .external_allowed(&policy_tenant(subject.tenant), &reply.organizer)
            .await
        {
            return Ok(());
        }
        let ctx = subject.ctx;
        if ctx.channel == Channel::Mcp && !ctx.scopes.contains(Scope::McpScheduleExternal) {
            return Err(AppError::forbidden().with_public_message(SafeMessage::from_static(
                "Answering an organizer outside the organisation needs the mcp:schedule_external scope.",
            )));
        }
        let now = deps.clock.now();
        let sender = ctx.principal().unwrap_or(reply.principal);
        let allowance = self
            .quotas
            .allowance(now, subject.tenant.id, sender, &deps.config.scheduling)
            .await;
        if allowance.remaining == 0 {
            return Err(AppError::rate_limited(allowance.wait));
        }
        let wire_attendee = reply.mailto.clone().unwrap_or_else(|| reply.attendee.clone());
        let snapshot = if wire_attendee == reply.attendee {
            reply.copy.clone()
        } else {
            let text = reply.copy.clone();
            let from = reply.attendee.clone();
            let to = wire_attendee.clone();
            blocking_ical(&self.core, move |limits| {
                let calendar = davhaven_ical::parse::parse(text.as_bytes(), limits)?;
                let renamed = rewrite_addresses(&calendar, &|address| (address == &from).then(|| to.clone()))?;
                davhaven_ical::serialize::serialize(&renamed)
            })
            .await?
            .map_err(machine_error)?
        };
        self.enqueue_mail(
            tx,
            subject.object,
            MailJob {
                recipient: reply.organizer.clone(),
                method: ItipMethod::Reply,
                template: TEMPLATE_REPLY,
                snapshot: Some(snapshot),
                replying_attendee: Some(wire_attendee),
                comment: reply.comment.clone(),
            },
        )
        .await?;
        self.quotas.record(now, subject.tenant.id, sender, 1).await;
        Ok(())
    }
}

/// A whole-object message of `method` for `recipient`.
pub(crate) fn whole(method: ItipMethod, recipient: &CalendarUserAddress, now: DateTime<Utc>) -> MessageSpec {
    MessageSpec {
        scope: MessageScope::Whole,
        ..MessageSpec::new(method, recipient.clone(), now)
    }
}
