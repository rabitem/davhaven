//! The organizer's side of a write: the plan of an organizer's `PUT`, and of the cancellation that deleting does.

use std::collections::{HashMap, HashSet};

use chrono::Duration;
use davhaven_domain::{
    Calendar, CalendarId, CalendarUserAddress, Channel, ErrorKind, EventTime, ItipMethod, ObjectIndex, PartStat,
    Precondition, Principal, PrincipalId, RequestContext, Scope, Tenant, Uid,
};
use davhaven_ical::filter::TimeRange;
use davhaven_ical::freebusy::BusyPeriod;
use davhaven_ical::{ErrorContext, ParsedCalendar};
use davhaven_ports::{FreeBusy, PolicyTenant, ResourceRequest, Tx};

use super::actor::ActorInfo;
use super::build::{BuildJob, BuildRecipient, Built, build};
use super::busy::busy_of_principal;
use super::execute::{MailJob, Plan, QueuedDelivery, QuotaUse, ResourceAnswer, TEMPLATE_CANCEL, TEMPLATE_REQUEST};
use super::plan::{Attendee, DecideInput, Decision, analyse, decide, scheduled_attendees};
use super::scheduler::{Planned, Scheduler, refuse};
use crate::addresses::{Class, Directory};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::itip::{CopyOp, InternalDelivery, Viewers, blocking_ical, policy_tenant, wants_copy};
use crate::objects::{ScheduleTagPlan, ScheduledWrite, WriteFacts};
use crate::services::{RecipientStatus, ScheduleStatus};

/// How far ahead a recurring request is examined for a resource's answer.
const RESOURCE_HORIZON: Duration = Duration::days(366);

/// One attendee the write touches.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent decision about the attendee; an enum would have to list their combinations"
)]
struct Touched {
    address: CalendarUserAddress,
    wire: CalendarUserAddress,
    class: Class,
    request: bool,
    cancel_new: bool,
    cancel_old: bool,
    instances: Vec<EventTime>,
    copy: bool,
    /// Whether the attendee is on the new copy (a removed attendee is not).
    on_new: bool,
    queued: bool,
    /// Whether nothing is sent to them: the policy, a limit or a conflict says no.
    denied: bool,
    /// Whether the event has more outside attendees than `scheduling.external_per_event` and this one is past the
    /// limit.
    over_limit: bool,
    status: Option<ScheduleStatus>,
    answer: Option<PartStat>,
    /// The calendar a missing copy of the event is created in.
    create_in: Option<CalendarId>,
}

impl Touched {
    fn messaged(&self) -> bool {
        self.request || self.cancel_new || self.cancel_old || !self.instances.is_empty()
    }

    /// Whether the recipient gets an invitation (a `REQUEST` of the event or of instances): what the quotas count.
    fn invited(&self) -> bool {
        self.request || !self.instances.is_empty()
    }

    fn internal(&self) -> bool {
        matches!(self.class, Class::Internal(_) | Class::Resource(_))
    }
}

/// Everything a plan is made from.
pub(super) struct Inputs<'a> {
    pub(super) ctx: &'a RequestContext,
    pub(super) tenant: &'a Tenant,
    pub(super) actor: &'a ActorInfo,
    pub(super) calendar: &'a Calendar,
    pub(super) uid: &'a Uid,
    pub(super) index: &'a ObjectIndex,
    pub(super) organizer: &'a CalendarUserAddress,
}

/// What changes and who is told.
pub(super) struct Change<'a> {
    /// The attendees of the new copy the server schedules.
    pub(super) targets: &'a [Attendee],
    /// The attendees of the stored copy the server schedules.
    pub(super) old_targets: &'a [Attendee],
    /// What is sent to whom.
    pub(super) decision: &'a Decision,
    /// The organizer's copy after the change.
    pub(super) calendar: ParsedCalendar,
    /// The stored copy.
    pub(super) old: Option<ParsedCalendar>,
    /// The copy the client sent.
    pub(super) incoming: ParsedCalendar,
    /// Whether the delivery states are written into the copy (not when the copy is deleted).
    pub(super) write_statuses: bool,
}

/// The way a queued recipient is delivered to, and from which version of the organizer's copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueueKind {
    method: ItipMethod,
    copy_only: bool,
    /// Whether the messages are built from the stored copy (a removed attendee is not on the new one).
    from_old: bool,
}

impl Scheduler {
    /// Plans an organizer's write: what changes in the organizer's copy, who is told, and what is delivered after
    /// the write.
    pub(super) async fn plan_organizer(
        &self,
        tx: &mut dyn Tx,
        facts: &WriteFacts<'_>,
        actor: &ActorInfo,
        organizer: &CalendarUserAddress,
    ) -> AppResult<Planned> {
        let old_text = facts.existing.map(|object| object.data.clone());
        let incoming = facts.incoming.clone();
        let analysis = blocking_ical(&self.core, move |limits| analyse(old_text.as_deref(), incoming, limits))
            .await?
            .map_err(|error| AppError::from_ical(error, ErrorContext::Store))?;
        if !analysis.violations.is_empty() {
            return Err(refuse(
                Precondition::AllowedOrganizerSchedulingObjectChange,
                "The organizer and the UID of a scheduling object cannot be changed.",
            ));
        }
        let inputs = Inputs {
            ctx: facts.ctx,
            tenant: facts.tenant,
            actor,
            calendar: facts.calendar,
            uid: &facts.index.uid,
            index: facts.index,
            organizer,
        };
        let is_organizer = |address: &CalendarUserAddress| address == organizer || actor.speaks_for(address);
        let targets = scheduled_attendees(&facts.index.attendees, is_organizer);
        let old_targets = scheduled_attendees(&analysis.old_attendees, is_organizer);
        let decision = if analysis.new_cancelled && (analysis.old.is_none() || analysis.old_cancelled) {
            // Nothing is sent about an event that is created cancelled (an import: nobody was invited) or stays
            // cancelled (its attendees were told).
            Decision::default()
        } else {
            decide(&DecideInput {
                diff: &analysis.update.diff,
                targets: &targets,
                old_targets: &old_targets,
                cancelled_series: analysis.new_cancelled,
            })
        };
        let (built, plan) = self
            .prepare(
                tx,
                &inputs,
                Change {
                    targets: &targets,
                    old_targets: &old_targets,
                    decision: &decision,
                    calendar: analysis.update.calendar,
                    old: analysis.old,
                    incoming: analysis.incoming,
                    write_statuses: true,
                },
            )
            .await?;
        Ok(Planned {
            write: ScheduledWrite {
                data: built.organizer,
                schedule_tag: ScheduleTagPlan::Fresh,
                ..ScheduledWrite::default()
            },
            plan,
        })
    }

    /// Classifies, applies the policy, builds the copy and the messages and turns them into a plan.
    pub(super) async fn prepare(
        &self,
        tx: &mut dyn Tx,
        inputs: &Inputs<'_>,
        change: Change<'_>,
    ) -> AppResult<(Built, Plan)> {
        let directory = self.directory(tx, inputs, &change).await?;
        let wire = directory.wire_map();
        let mut touched = self.classify(inputs, &directory, &wire, &change);
        let organizers = organizer_addresses(inputs, &wire);
        let charged = self
            .apply_policy(tx, inputs, &mut touched, &change.calendar, &organizers)
            .await?;
        let now = self.core.deps().clock.now();
        let job = BuildJob {
            answers: touched
                .iter()
                .filter_map(|recipient| recipient.answer.map(|partstat| (recipient.address.clone(), partstat)))
                .collect(),
            statuses: touched
                .iter()
                .filter(|recipient| change.write_statuses && recipient.on_new && recipient.messaged())
                .filter_map(|recipient| {
                    recipient
                        .status
                        .map(|status| (recipient.address.clone(), status.code()))
                })
                .collect(),
            recipients: touched
                .iter()
                .map(|recipient| BuildRecipient {
                    wire: recipient.wire.clone(),
                    request: recipient.request,
                    cancel_new: recipient.cancel_new,
                    cancel_old: recipient.cancel_old,
                    instances: recipient.instances.clone(),
                    copy: recipient.copy,
                    internal: recipient.internal(),
                })
                .collect(),
            calendar: change.calendar,
            old: change.old,
            incoming: change.incoming,
            wire,
            now,
            organizer: inputs.organizer.clone(),
            // A colleague who writes in the name of the organizer is named as the sender (PLAN 2.8).
            sent_by: if inputs.actor.on_behalf_of_owner(inputs.organizer) {
                inputs.actor.mailto()
            } else {
                None
            },
        };
        let built = blocking_ical(&self.core, move |limits| build(&job, limits))
            .await?
            .map_err(|error| AppError::from_ical(error, ErrorContext::Scheduling))?;
        let mut plan = Self::assemble(&touched, &built);
        plan.organizers = organizers;
        plan.quota = (charged > 0).then_some(QuotaUse {
            tenant: inputs.tenant.id,
            principal: inputs.actor.principal.id,
            recipients: charged,
        });
        Ok((built, plan))
    }

    /// Looks every address the write names up, once: the attendees of both versions, the organizer and everybody
    /// the event lists.
    async fn directory(&self, tx: &mut dyn Tx, inputs: &Inputs<'_>, change: &Change<'_>) -> AppResult<Directory> {
        let mut wanted: Vec<CalendarUserAddress> = change
            .targets
            .iter()
            .chain(change.old_targets.iter())
            .map(|attendee| attendee.address.clone())
            .collect();
        wanted.push(inputs.organizer.clone());
        wanted.extend(inputs.index.attendees.iter().map(|attendee| attendee.address.clone()));
        wanted.sort();
        wanted.dedup();
        let mut directory = Directory::load(tx, inputs.tenant, &self.core.deps().urls, &wanted)
            .await?
            .with_known(&inputs.actor.principal, &inputs.actor.addresses);
        if let Some((owner, addresses)) = &inputs.actor.owner {
            directory = directory.with_known(owner, addresses);
        }
        Ok(directory)
    }

    /// Classifies the attendees the decision touches and marks the outside recipients beyond the limit of the
    /// event.
    fn classify(
        &self,
        inputs: &Inputs<'_>,
        directory: &Directory,
        wire: &HashMap<CalendarUserAddress, CalendarUserAddress>,
        change: &Change<'_>,
    ) -> Vec<Touched> {
        let (targets, old_targets, decision) = (change.targets, change.old_targets, change.decision);
        // The first `external_per_event` outside attendees of an event get its messages; the rest are not mailed and
        // their status says so. The same recipients are within the limit for an invitation and for the cancellation
        // that follows it, and the limit never makes a write fail.
        let per_event = usize::try_from(self.core.deps().config.scheduling.external_per_event).unwrap_or(usize::MAX);
        let within_limit = |list: &[Attendee]| -> Vec<CalendarUserAddress> {
            list.iter()
                .filter(|attendee| directory.is_external(&attendee.address, attendee.cutype))
                .take(per_event)
                .map(|attendee| attendee.address.clone())
                .collect()
        };
        let mut within = within_limit(targets);
        within.extend(within_limit(old_targets));
        let mut touched = Vec::new();
        let in_order = targets.iter().chain(
            old_targets
                .iter()
                .filter(|old| !targets.iter().any(|attendee| attendee.address == old.address)),
        );
        for attendee in in_order {
            let address = &attendee.address;
            let request = decision.request.contains(address);
            let cancel_new = decision.cancel_new.contains(address);
            let cancel_old = decision.cancel_old.contains(address);
            let instances = decision
                .cancel_instances
                .iter()
                .find(|(who, _)| who == address)
                .map(|(_, list)| list.clone())
                .unwrap_or_default();
            let copy = decision.updates_copy(address);
            if !(request || cancel_new || cancel_old || !instances.is_empty() || copy) {
                continue;
            }
            let class = directory.classify(address, attendee.cutype);
            if class
                .principal()
                .is_some_and(|principal| is_the_organizer(inputs, principal.id))
            {
                continue;
            }
            let on_new = targets.iter().any(|candidate| &candidate.address == address);
            touched.push(Touched {
                wire: wire.get(address).cloned().unwrap_or_else(|| address.clone()),
                over_limit: matches!(class, Class::External) && !within.contains(address),
                address: address.clone(),
                class,
                request,
                cancel_new,
                cancel_old,
                instances,
                copy,
                on_new,
                queued: false,
                denied: false,
                status: None,
                answer: None,
                create_in: None,
            });
        }
        touched
    }

    /// Asks the policy and applies the limits: the status of every recipient, who is queued, who is refused, what
    /// resources answer and whose copy is created. Answers how many invitations to outside recipients are mailed,
    /// which the quotas count once the object is stored.
    ///
    /// Nothing here refuses the write: a recipient that cannot be written to (the policy says no, the event or the
    /// quota is used up, the recipient has another organizer's event under the `UID`) is not written to and the
    /// organizer's copy says so (`SCHEDULE-STATUS` 5.1), like clients expect delivery state to be reported.
    async fn apply_policy(
        &self,
        tx: &mut dyn Tx,
        inputs: &Inputs<'_>,
        touched: &mut [Touched],
        copy: &ParsedCalendar,
        organizers: &[CalendarUserAddress],
    ) -> AppResult<u32> {
        let deps = self.core.deps();
        let tenant = policy_tenant(inputs.tenant);
        let max_sync = usize::try_from(deps.config.scheduling.max_sync_internal_attendees).unwrap_or(usize::MAX);
        let mut internal = 0_usize;
        let mut mails = 0_u32;
        let mut invitations = Invitations::default();
        for recipient in touched.iter_mut() {
            match &recipient.class {
                Class::Internal(principal) | Class::Resource(principal) => {
                    // A recipient who has somebody else's event under the UID is not ours to write to: it would be
                    // replaced or deleted by a message that anybody can address to a UID they know.
                    if holds_another_organizers_event(tx, inputs.uid, principal.id, organizers).await? {
                        recipient.denied = true;
                        recipient.status = Some(ScheduleStatus::Failed);
                        continue;
                    }
                    internal += 1;
                    recipient.queued = internal > max_sync;
                    recipient.status = Some(if recipient.queued {
                        ScheduleStatus::Queued
                    } else {
                        ScheduleStatus::Delivered
                    });
                }
                Class::External => {
                    if !recipient.messaged() {
                        continue;
                    }
                    if self.may_mail(inputs, &tenant, recipient, &mut invitations).await {
                        recipient.status = Some(ScheduleStatus::ImipSent);
                        mails += 1;
                    } else {
                        recipient.denied = true;
                        recipient.status = Some(ScheduleStatus::Failed);
                    }
                }
                Class::Group | Class::Unknown => recipient.status = Some(ScheduleStatus::UnknownAddress),
            }
        }
        // A caller over MCP may write to people outside the organisation only with the scope that says so
        // (PLAN 2.12): the mail is the side effect that cannot be taken back.
        if mails > 0 && inputs.ctx.channel == Channel::Mcp && !inputs.ctx.scopes.contains(Scope::McpScheduleExternal) {
            return Err(AppError::forbidden().with_public_message(SafeMessage::from_static(
                "Sending invitations to people outside the organisation needs the mcp:schedule_external scope.",
            )));
        }
        self.answers_and_copies(tx, inputs, &tenant, touched, copy).await?;
        Ok(invitations.charged)
    }

    /// Whether the recipient outside the tenant is mailed: the policy allows it, the event is within its limit of
    /// outside attendees and, for an invitation, the quotas have room. An invitation that fits is counted.
    async fn may_mail(
        &self,
        inputs: &Inputs<'_>,
        tenant: &PolicyTenant,
        recipient: &Touched,
        invitations: &mut Invitations,
    ) -> bool {
        let deps = self.core.deps();
        if recipient.over_limit
            || !deps
                .scheduling_policy
                .external_allowed(tenant, &recipient.address)
                .await
        {
            return false;
        }
        // Invitations count against the quotas; cancellations never do.
        if !recipient.invited() {
            return true;
        }
        let left = if let Some(left) = invitations.allowance {
            left
        } else {
            let left = self
                .quotas
                .allowance(
                    deps.clock.now(),
                    inputs.tenant.id,
                    inputs.actor.principal.id,
                    &deps.config.scheduling,
                )
                .await
                .remaining;
            invitations.allowance = Some(left);
            left
        };
        if invitations.charged < left {
            invitations.charged += 1;
            true
        } else {
            false
        }
    }

    /// What the resources among the recipients answer, and where the copies of the invitations that are delivered
    /// inside the transaction go.
    async fn answers_and_copies(
        &self,
        tx: &mut dyn Tx,
        inputs: &Inputs<'_>,
        tenant: &PolicyTenant,
        touched: &mut [Touched],
        copy: &ParsedCalendar,
    ) -> AppResult<()> {
        let mut viewers: Option<Viewers> = None;
        for recipient in touched
            .iter_mut()
            .filter(|recipient| recipient.internal() && !recipient.queued && !recipient.denied)
        {
            let principal = match &recipient.class {
                Class::Internal(principal) | Class::Resource(principal) => (**principal).clone(),
                _ => continue,
            };
            if recipient.request
                && let Class::Resource(_) = &recipient.class
            {
                recipient.answer = self.resource_answer(tx, inputs, tenant, &principal, copy).await?;
            }
            if !recipient.request || recipient.cancel_new || recipient.answer == Some(PartStat::Declined) {
                continue;
            }
            if viewers.is_none() {
                viewers = Some(Viewers::load(tx, inputs.calendar).await?);
            }
            recipient.create_in = wants_copy(
                &self.core,
                tx,
                inputs.tenant,
                inputs.organizer,
                viewers.as_ref(),
                &principal,
            )
            .await?;
        }
        Ok(())
    }

    /// How a resource answers a request: the policy decides, given the busy time of the resource that collides with
    /// the instances of the request (without the event itself, which a resource may already hold).
    ///
    /// The instances are expanded from the copy, not read from the index: the index is padded on purpose (it only has
    /// to be a superset of what a query asks for), so a booking that starts when another one ends would look like a
    /// collision.
    async fn resource_answer(
        &self,
        tx: &mut dyn Tx,
        inputs: &Inputs<'_>,
        tenant: &PolicyTenant,
        resource: &Principal,
        copy: &ParsedCalendar,
    ) -> AppResult<Option<PartStat>> {
        let Some(first) = inputs.index.first_start else {
            return Ok(None);
        };
        let recurring = inputs.index.is_recurring;
        let one_second = Duration::seconds(1);
        let last = inputs
            .index
            .last_end
            .map_or(first + RESOURCE_HORIZON, |end| end.min(first + RESOURCE_HORIZON))
            .max(first);
        let window = TimeRange::new(Some(first), Some(last + one_second));
        let (zone, expanded) = (inputs.tenant.settings.timezone, copy.clone());
        let instances = blocking_ical(&self.core, move |limits| {
            davhaven_ical::expand::expand_in_zone(&expanded, &window, limits, zone)
        })
        .await?;
        // A request that cannot be expanded is left to a person.
        let Ok(instances) = instances else {
            return Ok(None);
        };
        let (Some(start), Some(end)) = (
            instances.iter().map(|instance| instance.start).min(),
            instances.iter().map(|instance| instance.end).max(),
        ) else {
            return Ok(None);
        };
        let end = end.max(start);
        // An instant is checked as the second it lasts.
        let span = TimeRange::new(Some(start), Some(end.max(start + one_second)));
        let busy = match busy_of_principal(&self.core, tx, inputs.tenant, resource, span, Some(inputs.uid)).await {
            Ok(busy) => busy,
            // A request the busy time cannot be computed for is left to a person.
            Err(error) if error.kind() == ErrorKind::Invalid => return Ok(None),
            Err(error) => return Err(error),
        };
        let collides = |period: &BusyPeriod| {
            instances.iter().any(|instance| {
                let until = if instance.end > instance.start {
                    instance.end
                } else {
                    instance.start + one_second
                };
                period.start < until && instance.start < period.end
            })
        };
        let free_busy = FreeBusy {
            busy: busy
                .iter()
                .filter(|period| collides(period))
                .map(|period| davhaven_ports::BusyPeriod {
                    start: period.start,
                    end: period.end,
                })
                .collect(),
        };
        let request = ResourceRequest {
            tenant: tenant.clone(),
            resource: resource.id,
            organizer: inputs.organizer.clone(),
            start,
            end,
            recurring,
        };
        Ok(self
            .core
            .deps()
            .scheduling_policy
            .resource_reply(&request, &free_busy)
            .await)
    }

    /// Turns the decisions and the built messages into what happens after the write.
    fn assemble(touched: &[Touched], built: &Built) -> Plan {
        let mut plan = Plan::default();
        let mut queued: Vec<(QueueKind, PrincipalId)> = Vec::new();
        for (recipient, text) in touched.iter().zip(&built.recipients) {
            if recipient.cancel_new {
                plan.revoke_all = true;
            }
            if recipient.cancel_old {
                plan.revoke.push(recipient.address.clone());
            }
            if recipient.on_new
                && recipient.messaged()
                && let Some(status) = recipient.status
            {
                plan.outcome.recipients.push(RecipientStatus {
                    address: recipient.address.clone(),
                    status,
                });
            }
            if recipient.denied {
                continue;
            }
            match &recipient.class {
                Class::Internal(principal) | Class::Resource(principal) => {
                    if recipient.queued {
                        let kind = if recipient.cancel_new || recipient.cancel_old {
                            QueueKind {
                                method: ItipMethod::Cancel,
                                copy_only: false,
                                from_old: recipient.cancel_old,
                            }
                        } else {
                            QueueKind {
                                method: ItipMethod::Request,
                                copy_only: !recipient.invited(),
                                from_old: false,
                            }
                        };
                        queued.push((kind, principal.id));
                        continue;
                    }
                    let mut messages: Vec<String> = Vec::new();
                    messages.extend(text.request.clone());
                    messages.extend(text.cancel.clone());
                    messages.extend(text.instance_cancels.iter().cloned());
                    let copy = if recipient.cancel_new || recipient.cancel_old {
                        CopyOp::Remove
                    } else if let Some(copy) = &text.copy {
                        CopyOp::Put {
                            text: copy.clone(),
                            create_in: recipient.create_in,
                        }
                    } else {
                        CopyOp::Keep
                    };
                    if matches!(copy, CopyOp::Keep) && messages.is_empty() {
                        continue;
                    }
                    plan.deliveries.push(InternalDelivery {
                        principal: (**principal).clone(),
                        address: recipient.wire.clone(),
                        copy,
                        messages,
                        inbox_names: None,
                    });
                    if let Some(answer) = recipient.answer {
                        plan.answers.push(ResourceAnswer {
                            principal: principal.id,
                            partstat: answer,
                        });
                    }
                }
                Class::External => {
                    if recipient.request || !recipient.instances.is_empty() {
                        plan.mails.push(MailJob {
                            recipient: recipient.wire.clone(),
                            method: ItipMethod::Request,
                            template: TEMPLATE_REQUEST,
                            snapshot: text.snapshot_request.clone(),
                            replying_attendee: None,
                            comment: None,
                        });
                    }
                    if recipient.cancel_new || recipient.cancel_old {
                        plan.mails.push(MailJob {
                            recipient: recipient.wire.clone(),
                            method: ItipMethod::Cancel,
                            template: TEMPLATE_CANCEL,
                            snapshot: text.snapshot_cancel.clone(),
                            replying_attendee: None,
                            comment: None,
                        });
                    }
                }
                Class::Group | Class::Unknown => {}
            }
        }
        plan.queued = Self::queue(&queued, built);
        plan
    }

    /// One queued delivery per kind: the recipients above the synchronous cap, with the copy their messages are built
    /// from (a cancellation of removed attendees is built from the stored copy, everything else from the new one).
    fn queue(queued: &[(QueueKind, PrincipalId)], built: &Built) -> Vec<QueuedDelivery> {
        let mut deliveries: Vec<(QueueKind, Vec<PrincipalId>)> = Vec::new();
        for (kind, principal) in queued {
            match deliveries.iter_mut().find(|(known, _)| known == kind) {
                Some((_, recipients)) => recipients.push(*principal),
                None => deliveries.push((*kind, vec![*principal])),
            }
        }
        deliveries
            .into_iter()
            .map(|(kind, recipients)| QueuedDelivery {
                method: kind.method,
                copy_only: kind.copy_only,
                recipients,
                snapshot: if kind.from_old {
                    built.wire_old.clone().unwrap_or_else(|| built.wire_new.clone())
                } else {
                    built.wire_new.clone()
                },
            })
            .collect()
    }
}

/// How many invitations to outside recipients a write sends, and how many the quotas allow it.
#[derive(Debug, Default)]
struct Invitations {
    /// What the quotas leave, once asked.
    allowance: Option<u32>,
    /// The invitations that are mailed.
    charged: u32,
}

/// Whether `recipient` has an event under `uid` that another organizer than `organizers` sent.
async fn holds_another_organizers_event(
    tx: &mut dyn Tx,
    uid: &Uid,
    recipient: PrincipalId,
    organizers: &[CalendarUserAddress],
) -> AppResult<bool> {
    Ok(tx
        .objects()
        .find_scheduling_uid(recipient, uid)
        .await?
        .is_some_and(|object| {
            !object
                .organizer_address
                .as_ref()
                .is_some_and(|address| organizers.contains(address))
        }))
}

/// Whether the principal is the organizer (or the owner the organizer writes for): never a recipient.
fn is_the_organizer(inputs: &Inputs<'_>, principal: PrincipalId) -> bool {
    principal == inputs.actor.principal.id
        || inputs
            .actor
            .owner
            .as_ref()
            .is_some_and(|(owner, _)| owner.id == principal)
}

/// Every address that names the organizer of this write: the copies of the recipients name them by one of these.
fn organizer_addresses(
    inputs: &Inputs<'_>,
    wire: &HashMap<CalendarUserAddress, CalendarUserAddress>,
) -> Vec<CalendarUserAddress> {
    let mut all: Vec<CalendarUserAddress> = match &inputs.actor.owner {
        Some((_, addresses)) if inputs.actor.on_behalf_of_owner(inputs.organizer) => addresses.clone(),
        _ => inputs.actor.addresses.clone(),
    };
    all.push(inputs.organizer.clone());
    all.extend(wire.get(inputs.organizer).cloned());
    let unique: HashSet<CalendarUserAddress> = all.drain(..).collect();
    let mut all: Vec<CalendarUserAddress> = unique.into_iter().collect();
    all.sort();
    all
}
