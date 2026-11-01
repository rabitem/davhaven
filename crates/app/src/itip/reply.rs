//! Folding a `REPLY` into the organizer's copy.

use davhaven_domain::events::{ObjectChange, ObjectChangeKind, SchedulingReplyPayload};
use davhaven_domain::{
    Calendar, CalendarId, CalendarUserAddress, ErrorKind, EventPayload, EventType, IcalLimits, InboxItem, InboxItemId,
    ObjectId, ObjectUri, PartStat, PrincipalId, RequestContext, StoredObject, Uid,
};
use davhaven_ical::IcalError;
use davhaven_ical::itip::{ItipMessage, ReplyApplication, apply_reply_with};
use davhaven_ports::{Expected, NewVersion, StoreError, Tx};

use super::{ItipProcessor, blocking_ical, is_data_error, machine_error};
use crate::audit::Journal;
use crate::authz::lock_one;
use crate::error::{AppError, AppResult};
use crate::objects::locate::publish_changes;
use crate::objects::prepare::{etag_of, prepare_calendar};

/// Why a reply was not applied. The organizer's copy is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// The organizer's copy is gone (the event was deleted or moved out of reach).
    UnknownEvent,
    /// The reply answers another version of the event than the organizer's copy is (`SEQUENCE` differs): the
    /// answer to an invitation that was overtaken must not answer the new one.
    StaleSequence,
    /// The reply does not fit the copy: the attendee is not on the event, the instances do not exist, the result
    /// would not be storable.
    InvalidReply,
}

/// How applying a reply can fail.
#[derive(Debug)]
pub(crate) enum ReplyError {
    /// The reply cannot be applied; the transaction is still good.
    Rejected(Rejection),
    /// The application failed (the store, the machine); the transaction is lost.
    Failed(AppError),
}

impl From<AppError> for ReplyError {
    fn from(error: AppError) -> Self {
        Self::Failed(error)
    }
}

impl From<StoreError> for ReplyError {
    fn from(error: StoreError) -> Self {
        Self::Failed(AppError::from(error))
    }
}

/// Whom to tell, and with what, when a reply was applied.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Notify<'a> {
    /// The principal whose scheduling inbox receives the `REPLY`; `None` for no inbox item.
    pub(crate) inbox_principal: Option<PrincipalId>,
    /// The name of the inbox item; `None` for a fresh one. An inbound message passes a name derived from its
    /// `Message-ID`, so a second delivery of the same mail finds the item.
    pub(crate) inbox_uri: Option<&'a ObjectUri>,
    /// The text of the `REPLY` as the inbox keeps it.
    pub(crate) text: &'a str,
}

/// A reply to apply.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReplyInput<'a> {
    /// The caller, for the audit trail of the events.
    pub(crate) ctx: &'a RequestContext,
    /// The organizer's copy as the caller found it; it is read again under the lock of its calendar.
    pub(crate) organizer: &'a StoredObject,
    /// The `REPLY`.
    pub(crate) message: &'a ItipMessage,
    /// The attendee who answers: taken from what the caller authenticated, never from the message.
    pub(crate) attendee: &'a CalendarUserAddress,
    /// The principal of the attendee, when the attendee is a member of the tenant.
    pub(crate) attendee_principal: Option<PrincipalId>,
    /// Whom to tell.
    pub(crate) notify: Notify<'a>,
    /// Whether the organizer is told even when the copy holds the answer already: the answering attendee wrote the
    /// organizer's own object (an event in a group calendar that both can write), so the answer was in it before the
    /// reply was applied.
    pub(crate) announce: bool,
}

/// What applying a reply did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplyReport {
    /// Whether the organizer's copy changed (an answer that repeats the stored one changes nothing).
    pub(crate) changed: bool,
    /// The organizer's object.
    pub(crate) object: ObjectId,
    /// The organizer's calendar.
    pub(crate) calendar: CalendarId,
    /// The UID of the event.
    pub(crate) uid: Uid,
    /// The answer.
    pub(crate) partstat: PartStat,
    /// The remark of the attendee.
    pub(crate) comment: Option<String>,
}

/// The reply folded into the copy, on a blocking thread.
struct Folded {
    applied: ReplyApplication,
    changed: bool,
}

fn fold(
    stored: &str,
    message: &ItipMessage,
    attendee: &CalendarUserAddress,
    limits: &IcalLimits,
) -> Result<Folded, IcalError> {
    let copy = davhaven_ical::parse::parse(stored.as_bytes(), limits)?;
    let applied = apply_reply_with(&copy, message, limits, Some(attendee))?;
    let changed = applied.updated != copy;
    Ok(Folded { applied, changed })
}

impl ItipProcessor {
    /// Folds the answer of `input.attendee` into the organizer's copy and tells the organizer.
    ///
    /// The calendar of the copy is locked first, the copy is read under the lock, so concurrent replies add up
    /// instead of overwriting each other. The `Schedule-Tag` of the copy stays: a reply is a server merge, and
    /// organizer clients rely on it to keep their writes (PLAN 2.7).
    ///
    /// # Errors
    ///
    /// [`ReplyError::Rejected`] when the reply does not fit the copy, [`ReplyError::Failed`] for store failures
    /// and a worker that did not finish.
    pub(crate) async fn apply_reply(&self, tx: &mut dyn Tx, input: ReplyInput<'_>) -> Result<ReplyReport, ReplyError> {
        let calendar = match lock_one(tx, input.organizer.calendar_id).await {
            Ok(calendar) => calendar,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(ReplyError::Rejected(Rejection::UnknownEvent));
            }
            Err(error) => return Err(ReplyError::Failed(error)),
        };
        let object = match tx.objects().get_by_id(input.organizer.id).await {
            Ok(object) => object,
            Err(StoreError::NotFound) => return Err(ReplyError::Rejected(Rejection::UnknownEvent)),
            Err(error) => return Err(error.into()),
        };
        let stored = object.data.clone();
        let message = input.message.clone();
        let attendee = input.attendee.clone();
        let folded = blocking_ical(&self.core, move |limits| fold(&stored, &message, &attendee, limits))
            .await?
            .map_err(|error| {
                if is_data_error(&error) {
                    ReplyError::Rejected(Rejection::InvalidReply)
                } else {
                    ReplyError::Failed(machine_error(error))
                }
            })?;
        if !folded.applied.sequence_matches {
            return Err(ReplyError::Rejected(Rejection::StaleSequence));
        }
        let journal = Journal::new(&self.core, input.ctx);
        if folded.changed {
            self.store_folded(tx, &journal, &calendar, &object, &folded).await?;
        }
        // An answer that repeats the stored one (a second click on the same button) tells the organizer nothing new,
        // unless it comes with a remark of its own.
        if folded.changed || folded.applied.comment.is_some() || input.announce {
            self.tell_organizer(tx, &journal, &input, (&calendar, &object), folded.applied.partstat)
                .await?;
        }
        Ok(ReplyReport {
            changed: folded.changed,
            object: object.id,
            calendar: calendar.id,
            uid: object.uid,
            partstat: folded.applied.partstat,
            comment: folded.applied.comment,
        })
    }

    /// Stores the organizer's copy with the answer folded in, keeping its `Schedule-Tag`, and logs the change.
    async fn store_folded(
        &self,
        tx: &mut dyn Tx,
        journal: &Journal<'_>,
        calendar: &Calendar,
        object: &StoredObject,
        folded: &Folded,
    ) -> AppResult<()> {
        let (prepared, text) = prepare_calendar(&self.core, folded.applied.updated.clone()).await?;
        let rows = tx.objects().attendees(object.id).await?;
        let version = NewVersion {
            id: object.id,
            uri: object.uri.clone(),
            etag: etag_of(&text),
            data: text,
            schedule_tag: object.schedule_tag.clone(),
            content_hash: prepared.hash.clone(),
            index: prepared.index.clone(),
            attendee_principals: rows
                .iter()
                .filter_map(|row| row.principal_id.map(|id| (row.address.clone(), id)))
                .collect(),
            external_key: object.external_key.clone(),
            origin: object.origin.clone(),
        };
        let result = tx
            .objects()
            .put(calendar.id, version, Expected::Etag(object.etag.clone()))
            .await?;
        publish_changes(
            journal,
            tx,
            calendar,
            result.seq,
            vec![ObjectChange {
                kind: ObjectChangeKind::Updated,
                object: Some(object.id),
                uri: object.uri.clone(),
                uid: object.uid.clone(),
                external_key: object.external_key.clone(),
                etag: Some(result.etag),
            }],
        )
        .await?;
        Ok(())
    }

    /// Puts the `REPLY` into the organizer's scheduling inbox and announces `scheduling.reply_received`.
    async fn tell_organizer(
        &self,
        tx: &mut dyn Tx,
        journal: &Journal<'_>,
        input: &ReplyInput<'_>,
        (calendar, object): (&Calendar, &StoredObject),
        partstat: PartStat,
    ) -> AppResult<()> {
        let deps = self.core.deps();
        if let Some(principal) = input.notify.inbox_principal {
            let now = deps.clock.now();
            let id = InboxItemId::from_uuid(deps.ids.new_id());
            let uri = match input.notify.inbox_uri {
                Some(uri) => uri.clone(),
                None => ObjectUri::parse(&format!("{id}.ics")).map_err(AppError::internal)?,
            };
            let tenant_id = tx.tenant_id();
            tx.inbox()
                .create(InboxItem {
                    id,
                    tenant_id,
                    principal_id: principal,
                    uri,
                    etag: etag_of(input.notify.text),
                    data: input.notify.text.to_owned(),
                    quarantined: false,
                    created_at: now,
                    updated_at: now,
                    version: 1,
                })
                .await?;
        }
        journal
            .publish(
                tx,
                EventType::SchedulingReplyReceived,
                EventPayload::SchedulingReply(SchedulingReplyPayload {
                    calendar: Some(calendar.id),
                    object: Some(object.id),
                    uid: Some(object.uid.clone()),
                    attendee: input.attendee_principal,
                    partstat: Some(partstat),
                    reason: None,
                }),
            )
            .await?;
        Ok(())
    }
}
