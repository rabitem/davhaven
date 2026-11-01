//! Delivery of invitations and cancellations to internal recipients.

use std::collections::BTreeMap;

use davhaven_domain::events::{ObjectChange, ObjectChangeKind};
use davhaven_domain::{
    Calendar, CalendarId, CalendarUserAddress, InboxItem, InboxItemId, ObjectId, ObjectUri, Principal, RequestContext,
    StoredObject, Uid,
};
use davhaven_ical::itip::carry_over_attendee_data;
use davhaven_ports::{Expected, NewVersion, StoreError, Tx};

use super::{ItipProcessor, blocking_ical, is_data_error, machine_error};
use crate::audit::Journal;
use crate::error::{AppError, AppResult};
use crate::objects::locate::publish_changes;
use crate::objects::prepare::{Prepared, etag_of, fresh_schedule_tag, prepare, prepare_calendar};

/// What happens to the recipient's copy of the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CopyOp {
    /// The copy stays as it is (the recipient only gets the message).
    Keep,
    /// The copy becomes `text`. A recipient who has a copy gets it replaced (keeping their own alarms and `TRANSP`);
    /// one who has none gets a new copy in `create_in`, when the policy added the invitation and the recipient does
    /// not see the organizer's calendar already.
    Put {
        /// The text of the copy: the message without its `METHOD`.
        text: String,
        /// The calendar a missing copy is created in; `None` creates none.
        create_in: Option<CalendarId>,
    },
    /// The copy is removed (the event was cancelled for the recipient).
    Remove,
}

/// What one internal recipient receives.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct InternalDelivery {
    /// The recipient.
    pub(crate) principal: Principal,
    /// The address the recipient is known by in the copy and the messages.
    pub(crate) address: CalendarUserAddress,
    /// What happens to their copy.
    pub(crate) copy: CopyOp,
    /// The messages for their scheduling inbox, as text with `METHOD`.
    pub(crate) messages: Vec<String>,
    /// Names for the inbox items, one per message; fresh names when absent. A delivery that can be repeated (a queued
    /// one) names its items after the record, so a retry finds what was delivered before.
    pub(crate) inbox_names: Option<Vec<ObjectUri>>,
}

/// What a delivery needs to know about the event it is about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeliveryScope<'a> {
    /// The caller (the organizer, or the server for queued deliveries).
    pub(crate) ctx: &'a RequestContext,
    /// The UID of the event.
    pub(crate) uid: &'a Uid,
    /// Every address that names the organizer the delivery is for. A copy the recipient has under the UID is the
    /// organizer's only when its `ORGANIZER` is one of them (see the module documentation of `itip`).
    pub(crate) organizers: &'a [CalendarUserAddress],
}

impl DeliveryScope<'_> {
    /// Whether `object` is a copy of an event of the organizer the delivery is for.
    fn sent_by_organizer(&self, object: &StoredObject) -> bool {
        object
            .organizer_address
            .as_ref()
            .is_some_and(|address| self.organizers.contains(address))
    }
}

/// Where a recipient's copy is, or goes.
struct Placed {
    existing: Option<StoredObject>,
    /// The calendar a new copy goes to.
    new_copy_in: Option<CalendarId>,
    /// Whether the recipient has another organizer's object under the UID: they are not delivered to.
    skipped: bool,
}

/// The changes of one calendar made by a delivery, for the domain event.
#[derive(Default)]
struct Changed {
    seq: u64,
    changes: Vec<ObjectChange>,
}

impl ItipProcessor {
    /// Delivers to the recipients, in the transaction of the caller.
    ///
    /// The calendars of all copies that are changed are locked together, in ascending id order (PLAN 2.8), before
    /// the first write. A recipient who sees the organizer's calendar already is the caller's business
    /// (`CopyOp::Put::create_in`). A recipient who has an object of **another** organizer under the UID is skipped
    /// altogether: nothing of theirs is replaced or removed and nothing is put into their inbox.
    ///
    /// Answers how many recipients were delivered to (those who were not skipped for that reason).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) async fn deliver(
        &self,
        tx: &mut dyn Tx,
        scope: &DeliveryScope<'_>,
        deliveries: &[InternalDelivery],
    ) -> AppResult<usize> {
        let mut placed: Vec<Placed> = Vec::with_capacity(deliveries.len());
        let mut locks: Vec<CalendarId> = Vec::new();
        for delivery in deliveries {
            let existing = tx
                .objects()
                .find_scheduling_uid(delivery.principal.id, scope.uid)
                .await?;
            if existing.as_ref().is_some_and(|object| !scope.sent_by_organizer(object)) {
                tracing::debug!(
                    "a delivery was skipped: the recipient has an object of another organizer under the UID"
                );
                placed.push(Placed {
                    existing: None,
                    new_copy_in: None,
                    skipped: true,
                });
                continue;
            }
            let new_copy_in = match (&delivery.copy, &existing) {
                (CopyOp::Put { create_in, .. }, None) => *create_in,
                _ => None,
            };
            if let Some(object) = &existing
                && !matches!(delivery.copy, CopyOp::Keep)
            {
                locks.push(object.calendar_id);
            }
            locks.extend(new_copy_in);
            placed.push(Placed {
                existing,
                new_copy_in,
                skipped: false,
            });
        }
        locks.sort();
        locks.dedup();
        let calendars: BTreeMap<CalendarId, Calendar> = if locks.is_empty() {
            BTreeMap::new()
        } else {
            tx.calendars()
                .lock(&locks)
                .await?
                .into_iter()
                .map(|calendar| (calendar.id, calendar))
                .collect()
        };
        let delivered = placed.iter().filter(|place| !place.skipped).count();
        let mut changed: BTreeMap<CalendarId, Changed> = BTreeMap::new();
        for (delivery, place) in deliveries.iter().zip(placed) {
            self.deliver_one(tx, scope, delivery, place, &mut changed).await?;
        }
        let journal = Journal::new(&self.core, scope.ctx);
        for (id, made) in changed {
            if let Some(calendar) = calendars.get(&id) {
                publish_changes(&journal, tx, calendar, made.seq, made.changes).await?;
            }
        }
        Ok(delivered)
    }

    /// One recipient: the copy, then the inbox.
    async fn deliver_one(
        &self,
        tx: &mut dyn Tx,
        scope: &DeliveryScope<'_>,
        delivery: &InternalDelivery,
        place: Placed,
        changed: &mut BTreeMap<CalendarId, Changed>,
    ) -> AppResult<()> {
        if place.skipped {
            return Ok(());
        }
        match &delivery.copy {
            CopyOp::Keep => {}
            CopyOp::Remove => {
                if let Some(object) = &place.existing {
                    Self::remove_copy(tx, object, changed).await?;
                }
            }
            CopyOp::Put { text, .. } => {
                if !self.put_copy(tx, scope, delivery, &place, text, changed).await? {
                    // The copy is newer than the message: the message is out of date as well.
                    return Ok(());
                }
            }
        }
        self.put_messages(tx, delivery).await
    }

    /// Removes the recipient's copy: the event was cancelled for them.
    async fn remove_copy(
        tx: &mut dyn Tx,
        object: &StoredObject,
        changed: &mut BTreeMap<CalendarId, Changed>,
    ) -> AppResult<()> {
        let seq = match tx
            .objects()
            .delete(object.calendar_id, &object.uri, Expected::Etag(object.etag.clone()))
            .await
        {
            Ok(seq) => seq,
            Err(StoreError::PreconditionFailed) => return Err(super::contention()),
            Err(error) => return Err(error.into()),
        };
        record(
            changed,
            object.calendar_id,
            seq,
            ObjectChange {
                kind: ObjectChangeKind::Deleted,
                object: None,
                uri: object.uri.clone(),
                uid: object.uid.clone(),
                external_key: object.external_key.clone(),
                etag: None,
            },
        );
        Ok(())
    }

    /// Brings the recipient's copy to `text`: replaces the copy they have (unless it holds that content already) or
    /// creates one where the caller decided one goes.
    ///
    /// What the recipient may change on their own copy (PLAN 2.8: their alarms and `TRANSP`) is carried over into
    /// the replacement, so an organizer's edit does not delete their reminders or make an event they marked free
    /// busy again. Answers `false` when the copy has a newer `SEQUENCE` than `text` and was left alone.
    async fn put_copy(
        &self,
        tx: &mut dyn Tx,
        scope: &DeliveryScope<'_>,
        delivery: &InternalDelivery,
        place: &Placed,
        text: &str,
        changed: &mut BTreeMap<CalendarId, Changed>,
    ) -> AppResult<bool> {
        let deps = self.core.deps();
        let target = place
            .existing
            .as_ref()
            .map(|object| object.calendar_id)
            .or(place.new_copy_in);
        let Some(calendar) = target else {
            return Ok(true);
        };
        let (prepared, text) = match &place.existing {
            Some(object) => self.with_own_settings(&object.data, text).await?,
            None => (prepare(&self.core, text).await?, text.to_owned()),
        };
        let text = text.as_str();
        if place
            .existing
            .as_ref()
            .is_some_and(|object| prepared.index.sequence < object.sequence)
        {
            return Ok(false);
        }
        let resolved = vec![(delivery.address.clone(), delivery.principal.id)];
        let version = |id: ObjectId, uri: ObjectUri, previous: Option<&StoredObject>| NewVersion {
            id,
            uri,
            data: text.to_owned(),
            etag: etag_of(text),
            schedule_tag: Some(fresh_schedule_tag(deps.ids.new_id())),
            content_hash: prepared.hash.clone(),
            index: prepared.index.clone(),
            attendee_principals: resolved.clone(),
            external_key: previous.and_then(|object| object.external_key.clone()),
            origin: previous.and_then(|object| object.origin.clone()),
        };
        match &place.existing {
            Some(object) if object.content_hash == prepared.hash => {}
            Some(object) => {
                let result = tx
                    .objects()
                    .put(
                        calendar,
                        version(object.id, object.uri.clone(), Some(object)),
                        Expected::Etag(object.etag.clone()),
                    )
                    .await
                    .map_err(|error| match error {
                        StoreError::PreconditionFailed => super::contention(),
                        other => AppError::from(other),
                    })?;
                record(
                    changed,
                    calendar,
                    result.seq,
                    ObjectChange {
                        kind: ObjectChangeKind::Updated,
                        object: Some(result.object_id),
                        uri: object.uri.clone(),
                        uid: object.uid.clone(),
                        external_key: object.external_key.clone(),
                        etag: Some(result.etag),
                    },
                );
            }
            None => self.create_copy(tx, scope, calendar, &version, changed).await?,
        }
        Ok(true)
    }

    /// `text` with the alarms and the `TRANSP` of the copy `previous`, prepared for storage.
    async fn with_own_settings(&self, previous: &str, text: &str) -> AppResult<(Prepared, String)> {
        let (old, new) = (previous.to_owned(), text.to_owned());
        let merged = blocking_ical(&self.core, move |limits| {
            let previous = davhaven_ical::parse::parse(old.as_bytes(), limits)?;
            let new = davhaven_ical::parse::parse(new.as_bytes(), limits)?;
            carry_over_attendee_data(&new, &previous)
        })
        .await?;
        match merged {
            Ok(calendar) => prepare_calendar(&self.core, calendar).await,
            // A copy that cannot be read is replaced as it is.
            Err(error) if is_data_error(&error) => Ok((prepare(&self.core, text).await?, text.to_owned())),
            Err(error) => Err(machine_error(error)),
        }
    }

    /// Puts the messages of the delivery into the recipient's scheduling inbox.
    async fn put_messages(&self, tx: &mut dyn Tx, delivery: &InternalDelivery) -> AppResult<()> {
        let deps = self.core.deps();
        for (position, message) in delivery.messages.iter().enumerate() {
            let now = deps.clock.now();
            let id = InboxItemId::from_uuid(deps.ids.new_id());
            let uri = match delivery.inbox_names.as_ref().and_then(|names| names.get(position)) {
                Some(uri) => uri.clone(),
                None => ObjectUri::parse(&format!("{id}.ics")).map_err(AppError::internal)?,
            };
            let tenant_id = tx.tenant_id();
            match tx
                .inbox()
                .create(InboxItem {
                    id,
                    tenant_id,
                    principal_id: delivery.principal.id,
                    uri,
                    etag: etag_of(message),
                    data: message.clone(),
                    quarantined: false,
                    created_at: now,
                    updated_at: now,
                    version: 1,
                })
                .await
            {
                Ok(_) => {}
                // A repeated delivery finds the item it made before.
                Err(StoreError::UniqueViolation(davhaven_ports::UniqueKey::InboxUri))
                    if delivery.inbox_names.is_some() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Creates a copy under the conventional name, or under a fresh one when another object has that name.
    async fn create_copy(
        &self,
        tx: &mut dyn Tx,
        scope: &DeliveryScope<'_>,
        calendar: CalendarId,
        version: &(dyn Fn(ObjectId, ObjectUri, Option<&StoredObject>) -> NewVersion + Sync),
        changed: &mut BTreeMap<CalendarId, Changed>,
    ) -> AppResult<()> {
        let deps = self.core.deps();
        let id = ObjectId::from_uuid(deps.ids.new_id());
        let mut uri = ObjectUri::for_uid(scope.uid);
        for attempt in 0..2 {
            let new = version(id, uri.clone(), None);
            let uid = new.index.uid.clone();
            match tx.objects().put(calendar, new, Expected::Absent).await {
                Ok(result) => {
                    record(
                        changed,
                        calendar,
                        result.seq,
                        ObjectChange {
                            kind: ObjectChangeKind::Created,
                            object: Some(result.object_id),
                            uri: uri.clone(),
                            uid,
                            external_key: None,
                            etag: Some(result.etag),
                        },
                    );
                    return Ok(());
                }
                // Another object has the conventional name: a fresh name does it.
                Err(StoreError::UniqueViolation(davhaven_ports::UniqueKey::ObjectUri)) if attempt == 0 => {
                    uri = ObjectUri::parse(&format!("{}.ics", deps.ids.new_id())).map_err(AppError::internal)?;
                }
                // The recipient got a copy in the meantime (a concurrent delivery): nothing to add.
                Err(StoreError::UniqueViolation(
                    davhaven_ports::UniqueKey::ObjectUid | davhaven_ports::UniqueKey::SchedulingUid,
                )) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

/// Notes a change of a calendar for the event that is published after the deliveries.
fn record(changed: &mut BTreeMap<CalendarId, Changed>, calendar: CalendarId, seq: u64, change: ObjectChange) {
    let entry = changed.entry(calendar).or_default();
    entry.seq = entry.seq.max(seq);
    entry.changes.push(change);
}
