//! Cases of the change logs, notifications and the scheduling inbox.

use davhaven_domain::{CalendarId, CollectionKey, CollectionKind, ETag, NotificationKind, ObjectUri, PrincipalId};
use davhaven_ports::{ChangeBatch, ChangeKind, Expected, InboxScope, UniqueKey};

use super::Outcome;
use super::world::{Db, StoreChecks, begin, id, inbox_item, key, notification, seed, version};
use crate::suite::Checks;

/// The change-log key of a calendar.
fn calendar_log(calendar: CalendarId) -> CollectionKey {
    CollectionKey {
        kind: CollectionKind::Calendar,
        id: calendar.as_uuid(),
    }
}

/// The key of a principal's collection.
fn principal_log(kind: CollectionKind, principal: PrincipalId) -> CollectionKey {
    CollectionKey {
        kind,
        id: principal.as_uuid(),
    }
}

/// A batch as `(name, sequence, kind)` triples.
fn summary(batch: &ChangeBatch) -> Vec<(String, u64, ChangeKind)> {
    batch
        .changes
        .iter()
        .map(|change| (change.uri.to_string(), change.seq, change.kind))
        .collect()
}

/// Collapsing, ordering, truncation and continuation of `since`.
pub(super) async fn changes_since(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let log = calendar_log(world.personal);
    let epoch = tx.changes().state(log).await?.epoch;
    let (a, b, c, d) = (
        version(0x4A1, "a.ics", "ua")?,
        version(0x4A2, "b.ics", "ub")?,
        version(0x4A3, "c.ics", "uc")?,
        version(0x4A4, "d.ics", "ud")?,
    );
    for event in [&a, &b, &c] {
        tx.objects()
            .put(world.personal, event.clone(), Expected::Absent)
            .await?;
    }
    tx.objects().put(world.personal, a.clone(), Expected::Any).await?;
    tx.objects().delete(world.personal, &b.uri, Expected::Any).await?;
    tx.objects().put(world.personal, d.clone(), Expected::Absent).await?;

    let all = tx.changes().since(log, epoch, 0, 100).await?;
    checks.equal(
        &summary(&all),
        &vec![
            ("c.ics".to_owned(), 3, ChangeKind::Upsert),
            ("a.ics".to_owned(), 4, ChangeKind::Upsert),
            ("b.ics".to_owned(), 5, ChangeKind::Delete),
            ("d.ics".to_owned(), 6, ChangeKind::Upsert),
        ],
        "one entry per member, the latest, ordered by sequence number",
    );
    checks.that(!all.truncated, "nothing is cut off");
    checks.equal(&all.current.seq, &6, "the current position");
    checks.equal(&all.current.epoch, &epoch, "with the epoch of the collection");

    checks.equal(
        &summary(&tx.changes().since(log, epoch, 3, 100).await?),
        &vec![
            ("a.ics".to_owned(), 4, ChangeKind::Upsert),
            ("b.ics".to_owned(), 5, ChangeKind::Delete),
            ("d.ics".to_owned(), 6, ChangeKind::Upsert),
        ],
        "only changes after the given sequence number",
    );
    let first = tx.changes().since(log, epoch, 0, 2).await?;
    checks.equal(
        &summary(&first),
        &vec![
            ("c.ics".to_owned(), 3, ChangeKind::Upsert),
            ("a.ics".to_owned(), 4, ChangeKind::Upsert),
        ],
        "a limit cuts the batch",
    );
    checks.that(first.truncated, "and says so");
    let last_seq = first.changes.last().map_or(0, |change| change.seq);
    let rest = tx.changes().since(log, epoch, last_seq, 2).await?;
    checks.equal(
        &summary(&rest),
        &vec![
            ("b.ics".to_owned(), 5, ChangeKind::Delete),
            ("d.ics".to_owned(), 6, ChangeKind::Upsert),
        ],
        "continuing from the last returned sequence number gets the rest",
    );
    checks.that(!rest.truncated, "which is complete");
    let current = tx.changes().since(log, epoch, 6, 10).await?;
    checks.that(
        current.changes.is_empty() && !current.truncated,
        "a token at the current position has nothing new",
    );
    let clamped = tx.changes().since(log, epoch, 0, 0).await?;
    checks.equal(&clamped.changes.len(), &1, "a limit of zero is raised to one");
    checks.that(clamped.truncated, "and still reports that more exist");
    Ok(())
}

/// Tokens that cannot be used are refused; positions exist for every kind of collection.
pub(super) async fn changes_token_checks(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let log = calendar_log(world.personal);
    let position = tx.changes().state(log).await?;
    tx.objects()
        .put(world.personal, version(0x4B1, "a.ics", "ua")?, Expected::Absent)
        .await?;
    checks.invalid_sync_token(
        tx.changes().since(log, id::<CalendarId>(0x1).as_uuid(), 0, 10).await,
        "a token of another epoch (never the 412 of a stale If-Match)",
    );
    checks.invalid_sync_token(
        tx.changes().since(log, position.epoch, 2, 10).await,
        "a token from the future",
    );
    checks.equal(
        &tx.changes().since(log, position.epoch, 1, 10).await?.changes.len(),
        &0,
        "the current token",
    );

    for kind in [
        CollectionKind::Home,
        CollectionKind::Inbox,
        CollectionKind::Notifications,
    ] {
        let state = tx.changes().state(principal_log(kind, world.olivia)).await?;
        checks.equal(
            &(state.seq, state.min_seq),
            &(0, 0),
            "a new principal's collections start empty",
        );
        checks.not_found(
            tx.changes().state(principal_log(kind, id(0x999))).await,
            "the position of an unknown principal",
        );
        checks.not_found(
            tx.changes()
                .since(principal_log(kind, id(0x999)), position.epoch, 0, 10)
                .await,
            "changes of an unknown principal's collection",
        );
    }
    checks.not_found(
        tx.changes().state(calendar_log(id(0x999))).await,
        "the position of an unknown calendar",
    );
    checks.not_found(
        tx.changes().since(calendar_log(id(0x999)), position.epoch, 0, 10).await,
        "changes of an unknown calendar",
    );
    let epochs: Vec<_> = {
        let mut seen = Vec::new();
        for kind in [
            CollectionKind::Home,
            CollectionKind::Inbox,
            CollectionKind::Notifications,
        ] {
            seen.push(tx.changes().state(principal_log(kind, world.olivia)).await?.epoch);
        }
        seen.push(position.epoch);
        seen
    };
    let mut distinct = epochs.clone();
    distinct.sort_unstable();
    distinct.dedup();
    checks.equal(
        &distinct.len(),
        &epochs.len(),
        "every collection has an epoch of its own",
    );
    Ok(())
}

/// Notifications and inbox items advance the log of their collection; `touch_*` advances without logging.
pub(super) async fn changes_of_principal_collections(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let notifications = principal_log(CollectionKind::Notifications, world.mia);
    let inbox = principal_log(CollectionKind::Inbox, world.mia);
    let notifications_epoch = tx.changes().state(notifications).await?.epoch;
    let inbox_epoch = tx.changes().state(inbox).await?.epoch;

    let first = tx
        .notifications()
        .create(notification(0x801, world.mia, "n1.xml", "invite-1")?)
        .await?;
    let mut changed = first.clone();
    changed.body_xml = "<changed/>".into();
    tx.notifications().update(changed, first.version).await?;
    tx.notifications()
        .create(notification(0x802, world.mia, "n2.xml", "invite-2")?)
        .await?;
    tx.notifications().delete(first.id).await?;
    checks.equal(
        &summary(&tx.changes().since(notifications, notifications_epoch, 0, 10).await?),
        &vec![
            ("n2.xml".to_owned(), 3, ChangeKind::Upsert),
            ("n1.xml".to_owned(), 4, ChangeKind::Delete),
        ],
        "notifications are logged by name: create, update, create, delete",
    );

    let item = tx
        .inbox()
        .create(inbox_item(0x901, world.mia, "i1.ics", false)?)
        .await?;
    let held = tx.inbox().create(inbox_item(0x902, world.mia, "i2.ics", true)?).await?;
    checks.equal(
        &tx.changes().state(inbox).await?.seq,
        &1,
        "a quarantined item is never shown to clients, so it does not move the inbox",
    );
    tx.inbox().delete(item.id).await?;
    tx.inbox().delete(held.id).await?;
    checks.equal(
        &summary(&tx.changes().since(inbox, inbox_epoch, 0, 10).await?),
        &vec![("i1.ics".to_owned(), 2, ChangeKind::Delete)],
        "delivered inbox items are logged by name (create, delete); quarantined ones, created or deleted, are not",
    );

    let home = principal_log(CollectionKind::Home, world.mia);
    let home_epoch = tx.changes().state(home).await?.epoch;
    checks.equal(&tx.changes().touch_home(world.mia).await?, &1, "touching the home");
    checks.equal(&tx.changes().touch_home(world.mia).await?, &2, "again");
    checks.equal(
        &tx.changes().touch_inbox(world.mia).await?,
        &3,
        "touching the inbox continues its sequence",
    );
    checks.equal(
        &tx.changes().touch_notifications(world.mia).await?,
        &5,
        "touching the notifications continues theirs",
    );
    let after = tx.changes().since(home, home_epoch, 0, 10).await?;
    checks.that(after.changes.is_empty(), "a touch logs no change");
    checks.equal(&after.current.seq, &2, "but moves the position");
    checks.not_found(
        tx.changes().touch_home(id(0x999)).await,
        "touching an unknown principal's home",
    );
    checks.not_found(
        tx.changes().touch_inbox(id(0x999)).await,
        "touching an unknown principal's inbox",
    );
    checks.not_found(
        tx.changes().touch_notifications(id(0x999)).await,
        "touching an unknown principal's notifications",
    );
    tx.commit().await?;
    Ok(())
}

/// The notification and inbox repositories.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn notifications_and_inbox(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let first = tx
        .notifications()
        .create(notification(0x801, world.mia, "n1.xml", "invite-1")?)
        .await?;
    checks.equal(&first.version, &1, "a new notification has version 1");
    checks.equal(&first.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(&first.kind, &NotificationKind::Invite, "its type");
    let second = tx
        .notifications()
        .create(notification(0x802, world.mia, "n2.xml", "invite-1")?)
        .await?;
    tx.notifications()
        .create(notification(0x803, world.olivia, "n1.xml", "invite-3")?)
        .await?;
    checks.equal(&tx.notifications().get(first.id).await?, &first, "get");
    checks.equal(
        &tx.notifications().get_by_uri(world.mia, &first.uri).await?,
        &first,
        "get by name",
    );
    checks.equal(
        &tx.notifications()
            .find_by_uid(world.mia, &key(davhaven_domain::Uid::parse("invite-1"))?)
            .await?,
        &Some(first.clone()),
        "find by uid returns the first of several",
    );
    checks.equal(
        &tx.notifications()
            .list(world.mia)
            .await?
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![first.id, second.id],
        "the notifications of a principal in id order",
    );
    let gone = key(davhaven_domain::ObjectUri::parse("gone.xml"))?;
    checks.equal(
        &tx.notifications()
            .get_many_by_uri(
                world.mia,
                &[second.uri.clone(), gone, first.uri.clone(), second.uri.clone()],
            )
            .await?
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![second.id, first.id],
        "several notifications by name: the ones that exist, in the order asked, each once, and only the principal's own (`n1.xml` is Olivia's too)",
    );
    checks.equal(
        &tx.notifications().get_many_by_uri(world.mia, &[]).await?.len(),
        &0,
        "no names, no notifications",
    );
    checks.unique(
        tx.notifications()
            .create(notification(0x804, world.mia, "n1.xml", "x")?)
            .await,
        UniqueKey::NotificationUri,
        "a duplicate name in one collection",
    );
    checks.not_found(
        tx.notifications()
            .create(notification(0x805, id(0x999), "n9.xml", "x")?)
            .await,
        "a notification for an unknown principal",
    );
    let mut changed = first.clone();
    changed.etag = ETag::from_bytes(b"new");
    changed.kind = NotificationKind::InviteReply;
    changed.body_xml = "<reply/>".into();
    let updated = tx.notifications().update(changed.clone(), first.version).await?;
    checks.equal(&updated.version, &2, "an update bumps the version");
    checks.equal(&updated.body_xml.as_str(), &"<reply/>", "the body changes");
    checks.equal(&updated.kind, &NotificationKind::InviteReply, "the type changes");
    checks.equal(&updated.uri, &first.uri, "the name does not");
    checks.precondition_failed(
        tx.notifications().update(changed, first.version).await,
        "a stale version",
    );
    checks.not_found(
        tx.notifications()
            .update(notification(0x998, world.mia, "zz.xml", "z")?, 1)
            .await,
        "an unknown notification",
    );
    tx.notifications().delete(second.id).await?;
    checks.not_found(tx.notifications().get(second.id).await, "a deleted notification");
    checks.not_found(tx.notifications().delete(second.id).await, "deleting twice");

    let delivered = tx
        .inbox()
        .create(inbox_item(0x901, world.mia, "i1.ics", false)?)
        .await?;
    let quarantined = tx.inbox().create(inbox_item(0x902, world.mia, "i2.ics", true)?).await?;
    checks.equal(&delivered.version, &1, "a new inbox item has version 1");
    checks.equal(&tx.inbox().get(delivered.id).await?, &delivered, "get");
    checks.equal(
        &tx.inbox().get_by_uri(world.mia, &quarantined.uri).await?,
        &quarantined,
        "get by name finds quarantined items too",
    );
    let nothing_there = key(davhaven_domain::ObjectUri::parse("gone.ics"))?;
    checks.equal(
        &tx.inbox()
            .get_many_by_uri(
                world.mia,
                &[quarantined.uri.clone(), nothing_there, delivered.uri.clone(), quarantined.uri.clone()],
            )
            .await?,
        &vec![quarantined.clone(), delivered.clone()],
        "several items by name: the ones that exist (quarantined ones too, the caller decides), in the order asked, each once",
    );
    checks.equal(
        &tx.inbox().get_many_by_uri(world.mia, &[]).await?.len(),
        &0,
        "no names, no items",
    );
    checks.equal(
        &tx.inbox()
            .get_many_by_uri(world.olivia, std::slice::from_ref(&delivered.uri))
            .await?
            .len(),
        &0,
        "the name of another principal's item finds nothing",
    );
    checks.equal(
        &tx.inbox().list(world.mia, InboxScope::Delivered).await?,
        &vec![delivered.clone()],
        "delivered items",
    );
    checks.equal(
        &tx.inbox().list(world.mia, InboxScope::Quarantined).await?,
        &vec![quarantined.clone()],
        "quarantined items",
    );
    checks.unique(
        tx.inbox().create(inbox_item(0x903, world.mia, "i1.ics", false)?).await,
        UniqueKey::InboxUri,
        "a duplicate name in one inbox",
    );
    checks.not_found(
        tx.inbox().create(inbox_item(0x904, id(0x999), "i9.ics", false)?).await,
        "an item for an unknown principal",
    );
    tx.inbox().delete(delivered.id).await?;
    checks.not_found(tx.inbox().get(delivered.id).await, "a deleted item");
    checks.not_found(tx.inbox().delete(delivered.id).await, "deleting twice");
    checks.not_found(
        tx.inbox()
            .get_by_uri(world.mia, &key(ObjectUri::parse("none.ics"))?)
            .await,
        "an unknown name",
    );
    tx.commit().await?;
    Ok(())
}
