//! Cases of the retention methods of the system transaction.

use std::time::Duration;

use chrono::TimeDelta;
use davhaven_domain::{AuditActor, AuditEvent};
use davhaven_domain::{
    CalendarKind, CollectionKey, CollectionKind, EventType, PrincipalKind, PrincipalStatus, TokenId,
};
use davhaven_ports::testing::ManualClock;
use davhaven_ports::{
    AuditFilter, AuditPurge, ChangeKind, Clock as _, Expected, IdempotencyClaim, IdempotencyRecord, IdempotencyStatus,
    InboxScope, NewAudit, NewOutbox, OutboxFailure, OutboxKey, OutboxMessage, PageReq, Reserved,
};

use super::Outcome;
use super::delivery::{delivery_for, subscription_for};
use super::world::{
    Db, StoreChecks, at, begin, binding, calendar, far_future, id, inbox_item, long_ago, notification, principal, read,
    rsvp_token, scheduling, seed, system, uuid, version,
};
use crate::suite::Checks;

/// Just after the instant long ago: before every instant a test stamps.
fn soon_after_long_ago() -> chrono::DateTime<chrono::Utc> {
    long_ago() + TimeDelta::days(1)
}

/// The cleanup methods remove what is older than their cut-off and nothing else.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn retention_purges(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let push = || OutboxMessage::ProviderPush(Reserved {});

    // Outbox: one done, one dead, one pending and one in flight.
    let mut tx = begin(db, world.a).await?;
    for n in [0xA01, 0xA02, 0xA04] {
        tx.outbox().enqueue(NewOutbox::now(id(n), push())).await?;
    }
    tx.outbox()
        .enqueue(NewOutbox::at(id(0xA03), push(), far_future()))
        .await?;
    tx.commit().await?;
    let mut sys = system(db).await?;
    sys.outbox_claim().claim(10, Duration::from_secs(600)).await?;
    sys.outbox_claim()
        .complete(OutboxKey {
            tenant: world.a,
            id: id(0xA01),
        })
        .await?;
    sys.outbox_claim()
        .fail(
            OutboxKey {
                tenant: world.a,
                id: id(0xA02),
            },
            OutboxFailure::dead("gave up"),
        )
        .await?;
    checks.equal(
        &sys.retention().purge_outbox(long_ago(), long_ago()).await?,
        &0,
        "nothing settled before the far past",
    );
    checks.equal(
        &sys.retention().purge_outbox(far_future(), long_ago()).await?,
        &1,
        "done records older than the first cut-off",
    );
    checks.equal(
        &sys.retention().purge_outbox(far_future(), far_future()).await?,
        &1,
        "dead records older than the second cut-off",
    );
    checks.equal(
        &sys.retention().purge_outbox(far_future(), far_future()).await?,
        &0,
        "pending and in-flight records are never purged",
    );
    sys.commit().await?;

    // Idempotency keys, OAuth states, RSVP tokens, inbox items, audit records.
    let token: TokenId = id(0x710);
    let key = |name: &str, expires| IdempotencyRecord {
        token_id: token,
        key: name.to_owned(),
        method: "POST".to_owned(),
        path: "/x".to_owned(),
        fingerprint: "f".to_owned(),
        status: IdempotencyStatus::InFlight,
        response_status: None,
        response: None,
        expires_at: expires,
    };
    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.idempotency().claim(key("old", long_ago())).await?,
        &IdempotencyClaim::Claimed,
        "an old key",
    );
    tx.idempotency().claim(key("new", far_future())).await?;
    let meeting = scheduling(
        version(0x4E1, "m.ics", "meeting")?,
        "mailto:olivia@example.org",
        &[("mailto:x@example.org", None)],
    )?;
    let object = tx
        .objects()
        .put(world.personal, meeting, Expected::Absent)
        .await?
        .object_id;
    let expired = {
        let mut expired = rsvp_token(0x731, object, "mailto:x@example.org", "rsvp-expired")?;
        expired.expires_at = long_ago();
        expired
    };
    tx.rsvp().create(expired).await?;
    let revoked = tx
        .rsvp()
        .create(rsvp_token(0x732, object, "mailto:x@example.org", "rsvp-revoked")?)
        .await?;
    tx.rsvp().revoke(revoked.id).await?;
    tx.rsvp()
        .create(rsvp_token(0x733, object, "mailto:x@example.org", "rsvp-live")?)
        .await?;
    tx.inbox()
        .create(inbox_item(0x901, world.mia, "i1.ics", false)?)
        .await?;
    tx.inbox().create(inbox_item(0x902, world.mia, "i2.ics", true)?).await?;
    let subscription = tx
        .webhooks()
        .create(subscription_for(0xB31, &[EventType::PrincipalCreated])?)
        .await?;
    tx.webhooks()
        .create_delivery(delivery_for(0xB32, subscription.id))
        .await?;
    tx.webhooks()
        .create_delivery(delivery_for(0xB33, subscription.id))
        .await?;
    tx.audit()
        .append(NewAudit {
            id: uuid(1),
            actor: AuditActor::system(),
            event: AuditEvent::TenantCreated,
        })
        .await?;
    tx.commit().await?;

    let mut sys = system(db).await?;
    checks.equal(
        &sys.retention().purge_deliveries(long_ago()).await?,
        &0,
        "no webhook deliveries older than long ago",
    );
    checks.equal(
        &sys.retention().purge_deliveries(far_future()).await?,
        &2,
        "webhook deliveries older than the cut-off",
    );
    checks.equal(&sys.retention().purge_deliveries(far_future()).await?, &0, "once");
    checks.equal(
        &sys.retention().purge_idempotency().await?,
        &1,
        "expired idempotency keys",
    );
    checks.equal(&sys.retention().purge_idempotency().await?, &0, "and only those");
    checks.equal(
        &sys.retention().purge_rsvp_tokens(soon_after_long_ago()).await?,
        &1,
        "expired RSVP tokens",
    );
    checks.equal(
        &sys.retention().purge_rsvp_tokens(far_future()).await?,
        &1,
        "revoked RSVP tokens",
    );
    checks.equal(
        &sys.retention().purge_inbox(long_ago()).await?,
        &0,
        "no inbox items older than long ago",
    );
    checks.equal(
        &sys.retention().purge_inbox(far_future()).await?,
        &2,
        "inbox items older than the cut-off",
    );
    checks.equal(
        &sys.retention().purge_audit(long_ago()).await?,
        &0,
        "no audit records older than long ago",
    );
    checks.equal(
        &sys.retention().purge_audit(far_future()).await?,
        &1,
        "audit records older than the cut-off",
    );
    checks.equal(&sys.retention().purge_audit(far_future()).await?, &0, "once");
    checks.equal(
        &sys.retention().purge_audit_checked(far_future()).await?,
        &AuditPurge::Purged(0),
        "the checked purge says it was permitted (the suite's database lets its role purge the audit log)",
    );
    sys.commit().await?;

    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.rsvp().for_object(object).await?.len(),
        &1,
        "the live RSVP token is kept",
    );
    checks.equal(
        &tx.inbox().list(world.mia, InboxScope::Delivered).await?.len(),
        &0,
        "the inbox is empty",
    );
    checks.equal(
        &tx.inbox().list(world.mia, InboxScope::Quarantined).await?.len(),
        &0,
        "quarantined items go too",
    );
    let inbox = CollectionKey {
        kind: CollectionKind::Inbox,
        id: world.mia.as_uuid(),
    };
    let state = tx.changes().state(inbox).await?;
    checks.equal(
        &state.seq,
        &2,
        "the delivered item's creation and purged deletion advanced the inbox sequence, the quarantined one's did not",
    );
    let batch = tx.changes().since(inbox, state.epoch, 0, 10).await?;
    checks.equal(
        &batch
            .changes
            .iter()
            .map(|change| (change.uri.to_string(), change.seq, change.kind))
            .collect::<Vec<_>>(),
        &vec![("i1.ics".to_owned(), 2, ChangeKind::Delete)],
        "a purged delivered item is logged as a deletion, so clients that sync the inbox learn of it; a purged \
         quarantined item was never shown and is not",
    );
    checks.equal(
        &tx.webhooks()
            .list_deliveries(subscription.id, PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "the purged deliveries are gone",
    );
    checks.equal(
        &tx.webhooks().get(subscription.id).await?.id,
        &subscription.id,
        "and the subscription is not",
    );
    checks.equal(
        &tx.audit()
            .list(&AuditFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "the audit log is empty",
    );
    let claim = tx.idempotency().claim(key("old", far_future())).await?;
    checks.equal(&claim, &IdempotencyClaim::Claimed, "a purged key is free");
    tx.commit().await?;
    Ok(())
}

/// Pruning the change logs raises the minimum sequence, so tokens that need pruned history are refused.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn retention_prunes_change_logs(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let log = CollectionKey {
        kind: CollectionKind::Calendar,
        id: world.personal.as_uuid(),
    };
    let home = CollectionKey {
        kind: CollectionKind::Home,
        id: world.olivia.as_uuid(),
    };
    let notifications = CollectionKey {
        kind: CollectionKind::Notifications,
        id: world.mia.as_uuid(),
    };
    let inbox = CollectionKey {
        kind: CollectionKind::Inbox,
        id: world.mia.as_uuid(),
    };
    let epochs = [
        tx.changes().state(log).await?.epoch,
        tx.changes().state(home).await?.epoch,
        tx.changes().state(notifications).await?.epoch,
        tx.changes().state(inbox).await?.epoch,
    ];
    for (n, name) in [(0x4F1, "a"), (0x4F2, "b"), (0x4F3, "c")] {
        tx.objects()
            .put(
                world.personal,
                version(n, &format!("{name}.ics"), name)?,
                Expected::Absent,
            )
            .await?;
    }
    tx.bindings()
        .create(binding(0x501, world.olivia, world.personal, "personal")?)
        .await?;
    tx.notifications()
        .create(notification(0x801, world.mia, "n.xml", "invite")?)
        .await?;
    tx.inbox().create(inbox_item(0x901, world.mia, "i.ics", false)?).await?;
    tx.commit().await?;

    let mut sys = system(db).await?;
    checks.equal(
        &sys.retention().prune_changes(long_ago()).await?,
        &0,
        "nothing is older than long ago",
    );
    checks.equal(
        &sys.retention().prune_changes(far_future()).await?,
        &6,
        "every change-log row older than the cut-off",
    );
    checks.equal(&sys.retention().prune_changes(far_future()).await?, &0, "once");
    sys.commit().await?;

    let mut tx = begin(db, world.a).await?;
    let state = tx.changes().state(log).await?;
    checks.equal(
        &(state.seq, state.min_seq),
        &(3, 3),
        "the minimum sequence is the last pruned one",
    );
    checks.invalid_sync_token(
        tx.changes().since(log, epochs[0], 0, 10).await,
        "a token older than the pruned history",
    );
    checks.invalid_sync_token(
        tx.changes().since(log, epochs[0], 2, 10).await,
        "even one that is one short",
    );
    checks.equal(
        &tx.changes().since(log, epochs[0], 3, 10).await?.changes.len(),
        &0,
        "a token at the minimum sequence still works",
    );
    for (key, epoch) in [(home, epochs[1]), (notifications, epochs[2]), (inbox, epochs[3])] {
        checks.invalid_sync_token(
            tx.changes().since(key, epoch, 0, 10).await,
            "a pruned principal collection",
        );
        checks.equal(
            &tx.changes().since(key, epoch, 1, 10).await?.changes.len(),
            &0,
            "and its token at the minimum",
        );
    }
    tx.objects()
        .put(world.personal, version(0x4F4, "d.ics", "d")?, Expected::Absent)
        .await?;
    let batch = tx.changes().since(log, epochs[0], 3, 10).await?;
    checks.equal(
        &batch
            .changes
            .iter()
            .map(|change| (change.uri.to_string(), change.seq))
            .collect::<Vec<_>>(),
        &vec![("d.ics".to_owned(), 4)],
        "later changes are found from the minimum",
    );
    tx.commit().await?;
    Ok(())
}

/// Principals and calendars that are due for their purge, across tenants.
pub(super) async fn retention_due_rows(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let early = tx
        .principals()
        .create(principal(0x150, "early", PrincipalKind::User)?)
        .await?;
    let late = tx
        .principals()
        .create(principal(0x151, "late", PrincipalKind::User)?)
        .await?;
    for (found, hour) in [(&late, 9), (&early, 8)] {
        let mut deleted = found.clone();
        deleted.status = PrincipalStatus::Deleted;
        deleted.deleted_at = Some(at(hour));
        tx.principals().update(deleted, found.version).await?;
    }
    let doomed = tx
        .calendars()
        .create(calendar(0x360, world.olivia, "doomed", CalendarKind::User)?)
        .await?;
    tx.calendars().soft_delete(doomed.id, doomed.version).await?;
    tx.commit().await?;
    let mut other = begin(db, world.b).await?;
    let gina = other.principals().get(world.gina).await?;
    let mut deleted = gina.clone();
    deleted.status = PrincipalStatus::Deleted;
    deleted.deleted_at = Some(at(7));
    other.principals().update(deleted, gina.version).await?;
    other.commit().await?;

    let mut sys = system(db).await?;
    checks.equal(
        &sys.retention().due_principals(at(10), 10).await?,
        &vec![(world.b, world.gina), (world.a, early.id), (world.a, late.id)],
        "deleted principals older than the cut-off, oldest first, across tenants",
    );
    checks.equal(
        &sys.retention().due_principals(at(9), 10).await?,
        &vec![(world.b, world.gina), (world.a, early.id)],
        "the cut-off is exclusive",
    );
    checks.equal(&sys.retention().due_principals(at(10), 1).await?.len(), &1, "the limit");
    checks.equal(
        &sys.retention().due_principals(at(7), 10).await?.len(),
        &0,
        "none before the first deletion",
    );
    checks.equal(
        &sys.retention().due_calendars(far_future(), 10).await?,
        &vec![(world.a, doomed.id)],
        "soft-deleted calendars older than the cut-off",
    );
    checks.equal(
        &sys.retention().due_calendars(long_ago(), 10).await?.len(),
        &0,
        "none before long ago",
    );
    sys.commit().await?;
    Ok(())
}

/// The oldest audit event of all tenants: what the cleanup worker publishes so that an operator hears when the job that purges
/// the audit log stops. It reads across tenants, so the answer is the oldest record of the whole log, whichever tenant it is in
/// and whichever order the records were written in.
///
/// The records have distinct times, and the oldest is in the log of the **second** tenant and was written **second**: an answer
/// that is the newest record (`max`), the oldest of one tenant, the first record written or the lowest id fails.
pub(super) async fn retention_oldest_audit_event(db: &Db, clock: &ManualClock, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let oldest = clock.now();
    let (middle, newest) = (oldest + TimeDelta::days(1), oldest + TimeDelta::days(2));
    let mut sys = system(db).await?;
    checks.equal(
        &sys.retention().oldest_audit_at().await?,
        &None,
        "an empty log has no oldest record",
    );
    sys.commit().await?;

    // Written out of order: the newest first, in the first tenant; then the oldest, in the second; then the middle one, in the
    // first again. Ids 1, 2, 3 are in the order of writing, so the order of the times is not the order of the ids.
    for (tenant, n, at) in [(world.a, 1, newest), (world.b, 2, oldest), (world.a, 3, middle)] {
        clock.set(at);
        let mut tx = begin(db, tenant).await?;
        tx.audit()
            .append(NewAudit {
                id: uuid(n),
                actor: AuditActor::system(),
                event: AuditEvent::TenantCreated,
            })
            .await?;
        tx.commit().await?;
    }
    let mut times = Vec::new();
    for tenant in [world.a, world.b] {
        let mut tx = read(db, tenant).await?;
        let listed = tx.audit().list(&AuditFilter::default(), PageReq::default()).await?;
        times.extend(listed.items.iter().map(|row| (row.tenant_id, row.at)));
    }
    times.sort();
    checks.equal(
        &times,
        &vec![(world.a, middle), (world.a, newest), (world.b, oldest)],
        "the records carry the times they were written at, the oldest in the log of the second tenant",
    );

    let mut sys = system(db).await?;
    checks.equal(
        &sys.retention().oldest_audit_at().await?,
        &Some(oldest),
        "the oldest record of all tenants, not the newest, not the oldest of the first tenant, not the first one written",
    );
    // Purging moves it: the oldest goes (it is the only one before the cut-off), and the next one is the oldest now.
    checks.equal(
        &sys.retention().purge_audit(oldest + TimeDelta::hours(12)).await?,
        &1,
        "the purge removes the oldest record",
    );
    checks.equal(
        &sys.retention().oldest_audit_at().await?,
        &Some(middle),
        "after the purge the next record is the oldest, in the other tenant",
    );
    checks.equal(
        &sys.retention().purge_audit(far_future()).await?,
        &2,
        "the purge removes the rest",
    );
    checks.equal(
        &sys.retention().oldest_audit_at().await?,
        &None,
        "a log that was purged to the end has no oldest record again",
    );
    sys.commit().await?;
    Ok(())
}
