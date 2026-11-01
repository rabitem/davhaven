//! Cases of transaction behaviour: rollback, failed writes, read-only transactions, stamps and health.

use davhaven_domain::{AuditActor, AuditEvent};
use davhaven_domain::{CalendarKind, PrincipalKind};
use davhaven_ports::{
    AuditFilter, CollectionProperty, Expected, NewAudit, NewOutbox, OutboxMessage, PageReq, PropertyScope, Reserved,
    TxMode, UniqueKey,
};

use super::Outcome;
use super::world::{
    Db, StoreChecks, app_password, begin, binding, calendar, epoch, grant, id, key, principal, read, seed, system,
    tenant, uuid, version,
};
use crate::suite::Checks;

/// Dropping a transaction without committing undoes everything, outbox messages and audit records included.
pub(super) async fn rollback_discards_everything(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    tx.principals()
        .create(principal(0x180, "temp", PrincipalKind::User)?)
        .await?;
    tx.calendars()
        .create(calendar(0x390, world.olivia, "temp", CalendarKind::User)?)
        .await?;
    tx.objects()
        .put(world.personal, version(0x4F1, "temp.ics", "temp")?, Expected::Absent)
        .await?;
    tx.outbox()
        .enqueue(NewOutbox::now(id(0xA01), OutboxMessage::ProviderPush(Reserved {})))
        .await?;
    tx.audit()
        .append(NewAudit {
            id: uuid(1),
            actor: AuditActor::system(),
            event: AuditEvent::TenantCreated,
        })
        .await?;
    checks.equal(
        &tx.outbox().get(id(0xA01)).await?.attempts,
        &0,
        "inside the transaction the message is visible",
    );
    drop(tx);

    let mut tx = begin(db, world.a).await?;
    checks.not_found(tx.principals().get(id(0x180)).await, "the principal is gone");
    checks.not_found(tx.calendars().get(id(0x390)).await, "the calendar is gone");
    checks.not_found(
        tx.objects()
            .get(world.personal, &key(davhaven_domain::ObjectUri::parse("temp.ics"))?)
            .await,
        "the object is gone",
    );
    checks.equal(
        &tx.calendars().get(world.personal).await?.sync_seq,
        &0,
        "the sequence did not move",
    );
    checks.not_found(
        tx.outbox().get(id(0xA01)).await,
        "the outbox message is gone with the change that caused it",
    );
    checks.equal(
        &tx.audit()
            .list(&AuditFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "the audit record is gone",
    );
    tx.principals()
        .create(principal(0x181, "kept", PrincipalKind::User)?)
        .await?;
    tx.outbox()
        .enqueue(NewOutbox::now(id(0xA02), OutboxMessage::ProviderPush(Reserved {})))
        .await?;
    tx.commit().await?;
    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.principals().get(id(0x181)).await?.name.as_str(),
        &"kept",
        "a committed principal stays",
    );
    checks.equal(
        &tx.outbox().get(id(0xA02)).await?.attempts,
        &0,
        "and its outbox message",
    );
    drop(tx);

    let mut sys = system(db).await?;
    sys.tenants().create(tenant(0xC, "temp", None)?).await?;
    drop(sys);
    let mut sys = system(db).await?;
    checks.equal(
        &sys.tenants()
            .find_by_slug(&key(davhaven_domain::TenantSlug::parse("temp"))?)
            .await?
            .is_none(),
        &true,
        "a system transaction rolls back too",
    );
    Ok(())
}

/// A failed repository call changes nothing and the transaction stays usable.
pub(super) async fn failed_writes_leave_no_trace(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let first = tx
        .principals()
        .create(principal(0x190, "first", PrincipalKind::User)?)
        .await?;
    checks.unique(
        tx.principals()
            .create(principal(0x191, "first", PrincipalKind::User)?)
            .await,
        UniqueKey::PrincipalName,
        "a unique violation",
    );
    checks.not_found(
        tx.bindings()
            .create(binding(0x590, first.id, id(0x999), "ghost")?)
            .await,
        "a missing parent",
    );
    checks.precondition_failed(tx.principals().update(first.clone(), 42).await, "a stale version");
    let second = tx
        .principals()
        .create(principal(0x192, "second", PrincipalKind::User)?)
        .await?;
    tx.objects()
        .put(world.personal, version(0x4F2, "a.ics", "uid-a")?, Expected::Absent)
        .await?;
    checks.unique(
        tx.objects()
            .put(world.personal, version(0x4F3, "b.ics", "uid-a")?, Expected::Absent)
            .await,
        UniqueKey::ObjectUid,
        "a unique violation of an object",
    );
    let next = tx
        .objects()
        .put(world.personal, version(0x4F4, "c.ics", "uid-c")?, Expected::Absent)
        .await?;
    checks.equal(&next.seq, &2, "failed writes do not consume sequence numbers");
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.principals().get(first.id).await?.version,
        &1,
        "the first principal was not touched by the failed update",
    );
    checks.equal(
        &tx.principals().get(second.id).await?.name.as_str(),
        &"second",
        "work after the failures was committed",
    );
    checks.not_found(
        tx.principals().get(id(0x191)).await,
        "the failed principal does not exist",
    );
    checks.equal(
        &tx.calendars().get(world.personal).await?.sync_seq,
        &2,
        "the committed sequence is the last used",
    );
    Ok(())
}

/// Read-only transactions read and refuse to write.
pub(super) async fn read_only_transactions(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = read(db, world.a).await?;
    checks.equal(
        &tx.principals().get(world.olivia).await?.id,
        &world.olivia,
        "reading works",
    );
    checks.internal(
        tx.principals()
            .create(principal(0x1A0, "nope", PrincipalKind::User)?)
            .await,
        "creating a principal",
    );
    checks.internal(tx.calendars().touch(world.personal).await, "touching a calendar");
    checks.internal(
        tx.calendars().lock(&[world.personal]).await,
        "locking a calendar (PostgreSQL refuses row locks in a read-only transaction)",
    );
    checks.internal(tx.changes().touch_home(world.olivia).await, "touching a home");
    checks.internal(
        tx.objects()
            .put(world.personal, version(0x4F5, "x.ics", "x")?, Expected::Any)
            .await,
        "putting an object",
    );
    checks.internal(
        tx.outbox()
            .enqueue(NewOutbox::now(id(0xA01), OutboxMessage::ProviderPush(Reserved {})))
            .await,
        "enqueueing an outbox message",
    );
    checks.internal(
        tx.audit()
            .append(NewAudit {
                id: uuid(1),
                actor: AuditActor::system(),
                event: AuditEvent::TenantCreated,
            })
            .await,
        "appending an audit record",
    );
    checks.equal(
        &tx.principals().get(world.mia).await?.id,
        &world.mia,
        "reading still works after refused writes",
    );
    tx.commit().await?;
    let mut tx = begin(db, world.a).await?;
    checks.not_found(tx.principals().get(id(0x1A0)).await, "nothing was written");
    Ok(())
}

/// Snapshot transactions (the mode for a listing that must agree with its sync token) read like read-only ones and
/// refuse every write. That they see one snapshot while writers commit is shown where two connections exist (the
/// PostgreSQL locking tests); the in-memory adapter runs transactions one after the other.
pub(super) async fn snapshot_transactions(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = db.begin(world.a, TxMode::Snapshot).await?;
    checks.equal(
        &tx.principals().get(world.olivia).await?.id,
        &world.olivia,
        "reading works",
    );
    checks.equal(
        &tx.objects().list(world.personal, PageReq::default()).await?.items.len(),
        &0,
        "listing works",
    );
    checks.internal(
        tx.principals()
            .create(principal(0x1A1, "nope", PrincipalKind::User)?)
            .await,
        "creating a principal",
    );
    checks.internal(tx.calendars().touch(world.personal).await, "touching a calendar");
    checks.internal(
        tx.objects()
            .put(world.personal, version(0x4F6, "x.ics", "x")?, Expected::Any)
            .await,
        "putting an object",
    );
    checks.equal(
        &tx.principals().get(world.mia).await?.id,
        &world.mia,
        "reading still works after refused writes",
    );
    tx.commit().await?;
    let mut tx = begin(db, world.a).await?;
    checks.not_found(tx.principals().get(id(0x1A1)).await, "nothing was written");
    Ok(())
}

/// Text the database cannot store is refused with the same typed error by every adapter. PostgreSQL rejects the
/// character U+0000 in text and `jsonb`, so a test on the in-memory adapter that stored it would pass for input that
/// is an error in production. The refusal changes nothing, and the transaction stays usable.
pub(super) async fn text_with_nul_is_refused(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let bad = "before\0after";

    let mut named = principal(0x1B0, "nul", PrincipalKind::User)?;
    named.display_name = bad.to_owned();
    checks.invalid_data(tx.principals().create(named).await, "a principal's display name");

    let mut described = calendar(0x3B0, world.olivia, "nul", CalendarKind::User)?;
    described.description = Some(bad.to_owned());
    checks.invalid_data(tx.calendars().create(described).await, "a calendar's description");

    let mut object = version(0x4B0, "nul.ics", "nul")?;
    object.data.push_str(bad);
    checks.invalid_data(
        tx.objects().put(world.personal, object, Expected::Any).await,
        "iCalendar text",
    );

    checks.invalid_data(
        tx.properties()
            .set(CollectionProperty {
                calendar_id: world.personal,
                scope: PropertyScope::Shared,
                ns: "DAV:".to_owned(),
                name: "displayname".to_owned(),
                value_xml: format!("<displayname>{bad}</displayname>"),
            })
            .await,
        "a collection property",
    );

    let mut label = app_password(0x7B0, world.olivia, "nul-pass");
    label.label = bad.to_owned();
    checks.invalid_data(tx.credentials().create_app_password(label).await, "a credential label");

    let mut summary = grant(0x6B0, world.shared, world.mia, davhaven_domain::GrantStatus::Pending);
    summary.summary = Some(bad.to_owned());
    checks.invalid_data(tx.grants().create(summary).await, "a grant's summary");

    // Nothing was stored, and the transaction still works.
    checks.not_found(tx.principals().get(id(0x1B0)).await, "the principal was not created");
    checks.not_found(tx.calendars().get(id(0x3B0)).await, "the calendar was not created");
    checks.equal(
        &tx.objects().list(world.personal, PageReq::default()).await?.items.len(),
        &0,
        "the object was not stored",
    );
    tx.principals()
        .create(principal(0x1B1, "fine", PrincipalKind::User)?)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Stamps are consistent (creation stamps both times alike, nothing goes back) and have the microsecond precision
/// both adapters share. That they carry the *injected* clock value is shown where the clock is at hand: the
/// adapters' own tests (`timestamps_come_from_the_injected_clock` for PostgreSQL, the behaviour tests for memory).
pub(super) async fn timestamps_are_consistent_and_microsecond_precise(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let first = tx
        .principals()
        .create(principal(0x1B0, "stamp-one", PrincipalKind::User)?)
        .await?;
    let second = tx
        .principals()
        .create(principal(0x1B1, "stamp-two", PrincipalKind::User)?)
        .await?;
    for created in [&first, &second] {
        checks.that(created.created_at != epoch(), "the entity's own timestamps are ignored");
        checks.equal(
            &created.created_at,
            &created.updated_at,
            "creation stamps both times alike",
        );
        checks.equal(
            &(created.created_at.timestamp_subsec_nanos() % 1000),
            &0,
            "timestamps have microsecond precision in every adapter",
        );
    }
    checks.that(
        second.created_at >= first.created_at,
        "the clock does not go back within a transaction",
    );
    let updated = tx.principals().update(first.clone(), first.version).await?;
    checks.that(
        updated.updated_at >= first.updated_at,
        "an update is stamped no earlier than the creation",
    );
    checks.equal(&updated.created_at, &first.created_at, "and keeps the creation time");
    tx.commit().await?;
    Ok(())
}

/// A working database reports itself ready.
pub(super) async fn health_is_ready(db: &Db, checks: &mut Checks) -> Outcome {
    let health = db.health().await;
    checks.that(
        health.is_ready(),
        &format!("a working, migrated database is ready, got {health:?}"),
    );
    Ok(())
}
