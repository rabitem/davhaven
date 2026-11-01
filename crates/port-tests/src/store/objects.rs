//! Cases of calendar objects and the write invariant (PLAN 2.7).

use davhaven_domain::{
    CalendarId, CalendarKind, CalendarUserAddress, Classification, CollectionKey, CollectionKind, ComponentKind, ETag,
    ExternalKey, ObjectUri, PartStat, ScheduleTag, Uid,
};
use davhaven_ports::{ChangeKind, Expected, IndexFilter, PageReq, TimeRange, UniqueKey};

use super::Outcome;
use super::world::{Db, StoreChecks, World, at, begin, calendar, id, key, keyed, scheduling, seed, uuid, version};
use crate::suite::Checks;

/// The change-log key of a calendar.
fn log_of(calendar: CalendarId) -> CollectionKey {
    CollectionKey {
        kind: CollectionKind::Calendar,
        id: calendar.as_uuid(),
    }
}

/// The URIs of a page of objects.
fn uris(page: &davhaven_ports::StorePage<davhaven_domain::StoredObject>) -> Vec<String> {
    page.items.iter().map(|object| object.uri.to_string()).collect()
}

/// Putting and reading objects: every column, verbatim data, replacement and the infinite end.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn objects_put_and_read(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut event = keyed(version(0x401, "event-1.ics", "uid-1")?, "crm:1")?;
    event.index.first_start = Some(at(10));
    event.index.last_end = Some(at(12));
    event.index.is_recurring = true;
    event.index.sequence = 3;
    event.index.class = Classification::Private;
    event.index.organizer = Some(key(CalendarUserAddress::parse("mailto:olivia@example.org"))?);
    event.schedule_tag = Some(ScheduleTag::from_uuid(uuid(0x77)));
    event.origin = Some("google".to_owned());
    let written = tx
        .objects()
        .put(world.personal, event.clone(), Expected::Absent)
        .await?;
    checks.equal(&written.created, &true, "the first put creates");
    checks.equal(&written.seq, &1, "and uses sequence number 1");
    checks.equal(&written.etag, &event.etag, "the ETag is the one the caller computed");
    checks.equal(
        &written.object_id,
        &event.id,
        "the object has the id of the new version",
    );

    let stored = tx.objects().get(world.personal, &event.uri).await?;
    checks.equal(&stored.id, &event.id, "id");
    checks.equal(&stored.tenant_id, &world.a, "the tenant of the transaction");
    checks.equal(&stored.calendar_id, &world.personal, "calendar");
    checks.equal(
        &stored.owner_id,
        &world.olivia,
        "the owner of the calendar, denormalized",
    );
    checks.equal(&stored.uid, &event.index.uid, "uid");
    checks.equal(&stored.etag, &event.etag, "etag");
    checks.equal(&stored.schedule_tag, &event.schedule_tag, "schedule tag");
    checks.equal(&stored.content_hash, &event.content_hash, "content hash");
    checks.equal(&stored.component, &ComponentKind::Event, "component");
    checks.equal(&stored.data, &event.data, "the data is stored verbatim");
    checks.equal(&stored.size, &u64::try_from(event.data.len()).unwrap_or(0), "size");
    checks.equal(&stored.first_start, &Some(at(10)), "first start");
    checks.equal(&stored.last_end, &Some(at(12)), "last end");
    checks.that(stored.is_recurring && !stored.is_scheduling, "flags");
    checks.equal(&stored.organizer_address, &event.index.organizer, "organizer");
    checks.equal(&stored.sequence, &3, "sequence");
    checks.equal(&stored.class, &Classification::Private, "class");
    checks.equal(&stored.external_key, &event.external_key, "external key");
    checks.equal(&stored.origin.as_deref(), &Some("google"), "origin");
    checks.equal(&stored.version, &1, "a new object has version 1");
    checks.equal(
        &stored.created_at,
        &stored.updated_at,
        "creation stamps both times alike",
    );
    checks.equal(&tx.objects().get_by_id(stored.id).await?, &stored, "get by id");
    checks.equal(
        &tx.objects().get_by_uid(world.personal, &event.index.uid).await?,
        &stored,
        "get by uid",
    );
    let external = key(ExternalKey::parse("crm:1"))?;
    checks.equal(
        &tx.objects().get_by_external_key(world.personal, &external).await?,
        &stored,
        "get by external key",
    );
    checks.equal(
        &tx.objects().find_scheduling_uid(world.olivia, &event.index.uid).await?,
        &None,
        "a non-scheduling object is not found by scheduling uid",
    );

    let mut replacement = keyed(version(0x499, "event-1.ics", "uid-1")?, "crm:1")?;
    replacement.data = "BEGIN:VCALENDAR\r\nX-FOLDED:aaa\r\n bbb\r\n\tccc \r\nEND:VCALENDAR\r\n".into();
    replacement.etag = ETag::from_bytes(replacement.data.as_bytes());
    let replaced = tx
        .objects()
        .put(world.personal, replacement.clone(), Expected::Any)
        .await?;
    checks.equal(&replaced.created, &false, "the second put replaces");
    checks.equal(&replaced.object_id, &stored.id, "the id of the existing object wins");
    checks.equal(&replaced.seq, &2, "and uses the next sequence number");
    let current = tx.objects().get(world.personal, &event.uri).await?;
    checks.equal(&current.id, &stored.id, "the replaced object keeps its id");
    checks.equal(&current.data, &replacement.data, "the new data is stored byte for byte");
    checks.equal(&current.etag, &replacement.etag, "with its ETag");
    checks.equal(&current.version, &2, "the version counts up");
    checks.equal(&current.created_at, &stored.created_at, "creation time stays");
    checks.that(
        current.updated_at >= stored.updated_at,
        "the update time does not go back",
    );
    checks.equal(&current.schedule_tag, &None, "a missing schedule tag clears it");

    let mut unbounded = version(0x402, "forever.ics", "uid-forever")?;
    unbounded.index.last_end = None;
    tx.objects()
        .put(world.personal, unbounded.clone(), Expected::Any)
        .await?;
    let forever = tx.objects().get(world.personal, &unbounded.uri).await?;
    checks.equal(&forever.last_end, &None, "an unbounded object has no last end");
    checks.equal(&forever.first_start, &Some(at(10)), "but a first start");
    let mut undated = version(0x403, "todo.ics", "uid-todo")?;
    undated.index.component = ComponentKind::Todo;
    undated.index.first_start = None;
    undated.index.last_end = None;
    tx.objects().put(world.personal, undated.clone(), Expected::Any).await?;
    let todo = tx.objects().get(world.personal, &undated.uri).await?;
    checks.that(
        todo.first_start.is_none() && todo.last_end.is_none(),
        "an undated object has neither",
    );
    checks.equal(&todo.component, &ComponentKind::Todo, "and keeps its component");

    let listed = tx.objects().list(world.personal, PageReq::default()).await?;
    checks.equal(
        &uris(&listed),
        &vec![
            "event-1.ics".to_owned(),
            "forever.ics".to_owned(),
            "todo.ics".to_owned(),
        ],
        "list",
    );
    checks.not_found(
        tx.objects()
            .get(world.personal, &key(ObjectUri::parse("missing.ics"))?)
            .await,
        "an unknown uri",
    );
    checks.not_found(tx.objects().get(id(0x999), &event.uri).await, "an unknown calendar");
    checks.not_found(tx.objects().get_by_id(id(0x999)).await, "an unknown id");
    checks.not_found(
        tx.objects().get_by_uid(world.personal, &key(Uid::parse("nope"))?).await,
        "an unknown uid",
    );
    checks.not_found(
        tx.objects()
            .put(id(0x999), version(0x404, "x.ics", "x")?, Expected::Any)
            .await,
        "a put into an unknown calendar",
    );
    tx.commit().await?;
    Ok(())
}

/// Attendee rows: ordering, resolved principals, replacement with the object.
pub(super) async fn objects_attendees(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let meeting = scheduling(
        version(0x410, "meeting.ics", "meeting")?,
        "mailto:olivia@example.org",
        &[
            ("mailto:zed@example.org", None),
            ("mailto:mia@example.org", Some(world.mia)),
            ("mailto:ghost@example.org", Some(id(0x999))),
            ("mailto:zed@example.org", None),
        ],
    )?;
    let written = tx
        .objects()
        .put(world.personal, meeting.clone(), Expected::Absent)
        .await?;
    let rows = tx.objects().attendees(written.object_id).await?;
    checks.equal(
        &rows.iter().map(|row| row.address.to_string()).collect::<Vec<_>>(),
        &vec![
            "mailto:ghost@example.org".to_owned(),
            "mailto:mia@example.org".to_owned(),
            "mailto:zed@example.org".to_owned(),
        ],
        "one row per address, ordered by address",
    );
    checks.equal(
        &rows.iter().map(|row| row.principal_id).collect::<Vec<_>>(),
        &vec![None, Some(world.mia), None],
        "resolved principals are kept, principals that do not exist stay unresolved",
    );
    checks.that(
        rows.iter()
            .all(|row| row.partstat == PartStat::NeedsAction && row.object_id == written.object_id),
        "status and object",
    );
    let found = tx
        .objects()
        .find_scheduling_uid(world.olivia, &meeting.index.uid)
        .await?;
    checks.equal(
        &found.map(|object| object.id),
        &Some(written.object_id),
        "found by scheduling uid",
    );

    let changed = scheduling(
        version(0x411, "meeting.ics", "meeting")?,
        "mailto:olivia@example.org",
        &[("mailto:new@example.org", None)],
    )?;
    tx.objects().put(world.personal, changed, Expected::Any).await?;
    let rows = tx.objects().attendees(written.object_id).await?;
    checks.equal(
        &rows.iter().map(|row| row.address.to_string()).collect::<Vec<_>>(),
        &vec!["mailto:new@example.org".to_owned()],
        "a replacement replaces the attendee rows",
    );
    tx.objects().delete(world.personal, &meeting.uri, Expected::Any).await?;
    checks.not_found(
        tx.objects().attendees(written.object_id).await,
        "the attendees of a deleted object",
    );
    checks.not_found(
        tx.objects().attendees(id(0x999)).await,
        "the attendees of an unknown object",
    );
    tx.commit().await?;
    Ok(())
}

/// The sequence moves exactly once per mutation, the change is logged at it, and failed writes change nothing.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn objects_write_invariant(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let log = log_of(world.personal);
    let start = tx.changes().state(log).await?;
    checks.equal(&start.seq, &0, "a new calendar has no changes");
    let first = version(0x421, "a.ics", "uid-a")?;
    let second = version(0x422, "b.ics", "uid-b")?;
    checks.equal(
        &tx.objects()
            .put(world.personal, first.clone(), Expected::Absent)
            .await?
            .seq,
        &1,
        "create a",
    );
    checks.equal(
        &tx.objects()
            .put(world.personal, first.clone(), Expected::Any)
            .await?
            .seq,
        &2,
        "replace a",
    );
    checks.equal(
        &tx.objects()
            .put(world.personal, second.clone(), Expected::Absent)
            .await?
            .seq,
        &3,
        "create b",
    );
    checks.equal(
        &tx.objects().delete(world.personal, &first.uri, Expected::Any).await?,
        &4,
        "delete a",
    );
    checks.equal(&tx.calendars().touch(world.personal).await?, &5, "touch");
    let calendar = tx.calendars().get(world.personal).await?;
    checks.equal(&calendar.sync_seq, &5, "the calendar's sequence is the last one used");

    let state = tx.changes().state(log).await?;
    checks.equal(&state.seq, &5, "the sync position agrees");
    let batch = tx.changes().since(log, start.epoch, 0, 10).await?;
    let entries: Vec<(String, u64, ChangeKind)> = batch
        .changes
        .iter()
        .map(|change| (change.uri.to_string(), change.seq, change.kind))
        .collect();
    checks.equal(
        &entries,
        &vec![
            ("b.ics".to_owned(), 3, ChangeKind::Upsert),
            ("a.ics".to_owned(), 4, ChangeKind::Delete),
        ],
        "the log holds the latest change of every member, ordered by sequence; a touch logs nothing",
    );

    // Failed writes move nothing.
    let twin = version(0x423, "c.ics", "uid-b")?;
    checks.unique(
        tx.objects().put(world.personal, twin, Expected::Absent).await,
        UniqueKey::ObjectUid,
        "a second resource with the uid",
    );
    checks.precondition_failed(
        tx.objects().put(world.personal, second.clone(), Expected::Absent).await,
        "creating what exists",
    );
    checks.not_found(
        tx.objects().delete(world.personal, &first.uri, Expected::Any).await,
        "deleting what is gone",
    );
    checks.precondition_failed(
        tx.objects()
            .delete(world.personal, &second.uri, Expected::Etag(ETag::from_bytes(b"other")))
            .await,
        "deleting with a wrong ETag",
    );
    checks.equal(
        &tx.calendars().get(world.personal).await?.sync_seq,
        &5,
        "failed writes leave the sequence alone",
    );
    let again = tx.changes().since(log, start.epoch, 0, 10).await?;
    checks.equal(&again.changes, &batch.changes, "and the log");
    checks.equal(&again.current, &state, "and the position");
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.changes().state(log).await?.seq,
        &5,
        "committed sequence numbers persist",
    );
    checks.equal(
        &tx.objects()
            .put(world.personal, version(0x424, "d.ics", "uid-d")?, Expected::Absent)
            .await?
            .seq,
        &6,
        "and the next write continues after them",
    );
    Ok(())
}

/// `Expected` for puts and deletes.
pub(super) async fn objects_expected_states(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let event = version(0x431, "e.ics", "uid-e")?;
    let stale = Expected::Etag(ETag::from_bytes(b"stale"));
    checks.precondition_failed(
        tx.objects().put(world.personal, event.clone(), stale.clone()).await,
        "If-Match on a missing object",
    );
    tx.objects()
        .put(world.personal, event.clone(), Expected::Absent)
        .await?;
    checks.precondition_failed(
        tx.objects().put(world.personal, event.clone(), Expected::Absent).await,
        "If-None-Match on an existing object",
    );
    checks.precondition_failed(
        tx.objects().put(world.personal, event.clone(), stale.clone()).await,
        "If-Match with another ETag",
    );
    tx.objects()
        .put(world.personal, event.clone(), Expected::Etag(event.etag.clone()))
        .await?;
    tx.objects().put(world.personal, event.clone(), Expected::Any).await?;

    checks.precondition_failed(
        tx.objects().delete(world.personal, &event.uri, Expected::Absent).await,
        "delete with Absent",
    );
    checks.precondition_failed(
        tx.objects().delete(world.personal, &event.uri, stale).await,
        "delete with another ETag",
    );
    checks.equal(
        &tx.objects()
            .delete(world.personal, &event.uri, Expected::Etag(event.etag.clone()))
            .await?,
        &4,
        "delete with the matching ETag",
    );
    for expected in [Expected::Any, Expected::Absent] {
        checks.not_found(
            tx.objects().delete(world.personal, &event.uri, expected).await,
            "deleting a missing object that nothing is expected of (a missing resource answers 404)",
        );
    }
    checks.precondition_failed(
        tx.objects()
            .delete(world.personal, &event.uri, Expected::Etag(event.etag.clone()))
            .await,
        "If-Match is false when no representation exists (RFC 7232 section 3.1): 412, as for a put",
    );
    checks.not_found(
        tx.objects().delete(id(0x999), &event.uri, Expected::Any).await,
        "deleting in an unknown calendar",
    );
    tx.commit().await?;
    Ok(())
}

/// Unique keys of objects: uid, external key and scheduling uid per owner.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn objects_unique_keys(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;

    tx.objects()
        .put(
            world.personal,
            keyed(version(0x441, "1.ics", "same")?, "key:1")?,
            Expected::Absent,
        )
        .await?;
    checks.unique(
        tx.objects()
            .put(world.personal, version(0x442, "2.ics", "same")?, Expected::Absent)
            .await,
        UniqueKey::ObjectUid,
        "the same uid in the same calendar",
    );
    checks.equal(
        &tx.objects()
            .get_by_uid(world.personal, &key(Uid::parse("same"))?)
            .await?
            .uri
            .to_string(),
        &"1.ics".to_owned(),
        "after the violation the object that holds the uid can be named in the same transaction (C:no-uid-conflict)",
    );
    tx.objects()
        .put(world.shared, version(0x443, "1.ics", "same")?, Expected::Absent)
        .await?;
    checks.unique(
        tx.objects()
            .put(
                world.personal,
                keyed(version(0x444, "3.ics", "other")?, "key:1")?,
                Expected::Absent,
            )
            .await,
        UniqueKey::ExternalKey,
        "the same external key in the same calendar",
    );
    tx.objects()
        .put(
            world.shared,
            keyed(version(0x445, "3.ics", "other")?, "key:1")?,
            Expected::Absent,
        )
        .await?;
    tx.objects()
        .put(
            world.personal,
            keyed(version(0x441, "1.ics", "same")?, "key:1")?,
            Expected::Any,
        )
        .await?;

    let meeting = |n: u128, uri: &str| {
        scheduling(
            version(n, uri, "meeting")?,
            "mailto:olivia@example.org",
            &[("mailto:x@example.org", None)],
        )
    };
    tx.objects()
        .put(world.personal, meeting(0x446, "m.ics")?, Expected::Absent)
        .await?;
    checks.unique(
        tx.objects()
            .put(world.shared, meeting(0x447, "m.ics")?, Expected::Absent)
            .await,
        UniqueKey::SchedulingUid,
        "a scheduling uid twice among the calendars of one owner",
    );
    checks.equal(
        &tx.objects()
            .find_scheduling_uid(world.olivia, &key(Uid::parse("meeting"))?)
            .await?
            .map(|object| (object.calendar_id, object.uri.to_string())),
        &Some((world.personal, "m.ics".to_owned())),
        "and so can the scheduling object that holds the uid (C:unique-scheduling-object-resource)",
    );
    tx.objects()
        .put(world.team_calendar, meeting(0x448, "m.ics")?, Expected::Absent)
        .await?;
    tx.objects()
        .put(world.shared, version(0x449, "plain.ics", "meeting")?, Expected::Absent)
        .await?;
    checks.equal(
        &tx.changes().state(log_of(world.shared)).await?.seq,
        &3,
        "failed writes did not advance the sequence of the calendar they targeted",
    );
    tx.objects()
        .delete(world.personal, &key(ObjectUri::parse("m.ics"))?, Expected::Any)
        .await?;
    tx.calendars()
        .create(calendar(0x350, world.olivia, "extra", CalendarKind::User)?)
        .await?;
    tx.objects()
        .put(id(0x350), meeting(0x44A, "m2.ics")?, Expected::Absent)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Moving objects: rename, relocation, conflicts.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn objects_move(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut original = version(0x451, "a.ics", "uid-a")?;
    original.schedule_tag = Some(ScheduleTag::from_uuid(uuid(0x55)));
    let created = tx
        .objects()
        .put(world.personal, original.clone(), Expected::Absent)
        .await?;
    let before = tx.objects().get(world.personal, &original.uri).await?;
    let renamed_uri = key(ObjectUri::parse("b.ics"))?;

    let (deleted_at_seq, upserted_at_seq) = tx
        .objects()
        .move_to(world.personal, &original.uri, world.personal, &renamed_uri)
        .await?;
    checks.equal(
        &(deleted_at_seq, upserted_at_seq),
        &(created.seq + 1, created.seq + 2),
        "a rename uses two consecutive sequence numbers of the calendar",
    );
    checks.not_found(
        tx.objects().get(world.personal, &original.uri).await,
        "the old name is gone",
    );
    let renamed = tx.objects().get(world.personal, &renamed_uri).await?;
    checks.equal(&renamed.id, &before.id, "a move keeps the id");
    checks.equal(&renamed.data, &before.data, "the data");
    checks.equal(&renamed.etag, &before.etag, "the ETag");
    checks.equal(&renamed.schedule_tag, &before.schedule_tag, "and the schedule tag");
    let log = log_of(world.personal);
    let epoch = tx.changes().state(log).await?.epoch;
    let batch = tx.changes().since(log, epoch, 0, 10).await?;
    checks.equal(
        &batch
            .changes
            .iter()
            .map(|change| (change.uri.to_string(), change.seq, change.kind))
            .collect::<Vec<_>>(),
        &vec![
            ("a.ics".to_owned(), 2, ChangeKind::Delete),
            ("b.ics".to_owned(), 3, ChangeKind::Upsert),
        ],
        "a rename logs a deletion of the old name and an upsert of the new one",
    );

    let shared_uri = key(ObjectUri::parse("moved.ics"))?;
    let (source_seq, target_seq) = tx
        .objects()
        .move_to(world.personal, &renamed_uri, world.shared, &shared_uri)
        .await?;
    checks.equal(
        &(source_seq, target_seq),
        &(4, 1),
        "a relocation uses the next sequence number of each calendar",
    );
    let moved = tx.objects().get(world.shared, &shared_uri).await?;
    checks.equal(
        &moved.calendar_id,
        &world.shared,
        "the object is in the target calendar",
    );
    checks.equal(&moved.id, &before.id, "with its id");
    checks.not_found(
        tx.objects().get(world.personal, &renamed_uri).await,
        "and no longer in the source",
    );
    let shared_log = log_of(world.shared);
    let shared_epoch = tx.changes().state(shared_log).await?.epoch;
    checks.equal(
        &tx.changes().since(shared_log, shared_epoch, 0, 10).await?.changes.len(),
        &1,
        "the target logs an upsert",
    );

    let (_, _) = tx
        .objects()
        .move_to(world.shared, &shared_uri, world.team_calendar, &shared_uri)
        .await?;
    checks.equal(
        &tx.objects().get(world.team_calendar, &shared_uri).await?.owner_id,
        &world.team,
        "the owner follows the calendar",
    );

    // Conflicts and missing things change nothing.
    tx.objects()
        .put(
            world.personal,
            version(0x452, "taken.ics", "uid-taken")?,
            Expected::Absent,
        )
        .await?;
    tx.objects()
        .put(world.personal, version(0x453, "x.ics", "uid-x")?, Expected::Absent)
        .await?;
    let taken = key(ObjectUri::parse("taken.ics"))?;
    let x = key(ObjectUri::parse("x.ics"))?;
    checks.unique(
        tx.objects().move_to(world.personal, &x, world.personal, &taken).await,
        UniqueKey::ObjectUri,
        "moving onto an existing name",
    );
    checks.unique(
        tx.objects().move_to(world.personal, &x, world.personal, &x).await,
        UniqueKey::ObjectUri,
        "moving onto itself",
    );
    tx.objects()
        .put(world.shared, version(0x454, "other.ics", "uid-x")?, Expected::Absent)
        .await?;
    checks.unique(
        tx.objects().move_to(world.personal, &x, world.shared, &x).await,
        UniqueKey::ObjectUid,
        "moving into a calendar that has the uid",
    );
    tx.objects()
        .put(
            world.personal,
            keyed(version(0x455, "k.ics", "uid-k")?, "key:k")?,
            Expected::Absent,
        )
        .await?;
    tx.objects()
        .put(
            world.shared,
            keyed(version(0x456, "kk.ics", "uid-kk")?, "key:k")?,
            Expected::Absent,
        )
        .await?;
    checks.unique(
        tx.objects()
            .move_to(
                world.personal,
                &key(ObjectUri::parse("k.ics"))?,
                world.shared,
                &key(ObjectUri::parse("k2.ics"))?,
            )
            .await,
        UniqueKey::ExternalKey,
        "moving into a calendar that has the external key",
    );
    // Scheduling uids are unique per owner: the second calendar of the group.
    tx.calendars()
        .create(calendar(0x340, world.team, "team-two", CalendarKind::Group)?)
        .await?;
    let team_two: CalendarId = id(0x340);
    let meeting = |n: u128, uri: &str| {
        scheduling(
            version(n, uri, "sched")?,
            "mailto:olivia@example.org",
            &[("mailto:x@example.org", None)],
        )
    };
    tx.objects()
        .put(world.team_calendar, meeting(0x457, "s.ics")?, Expected::Absent)
        .await?;
    tx.objects()
        .put(world.personal, meeting(0x458, "s.ics")?, Expected::Absent)
        .await?;
    checks.unique(
        tx.objects()
            .move_to(
                world.personal,
                &key(ObjectUri::parse("s.ics"))?,
                team_two,
                &key(ObjectUri::parse("s.ics"))?,
            )
            .await,
        UniqueKey::SchedulingUid,
        "moving a scheduling object to another calendar of an owner who has the uid",
    );
    checks.not_found(
        tx.objects()
            .move_to(world.personal, &key(ObjectUri::parse("nothing.ics"))?, world.shared, &x)
            .await,
        "moving an unknown object",
    );
    checks.not_found(
        tx.objects().move_to(id(0x999), &x, world.shared, &x).await,
        "moving from an unknown calendar",
    );
    checks.not_found(
        tx.objects().move_to(world.personal, &x, id(0x999), &x).await,
        "moving to an unknown calendar",
    );
    checks.equal(
        &tx.objects().get(world.personal, &x).await?.uri,
        &x,
        "failed moves leave the object where it was",
    );
    tx.commit().await?;
    Ok(())
}

/// Index queries: filters, the superset rule for time ranges, ordering and pages.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn objects_query(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let cal = world.personal;
    let mut e1 = keyed(version(0x461, "1.ics", "u1")?, "k:1")?;
    e1.index.first_start = Some(at(10));
    e1.index.last_end = Some(at(11));
    let mut e2 = keyed(version(0x462, "2.ics", "u2")?, "k:2")?;
    e2.index.first_start = Some(at(12));
    e2.index.last_end = Some(at(13));
    let mut e3 = version(0x463, "3.ics", "u3")?;
    e3.index.component = ComponentKind::Todo;
    e3.index.first_start = None;
    e3.index.last_end = None;
    let mut e4 = keyed(version(0x464, "4.ics", "u4")?, "x:4")?;
    e4.index.first_start = Some(at(9));
    e4.index.last_end = None;
    e4.index.is_recurring = true;
    let mut e5 = scheduling(
        version(0x465, "5.ics", "u5")?,
        "mailto:o@example.org",
        &[("mailto:p@example.org", None)],
    )?;
    e5.index.first_start = Some(at(20));
    e5.index.last_end = Some(at(21));
    for event in [&e1, &e2, &e3, &e4, &e5] {
        tx.objects().put(cal, event.clone(), Expected::Absent).await?;
    }
    macro_rules! matching {
        ($filter:expr) => {
            uris(&tx.objects().query(cal, &$filter, PageReq::default()).await?)
        };
    }
    let names = |list: &[&str]| list.iter().map(|name| (*name).to_owned()).collect::<Vec<_>>();
    checks.equal(
        &matching!(IndexFilter::all()),
        &names(&["1.ics", "2.ics", "3.ics", "4.ics", "5.ics"]),
        "no filter matches everything, in id order",
    );
    checks.equal(
        &matching!(IndexFilter {
            component: Some(ComponentKind::Todo),
            ..IndexFilter::all()
        }),
        &names(&["3.ics"]),
        "component",
    );
    let range = |start, end| IndexFilter {
        time_range: Some(TimeRange { start, end }),
        ..IndexFilter::all()
    };
    checks.equal(
        &matching!(range(Some(at(10)), Some(at(11)))),
        &names(&["1.ics", "3.ics", "4.ics"]),
        "a bounded range: overlapping, undated and unbounded objects (the pre-filter is closed at both ends)",
    );
    checks.equal(
        &matching!(range(Some(at(13)), None)),
        &names(&["2.ics", "3.ics", "4.ics", "5.ics"]),
        "an open end: the object end is inclusive (a superset; 2.ics ends where the range starts), undated and \
         unbounded objects always match",
    );
    checks.equal(
        &matching!(range(Some(at(12)), Some(at(13)))),
        &names(&["2.ics", "3.ics", "4.ics"]),
        "another range",
    );
    checks.equal(
        &matching!(range(None, Some(at(10)))),
        &names(&["1.ics", "3.ics", "4.ics"]),
        "an open start: an object that starts exactly at the range end is a candidate too (a to-do due then          matches by RFC 4791 section 9.9), one that starts after it is not",
    );
    checks.equal(
        &matching!(IndexFilter {
            uid: Some(key(Uid::parse("u2"))?),
            ..IndexFilter::all()
        }),
        &names(&["2.ics"]),
        "uid",
    );
    checks.equal(
        &matching!(IndexFilter {
            uris: Some(vec![
                key(ObjectUri::parse("2.ics"))?,
                key(ObjectUri::parse("1.ics"))?,
                key(ObjectUri::parse("none.ics"))?
            ]),
            ..IndexFilter::all()
        }),
        &names(&["1.ics", "2.ics"]),
        "multiget by names",
    );
    checks.equal(
        &matching!(IndexFilter {
            uris: Some(Vec::new()),
            ..IndexFilter::all()
        }),
        &Vec::<String>::new(),
        "an empty name list matches nothing",
    );
    checks.equal(
        &matching!(IndexFilter {
            external_key: Some(key(ExternalKey::parse("k:2"))?),
            ..IndexFilter::all()
        }),
        &names(&["2.ics"]),
        "external key",
    );
    checks.equal(
        &matching!(IndexFilter {
            external_key_prefix: Some("k:".to_owned()),
            ..IndexFilter::all()
        }),
        &names(&["1.ics", "2.ics"]),
        "external key prefix",
    );
    checks.equal(
        &matching!(IndexFilter {
            organizer: Some(key(CalendarUserAddress::parse("MAILTO:O@example.org"))?),
            ..IndexFilter::all()
        }),
        &names(&["5.ics"]),
        "organizer",
    );
    checks.equal(
        &matching!(IndexFilter {
            is_scheduling: Some(true),
            ..IndexFilter::all()
        }),
        &names(&["5.ics"]),
        "scheduling objects",
    );
    checks.equal(
        &matching!(IndexFilter {
            is_scheduling: Some(false),
            ..IndexFilter::all()
        }),
        &names(&["1.ics", "2.ics", "3.ics", "4.ics"]),
        "non-scheduling objects",
    );
    checks.equal(
        &matching!(IndexFilter {
            component: Some(ComponentKind::Event),
            is_scheduling: Some(false),
            external_key_prefix: Some("x".to_owned()),
            ..IndexFilter::all()
        }),
        &names(&["4.ics"]),
        "filters combine",
    );
    let first = tx.objects().query(cal, &IndexFilter::all(), PageReq::first(2)).await?;
    checks.equal(&uris(&first), &names(&["1.ics", "2.ics"]), "the first page");
    let cursor = first.next;
    checks.that(cursor.is_some(), "has a cursor");
    if let Some(cursor) = cursor {
        let second = tx
            .objects()
            .query(cal, &IndexFilter::all(), PageReq::first(2).after(cursor))
            .await?;
        checks.equal(&uris(&second), &names(&["3.ics", "4.ics"]), "the second page");
        let third = tx
            .objects()
            .query(
                cal,
                &IndexFilter::all(),
                PageReq::first(2).after(second.next.unwrap_or(cursor)),
            )
            .await?;
        checks.equal(&uris(&third), &names(&["5.ics"]), "the last page");
        checks.equal(&third.next, &None, "has no cursor");
    }
    checks.not_found(
        tx.objects()
            .query(id(0x999), &IndexFilter::all(), PageReq::default())
            .await,
        "a query in an unknown calendar",
    );
    checks.not_found(
        tx.objects().list(id(0x999), PageReq::default()).await,
        "a list of an unknown calendar",
    );
    Ok(())
}

/// Objects of a soft-deleted calendar are invisible and do not occupy scheduling uids.
pub(super) async fn objects_of_deleted_calendars(db: &Db, checks: &mut Checks) -> Outcome {
    let world: World = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let meeting = scheduling(
        version(0x471, "m.ics", "meeting")?,
        "mailto:olivia@example.org",
        &[("mailto:x@example.org", None)],
    )?;
    let written = tx
        .objects()
        .put(world.personal, meeting.clone(), Expected::Absent)
        .await?;
    let doomed = tx.calendars().get(world.personal).await?;
    tx.calendars().soft_delete(doomed.id, doomed.version).await?;
    checks.not_found(tx.objects().get_by_id(written.object_id).await, "get by id");
    checks.not_found(tx.objects().get(world.personal, &meeting.uri).await, "get by name");
    checks.not_found(
        tx.objects().get_by_uid(world.personal, &meeting.index.uid).await,
        "get by uid",
    );
    checks.not_found(tx.objects().attendees(written.object_id).await, "attendees");
    checks.not_found(
        tx.objects()
            .query(world.personal, &IndexFilter::all(), PageReq::default())
            .await,
        "a query in the deleted calendar",
    );
    checks.not_found(
        tx.objects()
            .put(world.personal, version(0x472, "n.ics", "n")?, Expected::Any)
            .await,
        "a put into the deleted calendar",
    );
    checks.equal(
        &tx.objects()
            .find_scheduling_uid(world.olivia, &meeting.index.uid)
            .await?,
        &None,
        "the scheduling uid is free",
    );
    tx.objects()
        .put(
            world.shared,
            scheduling(
                version(0x473, "m.ics", "meeting")?,
                "mailto:olivia@example.org",
                &[("mailto:x@example.org", None)],
            )?,
            Expected::Absent,
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

/// An instant (a component without `DTEND` or `DURATION`, so `last_end == first_start`) is a candidate for a range
/// that starts at it (RFC 4791 section 9.9: `start <= DTSTART < end`), and for a range that ends at it (the rows of
/// the table anchored on `DUE` or `COMPLETED` match then): the pre-filter is closed at both ends and stays a
/// superset.
pub(super) async fn objects_query_instants(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let cal = world.personal;
    let mut ending = version(0x471, "ending.ics", "ending")?;
    ending.index.first_start = Some(at(10));
    ending.index.last_end = Some(at(12));
    let mut instant = version(0x472, "instant.ics", "instant")?;
    instant.index.first_start = Some(at(12));
    instant.index.last_end = Some(at(12));
    let mut later = version(0x473, "later.ics", "later")?;
    later.index.first_start = Some(at(14));
    later.index.last_end = Some(at(15));
    for event in [ending, instant, later] {
        tx.objects().put(cal, event, Expected::Absent).await?;
    }
    let names = |list: &[&str]| list.iter().map(|name| (*name).to_owned()).collect::<Vec<_>>();
    let range = |start, end| IndexFilter {
        time_range: Some(TimeRange { start, end }),
        ..IndexFilter::all()
    };
    let found = uris(
        &tx.objects()
            .query(cal, &range(Some(at(12)), Some(at(13))), PageReq::default())
            .await?,
    );
    checks.that(
        found.contains(&"instant.ics".to_owned()),
        "an instant at the range start is a candidate (it is lost for good if the pre-filter drops it)",
    );
    checks.equal(
        &found,
        &names(&["ending.ics", "instant.ics"]),
        "the object that merely ends where the range starts may be returned too: the exact filter drops it",
    );
    checks.equal(
        &uris(
            &tx.objects()
                .query(cal, &range(Some(at(11)), Some(at(12))), PageReq::default())
                .await?,
        ),
        &names(&["ending.ics", "instant.ics"]),
        "the range end is closed too: an instant at the range end is a candidate (a to-do due then matches); the \
         exact filter drops the ones the half-open range excludes",
    );
    checks.equal(
        &uris(
            &tx.objects()
                .query(cal, &range(Some(at(12)), None), PageReq::default())
                .await?,
        ),
        &names(&["ending.ics", "instant.ics", "later.ics"]),
        "an open end",
    );
    checks.equal(
        &uris(
            &tx.objects()
                .query(cal, &range(Some(at(13)), None), PageReq::default())
                .await?,
        ),
        &names(&["later.ics"]),
        "nothing that ended before the range starts",
    );
    Ok(())
}

/// Event data with umlauts and characters beyond the Basic Multilingual Plane is stored and returned byte for byte,
/// and `size` counts bytes.
pub(super) async fn objects_unicode_data(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut text = version(0x481, "fest.ics", "fest")?;
    text.data = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:fest\r\nSUMMARY:Größenwahn und Gemütlichkeit 🎉 日本語\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    text.etag = ETag::from_bytes(text.data.as_bytes());
    let wanted = text.data.clone();
    tx.objects().put(world.personal, text, Expected::Absent).await?;
    let stored = tx
        .objects()
        .get(world.personal, &key(ObjectUri::parse("fest.ics"))?)
        .await?;
    checks.equal(&stored.data, &wanted, "the data comes back byte for byte");
    checks.equal(
        &stored.size,
        &u64::try_from(wanted.len()).unwrap_or(0),
        "and its size counts bytes, not characters",
    );
    tx.commit().await?;
    Ok(())
}

/// One row of the RFC 4791 section 9.9 table, as the index stores it: the component's interval, and the rule of the
/// table in whole hours (`start`/`end` are the range bounds; an open bound is far below or above every anchor).
struct RfcRow {
    uri: &'static str,
    first: Option<i64>,
    last: Option<i64>,
    /// The condition of the table row.
    matches: fn(i64, i64) -> bool,
}

/// The bounds that stand for an open range end.
const OPEN_START: i64 = -1_000;
const OPEN_END: i64 = 1_000;

/// The rows of the table that are anchored on one instant or on an interval, with the anchors of 10:00 to 12:00.
fn rfc_rows() -> Vec<RfcRow> {
    vec![
        // VEVENT with DTEND (10:00 to 12:00): (start < DTEND) AND (end > DTSTART).
        RfcRow {
            uri: "event-dtend.ics",
            first: Some(10),
            last: Some(12),
            matches: |start, end| start < 12 && end > 10,
        },
        // VEVENT with DTEND equal to DTSTART (11:00) and VEVENT with DURATION:PT0S: (start <= DTSTART) AND
        // (end > DTSTART).
        RfcRow {
            uri: "event-zero-length.ics",
            first: Some(11),
            last: Some(11),
            matches: |start, end| start <= 11 && end > 11,
        },
        RfcRow {
            uri: "event-duration-zero.ics",
            first: Some(10),
            last: Some(10),
            matches: |start, end| start <= 10 && end > 10,
        },
        // VEVENT with only DTSTART (a date-time): (start <= DTSTART) AND (end > DTSTART).
        RfcRow {
            uri: "event-dtstart-only.ics",
            first: Some(12),
            last: Some(12),
            matches: |start, end| start <= 12 && end > 12,
        },
        // VTODO with only DUE (10:00): (start < DUE) AND (end >= DUE). The index anchors on the DUE instant.
        RfcRow {
            uri: "todo-due-only.ics",
            first: Some(10),
            last: Some(10),
            matches: |start, end| start < 10 && end >= 10,
        },
        // VTODO with only COMPLETED (11:00): (start <= COMPLETED) AND (end >= COMPLETED).
        RfcRow {
            uri: "todo-completed-only.ics",
            first: Some(11),
            last: Some(11),
            matches: |start, end| start <= 11 && end >= 11,
        },
        // VTODO with DTSTART (10:00) and DUE (12:00): (start < DUE OR start <= DTSTART) AND
        // (end > DTSTART OR end >= DUE).
        RfcRow {
            uri: "todo-dtstart-due.ics",
            first: Some(10),
            last: Some(12),
            matches: |start, end| (start < 12 || start <= 10) && (end > 10 || end >= 12),
        },
        // An unbounded recurrence starting at 10:00 and a component without any date: they match every range
        // that can contain an occurrence (the exact filter decides), the undated one every range.
        RfcRow {
            uri: "event-recurring-forever.ics",
            first: Some(10),
            last: None,
            matches: |_, end| end > 10,
        },
        RfcRow {
            uri: "todo-undated.ics",
            first: None,
            last: None,
            matches: |_, _| true,
        },
    ]
}

/// The pre-filter never misses a row of the RFC 4791 section 9.9 table, at either end of the range, and the stores
/// answer exactly what `davhaven_domain::index::interval_may_overlap` says (the one definition the SQL mirrors).
///
/// Every row of the table is stored with the interval its anchors give, and every range between 08:00 and 14:00 (and
/// the open ones) is probed: whatever the table matches must be among the candidates, whatever the definition
/// admits must be returned, and nothing else.
pub(super) async fn objects_time_range_vectors(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let cal = world.personal;
    let rows = rfc_rows();
    for (n, row) in (0x4A0_u128..).zip(&rows) {
        let mut object = version(n, row.uri, row.uri)?;
        object.index.first_start = row.first.map(|hour| at(u32::try_from(hour).unwrap_or(0)));
        object.index.last_end = row.last.map(|hour| at(u32::try_from(hour).unwrap_or(0)));
        if row.uri.starts_with("todo") {
            object.index.component = ComponentKind::Todo;
        }
        tx.objects().put(cal, object, Expected::Absent).await?;
    }
    let hours = |bound: Option<i64>| bound.map(|hour| at(u32::try_from(hour).unwrap_or(0)));
    let bounds: Vec<Option<i64>> = std::iter::once(None).chain((8..=14).map(Some)).collect();
    for &start in &bounds {
        for &end in &bounds {
            if let (Some(start), Some(end)) = (start, end)
                && start >= end
            {
                continue;
            }
            let range = TimeRange {
                start: hours(start),
                end: hours(end),
            };
            let found: Vec<String> = uris(
                &tx.objects()
                    .query(
                        cal,
                        &IndexFilter {
                            time_range: Some(range),
                            ..IndexFilter::all()
                        },
                        PageReq::first(100),
                    )
                    .await?,
            );
            let (low, high) = (start.unwrap_or(OPEN_START), end.unwrap_or(OPEN_END));
            for row in &rows {
                let candidate = found.iter().any(|uri| uri == row.uri);
                if (row.matches)(low, high) {
                    checks.that(
                        candidate,
                        &format!(
                            "{} matches the range {start:?}..{end:?} by RFC 4791 section 9.9, so the pre-filter must \
                             return it (a candidate dropped here never reaches the exact filter)",
                            row.uri
                        ),
                    );
                }
                let admitted = davhaven_domain::index::interval_may_overlap(
                    hours(row.first),
                    hours(row.last),
                    range.start,
                    range.end,
                );
                checks.equal(
                    &candidate,
                    &admitted,
                    &format!(
                        "{} for the range {start:?}..{end:?}: the store answers what interval_may_overlap says",
                        row.uri
                    ),
                );
            }
        }
    }
    Ok(())
}

/// Listings without the iCalendar text return the same objects in the same order with the same index columns, and
/// the lookups of the conflicting resource name it without loading it.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn objects_index_listings(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let cal = world.personal;
    for (n, name) in [(0x4B1_u128, "a"), (0x4B2, "b"), (0x4B3, "c")] {
        let mut event = version(n, &format!("{name}.ics"), name)?;
        if name == "b" {
            event.index.component = ComponentKind::Todo;
        }
        tx.objects().put(cal, event, Expected::Absent).await?;
    }
    let meeting = scheduling(
        version(0x4B4, "m.ics", "meeting")?,
        "mailto:olivia@example.org",
        &[("mailto:x@example.org", None)],
    )?;
    tx.objects().put(world.shared, meeting, Expected::Absent).await?;

    let full = tx.objects().list(cal, PageReq::first(2)).await?;
    let heads = tx.objects().list_index(cal, PageReq::first(2)).await?;
    checks.equal(
        &heads.items,
        &full
            .items
            .iter()
            .map(davhaven_ports::ObjectHead::from)
            .collect::<Vec<_>>(),
        "a page of heads is the page of objects without their text",
    );
    checks.equal(&heads.next, &full.next, "and has the same cursor");
    let next = tx
        .objects()
        .list_index(cal, PageReq::first(2).after(heads.next.unwrap_or_default()))
        .await?;
    checks.equal(&next.items.len(), &1, "the cursor continues after the last head");
    checks.equal(&next.next, &None, "and ends");
    checks.that(
        heads.items.iter().all(|head| head.size > 0),
        "heads carry the size of the text they leave out",
    );

    let only_todos = IndexFilter {
        component: Some(ComponentKind::Todo),
        ..IndexFilter::all()
    };
    let queried = tx.objects().query(cal, &only_todos, PageReq::default()).await?;
    let query_heads = tx.objects().query_index(cal, &only_todos, PageReq::default()).await?;
    checks.equal(
        &query_heads.items,
        &queried
            .items
            .iter()
            .map(davhaven_ports::ObjectHead::from)
            .collect::<Vec<_>>(),
        "an index query answers the candidates of the query without their text",
    );
    checks.not_found(
        tx.objects().list_index(id(0x999), PageReq::default()).await,
        "heads of an unknown calendar",
    );
    checks.not_found(
        tx.objects()
            .query_index(id(0x999), &IndexFilter::all(), PageReq::default())
            .await,
        "a head query in an unknown calendar",
    );

    let uid = |text: &str| key(Uid::parse(text));
    checks.equal(
        &tx.objects()
            .uri_for_uid(cal, &uid("a")?)
            .await?
            .map(|uri| uri.to_string()),
        &Some("a.ics".to_owned()),
        "the resource that holds a uid",
    );
    checks.equal(
        &tx.objects().uri_for_uid(cal, &uid("nobody")?).await?,
        &None,
        "no resource holds an unused uid",
    );
    checks.equal(
        &tx.objects().uri_for_uid(world.shared, &uid("a")?).await?,
        &None,
        "uids are per calendar",
    );
    checks.not_found(
        tx.objects().uri_for_uid(id(0x999), &uid("a")?).await,
        "a uid lookup in an unknown calendar",
    );
    checks.equal(
        &tx.objects()
            .uri_for_scheduling_uid(world.olivia, &uid("meeting")?)
            .await?
            .map(|(calendar, uri)| (calendar, uri.to_string())),
        &Some((world.shared, "m.ics".to_owned())),
        "the scheduling object that holds a uid among the owner's calendars",
    );
    checks.equal(
        &tx.objects().uri_for_scheduling_uid(world.olivia, &uid("a")?).await?,
        &None,
        "a plain event does not hold a scheduling uid",
    );
    checks.equal(
        &tx.objects().uri_for_scheduling_uid(world.mia, &uid("meeting")?).await?,
        &None,
        "scheduling uids are per owner",
    );
    Ok(())
}

/// After a uid conflict the application names the conflicting resource in the same transaction
/// (`C:no-uid-conflict`, `C:unique-scheduling-object-resource`): the sequence lock the calendar, put, look the uid up,
/// answers with the object that caused the violation, and the failed put changed nothing.
pub(super) async fn objects_uid_conflicts_name_the_resource(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let cal = world.personal;
    tx.objects()
        .put(cal, version(0x4C1, "holder.ics", "taken")?, Expected::Absent)
        .await?;
    tx.objects()
        .put(
            world.shared,
            scheduling(
                version(0x4C2, "meeting-holder.ics", "meeting")?,
                "mailto:olivia@example.org",
                &[("mailto:x@example.org", None)],
            )?,
            Expected::Absent,
        )
        .await?;
    let before = tx.changes().state(log_of(cal)).await?.seq;

    tx.calendars().lock(&[cal]).await?;
    checks.unique(
        tx.objects()
            .put(cal, version(0x4C3, "intruder.ics", "taken")?, Expected::Absent)
            .await,
        UniqueKey::ObjectUid,
        "a second resource with the uid",
    );
    checks.equal(
        &tx.objects()
            .uri_for_uid(cal, &key(Uid::parse("taken"))?)
            .await?
            .map(|uri| uri.to_string()),
        &Some("holder.ics".to_owned()),
        "while the lock is held, the lookup names the resource that caused the violation",
    );
    checks.equal(
        &tx.changes().state(log_of(cal)).await?.seq,
        &before,
        "the failed put did not advance the sequence",
    );

    // The same for a scheduling object in another calendar of the owner.
    tx.calendars().lock(&[cal, world.shared]).await?;
    checks.unique(
        tx.objects()
            .put(
                cal,
                scheduling(
                    version(0x4C4, "meeting-intruder.ics", "meeting")?,
                    "mailto:olivia@example.org",
                    &[("mailto:x@example.org", None)],
                )?,
                Expected::Absent,
            )
            .await,
        UniqueKey::SchedulingUid,
        "a second scheduling object with the uid among the owner's calendars",
    );
    checks.equal(
        &tx.objects()
            .uri_for_scheduling_uid(world.olivia, &key(Uid::parse("meeting"))?)
            .await?
            .map(|(calendar, uri)| (calendar, uri.to_string())),
        &Some((world.shared, "meeting-holder.ics".to_owned())),
        "and the lookup names the calendar and the resource",
    );
    tx.commit().await?;
    Ok(())
}
